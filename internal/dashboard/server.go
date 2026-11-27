// Package dashboard serves the local browser dashboard that gruff-go dashboard starts for interactive analysis.
//
// It hosts the HTTP server, default options, and scan orchestration entrypoints.
// By default the server listens on 127.0.0.1:8765 and refuses a non-loopback host unless --allow-public is given.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blundergoat/gruff-go/internal/rule"
)

// DefaultHost is the loopback bind host Serve uses when Options.Host is blank.
//
// Only this machine can reach a dashboard bound here; Serve refuses any non-loopback host unless AllowPublic is set.
const DefaultHost = "127.0.0.1"

// DefaultPort is the dashboard port used when no port is specified.
const DefaultPort = 8765

// DefaultScanTimeout is the per-scan wall-clock deadline.
const DefaultScanTimeout = 120 * time.Second

// Options configures a dashboard server started by gruff-go dashboard.
//
// Host, Port and AllowPublic decide where Serve listens, and a positive ScanTimeout also sets the HTTP write timeout.
// Most other fields are scan defaults the page starts from, and Ready lets a caller wait until the listener is up.
type Options struct {
	// Host is the bind host; empty defaults to DefaultHost (loopback).
	Host string
	// Port is the TCP listener port; zero or negative defaults to DefaultPort.
	Port int
	// ScanTimeout requests cancellation of a scan after this duration; zero disables the deadline.
	ScanTimeout time.Duration
	// ProjectRoot is the default project directory used by scans when the query omits one.
	ProjectRoot string
	// Paths are the default discovery paths under ProjectRoot used by initial scans.
	Paths []string
	// ConfigPath is the default .gruff-go.yaml location consumed by scans.
	ConfigPath string
	// SkipConfig disables config file loading when true.
	SkipConfig bool
	// BaselinePath is the default baseline file used by scans.
	BaselinePath string
	// SkipBaseline disables baseline application when true.
	SkipBaseline bool
	// IncludeIgnored disables gitignore filtering when true.
	IncludeIgnored bool
	// DeepScanBudget is the optional atomic CLI override applied above project config.
	DeepScanBudget string
	// DiffMode starts scans against HEAD by default when true, keeping findings in any changed function, even on its unchanged lines.
	DiffMode bool
	// FailOn is the default severity threshold used for scan exit codes.
	FailOn string
	// ReportInteractive renders the interactive findings UI when true.
	ReportInteractive bool
	// EditorLink selects none, vscode or phpstorm for finding links; an empty or unknown value leaves locations as plain text.
	EditorLink string
	// AllowPublic permits binding to non-loopback hosts; required to expose the dashboard beyond localhost.
	AllowPublic bool
	// Registry is unused by dashboard scans, which construct their rules from defaults and project configuration.
	Registry rule.Registry
	// IgnorePaths is unused by dashboard scans; discovery exclusions come from the project config.
	IgnorePaths []string
	// Ready, if non-nil, is closed once the listener is bound and the start-up banner has been written.
	// Tests and supervised launchers use it to synchronise teardown without polling or sleeping.
	Ready chan<- struct{}
}

// Serve binds the dashboard listener, prints the start-up banner and serves HTTP clients until shut down.
//
// The opts value supplies the bind address and scan defaults: a blank Host means DefaultHost and a Port of zero or less means DefaultPort.
// Serve closes opts.Ready, when non-nil, after binding the listener and attempting to write the start-up banner.
//
// The stdout writer receives the start-up banner with the dashboard URL, and stderr a warning when opts.AllowPublic admits a non-loopback host.
// Cancelling ctx or receiving SIGINT or SIGTERM starts a graceful shutdown with a five-second deadline.
//
// It returns nil after a clean shutdown, and fails before binding when the host is not loopback and opts.AllowPublic is false.
// It also returns an error when the address cannot be bound, such as a port another process already holds, or when the server or its shutdown fails.
func Serve(ctx context.Context, stdout, stderr io.Writer, opts Options) error {
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		host = DefaultHost
	}
	port := opts.Port
	if port <= 0 {
		port = DefaultPort
	}
	// A non-loopback --host such as 0.0.0.0 without --allow-public stops gruff-go dashboard here, before anything binds, and the command exits 1.
	if !isLoopbackHost(host) && !opts.AllowPublic {
		return fmt.Errorf("refusing to bind to non-loopback host %q without --allow-public", host)
	}
	if !isLoopbackHost(host) {
		fmt.Fprintf(stderr, "WARNING: binding dashboard to non-loopback host %s\n", host)
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	listener, err := net.Listen("tcp", address)
	// A port already in use, such as a second dashboard on the same port, fails here and Serve returns the listen error.
	if err != nil {
		return fmt.Errorf("listen %s: %w", address, err)
	}

	handler := NewHandler(opts)
	writeTimeout := time.Duration(0)
	// With a positive ScanTimeout, the HTTP write timeout is ten seconds longer than the scan deadline; otherwise writes have no timeout.
	if opts.ScanTimeout > 0 {
		writeTimeout = opts.ScanTimeout + 10*time.Second
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Fprintf(stdout, "Serving gruff-go dashboard at %s\n", initialURL(host, port, opts))
	fmt.Fprintln(stdout, "Use the controls panel to refresh the scan or point gruff at another project. Ctrl+C to stop.")
	if opts.Ready != nil {
		close(opts.Ready)
	}

	shutdownCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()

	select {
	case <-shutdownCtx.Done():
		shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		// A request still running after five seconds, such as a long scan, makes Shutdown fail and Serve returns that error.
		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// isLoopbackHost reports whether host is localhost, ignoring case, or a literal loopback IP address such as 127.0.0.1 or ::1.
// It does no DNS lookup: any other name, or an IPv6 address wrapped in brackets, reports false, so Serve needs --allow-public for it.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

// initialURL builds the dashboard link Serve prints in its start-up banner, carrying the default scan settings as its query string.
//
// The host and port are the listener address, and opts supplies the default scan settings encoded as the query.
// It returns the http URL text built from host, port and the encoded settings after a question mark.
// An IPv6 host such as ::1 gets no brackets, so the printed link for it is not a valid URL.
func initialURL(host string, port int, opts Options) string {
	state := defaultState(opts)
	query := dashboardQueryFromState(state)
	return fmt.Sprintf("http://%s:%d/?%s", host, port, query)
}

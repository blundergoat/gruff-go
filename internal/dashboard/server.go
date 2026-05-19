// Package dashboard serves the local browser dashboard for interactive analysis.
// It hosts the HTTP server, default options, and scan orchestration entrypoints.
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

// DefaultHost is the loopback bind host used unless overridden.
const DefaultHost = "127.0.0.1"

// DefaultPort is the dashboard port used when no port is specified.
const DefaultPort = 8765

// DefaultScanTimeout is the per-scan wall-clock deadline.
const DefaultScanTimeout = 120 * time.Second

// Options configures a dashboard server.
type Options struct {
	// Host is the bind host; empty defaults to DefaultHost (loopback).
	Host string
	// Port is the TCP listener port; zero or negative defaults to DefaultPort.
	Port int
	// ScanTimeout caps the wall-clock duration of a single scan; zero disables the deadline.
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
	// DiffMode enables changed-lines-only scans by default when true.
	DiffMode bool
	// FailOn is the default severity threshold used for scan exit codes.
	FailOn string
	// ReportInteractive renders the interactive findings UI when true.
	ReportInteractive bool
	// EditorLink is the editor URL template used to deep-link findings (e.g. "vscode://file/{path}:{line}").
	EditorLink string
	// AllowPublic permits binding to non-loopback hosts; required to expose the dashboard beyond localhost.
	AllowPublic bool
	// Registry supplies the rules used by scan handlers.
	Registry rule.Registry
	// IgnorePaths lists path patterns suppressed from discovery on every scan.
	IgnorePaths []string
}

// Serve binds the dashboard listener and processes HTTP clients until shut down.
// Returns nil on clean shutdown, non-nil on bind or server error.
func Serve(ctx context.Context, stdout, stderr io.Writer, opts Options) error {
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		host = DefaultHost
	}
	port := opts.Port
	if port <= 0 {
		port = DefaultPort
	}
	if !isLoopbackHost(host) && !opts.AllowPublic {
		return fmt.Errorf("refusing to bind to non-loopback host %q without --allow-public", host)
	}
	if !isLoopbackHost(host) {
		fmt.Fprintf(stderr, "WARNING: binding dashboard to non-loopback host %s\n", host)
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen %s: %w", address, err)
	}

	handler := NewHandler(opts)
	writeTimeout := time.Duration(0)
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

// isLoopbackHost reports whether the host string resolves to a loopback address.
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

// initialURL builds the dashboard root URL with the default scan query string.
func initialURL(host string, port int, opts Options) string {
	state := defaultState(opts)
	query := dashboardQueryFromState(state)
	return fmt.Sprintf("http://%s:%d/?%s", host, port, query)
}

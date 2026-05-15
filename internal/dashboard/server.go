// Package dashboard serves the local browser dashboard for interactive analysis.
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
	Host              string
	Port              int
	ScanTimeout       time.Duration
	ProjectRoot       string
	Paths             []string
	ConfigPath        string
	NoConfig          bool
	BaselinePath      string
	NoBaseline        bool
	IncludeIgnored    bool
	Diff              bool
	FailOn            string
	ReportInteractive bool
	EditorLink        string
	AllowPublic       bool
	Registry          rule.Registry
	IgnorePaths       []string
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
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      opts.ScanTimeout + 10*time.Second,
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

func initialURL(host string, port int, opts Options) string {
	state := defaultState(opts)
	query := dashboardQueryFromState(state)
	return fmt.Sprintf("http://%s:%d/?%s", host, port, query)
}

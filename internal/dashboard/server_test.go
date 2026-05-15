package dashboard

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost", "LocalHost"}
	for _, host := range loopback {
		if !isLoopbackHost(host) {
			t.Errorf("isLoopbackHost(%q) = false, want true", host)
		}
	}
	public := []string{"0.0.0.0", "192.168.1.1", "example.com", "10.0.0.5"}
	for _, host := range public {
		if isLoopbackHost(host) {
			t.Errorf("isLoopbackHost(%q) = true, want false", host)
		}
	}
}

func TestServeRefusesPublicHostWithoutAllowPublic(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Serve(context.Background(), &stdout, &stderr, Options{Host: "0.0.0.0", Port: 0})
	if err == nil {
		t.Fatal("expected error binding to public host without --allow-public")
	}
	if !strings.Contains(err.Error(), "0.0.0.0") || !strings.Contains(err.Error(), "--allow-public") {
		t.Errorf("error %q does not mention public-bind gate", err.Error())
	}
}

func TestServeShutsDownOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, &stdout, &stderr, Options{
			Host:        "127.0.0.1",
			Port:        ephemeralPort(t),
			ScanTimeout: time.Second,
		})
	}()

	// Give the server a moment to bind.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve returned %v on shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not shut down within 2s of context cancel")
	}

	out := stdout.String()
	if !strings.Contains(out, "Serving gruff-go dashboard at http://127.0.0.1:") {
		t.Errorf("expected start-up message in stdout; got: %s", out)
	}
}

func TestInitialURLEncodesDefaultState(t *testing.T) {
	got := initialURL("127.0.0.1", 8765, Options{ProjectRoot: "/repo", FailOn: "medium"})
	if !strings.HasPrefix(got, "http://127.0.0.1:8765/?") {
		t.Errorf("URL prefix = %q", got)
	}
	if !strings.Contains(got, "project=") {
		t.Errorf("URL should encode project key; got %s", got)
	}
}

func ephemeralPort(t *testing.T) int {
	t.Helper()
	port, err := pickEphemeralPort()
	if err != nil {
		t.Fatalf("ephemeral port: %v", err)
	}
	return port
}

// Package dashboard test helpers expose shared utilities for server tests.
//
// They keep listener boilerplate out of individual test files: pickEphemeralPort finds a free loopback port for a test server.
// A test that uses it avoids a fixed port that could already be taken on the machine running go test.
package dashboard

import "net"

// pickEphemeralPort returns an OS-allocated free port for test servers.
//
// It listens on loopback port zero and closes the listener before returning, so the port is only known to be free at that moment.
// It fails with the net.Listen error and a zero port when the loopback listener cannot be opened.
func pickEphemeralPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

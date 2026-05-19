// Package dashboard test helpers expose shared utilities for server tests.
// They keep listener and fixture boilerplate out of individual test files.
package dashboard

import "net"

// pickEphemeralPort returns an OS-allocated free port for test servers.
func pickEphemeralPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

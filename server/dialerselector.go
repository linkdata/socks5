package server

import "github.com/linkdata/socks5"

// A socks5.DialerSelector returns the ContextDialer to use.
type DialerSelector interface {
	// Socks5SelectDialer returns the ContextDialer to use.
	Socks5SelectDialer(am socks5.AuthMethod, username, network, address string) (cd socks5.ContextDialer, err error)
}

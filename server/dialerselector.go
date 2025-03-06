package server

import "github.com/linkdata/socks5"

// DialerSelector returns the ContextDialer to use.
type DialerSelector interface {
	// SelectDialer returns the ContextDialer to use.
	SelectDialer(am socks5.AuthMethod, username, network, address string) (cd socks5.ContextDialer, err error)
}

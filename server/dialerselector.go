package server

import "github.com/linkdata/socks5"

// A socks5.DialerSelector returns the ContextDialer to use.
type DialerSelector interface {
	// Socks5SelectDialer returns the ContextDialer to use.
	//
	// When called, client has already logged in using the given AuthMethod and username.
	// In case of error, it is recommended to return one of the socks5.ErrReply... errors,
	// as those will be mapped to SOCKS5 error codes in the reply to the client.
	Socks5SelectDialer(am socks5.AuthMethod, username, network, address string) (cd socks5.ContextDialer, err error)
}

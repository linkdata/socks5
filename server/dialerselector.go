package server

import "github.com/linkdata/socks5"

// A socks5.DialerSelector returns the ContextDialer to use.
type DialerSelector interface {
	// SelectDialer returns the ContextDialer to use.
	//
	// When called, client has already logged in. If username is the empty string, AuthMethodNone was used.
	// In case of error, it is recommended to return one of the socks5.ErrReply... errors,
	// as those will be mapped to SOCKS5 error codes in the reply to the client.
	SelectDialer(username, network, address string) (cd socks5.ContextDialer, err error)
}

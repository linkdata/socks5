package socks5

import (
	"net"
)

const Socks5Version = 5

type AuthMethod byte

const (
	AuthMethodNone      AuthMethod = 0   // no authentication required (RFC 1928, section 3)
	AuthUserPass        AuthMethod = 2   // user/password authentication (RFC 1928, section 3)
	AuthNoAcceptable    AuthMethod = 255 // no acceptable authentication methods (RFC 1928, section 3)
	AuthSuccess                    = 0   // client auth accepted
	AuthFailure                    = 1   // client auth denied
	AuthUserPassVersion            = 1   // auth version byte (RFC 1929).
)

type CommandType byte

const (
	CommandConnect   CommandType = 1
	CommandBind      CommandType = 2
	CommandAssociate CommandType = 3
)

var (
	DefaultDialer ContextDialer = &net.Dialer{}
	LogPrefix                   = "socks5: "
)

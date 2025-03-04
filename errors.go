package socks5

import "errors"

var (
	ErrUnsupportedNetwork      = errors.New("unsupported network")
	ErrAuthMethodNotSupported  = errors.New("auth method not supported")
	ErrIllegalUsername         = errors.New("illegal username")
	ErrIllegalPassword         = errors.New("illegal password")
	ErrVersion                 = errors.New("invalid SOCKS version")
	ErrInvalidPortNumber       = errors.New("invalid port number")
	ErrBadSOCKSAuthVersion     = errors.New("bad SOCKS auth version")
	ErrUnsupportedCommand      = errors.New("unsupported command")
	ErrAuthFailed              = errors.New("authentication failed")
	ErrInvalidUDPPacket        = errors.New("invalid udp packet")
	ErrFragmentedUDPPacket     = errors.New("fragmented udp packet")
	ErrNoAcceptableAuthMethods = errors.New("no acceptable auth methods")
)

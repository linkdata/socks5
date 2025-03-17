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
	ErrAuthFailed              = errors.New("authentication failed")
	ErrInvalidUDPPacket        = errors.New("invalid udp packet")
	ErrFragmentedUDPPacket     = errors.New("fragmented udp packet")
	ErrNoAcceptableAuthMethods = errors.New("no acceptable auth methods")
	ErrUnsupportedScheme       = errors.New("unsupported scheme")
)

func JoinErrs(errs ...error) (err error) {
	n := 0
	for _, e := range errs {
		if e != nil {
			err = e
			n++
		}
	}
	if n > 1 {
		err = errors.Join(errs...)
	}
	return
}

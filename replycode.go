package socks5

import (
	"errors"
	"fmt"
)

// ReplyCode are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type ReplyCode byte

// The set of valid SOCKS5 reply types as per the RFC 1928.
const (
	Success              ReplyCode = 0
	GeneralFailure       ReplyCode = 1
	ConnectionNotAllowed ReplyCode = 2
	NetworkUnreachable   ReplyCode = 3
	HostUnreachable      ReplyCode = 4
	ConnectionRefused    ReplyCode = 5
	TtlExpired           ReplyCode = 6
	CommandNotSupported  ReplyCode = 7
	AddrTypeNotSupported ReplyCode = 8
)

var (
	ErrGeneralFailure       = errors.New("general failure")
	ErrConnectionNotAllowed = errors.New("connection not allowed")
	ErrNetworkUnreachable   = errors.New("network unreachable")
	ErrHostUnreachable      = errors.New("host unreachable")
	ErrConnectionRefused    = errors.New("connection refused")
	ErrTtlExpired           = errors.New("ttl expired")
	ErrCommandNotSupported  = errors.New("command not supported")
	ErrAddrTypeNotSupported = errors.New("address type not supported")
)

var replyCodeError = map[ReplyCode]error{
	Success:              nil,
	GeneralFailure:       ErrGeneralFailure,
	ConnectionNotAllowed: ErrConnectionNotAllowed,
	NetworkUnreachable:   ErrNetworkUnreachable,
	HostUnreachable:      ErrHostUnreachable,
	ConnectionRefused:    ErrConnectionRefused,
	TtlExpired:           ErrTtlExpired,
	CommandNotSupported:  ErrCommandNotSupported,
	AddrTypeNotSupported: ErrAddrTypeNotSupported,
}

func (code ReplyCode) ToError() error {
	if err, ok := replyCodeError[code]; ok {
		return err
	}
	return fmt.Errorf("code(%d)", int(code))
}

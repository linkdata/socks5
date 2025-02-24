package socks5

import (
	"strconv"
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

func (code ReplyCode) String() string {
	switch code {
	case Success:
		return "success"
	case GeneralFailure:
		return "general failure"
	case ConnectionNotAllowed:
		return "connection not allowed"
	case NetworkUnreachable:
		return "network unreachable"
	case HostUnreachable:
		return "host unreachable"
	case ConnectionRefused:
		return "connection refused"
	case TtlExpired:
		return "TTL expired"
	case CommandNotSupported:
		return "command not supported"
	case AddrTypeNotSupported:
		return "address type not supported"
	default:
		return strconv.Itoa(int(code))
	}
}

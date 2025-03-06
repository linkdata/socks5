package socks5

import (
	"net"
	"time"
)

type AuthMethod byte

// Authentication METHODs described in RFC 1928, section 3.
const (
	NoAuthRequired   AuthMethod = 0
	PasswordAuth     AuthMethod = 2
	NoAcceptableAuth AuthMethod = 255
)

const (
	AuthSuccess = 0
	AuthFailure = 1
)

// PasswordAuthVersion is the auth version byte described in RFC 1929.
const PasswordAuthVersion = 1

// Socks5Version is the byte that represents the SOCKS version
// in requests.
const Socks5Version byte = 5

// CommandType are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type CommandType byte

// The set of valid SOCKS5 commands as described in RFC 1928.
const (
	ConnectCommand   CommandType = 1
	BindCommand      CommandType = 2
	AssociateCommand CommandType = 3
)

var (
	DefaultDialer   ContextDialer = &net.Dialer{}
	LogPrefix                     = "socks5: "
	UDPTimeout                    = time.Second * 10
	ListenerTimeout               = time.Second * 1
)

package socks5

type AuthMethod byte

// Authentication METHODs described in RFC 1928, section 3.
const (
	NoAuthRequired   AuthMethod = 0
	PasswordAuth     AuthMethod = 2
	NoAcceptableAuth AuthMethod = 255
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

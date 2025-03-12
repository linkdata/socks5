package socks5

import "net"

type Dialer interface {
	Dial(network, addr string) (conn net.Conn, err error)
}

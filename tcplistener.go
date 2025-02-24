package socks5

import "net"

type TCPListener interface {
	ListenTCP(addr *net.TCPAddr) (net.Listener, error)
}

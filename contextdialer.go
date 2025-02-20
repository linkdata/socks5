package socks5

import (
	"context"
	"net"
)

type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

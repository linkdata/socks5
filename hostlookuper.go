package socks5

import "context"

type HostLookuper interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

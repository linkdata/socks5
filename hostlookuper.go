package socks5

import "context"

// HostLookuper is the signature of net.DefaultResolver.LookupHost
type HostLookuper interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

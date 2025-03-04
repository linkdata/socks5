package server

import (
	"io"

	"github.com/linkdata/socks5"
)

// Request is the request packet
type Request struct {
	Addr socks5.Addr
	Cmd  socks5.CommandType
}

// ReadRequest read request packet from client
func ReadRequest(r io.Reader) (req *Request, err error) {
	bb := make([]byte, 3)
	if _, err = io.ReadFull(r, bb); err == nil {
		if err = socks5.MustEqual(bb[0], socks5.Socks5Version, socks5.ErrVersion); err == nil {
			var addr socks5.Addr
			if addr, err = socks5.ReadAddr(r); err == nil {
				req = &Request{
					Addr: addr,
					Cmd:  socks5.CommandType(bb[1]),
				}
			}
		}
	}
	return
}

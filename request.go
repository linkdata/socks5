package socks5

import (
	"errors"
	"io"
)

// Request is the request packet
type Request struct {
	Addr Addr
	Cmd  CommandType
}

var ErrVersion = errors.New("invalid SOCKS version")

// ReadRequest read request packet from client
func ReadRequest(r io.Reader) (req *Request, err error) {
	bb := make([]byte, 3)
	if _, err = io.ReadFull(r, bb); err == nil {
		if err = MustEqual(bb[0], Socks5Version, ErrVersion); err == nil {
			var addr Addr
			if addr, err = ReadAddr(r); err == nil {
				req = &Request{
					Addr: addr,
					Cmd:  CommandType(bb[1]),
				}
			}
		}
	}
	return
}

package socks5

import (
	"bytes"
	"errors"
)

type UdpRequest struct {
	Addr Addr
	Frag byte
}

var ErrInvalidUdpRequest = errors.New("invalid udp request header")

func requireValidHeader(data []byte) (err error) {
	if len(data) < 4 || !(data[0] == 0 && data[1] == 0) {
		err = ErrInvalidUdpRequest
	}
	return
}

func ParseUDPRequest(data []byte) (req *UdpRequest, body []byte, err error) {
	if err = requireValidHeader(data); err == nil {
		frag := data[2]
		reader := bytes.NewReader(data[3:])
		var addr Addr
		if addr, err = ParseAddr(reader); err == nil {
			bodyLen := reader.Len()
			body = data[len(data)-bodyLen:]
			req = &UdpRequest{
				Frag: frag,
				Addr: addr,
			}
		}
	}
	return
}

func (u *UdpRequest) AppendBinary(inbuf []byte) (outbuf []byte, err error) {
	outbuf = append(inbuf, 0, 0, u.Frag)
	outbuf, err = u.Addr.AppendBinary(outbuf)
	return
}

func (u *UdpRequest) MarshalBinary() (pkt []byte, err error) {
	return u.AppendBinary(nil)
}

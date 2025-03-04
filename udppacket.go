package socks5

import (
	"bytes"
)

type UDPPacket struct {
	Addr Addr
	Body []byte
}

func requireValidHeader(data []byte) (err error) {
	if len(data) < 4 || data[0] != 0 || data[1] != 0 {
		err = ErrInvalidUDPPacket
	} else if data[2] != 0 {
		err = ErrFragmentedUDPPacket
	}
	return
}

func ParseUDPPacket(data []byte) (pkt *UDPPacket, err error) {
	if err = requireValidHeader(data); err == nil {
		reader := bytes.NewReader(data[3:])
		var addr Addr
		if addr, err = ReadAddr(reader); err == nil {
			pkt = &UDPPacket{
				Addr: addr,
				Body: data[len(data)-reader.Len():],
			}
		}
	}
	return
}

func (u *UDPPacket) AppendBinary(inbuf []byte) (outbuf []byte, err error) {
	outbuf = append(inbuf, 0, 0, 0)
	if outbuf, err = u.Addr.AppendBinary(outbuf); err == nil {
		outbuf = append(outbuf, u.Body...)
	}
	return
}

func (u *UDPPacket) MarshalBinary() (pkt []byte, err error) {
	return u.AppendBinary(nil)
}

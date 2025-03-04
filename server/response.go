package server

import "github.com/linkdata/socks5"

// Response contains the contents of
// a Response packet sent from the proxy
// to the client.
type Response struct {
	Addr  socks5.Addr
	Reply socks5.ReplyCode
}

// MarshalBinary converts a Response struct into a packet.
func (res *Response) MarshalBinary() (pkt []byte, err error) {
	pkt = append(pkt, socks5.Socks5Version, byte(res.Reply), 0)
	pkt, err = res.Addr.AppendBinary(pkt)
	return
}

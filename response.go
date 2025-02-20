package socks5

// Response contains the contents of
// a Response packet sent from the proxy
// to the client.
type Response struct {
	Addr  Addr
	Reply ReplyCode
}

// MarshalBinary converts a Response struct into a packet.
func (res *Response) MarshalBinary() (pkt []byte, err error) {
	pkt = append(pkt, Socks5Version, byte(res.Reply), 0)
	pkt, err = res.Addr.AppendBinary(pkt)
	return
}

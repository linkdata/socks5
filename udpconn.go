package socks5

import (
	"errors"
	"net"
)

type errUnsupportedMethod string

func (eu errUnsupportedMethod) Error() string {
	return errors.ErrUnsupported.Error() + ": " + string(eu)
}

func (eu errUnsupportedMethod) Is(tgt error) bool {
	return tgt == errors.ErrUnsupported
}

var _ net.PacketConn = &UDPConn{}

type UDPConn struct {
	proxyAddress  net.Addr
	defaultTarget net.Addr
	net.PacketConn
}

type udpAddr struct {
	Addr
}

func (ua udpAddr) Network() string {
	return "udp"
}

func NewUDPConn(raw net.PacketConn, proxyAddress net.Addr, defaultTarget net.Addr) (*UDPConn, error) {
	conn := &UDPConn{
		proxyAddress:  proxyAddress,
		defaultTarget: defaultTarget,
		PacketConn:    raw,
	}
	return conn, nil
}

const maxUDPPrefixLength = 3 + 1 + 1 + 255 + 2 // hdr + addrType + strLen + domainName + port

func (c *UDPConn) ReadFrom(p []byte) (n int, netaddr net.Addr, err error) {
	buf := make([]byte, len(p)+maxUDPPrefixLength)
	if n, netaddr, err = c.PacketConn.ReadFrom(buf); err == nil {
		if err = MustEqual(netaddr.String(), c.proxyAddress.String(), ErrInvalidUDPPacket); err == nil {
			var pkt *UDPPacket
			if pkt, err = ParseUDPPacket(buf[:n]); err == nil {
				n = copy(p, pkt.Body)
				netaddr = udpAddr{Addr: pkt.Addr}
			}
		}
	}
	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	for err == nil {
		var netaddr net.Addr
		if n, netaddr, err = c.ReadFrom(b); err == nil {
			if netaddr.String() == c.defaultTarget.String() {
				break
			}
		}
	}
	return
}

func (c *UDPConn) WriteTo(p []byte, netaddr net.Addr) (n int, err error) {
	var addr Addr
	if addr, err = AddrFromString(netaddr.String()); err == nil {
		var buf []byte
		buf = append(buf, 0, 0, 0) // udp prefix
		if buf, err = addr.AppendBinary(buf); err == nil {
			prefixlen := len(buf)
			buf = append(buf, p...)
			n, err = c.PacketConn.WriteTo(buf, c.proxyAddress)
			n -= prefixlen
			if n < 0 {
				n = 0
			}
		}
	}
	return
}

func (c *UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.defaultTarget)
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.defaultTarget
}

func (c *UDPConn) SetReadBuffer(bytes int) (err error) {
	err = errUnsupportedMethod("SetReadBuffer")
	if x, ok := c.PacketConn.(interface{ SetReadBuffer(bytes int) error }); ok {
		err = x.SetReadBuffer(bytes)
	}
	return
}

func (c *UDPConn) SetWriteBuffer(bytes int) (err error) {
	err = errUnsupportedMethod("SetWriteBuffer")
	if x, ok := c.PacketConn.(interface{ SetWriteBuffer(bytes int) error }); ok {
		err = x.SetWriteBuffer(bytes)
	}
	return
}

func (c *UDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	err = errUnsupportedMethod("ReadFromUDP")
	if x, ok := c.PacketConn.(interface {
		ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	}); ok {
		n, addr, err = x.ReadFromUDP(b)
	}
	return
}

func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	err = errUnsupportedMethod("ReadMsgUDP")
	if x, ok := c.PacketConn.(interface {
		ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
	}); ok {
		n, oobn, flags, addr, err = x.ReadMsgUDP(b, oob)
	}
	return
}

func (c *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	err = errUnsupportedMethod("WriteToUDP")
	if udpConn, ok := c.PacketConn.(interface {
		WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	}); ok {
		n, err = udpConn.WriteToUDP(b, addr)
	}
	return
}

// WriteMsgUDP implements the net.UDPConn WriteMsgUDP method.
func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	err = errUnsupportedMethod("WriteMsgUDP")
	if udpConn, ok := c.PacketConn.(interface {
		WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
	}); ok {
		n, oobn, err = udpConn.WriteMsgUDP(b, oob, addr)
	}
	return
}

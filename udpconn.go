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
	targetAddr net.Addr
	net.Conn   // connection to the proxy server
}

type udpAddr struct {
	Addr
}

func (ua udpAddr) Network() string {
	return "udp"
}

func NewUDPConn(raw net.Conn, address string) (c *UDPConn, err error) {
	var addr Addr
	if addr, err = AddrFromString(address); err == nil {
		c = &UDPConn{
			targetAddr: addr,
			Conn:       raw,
		}
	}
	return
}

const maxUDPPrefixLength = 3 + 1 + 1 + 255 + 2 // hdr + addrType + strLen + domainName + port

func (c *UDPConn) ReadFrom(p []byte) (n int, netaddr net.Addr, err error) {
	buf := make([]byte, len(p)+maxUDPPrefixLength)
	if n, err = c.Conn.Read(buf); err == nil {
		var pkt *UDPPacket
		if pkt, err = ParseUDPPacket(buf[:n]); err == nil {
			n = copy(p, pkt.Body)
			netaddr = udpAddr{Addr: pkt.Addr}
		}
	}
	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	for err == nil {
		var netaddr net.Addr
		n, netaddr, err = c.ReadFrom(b)
		if netaddr.String() == c.targetAddr.String() {
			break
		}
	}
	return
}

func (c *UDPConn) writeTo(p []byte, addr Addr) (n int, err error) {
	var buf []byte
	buf = append(buf, 0, 0, 0) // udp prefix
	if buf, err = addr.AppendBinary(buf); err == nil {
		prefixlen := len(buf)
		buf = append(buf, p...)
		n, err = c.Conn.Write(buf)
		n -= prefixlen
		n = max(n, 0)
	}
	return
}

func (c *UDPConn) WriteTo(p []byte, netaddr net.Addr) (n int, err error) {
	var addr Addr
	if addr, err = AddrFromString(netaddr.String()); err == nil {
		n, err = c.writeTo(p, addr)
	}
	return
}

func (c *UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.targetAddr)
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.targetAddr
}

func (c *UDPConn) SetReadBuffer(bytes int) (err error) {
	err = errUnsupportedMethod("SetReadBuffer")
	if x, ok := c.Conn.(interface{ SetReadBuffer(bytes int) error }); ok {
		err = x.SetReadBuffer(bytes)
	}
	return
}

func (c *UDPConn) SetWriteBuffer(bytes int) (err error) {
	err = errUnsupportedMethod("SetWriteBuffer")
	if x, ok := c.Conn.(interface{ SetWriteBuffer(bytes int) error }); ok {
		err = x.SetWriteBuffer(bytes)
	}
	return
}

func (c *UDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	err = errUnsupportedMethod("ReadFromUDP")
	if x, ok := c.Conn.(interface {
		ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	}); ok {
		n, addr, err = x.ReadFromUDP(b)
	}
	return
}

func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	err = errUnsupportedMethod("ReadMsgUDP")
	if x, ok := c.Conn.(interface {
		ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
	}); ok {
		n, oobn, flags, addr, err = x.ReadMsgUDP(b, oob)
	}
	return
}

func (c *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	err = errUnsupportedMethod("WriteToUDP")
	if udpConn, ok := c.Conn.(interface {
		WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	}); ok {
		n, err = udpConn.WriteToUDP(b, addr)
	}
	return
}

// WriteMsgUDP implements the net.UDPConn WriteMsgUDP method.
func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	err = errUnsupportedMethod("WriteMsgUDP")
	if udpConn, ok := c.Conn.(interface {
		WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
	}); ok {
		n, oobn, err = udpConn.WriteMsgUDP(b, oob, addr)
	}
	return
}

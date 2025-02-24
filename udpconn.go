package socks5

import (
	"net"
)

var _ net.PacketConn = &UDPConn{}

type UDPConn struct {
	targetAddr net.Addr
	net.Conn   // connection to the proxy server
}

type udpAddr struct {
	net.Addr
}

func (ua udpAddr) Network() string {
	return "udp"
}

func NewUDPConn(raw net.Conn, address string) (c *UDPConn, err error) {
	var addr Addr
	if addr, err = AddrFromString(address); err == nil {
		c = &UDPConn{
			targetAddr: udpAddr{addr},
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

package socks5

import (
	"encoding"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// AddrType are the bytes sent in SOCKS5 packets
// that represent particular address types.
type AddrType byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	Ipv4       AddrType = 1
	DomainName AddrType = 3
	Ipv6       AddrType = 4
)

type Addr struct {
	Addr string
	Port uint16
	Type AddrType
}

var _ encoding.BinaryMarshaler = Addr{}
var _ encoding.BinaryAppender = Addr{}

var (
	ErrInvalidIPv4Address     = errors.New("invalid IPv4 address for binding")
	ErrInvalidIPv6Address     = errors.New("invalid IPv6 address for binding")
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	ErrInvalidDomainName      = errors.New("invalid domain name for binding")
)

var ZeroAddr = Addr{Type: Ipv4, Addr: "0.0.0.0", Port: 0}

func AddrFromHostPort(host string, port uint16) (addr Addr) {
	if host != "" {
		addr.Addr = host
		if ipaddr, err := netip.ParseAddr(host); err == nil {
			ipaddr = ipaddr.Unmap()
			if ipaddr.Is4() {
				addr.Type = Ipv4
			} else {
				addr.Type = Ipv6
			}
		} else {
			addr.Type = DomainName
		}
	} else {
		addr = ZeroAddr
	}
	addr.Port = port
	return
}

func AddrFromString(s string) (addr Addr, err error) {
	var host string
	var port uint16
	if host, port, err = SplitHostPort(s); err == nil {
		addr = AddrFromHostPort(host, port)
	}
	return
}

func ReadAddr(r io.Reader) (addr Addr, err error) {
	var addrTypeData [1]byte
	if _, err = io.ReadFull(r, addrTypeData[:]); err == nil {
		addr.Type = AddrType(addrTypeData[0])
		switch addr.Type {
		case Ipv4:
			var ip [4]byte
			if _, err = io.ReadFull(r, ip[:]); err == nil {
				addr.Addr = netip.AddrFrom4(ip).String()
			}
		case DomainName:
			var dstSizeByte [1]byte
			if _, err = io.ReadFull(r, dstSizeByte[:]); err == nil {
				dstSize := int(dstSizeByte[0])
				domainName := make([]byte, dstSize)
				if _, err = io.ReadFull(r, domainName); err == nil {
					addr.Addr = string(domainName)
				}
			}
		case Ipv6:
			var ip [16]byte
			if _, err = io.ReadFull(r, ip[:]); err == nil {
				addr.Addr = netip.AddrFrom16(ip).String()
			}
		default:
			err = ErrUnsupportedAddressType
		}
		if err == nil {
			var portBytes [2]byte
			if _, err = io.ReadFull(r, portBytes[:]); err == nil {
				addr.Port = binary.BigEndian.Uint16(portBytes[:])
			}
		}
	}
	return
}

func requireIPv4(s string) (addr netip.Addr, err error) {
	if addr, err = netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		if !addr.Is4() {
			err = ErrInvalidIPv4Address
		}
	}
	return
}

func requireIPv6(s string) (addr netip.Addr, err error) {
	if addr, err = netip.ParseAddr(s); err == nil {
		if !addr.Is6() {
			err = ErrInvalidIPv6Address
		}
	}
	return
}

func (s Addr) AppendBinary(inbuf []byte) (outbuf []byte, err error) {
	var data []byte
	var addr netip.Addr
	switch s.Type {
	case Ipv4:
		if addr, err = requireIPv4(s.Addr); err == nil {
			data, err = addr.AppendBinary(data)
		}
	case DomainName:
		if err = MustStr(s.Addr, ErrInvalidDomainName); err == nil {
			data = append(data, byte(len(s.Addr)))
			data = append(data, []byte(s.Addr)...)
		}
	case Ipv6:
		if addr, err = requireIPv6(s.Addr); err == nil {
			data, err = addr.AppendBinary(data)
		}
	default:
		err = ErrUnsupportedAddressType
	}
	if err == nil {
		outbuf = append(inbuf, byte(s.Type))
		outbuf = append(outbuf, data...)
		outbuf = binary.BigEndian.AppendUint16(outbuf, s.Port)
	}
	return
}

func (s Addr) MarshalBinary() ([]byte, error) {
	return s.AppendBinary(nil)
}

func (s Addr) Network() string {
	return "tcp"
}

func (s Addr) String() string {
	return net.JoinHostPort(s.Addr, strconv.Itoa(int(s.Port)))
}

func (s *Addr) IsAny() bool {
	return s.Addr == "0.0.0.0" || s.Addr == "::"
}

func (s *Addr) ReplaceAny(hostport string) {
	if s.IsAny() {
		if nip, err := netip.ParseAddrPort(hostport); err == nil {
			addr := nip.Addr()
			addr = addr.Unmap()
			s.Addr = addr.String()
			s.Type = Ipv4
			if addr.Is6() {
				s.Type = Ipv6
			}
		}
	}
}

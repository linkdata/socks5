package socks5_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/linkdata/socks5"
)

func TestAddr_MarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		addr    socks5.Addr
		want    []byte
		wantErr bool
	}{
		{
			name:    "ZeroAddr",
			addr:    socks5.ZeroAddr,
			want:    []byte{1, 0, 0, 0, 0, 0, 0},
			wantErr: false,
		},
		{
			name: "DomainName",
			addr: socks5.Addr{
				Type: socks5.DomainName,
				Addr: "foo.bar",
				Port: 1234,
			},
			want:    []byte{0x3, 0x7, 0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x4, 0xd2},
			wantErr: false,
		},
		{
			name: "IPv4",
			addr: socks5.Addr{
				Type: socks5.Ipv4,
				Addr: "127.0.0.1",
				Port: 8080,
			},
			want:    []byte{0x1, 0x7f, 0x0, 0x0, 0x1, 0x1f, 0x90},
			wantErr: false,
		},
		{
			name: "IPv6",
			addr: socks5.Addr{
				Type: socks5.Ipv6,
				Addr: "2001:0:130f::9c0:876a:130b",
				Port: 8081,
			},
			want:    []byte{0x4, 0x20, 0x1, 0x0, 0x0, 0x13, 0xf, 0x0, 0x0, 0x0, 0x0, 0x9, 0xc0, 0x87, 0x6a, 0x13, 0xb, 0x1f, 0x91},
			wantErr: false,
		},
		{
			name: "InvalidDomainName",
			addr: socks5.Addr{
				Type: socks5.DomainName,
				Addr: strings.Repeat("x", 256),
			},
			wantErr: true,
		},
		{
			name: "InvalidIPv4",
			addr: socks5.Addr{
				Type: socks5.Ipv4,
				Addr: "2001:0:130f::9c0:876a:130b",
			},
			wantErr: true,
		},
		{
			name: "InvalidIPv6",
			addr: socks5.Addr{
				Type: socks5.Ipv6,
				Addr: "127.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "InvalidType",
			addr: socks5.Addr{
				Type: socks5.AddrType(0),
				Addr: "127.0.0.1",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.addr.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("Addr.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Addr.MarshalBinary()\n got %#v\nwant %#v\n", got, tt.want)
			}
			gotaddr, err := socks5.ParseAddr(bytes.NewReader(got))
			if !tt.wantErr {
				if err != nil {
					t.Errorf("ParseAddr() error = %v", err)
					return
				}
				if !reflect.DeepEqual(gotaddr, tt.addr) {
					t.Errorf("ParseAddr()\n got %#v\nwant %#v\n", gotaddr, tt.addr)
				}
			} else {
				if err == nil {
					t.Errorf("ParseAddr() returned no error")
				}
			}
		})
	}
}

func TestAddr_String(t *testing.T) {
	addr := socks5.Addr{
		Type: socks5.DomainName,
		Addr: "foo.bar",
		Port: 1234,
	}
	if x := addr.String(); x != "foo.bar:1234" {
		t.Error(x)
	}
}

func TestParseAddr(t *testing.T) {
	_, err := socks5.ParseAddr(bytes.NewReader([]byte{0x0, 0x7f, 0x0, 0x0, 0x1, 0x1f, 0x90}))
	if err != socks5.ErrUnsupportedAddressType {
		t.Error(err)
	}
}

func TestMakeAddr(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		port     uint16
		wantAddr socks5.Addr
	}{
		{
			name:     "empty",
			s:        "",
			port:     0,
			wantAddr: socks5.ZeroAddr,
		},
		{
			name:     "ipv4",
			s:        "127.0.0.1",
			port:     100,
			wantAddr: socks5.Addr{Addr: "127.0.0.1", Port: 100, Type: socks5.Ipv4},
		},
		{
			name:     "ipv6",
			s:        "2001:0:130f::9c0:876a:130b",
			port:     100,
			wantAddr: socks5.Addr{Addr: "2001:0:130f::9c0:876a:130b", Port: 100, Type: socks5.Ipv6},
		},
		{
			name:     "domainname",
			s:        "localhost",
			wantAddr: socks5.Addr{Addr: "localhost", Port: 0, Type: socks5.DomainName},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotAddr := socks5.MakeAddr(tt.s, tt.port); !reflect.DeepEqual(gotAddr, tt.wantAddr) {
				t.Errorf("MakeAddr() = %v, want %v", gotAddr, tt.wantAddr)
			}
		})
	}
}

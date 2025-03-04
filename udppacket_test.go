package socks5_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/linkdata/socks5"
)

var normalPacket = []byte{0, 0, 0, byte(socks5.DomainName), 1, 'x', 0, 1, 2}

func TestParseUDPPacket_Invalid(t *testing.T) {
	_, err := socks5.ParseUDPPacket(nil)
	if err != socks5.ErrInvalidUDPPacket {
		t.Error(err)
	}
	_, err = socks5.ParseUDPPacket([]byte{0, 0, 1, 0})
	if err != socks5.ErrFragmentedUDPPacket {
		t.Error(err)
	}
	_, err = socks5.ParseUDPPacket([]byte{0, 0, 0, 0})
	if err != socks5.ErrUnsupportedAddressType {
		t.Error(err)
	}
}

func TestUDPPacket_MarshalBinary(t *testing.T) {
	pkt, err := socks5.ParseUDPPacket(normalPacket)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pkt.Addr, socks5.Addr{Addr: "x", Type: socks5.DomainName, Port: 1}) {
		t.Error(pkt.Addr)
	}
	if !bytes.Equal(pkt.Body, []byte{2}) {
		t.Error(pkt.Body)
	}
	b, err := pkt.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, normalPacket) {
		t.Error(b)
	}
}

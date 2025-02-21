package socks5_test

import (
	"testing"

	"github.com/linkdata/socks5"
)

func TestParseUDPRequest_Invalid(t *testing.T) {
	_, err := socks5.ParseUDPPacket(nil)
	if err != socks5.ErrInvalidUDPPacket {
		t.Error(err)
	}
	_, err = socks5.ParseUDPPacket([]byte{0, 0, 1, 0})
	if err != socks5.ErrFragmentedUDPPacket {
		t.Error(err)
	}
}

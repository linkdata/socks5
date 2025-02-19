package socks5_test

import (
	"testing"

	"github.com/linkdata/socks5"
)

func TestParseUDPRequest_Invalid(t *testing.T) {
	_, _, err := socks5.ParseUDPRequest(nil)
	if err != socks5.ErrInvalidUdpRequest {
		t.Error(err)
	}
}

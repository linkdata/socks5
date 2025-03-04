package server_test

import (
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5test"
)

func init() {
	socks5.UDPTimeout = time.Millisecond * 10
}

func TestUDP_Single(t *testing.T) {
	socks5test.UDP_Single(t, srvfn, clifn)
}

func TestUDP_Multiple(t *testing.T) {
	socks5test.UDP_Multiple(t, srvfn, clifn)
}

func TestUDP_InvalidPacket(t *testing.T) {
	socks5test.UDP_InvalidPacket(t, srvfn, clifn)
}

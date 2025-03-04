package server_test

import (
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5test"
)

func init() {
	socks5.ListenerTimeout = time.Millisecond * 10
}

func TestListen_SingleRequest(t *testing.T) {
	socks5test.Listen_SingleRequest(t, srvfn, clifn)
}

func TestListen_SerialRequests(t *testing.T) {
	socks5test.Listen_SerialRequests(t, srvfn, clifn)
}

func TestListen_ParallelRequests(t *testing.T) {
	socks5test.Listen_ParallelRequests(t, srvfn, clifn)
}

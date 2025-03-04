package server_test

import (
	"testing"

	"github.com/linkdata/socks5test"
)

func Test_Resolve_Local(t *testing.T) {
	socks5test.Resolve_Local(t, srvfn, clifn)
}

func Test_Resolve_Local_InvalidHostname(t *testing.T) {
	socks5test.Resolve_Local_InvalidHostname(t, srvfn, clifn)
}

func Test_Resolve_Remote(t *testing.T) {
	socks5test.Resolve_Remote(t, srvfn, clifn)
}

func Test_Resolve_Remote_InvalidHostname(t *testing.T) {
	socks5test.Resolve_Remote_InvalidHostname(t, srvfn, clifn)
}

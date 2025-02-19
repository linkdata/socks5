package socks5_test

import (
	"testing"

	"github.com/linkdata/socks5"
)

func TestMustEqual(t *testing.T) {
	if x := socks5.MustEqual(1, 1, socks5.ErrVersion); x != nil {
		t.Error(x)
	}
	if x := socks5.MustEqual(0, 1, socks5.ErrVersion); x != socks5.ErrVersion {
		t.Error(x)
	}
}

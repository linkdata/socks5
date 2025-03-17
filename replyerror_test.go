package socks5_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/linkdata/socks5"
)

func TestReplyError(t *testing.T) {
	err := socks5.ErrReplyConnectionRefused
	if !strings.Contains(err.Error(), "refused") {
		t.Error(err.Error())
	}
	if !errors.Is(err, socks5.ErrReplyConnectionRefused) {
		t.Error(err)
	}
	if !errors.Is(err, socks5.ErrReply) {
		t.Errorf("%#v", err)
	}
	if errors.Is(err, socks5.ErrReplyHostUnreachable) {
		t.Error(err)
	}

	re := socks5.ReplyError{99}
	if x := re.Error(); x != "socks5code(99)" {
		t.Error(x)
	}
}

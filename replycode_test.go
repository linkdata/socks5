package socks5

import "testing"

func TestReplyCode_ToError(t *testing.T) {
	for k, v := range replyCodeError {
		if k.ToError() != v {
			t.Error(k, v)
		}
	}
	code := ReplyCode(254)
	if x := code.ToError().Error(); x != "socks5code(254)" {
		t.Error(x)
	}
}

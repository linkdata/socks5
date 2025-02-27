package socks5

import "testing"

func TestReplyCode_Error(t *testing.T) {
	for k, v := range replyCodeError {
		want := "success"
		if v != nil {
			want = v.Error()
		}
		if k.Error() != want {
			t.Error(k.Error(), want)
		}
	}
	code := ReplyCode(254)
	if code.Error() != "254" {
		t.Error("not 254")
	}
}

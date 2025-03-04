package socks5

import "testing"

func Test_SplitHostPort(t *testing.T) {
	host, port, err := SplitHostPort("host:10")
	if err != nil {
		t.Error(err)
	}
	if host != "host" {
		t.Error(host)
	}
	if port != 10 {
		t.Error(port)
	}
	_, _, err = SplitHostPort("host:-1")
	if err != ErrInvalidPortNumber {
		t.Error(err)
	}
}

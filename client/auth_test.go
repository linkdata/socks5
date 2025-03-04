package client_test

import (
	"testing"

	"github.com/linkdata/socks5test"
)

func TestAuth_None(t *testing.T) {
	socks5test.Auth_None(t, srvfn, clifn)
}

func TestAuth_NoAcceptable(t *testing.T) {
	socks5test.Auth_NoAcceptable(t, srvfn, clifn)
}

func TestAuth_Password(t *testing.T) {
	socks5test.Auth_Password(t, srvfn, clifn)
}

func TestAuth_InvalidPassword(t *testing.T) {
	socks5test.Auth_InvalidPassword(t, srvfn, clifn)
}

func TestAuth_WrongPassword(t *testing.T) {
	socks5test.Auth_WrongPassword(t, srvfn, clifn)
}

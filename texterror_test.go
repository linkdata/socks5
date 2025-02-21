package socks5

import (
	"io"
	"testing"
)

func TestNewTextError(t *testing.T) {
	err := NewTextError(io.EOF, "eof")
	uw := err.(interface{ Unwrap() error })
	if x := uw.Unwrap(); x != io.EOF {
		t.Error(x)
	}
	if x := err.Error(); x != "eof: EOF" {
		t.Error(x)
	}
}

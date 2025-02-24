package socks5_test

import (
	"io"
	"testing"

	"github.com/linkdata/socks5"
)

func TestNote(t *testing.T) {
	err := socks5.Note(io.EOF, "prefix")
	uw := err.(interface{ Unwrap() error })
	if x := uw.Unwrap(); x != io.EOF {
		t.Error(x)
	}
	if x := err.Error(); x != "prefix: "+io.EOF.Error() {
		t.Error(x)
	}
}

package socks5_test

import (
	"errors"
	"io"
	"testing"

	"github.com/linkdata/socks5"
)

func TestJoinErrs(t *testing.T) {
	tests := []struct {
		name string
		errs []error
		want error
	}{
		{
			name: "nil",
			errs: nil,
			want: nil,
		},
		{
			name: "single",
			errs: []error{io.EOF},
			want: io.EOF,
		},
		{
			name: "list",
			errs: []error{io.EOF, io.ErrClosedPipe},
			want: errors.Join(io.EOF, io.ErrClosedPipe),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := socks5.JoinErrs(tt.errs...)
			if tt.want != nil {
				if got.Error() != tt.want.Error() {
					t.Errorf(" got: %#v\nwant: %#v\n", got, tt.want)
				}
			} else if got != nil {
				t.Error("expected nil")
			}
		})
	}
}

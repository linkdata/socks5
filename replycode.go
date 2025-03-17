package socks5

import (
	"fmt"
)

// ReplyCode is the reply code in SOCKS5 packets sent from the server to a client.
type ReplyCode byte

const (
	ReplySuccess              ReplyCode = 0
	ReplyGeneralFailure       ReplyCode = 1
	ReplyConnectionNotAllowed ReplyCode = 2
	ReplyNetworkUnreachable   ReplyCode = 3
	ReplyHostUnreachable      ReplyCode = 4
	ReplyConnectionRefused    ReplyCode = 5
	ReplyTTLExpired           ReplyCode = 6
	ReplyCommandNotSupported  ReplyCode = 7
	ReplyAddrTypeNotSupported ReplyCode = 8
)

var replyCodeError = map[ReplyCode]error{
	ReplySuccess:              nil,
	ReplyGeneralFailure:       ErrReplyGeneralFailure,
	ReplyConnectionNotAllowed: ErrReplyConnectionNotAllowed,
	ReplyNetworkUnreachable:   ErrReplyNetworkUnreachable,
	ReplyHostUnreachable:      ErrReplyHostUnreachable,
	ReplyConnectionRefused:    ErrReplyConnectionRefused,
	ReplyTTLExpired:           ErrReplyTTLExpired,
	ReplyCommandNotSupported:  ErrReplyCommandNotSupported,
	ReplyAddrTypeNotSupported: ErrReplyAddrTypeNotSupported,
}

func (code ReplyCode) ToError() error {
	if err, ok := replyCodeError[code]; ok {
		return err
	}
	return fmt.Errorf("socks5code(%v)", code)
}

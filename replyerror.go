package socks5

import "fmt"

type ReplyError struct {
	ReplyCode
}

var replyErrorText = []string{
	ReplySuccess:              "success",
	ReplyGeneralFailure:       "general failure",
	ReplyConnectionNotAllowed: "connection not allowed",
	ReplyNetworkUnreachable:   "network unreachable",
	ReplyHostUnreachable:      "host unreachable",
	ReplyConnectionRefused:    "connection refused",
	ReplyTTLExpired:           "ttl expired",
	ReplyCommandNotSupported:  "command not supported",
	ReplyAddrTypeNotSupported: "address type not supported",
}

var (
	ErrReply                     = ReplyError{ReplyGeneralFailure} // for testing against with errors.Is()
	ErrReplySuccess              = ReplyError{ReplySuccess}
	ErrReplyGeneralFailure       = ReplyError{ReplyGeneralFailure}
	ErrReplyConnectionNotAllowed = ReplyError{ReplyConnectionNotAllowed}
	ErrReplyNetworkUnreachable   = ReplyError{ReplyNetworkUnreachable}
	ErrReplyHostUnreachable      = ReplyError{ReplyHostUnreachable}
	ErrReplyConnectionRefused    = ReplyError{ReplyConnectionRefused}
	ErrReplyTTLExpired           = ReplyError{ReplyTTLExpired}
	ErrReplyCommandNotSupported  = ReplyError{ReplyCommandNotSupported}
	ErrReplyAddrTypeNotSupported = ReplyError{ReplyAddrTypeNotSupported}
)

func (re ReplyError) Error() string {
	if int(re.ReplyCode) < len(replyErrorText) {
		return replyErrorText[re.ReplyCode]
	}
	return fmt.Sprintf("socks5code(%v)", re.ReplyCode)
}

func (re ReplyError) Is(target error) (yes bool) {
	return target == ErrReply
}

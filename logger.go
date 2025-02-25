package socks5

type Logger interface {
	Info(msg string, keyvaluepairs ...any)
	Error(msg string, keyvaluepairs ...any)
}

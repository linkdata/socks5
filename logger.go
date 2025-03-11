package socks5

// Logger is an abstraction of log/slog.
type Logger interface {
	Info(msg string, keyvaluepairs ...any)
	Error(msg string, keyvaluepairs ...any)
}

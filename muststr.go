package socks5

// MustStr returns nil if s is a non-empty string less than 256 characters, otherwise it returns err.
func MustStr(s string, err error) error {
	if len(s) > 0 && len(s) < 256 {
		return nil
	}
	return err
}

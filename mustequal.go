package socks5

// MustEqual returns nil if a == b, otherwise it returns err.
func MustEqual[T comparable](a, b T, err error) error {
	if a == b {
		return nil
	}
	return err
}

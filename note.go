package socks5

type errNote struct {
	err error
	txt string
}

func (te errNote) Error() string {
	return te.txt + ": " + te.err.Error()
}

func (te errNote) Unwrap() error {
	return te.err
}

// Note returns nil if err is nil, otherwise returns err prefixed with txt, a colon and a space.
func Note(err error, txt string) error {
	if err != nil {
		err = errNote{err: err, txt: txt}
	}
	return err
}

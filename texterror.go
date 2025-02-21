package socks5

type TextError struct {
	err error
	txt string
}

func (te TextError) Error() string {
	return te.txt + ": " + te.err.Error()
}

func (te TextError) Unwrap() error {
	return te.err
}

func NewTextError(err error, txt string) error {
	if err != nil {
		err = TextError{err: err, txt: txt}
	}
	return err
}

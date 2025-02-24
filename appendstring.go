package socks5

func AppendString(inbuf []byte, s string, lengtherror error) (outbuf []byte, err error) {
	if len(s) > 255 {
		err = lengtherror
	} else {
		outbuf = append(inbuf, byte(len(s)))
		outbuf = append(outbuf, s...)
	}
	return
}

package socks5

func AppendString(inbuf []byte, s string, lengtherror error) (outbuf []byte, err error) {
	err = lengtherror
	if len(s) < 256 {
		err = nil
		outbuf = append(inbuf, byte(len(s)))
		outbuf = append(outbuf, s...)
	}
	return
}

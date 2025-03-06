package server

import (
	"io"

	"github.com/linkdata/socks5"
)

// Authenticator provide authentication of users.
type Authenticator interface {
	Method() socks5.AuthMethod
	Authenticate(r io.Reader, w io.Writer, userAddr string) (username string, err error)
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) Method() socks5.AuthMethod { return socks5.NoAuthRequired }

func (a NoAuthAuthenticator) Authenticate(_ io.Reader, w io.Writer, _ string) (username string, err error) {
	_, err = w.Write([]byte{socks5.Socks5Version, byte(a.Method())})
	return
}

// UserPassAuthenticator is used to handle username/password based authentication.
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Method() socks5.AuthMethod { return socks5.PasswordAuth }

func (a UserPassAuthenticator) Authenticate(r io.Reader, w io.Writer, userAddr string) (username string, err error) {
	resultcode := byte(socks5.AuthFailure)
	if _, err = w.Write([]byte{socks5.Socks5Version, byte(a.Method())}); err == nil {
		var hdr [2]byte
		if _, err = io.ReadFull(r, hdr[:]); err == nil {
			if err = socks5.MustEqual(hdr[0], socks5.PasswordAuthVersion, socks5.ErrBadSOCKSAuthVersion); err == nil {
				usrLen := int(hdr[1])
				usrBytes := make([]byte, usrLen)
				if _, err = io.ReadFull(r, usrBytes); err == nil {
					var hdrPwd [1]byte
					if _, err = io.ReadFull(r, hdrPwd[:]); err == nil {
						pwdLen := int(hdrPwd[0])
						pwdBytes := make([]byte, pwdLen)
						if _, err = io.ReadFull(r, pwdBytes); err == nil {
							usr := string(usrBytes)
							err = socks5.ErrAuthFailed
							if a.Credentials.Valid(usr, string(pwdBytes), userAddr) {
								err = nil
								resultcode = socks5.AuthSuccess
								username = usr
							}
						}
					}
				}
			}
		}
	}
	_, e := w.Write([]byte{socks5.PasswordAuthVersion, resultcode})
	err = socks5.JoinErrs(err, e)
	return
}

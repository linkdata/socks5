package server

import (
	"io"

	"github.com/linkdata/socks5"
)

// Authenticator provide authentication of users.
type Authenticator interface {
	// Socks5Authenticate provide authentication of users. Return socks5.ErrAuthMethodNotSupported if the method is
	// not supported by the authenticator.
	Socks5Authenticate(rw io.ReadWriter, am socks5.AuthMethod, address string) (username string, err error)
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) Socks5Authenticate(rw io.ReadWriter, am socks5.AuthMethod, _ string) (username string, err error) {
	err = socks5.ErrAuthMethodNotSupported
	if am == socks5.AuthMethodNone {
		_, err = rw.Write([]byte{socks5.Socks5Version, byte(am)})
	}
	return
}

// UserPassAuthenticator is used to handle username/password based authentication.
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Socks5Authenticate(rw io.ReadWriter, am socks5.AuthMethod, address string) (username string, err error) {
	err = socks5.ErrAuthMethodNotSupported
	if am == socks5.AuthUserPass {
		resultcode := byte(socks5.AuthFailure)
		if _, err = rw.Write([]byte{socks5.Socks5Version, byte(am)}); err == nil {
			var hdr [2]byte
			if _, err = io.ReadFull(rw, hdr[:]); err == nil {
				if err = socks5.MustEqual(hdr[0], socks5.AuthUserPassVersion, socks5.ErrBadSOCKSAuthVersion); err == nil {
					usrLen := int(hdr[1])
					usrBytes := make([]byte, usrLen)
					if _, err = io.ReadFull(rw, usrBytes); err == nil {
						var hdrPwd [1]byte
						if _, err = io.ReadFull(rw, hdrPwd[:]); err == nil {
							pwdLen := int(hdrPwd[0])
							pwdBytes := make([]byte, pwdLen)
							if _, err = io.ReadFull(rw, pwdBytes); err == nil {
								usr := string(usrBytes)
								err = socks5.ErrAuthFailed
								if a.Credentials.Socks5ValidateCredentials(usr, string(pwdBytes), address) {
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
		_, e := rw.Write([]byte{socks5.AuthUserPassVersion, resultcode})
		err = socks5.JoinErrs(err, e)
	}
	return
}

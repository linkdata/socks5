package server

// CredentialStore is used to support user/pass authentication optional network addr
// if you want to limit user network addr,you can refuse it.
type CredentialStore interface {
	Socks5ValidateCredentials(user, password, userAddr string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

// Socks5ValidateCredentials implement interface CredentialStore
func (s StaticCredentials) Socks5ValidateCredentials(user, password, _ string) bool {
	pass, ok := s[user]
	return ok && password == pass
}

package server

// CredentialStore is used to support user/pass authentication optional network address filtering.
type CredentialStore interface {
	Socks5ValidateCredentials(username, password, address string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

// Socks5ValidateCredentials implement interface CredentialStore
func (s StaticCredentials) Socks5ValidateCredentials(username, password, _ string) bool {
	pass, ok := s[username]
	return ok && password == pass
}

package server

// CredentialsValidator is used to support user/pass authentication optional network address filtering.
type CredentialsValidator interface {
	ValidateCredentials(username, password, address string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) ValidateCredentials(username, password, _ string) bool {
	pass, ok := s[username]
	return ok && password == pass
}

package cookiecrypt

import "errors"

var (
	// ErrInvalidKey reports a configured key that is not 64 hex characters
	// decoding to 32 bytes.
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidCiphertext reports a cookie value that could not be
	// authenticated and decrypted with any configured key.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

package cookiecrypt

import "errors"

var (
	ErrInvalidKey        = errors.New("invalid key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

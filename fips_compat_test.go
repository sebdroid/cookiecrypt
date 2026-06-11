//go:build !go1.26

package cookiecrypt

// Pre-1.26 toolchains cannot detect FIPS 140-only mode, so x/crypto lets
// ChaCha20-Poly1305 run (non-compliantly) instead of rejecting it.
const chachaFIPSEnforced = false

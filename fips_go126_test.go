//go:build go1.26

package cookiecrypt

// x/crypto rejects non-approved ciphers in FIPS 140-only mode via
// crypto/fips140.Enforced, which requires Go 1.26.
const chachaFIPSEnforced = true

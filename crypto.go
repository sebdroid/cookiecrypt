package cookiecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Supported AEAD ciphers. Both use 96-bit nonces, so both share the
// ~2^32-encryptions-per-key bound; rotate keys well before that (see README).
const (
	CipherAESGCM           = "aes-gcm"           // NIST SP 800-38D
	CipherChaCha20Poly1305 = "chacha20-poly1305" // RFC 8439
)

const keyBytes = 32

// Browsers only guarantee ~50 cookies per domain (RFC 6265 §6.1), so larger
// splits can't round-trip; the cap also bounds work from forged count headers.
const maxChunks = 32

func (cc *Cookiecrypt) Provision(ctx caddy.Context) error {
	cc.logger = ctx.Logger()
	return cc.provision()
}

// provision is Provision minus the caddy.Context dependency, for tests.
func (cc *Cookiecrypt) provision() error {
	if cc.Prefix == nil {
		cc.prefix = "cc_"
	} else {
		cc.prefix = *cc.Prefix // "" enables no-prefix mode
	}
	if cc.Cipher == "" {
		cc.Cipher = CipherAESGCM
	}
	if cc.MaxCookieSize == 0 {
		cc.MaxCookieSize = 4096
	}

	repl := caddy.NewReplacer()
	cc.aeads = nil
	for i, k := range cc.Keys {
		resolved, err := repl.ReplaceOrErr(k, true, true)
		if err != nil {
			return fmt.Errorf("key %d: %w", i+1, err)
		}
		// Keys from {file.*} placeholders often carry stray whitespace.
		raw, err := hex.DecodeString(strings.TrimSpace(resolved))
		if err != nil {
			return fmt.Errorf("key %d: %w: not valid hex: %v", i+1, ErrInvalidKey, err)
		}
		if len(raw) != keyBytes {
			return fmt.Errorf("key %d: %w: need %d bytes (%d hex chars), got %d",
				i+1, ErrInvalidKey, keyBytes, keyBytes*2, len(raw))
		}
		aead, err := newAEAD(cc.Cipher, raw)
		if err != nil {
			return err
		}
		cc.aeads = append(cc.aeads, aead)
	}
	return nil
}

func (cc *Cookiecrypt) Validate() error {
	if len(cc.Keys) == 0 {
		return fmt.Errorf("%w: at least one key is required", ErrInvalidKey)
	}
	if cc.MaxCookieSize < 512 {
		return fmt.Errorf("max_cookie_size must be at least 512, got %d", cc.MaxCookieSize)
	}
	if cc.Prefix != nil && *cc.Prefix != "" && !isToken(*cc.Prefix) {
		return fmt.Errorf("prefix must be an RFC 6265 token or empty (no-prefix mode), got %q", *cc.Prefix)
	}
	for _, p := range append(append([]string{}, cc.AllowInbound...), cc.AllowOutbound...) {
		pat := strings.TrimPrefix(p, "!")
		if pat == "" {
			return fmt.Errorf("invalid pattern %q: empty", p)
		}
		// path.Match (Go ≥1.16) reports ErrBadPattern even on early mismatch,
		// so a single probe validates the whole pattern.
		if _, err := path.Match(pat, "probe"); err != nil {
			return fmt.Errorf("invalid pattern %q: %w", p, err)
		}
	}
	return nil
}

func newAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	switch cipherName {
	case CipherAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("cipher %s: %w", CipherAESGCM, err)
		}
		// NewGCMWithRandomNonce prepends its internally generated nonce,
		// matching the manual nonce‖ciphertext‖tag wire format, and unlike
		// NewGCM is allowed under GODEBUG=fips140=only (which rejects
		// externally supplied nonces).
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, fmt.Errorf("cipher %s: %w", CipherAESGCM, err)
		}
		return aead, nil
	case CipherChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			if fips140.Enabled() {
				return nil, fmt.Errorf("cipher %s: %w; use the default %s, which is FIPS-approved",
					CipherChaCha20Poly1305, err, CipherAESGCM)
			}
			return nil, fmt.Errorf("cipher %s: %w", CipherChaCha20Poly1305, err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unknown cipher %q", cipherName)
	}
}

// encrypt seals value with AAD = the cookie's original name, so a ciphertext
// can never be replayed under another cookie's name.
func encrypt(aead cipher.AEAD, name, value string) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(value), []byte(name))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// decrypt tries every configured key (rotation: first key encrypts, all keys
// decrypt) with AAD = the cookie's original name.
func (cc *Cookiecrypt) decrypt(name, encoded string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	for _, aead := range cc.aeads {
		if len(raw) < aead.NonceSize()+aead.Overhead() {
			return "", ErrInvalidCiphertext
		}
		plaintext, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(name))
		if err == nil {
			return string(plaintext), nil
		}
	}
	return "", ErrInvalidCiphertext
}

// Browser-enforced name prefixes (RFC 6265bis) must stay outermost when
// renaming, or the browser's storage-time enforcement is silently lost.
var specialPrefixes = [...]string{"__Host-", "__Secure-"}

func splitSpecialPrefix(name string) (special, base string) {
	for _, p := range specialPrefixes {
		if strings.HasPrefix(name, p) {
			return p, name[len(p):]
		}
	}
	return "", name
}

// escapeName doubles dots, so escaped names contain only even dot runs and
// chunk suffixes (".1"…) can never collide with an encrypted name.
func escapeName(base string) string {
	return strings.ReplaceAll(base, ".", "..")
}

// unescapeName reverses escapeName. Odd dot runs are invalid: chunk cookies
// (consumed by reassembly, never parsed here), orphans, or forgeries.
func unescapeName(escaped string) (string, bool) {
	if !strings.Contains(escaped, ".") {
		return escaped, true
	}
	out := make([]byte, 0, len(escaped))
	for i := 0; i < len(escaped); {
		if escaped[i] != '.' {
			out = append(out, escaped[i])
			i++
			continue
		}
		j := i
		for j < len(escaped) && escaped[j] == '.' {
			j++
		}
		run := j - i
		if run%2 != 0 {
			return "", false
		}
		for range run / 2 {
			out = append(out, '.')
		}
		i = j
	}
	return string(out), true
}

// encryptedName maps "X.1" → "cc_X..1" and "__Host-s" → "__Host-cc_s".
func (cc *Cookiecrypt) encryptedName(name string) string {
	special, base := splitSpecialPrefix(name)
	return special + cc.prefix + escapeName(base)
}

// matchAny reports whether name matches any positive pattern and no
// "!"-negated one (deny overrides). `\!` matches a literal leading '!'.
func matchAny(patterns []string, name string) bool {
	matched := false
	for _, p := range patterns {
		if negated, isNeg := strings.CutPrefix(p, "!"); isNeg {
			if matchOne(negated, name) {
				return false
			}
			continue
		}
		if !matched && matchOne(p, name) {
			matched = true
		}
	}
	return matched
}

// matchOne ignores the match error: cookie names cannot contain '/', and
// Validate has already rejected malformed patterns.
func matchOne(pattern, name string) bool {
	if !strings.ContainsAny(pattern, `*?[\`) {
		return pattern == name
	}
	ok, _ := path.Match(pattern, name)
	return ok
}

// isToken reports whether s is a non-empty RFC 6265 cookie-name token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// parseChunkCount accepts strictly 2–maxChunks: decimal, no leading zeros.
func parseChunkCount(s string) (int, bool) {
	if len(s) == 0 || len(s) > 2 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 2 || n > maxChunks {
		return 0, false
	}
	return n, true
}

// validCookieValue mirrors net/http's value byte rules (optional surrounding
// quotes, then 0x20–0x7E minus '"' ';' '\\'). Defensive: drop, never mutate.
func validCookieValue(v string) bool {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 || b >= 0x7f || b == '"' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}

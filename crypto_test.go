package cookiecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

const (
	testKey1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testKey2 = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)

func ptr[T any](v T) *T { return &v }

// newCC builds a provisioned middleware with sane test defaults.
func newCC(t *testing.T, mutate func(*CookieCrypt)) *CookieCrypt {
	t.Helper()
	cc := &CookieCrypt{Keys: []string{testKey1}}
	if mutate != nil {
		mutate(cc)
	}
	cc.logger = zaptest.NewLogger(t)
	require.NoError(t, cc.provision())
	return cc
}

func mustEncrypt(t *testing.T, cc *CookieCrypt, name, value string) string {
	t.Helper()
	ct, err := encrypt(cc.aeads[0], name, value)
	require.NoError(t, err)
	return ct
}

func TestProvisionKeys(t *testing.T) {
	t.Run("single key", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1}}
		require.NoError(t, cc.provision())
		assert.Len(t, cc.aeads, 1)
	})

	t.Run("multiple keys", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1, testKey2}}
		require.NoError(t, cc.provision())
		assert.Len(t, cc.aeads, 2)
	})

	t.Run("bad hex", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{"zz" + testKey1[2:]}}
		assert.ErrorIs(t, cc.provision(), ErrInvalidKey)
	})

	t.Run("wrong length", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1[:32]}}
		assert.ErrorIs(t, cc.provision(), ErrInvalidKey)
	})

	t.Run("empty key", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{""}}
		assert.ErrorIs(t, cc.provision(), ErrInvalidKey)
	})

	t.Run("env placeholder", func(t *testing.T) {
		t.Setenv("COOKIECRYPT_TEST_KEY", testKey1)
		cc := &CookieCrypt{Keys: []string{"{env.COOKIECRYPT_TEST_KEY}"}}
		require.NoError(t, cc.provision())
		assert.Len(t, cc.aeads, 1)
	})

	t.Run("unset env placeholder", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{"{env.COOKIECRYPT_TEST_UNSET}"}}
		err := cc.provision()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "COOKIECRYPT_TEST_UNSET")
	})

	t.Run("unknown cipher", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1}, Cipher: "rot13"}
		err := cc.provision()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cipher")
	})

	t.Run("AEAD errors carry the cipher name", func(t *testing.T) {
		for _, cipherName := range []string{CipherAESGCM, CipherChaCha20Poly1305} {
			_, err := newAEAD(cipherName, []byte("short"))
			require.Error(t, err, cipherName)
			assert.Contains(t, err.Error(), cipherName)
		}
	})

	t.Run("omitted prefix defaults to cc_", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1}}
		require.NoError(t, cc.provision())
		assert.Equal(t, "cc_", cc.prefix)
	})

	t.Run("explicitly empty prefix enables no-prefix mode", func(t *testing.T) {
		cc := &CookieCrypt{Keys: []string{testKey1}, Prefix: ptr("")}
		require.NoError(t, cc.provision())
		assert.Equal(t, "", cc.prefix)
	})
}

func TestValidate(t *testing.T) {
	valid := func() *CookieCrypt {
		return &CookieCrypt{Keys: []string{testKey1}, Prefix: ptr("cc_"), MaxCookieSize: 4096}
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, valid().Validate())
	})

	t.Run("no keys", func(t *testing.T) {
		cc := valid()
		cc.Keys = nil
		assert.ErrorIs(t, cc.Validate(), ErrInvalidKey)
	})

	t.Run("max_cookie_size too small", func(t *testing.T) {
		cc := valid()
		cc.MaxCookieSize = 256
		assert.Error(t, cc.Validate())
	})

	t.Run("empty prefix is valid (no-prefix mode)", func(t *testing.T) {
		cc := valid()
		cc.Prefix = ptr("")
		assert.NoError(t, cc.Validate())
	})

	t.Run("omitted prefix is valid", func(t *testing.T) {
		cc := valid()
		cc.Prefix = nil
		assert.NoError(t, cc.Validate())
	})

	t.Run("non-token prefix", func(t *testing.T) {
		cc := valid()
		cc.Prefix = ptr("cc prefix")
		assert.Error(t, cc.Validate())
	})

	t.Run("bad pattern", func(t *testing.T) {
		cc := valid()
		cc.AllowOutbound = []string{"a["}
		assert.Error(t, cc.Validate())
	})

	t.Run("bad negated pattern", func(t *testing.T) {
		cc := valid()
		cc.AllowOutbound = []string{"!a["}
		assert.Error(t, cc.Validate())
	})

	t.Run("bare negation", func(t *testing.T) {
		cc := valid()
		cc.AllowInbound = []string{"!"}
		assert.Error(t, cc.Validate())
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, cipherName := range []string{CipherAESGCM, CipherChaCha20Poly1305} {
		t.Run(cipherName, func(t *testing.T) {
			cc := newCC(t, func(cc *CookieCrypt) { cc.Cipher = cipherName })

			ct := mustEncrypt(t, cc, "session", "value-123")
			pt, err := cc.decrypt("session", ct)
			require.NoError(t, err)
			assert.Equal(t, "value-123", pt)

			// Random nonces: same input never yields the same ciphertext.
			assert.NotEqual(t, ct, mustEncrypt(t, cc, "session", "value-123"))

			// Empty values are legal (deletion cookies).
			empty := mustEncrypt(t, cc, "gone", "")
			pt, err = cc.decrypt("gone", empty)
			require.NoError(t, err)
			assert.Equal(t, "", pt)
		})
	}
}

func TestDecryptRejects(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "a", "secret")

	t.Run("AAD name mismatch", func(t *testing.T) {
		_, err := cc.decrypt("b", ct)
		assert.ErrorIs(t, err, ErrInvalidCiphertext)
	})

	t.Run("tampered", func(t *testing.T) {
		raw, err := base64.RawURLEncoding.DecodeString(ct)
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0x01
		_, err = cc.decrypt("a", base64.RawURLEncoding.EncodeToString(raw))
		assert.ErrorIs(t, err, ErrInvalidCiphertext)
	})

	t.Run("truncated", func(t *testing.T) {
		raw, err := base64.RawURLEncoding.DecodeString(ct)
		require.NoError(t, err)
		_, err = cc.decrypt("a", base64.RawURLEncoding.EncodeToString(raw[:10]))
		assert.ErrorIs(t, err, ErrInvalidCiphertext)
	})

	t.Run("bad base64", func(t *testing.T) {
		_, err := cc.decrypt("a", "!!!not-base64!!!")
		assert.ErrorIs(t, err, ErrInvalidCiphertext)
	})
}

// TestFIPSOnlyMode re-executes this test in a child process with
// GODEBUG=fips140=only: the default AES-GCM cipher must keep working (it uses
// NewGCMWithRandomNonce, the FIPS-approved construction), and chacha20-poly1305
// must fail at provision with guidance pointing at aes-gcm.
func TestFIPSOnlyMode(t *testing.T) {
	if os.Getenv("COOKIECRYPT_FIPS_CHILD") == "1" {
		cc := &CookieCrypt{Keys: []string{testKey1}}
		require.NoError(t, cc.provision())
		ct, err := encrypt(cc.aeads[0], "session", "value")
		require.NoError(t, err)
		pt, err := cc.decrypt("session", ct)
		require.NoError(t, err)
		require.Equal(t, "value", pt)

		chacha := &CookieCrypt{Keys: []string{testKey1}, Cipher: CipherChaCha20Poly1305}
		err = chacha.provision()
		require.Error(t, err)
		require.Contains(t, err.Error(), CipherChaCha20Poly1305)
		require.Contains(t, err.Error(), CipherAESGCM) // actionable guidance
		return
	}

	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run", "^TestFIPSOnlyMode$", "-test.v")
	cmd.Env = append(os.Environ(), "COOKIECRYPT_FIPS_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child test under fips140=only failed:\n%s", out)
	assert.Contains(t, string(out), "PASS")
}

func TestWireFormatCompatibleWithManualNonceGCM(t *testing.T) {
	// Ciphertexts minted before the switch to NewGCMWithRandomNonce used
	// cipher.NewGCM with a manually prepended 12-byte nonce — byte-identical
	// on the wire. Cookies issued under the old construction must keep
	// decrypting.
	cc := newCC(t, nil)
	key, err := hex.DecodeString(testKey1)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	legacy, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, legacy.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	raw := legacy.Seal(nonce, nonce, []byte("v1-value"), []byte("session"))

	pt, err := cc.decrypt("session", base64.RawURLEncoding.EncodeToString(raw))
	require.NoError(t, err)
	assert.Equal(t, "v1-value", pt)
}

func TestKeyRotation(t *testing.T) {
	oldCC := newCC(t, nil) // key1 only
	newCCBoth := newCC(t, func(cc *CookieCrypt) { cc.Keys = []string{testKey2, testKey1} })

	// A cookie minted under the old key still decrypts after rotation.
	oldCT := mustEncrypt(t, oldCC, "session", "v1")
	pt, err := newCCBoth.decrypt("session", oldCT)
	require.NoError(t, err)
	assert.Equal(t, "v1", pt)

	// New cookies are minted under the new (first) key only.
	newCT := mustEncrypt(t, newCCBoth, "session", "v2")
	_, err = oldCC.decrypt("session", newCT)
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

func TestNameEscaping(t *testing.T) {
	assert.Equal(t, "plain", escapeName("plain"))
	assert.Equal(t, "a..b", escapeName("a.b"))
	assert.Equal(t, "....", escapeName(".."))

	for escaped, want := range map[string]string{
		"plain": "plain",
		"a..b":  "a.b",
		"....":  "..",
	} {
		got, ok := unescapeName(escaped)
		require.True(t, ok, escaped)
		assert.Equal(t, want, got)
	}

	for _, bad := range []string{"a.b", "a...b", ".", "a.", "a.1"} {
		_, ok := unescapeName(bad)
		assert.False(t, ok, bad)
	}
}

func TestEncryptedName(t *testing.T) {
	cc := newCC(t, nil)
	assert.Equal(t, "cc_session", cc.encryptedName("session"))
	assert.Equal(t, "cc_X..1", cc.encryptedName("X.1"))
	assert.Equal(t, "__Host-cc_session", cc.encryptedName("__Host-session"))
	assert.Equal(t, "__Secure-cc_a..b", cc.encryptedName("__Secure-a.b"))
}

func TestMatchAny(t *testing.T) {
	assert.True(t, matchAny([]string{"exact"}, "exact"))
	assert.False(t, matchAny([]string{"exact"}, "exactly"))
	assert.True(t, matchAny([]string{"auth_*"}, "auth_token"))
	assert.False(t, matchAny([]string{"auth_*"}, "session"))
	assert.True(t, matchAny([]string{"c?"}, "cx"))
	assert.True(t, matchAny([]string{"[a-c]x"}, "bx"))
	assert.False(t, matchAny(nil, "anything"))
}

func TestMatchAnyNegation(t *testing.T) {
	// v1 `allowlist A B` emulation: everything except A and B.
	v1 := []string{"*", "!A", "!B"}
	assert.True(t, matchAny(v1, "C"))
	assert.False(t, matchAny(v1, "A"))
	assert.False(t, matchAny(v1, "B"))

	// Deny overrides regardless of order.
	assert.False(t, matchAny([]string{"!A", "*"}, "A"))

	// Negations can be globs too.
	assert.False(t, matchAny([]string{"*", "!auth_*"}, "auth_token"))
	assert.True(t, matchAny([]string{"*", "!auth_*"}, "session"))

	// A negation alone matches nothing (no positive pattern).
	assert.False(t, matchAny([]string{"!A"}, "B"))

	// `\!` matches a cookie literally named "!A" without negating.
	assert.True(t, matchAny([]string{`\!A`}, "!A"))
}

func TestParseChunkCount(t *testing.T) {
	for s, want := range map[string]int{"2": 2, "10": 10, "32": 32} {
		got, ok := parseChunkCount(s)
		require.True(t, ok, s)
		assert.Equal(t, want, got)
	}
	for _, bad := range []string{"", "0", "1", "02", "33", "999999999", "2a", "-2"} {
		_, ok := parseChunkCount(bad)
		assert.False(t, ok, bad)
	}
}

func TestValidCookieValue(t *testing.T) {
	assert.True(t, validCookieValue("abc-123"))
	assert.True(t, validCookieValue(`"a b"`)) // quoted pair allows inner spaces
	assert.True(t, validCookieValue(""))
	assert.False(t, validCookieValue("a;b"))
	assert.False(t, validCookieValue(`a"b`))
	assert.False(t, validCookieValue("a\x00b"))
}

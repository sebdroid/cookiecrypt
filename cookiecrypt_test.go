package cookiecrypt

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

var (
	TestKey = "b114d13fbe83352d37b8d0d2129d7d91"

	InvalidTestKey = "ztWhhGxD/ateoDhc+JBs3mkQAgTo8F9cbSf61n6pCuo="
)

func TestEncrypt(t *testing.T) {
	a := assert.New(t)
	logger := zaptest.NewLogger(t)

	crypt := CookieCrypt{
		Key:    TestKey,
		Prefix: "cc_",
		logger: logger,
	}

	ciphertext, err := encrypt(TestKey, "TEST_VALUE")
	a.NoError(err)

	plaintext, err := crypt.decrypt(ciphertext)
	a.Equal("TEST_VALUE", plaintext)
	a.NoError(err)

	ciphertext2, err := encrypt(TestKey, "TEST_VALUE")
	a.NotEqual(ciphertext, ciphertext2)
	a.NoError(err)

	_, err = encrypt(InvalidTestKey, "TEST_VALUE")
	a.Error(ErrInvalidKey, err)
}

func TestDecrypt(t *testing.T) {
	a := assert.New(t)
	logger := zaptest.NewLogger(t)

	crypt := CookieCrypt{
		Key:    TestKey,
		Prefix: "cc_",
		logger: logger,
	}

	plaintext, err := crypt.decrypt("orWhioRjRauWIGrcM1BzyM2zKZCN7wkkfYQeOnaTvEgNwTWjbEc=")
	a.Equal("TEST_VALUE", plaintext)
	a.NoError(err)

	_, err = crypt.decrypt("INVALID_CIPHERTEXT")
	a.Error(ErrInvalidCiphertext, err)

	crypt = CookieCrypt{
		Key:    InvalidTestKey,
		Prefix: "cc_",
		logger: logger,
	}

	_, err = crypt.decrypt("orWhioRjRauWIGrcM1BzyM2zKZCN7wkkfYQeOnaTvEgNwTWjbEc=")
	a.Error(ErrInvalidKey, err)
}

func TestShouldProcess(t *testing.T) {
	a := assert.New(t)
	logger := zaptest.NewLogger(t)

	crypt := CookieCrypt{
		Key:    TestKey,
		Prefix: "cc_",
		logger: logger,
	}

	a.True(crypt.shouldProcess("TEST"))
	a.True(crypt.shouldProcess("TEST2"))
	a.True(crypt.shouldProcess("TEST3"))

	crypt.Allowlist = []string{"TEST"}
	crypt.Denylist = []string{"TEST2"}

	a.True(crypt.shouldProcess("TEST"))
	a.False(crypt.shouldProcess("TEST2"))
	a.False(crypt.shouldProcess("TEST3"))

	crypt.Allowlist = []string{}
	a.True(crypt.shouldProcess("TEST"))
	a.False(crypt.shouldProcess("TEST2"))
	a.True(crypt.shouldProcess("TEST3"))
}

func TestParseFull(t *testing.T) {
	a := assert.New(t)
	cc := CookieCrypt{}

	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`cookiecrypt {
			key "b114d13fbe83352d37b8d0d2129d7d91"
			prefix "cc_"
			allowlist "TEST" "TEST2"
			denylist "TEST3" "TEST4"
		}`),
	}

	expected := CookieCrypt{
		Key:       "b114d13fbe83352d37b8d0d2129d7d91",
		Prefix:    "cc_",
		Allowlist: []string{"TEST", "TEST2"},
		Denylist:  []string{"TEST3", "TEST4"},
	}

	err := cc.UnmarshalCaddyfile(helper.Dispenser)
	a.ElementsMatch(expected.Allowlist, cc.Allowlist)
	a.ElementsMatch(expected.Denylist, cc.Denylist)
	a.Equal(expected.Key, cc.Key)
	a.Equal(expected.Prefix, cc.Prefix)
	a.NoError(err)
}

func TestParseInvalid(t *testing.T) {
	a := assert.New(t)
	cc := CookieCrypt{}

	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`cookiecrypt {
			key "b114d13fbe83352d37b8d0d2129d7d9"
			prefix "cc_"
			allowlist "TEST" "TEST2"
			denylist "TEST3" "TEST4"
		}`),
	}

	a.Error(fmt.Errorf(""), cc.UnmarshalCaddyfile(helper.Dispenser))
}

func TestParsePartial(t *testing.T) {
	a := assert.New(t)
	cc := CookieCrypt{}

	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`cookiecrypt {
			key "b114d13fbe83352d37b8d0d2129d7d91"
			prefix ""
		}`),
	}

	expected := CookieCrypt{
		Key:       "b114d13fbe83352d37b8d0d2129d7d91",
		Prefix:    "",
		Allowlist: []string{},
		Denylist:  []string{},
	}

	err := cc.UnmarshalCaddyfile(helper.Dispenser)
	a.ElementsMatch(expected.Allowlist, cc.Allowlist)
	a.ElementsMatch(expected.Denylist, cc.Denylist)
	a.Equal(expected.Key, cc.Key)
	a.Equal(expected.Prefix, cc.Prefix)
	a.NoError(err)
}
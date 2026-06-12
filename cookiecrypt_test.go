package cookiecrypt

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRequest sends a request with the given Cookie headers through the
// middleware and returns the request as the next handler saw it.
func runRequest(t *testing.T, cc *Cookiecrypt, cookieHeaders ...string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	for _, h := range cookieHeaders {
		req.Header.Add("Cookie", h)
	}
	var captured *http.Request
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		captured = r
		return nil
	})
	require.NoError(t, cc.ServeHTTP(httptest.NewRecorder(), req, next))
	require.NotNil(t, captured)
	return captured
}

// cookieMap parses the forwarded Cookie header leniently (first duplicate
// wins), mirroring how the middleware itself reads segments.
func cookieMap(r *http.Request) map[string]string {
	m := map[string]string{}
	for _, hv := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(hv, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if before, after, ok := strings.Cut(part, "="); ok {
				if _, dup := m[before]; !dup {
					m[before] = after
				}
			}
		}
	}
	return m
}

// splitCT splits a ciphertext into a count-declaring segment plus chunk
// segments, mimicking the outbound splitter's wire format.
func splitCT(encName, ct string, count int) []string {
	size := (len(ct) + count - 1) / count
	segs := make([]string, 0, count)
	for i := range count {
		end := min((i+1)*size, len(ct))
		part := ct[i*size : end]
		if i == 0 {
			segs = append(segs, encName+"="+strconv.Itoa(count)+":"+part)
		} else {
			segs = append(segs, encName+"."+strconv.Itoa(i)+"="+part)
		}
	}
	return segs
}

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		cc := new(Cookiecrypt)
		d := caddyfile.NewTestDispenser(`cookiecrypt {
			key ` + testKey1 + ` ` + testKey2 + `
			key ` + testKey1 + `
			cipher chacha20-poly1305
			prefix enc_
			block_unencrypted
			allow_inbound sso_* legacy
			allow_outbound "pub_*"
			max_cookie_size 2048
			secure
			httponly
		}`)
		require.NoError(t, cc.UnmarshalCaddyfile(d))
		assert.Equal(t, []string{testKey1, testKey2, testKey1}, cc.Keys)
		assert.Equal(t, CipherChaCha20Poly1305, cc.Cipher)
		require.NotNil(t, cc.Prefix)
		assert.Equal(t, "enc_", *cc.Prefix)
		assert.True(t, cc.BlockUnencrypted)
		assert.Equal(t, []string{"sso_*", "legacy"}, cc.AllowInbound)
		assert.Equal(t, []string{"pub_*"}, cc.AllowOutbound)
		assert.Equal(t, 2048, cc.MaxCookieSize)
		assert.True(t, cc.Secure)
		assert.True(t, cc.HTTPOnly)
	})

	t.Run("unknown directive", func(t *testing.T) {
		cc := new(Cookiecrypt)
		d := caddyfile.NewTestDispenser(`cookiecrypt {
			allowlist A B
		}`)
		assert.Error(t, cc.UnmarshalCaddyfile(d))
	})

	t.Run("flag with argument", func(t *testing.T) {
		cc := new(Cookiecrypt)
		d := caddyfile.NewTestDispenser(`cookiecrypt {
			block_unencrypted yes
		}`)
		assert.Error(t, cc.UnmarshalCaddyfile(d))
	})

	t.Run("key without argument", func(t *testing.T) {
		cc := new(Cookiecrypt)
		d := caddyfile.NewTestDispenser(`cookiecrypt {
			key
		}`)
		assert.Error(t, cc.UnmarshalCaddyfile(d))
	})

	t.Run("non-numeric max_cookie_size", func(t *testing.T) {
		cc := new(Cookiecrypt)
		d := caddyfile.NewTestDispenser(`cookiecrypt {
			max_cookie_size big
		}`)
		assert.Error(t, cc.UnmarshalCaddyfile(d))
	})

	t.Run("missing or extra arguments", func(t *testing.T) {
		for _, directive := range []string{
			"cipher",          // missing arg
			"prefix",          // missing arg
			"allow_inbound",   // missing patterns
			"allow_outbound",  // missing patterns
			"max_cookie_size", // missing arg
			"secure on",       // flags take no args
			"httponly on",
		} {
			cc := new(Cookiecrypt)
			d := caddyfile.NewTestDispenser("cookiecrypt {\n\t" + directive + "\n}")
			assert.Error(t, cc.UnmarshalCaddyfile(d), directive)
		}
	})
}

func TestParseCaddyfileHelper(t *testing.T) {
	h := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`cookiecrypt {
			key ` + testKey1 + `
		}`),
	}
	handler, err := parseCaddyfile(h)
	require.NoError(t, err)
	cc, ok := handler.(*Cookiecrypt)
	require.True(t, ok)
	assert.Equal(t, []string{testKey1}, cc.Keys)

	bad := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`cookiecrypt {
			bogus
		}`),
	}
	_, err = parseCaddyfile(bad)
	assert.Error(t, err)
}

func TestRequestNoCookies(t *testing.T) {
	cc := newCC(t, nil)
	got := runRequest(t, cc)
	assert.Empty(t, got.Header.Values("Cookie"))
}

func TestRequestDecryptReplacesCiphertext(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "session", "hello")

	got := runRequest(t, cc, "cc_session="+ct+"; other=1")
	m := cookieMap(got)
	assert.Equal(t, "hello", m["session"])
	assert.Equal(t, "1", m["other"])
	assert.NotContains(t, m, "cc_session")
}

func TestRequestUntouchedWhenNothingChanges(t *testing.T) {
	cc := newCC(t, nil)
	headers := []string{"a=1; b=2", "we[ird=stuff"}
	got := runRequest(t, cc, headers...)
	// No encrypted cookies and block_unencrypted off: the original headers
	// must pass through byte-for-byte, even the RFC-invalid segment that
	// Go's strict parser would drop.
	assert.Equal(t, headers, got.Header.Values("Cookie"))
}

func TestRequestInvalidSegmentPreservedOnRebuild(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "X", "v")
	got := runRequest(t, cc, "cc_X="+ct+"; bad[name=v")
	header := got.Header.Get("Cookie")
	assert.Contains(t, header, "X=v")
	assert.Contains(t, header, "bad[name=v")
}

func TestRequestDropsHeaderUnsafePlaintext(t *testing.T) {
	cc := newCC(t, nil)
	// encrypt seals any byte string, but a value containing ';' can never be
	// emitted into a rebuilt Cookie header: dropped, not mutated.
	ct := mustEncrypt(t, cc, "X", "a;b")
	m := cookieMap(runRequest(t, cc, "cc_X="+ct+"; ok=1"))
	assert.NotContains(t, m, "X")
	assert.Equal(t, "1", m["ok"])
}

func TestRequestDegenerateSegments(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "X", "v")
	// Empty segments vanish harmlessly; a nameless segment survives the
	// rebuild verbatim.
	got := runRequest(t, cc, "a=1;; cc_X="+ct+"; noequals; ")
	header := got.Header.Get("Cookie")
	assert.Contains(t, header, "a=1")
	assert.Contains(t, header, "X=v")
	assert.Contains(t, header, "noequals")
}

func TestRequestMultipleCookieHeaders(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "X", "v")
	got := runRequest(t, cc, "cc_X="+ct, "y=2")
	m := cookieMap(got)
	assert.Equal(t, "v", m["X"])
	assert.Equal(t, "2", m["y"])
}

func TestShadowRule(t *testing.T) {
	t.Run("valid ciphertext wins over forged bare", func(t *testing.T) {
		cc := newCC(t, nil)
		ct := mustEncrypt(t, cc, "X", "real")
		m := cookieMap(runRequest(t, cc, "cc_X="+ct+"; X=forged"))
		assert.Equal(t, "real", m["X"])
	})

	t.Run("corruption variant drops both", func(t *testing.T) {
		cc := newCC(t, nil)
		m := cookieMap(runRequest(t, cc, "cc_X=garbage; X=forged; ok=1"))
		assert.NotContains(t, m, "X")
		assert.Equal(t, "1", m["ok"])
	})

	t.Run("allow_inbound does not bypass shadowing", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) { cc.AllowInbound = []string{"X"} })
		m := cookieMap(runRequest(t, cc, "cc_X=garbage; X=forged"))
		assert.NotContains(t, m, "X")
	})

	t.Run("bare-only cookie untouched", func(t *testing.T) {
		cc := newCC(t, nil)
		m := cookieMap(runRequest(t, cc, "X=sso-handoff"))
		assert.Equal(t, "sso-handoff", m["X"])
	})
}

func TestAllowOutboundShadowException(t *testing.T) {
	t.Run("garbage ciphertext cannot evict bare cookie", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) { cc.AllowOutbound = []string{"session"} })
		m := cookieMap(runRequest(t, cc, "cc_session=garbage; session=legit"))
		assert.Equal(t, "legit", m["session"])
	})

	t.Run("valid ciphertext still wins", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) { cc.AllowOutbound = []string{"session"} })
		ct := mustEncrypt(t, cc, "session", "migrated")
		m := cookieMap(runRequest(t, cc, "cc_session="+ct+"; session=old"))
		assert.Equal(t, "migrated", m["session"])
	})
}

func TestDuplicateCiphertexts(t *testing.T) {
	cc := newCC(t, nil)
	ct1 := mustEncrypt(t, cc, "X", "first")
	ct2 := mustEncrypt(t, cc, "X", "second")

	t.Run("first valid duplicate wins", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "cc_X="+ct1+"; cc_X="+ct2))
		assert.Equal(t, "first", m["X"])
	})

	t.Run("invalid first falls through to valid second", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "cc_X=garbage; cc_X="+ct2+"; X=forged"))
		assert.Equal(t, "second", m["X"])
	})
}

func TestBlockUnencrypted(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		cc := newCC(t, nil)
		m := cookieMap(runRequest(t, cc, "plain=1"))
		assert.Equal(t, "1", m["plain"])
	})

	t.Run("on drops bare cookies", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) { cc.BlockUnencrypted = true })
		m := cookieMap(runRequest(t, cc, "plain=1"))
		assert.Empty(t, m)
	})

	t.Run("allow_inbound glob exempts", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) {
			cc.BlockUnencrypted = true
			cc.AllowInbound = []string{"sso_*"}
		})
		m := cookieMap(runRequest(t, cc, "sso_token=t; other=2"))
		assert.Equal(t, "t", m["sso_token"])
		assert.NotContains(t, m, "other")
	})

	t.Run("allow_outbound names pass automatically", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) {
			cc.BlockUnencrypted = true
			cc.AllowOutbound = []string{"pub"}
		})
		m := cookieMap(runRequest(t, cc, "pub=1"))
		assert.Equal(t, "1", m["pub"])
	})

	t.Run("negated allow_outbound names stay blocked", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) {
			cc.BlockUnencrypted = true
			cc.AllowOutbound = []string{"*", "!A"}
		})
		m := cookieMap(runRequest(t, cc, "A=1; C=3"))
		assert.NotContains(t, m, "A") // A is in the encrypted set; bare form blocked
		assert.Equal(t, "3", m["C"])
	})

	t.Run("negation in one list cannot veto the other", func(t *testing.T) {
		cc := newCC(t, func(cc *Cookiecrypt) {
			cc.BlockUnencrypted = true
			cc.AllowInbound = []string{"A"}
			cc.AllowOutbound = []string{"*", "!A"}
		})
		m := cookieMap(runRequest(t, cc, "A=1"))
		assert.Equal(t, "1", m["A"]) // explicit allow_inbound wins
	})
}

func TestChunkReassembly(t *testing.T) {
	cc := newCC(t, nil)
	long := strings.Repeat("0123456789", 30)
	ct := mustEncrypt(t, cc, "big", long)

	t.Run("happy path", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, strings.Join(splitCT("cc_big", ct, 3), "; ")))
		assert.Equal(t, long, m["big"])
	})

	t.Run("missing chunk drops all", func(t *testing.T) {
		segs := splitCT("cc_big", ct, 3)
		m := cookieMap(runRequest(t, cc, segs[0]+"; "+segs[2]+"; ok=1"))
		assert.NotContains(t, m, "big")
		assert.Equal(t, "1", m["ok"])
	})

	t.Run("stale orphan beyond count is ignored", func(t *testing.T) {
		segs := splitCT("cc_big", ct, 2)
		m := cookieMap(runRequest(t, cc, strings.Join(segs, "; ")+"; cc_big.2=stale"))
		assert.Equal(t, long, m["big"])
		assert.NotContains(t, m, "cc_big.2")
	})

	t.Run("orphan fragment alone is dropped", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "cc_big.1=zzz; ok=1"))
		assert.NotContains(t, m, "cc_big.1")
		assert.Equal(t, "1", m["ok"])
	})

	t.Run("chunk spliced from another cookie fails authentication", func(t *testing.T) {
		ctY := mustEncrypt(t, cc, "other", long)
		x := splitCT("cc_big", ct, 2)
		y := splitCT("cc_other", ctY, 2)
		// Swap the second chunks between the two cookies.
		swapped := x[0] + "; cc_big.1=" + strings.TrimPrefix(y[1], "cc_other.1=") +
			"; " + y[0] + "; cc_other.1=" + strings.TrimPrefix(x[1], "cc_big.1=")
		m := cookieMap(runRequest(t, cc, swapped))
		assert.NotContains(t, m, "big")
		assert.NotContains(t, m, "other")
	})

	t.Run("forged counts are rejected cheaply", func(t *testing.T) {
		for _, v := range []string{"999999999:abc", "0:a", "1:a", "02:a", "33:a"} {
			m := cookieMap(runRequest(t, cc, "cc_big="+v+"; ok=1"))
			assert.NotContains(t, m, "big", v)
			assert.Equal(t, "1", m["ok"], v)
		}
	})
}

func TestDottedNamesCoexist(t *testing.T) {
	cc := newCC(t, nil)
	ctX := mustEncrypt(t, cc, "X", "whole")
	ctX1 := mustEncrypt(t, cc, "X.1", "dotted")

	// "X.1" encrypts to "cc_X..1", which can never collide with chunk
	// "cc_X.1" of a split "X".
	m := cookieMap(runRequest(t, cc, "cc_X="+ctX+"; cc_X..1="+ctX1))
	assert.Equal(t, "whole", m["X"])
	assert.Equal(t, "dotted", m["X.1"])
}

func TestHostPrefixInbound(t *testing.T) {
	cc := newCC(t, nil)
	ct := mustEncrypt(t, cc, "__Host-session", "v")

	t.Run("round trip restores special prefix", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "__Host-cc_session="+ct))
		assert.Equal(t, "v", m["__Host-session"])
	})

	t.Run("shadow rule covers special-prefixed bare twin", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "__Host-cc_session="+ct+"; __Host-session=forged"))
		assert.Equal(t, "v", m["__Host-session"])
	})
}

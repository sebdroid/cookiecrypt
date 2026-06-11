package cookiecrypt

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runResponse drives the middleware's response path with the given handler.
func runResponse(t *testing.T, cc *CookieCrypt, handler caddyhttp.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, cc.ServeHTTP(rec, req, handler))
	return rec
}

// setCookieHandler emits the given Set-Cookie lines, then finishes the
// response via finish (defaults to a plain Write).
func setCookieHandler(lines []string, finish func(w http.ResponseWriter)) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		for _, l := range lines {
			w.Header().Add("Set-Cookie", l)
		}
		if finish != nil {
			finish(w)
		} else {
			_, _ = w.Write([]byte("body"))
		}
		return nil
	}
}

// replayHeader turns response Set-Cookie lines into a request Cookie header,
// as a browser would.
func replayHeader(lines []string) string {
	pairs := make([]string, 0, len(lines))
	for _, l := range lines {
		if i := strings.IndexByte(l, ';'); i >= 0 {
			l = l[:i]
		}
		pairs = append(pairs, l)
	}
	return strings.Join(pairs, "; ")
}

func TestResponseEncryptsOnExplicitWriteHeader(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"X=v; Path=/"}, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("body"))
	}))

	assert.Equal(t, http.StatusCreated, rec.Code)
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "cc_X="), lines[0])
	assert.True(t, strings.HasSuffix(lines[0], "; Path=/"), lines[0])
	assert.NotContains(t, lines[0], "X=v")
}

func TestResponseEncryptsOnImplicitWrite(t *testing.T) {
	// Regression: Write without WriteHeader used to ship the implicit 200
	// below the wrapper, leaking the plaintext Set-Cookie.
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"X=v"}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "cc_X="), lines[0])
}

func TestResponseEncryptsOnReadFrom(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"X=v"}, func(w http.ResponseWriter) {
		rf, ok := w.(io.ReaderFrom)
		if !ok {
			panic("response writer must implement io.ReaderFrom")
		}
		_, _ = rf.ReadFrom(strings.NewReader("streamed"))
	}))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "cc_X="), lines[0])
	assert.Equal(t, "streamed", rec.Body.String())
}

func TestResponseEncryptsOnFlush(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"X=v"}, func(w http.ResponseWriter) {
		//nolint:bodyclose
		require.NoError(t, http.NewResponseController(w).Flush())
	}))

	assert.True(t, rec.Flushed)
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "cc_X="), lines[0])
}

func TestResponseWithoutCookies(t *testing.T) {
	// The hot path: most responses set no cookies at all.
	cc := newCC(t, nil)
	rec := runResponse(t, cc, func(w http.ResponseWriter, r *http.Request) error {
		_, err := w.Write([]byte("body"))
		return err
	})
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Equal(t, "body", rec.Body.String())
}

func TestResponseAttributesVerbatim(t *testing.T) {
	cc := newCC(t, nil)
	attrs := "; Path=/; Domain=example.com; FutureAttr=42; SameSite=Lax"
	rec := runResponse(t, cc, setCookieHandler([]string{"X=v" + attrs}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	// Unknown attributes survive because the splice is verbatim, unlike
	// http.ParseSetCookie which drops what it does not recognise.
	assert.True(t, strings.HasSuffix(lines[0], attrs), lines[0])
}

func TestResponseMalformedLinePassthrough(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"no-equals-anywhere"}, nil))
	assert.Equal(t, []string{"no-equals-anywhere"}, rec.Header().Values("Set-Cookie"))
}

func TestResponseDeletionCookie(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"X=; Max-Age=0"}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "cc_X="), lines[0])
	assert.True(t, strings.HasSuffix(lines[0], "; Max-Age=0"), lines[0])

	// The encrypted empty value round-trips to empty.
	ct := strings.TrimSuffix(strings.TrimPrefix(lines[0], "cc_X="), "; Max-Age=0")
	pt, err := cc.decrypt("X", ct)
	require.NoError(t, err)
	assert.Equal(t, "", pt)
}

func TestResponseSecureHTTPOnly(t *testing.T) {
	cc := newCC(t, func(cc *CookieCrypt) { cc.Secure = true; cc.HTTPOnly = true })

	t.Run("appended when missing", func(t *testing.T) {
		rec := runResponse(t, cc, setCookieHandler([]string{"X=v; Path=/"}, nil))
		line := rec.Header().Get("Set-Cookie")
		assert.True(t, strings.HasSuffix(line, "; Path=/; Secure; HttpOnly"), line)
	})

	t.Run("not duplicated, case-insensitive", func(t *testing.T) {
		rec := runResponse(t, cc, setCookieHandler([]string{"X=v; secure; HTTPONLY"}, nil))
		line := rec.Header().Get("Set-Cookie")
		assert.Equal(t, 1, strings.Count(strings.ToLower(line), "secure"), line)
		assert.Equal(t, 1, strings.Count(strings.ToLower(line), "httponly"), line)
	})
}

func TestResponseAllowOutbound(t *testing.T) {
	cc := newCC(t, func(cc *CookieCrypt) {
		cc.AllowOutbound = []string{"pub_*"}
		cc.Secure = true
	})
	rec := runResponse(t, cc, setCookieHandler([]string{"pub_a=v; Path=/", "priv=v"}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 2)
	// Allowlisted lines pass through completely verbatim — even the secure
	// flag is not appended to them.
	assert.Equal(t, "pub_a=v; Path=/", lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "cc_priv="), lines[1])
}

func TestResponseAllowOutboundNegation(t *testing.T) {
	// v1 `allowlist A B` (encrypt only A and B) maps to `allow_outbound * !A !B`.
	cc := newCC(t, func(cc *CookieCrypt) { cc.AllowOutbound = []string{"*", "!A", "!B"} })
	rec := runResponse(t, cc, setCookieHandler([]string{"A=1", "B=2", "C=3"}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "cc_A="), lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "cc_B="), lines[1])
	assert.Equal(t, "C=3", lines[2])

	// The full loop still works: A and B decrypt, C passes through, and the
	// shadow rule stays unconditional for the encrypted names.
	m := cookieMap(runRequest(t, cc, replayHeader(lines)+"; A=forged"))
	assert.Equal(t, "1", m["A"])
	assert.Equal(t, "2", m["B"])
	assert.Equal(t, "3", m["C"])
}

func TestResponseHostPrefixOutermost(t *testing.T) {
	cc := newCC(t, nil)
	rec := runResponse(t, cc, setCookieHandler([]string{"__Host-sess=v; Secure; Path=/"}, nil))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	// The browser-enforced prefix stays outermost so its storage rules
	// keep applying to the encrypted cookie.
	assert.True(t, strings.HasPrefix(lines[0], "__Host-cc_sess="), lines[0])
	assert.True(t, strings.HasSuffix(lines[0], "; Secure; Path=/"), lines[0])
}

func TestResponseSplitting(t *testing.T) {
	const attrs = "; Path=/; SameSite=Lax"
	long := strings.Repeat("v", 2000)

	probe := newCC(t, func(cc *CookieCrypt) { cc.MaxCookieSize = 1 << 20 })
	rec := runResponse(t, probe, setCookieHandler([]string{"big=" + long + attrs}, nil))
	unsplit := rec.Header().Get("Set-Cookie")
	require.True(t, strings.HasPrefix(unsplit, "cc_big="), unsplit)

	t.Run("line exactly at the limit stays unsplit", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.MaxCookieSize = len(unsplit) })
		rec := runResponse(t, cc, setCookieHandler([]string{"big=" + long + attrs}, nil))
		assert.Len(t, rec.Header().Values("Set-Cookie"), 1)
	})

	t.Run("one byte over the limit splits", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.MaxCookieSize = len(unsplit) - 1 })
		rec := runResponse(t, cc, setCookieHandler([]string{"big=" + long + attrs}, nil))
		lines := rec.Header().Values("Set-Cookie")
		require.Greater(t, len(lines), 1)

		for i, l := range lines {
			assert.LessOrEqual(t, len(l), cc.MaxCookieSize, l)
			assert.True(t, strings.HasSuffix(l, attrs), "attributes must repeat on chunk %d", i)
			if i == 0 {
				assert.True(t, strings.HasPrefix(l, "cc_big="), l)
			} else {
				assert.True(t, strings.HasPrefix(l, "cc_big."), l)
			}
		}

		// And the split cookie reassembles to the original value.
		m := cookieMap(runRequest(t, cc, replayHeader(lines)))
		assert.Equal(t, long, m["big"])
	})

	t.Run("attributes exhausting the budget drop the cookie", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.MaxCookieSize = 600 })
		hugeAttrs := "; Path=/" + strings.Repeat("p", 580)
		rec := runResponse(t, cc, setCookieHandler([]string{"big=" + long + hugeAttrs, "ok=1"}, nil))

		lines := rec.Header().Values("Set-Cookie")
		require.Len(t, lines, 1) // "big" dropped fail-closed, "ok" survives
		assert.True(t, strings.HasPrefix(lines[0], "cc_ok="), lines[0])
	})

	t.Run("value too large for 32 chunks is dropped", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.MaxCookieSize = 512 })
		veryLong := strings.Repeat("v", 32*512)
		rec := runResponse(t, cc, setCookieHandler([]string{"big=" + veryLong}, nil))
		assert.Empty(t, rec.Header().Values("Set-Cookie"))
	})
}

// hijackableRecorder simulates a hijackable connection (e.g. a WebSocket
// upgrade) that httptest.ResponseRecorder cannot.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	conn, _ := net.Pipe()
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

func TestResponseWriterHijack(t *testing.T) {
	// Regression for "can't switch protocols using non-Hijacker
	// ResponseWriter": Caddy's reverse proxy hijacks via
	// http.ResponseController, which must reach the underlying writer
	// through Unwrap.
	cc := newCC(t, nil)
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		conn, _, err := http.NewResponseController(w).Hijack()
		require.NoError(t, err)
		return conn.Close()
	})
	require.NoError(t, cc.ServeHTTP(rec, req, next))
	assert.True(t, rec.hijacked)
}

func TestResponseWriterUnwrap(t *testing.T) {
	cc := newCC(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)

	var sawRecorder bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		require.True(t, ok)
		_, sawRecorder = u.Unwrap().(*httptest.ResponseRecorder)
		return nil
	})
	require.NoError(t, cc.ServeHTTP(rec, req, next))
	// Unwrap must reach the underlying writer so http.ResponseController
	// (Caddy's Flush/Hijack path) works through the wrapper.
	assert.True(t, sawRecorder)
}

func TestE2ECustomPrefix(t *testing.T) {
	cc := newCC(t, func(cc *CookieCrypt) { cc.Prefix = ptr("enc_") })

	rec := runResponse(t, cc, setCookieHandler([]string{"session=v; Path=/"}, nil))
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "enc_session="), lines[0])

	m := cookieMap(runRequest(t, cc, replayHeader(lines)))
	assert.Equal(t, "v", m["session"])

	// The configured prefix is the reserved namespace: a bare client cookie
	// that happens to carry it is treated as ciphertext and dropped, while
	// the default "cc_" prefix has no special meaning for this instance.
	m = cookieMap(runRequest(t, cc, "enc_fake=zzz; cc_other=1"))
	assert.NotContains(t, m, "enc_fake")
	assert.Equal(t, "1", m["cc_other"])
}

func TestPrefixCarryingNames(t *testing.T) {
	t.Run("backend-set cc_ name round-trips via double prefix", func(t *testing.T) {
		cc := newCC(t, nil)
		rec := runResponse(t, cc, setCookieHandler([]string{"cc_test=v"}, nil))
		lines := rec.Header().Values("Set-Cookie")
		require.Len(t, lines, 1)
		assert.True(t, strings.HasPrefix(lines[0], "cc_cc_test="), lines[0])

		m := cookieMap(runRequest(t, cc, replayHeader(lines)+"; cc_test=forged"))
		assert.Equal(t, "v", m["cc_test"]) // the forged bare form still loses
	})

	t.Run("listed raw cc_ name passes both directions", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.AllowOutbound = []string{"cc_legacy"} })
		rec := runResponse(t, cc, setCookieHandler([]string{"cc_legacy=plain"}, nil))
		assert.Equal(t, []string{"cc_legacy=plain"}, rec.Header().Values("Set-Cookie"))

		m := cookieMap(runRequest(t, cc, "cc_legacy=plain"))
		assert.Equal(t, "plain", m["cc_legacy"])
	})

	t.Run("allow_inbound raw cc_ name survives block_unencrypted", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) {
			cc.BlockUnencrypted = true
			cc.AllowInbound = []string{"cc_legacy"}
		})
		m := cookieMap(runRequest(t, cc, "cc_legacy=plain"))
		assert.Equal(t, "plain", m["cc_legacy"])
	})

	t.Run("encrypted twin beats listed bare form", func(t *testing.T) {
		cc := newCC(t, func(cc *CookieCrypt) { cc.AllowOutbound = []string{"cc_legacy"} })
		ct := mustEncrypt(t, cc, "cc_legacy", "migrated")
		m := cookieMap(runRequest(t, cc, "cc_cc_legacy="+ct+"; cc_legacy=old"))
		assert.Equal(t, "migrated", m["cc_legacy"])
	})
}

func TestE2ENoPrefix(t *testing.T) {
	long := strings.Repeat("0123456789", 200) // forces splitting at 1024
	cc := newCC(t, func(cc *CookieCrypt) {
		cc.Prefix = ptr("")
		cc.MaxCookieSize = 1024
		cc.AllowOutbound = []string{"pub_*"}
	})

	rec := runResponse(t, cc, setCookieHandler([]string{
		"session=secret; Path=/",
		"user.prefs=dark",
		"big=" + long,
		"__Host-id=h; Secure; Path=/",
		"pub_a=plain",
	}, nil))
	lines := rec.Header().Values("Set-Cookie")

	// Names survive unchanged (modulo dot escaping); values are ciphertext.
	var names []string
	for _, l := range lines {
		names = append(names, l[:strings.IndexByte(l, '=')])
		assert.NotContains(t, l, "=secret")
		assert.NotContains(t, l, "=dark")
	}
	assert.Contains(t, names, "session")
	assert.Contains(t, names, "user..prefs") // dot escaping still applies
	assert.Contains(t, names, "big")
	assert.Contains(t, names, "__Host-id")
	assert.Contains(t, lines, "pub_a=plain") // allow_outbound stays verbatim

	// Full round trip, including chunk reassembly of the split cookie.
	m := cookieMap(runRequest(t, cc, replayHeader(lines)))
	assert.Equal(t, "secret", m["session"])
	assert.Equal(t, "dark", m["user.prefs"])
	assert.Equal(t, long, m["big"])
	assert.Equal(t, "h", m["__Host-id"])
	assert.Equal(t, "plain", m["pub_a"])
}

func TestNoPrefixInbound(t *testing.T) {
	cc := newCC(t, func(cc *CookieCrypt) {
		cc.Prefix = ptr("")
		cc.AllowInbound = []string{"sso_*", "clock", "mp_*"}
		cc.AllowOutbound = []string{"pub"}
	})

	t.Run("unlisted plaintext is dropped", func(t *testing.T) {
		// No-prefix mode implies block_unencrypted: anything that is neither
		// valid ciphertext nor listed cannot reach the backend.
		m := cookieMap(runRequest(t, cc, "forged=1; sso_x=2"))
		assert.NotContains(t, m, "forged")
		assert.Equal(t, "2", m["sso_x"])
	})

	t.Run("allow_outbound names pass inbound", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "pub=1"))
		assert.Equal(t, "1", m["pub"])
	})

	t.Run("listed value with colon survives chunk misdetection", func(t *testing.T) {
		// "12:30" parses as a plausible count header; reassembly fails and
		// the listed name falls back to verbatim passthrough.
		m := cookieMap(runRequest(t, cc, "clock=12:30"))
		assert.Equal(t, "12:30", m["clock"])
	})

	t.Run("listed dotted name passes despite parity", func(t *testing.T) {
		m := cookieMap(runRequest(t, cc, "mp_a.b=1"))
		assert.Equal(t, "1", m["mp_a.b"])
	})

	t.Run("valid ciphertext beats kept plaintext duplicate", func(t *testing.T) {
		ct := mustEncrypt(t, cc, "sso_x", "real")
		m := cookieMap(runRequest(t, cc, "sso_x=plain; sso_x="+ct))
		assert.Equal(t, "real", m["sso_x"])
	})
}

func TestE2ERoundTrip(t *testing.T) {
	long := strings.Repeat("0123456789", 200) // forces splitting at 1024

	cases := map[string]string{
		"session":     "plain-value",
		"quoted":      `"a b"`,
		"big":         long,
		"big.1":       "dotted-sibling", // collides with chunk names without escaping
		"__Host-sess": "host-locked",
		"empty":       "",
	}

	for _, cipherName := range []string{CipherAESGCM, CipherChaCha20Poly1305} {
		t.Run(cipherName, func(t *testing.T) {
			cc := newCC(t, func(cc *CookieCrypt) {
				cc.Cipher = cipherName
				cc.MaxCookieSize = 1024
			})

			var lines []string
			for name, value := range cases {
				lines = append(lines, name+"="+value+"; Path=/")
			}
			rec := runResponse(t, cc, setCookieHandler(lines, nil))

			outLines := rec.Header().Values("Set-Cookie")
			for _, l := range outLines {
				for _, value := range cases {
					if value == "" {
						continue
					}
					assert.NotContains(t, l, "="+value, "plaintext leaked: %s", l)
				}
			}

			m := cookieMap(runRequest(t, cc, replayHeader(outLines)))
			for name, value := range cases {
				assert.Equal(t, value, m[name], name)
			}
			for name := range m {
				assert.False(t, strings.Contains(name, cc.prefix),
					"encrypted cookie %q leaked to the backend", name)
			}
		})
	}
}

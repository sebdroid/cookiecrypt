package cookiecrypt

import (
	"crypto/cipher"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// CookieCrypt encrypts every outbound Set-Cookie (AES-256-GCM by default,
// AAD-bound to the cookie's name) and transparently decrypts the matching
// cookies on inbound requests.
type CookieCrypt struct {
	// Keys are 64-char hex strings (32 raw bytes each). The first key
	// encrypts; all keys are tried on decrypt, enabling rotation.
	// Placeholders like {env.COOKIECRYPT_KEY} are resolved at provision.
	Keys []string `json:"keys,omitempty"`
	// Cipher is "aes-gcm" (default) or "chacha20-poly1305".
	Cipher string `json:"cipher,omitempty"`
	// Prefix marks encrypted cookie names (default "cc_" when omitted) and is
	// a reserved namespace. Explicitly empty enables no-prefix mode: every
	// inbound cookie is presumed ciphertext, and bare cookies are dropped
	// unless they match AllowInbound or AllowOutbound.
	Prefix *string `json:"prefix,omitempty"`
	// BlockUnencrypted drops bare (unencrypted) client cookies unless their
	// name matches AllowInbound.
	BlockUnencrypted bool `json:"block_unencrypted,omitempty"`
	// AllowInbound exempts bare client cookies from BlockUnencrypted
	// (path.Match globs, "!" negates). Names matching AllowOutbound are
	// accepted automatically.
	AllowInbound []string `json:"allow_inbound,omitempty"`
	// AllowOutbound cookies are passed through verbatim on responses instead
	// of being encrypted (path.Match globs, "!" negates — deny overrides, so
	// `* !A !B` encrypts only A and B).
	AllowOutbound []string `json:"allow_outbound,omitempty"`
	// MaxCookieSize is the per-Set-Cookie-line split threshold in bytes
	// (default 4096 per RFC 6265 §6.1, minimum 512).
	MaxCookieSize int `json:"max_cookie_size,omitempty"`
	// Secure appends the Secure attribute to encrypted Set-Cookies.
	Secure bool `json:"secure,omitempty"`
	// HTTPOnly appends the HttpOnly attribute to encrypted Set-Cookies.
	HTTPOnly bool `json:"httponly,omitempty"`

	aeads  []cipher.AEAD
	prefix string // Prefix resolved at provision (nil → "cc_")
	logger *zap.Logger
}

func init() {
	caddy.RegisterModule(CookieCrypt{})
	httpcaddyfile.RegisterHandlerDirective("cookiecrypt", parseCaddyfile)
}

func (CookieCrypt) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cookiecrypt",
		New: func() caddy.Module { return new(CookieCrypt) },
	}
}

func (cc *CookieCrypt) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for d.NextBlock(0) {
		switch d.Val() {
		case "key":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			cc.Keys = append(cc.Keys, args...)
		case "cipher":
			if !d.AllArgs(&cc.Cipher) {
				return d.ArgErr()
			}
		case "prefix":
			var p string
			if !d.AllArgs(&p) {
				return d.ArgErr()
			}
			cc.Prefix = &p
		case "block_unencrypted":
			if d.NextArg() {
				return d.ArgErr()
			}
			cc.BlockUnencrypted = true
		case "allow_inbound":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			cc.AllowInbound = append(cc.AllowInbound, args...)
		case "allow_outbound":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			cc.AllowOutbound = append(cc.AllowOutbound, args...)
		case "max_cookie_size":
			var raw string
			if !d.AllArgs(&raw) {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				return d.Errf("max_cookie_size: %v", err)
			}
			cc.MaxCookieSize = n
		case "secure":
			if d.NextArg() {
				return d.ArgErr()
			}
			cc.Secure = true
		case "httponly":
			if d.NextArg() {
				return d.ArgErr()
			}
			cc.HTTPOnly = true
		default:
			return d.Errf("unknown directive %s", d.Val())
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	cc := new(CookieCrypt)
	err := cc.UnmarshalCaddyfile(h.Dispenser)
	return cc, err
}

func (cc *CookieCrypt) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	cc.processRequestCookies(r)

	rw := &cookieInterceptResponseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		cc:                    cc,
	}
	return next.ServeHTTP(rw, r)
}

// cookieSegment is one ';'-separated piece of a Cookie header, kept verbatim
// so untouched cookies pass through byte-for-byte (Go's strict cookie parser
// would silently drop RFC-invalid ones).
type cookieSegment struct {
	raw   string
	name  string // "" when the segment has no '='
	value string
}

// processRequestCookies decrypts prefixed cookies, reassembles split ones,
// enforces the shadow rule and block_unencrypted, and rebuilds the Cookie
// header — but only if anything actually changed.
func (cc *CookieCrypt) processRequestCookies(r *http.Request) {
	headerVals := r.Header.Values("Cookie")
	if len(headerVals) == 0 {
		return
	}

	var segs []cookieSegment
	for _, hv := range headerVals {
		for part := range strings.SplitSeq(hv, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			seg := cookieSegment{raw: part}
			if before, after, ok := strings.Cut(part, "="); ok {
				seg.name, seg.value = before, after
			}
			segs = append(segs, seg)
		}
	}

	// Split the encrypted namespace into primaries (valid escaped names) and
	// chunk-shaped names (odd dot runs).
	type primaryCookie struct {
		idx  int
		name string // original (unescaped, special prefix restored)
	}
	var (
		primaries []primaryCookie
		chunky    []int
		isEnc     = make([]bool, len(segs))
		encIdx    = make(map[string][]int) // full encrypted cookie name → seg indices
	)
	for i, s := range segs {
		if s.name == "" {
			continue
		}
		// In no-prefix mode every named cookie is in the encrypted namespace.
		special, rest := splitSpecialPrefix(s.name)
		if !strings.HasPrefix(rest, cc.prefix) {
			continue
		}
		isEnc[i] = true
		encIdx[s.name] = append(encIdx[s.name], i)
		if base, ok := unescapeName(rest[len(cc.prefix):]); ok {
			primaries = append(primaries, primaryCookie{idx: i, name: special + base})
		} else {
			chunky = append(chunky, i)
		}
	}

	var (
		modified bool
		drop     = make([]bool, len(segs))
		replaced = make(map[int]string)
		emitted  = make(map[string]bool) // original names already decrypted (first valid duplicate wins)
		shadow   = make(map[string]bool) // bare twins of these names must be dropped
	)

	// A non-decryptable cookie with a listed name is a legitimate bare
	// cookie. Lists name the decoded form in no-prefix mode, the raw form
	// otherwise (e.g. allow_outbound cc_legacy, which outbound also matches
	// raw and passes verbatim).
	listedBare := func(raw, decoded string) (string, bool) {
		name := raw
		if cc.prefix == "" {
			name = decoded
		}
		if matchAny(cc.AllowInbound, name) || matchAny(cc.AllowOutbound, name) {
			return name, true
		}
		return "", false
	}
	var kept []primaryCookie

	for _, p := range primaries {
		seg := segs[p.idx]
		if emitted[p.name] {
			drop[p.idx], modified = true, true
			cc.logger.Debug("dropping duplicate encrypted cookie", zap.String("cookie", p.name))
			continue
		}

		ciphertext := seg.value
		var chunkIdxs []int
		ok := true
		reason := ""
		if ci := strings.IndexByte(seg.value, ':'); ci >= 0 {
			// ':' never appears in unsplit ciphertext (RawURL base64), so it
			// unambiguously marks a split cookie's count header.
			count, valid := parseChunkCount(seg.value[:ci])
			if !valid {
				ok, reason = false, "invalid chunk count"
			} else {
				var sb strings.Builder
				sb.WriteString(seg.value[ci+1:])
				for n := 1; n < count; n++ {
					// Chunk names are constructed, never parsed.
					idxs := encIdx[seg.name+"."+strconv.Itoa(n)]
					if len(idxs) == 0 {
						ok, reason = false, "missing chunk"
						break
					}
					sb.WriteString(segs[idxs[0]].value)
					chunkIdxs = append(chunkIdxs, idxs[0])
				}
				ciphertext = sb.String()
			}
		}

		var plaintext string
		if ok {
			pt, err := cc.decrypt(p.name, ciphertext)
			if err != nil {
				ok, reason = false, "decrypt failed"
			} else if !validCookieValue(pt) {
				ok, reason = false, "decrypted value not header-safe"
			} else {
				plaintext = pt
			}
		}

		if ok {
			replaced[p.idx] = p.name + "=" + plaintext
			// Chunks are consumed only on success, so a plaintext that merely
			// looks like a count header ("12:30") can't eat sibling cookies.
			for _, ci := range chunkIdxs {
				drop[ci] = true
			}
			emitted[p.name] = true
			shadow[p.name] = true
			modified = true
			cc.logger.Debug("cookie decrypted", zap.String("cookie", p.name))
			continue
		}

		if name, isListed := listedBare(seg.name, p.name); isListed {
			kept = append(kept, primaryCookie{idx: p.idx, name: name})
			cc.logger.Debug("passing through listed plaintext cookie", zap.String("cookie", name))
			continue
		}

		drop[p.idx], modified = true, true
		cc.logger.Warn("dropping encrypted cookie: "+reason, zap.String("cookie", p.name))
		// Bare twins of failed ciphertexts are shadowed too — except for
		// allow_outbound names, where bare is the legitimate form and forged
		// garbage must not evict it.
		if !matchAny(cc.AllowOutbound, p.name) {
			shadow[p.name] = true
		}
	}

	// Unconsumed chunk-shaped cookies are stale orphans (or forged); they
	// never block reads of the primary.
	for _, i := range chunky {
		if drop[i] {
			continue
		}
		if name, isListed := listedBare(segs[i].name, segs[i].name); isListed {
			kept = append(kept, primaryCookie{idx: i, name: name})
			continue
		}
		drop[i], modified = true, true
		cc.logger.Warn("dropping orphaned cookie fragment", zap.String("cookie", segs[i].name))
	}

	// A decrypted twin always beats a kept plaintext duplicate.
	for _, k := range kept {
		if emitted[k.name] {
			drop[k.idx], modified = true, true
			cc.logger.Warn("dropping plaintext cookie shadowed by encrypted twin", zap.String("cookie", k.name))
		}
	}

	for i, s := range segs {
		if s.name == "" || isEnc[i] {
			continue
		}
		if shadow[s.name] {
			drop[i], modified = true, true
			cc.logger.Warn("dropping plaintext cookie shadowed by encrypted twin", zap.String("cookie", s.name))
			continue
		}
		// Lists are evaluated independently so a negation in one cannot veto
		// an explicit allow in the other.
		if cc.BlockUnencrypted && !matchAny(cc.AllowInbound, s.name) && !matchAny(cc.AllowOutbound, s.name) {
			drop[i], modified = true, true
			cc.logger.Warn("dropping unencrypted cookie", zap.String("cookie", s.name))
		}
	}

	if !modified {
		return
	}
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		if repl, isReplaced := replaced[i]; isReplaced {
			out = append(out, repl)
			continue
		}
		if drop[i] {
			continue
		}
		out = append(out, s.raw)
	}
	if len(out) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(out, "; "))
}

var (
	_ caddy.Provisioner           = (*CookieCrypt)(nil)
	_ caddy.Validator             = (*CookieCrypt)(nil)
	_ caddyhttp.MiddlewareHandler = (*CookieCrypt)(nil)
	_ caddyfile.Unmarshaler       = (*CookieCrypt)(nil)
)

package cookiecrypt

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// cookieInterceptResponseWriter rewrites Set-Cookie exactly once, at
// header-write time. Write, ReadFrom, and Flush force the implicit 200
// through this wrapper so plaintext cookies cannot leak past it; the embedded
// wrapper's Unwrap keeps http.ResponseController (Caddy's Flush/Hijack)
// working. Hijacked 101/upgrade responses bypass header processing.
type cookieInterceptResponseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	cc          *CookieCrypt
	wroteHeader bool
}

func (w *cookieInterceptResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.processSetCookies()
	}
	w.ResponseWriterWrapper.WriteHeader(statusCode)
}

func (w *cookieInterceptResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.Write(b)
}

func (w *cookieInterceptResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.ReadFrom(r)
}

func (w *cookieInterceptResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	//nolint:bodyclose
	_ = http.NewResponseController(w.ResponseWriterWrapper.ResponseWriter).Flush()
}

func (w *cookieInterceptResponseWriter) processSetCookies() {
	headers := w.Header()
	lines := headers["Set-Cookie"]
	if len(lines) == 0 {
		return
	}
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		out = append(out, w.cc.transformSetCookie(raw)...)
	}
	if len(out) == 0 {
		headers.Del("Set-Cookie")
		return
	}
	headers["Set-Cookie"] = out
}

// transformSetCookie encrypts one Set-Cookie line, splitting it when it
// exceeds MaxCookieSize. Attributes are spliced verbatim — http.ParseSetCookie
// would drop ones it doesn't recognize. Returns nil to drop the line: on
// error, plaintext is never emitted.
func (cc *CookieCrypt) transformSetCookie(raw string) []string {
	name, value, ok := strings.Cut(raw, "=")
	if !ok {
		cc.logger.Debug("passing through malformed Set-Cookie line")
		return []string{raw}
	}
	attrs := ""
	if si := strings.IndexByte(value, ';'); si >= 0 {
		value, attrs = value[:si], value[si:]
	}

	if matchAny(cc.AllowOutbound, name) {
		cc.logger.Debug("passing through allow_outbound cookie", zap.String("cookie", name))
		return []string{raw}
	}

	if cc.Secure && !hasAttr(attrs, "Secure") {
		attrs += "; Secure"
	}
	if cc.HTTPOnly && !hasAttr(attrs, "HttpOnly") {
		attrs += "; HttpOnly"
	}

	encVal, err := encrypt(cc.aeads[0], name, value)
	if err != nil {
		cc.logger.Error("encrypt failed, dropping Set-Cookie line", zap.String("cookie", name), zap.Error(err))
		return nil
	}
	encName := cc.encryptedName(name)

	line := encName + "=" + encVal + attrs
	if len(line) <= cc.MaxCookieSize {
		cc.logger.Debug("cookie encrypted", zap.String("cookie", name))
		return []string{line}
	}

	// Every chunk line repeats the name and attributes; reserve 3 bytes for
	// the worst-case count header ("32:") or chunk-name suffix (".31").
	budget := cc.MaxCookieSize - len(encName) - 1 - 3 - len(attrs)
	if budget <= 16 {
		cc.logger.Error("attributes leave no room to split cookie within max_cookie_size, dropping",
			zap.String("cookie", name))
		return nil
	}
	count := (len(encVal) + budget - 1) / budget
	if count > maxChunks {
		cc.logger.Error("cookie too large to split, dropping",
			zap.String("cookie", name), zap.Int("chunks_needed", count))
		return nil
	}

	lines := make([]string, 0, count)
	for i := range count {
		end := min((i+1)*budget, len(encVal))
		part := encVal[i*budget : end]
		if i == 0 {
			lines = append(lines, encName+"="+strconv.Itoa(count)+":"+part+attrs)
		} else {
			lines = append(lines, encName+"."+strconv.Itoa(i)+"="+part+attrs)
		}
	}
	cc.logger.Debug("cookie encrypted and split", zap.String("cookie", name), zap.Int("chunks", count))
	return lines
}

func hasAttr(attrs, want string) bool {
	for a := range strings.SplitSeq(attrs, ";") {
		a = strings.TrimSpace(a)
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			a = a[:eq]
		}
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

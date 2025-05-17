package cookiecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type CookieCrypt struct {
	Key       string   `json:"key,omitempty"`
	Prefix    string   `json:"prefix,omitempty"`
	Allowlist []string `json:"allowlist,omitempty"`
	Denylist  []string `json:"denylist,omitempty"`

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

func (cc *CookieCrypt) Provision(ctx caddy.Context) error {
	cc.logger = ctx.Logger()

	if cc.Prefix == "" {
		cc.Prefix = "cc_"
	}

	return nil
}

func (cc *CookieCrypt) Validate() error {
	if _, err := aes.NewCipher([]byte(cc.Key)); err != nil {
		return ErrInvalidKey
	}
	return nil
}

func (cc *CookieCrypt) Error(err error) {
	cc.logger.Error("error", zap.Error(err))
}

func (cc *CookieCrypt) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for d.NextBlock(0) {
		switch d.Val() {
		case "key":
			if !d.AllArgs(&cc.Key) {
				return d.ArgErr()
			}
		case "prefix":
			if !d.AllArgs(&cc.Prefix) {
				return d.ArgErr()
			}
		case "allowlist":
			cc.Allowlist = d.RemainingArgs()
		case "denylist":
			cc.Denylist = d.RemainingArgs()
		default:
			return fmt.Errorf("unknown directive %s", d.Val())
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var cc CookieCrypt
	err := cc.UnmarshalCaddyfile(h.Dispenser)
	return cc, err
}

func (cc *CookieCrypt) shouldProcess(name string) bool {
	if len(cc.Allowlist) > 0 {
		for _, a := range cc.Allowlist {
			if a == name {
				return true
			}
		}
		cc.logger.Info("cookie not in allowlist", zap.String("cookie", name))
		return false
	}
	for _, d := range cc.Denylist {
		if d == name {
			cc.logger.Info("cookie in denylist", zap.String("cookie", name))
			return false
		}
	}
	return true
}

func (cc *CookieCrypt) decrypt(ciphertext string) (string, error) {
	raw, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(cc.Key))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesgcm.NonceSize()
	if len(raw) < nonceSize {
		return "", ErrInvalidCiphertext
	}
	nonce, ciphertextRaw := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertextRaw, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

type cookieInterceptResponseWriter struct {
	http.ResponseWriter
	logger        *zap.Logger
	key           string
	prefix        string
	shouldProcess func(name string) bool
}

func encrypt(key string, plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (w *cookieInterceptResponseWriter) WriteHeader(statusCode int) {
	headers := w.Header()
	cookies := headers["Set-Cookie"]
	newCookies := []string{}

	for _, raw := range cookies {
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) < 2 {
			newCookies = append(newCookies, raw)
			continue
		}
		name := parts[0]
		valueParts := strings.SplitN(parts[1], ";", 2)
		value := valueParts[0]

		if !w.shouldProcess(name) {
			newCookies = append(newCookies, raw)
			continue
		}

		encVal, err := encrypt(w.key, value)
		if err != nil {
			newCookies = append(newCookies, raw)
			continue
		}
		rest := ""
		if len(valueParts) == 2 {
			rest = ";" + valueParts[1]
		}
		newCookies = append(newCookies, w.prefix+name+"="+encVal+rest)
		w.logger.Info("crypted cookie", zap.String("cookie", name))
	}
	if len(newCookies) > 0 {
		headers["Set-Cookie"] = newCookies
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (cc CookieCrypt) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, cc.Prefix) {
			continue
		}
		name := strings.TrimPrefix(c.Name, cc.Prefix)
		cc.logger.Info("detected crypted cookie", zap.String("cookie", name))

		if !cc.shouldProcess(name) {
			continue
		}

		if decrypted, err := cc.decrypt(c.Value); err == nil {
			r.AddCookie(&http.Cookie{
				Name:  name,
				Value: decrypted,
			})
			cc.logger.Info("cookie decrypted", zap.String("cookie", name))
		}
	}

	rw := &cookieInterceptResponseWriter{
		ResponseWriter: w,
		logger:         cc.logger,
		key:            cc.Key,
		prefix:         cc.Prefix,
		shouldProcess:  cc.shouldProcess,
	}
	return next.ServeHTTP(rw, r)
}

var (
	_ caddy.Provisioner           = (*CookieCrypt)(nil)
	_ caddy.Validator             = (*CookieCrypt)(nil)
	_ caddyhttp.MiddlewareHandler = (*CookieCrypt)(nil)
	_ caddyfile.Unmarshaler       = (*CookieCrypt)(nil)
)

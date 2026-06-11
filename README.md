# cookiecrypt
> http.handlers.cookiecrypt

[![Go Build](https://github.com/sebdroid/cookiecrypt/actions/workflows/go.yml/badge.svg)](https://github.com/sebdroid/cookiecrypt/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/sebdroid/cookiecrypt)](https://goreportcard.com/report/github.com/sebdroid/cookiecrypt)

Caddy HTTP middleware that encrypts cookies in transit.

Every `Set-Cookie` is encrypted, and the matching cookies on incoming requests are transparently decrypted before they reach the backend.

Each ciphertext is bound to its cookie's name, so a value sealed for one cookie cannot be replayed under another name. Failures are fail-closed: a cookie that cannot be encrypted is never sent in plaintext, and a cookie that cannot be decrypted is dropped, never forwarded raw.

[Documentation](https://caddyserver.com/docs/modules/http.handlers.cookiecrypt)

## Install

This module can be built at Caddy's [official site](https://caddyserver.com/download?package=github.com%2Fsebdroid%2Fcookiecrypt).
To build locally, use [`xcaddy`](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/sebdroid/cookiecrypt
```

> [!IMPORTANT]
> Requires Caddy v2.11.2 or newer - the oldest release that supports this module's cryptography and has no known vulnerabilities in its dependencies. Building with any newer Caddy works automatically: Go always selects the newer of your Caddy version and this minimum.

## Sample Caddyfile

```Caddyfile
{
	order cookiecrypt before reverse_proxy
}

example.com {
	cookiecrypt {
		key {env.COOKIECRYPT_KEY}
	}
	reverse_proxy http://127.0.0.1:5173
}
```

Generate a key with:

```bash
openssl rand -hex 32
```

> [!TIP]
> Keep secrets out of your Caddyfile with placeholders: `{env.COOKIECRYPT_KEY}` reads an environment variable, `{file./run/secrets/cookiecrypt.key}` reads the key from a file. Both are resolved once, when the config loads.

## Configuration

```Caddyfile
cookiecrypt {
	key <hex64> [<hex64>...]     # repeatable; first key encrypts, all keys decrypt (rotation)
	cipher aes-gcm               # or chacha20-poly1305
	prefix cc_                   # marks encrypted cookie names; "" = no-prefix mode
	block_unencrypted            # drop bare client cookies (default: off)
	allow_inbound <patterns...>  # exceptions to block_unencrypted
	allow_outbound <patterns...> # never encrypt these on responses
	max_cookie_size 4096         # split threshold per Set-Cookie line (min 512)
	secure                       # append Secure to encrypted Set-Cookies
	httponly                     # append HttpOnly to encrypted Set-Cookies
}
```

JSON config uses the same names: `keys` (array), `cipher`, `prefix`, `block_unencrypted`, `allow_inbound`, `allow_outbound`, `max_cookie_size`, `secure`, `httponly`.

### Directional model

- **Outbound (responses):** every `Set-Cookie` is encrypted by default. Names matching `allow_outbound` pass through verbatim. Attributes (`Path`, `Max-Age`, `SameSite`, etc.) are preserved byte-for-byte.
- **Inbound (requests):** encrypted cookies are decrypted and renamed back. Bare (unencrypted) client cookies pass through by default; with `block_unencrypted` they are dropped unless they match `allow_inbound`. `allow_outbound` names are accepted inbound automatically.
- **Shadow rule:** when a request carries both an encrypted cookie and a bare cookie of the same name, the bare one is dropped - a client cannot bypass encryption by sending a forged plaintext twin, even alongside a deliberately corrupted ciphertext. However, if a cookie is named in `allow_outbound`, a garbage ciphertext cannot evict the bare cookie; only a valid encrypted twin can.

Patterns in both lists are [`path.Match`](https://pkg.go.dev/path#Match) globs: `auth_*`, `c?`, `[a-z]token`, or plain literal names. A leading `!` negates a pattern, and negations always win regardless of order - `allow_outbound * !A !B` means "pass everything through except A and B" (i.e. encrypt only A and B). To match a cookie literally named `!A`, escape it as `\!A`.

### Ciphers

| Cipher              | Standard                     | Notes                                             |
| ------------------- | ---------------------------- | ------------------------------------------------- |
| `aes-gcm` (default) | AES-256-GCM, NIST SP 800-38D | FIPS-approved, hardware-accelerated on most CPUs  |
| `chacha20-poly1305` | RFC 8439                     | Faster on CPUs without AES instructions; not FIPS |

> [!NOTE]
> **FIPS environments:** Only `aes-gcm` works under `GODEBUG=fips140=only`. `chacha20-poly1305` is not an approved algorithm; when Caddy is built with Go 1.26 or newer, FIPS-only mode refuses to load a `chacha20-poly1305` config with an error pointing back to `aes-gcm`. Builds on older toolchains cannot detect FIPS-only mode and will run it regardless - build with Go 1.26+ if FIPS compliance matters to you.

### Key rotation

> [!IMPORTANT]
> Rotate on your normal schedule, and always before a single key has protected roughly 4 billion cookies - a hard cryptographic limit shared by both ciphers.

1. Generate a new key: `openssl rand -hex 32`.
2. Put it **first** in the `key` directive, keeping the old key(s) after it:
   `key <new> <old>`.
3. Reload Caddy. New cookies are sealed with the new key; existing cookies still decrypt via the old one and are re-sealed with the new key on the next response that sets them.
4. After your longest cookie lifetime has passed, remove the old key.

### Cookie splitting

Browsers only guarantee 4096 bytes per cookie ([RFC 6265 - 6.1](https://www.rfc-editor.org/rfc/rfc6265#section-6.1)), and encryption adds overhead. When an encrypted `Set-Cookie` line would exceed `max_cookie_size`, the value is split across numbered cookies (`cc_name`, `cc_name.1`, …, at most 32 chunks), each repeating the original attributes, and reassembled transparently on the way back in. Browsers also only guarantee ~50 cookies per domain.

If a split cookie later shrinks, stale chunk cookies may linger in the browser. They are ignored on read (they never block the cookie) and expire on their own schedule.

### `__Host-` / `__Secure-` cookie name prefixes

Browser-enforced name prefixes stay outermost when renaming: `__Host-session` is stored as `__Host-cc_session`, so the browser keeps enforcing its rules (`Secure`, `Path=/`, no `Domain`) on the encrypted cookie, and the backend gets `__Host-session` back after decryption.

### Reserved namespace and name escaping

- The configured `prefix` is a reserved namespace: a client cookie that happens to carry it is treated as ciphertext and dropped if it fails to decrypt. Backend-set cookies whose real name carries the prefix still round-trip - `cc_test` is simply stored double-prefixed as `cc_cc_test`. Cookies with such names set *outside* this middleware (JavaScript, sibling apps) are dropped inbound unless their raw name is listed in `allow_inbound` or `allow_outbound`.
- Dots in cookie names are escaped in the stored name (`user.prefs` → `cc_user..prefs`) so that chunk names (`cc_X.1`) can never collide with the encrypted form of a real cookie named `X.1`. This is purely cosmetic - your application always sees the original name.

### No-prefix mode

Setting `prefix ""` explicitly removes the prefix entirely: cookie names stay unchanged in the browser (dots are still doubled - see name escaping above) and only values become ciphertext. Since nothing marks a cookie as encrypted, **every** inbound cookie is presumed to be encrypted - it is decrypted, or dropped if decryption fails. Cookies listed in `allow_inbound` or `allow_outbound` that aren't valid ciphertext pass through as ordinary bare cookies (a validly encrypted twin still wins over a plaintext duplicate).

> [!WARNING]
> Cookies set client-side (JavaScript `document.cookie` - analytics, consent banners) and by other subsystems are dropped unless listed. Audit your traffic and populate `allow_inbound` globs before enabling this mode.

Consequences to weigh before enabling it:

- `block_unencrypted` is effectively always on - a forged or unknown plaintext cookie cannot be decrypted and is dropped.
- `__Host-`/`__Secure-` prefixes are preserved automatically, since names never change.
- There is no reserved namespace to collide with.

Omitting `prefix` keeps the default `cc_`; only an explicit empty string enables this mode.

### Logging

Per-cookie success events log at `DEBUG`. Dropped cookies (failed decryption, shadowed plaintext, `block_unencrypted`) log at `WARN`, encryption failures at `ERROR` - always with the cookie's name, never its value.

## Licence

cookiecrypt is licensed under the [Apache License 2.0](LICENSE): use it, modify it, and redistribute it freely, commercially or not. When you redistribute, include the licence, carry forward the attribution notices from the [NOTICE](NOTICE) file, and mark any files you change as modified - that keeps the credit with the original work and the responsibility for changes with whoever made them.

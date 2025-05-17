# cookiecrypt
> http.handlers.cookiecrypt

![Go Workflow](https://github.com/sebdroid/cookiecrypt/actions/workflows/go.yml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/sebdroid/cookiecrypt)](https://goreportcard.com/badge/github.com/sebdroid/cookiecrypt)

Caddy HTTP Middleware to encrypt/decrypt cookies in transit

[Documentation](https://caddyserver.com/docs/modules/http.handlers.cookiecrypt)

## Install

This module can be built at Caddy's [official site](https://caddyserver.com/download?package=github.com%2Fsebdroid%2Fcookiecrypt).
To build locally, use [`xcaddy`](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/sebdroid/cookiecrypt
```

## Sample Caddyfile

```Caddyfile
{
	order cookiecrypt before reverse_proxy
}

example.com {
	cookiecrypt {
		key "e7e05ca2229da9a74f3874f29933cde8"
		prefix "cookiecrypt_"
		allowlist "Cookie1" "Cookie2"
		denylist "Cookie3" "Cookie3"
	}
	reverse_proxy http://127.0.0.1:5173
}
```

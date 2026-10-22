# phpsafepass

A checking FastCGI pass-through that sits between your web server and
PHP-FPM. It reads each request, validates it structurally, and forwards
only what passes — multipart bodies are re-serialized so PHP never parses
the attacker's bytes. Anything malformed is rejected with `400` and never
reaches PHP. A small static binary, no runtime dependencies.

It's not a substitute for patching or upgrading PHP, but on an old or
end-of-life version you can't fix today, it can buy you some time.

## Where it sits

Today the web server speaks FastCGI straight to PHP-FPM:

```
   ┌──────────────────────┐    FastCGI    ┌───────────┐
   │  nginx / Apache / …   │ ────────────► │  PHP-FPM  │
   └──────────────────────┘               └───────────┘
```

phpsafepass drops in between — same FastCGI on both sides, nothing else to
change — and checks every request before PHP ever sees it:

```
   ┌──────────────────────┐   FastCGI   ┌───────────────┐   FastCGI   ┌───────────┐
   │  nginx / Apache / …   │ ──────────► │  phpsafepass  │ ──────────► │  PHP-FPM  │
   └──────────────────────┘             └───────┬───────┘             └───────────┘
                                                │
                                                ╳  malformed or dangerous request:
                                                   rejected with 400, never reaches PHP
```

## Why

PHP's C-level request parsers have repeatedly had critical bugs reachable
straight from a crafted HTTP request — the multipart parser and the
`session.upload_progress` handler among them. phpsafepass closes that path
without signatures:

- **multipart** bodies are fully parsed and re-serialized with a fresh
  random boundary, so PHP's parser only ever sees bytes phpsafepass wrote;
- the `PHP_SESSION_UPLOAD_PROGRESS` trigger field is rejected outright;
- requests with ambiguous framing, bare CR/LF, NUL bytes, or structurally
  broken multipart/JSON/form bodies are refused before the backend.

Everything else (GET, JSON, urlencoded, other content types) is checked and
forwarded byte-for-byte unchanged.

### CVEs this targets

- **CVE-2026-109618** — use-after-free in the `session.upload_progress`
  handler (the `PHP_SESSION_UPLOAD_PROGRESS` field is rejected)
- **CVE-2026-109619** — use-after-free in the multipart form-data parser
  (multipart bodies are re-serialized, so PHP never parses attacker bytes)

These two are the "php2shell" pair. The same two mechanisms also cover
earlier bugs of the same shape — the multipart parser (e.g. CVE-2024-3096)
and the upload-progress handler (e.g. CVE-2024-11236). It does **not**
address PHP bugs outside the request parsers, such as the SOAP
use-after-free (CVE-2026-6722).

## Build

Written in Rust, standard library only — no crate dependencies.

```bash
cargo build --release          # target/release/phpsafepass

# static, dependency-free binary for deploy:
sudo apt install musl-tools
rustup target add x86_64-unknown-linux-musl
make static                    # target/x86_64-unknown-linux-musl/release/phpsafepass

cargo test                     # unit + end-to-end tests
```

## Docker

A rolling `edge` image (scratch + the static binary, ~500 KB) is published
to GHCR on every push — no version tags, `edge` and `latest` always point at
the newest build:

```bash
docker pull ghcr.io/analogic/phpsafepass:edge
# phpsafepass LISTEN UPSTREAM
docker run -p 9000:9000 ghcr.io/analogic/phpsafepass:edge 0.0.0.0:9000 php-fpm:9000
```

As a compose service in front of a PHP-FPM pool:

```yaml
services:
  phpsafepass:
    image: ghcr.io/analogic/phpsafepass:edge
    command: ["0.0.0.0:9000", "php-fpm:9000"]
    ports:
      - "9000:9000"
```

## Run

```
phpsafepass LISTEN UPSTREAM
```

`LISTEN` and `UPSTREAM` are each `host:port` or `/path/to.sock`. phpsafepass
listens where the web server connects, and forwards to the PHP-FPM pool.

```bash
# TCP both sides
phpsafepass 127.0.0.1:10001 127.0.0.1:9000

# listen on a Unix socket, forward to the pool's socket
phpsafepass /run/phpsafepass.sock /run/php/php5.6-fpm.sock
```

## Apache

Point the existing PHP-FPM handler at phpsafepass instead of the pool:

```apache
<FilesMatch "\.php$">
    SetHandler "proxy:fcgi://127.0.0.1:10001"
</FilesMatch>
```

Or, if phpsafepass listens on a Unix socket:

```apache
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/phpsafepass.sock|fcgi://phpsafepass/"
</FilesMatch>
```

Apache still resolves `SCRIPT_FILENAME`, `PATH_INFO`, `HTTPS`, `REMOTE_ADDR`
exactly as before; phpsafepass passes those params through untouched.

## Credits

The structural-sanitization approach — fully parsing a request and
re-serializing it so the backend never sees the attacker's bytes —
originates with [Qbix proxy](https://github.com/Qbix/proxy). phpsafepass
distills that idea down to a single FastCGI pass-through.

## License

See [LICENSE](LICENSE).

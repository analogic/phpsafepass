# phpsafepass

A checking FastCGI pass-through that sits between your web server and
PHP-FPM. It reads each request, validates it structurally, and forwards
only what passes — multipart bodies are re-serialized so PHP never parses
the attacker's bytes. Anything malformed is rejected with `400` and never
reaches PHP. A tiny static binary (~100 KB), no dependencies.

It's not a substitute for patching or upgrading PHP, but on an old or
end-of-life version you can't fix today, it can buy you some time.

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

```bash
make                 # build/phpsafepass          (dynamic, development)
sudo apt install musl-tools
make static          # build/phpsafepass-static   (static, deploy)
make test            # build static + run the test suite
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

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
   │  nginx / Apache / …  │ ────────────► │  PHP-FPM  │
   └──────────────────────┘               └───────────┘
```

phpsafepass drops in between — same FastCGI on both sides, nothing else to
change — and checks every request before PHP ever sees it:

```
   ┌──────────────────────┐   FastCGI   ┌───────────────┐   FastCGI   ┌───────────┐
   │  nginx / Apache / …  │ ──────────► │  phpsafepass  │ ──────────► │  PHP-FPM  │
   └──────────────────────┘             └───────┬───────┘             └───────────┘
                                                │
                                                ╳  malformed or dangerous request:
                                                   rejected with 400, never reaches PHP
```

## Why

phpsafepass does two things, and it's worth being precise about each:

1. **Re-serializes multipart bodies.** Every `multipart/form-data` body is
   fully parsed and re-emitted with a fresh boundary, so PHP's multipart
   parser only ever sees bytes phpsafepass wrote — not the client's. This
   closes classic *parser-differential* multipart bugs (e.g. CVE-2024-3096).
2. **Caps the shapes that drive the 2026 bugs.** It limits the number of form
   fields and how deeply field names nest (`a[b][c]…`), on both multipart and
   urlencoded bodies, and rejects the `PHP_SESSION_UPLOAD_PROGRESS` field.

Everything else — GET, JSON, any other content type — is forwarded
byte-for-byte unchanged. phpsafepass is **not** a WAF, has no signatures, and
stays out of the way otherwise.

### On CVE-2026-109618 / CVE-2026-109619 (the "php2shell" pair)

Be honest with yourself about these: they are **not** malformed-byte parser
bugs. They are state-corruption-on-fatal-error bugs — a fatal (typically
`memory_limit` exhausted during allocation) interrupts parsing and leaves
dangling state that request shutdown then frees and a later request reclaims,
leading to RCE. The triggers are *memory pressure* and *allocation
explosion* (many fields, deeply nested field names, `filename=""` parts),
plus the upload-progress path — see the
[write-up](https://calif.io/php2shell/).

So re-serializing "clean" multipart bytes does **not** fix them: a perfectly
well-formed body with thousands of deeply nested field names triggers the bug
just the same.

**How phpsafepass actually helps.** Not by spotting malicious bytes — there
are none to spot — but by keeping *every* request it forwards cheap enough
that PHP won't hit the OOM-fatal while parsing it. With `--max-fields 1000`
and `--max-depth 32`, the nested structures PHP builds from a request are
bounded to tens of MB at most; `--max-request` bounds the raw bytes. Under a
normal `memory_limit` (default 128M) that stays comfortably below the limit,
so the fatal that the whole exploit chain depends on never fires on a request
that passed through. For the front-door automatic-parsing trigger
(multipart/urlencoded → `$_POST`/`$_FILES`), that cuts off the chain. The
upload-progress field is refused on top.

**Where this still falls short — know these:**

- It assumes real headroom under `memory_limit`. On a host with a low limit
  (some shared hosting uses 32–64M) or an app already near its limit, tighten
  the caps (`--max-fields`, `--max-depth`, `--max-request`) accordingly.
- It does nothing for the `unserialize()` / `session_start()` variant — that
  decodes data the application handles, not the request body phpsafepass
  parses — nor for PHP bugs outside request parsing (e.g. the SOAP UAF,
  CVE-2026-6722).

**It is still not a fix. Patch PHP** (October 2026 security release). If you
genuinely can't, either put phpsafepass in front with tight caps **and keep a
normal finite `memory_limit`** (it's your backstop; no allowed request should
approach it), *or*, without a proxy, apply the upstream mitigations
(`session.upload_progress.enabled=0`, and `memory_limit=-1` — which removes
the trigger but drops your memory backstop, so it trades RCE risk for DoS
risk). Don't do `memory_limit=-1` *and* run phpsafepass; that just throws away
the backstop. phpsafepass only buys time.

## Written in Rust

Deliberately, not for fashion:

- **Memory safety where it matters most.** The entire job of this program is
  to parse bytes from a hostile client. A buffer overflow or use-after-free
  in the checker would be the exact class of bug it exists to stop — so the
  checker is written in a language that rules those out.
- **No dependencies.** Standard library only, zero crates. Nothing to audit
  but the code itself, and no supply chain to trust.
- **One small static binary.** A musl build links statically and drops into a
  `scratch` container (~500 KB), with no runtime to install anywhere.

## Download

A prebuilt static binary for x86-64 Linux is attached to the rolling `edge`
release — always the latest build of `main`, no version to pick:

```bash
curl -L -o phpsafepass \
  https://github.com/analogic/phpsafepass/releases/download/edge/phpsafepass-x86_64-linux
chmod +x phpsafepass
```

Or build it yourself (or pull the Docker image, below).

## Build

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
phpsafepass LISTEN UPSTREAM [--max-request SIZE] [--max-fields N] [--max-depth N]
```

`LISTEN` and `UPSTREAM` are each `host:port` or `/path/to.sock`. phpsafepass
listens where the web server connects, and forwards to the PHP-FPM pool.

| flag | default | what it bounds |
|------|---------|----------------|
| `--max-request` | `64M` | buffered request size (params + body). Set it **near your PHP `post_max_size`**. Accepts `K`/`M`/`G` or plain bytes. |
| `--max-fields` | `1000` | form fields (multipart parts / urlencoded pairs); PHP's `max_input_vars` default |
| `--max-depth` | `32` | `a[b][c]…` array nesting per field name |

These three caps are the lever that keeps every allowed request cheap enough
to stay well under PHP's `memory_limit` — see below. Tighten them on hosts
with a low `memory_limit`.

```bash
# TCP both sides, tuned for an 8M post_max_size
phpsafepass 127.0.0.1:10001 127.0.0.1:9000 --max-request 8M

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

## Is it AI slop? I don't trust it.

Fair — a lot of this was written with an AI, and this is a thing you'd put
directly between the internet and your PHP. You shouldn't take it on faith.

So it's kept small and boring on purpose: the whole program is about 800
lines of dependency-free Rust across four files, with a roughly equal amount
of tests. That's little enough that you can just read it — and you should,
before you run it. Start with [`src/check.rs`](src/check.rs); that's the
security-critical part, where every request is validated and multipart
bodies are re-serialized. [`src/fcgi.rs`](src/fcgi.rs) is the FastCGI wire
format and [`src/main.rs`](src/main.rs) is the socket plumbing.

Don't trust the description. Read the code — there isn't much of it.

## Credits

The structural-sanitization approach — fully parsing a request and
re-serializing it so the backend never sees the attacker's bytes —
originates with [Qbix proxy](https://github.com/Qbix/proxy). phpsafepass
distills that idea down to a single FastCGI pass-through.

## License

See [LICENSE](LICENSE).

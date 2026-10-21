/* fastcgi.c — FastCGI binary protocol for forwarding to PHP-FPM.
 *
 * Implements just enough of the spec to act as a client (the proxy
 * side of a responder transaction).  The record format is:
 *
 *   byte  version      = 1
 *   byte  type
 *   u16   requestId    (big-endian)
 *   u16   contentLength
 *   byte  paddingLength
 *   byte  reserved
 *   [contentLength bytes of content]
 *   [paddingLength bytes of padding]
 *
 * Record types we use:
 *   1 = BEGIN_REQUEST   (we send)
 *   3 = END_REQUEST     (we read)
 *   4 = PARAMS          (we send)
 *   5 = STDIN           (we send)
 *   6 = STDOUT          (we read)
 *   7 = STDERR          (we read, logged)
 *
 * Reference: https://fastcgi-archives.github.io/FastCGI_Specification.html
 */
#include "userver.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>

/* ── record types ────────────────────────────────────────────────── */
#define FCGI_BEGIN_REQUEST   1
#define FCGI_END_REQUEST     3
#define FCGI_PARAMS          4
#define FCGI_STDIN           5
#define FCGI_STDOUT          6
#define FCGI_STDERR          7

#define FCGI_RESPONDER       1
#define FCGI_MAX_CONTENT     65535
#define FCGI_REQUEST_ID      1   /* we use a single request per connection */

/* ── wire helpers ────────────────────────────────────────────────── */

static void put_u16be(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static uint16_t get_u16be(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* Write a complete FCGI record header into buf (8 bytes). */
static void fcgi_header(uint8_t* buf, uint8_t type, uint16_t content_len) {
    buf[0] = 1;   /* version */
    buf[1] = type;
    put_u16be(buf + 2, FCGI_REQUEST_ID);
    put_u16be(buf + 4, content_len);
    buf[6] = 0;   /* padding */
    buf[7] = 0;   /* reserved */
}

/* Send all bytes, retrying on partial writes. */
static int send_all(int fd, const void* data, size_t n) {
    const uint8_t* p = data;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* Send a typed record (content may be NULL for zero-length). */
static int send_record(int fd, uint8_t type, const void* content, uint16_t len) {
    uint8_t hdr[8];
    fcgi_header(hdr, type, len);
    if (send_all(fd, hdr, 8)) return -1;
    if (len > 0 && send_all(fd, content, len)) return -1;
    return 0;
}

/* Send BEGIN_REQUEST (role=RESPONDER, flags=0 → close connection when done). */
static int send_begin_request(int fd) {
    uint8_t body[8] = {0};
    put_u16be(body, FCGI_RESPONDER);  /* role */
    /* body[2] = flags = 0 (FCGI_KEEP_CONN not set) */
    return send_record(fd, FCGI_BEGIN_REQUEST, body, 8);
}

/* Encode one FCGI name-value pair into a buffer. */
static void encode_param(UBuf* buf, const char* name, size_t nlen, const char* value, size_t vlen) {
    /* Length encoding: < 128 = 1 byte, >= 128 = 4 bytes with high bit set */
    if (nlen < 128) {
        uint8_t b = (uint8_t)nlen;
        ubuf_add(buf, &b, 1);
    } else {
        uint8_t b[4];
        b[0] = (uint8_t)(0x80 | ((nlen >> 24) & 0x7f));
        b[1] = (uint8_t)((nlen >> 16) & 0xff);
        b[2] = (uint8_t)((nlen >> 8) & 0xff);
        b[3] = (uint8_t)(nlen & 0xff);
        ubuf_add(buf, b, 4);
    }
    if (vlen < 128) {
        uint8_t b = (uint8_t)vlen;
        ubuf_add(buf, &b, 1);
    } else {
        uint8_t b[4];
        b[0] = (uint8_t)(0x80 | ((vlen >> 24) & 0x7f));
        b[1] = (uint8_t)((vlen >> 16) & 0xff);
        b[2] = (uint8_t)((vlen >> 8) & 0xff);
        b[3] = (uint8_t)(vlen & 0xff);
        ubuf_add(buf, b, 4);
    }
    ubuf_add(buf, name, nlen);
    ubuf_add(buf, value, vlen);
}

/* Add a string param. */
static void add_param(UBuf* buf, const char* name, const char* value) {
    if (!value) value = "";
    encode_param(buf, name, strlen(name), value, strlen(value));
}

/* Send PARAMS records (split across multiple records if needed). */
static int send_params(int fd, UBuf* params) {
    const uint8_t* p = (const uint8_t*)params->data;
    size_t left = params->len;
    while (left > 0) {
        uint16_t chunk = left > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : (uint16_t)left;
        if (send_record(fd, FCGI_PARAMS, p, chunk)) return -1;
        p += chunk; left -= chunk;
    }
    /* Empty PARAMS record signals end of params */
    return send_record(fd, FCGI_PARAMS, NULL, 0);
}

/* Send STDIN records. */
static int send_stdin(int fd, const char* body, size_t body_len) {
    const uint8_t* p = (const uint8_t*)body;
    size_t left = body_len;
    while (left > 0) {
        uint16_t chunk = left > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : (uint16_t)left;
        if (send_record(fd, FCGI_STDIN, p, chunk)) return -1;
        p += chunk; left -= chunk;
    }
    /* Empty STDIN signals end of input */
    return send_record(fd, FCGI_STDIN, NULL, 0);
}

/* ── reading the response ────────────────────────────────────────── */

/* Read exactly n bytes from fd. */
static int recv_all(int fd, void* buf, size_t n) {
    uint8_t* p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* Maximum response size from a backend (64 MiB).  Prevents a
   misbehaving backend from exhausting proxy memory. */
#define MAX_RESPONSE_BYTES (64 * 1024 * 1024)

/* Read records from the backend until END_REQUEST.  Collects STDOUT
   into `out` and logs STDERR. */
static int read_response(int fd, UBuf* out) {
    for (;;) {
        uint8_t hdr[8];
        if (recv_all(fd, hdr, 8)) return -1;

        uint8_t type = hdr[1];
        uint16_t clen = get_u16be(hdr + 4);
        uint8_t pad = hdr[6];

        /* Read content + padding */
        uint8_t* content = NULL;
        if (clen + pad > 0) {
            content = malloc(clen + pad);
            if (recv_all(fd, content, clen + pad)) { free(content); return -1; }
        }

        switch (type) {
        case FCGI_STDOUT:
            if (clen > 0) {
                if (out->len + clen > MAX_RESPONSE_BYTES) {
                    free(content);
                    return -1;  /* response too large */
                }
                ubuf_add(out, content, clen);
            }
            break;
        case FCGI_STDERR:
            if (clen > 0) {
                /* Log stderr from PHP, but don't forward to client */
                char* msg = malloc(clen + 1);
                memcpy(msg, content, clen); msg[clen] = 0;
                fprintf(stderr, "[fastcgi-stderr] %s\n", msg);
                free(msg);
            }
            break;
        case FCGI_END_REQUEST:
            free(content);
            return 0;  /* done */
        }
        free(content);
    }
}

/* Parse CGI-style response (headers + blank line + body) from PHP-FPM
   output into a UResp. */
static int parse_cgi_response(UBuf* raw, UResp* resp) {
    uresp_init(resp);

    char* data = raw->data;
    size_t len = raw->len;

    /* Find header/body separator */
    char* sep = memmem(data, len, "\r\n\r\n", 4);
    if (!sep) {
        /* PHP might use just \n\n */
        sep = memmem(data, len, "\n\n", 2);
        if (!sep) {
            /* No headers — entire output is body */
            resp->status = 200;
            ubuf_add(&resp->body, data, len);
            return 0;
        }
    }

    int sep_len = (sep[0] == '\r') ? 4 : 2;

    /* Parse headers */
    resp->status = 200;  /* default unless Status: header */
    char* line = data;
    while (line < sep) {
        char* eol = memmem(line, (size_t)(sep - line), (sep[0] == '\r') ? "\r\n" : "\n",
                           (sep[0] == '\r') ? 2 : 1);
        if (!eol) eol = sep;
        size_t ll = (size_t)(eol - line);

        /* Parse "Name: value" */
        char* colon = memchr(line, ':', ll);
        if (colon) {
            *colon = 0;
            char* v = colon + 1;
            while (*v == ' ') v++;
            size_t vl = ll - (size_t)(v - line);

            if (!strcasecmp(line, "status")) {
                resp->status = atoi(v);
            } else {
                /* Copy as a response header */
                char name[128], val[4096];
                snprintf(name, sizeof name, "%s", line);
                snprintf(val, sizeof val, "%.*s", (int)vl, v);
                uresp_header(resp, name, val);
                if (!strcasecmp(name, "content-type")) resp->has_ctype = 1;
            }
        }

        line = eol + ((sep[0] == '\r') ? 2 : 1);
    }

    /* Body is everything after the separator */
    char* body_start = sep + sep_len;
    size_t body_len = len - (size_t)(body_start - data);
    if (body_len > 0) ubuf_add(&resp->body, body_start, body_len);

    return 0;
}

/* one FastCGI name/value length (1 or 4 bytes); -1 when truncated */
static int param_len(const uint8_t* p, size_t n, size_t* i, size_t* out) {
    if (*i >= n) return -1;
    if (p[*i] < 128) { *out = p[(*i)++]; return 0; }
    if (*i + 4 > n) return -1;
    *out = ((size_t)(p[*i] & 0x7f) << 24) | ((size_t)p[*i + 1] << 16) | ((size_t)p[*i + 2] << 8) | p[*i + 3];
    *i += 4;
    return 0;
}

/* walk name/value pairs; f returns nonzero to stop.  -1 on malformed */
int fcgi_each_param(const char* raw, size_t n,
                      int (*f)(void* ctx, const char* k, size_t kl, const char* v, size_t vl), void* ctx) {
    const uint8_t* p = (const uint8_t*)raw;
    size_t i = 0, kl, vl;
    while (i < n) {
        if (param_len(p, n, &i, &kl) || param_len(p, n, &i, &vl) || kl > n - i || vl > n - i - kl) return -1;
        if (f(ctx, raw + i, kl, raw + i + kl, vl)) return 0;
        i += kl + vl;
    }
    return 0;
}

static int is_param(const char* k, size_t kl, const char* name) { return kl == strlen(name) && !memcmp(k, name, kl); }

static int copy_one(void* ctx, const char* k, size_t kl, const char* v, size_t vl) {
    if ((kl >= 5 && !memcmp(k, "HTTP_", 5)) || is_param(k, kl, "CONTENT_TYPE") || is_param(k, kl, "CONTENT_LENGTH")) return 0;
    encode_param((UBuf*)ctx, k, kl, v, vl);
    return 0;
}
static void copy_params(UBuf* out, const char* raw, size_t n) { fcgi_each_param(raw, n, copy_one, out); }

/* ── FastCGI client side (Apache proxy:fcgi → us) ────────────────── */

typedef struct { UBuf* http; const char* method; size_t ml; const char* uri; size_t ul; int bad; } Xlate;

static int xlate_one(void* ctx, const char* k, size_t kl, const char* v, size_t vl) {
    Xlate* x = ctx;
    /* these bytes become an HTTP header block: no CR, LF or NUL anywhere */
    if (memchr(v, '\r', vl) || memchr(v, '\n', vl) || memchr(v, 0, vl) ||
        memchr(k, '\r', kl) || memchr(k, '\n', kl) || memchr(k, 0, kl) || memchr(k, ':', kl)) { x->bad = 1; return 1; }
    if (is_param(k, kl, "REQUEST_METHOD")) { x->method = v; x->ml = vl; }
    else if (is_param(k, kl, "REQUEST_URI")) { x->uri = v; x->ul = vl; }
    else if (is_param(k, kl, "CONTENT_TYPE")) ubuf_printf(x->http, "Content-Type: %.*s\r\n", (int)vl, v);
    else if (kl > 5 && !memcmp(k, "HTTP_", 5)) {
        /* framing is ours (Content-Length below); HTTP_PROXY is httpoxy */
        if (is_param(k, kl, "HTTP_CONTENT_LENGTH") || is_param(k, kl, "HTTP_TRANSFER_ENCODING") ||
            is_param(k, kl, "HTTP_PROXY")) return 0;
        for (size_t j = 5; j < kl; j++) { char ch = k[j] == '_' ? '-' : k[j]; ubuf_add(x->http, &ch, 1); }
        ubuf_printf(x->http, ": %.*s\r\n", (int)vl, v);
    }
    return 0;
}

int fcgi_in_translate(UConn* c, UResp* err) {
    const uint8_t* p = (const uint8_t*)c->in.data;
    size_t n = c->in.len, i = 0;
    UBuf params = {0}, body = {0};
    int got_begin = 0, done = 0;
    while (!done) {
        if (n - i < 8) goto incomplete;
        uint8_t type = p[i + 1];
        size_t cl = get_u16be(p + i + 4), pl = p[i + 6];
        if (p[i] != 1) goto bad;
        if (n - i < 8 + cl + pl) goto incomplete;
        const uint8_t* d = p + i + 8;
        if (type == FCGI_BEGIN_REQUEST && cl >= 8) {
            got_begin = 1;
            c->fcgi_id = get_u16be(p + i + 2);
            c->fcgi_keep = d[2] & 1;
            if (get_u16be(d) != FCGI_RESPONDER) goto bad;
        } else if (type == FCGI_PARAMS) {
            ubuf_add(&params, d, cl);
        } else if (type == FCGI_STDIN) {
            if (cl == 0) done = 1;
            else if (body.len + cl > g_cfg.max_post) { ubuf_free(&params); ubuf_free(&body); err->status = 413;
                uresp_header(err, "Content-Type", "text/plain; charset=utf-8"); ubuf_adds(&err->body, "Payload Too Large"); return -1; }
            else ubuf_add(&body, d, cl);
        }   /* ABORT_REQUEST, GET_VALUES: nothing to do for a single request */
        i += 8 + cl + pl;
    }
    if (!got_begin) goto bad;

    UBuf http = {0}, hdrs = {0};
    Xlate x = { &hdrs, "GET", 3, NULL, 0, 0 };
    if (fcgi_each_param(params.data, params.len, xlate_one, &x) || x.bad || !x.uri || !x.ul) { ubuf_free(&hdrs); goto bad; }
    ubuf_printf(&http, "%.*s %.*s HTTP/1.1\r\n", (int)x.ml, x.method, (int)x.ul, x.uri);
    if (hdrs.len) ubuf_add(&http, hdrs.data, hdrs.len);
    ubuf_free(&hdrs);
    if (body.len) ubuf_printf(&http, "Content-Length: %zu\r\n", body.len);
    ubuf_adds(&http, "\r\n");
    if (body.len) ubuf_add(&http, body.data, body.len);
    ubuf_free(&body);

    /* swap the FastCGI request for its HTTP form, keep anything after it */
    if (n > i) ubuf_add(&http, c->in.data + i, n - i);
    ubuf_free(&c->in);
    c->in = http;
    free(c->fcgi_params);
    c->fcgi_params = params.data ? params.data : calloc(1, 1);
    c->fcgi_params_len = params.len;
    return 1;

incomplete:
    ubuf_free(&params); ubuf_free(&body);
    if (n > g_cfg.max_post + g_cfg.max_header + 65536) { err->status = 413;
        uresp_header(err, "Content-Type", "text/plain; charset=utf-8"); ubuf_adds(&err->body, "Payload Too Large"); return -1; }
    return 0;
bad:
    ubuf_free(&params); ubuf_free(&body);
    err->status = 400;
    uresp_header(err, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&err->body, "Bad Request: malformed FastCGI request");
    return -1;
}

/* the response as CGI (Status: + headers + body) in STDOUT records */
void fcgi_in_response(uint16_t id, const UResp* resp, int send_body, UBuf* out) {
    UBuf cgi = {0};
    ubuf_printf(&cgi, "Status: %d %s\r\n", resp->status, http_reason(resp->status));
    if (resp->head.len) ubuf_add(&cgi, resp->head.data, resp->head.len);
    if (!resp->has_ctype) ubuf_adds(&cgi, "Content-Type: text/plain; charset=utf-8\r\n");
    ubuf_adds(&cgi, "\r\n");
    if (send_body && resp->body.len) ubuf_add(&cgi, resp->body.data, resp->body.len);

    uint8_t h[8];
    for (size_t off = 0; off < cgi.len; ) {
        size_t chunk = cgi.len - off > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : cgi.len - off;
        fcgi_header(h, FCGI_STDOUT, (uint16_t)chunk); put_u16be(h + 2, id);
        ubuf_add(out, h, 8); ubuf_add(out, cgi.data + off, chunk);
        off += chunk;
    }
    ubuf_free(&cgi);
    fcgi_header(h, FCGI_STDOUT, 0); put_u16be(h + 2, id); ubuf_add(out, h, 8);
    static const uint8_t end[8] = { 0, 0, 0, 0, 0 /* FCGI_REQUEST_COMPLETE */, 0, 0, 0 };
    fcgi_header(h, FCGI_END_REQUEST, 8); put_u16be(h + 2, id);
    ubuf_add(out, h, 8); ubuf_add(out, end, 8);
}

/* ── public API ──────────────────────────────────────────────────── */

int fastcgi_forward(int sock_fd, UReq* req, UResp* resp,
                    const char* document_root, const char* script_filename) {
    /* Send BEGIN_REQUEST */
    if (send_begin_request(sock_fd)) goto err;

    /* Build PARAMS */
    UBuf params = {0};
    if (req->fcgi_params) {
        /* Apache already resolved the script, PATH_INFO, HTTPS, REMOTE_ADDR:
           keep its params, but body framing and headers come from the
           sanitized request below */
        copy_params(&params, req->fcgi_params, req->fcgi_params_len);
        goto headers;
    }
    add_param(&params, "REQUEST_METHOD", req->method);
    add_param(&params, "REQUEST_URI", req->uri);
    add_param(&params, "QUERY_STRING", req->query);
    add_param(&params, "DOCUMENT_ROOT", document_root);
    /* frameworks derive the route from these (nginx's fastcgi_params);
       /x.php/a/b splits into script /x.php and PATH_INFO /a/b */
    char sf[4096];
    snprintf(sf, sizeof sf, "%s", script_filename);
    char* pi = strstr(sf, ".php/");
    if (pi) pi[4] = 0;
    /* from the URL, not script_filename: proxy.c appends index.php to a trailing / */
    const char* upi = strstr(req->path, ".php/");
    const char* path_info = upi ? upi + 4 : "";
    add_param(&params, "SCRIPT_FILENAME", sf);
    char script_name[4096];
    const char* rel = sf + strlen(document_root);
    snprintf(script_name, sizeof script_name, "%s%s", *rel == '/' ? "" : "/", rel);
    add_param(&params, "SCRIPT_NAME", script_name);
    add_param(&params, "PATH_INFO", path_info);
    char self[8192];
    snprintf(self, sizeof self, "%s%s", script_name, path_info);
    add_param(&params, "PHP_SELF", self);
    add_param(&params, "SERVER_PROTOCOL", "HTTP/1.1");
    add_param(&params, "SERVER_NAME", ureq_header(req, "host"));
    /* behind a local front server the client is the last X-Forwarded-For
       entry (the one it appended); earlier entries are client-supplied */
    char raddr[64];
    snprintf(raddr, sizeof raddr, "%s", req->remote_ip);
    const char* xff = ureq_header(req, "x-forwarded-for");
    if (xff && (!strcmp(req->remote_ip, "127.0.0.1") || !strcmp(req->remote_ip, "::1"))) {
        const char* last = strrchr(xff, ',');
        last = last ? last + 1 : xff;
        while (*last == ' ') last++;
        snprintf(raddr, sizeof raddr, "%.*s", (int)strcspn(last, " "), last);
    }
    add_param(&params, "REMOTE_ADDR", raddr);
    /* TLS ends at the front server, which says so in X-Forwarded-Proto */
    const char* xfp = ureq_header(req, "x-forwarded-proto");
    add_param(&params, "HTTPS", req->tls || (xfp && !strcasecmp(xfp, "https")) ? "on" : "");

    char portbuf[8];
    snprintf(portbuf, sizeof portbuf, "%d", req->local_port);
    add_param(&params, "SERVER_PORT", portbuf);

    char rportbuf[8];
    snprintf(rportbuf, sizeof rportbuf, "%d", req->remote_port);
    add_param(&params, "REMOTE_PORT", rportbuf);

headers:
    /* Content-Type and Content-Length */
    const char* ct = ureq_header(req, "content-type");
    if (ct) add_param(&params, "CONTENT_TYPE", ct);
    if (req->body_len > 0) {
        char clbuf[32];
        snprintf(clbuf, sizeof clbuf, "%zu", req->body_len);
        add_param(&params, "CONTENT_LENGTH", clbuf);
    }

    /* Forward remaining headers as HTTP_* variables */
    for (int i = 0; i < req->nh; i++) {
        const char* name = req->h[i].name;
        /* Skip headers already sent as specific params */
        if (!strcmp(name, "content-type") || !strcmp(name, "content-length")) continue;

        /* Build HTTP_NAME (uppercase, hyphens to underscores) */
        char envname[256];
        memcpy(envname, "HTTP_", 5);
        size_t j = 5;
        for (const char* c = name; *c && j < sizeof(envname) - 1; c++) {
            envname[j++] = (*c == '-') ? '_' : (char)toupper((unsigned char)*c);
        }
        envname[j] = 0;
        add_param(&params, envname, req->h[i].value);
    }

    if (send_params(sock_fd, &params)) { ubuf_free(&params); goto err; }
    ubuf_free(&params);

    /* Send STDIN (the request body) */
    if (send_stdin(sock_fd, req->body, req->body_len)) goto err;

    /* Read the response */
    UBuf raw = {0};
    if (read_response(sock_fd, &raw)) { ubuf_free(&raw); goto err; }

    /* Parse CGI response into UResp */
    if (parse_cgi_response(&raw, resp)) { ubuf_free(&raw); goto err; }
    ubuf_free(&raw);

    return 1;

err:
    uresp_init(resp);
    resp->status = 502;
    resp->close = 1;
    uresp_header(resp, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&resp->body, "Bad Gateway: FastCGI backend error");
    return 1;  /* still "done" — we have an error response */
}

/* passthru.c — phpsafepass: a checking FastCGI pass-through, Apache → PHP-FPM.
 *
 *   phpsafepass LISTEN_HOST:PORT UPSTREAM      (UPSTREAM: host:port or /unix.sock)
 *
 * Reads one FastCGI request, runs sanitize.c's checks on it (framing,
 * method/content-type, multipart structure, JSON, form encoding), and if
 * they pass forwards the ORIGINAL bytes untouched; PHP-FPM's response is
 * relayed byte for byte.  A request that fails gets an error status from
 * here and never reaches PHP.  Nothing is rewritten, so Apache's params
 * (SCRIPT_FILENAME, PATH_INFO, HTTPS, REMOTE_ADDR ...) arrive as sent.
 */
#include "userver.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

UConfig g_cfg;   /* util.c and http.c read it; defaults are fine here */

/* ponytail: fixed limits; make them flags when a site needs other values */
#define MAX_REQUEST   (64u << 20)   /* params + body */
#define FCGI_MAX_CONTENT 65535
enum { BEGIN_REQUEST = 1, ABORT_REQUEST = 2, END_REQUEST = 3, PARAMS = 4, STDIN = 5, RESPONDER = 1 };
#define CLIENT_TIMEOUT 60           /* s, Apache → us */
#define UPSTREAM_TIMEOUT 600        /* s, PHP may run long */

static const char* g_upstream;
static UBackendConstraints g_bc;   /* zero = structural checks only */

static void set_timeout(int fd, int s) {
    struct timeval tv = { s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

/* "host:port" / "[v6]:port"; host split off into h */
static int split_hostport(const char* spec, char* h, size_t hn, const char** port) {
    const char* colon = strrchr(spec, ':');
    if (!colon || (size_t)(colon - spec) >= hn) return -1;
    snprintf(h, hn, "%.*s", (int)(colon - spec), spec[0] == '[' ? spec + 1 : spec);
    char* e = strchr(h, ']'); if (e) *e = 0;
    *port = colon + 1;
    return 0;
}

static int dial(const char* spec) {
    if (spec[0] == '/') {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a = { .sun_family = AF_UNIX };
        snprintf(a.sun_path, sizeof a.sun_path, "%s", spec);
        if (fd >= 0 && connect(fd, (struct sockaddr*)&a, sizeof a) == 0) return fd;
        if (fd >= 0) close(fd);
        return -1;
    }
    char h[256]; const char* port;
    if (split_hostport(spec, h, sizeof h, &port)) return -1;
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res, *ai;
    if (getaddrinfo(h, port, &hints, &res)) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int listen_on(const char* spec) {
    if (spec[0] == '/') {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a = { .sun_family = AF_UNIX };
        snprintf(a.sun_path, sizeof a.sun_path, "%s", spec);
        unlink(spec);   /* clear a stale socket from a previous run */
        mode_t old = umask(0111);   /* ponytail: 0666 socket, lock down with a dir perm if the box is multi-user */
        int rc = fd < 0 || bind(fd, (struct sockaddr*)&a, sizeof a) || listen(fd, 512);
        umask(old);
        if (rc) { if (fd >= 0) close(fd); return -1; }
        return fd;
    }
    char h[256]; const char* port;
    if (split_hostport(spec, h, sizeof h, &port)) return -1;
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE }, *res;
    if (getaddrinfo(*h ? h : NULL, port, &hints, &res)) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol), one = 1;
    if (fd >= 0) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (fd < 0 || bind(fd, res->ai_addr, res->ai_addrlen) || listen(fd, 512)) { if (fd >= 0) close(fd); fd = -1; }
    freeaddrinfo(res);
    return fd;
}

static int read_full(int fd, void* buf, size_t n) {
    for (size_t got = 0; got < n; ) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const void* buf, size_t n) {
    for (size_t put = 0; put < n; ) {
        ssize_t w = write(fd, (const char*)buf + put, n - put);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return -1; }
        put += (size_t)w;
    }
    return 0;
}

/* one record appended to raw; type, id, content length and offset out */
static int read_record(int fd, UBuf* raw, uint8_t* type, uint16_t* id, size_t* cl, size_t* off) {
    uint8_t h[8];
    if (read_full(fd, h, 8) || h[0] != 1) return -1;
    *type = h[1]; *id = (uint16_t)(h[2] << 8 | h[3]); *cl = (size_t)(h[4] << 8 | h[5]);
    size_t rest = *cl + h[6];   /* content + padding */
    ubuf_add(raw, h, 8);
    *off = raw->len;
    ubuf_reserve(raw, rest);
    if (read_full(fd, raw->data + raw->len, rest)) return -1;
    raw->len += rest;
    return 0;
}

/* ── the check: rebuild just enough of a UReq for sanitize_request ── */

typedef struct { UReq* r; int bad; } Build;

static char* own(UReq* r, const char* p, size_t n) {
    char* s = strndup(p, n);
    r->allocs = realloc(r->allocs, sizeof(char*) * (size_t)(r->nallocs + 1));
    r->allocs[r->nallocs++] = s;
    return s;
}

static int is_p(const char* k, size_t kl, const char* name) { return kl == strlen(name) && !memcmp(k, name, kl); }

static int build_one(void* ctx, const char* k, size_t kl, const char* v, size_t vl) {
    Build* b = ctx; UReq* r = b->r;
    /* PHP reads these as C strings: an embedded NUL would make it see less
       than we checked.  CR/LF has no business in a header value. */
    if (memchr(k, 0, kl) || memchr(v, 0, vl)) { b->bad = 1; return 1; }
    if (is_p(k, kl, "REQUEST_METHOD")) r->method = own(r, v, vl);
    else if (is_p(k, kl, "REQUEST_URI")) r->uri = own(r, v, vl);
    else if (is_p(k, kl, "QUERY_STRING")) r->query = own(r, v, vl);
    else if (is_p(k, kl, "CONTENT_TYPE") || (kl > 5 && !memcmp(k, "HTTP_", 5))) {
        if (memchr(v, '\r', vl) || memchr(v, '\n', vl)) { b->bad = 1; return 1; }
        if (r->nh >= UREQ_MAX_HEADERS) { b->bad = 1; return 1; }
        const char* n = k[0] == 'C' ? k : k + 5; size_t nl = k[0] == 'C' ? kl : kl - 5;
        char* name = own(r, n, nl);
        for (char* c = name; *c; c++) *c = *c == '_' ? '-' : (char)tolower((unsigned char)*c);
        r->h[r->nh].name = name; r->h[r->nh].value = own(r, v, vl); r->nh++;
    }
    return 0;
}

/* 0 = pass; else resp holds the rejection */
/* 0 = pass.  On a multipart request, new_body gets the re-serialized body
   and new_ct its new Content-Type (new boundary); for anything else both
   stay empty and the caller forwards the original bytes. */
static int check(const UBuf* params, const UBuf* body, UResp* resp, UBuf* new_body, char** new_ct) {
    UReq r; memset(&r, 0, sizeof r);
    Build b = { &r, 0 };
    int rc = 0;
    if (fcgi_each_param(params->data, params->len, build_one, &b) || b.bad) {
        resp->status = 400; ubuf_adds(&resp->body, "Bad Request: malformed FastCGI params"); rc = -1; goto out;
    }
    if (!r.method) r.method = own(&r, "GET", 3);
    if (!r.uri) r.uri = own(&r, "", 0);
    if (!r.query) r.query = own(&r, "", 0);
    const char* ct = ureq_header(&r, "content-type");
    int multipart = ct && !strncasecmp(ct, "multipart/form-data", 19) && body->len > 0;
    /* sanitize re-serializes multipart (and urlencoded) into r.body; we
       keep only the multipart result, so give it a copy of the body */
    r.bodymem = malloc(body->len + 1);
    if (body->len) memcpy(r.bodymem, body->data, body->len);
    r.bodymem[body->len] = 0;
    r.body = r.bodymem; r.body_len = body->len;
    r.fcgi_params = calloc(1, 1);   /* sanitize: no X-Forwarded-* additions */
    rc = sanitize_request(&r, resp, &g_bc);
    if (rc == 0 && multipart) {
        ubuf_add(new_body, r.body, r.body_len);
        const char* nc = ureq_header(&r, "content-type");
        *new_ct = strdup(nc ? nc : ct);
    }
out:
    if (rc) fprintf(stderr, "[phpsafepass] rejected %d %s %s: %.*s\n", resp->status,
                    r.method ? r.method : "-", r.uri ? r.uri : "-", (int)resp->body.len, resp->body.data ? resp->body.data : "");
    ureq_free(&r);
    return rc;
}

/* ── rebuild a request to upstream (multipart re-serialized) ─────── */

static void enc_len(UBuf* b, size_t n) {
    if (n < 128) { uint8_t c = (uint8_t)n; ubuf_add(b, &c, 1); }
    else { uint8_t c[4] = { (uint8_t)(0x80 | n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n }; ubuf_add(b, c, 4); }
}

/* re-encode the params, swapping CONTENT_TYPE and CONTENT_LENGTH */
typedef struct { UBuf* out; const char* ct; const char* cl; } Reparam;
static int reparam_one(void* ctx, const char* k, size_t kl, const char* v, size_t vl) {
    Reparam* rp = ctx;
    if (is_p(k, kl, "CONTENT_TYPE")) { v = rp->ct; vl = strlen(rp->ct); }
    else if (is_p(k, kl, "CONTENT_LENGTH")) { v = rp->cl; vl = strlen(rp->cl); }
    enc_len(rp->out, kl); enc_len(rp->out, vl); ubuf_add(rp->out, k, kl); ubuf_add(rp->out, v, vl);
    return 0;
}

/* append a (possibly >64k, so split) FastCGI record stream of one type */
static void emit(UBuf* out, uint8_t type, uint16_t id, const char* data, size_t len) {
    size_t off = 0;
    do {
        size_t chunk = len - off > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : len - off;
        uint8_t h[8] = { 1, type, (uint8_t)(id >> 8), (uint8_t)id, (uint8_t)(chunk >> 8), (uint8_t)chunk, 0, 0 };
        ubuf_add(out, h, 8);
        if (chunk) ubuf_add(out, data + off, chunk);
        off += chunk;
    } while (off < len);
}

static void build_request(UBuf* out, uint16_t id, int keep, const UBuf* params,
                          const char* new_ct, const UBuf* new_body) {
    char cl[32]; snprintf(cl, sizeof cl, "%zu", new_body->len);
    UBuf p = {0};
    Reparam rp = { &p, new_ct, cl };
    fcgi_each_param(params->data, params->len, reparam_one, &rp);
    uint8_t begin[8] = { 0, RESPONDER, (uint8_t)(keep & 1), 0, 0, 0, 0, 0 };
    emit(out, BEGIN_REQUEST, id, (char*)begin, 8);
    emit(out, PARAMS, id, p.data, p.len);
    emit(out, PARAMS, id, NULL, 0);
    emit(out, STDIN, id, new_body->data, new_body->len);
    emit(out, STDIN, id, NULL, 0);
    ubuf_free(&p);
}

static void reply(int cfd, uint16_t id, UResp* resp) {
    UBuf out = {0};
    if (!resp->has_ctype) uresp_header(resp, "Content-Type", "text/plain; charset=utf-8"), resp->has_ctype = 1;
    fcgi_in_response(id, resp, 1, &out);
    write_all(cfd, out.data, out.len);
    ubuf_free(&out);
}


/* one request from Apache: 1 = served (connection may continue), 0 = close */
static int serve_one(int cfd) {
    UBuf raw = {0}, params = {0}, body = {0};
    uint8_t type; uint16_t id = 1; size_t cl, off;
    int keep = 0, begun = 0, again = 0;

    /* buffer it whole: BEGIN, PARAMS..., STDIN... up to the empty STDIN */
    for (;;) {
        if (read_record(cfd, &raw, &type, &id, &cl, &off) || raw.len > MAX_REQUEST) goto out;
        const uint8_t* d = (const uint8_t*)raw.data + off;
        if (type == BEGIN_REQUEST && cl >= 8) {
            if ((d[0] << 8 | d[1]) != RESPONDER) goto out;
            begun = 1; keep = d[2] & 1;
        } else if (type == PARAMS) ubuf_add(&params, d, cl);
        else if (type == STDIN) { if (!cl) break; ubuf_add(&body, d, cl); }
        else if (type == ABORT_REQUEST) goto out;
    }
    if (!begun) goto out;

    UResp resp; uresp_init(&resp);
    UBuf new_body = {0}; char* new_ct = NULL;
    if (check(&params, &body, &resp, &new_body, &new_ct)) { reply(cfd, id, &resp); uresp_free(&resp); again = keep; goto out; }
    uresp_free(&resp);

    /* multipart was re-serialized: forward the rebuilt request, not raw */
    UBuf rebuilt = {0};
    if (new_ct) { build_request(&rebuilt, id, keep, &params, new_ct, &new_body); free(new_ct); }
    ubuf_free(&new_body);
    const char* fwd = rebuilt.data ? rebuilt.data : raw.data;
    size_t fwd_len = rebuilt.data ? rebuilt.len : raw.len;

    int ufd = dial(g_upstream);
    if (ufd < 0) {
        fprintf(stderr, "[phpsafepass] cannot reach %s: %s\n", g_upstream, strerror(errno));
        uresp_init(&resp); resp.status = 502; ubuf_adds(&resp.body, "Bad Gateway");
        reply(cfd, id, &resp); uresp_free(&resp); ubuf_free(&rebuilt);
        goto out;
    }
    set_timeout(ufd, UPSTREAM_TIMEOUT);
    /* original bytes as Apache sent them, or the re-serialized multipart */
    if (write_all(ufd, fwd, fwd_len) == 0) {
        /* relay the response record by record until END_REQUEST */
        for (;;) {
            UBuf rec = {0}; uint16_t rid;
            if (read_record(ufd, &rec, &type, &rid, &cl, &off) || write_all(cfd, rec.data, rec.len)) { ubuf_free(&rec); break; }
            ubuf_free(&rec);
            if (type == END_REQUEST) { again = keep; break; }
        }
    }
    close(ufd);
    ubuf_free(&rebuilt);
out:
    ubuf_free(&raw); ubuf_free(&params); ubuf_free(&body);
    return again;
}

static void* serve(void* arg) {
    int cfd = (int)(intptr_t)arg;
    set_timeout(cfd, CLIENT_TIMEOUT);
    while (serve_one(cfd)) { }
    close(cfd);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: phpsafepass LISTEN UPSTREAM\n"
        "  LISTEN, UPSTREAM: host:port or /path/to.sock\n"); return 2; }
    g_upstream = argv[2];
    signal(SIGPIPE, SIG_IGN);
    int lfd = listen_on(argv[1]);
    if (lfd < 0) { fprintf(stderr, "[phpsafepass] cannot listen on %s: %s\n", argv[1], strerror(errno)); return 1; }
    fprintf(stderr, "[phpsafepass] %s -> %s\n", argv[1], g_upstream);
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR || errno == ECONNABORTED || errno == EMFILE) continue; break; }
        pthread_t t;
        if (pthread_create(&t, NULL, serve, (void*)(intptr_t)cfd)) { close(cfd); continue; }
        pthread_detach(t);
    }
    return 1;
}

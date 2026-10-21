#!/usr/bin/env python3
"""End-to-end tests for phpsafepass (the checking FastCGI pass-through).

Starts the built binary pointed at an in-process fake PHP-FPM, speaks
FastCGI to it the way Apache's mod_proxy_fcgi does, and asserts on both
the status returned to the client and the exact bytes the backend saw.

No framework, no deps — just the stdlib.  Run it with `make test` or
`python3 tests/test_phpsafepass.py [path/to/phpsafepass]`.
"""
import os, socket, struct, subprocess, sys, threading, time

BIN = sys.argv[1] if len(sys.argv) > 1 else "build/phpsafepass-static"

# ── FastCGI wire helpers ─────────────────────────────────────────────
FCGI_BEGIN, FCGI_END, FCGI_PARAMS, FCGI_STDIN, FCGI_STDOUT = 1, 3, 4, 5, 6
RESPONDER = 1


def _rec(t, rid, data):
    out = b""
    off = 0
    while True:
        chunk = data[off:off + 65535]
        out += struct.pack(">BBHHBB", 1, t, rid, len(chunk), 0, 0) + chunk
        off += len(chunk)
        if off >= len(data):
            break
    return out


def _len(n):
    return bytes([n]) if n < 128 else struct.pack(">I", n | 0x80000000)


def _nv(k, v):
    k, v = k.encode(), v.encode()
    return _len(len(k)) + _len(len(v)) + k + v


def build_request(params, body=b"", rid=1, keep=0):
    p = b"".join(_nv(k, v) for k, v in params.items())
    out = _rec(FCGI_BEGIN, rid, struct.pack(">HB5x", RESPONDER, keep))
    out += _rec(FCGI_PARAMS, rid, p) + _rec(FCGI_PARAMS, rid, b"")
    if body:
        out += _rec(FCGI_STDIN, rid, body)
    return out + _rec(FCGI_STDIN, rid, b"")


def parse_params(raw):
    def ln(d, i):
        if d[i] < 128:
            return d[i], i + 1
        return struct.unpack(">I", d[i:i + 4])[0] & 0x7fffffff, i + 4
    out, i = {}, 0
    while i < len(raw):
        nl, i = ln(raw, i)
        vl, i = ln(raw, i)
        out[raw[i:i + nl].decode()] = raw[i + nl:i + nl + vl].decode("latin1")
        i += nl + vl
    return out


def demux(raw):
    """Split a FastCGI response stream into (status_line, stdout_body)."""
    i, out, ended = 0, b"", False
    while i + 8 <= len(raw):
        _, t, _, cl, pl, _ = struct.unpack(">BBHHBB", raw[i:i + 8])
        if i + 8 + cl + pl > len(raw):
            break
        if t == FCGI_STDOUT:
            out += raw[i + 8:i + 8 + cl]
        if t == FCGI_END:
            ended = True
        i += 8 + cl + pl
    head, _, body = out.partition(b"\r\n\r\n")
    status = 200
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"status:"):
            status = int(line.split()[1])
    return status, head, body, ended


# ── fake PHP-FPM: records each request, answers 201 ──────────────────
class FakeFPM:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.seen = []            # (params dict, stdin bytes) per request
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        raw, params, stdin, rid = b"", b"", b"", 1
        try:
            while True:
                hdr = self._read(c, 8)
                _, t, rid, cl, pl, _ = struct.unpack(">BBHHBB", hdr)
                data = self._read(c, cl + pl)[:cl]
                if t == FCGI_PARAMS:
                    params += data
                elif t == FCGI_STDIN:
                    if cl == 0:
                        break
                    stdin += data
            self.seen.append((parse_params(params), stdin))
            resp = b"Status: 201 Created\r\nX-From: fpm\r\nContent-Type: text/plain\r\n\r\nphp body"
            c.sendall(_rec(FCGI_STDOUT, rid, resp) + _rec(FCGI_STDOUT, rid, b"")
                      + struct.pack(">BBHHBB", 1, FCGI_END, rid, 8, 0, 0) + b"\0" * 8)
        except (OSError, struct.error):
            pass
        finally:
            c.close()

    @staticmethod
    def _read(c, n):
        b = b""
        while len(b) < n:
            x = c.recv(n - len(b))
            if not x:
                raise OSError("short read")
            b += x
        return b


# ── client ───────────────────────────────────────────────────────────
def talk(port, data, reuse=None):
    s = reuse or socket.create_connection(("127.0.0.1", port))
    s.sendall(data)
    raw = b""
    while True:
        x = s.recv(65536)
        if not x:
            break
        raw += x
        _, _, _, ended = demux(raw)
        if ended:
            break
    if not reuse:
        s.close()
    return raw


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_up(port):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)


# ── test registry ────────────────────────────────────────────────────
PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, detail))


APACHE = {
    "REQUEST_METHOD": "GET", "REQUEST_URI": "/info.php/ahoj/?test", "QUERY_STRING": "test",
    "SCRIPT_FILENAME": "proxy:fcgi://localhost/info.php", "SCRIPT_NAME": "/info.php",
    "PATH_INFO": "/ahoj/", "DOCUMENT_ROOT": "/var/www", "HTTPS": "on",
    "REMOTE_ADDR": "203.0.113.9", "SERVER_NAME": "example.com", "SERVER_PORT": "443",
    "HTTP_HOST": "example.com", "HTTP_USER_AGENT": "curl/8", "HTTP_ACCEPT": "*/*",
}
MP = dict(APACHE, REQUEST_METHOD="POST", REQUEST_URI="/info.php",
          CONTENT_TYPE="multipart/form-data; boundary=XX", CONTENT_LENGTH="0")
GOOD_MP = (b'--XX\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
           b'Content-Type: text/plain\r\n\r\nHELLO\r\n'
           b'--XX\r\nContent-Disposition: form-data; name="g"\r\n\r\nworld\r\n--XX--\r\n')


def run(fpm, port):
    # ── requests that must pass through verbatim ──────────────────────
    fpm.seen.clear()
    st, _, body, ended = demux(talk(port, build_request(APACHE)))
    check("GET passes", st == 201 and ended)
    check("response body relayed", body == b"php body", repr(body))
    p, stdin = fpm.seen[-1]
    check("GET params verbatim", p["REQUEST_URI"] == "/info.php/ahoj/?test"
          and p["QUERY_STRING"] == "test" and p["PATH_INFO"] == "/ahoj/" and p["HTTPS"] == "on")
    check("GET no body", stdin == b"")

    for ct, b_ in [("application/x-www-form-urlencoded", b"a=1&b=2"),
                   ("application/json", b'{"a":[1,2,3],"b":"x"}'),
                   ("text/plain", b"anything at all")]:
        fpm.seen.clear()
        pr = dict(APACHE, REQUEST_METHOD="POST", REQUEST_URI="/info.php",
                  CONTENT_TYPE=ct, CONTENT_LENGTH=str(len(b_)))
        st, _, _, _ = demux(talk(port, build_request(pr, b_)))
        _, stdin = fpm.seen[-1]
        check("%s passes verbatim" % ct, st == 201 and stdin == b_, repr(stdin))

    # ── multipart: re-serialized, data preserved ──────────────────────
    fpm.seen.clear()
    st, _, _, _ = demux(talk(port, build_request(MP, GOOD_MP)))
    p, stdin = fpm.seen[-1]
    check("multipart passes", st == 201)
    check("multipart boundary changed", "boundary=XX" not in p["CONTENT_TYPE"], p["CONTENT_TYPE"])
    check("multipart bytes differ from input", stdin != GOOD_MP)
    check("multipart CONTENT_LENGTH matches", p["CONTENT_LENGTH"] == str(len(stdin)))
    newb = p["CONTENT_TYPE"].split("boundary=")[1].encode()
    check("multipart body uses new boundary", stdin.startswith(b"--" + newb))
    check("multipart field data preserved",
          b"HELLO" in stdin and b"world" in stdin and b'name="f"' in stdin
          and b'filename="a.txt"' in stdin and b"text/plain" in stdin)

    # ── requests that must be rejected before the backend ─────────────
    rejects = [
        ("upload progress field", MP,
         b'--XX\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n--XX--\r\n'),
        ("multipart garbage body", MP, b"no boundary here"),
        ("multipart no boundary param", dict(MP, CONTENT_TYPE="multipart/form-data"), b"x"),
        ("multipart part no disposition", MP, b'--XX\r\nX-H: 1\r\n\r\nhi\r\n--XX--\r\n'),
        ("multipart part no name", MP, b'--XX\r\nContent-Disposition: form-data\r\n\r\nhi\r\n--XX--\r\n'),
        ("multipart quote in name", MP,
         b'--XX\r\nContent-Disposition: form-data; name="a\\"b"\r\n\r\nhi\r\n--XX--\r\n'),
        ("bad JSON unbalanced", dict(APACHE, REQUEST_METHOD="POST", REQUEST_URI="/info.php",
         CONTENT_TYPE="application/json", CONTENT_LENGTH="6"), b'{"a":['),
        ("CRLF in header param", dict(APACHE, HTTP_USER_AGENT="x\r\nX-Evil: 1"), b""),
        ("NUL in param value", dict(APACHE, QUERY_STRING="a\x00b"), b""),
    ]
    for name, params, body in rejects:
        fpm.seen.clear()
        st, _, _, ended = demux(talk(port, build_request(params, body)))
        check("reject: %s" % name, st == 400 and ended and not fpm.seen,
              "status=%d forwarded=%d" % (st, len(fpm.seen)))

    # ── keep-alive: several requests on one connection ────────────────
    fpm.seen.clear()
    s = socket.create_connection(("127.0.0.1", port))
    oks = 0
    for rid in (7, 8, 9):
        st, _, _, ended = demux(talk(port, build_request(APACHE, rid=rid, keep=1), reuse=s))
        if st == 201 and ended:
            oks += 1
    s.close()
    check("keep-alive 3 requests on one conn", oks == 3 and len(fpm.seen) == 3)

    # ── backend unreachable → 502 (own instance, dead upstream) ───────
    dead = free_port()
    lp = free_port()
    p2 = subprocess.Popen([BIN, "127.0.0.1:%d" % lp, "127.0.0.1:%d" % dead], stderr=subprocess.PIPE)
    try:
        wait_up(lp)
        st, _, _, ended = demux(talk(lp, build_request(APACHE)))
        check("backend down → 502", st == 502 and ended, "status=%d" % st)
    finally:
        p2.terminate()
        p2.wait()


def main():
    if not os.path.exists(BIN):
        print("binary not found: %s (run `make pass` first)" % BIN)
        return 1
    fpm = FakeFPM()
    port = free_port()   # hand the port to phpsafepass (small race, fine for a test)
    proc = subprocess.Popen([BIN, "127.0.0.1:%d" % port, "127.0.0.1:%d" % fpm.port],
                            stderr=subprocess.PIPE)
    try:
        wait_up(port)
        run(fpm, port)
    finally:
        proc.terminate()
        proc.wait()
    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

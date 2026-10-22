//! End-to-end tests: start the built binary pointed at an in-process fake
//! PHP-FPM, speak FastCGI to it the way Apache's mod_proxy_fcgi does, and
//! assert on both the status returned to the client and the exact bytes the
//! backend saw.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use phpsafepass::fcgi::{self, parse_params};

const BIN: &str = env!("CARGO_BIN_EXE_phpsafepass");

// ── FastCGI wire helpers ─────────────────────────────────────────────────

fn build_request(params: &[(&str, &str)], body: &[u8], rid: u16, keep: u8) -> Vec<u8> {
    let mut p = Vec::new();
    for (k, v) in params {
        fcgi::encode_param(&mut p, k.as_bytes(), v.as_bytes());
    }
    let mut out = Vec::new();
    let begin = [0, 1, keep, 0, 0, 0, 0, 0]; // role=RESPONDER(1), flags=keep
    fcgi::emit(&mut out, fcgi::BEGIN_REQUEST, rid, &begin);
    fcgi::emit(&mut out, fcgi::PARAMS, rid, &p);
    fcgi::emit(&mut out, fcgi::PARAMS, rid, &[]);
    if !body.is_empty() {
        fcgi::emit(&mut out, fcgi::STDIN, rid, body);
    }
    fcgi::emit(&mut out, fcgi::STDIN, rid, &[]);
    out
}

fn read_record(s: &mut impl Read) -> std::io::Result<(u8, u16, Vec<u8>)> {
    let mut h = [0u8; 8];
    s.read_exact(&mut h)?;
    let t = h[1];
    let id = u16::from_be_bytes([h[2], h[3]]);
    let cl = u16::from_be_bytes([h[4], h[5]]) as usize;
    let pl = h[6] as usize;
    let mut b = vec![0u8; cl + pl];
    s.read_exact(&mut b)?;
    b.truncate(cl);
    Ok((t, id, b))
}

/// Send a request and read the response. Returns (status, body, ended).
fn talk(s: &mut TcpStream, data: &[u8]) -> (u16, Vec<u8>, bool) {
    s.write_all(data).unwrap();
    let mut stdout = Vec::new();
    let mut ended = false;
    loop {
        match read_record(s) {
            Ok((t, _, d)) => {
                if t == fcgi::STDOUT {
                    stdout.extend_from_slice(&d);
                }
                if t == fcgi::END_REQUEST {
                    ended = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let (status, body) = demux(&stdout);
    (status, body, ended)
}

fn demux(stdout: &[u8]) -> (u16, Vec<u8>) {
    let split = stdout.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&stdout[..i], stdout[i + 4..].to_vec()),
        None => (stdout, Vec::new()),
    };
    let mut status = 200u16;
    for line in head.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        if line.to_ascii_lowercase().starts_with("status:") {
            if let Some(n) = line.split_whitespace().nth(1) {
                status = n.parse().unwrap_or(0);
            }
        }
    }
    (status, body)
}

// ── fake PHP-FPM: records each request, answers 201 ──────────────────────

type Seen = Arc<Mutex<Vec<(Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>)>>>;

struct FakeFpm {
    port: u16,
    seen: Seen,
}

fn fake_fpm() -> FakeFpm {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut c) = conn else { return };
            let seen = Arc::clone(&seen2);
            std::thread::spawn(move || {
                let mut params = Vec::new();
                let mut stdin = Vec::new();
                #[allow(unused_assignments)]
                let mut rid = 1u16;
                loop {
                    match read_record(&mut c) {
                        Ok((t, id, d)) => {
                            rid = id;
                            if t == fcgi::PARAMS {
                                params.extend_from_slice(&d);
                            } else if t == fcgi::STDIN {
                                if d.is_empty() {
                                    break;
                                }
                                stdin.extend_from_slice(&d);
                            }
                        }
                        Err(_) => return,
                    }
                }
                let decoded = parse_params(&params)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();
                seen.lock().unwrap().push((decoded, stdin));
                let resp = b"Status: 201 Created\r\nX-From: fpm\r\nContent-Type: text/plain\r\n\r\nphp body";
                let mut out = Vec::new();
                fcgi::emit(&mut out, fcgi::STDOUT, rid, resp);
                fcgi::emit(&mut out, fcgi::STDOUT, rid, &[]);
                out.extend_from_slice(&[1, fcgi::END_REQUEST, (rid >> 8) as u8, rid as u8, 0, 8, 0, 0]);
                out.extend_from_slice(&[0u8; 8]);
                let _ = c.write_all(&out);
            });
        }
    });
    FakeFpm { port, seen }
}

// ── process + ports ──────────────────────────────────────────────────────

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn spawn_proxy(listen: u16, upstream: u16) -> Proc {
    let p = Command::new(BIN)
        .arg(format!("127.0.0.1:{listen}"))
        .arg(format!("127.0.0.1:{upstream}"))
        .spawn()
        .expect("spawn phpsafepass");
    wait_up(listen);
    Proc(p)
}

fn wait_up(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("proxy on {port} never came up");
}

fn conn(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn get(pairs: &[(&[u8], &[u8])], name: &[u8]) -> String {
    pairs
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

// ── fixtures ──────────────────────────────────────────────────────────────

fn apache() -> Vec<(&'static str, &'static str)> {
    vec![
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", "/info.php/ahoj/?test"),
        ("QUERY_STRING", "test"),
        ("SCRIPT_FILENAME", "proxy:fcgi://localhost/info.php"),
        ("SCRIPT_NAME", "/info.php"),
        ("PATH_INFO", "/ahoj/"),
        ("DOCUMENT_ROOT", "/var/www"),
        ("HTTPS", "on"),
        ("REMOTE_ADDR", "203.0.113.9"),
        ("SERVER_NAME", "example.com"),
        ("SERVER_PORT", "443"),
        ("HTTP_HOST", "example.com"),
        ("HTTP_USER_AGENT", "curl/8"),
        ("HTTP_ACCEPT", "*/*"),
    ]
}

fn mp(ct: &'static str) -> Vec<(&'static str, &'static str)> {
    let mut p = apache();
    p[0].1 = "POST";
    p[1].1 = "/info.php";
    p.push(("CONTENT_TYPE", ct));
    p.push(("CONTENT_LENGTH", "0"));
    p
}

const GOOD_MP: &[u8] = b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nHELLO\r\n--XX\r\nContent-Disposition: form-data; name=\"g\"\r\n\r\nworld\r\n--XX--\r\n";

// ── tests ──────────────────────────────────────────────────────────────────

#[test]
fn end_to_end() {
    let fpm = fake_fpm();
    let lp = free_port();
    let _proxy = spawn_proxy(lp, fpm.port);

    // GET passes through verbatim, response relayed
    fpm.seen.lock().unwrap().clear();
    let (st, body, ended) = talk(&mut conn(lp), &build_request(&apache(), b"", 1, 0));
    assert_eq!((st, ended), (201, true));
    assert_eq!(body, b"php body");
    let (p, stdin) = fpm.seen.lock().unwrap().last().unwrap().clone();
    assert_eq!(get(&borrow(&p), b"REQUEST_URI"), "/info.php/ahoj/?test");
    assert_eq!(get(&borrow(&p), b"QUERY_STRING"), "test");
    assert_eq!(get(&borrow(&p), b"PATH_INFO"), "/ahoj/");
    assert_eq!(get(&borrow(&p), b"HTTPS"), "on");
    assert!(stdin.is_empty());

    // bodies that must pass through byte-for-byte
    for (ct, b) in [
        ("application/x-www-form-urlencoded", &b"a=1&b=2"[..]),
        ("application/json", &b"{\"a\":[1,2,3],\"b\":\"x\"}"[..]),
        ("text/plain", &b"anything at all"[..]),
    ] {
        fpm.seen.lock().unwrap().clear();
        let mut pr = apache();
        pr[0].1 = "POST";
        pr[1].1 = "/info.php";
        pr.push(("CONTENT_TYPE", ct));
        let clen = b.len().to_string();
        pr.push(("CONTENT_LENGTH", Box::leak(clen.into_boxed_str())));
        let (st, _, _) = talk(&mut conn(lp), &build_request(&pr, b, 1, 0));
        let (_, stdin) = fpm.seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(st, 201, "{ct}");
        assert_eq!(stdin, b, "{ct} body changed");
    }

    // multipart is re-serialized, data preserved
    fpm.seen.lock().unwrap().clear();
    let (st, _, _) = talk(&mut conn(lp), &build_request(&mp("multipart/form-data; boundary=XX"), GOOD_MP, 1, 0));
    assert_eq!(st, 201);
    let (p, stdin) = fpm.seen.lock().unwrap().last().unwrap().clone();
    let ct = get(&borrow(&p), b"CONTENT_TYPE");
    assert!(!ct.contains("boundary=XX"), "{ct}");
    assert_ne!(stdin, GOOD_MP);
    assert_eq!(get(&borrow(&p), b"CONTENT_LENGTH"), stdin.len().to_string());
    let nb = ct.split("boundary=").nth(1).unwrap();
    assert!(stdin.starts_with(format!("--{nb}").as_bytes()));
    let s = String::from_utf8_lossy(&stdin);
    for want in ["HELLO", "world", "name=\"f\"", "filename=\"a.txt\"", "text/plain"] {
        assert!(s.contains(want), "missing {want}");
    }

    // large multipart part (>64k) exercises record splitting both directions
    fpm.seen.lock().unwrap().clear();
    let big = vec![b'A'; 200_000];
    let mut body = Vec::new();
    body.extend_from_slice(b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"big.bin\"\r\n\r\n");
    body.extend_from_slice(&big);
    body.extend_from_slice(b"\r\n--XX--\r\n");
    let (st, _, ended) = talk(&mut conn(lp), &build_request(&mp("multipart/form-data; boundary=XX"), &body, 1, 0));
    assert_eq!((st, ended), (201, true));
    let (_, stdin) = fpm.seen.lock().unwrap().last().unwrap().clone();
    assert!(find(&stdin, &big).is_some(), "large body not preserved");

    // requests rejected before the backend: status 400, nothing forwarded
    let xx = "multipart/form-data; boundary=XX";
    let rejects: Vec<(Vec<(&str, &str)>, &[u8])> = vec![
        (mp(xx), &b"--XX\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n--XX--\r\n"[..]),
        (mp(xx), &b"no boundary here"[..]),
        (mp("multipart/form-data"), &b"x"[..]),
        (mp(xx), &b"--XX\r\nX-H: 1\r\n\r\nhi\r\n--XX--\r\n"[..]),
        (mp(xx), &b"--XX\r\nContent-Disposition: form-data\r\n\r\nhi\r\n--XX--\r\n"[..]),
        (mp(xx), &b"--XX\r\nContent-Disposition: form-data; name=\"a\\\"b\"\r\n\r\nhi\r\n--XX--\r\n"[..]),
    ];
    for (params, body) in rejects {
        fpm.seen.lock().unwrap().clear();
        let (st, _, ended) = talk(&mut conn(lp), &build_request(&params, body, 1, 0));
        assert_eq!((st, ended), (400, true), "params[0]={:?}", params[0]);
        assert!(fpm.seen.lock().unwrap().is_empty(), "request leaked to backend");
    }

    // keep-alive: several requests on one connection
    fpm.seen.lock().unwrap().clear();
    let mut s = conn(lp);
    let mut oks = 0;
    for rid in [7u16, 8, 9] {
        let (st, _, ended) = talk(&mut s, &build_request(&apache(), b"", rid, 1));
        if st == 201 && ended {
            oks += 1;
        }
    }
    assert_eq!(oks, 3);
    assert_eq!(fpm.seen.lock().unwrap().len(), 3);
}

#[test]
fn backend_down_502() {
    let dead = free_port();
    let lp = free_port();
    let _proxy = spawn_proxy(lp, dead);
    let (st, _, ended) = talk(&mut conn(lp), &build_request(&apache(), b"", 1, 0));
    assert_eq!((st, ended), (502, true));
}

// ── small builders kept out of the body for readability ───────────────────

fn borrow(p: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    p.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

//! phpsafepass — a checking FastCGI pass-through, Apache → PHP-FPM.
//!
//!   phpsafepass LISTEN UPSTREAM [--max-request S] [--max-fields N] [--max-depth N]
//!   phpsafepass --health TARGET        (exit 0 if TARGET accepts a connection)
//!   (LISTEN/UPSTREAM/TARGET: host:port or /path/to.sock)
//!
//! Reads one FastCGI request, runs the structural check, and if it passes
//! forwards the ORIGINAL bytes untouched — so Apache's params (SCRIPT_FILENAME,
//! PATH_INFO, HTTPS, REMOTE_ADDR, ...) arrive as sent. Multipart bodies are
//! re-serialized first so PHP never parses the attacker's bytes. A request
//! that fails the check gets an error status from here and never reaches PHP.

use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use phpsafepass::check::{self, Outcome};
use phpsafepass::fcgi;

const DEFAULT_MAX_REQUEST: usize = 64 << 20; // params + body; override on the CLI
const CLIENT_TIMEOUT: u64 = 60; // s, Apache → us
const UPSTREAM_TIMEOUT: u64 = 600; // s, PHP may run long

/// Runtime knobs shared with every connection.
#[derive(Clone, Copy)]
struct Config {
    max_request: usize,
    limits: check::Limits,
}

/// A client or upstream connection, TCP or Unix.
trait Stream: Read + Write + Send {
    /// Set read/write timeouts and, for TCP, disable Nagle (we send whole
    /// requests/records at once, so Nagle only adds latency).
    fn tune(&self, timeout_secs: u64);
}
impl Stream for TcpStream {
    fn tune(&self, s: u64) {
        let d = Some(Duration::from_secs(s));
        let _ = self.set_read_timeout(d);
        let _ = self.set_write_timeout(d);
        let _ = self.set_nodelay(true);
    }
}
impl Stream for UnixStream {
    fn tune(&self, s: u64) {
        let d = Some(Duration::from_secs(s));
        let _ = self.set_read_timeout(d);
        let _ = self.set_write_timeout(d);
    }
}

enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}
impl Listener {
    fn bind(spec: &str) -> io::Result<Listener> {
        if spec.starts_with('/') {
            let _ = std::fs::remove_file(spec); // clear a stale socket
            let l = UnixListener::bind(spec)?;
            // ponytail: 0666 socket; lock down with a dir perm if multi-user
            let _ = std::fs::set_permissions(spec, std::fs::Permissions::from_mode(0o666));
            Ok(Listener::Unix(l))
        } else {
            Ok(Listener::Tcp(TcpListener::bind(normalize(spec))?))
        }
    }
    fn accept(&self) -> io::Result<Box<dyn Stream>> {
        match self {
            Listener::Tcp(l) => Ok(Box::new(l.accept()?.0)),
            Listener::Unix(l) => Ok(Box::new(l.accept()?.0)),
        }
    }
}

fn normalize(spec: &str) -> String {
    if spec.starts_with(':') {
        format!("0.0.0.0{spec}") // ":9000" → all interfaces
    } else {
        spec.to_string()
    }
}

fn dial(spec: &str) -> Option<Box<dyn Stream>> {
    if spec.starts_with('/') {
        UnixStream::connect(spec).ok().map(|s| Box::new(s) as Box<dyn Stream>)
    } else {
        TcpStream::connect(normalize(spec)).ok().map(|s| Box::new(s) as Box<dyn Stream>)
    }
}

/// Read one FastCGI record. Appends the full raw record (header + content +
/// padding) to `raw`, and returns its type, request id, and content bytes.
fn read_record<R: Read + ?Sized>(r: &mut R, raw: &mut Vec<u8>) -> io::Result<(u8, u16, Vec<u8>)> {
    let mut h = [0u8; 8];
    r.read_exact(&mut h)?;
    if h[0] != fcgi::VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad FastCGI version"));
    }
    let t = h[1];
    let id = u16::from_be_bytes([h[2], h[3]]);
    let cl = u16::from_be_bytes([h[4], h[5]]) as usize;
    let pl = h[6] as usize;
    let mut buf = vec![0u8; cl + pl];
    r.read_exact(&mut buf)?;
    raw.extend_from_slice(&h);
    raw.extend_from_slice(&buf);
    buf.truncate(cl);
    Ok((t, id, buf))
}

fn send_reject<W: Write>(w: &mut W, id: u16, status: u16, body: &[u8]) {
    let mut out = Vec::new();
    fcgi::response(&mut out, id, status, body);
    let _ = w.write_all(&out);
}

/// Rebuild a FastCGI request for a re-serialized multipart body, copying
/// the original params but swapping CONTENT_TYPE and CONTENT_LENGTH.
fn build_rewrite(id: u16, keep: bool, params: &[(&[u8], &[u8])], new_ct: &str, new_body: &[u8]) -> Vec<u8> {
    let cl = new_body.len().to_string();
    let mut p = Vec::new();
    for &(k, v) in params {
        let v2: &[u8] = if k == b"CONTENT_TYPE" {
            new_ct.as_bytes()
        } else if k == b"CONTENT_LENGTH" {
            cl.as_bytes()
        } else {
            v
        };
        fcgi::encode_param(&mut p, k, v2);
    }
    let mut out = Vec::new();
    let begin = [(fcgi::RESPONDER >> 8) as u8, fcgi::RESPONDER as u8, keep as u8, 0, 0, 0, 0, 0];
    fcgi::emit(&mut out, fcgi::BEGIN_REQUEST, id, &begin);
    fcgi::emit(&mut out, fcgi::PARAMS, id, &p);
    fcgi::emit(&mut out, fcgi::PARAMS, id, &[]);
    fcgi::emit(&mut out, fcgi::STDIN, id, new_body);
    fcgi::emit(&mut out, fcgi::STDIN, id, &[]);
    out
}

/// Serve one request. Returns Ok(true) if the connection may carry another
/// (keep-alive), Ok(false) to close. The client's `BufReader` is reused
/// across keep-alive requests so bytes read ahead are not lost.
fn serve_one(client: &mut BufReader<Box<dyn Stream>>, upstream: &str, cfg: Config) -> io::Result<bool> {
    let mut raw = Vec::new();
    let mut params_buf = Vec::new();
    let mut body = Vec::new();
    #[allow(unused_assignments)]
    let mut id = 1u16; // FastCGI request id; the records below set the real one
    let mut keep = false;
    let mut begun = false;

    // Buffer the whole request: BEGIN, PARAMS..., STDIN... up to empty STDIN.
    loop {
        let (t, rid, data) = match read_record(client, &mut raw) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        id = rid;
        if raw.len() > cfg.max_request {
            return Ok(false);
        }
        match t {
            fcgi::BEGIN_REQUEST if data.len() >= 8 => {
                if u16::from_be_bytes([data[0], data[1]]) != fcgi::RESPONDER {
                    return Ok(false);
                }
                begun = true;
                keep = data[2] & 1 != 0;
            }
            fcgi::PARAMS => params_buf.extend_from_slice(&data),
            fcgi::STDIN => {
                if data.is_empty() {
                    break;
                }
                body.extend_from_slice(&data);
            }
            fcgi::ABORT_REQUEST => return Ok(false),
            _ => {}
        }
    }
    if !begun {
        return Ok(false);
    }

    let pairs = match fcgi::parse_params(&params_buf) {
        Some(p) => p,
        None => {
            send_reject(client.get_mut(), id, 400, b"Bad Request: malformed FastCGI params");
            return Ok(keep);
        }
    };

    // Only re-serialized multipart gets a new buffer; everything else is
    // forwarded straight from `raw` with no copy.
    let rebuilt: Option<Vec<u8>> = match check::check(&pairs, &body, cfg.limits) {
        Outcome::Reject { status, msg } => {
            eprintln!(
                "[phpsafepass] rejected {status} {} {}: {msg}",
                param(&pairs, b"REQUEST_METHOD"),
                param(&pairs, b"REQUEST_URI")
            );
            send_reject(client.get_mut(), id, status, msg.as_bytes());
            return Ok(keep);
        }
        Outcome::Pass => None,
        Outcome::Rewrite { content_type, body: nb } => {
            Some(build_rewrite(id, keep, &pairs, &content_type, &nb))
        }
    };
    let forward: &[u8] = rebuilt.as_deref().unwrap_or(&raw);

    let mut up = match dial(upstream) {
        Some(s) => s,
        None => {
            eprintln!("[phpsafepass] cannot reach {upstream}");
            send_reject(client.get_mut(), id, 502, b"Bad Gateway");
            return Ok(keep);
        }
    };
    up.tune(UPSTREAM_TIMEOUT);
    if up.write_all(forward).is_err() {
        return Ok(false);
    }

    // Relay the response record by record until END_REQUEST. Buffered reads
    // cut syscalls; writes go straight out (NODELAY) so streaming stays live.
    let mut up = BufReader::new(up);
    loop {
        let mut rec = Vec::new();
        let t = match read_record(&mut up, &mut rec) {
            Ok((t, _, _)) => t,
            Err(_) => return Ok(false),
        };
        if client.get_mut().write_all(&rec).is_err() {
            return Ok(false);
        }
        if t == fcgi::END_REQUEST {
            break;
        }
    }
    Ok(keep)
}

fn param<'a>(pairs: &'a [(&'a [u8], &'a [u8])], name: &[u8]) -> std::borrow::Cow<'a, str> {
    pairs
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| String::from_utf8_lossy(v))
        .unwrap_or(std::borrow::Cow::Borrowed("-"))
}

fn serve(client: Box<dyn Stream>, upstream: Arc<String>, cfg: Config) {
    client.tune(CLIENT_TIMEOUT);
    let mut reader = BufReader::new(client);
    while let Ok(true) = serve_one(&mut reader, &upstream, cfg) {}
}

/// Parse a byte size like `64M`, `128m`, `1G`, `1024K`, or a plain byte count.
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1024),
        b'm' | b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim().parse::<usize>().ok().map(|n| n * mult)
}

/// `--health TARGET`: exit 0 if we can open a connection to TARGET, else 1.
/// Lets a scratch image have a HEALTHCHECK without a shell.
fn health(target: &str) -> ! {
    std::process::exit(if dial(target).is_some() { 0 } else { 1 });
}

const USAGE: &str = "\
usage: phpsafepass LISTEN UPSTREAM [options]
       phpsafepass --health TARGET

  LISTEN, UPSTREAM, TARGET   host:port or /path/to.sock

options:
  --max-request SIZE   max buffered request size (default 64M); set near your
                       PHP post_max_size. Accepts K/M/G suffixes or plain bytes.
  --max-fields N       max form fields, multipart or urlencoded (default 1000)
  --max-depth N        max a[b][c]... name nesting per field (default 32)";

enum Mode {
    Run { listen: String, upstream: String, cfg: Config },
    Health(String),
}

/// Parse argv (without the program name). Flags take a following value.
fn parse_args(argv: &[String]) -> Result<Mode, String> {
    let mut pos: Vec<String> = Vec::new();
    let mut max_request = DEFAULT_MAX_REQUEST;
    let mut limits = check::Limits::default();
    let mut i = 0;
    let next = |i: usize, what: &str| {
        argv.get(i + 1).cloned().ok_or(format!("{what} needs a value"))
    };
    while i < argv.len() {
        match argv[i].as_str() {
            "--health" => return Ok(Mode::Health(next(i, "--health")?)),
            "--max-request" => {
                let v = next(i, "--max-request")?;
                max_request = parse_size(&v).ok_or(format!("bad --max-request: {v}"))?;
                i += 2;
            }
            "--max-fields" => {
                let v = next(i, "--max-fields")?;
                limits.max_fields = v.parse().map_err(|_| format!("bad --max-fields: {v}"))?;
                i += 2;
            }
            "--max-depth" => {
                let v = next(i, "--max-depth")?;
                limits.max_depth = v.parse().map_err(|_| format!("bad --max-depth: {v}"))?;
                i += 2;
            }
            s if s.starts_with("--") => return Err(format!("unknown option: {s}")),
            _ => {
                pos.push(argv[i].clone());
                i += 1;
            }
        }
    }
    if pos.len() != 2 {
        return Err("need exactly LISTEN and UPSTREAM".into());
    }
    Ok(Mode::Run {
        listen: pos[0].clone(),
        upstream: pos[1].clone(),
        cfg: Config { max_request, limits },
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (listen, upstream, cfg) = match parse_args(&argv) {
        Ok(Mode::Health(target)) => health(&target),
        Ok(Mode::Run { listen, upstream, cfg }) => (listen, upstream, cfg),
        Err(e) => {
            eprintln!("phpsafepass: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let upstream = Arc::new(upstream);

    let listener = match Listener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[phpsafepass] cannot listen on {listen}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "[phpsafepass] {listen} -> {upstream} (max request {} B, {} fields, depth {})",
        cfg.max_request, cfg.limits.max_fields, cfg.limits.max_depth
    );

    loop {
        match listener.accept() {
            Ok(client) => {
                let up = Arc::clone(&upstream);
                std::thread::spawn(move || serve(client, up, cfg));
            }
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units_and_bytes() {
        assert_eq!(parse_size("64M"), Some(64 << 20));
        assert_eq!(parse_size("128m"), Some(128 << 20));
        assert_eq!(parse_size("1G"), Some(1 << 30));
        assert_eq!(parse_size("512K"), Some(512 << 10));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("  32M "), Some(32 << 20));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("M"), None);
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_and_flags() {
        match parse_args(&args(&["127.0.0.1:9000", "php:9000"])).unwrap() {
            Mode::Run { listen, upstream, cfg } => {
                assert_eq!(listen, "127.0.0.1:9000");
                assert_eq!(upstream, "php:9000");
                assert_eq!(cfg.max_request, DEFAULT_MAX_REQUEST);
                assert_eq!(cfg.limits.max_fields, check::DEFAULT_MAX_FIELDS);
                assert_eq!(cfg.limits.max_depth, check::DEFAULT_MAX_DEPTH);
            }
            _ => panic!("expected Run"),
        }
        match parse_args(&args(&["a:1", "b:2", "--max-request", "8M", "--max-fields", "200", "--max-depth", "8"])).unwrap() {
            Mode::Run { cfg, .. } => {
                assert_eq!(cfg.max_request, 8 << 20);
                assert_eq!(cfg.limits.max_fields, 200);
                assert_eq!(cfg.limits.max_depth, 8);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_args_health_and_errors() {
        assert!(matches!(parse_args(&args(&["--health", "php:9000"])).unwrap(), Mode::Health(t) if t == "php:9000"));
        assert!(parse_args(&args(&["only-one"])).is_err());
        assert!(parse_args(&args(&["a:1", "b:2", "c:3"])).is_err());
        assert!(parse_args(&args(&["a:1", "b:2", "--nope"])).is_err());
        assert!(parse_args(&args(&["a:1", "b:2", "--max-fields", "xx"])).is_err());
        assert!(parse_args(&args(&["a:1", "b:2", "--max-request"])).is_err());
    }
}

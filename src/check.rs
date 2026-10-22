//! The request check: validate the FastCGI params and the body, and for
//! multipart bodies re-serialize them so PHP only ever parses bytes we
//! wrote. Mirrors the structural checks of the original C `sanitize.c`;
//! the per-backend allow-lists that tool carried are all unset in the
//! pass-through, so only the structural rules remain here.

use std::io::Read;

/// What to do with a checked request.
#[derive(Debug)]
pub enum Outcome {
    /// Forward the client's original bytes unchanged.
    Pass,
    /// Multipart body was re-serialized: forward with this Content-Type
    /// and body instead of the originals.
    Rewrite { content_type: String, body: Vec<u8> },
    /// Reject before the backend; reply with this status and message.
    Reject { status: u16, msg: &'static str },
}

const JSON_MAX_DEPTH: i32 = 32;
const JSON_MAX_STRING: usize = 1 << 20;
const URLENC_MAX_PARAMS: i32 = 128;
const URLENC_MAX_VALUE: usize = 64 << 10;
const MAX_HEADERS: usize = 128;
const MAX_PARTS: usize = 256;

/// Check one request. `params` are the decoded FastCGI name/value pairs,
/// `body` the concatenated STDIN.
pub fn check(params: &[(&[u8], &[u8])], body: &[u8]) -> Outcome {
    let mut content_type: Option<&[u8]> = None;
    let mut nheaders = 0usize;

    for &(k, v) in params {
        // PHP reads these as C strings: an embedded NUL would make it see
        // less than we checked.
        if k.contains(&0) || v.contains(&0) {
            return Outcome::Reject { status: 400, msg: "NUL byte in FastCGI param" };
        }
        let is_ct = k == b"CONTENT_TYPE";
        let is_http = k.len() > 5 && &k[..5] == b"HTTP_";
        if is_ct || is_http {
            // CR/LF has no business in a header value (would smuggle a header)
            if v.contains(&b'\r') || v.contains(&b'\n') {
                return Outcome::Reject { status: 400, msg: "CR/LF in header value" };
            }
            nheaders += 1;
            if nheaders > MAX_HEADERS {
                return Outcome::Reject { status: 400, msg: "too many headers" };
            }
        }
        if is_ct {
            content_type = Some(v);
        }
    }

    if let Some(ct) = content_type {
        if !body.is_empty() {
            if let Some(base) = media_base(ct) {
                let base = base.as_slice();
                if base == b"multipart/form-data" {
                    return match sanitize_multipart(ct, body) {
                        Ok((nct, nbody)) => Outcome::Rewrite { content_type: nct, body: nbody },
                        Err((status, msg)) => Outcome::Reject { status, msg },
                    };
                } else if base == b"application/json" {
                    if let Err((status, msg)) = sanitize_json(body) {
                        return Outcome::Reject { status, msg };
                    }
                } else if base == b"application/x-www-form-urlencoded" {
                    if let Err((status, msg)) = sanitize_urlencoded(body) {
                        return Outcome::Reject { status, msg };
                    }
                }
                // other content types pass through as-is
            }
        }
    }

    Outcome::Pass
}

/// Base media type, lowercased, parameters (`; boundary=...`) stripped.
fn media_base(ct: &[u8]) -> Option<Vec<u8>> {
    let end = find(ct, b";").unwrap_or(ct.len());
    let mut len = end;
    while len > 0 && ct[len - 1] == b' ' {
        len -= 1;
    }
    if len == 0 {
        return None;
    }
    Some(ct[..len].to_ascii_lowercase())
}

// ── multipart ──────────────────────────────────────────────────────────

struct Part<'a> {
    name: Vec<u8>,
    filename: Option<Vec<u8>>,
    content_type: Option<Vec<u8>>,
    data: &'a [u8],
}

fn sanitize_multipart(ct: &[u8], body: &[u8]) -> Result<(String, Vec<u8>), (u16, &'static str)> {
    let boundary = mp_param(ct, "boundary").ok_or((400, "Missing multipart boundary"))?;
    if boundary.is_empty() {
        return Err((400, "Missing multipart boundary"));
    }
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(&boundary);

    let mut parts: Vec<Part> = Vec::new();

    let first = find(body, &delim).ok_or((400, "No multipart boundary found in body"))?;
    let mut start = first + delim.len();
    if body[start..].starts_with(b"\r\n") {
        start += 2;
    }

    while start < body.len() && parts.len() < MAX_PARTS {
        let rel = match find(&body[start..], &delim) {
            Some(r) => r,
            None => break,
        };
        let pend = start + rel;
        let mut partlen = pend - start;
        if partlen >= 2 && &body[start + partlen - 2..start + partlen] == b"\r\n" {
            partlen -= 2;
        }
        let part = &body[start..start + partlen];

        let hdr_end = find(part, b"\r\n\r\n").ok_or((400, "Malformed multipart part"))?;
        let data = &part[hdr_end + 4..];

        let mut disposition: Option<&[u8]> = None;
        let mut content_type: Option<Vec<u8>> = None;
        for line in split(&part[..hdr_end], b"\r\n") {
            if line.len() > 20 && line[..20].eq_ignore_ascii_case(b"content-disposition:") {
                disposition = Some(trim_lead_space(&line[20..]));
            } else if line.len() > 13 && line[..13].eq_ignore_ascii_case(b"content-type:") {
                content_type = Some(trim_lead_space(&line[13..]).to_vec());
            }
        }

        let disposition = disposition.ok_or((400, "Multipart part missing Content-Disposition"))?;
        let name = mp_param(disposition, "name").ok_or((400, "Multipart part missing name"))?;
        // the field that wakes session.upload_progress (CVE-2026-109618)
        if name.as_slice() == b"PHP_SESSION_UPLOAD_PROGRESS" {
            return Err((400, "Upload progress field not allowed"));
        }
        // quotes/backslashes would break out of the quoted field on re-serialize
        if name.contains(&b'"') || name.contains(&b'\\') {
            return Err((400, "Invalid character in multipart field name"));
        }
        let filename = mp_param(disposition, "filename");
        if let Some(f) = &filename {
            if f.contains(&b'"') || f.contains(&b'\\') {
                return Err((400, "Invalid character in multipart filename"));
            }
        }

        parts.push(Part { name, filename, content_type, data });

        start = pend + delim.len();
        if body[start..].starts_with(b"--") {
            break; // final delimiter
        }
        if body[start..].starts_with(b"\r\n") {
            start += 2;
        }
    }

    if parts.is_empty() {
        return Err((400, "Empty multipart body"));
    }

    // Re-serialize from our parsed representation with a fresh boundary —
    // this is the security step: PHP never sees the original bytes.
    let nb = make_boundary();
    let mut out = Vec::new();
    for p in &parts {
        out.extend_from_slice(format!("--{}\r\n", nb).as_bytes());
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        out.extend_from_slice(&p.name);
        out.push(b'"');
        if let Some(f) = &p.filename {
            out.extend_from_slice(b"; filename=\"");
            out.extend_from_slice(f);
            out.push(b'"');
        }
        out.extend_from_slice(b"\r\n");
        if let Some(c) = &p.content_type {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(p.data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{}--\r\n", nb).as_bytes());

    Ok((format!("multipart/form-data; boundary={}", nb), out))
}

/// Pull a quoted-or-token parameter value (`name="x"`, `boundary=y`) out of
/// a header. Case-insensitive on the key; the key must start the value or
/// follow a `;`/space — so searching for `name` skips the `name` inside
/// `filename`.
fn mp_param(header: &[u8], param: &str) -> Option<Vec<u8>> {
    let pb = param.as_bytes();
    let mut from = 0;
    loop {
        let rel = find_ci(&header[from..], pb)?;
        let p = from + rel;
        let after = p + pb.len();
        if p != 0 && header[p - 1] != b';' && header[p - 1] != b' ' {
            from = after;
            continue;
        }
        let mut i = after;
        while i < header.len() && header[i] == b' ' {
            i += 1;
        }
        if i >= header.len() || header[i] != b'=' {
            from = after;
            continue;
        }
        i += 1; // past '='
        while i < header.len() && header[i] == b' ' {
            i += 1;
        }
        if i < header.len() && header[i] == b'"' {
            i += 1;
            let s = i;
            while i < header.len() && header[i] != b'"' {
                i += 1;
            }
            if i >= header.len() {
                return None; // unterminated quote
            }
            return Some(header[s..i].to_vec());
        }
        let s = i;
        while i < header.len() && !matches!(header[i], b';' | b' ' | b'\r' | b'\n') {
            i += 1;
        }
        return Some(header[s..i].to_vec());
    }
}

// ── JSON ─────────────────────────────────────────────────────────────────

/// Walk the bytes enforcing nesting depth, string length, and overall
/// balance — enough to reject the malformed input a differential parser
/// bug feeds on, without building a tree.
fn sanitize_json(body: &[u8]) -> Result<(), (u16, &'static str)> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut slen = 0usize;
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if in_string {
            if c == b'\\' {
                i += 2;
                slen += 2;
                continue;
            }
            if c == b'"' {
                if slen > JSON_MAX_STRING {
                    return Err((400, "JSON string too long"));
                }
                in_string = false;
            } else {
                slen += 1;
            }
        } else {
            match c {
                b'"' => {
                    in_string = true;
                    slen = 0;
                }
                b'{' | b'[' => {
                    depth += 1;
                    if depth > JSON_MAX_DEPTH {
                        return Err((400, "JSON nesting too deep"));
                    }
                }
                b'}' | b']' => {
                    if depth > 0 {
                        depth -= 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    if in_string || depth != 0 {
        return Err((400, "Malformed JSON"));
    }
    Ok(())
}

// ── urlencoded ─────────────────────────────────────────────────────────

/// Validate `a=1&b=2` framing (param count, value size). The body is
/// forwarded verbatim; this only rejects the pathological shapes.
fn sanitize_urlencoded(body: &[u8]) -> Result<(), (u16, &'static str)> {
    let mut params = 0i32;
    let mut p = 0;
    while p < body.len() {
        let rel = find(&body[p..], b"&");
        let pairlen = rel.unwrap_or(body.len() - p);
        if pairlen > 0 {
            params += 1;
            if params > URLENC_MAX_PARAMS {
                return Err((400, "Too many form parameters"));
            }
            let pair = &body[p..p + pairlen];
            let vlen = match find(pair, b"=") {
                Some(eq) => pairlen - (eq + 1),
                None => 0,
            };
            if vlen > URLENC_MAX_VALUE {
                return Err((400, "Form parameter value too large"));
            }
        }
        p += pairlen;
        if rel.is_some() {
            p += 1; // skip '&'
        }
    }
    Ok(())
}

// ── byte helpers ───────────────────────────────────────────────────────

fn trim_lead_space(mut s: &[u8]) -> &[u8] {
    while s.first() == Some(&b' ') {
        s = &s[1..];
    }
    s
}

/// First index of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Case-insensitive (ASCII) first index of `needle` in `hay`.
fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

fn split<'a>(hay: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = find(&hay[i..], sep) {
        out.push(&hay[i..i + rel]);
        i += rel + sep.len();
    }
    out.push(&hay[i..]);
    out
}

/// A fresh 32-char alphanumeric multipart boundary.
fn make_boundary() -> String {
    const CH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut raw = [0u8; 32];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .is_ok();
    if !ok {
        // ponytail: clock-seeded LCG fallback; fine, the boundary only
        // needs to not collide with the body, not be cryptographic
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9)
            ^ (raw.as_ptr() as u64);
        for b in raw.iter_mut() {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (seed >> 33) as u8;
        }
    }
    raw.iter().map(|&b| CH[b as usize % CH.len()] as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // string literals are 'static, so the returned slices outlive the
    // (temporary) argument array
    fn pairs(kv: &[(&'static str, &'static str)]) -> Vec<(&'static [u8], &'static [u8])> {
        kv.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())).collect()
    }

    const GOOD_MP: &[u8] = b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nHELLO\r\n--XX\r\nContent-Disposition: form-data; name=\"g\"\r\n\r\nworld\r\n--XX--\r\n";

    fn reject_status(o: Outcome) -> u16 {
        match o {
            Outcome::Reject { status, .. } => status,
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[test]
    fn get_passes() {
        let p = pairs(&[("REQUEST_METHOD", "GET"), ("QUERY_STRING", "a=1")]);
        assert!(matches!(check(&p, b""), Outcome::Pass));
    }

    #[test]
    fn json_urlencoded_text_pass_verbatim() {
        for (ct, body) in [
            ("application/x-www-form-urlencoded", &b"a=1&b=2"[..]),
            ("application/json", b"{\"a\":[1,2,3],\"b\":\"x\"}"),
            ("text/plain", b"anything at all"),
        ] {
            let p = pairs(&[("CONTENT_TYPE", ct)]);
            assert!(matches!(check(&p, body), Outcome::Pass), "ct={ct}");
        }
    }

    #[test]
    fn multipart_is_reserialized() {
        let p = pairs(&[("CONTENT_TYPE", "multipart/form-data; boundary=XX")]);
        match check(&p, GOOD_MP) {
            Outcome::Rewrite { content_type, body } => {
                assert!(!content_type.contains("boundary=XX"), "{content_type}");
                let nb = content_type.split("boundary=").nth(1).unwrap();
                assert!(body.starts_with(format!("--{nb}").as_bytes()));
                assert_ne!(body, GOOD_MP);
                let s = String::from_utf8_lossy(&body);
                for want in ["HELLO", "world", "name=\"f\"", "filename=\"a.txt\"", "text/plain", "name=\"g\""] {
                    assert!(s.contains(want), "missing {want} in {s}");
                }
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn multipart_preserves_binary_data() {
        // NUL and other control/high bytes in the part data must survive the
        // re-serialization byte-for-byte (the data must not contain the boundary)
        let payload = b"\x00\x01\x02 raw\xff\xfe bytes\x00";
        let mut body = Vec::new();
        body.extend_from_slice(b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\n\r\n");
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n--XX--\r\n");
        let p = pairs(&[("CONTENT_TYPE", "multipart/form-data; boundary=XX")]);
        match check(&p, &body) {
            Outcome::Rewrite { body, .. } => {
                assert!(find(&body, payload).is_some(), "binary payload not preserved");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn reject_upload_progress() {
        let p = pairs(&[("CONTENT_TYPE", "multipart/form-data; boundary=XX")]);
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n--XX--\r\n";
        assert_eq!(reject_status(check(&p, body)), 400);
    }

    #[test]
    fn reject_multipart_variants() {
        let xx = pairs(&[("CONTENT_TYPE", "multipart/form-data; boundary=XX")]);
        let cases: &[&[u8]] = &[
            b"no boundary here",
            b"--XX\r\nX-H: 1\r\n\r\nhi\r\n--XX--\r\n",             // no disposition
            b"--XX\r\nContent-Disposition: form-data\r\n\r\nhi\r\n--XX--\r\n", // no name
            b"--XX\r\nContent-Disposition: form-data; name=\"a\\\"b\"\r\n\r\nhi\r\n--XX--\r\n", // quote/backslash
        ];
        for body in cases {
            assert_eq!(reject_status(check(&xx, body)), 400, "{:?}", String::from_utf8_lossy(body));
        }
        // no boundary param at all
        let nb = pairs(&[("CONTENT_TYPE", "multipart/form-data")]);
        assert_eq!(reject_status(check(&nb, b"x")), 400);
    }

    #[test]
    fn mp_param_skips_name_inside_filename() {
        // filename comes first; `name` must still resolve to the real field
        let hdr = b"form-data; filename=\"name.txt\"; name=\"real\"";
        assert_eq!(mp_param(hdr, "name").unwrap(), *b"real");
        assert_eq!(mp_param(hdr, "filename").unwrap(), *b"name.txt");
    }

    #[test]
    fn mp_param_quoted_and_token() {
        assert_eq!(mp_param(b"multipart/form-data; boundary=abc123", "boundary").unwrap(), *b"abc123");
        assert_eq!(mp_param(b"form-data; name=\"a b\"", "name").unwrap(), *b"a b");
    }

    #[test]
    fn reject_bad_json() {
        let p = pairs(&[("CONTENT_TYPE", "application/json")]);
        assert_eq!(reject_status(check(&p, b"{\"a\":[")), 400);
        assert_eq!(reject_status(check(&p, b"{\"a\":\"unterminated")), 400);
    }

    #[test]
    fn json_escaped_quote_is_valid() {
        let p = pairs(&[("CONTENT_TYPE", "application/json")]);
        assert!(matches!(check(&p, b"{\"a\":\"he said \\\"hi\\\"\"}"), Outcome::Pass));
    }

    #[test]
    fn json_too_deep() {
        let deep = "[".repeat(40);
        let p = pairs(&[("CONTENT_TYPE", "application/json")]);
        assert_eq!(reject_status(check(&p, deep.as_bytes())), 400);
    }

    #[test]
    fn reject_crlf_in_header() {
        let p = pairs(&[("HTTP_USER_AGENT", "x\r\nX-Evil: 1")]);
        assert_eq!(reject_status(check(&p, b"")), 400);
    }

    #[test]
    fn reject_nul_in_param() {
        let p = vec![(&b"QUERY_STRING"[..], &b"a\x00b"[..])];
        assert_eq!(reject_status(check(&p, b"")), 400);
    }

    #[test]
    fn urlencoded_too_many_params() {
        let many = vec!["a=1"; 200].join("&");
        let p = pairs(&[("CONTENT_TYPE", "application/x-www-form-urlencoded")]);
        assert_eq!(reject_status(check(&p, many.as_bytes())), 400);
    }

    #[test]
    fn media_base_strips_params() {
        assert_eq!(media_base(b"multipart/form-data; boundary=XX").unwrap(), *b"multipart/form-data");
        assert_eq!(media_base(b"APPLICATION/JSON").unwrap(), *b"application/json");
    }

    #[test]
    fn empty_body_multipart_passes() {
        // CONTENT_TYPE multipart but no body: nothing to parse, forward as-is
        let p = pairs(&[("CONTENT_TYPE", "multipart/form-data; boundary=XX")]);
        assert!(matches!(check(&p, b""), Outcome::Pass));
    }
}

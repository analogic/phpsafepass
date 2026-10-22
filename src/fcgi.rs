//! Minimal FastCGI wire codec: name/value params in/out, record framing,
//! and a CGI-style response encoder. Just what the pass-through needs.

pub const VERSION: u8 = 1;
pub const BEGIN_REQUEST: u8 = 1;
pub const ABORT_REQUEST: u8 = 2;
pub const END_REQUEST: u8 = 3;
pub const PARAMS: u8 = 4;
pub const STDIN: u8 = 5;
pub const STDOUT: u8 = 6;
pub const RESPONDER: u16 = 1;

/// Max content bytes in one FastCGI record (the 16-bit length field).
pub const MAX_CONTENT: usize = 65535;

fn read_len(p: &[u8], i: &mut usize) -> Option<usize> {
    let b = *p.get(*i)?;
    if b < 128 {
        *i += 1;
        return Some(b as usize);
    }
    if *i + 4 > p.len() {
        return None;
    }
    let n = ((b & 0x7f) as usize) << 24
        | (p[*i + 1] as usize) << 16
        | (p[*i + 2] as usize) << 8
        | (p[*i + 3] as usize);
    *i += 4;
    Some(n)
}

/// Decode FastCGI name/value pairs into borrowed `(name, value)` slices.
/// Returns `None` if the stream is truncated or a length runs past the end.
pub fn parse_params(raw: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < raw.len() {
        let kl = read_len(raw, &mut i)?;
        let vl = read_len(raw, &mut i)?;
        if kl > raw.len() - i || vl > raw.len() - i - kl {
            return None;
        }
        out.push((&raw[i..i + kl], &raw[i + kl..i + kl + vl]));
        i += kl + vl;
    }
    Some(out)
}

fn encode_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.push(0x80 | (n >> 24) as u8);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
}

/// Encode one name/value pair onto a PARAMS buffer.
pub fn encode_param(out: &mut Vec<u8>, k: &[u8], v: &[u8]) {
    encode_len(out, k.len());
    encode_len(out, v.len());
    out.extend_from_slice(k);
    out.extend_from_slice(v);
}

/// Append a record stream of one type, splitting content over as many
/// records as needed (and always emitting at least one, so an empty
/// `data` produces the stream-terminating zero-length record).
pub fn emit(out: &mut Vec<u8>, rtype: u8, id: u16, data: &[u8]) {
    let mut off = 0;
    loop {
        let chunk = (data.len() - off).min(MAX_CONTENT);
        out.push(VERSION);
        out.push(rtype);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(chunk as u16).to_be_bytes());
        out.push(0); // padding length
        out.push(0); // reserved
        out.extend_from_slice(&data[off..off + chunk]);
        off += chunk;
        if off >= data.len() {
            break;
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

/// Encode a complete CGI response (status + plain-text body) as a FastCGI
/// STDOUT stream followed by END_REQUEST, ready to write to the client.
pub fn response(out: &mut Vec<u8>, id: u16, status: u16, body: &[u8]) {
    let mut cgi = Vec::new();
    cgi.extend_from_slice(format!("Status: {} {}\r\n", status, reason(status)).as_bytes());
    cgi.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
    cgi.extend_from_slice(body);

    emit(out, STDOUT, id, &cgi);
    emit(out, STDOUT, id, &[]); // end of STDOUT stream

    // END_REQUEST: 8-byte body (appStatus 0, protocolStatus 0 = COMPLETE)
    out.push(VERSION);
    out.push(END_REQUEST);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0);
    out.extend_from_slice(&[0u8; 8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_roundtrip_short_and_long() {
        let long = "v".repeat(200); // forces 4-byte length encoding
        let mut buf = Vec::new();
        encode_param(&mut buf, b"REQUEST_METHOD", b"GET");
        encode_param(&mut buf, b"BIG", long.as_bytes());
        let got = parse_params(&buf).unwrap();
        assert_eq!(got[0], (&b"REQUEST_METHOD"[..], &b"GET"[..]));
        assert_eq!(got[1].0, b"BIG");
        assert_eq!(got[1].1, long.as_bytes());
    }

    #[test]
    fn param_empty_value() {
        let mut buf = Vec::new();
        encode_param(&mut buf, b"QUERY_STRING", b"");
        let got = parse_params(&buf).unwrap();
        assert_eq!(got[0], (&b"QUERY_STRING"[..], &b""[..]));
    }

    #[test]
    fn param_truncated_is_none() {
        // length byte says 5 but only 2 bytes of name follow
        let buf = [5u8, 1, b'a', b'b'];
        assert!(parse_params(&buf).is_none());
    }

    #[test]
    fn param_length_overflow_is_none() {
        // name length 1, value length 200 but no bytes
        let buf = [1u8, 0x80, 0, 0, 200, b'k'];
        assert!(parse_params(&buf).is_none());
    }

    #[test]
    fn emit_splits_over_64k() {
        let data = vec![7u8; MAX_CONTENT + 10];
        let mut out = Vec::new();
        emit(&mut out, STDIN, 1, &data);
        // first record full (8 + 65535), second record 8 + 10
        assert_eq!(out.len(), 8 + MAX_CONTENT + 8 + 10);
        assert_eq!(out[1], STDIN);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), MAX_CONTENT as u16);
    }

    #[test]
    fn emit_empty_is_one_zero_record() {
        let mut out = Vec::new();
        emit(&mut out, PARAMS, 3, &[]);
        assert_eq!(out, vec![VERSION, PARAMS, 0, 3, 0, 0, 0, 0]);
    }

    #[test]
    fn response_has_status_and_end() {
        let mut out = Vec::new();
        response(&mut out, 1, 400, b"nope");
        // somewhere in the stdout content is the status line
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Status: 400 Bad Request"));
        assert!(s.contains("nope"));
        // last record is END_REQUEST
        let tail = &out[out.len() - 16..];
        assert_eq!(tail[1], END_REQUEST);
    }
}

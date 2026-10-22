//! phpsafepass — a checking FastCGI pass-through between a web server
//! (Apache mod_proxy_fcgi) and PHP-FPM.
//!
//! The binary lives in `main.rs`; the wire codec and the request check
//! are here so they can be unit-tested directly.

pub mod check;
pub mod fcgi;

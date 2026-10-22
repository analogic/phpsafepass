# phpsafepass — a checking FastCGI pass-through for PHP-FPM.
# Thin wrapper over cargo so `make` / `make test` keep working.

MUSL_TARGET := x86_64-unknown-linux-musl

.PHONY: all static test clean

all:
	cargo build --release

# Static, dependency-free binary for deploy. Needs the musl target:
#   rustup target add x86_64-unknown-linux-musl   (and musl-tools)
static:
	cargo build --release --target $(MUSL_TARGET)
	@echo "→ target/$(MUSL_TARGET)/release/phpsafepass"

test:
	cargo test

clean:
	cargo clean

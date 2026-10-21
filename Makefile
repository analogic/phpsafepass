# Makefile — phpsafepass: a checking FastCGI pass-through for PHP-FPM.
#
# Sits between the web server (Apache mod_proxy_fcgi) and PHP-FPM, checks
# every request structurally, and forwards only what passes — re-serializing
# multipart bodies so PHP never parses attacker bytes.
#
# Targets:
#   make            Dynamic-linked binary (development)   -> build/phpsafepass
#   make static     Static musl binary (deploy)           -> build/phpsafepass-static
#   make test       Build static + run the test suite
#   make clean

SHELL   := /bin/bash

CC_DYN   ?= gcc
CC_MUSL  ?= musl-gcc

CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation
CFLAGS  += -std=gnu11 -pthread -ffunction-sections -fdata-sections
LDFLAGS_DYN  = -Wl,--gc-sections
LDFLAGS_MUSL = -Wl,--gc-sections -static
LDLIBS  = -lpthread

SRC     := src/passthru.c src/sanitize.c src/fastcgi.c src/http.c src/util.c
HEADERS := src/userver.h

BUILD    := build
BIN_DYN  := $(BUILD)/phpsafepass
BIN_MUSL := $(BUILD)/phpsafepass-static

.PHONY: all static test clean

all: $(BIN_DYN)

$(BIN_DYN): $(SRC) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC_DYN) $(CFLAGS) $(LDFLAGS_DYN) -o $@ $(SRC) $(LDLIBS)
	@echo "→ $@ ($$(du -sh $@ | cut -f1))"

static: $(BIN_MUSL)

$(BIN_MUSL): $(SRC) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC_MUSL) $(CFLAGS) $(LDFLAGS_MUSL) -o $@ $(SRC) $(LDLIBS)
	strip $@
	@echo "→ $@ (static, $$(du -sh $@ | cut -f1))"

test: static
	python3 tests/test_phpsafepass.py $(BIN_MUSL)

clean:
	rm -rf $(BUILD)

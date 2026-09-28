.PHONY: test lint build install uninstall clean
SHELL_FILES := install.sh uninstall.sh bin/*.sh test/*.sh

test:            ## filter logic tests (needs jq) — runs on Linux or macOS
	@for t in test/*-tests.sh; do printf "== %-24s " $$t; out=$$(bash $$t 2>&1) && echo "$$out" | tail -1 || { echo "$$out"; exit 1; }; done

lint:            ## shell syntax + shellcheck (if installed) + cfg parses
	@for f in $(SHELL_FILES); do bash -n $$f; done
	@command -v shellcheck >/dev/null && shellcheck -S warning $(SHELL_FILES) || echo "shellcheck not installed, skipped"
	@bin/cfg.sh configs/ESDaemon.cfg json >/dev/null && echo "cfg ok"

build:           ## compile uls-writer (macOS, needs Xcode CLT)
	@mkdir -p build && swiftc -O -o build/uls-writer src/uls-writer.swift && codesign -s - -f build/uls-writer && echo "build/uls-writer ok"

install: build   ## install on this Mac (root)
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

clean:
	rm -rf build

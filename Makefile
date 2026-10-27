.PHONY: test lint build install uninstall clean
SHELL_FILES := install.sh uninstall.sh quick-install.sh bin/esdaemon bin/*.sh test/*.sh redteam/*.sh

test:            ## filter logic tests (needs jq) — runs on Linux or macOS
	@chmod +x bin/*.sh bin/esdaemon test/*.sh 2>/dev/null || true   # a bit-stripped checkout (ZIP/Windows push) still runs
	@for t in test/*-tests.sh; do printf "== %-24s " $$t; out=$$(bash $$t 2>&1) && echo "$$out" | tail -1 || { echo "$$out"; exit 1; }; done

lint:            ## shell syntax + shellcheck (if installed) + cfg parses + scripts committed executable
	@for f in $(SHELL_FILES); do bash -n $$f; done
	@command -v shellcheck >/dev/null && shellcheck -S warning $(SHELL_FILES) || echo "shellcheck not installed, skipped"
	@bash bin/cfg.sh configs/ESDaemon.cfg json >/dev/null && echo "cfg ok"   # bash-invoked: a bit-stripped checkout (ZIP/Windows push) still lints
	@if [ -e .git ]; then bad=$$(git ls-files -s $(SHELL_FILES) | grep -v '^100755' | cut -f2); \
	  [ -z "$$bad" ] || { echo "not executable in git, fix: git update-index --chmod=+x" $$bad; exit 1; }; echo "exec bits ok"; \
	else echo "not a git checkout, exec-bit check skipped"; fi   # from the git index: a ZIP or Windows tree has no execute bits on disk

build:           ## compile ESDaemon (macOS, needs Xcode CLT)
	@mkdir -p build && swiftc -O -o build/ESDaemon src/ESDaemon.swift && codesign -s - -f build/ESDaemon && echo "build/ESDaemon ok"

install: build   ## install on this Mac (root)
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

clean:
	rm -rf build

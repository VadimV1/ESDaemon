.PHONY: test lint build pkg install uninstall clean
SHELL_FILES := install.sh uninstall.sh quick-install.sh bin/esdaemon bin/*.sh test/*.sh redteam/*.sh

test:            ## filter logic tests (needs jq) — runs on Linux or macOS
	@chmod +x bin/*.sh bin/esdaemon test/*.sh 2>/dev/null || true   # a bit-stripped checkout (ZIP/Windows push) still runs
	@for t in test/*-tests.sh; do printf "== %-24s " $$t; out=$$(bash $$t 2>&1) && echo "$$out" | tail -1 || { echo "$$out"; exit 1; }; done

lint:            ## shell syntax + shellcheck (if installed) + cfg parses + scripts committed executable + text committed LF
	@bad=; for f in $(SHELL_FILES); do bash -n "$$f" || bad="$$bad $$f"; done; \
	  [ -z "$$bad" ] || { echo "syntax errors in:$$bad"; exit 1; }; echo "syntax ok"   # every file counts: a loop's status is only its last command's
	@if command -v shellcheck >/dev/null; then shellcheck -S warning $(SHELL_FILES) && echo "shellcheck ok"; \
	else echo "shellcheck not installed, skipped"; fi   # if/else, not && ||: a finding fails lint instead of passing as "not installed"
	@bash bin/cfg.sh configs/ESDaemon.cfg json >/dev/null && echo "cfg ok"   # bash-invoked: a bit-stripped checkout (ZIP/Windows push) still lints
	@if [ -e .git ]; then bad=$$(git ls-files -s $(SHELL_FILES) | grep -v '^100755' | cut -f2); \
	  [ -z "$$bad" ] || { echo "not executable in git, fix: git update-index --chmod=+x" $$bad; exit 1; }; echo "exec bits ok"; \
	else echo "not a git checkout, exec-bit check skipped"; fi   # from the git index: a ZIP or Windows tree has no execute bits on disk
	@if [ -e .git ]; then bad=$$(git ls-files --eol | grep -E '^i/(crlf|mixed)' | cut -f2); \
	  [ -z "$$bad" ] || { echo "CRLF in git, fix: git add --renormalize" $$bad; exit 1; }; echo "line endings ok"; \
	else echo "not a git checkout, line-ending check skipped"; fi   # from the git index: a file in git with CRLF checks out CRLF everywhere

build:           ## compile ESDaemon (macOS, needs Xcode CLT)
	@mkdir -p build && swiftc -O -o build/ESDaemon src/ESDaemon.swift && codesign -s - -f build/ESDaemon && echo "build/ESDaemon ok"

pkg:             ## build the macOS installer .pkg (macOS, needs pkgbuild; uses build/ESDaemon, builds it if missing)
	./bin/mkpkg.sh

install: build   ## install on this Mac (root)
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

clean:
	rm -rf build

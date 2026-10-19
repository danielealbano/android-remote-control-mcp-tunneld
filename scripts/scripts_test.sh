#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_MKTEMP="$(command -v mktemp)"
REAL_SORT="$(command -v sort)"
FAILS=0

tmproot="$(mktemp -d)"
trap 'rm -rf "$tmproot"' EXIT
export TMPDIR="$tmproot"
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

no_tmp_litter() {
	for f in "$1"/.third-party-licenses.*; do
		[ -e "$f" ] && return 1
	done
	return 0
}

make_stub_go() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/go" <<'SHIM'
#!/bin/sh
case "$1 ${2:-}" in
	"env GOROOT"|"env GOVERSION")
		echo "go env $2" >> "$STUB_CALL_LOG"
		if [ "${STUB_GO_ENV_FAIL:-}" = "$2" ]; then exit "$STUB_GO_ENV_EXIT"; fi
		if [ "$2" = "GOROOT" ]; then echo "$STUB_GOROOT"; else echo "go0.0-stub"; fi ;;
	"list "*)
		echo "go list" >> "$STUB_CALL_LOG"
		printf '%s/%s/%s\n' "${GOOS:-}" "${GOARCH:-}" "${CGO_ENABLED:-}" >> "$STUB_GO_LIST_LOG"
		printf '%s\n' "$*" >> "$STUB_GO_ARGS_LOG"
		if [ "${STUB_GO_LIST_EXIT:-0}" != "0" ]; then exit "$STUB_GO_LIST_EXIT"; fi
		cat "$STUB_GO_LIST_FILE" ;;
	*) echo "stub go: unexpected arguments: $*" >&2; exit 2 ;;
esac
SHIM
	chmod +x "$bindir/go"
}

make_stub_mktemp() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/mktemp" <<'SHIM'
#!/bin/sh
echo mktemp >> "$STUB_CALL_LOG"
n=0
if [ -e "$STUB_MKTEMP_COUNT" ]; then n="$(cat "$STUB_MKTEMP_COUNT")"; fi
n=$((n + 1))
echo "$n" > "$STUB_MKTEMP_COUNT"
printf '%s\n' "$*" >> "$STUB_MKTEMP_ARGS_LOG"
if [ "${STUB_MKTEMP_FAIL:-0}" != "0" ] && [ "$n" -ge 2 ]; then exit 5; fi
exec "$REAL_MKTEMP" "$@"
SHIM
	chmod +x "$bindir/mktemp"
}

make_stub_sort() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/sort" <<'SHIM'
#!/bin/sh
echo sort >> "$STUB_CALL_LOG"
echo "${LC_ALL:-unset}" >> "$STUB_SORT_LOG"
if [ "${STUB_SORT_EXIT:-0}" != "0" ]; then exit "$STUB_SORT_EXIT"; fi
exec "$REAL_SORT" "$@"
SHIM
	chmod +x "$bindir/sort"
}

make_fixture() {
	root="$1"
	mkdir -p "$root/goroot" "$root/mods/alpha" "$root/mods/alpha-sub" "$root/mods/beta"
	printf 'GO TOOLCHAIN LICENSE TEXT\nGO TOOLCHAIN LICENSE SECOND LINE\n' > "$root/goroot/LICENSE"
	printf 'ALPHA LICENSE TEXT\nALPHA LICENSE SECOND LINE\n' > "$root/mods/alpha/LICENSE"
	echo "ALPHA NOTICE TEXT" > "$root/mods/alpha/NOTICE"
	echo "ALPHA SUB LICENSE TEXT" > "$root/mods/alpha-sub/LICENSE"
	echo "BETA LICENCE TEXT" > "$root/mods/beta/LICENCE"
	echo "BETA COPYING TEXT" > "$root/mods/beta/COPYING"
	printf 'example.com/beta@v0.3.1 %s/mods/beta\nexample.com/alpha/sub@v0.1.0 %s/mods/alpha-sub\nexample.com/alpha@v1.2.0 %s/mods/alpha\nexample.com/alpha@v1.2.0 %s/mods/alpha\n' \
		"$root" "$root" "$root" "$root" > "$root/list.txt"
	cat > "$root/expected.txt" <<'EXPECTED'
Third-party licenses and notices for the tunneld binary.
Each section is the verbatim license or notice file of one component the binary is built from.

==== Go toolchain and standard library (go0.0-stub)

GO TOOLCHAIN LICENSE TEXT
GO TOOLCHAIN LICENSE SECOND LINE

==== example.com/alpha@v1.2.0 (LICENSE)

ALPHA LICENSE TEXT
ALPHA LICENSE SECOND LINE

==== example.com/alpha@v1.2.0 (NOTICE)

ALPHA NOTICE TEXT

==== example.com/alpha/sub@v0.1.0 (LICENSE)

ALPHA SUB LICENSE TEXT

==== example.com/beta@v0.3.1 (LICENCE)

BETA LICENCE TEXT

==== example.com/beta@v0.3.1 (COPYING)

BETA COPYING TEXT
EXPECTED
}

run_gen() {
	LC_ALL='' GOOS='' GOARCH='' CGO_ENABLED='' \
		PATH="$b:$PATH" STUB_GOROOT="$t/goroot" STUB_GO_LIST_FILE="$t/list.txt" STUB_GO_LIST_LOG="$t/list.log" \
		STUB_GO_ARGS_LOG="$t/go-args.log" \
		STUB_MKTEMP_COUNT="$t/mktemp.count" STUB_MKTEMP_ARGS_LOG="$t/mktemp-args.log" REAL_MKTEMP="$REAL_MKTEMP" \
		STUB_SORT_LOG="$t/sort.log" REAL_SORT="$REAL_SORT" STUB_CALL_LOG="$t/calls.log" \
		sh "$DIR/third-party-licenses.sh" "$@"
}

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_stub_sort "$b"
make_stub_mktemp "$b"
make_fixture "$t"
echo OLD > "$t/out.txt"
ln "$t/out.txt" "$t/old.lnk"
expected_list_log='linux/amd64/0
linux/arm64/0'
expected_go_args='list -deps -f {{if and (not .Standard) .Module (not .Module.Main)}}{{.Module.Path}}@{{.Module.Version}} {{.Module.Dir}}{{end}} ./cmd/tunneld'
expected_mktemp_args="$t/.third-party-licenses.mods.XXXXXX
$t/.third-party-licenses.XXXXXX"
expected_calls='go env GOVERSION
go env GOROOT
mktemp
mktemp
go list
go list
sort'
if run_gen "$t/out.txt" &&
  [ -n "$(find "$t/out.txt" -perm 644)" ] &&
  cmp -s "$t/expected.txt" "$t/out.txt" &&
  [ "$(cat "$t/old.lnk")" = "OLD" ] &&
  [ "$(cat "$t/list.log")" = "$expected_list_log" ] &&
  [ "$(cat "$t/go-args.log")" = "$expected_go_args
$expected_go_args" ] &&
  [ "$(cat "$t/mktemp-args.log")" = "$expected_mktemp_args" ] &&
  [ "$(cat "$t/sort.log")" = "C" ] &&
  [ "$(cat "$t/calls.log")" = "$expected_calls" ] &&
  no_tmp_litter "$t"; then
  pass "generator writes the expected file byte for byte"
else
  fail "generator writes the expected file byte for byte"
  diff "$t/expected.txt" "$t/out.txt" >&2 || :
fi

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_fixture "$t"
if (cd "$t" && run_gen) && [ -f "$t/THIRD_PARTY_LICENSES.txt" ] && no_tmp_litter "$t"; then
  pass "generator uses the default output name"
else
  fail "generator uses the default output name"
fi

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_fixture "$t"
mkdir "$t/mods/gamma"
echo "example.com/gamma@v0.0.1 $t/mods/gamma" >> "$t/list.txt"
echo OLD > "$t/out.txt"
rc=0
run_gen "$t/out.txt" 2> "$t/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q 'no license file in example.com/gamma' "$t/err.txt" &&
  [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t"; then
  pass "generator fails on a module without a license file and keeps the old output"
else
  fail "generator fails on a module without a license file and keeps the old output"
  cat "$t/err.txt" >&2
fi

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_fixture "$t"
echo "example.com/delta@v0.0.2 $t/mods/delta" >> "$t/list.txt"
echo OLD > "$t/out.txt"
rc=0
run_gen "$t/out.txt" 2> "$t/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q 'no module directory for example.com/delta' "$t/err.txt" &&
  [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t"; then
  pass "generator fails on a module without a directory and keeps the old output"
else
  fail "generator fails on a module without a directory and keeps the old output"
  cat "$t/err.txt" >&2
fi

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_fixture "$t"
echo OLD > "$t/out.txt"
rc=0
(export STUB_GO_LIST_EXIT=4; run_gen "$t/out.txt") || rc=$?
if [ "$rc" -eq 4 ] && [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t"; then
  pass "generator fails when go list fails and keeps the old output"
else
  fail "generator fails when go list fails and keeps the old output"
fi

for key in GOVERSION GOROOT; do
  t="$(mktemp -d)"
  b="$(mktemp -d)"
  make_stub_go "$b"
  make_stub_mktemp "$b"
  make_fixture "$t"
  echo OLD > "$t/out.txt"
  rc=0
  (export STUB_GO_ENV_FAIL="$key" STUB_GO_ENV_EXIT=3; run_gen "$t/out.txt") || rc=$?
  if [ "$rc" -eq 3 ] && [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t" &&
	[ ! -e "$t/list.log" ] && [ ! -e "$t/mktemp.count" ]; then
	pass "generator fails when go env $key fails before writing anything"
  else
	fail "generator fails when go env $key fails before writing anything"
  fi
done

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_stub_mktemp "$b"
make_fixture "$t"
echo OLD > "$t/out.txt"
rc=0
(export STUB_MKTEMP_FAIL=1; run_gen "$t/out.txt") || rc=$?
if [ "$rc" -eq 5 ] && [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t" &&
  [ "$(cat "$t/mktemp.count")" = "2" ]; then
  pass "generator fails when the second mktemp fails and leaves no temp file"
else
  fail "generator fails when the second mktemp fails and leaves no temp file"
fi

t="$(mktemp -d)"
b="$(mktemp -d)"
make_stub_go "$b"
make_stub_sort "$b"
make_fixture "$t"
echo OLD > "$t/out.txt"
rc=0
(export STUB_SORT_EXIT=6; run_gen "$t/out.txt") || rc=$?
if [ "$rc" -eq 6 ] && [ "$(cat "$t/out.txt")" = "OLD" ] && no_tmp_litter "$t"; then
  pass "generator fails when sort fails and keeps the old output"
else
  fail "generator fails when sort fails and keeps the old output"
fi

if [ "$FAILS" -ne 0 ]; then
  echo "$FAILS script test(s) failed"
  exit 1
fi
echo "all script tests passed"

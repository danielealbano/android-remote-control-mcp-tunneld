#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILS=0
tmproot="$(mktemp -d)"
trap 'rm -rf "$tmproot"' EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

bindir="$tmproot/bin"
mkdir -p "$bindir"
cat > "$bindir/curl" <<'SHIM'
#!/bin/sh
echo "$*" >> "$STUB_DIR/args"
url=""
data=""
while [ $# -gt 0 ]; do
	case "$1" in
	-d) data="$2"; shift 2 ;;
	-m | -K | -X | -H | -o | -w) shift 2 ;;
	-*) shift ;;
	*) url="$1"; shift ;;
	esac
done
case "$url" in
*/metrics)
	if [ -n "$data" ]; then
		cat > "$STUB_DIR/stdin"
		printf '%s' "$data" > "$STUB_DIR/body"
		printf '%s' "${STUB_BOARD_CODE:-202}"
	else
		[ "${STUB_METRICS_FAIL:-0}" = 1 ] && exit 7
		cat "$STUB_DIR/metrics"
	fi
	;;
*/healthz) printf '%s' "${STUB_HEALTHZ_CODE:-200}" ;;
*/scrape*) printf 'redis_up %s\n' "${STUB_REDIS_UP:-1}" ;;
esac
SHIM
chmod +x "$bindir/curl"

run() {
	PATH="$bindir:$PATH" STUB_DIR="$tmproot" RUNTIME_DIRECTORY="$tmproot/state" STATUS_NODE=n7 STATUS_HOST=10.0.0.7 \
		STATUS_URL=https://ingest.example.test/metrics STATUS_TOKEN=sekret-token "$@" sh "$DIR/arc-status-report.sh"
}

reset() {
	rm -rf "$tmproot/state" "$tmproot/body" "$tmproot/args"
	mkdir -p "$tmproot/state"
}

counters() {
	cat > "$tmproot/metrics" <<METRICS
tunneld_valkey_pool_timeouts_total $1
tunneld_acme_issue_total{ca="gts",result="fail"} $2
tunneld_acme_issue_total{ca="letsencrypt",result="fail"} 0
tunneld_acme_issue_total{ca="letsencrypt",result="ok"} $3
tunneld_acme_issue_total{ca="letsencrypt",result="rate-limited"} 9
METRICS
}

value_of() {
	python3 -I -c 'import json,sys
print({m["name"]: m["gauge"]["value"] for m in json.load(open(sys.argv[1]))}[sys.argv[2]])' "$tmproot/body" "$1"
}

expect() {
	got="$(value_of "$2")"
	if [ "$got" = "$3" ]; then pass "$1"; else fail "$1: $2 = $got, want $3"; fi
}

reset
counters 4 2 7
if run env >/dev/null 2>&1; then pass "a healthy node reports"; else fail "a healthy node reports"; fi
expect "the node is reported" arc_status_report 1
expect "Valkey is reachable" arc_valkey_reachable 1
expect "the local Valkey is up" arc_valkey_local_up 1
expect "the first run reports no failures from existing counters" arc_acme_failures 0
expect "the first run reports no issuance from existing counters" arc_acme_issued 0
expect "the first run reports no timeouts from existing counters" arc_valkey_pool_timeouts 0
if grep -q '"node":"n7"' "$tmproot/body"; then pass "the report carries the node"; else fail "the report carries the node"; fi
if grep -q 'sekret-token' "$tmproot/args"; then fail "the token reached a command line"; else pass "the token stays off the command line"; fi
if grep -q 'sekret-token' "$tmproot/stdin"; then pass "the token is sent through curl's config"; else fail "the token is sent through curl's config"; fi

counters 5 4 8
run env >/dev/null 2>&1
expect "new real failures are counted, rate limits are not" arc_acme_failures 2
expect "new issuance is counted" arc_acme_issued 1
expect "new pool timeouts are counted" arc_valkey_pool_timeouts 1

counters 0 1 0
run env >/dev/null 2>&1
expect "counters that reset count from zero" arc_acme_failures 1

reset
counters 0 0 0
run env STUB_HEALTHZ_CODE=503 STUB_REDIS_UP=0 >/dev/null 2>&1
expect "an unhealthy tunneld reports Valkey unreachable" arc_valkey_reachable 0
expect "a down local Valkey is reported" arc_valkey_local_up 0

reset
counters 0 0 0
if run env STUB_METRICS_FAIL=1 >/dev/null 2>&1; then fail "an unanswered metrics read must fail"; else pass "an unanswered metrics read fails"; fi
if [ -e "$tmproot/body" ]; then fail "an unanswered metrics read must send nothing"; else pass "an unanswered metrics read sends nothing"; fi

reset
counters 0 0 0
err="$(run env STUB_BOARD_CODE=401 2>&1 >/dev/null || true)"
case "$err" in
*"status board answered 401"*) pass "a refused report is an error" ;;
*) fail "a refused report is an error: $err" ;;
esac

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

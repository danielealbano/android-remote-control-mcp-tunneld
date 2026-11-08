#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILS=0
unset STATUS_REPORT_CONFIG STATUS_URL STATUS_TOKEN_FILE STUB_SSH_FAIL_ON STUB_BOARD_CODE STUB_METRICS_FAIL STUB_HEALTHZ_CODE STUB_REDIS_UP
tmproot="$(mktemp -d)"
trap 'rm -rf "$tmproot"' EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

shown() {
	if out="$("$@" 2>&1)"; then status=0; else status=$?; fi
	printf '%s\n' "$out" | sed 's/^/  output: /'
}

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
shown run env
if [ "$status" = 0 ]; then pass "a healthy node reports"; else fail "a healthy node reports: the reporter exited $status"; fi
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
shown run env
[ "$status" = 0 ] || fail "the second report must succeed: the reporter exited $status"
expect "new real failures are counted, rate limits are not" arc_acme_failures 2
expect "new issuance is counted" arc_acme_issued 1
expect "new pool timeouts are counted" arc_valkey_pool_timeouts 1

counters 0 1 0
shown run env
[ "$status" = 0 ] || fail "the report after a counter reset must succeed: the reporter exited $status"
expect "counters that reset count from zero" arc_acme_failures 1

reset
counters 0 0 0
shown run env STUB_HEALTHZ_CODE=503 STUB_REDIS_UP=0
[ "$status" = 0 ] || fail "an unhealthy node must still be reported: the reporter exited $status"
expect "an unhealthy tunneld reports Valkey unreachable" arc_valkey_reachable 0
expect "a down local Valkey is reported" arc_valkey_local_up 0

reset
counters 0 0 0
shown run env STUB_METRICS_FAIL=1
if [ "$status" = 0 ]; then fail "an unanswered metrics read must fail"; else pass "an unanswered metrics read fails"; fi
if [ -e "$tmproot/body" ]; then fail "an unanswered metrics read must send nothing"; else pass "an unanswered metrics read sends nothing"; fi

reset
counters 0 0 0
shown run env STUB_BOARD_CODE=401
case "$status:$out" in
0:*) fail "a refused report must fail" ;;
*"status board answered 401"*) pass "a refused report is an error" ;;
*) fail "a refused report is an error and says the board's answer" ;;
esac

cat > "$bindir/ssh" <<'SHIM'
#!/bin/sh
echo "$*" >> "$STUB_DIR/ssh_args"
if [ -n "${STUB_SSH_FAIL_ON:-}" ]; then
	case "$*" in
	*"$STUB_SSH_FAIL_ON"*) exit 1 ;;
	esac
fi
cat >> "$STUB_DIR/ssh_stdin"
SHIM
chmod +x "$bindir/ssh"

cat > "$tmproot/nodes.conf" <<'CONF'
# node ssh-target internal-address

n1 root@198.51.100.1 10.0.0.1
n2 root@198.51.100.2 10.0.0.2
CONF
printf 'sekret-token\n' > "$tmproot/token"

install() {
	rm -f "$tmproot/ssh_args" "$tmproot/ssh_stdin"
	PATH="$bindir:$PATH" STUB_DIR="$tmproot" sh "$DIR/install.sh" "$@"
}

has() {
	if [ -f "$tmproot/$2" ] && grep -q -- "$3" "$tmproot/$2"; then pass "$1"; else fail "$1"; fi
}

hasnt() {
	if [ -f "$tmproot/$2" ] && grep -q -- "$3" "$tmproot/$2"; then fail "$1"; else pass "$1"; fi
}

shown install --config "$tmproot/nodes.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/token" -- -o BatchMode=yes
[ "$status" = 0 ] || fail "install must succeed: it exited $status"
case "$out" in
*"n1 installed"*"n2 installed"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order" ;;
esac
has "install writes the first node's values" ssh_stdin 'STATUS_NODE=n1'
has "install writes the first node's address" ssh_stdin 'STATUS_HOST=10.0.0.1'
has "install writes the second node's values" ssh_stdin 'STATUS_NODE=n2'
has "install writes the URL" ssh_stdin 'STATUS_URL=https://ingest.example.test/metrics'
has "install writes the token to the node" ssh_stdin 'STATUS_TOKEN=sekret-token'
hasnt "install keeps the token off the command line" ssh_args 'sekret-token'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'
has "install enables the timer" ssh_args 'enable --now arc-status-report.timer'
has "install copies the reporter" ssh_stdin 'arc_valkey_reachable'

export STATUS_REPORT_CONFIG="$tmproot/nodes.conf" STATUS_URL=https://env.example.test/metrics STATUS_TOKEN_FILE="$tmproot/token"
shown install
if [ "$status" = 0 ]; then pass "install reads its settings from the environment"; else fail "install reads its settings from the environment: it exited $status"; fi
has "install uses the URL from the environment" ssh_stdin 'STATUS_URL=https://env.example.test/metrics'

shown install --url https://cli.example.test/metrics
[ "$status" = 0 ] || fail "install with a URL on the command line must succeed: it exited $status"
has "a command-line setting overrides the environment" ssh_stdin 'STATUS_URL=https://cli.example.test/metrics'
unset STATUS_REPORT_CONFIG STATUS_URL STATUS_TOKEN_FILE

refused() {
	label=$1
	want=$2
	shift 2
	rm -f "$tmproot/ssh_args"
	shown install "$@"
	case "$status:$out" in
	0:*) fail "$label must fail" ;;
	*"$want"*) pass "$label fails and says so" ;;
	*) fail "$label must say \"$want\"" ;;
	esac
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a URL" "Usage: install.sh" --config "$tmproot/nodes.conf" --token-file "$tmproot/token"
: > "$tmproot/empty-token"
refused "an empty token file" "is empty" --config "$tmproot/nodes.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/empty-token"
printf 'n1 root@198.51.100.1\n' > "$tmproot/bad.conf"
refused "an incomplete config line" "config line for n1 needs <node> <ssh-target> <internal-address>" --config "$tmproot/bad.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/token"

export STUB_SSH_FAIL_ON=root@198.51.100.1
shown install --config "$tmproot/nodes.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/token"
unset STUB_SSH_FAIL_ON
case "$status:$out" in
0:* | *"installed"*) fail "a failed node must stop the install" ;;
*"n1: ssh failed, or /etc/tunneld/status-report.env could not be written there; the install stops here"*) pass "a failed node stops the install and says so" ;;
*) fail "a failed node stops the install and says so" ;;
esac
hasnt "a failed node leaves the next node untouched" ssh_args 'root@198.51.100.2'

printf 'n1 root@198.51.100.1 10.0.0.1\nn2 root@198.51.100.2 10.0.0.2' > "$tmproot/no-final-newline.conf"
shown install --config "$tmproot/no-final-newline.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/token"
case "$status:$out" in
0:*"n2 installed"*) pass "a config without a final newline still installs its last node" ;;
*) fail "a config without a final newline still installs its last node" ;;
esac

for step in 'cat > /etc/tunneld/status-report.env|/etc/tunneld/status-report.env' 'cat > /usr/local/sbin/arc-status-report|/usr/local/sbin/arc-status-report'; do
	STUB_SSH_FAIL_ON=${step%%|*}
	export STUB_SSH_FAIL_ON
	shown install --config "$tmproot/nodes.conf" --url https://ingest.example.test/metrics --token-file "$tmproot/token"
	unset STUB_SSH_FAIL_ON
	case "$status:$out" in
	0:*) fail "a failed write of ${step#*|} must stop the install" ;;
	*"n1: ssh failed, or ${step#*|} could not be written there; the install stops here, so the nodes after it are not touched"*) pass "a failed write of ${step#*|} stops the install and says so" ;;
	*) fail "a failed write of ${step#*|} stops the install and says so" ;;
	esac
	hasnt "a failed write of ${step#*|} leaves the next node untouched" ssh_args 'root@198.51.100.2'
done

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

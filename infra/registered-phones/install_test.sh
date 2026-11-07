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
# node ssh-target

n1 root@198.51.100.1
n2 root@198.51.100.2
CONF
printf 'binary-bytes\n' > "$tmproot/arc-registered-phones"

install() {
	rm -f "$tmproot/ssh_args" "$tmproot/ssh_stdin"
	PATH="$bindir:$PATH" STUB_DIR="$tmproot" sh "$DIR/install.sh" "$@"
}

all() {
	install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-registered-phones" --enrolled-since 2026-01-02 "$@"
}

has() {
	if grep -q -- "$3" "$tmproot/$2" 2>/dev/null; then pass "$1"; else fail "$1"; fi
}

hasnt() {
	if grep -q -- "$3" "$tmproot/$2" 2>/dev/null; then fail "$1"; else pass "$1"; fi
}

out="$(all -- -o BatchMode=yes)"
case "$out" in
*"n1 installed, counted once, counts every hour"*"n2 installed, counted once, counts every hour"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order: $out" ;;
esac
has "install checks the node has tunneld's settings" ssh_args 'test -r /etc/tunneld/tunneld.env'
has "install writes the first counted day" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-01-02$'
has "install keeps the settings file private" ssh_args 'chmod 600 /etc/tunneld/registered-phones.env'
has "install copies the service" ssh_stdin 'EnvironmentFile=/etc/tunneld/registered-phones.env'
has "install copies the timer" ssh_stdin 'OnCalendar=hourly'
has "install copies the binary" ssh_stdin 'binary-bytes'
has "install replaces the binary in one step" ssh_args 'mv /usr/local/sbin/arc-registered-phones.new /usr/local/sbin/arc-registered-phones'
has "install enables the timer" ssh_args 'enable --now arc-registered-phones.timer'
has "install runs the count once" ssh_args 'start arc-registered-phones.service'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'

if REGISTERED_PHONES_CONFIG="$tmproot/nodes.conf" REGISTERED_PHONES_BINARY="$tmproot/arc-registered-phones" \
	REGISTERED_PHONES_ENROLLED_SINCE=2026-03-04 install >/dev/null; then
	pass "install reads its settings from the environment"
else
	fail "install reads its settings from the environment"
fi
has "install writes the day from the environment" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-03-04$'

REGISTERED_PHONES_ENROLLED_SINCE=2026-03-04 all --enrolled-since 2026-05-06 >/dev/null
has "a command-line setting overrides the environment" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-05-06$'

refused() {
	label=$1
	shift
	rm -f "$tmproot/ssh_args"
	if "$@" >/dev/null 2>&1; then fail "$label must fail"; else pass "$label fails"; fi
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a binary" install --config "$tmproot/nodes.conf" --enrolled-since 2026-01-02
refused "install without a first counted day" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-registered-phones"
refused "a first counted day that is not YYYY-MM-DD" all --enrolled-since 2026-1-2
refused "a first counted day with shell characters" all --enrolled-since "2026-01-02';reboot'"
printf 'n1\n' > "$tmproot/bad.conf"
refused "a config line without an ssh target" all --config "$tmproot/bad.conf"
printf 'n1 root@198.51.100.1 11:00\n' > "$tmproot/extra.conf"
refused "a config line with an extra field" all --config "$tmproot/extra.conf"

out="$(STUB_SSH_FAIL_ON=root@198.51.100.1 all 2>/dev/null || true)"
case "$out" in
*"installed"*) fail "a failed node must stop the install: $out" ;;
*) pass "a failed node stops the install" ;;
esac
hasnt "a failed node leaves the next node untouched" ssh_args 'root@198.51.100.2'

out="$(STUB_SSH_FAIL_ON='start arc-registered-phones.service' all 2>&1 || true)"
case "$out" in
*"n1: the first count failed"*) pass "a failed first count stops the install and says so" ;;
*) fail "a failed first count stops the install and says so: $out" ;;
esac
hasnt "a failed first count leaves the next node untouched" ssh_args 'root@198.51.100.2'

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

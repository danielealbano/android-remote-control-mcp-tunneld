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
# node ssh-target HH:MM

n1 root@198.51.100.1 11:00
n2 root@198.51.100.2 11:30
CONF
printf 'sekret-token\n' > "$tmproot/token"
printf 'binary-bytes\n' > "$tmproot/arc-refused-apps"

install() {
	rm -f "$tmproot/ssh_args" "$tmproot/ssh_stdin"
	PATH="$bindir:$PATH" STUB_DIR="$tmproot" sh "$DIR/install.sh" "$@"
}

all() {
	install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-refused-apps" --timezone Etc/UTC \
		--telegram-token-file "$tmproot/token" --telegram-chat 12345 "$@"
}

has() {
	if grep -q -- "$3" "$tmproot/$2" 2>/dev/null; then pass "$1"; else fail "$1"; fi
}

hasnt() {
	if grep -q -- "$3" "$tmproot/$2" 2>/dev/null; then fail "$1"; else pass "$1"; fi
}

out="$(all -- -o BatchMode=yes)"
case "$out" in
*"n1 installed, runs every day at 11:00 Etc/UTC"*"n2 installed, runs every day at 11:30 Etc/UTC"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order: $out" ;;
esac
has "install checks the node has tunneld's settings" ssh_stdin 'test -r /etc/tunneld/tunneld.env'
has "install checks the node accepts the run time" ssh_stdin "systemd-analyze calendar '\*-\*-\* 11:30:00 Etc/UTC'"
has "install writes the first node's name" ssh_stdin 'REFUSED_APPS_NODE=n1'
has "install writes the second node's name" ssh_stdin 'REFUSED_APPS_NODE=n2'
has "install writes the time zone" ssh_stdin 'REFUSED_APPS_TIMEZONE=Etc/UTC'
has "install writes the chat" ssh_stdin 'REFUSED_APPS_TELEGRAM_CHAT=12345'
has "install writes the token to the node" ssh_stdin 'REFUSED_APPS_TELEGRAM_TOKEN=sekret-token'
hasnt "install keeps the token off the command line" ssh_args 'sekret-token'
has "install gives the first node its run time" ssh_stdin 'OnCalendar=\*-\*-\* 11:00:00 Etc/UTC'
has "install gives the second node its run time" ssh_stdin 'OnCalendar=\*-\*-\* 11:30:00 Etc/UTC'
has "install copies the service" ssh_stdin 'EnvironmentFile=/etc/tunneld/tunneld.env'
has "install copies the binary" ssh_stdin 'binary-bytes'
has "install replaces the binary in one step" ssh_args 'mv /usr/local/sbin/arc-refused-apps.new /usr/local/sbin/arc-refused-apps'
has "install enables the timer" ssh_args 'enable --now arc-refused-apps.timer'
hasnt "install does not run the report itself" ssh_args 'start arc-refused-apps.service'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'

if REFUSED_APPS_CONFIG="$tmproot/nodes.conf" REFUSED_APPS_BINARY="$tmproot/arc-refused-apps" REFUSED_APPS_TIMEZONE=Etc/UTC \
	REFUSED_APPS_TELEGRAM_TOKEN_FILE="$tmproot/token" REFUSED_APPS_TELEGRAM_CHAT=-100 install >/dev/null; then
	pass "install reads its settings from the environment"
else
	fail "install reads its settings from the environment"
fi
has "install takes a negative group chat id" ssh_stdin 'REFUSED_APPS_TELEGRAM_CHAT=-100'

all --timezone Etc/GMT+1 >/dev/null
has "a command-line setting overrides the environment" ssh_stdin 'REFUSED_APPS_TIMEZONE=Etc/GMT+1'

refused() {
	label=$1
	shift
	rm -f "$tmproot/ssh_args"
	if "$@" >/dev/null 2>&1; then fail "$label must fail"; else pass "$label fails"; fi
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a binary" install --config "$tmproot/nodes.conf" --timezone Etc/UTC --telegram-token-file "$tmproot/token" --telegram-chat 1
refused "a time zone with shell characters" all --timezone "Etc/UTC';reboot'"
refused "a chat id that is not a number" all --telegram-chat 12a
refused "an empty chat id" all --telegram-chat -
: > "$tmproot/empty-token"
refused "an empty token file" all --telegram-token-file "$tmproot/empty-token"
printf 'n1 root@198.51.100.1 25:00\n' > "$tmproot/bad-time.conf"
refused "a run time that is not HH:MM" all --config "$tmproot/bad-time.conf"
printf 'n1 root@198.51.100.1\n' > "$tmproot/bad.conf"
refused "an incomplete config line" all --config "$tmproot/bad.conf"

out="$(STUB_SSH_FAIL_ON=root@198.51.100.1 all 2>/dev/null || true)"
case "$out" in
*"installed"*) fail "a failed node must stop the install: $out" ;;
*) pass "a failed node stops the install" ;;
esac
hasnt "a failed node leaves the next node untouched" ssh_args 'root@198.51.100.2'

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

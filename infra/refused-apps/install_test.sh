#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILS=0
unset REFUSED_APPS_CONFIG REFUSED_APPS_BINARY REFUSED_APPS_TIMEZONE REFUSED_APPS_TELEGRAM_TOKEN_FILE REFUSED_APPS_TELEGRAM_CHAT REFUSED_APPS_HIDE_APPS STUB_SSH_FAIL_ON
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
	if [ -f "$tmproot/$2" ] && grep -q -- "$3" "$tmproot/$2"; then pass "$1"; else fail "$1"; fi
}

hasnt() {
	if [ -f "$tmproot/$2" ] && grep -q -- "$3" "$tmproot/$2"; then fail "$1"; else pass "$1"; fi
}

run() {
	if out="$("$@" 2>&1)"; then status=0; else status=$?; fi
	printf '%s\n' "$out" | sed 's/^/  installer: /'
}

expect_ok() {
	label=$1
	shift
	run "$@"
	if [ "$status" = 0 ]; then pass "$label"; else fail "$label: the installer exited $status"; fi
}

expect_fail() {
	label=$1
	want=$2
	shift 2
	run "$@"
	if [ "$status" = 0 ]; then
		fail "$label: the installer must fail"
		return
	fi
	case "$out" in
	*"$want"*) pass "$label" ;;
	*) fail "$label: the installer must say \"$want\"" ;;
	esac
}

expect_ok "install succeeds on every node" all -- -o BatchMode=yes
case "$out" in
*"n1 installed, runs every day at 11:00 Etc/UTC"*"n2 installed, runs every day at 11:30 Etc/UTC"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order" ;;
esac
has "install checks the node has tunneld's settings" ssh_stdin 'test -r /etc/tunneld/tunneld.env'
has "install checks the node accepts the run time" ssh_stdin "systemd-analyze calendar '\*-\*-\* 11:30:00 Etc/UTC'"
has "install writes the first node's name" ssh_stdin 'REFUSED_APPS_NODE=n1'
has "install writes the second node's name" ssh_stdin 'REFUSED_APPS_NODE=n2'
has "install writes the time zone" ssh_stdin 'REFUSED_APPS_TIMEZONE=Etc/UTC'
has "install writes the chat" ssh_stdin 'REFUSED_APPS_TELEGRAM_CHAT=12345'
has "install writes the token to the node" ssh_stdin 'REFUSED_APPS_TELEGRAM_TOKEN=sekret-token'
has "install hides no app unless asked" ssh_stdin 'REFUSED_APPS_HIDE_APPS=$'
hasnt "install keeps the token off the command line" ssh_args 'sekret-token'
has "install writes the settings file privately and stops if it cannot" ssh_args 'umask 077 && cat > /etc/tunneld/refused-apps.env && chmod 600 /etc/tunneld/refused-apps.env'
has "install gives the first node its run time" ssh_stdin 'OnCalendar=\*-\*-\* 11:00:00 Etc/UTC'
has "install gives the second node its run time" ssh_stdin 'OnCalendar=\*-\*-\* 11:30:00 Etc/UTC'
has "install copies the service" ssh_stdin 'EnvironmentFile=/etc/tunneld/tunneld.env'
has "install copies the binary" ssh_stdin 'binary-bytes'
has "install replaces the binary in one step" ssh_args 'mv /usr/local/sbin/arc-refused-apps.new /usr/local/sbin/arc-refused-apps'
has "install enables the timer" ssh_args 'enable --now arc-refused-apps.timer'
hasnt "install does not run the report itself" ssh_args 'start arc-refused-apps.service'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'

export REFUSED_APPS_CONFIG="$tmproot/nodes.conf" REFUSED_APPS_BINARY="$tmproot/arc-refused-apps" REFUSED_APPS_TIMEZONE=Etc/UTC \
	REFUSED_APPS_TELEGRAM_TOKEN_FILE="$tmproot/token" REFUSED_APPS_TELEGRAM_CHAT=-100
expect_ok "install reads its settings from the environment" install
has "install takes a negative group chat id" ssh_stdin 'REFUSED_APPS_TELEGRAM_CHAT=-100'
unset REFUSED_APPS_CONFIG REFUSED_APPS_BINARY REFUSED_APPS_TELEGRAM_TOKEN_FILE REFUSED_APPS_TELEGRAM_CHAT

expect_ok "install takes a time zone from the command line over the environment" all --timezone Etc/GMT+1
has "a command-line setting overrides the environment" ssh_stdin 'REFUSED_APPS_TIMEZONE=Etc/GMT+1'
unset REFUSED_APPS_TIMEZONE

expect_ok "install takes hidden apps from the command line" all --hide-apps dev.example.own,dev.example.own.debug
has "install writes the hidden apps" ssh_stdin 'REFUSED_APPS_HIDE_APPS=dev.example.own,dev.example.own.debug$'
export REFUSED_APPS_HIDE_APPS=dev.example.own
expect_ok "install takes hidden apps from the environment" all
has "install reads the hidden apps from the environment" ssh_stdin 'REFUSED_APPS_HIDE_APPS=dev.example.own$'
unset REFUSED_APPS_HIDE_APPS

refused() {
	label=$1
	want=$2
	shift 2
	rm -f "$tmproot/ssh_args"
	expect_fail "$label fails and says so" "$want" "$@"
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a binary" "Usage: install.sh" install --config "$tmproot/nodes.conf" --timezone Etc/UTC --telegram-token-file "$tmproot/token" --telegram-chat 1
refused "a time zone with shell characters" "has characters a time zone name never has" all --timezone "Etc/UTC';reboot'"
refused "a chat id that is not a number" "Telegram chat id 12a is not a number" all --telegram-chat 12a
refused "a hidden app list with shell characters" "must be app ids separated by single commas" all --hide-apps 'dev.example.own;reboot'
refused "a hidden app list with an empty entry" "must be app ids separated by single commas" all --hide-apps dev.example.own,,dev.example.other
refused "a hidden app list ending in a comma" "must be app ids separated by single commas" all --hide-apps dev.example.own,
refused "an empty chat id" "Telegram chat id - is not a number" all --telegram-chat -
: > "$tmproot/empty-token"
refused "an empty token file" "is empty" all --telegram-token-file "$tmproot/empty-token"
printf 'n1 root@198.51.100.1 25:00\n' > "$tmproot/bad-time.conf"
refused "a run time that is not HH:MM" "run time 25:00 for n1 is not HH:MM" all --config "$tmproot/bad-time.conf"
printf 'n1 root@198.51.100.1\n' > "$tmproot/bad.conf"
refused "an incomplete config line" "config line for n1 needs <node> <ssh-target> <HH:MM>" all --config "$tmproot/bad.conf"

printf 'n1 root@198.51.100.1 11:00\nn2 root@198.51.100.2 11:30' > "$tmproot/no-final-newline.conf"
expect_ok "a config without a final newline installs" all --config "$tmproot/no-final-newline.conf"
case "$out" in
*"n2 installed, runs every day at 11:30 Etc/UTC"*) pass "a config without a final newline still installs its last node" ;;
*) fail "a config without a final newline still installs its last node" ;;
esac

export STUB_SSH_FAIL_ON=root@198.51.100.1
expect_fail "a failed node stops the install and says so" "n1 has no readable /etc/tunneld/tunneld.env, or does not accept 11:00 in Etc/UTC" all
hasnt "a failed node leaves the next node untouched" ssh_args 'root@198.51.100.2'
export STUB_SSH_FAIL_ON='cat > /etc/tunneld/refused-apps.env'
expect_fail "a settings file that cannot be written stops the install and says so" \
	"n1: ssh failed, or /etc/tunneld/refused-apps.env could not be written there; the install stops here, so the nodes after it are not touched" all
hasnt "a settings file that cannot be written leaves the next node untouched" ssh_args 'root@198.51.100.2'
unset STUB_SSH_FAIL_ON

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

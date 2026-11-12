#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILS=0
unset BUSY_CLIENTS_CONFIG BUSY_CLIENTS_BINARY BUSY_CLIENTS_TIMEZONE BUSY_CLIENTS_DAILY_HOUR BUSY_CLIENTS_TELEGRAM_TOKEN_FILE \
	BUSY_CLIENTS_TELEGRAM_CHAT BUSY_CLIENTS_EXCLUDE STUB_SSH_FAIL_ON STUB_SSH_FAIL_STDIN
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
input=$(cat)
printf '%s\n' "$input" >> "$STUB_DIR/ssh_stdin"
if [ -n "${STUB_SSH_FAIL_STDIN:-}" ]; then
	case "$input" in
	*"$STUB_SSH_FAIL_STDIN"*) exit 1 ;;
	esac
fi
SHIM
chmod +x "$bindir/ssh"

cat > "$tmproot/nodes.conf" <<'CONF'
# node ssh-target MM

n1 root@198.51.100.1 10
n2 root@198.51.100.2 40
CONF
printf 'binary-bytes\n' > "$tmproot/arc-busy-clients"
printf '123:sekret-bot-token\n' > "$tmproot/token"
: > "$tmproot/empty-token"

install() {
	rm -f "$tmproot/ssh_args" "$tmproot/ssh_stdin"
	PATH="$bindir:$PATH" STUB_DIR="$tmproot" sh "$DIR/install.sh" "$@"
}

all() {
	install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-busy-clients" --timezone Europe/Zurich --daily-hour 09 \
		--telegram-token-file "$tmproot/token" --telegram-chat -100123 --exclude 198.51.100.7,203.0.113.0/24 "$@"
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
*"n1 installed, checked once, checks every hour at minute 10"*"n2 installed, checked once, checks every hour at minute 40"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order" ;;
esac
has "install checks the node has tunneld's settings and accepts the minute and time zone" ssh_stdin "test -r /etc/tunneld/tunneld.env && systemd-analyze calendar '\*-\*-\* \*:10:00 Europe/Zurich'"
has "install writes the node" ssh_stdin '^BUSY_CLIENTS_NODE=n1$'
has "install writes the second node" ssh_stdin '^BUSY_CLIENTS_NODE=n2$'
has "install writes the time zone" ssh_stdin '^BUSY_CLIENTS_TIMEZONE=Europe/Zurich$'
has "install writes the daily hour without its leading zero" ssh_stdin '^BUSY_CLIENTS_DAILY_HOUR=9$'
has "install writes the chat" ssh_stdin '^BUSY_CLIENTS_TELEGRAM_CHAT=-100123$'
has "install writes the token without its newline" ssh_stdin '^BUSY_CLIENTS_TELEGRAM_TOKEN=123:sekret-bot-token$'
has "install writes the exclude list" ssh_stdin '^BUSY_CLIENTS_EXCLUDE=198.51.100.7,203.0.113.0/24$'
has "install keeps the settings file private" ssh_args 'umask 077 && cat > /etc/tunneld/busy-clients.env && chmod 600 /etc/tunneld/busy-clients.env'
has "install copies the service" ssh_stdin 'EnvironmentFile=/etc/tunneld/busy-clients.env'
has "install gives the first node its minute" ssh_stdin 'OnCalendar=\*-\*-\* \*:10:00'
has "install gives the second node its minute" ssh_stdin 'OnCalendar=\*-\*-\* \*:40:00'
has "install copies the binary" ssh_stdin 'binary-bytes'
has "install replaces the binary in one step" ssh_args 'mv /usr/local/sbin/arc-busy-clients.new /usr/local/sbin/arc-busy-clients'
has "install enables the timer" ssh_args 'enable --now arc-busy-clients.timer'
has "install runs the check once" ssh_args 'start arc-busy-clients.service'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'

for pair in 00:0 07:7 7:7 10:10 23:23; do
	expect_ok "a daily hour of ${pair%%:*} installs" all --daily-hour "${pair%%:*}"
	has "a daily hour of ${pair%%:*} is written as ${pair##*:}" ssh_stdin "^BUSY_CLIENTS_DAILY_HOUR=${pair##*:}\$"
done

expect_ok "an empty exclude list installs" all --exclude ''
has "an empty exclude list is written empty" ssh_stdin '^BUSY_CLIENTS_EXCLUDE=$'

export BUSY_CLIENTS_CONFIG="$tmproot/nodes.conf" BUSY_CLIENTS_BINARY="$tmproot/arc-busy-clients" BUSY_CLIENTS_TIMEZONE=UTC \
	BUSY_CLIENTS_DAILY_HOUR=8 BUSY_CLIENTS_TELEGRAM_TOKEN_FILE="$tmproot/token" BUSY_CLIENTS_TELEGRAM_CHAT=42 BUSY_CLIENTS_EXCLUDE=192.0.2.1
expect_ok "install reads its settings from the environment" install
has "install writes the time zone from the environment" ssh_stdin '^BUSY_CLIENTS_TIMEZONE=UTC$'
has "install writes the daily hour from the environment" ssh_stdin '^BUSY_CLIENTS_DAILY_HOUR=8$'
has "install writes the chat from the environment" ssh_stdin '^BUSY_CLIENTS_TELEGRAM_CHAT=42$'
has "install writes the exclude list from the environment" ssh_stdin '^BUSY_CLIENTS_EXCLUDE=192.0.2.1$'
expect_ok "install takes settings from the command line over the environment" install --daily-hour 21 --exclude 2001:db8::/32
has "a command-line daily hour overrides the environment" ssh_stdin '^BUSY_CLIENTS_DAILY_HOUR=21$'
has "a command-line exclude list overrides the environment" ssh_stdin '^BUSY_CLIENTS_EXCLUDE=2001:db8::/32$'
unset BUSY_CLIENTS_CONFIG BUSY_CLIENTS_BINARY BUSY_CLIENTS_TIMEZONE BUSY_CLIENTS_DAILY_HOUR BUSY_CLIENTS_TELEGRAM_TOKEN_FILE \
	BUSY_CLIENTS_TELEGRAM_CHAT BUSY_CLIENTS_EXCLUDE

refused() {
	label=$1
	want=$2
	shift 2
	rm -f "$tmproot/ssh_args"
	expect_fail "$label fails and says so" "$want" "$@"
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a binary" "Usage: install.sh" install --config "$tmproot/nodes.conf" --timezone UTC --daily-hour 9 --telegram-token-file "$tmproot/token" --telegram-chat 42
refused "install without a time zone" "Usage: install.sh" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-busy-clients" --daily-hour 9 --telegram-token-file "$tmproot/token" --telegram-chat 42
refused "install without a daily hour" "Usage: install.sh" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-busy-clients" --timezone UTC --telegram-token-file "$tmproot/token" --telegram-chat 42
refused "install without a token file" "Usage: install.sh" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-busy-clients" --timezone UTC --daily-hour 9 --telegram-chat 42
refused "install without a chat" "Usage: install.sh" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-busy-clients" --timezone UTC --daily-hour 9 --telegram-token-file "$tmproot/token"
refused "an unreadable token file" "cannot read $tmproot/missing-token" all --telegram-token-file "$tmproot/missing-token"
refused "an empty token file" "token file $tmproot/empty-token is empty" all --telegram-token-file "$tmproot/empty-token"
refused "a chat id that is not a number" "Telegram chat id 12a is not a number" all --telegram-chat 12a
refused "a time zone with shell characters" "time zone Europe/Zurich';reboot' has characters a time zone name never has" all --timezone "Europe/Zurich';reboot'"
refused "a daily hour of 24" "daily hour 24 is not HH (00-23)" all --daily-hour 24
refused "a daily hour that is not a number" "daily hour 9a is not HH (00-23)" all --daily-hour 9a
refused "a daily hour with shell characters" "is not HH (00-23)" all --daily-hour '9;reboot'
refused "an exclude list with shell characters" "must be addresses or CIDR ranges separated by single commas" all --exclude '192.0.2.1;reboot'
refused "an exclude list with a leading comma" "must be addresses or CIDR ranges separated by single commas" all --exclude ,192.0.2.1
refused "an exclude list with a trailing comma" "must be addresses or CIDR ranges separated by single commas" all --exclude 192.0.2.1,
refused "an exclude list with a doubled comma" "must be addresses or CIDR ranges separated by single commas" all --exclude 192.0.2.1,,192.0.2.2

printf 'n1\n' > "$tmproot/bad.conf"
refused "a config line without an ssh target" "config line for n1 needs <node> <ssh-target> <MM>; nothing was installed" all --config "$tmproot/bad.conf"
printf 'n1 root@198.51.100.1\n' > "$tmproot/no-minute.conf"
refused "a config line without a minute" "config line for n1 needs <node> <ssh-target> <MM>" all --config "$tmproot/no-minute.conf"
printf 'n1 root@198.51.100.1 00 x\n' > "$tmproot/extra.conf"
refused "a config line with an extra field" "config line for n1 needs <node> <ssh-target> <MM>" all --config "$tmproot/extra.conf"
printf 'n1 root@198.51.100.1 60\n' > "$tmproot/bad-minute.conf"
refused "a minute that is not MM" "run minute 60 for n1 is not MM (00-59); nothing was installed" all --config "$tmproot/bad-minute.conf"
printf 'n1 root@198.51.100.1 *\n' > "$tmproot/glob-minute.conf"
refused "a minute with shell characters" "is not MM (00-59)" all --config "$tmproot/glob-minute.conf"
printf 'n1 root@198.51.100.1 00\nn2 root@198.51.100.2 x\n' > "$tmproot/late-bad.conf"
refused "a bad line after a good one" "run minute x for n2 is not MM (00-59); nothing was installed" all --config "$tmproot/late-bad.conf"
printf 'n1 root@198.51.100.1 00\nn2 root@198.51.100.2 10\n' > "$tmproot/close.conf"
refused "two nodes less than 30 minutes apart" "n2 (minute 10) and n1 (minute 00) run less than 30 minutes apart" all --config "$tmproot/close.conf"
printf 'n1 root@198.51.100.1 50\nn2 root@198.51.100.2 05\n' > "$tmproot/close-around-the-hour.conf"
refused "two nodes less than 30 minutes apart around the hour" "n2 (minute 05) and n1 (minute 50) run less than 30 minutes apart" all --config "$tmproot/close-around-the-hour.conf"
printf 'n1 root@198.51.100.1 15\nn2 root@198.51.100.2 15\n' > "$tmproot/same.conf"
refused "two nodes at the same minute" "run less than 30 minutes apart" all --config "$tmproot/same.conf"
printf 'n1 root@198.51.100.1 00\nn2 root@198.51.100.2 30\nn3 root@198.51.100.3 45\n' > "$tmproot/three.conf"
refused "a third node" "n3 (minute 45) and n1 (minute 00) run less than 30 minutes apart" all --config "$tmproot/three.conf"
printf '# no nodes\n\n' > "$tmproot/empty.conf"
refused "a config without nodes" "names no node; nothing was installed" all --config "$tmproot/empty.conf"

printf 'n1 root@198.51.100.1 10\nn2 root@198.51.100.2 40' > "$tmproot/no-final-newline.conf"
expect_ok "a config without a final newline installs" all --config "$tmproot/no-final-newline.conf"
case "$out" in
*"n2 installed, checked once, checks every hour at minute 40"*) pass "a config without a final newline still installs its last node" ;;
*) fail "a config without a final newline still installs its last node" ;;
esac

stops() {
	label=$1
	want=$2
	expect_fail "$label stops the install and says so" "n1: $want; the install stops here, so the nodes after it are not touched" all
	hasnt "$label leaves the next node untouched" ssh_args 'root@198.51.100.2'
}

export STUB_SSH_FAIL_ON=root@198.51.100.1
stops "an unreachable node" "ssh failed, /etc/tunneld/tunneld.env is not readable there, or it does not accept the time zone Europe/Zurich"
export STUB_SSH_FAIL_ON='cat > /etc/tunneld/busy-clients.env'
stops "a settings file that cannot be written" "ssh failed, or /etc/tunneld/busy-clients.env could not be written there"
export STUB_SSH_FAIL_ON='cat > /etc/systemd/system/arc-busy-clients.service'
stops "a service unit that cannot be written" "ssh failed, or the service unit could not be written there"
export STUB_SSH_FAIL_ON='cat > /etc/systemd/system/arc-busy-clients.timer'
stops "a timer unit that cannot be written" "ssh failed, or the timer unit could not be written there"
export STUB_SSH_FAIL_ON='cat > /usr/local/sbin/arc-busy-clients.new'
stops "a binary that cannot be installed" "ssh failed, or the binary could not be installed there"
export STUB_SSH_FAIL_ON='enable --now arc-busy-clients.timer'
stops "a timer that cannot be enabled" "ssh failed, or systemd could not enable the hourly timer"
hasnt "a timer that cannot be enabled runs no check" ssh_args 'start arc-busy-clients.service'
export STUB_SSH_FAIL_ON='systemctl start arc-busy-clients.service'
stops "a failed first check" "ssh failed, or the first check failed; journalctl -u arc-busy-clients on the node says why"
unset STUB_SSH_FAIL_ON

export STUB_SSH_FAIL_STDIN='systemd-analyze calendar'
expect_fail "a time zone the node does not know stops the install and says so" "n1: ssh failed, /etc/tunneld/tunneld.env is not readable there, or it does not accept the time zone Europe/Zurich" all
hasnt "a time zone the node does not know writes no settings" ssh_stdin 'BUSY_CLIENTS_NODE='
hasnt "a time zone the node does not know leaves the next node untouched" ssh_args 'root@198.51.100.2'
unset STUB_SSH_FAIL_STDIN

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILS=0
unset REGISTERED_PHONES_CONFIG REGISTERED_PHONES_BINARY REGISTERED_PHONES_ENROLLED_SINCE STUB_SSH_FAIL_ON STUB_SSH_FAIL_STDIN
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

n1 root@198.51.100.1 00
n2 root@198.51.100.2 30
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
*"n1 installed, counted once, counts every hour at minute 00"*"n2 installed, counted once, counts every hour at minute 30"*) pass "install reaches every node in order, past comments and blanks" ;;
*) fail "install reaches every node in order" ;;
esac
has "install checks the node has tunneld's settings" ssh_stdin 'test -r /etc/tunneld/tunneld.env'
has "install checks the first counted day is a real day on the node" ssh_stdin 'date -u -d 2026-01-02 +%F)" = 2026-01-02 \]'
has "install writes the first counted day" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-01-02$'
has "install keeps the settings file private" ssh_args 'umask 077 && cat > /etc/tunneld/registered-phones.env && chmod 600 /etc/tunneld/registered-phones.env'
has "install copies the service" ssh_stdin 'EnvironmentFile=/etc/tunneld/registered-phones.env'
has "install gives the first node its minute" ssh_stdin 'OnCalendar=\*-\*-\* \*:00:00'
has "install gives the second node its minute" ssh_stdin 'OnCalendar=\*-\*-\* \*:30:00'
has "install copies the binary" ssh_stdin 'binary-bytes'
has "install replaces the binary in one step" ssh_args 'mv /usr/local/sbin/arc-registered-phones.new /usr/local/sbin/arc-registered-phones'
has "install enables the timer" ssh_args 'enable --now arc-registered-phones.timer'
has "install runs the count once" ssh_args 'start arc-registered-phones.service'
has "install passes the options after -- to ssh" ssh_args '-o BatchMode=yes root@198.51.100.2'

export REGISTERED_PHONES_CONFIG="$tmproot/nodes.conf" REGISTERED_PHONES_BINARY="$tmproot/arc-registered-phones" REGISTERED_PHONES_ENROLLED_SINCE=2026-03-04
expect_ok "install reads its settings from the environment" install
has "install writes the day from the environment" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-03-04$'
expect_ok "install takes a day from the command line over the environment" all --enrolled-since 2026-05-06
has "a command-line setting overrides the environment" ssh_stdin '^REGISTERED_PHONES_ENROLLED_SINCE=2026-05-06$'
unset REGISTERED_PHONES_CONFIG REGISTERED_PHONES_BINARY REGISTERED_PHONES_ENROLLED_SINCE

refused() {
	label=$1
	want=$2
	shift 2
	rm -f "$tmproot/ssh_args"
	expect_fail "$label fails and says so" "$want" "$@"
	if [ -e "$tmproot/ssh_args" ]; then fail "$label must touch no node"; else pass "$label touches no node"; fi
}

refused "install without a binary" "Usage: install.sh" install --config "$tmproot/nodes.conf" --enrolled-since 2026-01-02
refused "install without a first counted day" "Usage: install.sh" install --config "$tmproot/nodes.conf" --binary "$tmproot/arc-registered-phones"
refused "a first counted day that is not YYYY-MM-DD" "first counted day 2026-1-2 is not YYYY-MM-DD" all --enrolled-since 2026-1-2
refused "a first counted day with shell characters" "is not YYYY-MM-DD" all --enrolled-since "2026-01-02';reboot'"
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
printf 'n1 root@198.51.100.1 50\nn2 root@198.51.100.2 20\n' > "$tmproot/apart-around-the-hour.conf"
expect_ok "two nodes 30 minutes apart around the hour install" all --config "$tmproot/apart-around-the-hour.conf"

printf 'n1 root@198.51.100.1 00\nn2 root@198.51.100.2 30' > "$tmproot/no-final-newline.conf"
expect_ok "a config without a final newline installs" all --config "$tmproot/no-final-newline.conf"
case "$out" in
*"n2 installed, counted once, counts every hour at minute 30"*) pass "a config without a final newline still installs its last node" ;;
*) fail "a config without a final newline still installs its last node" ;;
esac

stops() {
	label=$1
	want=$2
	expect_fail "$label stops the install and says so" "n1: $want; the install stops here, so the nodes after it are not touched" all
	hasnt "$label leaves the next node untouched" ssh_args 'root@198.51.100.2'
}

export STUB_SSH_FAIL_ON=root@198.51.100.1
stops "an unreachable node" "ssh failed, /etc/tunneld/tunneld.env is not readable there, or 2026-01-02 is not a real day"
export STUB_SSH_FAIL_ON='cat > /etc/tunneld/registered-phones.env'
stops "a settings file that cannot be written" "ssh failed, or /etc/tunneld/registered-phones.env could not be written there"
export STUB_SSH_FAIL_ON='cat > /etc/systemd/system/arc-registered-phones.service'
stops "a service unit that cannot be written" "ssh failed, or the service unit could not be written there"
export STUB_SSH_FAIL_ON='cat > /etc/systemd/system/arc-registered-phones.timer'
stops "a timer unit that cannot be written" "ssh failed, or the timer unit could not be written there"
export STUB_SSH_FAIL_ON='cat > /usr/local/sbin/arc-registered-phones.new'
stops "a binary that cannot be installed" "ssh failed, or the binary could not be installed there"
export STUB_SSH_FAIL_ON='enable --now arc-registered-phones.timer'
stops "a timer that cannot be enabled" "ssh failed, or systemd could not enable the hourly timer"
hasnt "a timer that cannot be enabled runs no count" ssh_args 'start arc-registered-phones.service'
export STUB_SSH_FAIL_ON='systemctl start arc-registered-phones.service'
stops "a failed first count" "ssh failed, or the first count failed; journalctl -u arc-registered-phones on the node says why"
unset STUB_SSH_FAIL_ON

export STUB_SSH_FAIL_STDIN='date -u -d 2026-02-30'
expect_fail "a day the node does not know stops the install and says so" "n1: ssh failed, /etc/tunneld/tunneld.env is not readable there, or 2026-02-30 is not a real day" all --enrolled-since 2026-02-30
hasnt "a day the node does not know writes no settings" ssh_stdin 'REGISTERED_PHONES_ENROLLED_SINCE='
hasnt "a day the node does not know leaves the next node untouched" ssh_args 'root@198.51.100.2'
unset STUB_SSH_FAIL_STDIN

[ "$FAILS" = 0 ] || { echo "$FAILS failed"; exit 1; }
echo "all passed"

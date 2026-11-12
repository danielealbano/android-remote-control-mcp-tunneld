#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--binary FILE] [--timezone ZONE] [--daily-hour HH] [--telegram-token-file FILE] [--telegram-chat ID] [--exclude LIST] [-- SSH_OPTION...]

Installs the hourly busy-clients check on every node in the config file, one node at a time, and runs it
once on each.
Each config line is: <node> <ssh-target> <MM>
MM is the minute of every hour the node runs at. The minutes must be at least 30 minutes apart (so at
most two nodes), so their hourly runs do not update the list of alerted addresses at the same moment.
The whole config file is checked before any node is touched.
Blank lines and lines starting with # are skipped.

  --config FILE               config file, or BUSY_CLIENTS_CONFIG
  --binary FILE               the arc-busy-clients binary (make busy-clients), or BUSY_CLIENTS_BINARY
  --timezone ZONE             time zone of the times in the messages and of the daily hour, or BUSY_CLIENTS_TIMEZONE
  --daily-hour HH             hour (00-23) from which the first run of the day sends the still-running line,
                              or BUSY_CLIENTS_DAILY_HOUR
  --telegram-token-file FILE  file holding the Telegram bot token, or BUSY_CLIENTS_TELEGRAM_TOKEN_FILE
  --telegram-chat ID          Telegram chat that receives the messages, or BUSY_CLIENTS_TELEGRAM_CHAT
  --exclude LIST              comma-separated addresses or CIDR ranges that are never counted, or
                              BUSY_CLIENTS_EXCLUDE (optional)

Everything after -- is passed to ssh.
USAGE
	exit 2
}

dir=$(cd "$(dirname "$0")" && pwd)
config=${BUSY_CLIENTS_CONFIG:-}
binary=${BUSY_CLIENTS_BINARY:-}
timezone=${BUSY_CLIENTS_TIMEZONE:-}
hour=${BUSY_CLIENTS_DAILY_HOUR:-}
token_file=${BUSY_CLIENTS_TELEGRAM_TOKEN_FILE:-}
chat=${BUSY_CLIENTS_TELEGRAM_CHAT:-}
exclude=${BUSY_CLIENTS_EXCLUDE:-}

while [ $# -gt 0 ]; do
	case "$1" in
	--config | --binary | --timezone | --daily-hour | --telegram-token-file | --telegram-chat | --exclude)
		[ $# -ge 2 ] || usage
		case "$1" in
		--config) config=$2 ;;
		--binary) binary=$2 ;;
		--timezone) timezone=$2 ;;
		--daily-hour) hour=$2 ;;
		--telegram-token-file) token_file=$2 ;;
		--telegram-chat) chat=$2 ;;
		--exclude) exclude=$2 ;;
		esac
		shift 2
		;;
	--)
		shift
		break
		;;
	-h | --help) usage ;;
	*) usage ;;
	esac
done

if [ -z "$config" ] || [ -z "$binary" ] || [ -z "$timezone" ] || [ -z "$hour" ] || [ -z "$token_file" ] || [ -z "$chat" ]; then
	usage
fi
for f in "$config" "$binary" "$token_file"; do
	[ -r "$f" ] || {
		echo "cannot read $f" >&2
		exit 1
	}
done
case "$timezone" in
*[!A-Za-z0-9_+/-]*)
	echo "time zone $timezone has characters a time zone name never has" >&2
	exit 1
	;;
esac
case "$hour" in
[01][0-9] | 2[0-3]) hour=${hour#0} ;;
[0-9]) ;;
*)
	echo "daily hour $hour is not HH (00-23)" >&2
	exit 1
	;;
esac
case "${chat#-}" in
'' | *[!0-9]*)
	echo "Telegram chat id $chat is not a number" >&2
	exit 1
	;;
esac
case "$exclude" in
*[!0-9A-Fa-f.:/,]* | ,* | *, | *,,*)
	echo "exclude list $exclude must be addresses or CIDR ranges separated by single commas" >&2
	exit 1
	;;
esac
token=$(tr -d '\r\n' < "$token_file")
[ -n "$token" ] || {
	echo "token file $token_file is empty" >&2
	exit 1
}

stop() {
	echo "$1; the install stops here, so the nodes after it are not touched" >&2
	exit 1
}

refuse() {
	echo "$1; nothing was installed" >&2
	exit 1
}

seen=""
while read -r node target minute extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	if [ -z "$target" ] || [ -z "$minute" ] || [ -n "$extra" ]; then
		refuse "config line for $node needs <node> <ssh-target> <MM>"
	fi
	case "$minute" in
	[0-5][0-9]) ;;
	*) refuse "run minute $minute for $node is not MM (00-59)" ;;
	esac
	for other in $seen; do
		a=${minute#0}
		b=${other##*:}
		b=${b#0}
		gap=$((a > b ? a - b : b - a))
		[ "$gap" -le 30 ] || gap=$((60 - gap))
		if [ "$gap" -lt 30 ]; then
			refuse "$node (minute $minute) and ${other%%:*} (minute ${other##*:}) run less than 30 minutes apart, so they could update the list of alerted addresses at the same time"
		fi
	done
	seen="$seen $node:$minute"
done 3< "$config"
[ -n "$seen" ] || refuse "config file $config names no node"

while read -r node target minute extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	printf "test -r /etc/tunneld/tunneld.env && systemd-analyze calendar '*-*-* *:%s:00 %s'\n" "$minute" "$timezone" |
		ssh "$@" "$target" sh ||
		stop "$node: ssh failed, /etc/tunneld/tunneld.env is not readable there, or it does not accept the time zone $timezone"
	printf 'BUSY_CLIENTS_NODE=%s\nBUSY_CLIENTS_TIMEZONE=%s\nBUSY_CLIENTS_DAILY_HOUR=%s\nBUSY_CLIENTS_TELEGRAM_CHAT=%s\nBUSY_CLIENTS_TELEGRAM_TOKEN=%s\nBUSY_CLIENTS_EXCLUDE=%s\n' "$node" "$timezone" "$hour" "$chat" "$token" "$exclude" |
		ssh "$@" "$target" 'umask 077 && cat > /etc/tunneld/busy-clients.env && chmod 600 /etc/tunneld/busy-clients.env' ||
		stop "$node: ssh failed, or /etc/tunneld/busy-clients.env could not be written there"
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-busy-clients.service' < "$dir/arc-busy-clients.service" ||
		stop "$node: ssh failed, or the service unit could not be written there"
	printf '[Unit]\nDescription=Check for busy client addresses every hour at minute %s\n\n[Timer]\nOnCalendar=*-*-* *:%s:00\n\n[Install]\nWantedBy=timers.target\n' "$minute" "$minute" |
		ssh "$@" "$target" 'cat > /etc/systemd/system/arc-busy-clients.timer' ||
		stop "$node: ssh failed, or the timer unit could not be written there"
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-busy-clients.new && chmod 755 /usr/local/sbin/arc-busy-clients.new && mv /usr/local/sbin/arc-busy-clients.new /usr/local/sbin/arc-busy-clients' < "$binary" ||
		stop "$node: ssh failed, or the binary could not be installed there"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-busy-clients.timer' < /dev/null ||
		stop "$node: ssh failed, or systemd could not enable the hourly timer"
	ssh "$@" "$target" 'systemctl start arc-busy-clients.service' < /dev/null ||
		stop "$node: ssh failed, or the first check failed; journalctl -u arc-busy-clients on the node says why"
	echo "$node installed, checked once, checks every hour at minute $minute"
done 3< "$config"

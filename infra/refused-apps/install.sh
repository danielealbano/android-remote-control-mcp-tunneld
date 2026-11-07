#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--binary FILE] [--timezone ZONE] [--telegram-token-file FILE] [--telegram-chat ID] [--hide-apps IDS] [-- SSH_OPTION...]

Installs the daily refused-apps report on every node in the config file, one node at a time.
Each config line is: <node> <ssh-target> <HH:MM>
The time is when that node runs the report; give each node a different time, at least 30 minutes apart.
Blank lines and lines starting with # are skipped.

  --config FILE               config file, or REFUSED_APPS_CONFIG
  --binary FILE               the arc-refused-apps binary (make refused-apps), or REFUSED_APPS_BINARY
  --timezone ZONE             time zone of the run times and the report, or REFUSED_APPS_TIMEZONE
  --telegram-token-file FILE  file holding the Telegram bot token, or REFUSED_APPS_TELEGRAM_TOKEN_FILE
  --telegram-chat ID          Telegram chat that receives the report, or REFUSED_APPS_TELEGRAM_CHAT
  --hide-apps IDS             comma-separated app ids kept on the attempt list but left out of the report
                              and the dashboard, or REFUSED_APPS_HIDE_APPS (optional)

Everything after -- is passed to ssh.
USAGE
	exit 2
}

dir=$(cd "$(dirname "$0")" && pwd)
config=${REFUSED_APPS_CONFIG:-}
binary=${REFUSED_APPS_BINARY:-}
timezone=${REFUSED_APPS_TIMEZONE:-}
token_file=${REFUSED_APPS_TELEGRAM_TOKEN_FILE:-}
chat=${REFUSED_APPS_TELEGRAM_CHAT:-}
hide_apps=${REFUSED_APPS_HIDE_APPS:-}

while [ $# -gt 0 ]; do
	case "$1" in
	--config | --binary | --timezone | --telegram-token-file | --telegram-chat | --hide-apps)
		[ $# -ge 2 ] || usage
		case "$1" in
		--config) config=$2 ;;
		--binary) binary=$2 ;;
		--timezone) timezone=$2 ;;
		--telegram-token-file) token_file=$2 ;;
		--telegram-chat) chat=$2 ;;
		--hide-apps) hide_apps=$2 ;;
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

if [ -z "$config" ] || [ -z "$binary" ] || [ -z "$timezone" ] || [ -z "$token_file" ] || [ -z "$chat" ]; then
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
case "${chat#-}" in
'' | *[!0-9]*)
	echo "Telegram chat id $chat is not a number" >&2
	exit 1
	;;
esac
case "$hide_apps" in
*[!A-Za-z0-9_.,]* | ,* | *, | *,,*)
	echo "hidden app list $hide_apps must be app ids separated by single commas" >&2
	exit 1
	;;
esac
token=$(tr -d '\r\n' < "$token_file")
[ -n "$token" ] || {
	echo "token file $token_file is empty" >&2
	exit 1
}

while read -r node target at <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	if [ -z "$target" ] || [ -z "$at" ]; then
		echo "config line for $node needs <node> <ssh-target> <HH:MM>" >&2
		exit 1
	fi
	case "$at" in
	[01][0-9]:[0-5][0-9] | 2[0-3]:[0-5][0-9]) ;;
	*)
		echo "run time $at for $node is not HH:MM" >&2
		exit 1
		;;
	esac
	printf "test -r /etc/tunneld/tunneld.env && systemd-analyze calendar '*-*-* %s:00 %s'\n" "$at" "$timezone" |
		ssh "$@" "$target" sh || {
		echo "$node: ssh failed, /etc/tunneld/tunneld.env is not readable there, or it does not accept $at in $timezone; the install stops here, so the nodes after it are not touched" >&2
		exit 1
	}
	printf 'REFUSED_APPS_NODE=%s\nREFUSED_APPS_TIMEZONE=%s\nREFUSED_APPS_TELEGRAM_CHAT=%s\nREFUSED_APPS_TELEGRAM_TOKEN=%s\nREFUSED_APPS_HIDE_APPS=%s\n' "$node" "$timezone" "$chat" "$token" "$hide_apps" |
		ssh "$@" "$target" 'umask 077 && cat > /etc/tunneld/refused-apps.env && chmod 600 /etc/tunneld/refused-apps.env' || {
		echo "$node: ssh failed, or /etc/tunneld/refused-apps.env could not be written there; the install stops here, so the nodes after it are not touched" >&2
		exit 1
	}
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-refused-apps.service' < "$dir/arc-refused-apps.service"
	printf '[Unit]\nDescription=Send the daily report of refused app enrollments at %s %s\n\n[Timer]\nOnCalendar=*-*-* %s:00 %s\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n' "$at" "$timezone" "$at" "$timezone" |
		ssh "$@" "$target" 'cat > /etc/systemd/system/arc-refused-apps.timer'
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-refused-apps.new && chmod 755 /usr/local/sbin/arc-refused-apps.new && mv /usr/local/sbin/arc-refused-apps.new /usr/local/sbin/arc-refused-apps' < "$binary"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-refused-apps.timer' < /dev/null
	echo "$node installed, runs every day at $at $timezone"
done 3< "$config"

#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--binary FILE] [--enrolled-since YYYY-MM-DD] [-- SSH_OPTION...]

Installs the hourly registered-phones count on every node in the config file, one node at a time,
and runs it once on each.
Each config line is: <node> <ssh-target> <MM>
MM is the minute of every hour the node runs at. The minutes must be at least 30 minutes apart (so at
most two nodes), so their hourly runs do not update the shared state at the same moment.
The whole config file is checked before any node is touched.
Blank lines and lines starting with # are skipped.

  --config FILE               config file, or REGISTERED_PHONES_CONFIG
  --binary FILE               the arc-registered-phones binary (make registered-phones), or REGISTERED_PHONES_BINARY
  --enrolled-since YYYY-MM-DD first UTC day whose enrollments are counted, or REGISTERED_PHONES_ENROLLED_SINCE

Everything after -- is passed to ssh.
USAGE
	exit 2
}

dir=$(cd "$(dirname "$0")" && pwd)
config=${REGISTERED_PHONES_CONFIG:-}
binary=${REGISTERED_PHONES_BINARY:-}
since=${REGISTERED_PHONES_ENROLLED_SINCE:-}

while [ $# -gt 0 ]; do
	case "$1" in
	--config | --binary | --enrolled-since)
		[ $# -ge 2 ] || usage
		case "$1" in
		--config) config=$2 ;;
		--binary) binary=$2 ;;
		--enrolled-since) since=$2 ;;
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

if [ -z "$config" ] || [ -z "$binary" ] || [ -z "$since" ]; then
	usage
fi
for f in "$config" "$binary"; do
	[ -r "$f" ] || {
		echo "cannot read $f" >&2
		exit 1
	}
done
case "$since" in
[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) ;;
*)
	echo "first counted day $since is not YYYY-MM-DD" >&2
	exit 1
	;;
esac

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
			refuse "$node (minute $minute) and ${other%%:*} (minute ${other##*:}) run less than 30 minutes apart, so they could update the shared state at the same time"
		fi
	done
	seen="$seen $node:$minute"
done 3< "$config"
[ -n "$seen" ] || refuse "config file $config names no node"

while read -r node target minute extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	printf "test -r /etc/tunneld/tunneld.env && [ \"\$(date -u -d %s +%%F)\" = %s ]\n" "$since" "$since" |
		ssh "$@" "$target" sh ||
		stop "$node: ssh failed, /etc/tunneld/tunneld.env is not readable there, or $since is not a real day"
	printf 'REGISTERED_PHONES_ENROLLED_SINCE=%s\n' "$since" |
		ssh "$@" "$target" 'umask 077 && cat > /etc/tunneld/registered-phones.env && chmod 600 /etc/tunneld/registered-phones.env' ||
		stop "$node: ssh failed, or /etc/tunneld/registered-phones.env could not be written there"
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-registered-phones.service' < "$dir/arc-registered-phones.service" ||
		stop "$node: ssh failed, or the service unit could not be written there"
	printf '[Unit]\nDescription=Count the registered phones for the dashboard every hour at minute %s\n\n[Timer]\nOnCalendar=*-*-* *:%s:00\n\n[Install]\nWantedBy=timers.target\n' "$minute" "$minute" |
		ssh "$@" "$target" 'cat > /etc/systemd/system/arc-registered-phones.timer' ||
		stop "$node: ssh failed, or the timer unit could not be written there"
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-registered-phones.new && chmod 755 /usr/local/sbin/arc-registered-phones.new && mv /usr/local/sbin/arc-registered-phones.new /usr/local/sbin/arc-registered-phones' < "$binary" ||
		stop "$node: ssh failed, or the binary could not be installed there"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-registered-phones.timer' < /dev/null ||
		stop "$node: ssh failed, or systemd could not enable the hourly timer"
	ssh "$@" "$target" 'systemctl start arc-registered-phones.service' < /dev/null ||
		stop "$node: ssh failed, or the first count failed; journalctl -u arc-registered-phones on the node says why"
	echo "$node installed, counted once, counts every hour at minute $minute"
done 3< "$config"

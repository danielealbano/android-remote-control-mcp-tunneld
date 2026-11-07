#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--binary FILE] [--enrolled-since YYYY-MM-DD] [-- SSH_OPTION...]

Installs the hourly registered-phones count on every node in the config file, one node at a time,
and runs it once on each.
Each config line is: <node> <ssh-target>
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

while read -r node target extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	if [ -z "$target" ] || [ -n "$extra" ]; then
		echo "config line for $node needs <node> <ssh-target>" >&2
		exit 1
	fi
	printf "test -r /etc/tunneld/tunneld.env && [ \"\$(date -u -d %s +%%F)\" = %s ]\n" "$since" "$since" |
		ssh "$@" "$target" sh || {
		echo "$node: ssh failed, /etc/tunneld/tunneld.env is not readable there, or $since is not a real day" >&2
		exit 1
	}
	printf 'REGISTERED_PHONES_ENROLLED_SINCE=%s\n' "$since" |
		ssh "$@" "$target" 'umask 077 && cat > /etc/tunneld/registered-phones.env && chmod 600 /etc/tunneld/registered-phones.env'
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-registered-phones.service' < "$dir/arc-registered-phones.service"
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-registered-phones.timer' < "$dir/arc-registered-phones.timer"
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-registered-phones.new && chmod 755 /usr/local/sbin/arc-registered-phones.new && mv /usr/local/sbin/arc-registered-phones.new /usr/local/sbin/arc-registered-phones' < "$binary"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-registered-phones.timer' < /dev/null || {
		echo "$node: ssh failed, or systemd could not enable the hourly timer" >&2
		exit 1
	}
	ssh "$@" "$target" 'systemctl start arc-registered-phones.service' < /dev/null || {
		echo "$node: ssh failed, or the first count failed; journalctl -u arc-registered-phones on the node says why" >&2
		exit 1
	}
	echo "$node installed, counted once, counts every hour"
done 3< "$config"

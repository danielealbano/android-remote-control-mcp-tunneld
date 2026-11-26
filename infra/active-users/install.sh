#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--binary FILE] [-- SSH_OPTION...]

Installs the active-users count on every node in the config file, one node at a time, and runs it
once on each. It runs every 15 minutes, at minutes 05, 20, 35 and 50, a few minutes after tunneld's
quarter-hour uploads of the lists of phones seen.
Each config line is: <node> <ssh-target>
The whole config file is checked before any node is touched.
Blank lines and lines starting with # are skipped.

  --config FILE  config file, or ACTIVE_USERS_CONFIG
  --binary FILE  the arc-active-users binary (make active-users), or ACTIVE_USERS_BINARY

Everything after -- is passed to ssh.
USAGE
	exit 2
}

dir=$(cd "$(dirname "$0")" && pwd)
config=${ACTIVE_USERS_CONFIG:-}
binary=${ACTIVE_USERS_BINARY:-}

while [ $# -gt 0 ]; do
	case "$1" in
	--config | --binary)
		[ $# -ge 2 ] || usage
		case "$1" in
		--config) config=$2 ;;
		--binary) binary=$2 ;;
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

if [ -z "$config" ] || [ -z "$binary" ]; then
	usage
fi
for f in "$config" "$binary"; do
	[ -r "$f" ] || {
		echo "cannot read $f" >&2
		exit 1
	}
done

stop() {
	echo "$1; the install stops here, so the nodes after it are not touched" >&2
	exit 1
}

refuse() {
	echo "$1; nothing was installed" >&2
	exit 1
}

nodes=0
while read -r node target extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	if [ -z "$target" ] || [ -n "$extra" ]; then
		refuse "config line for $node needs <node> <ssh-target>"
	fi
	nodes=$((nodes + 1))
done 3< "$config"
[ "$nodes" -gt 0 ] || refuse "config file $config names no node"

while read -r node target extra <&3 || [ -n "$node" ]; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	ssh "$@" "$target" 'test -r /etc/tunneld/tunneld.env' < /dev/null ||
		stop "$node: ssh failed, or /etc/tunneld/tunneld.env is not readable there"
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-active-users.service' < "$dir/arc-active-users.service" ||
		stop "$node: ssh failed, or the service unit could not be written there"
	printf '[Unit]\nDescription=Count the active users for the dashboard every 15 minutes\n\n[Timer]\nOnCalendar=*-*-* *:05/15:00\n\n[Install]\nWantedBy=timers.target\n' |
		ssh "$@" "$target" 'cat > /etc/systemd/system/arc-active-users.timer' ||
		stop "$node: ssh failed, or the timer unit could not be written there"
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-active-users.new && chmod 755 /usr/local/sbin/arc-active-users.new && mv /usr/local/sbin/arc-active-users.new /usr/local/sbin/arc-active-users' < "$binary" ||
		stop "$node: ssh failed, or the binary could not be installed there"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-active-users.timer' < /dev/null ||
		stop "$node: ssh failed, or systemd could not enable the timer"
	ssh "$@" "$target" 'systemctl start arc-active-users.service' < /dev/null ||
		stop "$node: ssh failed, or the first count failed; journalctl -u arc-active-users on the node says why"
	echo "$node installed, counted once, counts every 15 minutes"
done 3< "$config"

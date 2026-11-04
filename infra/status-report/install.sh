#!/bin/sh
set -eu

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [--config FILE] [--url URL] [--token-file FILE] [-- SSH_OPTION...]

Installs the status reporter on every node in the config file, one node at a time.
Each config line is: <node> <ssh-target> <internal-address>
Blank lines and lines starting with # are skipped.

  --config FILE      config file, or STATUS_REPORT_CONFIG
  --url URL          status board ingest URL, or STATUS_URL
  --token-file FILE  file holding the source token, or STATUS_TOKEN_FILE

Everything after -- is passed to ssh.
USAGE
	exit 2
}

dir=$(cd "$(dirname "$0")" && pwd)
config=${STATUS_REPORT_CONFIG:-}
url=${STATUS_URL:-}
token_file=${STATUS_TOKEN_FILE:-}

while [ $# -gt 0 ]; do
	case "$1" in
	--config | --url | --token-file)
		[ $# -ge 2 ] || usage
		case "$1" in
		--config) config=$2 ;;
		--url) url=$2 ;;
		--token-file) token_file=$2 ;;
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

if [ -z "$config" ] || [ -z "$url" ] || [ -z "$token_file" ]; then
	usage
fi
[ -r "$config" ] || {
	echo "cannot read config file $config" >&2
	exit 1
}
[ -r "$token_file" ] || {
	echo "cannot read token file $token_file" >&2
	exit 1
}
token=$(tr -d '\r\n' < "$token_file")
[ -n "$token" ] || {
	echo "token file $token_file is empty" >&2
	exit 1
}

while read -r node target host <&3; do
	case "$node" in
	'' | \#*) continue ;;
	esac
	if [ -z "$target" ] || [ -z "$host" ]; then
		echo "config line for $node needs <node> <ssh-target> <internal-address>" >&2
		exit 1
	fi
	printf 'STATUS_NODE=%s\nSTATUS_HOST=%s\nSTATUS_URL=%s\nSTATUS_TOKEN=%s\n' "$node" "$host" "$url" "$token" |
		ssh "$@" "$target" 'umask 077; cat > /etc/tunneld/status-report.env; chmod 600 /etc/tunneld/status-report.env'
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-status-report.service' < "$dir/arc-status-report.service"
	ssh "$@" "$target" 'cat > /etc/systemd/system/arc-status-report.timer' < "$dir/arc-status-report.timer"
	ssh "$@" "$target" 'cat > /usr/local/sbin/arc-status-report; chmod 755 /usr/local/sbin/arc-status-report' < "$dir/arc-status-report.sh"
	ssh "$@" "$target" 'systemctl daemon-reload && systemctl enable --now arc-status-report.timer && systemctl start arc-status-report.service' < /dev/null
	echo "$node installed"
done 3< "$config"

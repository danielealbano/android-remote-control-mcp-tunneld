#!/bin/sh
set -u

state_dir="${RUNTIME_DIRECTORY:?}"
exporter_port="${STATUS_EXPORTER_PORT:-9121}"
internal_port="${STATUS_INTERNAL_PORT:-9090}"
valkey_port="${STATUS_VALKEY_PORT:-6379}"
internal="http://$STATUS_HOST:$internal_port"

metrics=$(curl -sS -m 5 "$internal/metrics") || { echo "tunneld metrics did not answer" >&2; exit 1; }

code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$internal/healthz")
reachable=0
[ "$code" = 200 ] && reachable=1

local_up=$(curl -sS -m 5 "http://$STATUS_HOST:$exporter_port/scrape?target=redis://$STATUS_HOST:$valkey_port" | awk '$1=="redis_up"{print $2}')
local_up=${local_up:-0}

total() {
	printf '%s\n' "$metrics" | awk -v pat="$1" '$0 ~ pat {s+=$NF} END {printf "%d", s}'
}

delta() {
	cur=$2
	file="$state_dir/$1"
	prev=$(cat "$file" 2>/dev/null || echo "$cur")
	echo "$cur" > "$file"
	if [ "$cur" -lt "$prev" ]; then
		echo "$cur"
	else
		echo $((cur - prev))
	fi
}

timeouts=$(delta pool_timeouts "$(total '^tunneld_valkey_pool_timeouts_total')")
failures=$(delta acme_failures "$(total '^tunneld_acme_issue_total.*result="fail"')")
issued=$(delta acme_issued "$(total '^tunneld_acme_issue_total.*result="ok"')")

metric() {
	printf '{"name":"%s","gauge":{"value":%s},"tags":{"node":"%s"}}' "$1" "$2" "$STATUS_NODE"
}

body="[$(metric arc_status_report 1),$(metric arc_valkey_reachable "$reachable"),$(metric arc_valkey_local_up "$local_up"),$(metric arc_valkey_pool_timeouts "$timeouts"),$(metric arc_acme_failures "$failures"),$(metric arc_acme_issued "$issued")]"

answer=$(printf 'header = "Authorization: Bearer %s"\n' "$STATUS_TOKEN" | curl -sS -m 10 -K - -X POST -H 'Content-Type: application/json' -d "$body" -o /dev/null -w '%{http_code}' "$STATUS_URL")
[ "$answer" = 202 ] || { echo "status board answered $answer" >&2; exit 1; }

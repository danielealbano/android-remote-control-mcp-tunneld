#!/bin/sh
# Downloads the Spamhaus DROP JSON-lines feed and converts it to `cidr <prefix>` ban-file lines.
# NO pipelines (each stage writes a temp file) so plain `set -e` catches every failure and pipefail
# — undefined in POSIX sh (shellcheck SC3040) — is never needed. Atomic handoff: temp file + mv.
set -eu

OUT_DIR="${OUT_DIR:?OUT_DIR required}"
DROP_URL="${DROP_URL:-https://www.spamhaus.org/drop/drop_v4.json}"

# $$-suffixed temps so concurrent invocations can't interleave into one file; the trap removes them on
# ANY exit (success or failure), so an aborted run leaves no litter and the previous output untouched.
feed="$OUT_DIR/droplist.feed.tmp.$$"
tmp="$OUT_DIR/droplist.bans.tmp.$$"
trap 'rm -f "$feed" "$tmp"' EXIT

# --max-time bounds a hung download; on any curl failure `set -e` aborts, leaving droplist.bans untouched.
curl -fsS --max-time 300 "$DROP_URL" -o "$feed"

# jq reads the feed file directly (no pipeline); select only records carrying a cidr.
jq -r 'select(.cidr) | "cidr \(.cidr)"' "$feed" > "$tmp"

# Refuse to install an EMPTY result: an upstream schema change (or an HTTP-200 empty body) would
# otherwise atomically replace the live droplist with zero entries — a silent mass-unban. Mirrors the
# DB-IP zero-row refusal in internal/ban/dbip.go.
[ -s "$tmp" ] || { echo "fetch-droplist: empty droplist output, keeping previous file" >&2; exit 1; }

mv "$tmp" "$OUT_DIR/droplist.bans"

#!/bin/sh
# Validates every ```mermaid fenced block in the given Markdown files by rendering it with mmdc
# (@mermaid-js/mermaid-cli via npx). Exits non-zero if any block fails to render.
set -eu

if [ "$#" -eq 0 ]; then
	echo "usage: mermaid-check.sh <file.md> [file.md ...]" >&2
	exit 2
fi

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

# Puppeteer needs --no-sandbox to launch Chromium in CI containers.
printf '{"args":["--no-sandbox"]}\n' > "$OUT_DIR/puppeteer.json"

status=0
for f in "$@"; do
	count="$(awk '/^```mermaid[ \t]*$/ { n++ } END { print n + 0 }' "$f")"
	if [ "$count" -eq 0 ]; then
		continue
	fi
	i=0
	while [ "$i" -lt "$count" ]; do
		awk -v want="$i" '
			/^```mermaid[ \t]*$/ { if (!in_block) { if (n == want) grab = 1; n++; in_block = 1; next } }
			/^```[ \t]*$/        { if (in_block) { in_block = 0; grab = 0; next } }
			grab { print }
		' "$f" > "$OUT_DIR/block.mmd"
		if npx --yes @mermaid-js/mermaid-cli -p "$OUT_DIR/puppeteer.json" \
			-i "$OUT_DIR/block.mmd" -o "$OUT_DIR/block.svg" > "$OUT_DIR/mmdc.log" 2>&1; then
			echo "OK   $f mermaid block $i"
		else
			echo "FAIL $f mermaid block $i"
			cat "$OUT_DIR/mmdc.log"
			status=1
		fi
		i=$((i + 1))
	done
done
exit "$status"

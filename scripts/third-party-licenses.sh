#!/bin/sh
set -eu

out="${1:-THIRD_PARTY_LICENSES.txt}"
out_dir="$(dirname "$out")"
gover="$(go env GOVERSION)"
goroot="$(go env GOROOT)"
mods="$(mktemp "$out_dir/.third-party-licenses.mods.XXXXXX")"
trap 'rm -f "$mods"' EXIT
tmp="$(mktemp "$out_dir/.third-party-licenses.XXXXXX")"
trap 'rm -f "$mods" "$tmp"' EXIT

for arch in amd64 arm64; do
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go list -deps \
		-f '{{if and (not .Standard) .Module (not .Module.Main)}}{{.Module.Path}}@{{.Module.Version}} {{.Module.Dir}}{{end}}' \
		./cmd/tunneld >> "$mods"
done
LC_ALL=C sort -u -t@ -k1,1 -o "$mods" "$mods"

{
	printf 'Third-party licenses and notices for the tunneld binary.\n'
	printf 'Each section is the verbatim license or notice file of one component the binary is built from.\n'
	printf '\n==== Go toolchain and standard library (%s)\n\n' "$gover"
	cat "$goroot/LICENSE"
	while read -r mod dir; do
		if [ -z "$dir" ] || [ ! -d "$dir" ]; then
			echo "third-party-licenses: no module directory for $mod" >&2
			exit 1
		fi
		found=0
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
			[ -f "$f" ] || continue
			found=1
			printf '\n==== %s (%s)\n\n' "$mod" "$(basename "$f")"
			cat "$f"
		done
		if [ "$found" -eq 0 ]; then
			echo "third-party-licenses: no license file in $mod ($dir)" >&2
			exit 1
		fi
	done < "$mods"
} > "$tmp"
chmod 644 "$tmp"
mv "$tmp" "$out"

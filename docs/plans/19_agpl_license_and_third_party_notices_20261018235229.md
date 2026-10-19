<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 19 — Relicense under AGPL-3.0-or-later and ship third-party license notices

Switch the project license from MIT to the GNU Affero General Public License v3 (or later), and make every
distributed artifact (goreleaser archives, the goreleaser image, the compose-built image) carry a
`THIRD_PARTY_LICENSES.txt` generated at build time from the binary's real dependency set.

## Context & key decisions (the decision record — not derivable from code)

- **License: GNU AGPL v3, "or (at your option) any later version"** — SPDX `AGPL-3.0-or-later`. The
  dependency audit of 2026-10-18 found every module compiled into `cmd/tunneld` (206 modules; identical
  sets on linux/amd64 and linux/arm64) under Apache-2.0, MIT, BSD-2/3-Clause or MPL-2.0, all
  GPLv3-compatible per the FSF license list; the 12 MPL-2.0 modules carry no "Incompatible With Secondary
  Licenses" notice, and MPL-2.0 §1.12 names AGPLv3 as a Secondary License. The Kotlin apps under
  `support/` and the fixture APKs are NOT published and are out of scope.
- **`LICENSE.md` keeps its name** (goreleaser's default `LICENSE*` glob matches it, and GitHub's licensee
  scores the `LICENSE.md` file name 0.95 in its `FILENAME_REGEXES`) and becomes the **verbatim** text of
  `https://www.gnu.org/licenses/agpl-3.0.txt`. The AGPL text forbids altering the license document, so the
  program's copyright + license notice lives in the README, with the FSF's standard "either version 3 of the
  License, or (at your option) any later version" wording. Copyright year **2026** (first commit 2026-08-16).
  **No per-file license headers**: the AGPL's "How to Apply These Terms" section follows "END OF TERMS AND
  CONDITIONS" (guidance, not a condition), and the project adds no code comments.
- **Third-party notices are generated at build time and NEVER committed.** Apache-2.0 §4(a)/(d), the BSD
  binary-redistribution clause and the MIT / Bouncy-Castle notice clause require the license texts and
  NOTICE attributions to accompany binaries. A committed file drifts on every dependabot `gomod` bump and a
  client-side hook never runs for dependabot; generation at build time always matches the exact `go.mod`
  being released (measured: under 1 s, ~1.3 MB).
- **Scope of the bundle:** `cmd/tunneld` is the only distributed binary (`client/` ships as source;
  `support/soak-client` is built locally). The platform list in the generator (linux/amd64, linux/arm64,
  `CGO_ENABLED=0`) mirrors the goreleaser `builds` and the two move in lockstep. The Go toolchain's own
  `LICENSE` is included because the runtime is statically linked (BSD-3 binary clause).
- **goreleaser `archives.files` must list our own files explicitly**: setting `files` replaces the
  default `LICENSE*`/`README*` globs (goreleaser `internal/pipe/archive/archive.go`: the defaults apply only
  when `files` is empty). `dockers_v2.extra_files` paths are relative to the repo root and land in the
  image build context at the same relative path.
- **No license-allowlist CI gate** (decided). No Mermaid chart is added or modified.

---

## User Story 1: Relicense under AGPL-3.0-or-later

- [x] **US1** — Replace the MIT license text and the image license label.

Why: decided on 2026-10-18 after the dependency audit; the network copyleft matches a server operated over a
network.

### Acceptance Criteria

- [x] `LICENSE.md` is byte-identical to `https://www.gnu.org/licenses/agpl-3.0.txt` (sha256
      `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`).
- [x] `.goreleaser.yaml` label `org.opencontainers.image.licenses` is `AGPL-3.0-or-later`.
- [x] `git grep -nw MIT -- ':!docs/plans' ':!go.sum' ':!fixtures'` matches nothing (today it matches only
      `LICENSE.md:1` and `.goreleaser.yaml:55`; the AGPL text does not contain the word).
- [x] No source file gains a license header.

### [x] Task 1.1: `LICENSE.md`

- [x] **Action 1.1.1** — `LICENSE.md` (modify, whole file): replace the content with the verbatim AGPLv3 text.

```sh
curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE.md
echo '0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0  LICENSE.md' | sha256sum -c -
```

#### Definition of Done

- [x] `LICENSE.md` starts with `                    GNU AFFERO GENERAL PUBLIC LICENSE` /
      `                       Version 3, 19 November 2007` and the `sha256sum -c` line printed `LICENSE.md: OK`.

### [x] Task 1.2: goreleaser image label

- [x] **Action 1.2.1** — `.goreleaser.yaml` (modify):

```diff
-      "org.opencontainers.image.licenses": "MIT"
+      "org.opencontainers.image.licenses": "AGPL-3.0-or-later"
```

#### Definition of Done

- [x] The label line reads as above (Action 1.2.1 changes no other line).

---

## User Story 2: Generate and ship `THIRD_PARTY_LICENSES.txt`

- [x] **US2** — Generate the third-party license bundle from the binary's dependency set at build time and
      ship it in the archives and both images.

Why: the permissive licenses of the compiled dependencies require their texts and NOTICE attributions to
accompany binary distributions; today the archives carry only `LICENSE.md` + `README.md` and the images only
the binary.

### Acceptance Criteria

- [x] `sh scripts/third-party-licenses.sh` writes `THIRD_PARTY_LICENSES.txt` (mode 0644) in the current
      directory; `sh scripts/third-party-licenses.sh <path>` writes `<path>`; the write is temp-file + `mv`.
- [x] The file starts with the two header lines, then `==== Go toolchain and standard library (<GOVERSION>)`
      followed by `$(go env GOROOT)/LICENSE`, then one `==== <module>@<version> (<file>)` section per
      root-level `LICENSE*` / `LICENCE*` / `COPYING*` / `NOTICE*` file of every module compiled into
      `./cmd/tunneld` on linux/amd64 ∪ linux/arm64 (`CGO_ENABLED=0`), main module excluded, sorted by
      module path (the sort key is the path alone, so a submodule follows its parent) in byte order
      (`LC_ALL=C`), each file verbatim.
- [x] A module without any such file or a module whose directory is missing makes the script exit 1 with a
      message naming the module; a failing `go env`, `go list`, `sort` or `mktemp` makes it exit non-zero with that
      command's own status. In every failure a pre-existing output file is left untouched and no
      `.third-party-licenses.*` temp file is left behind — including when `go env` fails before any temp file
      exists and when the second `mktemp` fails after the first succeeded.
- [x] `scripts/scripts_test.sh` covers every case of the Task 2.2 table and `make test-scripts` runs both
      harnesses.
- [x] `make third-party-licenses` runs the script; `/THIRD_PARTY_LICENSES.txt` is gitignored.
- [x] `.goreleaser.yaml`: the generator runs as a `before` hook after `go mod download`; `archives.files`
      is exactly `LICENSE.md`, `README.md`, `THIRD_PARTY_LICENSES.txt`; `dockers_v2.extra_files` lists
      `THIRD_PARTY_LICENSES.txt`; `Dockerfile.goreleaser` copies it to `/THIRD_PARTY_LICENSES.txt`.
- [x] `Dockerfile` generates `/THIRD_PARTY_LICENSES.txt` in the build stage and copies it into the final
      image at `/THIRD_PARTY_LICENSES.txt`, readable by the `nonroot` user (mode 0644).
- [x] CI `static-checks` has a `third-party licenses` step running `make third-party-licenses` between
      `script tests` and `compose config`.

### [x] Task 2.1: The generator script

- [x] **Action 2.1.1** — `scripts/third-party-licenses.sh` (create, mode 0755, tabs like `scripts/mermaid-check.sh`):

```sh
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
```

Constraints (not derivable from the code): no pipeline carries a command that can fail — `go list` writes
into `$mods`, `sort -o` rewrites `$mods` in place (POSIX `sort`: the output file "can be the same as one of
the input files"), and the `while` reads `$mods` by redirection — so every failure aborts through `set -e`
with the failing command's own status (this host's `/bin/sh`, dash 0.5.12-6ubuntu5, rejects
`set -o pipefail`, so a pipeline could not be made safe); `gover`/`goroot` are plain assignments so a failing
`go env` aborts before any temp file exists; the EXIT trap is installed right after the first `mktemp` so a
failing second `mktemp` leaves nothing behind; the redirected `while` runs in the main shell, so its `exit 1`
ends the script before `mv` and the trap removes both temp files; `-t@ -k1,1` sorts and de-duplicates on the
module path alone (each `/`-separated element of a module path holds only ASCII letters, digits, `-`, `.`,
`_`, `~` — `golang.org/x/mod` `module.modPathOK` — so a module path never contains `@`, while a module-cache
directory does) and `LC_ALL=C` fixes byte order across machines — a whole-line sort would put
`example.com/a/b@…` BEFORE `example.com/a@…` because `/` sorts before `@`; `read -r mod dir` keeps any spaces
of the directory path in `dir` (the last variable); `chmod 644` undoes `mktemp`'s 0600, which `mv`,
`docker COPY` and goreleaser's tar writer would otherwise all preserve.

#### Definition of Done

- [x] The file exists with exactly the content above and mode 0755.

### [x] Task 2.2: Script test harness

- [x] **Action 2.2.1** — `scripts/scripts_test.sh` (create, mode 0755; the shared infrastructure in full,
      modelled on `deploy/scripts/scripts_test.sh`):

```sh
#!/bin/sh
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_MKTEMP="$(command -v mktemp)"
REAL_SORT="$(command -v sort)"
FAILS=0

tmproot="$(mktemp -d)"
trap 'rm -rf "$tmproot"' EXIT
export TMPDIR="$tmproot"
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

no_tmp_litter() {
	for f in "$1"/.third-party-licenses.*; do
		[ -e "$f" ] && return 1
	done
	return 0
}

make_stub_go() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/go" <<'SHIM'
#!/bin/sh
case "$1 ${2:-}" in
	"env GOROOT"|"env GOVERSION")
		echo "go env $2" >> "$STUB_CALL_LOG"
		if [ "${STUB_GO_ENV_FAIL:-}" = "$2" ]; then exit "$STUB_GO_ENV_EXIT"; fi
		if [ "$2" = "GOROOT" ]; then echo "$STUB_GOROOT"; else echo "go0.0-stub"; fi ;;
	"list "*)
		echo "go list" >> "$STUB_CALL_LOG"
		printf '%s/%s/%s\n' "${GOOS:-}" "${GOARCH:-}" "${CGO_ENABLED:-}" >> "$STUB_GO_LIST_LOG"
		printf '%s\n' "$*" >> "$STUB_GO_ARGS_LOG"
		if [ "${STUB_GO_LIST_EXIT:-0}" != "0" ]; then exit "$STUB_GO_LIST_EXIT"; fi
		cat "$STUB_GO_LIST_FILE" ;;
	*) echo "stub go: unexpected arguments: $*" >&2; exit 2 ;;
esac
SHIM
	chmod +x "$bindir/go"
}

make_stub_mktemp() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/mktemp" <<'SHIM'
#!/bin/sh
echo mktemp >> "$STUB_CALL_LOG"
n=0
if [ -e "$STUB_MKTEMP_COUNT" ]; then n="$(cat "$STUB_MKTEMP_COUNT")"; fi
n=$((n + 1))
echo "$n" > "$STUB_MKTEMP_COUNT"
printf '%s\n' "$*" >> "$STUB_MKTEMP_ARGS_LOG"
if [ "${STUB_MKTEMP_FAIL:-0}" != "0" ] && [ "$n" -ge 2 ]; then exit 5; fi
exec "$REAL_MKTEMP" "$@"
SHIM
	chmod +x "$bindir/mktemp"
}

make_stub_sort() {
	bindir="$1"
	mkdir -p "$bindir"
	cat > "$bindir/sort" <<'SHIM'
#!/bin/sh
echo sort >> "$STUB_CALL_LOG"
echo "${LC_ALL:-unset}" >> "$STUB_SORT_LOG"
if [ "${STUB_SORT_EXIT:-0}" != "0" ]; then exit "$STUB_SORT_EXIT"; fi
exec "$REAL_SORT" "$@"
SHIM
	chmod +x "$bindir/sort"
}

make_fixture() {
	root="$1"
	mkdir -p "$root/goroot" "$root/mods/alpha" "$root/mods/alpha-sub" "$root/mods/beta"
	printf 'GO TOOLCHAIN LICENSE TEXT\nGO TOOLCHAIN LICENSE SECOND LINE\n' > "$root/goroot/LICENSE"
	printf 'ALPHA LICENSE TEXT\nALPHA LICENSE SECOND LINE\n' > "$root/mods/alpha/LICENSE"
	echo "ALPHA NOTICE TEXT" > "$root/mods/alpha/NOTICE"
	echo "ALPHA SUB LICENSE TEXT" > "$root/mods/alpha-sub/LICENSE"
	echo "BETA LICENCE TEXT" > "$root/mods/beta/LICENCE"
	echo "BETA COPYING TEXT" > "$root/mods/beta/COPYING"
	printf 'example.com/beta@v0.3.1 %s/mods/beta\nexample.com/alpha/sub@v0.1.0 %s/mods/alpha-sub\nexample.com/alpha@v1.2.0 %s/mods/alpha\nexample.com/alpha@v1.2.0 %s/mods/alpha\n' \
		"$root" "$root" "$root" "$root" > "$root/list.txt"
	cat > "$root/expected.txt" <<'EXPECTED'
Third-party licenses and notices for the tunneld binary.
Each section is the verbatim license or notice file of one component the binary is built from.

==== Go toolchain and standard library (go0.0-stub)

GO TOOLCHAIN LICENSE TEXT
GO TOOLCHAIN LICENSE SECOND LINE

==== example.com/alpha@v1.2.0 (LICENSE)

ALPHA LICENSE TEXT
ALPHA LICENSE SECOND LINE

==== example.com/alpha@v1.2.0 (NOTICE)

ALPHA NOTICE TEXT

==== example.com/alpha/sub@v0.1.0 (LICENSE)

ALPHA SUB LICENSE TEXT

==== example.com/beta@v0.3.1 (LICENCE)

BETA LICENCE TEXT

==== example.com/beta@v0.3.1 (COPYING)

BETA COPYING TEXT
EXPECTED
}

run_gen() {
	LC_ALL='' GOOS='' GOARCH='' CGO_ENABLED='' \
		PATH="$b:$PATH" STUB_GOROOT="$t/goroot" STUB_GO_LIST_FILE="$t/list.txt" STUB_GO_LIST_LOG="$t/list.log" \
		STUB_GO_ARGS_LOG="$t/go-args.log" \
		STUB_MKTEMP_COUNT="$t/mktemp.count" STUB_MKTEMP_ARGS_LOG="$t/mktemp-args.log" REAL_MKTEMP="$REAL_MKTEMP" \
		STUB_SORT_LOG="$t/sort.log" REAL_SORT="$REAL_SORT" STUB_CALL_LOG="$t/calls.log" \
		sh "$DIR/third-party-licenses.sh" "$@"
}
```

Every case follows the harness pattern: `t="$(mktemp -d)"; b="$(mktemp -d)"; make_stub_go "$b";
make_fixture "$t"; … pass/fail`. `list.txt` lists beta first, then `alpha/sub`, then alpha TWICE (a real
invocation runs `go list` once per arch and both print it): sorting by module path (alpha, alpha/sub, beta —
a whole-line sort would put `alpha/sub` first) and de-duplication are both observable; the `sort` stub
records the `LC_ALL` value `sort` ran under, so the byte-order requirement is observable without depending on
the locales installed on the machine; `run_gen` clears `LC_ALL`, `GOOS`, `GOARCH` and `CGO_ENABLED` so a value
exported by the caller can never stand in for the script's own assignments.
The script is invoked with `$t/out.txt` as the output path except in the default-name case, which runs it
from `$t` as the working directory with no argument. "Old output preserved" means `echo OLD > "$t/out.txt"`
before the run and `out.txt` still reading `OLD` after it.

| Test name | Verifies | Setup notes |
|---|---|---|
| `generator writes the expected file byte for byte` | `out.txt` exists with mode 0644 (`find "$t/out.txt" -perm 644` prints it); `cmp -s "$t/expected.txt" "$t/out.txt"` — the fixture's `expected.txt` is the exact output: the two header lines, the Go heading with `go0.0-stub` followed by the two-line Go license, then `example.com/alpha@v1.2.0 (LICENSE)` (two lines), `example.com/alpha@v1.2.0 (NOTICE)`, `example.com/alpha/sub@v0.1.0 (LICENSE)`, `example.com/beta@v0.3.1 (LICENCE)`, `example.com/beta@v0.3.1 (COPYING)`, each text verbatim under its own heading, alpha once although listed twice, alpha before `alpha/sub` before beta although listed in reverse; `list.log` is exactly `linux/amd64/0` then `linux/arm64/0`; `go-args.log` is exactly two lines `list -deps -f {{if and (not .Standard) .Module (not .Module.Main)}}{{.Module.Path}}@{{.Module.Version}} {{.Module.Dir}}{{end}} ./cmd/tunneld`; `mktemp-args.log` is exactly `$t/.third-party-licenses.mods.XXXXXX` then `$t/.third-party-licenses.XXXXXX`; `sort.log` is exactly `C`; `calls.log` is exactly `go env GOVERSION`, `go env GOROOT`, `mktemp`, `mktemp`, `go list`, `go list`, `sort` (one per line); `old.lnk` (a hard link to the pre-existing `out.txt`) still reads `OLD`, so the output was renamed into place rather than rewritten; `no_tmp_litter "$t"`; on failure the case prints `diff expected.txt out.txt` | `make_stub_sort "$b"`, `make_stub_mktemp "$b"`, `echo OLD > "$t/out.txt"`, `ln "$t/out.txt" "$t/old.lnk"`, then `run_gen "$t/out.txt"` |
| `generator uses the default output name` | `THIRD_PARTY_LICENSES.txt` is created in the working directory; `no_tmp_litter "$t"` | `(cd "$t" && run_gen)` |
| `generator fails on a module without a license file and keeps the old output` | exit status 1; stderr contains `no license file in example.com/gamma`; old output preserved; `no_tmp_litter "$t"` | `mkdir "$t/mods/gamma"`; append `example.com/gamma@v0.0.1 $t/mods/gamma` to `list.txt`; stderr captured to `$t/err.txt` for the assertion and printed when the case fails |
| `generator fails on a module without a directory and keeps the old output` | exit status 1; stderr contains `no module directory for example.com/delta`; old output preserved; `no_tmp_litter "$t"` | append `example.com/delta@v0.0.2 $t/mods/delta` (no such directory) to `list.txt`; stderr captured to `$t/err.txt` for the assertion and printed when the case fails |
| `generator fails when go list fails and keeps the old output` | exit status 4 (the stub's own status); old output preserved; `no_tmp_litter "$t"` | `(export STUB_GO_LIST_EXIT=4; run_gen "$t/out.txt")` |
| `generator fails when go env <key> fails before writing anything` (run once per key, `GOVERSION` then `GOROOT`, each with a fresh `$t`/`$b`) | exit status 3 (the stub's own status); old output preserved; `no_tmp_litter "$t"`; `list.log` does not exist (no `go list` ran); `mktemp.count` does not exist (no `mktemp` ran) | `make_stub_mktemp "$b"`, then `(export STUB_GO_ENV_FAIL="$key" STUB_GO_ENV_EXIT=3; run_gen "$t/out.txt")` — the stub fails only the named key, so each call is exercised on its own |
| `generator fails when the second mktemp fails and leaves no temp file` | exit status 5 (the stub's own status); old output preserved; `no_tmp_litter "$t"`; `mktemp.count` reads `2` | `make_stub_mktemp "$b"`, then `(export STUB_MKTEMP_FAIL=1; run_gen "$t/out.txt")` |
| `generator fails when sort fails and keeps the old output` | exit status 6 (the stub's own status); old output preserved; `no_tmp_litter "$t"` | `make_stub_sort "$b"`, then `(export STUB_SORT_EXIT=6; run_gen "$t/out.txt")` |

The file ends like the existing harness: a non-zero `FAILS` prints `<n> script test(s) failed` and exits 1,
otherwise `all script tests passed`.

#### Definition of Done

- [x] The file exists with the infrastructure above, the eight cases, and mode 0755.

### [x] Task 2.3: Makefile target + `.gitignore`

- [x] **Action 2.3.1** — `Makefile` (modify): add `third-party-licenses` to `.PHONY`, the second harness to
      `test-scripts`, and the new target:

```diff
 .PHONY: build lint vet govulncheck test-unit test-integration test-e2e test-soak-app test-staging test-all test-scripts \
-        tidy compose-config mermaid-check attest-probe tunnel-app soak-app soak-client
+        tidy compose-config mermaid-check third-party-licenses attest-probe tunnel-app soak-app soak-client
```

```diff
 test-scripts:
 	sh deploy/scripts/scripts_test.sh
+	sh scripts/scripts_test.sh
```

```diff
 # Validates every ```mermaid block in README.md and under docs/ via mmdc (mermaid-cli).
 mermaid-check:
 	sh scripts/mermaid-check.sh README.md $(shell find docs -name '*.md')
+
+third-party-licenses:
+	sh scripts/third-party-licenses.sh
```

- [x] **Action 2.3.2** — `.gitignore` (modify): after the `/bin/` line add:

```
/THIRD_PARTY_LICENSES.txt
```

#### Definition of Done

- [x] The three Makefile hunks and the `.gitignore` line are in place; recipe lines start with a tab.

### [x] Task 2.4: goreleaser + both Dockerfiles

- [x] **Action 2.4.1** — `.goreleaser.yaml` (modify):

```diff
 before:
   hooks:
     - go mod download
+    - sh scripts/third-party-licenses.sh
```

```diff
     formats:
       - tar.gz
     name_template: "tunneld_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
+    files:
+      - LICENSE.md
+      - README.md
+      - THIRD_PARTY_LICENSES.txt
```

```diff
     platforms:
       - linux/amd64
       - linux/arm64
+    extra_files:
+      - THIRD_PARTY_LICENSES.txt
     labels:
```

- [x] **Action 2.4.2** — `Dockerfile.goreleaser` (modify):

```diff
 COPY $TARGETPLATFORM/tunneld /tunneld
+COPY THIRD_PARTY_LICENSES.txt /THIRD_PARTY_LICENSES.txt
 ENTRYPOINT ["/tunneld", "serve"]
```

- [x] **Action 2.4.3** — `Dockerfile` (modify):

```diff
 RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /tunneld ./cmd/tunneld
+RUN sh scripts/third-party-licenses.sh /THIRD_PARTY_LICENSES.txt

 FROM gcr.io/distroless/static:nonroot
 COPY --from=build /tunneld /tunneld
+COPY --from=build /THIRD_PARTY_LICENSES.txt /THIRD_PARTY_LICENSES.txt
 ENTRYPOINT ["/tunneld", "serve"]
```

#### Definition of Done

- [x] The five hunks are in place; `.goreleaser.yaml` has no other change besides Action 1.2.1.

### [x] Task 2.5: CI step

- [x] **Action 2.5.1** — `.github/workflows/ci.yml` (modify, `static-checks` job), after the `script tests` step:

```diff
       - name: script tests
         run: make test-scripts
+      - name: third-party licenses
+        run: make third-party-licenses
       - name: compose config
```

#### Definition of Done

- [x] The step order is shellcheck → script tests → third-party licenses → compose config → setup-node →
      mermaid-check.

---

## User Story 3: Documentation

- [x] **US3** — Record the license and the third-party-notices mechanism in the README, the canonical docs
      and the project rule file.

Why: the README carries the program notice (the AGPL text itself may not be edited); `docs/PROJECT.md` and
`.claude/rules/project.md` MUST stay current (releases, standard commands, repository hygiene).

### Acceptance Criteria

- [x] `README.md` has a `## License` section (program notice with copyright 2026 and the AGPL-3.0-or-later
      wording, pointer to `LICENSE.md`, the third-party-notices statement) and the DB-IP CC BY 4.0 attribution
      paragraph preserved byte for byte; the former `## Attribution` heading is gone.
- [x] `docs/PROJECT.md` §7 describes the license, the generated `THIRD_PARTY_LICENSES.txt` in archives and
      images, the `third-party-licenses` command, and keeps the DB-IP attribution rule.
- [x] `.claude/rules/project.md` lists `make third-party-licenses`, the extended `make test-scripts`, the
      CI step, and the license / notices rules under Repository hygiene; it references the canonical docs
      and adds no plan numbers.

### [x] Task 3.1: README `## License` section

- [x] **Action 3.1.1** — `README.md` (modify): replace the `## Attribution` section (lines 153–156) with:

```markdown
## License

Copyright 2026 Daniele Salvatore Albano

tunneld is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. It is distributed WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [`LICENSE.md`](LICENSE.md) for the
full text.

Every release archive and image carries `THIRD_PARTY_LICENSES.txt`: the license and notice files of the
Go toolchain and of every module compiled into the `tunneld` binary, generated at build time by
`make third-party-licenses` (`scripts/third-party-licenses.sh`).

Country data: **DB-IP Country Lite** — © db-ip.com, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
```

#### Definition of Done

- [x] The section reads as above and nothing else in the README changed.

### [x] Task 3.2: `docs/PROJECT.md`

- [x] **Action 3.2.1** — `docs/PROJECT.md` (modify, §7 Operations):

```diff
 - **Releases**: `v*` tags → goreleaser → linux amd64/arm64 archives + multi-arch image
-  `ghcr.io/danielealbano/android-remote-control-mcp-tunneld`.
+  `ghcr.io/danielealbano/android-remote-control-mcp-tunneld`. Every archive carries `LICENSE.md`,
+  `README.md` and `THIRD_PARTY_LICENSES.txt`; every image (goreleaser and compose-built) carries
+  `/THIRD_PARTY_LICENSES.txt`. That file is generated at build time by `scripts/third-party-licenses.sh`
+  from the Go toolchain's license and the license/notice files of every module compiled into `cmd/tunneld`
+  on linux amd64 and arm64 (the goreleaser platforms); it is never committed.
 - **Standard commands**: the Makefile (`build`, `lint`, `vet`, `govulncheck`, `test-unit`,
-  `test-integration`, `test-e2e`, `test-staging`, `test-scripts`, `compose-config`, `mermaid-check`; `test-soak-app` runs the
+  `test-integration`, `test-e2e`, `test-staging`, `test-scripts`, `compose-config`, `mermaid-check`,
+  `third-party-licenses`; `test-soak-app` runs the
   soak-app device tests, which are behind the `soak` build tag and never part of the default gates). The integration,
```

```diff
-- **Attribution**: country data is DB-IP Country Lite — © db-ip.com, CC BY 4.0 (the README carries the
-  attribution; it MUST be preserved).
+- **License**: tunneld is licensed under the GNU Affero General Public License, version 3 or (at your
+  option) any later version (`LICENSE.md` is the verbatim license text; the program notice is in the
+  README). Country data is DB-IP Country Lite — © db-ip.com, CC BY 4.0 (the README carries the
+  attribution; it MUST be preserved).
```

#### Definition of Done

- [x] The three bullets read as above; no other part of the document changed.

### [x] Task 3.3: `.claude/rules/project.md`

- [x] **Action 3.3.1** — `.claude/rules/project.md` (modify), Tech Stack `Release` row:

```diff
-| Release | goreleaser (`v*` tags) | linux amd64+arm64 archives + multi-arch image `ghcr.io/danielealbano/android-remote-control-mcp-tunneld`. |
+| Release | goreleaser (`v*` tags) | linux amd64+arm64 archives + multi-arch image `ghcr.io/danielealbano/android-remote-control-mcp-tunneld`; archives and images carry `THIRD_PARTY_LICENSES.txt`, generated at build time by `scripts/third-party-licenses.sh` (see `docs/PROJECT.md` §7). |
```

- [x] **Action 3.3.2** — same file, Repository hygiene, add after the DB-IP bullet:

```markdown
- **License: AGPL-3.0-or-later.** `LICENSE.md` is the verbatim GNU AGPLv3 text and MUST NOT be edited; the
  program notice lives in the README `## License` section. No per-file license headers.
- `THIRD_PARTY_LICENSES.txt` is GENERATED at build time (`make third-party-licenses`) from the Go
  toolchain's license and every module compiled into `cmd/tunneld` on linux amd64 + arm64 — the platform
  list in `scripts/third-party-licenses.sh` MUST match the goreleaser `builds` — and MUST NEVER be committed
  (it is gitignored). A module without a root `LICENSE*`/`LICENCE*`/`COPYING*`/`NOTICE*` file fails the build.
```

- [x] **Action 3.3.3** — same file, Standard Commands:

```diff
-- `make test-scripts` — POSIX harness for the `deploy/scripts/` fetch/gen-ca scripts
+- `make test-scripts` — POSIX harnesses for the `deploy/scripts/` fetch/gen-ca scripts and the `scripts/` generator
```

```diff
 - `make mermaid-check` — validate all Mermaid blocks in `README.md` + `docs/` via `mmdc`
+- `make third-party-licenses` — generate `THIRD_PARTY_LICENSES.txt` (gitignored) from the binary's dependency set
```

```diff
-(`.github/workflows/ci.yml`) runs `static-checks` (lint ×5, govulncheck, tidy-drift, shellcheck,
-script tests, compose config, mermaid-check), `build`, `test-unit`, `test-integration`, `test-e2e`, `test-staging`,
+(`.github/workflows/ci.yml`) runs `static-checks` (lint ×5, govulncheck, tidy-drift, shellcheck,
+script tests, third-party licenses, compose config, mermaid-check), `build`, `test-unit`, `test-integration`, `test-e2e`, `test-staging`,
```

#### Definition of Done

- [x] The five hunks are in place; the file stays concise and contains no plan number.

---

## User Story 4: Ground-up double check

- [x] **US4** — Verify EVERYTHING implemented by this plan from the ground up.

Why: the pipeline requires one final verification of every change against the plan, with the quality gates
run once, at the end.

### Acceptance Criteria

- [x] Every checkbox of US1–US3 is ticked against the files on disk (re-read each touched file).
- [x] All quality gates pass on the final code.

### [x] Task 4.1: Re-read and verify every change

- [x] **Action 4.1.1** — Re-read `LICENSE.md` (sha256 check), `.goreleaser.yaml`, `Dockerfile`,
      `Dockerfile.goreleaser`, `.gitignore`, `Makefile`, `.github/workflows/ci.yml`,
      `scripts/third-party-licenses.sh`, `scripts/scripts_test.sh`, `README.md`, `docs/PROJECT.md`,
      `.claude/rules/project.md` and compare each against its action; run the US1 `git grep` (zero matches);
      `git diff --name-only main...HEAD` together with `git status --porcelain` lists exactly those twelve files
      plus this plan document and the recorded out-of-plan test fix `internal/server/acmehttp_test.go` (one
      changed line, no header) and nothing else, so no source file gained a header.
- [x] **Action 4.1.2** — Run `make third-party-licenses` and verify the output: the Go heading first with
      `go1.27.2`; `grep -c '^==== ' THIRD_PARTY_LICENSES.txt` = 1 + the number of license/notice files of the
      modules; the module list (`sed -n 's/^==== \(.*\)@.*/\1/p' | sort -u`) equals
      `GOOS=linux CGO_ENABLED=0 go list -deps -f '{{if and (not .Standard) .Module (not .Module.Main)}}{{.Module.Path}}{{end}}' ./cmd/tunneld | sort -u`
      for both `GOARCH=amd64` and `GOARCH=arm64`; 11 `(NOTICE*)` sections — 9 `(NOTICE)` + 2 `(NOTICE.txt)`
      (aws-sdk-go-v2 and grpc; the others: smithy-go, pquerna/otp, the four `prometheus/*` modules,
      vinyldns/go-vinyldns, go.yaml.in/yaml/v3, gopkg.in/yaml.v2); the 12 MPL-2.0 texts present; file mode 0644;
      `git status --porcelain` does not list the file.
- [x] **Action 4.1.3** — `goreleaser check`; then `goreleaser release --snapshot --clean --skip=publish`
      (captured with `tee`): every `dist/tunneld_*_linux_*.tar.gz` lists exactly `LICENSE.md`, `README.md`,
      `THIRD_PARTY_LICENSES.txt`, `tunneld`, with the notices entry mode 0644; BOTH platform images the
      snapshot run loads locally (the `ghcr.io/danielealbano/android-remote-control-mcp-tunneld` tags suffixed
      `-amd64` and `-arm64`) contain `/THIRD_PARTY_LICENSES.txt` mode 0644 (`docker create` + `docker cp`) and
      carry the label `org.opencontainers.image.licenses` = `AGPL-3.0-or-later`.
- [x] **Action 4.1.4** — `docker build -f Dockerfile -t tunneld:plan19 .` (captured with `tee`); extract
      `/THIRD_PARTY_LICENSES.txt` from the image (`docker create` + `docker cp`), check mode 0644 and that its
      content equals the output of `make third-party-licenses` run with the same Go toolchain.

#### Definition of Done

- [x] Quality gates, each captured with `tee` to `/tmp/<descriptive>.log`, all exit 0: `make lint`,
      `make build`, `make vet`, `make govulncheck`, `make test-unit`, `make test-scripts`,
      `make test-integration`, `make test-e2e`, `make test-staging` (skips without
      `TUNNELD_STAGING_SSH_KEY`), `make compose-config`, `make third-party-licenses`.

## Deviations

- **Action 2.3.1 (Makefile `.PHONY` context):** `main` gained `test-soak-app` in the `.PHONY` list after the
  plan was written (PR #58), so the hunk was applied onto the current line — `third-party-licenses` is added
  in the same position, next to `mermaid-check`; the recipe hunks applied unchanged.
- **Action 2.2.1 (`line_of` helper):** the harness briefly carried a `line_of <pattern> <file>` helper so the
  happy path could assert that the Go license text precedes the first module text; the byte-for-byte
  comparison below made it redundant and it was removed again.
- **Action 3.2.1 (`docs/PROJECT.md` Standard commands context):** PR #58 reworded the bullet (it now also
  describes `test-soak-app`), so `third-party-licenses` was inserted after `mermaid-check` in the current
  sentence instead of the plan's context lines; the Releases and License bullets applied as planned.
- **Action 3.3.3 (`.claude/rules/project.md` CI line context):** the line now reads `lint ×5` (PR #58 added
  the `e2e,soak` lint pass); `third-party licenses` was inserted into the current line.
- **Action 2.2.1 (stub argument logs — code review):** the `go` stub also appends its full argument list to
  `go-args.log` and the `mktemp` stub appends its template to `mktemp-args.log`; the happy-path case asserts
  both `go list` calls carry exactly `-deps`, the module-filter template and `./cmd/tunneld`, and that both
  temp files are created in the output directory. The `mktemp` stub fails its second call only when
  `STUB_MKTEMP_FAIL=1`, so it can be installed in the happy path. Without these, a generator that dropped
  `-deps` (one heading, exit 0) or created its temp files elsewhere passed every test.
- **Commit `04bfda2` scope (code review):** the review noted the commit spans `scripts/`, the `Makefile`
  and `.gitignore` and so should carry the `tunneld` scope; the user decided on 2026-10-19 NOT to rewrite the
  pushed history, so the message stays as published.
- **Action 2.2.1 (ordered call log + stderr — code review):** every stub also appends to one shared
  `calls.log`, and the happy path asserts the exact sequence `go env GOVERSION`, `go env GOROOT`, `mktemp`,
  `mktemp`, `go list`, `go list`, `sort`, which pins that BOTH `go env` calls run before any `mktemp`; the
  go-env failure case runs once per key (`STUB_GO_ENV_FAIL=GOVERSION|GOROOT`), so a masked failure of either
  call is caught on its own. The failure cases let the generator's
  stderr reach the console, as the reference harness does; the two cases that assert on stderr capture it and
  print it when they fail. The `mktemp` stub reads its counter behind an existence check instead of
  `2>/dev/null || echo 0`, so an unexpected read error is no longer hidden.
- **Out-of-plan test fix (`internal/server/acmehttp_test.go`, `expectClosedByPeer`):** the final gate run
  failed `TestGuardListener_UnparseablePeerRefused` with `io: read/write on closed pipe` at the
  `SetReadDeadline` call: `net.Pipe` returns `io.ErrClosedPipe` from `SetReadDeadline` once EITHER end is
  closed (Go 1.27.2 `net/pipe.go`), and the guard's check goroutine closes the server end concurrently, so the
  helper failed whenever that goroutine won the race. The helper now tolerates that one error from the
  deadline call; the following `Read` still asserts `io.EOF`, which only a peer close produces. Fixed per the
  fix-broken-tests rule; no production code changed.
- **Action 2.2.1 (byte-for-byte happy path, subshell exports — code review):** the fixture now holds a two-line
  Go license and a two-line alpha license plus an `expected.txt` with the exact output, and the happy path
  asserts `cmp -s expected.txt out.txt` (printing the diff when it fails) instead of heading, presence and
  ordering checks — a swapped heading/content or a truncated file passed the previous assertions. The
  failure cases set their stub controls with `export` inside a subshell (`(export STUB_…; run_gen …)`) because
  POSIX leaves it unspecified whether a prefix assignment on a function call is exported to the function's
  children; the case names in the table changed accordingly.
- **Action 2.2.1 (rename observable — code review):** the happy path pre-creates `out.txt` as `OLD` with a hard
  link `old.lnk` and asserts the link still reads `OLD` after the run: a rename replaces the directory entry
  and leaves the linked inode untouched, while an in-place `cp` or `cat >` rewrites it — the previous cases
  never exercised the temp-file + `mv` contract on an existing output.

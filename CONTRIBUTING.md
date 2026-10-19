# Contributing

Thank you for your interest in contributing to the Android Remote Control MCP tunnel server (`tunneld`)!

## Getting Started

1. Fork the repository.
2. Create a branch named `<type>/<short-description>`, where `<type>` is one of `feat`, `fix`, `refactor`,
   `test`, `docs`, `chore` or `style`: `git checkout -b feat/your-feature`.
3. Make your changes following the project conventions, with tests.
4. Make sure the checks pass: `make lint && make vet && make build && make test-unit && make test-scripts`.
5. Commit with messages in the form `<type>(<scope>): <short description>`, e.g.
   `fix(phoneconn): close the stale connection on rebind`; the scopes are listed in
   [`.claude/rules/project.md`](.claude/rules/project.md). Sign your commits: `main` only accepts verified
   signatures.
6. Open a pull request against `main`. CI runs the linters, the build and every test tier; pull requests are
   merged with a merge commit.

## Development Conventions

- **Language**: Go (the version is pinned in `go.mod`), one static binary built with `CGO_ENABLED=0`.
- **Design**: interfaces at the consumer site, constructor dependency injection (all wiring in `server.Run`, no
  package globals), `context.Context` first on any I/O, `errgroup` for goroutine groups.
- **Testing**: table-driven unit tests (miniredis, httptest, fake clocks); integration and e2e tests run the
  real server against containers started with testcontainers-go.
- **Linting**: golangci-lint without `//nolint` suppressions, `go vet`, govulncheck and shellcheck. Charts in
  Markdown are Mermaid only.
- **Invariants**: tunneld relays opaque TLS and must never read tunnel traffic. The wire protocol is defined by
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md); any wire change updates it and the Go client in `client/` together.
- **Repository hygiene**: only placeholder values in the repository (`example.test`, country codes `XX`/`YY`,
  secrets `changeme`); never log secrets, key material or tunnel payloads.

See [`docs/PROJECT.md`](docs/PROJECT.md) for the operational reference and
[`.claude/rules/go.md`](.claude/rules/go.md) for the complete Go conventions.

---

## Requirements

- **Go**: the version in `go.mod`.
- **GNU make**.
- **Docker**: the integration, e2e and staging tests start Valkey, MinIO and a test ACME CA with
  testcontainers; Docker also builds the image and runs the compose stack.
- **golangci-lint v2.14.0** (the version CI uses) and **shellcheck**, for `make lint`.
- **Node.js** with `npx`, for `make mermaid-check` (CI uses Node 24).
- Optional: the **Android SDK** and **adb** with one attached device, for the on-device test apps under
  `support/` (`make attest-probe`, `make tunnel-app`, `make soak-app`) and the device e2e tests.

---

## Building

```bash
make build                                      # bin/tunneld
docker build -t tunneld:local -f Dockerfile .   # the runtime image the compose stack uses
make third-party-licenses                       # THIRD_PARTY_LICENSES.txt (generated, gitignored)
```

The compose deployment quickstart is in the [README](README.md).

---

## Testing

| Command | What it runs | Needs |
|---|---|---|
| `make test-unit` | unit tests with the race detector | — |
| `make test-integration` | the assembled server against Valkey, MinIO and Pebble containers | Docker |
| `make test-e2e` | two replicas end to end; the device tests skip unless one adb device is attached | Docker |
| `make test-staging` | real Let's Encrypt and GTS staging validation through a reverse SSH tunnel; skips without `TUNNELD_STAGING_SSH_KEY` | Docker, the `TUNNELD_STAGING_*` variables |
| `make test-scripts` | the POSIX harnesses for the shell scripts | — |
| `make test-all` | unit, integration, e2e and staging | Docker |

`make test-soak-app` runs the soak-app device tests; it is not part of the default gates.

---

## Linting

```bash
make lint            # golangci-lint for every build-tag set, shellcheck, compose config check
make vet
make govulncheck
make tidy            # go mod tidy; CI fails on go.mod / go.sum drift
make mermaid-check   # validates every Mermaid chart in README.md and docs/
```

---

## Architecture

One binary is the internet edge on raw TCP `:443`: it peeks each TLS ClientHello, routes on SNI and splices the
opaque encrypted stream to a connection the phone dials back to the node the client entered. Valkey holds the
transient control state and a plain S3 bucket the durable state. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the system map and [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire protocol.

---

## License

tunneld is licensed under the GNU Affero General Public License, version 3 or (at your option) any later version
([`LICENSE.md`](LICENSE.md)). Under GitHub's Terms of Service, contributions to this repository are licensed under
the same terms.

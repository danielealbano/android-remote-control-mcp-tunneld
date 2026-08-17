# Go Rules — ABSOLUTE RULES

These rules apply to ANY Go project where this file is present. They are **VERY STRICT and ABSOLUTELY NON-NEGOTIABLE**!
Project-specific details (structure, dependencies, Makefile targets) live in the project-specific rule file.

## 1) Architecture & Idioms — ABSOLUTE RULES

### Go idioms first
- You MUST follow Effective Go, the Go Code Review Comments wiki, and the Go Proverbs.
- You MUST ALWAYS prefer simplicity over cleverness. Clear is better than clever.
- You MUST accept interfaces, return structs.
- You MUST keep packages small and cohesive; you MUST NEVER create "util" or "common" mega-packages.
- You MUST use composition (embedding) rather than deep type hierarchies.
- You MUST export only what consumers need; keep the public API surface minimal.
- You MUST NEVER create APIs that accept nils — it usually means too many things are being done in one place and a refactor / split is required.
- You MUST keep the responsibilities in the code narrow.
- You MUST ALWAYS write code that is testability friendly.

### Interface-first and testability
- You MUST define interfaces at the **consumer** site, not the provider, following Go convention.
- You MUST default to interfaces for components that touch external systems or contain business logic that should be unit tested in isolation.
- You MUST keep interfaces small (1–3 methods). You MUST ALWAYS prefer composing small interfaces over large ones.

### Functional options pattern
- You MUST use the functional options pattern for configurable constructors: `func(*T) error` option functions.
- Constructor functions MUST be named `NewXxx(requiredArgs, ...options)`.

### Dependency injection
- You MUST pass dependencies explicitly via constructor parameters or functional options.
- You MUST NEVER rely on package-level globals or `init()` for wiring dependencies.
- `context.Context` MUST be the first parameter of any function that does I/O or may be cancelled.

### Concurrency and race conditions
You MUST ALWAYS assume the system can run in parallel: multiple requests, multiple goroutines, retries, overlapping operations.

You MUST:
- design for idempotency where appropriate,
- protect shared state with mutexes, channels, or atomic operations,
- use `context.Context` for cancellation and timeouts,
- handle retries safely without duplicate side effects,
- NEVER launch goroutines that can leak (you MUST ALWAYS ensure they can be stopped via context or channel close).

### Goroutine management
- Every goroutine MUST have a clear shutdown path (via `context.Context` cancellation, channel close, or `sync.WaitGroup`).
- You MUST use `errgroup.Group` (from `golang.org/x/sync/errgroup`) for managing groups of goroutines with error propagation.
- You MUST NEVER fire-and-forget goroutines in production code.
- You MUST protect shared mutable state with `sync.Mutex`, `sync.RWMutex`, channels, or `sync/atomic`.

## 2) Coding Standards — ABSOLUTE RULES

### Validation
- You MUST ALWAYS validate inputs at the boundary.
- You MUST use struct tags or explicit validation functions.
- You MUST return structured error responses with enough detail for the caller to fix the issue.

### Error handling
- You MUST ALWAYS check and handle errors. You MUST NEVER use `_` to discard errors unless there is a documented justification.
- You MUST wrap errors with context using `fmt.Errorf("operation description: %w", err)`.
- You MUST use sentinel errors (`var ErrNotFound = errors.New(...)`) for errors that callers need to match with `errors.Is`.
- You MUST use custom error types (implementing the `error` interface) when callers need to inspect error details with `errors.As`.
- You MUST NEVER panic in library code. Panics are acceptable only for truly unrecoverable programmer errors in `main` or `init`.
- You MUST return errors, not log-and-continue, unless the error is truly informational.

### Context usage
- `context.Context` MUST be the first parameter of any function that performs I/O, calls external services, or may need cancellation.
- You MUST ALWAYS propagate context through the call chain; you MUST NEVER create a new background context in the middle of a request.
- You MUST use `context.WithTimeout` or `context.WithDeadline` for external calls.

### Logging
- You MUST use the following log levels: `Debug` (fine-grained internal flow), `Info` (business events), `Warn` (recoverable), `Error` (unrecoverable).
- You MUST ALWAYS include identifiers in logs (request ID, entity ID, etc.).
- You MUST NEVER log secrets, tokens, API keys, or PII.
- Errors MUST be actionable: include what failed, which identifiers, and likely next steps.

### Configuration
- You MUST NEVER hardcode secrets or environment-specific values.
- You MUST use environment variables for configuration; parse them with strongly typed structs.
- You MUST validate all required configuration at startup. Fail fast with a clear error message if anything is missing or invalid.
- You MUST use strongly typed config structs, not scattered `os.Getenv` calls throughout the code.

### Module management
- You MUST keep `go.mod` clean: run `go mod tidy` after adding or removing dependencies.
- You MUST ALWAYS commit both `go.mod` and `go.sum`.
- You MUST use latest stable versions of dependencies.
- You MUST prefer well-maintained packages with active development.
- You MUST check for known vulnerabilities before adding: `govulncheck ./...`.
- You MUST prefer the Go standard library over third-party packages when feasible.
- You MUST ALWAYS wrap third-party clients behind your own interface so you can swap or mock them.

## 3) Testing Rules — ABSOLUTE RULES

All references to "tests" in this document mean automated tests (unit, integration, and e2e) that run during development and in CI/CD pipelines.

### General principles
- Tests are MANDATORY for all changes. There are ZERO exceptions.
- Tests MUST be small, focused, and non-redundant while still covering: happy path, edge cases, failure modes.
- Tests MUST ALWAYS pass.
- Tests MUST NOT depend on execution order.
- Tests MUST clean up after themselves (temp files, test containers).

### Test organization and naming
- Test files MUST live next to the code they test: `foo.go` → `foo_test.go`.
- You MUST use the `_test` package suffix for black-box tests (e.g., `package foo_test`) to test only the public API.
- You MUST use the same package name only when you need to test unexported internals, and you MUST prefer this sparingly.
- You MUST name test functions descriptively: `TestServiceName_MethodName_Scenario`.

### Table-driven tests
- You MUST use table-driven tests as the default pattern for functions with multiple input/output cases.
- Each test case MUST have a descriptive `name` field.
- You MUST use `t.Run(tc.name, func(t *testing.T) { ... })` for subtests.
- You MUST mark test helpers with `t.Helper()`.

```go
func TestParseURL_Variants(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {name: "valid https URL", input: "https://example.com", want: "https://example.com", wantErr: false},
        {name: "empty string", input: "", want: "", wantErr: true},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            got, err := ParseURL(tc.input)
            if (err != nil) != tc.wantErr {
                t.Fatalf("ParseURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
            }
            if got != tc.want {
                t.Errorf("ParseURL(%q) = %q, want %q", tc.input, got, tc.want)
            }
        })
    }
}
```

### Unit tests
- Unit tests MUST be fast (no I/O, no network, no external services).
- You MUST use interfaces and dependency injection to mock external dependencies.
- You MUST use `t.Parallel()` for tests that are safe to run concurrently.
- You MUST prefer the standard library (`t.Errorf`, `t.Fatalf`) or `testify/assert` and `testify/require` if already in use.
- You MUST use `testing/fstest.MapFS` or `os.MkdirTemp` for filesystem-dependent tests.
- You MUST short-circuit with `t.Skip("reason")` or `-short` flag for tests that are too slow for rapid iteration.

### Integration tests
- Integration tests MUST verify that individual components work correctly against real external systems.
- You MUST guard integration tests with the build tag `//go:build integration` at the top of the file.
- **Testcontainers are MANDATORY**: when a test needs any external service, it MUST use `testcontainers-go` to spin up that service. You MUST NEVER rely on pre-running Docker Compose services or shared, long-lived test infrastructure.
- You MUST start containers in `TestMain` or in a shared test helper and pass connection details to tests. You MUST use `t.Cleanup` (or `defer container.Terminate(ctx)`) to guarantee teardown.
- Containers MUST be ephemeral and isolated: each test suite gets its own container instance.
- Each integration test MUST set up and tear down its own state (use `t.Cleanup`).
- Integration tests MUST respect `context.Context` timeouts.

### End-to-end (E2E) tests
- E2E tests MUST exercise the full system roundtrip.
- You MUST guard E2E tests with the build tag `//go:build e2e`.
- All required infrastructure MUST be started via `testcontainers-go` (same rules as integration tests).
- E2E tests MUST be idempotent and safe to re-run.
- You MUST use realistic but deterministic test data.

### Race detection
- CI MUST run tests with `-race` flag: `go test -race ./...`.
- You MUST fix all data races immediately; they are not warnings — they are bugs.

### Mocking
- You MUST use interfaces for all external boundaries so they can be mocked in tests.
- You MUST prefer hand-written mocks (simple struct implementing the interface) for small interfaces.
- You MUST use code generation (`mockgen`, `moq`, or `counterfeiter`) only for interfaces with many methods.
- You MUST NEVER mock what you don't own in unit tests — you MUST wrap third-party clients behind your own interface first.

### Environment variables for tests
- IF the project defines a dotenv file for test configuration (e.g. a gitignored `.env` with a committed `.env.example`), the Makefile test targets MUST source it automatically when present, and manual `go test` runs MUST source it first: `set -a && source .env && set +a && go test ...`. Whether such a file exists — and what it contains — is defined in the project-specific rule file, NOT here.
- Integration and E2E tests using testcontainers do NOT need pre-configured environment variables — they start their own infrastructure.

### Manual testing documentation
- Manual tests are NOT a substitute for automated tests.
- If manual testing steps are necessary, they MUST be clearly labeled as "**Manual Test**" or "**Manual QA Steps**" and documented separately from automated test descriptions.

## 4) Quality Gates — ABSOLUTE RULES

### Definition of Done
A change MUST be considered DONE **ONLY AND ONLY** if ALL are true:

- All relevant automated tests are written AND passing (unit, integration, e2e as appropriate).
- No linting warnings/errors.
- The project builds without errors and without warnings (`go build ./...`).
- No TODOs, no commented-out dead code, no "temporary hacks".
- Changes are small, readable, and aligned with existing Go patterns.

### Fix broken tests — ABSOLUTE RULE
- You MUST fix ANY broken test, even if unrelated to your changes. Finish your current change first, then fix the broken test immediately.
- You MUST NEVER leave the test suite broken. There are ZERO exceptions.

### Fix broken linting — ABSOLUTE RULE
- You MUST fix ANY linting or formatting error, even if unrelated to your changes. Finish your current change first, then fix the violations immediately.
- You MUST NEVER leave the codebase with linting or formatting violations. There are ZERO exceptions.

### No linting suppression — ABSOLUTE RULE
- You MUST NEVER suppress, silence, or skip linting rules (e.g., `//nolint` directive comments, disabling rules in config) to make errors disappear.
- You MUST FIX the root cause of every linting error or warning by adjusting the implementation.
- The ONLY exception is when a linting rule GENUINELY and unavoidably conflicts with the project's documented design decisions. In that case, you MUST explain the conflict to the user and get EXPLICIT approval before adding any suppression. This is NON-NEGOTIABLE.

### Standard build/lint/test commands
- Build: `go build ./...`
- Vet: `go vet ./...`
- Unit tests: `go test -short -race ./...`
- Integration tests: `go test -tags=integration -race -v ./...`
- E2E tests: `go test -tags=e2e -race -v ./...`

Project-specific Makefile targets and additional commands are defined in the project-specific rule file.

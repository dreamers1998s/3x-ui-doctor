# Contributing

Contributions are welcome when they preserve the read-only and clean-room
boundaries.

1. Open an issue describing the evidence and affected 3x-ui version.
2. Add a redacted fixture and a failing test.
3. Implement the smallest version-scoped change.
4. Run `go test ./...`, `go test -race ./...`, and `go vet ./...`.
5. Confirm seeded credentials do not appear in reports or errors.

Do not copy source, test fixtures containing private data, or generated code
from GPL-3.0 3x-ui into this MIT repository. Public API behavior may be described
independently and tested with synthetic fixtures.

Rules must remain deterministic and must not perform network requests. A rule
consumes normalized evidence and returns a structured finding with impact and
remediation.

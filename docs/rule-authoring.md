# Rule authoring

v0.1 rules are compiled into the binary. Third-party runtime rule packages are
out of scope.

A rule must:

- consume only normalized, redacted snapshot evidence;
- perform no network, filesystem, clock, or environment access;
- return `PASS`, `WARN`, `FAIL`, or `INCONCLUSIVE` deterministically;
- distinguish missing evidence from a passing check;
- include an anonymous subject, observed/expected state, impact, and
  remediation; and
- include synthetic fixtures for pass, failure, and incomplete evidence.

Rule identifiers are stable public interfaces. Do not reuse an identifier for a
different invariant.

# Architecture

```text
doctor.yaml + environment secrets
              |
              v
        secure HTTP adapters
              |
              v
 typed v3.5/v3.6 collection ----> in-memory subscription parsing
              |
              v
 normalization + keyed redaction
              |
              v
 versioned snapshot ----> baseline diff
              |                 |
              +-------> pure rule engine
                              |
                              v
                 terminal / JSON / Markdown
```

Adapters own wire-format differences and the read-endpoint allowlist. The
collector owns bounded concurrency, topology reconciliation, deterministic
topology-wide sampling, and observation timing. Rules never receive tokens, raw response
bodies, URLs, client credentials, or subscription IDs.

The persisted snapshot is the compatibility boundary between `preflight` and
`verify`. Its schema, Doctor version, rule-pack version, target version,
redaction key ID, and sampling parameters are recorded in the manifest.

No package imports upstream 3x-ui code. OpenAPI is evidence, not executable
code generation input.

# Compatibility

| Source | Target/check | v0.1 behavior |
|---|---|---|
| v3.5.0 | preflight for v3.6.0 | Guaranteed rule adapter |
| v3.6.0 | check or verify | Guaranteed rule adapter |
| other | any | Generic safe reads; `INCONCLUSIVE` |

The runtime fetches the authenticated OpenAPI document and verifies every
operation Doctor depends on. Whole-document hash drift is recorded as a warning
in upgrade diffs; removal of a required operation is blocking. Runtime code or
rules are never downloaded.

`--target stable` queries the official GitHub latest-release endpoint and pins
the returned tag into the manifest. v0.1 refuses to call a target other than
v3.6.0 even if a newer stable version exists.

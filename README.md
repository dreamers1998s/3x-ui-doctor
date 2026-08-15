# 3x-ui Doctor

Preflight, audit and regression checks for 3x-ui.

3x-ui Doctor is an unofficial, read-only-first companion CLI that checks panel
APIs, generated Xray configuration, subscriptions, direct child-node
consistency, traffic accounting, quota state, and upgrade regressions.

> [!IMPORTANT]
> `READY` means that Doctor found no known blocker in the evidence it could
> collect. It is not a guarantee that an upgrade is risk free.

## v0.1 compatibility

- Guaranteed preflight path: 3x-ui v3.5.0 to v3.6.0
- Daily checks: v3.6.0
- Unknown versions: generic safe reads only; readiness is `INCONCLUSIVE`
- Distribution: Linux amd64 and arm64 binaries, plus a non-root container

The implementation is independent and uses documented HTTP APIs. It does not
read or write `x-ui.db`, call update/restart/reset endpoints, or inject code into
the panel frontend.

## Why

A configuration can save successfully but fail when rendered for Xray. A
subscription can be generated but fail to parse. A node can appear online while
traffic counters or assigned objects have diverged. Doctor records evidence at
each layer and produces a redacted report suitable for an incident or upgrade
review.

## Commands

```sh
xui-doctor preflight \
  --config doctor.yaml \
  --target v3.6.0 \
  --baseline-out before-upgrade.json

xui-doctor verify \
  --config doctor.yaml \
  --baseline before-upgrade.json

xui-doctor check --config doctor.yaml
```

All commands accept:

- `--format terminal|json|markdown`
- `--output <path|->`
- `--observe 60s`
- `--force`

Exit codes are `0 READY`, `1 BLOCKED`, `2 INCONCLUSIVE`, and `3` for invalid
input or initialization failure. `BLOCKED` wins when blocking and inconclusive
findings coexist.

## Configuration

Copy [`doctor.example.yaml`](doctor.example.yaml), then provide secrets through
environment variables:

```sh
export XUI_MASTER_TOKEN='...'
export XUI_NODE_DE_TOKEN='...'
export XUI_DOCTOR_HMAC_KEY="$(openssl rand -hex 32)"
```

The HMAC key must remain the same between `preflight` and `verify`; it lets
Doctor recognize the same object without writing its original identifier.
`key_id` is a non-secret label used to reject baselines created with a different
key.

Each direct child panel needs its own URL and API token. The configured
`master_node_guid` must match the stable GUID shown by the master. Tokens cannot
be embedded in YAML.

TLS verification is mandatory. A SHA-256 leaf certificate pin can be used as an
explicit trust root for a self-signed panel. Doctor does not inherit
`HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`; a proxy must be explicitly referenced
by an environment-variable name in the configuration.

## Built-in rules

| Rule | Check |
|---|---|
| API-001 | Safe response body, media type, and envelope |
| API-003 | Required OpenAPI operations and version support |
| CFG-001 | Fallback destination resolution |
| CFG-002 | v3.6 protocol/transport/security compatibility |
| CFG-003 | Saved versus generated Xray configuration |
| SUB-001 | Raw, Base64, JSON, and Clash parsing |
| SUB-003 | Share-link versus subscription semantics |
| NODE-001 | Reachability, identity, and target version |
| NODE-003 | Assigned inbound/client consistency |
| TRAFFIC-001 | Repeated traffic accumulation |
| TRAFFIC-002 | Persistent cross-node counter deviation |
| LIMIT-001 | Enabled state after quota or expiry |

Doctor samples traffic six times over 60 seconds by default. A cross-node
deviation must persist for three samples and exceed `max(5%, 64 MiB)` before it
blocks. Subscription checks use deterministic stratified sampling with a
default cap of 50 client/inbound samples across the entire configured topology.

## Reports and data safety

Raw responses, API tokens, cookies, client credentials, subscription IDs, and
private keys are never serialized. Reports use stable keyed aliases such as
`client_12ab34cd56ef`. Network identifiers are hidden by default.

Set `report.include_network_identifiers: true` only when raw domain names and
IP addresses are required for a private investigation. Such snapshots and
reports are marked sensitive; the allowlist extractor still excludes arbitrary
configuration fields, credentials, and private keys.

File output is written to a restricted temporary file and atomically installed.
Existing files are not replaced unless `--force` is supplied. If owner-only
permissions cannot be established, file output fails closed.

See [`docs/security-model.md`](docs/security-model.md) for the full threat model.

## Build and test

Go 1.26 or later is required.

```sh
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o bin/xui-doctor ./cmd/xui-doctor
```

Container build:

```sh
docker build -t 3x-ui-doctor:dev .
docker run --rm --read-only --cap-drop=ALL \
  -v "$PWD/doctor.yaml:/config/doctor.yaml:ro" \
  -e XUI_MASTER_TOKEN -e XUI_DOCTOR_HMAC_KEY \
  3x-ui-doctor:dev check --config /config/doctor.yaml
```

Tagged releases contain Linux amd64/arm64 binaries, `SHA256SUMS`, and an SPDX
SBOM. Multi-platform container releases are published with BuildKit provenance,
an SBOM attestation, and an immutable digest recorded in the workflow summary.

## Project status and authorization

3x-ui Doctor is an unofficial community project and is not affiliated with the
3x-ui maintainers. Use it only on systems you own or are authorized to manage.

The project is MIT licensed. If upstream GPL-3.0 implementation code is ever
copied, modified, or linked, the license decision must be reviewed again.

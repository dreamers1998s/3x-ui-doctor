# Security model

## Protected data

- panel tokens and cookies;
- UUIDs, passwords, auth values, and subscription IDs;
- emails, Telegram identifiers, comments, domains, and IP addresses;
- Reality and other private keys;
- certificate paths and database connection strings.

## Controls

- secrets are environment references, never YAML values;
- TLS uses the system trust store or an exact SHA-256 leaf pin;
- a panel pin applies only to that panel origin (including same-origin
  subscriptions); cross-origin subscription hosts always use system trust;
- system proxy variables are ignored unless an explicit proxy reference exists;
- panel Authorization is sent only to the configured panel origin;
- cross-origin redirects are denied unless the host is allowlisted, and never
  receive panel Authorization or cookies;
- response bodies are bounded to 32 MiB;
- persisted identities are keyed HMAC aliases;
- raw domain/IP fields are excluded unless
  `report.include_network_identifiers` is explicitly enabled;
- reports contain structured error codes instead of response fragments;
- file output uses a restricted temporary file and atomic installation; and
- no mutating panel endpoint exists in the client API.

## Residual risks

An API token remains a full-administrator credential if Doctor or the host is
compromised. A report still reveals topology size, versions, rule outcomes, and
stable aliases. Protect report files as operational security material.

Opting into network identifiers marks output as sensitive. Only explicitly
recognized address fields are retained; configuration objects are never walked
recursively because unrelated fields can contain credentials or private keys.

Subscription checks use live client credentials in memory. A process memory
dump can expose them. Run Doctor on a trusted host, avoid swap/core dumps where
appropriate, and rotate client credentials after suspected host compromise.

## Failure policy

Unknown versions, missing nodes, timeouts, and insufficient samples are
`INCONCLUSIVE`. Proven identity/configuration mismatches are `BLOCKED`. Output
permission failure is an initialization error and leaves no completed output.

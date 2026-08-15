# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for the repository.
Do not open a public issue containing panel URLs, tokens, subscription links,
client identifiers, report files, or reproducible credentials.

Include the affected Doctor version, operating system, command, and a minimal
redacted reproduction. Replace all secrets before attaching logs or snapshots.

## Supported versions

Security fixes are provided for the latest released version. The current
development branch may change without compatibility guarantees.

## Operational boundary

Doctor's API token has full panel-administrator authority even though Doctor
uses only audited read endpoints. Create a dedicated token per panel, transmit
it only over verified TLS, store it in a secret manager or environment variable,
and revoke it when no longer needed.

Doctor is not an authorization bypass. Use it only against systems you own or
are explicitly authorized to manage.

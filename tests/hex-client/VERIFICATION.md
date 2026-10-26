# Verification

Run on 2026-10-26 using Elixir 1.20.1, Erlang/OTP 29.0.2 and Hex 2.6.0.
Both `unsafe_registry` and `no_verify_repo_origin` were confirmed false in the
client's effective configuration.

| Real Mix app case | Local storage | MinIO S3 storage |
|---|---|---|
| Public Hex.pm cold install, compile and JSON assertion | Passed | Passed |
| Restart Nora; block upstream; fresh client installs and runs | Passed | Passed |
| Young locked release denied with HTTP 403, client cooldown off | Passed | Passed |
| Young exact pin without lock denied with HTTP 403, client cooldown off | Passed | Passed |
| Nonmatching exemption still rejects young release | Passed | Passed |
| Exact exemption allows young locked release | Passed | Passed |
| Exact exemption allows young pin without lock | Passed | Passed |
| Removing exemption restores blocking with same persisted Nora cache | Passed | Passed |
| Mature signed fixture resolves with client cooldown and runs | Passed | Passed |

Hex 2.2.1 (without native client cooldown support) also passed all seven controlled
fixture cases on local storage. All fixture cases used an explicit fixture trust
anchor; public cases used the official Hex.pm key. Exempt client installs used
`HEX_COOLDOWN=0d`; Nora still enforced the seven-day policy for non-exempt names.

The app uses the actual Jason 1.4.4 archive and verifies JSON decoding. Controlled
cases re-sign metadata with adjusted timestamps, so results do not depend on a
new public package happening to exist. MinIO was an ephemeral container running
`quay.io/minio/minio:RELEASE.2025-02-07T23-21-09Z`; this validates the S3 API backend,
not a live AWS deployment or EKS IAM configuration.

Reproduce with the commands in README.md. Ignored `.state/` contains server logs
and per-client/backend JSON outcomes from local runs. All three commands passed
against the final binary, SHA-256:
`e31d0d1aecf5f11519f9cb32886e2018d0f28b90b6e7a47acf7b6ce59c9b9219`.

Rust verification: 88 library and 3,081 binary tests passed; one pre-existing
binary test remains ignored. Coverage includes exempt young/missing/untrusted
dates, cache hits, exact matching, retained blocklist/allowlist/signature/checksum
checks, valid SIGHUP addition/removal, rejected invalid reloads, input validation
and environment overrides. Clippy with tests and `-D warnings`, formatting, diff
whitespace and changelog checks passed.

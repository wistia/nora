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
| Mature signed fixture resolves with client cooldown and runs | Passed | Passed |

Hex 2.2.1 (without native client cooldown support) also passed the young locked,
young pinned and mature fixture cases on local storage. All fixture cases used
an explicit fixture trust anchor; public cases used the official Hex.pm key.

The app uses the actual Jason 1.4.4 archive and verifies JSON decoding. Negative
cases use a separately signed controlled upstream, so results do not depend on a
new public package happening to exist. MinIO was an ephemeral container running
`quay.io/minio/minio:RELEASE.2025-02-07T23-21-09Z`; this validates the S3 API backend,
not a live AWS deployment or EKS IAM configuration.

Reproduce with the commands in README.md. Ignored `.state/` contains server logs
and per-client/backend JSON outcomes from local runs.

Rust verification: full default library/binary suite passed (88 library tests
and 3,074 binary tests; one pre-existing ignored test). Clippy with tests and
`-D warnings`, formatting, diff whitespace and changelog fragment checks passed.

All three real-client commands were repeated successfully against the final
binary (SHA-256 `34daa05458cb331ce7979ffb79940744f876482212c22bf198502824dfd2f0e3`).
The final focused run passed 14 Hex-related tests after the immutable-cache
optimization; the full suite and Clippy results above also passed.

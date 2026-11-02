# Hex / Elixir read-only mirror

Hex is explicitly opt-in, including when `registries.enable = "all"`. It proxies
public `hexpm` repositories and uses the existing local/S3/GCS storage layer.

```toml
[registries]
enable = ["npm", "gems", "go", "hex"]

[server]
trust_upstream_dates = true

[hex]
proxy = "https://repo.hex.pm"
proxy_timeout = 30
metadata_ttl = 300
serve_stale = true
revalidate = true

[curation]
mode = "enforce"
min_release_age = "7d"
quarantine = "enforce"
quarantine_ttl = "7d"
```

Set every registry explicitly when using `enable`; it replaces legacy selection.
Global cooldown settings apply to Hex. `[curation.hex]` supports the standard
per-registry `min_release_age`, `quarantine` and `quarantine_ttl` overrides.
Package cooldown exemptions use exact Hex package names:

```toml
[curation.hex]
cooldown_exempt_packages = ["wistia_some_package"]
```

Listed names are exempt from both release age and digest quarantine for all their
versions, including when dates are missing or untrusted. Every other package keeps
the configured cooldown. Wildcards, scopes and publisher/owner matching are not
supported. Signature, repository identity, checksum, blocklist, allowlist and
namespace checks remain active. This setting is currently supported only for Hex;
non-empty exemption lists in other registry sections are configuration errors.

`NORA_CURATION_HEX_COOLDOWN_EXEMPT_PACKAGES` accepts a comma-separated list; an
empty value clears the list. SIGHUP applies exemption additions/removals to both
cooldown checks. Removing an exemption restores enforcement for future requests,
including cached tarballs; it does not change existing digest first-seen records.

Client cooldown is independent of Nora's exemptions. To resolve a young exempt
package, use `HEX_COOLDOWN=0d`; Nora still enforces the server cooldown on every
non-exempt package. With client cooldown enabled, Hex may exclude a young exempt
version before ever requesting its tarball. An allowlist approval alone is not a
complete exemption from the independent digest quarantine.

Bootstrap Hex before configuring the mirror:

```sh
mix local.hex --force
export HEX_MIRROR=https://packages.wistia.land/hex
export HEX_COOLDOWN=7d
mix deps.get
```

Hex 2.6.0 supports client cooldown resolution. Nora independently rejects young
tarballs, including pinned/locked dependencies with client cooldown disabled.
Older clients work but may select a young version and then fail at download.
Neither signature nor origin verification needs to be disabled. Hex version
update checks can report 404: installation archives are outside this mirror.

## Trust and enforcement

Nora verifies RSA PKCS#1 v1.5 / SHA-512 signatures over the original protobuf
payloads, checks the `hexpm` repository and requested package identities, and
relays the original gzip bytes unchanged. It uses signed `published_at` and
`outer_checksum` fields; a separate Hex JSON API dependency is unnecessary.
Every tarball is checked against the signed SHA-256, including cached bytes.
A direct cold tarball request fetches verified metadata before the age decision.

The bundled trust anchor comes from Hex 2.6.0's official Hex.pm public key.
`hex.public_key_file` explicitly overrides it with an RSA SPKI PEM public key,
allowing operator-managed rotation and isolated test repositories. Nora never
learns a new trust anchor from an upstream `/public_key` response. Changing the
key causes cached records signed by the old key to fail verification.

`trust_upstream_dates = false` uses first-seen quarantine, even for old releases.
Legacy records without a publication timestamp also use first-seen quarantine.
Keep quarantine enforced, as in the example, to cover missing timestamps.
Missing/invalid outer checksums, invalid signatures and corrupt caches fail
closed. Metadata freshness uses ETag/Last-Modified revalidation; `serve_stale`
allows previously verified metadata on upstream failures. Invalid new metadata
never replaces a verified cached record. Set `serve_stale = false` to require
successful refreshes after the TTL. Signed records do not provide a separate
cryptographic freshness guarantee against replay.

Metadata responses and decompressed protobufs are limited to 64 MiB; tarballs
are limited to 100 MiB. Upstream redirects remain on the configured origin.

## Interfaces and limits

GET and HEAD: `/hex/packages/{name}`, `/hex/names`, `/hex/versions`,
`/hex/tarballs/{name}-{version}.tar`, `/hex/public_key`,
`/hex/installs/hex-1.x.csv`. Publishing/deletion,
private `/repos/{organization}`, documentation, installation archives, CLI
`mirror` and import are not supported. Internal namespace names are never sent
upstream; this feature provides no locally published Hex packages.

Environment equivalents: `NORA_HEX_ENABLED`, `NORA_HEX_PROXY`,
`NORA_HEX_PROXY_AUTH` (Basic auth for an operator-controlled upstream mirror),
`NORA_HEX_PROXY_TIMEOUT`, `NORA_HEX_METADATA_TTL`, `NORA_HEX_SERVE_STALE`,
`NORA_HEX_REVALIDATE`, `NORA_HEX_PUBLIC_KEY_FILE` and the standard
`NORA_CURATION_HEX_*` overrides. The client should retain its trusted Hex.pm key;
custom test keys must only be configured in isolated test homes.

Artifacts already in a client's cache do not pass through Nora. Use fresh client
caches when testing enforcement. See [the real Mix app smoke](../tests/hex-client/README.md).

Protocol sources: [registry v2](https://github.com/hexpm/specifications/blob/main/registry-v2.md),
[package schema](https://github.com/hexpm/specifications/blob/main/registry/package.proto),
[Hex public key](https://github.com/hexpm/hex/blob/v2.6.0/lib/hex/repo.ex).

## HTTP caching and client update checks

Successful tarball responses advertise `public, max-age=31536000, immutable`.
Signed package/listing metadata and the public key advertise
`public, max-age=60, must-revalidate`. Shared caches can serve successful downloads
without rerunning Nora policy gates until expiry; invalidate affected tarball paths
after emergency policy changes. The upstream metadata TTL remains independent of
these downstream cache lifetimes.

Hex checks for client updates at `/installs/hex-1.x.csv` beneath its mirror URL.
Nora relays that informational CSV with a 60-second cache lifetime and a 1 MiB
response limit. For the default `https://repo.hex.pm` upstream, the catalog comes
from `https://builds.hex.pm` directly, without upstream credentials; this avoids
the public repository's cross-origin redirect. Custom upstream mirrors must serve
the catalog themselves. The CSV is not signed registry metadata and is never used
to approve packages or bypass package verification or cooldown checks.

This supports the update notification, not installation archives or `mix local.hex`:
provision the Hex client separately in build images. A missing catalog produces a
nonfatal update-check warning; dependency resolution can still succeed.

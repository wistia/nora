# Wistia proxy cooldown extensions

The npm, RubyGems, Go and Hex proxy artifact gates persist digest first-seen
records in object storage when an S3 or GCS backend is selected. Each digest has
an immutable `.nora-quarantine/<registry>/<sha256>.json` object. A conditional
create chooses one timestamp across concurrent replicas; subsequent requests
always read the winner. Object writes include the normal storage integrity pin.
Unreadable or invalid records return 503 in enforce mode. Local deployments
retain the existing JSONL store; other registry formats still use that store.

Trusted upstream publication dates seed a newly created digest record. Missing
or untrusted dates start the hold at the first request. A restart or another
replica cannot reset that timestamp. Do not expire the shared record prefix with
an object lifecycle rule. Existing local JSONL ledgers are not automatically
migrated to S3; dateless artifacts begin their shared hold on first access there.

Literal npm scopes and Go module prefixes can bypass the release-age and digest
quarantine controls:

```toml
[curation.npm]
cooldown_exempt_prefixes = ["@wistia/"]

[curation.go]
cooldown_exempt_prefixes = ["github.com/wistia/"]
```

The trailing slash is required. These are literal prefixes, not globs, so
`@wistia-other/pkg` and `github.com/wistia-other/pkg` remain subject to cooldown.
Go paths are matched after decoding the module proxy's `!` uppercase encoding.
Blocklists, allowlists, integrity checks and internal namespace isolation remain
active. Exemptions reload with curation configuration; removing an exemption
restores both gates. Existing exact-name Hex exemptions are unchanged.

The object storage backend must support atomic create-if-absent writes (S3
`If-None-Match: *`). Unsupported conditional writes fail closed. Coordination
records are hidden from ordinary registry listings and garbage collection.

RubyGems also accepts exact package-name exemptions through
`[curation.gems] cooldown_exempt_packages = ["my_internal_gem"]` or
`NORA_CURATION_GEMS_COOLDOWN_EXEMPT_PACKAGES`. These are case-sensitive names,
not prefixes. See [RubyGems compact-index caching](gems-compact-cache.md) for the
shorter checksum refresh interval used for exempt gems and the shared,
checksum-keyed `/info` body cache.

## Exact-version exemptions

All four Wistia proxy ecosystems accept `cooldown_exempt_versions` under their
curation section, for example:

```toml
[curation.gems]
cooldown_exempt_versions = [{ name = "trilogy", version = "2.13.2" }]
```

Entries match exact names and versions using curation normalization, not ranges
or globs. A match skips release-age and digest quarantine only; all other
curation controls remain active. Existing package/prefix exemptions are additive.
Unknown versions cannot match. Removing an entry restores ordinary cooldown
evaluation without changing stored quarantine timestamps. RubyGems platform
builds share their resolved release version; ambiguous artifacts require every
identity to qualify. Configuration reload applies changes.

## PyPI index and denial caching

Successful anonymous PyPI project indexes use `Cache-Control: public, max-age=300, stale-while-revalidate=86400, stale-if-error=432000` and `Vary: Accept`. New versions can take five minutes to appear, and cached indexes can remain stale during an origin outage. Authenticated and private index responses are `private, no-store`; an incomplete local fallback is `no-store`.

A PyPI minimum-release-age denial with a known release date uses `public, max-age=0, s-maxage=N`, where N is the lesser of 300 seconds and the remaining cooldown. A configured bypass token disables shared caching of these denials. Other denial rules do not receive this TTL. A newly added exemption can take up to five minutes to become visible through a cached denial.

CloudFront must cache HTML and JSON separately by `Accept`, and must forward requests with `Authorization` or `X-Nora-Bypass-Token` to the origin without serving an anonymous cached response. Set the minimum TTL to zero and allow a maximum TTL long enough for the stale windows. Configure the 403 error-caching minimum TTL to zero: CloudFront otherwise uses the greater of that minimum and `s-maxage`, which can extend a denial beyond the release-age boundary. Verify these distribution settings and cache hits separately; response headers alone do not enable caching.

PyPI digest quarantine uses shared object-store records under `.nora-quarantine/pypi/` when using S3. Replicas agree on the first successful record and fail closed if shared state cannot be read or written. On migration, existing cached artifacts without a shared record are evaluated using their trusted upstream upload time when available; artifacts without a trusted date begin a new quarantine hold. Local storage continues to use the local ledger.

PyPI exact-version cooldown exemptions use `[[curation.pypi.cooldown_exempt_versions]]` entries. Project names use PEP 503 normalization and versions use PEP 440 equivalence. These entries skip release-age and digest-quarantine checks only; blocklists, integrity and namespace checks still apply. Exemptions do not grant access to private upstream artifacts.

## Maven shared quarantine migration

Maven artifacts use shared object-store quarantine records so replicas agree on
first seen. Existing cached artifacts without a shared record may receive a new
seven-day hold if no trusted upstream release date is available. Deploying this
change does not invalidate existing CloudFront artifacts: invalidate affected
Maven paths separately when policy enforcement must take effect immediately.
Warm requests use shared, digest-bound date evidence. Cached artifacts lacking
evidence may require upstream revalidation as described below; a cold Maven
Central response without a usable date header may require a Central search
lookup.

Maven exact-version cooldown exemptions use `[[curation.maven.cooldown_exempt_versions]]` entries with a case-sensitive `group.id:artifact-id` name and exact version. These entries skip release-age and digest-quarantine checks only; blocklists, integrity and namespace checks still apply. Exemptions do not grant access to private upstream artifacts.

Maven metadata XML and all checksum sidecars use `Cache-Control: no-store`, as do snapshot paths. Stable XML and checksum URLs can be fetched and revalidated independently; equal TTLs do not ensure generation consistency. Long stale windows are deferred until a generation-consistent strategy is available. Existing cached metadata and sidecars require CloudFront invalidation when this policy deploys. Release artifact caching is unchanged.

### Release-date evidence from configured Maven upstreams

With `server.trust_upstream_dates = true`, immutable release files fetched from
any explicitly configured `maven.proxies` entry can use the successful GET
response's valid `Last-Modified` header as release-date evidence. This includes
authenticated and private repositories, and public alternatives such as
Confluent. It is an explicit trust in the origin's reported modification time, not cryptographic
proof of publication time. Configure only upstreams whose dates you trust.
Explicit HTTP upstreams are supported, but HTTPS provides transport integrity.

Trust is scoped to each configured URL's scheme, host, port and repository path.
Redirects are not followed when trusting response dates; URL credentials, query
strings and fragments are not accepted as date sources. Credentials supplied in
a proxy's `auth` field still authenticate the fetch and are not saved in evidence.
Snapshot files and mutable Maven metadata do not provide this evidence. A
look-alike origin is trusted only if it is independently configured, not because
its hostname resembles another configured origin.

Nora stores successful evidence under `.nora-maven-dates/`, bound to the exact
artifact path, source URL and byte digest. Warm requests read shared evidence
instead of querying search, and the source must still be in the configured
upstream list. Each POM, JAR, checksum and Gradle `.module` file has its own
response evidence; dates are not reused for other files in the version.

Only cold responses directly from the canonical HTTPS Central release
repositories `repo.maven.apache.org/maven2` or `repo1.maven.org/maven2` may use
the public exact-GAV search API when the response has no usable date header.
Search websites are not artifact repository aliases. The lookup has a
two-second cap and verifies every returned coordinate; coordinates from other
configured upstreams are never sent to Central search. Missing, malformed or
future headers from non-Central upstreams retain the unknown-date quarantine.
Recent valid dates still enforce the minimum release age. Disabling
upstream-date trust keeps first-observation quarantine in effect.

Central search timeouts, upstream errors and malformed responses (including
valid JSON with an invalid envelope or upstream error status) return retryable
`503 Service Unavailable`, `Retry-After: 30` and `Cache-Control: no-store` when
cooldown enforcement requires a date. A shared thirty-second backoff preserves
that result without seeding a quarantine hold or publishing artifact bytes. A
successful search with no usable date retains unknown-date quarantine. Missing
shared date records also retain that policy; storage errors, corrupt records and
failed evidence readback return retryable 503 when dates are required.

A blocklist-only policy does not require date lookup success. A valid curation
bypass token removes the release-age requirement but does not bypass enforced
digest quarantine. Range requests retain partial storage reads when no
digest-bound date or integrity checks are needed, including valid curation bypass
requests when digest quarantine is off. Newly held bytes are not published to the
artifact cache before a successful quarantine decision, so later cold retries
can recover evidence. Cached unknown-date releases can recover through the
bounded revalidation described below.

## Recovering a shared Maven unknown-date hold

The explicit recoverable Maven quarantine API preserves the original shared
`first_seen` observation and tags newly created records with timestamp provenance.
Validated release evidence is stored independently under
`.nora-quarantine-release/maven/`, using conditional creation and read-back so
replicas agree without rewriting the observation. Only artifact URLs beneath a
currently configured Maven upstream, valid nonfuture dates and evidence bound
to the served SHA-256 content digest qualify. Evidence establishes the age of
those bytes, not the release date of every GAV containing them: the handler must
separately evaluate its exact artifact's release-age rule using current validated
evidence.

Recovery requires upstream-date trust to remain enabled and current evidence to
be supplied by the handler. Missing evidence keeps the original hold, disabling
trust immediately stops using recovery evidence, and unreadable or corrupt state
fails closed. Untagged records retain their existing hold. This API's recovery is
for shared object storage; the local JSONL ledger remains conservative and starts
from the local observation without accepting release-date recovery.

Existing immutable cached bytes lacking currently trusted evidence can be
re-fetched from configured upstreams to repair a hold, with a shared
thirty-second retry timestamp. This also permits replacing a removed source with
another configured source. A repair must return the same bytes; it cannot
replace a cached release. Original shared quarantine observations and legacy
untagged holds are preserved.

Once an artifact's original observation is old enough for both the quarantine
window and the active minimum-release-age threshold, missing date evidence does
not require another upstream request. A release-age-only policy with quarantine
disabled still attempts date recovery instead of relying on quarantine state.

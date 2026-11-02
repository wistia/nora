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

Maven artifacts use shared object-store quarantine records so replicas agree on first seen. Existing cached artifacts without a shared record may receive a new seven-day hold if no trusted Maven Central release date is available. Deploying this change does not invalidate existing CloudFront artifacts: invalidate affected Maven paths separately when policy enforcement must take effect immediately. Cached Maven requests now consult Maven Central for a trusted release date when applicable; this adds upstream latency and may fall back to first-seen quarantine if the date lookup fails.

Maven exact-version cooldown exemptions use `[[curation.maven.cooldown_exempt_versions]]` entries with a case-sensitive `group.id:artifact-id` name and exact version. These entries skip release-age and digest-quarantine checks only; blocklists, integrity and namespace checks still apply. Exemptions do not grant access to private upstream artifacts.

Maven metadata XML and all checksum sidecars use `Cache-Control: no-store`, as do snapshot paths. Stable XML and checksum URLs can be fetched and revalidated independently; equal TTLs do not ensure generation consistency. Long stale windows are deferred until a generation-consistent strategy is available. Existing cached metadata and sidecars require CloudFront invalidation when this policy deploys. Release artifact caching is unchanged.

### Maven Central release-date evidence

With `trust_upstream_dates=true`, immutable files fetched directly from the HTTPS release repositories `repo.maven.apache.org/maven2` or `repo1.maven.org/maven2` can use the successful GET response's `Last-Modified` as trusted upstream date evidence. This is an explicit trust in the origin's reported modification time, not cryptographic proof of publication time. Redirected, authenticated, private, snapshot, and look-alike origins do not provide this evidence. Search websites are not artifact repository aliases.

Nora stores successful evidence under `.nora-maven-dates/`, bound to the exact artifact path, source URL and byte digest. A warm artifact reads shared evidence instead of querying search. For a cold canonical Central response without a usable header, Nora uses the documented exact-GAV search API with a two-second cap and verifies every returned coordinate. A failed lookup is retried after a thirty-second shared backoff; missing dates continue to quarantine. Newly held bytes are not published to the artifact cache before a successful quarantine decision, so later cold retries can recover evidence. Starting from a clean enforced store is the supported rollout; enabling enforcement over pre-existing unknown-date cached bytes requires separate migration handling.

## Recovering a shared Maven unknown-date hold

The explicit recoverable Maven quarantine API preserves the original shared
`first_seen` observation and tags newly created records with timestamp provenance.
Validated Central release evidence is stored independently under
`.nora-quarantine-release/maven/`, using conditional creation and read-back so
replicas agree without rewriting the observation. Only canonical HTTPS Central
artifact URLs, valid nonfuture dates and evidence bound to the served SHA-256
content digest qualify. Evidence establishes the age of those bytes, not the
release date of every GAV containing them: the handler must separately evaluate
its exact artifact's release-age rule using current validated evidence.

Recovery requires upstream-date trust to remain enabled and current evidence to
be supplied by the handler. Missing evidence keeps the original hold, disabling
trust immediately stops using recovery evidence, and unreadable or corrupt state
fails closed. Untagged records retain their existing hold. This API's recovery is
for shared object storage; the local JSONL ledger remains conservative and starts
from the local observation without accepting release-date recovery.

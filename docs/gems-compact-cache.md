# RubyGems compact-index caching

Successful `/info/<gem>` responses advertise `Cache-Control: public, max-age=86400`
by default. Exact-name cooldown-exempt gems use `public, max-age=60` (capped by
the normal lifetime). This downstream policy applies to fresh fetches, memory and
shared-storage hits, legacy metadata, and offline copies. Stale fallbacks and
errors do not receive the long lifetime; explicit upstream `private`, `no-store`
or `no-cache` directives remain respected. `/versions` retains upstream headers.

HTTP lifetime is separate from memory retention and checksum refresh intervals.
A CDN or client can retain an ordinary gem's metadata for a day, including an old
view of yanks or corrections. Adding an exemption affects new origin responses;
already cached responses expire at their original TTL unless invalidated.

## Freshness and replicas

The last record for a gem in `/versions` gives the MD5 change identifier of its
current `/info` document. Nora periodically refreshes a complete checksum map on
demand, using the existing conditional upstream request and shared S3 cache.
A monthly `/versions` rewrite replaces the map, including removed names.

Each replica keeps its own map. Normal gems check its freshness against
`gems.metadata_ttl` (300 seconds by default). Exact-name cooldown-exempt gems use
the shorter of that interval and `gems.exempt_metadata_ttl` (60 seconds). When
exemptions are configured, the `/versions` endpoint also uses that shorter
interval so clients can discover exempt releases promptly. Refreshes are on
request, not background polling.

Bodies and their upstream Cache-Control are stored together at
`.nora-gems-info/<gem>/<checksum>` in shared storage. These internal keys are
hidden from package listings. A new checksum selects a new object; there is no
cross-replica deletion or mutable per-gem freshness pointer. An old replica can
serve its old snapshot within its refresh window without overwriting the newer
body. Concurrent fills on one replica are coalesced. Different replicas may
fetch the same body concurrently, which is safe; no distributed lock is needed.

Nora checks a downloaded or shared body against its expected checksum before
using it. A mismatch (for example while upstream CDN nodes disagree during a
publish) forces an upstream `/versions` revalidation even if the shared S3 index
is still fresh, then retries the `/info` lookup once. Concurrent requests reuse
a snapshot that another request has already recovered. Successful forced checks
are reused for five seconds even when they return 304 with the same checksum,
so a concurrent publishing-race failure cannot force one index check per caller.
A persistent mismatch returns an uncacheable 502 and never publishes the mismatched body under the
expected checksum. MD5 is the protocol's change identifier, not a
security guarantee; existing storage integrity and artifact curation gates
remain in force.

A replica's hot body cache is bounded to 64 MiB and 4,096 entries, with a default
one-day residence time. A matching hot entry requires no per-gem S3 operations.
On a local miss, another replica's shared object can be reused. Existing
`gems/info/<gem>` bodies migrate without an upstream fetch if their bytes match
the current checksum. Shared immutable objects survive process restarts; the
one-day setting expires memory entries, not S3 objects. Old checksum objects are
not proactively deleted by this implementation; configure an S3 lifecycle rule
for the internal prefix if storage retention needs a bound. Active objects can
always be reconstructed from upstream after expiration.

Records with missing or unsupported checksums disable checksum caching only
for their own gem; an unusable latest record clears any older checksum for that
gem. The rest of the index remains usable. If the whole index cannot be used,
Nora backs off refresh attempts for five seconds instead of rereading and
parsing it for every `/info` request.

## UI and filename-identity readers

The UI and ambiguous-filename checks select the same checksum-keyed documents
as `/info`, using a shared cache-only resolver. No background mutable alias
writer or alias-repair workers remain for checksum-managed metadata. An older
replica may retain its own bounded-age checksum snapshot, but writing an old `gems/info/<gem>` alias cannot
roll back a newer replica's UI or identity metadata.

Cached readers share the published snapshot and hot document cache. A cold
reader can load `/versions` from shared storage; concurrent cache-only readers
share that load and parse for the configured refresh interval per replica. It does not fetch upstream `/versions` or `/info`.
With metadata caching disabled (`metadata_ttl=0`), read-only consumers reuse their
observed shared snapshot for five seconds to avoid repeatedly parsing the whole
index. Failed shared-index reads also back off for five seconds. An upstream
HTTP refresh never holds the published-snapshot lock during network I/O, so
cache-only consumers can keep using their view while it is in progress.

Version/platform summaries are parsed once per hot document. Identity lookups
deduplicate candidate package names and limit concurrent storage lookups to four.
A known checksum with no usable body never falls back to a mismatching alias;
missing or stale managed identity data keeps every possible filename identity
subject to policy. The UI still merges cached `.gem` versions through its
existing single storage listing. Internal namespaces, disabled checksum caching,
and gems without a usable checksum retain their legacy local metadata path.
Offline registries prefer explicit local metadata; if it is absent, cached
checksum documents remain available without upstream access.

Transient `/info` failures can serve a previously validated hot document. After
restart, a last-resort fallback examines at most 16 stored checksum objects with
at most four concurrent reads and validates their content checksums. Concurrent
fallbacks coalesce that scan, retain only the best candidate, and warm the hot
cache for later stale responses. These
history reads happen only on the failure path. Mutable legacy bodies remain a
compatibility fallback, but no managed reader uses them in place of a known
checksum. Stale responses are never stored under the new checksum key.

If `/versions` cannot be used, or it has no usable entry for a gem, Nora retains
its previous `/info` TTL/ETag/Last-Modified behavior. Transient `/info` fetch
failures also honor `serve_stale=true` when an old validated or legacy body is available,
even if its checksum differs from the current snapshot. Such responses carry
`X-Nora-Stale: true` and `Cache-Control: public, max-age=0, must-revalidate`;
they are never stored under the new checksum. Checksum mismatches are not
treated as transient fetch failures. Internal namespace gems and offline-only registries continue to use their local copies,
without consulting upstream `/versions`. Namespace and curation checks run
before the hot cache is consulted. Validated upstream fills retain the existing
proxy-fetch audit/activity events; hot, shared and migrated hits emit cache-hit
activity events.

## Configuration

```toml
[gems]
info_checksum_cache = true # default; false restores the previous /info path
metadata_ttl = 300
exempt_metadata_ttl = 60
info_cache_ttl = 86400 # memory residence, not metadata freshness or HTTP max-age
info_http_max_age = 86400 # downstream /info lifetime, seconds
exempt_info_http_max_age = 60 # capped by info_http_max_age

[curation.gems]
cooldown_exempt_packages = ["my_internal_gem"]
```

RubyGems exemptions are exact, case-sensitive package names, not prefixes or
globs. They bypass release-age and digest-quarantine cooldowns for both `.gem`
and `.gemspec.rz` downloads, on cached and upstream paths. Blocklists,
allowlists, namespace isolation and integrity checks still apply. Ambiguous gem
filenames must have every possible identity exempt before digest quarantine is
skipped. Existing registry-wide `[curation.gems] min_release_age` overrides also
remain supported.

Environment equivalents:

- `NORA_GEMS_INFO_CHECKSUM_CACHE`
- `NORA_GEMS_METADATA_TTL`
- `NORA_GEMS_EXEMPT_METADATA_TTL`
- `NORA_GEMS_INFO_CACHE_TTL`
- `NORA_GEMS_INFO_HTTP_MAX_AGE`
- `NORA_GEMS_EXEMPT_INFO_HTTP_MAX_AGE`
- `NORA_CURATION_GEMS_COOLDOWN_EXEMPT_PACKAGES` (comma-separated exact names)

HTTP max-age settings accept nonnegative seconds; zero requires revalidation.
For server-side TTL settings, existing duration semantics apply: zero means immediately stale; `-1` disables
expiry. Shorter exempt refresh settings do not lengthen an explicitly shorter
normal TTL. Curation exemptions are read from the hot-reloaded engine, so SIGHUP
changes take effect without clearing any body objects.

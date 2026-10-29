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

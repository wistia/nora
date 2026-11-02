Maven cooldowns now trust valid artifact `Last-Modified` dates from every
explicitly configured proxy when `server.trust_upstream_dates` is enabled,
including Confluent and authenticated repositories. Evidence remains bound to
the configured origin, repository path and exact bytes. Missing dates retain
quarantine, recent releases retain their cooldown, and only Central uses the
public search fallback. Existing cached unknown-date holds can recover after
revalidating identical bytes against a configured upstream.

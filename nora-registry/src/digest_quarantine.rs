// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Digest quarantine — first-seen tracking for proxy-fetched artifacts.
//!
//! Tracks when a content digest was first seen by NORA's proxy layer.
//! New digests can be held in quarantine for a configurable duration,
//! providing a time-based supply chain defense for registries that lack
//! upstream publish dates (e.g. Docker/OCI).
//!
//! Persistence: append-only JSONL file, compacted on startup via atomic rewrite.
//! Fail-open: corrupt or missing JSONL → empty store, all pulls pass.

use crate::log_redact::RecordedUrl;
use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use axum::http::{header, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

/// Stale entry TTL: entries older than 90 days are pruned on startup.
const PRUNE_TTL_SECS: i64 = 90 * 24 * 3600;

// ============================================================================
// Quarantine Mode
// ============================================================================

/// Quarantine operating mode.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineMode {
    /// Quarantine disabled (default).
    #[default]
    Off,
    /// Record + log, but don't block downloads.
    Observe,
    /// Block downloads for unknown/pending digests.
    Enforce,
}

impl std::fmt::Display for QuarantineMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Observe => write!(f, "observe"),
            Self::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for QuarantineMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "unknown quarantine mode {:?} — valid values: off, observe, enforce",
                other
            )),
        }
    }
}

// ============================================================================
// Digest Entry
// ============================================================================

/// A single quarantine record persisted in JSONL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    /// Registry type (e.g. "docker").
    pub registry: String,
    /// Content digest (e.g. "sha256:abc123...").
    pub digest: String,
    /// Unix timestamp (seconds) when first seen by NORA.
    pub first_seen: i64,
    /// Upstream that provided the content (e.g. "registry-1.docker.io"), any userinfo in its
    /// URL masked as in the log, by its type.
    pub upstream: RecordedUrl,
}

// ============================================================================
// Quarantine Status
// ============================================================================

/// Result of checking a digest against the quarantine store.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineStatus {
    /// Digest not seen before — just recorded.
    New,
    /// Digest known but still within quarantine window.
    Pending { remaining_secs: i64 },
    /// Digest has aged past the quarantine threshold.
    Mature,
}

impl QuarantineStatus {
    /// Value for the `X-Nora-Quarantine` response header.
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Pending { .. } => "pending",
            Self::Mature => "mature",
        }
    }
}

// ============================================================================
// Digest Store
// ============================================================================

/// In-memory digest store backed by an append-only JSONL file.
///
/// Thread-safe via `parking_lot::RwLock`. Reads (check) take a shared lock,
/// writes (record) take an exclusive lock with double-check pattern.
pub struct DigestStore {
    entries: RwLock<HashMap<String, DigestEntry>>,
    path: PathBuf,
}

impl DigestStore {
    /// Load existing entries from JSONL, prune stale (>90d), compact file.
    ///
    /// Fail-open: corrupt lines are skipped, missing file → empty store.
    pub fn load(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("quarantine.jsonl");
        let mut entries = HashMap::new();

        if path.exists() {
            match File::open(&path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let now = Utc::now().timestamp();
                    let cutoff = now - PRUNE_TTL_SECS;
                    let mut skipped = 0u32;

                    for line in reader.lines() {
                        let line = match line {
                            Ok(l) => l,
                            Err(e) => {
                                warn!(error = %e, "Skipping unreadable quarantine line");
                                skipped += 1;
                                continue;
                            }
                        };
                        if line.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<DigestEntry>(&line) {
                            // A line written before the credential was masked is read masked,
                            // and loses it in the rewrite below.
                            Ok(entry) => {
                                if entry.first_seen >= cutoff {
                                    let key = format!("{}:{}", entry.registry, entry.digest);
                                    entries.entry(key).or_insert(entry);
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Skipping unparsable quarantine entry");
                                skipped += 1;
                            }
                        }
                    }

                    info!(
                        path = %path.display(),
                        entries = entries.len(),
                        skipped = skipped,
                        "Quarantine store loaded"
                    );
                }
                Err(e) => {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "Failed to open quarantine file, starting empty (fail-open)"
                    );
                }
            }

            // Compact: atomic rewrite removes duplicates and pruned entries
            atomic_rewrite(&path, &entries);
        }

        Self {
            entries: RwLock::new(entries),
            path,
        }
    }

    /// Create an empty store (for tests or when quarantine is off).
    pub fn empty(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("quarantine.jsonl");
        Self {
            entries: RwLock::new(HashMap::new()),
            path,
        }
    }

    /// Record a proxy-fetched digest. Returns the entry (existing or new).
    ///
    /// Idempotent: if the digest already exists, the original entry is returned.
    /// New entries are appended to JSONL asynchronously.
    /// `first_seen` overrides the recorded first-seen timestamp with a trusted
    /// upstream release date (only when `server.trust_upstream_dates` is set and
    /// the registry caches one, #750); `None` uses NORA's own clock — the
    /// unspoofable default. SECURITY: a trusted date is upstream-supplied and
    /// spoofable, so it is opt-in via `trust_upstream_dates`.
    pub fn record(
        &self,
        registry: &str,
        digest: &str,
        upstream: &str,
        first_seen: Option<i64>,
    ) -> DigestEntry {
        let key = format!("{}:{}", registry, digest);

        // Fast path: read lock
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&key) {
                return entry.clone();
            }
        }

        // Slow path: write lock
        let mut entries = self.entries.write();
        // Double-check after acquiring write lock
        if let Some(entry) = entries.get(&key) {
            return entry.clone();
        }

        let entry = DigestEntry {
            registry: registry.to_string(),
            digest: digest.to_string(),
            first_seen: first_seen.unwrap_or_else(|| Utc::now().timestamp()),
            upstream: RecordedUrl::new(upstream),
        };

        entries.insert(key, entry.clone());
        append_jsonl(&self.path, &entry);
        entry
    }

    // NOTE: the ledger records PROXY-fetched content only. Locally-pushed artifacts
    // are intentionally NOT recorded — the cooldown is a control on content arriving
    // from upstream, and the serve gate treats an unrecorded digest (`New`) as "serve".
    // A prior `record_trusted` matured local pushes here; it was removed because it
    // wrote the same key the proxy `check` reads, letting a local push set the
    // first-seen clock for a digest later fetched from upstream.

    /// Check quarantine status for a digest.
    #[must_use = "ignoring quarantine status may serve blocked artifacts"]
    pub fn check(&self, registry: &str, digest: &str, quarantine_secs: i64) -> QuarantineStatus {
        let key = format!("{}:{}", registry, digest);
        let entries = self.entries.read();

        match entries.get(&key) {
            None => QuarantineStatus::New,
            Some(entry) => {
                let age = Utc::now().timestamp() - entry.first_seen;
                if age >= quarantine_secs {
                    QuarantineStatus::Mature
                } else {
                    QuarantineStatus::Pending {
                        remaining_secs: quarantine_secs - age,
                    }
                }
            }
        }
    }

    /// Number of tracked digests.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

// ============================================================================
// Generic proxy quarantine gate
// ============================================================================
//
// Registry-agnostic generalization of the digest-quarantine wiring that
// previously lived only in the Docker handler. min-release-age cannot give a
// trustworthy release age on the proxy path (upstream dates are unsigned and
// spoofable, and several registries expose no date at all), so first-seen
// quarantine — keyed on the artifact's content digest and NORA's own clock — is
// the unspoofable supply-chain control that works for every proxy registry.

/// Resolve the effective quarantine `(mode, ttl_secs)` from the global curation
/// config. Returns `(Off, 0)` when disabled. Per-registry overrides can be
/// layered on top later; the proxy gate uses the global setting for now.
pub fn resolve_global(mode: Option<&QuarantineMode>, ttl: Option<&str>) -> (QuarantineMode, i64) {
    let mode = mode.cloned().unwrap_or(QuarantineMode::Off);
    if matches!(mode, QuarantineMode::Off) {
        return (QuarantineMode::Off, 0);
    }
    // Config validation refuses a TTL that does not parse (#1099); the default only
    // covers a config built without it.
    let secs = crate::curation::parse_duration(ttl.unwrap_or("14d")).unwrap_or(14 * 86400);
    (mode, secs)
}

/// Post-fetch / pre-serve quarantine gate for a proxy-fetched artifact.
///
/// Records the artifact's content digest as first-seen, then checks maturity.
/// Returns `Some(403)` to BLOCK (enforce mode, not yet mature), `None` to serve.
/// In observe mode it logs but never blocks. Idempotent: `record` preserves the
/// earliest `first_seen`, so calling this on every request (proxy fetch or cache
/// hit) is safe and the quarantine clock does not reset.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate(
    store: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
) -> Option<Response> {
    proxy_gate_dated(
        store,
        registry,
        bytes,
        mode,
        quarantine_secs,
        upstream,
        None,
    )
}

/// The first-seen a proxy handler gives [`proxy_gate_dated`]: its release date, only when upstream
/// dates are trusted (#750). Without trust a handler's date is NORA's cache-age of a metadata file —
/// when NORA last wrote a listing, not when it first fetched these bytes — and taken as first-seen
/// it would let a file fetched now pass as mature, so the quarantine keeps its own clock.
pub fn first_seen_seed(trust_upstream_dates: bool, release_date: Option<i64>) -> Option<i64> {
    release_date.filter(|_| trust_upstream_dates)
}

/// Like [`proxy_gate`], but seeds the first-seen clock from a trusted upstream
/// release date (#750). When `trusted_first_seen` is `Some` — only when
/// `server.trust_upstream_dates` is set and the registry caches a date — an
/// artifact whose release date is already older than the TTL matures
/// immediately, so a provably-old package is not held as "new to this mirror".
/// `None` falls back to NORA's own clock (the unspoofable default).
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate_dated(
    store: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
    trusted_first_seen: Option<i64>,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    store.record(registry, &digest, upstream, trusted_first_seen);
    let status = store.check(registry, &digest, quarantine_secs);
    if matches!(status, QuarantineStatus::Mature) {
        return None;
    }
    // Operator-facing signal: previously a held artifact was visible only in this
    // WARN line. The metric lets the operator alert/graph on it, and the log + the
    // 403 now name the responsible policy (registry + quarantine_ttl + remaining).
    let outcome = if matches!(mode, QuarantineMode::Enforce) {
        "blocked"
    } else {
        "observed"
    };
    crate::metrics::QUARANTINE_HOLDS_TOTAL
        .with_label_values(&[registry, outcome])
        .inc();
    warn!(
        registry = %registry,
        digest = %digest,
        status = %status.header_value(),
        mode = %mode,
        quarantine_ttl_secs = quarantine_secs,
        "quarantine: proxy artifact held by registry policy"
    );
    if matches!(mode, QuarantineMode::Enforce) {
        Some(quarantine_forbidden(
            registry,
            &digest,
            &status,
            quarantine_secs,
        ))
    } else {
        None
    }
}

/// Use one immutable object per digest for cross-replica first-seen state.
/// A conditional PUT chooses the first writer; all replicas read the winner.
/// Storage errors or malformed records fail closed in enforce mode. Local storage
/// keeps the existing JSONL implementation for single-process installations.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_gate_shared(
    storage: &crate::Storage,
    local: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
    trusted_first_seen: Option<i64>,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    if storage.backend_name() == "local" {
        return proxy_gate_dated(
            local,
            registry,
            bytes,
            mode,
            quarantine_secs,
            upstream,
            trusted_first_seen,
        );
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    let key = format!(
        ".nora-quarantine/{registry}/{}.json",
        digest.trim_start_matches("sha256:")
    );
    let now = Utc::now().timestamp();
    let result = async {
        let data = match storage.get(&key).await {
            Ok(data) => data,
            Err(crate::storage::StorageError::NotFound) => {
                let entry = DigestEntry {
                    registry: registry.to_owned(),
                    digest: digest.clone(),
                    first_seen: trusted_first_seen.unwrap_or(now),
                    upstream: RecordedUrl::new(upstream),
                };
                let data = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
                storage
                    .create_internal(&key, &data)
                    .await
                    .map_err(|e| e.to_string())?;
                // Always read back, including when this replica lost a concurrent create.
                storage.get(&key).await.map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };
        let entry: DigestEntry = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
        if entry.registry != registry || entry.digest != digest || entry.first_seen < 0 {
            return Err("quarantine record does not match its key".to_owned());
        }
        Ok(entry)
    }
    .await;
    let entry = match result {
        Ok(entry) => entry,
        Err(error) => {
            tracing::error!(%registry, %digest, %error, "shared quarantine unavailable");
            return matches!(mode, QuarantineMode::Enforce).then(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Shared quarantine state unavailable",
                )
                    .into_response()
            });
        }
    };
    let remaining_secs = quarantine_secs.saturating_sub(now.saturating_sub(entry.first_seen));
    if remaining_secs <= 0 {
        return None;
    }
    let outcome = if matches!(mode, QuarantineMode::Enforce) {
        "blocked"
    } else {
        "observed"
    };
    crate::metrics::QUARANTINE_HOLDS_TOTAL
        .with_label_values(&[registry, outcome])
        .inc();
    warn!(%registry, %digest, remaining_secs, %mode, "quarantine: proxy artifact held by shared policy");
    matches!(mode, QuarantineMode::Enforce).then(|| {
        quarantine_forbidden(
            registry,
            &digest,
            &QuarantineStatus::Pending { remaining_secs },
            quarantine_secs,
        )
    })
}

/// Release evidence is accepted only for bytes retrieved from a canonical Central
/// artifact URL. The caller must additionally enable `trust_upstream_dates` and
/// establish that the timestamp belongs to that response (or verified digest cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TrustedReleaseEvidence {
    published_at: i64,
    artifact_url: String,
    digest: String,
}

impl TrustedReleaseEvidence {
    pub(crate) fn maven_central(
        published_at: i64,
        artifact_url: &str,
        bytes: &[u8],
    ) -> Option<Self> {
        use sha2::Digest;
        let url = reqwest::Url::parse(artifact_url).ok()?;
        if published_at <= 0
            || published_at > Utc::now().timestamp()
            || url.scheme() != "https"
            || !matches!(
                url.host_str(),
                Some("repo.maven.apache.org" | "repo1.maven.org")
            )
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let artifact = url.path().strip_prefix("/maven2/")?;
        if artifact.split('/').count() < 4
            || artifact
                .split('/')
                .any(|part| part.ends_with("-SNAPSHOT") || part.starts_with("maven-metadata.xml"))
            || artifact.ends_with('/')
            || artifact.contains('%')
            || crate::validation::validate_storage_key(artifact).is_err()
        {
            return None;
        }
        Some(Self {
            published_at,
            artifact_url: url.to_string(),
            digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes))),
        })
    }

    fn matches_bytes(&self, bytes: &[u8]) -> bool {
        Self::maven_central(self.published_at, &self.artifact_url, bytes)
            .is_some_and(|validated| validated.digest == self.digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SharedTimestampOrigin {
    FallbackObservation,
    TrustedRelease,
}

#[derive(Serialize, Deserialize)]
struct RecoverableDigestEntry {
    #[serde(flatten)]
    entry: DigestEntry,
    #[serde(default)]
    timestamp_origin: Option<SharedTimestampOrigin>,
}

/// Maven-only shared quarantine with explicit trusted-date recovery. The original
/// observation is immutable; independently immutable release evidence supplies the
/// eligibility date only while upstream-date trust is enabled. Legacy records and
/// local JSONL ledgers retain their conservative behavior.
#[allow(clippy::too_many_arguments)]
#[must_use = "the returned response blocks a quarantined artifact"]
pub(crate) async fn proxy_gate_shared_recoverable(
    storage: &crate::Storage,
    local: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
    trust_upstream_dates: bool,
    trusted_release: Option<&TrustedReleaseEvidence>,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    let evidence = trusted_release.filter(|_| trust_upstream_dates);
    if registry != "maven" || evidence.is_some_and(|e| !e.matches_bytes(bytes)) {
        return matches!(mode, QuarantineMode::Enforce).then(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Invalid trusted release evidence",
            )
                .into_response()
        });
    }
    if storage.backend_name() == "local" {
        return proxy_gate_dated(
            local,
            registry,
            bytes,
            mode,
            quarantine_secs,
            upstream,
            // The legacy local ledger has no reversible provenance/evidence record.
            // Keep this new API conservative rather than permanently seeding it.
            None,
        );
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    let key = format!(
        ".nora-quarantine/{registry}/{}.json",
        digest.trim_start_matches("sha256:")
    );
    let evidence_key = format!(
        ".nora-quarantine-release/{registry}/{}.json",
        digest.trim_start_matches("sha256:")
    );
    let now = Utc::now().timestamp();
    let result: Result<i64, String> = async {
        let record = match storage.get(&key).await {
            Ok(data) => data,
            Err(crate::storage::StorageError::NotFound) => {
                let entry = RecoverableDigestEntry {
                    entry: DigestEntry { registry: registry.to_owned(), digest: digest.clone(), first_seen: now, upstream: RecordedUrl::new(upstream) },
                    timestamp_origin: Some(if evidence.is_some() { SharedTimestampOrigin::TrustedRelease } else { SharedTimestampOrigin::FallbackObservation }),
                };
                let data = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
                storage.create_internal(&key, &data).await.map_err(|e| e.to_string())?;
                storage.get(&key).await.map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };
        let record: RecoverableDigestEntry = serde_json::from_slice(&record).map_err(|e| e.to_string())?;
        if record.entry.registry != registry || record.entry.digest != digest || record.entry.first_seen < 0 {
            return Err("quarantine record does not match its key or clock".to_owned());
        }
        let first_seen = record.entry.first_seen;
        if record.timestamp_origin.is_none() {
            warn!(%registry, %digest, "legacy quarantine record has no release-date provenance; retaining original hold");
            return Ok(first_seen);
        }
        // The handler must know the current release date too, so its independent
        // min-release-age filter can evaluate stricter thresholds before this gate.
        if !trust_upstream_dates || evidence.is_none() {
            return Ok(first_seen);
        }
        let saved = match storage.get(&evidence_key).await {
            Ok(data) => Some(data),
            Err(crate::storage::StorageError::NotFound) => match evidence {
                Some(evidence) => {
                    let data = serde_json::to_vec(evidence).map_err(|e| e.to_string())?;
                    let created = storage.create_internal(&evidence_key, &data).await.map_err(|e| e.to_string())?;
                    if created {
                        info!(%registry, %digest, observed_first_seen = first_seen,
                            trusted_release_date = evidence.published_at,
                            source = %evidence.artifact_url,
                            "shared quarantine trusted release evidence recorded; original observation preserved");
                    }
                    Some(storage.get(&evidence_key).await.map_err(|e| e.to_string())?)
                }
                None => None,
            },
            Err(e) => return Err(e.to_string()),
        };
        let Some(saved) = saved else { return Ok(first_seen); };
        let saved: TrustedReleaseEvidence = serde_json::from_slice(&saved).map_err(|e| e.to_string())?;
        if !saved.matches_bytes(bytes) {
            return Err("trusted release evidence does not match artifact bytes or source".to_owned());
        }
        Ok(first_seen.min(saved.published_at))
    }.await;
    let first_seen = match result {
        Ok(first_seen) => first_seen,
        Err(error) => {
            tracing::error!(%registry, %digest, %error, "shared recoverable quarantine unavailable");
            return matches!(mode, QuarantineMode::Enforce).then(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Shared quarantine state unavailable",
                )
                    .into_response()
            });
        }
    };
    let remaining_secs = quarantine_secs.saturating_sub(now.saturating_sub(first_seen));
    if remaining_secs <= 0 {
        return None;
    }
    crate::metrics::QUARANTINE_HOLDS_TOTAL
        .with_label_values(&[
            registry,
            if matches!(mode, QuarantineMode::Enforce) {
                "blocked"
            } else {
                "observed"
            },
        ])
        .inc();
    matches!(mode, QuarantineMode::Enforce).then(|| {
        quarantine_forbidden(
            registry,
            &digest,
            &QuarantineStatus::Pending { remaining_secs },
            quarantine_secs,
        )
    })
}

/// Build a generic 403 for a quarantined proxy artifact (non-Docker shape).
///
/// Names the responsible policy (`registry` + `quarantine_ttl_secs` + how much
/// longer the hold lasts) so the client — and an operator reading the body — can
/// tell WHY it was held, not just that it was.
fn quarantine_forbidden(
    registry: &str,
    digest: &str,
    status: &QuarantineStatus,
    quarantine_secs: i64,
) -> Response {
    let remaining = match status {
        QuarantineStatus::New => quarantine_secs,
        QuarantineStatus::Pending { remaining_secs } => *remaining_secs,
        QuarantineStatus::Mature => 0,
    };
    let quarantine_until = Utc::now().timestamp() + remaining;
    let body = serde_json::json!({
        "error": "quarantine",
        "message": format!(
            "held by quarantine policy on registry '{}': artifact must age past the quarantine window before it is served",
            registry
        ),
        "detail": {
            "registry": registry,
            "digest": digest,
            "policy": {
                "control": "quarantine",
                "quarantine_ttl_secs": quarantine_secs,
            },
            "quarantine_until": quarantine_until,
            "remaining_secs": remaining,
        }
    });
    (
        StatusCode::FORBIDDEN,
        [
            (
                HeaderName::from_static("x-nora-quarantine"),
                status.header_value(),
            ),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
}

// ============================================================================
// JSONL I/O helpers
// ============================================================================

/// Append a single entry to the JSONL file (async via spawn_blocking).
fn append_jsonl(path: &Path, entry: &DigestEntry) {
    let path = path.to_path_buf();
    let json = match serde_json::to_string(entry) {
        Ok(j) => j,
        Err(_) => return,
    };

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    tokio::task::spawn_blocking(move || {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", json);
                let _ = file.flush();
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    error = %e,
                    "Failed to append quarantine entry (fail-open)"
                );
            }
        }
    });
}

/// Rewrite JSONL atomically: write temp file → fsync → rename.
///
/// Crash-safe: partial write leaves the old file intact.
fn atomic_rewrite(path: &Path, entries: &HashMap<String, DigestEntry>) {
    if entries.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }

    let tmp_path = path.with_extension("jsonl.tmp");

    match File::create(&tmp_path) {
        Ok(mut file) => {
            for entry in entries.values() {
                if let Ok(json) = serde_json::to_string(entry) {
                    let _ = writeln!(file, "{}", json);
                }
            }
            if file.flush().is_ok() && file.sync_all().is_ok() {
                if let Err(e) = fs::rename(&tmp_path, path) {
                    error!(error = %e, "Failed to rename quarantine temp file");
                    let _ = fs::remove_file(&tmp_path);
                }
            } else {
                let _ = fs::remove_file(&tmp_path);
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to create quarantine temp file");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_quarantine_mode_from_str() {
        assert_eq!(
            "off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
        assert_eq!(
            "observe".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "enforce".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        // Case insensitive
        assert_eq!(
            "OBSERVE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "ENFORCE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        assert_eq!(
            "Off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
    }

    #[test]
    fn test_quarantine_mode_rejects_invalid() {
        assert!("anything".parse::<QuarantineMode>().is_err());
        assert!("eforce".parse::<QuarantineMode>().is_err());
        assert!("enabled".parse::<QuarantineMode>().is_err());
        assert!("on".parse::<QuarantineMode>().is_err());
        assert!("".parse::<QuarantineMode>().is_err());
        // Error message includes valid values
        let err = "typo".parse::<QuarantineMode>().unwrap_err();
        assert!(err.contains("off"), "error should list valid values: {err}");
        assert!(
            err.contains("observe"),
            "error should list valid values: {err}"
        );
        assert!(
            err.contains("enforce"),
            "error should list valid values: {err}"
        );
    }

    #[test]
    fn test_quarantine_mode_display_roundtrip() {
        for mode in [
            QuarantineMode::Off,
            QuarantineMode::Observe,
            QuarantineMode::Enforce,
        ] {
            let s = mode.to_string();
            let parsed: QuarantineMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_quarantine_mode_default_is_off() {
        assert_eq!(QuarantineMode::default(), QuarantineMode::Off);
    }

    #[test]
    fn test_check_unknown_digest_is_new() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let status = store.check("docker", "sha256:abc123", 86400);
        assert_eq!(status, QuarantineStatus::New);
    }

    #[tokio::test]
    async fn test_record_then_check_pending() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc123", "registry-1.docker.io", None);

        let status = store.check("docker", "sha256:abc123", 86400);
        match status {
            QuarantineStatus::Pending { remaining_secs } => {
                assert!(remaining_secs > 0);
                assert!(remaining_secs <= 86400);
            }
            other => panic!("Expected Pending, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_then_check_mature_zero_ttl() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc123", "registry-1.docker.io", None);

        // TTL=0 → immediately mature
        let status = store.check("docker", "sha256:abc123", 0);
        assert_eq!(status, QuarantineStatus::Mature);
    }

    #[tokio::test]
    async fn test_unrecorded_digest_is_new() {
        // The ledger tracks proxy-fetched content only. A digest that was never
        // proxy-recorded (e.g. a locally-pushed artifact, which is deliberately not
        // recorded) reads as `New`. The cache-serve gate treats `New` as "serve" and
        // blocks only `Pending`, so a local push is served and can never set the
        // first-seen clock for — or mature — a digest on the proxy path.
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let status = store.check("docker", "sha256:never_seen", 86400);
        assert_eq!(status, QuarantineStatus::New);
    }

    #[tokio::test]
    async fn test_record_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let entry1 = store.record("docker", "sha256:abc", "upstream1", None);
        let entry2 = store.record("docker", "sha256:abc", "upstream2", None);

        assert_eq!(entry1.first_seen, entry2.first_seen);
        assert_eq!(entry1.upstream, entry2.upstream);
        assert_eq!(store.len(), 1);
    }

    /// An upstream configured with a credential is written down without it, in memory and in
    /// the ledger file; the rest of its URL is kept.
    #[tokio::test]
    async fn the_ledger_names_an_upstream_without_its_credential() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());
        let entry = store.record(
            "npm",
            "sha256:abc",
            "https://ci-user:s3cret@npm.example/pkg/-/pkg-1.0.0.tgz?x=1",
            None,
        );
        let named = "https://***@npm.example/pkg/-/pkg-1.0.0.tgz?x=1";
        assert_eq!(entry.upstream.as_str(), named);
        let ledger = tmp.path().join("quarantine.jsonl");
        let mut written = String::new();
        for _ in 0..100 {
            written = std::fs::read_to_string(&ledger).unwrap_or_default();
            if !written.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(written.contains(named), "{written}");
        assert!(
            !written.contains("s3cret") && !written.contains("ci-user"),
            "{written}"
        );
        let reloaded = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(reloaded.len(), 1);
    }

    /// A ledger written before the credential was masked loses it on the next start: loading
    /// rewrites the file.
    #[test]
    fn a_credential_already_in_the_ledger_is_masked_on_load() {
        let tmp = TempDir::new().unwrap();
        let ledger = tmp.path().join("quarantine.jsonl");
        let line = serde_json::json!({
            "registry": "npm", "digest": "sha256:abc", "first_seen": Utc::now().timestamp(),
            "upstream": "https://ci-user:s3cret@npm.example/pkg/-/pkg-1.0.0.tgz",
        });
        std::fs::write(&ledger, format!("{line}\n")).unwrap();
        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);
        let written = std::fs::read_to_string(&ledger).unwrap();
        assert!(
            written.contains("https://***@npm.example/pkg/-/pkg-1.0.0.tgz"),
            "{written}"
        );
        assert!(
            !written.contains("s3cret") && !written.contains("ci-user"),
            "{written}"
        );
    }

    #[tokio::test]
    async fn test_registry_isolation() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc", "docker-upstream", None);
        store.record("npm", "sha256:abc", "npmjs.org", None);

        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn test_trusted_first_seen_matures_old_release() {
        // #750: when a trusted upstream release date is supplied, the artifact's
        // first_seen is that date — so a package released long ago is immediately
        // Mature (served), not held as "new to this mirror".
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());
        let two_years_ago = Utc::now().timestamp() - 2 * 365 * 86400;

        store.record(
            "pypi",
            "sha256:old",
            "files.pythonhosted.org",
            Some(two_years_ago),
        );
        // 14-day TTL: a 2-year-old release is well past it.
        assert_eq!(
            store.check("pypi", "sha256:old", 14 * 86400),
            QuarantineStatus::Mature
        );

        // A freshly-released artifact (date = now) is still held.
        store.record(
            "pypi",
            "sha256:fresh",
            "files.pythonhosted.org",
            Some(Utc::now().timestamp()),
        );
        assert!(matches!(
            store.check("pypi", "sha256:fresh", 14 * 86400),
            QuarantineStatus::Pending { .. }
        ));

        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let jsonl_path = tmp.path().join("quarantine.jsonl");

        // Write JSONL directly (bypass async spawn_blocking in record())
        let now = Utc::now().timestamp();
        let entries = [
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:aaa".into(),
                first_seen: now,
                upstream: "upstream1".into(),
            },
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:bbb".into(),
                first_seen: now,
                upstream: "upstream2".into(),
            },
        ];
        {
            let mut file = std::fs::File::create(&jsonl_path).unwrap();
            for e in &entries {
                writeln!(file, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
            file.flush().unwrap();
        }

        let store = DigestStore::load(path);
        assert_eq!(store.len(), 2);

        let status = store.check("docker", "sha256:aaa", 86400);
        assert!(matches!(status, QuarantineStatus::Pending { .. }));
    }

    #[test]
    fn test_load_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_load_corrupt_file_fail_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let valid = serde_json::json!({
            "registry": "docker",
            "digest": "sha256:good",
            "first_seen": now,
            "upstream": "up"
        });
        std::fs::write(&path, format!("not json\n{}\ngarbage\n", valid)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_prune_stale_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let old_ts = now - (91 * 24 * 3600); // 91 days — stale
        let fresh_ts = now - (10 * 24 * 3600); // 10 days — kept

        let old = serde_json::json!({
            "registry": "docker", "digest": "sha256:old",
            "first_seen": old_ts, "upstream": "up"
        });
        let fresh = serde_json::json!({
            "registry": "docker", "digest": "sha256:fresh",
            "first_seen": fresh_ts, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n", old, fresh)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);

        assert!(matches!(
            store.check("docker", "sha256:fresh", 86400),
            QuarantineStatus::Mature
        ));
        assert_eq!(
            store.check("docker", "sha256:old", 86400),
            QuarantineStatus::New
        );
    }

    #[test]
    fn test_quarantine_status_header_values() {
        assert_eq!(QuarantineStatus::New.header_value(), "new");
        assert_eq!(
            QuarantineStatus::Pending {
                remaining_secs: 100
            }
            .header_value(),
            "pending"
        );
        assert_eq!(QuarantineStatus::Mature.header_value(), "mature");
    }

    #[test]
    fn test_atomic_rewrite_compacts_duplicates() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let entry = serde_json::json!({
            "registry": "docker", "digest": "sha256:dup",
            "first_seen": now, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n{}\n", entry, entry, entry)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn test_empty_store_is_empty() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_digest_entry_serialization() {
        let entry = DigestEntry {
            registry: "docker".to_string(),
            digest: "sha256:abc".to_string(),
            first_seen: 1700000000,
            upstream: "registry-1.docker.io".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"registry\":\"docker\""));
        assert!(json.contains("\"first_seen\":1700000000"));

        let parsed: DigestEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.digest, "sha256:abc");
    }

    /// Every line of an old ledger loses its credential on load, not only the first: the
    /// rewrite keeps none of the users or passwords any line carried.
    #[test]
    fn every_credential_already_in_the_ledger_is_masked_on_load() {
        let tmp = TempDir::new().unwrap();
        let ledger = tmp.path().join("quarantine.jsonl");
        let now = Utc::now().timestamp();
        let mut text = String::new();
        for (digest, user) in [("sha256:aaa", "first-user"), ("sha256:bbb", "second-user")] {
            let line = serde_json::json!({
                "registry": "npm", "digest": digest, "first_seen": now,
                "upstream": format!("https://{user}:s3cret@npm.example/pkg/-/pkg-1.0.0.tgz"),
            });
            text.push_str(&format!("{line}\n"));
        }
        std::fs::write(&ledger, text).unwrap();
        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 2);
        let written = std::fs::read_to_string(&ledger).unwrap();
        assert!(!written.contains("s3cret"), "{written}");
        assert!(!written.contains("-user"), "{written}");
    }
    /// Each line of a ledger is loaded as the log has its URL, whatever the lines around it
    /// hold: userinfo masked up to its last `@`, a URL without userinfo kept as it is; the
    /// rewritten file and a new record alike.
    #[tokio::test]
    async fn every_ledger_line_is_loaded_with_its_upstream_masked() {
        let rows = [
            (
                "sha256:a1",
                "https://ci-user:s3cret@npm.example/pkg/-/pkg-1.0.0.tgz",
                "https://***@npm.example/pkg/-/pkg-1.0.0.tgz",
            ),
            (
                "sha256:a2",
                "https://npm.example/pkg/-/pkg-2.0.0.tgz",
                "https://npm.example/pkg/-/pkg-2.0.0.tgz",
            ),
            (
                "sha256:a3",
                "https://ci-user:p@ss@w0rd@npm.example/pkg",
                "https://***@npm.example/pkg",
            ),
            ("sha256:a4", "registry-1.docker.io", "registry-1.docker.io"),
            (
                "sha256:a5",
                "http://only-user@127.0.0.1:4873/pkg",
                "http://***@127.0.0.1:4873/pkg",
            ),
            (
                "sha256:a6",
                "https://second:s3cret@npm.example/x?q=a@b",
                "https://***@npm.example/x?q=a@b",
            ),
        ];
        let secrets = ["s3cret", "ci-user", "p@ss", "w0rd", "only-user", "second"];
        let now = Utc::now().timestamp();
        for reversed in [false, true] {
            let mut lines: Vec<_> = rows.iter().collect();
            if reversed {
                lines.reverse();
            }
            let tmp = TempDir::new().unwrap();
            let ledger = tmp.path().join("quarantine.jsonl");
            let text: String = lines
                .iter()
                .map(|(digest, upstream, _)| {
                    let line = serde_json::json!({
                        "registry": "npm", "digest": digest, "first_seen": now,
                        "upstream": upstream,
                    });
                    format!("{line}\n")
                })
                .collect();
            std::fs::write(&ledger, text).unwrap();
            let store = DigestStore::load(tmp.path().to_str().unwrap());
            assert_eq!(store.len(), rows.len());
            for (digest, upstream, recorded) in rows {
                // A digest already recorded answers its entry as loaded.
                let entry = store.record("npm", digest, "unused", None);
                assert_eq!(
                    entry.upstream.as_str(),
                    recorded,
                    "{upstream}, reversed: {reversed}"
                );
            }
            let written = std::fs::read_to_string(&ledger).unwrap();
            for secret in secrets {
                assert!(!written.contains(secret), "{secret} in {written}");
            }
            for (_, upstream, _) in rows {
                let entry = store.record("npm", &format!("new:{upstream}"), upstream, None);
                for secret in secrets {
                    assert!(!entry.upstream.as_str().contains(secret), "{entry:?}");
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod shared_tests {
    use super::*;
    use sha2::Digest;

    #[tokio::test]
    async fn shared_quarantine_survives_new_replica_and_concurrent_first_writers() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let a = DigestStore::empty(dir.path().to_str().unwrap());
        let b = DigestStore::empty(dir.path().to_str().unwrap());
        let bytes = b"immutable artifact";
        let now = Utc::now().timestamp();
        let ttl = 7 * 86400;
        let (left, right) = tokio::join!(
            proxy_gate_shared(
                &storage,
                &a,
                "npm",
                bytes,
                &QuarantineMode::Enforce,
                ttl,
                "upstream",
                Some(now - ttl - 100)
            ),
            proxy_gate_shared(
                &storage,
                &b,
                "npm",
                bytes,
                &QuarantineMode::Enforce,
                ttl,
                "upstream",
                Some(now - ttl - 50)
            ),
        );
        assert!(left.is_none() && right.is_none());
        // No seed and a fresh process-local store still observes the shared matured record.
        assert!(proxy_gate_shared(
            &storage,
            &b,
            "npm",
            bytes,
            &QuarantineMode::Enforce,
            ttl,
            "upstream",
            None
        )
        .await
        .is_none());
        let keys = storage.list_internal(".nora-quarantine/").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!dir.path().join("quarantine.jsonl").exists());
    }

    #[tokio::test]
    async fn shared_quarantine_keeps_first_timestamp_and_fails_closed_on_bad_state() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        let bytes = b"recent artifact";
        let ttl = 7 * 86400;
        let blocked = proxy_gate_shared(
            &storage,
            &local,
            "go",
            bytes,
            &QuarantineMode::Enforce,
            ttl,
            "upstream",
            None,
        )
        .await
        .unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        // A later replica cannot rewrite the winner with an older upstream seed.
        let blocked = proxy_gate_shared(
            &storage,
            &local,
            "go",
            bytes,
            &QuarantineMode::Enforce,
            ttl,
            "upstream",
            Some(1),
        )
        .await
        .unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        let key = format!(".nora-quarantine/go/{digest}.json");
        storage.put(&key, b"malformed").await.unwrap();
        let unavailable = proxy_gate_shared(
            &storage,
            &local,
            "go",
            bytes,
            &QuarantineMode::Enforce,
            ttl,
            "upstream",
            None,
        )
        .await
        .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(proxy_gate_shared(
            &storage,
            &local,
            "go",
            bytes,
            &QuarantineMode::Off,
            ttl,
            "upstream",
            None
        )
        .await
        .is_none());
    }

    #[test]
    #[ignore = "requires a disposable loopback MinIO bucket nora-shared-quarantine-test"]
    fn shared_quarantine_across_independent_s3_clients() {
        let _lock = crate::test_env::env_lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let endpoint =
                    std::env::var("NORA_TEST_S3_ENDPOINT").expect("set NORA_TEST_S3_ENDPOINT");
                assert!(endpoint.starts_with("http://127.0.0.1:"));
                let client = || {
                    crate::Storage::new_s3(
                        &endpoint,
                        "nora-shared-quarantine-test",
                        "us-east-1",
                        Some("nora-test"),
                        Some("nora-test-secret"),
                        false,
                        false,
                    )
                };
                let a = client();
                let b = client();
                let dir = tempfile::tempdir().unwrap();
                let local = DigestStore::empty(dir.path().to_str().unwrap());
                let bytes = uuid::Uuid::new_v4().to_string().into_bytes();
                let ttl = 7 * 86400;
                let old = Utc::now().timestamp() - ttl - 100;
                let (left, right) = tokio::join!(
                    proxy_gate_shared(
                        &a,
                        &local,
                        "npm",
                        &bytes,
                        &QuarantineMode::Enforce,
                        ttl,
                        "upstream",
                        Some(old)
                    ),
                    proxy_gate_shared(
                        &b,
                        &local,
                        "npm",
                        &bytes,
                        &QuarantineMode::Enforce,
                        ttl,
                        "upstream",
                        Some(old + 50)
                    ),
                );
                assert!(left.is_none() && right.is_none());
                drop(a);
                drop(b);
                assert!(proxy_gate_shared(
                    &client(),
                    &local,
                    "npm",
                    &bytes,
                    &QuarantineMode::Enforce,
                    ttl,
                    "upstream",
                    None
                )
                .await
                .is_none());
                assert!(!dir.path().join("quarantine.jsonl").exists());
                // Create-if-absent must preserve the winning object through distinct S3 clients.
                let key = format!(".nora-quarantine/test/{}", uuid::Uuid::new_v4());
                let (a, b) = (client(), client());
                let (left, right) =
                    tokio::join!(a.create_internal(&key, b"a"), b.create_internal(&key, b"b"));
                assert_ne!(left.unwrap(), right.unwrap());
            });
    }

    #[tokio::test]
    async fn conditional_create_has_exactly_one_winner() {
        let storage = crate::Storage::in_memory();
        let (a, b) = tokio::join!(
            storage.create_internal(".nora-quarantine/test", b"a"),
            storage.create_internal(".nora-quarantine/test", b"b")
        );
        assert_ne!(a.unwrap(), b.unwrap());
        let winner = storage.get(".nora-quarantine/test").await.unwrap();
        assert!(winner.as_ref() == b"a" || winner.as_ref() == b"b");
    }
}

#[cfg(test)]
mod trusted_release_recovery_tests {
    use super::*;
    use sha2::Digest;

    const URL: &str = "https://repo.maven.apache.org/maven2/org/example/demo/1.0/demo-1.0.jar";
    const TTL: i64 = 7 * 86400;
    const BYTES: &[u8] = b"artifact bytes";

    fn keys() -> (String, String) {
        let digest = hex::encode(sha2::Sha256::digest(BYTES));
        (
            format!(".nora-quarantine/maven/{digest}.json"),
            format!(".nora-quarantine-release/maven/{digest}.json"),
        )
    }

    async fn gate(
        storage: &crate::Storage,
        local: &DigestStore,
        trust: bool,
        evidence: Option<&TrustedReleaseEvidence>,
    ) -> Option<Response> {
        proxy_gate_shared_recoverable(
            storage,
            local,
            "maven",
            BYTES,
            &QuarantineMode::Enforce,
            TTL,
            URL,
            trust,
            evidence,
        )
        .await
    }

    #[tokio::test]
    async fn recoverable_quarantine_shares_recovery_without_rewriting_observation() {
        let storage = crate::Storage::in_memory();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = DigestStore::empty(a_dir.path().to_str().unwrap());
        let b = DigestStore::empty(b_dir.path().to_str().unwrap());
        assert_eq!(
            gate(&storage, &a, true, None).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let (key, recovery_key) = keys();
        let original = storage.get(&key).await.unwrap();
        let record: RecoverableDigestEntry = serde_json::from_slice(&original).unwrap();
        assert!(matches!(
            record.timestamp_origin,
            Some(SharedTimestampOrigin::FallbackObservation)
        ));
        let old =
            TrustedReleaseEvidence::maven_central(Utc::now().timestamp() - TTL - 60, URL, BYTES)
                .unwrap();
        let (one, two) = tokio::join!(
            gate(&storage, &a, true, Some(&old)),
            gate(&storage, &b, true, Some(&old))
        );
        assert!(one.is_none());
        assert!(two.is_none());
        assert_eq!(storage.get(&key).await.unwrap(), original);
        assert!(storage.get(&recovery_key).await.is_ok());
        // Missing caller evidence cannot silently bypass a stricter release-age
        // rule which the handler was unable to evaluate.
        assert_eq!(
            gate(&storage, &b, true, None).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        // Disabling upstream trust stops using the independent evidence immediately.
        assert_eq!(
            gate(&storage, &b, false, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn recoverable_quarantine_keeps_young_releases_held() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        let young =
            TrustedReleaseEvidence::maven_central(Utc::now().timestamp() - 60, URL, BYTES).unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&young))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            gate(&storage, &local, true, None).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn recoverable_quarantine_rejects_evidence_for_other_bytes() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        let wrong = TrustedReleaseEvidence::maven_central(1, URL, b"different bytes").unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&wrong))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn recoverable_quarantine_does_not_override_legacy_holds() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        let (key, _) = keys();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(BYTES)));
        let legacy = DigestEntry {
            registry: "maven".into(),
            digest,
            first_seen: Utc::now().timestamp(),
            upstream: RecordedUrl::new(URL),
        };
        let original = serde_json::to_vec(&legacy).unwrap();
        storage.put(&key, &original).await.unwrap();
        let old = TrustedReleaseEvidence::maven_central(1, URL, BYTES).unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            storage.get(&key).await.unwrap().as_ref(),
            original.as_slice()
        );
    }

    #[tokio::test]
    async fn recoverable_quarantine_fails_closed_on_corrupt_state_even_with_old_date() {
        let storage = crate::Storage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        let (key, recovery_key) = keys();
        let old = TrustedReleaseEvidence::maven_central(1, URL, BYTES).unwrap();
        storage.put(&key, b"bad record").await.unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        storage.delete(&key).await.unwrap();
        assert!(gate(&storage, &local, true, Some(&old)).await.is_none());
        storage.put(&recovery_key, b"bad evidence").await.unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn recoverable_quarantine_preserves_conservative_local_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        let local = DigestStore::empty(dir.path().to_str().unwrap());
        assert_eq!(
            gate(&storage, &local, true, None).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let old = TrustedReleaseEvidence::maven_central(1, URL, BYTES).unwrap();
        assert_eq!(
            gate(&storage, &local, true, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let fresh_dir = tempfile::tempdir().unwrap();
        let fresh_storage = crate::Storage::new_local(fresh_dir.path().to_str().unwrap());
        let fresh_local = DigestStore::empty(fresh_dir.path().to_str().unwrap());
        assert_eq!(
            gate(&fresh_storage, &fresh_local, true, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            gate(&fresh_storage, &fresh_local, false, Some(&old))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn trusted_release_evidence_requires_canonical_central_artifact_and_valid_time() {
        assert!(TrustedReleaseEvidence::maven_central(1, URL, BYTES).is_some());
        for date in [-1, 0, Utc::now().timestamp() + 3600] {
            assert!(TrustedReleaseEvidence::maven_central(date, URL, BYTES).is_none());
        }
        for url in [
            "http://repo.maven.apache.org/maven2/a.jar",
            "https://repo.maven.apache.org.evil.example/maven2/a.jar",
            "https://repo.maven.apache.org:8443/maven2/a.jar",
            "https://user:pass@repo.maven.apache.org/maven2/a.jar",
            "https://repo.maven.apache.org/maven2/a.jar?x=1",
            "https://repo.maven.apache.org/maven2/a.jar#x",
            "https://repo.maven.apache.org/other/a.jar",
            "https://repo.maven.apache.org/maven2/",
            "https://repo.maven.apache.org/maven2/a%2fb.jar",
        ] {
            assert!(
                TrustedReleaseEvidence::maven_central(1, url, BYTES).is_none(),
                "{url}"
            );
        }
    }
}

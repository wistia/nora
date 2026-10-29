// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Rebuildable, per-replica compact-index cache. `/versions` is the freshness
//! authority; /info objects are shared by checksum, never invalidated by name.
//! MD5 is the protocol's change identifier, not a security/integrity guarantee.

use super::gems::{fetch_index_with_ttl, read_index_metadata, write_index_metadata, IndexMetadata};
use super::{proxy_fetch_conditional_with_cache_control, Revalidation, Validators};
use crate::cache_ttl::{is_within_ttl, now_unix};
use crate::config::UpstreamAuth;
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::body::{to_bytes, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use md5::{Digest, Md5};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const MAX_VERSIONS_BYTES: usize = 64 * 1024 * 1024;
const MAX_INFO_BYTES: usize = 8 * 1024 * 1024;
const MAX_HOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_HOT_ENTRIES: usize = 4096;

#[derive(Default)]
pub(crate) struct CompactCache {
    snapshot: tokio::sync::Mutex<Option<Snapshot>>,
    hot: parking_lot::Mutex<HotCache>,
    fills: crate::proxy_coalesce::InflightMap<Arc<InfoDocument>>,
}

struct Snapshot {
    checked_at: u64,
    checksums: HashMap<String, String>,
}

#[derive(Default)]
struct HotCache {
    entries: HashMap<String, (u64, Arc<InfoDocument>)>,
    bytes: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InfoDocument {
    body: String,
    cache_control: Option<String>,
}

impl HotCache {
    fn get(&mut self, key: &str, ttl: i64) -> Option<Arc<InfoDocument>> {
        let (inserted, document) = self.entries.get(key)?;
        if is_within_ttl(*inserted, ttl) {
            return Some(Arc::clone(document));
        }
        let (_, document) = self.entries.remove(key)?;
        self.bytes -= document.body.len();
        None
    }

    fn insert(&mut self, key: String, document: Arc<InfoDocument>) {
        if document.body.len() > MAX_HOT_BYTES {
            return;
        }
        if let Some((_, old)) = self.entries.remove(&key) {
            self.bytes -= old.body.len();
        }
        while self.bytes + document.body.len() > MAX_HOT_BYTES
            || self.entries.len() >= MAX_HOT_ENTRIES
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (time, _))| time)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some((_, old)) = self.entries.remove(&oldest) {
                self.bytes -= old.body.len();
            }
        }
        self.bytes += document.body.len();
        self.entries.insert(key, (now_unix(), document));
    }
}

/// The client-visible /versions must discover exempt releases at the shorter interval too.
pub(super) fn versions_ttl(state: &AppState) -> i64 {
    if state
        .curation()
        .curation_engine
        .has_cooldown_exempt_packages(RegistryType::Gems)
    {
        shorter_ttl(
            state.config.gems.metadata_ttl,
            state.config.gems.exempt_metadata_ttl,
        )
    } else {
        state.config.gems.metadata_ttl
    }
}

fn shorter_ttl(normal: i64, exempt: i64) -> i64 {
    match (normal < 0, exempt < 0) {
        (true, _) => exempt,
        (_, true) => normal,
        _ => normal.min(exempt),
    }
}

/// Last occurrence wins, including yank records. Monthly rewrites replace the
/// complete map: they are not treated as append-only deltas.
fn parse_versions(body: &[u8]) -> Option<HashMap<String, String>> {
    let text = std::str::from_utf8(body).ok()?;
    let (_, records) = text.split_once("---\n")?;
    let mut checksums = HashMap::new();
    for line in records.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let _versions = fields.next()?;
        let checksum = fields.next()?;
        if fields.next().is_some()
            || !super::gems::is_valid_gem_name(name)
            || checksum.len() != 32
            || !checksum.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        checksums.insert(name.to_owned(), checksum.to_ascii_lowercase());
    }
    Some(checksums)
}

fn matches_checksum(body: &[u8], checksum: &str) -> bool {
    hex::encode(Md5::digest(body)) == checksum
}

async fn expected_checksum(state: &AppState, name: &str) -> Option<String> {
    let exempt = state
        .curation()
        .curation_engine
        .cooldown_exempt(RegistryType::Gems, name);
    let ttl = if exempt {
        shorter_ttl(
            state.config.gems.metadata_ttl,
            state.config.gems.exempt_metadata_ttl,
        )
    } else {
        state.config.gems.metadata_ttl
    };
    // A single refresh per replica, shared by all concurrent /info requests.
    // Cancellation releases the mutex; incomplete snapshots are never published.
    let mut snapshot = state.gems_cache.snapshot.lock().await;
    if snapshot
        .as_ref()
        .is_none_or(|snapshot| !is_within_ttl(snapshot.checked_at, ttl))
    {
        // Sample freshness before fetching. A later stat could observe another
        // replica's newer write and incorrectly extend this older body's TTL.
        let started_at = now_unix();
        let cached_at = state
            .storage
            .stat("gems/versions")
            .await
            .map(|meta| meta.modified);
        let response = fetch_index_with_ttl(state, "versions", ttl).await;
        if response.status() != StatusCode::OK || response.headers().contains_key("x-nora-stale") {
            return None; // legacy conditional-fetch/serve-stale path remains available
        }
        let body = to_bytes(response.into_body(), MAX_VERSIONS_BYTES)
            .await
            .ok()?;
        let checksums = parse_versions(&body)?;
        // Use the shared object's actual validation time, not the time we read it:
        // another replica's nearly-expired copy must not get a new TTL locally.
        let checked_at = cached_at
            .filter(|time| is_within_ttl(*time, ttl))
            .unwrap_or(started_at);
        *snapshot = Some(Snapshot {
            checked_at,
            checksums,
        });
    }
    snapshot.as_ref()?.checksums.get(name).cloned()
}

fn response(document: &InfoDocument) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        document.body.clone(),
    )
        .into_response();
    if let Some(value) = document
        .cache_control
        .as_deref()
        .and_then(|value| HeaderValue::from_str(value).ok())
    {
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }
    response
}

/// None means no usable /versions entry: retain the existing metadata TTL,
/// conditional revalidation, offline and stale-on-error behavior.
pub(super) async fn info(state: &AppState, name: &str) -> Option<Response> {
    let checksum = expected_checksum(state, name).await?;
    let key = format!(".nora-gems-info/{name}/{checksum}");
    let ttl = state.config.gems.info_cache_ttl;
    if let Some(document) = state.gems_cache.hot.lock().get(&key, ttl) {
        state.metrics.record_download("gems");
        state.metrics.record_cache_hit("gems");
        return Some(response(&document));
    }
    let document = state
        .gems_cache
        .fills
        .coalesced(
            &key,
            "gems",
            Duration::from_secs(state.config.gems.proxy_timeout.saturating_add(10)),
            || async {
                // Recheck after election; a previous fill may just have finished.
                if let Some(document) = state.gems_cache.hot.lock().get(&key, ttl) {
                    return Some(document);
                }
                if let Ok(bytes) = state.storage.get(&key).await {
                    if let Ok(document) = serde_json::from_slice::<InfoDocument>(&bytes) {
                        if matches_checksum(document.body.as_bytes(), &checksum) {
                            let document = Arc::new(document);
                            state
                                .gems_cache
                                .hot
                                .lock()
                                .insert(key.clone(), Arc::clone(&document));
                            state.metrics.record_cache_hit("gems");
                            return Some(document);
                        }
                    }
                }
                // Migrate a valid old name-keyed cache without downloading it again.
                let legacy_key = format!("gems/info/{name}");
                let legacy = state.storage.get(&legacy_key).await.ok();
                let document =
                    if let Some(body) = legacy.filter(|body| matches_checksum(body, &checksum)) {
                        let metadata = read_index_metadata(state, &legacy_key).await;
                        InfoDocument {
                            body: String::from_utf8(body.to_vec()).ok()?,
                            cache_control: metadata.cache_control,
                        }
                    } else {
                        let url = format!(
                            "{}/info/{name}",
                            state.config.gems.proxy.as_deref()?.trim_end_matches('/')
                        );
                        let (result, cache_control) = proxy_fetch_conditional_with_cache_control(
                            &state.http_client,
                            &url,
                            Duration::from_secs(state.config.gems.proxy_timeout),
                            expose_opt(&state.config.gems.proxy_auth).map(UpstreamAuth::Basic),
                            &Validators::default(),
                            &state.circuit_breaker,
                            RegistryType::Gems,
                        )
                        .await
                        .ok()?;
                        let Revalidation::Modified { body, validators } = result else {
                            return None;
                        };
                        if body.len() > MAX_INFO_BYTES || !matches_checksum(&body, &checksum) {
                            // A publishing race or stale upstream CDN must not poison this key.
                            *state.gems_cache.snapshot.lock().await = None;
                            return None;
                        }
                        state.metrics.record_cache_miss("gems");
                        // Keep the legacy browsing/date/identity readers working. This mutable
                        // alias is not used as the checksum cache's freshness authority.
                        let storage = state.storage.clone();
                        let repo_index = Arc::clone(&state.repo_index);
                        let alias_body = Bytes::copy_from_slice(&body);
                        let metadata = IndexMetadata {
                            validators,
                            cache_control: cache_control.clone(),
                        };
                        tokio::spawn(async move {
                            if storage.put(&legacy_key, &alias_body).await.is_ok() {
                                write_index_metadata(&storage, &legacy_key, &metadata).await;
                                repo_index.invalidate("gems");
                            }
                        });
                        InfoDocument {
                            body: String::from_utf8(body).ok()?,
                            cache_control,
                        }
                    };
                // One envelope pairs body and policy atomically across replicas. Keys
                // identify content, so competing fills cannot replace a different version.
                if let Ok(bytes) = serde_json::to_vec(&document) {
                    if let Err(error) = state.storage.put(&key, &bytes).await {
                        tracing::warn!(%key, ?error, "failed to persist checksum-keyed gem info");
                    }
                }
                let document = Arc::new(document);
                state
                    .gems_cache
                    .hot
                    .lock()
                    .insert(key.clone(), Arc::clone(&document));
                Some(document)
            },
        )
        .await;
    state.metrics.record_download("gems");
    Some(match document {
        Some(document) => response(&document),
        None => (
            StatusCode::BAD_GATEWAY,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::Method;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn checksum(body: &str) -> String {
        hex::encode(Md5::digest(body.as_bytes()))
    }
    fn versions(name: &str, body: &str) -> String {
        format!("created_at: test\n---\n{name} 1.0.0 {}\n", checksum(body))
    }

    #[test]
    fn latest_checksum_wins_and_rewrites_replace_the_map() {
        let first = "a".repeat(32);
        let latest = "b".repeat(32);
        let data = format!("created_at: x\n---\nrails 1.0.0 {first}\nrails -1.0.0 {latest}\n");
        assert_eq!(parse_versions(data.as_bytes()).unwrap()["rails"], latest);
        let rewritten = versions("rack", "rack index");
        let parsed = parse_versions(rewritten.as_bytes()).unwrap();
        assert!(!parsed.contains_key("rails"));
        assert_eq!(parsed["rack"], checksum("rack index"));
        assert!(parse_versions(b"---\nrails 1.0.0 not-a-checksum\n").is_none());
        assert!(
            parse_versions(b"---\n../secret 1.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").is_none()
        );
        assert_eq!(shorter_ttl(-1, 60), 60);
        assert_eq!(shorter_ttl(300, -1), 300);
    }

    #[test]
    fn hot_cache_expires_and_bounds_entry_count() {
        let mut cache = HotCache::default();
        for n in 0..=MAX_HOT_ENTRIES {
            cache.insert(
                n.to_string(),
                Arc::new(InfoDocument {
                    body: "body".into(),
                    cache_control: None,
                }),
            );
        }
        assert_eq!(cache.entries.len(), MAX_HOT_ENTRIES);
        assert_eq!(cache.bytes, MAX_HOT_ENTRIES * 4);
        let key = cache.entries.keys().next().unwrap().clone();
        cache.entries.get_mut(&key).unwrap().0 = 0;
        assert!(cache.get(&key, 86400).is_none());
        assert_eq!(cache.bytes, (MAX_HOT_ENTRIES - 1) * 4);
    }

    #[tokio::test]
    async fn legacy_body_migrates_without_an_upstream_info_fetch() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        let body = "---\n1.0.0\n";
        ctx.state
            .storage
            .put("gems/versions", versions("rails", body).as_bytes())
            .await
            .unwrap();
        ctx.state
            .storage
            .put("gems/info/rails", body.as_bytes())
            .await
            .unwrap();
        write_index_metadata(
            &ctx.state.storage,
            "gems/info/rails",
            &IndexMetadata {
                validators: Validators::default(),
                cache_control: Some("max-age=17, public".into()),
            },
        )
        .await;
        let result = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(
            result.headers()[header::CACHE_CONTROL],
            "max-age=17, public"
        );
        assert_eq!(body_bytes(result).await.as_ref(), body.as_bytes());
        assert!(ctx
            .state
            .storage
            .get(&format!(".nora-gems-info/rails/{}", checksum(body)))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn unavailable_versions_falls_back_to_the_existing_info_fetch() {
        let upstream = MockServer::start().await;
        Mock::given(path("/versions"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(path("/info/rails"))
            .respond_with(ResponseTemplate::new(200).set_body_string("legacy"))
            .expect(1)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        let response = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"legacy");
    }

    #[tokio::test]
    async fn namespace_and_offline_paths_do_not_consult_versions() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
            cfg.curation.internal_namespaces = vec!["internal*".into()];
        });
        assert_eq!(
            send(&ctx.app, Method::GET, "/gems/info/internal_gem", "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        ctx.state
            .storage
            .put("gems/info/internal_gem", b"local")
            .await
            .unwrap();
        assert_eq!(
            body_bytes(send(&ctx.app, Method::GET, "/gems/info/internal_gem", "").await)
                .await
                .as_ref(),
            b"local"
        );
        let offline = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = None;
            cfg.gems.info_checksum_cache = true;
        });
        offline
            .state
            .storage
            .put("gems/info/rails", b"offline")
            .await
            .unwrap();
        assert_eq!(
            body_bytes(send(&offline.app, Method::GET, "/gems/info/rails", "").await)
                .await
                .as_ref(),
            b"offline"
        );
    }

    #[tokio::test]
    async fn hot_info_cannot_bypass_curation() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocked.json");
        std::fs::write(&blocklist, r#"{"version":1,"rules":[{"registry":"gems","name":"rails","version":"*","reason":"blocked"}]}"#).unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some("http://127.0.0.1:1".into());
            cfg.gems.info_checksum_cache = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_str().unwrap().into());
        });
        ctx.state
            .storage
            .put("gems/versions", versions("rails", "cached").as_bytes())
            .await
            .unwrap();
        ctx.state
            .storage
            .put("gems/info/rails", b"cached")
            .await
            .unwrap();
        assert_eq!(
            info(&ctx.state, "rails").await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send(&ctx.app, Method::GET, "/gems/info/rails", "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn memory_hits_survive_storage_removal_and_preserve_upstream_policy() {
        let upstream = MockServer::start().await;
        let body = "---\n1.0.0 |checksum:gem-digest\n";
        Mock::given(method("GET"))
            .and(path("/info/rails"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("cache-control", "max-age=60, public"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        ctx.state
            .storage
            .put("gems/versions", versions("rails", body).as_bytes())
            .await
            .unwrap();
        let first = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[header::CACHE_CONTROL], "max-age=60, public");
        assert_eq!(body_bytes(first).await.as_ref(), body.as_bytes());
        let key = format!(".nora-gems-info/rails/{}", checksum(body));
        // A separate replica starts with no local state and uses shared S3-equivalent storage.
        let mut replica = ctx.state.clone();
        replica.gems_cache = Arc::default();
        let response = info(&replica, "rails").await.unwrap();
        assert_eq!(body_bytes(response).await.as_ref(), body.as_bytes());
        ctx.state.storage.delete(&key).await.unwrap();
        ctx.state.storage.delete("gems/versions").await.unwrap();
        for state in [&ctx.state, &replica] {
            let response = info(state, "rails").await.unwrap();
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "max-age=60, public"
            );
            assert_eq!(body_bytes(response).await.as_ref(), body.as_bytes());
        }
    }

    #[tokio::test]
    async fn changed_checksums_and_old_replica_snapshots_cannot_overwrite_each_other() {
        let upstream = MockServer::start().await;
        let old = "---\n1.0.0\n";
        let new = "---\n1.0.0\n2.0.0\n";
        Mock::given(path("/info/rails"))
            .respond_with(ResponseTemplate::new(200).set_body_string(old))
            .expect(1)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        ctx.state
            .storage
            .put("gems/versions", versions("rails", old).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            body_bytes(info(&ctx.state, "rails").await.unwrap())
                .await
                .as_ref(),
            old.as_bytes()
        );
        upstream.verify().await;
        upstream.reset().await;
        Mock::given(path("/info/rails"))
            .respond_with(ResponseTemplate::new(200).set_body_string(new))
            .expect(1)
            .mount(&upstream)
            .await;
        ctx.state
            .storage
            .put("gems/versions", versions("rails", new).as_bytes())
            .await
            .unwrap();
        let mut replica = ctx.state.clone();
        replica.gems_cache = Arc::default();
        assert_eq!(
            body_bytes(info(&replica, "rails").await.unwrap())
                .await
                .as_ref(),
            new.as_bytes()
        );
        // The first replica's bounded old snapshot still refers to the old body.
        assert_eq!(
            body_bytes(info(&ctx.state, "rails").await.unwrap())
                .await
                .as_ref(),
            old.as_bytes()
        );
        ctx.state
            .gems_cache
            .snapshot
            .lock()
            .await
            .as_mut()
            .unwrap()
            .checked_at = 0;
        assert_eq!(
            body_bytes(info(&ctx.state, "rails").await.unwrap())
                .await
                .as_ref(),
            new.as_bytes()
        );
        for body in [old, new] {
            let key = format!(".nora-gems-info/rails/{}", checksum(body));
            let stored: InfoDocument =
                serde_json::from_slice(&ctx.state.storage.get(&key).await.unwrap()).unwrap();
            assert_eq!(stored.body, body);
        }
    }

    #[tokio::test]
    async fn exempt_gems_refresh_the_snapshot_earlier() {
        let upstream = MockServer::start().await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
            cfg.curation.gems.cooldown_exempt_packages = vec!["private_gem".into()];
        });
        let old = format!(
            "---\nrails 1.0.0 {}\nprivate_gem 1.0.0 {}\n",
            checksum("old"),
            checksum("old")
        );
        let new = old.replace(&checksum("old"), &checksum("new"));
        ctx.state
            .storage
            .put("gems/versions", old.as_bytes())
            .await
            .unwrap();
        assert_eq!(
            expected_checksum(&ctx.state, "rails").await.unwrap(),
            checksum("old")
        );
        ctx.state
            .gems_cache
            .snapshot
            .lock()
            .await
            .as_mut()
            .unwrap()
            .checked_at = now_unix() - 120;
        ctx.state
            .storage
            .put("gems/versions", new.as_bytes())
            .await
            .unwrap();
        assert_eq!(
            expected_checksum(&ctx.state, "rails").await.unwrap(),
            checksum("old")
        );
        assert_eq!(versions_ttl(&ctx.state), 60);
        assert_eq!(
            expected_checksum(&ctx.state, "private_gem").await.unwrap(),
            checksum("new")
        );
        assert_eq!(
            expected_checksum(&ctx.state, "rails").await.unwrap(),
            checksum("new")
        );
    }

    #[tokio::test]
    async fn mismatched_upstream_body_is_never_published_under_the_expected_checksum() {
        let upstream = MockServer::start().await;
        Mock::given(path("/info/rails"))
            .respond_with(ResponseTemplate::new(200).set_body_string("unexpected"))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        ctx.state
            .storage
            .put("gems/versions", versions("rails", "expected").as_bytes())
            .await
            .unwrap();
        let response = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(ctx
            .state
            .storage
            .get(&format!(".nora-gems-info/rails/{}", checksum("expected")))
            .await
            .is_err());
        assert!(ctx.state.gems_cache.snapshot.lock().await.is_none());
    }

    #[tokio::test]
    async fn concurrent_local_misses_share_one_fetch() {
        let upstream = MockServer::start().await;
        let body = "---\n1.0.0\n";
        Mock::given(path("/info/rails"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .set_delay(Duration::from_millis(50)),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.info_checksum_cache = true;
        });
        ctx.state
            .storage
            .put("gems/versions", versions("rails", body).as_bytes())
            .await
            .unwrap();
        let responses = futures::future::join_all((0..20).map(|_| info(&ctx.state, "rails"))).await;
        for response in responses {
            assert_eq!(
                body_bytes(response.unwrap()).await.as_ref(),
                body.as_bytes()
            );
        }
    }

    #[tokio::test]
    async fn ruby_gem_exemption_skips_cooldown_but_not_a_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocked.json");
        std::fs::write(&blocklist, r#"{"version":1,"rules":[{"registry":"gems","name":"blocked_gem","version":"*","reason":"blocked"}]}"#).unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".into());
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("7d".into());
            cfg.curation.gems.cooldown_exempt_packages =
                vec!["private_gem".into(), "blocked_gem".into()];
            cfg.curation.blocklist_path = Some(blocklist.to_str().unwrap().into());
        });
        for name in ["private_gem", "ordinary_gem", "blocked_gem"] {
            ctx.state
                .storage
                .put(&format!("gems/gems/{name}-1.0.0.gem"), b"gem")
                .await
                .unwrap();
        }
        assert_eq!(
            send(
                &ctx.app,
                Method::GET,
                "/gems/gems/private_gem-1.0.0.gem",
                ""
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::GET,
                "/gems/gems/ordinary_gem-1.0.0.gem",
                ""
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::GET,
                "/gems/gems/blocked_gem-1.0.0.gem",
                ""
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
}

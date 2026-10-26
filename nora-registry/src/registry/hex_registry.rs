// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Public Hex.pm mirror: preserve signed records and gate immutable tarballs.
use crate::{config::UpstreamAuth, registry_type::RegistryType, AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use flate2::read::GzDecoder;
use prost::Message;
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
    RsaPublicKey,
};
use sha2::Digest;
use std::{io::Read, time::Duration};

const PUBLIC_KEY: &str = include_str!("hex/hexpm.pem");
const MAX_METADATA: u64 = 64 * 1024 * 1024;

// Minimal views of the official proto2 schemas. Unused fields are deliberately
// skipped; signed payload bytes are verified and relayed, never re-encoded.
#[derive(Clone, PartialEq, Message)]
struct Signed {
    #[prost(bytes = "vec", required, tag = "1")]
    payload: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
}
#[derive(Clone, PartialEq, Message)]
struct Package {
    #[prost(message, repeated, tag = "1")]
    releases: Vec<Release>,
    #[prost(string, required, tag = "2")]
    name: String,
    #[prost(string, required, tag = "3")]
    repository: String,
}
#[derive(Clone, PartialEq, Message)]
struct Release {
    #[prost(string, required, tag = "1")]
    version: String,
    #[prost(bytes = "vec", optional, tag = "5")]
    outer_checksum: Option<Vec<u8>>,
    #[prost(message, optional, tag = "7")]
    published_at: Option<Timestamp>,
}
#[derive(Clone, PartialEq, Message)]
struct Timestamp {
    #[prost(int64, required, tag = "1")]
    seconds: i64,
    #[prost(int32, required, tag = "2")]
    nanos: i32,
}
#[derive(Clone, PartialEq, Message)]
struct Listing {
    #[prost(string, required, tag = "2")]
    repository: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/hex/packages/{name}", get(package))
        .route("/hex/tarballs/{archive}", get(tarball))
        .route("/hex/names", get(names))
        .route("/hex/versions", get(versions))
        .route("/hex/public_key", get(public_key))
}

fn key_pem(state: &AppState) -> Result<String, StatusCode> {
    match &state.config.hex.public_key_file {
        Some(path) => std::fs::read_to_string(path).map_err(|_| StatusCode::BAD_GATEWAY),
        None => Ok(PUBLIC_KEY.to_owned()),
    }
}

fn verified_payload(bytes: &[u8], pem: &str) -> Result<Vec<u8>, StatusCode> {
    let bad = StatusCode::BAD_GATEWAY;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(bad);
    }
    let mut decoded = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| bad)?;
    if decoded.len() as u64 > MAX_METADATA {
        return Err(bad);
    }
    let signed = Signed::decode(decoded.as_slice()).map_err(|_| bad)?;
    let key = RsaPublicKey::from_public_key_pem(pem).map_err(|_| bad)?;
    let signature =
        Signature::try_from(signed.signature.as_deref().ok_or(bad)?).map_err(|_| bad)?;
    VerifyingKey::<sha2_010::Sha512>::new(key)
        .verify(&signed.payload, &signature)
        .map_err(|_| bad)?;
    Ok(signed.payload)
}

fn verify_record(bytes: &[u8], pem: &str, name: Option<&str>) -> Result<(), StatusCode> {
    let payload = verified_payload(bytes, pem)?;
    let valid = if let Some(name) = name {
        let pkg = Package::decode(payload.as_slice()).map_err(|_| StatusCode::BAD_GATEWAY)?;
        pkg.name == name && pkg.repository == "hexpm"
    } else {
        Listing::decode(payload.as_slice())
            .map_err(|_| StatusCode::BAD_GATEWAY)?
            .repository
            == "hexpm"
    };
    if valid {
        Ok(())
    } else {
        Err(StatusCode::BAD_GATEWAY)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn internal(state: &AppState, name: &str) -> bool {
    crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        RegistryType::Hex,
        name,
    )
}

/// Validate cached records too: a disk/S3 cache is not a trust anchor.
async fn metadata(
    state: &AppState,
    path: &str,
    name: Option<&str>,
    force: bool,
) -> Result<Vec<u8>, StatusCode> {
    use crate::registry::{
        proxy_fetch_conditional_bounded, read_validators, write_validators, ProxyError,
        Revalidation, Validators,
    };
    let key = format!("hex/{path}");
    let pem = key_pem(state)?;
    let cached = state
        .storage
        .get(&key)
        .await
        .ok()
        .filter(|b| verify_record(b, &pem, name).is_ok());
    let local = name.is_some_and(|n| internal(state, n));
    let fresh = state.storage.stat(&key).await.is_some_and(|m| {
        crate::cache_ttl::is_within_ttl(m.modified, state.config.hex.metadata_ttl)
    });
    if let Some(ref bytes) = cached {
        if local || state.config.hex.proxy.is_none() || (!force && fresh) {
            state.metrics.record_cache_hit("hex");
            return Ok(bytes.to_vec());
        }
    }
    if local {
        return Err(StatusCode::NOT_FOUND);
    }
    let upstream = state
        .config
        .hex
        .proxy
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let url = format!("{}/{path}", upstream.trim_end_matches('/'));
    let validators = if cached.is_some() && state.config.hex.revalidate {
        read_validators(&state.storage, &key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    match proxy_fetch_conditional_bounded(
        &state.http_client_same_origin,
        &url,
        Duration::from_secs(state.config.hex.proxy_timeout),
        crate::secrets::expose_opt(&state.config.hex.proxy_auth).map(UpstreamAuth::Basic),
        &validators,
        &state.circuit_breaker,
        RegistryType::Hex,
        MAX_METADATA,
    )
    .await
    {
        Ok(Revalidation::Modified { body, validators }) => {
            verify_record(&body, &pem, name)?;
            state
                .storage
                .put(&key, &body)
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            write_validators(&state.storage, &key, &validators).await;
            Ok(body)
        }
        Ok(Revalidation::NotModified) => {
            let body = cached.ok_or(StatusCode::BAD_GATEWAY)?;
            state
                .storage
                .put(&key, &body)
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            Ok(body.to_vec())
        }
        Err(ProxyError::NotFound) => Err(StatusCode::NOT_FOUND),
        Err(_) if state.config.hex.serve_stale && cached.is_some() => {
            state.metrics.record_cache_hit("hex");
            cached.map(|b| b.to_vec()).ok_or(StatusCode::BAD_GATEWAY)
        }
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}
fn binary(bytes: Vec<u8>) -> Response {
    ([("content-type", "application/octet-stream")], bytes).into_response()
}
async fn public_key(State(state): State<AppState>) -> Response {
    match key_pem(&state) {
        Ok(key) => key.into_response(),
        Err(s) => s.into_response(),
    }
}
async fn names(State(state): State<AppState>) -> Response {
    listing(&state, "names").await
}
async fn versions(State(state): State<AppState>) -> Response {
    listing(&state, "versions").await
}
async fn listing(state: &AppState, path: &str) -> Response {
    match metadata(state, path, None, false).await {
        Ok(b) => binary(b),
        Err(s) => s.into_response(),
    }
}
async fn package(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !valid_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match metadata(&state, &format!("packages/{name}"), Some(&name), false).await {
        Ok(b) => binary(b),
        Err(s) => s.into_response(),
    }
}
async fn tarball(
    State(state): State<AppState>,
    Path(archive): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some((name, version)) = archive.strip_suffix(".tar").and_then(|a| a.split_once('-')) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_name(name)
        || version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if internal(&state, name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(resp) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        RegistryType::Hex,
        name,
        crate::curation::RequestVersion::of_artifact(Some(version)),
        None,
    ) {
        return resp;
    }
    let path = format!("packages/{name}");
    let release = async {
        let pem = key_pem(&state)?;
        for force in [false, true] {
            let bytes = metadata(&state, &path, Some(name), force).await?;
            let payload = verified_payload(&bytes, &pem)?;
            let package =
                Package::decode(payload.as_slice()).map_err(|_| StatusCode::BAD_GATEWAY)?;
            if let Some(release) = package.releases.into_iter().find(|r| r.version == version) {
                return Ok(release);
            }
        }
        Err(StatusCode::NOT_FOUND)
    }
    .await;
    let release = match release {
        Ok(r) => r,
        Err(s) => return s.into_response(),
    };
    let date = release
        .published_at
        .filter(|t| (0..1_000_000_000).contains(&t.nanos) && t.seconds > 0)
        .and_then(|t| t.seconds.checked_add(i64::from(t.nanos > 0)));
    let date =
        crate::digest_quarantine::first_seen_seed(state.config.server.trust_upstream_dates, date);
    if let Some(resp) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        RegistryType::Hex,
        name,
        crate::curation::RequestVersion::of_artifact(Some(version)),
        date,
    ) {
        return resp;
    }
    let Some(checksum) = release.outer_checksum.filter(|c| c.len() == 32) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let key = format!("hex/tarballs/{archive}");
    let cached = state.storage.get(&key).await.ok();
    let from_cache = cached.is_some();
    let bytes = if let Some(bytes) = cached {
        state.metrics.record_cache_hit("hex");
        bytes.to_vec()
    } else {
        let Some(upstream) = &state.config.hex.proxy else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let url = format!("{}/tarballs/{archive}", upstream.trim_end_matches('/'));
        match crate::registry::proxy_fetch_conditional_bounded(
            &state.http_client_same_origin,
            &url,
            Duration::from_secs(state.config.hex.proxy_timeout),
            crate::secrets::expose_opt(&state.config.hex.proxy_auth).map(UpstreamAuth::Basic),
            &crate::registry::Validators::default(),
            &state.circuit_breaker,
            RegistryType::Hex,
            100 * 1024 * 1024,
        )
        .await
        {
            Ok(crate::registry::Revalidation::Modified { body, .. }) => body,
            Err(crate::registry::ProxyError::NotFound) => {
                return StatusCode::NOT_FOUND.into_response()
            }
            _ => return StatusCode::BAD_GATEWAY.into_response(),
        }
    };
    if sha2::Sha256::digest(&bytes).as_slice() != checksum {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    if let Some(resp) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        RegistryType::Hex,
        name,
        Some(version),
        &bytes,
    ) {
        return resp;
    }
    if !from_cache && state.storage.put(&key, &bytes).await.is_err() {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let cfg = &state.config.curation;
    let (mode, ttl) = crate::digest_quarantine::resolve_global(
        cfg.hex.quarantine.as_ref().or(cfg.quarantine.as_ref()),
        cfg.hex
            .quarantine_ttl
            .as_deref()
            .or(cfg.quarantine_ttl.as_deref()),
    );
    let exempt = state
        .curation()
        .curation_engine
        .cooldown_exempt(RegistryType::Hex, name);
    if !exempt {
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "hex",
            &bytes,
            &mode,
            ttl,
            "hexpm",
            date,
        ) {
            return resp;
        }
    }
    if !from_cache {
        state.repo_index.invalidate("hex");
    }
    state.metrics.record_download("hex");
    binary(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        create_test_context_with_config, quarantine_7d, send, upstream_paths, TestContext,
    };
    use axum::http::Method;
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::DecodePrivateKey,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey,
    };
    use std::{io::Write, sync::OnceLock};
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    const PUBLIC: &str = include_str!("../../../tests/hex-client/fixtures/test-public.pem");
    const PRIVATE: &str = include_str!("../../../tests/hex-client/fixtures/test-private.pem");
    const RECORD: &[u8] = include_bytes!("../../../tests/hex-client/fixtures/jason.record");
    const ARCHIVE: &[u8] = include_bytes!("../../../tests/hex-client/fixtures/jason-1.4.4.tar");
    const DOWNLOAD: &str = "/hex/tarballs/jason-1.4.4.tar";

    fn sign(payload: Vec<u8>) -> Vec<u8> {
        static KEY: OnceLock<SigningKey<sha2_010::Sha512>> = OnceLock::new();
        let key =
            KEY.get_or_init(|| SigningKey::new(RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap()));
        let sig = key.sign(&payload).to_vec();
        let signed = Signed {
            payload,
            signature: Some(sig),
        }
        .encode_to_vec();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&signed).unwrap();
        gzip.finish().unwrap()
    }
    fn record(date: Option<i64>, checksum: &[u8]) -> Vec<u8> {
        sign(
            Package {
                name: "jason".into(),
                repository: "hexpm".into(),
                releases: vec![Release {
                    version: "1.4.4".into(),
                    outer_checksum: Some(checksum.to_vec()),
                    published_at: date.map(|seconds| Timestamp { seconds, nanos: 0 }),
                }],
            }
            .encode_to_vec(),
        )
    }
    async fn fixture(body: Vec<u8>, trust: bool) -> (MockServer, TestContext) {
        fixture_with_policy(body, trust, |_| {}).await
    }
    async fn fixture_with_policy(
        body: Vec<u8>,
        trust: bool,
        customize: impl FnOnce(&mut crate::config::Config),
    ) -> (MockServer, TestContext) {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/packages/jason"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&up)
            .await;
        Mock::given(method("GET"))
            .and(path("/tarballs/jason-1.4.4.tar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(ARCHIVE))
            .mount(&up)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.hex.enabled = true;
            cfg.hex.proxy = Some(up.uri());
            cfg.hex.public_key_file = Some(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../tests/hex-client/fixtures/test-public.pem"
                )
                .into(),
            );
            cfg.server.trust_upstream_dates = trust;
            quarantine_7d(cfg);
            cfg.curation.min_release_age = Some("7d".into());
            customize(cfg);
        });
        (up, ctx)
    }
    async fn status(ctx: &TestContext) -> StatusCode {
        send(&ctx.app, Method::GET, DOWNLOAD, "").await.status()
    }
    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }
    fn checksum() -> Vec<u8> {
        sha2::Sha256::digest(ARCHIVE).to_vec()
    }

    #[tokio::test]
    async fn cooldown_exemption_allows_young_and_dateless_packages_and_cache_hits() {
        for (date, trust) in [(Some(now()), true), (None, true), (Some(now()), false)] {
            let (_up, ctx) = fixture_with_policy(record(date, &checksum()), trust, |cfg| {
                cfg.curation.hex.cooldown_exempt_packages = vec!["jason".into()];
            })
            .await;
            assert_eq!(status(&ctx).await, StatusCode::OK);
            assert_eq!(status(&ctx).await, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn cooldown_exemption_is_exact_and_preserves_blocklists_and_integrity() {
        for entry in ["jas", "jason_other"] {
            let (_up, ctx) = fixture_with_policy(record(Some(now()), &checksum()), true, |cfg| {
                cfg.curation.hex.cooldown_exempt_packages = vec![entry.into()];
            })
            .await;
            assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
        }
        let (_dir, blocklist) = crate::test_helpers::blocklist_file("hex", "jason");
        let (up, ctx) = fixture_with_policy(record(Some(now()), &checksum()), true, |cfg| {
            cfg.curation.hex.cooldown_exempt_packages = vec!["jason".into()];
            cfg.curation.blocklist_path = Some(blocklist);
        })
        .await;
        assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
        assert!(upstream_paths(&up).await.is_empty());
        for body in [record(Some(now()), &[0; 32]), RECORD.to_vec()] {
            let (_up, ctx) = fixture_with_policy(body, true, |cfg| {
                cfg.curation.hex.cooldown_exempt_packages = vec!["jason".into()];
            })
            .await;
            assert_eq!(status(&ctx).await, StatusCode::BAD_GATEWAY);
        }
    }

    #[tokio::test]
    async fn cooldown_exemption_preserves_allowlist_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("allowlist.json");
        std::fs::write(
            &file,
            r#"{"version":1,"entries":[{"registry":"hex","name":"other","version":"1.4.4"}]}"#,
        )
        .unwrap();
        let (up, ctx) = fixture_with_policy(record(Some(now()), &checksum()), true, |cfg| {
            cfg.curation.hex.cooldown_exempt_packages = vec!["jason".into()];
            cfg.curation.allowlist_path = Some(file.to_str().unwrap().into());
        })
        .await;
        assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
        assert!(upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn invalid_exemption_reload_preserves_previous_policy() {
        let (_up, ctx) = fixture(record(Some(now()), &checksum()), true).await;
        let (_dir, file) = crate::test_helpers::reload_file(&ctx, |cfg| {
            cfg.curation.hex.cooldown_exempt_packages = vec!["*".into()];
        });
        let result = {
            let _lock = crate::test_env::env_lock();
            let held = crate::HeldQuarantine::of(&ctx.state.config.curation);
            crate::reload_curation(&ctx.state.reloadable, &held, Some(file))
        };
        assert!(result.is_err());
        assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cooldown_exemption_reload_skips_existing_hold_and_removal_restores_it() {
        let (_up, ctx) = fixture(record(None, &checksum()), true).await;
        assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
        crate::test_helpers::reload_curation(&ctx, |cfg| {
            cfg.curation.hex.cooldown_exempt_packages = vec!["jason".into()];
        });
        assert_eq!(status(&ctx).await, StatusCode::OK);
        crate::test_helpers::reload_curation(&ctx, |cfg| {
            cfg.curation.hex.cooldown_exempt_packages.clear();
        });
        assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
    }

    #[test]
    fn official_record_verifies_and_contains_release_checksum_and_date() {
        let payload = verified_payload(RECORD, PUBLIC_KEY).unwrap();
        let pkg = Package::decode(payload.as_slice()).unwrap();
        let release = pkg.releases.iter().find(|r| r.version == "1.4.4").unwrap();
        assert_eq!(
            release.outer_checksum.as_deref(),
            Some(checksum().as_slice())
        );
        assert!(release.published_at.as_ref().unwrap().seconds > 0);
        assert!(verify_record(RECORD, PUBLIC_KEY, Some("jason")).is_ok());
        assert!(verify_record(RECORD, PUBLIC_KEY, Some("other")).is_err());
        assert!(verify_record(RECORD, PUBLIC, Some("jason")).is_err());
    }
    #[test]
    fn malformed_unsigned_wrong_origin_and_oversized_metadata_are_rejected() {
        assert!(verified_payload(b"not gzip", PUBLIC).is_err());
        let wrong = sign(
            Package {
                name: "jason".into(),
                repository: "other".into(),
                releases: vec![],
            }
            .encode_to_vec(),
        );
        assert!(verify_record(&wrong, PUBLIC, Some("jason")).is_err());
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(
            &Signed {
                payload: vec![0],
                signature: None,
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(verified_payload(&gzip.finish().unwrap(), PUBLIC).is_err());
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&vec![0; MAX_METADATA as usize + 1]).unwrap();
        assert!(verified_payload(&gzip.finish().unwrap(), PUBLIC).is_err());
    }
    #[tokio::test]
    async fn cold_tarball_primes_metadata_and_cached_download_stays_verified() {
        let body = record(Some(now() - 8 * 86400), &checksum());
        let (up, ctx) = fixture(body.clone(), true).await;
        assert_eq!(status(&ctx).await, StatusCode::OK);
        assert_eq!(status(&ctx).await, StatusCode::OK);
        assert_eq!(
            upstream_paths(&up).await,
            vec!["/packages/jason", "/tarballs/jason-1.4.4.tar"]
        );
        assert_eq!(
            ctx.state
                .storage
                .get("hex/packages/jason")
                .await
                .unwrap()
                .as_ref(),
            body
        );
        ctx.state
            .storage
            .put("hex/tarballs/jason-1.4.4.tar", b"corruption")
            .await
            .unwrap();
        assert_eq!(status(&ctx).await, StatusCode::BAD_GATEWAY);
    }
    #[tokio::test]
    async fn recent_and_future_releases_are_blocked_without_fetching_tarball() {
        for date in [now() - 6 * 86400, now() + 86400] {
            let (up, ctx) = fixture(record(Some(date), &checksum()), true).await;
            assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
            assert_eq!(upstream_paths(&up).await, vec!["/packages/jason"]);
        }
    }
    #[tokio::test]
    async fn missing_or_untrusted_dates_use_first_seen_quarantine() {
        for (date, trust) in [(None, true), (Some(now() - 30 * 86400), false)] {
            let (_up, ctx) = fixture(record(date, &checksum()), trust).await;
            assert_eq!(status(&ctx).await, StatusCode::FORBIDDEN);
        }
    }
    #[tokio::test]
    async fn wrong_checksum_and_untrusted_signature_fail_closed() {
        let (_up, ctx) = fixture(record(Some(now() - 30 * 86400), &[0; 32]), true).await;
        assert_eq!(status(&ctx).await, StatusCode::BAD_GATEWAY);
        let (up, ctx) = fixture(RECORD.to_vec(), true).await;
        assert_eq!(status(&ctx).await, StatusCode::BAD_GATEWAY);
        assert_eq!(upstream_paths(&up).await, vec!["/packages/jason"]);
    }
    #[tokio::test]
    async fn metadata_bytes_are_preserved_and_conditional_304_reuses_verified_copy() {
        let body = record(Some(now() - 30 * 86400), &checksum());
        let (up, ctx) = fixture(body.clone(), true).await;
        ctx.state
            .storage
            .put("hex/packages/jason", &body)
            .await
            .unwrap();
        crate::registry::write_validators(
            &ctx.state.storage,
            "hex/packages/jason",
            &crate::registry::Validators {
                etag: Some("\"test\"".into()),
                last_modified: None,
            },
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/packages/jason"))
            .and(header("if-none-match", "\"test\""))
            .respond_with(ResponseTemplate::new(304))
            .with_priority(1)
            .expect(1)
            .mount(&up)
            .await;
        assert_eq!(
            metadata(&ctx.state, "packages/jason", Some("jason"), true)
                .await
                .unwrap(),
            body
        );
    }
    #[tokio::test]
    async fn verified_stale_metadata_survives_outage_but_not_corruption() {
        let body = record(Some(now() - 30 * 86400), &checksum());
        let (up, ctx) = fixture(body.clone(), true).await;
        ctx.state
            .storage
            .put("hex/packages/jason", &body)
            .await
            .unwrap();
        up.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&up)
            .await;
        assert_eq!(
            metadata(&ctx.state, "packages/jason", Some("jason"), true)
                .await
                .unwrap(),
            body
        );
        ctx.state
            .storage
            .put("hex/packages/jason", b"corrupt")
            .await
            .unwrap();
        assert!(metadata(&ctx.state, "packages/jason", Some("jason"), true)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn internal_names_and_blocklists_never_contact_upstream() {
        let up = MockServer::start().await;
        let (_dir, blocklist) = crate::test_helpers::blocklist_file("hex", "jason");
        for local in [true, false] {
            let ctx = create_test_context_with_config(|cfg| {
                cfg.hex.enabled = true;
                cfg.hex.proxy = Some(up.uri());
                quarantine_7d(cfg);
                if local {
                    cfg.curation.internal_namespaces = vec!["jason".into()];
                } else {
                    cfg.curation.blocklist_path = Some(blocklist.clone());
                }
            });
            assert_ne!(status(&ctx).await, StatusCode::OK);
            assert!(upstream_paths(&up).await.is_empty());
        }
    }
    #[tokio::test]
    async fn unknown_version_refreshes_once_and_writes_are_rejected() {
        let (up, ctx) = fixture(record(Some(now() - 30 * 86400), &checksum()), true).await;
        assert_eq!(
            send(&ctx.app, Method::GET, "/hex/tarballs/jason-9.9.9.tar", "")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            upstream_paths(&up).await,
            vec!["/packages/jason", "/packages/jason"]
        );
        assert!(!send(&ctx.app, Method::PUT, DOWNLOAD, "bytes")
            .await
            .status()
            .is_success());
        assert_eq!(
            send(&ctx.app, Method::GET, "/hex/tarballs/jason-1%2F4.tar", "")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod bounds_tests {
    use super::*;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn upstream_body_cannot_exceed_limit() {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0; 64]))
            .mount(&up)
            .await;
        let ctx = create_test_context_with_config(|_| {});
        let result = crate::registry::proxy_fetch_conditional_bounded(
            &ctx.state.http_client,
            &up.uri(),
            Duration::from_secs(5),
            None,
            &crate::registry::Validators::default(),
            &ctx.state.circuit_breaker,
            RegistryType::Hex,
            32,
        )
        .await;
        assert!(result.is_err());
    }
}

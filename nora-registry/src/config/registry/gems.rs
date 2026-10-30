// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default = "default_gems_proxy",
        deserialize_with = "super::super::deserialize_upstream"
    )]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    /// Share checksum-keyed compact-index bodies between replicas; hot reads stay in memory.
    #[serde(default = "super::super::default_true")]
    pub info_checksum_cache: bool,
    /// Refresh /versions more frequently when cooldown-exempt gems are configured.
    #[serde(default = "default_exempt_metadata_ttl")]
    pub exempt_metadata_ttl: i64,
    /// Maximum residence time in the bounded per-process /info body cache.
    #[serde(default = "default_info_cache_ttl")]
    pub info_cache_ttl: i64,
    /// Downstream HTTP cache lifetime for successful /info responses, in seconds.
    #[serde(default = "default_info_http_max_age")]
    pub info_http_max_age: u64,
    /// Downstream lifetime for exact-name cooldown exemptions, in seconds.
    #[serde(default = "default_exempt_info_http_max_age")]
    pub exempt_info_http_max_age: u64,
    /// Downstream info stale while revalidate window in seconds; zero disables it.
    #[serde(default = "default_info_stale_while_revalidate")]
    pub info_stale_while_revalidate: u64,
    /// Downstream info stale if error window in seconds; zero disables it.
    #[serde(default = "default_info_stale_if_error")]
    pub info_stale_if_error: u64,
    /// Downstream exempt info stale while revalidate window in seconds; zero disables it.
    #[serde(default = "default_exempt_info_stale_while_revalidate")]
    pub exempt_info_stale_while_revalidate: u64,
    /// Downstream exempt info stale if error window in seconds; zero disables it.
    #[serde(default = "default_exempt_info_stale_if_error")]
    pub exempt_info_stale_if_error: u64,
    /// Downstream /versions stale while revalidate window in seconds; zero disables it.
    #[serde(default = "default_versions_stale_while_revalidate")]
    pub versions_stale_while_revalidate: u64,
    /// Downstream /versions stale if error window in seconds; zero disables it.
    #[serde(default = "default_versions_stale_if_error")]
    pub versions_stale_if_error: u64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Revalidate stale compact-index metadata with a conditional request
    /// (`If-None-Match` / `If-Modified-Since`) instead of always re-downloading
    /// the full body. Fail-open: any error falls back to a full fetch. RubyGems
    /// compact-index endpoints support validators, so a 304 avoids the download.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
}

fn default_exempt_metadata_ttl() -> i64 {
    60
}
fn default_info_cache_ttl() -> i64 {
    86400
}

fn default_info_http_max_age() -> u64 {
    86400
}
fn default_exempt_info_http_max_age() -> u64 {
    60
}

fn default_info_stale_while_revalidate() -> u64 {
    259200
}
fn default_info_stale_if_error() -> u64 {
    432000
}
fn default_exempt_info_stale_while_revalidate() -> u64 {
    259200
}
fn default_exempt_info_stale_if_error() -> u64 {
    432000
}

fn default_versions_stale_while_revalidate() -> u64 {
    259200
}
fn default_versions_stale_if_error() -> u64 {
    432000
}

fn default_gems_proxy() -> Option<String> {
    Some("https://rubygems.org".to_string())
}

impl Default for GemsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_gems_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            info_checksum_cache: true,
            exempt_metadata_ttl: default_exempt_metadata_ttl(),
            info_cache_ttl: default_info_cache_ttl(),
            info_http_max_age: default_info_http_max_age(),
            exempt_info_http_max_age: default_exempt_info_http_max_age(),
            info_stale_while_revalidate: default_info_stale_while_revalidate(),
            info_stale_if_error: default_info_stale_if_error(),
            exempt_info_stale_while_revalidate: default_exempt_info_stale_while_revalidate(),
            exempt_info_stale_if_error: default_exempt_info_stale_if_error(),
            versions_stale_while_revalidate: default_versions_stale_while_revalidate(),
            versions_stale_if_error: default_versions_stale_if_error(),
            serve_stale: true,
            revalidate: true,
        }
    }
}

impl GemsConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GEMS_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY") {
            self.proxy = super::super::upstream_setting(val);
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_GEMS_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_GEMS_METADATA_TTL") {
            super::super::parse_env_warn("NORA_GEMS_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_GEMS_INFO_CHECKSUM_CACHE") {
            self.info_checksum_cache = val == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GEMS_EXEMPT_METADATA_TTL") {
            super::super::parse_env_warn(
                "NORA_GEMS_EXEMPT_METADATA_TTL",
                &val,
                &mut self.exempt_metadata_ttl,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_INFO_CACHE_TTL") {
            super::super::parse_env_warn(
                "NORA_GEMS_INFO_CACHE_TTL",
                &val,
                &mut self.info_cache_ttl,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_INFO_HTTP_MAX_AGE") {
            super::super::parse_env_warn(
                "NORA_GEMS_INFO_HTTP_MAX_AGE",
                &val,
                &mut self.info_http_max_age,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_EXEMPT_INFO_HTTP_MAX_AGE") {
            super::super::parse_env_warn(
                "NORA_GEMS_EXEMPT_INFO_HTTP_MAX_AGE",
                &val,
                &mut self.exempt_info_http_max_age,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_INFO_STALE_WHILE_REVALIDATE") {
            super::super::parse_env_warn(
                "NORA_GEMS_INFO_STALE_WHILE_REVALIDATE",
                &val,
                &mut self.info_stale_while_revalidate,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_INFO_STALE_IF_ERROR") {
            super::super::parse_env_warn(
                "NORA_GEMS_INFO_STALE_IF_ERROR",
                &val,
                &mut self.info_stale_if_error,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_EXEMPT_INFO_STALE_WHILE_REVALIDATE") {
            super::super::parse_env_warn(
                "NORA_GEMS_EXEMPT_INFO_STALE_WHILE_REVALIDATE",
                &val,
                &mut self.exempt_info_stale_while_revalidate,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_EXEMPT_INFO_STALE_IF_ERROR") {
            super::super::parse_env_warn(
                "NORA_GEMS_EXEMPT_INFO_STALE_IF_ERROR",
                &val,
                &mut self.exempt_info_stale_if_error,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_VERSIONS_STALE_WHILE_REVALIDATE") {
            super::super::parse_env_warn(
                "NORA_GEMS_VERSIONS_STALE_WHILE_REVALIDATE",
                &val,
                &mut self.versions_stale_while_revalidate,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_VERSIONS_STALE_IF_ERROR") {
            super::super::parse_env_warn(
                "NORA_GEMS_VERSIONS_STALE_IF_ERROR",
                &val,
                &mut self.versions_stale_if_error,
            );
        }
        if let Ok(val) = env::var("NORA_GEMS_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_GEMS_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stale_directive_tests {
    use super::GemsConfig;

    #[test]
    fn defaults_and_old_config_enable_normal_exempt_and_versions_stale_windows() {
        for config in [
            GemsConfig::default(),
            toml::from_str::<GemsConfig>("").unwrap(),
        ] {
            assert_eq!(config.info_stale_while_revalidate, 259200);
            assert_eq!(config.info_stale_if_error, 432000);
            assert_eq!(config.exempt_info_stale_while_revalidate, 259200);
            assert_eq!(config.exempt_info_stale_if_error, 432000);
            assert_eq!(config.versions_stale_while_revalidate, 259200);
            assert_eq!(config.versions_stale_if_error, 432000);
        }
    }

    #[test]
    fn stale_windows_accept_zero_and_reject_negative_seconds() {
        let config: GemsConfig = toml::from_str("info_stale_while_revalidate = 0\ninfo_stale_if_error = 10\nexempt_info_stale_while_revalidate = 1\nexempt_info_stale_if_error = 2").unwrap();
        assert_eq!(config.info_stale_while_revalidate, 0);
        assert_eq!(config.info_stale_if_error, 10);
        assert_eq!(config.exempt_info_stale_while_revalidate, 1);
        assert_eq!(config.exempt_info_stale_if_error, 2);
        for field in [
            "info_stale_while_revalidate",
            "info_stale_if_error",
            "exempt_info_stale_while_revalidate",
            "exempt_info_stale_if_error",
            "versions_stale_while_revalidate",
            "versions_stale_if_error",
        ] {
            assert!(toml::from_str::<GemsConfig>(&format!("{field} = -1")).is_err());
        }
    }
}

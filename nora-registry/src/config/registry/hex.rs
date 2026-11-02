// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hex_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default)]
    pub public_key_file: Option<String>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Use stored ETag/Last-Modified validators when refreshing signed metadata.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
}

fn default_hex_proxy() -> Option<String> {
    Some("https://repo.hex.pm".to_string())
}

impl Default for HexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_hex_proxy(),
            proxy_auth: None,
            public_key_file: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate: true,
        }
    }
}

impl HexConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HEX_PUBLIC_KEY_FILE") {
            self.public_key_file = Some(val);
        }
        if let Ok(val) = env::var("NORA_HEX_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_HEX_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_HEX_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_HEX_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_HEX_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_HEX_METADATA_TTL") {
            super::super::parse_env_warn("NORA_HEX_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_HEX_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_HEX_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_opt_in_and_serde_defaults_match() {
        let direct = HexConfig::default();
        let parsed: HexConfig = toml::from_str("").unwrap();
        assert_eq!(
            serde_json::to_value(direct).unwrap(),
            serde_json::to_value(parsed).unwrap()
        );
        assert!(!HexConfig::default().enabled);
    }
    #[test]
    fn hex_cooldown_exemption_config_validates_exact_names_and_rejects_other_registries() {
        let _lock = crate::test_env::env_lock();
        for (name, valid) in [
            ("jason", true),
            ("wistia_player", true),
            ("*", false),
            ("jason*", false),
            ("@wistia", false),
            ("Jason", false),
            ("", false),
        ] {
            let mut cfg = crate::config::Config::default();
            cfg.curation.hex.cooldown_exempt_packages = vec![name.into()];
            let (_, errors) = cfg.validate();
            assert_eq!(
                errors
                    .iter()
                    .all(|e| !e.contains("cooldown_exempt_packages")),
                valid,
                "{name}: {errors:?}"
            );
        }
        let mut cfg = crate::config::Config::default();
        cfg.curation.npm.cooldown_exempt_packages = vec!["jason".into()];
        assert!(cfg
            .validate()
            .1
            .iter()
            .any(|e| e.contains("only supported for hex")));
    }

    #[test]
    fn hex_cooldown_exemption_env_is_comma_separated_and_empty_clears_it() {
        let _lock = crate::test_env::env_lock();
        let key = "NORA_CURATION_HEX_COOLDOWN_EXEMPT_PACKAGES";
        let old = std::env::var_os(key);
        let mut cfg = crate::config::CurationConfig::default();
        std::env::set_var(key, "jason, wistia_player");
        cfg.apply_env_overrides().unwrap();
        assert_eq!(
            cfg.hex.cooldown_exempt_packages,
            vec!["jason", "wistia_player"]
        );
        std::env::set_var(key, "");
        cfg.apply_env_overrides().unwrap();
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        assert!(cfg.hex.cooldown_exempt_packages.is_empty());
    }

    #[test]
    fn hex_env_overrides_are_applied() {
        let _lock = crate::test_env::env_lock();
        let old = std::env::var_os("NORA_HEX_METADATA_TTL");
        std::env::set_var("NORA_HEX_METADATA_TTL", "123");
        let mut cfg = HexConfig::default();
        cfg.apply_env_overrides();
        match old {
            Some(v) => std::env::set_var("NORA_HEX_METADATA_TTL", v),
            None => std::env::remove_var("NORA_HEX_METADATA_TTL"),
        }
        assert_eq!(cfg.metadata_ttl, 123);
    }
}

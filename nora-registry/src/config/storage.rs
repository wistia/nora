// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Storage backend configuration.

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageMode {
    #[default]
    Local,
    S3,
    Gcs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub mode: StorageMode,
    #[serde(default = "default_storage_path")]
    pub path: String,
    #[serde(default = "default_s3_url")]
    pub s3_url: String,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    /// S3 access key (optional, uses the AWS credential chain if not set).
    #[serde(default, skip_serializing)]
    pub s3_access_key: Option<ProtectedString>,
    /// S3 secret key (optional, uses the AWS credential chain if not set).
    #[serde(default, skip_serializing)]
    pub s3_secret_key: Option<ProtectedString>,
    /// S3 region (default: us-east-1)
    #[serde(default = "default_s3_region")]
    pub s3_region: String,
    /// Use virtual-hosted-style requests. Default: false (path-style, bucket appended
    /// to the endpoint path). When true, `s3_url` is used VERBATIM and must already
    /// include the bucket host, e.g. `https://<bucket>.oss-<region>.aliyuncs.com`.
    /// Some providers reject signed path-style requests entirely — e.g. Alibaba
    /// Cloud OSS answers them with 403 `SecondLevelDomainForbidden`.
    #[serde(default)]
    pub s3_virtual_hosted: bool,
    /// Disable S3 request signing for anonymous buckets or emulators.
    /// Default: false. Cannot be combined with explicit S3 credentials.
    #[serde(default)]
    pub s3_anonymous: bool,
    /// GCS: path to a service-account JSON key file. Unset = ambient
    /// credentials (GOOGLE_* env, then the instance metadata server — GKE
    /// Workload Identity / GCE service accounts need no key material).
    #[serde(default)]
    pub gcs_service_account_path: Option<String>,
    /// GCS: endpoint override for emulators or Private Google Access
    /// endpoints. Unset = https://storage.googleapis.com.
    /// Emulator-only caveat: an `http://` override also disables request
    /// signing — do not point this at a plaintext non-emulator endpoint.
    /// Writes still ask for a token, so against an emulator also set
    /// `gcs_service_account_path` to a key file with `"disable_oauth": true`
    /// (`private_key`, `private_key_id` and `client_email` must be present but
    /// are not used). The emulator must serve the GCS XML API, including
    /// object PUT and `x-goog-copy-source` copies: fake-gcs-server does not.
    #[serde(default)]
    pub gcs_base_url: Option<String>,
}

pub(super) fn default_s3_region() -> String {
    "us-east-1".to_string()
}

pub(super) fn default_storage_path() -> String {
    "data/storage".to_string()
}

pub(super) fn default_s3_url() -> String {
    "http://127.0.0.1:9000".to_string()
}

pub(super) fn default_bucket() -> String {
    "registry".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            mode: StorageMode::Local,
            path: default_storage_path(),
            s3_url: default_s3_url(),
            bucket: default_bucket(),
            s3_access_key: None,
            s3_secret_key: None,
            s3_region: default_s3_region(),
            s3_virtual_hosted: false,
            s3_anonymous: false,
            gcs_service_account_path: None,
            gcs_base_url: None,
        }
    }
}

impl StorageConfig {
    /// Apply environment variable overrides for storage config.
    ///
    /// Returns `Err` if `NORA_STORAGE_MODE` has an unrecognized value — fail-closed (#562).
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_STORAGE_MODE") {
            self.mode = match val.to_lowercase().as_str() {
                "local" | "filesystem" => StorageMode::Local,
                "s3" => StorageMode::S3,
                "gcs" => StorageMode::Gcs,
                other => {
                    return Err(format!(
                        "NORA_STORAGE_MODE={:?} is invalid — valid values: local, s3, gcs",
                        other
                    ))
                }
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_PATH") {
            self.path = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_URL") {
            self.s3_url = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_BUCKET") {
            self.bucket = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_GCS_SERVICE_ACCOUNT_PATH") {
            self.gcs_service_account_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_STORAGE_GCS_BASE_URL") {
            self.gcs_base_url = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_ACCESS_KEY") {
            self.s3_access_key = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_SECRET_KEY") {
            self.s3_secret_key = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_REGION") {
            self.s3_region = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_VIRTUAL_HOSTED") {
            self.s3_virtual_hosted = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_ANONYMOUS") {
            self.s3_anonymous = match val.to_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return Err("NORA_STORAGE_S3_ANONYMOUS must be true, false, 1, or 0".into()),
            };
        }

        Ok(())
    }

    pub(super) fn validate_s3_credentials(&self) -> Result<(), String> {
        if self.s3_access_key.is_some() != self.s3_secret_key.is_some() {
            return Err(
                "storage.s3_access_key and storage.s3_secret_key must be set together".into(),
            );
        }
        if self.s3_anonymous && self.s3_access_key.is_some() {
            return Err(
                "storage.s3_anonymous cannot be combined with explicit S3 credentials".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn s3_authentication_configuration_is_explicit() {
        let mut cfg: StorageConfig = toml::from_str("mode = \"s3\"").unwrap();
        assert!(!cfg.s3_anonymous);
        assert!(cfg.validate_s3_credentials().is_ok());
        cfg.s3_access_key = Some(ProtectedString::new("access".into()));
        assert!(cfg.validate_s3_credentials().is_err());
        cfg.s3_secret_key = Some(ProtectedString::new("secret".into()));
        assert!(cfg.validate_s3_credentials().is_ok());
        cfg.s3_anonymous = true;
        assert!(cfg.validate_s3_credentials().is_err());
        cfg.s3_access_key = None;
        assert!(cfg.validate_s3_credentials().is_err());
        cfg.s3_secret_key = None;
        assert!(cfg.validate_s3_credentials().is_ok());
    }

    #[test]
    fn s3_anonymous_env_requires_a_boolean() {
        let _lock = crate::test_env::env_lock();
        let saved = std::env::var_os("NORA_STORAGE_S3_ANONYMOUS");
        let mut cfg = StorageConfig::default();
        for (value, expected) in [("true", true), ("0", false), ("1", true), ("false", false)] {
            std::env::set_var("NORA_STORAGE_S3_ANONYMOUS", value);
            cfg.apply_env_overrides().unwrap();
            assert_eq!(cfg.s3_anonymous, expected);
        }
        std::env::set_var("NORA_STORAGE_S3_ANONYMOUS", "treu");
        let result = cfg.apply_env_overrides();
        match saved {
            Some(value) => std::env::set_var("NORA_STORAGE_S3_ANONYMOUS", value),
            None => std::env::remove_var("NORA_STORAGE_S3_ANONYMOUS"),
        }
        assert!(result.unwrap_err().contains("NORA_STORAGE_S3_ANONYMOUS"));
    }

    #[test]
    fn test_gcs_mode_parses_from_toml_and_env() {
        let _lock = crate::test_env::env_lock();
        let cfg: StorageConfig = toml::from_str("mode = \"gcs\"\nbucket = \"artifacts\"").unwrap();
        assert_eq!(cfg.mode, StorageMode::Gcs);
        assert_eq!(cfg.bucket, "artifacts");
        assert_eq!(cfg.gcs_service_account_path, None);
        assert_eq!(cfg.gcs_base_url, None);

        let mut cfg = StorageConfig::default();
        // config/mod.rs tests set NORA_STORAGE_MODE too; the env lock above serializes them.
        std::env::set_var("NORA_STORAGE_MODE", "gcs");
        std::env::set_var("NORA_STORAGE_GCS_SERVICE_ACCOUNT_PATH", "/sa.json");
        std::env::set_var("NORA_STORAGE_GCS_BASE_URL", "http://127.0.0.1:4443");
        let r = cfg.apply_env_overrides();
        std::env::remove_var("NORA_STORAGE_MODE");
        std::env::remove_var("NORA_STORAGE_GCS_SERVICE_ACCOUNT_PATH");
        std::env::remove_var("NORA_STORAGE_GCS_BASE_URL");
        r.unwrap();
        assert_eq!(cfg.mode, StorageMode::Gcs);
        assert_eq!(cfg.gcs_service_account_path.as_deref(), Some("/sa.json"));
        assert_eq!(cfg.gcs_base_url.as_deref(), Some("http://127.0.0.1:4443"));
    }

    #[test]
    fn test_unknown_mode_still_fails_closed() {
        let _lock = crate::test_env::env_lock();
        let mut cfg = StorageConfig::default();
        std::env::set_var("NORA_STORAGE_MODE", "azure");
        let r = cfg.apply_env_overrides();
        std::env::remove_var("NORA_STORAGE_MODE");
        let err = r.unwrap_err();
        assert!(err.contains("local, s3, gcs"), "{err}");
    }
}

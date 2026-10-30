// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Curation layer configuration.

use crate::digest_quarantine::QuarantineMode;
use crate::registry_type::RegistryType;
use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

/// Curation operating mode.
///
/// - `off` — curation disabled, all requests pass through (default)
/// - `audit` — evaluate filters and log decisions, but never block
/// - `enforce` — evaluate filters and block requests that match a deny rule
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationMode {
    #[default]
    Off,
    Audit,
    Enforce,
}

impl std::fmt::Display for CurationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurationMode::Off => write!(f, "off"),
            CurationMode::Audit => write!(f, "audit"),
            CurationMode::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for CurationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "audit" => Ok(Self::Audit),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "unknown curation mode {:?} — valid values: off, audit, enforce",
                other
            )),
        }
    }
}

/// Behavior when a curation filter returns an error or panics.
///
/// - `closed` — treat as blocked (fail-safe, default)
/// - `open` — treat as allowed (fail-open)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationOnFailure {
    #[default]
    Closed,
    Open,
}

/// Curation layer configuration.
///
/// # Environment Variables
/// - `NORA_CURATION_MODE` — off/audit/enforce (default: off)
/// - `NORA_CURATION_ON_FAILURE` — closed/open (default: closed)
/// - `NORA_CURATION_ALLOWLIST_PATH` — path to allowlist JSON file
/// - `NORA_CURATION_BLOCKLIST_PATH` — path to blocklist JSON file
/// - `NORA_CURATION_BYPASS_TOKEN` — token to bypass curation checks
/// - `NORA_CURATION_REQUIRE_INTEGRITY` — require integrity metadata (default: false)
/// - `NORA_CURATION_INTERNAL_NS` — comma-separated glob patterns
/// - `NORA_CURATION_MIN_RELEASE_AGE` — minimum release age (e.g., "7d", "24h", "1w")
/// - `NORA_CURATION_QUARANTINE` — quarantine mode: off/observe/enforce (default: off)
/// - `NORA_CURATION_QUARANTINE_TTL` — quarantine hold duration (e.g., "14d", "24h")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurationConfig {
    #[serde(default)]
    pub mode: CurationMode,
    /// Whether `mode` was written down (the config file or `NORA_CURATION_MODE`), rather than
    /// left at its default. An open proxy is the operator's decision only when it is (#1135).
    #[serde(skip)]
    pub mode_explicit: bool,
    #[serde(default)]
    pub on_failure: CurationOnFailure,
    #[serde(default)]
    pub allowlist_path: Option<String>,
    #[serde(default)]
    pub blocklist_path: Option<String>,
    /// Token to bypass curation. Should only be set via env var, not config file.
    #[serde(default, skip_serializing)]
    pub bypass_token: Option<ProtectedString>,
    #[serde(default)]
    pub require_integrity: bool,
    /// Glob patterns for internal namespaces that must never be proxied upstream.
    /// Always active regardless of curation mode (security boundary).
    #[serde(default)]
    pub internal_namespaces: Vec<String>,
    /// Minimum release age before a package is allowed (e.g., "7d", "24h", "1w").
    /// Packages published less than this duration ago are blocked.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// Digest quarantine mode: "off" (default), "observe", or "enforce".
    /// Tracks first-seen timestamps for proxy-fetched content digests.
    /// Invalid values are rejected at config parse time (ADR-8: security never silently disabled).
    #[serde(default)]
    pub quarantine: Option<QuarantineMode>,
    /// How long new digests are held in quarantine (e.g., "14d", "24h", "1w").
    #[serde(default)]
    pub quarantine_ttl: Option<String>,
    /// Per-registry curation overrides. Overrides `min_release_age` per registry.
    #[serde(default)]
    pub npm: RegistryCurationOverride,
    #[serde(default)]
    pub pypi: RegistryCurationOverride,
    #[serde(default)]
    pub cargo: RegistryCurationOverride,
    #[serde(default)]
    pub go: RegistryCurationOverride,
    #[serde(default)]
    pub docker: RegistryCurationOverride,
    #[serde(default)]
    pub maven: RegistryCurationOverride,
    #[serde(default)]
    pub gems: RegistryCurationOverride,
    #[serde(default)]
    pub terraform: RegistryCurationOverride,
    #[serde(default)]
    pub ansible: RegistryCurationOverride,
    #[serde(default)]
    pub nuget: RegistryCurationOverride,
    #[serde(rename = "pub", default)]
    pub pub_dart: RegistryCurationOverride,
    #[serde(default)]
    pub hex: RegistryCurationOverride,
    #[serde(default)]
    pub conan: RegistryCurationOverride,
    #[serde(default)]
    pub rpm: RegistryCurationOverride,
    #[serde(default)]
    pub deb: RegistryCurationOverride,
    #[serde(default)]
    pub cpan: RegistryCurationOverride,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownExemptVersion {
    pub name: String,
    pub version: String,
}

/// Per-registry curation override (used within `[curation.{registry}]`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryCurationOverride {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cooldown_exempt_versions: Vec<CooldownExemptVersion>,
    /// Override min_release_age for this specific registry.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// Override quarantine mode for this specific registry.
    #[serde(default)]
    pub quarantine: Option<QuarantineMode>,
    /// Override quarantine TTL for this specific registry.
    #[serde(default)]
    pub quarantine_ttl: Option<String>,
    /// Exact Hex or RubyGems package names exempt from release age and digest quarantine.
    /// Only supported for Hex and Gems; other registry sections reject non-empty lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cooldown_exempt_packages: Vec<String>,
    /// Literal npm scope or Go module path prefixes, including the trailing slash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cooldown_exempt_prefixes: Vec<String>,
}

fn valid_exempt_identity(registry: RegistryType, name: &str, version: &str) -> bool {
    let component = |value: &str| {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    };
    let valid_name = match registry {
        RegistryType::Npm => {
            name.len() <= 214
                && if let Some(scoped) = name.strip_prefix('@') {
                    scoped
                        .split_once('/')
                        .is_some_and(|(scope, package)| component(scope) && component(package))
                } else {
                    component(name)
                }
        }
        RegistryType::Go => name.contains('.') && name.split('/').all(component),
        RegistryType::Hex => {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        }
        RegistryType::Gems => {
            name.len() <= 256 && component(name) && !name.contains('~') && !name.contains("..")
        }
        _ => false,
    };
    valid_name
        && match registry {
            RegistryType::Npm => crate::curation::npm_version_key(version).is_some(),
            RegistryType::Go => crate::curation::go_version_key(version).is_some(),
            RegistryType::Hex => crate::curation::pub_version_key(version).is_some(),
            RegistryType::Gems => {
                version.len() <= 256
                    && version.split('.').enumerate().all(|(index, segment)| {
                        !segment.is_empty()
                            && segment.bytes().all(|b| {
                                if index == 0 {
                                    b.is_ascii_digit()
                                } else {
                                    b.is_ascii_alphanumeric()
                                }
                            })
                    })
            }
            _ => false,
        }
}

impl Default for CurationConfig {
    fn default() -> Self {
        Self {
            mode: CurationMode::Off,
            mode_explicit: false,
            on_failure: CurationOnFailure::Closed,
            allowlist_path: None,
            blocklist_path: None,
            bypass_token: None,
            require_integrity: false,
            internal_namespaces: Vec::new(),
            min_release_age: None,
            quarantine: None,
            quarantine_ttl: None,
            npm: RegistryCurationOverride::default(),
            pypi: RegistryCurationOverride::default(),
            cargo: RegistryCurationOverride::default(),
            go: RegistryCurationOverride::default(),
            docker: RegistryCurationOverride::default(),
            maven: RegistryCurationOverride::default(),
            gems: RegistryCurationOverride::default(),
            terraform: RegistryCurationOverride::default(),
            ansible: RegistryCurationOverride::default(),
            nuget: RegistryCurationOverride::default(),
            pub_dart: RegistryCurationOverride::default(),
            hex: RegistryCurationOverride::default(),
            conan: RegistryCurationOverride::default(),
            rpm: RegistryCurationOverride::default(),
            deb: RegistryCurationOverride::default(),
            cpan: RegistryCurationOverride::default(),
        }
    }
}

impl CurationConfig {
    /// The `[curation.<registry>]` section of `rt`; `None` for Raw and Hugging Face,
    /// which have none.
    ///
    /// The `match` is exhaustive over [`RegistryType`], so a new registry is a
    /// compile error here until its section is declared — a hand-written list of
    /// sections once left out rpm, deb and cpan, and their `min_release_age` was
    /// read by nothing (#1098).
    pub fn registry_override(&self, rt: RegistryType) -> Option<&RegistryCurationOverride> {
        match rt {
            RegistryType::Docker => Some(&self.docker),
            RegistryType::Maven => Some(&self.maven),
            RegistryType::Npm => Some(&self.npm),
            RegistryType::Cargo => Some(&self.cargo),
            RegistryType::PyPI => Some(&self.pypi),
            RegistryType::Go => Some(&self.go),
            RegistryType::Raw => None,
            RegistryType::Gems => Some(&self.gems),
            RegistryType::Terraform => Some(&self.terraform),
            RegistryType::Ansible => Some(&self.ansible),
            RegistryType::Nuget => Some(&self.nuget),
            RegistryType::PubDart => Some(&self.pub_dart),
            RegistryType::Hex => Some(&self.hex),
            RegistryType::Conan => Some(&self.conan),
            RegistryType::Rpm => Some(&self.rpm),
            RegistryType::Deb => Some(&self.deb),
            RegistryType::Cpan => Some(&self.cpan),
            RegistryType::HuggingFace => None,
        }
    }

    /// The settings a SIGHUP reload does not apply, keyed as config.toml spells them, with
    /// their values: the digest quarantine, global and each registry's own.
    ///
    /// A reload swaps the curation engine, rebuilt from the file, and the bypass token. The
    /// digest quarantine is not in either: each format reads it from the configuration NORA
    /// started with, and the start decides whether the store of first-seen digests is loaded
    /// at all. A key is listed whether it is set or not, so a key removed from the file differs
    /// from the one NORA started with as a key set or changed does.
    ///
    /// The destructuring names every field, so a new key does not compile until it is
    /// placed on one side.
    pub fn unreloaded_settings(&self) -> Vec<(String, String)> {
        let Self {
            // In the engine a reload builds, or the bypass token it swaps.
            mode: _,
            allowlist_path: _,
            blocklist_path: _,
            bypass_token: _,
            require_integrity: _,
            internal_namespaces: _,
            min_release_age: _,
            // Whether `mode` was written down: read once, for the notice at start.
            mode_explicit: _,
            // Validation refuses any value but `closed`, and with it the reload.
            on_failure: _,
            quarantine,
            quarantine_ttl,
            // A registry's own section, walked below through `registry_override`.
            npm: _,
            pypi: _,
            cargo: _,
            go: _,
            docker: _,
            maven: _,
            gems: _,
            terraform: _,
            ansible: _,
            nuget: _,
            pub_dart: _,
            hex: _,
            conan: _,
            rpm: _,
            deb: _,
            cpan: _,
        } = self;
        let mut settings = vec![
            ("curation.quarantine".to_string(), format!("{quarantine:?}")),
            (
                "curation.quarantine_ttl".to_string(),
                format!("{quarantine_ttl:?}"),
            ),
        ];
        for &rt in RegistryType::all() {
            let Some(own) = self.registry_override(rt) else {
                continue;
            };
            let RegistryCurationOverride {
                // In the engine a reload builds.
                min_release_age: _,
                cooldown_exempt_packages: _,
                cooldown_exempt_prefixes: _,
                cooldown_exempt_versions: _,
                quarantine,
                quarantine_ttl,
            } = own;
            settings.push((
                format!("curation.{rt}.quarantine"),
                format!("{quarantine:?}"),
            ));
            settings.push((
                format!("curation.{rt}.quarantine_ttl"),
                format!("{quarantine_ttl:?}"),
            ));
        }
        settings
    }

    /// Test-only: [`Self::registry_override`] to change, for tests that set a section of every
    /// registry in turn.
    #[cfg(test)]
    pub(crate) fn registry_override_mut(
        &mut self,
        rt: RegistryType,
    ) -> Option<&mut RegistryCurationOverride> {
        match rt {
            RegistryType::Docker => Some(&mut self.docker),
            RegistryType::Maven => Some(&mut self.maven),
            RegistryType::Npm => Some(&mut self.npm),
            RegistryType::Cargo => Some(&mut self.cargo),
            RegistryType::PyPI => Some(&mut self.pypi),
            RegistryType::Go => Some(&mut self.go),
            RegistryType::Raw => None,
            RegistryType::Gems => Some(&mut self.gems),
            RegistryType::Terraform => Some(&mut self.terraform),
            RegistryType::Ansible => Some(&mut self.ansible),
            RegistryType::Nuget => Some(&mut self.nuget),
            RegistryType::PubDart => Some(&mut self.pub_dart),
            RegistryType::Hex => Some(&mut self.hex),
            RegistryType::Conan => Some(&mut self.conan),
            RegistryType::Rpm => Some(&mut self.rpm),
            RegistryType::Deb => Some(&mut self.deb),
            RegistryType::Cpan => Some(&mut self.cpan),
            RegistryType::HuggingFace => None,
        }
    }

    /// Match cooldown exemptions without bypassing other curation filters.
    pub fn cooldown_exempt(&self, registry: RegistryType, name: &str) -> bool {
        let Some(section) = self.registry_override(registry) else {
            return false;
        };
        (matches!(registry, RegistryType::Hex | RegistryType::Gems)
            && section.cooldown_exempt_packages.iter().any(|p| p == name))
            || (matches!(registry, RegistryType::Npm | RegistryType::Go)
                && section
                    .cooldown_exempt_prefixes
                    .iter()
                    .any(|p| !p.is_empty() && p.ends_with('/') && name.starts_with(p)))
    }

    pub fn cooldown_exempt_version(
        &self,
        registry: RegistryType,
        name: &str,
        version: Option<&str>,
    ) -> bool {
        self.cooldown_exempt(registry, name)
            || version.is_some_and(|version| {
                self.registry_override(registry).is_some_and(|section| {
                    section.cooldown_exempt_versions.iter().any(|entry| {
                        crate::curation::curation_name(registry, &entry.name)
                            == crate::curation::curation_name(registry, name)
                            && crate::curation::curation_version(registry, &entry.version)
                                == crate::curation::curation_version(registry, version)
                    })
                })
            })
    }

    /// Validate exemption declarations at startup and on curation reload.
    pub fn cooldown_exemption_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for &registry in RegistryType::all() {
            if let Some(section) = self.registry_override(registry) {
                for entry in &section.cooldown_exempt_versions {
                    if !valid_exempt_identity(registry, &entry.name, &entry.version) {
                        errors.push(format!("curation.{registry}.cooldown_exempt_versions requires exact names and versions for npm, go, hex or gems"));
                    }
                }

                for prefix in &section.cooldown_exempt_prefixes {
                    let valid = match registry {
                        RegistryType::Npm => prefix
                            .strip_prefix('@')
                            .and_then(|p| p.strip_suffix('/'))
                            .is_some_and(|scope| {
                                !scope.is_empty()
                                    && scope.bytes().all(|b| {
                                        b.is_ascii_lowercase()
                                            || b.is_ascii_digit()
                                            || b"-._~".contains(&b)
                                    })
                            }),
                        RegistryType::Go => {
                            prefix.ends_with('/')
                                && prefix.contains('.')
                                && prefix.split('/').rev().skip(1).all(|part| {
                                    !part.is_empty()
                                        && part != "."
                                        && part != ".."
                                        && part.bytes().all(|b| {
                                            b.is_ascii_alphanumeric() || b".-_~".contains(&b)
                                        })
                                })
                        }
                        _ => false,
                    };
                    if !valid {
                        errors.push(format!("curation.{registry}.cooldown_exempt_prefixes: {prefix:?} must be a literal npm scope or Go module prefix ending in / (npm and go only)"));
                    }
                }
                for name in &section.cooldown_exempt_packages {
                    if registry == RegistryType::Gems {
                        if name.is_empty()
                            || name.len() > 256
                            || name.contains("..")
                            || !name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                        {
                            errors.push(format!("curation.gems.cooldown_exempt_packages: {name:?} must be an exact RubyGems package name (no wildcards or paths)"));
                        }
                    } else if registry != RegistryType::Hex {
                        errors.push(format!("curation.{registry}.cooldown_exempt_packages is only supported for hex and gems"));
                    } else if name.is_empty()
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        errors.push(format!("curation.hex.cooldown_exempt_packages: {name:?} must be an exact lowercase Hex package name (no wildcards or scopes)"));
                    }
                }
            }
        }

        errors
    }

    /// Apply environment variable overrides for curation config.
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(value) = env::var("NORA_CURATION_GEMS_COOLDOWN_EXEMPT_PACKAGES") {
            self.gems.cooldown_exempt_packages = value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Ok(value) = env::var("NORA_CURATION_HEX_COOLDOWN_EXEMPT_PACKAGES") {
            self.hex.cooldown_exempt_packages = if value.trim().is_empty() {
                Vec::new()
            } else {
                value
                    .split(',')
                    .map(|name| name.trim().to_owned())
                    .collect()
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_MODE") {
            self.mode = val
                .parse::<CurationMode>()
                .map_err(|e| format!("NORA_CURATION_MODE={:?}: {}", val, e))?;
            self.mode_explicit = true;
        }
        if let Ok(val) = env::var("NORA_CURATION_ON_FAILURE") {
            self.on_failure = match val.to_lowercase().as_str() {
                "open" => CurationOnFailure::Open,
                _ => CurationOnFailure::Closed,
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_ALLOWLIST_PATH") {
            self.allowlist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BLOCKLIST_PATH") {
            self.blocklist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BYPASS_TOKEN") {
            self.bypass_token = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_REQUIRE_INTEGRITY") {
            self.require_integrity = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CURATION_INTERNAL_NS") {
            self.internal_namespaces = if val.is_empty() {
                Vec::new()
            } else {
                val.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_MIN_RELEASE_AGE") {
            self.min_release_age = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_QUARANTINE") {
            self.quarantine = if val.is_empty() {
                None
            } else {
                Some(
                    val.parse::<QuarantineMode>()
                        .map_err(|e| format!("NORA_CURATION_QUARANTINE={:?}: {}", val, e))?,
                )
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_QUARANTINE_TTL") {
            self.quarantine_ttl = if val.is_empty() { None } else { Some(val) };
        }

        // Per-registry curation overrides
        for (env_suffix, field) in [
            ("NPM", &mut self.npm),
            ("PYPI", &mut self.pypi),
            ("CARGO", &mut self.cargo),
            ("GO", &mut self.go),
            ("DOCKER", &mut self.docker),
            ("MAVEN", &mut self.maven),
            ("GEMS", &mut self.gems),
            ("TERRAFORM", &mut self.terraform),
            ("ANSIBLE", &mut self.ansible),
            ("NUGET", &mut self.nuget),
            ("PUB", &mut self.pub_dart),
            ("HEX", &mut self.hex),
            ("CONAN", &mut self.conan),
            ("RPM", &mut self.rpm),
            ("DEB", &mut self.deb),
            ("CPAN", &mut self.cpan),
        ] {
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_MIN_RELEASE_AGE", env_suffix)) {
                field.min_release_age = if val.is_empty() { None } else { Some(val) };
            }
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_QUARANTINE", env_suffix)) {
                field.quarantine = if val.is_empty() {
                    None
                } else {
                    Some(val.parse::<QuarantineMode>().map_err(|e| {
                        format!("NORA_CURATION_{}_QUARANTINE={:?}: {}", env_suffix, val, e)
                    })?)
                };
            }
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_QUARANTINE_TTL", env_suffix)) {
                field.quarantine_ttl = if val.is_empty() { None } else { Some(val) };
            }
        }

        Ok(())
    }

    /// Every `min_release_age` and `quarantine_ttl`, global and per registry, that
    /// does not parse as a duration, named by key and value. A configuration error
    /// in every mode (#1099): the quarantine fell back to 14 days on one without a
    /// word, and outside enforce mode an unparsable minimum age was only logged.
    pub fn duration_errors(&self) -> Vec<String> {
        let mut durations = vec![
            (
                "curation.min_release_age".to_string(),
                self.min_release_age.as_deref(),
            ),
            (
                "curation.quarantine_ttl".to_string(),
                self.quarantine_ttl.as_deref(),
            ),
        ];
        for &rt in RegistryType::all() {
            if let Some(section) = self.registry_override(rt) {
                durations.push((
                    format!("curation.{rt}.min_release_age"),
                    section.min_release_age.as_deref(),
                ));
                durations.push((
                    format!("curation.{rt}.quarantine_ttl"),
                    section.quarantine_ttl.as_deref(),
                ));
            }
        }
        durations
            .into_iter()
            .filter_map(|(key, value)| {
                let value = value?;
                let error = crate::curation::parse_duration(value).err()?;
                Some(format!("{key}=\"{value}\" is not a duration: {error}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    #[test]
    fn gems_exemptions_are_exact_names_not_prefixes_or_patterns() {
        let mut cfg = CurationConfig::default();
        cfg.gems.cooldown_exempt_packages = vec!["private_gem".into(), "Acme.Tool".into()];
        assert!(cfg.cooldown_exemption_errors().is_empty());
        assert!(cfg.cooldown_exempt(RegistryType::Gems, "private_gem"));
        assert!(cfg.cooldown_exempt(RegistryType::Gems, "Acme.Tool"));
        assert!(!cfg.cooldown_exempt(RegistryType::Gems, "private_gem_other"));
        assert!(!cfg.cooldown_exempt(RegistryType::Gems, "acme.tool"));
        assert!(!cfg.cooldown_exempt(RegistryType::Hex, "private_gem"));
        for bad in ["", "*", "acme/*", "../secret", "a..b"] {
            cfg.gems.cooldown_exempt_packages = vec![bad.into()];
            assert!(!cfg.cooldown_exemption_errors().is_empty(), "{bad}");
        }
    }

    #[test]
    fn cooldown_prefixes_are_registry_specific_and_bounded() {
        let mut cfg = CurationConfig::default();
        cfg.npm.cooldown_exempt_prefixes = vec!["@wistia/".into()];
        cfg.go.cooldown_exempt_prefixes = vec!["github.com/wistia/".into()];
        assert!(cfg.cooldown_exemption_errors().is_empty());
        assert!(cfg.cooldown_exempt(RegistryType::Npm, "@wistia/player"));
        assert!(!cfg.cooldown_exempt(RegistryType::Npm, "@wistia-other/player"));
        assert!(!cfg.cooldown_exempt(RegistryType::Gems, "@wistia/player"));
        assert!(cfg.cooldown_exempt(RegistryType::Go, "github.com/wistia/pkg/v2"));
        assert!(!cfg.cooldown_exempt(RegistryType::Go, "github.com/wistia-other/pkg"));
        for bad in ["", "@wistia", "*", "@wistia/*", "@wistia/pkg/"] {
            cfg.npm.cooldown_exempt_prefixes = vec![bad.into()];
            assert!(!cfg.cooldown_exemption_errors().is_empty(), "{bad:?}");
        }
        cfg.npm.cooldown_exempt_prefixes.clear();
        for bad in [
            "",
            "github.com/wistia",
            "github.com/*/",
            "github.com/../",
            "/",
        ] {
            cfg.go.cooldown_exempt_prefixes = vec![bad.into()];
            assert!(!cfg.cooldown_exemption_errors().is_empty(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod exact_version_tests {
    use super::*;

    fn config(registry: RegistryType, name: &str, version: &str) -> CurationConfig {
        let mut config = CurationConfig::default();
        config
            .registry_override_mut(registry)
            .unwrap()
            .cooldown_exempt_versions
            .push(CooldownExemptVersion {
                name: name.into(),
                version: version.into(),
            });
        config
    }

    #[test]
    fn exact_versions_are_registry_specific_and_normalized() {
        for (registry, name, version, spelling, sibling) in [
            (
                RegistryType::Gems,
                "example",
                "1.2.3.pre",
                "1.2.3.pre",
                "1.2.4",
            ),
            (
                RegistryType::Npm,
                "@wistia/example",
                "1.2.3",
                "v1.2.3",
                "1.2.4",
            ),
            (
                RegistryType::Go,
                "github.com/Example/module",
                "v1.2",
                "v1.2.0",
                "v1.2.1",
            ),
            (RegistryType::Hex, "example", "1.2.3", "1.2.3", "1.2.4"),
        ] {
            let config = config(registry, name, version);
            assert!(config.cooldown_exemption_errors().is_empty());
            assert!(config.cooldown_exempt_version(registry, name, Some(spelling)));
            assert!(!config.cooldown_exempt_version(registry, name, Some(sibling)));
            assert!(!config.cooldown_exempt_version(registry, "other", Some(spelling)));
            assert!(!config.cooldown_exempt_version(registry, name, None));
            for other in [
                RegistryType::Gems,
                RegistryType::Npm,
                RegistryType::Go,
                RegistryType::Hex,
            ] {
                if registry != other {
                    assert!(!config.cooldown_exempt_version(other, name, Some(spelling)));
                }
            }
        }
        assert!(valid_exempt_identity(
            RegistryType::Go,
            "github.com/example/module",
            "v0.0.0-20260101120000-abcdef123456"
        ));
    }

    #[test]
    fn malformed_and_unsupported_entries_are_refused() {
        for (registry, name, version) in [
            (RegistryType::Go, "github.com/example/module", "1.2.3"),
            (RegistryType::Go, "example", "v1.2.3"),
            (RegistryType::Npm, "example", "1.x"),
            (RegistryType::Npm, "example", "latest"),
            (RegistryType::Npm, "@scope/*", "1.2.3"),
            (RegistryType::Hex, "Bad/Name", "1.2.3"),
            (RegistryType::Gems, "example", "/bad"),
            (RegistryType::Gems, "example", "latest"),
            (RegistryType::Gems, "example", ""),
            (RegistryType::Cargo, "example", "1.2.3"),
        ] {
            assert!(
                !config(registry, name, version)
                    .cooldown_exemption_errors()
                    .is_empty(),
                "{registry}: {name}@{version}"
            );
        }
    }
}

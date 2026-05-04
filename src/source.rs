//! Typed config source provenance.
//!
//! `ConfigSource` catalogs the *kind* of every layer in a [`crate::ProviderChain`]
//! — defaults, env vars, files — so consumers can answer "where did this
//! value come from?" without parsing logs or re-walking discovery. Every
//! `with_*` builder on `ProviderChain` pushes a `ConfigSource`; the chain
//! exposes them in merge order (lowest priority first).
//!
//! The variants are `#[non_exhaustive]` so future additions (HTTP, Vault,
//! `ConfigMap`, etc.) can land without breaking consumers that match.

use std::fmt;
use std::path::{Path, PathBuf};

/// A single layer in a config provider chain.
///
/// Variants are emitted in merge order (lowest priority first, highest
/// priority last). The closed enum makes the universe of source kinds
/// structural: a misspelled or fabricated source cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigSource {
    /// Serde-serialized defaults injected via
    /// [`crate::ProviderChain::with_defaults`].
    Defaults,
    /// Environment variables under the given prefix
    /// (e.g. `"MYAPP_"`). Empty prefix means no namespace.
    Env(String),
    /// A config file on disk. The format is auto-detected from the
    /// extension by [`crate::ProviderChain::with_file`].
    File(PathBuf),
}

impl ConfigSource {
    /// Returns the file path if this source is a [`ConfigSource::File`].
    #[must_use]
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::File(p) => Some(p.as_path()),
            _ => None,
        }
    }

    /// Returns the env-var prefix if this source is a [`ConfigSource::Env`].
    #[must_use]
    pub fn as_env_prefix(&self) -> Option<&str> {
        match self {
            Self::Env(prefix) => Some(prefix.as_str()),
            _ => None,
        }
    }

    /// Returns `true` for [`ConfigSource::File`].
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Returns `true` for [`ConfigSource::Env`].
    #[must_use]
    pub fn is_env(&self) -> bool {
        matches!(self, Self::Env(_))
    }

    /// Returns `true` for [`ConfigSource::Defaults`].
    #[must_use]
    pub fn is_defaults(&self) -> bool {
        matches!(self, Self::Defaults)
    }

    /// Canonical `figment::Metadata::name` shape emitted by
    /// [`figment::providers::Env`]: `` `PREFIX` environment variable(s) ``
    /// for prefixed providers, `"environment variable(s)"` for raw env
    /// (no prefix). Mirrors figment's `Env::metadata` impl one-to-one,
    /// including the prefix-uppercasing discipline.
    ///
    /// Empty `prefix` yields the bare shape; non-empty `prefix` yields
    /// the backtick-wrapped form with the prefix uppercased to match
    /// figment's emission.
    ///
    /// One source of truth for the env-provider metadata-name shape on
    /// the shikumi side: providers (figment) emit it, the
    /// failing-source resolver inverts it via [`Self::strip_env_metadata_name`],
    /// and tests round-trip both directions through one definition.
    #[must_use]
    pub fn env_metadata_name(prefix: &str) -> String {
        if prefix.is_empty() {
            "environment variable(s)".to_owned()
        } else {
            format!("`{}` environment variable(s)", prefix.to_ascii_uppercase())
        }
    }

    /// Inverse of [`Self::env_metadata_name`]: recognize a
    /// `figment::Metadata::name` as a `figment::providers::Env`-shaped
    /// tag and recover the (uppercased) prefix when present.
    ///
    /// Returns:
    /// - `Some(EnvMetadataTag::Prefixed(prefix))` for
    ///   `` `PREFIX` environment variable(s) ``. The returned slice is
    ///   borrowed into `name` (no allocation) and carries figment's
    ///   uppercased prefix verbatim — callers matching against a
    ///   recorded [`ConfigSource::Env`] must compare with
    ///   [`str::eq_ignore_ascii_case`] since users may pass mixed-case
    ///   prefixes to [`crate::ProviderChain::with_env`].
    /// - `Some(EnvMetadataTag::Bare)` for `"environment variable(s)"`
    ///   (no prefix; figment's `Env::raw()` shape).
    /// - `None` for any other metadata name (file-path tags from
    ///   figment's YAML/TOML providers, shikumi-built provider tags
    ///   recognized by [`crate::Format::strip_metadata_name`], unrelated
    ///   names, or the empty string).
    ///
    /// Used by [`crate::ShikumiError::failing_source`] to map figment
    /// per-value metadata back to a [`ConfigSource::Env`] entry in the
    /// recorded chain without re-implementing the figment-side shape.
    #[must_use]
    pub fn strip_env_metadata_name(name: &str) -> Option<EnvMetadataTag<'_>> {
        if !name.contains("environment variable") {
            return None;
        }
        if let Some(rest) = name.strip_prefix('`')
            && let Some(end) = rest.find('`')
        {
            return Some(EnvMetadataTag::Prefixed(&rest[..end]));
        }
        Some(EnvMetadataTag::Bare)
    }
}

/// Recognized form of [`figment::providers::Env`]'s
/// `figment::Metadata::name`, as parsed by
/// [`ConfigSource::strip_env_metadata_name`].
///
/// The closed enum makes the env-tag shape space structural: any
/// figment env metadata name maps to exactly one variant (or to `None`
/// if it isn't an env tag at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnvMetadataTag<'a> {
    /// `` `PREFIX` environment variable(s) `` — figment emitted the
    /// prefix uppercased; the borrowed slice carries it verbatim.
    Prefixed(&'a str),
    /// `environment variable(s)` — `figment::providers::Env::raw()`
    /// shape (no prefix).
    Bare,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Defaults => f.write_str("defaults"),
            Self::Env(prefix) if prefix.is_empty() => f.write_str("env"),
            Self::Env(prefix) => write!(f, "env({prefix})"),
            Self::File(path) => write!(f, "file({})", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_display() {
        assert_eq!(ConfigSource::Defaults.to_string(), "defaults");
    }

    #[test]
    fn env_display_with_prefix() {
        let s = ConfigSource::Env("MYAPP_".to_owned());
        assert_eq!(s.to_string(), "env(MYAPP_)");
    }

    #[test]
    fn env_display_empty_prefix() {
        assert_eq!(ConfigSource::Env(String::new()).to_string(), "env");
    }

    #[test]
    fn file_display_includes_path() {
        let s = ConfigSource::File(PathBuf::from("/etc/app/app.yaml"));
        assert_eq!(s.to_string(), "file(/etc/app/app.yaml)");
    }

    #[test]
    fn as_path_returns_path_for_file_only() {
        let f = ConfigSource::File(PathBuf::from("/x.yaml"));
        assert_eq!(f.as_path(), Some(Path::new("/x.yaml")));
        assert_eq!(ConfigSource::Defaults.as_path(), None);
        assert_eq!(ConfigSource::Env("X_".to_owned()).as_path(), None);
    }

    #[test]
    fn as_env_prefix_returns_prefix_for_env_only() {
        let e = ConfigSource::Env("APP_".to_owned());
        assert_eq!(e.as_env_prefix(), Some("APP_"));
        assert_eq!(ConfigSource::Defaults.as_env_prefix(), None);
        assert_eq!(
            ConfigSource::File(PathBuf::from("/x")).as_env_prefix(),
            None
        );
    }

    #[test]
    fn predicates_match_one_variant_each() {
        let f = ConfigSource::File(PathBuf::from("/a"));
        let e = ConfigSource::Env("E_".to_owned());
        let d = ConfigSource::Defaults;

        assert!(f.is_file() && !f.is_env() && !f.is_defaults());
        assert!(!e.is_file() && e.is_env() && !e.is_defaults());
        assert!(!d.is_file() && !d.is_env() && d.is_defaults());
    }

    #[test]
    fn equality_and_hash_distinguish_variants() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(ConfigSource::Defaults);
        set.insert(ConfigSource::Env("X_".to_owned()));
        set.insert(ConfigSource::Env("X_".to_owned())); // duplicate
        set.insert(ConfigSource::File(PathBuf::from("/a.yaml")));

        assert_eq!(set.len(), 3, "duplicate env entries should collapse");
        assert!(set.contains(&ConfigSource::Defaults));
    }

    #[test]
    fn clone_preserves_data() {
        let s = ConfigSource::File(PathBuf::from("/a/b.yaml"));
        let c = s.clone();
        assert_eq!(s, c);
    }

    // ---- env_metadata_name / strip_env_metadata_name ----

    #[test]
    fn env_metadata_name_empty_prefix_yields_bare_shape() {
        // Mirrors figment's `Env::raw()` shape (no backtick wrapper).
        assert_eq!(
            ConfigSource::env_metadata_name(""),
            "environment variable(s)"
        );
    }

    #[test]
    fn env_metadata_name_uppercases_prefix_to_match_figment() {
        // figment uppercases the prefix when emitting metadata; the
        // constructor must match that discipline so round-trip works
        // regardless of the casing the user passed to `with_env`.
        assert_eq!(
            ConfigSource::env_metadata_name("myapp_"),
            "`MYAPP_` environment variable(s)"
        );
        assert_eq!(
            ConfigSource::env_metadata_name("MyApp_"),
            "`MYAPP_` environment variable(s)"
        );
        assert_eq!(
            ConfigSource::env_metadata_name("APP_"),
            "`APP_` environment variable(s)"
        );
    }

    #[test]
    fn strip_env_metadata_name_recognizes_prefixed_shape() {
        let tag = ConfigSource::strip_env_metadata_name("`MYAPP_` environment variable(s)");
        assert_eq!(tag, Some(EnvMetadataTag::Prefixed("MYAPP_")));
    }

    #[test]
    fn strip_env_metadata_name_recognizes_bare_shape() {
        let tag = ConfigSource::strip_env_metadata_name("environment variable(s)");
        assert_eq!(tag, Some(EnvMetadataTag::Bare));
    }

    #[test]
    fn strip_env_metadata_name_accepts_singular_form() {
        // The recognition contract says `contains("environment variable")`,
        // so figment's `(s)` parens are optional from the parser's POV.
        let tag = ConfigSource::strip_env_metadata_name("`X_` environment variable");
        assert_eq!(tag, Some(EnvMetadataTag::Prefixed("X_")));
    }

    #[test]
    fn strip_env_metadata_name_rejects_unrelated_strings() {
        for name in [
            "",
            "/etc/app/app.yaml",
            "lisp: /etc/app.lisp",
            "nix: /etc/app.nix",
            "yaml",
            "`MYAPP_` something else",
            "envvar `X_` typo",
        ] {
            assert!(
                ConfigSource::strip_env_metadata_name(name).is_none(),
                "unrelated metadata name `{name}` must not match env tag"
            );
        }
    }

    #[test]
    fn env_metadata_name_round_trip_for_prefixed_form() {
        // The constructor and inverse must compose to identity on the
        // prefix (modulo case-folding, which figment performs).
        for prefix in ["MYAPP_", "TOBIRA_", "X_", "FOO_BAR_"] {
            let name = ConfigSource::env_metadata_name(prefix);
            let tag = ConfigSource::strip_env_metadata_name(&name)
                .expect("constructor output must round-trip through inverse");
            assert_eq!(tag, EnvMetadataTag::Prefixed(prefix));
        }
    }

    #[test]
    fn env_metadata_name_round_trip_for_bare_form() {
        let name = ConfigSource::env_metadata_name("");
        let tag = ConfigSource::strip_env_metadata_name(&name).expect("bare must round-trip");
        assert_eq!(tag, EnvMetadataTag::Bare);
    }

    #[test]
    fn strip_env_metadata_name_borrows_into_input() {
        // The prefix slice must be a sub-borrow of the input, not a
        // fresh allocation — observable via pointer arithmetic.
        let name = ConfigSource::env_metadata_name("MYAPP_");
        let EnvMetadataTag::Prefixed(prefix) =
            ConfigSource::strip_env_metadata_name(&name).expect("prefixed shape must match")
        else {
            panic!("expected prefixed variant");
        };
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let prefix_start = prefix.as_ptr() as usize;
        assert!(
            prefix_start >= name_start && prefix_start < name_end,
            "prefix must borrow into input"
        );
    }

    #[test]
    fn strip_env_metadata_name_round_trips_through_figment_emission() {
        // Pin the contract that figment's `Env` provider emits the
        // exact shape this primitive recognizes. If figment changes
        // its emission, this test breaks before the resolver does.
        use figment::Provider;
        for prefix in ["MYAPP_", "TOBIRA_", "X_"] {
            let env = figment::providers::Env::prefixed(prefix);
            let md = env.metadata();
            let name: &str = md.name.as_ref();
            let tag = ConfigSource::strip_env_metadata_name(name)
                .expect("figment Env metadata-name must match env-tag shape");
            assert_eq!(tag, EnvMetadataTag::Prefixed(prefix));
        }
    }

    #[test]
    fn env_metadata_name_matches_figment_emission_byte_for_byte() {
        // Stronger invariant: shikumi's constructor produces the same
        // bytes figment emits, so the cross-side contract holds at the
        // level of equality, not just recognition.
        use figment::Provider;
        for prefix in ["MYAPP_", "TOBIRA_", "X_"] {
            let figment_name = figment::providers::Env::prefixed(prefix)
                .metadata()
                .name
                .into_owned();
            let shikumi_name = ConfigSource::env_metadata_name(prefix);
            assert_eq!(
                figment_name, shikumi_name,
                "shikumi's env_metadata_name must match figment's emission"
            );
        }
    }

    #[test]
    fn strip_env_metadata_name_disjoint_from_format_strip() {
        // The two strip-name primitives must partition the metadata-name
        // space cleanly — a Format tag must never be misrecognized as an
        // env tag, and vice versa.
        use crate::discovery::Format;

        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/etc/app.cfg"));
            assert!(
                ConfigSource::strip_env_metadata_name(&name).is_none(),
                "format tag `{name}` must not be recognized as env tag"
            );
        }
        for prefix in ["MYAPP_", ""] {
            let name = ConfigSource::env_metadata_name(prefix);
            assert!(
                Format::strip_metadata_name(&name).is_none(),
                "env tag `{name}` must not be recognized as format tag"
            );
        }
    }
}

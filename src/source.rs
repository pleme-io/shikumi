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
use std::panic::Location;
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

/// Closed-enum classification of `figment::Metadata::name`.
///
/// figment attaches per-value attribution along two axes: the
/// `figment::Source` axis (parsed by [`FigmentSourceTag::classify`])
/// and the `figment::Metadata::name` axis (parsed here). Three name
/// shapes are recognized today, partitioned across two variants:
///
/// - `"<format>: <path>"` from a shikumi-built provider (recognized
///   via [`crate::Format::parse_metadata_tag`]) →
///   [`Self::Format`].
/// - `` `PREFIX` environment variable(s) `` from
///   [`figment::providers::Env::prefixed`] (recognized via
///   [`ConfigSource::strip_env_metadata_name`] returning
///   [`EnvMetadataTag::Prefixed`]) → [`Self::Env`].
/// - `"environment variable(s)"` from
///   [`figment::providers::Env::raw`] (recognized via the same parser
///   returning [`EnvMetadataTag::Bare`]) → [`Self::Env`].
///
/// The two sub-parsers' recognized inputs are disjoint (pinned by
/// `strip_env_metadata_name_disjoint_from_format_strip` in this
/// module), so every `figment::Metadata::name` maps to exactly one
/// variant or to `None`.
///
/// Structural mirror of [`FigmentSourceTag`] on the name axis: the
/// pair `(FigmentSourceTag, FigmentNameTag)` closes the
/// figment-metadata coordinate space the failing-source resolver
/// dispatches over. Together with [`FormatMetadataTag`] (the
/// `"<format>: <path>"` envelope on the shikumi-provider sub-axis),
/// [`EnvMetadataTag`] (the env-name sub-axis), and
/// [`crate::AttributionRule`] (the
/// `(source × name × chain) → rule` dispatch), the four typed shapes
/// together close figment's metadata attribution surface.
///
/// `Copy` and allocation-free: both inner variants borrow into the
/// input metadata-name `&str`. `#[non_exhaustive]` so a future
/// figment provider attaching a third name-axis shape (e.g. a
/// hypothetical `"http://… config endpoint"` tag) lands as one new
/// variant without breaking exhaustivity at consumer matches.
///
/// [`FormatMetadataTag`]: crate::FormatMetadataTag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FigmentNameTag<'a> {
    /// `"<format>: <path>"` shape — a shikumi-built provider's
    /// `figment::Metadata::name`. Carries the parsed
    /// [`crate::FormatMetadataTag`] envelope (format + borrowed path).
    Format(crate::discovery::FormatMetadataTag<'a>),
    /// `` `PREFIX` environment variable(s) `` or
    /// `"environment variable(s)"` — figment's `Env` provider's
    /// `figment::Metadata::name`. Carries the
    /// prefixed/bare distinction in [`EnvMetadataTag`].
    Env(EnvMetadataTag<'a>),
}

impl<'a> FigmentNameTag<'a> {
    /// Classify a `figment::Metadata::name` into its typed shape.
    ///
    /// Tries the shikumi-provider format-prefix shape first via
    /// [`crate::Format::parse_metadata_tag`]; on no match, tries the
    /// figment-Env shape via
    /// [`ConfigSource::strip_env_metadata_name`]; returns `None` for
    /// any other shape (file paths from figment's YAML/TOML providers,
    /// unrelated names, the empty string).
    ///
    /// The two sub-parsers are disjoint (pinned by
    /// `strip_env_metadata_name_disjoint_from_format_strip`), so
    /// iteration order does not affect correctness; the order matches
    /// the failing-source resolver's preference.
    ///
    /// One source of truth for the figment-name-axis dispatch on
    /// [`figment::Metadata`]: callers ([`crate::ShikumiError::failing_source`]
    /// and any future per-value attribution consumer) match on this
    /// enum instead of calling
    /// [`crate::Format::parse_metadata_tag`] and
    /// [`ConfigSource::strip_env_metadata_name`] in sequence. If a
    /// new figment-recognized name shape lands, exactly one site here
    /// changes (a new variant + a new branch in `classify`) and the
    /// resolver's match becomes non-exhaustive at compile time —
    /// catching unhandled cases before they reach users.
    #[must_use]
    pub fn classify(name: &'a str) -> Option<Self> {
        if let Some(tag) = crate::discovery::Format::parse_metadata_tag(name) {
            return Some(Self::Format(tag));
        }
        if let Some(tag) = ConfigSource::strip_env_metadata_name(name) {
            return Some(Self::Env(tag));
        }
        None
    }

    /// Returns the inner [`crate::FormatMetadataTag`] if this is the
    /// [`Self::Format`] variant.
    #[must_use]
    pub fn as_format(self) -> Option<crate::discovery::FormatMetadataTag<'a>> {
        match self {
            Self::Format(tag) => Some(tag),
            Self::Env(_) => None,
        }
    }

    /// Returns the inner [`EnvMetadataTag`] if this is the
    /// [`Self::Env`] variant.
    #[must_use]
    pub fn as_env(self) -> Option<EnvMetadataTag<'a>> {
        match self {
            Self::Env(tag) => Some(tag),
            Self::Format(_) => None,
        }
    }
}

/// Borrowed classification of a [`figment::Source`].
///
/// figment's `Source` is `#[non_exhaustive]` and is queried via three
/// `Option`-returning accessors ([`figment::Source::file_path`],
/// [`figment::Source::code_location`], [`figment::Source::custom`]). This
/// enum lifts those open-coded probes into one typed dispatch: a single
/// [`Self::classify`] call takes `&figment::Source` and returns the one
/// recognized variant (or `None` if figment grew a fourth variant we
/// don't yet model).
///
/// The source axis of figment metadata is the structural mirror of the
/// name axis ([`crate::Format::strip_metadata_name`] /
/// [`ConfigSource::strip_env_metadata_name`]): every `figment::Metadata`
/// carries an optional `name: Cow<'static, str>` and an optional
/// `source: Option<Source>`. The three primitives partition the
/// recognized shapes across both axes; resolvers (e.g.
/// [`crate::ShikumiError::failing_source`]) dispatch on them without
/// re-implementing figment's Source-side query methods.
///
/// All variants borrow into either the input `Source` (`File`, `Custom`)
/// or into the `'static` panic location figment carries (`Code`), so the
/// enum is `Copy` and allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FigmentSourceTag<'a> {
    /// `figment::Source::File(_)` — the borrowed file path. This is the
    /// shape figment's built-in YAML/TOML providers attach to per-value
    /// metadata; matched by [`ConfigSource::as_path`] equality in the
    /// resolver.
    File(&'a Path),
    /// `figment::Source::Code(_)` — the source-code location attached by
    /// [`figment::providers::Serialized`] (the shape behind
    /// [`crate::ProviderChain::with_defaults`]). Carries figment's
    /// `&'static Location<'static>` verbatim.
    Code(&'static Location<'static>),
    /// `figment::Source::Custom(_)` — the borrowed custom-source string.
    /// Used by figment-ecosystem providers that can't fit the File/Code
    /// shape (e.g. HTTP, Vault, in-memory dicts).
    Custom(&'a str),
}

impl<'a> FigmentSourceTag<'a> {
    /// Classify a [`figment::Source`] into its typed shape.
    ///
    /// Returns `Some(variant)` for each of figment's three documented
    /// `Source` variants (`File` / `Code` / `Custom`), with the inner
    /// data borrowed from `source`. Returns `None` only if figment grew
    /// a new variant after this enum was last extended; callers should
    /// treat `None` as "unrecognized source shape" rather than "no
    /// source attached".
    ///
    /// One source of truth for the figment-Source-axis dispatch: the
    /// resolver in [`crate::ShikumiError::failing_source`] routes its
    /// `Source::File` / `Source::Code` arms through this primitive
    /// instead of calling [`figment::Source::file_path`] /
    /// [`figment::Source::code_location`] in line. If figment changes
    /// its Source taxonomy (renames a variant, adds `Source::Url`,
    /// etc.), exactly one site here changes and the
    /// `figment_source_tag_classifies_*` tests catch the drift before
    /// it reaches the resolver.
    #[must_use]
    pub fn classify(source: &'a figment::Source) -> Option<Self> {
        if let Some(p) = source.file_path() {
            return Some(Self::File(p));
        }
        if let Some(loc) = source.code_location() {
            return Some(Self::Code(loc));
        }
        if let Some(c) = source.custom() {
            return Some(Self::Custom(c));
        }
        None
    }

    /// Returns the file path if this tag is a [`Self::File`].
    #[must_use]
    pub fn as_file_path(self) -> Option<&'a Path> {
        match self {
            Self::File(p) => Some(p),
            _ => None,
        }
    }

    /// Returns `true` for [`Self::Code`].
    #[must_use]
    pub fn is_code(self) -> bool {
        matches!(self, Self::Code(_))
    }

    /// Returns the custom-source string if this tag is a [`Self::Custom`].
    #[must_use]
    pub fn as_custom(self) -> Option<&'a str> {
        match self {
            Self::Custom(c) => Some(c),
            _ => None,
        }
    }
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

    // ---- FigmentSourceTag::classify ----

    #[test]
    fn figment_source_tag_classifies_file_path() {
        let src = figment::Source::File(PathBuf::from("/etc/app/app.yaml"));
        let tag = FigmentSourceTag::classify(&src).expect("File source must classify");
        assert_eq!(tag, FigmentSourceTag::File(Path::new("/etc/app/app.yaml")));
        assert_eq!(tag.as_file_path(), Some(Path::new("/etc/app/app.yaml")));
        assert!(!tag.is_code());
        assert_eq!(tag.as_custom(), None);
    }

    #[test]
    fn figment_source_tag_classifies_code_location() {
        // Source::Code carries a `&'static Location<'static>`; constructing
        // one via `Location::caller()` works inside `#[track_caller]`-ish
        // paths but is fiddly outside them. Use the Serialized provider
        // (which figment tags with `Source::Code`) to obtain a real one.
        use figment::Provider;
        let provider = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let md = provider.metadata();
        let src = md.source.as_ref().expect("Serialized attaches a source");
        let tag = FigmentSourceTag::classify(src).expect("Code source must classify");
        assert!(
            matches!(tag, FigmentSourceTag::Code(_)),
            "expected Code variant, got {tag:?}"
        );
        assert!(tag.is_code());
        assert_eq!(tag.as_file_path(), None);
        assert_eq!(tag.as_custom(), None);
    }

    #[test]
    fn figment_source_tag_classifies_custom() {
        let src = figment::Source::Custom("ftp://configs.example.com/app.yaml".to_owned());
        let tag = FigmentSourceTag::classify(&src).expect("Custom source must classify");
        assert_eq!(
            tag,
            FigmentSourceTag::Custom("ftp://configs.example.com/app.yaml")
        );
        assert_eq!(tag.as_custom(), Some("ftp://configs.example.com/app.yaml"));
        assert!(!tag.is_code());
        assert_eq!(tag.as_file_path(), None);
    }

    #[test]
    fn figment_source_tag_borrows_into_input_for_file() {
        // The path slice must be a sub-borrow of the input PathBuf, not a
        // fresh allocation — observable via pointer arithmetic.
        let src = figment::Source::File(PathBuf::from("/etc/app/app.yaml"));
        let FigmentSourceTag::File(borrowed) =
            FigmentSourceTag::classify(&src).expect("File classify")
        else {
            panic!("expected File variant");
        };
        let figment::Source::File(ref owned) = src else {
            unreachable!()
        };
        let owned_start = owned.as_os_str().as_encoded_bytes().as_ptr() as usize;
        let owned_end = owned_start + owned.as_os_str().as_encoded_bytes().len();
        let borrowed_start = borrowed.as_os_str().as_encoded_bytes().as_ptr() as usize;
        assert!(
            borrowed_start >= owned_start && borrowed_start < owned_end,
            "path must borrow into source"
        );
    }

    #[test]
    fn figment_source_tag_borrows_into_input_for_custom() {
        let src = figment::Source::Custom("vault://kv/app".to_owned());
        let FigmentSourceTag::Custom(c) =
            FigmentSourceTag::classify(&src).expect("Custom classify")
        else {
            panic!("expected Custom variant");
        };
        let figment::Source::Custom(ref s) = src else {
            unreachable!()
        };
        let s_start = s.as_ptr() as usize;
        let s_end = s_start + s.len();
        let c_start = c.as_ptr() as usize;
        assert!(
            c_start >= s_start && c_start < s_end,
            "custom slice must borrow into source"
        );
    }

    #[test]
    fn figment_source_tag_classify_round_trips_through_yaml_provider() {
        // Pin the cross-side contract that figment's YAML file provider
        // attaches a Source::File which classifies as
        // FigmentSourceTag::File(<path>). If figment changes the shape it
        // attaches to file-based providers, this test breaks before the
        // resolver does.
        use figment::providers::Format as _;

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("c.yaml");
        std::fs::write(&file, "k: v\n").unwrap();
        let figment = figment::Figment::new().merge(figment::providers::Yaml::file(&file));
        let value: figment::value::Value = figment.find_value("k").unwrap();
        let tag = figment.get_metadata(value.tag()).unwrap();
        let src = tag.source.as_ref().expect("Yaml::file attaches a source");
        let classified = FigmentSourceTag::classify(src).expect("Yaml file source must classify");
        assert_eq!(classified, FigmentSourceTag::File(file.as_path()));
    }

    #[test]
    fn figment_source_tag_classify_round_trips_through_serialized_provider() {
        // The Serialized provider — which `ProviderChain::with_defaults`
        // routes through — must attach a Source::Code that classifies
        // as FigmentSourceTag::Code(_). Pinning this end-to-end ensures
        // resolve_failing_source's `Code → defaults` arm stays honest.
        use figment::Provider;
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"name": "default"}));
        let md = prov.metadata();
        let src = md
            .source
            .as_ref()
            .expect("Serialized attaches a Source::Code");
        let tag = FigmentSourceTag::classify(src).expect("Code source must classify");
        assert!(tag.is_code(), "Serialized must classify as Code");
    }

    #[test]
    fn figment_source_tag_variants_are_disjoint() {
        // Each Source variant must classify into exactly one
        // FigmentSourceTag variant — no Source can claim two tags at once.
        let file_src = figment::Source::File(PathBuf::from("/x"));
        let custom_src = figment::Source::Custom("c".to_owned());

        let file_tag = FigmentSourceTag::classify(&file_src).unwrap();
        let custom_tag = FigmentSourceTag::classify(&custom_src).unwrap();

        assert!(file_tag.as_file_path().is_some() && !file_tag.is_code());
        assert!(file_tag.as_custom().is_none());
        assert!(custom_tag.as_custom().is_some() && !custom_tag.is_code());
        assert!(custom_tag.as_file_path().is_none());
    }

    // ---- FigmentNameTag::classify ----

    #[test]
    fn figment_name_tag_classifies_format_metadata_name() {
        // shikumi-built provider's "<format>: <path>" shape must
        // route to the Format variant for every Format whose
        // has_shikumi_provider() is true.
        use crate::discovery::Format;
        let path = Path::new("/etc/app/app.cfg");
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let name = f.metadata_name(path);
            let tag = FigmentNameTag::classify(&name).expect("format tag must classify");
            let inner = tag.as_format().expect("expected Format variant");
            assert_eq!(inner.format, *f);
            assert_eq!(inner.path, path);
            assert!(tag.as_env().is_none(), "Format must not also be Env");
        }
    }

    #[test]
    fn figment_name_tag_classifies_env_prefixed() {
        let name = ConfigSource::env_metadata_name("MYAPP_");
        let tag = FigmentNameTag::classify(&name).expect("env-prefixed must classify");
        assert_eq!(tag, FigmentNameTag::Env(EnvMetadataTag::Prefixed("MYAPP_")));
        assert_eq!(tag.as_env(), Some(EnvMetadataTag::Prefixed("MYAPP_")));
        assert!(tag.as_format().is_none(), "Env must not also be Format");
    }

    #[test]
    fn figment_name_tag_classifies_env_bare() {
        let name = ConfigSource::env_metadata_name("");
        let tag = FigmentNameTag::classify(&name).expect("env-bare must classify");
        assert_eq!(tag, FigmentNameTag::Env(EnvMetadataTag::Bare));
        assert_eq!(tag.as_env(), Some(EnvMetadataTag::Bare));
        assert!(tag.as_format().is_none());
    }

    #[test]
    fn figment_name_tag_returns_none_for_unrelated() {
        for name in [
            "",
            "/etc/app/app.yaml", // figment Yaml provider's name shape
            "/var/lib/app.toml",
            "default",      // figment Serialized's typical name
            "yaml",         // bare format token, missing colon-space
            "json: /x.cfg", // recognized format token but Json is not a Format
            "envvar `X_`",  // env-shaped but missing the literal substring
        ] {
            assert!(
                FigmentNameTag::classify(name).is_none(),
                "unrelated metadata name `{name}` must not classify"
            );
        }
    }

    #[test]
    fn figment_name_tag_variants_are_disjoint() {
        // Every recognized name must classify into exactly one
        // FigmentNameTag variant — no name can claim both Format and
        // Env. Mirrors the FigmentSourceTag disjointness invariant on
        // the source axis, and pins the disjointness contract that
        // `classify`'s sequential dispatch relies on.
        use crate::discovery::Format;
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/etc/app.cfg"));
            let tag = FigmentNameTag::classify(&name).expect("format tag classifies");
            assert!(tag.as_format().is_some());
            assert!(tag.as_env().is_none());
        }
        for prefix in ["MYAPP_", ""] {
            let name = ConfigSource::env_metadata_name(prefix);
            let tag = FigmentNameTag::classify(&name).expect("env tag classifies");
            assert!(tag.as_env().is_some());
            assert!(tag.as_format().is_none());
        }
    }

    #[test]
    fn figment_name_tag_format_borrows_into_input() {
        // The path slice inside the Format envelope must be a
        // sub-borrow of the input metadata-name string — Path::new
        // preserves the byte borrow.
        use crate::discovery::Format;
        let name = Format::Nix.metadata_name(Path::new("/etc/app/app.nix"));
        let tag = FigmentNameTag::classify(&name).expect("classify");
        let FigmentNameTag::Format(inner) = tag else {
            panic!("expected Format variant");
        };
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let path_bytes = inner.path.as_os_str().as_encoded_bytes();
        let path_start = path_bytes.as_ptr() as usize;
        assert!(
            path_start >= name_start && path_start < name_end,
            "Format.path must borrow into input"
        );
    }

    #[test]
    fn figment_name_tag_env_borrows_into_input() {
        let name = ConfigSource::env_metadata_name("BORROW_");
        let tag = FigmentNameTag::classify(&name).expect("classify");
        let FigmentNameTag::Env(EnvMetadataTag::Prefixed(prefix)) = tag else {
            panic!("expected Env(Prefixed) variant");
        };
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let prefix_start = prefix.as_ptr() as usize;
        assert!(
            prefix_start >= name_start && prefix_start < name_end,
            "Env(Prefixed) must borrow into input"
        );
    }

    #[test]
    fn figment_name_tag_round_trips_through_figment_env_emission() {
        // Pin the cross-side contract: figment's Env provider emits
        // exactly the shape FigmentNameTag::Env recognizes. If figment
        // changes its emission, this test breaks before the resolver
        // does.
        use figment::Provider;
        for prefix in ["MYAPP_", "TOBIRA_", "X_"] {
            let env = figment::providers::Env::prefixed(prefix);
            let md = env.metadata();
            let name: &str = md.name.as_ref();
            let tag = FigmentNameTag::classify(name).expect("figment Env name must classify");
            assert_eq!(tag, FigmentNameTag::Env(EnvMetadataTag::Prefixed(prefix)));
        }
    }

    #[test]
    fn figment_name_tag_round_trips_through_format_emission() {
        // The complementary cross-side contract: every shikumi-built
        // provider variant's emitted metadata-name classifies as
        // FigmentNameTag::Format with the same format and path.
        use crate::discovery::Format;
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/etc/app/app.cfg");
            let name = f.metadata_name(path);
            let tag = FigmentNameTag::classify(&name).expect("format-emitted name classifies");
            let inner = tag.as_format().expect("Format variant");
            assert_eq!(inner.format, *f);
            assert_eq!(inner.path, path);
        }
    }

    #[test]
    fn figment_name_tag_is_copy_and_hashable() {
        use std::collections::HashSet;
        // Copy: rebind without move.
        let n1 = ConfigSource::env_metadata_name("X_");
        let t1 = FigmentNameTag::classify(&n1).unwrap();
        let t2 = t1;
        let t3 = t1;
        assert_eq!(t1, t2);
        assert_eq!(t2, t3);

        // Hash: distinct shapes hash to distinct buckets in a HashSet.
        let mut set = HashSet::new();
        let np = ConfigSource::env_metadata_name("MYAPP_");
        let nb = ConfigSource::env_metadata_name("");
        let nf = crate::discovery::Format::Nix.metadata_name(Path::new("/a.nix"));
        set.insert(FigmentNameTag::classify(&np).unwrap());
        set.insert(FigmentNameTag::classify(&nb).unwrap());
        set.insert(FigmentNameTag::classify(&nf).unwrap());
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn figment_name_tag_yaml_provider_emission_is_unrecognized() {
        // figment's built-in Yaml provider attaches the file path as
        // metadata.name. That shape is not a name-axis tag — it
        // belongs to the source-axis (Source::File). FigmentNameTag
        // must report None so the resolver falls through to
        // source-axis dispatch.
        use figment::providers::Format as _;
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("c.yaml");
        std::fs::write(&file, "k: v\n").unwrap();
        let figment = figment::Figment::new().merge(figment::providers::Yaml::file(&file));
        let value: figment::value::Value = figment.find_value("k").unwrap();
        let md = figment.get_metadata(value.tag()).unwrap();
        let name: &str = md.name.as_ref();
        assert!(
            FigmentNameTag::classify(name).is_none(),
            "Yaml provider's path-shaped name `{name}` must NOT classify as a name-axis tag"
        );
    }
}

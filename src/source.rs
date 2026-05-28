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

    /// Data-free discriminant of this [`ConfigSource`]: the kind of
    /// layer ([`ConfigSourceKind::Defaults`] / [`ConfigSourceKind::Env`]
    /// / [`ConfigSourceKind::File`]) independent of its specific path
    /// or prefix.
    ///
    /// One source of truth for the kind partition over [`ConfigSource`]:
    /// observers that need only the layer-kind axis (filtering a chain,
    /// hashing a layer's class, comparing against
    /// [`crate::AttributionRule::layer_kind`]) match on this closed
    /// enum instead of matching three [`Self::is_defaults`] /
    /// [`Self::is_env`] / [`Self::is_file`] booleans together.
    ///
    /// Pairs with [`crate::AttributionRule::layer_kind`] under the
    /// invariant `attr.rule.layer_kind() == attr.source.kind()` for
    /// every [`crate::FailingSourceAttribution`] the resolver
    /// produces — pinned by
    /// `attribution_rule_layer_kind_agrees_with_source_kind` in
    /// `error.rs`. Without the kind primitive this contract was
    /// implicit in the rule names; lifting it makes "the rule and the
    /// source agree on layer kind" a structural law.
    ///
    /// `Copy + Eq + Hash + #[non_exhaustive]`, allocation-free,
    /// trait-bounds parity with the sibling typescape primitives
    /// ([`crate::AttributionRule`], [`crate::AttributionConfidence`],
    /// [`FigmentSourceTag`], [`FigmentNameTag`]).
    #[must_use]
    pub fn kind(&self) -> ConfigSourceKind {
        match self {
            Self::Defaults => ConfigSourceKind::Defaults,
            Self::Env(_) => ConfigSourceKind::Env,
            Self::File(_) => ConfigSourceKind::File,
        }
    }

    /// The [`crate::discovery::Format`] declared by this source's file
    /// extension, if this is a [`Self::File`] with a recognized extension.
    ///
    /// Returns `None` for [`Self::Defaults`] / [`Self::Env`] sources. A
    /// `File` whose extension is unrecognized or absent also yields `None`
    /// — [`crate::ProviderChain::with_file`] parses such files with the
    /// conservative TOML fallback, so a `None` on a `File` source means
    /// "the extension did not declare a format", not "no file". Use
    /// [`Self::is_file`] / [`Self::as_path`] to distinguish.
    ///
    /// Routes through [`crate::discovery::Format::from_path`], the single
    /// `(path → Format)` detection site that `with_file` also uses, so the
    /// recorded provenance chain reports exactly the format the loader
    /// detected — a consumer reading "which format parsed this layer?" off
    /// the chain never re-derives the extension triple, and reload (which
    /// replays this chain) and the original load agree on format by
    /// construction.
    #[must_use]
    pub fn file_format(&self) -> Option<crate::discovery::Format> {
        match self {
            Self::File(path) => crate::discovery::Format::from_path(path),
            _ => None,
        }
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

/// Data-free discriminant of [`ConfigSource`]: the kind of layer
/// independent of its inner path or prefix.
///
/// Closed three-way partition over the [`ConfigSource`] variant space,
/// returned by [`ConfigSource::kind`]. The enum exists so consumers
/// that care only about the kind axis (chain filters, layer-class
/// hashes, the (rule × layer-kind) attribution invariant) match on one
/// closed enum instead of matching three
/// ([`ConfigSource::is_defaults`] / [`ConfigSource::is_env`] /
/// [`ConfigSource::is_file`]) booleans together.
///
/// Paired with [`crate::AttributionRule::layer_kind`] under the
/// invariant `attr.rule.layer_kind() == attr.source.kind()` for every
/// [`crate::FailingSourceAttribution`] the resolver produces. Adding a
/// future [`ConfigSource`] variant (e.g. `Http(_)`, `Vault(_)`,
/// `ConfigMap(_)`) means adding one [`ConfigSourceKind`] variant in
/// lockstep — the exhaustive [`ConfigSource::kind`] match forces the
/// assignment at compile time, and any new [`crate::AttributionRule`]
/// that attributes to the new layer must declare the same kind in its
/// [`crate::AttributionRule::layer_kind`] arm.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, allocation-free,
/// trait-bounds parity with the sibling typescape primitives
/// ([`crate::AttributionRule`], [`crate::AttributionConfidence`],
/// [`FigmentSourceTag`], [`FigmentNameTag`], [`EnvMetadataTag`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigSourceKind {
    /// Maps to [`ConfigSource::Defaults`].
    Defaults,
    /// Maps to [`ConfigSource::Env`] regardless of prefix value.
    Env,
    /// Maps to [`ConfigSource::File`] regardless of path value.
    File,
}

impl ConfigSourceKind {
    /// Every [`ConfigSourceKind`] variant, in declaration order
    /// ([`Self::Defaults`], [`Self::Env`], [`Self::File`]).
    ///
    /// The closed list of layer kinds shikumi recognizes. Iterate to
    /// enumerate the layer-kind space without listing variants by hand
    /// at every consumer site — e.g. dashboards initializing per-kind
    /// chain counters, attestation manifests recording the layer-kind
    /// space's cardinality, tests asserting cube-coverage over the
    /// orthogonal `(axis × layer_kind × confidence)` coordinate space
    /// in [`crate::AttributionRule::from_coordinates`].
    ///
    /// One source of truth for the layer-kind enumeration on the
    /// [`ConfigSourceKind`] axis: peer to [`crate::Format::ALL`] on the
    /// [`crate::Format`] axis, [`crate::ShikumiErrorKind::ALL`] on the
    /// kind axis, and [`crate::AttributionRule::ALL`] on the rule axis
    /// — the same typescape discipline applied across the closed-enum
    /// primitive set. Before this constant, the layer-kind enumeration
    /// was inlined as a `[File, Env, Defaults]` array literal at sites
    /// that needed to iterate (the cube-coverage loop in
    /// `attribution_rule_from_coordinates_returns_none_for_unrecognized_cells`,
    /// the trait-bounds parity check in
    /// `config_source_kind_is_copy_and_hashable`); each duplicated
    /// literal had to be manually kept in lockstep with the enum's
    /// variant set.
    ///
    /// Adding a new variant to [`Self`] (e.g. a future `Http`, `Vault`,
    /// or `ConfigMap` layer kind paired with a new
    /// [`ConfigSource`] variant) means extending this slice in lockstep
    /// with the variant itself. The compiler enforces nothing here
    /// directly, so the
    /// `config_source_kind_all_covers_every_constructible_variant` test
    /// pins the contract by asserting that every kind produced by
    /// [`ConfigSource::kind`] over the canonical sample table appears
    /// in [`Self::ALL`], and the `config_source_kind_all_has_no_duplicates`
    /// test pins that the constant is a set (no double-listed variant).
    /// Together they pin the constant to the variant space the
    /// typescape recognizes.
    pub const ALL: &'static [Self] = &[Self::Defaults, Self::Env, Self::File];

    /// Canonical operator-facing lowercase name of the layer kind —
    /// `"defaults"`, `"env"`, or `"file"`.
    ///
    /// The single source of truth for the layer-kind label strings on
    /// the [`ConfigSourceKind`] axis. Inherent mirror of the
    /// [`crate::ClosedAxisLabel`] trait method; the trait impl
    /// delegates here so the canonical names live at one site instead
    /// of being re-stated at every operator-facing surface (a future
    /// structured-log field naming the failing layer's class, a CLI
    /// flag filtering attributions by layer kind, an attestation
    /// manifest recording the layer-kind histogram of loaded values).
    /// The strings match the variant identifiers in ASCII-lowercase
    /// form — the same form an operator would type into an env var or
    /// CLI flag.
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned for
    /// every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `config_source_kind_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"Env"`, prefixing `"layer-env"`) fails at
    /// that site before drifting through the round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Defaults => "defaults",
            Self::Env => "env",
            Self::File => "file",
        }
    }
}

impl crate::ClosedAxis for ConfigSourceKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for ConfigSourceKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

/// Chain-level provenance queries over a recorded [`ConfigSource`] chain.
///
/// The recorded chain — the `&[ConfigSource]` returned by
/// [`crate::ConfigStore::sources`] / [`crate::ProviderChain::sources`] and
/// replayed verbatim on every [`crate::ConfigStore::reload`] — is the
/// executable recipe that built a store. This trait turns "which layer in
/// the recipe …?" questions into named queries over the slice, so the
/// answer is read off the typed provenance rather than re-derived by an
/// open-coded `iter().find` / `iter().filter` at every consumer.
///
/// One source of truth for the chain-walk discipline: the failing-source
/// resolver behind [`crate::ShikumiError::failing_source`] previously
/// open-coded "find the [`ConfigSource::File`] whose path equals P" twice
/// (once per file-attribution rule), "the sole layer of kind K" twice
/// (the env- and defaults-uniqueness rules), and "the [`ConfigSource::Env`]
/// layer whose prefix matches P case-insensitively" once
/// (the env-by-prefix rule); all five collapse to one
/// [`Self::find_file`] / [`Self::unique_of_kind`] / [`Self::find_env_by_prefix`]
/// site here. Future consumers reading the recipe — an attestation
/// manifest grouping layers by kind, a diagnostic dump locating the file
/// layer behind a value, a chain-diff that needs to match an env layer
/// across reloads, a new uniqueness-keyed attribution rule for a future
/// [`ConfigSource`] variant — key on these queries instead of re-walking
/// the slice.
///
/// Implemented for `[ConfigSource]`, so it applies to any `&[ConfigSource]`
/// (a borrowed `Vec`, a stored chain slice) by deref.
pub trait ConfigSourceChain {
    /// The first [`ConfigSource::File`] entry whose path equals `path`,
    /// or `None` if no file layer in the chain was loaded from `path`.
    ///
    /// Matches only [`ConfigSource::File`] layers — [`ConfigSource::Env`]
    /// and [`ConfigSource::Defaults`] carry no path and never match. The
    /// comparison is exact-path (per [`ConfigSource::as_path`]); it does
    /// not canonicalize, so a caller comparing against a discovery result
    /// should pass the same path shape the chain recorded.
    fn find_file(&self, path: &Path) -> Option<&ConfigSource>;

    /// The sole chain entry whose [`ConfigSource::kind`] equals `kind`,
    /// or `None` if the chain holds zero or more than one such layer.
    ///
    /// Returns `Some` only on a *unique* match: this is the
    /// "exactly one layer of this kind" query the failing-source resolver
    /// uses to attribute an unprefixed env value to the chain's sole
    /// [`ConfigSourceKind::Env`] layer, or a code-sourced value to its
    /// sole [`ConfigSourceKind::Defaults`] layer. Keyed on the typed
    /// [`ConfigSourceKind`] discriminant, so a future variant participates
    /// without touching this method.
    fn unique_of_kind(&self, kind: ConfigSourceKind) -> Option<&ConfigSource>;

    /// The first [`ConfigSource::Env`] entry whose recorded prefix equals
    /// `prefix` under ASCII-case-insensitive comparison, or `None` if no
    /// env layer in the chain carries that prefix.
    ///
    /// Matches only [`ConfigSource::Env`] layers — [`ConfigSource::File`]
    /// and [`ConfigSource::Defaults`] carry no prefix and never match.
    /// The comparison is [`str::eq_ignore_ascii_case`] rather than
    /// strict equality because figment uppercases the prefix when
    /// emitting [`figment::Metadata::name`] (see
    /// [`ConfigSource::env_metadata_name`]) while users may pass any
    /// case to [`crate::ProviderChain::with_env`]; a strict comparison
    /// would silently drop legitimate matches when the user-supplied
    /// prefix and figment's emitted form disagree on case.
    ///
    /// The third chain-level provenance query peer to [`Self::find_file`]
    /// (path-equality on `ConfigSource::File`) and [`Self::unique_of_kind`]
    /// (kind-uniqueness on the typed discriminant). Together the three
    /// methods close the chain-walk discipline for the failing-source
    /// resolver: every "which layer in the recipe …?" question routes
    /// through one named primitive instead of an open-coded
    /// `iter().find` / `iter().filter` that re-derives the comparison
    /// shape at every consumer.
    fn find_env_by_prefix(&self, prefix: &str) -> Option<&ConfigSource>;
}

impl ConfigSourceChain for [ConfigSource] {
    fn find_file(&self, path: &Path) -> Option<&ConfigSource> {
        self.iter().find(|s| s.as_path() == Some(path))
    }

    fn unique_of_kind(&self, kind: ConfigSourceKind) -> Option<&ConfigSource> {
        let mut matches = self.iter().filter(|s| s.kind() == kind);
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    fn find_env_by_prefix(&self, prefix: &str) -> Option<&ConfigSource> {
        self.iter().find(|s| {
            s.as_env_prefix()
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        })
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
        matches!(self.kind(), FigmentSourceKind::Code)
    }

    /// Returns the custom-source string if this tag is a [`Self::Custom`].
    #[must_use]
    pub fn as_custom(self) -> Option<&'a str> {
        match self {
            Self::Custom(c) => Some(c),
            _ => None,
        }
    }

    /// Data-free, `'static` discriminant of this [`FigmentSourceTag`]:
    /// the kind of `figment::Source` ([`FigmentSourceKind::File`] /
    /// [`FigmentSourceKind::Code`] / [`FigmentSourceKind::Custom`])
    /// independent of the inner borrowed path / location / string.
    ///
    /// One source of truth for the figment-Source-axis kind partition.
    /// Observers that need only the kind axis (filtering by source class,
    /// hashing in a `'static` map, recording per-failure source-class in
    /// an attestation manifest) match on this closed enum instead of
    /// pattern-matching against [`FigmentSourceTag`] with a borrowed
    /// lifetime, or chaining [`Self::as_file_path`] / [`Self::is_code`] /
    /// [`Self::as_custom`] together. The kind is `'static`, so it can
    /// cross threads, serialize, and persist across observation
    /// boundaries the borrowed tag cannot.
    ///
    /// Mirrors the [`ConfigSource`] → [`ConfigSourceKind`] lift on the
    /// shikumi-source axis: same typescape discipline (closed,
    /// allocation-free, `Copy + Eq + Hash + #[non_exhaustive]`,
    /// exhaustive forward map), applied to figment's `Source` axis. The
    /// two kind partitions are structurally distinct universes — one
    /// classifies shikumi's recorded chain layers, the other classifies
    /// figment's per-value source attribution — but compose under one
    /// typescape primitive set.
    ///
    /// Pairs with [`Self::attribution_axis`]: the projection is constant
    /// ([`crate::AttributionAxis::MetadataSource`] for every variant)
    /// since [`FigmentSourceTag`] *is* the typed reading of
    /// `figment::Metadata::source`. That structural law is pinned by
    /// `figment_source_tag_attribution_axis_is_always_metadata_source`.
    /// A future variant landing on [`FigmentSourceTag`] (e.g. a
    /// `Source::Url` shape if figment grows one) forces a
    /// [`FigmentSourceKind`] arm in lockstep at compile time, and the
    /// constant axis projection extends without per-site updates.
    #[must_use]
    pub fn kind(self) -> FigmentSourceKind {
        match self {
            Self::File(_) => FigmentSourceKind::File,
            Self::Code(_) => FigmentSourceKind::Code,
            Self::Custom(_) => FigmentSourceKind::Custom,
        }
    }

    /// [`crate::AttributionAxis`] of this tag — constant
    /// [`crate::AttributionAxis::MetadataSource`] for every variant,
    /// since [`FigmentSourceTag`] *is* the typed reading of
    /// `figment::Metadata::source`.
    ///
    /// One source of truth for the structural law that every
    /// figment-Source-axis attribution dispatches off `metadata.source`,
    /// regardless of which variant fires. The pair
    /// (figment-side: [`FigmentSourceTag::attribution_axis`],
    /// resolver-side: [`crate::AttributionRule::metadata_axis`]) cross-checks
    /// the axis between the two surfaces; consumers reading either side
    /// see the same axis label without re-deriving the
    /// (typed-source × name-string) partition. Mirrors
    /// [`FigmentNameTag`]-shaped attributions, which always sit on
    /// [`crate::AttributionAxis::MetadataName`] by the same structural
    /// argument.
    #[must_use]
    pub fn attribution_axis(self) -> crate::AttributionAxis {
        let _ = self.kind();
        crate::AttributionAxis::MetadataSource
    }
}

/// Data-free, `'static` discriminant of [`FigmentSourceTag`]: the kind
/// of `figment::Source` independent of the inner borrowed path /
/// location / string.
///
/// Closed three-way partition over the [`FigmentSourceTag`] variant
/// space, returned by [`FigmentSourceTag::kind`]. The enum exists so
/// consumers that need only the kind axis (filtering by source class,
/// hashing in a `'static` map, recording per-failure source-class in
/// an attestation manifest, comparing across thread boundaries) match
/// on one closed enum instead of pattern-matching against the borrowed
/// tag or chaining [`FigmentSourceTag::as_file_path`] /
/// [`FigmentSourceTag::is_code`] / [`FigmentSourceTag::as_custom`]
/// together.
///
/// Mirrors the [`ConfigSource`] → [`ConfigSourceKind`] lift on the
/// shikumi-source axis: same typescape discipline (closed,
/// allocation-free, `Copy + Eq + Hash + #[non_exhaustive]`,
/// exhaustive forward map), applied to figment's `Source` axis.
///
/// `'static` and allocation-free — no lifetime parameter, unlike
/// [`FigmentSourceTag`]. The kind survives any borrow on the
/// originating `figment::Source` and can therefore cross thread
/// boundaries, serialize, and live in long-lived structures (the way
/// [`ConfigSourceKind`] does on the captured cross-thread observable
/// form of [`crate::ReloadFailure`]).
///
/// Adding a future [`FigmentSourceTag`] variant (e.g. a `Source::Url`
/// shape if figment grows one) means adding one [`FigmentSourceKind`]
/// variant in lockstep — the exhaustive [`FigmentSourceTag::kind`]
/// match forces the assignment at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FigmentSourceKind {
    /// Maps to [`FigmentSourceTag::File`] regardless of inner path.
    File,
    /// Maps to [`FigmentSourceTag::Code`] regardless of inner location.
    Code,
    /// Maps to [`FigmentSourceTag::Custom`] regardless of inner string.
    Custom,
}

impl FigmentSourceKind {
    /// Every [`FigmentSourceKind`] variant, in declaration order
    /// ([`Self::File`], [`Self::Code`], [`Self::Custom`]).
    ///
    /// The closed list of `figment::Source` kinds shikumi recognizes.
    /// Iterate to enumerate the figment-Source-axis kind space without
    /// listing variants by hand at every consumer site — e.g.
    /// dashboards initializing per-kind counters (weighting `Custom`
    /// attributions visibly weaker than `File`/`Code` ones since
    /// `Source::Custom` is a free-form string), attestation manifests
    /// recording the figment-Source-axis kind space's cardinality,
    /// structured-diagnostics legends rendering different prose per
    /// class, or partition-coverage tests asserting disjointness across
    /// the figment-side classification.
    ///
    /// One source of truth for the kind enumeration on the
    /// [`FigmentSourceKind`] axis: peer to [`crate::Format::ALL`] on
    /// the format axis, [`crate::ShikumiErrorKind::ALL`] on the kind
    /// axis, [`crate::AttributionRule::ALL`] on the rule axis,
    /// [`ConfigSourceKind::ALL`] on the shikumi-side layer-kind axis,
    /// [`crate::FieldPathLocalization::ALL`] on the
    /// field-path-localization axis,
    /// [`crate::FormatProvenance::ALL`] on the format-provenance
    /// axis, [`crate::AttributionAxis::ALL`] on the metadata axis,
    /// and [`crate::AttributionConfidence::ALL`] on the confidence
    /// axis — the same typescape discipline (closed `'static` slice,
    /// in declaration order) applied to figment's `Source`-axis kind.
    /// Before this constant, the kind enumeration was inlined as a
    /// `[File, Code, Custom]` array literal at sites that needed to
    /// iterate (the `figment_source_kind_is_static_and_copy_and_hashable`
    /// test inserted each variant by hand; the
    /// `figment_source_kind_partitions_disjointly` test built a
    /// `[(Tag, Kind); 3]` table inline); each duplicated literal had to
    /// be manually kept in lockstep with the enum's variant set.
    ///
    /// Adding a new variant to [`Self`] (e.g. a future `Url` kind in
    /// lockstep with a hypothetical `FigmentSourceTag::Url` if figment
    /// grows one) means extending this slice in lockstep with the
    /// variant itself. The compiler enforces nothing here directly,
    /// so the `figment_source_kind_all_covers_every_constructible_tag`
    /// test pins the contract by asserting that every kind produced by
    /// [`FigmentSourceTag::kind`] over the canonical sample table
    /// appears in [`Self::ALL`], and the
    /// `figment_source_kind_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant). Together they pin
    /// the constant to the variant space the typescape recognizes.
    pub const ALL: &'static [Self] = &[Self::File, Self::Code, Self::Custom];

    /// Returns `true` for [`Self::File`]; equivalent to
    /// `self == FigmentSourceKind::File`. Convenience predicate
    /// matching the [`ConfigSource::is_file`] /
    /// [`ConfigSource::is_env`] / [`ConfigSource::is_defaults`]
    /// sibling pattern on the shikumi-source axis.
    #[must_use]
    pub fn is_file(self) -> bool {
        matches!(self, Self::File)
    }

    /// Returns `true` for [`Self::Code`].
    #[must_use]
    pub fn is_code(self) -> bool {
        matches!(self, Self::Code)
    }

    /// Returns `true` for [`Self::Custom`].
    #[must_use]
    pub fn is_custom(self) -> bool {
        matches!(self, Self::Custom)
    }

    /// Canonical operator-facing lowercase name of the figment-Source
    /// kind — `"file"`, `"code"`, or `"custom"`.
    ///
    /// The single source of truth for the figment-Source-axis kind
    /// label strings on the [`FigmentSourceKind`] axis. Inherent mirror
    /// of the [`crate::ClosedAxisLabel`] trait method; the trait impl
    /// delegates here so the canonical names live at one site instead
    /// of being re-stated at every operator-facing surface (a future
    /// structured-log field naming the figment-Source-axis kind of a
    /// failing attribution, a CLI flag filtering attributions by
    /// figment-Source-axis kind, an attestation manifest recording the
    /// figment-Source-axis kind histogram of loaded values). The
    /// strings match the variant identifiers in ASCII-lowercase form —
    /// the same form an operator would type into an env var or CLI
    /// flag.
    ///
    /// The label space coincides with [`ConfigSourceKind::as_str`] on
    /// the `"file"` cell — [`Self::File`] and
    /// [`ConfigSourceKind::File`] both render as `"file"`, by design:
    /// the shikumi-side file layer typically loads through a figment
    /// File-source provider, so the operator-facing label is the same
    /// concept viewed from the two sides of the resolution boundary
    /// ([`crate::AttributionSourceKindCoordinates`] joins the two
    /// axes as the (figment-source-kind × shikumi-layer-kind) cube).
    /// The other two cells (`"code"`, `"custom"`) are unique to the
    /// figment-Source axis. The trait-uniform distinctness law
    /// (`closed_axis_label_as_str_distinct_for_every_implementor`)
    /// pins distinctness within an axis only; cross-axis label
    /// coincidence is structural, not a discipline violation.
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned for
    /// every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `figment_source_kind_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"Code"`, prefixing `"figment-file"`) fails
    /// at that site before drifting through the round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Code => "code",
            Self::Custom => "custom",
        }
    }
}

impl crate::ClosedAxis for FigmentSourceKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for FigmentSourceKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
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
    fn file_format_reports_extension_format_for_file_only() {
        use crate::discovery::Format;
        assert_eq!(
            ConfigSource::File(PathBuf::from("/etc/app/app.yaml")).file_format(),
            Some(Format::Yaml)
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("app.yml")).file_format(),
            Some(Format::Yaml)
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("app.toml")).file_format(),
            Some(Format::Toml)
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("app.lisp")).file_format(),
            Some(Format::Lisp)
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("app.nix")).file_format(),
            Some(Format::Nix)
        );
        // Non-File sources have no file format.
        assert_eq!(ConfigSource::Defaults.file_format(), None);
        assert_eq!(ConfigSource::Env("APP_".to_owned()).file_format(), None);
    }

    #[test]
    fn file_format_none_for_unrecognized_or_extensionless_file() {
        // A `File` with an unknown extension yields `None` even though
        // `with_file` would parse it via the TOML fallback — `None` here
        // means "extension declared no format", distinguished from a
        // non-File source by `is_file`.
        let unknown = ConfigSource::File(PathBuf::from("app.conf"));
        assert_eq!(unknown.file_format(), None);
        assert!(unknown.is_file());

        let no_ext = ConfigSource::File(PathBuf::from("app"));
        assert_eq!(no_ext.file_format(), None);
        assert!(no_ext.is_file());
    }

    #[test]
    fn file_format_agrees_with_format_from_path_pointwise() {
        // The accessor is exactly `Format::from_path` on the recorded path
        // for `File` sources, and `None` otherwise.
        for path in [
            "c.yaml", "c.yml", "c.toml", "c.lisp", "c.el", "c.nix", "c.json", "c",
        ] {
            let src = ConfigSource::File(PathBuf::from(path));
            assert_eq!(
                src.file_format(),
                crate::discovery::Format::from_path(Path::new(path)),
                "path: {path}"
            );
        }
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

    // ---- ConfigSourceChain (chain-level provenance queries) ----

    fn sample_chain() -> Vec<ConfigSource> {
        vec![
            ConfigSource::File(PathBuf::from("/etc/app/app.yaml")),
            ConfigSource::File(PathBuf::from("/home/u/.config/app/app.yaml")),
            ConfigSource::Env("APP_".to_owned()),
        ]
    }

    #[test]
    fn find_file_returns_matching_file_entry() {
        let chain = sample_chain();
        let hit = chain
            .find_file(Path::new("/home/u/.config/app/app.yaml"))
            .expect("a file layer was loaded from that path");
        assert_eq!(
            hit.as_path(),
            Some(Path::new("/home/u/.config/app/app.yaml"))
        );
    }

    #[test]
    fn find_file_none_for_unrecorded_path() {
        let chain = sample_chain();
        assert!(chain.find_file(Path::new("/nope.yaml")).is_none());
    }

    #[test]
    fn find_file_ignores_non_file_layers() {
        // A path that no File layer carries; Env/Defaults must never match
        // even though the chain has those layers.
        let chain = [ConfigSource::Defaults, ConfigSource::Env("E_".to_owned())];
        assert!(chain.find_file(Path::new("/etc/app/app.yaml")).is_none());
    }

    #[test]
    fn find_file_agrees_with_open_coded_walk_pointwise() {
        let chain = sample_chain();
        for probe in [
            Path::new("/etc/app/app.yaml"),
            Path::new("/home/u/.config/app/app.yaml"),
            Path::new("/missing.toml"),
        ] {
            let lifted = chain.find_file(probe);
            let manual = chain.iter().find(|s| s.as_path() == Some(probe));
            assert_eq!(
                lifted, manual,
                "find_file must match the walk for {probe:?}"
            );
        }
    }

    #[test]
    fn unique_of_kind_returns_sole_layer() {
        let chain = [
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/a.yaml")),
        ];
        let env = chain
            .unique_of_kind(ConfigSourceKind::Env)
            .expect("exactly one env layer");
        assert_eq!(env.as_env_prefix(), Some("ONLY_"));
        let defaults = chain
            .unique_of_kind(ConfigSourceKind::Defaults)
            .expect("exactly one defaults layer");
        assert!(defaults.is_defaults());
    }

    #[test]
    fn unique_of_kind_none_when_ambiguous() {
        // Two File layers → File is not unique.
        let chain = sample_chain();
        assert!(chain.unique_of_kind(ConfigSourceKind::File).is_none());
    }

    #[test]
    fn unique_of_kind_none_when_absent() {
        // Chain with no defaults layer.
        let chain = sample_chain();
        assert!(chain.unique_of_kind(ConfigSourceKind::Defaults).is_none());
    }

    #[test]
    fn unique_of_kind_agrees_with_open_coded_uniqueness() {
        // Pin equivalence to the filter+next+next().is_none() pattern the
        // failing-source resolver used to inline, over every kind and over
        // chains with 0, 1, and 2 layers of the probed kind.
        let chains = [
            Vec::new(),
            vec![ConfigSource::Defaults],
            sample_chain(),
            vec![
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::Env("B_".to_owned()),
            ],
        ];
        for chain in &chains {
            for kind in ConfigSourceKind::ALL.iter().copied() {
                let lifted = chain.unique_of_kind(kind);
                let mut hits = chain.iter().filter(|s| s.kind() == kind);
                let manual = hits.next().filter(|_| hits.next().is_none());
                assert_eq!(
                    lifted, manual,
                    "unique_of_kind({kind:?}) must match the open-coded uniqueness walk"
                );
            }
        }
    }

    #[test]
    fn find_env_by_prefix_returns_matching_env_entry() {
        let chain = sample_chain();
        let hit = chain
            .find_env_by_prefix("APP_")
            .expect("an env layer was recorded with that prefix");
        assert_eq!(hit.as_env_prefix(), Some("APP_"));
    }

    #[test]
    fn find_env_by_prefix_matches_case_insensitively() {
        // figment uppercases the prefix when emitting metadata names,
        // while users may pass any case to ProviderChain::with_env. The
        // primitive must match across the case boundary so the
        // failing-source resolver's EnvByPrefix rule fires regardless of
        // which side carries the canonical casing.
        let chain = [ConfigSource::Env("myapp_".to_owned())];
        let hit = chain
            .find_env_by_prefix("MYAPP_")
            .expect("ASCII case-insensitive match must locate the layer");
        assert_eq!(hit.as_env_prefix(), Some("myapp_"));

        let chain = [ConfigSource::Env("MyApp_".to_owned())];
        assert!(chain.find_env_by_prefix("MYAPP_").is_some());
        assert!(chain.find_env_by_prefix("myapp_").is_some());
        assert!(chain.find_env_by_prefix("myApp_").is_some());
    }

    #[test]
    fn find_env_by_prefix_none_for_unrecorded_prefix() {
        let chain = sample_chain();
        assert!(chain.find_env_by_prefix("OTHER_").is_none());
    }

    #[test]
    fn find_env_by_prefix_ignores_non_env_layers() {
        // A chain of File/Defaults layers must never match, even when the
        // probe is a non-empty prefix string that could conceivably collide
        // with some file path; only Env layers carry prefixes.
        let chain = [
            ConfigSource::Defaults,
            ConfigSource::File(PathBuf::from("/etc/APP_/app.yaml")),
        ];
        assert!(chain.find_env_by_prefix("APP_").is_none());
    }

    #[test]
    fn find_env_by_prefix_returns_first_match() {
        // Two env layers with the same prefix (degenerate but constructible
        // via two with_env calls): the first match wins, matching the
        // iter().find semantics the resolver previously inlined.
        let first = ConfigSource::Env("DUP_".to_owned());
        let second = ConfigSource::Env("DUP_".to_owned());
        let chain = [first.clone(), second];
        let hit = chain
            .find_env_by_prefix("DUP_")
            .expect("first matching env layer");
        // Compare by address: must be the first slot, not the second.
        assert!(std::ptr::eq(hit, &chain[0]));
    }

    #[test]
    fn find_env_by_prefix_matches_empty_prefix() {
        // figment::providers::Env::raw() emits the bare metadata-name
        // shape, recognized as EnvMetadataTag::Bare and routed to the
        // uniqueness rule by the resolver — but a chain may still carry
        // an Env layer with the empty prefix. The primitive matches it
        // pointwise.
        let chain = [ConfigSource::Env(String::new())];
        let hit = chain
            .find_env_by_prefix("")
            .expect("empty-prefix env layer");
        assert_eq!(hit.as_env_prefix(), Some(""));
    }

    #[test]
    fn find_env_by_prefix_agrees_with_open_coded_walk_pointwise() {
        // Pin equivalence to the iter().find(|s| s.as_env_prefix()
        // .is_some_and(|p| p.eq_ignore_ascii_case(probe))) pattern the
        // failing-source resolver used to inline, across the case
        // boundary and across chains with 0, 1, and 2 env layers.
        let chains = [
            Vec::new(),
            vec![ConfigSource::Defaults],
            sample_chain(),
            vec![
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::Env("B_".to_owned()),
            ],
            vec![ConfigSource::Env("MixedCase_".to_owned())],
        ];
        for chain in &chains {
            for probe in ["APP_", "app_", "A_", "MIXEDCASE_", "OTHER_", ""] {
                let lifted = chain.find_env_by_prefix(probe);
                let manual = chain.iter().find(|s| {
                    s.as_env_prefix()
                        .is_some_and(|p| p.eq_ignore_ascii_case(probe))
                });
                assert_eq!(
                    lifted, manual,
                    "find_env_by_prefix({probe:?}) must match the open-coded walk"
                );
            }
        }
    }

    // ---- ConfigSourceKind / ConfigSource::kind ----

    #[test]
    fn kind_classifies_defaults() {
        assert_eq!(ConfigSource::Defaults.kind(), ConfigSourceKind::Defaults);
    }

    #[test]
    fn kind_classifies_env_regardless_of_prefix() {
        // Inner prefix does not influence kind — every Env variant maps
        // to ConfigSourceKind::Env, including the empty-prefix case.
        for prefix in ["", "MYAPP_", "X_", "very_long_prefix_with_underscores_"] {
            let s = ConfigSource::Env(prefix.to_owned());
            assert_eq!(s.kind(), ConfigSourceKind::Env);
        }
    }

    #[test]
    fn kind_classifies_file_regardless_of_path() {
        // Inner path does not influence kind — every File variant maps
        // to ConfigSourceKind::File, including bare and deep paths.
        for path in ["/etc/app.yaml", "rel.toml", "/very/deep/path/cfg.lisp"] {
            let s = ConfigSource::File(PathBuf::from(path));
            assert_eq!(s.kind(), ConfigSourceKind::File);
        }
    }

    #[test]
    fn kind_partitions_every_constructible_variant() {
        // Every ConfigSource maps to exactly one ConfigSourceKind. Pins
        // the partition contract that ConfigSource::kind is a total
        // function over the variant space; a new variant added to
        // ConfigSource forces a kind assignment in the exhaustive
        // match (compile-time), and this test pins that the partition
        // is a function (no source maps to two kinds).
        let cases: [(ConfigSource, ConfigSourceKind); 3] = [
            (ConfigSource::Defaults, ConfigSourceKind::Defaults),
            (ConfigSource::Env("X_".to_owned()), ConfigSourceKind::Env),
            (
                ConfigSource::File(PathBuf::from("/x")),
                ConfigSourceKind::File,
            ),
        ];
        for (src, expected) in &cases {
            assert_eq!(src.kind(), *expected);
        }
        // Distinct sources of the same kind collapse to the same kind
        // (the kind discriminant is data-free).
        assert_eq!(
            ConfigSource::Env("A_".to_owned()).kind(),
            ConfigSource::Env("B_".to_owned()).kind(),
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("/a")).kind(),
            ConfigSource::File(PathBuf::from("/b")).kind(),
        );
    }

    #[test]
    fn kind_agrees_with_is_predicates_pointwise() {
        // The kind() / is_*() pair must agree on every constructible
        // variant — kind is the closed-enum lift of the three booleans.
        for src in [
            ConfigSource::Defaults,
            ConfigSource::Env("X_".to_owned()),
            ConfigSource::File(PathBuf::from("/x")),
        ] {
            assert_eq!(src.is_defaults(), src.kind() == ConfigSourceKind::Defaults);
            assert_eq!(src.is_env(), src.kind() == ConfigSourceKind::Env);
            assert_eq!(src.is_file(), src.kind() == ConfigSourceKind::File);
        }
    }

    #[test]
    fn config_source_kind_is_copy_and_hashable() {
        // Trait-bounds parity with sibling typescape primitives
        // (AttributionRule, AttributionConfidence, FigmentSourceTag,
        // FigmentNameTag, EnvMetadataTag). Iterates ConfigSourceKind::ALL
        // so a future variant landing extends the parity check without
        // editing this test.
        use std::collections::HashSet;
        let mut set: HashSet<ConfigSourceKind> = ConfigSourceKind::ALL.iter().copied().collect();
        set.insert(ConfigSourceKind::Defaults); // duplicate
        assert_eq!(set.len(), ConfigSourceKind::ALL.len());
        // Copy: rebind without move.
        let k = ConfigSourceKind::Env;
        let k2 = k;
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k2, k3);
    }

    // ---- ConfigSourceKind::ALL tests ----

    #[test]
    fn config_source_kind_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every variant appears
        // at most once. Pins the "no double-listed kind" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost kind contributing twice to a partition tally over the
        // ConfigSource / AttributionRule layer-kind projection.
        use std::collections::HashSet;
        let unique: HashSet<ConfigSourceKind> = ConfigSourceKind::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ConfigSourceKind::ALL.len(),
            "ConfigSourceKind::ALL must contain no duplicates",
        );
    }

    #[test]
    fn config_source_kind_all_covers_every_constructible_variant() {
        // Mutual-cover statement: the canonical sample table covers every
        // ConfigSourceKind variant exactly once via ConfigSource::kind,
        // and ALL equals the same set. A future ConfigSource variant
        // landing forces a kind() arm (compile-time, exhaustive match)
        // and a sample-table row (here); this test fails until ALL is
        // extended in lockstep, catching forgotten ALL updates.
        use std::collections::HashSet;
        let produced: HashSet<ConfigSourceKind> = [
            ConfigSource::Defaults,
            ConfigSource::Env("X_".to_owned()),
            ConfigSource::File(PathBuf::from("/x")),
        ]
        .iter()
        .map(ConfigSource::kind)
        .collect();
        let listed: HashSet<ConfigSourceKind> = ConfigSourceKind::ALL.iter().copied().collect();
        assert_eq!(
            produced, listed,
            "ConfigSourceKind::ALL must equal the kind set produced by ConfigSource::kind",
        );
    }

    #[test]
    fn config_source_kind_all_cardinality_matches_variant_count() {
        // Stronger statement of the prior test on the cardinality axis:
        // ALL.len() must equal the variant count of the closed partition
        // (three: Defaults, Env, File). Stated through the constant
        // rather than an inline literal so a future variant landing
        // forces a sample-table row + an ALL entry in lockstep.
        let produced_count = [
            ConfigSource::Defaults,
            ConfigSource::Env(String::new()),
            ConfigSource::File(PathBuf::from("/x")),
        ]
        .iter()
        .map(ConfigSource::kind)
        .collect::<std::collections::HashSet<_>>()
        .len();
        assert_eq!(
            ConfigSourceKind::ALL.len(),
            produced_count,
            "ALL.len() must equal the canonical kind-partition cardinality",
        );
    }

    #[test]
    fn config_source_kind_all_iterates_in_declaration_order() {
        // The constant lists variants in the same order as the enum's
        // declaration arms (Defaults, Env, File). Iteration order is
        // observable — consumers (alerting policies, dashboards, miette
        // diagnostic renderers) that rely on a stable ordering for
        // priority/severity can route on it.
        assert_eq!(
            ConfigSourceKind::ALL,
            &[
                ConfigSourceKind::Defaults,
                ConfigSourceKind::Env,
                ConfigSourceKind::File,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn config_source_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on ConfigSourceKind::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Env", prefixing "layer-env", switching
        // "defaults" to "default" — colliding with ConfigTierKind's
        // "default" label across axes) fails here before drifting
        // through the trait-uniform round-trip law and the
        // operator-facing rendering surface.
        assert_eq!(ConfigSourceKind::Defaults.as_str(), "defaults");
        assert_eq!(ConfigSourceKind::Env.as_str(), "env");
        assert_eq!(ConfigSourceKind::File.as_str(), "file");
    }

    #[test]
    fn config_source_kind_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // ConfigSourceKind: each canonical lowercase name parses back
        // to its variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the ConfigSourceKind site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law. Composes with the cross-axis
        // distinctness pin in
        // `config_source_kind_as_str_yields_canonical_lowercase_names`:
        // the three canonical names ("defaults", "env", "file") are
        // disjoint from the four ConfigTierKind labels ("bare",
        // "discovered", "default", "custom"), so an operator-facing
        // surface that routes a string label through both parsers
        // sequentially returns at most one Some(_), never both.
        use crate::ClosedAxisLabel;
        for k in ConfigSourceKind::ALL.iter().copied() {
            assert_eq!(
                <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str(k.as_str()),
                Some(k),
                "trait from_canonical_str must round-trip for {k:?}",
            );
        }
        // Case-insensitive parse: the default impl uses
        // `eq_ignore_ascii_case`, so mixed-case forms an operator
        // might type in an env var or CLI flag reach the same variant.
        assert_eq!(
            <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str("DEFAULTS"),
            Some(ConfigSourceKind::Defaults),
        );
        assert_eq!(
            <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str("Env"),
            Some(ConfigSourceKind::Env),
        );
        assert_eq!(
            <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str("FILE"),
            Some(ConfigSourceKind::File),
        );
        // Unrecognized strings return None — the parse is closed over
        // `ConfigSourceKind::ALL` and rejects anything else, including
        // the singular form of "defaults" (a one-character drift).
        assert_eq!(
            <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str("default"),
            None,
        );
        assert_eq!(
            <ConfigSourceKind as ClosedAxisLabel>::from_canonical_str("http"),
            None,
        );
    }

    #[test]
    fn config_source_kind_all_covers_every_attribution_rule_layer_kind() {
        // Cross-axis coverage: every AttributionRule's layer_kind() is a
        // ConfigSourceKind that appears in ALL. Pins the structural
        // alignment between the rule space's layer-kind projection and
        // the layer-kind universe — a future rule landing with a
        // layer_kind that ALL doesn't list fails this test before any
        // observation site can silently bucket it as "unknown".
        use std::collections::HashSet;
        let rule_kinds: HashSet<ConfigSourceKind> = crate::error::AttributionRule::ALL
            .iter()
            .map(|r| r.layer_kind())
            .collect();
        let listed: HashSet<ConfigSourceKind> = ConfigSourceKind::ALL.iter().copied().collect();
        assert!(
            rule_kinds.is_subset(&listed),
            "every AttributionRule::layer_kind() must appear in ConfigSourceKind::ALL: \
             rule_kinds={rule_kinds:?}, listed={listed:?}",
        );
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

    // ---- FigmentSourceKind / FigmentSourceTag::kind ----

    #[test]
    fn figment_source_kind_classifies_each_variant() {
        // The forward map is exhaustive: every FigmentSourceTag variant
        // pins to exactly one FigmentSourceKind. Pairs with the
        // `kind_partitions_every_constructible_variant` style on
        // ConfigSource → ConfigSourceKind.
        let file_src = figment::Source::File(PathBuf::from("/etc/app/app.yaml"));
        let file_tag = FigmentSourceTag::classify(&file_src).unwrap();
        assert_eq!(file_tag.kind(), FigmentSourceKind::File);

        // Source::Code arrives via the Serialized provider.
        use figment::Provider;
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let md = prov.metadata();
        let code_src = md.source.as_ref().unwrap();
        let code_tag = FigmentSourceTag::classify(code_src).unwrap();
        assert_eq!(code_tag.kind(), FigmentSourceKind::Code);

        let custom_src = figment::Source::Custom("vault://kv/app".to_owned());
        let custom_tag = FigmentSourceTag::classify(&custom_src).unwrap();
        assert_eq!(custom_tag.kind(), FigmentSourceKind::Custom);
    }

    #[test]
    fn figment_source_kind_is_data_free() {
        // Inner data does not influence kind — every File maps to
        // FigmentSourceKind::File regardless of path; Custom regardless
        // of string. Mirrors `kind_classifies_file_regardless_of_path`
        // on the ConfigSource side.
        for path in ["/a", "/very/long/path/to/cfg.yaml", "rel.toml"] {
            let src = figment::Source::File(PathBuf::from(path));
            assert_eq!(
                FigmentSourceTag::classify(&src).unwrap().kind(),
                FigmentSourceKind::File,
            );
        }
        for s in ["", "a", "vault://kv/x", "ftp://configs"] {
            let src = figment::Source::Custom(s.to_owned());
            assert_eq!(
                FigmentSourceTag::classify(&src).unwrap().kind(),
                FigmentSourceKind::Custom,
            );
        }
    }

    #[test]
    fn figment_source_kind_agrees_with_predicates_pointwise() {
        // The kind() / is_*() pair must agree on every constructible
        // tag variant — kind is the closed-enum lift of the open-coded
        // booleans.
        use figment::Provider;
        let file_src = figment::Source::File(PathBuf::from("/x"));
        let custom_src = figment::Source::Custom("c".to_owned());
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let md = prov.metadata();
        let code_src = md.source.as_ref().unwrap();
        for tag in [
            FigmentSourceTag::classify(&file_src).unwrap(),
            FigmentSourceTag::classify(code_src).unwrap(),
            FigmentSourceTag::classify(&custom_src).unwrap(),
        ] {
            assert_eq!(tag.is_code(), tag.kind() == FigmentSourceKind::Code);
            assert_eq!(
                tag.as_file_path().is_some(),
                tag.kind() == FigmentSourceKind::File,
            );
            assert_eq!(
                tag.as_custom().is_some(),
                tag.kind() == FigmentSourceKind::Custom,
            );
            // Kind-side predicates agree pointwise with the tag-side
            // predicates.
            assert_eq!(tag.kind().is_file(), tag.kind() == FigmentSourceKind::File);
            assert_eq!(tag.kind().is_code(), tag.kind() == FigmentSourceKind::Code);
            assert_eq!(
                tag.kind().is_custom(),
                tag.kind() == FigmentSourceKind::Custom,
            );
        }
    }

    #[test]
    fn figment_source_kind_is_static_and_copy_and_hashable() {
        // The discriminant is `'static` (no lifetime parameter) so it
        // can cross thread boundaries the borrowed tag cannot. Trait
        // bounds match the sibling typescape primitives
        // (ConfigSourceKind, AttributionRule, AttributionConfidence,
        // AttributionAxis).
        use std::collections::HashSet;
        let mut set: HashSet<FigmentSourceKind> = HashSet::new();
        for k in FigmentSourceKind::ALL.iter().copied() {
            set.insert(k);
        }
        set.insert(FigmentSourceKind::File); // duplicate
        assert_eq!(set.len(), FigmentSourceKind::ALL.len());

        // Copy: rebind without move.
        let k = FigmentSourceKind::Code;
        let k2 = k;
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k2, k3);

        // Send + Sync + 'static — observable by inserting into a static
        // bound: a HashSet<K> requires K: Hash + Eq, and the set itself
        // is movable across threads since K has no lifetime.
        fn assert_static<T: 'static>() {}
        assert_static::<FigmentSourceKind>();
    }

    #[test]
    fn figment_source_kind_partitions_disjointly() {
        // Each FigmentSourceTag must classify into exactly one
        // FigmentSourceKind — no tag claims two kinds at once. Mirrors
        // the disjointness invariants on FigmentSourceTag (the borrowed
        // form) and ConfigSource (the shikumi-side form).
        use figment::Provider;
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let md = prov.metadata();
        let cases: [(FigmentSourceTag<'_>, FigmentSourceKind); 3] = [
            (
                FigmentSourceTag::File(Path::new("/x")),
                FigmentSourceKind::File,
            ),
            (
                FigmentSourceTag::Code(
                    md.source
                        .as_ref()
                        .and_then(figment::Source::code_location)
                        .unwrap(),
                ),
                FigmentSourceKind::Code,
            ),
            (FigmentSourceTag::Custom("c"), FigmentSourceKind::Custom),
        ];
        for (tag, expected) in cases {
            assert_eq!(tag.kind(), expected);
            // Distinct tags of the same kind collapse to the same kind
            // (the kind discriminant is data-free).
        }
        assert_eq!(
            FigmentSourceTag::File(Path::new("/a")).kind(),
            FigmentSourceTag::File(Path::new("/b")).kind(),
        );
    }

    #[test]
    fn figment_source_tag_attribution_axis_is_always_metadata_source() {
        // Structural law: every FigmentSourceTag classification sits on
        // the metadata.source axis. This is the cross-primitive bridge
        // between FigmentSourceTag and AttributionAxis — peers with
        // FigmentNameTag's implicit always-MetadataName placement.
        use crate::AttributionAxis;
        use figment::Provider;
        let file_src = figment::Source::File(PathBuf::from("/etc/app.yaml"));
        let custom_src = figment::Source::Custom("c".to_owned());
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let md = prov.metadata();
        let code_src = md.source.as_ref().unwrap();

        for tag in [
            FigmentSourceTag::classify(&file_src).unwrap(),
            FigmentSourceTag::classify(code_src).unwrap(),
            FigmentSourceTag::classify(&custom_src).unwrap(),
        ] {
            assert_eq!(tag.attribution_axis(), AttributionAxis::MetadataSource);
        }
    }

    #[test]
    fn figment_source_kind_round_trips_through_classify() {
        // End-to-end: classify a real figment::Source, project to kind,
        // and confirm the kind matches the originating Source variant.
        // Pins the cross-side contract that classify + kind agree with
        // figment's own variant taxonomy.
        let file = figment::Source::File(PathBuf::from("/x.yaml"));
        let custom = figment::Source::Custom("y".to_owned());
        assert_eq!(
            FigmentSourceTag::classify(&file).unwrap().kind(),
            FigmentSourceKind::File,
        );
        assert_eq!(
            FigmentSourceTag::classify(&custom).unwrap().kind(),
            FigmentSourceKind::Custom,
        );
    }

    // ---- FigmentSourceKind::ALL cover / partition / order ----

    /// Canonical sample table covering every `FigmentSourceTag` variant
    /// once, with the kind each must classify into. Sources for the
    /// `figment_source_kind_all_*` cover/partition tests below — peer
    /// to the inline `[(Tag, Kind); 3]` cases in
    /// `figment_source_kind_partitions_disjointly`.
    fn canonical_figment_source_kind_samples() -> Vec<(figment::Source, FigmentSourceKind)> {
        use figment::Provider;
        let prov = figment::providers::Serialized::defaults(serde_json::json!({"k": "v"}));
        let code_src = prov.metadata().source.expect("Serialized attaches Source");
        vec![
            (
                figment::Source::File(PathBuf::from("/etc/app/app.yaml")),
                FigmentSourceKind::File,
            ),
            (code_src, FigmentSourceKind::Code),
            (
                figment::Source::Custom("vault://kv/app".to_owned()),
                FigmentSourceKind::Custom,
            ),
        ]
    }

    #[test]
    fn figment_source_kind_all_has_no_duplicates() {
        // The constant must be a set — no variant listed twice. Pins
        // the typescape discipline shared with `Format::ALL`,
        // `ShikumiErrorKind::ALL`, `AttributionRule::ALL`,
        // `ConfigSourceKind::ALL`, `FieldPathLocalization::ALL`,
        // `FormatProvenance::ALL`, `AttributionAxis::ALL`, and
        // `AttributionConfidence::ALL`: the closed-enum `ALL` constant
        // is a deduplicated `'static` slice.
        use std::collections::HashSet;
        let set: HashSet<FigmentSourceKind> = FigmentSourceKind::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            FigmentSourceKind::ALL.len(),
            "FigmentSourceKind::ALL must contain no duplicates; got: {:?}",
            FigmentSourceKind::ALL,
        );
    }

    #[test]
    fn figment_source_kind_all_covers_every_constructible_tag() {
        // Subset cover: every kind produced by FigmentSourceTag::kind
        // over the canonical sample table must lie in
        // FigmentSourceKind::ALL. Pins the cross-axis cover law: the
        // tag space cannot manufacture a kind outside the declared kind
        // enumeration. A future tag variant that adds a new kind class
        // must extend FigmentSourceKind and its ALL in the same commit;
        // otherwise this test fails.
        use std::collections::HashSet;
        let declared: HashSet<FigmentSourceKind> = FigmentSourceKind::ALL.iter().copied().collect();
        let observed: HashSet<FigmentSourceKind> = canonical_figment_source_kind_samples()
            .iter()
            .map(|(src, _)| FigmentSourceTag::classify(src).unwrap().kind())
            .collect();
        assert!(
            observed.is_subset(&declared),
            "FigmentSourceTag::kind image must lie in FigmentSourceKind::ALL; \
             observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn figment_source_kind_all_equals_tag_kind_image() {
        // Tight equality (stronger than subset cover): every variant
        // in FigmentSourceKind::ALL must be witnessed by at least one
        // tag's kind() — no orphan variant in the declared kind space
        // lacks a producing tag. Today the three kind variants are all
        // reached (File by Source::File, Code by Source::Code via the
        // Serialized provider, Custom by Source::Custom); this test
        // pins that contract.
        use std::collections::HashSet;
        let declared: HashSet<FigmentSourceKind> = FigmentSourceKind::ALL.iter().copied().collect();
        let observed: HashSet<FigmentSourceKind> = canonical_figment_source_kind_samples()
            .iter()
            .map(|(src, _)| FigmentSourceTag::classify(src).unwrap().kind())
            .collect();
        assert_eq!(
            observed, declared,
            "FigmentSourceTag::kind image must equal FigmentSourceKind::ALL",
        );
    }

    #[test]
    fn figment_source_kind_all_cardinality_matches_partition() {
        // The constant's cardinality must equal the number of distinct
        // kind cells produced by the tag space — pins that ALL is
        // sized to the partition, not to a stale hand-typed count. A
        // future variant added to FigmentSourceKind without a tag that
        // witnesses it (or vice versa) breaks this equality.
        use std::collections::HashSet;
        let cells: HashSet<FigmentSourceKind> = canonical_figment_source_kind_samples()
            .iter()
            .map(|(src, _)| FigmentSourceTag::classify(src).unwrap().kind())
            .collect();
        assert_eq!(
            FigmentSourceKind::ALL.len(),
            cells.len(),
            "FigmentSourceKind::ALL cardinality must match partition cell count",
        );
    }

    #[test]
    fn figment_source_kind_all_declaration_order_is_file_code_custom() {
        // Pin declaration order. Consumers (diagnostics legends,
        // attestation manifests, dashboard column orderings) that
        // iterate ALL get a stable order; reordering the slice is a
        // breaking change that must show up here.
        assert_eq!(
            FigmentSourceKind::ALL,
            &[
                FigmentSourceKind::File,
                FigmentSourceKind::Code,
                FigmentSourceKind::Custom,
            ],
        );
    }

    #[test]
    fn figment_source_kind_all_partition_is_file_xor_code_xor_custom() {
        // Boolean partition: `is_file` / `is_code` / `is_custom` over a
        // tag sliced by each kind cell must agree with the cell's
        // identity. Pins that FigmentSourceKind::ALL is a partition of
        // the tag space's kind image — every tag lands in exactly one
        // cell, and the boolean accessors agree pointwise.
        let samples = canonical_figment_source_kind_samples();
        for kind in FigmentSourceKind::ALL.iter().copied() {
            let witnessing_src = samples
                .iter()
                .find(|(src, _)| FigmentSourceTag::classify(src).unwrap().kind() == kind)
                .map(|(src, _)| src)
                .expect("every kind cell must be witnessed by some tag");
            let tag = FigmentSourceTag::classify(witnessing_src).unwrap();
            match kind {
                FigmentSourceKind::File => {
                    assert!(tag.kind().is_file());
                    assert!(!tag.kind().is_code());
                    assert!(!tag.kind().is_custom());
                }
                FigmentSourceKind::Code => {
                    assert!(tag.kind().is_code());
                    assert!(!tag.kind().is_file());
                    assert!(!tag.kind().is_custom());
                }
                FigmentSourceKind::Custom => {
                    assert!(tag.kind().is_custom());
                    assert!(!tag.kind().is_file());
                    assert!(!tag.kind().is_code());
                }
            }
        }
    }

    #[test]
    fn figment_source_kind_all_iterates_in_declaration_order() {
        // Sanity: iteration over ALL yields variants in the same order
        // as the slice literal. Peer to `config_source_kind_all_iterates_in_declaration_order`
        // on the shikumi-side kind axis.
        let collected: Vec<FigmentSourceKind> = FigmentSourceKind::ALL.to_vec();
        assert_eq!(
            collected,
            vec![
                FigmentSourceKind::File,
                FigmentSourceKind::Code,
                FigmentSourceKind::Custom,
            ],
        );
    }

    #[test]
    fn figment_source_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on FigmentSourceKind::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Code", prefixing "figment-file",
        // switching "custom" to "raw") fails here before drifting
        // through the trait-uniform round-trip law and the
        // operator-facing rendering surface. The `"file"` label
        // intentionally coincides with `ConfigSourceKind::File`'s
        // label by typescape design: the two axes meet at the
        // shikumi-file-layer ↔ figment-File-source resolution
        // boundary, joined as a cube cell in
        // `AttributionSourceKindCoordinates`.
        assert_eq!(FigmentSourceKind::File.as_str(), "file");
        assert_eq!(FigmentSourceKind::Code.as_str(), "code");
        assert_eq!(FigmentSourceKind::Custom.as_str(), "custom");
    }

    #[test]
    fn figment_source_kind_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // FigmentSourceKind: each canonical lowercase name parses back
        // to its variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the FigmentSourceKind site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law. Mixed-case forms an operator might
        // type in an env var or CLI flag (`"File"`, `"CODE"`,
        // `"Custom"`) round-trip case-insensitively. Unrecognized
        // strings — including `"code "` (trailing whitespace) and
        // `"fil"` (a one-character drift from `"file"`) — reject.
        use crate::ClosedAxisLabel;
        for k in FigmentSourceKind::ALL.iter().copied() {
            assert_eq!(
                <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str(k.as_str()),
                Some(k),
                "trait from_canonical_str must round-trip for {k:?}",
            );
        }
        assert_eq!(
            <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str("File"),
            Some(FigmentSourceKind::File),
        );
        assert_eq!(
            <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str("CODE"),
            Some(FigmentSourceKind::Code),
        );
        assert_eq!(
            <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str("Custom"),
            Some(FigmentSourceKind::Custom),
        );
        assert_eq!(
            <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str("code "),
            None,
        );
        assert_eq!(
            <FigmentSourceKind as ClosedAxisLabel>::from_canonical_str("fil"),
            None,
        );
    }

    #[test]
    fn figment_source_kind_all_attribution_axis_image_is_metadata_source() {
        // Cross-primitive cover law: every kind in FigmentSourceKind::ALL
        // — when projected back through a witnessing tag's
        // `attribution_axis()` — must lie on AttributionAxis::MetadataSource.
        // Pins the structural law `figment_source_tag_attribution_axis_is_always_metadata_source`
        // from the perspective of the kind axis: the figment-Source-axis
        // kind partition is a sub-partition of the metadata.source
        // attribution axis. Mirrors how `AttributionConfidence::ALL`
        // pins its image in `failing_source_attribution_confidence_image_lies_in_all`.
        use crate::AttributionAxis;
        use std::collections::HashSet;
        let samples = canonical_figment_source_kind_samples();
        let observed: HashSet<AttributionAxis> = FigmentSourceKind::ALL
            .iter()
            .copied()
            .map(|kind| {
                let (src, _) = samples
                    .iter()
                    .find(|(src, _)| FigmentSourceTag::classify(src).unwrap().kind() == kind)
                    .expect("every kind cell must be witnessed");
                FigmentSourceTag::classify(src).unwrap().attribution_axis()
            })
            .collect();
        assert_eq!(
            observed,
            HashSet::from([AttributionAxis::MetadataSource]),
            "every FigmentSourceKind variant projects to AttributionAxis::MetadataSource",
        );
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

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
use std::str::FromStr;

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

    /// The [`EnvMetadataTagKind`] declared by this source's recorded env
    /// prefix shape, if this is a [`Self::Env`] layer.
    ///
    /// Returns `Some(EnvMetadataTagKind::Bare)` for [`Self::Env`] with an
    /// empty prefix (the layer figment routes through
    /// [`figment::providers::Env::raw`]-shape emission), and
    /// `Some(EnvMetadataTagKind::Prefixed)` for [`Self::Env`] with any
    /// non-empty prefix (the layer figment routes through
    /// [`figment::providers::Env::prefixed`]-shape emission). Returns
    /// `None` for [`Self::Defaults`] / [`Self::File`] sources — those
    /// layers carry no env-prefix shape at all.
    ///
    /// The chain-side projection on the env-name sub-axis: pointwise
    /// peer of the figment-side [`EnvMetadataTag::kind`] projection that
    /// reaches the same [`EnvMetadataTagKind`] axis from the parsed
    /// `figment::Metadata::name`. The two surfaces converge on one kind
    /// axis by construction — given the same `prefix`, the chain entry
    /// `ConfigSource::Env(prefix.into()).env_prefix_kind()` agrees with
    /// `ConfigSource::strip_env_metadata_name(&ConfigSource::env_metadata_name(prefix))
    /// .map(EnvMetadataTag::kind)` — pinned by
    /// `env_prefix_kind_agrees_with_figment_env_metadata_tag_kind` so a
    /// future divergence (e.g. figment growing a `Glob` env shape that
    /// [`Self::strip_env_metadata_name`] recognizes but the chain
    /// projection does not) surfaces at the boundary.
    ///
    /// The partial projection composed by
    /// [`ConfigSourceChain::env_prefix_kind_histogram`] to lift the
    /// (chain → `EnvMetadataTagKind`) tally over the env-prefix-presence
    /// axis — peer to [`Self::file_format`] on the file-format axis and
    /// [`Self::kind`] on the layer-kind axis. Together the three
    /// projections close the natural per-cell axes of the chain entry:
    /// every [`ConfigSource`] carries a total [`ConfigSourceKind`]
    /// discriminant ([`Self::kind`]) and at most one of the two partial
    /// sub-axis projections ([`Self::file_format`] on `File` layers with
    /// recognized extensions, [`Self::env_prefix_kind`] on `Env` layers
    /// regardless of prefix shape) — a structural partition the trait-
    /// default histograms now expose as three aggregate projections.
    #[must_use]
    pub fn env_prefix_kind(&self) -> Option<EnvMetadataTagKind> {
        match self {
            Self::Env(prefix) if prefix.is_empty() => Some(EnvMetadataTagKind::Bare),
            Self::Env(_) => Some(EnvMetadataTagKind::Prefixed),
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
///
/// **Trait surface** — alongside the canonical
/// `Debug + Clone + Copy + PartialEq + Eq + Hash` set, the derive also
/// includes [`Ord`] + [`PartialOrd`]. The total order is the
/// declaration-order lex over [`Self::ALL`]
/// (`Defaults < Env < File`), so a
/// [`BTreeMap<ConfigSourceKind, T>`][std::collections::BTreeMap] keyed
/// on the layer-kind axis (per-kind attribution histograms, per-kind
/// failure-rate dashboards, attestation manifests recording the layer-
/// kind cardinality mix of a recorded chain) emits rows in declaration
/// order deterministically without a hand-rolled comparator at the
/// renderer. Idiom-peer of the [`Ord`] derive on
/// [`crate::FormatProvenance`] (commit `2c7654c`), [`crate::Format`]
/// (commit `b56b121`), and the typed-cube classifiers
/// ([`crate::ModalityClass`], [`crate::PartitionFace`], …); pinned by
/// [`tests::config_source_kind_ord_matches_all_declaration_order`].
///
/// **Canonical-string surface** — [`fmt::Display`] /
/// [`std::str::FromStr`] round-trip through the canonical operator-
/// facing lowercase label [`Self::as_str`] returns (`"defaults"` /
/// `"env"` / `"file"`); `FromStr` lowers through the trait-default
/// [`crate::ClosedAxisLabel::from_canonical_str`] parse and inherits
/// ASCII case-insensitivity. Pinned by
/// [`tests::config_source_kind_display_matches_as_str`] and
/// [`tests::config_source_kind_from_str_round_trips_over_every_variant`].
///
/// **Serde surface** — [`serde::Serialize`] / [`serde::Deserialize`]
/// are the canonical idiom-peer of the ([`fmt::Display`],
/// [`std::str::FromStr`]) pair. Serialize emits the canonical
/// lowercase label through [`serde::Serializer::collect_str`];
/// Deserialize lowers through [`<Self as FromStr>::from_str`],
/// inheriting the trait-default case-insensitivity. An attestation
/// manifest field recording which layer-kind originated a failing
/// attribution, a structured-log payload tagging the layer-kind of a
/// chain entry, or a consumer struct holding a [`ConfigSourceKind`]
/// under `#[derive(Serialize, Deserialize)]` round-trips through the
/// canonical label without a consumer-side rename helper. Pinned by
/// [`tests::config_source_kind_serde_yaml_round_trips_over_every_variant`],
/// [`tests::config_source_kind_serde_json_round_trips_over_every_variant`],
/// [`tests::config_source_kind_serde_yaml_is_case_insensitive`], and
/// [`tests::config_source_kind_serde_yaml_unknown_kind_error_carries_label_verbatim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
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

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the layer-kind closed-enum, lifted to one macro after the
// 16+ hand-rolled idiom-peers preceding this commit (WatchEventClass at
// `94f8a8b`, ShikumiErrorKind at `4b53792`, DiffLineKind at `74ee853`).
// See `closed_axis_label_string_surface!` in `crate::macros` for the
// contract; behavior is byte-identical to the hand-rolled impls the
// macro replaces — the verbatim-label `Parse` error body, the case-
// insensitive `from_canonical_str` lowering, the `collect_str`-based
// serde emission, and the visitor's `expecting` message all match the
// prior surface pointwise. Pinned by
// `tests::config_source_kind_display_matches_as_str`,
// `tests::config_source_kind_from_str_*`, and
// `tests::config_source_kind_serde_yaml_*`.
closed_axis_label_string_surface! {
    type = ConfigSourceKind,
    parse_error = "unknown config source kind",
    expecting = "a canonical ConfigSourceKind lowercase label \
                 (`defaults`, `env`, `file`; case-insensitive)",
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

    /// Dense per-layer-kind tally of the chain over the
    /// [`ConfigSourceKind`] axis — the typed histogram every
    /// attestation manifest, structured-log dashboard, and
    /// chain-shape audit bucketing the (defaults × env × file) layer
    /// counts has previously re-derived inline.
    ///
    /// Equivalent to
    /// `crate::axis_histogram(self.iter().map(ConfigSource::kind))`
    /// but named at the chain-walk surface so consumers reading the
    /// recipe ([`crate::ConfigStore::sources`] /
    /// [`crate::ProviderChain::sources`]) don't reach for the cube-
    /// level generic helper. The histogram's `total()` equals
    /// `self.len()` pointwise (every chain entry projects to exactly
    /// one kind); `is_empty()` iff the chain is empty.
    ///
    /// Peer to [`crate::ConfigDiff::kind_histogram`] on the
    /// diff-line axis, [`crate::axis_histogram`] on the generic
    /// closed-axis helper surface. The two concrete consumers of
    /// [`crate::AxisHistogram`] now sit on the (chain-shape × diff-
    /// shape) pair the typescape's recipe and reload surfaces emit;
    /// future axis-tally consumers (a watcher-side reload-trigger
    /// histogram over [`crate::WatchEventClass`], a secret-resolution
    /// refusal histogram over [`crate::secret_client::SecretErrorKind`],
    /// a format-axis loader histogram over [`crate::Format`]) inherit
    /// the same lift discipline by composing `axis_histogram` over
    /// the appropriate per-cell projection.
    ///
    /// The fourth chain-level provenance query peer to
    /// [`Self::find_file`], [`Self::unique_of_kind`], and
    /// [`Self::find_env_by_prefix`]: those three answer
    /// "*which layer in the recipe …?*" point queries; this one
    /// answers the *aggregate* "*how many layers of each kind?*"
    /// over the same chain. Trait-default implementation so a
    /// chain-shape consumer reading the histogram does not need to
    /// retain the chain slice — the projection is one method call.
    fn layer_kind_histogram(&self) -> crate::AxisHistogram<ConfigSourceKind>
    where
        Self: AsRef<[ConfigSource]>,
    {
        crate::axis_histogram(self.as_ref().iter().map(ConfigSource::kind))
    }

    /// Dense per-format tally of the chain's [`ConfigSource::File`]
    /// layers over the [`crate::discovery::Format`] axis — the typed
    /// histogram every per-format dashboard, attestation manifest
    /// bucketing the (yaml × toml × lisp × nix) loader counts, and
    /// chain-shape audit has previously re-derived inline.
    ///
    /// Equivalent to
    /// `crate::axis_histogram(self.iter().filter_map(ConfigSource::file_format))`
    /// but named at the chain-walk surface so consumers reading the
    /// recipe ([`crate::ConfigStore::sources`] /
    /// [`crate::ProviderChain::sources`]) don't reach for the cube-
    /// level generic helper. Only [`ConfigSource::File`] entries with
    /// a recognized extension contribute: [`ConfigSource::Defaults`]
    /// and [`ConfigSource::Env`] entries project to [`None`] through
    /// [`ConfigSource::file_format`] (no path to read), as do `File`
    /// entries whose extension is unrecognized or absent (the
    /// conservative TOML fallback in
    /// [`crate::ProviderChain::with_file`] does not declare a format
    /// on the recipe). The histogram's `total()` therefore equals the
    /// count of `File` entries with recognized extensions, which is
    /// at most `self.layer_kind_histogram().count(ConfigSourceKind::File)`
    /// — with equality exactly when every file layer in the chain
    /// carries a recognized extension. `is_empty()` iff no chain
    /// entry projects through [`ConfigSource::file_format`] to a
    /// recognized format.
    ///
    /// Peer to [`Self::layer_kind_histogram`] on the
    /// [`ConfigSourceKind`] axis,
    /// [`crate::ConfigDiff::kind_histogram`] on the diff-line axis,
    /// and [`crate::axis_histogram`] on the generic closed-axis
    /// helper surface. With this lift the chain-shape surface carries
    /// the two natural aggregate projections side by side: one over
    /// the (defaults × env × file) layer-kind axis (every entry
    /// contributes), and one over the (yaml × toml × lisp × nix)
    /// file-format axis (file entries with recognized extensions
    /// contribute). The named histogram delivers the
    /// "format-axis loader histogram over [`crate::Format`]" the
    /// [`Self::layer_kind_histogram`] doc-string promised as the next
    /// axis-tally consumer.
    ///
    /// Trait-default implementation so a chain-shape consumer reading
    /// the histogram does not need to retain the chain slice — the
    /// projection is one method call. A future [`crate::Format`]
    /// variant lands as one new column in the histogram automatically
    /// (the typescape's [`crate::Format::ALL`] / [`crate::AxisHistogram`]
    /// discipline sizes the slot count); no per-consumer update is
    /// required.
    fn file_format_histogram(&self) -> crate::AxisHistogram<crate::discovery::Format>
    where
        Self: AsRef<[ConfigSource]>,
    {
        crate::axis_histogram(self.as_ref().iter().filter_map(ConfigSource::file_format))
    }

    /// Dense per-env-prefix-presence tally of the chain's
    /// [`ConfigSource::Env`] layers over the [`EnvMetadataTagKind`] axis
    /// — the typed histogram every attestation manifest, structured-log
    /// dashboard, and chain-shape audit bucketing the (prefixed × bare)
    /// env-layer counts has previously re-derived inline.
    ///
    /// Equivalent to
    /// `crate::axis_histogram(self.iter().filter_map(ConfigSource::env_prefix_kind))`
    /// but named at the chain-walk surface so consumers reading the
    /// recipe ([`crate::ConfigStore::sources`] /
    /// [`crate::ProviderChain::sources`]) don't reach for the cube-
    /// level generic helper. Only [`ConfigSource::Env`] entries
    /// contribute: [`ConfigSource::Defaults`] and [`ConfigSource::File`]
    /// entries project to [`None`] through
    /// [`ConfigSource::env_prefix_kind`] (no env-prefix shape to read).
    /// Unlike [`Self::file_format_histogram`] — where some `File` entries
    /// can project to [`None`] when the extension is unrecognized — every
    /// `Env` entry projects to a `Some` cell regardless of prefix value:
    /// the empty-prefix case maps to [`EnvMetadataTagKind::Bare`], every
    /// non-empty prefix maps to [`EnvMetadataTagKind::Prefixed`]. The
    /// histogram's `total()` therefore equals
    /// `self.layer_kind_histogram().count(ConfigSourceKind::Env)`
    /// pointwise — strict equality, not the inequality bound the file-
    /// format histogram carries. `is_empty()` iff the chain holds no
    /// `Env` entries.
    ///
    /// Third chain-level histogram peer of [`Self::layer_kind_histogram`]
    /// on the [`ConfigSourceKind`] layer-kind axis and
    /// [`Self::file_format_histogram`] on the file-format axis. With this
    /// lift the chain-shape surface carries the three natural aggregate
    /// projections side by side: one over the total layer-kind axis
    /// (every entry contributes), one over the file-format axis (file
    /// entries with recognized extensions contribute), and one over the
    /// env-prefix-presence axis (every env entry contributes). The named
    /// histogram delivers the "env-name sub-axis loader histogram over
    /// [`EnvMetadataTagKind`]" the chain-shape lift discipline now closes
    /// at three sites — every future axis-tally consumer composes
    /// [`crate::axis_histogram`] over the appropriate per-cell projection
    /// on the same template.
    ///
    /// Pairs structurally with the figment-side
    /// [`EnvMetadataTag::kind`] projection: for any `Env(prefix)` chain
    /// entry, the chain-side projection
    /// [`ConfigSource::env_prefix_kind`] agrees pointwise with the
    /// figment-side projection over
    /// [`ConfigSource::env_metadata_name`]/
    /// [`ConfigSource::strip_env_metadata_name`]. The two histograms
    /// (one on each surface) would read the same per-cell counts, so a
    /// future divergence in either projection surfaces at the kind axis.
    ///
    /// Trait-default implementation so a chain-shape consumer reading
    /// the histogram does not need to retain the chain slice — the
    /// projection is one method call. A future [`EnvMetadataTag`]
    /// variant lands as one new column in the histogram automatically
    /// (the typescape's [`EnvMetadataTagKind::ALL`] /
    /// [`crate::AxisHistogram`] discipline sizes the slot count); no
    /// per-consumer update is required.
    fn env_prefix_kind_histogram(&self) -> crate::AxisHistogram<EnvMetadataTagKind>
    where
        Self: AsRef<[ConfigSource]>,
    {
        crate::axis_histogram(
            self.as_ref()
                .iter()
                .filter_map(ConfigSource::env_prefix_kind),
        )
    }
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

impl EnvMetadataTag<'_> {
    /// Data-free, `'static` discriminant of this [`EnvMetadataTag`]:
    /// the kind of figment env-metadata shape
    /// ([`EnvMetadataTagKind::Prefixed`] / [`EnvMetadataTagKind::Bare`])
    /// independent of the inner borrowed prefix slice.
    ///
    /// One source of truth for the env-metadata-tag kind partition.
    /// Observers that need only the kind axis (filtering by prefix
    /// presence, hashing in a `'static` map, recording the
    /// prefixed/bare class of a failing env attribution in an
    /// attestation manifest, comparing across thread boundaries) match
    /// on this closed enum instead of pattern-matching against the
    /// borrowed tag with a lifetime parameter.
    ///
    /// Symmetric peer of [`FigmentSourceTag::kind`] and
    /// [`FigmentNameTag::kind`] on the third figment-metadata sub-axis:
    /// together the triple [`FigmentSourceKind`] /
    /// [`FigmentNameTagKind`] / [`EnvMetadataTagKind`] closes the
    /// figment-metadata kind universe (source axis × name axis ×
    /// env-name sub-axis) under one typescape primitive set, every
    /// borrowed tag projects to a `'static` discriminant on its axis.
    ///
    /// A future [`EnvMetadataTag`] variant landing (e.g. a hypothetical
    /// `Glob(&str)` shape if figment grows pattern-matched env
    /// providers) forces a corresponding [`EnvMetadataTagKind`] arm
    /// through the exhaustive match below.
    #[must_use]
    pub fn kind(self) -> EnvMetadataTagKind {
        match self {
            Self::Prefixed(_) => EnvMetadataTagKind::Prefixed,
            Self::Bare => EnvMetadataTagKind::Bare,
        }
    }
}

/// Data-free, `'static` discriminant of [`EnvMetadataTag`]: the kind of
/// figment env-metadata shape independent of the inner borrowed prefix
/// slice.
///
/// Closed two-way partition over the [`EnvMetadataTag`] variant space,
/// returned by [`EnvMetadataTag::kind`]. The enum exists so consumers
/// that need only the kind axis (filtering by prefix presence, hashing
/// in a `'static` map, recording the prefixed/bare class of a failing
/// env attribution in an attestation manifest, comparing across thread
/// boundaries) match on one closed enum instead of pattern-matching
/// against the borrowed tag with a lifetime parameter.
///
/// Symmetric peer of [`FigmentSourceKind`] on the figment-Source axis
/// and [`FigmentNameTagKind`] on the figment-Name axis: same typescape
/// discipline (closed, allocation-free,
/// `Copy + Eq + Hash + #[non_exhaustive]`, exhaustive forward map),
/// applied to figment's env-metadata sub-axis. Before this lift, the
/// figment-metadata kind universe carried typed `'static` kinds on the
/// outer `Metadata::source` and `Metadata::name` axes but the inner
/// env-name sub-axis (the [`FigmentNameTag::Env`] variant's borrowed
/// payload) had only the borrowed tag with no `'static` discriminant;
/// observers needing the cross-thread, cross-axis prefixed/bare
/// classification had to either retain the borrowed tag (lifetime
/// contamination) or re-derive the partition through inlined
/// `matches!(tag, EnvMetadataTag::Prefixed(_))` predicates at every
/// observation site.
///
/// `'static` and allocation-free — no lifetime parameter, unlike
/// [`EnvMetadataTag`]. The kind survives any borrow on the originating
/// `figment::Metadata::name` and can therefore cross thread boundaries,
/// serialize, and live in long-lived structures (the way
/// [`ConfigSourceKind`] does on the captured cross-thread observable
/// form of [`crate::ReloadFailure`], and [`FigmentSourceKind`] /
/// [`FigmentNameTagKind`] do on the outer figment-metadata axes).
///
/// Adding a future [`EnvMetadataTag`] variant (e.g. a hypothetical
/// `Glob(&str)` shape if figment grows pattern-matched env providers)
/// means adding one [`EnvMetadataTagKind`] variant in lockstep — the
/// exhaustive [`EnvMetadataTag::kind`] match forces the assignment at
/// compile time.
/// `Ord` / `PartialOrd` are declaration-order lex over
/// [`Self::ALL`] (`Prefixed < Bare`): a `BTreeMap<EnvMetadataTagKind, T>`
/// keyed on the env-name sub-axis kind (per-kind attribution
/// histograms, per-kind failure-rate dashboards, attestation manifests
/// recording the env-name sub-axis kind cardinality mix of a recorded
/// chain) emits rows in that order deterministically without a
/// hand-rolled comparator at the renderer. Idiom-peer of the same
/// derive on [`FigmentSourceKind`] (commit `5df265c`) and
/// [`FigmentNameTagKind`] (commit `64a47e7`) lifted onto the env-name
/// sub-axis sibling closed-enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EnvMetadataTagKind {
    /// Maps to [`EnvMetadataTag::Prefixed`] regardless of inner
    /// borrowed prefix slice. Reached from a
    /// `figment::Metadata::name` of shape
    /// `` `PREFIX` environment variable(s) `` emitted by
    /// [`figment::providers::Env::prefixed`].
    Prefixed,
    /// Maps to [`EnvMetadataTag::Bare`]. Reached from a
    /// `figment::Metadata::name` of shape `"environment variable(s)"`
    /// emitted by [`figment::providers::Env::raw`].
    Bare,
}

impl EnvMetadataTagKind {
    /// Every [`EnvMetadataTagKind`] variant, in declaration order
    /// ([`Self::Prefixed`], [`Self::Bare`]).
    ///
    /// The closed list of env-metadata-tag shape classes shikumi
    /// recognizes. Iterate to enumerate the env-name sub-axis kind
    /// space without listing variants by hand at every consumer site —
    /// dashboards initializing per-kind counters (weighting `Bare`
    /// attributions visibly more weakly than `Prefixed` ones since the
    /// bare shape carries no scoping information), attestation
    /// manifests recording the env-name sub-axis kind histogram of
    /// failing attributions, structured-diagnostics legends rendering
    /// different prose per class, or partition-coverage tests asserting
    /// disjointness across the classification.
    ///
    /// One source of truth for the kind enumeration on the
    /// [`EnvMetadataTagKind`] axis: peer to [`FigmentSourceKind::ALL`]
    /// on the figment-Source axis, [`FigmentNameTagKind::ALL`] on the
    /// figment-Name axis, and the other closed-axis primitives' `ALL`
    /// constants — the same typescape discipline (closed `'static`
    /// slice, in declaration order) applied to figment's env-name
    /// sub-axis.
    ///
    /// Adding a new variant to [`Self`] (e.g. a future `Glob` kind in
    /// lockstep with a hypothetical `EnvMetadataTag::Glob` if figment
    /// grows pattern-matched env providers) means extending this slice
    /// in lockstep with the variant itself. The compiler enforces
    /// nothing here directly, so the
    /// `env_metadata_tag_kind_all_covers_every_constructible_tag` test
    /// pins the contract by asserting that every kind produced by
    /// [`EnvMetadataTag::kind`] over the canonical sample table
    /// appears in [`Self::ALL`], and the
    /// `env_metadata_tag_kind_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant).
    pub const ALL: &'static [Self] = &[Self::Prefixed, Self::Bare];

    /// Returns `true` for [`Self::Prefixed`]; equivalent to
    /// `self == EnvMetadataTagKind::Prefixed`. Convenience predicate
    /// matching the [`FigmentNameTagKind::is_format`] /
    /// [`FigmentNameTagKind::is_env`] sibling pattern on the
    /// figment-Name axis.
    #[must_use]
    pub fn is_prefixed(self) -> bool {
        matches!(self, Self::Prefixed)
    }

    /// Returns `true` for [`Self::Bare`].
    #[must_use]
    pub fn is_bare(self) -> bool {
        matches!(self, Self::Bare)
    }

    /// Canonical operator-facing lowercase name of the env-metadata
    /// kind — `"prefixed"` for [`Self::Prefixed`], `"bare"` for
    /// [`Self::Bare`].
    ///
    /// The single source of truth for the env-name sub-axis kind label
    /// strings on the [`EnvMetadataTagKind`] axis. Inherent mirror of
    /// the [`crate::ClosedAxisLabel`] trait method; the trait impl
    /// delegates here so the canonical names live at one site instead
    /// of being re-stated at every operator-facing surface (a future
    /// structured-log field naming the env-tag kind of a failing
    /// attribution, a CLI flag filtering env attributions by
    /// prefixed/bare class, an attestation manifest recording the
    /// env-name sub-axis kind histogram of loaded values). The
    /// strings match the variant identifiers in ASCII-lowercase form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prefixed => "prefixed",
            Self::Bare => "bare",
        }
    }
}

impl crate::ClosedAxis for EnvMetadataTagKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for EnvMetadataTagKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl fmt::Display for EnvMetadataTagKind {
    /// Write the canonical operator-facing lowercase label
    /// [`Self::as_str`] returns (`"prefixed"` / `"bare"`) — the same
    /// scalar [`<Self as serde::Serialize>::serialize`] emits and the
    /// same scalar [`<Self as std::str::FromStr>::from_str`] accepts.
    /// Idiom-peer of the `Display` impl on [`FigmentSourceKind`]
    /// (commit `5df265c`) and [`FigmentNameTagKind`]
    /// (commit `64a47e7`) lifted onto the env-name sub-axis sibling
    /// closed-enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EnvMetadataTagKind {
    type Err = crate::ShikumiError;

    /// Parse the canonical operator-facing lowercase label
    /// (`"prefixed"` / `"bare"`) produced by [`Self::as_str`];
    /// case-insensitive over ASCII via the trait-default
    /// [`<Self as crate::ClosedAxisLabel>::from_canonical_str`] parse.
    /// On unrecognized input, returns [`crate::ShikumiError::Parse`]
    /// with the offending label embedded verbatim — matching the
    /// verbatim-substring rejection discipline already established by
    /// [`<FigmentNameTagKind as FromStr>::from_str`] (commit `64a47e7`),
    /// [`<FigmentSourceKind as FromStr>::from_str`] (commit `5df265c`),
    /// [`<ConfigSourceKind as FromStr>::from_str`] (commit `e0b96d1`),
    /// [`<crate::FormatProvenance as FromStr>::from_str`]
    /// (commit `2c7654c`), and
    /// [`crate::ParseFormatCoordinatesError`] (commit `06a2f42`) so
    /// the same localization story (the operator sees the offending
    /// substring in the rendered diagnostic) carries to the env-name
    /// sub-axis kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s).ok_or_else(|| {
            crate::ShikumiError::Parse(format!("unknown env metadata tag kind: {s}"))
        })
    }
}

impl serde::Serialize for EnvMetadataTagKind {
    /// Serialize the env-name sub-axis kind as the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns — the
    /// same scalar the [`fmt::Display`] impl writes. Routes through
    /// [`serde::Serializer::collect_str`] so the serialized
    /// representation is exactly `format!("{self}")` with no
    /// intermediate allocation.
    ///
    /// Closes the canonical (`Serialize`, `Deserialize`) serde
    /// idiom-peer of the (`Display`, [`std::str::FromStr`]) stdlib
    /// pair on the env-name sub-axis kind primitive. A kind emitted
    /// into a YAML attestation manifest field, a JSON observability
    /// payload, or any consumer struct holding an
    /// [`EnvMetadataTagKind`] field under
    /// `#[derive(Serialize, Deserialize)]` round-trips through the
    /// canonical label without a consumer-side rename helper.
    ///
    /// **Round-trip law** — for every `k: EnvMetadataTagKind`,
    /// `serde_yaml::from_str::<EnvMetadataTagKind>(&serde_yaml::to_string(&k)?)? == k`
    /// and the same on `serde_json`. Pinned by
    /// [`tests::env_metadata_tag_kind_serde_yaml_round_trips_over_every_variant`]
    /// and
    /// [`tests::env_metadata_tag_kind_serde_json_round_trips_over_every_variant`].
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for EnvMetadataTagKind {
    /// Deserialize the env-name sub-axis kind from the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns via
    /// [`serde::Deserializer::deserialize_str`] with a visitor whose
    /// `visit_str` lowers to [`<Self as FromStr>::from_str`] and
    /// routes any [`crate::ShikumiError`] through
    /// [`serde::de::Error::custom`].
    ///
    /// **Case insensitivity inherits from [`FromStr`]** — the
    /// [`crate::ClosedAxisLabel::from_canonical_str`] trait default
    /// uses [`str::eq_ignore_ascii_case`] over [`Self::ALL`], so
    /// uppercase or mixed-case scalars (e.g. `Prefixed`, `BARE`) parse
    /// pointwise. Pinned by
    /// [`tests::env_metadata_tag_kind_serde_yaml_is_case_insensitive`].
    ///
    /// **Unknown-kind rejection carries the offending label verbatim**
    /// — a manifest field carrying an unrecognized kind surfaces at
    /// the serde error site with the offending substring verbatim in
    /// the rendered message, lifted through
    /// [`crate::ShikumiError::Parse`]'s `Display` impl. Pinned by
    /// [`tests::env_metadata_tag_kind_serde_yaml_unknown_kind_error_carries_label_verbatim`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvMetadataTagKindVisitor;

        impl serde::de::Visitor<'_> for EnvMetadataTagKindVisitor {
            type Value = EnvMetadataTagKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a canonical EnvMetadataTagKind lowercase label \
                     (`prefixed`, `bare`; case-insensitive)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<EnvMetadataTagKind, E> {
                v.parse::<EnvMetadataTagKind>().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(EnvMetadataTagKindVisitor)
    }
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

    /// Data-free, `'static` discriminant of this [`FigmentNameTag`]:
    /// the kind of `figment::Metadata::name` shape
    /// ([`FigmentNameTagKind::Format`] / [`FigmentNameTagKind::Env`])
    /// independent of the inner borrowed [`crate::FormatMetadataTag`]
    /// envelope or [`EnvMetadataTag`] prefix.
    ///
    /// One source of truth for the figment-name-axis kind partition.
    /// Observers that need only the kind axis (filtering by name-tag
    /// class, hashing in a `'static` map, recording per-failure
    /// name-class in an attestation manifest, comparing across thread
    /// boundaries) match on this closed enum instead of pattern-matching
    /// against [`FigmentNameTag`] with a borrowed lifetime, or chaining
    /// [`Self::as_format`] / [`Self::as_env`] together. The kind is
    /// `'static`, so it can cross threads, serialize, and persist
    /// across observation boundaries the borrowed tag cannot.
    ///
    /// Symmetric peer of [`FigmentSourceTag::kind`] on the figment-Source
    /// axis: same typescape discipline (closed, allocation-free,
    /// `Copy + Eq + Hash + #[non_exhaustive]`, exhaustive forward map),
    /// applied to figment's `Metadata::name` axis. The pair
    /// ([`FigmentSourceKind`] on the source axis, [`FigmentNameTagKind`]
    /// on the name axis) closes the figment-metadata kind universe under
    /// one typescape primitive set: every `figment::Metadata` field's
    /// borrowed tag projects to a `'static` discriminant on its axis.
    ///
    /// Pairs with [`Self::attribution_axis`]: the projection is constant
    /// ([`crate::AttributionAxis::MetadataName`] for every variant) since
    /// [`FigmentNameTag`] *is* the typed reading of
    /// `figment::Metadata::name`. That structural law mirrors the
    /// `attribution_axis` constant on [`FigmentSourceTag`] (always
    /// [`crate::AttributionAxis::MetadataSource`]).
    /// A future variant landing on [`FigmentNameTag`] (e.g. a
    /// hypothetical `"http://… config endpoint"` name shape) forces a
    /// [`FigmentNameTagKind`] arm in lockstep at compile time, and the
    /// constant axis projection extends without per-site updates.
    #[must_use]
    pub fn kind(self) -> FigmentNameTagKind {
        match self {
            Self::Format(_) => FigmentNameTagKind::Format,
            Self::Env(_) => FigmentNameTagKind::Env,
        }
    }

    /// [`crate::AttributionAxis`] of this tag — constant
    /// [`crate::AttributionAxis::MetadataName`] for every variant, since
    /// [`FigmentNameTag`] *is* the typed reading of
    /// `figment::Metadata::name`.
    ///
    /// One source of truth for the structural law that every
    /// figment-name-axis attribution dispatches off `metadata.name`,
    /// regardless of which variant fires. Mirrors
    /// [`FigmentSourceTag::attribution_axis`] (constant
    /// [`crate::AttributionAxis::MetadataSource`]) on the source axis:
    /// each typed reading of a `figment::Metadata` field maps to its
    /// originating axis as a constant. The pair
    /// (name-side: [`Self::attribution_axis`], source-side:
    /// [`FigmentSourceTag::attribution_axis`], resolver-side:
    /// [`crate::AttributionRule::metadata_axis`]) cross-checks the axis
    /// across the three surfaces; consumers see the same axis label
    /// without re-deriving the (typed-source × name-string) partition.
    #[must_use]
    pub fn attribution_axis(self) -> crate::AttributionAxis {
        let _ = self.kind();
        crate::AttributionAxis::MetadataName
    }
}

/// Data-free, `'static` discriminant of [`FigmentNameTag`]: the kind of
/// `figment::Metadata::name` shape independent of the inner borrowed
/// [`crate::FormatMetadataTag`] envelope or [`EnvMetadataTag`] prefix.
///
/// Closed two-way partition over the [`FigmentNameTag`] variant space,
/// returned by [`FigmentNameTag::kind`]. The enum exists so consumers
/// that need only the kind axis (filtering by name-tag class, hashing
/// in a `'static` map, recording per-failure name-class in an
/// attestation manifest, comparing across thread boundaries) match on
/// one closed enum instead of pattern-matching against the borrowed
/// tag or chaining [`FigmentNameTag::as_format`] /
/// [`FigmentNameTag::as_env`] together.
///
/// Symmetric peer of [`FigmentSourceKind`] on the figment-Source axis:
/// same typescape discipline (closed, allocation-free,
/// `Copy + Eq + Hash + #[non_exhaustive]`, exhaustive forward map),
/// applied to figment's `Metadata::name` axis. Before this lift, the
/// figment-metadata kind universe was asymmetric — the
/// `Metadata::source` axis had a typed `'static` kind ([`FigmentSourceKind`])
/// but the `Metadata::name` axis had only the borrowed tag
/// ([`FigmentNameTag`]) with no `'static` discriminant; observers
/// needing the cross-thread, cross-axis kind classification on the
/// name side had to either retain the borrowed tag (lifetime
/// contamination) or re-derive the partition through
/// [`FigmentNameTag::as_format`] / [`FigmentNameTag::as_env`]
/// inlined at every observation site.
///
/// `'static` and allocation-free — no lifetime parameter, unlike
/// [`FigmentNameTag`]. The kind survives any borrow on the originating
/// `figment::Metadata::name` and can therefore cross thread boundaries,
/// serialize, and live in long-lived structures (the way
/// [`ConfigSourceKind`] does on the captured cross-thread observable
/// form of [`crate::ReloadFailure`], and [`FigmentSourceKind`] does on
/// the figment-Source side).
///
/// Adding a future [`FigmentNameTag`] variant (e.g. a hypothetical
/// `"http://… config endpoint"` shape if figment's name-axis grows one)
/// means adding one [`FigmentNameTagKind`] variant in lockstep — the
/// exhaustive [`FigmentNameTag::kind`] match forces the assignment at
/// compile time.
///
/// `Ord` and `PartialOrd` are derived as declaration-order lex over
/// [`Self::ALL`] (`Format < Env`): a `BTreeMap<FigmentNameTagKind, T>`
/// keyed on the figment-Name-axis kind (per-kind attribution
/// histograms, per-kind failure-rate dashboards, attestation manifests
/// recording the figment-Name kind cardinality mix of a recorded
/// chain) emits rows in that order deterministically without a
/// hand-rolled comparator at the renderer. Idiom-peer of the same
/// derive on [`FigmentSourceKind`] (commit `5df265c`) lifted onto the
/// figment-Name-axis sibling closed-enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FigmentNameTagKind {
    /// Maps to [`FigmentNameTag::Format`] regardless of inner
    /// [`crate::FormatMetadataTag`] envelope. Reached from a
    /// `figment::Metadata::name` of shape `"<format>: <path>"` emitted
    /// by a shikumi-built provider ([`crate::LispProvider`],
    /// [`crate::NixProvider`]).
    Format,
    /// Maps to [`FigmentNameTag::Env`] regardless of inner
    /// [`EnvMetadataTag`] prefix. Reached from a
    /// `figment::Metadata::name` of shape
    /// `` `PREFIX` environment variable(s) `` or
    /// `"environment variable(s)"` emitted by `figment::providers::Env`.
    Env,
}

impl FigmentNameTagKind {
    /// Every [`FigmentNameTagKind`] variant, in declaration order
    /// ([`Self::Format`], [`Self::Env`]).
    ///
    /// The closed list of `figment::Metadata::name` shape classes shikumi
    /// recognizes. Iterate to enumerate the figment-name-axis kind space
    /// without listing variants by hand at every consumer site — e.g.
    /// dashboards initializing per-kind counters (weighting `Env`
    /// attributions visibly differently from `Format` ones since they
    /// originate from distinct provider classes), attestation manifests
    /// recording the figment-name-axis kind space's cardinality,
    /// structured-diagnostics legends rendering different prose per
    /// class, or partition-coverage tests asserting disjointness across
    /// the figment-side classification on the name axis.
    ///
    /// One source of truth for the kind enumeration on the
    /// [`FigmentNameTagKind`] axis: peer to [`FigmentSourceKind::ALL`]
    /// on the figment-Source axis, [`ConfigSourceKind::ALL`] on the
    /// shikumi-side layer-kind axis, [`crate::AttributionAxis::ALL`] on
    /// the metadata axis, and the other closed-axis primitives' `ALL`
    /// constants — the same typescape discipline (closed `'static` slice,
    /// in declaration order) applied to figment's `Metadata::name` axis.
    ///
    /// Adding a new variant to [`Self`] (e.g. a future `Url` kind in
    /// lockstep with a hypothetical `FigmentNameTag::Url` if figment
    /// grows one) means extending this slice in lockstep with the
    /// variant itself. The compiler enforces nothing here directly,
    /// so the `figment_name_tag_kind_all_covers_every_constructible_tag`
    /// test pins the contract by asserting that every kind produced by
    /// [`FigmentNameTag::kind`] over the canonical sample table appears
    /// in [`Self::ALL`], and the `figment_name_tag_kind_all_has_no_duplicates`
    /// test pins that the constant is a set (no double-listed variant).
    pub const ALL: &'static [Self] = &[Self::Format, Self::Env];

    /// Returns `true` for [`Self::Format`]; equivalent to
    /// `self == FigmentNameTagKind::Format`. Convenience predicate
    /// matching the [`FigmentSourceKind::is_file`] /
    /// [`FigmentSourceKind::is_code`] / [`FigmentSourceKind::is_custom`]
    /// sibling pattern on the figment-Source axis.
    #[must_use]
    pub fn is_format(self) -> bool {
        matches!(self, Self::Format)
    }

    /// Returns `true` for [`Self::Env`].
    #[must_use]
    pub fn is_env(self) -> bool {
        matches!(self, Self::Env)
    }

    /// Canonical operator-facing lowercase name of the figment-name
    /// kind — `"format"` for [`Self::Format`], `"env"` for [`Self::Env`].
    ///
    /// The single source of truth for the figment-name-axis kind label
    /// strings on the [`FigmentNameTagKind`] axis. Inherent mirror of
    /// the [`crate::ClosedAxisLabel`] trait method; the trait impl
    /// delegates here so the canonical names live at one site instead
    /// of being re-stated at every operator-facing surface (a future
    /// structured-log field naming the figment-name-axis kind of a
    /// failing attribution, a CLI flag filtering attributions by
    /// figment-name-axis kind, an attestation manifest recording the
    /// figment-name-axis kind histogram of loaded values). The
    /// strings match the variant identifiers in ASCII-lowercase form.
    ///
    /// The `"env"` label intentionally coincides with
    /// [`ConfigSourceKind::Env`]'s label by typescape design: the two
    /// axes meet at the shikumi-env-layer ↔ figment-Env-name
    /// resolution boundary. The trait-uniform distinctness law
    /// (`closed_axis_label_as_str_distinct_for_every_implementor`)
    /// pins distinctness within an axis only; cross-axis label
    /// coincidence is structural, not a discipline violation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Env => "env",
        }
    }
}

impl crate::ClosedAxis for FigmentNameTagKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for FigmentNameTagKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl fmt::Display for FigmentNameTagKind {
    /// Write the canonical operator-facing lowercase label
    /// [`Self::as_str`] returns (`"format"` / `"env"`) — the same
    /// scalar [`<Self as serde::Serialize>::serialize`] emits and the
    /// same scalar [`<Self as std::str::FromStr>::from_str`] accepts.
    /// Idiom-peer of the `Display` impl on [`FigmentSourceKind`]
    /// (commit `5df265c`) lifted onto the figment-Name-axis sibling
    /// closed-enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FigmentNameTagKind {
    type Err = crate::ShikumiError;

    /// Parse the canonical operator-facing lowercase label
    /// (`"format"` / `"env"`) produced by [`Self::as_str`];
    /// case-insensitive over ASCII via the trait-default
    /// [`<Self as crate::ClosedAxisLabel>::from_canonical_str`] parse.
    /// On unrecognized input, returns [`crate::ShikumiError::Parse`]
    /// with the offending label embedded verbatim — matching the
    /// verbatim-substring rejection discipline already established by
    /// [`<FigmentSourceKind as FromStr>::from_str`] (commit `5df265c`),
    /// [`<ConfigSourceKind as FromStr>::from_str`] (commit `e0b96d1`),
    /// [`<crate::FormatProvenance as FromStr>::from_str`]
    /// (commit `2c7654c`), and
    /// [`crate::ParseFormatCoordinatesError`] (commit `06a2f42`) so
    /// the same localization story (the operator sees the offending
    /// substring in the rendered diagnostic) carries to the
    /// figment-Name-axis kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s).ok_or_else(|| {
            crate::ShikumiError::Parse(format!("unknown figment name tag kind: {s}"))
        })
    }
}

impl serde::Serialize for FigmentNameTagKind {
    /// Serialize the figment-Name-axis kind as the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns — the
    /// same scalar the [`fmt::Display`] impl writes. Routes through
    /// [`serde::Serializer::collect_str`] so the serialized
    /// representation is exactly `format!("{self}")` with no
    /// intermediate allocation.
    ///
    /// Closes the canonical (`Serialize`, `Deserialize`) serde
    /// idiom-peer of the (`Display`, [`std::str::FromStr`]) stdlib
    /// pair on the figment-Name-axis kind primitive. A kind emitted
    /// into a YAML attestation manifest field, a JSON observability
    /// payload, or any consumer struct holding a
    /// [`FigmentNameTagKind`] field under
    /// `#[derive(Serialize, Deserialize)]` round-trips through the
    /// canonical label without a consumer-side rename helper.
    ///
    /// **Round-trip law** — for every `k: FigmentNameTagKind`,
    /// `serde_yaml::from_str::<FigmentNameTagKind>(&serde_yaml::to_string(&k)?)? == k`
    /// and the same on `serde_json`. Pinned by
    /// [`tests::figment_name_tag_kind_serde_yaml_round_trips_over_every_variant`]
    /// and
    /// [`tests::figment_name_tag_kind_serde_json_round_trips_over_every_variant`].
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for FigmentNameTagKind {
    /// Deserialize the figment-Name-axis kind from the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns via
    /// [`serde::Deserializer::deserialize_str`] with a visitor whose
    /// `visit_str` lowers to [`<Self as FromStr>::from_str`] and
    /// routes any [`crate::ShikumiError`] through
    /// [`serde::de::Error::custom`].
    ///
    /// **Case insensitivity inherits from [`FromStr`]** — the
    /// [`crate::ClosedAxisLabel::from_canonical_str`] trait default
    /// uses [`str::eq_ignore_ascii_case`] over [`Self::ALL`], so
    /// uppercase or mixed-case scalars (e.g. `Format`, `ENV`) parse
    /// pointwise. Pinned by
    /// [`tests::figment_name_tag_kind_serde_yaml_is_case_insensitive`].
    ///
    /// **Unknown-kind rejection carries the offending label verbatim**
    /// — a manifest field carrying an unrecognized kind surfaces at
    /// the serde error site with the offending substring verbatim in
    /// the rendered message, lifted through
    /// [`crate::ShikumiError::Parse`]'s `Display` impl. Pinned by
    /// [`tests::figment_name_tag_kind_serde_yaml_unknown_kind_error_carries_label_verbatim`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FigmentNameTagKindVisitor;

        impl serde::de::Visitor<'_> for FigmentNameTagKindVisitor {
            type Value = FigmentNameTagKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a canonical FigmentNameTagKind lowercase label \
                     (`format`, `env`; case-insensitive)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<FigmentNameTagKind, E> {
                v.parse::<FigmentNameTagKind>().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FigmentNameTagKindVisitor)
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
///
/// **Total order** — the derived `Ord` / `PartialOrd` impls lex over
/// the variant declaration order in [`Self::ALL`]
/// (`File < Code < Custom`), matching the trait-uniform discipline
/// already landed on the sibling closed-enum axis primitives
/// [`ConfigSourceKind`] (commit `e0b96d1`),
/// [`crate::Format`] (commit `b56b121`),
/// [`crate::FormatProvenance`] (commit `2c7654c`), and
/// [`crate::FormatCoordinates`] (commit `06a2f42`). A
/// `BTreeMap<FigmentSourceKind, T>` keyed on the figment-Source axis
/// kind (per-kind attribution counters, per-kind failure-rate
/// dashboards, attestation manifests recording the figment-Source
/// kind cardinality mix) emits rows in declaration order
/// deterministically. Pinned by
/// [`tests::figment_source_kind_ord_matches_all_declaration_order`]
/// and
/// [`tests::figment_source_kind_btreemap_emits_in_declaration_order`].
///
/// **Canonical wire form** — the [`fmt::Display`], [`FromStr`],
/// [`serde::Serialize`], and [`serde::Deserialize`] impls route
/// through the canonical lowercase label [`Self::as_str`] returns
/// (`"file"`, `"code"`, `"custom"`). A consumer struct holding a
/// [`FigmentSourceKind`] field under
/// `#[derive(Serialize, Deserialize)]` round-trips through the
/// canonical label without a consumer-side rename helper; an
/// operator typing the canonical name into an env var or CLI flag
/// parses pointwise through [`FromStr`] case-insensitively over
/// ASCII. Idiom-peer of the canonical surface already lifted onto
/// [`ConfigSourceKind`] (commit `e0b96d1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
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

impl fmt::Display for FigmentSourceKind {
    /// Write the canonical operator-facing lowercase label
    /// [`Self::as_str`] returns (`"file"` / `"code"` / `"custom"`) —
    /// the same scalar [`<Self as serde::Serialize>::serialize`] emits
    /// and the same scalar [`<Self as std::str::FromStr>::from_str`]
    /// accepts. Idiom-peer of the `Display` impl on
    /// [`ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
    /// figment-Source-axis sibling closed-enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FigmentSourceKind {
    type Err = crate::ShikumiError;

    /// Parse the canonical operator-facing lowercase label
    /// (`"file"` / `"code"` / `"custom"`) produced by [`Self::as_str`];
    /// case-insensitive over ASCII via the trait-default
    /// [`<Self as crate::ClosedAxisLabel>::from_canonical_str`] parse.
    /// On unrecognized input, returns [`crate::ShikumiError::Parse`]
    /// with the offending label embedded verbatim — matching the
    /// verbatim-substring rejection discipline already established by
    /// [`<ConfigSourceKind as FromStr>::from_str`] (commit `e0b96d1`),
    /// [`<crate::FormatProvenance as FromStr>::from_str`]
    /// (commit `2c7654c`), and
    /// [`crate::ParseFormatCoordinatesError`] (commit `06a2f42`) so
    /// the same localization story (the operator sees the offending
    /// substring in the rendered diagnostic) carries to the
    /// figment-Source-axis kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s)
            .ok_or_else(|| crate::ShikumiError::Parse(format!("unknown figment source kind: {s}")))
    }
}

impl serde::Serialize for FigmentSourceKind {
    /// Serialize the figment-Source-axis kind as the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns —
    /// the same scalar the [`fmt::Display`] impl writes. Routes
    /// through [`serde::Serializer::collect_str`] so the serialized
    /// representation is exactly `format!("{self}")` with no
    /// intermediate allocation.
    ///
    /// Closes the canonical (`Serialize`, `Deserialize`) serde
    /// idiom-peer of the (`Display`, [`std::str::FromStr`]) stdlib
    /// pair on the figment-Source-axis kind primitive. A kind emitted
    /// into a YAML attestation manifest field, a JSON observability
    /// payload, or any consumer struct holding a
    /// [`FigmentSourceKind`] field under
    /// `#[derive(Serialize, Deserialize)]` round-trips through the
    /// canonical label without a consumer-side rename helper.
    ///
    /// **Round-trip law** — for every `k: FigmentSourceKind`,
    /// `serde_yaml::from_str::<FigmentSourceKind>(&serde_yaml::to_string(&k)?)? == k`
    /// and the same on `serde_json`. Pinned by
    /// [`tests::figment_source_kind_serde_yaml_round_trips_over_every_variant`]
    /// and
    /// [`tests::figment_source_kind_serde_json_round_trips_over_every_variant`].
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for FigmentSourceKind {
    /// Deserialize the figment-Source-axis kind from the canonical
    /// operator-facing lowercase label [`Self::as_str`] returns via
    /// [`serde::Deserializer::deserialize_str`] with a visitor whose
    /// `visit_str` lowers to [`<Self as FromStr>::from_str`] and
    /// routes any [`crate::ShikumiError`] through
    /// [`serde::de::Error::custom`].
    ///
    /// **Case insensitivity inherits from [`FromStr`]** — the
    /// [`crate::ClosedAxisLabel::from_canonical_str`] trait default
    /// uses [`str::eq_ignore_ascii_case`] over [`Self::ALL`], so
    /// uppercase or mixed-case scalars (e.g. `File`, `CODE`,
    /// `Custom`) parse pointwise. Pinned by
    /// [`tests::figment_source_kind_serde_yaml_is_case_insensitive`].
    ///
    /// **Unknown-kind rejection carries the offending label verbatim**
    /// — a manifest field carrying an unrecognized kind surfaces at
    /// the serde error site with the offending substring verbatim in
    /// the rendered message, lifted through
    /// [`crate::ShikumiError::Parse`]'s `Display` impl. Pinned by
    /// [`tests::figment_source_kind_serde_yaml_unknown_kind_error_carries_label_verbatim`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FigmentSourceKindVisitor;

        impl serde::de::Visitor<'_> for FigmentSourceKindVisitor {
            type Value = FigmentSourceKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a canonical FigmentSourceKind lowercase label \
                     (`file`, `code`, `custom`; case-insensitive)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<FigmentSourceKind, E> {
                v.parse::<FigmentSourceKind>().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FigmentSourceKindVisitor)
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

    // ---- ConfigSourceChain::layer_kind_histogram ----

    #[test]
    fn layer_kind_histogram_counts_each_kind_pointwise() {
        // Concrete pin on the (chain → ConfigSourceKind tally)
        // projection. `sample_chain()` is two File layers + one Env
        // layer (no Defaults), so the histogram must read 2 File,
        // 1 Env, 0 Defaults.
        let chain = sample_chain();
        let hist = chain.as_slice().layer_kind_histogram();
        assert_eq!(hist.count(ConfigSourceKind::File), 2);
        assert_eq!(hist.count(ConfigSourceKind::Env), 1);
        assert_eq!(hist.count(ConfigSourceKind::Defaults), 0);
        // total() equals chain length pointwise (every entry projects
        // to exactly one kind).
        assert_eq!(hist.total(), chain.len());
    }

    #[test]
    fn layer_kind_histogram_empty_chain_is_zero_on_every_cell() {
        // Empty-chain law: every cell reads zero, total is zero,
        // is_empty() is true. Pins the monoid identity at the
        // chain-shape boundary.
        let chain: [ConfigSource; 0] = [];
        let hist = chain.layer_kind_histogram();
        for kind in ConfigSourceKind::ALL.iter().copied() {
            assert_eq!(
                hist.count(kind),
                0,
                "empty chain must read zero on every kind cell ({kind:?})",
            );
        }
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn layer_kind_histogram_agrees_with_open_coded_per_kind_count() {
        // The lift collapses the per-cell `iter().filter(|s| s.kind()
        // == k).count()` loop the typescape doc-strings promised — pin
        // pointwise equivalence over the typed kind axis across chains
        // with 0, 1, 2, and 3 entries of mixed kinds, so a future
        // regression in either side surfaces here.
        let chains = [
            Vec::new(),
            vec![ConfigSource::Defaults],
            sample_chain(),
            vec![
                ConfigSource::Defaults,
                ConfigSource::Defaults,
                ConfigSource::Env("X_".to_owned()),
            ],
        ];
        for chain in &chains {
            let hist = chain.as_slice().layer_kind_histogram();
            for kind in ConfigSourceKind::ALL.iter().copied() {
                let manual = chain.iter().filter(|s| s.kind() == kind).count();
                assert_eq!(
                    hist.count(kind),
                    manual,
                    "layer_kind_histogram({kind:?}) must equal the open-coded \
                     filter-count over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    #[test]
    fn layer_kind_histogram_iter_yields_declaration_order() {
        // The dense per-cell iteration must yield the
        // ConfigSourceKind::ALL declaration order
        // (Defaults, Env, File) regardless of the chain's observation
        // order — observation order does not leak into the histogram's
        // value-side iteration. Mirror of
        // `kind_histogram_iter_yields_declaration_order` on the
        // diff-line axis in `tiered::tests`.
        let chain = vec![
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::Env("E_".to_owned()),
            ConfigSource::Defaults,
        ];
        let pairs: Vec<(ConfigSourceKind, usize)> =
            chain.as_slice().layer_kind_histogram().iter().collect();
        let values: Vec<ConfigSourceKind> = pairs.iter().map(|(k, _)| *k).collect();
        assert_eq!(values, ConfigSourceKind::ALL.to_vec());
    }

    #[test]
    fn layer_kind_histogram_equals_axis_histogram_over_kind_projection() {
        // Pin equivalence to the generic
        // `crate::axis_histogram(self.iter().map(ConfigSource::kind))`
        // shape the trait-default method routes through — the lift
        // must not silently re-implement the per-cell count loop on
        // a parallel surface. Pointwise equality on every kind cell.
        let chains = [
            sample_chain(),
            vec![ConfigSource::Defaults, ConfigSource::Defaults],
            vec![
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::Env("B_".to_owned()),
                ConfigSource::File(PathBuf::from("/x.toml")),
            ],
        ];
        for chain in &chains {
            let lifted = chain.as_slice().layer_kind_histogram();
            let generic = crate::axis_histogram(chain.iter().map(ConfigSource::kind));
            for kind in ConfigSourceKind::ALL.iter().copied() {
                assert_eq!(
                    lifted.count(kind),
                    generic.count(kind),
                    "layer_kind_histogram must equal axis_histogram(kind-projection) \
                     on {kind:?} over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    // ---- ConfigSourceChain::file_format_histogram ----

    #[test]
    fn file_format_histogram_counts_each_recognized_format_pointwise() {
        // Concrete pin on the (chain → Format tally) projection on the
        // file-axis sub-slice. `sample_chain()` is two `.yaml` File
        // layers + one Env layer (no Defaults), so the histogram must
        // read 2 Yaml, 0 Toml, 0 Lisp, 0 Nix. The Env layer projects
        // to None through `file_format()` and contributes to no cell.
        use crate::discovery::Format;
        let chain = sample_chain();
        let hist = chain.as_slice().file_format_histogram();
        assert_eq!(hist.count(Format::Yaml), 2);
        assert_eq!(hist.count(Format::Toml), 0);
        assert_eq!(hist.count(Format::Lisp), 0);
        assert_eq!(hist.count(Format::Nix), 0);
        // total() equals the count of File entries with recognized
        // extensions — here 2 (both `.yaml`).
        assert_eq!(hist.total(), 2);
    }

    #[test]
    fn file_format_histogram_covers_every_recognized_format() {
        // A chain with one File entry per recognized format must
        // produce a histogram with exactly one observation per Format
        // cell — total equals Format::ALL cardinality. Pins the
        // uniform-cover law on the file-format axis.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.toml")),
            ConfigSource::File(PathBuf::from("/c.lisp")),
            ConfigSource::File(PathBuf::from("/d.nix")),
        ];
        let hist = chain.as_slice().file_format_histogram();
        for format in Format::ALL.iter().copied() {
            assert_eq!(
                hist.count(format),
                1,
                "uniform-cover chain must read 1 on every Format cell ({format:?})",
            );
        }
        assert_eq!(hist.total(), Format::ALL.len());
    }

    #[test]
    fn file_format_histogram_empty_chain_is_zero_on_every_cell() {
        // Empty-chain law on the file-format axis: every cell reads
        // zero, total is zero, is_empty() is true. Pins the monoid
        // identity at the chain-shape boundary on the second
        // chain-level histogram surface.
        use crate::discovery::Format;
        let chain: [ConfigSource; 0] = [];
        let hist = chain.file_format_histogram();
        for format in Format::ALL.iter().copied() {
            assert_eq!(
                hist.count(format),
                0,
                "empty chain must read zero on every Format cell ({format:?})",
            );
        }
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn file_format_histogram_ignores_defaults_and_env_layers() {
        // Defaults and Env entries carry no path and project to None
        // through `file_format()`; they must not contribute to any
        // Format cell regardless of how many chain entries of those
        // kinds are present.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::Env(String::new()),
        ];
        let hist = chain.as_slice().file_format_histogram();
        for format in Format::ALL.iter().copied() {
            assert_eq!(
                hist.count(format),
                0,
                "Defaults/Env-only chain must read zero on every Format cell ({format:?})",
            );
        }
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn file_format_histogram_ignores_unrecognized_and_extensionless_files() {
        // File entries whose extension is unrecognized or absent yield
        // None through `file_format()` (the conservative TOML fallback
        // in `with_file` does not declare a format on the recipe);
        // they must not contribute to any Format cell. Pins the
        // `None`-discipline pointwise.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::File(PathBuf::from("/etc/cfg.unknownext")),
            ConfigSource::File(PathBuf::from("/etc/no_extension")),
            ConfigSource::File(PathBuf::from("/etc/.dotfile")),
        ];
        let hist = chain.as_slice().file_format_histogram();
        for format in Format::ALL.iter().copied() {
            assert_eq!(
                hist.count(format),
                0,
                "unrecognized-extension chain must read zero on {format:?}",
            );
        }
        assert_eq!(hist.total(), 0);
    }

    #[test]
    fn file_format_histogram_agrees_with_open_coded_per_format_count() {
        // The lift collapses the per-cell
        // `iter().filter_map(file_format).filter(|f| *f == X).count()`
        // loop the typescape doc-strings promised — pin pointwise
        // equivalence over the typed format axis across chains of
        // mixed kinds, mixed formats, and mixed recognized/unrecognized
        // extensions so a future regression in either side surfaces
        // here.
        use crate::discovery::Format;
        let chains = [
            Vec::new(),
            vec![ConfigSource::Defaults],
            sample_chain(),
            vec![
                ConfigSource::File(PathBuf::from("/a.yaml")),
                ConfigSource::File(PathBuf::from("/b.yml")),
                ConfigSource::File(PathBuf::from("/c.toml")),
                ConfigSource::File(PathBuf::from("/d.lisp")),
                ConfigSource::File(PathBuf::from("/e.unknownext")),
                ConfigSource::Env("X_".to_owned()),
            ],
        ];
        for chain in &chains {
            let hist = chain.as_slice().file_format_histogram();
            for format in Format::ALL.iter().copied() {
                let manual = chain
                    .iter()
                    .filter_map(ConfigSource::file_format)
                    .filter(|f| *f == format)
                    .count();
                assert_eq!(
                    hist.count(format),
                    manual,
                    "file_format_histogram({format:?}) must equal the open-coded \
                     filter_map+filter count over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    #[test]
    fn file_format_histogram_iter_yields_format_all_declaration_order() {
        // The dense per-cell iteration must yield the Format::ALL
        // declaration order (Yaml, Toml, Lisp, Nix) regardless of the
        // chain's observation order — observation order does not leak
        // into the histogram's value-side iteration. Peer to
        // `layer_kind_histogram_iter_yields_declaration_order` on the
        // ConfigSourceKind axis.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::File(PathBuf::from("/a.nix")),
            ConfigSource::File(PathBuf::from("/b.lisp")),
            ConfigSource::File(PathBuf::from("/c.toml")),
            ConfigSource::File(PathBuf::from("/d.yaml")),
        ];
        let pairs: Vec<(Format, usize)> = chain.as_slice().file_format_histogram().iter().collect();
        let values: Vec<Format> = pairs.iter().map(|(f, _)| *f).collect();
        assert_eq!(values, Format::ALL.to_vec());
    }

    #[test]
    fn file_format_histogram_equals_axis_histogram_over_file_format_projection() {
        // Pin equivalence to the generic
        // `crate::axis_histogram(self.iter().filter_map(ConfigSource::file_format))`
        // shape the trait-default method routes through — the lift
        // must not silently re-implement the per-cell count loop on a
        // parallel surface. Pointwise equality on every Format cell.
        use crate::discovery::Format;
        let chains = [
            sample_chain(),
            vec![
                ConfigSource::Defaults,
                ConfigSource::Defaults,
                ConfigSource::File(PathBuf::from("/x.toml")),
            ],
            vec![
                ConfigSource::File(PathBuf::from("/a.yaml")),
                ConfigSource::File(PathBuf::from("/b.lisp")),
                ConfigSource::File(PathBuf::from("/c.unknownext")),
                ConfigSource::Env("E_".to_owned()),
            ],
        ];
        for chain in &chains {
            let lifted = chain.as_slice().file_format_histogram();
            let generic = crate::axis_histogram(chain.iter().filter_map(ConfigSource::file_format));
            for format in Format::ALL.iter().copied() {
                assert_eq!(
                    lifted.count(format),
                    generic.count(format),
                    "file_format_histogram must equal \
                     axis_histogram(file_format-projection) on {format:?} \
                     over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    #[test]
    fn file_format_histogram_total_bounded_by_file_layer_count() {
        // Cross-histogram invariant: the file-format histogram's total
        // is at most the layer-kind histogram's count of File entries,
        // since `file_format()` projects only `File` layers to `Some`
        // (and even then only when the extension is recognized). The
        // strict inequality happens exactly when some `File` layer
        // carries an unrecognized or absent extension. Pins the
        // structural relationship between the two chain-level
        // histograms the trait now exposes.
        let chains: [Vec<ConfigSource>; 4] = [
            sample_chain(),
            vec![ConfigSource::Defaults, ConfigSource::Env("E_".to_owned())],
            vec![
                ConfigSource::File(PathBuf::from("/a.yaml")),
                ConfigSource::File(PathBuf::from("/b.unknownext")),
                ConfigSource::File(PathBuf::from("/c.no_extension")),
            ],
            vec![
                ConfigSource::File(PathBuf::from("/a.yaml")),
                ConfigSource::File(PathBuf::from("/b.toml")),
                ConfigSource::File(PathBuf::from("/c.lisp")),
                ConfigSource::File(PathBuf::from("/d.nix")),
            ],
        ];
        for chain in &chains {
            let file_kind_count = chain
                .as_slice()
                .layer_kind_histogram()
                .count(ConfigSourceKind::File);
            let format_total = chain.as_slice().file_format_histogram().total();
            assert!(
                format_total <= file_kind_count,
                "file_format_histogram total ({format_total}) must be at most \
                 layer_kind_histogram(File) ({file_kind_count}) over chain of length {}",
                chain.len(),
            );
        }
        // Equality case: every File layer carries a recognized
        // extension — the bound is tight on the uniform-cover chain.
        let uniform = vec![
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.toml")),
            ConfigSource::File(PathBuf::from("/c.lisp")),
            ConfigSource::File(PathBuf::from("/d.nix")),
        ];
        let file_kind_count = uniform
            .as_slice()
            .layer_kind_histogram()
            .count(ConfigSourceKind::File);
        let format_total = uniform.as_slice().file_format_histogram().total();
        assert_eq!(
            format_total, file_kind_count,
            "uniform-cover chain: file_format_histogram total must equal \
             layer_kind_histogram(File)",
        );
        // Strict-inequality case: at least one File layer carries an
        // unrecognized extension — the bound is strict.
        let mixed = vec![
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.unknownext")),
        ];
        let file_kind_count = mixed
            .as_slice()
            .layer_kind_histogram()
            .count(ConfigSourceKind::File);
        let format_total = mixed.as_slice().file_format_histogram().total();
        assert!(
            format_total < file_kind_count,
            "mixed-extension chain: file_format_histogram total ({format_total}) \
             must be strictly less than layer_kind_histogram(File) ({file_kind_count})",
        );
    }

    // ---- ConfigSource::env_prefix_kind ----

    #[test]
    fn env_prefix_kind_classifies_empty_prefix_as_bare() {
        // The empty-prefix Env layer is the chain-side projection of the
        // figment::providers::Env::raw shape — its env_prefix_kind must
        // read EnvMetadataTagKind::Bare. Pins the per-cell projection on
        // the bare side of the kind axis.
        let s = ConfigSource::Env(String::new());
        assert_eq!(s.env_prefix_kind(), Some(EnvMetadataTagKind::Bare));
    }

    #[test]
    fn env_prefix_kind_classifies_non_empty_prefix_as_prefixed() {
        // Every non-empty prefix Env layer projects to
        // EnvMetadataTagKind::Prefixed — the chain-side projection of
        // figment::providers::Env::prefixed. Across ASCII-case and
        // long-prefix shapes the kind axis only carries the
        // prefixed/bare partition; case and length do not influence it.
        for prefix in [
            "MYAPP_",
            "x_",
            "MixedCase_",
            "very_long_prefix_with_underscores_",
            "A",
        ] {
            let s = ConfigSource::Env(prefix.to_owned());
            assert_eq!(
                s.env_prefix_kind(),
                Some(EnvMetadataTagKind::Prefixed),
                "non-empty prefix {prefix:?} must classify as Prefixed",
            );
        }
    }

    #[test]
    fn env_prefix_kind_is_none_for_non_env_sources() {
        // Defaults and File layers carry no env-prefix shape at all —
        // env_prefix_kind must read None on every non-Env source.
        assert_eq!(ConfigSource::Defaults.env_prefix_kind(), None);
        assert_eq!(
            ConfigSource::File(PathBuf::from("/etc/app.yaml")).env_prefix_kind(),
            None,
        );
        assert_eq!(
            ConfigSource::File(PathBuf::from("/etc/app.unknownext")).env_prefix_kind(),
            None,
        );
    }

    #[test]
    fn env_prefix_kind_partitions_env_variants_pointwise() {
        // Exhaustive on the EnvMetadataTagKind::ALL slice: every kind
        // must be reached by at least one Env layer (Bare via empty
        // prefix, Prefixed via any non-empty prefix), and the partition
        // is disjoint on the Env-source side (no Env layer projects to
        // two cells, no kind is unreachable). Together with
        // [`env_prefix_kind_is_none_for_non_env_sources`] this closes
        // the per-cell projection law.
        let mut reached: Vec<EnvMetadataTagKind> = Vec::new();
        for layer in [
            ConfigSource::Env(String::new()),
            ConfigSource::Env("X_".to_owned()),
        ] {
            let k = layer
                .env_prefix_kind()
                .expect("every Env layer must project to Some");
            assert!(
                !reached.contains(&k),
                "env_prefix_kind must not project two Env layers to the same kind in this sample",
            );
            reached.push(k);
        }
        for kind in EnvMetadataTagKind::ALL {
            assert!(
                reached.contains(kind),
                "EnvMetadataTagKind::{kind:?} must be reachable from some Env layer",
            );
        }
    }

    #[test]
    fn env_prefix_kind_agrees_with_figment_env_metadata_tag_kind() {
        // Cross-surface commutativity: the chain-side projection
        // ConfigSource::Env(prefix).env_prefix_kind() must agree pointwise
        // with the figment-side projection that goes through
        // env_metadata_name (the canonical figment::Metadata::name shape
        // for the recorded prefix) and strip_env_metadata_name (the
        // parse), then takes EnvMetadataTag::kind. The two surfaces
        // converge on one EnvMetadataTagKind axis by construction — a
        // future divergence (a figment env shape that one surface
        // recognizes and the other does not) surfaces here.
        for prefix in ["", "APP_", "MYAPP_", "x_", "MixedCase_"] {
            let chain_side = ConfigSource::Env(prefix.to_owned())
                .env_prefix_kind()
                .expect("every Env layer projects through env_prefix_kind");
            let figment_side =
                ConfigSource::strip_env_metadata_name(&ConfigSource::env_metadata_name(prefix))
                    .map(EnvMetadataTag::kind)
                    .expect("env_metadata_name round-trips through strip_env_metadata_name");
            assert_eq!(
                chain_side, figment_side,
                "env_prefix_kind({prefix:?}) must agree with the figment-side EnvMetadataTag::kind",
            );
        }
    }

    // ---- ConfigSourceChain::env_prefix_kind_histogram ----

    #[test]
    fn env_prefix_kind_histogram_counts_each_kind_pointwise() {
        // Concrete pin on the (chain → EnvMetadataTagKind tally)
        // projection. `sample_chain()` carries one Env("APP_") layer
        // (and two File layers + zero Defaults), so the histogram must
        // read 1 Prefixed, 0 Bare. The File and Defaults entries project
        // to None through env_prefix_kind() and contribute to no cell.
        let chain = sample_chain();
        let hist = chain.as_slice().env_prefix_kind_histogram();
        assert_eq!(hist.count(EnvMetadataTagKind::Prefixed), 1);
        assert_eq!(hist.count(EnvMetadataTagKind::Bare), 0);
        // total() equals the count of Env entries — here 1.
        assert_eq!(hist.total(), 1);
    }

    #[test]
    fn env_prefix_kind_histogram_covers_every_kind() {
        // A chain with one Env layer per kind (empty-prefix → Bare,
        // non-empty → Prefixed) must produce a histogram with exactly
        // one observation per EnvMetadataTagKind cell — total equals
        // EnvMetadataTagKind::ALL cardinality. Pins the uniform-cover
        // law on the env-prefix-presence axis.
        let chain = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env("APP_".to_owned()),
        ];
        let hist = chain.as_slice().env_prefix_kind_histogram();
        for kind in EnvMetadataTagKind::ALL.iter().copied() {
            assert_eq!(
                hist.count(kind),
                1,
                "uniform-cover chain must read 1 on every EnvMetadataTagKind cell ({kind:?})",
            );
        }
        assert_eq!(hist.total(), EnvMetadataTagKind::ALL.len());
    }

    #[test]
    fn env_prefix_kind_histogram_empty_chain_is_zero_on_every_cell() {
        // Empty-chain law on the env-prefix-presence axis: every cell
        // reads zero, total is zero, is_empty() is true. Pins the
        // monoid identity at the chain-shape boundary on the third
        // chain-level histogram surface.
        let chain: [ConfigSource; 0] = [];
        let hist = chain.env_prefix_kind_histogram();
        for kind in EnvMetadataTagKind::ALL.iter().copied() {
            assert_eq!(
                hist.count(kind),
                0,
                "empty chain must read zero on every EnvMetadataTagKind cell ({kind:?})",
            );
        }
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn env_prefix_kind_histogram_ignores_defaults_and_file_layers() {
        // Defaults and File entries carry no env-prefix shape and
        // project to None through `env_prefix_kind()`; they must not
        // contribute to any EnvMetadataTagKind cell regardless of how
        // many chain entries of those kinds are present, regardless of
        // file extension recognition.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Defaults,
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
            ConfigSource::File(PathBuf::from("/etc/app.unknownext")),
        ];
        let hist = chain.as_slice().env_prefix_kind_histogram();
        for kind in EnvMetadataTagKind::ALL.iter().copied() {
            assert_eq!(
                hist.count(kind),
                0,
                "Defaults/File-only chain must read zero on every \
                 EnvMetadataTagKind cell ({kind:?})",
            );
        }
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn env_prefix_kind_histogram_agrees_with_open_coded_per_kind_count() {
        // The lift collapses the per-cell
        // `iter().filter_map(env_prefix_kind).filter(|k| *k == X).count()`
        // loop the typescape doc-strings promised — pin pointwise
        // equivalence over the typed env-prefix-presence axis across
        // chains of mixed kinds, mixed prefix shapes, and chains with
        // zero, one, or many env layers so a future regression in
        // either side surfaces here.
        let chains = [
            Vec::new(),
            vec![ConfigSource::Defaults],
            sample_chain(),
            vec![
                ConfigSource::Env(String::new()),
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::Env("B_".to_owned()),
                ConfigSource::Env(String::new()),
                ConfigSource::File(PathBuf::from("/a.yaml")),
            ],
        ];
        for chain in &chains {
            let hist = chain.as_slice().env_prefix_kind_histogram();
            for kind in EnvMetadataTagKind::ALL.iter().copied() {
                let manual = chain
                    .iter()
                    .filter_map(ConfigSource::env_prefix_kind)
                    .filter(|k| *k == kind)
                    .count();
                assert_eq!(
                    hist.count(kind),
                    manual,
                    "env_prefix_kind_histogram({kind:?}) must equal the open-coded \
                     filter_map+filter count over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    #[test]
    fn env_prefix_kind_histogram_iter_yields_declaration_order() {
        // The dense per-cell iteration must yield the
        // EnvMetadataTagKind::ALL declaration order (Prefixed, Bare)
        // regardless of the chain's observation order — observation
        // order does not leak into the histogram's value-side
        // iteration. Peer to
        // `file_format_histogram_iter_yields_format_all_declaration_order`
        // on the file-format axis and
        // `layer_kind_histogram_iter_yields_declaration_order` on the
        // layer-kind axis.
        let chain = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env("LATER_".to_owned()),
            ConfigSource::Env(String::new()),
        ];
        let pairs: Vec<(EnvMetadataTagKind, usize)> = chain
            .as_slice()
            .env_prefix_kind_histogram()
            .iter()
            .collect();
        let values: Vec<EnvMetadataTagKind> = pairs.iter().map(|(k, _)| *k).collect();
        assert_eq!(values, EnvMetadataTagKind::ALL.to_vec());
    }

    #[test]
    fn env_prefix_kind_histogram_equals_axis_histogram_over_env_prefix_kind_projection() {
        // Pin equivalence to the generic
        // `crate::axis_histogram(self.iter().filter_map(ConfigSource::env_prefix_kind))`
        // shape the trait-default method routes through — the lift
        // must not silently re-implement the per-cell count loop on a
        // parallel surface. Pointwise equality on every
        // EnvMetadataTagKind cell.
        let chains = [
            sample_chain(),
            vec![
                ConfigSource::Defaults,
                ConfigSource::Defaults,
                ConfigSource::Env("X_".to_owned()),
            ],
            vec![
                ConfigSource::Env(String::new()),
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::File(PathBuf::from("/a.yaml")),
            ],
        ];
        for chain in &chains {
            let lifted = chain.as_slice().env_prefix_kind_histogram();
            let generic =
                crate::axis_histogram(chain.iter().filter_map(ConfigSource::env_prefix_kind));
            for kind in EnvMetadataTagKind::ALL.iter().copied() {
                assert_eq!(
                    lifted.count(kind),
                    generic.count(kind),
                    "env_prefix_kind_histogram must equal \
                     axis_histogram(env_prefix_kind-projection) on {kind:?} \
                     over chain of length {}",
                    chain.len(),
                );
            }
        }
    }

    #[test]
    fn layer_kind_histogram_dominant_cell_picks_majority_kind() {
        // Cross-surface pin: the
        // [`crate::AxisHistogram::dominant_cell`] projection composes
        // with the chain-level [`Self::layer_kind_histogram`] to read
        // "the dominant layer kind in this chain" at one method-call
        // site. `sample_chain()` is two File layers + one Env layer
        // (no Defaults), so the dominant kind must be File.
        let chain = sample_chain();
        assert_eq!(
            chain.as_slice().layer_kind_histogram().dominant_cell(),
            Some(ConfigSourceKind::File),
        );
    }

    #[test]
    fn file_format_histogram_dominant_cell_picks_majority_format() {
        // Cross-surface pin on the file-format axis: a chain of three
        // `.yaml` + one `.toml` File layers has dominant Format = Yaml
        // (strict majority — no tie-breaking required). Env / Defaults
        // entries do not contribute (project to None through
        // `file_format()`), so the dominant cell of the file-format
        // histogram is decided by the File-only sub-slice.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.yaml")),
            ConfigSource::File(PathBuf::from("/c.yaml")),
            ConfigSource::File(PathBuf::from("/d.toml")),
        ];
        assert_eq!(
            chain.as_slice().file_format_histogram().dominant_cell(),
            Some(Format::Yaml),
        );
    }

    #[test]
    fn env_prefix_kind_histogram_dominant_cell_for_mixed_prefix_chain() {
        // Cross-surface pin on the env-prefix-presence axis: a chain
        // with two `Env(prefix)` (one bare, one prefixed) has
        // dominant_cell tied; tie-breaking by `EnvMetadataTagKind::ALL`
        // declaration order (Prefixed, Bare) yields Prefixed. Pinned
        // here so the documented declaration-order tie-break is
        // structurally visible at the chain surface, not just the
        // generic `AxisHistogram` surface.
        let chain = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env("APP_".to_owned()),
        ];
        assert_eq!(
            chain.as_slice().env_prefix_kind_histogram().dominant_cell(),
            Some(EnvMetadataTagKind::Prefixed),
        );

        // Sanity: a chain dominated by bare-prefix Env layers picks
        // Bare. Pin the strict-majority case alongside the tie case so
        // both halves of the projection are concretely named.
        let bare_majority = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env(String::new()),
            ConfigSource::Env("X_".to_owned()),
        ];
        assert_eq!(
            bare_majority
                .as_slice()
                .env_prefix_kind_histogram()
                .dominant_cell(),
            Some(EnvMetadataTagKind::Bare),
        );
    }

    #[test]
    fn chain_histograms_dominant_cell_is_none_on_empty_chain() {
        // Empty-chain composition: every chain-level histogram
        // (layer_kind / file_format / env_prefix_kind) over an empty
        // chain is the all-zero histogram, so `dominant_cell` reads
        // None at all three surfaces. Pins the cross-surface
        // empty-history convention at one site.
        let chain: [ConfigSource; 0] = [];
        assert_eq!(chain.layer_kind_histogram().dominant_cell(), None);
        assert_eq!(chain.file_format_histogram().dominant_cell(), None);
        assert_eq!(chain.env_prefix_kind_histogram().dominant_cell(), None);
    }

    #[test]
    fn layer_kind_histogram_distinct_cells_counts_observed_kinds() {
        // Cross-surface pin: the
        // [`crate::AxisHistogram::distinct_cells`] projection composes
        // with [`Self::layer_kind_histogram`] to read "how many
        // distinct layer kinds did this chain contain?" at one
        // method-call site. `sample_chain()` is two File layers + one
        // Env layer (no Defaults), so distinct_cells = 2 (File, Env).
        let chain = sample_chain();
        assert_eq!(chain.as_slice().layer_kind_histogram().distinct_cells(), 2);

        // Singleton-kind chain: every layer is Defaults, so
        // distinct_cells = 1 — the support is the single observed cell.
        let defaults_only = vec![ConfigSource::Defaults, ConfigSource::Defaults];
        assert_eq!(
            defaults_only
                .as_slice()
                .layer_kind_histogram()
                .distinct_cells(),
            1,
        );

        // Axis-cover chain: one layer per kind covers the whole
        // [`ConfigSourceKind::ALL`] axis, so distinct_cells equals the
        // axis cardinality — the maximum-coverage witness. Reads
        // through the named predicate [`AxisHistogram::is_full_cover`]
        // — the boolean form of `distinct_cells == axis_cardinality`
        // — so the typed full-cover question reaches the chain-level
        // histogram without re-deriving the equality at the call site.
        let axis_cover = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        assert!(axis_cover.as_slice().layer_kind_histogram().is_full_cover(),);
    }

    #[test]
    fn file_format_histogram_distinct_cells_counts_observed_formats() {
        // Cross-surface pin on the file-format axis: distinct_cells
        // counts the *recognized* formats observed in the chain. Env /
        // Defaults / unrecognized-extension File entries project to
        // None through `file_format()` so they do not contribute, and
        // duplicate entries on the same format collapse to one
        // distinct cell — the support cardinality is bounded by the
        // axis cardinality, not by the layer count.
        use crate::discovery::Format;
        // Three .yaml + one .toml + Env + Defaults → distinct file
        // formats observed = 2 (Yaml, Toml).
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.yaml")),
            ConfigSource::File(PathBuf::from("/c.yaml")),
            ConfigSource::File(PathBuf::from("/d.toml")),
        ];
        let hist = chain.as_slice().file_format_histogram();
        assert_eq!(hist.distinct_cells(), 2);
        // Companion bound: distinct_cells <= axis_cardinality::<Format>().
        assert!(hist.distinct_cells() <= crate::axis_cardinality::<Format>());
        // Companion bound: distinct_cells <= total.
        assert!(hist.distinct_cells() <= hist.total());

        // Env-only chain: no File layer contributes to the format
        // histogram, so distinct_cells = 0 — the empty-support
        // witness even though the chain is non-empty.
        let env_only = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::Env(String::new()),
        ];
        assert_eq!(
            env_only.as_slice().file_format_histogram().distinct_cells(),
            0,
        );
    }

    #[test]
    fn env_prefix_kind_histogram_distinct_cells_counts_observed_prefix_kinds() {
        // Cross-surface pin on the env-prefix-presence axis: a chain
        // with both a bare and a prefixed Env layer has distinct_cells
        // = 2 — the full axis is covered. A chain with only prefixed
        // Env layers reads 1; a File/Defaults-only chain reads 0.
        let both = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env("APP_".to_owned()),
        ];
        // The full-cover witness on the env-prefix axis — reads
        // through the named [`AxisHistogram::is_full_cover`] predicate
        // rather than the open-coded `distinct_cells ==
        // axis_cardinality` equality.
        assert!(both.as_slice().env_prefix_kind_histogram().is_full_cover(),);

        let prefixed_only = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::Env("OTHER_".to_owned()),
        ];
        assert_eq!(
            prefixed_only
                .as_slice()
                .env_prefix_kind_histogram()
                .distinct_cells(),
            1,
        );

        let no_env = vec![
            ConfigSource::Defaults,
            ConfigSource::File(PathBuf::from("/x.yaml")),
        ];
        assert_eq!(
            no_env
                .as_slice()
                .env_prefix_kind_histogram()
                .distinct_cells(),
            0,
        );
    }

    #[test]
    fn layer_kind_histogram_recessive_cell_picks_minority_kind() {
        // Cross-surface pin: the
        // [`crate::AxisHistogram::recessive_cell`] projection composes
        // with [`Self::layer_kind_histogram`] to read "the rarest
        // observed layer kind in this chain" at one method-call site.
        // `sample_chain()` is two File layers + one Env layer (no
        // Defaults), so the rarest observed kind is Env. Defaults
        // does not appear in the chain (count 0) and is excluded from
        // the argmin per the recessive_cell zero-cell-exclusion rule
        // — the projection picks the rarest *observed* kind, not the
        // overall minimum.
        let chain = sample_chain();
        assert_eq!(
            chain.as_slice().layer_kind_histogram().recessive_cell(),
            Some(ConfigSourceKind::Env),
        );
    }

    #[test]
    fn file_format_histogram_recessive_cell_picks_minority_format() {
        // Cross-surface pin on the file-format axis: a chain of three
        // `.yaml` + one `.toml` File layers has rarest observed
        // Format = Toml (strict minimum — no tie-breaking required).
        // Env / Defaults entries do not contribute (project to None
        // through `file_format()`) and the unobserved Lisp / Nix
        // formats are at count 0 and excluded from the argmin per
        // the recessive_cell zero-cell-exclusion rule.
        use crate::discovery::Format;
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.yaml")),
            ConfigSource::File(PathBuf::from("/c.yaml")),
            ConfigSource::File(PathBuf::from("/d.toml")),
        ];
        assert_eq!(
            chain.as_slice().file_format_histogram().recessive_cell(),
            Some(Format::Toml),
        );
    }

    #[test]
    fn env_prefix_kind_histogram_recessive_cell_for_mixed_prefix_chain() {
        // Cross-surface pin on the env-prefix-presence axis: a chain
        // with two `Env(prefix)` (one bare, one prefixed) has
        // recessive_cell tied at count 1; tie-breaking by
        // `EnvMetadataTagKind::ALL` declaration order (Prefixed,
        // Bare) yields Prefixed — identical to `dominant_cell` on
        // the same tied input. The two projections coincide on every
        // uniform histogram; the pair witnesses that agreement here.
        let chain = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env("APP_".to_owned()),
        ];
        assert_eq!(
            chain
                .as_slice()
                .env_prefix_kind_histogram()
                .recessive_cell(),
            Some(EnvMetadataTagKind::Prefixed),
        );

        // Strict-minority case: a chain dominated by bare-prefix Env
        // layers picks Prefixed as the rarest observed cell. Pin the
        // strict-minimum case alongside the tie case so both halves
        // of the projection are concretely named.
        let bare_majority = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env(String::new()),
            ConfigSource::Env("X_".to_owned()),
        ];
        assert_eq!(
            bare_majority
                .as_slice()
                .env_prefix_kind_histogram()
                .recessive_cell(),
            Some(EnvMetadataTagKind::Prefixed),
        );
    }

    #[test]
    fn chain_histograms_recessive_cell_is_none_on_empty_chain() {
        // Empty-chain composition: every chain-level histogram
        // (layer_kind / file_format / env_prefix_kind) over an empty
        // chain is the all-zero histogram, so `recessive_cell` reads
        // None at all three surfaces. Peer to
        // `chain_histograms_dominant_cell_is_none_on_empty_chain` —
        // the two projections share the same empty-history
        // convention.
        let chain: [ConfigSource; 0] = [];
        assert_eq!(chain.layer_kind_histogram().recessive_cell(), None);
        assert_eq!(chain.file_format_histogram().recessive_cell(), None);
        assert_eq!(chain.env_prefix_kind_histogram().recessive_cell(), None);
    }

    #[test]
    fn chain_histograms_dominant_and_recessive_agree_on_uniform_singleton_chain() {
        // Cross-surface boundary pin: every chain over which a
        // chain-level histogram resolves to a single observed cell —
        // a Defaults-only chain on layer_kind, a `.yaml`-only chain
        // on file_format, a Bare-only Env chain on
        // env_prefix_kind — has `dominant_cell == recessive_cell`,
        // both pointing at the single observed cell. Peer to the
        // cube-side
        // `axis_histogram_dominant_and_recessive_agree_on_uniform_axis_cover_for_every_implementor`
        // pin — the histogram-side agreement holds on every
        // *singleton-support* histogram, not just on the
        // axis-cover histograms; pin the chain-side witness here so
        // the discipline is named at both surfaces.
        use crate::discovery::Format;
        // layer_kind: Defaults-only chain → both projections = Defaults.
        let defaults_only = vec![ConfigSource::Defaults, ConfigSource::Defaults];
        let layer_hist = defaults_only.as_slice().layer_kind_histogram();
        assert_eq!(layer_hist.dominant_cell(), Some(ConfigSourceKind::Defaults));
        assert_eq!(layer_hist.recessive_cell(), layer_hist.dominant_cell());
        // file_format: `.yaml`-only chain → both = Yaml.
        let yaml_only = vec![
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.yaml")),
        ];
        let format_hist = yaml_only.as_slice().file_format_histogram();
        assert_eq!(format_hist.dominant_cell(), Some(Format::Yaml));
        assert_eq!(format_hist.recessive_cell(), format_hist.dominant_cell());
        // env_prefix_kind: Bare-only Env chain → both = Bare.
        let bare_only = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env(String::new()),
        ];
        let env_hist = bare_only.as_slice().env_prefix_kind_histogram();
        assert_eq!(env_hist.dominant_cell(), Some(EnvMetadataTagKind::Bare));
        assert_eq!(env_hist.recessive_cell(), env_hist.dominant_cell());
    }

    #[test]
    fn chain_histograms_spread_is_zero_on_empty_chain() {
        // Empty-chain composition: every chain-level histogram
        // (layer_kind / file_format / env_prefix_kind) over an empty
        // chain is the all-zero histogram, so `spread` reads 0 at
        // all three surfaces — peer to the
        // `chain_histograms_dominant_cell_is_none_on_empty_chain`,
        // `chain_histograms_recessive_cell_is_none_on_empty_chain`,
        // and `chain_histograms_distinct_cells_is_zero_on_empty_chain`
        // empty-history conventions. Pins the cross-surface
        // empty-history convention for the spread scalar at one site.
        let chain: [ConfigSource; 0] = [];
        assert_eq!(chain.layer_kind_histogram().spread(), 0);
        assert_eq!(chain.file_format_histogram().spread(), 0);
        assert_eq!(chain.env_prefix_kind_histogram().spread(), 0);
    }

    #[test]
    fn layer_kind_histogram_spread_reads_distribution_skew() {
        // Cross-surface pin: composing [`crate::AxisHistogram::spread`]
        // with [`Self::layer_kind_histogram`] reads "how unevenly did
        // this chain distribute observations across the observed layer
        // kinds?" at one method-call site.
        //
        // `sample_chain()` has two File layers and one Env layer (no
        // Defaults); observed support = {File, Env} with counts
        // (File: 2, Env: 1) → peak 2, trough 1, spread 1 — the
        // canonical strict-skew shape on a binary observed support.
        let chain = sample_chain();
        let hist = chain.as_slice().layer_kind_histogram();
        assert_eq!(hist.peak_count(), 2);
        assert_eq!(hist.trough_count(), 1);
        assert_eq!(hist.spread(), 1);

        // Singleton-support chain: a Defaults-only chain has one
        // observed cell (peak = trough = chain length), spread = 0
        // — the structural "balanced observation" boundary on the
        // singleton-support shape.
        let defaults_only = vec![ConfigSource::Defaults, ConfigSource::Defaults];
        assert_eq!(defaults_only.as_slice().layer_kind_histogram().spread(), 0);

        // Axis-cover chain (one layer per kind): every cell at 1,
        // peak = trough = 1, spread = 0 — the structural balanced
        // observation boundary on the maximum-coverage shape.
        let axis_cover = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        assert_eq!(axis_cover.as_slice().layer_kind_histogram().spread(), 0);
    }

    #[test]
    fn layer_kind_histogram_unobserved_lists_unused_layer_kinds() {
        // Cross-surface pin: the [`crate::AxisHistogram::unobserved`]
        // projection composes with [`Self::layer_kind_histogram`] to
        // read "which layer kinds did this chain never realize?" at
        // one method-call site. `sample_chain()` is two File layers
        // + one Env layer (no Defaults), so the unobserved kinds are
        // exactly {Defaults} — the strict-subset coverage-gap case.
        use crate::cube::axis_cardinality;
        use std::collections::HashSet;
        let chain = sample_chain();
        let gap: HashSet<ConfigSourceKind> = chain
            .as_slice()
            .layer_kind_histogram()
            .unobserved()
            .collect();
        assert_eq!(gap, HashSet::from([ConfigSourceKind::Defaults]));

        // Defaults-only chain → unobserved = {Env, File}: the dual
        // case where the support is the singleton {Defaults} and the
        // coverage gap is the rest of the axis.
        let defaults_only = vec![ConfigSource::Defaults, ConfigSource::Defaults];
        let defaults_gap: HashSet<ConfigSourceKind> = defaults_only
            .as_slice()
            .layer_kind_histogram()
            .unobserved()
            .collect();
        assert_eq!(
            defaults_gap,
            HashSet::from([ConfigSourceKind::Env, ConfigSourceKind::File]),
        );

        // Full-axis cover chain → unobserved is empty: every layer
        // kind appears at least once, so there is no coverage gap.
        // The dual boundary of the empty-chain case (which is pinned
        // in `chain_histograms_unobserved_is_full_axis_on_empty_chain`
        // below).
        let axis_cover = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/x.yaml")),
        ];
        assert_eq!(
            axis_cover
                .as_slice()
                .layer_kind_histogram()
                .unobserved()
                .count(),
            0,
        );
        assert_eq!(
            axis_cover
                .as_slice()
                .layer_kind_histogram()
                .distinct_cells(),
            axis_cardinality::<ConfigSourceKind>(),
        );
    }

    #[test]
    fn file_format_histogram_unobserved_lists_unused_formats() {
        // Cross-surface pin on the file-format axis: a chain of three
        // `.yaml` + one `.toml` File layers + an Env + Defaults has
        // observed file-format support {Yaml, Toml}, so the
        // coverage gap is the unobserved formats {Lisp, Nix} — the
        // strict-subset case. Env / Defaults entries project to
        // None through `file_format()` and contribute nothing to the
        // histogram total, so they do not enter the support.
        use crate::discovery::Format;
        use std::collections::HashSet;
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/a.yaml")),
            ConfigSource::File(PathBuf::from("/b.yaml")),
            ConfigSource::File(PathBuf::from("/c.yaml")),
            ConfigSource::File(PathBuf::from("/d.toml")),
        ];
        let gap: HashSet<Format> = chain
            .as_slice()
            .file_format_histogram()
            .unobserved()
            .collect();
        assert_eq!(gap, HashSet::from([Format::Lisp, Format::Nix]));

        // Env-only chain → file_format support is empty, so
        // unobserved = full axis = {Yaml, Toml, Lisp, Nix}. Peer to
        // the empty-histogram boundary on the cube side: an all-zero
        // histogram has every cell unobserved.
        let env_only = vec![ConfigSource::Env(String::new())];
        let env_only_gap: HashSet<Format> = env_only
            .as_slice()
            .file_format_histogram()
            .unobserved()
            .collect();
        assert_eq!(env_only_gap, Format::ALL.iter().copied().collect());
    }

    #[test]
    fn env_prefix_kind_histogram_unobserved_lists_unused_prefix_kinds() {
        // Cross-surface pin on the env-prefix-presence axis: a
        // Bare-only Env chain has env_prefix_kind support {Bare}, so
        // the coverage gap is {Prefixed} — the strict-subset case
        // peer to the singleton-support pin on `layer_kind_histogram`.
        // The dual chain (Prefixed-only) closes the symmetric case.
        use std::collections::HashSet;
        let bare_only = vec![
            ConfigSource::Env(String::new()),
            ConfigSource::Env(String::new()),
        ];
        let bare_gap: HashSet<EnvMetadataTagKind> = bare_only
            .as_slice()
            .env_prefix_kind_histogram()
            .unobserved()
            .collect();
        assert_eq!(bare_gap, HashSet::from([EnvMetadataTagKind::Prefixed]));

        let prefixed_only = vec![
            ConfigSource::Env("A_".to_owned()),
            ConfigSource::Env("B_".to_owned()),
        ];
        let prefixed_gap: HashSet<EnvMetadataTagKind> = prefixed_only
            .as_slice()
            .env_prefix_kind_histogram()
            .unobserved()
            .collect();
        assert_eq!(prefixed_gap, HashSet::from([EnvMetadataTagKind::Bare]));

        // No-Env chain (Defaults + File only) → empty support, so
        // unobserved is the full env-prefix-kind axis.
        let no_env = vec![
            ConfigSource::Defaults,
            ConfigSource::File(PathBuf::from("/x.yaml")),
        ];
        let no_env_gap: HashSet<EnvMetadataTagKind> = no_env
            .as_slice()
            .env_prefix_kind_histogram()
            .unobserved()
            .collect();
        assert_eq!(
            no_env_gap,
            EnvMetadataTagKind::ALL.iter().copied().collect(),
        );
    }

    #[test]
    fn chain_histograms_unobserved_is_full_axis_on_empty_chain() {
        // Empty-chain composition: every chain-level histogram
        // (layer_kind / file_format / env_prefix_kind) over an empty
        // chain is the all-zero histogram, so `unobserved` iterates
        // the full axis at all three surfaces. Peer to
        // `chain_histograms_dominant_cell_is_none_on_empty_chain` and
        // `chain_histograms_distinct_cells_is_zero_on_empty_chain`:
        // the empty-history convention is named at the coverage-gap
        // surface as well, with the tight boundary witness
        // (`unobserved_cells` reaches every cell because every cell is
        // unobserved). Reads through the named scalar
        // [`AxisHistogram::unobserved_cells`] — the structural
        // complement of [`AxisHistogram::distinct_cells`] over the
        // closed axis — rather than the open-coded
        // `unobserved().count()` chain.
        use crate::cube::axis_cardinality;
        let chain: [ConfigSource; 0] = [];
        assert_eq!(
            chain.layer_kind_histogram().unobserved_cells(),
            axis_cardinality::<ConfigSourceKind>(),
        );
        assert_eq!(
            chain.file_format_histogram().unobserved_cells(),
            axis_cardinality::<crate::discovery::Format>(),
        );
        assert_eq!(
            chain.env_prefix_kind_histogram().unobserved_cells(),
            axis_cardinality::<EnvMetadataTagKind>(),
        );
    }

    #[test]
    fn chain_histograms_distinct_cells_is_zero_on_empty_chain() {
        // Empty-chain composition: every chain-level histogram
        // (layer_kind / file_format / env_prefix_kind) over an empty
        // chain is the all-zero histogram, so distinct_cells = 0 at
        // all three surfaces. Peer to the
        // chain_histograms_dominant_cell_is_none_on_empty_chain pin —
        // pins the cross-surface empty-history convention for the
        // support-cardinality projection at one site.
        let chain: [ConfigSource; 0] = [];
        assert_eq!(chain.layer_kind_histogram().distinct_cells(), 0);
        assert_eq!(chain.file_format_histogram().distinct_cells(), 0);
        assert_eq!(chain.env_prefix_kind_histogram().distinct_cells(), 0);
    }

    #[test]
    fn env_prefix_kind_histogram_total_equals_env_layer_count() {
        // Cross-histogram invariant — STRICT equality (no inequality
        // bound, unlike the file-format histogram): every Env layer
        // projects to a Some cell on env_prefix_kind (empty-prefix →
        // Bare, non-empty → Prefixed), so the histogram total is
        // exactly the Env count in the layer-kind histogram regardless
        // of prefix shape. Pins the stronger structural law between the
        // chain's third and first aggregate projections.
        let chains: [Vec<ConfigSource>; 5] = [
            sample_chain(),
            vec![],
            vec![ConfigSource::Defaults, ConfigSource::Defaults],
            vec![
                ConfigSource::Env(String::new()),
                ConfigSource::Env("A_".to_owned()),
                ConfigSource::Env("B_".to_owned()),
                ConfigSource::Env(String::new()),
            ],
            vec![
                ConfigSource::Defaults,
                ConfigSource::File(PathBuf::from("/a.yaml")),
                ConfigSource::Env("E_".to_owned()),
                ConfigSource::File(PathBuf::from("/b.unknownext")),
                ConfigSource::Env(String::new()),
            ],
        ];
        for chain in &chains {
            let env_kind_count = chain
                .as_slice()
                .layer_kind_histogram()
                .count(ConfigSourceKind::Env);
            let env_prefix_total = chain.as_slice().env_prefix_kind_histogram().total();
            assert_eq!(
                env_prefix_total,
                env_kind_count,
                "env_prefix_kind_histogram total ({env_prefix_total}) must equal \
                 layer_kind_histogram(Env) ({env_kind_count}) over chain of length {}",
                chain.len(),
            );
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

    #[test]
    fn config_source_kind_ord_matches_all_declaration_order() {
        // The derived Ord on ConfigSourceKind is declaration-order lex
        // over ALL: `Defaults < Env < File`. A BTreeMap keyed on the
        // layer-kind axis (per-kind attribution histograms, per-kind
        // failure-rate dashboards, attestation manifests recording the
        // layer-kind cardinality mix of a recorded chain) emits rows in
        // that order deterministically without a hand-rolled comparator
        // at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under Ord,
        // (2) cmp/partial_cmp agree with the array-index lex over ALL on
        // every pair (and reflexivity holds).
        use std::cmp::Ordering;
        for window in ConfigSourceKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "ConfigSourceKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in ConfigSourceKind::ALL.iter().enumerate() {
            for (j, &b) in ConfigSourceKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "ConfigSourceKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "ConfigSourceKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn config_source_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed consumer
        // site: a BTreeMap<ConfigSourceKind, _> emits keys in
        // declaration order on `iter()` / `into_iter()` regardless of
        // insertion order, matching `ConfigSourceKind::ALL`. Idiom-peer
        // of the same pin on FormatProvenance (commit `2c7654c`) and on
        // FormatMetadataTag (commit `fc0051e`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<ConfigSourceKind, u32> = BTreeMap::new();
        counts.insert(ConfigSourceKind::File, 3);
        counts.insert(ConfigSourceKind::Defaults, 1);
        counts.insert(ConfigSourceKind::Env, 2);
        let observed: Vec<ConfigSourceKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            ConfigSourceKind::ALL.to_vec(),
            "BTreeMap<ConfigSourceKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn config_source_kind_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in lockstep.
        for k in ConfigSourceKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn config_source_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in ConfigSourceKind::ALL {
            let rendered = k.to_string();
            let parsed: ConfigSourceKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn config_source_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var or
        // CLI flag parse pointwise to the same variant.
        assert_eq!(
            "DEFAULTS".parse::<ConfigSourceKind>().unwrap(),
            ConfigSourceKind::Defaults,
        );
        assert_eq!(
            "Env".parse::<ConfigSourceKind>().unwrap(),
            ConfigSourceKind::Env,
        );
        assert_eq!(
            "FILE".parse::<ConfigSourceKind>().unwrap(),
            ConfigSourceKind::File,
        );
    }

    #[test]
    fn config_source_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // FormatProvenance's FromStr surface (commit `2c7654c`) and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["default", "http", "vault", "", "  env"] {
            let err = bad
                .parse::<ConfigSourceKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn config_source_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize, Deserialize)
        // idiom-peer of the (Display, FromStr) stdlib pair on the layer-
        // kind axis. A consumer struct holding a ConfigSourceKind field
        // under #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the layer-kind of a failing attribution)
        // round-trips without a consumer-side rename helper.
        for k in ConfigSourceKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: ConfigSourceKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn config_source_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip law
        // composes pointwise — a future divergence in either Serialize
        // impl surfaces here.
        for k in ConfigSourceKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: ConfigSourceKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn config_source_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, ConfigSourceKind)] = &[
            ("Defaults", ConfigSourceKind::Defaults),
            ("ENV", ConfigSourceKind::Env),
            ("File", ConfigSourceKind::File),
        ];
        for (input, expected) in cases {
            let parsed: ConfigSourceKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn config_source_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized layer-kind label surfaces at the serde error
        // site with the offending substring verbatim in the rendered
        // message, lifted through ShikumiError::Parse's Display impl.
        // Same verbatim-rejection discipline as FormatProvenance's
        // serde surface (commit `2c7654c`) and Format's serde surface
        // (commit `b56b121`).
        for bad in &["http", "vault", "default", "configmap"] {
            let err = serde_yaml::from_str::<ConfigSourceKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
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
    fn figment_source_kind_ord_matches_all_declaration_order() {
        // The derived Ord on FigmentSourceKind is declaration-order lex
        // over ALL: `File < Code < Custom`. A BTreeMap keyed on the
        // figment-Source-axis kind (per-kind attribution histograms,
        // per-kind failure-rate dashboards, attestation manifests
        // recording the figment-Source-axis kind cardinality mix) emits
        // rows in that order deterministically without a hand-rolled
        // comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under Ord,
        // (2) cmp/partial_cmp agree with the array-index lex over ALL on
        // every pair (and reflexivity holds). Idiom-peer of the same pin
        // on ConfigSourceKind (commit `e0b96d1`).
        use std::cmp::Ordering;
        for window in FigmentSourceKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "FigmentSourceKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in FigmentSourceKind::ALL.iter().enumerate() {
            for (j, &b) in FigmentSourceKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "FigmentSourceKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "FigmentSourceKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn figment_source_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed consumer
        // site: a BTreeMap<FigmentSourceKind, _> emits keys in
        // declaration order on `iter()` / `into_iter()` regardless of
        // insertion order, matching `FigmentSourceKind::ALL`. Idiom-peer
        // of the same pin on ConfigSourceKind (commit `e0b96d1`) and on
        // FormatProvenance (commit `2c7654c`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<FigmentSourceKind, u32> = BTreeMap::new();
        counts.insert(FigmentSourceKind::Custom, 3);
        counts.insert(FigmentSourceKind::File, 1);
        counts.insert(FigmentSourceKind::Code, 2);
        let observed: Vec<FigmentSourceKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            FigmentSourceKind::ALL.to_vec(),
            "BTreeMap<FigmentSourceKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn figment_source_kind_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on ConfigSourceKind
        // (commit `e0b96d1`).
        for k in FigmentSourceKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn figment_source_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in FigmentSourceKind::ALL {
            let rendered = k.to_string();
            let parsed: FigmentSourceKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn figment_source_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var or
        // CLI flag parse pointwise to the same variant.
        assert_eq!(
            "FILE".parse::<FigmentSourceKind>().unwrap(),
            FigmentSourceKind::File,
        );
        assert_eq!(
            "Code".parse::<FigmentSourceKind>().unwrap(),
            FigmentSourceKind::Code,
        );
        assert_eq!(
            "CuStOm".parse::<FigmentSourceKind>().unwrap(),
            FigmentSourceKind::Custom,
        );
    }

    #[test]
    fn figment_source_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`),
        // FormatProvenance's FromStr surface (commit `2c7654c`), and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["files", "raw", "url", "", "  code"] {
            let err = bad
                .parse::<FigmentSourceKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn figment_source_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize, Deserialize)
        // idiom-peer of the (Display, FromStr) stdlib pair on the
        // figment-Source-axis kind primitive. A consumer struct holding
        // a FigmentSourceKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation manifest
        // recording the figment-Source kind of a failing attribution)
        // round-trips without a consumer-side rename helper.
        for k in FigmentSourceKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: FigmentSourceKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn figment_source_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip law
        // composes pointwise — a future divergence in either Serialize
        // impl surfaces here.
        for k in FigmentSourceKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: FigmentSourceKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn figment_source_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, FigmentSourceKind)] = &[
            ("File", FigmentSourceKind::File),
            ("CODE", FigmentSourceKind::Code),
            ("Custom", FigmentSourceKind::Custom),
        ];
        for (input, expected) in cases {
            let parsed: FigmentSourceKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn figment_source_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized figment-Source-axis kind label surfaces at
        // the serde error site with the offending substring verbatim in
        // the rendered message, lifted through ShikumiError::Parse's
        // Display impl. Same verbatim-rejection discipline as
        // ConfigSourceKind's serde surface (commit `e0b96d1`) and
        // FormatProvenance's serde surface (commit `2c7654c`).
        for bad in &["files", "raw", "url", "configmap"] {
            let err = serde_yaml::from_str::<FigmentSourceKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_ord_matches_all_declaration_order() {
        // The derived Ord on FigmentNameTagKind is declaration-order
        // lex over ALL: `Format < Env`. A BTreeMap keyed on the
        // figment-Name-axis kind (per-kind attribution histograms,
        // per-kind failure-rate dashboards, attestation manifests
        // recording the figment-Name-axis kind cardinality mix) emits
        // rows in that order deterministically without a hand-rolled
        // comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex over
        // ALL on every pair (and reflexivity holds). Idiom-peer of the
        // same pin on FigmentSourceKind (commit `5df265c`) and
        // ConfigSourceKind (commit `e0b96d1`).
        use std::cmp::Ordering;
        for window in FigmentNameTagKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "FigmentNameTagKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in FigmentNameTagKind::ALL.iter().enumerate() {
            for (j, &b) in FigmentNameTagKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "FigmentNameTagKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "FigmentNameTagKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn figment_name_tag_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed consumer
        // site: a BTreeMap<FigmentNameTagKind, _> emits keys in
        // declaration order on `iter()` / `into_iter()` regardless of
        // insertion order, matching `FigmentNameTagKind::ALL`.
        // Idiom-peer of the same pin on FigmentSourceKind
        // (commit `5df265c`) and ConfigSourceKind (commit `e0b96d1`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<FigmentNameTagKind, u32> = BTreeMap::new();
        counts.insert(FigmentNameTagKind::Env, 2);
        counts.insert(FigmentNameTagKind::Format, 1);
        let observed: Vec<FigmentNameTagKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            FigmentNameTagKind::ALL.to_vec(),
            "BTreeMap<FigmentNameTagKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn figment_name_tag_kind_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on FigmentSourceKind
        // (commit `5df265c`).
        for k in FigmentNameTagKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in FigmentNameTagKind::ALL {
            let rendered = k.to_string();
            let parsed: FigmentNameTagKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn figment_name_tag_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var or
        // CLI flag parse pointwise to the same variant.
        assert_eq!(
            "FORMAT".parse::<FigmentNameTagKind>().unwrap(),
            FigmentNameTagKind::Format,
        );
        assert_eq!(
            "Env".parse::<FigmentNameTagKind>().unwrap(),
            FigmentNameTagKind::Env,
        );
        assert_eq!(
            "FoRmAt".parse::<FigmentNameTagKind>().unwrap(),
            FigmentNameTagKind::Format,
        );
    }

    #[test]
    fn figment_name_tag_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // FigmentSourceKind's FromStr surface (commit `5df265c`),
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`),
        // FormatProvenance's FromStr surface (commit `2c7654c`), and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["formats", "envs", "raw", "", "  env"] {
            let err = bad
                .parse::<FigmentNameTagKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize, Deserialize)
        // idiom-peer of the (Display, FromStr) stdlib pair on the
        // figment-Name-axis kind primitive. A consumer struct holding
        // a FigmentNameTagKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the figment-Name kind of a failing
        // attribution) round-trips without a consumer-side rename
        // helper.
        for k in FigmentNameTagKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: FigmentNameTagKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn figment_name_tag_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for k in FigmentNameTagKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: FigmentNameTagKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn figment_name_tag_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, FigmentNameTagKind)] = &[
            ("Format", FigmentNameTagKind::Format),
            ("ENV", FigmentNameTagKind::Env),
            ("FoRmAt", FigmentNameTagKind::Format),
        ];
        for (input, expected) in cases {
            let parsed: FigmentNameTagKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized figment-Name-axis kind label surfaces at the
        // serde error site with the offending substring verbatim in
        // the rendered message, lifted through ShikumiError::Parse's
        // Display impl. Same verbatim-rejection discipline as
        // FigmentSourceKind's serde surface (commit `5df265c`),
        // ConfigSourceKind's serde surface (commit `e0b96d1`), and
        // FormatProvenance's serde surface (commit `2c7654c`).
        for bad in &["formats", "envs", "raw", "configmap"] {
            let err = serde_yaml::from_str::<FigmentNameTagKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn env_metadata_tag_kind_ord_matches_all_declaration_order() {
        // The derived Ord on EnvMetadataTagKind is declaration-order
        // lex over ALL: `Prefixed < Bare`. A BTreeMap keyed on the
        // env-name sub-axis kind (per-kind attribution histograms,
        // per-kind failure-rate dashboards, attestation manifests
        // recording the env-name sub-axis kind cardinality mix of a
        // recorded chain) emits rows in that order deterministically
        // without a hand-rolled comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds). Idiom-peer
        // of the same pin on FigmentNameTagKind (commit `64a47e7`),
        // FigmentSourceKind (commit `5df265c`), and ConfigSourceKind
        // (commit `e0b96d1`).
        use std::cmp::Ordering;
        for window in EnvMetadataTagKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "EnvMetadataTagKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in EnvMetadataTagKind::ALL.iter().enumerate() {
            for (j, &b) in EnvMetadataTagKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "EnvMetadataTagKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "EnvMetadataTagKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn env_metadata_tag_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed consumer
        // site: a BTreeMap<EnvMetadataTagKind, _> emits keys in
        // declaration order on `iter()` / `into_iter()` regardless of
        // insertion order, matching `EnvMetadataTagKind::ALL`.
        // Idiom-peer of the same pin on FigmentNameTagKind
        // (commit `64a47e7`), FigmentSourceKind (commit `5df265c`),
        // and ConfigSourceKind (commit `e0b96d1`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<EnvMetadataTagKind, u32> = BTreeMap::new();
        counts.insert(EnvMetadataTagKind::Bare, 2);
        counts.insert(EnvMetadataTagKind::Prefixed, 1);
        let observed: Vec<EnvMetadataTagKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            EnvMetadataTagKind::ALL.to_vec(),
            "BTreeMap<EnvMetadataTagKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn env_metadata_tag_kind_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on FigmentNameTagKind
        // (commit `64a47e7`) and FigmentSourceKind (commit `5df265c`).
        for k in EnvMetadataTagKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn env_metadata_tag_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in EnvMetadataTagKind::ALL {
            let rendered = k.to_string();
            let parsed: EnvMetadataTagKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn env_metadata_tag_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var
        // or CLI flag parse pointwise to the same variant.
        assert_eq!(
            "PREFIXED".parse::<EnvMetadataTagKind>().unwrap(),
            EnvMetadataTagKind::Prefixed,
        );
        assert_eq!(
            "Bare".parse::<EnvMetadataTagKind>().unwrap(),
            EnvMetadataTagKind::Bare,
        );
        assert_eq!(
            "PrEfIxEd".parse::<EnvMetadataTagKind>().unwrap(),
            EnvMetadataTagKind::Prefixed,
        );
        assert_eq!(
            "bArE".parse::<EnvMetadataTagKind>().unwrap(),
            EnvMetadataTagKind::Bare,
        );
    }

    #[test]
    fn env_metadata_tag_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // FigmentNameTagKind's FromStr surface (commit `64a47e7`),
        // FigmentSourceKind's FromStr surface (commit `5df265c`),
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`),
        // FormatProvenance's FromStr surface (commit `2c7654c`), and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["pref", "raw", "naked", "", "  bare"] {
            let err = bad
                .parse::<EnvMetadataTagKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn env_metadata_tag_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize, Deserialize)
        // idiom-peer of the (Display, FromStr) stdlib pair on the
        // env-name sub-axis kind primitive. A consumer struct holding
        // an EnvMetadataTagKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the env-name sub-axis kind of a failing
        // attribution) round-trips without a consumer-side rename
        // helper.
        for k in EnvMetadataTagKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: EnvMetadataTagKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn env_metadata_tag_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for k in EnvMetadataTagKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: EnvMetadataTagKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn env_metadata_tag_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, EnvMetadataTagKind)] = &[
            ("Prefixed", EnvMetadataTagKind::Prefixed),
            ("BARE", EnvMetadataTagKind::Bare),
            ("PrEfIxEd", EnvMetadataTagKind::Prefixed),
            ("bArE", EnvMetadataTagKind::Bare),
        ];
        for (input, expected) in cases {
            let parsed: EnvMetadataTagKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn env_metadata_tag_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized env-name sub-axis kind label surfaces at
        // the serde error site with the offending substring verbatim
        // in the rendered message, lifted through
        // ShikumiError::Parse's Display impl. Same verbatim-rejection
        // discipline as FigmentNameTagKind's serde surface
        // (commit `64a47e7`), FigmentSourceKind's serde surface
        // (commit `5df265c`), ConfigSourceKind's serde surface
        // (commit `e0b96d1`), and FormatProvenance's serde surface
        // (commit `2c7654c`).
        for bad in &["pref", "raw", "naked", "envvar"] {
            let err = serde_yaml::from_str::<EnvMetadataTagKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn env_metadata_tag_kind_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on EnvMetadataTagKind's YAML
        // emission: both variants render as a bare lowercase scalar
        // (no quotes, no tag prefix). Routes through
        // Serializer::collect_str → Display → as_str, so the wire
        // shape is exactly `format!("{k}")` followed by serde_yaml's
        // newline terminator. Pins the serde idiom-peer of the
        // Display surface byte-for-byte at concrete positions across
        // both variants. Idiom-peer of
        // `secret_ref_shape_serde_yaml_emission_is_bare_scalar`
        // (commit `8a84bb6`).
        assert_eq!(
            serde_yaml::to_string(&EnvMetadataTagKind::Prefixed).unwrap(),
            "prefixed\n",
        );
        assert_eq!(
            serde_yaml::to_string(&EnvMetadataTagKind::Bare).unwrap(),
            "bare\n",
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

    // ---- FigmentNameTagKind / FigmentNameTag::kind ----
    //
    // The (FigmentNameTag → FigmentNameTagKind) lift closes the
    // figment-metadata kind universe under one typescape primitive set:
    // the figment-Source axis was already projected to a `'static`
    // discriminant (FigmentSourceKind via FigmentSourceTag::kind); the
    // figment-`Metadata::name` axis now has its symmetric peer. Tests
    // mirror the FigmentSourceKind suite pointwise.

    /// Canonical sample table covering every `FigmentNameTag` variant
    /// once, with the kind each must classify into. Source for the
    /// `figment_name_tag_kind_all_*` cover/partition tests below — peer
    /// to `canonical_figment_source_kind_samples` on the figment-Source
    /// axis.
    fn canonical_figment_name_tag_kind_samples() -> Vec<(String, FigmentNameTagKind)> {
        vec![
            (
                crate::discovery::Format::Lisp.metadata_name(Path::new("/etc/app/app.lisp")),
                FigmentNameTagKind::Format,
            ),
            (
                crate::discovery::Format::Nix.metadata_name(Path::new("/etc/app/app.nix")),
                FigmentNameTagKind::Format,
            ),
            (
                ConfigSource::env_metadata_name("MYAPP_"),
                FigmentNameTagKind::Env,
            ),
            (ConfigSource::env_metadata_name(""), FigmentNameTagKind::Env),
        ]
    }

    #[test]
    fn figment_name_tag_kind_classifies_each_variant() {
        // The forward map FigmentNameTag → FigmentNameTagKind is
        // exhaustive: every variant pins to exactly one kind. Mirrors
        // `figment_source_kind_classifies_each_variant` on the
        // figment-Source axis.
        let lisp_name = crate::discovery::Format::Lisp.metadata_name(Path::new("/a.lisp"));
        let lisp_tag = FigmentNameTag::classify(&lisp_name).unwrap();
        assert_eq!(lisp_tag.kind(), FigmentNameTagKind::Format);

        let nix_name = crate::discovery::Format::Nix.metadata_name(Path::new("/a.nix"));
        let nix_tag = FigmentNameTag::classify(&nix_name).unwrap();
        assert_eq!(nix_tag.kind(), FigmentNameTagKind::Format);

        let prefixed = ConfigSource::env_metadata_name("APP_");
        let prefixed_tag = FigmentNameTag::classify(&prefixed).unwrap();
        assert_eq!(prefixed_tag.kind(), FigmentNameTagKind::Env);

        let bare = ConfigSource::env_metadata_name("");
        let bare_tag = FigmentNameTag::classify(&bare).unwrap();
        assert_eq!(bare_tag.kind(), FigmentNameTagKind::Env);
    }

    #[test]
    fn figment_name_tag_kind_is_data_free() {
        // Inner data does not influence kind — every Format variant
        // maps to FigmentNameTagKind::Format regardless of the inner
        // FormatMetadataTag's format or path; every Env variant maps
        // to FigmentNameTagKind::Env regardless of the inner
        // EnvMetadataTag's prefix / bare distinction. Mirrors
        // `figment_source_kind_is_data_free` on the figment-Source axis.
        for (format, path) in [
            (crate::discovery::Format::Lisp, "/a.lisp"),
            (crate::discovery::Format::Lisp, "/very/long/path/to/x.lisp"),
            (crate::discovery::Format::Nix, "rel.nix"),
        ] {
            let name = format.metadata_name(Path::new(path));
            let tag = FigmentNameTag::classify(&name).unwrap();
            assert_eq!(tag.kind(), FigmentNameTagKind::Format);
        }
        for prefix in ["MYAPP_", "TOBIRA_", "X_", ""] {
            let name = ConfigSource::env_metadata_name(prefix);
            let tag = FigmentNameTag::classify(&name).unwrap();
            assert_eq!(tag.kind(), FigmentNameTagKind::Env);
        }
    }

    #[test]
    fn figment_name_tag_kind_agrees_with_as_predicates_pointwise() {
        // The kind() / as_format() / as_env() pair must agree on every
        // constructible tag variant — kind is the closed-enum lift of
        // the two `as_*` projection predicates. Mirrors
        // `figment_source_kind_agrees_with_predicates_pointwise` on the
        // figment-Source axis.
        for (name, _) in canonical_figment_name_tag_kind_samples() {
            let tag = FigmentNameTag::classify(&name).unwrap();
            assert_eq!(
                tag.as_format().is_some(),
                tag.kind() == FigmentNameTagKind::Format,
            );
            assert_eq!(
                tag.as_env().is_some(),
                tag.kind() == FigmentNameTagKind::Env,
            );
            // Kind-side predicates agree pointwise with the as_* tag
            // projections.
            assert_eq!(
                tag.kind().is_format(),
                tag.kind() == FigmentNameTagKind::Format,
            );
            assert_eq!(tag.kind().is_env(), tag.kind() == FigmentNameTagKind::Env);
        }
    }

    #[test]
    fn figment_name_tag_attribution_axis_is_always_metadata_name() {
        // Structural law: every FigmentNameTag classification sits on
        // the metadata.name axis. This is the cross-primitive bridge
        // between FigmentNameTag and AttributionAxis — symmetric peer
        // of `figment_source_tag_attribution_axis_is_always_metadata_source`
        // on the figment-Source axis.
        use crate::AttributionAxis;
        for (name, _) in canonical_figment_name_tag_kind_samples() {
            let tag = FigmentNameTag::classify(&name).unwrap();
            assert_eq!(tag.attribution_axis(), AttributionAxis::MetadataName);
        }
    }

    #[test]
    fn figment_name_tag_kind_is_static_and_copy_and_hashable() {
        // The discriminant is `'static` (no lifetime parameter) so it
        // can cross thread boundaries the borrowed tag cannot. Trait
        // bounds match the sibling typescape primitives
        // (FigmentSourceKind, ConfigSourceKind, AttributionRule,
        // AttributionConfidence, AttributionAxis).
        fn assert_static<T: 'static>() {}
        use std::collections::HashSet;
        let mut set: HashSet<FigmentNameTagKind> =
            FigmentNameTagKind::ALL.iter().copied().collect();
        set.insert(FigmentNameTagKind::Format); // duplicate
        assert_eq!(set.len(), FigmentNameTagKind::ALL.len());

        // Copy: rebind without move.
        let k = FigmentNameTagKind::Env;
        let k2 = k;
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k2, k3);

        // 'static — observable by inserting into a static bound.
        assert_static::<FigmentNameTagKind>();
    }

    #[test]
    fn figment_name_tag_kind_all_has_no_duplicates() {
        // The constant must be a set — no variant listed twice. Pins
        // the typescape discipline shared with FigmentSourceKind::ALL
        // and the other closed-enum kind axes.
        use std::collections::HashSet;
        let set: HashSet<FigmentNameTagKind> = FigmentNameTagKind::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            FigmentNameTagKind::ALL.len(),
            "FigmentNameTagKind::ALL must contain no duplicates; got: {:?}",
            FigmentNameTagKind::ALL,
        );
    }

    #[test]
    fn figment_name_tag_kind_all_covers_every_constructible_tag() {
        // Subset cover: every kind produced by FigmentNameTag::kind
        // over the canonical sample table must lie in
        // FigmentNameTagKind::ALL. A future tag variant that adds a new
        // kind class must extend FigmentNameTagKind and its ALL in the
        // same commit; otherwise this test fails.
        use std::collections::HashSet;
        let declared: HashSet<FigmentNameTagKind> =
            FigmentNameTagKind::ALL.iter().copied().collect();
        let observed: HashSet<FigmentNameTagKind> = canonical_figment_name_tag_kind_samples()
            .iter()
            .map(|(name, _)| FigmentNameTag::classify(name).unwrap().kind())
            .collect();
        assert!(
            observed.is_subset(&declared),
            "FigmentNameTag::kind image must lie in FigmentNameTagKind::ALL; \
             observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn figment_name_tag_kind_all_equals_tag_kind_image() {
        // Tight equality (stronger than subset cover): every variant
        // in FigmentNameTagKind::ALL must be witnessed by at least one
        // tag's kind() — no orphan variant in the declared kind space
        // lacks a producing tag.
        use std::collections::HashSet;
        let declared: HashSet<FigmentNameTagKind> =
            FigmentNameTagKind::ALL.iter().copied().collect();
        let observed: HashSet<FigmentNameTagKind> = canonical_figment_name_tag_kind_samples()
            .iter()
            .map(|(name, _)| FigmentNameTag::classify(name).unwrap().kind())
            .collect();
        assert_eq!(
            observed, declared,
            "FigmentNameTag::kind image must equal FigmentNameTagKind::ALL",
        );
    }

    #[test]
    fn figment_name_tag_kind_all_declaration_order_is_format_env() {
        // Pin declaration order. Consumers (diagnostics legends,
        // attestation manifests, dashboard column orderings) that
        // iterate ALL get a stable order; reordering the slice is a
        // breaking change that must show up here.
        assert_eq!(
            FigmentNameTagKind::ALL,
            &[FigmentNameTagKind::Format, FigmentNameTagKind::Env],
        );
    }

    #[test]
    fn figment_name_tag_kind_all_partition_is_format_xor_env() {
        // Boolean partition: `is_format` / `is_env` over a tag sliced
        // by each kind cell must agree with the cell's identity.
        let samples = canonical_figment_name_tag_kind_samples();
        for kind in FigmentNameTagKind::ALL.iter().copied() {
            let witnessing_name = samples
                .iter()
                .find(|(name, _)| FigmentNameTag::classify(name).unwrap().kind() == kind)
                .map(|(name, _)| name)
                .expect("every kind cell must be witnessed by some tag");
            let tag = FigmentNameTag::classify(witnessing_name).unwrap();
            match kind {
                FigmentNameTagKind::Format => {
                    assert!(tag.kind().is_format());
                    assert!(!tag.kind().is_env());
                }
                FigmentNameTagKind::Env => {
                    assert!(tag.kind().is_env());
                    assert!(!tag.kind().is_format());
                }
            }
        }
    }

    #[test]
    fn figment_name_tag_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on FigmentNameTagKind::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Env", prefixing "name-format") fails here
        // before drifting through the trait-uniform round-trip law and
        // the operator-facing rendering surface. The `"env"` label
        // intentionally coincides with `ConfigSourceKind::Env`'s label
        // by typescape design: the two axes meet at the shikumi-env-
        // layer ↔ figment-Env-name resolution boundary.
        assert_eq!(FigmentNameTagKind::Format.as_str(), "format");
        assert_eq!(FigmentNameTagKind::Env.as_str(), "env");
    }

    #[test]
    fn figment_name_tag_kind_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // FigmentNameTagKind: each canonical lowercase name parses back
        // to its variant via the ClosedAxisLabel default impl. Mixed-
        // case forms an operator might type round-trip case-insensitively.
        use crate::ClosedAxisLabel;
        for k in FigmentNameTagKind::ALL.iter().copied() {
            assert_eq!(
                <FigmentNameTagKind as ClosedAxisLabel>::from_canonical_str(k.as_str()),
                Some(k),
                "trait from_canonical_str must round-trip for {k:?}",
            );
        }
        assert_eq!(
            <FigmentNameTagKind as ClosedAxisLabel>::from_canonical_str("Format"),
            Some(FigmentNameTagKind::Format),
        );
        assert_eq!(
            <FigmentNameTagKind as ClosedAxisLabel>::from_canonical_str("ENV"),
            Some(FigmentNameTagKind::Env),
        );
        // Unrecognized strings — including the trailing-whitespace
        // case and a one-character drift — reject.
        assert_eq!(
            <FigmentNameTagKind as ClosedAxisLabel>::from_canonical_str("env "),
            None,
        );
        assert_eq!(
            <FigmentNameTagKind as ClosedAxisLabel>::from_canonical_str("forma"),
            None,
        );
    }

    #[test]
    fn figment_name_tag_kind_all_attribution_axis_image_is_metadata_name() {
        // Cross-primitive cover law: every kind in FigmentNameTagKind::ALL
        // — when projected back through a witnessing tag's
        // `attribution_axis()` — must lie on AttributionAxis::MetadataName.
        // Pins the structural law `figment_name_tag_attribution_axis_is_always_metadata_name`
        // from the perspective of the kind axis: the figment-name-axis
        // kind partition is a sub-partition of the metadata.name
        // attribution axis. Symmetric peer of
        // `figment_source_kind_all_attribution_axis_image_is_metadata_source`
        // on the figment-Source axis.
        use crate::AttributionAxis;
        use std::collections::HashSet;
        let samples = canonical_figment_name_tag_kind_samples();
        let observed: HashSet<AttributionAxis> = FigmentNameTagKind::ALL
            .iter()
            .copied()
            .map(|kind| {
                let (name, _) = samples
                    .iter()
                    .find(|(name, _)| FigmentNameTag::classify(name).unwrap().kind() == kind)
                    .expect("every kind cell must be witnessed");
                FigmentNameTag::classify(name).unwrap().attribution_axis()
            })
            .collect();
        assert_eq!(
            observed,
            HashSet::from([AttributionAxis::MetadataName]),
            "every FigmentNameTagKind variant projects to AttributionAxis::MetadataName",
        );
    }

    #[test]
    fn figment_name_tag_kind_round_trips_through_figment_env_emission() {
        // End-to-end: classify a real figment::providers::Env-emitted
        // metadata-name through FigmentNameTag, project to kind, and
        // confirm the kind matches FigmentNameTagKind::Env. Pins the
        // cross-side contract that figment's Env emission lands on the
        // Env kind cell.
        use figment::Provider;
        for prefix in ["MYAPP_", "TOBIRA_", "X_"] {
            let env = figment::providers::Env::prefixed(prefix);
            let md = env.metadata();
            let name: &str = md.name.as_ref();
            let tag = FigmentNameTag::classify(name).expect("figment Env name must classify");
            assert_eq!(tag.kind(), FigmentNameTagKind::Env);
        }
    }

    #[test]
    fn figment_name_tag_kind_round_trips_through_format_emission() {
        // End-to-end: every shikumi-built provider variant's emitted
        // metadata-name classifies via FigmentNameTag::Format and
        // projects to FigmentNameTagKind::Format. Pins the cross-side
        // contract that shikumi's own emissions land on the Format
        // kind cell.
        use crate::discovery::Format;
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/etc/app/app.cfg"));
            let tag = FigmentNameTag::classify(&name).expect("format-emitted name classifies");
            assert_eq!(tag.kind(), FigmentNameTagKind::Format);
        }
    }

    // ---- EnvMetadataTagKind / EnvMetadataTag::kind ----
    //
    // The (EnvMetadataTag → EnvMetadataTagKind) lift closes the
    // figment-metadata kind universe on the third sub-axis: the
    // outer figment-Source axis was projected to a `'static`
    // discriminant via FigmentSourceTag::kind → FigmentSourceKind, the
    // outer figment-Name axis via FigmentNameTag::kind →
    // FigmentNameTagKind, and the inner env-name sub-axis (inside
    // FigmentNameTag::Env) now lifts to EnvMetadataTagKind. Tests
    // mirror the FigmentNameTagKind suite pointwise.

    /// Canonical sample table covering every `EnvMetadataTag` variant
    /// once, with the kind each must classify into. Source for the
    /// `env_metadata_tag_kind_all_*` cover/partition tests below — peer
    /// to `canonical_figment_name_tag_kind_samples` on the figment-Name
    /// axis.
    fn canonical_env_metadata_tag_kind_samples() -> Vec<(String, EnvMetadataTagKind)> {
        vec![
            (
                ConfigSource::env_metadata_name("MYAPP_"),
                EnvMetadataTagKind::Prefixed,
            ),
            (
                ConfigSource::env_metadata_name("TOBIRA_"),
                EnvMetadataTagKind::Prefixed,
            ),
            (
                ConfigSource::env_metadata_name(""),
                EnvMetadataTagKind::Bare,
            ),
        ]
    }

    #[test]
    fn env_metadata_tag_kind_classifies_each_variant() {
        // The forward map EnvMetadataTag → EnvMetadataTagKind is
        // exhaustive: every variant pins to exactly one kind. Mirrors
        // `figment_name_tag_kind_classifies_each_variant` on the
        // figment-Name axis.
        let prefixed_name = ConfigSource::env_metadata_name("APP_");
        let prefixed = ConfigSource::strip_env_metadata_name(&prefixed_name)
            .expect("prefixed env metadata classifies");
        assert_eq!(prefixed.kind(), EnvMetadataTagKind::Prefixed);

        let bare_name = ConfigSource::env_metadata_name("");
        let bare = ConfigSource::strip_env_metadata_name(&bare_name)
            .expect("bare env metadata classifies");
        assert_eq!(bare.kind(), EnvMetadataTagKind::Bare);
    }

    #[test]
    fn env_metadata_tag_kind_is_data_free() {
        // Inner data does not influence kind — every Prefixed variant
        // maps to EnvMetadataTagKind::Prefixed regardless of the inner
        // borrowed prefix slice. Mirrors `figment_name_tag_kind_is_data_free`
        // on the figment-Name axis.
        for prefix in ["MYAPP_", "TOBIRA_", "X_", "VERY_LONG_PREFIX_"] {
            let tag = EnvMetadataTag::Prefixed(prefix);
            assert_eq!(tag.kind(), EnvMetadataTagKind::Prefixed);
        }
        // The Bare variant has no inner data; the projection is constant.
        assert_eq!(EnvMetadataTag::Bare.kind(), EnvMetadataTagKind::Bare);
    }

    #[test]
    fn env_metadata_tag_kind_agrees_with_predicates_pointwise() {
        // The kind() projection must agree with the kind-side
        // `is_prefixed` / `is_bare` predicates pointwise on every
        // constructible tag variant. Mirrors
        // `figment_name_tag_kind_agrees_with_as_predicates_pointwise`
        // on the figment-Name axis.
        for (name, _) in canonical_env_metadata_tag_kind_samples() {
            let tag = ConfigSource::strip_env_metadata_name(&name)
                .expect("canonical sample must classify as env metadata");
            assert_eq!(
                tag.kind().is_prefixed(),
                tag.kind() == EnvMetadataTagKind::Prefixed,
            );
            assert_eq!(tag.kind().is_bare(), tag.kind() == EnvMetadataTagKind::Bare,);
        }
    }

    #[test]
    fn env_metadata_tag_kind_is_static_and_copy_and_hashable() {
        // The discriminant is `'static` (no lifetime parameter) so it
        // can cross thread boundaries the borrowed tag cannot. Trait
        // bounds match the sibling typescape primitives
        // (FigmentNameTagKind, FigmentSourceKind, ConfigSourceKind,
        // AttributionRule, AttributionConfidence, AttributionAxis).
        fn assert_static<T: 'static>() {}
        use std::collections::HashSet;
        let mut set: HashSet<EnvMetadataTagKind> =
            EnvMetadataTagKind::ALL.iter().copied().collect();
        set.insert(EnvMetadataTagKind::Prefixed); // duplicate
        assert_eq!(set.len(), EnvMetadataTagKind::ALL.len());

        // Copy: rebind without move.
        let k = EnvMetadataTagKind::Bare;
        let k2 = k;
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k2, k3);

        // 'static — observable by inserting into a static bound.
        assert_static::<EnvMetadataTagKind>();
    }

    #[test]
    fn env_metadata_tag_kind_all_has_no_duplicates() {
        // The constant must be a set — no variant listed twice. Pins
        // the typescape discipline shared with FigmentNameTagKind::ALL,
        // FigmentSourceKind::ALL, and the other closed-enum kind axes.
        use std::collections::HashSet;
        let set: HashSet<EnvMetadataTagKind> = EnvMetadataTagKind::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            EnvMetadataTagKind::ALL.len(),
            "EnvMetadataTagKind::ALL must contain no duplicates; got: {:?}",
            EnvMetadataTagKind::ALL,
        );
    }

    #[test]
    fn env_metadata_tag_kind_all_covers_every_constructible_tag() {
        // Subset cover: every kind produced by EnvMetadataTag::kind
        // over the canonical sample table must lie in
        // EnvMetadataTagKind::ALL. A future tag variant that adds a new
        // kind class must extend EnvMetadataTagKind and its ALL in the
        // same commit; otherwise this test fails.
        use std::collections::HashSet;
        let declared: HashSet<EnvMetadataTagKind> =
            EnvMetadataTagKind::ALL.iter().copied().collect();
        let observed: HashSet<EnvMetadataTagKind> = canonical_env_metadata_tag_kind_samples()
            .iter()
            .map(|(name, _)| {
                ConfigSource::strip_env_metadata_name(name)
                    .expect("canonical sample must classify as env metadata")
                    .kind()
            })
            .collect();
        assert!(
            observed.is_subset(&declared),
            "EnvMetadataTag::kind image must lie in EnvMetadataTagKind::ALL; \
             observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn env_metadata_tag_kind_all_equals_tag_kind_image() {
        // Tight equality (stronger than subset cover): every variant
        // in EnvMetadataTagKind::ALL must be witnessed by at least one
        // tag's kind() — no orphan variant in the declared kind space
        // lacks a producing tag.
        use std::collections::HashSet;
        let declared: HashSet<EnvMetadataTagKind> =
            EnvMetadataTagKind::ALL.iter().copied().collect();
        let observed: HashSet<EnvMetadataTagKind> = canonical_env_metadata_tag_kind_samples()
            .iter()
            .map(|(name, _)| {
                ConfigSource::strip_env_metadata_name(name)
                    .expect("canonical sample must classify as env metadata")
                    .kind()
            })
            .collect();
        assert_eq!(
            observed, declared,
            "EnvMetadataTag::kind image must equal EnvMetadataTagKind::ALL",
        );
    }

    #[test]
    fn env_metadata_tag_kind_all_declaration_order_is_prefixed_bare() {
        // Pin declaration order. Consumers (diagnostics legends,
        // attestation manifests, dashboard column orderings) that
        // iterate ALL get a stable order; reordering the slice is a
        // breaking change that must show up here.
        assert_eq!(
            EnvMetadataTagKind::ALL,
            &[EnvMetadataTagKind::Prefixed, EnvMetadataTagKind::Bare],
        );
    }

    #[test]
    fn env_metadata_tag_kind_all_partition_is_prefixed_xor_bare() {
        // Boolean partition: `is_prefixed` / `is_bare` over a tag
        // sliced by each kind cell must agree with the cell's identity.
        let samples = canonical_env_metadata_tag_kind_samples();
        for kind in EnvMetadataTagKind::ALL.iter().copied() {
            let witnessing_name = samples
                .iter()
                .find(|(name, _)| {
                    ConfigSource::strip_env_metadata_name(name)
                        .expect("sample must classify")
                        .kind()
                        == kind
                })
                .map(|(name, _)| name)
                .expect("every kind cell must be witnessed by some tag");
            let tag = ConfigSource::strip_env_metadata_name(witnessing_name)
                .expect("witness must classify");
            match kind {
                EnvMetadataTagKind::Prefixed => {
                    assert!(tag.kind().is_prefixed());
                    assert!(!tag.kind().is_bare());
                }
                EnvMetadataTagKind::Bare => {
                    assert!(tag.kind().is_bare());
                    assert!(!tag.kind().is_prefixed());
                }
            }
        }
    }

    #[test]
    fn env_metadata_tag_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on EnvMetadataTagKind::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Prefixed", prefixing "env-prefixed")
        // fails here before drifting through the trait-uniform
        // round-trip law and the operator-facing rendering surface.
        assert_eq!(EnvMetadataTagKind::Prefixed.as_str(), "prefixed");
        assert_eq!(EnvMetadataTagKind::Bare.as_str(), "bare");
    }

    #[test]
    fn env_metadata_tag_kind_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // EnvMetadataTagKind: each canonical lowercase name parses
        // back to its variant via the ClosedAxisLabel default impl.
        // Mixed-case forms an operator might type round-trip
        // case-insensitively.
        use crate::ClosedAxisLabel;
        for k in EnvMetadataTagKind::ALL.iter().copied() {
            assert_eq!(
                <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str(k.as_str()),
                Some(k),
                "trait from_canonical_str must round-trip for {k:?}",
            );
        }
        assert_eq!(
            <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str("Prefixed"),
            Some(EnvMetadataTagKind::Prefixed),
        );
        assert_eq!(
            <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str("BARE"),
            Some(EnvMetadataTagKind::Bare),
        );
        // Unrecognized strings — including a trailing-whitespace case
        // and a one-character drift — reject.
        assert_eq!(
            <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str("bare "),
            None,
        );
        assert_eq!(
            <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str("prefixe"),
            None,
        );
        assert_eq!(
            <EnvMetadataTagKind as ClosedAxisLabel>::from_canonical_str(""),
            None,
        );
    }

    #[test]
    fn env_metadata_tag_kind_pairs_with_figment_name_tag_kind_env() {
        // Cross-primitive bridge: when a FigmentNameTag is the Env
        // variant, the inner EnvMetadataTag's kind classifies the
        // env sub-shape. Pins the structural law that the
        // (FigmentNameTagKind::Env → EnvMetadataTagKind) refinement
        // path covers every env-shaped metadata-name observation.
        for (name, expected_env_kind) in canonical_env_metadata_tag_kind_samples() {
            let outer = FigmentNameTag::classify(&name)
                .expect("canonical env metadata classifies via FigmentNameTag");
            assert_eq!(outer.kind(), FigmentNameTagKind::Env);
            let inner = outer
                .as_env()
                .expect("Env variant must expose inner EnvMetadataTag");
            assert_eq!(inner.kind(), expected_env_kind);
        }
    }

    #[test]
    fn env_metadata_tag_kind_round_trips_through_figment_env_emission() {
        // End-to-end: classify a real figment::providers::Env-emitted
        // metadata-name through EnvMetadataTag::kind, and confirm the
        // kind matches EnvMetadataTagKind::Prefixed for prefixed
        // emissions. Pins the cross-side contract that figment's
        // prefixed Env emission lands on the Prefixed kind cell.
        use figment::Provider;
        for prefix in ["MYAPP_", "TOBIRA_", "X_"] {
            let env = figment::providers::Env::prefixed(prefix);
            let md = env.metadata();
            let name: &str = md.name.as_ref();
            let tag = ConfigSource::strip_env_metadata_name(name)
                .expect("figment prefixed Env name must classify as env metadata");
            assert_eq!(tag.kind(), EnvMetadataTagKind::Prefixed);
        }
    }
}

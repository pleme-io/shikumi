use std::path::PathBuf;

use crate::source::{
    ConfigSource, ConfigSourceKind, EnvMetadataTag, FigmentNameTag, FigmentSourceKind,
    FigmentSourceTag,
};

/// Errors produced by shikumi's config discovery, loading, and watching.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ShikumiError {
    /// No config file was found at any of the searched locations.
    #[error("config file not found; tried: {}", tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    NotFound { tried: Vec<PathBuf> },

    /// The config file could not be parsed.
    #[error("config parse error: {0}")]
    Parse(String),

    /// The file watcher encountered an error.
    #[error("file watch error: {0}")]
    Watch(#[from] notify::Error),

    /// An I/O error occurred during config file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Figment extraction or merge failed without source attribution.
    ///
    /// Produced by direct `From<Box<figment::Error>>` conversions — e.g.
    /// when a consumer hands a raw figment error to shikumi. Boxed to keep
    /// `ShikumiError` small (`figment::Error` is ~208 bytes).
    ///
    /// New code should prefer [`ShikumiError::Extract`], which carries the
    /// [`ConfigSource`] chain that produced the failure.
    #[error("figment error: {0}")]
    Figment(#[from] Box<figment::Error>),

    /// Configuration extraction through a [`crate::ProviderChain`] failed.
    ///
    /// Carries the typed [`ConfigSource`] chain in merge order (lowest
    /// priority first) so the failure can be traced back to the layers
    /// that produced it without grepping logs or re-walking discovery.
    /// The dotted field path of the offending key (when figment can
    /// localize it) and — when figment's per-value `Metadata` can be
    /// matched against an entry in the recorded chain — the specific
    /// failing source layer are also embedded in the rendered display.
    #[error(
        "config extraction failed [layers: {}]{}{}: {error}",
        display_sources(sources),
        display_failing_source(sources, error),
        display_field_path(&error.path)
    )]
    Extract {
        /// The provider chain in merge order at the moment of failure.
        sources: Vec<ConfigSource>,
        /// Boxed underlying figment error (kept small; `figment::Error` is ~208 bytes).
        #[source]
        error: Box<figment::Error>,
    },
}

fn display_sources(sources: &[ConfigSource]) -> String {
    if sources.is_empty() {
        "<empty>".to_owned()
    } else {
        sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

fn display_field_path(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" at field `{}`", path.join("."))
    }
}

fn display_failing_source(sources: &[ConfigSource], error: &figment::Error) -> String {
    resolve_failing_source(error, sources)
        .map(|a| format!(" from {}", a.source))
        .unwrap_or_default()
}

/// Closed partition over the [`ShikumiError`] variant space.
///
/// Data-free discriminant of [`ShikumiError`]: every error classifies
/// into exactly one variant of [`ShikumiErrorKind`], recoverable from
/// any error via [`ShikumiError::kind`]. The closed enum lifts the
/// kind axis off the data-bearing sum type so consumers route on
/// kind without destructuring data they don't need — peer typed
/// projection to [`AttributionConfidence`] (closed binary partition
/// over [`AttributionRule`]) on the attribution surface.
///
/// Before this enum, the existing predicates [`ShikumiError::is_not_found`]
/// and [`ShikumiError::is_parse`] covered two of the six variants;
/// observers wanting the other four had to re-derive an `is_*`
/// predicate or `matches!` against the variant inline. With
/// [`ShikumiError::kind`] the partition is one method call, returning
/// a closed-enum value usable in `match`, `HashMap` keys, log labels,
/// or alerting buckets without the consumer touching the
/// data-bearing variants.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, matching the typescape
/// discipline of the sibling closed-enum primitives
/// ([`AttributionRule`], [`AttributionConfidence`],
/// [`FigmentSourceTag`], [`crate::FigmentNameTag`],
/// [`EnvMetadataTag`]): closed, allocation-free, extensible without
/// breaking exhaustivity at consumer matches when a future
/// [`ShikumiError`] variant lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ShikumiErrorKind {
    /// [`ShikumiError::NotFound`] — discovery exhausted every searched
    /// location without finding a config file.
    NotFound,
    /// [`ShikumiError::Parse`] — a parser (format detection,
    /// shikumi-built provider, downstream deserializer) reported a
    /// shape error with prose context but no figment metadata.
    Parse,
    /// [`ShikumiError::Watch`] — the file watcher (`notify` crate)
    /// reported an error setting up or processing watch events.
    Watch,
    /// [`ShikumiError::Io`] — a [`std::io::Error`] surfaced from a
    /// config-file operation.
    Io,
    /// [`ShikumiError::Figment`] — a raw [`figment::Error`] reached
    /// shikumi without an attached [`ConfigSource`] chain (the
    /// pre-[`ShikumiError::Extract`] code path; see the variant doc).
    Figment,
    /// [`ShikumiError::Extract`] — a [`crate::ProviderChain`]
    /// extraction failed; the recorded [`ConfigSource`] chain and the
    /// boxed underlying [`figment::Error`] are both available for
    /// attribution via [`ShikumiError::failing_attribution`].
    Extract,
}

impl ShikumiErrorKind {
    /// Every [`ShikumiErrorKind`] variant, in the same declaration order
    /// as the [`ShikumiError`] arms in [`ShikumiError::kind`].
    ///
    /// The closed list of kinds shikumi recognizes. Iterate to enumerate
    /// the kind space without listing variants by hand at every consumer
    /// site — e.g. dashboards initializing per-kind alert thresholds,
    /// attestation manifests recording the rule space's cardinality,
    /// tests that must round-trip every kind, partition tests asserting
    /// disjointness over the whole universe.
    ///
    /// One source of truth for the kind enumeration on the
    /// [`ShikumiErrorKind`] axis: peer to [`crate::Format::ALL`] on the
    /// [`crate::Format`] axis, the same typescape discipline applied
    /// across the closed-enum primitive set. Before this constant, the
    /// kind enumeration was inlined as a `[NotFound, Parse, Watch, Io,
    /// Figment, Extract]` array literal at every site that needed to
    /// iterate (the `kind_partitions_every_variant` and
    /// `is_figment_bearing_partitions_every_kind` tests in
    /// [`error::tests`]); each duplicated literal had to be manually
    /// kept in lockstep with the enum's variant set.
    ///
    /// Adding a new variant to [`ShikumiErrorKind`] means extending this
    /// slice in lockstep with the variant itself. The compiler enforces
    /// nothing here directly, so the
    /// `shikumi_error_kind_all_covers_every_constructed_variant` test
    /// pins the contract by asserting that every kind produced by
    /// [`ShikumiError::kind`] over the construction-table surface
    /// (`error::tests::one_per_kind`) appears in [`Self::ALL`], and the
    /// `shikumi_error_kind_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant). Together they
    /// pin the constant to the variant space the typescape recognizes.
    pub const ALL: &'static [Self] = &[
        Self::NotFound,
        Self::Parse,
        Self::Watch,
        Self::Io,
        Self::Figment,
        Self::Extract,
    ];

    /// Returns `true` if this kind wraps a [`figment::Error`] —
    /// [`Self::Extract`] (with a recorded [`ConfigSource`] chain) and
    /// [`Self::Figment`] (without). The figment-bearing variants are
    /// the only ones whose [`ShikumiError::field_path`] can possibly
    /// localize the offending field, because the figment error is
    /// where the dotted key lives.
    ///
    /// One source of truth for the (kind → wraps-figment) projection
    /// over the kind partition. Before this method, the partition
    /// was implicit in two sites — the `match` in
    /// [`ShikumiError::field_path`] (figment-bearing variants → `Some`,
    /// others → `None`) and the prose in
    /// [`crate::ReloadFailure::field_path`]'s doc — and required
    /// observers wanting to distinguish "figment couldn't localize"
    /// from "this kind doesn't carry figment at all" to re-derive the
    /// classification by `matches!` against two specific variants.
    /// Now it composes as one method call: `kind.is_figment_bearing()`.
    ///
    /// Composes with [`crate::FieldPathLocalization`]: the typed
    /// tri-state field-localization partition over the captured-failure
    /// surface uses this predicate to tell apart its
    /// [`crate::FieldPathLocalization::FigmentUnlocalized`] (figment
    /// bearing, but no localized field) and
    /// [`crate::FieldPathLocalization::NotApplicable`] (kind doesn't
    /// carry figment) variants. A future kind landing forces a
    /// classification in the exhaustive match below; the partition
    /// stays coherent by construction.
    #[must_use]
    pub fn is_figment_bearing(self) -> bool {
        match self {
            Self::Extract | Self::Figment => true,
            Self::NotFound | Self::Parse | Self::Watch | Self::Io => false,
        }
    }

    /// Canonical operator-facing lowercase name of the error kind —
    /// [`Self::NotFound`] renders as `"not-found"`, [`Self::Parse`] as
    /// `"parse"`, [`Self::Watch`] as `"watch"`, [`Self::Io`] as
    /// `"io"`, [`Self::Figment`] as `"figment"`, [`Self::Extract`] as
    /// `"extract"`.
    ///
    /// Single source of truth for the six canonical strings that
    /// previously had no typed accessor — the kind axis carried the
    /// variant identifier (a structural tag) but no operator-facing
    /// label, so a future structured-log field naming the surfaced
    /// kind, a CLI flag filtering captured failures by kind
    /// (`--filter-kind=parse`), a miette structured-diagnostic legend
    /// keying per-kind severity, an alerting bucket histogramming the
    /// kind partition over the captured-failure surface, an
    /// attestation manifest recording the kind histogram, or a
    /// dashboard cell rendering the `(kind × localization)` cube
    /// ([`ErrorLocalizationCoordinates`]) keyed by canonical labels
    /// on every axis would each have re-derived the string mapping
    /// inline at the consumer site with no structural guarantee of
    /// agreement.
    ///
    /// Kebab-case for the compound-noun variant [`Self::NotFound`]
    /// (`"not-found"`) — the same convention shared with
    /// [`crate::FormatProvenance::as_str`] (`"figment-builtin"` /
    /// `"shikumi-built"`) and [`crate::AttributionAxis::as_str`]
    /// (`"metadata-source"` / `"metadata-name"`): compound-noun
    /// variant identifiers route the punctuation at the type level
    /// (operator-facing string) rather than at the call site. The
    /// remaining five single-word variants render as their lowercase
    /// identifier ([`Self::Parse`] → `"parse"`, [`Self::Watch`] →
    /// `"watch"`, [`Self::Io`] → `"io"`, [`Self::Figment`] →
    /// `"figment"`, [`Self::Extract`] → `"extract"`), matching the
    /// single-word lowercase convention shared with
    /// [`crate::ConfigSourceKind::as_str`] (`"defaults"` / `"env"` /
    /// `"file"`), [`crate::FigmentSourceKind::as_str`] (`"file"` /
    /// `"code"` / `"custom"`), [`crate::Format::as_str`] (`"yaml"` /
    /// `"toml"` / `"lisp"` / `"nix"`), and
    /// [`AttributionConfidence::as_str`] (`"exact"` / `"fallback"`).
    /// The bare `"io"` (rather than `"i-o"` or `"input-output"`) is
    /// the canonical Rust-ecosystem rendering shared with
    /// [`std::io`] and the [`std::io::Error`] this kind wraps.
    ///
    /// `&'static str` so the label is allocation-free at every call
    /// site; `const fn` so the labels are usable in const contexts
    /// (static slice initializers, match arms over a const cube).
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned
    /// for every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `shikumi_error_kind_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"NotFound"`, switching `"figment"` to
    /// `"raw-figment"`, dropping the `"not-"` prefix on
    /// [`Self::NotFound`]) fails at that site before drifting through
    /// the round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::Parse => "parse",
            Self::Watch => "watch",
            Self::Io => "io",
            Self::Figment => "figment",
            Self::Extract => "extract",
        }
    }
}

/// Closed tri-state partition over the field-path-localization axis of
/// a [`ShikumiError`] / [`crate::ReloadFailure`].
///
/// Surfaces the tri-state distinction
/// [`ShikumiError::field_path`] preserves but
/// [`crate::ReloadFailure::field_path`] (a plain `Vec<String>`)
/// collapses: an empty `Vec` on the cross-thread observable form means
/// either "figment couldn't localize the offending field" *or* "this
/// error variant doesn't carry figment context at all", and observers
/// previously had to consult [`Self::kind`] (via
/// [`ShikumiErrorKind::is_figment_bearing`]) and the `Vec` emptiness
/// together to recover the original tri-state.
///
/// One source of truth for the field-localization axis: consumers
/// route on the closed enum (in `match`, `HashMap` keys, log labels,
/// alerting buckets) instead of re-deriving the tri-state at every
/// observation site. Peer typed projection to [`ShikumiErrorKind`]
/// (closed partition over the variant axis), [`AttributionRule`]
/// (closed partition over the why-axis), and [`AttributionConfidence`]
/// (closed partition over the confidence axis) — same typescape
/// discipline (closed, allocation-free, exhaustive-match,
/// `#[non_exhaustive]`).
///
/// Pairs with [`ShikumiError::field_path`] for the segments themselves
/// (when [`Self::Localized`]); the localization axis answers
/// "*was* the failure localized?" while the field-path slot answers
/// "*where* was it localized?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FieldPathLocalization {
    /// Figment localized the offending field at a non-empty dotted
    /// path, recoverable as segments via
    /// [`ShikumiError::field_path`] /
    /// [`crate::ReloadFailure::field_path`]. The error is
    /// figment-bearing
    /// ([`ShikumiErrorKind::is_figment_bearing`] returns `true`),
    /// and the wrapped [`figment::Error::path`] has at least one
    /// segment.
    Localized,
    /// The error is figment-bearing
    /// ([`ShikumiErrorKind::is_figment_bearing`] returns `true`),
    /// but figment did not attach a non-empty dotted path —
    /// typically a top-level type mismatch, a deserializer error
    /// reported without a key context, or a manually constructed
    /// `figment::Error` lacking metadata.
    FigmentUnlocalized,
    /// The error variant does not wrap a [`figment::Error`] at all —
    /// [`ShikumiError::NotFound`], [`ShikumiError::Parse`],
    /// [`ShikumiError::Watch`], [`ShikumiError::Io`]
    /// ([`ShikumiErrorKind::is_figment_bearing`] returns `false`).
    /// The notion of a per-key field path does not apply to these
    /// variants; observers should not interpret an empty
    /// [`crate::ReloadFailure::field_path`] alongside one of these
    /// kinds as a localization failure.
    NotApplicable,
}

impl FieldPathLocalization {
    /// Every recognized localization cell, in declaration order
    /// ([`Self::Localized`], [`Self::FigmentUnlocalized`],
    /// [`Self::NotApplicable`]).
    ///
    /// One source of truth for the localization-axis universe. Peer
    /// to [`ShikumiErrorKind::ALL`] on the kind axis,
    /// [`AttributionRule::ALL`] on the rule axis, and
    /// [`crate::ConfigSourceKind::ALL`] on the layer-kind axis: the
    /// same typescape discipline (closed `'static` slice, in
    /// declaration order) applied to the localization axis.
    /// Consumers iterating "every recognized localization" (per-cell
    /// alert thresholds, dashboards, attestation manifests recording
    /// the localization space's cardinality, structured-diagnostics
    /// legends, partition-coverage tests) read this constant instead
    /// of hard-coding the variant list, which would have to be kept
    /// manually in lockstep with the enum's variant set.
    ///
    /// Adding a new variant to [`FieldPathLocalization`] means
    /// extending this slice in lockstep with the variant itself. The
    /// compiler enforces nothing here directly, so the
    /// `field_path_localization_all_covers_every_constructed_localization`
    /// test pins the contract by asserting that every value produced
    /// by [`ShikumiError::field_path_localization`] over the
    /// canonical-cell surface appears in [`Self::ALL`], and the
    /// `field_path_localization_all_has_no_duplicates` test pins
    /// that the constant is a set (no double-listed variant).
    /// Together they pin the constant to the variant space the
    /// typescape recognizes.
    pub const ALL: &'static [Self] = &[
        Self::Localized,
        Self::FigmentUnlocalized,
        Self::NotApplicable,
    ];

    /// Canonical operator-facing lowercase name of the localization cell —
    /// [`Self::Localized`] renders as `"localized"`,
    /// [`Self::FigmentUnlocalized`] renders as `"figment-unlocalized"`,
    /// [`Self::NotApplicable`] renders as `"not-applicable"`.
    ///
    /// Single source of truth for the three canonical strings on the
    /// field-localization axis. Before this lift the cells carried only
    /// their variant identifier (a structural tag, not an
    /// operator-facing label), so a future structured-log field naming
    /// the surfaced localization, a CLI flag filtering captured failures
    /// by localization (`--filter-localization=figment-unlocalized`),
    /// a miette structured-diagnostic legend keying per-cell severity, an
    /// alerting bucket histogramming the localization partition over the
    /// captured-failure surface, an attestation manifest recording the
    /// localization histogram, or a dashboard cell rendering the
    /// `(kind × localization)` cube ([`ErrorLocalizationCoordinates`])
    /// keyed by canonical labels on every axis would each have
    /// re-derived the string mapping inline at the consumer site with
    /// no structural guarantee of agreement.
    ///
    /// Kebab-case for the two compound-noun variants
    /// ([`Self::FigmentUnlocalized`] → `"figment-unlocalized"`,
    /// [`Self::NotApplicable`] → `"not-applicable"`) — the same
    /// convention shared with [`ShikumiErrorKind::as_str`]
    /// (`"not-found"`), [`crate::FormatProvenance::as_str`]
    /// (`"figment-builtin"` / `"shikumi-built"`), and
    /// [`crate::AttributionAxis::as_str`] (`"metadata-source"` /
    /// `"metadata-name"`): compound-noun variant identifiers route the
    /// punctuation at the type level (operator-facing string) rather
    /// than at the call site. The remaining single-word variant
    /// ([`Self::Localized`] → `"localized"`) renders as its lowercase
    /// identifier, matching the single-word lowercase convention shared
    /// with [`crate::ConfigSourceKind::as_str`] (`"defaults"` / `"env"`
    /// / `"file"`), [`crate::FigmentSourceKind::as_str`] (`"file"` /
    /// `"code"` / `"custom"`), [`crate::Format::as_str`] (`"yaml"` /
    /// `"toml"` / `"lisp"` / `"nix"`), and
    /// [`AttributionConfidence::as_str`] (`"exact"` / `"fallback"`).
    ///
    /// `&'static str` so the label is allocation-free at every call
    /// site; `const fn` so the labels are usable in const contexts
    /// (static slice initializers, match arms over a const cube).
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned
    /// for every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `field_path_localization_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"Localized"`, switching `"not-applicable"`
    /// to `"n-a"`, collapsing `"figment-unlocalized"` to
    /// `"figmentunlocalized"`) fails at that site before drifting
    /// through the trait-uniform round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Localized => "localized",
            Self::FigmentUnlocalized => "figment-unlocalized",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// Reason a [`figment::Error`] was attributed to a specific layer in the
/// recorded [`ConfigSource`] chain by [`resolve_failing_source`].
///
/// The resolver dispatches over five distinct rules, applied in order;
/// the first that matches produces the attribution. Before this enum,
/// the resolver returned just `Option<&ConfigSource>`, collapsing the
/// rule that fired into its result.
///
/// Lifting the rule into the type lets observers distinguish *exact*
/// attribution (path / prefix equality) from *fallback* attribution
/// (uniqueness in the chain) — a partition formalized by
/// [`AttributionConfidence`] and recoverable from any rule via
/// [`Self::confidence`]. The distinction matters for:
///
/// - Structured diagnostics that want to render different prose for
///   "blamed via file path equality" vs. "blamed via env-prefix
///   uniqueness fallback".
/// - Attestation manifests that record per-failure attribution
///   provenance alongside the chain.
/// - Tests that pin exactly which rule a scenario exercises (rather
///   than checking only that *some* layer was attributed).
///
/// Variants are `#[non_exhaustive]` so future resolution rules — e.g.
/// custom-source attribution for [`FigmentSourceTag::Custom`] when a
/// matching `ConfigSource::External(_)` lands — extend the enum without
/// breaking exhaustivity at consumer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionRule {
    /// `metadata.source` classified as [`FigmentSourceTag::File`];
    /// matched by exact path equality against a [`ConfigSource::File`]
    /// entry. The shape figment's built-in YAML/TOML providers attach.
    FileBySource,
    /// `metadata.name` matched a shikumi-built provider's
    /// `"<format>: <path>"` shape (per [`Format::strip_metadata_name`]);
    /// matched by extracted path equality against a
    /// [`ConfigSource::File`] entry. The shape [`crate::NixProvider`]
    /// (and [`crate::LispProvider`] when the `lisp` feature is on) attach.
    FileByMetadataName,
    /// `metadata.name` was env-tag shaped with a prefix (per
    /// [`ConfigSource::strip_env_metadata_name`] returning
    /// [`EnvMetadataTag::Prefixed`]); matched by case-insensitive
    /// prefix equality against a [`ConfigSource::Env`] entry. The
    /// shape `figment::providers::Env::prefixed(_)` attaches.
    EnvByPrefix,
    /// `metadata.name` was env-tag shaped (prefixed-without-match or
    /// bare); no prefix equality match in the chain, but exactly one
    /// [`ConfigSource::Env`] is recorded — attributed to that unique
    /// entry as a fallback.
    EnvByUniqueness,
    /// `metadata.source` classified as [`FigmentSourceTag::Code`] (the
    /// shape [`figment::providers::Serialized`] attaches, behind
    /// [`crate::ProviderChain::with_defaults`]), and exactly one
    /// [`ConfigSource::Defaults`] is recorded in the chain.
    DefaultsByCodeUniqueness,
}

impl AttributionRule {
    /// Every [`AttributionRule`] variant, in declaration order
    /// ([`Self::FileBySource`], [`Self::FileByMetadataName`],
    /// [`Self::EnvByPrefix`], [`Self::EnvByUniqueness`],
    /// [`Self::DefaultsByCodeUniqueness`]).
    ///
    /// The closed list of resolution rules shikumi recognizes. Iterate
    /// to enumerate the rule space without listing variants by hand at
    /// every consumer site — e.g. dashboards initializing per-rule
    /// counters, attestation manifests recording the rule space's
    /// cardinality, tests asserting partition totality across every
    /// orthogonal axis ([`Self::confidence`], [`Self::layer_kind`],
    /// [`Self::metadata_axis`]).
    ///
    /// One source of truth for the rule enumeration on the
    /// [`AttributionRule`] axis: peer to [`crate::Format::ALL`] on the
    /// [`crate::Format`] axis and [`ShikumiErrorKind::ALL`] on the kind
    /// axis, the same typescape discipline applied across the
    /// closed-enum primitive set. Before this constant, the rule
    /// enumeration was inlined as a `[FileBySource, FileByMetadataName,
    /// EnvByPrefix, EnvByUniqueness, DefaultsByCodeUniqueness]` array
    /// literal at every site that needed to iterate (every total-axis
    /// partition test in [`error::tests`]); each duplicated literal had
    /// to be manually kept in lockstep with the enum's variant set.
    ///
    /// Adding a new variant to [`Self`] means extending this slice in
    /// lockstep with the variant itself. The compiler enforces nothing
    /// here directly, so the
    /// `attribution_rule_all_covers_every_recognized_variant` test pins
    /// the contract by asserting that every rule produced by the
    /// canonical `rule_coordinate_table()` (the construction-table
    /// surface) appears in [`Self::ALL`], and the
    /// `attribution_rule_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant). Together they pin
    /// the constant to the variant space the typescape recognizes.
    pub const ALL: &'static [Self] = &[
        Self::FileBySource,
        Self::FileByMetadataName,
        Self::EnvByPrefix,
        Self::EnvByUniqueness,
        Self::DefaultsByCodeUniqueness,
    ];

    /// Canonical operator-facing lowercase name of the attribution rule —
    /// [`Self::FileBySource`] renders as `"file-by-source"`,
    /// [`Self::FileByMetadataName`] as `"file-by-metadata-name"`,
    /// [`Self::EnvByPrefix`] as `"env-by-prefix"`,
    /// [`Self::EnvByUniqueness`] as `"env-by-uniqueness"`,
    /// [`Self::DefaultsByCodeUniqueness`] as
    /// `"defaults-by-code-uniqueness"`.
    ///
    /// Single source of truth for the five canonical strings that
    /// previously had no typed accessor — the rule axis carried the
    /// variant identifier (a structural tag) but no operator-facing
    /// label, so a future structured-log field naming the surfaced
    /// rule, a CLI flag filtering captured failures by rule
    /// (`--filter-rule=env-by-prefix`), a miette structured-diagnostic
    /// legend keying per-rule provenance, an alerting bucket
    /// histogramming the rule partition over the captured-failure
    /// surface, an attestation manifest recording the rule histogram, or
    /// a dashboard cell rendering the
    /// `(metadata-axis × layer-kind × confidence)` cube
    /// ([`AttributionCoordinates`]) or the
    /// `(figment-source × layer-kind)` cube
    /// ([`AttributionSourceKindCoordinates`]) keyed by canonical
    /// labels on every axis would each have re-derived the string
    /// mapping inline at the consumer site with no structural
    /// guarantee of agreement.
    ///
    /// Kebab-case for every variant — all five are compound-noun
    /// identifiers (`<source-axis>-by-<dispatch>`); the type-name
    /// segmentation `<X>By<Y>` routes the punctuation at the type level
    /// (operator-facing string) rather than at the call site. Compound
    /// kebab convention shared with [`ShikumiErrorKind::as_str`]
    /// (`"not-found"`), [`FieldPathLocalization::as_str`]
    /// (`"figment-unlocalized"` / `"not-applicable"`),
    /// [`crate::FormatProvenance::as_str`] (`"figment-builtin"` /
    /// `"shikumi-built"`), and [`crate::AttributionAxis::as_str`]
    /// (`"metadata-source"` / `"metadata-name"`). The kebab segments
    /// align with the rule's typed projections: the leading segment
    /// names the [`ConfigSourceKind`] the rule attributes to via
    /// [`Self::layer_kind`] (`file` / `env` / `defaults`), and the
    /// trailing segments name the dispatch shape the resolver consulted
    /// (`source` for `metadata.source` typed classification,
    /// `metadata-name` / `prefix` / `uniqueness` / `code-uniqueness`
    /// for the name-axis dispatches).
    ///
    /// `&'static str` so the label is allocation-free at every call
    /// site; `const fn` so the labels are usable in const contexts
    /// (static slice initializers, match arms over a const cube).
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned
    /// for every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `attribution_rule_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. dropping the `-by-` infix on `EnvByPrefix` to
    /// `"env-prefix"`, collapsing `"defaults-by-code-uniqueness"` to
    /// `"defaults"`, capitalizing the type-segment names) fails at
    /// that site before drifting through the trait-uniform round-trip
    /// law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileBySource => "file-by-source",
            Self::FileByMetadataName => "file-by-metadata-name",
            Self::EnvByPrefix => "env-by-prefix",
            Self::EnvByUniqueness => "env-by-uniqueness",
            Self::DefaultsByCodeUniqueness => "defaults-by-code-uniqueness",
        }
    }

    /// Confidence class of this rule: [`AttributionConfidence::Exact`]
    /// for equality-based attributions ([`Self::FileBySource`],
    /// [`Self::FileByMetadataName`], [`Self::EnvByPrefix`]), or
    /// [`AttributionConfidence::Fallback`] for uniqueness-based
    /// attributions ([`Self::EnvByUniqueness`],
    /// [`Self::DefaultsByCodeUniqueness`]).
    ///
    /// One source of truth for the exact-vs-fallback partition over
    /// the rule space. Before this method, the partition was
    /// re-stated in prose at three doc sites
    /// ([`Self`], [`ShikumiError::failing_attribution`],
    /// [`crate::ReloadFailure::attribution_rule`]) and re-derived
    /// inline by every observer that wanted to weight fallback
    /// attributions weaker than equality-based ones (dashboards,
    /// alerting policies, miette diagnostic renderers). Now it
    /// composes as one method call: `rule.confidence()`.
    ///
    /// When a new resolution rule lands as a [`Self`] variant, the
    /// exhaustive match below forces a confidence assignment in
    /// lockstep — the typescape pins the partition to one site, and
    /// the `attribution_rule_confidence_*` tests pin which side each
    /// rule sits on.
    #[must_use]
    pub fn confidence(self) -> AttributionConfidence {
        match self {
            Self::FileBySource | Self::FileByMetadataName | Self::EnvByPrefix => {
                AttributionConfidence::Exact
            }
            Self::EnvByUniqueness | Self::DefaultsByCodeUniqueness => {
                AttributionConfidence::Fallback
            }
        }
    }

    /// Returns `true` if this rule is equality-based; equivalent to
    /// `self.confidence() == AttributionConfidence::Exact`.
    #[must_use]
    pub fn is_exact(self) -> bool {
        matches!(self.confidence(), AttributionConfidence::Exact)
    }

    /// Returns `true` if this rule is uniqueness-based; equivalent to
    /// `self.confidence() == AttributionConfidence::Fallback`.
    #[must_use]
    pub fn is_fallback(self) -> bool {
        matches!(self.confidence(), AttributionConfidence::Fallback)
    }

    /// [`ConfigSourceKind`] of the layer this rule attributes to:
    /// [`ConfigSourceKind::File`] for the file-axis rules
    /// ([`Self::FileBySource`], [`Self::FileByMetadataName`]),
    /// [`ConfigSourceKind::Env`] for the env-axis rules
    /// ([`Self::EnvByPrefix`], [`Self::EnvByUniqueness`]),
    /// [`ConfigSourceKind::Defaults`] for the defaults-axis rule
    /// ([`Self::DefaultsByCodeUniqueness`]).
    ///
    /// One source of truth for the (rule → layer-kind) projection. The
    /// information was previously implicit in each rule's name prefix
    /// (`File*`, `Env*`, `Defaults*`); lifting it to a typed accessor
    /// pins the "this rule attributes to layer kind X" contract at the
    /// type level. A future variant added to [`Self`] forces a
    /// kind assignment in the exhaustive match in lockstep.
    ///
    /// Closes the (rule × layer-kind) attribution invariant: for every
    /// [`FailingSourceAttribution`] the resolver produces,
    /// `attr.rule.layer_kind() == attr.source.kind()`. The contract is
    /// pinned by `attribution_rule_layer_kind_agrees_with_source_kind`
    /// — a structural law that any new resolver path must respect, and
    /// which observers can rely on without re-deriving the rule-name →
    /// kind mapping at every call site.
    ///
    /// Composes with [`Self::confidence`]: the two accessors are
    /// orthogonal projections over the rule space — `confidence` along
    /// the (exact × fallback) axis, `layer_kind` along the
    /// (file × env × defaults) axis. Together they pin a recognized
    /// rule's coordinates without consumers destructuring specific
    /// variants.
    #[must_use]
    pub fn layer_kind(self) -> ConfigSourceKind {
        match self {
            Self::FileBySource | Self::FileByMetadataName => ConfigSourceKind::File,
            Self::EnvByPrefix | Self::EnvByUniqueness => ConfigSourceKind::Env,
            Self::DefaultsByCodeUniqueness => ConfigSourceKind::Defaults,
        }
    }

    /// [`AttributionAxis`] of this rule: which `figment::Metadata` field
    /// the resolver consulted to dispatch the attribution.
    /// [`AttributionAxis::MetadataSource`] for rules driven by figment's
    /// typed source classification ([`FigmentSourceTag::classify`]):
    /// [`Self::FileBySource`] (`Source::File`),
    /// [`Self::DefaultsByCodeUniqueness`] (`Source::Code`).
    /// [`AttributionAxis::MetadataName`] for rules driven by parsing
    /// figment's human-readable name string:
    /// [`Self::FileByMetadataName`] (`"<format>: <path>"`),
    /// [`Self::EnvByPrefix`] (`` `PREFIX` environment variable(s) ``),
    /// [`Self::EnvByUniqueness`] (env-shaped name without prefix match).
    ///
    /// One source of truth for the (rule → metadata-axis) projection.
    /// The information was previously implicit in each rule's name
    /// suffix (`*BySource`, `*ByMetadataName`, `*ByPrefix`,
    /// `*ByCodeUniqueness`) and in the resolver's branching shape;
    /// lifting it to a typed accessor pins "this rule consulted
    /// figment metadata field X" at the type level. A future variant
    /// added to [`Self`] forces an axis assignment in the exhaustive
    /// match in lockstep.
    ///
    /// Operational distinction: `metadata.source` is figment's typed
    /// source classification (structural — it survives provider-name
    /// changes upstream), while `metadata.name` is a human-readable
    /// provider name parsed by string-matching (brittle — depends on
    /// the upstream provider continuing to emit a name shape we
    /// recognize via [`Format::strip_metadata_name`] /
    /// [`ConfigSource::strip_env_metadata_name`]). Diagnostics,
    /// dashboards, and attestation manifests that record attribution
    /// provenance can weight name-axis attributions visibly weaker
    /// than source-axis ones; consumers route on the closed enum
    /// instead of inspecting the rule's name.
    ///
    /// Composes orthogonally with [`Self::confidence`] (exact × fallback)
    /// and [`Self::layer_kind`] (file × env × defaults): the three
    /// projections are independent axes over the rule space, and
    /// together place a recognized rule at coordinates
    /// (axis × confidence × layer-kind) without consumers destructuring
    /// specific variants. The
    /// `attribution_rule_metadata_axis_orthogonal_to_confidence` and
    /// `attribution_rule_metadata_axis_orthogonal_to_layer_kind`
    /// tests pin both orthogonality contracts.
    #[must_use]
    pub fn metadata_axis(self) -> AttributionAxis {
        match self {
            Self::FileBySource | Self::DefaultsByCodeUniqueness => AttributionAxis::MetadataSource,
            Self::FileByMetadataName | Self::EnvByPrefix | Self::EnvByUniqueness => {
                AttributionAxis::MetadataName
            }
        }
    }

    /// [`FigmentSourceKind`] of the `figment::Source` shape this rule
    /// structurally requires, or [`None`] when the rule is dispatched
    /// off `metadata.name` and therefore does not constrain the
    /// originating `figment::Source` at all.
    ///
    /// Source-axis rules ([`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataSource`]) consult
    /// `figment::Metadata::source` directly via
    /// [`FigmentSourceTag::classify`], so the rule's identity already
    /// pins the [`FigmentSourceKind`] cell that fired:
    /// [`Self::FileBySource`] ⇒ [`Some(FigmentSourceKind::File)`],
    /// [`Self::DefaultsByCodeUniqueness`] ⇒
    /// [`Some(FigmentSourceKind::Code)`]. Name-axis rules
    /// ([`Self::metadata_axis`] returns [`AttributionAxis::MetadataName`])
    /// consult `figment::Metadata::name` instead — figment's actual
    /// `Source` may be anything the upstream provider attached
    /// (typically [`FigmentSourceKind::Custom`] for shikumi-built
    /// providers and [`figment::providers::Env`], but the rule does
    /// not require it) — so the partial projection returns [`None`]:
    /// [`Self::FileByMetadataName`], [`Self::EnvByPrefix`],
    /// [`Self::EnvByUniqueness`] all map to [`None`].
    ///
    /// One source of truth for the (rule → figment-source-kind)
    /// projection. The information was previously implicit in the
    /// resolver's branching shape and recoverable only by re-reading
    /// `metadata.source` off the originating [`figment::Error`]; lifting
    /// it to a typed accessor pins "this rule's identity already names
    /// the figment-Source-axis cell" at the type level. A future
    /// variant added to [`Self`] forces a kind assignment in the
    /// exhaustive match in lockstep.
    ///
    /// Composes with [`Self::metadata_axis`] as a refinement on the
    /// source-axis: the partial projection is [`Some`] exactly when
    /// `self.metadata_axis() == AttributionAxis::MetadataSource`. The
    /// `Some-iff-MetadataSource` invariant is structural — every
    /// source-axis rule's identity already pins one
    /// [`FigmentSourceKind`] cell by construction — and pinned by
    /// `attribution_rule_figment_source_kind_some_iff_metadata_axis_source`.
    ///
    /// Composes with [`Self::layer_kind`] as a partial diagonal on the
    /// source-axis subset: when [`Some`], the (figment-source-kind,
    /// layer-kind) pair lies on the structural diagonal
    /// `(File, File)` / `(Code, Defaults)` — the two source-axis
    /// rules' (`figment::Source` ↔ [`ConfigSource`]) correspondence.
    /// Pinned by
    /// `attribution_rule_figment_source_kind_agrees_with_layer_kind_when_some`.
    ///
    /// Image of the projection over [`Self::ALL`] is exactly
    /// `{FigmentSourceKind::File, FigmentSourceKind::Code}` — two of
    /// the three [`FigmentSourceKind`] cells. The third cell
    /// [`FigmentSourceKind::Custom`] is reachable on the figment-side
    /// classification (see
    /// [`figment_source_kind_all_attribution_axis_image_is_metadata_source`])
    /// but no recognized [`AttributionRule`] currently dispatches off
    /// `Source::Custom` — the docstring on [`Self`] names
    /// custom-source attribution as a future direction. When that
    /// rule lands, this accessor's image extends in lockstep.
    ///
    /// Pairs with [`FailingSourceAttribution::figment_source_kind`] /
    /// [`crate::ReloadFailure::figment_source_kind`]: the same
    /// projection surfaced off the borrowed and cross-thread
    /// observable forms, with the cross-thread accessor lifted to
    /// `Option<_>` to track the `Some-iff-attribution` discipline
    /// established for the sibling projection accessors.
    #[must_use]
    pub fn figment_source_kind(self) -> Option<FigmentSourceKind> {
        match self {
            Self::FileBySource => Some(FigmentSourceKind::File),
            Self::DefaultsByCodeUniqueness => Some(FigmentSourceKind::Code),
            Self::FileByMetadataName | Self::EnvByPrefix | Self::EnvByUniqueness => None,
        }
    }

    /// Forward partial unifier of the two source-axis projections
    /// over this rule: [`Self::figment_source_kind`] (partial) and
    /// [`Self::layer_kind`] (total). Returns the rule's joint cell on
    /// the (figment-Source-axis kind × shikumi-layer-kind) plane as
    /// a typed [`AttributionSourceKindCoordinates`] envelope.
    ///
    /// Some-iff-MetadataSource discipline: returns [`Some`] exactly
    /// when [`Self::figment_source_kind`] returns [`Some`]
    /// (equivalently, when [`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataSource`]). Source-axis rules pin
    /// both halves of their joint cell:
    /// [`Self::FileBySource`] → `(File, File)`,
    /// [`Self::DefaultsByCodeUniqueness`] → `(Code, Defaults)`.
    /// Name-axis rules pin only [`Self::layer_kind`]; their
    /// figment-Source-axis half is unconstrained, so the joint cell
    /// is [`None`].
    ///
    /// One source of truth for the (figment-Source-axis kind ×
    /// shikumi-layer-kind) joint cell on a recognized rule. Before
    /// this method, observers that wanted the structural diagonal —
    /// per-cell dashboards routing on the joint cell, attestation
    /// manifests recording the source-axis rule subset's image,
    /// structured-diagnostics legends rendering distinct prose per
    /// joint cell — inlined a two-step
    /// `self.figment_source_kind().map(|fk| (fk, self.layer_kind()))`
    /// projection at every site. The named struct collapses the two
    /// reads (one partial, one total) into one [`Option<_>`] read,
    /// surfacing the joint cell as a typescape-eligible value
    /// (`Copy + Eq + Hash + #[non_exhaustive]`) usable in `match`,
    /// `HashMap` keys, log labels, alerting buckets, and attestation
    /// manifest payloads.
    ///
    /// Pairs with [`AttributionSourceKindCoordinates::is_realizable`]
    /// as the membership-predicate discipline: every [`Some`] return
    /// of this accessor produces a cell satisfying
    /// `is_realizable`. Peer to
    /// [`crate::ShikumiError::error_localization_coordinates`] /
    /// [`ErrorLocalizationCoordinates::is_realizable`] on the third
    /// product cube — both are total-or-partial forward maps whose
    /// image is the recognized subset of the cube.
    ///
    /// Composes with the captured-failure envelopes — the convenience
    /// forwarders
    /// [`FailingSourceAttribution::attribution_source_kind_coordinates`]
    /// and [`crate::ReloadFailure::attribution_source_kind_coordinates`]
    /// surface the same joint cell off the borrowed and cross-thread
    /// observable surfaces, with the cross-thread accessor lifted to
    /// the same `Some-iff-source-axis-attribution` discipline.
    #[must_use]
    pub fn attribution_source_kind_coordinates(self) -> Option<AttributionSourceKindCoordinates> {
        self.figment_source_kind()
            .map(|figment_source_kind| AttributionSourceKindCoordinates {
                figment_source_kind,
                layer_kind: self.layer_kind(),
            })
    }

    /// Forward unifier of the three orthogonal projections over this
    /// rule: [`Self::metadata_axis`], [`Self::layer_kind`],
    /// [`Self::confidence`]. Returns the rule's coordinates as a
    /// typed [`AttributionCoordinates`] envelope.
    ///
    /// One source of truth for the three-axis read on a recognized
    /// rule. Before this method, observers that wanted the full
    /// coordinate triple inlined three method calls
    /// (`(rule.metadata_axis(), rule.layer_kind(), rule.confidence())`)
    /// at every site; the named struct collapses the three reads into
    /// one and surfaces the triple as a typescape-eligible value
    /// (`Copy + Eq + Hash + #[non_exhaustive]`) usable in `match`,
    /// `HashMap` keys, log labels, alerting buckets, and attestation
    /// manifest payloads.
    ///
    /// Pairs with [`Self::from_coordinates`] as the partial inverse:
    /// `Self::from_coordinates(self.coordinates()) == Some(self)` for
    /// every recognized [`Self`] variant — the bijection is pinned by
    /// `attribution_rule_coordinates_round_trip`. The forward map is
    /// total over the rule space; the inverse is partial, returning
    /// `None` for the seven product cells of the
    /// (axis × layer-kind × confidence) cube no recognized rule
    /// occupies.
    ///
    /// Composes with the captured-failure envelopes — the convenience
    /// forwarders [`FailingSourceAttribution::coordinates`] and
    /// [`crate::ReloadFailure::coordinates`] surface the same triple
    /// off the borrowed and cross-thread observable surfaces, with
    /// the cross-thread accessor lifted to `Option<_>` to track the
    /// `Some-iff-attribution` discipline established for the sibling
    /// projection accessors.
    #[must_use]
    pub fn coordinates(self) -> AttributionCoordinates {
        AttributionCoordinates {
            axis: self.metadata_axis(),
            layer_kind: self.layer_kind(),
            confidence: self.confidence(),
        }
    }

    /// Partial inverse of [`Self::coordinates`]: re-hydrate a
    /// recognized rule from its coordinate triple, or [`None`] for
    /// unrecognized triples.
    ///
    /// The (axis × `layer_kind` × confidence) cube has 2 × 3 × 2 = 12
    /// product cells; today's rule space occupies 5 of them. The
    /// inverse map names the five: `(MetadataSource, File, Exact)
    /// → FileBySource`; `(MetadataName, File, Exact) →
    /// FileByMetadataName`; `(MetadataName, Env, Exact) → EnvByPrefix`;
    /// `(MetadataName, Env, Fallback) → EnvByUniqueness`;
    /// `(MetadataSource, Defaults, Fallback) →
    /// DefaultsByCodeUniqueness`. Every other cell returns [`None`].
    ///
    /// Operational use: an attestation manifest, structured-log replay,
    /// or cross-process diagnostic that observes the three coordinates
    /// (e.g. captured into a serialized snapshot) recovers the typed
    /// rule by one method call instead of re-deriving the dispatch
    /// inline. Since the rule space and the recognized-cell set are
    /// pinned at the type level, the inverse stays coherent under
    /// future variant additions: a new rule landing in a previously
    /// unrecognized cell forces both an arm in this exhaustive match
    /// (compile-time, via the `match` over `Self` in
    /// [`Self::coordinates`]) and a row in the
    /// `attribution_rule_coordinates_round_trip` and
    /// `attribution_rule_from_coordinates_recognizes_each_rule` tests
    /// (test-time).
    ///
    /// Strictly stronger than `matches!` against the rule space:
    /// `from_coordinates` consumes the closed-enum coordinate triple
    /// (no string parsing, no inline tuple destructuring), so the
    /// recognized-cell predicate stays one method call regardless of
    /// how many rules the substrate accumulates.
    #[must_use]
    pub fn from_coordinates(coords: AttributionCoordinates) -> Option<Self> {
        match (coords.axis, coords.layer_kind, coords.confidence) {
            (
                AttributionAxis::MetadataSource,
                ConfigSourceKind::File,
                AttributionConfidence::Exact,
            ) => Some(Self::FileBySource),
            (
                AttributionAxis::MetadataName,
                ConfigSourceKind::File,
                AttributionConfidence::Exact,
            ) => Some(Self::FileByMetadataName),
            (
                AttributionAxis::MetadataName,
                ConfigSourceKind::Env,
                AttributionConfidence::Exact,
            ) => Some(Self::EnvByPrefix),
            (
                AttributionAxis::MetadataName,
                ConfigSourceKind::Env,
                AttributionConfidence::Fallback,
            ) => Some(Self::EnvByUniqueness),
            (
                AttributionAxis::MetadataSource,
                ConfigSourceKind::Defaults,
                AttributionConfidence::Fallback,
            ) => Some(Self::DefaultsByCodeUniqueness),
            _ => None,
        }
    }
}

/// Coordinate triple of an [`AttributionRule`] over the three
/// orthogonal projections [`AttributionAxis`] (which `figment::Metadata`
/// field drove dispatch), [`ConfigSourceKind`] (which layer class the
/// rule attributes to), and [`AttributionConfidence`] (equality-based
/// vs uniqueness-based attribution).
///
/// One named typescape value collapsing the three closed-enum reads
/// into one. The (axis × `layer_kind` × confidence) cube has
/// 2 × 3 × 2 = 12 product cells; today's rule space occupies 5 of
/// them. [`AttributionRule::coordinates`] is the total forward map
/// from the rule space; [`AttributionRule::from_coordinates`] is the
/// partial inverse, [`Some`] exactly on the five recognized cells.
///
/// The struct exists (rather than a bare tuple) so call sites
/// document which slot is which — `axis` / `layer_kind` /
/// `confidence` — at the type level rather than relying on positional
/// destructuring discipline. Consumers route on the named fields in
/// `match`, `HashMap` keys, structured-log payloads, and attestation
/// manifests; the `Copy + Eq + Hash + #[non_exhaustive]` bounds match
/// the sibling closed-enum primitives ([`AttributionRule`],
/// [`AttributionConfidence`], [`AttributionAxis`],
/// [`ConfigSourceKind`], [`ShikumiErrorKind`],
/// [`FieldPathLocalization`]).
///
/// Strict superset of the three Option-returning accessors on
/// [`crate::ReloadFailure`]
/// ([`crate::ReloadFailure::attribution_confidence`],
/// [`crate::ReloadFailure::layer_kind`],
/// [`crate::ReloadFailure::metadata_axis`]):
/// [`crate::ReloadFailure::coordinates`] returns the triple as one
/// `Option<AttributionCoordinates>` read, populated exactly when the
/// captured envelope carries an attribution rule. The same
/// `Some-iff-attribution` discipline as the sibling projections.
///
/// Future fidelity work — adding a fourth axis (e.g. a `figment::Source`
/// sub-classification beyond `File`/`Code`/`Custom`), or refining one
/// of the existing axes — extends this struct as one new field plus
/// one match arm in [`AttributionRule::coordinates`] /
/// [`AttributionRule::from_coordinates`]; existing consumers that
/// destructure on the named fields stay coherent under the
/// `#[non_exhaustive]` discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttributionCoordinates {
    /// Which `figment::Metadata` field the resolver dispatched off —
    /// see [`AttributionAxis`] / [`AttributionRule::metadata_axis`].
    pub axis: AttributionAxis,
    /// Which [`ConfigSource`] layer kind the rule attributes to —
    /// see [`ConfigSourceKind`] / [`AttributionRule::layer_kind`].
    pub layer_kind: ConfigSourceKind,
    /// Equality-based or uniqueness-based attribution — see
    /// [`AttributionConfidence`] / [`AttributionRule::confidence`].
    pub confidence: AttributionConfidence,
}

impl AttributionCoordinates {
    /// Every cell of the `axis × layer_kind × confidence` product
    /// cube — the structural composition of [`AttributionAxis::ALL`]
    /// (2 cells), [`ConfigSourceKind::ALL`] (3 cells), and
    /// [`AttributionConfidence::ALL`] (2 cells) into the
    /// `2 × 3 × 2 = 12`-cell coordinate space, in lexicographic order
    /// over the three sibling slices (axis outermost, `layer_kind`
    /// middle, confidence innermost).
    ///
    /// One named typescape value collapsing the three-axis product
    /// enumeration into one constant. Before this lift, every consumer
    /// that wanted the cube — the
    /// `attribution_rule_from_coordinates_returns_none_for_unrecognized_cells`
    /// cube-cover test, future per-cell dashboards, attestation
    /// manifests recording the coordinate space's cardinality,
    /// structured-diagnostics legends rendering different prose per
    /// cell — had to inline a triple-nested
    /// `for axis in AttributionAxis::ALL { for layer_kind in
    /// ConfigSourceKind::ALL { for confidence in
    /// AttributionConfidence::ALL { … } } }` loop and re-derive the
    /// product on the fly. Iterate [`Self::ALL`] instead.
    ///
    /// This is the first product-axis `ALL` constant on the typescape
    /// primitive set — peer to the nine sibling per-axis closed-enum
    /// `ALL` constants ([`crate::Format::ALL`],
    /// [`ShikumiErrorKind::ALL`], [`AttributionRule::ALL`],
    /// [`ConfigSourceKind::ALL`], [`FieldPathLocalization::ALL`],
    /// [`crate::FormatProvenance::ALL`], [`AttributionAxis::ALL`],
    /// [`AttributionConfidence::ALL`],
    /// [`crate::FigmentSourceKind::ALL`]) but lifted on a structural
    /// composition of three of them rather than on a single axis.
    /// The same typescape discipline (closed `'static` slice, in
    /// declaration order, `Copy + Eq + Hash + #[non_exhaustive]`
    /// element type) applied to the product cube.
    ///
    /// Cardinality is pinned by the
    /// `attribution_coordinates_all_cardinality_matches_product_of_axes`
    /// test against
    /// `AttributionAxis::ALL.len() * ConfigSourceKind::ALL.len() *
    /// AttributionConfidence::ALL.len()`, so any new variant on any
    /// of the three sibling axes forces an extension of this slice
    /// in lockstep with the variant itself. The
    /// `attribution_coordinates_all_equals_axes_cartesian_product`
    /// test pins tight equality against the inline triple-nested
    /// product over the sibling `ALL` constants — `Self::ALL` is the
    /// product, not a subset and not a superset.
    ///
    /// The partition into recognized and unrecognized cells is the
    /// 5 + 7 split pinned by [`AttributionRule::from_coordinates`]:
    /// 5 cells (`AttributionRule::ALL.len()`) map to a [`Some`] rule;
    /// 7 cells map to [`None`]. The
    /// `attribution_coordinates_all_recognized_image_equals_rule_coordinates`
    /// test pins the recognized half as the exact image of
    /// [`AttributionRule::coordinates`] over [`AttributionRule::ALL`],
    /// and the
    /// `attribution_coordinates_all_partitions_into_recognized_and_unrecognized`
    /// test pins the cardinality split.
    pub const ALL: &'static [Self] = &[
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::Defaults,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::Defaults,
            confidence: AttributionConfidence::Fallback,
        },
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::Env,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::Env,
            confidence: AttributionConfidence::Fallback,
        },
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Fallback,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::Defaults,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::Defaults,
            confidence: AttributionConfidence::Fallback,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::Env,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::Env,
            confidence: AttributionConfidence::Fallback,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Exact,
        },
        Self {
            axis: AttributionAxis::MetadataName,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Fallback,
        },
    ];

    /// Realizability predicate over the 12-cell product cube: returns
    /// `true` exactly on the 5 cells some recognized [`AttributionRule`]
    /// occupies, and `false` on the remaining 7 cells.
    ///
    /// Equivalent to `AttributionRule::from_coordinates(self).is_some()`
    /// — the closed-enum lift of the partial-inverse-is-Some test on
    /// this cube. Observers that only need the Boolean membership ("is
    /// this cell observable from a recognized rule?") no longer reach
    /// for the partial inverse and discard its [`Some`] payload; the
    /// predicate is one method call regardless of how the rule space
    /// dispatch is currently shaped.
    ///
    /// One source of truth for the realizability test on the
    /// (`axis × layer_kind × confidence`) cube. Before this method,
    /// every site that wanted "is this a recognized cell?" inlined
    /// `AttributionRule::from_coordinates(coords).is_some()` (or its
    /// negation `.is_none()`) at the call site — the realizability /
    /// recognized-cell partition was reachable only through the
    /// partial inverse. The named predicate collapses that to a typed
    /// accessor on the cube, matching the realizability-predicate
    /// discipline already established by
    /// [`ErrorLocalizationCoordinates::is_realizable`] (the
    /// kind × localization cube) and
    /// [`AttributionSourceKindCoordinates::is_realizable`] (the
    /// figment-source-kind × layer-kind cube). With the
    /// [`crate::FormatCoordinates::is_realizable`] lift on the fourth
    /// (format × provenance) cube, the substrate now exposes a
    /// uniform `is_realizable()` predicate on all four product cubes
    /// of the typescape primitive set — the four-cube symmetry is
    /// closed under one Boolean interface.
    ///
    /// Operational use: an attestation manifest, structured-log
    /// replay, or cross-process diagnostic that observes the
    /// (axis, `layer_kind`, confidence) coordinates recovers the
    /// realizability classification — "is this cell a valid
    /// observation of a recognized [`AttributionRule`], or a cross-
    /// axis consistency violation no recognized rule occupies" — by
    /// one method call instead of re-deriving the dispatch from the
    /// partial inverse inline. Future variants land coherently: a new
    /// [`AttributionRule`] landing in a previously unrecognized cell
    /// extends the realizable image, forces an arm in
    /// [`AttributionRule::from_coordinates`] (compile-time), and
    /// forces an extension of the realizable-image expectation in
    /// `attribution_coordinates_is_realizable_image_equals_rule_image`
    /// (test-time) — all three stay in lockstep.
    ///
    /// Peer to [`ErrorLocalizationCoordinates::is_realizable`] and
    /// [`AttributionSourceKindCoordinates::is_realizable`]: same
    /// `Copy`-by-value receiver, same Boolean shape, same membership-
    /// over-the-recognized-image semantics. The implementation on
    /// this cube delegates to the partial inverse (the forward map is
    /// injective on the recognized half, so realizability is exactly
    /// the partial inverse's [`Some`] domain); on the other two cubes
    /// the predicate is a direct pattern match because the forward
    /// map is non-injective or partial.
    #[must_use]
    pub fn is_realizable(self) -> bool {
        AttributionRule::from_coordinates(self).is_some()
    }
}

/// Coordinate pair over the two orthogonal closed-enum projections
/// every [`ShikumiError`] (and every captured
/// [`crate::ReloadFailure`]) carries on its error-path-fidelity
/// surface: [`ShikumiErrorKind`] (which variant) and
/// [`FieldPathLocalization`] (whether figment localized the
/// offending field, didn't, or wasn't applicable at all).
///
/// One named typescape value collapsing the two closed-enum reads
/// into one. The (`kind` × `localization`) plane has
/// `ShikumiErrorKind::ALL.len()` × `FieldPathLocalization::ALL.len()`
/// = 6 × 3 = 18 product cells; today's error space occupies 8 of
/// them — the "realizable" cells in the partition pinned by
/// [`Self::is_realizable`]:
///
/// - 4 cells for figment-bearing kinds (`Figment`, `Extract`)
///   × figment-attached localizations (`Localized`, `FigmentUnlocalized`).
/// - 4 cells for non-figment-bearing kinds (`NotFound`, `Parse`,
///   `Watch`, `Io`) × `NotApplicable`.
///
/// The other 10 cells are unrealizable by construction —
/// [`ShikumiError::field_path_localization`] cannot return
/// `NotApplicable` on a figment-bearing variant (it routes through
/// the figment error's `path` slot), and it cannot return
/// `Localized` or `FigmentUnlocalized` on a non-figment-bearing
/// variant (those variants have no figment error to project from at
/// all). The realizability invariant is therefore
/// `kind.is_figment_bearing() == (localization != NotApplicable)`,
/// pinned by [`Self::is_realizable`] and verified pointwise across
/// the construction-table surface by
/// `error_localization_coordinates_realizable_image_equals_observed_pairs`.
///
/// Third product-axis `ALL` constant on the typescape primitive set,
/// peer to [`AttributionCoordinates::ALL`] (the first,
/// `axis × layer_kind × confidence`) and
/// [`crate::FormatCoordinates::ALL`] (the second,
/// `format × provenance`), but lifted on a different sibling pair
/// (`ShikumiErrorKind × FieldPathLocalization`). The same typescape
/// discipline applies: closed `'static` slice, in declaration order,
/// `Copy + Eq + Hash + #[non_exhaustive]` element type, cardinality
/// pinned as a product of the constituent axis cardinalities, and a
/// forward-total / inverse-partial round-trip pair —
/// [`ShikumiError::error_localization_coordinates`] (and the
/// captured-failure mirror
/// [`crate::ReloadFailure::error_localization_coordinates`]) is the
/// forward total map; [`Self::is_realizable`] is the membership
/// predicate over the recognized 8-cell subset.
///
/// The struct exists (rather than a bare tuple) so call sites
/// document which slot is which — `kind` / `localization` — at the
/// type level rather than relying on positional destructuring
/// discipline. Consumers route on the named fields in `match`,
/// `HashMap` keys, structured-log payloads, and attestation
/// manifests; the `Copy + Eq + Hash + #[non_exhaustive]` bounds
/// match the sibling product-cube structs
/// ([`AttributionCoordinates`], [`crate::FormatCoordinates`]) and
/// the underlying axis primitives ([`ShikumiErrorKind`],
/// [`FieldPathLocalization`]).
///
/// Future fidelity work — adding a third axis (e.g. an
/// `is_recoverable` / `is_transient` retry-class projection over the
/// kind partition) — extends this struct as one new field plus one
/// match arm in the forward map; existing consumers that destructure
/// on the named fields stay coherent under the `#[non_exhaustive]`
/// discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ErrorLocalizationCoordinates {
    /// Which [`ShikumiError`] variant kind the cell describes — see
    /// [`ShikumiErrorKind`] / [`ShikumiError::kind`].
    pub kind: ShikumiErrorKind,
    /// Which field-path-localization state the cell describes — see
    /// [`FieldPathLocalization`] /
    /// [`ShikumiError::field_path_localization`].
    pub localization: FieldPathLocalization,
}

impl ErrorLocalizationCoordinates {
    /// Every cell of the `kind × localization` product cube — the
    /// structural composition of [`ShikumiErrorKind::ALL`] (6 cells)
    /// and [`FieldPathLocalization::ALL`] (3 cells) into the
    /// `6 × 3 = 18`-cell coordinate space, in lexicographic order
    /// over the two sibling slices (kind outermost, localization
    /// innermost).
    ///
    /// One named typescape value collapsing the two-axis product
    /// enumeration into one constant. Before this lift, every
    /// consumer that wanted the cube — partition tests over the
    /// (kind × localization) plane, future per-cell dashboards
    /// (per-kind alert thresholds segmented by localization state),
    /// attestation manifests recording the error-fidelity space's
    /// cardinality, structured-diagnostics legends rendering
    /// different prose per cell ("Extract with Localized field"
    /// vs. "Extract without localized field" vs. "Parse, no figment
    /// context at all") — had to inline a doubly-nested
    /// `for kind in ShikumiErrorKind::ALL { for localization in
    /// FieldPathLocalization::ALL { … } }` loop and re-derive the
    /// product on the fly. Iterate [`Self::ALL`] instead.
    ///
    /// Third product-axis `ALL` constant on the typescape primitive
    /// set — peer to [`AttributionCoordinates::ALL`] (the first,
    /// 12-cell `axis × layer_kind × confidence` cube) and
    /// [`crate::FormatCoordinates::ALL`] (the second, 8-cell
    /// `format × provenance` cube), but lifted on a different
    /// sibling pair (`ShikumiErrorKind × FieldPathLocalization`).
    /// Same typescape discipline (closed `'static` slice, in
    /// declaration order, `Copy + Eq + Hash + #[non_exhaustive]`
    /// element type) applied to the error-fidelity product cube.
    ///
    /// Cardinality is pinned by the
    /// `error_localization_coordinates_all_cardinality_matches_product_of_axes`
    /// test against
    /// `ShikumiErrorKind::ALL.len() * FieldPathLocalization::ALL.len()`,
    /// so any new variant on either sibling axis forces an extension
    /// of this slice in lockstep with the variant itself. The
    /// `error_localization_coordinates_all_equals_axes_cartesian_product`
    /// test pins tight equality against the inline doubly-nested
    /// product over the sibling `ALL` constants — `Self::ALL` is the
    /// product, not a subset and not a superset.
    ///
    /// The partition into realizable and unrealizable cells is the
    /// 8 + 10 split pinned by [`Self::is_realizable`]: 8 cells satisfy
    /// the realizability invariant (2 figment-bearing kinds × 2
    /// figment-attached localizations + 4 non-figment-bearing kinds ×
    /// [`FieldPathLocalization::NotApplicable`]); the other 10 cells
    /// violate it. The `error_localization_coordinates_realizable_image_equals_observed_pairs`
    /// test pins the realizable half as the exact image of
    /// [`ShikumiError::error_localization_coordinates`] over the
    /// canonical construction-table surface, and the
    /// `error_localization_coordinates_realizable_partitions_into_8_realizable_and_10_unrealizable`
    /// test pins the cardinality split.
    pub const ALL: &'static [Self] = &[
        Self {
            kind: ShikumiErrorKind::NotFound,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::NotFound,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::NotFound,
            localization: FieldPathLocalization::NotApplicable,
        },
        Self {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::NotApplicable,
        },
        Self {
            kind: ShikumiErrorKind::Watch,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Watch,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Watch,
            localization: FieldPathLocalization::NotApplicable,
        },
        Self {
            kind: ShikumiErrorKind::Io,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Io,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Io,
            localization: FieldPathLocalization::NotApplicable,
        },
        Self {
            kind: ShikumiErrorKind::Figment,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Figment,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Figment,
            localization: FieldPathLocalization::NotApplicable,
        },
        Self {
            kind: ShikumiErrorKind::Extract,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Extract,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Extract,
            localization: FieldPathLocalization::NotApplicable,
        },
    ];

    /// Realizability predicate over the 18-cell product cube:
    /// returns `true` exactly on the 8 cells that can be produced by
    /// [`ShikumiError::error_localization_coordinates`] (or its
    /// captured-failure mirror
    /// [`crate::ReloadFailure::error_localization_coordinates`]) on
    /// some constructible [`ShikumiError`] value, and `false` on the
    /// remaining 10 cells.
    ///
    /// The invariant is
    /// `self.kind.is_figment_bearing() ==
    /// (self.localization != FieldPathLocalization::NotApplicable)`,
    /// proven pointwise by the partition contracts pinning
    /// [`ShikumiError::field_path_localization`]: figment-bearing
    /// variants (`Figment`, `Extract`) always project to
    /// `Localized` or `FigmentUnlocalized` (the figment error's
    /// `path` slot is `Some`); non-figment-bearing variants
    /// (`NotFound`, `Parse`, `Watch`, `Io`) always project to
    /// `NotApplicable` (no figment error to project from).
    ///
    /// Operational use: an attestation manifest, structured-log
    /// replay, or cross-process diagnostic that observes the (kind,
    /// localization) coordinates recovers the realizability
    /// classification — "is this cell a valid observation, or a
    /// data-quality bug" — by one method call instead of re-deriving
    /// the consistency check inline. Future kind / localization
    /// variants land coherently: a new figment-bearing kind or a
    /// new localization state forces both the
    /// [`ShikumiErrorKind::is_figment_bearing`] partition
    /// (compile-time exhaustive match) and the
    /// `error_localization_coordinates_realizable_partitions_into_8_realizable_and_10_unrealizable`
    /// cardinality split (test-time) to stay in lockstep.
    #[must_use]
    pub fn is_realizable(self) -> bool {
        self.kind.is_figment_bearing()
            == !matches!(self.localization, FieldPathLocalization::NotApplicable)
    }
}

/// Coordinate pair over the two orthogonal closed-enum projections
/// every source-axis [`AttributionRule`] pins on its joint
/// (figment-Source-axis kind × shikumi-layer-kind) cell:
/// [`FigmentSourceKind`] (which [`figment::Source`] class the rule's
/// identity already names) and [`ConfigSourceKind`] (which
/// [`ConfigSource`] layer class the rule attributes to).
///
/// One named typescape value collapsing the two closed-enum reads
/// into one. The (`figment_source_kind × layer_kind`) plane has
/// `FigmentSourceKind::ALL.len()` × `ConfigSourceKind::ALL.len()`
/// = 3 × 3 = 9 product cells; today's source-axis rule subset
/// occupies 2 of them — the "realizable" cells in the partition
/// pinned by [`Self::is_realizable`]:
///
/// - [`AttributionRule::FileBySource`] →
///   `(FigmentSourceKind::File, ConfigSourceKind::File)`.
/// - [`AttributionRule::DefaultsByCodeUniqueness`] →
///   `(FigmentSourceKind::Code, ConfigSourceKind::Defaults)`.
///
/// The other 7 cells are unrealizable today by construction — no
/// recognized [`AttributionRule`] dispatches off the
/// (`FigmentSourceKind::Custom`, _) row, no recognized rule pairs
/// `FigmentSourceKind::File` with [`ConfigSourceKind::Env`] or
/// [`ConfigSourceKind::Defaults`], and no recognized rule pairs
/// `FigmentSourceKind::Code` with [`ConfigSourceKind::File`] or
/// [`ConfigSourceKind::Env`]. The realizability invariant is "lies
/// on the structural diagonal of source-axis rules":
/// `(figment_source_kind, layer_kind) ∈ {(File, File),
/// (Code, Defaults)}`, pinned by [`Self::is_realizable`] and
/// verified pointwise across the rule space by
/// `attribution_source_kind_coordinates_realizable_image_equals_rule_image`.
///
/// Fourth product-axis `ALL` constant on the typescape primitive
/// set, peer to [`AttributionCoordinates::ALL`] (the first, 12-cell
/// `axis × layer_kind × confidence` cube),
/// [`crate::FormatCoordinates::ALL`] (the second, 8-cell
/// `format × provenance` cube), and
/// [`ErrorLocalizationCoordinates::ALL`] (the third, 18-cell
/// `kind × localization` cube), but lifted on a different sibling
/// pair (`FigmentSourceKind × ConfigSourceKind`). The same typescape
/// discipline applies: closed `'static` slice, in declaration order,
/// `Copy + Eq + Hash + #[non_exhaustive]` element type, cardinality
/// pinned as a product of the constituent axis cardinalities, and a
/// forward-partial / membership-predicate pair —
/// [`AttributionRule::attribution_source_kind_coordinates`] (and
/// the convenience forwarders
/// [`FailingSourceAttribution::attribution_source_kind_coordinates`]
/// / [`crate::ReloadFailure::attribution_source_kind_coordinates`])
/// is the forward partial map (`None` for name-axis rules);
/// [`Self::is_realizable`] is the membership predicate over the
/// recognized 2-cell subset.
///
/// Composes [`AttributionRule::figment_source_kind`] (the partial
/// projection onto the figment-Source-axis kind) with
/// [`AttributionRule::layer_kind`] (the total projection onto the
/// shikumi-layer-kind) into one [`Copy`] joint cell. Operationally
/// distinguishes the realizable image of the source-axis rule
/// subset from the cross-axis consistency violations
/// (e.g. `(File, Defaults)`, `(Code, File)`, `(Custom, *)`) that no
/// recognized rule can occupy. Future custom-source rules (named in
/// the [`AttributionRule`] docstring as the natural extension when a
/// [`ConfigSource`] variant lands matching figment's
/// `Source::Custom`) extend this image in lockstep with the rule
/// space.
///
/// The struct exists (rather than a bare tuple) so call sites
/// document which slot is which — `figment_source_kind` /
/// `layer_kind` — at the type level rather than relying on positional
/// destructuring discipline. Consumers route on the named fields in
/// `match`, `HashMap` keys, structured-log payloads, and attestation
/// manifests; the `Copy + Eq + Hash + #[non_exhaustive]` bounds
/// match the sibling product-cube structs
/// ([`AttributionCoordinates`], [`crate::FormatCoordinates`],
/// [`ErrorLocalizationCoordinates`]) and the underlying axis
/// primitives ([`FigmentSourceKind`], [`ConfigSourceKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttributionSourceKindCoordinates {
    /// Which [`figment::Source`]-axis kind the source-axis rule's
    /// identity already pins — see [`FigmentSourceKind`] /
    /// [`AttributionRule::figment_source_kind`].
    pub figment_source_kind: FigmentSourceKind,
    /// Which [`ConfigSource`] layer kind the rule attributes to —
    /// see [`ConfigSourceKind`] / [`AttributionRule::layer_kind`].
    pub layer_kind: ConfigSourceKind,
}

impl AttributionSourceKindCoordinates {
    /// Every cell of the `figment_source_kind × layer_kind` product
    /// cube — the structural composition of [`FigmentSourceKind::ALL`]
    /// (3 cells) and [`ConfigSourceKind::ALL`] (3 cells) into the
    /// `3 × 3 = 9`-cell coordinate space, in lexicographic order
    /// over the two sibling slices (`figment_source_kind` outermost,
    /// `layer_kind` innermost).
    ///
    /// Fourth product-axis `ALL` constant on the typescape primitive
    /// set — peer to [`AttributionCoordinates::ALL`] (the first,
    /// 12-cell `axis × layer_kind × confidence` cube),
    /// [`crate::FormatCoordinates::ALL`] (the second, 8-cell
    /// `format × provenance` cube), and
    /// [`ErrorLocalizationCoordinates::ALL`] (the third, 18-cell
    /// `kind × localization` cube), but lifted on a different
    /// sibling pair (`FigmentSourceKind × ConfigSourceKind`). Same
    /// typescape discipline (closed `'static` slice, in declaration
    /// order, `Copy + Eq + Hash + #[non_exhaustive]` element type)
    /// applied to the attribution-source-kind product cube.
    ///
    /// Cardinality is pinned by
    /// `attribution_source_kind_coordinates_all_cardinality_matches_product_of_axes`
    /// against
    /// `FigmentSourceKind::ALL.len() * ConfigSourceKind::ALL.len()`,
    /// so any new variant on either sibling axis forces an extension
    /// of this slice in lockstep with the variant itself. The
    /// `attribution_source_kind_coordinates_all_equals_axes_cartesian_product`
    /// test pins tight equality against the inline doubly-nested
    /// product over the sibling `ALL` constants — `Self::ALL` is the
    /// product, not a subset and not a superset.
    ///
    /// The partition into realizable and unrealizable cells is the
    /// 2 + 7 split pinned by [`Self::is_realizable`]: 2 cells lie on
    /// the structural diagonal of source-axis rules (`(File, File)`
    /// from [`AttributionRule::FileBySource`] and `(Code, Defaults)`
    /// from [`AttributionRule::DefaultsByCodeUniqueness`]); the other
    /// 7 cells are unrealizable today. The
    /// `attribution_source_kind_coordinates_realizable_image_equals_rule_image`
    /// test pins the realizable half as the exact image of
    /// [`AttributionRule::attribution_source_kind_coordinates`] over
    /// [`AttributionRule::ALL`], and the
    /// `attribution_source_kind_coordinates_realizable_partitions_into_2_realizable_and_7_unrealizable`
    /// test pins the cardinality split.
    pub const ALL: &'static [Self] = &[
        Self {
            figment_source_kind: FigmentSourceKind::File,
            layer_kind: ConfigSourceKind::Defaults,
        },
        Self {
            figment_source_kind: FigmentSourceKind::File,
            layer_kind: ConfigSourceKind::Env,
        },
        Self {
            figment_source_kind: FigmentSourceKind::File,
            layer_kind: ConfigSourceKind::File,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Code,
            layer_kind: ConfigSourceKind::Defaults,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Code,
            layer_kind: ConfigSourceKind::Env,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Code,
            layer_kind: ConfigSourceKind::File,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Custom,
            layer_kind: ConfigSourceKind::Defaults,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Custom,
            layer_kind: ConfigSourceKind::Env,
        },
        Self {
            figment_source_kind: FigmentSourceKind::Custom,
            layer_kind: ConfigSourceKind::File,
        },
    ];

    /// Realizability predicate over the 9-cell product cube: returns
    /// `true` exactly on the 2 cells that can be produced by
    /// [`AttributionRule::attribution_source_kind_coordinates`] (or
    /// its captured-failure mirrors
    /// [`FailingSourceAttribution::attribution_source_kind_coordinates`]
    /// and [`crate::ReloadFailure::attribution_source_kind_coordinates`])
    /// on some recognized [`AttributionRule`] variant, and `false`
    /// on the remaining 7 cells.
    ///
    /// The invariant is the structural diagonal of source-axis
    /// rules:
    /// `(figment_source_kind, layer_kind) ∈ {(File, File),
    /// (Code, Defaults)}`. Proven by enumeration over the rule space:
    /// [`AttributionRule::FileBySource`] is the only source-axis rule
    /// that dispatches off [`figment::Source::File`] and pairs with
    /// [`ConfigSource::File`] (so its joint cell is `(File, File)`);
    /// [`AttributionRule::DefaultsByCodeUniqueness`] is the only
    /// source-axis rule that dispatches off [`figment::Source::Code`]
    /// and pairs with [`ConfigSource::Defaults`] (so its joint cell
    /// is `(Code, Defaults)`). Name-axis rules don't pin a
    /// `figment_source_kind` at all and are absent from this image.
    ///
    /// Operational use: an attestation manifest, structured-log
    /// replay, or cross-process diagnostic that observes the
    /// (`figment_source_kind`, `layer_kind`) coordinates recovers
    /// the realizability classification — "is this cell a valid
    /// observation of a recognized source-axis rule, or a cross-axis
    /// consistency violation" — by one method call instead of
    /// re-deriving the consistency check inline. Future custom-source
    /// rules land coherently: a new [`AttributionRule`] variant that
    /// dispatches off [`figment::Source::Custom`] extends the
    /// recognized image, forces an exhaustive-match arm in
    /// [`AttributionRule::attribution_source_kind_coordinates`]
    /// (compile-time), and forces an extension of the
    /// `attribution_source_kind_coordinates_realizable_image_equals_rule_image`
    /// expectation (test-time) — all three stay in lockstep.
    ///
    /// Peer to [`ErrorLocalizationCoordinates::is_realizable`] (the
    /// realizability predicate over the third product cube): both
    /// are membership predicates on a non-injective forward map's
    /// image. Pairs with the partial-inverse discipline of
    /// [`AttributionRule::from_coordinates`] /
    /// [`crate::FormatCoordinates::format_or_none`] on the cubes
    /// where the forward map is injective.
    #[must_use]
    pub fn is_realizable(self) -> bool {
        matches!(
            (self.figment_source_kind, self.layer_kind),
            (FigmentSourceKind::File, ConfigSourceKind::File)
                | (FigmentSourceKind::Code, ConfigSourceKind::Defaults)
        )
    }
}

impl crate::ClosedAxis for ShikumiErrorKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for ShikumiErrorKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl crate::ClosedAxis for FieldPathLocalization {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for FieldPathLocalization {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl crate::ClosedAxis for AttributionRule {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for AttributionRule {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl crate::ClosedAxis for AttributionConfidence {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxis for AttributionAxis {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxis for AttributionCoordinates {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ProductCube for AttributionCoordinates {
    fn is_realizable(self) -> bool {
        Self::is_realizable(self)
    }
}

impl crate::PartialInverseCube for AttributionCoordinates {
    type Image = AttributionRule;

    fn invert(self) -> Option<AttributionRule> {
        AttributionRule::from_coordinates(self)
    }

    fn forward(image: AttributionRule) -> Self {
        image.coordinates()
    }
}

impl crate::ClosedAxis for ErrorLocalizationCoordinates {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ProductCube for ErrorLocalizationCoordinates {
    fn is_realizable(self) -> bool {
        Self::is_realizable(self)
    }
}

impl crate::ClosedAxis for AttributionSourceKindCoordinates {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ProductCube for AttributionSourceKindCoordinates {
    fn is_realizable(self) -> bool {
        Self::is_realizable(self)
    }
}

/// Confidence class of an [`AttributionRule`].
///
/// Closed binary partition over the rule space:
/// [`AttributionRule::confidence`] is the canonical map. The shape
/// is named (rather than a `bool` flag) so consumers don't re-invent
/// `is_exact_attribution: bool` at every observation site, and so
/// future tertiary classifications (e.g. a `Heuristic` confidence
/// for resolver paths that combine equality with structural hints)
/// land as one new variant peer to the existing two.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, matching the typescape
/// discipline of the sibling primitives [`AttributionRule`],
/// [`FigmentSourceTag`], and [`crate::FigmentNameTag`]: closed,
/// allocation-free, extensible without breaking exhaustivity at
/// consumer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionConfidence {
    /// Equality-based attribution — `metadata.source` or
    /// `metadata.name` matched a recorded [`ConfigSource`] by exact
    /// equality (path, prefix). The substrate has high confidence
    /// the named layer is the actual source of the offending value.
    Exact,
    /// Uniqueness-based attribution — `metadata` did not match any
    /// recorded layer by equality, but exactly one layer of the
    /// matching kind exists in the chain, so it is named by
    /// elimination. The substrate has lower confidence; consumers
    /// (dashboards, miette diagnostic renderers, alerting policies)
    /// may want to weight or render this differently.
    Fallback,
}

impl AttributionConfidence {
    /// Every [`AttributionConfidence`] variant, in declaration order
    /// ([`Self::Exact`], [`Self::Fallback`]).
    ///
    /// The closed list of confidence classes shikumi's attribution
    /// resolver assigns to a recognized [`AttributionRule`]. Iterate
    /// to enumerate the confidence space without listing variants by
    /// hand at every consumer site — e.g. alerting policies
    /// initializing per-confidence thresholds (weighting `Fallback`
    /// attributions visibly weaker than `Exact` ones), attestation
    /// manifests recording the confidence space's cardinality,
    /// structured-diagnostics legends rendering different prose per
    /// class, or product-cube enumerations crossing the confidence
    /// axis with [`AttributionAxis::ALL`] and [`ConfigSourceKind::ALL`]
    /// (the 12-cell `axis × layer_kind × confidence` cube that
    /// [`AttributionRule::from_coordinates`] partitions).
    ///
    /// One source of truth for the axis enumeration on the
    /// [`AttributionConfidence`] axis: peer to [`crate::Format::ALL`]
    /// on the format axis, [`ShikumiErrorKind::ALL`] on the kind
    /// axis, [`AttributionRule::ALL`] on the rule axis,
    /// [`ConfigSourceKind::ALL`] on the layer-kind axis,
    /// [`FieldPathLocalization::ALL`] on the field-path-localization
    /// axis, [`crate::FormatProvenance::ALL`] on the format-provenance
    /// axis, and [`AttributionAxis::ALL`] on the metadata axis — the
    /// same typescape discipline (closed `'static` slice, in
    /// declaration order) applied to the confidence axis. Before this
    /// constant, the confidence enumeration was inlined as an
    /// `[Exact, Fallback]` array literal at every site that needed to
    /// iterate (the 12-cell cube cover test in [`error::tests`]) or
    /// hand-counted (`assert_eq!(set.len(), 2)` in
    /// `attribution_confidence_is_copy_and_hashable`); each
    /// duplicated literal had to be manually kept in lockstep with
    /// the enum's variant set.
    ///
    /// Adding a new variant to [`Self`] (e.g. a `Heuristic` class for
    /// resolver paths that combine equality with structural hints)
    /// means extending this slice in lockstep with the variant
    /// itself. The compiler enforces nothing here directly, so the
    /// `attribution_confidence_all_covers_every_rule_confidence` test
    /// pins the contract by asserting that every confidence produced
    /// by [`AttributionRule::confidence`] over [`AttributionRule::ALL`]
    /// appears in [`Self::ALL`], and the
    /// `attribution_confidence_all_has_no_duplicates` test pins that
    /// the constant is a set (no double-listed variant). Together
    /// they pin the constant to the variant space the typescape
    /// recognizes.
    pub const ALL: &'static [Self] = &[Self::Exact, Self::Fallback];

    /// Canonical operator-facing lowercase name of the confidence
    /// class — [`Self::Exact`] renders as `"exact"`,
    /// [`Self::Fallback`] renders as `"fallback"`.
    ///
    /// Single source of truth for the two canonical strings that
    /// previously appeared only inline at the per-variant `match`
    /// site of [`AttributionRule::confidence`] (where the variant
    /// identifier doubles as a structural tag, not as an
    /// operator-facing label) and in doc-prose; no typed accessor
    /// surfaced the operator-facing label, so a future structured-
    /// log field naming the failing attribution's confidence class,
    /// a CLI flag filtering attributions by confidence
    /// (`--filter-confidence=fallback`), an attestation manifest
    /// recording the confidence histogram of resolved failures, or
    /// a dashboard cell rendering the
    /// `(axis × layer-kind × confidence)` cube
    /// ([`AttributionCoordinates`]) keyed by canonical labels on
    /// each axis would each have re-derived the string mapping
    /// inline at the consumer site with no structural guarantee of
    /// agreement.
    ///
    /// `&'static str` so the label is allocation-free at every call
    /// site; `const fn` so the labels are usable in const contexts
    /// (static slice initializers, match arms over a const cube).
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned
    /// for every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test
    /// in `cube::tests`. The concrete-position pin at
    /// `attribution_confidence_as_str_yields_canonical_lowercase_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"Exact"`, switching `"fallback"` to
    /// `"unique"`) fails at that site before drifting through the
    /// round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Fallback => "fallback",
        }
    }
}

impl crate::ClosedAxisLabel for AttributionConfidence {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

/// Figment-metadata field consulted by an [`AttributionRule`].
///
/// Closed binary partition over the rule space: every recognized
/// resolver path dispatches off either `metadata.source` (figment's
/// typed `Source` classification, recovered via
/// [`FigmentSourceTag::classify`]) or `metadata.name` (figment's
/// human-readable provider-name string, parsed by
/// [`Format::strip_metadata_name`] /
/// [`ConfigSource::strip_env_metadata_name`]). The shape is named
/// (rather than a `bool` flag) so consumers don't re-invent
/// `is_source_axis_attribution: bool` at every observation site, and
/// so future tertiary classifications (e.g. a `MetadataExtras` axis
/// for figment providers that surface additional typed fields) land as
/// one new variant peer to the existing two.
///
/// [`AttributionRule::metadata_axis`] is the canonical map. The
/// projection is orthogonal to both [`AttributionRule::confidence`]
/// (exact × fallback) and [`AttributionRule::layer_kind`]
/// (file × env × defaults) — pinned by
/// `attribution_rule_metadata_axis_orthogonal_to_confidence` and
/// `attribution_rule_metadata_axis_orthogonal_to_layer_kind`.
///
/// Operational distinction:
///
/// - [`Self::MetadataSource`] is figment's *typed* source axis
///   ([`figment::Source::File`], [`figment::Source::Code`],
///   [`figment::Source::Custom`]). Structurally stable — survives
///   upstream provider-name churn.
/// - [`Self::MetadataName`] is figment's *string* provider-name axis
///   parsed by shape-matching against shikumi-known forms. More
///   brittle — depends on the upstream provider continuing to emit a
///   recognized name shape; a renamed figment provider drops out of
///   resolution silently.
///
/// Consumers (diagnostics, dashboards, attestation manifests) that
/// want to weight name-axis attributions visibly weaker than
/// source-axis ones route on this closed enum instead of grepping
/// the rule's name.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, matching the typescape
/// discipline of the sibling primitives ([`AttributionRule`],
/// [`AttributionConfidence`], [`ConfigSourceKind`],
/// [`FigmentSourceTag`], [`FigmentNameTag`]): closed,
/// allocation-free, extensible without breaking exhaustivity at
/// consumer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionAxis {
    /// Resolver dispatched off `metadata.source` — figment's typed
    /// [`figment::Source`] classification recovered via
    /// [`FigmentSourceTag::classify`]. Structural; rules in this
    /// class: [`AttributionRule::FileBySource`],
    /// [`AttributionRule::DefaultsByCodeUniqueness`].
    MetadataSource,
    /// Resolver dispatched off `metadata.name` — figment's
    /// human-readable provider-name string, recognized by
    /// shape-matching ([`Format::strip_metadata_name`] /
    /// [`ConfigSource::strip_env_metadata_name`] /
    /// [`FigmentNameTag::classify`]). String-shape-dependent; rules
    /// in this class: [`AttributionRule::FileByMetadataName`],
    /// [`AttributionRule::EnvByPrefix`],
    /// [`AttributionRule::EnvByUniqueness`].
    MetadataName,
}

impl AttributionAxis {
    /// Every [`AttributionAxis`] variant, in declaration order
    /// ([`Self::MetadataSource`], [`Self::MetadataName`]).
    ///
    /// The closed list of figment-metadata fields shikumi's resolver
    /// dispatches off. Iterate to enumerate the axis space without
    /// listing variants by hand at every consumer site — e.g.
    /// dashboards initializing per-axis counters (weighting name-axis
    /// attributions visibly weaker than source-axis ones), attestation
    /// manifests recording the axis space's cardinality, structured-
    /// diagnostics legends rendering different prose per axis, or
    /// product-cube enumerations crossing the axis with
    /// [`ConfigSourceKind::ALL`] and the confidence axis.
    ///
    /// One source of truth for the axis enumeration on the
    /// [`AttributionAxis`] axis: peer to [`crate::Format::ALL`] on the
    /// format axis, [`ShikumiErrorKind::ALL`] on the kind axis,
    /// [`AttributionRule::ALL`] on the rule axis,
    /// [`ConfigSourceKind::ALL`] on the layer-kind axis,
    /// [`FieldPathLocalization::ALL`] on the field-path-localization
    /// axis, and [`crate::FormatProvenance::ALL`] on the format-
    /// provenance axis — the same typescape discipline (closed
    /// `'static` slice, in declaration order) applied to the metadata
    /// axis. Before this constant, the axis enumeration was inlined as
    /// a `[MetadataSource, MetadataName]` array literal at every site
    /// that needed to iterate (the 12-cell cube cover test in
    /// [`error::tests`]); each duplicated literal had to be manually
    /// kept in lockstep with the enum's variant set.
    ///
    /// Adding a new variant to [`Self`] (e.g. a `MetadataExtras` axis
    /// if figment grows additional typed metadata fields) means
    /// extending this slice in lockstep with the variant itself. The
    /// compiler enforces nothing here directly, so the
    /// `attribution_axis_all_covers_every_rule_axis` test pins the
    /// contract by asserting that every axis produced by
    /// [`AttributionRule::metadata_axis`] over [`AttributionRule::ALL`]
    /// appears in [`Self::ALL`], and the
    /// `attribution_axis_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant). Together they pin
    /// the constant to the variant space the typescape recognizes.
    pub const ALL: &'static [Self] = &[Self::MetadataSource, Self::MetadataName];

    /// Canonical operator-facing kebab-case name of the metadata axis —
    /// [`Self::MetadataSource`] renders as `"metadata-source"`,
    /// [`Self::MetadataName`] renders as `"metadata-name"`.
    ///
    /// Single source of truth for the two canonical strings that
    /// previously appeared only inline at the per-variant `match` site
    /// of [`AttributionRule::metadata_axis`] (where the variant
    /// identifier doubles as a structural tag, not as an
    /// operator-facing label) and in doc-prose; no typed accessor
    /// surfaced the operator-facing label, so a future structured-log
    /// field naming the failing attribution's metadata axis, a CLI
    /// flag filtering attributions by axis
    /// (`--filter-axis=metadata-name`), an attestation manifest
    /// recording the per-axis histogram of resolved failures, or a
    /// dashboard cell rendering the
    /// `(axis × layer-kind × confidence)` cube
    /// ([`AttributionCoordinates`]) keyed by canonical labels on every
    /// axis would each have re-derived the string mapping inline at
    /// the consumer site with no structural guarantee of agreement.
    ///
    /// Kebab-case (rather than single-word lowercase) because the
    /// variant identifiers are compound nouns whose punctuation
    /// belongs at the type level (operator-facing string) rather than
    /// at the call site — the same convention shared with
    /// [`crate::FormatProvenance::as_str`]
    /// (`"figment-builtin"` / `"shikumi-built"`). Distinguishing
    /// `"metadata-source"` from `"source"` (the
    /// [`ConfigSourceKind`] / [`FigmentSourceKind`] kind-axis prefix)
    /// keeps the operator-facing axis namespace flat: a structured
    /// log field carrying the canonical name disambiguates "which
    /// `figment::Metadata` field drove this attribution?" from "what
    /// kind of layer was blamed?" by string identity.
    ///
    /// `&'static str` so the label is allocation-free at every call
    /// site; `const fn` so the labels are usable in const contexts
    /// (static slice initializers, match arms over a const cube).
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` is pinned for
    /// every variant uniformly by the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `attribution_axis_as_str_yields_canonical_kebab_case_names`
    /// holds the literal strings stable so a future rename
    /// (e.g. capitalizing `"MetadataSource"`, switching
    /// `"metadata-name"` to `"name"`, dropping the `"metadata-"`
    /// prefix) fails at that site before drifting through the
    /// round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataSource => "metadata-source",
            Self::MetadataName => "metadata-name",
        }
    }
}

impl crate::ClosedAxisLabel for AttributionAxis {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

/// Typed envelope returned by [`ShikumiError::failing_attribution`]:
/// the attributed [`ConfigSource`] and the [`AttributionRule`] that
/// produced the attribution.
///
/// The source borrows into the recorded chain so the envelope shares
/// the error's lifetime; the rule is `Copy`. Pair-struct over the
/// `(which-layer × why)` axis: the (where × what) failure surface
/// (chain × field-path) gains a third axis (rule) that pins the
/// attribution mechanism to one of the five typed cases in
/// [`AttributionRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FailingSourceAttribution<'a> {
    /// The recorded [`ConfigSource`] entry blamed for the failure.
    pub source: &'a ConfigSource,
    /// The rule under which `source` was attributed.
    pub rule: AttributionRule,
}

impl<'a> FailingSourceAttribution<'a> {
    pub(crate) fn new(source: &'a ConfigSource, rule: AttributionRule) -> Self {
        Self { source, rule }
    }

    /// Confidence class of [`Self::rule`]; convenience over
    /// [`AttributionRule::confidence`]. One method call answers
    /// "is the named layer attributed by equality or by elimination?"
    /// without destructuring the envelope.
    #[must_use]
    pub fn confidence(self) -> AttributionConfidence {
        self.rule.confidence()
    }

    /// [`ConfigSourceKind`] of [`Self::source`]; convenience over
    /// [`AttributionRule::layer_kind`]. One method call answers "what
    /// kind of layer was blamed?" — file, env, or defaults — without
    /// destructuring the envelope.
    ///
    /// Equal to `self.source.kind()` by construction (the resolver
    /// only ever pairs a rule with a source of the matching kind);
    /// the contract is pinned by
    /// `attribution_rule_layer_kind_agrees_with_source_kind`. Reading
    /// it through this accessor (rather than `self.source.kind()`)
    /// surfaces the same kind as a consequence of the rule, not an
    /// independent fact about the source.
    #[must_use]
    pub fn layer_kind(self) -> ConfigSourceKind {
        self.rule.layer_kind()
    }

    /// [`AttributionAxis`] of [`Self::rule`]; convenience over
    /// [`AttributionRule::metadata_axis`]. One method call answers
    /// "which figment metadata field drove this attribution?" —
    /// `metadata.source` (typed source classification, structurally
    /// stable) or `metadata.name` (human-readable name, parsed by
    /// shape-matching) — without destructuring the envelope.
    ///
    /// Composes with [`Self::confidence`] (exact × fallback) and
    /// [`Self::layer_kind`] (file × env × defaults): three orthogonal
    /// projections over the rule space, surfaced as three method
    /// calls on the envelope. Diagnostics that want to render
    /// name-axis attributions as more brittle than source-axis ones
    /// — or attestation manifests that record per-failure attribution
    /// provenance — route on this closed enum instead of inspecting
    /// the rule's name.
    #[must_use]
    pub fn metadata_axis(self) -> AttributionAxis {
        self.rule.metadata_axis()
    }

    /// [`FigmentSourceKind`] of [`Self::rule`]; convenience over
    /// [`AttributionRule::figment_source_kind`]. One method call
    /// answers "did the rule already pin which figment-Source-axis
    /// cell fired?" — [`Some`] for source-axis rules
    /// ([`AttributionRule::FileBySource`] →
    /// [`Some(FigmentSourceKind::File)`],
    /// [`AttributionRule::DefaultsByCodeUniqueness`] →
    /// [`Some(FigmentSourceKind::Code)`]), [`None`] for name-axis
    /// rules whose identity does not constrain the originating
    /// `figment::Source` — without destructuring the envelope or
    /// re-reading `metadata.source` off the originating
    /// [`figment::Error`].
    ///
    /// Some-iff-MetadataSource discipline shared with
    /// [`AttributionRule::figment_source_kind`]: the projection is
    /// [`Some`] exactly when [`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataSource`]. Pinned by
    /// `failing_source_attribution_figment_source_kind_mirrors_rule_figment_source_kind`.
    #[must_use]
    pub fn figment_source_kind(self) -> Option<FigmentSourceKind> {
        self.rule.figment_source_kind()
    }

    /// Joint (figment-Source-axis kind × shikumi-layer-kind) cell of
    /// [`Self::rule`]; convenience over
    /// [`AttributionRule::attribution_source_kind_coordinates`]. One
    /// method call returns the source-axis rule's joint cell — the
    /// figment-Source-axis kind paired with the shikumi-layer kind —
    /// without destructuring the envelope or inlining the two sibling
    /// reads ([`Self::figment_source_kind`], [`Self::layer_kind`]) at
    /// the call site.
    ///
    /// Some-iff-MetadataSource discipline shared with
    /// [`AttributionRule::attribution_source_kind_coordinates`]: the
    /// joint cell is [`Some`] exactly when [`Self::metadata_axis`]
    /// returns [`AttributionAxis::MetadataSource`]. Pinned by
    /// `failing_source_attribution_attribution_source_kind_coordinates_mirrors_rule`.
    #[must_use]
    pub fn attribution_source_kind_coordinates(self) -> Option<AttributionSourceKindCoordinates> {
        self.rule.attribution_source_kind_coordinates()
    }

    /// Coordinate triple of [`Self::rule`]; convenience over
    /// [`AttributionRule::coordinates`]. One method call returns the
    /// (axis × layer-kind × confidence) coordinates of the rule that
    /// fired, without destructuring the envelope or inlining the
    /// three sibling forwarders ([`Self::metadata_axis`],
    /// [`Self::layer_kind`], [`Self::confidence`]) at the call site.
    ///
    /// Equal by construction to
    /// `AttributionCoordinates { axis: self.metadata_axis(),
    /// layer_kind: self.layer_kind(), confidence: self.confidence() }`
    /// — the convenience forwarder stays a thin lift of the
    /// underlying rule's coordinate accessor; the contract is pinned
    /// by `failing_source_attribution_coordinates_mirrors_rule_coordinates`.
    #[must_use]
    pub fn coordinates(self) -> AttributionCoordinates {
        self.rule.coordinates()
    }
}

/// Map a figment error's per-value [`figment::Metadata`] back to the
/// specific [`ConfigSource`] in the recorded chain that produced the
/// offending value, alongside the [`AttributionRule`] that fired.
///
/// Returns a [`FailingSourceAttribution`] borrowed into `chain` so
/// callers share its lifetime. `None` when figment did not attach
/// metadata (e.g. an `Error::from(String)` constructed without a
/// provider context), or when the metadata cannot be matched to any
/// recorded entry under any rule.
///
/// Resolution rules, applied in order; the first that matches wins:
/// 1. [`AttributionRule::FileBySource`] — `metadata.source` classifies
///    (per [`FigmentSourceTag::classify`]) as
///    [`FigmentSourceTag::File`], and a [`ConfigSource::File`] entry's
///    path equals it.
/// 2. [`AttributionRule::FileByMetadataName`] — `metadata.name` matches
///    a shikumi-built provider's `"<format>: <path>"` shape (per
///    [`Format::strip_metadata_name`]), and a [`ConfigSource::File`]
///    entry's path equals the extracted path.
/// 3. [`AttributionRule::EnvByPrefix`] — `metadata.name` is env-tag
///    shaped with a prefix (per
///    [`ConfigSource::strip_env_metadata_name`] returning
///    [`EnvMetadataTag::Prefixed`]), and a [`ConfigSource::Env`]
///    entry's prefix matches case-insensitively.
/// 4. [`AttributionRule::EnvByUniqueness`] — `metadata.name` is env-tag
///    shaped (prefixed-without-match or bare), no prefix match in the
///    chain, and exactly one [`ConfigSource::Env`] entry exists.
/// 5. [`AttributionRule::DefaultsByCodeUniqueness`] — `metadata.source`
///    classifies as [`FigmentSourceTag::Code`], and exactly one
///    [`ConfigSource::Defaults`] entry exists.
fn resolve_failing_source<'a>(
    error: &figment::Error,
    chain: &'a [ConfigSource],
) -> Option<FailingSourceAttribution<'a>> {
    let md = error.metadata.as_ref()?;
    let source_tag = md.source.as_ref().and_then(FigmentSourceTag::classify);

    if let Some(FigmentSourceTag::File(p)) = source_tag
        && let Some(hit) = chain.iter().find(|s| s.as_path() == Some(p))
    {
        return Some(FailingSourceAttribution::new(
            hit,
            AttributionRule::FileBySource,
        ));
    }

    match FigmentNameTag::classify(md.name.as_ref()) {
        Some(FigmentNameTag::Format(tag)) => {
            if let Some(hit) = chain.iter().find(|s| s.as_path() == Some(tag.path)) {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::FileByMetadataName,
                ));
            }
        }
        Some(FigmentNameTag::Env(env_tag)) => {
            if let EnvMetadataTag::Prefixed(prefix_upper) = env_tag
                && let Some(hit) = chain.iter().find(|s| {
                    s.as_env_prefix()
                        .is_some_and(|p| p.eq_ignore_ascii_case(prefix_upper))
                })
            {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::EnvByPrefix,
                ));
            }
            let mut envs = chain.iter().filter(|s| s.is_env());
            if let Some(only) = envs.next()
                && envs.next().is_none()
            {
                return Some(FailingSourceAttribution::new(
                    only,
                    AttributionRule::EnvByUniqueness,
                ));
            }
        }
        None => {}
    }

    if matches!(source_tag, Some(FigmentSourceTag::Code(_))) {
        let mut defaults = chain.iter().filter(|s| s.is_defaults());
        if let Some(only) = defaults.next()
            && defaults.next().is_none()
        {
            return Some(FailingSourceAttribution::new(
                only,
                AttributionRule::DefaultsByCodeUniqueness,
            ));
        }
    }

    None
}

impl ShikumiError {
    /// Closed-enum classification of this error's variant — the typed
    /// kind partition over the [`ShikumiError`] variant space.
    ///
    /// One source of truth for the kind axis: consumers route on the
    /// returned [`ShikumiErrorKind`] (in `match`, `HashMap` keys, log
    /// labels, alerting buckets) instead of writing per-variant
    /// `is_*` predicates or open-coded `matches!` against the
    /// data-bearing sum type. Equivalent to `matches!` on the
    /// underlying variant — but the closed-enum return value composes
    /// further (it's `Copy + Eq + Hash`), where a `bool` does not.
    ///
    /// Strict superset of [`Self::is_not_found`] and [`Self::is_parse`]:
    /// `err.is_not_found()` is `err.kind() == ShikumiErrorKind::NotFound`,
    /// and likewise for `is_parse`. The two predicates remain as
    /// convenience accessors; new code that needs to distinguish more
    /// than one kind should prefer this one accessor over a chain of
    /// predicates.
    ///
    /// The implementation is one exhaustive `match`, so a future
    /// [`ShikumiError`] variant landing forces a corresponding
    /// [`ShikumiErrorKind`] variant in lockstep at compile time —
    /// the kind partition stays coherent by construction.
    #[must_use]
    pub fn kind(&self) -> ShikumiErrorKind {
        match self {
            Self::NotFound { .. } => ShikumiErrorKind::NotFound,
            Self::Parse(_) => ShikumiErrorKind::Parse,
            Self::Watch(_) => ShikumiErrorKind::Watch,
            Self::Io(_) => ShikumiErrorKind::Io,
            Self::Figment(_) => ShikumiErrorKind::Figment,
            Self::Extract { .. } => ShikumiErrorKind::Extract,
        }
    }

    /// Returns `true` if this is a `NotFound` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::NotFound`.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::NotFound)
    }

    /// Returns `true` if this is a `Parse` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Parse`.
    #[must_use]
    pub fn is_parse(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Parse)
    }

    /// Returns the list of paths that were tried, if this is a `NotFound` error.
    #[must_use]
    pub fn tried_paths(&self) -> Option<&[PathBuf]> {
        match self {
            Self::NotFound { tried } => Some(tried),
            _ => None,
        }
    }

    /// Returns the typed [`ConfigSource`] chain attached to this error.
    ///
    /// Currently populated only by [`ShikumiError::Extract`]; future
    /// variants may attach a chain too. Callers should treat `None` as
    /// "no provenance recorded," not "no sources contributed."
    #[must_use]
    pub fn sources(&self) -> Option<&[ConfigSource]> {
        match self {
            Self::Extract { sources, .. } => Some(sources),
            _ => None,
        }
    }

    /// Returns the dotted field path that produced the failure, if known.
    ///
    /// Drawn from the wrapped [`figment::Error::path`] for variants that
    /// box one ([`Self::Extract`], [`Self::Figment`]). Returned as a
    /// borrowed slice so callers can inspect the raw segments
    /// (`["window", "size"]`) rather than re-parsing the rendered
    /// "at field" Display segment.
    ///
    /// `None` for variants that do not wrap a figment error
    /// ([`Self::Parse`], [`Self::NotFound`], [`Self::Watch`],
    /// [`Self::Io`]). An empty slice means figment did not localize the
    /// offending field — typically a top-level type mismatch or an error
    /// the deserializer reported without a key context — and is
    /// distinct from `None`.
    ///
    /// Pairs with [`Self::sources`] to form the (where × what) failure
    /// surface: provenance answers "which layer chain contributed?"
    /// while this answers "which field inside the produced value did
    /// the deserializer reject?".
    #[must_use]
    pub fn field_path(&self) -> Option<&[String]> {
        match self {
            Self::Extract { error, .. } | Self::Figment(error) => Some(&error.path),
            _ => None,
        }
    }

    /// Closed-enum classification of this error's field-path
    /// localization state — typed projection over the tri-state
    /// surfaced by [`Self::field_path`]: `None`,
    /// `Some(empty)`, `Some(non-empty)`.
    ///
    /// One source of truth for the tri-state: consumers route on the
    /// returned [`FieldPathLocalization`] (in `match`, `HashMap`
    /// keys, log labels, alerting buckets) instead of re-deriving the
    /// (`is_some()`, `is_empty()`) decision at every site or pinning
    /// the figment-bearing variant set inline by
    /// `matches!(self, Extract { .. } | Figment(_))`. The
    /// localization axis composes with the kind axis
    /// ([`Self::kind`] / [`ShikumiErrorKind::is_figment_bearing`]) and
    /// the field-path slot ([`Self::field_path`]): the kind tells
    /// you whether figment was even an option, the localization tells
    /// you whether figment took it, and the field path holds the
    /// segments when it did.
    ///
    /// Mirrored on the cross-thread observable form by
    /// [`crate::ReloadFailure::field_path_localization`]: the
    /// captured-failure envelope's projection agrees pointwise with
    /// the source error's, pinning the lossless-capture contract for
    /// the localization axis (the `Vec<String>` representation on
    /// [`crate::ReloadFailure::field_path`] alone collapses
    /// `Some(empty)` and `None` into the same observable; the typed
    /// accessor restores the distinction).
    #[must_use]
    pub fn field_path_localization(&self) -> FieldPathLocalization {
        match self.field_path() {
            Some(path) if !path.is_empty() => FieldPathLocalization::Localized,
            Some(_) => FieldPathLocalization::FigmentUnlocalized,
            None => FieldPathLocalization::NotApplicable,
        }
    }

    /// Coordinate pair over the two orthogonal closed-enum
    /// projections this error carries on the error-path-fidelity
    /// surface — [`Self::kind`] (which variant) and
    /// [`Self::field_path_localization`] (figment-attached or not).
    ///
    /// One named typescape value collapsing the two reads into one.
    /// Total forward map: every constructible [`ShikumiError`]
    /// produces a coordinate cell in the 18-cell product cube
    /// [`ErrorLocalizationCoordinates::ALL`], and the produced cell
    /// always satisfies [`ErrorLocalizationCoordinates::is_realizable`]
    /// (pinned by
    /// `shikumi_error_error_localization_coordinates_returns_realizable_cell`
    /// over the canonical construction-table surface). The 10
    /// unrealizable cells in the cube are observable only as a
    /// cross-axis consistency violation — never as the image of this
    /// accessor.
    ///
    /// Strict superset of the two sibling accessors
    /// ([`Self::kind`], [`Self::field_path_localization`]): the
    /// coordinate carries both as one `Copy` value, usable in
    /// `match`, `HashMap` keys, structured-log payloads, and
    /// attestation manifests without re-reading the two projections
    /// separately. Mirrored on the cross-thread observable form by
    /// [`crate::ReloadFailure::error_localization_coordinates`]: the
    /// captured-failure envelope's projection agrees pointwise with
    /// the source error's, pinning the lossless-capture contract
    /// for the (kind × localization) coordinate plane.
    #[must_use]
    pub fn error_localization_coordinates(&self) -> ErrorLocalizationCoordinates {
        ErrorLocalizationCoordinates {
            kind: self.kind(),
            localization: self.field_path_localization(),
        }
    }

    /// Returns the specific [`ConfigSource`] in the recorded chain that
    /// produced the failure, if attribution is possible.
    ///
    /// Distinct from [`Self::sources`], which returns the whole chain:
    /// `failing_source` pinpoints the *one* layer figment's per-value
    /// metadata blames for the offending field. Returned by reference
    /// into the recorded chain so it shares the error's lifetime.
    ///
    /// Pairs with [`Self::sources`] (full chain) and [`Self::field_path`]
    /// (offending key) to form the closed (which-layer × which-field)
    /// failure coordinate inside the (where × what) surface.
    ///
    /// Returns `None` for variants that do not record a chain
    /// ([`Self::Parse`], [`Self::NotFound`], [`Self::Watch`],
    /// [`Self::Io`], [`Self::Figment`]); for [`Self::Extract`] errors
    /// when figment did not attach `Metadata` (e.g. a manually
    /// constructed `figment::Error::from(string)`); and when the
    /// metadata cannot be matched to any entry in the recorded chain
    /// (callers should fall back to [`Self::sources`]).
    ///
    /// Wraps [`Self::failing_attribution`], dropping the
    /// [`AttributionRule`]; callers that need to distinguish exact
    /// attribution (path / prefix equality) from fallback attribution
    /// (uniqueness in the chain) should use the envelope directly.
    #[must_use]
    pub fn failing_source(&self) -> Option<&ConfigSource> {
        self.failing_attribution().map(|a| a.source)
    }

    /// Returns the typed attribution envelope — the
    /// [`ConfigSource`] in the recorded chain blamed for the failure
    /// and the [`AttributionRule`] that produced the attribution — if
    /// attribution is possible.
    ///
    /// Strict superset of [`Self::failing_source`]: same `None`
    /// conditions, but on `Some` carries the rule alongside the source.
    /// Pair the rule with the source to render rule-aware structured
    /// diagnostics (e.g. mark fallback attributions like
    /// [`AttributionRule::EnvByUniqueness`] /
    /// [`AttributionRule::DefaultsByCodeUniqueness`] visibly weaker
    /// than equality-based ones), or to record per-failure attribution
    /// provenance in attestation manifests.
    ///
    /// Borrowed reference into the recorded chain, so the envelope
    /// shares this error's lifetime.
    #[must_use]
    pub fn failing_attribution(&self) -> Option<FailingSourceAttribution<'_>> {
        match self {
            Self::Extract { sources, error } => resolve_failing_source(error, sources),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display_lists_paths() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/a/b.yaml"), PathBuf::from("/c/d.toml")],
        };
        let msg = err.to_string();
        assert!(msg.contains("/a/b.yaml"), "error should list first path");
        assert!(msg.contains("/c/d.toml"), "error should list second path");
        assert!(msg.contains(", "), "paths should be comma-separated");
    }

    #[test]
    fn not_found_empty_tried() {
        let err = ShikumiError::NotFound { tried: vec![] };
        let msg = err.to_string();
        assert!(msg.contains("config file not found"));
    }

    #[test]
    fn parse_error_display() {
        let err = ShikumiError::Parse("unexpected token".to_owned());
        let msg = err.to_string();
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn figment_error_from_conversion() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();

        let shikumi_err: ShikumiError = Box::new(figment_err).into();
        assert!(
            matches!(shikumi_err, ShikumiError::Figment(_)),
            "expected Figment variant"
        );
        let msg = shikumi_err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn is_not_found_helper() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/a")],
        };
        assert!(err.is_not_found());
        assert!(!err.is_parse());
    }

    #[test]
    fn is_parse_helper() {
        let err = ShikumiError::Parse("bad".to_owned());
        assert!(err.is_parse());
        assert!(!err.is_not_found());
    }

    #[test]
    fn tried_paths_returns_paths_for_not_found() {
        let paths = vec![PathBuf::from("/x"), PathBuf::from("/y")];
        let err = ShikumiError::NotFound {
            tried: paths.clone(),
        };
        assert_eq!(err.tried_paths(), Some(paths.as_slice()));

        let parse_err = ShikumiError::Parse("bad".to_owned());
        assert_eq!(parse_err.tried_paths(), None);
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let shikumi_err: ShikumiError = io_err.into();
        assert!(matches!(shikumi_err, ShikumiError::Io(_)));
        assert!(shikumi_err.to_string().contains("file gone"));
    }

    #[test]
    fn error_is_debug_printable() {
        let err = ShikumiError::Parse("test".to_owned());
        let debug = format!("{err:?}");
        assert!(debug.contains("Parse"));
    }

    #[test]
    fn watch_error_from_conversion() {
        let notify_err = notify::Error::generic("test watcher error");
        let shikumi_err: ShikumiError = notify_err.into();
        assert!(
            matches!(shikumi_err, ShikumiError::Watch(_)),
            "expected Watch variant"
        );
        let msg = shikumi_err.to_string();
        assert!(msg.contains("test watcher error"));
    }

    #[test]
    fn watch_error_display() {
        let notify_err = notify::Error::generic("poll failed");
        let err: ShikumiError = notify_err.into();
        let msg = err.to_string();
        assert!(msg.contains("file watch error"));
        assert!(msg.contains("poll failed"));
    }

    #[test]
    fn figment_error_display_contains_context() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();
        let err: ShikumiError = Box::new(figment_err).into();
        let msg = err.to_string();
        assert!(msg.contains("figment error"), "should have figment prefix");
    }

    #[test]
    fn error_source_chain() {
        use std::error::Error;

        let notify_err = notify::Error::generic("test");
        let err: ShikumiError = notify_err.into();
        assert!(err.source().is_some(), "Watch variant should have a source");

        let parse_err = ShikumiError::Parse("test".to_owned());
        assert!(
            parse_err.source().is_none(),
            "Parse variant should not have a source"
        );
    }

    #[test]
    fn not_found_single_path() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/only/one.yaml")],
        };
        let msg = err.to_string();
        assert!(msg.contains("/only/one.yaml"));
        assert!(!msg.contains(", "), "single path should have no comma");
    }

    // ---- Extract variant tests ----

    fn fake_figment_error() -> Box<figment::Error> {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        Box::new(result.unwrap_err())
    }

    #[test]
    fn extract_display_lists_layers_in_order() {
        let err = ShikumiError::Extract {
            sources: vec![
                ConfigSource::Defaults,
                ConfigSource::Env("APP_".to_owned()),
                ConfigSource::File(PathBuf::from("/etc/app.yaml")),
            ],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(msg.contains("config extraction failed"));
        assert!(msg.contains("defaults"));
        assert!(msg.contains("env(APP_)"));
        assert!(msg.contains("file(/etc/app.yaml)"));
        // Order matters: defaults first, then env, then file.
        let d = msg.find("defaults").unwrap();
        let e = msg.find("env(APP_)").unwrap();
        let f = msg.find("file(/etc/app.yaml)").unwrap();
        assert!(d < e && e < f, "layers must render in merge order");
    }

    #[test]
    fn extract_display_with_empty_sources() {
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(msg.contains("config extraction failed"));
        assert!(msg.contains("<empty>"));
    }

    #[test]
    fn extract_carries_source_chain_via_helper() {
        let chain = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/x.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain.clone(),
            error: fake_figment_error(),
        };
        assert_eq!(err.sources(), Some(chain.as_slice()));
    }

    #[test]
    fn sources_helper_returns_none_for_other_variants() {
        assert!(ShikumiError::Parse("x".to_owned()).sources().is_none());
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .sources()
            .is_none()
        );
        assert!(
            ShikumiError::Figment(fake_figment_error())
                .sources()
                .is_none()
        );
    }

    #[test]
    fn extract_source_chain_preserves_figment_error() {
        use std::error::Error;
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let src = err.source().expect("Extract should expose a #[source]");
        // The wrapped figment error should be reachable.
        assert!(!format!("{src}").is_empty());
    }

    #[test]
    fn extract_is_distinct_from_figment_variant() {
        let extract = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let figment = ShikumiError::Figment(fake_figment_error());
        assert!(matches!(extract, ShikumiError::Extract { .. }));
        assert!(matches!(figment, ShikumiError::Figment(_)));
        assert_ne!(extract.to_string(), figment.to_string());
    }

    // ---- field_path() tests ----

    /// Build a real extraction failure that figment can attach a path to:
    /// type mismatch on a typed field. The deserializer reports the offending
    /// key, so figment fills in `error.path`.
    fn extract_error_with_typed_field_path() -> ShikumiError {
        use crate::provider::ProviderChain;
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("typed.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        // Keep the temp dir alive long enough for the caller to read the error.
        // (figment loads the file synchronously inside `extract`, so the file is
        // no longer needed after this point.)
        drop(dir);
        err
    }

    #[test]
    fn field_path_none_for_non_figment_variants() {
        assert!(ShikumiError::Parse("x".to_owned()).field_path().is_none());
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .field_path()
            .is_none()
        );
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let io_err: ShikumiError = io.into();
        assert!(io_err.field_path().is_none());
    }

    #[test]
    fn field_path_some_empty_for_extract_without_localized_field() {
        // Bare Figment::new() failure: no provider, no path attribution.
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let path = err
            .field_path()
            .expect("Extract always exposes a (possibly empty) field path");
        assert!(
            path.is_empty(),
            "no localized field, but accessor is Some(&[])"
        );
    }

    #[test]
    fn field_path_some_empty_for_figment_variant_without_localized_field() {
        let err = ShikumiError::Figment(fake_figment_error());
        let path = err
            .field_path()
            .expect("Figment always exposes a (possibly empty) field path");
        assert!(path.is_empty());
    }

    #[test]
    fn field_path_carries_offending_field_for_typed_failure() {
        let err = extract_error_with_typed_field_path();
        let path = err.field_path().expect("Extract exposes field path");
        assert_eq!(
            path,
            &["count".to_owned()],
            "figment should localize the offending key"
        );
    }

    #[test]
    fn extract_display_includes_field_path_segment_when_localized() {
        let err = extract_error_with_typed_field_path();
        let msg = err.to_string();
        assert!(
            msg.contains("at field `count`"),
            "rendered error must cite the failing field; got: {msg}"
        );
    }

    #[test]
    fn extract_display_omits_field_path_segment_when_empty() {
        // Bare Figment::new() extraction failure has no path; ensure the
        // segment is omitted (no stray `at field`` `` slot, no double colons).
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(!msg.contains("at field"), "no path → no `at field` segment");
        assert!(msg.contains("[layers: defaults]:"));
    }

    // ---- failing_source() tests ----

    fn extract_error_with_file_path_failure() -> (tempfile::TempDir, ShikumiError) {
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("typed.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_env("FAILING_SRC_FILE_NOTSET_")
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        (dir, err)
    }

    #[test]
    fn failing_source_pins_file_layer_for_typed_file_failure() {
        let (dir, err) = extract_error_with_file_path_failure();
        let s = err
            .failing_source()
            .expect("Extract attributes failure to a recorded source");
        assert!(s.is_file(), "expected failing source to be a file layer");
        assert_eq!(s.as_path(), Some(dir.path().join("typed.yaml").as_path()));
    }

    #[test]
    fn failing_source_pins_env_layer_when_env_provides_offending_field() {
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let var = "FAILSRC_ENV_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_env("FAILSRC_ENV_")
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };

        let s = err
            .failing_source()
            .expect("env-only failure must attribute to the env layer");
        assert!(s.is_env(), "expected failing source to be the env layer");
        assert_eq!(s.as_env_prefix(), Some("FAILSRC_ENV_"));
    }

    #[test]
    fn failing_source_distinguishes_env_from_file_in_layered_chain() {
        // Both env and file are present; only env supplies `count`.
        // figment's per-value metadata pins the failure to env, not file.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("ok.yaml");
        std::fs::write(&file, "name: present\n").unwrap();

        let var = "FAILSRC_DISCRIM_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_file(&file)
            .with_env("FAILSRC_DISCRIM_")
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };

        let s = err
            .failing_source()
            .expect("Extract must attribute the failure");
        assert_eq!(
            s.as_env_prefix(),
            Some("FAILSRC_DISCRIM_"),
            "env (the actual offender) must win over the unrelated file layer"
        );
    }

    #[test]
    fn failing_source_none_for_figment_variant() {
        // `Figment` carries no recorded chain; `failing_source` requires
        // a chain to resolve into, so it returns None even if the
        // wrapped error has metadata.
        let err = ShikumiError::Figment(fake_figment_error());
        assert!(err.failing_source().is_none());
    }

    #[test]
    fn failing_source_none_for_non_figment_variants() {
        assert!(
            ShikumiError::Parse("x".to_owned())
                .failing_source()
                .is_none()
        );
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .failing_source()
            .is_none()
        );
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let io_err: ShikumiError = io.into();
        assert!(io_err.failing_source().is_none());
    }

    #[test]
    fn failing_source_none_when_no_metadata_attached() {
        // Manually constructed figment::Error has no metadata; even with
        // a recorded chain, attribution cannot be resolved.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults, ConfigSource::Env("X_".to_owned())],
            error: fake_figment_error(),
        };
        assert!(
            err.failing_source().is_none(),
            "no metadata → no attribution"
        );
    }

    #[test]
    fn failing_source_none_when_chain_missing_matching_entry() {
        // Build a figment error whose metadata points at a file path that
        // is *not* in the recorded chain. The resolver must not fabricate
        // a match.
        let (_dir, real) = extract_error_with_file_path_failure();
        let ShikumiError::Extract { error: inner, .. } = real else {
            unreachable!();
        };
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults], // no File entry
            error: inner,
        };
        assert!(err.failing_source().is_none());
    }

    #[test]
    fn extract_display_includes_failing_source_segment_when_known() {
        let (dir, err) = extract_error_with_file_path_failure();
        let path_disp = dir.path().join("typed.yaml").display().to_string();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("from file({path_disp})")),
            "rendered error must cite the failing layer; got: {msg}"
        );
    }

    #[test]
    fn extract_display_omits_failing_source_segment_when_unknown() {
        // No metadata attached → no `from <src>` segment.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(
            !msg.contains(" from "),
            "no attribution → no `from` segment; got: {msg}"
        );
    }

    #[test]
    fn extract_display_orders_segments_layers_then_from_then_field() {
        let (_dir, err) = extract_error_with_file_path_failure();
        let msg = err.to_string();
        let l = msg.find("[layers:").expect("layers segment");
        let f = msg.find(" from ").expect("from segment");
        let a = msg.find(" at field ").expect("field segment");
        assert!(l < f && f < a, "segment order: layers -> from -> at field");
    }

    #[test]
    fn failing_source_env_match_is_case_insensitive() {
        // figment uppercases prefixes when emitting metadata names; our
        // recorded ConfigSource keeps the original casing. Ensure the
        // resolver bridges both.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let var = "FAILSRC_CASE_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_env("failsrc_case_") // lowercase user input
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };
        let s = err.failing_source().expect("env attribution");
        assert_eq!(s.as_env_prefix(), Some("failsrc_case_"));
    }

    #[test]
    fn field_path_preserves_dotted_segments_via_with_path() {
        // figment's Error::with_path splits on '.'; verify the accessor
        // preserves segment shape rather than collapsing back to a string.
        let raw = figment::Error::from("typed".to_owned()).with_path("window.size");
        let err = ShikumiError::Extract {
            sources: vec![],
            error: Box::new(raw),
        };
        let path = err.field_path().expect("Extract exposes field path");
        assert_eq!(
            path,
            &["window".to_owned(), "size".to_owned()],
            "segments must be preserved, not collapsed"
        );
        // And Display joins them with '.' for the human-readable form.
        assert!(err.to_string().contains("at field `window.size`"));
    }

    // ---- failing_attribution() / AttributionRule tests ----

    /// Synthesize a `figment::Error` pre-tagged with the given metadata
    /// name. Used to drive resolver paths that depend on
    /// `metadata.name`-shape (`FileByMetadataName`, `Env*`) without
    /// needing a live shikumi-built provider in the test process.
    fn synthetic_error_with_metadata_name(name: &'static str) -> Box<figment::Error> {
        let mut e = figment::Error::from("synth".to_owned());
        e.metadata = Some(figment::Metadata::named(name));
        Box::new(e)
    }

    #[test]
    fn failing_attribution_rule_file_by_source_for_yaml_extract() {
        // figment's built-in YAML provider attaches Source::File; the
        // resolver matches by path equality and reports FileBySource.
        let (dir, err) = extract_error_with_file_path_failure();
        let attr = err
            .failing_attribution()
            .expect("typed file failure must attribute");
        assert_eq!(attr.rule, AttributionRule::FileBySource);
        assert_eq!(
            attr.source.as_path(),
            Some(dir.path().join("typed.yaml").as_path())
        );
    }

    #[test]
    fn failing_attribution_rule_file_by_metadata_name_for_shikumi_provider() {
        // shikumi-built providers tag attribution via
        // `metadata.name = "<format>: <path>"`. The resolver inverts via
        // `Format::strip_metadata_name` and reports FileByMetadataName.
        let path = PathBuf::from("/etc/app/app.nix");
        let name = "nix: /etc/app/app.nix";
        let chain = vec![ConfigSource::Defaults, ConfigSource::File(path.clone())];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name(name),
        };
        let attr = err
            .failing_attribution()
            .expect("shikumi-provider tag must attribute");
        assert_eq!(attr.rule, AttributionRule::FileByMetadataName);
        assert_eq!(attr.source.as_path(), Some(path.as_path()));
    }

    #[test]
    fn failing_attribution_rule_env_by_prefix_when_chain_has_matching_env() {
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
            ConfigSource::Env("OTHER_".to_owned()),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`MYAPP_` environment variable(s)"),
        };
        let attr = err
            .failing_attribution()
            .expect("env-prefix tag must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByPrefix);
        assert_eq!(attr.source.as_env_prefix(), Some("MYAPP_"));
    }

    #[test]
    fn failing_attribution_rule_env_by_uniqueness_for_unmatched_prefix() {
        // Tag carries a prefix the chain doesn't record, but exactly one
        // Env entry exists — fall back to EnvByUniqueness on that entry.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`UNRELATED_` environment variable(s)"),
        };
        let attr = err
            .failing_attribution()
            .expect("unique-env fallback must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.source.as_env_prefix(), Some("ONLY_"));
    }

    #[test]
    fn failing_attribution_rule_env_by_uniqueness_for_bare_env_tag() {
        // Bare env tag (figment's Env::raw shape): no prefix to match;
        // unique Env entry wins via EnvByUniqueness.
        let chain = vec![ConfigSource::Env("BARE_".to_owned())];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("environment variable(s)"),
        };
        let attr = err.failing_attribution().expect("bare-env must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.source.as_env_prefix(), Some("BARE_"));
    }

    #[test]
    fn failing_attribution_rule_defaults_by_code_uniqueness_for_serialized() {
        // figment's Serialized provider attaches Source::Code; the
        // resolver dispatches to defaults-by-code-uniqueness when
        // exactly one Defaults layer is recorded.
        use crate::provider::ProviderChain;
        use serde::Serialize;
        #[derive(Serialize)]
        struct Bad {
            count: String, // typed mismatch when extracted as Cfg::count: u32
        }
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let attr = err
            .failing_attribution()
            .expect("defaults-only failure must attribute");
        assert_eq!(attr.rule, AttributionRule::DefaultsByCodeUniqueness);
        assert!(attr.source.is_defaults());
    }

    #[test]
    fn failing_attribution_none_for_no_metadata() {
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults, ConfigSource::Env("X_".to_owned())],
            error: fake_figment_error(),
        };
        assert!(err.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_none_when_chain_lacks_matching_entry() {
        // metadata.name names a file the chain doesn't carry, and no
        // env / defaults fallback applies — must be None, not fabricated.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::File(PathBuf::from("/other.yaml"))],
            error: synthetic_error_with_metadata_name("nix: /etc/app/app.nix"),
        };
        assert!(err.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_borrows_into_chain() {
        // The envelope's source must be a sub-borrow of the recorded
        // chain — not a fresh allocation, not a clone.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("BORROWED_".to_owned()),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`BORROWED_` environment variable(s)"),
        };
        let ShikumiError::Extract {
            sources: ref recorded,
            ..
        } = err
        else {
            unreachable!();
        };
        let recorded_ptr = recorded.as_ptr();
        let attr = err.failing_attribution().expect("attribution");
        let attr_ptr = std::ptr::from_ref::<ConfigSource>(attr.source);
        // attr.source must point inside the recorded Vec (specifically,
        // at the second entry).
        unsafe {
            assert_eq!(attr_ptr, recorded_ptr.add(1));
        }
    }

    #[test]
    fn failing_source_agrees_with_failing_attribution_source() {
        // The legacy `failing_source` helper must equal the envelope's
        // `.source` field on every attributed Extract.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        let legacy = err.failing_source().expect("legacy attribution");
        assert!(std::ptr::eq(attr.source, legacy));
    }

    #[test]
    fn failing_attribution_rule_resolution_order_prefers_file_by_source_over_name() {
        // If both a Source::File classification and a metadata-name match
        // could resolve, the source-axis rule wins (it's tried first).
        // Synthesize a metadata that has *both* a Source::File pointing
        // at one chain entry and a name pointing at a *different* chain
        // entry — observe the source-axis rule fires.
        let path_a = PathBuf::from("/a/app.yaml");
        let path_b = PathBuf::from("/b/app.nix");
        let chain = vec![
            ConfigSource::File(path_a.clone()),
            ConfigSource::File(path_b.clone()),
        ];
        let mut e = figment::Error::from("synth".to_owned());
        let mut md = figment::Metadata::named("nix: /b/app.nix");
        md.source = Some(figment::Source::File(path_a.clone()));
        e.metadata = Some(md);
        let err = ShikumiError::Extract {
            sources: chain,
            error: Box::new(e),
        };
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::FileBySource);
        assert_eq!(attr.source.as_path(), Some(path_a.as_path()));
    }

    #[test]
    fn attribution_rule_is_copy_and_hashable() {
        // The enum is part of the typescape; the trait bounds match the
        // sibling primitives (FigmentSourceTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributionRule::FileBySource);
        set.insert(AttributionRule::FileByMetadataName);
        set.insert(AttributionRule::EnvByPrefix);
        set.insert(AttributionRule::EnvByUniqueness);
        set.insert(AttributionRule::DefaultsByCodeUniqueness);
        assert_eq!(set.len(), AttributionRule::ALL.len());
        // Copy: rebind without move.
        let r = AttributionRule::FileBySource;
        let r2 = r;
        let r3 = r;
        assert_eq!(r, r2);
        assert_eq!(r2, r3);
    }

    // ---- AttributionConfidence / AttributionRule::confidence tests ----

    #[test]
    fn attribution_rule_confidence_exact_for_equality_rules() {
        // The three equality-based rules — file-path equality (both
        // axes) and env-prefix equality — must classify as Exact.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
        ] {
            assert_eq!(rule.confidence(), AttributionConfidence::Exact);
            assert!(rule.is_exact());
            assert!(!rule.is_fallback());
        }
    }

    #[test]
    fn attribution_rule_confidence_fallback_for_uniqueness_rules() {
        // The two uniqueness-based rules — env-by-uniqueness and
        // defaults-by-code-uniqueness — must classify as Fallback.
        for rule in [
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_eq!(rule.confidence(), AttributionConfidence::Fallback);
            assert!(rule.is_fallback());
            assert!(!rule.is_exact());
        }
    }

    #[test]
    fn attribution_rule_confidence_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // AttributionConfidence variant — no rule may be both exact and
        // fallback, none may be neither. Pins the partition contract
        // that the typescape lifts: a future variant added to
        // AttributionRule forces a confidence assignment in the
        // exhaustive match (compile-time), and this test pins the
        // resulting partition (test-time).
        for rule in AttributionRule::ALL.iter().copied() {
            assert_ne!(
                rule.is_exact(),
                rule.is_fallback(),
                "rule {rule:?} must be exactly one of exact / fallback"
            );
        }
    }

    #[test]
    fn attribution_confidence_is_copy_and_hashable() {
        // Typescape bounds parity with sibling primitives.
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for c in AttributionConfidence::ALL.iter().copied() {
            set.insert(c);
        }
        set.insert(AttributionConfidence::Exact); // duplicate
        assert_eq!(set.len(), AttributionConfidence::ALL.len());
        // Copy: rebind without move.
        let c = AttributionConfidence::Exact;
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn failing_source_attribution_confidence_mirrors_rule_confidence() {
        // The envelope's confidence() method must agree with the
        // rule's, byte-for-byte, on every recognized rule. Pins the
        // contract that the convenience accessor stays a thin
        // forwarder.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.confidence(), rule.confidence());
        }
    }

    #[test]
    fn failing_attribution_confidence_exact_for_yaml_extract() {
        // End-to-end: a real YAML-file extract failure attributes via
        // FileBySource (Exact). The envelope's confidence accessor
        // must surface that without the consumer destructuring the
        // rule.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.confidence(), AttributionConfidence::Exact);
        assert!(attr.confidence() == attr.rule.confidence());
    }

    // ---- AttributionConfidence::ALL cover / partition / order ----

    #[test]
    fn attribution_confidence_all_has_no_duplicates() {
        // The constant must be a set — no variant listed twice. Pins
        // the typescape discipline shared with `Format::ALL`,
        // `ShikumiErrorKind::ALL`, `AttributionRule::ALL`,
        // `ConfigSourceKind::ALL`, `FieldPathLocalization::ALL`,
        // `FormatProvenance::ALL`, and `AttributionAxis::ALL`: the
        // closed-enum `ALL` constant is a deduplicated `'static`
        // slice.
        use std::collections::HashSet;
        let set: HashSet<AttributionConfidence> =
            AttributionConfidence::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            AttributionConfidence::ALL.len(),
            "AttributionConfidence::ALL must contain no duplicates; got: {:?}",
            AttributionConfidence::ALL,
        );
    }

    #[test]
    fn attribution_confidence_all_covers_every_rule_confidence() {
        // Every confidence produced by AttributionRule::confidence
        // over AttributionRule::ALL must lie in
        // AttributionConfidence::ALL. Pins the cross-axis cover law:
        // the rule space cannot manufacture a confidence outside the
        // declared confidence enumeration. A future rule that adds a
        // new confidence class must extend AttributionConfidence and
        // its ALL in the same commit; otherwise this test fails.
        use std::collections::HashSet;
        let declared: HashSet<AttributionConfidence> =
            AttributionConfidence::ALL.iter().copied().collect();
        let observed: HashSet<AttributionConfidence> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::confidence)
            .collect();
        assert!(
            observed.is_subset(&declared),
            "AttributionRule::confidence image must lie in AttributionConfidence::ALL; \
             observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn attribution_confidence_all_equals_rule_confidence_image() {
        // Tight equality (stronger than subset cover): every variant
        // in AttributionConfidence::ALL must be witnessed by at least
        // one rule's confidence() — no orphan variant in the
        // declared confidence space lacks a producing rule. Today the
        // two confidence variants are both reached (Exact by the
        // three equality rules, Fallback by the two uniqueness
        // rules); this test pins that contract.
        use std::collections::HashSet;
        let declared: HashSet<AttributionConfidence> =
            AttributionConfidence::ALL.iter().copied().collect();
        let observed: HashSet<AttributionConfidence> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::confidence)
            .collect();
        assert_eq!(
            observed, declared,
            "AttributionRule::confidence image must equal AttributionConfidence::ALL",
        );
    }

    #[test]
    fn attribution_confidence_all_cardinality_matches_partition() {
        // The constant's cardinality must equal the number of
        // distinct confidence cells produced by the rule space —
        // pins that ALL is sized to the partition, not to a stale
        // hand-typed count. A future variant added to
        // AttributionConfidence without a rule that witnesses it
        // (or vice versa) breaks this equality.
        use std::collections::HashSet;
        let cells: HashSet<AttributionConfidence> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::confidence)
            .collect();
        assert_eq!(
            AttributionConfidence::ALL.len(),
            cells.len(),
            "AttributionConfidence::ALL cardinality must match partition cell count",
        );
    }

    #[test]
    fn attribution_confidence_all_declaration_order_is_exact_then_fallback() {
        // Pin declaration order. Consumers (diagnostics legends,
        // attestation manifests, dashboard column orderings) that
        // iterate ALL get a stable order; reordering the slice is a
        // breaking change that must show up here.
        assert_eq!(
            AttributionConfidence::ALL,
            &[
                AttributionConfidence::Exact,
                AttributionConfidence::Fallback,
            ],
        );
    }

    #[test]
    fn attribution_confidence_all_partition_is_exact_xor_fallback() {
        // Boolean partition: `is_exact` and `is_fallback` over a rule
        // sliced by each confidence cell must agree with the cell's
        // identity. Pins that AttributionConfidence::ALL is a
        // partition of the rule space's confidence image — every
        // rule lands in exactly one cell, and the boolean accessors
        // agree.
        for confidence in AttributionConfidence::ALL.iter().copied() {
            let witnessing_rule = AttributionRule::ALL
                .iter()
                .copied()
                .find(|rule| rule.confidence() == confidence)
                .expect("every confidence cell must be witnessed by some rule");
            match confidence {
                AttributionConfidence::Exact => {
                    assert!(witnessing_rule.is_exact());
                    assert!(!witnessing_rule.is_fallback());
                }
                AttributionConfidence::Fallback => {
                    assert!(witnessing_rule.is_fallback());
                    assert!(!witnessing_rule.is_exact());
                }
            }
        }
    }

    #[test]
    fn attribution_confidence_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on AttributionConfidence::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Exact", switching "fallback" to
        // "unique", prefixing "confidence-exact") fails here before
        // drifting through the trait-uniform round-trip law and the
        // operator-facing rendering surface. The two single-word
        // labels follow the lowercase convention shared with
        // ConfigSourceKind / FigmentSourceKind on the kind axes.
        assert_eq!(AttributionConfidence::Exact.as_str(), "exact");
        assert_eq!(AttributionConfidence::Fallback.as_str(), "fallback");
    }

    #[test]
    fn attribution_confidence_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // AttributionConfidence: each canonical lowercase name parses
        // back to its variant via the ClosedAxisLabel default impl.
        // The canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the AttributionConfidence site
        // so a future override of `from_canonical_str` (none today)
        // is still held to the law. Mixed-case forms an operator
        // might type in an env var or CLI flag (`"Exact"`,
        // `"FALLBACK"`) round-trip case-insensitively. Unrecognized
        // strings — including `"exact "` (trailing whitespace) and
        // `"fall"` (a prefix drift from `"fallback"`) — reject.
        use crate::ClosedAxisLabel;
        for c in AttributionConfidence::ALL.iter().copied() {
            assert_eq!(
                <AttributionConfidence as ClosedAxisLabel>::from_canonical_str(c.as_str()),
                Some(c),
                "trait from_canonical_str must round-trip for {c:?}",
            );
        }
        assert_eq!(
            <AttributionConfidence as ClosedAxisLabel>::from_canonical_str("Exact"),
            Some(AttributionConfidence::Exact),
        );
        assert_eq!(
            <AttributionConfidence as ClosedAxisLabel>::from_canonical_str("FALLBACK"),
            Some(AttributionConfidence::Fallback),
        );
        assert_eq!(
            <AttributionConfidence as ClosedAxisLabel>::from_canonical_str("exact "),
            None,
        );
        assert_eq!(
            <AttributionConfidence as ClosedAxisLabel>::from_canonical_str("fall"),
            None,
        );
    }

    #[test]
    fn attribution_axis_as_str_yields_canonical_kebab_case_names() {
        // Concrete-position pin on AttributionAxis::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "MetadataSource", switching
        // "metadata-name" to "name", dropping the "metadata-" prefix,
        // collapsing the hyphen to "metadatasource") fails here before
        // drifting through the trait-uniform round-trip law and the
        // operator-facing rendering surface. The two compound-noun
        // labels follow the kebab-case convention shared with
        // FormatProvenance ("figment-builtin"/"shikumi-built") — the
        // hyphen separates the metadata-namespace prefix from the
        // axis-name suffix, distinguishing the canonical names from
        // the kind-axis prefix ("source") shared by ConfigSourceKind
        // and FigmentSourceKind.
        assert_eq!(AttributionAxis::MetadataSource.as_str(), "metadata-source");
        assert_eq!(AttributionAxis::MetadataName.as_str(), "metadata-name");
    }

    #[test]
    fn attribution_axis_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // AttributionAxis: each canonical kebab-case name parses back
        // to its variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the AttributionAxis site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law. Mixed-case forms an operator might
        // type in an env var or CLI flag (`"Metadata-Source"`,
        // `"METADATA-NAME"`) round-trip case-insensitively.
        // Unrecognized strings — including `"metadata-source "`
        // (trailing whitespace), `"source"` (the bare kind-axis
        // prefix shared with ConfigSourceKind / FigmentSourceKind,
        // structurally distinct from the metadata-axis label), and
        // `"metadata_source"` (underscore instead of hyphen) —
        // reject.
        use crate::ClosedAxisLabel;
        for axis in AttributionAxis::ALL.iter().copied() {
            assert_eq!(
                <AttributionAxis as ClosedAxisLabel>::from_canonical_str(axis.as_str()),
                Some(axis),
                "trait from_canonical_str must round-trip for {axis:?}",
            );
        }
        assert_eq!(
            <AttributionAxis as ClosedAxisLabel>::from_canonical_str("Metadata-Source"),
            Some(AttributionAxis::MetadataSource),
        );
        assert_eq!(
            <AttributionAxis as ClosedAxisLabel>::from_canonical_str("METADATA-NAME"),
            Some(AttributionAxis::MetadataName),
        );
        assert_eq!(
            <AttributionAxis as ClosedAxisLabel>::from_canonical_str("metadata-source "),
            None,
        );
        assert_eq!(
            <AttributionAxis as ClosedAxisLabel>::from_canonical_str("source"),
            None,
        );
        assert_eq!(
            <AttributionAxis as ClosedAxisLabel>::from_canonical_str("metadata_source"),
            None,
        );
    }

    #[test]
    fn shikumi_error_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on ShikumiErrorKind::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "NotFound", switching "figment" to
        // "raw-figment", dropping the "not-" prefix on
        // ShikumiErrorKind::NotFound, collapsing "not-found" to
        // "notfound") fails here before drifting through the
        // trait-uniform round-trip law and the operator-facing
        // rendering surface. The single compound-noun variant
        // (ShikumiErrorKind::NotFound) follows the kebab-case
        // convention shared with FormatProvenance
        // ("figment-builtin"/"shikumi-built") and AttributionAxis
        // ("metadata-source"/"metadata-name"); the remaining five
        // single-word variants follow the lowercase convention shared
        // with ConfigSourceKind, FigmentSourceKind, Format, and
        // AttributionConfidence.
        assert_eq!(ShikumiErrorKind::NotFound.as_str(), "not-found");
        assert_eq!(ShikumiErrorKind::Parse.as_str(), "parse");
        assert_eq!(ShikumiErrorKind::Watch.as_str(), "watch");
        assert_eq!(ShikumiErrorKind::Io.as_str(), "io");
        assert_eq!(ShikumiErrorKind::Figment.as_str(), "figment");
        assert_eq!(ShikumiErrorKind::Extract.as_str(), "extract");
    }

    #[test]
    fn shikumi_error_kind_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // ShikumiErrorKind: each canonical name parses back to its
        // variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the ShikumiErrorKind site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law. Mixed-case forms an operator might
        // type in an env var or CLI flag (`"Not-Found"`, `"PARSE"`,
        // `"IO"`) round-trip case-insensitively. Unrecognized strings
        // — including `"notfound"` (collapsed without hyphen,
        // structurally distinct from the canonical kebab form),
        // `"parse "` (trailing whitespace), and `"err"` (an
        // unrecognized prefix) — reject.
        use crate::ClosedAxisLabel;
        for kind in ShikumiErrorKind::ALL.iter().copied() {
            assert_eq!(
                <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str(kind.as_str()),
                Some(kind),
                "trait from_canonical_str must round-trip for {kind:?}",
            );
        }
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("Not-Found"),
            Some(ShikumiErrorKind::NotFound),
        );
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("PARSE"),
            Some(ShikumiErrorKind::Parse),
        );
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("IO"),
            Some(ShikumiErrorKind::Io),
        );
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("notfound"),
            None,
        );
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("parse "),
            None,
        );
        assert_eq!(
            <ShikumiErrorKind as ClosedAxisLabel>::from_canonical_str("err"),
            None,
        );
    }

    #[test]
    fn field_path_localization_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on FieldPathLocalization::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. capitalizing "Localized", switching "not-applicable"
        // to "n-a", collapsing "figment-unlocalized" to
        // "figmentunlocalized") fails here before drifting through the
        // trait-uniform round-trip law and the operator-facing
        // rendering surface. The two compound-noun variants
        // (FigmentUnlocalized, NotApplicable) follow the kebab-case
        // convention shared with ShikumiErrorKind ("not-found"),
        // FormatProvenance ("figment-builtin"/"shikumi-built"), and
        // AttributionAxis ("metadata-source"/"metadata-name"); the
        // remaining single-word variant (Localized) follows the
        // lowercase convention shared with ConfigSourceKind,
        // FigmentSourceKind, Format, and AttributionConfidence.
        assert_eq!(FieldPathLocalization::Localized.as_str(), "localized");
        assert_eq!(
            FieldPathLocalization::FigmentUnlocalized.as_str(),
            "figment-unlocalized",
        );
        assert_eq!(
            FieldPathLocalization::NotApplicable.as_str(),
            "not-applicable",
        );
    }

    #[test]
    fn field_path_localization_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // FieldPathLocalization: each canonical name parses back to
        // its variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the FieldPathLocalization site
        // so a future override of `from_canonical_str` (none today)
        // is still held to the law. Mixed-case forms an operator
        // might type in an env var or CLI flag (`"Localized"`,
        // `"FIGMENT-UNLOCALIZED"`, `"Not-Applicable"`) round-trip
        // case-insensitively. Unrecognized strings — including
        // `"figmentunlocalized"` (collapsed without hyphen,
        // structurally distinct from the canonical kebab form),
        // `"localized "` (trailing whitespace), and `"unlocalized"`
        // (an unrecognized prefix-suffix collision) — reject.
        use crate::ClosedAxisLabel;
        for loc in FieldPathLocalization::ALL.iter().copied() {
            assert_eq!(
                <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str(loc.as_str()),
                Some(loc),
                "trait from_canonical_str must round-trip for {loc:?}",
            );
        }
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("Localized"),
            Some(FieldPathLocalization::Localized),
        );
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("FIGMENT-UNLOCALIZED"),
            Some(FieldPathLocalization::FigmentUnlocalized),
        );
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("Not-Applicable"),
            Some(FieldPathLocalization::NotApplicable),
        );
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("figmentunlocalized"),
            None,
        );
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("localized "),
            None,
        );
        assert_eq!(
            <FieldPathLocalization as ClosedAxisLabel>::from_canonical_str("unlocalized"),
            None,
        );
    }

    #[test]
    fn attribution_rule_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on AttributionRule::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. dropping the `-by-` infix on `EnvByPrefix` to
        // `"env-prefix"`, collapsing `"defaults-by-code-uniqueness"` to
        // `"defaults"`, capitalizing the type-segment names) fails
        // here before drifting through the trait-uniform round-trip
        // law and the operator-facing rendering surface. All five
        // variants follow the kebab-case convention shared with
        // ShikumiErrorKind ("not-found"), FieldPathLocalization
        // ("figment-unlocalized"/"not-applicable"), FormatProvenance
        // ("figment-builtin"/"shikumi-built"), and AttributionAxis
        // ("metadata-source"/"metadata-name"); the kebab segments
        // align with the rule's typed projections (`layer_kind` →
        // leading segment, `metadata_axis` / dispatch shape → trailing
        // segments).
        assert_eq!(AttributionRule::FileBySource.as_str(), "file-by-source");
        assert_eq!(
            AttributionRule::FileByMetadataName.as_str(),
            "file-by-metadata-name",
        );
        assert_eq!(AttributionRule::EnvByPrefix.as_str(), "env-by-prefix");
        assert_eq!(
            AttributionRule::EnvByUniqueness.as_str(),
            "env-by-uniqueness",
        );
        assert_eq!(
            AttributionRule::DefaultsByCodeUniqueness.as_str(),
            "defaults-by-code-uniqueness",
        );
    }

    #[test]
    fn attribution_rule_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // AttributionRule: each canonical name parses back to its
        // variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the AttributionRule site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law. Mixed-case forms an operator might
        // type in an env var or CLI flag (`"File-By-Source"`,
        // `"ENV-BY-PREFIX"`, `"Defaults-By-Code-Uniqueness"`)
        // round-trip case-insensitively. Unrecognized strings —
        // including `"filebysource"` (collapsed without hyphens,
        // structurally distinct from the canonical kebab form),
        // `"file-by-source "` (trailing whitespace), and
        // `"file-by"` (an unrecognized prefix) — reject.
        use crate::ClosedAxisLabel;
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                <AttributionRule as ClosedAxisLabel>::from_canonical_str(rule.as_str()),
                Some(rule),
                "trait from_canonical_str must round-trip for {rule:?}",
            );
        }
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("File-By-Source"),
            Some(AttributionRule::FileBySource),
        );
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("ENV-BY-PREFIX"),
            Some(AttributionRule::EnvByPrefix),
        );
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("Defaults-By-Code-Uniqueness"),
            Some(AttributionRule::DefaultsByCodeUniqueness),
        );
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("filebysource"),
            None,
        );
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("file-by-source "),
            None,
        );
        assert_eq!(
            <AttributionRule as ClosedAxisLabel>::from_canonical_str("file-by"),
            None,
        );
    }

    #[test]
    fn failing_source_attribution_confidence_image_lies_in_all() {
        // Cross-envelope cover law: every confidence surfaced by
        // FailingSourceAttribution::confidence over the rule space
        // must lie in AttributionConfidence::ALL. Pins that the
        // envelope's accessor cannot manufacture a confidence outside
        // the declared confidence enumeration — peer to the
        // analogous law `failing_source_attribution_metadata_axis_*`
        // for AttributionAxis::ALL.
        use std::collections::HashSet;
        let src = ConfigSource::Defaults;
        let observed: HashSet<AttributionConfidence> = AttributionRule::ALL
            .iter()
            .copied()
            .map(|rule| FailingSourceAttribution::new(&src, rule).confidence())
            .collect();
        let declared: HashSet<AttributionConfidence> =
            AttributionConfidence::ALL.iter().copied().collect();
        assert!(
            observed.is_subset(&declared),
            "every confidence surfaced by FailingSourceAttribution::confidence must lie in \
             AttributionConfidence::ALL; observed: {observed:?}, declared: {declared:?}",
        );
    }

    // ---- AttributionRule::layer_kind / FailingSourceAttribution::layer_kind ----

    #[test]
    fn attribution_rule_layer_kind_file_for_file_axis_rules() {
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
        ] {
            assert_eq!(rule.layer_kind(), ConfigSourceKind::File);
        }
    }

    #[test]
    fn attribution_rule_layer_kind_env_for_env_axis_rules() {
        for rule in [
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            assert_eq!(rule.layer_kind(), ConfigSourceKind::Env);
        }
    }

    #[test]
    fn attribution_rule_layer_kind_defaults_for_defaults_axis_rule() {
        assert_eq!(
            AttributionRule::DefaultsByCodeUniqueness.layer_kind(),
            ConfigSourceKind::Defaults,
        );
    }

    #[test]
    fn attribution_rule_layer_kind_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // ConfigSourceKind. Pins the partition contract that
        // AttributionRule::layer_kind is a total function over the
        // rule space; a future variant added to AttributionRule
        // forces a kind assignment in the exhaustive match
        // (compile-time), and this test pins the kind choice for each
        // existing rule (test-time).
        let cases = [
            (AttributionRule::FileBySource, ConfigSourceKind::File),
            (AttributionRule::FileByMetadataName, ConfigSourceKind::File),
            (AttributionRule::EnvByPrefix, ConfigSourceKind::Env),
            (AttributionRule::EnvByUniqueness, ConfigSourceKind::Env),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                ConfigSourceKind::Defaults,
            ),
        ];
        for (rule, expected) in cases {
            assert_eq!(rule.layer_kind(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_rule_layer_kind_orthogonal_to_confidence() {
        // The (layer_kind × confidence) product over the rule space
        // must cover at least three distinct (kind, conf) pairs — the
        // two projections are orthogonal axes, not a single
        // partition. Pins the contract that adding a future variant
        // to one axis is independent of the other.
        use std::collections::HashSet;
        let mut pairs: HashSet<(ConfigSourceKind, AttributionConfidence)> = HashSet::new();
        for rule in AttributionRule::ALL.iter().copied() {
            pairs.insert((rule.layer_kind(), rule.confidence()));
        }
        // Today: (File, Exact), (Env, Exact), (Env, Fallback),
        // (Defaults, Fallback) — four distinct cells.
        assert!(
            pairs.len() >= 3,
            "kind × confidence must span ≥3 cells; got: {pairs:?}"
        );
    }

    #[test]
    fn failing_source_attribution_layer_kind_mirrors_rule_layer_kind() {
        // The envelope's layer_kind() must agree with the rule's,
        // byte-for-byte, on every recognized rule. Pins the contract
        // that the convenience accessor stays a thin forwarder.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.layer_kind(), rule.layer_kind());
        }
    }

    #[test]
    fn attribution_rule_layer_kind_agrees_with_source_kind() {
        // Cross-primitive invariant: for every constructible attributed
        // Extract, the rule's layer_kind() must equal the attributed
        // source's kind(). The resolver may only pair a rule with a
        // source of the matching kind; this test pins that discipline
        // across every resolver path the rest of this module exercises.
        use crate::provider::ProviderChain;
        use serde::Serialize;

        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }

        #[derive(Serialize)]
        struct Bad {
            count: String,
        }

        // FileBySource: figment's YAML provider attaches Source::File.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("kind_invariant.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let attr_file = err_file.failing_attribution().expect("file attribution");
        assert_eq!(attr_file.layer_kind(), attr_file.source.kind());
        assert_eq!(attr_file.layer_kind(), ConfigSourceKind::File);

        // EnvByPrefix: synthetic env-prefixed metadata-name with a
        // matching Env entry in the chain.
        let chain_env = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("KIND_INV_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain_env,
            error: synthetic_error_with_metadata_name("`KIND_INV_` environment variable(s)"),
        };
        let attr_env = err_env.failing_attribution().expect("env attribution");
        assert_eq!(attr_env.layer_kind(), attr_env.source.kind());
        assert_eq!(attr_env.layer_kind(), ConfigSourceKind::Env);

        // EnvByUniqueness: env tag with no matching prefix, unique Env
        // in chain.
        let chain_unique_env = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err_unique = ShikumiError::Extract {
            sources: chain_unique_env,
            error: synthetic_error_with_metadata_name("`UNRELATED_` environment variable(s)"),
        };
        let attr_unique = err_unique
            .failing_attribution()
            .expect("env-uniqueness attribution");
        assert_eq!(attr_unique.layer_kind(), attr_unique.source.kind());
        assert_eq!(attr_unique.layer_kind(), ConfigSourceKind::Env);

        // FileByMetadataName: synthetic shikumi-provider tag with a
        // matching File entry in the chain.
        let path_meta = PathBuf::from("/etc/app/app.nix");
        let chain_meta = vec![ConfigSource::File(path_meta.clone())];
        let err_meta = ShikumiError::Extract {
            sources: chain_meta,
            error: synthetic_error_with_metadata_name("nix: /etc/app/app.nix"),
        };
        let attr_meta = err_meta
            .failing_attribution()
            .expect("file-by-name attribution");
        assert_eq!(attr_meta.layer_kind(), attr_meta.source.kind());
        assert_eq!(attr_meta.layer_kind(), ConfigSourceKind::File);

        // DefaultsByCodeUniqueness: figment's Serialized provider
        // attaches Source::Code; defaults-only chain dispatches to
        // DefaultsByCodeUniqueness.
        let err_defaults = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let attr_defaults = err_defaults
            .failing_attribution()
            .expect("defaults attribution");
        assert_eq!(attr_defaults.layer_kind(), attr_defaults.source.kind());
        assert_eq!(attr_defaults.layer_kind(), ConfigSourceKind::Defaults);
    }

    #[test]
    fn failing_attribution_confidence_fallback_for_unmatched_env_prefix() {
        // End-to-end: a synthetic env-prefixed metadata name with no
        // matching env prefix in the chain falls back to
        // EnvByUniqueness (Fallback). The envelope reports Fallback.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`UNRELATED_` environment variable(s)"),
        };
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.confidence(), AttributionConfidence::Fallback);
    }

    // ---- ShikumiErrorKind / ShikumiError::kind tests ----

    fn one_per_kind() -> Vec<(ShikumiErrorKind, ShikumiError)> {
        vec![
            (
                ShikumiErrorKind::NotFound,
                ShikumiError::NotFound {
                    tried: vec![PathBuf::from("/a")],
                },
            ),
            (
                ShikumiErrorKind::Parse,
                ShikumiError::Parse("bad".to_owned()),
            ),
            (
                ShikumiErrorKind::Watch,
                ShikumiError::from(notify::Error::generic("test")),
            ),
            (
                ShikumiErrorKind::Io,
                ShikumiError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "x")),
            ),
            (
                ShikumiErrorKind::Figment,
                ShikumiError::Figment(fake_figment_error()),
            ),
            (
                ShikumiErrorKind::Extract,
                ShikumiError::Extract {
                    sources: vec![ConfigSource::Defaults],
                    error: fake_figment_error(),
                },
            ),
        ]
    }

    #[test]
    fn kind_classifies_every_variant() {
        for (expected, err) in one_per_kind() {
            assert_eq!(
                err.kind(),
                expected,
                "kind() must classify {err:?} as {expected:?}"
            );
        }
    }

    #[test]
    fn kind_partitions_every_variant() {
        // Each constructed error classifies into exactly one
        // ShikumiErrorKind — no error matches two kinds, none matches
        // none. Pins the partition contract that the typescape lifts:
        // a future ShikumiError variant forces both an exhaustive-match
        // assignment in `kind()` (compile-time) and a row in this
        // table (test-time).
        for (expected, err) in one_per_kind() {
            let matches: Vec<_> = ShikumiErrorKind::ALL
                .iter()
                .filter(|k| err.kind() == **k)
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "{err:?} must match exactly one kind (got {matches:?}, expected {expected:?})"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_not_found_pointwise() {
        // Pin the convenience-accessor forwarder contract: across every
        // variant, `is_not_found()` must agree byte-for-byte with the
        // typed-kind comparison.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_not_found(),
                err.kind() == ShikumiErrorKind::NotFound,
                "is_not_found must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_parse_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_parse(),
                err.kind() == ShikumiErrorKind::Parse,
                "is_parse must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn shikumi_error_kind_is_copy_and_hashable() {
        // Typescape bounds parity with the sibling closed-enum
        // primitives (AttributionRule, AttributionConfidence,
        // FigmentSourceTag, FigmentNameTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ShikumiErrorKind::NotFound);
        set.insert(ShikumiErrorKind::Parse);
        set.insert(ShikumiErrorKind::Watch);
        set.insert(ShikumiErrorKind::Io);
        set.insert(ShikumiErrorKind::Figment);
        set.insert(ShikumiErrorKind::Extract);
        set.insert(ShikumiErrorKind::NotFound); // duplicate — no growth
        assert_eq!(set.len(), 6, "every kind must hash distinctly");

        // Copy: rebind without move.
        let k = ShikumiErrorKind::Extract;
        let k2 = k;
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k2, k3);
    }

    // ---- ShikumiErrorKind::ALL tests ----

    #[test]
    fn shikumi_error_kind_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every variant appears
        // at most once. Pins the "no double-listed kind" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost kind contributing twice to a partition tally.
        use std::collections::HashSet;
        let unique: HashSet<ShikumiErrorKind> = ShikumiErrorKind::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ShikumiErrorKind::ALL.len(),
            "ShikumiErrorKind::ALL must contain no duplicates",
        );
    }

    #[test]
    fn shikumi_error_kind_all_covers_every_constructed_variant() {
        // The construction-table surface in `one_per_kind()` covers every
        // ShikumiError variant once. Pin the contract that every kind
        // ShikumiError::kind can return appears in ShikumiErrorKind::ALL,
        // and that ALL contains no extras: the mutual-cover statement
        // proves ALL is in 1-1 correspondence with the kind partition
        // surfaced by the variant set.
        use std::collections::HashSet;
        let produced: HashSet<ShikumiErrorKind> =
            one_per_kind().into_iter().map(|(k, _)| k).collect();
        let listed: HashSet<ShikumiErrorKind> = ShikumiErrorKind::ALL.iter().copied().collect();
        assert_eq!(
            produced, listed,
            "ShikumiErrorKind::ALL must equal the kind set produced by ShikumiError::kind",
        );
    }

    #[test]
    fn shikumi_error_kind_all_cardinality_matches_construction_table() {
        // Stronger statement of the prior test on the cardinality axis:
        // ALL.len() must equal the number of constructed-variant rows.
        // A future ShikumiError variant landing forces both an arm in
        // `kind()` (compile-time, exhaustive match) and a row in
        // `one_per_kind()` (test-time); this assertion fails until ALL
        // is extended in lockstep, catching forgotten ALL updates.
        assert_eq!(
            ShikumiErrorKind::ALL.len(),
            one_per_kind().len(),
            "ALL.len() must equal one_per_kind().len()",
        );
    }

    #[test]
    fn shikumi_error_kind_all_iterates_in_declaration_order() {
        // The constant lists variants in the same order as `kind()`'s
        // exhaustive match arms (NotFound, Parse, Watch, Io, Figment,
        // Extract). Iteration order is observable — consumers (alerting
        // policies, dashboards) that rely on a stable ordering for
        // priority/severity can route on it.
        assert_eq!(
            ShikumiErrorKind::ALL,
            &[
                ShikumiErrorKind::NotFound,
                ShikumiErrorKind::Parse,
                ShikumiErrorKind::Watch,
                ShikumiErrorKind::Io,
                ShikumiErrorKind::Figment,
                ShikumiErrorKind::Extract,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn shikumi_error_kind_all_partitions_figment_bearing_axis() {
        // ALL composes with is_figment_bearing as the universe over
        // which the figment-bearing partition is total: exactly two of
        // the listed kinds bear figment, the rest don't. Stated through
        // the constant rather than an inline literal.
        let bearing = ShikumiErrorKind::ALL
            .iter()
            .filter(|k| k.is_figment_bearing())
            .count();
        let non_bearing = ShikumiErrorKind::ALL
            .iter()
            .filter(|k| !k.is_figment_bearing())
            .count();
        assert_eq!(bearing, 2, "two ALL variants bear figment");
        assert_eq!(
            bearing + non_bearing,
            ShikumiErrorKind::ALL.len(),
            "the figment-bearing partition must cover ALL exactly once",
        );
    }

    #[test]
    fn kind_partitions_distinguish_extract_from_figment() {
        // The two figment-bearing variants — Extract (with chain) and
        // Figment (without) — must classify into distinct kinds, even
        // though they share field-path semantics. Pins the contract
        // that the kind axis is finer than the figment-bearing axis.
        let extract = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let figment = ShikumiError::Figment(fake_figment_error());
        assert_eq!(extract.kind(), ShikumiErrorKind::Extract);
        assert_eq!(figment.kind(), ShikumiErrorKind::Figment);
        assert_ne!(extract.kind(), figment.kind());
    }

    // ---- ShikumiErrorKind::is_figment_bearing tests ----

    #[test]
    fn is_figment_bearing_true_for_extract_and_figment() {
        // The two figment-wrapping kinds: Extract (with chain) and
        // Figment (without). Pins which kinds the localization axis
        // can possibly attach to.
        assert!(ShikumiErrorKind::Extract.is_figment_bearing());
        assert!(ShikumiErrorKind::Figment.is_figment_bearing());
    }

    #[test]
    fn is_figment_bearing_false_for_non_figment_kinds() {
        for kind in [
            ShikumiErrorKind::NotFound,
            ShikumiErrorKind::Parse,
            ShikumiErrorKind::Watch,
            ShikumiErrorKind::Io,
        ] {
            assert!(!kind.is_figment_bearing(), "{kind:?} must not bear figment");
        }
    }

    #[test]
    fn is_figment_bearing_partitions_every_kind() {
        // Every ShikumiErrorKind variant must classify into exactly one
        // figment-bearing cell — no kind may straddle, none may fall
        // through. Pins the typescape contract that the figment-bearing
        // axis is total over the kind partition; a future kind landing
        // forces an assignment in the exhaustive match.
        let bearing: Vec<_> = ShikumiErrorKind::ALL
            .iter()
            .filter(|k| k.is_figment_bearing())
            .collect();
        assert_eq!(
            bearing.len(),
            2,
            "exactly two kinds bear figment; got: {bearing:?}"
        );
    }

    #[test]
    fn is_figment_bearing_agrees_with_field_path_some_pointwise() {
        // Cross-primitive invariant: a kind is figment-bearing iff the
        // corresponding ShikumiError variant's field_path() returns
        // Some(_). The kind-axis predicate must agree with the
        // variant-axis behaviour byte-for-byte.
        for (kind, err) in one_per_kind() {
            assert_eq!(
                kind.is_figment_bearing(),
                err.field_path().is_some(),
                "is_figment_bearing must mirror field_path-some for {kind:?}"
            );
        }
    }

    // ---- FieldPathLocalization / field_path_localization tests ----

    #[test]
    fn field_path_localization_localized_for_extract_with_typed_field() {
        // A real Extract failure with a localized typed-mismatch field
        // classifies as Localized.
        let err = extract_error_with_typed_field_path();
        assert_eq!(
            err.field_path_localization(),
            FieldPathLocalization::Localized
        );
    }

    #[test]
    fn field_path_localization_unlocalized_for_extract_without_field() {
        // Bare Figment::new() failure wrapped in Extract: figment
        // attached no path. The error is figment-bearing but
        // unlocalized.
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        assert_eq!(
            err.field_path_localization(),
            FieldPathLocalization::FigmentUnlocalized
        );
    }

    #[test]
    fn field_path_localization_unlocalized_for_figment_without_field() {
        // Bare Figment variant: figment-bearing, no localized field.
        let err = ShikumiError::Figment(fake_figment_error());
        assert_eq!(
            err.field_path_localization(),
            FieldPathLocalization::FigmentUnlocalized
        );
    }

    #[test]
    fn field_path_localization_localized_for_figment_with_field() {
        // Figment variant carrying a localized path: still Localized,
        // because the localization axis is on the figment-bearing axis,
        // not the variant axis.
        let raw = figment::Error::from("typed".to_owned()).with_path("a.b");
        let err = ShikumiError::Figment(Box::new(raw));
        assert_eq!(
            err.field_path_localization(),
            FieldPathLocalization::Localized
        );
    }

    #[test]
    fn field_path_localization_not_applicable_for_non_figment_variants() {
        // The four non-figment-bearing kinds (Parse, NotFound, Watch,
        // Io) classify as NotApplicable — they don't carry a figment
        // error at all, so the localization axis simply does not apply.
        for err in [
            ShikumiError::Parse("x".to_owned()),
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")],
            },
            ShikumiError::from(notify::Error::generic("w")),
            ShikumiError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "x")),
        ] {
            assert_eq!(
                err.field_path_localization(),
                FieldPathLocalization::NotApplicable,
                "non-figment variant must classify as NotApplicable: {err:?}"
            );
        }
    }

    /// Canonical sample table: one [`ShikumiError`] per
    /// [`FieldPathLocalization`] cell. Mirrors `one_per_kind()` on the
    /// kind axis but pinned to the localization axis — every variant
    /// of `FieldPathLocalization::ALL` is the second tuple element of
    /// exactly one row.
    fn one_per_localization() -> Vec<(ShikumiError, FieldPathLocalization)> {
        vec![
            (
                ShikumiError::Extract {
                    sources: vec![],
                    error: Box::new(figment::Error::from("t".to_owned()).with_path("k")),
                },
                FieldPathLocalization::Localized,
            ),
            (
                ShikumiError::Extract {
                    sources: vec![],
                    error: fake_figment_error(),
                },
                FieldPathLocalization::FigmentUnlocalized,
            ),
            (
                ShikumiError::Parse("x".to_owned()),
                FieldPathLocalization::NotApplicable,
            ),
        ]
    }

    #[test]
    fn field_path_localization_partitions_every_variant() {
        // Every constructed error classifies into exactly one
        // FieldPathLocalization cell — no variant straddles, none falls
        // through. Pins the partition contract that the typescape
        // lifts: a future ShikumiError variant forces a classification
        // in field_path_localization() (compile-time via field_path's
        // exhaustive match) and a row in this table (test-time).
        for (err, expected) in one_per_localization() {
            let matches: Vec<_> = FieldPathLocalization::ALL
                .iter()
                .filter(|loc| err.field_path_localization() == **loc)
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "{err:?} must classify into exactly one cell (got {matches:?}, expected {expected:?})"
            );
            assert_eq!(err.field_path_localization(), expected);
        }
    }

    #[test]
    fn field_path_localization_agrees_with_field_path_pointwise() {
        // Cross-axis invariant: the typed projection mirrors the raw
        // tri-state of field_path() byte-for-byte. Pins the contract
        // that field_path_localization() is a pure projection of
        // field_path() — same partition, lifted to a closed enum.
        for (_, err) in one_per_kind() {
            let expected = match err.field_path() {
                Some(p) if !p.is_empty() => FieldPathLocalization::Localized,
                Some(_) => FieldPathLocalization::FigmentUnlocalized,
                None => FieldPathLocalization::NotApplicable,
            };
            assert_eq!(
                err.field_path_localization(),
                expected,
                "field_path_localization must mirror field_path() for {err:?}"
            );
        }
    }

    #[test]
    fn field_path_localization_is_copy_and_hashable() {
        // Typescape bounds parity with sibling closed-enum primitives
        // (ShikumiErrorKind, AttributionRule, AttributionConfidence,
        // FigmentSourceTag, FigmentNameTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FieldPathLocalization::Localized);
        set.insert(FieldPathLocalization::FigmentUnlocalized);
        set.insert(FieldPathLocalization::NotApplicable);
        set.insert(FieldPathLocalization::Localized); // duplicate — no growth
        assert_eq!(set.len(), 3, "every localization must hash distinctly");

        // Copy: rebind without move.
        let l = FieldPathLocalization::Localized;
        let l2 = l;
        let l3 = l;
        assert_eq!(l, l2);
        assert_eq!(l2, l3);
    }

    // ---- FieldPathLocalization::ALL tests ----

    #[test]
    fn field_path_localization_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every variant appears
        // at most once. Pins the "no double-listed cell" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost localization contributing twice to a partition tally.
        use std::collections::HashSet;
        let unique: HashSet<FieldPathLocalization> =
            FieldPathLocalization::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            FieldPathLocalization::ALL.len(),
            "FieldPathLocalization::ALL must contain no duplicates",
        );
    }

    #[test]
    fn field_path_localization_all_covers_every_constructed_localization() {
        // The canonical sample surface in `one_per_localization()` covers
        // every FieldPathLocalization cell once. Pin the contract that
        // every value field_path_localization() can return appears in
        // FieldPathLocalization::ALL, and that ALL contains no extras:
        // the mutual-cover statement proves ALL is in 1-1 correspondence
        // with the localization partition surfaced by the cell set.
        use std::collections::HashSet;
        let produced: HashSet<FieldPathLocalization> = one_per_localization()
            .into_iter()
            .map(|(_, loc)| loc)
            .collect();
        let listed: HashSet<FieldPathLocalization> =
            FieldPathLocalization::ALL.iter().copied().collect();
        assert_eq!(
            produced, listed,
            "FieldPathLocalization::ALL must equal the cell set produced by field_path_localization()",
        );
    }

    #[test]
    fn field_path_localization_all_cardinality_matches_canonical_table() {
        // Stronger statement of the prior test on the cardinality axis:
        // ALL.len() must equal the number of canonical-cell rows. A
        // future FieldPathLocalization variant landing forces both an
        // arm in `field_path_localization()` (compile-time, exhaustive
        // match on `field_path`'s tri-state) and a row in
        // `one_per_localization()` (test-time); this assertion fails
        // until ALL is extended in lockstep, catching forgotten ALL
        // updates.
        assert_eq!(
            FieldPathLocalization::ALL.len(),
            one_per_localization().len(),
            "ALL.len() must equal one_per_localization().len()",
        );
    }

    #[test]
    fn field_path_localization_all_iterates_in_declaration_order() {
        // The constant lists variants in the same order as the enum's
        // declaration (Localized, FigmentUnlocalized, NotApplicable).
        // Iteration order is observable — consumers (alerting policies,
        // dashboards, structured-diagnostics legends) that rely on a
        // stable ordering for confidence ranking — Localized strongest,
        // NotApplicable weakest — can route on it.
        assert_eq!(
            FieldPathLocalization::ALL,
            &[
                FieldPathLocalization::Localized,
                FieldPathLocalization::FigmentUnlocalized,
                FieldPathLocalization::NotApplicable,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn field_path_localization_all_partitions_figment_bearing_axis() {
        // ALL composes with the kind/figment-bearing axis: exactly two
        // of the listed cells (Localized, FigmentUnlocalized) classify
        // as figment-bearing on the kind side; the third
        // (NotApplicable) does not. Pins the cross-axis partition
        // through the constant rather than an inline literal.
        let bearing_side: usize = FieldPathLocalization::ALL
            .iter()
            .filter(|loc| {
                matches!(
                    loc,
                    FieldPathLocalization::Localized | FieldPathLocalization::FigmentUnlocalized,
                )
            })
            .count();
        let non_bearing_side: usize = FieldPathLocalization::ALL
            .iter()
            .filter(|loc| matches!(loc, FieldPathLocalization::NotApplicable))
            .count();
        assert_eq!(
            bearing_side, 2,
            "two ALL cells sit on the figment-bearing side"
        );
        assert_eq!(
            bearing_side + non_bearing_side,
            FieldPathLocalization::ALL.len(),
            "the figment-bearing-side partition must cover ALL exactly once",
        );
    }

    #[test]
    fn field_path_localization_all_covers_every_kind_axis_classification() {
        // Cross-axis cover: every ShikumiError in the kind-axis sample
        // table classifies into a FieldPathLocalization cell that lies
        // in ALL. Pins the contract that no kind escapes the
        // localization universe.
        use std::collections::HashSet;
        let listed: HashSet<FieldPathLocalization> =
            FieldPathLocalization::ALL.iter().copied().collect();
        for (_, err) in one_per_kind() {
            let loc = err.field_path_localization();
            assert!(
                listed.contains(&loc),
                "kind-axis sample {err:?} produced localization {loc:?} not in ALL",
            );
        }
    }

    #[test]
    fn field_path_localization_localized_implies_kind_figment_bearing() {
        // Cross-primitive invariant: when the localization axis says
        // Localized or FigmentUnlocalized, the kind axis must say
        // figment-bearing; when NotApplicable, the kind axis must say
        // not figment-bearing. The two axes are linked by construction.
        for (_, err) in one_per_kind() {
            let loc = err.field_path_localization();
            let bearing = err.kind().is_figment_bearing();
            match loc {
                FieldPathLocalization::Localized | FieldPathLocalization::FigmentUnlocalized => {
                    assert!(
                        bearing,
                        "Localized/FigmentUnlocalized → kind must bear figment ({err:?})"
                    );
                }
                FieldPathLocalization::NotApplicable => {
                    assert!(
                        !bearing,
                        "NotApplicable → kind must not bear figment ({err:?})"
                    );
                }
            }
        }
    }

    // ---- AttributionAxis / AttributionRule::metadata_axis tests ----

    #[test]
    fn attribution_rule_metadata_axis_metadata_source_for_source_axis_rules() {
        // The two source-axis rules — typed Source::File classification
        // and typed Source::Code classification — must classify as
        // MetadataSource. Pins which rules dispatch off figment's
        // structural source field rather than parsing its name string.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_eq!(rule.metadata_axis(), AttributionAxis::MetadataSource);
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_metadata_name_for_name_axis_rules() {
        // The three name-axis rules — shikumi-provider tag, env-prefix
        // tag, env-bare/unmatched tag — all dispatch by parsing
        // figment's metadata.name string, so they classify as
        // MetadataName.
        for rule in [
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            assert_eq!(rule.metadata_axis(), AttributionAxis::MetadataName);
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // AttributionAxis — no rule may be both source-axis and
        // name-axis, none may be neither. Pins the partition contract
        // that the typescape lifts: a future variant added to
        // AttributionRule forces an axis assignment in the exhaustive
        // match (compile-time), and this test pins the resulting
        // partition (test-time).
        let cases = [
            (
                AttributionRule::FileBySource,
                AttributionAxis::MetadataSource,
            ),
            (
                AttributionRule::FileByMetadataName,
                AttributionAxis::MetadataName,
            ),
            (AttributionRule::EnvByPrefix, AttributionAxis::MetadataName),
            (
                AttributionRule::EnvByUniqueness,
                AttributionAxis::MetadataName,
            ),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                AttributionAxis::MetadataSource,
            ),
        ];
        for (rule, expected) in cases {
            assert_eq!(rule.metadata_axis(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_axis_is_copy_and_hashable() {
        // Typescape bounds parity with sibling closed-enum primitives
        // (AttributionRule, AttributionConfidence, ShikumiErrorKind,
        // FieldPathLocalization, ConfigSourceKind, FigmentSourceTag,
        // FigmentNameTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for axis in AttributionAxis::ALL.iter().copied() {
            set.insert(axis);
        }
        set.insert(AttributionAxis::MetadataSource); // duplicate — no growth
        assert_eq!(
            set.len(),
            AttributionAxis::ALL.len(),
            "every axis must hash distinctly"
        );

        // Copy: rebind without move.
        let a = AttributionAxis::MetadataSource;
        let a2 = a;
        let a3 = a;
        assert_eq!(a, a2);
        assert_eq!(a2, a3);
    }

    #[test]
    fn attribution_axis_all_has_no_duplicates() {
        // AttributionAxis::ALL must be a set — no variant listed twice.
        // Pins the duplication-free property of the constant against
        // accidental double-listing on future variant additions.
        use std::collections::HashSet;
        let set: HashSet<AttributionAxis> = AttributionAxis::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            AttributionAxis::ALL.len(),
            "AttributionAxis::ALL must list every variant exactly once; got duplicates in {:?}",
            AttributionAxis::ALL,
        );
    }

    #[test]
    fn attribution_axis_all_covers_every_rule_axis() {
        // Every axis produced by AttributionRule::metadata_axis over the
        // canonical rule-axis surface (AttributionRule::ALL) must appear
        // in AttributionAxis::ALL — pins the cover law that
        // AttributionAxis::ALL is at least as large as the image of
        // (rule → axis) over the typescape's rule space. Strictly
        // stronger than checking each rule's axis in isolation: this
        // pins the constant against silently dropping an axis a future
        // AttributionRule variant could reach.
        use std::collections::HashSet;
        let produced: HashSet<AttributionAxis> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::metadata_axis)
            .collect();
        let declared: HashSet<AttributionAxis> = AttributionAxis::ALL.iter().copied().collect();
        assert!(
            produced.is_subset(&declared),
            "every axis reached by AttributionRule::metadata_axis must lie in \
             AttributionAxis::ALL; produced: {produced:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn attribution_axis_all_equals_rule_axis_image() {
        // Tighter than the subset cover: AttributionAxis::ALL must equal
        // the image set of AttributionRule::metadata_axis over
        // AttributionRule::ALL. No declared axis lacks a rule reaching
        // it today — every variant in ALL is exercised by the rule
        // space. A future axis that lands without a corresponding rule
        // (or vice versa) fails this test in lockstep.
        use std::collections::HashSet;
        let produced: HashSet<AttributionAxis> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::metadata_axis)
            .collect();
        let declared: HashSet<AttributionAxis> = AttributionAxis::ALL.iter().copied().collect();
        assert_eq!(
            produced, declared,
            "AttributionAxis::ALL must equal the image of (rule → axis); \
             produced: {produced:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn attribution_axis_all_cardinality_matches_partition() {
        // AttributionAxis::ALL.len() must equal the number of distinct
        // axes produced by AttributionRule::metadata_axis over the
        // canonical rule-axis surface. Pins the cardinality contract
        // between the declared universe and the partition over the
        // rule space.
        use std::collections::HashSet;
        let distinct: HashSet<AttributionAxis> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::metadata_axis)
            .collect();
        assert_eq!(
            AttributionAxis::ALL.len(),
            distinct.len(),
            "AttributionAxis::ALL.len() ({}) must match the partition cardinality ({})",
            AttributionAxis::ALL.len(),
            distinct.len(),
        );
    }

    #[test]
    fn attribution_axis_all_lists_variants_in_declaration_order() {
        // Pins the declaration order: MetadataSource before
        // MetadataName. The constant doubles as a stable ordering for
        // diagnostics legends and attestation manifests; reordering
        // would silently shuffle external consumers' iteration order.
        assert_eq!(
            AttributionAxis::ALL,
            &[
                AttributionAxis::MetadataSource,
                AttributionAxis::MetadataName
            ],
            "AttributionAxis::ALL must list variants in declaration order",
        );
    }

    #[test]
    fn attribution_axis_all_covers_failing_source_attribution_axes() {
        // Cross-axis cover: every axis surfaced by
        // FailingSourceAttribution::metadata_axis over the rule space
        // must lie in AttributionAxis::ALL. Pins the contract that the
        // captured-failure envelope's axis accessor stays a thin
        // forwarder over the rule's axis (no envelope-specific axis
        // ever escapes the declared universe).
        use std::collections::HashSet;
        let src = ConfigSource::Defaults;
        let observed: HashSet<AttributionAxis> = AttributionRule::ALL
            .iter()
            .copied()
            .map(|rule| FailingSourceAttribution::new(&src, rule).metadata_axis())
            .collect();
        let declared: HashSet<AttributionAxis> = AttributionAxis::ALL.iter().copied().collect();
        assert!(
            observed.is_subset(&declared),
            "every axis surfaced by FailingSourceAttribution::metadata_axis must lie in \
             AttributionAxis::ALL; observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn attribution_rule_metadata_axis_orthogonal_to_confidence() {
        // The (metadata_axis × confidence) product over the rule space
        // must cover at least three distinct cells — the two
        // projections are orthogonal axes, not a single partition.
        // Today: (MetadataSource, Exact) — FileBySource;
        //        (MetadataSource, Fallback) — DefaultsByCodeUniqueness;
        //        (MetadataName, Exact) — FileByMetadataName, EnvByPrefix;
        //        (MetadataName, Fallback) — EnvByUniqueness.
        // Four distinct cells → orthogonal in a non-trivial way.
        use std::collections::HashSet;
        let mut pairs: HashSet<(AttributionAxis, AttributionConfidence)> = HashSet::new();
        for rule in AttributionRule::ALL.iter().copied() {
            pairs.insert((rule.metadata_axis(), rule.confidence()));
        }
        assert_eq!(
            pairs.len(),
            4,
            "axis × confidence must span all four cells; got: {pairs:?}"
        );
    }

    #[test]
    fn attribution_rule_metadata_axis_orthogonal_to_layer_kind() {
        // The (metadata_axis × layer_kind) product over the rule space
        // must cover at least three distinct cells.
        // Today: (MetadataSource, File) — FileBySource;
        //        (MetadataSource, Defaults) — DefaultsByCodeUniqueness;
        //        (MetadataName, File) — FileByMetadataName;
        //        (MetadataName, Env) — EnvByPrefix, EnvByUniqueness.
        // Four cells of the 2 × 3 = 6 product → finer than either axis.
        use std::collections::HashSet;
        let mut pairs: HashSet<(AttributionAxis, ConfigSourceKind)> = HashSet::new();
        for rule in AttributionRule::ALL.iter().copied() {
            pairs.insert((rule.metadata_axis(), rule.layer_kind()));
        }
        assert!(
            pairs.len() >= 3,
            "axis × layer_kind must span ≥3 cells; got: {pairs:?}"
        );
    }

    #[test]
    fn attribution_rule_metadata_axis_three_axis_product_is_rule_identity() {
        // Triple (metadata_axis × layer_kind × confidence) over the
        // rule space must cover ≥5 cells — enough to distinguish every
        // rule from every other rule. The three projections together
        // form an injective map from AttributionRule to the (axis ×
        // kind × confidence) product, modulo the EnvByPrefix /
        // FileByMetadataName tie on (MetadataName, Exact, _) — those
        // share the (axis, confidence) coordinates but split on
        // layer_kind. Pins the contract that the three projections
        // are jointly a complete coordinate system over the rule
        // space (no rule has the same triple as another).
        use std::collections::HashSet;
        let mut triples: HashSet<(AttributionAxis, ConfigSourceKind, AttributionConfidence)> =
            HashSet::new();
        for rule in AttributionRule::ALL.iter().copied() {
            triples.insert((rule.metadata_axis(), rule.layer_kind(), rule.confidence()));
        }
        assert_eq!(
            triples.len(),
            AttributionRule::ALL.len(),
            "triple (axis × kind × confidence) must distinguish every rule; got: {triples:?}"
        );
    }

    #[test]
    fn failing_source_attribution_metadata_axis_mirrors_rule_metadata_axis() {
        // The envelope's metadata_axis() must agree with the rule's,
        // byte-for-byte, on every recognized rule. Pins the contract
        // that the convenience accessor stays a thin forwarder.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.metadata_axis(), rule.metadata_axis());
        }
    }

    // ---- AttributionRule::figment_source_kind tests ----

    #[test]
    fn attribution_rule_figment_source_kind_some_for_file_by_source() {
        // FileBySource dispatches off Source::File classification, so
        // the rule's identity already pins FigmentSourceKind::File.
        assert_eq!(
            AttributionRule::FileBySource.figment_source_kind(),
            Some(FigmentSourceKind::File),
        );
    }

    #[test]
    fn attribution_rule_figment_source_kind_some_for_defaults_by_code_uniqueness() {
        // DefaultsByCodeUniqueness dispatches off Source::Code
        // classification, so the rule's identity already pins
        // FigmentSourceKind::Code.
        assert_eq!(
            AttributionRule::DefaultsByCodeUniqueness.figment_source_kind(),
            Some(FigmentSourceKind::Code),
        );
    }

    #[test]
    fn attribution_rule_figment_source_kind_none_for_name_axis_rules() {
        // The three name-axis rules dispatch off `metadata.name`, not
        // `metadata.source`, so the rule's identity does not pin a
        // FigmentSourceKind cell — return None for all three.
        for rule in [
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            assert_eq!(
                rule.figment_source_kind(),
                None,
                "name-axis rule {rule:?} must not pin a FigmentSourceKind",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_source_kind_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // Option<FigmentSourceKind> cell. Pins the partition contract
        // that AttributionRule::figment_source_kind is a total function
        // over the rule space (returning a partial projection); a
        // future variant added to AttributionRule forces an assignment
        // in the exhaustive match (compile-time), and this test pins
        // the resulting partition (test-time).
        let cases = [
            (AttributionRule::FileBySource, Some(FigmentSourceKind::File)),
            (AttributionRule::FileByMetadataName, None),
            (AttributionRule::EnvByPrefix, None),
            (AttributionRule::EnvByUniqueness, None),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                Some(FigmentSourceKind::Code),
            ),
        ];
        for (rule, expected) in cases {
            assert_eq!(rule.figment_source_kind(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_rule_figment_source_kind_some_iff_metadata_axis_source() {
        // Structural composition law: figment_source_kind is Some
        // exactly when metadata_axis is MetadataSource. Pins the
        // refinement: source-axis rules' identity already names a
        // FigmentSourceKind cell; name-axis rules' identity does not.
        // Stronger than per-variant arms: enumerate the entire rule
        // space against the biconditional.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.figment_source_kind().is_some(),
                rule.metadata_axis() == AttributionAxis::MetadataSource,
                "rule {rule:?}: figment_source_kind.is_some() must equal \
                 (metadata_axis == MetadataSource)",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_source_kind_image_is_file_and_code_only() {
        // Image of figment_source_kind over the rule space is exactly
        // {File, Code} — two of the three FigmentSourceKind cells.
        // The third cell (Custom) is reachable on the figment-side
        // classification but no recognized AttributionRule currently
        // dispatches off Source::Custom. Pins the image cardinality
        // and identity at the type level so a future custom-source
        // rule landing extends the image in lockstep.
        use std::collections::HashSet;
        let observed: HashSet<FigmentSourceKind> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::figment_source_kind)
            .collect();
        let expected: HashSet<FigmentSourceKind> =
            HashSet::from([FigmentSourceKind::File, FigmentSourceKind::Code]);
        assert_eq!(
            observed, expected,
            "image of figment_source_kind over AttributionRule::ALL must equal \
             {{File, Code}}; got: {observed:?}",
        );
    }

    #[test]
    fn attribution_rule_figment_source_kind_agrees_with_layer_kind_when_some() {
        // Structural diagonal on the source-axis subset: when
        // figment_source_kind is Some, the (figment-source-kind,
        // layer-kind) pair lies on the structural diagonal pinned by
        // the resolver (`Source::File` blames a `ConfigSource::File`
        // entry; `Source::Code` paired with a single
        // `ConfigSource::Defaults` blames it). The two source-axis
        // rules' identities already name both halves of their joint
        // (figment-source × shikumi-layer) coordinate cell.
        let cases = [
            (
                AttributionRule::FileBySource,
                FigmentSourceKind::File,
                ConfigSourceKind::File,
            ),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                FigmentSourceKind::Code,
                ConfigSourceKind::Defaults,
            ),
        ];
        for (rule, fk, ck) in cases {
            assert_eq!(rule.figment_source_kind(), Some(fk), "rule {rule:?}");
            assert_eq!(rule.layer_kind(), ck, "rule {rule:?}");
        }
        // Negative half: name-axis rules pin layer_kind but not
        // figment_source_kind — the diagonal does not extend to them.
        for rule in [
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            assert!(
                rule.figment_source_kind().is_none(),
                "name-axis rule {rule:?} must not lie on the source-axis diagonal",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_source_kind_image_lies_in_figment_source_kind_all() {
        // Cross-primitive cover law: every kind surfaced by
        // AttributionRule::figment_source_kind over the rule space
        // must lie in FigmentSourceKind::ALL. Pins the contract that
        // the rule's partial projection stays a sub-image of the
        // declared figment-Source-axis kind universe — no
        // rule-specific kind ever escapes the typescape's declared
        // axis. Mirrors how `attribution_axis_all_covers_failing_source_attribution_axes`
        // pins the metadata-axis cover.
        use std::collections::HashSet;
        let observed: HashSet<FigmentSourceKind> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::figment_source_kind)
            .collect();
        let declared: HashSet<FigmentSourceKind> = FigmentSourceKind::ALL.iter().copied().collect();
        assert!(
            observed.is_subset(&declared),
            "image of figment_source_kind must lie in FigmentSourceKind::ALL; \
             observed: {observed:?}, declared: {declared:?}",
        );
    }

    #[test]
    fn failing_source_attribution_figment_source_kind_mirrors_rule_figment_source_kind() {
        // The envelope's figment_source_kind() must agree with the
        // rule's, byte-for-byte, on every recognized rule. Pins the
        // contract that the convenience accessor stays a thin
        // forwarder over AttributionRule::figment_source_kind.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.figment_source_kind(), rule.figment_source_kind());
        }
    }

    #[test]
    fn failing_source_attribution_figment_source_kind_some_iff_metadata_axis_source() {
        // The envelope's figment_source_kind is Some exactly when its
        // metadata_axis is MetadataSource. Forwarder discipline pins
        // the same biconditional as
        // `attribution_rule_figment_source_kind_some_iff_metadata_axis_source`,
        // surfaced through the borrowed envelope.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.figment_source_kind().is_some(),
                attr.metadata_axis() == AttributionAxis::MetadataSource,
                "envelope for rule {rule:?}: figment_source_kind.is_some() must equal \
                 (metadata_axis == MetadataSource)",
            );
        }
    }

    #[test]
    fn failing_attribution_metadata_axis_metadata_source_for_yaml_extract() {
        // End-to-end: a real YAML-file extract failure attributes via
        // FileBySource — the resolver dispatched off `metadata.source`
        // (figment's typed Source::File). The envelope's metadata_axis
        // accessor must surface MetadataSource without the consumer
        // destructuring the rule.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.metadata_axis(), AttributionAxis::MetadataSource);
        assert_eq!(attr.metadata_axis(), attr.rule.metadata_axis());
    }

    #[test]
    fn failing_attribution_metadata_axis_metadata_name_for_synthetic_env_prefix() {
        // End-to-end: a synthetic env-prefixed metadata name with a
        // matching env prefix in the chain attributes via EnvByPrefix
        // — name-axis. The envelope reports MetadataName.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MAXIS_".to_owned()),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`MAXIS_` environment variable(s)"),
        };
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::EnvByPrefix);
        assert_eq!(attr.metadata_axis(), AttributionAxis::MetadataName);
    }

    // ---- AttributionCoordinates / AttributionRule::coordinates / from_coordinates ----

    /// The 5 recognized rules paired with their coordinate triples — one
    /// source of truth for the bijection table consumed by both the
    /// forward and inverse round-trip tests.
    fn rule_coordinate_table() -> [(AttributionRule, AttributionCoordinates); 5] {
        [
            (
                AttributionRule::FileBySource,
                AttributionCoordinates {
                    axis: AttributionAxis::MetadataSource,
                    layer_kind: ConfigSourceKind::File,
                    confidence: AttributionConfidence::Exact,
                },
            ),
            (
                AttributionRule::FileByMetadataName,
                AttributionCoordinates {
                    axis: AttributionAxis::MetadataName,
                    layer_kind: ConfigSourceKind::File,
                    confidence: AttributionConfidence::Exact,
                },
            ),
            (
                AttributionRule::EnvByPrefix,
                AttributionCoordinates {
                    axis: AttributionAxis::MetadataName,
                    layer_kind: ConfigSourceKind::Env,
                    confidence: AttributionConfidence::Exact,
                },
            ),
            (
                AttributionRule::EnvByUniqueness,
                AttributionCoordinates {
                    axis: AttributionAxis::MetadataName,
                    layer_kind: ConfigSourceKind::Env,
                    confidence: AttributionConfidence::Fallback,
                },
            ),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                AttributionCoordinates {
                    axis: AttributionAxis::MetadataSource,
                    layer_kind: ConfigSourceKind::Defaults,
                    confidence: AttributionConfidence::Fallback,
                },
            ),
        ]
    }

    #[test]
    fn attribution_rule_coordinates_returns_expected_triple_per_rule() {
        // Every rule's coordinates() returns the triple pinned by the
        // canonical table — the forward map is total over the rule
        // space and stable across changes that don't touch the
        // (axis, layer_kind, confidence) projections.
        for (rule, expected) in rule_coordinate_table() {
            assert_eq!(rule.coordinates(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_rule_coordinates_agrees_with_three_projection_accessors() {
        // The named-struct lift must be byte-for-byte identical with the
        // tuple of the three sibling projections — the unifier stays a
        // thin wrapper, never a re-derived computation.
        for (rule, _) in rule_coordinate_table() {
            let c = rule.coordinates();
            assert_eq!(c.axis, rule.metadata_axis());
            assert_eq!(c.layer_kind, rule.layer_kind());
            assert_eq!(c.confidence, rule.confidence());
        }
    }

    #[test]
    fn attribution_rule_coordinates_distinguishes_every_rule() {
        // Joint injectivity: distinct rules give distinct coordinates.
        // Stronger statement of the
        // attribution_rule_metadata_axis_three_axis_product_is_rule_identity
        // claim, but stated in terms of the named struct rather than
        // the underlying tuple.
        use std::collections::HashSet;
        let coords: HashSet<AttributionCoordinates> = rule_coordinate_table()
            .iter()
            .map(|(rule, _)| rule.coordinates())
            .collect();
        assert_eq!(
            coords.len(),
            AttributionRule::ALL.len(),
            "every rule must occupy a distinct coordinate cell; got: {coords:?}"
        );
    }

    #[test]
    fn attribution_rule_from_coordinates_recognizes_each_rule() {
        // The inverse map names the five recognized cells. Pins the
        // partial-bijection table at the type level — a future rule
        // landing forces a new arm in from_coordinates and a new row
        // here.
        for (expected_rule, coords) in rule_coordinate_table() {
            assert_eq!(
                AttributionRule::from_coordinates(coords),
                Some(expected_rule),
                "from_coordinates must recognize {coords:?} as {expected_rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_from_coordinates_round_trips_with_coordinates() {
        // The bijection statement: from_coordinates(rule.coordinates())
        // == Some(rule) for every recognized rule. The forward map is
        // total over the rule space; the inverse is partial but
        // populated on every cell the forward map ever produces.
        for (rule, _) in rule_coordinate_table() {
            assert_eq!(
                AttributionRule::from_coordinates(rule.coordinates()),
                Some(rule),
                "round-trip must recover rule {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_from_coordinates_returns_none_for_unrecognized_cells() {
        // The (axis × layer_kind × confidence) cube has 12 cells; 5 are
        // recognized, 7 are not. The inverse must return None on every
        // unrecognized cell — no fabricated attributions, no defaults.
        // Stronger than `is_none() count == 7`: enumerate the exact
        // unrecognized cells to pin which ones never gain a rule.
        //
        // Iterates the named product cube `AttributionCoordinates::ALL`
        // rather than re-deriving the triple-nested product inline; the
        // `attribution_coordinates_all_equals_axes_cartesian_product`
        // test pins that the constant is byte-for-byte the cartesian
        // product of the three sibling axis `ALL` slices.
        let recognized: std::collections::HashSet<AttributionCoordinates> =
            rule_coordinate_table().iter().map(|(_, c)| *c).collect();
        let mut unrecognized_count = 0usize;
        for coords in AttributionCoordinates::ALL.iter().copied() {
            if recognized.contains(&coords) {
                continue;
            }
            unrecognized_count += 1;
            assert_eq!(
                AttributionRule::from_coordinates(coords),
                None,
                "unrecognized cell {coords:?} must not resolve to a rule",
            );
        }
        assert_eq!(
            unrecognized_count, 7,
            "the 12-cell cube must contain exactly 7 unrecognized cells; got: {unrecognized_count}",
        );
    }

    #[test]
    fn attribution_rule_from_coordinates_rejects_specific_unrecognized_cells() {
        // Spot-check the four unrecognized cells that the rule space
        // structurally cannot occupy today: source-axis env attributions
        // (figment's Env provider attaches name, not source), name-axis
        // defaults attributions (figment's Serialized provider attaches
        // source, not a recognized name shape), and the source-axis
        // file × Fallback / source-axis defaults × Exact diagonal cells.
        let unrecognized = [
            // source-axis Env: figment's Env provider doesn't attach a
            // typed Source for env, so this cell is structurally empty.
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::Env,
                confidence: AttributionConfidence::Exact,
            },
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::Env,
                confidence: AttributionConfidence::Fallback,
            },
            // name-axis Defaults: figment's Serialized provider attaches
            // Source::Code; no name-axis recognition path for defaults.
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::Defaults,
                confidence: AttributionConfidence::Exact,
            },
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::Defaults,
                confidence: AttributionConfidence::Fallback,
            },
            // source-axis File × Fallback: FileBySource is Exact-only;
            // no fallback path on the typed source classification.
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::File,
                confidence: AttributionConfidence::Fallback,
            },
            // source-axis Defaults × Exact: DefaultsByCodeUniqueness is
            // Fallback-only; no equality-based defaults attribution.
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::Defaults,
                confidence: AttributionConfidence::Exact,
            },
            // name-axis File × Fallback: FileByMetadataName is
            // Exact-only; no uniqueness-based file-name attribution.
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::File,
                confidence: AttributionConfidence::Fallback,
            },
        ];
        for coords in unrecognized {
            assert!(
                AttributionRule::from_coordinates(coords).is_none(),
                "from_coordinates must reject unrecognized cell {coords:?}",
            );
        }
    }

    #[test]
    fn attribution_coordinates_is_copy_and_hashable() {
        // Trait-bounds parity with sibling typescape primitives
        // (AttributionRule, AttributionConfidence, AttributionAxis,
        // ConfigSourceKind, ShikumiErrorKind, FieldPathLocalization,
        // FigmentSourceTag, FigmentNameTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for (_, coords) in rule_coordinate_table() {
            set.insert(coords);
        }
        assert_eq!(set.len(), 5, "every coordinate triple must hash distinctly");

        // Copy: rebind without move.
        let c = AttributionCoordinates {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Exact,
        };
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    // ---- AttributionCoordinates::ALL cover / partition / order ----
    //
    // First product-axis `ALL` lift on the typescape primitive set:
    // structural composition of `AttributionAxis::ALL` (2 cells),
    // `ConfigSourceKind::ALL` (3 cells), and `AttributionConfidence::ALL`
    // (2 cells) into a single 12-element `&'static [Self]`. Peers the
    // nine sibling per-axis `ALL` constants on a product axis rather
    // than on a single axis.

    #[test]
    fn attribution_coordinates_all_has_no_duplicates() {
        // The constant is a set, not a multiset — every cell appears
        // exactly once. Peer to the per-axis `*_all_has_no_duplicates`
        // invariants for sibling primitives.
        use std::collections::HashSet;
        let set: HashSet<AttributionCoordinates> =
            AttributionCoordinates::ALL.iter().copied().collect();
        assert_eq!(
            set.len(),
            AttributionCoordinates::ALL.len(),
            "AttributionCoordinates::ALL must contain no duplicates; got: {:?}",
            AttributionCoordinates::ALL,
        );
    }

    #[test]
    fn attribution_coordinates_all_cardinality_matches_product_of_axes() {
        // The cube cardinality must equal the product of the three
        // sibling axis `ALL` cardinalities. A new variant on any of
        // the three axes forces an extension of `AttributionCoordinates::ALL`
        // in lockstep — this test reads the product cardinality on
        // the fly from the sibling constants, so the contract stays
        // coherent regardless of which axis grows.
        assert_eq!(
            AttributionCoordinates::ALL.len(),
            AttributionAxis::ALL.len()
                * ConfigSourceKind::ALL.len()
                * AttributionConfidence::ALL.len(),
            "AttributionCoordinates::ALL cardinality must equal \
             AttributionAxis::ALL.len() * ConfigSourceKind::ALL.len() * \
             AttributionConfidence::ALL.len()",
        );
        // Today: 2 × 3 × 2 = 12. Pin the concrete current value too,
        // so a future axis growth shows up as two failing assertions
        // (the product law and the literal-12 invariant) rather than
        // a silent rebalance.
        assert_eq!(
            AttributionCoordinates::ALL.len(),
            12,
            "AttributionCoordinates::ALL cardinality must be 12 today; \
             got: {}",
            AttributionCoordinates::ALL.len(),
        );
    }

    #[test]
    fn attribution_coordinates_all_equals_axes_cartesian_product() {
        // Tight equality (not just subset cover): the constant is the
        // exact image of the triple-nested cartesian product over the
        // three sibling axis `ALL` slices. Pins that `Self::ALL` is
        // the product — every product cell appears, every appearing
        // cell is a product cell, no extras and no omissions.
        use std::collections::HashSet;
        let declared: HashSet<AttributionCoordinates> =
            AttributionCoordinates::ALL.iter().copied().collect();
        let mut product: HashSet<AttributionCoordinates> = HashSet::new();
        for axis in AttributionAxis::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                for confidence in AttributionConfidence::ALL.iter().copied() {
                    product.insert(AttributionCoordinates {
                        axis,
                        layer_kind,
                        confidence,
                    });
                }
            }
        }
        assert_eq!(
            declared, product,
            "AttributionCoordinates::ALL must equal the cartesian product \
             of AttributionAxis::ALL × ConfigSourceKind::ALL × \
             AttributionConfidence::ALL; declared: {declared:?}, \
             product: {product:?}",
        );
    }

    #[test]
    fn attribution_coordinates_all_iterates_in_lexicographic_order() {
        // Declaration order is lexicographic over the three sibling
        // axis `ALL` slices: axis outermost, layer_kind middle,
        // confidence innermost. Pins the iteration order so that
        // consumers depending on a stable enumeration (e.g. fixture
        // tables in downstream tests, attestation manifests recording
        // the cube in canonical order) stay coherent.
        let mut expected: Vec<AttributionCoordinates> = Vec::new();
        for axis in AttributionAxis::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                for confidence in AttributionConfidence::ALL.iter().copied() {
                    expected.push(AttributionCoordinates {
                        axis,
                        layer_kind,
                        confidence,
                    });
                }
            }
        }
        assert_eq!(
            AttributionCoordinates::ALL.to_vec(),
            expected,
            "AttributionCoordinates::ALL must list cells in lexicographic \
             order over (AttributionAxis::ALL, ConfigSourceKind::ALL, \
             AttributionConfidence::ALL)",
        );
    }

    #[test]
    fn attribution_coordinates_all_partitions_into_recognized_and_unrecognized() {
        // The 12-cell cube splits into 5 recognized cells (one per
        // `AttributionRule`) and 7 unrecognized cells. The two
        // populations are disjoint and cover `Self::ALL` — pins the
        // partition cardinalities against the sibling rule space.
        let recognized = AttributionCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| AttributionRule::from_coordinates(*c).is_some())
            .count();
        let unrecognized = AttributionCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| AttributionRule::from_coordinates(*c).is_none())
            .count();
        assert_eq!(
            recognized,
            AttributionRule::ALL.len(),
            "recognized-cell count must equal AttributionRule::ALL cardinality",
        );
        assert_eq!(
            unrecognized,
            AttributionCoordinates::ALL.len() - AttributionRule::ALL.len(),
            "unrecognized-cell count must equal cube cardinality minus \
             AttributionRule::ALL cardinality",
        );
        // Together they cover ALL — no cell is both recognized and
        // unrecognized, and no cell falls outside the partition.
        assert_eq!(
            recognized + unrecognized,
            AttributionCoordinates::ALL.len(),
            "the recognized + unrecognized partition must cover \
             AttributionCoordinates::ALL exactly",
        );
    }

    #[test]
    fn attribution_coordinates_all_recognized_image_equals_rule_coordinates() {
        // The recognized half of `AttributionCoordinates::ALL` —
        // those cells `c` where `AttributionRule::from_coordinates(c)`
        // is `Some(_)` — must equal the exact image of
        // `AttributionRule::coordinates` over `AttributionRule::ALL`.
        // Stronger than the cardinality match in the partition test:
        // pins which specific cells are recognized, not just how many.
        use std::collections::HashSet;
        let recognized_in_cube: HashSet<AttributionCoordinates> = AttributionCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| AttributionRule::from_coordinates(*c).is_some())
            .collect();
        let rule_image: HashSet<AttributionCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::coordinates)
            .collect();
        assert_eq!(
            recognized_in_cube, rule_image,
            "recognized cells of AttributionCoordinates::ALL must equal \
             the image of AttributionRule::coordinates over AttributionRule::ALL",
        );
    }

    #[test]
    fn attribution_coordinates_all_round_trips_through_from_coordinates_on_recognized_cells() {
        // For every recognized cell `c` in `Self::ALL`, the inverse
        // map `from_coordinates(c)` returns a rule `r` such that
        // `r.coordinates() == c`. The named-struct lift is a bijection
        // on the 5 recognized cells; iterating the product cube is
        // the canonical way to enumerate them.
        let mut round_tripped = 0usize;
        for coords in AttributionCoordinates::ALL.iter().copied() {
            if let Some(rule) = AttributionRule::from_coordinates(coords) {
                assert_eq!(
                    rule.coordinates(),
                    coords,
                    "recognized cell {coords:?} must round-trip via \
                     from_coordinates -> coordinates",
                );
                round_tripped += 1;
            }
        }
        assert_eq!(
            round_tripped,
            AttributionRule::ALL.len(),
            "exactly AttributionRule::ALL.len() cells must round-trip; \
             got: {round_tripped}",
        );
    }

    #[test]
    fn attribution_coordinates_is_realizable_agrees_with_from_coordinates_some() {
        // Pins the realizability invariant pointwise on every cell of
        // the cube:
        //   is_realizable iff AttributionRule::from_coordinates is Some.
        // The two definitions agree on all 12 cells.
        for cell in AttributionCoordinates::ALL.iter().copied() {
            let expected = AttributionRule::from_coordinates(cell).is_some();
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal from_coordinates(_).is_some()",
            );
        }
    }

    #[test]
    fn attribution_coordinates_realizable_partitions_into_5_realizable_and_7_unrealizable() {
        // Pins the 5 + 7 cardinality split:
        // - 5 realizable cells, one per recognized AttributionRule
        //   (FileBySource, FileByMetadataName, EnvByPrefix,
        //   EnvByUniqueness, DefaultsByCodeUniqueness).
        // - 7 unrealizable cells covering every (axis, layer_kind,
        //   confidence) combination no recognized rule occupies.
        // A future AttributionRule landing in a previously unrecognized
        // cell extends the realizable image, shrinking the unrealizable
        // count and growing the realizable count in lockstep.
        let realizable = AttributionCoordinates::ALL
            .iter()
            .filter(|c| c.is_realizable())
            .count();
        let unrealizable = AttributionCoordinates::ALL
            .iter()
            .filter(|c| !c.is_realizable())
            .count();
        assert_eq!(
            realizable,
            AttributionRule::ALL.len(),
            "realizable cells must equal AttributionRule::ALL cardinality",
        );
        assert_eq!(
            unrealizable,
            AttributionCoordinates::ALL.len() - AttributionRule::ALL.len(),
            "unrealizable cells must equal cube cardinality minus rule cardinality",
        );
        assert_eq!(
            realizable + unrealizable,
            AttributionCoordinates::ALL.len(),
            "realizable + unrealizable must cover ALL exactly once",
        );
        // Pin the concrete current values too — the partition is 5 + 7
        // today; future rule additions move both counts in lockstep.
        assert_eq!(realizable, 5);
        assert_eq!(unrealizable, 7);
    }

    #[test]
    fn attribution_coordinates_is_realizable_image_equals_rule_image() {
        // The realizable half of ALL is the exact image of
        // AttributionRule::coordinates over the rule space. Pins which
        // specific cells (not just how many) are observable from a
        // recognized AttributionRule — a tighter contract than the
        // cardinality split. Future rules land coherently: a new rule
        // extends the image and forces an expansion of the realizable
        // subset in lockstep.
        use std::collections::HashSet;
        let observed: HashSet<AttributionCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .map(AttributionRule::coordinates)
            .collect();
        let realizable: HashSet<AttributionCoordinates> = AttributionCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.is_realizable())
            .collect();
        assert_eq!(
            observed, realizable,
            "observed image over AttributionRule::ALL must equal the realizable cells",
        );
    }

    #[test]
    fn attribution_rule_coordinates_always_lies_on_realizable_cell() {
        // Forward-total / image-realizable contract: every cell
        // produced by AttributionRule::coordinates must satisfy
        // is_realizable. The forward map never escapes into the
        // unrealizable half of the cube, no matter which rule is
        // queried.
        for rule in AttributionRule::ALL.iter().copied() {
            assert!(
                rule.coordinates().is_realizable(),
                "rule {rule:?}: coordinates() must produce a realizable cell",
            );
        }
    }

    #[test]
    fn attribution_coordinates_unrealizable_cells_have_no_inverse() {
        // Symmetric of the forward-total contract: every unrealizable
        // cell has no inverse rule. Closes the partial-inverse / Boolean-
        // predicate equivalence in the unrealizable direction:
        // `!c.is_realizable() iff AttributionRule::from_coordinates(c)
        // .is_none()`. Pointwise verification across the 12-cell cube.
        for cell in AttributionCoordinates::ALL.iter().copied() {
            if !cell.is_realizable() {
                assert!(
                    AttributionRule::from_coordinates(cell).is_none(),
                    "unrealizable cell {cell:?}: from_coordinates must be None",
                );
            }
        }
    }

    #[test]
    fn failing_source_attribution_coordinates_mirrors_rule_coordinates() {
        // The envelope's coordinates() method must agree with the
        // rule's, byte-for-byte, on every recognized rule. Pins the
        // contract that the convenience accessor stays a thin
        // forwarder over AttributionRule::coordinates.
        for (rule, expected) in rule_coordinate_table() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.coordinates(), expected);
            assert_eq!(attr.coordinates(), rule.coordinates());
        }
    }

    #[test]
    fn failing_source_attribution_coordinates_field_agreement() {
        // The named-struct lift on the envelope side must surface the
        // same per-axis values as the three sibling forwarders
        // (metadata_axis, layer_kind, confidence). The three
        // accessors and the unified coordinates accessor are a single
        // typed surface, not three independent reads.
        for (rule, _) in rule_coordinate_table() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            let c = attr.coordinates();
            assert_eq!(c.axis, attr.metadata_axis());
            assert_eq!(c.layer_kind, attr.layer_kind());
            assert_eq!(c.confidence, attr.confidence());
        }
    }

    #[test]
    fn failing_attribution_coordinates_for_yaml_extract() {
        // End-to-end: a real YAML-file extract failure attributes via
        // FileBySource. The envelope's coordinates accessor surfaces
        // the (MetadataSource, File, Exact) triple without the
        // consumer destructuring the rule.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(
            attr.coordinates(),
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::File,
                confidence: AttributionConfidence::Exact,
            },
        );
        // Round-trip the captured coordinates back to the rule.
        assert_eq!(
            AttributionRule::from_coordinates(attr.coordinates()),
            Some(AttributionRule::FileBySource),
        );
    }

    #[test]
    fn failing_attribution_metadata_axis_metadata_source_for_defaults_only_extract() {
        // End-to-end: a defaults-only Serialized extract dispatches
        // via DefaultsByCodeUniqueness — the resolver inspected
        // `metadata.source` (figment's typed Source::Code), even
        // though the rule is uniqueness-based. Pins that the axis
        // partition is independent of the confidence partition.
        use crate::provider::ProviderChain;
        use serde::Serialize;
        #[derive(Serialize)]
        struct Bad {
            count: String,
        }
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::DefaultsByCodeUniqueness);
        assert_eq!(attr.metadata_axis(), AttributionAxis::MetadataSource);
        // Confidence is Fallback — pins independence of the two axes.
        assert_eq!(attr.confidence(), AttributionConfidence::Fallback);
    }

    // ---- AttributionRule::ALL tests ----

    #[test]
    fn attribution_rule_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every variant appears
        // at most once. Pins the "no double-listed rule" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost rule contributing twice to a partition tally over the
        // confidence / layer_kind / metadata_axis projections.
        use std::collections::HashSet;
        let unique: HashSet<AttributionRule> = AttributionRule::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            AttributionRule::ALL.len(),
            "AttributionRule::ALL must contain no duplicates",
        );
    }

    #[test]
    fn attribution_rule_all_covers_every_recognized_variant() {
        // The construction-table surface in `rule_coordinate_table()`
        // covers every AttributionRule variant once (one row per rule).
        // Pin the contract that every rule produced by the canonical
        // table appears in AttributionRule::ALL, and that ALL contains
        // no extras: the mutual-cover statement proves ALL is in 1-1
        // correspondence with the rule partition surfaced by the
        // resolver / inverse-bijection table.
        use std::collections::HashSet;
        let produced: HashSet<AttributionRule> = rule_coordinate_table()
            .into_iter()
            .map(|(r, _)| r)
            .collect();
        let listed: HashSet<AttributionRule> = AttributionRule::ALL.iter().copied().collect();
        assert_eq!(
            produced, listed,
            "AttributionRule::ALL must equal the rule set produced by rule_coordinate_table",
        );
    }

    #[test]
    fn attribution_rule_all_cardinality_matches_coordinate_table() {
        // Stronger statement of the prior test on the cardinality axis:
        // ALL.len() must equal the number of construction-table rows.
        // A future AttributionRule variant landing forces both an arm
        // in `coordinates()` / `from_coordinates()` (compile-time,
        // exhaustive match) and a row in `rule_coordinate_table()`
        // (test-time); this assertion fails until ALL is extended in
        // lockstep, catching forgotten ALL updates.
        assert_eq!(
            AttributionRule::ALL.len(),
            rule_coordinate_table().len(),
            "ALL.len() must equal rule_coordinate_table().len()",
        );
    }

    #[test]
    fn attribution_rule_all_iterates_in_declaration_order() {
        // The constant lists variants in the same order as the enum's
        // declaration arms (FileBySource, FileByMetadataName, EnvByPrefix,
        // EnvByUniqueness, DefaultsByCodeUniqueness). Iteration order is
        // observable — consumers (alerting policies, dashboards, miette
        // diagnostic renderers) that rely on a stable ordering for
        // priority/severity can route on it.
        assert_eq!(
            AttributionRule::ALL,
            &[
                AttributionRule::FileBySource,
                AttributionRule::FileByMetadataName,
                AttributionRule::EnvByPrefix,
                AttributionRule::EnvByUniqueness,
                AttributionRule::DefaultsByCodeUniqueness,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn attribution_rule_all_partitions_confidence_axis() {
        // ALL composes with confidence() as the universe over which the
        // exact-vs-fallback partition is total: every listed rule
        // classifies into exactly one confidence cell, and the two
        // counts sum to ALL.len(). Stated through the constant rather
        // than an inline literal — peer to
        // shikumi_error_kind_all_partitions_figment_bearing_axis on
        // the kind axis.
        let exact = AttributionRule::ALL.iter().filter(|r| r.is_exact()).count();
        let fallback = AttributionRule::ALL
            .iter()
            .filter(|r| r.is_fallback())
            .count();
        assert_eq!(exact, 3, "three ALL rules are exact");
        assert_eq!(fallback, 2, "two ALL rules are fallback");
        assert_eq!(
            exact + fallback,
            AttributionRule::ALL.len(),
            "the confidence partition must cover ALL exactly once",
        );
    }

    #[test]
    fn attribution_rule_all_partitions_layer_kind_axis() {
        // ALL composes with layer_kind() as the universe over which the
        // (file × env × defaults) partition is total. The three counts
        // sum to ALL.len() with no rule unaccounted for.
        let file = AttributionRule::ALL
            .iter()
            .filter(|r| r.layer_kind() == ConfigSourceKind::File)
            .count();
        let env = AttributionRule::ALL
            .iter()
            .filter(|r| r.layer_kind() == ConfigSourceKind::Env)
            .count();
        let defaults = AttributionRule::ALL
            .iter()
            .filter(|r| r.layer_kind() == ConfigSourceKind::Defaults)
            .count();
        assert_eq!(file, 2, "two ALL rules attribute to File");
        assert_eq!(env, 2, "two ALL rules attribute to Env");
        assert_eq!(defaults, 1, "one ALL rule attributes to Defaults");
        assert_eq!(
            file + env + defaults,
            AttributionRule::ALL.len(),
            "the layer_kind partition must cover ALL exactly once",
        );
    }

    #[test]
    fn attribution_rule_all_partitions_metadata_axis() {
        // ALL composes with metadata_axis() as the universe over which
        // the (source × name) partition is total. The two counts sum to
        // ALL.len() with no rule unaccounted for.
        let source = AttributionRule::ALL
            .iter()
            .filter(|r| r.metadata_axis() == AttributionAxis::MetadataSource)
            .count();
        let name = AttributionRule::ALL
            .iter()
            .filter(|r| r.metadata_axis() == AttributionAxis::MetadataName)
            .count();
        assert_eq!(source, 2, "two ALL rules dispatch off metadata.source");
        assert_eq!(name, 3, "three ALL rules dispatch off metadata.name");
        assert_eq!(
            source + name,
            AttributionRule::ALL.len(),
            "the metadata_axis partition must cover ALL exactly once",
        );
    }

    #[test]
    fn attribution_rule_all_layer_kind_agrees_with_attribution_source_kind() {
        // For every rule in ALL, building a FailingSourceAttribution
        // from a ConfigSource of the rule's declared layer_kind keeps
        // the structural law `attr.layer_kind() == attr.source.kind()`
        // intact. Pins the cross-axis composition over the constant
        // surface, peer to the existing
        // attribution_rule_layer_kind_agrees_with_source_kind end-to-end
        // test on real resolver paths.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = match rule.layer_kind() {
                ConfigSourceKind::File => ConfigSource::File(PathBuf::from("/etc/app.yaml")),
                ConfigSourceKind::Env => ConfigSource::Env("APP_".to_owned()),
                ConfigSourceKind::Defaults => ConfigSource::Defaults,
            };
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.layer_kind(),
                attr.source.kind(),
                "rule {rule:?}: layer_kind / source.kind() must agree",
            );
        }
    }

    // ---- ErrorLocalizationCoordinates / error_localization_coordinates tests ----

    #[test]
    fn error_localization_coordinates_all_has_no_duplicates() {
        // Pins the constant is a set, not a multiset — every cell in
        // ALL is unique, the cardinality the typescape relies on so
        // consumers iterating ALL never see a doubled cell.
        use std::collections::HashSet;
        let unique: HashSet<ErrorLocalizationCoordinates> =
            ErrorLocalizationCoordinates::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ErrorLocalizationCoordinates::ALL.len(),
            "ErrorLocalizationCoordinates::ALL must contain no duplicates",
        );
    }

    #[test]
    fn error_localization_coordinates_all_cardinality_matches_product_of_axes() {
        // Pins the product-cube cardinality contract as a function of
        // the constituent axis cardinalities rather than a literal
        // integer: any new variant on either sibling axis
        // (ShikumiErrorKind::ALL or FieldPathLocalization::ALL)
        // forces an extension of Self::ALL in lockstep through this
        // assertion. Also pins the concrete current value (18) so
        // an unintentional churn on either axis is caught even when
        // the product math still works out.
        assert_eq!(
            ErrorLocalizationCoordinates::ALL.len(),
            ShikumiErrorKind::ALL.len() * FieldPathLocalization::ALL.len(),
            "ALL must equal the cartesian product cardinality",
        );
        assert_eq!(
            ErrorLocalizationCoordinates::ALL.len(),
            18,
            "ALL must have 6 * 3 = 18 cells today",
        );
    }

    #[test]
    fn error_localization_coordinates_all_equals_axes_cartesian_product() {
        // Tight equality (not subset) against the inline doubly-nested
        // product over the sibling ALL slices: Self::ALL IS the
        // cartesian product, no extras and no omissions. A future
        // variant on either sibling axis (kind or localization)
        // forces both an entry in the constant and a corresponding
        // cell appearing here through the inline product enumeration.
        use std::collections::HashSet;
        let mut expected: HashSet<ErrorLocalizationCoordinates> = HashSet::new();
        for kind in ShikumiErrorKind::ALL.iter().copied() {
            for localization in FieldPathLocalization::ALL.iter().copied() {
                expected.insert(ErrorLocalizationCoordinates { kind, localization });
            }
        }
        let listed: HashSet<ErrorLocalizationCoordinates> =
            ErrorLocalizationCoordinates::ALL.iter().copied().collect();
        assert_eq!(
            listed, expected,
            "ALL must be the exact cartesian product of the sibling ALL slices",
        );
    }

    #[test]
    fn error_localization_coordinates_all_iterates_in_lexicographic_order() {
        // Pins iteration order kind-outer / localization-inner — the
        // doubly-nested product enumeration over the sibling ALL
        // slices in lexicographic order. Consumers (dashboards,
        // attestation manifests) that rely on a stable iteration
        // order for deterministic output read the canonical order
        // from this constant.
        let mut expected: Vec<ErrorLocalizationCoordinates> = Vec::new();
        for kind in ShikumiErrorKind::ALL.iter().copied() {
            for localization in FieldPathLocalization::ALL.iter().copied() {
                expected.push(ErrorLocalizationCoordinates { kind, localization });
            }
        }
        let listed: Vec<ErrorLocalizationCoordinates> = ErrorLocalizationCoordinates::ALL.to_vec();
        assert_eq!(
            listed, expected,
            "ALL must iterate in kind-outer / localization-inner lexicographic order",
        );
    }

    #[test]
    fn error_localization_coordinates_is_realizable_agrees_with_figment_bearing_law() {
        // Pins the realizability invariant pointwise on every cell of
        // the cube:
        //   is_realizable iff
        //   kind.is_figment_bearing() == (localization != NotApplicable).
        // The two definitions agree on all 18 cells.
        for cell in ErrorLocalizationCoordinates::ALL.iter().copied() {
            let expected = cell.kind.is_figment_bearing()
                == !matches!(cell.localization, FieldPathLocalization::NotApplicable);
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal the figment-bearing law",
            );
        }
    }

    #[test]
    fn error_localization_coordinates_realizable_partitions_into_8_realizable_and_10_unrealizable()
    {
        // Pins the 8 + 10 cardinality split:
        // - 2 figment-bearing kinds (Figment, Extract)
        //   × 2 figment-attached localizations (Localized,
        //     FigmentUnlocalized) = 4 realizable cells.
        // - 4 non-figment-bearing kinds (NotFound, Parse, Watch, Io)
        //   × 1 NotApplicable = 4 realizable cells.
        // Total realizable = 8; total unrealizable = 10. A future
        // variant on either sibling axis lands as new cells whose
        // realizability is forced by the is_figment_bearing law,
        // keeping this partition coherent by construction.
        let realizable = ErrorLocalizationCoordinates::ALL
            .iter()
            .filter(|c| c.is_realizable())
            .count();
        let unrealizable = ErrorLocalizationCoordinates::ALL
            .iter()
            .filter(|c| !c.is_realizable())
            .count();
        assert_eq!(realizable, 8, "realizable cells must be 8");
        assert_eq!(unrealizable, 10, "unrealizable cells must be 10");
        assert_eq!(
            realizable + unrealizable,
            ErrorLocalizationCoordinates::ALL.len(),
            "realizable + unrealizable must cover ALL exactly once",
        );
    }

    #[test]
    fn error_localization_coordinates_realizable_image_equals_observed_pairs() {
        // The realizable half of ALL is the exact image of
        // ShikumiError::error_localization_coordinates over the
        // canonical construction-table surface. Pins which specific
        // cells (not just how many) are observable from a real
        // ShikumiError value — a tighter contract than the
        // cardinality split. The construction surface here augments
        // `one_per_kind()` (which covers NotFound/Parse/Watch/Io
        // collapsing to NotApplicable, plus the
        // FigmentUnlocalized cells for Extract / Figment) with two
        // path-bearing Figment-bearing constructions and one
        // Extract+FigmentUnlocalized — together they enumerate all
        // 8 realizable cells exactly.
        use std::collections::HashSet;
        let mut observed: HashSet<ErrorLocalizationCoordinates> = HashSet::new();
        for (_, err) in one_per_kind() {
            observed.insert(err.error_localization_coordinates());
        }
        for (err, _) in one_per_localization() {
            observed.insert(err.error_localization_coordinates());
        }
        // Figment + Localized: a figment error with a non-empty path
        // wrapped in ShikumiError::Figment.
        let figment_localized = ShikumiError::Figment(Box::new(
            figment::Error::from("t".to_owned()).with_path("k"),
        ));
        observed.insert(figment_localized.error_localization_coordinates());
        let realizable: HashSet<ErrorLocalizationCoordinates> = ErrorLocalizationCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.is_realizable())
            .collect();
        assert_eq!(
            observed, realizable,
            "observed pairs from the construction-table surface must equal the realizable cells",
        );
    }

    #[test]
    fn shikumi_error_error_localization_coordinates_returns_realizable_cell() {
        // Every constructible ShikumiError maps to a realizable cell.
        // Pins the forward-total / image-realizable contract: the
        // accessor never produces an unrealizable cell, no matter
        // which variant is constructed. Holds over the canonical
        // construction-table surface; a future variant lands with a
        // row here and is forced to satisfy the same invariant.
        for (_, err) in one_per_kind() {
            let cell = err.error_localization_coordinates();
            assert!(
                cell.is_realizable(),
                "every constructible error must map to a realizable cell (got {cell:?} from {err:?})",
            );
        }
        for (err, _) in one_per_localization() {
            let cell = err.error_localization_coordinates();
            assert!(
                cell.is_realizable(),
                "every constructible error must map to a realizable cell (got {cell:?} from {err:?})",
            );
        }
    }

    #[test]
    fn shikumi_error_error_localization_coordinates_mirrors_sibling_accessors() {
        // The coordinate accessor is a thin lift over the two sibling
        // accessors (kind, field_path_localization): the produced
        // cell's named fields must agree byte-for-byte with the two
        // separate reads. Pins the lossless-decomposition contract
        // — consumers using either the coordinate or the two reads
        // separately see the same data.
        for (_, err) in one_per_kind() {
            let cell = err.error_localization_coordinates();
            assert_eq!(
                cell.kind,
                err.kind(),
                "coordinate.kind must agree with err.kind() for {err:?}",
            );
            assert_eq!(
                cell.localization,
                err.field_path_localization(),
                "coordinate.localization must agree with err.field_path_localization() for {err:?}",
            );
        }
    }

    #[test]
    fn error_localization_coordinates_is_copy_and_hashable() {
        // Typescape bounds parity with the sibling product-cube
        // structs (AttributionCoordinates, FormatCoordinates) and the
        // underlying axis primitives (ShikumiErrorKind,
        // FieldPathLocalization).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Extract,
            localization: FieldPathLocalization::Localized,
        });
        set.insert(ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::NotApplicable,
        });
        // Duplicate insertion — no growth.
        set.insert(ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Extract,
            localization: FieldPathLocalization::Localized,
        });
        assert_eq!(set.len(), 2, "every coordinate must hash distinctly");

        // Copy: rebind without move.
        let c = ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Figment,
            localization: FieldPathLocalization::FigmentUnlocalized,
        };
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    // ---- AttributionSourceKindCoordinates::ALL cover / partition / realizability ----

    #[test]
    fn attribution_source_kind_coordinates_all_has_no_duplicates() {
        // Pins that the constant is a set, not a multiset — every
        // cell appears at most once. Mirrors the
        // `_all_has_no_duplicates` discipline on every sibling
        // product-cube `ALL` (AttributionCoordinates,
        // FormatCoordinates, ErrorLocalizationCoordinates).
        use std::collections::HashSet;
        let unique: HashSet<AttributionSourceKindCoordinates> =
            AttributionSourceKindCoordinates::ALL
                .iter()
                .copied()
                .collect();
        assert_eq!(
            unique.len(),
            AttributionSourceKindCoordinates::ALL.len(),
            "AttributionSourceKindCoordinates::ALL must contain no duplicates; got: {:?}",
            AttributionSourceKindCoordinates::ALL,
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_all_cardinality_matches_product_of_axes() {
        // Pins the product-cube cardinality contract as a function of
        // the constituent axis cardinalities rather than a literal
        // integer: any new variant on either sibling axis
        // (FigmentSourceKind::ALL or ConfigSourceKind::ALL) forces an
        // extension of Self::ALL in lockstep through this assertion.
        // Also pins the concrete current value (9) so an unintentional
        // churn on either axis is caught even when the product math
        // still works out.
        assert_eq!(
            AttributionSourceKindCoordinates::ALL.len(),
            FigmentSourceKind::ALL.len() * ConfigSourceKind::ALL.len(),
            "ALL must equal the cartesian product cardinality",
        );
        assert_eq!(
            AttributionSourceKindCoordinates::ALL.len(),
            9,
            "ALL must have 3 * 3 = 9 cells today",
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_all_equals_axes_cartesian_product() {
        // Tight equality (not subset) against the inline doubly-nested
        // product over the sibling ALL slices: Self::ALL IS the
        // cartesian product, no extras and no omissions. A future
        // variant on either sibling axis (figment_source_kind or
        // layer_kind) forces both an entry in the constant and a
        // corresponding cell appearing here through the inline product
        // enumeration.
        use std::collections::HashSet;
        let mut expected: HashSet<AttributionSourceKindCoordinates> = HashSet::new();
        for figment_source_kind in FigmentSourceKind::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                expected.insert(AttributionSourceKindCoordinates {
                    figment_source_kind,
                    layer_kind,
                });
            }
        }
        let listed: HashSet<AttributionSourceKindCoordinates> =
            AttributionSourceKindCoordinates::ALL
                .iter()
                .copied()
                .collect();
        assert_eq!(
            listed, expected,
            "ALL must be the exact cartesian product of the sibling ALL slices",
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_all_iterates_in_lexicographic_order() {
        // Pins iteration order figment_source_kind-outer /
        // layer_kind-inner — the doubly-nested product enumeration
        // over the sibling ALL slices in lexicographic order.
        // Consumers (dashboards, attestation manifests) that rely on
        // a stable iteration order for deterministic output read the
        // canonical order from this constant.
        let mut expected: Vec<AttributionSourceKindCoordinates> = Vec::new();
        for figment_source_kind in FigmentSourceKind::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                expected.push(AttributionSourceKindCoordinates {
                    figment_source_kind,
                    layer_kind,
                });
            }
        }
        let listed: Vec<AttributionSourceKindCoordinates> =
            AttributionSourceKindCoordinates::ALL.to_vec();
        assert_eq!(
            listed, expected,
            "ALL must iterate in figment_source_kind-outer / layer_kind-inner lexicographic order",
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_is_realizable_matches_diagonal() {
        // Pins the realizability invariant pointwise on every cell of
        // the cube:
        //   is_realizable iff
        //   (figment_source_kind, layer_kind) ∈ {(File, File), (Code, Defaults)}.
        // The two definitions agree on all 9 cells.
        for cell in AttributionSourceKindCoordinates::ALL.iter().copied() {
            let expected = matches!(
                (cell.figment_source_kind, cell.layer_kind),
                (FigmentSourceKind::File, ConfigSourceKind::File)
                    | (FigmentSourceKind::Code, ConfigSourceKind::Defaults)
            );
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal the source-axis diagonal law",
            );
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_realizable_partitions_into_2_realizable_and_7_unrealizable()
     {
        // Pins the 2 + 7 cardinality split:
        // - 2 realizable cells on the structural diagonal of source-
        //   axis rules: (File, File) from FileBySource and
        //   (Code, Defaults) from DefaultsByCodeUniqueness.
        // - 7 unrealizable cells covering every other combination:
        //   (File, Defaults), (File, Env), (Code, Env), (Code, File),
        //   (Custom, Defaults), (Custom, Env), (Custom, File).
        // A future custom-source rule lands as a new realizable cell
        // whose realizability is forced by the diagonal law,
        // extending the realizable image and shrinking the
        // unrealizable count in lockstep.
        let realizable = AttributionSourceKindCoordinates::ALL
            .iter()
            .filter(|c| c.is_realizable())
            .count();
        let unrealizable = AttributionSourceKindCoordinates::ALL
            .iter()
            .filter(|c| !c.is_realizable())
            .count();
        assert_eq!(realizable, 2, "realizable cells must be 2");
        assert_eq!(unrealizable, 7, "unrealizable cells must be 7");
        assert_eq!(
            realizable + unrealizable,
            AttributionSourceKindCoordinates::ALL.len(),
            "realizable + unrealizable must cover ALL exactly once",
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_realizable_image_equals_rule_image() {
        // The realizable half of ALL is the exact image of
        // AttributionRule::attribution_source_kind_coordinates over
        // the rule space. Pins which specific cells (not just how
        // many) are observable from a recognized AttributionRule —
        // a tighter contract than the cardinality split. Future
        // custom-source rules land coherently: a new rule extends
        // the image and forces an expansion of the realizable subset
        // in lockstep.
        use std::collections::HashSet;
        let observed: HashSet<AttributionSourceKindCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::attribution_source_kind_coordinates)
            .collect();
        let realizable: HashSet<AttributionSourceKindCoordinates> =
            AttributionSourceKindCoordinates::ALL
                .iter()
                .copied()
                .filter(|c| c.is_realizable())
                .collect();
        assert_eq!(
            observed, realizable,
            "observed image over AttributionRule::ALL must equal the realizable cells",
        );
    }

    #[test]
    fn attribution_rule_attribution_source_kind_coordinates_returns_realizable_cell_when_some() {
        // Forward-partial / image-realizable contract: every Some
        // return from AttributionRule::attribution_source_kind_coordinates
        // must satisfy is_realizable. The accessor never produces an
        // unrealizable cell, no matter which rule is queried.
        for rule in AttributionRule::ALL.iter().copied() {
            if let Some(cell) = rule.attribution_source_kind_coordinates() {
                assert!(
                    cell.is_realizable(),
                    "rule {rule:?} mapped to non-realizable cell {cell:?}",
                );
            }
        }
    }

    #[test]
    fn attribution_rule_attribution_source_kind_coordinates_some_iff_metadata_axis_source() {
        // Composition law on AttributionRule: the partial joint cell
        // projection is Some exactly when metadata_axis is
        // MetadataSource. Stronger than per-variant arms — enumerates
        // the entire rule space against the biconditional.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.attribution_source_kind_coordinates().is_some(),
                rule.metadata_axis() == AttributionAxis::MetadataSource,
                "rule {rule:?}: attribution_source_kind_coordinates.is_some() must equal \
                 (metadata_axis == MetadataSource)",
            );
        }
    }

    #[test]
    fn attribution_rule_attribution_source_kind_coordinates_mirrors_paired_projections() {
        // The joint-cell accessor must agree byte-for-byte with the
        // inline pairing of the two sibling projections:
        // - figment_source_kind() → cell.figment_source_kind
        // - layer_kind()          → cell.layer_kind
        // Pins the lossless-decomposition contract: consumers using
        // either the joint cell or the two reads separately see the
        // same data.
        for rule in AttributionRule::ALL.iter().copied() {
            let joint = rule.attribution_source_kind_coordinates();
            let paired = rule.figment_source_kind().map(|figment_source_kind| {
                AttributionSourceKindCoordinates {
                    figment_source_kind,
                    layer_kind: rule.layer_kind(),
                }
            });
            assert_eq!(
                joint, paired,
                "rule {rule:?}: joint accessor must equal the paired projections",
            );
        }
    }

    #[test]
    fn attribution_rule_attribution_source_kind_coordinates_pins_known_rules() {
        // Per-variant pinning table: source-axis rules already name
        // both halves of their joint cell, name-axis rules name
        // neither.
        let cases: [(AttributionRule, Option<AttributionSourceKindCoordinates>); 5] = [
            (
                AttributionRule::FileBySource,
                Some(AttributionSourceKindCoordinates {
                    figment_source_kind: FigmentSourceKind::File,
                    layer_kind: ConfigSourceKind::File,
                }),
            ),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                Some(AttributionSourceKindCoordinates {
                    figment_source_kind: FigmentSourceKind::Code,
                    layer_kind: ConfigSourceKind::Defaults,
                }),
            ),
            (AttributionRule::FileByMetadataName, None),
            (AttributionRule::EnvByPrefix, None),
            (AttributionRule::EnvByUniqueness, None),
        ];
        for (rule, expected) in cases {
            assert_eq!(
                rule.attribution_source_kind_coordinates(),
                expected,
                "rule {rule:?}: attribution_source_kind_coordinates pin",
            );
        }
    }

    #[test]
    fn failing_source_attribution_attribution_source_kind_coordinates_mirrors_rule() {
        // The envelope's accessor must agree with the rule's,
        // byte-for-byte, on every recognized rule. Pins the
        // convenience accessor as a thin forwarder over
        // AttributionRule::attribution_source_kind_coordinates.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.attribution_source_kind_coordinates(),
                rule.attribution_source_kind_coordinates(),
                "envelope for rule {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_is_copy_and_hashable() {
        // Typescape bounds parity with the sibling product-cube
        // structs (AttributionCoordinates, FormatCoordinates,
        // ErrorLocalizationCoordinates) and the underlying axis
        // primitives (FigmentSourceKind, ConfigSourceKind).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributionSourceKindCoordinates {
            figment_source_kind: FigmentSourceKind::File,
            layer_kind: ConfigSourceKind::File,
        });
        set.insert(AttributionSourceKindCoordinates {
            figment_source_kind: FigmentSourceKind::Code,
            layer_kind: ConfigSourceKind::Defaults,
        });
        // Duplicate insertion — no growth.
        set.insert(AttributionSourceKindCoordinates {
            figment_source_kind: FigmentSourceKind::File,
            layer_kind: ConfigSourceKind::File,
        });
        assert_eq!(set.len(), 2, "every coordinate must hash distinctly");

        // Copy: rebind without move.
        let c = AttributionSourceKindCoordinates {
            figment_source_kind: FigmentSourceKind::Custom,
            layer_kind: ConfigSourceKind::Env,
        };
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn attribution_source_kind_coordinates_realizable_image_lies_in_attribution_source_kind_coordinates_all()
     {
        // Cross-primitive cover law: every realizable cell observed
        // from AttributionRule lies in
        // AttributionSourceKindCoordinates::ALL. Pins the contract
        // that the rule's partial-projection image stays a sub-image
        // of the declared product cube — no rule-specific joint cell
        // ever escapes the typescape's declared product axis.
        use std::collections::HashSet;
        let observed: HashSet<AttributionSourceKindCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::attribution_source_kind_coordinates)
            .collect();
        let declared: HashSet<AttributionSourceKindCoordinates> =
            AttributionSourceKindCoordinates::ALL
                .iter()
                .copied()
                .collect();
        assert!(
            observed.is_subset(&declared),
            "image of attribution_source_kind_coordinates must lie in \
             AttributionSourceKindCoordinates::ALL; observed: {observed:?}, \
             declared: {declared:?}",
        );
    }
}

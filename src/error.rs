use std::path::PathBuf;

use crate::source::{
    ConfigSource, ConfigSourceChain, ConfigSourceKind, EnvMetadataTag, FigmentNameTag,
    FigmentNameTagKind, FigmentSourceKind, FigmentSourceTag,
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

    /// A resolved candidate parsed cleanly (figment/serde succeeded) but
    /// failed semantic validation — [`crate::hotswap::Validate::validate`]
    /// (feature `hotswap`) returned `Err`. Distinct from
    /// [`Self::Extract`]/[`Self::Figment`]: those catch shape/type
    /// mismatches figment can detect on its own; this catches a
    /// well-typed value that is still semantically wrong (an unknown
    /// enum-string, an out-of-range port, a cross-field constraint).
    #[error("config validation failed: {0}")]
    Validation(String),
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
        format!(" at field `{}`", dotted_field_path(path))
    }
}

/// Render a figment field-path segment slice as a single `.`-joined
/// dotted key.
///
/// One source of truth for the operator-facing rendering of an offending
/// field path. Shared by the [`ShikumiError::Extract`] `Display` impl
/// (`display_field_path`), the programmatic [`ShikumiError::field_path_dotted`]
/// accessor, and the cross-thread [`crate::ReloadFailure::field_path_dotted`]
/// mirror — so the live error, its rendered display segment, and its
/// captured envelope name the offending field with byte-identical
/// strings and can never drift on the separator.
pub(crate) fn dotted_field_path(path: &[String]) -> String {
    path.join(".")
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
///
/// `Ord` / `PartialOrd` are declaration-order lex over [`Self::ALL`]
/// (`NotFound < Parse < Watch < Io < Figment < Extract`): a
/// `BTreeMap<ShikumiErrorKind, T>` keyed on the error-kind axis
/// (per-kind failure-rate histograms, per-kind alert thresholds,
/// attestation manifests recording the captured-failure mix
/// histogram, structured-diagnostic legends bucketing per-kind
/// counters in declaration order) emits rows in that order
/// deterministically without a hand-rolled comparator at the
/// renderer. Idiom-peer of the same derive on
/// [`crate::SecretClientKind`] (commit `24c7b33`),
/// [`crate::DiffLineKind`] (commit `c403e1a`),
/// [`crate::WatchEventClass`] (commit `94f8a8b`),
/// [`crate::EnvMetadataTagKind`] (commit `b556b75`),
/// [`crate::SecretRefShape`] (commit `8a84bb6`),
/// [`crate::SecretBackendKind`] (commit `9b1da86`),
/// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
/// [`crate::FigmentSourceKind`] (commit `5df265c`), and
/// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
/// captured-failure variant axis closed-enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// [`ShikumiError::Validation`] — a resolved candidate parsed
    /// cleanly but failed semantic validation.
    Validation,
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
        Self::Validation,
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
    ///
    /// `const fn` so the polarity is usable in const contexts (static
    /// slice initializers, const cube arms) — parity with the peer
    /// sibling predicates on the neighbouring closed axes
    /// ([`AttributionConfidence::is_exact`],
    /// [`FieldPathLocalization::is_applicable`],
    /// [`crate::FormatProvenance::is_shikumi_built`]).
    #[must_use]
    pub const fn is_figment_bearing(self) -> bool {
        match self {
            Self::Extract | Self::Figment => true,
            Self::NotFound | Self::Parse | Self::Watch | Self::Io | Self::Validation => false,
        }
    }

    /// Returns `true` for the kinds that do *not* wrap a
    /// [`figment::Error`] — [`Self::NotFound`], [`Self::Parse`],
    /// [`Self::Watch`], [`Self::Io`], [`Self::Validation`]; equivalent
    /// to `!self.is_figment_bearing()`.
    ///
    /// Sibling of [`Self::is_figment_bearing`] on the other half of the
    /// closed binary partition over the kind axis. Single source of
    /// truth for the non-figment-bearing side: before this sibling the
    /// negation was inlined as fresh `!kind.is_figment_bearing()` reads
    /// at the ALL-partition cardinality pins
    /// (`shikumi_error_kind_all_partitions_figment_bearing_axis`,
    /// `is_figment_bearing_false_for_non_figment_kinds`), each of which
    /// re-derived the polarity of the negative arm at the call site.
    /// The routing collapses that to one — the negative half is now a
    /// named predicate at the kind altitude, so the
    /// closed-binary-partition pin
    /// (`is_figment_bearing_predicates_are_a_closed_binary_partition`)
    /// can hold the two arms exhaustive and disjoint.
    ///
    /// Peer sibling-predicate pair on the same typescape discipline as
    /// [`AttributionConfidence::is_exact`] /
    /// [`AttributionConfidence::is_fallback`] on the confidence axis,
    /// [`FieldPathLocalization::is_applicable`] /
    /// [`FieldPathLocalization::is_not_applicable`] on the localization
    /// axis, and [`crate::FormatProvenance::is_shikumi_built`] /
    /// [`crate::FormatProvenance::is_figment_builtin`] on the
    /// format-provenance axis: closed-axis primitives expose a
    /// per-partition predicate alongside the closed-enum dispatch so
    /// the common "is it this side?" question stays one method call.
    #[must_use]
    pub const fn is_not_figment_bearing(self) -> bool {
        !self.is_figment_bearing()
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
            Self::Validation => "validation",
        }
    }

    /// Returns `true` for [`Self::NotFound`]; equivalent to
    /// `self == ShikumiErrorKind::NotFound`.
    ///
    /// Kind-side sibling predicate over the closed seven-way
    /// [`ShikumiErrorKind`] partition. Consumers holding only the kind
    /// (a `HashMap`/`HashSet` key, a `BTreeMap` bucket, a per-kind
    /// alerting-threshold table, a cross-thread failure-class tag
    /// captured on a [`crate::ReloadFailure`] envelope after the
    /// borrowed [`ShikumiError`] payload's owned
    /// `Vec<PathBuf>` / `notify::Error` / `Box<figment::Error>` /
    /// `Vec<ConfigSource>` fields have been dropped) classify without
    /// materializing a synthetic [`ShikumiError`] first — the tag-side
    /// data-carrying enum holds payloads a kind-only observer cannot
    /// cheaply reconstruct.
    ///
    /// Peer to [`crate::SecretErrorKind::is_not_found`] /
    /// [`crate::SecretErrorKind::is_unauthorized`] / … on the
    /// secret-client error-kind axis (closed by `6b67a81`),
    /// [`crate::ConfigSourceKind::is_defaults`] /
    /// [`crate::ConfigSourceKind::is_env`] /
    /// [`crate::ConfigSourceKind::is_file`] on the shikumi-side
    /// layer-kind axis (closed by `9600b8b`),
    /// [`crate::FigmentSourceKind::is_file`] /
    /// [`crate::FigmentSourceKind::is_code`] /
    /// [`crate::FigmentSourceKind::is_custom`] on the figment-side
    /// source axis, and [`crate::SecretBackendKind::is_literal`] /
    /// [`crate::SecretBackendKind::is_op`] / … on the payload-carrying
    /// secret-backend axis (closed by `9dc6d1f`): same kind-side
    /// sibling-predicate discipline applied to the shikumi error-
    /// variant axis, previously carrying only the meta-partition
    /// predicates [`Self::is_figment_bearing`] /
    /// [`Self::is_not_figment_bearing`] with no per-variant
    /// classification at the primitive's altitude.
    ///
    /// Structural bridge to the tag-side sibling
    /// [`ShikumiError::is_not_found`]:
    /// `err.kind().is_not_found() == err.is_not_found()` for every
    /// [`ShikumiError`], pinned by
    /// [`tests::shikumi_error_kind_not_found_predicate_agrees_with_shikumi_error_is_not_found_pointwise`].
    /// The seven sibling predicates form a closed disjoint partition of
    /// [`Self::ALL`] — every variant satisfies exactly one, none
    /// satisfies two, none satisfies zero — pinned by
    /// [`tests::shikumi_error_kind_predicates_are_a_closed_septet_partition`].
    /// The kind-alone equality-agreement law
    /// (`k.is_X() == (k == Self::X)` for every variant) is pinned by
    /// [`tests::shikumi_error_kind_predicates_agree_with_equality_pointwise`].
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Returns `true` for [`Self::Parse`]; equivalent to
    /// `self == ShikumiErrorKind::Parse`. Kind-side sibling predicate;
    /// see [`Self::is_not_found`] for the full contract.
    ///
    /// Structural bridge to the tag-side sibling
    /// [`ShikumiError::is_parse`]:
    /// `err.kind().is_parse() == err.is_parse()` for every
    /// [`ShikumiError`], pinned by
    /// [`tests::shikumi_error_kind_parse_predicate_agrees_with_shikumi_error_is_parse_pointwise`].
    #[must_use]
    pub const fn is_parse(self) -> bool {
        matches!(self, Self::Parse)
    }

    /// Returns `true` for [`Self::Watch`]; equivalent to
    /// `self == ShikumiErrorKind::Watch`. Kind-side sibling predicate;
    /// see [`Self::is_not_found`] for the full contract.
    ///
    /// Classifies the file-watcher (`notify` crate) failure surface —
    /// symlink-target churn, inotify/FSEvents backpressure, or the
    /// polling-watcher's `read_dir` errors — as its own kind
    /// distinct from [`Self::Io`] (which surfaces a bare
    /// [`std::io::Error`] from a config-file operation without
    /// [`notify`] context).
    #[must_use]
    pub const fn is_watch(self) -> bool {
        matches!(self, Self::Watch)
    }

    /// Returns `true` for [`Self::Io`]; equivalent to
    /// `self == ShikumiErrorKind::Io`. Kind-side sibling predicate;
    /// see [`Self::is_not_found`] for the full contract.
    ///
    /// Classifies a [`std::io::Error`] surfaced from a config-file
    /// operation (directory listing, file read) — distinct from
    /// [`Self::Watch`] (a [`notify`]-level failure that may itself
    /// wrap an I/O error) and from [`Self::NotFound`] (typed
    /// exhaustion-of-search-locations reporting rather than a raw
    /// [`std::io::ErrorKind::NotFound`]).
    #[must_use]
    pub const fn is_io(self) -> bool {
        matches!(self, Self::Io)
    }

    /// Returns `true` for [`Self::Figment`]; equivalent to
    /// `self == ShikumiErrorKind::Figment`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Kind-side refinement of [`Self::is_figment_bearing`] — one of
    /// the two figment-bearing kinds ([`Self::Figment`] and
    /// [`Self::Extract`]); the sibling
    /// `k.is_figment() || k.is_extract() == k.is_figment_bearing()`
    /// law is pinned by
    /// [`tests::shikumi_error_kind_figment_extract_siblings_partition_is_figment_bearing`].
    /// Observers wanting to distinguish a raw [`figment::Error`]
    /// (`From<Box<figment::Error>>` construction, without a recorded
    /// [`ConfigSource`] chain) from an
    /// [`ShikumiError::Extract`] (with recorded chain) — a
    /// [`crate::ProviderChain`]-attributed failure that
    /// [`crate::ReloadFailure::failing_attribution`] can localize —
    /// route on this predicate at the kind altitude rather than
    /// re-deriving the two-way split from
    /// [`Self::is_figment_bearing`] plus a second predicate.
    #[must_use]
    pub const fn is_figment(self) -> bool {
        matches!(self, Self::Figment)
    }

    /// Returns `true` for [`Self::Extract`]; equivalent to
    /// `self == ShikumiErrorKind::Extract`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Kind-side refinement of [`Self::is_figment_bearing`] — the
    /// figment-bearing kind that also carries a recorded
    /// [`ConfigSource`] chain via [`ShikumiError::sources`], the
    /// prerequisite for [`ShikumiError::failing_attribution`] to
    /// localize a failing layer via the recognized rules in
    /// [`AttributionRule::ALL`]. Peer of [`Self::is_figment`] on the
    /// other cell of the figment-bearing partition.
    #[must_use]
    pub const fn is_extract(self) -> bool {
        matches!(self, Self::Extract)
    }

    /// Returns `true` for [`Self::Validation`]; equivalent to
    /// `self == ShikumiErrorKind::Validation`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Classifies the [`crate::hotswap::Validate::validate`]
    /// (feature `hotswap`) semantic-refusal surface: a candidate
    /// parsed cleanly by figment/serde but failed a cross-field
    /// invariant, an out-of-range port, or an unknown-enum string —
    /// distinct from the two figment-bearing kinds that report
    /// shape/type mismatches figment can detect on its own.
    #[must_use]
    pub const fn is_validation(self) -> bool {
        matches!(self, Self::Validation)
    }

    /// The two FIGMENT-BEARING [`ShikumiErrorKind`] variants —
    /// [`Self::Figment`] (a bare [`figment::Error`] without a recorded
    /// [`ConfigSource`] chain) and [`Self::Extract`] (with a recorded
    /// chain) — in the SAME relative declaration order they occupy in
    /// [`Self::ALL`], carrying the *figment-wrapping* pole of the
    /// (figment-bearing × not-figment-bearing) polarity axis at the
    /// primitive's OWN altitude on the seven-way kind axis, mirroring
    /// the shipped boolean predicate [`Self::is_figment_bearing`] one
    /// altitude down: every variant in this slice satisfies
    /// `k.is_figment_bearing()`, and no variant outside it does.
    ///
    /// Paired with [`Self::NOT_FIGMENT_BEARING`], the two disjoint
    /// slices partition [`Self::ALL`] at the static-slice altitude the
    /// same way the shipped boolean predicates
    /// [`Self::is_figment_bearing`] / [`Self::is_not_figment_bearing`]
    /// meta-partition it at the boolean altitude. The two constants sit
    /// in the same `impl ShikumiErrorKind` block as [`Self::ALL`] and
    /// follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Written as an explicit two-variant slice literal in the SAME
    /// relative declaration order the figment-bearing pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_figment_bearing`] at const-fn altitude — so
    /// the two declarations (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first shape where they disagree.
    /// A hypothetical third figment-bearing kind — a variant that
    /// wraps a figment error through a third path the two current arms
    /// don't name — lands here in lockstep with
    /// [`Self::is_figment_bearing`], and the cardinality pin catches
    /// any drift between the slice and the boolean predicate on the
    /// same edit.
    ///
    /// Idiom-peer of [`crate::Format::FEATURE_GATED`] (commit
    /// `2013269`) on the file-format axis (the first landing of this
    /// discipline on a five-way primitive with an interleaved polarity
    /// partition), [`crate::source::FigmentNameTagKind::FORMAT`]
    /// (commit `2d2ef9d`),
    /// [`crate::source::EnvMetadataTagKind::PREFIXED`] (commit
    /// `13304d0`), [`AttributionAxis::METADATA_SOURCE`] (commit
    /// `34bfbb6`), [`crate::cli::OutputFormat::YAML`] (commit
    /// `292ca1d`), [`AttributionConfidence::EXACT`] (commit `13c1003`),
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] (commit `7ef79e4`),
    /// [`crate::secret::SecretRefShape::WHOLE`] (commit `036673b`),
    /// [`crate::cube::PartitionFace::REALIZABLE`] (commit `a344056`),
    /// [`crate::source::ConfigSourceKind::DEFAULTS`] (commit
    /// `2cd8ef8`), and [`crate::tiered::ConfigTierKind::COMPUTED`]
    /// (commit `2c0686f`) — the per-half meta-partition slice-constant
    /// discipline applied here to the seven-way shikumi error-kind
    /// axis's (figment-bearing × not-figment-bearing) meta-partition,
    /// with a genuine interleaved projection: the not-figment-bearing
    /// pole spans [`Self::NotFound`] / [`Self::Parse`] / [`Self::Watch`]
    /// / [`Self::Io`] on the ALL-prefix and [`Self::Validation`] on the
    /// ALL-suffix, split by the two figment-bearing cells in the middle
    /// ([`Self::Figment`] and [`Self::Extract`]).
    ///
    /// The two agreement laws
    /// (`FIGMENT_BEARING.iter().all(|k| k.is_figment_bearing())` and
    /// `FIGMENT_BEARING.iter().all(|k| !k.is_not_figment_bearing())`)
    /// are pinned by
    /// [`tests::shikumi_error_kind_figment_bearing_slice_agrees_with_is_figment_bearing_predicate`].
    /// Partition invariant with [`Self::NOT_FIGMENT_BEARING`]:
    /// [`tests::shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::shikumi_error_kind_figment_bearing_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::shikumi_error_kind_figment_bearing_and_not_figment_bearing_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_are_const_addressable`].
    pub const FIGMENT_BEARING: &'static [Self] = &[Self::Figment, Self::Extract];

    /// The five NOT-FIGMENT-BEARING [`ShikumiErrorKind`] variants —
    /// [`Self::NotFound`], [`Self::Parse`], [`Self::Watch`],
    /// [`Self::Io`], and [`Self::Validation`] — in the SAME relative
    /// declaration order they occupy in [`Self::ALL`], the complement
    /// pole of [`Self::FIGMENT_BEARING`] on the
    /// (figment-bearing × not-figment-bearing) closed-binary polarity at
    /// the axis primitive's OWN altitude on the seven-way kind axis.
    /// Mirrors the shipped boolean predicate
    /// [`Self::is_not_figment_bearing`] one altitude down.
    ///
    /// The declaration-order projection preserves [`Self::ALL`]'s
    /// interleaving on this pole: [`Self::NotFound`], [`Self::Parse`],
    /// [`Self::Watch`], and [`Self::Io`] come before [`Self::Figment`]
    /// / [`Self::Extract`] (skipped — the other pole), and
    /// [`Self::Validation`] comes AFTER [`Self::Figment`] /
    /// [`Self::Extract`], so the not-figment-bearing slice is neither a
    /// prefix nor a suffix of [`Self::ALL`] but the ALL-order filtered
    /// projection under [`Self::is_not_figment_bearing`]. Any future
    /// variant landing on this pole extends the slice at the
    /// ALL-declaration-order position, not at the tail.
    ///
    /// The partition invariant with [`Self::FIGMENT_BEARING`] pins the
    /// whole-set cardinality identity
    /// `FIGMENT_BEARING.len() + NOT_FIGMENT_BEARING.len() == ALL.len()`.
    /// Because the axis is a closed binary meta-partition by
    /// construction today, a future third figment-bearing kind would
    /// first fail the two-versus-five cardinality pins, then fail the
    /// partition and cardinality pins on this constant pair unless
    /// extended in lockstep with the boolean predicates.
    ///
    /// See [`Self::FIGMENT_BEARING`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a
    /// filter through [`Self::is_figment_bearing`]), and the
    /// load-bearing agreement, partition, order-preservation,
    /// no-duplicates, cardinality, and const-addressability pins.
    pub const NOT_FIGMENT_BEARING: &'static [Self] = &[
        Self::NotFound,
        Self::Parse,
        Self::Watch,
        Self::Io,
        Self::Validation,
    ];

    /// The single [`Self::NotFound`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude — the singleton slice `&[Self::NotFound]`
    /// mirroring the shipped boolean predicate [`Self::is_not_found`]
    /// one altitude down: every variant in this slice satisfies
    /// `kind.is_not_found()`, and no variant outside it does.
    ///
    /// Paired with the six siblings ([`Self::ONLY_PARSE`],
    /// [`Self::ONLY_WATCH`], [`Self::ONLY_IO`], [`Self::ONLY_FIGMENT`],
    /// [`Self::ONLY_EXTRACT`], [`Self::ONLY_VALIDATION`]), the seven
    /// disjoint singleton slices partition [`Self::ALL`] at the
    /// static-slice altitude the same way the shipped boolean
    /// predicates ([`Self::is_not_found`] / [`Self::is_parse`] /
    /// [`Self::is_watch`] / [`Self::is_io`] / [`Self::is_figment`] /
    /// [`Self::is_extract`] / [`Self::is_validation`]) meta-partition it
    /// at the boolean altitude. All seven constants sit in the same
    /// `impl ShikumiErrorKind` block as [`Self::ALL`] /
    /// [`Self::FIGMENT_BEARING`] / [`Self::NOT_FIGMENT_BEARING`] and
    /// follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the seven identity poles occupy in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through the seven identity predicates at const-fn altitude —
    /// so the two declaration surfaces (the slice literals and the
    /// boolean predicates) remain independent load-bearing witnesses
    /// of the same identity meta-partition, and a future edit that
    /// shifts a variant across an identity pole on ONE surface but not
    /// the other diverges at test time on the first shape where they
    /// disagree.
    ///
    /// Also the first cell of [`Self::NOT_FIGMENT_BEARING`] — the two
    /// witnesses agree here (`ONLY_NOT_FOUND ⊆ NOT_FIGMENT_BEARING`)
    /// per the identity-vs-compound cross-check that pins the seven
    /// identity singletons against the shipped figment-bearing meta-
    /// partition.
    ///
    /// **Idiom-peer.** Septenary landing of the per-half meta-partition
    /// slice-constant discipline, matching altitude-for-altitude the
    /// senary [`crate::secret_client::SecretOperation::ONLY_GET`] / …
    /// / `ONLY_GET_VERSION` (commit `bfe3e24`), the septenary
    /// [`crate::secret_client::SecretClientKind::ONLY_MEM`] / … /
    /// `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), the octonary
    /// [`crate::secret::SecretBackendKind::ONLY_LITERAL`] / … /
    /// `ONLY_GCP_SECRET` (commit `19364e3`), the quinary
    /// [`crate::cli::TierArg::ONLY_BARE`] / … / `ONLY_ENV` (commit
    /// `f7f5529`), and the quaternary
    /// [`crate::tiered::ConfigTierKind::ONLY_BARE`] / … /
    /// `ONLY_CUSTOM` (commit `ff6492b`) — the per-half meta-partition
    /// slice-constant discipline applied here to the seven-way
    /// [`ShikumiErrorKind`] axis (the first identity-partition landing
    /// on the error-kind primitive), lifting the seven identity poles
    /// onto the slice-constant altitude alongside the shipped compound-
    /// polarity [`Self::FIGMENT_BEARING`] / [`Self::NOT_FIGMENT_BEARING`]
    /// pair one altitude up.
    ///
    /// The seven agreement laws
    /// (`ONLY_NOT_FOUND.iter().all(|k| k.is_not_found())` and
    /// `ONLY_NOT_FOUND.iter().all(|k| !k.is_parse() && !k.is_watch() &&
    /// !k.is_io() && !k.is_figment() && !k.is_extract() &&
    /// !k.is_validation())`, symmetric on the six siblings) are pinned
    /// by
    /// [`tests::shikumi_error_kind_identity_slices_agree_with_identity_predicates`].
    /// Partition invariant across all seven:
    /// [`tests::shikumi_error_kind_identity_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::shikumi_error_kind_identity_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::shikumi_error_kind_identity_slices_have_no_duplicates`].
    /// Cardinality-agreement with the seven boolean poles:
    /// [`tests::shikumi_error_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::shikumi_error_kind_identity_slices_are_const_addressable`].
    /// Cross-altitude weld with the compound-polarity pair:
    /// [`tests::shikumi_error_kind_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_NOT_FOUND: &'static [Self] = &[Self::NotFound];

    /// The single [`Self::Parse`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude. See [`Self::ONLY_NOT_FOUND`] for the full
    /// contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_PARSE: &'static [Self] = &[Self::Parse];

    /// The single [`Self::Watch`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude. See [`Self::ONLY_NOT_FOUND`] for the full
    /// contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_WATCH: &'static [Self] = &[Self::Watch];

    /// The single [`Self::Io`] pole of the seven-way identity meta-
    /// partition on the [`ShikumiErrorKind`] axis at the static-slice
    /// altitude. See [`Self::ONLY_NOT_FOUND`] for the full contract,
    /// load-bearing pins, and idiom-peer landings.
    pub const ONLY_IO: &'static [Self] = &[Self::Io];

    /// The single [`Self::Figment`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude. Also the first cell of [`Self::FIGMENT_BEARING`]
    /// — the two witnesses agree here (`ONLY_FIGMENT ⊆ FIGMENT_BEARING`)
    /// per the identity-vs-compound cross-check. See
    /// [`Self::ONLY_NOT_FOUND`] for the full contract, load-bearing
    /// pins, and idiom-peer landings.
    pub const ONLY_FIGMENT: &'static [Self] = &[Self::Figment];

    /// The single [`Self::Extract`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude. Also the second cell of [`Self::FIGMENT_BEARING`]
    /// — the two witnesses agree here (`ONLY_EXTRACT ⊆ FIGMENT_BEARING`)
    /// per the identity-vs-compound cross-check. See
    /// [`Self::ONLY_NOT_FOUND`] for the full contract, load-bearing
    /// pins, and idiom-peer landings.
    pub const ONLY_EXTRACT: &'static [Self] = &[Self::Extract];

    /// The single [`Self::Validation`] pole of the seven-way identity
    /// meta-partition on the [`ShikumiErrorKind`] axis at the static-
    /// slice altitude. Also the last cell of
    /// [`Self::NOT_FIGMENT_BEARING`] — the two witnesses agree here
    /// (`ONLY_VALIDATION ⊆ NOT_FIGMENT_BEARING`) per the identity-vs-
    /// compound cross-check, and the interleaved position (after the
    /// two figment-bearing cells in [`Self::ALL`]) means the identity-
    /// slice union on the non-figment-bearing pole reproduces
    /// [`Self::NOT_FIGMENT_BEARING`]'s neither-prefix-nor-suffix
    /// projection. See [`Self::ONLY_NOT_FOUND`] for the full contract,
    /// load-bearing pins, and idiom-peer landings.
    pub const ONLY_VALIDATION: &'static [Self] = &[Self::Validation];
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

    /// The two APPLICABLE [`FieldPathLocalization`] variants —
    /// [`Self::Localized`] (figment attached a non-empty dotted path)
    /// and [`Self::FigmentUnlocalized`] (figment error present but its
    /// `path` slot is empty) — in the SAME relative declaration order
    /// they occupy in [`Self::ALL`], carrying the
    /// *figment-bearing-signal-present* pole of the
    /// (applicable × not-applicable) polarity axis at the primitive's
    /// OWN altitude on the field-localization axis, mirroring the
    /// shipped boolean predicate [`Self::is_applicable`] one altitude
    /// down: every variant in this slice satisfies
    /// `loc.is_applicable()`, and no variant outside it does.
    ///
    /// Paired with [`Self::NOT_APPLICABLE`], the two disjoint slices
    /// partition [`Self::ALL`] at the static-slice altitude the same
    /// way the shipped boolean predicates [`Self::is_applicable`] /
    /// [`Self::is_not_applicable`] meta-partition it at the boolean
    /// altitude. The two constants sit in the same `impl
    /// FieldPathLocalization` block as [`Self::ALL`] and follow the
    /// same `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit two-variant slice literal in the SAME
    /// relative declaration order the applicable pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_applicable`] at const-fn altitude — so the
    /// two declarations (the slice literal and the boolean predicate)
    /// remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first shape where they disagree.
    /// A hypothetical fourth variant landing on the applicable side
    /// (e.g. a `PartiallyLocalized` cell for a source that reports a
    /// coarse-grained container but no leaf key) lands here in
    /// lockstep with [`Self::is_applicable`], and the cardinality pin
    /// catches any drift between the slice and the boolean predicate
    /// on the same edit.
    ///
    /// Idiom-peer of [`crate::ShikumiErrorKind::FIGMENT_BEARING`]
    /// (commit `e45018d`), [`crate::Format::FEATURE_GATED`] (commit
    /// `2013269`), [`crate::source::FigmentNameTagKind::FORMAT`]
    /// (commit `2d2ef9d`), [`crate::source::EnvMetadataTagKind::PREFIXED`]
    /// (commit `13304d0`), [`crate::AttributionAxis::METADATA_SOURCE`]
    /// (commit `34bfbb6`), [`crate::cli::OutputFormat::YAML`] (commit
    /// `292ca1d`), [`crate::AttributionConfidence::EXACT`] (commit
    /// `13c1003`), [`crate::FormatProvenance::FIGMENT_BUILTIN`]
    /// (commit `7ef79e4`), [`crate::secret::SecretRefShape::WHOLE`]
    /// (commit `036673b`), and [`crate::cube::PartitionFace::REALIZABLE`]
    /// (commit `a344056`) — the per-half meta-partition slice-constant
    /// discipline applied here to the three-way field-localization
    /// axis's (applicable × not-applicable) 2/1 meta-partition.
    ///
    /// The two agreement laws
    /// (`APPLICABLE.iter().all(|l| l.is_applicable())` and
    /// `APPLICABLE.iter().all(|l| !l.is_not_applicable())`) are pinned
    /// by
    /// [`tests::field_path_localization_applicable_slice_agrees_with_is_applicable_predicate`].
    /// Partition invariant with [`Self::NOT_APPLICABLE`]:
    /// [`tests::field_path_localization_applicable_and_not_applicable_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::field_path_localization_applicable_and_not_applicable_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::field_path_localization_applicable_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::field_path_localization_applicable_and_not_applicable_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::field_path_localization_applicable_and_not_applicable_slices_are_const_addressable`].
    pub const APPLICABLE: &'static [Self] = &[Self::Localized, Self::FigmentUnlocalized];

    /// The one NOT-APPLICABLE [`FieldPathLocalization`] variant —
    /// [`Self::NotApplicable`] — carrying the
    /// *no-figment-error-at-all* pole of the
    /// (applicable × not-applicable) polarity axis at the primitive's
    /// OWN altitude on the field-localization axis, mirroring the
    /// shipped boolean predicate [`Self::is_not_applicable`] one
    /// altitude down.
    ///
    /// A single-variant slice at today's cardinality — the
    /// not-applicable pole is currently a singleton — but declared as
    /// a slice (not a scalar) so a future non-applicable variant lands
    /// here in lockstep at the ALL-declaration-order position, and
    /// [`Self::APPLICABLE`] and [`Self::NOT_APPLICABLE`] retain the
    /// same shape at the type level. Idiom-peer of
    /// [`crate::AttributionAxis::METADATA_NAME`] (commit `34bfbb6`) and
    /// [`crate::AttributionConfidence::FALLBACK`] (commit `13c1003`),
    /// both of which are today singletons on their respective
    /// closed-binary primitives and would extend the same way.
    ///
    /// See [`Self::APPLICABLE`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_not_applicable`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const NOT_APPLICABLE: &'static [Self] = &[Self::NotApplicable];

    /// The single LOCALIZED [`FieldPathLocalization`] variant —
    /// [`Self::Localized`] (the figment-attached-dotted-path pole of the
    /// (localized × figment-unlocalized × not-applicable) identity
    /// meta-partition on the field-localization axis) — in the SAME
    /// relative declaration order it occupies in [`Self::ALL`], as a
    /// `'static` slice constant at the primitive's OWN altitude on the
    /// three-way field-localization axis. Mirrors the shipped boolean
    /// predicate [`Self::is_localized`] one altitude down (per-variant
    /// polarity) and follows the same `pub const &'static [Self]`
    /// static-slice discipline as [`Self::ALL`].
    ///
    /// Paired with [`Self::ONLY_FIGMENT_UNLOCALIZED`] and
    /// [`Self::ONLY_NOT_APPLICABLE`], the three disjoint singleton slices
    /// partition [`Self::ALL`] at the static-slice altitude the same way
    /// the shipped boolean predicates [`Self::is_localized`] /
    /// [`Self::is_figment_unlocalized`] / [`Self::is_not_applicable`]
    /// meta-partition it at the boolean altitude (per
    /// [`tests::field_path_localization_per_variant_predicates_are_a_closed_ternary_partition`]).
    /// The three constants sit in the same `impl FieldPathLocalization`
    /// block as [`Self::ALL`] and the shipped compound-polarity
    /// meta-partition [`Self::APPLICABLE`] / [`Self::NOT_APPLICABLE`],
    /// and follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the localized pole occupies in
    /// [`Self::ALL`], not derived by filtering [`Self::ALL`] through
    /// [`Self::is_localized`] at const-fn altitude — so the two
    /// declaration surfaces (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the same
    /// identity meta-partition, and a future edit that shifts a variant
    /// across the polarity on ONE surface but not the other diverges
    /// at test time on the first shape where they disagree.
    ///
    /// A per-half consumer iterating [`Self::ONLY_LOCALIZED`] (a
    /// diagnostics renderer emitting a source-span annotation only when
    /// the leaf-key path is available; a CLI
    /// `--filter-localization=localized` walking captured failure
    /// records; a per-cell alerting bucket on the failure surface; an
    /// attestation manifest recording the per-cell localization
    /// histogram of resolved failures; a structured-log field surfacing
    /// only failures with an attached dotted path) reaches the localized
    /// pole without a runtime filter through
    /// `FieldPathLocalization::ALL.iter().filter(|l| l.is_localized())`
    /// — one static slice reference, const-addressable end-to-end,
    /// ordered the same way [`Self::ALL`] is.
    ///
    /// Ternary peer of the shipped ternary
    /// [`crate::AttributionRule::LAYER_FILE`] /
    /// [`crate::AttributionRule::LAYER_ENV`] /
    /// [`crate::AttributionRule::LAYER_DEFAULTS`] compound-polarity
    /// meta-partition (commit `fae8271`) and of the shipped ternary
    /// identity meta-partition
    /// [`crate::FigmentSourceKind::FILE`] /
    /// [`crate::FigmentSourceKind::CODE`] /
    /// [`crate::FigmentSourceKind::CUSTOM`] (commit `723060b`) on the
    /// figment-Source-axis kind; identity-partition peer of the shipped
    /// quinary [`crate::AttributionRule::ONLY_FILE_BY_SOURCE`] / …
    /// (commit `9ac2fcb`) and septenary
    /// [`crate::ShikumiErrorKind::ONLY_NOT_FOUND`] / … (commit
    /// `6e74116`) — the per-half meta-partition slice-constant
    /// discipline applied here to the three-way
    /// field-path-localization axis's identity meta-partition.
    ///
    /// A future quaternary variant (e.g. a `PartiallyLocalized` cell for
    /// a source that reports a coarse-grained container but no leaf key,
    /// referenced in [`Self::ALL`]'s docs) landing on [`Self`] must
    /// either extend one slice in lockstep with the boolean predicate
    /// that admits it, or introduce a fourth slice; the partition and
    /// cardinality pins refuse a silent landing under the negation of
    /// one of the existing three.
    ///
    /// The three-way agreement laws
    /// (`ONLY_LOCALIZED.iter().all(|l| l.is_localized())`,
    /// `!ONLY_LOCALIZED.iter().any(|l| l.is_figment_unlocalized())`,
    /// `!ONLY_LOCALIZED.iter().any(|l| l.is_not_applicable())`, and the
    /// symmetric laws on [`Self::ONLY_FIGMENT_UNLOCALIZED`] and
    /// [`Self::ONLY_NOT_APPLICABLE`]) are pinned by
    /// [`tests::field_path_localization_identity_slices_agree_with_identity_predicates`].
    /// Ternary partition invariant across all three siblings:
    /// [`tests::field_path_localization_identity_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::field_path_localization_identity_slices_preserve_all_order`].
    /// No duplicates on any half:
    /// [`tests::field_path_localization_identity_slices_have_no_duplicates`].
    /// Cardinality-agreement with the boolean poles:
    /// [`tests::field_path_localization_identity_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::field_path_localization_identity_slices_are_const_addressable`].
    /// Cross-altitude weld against the shipped compound-polarity
    /// [`Self::APPLICABLE`] / [`Self::NOT_APPLICABLE`] meta-partition:
    /// [`tests::field_path_localization_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_LOCALIZED: &'static [Self] = &[Self::Localized];

    /// The single FIGMENT-UNLOCALIZED [`FieldPathLocalization`] variant
    /// — [`Self::FigmentUnlocalized`] (the figment-error-present-but-
    /// empty-path pole of the identity meta-partition on the
    /// field-localization axis) — in the SAME relative declaration order
    /// it occupies in [`Self::ALL`], mirroring the shipped boolean
    /// predicate [`Self::is_figment_unlocalized`] one altitude down.
    ///
    /// See [`Self::ONLY_LOCALIZED`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_figment_unlocalized`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality,
    /// const-addressability, and cross-altitude weld pins that hold
    /// uniformly across all three identity-partition halves.
    pub const ONLY_FIGMENT_UNLOCALIZED: &'static [Self] = &[Self::FigmentUnlocalized];

    /// The single NOT-APPLICABLE [`FieldPathLocalization`] variant —
    /// [`Self::NotApplicable`] (the no-figment-error-at-all pole of the
    /// identity meta-partition on the field-localization axis) — in the
    /// SAME relative declaration order it occupies in [`Self::ALL`],
    /// mirroring the shipped boolean predicate [`Self::is_not_applicable`]
    /// one altitude down.
    ///
    /// At today's cardinality this singleton coincides pointwise with
    /// the shipped compound-polarity slice [`Self::NOT_APPLICABLE`]
    /// because the not-applicable pole of the (applicable ×
    /// not-applicable) partition currently holds exactly one variant.
    /// The two constants remain independent declaration surfaces even
    /// so — one names the identity image of the [`Self::NotApplicable`]
    /// cell (peer of [`Self::ONLY_LOCALIZED`] /
    /// [`Self::ONLY_FIGMENT_UNLOCALIZED`] under the ternary identity
    /// meta-partition), the other names the not-applicable half of the
    /// coarser binary (applicable × not-applicable) meta-partition
    /// (peer of [`Self::APPLICABLE`] under the binary applicable-vs-not
    /// projection). A future variant landing on the not-applicable side
    /// (e.g. an additional `no-error` cell for a fresh non-figment
    /// error class) would extend [`Self::NOT_APPLICABLE`] with the new
    /// variant but leave [`Self::ONLY_NOT_APPLICABLE`] unchanged, and
    /// the two would diverge at the cross-altitude weld pin
    /// [`tests::field_path_localization_identity_slices_agree_with_compound_polarity_slices`]
    /// before drifting through a consumer that materializes one
    /// altitude from the other.
    ///
    /// See [`Self::ONLY_LOCALIZED`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_not_applicable`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality,
    /// const-addressability, and cross-altitude weld pins.
    pub const ONLY_NOT_APPLICABLE: &'static [Self] = &[Self::NotApplicable];

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

    /// Returns `true` when the localization axis carries a signal about
    /// figment-side path attribution — [`Self::Localized`] (figment
    /// attached a non-empty dotted path) or [`Self::FigmentUnlocalized`]
    /// (figment error present but its `path` slot is empty). Returns
    /// `false` for [`Self::NotApplicable`] (no figment error at all,
    /// so "*was* the failure localized" has no meaningful answer — the
    /// question does not apply).
    ///
    /// Single source of truth for the (`Localized`|`FigmentUnlocalized`)
    /// vs. (`NotApplicable`) partition on the localization axis. Before
    /// this sibling, the partition was inlined as fresh
    /// `matches!(loc, FieldPathLocalization::NotApplicable)` reads at
    /// four sites — [`ErrorLocalizationCoordinates::is_realizable`]
    /// (routing the realizability invariant against
    /// [`ShikumiErrorKind::is_figment_bearing`]) plus three test-side
    /// partition and cross-primitive pins — each of which had to be
    /// kept in lockstep by convention. A future variant landing on
    /// [`Self`] (e.g. a third `PartiallyLocalized` cell for a source
    /// that reports a coarse-grained container but no leaf key) would
    /// have had four sites to reclassify. The routing collapses that
    /// to one: the polarity of the partition is defined here, and the
    /// four consumer sites follow through this predicate.
    ///
    /// Peer sibling-predicate pair on the same typescape discipline as
    /// [`AttributionConfidence::is_exact`] / [`AttributionConfidence::is_fallback`]
    /// on the confidence axis, [`crate::FormatProvenance::is_shikumi_built`]
    /// / [`crate::FormatProvenance::is_figment_builtin`] on the
    /// format-provenance axis, and [`AttributionRule::is_exact`] /
    /// [`AttributionRule::is_fallback`] on the source-attribution axis:
    /// typescape primitives expose a per-partition predicate alongside
    /// the closed-enum dispatch so the common "is it this side?"
    /// question stays one method call.
    ///
    /// Cross-axis: the realizability invariant on
    /// [`ErrorLocalizationCoordinates`] reads
    /// `cell.kind.is_figment_bearing() == cell.localization.is_applicable()`
    /// — the two partition predicates align exactly on the recognized
    /// 9-cell realizable subset of the 21-cell (kind × localization)
    /// cube, pinned pointwise by
    /// `error_localization_coordinates_is_realizable_agrees_with_figment_bearing_law`.
    #[must_use]
    pub const fn is_applicable(self) -> bool {
        matches!(self, Self::Localized | Self::FigmentUnlocalized)
    }

    /// Returns `true` for [`Self::NotApplicable`]; equivalent to
    /// `!self.is_applicable()`.
    ///
    /// Sibling of [`Self::is_applicable`] on the other half of the
    /// closed binary partition over the localization axis; same
    /// routing rationale (see [`Self::is_applicable`] docs), same peer
    /// pattern ([`AttributionConfidence::is_fallback`],
    /// [`crate::FormatProvenance::is_figment_builtin`],
    /// [`AttributionRule::is_fallback`]).
    ///
    /// Doubles as the per-variant sibling of [`Self::is_localized`] /
    /// [`Self::is_figment_unlocalized`] on the [`Self::NotApplicable`]
    /// corner: the coarser applicable/not-applicable meta-partition
    /// and the finer per-variant ternary partition agree on this cell
    /// because [`Self::NotApplicable`] is the sole inhabitant of the
    /// not-applicable side. Pinned pointwise by
    /// [`tests::field_path_localization_per_variant_predicates_refine_is_applicable`].
    #[must_use]
    pub const fn is_not_applicable(self) -> bool {
        matches!(self, Self::NotApplicable)
    }

    /// Returns `true` for [`Self::Localized`]; the per-variant sibling
    /// on the applicable side of the partition.
    ///
    /// One source of truth for the "did figment attach a non-empty
    /// dotted field path?" question over [`FieldPathLocalization`].
    /// [`Self::is_applicable`] answers the coarser meta-question — is
    /// the localization axis *carrying a signal* about figment-side
    /// path attribution at all — which fuses [`Self::Localized`] and
    /// [`Self::FigmentUnlocalized`] into one cell; a consumer that
    /// only wants the "localized-with-path" answer (a structured-log
    /// branch that renders the dotted path when present, a CLI filter
    /// on `--filter-localization=localized`, a miette diagnostic that
    /// annotates the source span when a leaf key is available, a
    /// telemetry counter keyed on the "figment gave us a path" side of
    /// the finer ternary) matches on this predicate instead of routing
    /// through [`Self::is_applicable`] and a second `matches!` at
    /// every site, or open-coding `matches!(loc,
    /// FieldPathLocalization::Localized)` and paying the
    /// closed-partition bookkeeping tax again.
    ///
    /// Peer sibling pattern on the same typescape discipline as
    /// [`AttributionRule::is_file_by_source`] on the rule-axis quintet,
    /// [`crate::ShikumiErrorKind::is_extract`] on the kind-axis septet,
    /// and [`crate::ConfigSourceKind::is_file`] on the layer-kind trio.
    /// Per-variant polarity pinned by
    /// [`tests::field_path_localization_is_localized_true_only_for_localized_variant`];
    /// the closed ternary partition over `Self::ALL` pinned by
    /// [`tests::field_path_localization_per_variant_predicates_are_a_closed_ternary_partition`];
    /// cross-partition refinement into the coarser applicable /
    /// not-applicable meta-axis pinned by
    /// [`tests::field_path_localization_per_variant_predicates_refine_is_applicable`].
    #[must_use]
    pub const fn is_localized(self) -> bool {
        matches!(self, Self::Localized)
    }

    /// Returns `true` for [`Self::FigmentUnlocalized`]; the
    /// per-variant sibling on the applicable side of the partition
    /// alongside [`Self::is_localized`].
    ///
    /// Names the second half of the applicable meta-cell —
    /// figment-bearing errors whose `path` slot is empty (typically a
    /// top-level type mismatch, a deserializer error reported without
    /// a key context, or a manually constructed `figment::Error`
    /// lacking metadata). A consumer that wants to distinguish "we
    /// have a figment error but no leaf-key path" from "we have a
    /// figment error with a dotted path" without routing through
    /// [`Self::is_applicable`] followed by a negated
    /// [`Self::is_localized`] check matches this predicate directly.
    /// See [`Self::is_localized`] for the full contract and peer
    /// pattern.
    #[must_use]
    pub const fn is_figment_unlocalized(self) -> bool {
        matches!(self, Self::FigmentUnlocalized)
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

    /// The three EXACT [`AttributionRule`] variants —
    /// [`Self::FileBySource`], [`Self::FileByMetadataName`], and
    /// [`Self::EnvByPrefix`] — in the SAME relative declaration order
    /// they occupy in [`Self::ALL`], carrying the *equality-based
    /// attribution* pole of the (exact × fallback) confidence
    /// meta-partition at the rule's OWN altitude on the attribution-rule
    /// axis, mirroring the shipped boolean predicate [`Self::is_exact`]
    /// one altitude down: every variant in this slice satisfies
    /// `rule.is_exact()`, and no variant outside it does.
    ///
    /// Paired with [`Self::FALLBACK`], the two disjoint slices partition
    /// [`Self::ALL`] at the static-slice altitude the same way the
    /// shipped boolean predicates [`Self::is_exact`] /
    /// [`Self::is_fallback`] meta-partition it at the boolean altitude.
    /// The two constants sit in the same `impl AttributionRule` block as
    /// [`Self::ALL`] and follow the same `pub const &'static [Self]`
    /// static-slice discipline.
    ///
    /// Written as an explicit three-variant slice literal in the SAME
    /// relative declaration order the exact pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_exact`] at const-fn altitude — so the two
    /// declarations (the slice literal and the boolean predicate) remain
    /// independent load-bearing witnesses of the same meta-partition,
    /// and a future edit that shifts a variant across the polarity on
    /// ONE declaration surface but not the other diverges at test time
    /// on the first shape where they disagree. A hypothetical sixth
    /// variant landing on the exact side (e.g. an `EnvByExactName` cell
    /// for a case-sensitive full-name equality match on the env axis)
    /// lands here in lockstep with [`Self::is_exact`], and the
    /// cardinality pin catches any drift between the slice and the
    /// boolean predicate on the same edit.
    ///
    /// Idiom-peer of
    /// [`crate::FieldPathLocalization::APPLICABLE`] (commit `9dad33d`),
    /// [`crate::ShikumiErrorKind::FIGMENT_BEARING`] (commit `e45018d`),
    /// [`crate::Format::FEATURE_GATED`] (commit `2013269`),
    /// [`crate::source::FigmentNameTagKind::FORMAT`] (commit `2d2ef9d`),
    /// [`crate::source::EnvMetadataTagKind::PREFIXED`] (commit `13304d0`),
    /// [`crate::AttributionAxis::METADATA_SOURCE`] (commit `34bfbb6`),
    /// [`crate::cli::OutputFormat::YAML`] (commit `292ca1d`),
    /// [`crate::AttributionConfidence::EXACT`] (commit `13c1003`),
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] (commit `7ef79e4`),
    /// [`crate::secret::SecretRefShape::WHOLE`] (commit `036673b`), and
    /// [`crate::cube::PartitionFace::REALIZABLE`] (commit `a344056`) —
    /// the per-half meta-partition slice-constant discipline applied
    /// here to the five-way attribution-rule axis's
    /// (exact × fallback) 3/2 meta-partition.
    ///
    /// The two agreement laws
    /// (`EXACT.iter().all(|r| r.is_exact())` and
    /// `EXACT.iter().all(|r| !r.is_fallback())`) are pinned by
    /// [`tests::attribution_rule_exact_slice_agrees_with_is_exact_predicate`].
    /// Partition invariant with [`Self::FALLBACK`]:
    /// [`tests::attribution_rule_exact_and_fallback_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_rule_exact_and_fallback_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::attribution_rule_exact_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::attribution_rule_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_rule_exact_and_fallback_slices_are_const_addressable`].
    pub const EXACT: &'static [Self] = &[
        Self::FileBySource,
        Self::FileByMetadataName,
        Self::EnvByPrefix,
    ];

    /// The two FALLBACK [`AttributionRule`] variants —
    /// [`Self::EnvByUniqueness`] and [`Self::DefaultsByCodeUniqueness`] —
    /// in the SAME relative declaration order they occupy in
    /// [`Self::ALL`], carrying the *uniqueness-based attribution* pole
    /// of the (exact × fallback) confidence meta-partition at the rule's
    /// OWN altitude on the attribution-rule axis, mirroring the shipped
    /// boolean predicate [`Self::is_fallback`] one altitude down.
    ///
    /// See [`Self::EXACT`] for the full contract, the discipline behind
    /// the explicit slice literal (rather than a filter through
    /// [`Self::is_fallback`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const FALLBACK: &'static [Self] = &[Self::EnvByUniqueness, Self::DefaultsByCodeUniqueness];

    /// The two LAYER_FILE [`AttributionRule`] variants —
    /// [`Self::FileBySource`] and [`Self::FileByMetadataName`] — in the
    /// SAME relative declaration order they occupy in [`Self::ALL`],
    /// carrying the *file-layer attribution* pole of the
    /// (file × env × defaults) layer-kind meta-partition at the rule's
    /// OWN altitude on the attribution-rule axis, mirroring the shipped
    /// boolean predicate [`Self::is_file_layer`] one altitude down:
    /// every variant in this slice satisfies `rule.is_file_layer()`, and
    /// no variant outside it does.
    ///
    /// Paired with [`Self::LAYER_ENV`] and [`Self::LAYER_DEFAULTS`], the
    /// three disjoint slices partition [`Self::ALL`] at the static-slice
    /// altitude the same way the shipped boolean predicates
    /// [`Self::is_file_layer`] / [`Self::is_env_layer`] /
    /// [`Self::is_defaults_layer`] meta-partition it at the boolean
    /// altitude (per
    /// [`tests::attribution_rule_layer_predicates_are_a_closed_ternary_partition`]).
    /// The three constants sit in the same `impl AttributionRule` block
    /// as [`Self::ALL`], [`Self::EXACT`], and [`Self::FALLBACK`], and
    /// follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Written as explicit slice literals in the SAME relative
    /// declaration order each pole occupies in [`Self::ALL`], rather
    /// than derived by filtering [`Self::ALL`] through
    /// [`Self::is_file_layer`] at const-fn altitude — so the two
    /// declarations (the slice literal and the boolean predicate) remain
    /// independent load-bearing witnesses of the same meta-partition,
    /// and a future edit that shifts a variant across the polarity on
    /// ONE declaration surface but not the other diverges at test time
    /// on the first shape where they disagree. A hypothetical sixth
    /// variant landing on the file side (e.g. a `FileByEnvOverride` cell
    /// referencing a file layer through an env-provided path) lands here
    /// in lockstep with [`Self::is_file_layer`], and the cardinality pin
    /// catches any drift between the slice and the boolean predicate on
    /// the same edit.
    ///
    /// Ternary peer of the binary [`Self::EXACT`] / [`Self::FALLBACK`]
    /// meta-partition on the confidence projection of the same axis
    /// (both project the five-way rule space onto orthogonal
    /// closed-partition axes at the static-slice altitude), and
    /// idiom-peer of the closed-binary landings on
    /// [`crate::FieldPathLocalization::APPLICABLE`] (commit `9dad33d`),
    /// [`crate::ShikumiErrorKind::FIGMENT_BEARING`] (commit `e45018d`),
    /// [`crate::Format::FEATURE_GATED`] (commit `2013269`),
    /// [`crate::source::FigmentNameTagKind::FORMAT`] (commit `2d2ef9d`),
    /// [`crate::source::EnvMetadataTagKind::PREFIXED`] (commit `13304d0`),
    /// [`crate::AttributionAxis::METADATA_SOURCE`] (commit `34bfbb6`),
    /// and the same-axis [`Self::EXACT`] (commit `19c11d2`, this axis's
    /// confidence-projection landing) — the per-half meta-partition
    /// slice-constant discipline applied here to the five-way
    /// attribution-rule axis's ternary (file × env × defaults) 2/2/1
    /// layer-kind meta-partition.
    ///
    /// The three-way agreement laws
    /// (`LAYER_FILE.iter().all(|r| r.is_file_layer())`,
    /// `!LAYER_FILE.iter().any(|r| r.is_env_layer())`,
    /// `!LAYER_FILE.iter().any(|r| r.is_defaults_layer())`, and the
    /// symmetric laws on [`Self::LAYER_ENV`] and
    /// [`Self::LAYER_DEFAULTS`]) are pinned by
    /// [`tests::attribution_rule_layer_slices_agree_with_layer_predicates`].
    /// Ternary partition invariant across all three siblings:
    /// [`tests::attribution_rule_layer_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_rule_layer_slices_preserve_all_order`].
    /// No duplicates on any half:
    /// [`tests::attribution_rule_layer_slices_have_no_duplicates`].
    /// Cardinality-agreement with the boolean poles:
    /// [`tests::attribution_rule_layer_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_rule_layer_slices_are_const_addressable`].
    pub const LAYER_FILE: &'static [Self] = &[Self::FileBySource, Self::FileByMetadataName];

    /// The two LAYER_ENV [`AttributionRule`] variants —
    /// [`Self::EnvByPrefix`] and [`Self::EnvByUniqueness`] — in the SAME
    /// relative declaration order they occupy in [`Self::ALL`], carrying
    /// the *env-layer attribution* pole of the (file × env × defaults)
    /// layer-kind meta-partition at the rule's OWN altitude on the
    /// attribution-rule axis, mirroring the shipped boolean predicate
    /// [`Self::is_env_layer`] one altitude down.
    ///
    /// See [`Self::LAYER_FILE`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_env_layer`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins that hold uniformly across all three
    /// layer-kind halves.
    pub const LAYER_ENV: &'static [Self] = &[Self::EnvByPrefix, Self::EnvByUniqueness];

    /// The single LAYER_DEFAULTS [`AttributionRule`] variant —
    /// [`Self::DefaultsByCodeUniqueness`] — carrying the
    /// *defaults-layer attribution* pole of the (file × env × defaults)
    /// layer-kind meta-partition at the rule's OWN altitude on the
    /// attribution-rule axis, mirroring the shipped boolean predicate
    /// [`Self::is_defaults_layer`] one altitude down.
    ///
    /// The unique-inhabitant singleton pole of the ternary
    /// (file × env × defaults) meta-partition — today the sole
    /// attribution rule to the defaults layer, alongside the two-cell
    /// [`Self::LAYER_FILE`] and [`Self::LAYER_ENV`] siblings. See
    /// [`Self::LAYER_FILE`] for the full contract, the discipline behind
    /// the explicit slice literal (rather than a filter through
    /// [`Self::is_defaults_layer`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const LAYER_DEFAULTS: &'static [Self] = &[Self::DefaultsByCodeUniqueness];

    /// The two METADATA_SOURCE_AXIS [`AttributionRule`] variants —
    /// [`Self::FileBySource`] and [`Self::DefaultsByCodeUniqueness`] — in
    /// the SAME relative declaration order they occupy in [`Self::ALL`],
    /// carrying the *`figment::Metadata::source`-dispatched* pole of the
    /// (metadata-source × metadata-name) meta-partition at the rule's OWN
    /// altitude on the attribution-rule axis, mirroring the shipped
    /// boolean predicate [`Self::is_metadata_source_axis`] one altitude
    /// down: every variant in this slice satisfies
    /// `rule.is_metadata_source_axis()`, and no variant outside it does.
    ///
    /// Paired with [`Self::METADATA_NAME_AXIS`], the two disjoint slices
    /// partition [`Self::ALL`] at the static-slice altitude the same way
    /// the shipped boolean predicates [`Self::is_metadata_source_axis`] /
    /// [`Self::is_metadata_name_axis`] meta-partition it at the boolean
    /// altitude (per
    /// [`tests::attribution_rule_metadata_axis_predicates_are_a_closed_binary_partition`]).
    /// The two constants sit in the same `impl AttributionRule` block as
    /// [`Self::ALL`], [`Self::EXACT`], [`Self::FALLBACK`],
    /// [`Self::LAYER_FILE`], [`Self::LAYER_ENV`], and
    /// [`Self::LAYER_DEFAULTS`], and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit two-variant slice literal in the SAME
    /// relative declaration order the source-axis pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_metadata_source_axis`] at const-fn altitude —
    /// so the two declarations (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other diverges
    /// at test time on the first shape where they disagree. A
    /// hypothetical sixth variant landing on the source side (e.g. a
    /// `EnvBySourceOverride` cell dispatching off `metadata.source` on
    /// the env layer) lands here in lockstep with
    /// [`Self::is_metadata_source_axis`], and the cardinality pin catches
    /// any drift between the slice and the boolean predicate on the same
    /// edit.
    ///
    /// Third orthogonal projection of the attribution-rule axis to close
    /// on the per-half meta-partition slice-constant discipline — after
    /// the binary confidence projection ([`Self::EXACT`] /
    /// [`Self::FALLBACK`], commit `19c11d2`) and the ternary layer-kind
    /// projection ([`Self::LAYER_FILE`] / [`Self::LAYER_ENV`] /
    /// [`Self::LAYER_DEFAULTS`], commit `fae8271`) — and idiom-peer of
    /// the closed-binary landings on
    /// [`crate::FieldPathLocalization::APPLICABLE`] (commit `9dad33d`),
    /// [`crate::ShikumiErrorKind::FIGMENT_BEARING`] (commit `e45018d`),
    /// [`crate::Format::FEATURE_GATED`] (commit `2013269`),
    /// [`crate::source::FigmentNameTagKind::FORMAT`] (commit `2d2ef9d`),
    /// [`crate::source::EnvMetadataTagKind::PREFIXED`] (commit `13304d0`),
    /// [`crate::AttributionAxis::METADATA_SOURCE`] (commit `34bfbb6`),
    /// [`crate::cli::OutputFormat::YAML`] (commit `292ca1d`),
    /// [`crate::AttributionConfidence::EXACT`] (commit `13c1003`),
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] (commit `7ef79e4`),
    /// [`crate::secret::SecretRefShape::WHOLE`] (commit `036673b`), and
    /// [`crate::cube::PartitionFace::REALIZABLE`] (commit `a344056`) —
    /// the per-half meta-partition slice-constant discipline applied
    /// here to the five-way attribution-rule axis's
    /// (metadata-source × metadata-name) 2/3 metadata-axis meta-partition.
    ///
    /// The bidirectional agreement laws
    /// (`METADATA_SOURCE_AXIS.iter().all(|r| r.is_metadata_source_axis())`
    /// and
    /// `METADATA_SOURCE_AXIS.iter().all(|r| !r.is_metadata_name_axis())`,
    /// symmetric on [`Self::METADATA_NAME_AXIS`]) are pinned by
    /// [`tests::attribution_rule_metadata_axis_slices_agree_with_metadata_axis_predicates`].
    /// Partition invariant with [`Self::METADATA_NAME_AXIS`]:
    /// [`tests::attribution_rule_metadata_axis_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_rule_metadata_axis_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::attribution_rule_metadata_axis_slices_have_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::attribution_rule_metadata_axis_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_rule_metadata_axis_slices_are_const_addressable`].
    pub const METADATA_SOURCE_AXIS: &'static [Self] =
        &[Self::FileBySource, Self::DefaultsByCodeUniqueness];

    /// The three METADATA_NAME_AXIS [`AttributionRule`] variants —
    /// [`Self::FileByMetadataName`], [`Self::EnvByPrefix`], and
    /// [`Self::EnvByUniqueness`] — in the SAME relative declaration order
    /// they occupy in [`Self::ALL`], carrying the
    /// *`figment::Metadata::name`-dispatched* pole of the
    /// (metadata-source × metadata-name) meta-partition at the rule's OWN
    /// altitude on the attribution-rule axis, mirroring the shipped
    /// boolean predicate [`Self::is_metadata_name_axis`] one altitude
    /// down.
    ///
    /// See [`Self::METADATA_SOURCE_AXIS`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a filter
    /// through [`Self::is_metadata_name_axis`]), and the load-bearing
    /// agreement, partition, order-preservation, no-duplicates,
    /// cardinality, and const-addressability pins.
    pub const METADATA_NAME_AXIS: &'static [Self] = &[
        Self::FileByMetadataName,
        Self::EnvByPrefix,
        Self::EnvByUniqueness,
    ];

    /// The single [`Self::FileBySource`] pole of the five-way identity
    /// meta-partition on the [`AttributionRule`] axis at the static-
    /// slice altitude — the singleton slice `&[Self::FileBySource]`
    /// mirroring the shipped boolean predicate
    /// [`Self::is_file_by_source`] one altitude down: every variant in
    /// this slice satisfies `rule.is_file_by_source()`, and no variant
    /// outside it does.
    ///
    /// Paired with the four siblings ([`Self::ONLY_FILE_BY_METADATA_NAME`],
    /// [`Self::ONLY_ENV_BY_PREFIX`], [`Self::ONLY_ENV_BY_UNIQUENESS`],
    /// [`Self::ONLY_DEFAULTS_BY_CODE_UNIQUENESS`]), the five disjoint
    /// singleton slices partition [`Self::ALL`] at the static-slice
    /// altitude the same way the shipped boolean predicates
    /// ([`Self::is_file_by_source`] / [`Self::is_file_by_metadata_name`] /
    /// [`Self::is_env_by_prefix`] / [`Self::is_env_by_uniqueness`] /
    /// [`Self::is_defaults_by_code_uniqueness`]) meta-partition it at
    /// the boolean altitude. All five constants sit in the same
    /// `impl AttributionRule` block as [`Self::ALL`] / [`Self::EXACT`] /
    /// [`Self::FALLBACK`] / [`Self::LAYER_FILE`] / [`Self::LAYER_ENV`] /
    /// [`Self::LAYER_DEFAULTS`] / [`Self::METADATA_SOURCE_AXIS`] /
    /// [`Self::METADATA_NAME_AXIS`] and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the five identity poles occupy in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through the five identity predicates at const-fn altitude — so
    /// the two declaration surfaces (the slice literals and the boolean
    /// predicates) remain independent load-bearing witnesses of the same
    /// identity meta-partition, and a future edit that shifts a variant
    /// across an identity pole on ONE surface but not the other diverges
    /// at test time on the first shape where they disagree.
    ///
    /// Also the first cell of [`Self::EXACT`], [`Self::LAYER_FILE`], and
    /// [`Self::METADATA_SOURCE_AXIS`] — the identity singleton agrees
    /// with all three shipped compound-polarity witnesses at once
    /// (`ONLY_FILE_BY_SOURCE ⊆ EXACT ∩ LAYER_FILE ∩ METADATA_SOURCE_AXIS`)
    /// per the identity-vs-compound cross-check that pins the five
    /// identity singletons against the shipped
    /// (exact × fallback), (file × env × defaults), and
    /// (metadata-source × metadata-name) compound-polarity
    /// meta-partitions.
    ///
    /// **Idiom-peer.** Quinary landing of the per-half meta-partition
    /// slice-constant discipline on a shikumi-native closed-primitive
    /// axis, matching altitude-for-altitude the quinary
    /// [`crate::discovery::Format::ONLY_YAML`] / … / `ONLY_BLUE`
    /// (commit `d880091`), the quinary
    /// [`crate::secret_client::SecretErrorKind::ONLY_NOT_FOUND`] / … /
    /// `ONLY_SHIKUMI` (commit `1a4ae14`), the septenary
    /// [`crate::error::ShikumiErrorKind::ONLY_NOT_FOUND`] / … /
    /// `ONLY_VALIDATION` (commit `6e74116`), the senary
    /// [`crate::secret_client::SecretOperation::ONLY_GET`] / … /
    /// `ONLY_GET_VERSION` (commit `bfe3e24`), the septenary
    /// [`crate::secret_client::SecretClientKind::ONLY_MEM`] / … /
    /// `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), the octonary
    /// [`crate::secret::SecretBackendKind::ONLY_LITERAL`] / … /
    /// `ONLY_GCP_SECRET` (commit `19364e3`), the quinary
    /// [`crate::cli::TierArg::ONLY_BARE`] / … / `ONLY_ENV` (commit
    /// `f7f5529`), and the quaternary
    /// [`crate::tiered::ConfigTierKind::ONLY_BARE`] / … /
    /// `ONLY_CUSTOM` (commit `ff6492b`) — the per-half meta-partition
    /// slice-constant discipline applied here to the five-way
    /// [`AttributionRule`] axis (the first identity-partition landing on
    /// the rule primitive), lifting the five identity poles onto the
    /// slice-constant altitude alongside the shipped compound-polarity
    /// [`Self::EXACT`] / [`Self::FALLBACK`],
    /// [`Self::LAYER_FILE`] / [`Self::LAYER_ENV`] /
    /// [`Self::LAYER_DEFAULTS`], and
    /// [`Self::METADATA_SOURCE_AXIS`] / [`Self::METADATA_NAME_AXIS`]
    /// witnesses one altitude up.
    ///
    /// The five agreement laws
    /// (`ONLY_FILE_BY_SOURCE.iter().all(|r| r.is_file_by_source())` and
    /// `ONLY_FILE_BY_SOURCE.iter().all(|r| !r.is_file_by_metadata_name()
    /// && !r.is_env_by_prefix() && !r.is_env_by_uniqueness()
    /// && !r.is_defaults_by_code_uniqueness())`, symmetric on the four
    /// siblings) are pinned by
    /// [`tests::attribution_rule_identity_slices_agree_with_identity_predicates`].
    /// Partition invariant across all five:
    /// [`tests::attribution_rule_identity_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_rule_identity_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::attribution_rule_identity_slices_have_no_duplicates`].
    /// Cardinality-agreement with the five boolean poles:
    /// [`tests::attribution_rule_identity_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_rule_identity_slices_are_const_addressable`].
    /// Cross-altitude weld with all three shipped compound-polarity
    /// witnesses:
    /// [`tests::attribution_rule_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_FILE_BY_SOURCE: &'static [Self] = &[Self::FileBySource];

    /// The single [`Self::FileByMetadataName`] pole of the five-way
    /// identity meta-partition on the [`AttributionRule`] axis at the
    /// static-slice altitude. Also the first cell of
    /// [`Self::METADATA_NAME_AXIS`] and the second cell of
    /// [`Self::LAYER_FILE`] and [`Self::EXACT`] — the identity singleton
    /// agrees with all three shipped compound-polarity witnesses at
    /// once. See [`Self::ONLY_FILE_BY_SOURCE`] for the full contract,
    /// load-bearing pins, and idiom-peer landings.
    pub const ONLY_FILE_BY_METADATA_NAME: &'static [Self] = &[Self::FileByMetadataName];

    /// The single [`Self::EnvByPrefix`] pole of the five-way identity
    /// meta-partition on the [`AttributionRule`] axis at the static-
    /// slice altitude. Also the last cell of [`Self::EXACT`] and the
    /// first cell of [`Self::LAYER_ENV`] and the second cell of
    /// [`Self::METADATA_NAME_AXIS`] — the identity singleton agrees
    /// with all three shipped compound-polarity witnesses at once. See
    /// [`Self::ONLY_FILE_BY_SOURCE`] for the full contract, load-bearing
    /// pins, and idiom-peer landings.
    pub const ONLY_ENV_BY_PREFIX: &'static [Self] = &[Self::EnvByPrefix];

    /// The single [`Self::EnvByUniqueness`] pole of the five-way
    /// identity meta-partition on the [`AttributionRule`] axis at the
    /// static-slice altitude. Also the first cell of [`Self::FALLBACK`]
    /// and the last cell of [`Self::LAYER_ENV`] and
    /// [`Self::METADATA_NAME_AXIS`] — the identity singleton agrees
    /// with all three shipped compound-polarity witnesses at once. See
    /// [`Self::ONLY_FILE_BY_SOURCE`] for the full contract, load-bearing
    /// pins, and idiom-peer landings.
    pub const ONLY_ENV_BY_UNIQUENESS: &'static [Self] = &[Self::EnvByUniqueness];

    /// The single [`Self::DefaultsByCodeUniqueness`] pole of the five-
    /// way identity meta-partition on the [`AttributionRule`] axis at
    /// the static-slice altitude. Also the sole cell of
    /// [`Self::LAYER_DEFAULTS`] and the last cell of [`Self::FALLBACK`]
    /// and [`Self::METADATA_SOURCE_AXIS`] — the identity singleton
    /// agrees with all three shipped compound-polarity witnesses at
    /// once, and reproduces [`Self::LAYER_DEFAULTS`] exactly on the
    /// layer-kind projection since the defaults pole is a singleton at
    /// the layer altitude too. See [`Self::ONLY_FILE_BY_SOURCE`] for the
    /// full contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_DEFAULTS_BY_CODE_UNIQUENESS: &'static [Self] = &[Self::DefaultsByCodeUniqueness];

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
    ///
    /// `const fn`: this projection is const-callable on `Copy` receivers
    /// (welded by
    /// [`tests::attribution_rule_confidence_and_confidence_predicates_are_const_callable`]),
    /// so `const` composition through it — a `const AttributionConfidence`
    /// binding produced from a `const AttributionRule`, or the routed
    /// `rule.confidence().is_exact()` short-circuit consumed by the
    /// [`Self::is_exact`] / [`Self::is_fallback`] siblings below — evaluates
    /// at compile time. Direct peer of the const-callable projection pairs
    /// on the borrowed figment-metadata triple ([`crate::EnvMetadataTag::kind`]
    /// at commit `d8db91f`, [`crate::FigmentNameTag::kind`] at commit
    /// `41ca5ca`, [`crate::FigmentSourceTag::classify`] at commit `22b705a`)
    /// and on the top-level [`crate::ConfigSource::kind`] projection at
    /// commit `8db9806`.
    #[must_use]
    pub const fn confidence(self) -> AttributionConfidence {
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
    ///
    /// Delegates to the sibling predicate
    /// [`AttributionConfidence::is_exact`] on the resolved confidence
    /// class, so the polarity of the (exact, fallback) partition is
    /// defined in exactly one place (the confidence altitude) and this
    /// source-altitude convenience follows automatically. Peer to
    /// [`crate::Format::has_shikumi_provider`], which routes through
    /// [`crate::FormatProvenance::is_shikumi_built`] the same way.
    /// Pinned pointwise by
    /// `attribution_rule_is_exact_agrees_with_confidence_is_exact`.
    ///
    /// `const fn`: const-callable on `Copy` receivers (welded by
    /// [`tests::attribution_rule_confidence_and_confidence_predicates_are_const_callable`]);
    /// the routed body `self.confidence().is_exact()` composes two
    /// const-callable primitives ([`Self::confidence`] above, sibling
    /// [`AttributionConfidence::is_exact`] at commit `5c2add4`), so the
    /// whole cascade evaluates at compile time.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.confidence().is_exact()
    }

    /// Returns `true` if this rule is uniqueness-based; equivalent to
    /// `self.confidence() == AttributionConfidence::Fallback`.
    ///
    /// Delegates to the sibling predicate
    /// [`AttributionConfidence::is_fallback`]; see [`Self::is_exact`]
    /// for the routing rationale. Pinned pointwise by
    /// `attribution_rule_is_fallback_agrees_with_confidence_is_fallback`.
    ///
    /// `const fn`: const-callable on `Copy` receivers (welded by
    /// [`tests::attribution_rule_confidence_and_confidence_predicates_are_const_callable`]);
    /// same routing shape as [`Self::is_exact`] above.
    #[must_use]
    pub const fn is_fallback(self) -> bool {
        self.confidence().is_fallback()
    }

    /// Returns `true` for [`Self::FileBySource`] only.
    ///
    /// Per-variant sibling of the closed quintet partition over the rule
    /// axis. [`Self::is_exact`] / [`Self::is_fallback`] answer the
    /// coarser *confidence* meta-partition; these five answer "which
    /// rule fired?" at the rule's own altitude, so a consumer holding a
    /// captured [`AttributionRule`] stops spelling
    /// `rule == AttributionRule::FileBySource` at its own site. Same
    /// shape as [`ShikumiErrorKind::is_not_found`] on the error-kind
    /// axis and [`ConfigSourceKind::is_file`] on the layer-kind axis.
    /// The quintet is pinned closed by
    /// `attribution_rule_predicates_are_a_closed_quintet_partition`, and
    /// refines the confidence, layer-kind, and metadata-axis
    /// projections by the three `attribution_rule_predicates_refine_*`
    /// pins.
    #[must_use]
    pub const fn is_file_by_source(self) -> bool {
        matches!(self, Self::FileBySource)
    }

    /// Returns `true` for [`Self::FileByMetadataName`] only.
    ///
    /// Sibling of [`Self::is_file_by_source`]; see it for the partition
    /// rationale.
    #[must_use]
    pub const fn is_file_by_metadata_name(self) -> bool {
        matches!(self, Self::FileByMetadataName)
    }

    /// Returns `true` for [`Self::EnvByPrefix`] only.
    ///
    /// Sibling of [`Self::is_file_by_source`]; see it for the partition
    /// rationale.
    #[must_use]
    pub const fn is_env_by_prefix(self) -> bool {
        matches!(self, Self::EnvByPrefix)
    }

    /// Returns `true` for [`Self::EnvByUniqueness`] only.
    ///
    /// Sibling of [`Self::is_file_by_source`]; see it for the partition
    /// rationale.
    #[must_use]
    pub const fn is_env_by_uniqueness(self) -> bool {
        matches!(self, Self::EnvByUniqueness)
    }

    /// Returns `true` for [`Self::DefaultsByCodeUniqueness`] only.
    ///
    /// Sibling of [`Self::is_file_by_source`]; see it for the partition
    /// rationale.
    #[must_use]
    pub const fn is_defaults_by_code_uniqueness(self) -> bool {
        matches!(self, Self::DefaultsByCodeUniqueness)
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
    ///
    /// `const`-callable — the body is an exhaustive match over the
    /// five payload-free [`Copy`] variants of [`Self`] projecting into
    /// unit variants of [`ConfigSourceKind`], both const-eligible under
    /// rustc 1.94.1. Closes the const-callability parity gap on this
    /// [`impl AttributionRule`] block: the sibling coordinate projection
    /// [`Self::confidence`] (const since it was introduced) already
    /// evaluates in const context on the (exact × fallback) axis, and
    /// with this change the orthogonal (file × env × defaults) axis
    /// projection meets it there — a compile-time-known
    /// [`AttributionRule`] projects both coordinates at compile time
    /// too, so a `static PAIR: (ConfigSourceKind, AttributionConfidence)
    /// = (rule.layer_kind(), rule.confidence())` diagnostic table can be
    /// wired without either projection dropping the caller off the
    /// const-context edge. Welded at compile time by
    /// [`tests::attribution_rule_layer_kind_is_const_callable`].
    #[must_use]
    pub const fn layer_kind(self) -> ConfigSourceKind {
        match self {
            Self::FileBySource | Self::FileByMetadataName => ConfigSourceKind::File,
            Self::EnvByPrefix | Self::EnvByUniqueness => ConfigSourceKind::Env,
            Self::DefaultsByCodeUniqueness => ConfigSourceKind::Defaults,
        }
    }

    /// Returns `true` if this rule attributes to a
    /// [`ConfigSource::File`] layer; equivalent to
    /// `self.layer_kind() == ConfigSourceKind::File`.
    ///
    /// Delegates to the sibling predicate [`ConfigSourceKind::is_file`]
    /// on the resolved layer kind, so the polarity of the
    /// (file × env × defaults) partition is defined in exactly one place
    /// (the layer-kind altitude) and this rule-altitude convenience
    /// follows automatically. The rule-altitude analogue of
    /// [`Self::is_exact`] on the (exact × fallback) confidence axis:
    /// same delegating shape, same "one source of truth" rationale.
    ///
    /// The two file-axis rules
    /// ([`Self::FileBySource`] and [`Self::FileByMetadataName`]) are
    /// the exact inhabitants of this predicate — pinned by
    /// [`tests::attribution_rule_is_file_layer_agrees_with_layer_kind_is_file`]
    /// against every rule in [`Self::ALL`]. Before this sibling the
    /// question routed as the two-hop composition
    /// `rule.layer_kind().is_file()` at every observer site (a
    /// per-file-rule alerting bucket, a diagnostic renderer weighting
    /// file-layer attributions differently, a captured-failure
    /// telemetry counter keyed on the layer kind); this collapses that
    /// to one method call at the rule altitude.
    ///
    /// `const`-callable — the body is the two-hop composition
    /// [`Self::layer_kind`] → [`ConfigSourceKind::is_file`], both
    /// [`pub const fn`] (the first lifted by `52c4a20`, the second
    /// const since it was introduced). Closes the const-callability
    /// parity gap on this [`impl AttributionRule`] block: the sibling
    /// rule-altitude convenience predicate [`Self::is_exact`] on the
    /// orthogonal (exact × fallback) confidence axis is `pub const fn`,
    /// and with this change the corresponding (file × env × defaults)
    /// layer-axis convenience predicate meets it there. Welded at
    /// compile time by
    /// [`tests::attribution_rule_layer_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_file_layer(self) -> bool {
        self.layer_kind().is_file()
    }

    /// Returns `true` if this rule attributes to a
    /// [`ConfigSource::Env`] layer; equivalent to
    /// `self.layer_kind() == ConfigSourceKind::Env`. Sibling of
    /// [`Self::is_file_layer`]; see it for the delegation rationale.
    ///
    /// The two env-axis rules
    /// ([`Self::EnvByPrefix`] and [`Self::EnvByUniqueness`]) are the
    /// exact inhabitants of this predicate — pinned by
    /// [`tests::attribution_rule_is_env_layer_agrees_with_layer_kind_is_env`].
    ///
    /// `const`-callable on the same rationale as [`Self::is_file_layer`];
    /// welded at compile time by
    /// [`tests::attribution_rule_layer_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_env_layer(self) -> bool {
        self.layer_kind().is_env()
    }

    /// Returns `true` if this rule attributes to a
    /// [`ConfigSource::Defaults`] layer; equivalent to
    /// `self.layer_kind() == ConfigSourceKind::Defaults`. Sibling of
    /// [`Self::is_file_layer`]; see it for the delegation rationale.
    ///
    /// The single defaults-axis rule
    /// ([`Self::DefaultsByCodeUniqueness`]) is the exact inhabitant of
    /// this predicate — pinned by
    /// [`tests::attribution_rule_is_defaults_layer_agrees_with_layer_kind_is_defaults`].
    /// The three layer-side siblings
    /// ([`Self::is_file_layer`], [`Self::is_env_layer`],
    /// [`Self::is_defaults_layer`]) form a closed ternary partition of
    /// [`Self::ALL`] — pinned by
    /// [`tests::attribution_rule_layer_predicates_are_a_closed_ternary_partition`].
    ///
    /// `const`-callable on the same rationale as [`Self::is_file_layer`];
    /// welded at compile time by
    /// [`tests::attribution_rule_layer_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_defaults_layer(self) -> bool {
        self.layer_kind().is_defaults()
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
    ///
    /// `const`-callable — the five-arm exhaustive match projects
    /// payload-free `Copy` variants of `Self` into unit variants of
    /// [`AttributionAxis`] and touches no allocator, `String`, or
    /// non-const helper on any path, so a compile-time-known rule
    /// projects its metadata-axis coordinate at compile time too.
    /// Matches the const-callability altitude the two sibling
    /// projections on the same `impl` block already occupy —
    /// [`Self::confidence`] (const since it was introduced) on the
    /// exact × fallback axis and [`Self::layer_kind`] (const since
    /// `52c4a20`) on the file × env × defaults axis — closing the
    /// third-axis parity gap on the (rule → axis × confidence ×
    /// layer_kind) orthogonal coordinate space. Pinned by
    /// [`tests::attribution_rule_metadata_axis_is_const_callable`].
    #[must_use]
    pub const fn metadata_axis(self) -> AttributionAxis {
        match self {
            Self::FileBySource | Self::DefaultsByCodeUniqueness => AttributionAxis::MetadataSource,
            Self::FileByMetadataName | Self::EnvByPrefix | Self::EnvByUniqueness => {
                AttributionAxis::MetadataName
            }
        }
    }

    /// Returns `true` if this rule was dispatched off
    /// `figment::Metadata::source`; equivalent to
    /// `self.metadata_axis() == AttributionAxis::MetadataSource`.
    ///
    /// Delegates to the sibling predicate
    /// [`AttributionAxis::is_metadata_source`] on the resolved
    /// metadata axis, so the polarity of the (metadata-source ×
    /// metadata-name) partition is defined in exactly one place (the
    /// axis altitude) and this rule-altitude convenience follows
    /// automatically. The rule-altitude analogue of [`Self::is_exact`]
    /// on the (exact × fallback) confidence axis and
    /// [`Self::is_file_layer`] on the (file × env × defaults) layer
    /// axis: same delegating shape, same "one source of truth"
    /// rationale.
    ///
    /// The two source-dispatched rules
    /// ([`Self::FileBySource`] and [`Self::DefaultsByCodeUniqueness`])
    /// are the exact inhabitants of this predicate — pinned by
    /// [`tests::attribution_rule_is_metadata_source_axis_agrees_with_metadata_axis_is_metadata_source`]
    /// against every rule in [`Self::ALL`]. Before this sibling the
    /// question routed as the two-hop composition
    /// `rule.metadata_axis().is_metadata_source()` at every observer
    /// site (a diagnostic renderer weighting source-axis attributions
    /// visibly stronger than name-axis ones, an attestation manifest
    /// recording the axis-partition histogram); this collapses that to
    /// one method call at the rule altitude.
    ///
    /// `const`-callable — the body is the two-hop composition
    /// [`Self::metadata_axis`] → [`AttributionAxis::is_metadata_source`],
    /// both [`pub const fn`] (the first lifted by `4f8a185`, the second
    /// const since it was introduced). Closes the const-callability
    /// parity gap on the metadata-axis rule-altitude convenience
    /// predicates so the (source × name) binary partition now meets the
    /// (file × env × defaults) ternary siblings
    /// [`Self::is_file_layer`] / [`Self::is_env_layer`] /
    /// [`Self::is_defaults_layer`] (lifted by `4eec3fa`) and the
    /// (exact × fallback) sibling [`Self::is_exact`] (const since
    /// introduced) at the same const-callability altitude on this
    /// [`impl AttributionRule`] block. Welded at compile time by
    /// [`tests::attribution_rule_metadata_axis_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_metadata_source_axis(self) -> bool {
        self.metadata_axis().is_metadata_source()
    }

    /// Returns `true` if this rule was dispatched off
    /// `figment::Metadata::name`; equivalent to
    /// `self.metadata_axis() == AttributionAxis::MetadataName`. Sibling
    /// of [`Self::is_metadata_source_axis`]; see it for the delegation
    /// rationale.
    ///
    /// The three name-dispatched rules ([`Self::FileByMetadataName`],
    /// [`Self::EnvByPrefix`], [`Self::EnvByUniqueness`]) are the exact
    /// inhabitants of this predicate — pinned by
    /// [`tests::attribution_rule_is_metadata_name_axis_agrees_with_metadata_axis_is_metadata_name`].
    /// The two axis-side siblings
    /// ([`Self::is_metadata_source_axis`],
    /// [`Self::is_metadata_name_axis`]) form a closed binary partition
    /// of [`Self::ALL`] — pinned by
    /// [`tests::attribution_rule_metadata_axis_predicates_are_a_closed_binary_partition`].
    ///
    /// `const`-callable on the same rationale as
    /// [`Self::is_metadata_source_axis`]; welded at compile time by
    /// [`tests::attribution_rule_metadata_axis_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_metadata_name_axis(self) -> bool {
        self.metadata_axis().is_metadata_name()
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
    ///
    /// `pub const fn` since the body is an exhaustive match on
    /// [`Self`]'s payload-free variants returning
    /// `Option<FigmentSourceKind>` (`FigmentSourceKind` is a
    /// payload-free enum; `Option::Some` construction is a `const`
    /// operation). The const-callability weld is
    /// [`tests::attribution_rule_figment_source_kind_is_const_callable`];
    /// it routes each of the five rule variants through the
    /// projection in `const` position and pins the partition against
    /// the exhaustive match at compile time. Peer const-lift of the
    /// rule-altitude partial-projection cascade on the sibling
    /// partial projection is [`Self::figment_name_tag_kind`] (now
    /// `pub const fn` in lockstep).
    #[must_use]
    pub const fn figment_source_kind(self) -> Option<FigmentSourceKind> {
        match self {
            Self::FileBySource => Some(FigmentSourceKind::File),
            Self::DefaultsByCodeUniqueness => Some(FigmentSourceKind::Code),
            Self::FileByMetadataName | Self::EnvByPrefix | Self::EnvByUniqueness => None,
        }
    }

    /// [`FigmentNameTagKind`] this rule's identity already pins on the
    /// figment-`Metadata::name` axis, or [`None`] when the rule is
    /// dispatched off `metadata.source` and therefore does not constrain
    /// the originating `figment::Metadata::name` at all.
    ///
    /// Symmetric peer of [`Self::figment_source_kind`] on the
    /// figment-`Metadata::name` axis: name-axis rules
    /// ([`Self::metadata_axis`] returns [`AttributionAxis::MetadataName`])
    /// consult `figment::Metadata::name` directly via
    /// [`FigmentNameTag::classify`], so the rule's identity already pins
    /// the [`FigmentNameTagKind`] cell that fired:
    /// [`Self::FileByMetadataName`] ⇒
    /// [`Some(FigmentNameTagKind::Format)`] (the resolver matched the
    /// shikumi-built provider's `"<format>: <path>"` shape, classifying
    /// to [`FigmentNameTag::Format`]),
    /// [`Self::EnvByPrefix`] ⇒ [`Some(FigmentNameTagKind::Env)`] (the
    /// resolver matched figment's `` `PREFIX` environment variable(s) ``
    /// shape, classifying to [`FigmentNameTag::Env`] with
    /// [`EnvMetadataTag::Prefixed`]),
    /// [`Self::EnvByUniqueness`] ⇒ [`Some(FigmentNameTagKind::Env)`] (the
    /// resolver matched an env-shaped name without a recorded prefix,
    /// classifying to [`FigmentNameTag::Env`] with either
    /// [`EnvMetadataTag::Prefixed`] or [`EnvMetadataTag::Bare`]).
    /// Source-axis rules ([`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataSource`]) consult
    /// `figment::Metadata::source` instead — the actual
    /// `figment::Metadata::name` may carry any text the upstream
    /// provider attached (figment's built-in YAML/TOML providers attach
    /// the file path verbatim; figment's `Serialized` attaches the
    /// `Source::Code` shape) — so the partial projection returns
    /// [`None`]: [`Self::FileBySource`], [`Self::DefaultsByCodeUniqueness`]
    /// both map to [`None`].
    ///
    /// One source of truth for the (rule → figment-name-tag-kind)
    /// projection — symmetric peer of the (rule → figment-source-kind)
    /// projection on the `Metadata::source` axis. Before this method, the
    /// information was implicit in the resolver's branching shape and
    /// recoverable only by re-reading `metadata.name` off the originating
    /// [`figment::Error`] and re-running [`FigmentNameTag::classify`] /
    /// [`FigmentNameTag::kind`] inline; lifting it to a typed accessor
    /// pins "this rule's identity already names the figment-name-axis
    /// kind cell" at the type level. A future variant added to [`Self`]
    /// forces a kind assignment in the exhaustive match in lockstep with
    /// the [`Self::figment_source_kind`] arm.
    ///
    /// Composes with [`Self::metadata_axis`] as a refinement on the
    /// name-axis: the partial projection is [`Some`] exactly when
    /// `self.metadata_axis() == AttributionAxis::MetadataName`. The
    /// `Some-iff-MetadataName` invariant is the dual of the
    /// `Some-iff-MetadataSource` invariant on [`Self::figment_source_kind`],
    /// and pinned by
    /// `attribution_rule_figment_name_tag_kind_some_iff_metadata_axis_name`.
    /// Composes with [`Self::figment_source_kind`] as a strict partition
    /// over the rule space: every rule's identity dispatches on exactly
    /// one figment-metadata axis, so for every rule exactly one of
    /// [`Self::figment_source_kind`] and [`Self::figment_name_tag_kind`]
    /// returns [`Some`]. Pinned by
    /// `attribution_rule_figment_name_tag_kind_xor_figment_source_kind`.
    ///
    /// Image of the projection over [`Self::ALL`] is exactly
    /// [`FigmentNameTagKind::ALL`] — both [`FigmentNameTagKind::Format`]
    /// (reached via [`Self::FileByMetadataName`]) and
    /// [`FigmentNameTagKind::Env`] (reached via [`Self::EnvByPrefix`] /
    /// [`Self::EnvByUniqueness`]) lie in the image. Pinned by
    /// `attribution_rule_figment_name_tag_kind_image_equals_figment_name_tag_kind_all`.
    ///
    /// Pairs with [`FailingSourceAttribution::figment_name_tag_kind`] /
    /// [`crate::ReloadFailure::figment_name_tag_kind`]: the same
    /// projection surfaced off the borrowed and cross-thread observable
    /// forms, with the cross-thread accessor lifted to `Option<_>` to
    /// track the `Some-iff-attribution` discipline established for the
    /// sibling projection accessors.
    ///
    /// `pub const fn` since the body is an exhaustive match on
    /// [`Self`]'s payload-free variants returning
    /// `Option<FigmentNameTagKind>` ([`FigmentNameTagKind`] is a
    /// payload-free enum; [`Option::Some`] construction is a `const`
    /// operation). The const-callability weld is
    /// [`tests::attribution_rule_figment_name_tag_kind_is_const_callable`];
    /// it routes each of the five rule variants through the projection
    /// in `const` position and pins the partition against the
    /// exhaustive match at compile time. Sibling const-lift of the
    /// rule-altitude partial-projection cascade on the source-axis
    /// partial projection is [`Self::figment_source_kind`] (already
    /// `pub const fn`), completing the (source-axis, name-axis)
    /// partial-projection pair at const altitude.
    #[must_use]
    pub const fn figment_name_tag_kind(self) -> Option<FigmentNameTagKind> {
        match self {
            Self::FileByMetadataName => Some(FigmentNameTagKind::Format),
            Self::EnvByPrefix | Self::EnvByUniqueness => Some(FigmentNameTagKind::Env),
            Self::FileBySource | Self::DefaultsByCodeUniqueness => None,
        }
    }

    /// Returns `true` when [`Self::figment_source_kind`] returns
    /// [`Some(FigmentSourceKind::File)`]; equivalent to
    /// `self.figment_source_kind() == Some(FigmentSourceKind::File)`.
    ///
    /// Rule-altitude sibling delegator on the figment-`Source`-axis
    /// [`Option<FigmentSourceKind>`] projection: mirrors
    /// [`Self::is_file_layer`] / [`Self::is_env_layer`] /
    /// [`Self::is_defaults_layer`] (the total [`Self::layer_kind`]
    /// projection's ternary sibling grid) and
    /// [`Self::is_metadata_source_axis`] / [`Self::is_metadata_name_axis`]
    /// (the total [`Self::metadata_axis`] projection's binary sibling
    /// grid) on the two total orthogonal projections, and matches the
    /// `Some-iff-attribution` discipline the partial projection was
    /// documented under: the delegator is `false` on every name-axis
    /// rule (where the outer `Option` is `None`) and `true` on the
    /// source-axis rule whose identity pins the `File` cell.
    ///
    /// One-hop lift through the partial projection. Every consumer
    /// routing on "did this attribution name a figment `Source::File`
    /// layer?" — an operator-facing dashboard weighting `File`-source
    /// attributions in the same bucket as the shikumi-side `File`
    /// layer (they meet at the shikumi-env-layer ↔ figment-Env-name
    /// resolution boundary in
    /// [`AttributionSourceKindCoordinates`]'s realizable diagonal), a
    /// structured-diagnostics legend rendering distinct prose per
    /// source-axis kind, a captured-failure counter keyed on the
    /// figment-Source-axis cell — had to route through the two-hop
    /// composition `rule.figment_source_kind() == Some(FigmentSourceKind::File)`
    /// (or the equivalent `is_some_and(FigmentSourceKind::is_file)`) at
    /// every observation site. The rule-altitude delegator collapses
    /// the two-hop probe into one, keeping the polarity of the
    /// figment-Source-axis partition defined in exactly one place
    /// ([`FigmentSourceKind::is_file`]).
    ///
    /// Pinned by
    /// `attribution_rule_is_figment_source_file_agrees_with_figment_source_kind_is_file`.
    /// The three source-axis sibling delegators
    /// ([`Self::is_figment_source_file`], [`Self::is_figment_source_code`],
    /// [`Self::is_figment_source_custom`]) form a `Some-iff-source-axis`
    /// disjoint partition of [`Self::ALL`] — exactly one holds on every
    /// source-axis rule, zero hold on every name-axis rule — pinned by
    /// `attribution_rule_figment_source_kind_predicates_partition_source_axis_rules`.
    #[must_use]
    pub fn is_figment_source_file(self) -> bool {
        self.figment_source_kind()
            .is_some_and(FigmentSourceKind::is_file)
    }

    /// Returns `true` when [`Self::figment_source_kind`] returns
    /// [`Some(FigmentSourceKind::Code)`]; equivalent to
    /// `self.figment_source_kind() == Some(FigmentSourceKind::Code)`.
    /// Sibling of [`Self::is_figment_source_file`]; see it for the
    /// delegation rationale and the closed-partition pin.
    ///
    /// The single source-axis rule dispatched off `Source::Code` —
    /// [`Self::DefaultsByCodeUniqueness`] — is the exact inhabitant of
    /// this predicate; pinned by
    /// `attribution_rule_is_figment_source_code_agrees_with_figment_source_kind_is_code`.
    #[must_use]
    pub fn is_figment_source_code(self) -> bool {
        self.figment_source_kind()
            .is_some_and(FigmentSourceKind::is_code)
    }

    /// Returns `true` when [`Self::figment_source_kind`] returns
    /// [`Some(FigmentSourceKind::Custom)`]; equivalent to
    /// `self.figment_source_kind() == Some(FigmentSourceKind::Custom)`.
    /// Sibling of [`Self::is_figment_source_file`]; see it for the
    /// delegation rationale and the closed-partition pin.
    ///
    /// Currently `false` on every recognized [`AttributionRule`] —
    /// [`FigmentSourceKind::Custom`] is reachable on the figment-side
    /// classification but no recognized rule currently dispatches off
    /// `Source::Custom` (see the image-cardinality pin
    /// `attribution_rule_figment_source_kind_image_is_file_and_code_only`).
    /// Pinned by
    /// `attribution_rule_is_figment_source_custom_never_holds` — a
    /// future custom-source rule landing extends the image in lockstep
    /// and moves the pin from `never` to per-variant polarity, forcing
    /// the delegator's routing to be re-verified against the new arm.
    #[must_use]
    pub fn is_figment_source_custom(self) -> bool {
        self.figment_source_kind()
            .is_some_and(FigmentSourceKind::is_custom)
    }

    /// Returns `true` when [`Self::figment_name_tag_kind`] returns
    /// [`Some(FigmentNameTagKind::Format)`]; equivalent to
    /// `self.figment_name_tag_kind() == Some(FigmentNameTagKind::Format)`.
    ///
    /// Rule-altitude sibling delegator on the figment-`Metadata::name`
    /// axis [`Option<FigmentNameTagKind>`] projection: symmetric peer
    /// of [`Self::is_figment_source_file`] on the sibling partial
    /// projection. The delegator is `false` on every source-axis rule
    /// (where the outer `Option` is `None`) and `true` on the single
    /// name-axis rule whose identity pins the `Format` cell
    /// ([`Self::FileByMetadataName`]).
    ///
    /// One-hop lift through the partial projection — mirrors the
    /// rationale documented on [`Self::is_figment_source_file`] and
    /// keeps the polarity of the figment-`Metadata::name`-axis-kind
    /// partition defined in exactly one place
    /// ([`FigmentNameTagKind::is_format`]).
    ///
    /// Pinned by
    /// `attribution_rule_is_figment_name_format_agrees_with_figment_name_tag_kind_is_format`.
    /// The two name-axis sibling delegators
    /// ([`Self::is_figment_name_format`], [`Self::is_figment_name_env`])
    /// form a `Some-iff-name-axis` disjoint partition of [`Self::ALL`] —
    /// exactly one holds on every name-axis rule, zero hold on every
    /// source-axis rule — pinned by
    /// `attribution_rule_figment_name_tag_kind_predicates_partition_name_axis_rules`.
    #[must_use]
    pub fn is_figment_name_format(self) -> bool {
        self.figment_name_tag_kind()
            .is_some_and(FigmentNameTagKind::is_format)
    }

    /// Returns `true` when [`Self::figment_name_tag_kind`] returns
    /// [`Some(FigmentNameTagKind::Env)`]; equivalent to
    /// `self.figment_name_tag_kind() == Some(FigmentNameTagKind::Env)`.
    /// Sibling of [`Self::is_figment_name_format`]; see it for the
    /// delegation rationale and the closed-partition pin.
    ///
    /// The two name-axis rules dispatched off env-shaped
    /// `Metadata::name` values ([`Self::EnvByPrefix`],
    /// [`Self::EnvByUniqueness`]) are the exact inhabitants of this
    /// predicate; pinned by
    /// `attribution_rule_is_figment_name_env_agrees_with_figment_name_tag_kind_is_env`.
    #[must_use]
    pub fn is_figment_name_env(self) -> bool {
        self.figment_name_tag_kind()
            .is_some_and(FigmentNameTagKind::is_env)
    }

    /// Partial inverse of
    /// [`crate::FormatProvenance::file_attribution_rule`]: re-hydrate the
    /// recognized [`crate::FormatProvenance`] from a file-axis attribution
    /// rule, or [`None`] for non-file-axis rules.
    ///
    /// File-axis rules ([`Self::layer_kind`] returns
    /// [`ConfigSourceKind::File`]) carry the provider class that emitted
    /// the offending file layer's metadata as a structural consequence of
    /// their dispatch shape:
    /// [`Self::FileBySource`] ⇒ [`Some(crate::FormatProvenance::FigmentBuiltin)`]
    /// (figment's YAML/TOML providers attach `Source::File`),
    /// [`Self::FileByMetadataName`] ⇒
    /// [`Some(crate::FormatProvenance::ShikumiBuilt)`] (shikumi's
    /// [`crate::LispProvider`] / [`crate::NixProvider`] attach the
    /// `"<format>: <path>"` shape). Non-file-axis rules
    /// ([`Self::EnvByPrefix`], [`Self::EnvByUniqueness`],
    /// [`Self::DefaultsByCodeUniqueness`]) all map to [`None`] — the
    /// (provenance ↔ file-rule) pairing only ranges over the file
    /// attribution sub-surface.
    ///
    /// One source of truth for the typed inverse of the
    /// (provenance → file-rule) projection. Before this method, the
    /// inverse was implicit in [`crate::FormatProvenance::file_attribution_rule`]'s
    /// match shape and recoverable only by manually re-deriving the
    /// (rule → provenance) dispatch inline — a string-of-prose contract,
    /// not a typed law. Now it composes as one method call: a recorded
    /// [`Self`] (read off a captured [`FailingSourceAttribution`] or
    /// [`crate::ReloadFailure::attribution_rule`]) routes to the
    /// originating provider class in one closed-enum read, with the
    /// `None`-on-non-file-axis discipline pinning the partial range at
    /// the type level. Pairs with the existing
    /// [`Self::figment_source_kind`] partial projection (and the
    /// total [`Self::layer_kind`] / [`Self::metadata_axis`] /
    /// [`Self::confidence`] projections) as a fifth orthogonal axis
    /// over the rule space.
    ///
    /// Closes the partial bijection on the file-axis sub-surface: the
    /// (provenance × file-axis rule) cube has 2 × 2 = 4 product cells
    /// (two provenances, two file rules); the recognized image is
    /// exactly the 2 diagonal cells where
    /// `provenance.file_attribution_rule() == rule` holds. The forward
    /// map [`crate::FormatProvenance::file_attribution_rule`] is total
    /// over the provenance space; this inverse is partial over the rule
    /// space, returning [`Some`] exactly on the two file-axis cells.
    /// The bijection laws — `rule.file_provenance().map(|p|
    /// p.file_attribution_rule()) == Some(rule)` for every file-axis
    /// rule, and `p.file_attribution_rule().file_provenance() == Some(p)`
    /// for every provenance — are pinned by
    /// `attribution_rule_file_provenance_round_trips_through_format_provenance`
    /// and `format_provenance_file_attribution_rule_round_trips_through_file_provenance`.
    ///
    /// `Some`-iff-file-layer-kind discipline: `self.file_provenance()`
    /// is [`Some`] exactly when [`Self::layer_kind`] is
    /// [`ConfigSourceKind::File`]. The partial image of this projection
    /// is exactly the file-axis sub-cube; pinned by
    /// `attribution_rule_file_provenance_some_iff_file_layer_kind`.
    /// A future variant added to [`Self`] forces a provenance assignment
    /// in the exhaustive match in lockstep — either as a new file-axis
    /// arm (carrying a [`Some(_)`] provenance) or a non-file-axis arm
    /// (carrying [`None`]) — and the cross-axis law stays coherent by
    /// construction.
    ///
    /// Mirrored on the captured-failure surfaces:
    /// [`FailingSourceAttribution::file_provenance`] (borrowed envelope)
    /// and [`crate::ReloadFailure::file_provenance`] (cross-thread
    /// observable form) surface the same projection through the captured
    /// rule slot, so a structured-log replay or attestation manifest
    /// that records a captured failure can recover the originating
    /// provider class without retaining the live [`crate::ShikumiError`].
    #[must_use]
    pub fn file_provenance(self) -> Option<crate::FormatProvenance> {
        match self {
            Self::FileBySource => Some(crate::FormatProvenance::FigmentBuiltin),
            Self::FileByMetadataName => Some(crate::FormatProvenance::ShikumiBuilt),
            Self::EnvByPrefix | Self::EnvByUniqueness | Self::DefaultsByCodeUniqueness => None,
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

    /// Forward partial unifier of the two name-axis projections over
    /// this rule: [`Self::figment_name_tag_kind`] (partial) and
    /// [`Self::layer_kind`] (total). Returns the rule's joint cell on
    /// the (figment-`Metadata::name`-axis kind × shikumi-layer-kind)
    /// plane as a typed [`AttributionNameKindCoordinates`] envelope.
    ///
    /// Some-iff-MetadataName discipline: returns [`Some`] exactly when
    /// [`Self::figment_name_tag_kind`] returns [`Some`] (equivalently,
    /// when [`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataName`]). Name-axis rules pin both
    /// halves of their joint cell:
    /// [`Self::FileByMetadataName`] → `(Format, File)`,
    /// [`Self::EnvByPrefix`] → `(Env, Env)`,
    /// [`Self::EnvByUniqueness`] → `(Env, Env)`. Source-axis rules pin
    /// only [`Self::layer_kind`]; their figment-name-axis half is
    /// unconstrained, so the joint cell is [`None`].
    ///
    /// One source of truth for the (figment-name-axis kind ×
    /// shikumi-layer-kind) joint cell on a recognized rule. Symmetric
    /// peer of [`Self::attribution_source_kind_coordinates`] on the
    /// figment-`Metadata::source` axis. Before this method, observers
    /// that wanted the joint cell on the name-axis sub-surface — a
    /// per-cell dashboard routing on the joint cell, an attestation
    /// manifest recording the name-axis rule subset's image, a
    /// structured-diagnostics legend rendering distinct prose per
    /// joint cell — inlined a two-step
    /// `self.figment_name_tag_kind().map(|nk| (nk, self.layer_kind()))`
    /// projection at every site. The named struct collapses the two
    /// reads (one partial, one total) into one [`Option<_>`] read,
    /// surfacing the joint cell as a typescape-eligible value
    /// (`Copy + Eq + Hash + #[non_exhaustive]`) usable in `match`,
    /// `HashMap` keys, log labels, alerting buckets, and attestation
    /// manifest payloads.
    ///
    /// Pairs with [`AttributionNameKindCoordinates::is_realizable`] as
    /// the membership-predicate discipline: every [`Some`] return of
    /// this accessor produces a cell satisfying `is_realizable`. Peer
    /// to [`Self::attribution_source_kind_coordinates`] /
    /// [`AttributionSourceKindCoordinates::is_realizable`] on the
    /// fourth product cube — both are total-or-partial forward maps
    /// whose image is the recognized subset of their cube.
    ///
    /// Composes with [`Self::attribution_source_kind_coordinates`] as a
    /// strict partition over the rule space: every rule's identity
    /// dispatches on exactly one figment-metadata axis, so for every
    /// rule exactly one of
    /// [`Self::attribution_source_kind_coordinates`] and
    /// [`Self::attribution_name_kind_coordinates`] returns [`Some`].
    /// Pinned by
    /// `attribution_rule_attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates`.
    ///
    /// Composes with the captured-failure envelopes — the convenience
    /// forwarders
    /// [`FailingSourceAttribution::attribution_name_kind_coordinates`]
    /// and [`crate::ReloadFailure::attribution_name_kind_coordinates`]
    /// surface the same joint cell off the borrowed and cross-thread
    /// observable surfaces, with the cross-thread accessor lifted to
    /// the same `Some-iff-name-axis-attribution` discipline.
    #[must_use]
    pub fn attribution_name_kind_coordinates(self) -> Option<AttributionNameKindCoordinates> {
        self.figment_name_tag_kind()
            .map(|figment_name_tag_kind| AttributionNameKindCoordinates {
                figment_name_tag_kind,
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
    ///
    /// `const`-callable — a compile-time-known rule's coordinate
    /// triple is a compile-time value, so a
    /// `static PER_RULE: [AttributionCoordinates;
    /// AttributionRule::ALL.len()]` per-rule coordinate table wires
    /// straight through to compile-time evaluation without a runtime
    /// projection, welded by
    /// [`tests::attribution_rule_coordinates_is_const_callable`]. Lifted
    /// to `const` alongside the three sibling total projections
    /// ([`Self::metadata_axis`], [`Self::layer_kind`],
    /// [`Self::confidence`]) it composes over — the unifier stays at
    /// the same const-callability altitude as every atomic component
    /// it reads.
    #[must_use]
    pub const fn coordinates(self) -> AttributionCoordinates {
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
    /// structural composition of [`ShikumiErrorKind::ALL`] (7 cells)
    /// and [`FieldPathLocalization::ALL`] (3 cells) into the
    /// `7 × 3 = 21`-cell coordinate space, in lexicographic order
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
    /// 9 + 12 split pinned by [`Self::is_realizable`]: 9 cells satisfy
    /// the realizability invariant (2 figment-bearing kinds × 2
    /// figment-attached localizations + 5 non-figment-bearing kinds ×
    /// [`FieldPathLocalization::NotApplicable`]); the other 12 cells
    /// violate it. The `error_localization_coordinates_realizable_image_equals_observed_pairs`
    /// test pins the realizable half as the exact image of
    /// [`ShikumiError::error_localization_coordinates`] over the
    /// canonical construction-table surface, and the
    /// `error_localization_coordinates_realizable_partitions_into_9_realizable_and_12_unrealizable`
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
        Self {
            kind: ShikumiErrorKind::Validation,
            localization: FieldPathLocalization::Localized,
        },
        Self {
            kind: ShikumiErrorKind::Validation,
            localization: FieldPathLocalization::FigmentUnlocalized,
        },
        Self {
            kind: ShikumiErrorKind::Validation,
            localization: FieldPathLocalization::NotApplicable,
        },
    ];

    /// Realizability predicate over the 21-cell product cube:
    /// returns `true` exactly on the 9 cells that can be produced by
    /// [`ShikumiError::error_localization_coordinates`] (or its
    /// captured-failure mirror
    /// [`crate::ReloadFailure::error_localization_coordinates`]) on
    /// some constructible [`ShikumiError`] value, and `false` on the
    /// remaining 12 cells.
    ///
    /// The invariant is
    /// `self.kind.is_figment_bearing() ==
    /// (self.localization != FieldPathLocalization::NotApplicable)`,
    /// proven pointwise by the partition contracts pinning
    /// [`ShikumiError::field_path_localization`]: figment-bearing
    /// variants (`Figment`, `Extract`) always project to
    /// `Localized` or `FigmentUnlocalized` (the figment error's
    /// `path` slot is `Some`); non-figment-bearing variants
    /// (`NotFound`, `Parse`, `Watch`, `Io`, `Validation`) always
    /// project to `NotApplicable` (no figment error to project from).
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
    ///
    /// `const`-callable, so a downstream consumer holding a
    /// compile-time-known coordinate cell — a `static
    /// REALIZABLE_TABLE: [bool; ErrorLocalizationCoordinates::ALL.len()]`
    /// per-cell realizability lookup, an attestation manifest
    /// recording realizable-image membership at compile time, a
    /// `const` sentinel for a compile-time-known (kind ×
    /// localization) pair — projects onto the realizability
    /// predicate at compile time without a runtime call, matching
    /// the const-callability of the two hop-predicates it
    /// composes ([`ShikumiErrorKind::is_figment_bearing`] and
    /// [`FieldPathLocalization::is_applicable`], both `const` since
    /// introduced). Pinned by
    /// [`tests::error_localization_coordinates_is_realizable_is_const_callable`].
    #[must_use]
    pub const fn is_realizable(self) -> bool {
        self.kind.is_figment_bearing() == self.localization.is_applicable()
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

/// Joint cell of a name-axis [`AttributionRule`]: the typed pair of
/// [`FigmentNameTagKind`] (which [`figment::Metadata::name`] class the
/// rule's identity already names) and [`ConfigSourceKind`] (which
/// [`ConfigSource`] layer class the rule attributes to).
///
/// Symmetric peer of [`AttributionSourceKindCoordinates`] on the
/// figment-`Metadata::name` axis: same typescape discipline (named
/// product struct, closed `'static` slice in declaration order,
/// `Copy + Eq + Hash + #[non_exhaustive]` element type, cardinality
/// pinned as a product of the constituent axis cardinalities, a
/// forward-partial / membership-predicate pair), applied to figment's
/// `Metadata::name` axis. The pair
/// (source-side: [`AttributionSourceKindCoordinates`],
/// name-side: [`AttributionNameKindCoordinates`]) closes the
/// figment-metadata × shikumi-layer joint-cell universe under one
/// typescape primitive set: every rule's identity already projects to
/// exactly one of the two cubes — pinned by the cross-axis XOR
/// partition law
/// `attribution_rule_attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates`.
///
/// The (`figment_name_tag_kind × layer_kind`) plane has
/// `FigmentNameTagKind::ALL.len()` × `ConfigSourceKind::ALL.len()`
/// = 2 × 3 = 6 product cells; today's name-axis rule subset occupies
/// 2 of them — the "realizable" cells in the partition pinned by
/// [`Self::is_realizable`]:
///
/// - [`AttributionRule::FileByMetadataName`] →
///   `(FigmentNameTagKind::Format, ConfigSourceKind::File)`.
/// - [`AttributionRule::EnvByPrefix`] /
///   [`AttributionRule::EnvByUniqueness`] →
///   `(FigmentNameTagKind::Env, ConfigSourceKind::Env)`.
///
/// The other 4 cells are unrealizable today by construction: no
/// recognized [`AttributionRule`] pairs `FigmentNameTagKind::Format`
/// with [`ConfigSourceKind::Env`] or [`ConfigSourceKind::Defaults`],
/// and no recognized rule pairs `FigmentNameTagKind::Env` with
/// [`ConfigSourceKind::File`] or [`ConfigSourceKind::Defaults`]. The
/// realizability invariant is "lies on the structural diagonal of
/// name-axis rules":
/// `(figment_name_tag_kind, layer_kind) ∈ {(Format, File), (Env, Env)}`,
/// pinned by [`Self::is_realizable`] and verified pointwise across the
/// rule space by
/// `attribution_name_kind_coordinates_realizable_image_equals_rule_image`.
///
/// Fifth product-axis `ALL` constant on the typescape primitive set,
/// peer to [`AttributionCoordinates::ALL`] (the first, 12-cell
/// `axis × layer_kind × confidence` cube),
/// [`crate::FormatCoordinates::ALL`] (the second, 8-cell
/// `format × provenance` cube),
/// [`ErrorLocalizationCoordinates::ALL`] (the third, 18-cell
/// `kind × localization` cube), and
/// [`AttributionSourceKindCoordinates::ALL`] (the fourth, 9-cell
/// `figment_source_kind × layer_kind` cube), but lifted on a different
/// sibling pair (`FigmentNameTagKind × ConfigSourceKind`).
/// [`AttributionRule::attribution_name_kind_coordinates`] (and the
/// convenience forwarders
/// [`FailingSourceAttribution::attribution_name_kind_coordinates`] /
/// [`crate::ReloadFailure::attribution_name_kind_coordinates`]) is the
/// forward partial map (`None` for source-axis rules);
/// [`Self::is_realizable`] is the membership predicate over the
/// recognized 2-cell subset.
///
/// Composes [`AttributionRule::figment_name_tag_kind`] (the partial
/// projection onto the figment-name-axis kind) with
/// [`AttributionRule::layer_kind`] (the total projection onto the
/// shikumi-layer-kind) into one [`Copy`] joint cell. Operationally
/// distinguishes the realizable image of the name-axis rule subset
/// from the cross-axis consistency violations
/// (e.g. `(Format, Env)`, `(Env, File)`) that no recognized rule can
/// occupy.
///
/// The struct exists (rather than a bare tuple) so call sites document
/// which slot is which — `figment_name_tag_kind` / `layer_kind` — at
/// the type level rather than relying on positional destructuring
/// discipline. Consumers route on the named fields in `match`,
/// `HashMap` keys, structured-log payloads, and attestation manifests;
/// the `Copy + Eq + Hash + #[non_exhaustive]` bounds match the sibling
/// product-cube structs ([`AttributionCoordinates`],
/// [`crate::FormatCoordinates`], [`ErrorLocalizationCoordinates`],
/// [`AttributionSourceKindCoordinates`]) and the underlying axis
/// primitives ([`FigmentNameTagKind`], [`ConfigSourceKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttributionNameKindCoordinates {
    /// Which [`figment::Metadata::name`]-axis kind the name-axis rule's
    /// identity already pins — see [`FigmentNameTagKind`] /
    /// [`AttributionRule::figment_name_tag_kind`].
    pub figment_name_tag_kind: FigmentNameTagKind,
    /// Which [`ConfigSource`] layer kind the rule attributes to —
    /// see [`ConfigSourceKind`] / [`AttributionRule::layer_kind`].
    pub layer_kind: ConfigSourceKind,
}

impl AttributionNameKindCoordinates {
    /// Every cell of the `figment_name_tag_kind × layer_kind` product
    /// cube — the structural composition of
    /// [`FigmentNameTagKind::ALL`] (2 cells) and
    /// [`ConfigSourceKind::ALL`] (3 cells) into the `2 × 3 = 6`-cell
    /// coordinate space, in lexicographic order over the two sibling
    /// slices (`figment_name_tag_kind` outermost, `layer_kind`
    /// innermost).
    ///
    /// Fifth product-axis `ALL` constant on the typescape primitive
    /// set — peer to [`AttributionCoordinates::ALL`],
    /// [`crate::FormatCoordinates::ALL`],
    /// [`ErrorLocalizationCoordinates::ALL`], and
    /// [`AttributionSourceKindCoordinates::ALL`] — lifted on the
    /// `FigmentNameTagKind × ConfigSourceKind` sibling pair. Same
    /// typescape discipline (closed `'static` slice, in declaration
    /// order, `Copy + Eq + Hash + #[non_exhaustive]` element type)
    /// applied to the attribution-name-kind product cube.
    ///
    /// Cardinality is pinned by
    /// `attribution_name_kind_coordinates_all_cardinality_matches_product_of_axes`
    /// against `FigmentNameTagKind::ALL.len() * ConfigSourceKind::ALL.len()`,
    /// so any new variant on either sibling axis forces an extension of
    /// this slice in lockstep with the variant itself. The
    /// `attribution_name_kind_coordinates_all_equals_axes_cartesian_product`
    /// test pins tight equality against the inline doubly-nested product
    /// over the sibling `ALL` constants — `Self::ALL` is the product,
    /// not a subset and not a superset.
    ///
    /// The partition into realizable and unrealizable cells is the
    /// 2 + 4 split pinned by [`Self::is_realizable`]: 2 cells lie on
    /// the structural diagonal of name-axis rules (`(Format, File)`
    /// from [`AttributionRule::FileByMetadataName`] and `(Env, Env)`
    /// from [`AttributionRule::EnvByPrefix`] /
    /// [`AttributionRule::EnvByUniqueness`]); the other 4 cells are
    /// unrealizable today. The
    /// `attribution_name_kind_coordinates_realizable_image_equals_rule_image`
    /// test pins the realizable half as the exact image of
    /// [`AttributionRule::attribution_name_kind_coordinates`] over
    /// [`AttributionRule::ALL`], and the
    /// `attribution_name_kind_coordinates_realizable_partitions_into_2_realizable_and_4_unrealizable`
    /// test pins the cardinality split.
    pub const ALL: &'static [Self] = &[
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Format,
            layer_kind: ConfigSourceKind::Defaults,
        },
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Format,
            layer_kind: ConfigSourceKind::Env,
        },
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Format,
            layer_kind: ConfigSourceKind::File,
        },
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Env,
            layer_kind: ConfigSourceKind::Defaults,
        },
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Env,
            layer_kind: ConfigSourceKind::Env,
        },
        Self {
            figment_name_tag_kind: FigmentNameTagKind::Env,
            layer_kind: ConfigSourceKind::File,
        },
    ];

    /// Realizability predicate over the 6-cell product cube: returns
    /// `true` exactly on the 2 cells that can be produced by
    /// [`AttributionRule::attribution_name_kind_coordinates`] (or its
    /// captured-failure mirrors
    /// [`FailingSourceAttribution::attribution_name_kind_coordinates`]
    /// and [`crate::ReloadFailure::attribution_name_kind_coordinates`])
    /// on some recognized [`AttributionRule`] variant, and `false`
    /// on the remaining 4 cells.
    ///
    /// The invariant is the structural diagonal of name-axis rules:
    /// `(figment_name_tag_kind, layer_kind) ∈ {(Format, File),
    /// (Env, Env)}`. Proven by enumeration over the rule space:
    /// [`AttributionRule::FileByMetadataName`] is the only name-axis
    /// rule that dispatches off [`FigmentNameTag::Format`] and pairs
    /// with [`ConfigSource::File`] (so its joint cell is
    /// `(Format, File)`); [`AttributionRule::EnvByPrefix`] and
    /// [`AttributionRule::EnvByUniqueness`] are the two name-axis rules
    /// that dispatch off [`FigmentNameTag::Env`] and pair with
    /// [`ConfigSource::Env`] (so both joint cells coincide on
    /// `(Env, Env)`). Source-axis rules don't pin a
    /// `figment_name_tag_kind` at all and are absent from this image.
    ///
    /// Operational use: an attestation manifest, structured-log replay,
    /// or cross-process diagnostic that observes the
    /// (`figment_name_tag_kind`, `layer_kind`) coordinates recovers the
    /// realizability classification — "is this cell a valid observation
    /// of a recognized name-axis rule, or a cross-axis consistency
    /// violation" — by one method call instead of re-deriving the
    /// consistency check inline. Future name-axis rules land coherently:
    /// a new [`AttributionRule`] variant that dispatches off a future
    /// [`FigmentNameTag`] variant extends the recognized image, forces
    /// an exhaustive-match arm in
    /// [`AttributionRule::attribution_name_kind_coordinates`]
    /// (compile-time), and forces an extension of the
    /// `attribution_name_kind_coordinates_realizable_image_equals_rule_image`
    /// expectation (test-time) — all three stay in lockstep.
    ///
    /// Peer to [`AttributionSourceKindCoordinates::is_realizable`] on
    /// the source-axis cube and
    /// [`ErrorLocalizationCoordinates::is_realizable`] on the
    /// error-localization cube: all three are membership predicates on
    /// a non-injective forward map's image. Pairs with the
    /// partial-inverse discipline of [`AttributionRule::from_coordinates`]
    /// / [`crate::FormatCoordinates::format_or_none`] on the cubes
    /// where the forward map is injective.
    ///
    /// [`FigmentNameTag::Format`]: crate::FigmentNameTag::Format
    /// [`FigmentNameTag::Env`]: crate::FigmentNameTag::Env
    #[must_use]
    pub fn is_realizable(self) -> bool {
        matches!(
            (self.figment_name_tag_kind, self.layer_kind),
            (FigmentNameTagKind::Format, ConfigSourceKind::File)
                | (FigmentNameTagKind::Env, ConfigSourceKind::Env)
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

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the captured-failure variant axis kind, lifted to one macro
// after the 16+ hand-rolled idiom-peers (Format, FormatProvenance,
// ConfigSourceKind, FigmentSourceKind, FigmentNameTagKind,
// SecretBackendKind, SecretRefShape, EnvMetadataTagKind, WatchEventClass
// (migrated 392cbeb), DiffLineKind, SecretClientKind, SecretErrorKind,
// SecretOperation). See `closed_axis_label_string_surface!` in
// `crate::macros` for the contract; behavior is byte-identical to the
// hand-rolled impls the macro replaces — the verbatim-label `Parse`
// error body, the case-insensitive `from_canonical_str` lowering, the
// `collect_str`-based serde emission, and the visitor's `expecting`
// message all match the prior surface pointwise. Pinned by
// `tests::shikumi_error_kind_display_matches_as_str`,
// `tests::shikumi_error_kind_from_str_*`, and
// `tests::shikumi_error_kind_serde_yaml_*`.
closed_axis_label_string_surface! {
    type = ShikumiErrorKind,
    parse_error = "unknown shikumi error kind",
    expecting = "a canonical ShikumiErrorKind label \
                 (`not-found`, `parse`, `watch`, `io`, `figment`, `extract`, `validation`; \
                 case-insensitive)",
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

impl crate::ClosedAxis for AttributionNameKindCoordinates {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ProductCube for AttributionNameKindCoordinates {
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

    /// Returns `true` for [`Self::Exact`]; equivalent to
    /// `self == AttributionConfidence::Exact`.
    ///
    /// Convenience predicate matching the sibling pair on
    /// [`crate::FormatProvenance`] ([`crate::FormatProvenance::is_shikumi_built`]
    /// / [`crate::FormatProvenance::is_figment_builtin`]): typescape
    /// primitives expose a per-variant predicate alongside the closed-
    /// enum dispatch so the common "is it this one?" question stays
    /// one method call.
    ///
    /// The source-altitude peers on [`AttributionRule`]
    /// ([`AttributionRule::is_exact`] / [`AttributionRule::is_fallback`])
    /// now route through this sibling — the polarity of the (exact,
    /// fallback) partition is defined once here, and the rule-altitude
    /// convenience follows automatically via
    /// `AttributionRule::is_exact() == self.confidence().is_exact()`.
    /// Before the routing, both the rule-altitude and the
    /// (implicit) confidence-altitude reads reached for a fresh
    /// `matches!` against `AttributionConfidence::Exact`, so a future
    /// change to what "exact" means (e.g. collapsing an added
    /// `Heuristic` cell into the exact half, or the reverse) had two
    /// places to keep in lockstep by convention. The routing collapses
    /// that to one.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact)
    }

    /// Returns `true` for [`Self::Fallback`]; equivalent to
    /// `self == AttributionConfidence::Fallback`.
    ///
    /// Sibling of [`Self::is_exact`] on the other half of the closed
    /// binary partition; same routing rationale (see [`Self::is_exact`]
    /// docs), same peer pattern
    /// ([`crate::FormatProvenance::is_figment_builtin`]).
    #[must_use]
    pub const fn is_fallback(self) -> bool {
        matches!(self, Self::Fallback)
    }

    /// The single EXACT [`AttributionConfidence`] variant —
    /// [`Self::Exact`] (the equality-based pole of the (exact ×
    /// fallback) confidence partition) — in the SAME relative
    /// declaration order it occupies in [`Self::ALL`], carrying the
    /// *exact* pole of the closed-binary polarity at the confidence
    /// primitive's OWN altitude on the confidence axis, mirroring the
    /// shipped boolean predicate [`Self::is_exact`] one altitude down:
    /// every variant in this slice satisfies `c.is_exact()`, and no
    /// variant outside it does.
    ///
    /// Paired with [`Self::FALLBACK`], the two disjoint slices
    /// partition [`Self::ALL`] at the static-slice altitude the same
    /// way the shipped boolean predicates [`Self::is_exact`] /
    /// [`Self::is_fallback`] meta-partition it at the boolean altitude.
    /// Both sit in the same `impl AttributionConfidence` block as
    /// [`Self::ALL`] and follow the same `pub const &'static [Self]`
    /// static-slice discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the exact pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_exact`] at const-fn altitude — so the two
    /// declarations (the slice literal and the boolean predicate)
    /// remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first confidence where they
    /// disagree.
    ///
    /// Idiom-peer of [`crate::PartitionFace::REALIZABLE`]
    /// (commit `a344056`), [`crate::SecretRefShape::WHOLE`]
    /// (commit `036673b`), [`crate::ConfigSourceKind::DEFAULTS`]
    /// (commit `2cd8ef8`), [`crate::ConfigTierKind::COMPUTED`]
    /// (commit `2c0686f`), [`crate::SecretOperation::MUTATING`]
    /// (commit `b2cfa2a`),
    /// [`crate::secret::SecretBackendKind::CLOUD_SECRET_MANAGER`]
    /// (commit `04e0f5d`),
    /// [`crate::secret_client::SecretClientKind::CLOUD_SECRET_MANAGER`]
    /// (commit `399ee8a`), and
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] (commit `7ef79e4`)
    /// — the per-half meta-partition slice-constant discipline applied
    /// here to the confidence axis, lifting the [`AttributionConfidence`]
    /// closed-binary primitive onto the slice-constant altitude.
    ///
    /// A future tertiary confidence variant (e.g. a `Heuristic` class
    /// for resolver paths that combine equality with structural hints,
    /// which the primitive's own doc-comment already anticipates)
    /// lands here either extending one of the two slices in lockstep
    /// with the boolean predicate that admits it, or introducing a
    /// third slice; the partition and cardinality pins refuse a silent
    /// landing under the negation of one of the existing two.
    ///
    /// The two agreement laws
    /// (`EXACT.iter().all(|c| c.is_exact())` and
    /// `EXACT.iter().all(|c| !c.is_fallback())`) are pinned by
    /// [`tests::attribution_confidence_exact_slice_agrees_with_is_exact_predicate`].
    /// Partition invariant with [`Self::FALLBACK`]:
    /// [`tests::attribution_confidence_exact_and_fallback_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_confidence_exact_and_fallback_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::attribution_confidence_exact_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::attribution_confidence_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_confidence_exact_and_fallback_slices_are_const_addressable`].
    pub const EXACT: &'static [Self] = &[Self::Exact];

    /// The single FALLBACK [`AttributionConfidence`] variant —
    /// [`Self::Fallback`] (the uniqueness-based pole of the (exact ×
    /// fallback) confidence partition) — in the SAME relative
    /// declaration order it occupies in [`Self::ALL`], the complement
    /// pole of [`Self::EXACT`] on the (exact × fallback) closed-binary
    /// polarity at the confidence primitive's OWN altitude on the
    /// confidence axis. Mirrors the shipped boolean predicate
    /// [`Self::is_fallback`] one altitude down.
    ///
    /// The partition invariant with [`Self::EXACT`] pins the whole-set
    /// cardinality identity
    /// `EXACT.len() + FALLBACK.len() == ALL.len()`. Because the axis
    /// is closed-binary and XOR-complementary by construction today, a
    /// future third confidence landing (e.g. a `Heuristic` class the
    /// primitive's own doc-comment anticipates) would first fail the
    /// two-entry cardinality pins, then fail the partition and
    /// cardinality pins on this constant pair unless extended in
    /// lockstep with the boolean predicates.
    ///
    /// See [`Self::EXACT`] for the full contract, the discipline behind
    /// the explicit slice literal (rather than a filter through
    /// [`Self::is_exact`]), and the load-bearing agreement and
    /// partition pins.
    pub const FALLBACK: &'static [Self] = &[Self::Fallback];
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

    /// Returns `true` for [`Self::MetadataSource`]; equivalent to
    /// `self == AttributionAxis::MetadataSource`.
    ///
    /// Convenience predicate matching the sibling pairs on every peer
    /// closed-axis primitive in the module: [`AttributionConfidence::is_exact`]
    /// / [`AttributionConfidence::is_fallback`] on the confidence axis,
    /// [`FieldPathLocalization::is_applicable`] /
    /// [`FieldPathLocalization::is_not_applicable`] on the localization
    /// axis, [`ShikumiErrorKind::is_figment_bearing`] /
    /// [`ShikumiErrorKind::is_not_figment_bearing`] on the kind axis,
    /// and [`crate::FormatProvenance::is_shikumi_built`] /
    /// [`crate::FormatProvenance::is_figment_builtin`] on the
    /// format-provenance axis. `AttributionAxis` was the last remaining
    /// single-predicate primitive in `error.rs`; this closes the
    /// sibling-predicate pattern on the metadata axis so consumers
    /// dispatching on the source-vs-name split (attribution-count
    /// dashboards weighting name-axis attributions visibly weaker,
    /// structured-log filters, per-axis histogram partitioning) stop
    /// re-inventing `matches!(axis, AttributionAxis::MetadataSource)` at
    /// each site — six such consumer sites in `error::tests` and two in
    /// `discovery::tests` already reach for a fresh `==
    /// AttributionAxis::MetadataSource` comparison; each is a candidate
    /// to route through this sibling as the polarity of the (source,
    /// name) partition consolidates at the axis altitude.
    ///
    /// A future tertiary variant (e.g. a `MetadataExtras` cell for
    /// figment providers that surface additional typed metadata fields)
    /// landing on [`Self`] must either extend one predicate to admit it
    /// or introduce a third predicate — the `attribution_axis_predicates
    /// _are_a_closed_binary_partition` test refuses to compile through
    /// a silent-landing under the negation of one of the existing two.
    #[must_use]
    pub const fn is_metadata_source(self) -> bool {
        matches!(self, Self::MetadataSource)
    }

    /// Returns `true` for [`Self::MetadataName`]; equivalent to
    /// `!self.is_metadata_source()`.
    ///
    /// Sibling of [`Self::is_metadata_source`] on the other half of the
    /// closed binary partition over the metadata axis; same routing
    /// rationale (see [`Self::is_metadata_source`] docs), same peer
    /// pattern ([`AttributionConfidence::is_fallback`],
    /// [`FieldPathLocalization::is_not_applicable`],
    /// [`ShikumiErrorKind::is_not_figment_bearing`],
    /// [`crate::FormatProvenance::is_figment_builtin`]).
    #[must_use]
    pub const fn is_metadata_name(self) -> bool {
        matches!(self, Self::MetadataName)
    }

    /// The single METADATA_SOURCE [`AttributionAxis`] variant —
    /// [`Self::MetadataSource`] (the typed-`figment::Source`-driven
    /// pole of the (source × name) metadata partition) — in the SAME
    /// relative declaration order it occupies in [`Self::ALL`], as a
    /// per-half projection of the (source × name) closed-binary
    /// polarity at the axis primitive's OWN altitude on the metadata
    /// axis. Mirrors the shipped boolean predicate
    /// [`Self::is_metadata_source`] one altitude down (per-variant
    /// polarity), and follows the same `pub const &'static [Self]`
    /// static-slice discipline as [`Self::ALL`].
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the source pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_metadata_source`] at const-fn altitude — so
    /// the two declarations (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the
    /// same meta-partition, and a future edit that shifts a variant
    /// across the polarity on ONE declaration surface but not the
    /// other diverges at test time on the first axis where they
    /// disagree.
    ///
    /// Peer to the shipped per-half slice constants
    /// [`AttributionConfidence::EXACT`] on the confidence axis,
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] on the format-
    /// provenance axis, [`crate::secret::SecretRefShape::WHOLE`] on
    /// the secret-ref extraction-shape axis,
    /// [`crate::tiered::ConfigTierKind::COMPUTED`] on the tier-kind
    /// axis, and [`crate::source::ConfigSourceKind::DEFAULTS`] on the
    /// layer-kind axis of the atomic `(tier, source)` pair — same
    /// altitude, applied to the metadata axis.
    ///
    /// A future tertiary variant (e.g. a `MetadataExtras` cell for
    /// figment providers that surface additional typed metadata
    /// fields) landing on [`Self`] must either extend one slice in
    /// lockstep with the boolean predicate that admits it, or
    /// introduce a third slice; the partition and cardinality pins
    /// refuse a silent landing under the negation of one of the
    /// existing two.
    ///
    /// The two agreement laws
    /// (`METADATA_SOURCE.iter().all(|a| a.is_metadata_source())` and
    /// `METADATA_SOURCE.iter().all(|a| !a.is_metadata_name())`) are
    /// pinned by
    /// [`tests::attribution_axis_metadata_source_slice_agrees_with_is_metadata_source_predicate`].
    /// Partition invariant with [`Self::METADATA_NAME`]:
    /// [`tests::attribution_axis_metadata_source_and_metadata_name_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::attribution_axis_metadata_source_and_metadata_name_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::attribution_axis_metadata_source_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::attribution_axis_metadata_source_and_metadata_name_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::attribution_axis_metadata_source_and_metadata_name_slices_are_const_addressable`].
    pub const METADATA_SOURCE: &'static [Self] = &[Self::MetadataSource];

    /// The single METADATA_NAME [`AttributionAxis`] variant —
    /// [`Self::MetadataName`] (the string-shape-driven pole of the
    /// (source × name) metadata partition) — in the SAME relative
    /// declaration order it occupies in [`Self::ALL`], the complement
    /// pole of [`Self::METADATA_SOURCE`] on the (source × name)
    /// closed-binary polarity at the axis primitive's OWN altitude on
    /// the metadata axis. Mirrors the shipped boolean predicate
    /// [`Self::is_metadata_name`] one altitude down.
    ///
    /// The partition invariant with [`Self::METADATA_SOURCE`] pins
    /// the whole-set cardinality identity
    /// `METADATA_SOURCE.len() + METADATA_NAME.len() == ALL.len()`.
    /// Because the axis is closed-binary and XOR-complementary by
    /// construction today, a future third metadata-axis landing (e.g.
    /// a `MetadataExtras` cell the primitive's own doc-comment
    /// anticipates) would first fail the two-entry cardinality pins,
    /// then fail the partition and cardinality pins on this constant
    /// pair unless extended in lockstep with the boolean predicates.
    ///
    /// See [`Self::METADATA_SOURCE`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a
    /// filter through [`Self::is_metadata_source`]), and the
    /// load-bearing agreement and partition pins.
    pub const METADATA_NAME: &'static [Self] = &[Self::MetadataName];
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

    /// [`FigmentNameTagKind`] of [`Self::rule`]; convenience over
    /// [`AttributionRule::figment_name_tag_kind`]. One method call
    /// answers "did the rule already pin which figment-name-axis cell
    /// fired?" — [`Some`] for name-axis rules
    /// ([`AttributionRule::FileByMetadataName`] →
    /// [`Some(FigmentNameTagKind::Format)`],
    /// [`AttributionRule::EnvByPrefix`] /
    /// [`AttributionRule::EnvByUniqueness`] →
    /// [`Some(FigmentNameTagKind::Env)`]), [`None`] for source-axis
    /// rules whose identity does not constrain the originating
    /// `figment::Metadata::name` — without destructuring the envelope or
    /// re-reading `metadata.name` off the originating
    /// [`figment::Error`].
    ///
    /// Some-iff-MetadataName discipline shared with
    /// [`AttributionRule::figment_name_tag_kind`]: the projection is
    /// [`Some`] exactly when [`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataName`] — the dual of the
    /// Some-iff-MetadataSource discipline on [`Self::figment_source_kind`].
    /// Pinned by
    /// `failing_source_attribution_figment_name_tag_kind_mirrors_rule_figment_name_tag_kind`.
    #[must_use]
    pub fn figment_name_tag_kind(self) -> Option<FigmentNameTagKind> {
        self.rule.figment_name_tag_kind()
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

    /// Joint (figment-`Metadata::name`-axis kind × shikumi-layer-kind)
    /// cell of [`Self::rule`]; convenience over
    /// [`AttributionRule::attribution_name_kind_coordinates`]. One
    /// method call returns the name-axis rule's joint cell — the
    /// figment-name-axis kind paired with the shikumi-layer kind —
    /// without destructuring the envelope or inlining the two sibling
    /// reads ([`Self::figment_name_tag_kind`], [`Self::layer_kind`])
    /// at the call site.
    ///
    /// Some-iff-MetadataName discipline shared with
    /// [`AttributionRule::attribution_name_kind_coordinates`]: the joint
    /// cell is [`Some`] exactly when [`Self::metadata_axis`] returns
    /// [`AttributionAxis::MetadataName`] — the dual of the
    /// Some-iff-MetadataSource discipline on
    /// [`Self::attribution_source_kind_coordinates`]. Pinned by
    /// `failing_source_attribution_attribution_name_kind_coordinates_mirrors_rule`.
    #[must_use]
    pub fn attribution_name_kind_coordinates(self) -> Option<AttributionNameKindCoordinates> {
        self.rule.attribution_name_kind_coordinates()
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

    /// [`crate::FormatProvenance`] of [`Self::rule`] on the file-axis
    /// sub-surface; convenience over [`AttributionRule::file_provenance`].
    /// One method call answers "which provider class — figment-builtin
    /// or shikumi-built — emitted the offending file layer's metadata?"
    /// without destructuring the envelope or re-deriving the
    /// (rule → provenance) projection inline.
    ///
    /// Some-iff-file-layer-kind discipline shared with
    /// [`AttributionRule::file_provenance`]: the projection is [`Some`]
    /// exactly when [`Self::layer_kind`] returns
    /// [`ConfigSourceKind::File`] (equivalently, when the captured rule
    /// is one of the two file-axis variants
    /// [`AttributionRule::FileBySource`] /
    /// [`AttributionRule::FileByMetadataName`]). Pinned by
    /// `failing_source_attribution_file_provenance_mirrors_rule_file_provenance`.
    #[must_use]
    pub fn file_provenance(self) -> Option<crate::FormatProvenance> {
        self.rule.file_provenance()
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
        && let Some(hit) = chain.find_file(p)
    {
        return Some(FailingSourceAttribution::new(
            hit,
            AttributionRule::FileBySource,
        ));
    }

    match FigmentNameTag::classify(md.name.as_ref()) {
        Some(FigmentNameTag::Format(tag)) => {
            if let Some(hit) = chain.find_file(tag.path) {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::FileByMetadataName,
                ));
            }
        }
        Some(FigmentNameTag::Env(env_tag)) => {
            if let EnvMetadataTag::Prefixed(prefix_upper) = env_tag
                && let Some(hit) = chain.find_env_by_prefix(prefix_upper)
            {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::EnvByPrefix,
                ));
            }
            if let Some(only) = chain.unique_of_kind(ConfigSourceKind::Env) {
                return Some(FailingSourceAttribution::new(
                    only,
                    AttributionRule::EnvByUniqueness,
                ));
            }
        }
        None => {}
    }

    if matches!(source_tag, Some(FigmentSourceTag::Code(_)))
        && let Some(only) = chain.unique_of_kind(ConfigSourceKind::Defaults)
    {
        return Some(FailingSourceAttribution::new(
            only,
            AttributionRule::DefaultsByCodeUniqueness,
        ));
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
    /// Strict superset of the tag-side septet [`Self::is_not_found`] /
    /// [`Self::is_parse`] / [`Self::is_watch`] / [`Self::is_io`] /
    /// [`Self::is_figment`] / [`Self::is_extract`] /
    /// [`Self::is_validation`]: each `is_X()` is
    /// `self.kind() == ShikumiErrorKind::X`. The seven predicates
    /// remain as convenience accessors; new code that needs to
    /// distinguish more than one kind should prefer this one accessor
    /// over a chain of predicates.
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
            Self::Validation(_) => ShikumiErrorKind::Validation,
        }
    }

    /// Returns `true` if this is a `NotFound` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::NotFound`.
    ///
    /// Tag-side sibling predicate over the closed seven-way
    /// [`ShikumiError`] variant space. Peer of [`Self::is_parse`] /
    /// [`Self::is_watch`] / [`Self::is_io`] / [`Self::is_figment`] /
    /// [`Self::is_extract`] / [`Self::is_validation`] — the full
    /// tag-side septet mirroring the kind-side septet on
    /// [`ShikumiErrorKind::is_not_found`] et al. Pointwise-agreement
    /// bridge with the kind-side predicate is pinned by
    /// [`tests::shikumi_error_is_not_found_agrees_with_shikumi_error_kind_is_not_found_pointwise`];
    /// the closed-septet partition on the tag-side (exactly one of the
    /// seven predicates holds on every constructed error) is pinned by
    /// [`tests::shikumi_error_predicates_are_a_closed_septet_partition`].
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::NotFound)
    }

    /// Returns `true` if this is a `Parse` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Parse`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    #[must_use]
    pub fn is_parse(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Parse)
    }

    /// Returns `true` if this is a `Watch` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Watch`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    #[must_use]
    pub fn is_watch(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Watch)
    }

    /// Returns `true` if this is an `Io` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Io`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Io)
    }

    /// Returns `true` if this is a `Figment` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Figment`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Tag-side refinement of [`Self::is_figment_bearing`] — one of
    /// the two figment-bearing corners
    /// (`self.is_figment() || self.is_extract() ==
    /// self.kind().is_figment_bearing()` pointwise, pinned by
    /// [`tests::shikumi_error_figment_extract_siblings_partition_is_figment_bearing`]).
    #[must_use]
    pub fn is_figment(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Figment)
    }

    /// Returns `true` if this is an `Extract` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Extract`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Tag-side refinement of [`Self::is_figment_bearing`] — the
    /// other figment-bearing corner, peer of [`Self::is_figment`].
    #[must_use]
    pub fn is_extract(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Extract)
    }

    /// Returns `true` if this is a `Validation` error. Convenience
    /// over [`Self::kind`]; equivalent to
    /// `self.kind() == ShikumiErrorKind::Validation`. Tag-side
    /// sibling predicate; see [`Self::is_not_found`] for the full
    /// contract.
    #[must_use]
    pub fn is_validation(&self) -> bool {
        matches!(self.kind(), ShikumiErrorKind::Validation)
    }

    /// True iff this error's kind carries a boxed [`figment::Error`]
    /// payload — the tag-side view of
    /// [`ShikumiErrorKind::is_figment_bearing`] one altitude down.
    ///
    /// Convenience over [`Self::kind`]; equivalent to
    /// `self.kind().is_figment_bearing()`. Consumers holding the
    /// borrowed error stop routing through the kind projection at
    /// the two figment-bearing corners
    /// ([`Self::Figment`] / [`Self::Extract`]) named at the type level.
    #[must_use]
    pub fn is_figment_bearing(&self) -> bool {
        self.kind().is_figment_bearing()
    }

    /// True iff this error's kind does *not* wrap a
    /// [`figment::Error`] — [`Self::NotFound`], [`Self::Parse`],
    /// [`Self::Watch`], [`Self::Io`], [`Self::Validation`]; the
    /// tag-side view of [`ShikumiErrorKind::is_not_figment_bearing`]
    /// one altitude down.
    ///
    /// Convenience over [`Self::kind`]; equivalent to
    /// `self.kind().is_not_figment_bearing()` and to
    /// `!self.is_figment_bearing()`. Sibling of
    /// [`Self::is_figment_bearing`] on the other half of the closed
    /// binary partition over the figment-bearing meta-axis.
    ///
    /// Consumers routing on "no figment error to unbox" (a
    /// [`crate::ConfigStore::last_reload_error`] observer skipping
    /// the [`Self::field_path`] / [`Self::sources`] fetch, a
    /// diagnostic layer refusing to reach for
    /// [`figment::Error::path`] against a kind that cannot carry
    /// one, a telemetry counter keyed on the non-figment-bearing
    /// half of the partition) name the answer at the tag altitude
    /// without a `!self.is_figment_bearing()` negation site or a
    /// re-derived `matches!(err, ShikumiError::NotFound { .. } | …)`
    /// against five specific variants. Adding a sixth non-figment-
    /// bearing variant lands at the kind-side match in
    /// [`ShikumiErrorKind::is_figment_bearing`] alone; both tag-side
    /// forwarders (this and [`Self::is_figment_bearing`]) pick the
    /// new classification up by construction.
    ///
    /// Kind-side/tag-side agreement is a structural law:
    /// `err.is_not_figment_bearing() ==
    ///  err.kind().is_not_figment_bearing()` for every
    /// [`ShikumiError`], pinned pointwise by
    /// [`tests::shikumi_error_is_not_figment_bearing_agrees_with_kind_is_not_figment_bearing_pointwise`].
    /// Complement identity with [`Self::is_figment_bearing`] —
    /// `err.is_not_figment_bearing() == !err.is_figment_bearing()`
    /// pointwise on every variant — is pinned by
    /// [`tests::shikumi_error_is_not_figment_bearing_is_complement_of_is_figment_bearing_pointwise`].
    /// The two sibling predicates form a closed disjoint binary
    /// partition of the [`ShikumiError`] construction table — every
    /// captured error satisfies exactly one, none satisfies both,
    /// none satisfies neither — pinned by
    /// [`tests::shikumi_error_figment_bearing_predicates_are_a_closed_binary_partition`].
    #[must_use]
    pub fn is_not_figment_bearing(&self) -> bool {
        self.kind().is_not_figment_bearing()
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

    /// The offending field path rendered as a single `.`-joined dotted
    /// key — the operator-facing form of [`Self::field_path`].
    ///
    /// Tri-state mirror of [`Self::field_path`], preserving the same
    /// `None` / `Some(empty)` / `Some(non-empty)` distinction at the
    /// rendered-string layer:
    /// - `None` for variants that do not wrap a figment error
    ///   ([`Self::Parse`], [`Self::NotFound`], [`Self::Watch`],
    ///   [`Self::Io`]) — figment never had a field to localize.
    /// - `Some("")` when figment did not localize the offending field
    ///   (a top-level type mismatch, or an error reported without a key
    ///   context) — distinct from `None`, matching the empty-slice arm
    ///   of [`Self::field_path`].
    /// - `Some("options.padding")` when figment localized a nested key.
    ///
    /// Routes through the same [`dotted_field_path`] join the
    /// [`Self::Extract`] `Display` impl uses, so a consumer building its
    /// own diagnostic (miette label, structured-log field, attestation
    /// manifest entry) renders the offending field byte-identically to
    /// the embedded display segment — no per-site `path.join(".")`. Pairs
    /// with [`Self::failing_source`] (which layer) and
    /// [`Self::field_path`] (raw segments) to complete the programmatic
    /// (which-field × which-layer) error-path-fidelity surface.
    ///
    /// Mirrored on the cross-thread observable form by
    /// [`crate::ReloadFailure::field_path_dotted`].
    #[must_use]
    pub fn field_path_dotted(&self) -> Option<String> {
        self.field_path().map(dotted_field_path)
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
    /// produces a coordinate cell in the 21-cell product cube
    /// [`ErrorLocalizationCoordinates::ALL`], and the produced cell
    /// always satisfies [`ErrorLocalizationCoordinates::is_realizable`]
    /// (pinned by
    /// `shikumi_error_error_localization_coordinates_returns_realizable_cell`
    /// over the canonical construction-table surface). The 12
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

/// Placeholder message body for the canonical "synthetic non-`Extract`
/// [`ShikumiError`] for typed-projection tests".
///
/// One source of truth for the arbitrary short string every test in
/// `error.rs`, `reload.rs`, and `observatory.rs` used to hand-inline as
/// `ShikumiError::Parse("x".to_owned())` when it needed a non-`Extract`
/// error class to exercise the `sources() == None` /
/// `field_path() == None` / `failing_source() == None` /
/// `failing_attribution() == None` / `kind() == Parse` /
/// `attribution_confidence() == None` / `layer_kind() == None` axes of
/// the accessor / envelope surface. Value is meaningless — the tests key
/// on the closed-enum classification and the accessor `None`s, not the
/// message body — but pinned to `"x"` for byte-compatibility with the
/// forty pre-lift call sites.
///
/// Peer of [`crate::source::SYNTHETIC_TEST_MESSAGE`] on the
/// `figment::Error` / [`crate::ReloadFailure::message`] side of the same
/// shared test-synthesis substrate axis. Pinned by the value pin
/// [`tests::synthetic_parse_message_is_x`] and the round-trip pin
/// [`tests::synthetic_parse_error_is_parse_variant_with_shared_message`]
/// (both on the helper's output shape) so a future placeholder change
/// lands at ONE named site and every test-side call site inherits the
/// new placeholder by construction.
#[cfg(test)]
pub(crate) const SYNTHETIC_PARSE_MESSAGE: &str = "x";

/// Test-only helper: synthesize a [`ShikumiError::Parse`] carrying the
/// shared [`SYNTHETIC_PARSE_MESSAGE`] body.
///
/// One source of truth for the previously-40-site byte-identical pattern
/// `ShikumiError::Parse("x".to_owned())` (27 in `reload.rs::tests`,
/// 7 in `observatory.rs::tests`, 6 in `error.rs::tests`), used
/// throughout the crate as the canonical "non-`Extract` synthetic error
/// class" — one whose [`ShikumiError::sources`] /
/// [`ShikumiError::field_path`] / [`ShikumiError::failing_source`] /
/// [`ShikumiError::failing_attribution`] accessors all return `None`,
/// whose [`ShikumiError::kind`] is [`ShikumiErrorKind::Parse`], and
/// whose projection onto [`crate::ReloadFailure`] yields the
/// fully-unattributed envelope shape.
///
/// Before this helper, the compiler enforced nothing between those
/// forty literals. Today [`ShikumiError::Parse`] is `Parse(String)`;
/// a future shape change — a second tuple field (e.g. `Parse(String,
/// FileSpan)` for a per-line span), a reshape to a struct-like variant
/// with source context, or a rename — would have failed to compile at
/// each of the forty open-coded call sites in lockstep, one recompile
/// per fix, forty paired edits before the accessor / envelope test grid
/// could observe the new shape. Routing every synthetic through this
/// helper collapses the drift class: a future shape change lands at
/// ONE named site (this fn's body) and every one of the forty call
/// sites inherits the new shape by construction.
///
/// Peer of [`crate::source::synthetic_env_metadata_error`] on the
/// name-axis synthetic-substrate boundary. Pinned by
/// [`tests::synthetic_parse_error_is_parse_variant_with_shared_message`]
/// (round-trip pin) plus per-file source-text pins
/// (`error_tests_route_synth_parse_through_synthetic_parse_error` +
/// the sibling pins in `reload.rs::tests` and `observatory.rs::tests`)
/// so a future re-inlining at a call site fires before the substrate
/// drifts.
#[cfg(test)]
#[must_use]
pub(crate) fn synthetic_parse_error() -> ShikumiError {
    ShikumiError::Parse(SYNTHETIC_PARSE_MESSAGE.to_owned())
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
    fn synthetic_parse_message_is_x() {
        // Value pin on the shared placeholder for the "synthetic
        // non-`Extract` `ShikumiError` for typed-projection tests"
        // universe. Peer of `source.rs::tests::synthetic_test_message_is_synth`
        // on the ShikumiError side of the same substrate axis.
        assert_eq!(super::SYNTHETIC_PARSE_MESSAGE, "x");
    }

    #[test]
    fn synthetic_parse_error_is_parse_variant_with_shared_message() {
        // Round-trip pin on the shared helper's output shape. Every
        // accessor the forty pre-lift call sites keyed on is exercised
        // here: kind() classifies to Parse, sources()/field_path()/
        // failing_source()/failing_attribution() all return None, and
        // the rendered display leads with the "config parse error: "
        // prefix followed by the shared placeholder body. A future
        // change to `synthetic_parse_error` that broke any of these
        // invariants (a Parse-variant shape change, a placeholder
        // rename, a wrong variant selection) fires here rather than at
        // one of the forty call sites the helper replaces.
        let err = super::synthetic_parse_error();
        assert_eq!(err.kind(), ShikumiErrorKind::Parse);
        assert!(
            matches!(&err, ShikumiError::Parse(s) if s == super::SYNTHETIC_PARSE_MESSAGE),
            "helper must return ShikumiError::Parse(SYNTHETIC_PARSE_MESSAGE)"
        );
        assert!(err.sources().is_none());
        assert!(err.field_path().is_none());
        assert!(err.failing_source().is_none());
        assert!(err.failing_attribution().is_none());
        assert_eq!(
            err.to_string(),
            format!("config parse error: {}", super::SYNTHETIC_PARSE_MESSAGE),
        );
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
        assert!(super::synthetic_parse_error().sources().is_none());
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
        assert!(super::synthetic_parse_error().field_path().is_none());
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

    /// Build a real extraction failure whose offending key is nested two
    /// levels deep, so figment localizes a multi-segment path
    /// (`["options", "padding"]`) and the `.`-join is exercised.
    fn extract_error_with_nested_field_path() -> ShikumiError {
        use crate::provider::ProviderChain;
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        struct Inner {
            #[allow(dead_code)]
            padding: u32,
        }
        #[derive(Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            options: Inner,
        }

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("nested.yaml");
        std::fs::write(&file, "options:\n  padding: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        drop(dir);
        err
    }

    // ---- field_path_dotted() tests ----

    #[test]
    fn field_path_dotted_none_for_non_figment_variants() {
        assert!(super::synthetic_parse_error().field_path_dotted().is_none());
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .field_path_dotted()
            .is_none()
        );
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let io_err: ShikumiError = io.into();
        assert!(io_err.field_path_dotted().is_none());
    }

    #[test]
    fn field_path_dotted_some_empty_for_unlocalized_extract() {
        // Figment-bearing but no localized field → Some("") (distinct
        // from the None of non-figment variants), mirroring the
        // Some(&[]) arm of field_path().
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        assert_eq!(err.field_path_dotted().as_deref(), Some(""));
    }

    #[test]
    fn field_path_dotted_joins_single_segment() {
        let err = extract_error_with_typed_field_path();
        assert_eq!(err.field_path_dotted().as_deref(), Some("count"));
    }

    #[test]
    fn field_path_dotted_joins_nested_segments_with_dot() {
        let err = extract_error_with_nested_field_path();
        assert_eq!(
            err.field_path_dotted().as_deref(),
            Some("options.padding"),
            "nested key must render dotted"
        );
    }

    #[test]
    fn field_path_dotted_matches_embedded_display_segment() {
        // The programmatic accessor and the Display impl share one join
        // helper — the rendered " at field `...`" segment must quote
        // exactly the dotted string the accessor returns.
        let err = extract_error_with_nested_field_path();
        let dotted = err.field_path_dotted().expect("localized");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("at field `{dotted}`")),
            "display segment must quote the accessor's dotted path; got: {msg}"
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
        assert!(super::synthetic_parse_error().failing_source().is_none());
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
        let err = ShikumiError::Extract {
            sources: vec![],
            error: crate::source::synthetic_field_path_error("window.size"),
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
        let mut e = figment::Error::from(crate::source::SYNTHETIC_TEST_MESSAGE.to_owned());
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
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
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
            error: crate::source::synthetic_env_metadata_error("UNRELATED_"),
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
            error: crate::source::synthetic_env_metadata_error(""),
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
            error: crate::source::synthetic_env_metadata_error("BORROWED_"),
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
        let mut e = figment::Error::from(crate::source::SYNTHETIC_TEST_MESSAGE.to_owned());
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
    fn attribution_confidence_is_exact_true_only_for_exact() {
        // Per-variant polarity pin on the sibling predicate. Exact is
        // the only cell that satisfies is_exact; the pin fires if a
        // future refactor flips the polarity (e.g. matches!(self,
        // Self::Fallback)) or widens the cell (e.g. a landed
        // Heuristic variant silently rolling into the exact half).
        // Mirror of format_has_shikumi_provider_lisp_and_nix_only on
        // the format-provenance altitude — same discipline applied
        // to the confidence altitude.
        assert!(AttributionConfidence::Exact.is_exact());
        assert!(!AttributionConfidence::Fallback.is_exact());
    }

    #[test]
    fn attribution_confidence_is_fallback_true_only_for_fallback() {
        // Per-variant polarity pin on the sibling predicate's other
        // half. Fallback is the only cell that satisfies is_fallback.
        // Mirror of format_has_figment_builtin_provider_yaml_and_toml_only.
        assert!(AttributionConfidence::Fallback.is_fallback());
        assert!(!AttributionConfidence::Exact.is_fallback());
    }

    #[test]
    fn attribution_confidence_predicates_are_a_closed_binary_partition() {
        // The two sibling predicates form a closed binary partition
        // over AttributionConfidence::ALL: every variant satisfies
        // exactly one, none satisfy neither, none satisfy both. This
        // is the confidence-altitude peer of the format-altitude
        // format_provider_class_predicates_are_a_closed_binary_partition
        // pin. A future tertiary confidence variant (e.g. Heuristic)
        // landing would fail this test — by design: the new class
        // must declare its own predicate and its own partition arm
        // rather than silently landing under the negation of one of
        // the existing two.
        for c in AttributionConfidence::ALL.iter().copied() {
            assert_ne!(
                c.is_exact(),
                c.is_fallback(),
                "confidence is binary; the two predicates must disagree pointwise on {c:?}",
            );
        }
        // Cover check: every variant satisfies at least one predicate
        // (rules out an added variant that neither predicate names).
        for c in AttributionConfidence::ALL.iter().copied() {
            assert!(
                c.is_exact() || c.is_fallback(),
                "closed binary partition: {c:?} must satisfy one of is_exact / is_fallback",
            );
        }
    }

    #[test]
    fn attribution_rule_is_exact_agrees_with_confidence_is_exact() {
        // The rule-altitude predicate and the confidence-altitude
        // predicate on the same corner (Exact) must agree pointwise
        // across AttributionRule::ALL — the rule-altitude peer is a
        // thin lift of self.confidence().is_exact(), and the two
        // entry points cannot drift. Mirror of the format-altitude
        // format_has_figment_builtin_provider_agrees_with_provenance_is_figment_builtin
        // pin. A future regression that re-inlines matches!(...) on
        // the rule side would still pass today because the polarity
        // still agrees; this pin is loud specifically when
        // AttributionConfidence::is_exact's polarity flips — the
        // rule-side must follow.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_exact(),
                rule.confidence().is_exact(),
                "is_exact must route through confidence().is_exact() on {rule:?}",
            );
            assert_eq!(
                rule.is_exact(),
                rule.confidence() == AttributionConfidence::Exact,
                "is_exact must agree with confidence == Exact on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_fallback_agrees_with_confidence_is_fallback() {
        // Mirror of the Exact-corner routing pin, on the Fallback
        // corner. Same rationale: the polarity of the (exact,
        // fallback) partition is defined once at the confidence
        // altitude; the rule-altitude convenience follows.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_fallback(),
                rule.confidence().is_fallback(),
                "is_fallback must route through confidence().is_fallback() on {rule:?}",
            );
            assert_eq!(
                rule.is_fallback(),
                rule.confidence() == AttributionConfidence::Fallback,
                "is_fallback must agree with confidence == Fallback on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_confidence_and_confidence_predicates_are_const_callable() {
        // Weld the const-callability of the (rule → confidence)
        // projection and its two routed sibling predicates
        // (`AttributionRule::confidence`, `AttributionRule::is_exact`,
        // `AttributionRule::is_fallback`) at compile time. Assigning
        // the results to `const` bindings pins const-ness at THIS line,
        // so the moment any of the three methods (or the routed
        // downstream `AttributionConfidence::is_exact`
        // / `is_fallback`) stops being `const`-callable — a future edit
        // that reaches for a non-const std helper anywhere in the
        // cascade, or a future variant that lands with a data-carrying
        // payload projected through a non-const constructor — the pin
        // fails to compile before the drift can reach downstream
        // consumers that assumed const-ness through the type.
        //
        // Direct peer of the const-callability seals on the borrowed
        // figment-metadata triple: the kind-side
        // `AttributionConfidence::is_exact` / `is_fallback` binary
        // (commit `5c2add4`, kind altitude) plus the tag-side
        // routing here (this file's rule altitude) mirror the
        // `FigmentSourceTag` / `FigmentSourceKind` (commit `22b705a`),
        // `FigmentNameTag` / `FigmentNameTagKind` (commit `41ca5ca`),
        // and `EnvMetadataTag` / `EnvMetadataTagKind` (commit `d8db91f`)
        // tag/kind pair seals — every closed binary confidence-shape
        // projection over the closed rule quintet now carries a
        // symmetric const-callability seal end-to-end.
        //
        // All five `AttributionRule` variants are data-free, so every
        // `AttributionRule::VAR` literal accepts `const` position
        // directly (no `Path::new` / `String` payload workaround as
        // needed on `FigmentSourceTag::Format` / `FigmentNameTag::Format`
        // per rust-lang/rust#143874). Consequently every cell of the
        // 5×3 (variant × cascade-step) grid welds directly through
        // `const` bindings.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const C_FBS: AttributionConfidence = R_FBS.confidence();
        const C_FBM: AttributionConfidence = R_FBM.confidence();
        const C_EBP: AttributionConfidence = R_EBP.confidence();
        const C_EBU: AttributionConfidence = R_EBU.confidence();
        const C_DBCU: AttributionConfidence = R_DBCU.confidence();

        const IE_FBS: bool = R_FBS.is_exact();
        const IE_FBM: bool = R_FBM.is_exact();
        const IE_EBP: bool = R_EBP.is_exact();
        const IE_EBU: bool = R_EBU.is_exact();
        const IE_DBCU: bool = R_DBCU.is_exact();

        const IF_FBS: bool = R_FBS.is_fallback();
        const IF_FBM: bool = R_FBM.is_fallback();
        const IF_EBP: bool = R_EBP.is_fallback();
        const IF_EBU: bool = R_EBU.is_fallback();
        const IF_DBCU: bool = R_DBCU.is_fallback();

        assert!(matches!(C_FBS, AttributionConfidence::Exact));
        assert!(matches!(C_FBM, AttributionConfidence::Exact));
        assert!(matches!(C_EBP, AttributionConfidence::Exact));
        assert!(matches!(C_EBU, AttributionConfidence::Fallback));
        assert!(matches!(C_DBCU, AttributionConfidence::Fallback));

        assert!(IE_FBS);
        assert!(IE_FBM);
        assert!(IE_EBP);
        assert!(!IE_EBU);
        assert!(!IE_DBCU);

        assert!(!IF_FBS);
        assert!(!IF_FBM);
        assert!(!IF_EBP);
        assert!(IF_EBU);
        assert!(IF_DBCU);
    }

    // ---- AttributionRule::EXACT / FALLBACK slice constants ----
    //
    // Six pins mirror the per-half meta-partition slice-constant
    // discipline that shipped in `9dad33d`
    // (`FieldPathLocalization::APPLICABLE / NOT_APPLICABLE`), `e45018d`
    // (`ShikumiErrorKind::FIGMENT_BEARING / NOT_FIGMENT_BEARING`),
    // `2013269` (`Format::FEATURE_GATED / ALWAYS_AVAILABLE`), and the
    // earlier closed-binary landings on `AttributionAxis`,
    // `AttributionConfidence`, `FormatProvenance`, `SecretRefShape`,
    // `PartitionFace`, `OutputFormat`, `EnvMetadataTagKind`,
    // `FigmentNameTagKind`, `ConfigTierKind`, `ConfigSourceKind`,
    // `SecretOperation`, `SecretBackendKind`, and `SecretClientKind` —
    // applied here to the five-way attribution-rule axis's
    // (exact × fallback) 3/2 compound-polarity meta-partition.
    // Directly nominated by `9dad33d`'s "future beneficiary (c)" as the
    // next rung of the same discipline.
    #[test]
    fn attribution_rule_exact_slice_agrees_with_is_exact_predicate() {
        // Bidirectional weld between the slice literal
        // `AttributionRule::EXACT` and the boolean predicate
        // `AttributionRule::is_exact` on the (exact × fallback)
        // confidence polarity axis. Every slice entry satisfies the
        // exact pole (and its complement `!is_fallback`), and every
        // ALL cell agrees on membership under the boolean predicate.
        // Idiom-peer of
        // `field_path_localization_applicable_slice_agrees_with_is_applicable_predicate`
        // (`9dad33d`) — the two independent declaration surfaces
        // (slice literal + boolean predicate) diverge at THIS pin on
        // the first shape where they disagree, before a consumer that
        // reads one altitude but not the other can observe the drift.
        for rule in AttributionRule::EXACT.iter().copied() {
            assert!(
                rule.is_exact(),
                "AttributionRule::EXACT entry {rule:?} must satisfy is_exact()",
            );
            assert!(
                !rule.is_fallback(),
                "AttributionRule::EXACT entry {rule:?} must NOT satisfy is_fallback()",
            );
        }
        for rule in AttributionRule::FALLBACK.iter().copied() {
            assert!(
                rule.is_fallback(),
                "AttributionRule::FALLBACK entry {rule:?} must satisfy is_fallback()",
            );
            assert!(
                !rule.is_exact(),
                "AttributionRule::FALLBACK entry {rule:?} must NOT satisfy is_exact()",
            );
        }
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                AttributionRule::EXACT.contains(&rule),
                rule.is_exact(),
                "EXACT membership must agree with is_exact() on AttributionRule::{rule:?}",
            );
            assert_eq!(
                AttributionRule::FALLBACK.contains(&rule),
                rule.is_fallback(),
                "FALLBACK membership must agree with is_fallback() on AttributionRule::{rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_exact_and_fallback_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `EXACT.len() + FALLBACK.len() == ALL.len()` at the slice
        // altitude on the attribution-rule axis. Idiom-peer of
        // `field_path_localization_applicable_and_not_applicable_slices_partition_all`
        // (`9dad33d`) — a variant landing on one slice AND the other,
        // or on neither, breaks the partition here before any consumer
        // that reasons about the polarity as a covering meta-partition
        // observes the drift.
        for rule in AttributionRule::EXACT {
            assert!(
                !AttributionRule::FALLBACK.contains(rule),
                "AttributionRule::{rule:?} appears in BOTH EXACT and FALLBACK",
            );
        }
        for rule in AttributionRule::ALL {
            let in_exact = AttributionRule::EXACT.contains(rule);
            let in_fallback = AttributionRule::FALLBACK.contains(rule);
            assert!(
                in_exact || in_fallback,
                "AttributionRule::{rule:?} is in NEITHER EXACT nor FALLBACK",
            );
            assert!(
                !(in_exact && in_fallback),
                "AttributionRule::{rule:?} is in BOTH EXACT and FALLBACK",
            );
        }
        assert_eq!(
            AttributionRule::EXACT.len() + AttributionRule::FALLBACK.len(),
            AttributionRule::ALL.len(),
            "EXACT and FALLBACK slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_rule_exact_and_fallback_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in AttributionRule::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted the exact pole (e.g. [EnvByPrefix,
        // FileBySource, FileByMetadataName] instead of the
        // ALL-declaration order [FileBySource, FileByMetadataName,
        // EnvByPrefix]) diverges at THIS pin. Idiom-peer of
        // `field_path_localization_applicable_and_not_applicable_slices_preserve_all_order`
        // (`9dad33d`).
        let exact_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_exact())
            .collect();
        assert_eq!(
            exact_from_all,
            AttributionRule::EXACT.to_vec(),
            "EXACT must be ALL-filtered by is_exact in declaration order",
        );
        let fallback_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_fallback())
            .collect();
        assert_eq!(
            fallback_from_all,
            AttributionRule::FALLBACK.to_vec(),
            "FALLBACK must be ALL-filtered by is_fallback in declaration order",
        );
    }

    #[test]
    fn attribution_rule_exact_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into EXACT, an accidental re-add of an already-present cell
        // into FALLBACK) fails at THIS pin before drifting through any
        // consumer that iterates the slice expecting a set.
        for slice in [AttributionRule::EXACT, AttributionRule::FALLBACK] {
            let mut seen: Vec<AttributionRule> = Vec::with_capacity(slice.len());
            for rule in slice {
                assert!(
                    !seen.contains(rule),
                    "AttributionRule slice {slice:?} contains duplicate entry {rule:?}",
                );
                seen.push(*rule);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn attribution_rule_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionRule::ALL — i.e.,
        // `EXACT.len() == ALL.iter().filter(is_exact).count()` and
        // `FALLBACK.len() == ALL.iter().filter(is_fallback).count()`
        // — the cardinality projection at the slice altitude agrees
        // with the boolean-altitude projection on both halves.
        // Concrete positions today: 3 exact + 2 fallback = 5 = ALL.
        // Idiom-peer of
        // `field_path_localization_applicable_and_not_applicable_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`9dad33d`).
        let exact_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_exact())
            .count();
        let fallback_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_fallback())
            .count();
        assert_eq!(
            AttributionRule::EXACT.len(),
            exact_count,
            "EXACT.len() must match the is_exact count on ALL",
        );
        assert_eq!(
            AttributionRule::FALLBACK.len(),
            fallback_count,
            "FALLBACK.len() must match the is_fallback count on ALL",
        );
        assert_eq!(AttributionRule::EXACT.len(), 3);
        assert_eq!(AttributionRule::FALLBACK.len(), 2);
        assert_eq!(AttributionRule::ALL.len(), 5);
    }

    #[test]
    fn attribution_rule_exact_and_fallback_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `field_path_localization_applicable_and_not_applicable_slices_are_const_addressable`
        // (`9dad33d`).
        const EXACT_LEN: usize = AttributionRule::EXACT.len();
        const FALLBACK_LEN: usize = AttributionRule::FALLBACK.len();
        const ALL_LEN: usize = AttributionRule::ALL.len();
        assert_eq!(EXACT_LEN, 3);
        assert_eq!(FALLBACK_LEN, 2);
        assert_eq!(EXACT_LEN + FALLBACK_LEN, ALL_LEN);
    }

    // Six pins mirror the per-half meta-partition slice-constant
    // discipline that shipped for AttributionRule's own binary
    // (exact × fallback) confidence projection (`19c11d2`), applied here
    // to the SAME axis's orthogonal ternary (file × env × defaults) 2/2/1
    // layer-kind projection. Directly nominated by `19c11d2`'s "future
    // beneficiary (c)" as the next rung of the discipline on this axis.
    #[test]
    fn attribution_rule_layer_slices_agree_with_layer_predicates() {
        // Three-way agreement pin across the (file × env × defaults)
        // ternary layer-kind meta-partition. Every LAYER_FILE entry
        // satisfies is_file_layer and neither is_env_layer nor
        // is_defaults_layer; every LAYER_ENV entry satisfies
        // is_env_layer alone; every LAYER_DEFAULTS entry satisfies
        // is_defaults_layer alone. Every AttributionRule::ALL cell
        // agrees on membership under each of the three boolean
        // predicates. The two independent declaration surfaces (slice
        // literals + boolean predicates) diverge at THIS pin on the
        // first shape where they disagree, before a consumer that reads
        // one altitude but not the other can observe the drift. Ternary
        // peer of
        // `attribution_rule_exact_slice_agrees_with_is_exact_predicate`
        // (`19c11d2`) on the confidence projection of the same axis.
        for rule in AttributionRule::LAYER_FILE.iter().copied() {
            assert!(
                rule.is_file_layer(),
                "AttributionRule::LAYER_FILE entry {rule:?} must satisfy is_file_layer()",
            );
            assert!(
                !rule.is_env_layer(),
                "AttributionRule::LAYER_FILE entry {rule:?} must NOT satisfy is_env_layer()",
            );
            assert!(
                !rule.is_defaults_layer(),
                "AttributionRule::LAYER_FILE entry {rule:?} must NOT satisfy is_defaults_layer()",
            );
        }
        for rule in AttributionRule::LAYER_ENV.iter().copied() {
            assert!(
                rule.is_env_layer(),
                "AttributionRule::LAYER_ENV entry {rule:?} must satisfy is_env_layer()",
            );
            assert!(
                !rule.is_file_layer(),
                "AttributionRule::LAYER_ENV entry {rule:?} must NOT satisfy is_file_layer()",
            );
            assert!(
                !rule.is_defaults_layer(),
                "AttributionRule::LAYER_ENV entry {rule:?} must NOT satisfy is_defaults_layer()",
            );
        }
        for rule in AttributionRule::LAYER_DEFAULTS.iter().copied() {
            assert!(
                rule.is_defaults_layer(),
                "AttributionRule::LAYER_DEFAULTS entry {rule:?} must satisfy is_defaults_layer()",
            );
            assert!(
                !rule.is_file_layer(),
                "AttributionRule::LAYER_DEFAULTS entry {rule:?} must NOT satisfy is_file_layer()",
            );
            assert!(
                !rule.is_env_layer(),
                "AttributionRule::LAYER_DEFAULTS entry {rule:?} must NOT satisfy is_env_layer()",
            );
        }
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                AttributionRule::LAYER_FILE.contains(&rule),
                rule.is_file_layer(),
                "LAYER_FILE membership must agree with is_file_layer() on AttributionRule::{rule:?}",
            );
            assert_eq!(
                AttributionRule::LAYER_ENV.contains(&rule),
                rule.is_env_layer(),
                "LAYER_ENV membership must agree with is_env_layer() on AttributionRule::{rule:?}",
            );
            assert_eq!(
                AttributionRule::LAYER_DEFAULTS.contains(&rule),
                rule.is_defaults_layer(),
                "LAYER_DEFAULTS membership must agree with is_defaults_layer() on AttributionRule::{rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_layer_slices_partition_all() {
        // Ternary partition invariant: the three per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `LAYER_FILE.len() + LAYER_ENV.len() + LAYER_DEFAULTS.len() ==
        // ALL.len()` at the slice altitude on the attribution-rule
        // axis's layer-kind projection. Ternary peer of
        // `attribution_rule_exact_and_fallback_slices_partition_all`
        // (`19c11d2`) on the binary confidence projection of the same
        // axis, and slice-altitude peer of
        // `attribution_rule_layer_predicates_are_a_closed_ternary_partition`
        // one altitude down. A variant landing on two slices or on
        // none breaks the partition here before any consumer that
        // reasons about the polarity as a covering meta-partition
        // observes the drift.
        for rule in AttributionRule::LAYER_FILE {
            assert!(
                !AttributionRule::LAYER_ENV.contains(rule),
                "AttributionRule::{rule:?} appears in BOTH LAYER_FILE and LAYER_ENV",
            );
            assert!(
                !AttributionRule::LAYER_DEFAULTS.contains(rule),
                "AttributionRule::{rule:?} appears in BOTH LAYER_FILE and LAYER_DEFAULTS",
            );
        }
        for rule in AttributionRule::LAYER_ENV {
            assert!(
                !AttributionRule::LAYER_DEFAULTS.contains(rule),
                "AttributionRule::{rule:?} appears in BOTH LAYER_ENV and LAYER_DEFAULTS",
            );
        }
        for rule in AttributionRule::ALL {
            let in_file = AttributionRule::LAYER_FILE.contains(rule);
            let in_env = AttributionRule::LAYER_ENV.contains(rule);
            let in_defaults = AttributionRule::LAYER_DEFAULTS.contains(rule);
            let held = usize::from(in_file) + usize::from(in_env) + usize::from(in_defaults);
            assert_eq!(
                held, 1,
                "AttributionRule::{rule:?} must appear in exactly one of LAYER_FILE / LAYER_ENV / LAYER_DEFAULTS (found in {held})",
            );
        }
        assert_eq!(
            AttributionRule::LAYER_FILE.len()
                + AttributionRule::LAYER_ENV.len()
                + AttributionRule::LAYER_DEFAULTS.len(),
            AttributionRule::ALL.len(),
            "LAYER_FILE + LAYER_ENV + LAYER_DEFAULTS slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_rule_layer_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in AttributionRule::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted the file pole (e.g.
        // [FileByMetadataName, FileBySource] instead of the
        // ALL-declaration order [FileBySource, FileByMetadataName])
        // diverges at THIS pin. Ternary peer of
        // `attribution_rule_exact_and_fallback_slices_preserve_all_order`
        // (`19c11d2`).
        let file_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_file_layer())
            .collect();
        assert_eq!(
            file_from_all,
            AttributionRule::LAYER_FILE.to_vec(),
            "LAYER_FILE must be ALL-filtered by is_file_layer in declaration order",
        );
        let env_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_env_layer())
            .collect();
        assert_eq!(
            env_from_all,
            AttributionRule::LAYER_ENV.to_vec(),
            "LAYER_ENV must be ALL-filtered by is_env_layer in declaration order",
        );
        let defaults_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_defaults_layer())
            .collect();
        assert_eq!(
            defaults_from_all,
            AttributionRule::LAYER_DEFAULTS.to_vec(),
            "LAYER_DEFAULTS must be ALL-filtered by is_defaults_layer in declaration order",
        );
    }

    #[test]
    fn attribution_rule_layer_slices_have_no_duplicates() {
        // No-duplicates pin on all three per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting through
        // any consumer that iterates the slice expecting a set. Ternary
        // peer of `attribution_rule_exact_slice_has_no_duplicates`
        // (`19c11d2`).
        for slice in [
            AttributionRule::LAYER_FILE,
            AttributionRule::LAYER_ENV,
            AttributionRule::LAYER_DEFAULTS,
        ] {
            let mut seen: Vec<AttributionRule> = Vec::with_capacity(slice.len());
            for rule in slice {
                assert!(
                    !seen.contains(rule),
                    "AttributionRule layer slice {slice:?} contains duplicate entry {rule:?}",
                );
                seen.push(*rule);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn attribution_rule_layer_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionRule::ALL — i.e.,
        // `LAYER_FILE.len() == ALL.iter().filter(is_file_layer).count()`
        // (and symmetric for the two siblings) — the cardinality
        // projection at the slice altitude agrees with the
        // boolean-altitude projection on all three halves. Concrete
        // positions today: 2 file + 2 env + 1 defaults = 5 = ALL.
        // Ternary peer of
        // `attribution_rule_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`19c11d2`).
        let file_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_file_layer())
            .count();
        let env_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_env_layer())
            .count();
        let defaults_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_defaults_layer())
            .count();
        assert_eq!(
            AttributionRule::LAYER_FILE.len(),
            file_count,
            "LAYER_FILE.len() must match the is_file_layer count on ALL",
        );
        assert_eq!(
            AttributionRule::LAYER_ENV.len(),
            env_count,
            "LAYER_ENV.len() must match the is_env_layer count on ALL",
        );
        assert_eq!(
            AttributionRule::LAYER_DEFAULTS.len(),
            defaults_count,
            "LAYER_DEFAULTS.len() must match the is_defaults_layer count on ALL",
        );
        assert_eq!(AttributionRule::LAYER_FILE.len(), 2);
        assert_eq!(AttributionRule::LAYER_ENV.len(), 2);
        assert_eq!(AttributionRule::LAYER_DEFAULTS.len(), 1);
        assert_eq!(AttributionRule::ALL.len(), 5);
    }

    #[test]
    fn attribution_rule_layer_slices_are_const_addressable() {
        // Const-time addressability pin: the three per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        // Ternary peer of
        // `attribution_rule_exact_and_fallback_slices_are_const_addressable`
        // (`19c11d2`).
        const FILE_LEN: usize = AttributionRule::LAYER_FILE.len();
        const ENV_LEN: usize = AttributionRule::LAYER_ENV.len();
        const DEFAULTS_LEN: usize = AttributionRule::LAYER_DEFAULTS.len();
        const ALL_LEN: usize = AttributionRule::ALL.len();
        assert_eq!(FILE_LEN, 2);
        assert_eq!(ENV_LEN, 2);
        assert_eq!(DEFAULTS_LEN, 1);
        assert_eq!(FILE_LEN + ENV_LEN + DEFAULTS_LEN, ALL_LEN);
    }

    // Six pins mirror the per-half meta-partition slice-constant
    // discipline that shipped for AttributionRule's own binary
    // (exact × fallback) confidence projection (`19c11d2`) and ternary
    // (file × env × defaults) layer-kind projection (`fae8271`), applied
    // here to the SAME axis's THIRD orthogonal projection — the binary
    // (metadata-source × metadata-name) 2/3 metadata-axis partition.
    // Directly nominated by `fae8271`'s "future beneficiary (c)" as the
    // next rung of the discipline on this axis, closing the third
    // projection after the confidence and layer-kind ones.
    #[test]
    fn attribution_rule_metadata_axis_slices_agree_with_metadata_axis_predicates() {
        // Bidirectional weld between the slice literals
        // `AttributionRule::METADATA_SOURCE_AXIS` /
        // `AttributionRule::METADATA_NAME_AXIS` and the boolean
        // predicates `AttributionRule::is_metadata_source_axis` /
        // `AttributionRule::is_metadata_name_axis` on the
        // (metadata-source × metadata-name) metadata-axis polarity.
        // Every slice entry satisfies its pole (and its complement), and
        // every ALL cell agrees on membership under each boolean
        // predicate. Binary peer of
        // `attribution_rule_layer_slices_agree_with_layer_predicates`
        // (`fae8271`) on the ternary layer-kind projection of the same
        // axis, and idiom-peer of
        // `attribution_rule_exact_slice_agrees_with_is_exact_predicate`
        // (`19c11d2`) on the binary confidence projection — the two
        // independent declaration surfaces (slice literal + boolean
        // predicate) diverge at THIS pin on the first shape where they
        // disagree, before a consumer that reads one altitude but not
        // the other can observe the drift.
        for rule in AttributionRule::METADATA_SOURCE_AXIS.iter().copied() {
            assert!(
                rule.is_metadata_source_axis(),
                "AttributionRule::METADATA_SOURCE_AXIS entry {rule:?} must satisfy is_metadata_source_axis()",
            );
            assert!(
                !rule.is_metadata_name_axis(),
                "AttributionRule::METADATA_SOURCE_AXIS entry {rule:?} must NOT satisfy is_metadata_name_axis()",
            );
        }
        for rule in AttributionRule::METADATA_NAME_AXIS.iter().copied() {
            assert!(
                rule.is_metadata_name_axis(),
                "AttributionRule::METADATA_NAME_AXIS entry {rule:?} must satisfy is_metadata_name_axis()",
            );
            assert!(
                !rule.is_metadata_source_axis(),
                "AttributionRule::METADATA_NAME_AXIS entry {rule:?} must NOT satisfy is_metadata_source_axis()",
            );
        }
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                AttributionRule::METADATA_SOURCE_AXIS.contains(&rule),
                rule.is_metadata_source_axis(),
                "METADATA_SOURCE_AXIS membership must agree with is_metadata_source_axis() on AttributionRule::{rule:?}",
            );
            assert_eq!(
                AttributionRule::METADATA_NAME_AXIS.contains(&rule),
                rule.is_metadata_name_axis(),
                "METADATA_NAME_AXIS membership must agree with is_metadata_name_axis() on AttributionRule::{rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint and
        // their union covers ALL. Direct application of the
        // meta-partition sum law
        // `METADATA_SOURCE_AXIS.len() + METADATA_NAME_AXIS.len() ==
        // ALL.len()` at the slice altitude on the attribution-rule axis's
        // metadata-axis projection. Binary peer of
        // `attribution_rule_exact_and_fallback_slices_partition_all`
        // (`19c11d2`) on the confidence projection of the same axis,
        // and slice-altitude peer of
        // `attribution_rule_metadata_axis_predicates_are_a_closed_binary_partition`
        // one altitude down. A variant landing on both slices or on
        // neither breaks the partition here before any consumer that
        // reasons about the polarity as a covering meta-partition
        // observes the drift.
        for rule in AttributionRule::METADATA_SOURCE_AXIS {
            assert!(
                !AttributionRule::METADATA_NAME_AXIS.contains(rule),
                "AttributionRule::{rule:?} appears in BOTH METADATA_SOURCE_AXIS and METADATA_NAME_AXIS",
            );
        }
        for rule in AttributionRule::ALL {
            let in_source = AttributionRule::METADATA_SOURCE_AXIS.contains(rule);
            let in_name = AttributionRule::METADATA_NAME_AXIS.contains(rule);
            assert!(
                in_source || in_name,
                "AttributionRule::{rule:?} is in NEITHER METADATA_SOURCE_AXIS nor METADATA_NAME_AXIS",
            );
            assert!(
                !(in_source && in_name),
                "AttributionRule::{rule:?} is in BOTH METADATA_SOURCE_AXIS and METADATA_NAME_AXIS",
            );
        }
        assert_eq!(
            AttributionRule::METADATA_SOURCE_AXIS.len() + AttributionRule::METADATA_NAME_AXIS.len(),
            AttributionRule::ALL.len(),
            "METADATA_SOURCE_AXIS and METADATA_NAME_AXIS slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_rule_metadata_axis_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its variants
        // in the SAME relative declaration order they appear in
        // AttributionRule::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted the source pole (e.g.
        // [DefaultsByCodeUniqueness, FileBySource] instead of the
        // ALL-declaration order [FileBySource,
        // DefaultsByCodeUniqueness]) diverges at THIS pin. Binary peer
        // of `attribution_rule_exact_and_fallback_slices_preserve_all_order`
        // (`19c11d2`).
        let source_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_metadata_source_axis())
            .collect();
        assert_eq!(
            source_from_all,
            AttributionRule::METADATA_SOURCE_AXIS.to_vec(),
            "METADATA_SOURCE_AXIS must be ALL-filtered by is_metadata_source_axis in declaration order",
        );
        let name_from_all: Vec<AttributionRule> = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_metadata_name_axis())
            .collect();
        assert_eq!(
            name_from_all,
            AttributionRule::METADATA_NAME_AXIS.to_vec(),
            "METADATA_NAME_AXIS must be ALL-filtered by is_metadata_name_axis in declaration order",
        );
    }

    #[test]
    fn attribution_rule_metadata_axis_slices_have_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice literals
        // are declared as sets under the discriminant `Eq` relation. A
        // future edit that accidentally double-lists a variant on one
        // half fails at THIS pin before drifting through any consumer
        // that iterates the slice expecting a set. Binary peer of
        // `attribution_rule_exact_slice_has_no_duplicates` (`19c11d2`).
        for slice in [
            AttributionRule::METADATA_SOURCE_AXIS,
            AttributionRule::METADATA_NAME_AXIS,
        ] {
            let mut seen: Vec<AttributionRule> = Vec::with_capacity(slice.len());
            for rule in slice {
                assert!(
                    !seen.contains(rule),
                    "AttributionRule metadata-axis slice {slice:?} contains duplicate entry {rule:?}",
                );
                seen.push(*rule);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionRule::ALL — i.e.,
        // `METADATA_SOURCE_AXIS.len() == ALL.iter().filter(is_metadata_source_axis).count()`
        // (and symmetric on METADATA_NAME_AXIS) — the cardinality
        // projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete positions
        // today: 2 source + 3 name = 5 = ALL. Binary peer of
        // `attribution_rule_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`19c11d2`).
        let source_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_metadata_source_axis())
            .count();
        let name_count = AttributionRule::ALL
            .iter()
            .copied()
            .filter(|r| r.is_metadata_name_axis())
            .count();
        assert_eq!(
            AttributionRule::METADATA_SOURCE_AXIS.len(),
            source_count,
            "METADATA_SOURCE_AXIS.len() must match the is_metadata_source_axis count on ALL",
        );
        assert_eq!(
            AttributionRule::METADATA_NAME_AXIS.len(),
            name_count,
            "METADATA_NAME_AXIS.len() must match the is_metadata_name_axis count on ALL",
        );
        assert_eq!(AttributionRule::METADATA_SOURCE_AXIS.len(), 2);
        assert_eq!(AttributionRule::METADATA_NAME_AXIS.len(), 3);
        assert_eq!(AttributionRule::ALL.len(), 5);
    }

    #[test]
    fn attribution_rule_metadata_axis_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Binary peer of
        // `attribution_rule_exact_and_fallback_slices_are_const_addressable`
        // (`19c11d2`).
        const SOURCE_LEN: usize = AttributionRule::METADATA_SOURCE_AXIS.len();
        const NAME_LEN: usize = AttributionRule::METADATA_NAME_AXIS.len();
        const ALL_LEN: usize = AttributionRule::ALL.len();
        assert_eq!(SOURCE_LEN, 2);
        assert_eq!(NAME_LEN, 3);
        assert_eq!(SOURCE_LEN + NAME_LEN, ALL_LEN);
    }

    #[test]
    fn attribution_rule_identity_slices_agree_with_identity_predicates() {
        // Five-way agreement pin across the (file_by_source ×
        // file_by_metadata_name × env_by_prefix × env_by_uniqueness ×
        // defaults_by_code_uniqueness) identity meta-partition. Every
        // ONLY_FILE_BY_SOURCE entry satisfies is_file_by_source and
        // none of the four sibling predicates; every
        // ONLY_FILE_BY_METADATA_NAME entry satisfies
        // is_file_by_metadata_name alone; … and so on across all five
        // halves. The two independent declaration surfaces (slice
        // literals + boolean predicates) diverge at THIS pin on the
        // first shape where they disagree, before a consumer that reads
        // one altitude but not the other can observe the drift.
        // Quinary peer of
        // `shikumi_error_kind_identity_slices_agree_with_identity_predicates`
        // (commit `6e74116`) two cells narrower.
        for r in AttributionRule::ONLY_FILE_BY_SOURCE.iter().copied() {
            assert!(
                r.is_file_by_source(),
                "ONLY_FILE_BY_SOURCE {r:?} must satisfy is_file_by_source"
            );
            assert!(
                !r.is_file_by_metadata_name(),
                "ONLY_FILE_BY_SOURCE {r:?} must NOT satisfy is_file_by_metadata_name"
            );
            assert!(
                !r.is_env_by_prefix(),
                "ONLY_FILE_BY_SOURCE {r:?} must NOT satisfy is_env_by_prefix"
            );
            assert!(
                !r.is_env_by_uniqueness(),
                "ONLY_FILE_BY_SOURCE {r:?} must NOT satisfy is_env_by_uniqueness"
            );
            assert!(
                !r.is_defaults_by_code_uniqueness(),
                "ONLY_FILE_BY_SOURCE {r:?} must NOT satisfy is_defaults_by_code_uniqueness"
            );
        }
        for r in AttributionRule::ONLY_FILE_BY_METADATA_NAME.iter().copied() {
            assert!(
                r.is_file_by_metadata_name(),
                "ONLY_FILE_BY_METADATA_NAME {r:?} must satisfy is_file_by_metadata_name"
            );
            assert!(
                !r.is_file_by_source(),
                "ONLY_FILE_BY_METADATA_NAME {r:?} must NOT satisfy is_file_by_source"
            );
            assert!(
                !r.is_env_by_prefix(),
                "ONLY_FILE_BY_METADATA_NAME {r:?} must NOT satisfy is_env_by_prefix"
            );
            assert!(
                !r.is_env_by_uniqueness(),
                "ONLY_FILE_BY_METADATA_NAME {r:?} must NOT satisfy is_env_by_uniqueness"
            );
            assert!(
                !r.is_defaults_by_code_uniqueness(),
                "ONLY_FILE_BY_METADATA_NAME {r:?} must NOT satisfy is_defaults_by_code_uniqueness"
            );
        }
        for r in AttributionRule::ONLY_ENV_BY_PREFIX.iter().copied() {
            assert!(
                r.is_env_by_prefix(),
                "ONLY_ENV_BY_PREFIX {r:?} must satisfy is_env_by_prefix"
            );
            assert!(
                !r.is_file_by_source(),
                "ONLY_ENV_BY_PREFIX {r:?} must NOT satisfy is_file_by_source"
            );
            assert!(
                !r.is_file_by_metadata_name(),
                "ONLY_ENV_BY_PREFIX {r:?} must NOT satisfy is_file_by_metadata_name"
            );
            assert!(
                !r.is_env_by_uniqueness(),
                "ONLY_ENV_BY_PREFIX {r:?} must NOT satisfy is_env_by_uniqueness"
            );
            assert!(
                !r.is_defaults_by_code_uniqueness(),
                "ONLY_ENV_BY_PREFIX {r:?} must NOT satisfy is_defaults_by_code_uniqueness"
            );
        }
        for r in AttributionRule::ONLY_ENV_BY_UNIQUENESS.iter().copied() {
            assert!(
                r.is_env_by_uniqueness(),
                "ONLY_ENV_BY_UNIQUENESS {r:?} must satisfy is_env_by_uniqueness"
            );
            assert!(
                !r.is_file_by_source(),
                "ONLY_ENV_BY_UNIQUENESS {r:?} must NOT satisfy is_file_by_source"
            );
            assert!(
                !r.is_file_by_metadata_name(),
                "ONLY_ENV_BY_UNIQUENESS {r:?} must NOT satisfy is_file_by_metadata_name"
            );
            assert!(
                !r.is_env_by_prefix(),
                "ONLY_ENV_BY_UNIQUENESS {r:?} must NOT satisfy is_env_by_prefix"
            );
            assert!(
                !r.is_defaults_by_code_uniqueness(),
                "ONLY_ENV_BY_UNIQUENESS {r:?} must NOT satisfy is_defaults_by_code_uniqueness"
            );
        }
        for r in AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS
            .iter()
            .copied()
        {
            assert!(
                r.is_defaults_by_code_uniqueness(),
                "ONLY_DEFAULTS_BY_CODE_UNIQUENESS {r:?} must satisfy is_defaults_by_code_uniqueness"
            );
            assert!(
                !r.is_file_by_source(),
                "ONLY_DEFAULTS_BY_CODE_UNIQUENESS {r:?} must NOT satisfy is_file_by_source"
            );
            assert!(
                !r.is_file_by_metadata_name(),
                "ONLY_DEFAULTS_BY_CODE_UNIQUENESS {r:?} must NOT satisfy is_file_by_metadata_name"
            );
            assert!(
                !r.is_env_by_prefix(),
                "ONLY_DEFAULTS_BY_CODE_UNIQUENESS {r:?} must NOT satisfy is_env_by_prefix"
            );
            assert!(
                !r.is_env_by_uniqueness(),
                "ONLY_DEFAULTS_BY_CODE_UNIQUENESS {r:?} must NOT satisfy is_env_by_uniqueness"
            );
        }
    }

    #[test]
    fn attribution_rule_identity_slices_partition_all() {
        // Quinary partition invariant: the five per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_FILE_BY_SOURCE.len() + ONLY_FILE_BY_METADATA_NAME.len()
        //  + ONLY_ENV_BY_PREFIX.len() + ONLY_ENV_BY_UNIQUENESS.len()
        //  + ONLY_DEFAULTS_BY_CODE_UNIQUENESS.len() == ALL.len()`.
        let identity_slices: [&[AttributionRule]; 5] = [
            AttributionRule::ONLY_FILE_BY_SOURCE,
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
            AttributionRule::ONLY_ENV_BY_PREFIX,
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for r in left.iter() {
                    assert!(
                        !right.contains(r),
                        "AttributionRule::{r:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for r in AttributionRule::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&r)))
                .sum();
            assert_eq!(
                held, 1,
                "AttributionRule::{r:?} must appear in exactly one identity \
                 slice (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            AttributionRule::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_rule_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in AttributionRule::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at THIS
        // pin.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<AttributionRule> = AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(AttributionRule::ONLY_FILE_BY_SOURCE, is_file_by_source);
        pin!(
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
            is_file_by_metadata_name
        );
        pin!(AttributionRule::ONLY_ENV_BY_PREFIX, is_env_by_prefix);
        pin!(
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
            is_env_by_uniqueness
        );
        pin!(
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS,
            is_defaults_by_code_uniqueness
        );
    }

    #[test]
    fn attribution_rule_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all five per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set.
        for slice in [
            AttributionRule::ONLY_FILE_BY_SOURCE,
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
            AttributionRule::ONLY_ENV_BY_PREFIX,
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS,
        ] {
            let mut seen: Vec<AttributionRule> = Vec::with_capacity(slice.len());
            for r in slice {
                assert!(
                    !seen.contains(r),
                    "AttributionRule identity slice {slice:?} contains \
                     duplicate entry {r:?}",
                );
                seen.push(*r);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn attribution_rule_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionRule::ALL — i.e.,
        // `ONLY_FILE_BY_SOURCE.len() == ALL.iter().filter(is_file_by_source).count()`
        // (and symmetric for the four siblings) — the cardinality
        // projection at the slice altitude agrees with the boolean-
        // altitude projection on all five halves. Concrete positions
        // today: 1 + 1 + 1 + 1 + 1 = 5 = ALL.
        let counts = [
            (
                "is_file_by_source",
                AttributionRule::ONLY_FILE_BY_SOURCE.len(),
                AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.is_file_by_source())
                    .count(),
            ),
            (
                "is_file_by_metadata_name",
                AttributionRule::ONLY_FILE_BY_METADATA_NAME.len(),
                AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.is_file_by_metadata_name())
                    .count(),
            ),
            (
                "is_env_by_prefix",
                AttributionRule::ONLY_ENV_BY_PREFIX.len(),
                AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.is_env_by_prefix())
                    .count(),
            ),
            (
                "is_env_by_uniqueness",
                AttributionRule::ONLY_ENV_BY_UNIQUENESS.len(),
                AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.is_env_by_uniqueness())
                    .count(),
            ),
            (
                "is_defaults_by_code_uniqueness",
                AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS.len(),
                AttributionRule::ALL
                    .iter()
                    .copied()
                    .filter(|r| r.is_defaults_by_code_uniqueness())
                    .count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(AttributionRule::ALL.len(), 5);
    }

    #[test]
    fn attribution_rule_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the five per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        const ONLY_FILE_BY_SOURCE_LEN: usize = AttributionRule::ONLY_FILE_BY_SOURCE.len();
        const ONLY_FILE_BY_METADATA_NAME_LEN: usize =
            AttributionRule::ONLY_FILE_BY_METADATA_NAME.len();
        const ONLY_ENV_BY_PREFIX_LEN: usize = AttributionRule::ONLY_ENV_BY_PREFIX.len();
        const ONLY_ENV_BY_UNIQUENESS_LEN: usize = AttributionRule::ONLY_ENV_BY_UNIQUENESS.len();
        const ONLY_DEFAULTS_BY_CODE_UNIQUENESS_LEN: usize =
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS.len();
        const ALL_LEN: usize = AttributionRule::ALL.len();
        assert_eq!(ONLY_FILE_BY_SOURCE_LEN, 1);
        assert_eq!(ONLY_FILE_BY_METADATA_NAME_LEN, 1);
        assert_eq!(ONLY_ENV_BY_PREFIX_LEN, 1);
        assert_eq!(ONLY_ENV_BY_UNIQUENESS_LEN, 1);
        assert_eq!(ONLY_DEFAULTS_BY_CODE_UNIQUENESS_LEN, 1);
        assert_eq!(
            ONLY_FILE_BY_SOURCE_LEN
                + ONLY_FILE_BY_METADATA_NAME_LEN
                + ONLY_ENV_BY_PREFIX_LEN
                + ONLY_ENV_BY_UNIQUENESS_LEN
                + ONLY_DEFAULTS_BY_CODE_UNIQUENESS_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn attribution_rule_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the three shipped compound-polarity
        // meta-partitions on the same axis:
        //   (1) confidence:      EXACT / FALLBACK
        //   (2) layer-kind:      LAYER_FILE / LAYER_ENV / LAYER_DEFAULTS
        //   (3) metadata-axis:   METADATA_SOURCE_AXIS / METADATA_NAME_AXIS
        // For every compound-polarity slice, the union of the identity
        // singletons whose sole variant sits on that pole equals the
        // shipped slice as a sequence in declaration order. A future
        // rearrangement of one meta-partition without the others (say,
        // reclassifying EnvByPrefix as fallback without updating the
        // identity → compound aggregation) diverges at THIS pin,
        // before drifting through a consumer that materializes one
        // altitude from another.

        // (1) confidence — EXACT covers the three equality-based rules
        // in declaration order (FileBySource, FileByMetadataName,
        // EnvByPrefix); FALLBACK covers the two uniqueness-based rules
        // in declaration order (EnvByUniqueness,
        // DefaultsByCodeUniqueness).
        let exact_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_FILE_BY_SOURCE,
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
            AttributionRule::ONLY_ENV_BY_PREFIX,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            exact_from_identity,
            AttributionRule::EXACT.to_vec(),
            "identity singleton union on the exact pole must reproduce \
             EXACT in declaration order",
        );
        let fallback_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            fallback_from_identity,
            AttributionRule::FALLBACK.to_vec(),
            "identity singleton union on the fallback pole must reproduce \
             FALLBACK in declaration order",
        );

        // (2) layer-kind — three-way partition. LAYER_DEFAULTS is a
        // singleton pole, so it agrees with ONLY_DEFAULTS_BY_CODE_UNIQUENESS
        // as a bare slice equality.
        let layer_file_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_FILE_BY_SOURCE,
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            layer_file_from_identity,
            AttributionRule::LAYER_FILE.to_vec(),
            "identity singleton union on the file-layer pole must reproduce \
             LAYER_FILE in declaration order",
        );
        let layer_env_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_ENV_BY_PREFIX,
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            layer_env_from_identity,
            AttributionRule::LAYER_ENV.to_vec(),
            "identity singleton union on the env-layer pole must reproduce \
             LAYER_ENV in declaration order",
        );
        assert_eq!(
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS.to_vec(),
            AttributionRule::LAYER_DEFAULTS.to_vec(),
            "the singleton identity slice on DefaultsByCodeUniqueness must \
             reproduce LAYER_DEFAULTS exactly",
        );

        // (3) metadata-axis — the interleaved projection. The source
        // pole holds FileBySource (index 0 in ALL) and
        // DefaultsByCodeUniqueness (index 4 in ALL), so the union
        // ONLY_FILE_BY_SOURCE + ONLY_DEFAULTS_BY_CODE_UNIQUENESS
        // reproduces METADATA_SOURCE_AXIS as a neither-prefix-nor-suffix
        // projection of ALL. The name pole holds the three
        // consecutive middle variants FileByMetadataName, EnvByPrefix,
        // EnvByUniqueness (indices 1..=3 in ALL).
        let metadata_source_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_FILE_BY_SOURCE,
            AttributionRule::ONLY_DEFAULTS_BY_CODE_UNIQUENESS,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            metadata_source_from_identity,
            AttributionRule::METADATA_SOURCE_AXIS.to_vec(),
            "identity singleton union on the metadata-source pole must \
             reproduce METADATA_SOURCE_AXIS in declaration order",
        );
        let metadata_name_from_identity: Vec<AttributionRule> = [
            AttributionRule::ONLY_FILE_BY_METADATA_NAME,
            AttributionRule::ONLY_ENV_BY_PREFIX,
            AttributionRule::ONLY_ENV_BY_UNIQUENESS,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            metadata_name_from_identity,
            AttributionRule::METADATA_NAME_AXIS.to_vec(),
            "identity singleton union on the metadata-name pole must \
             reproduce METADATA_NAME_AXIS in declaration order",
        );
    }

    #[test]
    fn attribution_rule_per_variant_predicates_are_true_only_for_their_own_variant() {
        // Per-variant polarity pin on each of the five corners. Mirror
        // of `shikumi_error_kind_is_*_true_only_for_*_variant` on the
        // error-kind axis and `config_source_kind_is_defaults_...` on
        // the layer-kind axis: pin what each sibling returns on every
        // cell of AttributionRule::ALL, so a `matches!` arm that
        // silently widened to admit a second variant fails here rather
        // than drifting through every consumer's classification.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_file_by_source(),
                rule == AttributionRule::FileBySource,
                "is_file_by_source must hold only on FileBySource, not {rule:?}",
            );
            assert_eq!(
                rule.is_file_by_metadata_name(),
                rule == AttributionRule::FileByMetadataName,
                "is_file_by_metadata_name must hold only on FileByMetadataName, not {rule:?}",
            );
            assert_eq!(
                rule.is_env_by_prefix(),
                rule == AttributionRule::EnvByPrefix,
                "is_env_by_prefix must hold only on EnvByPrefix, not {rule:?}",
            );
            assert_eq!(
                rule.is_env_by_uniqueness(),
                rule == AttributionRule::EnvByUniqueness,
                "is_env_by_uniqueness must hold only on EnvByUniqueness, not {rule:?}",
            );
            assert_eq!(
                rule.is_defaults_by_code_uniqueness(),
                rule == AttributionRule::DefaultsByCodeUniqueness,
                "is_defaults_by_code_uniqueness must hold only on DefaultsByCodeUniqueness, not {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_predicates_are_a_closed_quintet_partition() {
        // Every cell of AttributionRule::ALL satisfies exactly one of
        // the five siblings — none two, none zero. The quintet analogue
        // of `shikumi_error_kind_predicates_are_a_closed_septet_partition`
        // and `secret_error_kind_...`: a future sixth rule variant that
        // lands without its own sibling arm satisfies zero predicates
        // and fails here, before a consumer silently classifies it
        // under the negation of an existing arm.
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_file_by_source())
                + usize::from(rule.is_file_by_metadata_name())
                + usize::from(rule.is_env_by_prefix())
                + usize::from(rule.is_env_by_uniqueness())
                + usize::from(rule.is_defaults_by_code_uniqueness());
            assert_eq!(
                held, 1,
                "exactly one sibling predicate must hold on {rule:?}"
            );
        }
    }

    #[test]
    fn attribution_rule_predicates_refine_confidence() {
        // Cross-partition refinement law on the (exact × fallback)
        // meta-axis: the finer per-variant quintet must compose back
        // into the coarser confidence binary exactly. Mirror of
        // `shikumi_error_kind_figment_extract_siblings_partition_is_figment_bearing`.
        // A future rule whose confidence assignment and sibling
        // membership disagree — e.g. a new equality-based rule filed
        // under Fallback in `confidence()` — fails here.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_exact(),
                rule.is_file_by_source()
                    || rule.is_file_by_metadata_name()
                    || rule.is_env_by_prefix(),
                "the exact-confidence arm must be exactly the three equality-based siblings on {rule:?}",
            );
            assert_eq!(
                rule.is_fallback(),
                rule.is_env_by_uniqueness() || rule.is_defaults_by_code_uniqueness(),
                "the fallback-confidence arm must be exactly the two uniqueness-based siblings on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_predicates_refine_layer_kind() {
        // Refinement law on the (file × env × defaults) layer-kind axis,
        // stated through ConfigSourceKind's own sibling predicates
        // (commit 9600b8b) rather than by equality. Pins that the rule
        // quintet and the layer-kind trio cannot drift apart: the two
        // file-axis rules are exactly the file-kind cell, the two
        // env-axis rules exactly the env-kind cell, the single defaults
        // rule exactly the defaults-kind cell.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.layer_kind().is_file(),
                rule.is_file_by_source() || rule.is_file_by_metadata_name(),
                "the file layer-kind cell must be exactly the two file-axis siblings on {rule:?}",
            );
            assert_eq!(
                rule.layer_kind().is_env(),
                rule.is_env_by_prefix() || rule.is_env_by_uniqueness(),
                "the env layer-kind cell must be exactly the two env-axis siblings on {rule:?}",
            );
            assert_eq!(
                rule.layer_kind().is_defaults(),
                rule.is_defaults_by_code_uniqueness(),
                "the defaults layer-kind cell must be exactly the one defaults-axis sibling on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_predicates_refine_metadata_axis() {
        // Refinement law on the third orthogonal projection, the
        // (metadata-source × metadata-name) dispatch axis, stated
        // through AttributionAxis's own sibling predicates (commit
        // afccd9f). Together with the confidence and layer-kind
        // refinement pins this closes the quintet against all three
        // orthogonal projections `AttributionCoordinates` is built
        // from, so the per-variant siblings and the coordinate cube
        // cannot disagree on any cell.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.metadata_axis().is_metadata_source(),
                rule.is_file_by_source() || rule.is_defaults_by_code_uniqueness(),
                "the metadata-source axis cell must be exactly the two source-dispatched siblings on {rule:?}",
            );
            assert_eq!(
                rule.metadata_axis().is_metadata_name(),
                rule.is_file_by_metadata_name()
                    || rule.is_env_by_prefix()
                    || rule.is_env_by_uniqueness(),
                "the metadata-name axis cell must be exactly the three name-dispatched siblings on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_file_layer_agrees_with_layer_kind_is_file() {
        // The rule-altitude predicate and the layer-kind-altitude
        // predicate on the same corner (File) must agree pointwise
        // across AttributionRule::ALL — the rule-altitude peer is a
        // thin lift of self.layer_kind().is_file(), and the two entry
        // points cannot drift. Mirror of the confidence-altitude
        // attribution_rule_is_exact_agrees_with_confidence_is_exact
        // pin on the coarser (exact × fallback) meta-axis. A future
        // regression that re-inlined matches!(...) on the rule side
        // would still pass today because the polarity still agrees;
        // this pin is loud specifically when
        // ConfigSourceKind::is_file's polarity flips — the rule-side
        // must follow.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_file_layer(),
                rule.layer_kind().is_file(),
                "is_file_layer must route through layer_kind().is_file() on {rule:?}",
            );
            assert_eq!(
                rule.is_file_layer(),
                rule.layer_kind() == ConfigSourceKind::File,
                "is_file_layer must agree with layer_kind == File on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_env_layer_agrees_with_layer_kind_is_env() {
        // Mirror of the File-corner routing pin, on the Env corner.
        // Same rationale (see the File pin's docs): the polarity of
        // the (file × env × defaults) partition is defined once at
        // the layer-kind altitude; the rule-altitude convenience
        // follows.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_env_layer(),
                rule.layer_kind().is_env(),
                "is_env_layer must route through layer_kind().is_env() on {rule:?}",
            );
            assert_eq!(
                rule.is_env_layer(),
                rule.layer_kind() == ConfigSourceKind::Env,
                "is_env_layer must agree with layer_kind == Env on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_defaults_layer_agrees_with_layer_kind_is_defaults() {
        // Mirror of the File-corner routing pin, on the Defaults
        // corner. Closes the ternary agreement grid — every layer
        // kind's polarity now has a rule-altitude sibling routed
        // through the layer-kind altitude.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_defaults_layer(),
                rule.layer_kind().is_defaults(),
                "is_defaults_layer must route through layer_kind().is_defaults() on {rule:?}",
            );
            assert_eq!(
                rule.is_defaults_layer(),
                rule.layer_kind() == ConfigSourceKind::Defaults,
                "is_defaults_layer must agree with layer_kind == Defaults on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_layer_predicates_are_a_closed_ternary_partition() {
        // Every cell of AttributionRule::ALL satisfies exactly one of
        // the three layer-kind sibling delegators — none two, none
        // zero. The rule-altitude analogue of
        // config_source_kind_predicates_are_a_closed_ternary_partition
        // on the layer-kind altitude, and the ternary peer of
        // attribution_rule_metadata_axis_predicates_are_a_closed_binary_partition
        // on the metadata-axis rule projection. A future sixth rule
        // variant whose layer-kind assignment lands under a fourth
        // (new) ConfigSourceKind cell would satisfy zero of the three
        // delegators and fail here, before a consumer silently
        // classified it under the negation of an existing arm.
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_file_layer())
                + usize::from(rule.is_env_layer())
                + usize::from(rule.is_defaults_layer());
            assert_eq!(
                held, 1,
                "exactly one layer-kind sibling delegator must hold on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_metadata_source_axis_agrees_with_metadata_axis_is_metadata_source() {
        // The rule-altitude predicate and the axis-altitude predicate
        // on the same corner (MetadataSource) must agree pointwise
        // across AttributionRule::ALL — the rule-altitude peer is a
        // thin lift of self.metadata_axis().is_metadata_source(), and
        // the two entry points cannot drift. Mirror of the layer-kind
        // altitude routing pins on the third orthogonal projection.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_metadata_source_axis(),
                rule.metadata_axis().is_metadata_source(),
                "is_metadata_source_axis must route through metadata_axis().is_metadata_source() on {rule:?}",
            );
            assert_eq!(
                rule.is_metadata_source_axis(),
                rule.metadata_axis() == AttributionAxis::MetadataSource,
                "is_metadata_source_axis must agree with metadata_axis == MetadataSource on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_metadata_name_axis_agrees_with_metadata_axis_is_metadata_name() {
        // Mirror of the MetadataSource-corner routing pin, on the
        // MetadataName corner. Closes the binary agreement grid — every
        // metadata-axis corner's polarity now has a rule-altitude
        // sibling routed through the axis altitude.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_metadata_name_axis(),
                rule.metadata_axis().is_metadata_name(),
                "is_metadata_name_axis must route through metadata_axis().is_metadata_name() on {rule:?}",
            );
            assert_eq!(
                rule.is_metadata_name_axis(),
                rule.metadata_axis() == AttributionAxis::MetadataName,
                "is_metadata_name_axis must agree with metadata_axis == MetadataName on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_predicates_are_a_closed_binary_partition() {
        // Every cell of AttributionRule::ALL satisfies exactly one of
        // the two metadata-axis sibling delegators — none two, none
        // zero. The rule-altitude analogue of
        // attribution_axis_predicates_are_a_closed_binary_partition
        // on the axis altitude, and the binary peer of
        // attribution_rule_layer_predicates_are_a_closed_ternary_partition
        // on the layer-kind rule projection. A future tertiary
        // AttributionAxis variant (the enum's doc names MetadataExtras
        // as a future direction) that a new rule dispatched off would
        // satisfy zero of the two delegators and fail here, forcing
        // the new axis cell's declaration in lockstep at the rule
        // altitude rather than silently landing under the negation of
        // an existing arm.
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_metadata_source_axis())
                + usize::from(rule.is_metadata_name_axis());
            assert_eq!(
                held, 1,
                "exactly one metadata-axis sibling delegator must hold on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_metadata_axis_predicates_are_const_callable() {
        // Weld the const-callability of the two metadata-axis
        // convenience predicates (`AttributionRule::is_metadata_source_axis`,
        // `AttributionRule::is_metadata_name_axis`) with the projection
        // they route through (`AttributionRule::metadata_axis`, lifted
        // to `const fn` by `4f8a185`) and the two
        // `AttributionAxis::is_metadata_{source,name}` predicates they
        // delegate to (const since they were introduced) at compile
        // time.
        //
        // Rule-altitude analogue on the (metadata-source × metadata-name)
        // axis of `attribution_rule_layer_predicates_are_const_callable`
        // on the (file × env × defaults) layer axis and the
        // confidence-axis welds on the (exact × fallback) axis: the
        // three rule-altitude predicate cascades — confidence, layer-kind,
        // metadata-axis — now live at the same const-callability
        // altitude, and each cell of the 5×2 (variant × predicate) grid
        // on the metadata axis welds directly through `const` bindings
        // on the five payload-free variants.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through each of the two delegating predicates in
        // const position. The moment any of the two predicates (or the
        // routed `metadata_axis` projection, or the routed downstream
        // `AttributionAxis::is_metadata_{source,name}` predicate) stops
        // being const-callable, one of the ten `const` welds below
        // fails to compile at THAT line before the drift can reach
        // downstream consumers that assumed const-ness through the
        // predicate — a `static PER_RULE: [(bool, bool);
        // AttributionRule::ALL.len()]` metadata-axis diagnostic table,
        // an attestation manifest carrying per-rule metadata-axis
        // membership at compile time, a `const` sentinel for a
        // compile-time-known rule's metadata-axis polarity.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const IMS_FBS: bool = R_FBS.is_metadata_source_axis();
        const IMS_FBM: bool = R_FBM.is_metadata_source_axis();
        const IMS_EBP: bool = R_EBP.is_metadata_source_axis();
        const IMS_EBU: bool = R_EBU.is_metadata_source_axis();
        const IMS_DBCU: bool = R_DBCU.is_metadata_source_axis();

        const IMN_FBS: bool = R_FBS.is_metadata_name_axis();
        const IMN_FBM: bool = R_FBM.is_metadata_name_axis();
        const IMN_EBP: bool = R_EBP.is_metadata_name_axis();
        const IMN_EBU: bool = R_EBU.is_metadata_name_axis();
        const IMN_DBCU: bool = R_DBCU.is_metadata_name_axis();

        // Pointwise: the (metadata-source × metadata-name) partition
        // places each of the five rules under exactly one of the two
        // metadata-axis predicates. The const-context welds above
        // prove const-callability; the pins below prove the mapping
        // stays agreed with the exhaustive match in `metadata_axis` —
        // a future edit that shifted a rule off its metadata axis
        // diverges here first, not at a downstream reader of a stale
        // metadata-axis classification.
        assert!(IMS_FBS);
        assert!(!IMS_FBM);
        assert!(!IMS_EBP);
        assert!(!IMS_EBU);
        assert!(IMS_DBCU);

        assert!(!IMN_FBS);
        assert!(IMN_FBM);
        assert!(IMN_EBP);
        assert!(IMN_EBU);
        assert!(!IMN_DBCU);

        // Cross-check: on every rule in `Self::ALL` the const-fn
        // delegating predicate stays pointwise equal to the two-hop
        // composition `metadata_axis().is_metadata_*()` it delegates
        // to — the const-context welds above only exercise the five
        // variants named at const-binding sites, but the runtime pin
        // threads the full closed list through the same delegation to
        // catch a future variant landing whose const-context weld was
        // forgotten upstream.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_metadata_source_axis(),
                rule.metadata_axis().is_metadata_source(),
                "is_metadata_source_axis must route through metadata_axis().is_metadata_source() on {rule:?}",
            );
            assert_eq!(
                rule.is_metadata_name_axis(),
                rule.metadata_axis().is_metadata_name(),
                "is_metadata_name_axis must route through metadata_axis().is_metadata_name() on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_axis_is_metadata_source_true_only_for_metadata_source_variant() {
        // Per-variant polarity pin on the MetadataSource side of the
        // (metadata-source, metadata-name) partition. Mirror of
        // `attribution_confidence_is_exact_true_only_for_exact` on the
        // confidence axis and
        // `field_path_localization_is_applicable_true_only_for_applicable_variants`
        // on the localization axis: pin what the sibling predicate
        // returns on each cell in AttributionAxis::ALL. A future edit
        // that widened AttributionAxis::is_metadata_source to admit
        // MetadataName (or narrowed it to reject MetadataSource) would
        // fail here before drifting through the (metadata-source,
        // metadata-name) polarity at every consumer site.
        assert!(AttributionAxis::MetadataSource.is_metadata_source());
        assert!(!AttributionAxis::MetadataName.is_metadata_source());
    }

    #[test]
    fn attribution_axis_is_metadata_name_true_only_for_metadata_name_variant() {
        // Sibling of the MetadataSource-corner polarity pin, on the
        // MetadataName corner. Same rationale (see the sibling test's
        // docs): pins what the closed-binary sibling returns on every
        // cell in AttributionAxis::ALL, so the two predicates form a
        // closed pair whose polarity a single edit cannot silently flip.
        assert!(!AttributionAxis::MetadataSource.is_metadata_name());
        assert!(AttributionAxis::MetadataName.is_metadata_name());
    }

    #[test]
    fn attribution_axis_predicates_are_a_closed_binary_partition() {
        // Closed-binary-partition pin on the (metadata-source,
        // metadata-name) split. Mirror of
        // `attribution_confidence_predicates_are_a_closed_binary_partition`
        // on the confidence axis,
        // `field_path_localization_predicates_are_a_closed_binary_partition`
        // on the localization axis, and
        // `is_figment_bearing_predicates_are_a_closed_binary_partition`
        // on the kind axis: every ALL cell satisfies exactly one of the
        // two sibling predicates — none satisfy both (a variant
        // claiming to be both source-axis and name-axis at once), none
        // satisfy neither (a variant outside the partition entirely).
        //
        // A future tertiary AttributionAxis variant (e.g. a
        // MetadataExtras cell for figment providers that surface
        // additional typed metadata fields, referenced in the enum's
        // doc-comment) would fail this pin by design: the new class
        // must declare its own partition arm — either extend one of
        // the existing predicates to admit it, or introduce a third
        // predicate — rather than silently landing under the negation
        // of one of the existing two.
        for &axis in AttributionAxis::ALL {
            let source = axis.is_metadata_source();
            let name = axis.is_metadata_name();
            assert!(
                source ^ name,
                "{axis:?} must satisfy exactly one of is_metadata_source / is_metadata_name",
            );
        }
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
    fn attribution_rule_layer_kind_is_const_callable() {
        // Weld the const-callability of the (rule → layer-kind)
        // projection `AttributionRule::layer_kind` with the sibling
        // (rule → confidence) projection `AttributionRule::confidence`
        // (const since it was introduced) at compile time. Mirrors the
        // shape of `config_tier_name_is_const_callable`
        // (`29a2f34`) / `provenance_new_seam_is_const_callable`
        // (`422cc76`) on the shikumi-crate-wide const-callability
        // discipline over the closed-primitive projection surface: a
        // compile-time-known `AttributionRule` projects both
        // orthogonal coordinates (`layer_kind` on the
        // file × env × defaults axis, `confidence` on the exact ×
        // fallback axis) at compile time too — the two projections
        // now live at the same const-callability altitude, so a
        // static per-rule coordinate table wired through either
        // projection stays wired to compile-time evaluation on both.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through the const-fn `layer_kind` projection in
        // const position. The moment `AttributionRule::layer_kind`
        // loses its const-ness (a future edit that reaches for a
        // non-const helper — a lookup through a runtime table, a
        // `String`-shaped intermediate, an allocator on the mapping
        // path — inside the five-arm exhaustive match) one of the
        // five `const` welds below fails to compile at THAT line
        // before the drift can reach downstream consumers that
        // assumed const-ness through the projection, and the five
        // pointwise pins catch a future edit that shifted the
        // rule → kind mapping off the file × env × defaults partition
        // before it drifts through observers that read the projection.
        const FILE_BY_SOURCE: ConfigSourceKind = AttributionRule::FileBySource.layer_kind();
        const FILE_BY_METADATA_NAME: ConfigSourceKind =
            AttributionRule::FileByMetadataName.layer_kind();
        const ENV_BY_PREFIX: ConfigSourceKind = AttributionRule::EnvByPrefix.layer_kind();
        const ENV_BY_UNIQUENESS: ConfigSourceKind = AttributionRule::EnvByUniqueness.layer_kind();
        const DEFAULTS_BY_CODE_UNIQUENESS: ConfigSourceKind =
            AttributionRule::DefaultsByCodeUniqueness.layer_kind();

        assert_eq!(FILE_BY_SOURCE, ConfigSourceKind::File);
        assert_eq!(FILE_BY_METADATA_NAME, ConfigSourceKind::File);
        assert_eq!(ENV_BY_PREFIX, ConfigSourceKind::Env);
        assert_eq!(ENV_BY_UNIQUENESS, ConfigSourceKind::Env);
        assert_eq!(DEFAULTS_BY_CODE_UNIQUENESS, ConfigSourceKind::Defaults);

        // Cross-check: the const-fn projection stays pointwise equal
        // on every rule in `Self::ALL` to the runtime-side
        // `rule.layer_kind()` call — the const-context weld only
        // exercises the five variants named at const-binding sites,
        // but the runtime pin threads the full closed list through
        // the same projection to catch a future variant landing
        // whose const-context weld was forgotten upstream.
        for (rule, expected) in [
            (AttributionRule::FileBySource, FILE_BY_SOURCE),
            (AttributionRule::FileByMetadataName, FILE_BY_METADATA_NAME),
            (AttributionRule::EnvByPrefix, ENV_BY_PREFIX),
            (AttributionRule::EnvByUniqueness, ENV_BY_UNIQUENESS),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                DEFAULTS_BY_CODE_UNIQUENESS,
            ),
        ] {
            assert_eq!(rule.layer_kind(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_rule_layer_predicates_are_const_callable() {
        // Weld the const-callability of the three layer-axis
        // convenience predicates (`AttributionRule::is_file_layer`,
        // `AttributionRule::is_env_layer`,
        // `AttributionRule::is_defaults_layer`) with the projection
        // they route through (`AttributionRule::layer_kind`, lifted
        // to `const fn` by `52c4a20`) and the three
        // `ConfigSourceKind::is_*` predicates they delegate to
        // (const since they were introduced) at compile time.
        //
        // Rule-altitude analogue on the (file × env × defaults) axis
        // of `attribution_rule_confidence_and_confidence_predicates_are_const_callable`
        // (`5c2add4`) on the orthogonal (exact × fallback) axis. The
        // two rule-altitude predicate cascades — confidence and
        // layer-kind — now live at the same const-callability
        // altitude, and each cell of the 5×3 (variant × predicate)
        // grid on the layer-axis welds directly through `const`
        // bindings on the five payload-free variants.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through each of the three delegating predicates in
        // const position. The moment any of the three predicates (or
        // the routed `layer_kind` projection, or the routed
        // downstream `ConfigSourceKind::is_*` predicate) stops being
        // const-callable, one of the fifteen `const` welds below
        // fails to compile at THAT line before the drift can reach
        // downstream consumers that assumed const-ness through the
        // predicate — a `static PER_RULE: [(bool, bool, bool);
        // AttributionRule::ALL.len()]` layer-axis diagnostic table,
        // an attestation manifest carrying per-rule layer-axis
        // membership at compile time, a `const` sentinel for a
        // compile-time-known rule's layer-axis polarity.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const IFL_FBS: bool = R_FBS.is_file_layer();
        const IFL_FBM: bool = R_FBM.is_file_layer();
        const IFL_EBP: bool = R_EBP.is_file_layer();
        const IFL_EBU: bool = R_EBU.is_file_layer();
        const IFL_DBCU: bool = R_DBCU.is_file_layer();

        const IEL_FBS: bool = R_FBS.is_env_layer();
        const IEL_FBM: bool = R_FBM.is_env_layer();
        const IEL_EBP: bool = R_EBP.is_env_layer();
        const IEL_EBU: bool = R_EBU.is_env_layer();
        const IEL_DBCU: bool = R_DBCU.is_env_layer();

        const IDL_FBS: bool = R_FBS.is_defaults_layer();
        const IDL_FBM: bool = R_FBM.is_defaults_layer();
        const IDL_EBP: bool = R_EBP.is_defaults_layer();
        const IDL_EBU: bool = R_EBU.is_defaults_layer();
        const IDL_DBCU: bool = R_DBCU.is_defaults_layer();

        // Pointwise: the (file × env × defaults) partition places
        // each of the five rules under exactly one of the three
        // layer-axis predicates. The const-context welds above prove
        // const-callability; the pins below prove the mapping stays
        // agreed with the exhaustive match in `layer_kind` — a future
        // edit that shifted a rule off its layer diverges here first,
        // not at a downstream reader of a stale layer-axis
        // classification.
        assert!(IFL_FBS);
        assert!(IFL_FBM);
        assert!(!IFL_EBP);
        assert!(!IFL_EBU);
        assert!(!IFL_DBCU);

        assert!(!IEL_FBS);
        assert!(!IEL_FBM);
        assert!(IEL_EBP);
        assert!(IEL_EBU);
        assert!(!IEL_DBCU);

        assert!(!IDL_FBS);
        assert!(!IDL_FBM);
        assert!(!IDL_EBP);
        assert!(!IDL_EBU);
        assert!(IDL_DBCU);

        // Cross-check: on every rule in `Self::ALL` the const-fn
        // delegating predicate stays pointwise equal to the two-hop
        // composition `layer_kind().is_*()` it delegates to — the
        // const-context welds above only exercise the five variants
        // named at const-binding sites, but the runtime pin threads
        // the full closed list through the same delegation to catch
        // a future variant landing whose const-context weld was
        // forgotten upstream.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_file_layer(),
                rule.layer_kind().is_file(),
                "is_file_layer must route through layer_kind().is_file() on {rule:?}",
            );
            assert_eq!(
                rule.is_env_layer(),
                rule.layer_kind().is_env(),
                "is_env_layer must route through layer_kind().is_env() on {rule:?}",
            );
            assert_eq!(
                rule.is_defaults_layer(),
                rule.layer_kind().is_defaults(),
                "is_defaults_layer must route through layer_kind().is_defaults() on {rule:?}",
            );
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
            error: crate::source::synthetic_env_metadata_error("KIND_INV_"),
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
            error: crate::source::synthetic_env_metadata_error("UNRELATED_"),
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
            error: crate::source::synthetic_env_metadata_error("UNRELATED_"),
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
            (
                ShikumiErrorKind::Validation,
                ShikumiError::Validation("bad".to_owned()),
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
    fn kind_agrees_with_is_watch_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_watch(),
                err.kind() == ShikumiErrorKind::Watch,
                "is_watch must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_io_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_io(),
                err.kind() == ShikumiErrorKind::Io,
                "is_io must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_figment_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_figment(),
                err.kind() == ShikumiErrorKind::Figment,
                "is_figment must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_extract_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_extract(),
                err.kind() == ShikumiErrorKind::Extract,
                "is_extract must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn kind_agrees_with_is_validation_pointwise() {
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_validation(),
                err.kind() == ShikumiErrorKind::Validation,
                "is_validation must agree with kind() for {err:?}"
            );
        }
    }

    #[test]
    fn shikumi_error_predicates_are_a_closed_septet_partition() {
        // Tag-side septet-partition pin, sibling of the kind-side
        // `shikumi_error_kind_predicates_are_a_closed_septet_partition`
        // one altitude up on the closed [`ShikumiErrorKind`] partition.
        // Every value in the canonical construction table satisfies
        // exactly one of the seven tag-side sibling predicates: none
        // satisfies two, none satisfies zero. A future variant landing
        // on ShikumiError without its own tag-side sibling predicate
        // collapses the partition to "zero" on that constructed cell,
        // failing here before drifting through any consumer site
        // (a resolver holding the borrowed error routing on the
        // tag-side answer before projecting through kind(), a
        // structured-log field naming the tag-side variant, a
        // cross-thread failure-tag capture on the borrowed error's
        // owned payloads).
        for (_, err) in one_per_kind() {
            let hits = usize::from(err.is_not_found())
                + usize::from(err.is_parse())
                + usize::from(err.is_watch())
                + usize::from(err.is_io())
                + usize::from(err.is_figment())
                + usize::from(err.is_extract())
                + usize::from(err.is_validation());
            assert_eq!(
                hits, 1,
                "{err:?} must satisfy exactly one of \
                 is_not_found/is_parse/is_watch/is_io/is_figment/is_extract/is_validation \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn shikumi_error_predicates_agree_pointwise_with_shikumi_error_kind_predicates() {
        // Structural bridge between the tag-side septet and the
        // kind-side septet: for every constructed error and every
        // sibling arm, `err.is_X() == err.kind().is_X()`. Peer of
        // `shikumi_error_kind_not_found_predicate_agrees_with_shikumi_error_is_not_found_pointwise`
        // and its `..._is_parse` sibling — extending the pair of
        // pre-existing pointwise-agreement pins to the full septet in
        // one loop. A future rename or matches!-arm drift on either
        // altitude fails here before the two altitudes silently
        // disagree on any consumer site (a per-kind alert threshold
        // reading the kind side and a resolver reading the tag side
        // must classify the same error identically).
        for (_, err) in one_per_kind() {
            let k = err.kind();
            assert_eq!(err.is_not_found(), k.is_not_found(), "not_found on {err:?}");
            assert_eq!(err.is_parse(), k.is_parse(), "parse on {err:?}");
            assert_eq!(err.is_watch(), k.is_watch(), "watch on {err:?}");
            assert_eq!(err.is_io(), k.is_io(), "io on {err:?}");
            assert_eq!(err.is_figment(), k.is_figment(), "figment on {err:?}");
            assert_eq!(err.is_extract(), k.is_extract(), "extract on {err:?}");
            assert_eq!(
                err.is_validation(),
                k.is_validation(),
                "validation on {err:?}"
            );
        }
    }

    #[test]
    fn shikumi_error_figment_extract_siblings_partition_is_figment_bearing() {
        // Tag-side refinement law mirroring the kind-side
        // `shikumi_error_kind_figment_extract_siblings_partition_is_figment_bearing`:
        // the coarser tag-side meta-predicate `is_figment_bearing()`
        // coincides pointwise with the disjunction of the two
        // figment-bearing sibling predicates
        // (`is_figment() ∨ is_extract()`) over the canonical
        // construction table. A future third figment-bearing variant
        // landing on ShikumiError must extend the sibling-predicate
        // septet AND route through `is_figment_bearing`'s
        // matches!-arm at the kind altitude; either half of the
        // refinement drifting alone fails here.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_figment_bearing(),
                err.is_figment() || err.is_extract(),
                "figment-bearing must equal (is_figment ∨ is_extract) on {err:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_is_figment_bearing_agrees_with_kind_is_figment_bearing_pointwise() {
        // Structural bridge between the new tag-side convenience
        // `ShikumiError::is_figment_bearing` and the pre-existing
        // kind-side `ShikumiErrorKind::is_figment_bearing`: the
        // tag-side accessor is the kind-side answer one altitude
        // down. A future edit whose matches!-arm on either altitude
        // silently drifts fails here before the two altitudes
        // disagree on any consumer site.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_figment_bearing(),
                err.kind().is_figment_bearing(),
                "figment-bearing must agree across altitudes on {err:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_is_not_figment_bearing_agrees_with_kind_is_not_figment_bearing_pointwise() {
        // Structural bridge for the complement half of the
        // figment-bearing meta-partition: the tag-side
        // `ShikumiError::is_not_figment_bearing` is the kind-side
        // `ShikumiErrorKind::is_not_figment_bearing` answer one
        // altitude down, matching the sibling pointwise-agreement
        // pin on the positive half
        // (`shikumi_error_is_figment_bearing_agrees_with_kind_is_figment_bearing_pointwise`).
        // A future edit whose matches!-arm on either altitude
        // silently drifts fails here before the two altitudes
        // disagree on any consumer site.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_not_figment_bearing(),
                err.kind().is_not_figment_bearing(),
                "not-figment-bearing must agree across altitudes on {err:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_is_not_figment_bearing_is_complement_of_is_figment_bearing_pointwise() {
        // Complement identity between the two tag-side halves of
        // the figment-bearing meta-partition: on every captured
        // error, `is_not_figment_bearing()` equals the boolean
        // negation of `is_figment_bearing()`. Mirrors the kind-side
        // sibling law implicit in the
        // `is_figment_bearing_predicates_are_a_closed_binary_partition`
        // pin at the kind altitude; welding both halves into a
        // pointwise-complement pin at the tag altitude keeps the
        // two forwarders in lockstep even if one is retargeted at
        // a different underlying predicate.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.is_not_figment_bearing(),
                !err.is_figment_bearing(),
                "is_not_figment_bearing must be the complement of is_figment_bearing on {err:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_figment_bearing_predicates_are_a_closed_binary_partition() {
        // Every captured error satisfies exactly one of the two
        // tag-side halves of the figment-bearing meta-partition
        // (`is_figment_bearing` XOR `is_not_figment_bearing`) —
        // never both, never neither. Tag-altitude peer of the
        // kind-altitude
        // `is_figment_bearing_predicates_are_a_closed_binary_partition`
        // pin. A future ShikumiError variant landing on a third
        // meta-classification (e.g. a hypothetical
        // `PartiallyFigmentBearing` corner) would force both halves
        // of the tag-side pair to reclassify in lockstep; either
        // half drifting alone breaks this partition and fails here
        // before drifting through any consumer.
        for (_, err) in one_per_kind() {
            let a = err.is_figment_bearing();
            let b = err.is_not_figment_bearing();
            assert!(
                a ^ b,
                "figment-bearing halves must partition every error \
                 (got is_figment_bearing={a}, is_not_figment_bearing={b} on {err:?})",
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
                ShikumiErrorKind::Validation,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn shikumi_error_kind_all_partitions_figment_bearing_axis() {
        // ALL composes with is_figment_bearing as the universe over
        // which the figment-bearing partition is total: exactly two of
        // the listed kinds bear figment, the rest don't. Stated through
        // the constant rather than an inline literal, and through the
        // is_not_figment_bearing sibling rather than a fresh
        // `!k.is_figment_bearing()` negation on the non-bearing side.
        let bearing = ShikumiErrorKind::ALL
            .iter()
            .filter(|k| k.is_figment_bearing())
            .count();
        let non_bearing = ShikumiErrorKind::ALL
            .iter()
            .filter(|k| k.is_not_figment_bearing())
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
            assert!(
                kind.is_not_figment_bearing(),
                "{kind:?} must satisfy the is_not_figment_bearing sibling",
            );
        }
    }

    #[test]
    fn is_figment_bearing_predicates_are_a_closed_binary_partition() {
        // The two sibling predicates form a closed binary partition
        // over ShikumiErrorKind::ALL: every variant satisfies exactly
        // one, none satisfy neither, none satisfy both. Kind-altitude
        // peer of
        // `attribution_confidence_predicates_are_a_closed_binary_partition`
        // (confidence axis) and
        // `field_path_localization_predicates_are_a_closed_binary_partition`
        // (localization axis). A future tertiary classification of the
        // figment-bearing axis — a kind that wraps figment through a
        // third path the two current arms don't name — would have to
        // declare its own arm in the exhaustive match rather than
        // silently landing under the negation of one of the existing
        // two.
        for k in ShikumiErrorKind::ALL.iter().copied() {
            assert_ne!(
                k.is_figment_bearing(),
                k.is_not_figment_bearing(),
                "figment-bearing is binary; the two predicates must disagree pointwise on {k:?}",
            );
            assert!(
                k.is_figment_bearing() || k.is_not_figment_bearing(),
                "closed binary partition: {k:?} must satisfy one of is_figment_bearing / is_not_figment_bearing",
            );
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

    // ---- ShikumiErrorKind per-variant sibling predicates ----

    #[test]
    fn shikumi_error_kind_is_not_found_true_only_for_not_found_variant() {
        // Per-variant polarity pin on the NotFound corner of the septet.
        // Sibling to the quintet-shape pins on SecretErrorKind
        // (`secret_error_kind_is_not_found_true_only_for_not_found_variant`,
        // added by 6b67a81) and the trio-shape pins on ConfigSourceKind
        // (`config_source_kind_is_defaults_true_only_for_defaults_variant`).
        // A future edit that flips the `matches!` arm on `is_not_found`
        // fails here before the equality-agreement pin masks it.
        assert!(ShikumiErrorKind::NotFound.is_not_found());
        assert!(!ShikumiErrorKind::Parse.is_not_found());
        assert!(!ShikumiErrorKind::Watch.is_not_found());
        assert!(!ShikumiErrorKind::Io.is_not_found());
        assert!(!ShikumiErrorKind::Figment.is_not_found());
        assert!(!ShikumiErrorKind::Extract.is_not_found());
        assert!(!ShikumiErrorKind::Validation.is_not_found());
    }

    #[test]
    fn shikumi_error_kind_is_parse_true_only_for_parse_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_parse());
        assert!(ShikumiErrorKind::Parse.is_parse());
        assert!(!ShikumiErrorKind::Watch.is_parse());
        assert!(!ShikumiErrorKind::Io.is_parse());
        assert!(!ShikumiErrorKind::Figment.is_parse());
        assert!(!ShikumiErrorKind::Extract.is_parse());
        assert!(!ShikumiErrorKind::Validation.is_parse());
    }

    #[test]
    fn shikumi_error_kind_is_watch_true_only_for_watch_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_watch());
        assert!(!ShikumiErrorKind::Parse.is_watch());
        assert!(ShikumiErrorKind::Watch.is_watch());
        assert!(!ShikumiErrorKind::Io.is_watch());
        assert!(!ShikumiErrorKind::Figment.is_watch());
        assert!(!ShikumiErrorKind::Extract.is_watch());
        assert!(!ShikumiErrorKind::Validation.is_watch());
    }

    #[test]
    fn shikumi_error_kind_is_io_true_only_for_io_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_io());
        assert!(!ShikumiErrorKind::Parse.is_io());
        assert!(!ShikumiErrorKind::Watch.is_io());
        assert!(ShikumiErrorKind::Io.is_io());
        assert!(!ShikumiErrorKind::Figment.is_io());
        assert!(!ShikumiErrorKind::Extract.is_io());
        assert!(!ShikumiErrorKind::Validation.is_io());
    }

    #[test]
    fn shikumi_error_kind_is_figment_true_only_for_figment_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_figment());
        assert!(!ShikumiErrorKind::Parse.is_figment());
        assert!(!ShikumiErrorKind::Watch.is_figment());
        assert!(!ShikumiErrorKind::Io.is_figment());
        assert!(ShikumiErrorKind::Figment.is_figment());
        assert!(!ShikumiErrorKind::Extract.is_figment());
        assert!(!ShikumiErrorKind::Validation.is_figment());
    }

    #[test]
    fn shikumi_error_kind_is_extract_true_only_for_extract_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_extract());
        assert!(!ShikumiErrorKind::Parse.is_extract());
        assert!(!ShikumiErrorKind::Watch.is_extract());
        assert!(!ShikumiErrorKind::Io.is_extract());
        assert!(!ShikumiErrorKind::Figment.is_extract());
        assert!(ShikumiErrorKind::Extract.is_extract());
        assert!(!ShikumiErrorKind::Validation.is_extract());
    }

    #[test]
    fn shikumi_error_kind_is_validation_true_only_for_validation_variant() {
        assert!(!ShikumiErrorKind::NotFound.is_validation());
        assert!(!ShikumiErrorKind::Parse.is_validation());
        assert!(!ShikumiErrorKind::Watch.is_validation());
        assert!(!ShikumiErrorKind::Io.is_validation());
        assert!(!ShikumiErrorKind::Figment.is_validation());
        assert!(!ShikumiErrorKind::Extract.is_validation());
        assert!(ShikumiErrorKind::Validation.is_validation());
    }

    #[test]
    fn shikumi_error_kind_predicates_are_a_closed_septet_partition() {
        // Every ShikumiErrorKind::ALL cell satisfies exactly one of the
        // seven sibling predicates: none satisfies two, none satisfies
        // zero. Septet analogue of the quintet-partition pin on
        // SecretErrorKind
        // (`secret_error_kind_predicates_are_a_closed_quintet_partition`)
        // and the ternary-partition pin on ConfigSourceKind
        // (`config_source_kind_predicates_are_a_closed_ternary_partition`).
        // A future variant landing on ShikumiErrorKind without its own
        // sibling predicate collapses the partition to "zero" on that
        // cell, failing here before drifting through any consumer site
        // (a per-kind retry-policy dispatch, a structured-diagnostic
        // legend, an attestation manifest recording the kind histogram
        // of captured failures).
        for k in ShikumiErrorKind::ALL.iter().copied() {
            let hits = usize::from(k.is_not_found())
                + usize::from(k.is_parse())
                + usize::from(k.is_watch())
                + usize::from(k.is_io())
                + usize::from(k.is_figment())
                + usize::from(k.is_extract())
                + usize::from(k.is_validation());
            assert_eq!(
                hits, 1,
                "ShikumiErrorKind::{k:?} must satisfy exactly one of \
                 is_not_found/is_parse/is_watch/is_io/is_figment/is_extract/is_validation \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn shikumi_error_kind_predicates_agree_with_equality_pointwise() {
        // The kind-alone equality-agreement law over
        // ShikumiErrorKind::ALL, matching the shape of
        // `secret_error_kind_predicates_agree_with_equality_pointwise`
        // on the secret-client error-kind axis and of
        // `config_source_kind_predicates_agree_with_equality_pointwise`
        // on the shikumi-side layer-kind axis. Catches the dual case
        // where a predicate's `matches!` arm silently accepts a second
        // variant (say a copy-paste that widened `is_io` to
        // `Self::Io | Self::Watch`) — the closed-septet-partition pin
        // catches the "zero" side of that drift by flipping the robbed
        // corner's hits from 1 to 0; this pin catches the "two on the
        // same corner" side without needing another corner to change.
        for k in ShikumiErrorKind::ALL.iter().copied() {
            assert_eq!(k.is_not_found(), k == ShikumiErrorKind::NotFound);
            assert_eq!(k.is_parse(), k == ShikumiErrorKind::Parse);
            assert_eq!(k.is_watch(), k == ShikumiErrorKind::Watch);
            assert_eq!(k.is_io(), k == ShikumiErrorKind::Io);
            assert_eq!(k.is_figment(), k == ShikumiErrorKind::Figment);
            assert_eq!(k.is_extract(), k == ShikumiErrorKind::Extract);
            assert_eq!(k.is_validation(), k == ShikumiErrorKind::Validation);
        }
    }

    #[test]
    fn shikumi_error_kind_figment_extract_siblings_partition_is_figment_bearing() {
        // Cross-partition refinement law: the meta-predicate
        // `is_figment_bearing` on the kind axis coincides pointwise
        // with the disjunction of the two per-variant sibling
        // predicates over the figment-bearing cells
        // (`is_figment` ∪ `is_extract`). Pins the invariant that the
        // finer per-variant partition is a refinement of the coarser
        // binary partition — a future third figment-bearing kind
        // would fail here if its is_figment_bearing arm was flipped
        // to `true` without also naming it in the per-variant sibling
        // set, or vice versa.
        for k in ShikumiErrorKind::ALL.iter().copied() {
            assert_eq!(
                k.is_figment_bearing(),
                k.is_figment() || k.is_extract(),
                "figment-bearing must equal (is_figment ∨ is_extract) on {k:?}",
            );
        }
    }

    // ---- ShikumiErrorKind::FIGMENT_BEARING / NOT_FIGMENT_BEARING slice pair ----
    //
    // Slice-altitude witnesses of the (figment-bearing ×
    // not-figment-bearing) compound-polarity meta-partition on the
    // seven-way kind axis. Idiom-peers of the shipped per-half slice
    // pairs on `Format` (`2013269`), `FigmentNameTagKind` (`2d2ef9d`),
    // `EnvMetadataTagKind` (`13304d0`), `AttributionAxis` (`34bfbb6`),
    // `OutputFormat` (`292ca1d`), `AttributionConfidence` (`13c1003`),
    // `FormatProvenance` (`7ef79e4`), `SecretRefShape` (`036673b`),
    // `PartitionFace` (`a344056`), `ConfigSourceKind` (`2cd8ef8`), and
    // `ConfigTierKind` (`2c0686f`) — applied here to the seven-way
    // shikumi error-kind axis's (figment-bearing × not-figment-bearing)
    // compound-polarity meta-partition, an INTERLEAVED projection in
    // which the not-figment-bearing pole spans both an ALL-prefix
    // (NotFound/Parse/Watch/Io) AND an ALL-suffix cell (Validation),
    // split by the two figment-bearing cells (Figment/Extract) in the
    // middle.

    #[test]
    fn shikumi_error_kind_figment_bearing_slice_agrees_with_is_figment_bearing_predicate() {
        // Bidirectional weld between the slice literal
        // `ShikumiErrorKind::FIGMENT_BEARING` and the boolean predicate
        // `ShikumiErrorKind::is_figment_bearing` on the
        // (figment-bearing × not-figment-bearing) polarity axis. Every
        // slice entry satisfies the figment-bearing pole (and its
        // complement `!is_not_figment_bearing`), and every ALL cell
        // agrees on membership under the boolean predicate. Idiom-peer
        // of `format_feature_gated_slice_agrees_with_is_feature_gated_predicate`
        // (`2013269`) — the two independent declaration surfaces
        // (slice literal + boolean predicate) diverge at THIS pin on
        // the first shape where they disagree, before a consumer that
        // reads one altitude but not the other can observe the drift.
        for k in ShikumiErrorKind::FIGMENT_BEARING.iter().copied() {
            assert!(
                k.is_figment_bearing(),
                "ShikumiErrorKind::FIGMENT_BEARING entry {k:?} must satisfy is_figment_bearing()",
            );
            assert!(
                !k.is_not_figment_bearing(),
                "ShikumiErrorKind::FIGMENT_BEARING entry {k:?} must NOT satisfy is_not_figment_bearing()",
            );
        }
        for k in ShikumiErrorKind::NOT_FIGMENT_BEARING.iter().copied() {
            assert!(
                k.is_not_figment_bearing(),
                "ShikumiErrorKind::NOT_FIGMENT_BEARING entry {k:?} must satisfy is_not_figment_bearing()",
            );
            assert!(
                !k.is_figment_bearing(),
                "ShikumiErrorKind::NOT_FIGMENT_BEARING entry {k:?} must NOT satisfy is_figment_bearing()",
            );
        }
        for k in ShikumiErrorKind::ALL.iter().copied() {
            assert_eq!(
                ShikumiErrorKind::FIGMENT_BEARING.contains(&k),
                k.is_figment_bearing(),
                "FIGMENT_BEARING membership must agree with is_figment_bearing() on ShikumiErrorKind::{k:?}",
            );
            assert_eq!(
                ShikumiErrorKind::NOT_FIGMENT_BEARING.contains(&k),
                k.is_not_figment_bearing(),
                "NOT_FIGMENT_BEARING membership must agree with is_not_figment_bearing() on ShikumiErrorKind::{k:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `FIGMENT_BEARING.len() + NOT_FIGMENT_BEARING.len() == ALL.len()`
        // at the slice altitude on the seven-way kind axis. Idiom-peer
        // of `format_feature_gated_and_always_available_slices_partition_all`
        // (`2013269`) — a variant landing on one slice AND the other,
        // or on neither, breaks the partition here before any consumer
        // that reasons about the polarity as a covering meta-partition
        // observes the drift.
        for k in ShikumiErrorKind::FIGMENT_BEARING.iter().copied() {
            assert!(
                !ShikumiErrorKind::NOT_FIGMENT_BEARING.contains(&k),
                "ShikumiErrorKind::{k:?} appears in BOTH FIGMENT_BEARING and NOT_FIGMENT_BEARING",
            );
        }
        for k in ShikumiErrorKind::ALL.iter().copied() {
            let in_figment_bearing = ShikumiErrorKind::FIGMENT_BEARING.contains(&k);
            let in_not_figment_bearing = ShikumiErrorKind::NOT_FIGMENT_BEARING.contains(&k);
            assert!(
                in_figment_bearing || in_not_figment_bearing,
                "ShikumiErrorKind::{k:?} is in NEITHER FIGMENT_BEARING nor NOT_FIGMENT_BEARING",
            );
            assert!(
                !(in_figment_bearing && in_not_figment_bearing),
                "ShikumiErrorKind::{k:?} is in BOTH FIGMENT_BEARING and NOT_FIGMENT_BEARING",
            );
        }
        assert_eq!(
            ShikumiErrorKind::FIGMENT_BEARING.len() + ShikumiErrorKind::NOT_FIGMENT_BEARING.len(),
            ShikumiErrorKind::ALL.len(),
            "FIGMENT_BEARING and NOT_FIGMENT_BEARING slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in ShikumiErrorKind::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. The
        // not-figment-bearing pole in particular is INTERLEAVED with
        // the figment-bearing pole in ShikumiErrorKind::ALL (NotFound,
        // Parse, Watch, Io, Figment, Extract, Validation — the
        // not-figment-bearing cells NotFound/Parse/Watch/Io on the
        // prefix AND Validation on the suffix are split by the
        // figment-bearing Figment/Extract pair in the middle), so a
        // suffix or prefix rewriting of the slices — or a reordering
        // of ALL that shuffled the interleaving — diverges at THIS
        // pin. Idiom-peer of
        // `format_feature_gated_and_always_available_slices_preserve_all_order`
        // (`2013269`).
        let figment_bearing_from_all: Vec<ShikumiErrorKind> = ShikumiErrorKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_figment_bearing())
            .collect();
        assert_eq!(
            figment_bearing_from_all,
            ShikumiErrorKind::FIGMENT_BEARING.to_vec(),
            "FIGMENT_BEARING must be ALL-filtered by is_figment_bearing in declaration order",
        );
        let not_figment_bearing_from_all: Vec<ShikumiErrorKind> = ShikumiErrorKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_not_figment_bearing())
            .collect();
        assert_eq!(
            not_figment_bearing_from_all,
            ShikumiErrorKind::NOT_FIGMENT_BEARING.to_vec(),
            "NOT_FIGMENT_BEARING must be ALL-filtered by is_not_figment_bearing in declaration order",
        );
    }

    #[test]
    fn shikumi_error_kind_figment_bearing_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into FIGMENT_BEARING, an accidental re-add of an
        // already-present cell into NOT_FIGMENT_BEARING) fails at THIS
        // pin before drifting through any consumer that iterates the
        // slice expecting a set.
        for slice in [
            ShikumiErrorKind::FIGMENT_BEARING,
            ShikumiErrorKind::NOT_FIGMENT_BEARING,
        ] {
            let mut seen: Vec<ShikumiErrorKind> = Vec::with_capacity(slice.len());
            for k in slice {
                assert!(
                    !seen.contains(k),
                    "ShikumiErrorKind slice {slice:?} contains duplicate entry {k:?}",
                );
                seen.push(*k);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn shikumi_error_kind_figment_bearing_and_not_figment_bearing_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on ShikumiErrorKind::ALL — i.e.,
        // `FIGMENT_BEARING.len() == ALL.iter().filter(is_figment_bearing).count()`
        // and `NOT_FIGMENT_BEARING.len() ==
        // ALL.iter().filter(is_not_figment_bearing).count()` — the
        // cardinality projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete
        // positions today: 2 figment-bearing + 5 not-figment-bearing
        // = 7 = ALL. Idiom-peer of
        // `format_feature_gated_and_always_available_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`2013269`).
        let figment_bearing_count = ShikumiErrorKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_figment_bearing())
            .count();
        let not_figment_bearing_count = ShikumiErrorKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_not_figment_bearing())
            .count();
        assert_eq!(
            ShikumiErrorKind::FIGMENT_BEARING.len(),
            figment_bearing_count,
            "FIGMENT_BEARING.len() must match the is_figment_bearing count on ALL",
        );
        assert_eq!(
            ShikumiErrorKind::NOT_FIGMENT_BEARING.len(),
            not_figment_bearing_count,
            "NOT_FIGMENT_BEARING.len() must match the is_not_figment_bearing count on ALL",
        );
        assert_eq!(ShikumiErrorKind::FIGMENT_BEARING.len(), 2);
        assert_eq!(ShikumiErrorKind::NOT_FIGMENT_BEARING.len(), 5);
        assert_eq!(ShikumiErrorKind::ALL.len(), 7);
    }

    #[test]
    fn shikumi_error_kind_figment_bearing_and_not_figment_bearing_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `format_feature_gated_and_always_available_slices_are_const_addressable`
        // (`2013269`).
        const FIGMENT_BEARING_LEN: usize = ShikumiErrorKind::FIGMENT_BEARING.len();
        const NOT_FIGMENT_BEARING_LEN: usize = ShikumiErrorKind::NOT_FIGMENT_BEARING.len();
        const ALL_LEN: usize = ShikumiErrorKind::ALL.len();
        assert_eq!(FIGMENT_BEARING_LEN, 2);
        assert_eq!(NOT_FIGMENT_BEARING_LEN, 5);
        assert_eq!(FIGMENT_BEARING_LEN + NOT_FIGMENT_BEARING_LEN, ALL_LEN);
    }

    // ── ShikumiErrorKind — identity meta-partition slice constants ────
    //
    // Septenary landing of the per-half meta-partition slice-constant
    // discipline on the seven-way ShikumiErrorKind axis (first
    // identity-partition landing on the error-kind primitive). Peer of
    // the senary `SecretOperation::ONLY_GET` / … / `ONLY_GET_VERSION`
    // (commit `bfe3e24`), the septenary `SecretClientKind::ONLY_MEM` /
    // … / `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), the octonary
    // `SecretBackendKind::ONLY_LITERAL` / … / `ONLY_GCP_SECRET` (commit
    // `19364e3`), and the quinary `TierArg::ONLY_BARE` / … / `ONLY_ENV`
    // (commit `f7f5529`). The seven pins below lock the identity
    // singletons as a coherent meta-partition at the primitive's
    // altitude alongside the shipped compound-polarity FIGMENT_BEARING
    // / NOT_FIGMENT_BEARING pair one altitude up.

    #[test]
    fn shikumi_error_kind_identity_slices_agree_with_identity_predicates() {
        // Seven-way agreement pin across the (not_found × parse ×
        // watch × io × figment × extract × validation) identity meta-
        // partition. Every ONLY_NOT_FOUND entry satisfies is_not_found
        // and none of the six sibling predicates; every ONLY_PARSE
        // entry satisfies is_parse alone; … and so on across all seven
        // halves. The two independent declaration surfaces (slice
        // literals + boolean predicates) diverge at THIS pin on the
        // first shape where they disagree, before a consumer that reads
        // one altitude but not the other can observe the drift.
        // Septenary peer of
        // `secret_operation_identity_slices_agree_with_identity_predicates`
        // (commit `bfe3e24`) one cell wider.
        for k in ShikumiErrorKind::ONLY_NOT_FOUND.iter().copied() {
            assert!(
                k.is_not_found(),
                "ONLY_NOT_FOUND {k:?} must satisfy is_not_found"
            );
            assert!(
                !k.is_parse(),
                "ONLY_NOT_FOUND {k:?} must NOT satisfy is_parse"
            );
            assert!(
                !k.is_watch(),
                "ONLY_NOT_FOUND {k:?} must NOT satisfy is_watch"
            );
            assert!(!k.is_io(), "ONLY_NOT_FOUND {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_figment(),
                "ONLY_NOT_FOUND {k:?} must NOT satisfy is_figment"
            );
            assert!(
                !k.is_extract(),
                "ONLY_NOT_FOUND {k:?} must NOT satisfy is_extract"
            );
            assert!(
                !k.is_validation(),
                "ONLY_NOT_FOUND {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_PARSE.iter().copied() {
            assert!(k.is_parse(), "ONLY_PARSE {k:?} must satisfy is_parse");
            assert!(
                !k.is_not_found(),
                "ONLY_PARSE {k:?} must NOT satisfy is_not_found"
            );
            assert!(!k.is_watch(), "ONLY_PARSE {k:?} must NOT satisfy is_watch");
            assert!(!k.is_io(), "ONLY_PARSE {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_figment(),
                "ONLY_PARSE {k:?} must NOT satisfy is_figment"
            );
            assert!(
                !k.is_extract(),
                "ONLY_PARSE {k:?} must NOT satisfy is_extract"
            );
            assert!(
                !k.is_validation(),
                "ONLY_PARSE {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_WATCH.iter().copied() {
            assert!(k.is_watch(), "ONLY_WATCH {k:?} must satisfy is_watch");
            assert!(
                !k.is_not_found(),
                "ONLY_WATCH {k:?} must NOT satisfy is_not_found"
            );
            assert!(!k.is_parse(), "ONLY_WATCH {k:?} must NOT satisfy is_parse");
            assert!(!k.is_io(), "ONLY_WATCH {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_figment(),
                "ONLY_WATCH {k:?} must NOT satisfy is_figment"
            );
            assert!(
                !k.is_extract(),
                "ONLY_WATCH {k:?} must NOT satisfy is_extract"
            );
            assert!(
                !k.is_validation(),
                "ONLY_WATCH {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_IO.iter().copied() {
            assert!(k.is_io(), "ONLY_IO {k:?} must satisfy is_io");
            assert!(
                !k.is_not_found(),
                "ONLY_IO {k:?} must NOT satisfy is_not_found"
            );
            assert!(!k.is_parse(), "ONLY_IO {k:?} must NOT satisfy is_parse");
            assert!(!k.is_watch(), "ONLY_IO {k:?} must NOT satisfy is_watch");
            assert!(!k.is_figment(), "ONLY_IO {k:?} must NOT satisfy is_figment");
            assert!(!k.is_extract(), "ONLY_IO {k:?} must NOT satisfy is_extract");
            assert!(
                !k.is_validation(),
                "ONLY_IO {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_FIGMENT.iter().copied() {
            assert!(k.is_figment(), "ONLY_FIGMENT {k:?} must satisfy is_figment");
            assert!(
                !k.is_not_found(),
                "ONLY_FIGMENT {k:?} must NOT satisfy is_not_found"
            );
            assert!(
                !k.is_parse(),
                "ONLY_FIGMENT {k:?} must NOT satisfy is_parse"
            );
            assert!(
                !k.is_watch(),
                "ONLY_FIGMENT {k:?} must NOT satisfy is_watch"
            );
            assert!(!k.is_io(), "ONLY_FIGMENT {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_extract(),
                "ONLY_FIGMENT {k:?} must NOT satisfy is_extract"
            );
            assert!(
                !k.is_validation(),
                "ONLY_FIGMENT {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_EXTRACT.iter().copied() {
            assert!(k.is_extract(), "ONLY_EXTRACT {k:?} must satisfy is_extract");
            assert!(
                !k.is_not_found(),
                "ONLY_EXTRACT {k:?} must NOT satisfy is_not_found"
            );
            assert!(
                !k.is_parse(),
                "ONLY_EXTRACT {k:?} must NOT satisfy is_parse"
            );
            assert!(
                !k.is_watch(),
                "ONLY_EXTRACT {k:?} must NOT satisfy is_watch"
            );
            assert!(!k.is_io(), "ONLY_EXTRACT {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_figment(),
                "ONLY_EXTRACT {k:?} must NOT satisfy is_figment"
            );
            assert!(
                !k.is_validation(),
                "ONLY_EXTRACT {k:?} must NOT satisfy is_validation"
            );
        }
        for k in ShikumiErrorKind::ONLY_VALIDATION.iter().copied() {
            assert!(
                k.is_validation(),
                "ONLY_VALIDATION {k:?} must satisfy is_validation"
            );
            assert!(
                !k.is_not_found(),
                "ONLY_VALIDATION {k:?} must NOT satisfy is_not_found"
            );
            assert!(
                !k.is_parse(),
                "ONLY_VALIDATION {k:?} must NOT satisfy is_parse"
            );
            assert!(
                !k.is_watch(),
                "ONLY_VALIDATION {k:?} must NOT satisfy is_watch"
            );
            assert!(!k.is_io(), "ONLY_VALIDATION {k:?} must NOT satisfy is_io");
            assert!(
                !k.is_figment(),
                "ONLY_VALIDATION {k:?} must NOT satisfy is_figment"
            );
            assert!(
                !k.is_extract(),
                "ONLY_VALIDATION {k:?} must NOT satisfy is_extract"
            );
        }
    }

    #[test]
    fn shikumi_error_kind_identity_slices_partition_all() {
        // Septenary partition invariant: the seven per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_NOT_FOUND.len() + ONLY_PARSE.len() + ONLY_WATCH.len() +
        //  ONLY_IO.len() + ONLY_FIGMENT.len() + ONLY_EXTRACT.len() +
        //  ONLY_VALIDATION.len() == ALL.len()`.
        let identity_slices: [&[ShikumiErrorKind]; 7] = [
            ShikumiErrorKind::ONLY_NOT_FOUND,
            ShikumiErrorKind::ONLY_PARSE,
            ShikumiErrorKind::ONLY_WATCH,
            ShikumiErrorKind::ONLY_IO,
            ShikumiErrorKind::ONLY_FIGMENT,
            ShikumiErrorKind::ONLY_EXTRACT,
            ShikumiErrorKind::ONLY_VALIDATION,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for k in left.iter() {
                    assert!(
                        !right.contains(k),
                        "ShikumiErrorKind::{k:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for k in ShikumiErrorKind::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&k)))
                .sum();
            assert_eq!(
                held, 1,
                "ShikumiErrorKind::{k:?} must appear in exactly one identity \
                 slice (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            ShikumiErrorKind::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn shikumi_error_kind_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in ShikumiErrorKind::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at THIS
        // pin.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<ShikumiErrorKind> = ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(ShikumiErrorKind::ONLY_NOT_FOUND, is_not_found);
        pin!(ShikumiErrorKind::ONLY_PARSE, is_parse);
        pin!(ShikumiErrorKind::ONLY_WATCH, is_watch);
        pin!(ShikumiErrorKind::ONLY_IO, is_io);
        pin!(ShikumiErrorKind::ONLY_FIGMENT, is_figment);
        pin!(ShikumiErrorKind::ONLY_EXTRACT, is_extract);
        pin!(ShikumiErrorKind::ONLY_VALIDATION, is_validation);
    }

    #[test]
    fn shikumi_error_kind_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all seven per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set.
        for slice in [
            ShikumiErrorKind::ONLY_NOT_FOUND,
            ShikumiErrorKind::ONLY_PARSE,
            ShikumiErrorKind::ONLY_WATCH,
            ShikumiErrorKind::ONLY_IO,
            ShikumiErrorKind::ONLY_FIGMENT,
            ShikumiErrorKind::ONLY_EXTRACT,
            ShikumiErrorKind::ONLY_VALIDATION,
        ] {
            let mut seen: Vec<ShikumiErrorKind> = Vec::with_capacity(slice.len());
            for k in slice {
                assert!(
                    !seen.contains(k),
                    "ShikumiErrorKind identity slice {slice:?} contains \
                     duplicate entry {k:?}",
                );
                seen.push(*k);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn shikumi_error_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on ShikumiErrorKind::ALL — i.e.,
        // `ONLY_NOT_FOUND.len() == ALL.iter().filter(is_not_found).count()`
        // (and symmetric for the six siblings) — the cardinality
        // projection at the slice altitude agrees with the boolean-
        // altitude projection on all seven halves. Concrete positions
        // today: 1 + 1 + 1 + 1 + 1 + 1 + 1 = 7 = ALL.
        let counts = [
            (
                "is_not_found",
                ShikumiErrorKind::ONLY_NOT_FOUND.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_not_found())
                    .count(),
            ),
            (
                "is_parse",
                ShikumiErrorKind::ONLY_PARSE.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_parse())
                    .count(),
            ),
            (
                "is_watch",
                ShikumiErrorKind::ONLY_WATCH.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_watch())
                    .count(),
            ),
            (
                "is_io",
                ShikumiErrorKind::ONLY_IO.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_io())
                    .count(),
            ),
            (
                "is_figment",
                ShikumiErrorKind::ONLY_FIGMENT.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_figment())
                    .count(),
            ),
            (
                "is_extract",
                ShikumiErrorKind::ONLY_EXTRACT.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_extract())
                    .count(),
            ),
            (
                "is_validation",
                ShikumiErrorKind::ONLY_VALIDATION.len(),
                ShikumiErrorKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_validation())
                    .count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(ShikumiErrorKind::ALL.len(), 7);
    }

    #[test]
    fn shikumi_error_kind_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the seven per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        const ONLY_NOT_FOUND_LEN: usize = ShikumiErrorKind::ONLY_NOT_FOUND.len();
        const ONLY_PARSE_LEN: usize = ShikumiErrorKind::ONLY_PARSE.len();
        const ONLY_WATCH_LEN: usize = ShikumiErrorKind::ONLY_WATCH.len();
        const ONLY_IO_LEN: usize = ShikumiErrorKind::ONLY_IO.len();
        const ONLY_FIGMENT_LEN: usize = ShikumiErrorKind::ONLY_FIGMENT.len();
        const ONLY_EXTRACT_LEN: usize = ShikumiErrorKind::ONLY_EXTRACT.len();
        const ONLY_VALIDATION_LEN: usize = ShikumiErrorKind::ONLY_VALIDATION.len();
        const ALL_LEN: usize = ShikumiErrorKind::ALL.len();
        assert_eq!(ONLY_NOT_FOUND_LEN, 1);
        assert_eq!(ONLY_PARSE_LEN, 1);
        assert_eq!(ONLY_WATCH_LEN, 1);
        assert_eq!(ONLY_IO_LEN, 1);
        assert_eq!(ONLY_FIGMENT_LEN, 1);
        assert_eq!(ONLY_EXTRACT_LEN, 1);
        assert_eq!(ONLY_VALIDATION_LEN, 1);
        assert_eq!(
            ONLY_NOT_FOUND_LEN
                + ONLY_PARSE_LEN
                + ONLY_WATCH_LEN
                + ONLY_IO_LEN
                + ONLY_FIGMENT_LEN
                + ONLY_EXTRACT_LEN
                + ONLY_VALIDATION_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn shikumi_error_kind_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the compound-polarity meta-partition
        // (FIGMENT_BEARING / NOT_FIGMENT_BEARING). The union of the
        // two identity singletons on the figment-bearing pole
        // (ONLY_FIGMENT + ONLY_EXTRACT) equals FIGMENT_BEARING as a
        // sequence in declaration order, and the union of the five
        // not-figment-bearing identity singletons (ONLY_NOT_FOUND +
        // ONLY_PARSE + ONLY_WATCH + ONLY_IO + ONLY_VALIDATION) equals
        // NOT_FIGMENT_BEARING likewise — the interleaved ALL-order
        // projection preserved on the not-figment-bearing pole.
        // A future rearrangement of one meta-partition without the
        // other (say, reclassifying Validation as figment-bearing
        // without updating the identity → compound aggregation)
        // diverges at THIS pin, before drifting through a consumer
        // that materializes one altitude from the other.
        let figment_bearing_from_identity: Vec<ShikumiErrorKind> = [
            ShikumiErrorKind::ONLY_FIGMENT,
            ShikumiErrorKind::ONLY_EXTRACT,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            figment_bearing_from_identity,
            ShikumiErrorKind::FIGMENT_BEARING.to_vec(),
            "identity singleton union on the figment-bearing pole must \
             reproduce FIGMENT_BEARING in declaration order",
        );
        let not_figment_bearing_from_identity: Vec<ShikumiErrorKind> = [
            ShikumiErrorKind::ONLY_NOT_FOUND,
            ShikumiErrorKind::ONLY_PARSE,
            ShikumiErrorKind::ONLY_WATCH,
            ShikumiErrorKind::ONLY_IO,
            ShikumiErrorKind::ONLY_VALIDATION,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            not_figment_bearing_from_identity,
            ShikumiErrorKind::NOT_FIGMENT_BEARING.to_vec(),
            "identity singleton union on the not-figment-bearing pole \
             must reproduce NOT_FIGMENT_BEARING in declaration order",
        );
    }

    #[test]
    fn shikumi_error_kind_not_found_predicate_agrees_with_shikumi_error_is_not_found_pointwise() {
        // Structural bridge between the new kind-side sibling
        // `is_not_found()` on ShikumiErrorKind and the pre-existing
        // tag-side accessor `ShikumiError::is_not_found()`, over the
        // canonical construction table `one_per_kind()`. The existing
        // `kind_agrees_with_is_not_found_pointwise` pin already held
        // the bridge under the closed-equality form
        // (`err.is_not_found() == (err.kind() == ShikumiErrorKind::NotFound)`);
        // consumers now read it through the named predicate at both
        // altitudes without spelling the closed-equality at their own
        // site — matching the shape of
        // `secret_error_kind_shikumi_predicate_agrees_with_as_shikumi_pointwise`
        // on the secret-client kind axis.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.kind().is_not_found(),
                err.is_not_found(),
                "kind-side and tag-side is_not_found must agree on {err:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_kind_parse_predicate_agrees_with_shikumi_error_is_parse_pointwise() {
        // Structural bridge for the Parse corner; peer of
        // `shikumi_error_kind_not_found_predicate_agrees_with_shikumi_error_is_parse_pointwise`
        // on the other pre-existing tag-side sibling.
        for (_, err) in one_per_kind() {
            assert_eq!(
                err.kind().is_parse(),
                err.is_parse(),
                "kind-side and tag-side is_parse must agree on {err:?}",
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
        let err = ShikumiError::Figment(crate::source::synthetic_field_path_error("a.b"));
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
            super::synthetic_parse_error(),
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
                    error: crate::source::synthetic_field_path_error("k"),
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
                super::synthetic_parse_error(),
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
        // through the constant rather than an inline literal — the
        // (applicable, not-applicable) partition is routed through
        // the FieldPathLocalization::is_applicable /
        // is_not_applicable sibling predicates rather than a fresh
        // `matches!` against the variant literals.
        let bearing_side: usize = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_applicable())
            .count();
        let non_bearing_side: usize = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_not_applicable())
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
    fn field_path_localization_is_applicable_true_only_for_applicable_variants() {
        // Per-variant polarity pin on the applicable side of the new
        // FieldPathLocalization::is_applicable sibling predicate.
        // Mirror of `attribution_confidence_is_exact_true_only_for_exact`
        // on the confidence axis and
        // `format_has_shikumi_provider_lisp_and_nix_only` on the
        // format-provenance axis: pins the polarity per variant so a
        // future edit collapsing / rearranging the (applicable,
        // not-applicable) partition fails at the polarity level
        // before drifting through the closed-partition law.
        assert!(FieldPathLocalization::Localized.is_applicable());
        assert!(FieldPathLocalization::FigmentUnlocalized.is_applicable());
        assert!(!FieldPathLocalization::NotApplicable.is_applicable());
    }

    #[test]
    fn field_path_localization_is_not_applicable_true_only_for_not_applicable_variant() {
        // Per-variant polarity pin on the NotApplicable side of the
        // partition. Mirror of
        // `attribution_confidence_is_fallback_true_only_for_fallback`.
        assert!(!FieldPathLocalization::Localized.is_not_applicable());
        assert!(!FieldPathLocalization::FigmentUnlocalized.is_not_applicable());
        assert!(FieldPathLocalization::NotApplicable.is_not_applicable());
    }

    #[test]
    fn field_path_localization_predicates_are_a_closed_binary_partition() {
        // Closed-binary-partition pin on the (applicable,
        // not-applicable) split. Mirror of
        // `attribution_confidence_predicates_are_a_closed_binary_partition`
        // on the confidence axis and
        // `format_provider_class_predicates_are_a_closed_binary_partition`
        // on the format-provenance axis: every ALL cell satisfies
        // exactly one of the two sibling predicates — none satisfies
        // both (a variant claiming to be both applicable and
        // not-applicable at once), none satisfies neither (a variant
        // outside the partition entirely).
        //
        // A future tertiary FieldPathLocalization variant (e.g. a
        // PartiallyLocalized cell for a source that reports a
        // coarse-grained container but no leaf key) would fail this
        // pin by design: the new class must declare its own partition
        // arm — either extend one of the existing predicates to admit
        // it, or introduce a third predicate — rather than silently
        // landing under the negation of one of the existing two.
        for &loc in FieldPathLocalization::ALL {
            let applicable = loc.is_applicable();
            let not_applicable = loc.is_not_applicable();
            assert!(
                applicable ^ not_applicable,
                "{loc:?} must satisfy exactly one of is_applicable / is_not_applicable",
            );
        }
    }

    #[test]
    fn field_path_localization_is_applicable_agrees_with_kind_is_figment_bearing_pointwise() {
        // Cross-axis routing pin: on every ShikumiError in the
        // kind-axis sample table, the localization-axis
        // is_applicable() predicate agrees with the kind-axis
        // is_figment_bearing() predicate. Same realizability
        // invariant that ErrorLocalizationCoordinates::is_realizable
        // holds cell-wise on the 21-cell cube, projected here through
        // the constructible-error surface.
        for (_, err) in one_per_kind() {
            let loc = err.field_path_localization();
            assert_eq!(
                loc.is_applicable(),
                err.kind().is_figment_bearing(),
                "loc.is_applicable() must agree with kind.is_figment_bearing() on {err:?} (loc={loc:?})",
            );
        }
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
        // Cross-primitive invariant: the localization-axis
        // (applicable, not-applicable) partition agrees pointwise with
        // the kind-axis figment-bearing partition — i.e.
        // `loc.is_applicable() == err.kind().is_figment_bearing()`
        // over every constructible error. The two axes are linked by
        // construction and the sibling predicate expresses that link
        // as ONE equality rather than a bipartite match arm.
        for (_, err) in one_per_kind() {
            let loc = err.field_path_localization();
            assert_eq!(
                loc.is_applicable(),
                err.kind().is_figment_bearing(),
                "loc.is_applicable() must agree with kind.is_figment_bearing() ({err:?}, loc={loc:?})",
            );
        }
    }

    #[test]
    fn field_path_localization_is_localized_true_only_for_localized_variant() {
        // Per-variant polarity pin on the Localized corner. Mirror of
        // `attribution_rule_per_variant_predicates_are_true_only_for_their_own_variant`
        // (AttributionRule quintet) and
        // `shikumi_error_kind_is_extract_true_only_for_extract_variant`
        // (ShikumiErrorKind septet): pin what each per-variant sibling
        // returns on every cell of FieldPathLocalization::ALL so a
        // `matches!` arm that silently widened to admit a second
        // variant fails here rather than drifting through every
        // consumer's classification.
        assert!(FieldPathLocalization::Localized.is_localized());
        assert!(!FieldPathLocalization::FigmentUnlocalized.is_localized());
        assert!(!FieldPathLocalization::NotApplicable.is_localized());
    }

    #[test]
    fn field_path_localization_is_figment_unlocalized_true_only_for_figment_unlocalized_variant() {
        // Sibling per-variant polarity pin on the FigmentUnlocalized
        // corner. Same rationale as
        // `field_path_localization_is_localized_true_only_for_localized_variant`.
        assert!(!FieldPathLocalization::Localized.is_figment_unlocalized());
        assert!(FieldPathLocalization::FigmentUnlocalized.is_figment_unlocalized());
        assert!(!FieldPathLocalization::NotApplicable.is_figment_unlocalized());
    }

    #[test]
    fn field_path_localization_per_variant_predicates_are_a_closed_ternary_partition() {
        // Every FieldPathLocalization::ALL cell satisfies exactly one
        // of the three per-variant siblings — none satisfies two, none
        // satisfies zero. Ternary analogue of
        // `attribution_rule_predicates_are_a_closed_quintet_partition`
        // on the rule axis and
        // `config_source_kind_predicates_are_a_closed_ternary_partition`
        // on the layer-kind axis. A future variant landing on
        // FieldPathLocalization without its own sibling arm satisfies
        // zero predicates and fails here, before a consumer silently
        // classifies it under the negation of an existing arm.
        for &loc in FieldPathLocalization::ALL {
            let held = usize::from(loc.is_localized())
                + usize::from(loc.is_figment_unlocalized())
                + usize::from(loc.is_not_applicable());
            assert_eq!(
                held, 1,
                "exactly one per-variant sibling must hold on {loc:?}",
            );
        }
    }

    #[test]
    fn field_path_localization_per_variant_predicates_refine_is_applicable() {
        // Cross-partition refinement law on the (applicable ×
        // not-applicable) meta-axis: the finer per-variant ternary
        // must compose back into the coarser applicable /
        // not-applicable binary exactly. Mirror of
        // `attribution_rule_predicates_refine_confidence` on the rule
        // axis, where the finer quintet composes into the coarser
        // (exact × fallback) confidence binary. A future edit that
        // reclassified `FigmentUnlocalized` under the not-applicable
        // side of `is_applicable` (or reclassified `NotApplicable`
        // under the applicable side) while leaving the per-variant
        // siblings unchanged fails here.
        for &loc in FieldPathLocalization::ALL {
            assert_eq!(
                loc.is_applicable(),
                loc.is_localized() || loc.is_figment_unlocalized(),
                "the applicable meta-cell must be exactly the two per-variant siblings on {loc:?}",
            );
            // The not-applicable meta-cell is stated through the
            // per-variant partition (negation of the applicable side)
            // rather than the equality-with-itself tautology on the
            // shared method: pins that the coarser and finer sides
            // agree that `NotApplicable` is the sole inhabitant of
            // the not-applicable half.
            assert_eq!(
                loc.is_not_applicable(),
                !(loc.is_localized() || loc.is_figment_unlocalized()),
                "the not-applicable meta-cell must be exactly the complement of the applicable siblings on {loc:?}",
            );
        }
    }

    // ---- FieldPathLocalization::APPLICABLE / NOT_APPLICABLE slice constants ----
    //
    // Six pins mirror the per-half meta-partition slice-constant discipline
    // that shipped in `2c0686f` (`ConfigTierKind::COMPUTED / CUSTOM`),
    // `2cf6dd8` (`ConfigSourceKind::DEFAULTS / OVERLAY`), `b2cfa2a`
    // (`SecretOperation::MUTATING / NON_MUTATING`), and the recent
    // closed-binary landings on `AttributionConfidence`, `SecretRefShape`,
    // `FormatProvenance`, `PartitionFace`, `OutputFormat`,
    // `EnvMetadataTagKind`, `FigmentNameTagKind`, `Format::FEATURE_GATED`,
    // and `ShikumiErrorKind::FIGMENT_BEARING` — applied here to the
    // three-way field-localization axis's (applicable × not-applicable)
    // 2/1 compound-polarity meta-partition.

    #[test]
    fn field_path_localization_applicable_slice_agrees_with_is_applicable_predicate() {
        // Bidirectional weld between the slice literal
        // `FieldPathLocalization::APPLICABLE` and the boolean predicate
        // `FieldPathLocalization::is_applicable` on the
        // (applicable × not-applicable) polarity axis. Every slice
        // entry satisfies the applicable pole (and its complement
        // `!is_not_applicable`), and every ALL cell agrees on
        // membership under the boolean predicate. Idiom-peer of
        // `format_feature_gated_slice_agrees_with_is_feature_gated_predicate`
        // (`2013269`) — the two independent declaration surfaces (slice
        // literal + boolean predicate) diverge at THIS pin on the first
        // shape where they disagree, before a consumer that reads one
        // altitude but not the other can observe the drift.
        for loc in FieldPathLocalization::APPLICABLE.iter().copied() {
            assert!(
                loc.is_applicable(),
                "FieldPathLocalization::APPLICABLE entry {loc:?} must satisfy is_applicable()",
            );
            assert!(
                !loc.is_not_applicable(),
                "FieldPathLocalization::APPLICABLE entry {loc:?} must NOT satisfy is_not_applicable()",
            );
        }
        for loc in FieldPathLocalization::NOT_APPLICABLE.iter().copied() {
            assert!(
                loc.is_not_applicable(),
                "FieldPathLocalization::NOT_APPLICABLE entry {loc:?} must satisfy is_not_applicable()",
            );
            assert!(
                !loc.is_applicable(),
                "FieldPathLocalization::NOT_APPLICABLE entry {loc:?} must NOT satisfy is_applicable()",
            );
        }
        for loc in FieldPathLocalization::ALL.iter().copied() {
            assert_eq!(
                FieldPathLocalization::APPLICABLE.contains(&loc),
                loc.is_applicable(),
                "APPLICABLE membership must agree with is_applicable() on FieldPathLocalization::{loc:?}",
            );
            assert_eq!(
                FieldPathLocalization::NOT_APPLICABLE.contains(&loc),
                loc.is_not_applicable(),
                "NOT_APPLICABLE membership must agree with is_not_applicable() on FieldPathLocalization::{loc:?}",
            );
        }
    }

    #[test]
    fn field_path_localization_applicable_and_not_applicable_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `APPLICABLE.len() + NOT_APPLICABLE.len() == ALL.len()` at
        // the slice altitude on the field-localization axis. Idiom-peer
        // of `format_feature_gated_and_always_available_slices_partition_all`
        // (`2013269`) — a variant landing on one slice AND the other,
        // or on neither, breaks the partition here before any consumer
        // that reasons about the polarity as a covering meta-partition
        // observes the drift.
        for loc in FieldPathLocalization::APPLICABLE {
            assert!(
                !FieldPathLocalization::NOT_APPLICABLE.contains(loc),
                "FieldPathLocalization::{loc:?} appears in BOTH APPLICABLE and NOT_APPLICABLE",
            );
        }
        for loc in FieldPathLocalization::ALL {
            let in_applicable = FieldPathLocalization::APPLICABLE.contains(loc);
            let in_not_applicable = FieldPathLocalization::NOT_APPLICABLE.contains(loc);
            assert!(
                in_applicable || in_not_applicable,
                "FieldPathLocalization::{loc:?} is in NEITHER APPLICABLE nor NOT_APPLICABLE",
            );
            assert!(
                !(in_applicable && in_not_applicable),
                "FieldPathLocalization::{loc:?} is in BOTH APPLICABLE and NOT_APPLICABLE",
            );
        }
        assert_eq!(
            FieldPathLocalization::APPLICABLE.len() + FieldPathLocalization::NOT_APPLICABLE.len(),
            FieldPathLocalization::ALL.len(),
            "APPLICABLE and NOT_APPLICABLE slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn field_path_localization_applicable_and_not_applicable_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in FieldPathLocalization::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted the applicable pole
        // ([Self::FigmentUnlocalized, Self::Localized] instead of the
        // ALL-declaration order [Self::Localized,
        // Self::FigmentUnlocalized], say) diverges at THIS pin.
        // Idiom-peer of
        // `format_feature_gated_and_always_available_slices_preserve_all_order`
        // (`2013269`).
        let applicable_from_all: Vec<FieldPathLocalization> = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_applicable())
            .collect();
        assert_eq!(
            applicable_from_all,
            FieldPathLocalization::APPLICABLE.to_vec(),
            "APPLICABLE must be ALL-filtered by is_applicable in declaration order",
        );
        let not_applicable_from_all: Vec<FieldPathLocalization> = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_not_applicable())
            .collect();
        assert_eq!(
            not_applicable_from_all,
            FieldPathLocalization::NOT_APPLICABLE.to_vec(),
            "NOT_APPLICABLE must be ALL-filtered by is_not_applicable in declaration order",
        );
    }

    #[test]
    fn field_path_localization_applicable_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into APPLICABLE, an accidental re-add of an already-present
        // cell into NOT_APPLICABLE) fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a set.
        for slice in [
            FieldPathLocalization::APPLICABLE,
            FieldPathLocalization::NOT_APPLICABLE,
        ] {
            let mut seen: Vec<FieldPathLocalization> = Vec::with_capacity(slice.len());
            for loc in slice {
                assert!(
                    !seen.contains(loc),
                    "FieldPathLocalization slice {slice:?} contains duplicate entry {loc:?}",
                );
                seen.push(*loc);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn field_path_localization_applicable_and_not_applicable_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on FieldPathLocalization::ALL —
        // i.e., `APPLICABLE.len() ==
        // ALL.iter().filter(is_applicable).count()` and
        // `NOT_APPLICABLE.len() ==
        // ALL.iter().filter(is_not_applicable).count()` — the
        // cardinality projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete
        // positions today: 2 applicable + 1 not-applicable = 3 = ALL.
        // Idiom-peer of
        // `format_feature_gated_and_always_available_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`2013269`).
        let applicable_count = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_applicable())
            .count();
        let not_applicable_count = FieldPathLocalization::ALL
            .iter()
            .copied()
            .filter(|loc| loc.is_not_applicable())
            .count();
        assert_eq!(
            FieldPathLocalization::APPLICABLE.len(),
            applicable_count,
            "APPLICABLE.len() must match the is_applicable count on ALL",
        );
        assert_eq!(
            FieldPathLocalization::NOT_APPLICABLE.len(),
            not_applicable_count,
            "NOT_APPLICABLE.len() must match the is_not_applicable count on ALL",
        );
        assert_eq!(FieldPathLocalization::APPLICABLE.len(), 2);
        assert_eq!(FieldPathLocalization::NOT_APPLICABLE.len(), 1);
        assert_eq!(FieldPathLocalization::ALL.len(), 3);
    }

    #[test]
    fn field_path_localization_applicable_and_not_applicable_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `format_feature_gated_and_always_available_slices_are_const_addressable`
        // (`2013269`).
        const APPLICABLE_LEN: usize = FieldPathLocalization::APPLICABLE.len();
        const NOT_APPLICABLE_LEN: usize = FieldPathLocalization::NOT_APPLICABLE.len();
        const ALL_LEN: usize = FieldPathLocalization::ALL.len();
        assert_eq!(APPLICABLE_LEN, 2);
        assert_eq!(NOT_APPLICABLE_LEN, 1);
        assert_eq!(APPLICABLE_LEN + NOT_APPLICABLE_LEN, ALL_LEN);
    }

    // ---- FieldPathLocalization::ONLY_LOCALIZED / ONLY_FIGMENT_UNLOCALIZED
    // / ONLY_NOT_APPLICABLE identity slice constants ----
    //
    // Seven pins mirror the per-half meta-partition slice-constant
    // discipline that shipped for AttributionRule's own identity
    // meta-partition (`9ac2fcb`), applied here to the three-way
    // field-path-localization axis's (localized × figment-unlocalized ×
    // not-applicable) 1/1/1 identity meta-partition. Ternary peer of the
    // shipped ternary identity landing on the figment-Source-axis kind
    // (`FigmentSourceKind::FILE / CODE / CUSTOM`, `723060b`) two altitudes
    // over and the shipped ternary compound-polarity landing on the
    // attribution-rule axis (`AttributionRule::LAYER_FILE / LAYER_ENV /
    // LAYER_DEFAULTS`, `fae8271`) one altitude over. Directly nominated
    // by the (applicable × not-applicable) compound-polarity APPLICABLE /
    // NOT_APPLICABLE landing (`9dad33d`) — the identity refinement is the
    // next rung of the same discipline on this axis.

    #[test]
    fn field_path_localization_identity_slices_agree_with_identity_predicates() {
        // Three-way agreement pin across the (localized ×
        // figment-unlocalized × not-applicable) identity meta-partition.
        // Every ONLY_LOCALIZED entry satisfies is_localized and neither
        // is_figment_unlocalized nor is_not_applicable; every
        // ONLY_FIGMENT_UNLOCALIZED entry satisfies is_figment_unlocalized
        // alone; every ONLY_NOT_APPLICABLE entry satisfies
        // is_not_applicable alone. Every FieldPathLocalization::ALL cell
        // agrees on membership under each of the three boolean
        // predicates. The two independent declaration surfaces (slice
        // literals + boolean predicates) diverge at THIS pin on the
        // first shape where they disagree, before a consumer that reads
        // one altitude but not the other can observe the drift.
        for loc in FieldPathLocalization::ONLY_LOCALIZED.iter().copied() {
            assert!(
                loc.is_localized(),
                "ONLY_LOCALIZED {loc:?} must satisfy is_localized",
            );
            assert!(
                !loc.is_figment_unlocalized(),
                "ONLY_LOCALIZED {loc:?} must NOT satisfy is_figment_unlocalized",
            );
            assert!(
                !loc.is_not_applicable(),
                "ONLY_LOCALIZED {loc:?} must NOT satisfy is_not_applicable",
            );
        }
        for loc in FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED
            .iter()
            .copied()
        {
            assert!(
                loc.is_figment_unlocalized(),
                "ONLY_FIGMENT_UNLOCALIZED {loc:?} must satisfy is_figment_unlocalized",
            );
            assert!(
                !loc.is_localized(),
                "ONLY_FIGMENT_UNLOCALIZED {loc:?} must NOT satisfy is_localized",
            );
            assert!(
                !loc.is_not_applicable(),
                "ONLY_FIGMENT_UNLOCALIZED {loc:?} must NOT satisfy is_not_applicable",
            );
        }
        for loc in FieldPathLocalization::ONLY_NOT_APPLICABLE.iter().copied() {
            assert!(
                loc.is_not_applicable(),
                "ONLY_NOT_APPLICABLE {loc:?} must satisfy is_not_applicable",
            );
            assert!(
                !loc.is_localized(),
                "ONLY_NOT_APPLICABLE {loc:?} must NOT satisfy is_localized",
            );
            assert!(
                !loc.is_figment_unlocalized(),
                "ONLY_NOT_APPLICABLE {loc:?} must NOT satisfy is_figment_unlocalized",
            );
        }
        for loc in FieldPathLocalization::ALL.iter().copied() {
            assert_eq!(
                FieldPathLocalization::ONLY_LOCALIZED.contains(&loc),
                loc.is_localized(),
                "ONLY_LOCALIZED membership must agree with is_localized() on FieldPathLocalization::{loc:?}",
            );
            assert_eq!(
                FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED.contains(&loc),
                loc.is_figment_unlocalized(),
                "ONLY_FIGMENT_UNLOCALIZED membership must agree with is_figment_unlocalized() on FieldPathLocalization::{loc:?}",
            );
            assert_eq!(
                FieldPathLocalization::ONLY_NOT_APPLICABLE.contains(&loc),
                loc.is_not_applicable(),
                "ONLY_NOT_APPLICABLE membership must agree with is_not_applicable() on FieldPathLocalization::{loc:?}",
            );
        }
    }

    #[test]
    fn field_path_localization_identity_slices_partition_all() {
        // Ternary partition invariant: the three per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_LOCALIZED.len() + ONLY_FIGMENT_UNLOCALIZED.len() +
        //  ONLY_NOT_APPLICABLE.len() == ALL.len()` at the slice altitude
        // on the field-localization axis.
        let identity_slices: [&[FieldPathLocalization]; 3] = [
            FieldPathLocalization::ONLY_LOCALIZED,
            FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED,
            FieldPathLocalization::ONLY_NOT_APPLICABLE,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for loc in left.iter() {
                    assert!(
                        !right.contains(loc),
                        "FieldPathLocalization::{loc:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for loc in FieldPathLocalization::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&loc)))
                .sum();
            assert_eq!(
                held, 1,
                "FieldPathLocalization::{loc:?} must appear in exactly one identity \
                 slice (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            FieldPathLocalization::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn field_path_localization_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in FieldPathLocalization::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. Trivially
        // true today because each identity slice is a singleton, but
        // the shape catches a hypothetical multi-cell future variant
        // reshuffle on the same axis (say a `PartiallyLocalized` cell
        // landing under is_localized) that landed in an order not
        // matching ALL's declaration order.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<FieldPathLocalization> = FieldPathLocalization::ALL
                    .iter()
                    .copied()
                    .filter(|loc| loc.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(FieldPathLocalization::ONLY_LOCALIZED, is_localized);
        pin!(
            FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED,
            is_figment_unlocalized
        );
        pin!(
            FieldPathLocalization::ONLY_NOT_APPLICABLE,
            is_not_applicable
        );
    }

    #[test]
    fn field_path_localization_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all three per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting through
        // any consumer that iterates the slice expecting a set.
        for slice in [
            FieldPathLocalization::ONLY_LOCALIZED,
            FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED,
            FieldPathLocalization::ONLY_NOT_APPLICABLE,
        ] {
            let mut seen: Vec<FieldPathLocalization> = Vec::with_capacity(slice.len());
            for loc in slice {
                assert!(
                    !seen.contains(loc),
                    "FieldPathLocalization identity slice {slice:?} contains \
                     duplicate entry {loc:?}",
                );
                seen.push(*loc);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn field_path_localization_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on FieldPathLocalization::ALL —
        // i.e., `ONLY_LOCALIZED.len() ==
        // ALL.iter().filter(is_localized).count()` (and symmetric for
        // the two siblings) — the cardinality projection at the slice
        // altitude agrees with the boolean-altitude projection on all
        // three halves. Concrete positions today: 1 + 1 + 1 = 3 = ALL.
        let counts = [
            (
                "is_localized",
                FieldPathLocalization::ONLY_LOCALIZED.len(),
                FieldPathLocalization::ALL
                    .iter()
                    .copied()
                    .filter(|loc| loc.is_localized())
                    .count(),
            ),
            (
                "is_figment_unlocalized",
                FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED.len(),
                FieldPathLocalization::ALL
                    .iter()
                    .copied()
                    .filter(|loc| loc.is_figment_unlocalized())
                    .count(),
            ),
            (
                "is_not_applicable",
                FieldPathLocalization::ONLY_NOT_APPLICABLE.len(),
                FieldPathLocalization::ALL
                    .iter()
                    .copied()
                    .filter(|loc| loc.is_not_applicable())
                    .count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(FieldPathLocalization::ALL.len(), 3);
    }

    #[test]
    fn field_path_localization_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the three per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        const ONLY_LOCALIZED_LEN: usize = FieldPathLocalization::ONLY_LOCALIZED.len();
        const ONLY_FIGMENT_UNLOCALIZED_LEN: usize =
            FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED.len();
        const ONLY_NOT_APPLICABLE_LEN: usize = FieldPathLocalization::ONLY_NOT_APPLICABLE.len();
        const ALL_LEN: usize = FieldPathLocalization::ALL.len();
        assert_eq!(ONLY_LOCALIZED_LEN, 1);
        assert_eq!(ONLY_FIGMENT_UNLOCALIZED_LEN, 1);
        assert_eq!(ONLY_NOT_APPLICABLE_LEN, 1);
        assert_eq!(
            ONLY_LOCALIZED_LEN + ONLY_FIGMENT_UNLOCALIZED_LEN + ONLY_NOT_APPLICABLE_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn field_path_localization_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the shipped compound-polarity meta-partition on
        // the same axis (APPLICABLE / NOT_APPLICABLE, `9dad33d`). For
        // every compound-polarity slice, the union of the identity
        // singletons whose sole variant sits on that pole equals the
        // shipped slice as a sequence in declaration order. A future
        // rearrangement of one meta-partition without the other (say,
        // reclassifying FigmentUnlocalized under the not-applicable
        // side without updating the identity → compound aggregation)
        // diverges at THIS pin, before drifting through a consumer that
        // materializes one altitude from the other.

        // Applicable pole covers the two figment-bearing variants in
        // declaration order (Localized, FigmentUnlocalized).
        let applicable_from_identity: Vec<FieldPathLocalization> = [
            FieldPathLocalization::ONLY_LOCALIZED,
            FieldPathLocalization::ONLY_FIGMENT_UNLOCALIZED,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            applicable_from_identity,
            FieldPathLocalization::APPLICABLE.to_vec(),
            "identity singleton union on the applicable pole must reproduce \
             APPLICABLE in declaration order",
        );

        // Not-applicable pole is a singleton at today's cardinality, so
        // the identity singleton ONLY_NOT_APPLICABLE agrees with the
        // compound-polarity slice NOT_APPLICABLE as bare slice equality
        // — the same identity ↔ compound coincidence AttributionRule
        // records between ONLY_DEFAULTS_BY_CODE_UNIQUENESS and
        // LAYER_DEFAULTS on the ternary layer-kind projection
        // (`9ac2fcb`). A future variant landing on the not-applicable
        // side would extend NOT_APPLICABLE but leave ONLY_NOT_APPLICABLE
        // unchanged, and the two would diverge at THIS pin.
        assert_eq!(
            FieldPathLocalization::ONLY_NOT_APPLICABLE.to_vec(),
            FieldPathLocalization::NOT_APPLICABLE.to_vec(),
            "the singleton identity slice on NotApplicable must \
             reproduce NOT_APPLICABLE exactly",
        );
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

    #[test]
    fn attribution_rule_metadata_axis_is_const_callable() {
        // Weld the const-callability of the (rule → metadata-axis)
        // projection `AttributionRule::metadata_axis` with the two
        // sibling coordinate projections on the same `impl
        // AttributionRule` block — `AttributionRule::confidence`
        // (const since it was introduced) and `AttributionRule::layer_kind`
        // (const since `52c4a20`) — at compile time. Mirrors the
        // shape of `attribution_rule_layer_kind_is_const_callable`
        // (`52c4a20`) / `config_tier_name_is_const_callable`
        // (`29a2f34`) / `provenance_new_seam_is_const_callable`
        // (`422cc76`) on the shikumi-crate-wide const-callability
        // discipline over the closed-primitive projection surface: a
        // compile-time-known `AttributionRule` projects all three
        // orthogonal coordinates (`metadata_axis` on the
        // source × name axis, `layer_kind` on the
        // file × env × defaults axis, `confidence` on the exact ×
        // fallback axis) at compile time too — the three projections
        // now live at the same const-callability altitude, so a
        // static per-rule coordinate table wired through any of the
        // three stays wired to compile-time evaluation across the
        // whole triple.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through the const-fn `metadata_axis` projection in
        // const position. The moment `AttributionRule::metadata_axis`
        // loses its const-ness (a future edit that reaches for a
        // non-const helper — a lookup through a runtime table, a
        // `String`-shaped intermediate, an allocator on the mapping
        // path — inside the five-arm exhaustive match) one of the
        // five `const` welds below fails to compile at THAT line
        // before the drift can reach downstream consumers that
        // assumed const-ness through the projection, and the five
        // pointwise pins catch a future edit that shifted the
        // rule → axis mapping off the source × name partition
        // before it drifts through observers that read the projection.
        const FILE_BY_SOURCE: AttributionAxis = AttributionRule::FileBySource.metadata_axis();
        const FILE_BY_METADATA_NAME: AttributionAxis =
            AttributionRule::FileByMetadataName.metadata_axis();
        const ENV_BY_PREFIX: AttributionAxis = AttributionRule::EnvByPrefix.metadata_axis();
        const ENV_BY_UNIQUENESS: AttributionAxis = AttributionRule::EnvByUniqueness.metadata_axis();
        const DEFAULTS_BY_CODE_UNIQUENESS: AttributionAxis =
            AttributionRule::DefaultsByCodeUniqueness.metadata_axis();

        assert_eq!(FILE_BY_SOURCE, AttributionAxis::MetadataSource);
        assert_eq!(FILE_BY_METADATA_NAME, AttributionAxis::MetadataName);
        assert_eq!(ENV_BY_PREFIX, AttributionAxis::MetadataName);
        assert_eq!(ENV_BY_UNIQUENESS, AttributionAxis::MetadataName);
        assert_eq!(DEFAULTS_BY_CODE_UNIQUENESS, AttributionAxis::MetadataSource);

        // Cross-check: the const-fn projection stays pointwise equal
        // on every rule in `Self::ALL` to the runtime-side
        // `rule.metadata_axis()` call — the const-context weld only
        // exercises the five variants named at const-binding sites,
        // but the runtime pin threads the full closed list through
        // the same projection to catch a future variant landing
        // whose const-context weld was forgotten upstream.
        for (rule, expected) in [
            (AttributionRule::FileBySource, FILE_BY_SOURCE),
            (AttributionRule::FileByMetadataName, FILE_BY_METADATA_NAME),
            (AttributionRule::EnvByPrefix, ENV_BY_PREFIX),
            (AttributionRule::EnvByUniqueness, ENV_BY_UNIQUENESS),
            (
                AttributionRule::DefaultsByCodeUniqueness,
                DEFAULTS_BY_CODE_UNIQUENESS,
            ),
        ] {
            assert_eq!(rule.metadata_axis(), expected, "rule {rule:?}");
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
                rule.metadata_axis().is_metadata_source(),
                "rule {rule:?}: figment_source_kind.is_some() must equal \
                 metadata_axis().is_metadata_source()",
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
    fn attribution_rule_figment_source_kind_is_const_callable() {
        // Weld the const-callability of the (rule → figment-source-kind)
        // partial projection at compile time. Peer of the sibling
        // const-callable welds on the same `impl AttributionRule` block
        // — `attribution_rule_layer_predicates_are_const_callable`
        // (layer axis), `attribution_rule_metadata_axis_predicates_are_const_callable`
        // (metadata axis), `attribution_rule_confidence_is_const_callable`
        // where present — lifted to the partial-projection altitude
        // where the codomain is `Option<FigmentSourceKind>` rather than
        // a `bool`.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through the partial projection in const position.
        // The moment the projection (or the routed
        // `FigmentSourceKind::{File,Code}` variant construction, or the
        // routed `Option::{Some,None}` construction) stops being
        // const-callable, one of the five `const` welds below fails to
        // compile at THAT line before the drift can reach downstream
        // consumers that assumed const-ness through the projection — a
        // `static PER_RULE: [Option<FigmentSourceKind>;
        // AttributionRule::ALL.len()]` per-rule figment-source-kind
        // lookup, an attestation manifest carrying the (rule →
        // figment-source-kind) partial map at compile time, a `const`
        // sentinel for a compile-time-known rule's figment-source-kind
        // cell.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const FSK_FBS: Option<FigmentSourceKind> = R_FBS.figment_source_kind();
        const FSK_FBM: Option<FigmentSourceKind> = R_FBM.figment_source_kind();
        const FSK_EBP: Option<FigmentSourceKind> = R_EBP.figment_source_kind();
        const FSK_EBU: Option<FigmentSourceKind> = R_EBU.figment_source_kind();
        const FSK_DBCU: Option<FigmentSourceKind> = R_DBCU.figment_source_kind();

        // Pointwise: the (Some(File), Some(Code), None×3) partition
        // places each of the five rules under exactly one Option cell
        // — the two source-axis rules on the `Some` half (naming the
        // File / Code cells) and the three name-axis rules on the
        // `None` half. The const-context welds above prove
        // const-callability; the pins below prove the mapping stays
        // agreed with the exhaustive match in `figment_source_kind` —
        // a future edit that shifted a rule off its source-kind
        // classification diverges here first, not at a downstream
        // reader of a stale (rule → figment-source-kind) mapping.
        assert_eq!(FSK_FBS, Some(FigmentSourceKind::File));
        assert_eq!(FSK_FBM, None);
        assert_eq!(FSK_EBP, None);
        assert_eq!(FSK_EBU, None);
        assert_eq!(FSK_DBCU, Some(FigmentSourceKind::Code));

        // Full-list pin: iterate `AttributionRule::ALL` against the
        // same expected sequence so a future variant landing on
        // `AttributionRule` without a corresponding update here fails
        // at the length check, mirroring the `ALL`-length pins on the
        // sibling axis-partition tests.
        let expected: [Option<FigmentSourceKind>; AttributionRule::ALL.len()] =
            [FSK_FBS, FSK_FBM, FSK_EBP, FSK_EBU, FSK_DBCU];
        for (rule, expected_kind) in AttributionRule::ALL.iter().copied().zip(expected) {
            assert_eq!(
                rule.figment_source_kind(),
                expected_kind,
                "rule {rule:?}: figment_source_kind must match its const-context weld",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_is_const_callable() {
        // Sibling of `attribution_rule_figment_source_kind_is_const_callable`
        // on the figment-`Metadata::name`-axis partial projection: welds
        // the const-callability of the (rule → figment-name-tag-kind)
        // projection at compile time. Together they complete the
        // (source-axis, name-axis) partial-projection pair at const
        // altitude, mirroring the earlier total-projection welds on the
        // same `impl AttributionRule` block
        // (`attribution_rule_layer_predicates_are_const_callable`,
        // `attribution_rule_metadata_axis_predicates_are_const_callable`)
        // but lifted to the partial-projection altitude where the
        // codomain is `Option<FigmentNameTagKind>` rather than a `bool`.
        //
        // A `const` binding routes each of the five `AttributionRule`
        // variants through the partial projection in const position.
        // The moment the projection (or the routed
        // `FigmentNameTagKind::{Format,Env}` variant construction, or
        // the routed `Option::{Some,None}` construction) stops being
        // const-callable, one of the five `const` welds below fails to
        // compile at THAT line before the drift can reach downstream
        // consumers that assumed const-ness through the projection — a
        // `static PER_RULE: [Option<FigmentNameTagKind>;
        // AttributionRule::ALL.len()]` per-rule figment-name-tag-kind
        // lookup, an attestation manifest carrying the (rule →
        // figment-name-tag-kind) partial map at compile time, a `const`
        // sentinel for a compile-time-known rule's figment-name-tag-kind
        // cell.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const FNTK_FBS: Option<FigmentNameTagKind> = R_FBS.figment_name_tag_kind();
        const FNTK_FBM: Option<FigmentNameTagKind> = R_FBM.figment_name_tag_kind();
        const FNTK_EBP: Option<FigmentNameTagKind> = R_EBP.figment_name_tag_kind();
        const FNTK_EBU: Option<FigmentNameTagKind> = R_EBU.figment_name_tag_kind();
        const FNTK_DBCU: Option<FigmentNameTagKind> = R_DBCU.figment_name_tag_kind();

        // Pointwise: the (Some(Format), Some(Env)×2, None×2) partition
        // places each of the five rules under exactly one Option cell
        // — the three name-axis rules on the `Some` half (with
        // FileByMetadataName naming the Format cell and both env-axis
        // rules naming the Env cell) and the two source-axis rules on
        // the `None` half. Dual of the (Some(File), Some(Code), None×3)
        // partition pinned by the sibling weld on
        // `figment_source_kind`: the two Options are strict complements
        // over the rule space, exactly one `Some` per rule
        // (`attribution_rule_figment_name_tag_kind_xor_figment_source_kind`
        // holds this contract at runtime). The const-context welds
        // above prove const-callability; the pins below prove the
        // mapping stays agreed with the exhaustive match in
        // `figment_name_tag_kind` — a future edit that shifted a rule
        // off its name-tag-kind classification diverges here first, not
        // at a downstream reader of a stale (rule →
        // figment-name-tag-kind) mapping.
        assert_eq!(FNTK_FBS, None);
        assert_eq!(FNTK_FBM, Some(FigmentNameTagKind::Format));
        assert_eq!(FNTK_EBP, Some(FigmentNameTagKind::Env));
        assert_eq!(FNTK_EBU, Some(FigmentNameTagKind::Env));
        assert_eq!(FNTK_DBCU, None);

        // Full-list pin: iterate `AttributionRule::ALL` against the
        // same expected sequence so a future variant landing on
        // `AttributionRule` without a corresponding update here fails
        // at the length check, mirroring the `ALL`-length pins on the
        // sibling axis-partition tests.
        let expected: [Option<FigmentNameTagKind>; AttributionRule::ALL.len()] =
            [FNTK_FBS, FNTK_FBM, FNTK_EBP, FNTK_EBU, FNTK_DBCU];
        for (rule, expected_kind) in AttributionRule::ALL.iter().copied().zip(expected) {
            assert_eq!(
                rule.figment_name_tag_kind(),
                expected_kind,
                "rule {rule:?}: figment_name_tag_kind must match its const-context weld",
            );
        }

        // Cross-projection pin: the two partial projections partition
        // the rule space by the `Some-iff-axis` invariant — exactly
        // one of (`figment_source_kind`, `figment_name_tag_kind`)
        // returns `Some` per rule. The two const-context weld arrays
        // agree with that partition at compile time, so a future edit
        // that made two variants Some on the same axis (or both None
        // on both axes) diverges here at the const-context pair
        // before drifting through the sibling runtime XOR pin.
        const FSK_FBS: Option<FigmentSourceKind> = R_FBS.figment_source_kind();
        const FSK_FBM: Option<FigmentSourceKind> = R_FBM.figment_source_kind();
        const FSK_EBP: Option<FigmentSourceKind> = R_EBP.figment_source_kind();
        const FSK_EBU: Option<FigmentSourceKind> = R_EBU.figment_source_kind();
        const FSK_DBCU: Option<FigmentSourceKind> = R_DBCU.figment_source_kind();
        assert!(FSK_FBS.is_some() ^ FNTK_FBS.is_some());
        assert!(FSK_FBM.is_some() ^ FNTK_FBM.is_some());
        assert!(FSK_EBP.is_some() ^ FNTK_EBP.is_some());
        assert!(FSK_EBU.is_some() ^ FNTK_EBU.is_some());
        assert!(FSK_DBCU.is_some() ^ FNTK_DBCU.is_some());
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
                attr.metadata_axis().is_metadata_source(),
                "envelope for rule {rule:?}: figment_source_kind.is_some() must equal \
                 metadata_axis().is_metadata_source()",
            );
        }
    }

    // ---- AttributionRule::figment_name_tag_kind / envelope mirror ----
    //
    // The (rule → figment-name-tag-kind) partial projection: name-axis
    // rules pin a FigmentNameTagKind cell at the type level
    // (FileByMetadataName → Format; EnvByPrefix / EnvByUniqueness → Env);
    // source-axis rules pin none. Symmetric peer of the
    // (rule → figment-source-kind) suite above.

    #[test]
    fn attribution_rule_figment_name_tag_kind_some_for_file_by_metadata_name() {
        // FileByMetadataName dispatches off the shikumi-built provider's
        // "<format>: <path>" metadata-name shape, classifying via
        // FigmentNameTag::Format — so the rule's identity already pins
        // FigmentNameTagKind::Format.
        assert_eq!(
            AttributionRule::FileByMetadataName.figment_name_tag_kind(),
            Some(FigmentNameTagKind::Format),
        );
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_some_for_env_by_prefix() {
        // EnvByPrefix dispatches off figment's
        // "`PREFIX` environment variable(s)" metadata-name shape,
        // classifying via FigmentNameTag::Env with EnvMetadataTag::Prefixed —
        // so the rule's identity already pins FigmentNameTagKind::Env.
        assert_eq!(
            AttributionRule::EnvByPrefix.figment_name_tag_kind(),
            Some(FigmentNameTagKind::Env),
        );
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_some_for_env_by_uniqueness() {
        // EnvByUniqueness dispatches off an env-shaped metadata-name
        // (either prefixed without a chain match, or bare), classifying
        // via FigmentNameTag::Env — so the rule's identity already pins
        // FigmentNameTagKind::Env.
        assert_eq!(
            AttributionRule::EnvByUniqueness.figment_name_tag_kind(),
            Some(FigmentNameTagKind::Env),
        );
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_none_for_source_axis_rules() {
        // The two source-axis rules dispatch off `metadata.source`, not
        // `metadata.name`, so the rule's identity does not pin a
        // FigmentNameTagKind cell — return None for both.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_eq!(
                rule.figment_name_tag_kind(),
                None,
                "source-axis rule {rule:?} must not pin a FigmentNameTagKind",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // Option<FigmentNameTagKind> cell. Pins the partition contract
        // that AttributionRule::figment_name_tag_kind is a total function
        // over the rule space (returning a partial projection); a
        // future variant added to AttributionRule forces an assignment
        // in the exhaustive match (compile-time), and this test pins
        // the resulting partition (test-time). Symmetric peer of
        // `attribution_rule_figment_source_kind_partitions_every_variant`.
        let cases = [
            (AttributionRule::FileBySource, None),
            (
                AttributionRule::FileByMetadataName,
                Some(FigmentNameTagKind::Format),
            ),
            (AttributionRule::EnvByPrefix, Some(FigmentNameTagKind::Env)),
            (
                AttributionRule::EnvByUniqueness,
                Some(FigmentNameTagKind::Env),
            ),
            (AttributionRule::DefaultsByCodeUniqueness, None),
        ];
        for (rule, expected) in cases {
            assert_eq!(rule.figment_name_tag_kind(), expected, "rule {rule:?}");
        }
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_some_iff_metadata_axis_name() {
        // Structural composition law: figment_name_tag_kind is Some
        // exactly when metadata_axis is MetadataName. The dual of
        // `attribution_rule_figment_source_kind_some_iff_metadata_axis_source`
        // on the name axis; together the two biconditionals pin that
        // every rule's identity dispatches on exactly one figment-metadata
        // axis (the AttributionAxis::ALL bi-partition: every rule has
        // exactly one MetadataSource-or-MetadataName label).
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.figment_name_tag_kind().is_some(),
                rule.metadata_axis().is_metadata_name(),
                "rule {rule:?}: figment_name_tag_kind.is_some() must equal \
                 metadata_axis().is_metadata_name()",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_image_equals_figment_name_tag_kind_all() {
        // Image of figment_name_tag_kind over the rule space, dropping
        // None returns, equals FigmentNameTagKind::ALL exactly — every
        // recognized name-axis kind (Format from FileByMetadataName, Env
        // from EnvByPrefix / EnvByUniqueness) is reachable through some
        // name-axis rule, and no rule projects outside FigmentNameTagKind::ALL.
        // Pins the surjectivity of the partial projection onto the
        // figment-name-tag-kind space. Peer to
        // `attribution_rule_file_provenance_image_equals_format_provenance_all`
        // for the file-provenance axis, and the dual of
        // `attribution_rule_figment_source_kind_image_is_file_and_code_only`
        // on the source-axis (where Custom remains unreached today).
        use std::collections::HashSet;
        let observed: HashSet<FigmentNameTagKind> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::figment_name_tag_kind)
            .collect();
        let expected: HashSet<FigmentNameTagKind> =
            FigmentNameTagKind::ALL.iter().copied().collect();
        assert_eq!(
            observed, expected,
            "image of figment_name_tag_kind over AttributionRule::ALL must equal \
             FigmentNameTagKind::ALL; got: {observed:?}",
        );
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_xor_figment_source_kind() {
        // Cross-axis partition law: every rule's identity dispatches on
        // exactly one figment-metadata axis, so for every rule exactly
        // one of figment_source_kind and figment_name_tag_kind returns
        // Some. The two partial projections together cover the rule
        // space disjointly. Strictly stronger than the two per-axis
        // biconditionals: pins the bi-partition of the rule space across
        // both figment-metadata axes at one site, mirroring
        // `attribution_axis_all_covers_failing_source_attribution_axes`
        // on the (MetadataSource vs MetadataName) partition.
        for rule in AttributionRule::ALL.iter().copied() {
            let src_some = rule.figment_source_kind().is_some();
            let name_some = rule.figment_name_tag_kind().is_some();
            assert!(
                src_some ^ name_some,
                "rule {rule:?}: exactly one of figment_source_kind / \
                 figment_name_tag_kind must be Some (got src_some={src_some}, \
                 name_some={name_some})",
            );
        }
    }

    // ---- AttributionRule rule-altitude sibling delegators on the two
    // ---- partial figment-metadata projections
    // ----
    // Peers of the rule-altitude sibling grids on the two total
    // projections (`is_file_layer` / `is_env_layer` / `is_defaults_layer`
    // on `layer_kind()`; `is_metadata_source_axis` / `is_metadata_name_axis`
    // on `metadata_axis()`), lifted through the partial-Option shape of
    // `figment_source_kind()` / `figment_name_tag_kind()` — the delegator
    // is `false` on the whole complementary axis (where the outer
    // `Option` is `None`), matching the `Some-iff-attribution`
    // discipline already documented on the partial projections.

    #[test]
    fn attribution_rule_is_figment_source_file_agrees_with_figment_source_kind_is_file() {
        // Per-corner routing-agreement pin on the File corner of the
        // figment-Source-axis projection. The rule-altitude delegator
        // is a thin lift of `self.figment_source_kind().is_some_and(
        // FigmentSourceKind::is_file)`; the two entry points cannot
        // drift. Mirrors `attribution_rule_is_file_layer_agrees_with_layer_kind_is_file`
        // on the layer-kind projection, lifted through the partial
        // `Option<_>` shape of the source-axis projection.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_figment_source_file(),
                rule.figment_source_kind()
                    .is_some_and(FigmentSourceKind::is_file),
                "is_figment_source_file must route through \
                 figment_source_kind().is_some_and(is_file) on {rule:?}",
            );
            assert_eq!(
                rule.is_figment_source_file(),
                rule.figment_source_kind() == Some(FigmentSourceKind::File),
                "is_figment_source_file must agree with figment_source_kind == Some(File) on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_figment_source_code_agrees_with_figment_source_kind_is_code() {
        // Sibling of the File-corner routing pin, on the Code corner.
        // Same twofold routing shape (delegator == is_some_and(is_code)
        // and delegator == Option<_> equality).
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_figment_source_code(),
                rule.figment_source_kind()
                    .is_some_and(FigmentSourceKind::is_code),
                "is_figment_source_code must route through \
                 figment_source_kind().is_some_and(is_code) on {rule:?}",
            );
            assert_eq!(
                rule.is_figment_source_code(),
                rule.figment_source_kind() == Some(FigmentSourceKind::Code),
                "is_figment_source_code must agree with figment_source_kind == Some(Code) on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_figment_source_custom_agrees_with_figment_source_kind_is_custom() {
        // Sibling of the File / Code corner routing pins, on the Custom
        // corner. Same twofold routing shape; the polarity per rule
        // happens to be `false` on every currently-recognized rule
        // (see `attribution_rule_is_figment_source_custom_never_holds`)
        // but the routing pin does not depend on the image being empty
        // — it pins the delegator's contract independently of which
        // rules currently inhabit the Custom cell.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_figment_source_custom(),
                rule.figment_source_kind()
                    .is_some_and(FigmentSourceKind::is_custom),
                "is_figment_source_custom must route through \
                 figment_source_kind().is_some_and(is_custom) on {rule:?}",
            );
            assert_eq!(
                rule.is_figment_source_custom(),
                rule.figment_source_kind() == Some(FigmentSourceKind::Custom),
                "is_figment_source_custom must agree with figment_source_kind == Some(Custom) on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_figment_source_custom_never_holds() {
        // Image-emptiness pin on the Custom cell: no recognized
        // AttributionRule currently dispatches off Source::Custom, so
        // the delegator returns false on every variant. Documented on
        // `figment_source_kind` and pinned image-side by
        // `attribution_rule_figment_source_kind_image_is_file_and_code_only`
        // — this test surfaces the same fact through the rule-altitude
        // predicate. A future custom-source rule landing (the enum's
        // doc names it as a future direction) makes at least one
        // variant return true here, forcing this test to be replaced
        // with a per-variant polarity pin against the new arm.
        for rule in AttributionRule::ALL.iter().copied() {
            assert!(
                !rule.is_figment_source_custom(),
                "no recognized rule dispatches off Source::Custom yet, but {rule:?} returned true",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_source_kind_predicates_partition_source_axis_rules() {
        // Some-iff-source-axis disjoint-partition pin: the three
        // source-axis sibling delegators sum to exactly one on every
        // source-axis rule (metadata_axis == MetadataSource, the outer
        // Option is Some) and exactly zero on every name-axis rule
        // (metadata_axis == MetadataName, the outer Option is None).
        // The rule-altitude analogue of
        // `figment_source_kind_predicates_are_a_closed_ternary_partition`
        // (the closed ternary partition on the FigmentSourceKind axis
        // itself, if named there) lifted through the partial-Option
        // shape. A future custom-source rule landing (Some(Custom))
        // still keeps the sum at 1 on the source-axis side; a future
        // rule dispatching off a new FigmentSourceKind variant (e.g.
        // Url) would collapse the sum to 0 on that arm and fail here,
        // forcing the delegator surface to extend in lockstep.
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_figment_source_file())
                + usize::from(rule.is_figment_source_code())
                + usize::from(rule.is_figment_source_custom());
            let expected = usize::from(rule.metadata_axis().is_metadata_source());
            assert_eq!(
                held, expected,
                "rule {rule:?}: exactly {expected} figment-Source-kind delegator(s) must hold \
                 (Some-iff-source-axis discipline; got held={held})",
            );
        }
    }

    #[test]
    fn attribution_rule_is_figment_name_format_agrees_with_figment_name_tag_kind_is_format() {
        // Per-corner routing-agreement pin on the Format corner of the
        // figment-Name-axis projection. Symmetric peer of the File-corner
        // routing pin on the source-axis. Same twofold routing shape.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_figment_name_format(),
                rule.figment_name_tag_kind()
                    .is_some_and(FigmentNameTagKind::is_format),
                "is_figment_name_format must route through \
                 figment_name_tag_kind().is_some_and(is_format) on {rule:?}",
            );
            assert_eq!(
                rule.is_figment_name_format(),
                rule.figment_name_tag_kind() == Some(FigmentNameTagKind::Format),
                "is_figment_name_format must agree with figment_name_tag_kind == Some(Format) on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_is_figment_name_env_agrees_with_figment_name_tag_kind_is_env() {
        // Sibling of the Format-corner routing pin, on the Env corner.
        // Same twofold routing shape.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.is_figment_name_env(),
                rule.figment_name_tag_kind()
                    .is_some_and(FigmentNameTagKind::is_env),
                "is_figment_name_env must route through \
                 figment_name_tag_kind().is_some_and(is_env) on {rule:?}",
            );
            assert_eq!(
                rule.is_figment_name_env(),
                rule.figment_name_tag_kind() == Some(FigmentNameTagKind::Env),
                "is_figment_name_env must agree with figment_name_tag_kind == Some(Env) on {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_name_tag_kind_predicates_partition_name_axis_rules() {
        // Some-iff-name-axis disjoint-partition pin: the two name-axis
        // sibling delegators sum to exactly one on every name-axis
        // rule (metadata_axis == MetadataName, the outer Option is
        // Some) and exactly zero on every source-axis rule
        // (metadata_axis == MetadataSource, the outer Option is None).
        // Dual of `attribution_rule_figment_source_kind_predicates_partition_source_axis_rules`
        // on the sibling axis. Cross-check pin
        // `attribution_rule_figment_metadata_delegators_form_bi_partition`
        // (below) joins the two partitions and asserts they cover the
        // full rule space exactly once.
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_figment_name_format())
                + usize::from(rule.is_figment_name_env());
            let expected = usize::from(rule.metadata_axis().is_metadata_name());
            assert_eq!(
                held, expected,
                "rule {rule:?}: exactly {expected} figment-Name-kind delegator(s) must hold \
                 (Some-iff-name-axis discipline; got held={held})",
            );
        }
    }

    #[test]
    fn attribution_rule_figment_metadata_delegators_form_bi_partition() {
        // Cross-axis bi-partition pin joining both rule-altitude
        // delegator groups: the source-axis (3) + name-axis (2) = 5
        // delegators sum to exactly one on every recognized rule.
        // Strictly stronger than the two per-axis partition pins
        // together — pins that the union of the two partial
        // partitions covers Self::ALL disjointly, mirroring
        // `attribution_rule_figment_name_tag_kind_xor_figment_source_kind`
        // at the delegator altitude (the biconditional on Options
        // becomes an exact-count sum on the booleans).
        for rule in AttributionRule::ALL.iter().copied() {
            let held = usize::from(rule.is_figment_source_file())
                + usize::from(rule.is_figment_source_code())
                + usize::from(rule.is_figment_source_custom())
                + usize::from(rule.is_figment_name_format())
                + usize::from(rule.is_figment_name_env());
            assert_eq!(
                held, 1,
                "rule {rule:?}: exactly one of the five figment-metadata rule-altitude \
                 delegators must hold (got held={held})",
            );
        }
    }

    #[test]
    fn failing_source_attribution_figment_name_tag_kind_mirrors_rule_figment_name_tag_kind() {
        // The envelope's figment_name_tag_kind() must agree with the
        // rule's, byte-for-byte, on every recognized rule. Pins the
        // contract that the convenience accessor stays a thin
        // forwarder over AttributionRule::figment_name_tag_kind, peer
        // to `failing_source_attribution_figment_source_kind_mirrors_rule_figment_source_kind`
        // on the source axis.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.figment_name_tag_kind(), rule.figment_name_tag_kind());
        }
    }

    #[test]
    fn failing_source_attribution_figment_name_tag_kind_some_iff_metadata_axis_name() {
        // The envelope's figment_name_tag_kind is Some exactly when its
        // metadata_axis is MetadataName. Forwarder discipline pins the
        // same biconditional as
        // `attribution_rule_figment_name_tag_kind_some_iff_metadata_axis_name`,
        // surfaced through the borrowed envelope. Dual of
        // `failing_source_attribution_figment_source_kind_some_iff_metadata_axis_source`.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.figment_name_tag_kind().is_some(),
                attr.metadata_axis().is_metadata_name(),
                "envelope for rule {rule:?}: figment_name_tag_kind.is_some() must equal \
                 metadata_axis().is_metadata_name()",
            );
        }
    }

    #[test]
    fn attribution_rule_file_provenance_pins_each_file_rule() {
        // The (file-rule -> provenance) partial inverse: FileBySource is
        // the figment-builtin file rule (figment's YAML/TOML providers
        // attach Source::File, matched by path equality); FileByMetadataName
        // is the shikumi-built file rule (the LispProvider / NixProvider
        // attach the "<format>: <path>" shape, matched by parsed-path
        // equality). The structural law pinned at the type level,
        // mirroring `format_provenance_file_attribution_rule_pins_each_provenance`
        // on the forward direction.
        assert_eq!(
            AttributionRule::FileBySource.file_provenance(),
            Some(crate::FormatProvenance::FigmentBuiltin),
        );
        assert_eq!(
            AttributionRule::FileByMetadataName.file_provenance(),
            Some(crate::FormatProvenance::ShikumiBuilt),
        );
    }

    #[test]
    fn attribution_rule_file_provenance_none_for_non_file_rules() {
        // Non-file-axis rules (env-prefix, env-uniqueness, defaults-code-
        // uniqueness) all map to None on the file_provenance projection.
        // The partial range of the inverse is the file-axis sub-surface
        // only — the (provenance ↔ file-rule) pairing does not extend to
        // env or defaults rules.
        for rule in [
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_eq!(
                rule.file_provenance(),
                None,
                "non-file-axis rule {rule:?} must not project to a FormatProvenance",
            );
        }
    }

    #[test]
    fn attribution_rule_file_provenance_some_iff_file_layer_kind() {
        // Structural composition law: file_provenance is Some exactly
        // when layer_kind is File. Pins the partial range: file-axis
        // rules' identity names a provider class; non-file-axis rules'
        // identity does not. Mirror of the `figment_source_kind ↔
        // MetadataSource` biconditional but on the (file × non-file)
        // sub-partition of the layer-kind axis.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.file_provenance().is_some(),
                rule.layer_kind() == ConfigSourceKind::File,
                "rule {rule:?}: file_provenance.is_some() must equal \
                 (layer_kind == File)",
            );
        }
    }

    #[test]
    fn attribution_rule_file_provenance_round_trips_through_format_provenance() {
        // Inverse-then-forward round-trip law on the file-axis subset:
        // for every file-axis rule, recovering the provenance via
        // file_provenance and projecting back through
        // FormatProvenance::file_attribution_rule returns the original
        // rule byte-for-byte. The bijection law on the recognized half
        // of the (provenance ↔ file-rule) pairing — peer to the
        // bijection laws Format::format_coordinates /
        // FormatCoordinates::format_or_none and
        // AttributionRule::coordinates / AttributionRule::from_coordinates
        // pin on their respective product cubes.
        for rule in AttributionRule::ALL.iter().copied() {
            if let Some(provenance) = rule.file_provenance() {
                assert_eq!(
                    provenance.file_attribution_rule(),
                    rule,
                    "rule {rule:?}: file_provenance → file_attribution_rule \
                     must round-trip to the originating rule",
                );
            }
        }
    }

    #[test]
    fn format_provenance_file_attribution_rule_round_trips_through_file_provenance() {
        // Forward-then-inverse round-trip law: for every provenance,
        // the file_attribution_rule's file_provenance recovers the
        // originating provenance. Dual of
        // `attribution_rule_file_provenance_round_trips_through_format_provenance`
        // — the forward map FormatProvenance::file_attribution_rule
        // (total over the provenance space) composes with the partial
        // inverse AttributionRule::file_provenance to the identity on
        // FormatProvenance::ALL.
        for provenance in crate::FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                provenance.file_attribution_rule().file_provenance(),
                Some(provenance),
                "provenance {provenance:?}: file_attribution_rule → file_provenance \
                 must round-trip to the originating provenance",
            );
        }
    }

    #[test]
    fn attribution_rule_file_provenance_image_equals_format_provenance_all() {
        // Image of file_provenance over the rule space, dropping None
        // returns, equals FormatProvenance::ALL exactly — every
        // recognized provenance is reachable through some file-axis
        // rule, and no rule projects outside FormatProvenance::ALL.
        // Pins the surjectivity of the partial inverse onto the
        // provenance space. Peer to
        // `attribution_rule_figment_source_kind_image_is_file_and_code_only`
        // for the figment_source_kind axis.
        use std::collections::HashSet;
        let observed: HashSet<crate::FormatProvenance> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::file_provenance)
            .collect();
        let expected: HashSet<crate::FormatProvenance> =
            crate::FormatProvenance::ALL.iter().copied().collect();
        assert_eq!(
            observed, expected,
            "image of file_provenance over AttributionRule::ALL must equal \
             FormatProvenance::ALL; got: {observed:?}",
        );
    }

    #[test]
    fn failing_source_attribution_file_provenance_mirrors_rule_file_provenance() {
        // The envelope's file_provenance() must agree with the rule's,
        // byte-for-byte, on every recognized rule. Pins the contract
        // that the convenience accessor stays a thin forwarder over
        // AttributionRule::file_provenance — peer to
        // `failing_source_attribution_figment_source_kind_mirrors_rule_figment_source_kind`
        // on the parallel partial-projection axis.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.file_provenance(), rule.file_provenance());
        }
    }

    #[test]
    fn failing_source_attribution_file_provenance_some_iff_file_layer_kind() {
        // The envelope's file_provenance is Some exactly when its
        // layer_kind is File. Forwarder discipline pins the same
        // biconditional as
        // `attribution_rule_file_provenance_some_iff_file_layer_kind`,
        // surfaced through the borrowed envelope.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.file_provenance().is_some(),
                attr.layer_kind() == ConfigSourceKind::File,
                "envelope for rule {rule:?}: file_provenance.is_some() must equal \
                 (layer_kind == File)",
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
            error: crate::source::synthetic_env_metadata_error("MAXIS_"),
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
    fn attribution_rule_coordinates_is_const_callable() {
        // Weld the const-callability of the (rule → coordinate-triple)
        // total unifier `AttributionRule::coordinates` at compile time.
        // Composed peer of the three sibling const-callable welds on
        // the same `impl AttributionRule` block — `metadata_axis`
        // (`4f8a185`), `layer_kind` (`52c4a20`), and `confidence`
        // (const since introduction) — lifted to the unifier altitude
        // where the codomain is the composite `AttributionCoordinates`
        // struct rather than a single closed enum. The three atomic
        // projections were already const-callable, so the composite
        // stays wired to compile-time evaluation across the whole
        // three-axis triple; a future edit that loses const-ness on
        // any hop of the composition fails at THAT line in the
        // const-context weld before drifting through downstream
        // consumers that assumed const-ness through the unifier — a
        // `static PER_RULE: [AttributionCoordinates;
        // AttributionRule::ALL.len()]` per-rule coordinate table, an
        // attestation manifest recording the (rule → coordinate)
        // total map at compile time, a `const` sentinel for a
        // compile-time-known rule's coordinate cell.
        const R_FBS: AttributionRule = AttributionRule::FileBySource;
        const R_FBM: AttributionRule = AttributionRule::FileByMetadataName;
        const R_EBP: AttributionRule = AttributionRule::EnvByPrefix;
        const R_EBU: AttributionRule = AttributionRule::EnvByUniqueness;
        const R_DBCU: AttributionRule = AttributionRule::DefaultsByCodeUniqueness;

        const C_FBS: AttributionCoordinates = R_FBS.coordinates();
        const C_FBM: AttributionCoordinates = R_FBM.coordinates();
        const C_EBP: AttributionCoordinates = R_EBP.coordinates();
        const C_EBU: AttributionCoordinates = R_EBU.coordinates();
        const C_DBCU: AttributionCoordinates = R_DBCU.coordinates();

        // Pointwise: the five recognized cells of the (axis ×
        // layer_kind × confidence) cube named by the five rule
        // variants. The const-context welds above prove
        // const-callability; the pins below prove the mapping stays
        // agreed with the exhaustive match in `coordinates` — a
        // future edit that shifted a rule off any of its three
        // orthogonal coordinates diverges here first, not at a
        // downstream reader of a stale (rule → coordinate) mapping.
        assert_eq!(
            C_FBS,
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::File,
                confidence: AttributionConfidence::Exact,
            },
        );
        assert_eq!(
            C_FBM,
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::File,
                confidence: AttributionConfidence::Exact,
            },
        );
        assert_eq!(
            C_EBP,
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::Env,
                confidence: AttributionConfidence::Exact,
            },
        );
        assert_eq!(
            C_EBU,
            AttributionCoordinates {
                axis: AttributionAxis::MetadataName,
                layer_kind: ConfigSourceKind::Env,
                confidence: AttributionConfidence::Fallback,
            },
        );
        assert_eq!(
            C_DBCU,
            AttributionCoordinates {
                axis: AttributionAxis::MetadataSource,
                layer_kind: ConfigSourceKind::Defaults,
                confidence: AttributionConfidence::Fallback,
            },
        );

        // Full-list pin: iterate `AttributionRule::ALL` against the
        // const-bound coordinate array so a future variant landing on
        // `AttributionRule` without a corresponding update here fails
        // at the length check, mirroring the `ALL`-length pins on the
        // sibling const-callable welds.
        let expected: [AttributionCoordinates; AttributionRule::ALL.len()] =
            [C_FBS, C_FBM, C_EBP, C_EBU, C_DBCU];
        for (rule, expected_coords) in AttributionRule::ALL.iter().copied().zip(expected) {
            assert_eq!(
                rule.coordinates(),
                expected_coords,
                "rule {rule:?}: coordinates must match its const-context weld",
            );
        }

        // Composition pin: each const-bound coordinate cell must
        // agree with the tuple of the three sibling const-callable
        // atomic projections routed through their own const-bound
        // reads. Welds the (metadata_axis, layer_kind, confidence)
        // unifier contract at compile-time-derived altitude alongside
        // the sibling runtime pin
        // `attribution_rule_coordinates_agrees_with_three_projection_accessors`
        // — a future edit that unbalances the unifier against any of
        // the three atomic projections diverges at THIS block, before
        // the runtime pin fires downstream. Reading each triple
        // through a fresh `const` weld also proves the three atomic
        // projections stay const-callable in lockstep with the
        // composite: if any one loses const-ness the corresponding
        // atomic binding fails to compile at THAT line, before the
        // composite binding can shadow the drift.
        const MA_FBS: AttributionAxis = R_FBS.metadata_axis();
        const LK_FBS: ConfigSourceKind = R_FBS.layer_kind();
        const CF_FBS: AttributionConfidence = R_FBS.confidence();
        assert_eq!(C_FBS.axis, MA_FBS);
        assert_eq!(C_FBS.layer_kind, LK_FBS);
        assert_eq!(C_FBS.confidence, CF_FBS);

        const MA_FBM: AttributionAxis = R_FBM.metadata_axis();
        const LK_FBM: ConfigSourceKind = R_FBM.layer_kind();
        const CF_FBM: AttributionConfidence = R_FBM.confidence();
        assert_eq!(C_FBM.axis, MA_FBM);
        assert_eq!(C_FBM.layer_kind, LK_FBM);
        assert_eq!(C_FBM.confidence, CF_FBM);

        const MA_EBP: AttributionAxis = R_EBP.metadata_axis();
        const LK_EBP: ConfigSourceKind = R_EBP.layer_kind();
        const CF_EBP: AttributionConfidence = R_EBP.confidence();
        assert_eq!(C_EBP.axis, MA_EBP);
        assert_eq!(C_EBP.layer_kind, LK_EBP);
        assert_eq!(C_EBP.confidence, CF_EBP);

        const MA_EBU: AttributionAxis = R_EBU.metadata_axis();
        const LK_EBU: ConfigSourceKind = R_EBU.layer_kind();
        const CF_EBU: AttributionConfidence = R_EBU.confidence();
        assert_eq!(C_EBU.axis, MA_EBU);
        assert_eq!(C_EBU.layer_kind, LK_EBU);
        assert_eq!(C_EBU.confidence, CF_EBU);

        const MA_DBCU: AttributionAxis = R_DBCU.metadata_axis();
        const LK_DBCU: ConfigSourceKind = R_DBCU.layer_kind();
        const CF_DBCU: AttributionConfidence = R_DBCU.confidence();
        assert_eq!(C_DBCU.axis, MA_DBCU);
        assert_eq!(C_DBCU.layer_kind, LK_DBCU);
        assert_eq!(C_DBCU.confidence, CF_DBCU);
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
            .filter(|r| r.metadata_axis().is_metadata_source())
            .count();
        let name = AttributionRule::ALL
            .iter()
            .filter(|r| r.metadata_axis().is_metadata_name())
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
        // assertion. Also pins the concrete current value (21) so
        // an unintentional churn on either axis is caught even when
        // the product math still works out.
        assert_eq!(
            ErrorLocalizationCoordinates::ALL.len(),
            ShikumiErrorKind::ALL.len() * FieldPathLocalization::ALL.len(),
            "ALL must equal the cartesian product cardinality",
        );
        assert_eq!(
            ErrorLocalizationCoordinates::ALL.len(),
            21,
            "ALL must have 7 * 3 = 21 cells today",
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
        //   kind.is_figment_bearing() == localization.is_applicable().
        // The two definitions agree on all 21 cells. Routes through
        // the FieldPathLocalization::is_applicable sibling — same
        // partition polarity as the inline `!matches!(loc,
        // NotApplicable)` this replaced, expressed as the typescape
        // primitive rather than a fresh literal match.
        for cell in ErrorLocalizationCoordinates::ALL.iter().copied() {
            let expected = cell.kind.is_figment_bearing() == cell.localization.is_applicable();
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal the figment-bearing law",
            );
        }
    }

    #[test]
    fn error_localization_coordinates_is_realizable_is_const_callable() {
        // Weld the const-callability of the realizability predicate
        // `ErrorLocalizationCoordinates::is_realizable` and the two
        // hop-predicates it composes — `ShikumiErrorKind::is_figment_bearing`
        // (const since introduced) and `FieldPathLocalization::is_applicable`
        // (const since introduced) — at compile time.
        //
        // Coordinate-cube analogue of the rule-altitude const-callability
        // welds on the sibling `AttributionRule` closed primitive
        // (`attribution_rule_layer_predicates_are_const_callable`,
        // `attribution_rule_metadata_axis_predicates_are_const_callable`):
        // the same discipline lifted to the product-cube altitude, where
        // realizability is a composition of two closed-axis partition
        // predicates rather than a single-axis polarity read. Four
        // representative cells — one from each corner of the
        // (figment-bearing × applicable) 2×2 realizability truth table —
        // route each corner through the delegating predicate in const
        // position, so the two-hop cascade
        // (kind.is_figment_bearing() == localization.is_applicable())
        // is pinned const-callable, not each hop in isolation. The
        // moment `is_realizable` (or either of the two composed
        // predicates it delegates to) stops being const-callable, one
        // of the four `const` welds below fails to compile at THAT line
        // before the drift can reach downstream consumers that assumed
        // const-ness through the predicate — a `static REALIZABLE_TABLE:
        // [bool; ErrorLocalizationCoordinates::ALL.len()]` per-cell
        // realizability lookup, an attestation manifest recording
        // realizable-image membership at compile time, a `const`
        // sentinel for a compile-time-known (kind × localization) pair.
        const C_FIGMENT_LOCALIZED: ErrorLocalizationCoordinates = ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Figment,
            localization: FieldPathLocalization::Localized,
        };
        const C_FIGMENT_NOT_APPLICABLE: ErrorLocalizationCoordinates =
            ErrorLocalizationCoordinates {
                kind: ShikumiErrorKind::Figment,
                localization: FieldPathLocalization::NotApplicable,
            };
        const C_PARSE_LOCALIZED: ErrorLocalizationCoordinates = ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::Localized,
        };
        const C_PARSE_NOT_APPLICABLE: ErrorLocalizationCoordinates = ErrorLocalizationCoordinates {
            kind: ShikumiErrorKind::Parse,
            localization: FieldPathLocalization::NotApplicable,
        };

        const IS_R_FL: bool = C_FIGMENT_LOCALIZED.is_realizable();
        const IS_R_FN: bool = C_FIGMENT_NOT_APPLICABLE.is_realizable();
        const IS_R_PL: bool = C_PARSE_LOCALIZED.is_realizable();
        const IS_R_PN: bool = C_PARSE_NOT_APPLICABLE.is_realizable();

        // Pointwise: the four corners of the 2×2 (figment-bearing ×
        // applicable) realizability truth table. The const-context
        // welds above prove const-callability; the pins below prove the
        // realizability mapping stays agreed with the figment-bearing
        // law (is_figment_bearing == is_applicable) — a future edit
        // that shifted either hop-predicate diverges here first, not at
        // a downstream reader of a stale realizability classification.
        assert!(IS_R_FL);
        assert!(!IS_R_FN);
        assert!(!IS_R_PL);
        assert!(IS_R_PN);

        // Cross-check: on every cell in `ALL` the const-fn
        // realizability predicate stays pointwise equal to the two-hop
        // composition `kind.is_figment_bearing() ==
        // localization.is_applicable()` it delegates to — the
        // const-context welds above only exercise the four corner cells
        // named at const-binding sites, but the runtime pin threads the
        // full closed 21-cell list through the same delegation to
        // catch a future variant landing whose const-context weld was
        // forgotten upstream.
        for cell in ErrorLocalizationCoordinates::ALL.iter().copied() {
            assert_eq!(
                cell.is_realizable(),
                cell.kind.is_figment_bearing() == cell.localization.is_applicable(),
                "is_realizable must route through the figment-bearing law on {cell:?}",
            );
        }
    }

    #[test]
    fn error_localization_coordinates_realizable_partitions_into_9_realizable_and_12_unrealizable()
    {
        // Pins the 9 + 12 cardinality split:
        // - 2 figment-bearing kinds (Figment, Extract)
        //   × 2 figment-attached localizations (Localized,
        //     FigmentUnlocalized) = 4 realizable cells.
        // - 5 non-figment-bearing kinds (NotFound, Parse, Watch, Io,
        //   Validation) × 1 NotApplicable = 5 realizable cells.
        // Total realizable = 9; total unrealizable = 12. A future
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
        assert_eq!(realizable, 9, "realizable cells must be 9");
        assert_eq!(unrealizable, 12, "unrealizable cells must be 12");
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
        // Extract+FigmentUnlocalized — together with the Validation
        // row `one_per_kind()` now carries, they enumerate all 9
        // realizable cells exactly.
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
        let figment_localized =
            ShikumiError::Figment(crate::source::synthetic_field_path_error("k"));
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
                rule.metadata_axis().is_metadata_source(),
                "rule {rule:?}: attribution_source_kind_coordinates.is_some() must equal \
                 metadata_axis().is_metadata_source()",
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

    // ---- AttributionNameKindCoordinates::ALL cover / partition / realizability ----

    #[test]
    fn attribution_name_kind_coordinates_all_has_no_duplicates() {
        // Pins that the constant is a set, not a multiset — every
        // cell appears at most once. Mirrors the
        // `_all_has_no_duplicates` discipline on every sibling
        // product-cube `ALL`.
        use std::collections::HashSet;
        let unique: HashSet<AttributionNameKindCoordinates> = AttributionNameKindCoordinates::ALL
            .iter()
            .copied()
            .collect();
        assert_eq!(
            unique.len(),
            AttributionNameKindCoordinates::ALL.len(),
            "AttributionNameKindCoordinates::ALL must contain no duplicates; got: {:?}",
            AttributionNameKindCoordinates::ALL,
        );
    }

    #[test]
    fn attribution_name_kind_coordinates_all_cardinality_matches_product_of_axes() {
        // Pins the product-cube cardinality contract as a function of
        // the constituent axis cardinalities rather than a literal
        // integer: any new variant on either sibling axis
        // (FigmentNameTagKind::ALL or ConfigSourceKind::ALL) forces an
        // extension of Self::ALL in lockstep through this assertion.
        // Also pins the concrete current value (6) so an unintentional
        // churn on either axis is caught even when the product math
        // still works out.
        assert_eq!(
            AttributionNameKindCoordinates::ALL.len(),
            FigmentNameTagKind::ALL.len() * ConfigSourceKind::ALL.len(),
            "ALL must equal the cartesian product cardinality",
        );
        assert_eq!(
            AttributionNameKindCoordinates::ALL.len(),
            6,
            "ALL must have 2 * 3 = 6 cells today",
        );
    }

    #[test]
    fn attribution_name_kind_coordinates_all_equals_axes_cartesian_product() {
        // Tight equality (not subset) against the inline doubly-nested
        // product over the sibling ALL slices: Self::ALL IS the
        // cartesian product, no extras and no omissions. A future
        // variant on either sibling axis (figment_name_tag_kind or
        // layer_kind) forces both an entry in the constant and a
        // corresponding cell appearing here through the inline product
        // enumeration.
        use std::collections::HashSet;
        let mut expected: HashSet<AttributionNameKindCoordinates> = HashSet::new();
        for figment_name_tag_kind in FigmentNameTagKind::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                expected.insert(AttributionNameKindCoordinates {
                    figment_name_tag_kind,
                    layer_kind,
                });
            }
        }
        let listed: HashSet<AttributionNameKindCoordinates> = AttributionNameKindCoordinates::ALL
            .iter()
            .copied()
            .collect();
        assert_eq!(
            listed, expected,
            "ALL must be the exact cartesian product of the sibling ALL slices",
        );
    }

    #[test]
    fn attribution_name_kind_coordinates_all_iterates_in_lexicographic_order() {
        // Pins iteration order figment_name_tag_kind-outer /
        // layer_kind-inner — the doubly-nested product enumeration
        // over the sibling ALL slices in lexicographic order.
        let mut expected: Vec<AttributionNameKindCoordinates> = Vec::new();
        for figment_name_tag_kind in FigmentNameTagKind::ALL.iter().copied() {
            for layer_kind in ConfigSourceKind::ALL.iter().copied() {
                expected.push(AttributionNameKindCoordinates {
                    figment_name_tag_kind,
                    layer_kind,
                });
            }
        }
        let listed: Vec<AttributionNameKindCoordinates> =
            AttributionNameKindCoordinates::ALL.to_vec();
        assert_eq!(
            listed, expected,
            "ALL must iterate in figment_name_tag_kind-outer / layer_kind-inner lexicographic order",
        );
    }

    #[test]
    fn attribution_name_kind_coordinates_is_realizable_matches_diagonal() {
        // Pins the realizability invariant pointwise on every cell of
        // the cube:
        //   is_realizable iff
        //   (figment_name_tag_kind, layer_kind) ∈ {(Format, File), (Env, Env)}.
        // The two definitions agree on all 6 cells.
        for cell in AttributionNameKindCoordinates::ALL.iter().copied() {
            let expected = matches!(
                (cell.figment_name_tag_kind, cell.layer_kind),
                (FigmentNameTagKind::Format, ConfigSourceKind::File)
                    | (FigmentNameTagKind::Env, ConfigSourceKind::Env)
            );
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal the name-axis diagonal law",
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_realizable_partitions_into_2_realizable_and_4_unrealizable()
     {
        // Pins the 2 + 4 cardinality split:
        // - 2 realizable cells on the structural diagonal of name-axis
        //   rules: (Format, File) from FileByMetadataName and
        //   (Env, Env) from {EnvByPrefix, EnvByUniqueness}.
        // - 4 unrealizable cells: (Format, Defaults), (Format, Env),
        //   (Env, Defaults), (Env, File).
        // A future name-axis rule lands as a realizable cell whose
        // realizability is forced by the diagonal law, extending the
        // realizable image and shrinking the unrealizable count in
        // lockstep.
        let realizable = AttributionNameKindCoordinates::ALL
            .iter()
            .filter(|c| c.is_realizable())
            .count();
        let unrealizable = AttributionNameKindCoordinates::ALL
            .iter()
            .filter(|c| !c.is_realizable())
            .count();
        assert_eq!(realizable, 2, "realizable cells must be 2");
        assert_eq!(unrealizable, 4, "unrealizable cells must be 4");
        assert_eq!(
            realizable + unrealizable,
            AttributionNameKindCoordinates::ALL.len(),
            "realizable + unrealizable must cover ALL exactly once",
        );
    }

    #[test]
    fn attribution_name_kind_coordinates_realizable_image_equals_rule_image() {
        // The realizable half of ALL is the exact image of
        // AttributionRule::attribution_name_kind_coordinates over the
        // rule space. Pins which specific cells (not just how many)
        // are observable from a recognized AttributionRule — a tighter
        // contract than the cardinality split. Future name-axis rules
        // land coherently: a new rule extends the image and forces an
        // expansion of the realizable subset in lockstep.
        use std::collections::HashSet;
        let observed: HashSet<AttributionNameKindCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::attribution_name_kind_coordinates)
            .collect();
        let realizable: HashSet<AttributionNameKindCoordinates> =
            AttributionNameKindCoordinates::ALL
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
    fn attribution_rule_attribution_name_kind_coordinates_returns_realizable_cell_when_some() {
        // Forward-partial / image-realizable contract: every Some
        // return from AttributionRule::attribution_name_kind_coordinates
        // must satisfy is_realizable. The accessor never produces an
        // unrealizable cell, no matter which rule is queried.
        for rule in AttributionRule::ALL.iter().copied() {
            if let Some(cell) = rule.attribution_name_kind_coordinates() {
                assert!(
                    cell.is_realizable(),
                    "rule {rule:?} mapped to non-realizable cell {cell:?}",
                );
            }
        }
    }

    #[test]
    fn attribution_rule_attribution_name_kind_coordinates_some_iff_metadata_axis_name() {
        // Composition law on AttributionRule: the partial joint cell
        // projection is Some exactly when metadata_axis is
        // MetadataName. Symmetric peer of
        // `attribution_rule_attribution_source_kind_coordinates_some_iff_metadata_axis_source`.
        for rule in AttributionRule::ALL.iter().copied() {
            assert_eq!(
                rule.attribution_name_kind_coordinates().is_some(),
                rule.metadata_axis().is_metadata_name(),
                "rule {rule:?}: attribution_name_kind_coordinates.is_some() must equal \
                 metadata_axis().is_metadata_name()",
            );
        }
    }

    #[test]
    fn attribution_rule_attribution_name_kind_coordinates_mirrors_paired_projections() {
        // The joint-cell accessor must agree byte-for-byte with the
        // inline pairing of the two sibling projections:
        // - figment_name_tag_kind() → cell.figment_name_tag_kind
        // - layer_kind()            → cell.layer_kind
        // Pins the lossless-decomposition contract: consumers using
        // either the joint cell or the two reads separately see the
        // same data.
        for rule in AttributionRule::ALL.iter().copied() {
            let joint = rule.attribution_name_kind_coordinates();
            let paired = rule.figment_name_tag_kind().map(|figment_name_tag_kind| {
                AttributionNameKindCoordinates {
                    figment_name_tag_kind,
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
    fn attribution_rule_attribution_name_kind_coordinates_pins_known_rules() {
        // Per-variant pinning table: name-axis rules already name
        // both halves of their joint cell, source-axis rules name
        // neither.
        let cases: [(AttributionRule, Option<AttributionNameKindCoordinates>); 5] = [
            (AttributionRule::FileBySource, None),
            (
                AttributionRule::FileByMetadataName,
                Some(AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Format,
                    layer_kind: ConfigSourceKind::File,
                }),
            ),
            (
                AttributionRule::EnvByPrefix,
                Some(AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Env,
                    layer_kind: ConfigSourceKind::Env,
                }),
            ),
            (
                AttributionRule::EnvByUniqueness,
                Some(AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Env,
                    layer_kind: ConfigSourceKind::Env,
                }),
            ),
            (AttributionRule::DefaultsByCodeUniqueness, None),
        ];
        for (rule, expected) in cases {
            assert_eq!(
                rule.attribution_name_kind_coordinates(),
                expected,
                "rule {rule:?}: attribution_name_kind_coordinates pin",
            );
        }
    }

    #[test]
    fn attribution_rule_attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates()
    {
        // Cross-axis partition law: every rule's identity dispatches
        // on exactly one figment-metadata axis, so for every rule
        // exactly one of attribution_source_kind_coordinates and
        // attribution_name_kind_coordinates returns Some. Closes the
        // joint-cell universe across the two cubes.
        for rule in AttributionRule::ALL.iter().copied() {
            let source = rule.attribution_source_kind_coordinates().is_some();
            let name = rule.attribution_name_kind_coordinates().is_some();
            assert_ne!(
                source, name,
                "rule {rule:?}: exactly one of the two joint cells must be Some",
            );
        }
    }

    #[test]
    fn failing_source_attribution_attribution_name_kind_coordinates_mirrors_rule() {
        // The envelope's accessor must agree with the rule's,
        // byte-for-byte, on every recognized rule. Pins the
        // convenience accessor as a thin forwarder over
        // AttributionRule::attribution_name_kind_coordinates.
        for rule in AttributionRule::ALL.iter().copied() {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(
                attr.attribution_name_kind_coordinates(),
                rule.attribution_name_kind_coordinates(),
                "envelope for rule {rule:?}",
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_is_copy_and_hashable() {
        // Typescape bounds parity with the sibling product-cube
        // structs (AttributionCoordinates, FormatCoordinates,
        // ErrorLocalizationCoordinates, AttributionSourceKindCoordinates)
        // and the underlying axis primitives (FigmentNameTagKind,
        // ConfigSourceKind).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributionNameKindCoordinates {
            figment_name_tag_kind: FigmentNameTagKind::Format,
            layer_kind: ConfigSourceKind::File,
        });
        set.insert(AttributionNameKindCoordinates {
            figment_name_tag_kind: FigmentNameTagKind::Env,
            layer_kind: ConfigSourceKind::Env,
        });
        // Duplicate insertion — no growth.
        set.insert(AttributionNameKindCoordinates {
            figment_name_tag_kind: FigmentNameTagKind::Format,
            layer_kind: ConfigSourceKind::File,
        });
        assert_eq!(set.len(), 2, "every coordinate must hash distinctly");

        // Copy: rebind without move.
        let c = AttributionNameKindCoordinates {
            figment_name_tag_kind: FigmentNameTagKind::Env,
            layer_kind: ConfigSourceKind::Defaults,
        };
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn attribution_name_kind_coordinates_realizable_image_lies_in_attribution_name_kind_coordinates_all()
     {
        // Cross-primitive cover law: every realizable cell observed
        // from AttributionRule lies in
        // AttributionNameKindCoordinates::ALL. Pins the contract that
        // the rule's partial-projection image stays a sub-image of the
        // declared product cube — no rule-specific joint cell ever
        // escapes the typescape's declared product axis.
        use std::collections::HashSet;
        let observed: HashSet<AttributionNameKindCoordinates> = AttributionRule::ALL
            .iter()
            .copied()
            .filter_map(AttributionRule::attribution_name_kind_coordinates)
            .collect();
        let declared: HashSet<AttributionNameKindCoordinates> = AttributionNameKindCoordinates::ALL
            .iter()
            .copied()
            .collect();
        assert!(
            observed.is_subset(&declared),
            "image of attribution_name_kind_coordinates must lie in \
             AttributionNameKindCoordinates::ALL; observed: {observed:?}, \
             declared: {declared:?}",
        );
    }

    // ── ShikumiErrorKind — Ord / Display / FromStr / serde ──────────
    //
    // The (Ord, Display, FromStr, serde::{Serialize, Deserialize})
    // quartet idiom-peer of the lift already landed on
    // `SecretClientKind` (commit `24c7b33`), `DiffLineKind`
    // (commit `c403e1a`), `WatchEventClass` (commit `94f8a8b`),
    // `EnvMetadataTagKind` (commit `b556b75`), `SecretRefShape`
    // (commit `8a84bb6`), `SecretBackendKind` (commit `9b1da86`),
    // `FigmentNameTagKind` (commit `64a47e7`), `FigmentSourceKind`
    // (commit `5df265c`), and `ConfigSourceKind` (commit `e0b96d1`),
    // now lifted onto the captured-failure variant axis kind primitive.

    #[test]
    fn shikumi_error_kind_ord_matches_all_declaration_order() {
        // The derived Ord on ShikumiErrorKind is declaration-order
        // lex over ALL: `NotFound < Parse < Watch < Io < Figment <
        // Extract`. A BTreeMap keyed on the captured-failure variant
        // axis kind (per-kind failure-rate histograms, per-kind
        // alert thresholds, attestation manifests recording the
        // captured-failure mix histogram, structured-diagnostic
        // legends bucketing per-kind counters in declaration order)
        // emits rows in that order deterministically without a hand-
        // rolled comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds). Idiom-peer
        // of the same pin on SecretClientKind (commit `24c7b33`)
        // and DiffLineKind (commit `c403e1a`).
        use std::cmp::Ordering;
        for window in ShikumiErrorKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "ShikumiErrorKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in ShikumiErrorKind::ALL.iter().enumerate() {
            for (j, &b) in ShikumiErrorKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "ShikumiErrorKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "ShikumiErrorKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn shikumi_error_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<ShikumiErrorKind, _> emits keys
        // in declaration order on `iter()` / `into_iter()` regardless
        // of insertion order, matching `ShikumiErrorKind::ALL`.
        // Idiom-peer of the same pin on SecretClientKind
        // (commit `24c7b33`) and DiffLineKind (commit `c403e1a`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<ShikumiErrorKind, u32> = BTreeMap::new();
        counts.insert(ShikumiErrorKind::Extract, 6);
        counts.insert(ShikumiErrorKind::NotFound, 1);
        counts.insert(ShikumiErrorKind::Figment, 5);
        counts.insert(ShikumiErrorKind::Io, 4);
        counts.insert(ShikumiErrorKind::Parse, 2);
        counts.insert(ShikumiErrorKind::Watch, 3);
        counts.insert(ShikumiErrorKind::Validation, 7);
        let observed: Vec<ShikumiErrorKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            ShikumiErrorKind::ALL.to_vec(),
            "BTreeMap<ShikumiErrorKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn shikumi_error_kind_display_matches_as_str() {
        // Display writes the canonical label as_str returns, byte-
        // for-byte. The two surfaces stay aligned by construction —
        // a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on SecretClientKind
        // (commit `24c7b33`), DiffLineKind (commit `c403e1a`), and
        // WatchEventClass (commit `94f8a8b`).
        for k in ShikumiErrorKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in ShikumiErrorKind::ALL {
            let rendered = k.to_string();
            let parsed: ShikumiErrorKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn shikumi_error_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var
        // or CLI flag parse pointwise to the same variant.
        assert_eq!(
            "NOT-FOUND".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::NotFound,
        );
        assert_eq!(
            "Parse".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::Parse,
        );
        assert_eq!(
            "WATCH".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::Watch,
        );
        assert_eq!(
            "Io".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::Io,
        );
        assert_eq!(
            "FiGmEnT".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::Figment,
        );
        assert_eq!(
            "EXTRACT".parse::<ShikumiErrorKind>().unwrap(),
            ShikumiErrorKind::Extract,
        );
    }

    #[test]
    fn shikumi_error_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // SecretClientKind's FromStr surface (commit `24c7b33`),
        // DiffLineKind's FromStr surface (commit `c403e1a`),
        // WatchEventClass's FromStr surface (commit `94f8a8b`),
        // EnvMetadataTagKind's FromStr surface (commit `b556b75`),
        // SecretRefShape's FromStr surface (commit `8a84bb6`),
        // SecretBackendKind's FromStr surface (commit `9b1da86`),
        // FigmentNameTagKind's FromStr surface (commit `64a47e7`),
        // FigmentSourceKind's FromStr surface (commit `5df265c`), and
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`).
        for bad in &["notfound", "parser", "fs", "input", "", "  parse"] {
            let err = bad
                .parse::<ShikumiErrorKind>()
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
    fn shikumi_error_kind_from_str_unknown_kind_returns_parse_variant() {
        // Concrete-position pin on the rejection-kind: the inherent
        // FromStr surface routes unknown labels through
        // ShikumiError::Parse, not through Watch / Io / Figment /
        // Extract. A future refactor of the error wrapping (e.g.
        // adding a dedicated `UnknownKind` variant) is held to
        // updating this site in lockstep, so consumers matching on
        // the wrapping kind keep matching the same variant.
        let err = "no-such-kind"
            .parse::<ShikumiErrorKind>()
            .expect_err("unrecognized label must reject");
        assert_eq!(
            err.kind(),
            ShikumiErrorKind::Parse,
            "FromStr rejection must surface as ShikumiErrorKind::Parse, got {err:?}",
        );
    }

    #[test]
    fn shikumi_error_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the captured-failure variant axis kind primitive.
        // A consumer struct holding a ShikumiErrorKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the kind of a captured failure)
        // round-trips without a consumer-side rename helper.
        for k in ShikumiErrorKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: ShikumiErrorKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn shikumi_error_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for k in ShikumiErrorKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: ShikumiErrorKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn shikumi_error_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, ShikumiErrorKind)] = &[
            ("NOT-FOUND", ShikumiErrorKind::NotFound),
            ("Parse", ShikumiErrorKind::Parse),
            ("WATCH", ShikumiErrorKind::Watch),
            ("Io", ShikumiErrorKind::Io),
            ("FiGmEnT", ShikumiErrorKind::Figment),
            ("EXTRACT", ShikumiErrorKind::Extract),
        ];
        for (input, expected) in cases {
            let parsed: ShikumiErrorKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn shikumi_error_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized captured-failure variant axis kind label
        // surfaces at the serde error site with the offending
        // substring verbatim in the rendered message, lifted through
        // ShikumiError::Parse's Display impl. Same verbatim-rejection
        // discipline as SecretClientKind's serde surface
        // (commit `24c7b33`), DiffLineKind's serde surface
        // (commit `c403e1a`), WatchEventClass's serde surface
        // (commit `94f8a8b`), and ConfigSourceKind's serde surface
        // (commit `e0b96d1`).
        for bad in &["notfound", "parser", "fs", "input"] {
            let err = serde_yaml::from_str::<ShikumiErrorKind>(bad)
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
    fn shikumi_error_kind_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on the YAML emission shape: a
        // ShikumiErrorKind serializes as a bare kebab/lowercase
        // scalar, not as a quoted string or a tagged enum. Captures
        // that an attestation manifest authoring tool can emit the
        // kind as a bare YAML scalar pointwise matching the
        // operator-facing label across all six variants.
        let pairs: &[(ShikumiErrorKind, &str)] = &[
            (ShikumiErrorKind::NotFound, "not-found\n"),
            (ShikumiErrorKind::Parse, "parse\n"),
            (ShikumiErrorKind::Watch, "watch\n"),
            (ShikumiErrorKind::Io, "io\n"),
            (ShikumiErrorKind::Figment, "figment\n"),
            (ShikumiErrorKind::Extract, "extract\n"),
        ];
        for (k, expected) in pairs {
            let yaml = serde_yaml::to_string(k).unwrap();
            assert_eq!(yaml, *expected, "YAML emission mismatch for {k:?}");
        }
    }

    #[test]
    fn error_tests_route_env_metadata_synthetics_through_env_metadata_name_writer() {
        // Source-text pin: no test body in this file may re-inline the
        // `` `PREFIX` environment variable(s) `` shape as a `&str` literal.
        // Every env-provider synthetic routes through
        // `crate::source::synthetic_env_metadata_error(prefix)` (which
        // in turn routes through `ConfigSource::env_metadata_name(prefix)`
        // and its three `ENV_METADATA_NAME_TAIL` / `..._TAIL_STEM` /
        // `..._PREFIX_QUOTE` `pub const`s), so a future edit to the
        // env-provider metadata-name shape lands at the three constants
        // in `src/source.rs` and every synthetic in this file inherits
        // the new shape by construction.
        //
        // Fail-before-pass-after: at this commit the eight sites this
        // test protects are the eight prior
        // `synthetic_error_with_metadata_name(".. environment variable(s)")`
        // callers in the `EnvByPrefix` / `EnvByUniqueness` resolver-arm
        // tests. Any future re-inlining fires here first, before drift
        // can silently desync the synthetic from the substrate — the
        // resolver would keep passing on the current shape but
        // stop attributing under a future shape edit, and no other test
        // in the crate cross-checks that agreement.
        //
        // Doc-comment / block-comment mentions of the shape are exempt
        // (they explain the invariant); the check filters lines whose
        // first non-whitespace token is `//`. String-literal mentions
        // inside test bodies — the exact drift class this test blocks —
        // are NOT exempt.
        const SRC: &str = include_str!("error.rs");
        const TAIL_STEM: &str = crate::source::ConfigSource::ENV_METADATA_NAME_TAIL_STEM;
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(TAIL_STEM)
            })
            // Exempt this test itself: it mentions the tail stem in its
            // own body (through the substrate `const`, not a literal) so
            // the assertion message can name what it is looking for.
            .filter(|(_, line)| {
                !line.contains("ENV_METADATA_NAME_TAIL_STEM")
                    && !line.contains("error_tests_route_env_metadata_synthetics")
            })
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "error.rs re-inlines the `{TAIL_STEM}[…]` env-metadata-name shape at \
             {} non-comment line(s) — route each through \
             `crate::source::synthetic_env_metadata_error(prefix)` so a future \
             shape edit at `ConfigSource::ENV_METADATA_NAME_TAIL` lands there \
             instead of silently desynchronising the synthetic from the writer: \
             {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn error_tests_route_synth_message_through_shared_const() {
        // Source-text pin on the shared placeholder message body: no
        // test body in this file may re-inline `"synth"` as a `&str`
        // literal for a `figment::Error::from(...)` /
        // `figment::Metadata::named(...)` construction.
        //
        // Every synthetic drives the resolver through the shared
        // `crate::source::SYNTHETIC_TEST_MESSAGE` const, so a future
        // placeholder change (rename for grep coverage in captured
        // test logs, per-test discriminator, or reserving the bare
        // `"synth"` for a real error shape figment might emit) lands
        // at ONE named site — the const in `src/source.rs` — and
        // every one of the two `error.rs::tests` sites plus the
        // thirty-three `reload.rs::tests` sites plus the one
        // `source.rs::tests` site inherits the new placeholder by
        // construction.
        //
        // Fail-before-pass-after: at this commit the two sites this
        // pin protects are `synthetic_error_with_metadata_name`'s
        // body and the open-coded `figment::Error::from(...)` inside
        // `failing_attribution_rule_file_by_source_wins_over_file_by_metadata_name`;
        // re-inlining either fires here first before the resolver
        // arm tests fall back to a stale placeholder shape.
        //
        // Doc-comment / block-comment mentions of the placeholder are
        // exempt (they explain the invariant); the check filters
        // lines whose first non-whitespace token is `//`.
        const SRC: &str = include_str!("error.rs");
        const NEEDLE: &str = "\"synth\"";
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(NEEDLE)
            })
            // Exempt this test itself: it mentions the placeholder in
            // its own body (as a needle) so the assertion can name what
            // it is looking for.
            .filter(|(_, line)| !line.contains("error_tests_route_synth_message"))
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "error.rs re-inlines the `\"synth\"` placeholder at {} non-comment \
             line(s) — route each through \
             `crate::source::SYNTHETIC_TEST_MESSAGE.to_owned()` so a future \
             placeholder edit at the shared const lands there instead of \
             silently desynchronising the synthetic from every other test-side \
             site in the crate: {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn error_tests_route_synth_parse_through_synthetic_parse_error() {
        // Source-text pin on the shared "synthetic non-`Extract`
        // `ShikumiError`" constructor: no test body in this file may
        // re-inline `ShikumiError::Parse("x".to_owned())` as a literal.
        //
        // Every test that needs a canonical non-`Extract` error class
        // (six such call sites in this file at the parent commit) routes
        // through `super::synthetic_parse_error()`, so a future change to
        // the [`ShikumiError::Parse`] variant shape (adding a per-line
        // span field, reshaping to a struct-like variant carrying source
        // context, or renaming) lands at ONE named site — the helper
        // body in `crate::error::synthetic_parse_error` — and every one
        // of the six previously-open-coded call sites inherits the new
        // shape by construction rather than failing to compile at six
        // distinct places one paired edit at a time. Peer of the sibling
        // pins in `reload.rs::tests` (27 sites) and
        // `observatory.rs::tests` (7 sites), which close the same
        // drift class on the other two axes of the same substrate.
        //
        // Fail-before-pass-after cross-check: the shape count was 6 at
        // the parent commit (before every site routed through
        // `super::synthetic_parse_error()`); this pin fires 6 offenders
        // at that state and 0 here.
        //
        // Doc-comment / block-comment mentions of the pattern are
        // exempt (they explain the invariant); the check filters lines
        // whose first non-whitespace token is `//`.
        const SRC: &str = include_str!("error.rs");
        const NEEDLE: &str = "ShikumiError::Parse(\"x\".to_owned())";
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(NEEDLE)
            })
            // Exempt this test itself: it mentions the pattern in its own
            // body (as a needle) so the assertion can name what it looks
            // for.
            .filter(|(_, line)| !line.contains("error_tests_route_synth_parse"))
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "error.rs re-inlines the `ShikumiError::Parse(\"x\".to_owned())` \
             shape at {} non-comment line(s) — route each through \
             `super::synthetic_parse_error()` so a future \
             `ShikumiError::Parse` shape change lands at the helper body \
             instead of at each open-coded literal apart: {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn error_tests_route_field_path_synthetics_through_synthetic_field_path_error() {
        // Source-text pin on the shared "synthetic figment error carrying
        // a localized field path" constructor: no test body in this file
        // may open-code the two-token
        // `figment::Error::from(<placeholder>.to_owned()).with_path(<path>)`
        // literal.
        //
        // Every test that needs a canonical
        // `figment::Error`-with-localized-path synthetic (four such call
        // sites in this file at the parent commit — one for the
        // `field_path_preserves_dotted_segments_via_with_path` accessor
        // check, one for the
        // `field_path_localization_localized_for_figment_with_field`
        // localization check, and two for the
        // `one_per_localization` / `error_localization_coordinates`
        // construction-table rows) routes through
        // `crate::source::synthetic_field_path_error(path)`, so a future
        // change to how figment attaches a localized path (a
        // hypothetical `Error::with_localized_path` replacement, an
        // owned-`String` slice bound on `with_path`, or a shape reshape
        // that carries the path as a `Vec<String>` at construction)
        // lands at ONE named site — the helper body in
        // `crate::source::synthetic_field_path_error` — and every one
        // of the four previously-open-coded call sites inherits the new
        // shape by construction. Peer of the sibling pin
        // `reload_tests_route_field_path_synthetics_through_synthetic_field_path_error`
        // in `reload.rs::tests` which closes the same drift class on
        // the two remaining call sites of the same substrate.
        //
        // Fail-before-pass-after cross-check: the shape count was 4 at
        // the parent commit (before every site routed through the
        // helper); this pin fires 4 offenders at that state and 0 here.
        //
        // Doc-comment / block-comment mentions of the pattern are
        // exempt (they explain the invariant); the check filters lines
        // whose first non-whitespace token is `//`.
        // Two-token needle: the pattern spans a `figment::Error::from(`
        // opener AND a `.with_path(` chained call on the SAME line.
        // Keeping the two fragments on separate lines of the pin body
        // (both here as `const` declarations AND in the assert message
        // via `{NEEDLE_A}` / `{NEEDLE_B}` interpolation) is what keeps
        // this pin from tripping on its own body: no non-comment line
        // inside this test carries both fragments literally.
        const NEEDLE_A: &str = "figment::Error::from(";
        const NEEDLE_B: &str = ".with_path(";
        const SRC: &str = include_str!("error.rs");
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(NEEDLE_A) && line.contains(NEEDLE_B)
            })
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "error.rs re-inlines the \
             `{NEEDLE_A}<placeholder>.to_owned()){NEEDLE_B}<path>)` \
             shape at {} non-comment line(s) — route each through \
             `crate::source::synthetic_field_path_error(path)` so a future \
             `figment::Error::with_path` shape change (or a placeholder-body \
             collapse onto `SYNTHETIC_TEST_MESSAGE`) lands at the helper body \
             instead of at each open-coded literal apart: {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn attribution_confidence_exact_slice_agrees_with_is_exact_predicate() {
        // Bidirectional weld between the slice literal
        // `AttributionConfidence::EXACT` and the boolean predicate
        // `AttributionConfidence::is_exact` on the (exact × fallback)
        // polarity axis. Every slice entry satisfies the exact pole
        // (and its complement `!is_fallback`), and every ALL cell
        // agrees on membership under the boolean predicate. Idiom-peer
        // of
        // `format_provenance_figment_builtin_slice_agrees_with_is_figment_builtin_predicate`
        // (commit `7ef79e4`) — the two independent declaration surfaces
        // (slice literal + boolean predicate) diverge at THIS pin on
        // the first confidence where they disagree, before a consumer
        // that reads one altitude but not the other can observe the
        // drift.
        for c in AttributionConfidence::EXACT.iter().copied() {
            assert!(
                c.is_exact(),
                "AttributionConfidence::EXACT entry {c:?} must satisfy is_exact()",
            );
            assert!(
                !c.is_fallback(),
                "AttributionConfidence::EXACT entry {c:?} must NOT satisfy is_fallback()",
            );
        }
        for c in AttributionConfidence::ALL.iter().copied() {
            assert_eq!(
                AttributionConfidence::EXACT.contains(&c),
                c.is_exact(),
                "EXACT membership must agree with is_exact() on AttributionConfidence::{c:?}",
            );
            assert_eq!(
                AttributionConfidence::FALLBACK.contains(&c),
                c.is_fallback(),
                "FALLBACK membership must agree with is_fallback() on AttributionConfidence::{c:?}",
            );
        }
    }

    #[test]
    fn attribution_confidence_exact_and_fallback_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `EXACT.len() + FALLBACK.len() == ALL.len()` at the slice
        // altitude on the confidence axis. Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_partition_all`
        // (commit `7ef79e4`) — a variant landing on one slice AND the
        // other, or on neither, breaks the partition here before any
        // consumer that reasons about the polarity as a covering
        // meta-partition observes the drift.
        for c in AttributionConfidence::EXACT.iter().copied() {
            assert!(
                !AttributionConfidence::FALLBACK.contains(&c),
                "AttributionConfidence::{c:?} appears in BOTH EXACT and FALLBACK",
            );
        }
        for c in AttributionConfidence::ALL.iter().copied() {
            let in_exact = AttributionConfidence::EXACT.contains(&c);
            let in_fallback = AttributionConfidence::FALLBACK.contains(&c);
            assert!(
                in_exact || in_fallback,
                "AttributionConfidence::{c:?} is in NEITHER EXACT nor FALLBACK",
            );
            assert!(
                !(in_exact && in_fallback),
                "AttributionConfidence::{c:?} is in BOTH EXACT and FALLBACK",
            );
        }
        assert_eq!(
            AttributionConfidence::EXACT.len() + AttributionConfidence::FALLBACK.len(),
            AttributionConfidence::ALL.len(),
            "EXACT and FALLBACK slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_confidence_exact_and_fallback_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in AttributionConfidence::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise, so a
        // renderer walking the two half-slices concatenated reproduces
        // the ALL order (`Exact` first, then `Fallback`). Idiom-peer
        // of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_preserve_all_order`
        // (commit `7ef79e4`) — a reordering of one slice without the
        // other, or a reordering of ALL that shuffles the two poles'
        // variant order without updating the slices, diverges at THIS
        // pin.
        let exact_from_all: Vec<AttributionConfidence> = AttributionConfidence::ALL
            .iter()
            .copied()
            .filter(|c| c.is_exact())
            .collect();
        assert_eq!(
            exact_from_all,
            AttributionConfidence::EXACT.to_vec(),
            "EXACT must be ALL-filtered by is_exact in declaration order",
        );
        let fallback_from_all: Vec<AttributionConfidence> = AttributionConfidence::ALL
            .iter()
            .copied()
            .filter(|c| c.is_fallback())
            .collect();
        assert_eq!(
            fallback_from_all,
            AttributionConfidence::FALLBACK.to_vec(),
            "FALLBACK must be ALL-filtered by is_fallback in declaration order",
        );
    }

    #[test]
    fn attribution_confidence_exact_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into FALLBACK, an accidental re-add of an already-present
        // Exact cell into EXACT) fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set. Idiom-peer of
        // `format_provenance_figment_builtin_slice_has_no_duplicates`
        // (commit `7ef79e4`).
        for slice in [
            AttributionConfidence::EXACT,
            AttributionConfidence::FALLBACK,
        ] {
            let deduped_len = {
                let mut seen: Vec<AttributionConfidence> = Vec::with_capacity(slice.len());
                for c in slice {
                    if !seen.contains(c) {
                        seen.push(*c);
                    }
                }
                seen.len()
            };
            assert_eq!(
                deduped_len,
                slice.len(),
                "AttributionConfidence slice {slice:?} contains duplicate entries",
            );
        }
    }

    #[test]
    fn attribution_confidence_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionConfidence::ALL —
        // i.e., `EXACT.len() == ALL.iter().filter(is_exact).count()`
        // and `FALLBACK.len() == ALL.iter().filter(is_fallback).count()`
        // — the cardinality projection at the slice altitude agrees
        // with the boolean-altitude projection on both halves.
        // Concrete positions today: 1 exact + 1 fallback = 2 = ALL.
        // Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (commit `7ef79e4`).
        let exact_count = AttributionConfidence::ALL
            .iter()
            .copied()
            .filter(|c| c.is_exact())
            .count();
        let fallback_count = AttributionConfidence::ALL
            .iter()
            .copied()
            .filter(|c| c.is_fallback())
            .count();
        assert_eq!(
            AttributionConfidence::EXACT.len(),
            exact_count,
            "EXACT.len() must match the is_exact count on ALL",
        );
        assert_eq!(
            AttributionConfidence::FALLBACK.len(),
            fallback_count,
            "FALLBACK.len() must match the is_fallback count on ALL",
        );
        assert_eq!(AttributionConfidence::EXACT.len(), 1);
        assert_eq!(AttributionConfidence::FALLBACK.len(), 1);
        assert_eq!(AttributionConfidence::ALL.len(), 2);
    }

    #[test]
    fn attribution_confidence_exact_and_fallback_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_are_const_addressable`
        // (commit `7ef79e4`).
        const EXACT_LEN: usize = AttributionConfidence::EXACT.len();
        const FALLBACK_LEN: usize = AttributionConfidence::FALLBACK.len();
        const ALL_LEN: usize = AttributionConfidence::ALL.len();
        assert_eq!(EXACT_LEN, 1);
        assert_eq!(FALLBACK_LEN, 1);
        assert_eq!(EXACT_LEN + FALLBACK_LEN, ALL_LEN);
    }

    #[test]
    fn attribution_axis_metadata_source_slice_agrees_with_is_metadata_source_predicate() {
        // Bidirectional weld between the slice literal
        // `AttributionAxis::METADATA_SOURCE` and the boolean predicate
        // `AttributionAxis::is_metadata_source` on the (source × name)
        // polarity axis. Every slice entry satisfies the source pole
        // (and its complement `!is_metadata_name`), and every ALL cell
        // agrees on membership under the boolean predicate. Idiom-peer
        // of
        // `attribution_confidence_exact_slice_agrees_with_is_exact_predicate`
        // (commit `13c1003`) — the two independent declaration
        // surfaces (slice literal + boolean predicate) diverge at THIS
        // pin on the first axis where they disagree, before a consumer
        // that reads one altitude but not the other can observe the
        // drift.
        for a in AttributionAxis::METADATA_SOURCE.iter().copied() {
            assert!(
                a.is_metadata_source(),
                "AttributionAxis::METADATA_SOURCE entry {a:?} must satisfy is_metadata_source()",
            );
            assert!(
                !a.is_metadata_name(),
                "AttributionAxis::METADATA_SOURCE entry {a:?} must NOT satisfy is_metadata_name()",
            );
        }
        for a in AttributionAxis::ALL.iter().copied() {
            assert_eq!(
                AttributionAxis::METADATA_SOURCE.contains(&a),
                a.is_metadata_source(),
                "METADATA_SOURCE membership must agree with is_metadata_source() on AttributionAxis::{a:?}",
            );
            assert_eq!(
                AttributionAxis::METADATA_NAME.contains(&a),
                a.is_metadata_name(),
                "METADATA_NAME membership must agree with is_metadata_name() on AttributionAxis::{a:?}",
            );
        }
    }

    #[test]
    fn attribution_axis_metadata_source_and_metadata_name_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `METADATA_SOURCE.len() + METADATA_NAME.len() == ALL.len()`
        // at the slice altitude on the metadata axis. Idiom-peer of
        // `attribution_confidence_exact_and_fallback_slices_partition_all`
        // (commit `13c1003`) — a variant landing on one slice AND the
        // other, or on neither, breaks the partition here before any
        // consumer that reasons about the polarity as a covering
        // meta-partition observes the drift.
        for a in AttributionAxis::METADATA_SOURCE.iter().copied() {
            assert!(
                !AttributionAxis::METADATA_NAME.contains(&a),
                "AttributionAxis::{a:?} appears in BOTH METADATA_SOURCE and METADATA_NAME",
            );
        }
        for a in AttributionAxis::ALL.iter().copied() {
            let in_source = AttributionAxis::METADATA_SOURCE.contains(&a);
            let in_name = AttributionAxis::METADATA_NAME.contains(&a);
            assert!(
                in_source || in_name,
                "AttributionAxis::{a:?} is in NEITHER METADATA_SOURCE nor METADATA_NAME",
            );
            assert!(
                !(in_source && in_name),
                "AttributionAxis::{a:?} is in BOTH METADATA_SOURCE and METADATA_NAME",
            );
        }
        assert_eq!(
            AttributionAxis::METADATA_SOURCE.len() + AttributionAxis::METADATA_NAME.len(),
            AttributionAxis::ALL.len(),
            "METADATA_SOURCE and METADATA_NAME slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn attribution_axis_metadata_source_and_metadata_name_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in AttributionAxis::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise, so a
        // renderer walking the two half-slices concatenated reproduces
        // the ALL order (`MetadataSource` first, then `MetadataName`).
        // Idiom-peer of
        // `attribution_confidence_exact_and_fallback_slices_preserve_all_order`
        // (commit `13c1003`) — a reordering of one slice without the
        // other, or a reordering of ALL that shuffles the two poles'
        // variant order without updating the slices, diverges at THIS
        // pin.
        let source_from_all: Vec<AttributionAxis> = AttributionAxis::ALL
            .iter()
            .copied()
            .filter(|a| a.is_metadata_source())
            .collect();
        assert_eq!(
            source_from_all,
            AttributionAxis::METADATA_SOURCE.to_vec(),
            "METADATA_SOURCE must be ALL-filtered by is_metadata_source in declaration order",
        );
        let name_from_all: Vec<AttributionAxis> = AttributionAxis::ALL
            .iter()
            .copied()
            .filter(|a| a.is_metadata_name())
            .collect();
        assert_eq!(
            name_from_all,
            AttributionAxis::METADATA_NAME.to_vec(),
            "METADATA_NAME must be ALL-filtered by is_metadata_name in declaration order",
        );
    }

    #[test]
    fn attribution_axis_metadata_source_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into METADATA_NAME, an accidental re-add of an already-
        // present MetadataSource cell into METADATA_SOURCE) fails at
        // THIS pin before drifting through any consumer that iterates
        // the slice expecting a set. Idiom-peer of
        // `attribution_confidence_exact_slice_has_no_duplicates`
        // (commit `13c1003`).
        for slice in [
            AttributionAxis::METADATA_SOURCE,
            AttributionAxis::METADATA_NAME,
        ] {
            let deduped_len = {
                let mut seen: Vec<AttributionAxis> = Vec::with_capacity(slice.len());
                for a in slice {
                    if !seen.contains(a) {
                        seen.push(*a);
                    }
                }
                seen.len()
            };
            assert_eq!(
                deduped_len,
                slice.len(),
                "AttributionAxis slice {slice:?} contains duplicate entries",
            );
        }
    }

    #[test]
    fn attribution_axis_metadata_source_and_metadata_name_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on AttributionAxis::ALL —
        // i.e., `METADATA_SOURCE.len() ==
        // ALL.iter().filter(is_metadata_source).count()` and
        // `METADATA_NAME.len() ==
        // ALL.iter().filter(is_metadata_name).count()` — the
        // cardinality projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete
        // positions today: 1 source + 1 name = 2 = ALL. Idiom-peer of
        // `attribution_confidence_exact_and_fallback_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (commit `13c1003`).
        let source_count = AttributionAxis::ALL
            .iter()
            .copied()
            .filter(|a| a.is_metadata_source())
            .count();
        let name_count = AttributionAxis::ALL
            .iter()
            .copied()
            .filter(|a| a.is_metadata_name())
            .count();
        assert_eq!(
            AttributionAxis::METADATA_SOURCE.len(),
            source_count,
            "METADATA_SOURCE.len() must match the is_metadata_source count on ALL",
        );
        assert_eq!(
            AttributionAxis::METADATA_NAME.len(),
            name_count,
            "METADATA_NAME.len() must match the is_metadata_name count on ALL",
        );
        assert_eq!(AttributionAxis::METADATA_SOURCE.len(), 1);
        assert_eq!(AttributionAxis::METADATA_NAME.len(), 1);
        assert_eq!(AttributionAxis::ALL.len(), 2);
    }

    #[test]
    fn attribution_axis_metadata_source_and_metadata_name_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `attribution_confidence_exact_and_fallback_slices_are_const_addressable`
        // (commit `13c1003`).
        const METADATA_SOURCE_LEN: usize = AttributionAxis::METADATA_SOURCE.len();
        const METADATA_NAME_LEN: usize = AttributionAxis::METADATA_NAME.len();
        const ALL_LEN: usize = AttributionAxis::ALL.len();
        assert_eq!(METADATA_SOURCE_LEN, 1);
        assert_eq!(METADATA_NAME_LEN, 1);
        assert_eq!(METADATA_SOURCE_LEN + METADATA_NAME_LEN, ALL_LEN);
    }
}

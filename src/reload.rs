//! Observable reload failure summary.
//!
//! [`ReloadFailure`] is the typed, [`Clone`]-able shape that
//! [`crate::ConfigStore`] publishes when a reload — manual
//! ([`crate::ConfigStore::reload`]) or hot-reload (the watcher in
//! [`crate::ConfigStore::load_and_watch`]) — fails. The slot is cleared
//! atomically when a subsequent reload succeeds, so observers get a
//! "most recent unrecovered failure" hint, not a history.
//!
//! [`crate::ShikumiError`] itself is not [`Clone`] (it boxes
//! `figment::Error`, which is not Clone). `ReloadFailure` is the
//! cross-thread observable form: a typed value that captures the
//! display string and the [`crate::ConfigSource`] chain at the moment
//! the failure was caught.

use std::fmt;

use crate::error::{
    AttributionAxis, AttributionConfidence, AttributionCoordinates, AttributionRule,
    ErrorLocalizationCoordinates, FailingSourceAttribution, FieldPathLocalization, ShikumiError,
    ShikumiErrorKind,
};
use crate::source::{ConfigSource, ConfigSourceKind, FigmentSourceKind};

/// A clone-able summary of the most recent reload failure on a
/// [`crate::ConfigStore`].
///
/// Pairs with [`crate::ConfigStore::generation`]: when an observer sees
/// the generation has not advanced past a checkpoint and a
/// [`ReloadFailure`] is present, the failure is the reason the
/// expected publish did not happen.
///
/// `#[non_exhaustive]` so future fidelity work (per-field path,
/// file/line spans, source provenance for non-`Extract` variants)
/// lands additively.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReloadFailure {
    /// Human-readable display of the underlying error, captured via
    /// [`std::fmt::Display`] at the moment the failure was caught.
    pub message: String,
    /// Closed-enum kind of the underlying [`ShikumiError`] that caused
    /// this reload failure, captured from
    /// [`crate::ShikumiError::kind`] at the moment the failure was
    /// caught. Total over the [`ReloadFailure`] surface — every captured
    /// failure has exactly one kind, regardless of whether attribution
    /// could be resolved.
    ///
    /// Surfaces the [`ShikumiErrorKind`] partition on the cross-thread
    /// observable envelope so consumers reading
    /// [`crate::ConfigStore::last_reload_error`] can bucket reload
    /// failures by error class (per-kind alert thresholds, per-kind
    /// dashboards, per-kind retry policies) with one closed-enum read
    /// instead of grepping the [`Self::message`] string. Pairs with
    /// [`Self::attribution_rule`] (rule axis, partial), [`Self::layer_kind`]
    /// (layer-kind axis, partial), and [`Self::attribution_confidence`]
    /// (confidence axis, partial) to give observers the full
    /// (kind × layer-kind × rule × confidence) projection of every
    /// captured failure as four typed reads.
    pub kind: ShikumiErrorKind,
    /// Provider chain in merge order at the moment of failure.
    /// Populated for [`crate::ShikumiError::Extract`]; empty for
    /// variants that do not record a chain (see
    /// [`crate::ShikumiError::sources`]).
    pub sources: Vec<ConfigSource>,
    /// Dotted field path of the offending key at the moment of failure,
    /// captured from [`crate::ShikumiError::field_path`]. Populated for
    /// extraction failures that figment could localize (e.g. a type
    /// mismatch on a typed field renders as `["count"]`); empty for
    /// non-figment-bearing variants and figment errors without a key
    /// context.
    pub field_path: Vec<String>,
    /// Specific [`ConfigSource`] in [`Self::sources`] that produced the
    /// offending value, captured from
    /// [`crate::ShikumiError::failing_source`] at the moment the failure
    /// was caught. Owned [`ConfigSource`] so the slot survives any
    /// borrow on the originating error.
    ///
    /// `None` for non-`Extract` failures, for `Extract` failures whose
    /// figment error did not carry per-value `Metadata`, and when the
    /// metadata could not be matched to any entry in the recorded
    /// chain. Pairs with [`Self::sources`] (full chain),
    /// [`Self::field_path`] (offending key),
    /// [`Self::attribution_rule`] (why the layer was blamed), and
    /// [`Self::layer_kind`] (file/env/defaults class of the blamed
    /// layer): when present, the tuple pins
    /// `(which-layer × which-field × which-rule × which-kind)` for
    /// the specific failure.
    pub failing_source: Option<ConfigSource>,
    /// The [`AttributionRule`] under which [`Self::failing_source`]
    /// was attributed, captured from
    /// [`crate::ShikumiError::failing_attribution`] at the moment the
    /// failure was caught. `Some(_)` exactly when
    /// [`Self::failing_source`] is `Some(_)`; `None` otherwise.
    ///
    /// Distinguishes *exact* attribution
    /// ([`AttributionRule::FileBySource`] /
    /// [`AttributionRule::FileByMetadataName`] /
    /// [`AttributionRule::EnvByPrefix`]) from *fallback* attribution
    /// ([`AttributionRule::EnvByUniqueness`] /
    /// [`AttributionRule::DefaultsByCodeUniqueness`]) for observers
    /// that want to weight the two differently in dashboards or
    /// alerting policies.
    pub attribution_rule: Option<AttributionRule>,
}

impl ReloadFailure {
    /// Capture a [`ReloadFailure`] from a [`ShikumiError`] reference.
    ///
    /// The error itself is not consumed — only its display string,
    /// recorded source chain (if any), and dotted field path (if any)
    /// are copied. This is the one canonical constructor; both
    /// [`crate::ConfigStore::reload`] and the
    /// [`crate::ConfigStore::load_and_watch`] watcher closure use it on
    /// the failure path.
    #[must_use]
    pub fn from_error(err: &ShikumiError) -> Self {
        let attribution = err.failing_attribution();
        Self {
            message: err.to_string(),
            kind: err.kind(),
            sources: err.sources().map(<[_]>::to_vec).unwrap_or_default(),
            field_path: err.field_path().map(<[_]>::to_vec).unwrap_or_default(),
            failing_source: attribution.map(|a| a.source.clone()),
            attribution_rule: attribution.map(|a| a.rule),
        }
    }

    /// [`ShikumiErrorKind`] of the underlying error this failure was
    /// captured from — convenience accessor over [`Self::kind`] (the
    /// public field). Total over the [`ReloadFailure`] surface (no
    /// [`Option`]): every captured failure has exactly one kind, peer to
    /// the way every [`ShikumiError`] always answers
    /// [`ShikumiError::kind`].
    ///
    /// Surfaces the kind axis on the cross-thread observable envelope so
    /// observers (dashboards, alerting policies, structured-log routers)
    /// route on error class without re-deriving from [`Self::message`]
    /// or destructuring the underlying [`ShikumiError`]. The accessor
    /// is the structural peer of [`Self::attribution_confidence`] and
    /// [`Self::layer_kind`] — typed projection over the captured
    /// failure surface — but its return type is
    /// [`ShikumiErrorKind`] (not `Option<_>`), because every error has
    /// a kind even when no attribution can be resolved.
    ///
    /// Composes orthogonally with [`Self::layer_kind`] (over the
    /// (file × env × defaults) axis) and
    /// [`Self::attribution_confidence`] (over the (exact × fallback)
    /// axis): together the three accessors close the
    /// (kind × layer-kind × confidence) projection over the failure
    /// surface. The kind axis is the only one of the three that is
    /// always populated; the other two answer
    /// `None` for non-attributed failures.
    #[must_use]
    pub fn kind(&self) -> ShikumiErrorKind {
        self.kind
    }

    /// Confidence class of [`Self::attribution_rule`], or `None`
    /// when no attribution was recorded — strict superset of
    /// [`Self::attribution_rule`]`.map(AttributionRule::confidence)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies) don't re-derive the exact-vs-fallback
    /// partition at every site.
    ///
    /// Returns `Some(_)` exactly when [`Self::attribution_rule`] is
    /// `Some(_)`; `None` otherwise. Pairs with
    /// [`Self::failing_source`] (which layer), [`Self::layer_kind`]
    /// (which kind of layer), and [`Self::attribution_rule`] (why
    /// named) to give observers the (which-layer × which-kind ×
    /// which-rule × how-confident) attribution quadruple in four
    /// closed-enum reads.
    #[must_use]
    pub fn attribution_confidence(&self) -> Option<AttributionConfidence> {
        self.attribution_rule.map(AttributionRule::confidence)
    }

    /// [`ConfigSourceKind`] of the layer blamed for the failure, or
    /// `None` when no attribution was recorded — strict superset of
    /// [`Self::attribution_rule`]`.map(AttributionRule::layer_kind)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies, structured-log routers) don't re-derive
    /// the (file × env × defaults) partition at every site.
    ///
    /// Returns `Some(_)` exactly when [`Self::attribution_rule`] is
    /// `Some(_)` (equivalently: when [`Self::failing_source`] is
    /// `Some(_)`); `None` otherwise. Equal to
    /// `self.failing_source.as_ref().map(ConfigSource::kind)` by
    /// construction — the cross-primitive
    /// `attr.rule.layer_kind() == attr.source.kind()` invariant from
    /// [`crate::FailingSourceAttribution`] propagates through
    /// [`Self::from_error`] into this slot, pinned end-to-end by
    /// `layer_kind_agrees_with_failing_source_kind_when_attributed`.
    ///
    /// Composes with [`Self::attribution_confidence`]: orthogonal
    /// projections over the rule space along the
    /// (file × env × defaults) and (exact × fallback) axes
    /// respectively. Observers reading
    /// `Arc<ReloadFailure>` from
    /// [`crate::ConfigStore::last_reload_error`] route on layer-kind
    /// without destructuring the rule, and weight fallback
    /// attributions visibly via the confidence accessor — both
    /// reads land as one closed-enum match each.
    #[must_use]
    pub fn layer_kind(&self) -> Option<ConfigSourceKind> {
        self.attribution_rule.map(AttributionRule::layer_kind)
    }

    /// [`AttributionAxis`] of the rule that named the blamed layer,
    /// or `None` when no attribution was recorded — strict superset
    /// of [`Self::attribution_rule`]`.map(AttributionRule::metadata_axis)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies, attestation manifests) don't re-derive the
    /// (`metadata.source` × `metadata.name`) partition at every
    /// observation site.
    ///
    /// Returns `Some(_)` exactly when [`Self::attribution_rule`] is
    /// `Some(_)` (equivalently: when [`Self::failing_source`] is
    /// `Some(_)`); `None` otherwise. Composes with
    /// [`Self::layer_kind`] (file × env × defaults) and
    /// [`Self::attribution_confidence`] (exact × fallback) as the
    /// third orthogonal projection over the rule space, giving
    /// observers the (axis × layer-kind × confidence) coordinates
    /// of every attributed failure as three closed-enum reads.
    ///
    /// Operationally distinguishes attributions driven by figment's
    /// typed source classification (structurally stable —
    /// [`AttributionAxis::MetadataSource`]) from attributions driven
    /// by parsing figment's human-readable provider-name string
    /// (string-shape-dependent — [`AttributionAxis::MetadataName`]).
    /// Observers that want to weight name-axis attributions visibly
    /// weaker than source-axis ones — peer to weighting
    /// [`AttributionConfidence::Fallback`] weaker than
    /// [`AttributionConfidence::Exact`] — read this accessor.
    #[must_use]
    pub fn metadata_axis(&self) -> Option<AttributionAxis> {
        self.attribution_rule.map(AttributionRule::metadata_axis)
    }

    /// [`FigmentSourceKind`] structurally pinned by
    /// [`Self::attribution_rule`], or `None` when no attribution was
    /// recorded *or* when the recorded attribution is name-axis
    /// (where the rule's identity does not constrain
    /// `figment::Metadata::source`) — strict superset of
    /// [`Self::attribution_rule`]`.and_then(AttributionRule::figment_source_kind)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies, attestation manifests) don't re-derive the
    /// (`Source::File` × `Source::Code` × `Source::Custom` × no-rule
    /// × name-axis) partition at every observation site.
    ///
    /// Two-stage `None` discipline: (1) `None` when no attribution
    /// was recorded ([`Self::attribution_rule`] is [`None`]),
    /// (2) `None` when the recorded attribution is name-axis
    /// ([`Self::metadata_axis`] is
    /// [`Some(AttributionAxis::MetadataName)`]) — neither path pins a
    /// figment-Source-axis cell. Source-axis attributions
    /// ([`AttributionRule::FileBySource`] →
    /// [`Some(FigmentSourceKind::File)`],
    /// [`AttributionRule::DefaultsByCodeUniqueness`] →
    /// [`Some(FigmentSourceKind::Code)`]) surface a [`Some`] cell
    /// directly. Operationally distinguishes "no provenance at all"
    /// from "name-axis provenance whose figment Source kind was not
    /// retained" — observers cannot recover figment's `Source`
    /// classification off the cross-thread envelope, but they can
    /// route on whether the attribution rule already pinned it.
    ///
    /// Composes with [`Self::metadata_axis`] as a refinement on the
    /// source-axis cells: when `Some`, the projection is
    /// [`Some`] exactly when [`Self::metadata_axis`] returns
    /// [`Some(AttributionAxis::MetadataSource)`]. Pinned by
    /// `figment_source_kind_some_iff_metadata_axis_metadata_source`.
    /// Composes with [`Self::layer_kind`] as a partial diagonal: when
    /// `Some`, `(figment_source_kind, layer_kind) ∈ {(File, File),
    /// (Code, Defaults)}` — pinned by
    /// `figment_source_kind_agrees_with_layer_kind_pointwise_when_some`.
    #[must_use]
    pub fn figment_source_kind(&self) -> Option<FigmentSourceKind> {
        self.attribution_rule
            .and_then(AttributionRule::figment_source_kind)
    }

    /// Coordinate triple of [`Self::attribution_rule`], or `None` when
    /// no attribution was recorded — strict superset of the three
    /// sibling Option-returning accessors
    /// ([`Self::attribution_confidence`], [`Self::layer_kind`],
    /// [`Self::metadata_axis`]) collapsed into one
    /// [`Option<AttributionCoordinates>`] read.
    ///
    /// Returns `Some(_)` exactly when [`Self::attribution_rule`] is
    /// `Some(_)` (equivalently: when [`Self::failing_source`] is
    /// `Some(_)`); `None` otherwise. The same `Some-iff-attribution`
    /// discipline as the sibling projections — pinned by
    /// `coordinates_some_iff_attribution_rule_some`.
    ///
    /// One source of truth for the (axis × layer-kind × confidence)
    /// triple on the cross-thread observable envelope. Before this
    /// accessor, observers reading
    /// [`crate::ConfigStore::last_reload_error`] inlined three
    /// `self.attribution_rule.map(AttributionRule::*)` calls at every
    /// site — a recurring three-line pattern. The named struct
    /// [`AttributionCoordinates`] collapses them to one read,
    /// surfacing the triple as a typescape value (`Copy + Eq + Hash`)
    /// usable as a `HashMap` key, log label, or attestation-manifest
    /// payload without consumers re-deriving the triple at every
    /// observation site.
    ///
    /// Pairs with [`AttributionRule::from_coordinates`]: an observer
    /// that captured the [`AttributionCoordinates`] of a previous
    /// failure (e.g. into a structured-log line) can re-hydrate the
    /// originating rule by one method call, recovering the closed-enum
    /// rule identity from its coordinates without retaining the
    /// originating [`crate::ShikumiError`]. The bijection is pinned by
    /// `coordinates_round_trip_through_from_coordinates`.
    #[must_use]
    pub fn coordinates(&self) -> Option<AttributionCoordinates> {
        self.attribution_rule.map(AttributionRule::coordinates)
    }

    /// Borrowed [`FailingSourceAttribution`] envelope fused from the
    /// two parallel [`Self::failing_source`] / [`Self::attribution_rule`]
    /// slots — peer to [`crate::ShikumiError::failing_attribution`] on
    /// the live error surface, lifted onto the cross-thread observable
    /// form.
    ///
    /// Returns [`Some`] exactly when both slots are populated
    /// (the [`Some`]-iff-attribution invariant pinned by
    /// `from_error_attribution_rule_some_iff_failing_source_some`),
    /// [`None`] otherwise. Reuses the existing borrowed envelope shape
    /// rather than introducing a new owned counterpart: the source
    /// borrows into [`Self::failing_source`], the rule is [`Copy`], and
    /// the envelope shares the captured failure's lifetime.
    ///
    /// One source of truth for the (`failing_source` × `attribution_rule`)
    /// pair on the captured envelope. Before this accessor, observers
    /// reading [`crate::ConfigStore::last_reload_error`] either read the
    /// two parallel [`Option`] fields and re-paired them inline (a
    /// recurring two-line pattern at every site that wanted both
    /// halves), or read each through one of the four sibling
    /// projection accessors ([`Self::attribution_confidence`],
    /// [`Self::layer_kind`], [`Self::metadata_axis`],
    /// [`Self::coordinates`]) and lost the [`ConfigSource`] half. This
    /// accessor returns the structurally-coherent pair as one read,
    /// surfaced through the same envelope shape that
    /// [`crate::ShikumiError::failing_attribution`] returns on the
    /// live-error side.
    ///
    /// Structurally pins the [`Some`]-iff-attribution invariant: even
    /// if the two public field slots somehow drifted out of agreement
    /// (e.g. a future construction site or a deserialized payload
    /// landed inconsistent halves), this accessor returns [`None`]
    /// unless both slots are populated — the legal subset of the
    /// 2 × 2 = 4 product cells of the (`failing_source.is_some()` ×
    /// `attribution_rule.is_some()`) cube is exactly the diagonal
    /// (both [`Some`], both [`None`]), and the envelope projection
    /// collapses any off-diagonal cell back to [`None`]. The contract
    /// is pinned by `failing_attribution_some_iff_both_halves_populated`.
    ///
    /// Mirrors [`crate::ShikumiError::failing_attribution`] pointwise
    /// on every captured failure: the lossless-capture contract for
    /// the attribution envelope is pinned by
    /// `failing_attribution_agrees_with_underlying_error_pointwise`.
    /// A future field added to [`FailingSourceAttribution`] (e.g. a
    /// per-attribution span, a confidence weight, a captured
    /// `figment::Metadata` slice) propagates through this accessor
    /// once, not through every observation site.
    ///
    /// Composes with [`Self::coordinates`]: both are partial
    /// projections of the same attribution slot, populated under the
    /// same [`Some`]-iff-attribution discipline. The envelope carries
    /// the [`ConfigSource`] alongside the [`AttributionRule`];
    /// [`Self::coordinates`] drops the source and returns the
    /// (axis × layer-kind × confidence) triple for consumers that
    /// only need the rule's coordinates.
    #[must_use]
    pub fn failing_attribution(&self) -> Option<FailingSourceAttribution<'_>> {
        match (&self.failing_source, self.attribution_rule) {
            (Some(source), Some(rule)) => Some(FailingSourceAttribution::new(source, rule)),
            _ => None,
        }
    }

    /// Closed-enum classification of this captured failure's
    /// field-path localization state — the typed tri-state projection
    /// over the [`Self::field_path`] / [`Self::kind`] pair.
    ///
    /// The cross-thread observable form of [`ReloadFailure`] stores
    /// the offending field path as a flat [`Vec<String>`], collapsing
    /// the original [`Option<&[String]>`] tri-state of
    /// [`crate::ShikumiError::field_path`] into bi-state
    /// (empty / non-empty). Observers reading
    /// [`crate::ConfigStore::last_reload_error`] previously had to
    /// consult both [`Self::kind`] (to ask "is this kind even
    /// figment-bearing?" via
    /// [`ShikumiErrorKind::is_figment_bearing`]) and
    /// `Self::field_path.is_empty()` together to recover the original
    /// tri-state; this accessor lifts the recovery into the type
    /// system as a closed [`FieldPathLocalization`] enum.
    ///
    /// Total over the [`ReloadFailure`] surface — every captured
    /// failure has exactly one localization classification, peer to
    /// [`Self::kind`] (which is also total). Pairs with
    /// [`Self::attribution_confidence`] (confidence axis, partial),
    /// [`Self::layer_kind`] (layer-kind axis, partial), and
    /// [`Self::attribution_rule`] (rule axis, partial) to give
    /// observers the full
    /// (kind × localization × layer-kind × rule × confidence)
    /// projection of every captured failure as five typed reads.
    ///
    /// Agrees pointwise with
    /// [`crate::ShikumiError::field_path_localization`] on every
    /// captured failure: the lossless-capture contract for the
    /// localization axis is pinned by
    /// `field_path_localization_agrees_with_underlying_error_pointwise`.
    /// A future variant landing on [`FieldPathLocalization`] forces a
    /// classification at every consumer's exhaustive match, in
    /// lockstep with the partition surfaced on
    /// [`crate::ShikumiError`].
    #[must_use]
    pub fn field_path_localization(&self) -> FieldPathLocalization {
        if self.kind.is_figment_bearing() {
            if self.field_path.is_empty() {
                FieldPathLocalization::FigmentUnlocalized
            } else {
                FieldPathLocalization::Localized
            }
        } else {
            FieldPathLocalization::NotApplicable
        }
    }

    /// Coordinate pair over the two orthogonal closed-enum
    /// projections every captured failure carries on the error-path-
    /// fidelity surface — [`Self::kind`] (which variant) and
    /// [`Self::field_path_localization`] (figment-attached or not).
    ///
    /// Total over the [`ReloadFailure`] surface — every captured
    /// failure has exactly one coordinate cell in the 18-cell
    /// product cube [`ErrorLocalizationCoordinates::ALL`], and the
    /// produced cell always satisfies
    /// [`ErrorLocalizationCoordinates::is_realizable`] (pinned by
    /// `error_localization_coordinates_returns_realizable_cell` over
    /// the captured-failure surface).
    ///
    /// Cross-thread mirror of
    /// [`ShikumiError::error_localization_coordinates`]: the
    /// captured envelope's coordinates agree pointwise with the
    /// underlying error's, pinning the lossless-capture contract for
    /// the (kind × localization) coordinate plane on the
    /// cross-thread observable form. Pinned by
    /// `error_localization_coordinates_agrees_with_underlying_error_pointwise`.
    ///
    /// Strict superset of the two sibling accessors
    /// ([`Self::kind`], [`Self::field_path_localization`]): the
    /// coordinate carries both as one `Copy` value, usable in
    /// `match`, `HashMap` keys, structured-log payloads, and
    /// attestation manifests without re-reading the two projections
    /// separately.
    #[must_use]
    pub fn error_localization_coordinates(&self) -> ErrorLocalizationCoordinates {
        ErrorLocalizationCoordinates {
            kind: self.kind(),
            localization: self.field_path_localization(),
        }
    }
}

impl fmt::Display for ReloadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_figment_error() -> Box<figment::Error> {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        Box::new(result.unwrap_err())
    }

    #[test]
    fn from_error_captures_display_message() {
        let err = ShikumiError::Parse("oops".to_owned());
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.message, err.to_string());
        assert!(f.message.contains("oops"));
    }

    #[test]
    fn from_error_captures_sources_for_extract_variant() {
        let chain = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain.clone(),
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.sources, chain);
    }

    #[test]
    fn from_error_yields_empty_sources_for_non_extract_variant() {
        let err = ShikumiError::Parse("x".to_owned());
        let f = ReloadFailure::from_error(&err);
        assert!(f.sources.is_empty());
    }

    #[test]
    fn from_error_yields_empty_sources_for_figment_variant() {
        let err = ShikumiError::Figment(fake_figment_error());
        let f = ReloadFailure::from_error(&err);
        assert!(f.sources.is_empty());
    }

    #[test]
    fn display_renders_message() {
        let f = ReloadFailure {
            message: "broken pipe".to_owned(),
            kind: ShikumiErrorKind::Parse,
            sources: vec![],
            field_path: vec![],
            failing_source: None,
            attribution_rule: None,
        };
        assert_eq!(f.to_string(), "broken pipe");
    }

    #[test]
    fn clone_preserves_data() {
        let f = ReloadFailure {
            message: "bad".to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![ConfigSource::Defaults],
            field_path: vec!["a".to_owned(), "b".to_owned()],
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };
        let g = f.clone();
        assert_eq!(g.message, f.message);
        assert_eq!(g.kind, f.kind);
        assert_eq!(g.sources, f.sources);
        assert_eq!(g.field_path, f.field_path);
        assert_eq!(g.failing_source, f.failing_source);
        assert_eq!(g.attribution_rule, f.attribution_rule);
    }

    #[test]
    fn from_error_does_not_consume_source() {
        let err = ShikumiError::Parse("keepable".to_owned());
        let _f = ReloadFailure::from_error(&err);
        // err still usable
        assert!(err.is_parse());
    }

    #[test]
    fn from_error_carries_path_provenance() {
        let path = PathBuf::from("/srv/cfg/app.yaml");
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::File(path.clone())],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.sources.len(), 1);
        assert_eq!(f.sources[0].as_path(), Some(path.as_path()));
    }

    // ---- field_path capture tests ----

    #[test]
    fn from_error_captures_field_path_for_extract_with_localized_field() {
        // Build a figment error that *has* a path attribution.
        let raw = figment::Error::from("typed".to_owned()).with_path("window.size");
        let err = ShikumiError::Extract {
            sources: vec![],
            error: Box::new(raw),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.field_path, vec!["window".to_owned(), "size".to_owned()]);
    }

    #[test]
    fn from_error_captures_empty_field_path_for_extract_without_localized_field() {
        // Bare figment::Error has no path; capture surfaces an empty Vec,
        // not panic, not None.
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.field_path.is_empty());
    }

    #[test]
    fn from_error_captures_empty_field_path_for_non_figment_variant() {
        let err = ShikumiError::Parse("bad".to_owned());
        let f = ReloadFailure::from_error(&err);
        assert!(
            f.field_path.is_empty(),
            "non-figment errors yield an empty field_path, not a missing one"
        );
    }

    #[test]
    fn from_error_captures_field_path_for_figment_variant() {
        let raw = figment::Error::from("typed".to_owned()).with_path("a.b.c");
        let err = ShikumiError::Figment(Box::new(raw));
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.field_path,
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
    }

    // ---- failing_source capture tests ----

    #[test]
    fn from_error_captures_failing_source_for_attributed_extract() {
        // Build a real attributed Extract: type mismatch on a file-only
        // value, env layer present but irrelevant to the offending field.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_env("RF_ATTR_NOTSET_")
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        let attributed = f
            .failing_source
            .expect("Extract attribution must propagate to ReloadFailure");
        assert!(attributed.is_file());
        assert_eq!(attributed.as_path(), Some(file.as_path()));
    }

    #[test]
    fn from_error_yields_none_failing_source_for_unattributed_extract() {
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(
            f.failing_source.is_none(),
            "no metadata to map → no failing_source"
        );
    }

    #[test]
    fn from_error_yields_none_failing_source_for_non_extract_variants() {
        assert!(
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned()))
                .failing_source
                .is_none()
        );
        assert!(
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error()))
                .failing_source
                .is_none()
        );
    }

    #[test]
    fn from_error_failing_source_owns_clone_independent_of_error_lifetime() {
        // Capture from a borrowed error, then drop the error. The
        // captured failing_source must remain valid (it's an owned
        // ConfigSource clone).
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_owned.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let f = {
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let owned = f.failing_source.expect("owned attribution survives drop");
        assert_eq!(owned.as_path(), Some(file.as_path()));
    }

    // ---- attribution_rule capture tests ----

    #[test]
    fn from_error_captures_attribution_rule_for_file_by_source() {
        // Real YAML file extract: figment attaches Source::File, the
        // resolver fires FileBySource. The rule must propagate to the
        // ReloadFailure alongside the source.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_rule.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.attribution_rule, Some(AttributionRule::FileBySource));
        assert!(f.failing_source.is_some());
    }

    #[test]
    fn from_error_attribution_rule_some_iff_failing_source_some() {
        // Invariant: the rule slot is populated exactly when the source
        // slot is. Across every variant.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        // Attributed: both Some.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("inv.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let attributed = ReloadFailure::from_error(
            &ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err(),
        );
        assert_eq!(
            attributed.failing_source.is_some(),
            attributed.attribution_rule.is_some()
        );
        assert!(attributed.failing_source.is_some());

        // Unattributed Extract: both None.
        let unattr = ReloadFailure::from_error(&ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        });
        assert!(unattr.failing_source.is_none());
        assert!(unattr.attribution_rule.is_none());

        // Non-Extract: both None.
        let parse = ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned()));
        assert!(parse.failing_source.is_none());
        assert!(parse.attribution_rule.is_none());
    }

    #[test]
    fn from_error_attribution_rule_none_for_unattributed_extract() {
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_rule.is_none());
    }

    // ---- attribution_confidence accessor tests ----

    #[test]
    fn attribution_confidence_exact_for_real_yaml_extract() {
        // Real YAML file extract attributes via FileBySource (Exact);
        // the typed accessor surfaces Exact without callers
        // destructuring the rule.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_conf_exact.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.attribution_confidence(),
            Some(AttributionConfidence::Exact)
        );
    }

    #[test]
    fn attribution_confidence_fallback_for_defaults_only_extract() {
        // A defaults-only extract whose Serialized provider attaches
        // Source::Code dispatches to DefaultsByCodeUniqueness
        // (Fallback). The accessor surfaces Fallback.
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
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.attribution_rule,
            Some(AttributionRule::DefaultsByCodeUniqueness)
        );
        assert_eq!(
            f.attribution_confidence(),
            Some(AttributionConfidence::Fallback)
        );
    }

    #[test]
    fn attribution_confidence_none_for_unattributed_extract() {
        // No metadata to map → no rule → no confidence. The Some-iff
        // contract holds across the rule and confidence accessors.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_confidence().is_none());
        assert!(f.attribution_rule.is_none());
    }

    #[test]
    fn attribution_confidence_some_iff_attribution_rule_some() {
        // Invariant: across every constructed ReloadFailure, the
        // confidence accessor is populated exactly when the rule slot
        // is. Pins the strict-superset contract that the accessor is a
        // pure forwarder over `rule.map(AttributionRule::confidence)`.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Extract {
                sources: vec![ConfigSource::Defaults],
                error: fake_figment_error(),
            }),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert_eq!(
                f.attribution_rule.is_some(),
                f.attribution_confidence().is_some()
            );
        }
    }

    #[test]
    fn attribution_confidence_agrees_with_rule_confidence_pointwise() {
        // For every constructible attribution scenario, the accessor
        // result equals attribution_rule.map(AttributionRule::confidence)
        // — pinning the convenience accessor as a pure projection.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            // Build a synthetic ReloadFailure carrying just the rule;
            // the accessor must derive confidence from it directly.
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert_eq!(f.attribution_confidence(), Some(rule.confidence()));
        }
    }

    // ---- layer_kind accessor tests ----

    #[test]
    fn layer_kind_file_for_real_yaml_extract() {
        // Real YAML file extract attributes via FileBySource → File;
        // the typed accessor surfaces File without callers
        // destructuring the rule or the source.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_kind_file.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.layer_kind(), Some(ConfigSourceKind::File));
    }

    #[test]
    fn layer_kind_defaults_for_defaults_only_extract() {
        // A defaults-only extract whose Serialized provider attaches
        // Source::Code dispatches to DefaultsByCodeUniqueness → Defaults.
        // The accessor surfaces Defaults.
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
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.attribution_rule,
            Some(AttributionRule::DefaultsByCodeUniqueness)
        );
        assert_eq!(f.layer_kind(), Some(ConfigSourceKind::Defaults));
    }

    #[test]
    fn layer_kind_none_for_unattributed_extract() {
        // No metadata to map → no rule → no layer_kind.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.layer_kind().is_none());
        assert!(f.attribution_rule.is_none());
    }

    #[test]
    fn layer_kind_none_for_non_extract_variants() {
        // Non-figment-bearing variants never carry attribution.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert!(f.layer_kind().is_none());
        }
    }

    #[test]
    fn layer_kind_some_iff_attribution_rule_some() {
        // Invariant: across every constructed ReloadFailure, the
        // layer_kind accessor is populated exactly when the rule slot
        // is. Pins the strict-superset contract that the accessor is
        // a pure forwarder over `rule.map(AttributionRule::layer_kind)`.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Extract {
                sources: vec![ConfigSource::Defaults],
                error: fake_figment_error(),
            }),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert_eq!(f.attribution_rule.is_some(), f.layer_kind().is_some());
        }
    }

    #[test]
    fn layer_kind_agrees_with_rule_layer_kind_pointwise() {
        // For every constructible attribution scenario, the accessor
        // result equals attribution_rule.map(AttributionRule::layer_kind)
        // — pinning the convenience accessor as a pure projection.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            // Build a synthetic ReloadFailure carrying just the rule;
            // the accessor must derive layer_kind from it directly.
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert_eq!(f.layer_kind(), Some(rule.layer_kind()));
        }
    }

    #[test]
    fn layer_kind_agrees_with_failing_source_kind_when_attributed() {
        // Cross-primitive invariant propagates from FailingSourceAttribution
        // through ReloadFailure: for every attributed reload failure,
        // f.layer_kind() == f.failing_source.as_ref().map(ConfigSource::kind).
        // The two formulations must agree byte-for-byte across every
        // resolver path the rest of this crate exercises.
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
        let file = dir.path().join("rf_kind_inv.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let f_file = ReloadFailure::from_error(
            &ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err(),
        );
        assert_eq!(
            f_file.layer_kind(),
            f_file.failing_source.as_ref().map(ConfigSource::kind),
        );
        assert_eq!(f_file.layer_kind(), Some(ConfigSourceKind::File));

        // DefaultsByCodeUniqueness: Serialized provider attaches Source::Code.
        let f_def = ReloadFailure::from_error(
            &ProviderChain::new()
                .with_defaults(&Bad {
                    count: "not_a_number".into(),
                })
                .extract::<Cfg>()
                .unwrap_err(),
        );
        assert_eq!(
            f_def.layer_kind(),
            f_def.failing_source.as_ref().map(ConfigSource::kind),
        );
        assert_eq!(f_def.layer_kind(), Some(ConfigSourceKind::Defaults));
    }

    #[test]
    fn layer_kind_orthogonal_to_attribution_confidence() {
        // The layer_kind / attribution_confidence pair are orthogonal
        // projections over the rule space along the
        // (file × env × defaults) and (exact × fallback) axes
        // respectively. Pin the orthogonality by exhibiting at least
        // three distinct (kind, confidence) pairs across constructible
        // ReloadFailure scenarios.
        use std::collections::HashSet;
        let mut pairs: HashSet<(ConfigSourceKind, AttributionConfidence)> = HashSet::new();
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let kind = f.layer_kind().expect("attributed → kind some");
            let conf = f.attribution_confidence().expect("attributed → conf some");
            pairs.insert((kind, conf));
        }
        assert!(
            pairs.len() >= 3,
            "kind × confidence must span ≥3 cells; got: {pairs:?}"
        );
    }

    // ---- ShikumiErrorKind (`kind` field & accessor) tests ----

    fn one_per_kind() -> [(ShikumiError, ShikumiErrorKind); 6] {
        // Mirrors the `one_per_kind()` table in `error::tests`: one
        // constructed `ShikumiError` per expected `ShikumiErrorKind`.
        // The reload-side test surface uses it to drive the
        // `ReloadFailure::kind` capture across every variant.
        [
            (
                ShikumiError::NotFound {
                    tried: vec![PathBuf::from("/nf")],
                },
                ShikumiErrorKind::NotFound,
            ),
            (ShikumiError::Parse("p".to_owned()), ShikumiErrorKind::Parse),
            (
                ShikumiError::Watch(notify::Error::generic("w")),
                ShikumiErrorKind::Watch,
            ),
            (
                ShikumiError::Io(std::io::Error::other("io")),
                ShikumiErrorKind::Io,
            ),
            (
                ShikumiError::Figment(fake_figment_error()),
                ShikumiErrorKind::Figment,
            ),
            (
                ShikumiError::Extract {
                    sources: vec![],
                    error: fake_figment_error(),
                },
                ShikumiErrorKind::Extract,
            ),
        ]
    }

    #[test]
    fn from_error_captures_kind_for_each_shikumi_error_variant() {
        // Total over the kind partition: every captured ReloadFailure
        // mirrors the underlying ShikumiError's kind, on both the field
        // and the accessor. Pins the typescape contract that
        // ReloadFailure::kind is a pure projection of
        // ShikumiError::kind through ReloadFailure::from_error.
        for (err, expected) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.kind, expected,
                "field must capture underlying kind for `{err:?}`"
            );
            assert_eq!(
                f.kind(),
                expected,
                "accessor must mirror field for `{err:?}`"
            );
        }
    }

    #[test]
    fn kind_accessor_agrees_with_field_pointwise() {
        // The accessor and the public field must agree on every captured
        // ReloadFailure — one is a pure forwarder of the other.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(f.kind(), f.kind);
        }
    }

    #[test]
    fn kind_agrees_with_underlying_error_kind_pointwise() {
        // f.kind() == err.kind() across every variant. The reload-side
        // capture is a strict projection of the error-side kind.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(f.kind(), err.kind(), "kind capture must mirror error");
        }
    }

    #[test]
    fn kind_is_total_no_option_at_capture_site() {
        // Distinct from the attribution_* accessors (which return
        // Option<_>), kind is total: every captured ReloadFailure has
        // exactly one kind, regardless of attribution. Pin the totality
        // by exercising every variant — including non-Extract ones,
        // where attribution_rule / failing_source / layer_kind /
        // attribution_confidence all return None — and asserting
        // `f.kind()` is well-defined regardless.
        for (err, expected) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            // Sanity: non-Extract variants have no attribution.
            if expected != ShikumiErrorKind::Extract {
                assert!(f.attribution_rule.is_none());
                assert!(f.failing_source.is_none());
                assert!(f.layer_kind().is_none());
                assert!(f.attribution_confidence().is_none());
            }
            // Yet kind() always answers.
            assert_eq!(f.kind(), expected);
        }
    }

    #[test]
    fn kind_partitions_every_captured_reload_failure() {
        // The kind axis partitions the captured-failure surface into
        // six disjoint cells. Pin disjointness: across the table, each
        // kind appears exactly once, and six distinct kinds populate
        // six distinct hash buckets.
        use std::collections::HashSet;
        let mut seen: HashSet<ShikumiErrorKind> = HashSet::new();
        for (err, expected) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert!(seen.insert(f.kind()), "kind `{expected:?}` not unique");
        }
        assert_eq!(seen.len(), 6, "kind partition must cover six cells");
    }

    #[test]
    fn kind_extract_propagates_through_real_provider_chain() {
        // End-to-end through a real ProviderChain extract failure: the
        // captured kind is Extract, regardless of whether attribution
        // resolves. Pins the contract that the capture path
        // (ProviderChain::extract → ShikumiError::Extract →
        // ReloadFailure::from_error → ReloadFailure::kind) preserves
        // the kind axis.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_kind_extract.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.kind(), ShikumiErrorKind::Extract);
        // And attribution still resolves alongside.
        assert!(f.attribution_rule.is_some());
    }

    #[test]
    fn kind_orthogonal_to_attribution_rule() {
        // The kind axis spans more cells than the attribution axis:
        // five of the six kinds carry no attribution_rule. Pin
        // orthogonality by exhibiting (kind, attribution_rule.is_some())
        // pairs that span ≥2 cells.
        use std::collections::HashSet;
        let mut pairs: HashSet<(ShikumiErrorKind, bool)> = HashSet::new();
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            pairs.insert((f.kind(), f.attribution_rule.is_some()));
        }
        // Across the table: at least the (Extract, false) cell (no
        // attribution captured because the fake figment error has no
        // metadata.source) and one (X, false) cell for non-Extract
        // variants must appear, demonstrating the kind axis is
        // not a redundant projection of the attribution axis.
        assert!(
            pairs.len() >= 2,
            "kind × attribution-presence must span ≥2 cells; got: {pairs:?}"
        );
    }

    #[test]
    fn kind_survives_clone_independent_of_originating_error() {
        // The captured kind is owned (Copy) — it must survive cloning
        // and outlive the originating ShikumiError, parallel to the
        // already-pinned `failing_source_owns_clone` invariant.
        let f = {
            let err = ShikumiError::Parse("ephemeral".to_owned());
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(g.kind(), ShikumiErrorKind::Parse);
        assert_eq!(g.kind(), f.kind());
    }

    // ---- FieldPathLocalization tests ----

    #[test]
    fn field_path_localization_localized_for_real_yaml_extract() {
        // Real YAML file extract failure with figment-localized field:
        // Localized.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_loc.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.field_path_localization(),
            FieldPathLocalization::Localized
        );
        // And the field_path slot carries the localized segments.
        assert!(!f.field_path.is_empty());
    }

    #[test]
    fn field_path_localization_unlocalized_for_extract_without_field() {
        // Bare Figment::new() extraction failure wrapped in Extract:
        // figment attached no path. FigmentUnlocalized.
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.field_path_localization(),
            FieldPathLocalization::FigmentUnlocalized
        );
        assert!(f.field_path.is_empty());
    }

    #[test]
    fn field_path_localization_unlocalized_for_figment_without_field() {
        // Bare Figment variant: figment-bearing, no localized field.
        let err = ShikumiError::Figment(fake_figment_error());
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.field_path_localization(),
            FieldPathLocalization::FigmentUnlocalized
        );
    }

    #[test]
    fn field_path_localization_not_applicable_for_non_figment_variants() {
        // Parse / NotFound / Watch / Io: NotApplicable. The captured
        // empty Vec<String> on field_path must not be confused with
        // "figment couldn't localize"; the typed accessor restores
        // the distinction.
        for err in [
            ShikumiError::Parse("x".to_owned()),
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")],
            },
            ShikumiError::Watch(notify::Error::generic("w")),
            ShikumiError::Io(std::io::Error::other("io")),
        ] {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.field_path_localization(),
                FieldPathLocalization::NotApplicable,
                "non-figment variant must capture as NotApplicable: {err:?}"
            );
            // Sanity: the Vec is empty for these too.
            assert!(f.field_path.is_empty());
        }
    }

    #[test]
    fn field_path_localization_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract: the captured envelope's projection
        // mirrors the source error's projection byte-for-byte, across
        // every variant. The tri-state distinction lost in the Vec<String>
        // representation is recovered by the typed accessor on both
        // sides — they must agree.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.field_path_localization(),
                err.field_path_localization(),
                "captured localization must mirror source localization for {err:?}"
            );
        }
    }

    #[test]
    fn field_path_localization_partitions_every_captured_failure() {
        // The localization axis partitions the captured-failure surface
        // into exactly the three FieldPathLocalization cells. Across
        // the standard one_per_kind() table, every captured failure
        // must classify into exactly one cell, and the table must
        // populate at least two distinct cells (the table doesn't
        // include a Localized example, but does cover NotApplicable
        // and FigmentUnlocalized).
        use std::collections::HashSet;
        let mut seen: HashSet<FieldPathLocalization> = HashSet::new();
        for (err, _) in one_per_kind() {
            seen.insert(ReloadFailure::from_error(&err).field_path_localization());
        }
        assert!(
            seen.len() >= 2,
            "one_per_kind table must span ≥2 localization cells; got: {seen:?}"
        );
        // Specifically: NotApplicable for the four non-figment kinds,
        // FigmentUnlocalized for Extract / Figment (the table builds
        // them without a path).
        assert!(seen.contains(&FieldPathLocalization::NotApplicable));
        assert!(seen.contains(&FieldPathLocalization::FigmentUnlocalized));
    }

    #[test]
    fn field_path_localization_localized_iff_field_path_non_empty() {
        // Cross-axis invariant on the captured envelope: Localized
        // exactly when field_path is non-empty. Pins the contract that
        // the typed projection and the raw Vec<String> agree on the
        // localized boundary.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.field_path_localization() == FieldPathLocalization::Localized,
                !f.field_path.is_empty(),
                "Localized iff field_path non-empty for {err:?}"
            );
        }
        // And for a constructed Localized capture (real YAML extract):
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_loc_iff.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.field_path_localization() == FieldPathLocalization::Localized,
            !f.field_path.is_empty(),
        );
        assert!(!f.field_path.is_empty());
    }

    #[test]
    fn field_path_localization_total_across_kind_axis() {
        // Distinct from the attribution_* accessors (which return
        // Option<_>), field_path_localization is total: every captured
        // ReloadFailure has exactly one localization classification,
        // regardless of attribution. Mirror of the kind-axis totality
        // pinned by `kind_is_total_no_option_at_capture_site`.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            // Always answers; the assignment is exhaustive.
            let _ = f.field_path_localization();
        }
    }

    #[test]
    fn field_path_localization_survives_clone_independent_of_originating_error() {
        // The captured localization is derived from owned slots
        // (kind: Copy + field_path: Vec<String> Clone) — it must survive
        // cloning and outlive the originating ShikumiError, parallel to
        // the already-pinned kind-clone and failing-source-owns-clone
        // invariants.
        let f = {
            let err = ShikumiError::Parse("ephemeral".to_owned());
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(
            g.field_path_localization(),
            FieldPathLocalization::NotApplicable
        );
        assert_eq!(g.field_path_localization(), f.field_path_localization());
    }

    #[test]
    fn field_path_localization_orthogonal_to_kind_axis() {
        // Across the constructible captured-failure surface, the
        // (kind × localization) projection must span more than two
        // cells: the partition is finer than either axis alone. The
        // one_per_kind() table covers six (kind, localization) pairs,
        // mostly (Non-figment kind, NotApplicable) and the two
        // figment-bearing kinds with FigmentUnlocalized; adding a
        // Localized capture forces a third cell along the localization
        // axis.
        use crate::provider::ProviderChain;
        use std::collections::HashSet;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let mut pairs: HashSet<(ShikumiErrorKind, FieldPathLocalization)> = HashSet::new();
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            pairs.insert((f.kind(), f.field_path_localization()));
        }
        // Add a Localized capture to expand the cell count.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_orth.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        pairs.insert((f.kind(), f.field_path_localization()));
        // Now: at least the four (non-figment kind, NotApplicable)
        // cells, the (Extract, FigmentUnlocalized), (Figment,
        // FigmentUnlocalized), and (Extract, Localized) cells —
        // ≥ 7 distinct cells across two axes that span 6 × 3 = 18.
        assert!(
            pairs.len() >= 5,
            "kind × localization must span ≥5 cells; got: {pairs:?}"
        );
    }

    // ---- AttributionAxis (`metadata_axis` accessor) tests ----

    #[test]
    fn metadata_axis_metadata_source_for_real_yaml_extract() {
        // Real YAML file extract attributes via FileBySource — the
        // resolver dispatched off `metadata.source` (figment's typed
        // Source::File classification). The accessor surfaces
        // MetadataSource without callers destructuring the rule.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_axis_src.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.metadata_axis(), Some(AttributionAxis::MetadataSource));
        assert_eq!(f.attribution_rule, Some(AttributionRule::FileBySource));
    }

    #[test]
    fn metadata_axis_metadata_source_for_defaults_only_extract() {
        // Defaults-only Serialized extract dispatches via
        // DefaultsByCodeUniqueness — the resolver inspected
        // `metadata.source` (figment's typed Source::Code). The
        // accessor surfaces MetadataSource even though the
        // confidence is Fallback — pins independence of the axis and
        // confidence partitions on the captured envelope.
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
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.attribution_rule,
            Some(AttributionRule::DefaultsByCodeUniqueness)
        );
        assert_eq!(f.metadata_axis(), Some(AttributionAxis::MetadataSource));
        assert_eq!(
            f.attribution_confidence(),
            Some(AttributionConfidence::Fallback)
        );
    }

    #[test]
    fn metadata_axis_none_for_unattributed_extract() {
        // No metadata to map → no rule → no metadata_axis. Pins the
        // Some-iff-attribution-rule contract on the third axis.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.metadata_axis().is_none());
        assert!(f.attribution_rule.is_none());
    }

    #[test]
    fn metadata_axis_none_for_non_extract_variants() {
        // Non-figment-bearing variants and the bare Figment variant
        // never carry attribution; the accessor must report None
        // across them all.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
            ReloadFailure::from_error(&ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")],
            }),
            ReloadFailure::from_error(&ShikumiError::Watch(notify::Error::generic("w"))),
            ReloadFailure::from_error(&ShikumiError::Io(std::io::Error::other("io"))),
        ] {
            assert!(f.metadata_axis().is_none());
        }
    }

    #[test]
    fn metadata_axis_some_iff_attribution_rule_some() {
        // Invariant: across every constructed ReloadFailure, the
        // metadata_axis accessor is populated exactly when the rule
        // slot is. Pins the strict-superset contract that the
        // accessor is a pure forwarder over
        // `rule.map(AttributionRule::metadata_axis)`.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Extract {
                sources: vec![ConfigSource::Defaults],
                error: fake_figment_error(),
            }),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert_eq!(f.attribution_rule.is_some(), f.metadata_axis().is_some());
        }
    }

    #[test]
    fn metadata_axis_agrees_with_rule_metadata_axis_pointwise() {
        // For every constructible attribution scenario, the accessor
        // result equals attribution_rule.map(AttributionRule::metadata_axis)
        // — pinning the convenience accessor as a pure projection of
        // the captured rule.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            // Build a synthetic ReloadFailure carrying just the rule;
            // the accessor must derive metadata_axis from it directly.
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert_eq!(f.metadata_axis(), Some(rule.metadata_axis()));
        }
    }

    #[test]
    fn metadata_axis_orthogonal_to_attribution_confidence() {
        // The metadata_axis × attribution_confidence pair are
        // orthogonal projections over the rule space along the
        // (source × name) and (exact × fallback) axes respectively.
        // Pin orthogonality by exhibiting all four (axis, confidence)
        // cells across constructible ReloadFailure scenarios.
        use std::collections::HashSet;
        let mut pairs: HashSet<(AttributionAxis, AttributionConfidence)> = HashSet::new();
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let axis = f.metadata_axis().expect("attributed → axis some");
            let conf = f.attribution_confidence().expect("attributed → conf some");
            pairs.insert((axis, conf));
        }
        assert_eq!(
            pairs.len(),
            4,
            "axis × confidence must span all four cells; got: {pairs:?}"
        );
    }

    #[test]
    fn metadata_axis_orthogonal_to_layer_kind() {
        // The metadata_axis × layer_kind pair must span ≥3 cells —
        // pinning that the axis partition is finer than (or
        // orthogonal to) the layer-kind partition on the captured
        // envelope.
        use std::collections::HashSet;
        let mut pairs: HashSet<(AttributionAxis, ConfigSourceKind)> = HashSet::new();
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let axis = f.metadata_axis().expect("attributed → axis some");
            let kind = f.layer_kind().expect("attributed → kind some");
            pairs.insert((axis, kind));
        }
        assert!(
            pairs.len() >= 3,
            "axis × layer_kind must span ≥3 cells; got: {pairs:?}"
        );
    }

    // ---- figment_source_kind accessor tests ----

    #[test]
    fn figment_source_kind_some_for_real_yaml_extract() {
        // A real YAML-file extract failure attributes via FileBySource,
        // whose identity already pins FigmentSourceKind::File.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_fsk.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.attribution_rule, Some(AttributionRule::FileBySource));
        assert_eq!(f.figment_source_kind(), Some(FigmentSourceKind::File));
    }

    #[test]
    fn figment_source_kind_some_for_defaults_only_extract() {
        // A defaults-only extract attributes via DefaultsByCodeUniqueness,
        // whose identity already pins FigmentSourceKind::Code.
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
        let f = ReloadFailure::from_error(&err);
        assert_eq!(
            f.attribution_rule,
            Some(AttributionRule::DefaultsByCodeUniqueness),
        );
        assert_eq!(f.figment_source_kind(), Some(FigmentSourceKind::Code));
    }

    #[test]
    fn figment_source_kind_none_for_unattributed_extract() {
        // No metadata to map → no rule → no figment_source_kind.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_rule.is_none());
        assert!(f.figment_source_kind().is_none());
    }

    #[test]
    fn figment_source_kind_none_for_non_extract_variants() {
        // Non-figment-bearing variants and bare Figment never carry
        // attribution → never carry a figment_source_kind.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert!(f.figment_source_kind().is_none());
        }
    }

    #[test]
    fn figment_source_kind_none_for_name_axis_attribution() {
        // Name-axis attributions (FileByMetadataName, EnvByPrefix,
        // EnvByUniqueness) carry an attribution_rule but their
        // identity does not pin a figment-Source-axis cell — the
        // accessor returns None even when the rule slot is Some.
        // Pins the two-stage None discipline documented on the
        // accessor.
        for rule in [
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert!(f.attribution_rule.is_some(), "rule {rule:?}");
            assert!(
                f.figment_source_kind().is_none(),
                "rule {rule:?}: name-axis attribution must yield None figment_source_kind",
            );
        }
    }

    #[test]
    fn figment_source_kind_agrees_with_rule_figment_source_kind_pointwise() {
        // For every constructible rule scenario, the accessor result
        // equals attribution_rule.and_then(AttributionRule::figment_source_kind)
        // — pinning the convenience accessor as a pure projection.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert_eq!(f.figment_source_kind(), rule.figment_source_kind());
        }
    }

    #[test]
    fn figment_source_kind_some_iff_metadata_axis_metadata_source() {
        // Composition law on the cross-thread envelope: when an
        // attribution is recorded, figment_source_kind is Some
        // exactly when metadata_axis is Some(MetadataSource). When no
        // attribution is recorded, both are None and the
        // biconditional still holds vacuously. Pins the same
        // refinement as the AttributionRule-side law, surfaced
        // through the captured envelope.
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(|rule| ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            })
            .chain(std::iter::once(ReloadFailure::from_error(
                &ShikumiError::Parse("x".to_owned()),
            )))
            .collect();
        for f in scenarios {
            assert_eq!(
                f.figment_source_kind().is_some(),
                f.metadata_axis() == Some(AttributionAxis::MetadataSource),
                "envelope {:?}: figment_source_kind.is_some() must equal \
                 (metadata_axis == Some(MetadataSource))",
                f.attribution_rule,
            );
        }
    }

    #[test]
    fn figment_source_kind_agrees_with_layer_kind_pointwise_when_some() {
        // Structural diagonal on the cross-thread envelope: when
        // figment_source_kind is Some, the (figment-source-kind,
        // layer-kind) pair lies on the structural diagonal pinned by
        // the resolver — (File, File) for FileBySource, (Code,
        // Defaults) for DefaultsByCodeUniqueness. The two source-axis
        // rules' identities already name both halves of their joint
        // (figment-source × shikumi-layer) coordinate cell; the
        // accessor surfaces both halves coherently.
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
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            assert_eq!(f.figment_source_kind(), Some(fk), "rule {rule:?}");
            assert_eq!(f.layer_kind(), Some(ck), "rule {rule:?}");
        }
    }

    #[test]
    fn figment_source_kind_survives_clone_independent_of_originating_error() {
        // The captured figment_source_kind is derived from the
        // captured rule (Copy) — it must survive cloning and outlive
        // the originating ShikumiError, parallel to the
        // metadata-axis-clone and layer-kind-clone invariants
        // already pinned on the cross-thread envelope.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let f = {
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("rf_fsk_clone.yaml");
            std::fs::write(&file, "count: not_a_number\n").unwrap();
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(g.figment_source_kind(), Some(FigmentSourceKind::File));
        assert_eq!(g.figment_source_kind(), f.figment_source_kind());
    }

    #[test]
    fn metadata_axis_survives_clone_independent_of_originating_error() {
        // The captured axis is derived from the captured rule (Copy)
        // — it must survive cloning and outlive the originating
        // ShikumiError, parallel to the kind-clone and
        // failing-source-owns-clone invariants already pinned.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let f = {
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("rf_axis_clone.yaml");
            std::fs::write(&file, "count: not_a_number\n").unwrap();
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(g.metadata_axis(), Some(AttributionAxis::MetadataSource));
        assert_eq!(g.metadata_axis(), f.metadata_axis());
    }

    // ---- coordinates accessor tests ----

    #[test]
    fn coordinates_for_real_yaml_extract_carries_full_triple() {
        // End-to-end: a real YAML-file extract failure surfaces the
        // (MetadataSource, File, Exact) triple in one accessor read.
        // The captured envelope's coordinates() agrees with the three
        // sibling Option-returning projection accessors.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_coords.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        let coords = f.coordinates().expect("attributed → coordinates some");
        assert_eq!(coords.axis, AttributionAxis::MetadataSource);
        assert_eq!(coords.layer_kind, ConfigSourceKind::File);
        assert_eq!(coords.confidence, AttributionConfidence::Exact);
    }

    #[test]
    fn coordinates_some_iff_attribution_rule_some() {
        // Some-iff-attribution invariant: the coordinates accessor is
        // populated exactly when the rule slot is, peer to
        // attribution_confidence / layer_kind / metadata_axis.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Extract {
                sources: vec![ConfigSource::Defaults],
                error: fake_figment_error(),
            }),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert_eq!(f.attribution_rule.is_some(), f.coordinates().is_some());
        }
    }

    #[test]
    fn coordinates_agrees_with_three_projection_accessors_pointwise() {
        // For every recognized rule, the named-struct lift on the
        // ReloadFailure side surfaces the same per-axis values as the
        // three sibling Option-returning forwarders. Pins the
        // contract that the accessor is a pure projection of
        // attribution_rule.map(AttributionRule::coordinates), not a
        // re-derived computation.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let coords = f.coordinates().expect("attributed → coords some");
            assert_eq!(Some(coords.axis), f.metadata_axis());
            assert_eq!(Some(coords.layer_kind), f.layer_kind());
            assert_eq!(Some(coords.confidence), f.attribution_confidence());
        }
    }

    #[test]
    fn coordinates_round_trips_through_from_coordinates() {
        // The bijection statement on the captured envelope: a captured
        // ReloadFailure's coordinates round-trip back to the originating
        // rule via AttributionRule::from_coordinates. Pins the
        // operational use case — re-hydrating a rule from a captured
        // structured-log payload of three closed-enum coordinates.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let coords = f.coordinates().expect("coords some");
            assert_eq!(
                AttributionRule::from_coordinates(coords),
                Some(rule),
                "captured coords for {rule:?} must round-trip"
            );
        }
    }

    #[test]
    fn coordinates_survives_clone_independent_of_originating_error() {
        // The captured triple is derived from the captured rule (Copy)
        // — it must survive cloning and outlive the originating
        // ShikumiError, parallel to the metadata_axis / layer_kind /
        // attribution_confidence clone-survival invariants.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let f = {
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("rf_coords_clone.yaml");
            std::fs::write(&file, "count: not_a_number\n").unwrap();
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        let expected = AttributionCoordinates {
            axis: AttributionAxis::MetadataSource,
            layer_kind: ConfigSourceKind::File,
            confidence: AttributionConfidence::Exact,
        };
        assert_eq!(g.coordinates(), Some(expected));
        assert_eq!(g.coordinates(), f.coordinates());
    }

    #[test]
    fn coordinates_distinguishes_every_rule_on_synthetic_failures() {
        // Joint injectivity on the captured envelope: distinct rules
        // captured into ReloadFailure produce distinct coordinate
        // triples. Pins the structural-completeness statement on the
        // cross-thread observable surface, peer to the underlying
        // AttributionRule joint-injectivity contract.
        use std::collections::HashSet;
        let mut coords_set: HashSet<AttributionCoordinates> = HashSet::new();
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            coords_set.insert(f.coordinates().expect("coords some"));
        }
        assert_eq!(
            coords_set.len(),
            5,
            "every captured rule must occupy a distinct coordinate cell; got: {coords_set:?}"
        );
    }

    // ---- failing_attribution accessor tests ----

    #[test]
    fn failing_attribution_for_real_yaml_extract_borrows_source_and_rule() {
        // End-to-end: a real YAML-file extract failure surfaces both
        // halves of the attribution as one borrowed envelope read,
        // peer to ShikumiError::failing_attribution on the live-error
        // side. The envelope's source borrows into the captured
        // failing_source slot; the rule is the captured rule.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr_envelope.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();

        let f = ReloadFailure::from_error(&err);
        let envelope = f.failing_attribution().expect("attributed → envelope some");
        assert_eq!(envelope.rule, AttributionRule::FileBySource);
        assert_eq!(envelope.source.as_path(), Some(file.as_path()));
    }

    #[test]
    fn failing_attribution_some_iff_both_halves_populated() {
        // The Some-iff-attribution invariant is structural on the
        // accessor: the diagonal (both Some / both None) of the
        // (failing_source × attribution_rule) 2×2 cube produces
        // Some(envelope) / None respectively, and the two off-diagonal
        // cells (only one half populated) collapse back to None.
        // Pins that the envelope projection is the legal subset of the
        // 4-cell product cube, peer to the way coordinates() and the
        // three sibling Option-returning forwarders enforce
        // Some-iff-rule.

        // Both Some: envelope Some.
        let both = ReloadFailure {
            message: "synth".to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![],
            field_path: vec![],
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };
        assert!(both.failing_attribution().is_some());

        // Both None: envelope None.
        let neither = ReloadFailure {
            message: "synth".to_owned(),
            kind: ShikumiErrorKind::Parse,
            sources: vec![],
            field_path: vec![],
            failing_source: None,
            attribution_rule: None,
        };
        assert!(neither.failing_attribution().is_none());

        // Off-diagonal (only source): envelope None — the legal-subset
        // collapse pins the structural invariant even if a future
        // construction site lands inconsistent halves.
        let only_source = ReloadFailure {
            message: "synth".to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![],
            field_path: vec![],
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: None,
        };
        assert!(only_source.failing_attribution().is_none());

        // Off-diagonal (only rule): envelope None.
        let only_rule = ReloadFailure {
            message: "synth".to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![],
            field_path: vec![],
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileBySource),
        };
        assert!(only_rule.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_none_for_unattributed_extract() {
        // No metadata to map → no attribution captured → envelope None.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_none_for_non_extract_variants() {
        // Non-figment-bearing variants and the bare Figment variant
        // never carry attribution; the envelope accessor must report
        // None across them all, peer to the four sibling
        // Option-returning projection accessors.
        for f in [
            ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned())),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
            ReloadFailure::from_error(&ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")],
            }),
            ReloadFailure::from_error(&ShikumiError::Watch(notify::Error::generic("w"))),
            ReloadFailure::from_error(&ShikumiError::Io(std::io::Error::other("io"))),
        ] {
            assert!(f.failing_attribution().is_none());
        }
    }

    #[test]
    fn failing_attribution_envelope_carries_same_halves_as_fields() {
        // For every captured-from real attributed extract, the envelope's
        // (source, rule) pair must equal the parallel (failing_source,
        // attribution_rule) field pair byte-for-byte. Pins the accessor
        // as a pure projection of the two slots, not a re-derived
        // computation.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr_parity.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        let envelope = f.failing_attribution().expect("attributed → envelope some");
        assert_eq!(Some(envelope.rule), f.attribution_rule);
        assert_eq!(Some(envelope.source), f.failing_source.as_ref());
    }

    #[test]
    fn failing_attribution_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the attribution envelope: the
        // captured ReloadFailure's failing_attribution() agrees with
        // the originating ShikumiError's failing_attribution() across
        // every variant, modulo the lifetime difference (the live
        // form borrows into the chain, the captured form borrows into
        // the cloned slots). The (source, rule) pair must match
        // byte-for-byte on every recognized rule.
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

        // FileBySource path.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr_pointwise.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        let live = err_file.failing_attribution().expect("live envelope some");
        let captured = f_file
            .failing_attribution()
            .expect("captured envelope some");
        assert_eq!(live.rule, captured.rule);
        assert_eq!(live.source, captured.source);

        // DefaultsByCodeUniqueness path.
        let err_def = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let f_def = ReloadFailure::from_error(&err_def);
        let live = err_def.failing_attribution().expect("live envelope some");
        let captured = f_def.failing_attribution().expect("captured envelope some");
        assert_eq!(live.rule, captured.rule);
        assert_eq!(live.source, captured.source);

        // Unattributed Extract: both surfaces must agree on None.
        let err_unattr = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f_unattr = ReloadFailure::from_error(&err_unattr);
        assert!(err_unattr.failing_attribution().is_none());
        assert!(f_unattr.failing_attribution().is_none());

        // Non-Extract variants: both surfaces must agree on None.
        for err in [
            ShikumiError::Parse("x".to_owned()),
            ShikumiError::Figment(fake_figment_error()),
        ] {
            let f = ReloadFailure::from_error(&err);
            assert!(err.failing_attribution().is_none());
            assert!(f.failing_attribution().is_none());
        }
    }

    #[test]
    fn failing_attribution_envelope_coordinates_match_separate_accessor() {
        // The envelope's coordinates() must equal the captured
        // failure's coordinates() on every attributed scenario —
        // pinning that routing through the envelope vs. the bare
        // accessor gives the same triple. Composition contract for
        // the (envelope, coordinates) pair on the captured surface,
        // peer to the (envelope, coordinates) pair on the live-error
        // surface.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = ReloadFailure {
                message: "synth".to_owned(),
                kind: ShikumiErrorKind::Extract,
                sources: vec![],
                field_path: vec![],
                failing_source: Some(ConfigSource::Defaults),
                attribution_rule: Some(rule),
            };
            let envelope = f.failing_attribution().expect("attributed → envelope some");
            assert_eq!(Some(envelope.coordinates()), f.coordinates());
            assert_eq!(envelope.confidence(), rule.confidence());
            assert_eq!(envelope.layer_kind(), rule.layer_kind());
            assert_eq!(envelope.metadata_axis(), rule.metadata_axis());
        }
    }

    #[test]
    fn failing_attribution_envelope_outlives_originating_error() {
        // Capture from a borrowed error, drop the error, then borrow
        // the envelope from the surviving ReloadFailure. The envelope
        // borrows into the captured failure's owned ConfigSource clone,
        // so it must remain valid after the originating ShikumiError
        // is dropped — parallel to the failing_source-owns-clone
        // invariant already pinned.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr_outlives.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let f = {
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let envelope = f.failing_attribution().expect("envelope some after drop");
        assert_eq!(envelope.rule, AttributionRule::FileBySource);
        assert_eq!(envelope.source.as_path(), Some(file.as_path()));
    }

    #[test]
    fn failing_attribution_some_iff_other_attribution_accessors_some() {
        // Cross-accessor invariant on the captured envelope: the new
        // failing_attribution() accessor and the four pre-existing
        // Some-iff-attribution accessors (attribution_confidence /
        // layer_kind / metadata_axis / coordinates) populate exactly
        // together. Pins that the envelope accessor lives on the same
        // diagonal of the attribution-presence cube as its peers, not
        // a refinement or a relaxation.
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

        // Attributed (FileBySource).
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_attr_diag_file.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let f_file = ReloadFailure::from_error(
            &ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err(),
        );

        // Attributed (DefaultsByCodeUniqueness).
        let f_def = ReloadFailure::from_error(
            &ProviderChain::new()
                .with_defaults(&Bad {
                    count: "not_a_number".into(),
                })
                .extract::<Cfg>()
                .unwrap_err(),
        );

        // Unattributed Extract.
        let f_unattr = ReloadFailure::from_error(&ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        });

        // Non-Extract.
        let f_parse = ReloadFailure::from_error(&ShikumiError::Parse("x".to_owned()));

        for f in [&f_file, &f_def, &f_unattr, &f_parse] {
            let env_some = f.failing_attribution().is_some();
            assert_eq!(env_some, f.attribution_confidence().is_some());
            assert_eq!(env_some, f.layer_kind().is_some());
            assert_eq!(env_some, f.metadata_axis().is_some());
            assert_eq!(env_some, f.coordinates().is_some());
            assert_eq!(env_some, f.attribution_rule.is_some());
            assert_eq!(env_some, f.failing_source.is_some());
        }
    }

    // ---- error_localization_coordinates tests ----

    #[test]
    fn error_localization_coordinates_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the (kind × localization)
        // coordinate plane on the cross-thread observable form: the
        // captured envelope's coordinate cell mirrors the source
        // error's cell byte-for-byte across every variant. Together
        // with `kind_agrees_with_underlying_error_pointwise` and
        // `field_path_localization_agrees_with_underlying_error_pointwise`,
        // this pins agreement on each named slot AND on the
        // collapsed pair, so a future variant landing must keep all
        // three projections in lockstep.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.error_localization_coordinates(),
                err.error_localization_coordinates(),
                "captured coordinates must mirror source coordinates for {err:?}"
            );
        }
    }

    #[test]
    fn error_localization_coordinates_returns_realizable_cell() {
        // Every captured failure maps to a realizable cell in the
        // 18-cell product cube. Pins the forward-total /
        // image-realizable contract on the cross-thread observable
        // form: the accessor never produces an unrealizable cell, no
        // matter which underlying variant was captured.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            let cell = f.error_localization_coordinates();
            assert!(
                cell.is_realizable(),
                "captured cell must be realizable (got {cell:?} from {err:?})",
            );
        }
    }

    #[test]
    fn error_localization_coordinates_mirrors_sibling_accessors_on_capture() {
        // The captured coordinate accessor is a thin lift over the
        // two sibling accessors (kind, field_path_localization) on
        // the envelope: the produced cell's named fields must agree
        // byte-for-byte with the two separate reads on the same
        // envelope. Pins the lossless-decomposition contract on the
        // cross-thread observable form.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            let cell = f.error_localization_coordinates();
            assert_eq!(
                cell.kind,
                f.kind(),
                "captured coordinate.kind must agree with f.kind() for {err:?}",
            );
            assert_eq!(
                cell.localization,
                f.field_path_localization(),
                "captured coordinate.localization must agree with f.field_path_localization() for {err:?}",
            );
        }
    }
}

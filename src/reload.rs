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
    AttributionAxis, AttributionConfidence, AttributionCoordinates, AttributionNameKindCoordinates,
    AttributionRule, AttributionSourceKindCoordinates, ErrorLocalizationCoordinates,
    FailingSourceAttribution, FieldPathLocalization, ShikumiError, ShikumiErrorKind,
    dotted_field_path,
};
use crate::source::{ConfigSource, ConfigSourceKind, FigmentNameTagKind, FigmentSourceKind};

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
    ///
    /// `const fn` — trivial [`Copy`] field read of
    /// [`Self::kind`] (`ShikumiErrorKind` is `Copy + #[repr]`-fixed),
    /// so the projection lifts to `const` at the envelope altitude
    /// verbatim with no body change. First const-lift on
    /// `impl ReloadFailure`, mirroring altitude-for-altitude the
    /// first const-lift on `impl ShikumiError`
    /// ([`ShikumiError::kind`], const since `4b00851`): the two
    /// altitudes now share the const-callability parity on the
    /// sum-type-to-kind projection surface.
    ///
    /// Weld: [`tests::reload_failure_kind_is_const_callable`]. Every
    /// other envelope-altitude forwarder on
    /// `impl ReloadFailure` — [`Self::attribution_confidence`] /
    /// [`Self::layer_kind`] / [`Self::metadata_axis`] and the
    /// figment-metadata-axis / joint-coordinate / file-provenance
    /// siblings — currently routes through non-const
    /// [`Option::map`] / [`Option::and_then`] over the recorded
    /// [`Self::attribution_rule`] slot; each lifts in a subsequent
    /// step by rewriting the routed body as an explicit `match`
    /// (whose arms compose already-const rule-altitude projections
    /// with the const-constructible `None` arm), so the kind
    /// forwarder is the const-callability prerequisite that opens
    /// the cascade at this altitude the same way `ShikumiError::kind`
    /// opened the tag-side septet + meta-axis pair at the tag
    /// altitude.
    #[must_use]
    pub const fn kind(&self) -> ShikumiErrorKind {
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
    ///
    /// `const fn`: const-callable on `&self` receivers backed by
    /// `static` bindings (welded by
    /// [`tests::reload_failure_attribution_confidence_is_const_callable`]).
    /// The routed body destructures [`Self::attribution_rule`] as an
    /// explicit `match` — the `Option::map(AttributionRule::confidence)`
    /// spelling routes through the non-const `Option::map` step —
    /// and both arms compose const-callable primitives: `None => None`
    /// is const-constructible, and `Some(rule) => Some(rule.confidence())`
    /// composes the `Copy` field projection on the `Copy + #[repr]`-fixed
    /// [`AttributionRule`] variant with the underlying
    /// [`AttributionRule::confidence`] total projection (const since
    /// `df3334f`, welded at compile time by
    /// [`crate::error::tests::attribution_rule_confidence_and_confidence_predicates_are_const_callable`]).
    /// Second const-lift on `impl ReloadFailure` after
    /// [`Self::kind`] (`9bc4eb7`, welded by
    /// [`tests::reload_failure_kind_is_const_callable`]): opens the
    /// envelope-altitude cascade over the Some-iff-attribution
    /// forwarders — [`Self::layer_kind`] / [`Self::metadata_axis`] and
    /// the figment-metadata-axis / joint-coordinate / file-provenance
    /// siblings each lift by the same `match`-arm rewrite in a
    /// subsequent step, so this lift is the prerequisite that opens
    /// the Some-iff-attribution altitude the same way
    /// [`FailingSourceAttribution::confidence`] (const since
    /// `df3334f`) opened the corresponding envelope altitude on the
    /// `FailingSourceAttribution` side. A downstream observer that
    /// carries a `ReloadFailure` reference through
    /// [`crate::ConfigStore::last_reload_error`] can now key on the
    /// exact-vs-fallback confidence axis in const context — a
    /// `const IS_EXACT: bool = matches!(REL.attribution_confidence(),
    /// Some(AttributionConfidence::Exact))` sentinel for a
    /// compile-time-known captured failure resolves at compile time
    /// without a runtime projection detour.
    #[must_use]
    pub const fn attribution_confidence(&self) -> Option<AttributionConfidence> {
        match self.attribution_rule {
            Some(rule) => Some(rule.confidence()),
            None => None,
        }
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
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable`]).
    /// The routed body rewrites the non-const
    /// `Option::<AttributionRule>::map(AttributionRule::layer_kind)`
    /// spelling — rustc rejects `Option::<T>::map` in const fn with
    /// E0658 — into an explicit `match self.attribution_rule` whose
    /// arms compose already-const primitives: the `Copy` field access
    /// on the `Copy + #[repr]`-fixed `Option<AttributionRule>` slot,
    /// the `Copy` variant read on the `AttributionRule` payload, and
    /// the underlying [`AttributionRule::layer_kind`] total projection
    /// (const since it was introduced). Member of the const-callable
    /// Some-iff-attribution forwarder quartet
    /// ([`Self::layer_kind`], [`Self::metadata_axis`],
    /// [`Self::figment_source_kind`], [`Self::figment_name_tag_kind`])
    /// unblocked by [`Self::attribution_confidence`] (`6d160c8`) and
    /// lifted in one consolidated step; peer to
    /// [`FailingSourceAttribution::layer_kind`] (const since
    /// `fc9e0c6`) at the corresponding envelope altitude on the
    /// borrowed-envelope side of the cross-thread observable surface.
    #[must_use]
    pub const fn layer_kind(&self) -> Option<ConfigSourceKind> {
        match self.attribution_rule {
            Some(rule) => Some(rule.layer_kind()),
            None => None,
        }
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
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable`]).
    /// The routed body composes the same const-callable Copy field
    /// access + variant read + underlying
    /// [`AttributionRule::metadata_axis`] total projection (const
    /// since it was introduced) that [`Self::layer_kind`] does, so a
    /// compile-time-known envelope projects both the layer-kind and
    /// metadata-axis coordinates at compile time — a
    /// `static PAIR: (Option<ConfigSourceKind>, Option<AttributionAxis>)
    /// = (REL.layer_kind(), REL.metadata_axis())` diagnostic table
    /// resolves without either projection dropping the caller off
    /// the const-context edge. Peer to
    /// [`FailingSourceAttribution::metadata_axis`] (const since
    /// `37b71fb`) at the corresponding altitude on the
    /// borrowed-envelope side.
    #[must_use]
    pub const fn metadata_axis(&self) -> Option<AttributionAxis> {
        match self.attribution_rule {
            Some(rule) => Some(rule.metadata_axis()),
            None => None,
        }
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
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable`]).
    /// The routed body rewrites the non-const
    /// `Option::<AttributionRule>::and_then(AttributionRule::figment_source_kind)`
    /// spelling — rustc rejects `Option::<T>::and_then` in const fn
    /// with E0658 — into an explicit `match self.attribution_rule`
    /// whose arms compose already-const primitives: the `Copy` field
    /// access on the `Copy` `Option<AttributionRule>` slot, the
    /// `Copy` variant read, and the underlying
    /// [`AttributionRule::figment_source_kind`] partial projection
    /// (const since it was introduced) that already returns an
    /// `Option<FigmentSourceKind>` const value on every arm — so no
    /// extra `Some` wrap is needed on the `Some` arm. Peer to
    /// [`FailingSourceAttribution::figment_source_kind`] (const since
    /// `b11bca7`) at the corresponding altitude on the
    /// borrowed-envelope side.
    #[must_use]
    pub const fn figment_source_kind(&self) -> Option<FigmentSourceKind> {
        match self.attribution_rule {
            Some(rule) => rule.figment_source_kind(),
            None => None,
        }
    }

    /// [`FigmentNameTagKind`] structurally pinned by
    /// [`Self::attribution_rule`], or `None` when no attribution was
    /// recorded *or* when the recorded attribution is source-axis
    /// (where the rule's identity does not constrain
    /// `figment::Metadata::name`) — strict superset of
    /// [`Self::attribution_rule`]`.and_then(AttributionRule::figment_name_tag_kind)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies, attestation manifests) don't re-derive the
    /// (rule → figment-name-tag-kind) partial projection at every
    /// observation site.
    ///
    /// Symmetric peer of [`Self::figment_source_kind`] on the
    /// figment-`Metadata::name` axis — the two accessors close the
    /// cross-thread observable form's figment-metadata kind universe.
    /// Before this accessor, the name-axis-side classification could
    /// not survive the borrowed-tag → owned-envelope boundary: the
    /// underlying [`FigmentNameTag`] is lifetime-parameterized
    /// (allocation-free but unable to cross thread boundaries or
    /// persist in [`ReloadFailure`]), so observers reading
    /// [`crate::ConfigStore::last_reload_error`] could only reach the
    /// figment-name-axis kind by retaining the live [`ShikumiError`]
    /// (impossible — [`ShikumiError`] is not [`Clone`]) or by
    /// re-parsing [`Self::message`] for the originating tag shape (a
    /// drift-prone string surface). The lifted accessor surfaces the
    /// `'static` [`FigmentNameTagKind`] discriminant through the
    /// captured rule slot.
    ///
    /// Two-stage `None` discipline mirroring [`Self::figment_source_kind`]:
    /// (1) `None` when no attribution was recorded
    /// ([`Self::attribution_rule`] is [`None`]),
    /// (2) `None` when the recorded attribution is source-axis
    /// ([`Self::metadata_axis`] is
    /// [`Some(AttributionAxis::MetadataSource)`]) — neither path pins a
    /// figment-name-axis cell. Name-axis attributions
    /// ([`AttributionRule::FileByMetadataName`] →
    /// [`Some(FigmentNameTagKind::Format)`],
    /// [`AttributionRule::EnvByPrefix`] /
    /// [`AttributionRule::EnvByUniqueness`] →
    /// [`Some(FigmentNameTagKind::Env)`]) surface a [`Some`] cell directly.
    /// Operationally distinguishes "no provenance at all" from
    /// "source-axis provenance whose figment name-tag kind was not
    /// retained" — observers cannot recover figment's `Metadata::name`
    /// classification off the cross-thread envelope, but they can
    /// route on whether the attribution rule already pinned it.
    ///
    /// Composes with [`Self::metadata_axis`] as a refinement on the
    /// name-axis cells: when [`Some`], the projection is [`Some`]
    /// exactly when [`Self::metadata_axis`] returns
    /// [`Some(AttributionAxis::MetadataName)`]. Pinned by
    /// `figment_name_tag_kind_some_iff_metadata_axis_metadata_name`.
    /// Composes with [`Self::figment_source_kind`] as a strict
    /// partition over the attributed-envelope surface: every attributed
    /// failure has exactly one of the two figment-metadata kind cells
    /// surfaced as [`Some`]; unattributed failures have both as [`None`].
    /// Pinned by
    /// `figment_name_tag_kind_xor_figment_source_kind_on_attributed_envelopes`.
    ///
    /// Cross-thread mirror of
    /// [`FailingSourceAttribution::figment_name_tag_kind`] (and of
    /// [`AttributionRule::figment_name_tag_kind`] at the rule layer): the
    /// captured envelope's projection agrees pointwise with the live
    /// error's, pinning the lossless-capture contract for the
    /// figment-name-tag-kind axis on the cross-thread observable form.
    /// Pinned by
    /// `figment_name_tag_kind_agrees_with_underlying_error_pointwise`.
    ///
    /// [`FigmentNameTag`]: crate::FigmentNameTag
    /// [`ShikumiError`]: crate::ShikumiError
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable`]).
    /// The routed body composes the same const-callable Copy field
    /// access + variant read + underlying
    /// [`AttributionRule::figment_name_tag_kind`] partial projection
    /// (const since it was introduced) that [`Self::figment_source_kind`]
    /// does on the source-axis side. Together with its source-axis
    /// peer, the two accessors now close the const-altitude parity
    /// between the cross-thread envelope and the borrowed
    /// [`FailingSourceAttribution`] side ([`Self::figment_name_tag_kind`]'s
    /// peer const since `a4692bc`) on the figment-metadata kind
    /// universe: a compile-time-known envelope surfaces the entire
    /// (figment-Source-axis kind × figment-name-axis kind) partial
    /// partition at compile time. Closes the const-callable
    /// Some-iff-attribution forwarder quartet
    /// ([`Self::layer_kind`], [`Self::metadata_axis`],
    /// [`Self::figment_source_kind`], [`Self::figment_name_tag_kind`])
    /// unblocked by [`Self::attribution_confidence`] (`6d160c8`), so
    /// the four orthogonal projections over the rule space
    /// (layer-kind × metadata-axis × figment-Source-axis kind ×
    /// figment-name-axis kind) all evaluate at compile time through
    /// the envelope. The remaining envelope-altitude forwarders
    /// ([`Self::file_provenance`],
    /// [`Self::attribution_source_kind_coordinates`],
    /// [`Self::attribution_name_kind_coordinates`],
    /// [`Self::coordinates`]) closed the second — and last — quartet
    /// by the same `match`-arm rewrite in the next step, welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable`].
    /// Every envelope-altitude Some-iff-attribution forwarder on
    /// `impl ReloadFailure` now occupies the const-callability altitude
    /// its peer on the borrowed [`FailingSourceAttribution`] side does.
    #[must_use]
    pub const fn figment_name_tag_kind(&self) -> Option<FigmentNameTagKind> {
        match self.attribution_rule {
            Some(rule) => rule.figment_name_tag_kind(),
            None => None,
        }
    }

    /// [`crate::FormatProvenance`] of the file layer blamed for the
    /// failure, or `None` when no attribution was recorded *or* when
    /// the recorded attribution is not on the file axis — strict
    /// superset of
    /// [`Self::attribution_rule`]`.and_then(AttributionRule::file_provenance)`,
    /// surfaced as a typed accessor so observers (dashboards, alerting
    /// policies, attestation manifests, structured-log routers) don't
    /// re-derive the (rule → file-provenance) partial projection at
    /// every observation site.
    ///
    /// Two-stage `None` discipline mirroring [`Self::figment_source_kind`]:
    /// (1) `None` when no attribution was recorded
    /// ([`Self::attribution_rule`] is [`None`]),
    /// (2) `None` when the recorded attribution is not on the file
    /// axis ([`Self::layer_kind`] is anything other than
    /// [`Some(crate::ConfigSourceKind::File)`]) — neither path pins a
    /// file-provider class. File-axis attributions
    /// ([`AttributionRule::FileBySource`] →
    /// [`Some(crate::FormatProvenance::FigmentBuiltin)`],
    /// [`AttributionRule::FileByMetadataName`] →
    /// [`Some(crate::FormatProvenance::ShikumiBuilt)`]) surface a
    /// [`Some`] cell directly. Operationally distinguishes "no
    /// attribution at all" from "env-axis or defaults-axis attribution
    /// that names no provider class" — observers cannot recover the
    /// originating provider class off the cross-thread envelope unless
    /// the captured rule already pinned it.
    ///
    /// Composes with [`Self::layer_kind`] as a refinement on the
    /// file-axis cells: when [`Some`], the projection is [`Some`]
    /// exactly when [`Self::layer_kind`] returns
    /// [`Some(crate::ConfigSourceKind::File)`]. Pinned by
    /// `file_provenance_some_iff_layer_kind_file`.
    ///
    /// Cross-thread mirror of
    /// [`FailingSourceAttribution::file_provenance`] (and of
    /// [`AttributionRule::file_provenance`] at the rule layer): the
    /// captured envelope's projection agrees pointwise with the live
    /// error's, pinning the lossless-capture contract for the
    /// file-provenance axis on the cross-thread observable form.
    /// Pinned by
    /// `file_provenance_agrees_with_underlying_error_pointwise`.
    ///
    /// Composes with [`Self::failing_source`] as the
    /// "which-layer × which-provider-class" coordinate over the file
    /// attribution sub-surface: a structured-log replay, attestation
    /// manifest, or per-format alerting policy that routes on both
    /// halves no longer reaches for the rule slot and projects through
    /// it inline.
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable`]).
    /// The routed body rewrites the non-const
    /// `Option::<AttributionRule>::and_then(AttributionRule::file_provenance)`
    /// spelling — rustc rejects `Option::<T>::and_then` in const fn
    /// with E0658 — into an explicit `match self.attribution_rule`
    /// whose `Some(rule) => rule.file_provenance()` arm composes an
    /// already-`Option`-returning const-fn primitive
    /// ([`AttributionRule::file_provenance`], const since `b71f975`)
    /// with the const-constructible `None => None` arm; no extra
    /// `Some` wrap on the `Some` arm. Member of the const-callable
    /// Some-iff-attribution forwarder *last* quartet
    /// ([`Self::file_provenance`],
    /// [`Self::attribution_source_kind_coordinates`],
    /// [`Self::attribution_name_kind_coordinates`],
    /// [`Self::coordinates`]) unblocked by the earlier quartet
    /// (`51975c3`) and lifted in one consolidated step; peer to
    /// [`FailingSourceAttribution::file_provenance`] (const since
    /// `00daccd`) at the corresponding envelope altitude on the
    /// borrowed-envelope side.
    #[must_use]
    pub const fn file_provenance(&self) -> Option<crate::FormatProvenance> {
        match self.attribution_rule {
            Some(rule) => rule.file_provenance(),
            None => None,
        }
    }

    /// Joint (figment-Source-axis kind × shikumi-layer-kind) cell
    /// pinned by [`Self::attribution_rule`], or `None` when no
    /// attribution was recorded *or* when the recorded attribution
    /// is name-axis (where the rule's identity does not constrain
    /// `figment::Metadata::source` and so does not pin a joint cell)
    /// — strict superset of
    /// [`Self::attribution_rule`]`.and_then(AttributionRule::attribution_source_kind_coordinates)`,
    /// surfaced as a typed accessor so observers (dashboards,
    /// alerting policies, attestation manifests) don't re-derive the
    /// (rule → joint cell) projection at every observation site.
    ///
    /// Two-stage `None` discipline mirroring
    /// [`Self::figment_source_kind`]: (1) `None` when no attribution
    /// was recorded ([`Self::attribution_rule`] is [`None`]),
    /// (2) `None` when the recorded attribution is name-axis
    /// ([`Self::metadata_axis`] is
    /// [`Some(AttributionAxis::MetadataName)`]) — neither path pins
    /// the joint cell. Source-axis attributions
    /// ([`AttributionRule::FileBySource`] → `(File, File)`,
    /// [`AttributionRule::DefaultsByCodeUniqueness`] →
    /// `(Code, Defaults)`) surface a [`Some`] cell directly.
    ///
    /// Composes [`Self::figment_source_kind`] and [`Self::layer_kind`]
    /// into one [`Copy`] joint cell; observers reading
    /// [`crate::ConfigStore::last_reload_error`] no longer pair the
    /// two partial reads inline. Every [`Some`] return satisfies
    /// [`AttributionSourceKindCoordinates::is_realizable`] —
    /// the structural diagonal of source-axis rules — pinned by
    /// `attribution_source_kind_coordinates_returns_realizable_cell_when_some`.
    ///
    /// Cross-thread mirror of
    /// [`FailingSourceAttribution::attribution_source_kind_coordinates`]
    /// (and of [`AttributionRule::attribution_source_kind_coordinates`]
    /// at the rule layer): the captured envelope's joint cell agrees
    /// pointwise with the live error's, pinning the lossless-capture
    /// contract for the source-axis joint cell on the cross-thread
    /// observable form. Pinned by
    /// `attribution_source_kind_coordinates_agrees_with_paired_projections_pointwise`.
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable`]).
    /// The routed body composes the same const-callable Copy field
    /// access + variant read + underlying
    /// [`AttributionRule::attribution_source_kind_coordinates`]
    /// partial projection (const since `0f23c22`) that
    /// [`Self::figment_source_kind`] does at the source-axis joint-cell
    /// altitude — the joint-cell partial projection lifts under the
    /// exact same closure-to-match rewrite as the underlying figment-
    /// Source-axis kind projection. Peer to
    /// [`FailingSourceAttribution::attribution_source_kind_coordinates`]
    /// (const since `d24ec4a`) at the corresponding envelope altitude
    /// on the borrowed-envelope side.
    #[must_use]
    pub const fn attribution_source_kind_coordinates(
        &self,
    ) -> Option<AttributionSourceKindCoordinates> {
        match self.attribution_rule {
            Some(rule) => rule.attribution_source_kind_coordinates(),
            None => None,
        }
    }

    /// Joint (figment-`Metadata::name`-axis kind × shikumi-layer-kind)
    /// cell pinned by [`Self::attribution_rule`], or `None` when no
    /// attribution was recorded *or* when the recorded attribution is
    /// source-axis (where the rule's identity does not constrain
    /// `figment::Metadata::name` and so does not pin a joint cell) —
    /// strict superset of
    /// [`Self::attribution_rule`]`.and_then(AttributionRule::attribution_name_kind_coordinates)`,
    /// surfaced as a typed accessor so observers (dashboards, alerting
    /// policies, attestation manifests) don't re-derive the (rule →
    /// joint cell) projection at every observation site.
    ///
    /// Symmetric peer of [`Self::attribution_source_kind_coordinates`]
    /// on the figment-`Metadata::name` axis — the two accessors close
    /// the cross-thread observable form's figment-metadata × shikumi-
    /// layer joint-cell universe. Every attributed envelope surfaces
    /// exactly one of the two joint cells as [`Some`]; unattributed
    /// envelopes surface both as [`None`]. Pinned by
    /// `attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates_on_attributed_envelopes`.
    ///
    /// Two-stage `None` discipline mirroring
    /// [`Self::attribution_source_kind_coordinates`]: (1) `None` when
    /// no attribution was recorded ([`Self::attribution_rule`] is
    /// [`None`]), (2) `None` when the recorded attribution is
    /// source-axis ([`Self::metadata_axis`] is
    /// [`Some(AttributionAxis::MetadataSource)`]) — neither path pins
    /// the joint cell. Name-axis attributions
    /// ([`AttributionRule::FileByMetadataName`] → `(Format, File)`,
    /// [`AttributionRule::EnvByPrefix`] /
    /// [`AttributionRule::EnvByUniqueness`] → `(Env, Env)`) surface a
    /// [`Some`] cell directly.
    ///
    /// Composes [`Self::figment_name_tag_kind`] and [`Self::layer_kind`]
    /// into one [`Copy`] joint cell; observers reading
    /// [`crate::ConfigStore::last_reload_error`] no longer pair the two
    /// partial reads inline. Every [`Some`] return satisfies
    /// [`AttributionNameKindCoordinates::is_realizable`] — the
    /// structural diagonal of name-axis rules — pinned by
    /// `attribution_name_kind_coordinates_returns_realizable_cell_when_some`.
    ///
    /// Cross-thread mirror of
    /// [`FailingSourceAttribution::attribution_name_kind_coordinates`]
    /// (and of [`AttributionRule::attribution_name_kind_coordinates`]
    /// at the rule layer): the captured envelope's joint cell agrees
    /// pointwise with the live error's, pinning the lossless-capture
    /// contract for the name-axis joint cell on the cross-thread
    /// observable form. Pinned by
    /// `attribution_name_kind_coordinates_agrees_with_paired_projections_pointwise`.
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable`]).
    /// The routed body composes the same const-callable Copy field
    /// access + variant read + underlying
    /// [`AttributionRule::attribution_name_kind_coordinates`] partial
    /// projection (const since `1621bb3`) that
    /// [`Self::figment_name_tag_kind`] does at the name-axis joint-cell
    /// altitude — the joint-cell partial projection lifts under the
    /// exact same closure-to-match rewrite as the underlying figment-
    /// `Metadata::name`-axis kind projection, so the source-axis /
    /// name-axis symmetry [`Self::attribution_source_kind_coordinates`]
    /// opened on the joint-cell surface stays const-preserving on
    /// both halves. Peer to
    /// [`FailingSourceAttribution::attribution_name_kind_coordinates`]
    /// (const since `0b7e71d`) at the corresponding envelope altitude
    /// on the borrowed-envelope side.
    #[must_use]
    pub const fn attribution_name_kind_coordinates(
        &self,
    ) -> Option<AttributionNameKindCoordinates> {
        match self.attribution_rule {
            Some(rule) => rule.attribution_name_kind_coordinates(),
            None => None,
        }
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
    ///
    /// `const fn`: const-callable through the envelope (welded by
    /// [`tests::reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable`]).
    /// The routed body rewrites the non-const
    /// `Option::<AttributionRule>::map(AttributionRule::coordinates)`
    /// spelling — rustc rejects `Option::<T>::map` in const fn with
    /// E0658 — into an explicit `match self.attribution_rule` whose
    /// `Some(rule) => Some(rule.coordinates())` arm composes the
    /// `Copy` variant read on the `AttributionRule` payload with the
    /// underlying [`AttributionRule::coordinates`] total projection
    /// (const since `02c5653`) and wraps the total return in
    /// `Some(_)`; the `None => None` arm is const-constructible.
    /// A compile-time-known captured envelope now folds through
    /// [`Self::coordinates`] and [`AttributionRule::from_coordinates`]
    /// without either projection dropping the caller off the
    /// const-context edge — a `const REL_TRIPLE: Option<AttributionCoordinates>
    /// = REL.coordinates()` cell followed by `const REL_RULE:
    /// Option<AttributionRule> = match REL_TRIPLE { Some(t) =>
    /// AttributionRule::from_coordinates(t), None => None }` re-hydrates
    /// the originating rule at compile time. Peer to
    /// [`FailingSourceAttribution::coordinates`] (const since
    /// `02c5653`) at the corresponding envelope altitude on the
    /// borrowed-envelope side.
    #[must_use]
    pub const fn coordinates(&self) -> Option<AttributionCoordinates> {
        match self.attribution_rule {
            Some(rule) => Some(rule.coordinates()),
            None => None,
        }
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
    ///
    /// `const fn`: const-callable on `&self` receivers backed by a
    /// `static ReloadFailure` binding. Closes the last non-const
    /// projection on `impl ReloadFailure` — the FIRST envelope-altitude
    /// forwarder on the cross-thread observable envelope that
    /// *constructs* (rather than projects out of) a borrowed
    /// [`FailingSourceAttribution`], so lifting it required the
    /// upstream [`FailingSourceAttribution::new`] constructor to be
    /// const first (const since `3c99e09`, which named this accessor
    /// as its immediate downstream compounding target). The routed
    /// body rewrites the tuple-match spelling
    /// `match (&self.failing_source, self.attribution_rule)` as a
    /// nested match — a mixed-by-ref/by-value tuple pattern in
    /// const context leans on tuple-construction reductions that are
    /// still unstable under rustc 1.94.1, so the equivalent nested
    /// match composes cleanly const-supported primitives instead:
    /// an outer `match &self.failing_source` (a field-borrow that
    /// only needs the `Option` discriminant read, const since Rust
    /// 1.46), an inner `match self.attribution_rule` (a `Copy`
    /// field load on `Option<AttributionRule>`), and the const-fn
    /// [`FailingSourceAttribution::new`] constructor on the joint
    /// `Some`-arm. With this lift every envelope-altitude
    /// projection on [`ReloadFailure`] — the total `Self::kind`,
    /// the Some-iff-attribution scalar quartet
    /// [`Self::attribution_confidence`] / [`Self::layer_kind`] /
    /// [`Self::metadata_axis`] / [`Self::coordinates`], the
    /// partial figment-metadata-axis pair
    /// [`Self::figment_source_kind`] /
    /// [`Self::figment_name_tag_kind`], the joint-cell pair
    /// [`Self::attribution_source_kind_coordinates`] /
    /// [`Self::attribution_name_kind_coordinates`], the
    /// [`Self::file_provenance`] partial, the total
    /// [`Self::field_path_localization`], the
    /// [`Self::error_localization_coordinates`] composition, and
    /// now this envelope constructor — evaluates at compile time.
    /// The cross-thread observable form now occupies the same const
    /// altitude the borrowed-envelope side occupied since the
    /// `fc9e0c6` / `37b71fb` / `b11bca7` / `a4692bc` / `00daccd` /
    /// `d24ec4a` / `0b7e71d` / `02c5653` / `3c99e09` cascade closed
    /// on `impl FailingSourceAttribution`. Welded by
    /// [`tests::reload_failure_failing_attribution_is_const_callable`].
    #[must_use]
    pub const fn failing_attribution(&self) -> Option<FailingSourceAttribution<'_>> {
        match &self.failing_source {
            Some(source) => match self.attribution_rule {
                Some(rule) => Some(FailingSourceAttribution::new(source, rule)),
                None => None,
            },
            None => None,
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
    ///
    /// `const`-callable — the projection body reads the `Copy`
    /// [`Self::kind`] field through the already-`const`
    /// [`ShikumiErrorKind::is_figment_bearing`] predicate and probes
    /// [`Self::field_path`] with the `const` [`Vec::is_empty`]
    /// primitive (stabilized const in Rust 1.87, below this crate's
    /// 1.89 MSRV), so no runtime allocator or trait-object dispatch is
    /// reached on any of the three branches. Welded by
    /// [`tests::reload_failure_field_path_localization_is_const_callable`].
    #[must_use]
    pub const fn field_path_localization(&self) -> FieldPathLocalization {
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

    /// The captured offending field path rendered as a single
    /// `.`-joined dotted key — the operator-facing form of
    /// [`Self::field_path`].
    ///
    /// Cross-thread mirror of [`crate::ShikumiError::field_path_dotted`],
    /// routed through the same `dotted_field_path` join so the live
    /// error and the captured envelope name the offending field with
    /// byte-identical strings. Total over the [`ReloadFailure`] surface
    /// (returns `String`, not `Option`): the flat [`Vec<String>`]
    /// representation of [`Self::field_path`] already collapsed the
    /// underlying `None` (non-figment) and `Some("")` (figment-but-
    /// unlocalized) tri-state into one empty observable, so both render
    /// as `""` here — the same collapse the field itself documents. The
    /// distinction is recoverable through [`Self::field_path_localization`].
    ///
    /// Agrees pointwise with the underlying error: for any
    /// [`crate::ShikumiError`] `e`,
    /// `ReloadFailure::from_error(&e).field_path_dotted()` equals
    /// `e.field_path_dotted().unwrap_or_default()` — pinned by
    /// `field_path_dotted_agrees_with_underlying_error_pointwise`.
    /// Lets an observer reading [`crate::ConfigStore::last_reload_error`]
    /// render the offending field without re-joining
    /// `Self::field_path` at the consumer site.
    #[must_use]
    pub fn field_path_dotted(&self) -> String {
        dotted_field_path(&self.field_path)
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
    ///
    /// `const`-callable: composes the two const-fn sub-projections
    /// [`Self::kind`] (const since `9bc4eb7`) and
    /// [`Self::field_path_localization`] (const since `64de910`)
    /// into an [`ErrorLocalizationCoordinates`] struct literal over
    /// two `Copy` closed-enum fields — the composition itself lands
    /// no runtime code past the two const sub-calls. Pinned by
    /// [`tests::reload_failure_error_localization_coordinates_is_const_callable`].
    #[must_use]
    pub const fn error_localization_coordinates(&self) -> ErrorLocalizationCoordinates {
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
        let err = crate::error::synthetic_parse_error();
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
        let err = ShikumiError::Extract {
            sources: vec![],
            error: crate::source::synthetic_field_path_error("window.size"),
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
        let err = ShikumiError::Figment(crate::source::synthetic_field_path_error("a.b.c"));
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error())
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
        let parse = ReloadFailure::from_error(&crate::error::synthetic_parse_error());
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            let f = synthetic_failure_with_rule(rule);
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            let f = synthetic_failure_with_rule(rule);
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
    fn layer_kind_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the (file × env × defaults)
        // layer-kind axis on the cross-thread observable form: the
        // captured envelope's layer_kind projection mirrors the source
        // error's layer_kind byte-for-byte across every constructible
        // ShikumiError variant. Peer of
        // `error_localization_coordinates_agrees_with_underlying_error_pointwise`
        // on the coordinate plane, and of
        // `figment_source_kind_agrees_with_underlying_error_pointwise` /
        // `figment_name_tag_kind_agrees_with_underlying_error_pointwise` /
        // `file_provenance_agrees_with_underlying_error_pointwise` on
        // the figment-metadata axes — this pin closes the same lossless-
        // capture contract on the layer-kind axis, so a future refactor
        // of either side (the live `ShikumiError::layer_kind` accessor
        // or the captured `ReloadFailure::layer_kind` field-forwarder)
        // is bound to move the other in lockstep.
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

        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.layer_kind(),
                err.layer_kind(),
                "captured layer_kind must mirror source layer_kind for {err:?}",
            );
        }

        // End-to-end pin on a real Extract failure: the layer-kind
        // survives capture through `ReloadFailure::from_error` on both
        // file-axis (FileBySource) and defaults-axis
        // (DefaultsByCodeUniqueness) attribution resolvers.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_lk_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert_eq!(f_file.layer_kind(), err_file.layer_kind());
        assert_eq!(f_file.layer_kind(), Some(ConfigSourceKind::File));

        let err_def = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let f_def = ReloadFailure::from_error(&err_def);
        assert_eq!(f_def.layer_kind(), err_def.layer_kind());
        assert_eq!(f_def.layer_kind(), Some(ConfigSourceKind::Defaults));
    }

    #[test]
    fn metadata_axis_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the (`metadata.source` ×
        // `metadata.name`) axis on the cross-thread observable form:
        // the captured envelope's metadata_axis projection mirrors the
        // source error's metadata_axis byte-for-byte across every
        // constructible ShikumiError variant. Peer of
        // `layer_kind_agrees_with_underlying_error_pointwise` on the
        // sibling axis, closing the same lossless-capture contract at
        // the metadata-axis altitude — a future refactor of either
        // side (the live `ShikumiError::metadata_axis` accessor or the
        // captured `ReloadFailure::metadata_axis` field-forwarder) is
        // bound to move the other in lockstep.
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

        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.metadata_axis(),
                err.metadata_axis(),
                "captured metadata_axis must mirror source metadata_axis for {err:?}",
            );
        }

        // End-to-end pin on a real Extract failure: the metadata-axis
        // survives capture through `ReloadFailure::from_error` on both
        // file-axis (FileBySource → MetadataSource) and defaults-axis
        // (DefaultsByCodeUniqueness → MetadataSource) attribution
        // resolvers.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_ma_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert_eq!(f_file.metadata_axis(), err_file.metadata_axis());
        assert_eq!(
            f_file.metadata_axis(),
            Some(AttributionAxis::MetadataSource)
        );

        let err_def = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let f_def = ReloadFailure::from_error(&err_def);
        assert_eq!(f_def.metadata_axis(), err_def.metadata_axis());
        assert_eq!(f_def.metadata_axis(), Some(AttributionAxis::MetadataSource));
    }

    #[test]
    fn attribution_confidence_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the (exact × fallback)
        // confidence axis on the cross-thread observable form: the
        // captured envelope's attribution_confidence projection mirrors
        // the source error's attribution_confidence byte-for-byte
        // across every constructible ShikumiError variant. Peer of
        // `layer_kind_agrees_with_underlying_error_pointwise` and
        // `metadata_axis_agrees_with_underlying_error_pointwise` on the
        // sibling axes, closing the same lossless-capture contract at
        // the confidence-axis altitude — a future refactor of either
        // side (the live `ShikumiError::attribution_confidence`
        // accessor or the captured `ReloadFailure::attribution_confidence`
        // field-forwarder) is bound to move the other in lockstep.
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

        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.attribution_confidence(),
                err.attribution_confidence(),
                "captured attribution_confidence must mirror source \
                 attribution_confidence for {err:?}",
            );
        }

        // End-to-end pin on real Extract failures across both
        // confidence classes: FileBySource → Exact and
        // DefaultsByCodeUniqueness → Fallback both survive capture
        // through `ReloadFailure::from_error` byte-for-byte, so the
        // captured envelope observes the same weighting as the live
        // error.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_ac_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert_eq!(
            f_file.attribution_confidence(),
            err_file.attribution_confidence(),
        );
        assert_eq!(
            f_file.attribution_confidence(),
            Some(AttributionConfidence::Exact),
        );

        let err_def = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let f_def = ReloadFailure::from_error(&err_def);
        assert_eq!(
            f_def.attribution_confidence(),
            err_def.attribution_confidence(),
        );
        assert_eq!(
            f_def.attribution_confidence(),
            Some(AttributionConfidence::Fallback),
        );
    }

    #[test]
    fn figment_source_kind_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the
        // (`file` × `code` × `custom`) figment-source axis on the
        // cross-thread observable form: the captured envelope's
        // figment_source_kind projection mirrors the source error's
        // figment_source_kind byte-for-byte across every constructible
        // ShikumiError variant. Peer of
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the figment-source-axis altitude — a future
        // refactor of either side (the live
        // `ShikumiError::figment_source_kind` accessor or the captured
        // `ReloadFailure::figment_source_kind` field-forwarder) is
        // bound to move the other in lockstep.
        //
        // Adds a name-axis probe on top of the source-axis file /
        // defaults probes carried by the sibling agreement tests: a
        // real EnvByPrefix Extract failure resolves to a Some(rule)
        // attribution whose figment_source_kind is None at the rule
        // layer, so the pointwise contract must reproduce that None on
        // both sides of the capture boundary without collapsing it
        // into the outer None-when-unattributed branch.
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

        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.figment_source_kind(),
                err.figment_source_kind(),
                "captured figment_source_kind must mirror source \
                 figment_source_kind for {err:?}",
            );
        }

        // End-to-end pin on real Extract failures across the two
        // source-axis figment-source cells: FileBySource → File and
        // DefaultsByCodeUniqueness → Code both survive capture through
        // `ReloadFailure::from_error` byte-for-byte.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_fsk_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err_file = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert_eq!(f_file.figment_source_kind(), err_file.figment_source_kind());
        assert_eq!(f_file.figment_source_kind(), Some(FigmentSourceKind::File));

        let err_def = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let f_def = ReloadFailure::from_error(&err_def);
        assert_eq!(f_def.figment_source_kind(), err_def.figment_source_kind());
        assert_eq!(f_def.figment_source_kind(), Some(FigmentSourceKind::Code));

        // End-to-end pin on the name-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // figment_source_kind == None on both sides — a Some outer /
        // None inner cell that the source-axis probes above never
        // reach, distinguishing the (attribution absent → outer None)
        // and (attribution present but rule is name-axis → inner None)
        // branches on both sides of the capture boundary.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(f_env.figment_source_kind(), err_env.figment_source_kind());
        assert_eq!(f_env.figment_source_kind(), None);
    }

    #[test]
    fn figment_name_tag_kind_agrees_with_shikumi_error_accessor_pointwise() {
        // Lossless-capture contract for the (`format` × `env`)
        // figment-name-tag axis on the cross-thread observable form: the
        // captured envelope's figment_name_tag_kind projection mirrors
        // the source error's `ShikumiError::figment_name_tag_kind`
        // (the direct live-error accessor added alongside this test)
        // byte-for-byte across every constructible ShikumiError variant.
        // Peer of `figment_source_kind_agrees_with_underlying_error_pointwise`
        // /
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the figment-name-tag-axis altitude — a future
        // refactor of either side (the live
        // `ShikumiError::figment_name_tag_kind` accessor or the captured
        // `ReloadFailure::figment_name_tag_kind` field-forwarder) is
        // bound to move the other in lockstep. Distinct from the
        // existing sibling `figment_name_tag_kind_agrees_with_underlying_error_pointwise`
        // test (which routes through `err.failing_attribution().and_then(...)`
        // for the underlying side): this pin routes through the
        // one-hop `ShikumiError::figment_name_tag_kind` accessor
        // directly, closing the API-symmetry contract on the
        // (`format` × `env`) name-axis peer of the cascade.
        //
        // Exercises the two source-axis / name-axis boundary cases the
        // pointwise contract must reproduce on both sides of the
        // capture boundary: (a) a source-axis FileBySource attribution
        // whose figment_name_tag_kind is None at the rule layer even
        // though failing_attribution is Some (Some outer, None inner);
        // (b) a name-axis EnvByPrefix attribution whose
        // figment_name_tag_kind lands on Env.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.figment_name_tag_kind(),
                err.figment_name_tag_kind(),
                "captured figment_name_tag_kind must mirror source \
                 figment_name_tag_kind for {err:?}",
            );
        }

        // End-to-end pin on the source-axis branch: a real FileBySource
        // Extract failure resolves to Some(rule) with
        // figment_name_tag_kind == None on both sides — the Some
        // outer / None inner cell that distinguishes the
        // (attribution absent → outer None) and (attribution present
        // but rule is source-axis → inner None) branches on the
        // captured / live-error sides of the boundary.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_fntk_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err_file = crate::provider::ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert!(err_file.failing_attribution().is_some());
        assert_eq!(
            f_file.figment_name_tag_kind(),
            err_file.figment_name_tag_kind()
        );
        assert_eq!(f_file.figment_name_tag_kind(), None);

        // End-to-end pin on the name-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // figment_name_tag_kind == Some(Env) on both sides — the Some
        // outer / Some inner cell that anchors the name-axis half of
        // the (source-axis, name-axis) partition of the attribution
        // surface.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(
            f_env.figment_name_tag_kind(),
            err_env.figment_name_tag_kind()
        );
        assert_eq!(f_env.figment_name_tag_kind(), Some(FigmentNameTagKind::Env));
    }

    #[test]
    fn file_provenance_agrees_with_shikumi_error_accessor_pointwise() {
        // Lossless-capture contract for the
        // (`FigmentBuiltin` × `ShikumiBuilt`) file-provenance axis on
        // the cross-thread observable form: the captured envelope's
        // file_provenance projection mirrors the source error's
        // `ShikumiError::file_provenance` (the direct live-error
        // accessor added alongside this test) byte-for-byte across
        // every constructible ShikumiError variant. Peer of
        // `figment_source_kind_agrees_with_underlying_error_pointwise`
        // /
        // `figment_name_tag_kind_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the file-provenance-axis altitude — a future
        // refactor of either side (the live
        // `ShikumiError::file_provenance` accessor or the captured
        // `ReloadFailure::file_provenance` field-forwarder) is bound to
        // move the other in lockstep.
        //
        // Exercises the two file-axis / non-file-axis boundary cases
        // the pointwise contract must reproduce on both sides of the
        // capture boundary: (a) a file-axis FileBySource attribution
        // whose file_provenance lands on FigmentBuiltin (Some outer,
        // Some inner); (b) a non-file-axis EnvByPrefix attribution
        // whose file_provenance is None at the rule layer even though
        // failing_attribution is Some (Some outer, None inner).
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.file_provenance(),
                err.file_provenance(),
                "captured file_provenance must mirror source \
                 file_provenance for {err:?}",
            );
        }

        // End-to-end pin on the file-axis branch: a real FileBySource
        // Extract failure resolves to Some(rule) with
        // file_provenance == Some(FigmentBuiltin) on both sides —
        // figment's built-in YAML provider attaches metadata.source as
        // a File source, so the resolver dispatches to FileBySource on
        // the MetadataSource axis and the file-provenance projection
        // recovers the originating provider class through the captured
        // rule slot.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_fp_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err_file = crate::provider::ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert!(err_file.failing_attribution().is_some());
        assert_eq!(f_file.file_provenance(), err_file.file_provenance());
        assert_eq!(
            f_file.file_provenance(),
            Some(crate::FormatProvenance::FigmentBuiltin),
        );

        // End-to-end pin on the non-file-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // file_provenance == None on both sides — a Some outer / None
        // inner cell that the file-axis probe above never reaches,
        // distinguishing the (attribution absent → outer None) and
        // (attribution present but rule is non-file-axis → inner None)
        // branches on both sides of the capture boundary.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(f_env.file_provenance(), err_env.file_provenance());
        assert_eq!(f_env.file_provenance(), None);
    }

    #[test]
    fn attribution_source_kind_coordinates_agrees_with_shikumi_error_accessor_pointwise() {
        // Lossless-capture contract for the source-axis joint-cell
        // (figment-Source-axis kind × shikumi-layer-kind) projection on
        // the cross-thread observable form: the captured envelope's
        // attribution_source_kind_coordinates projection mirrors the
        // source error's `ShikumiError::attribution_source_kind_coordinates`
        // (the direct live-error accessor added alongside this test)
        // byte-for-byte across every constructible ShikumiError variant.
        // Peer of
        // `file_provenance_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `figment_source_kind_agrees_with_underlying_error_pointwise`
        // /
        // `figment_name_tag_kind_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the source-axis joint-cell altitude — a future
        // refactor of either side (the live
        // `ShikumiError::attribution_source_kind_coordinates` accessor
        // or the captured `ReloadFailure::attribution_source_kind_coordinates`
        // field-forwarder) is bound to move the other in lockstep.
        // Distinct from the pre-existing
        // `attribution_source_kind_coordinates_agrees_with_rule_pointwise`
        // test (which routed through
        // `err.failing_attribution().and_then(|a| a.attribution_source_kind_coordinates())`
        // for the underlying side): this pin routes through the one-hop
        // `ShikumiError::attribution_source_kind_coordinates` accessor
        // directly.
        //
        // Exercises the two source-axis / name-axis boundary cases the
        // pointwise contract must reproduce on both sides of the
        // capture boundary: (a) a source-axis FileBySource attribution
        // whose joint cell lands on (File, File) (Some outer, Some
        // inner); (b) a name-axis EnvByPrefix attribution whose
        // attribution_source_kind_coordinates is None at the rule
        // layer even though failing_attribution is Some (Some outer,
        // None inner).
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.attribution_source_kind_coordinates(),
                err.attribution_source_kind_coordinates(),
                "captured attribution_source_kind_coordinates must \
                 mirror source attribution_source_kind_coordinates for \
                 {err:?}",
            );
        }

        // End-to-end pin on the source-axis branch: a real FileBySource
        // Extract failure resolves to Some(rule) with
        // attribution_source_kind_coordinates == Some((File, File)) on
        // both sides — figment's built-in YAML provider attaches
        // metadata.source as a File source, so the resolver dispatches
        // to FileBySource on the MetadataSource axis and the
        // joint-cell projection recovers the source-axis rule's paired
        // identity through the captured rule slot.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_askc_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err_file = crate::provider::ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert!(err_file.failing_attribution().is_some());
        assert_eq!(
            f_file.attribution_source_kind_coordinates(),
            err_file.attribution_source_kind_coordinates(),
        );
        assert_eq!(
            f_file.attribution_source_kind_coordinates(),
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::File,
                layer_kind: ConfigSourceKind::File,
            }),
        );

        // End-to-end pin on the name-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // attribution_source_kind_coordinates == None on both sides —
        // a Some outer / None inner cell that the source-axis probe
        // above never reaches, distinguishing the (attribution absent
        // → outer None) and (attribution present but rule is name-axis
        // → inner None) branches on both sides of the capture
        // boundary.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(
            f_env.attribution_source_kind_coordinates(),
            err_env.attribution_source_kind_coordinates(),
        );
        assert_eq!(f_env.attribution_source_kind_coordinates(), None);
    }

    #[test]
    fn attribution_name_kind_coordinates_agrees_with_shikumi_error_accessor_pointwise() {
        // Lossless-capture contract for the name-axis joint-cell
        // (figment-`Metadata::name`-axis kind × shikumi-layer-kind)
        // projection on the cross-thread observable form: the captured
        // envelope's attribution_name_kind_coordinates projection
        // mirrors the source error's
        // `ShikumiError::attribution_name_kind_coordinates` (the direct
        // live-error accessor added alongside this test) byte-for-byte
        // across every constructible ShikumiError variant. Peer of
        // `attribution_source_kind_coordinates_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `file_provenance_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `figment_source_kind_agrees_with_underlying_error_pointwise`
        // /
        // `figment_name_tag_kind_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the name-axis joint-cell altitude — a future
        // refactor of either side (the live
        // `ShikumiError::attribution_name_kind_coordinates` accessor or
        // the captured `ReloadFailure::attribution_name_kind_coordinates`
        // field-forwarder) is bound to move the other in lockstep.
        // Distinct from the pre-existing
        // `attribution_name_kind_coordinates_agrees_with_rule_pointwise`
        // test (which routed through
        // `err.failing_attribution().and_then(|a| a.attribution_name_kind_coordinates())`
        // for the underlying side): this pin routes through the
        // one-hop `ShikumiError::attribution_name_kind_coordinates`
        // accessor directly.
        //
        // Exercises the two name-axis / source-axis boundary cases the
        // pointwise contract must reproduce on both sides of the
        // capture boundary: (a) a name-axis EnvByPrefix attribution
        // whose joint cell lands on (Env, Env) (Some outer, Some
        // inner); (b) a source-axis FileBySource attribution whose
        // attribution_name_kind_coordinates is None at the rule layer
        // even though failing_attribution is Some (Some outer, None
        // inner).
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.attribution_name_kind_coordinates(),
                err.attribution_name_kind_coordinates(),
                "captured attribution_name_kind_coordinates must \
                 mirror source attribution_name_kind_coordinates for \
                 {err:?}",
            );
        }

        // End-to-end pin on the name-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // attribution_name_kind_coordinates == Some((Env, Env)) on
        // both sides — figment's env-shaped Metadata::name and the
        // chain's single Env source route the resolver to EnvByPrefix
        // on the MetadataName axis and the joint-cell projection
        // recovers the name-axis rule's paired identity through the
        // captured rule slot.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(
            f_env.attribution_name_kind_coordinates(),
            err_env.attribution_name_kind_coordinates(),
        );
        assert_eq!(
            f_env.attribution_name_kind_coordinates(),
            Some(AttributionNameKindCoordinates {
                figment_name_tag_kind: FigmentNameTagKind::Env,
                layer_kind: ConfigSourceKind::Env,
            }),
        );

        // End-to-end pin on the source-axis branch: a real FileBySource
        // Extract failure resolves to Some(rule) with
        // attribution_name_kind_coordinates == None on both sides — a
        // Some outer / None inner cell that the name-axis probe above
        // never reaches, distinguishing the (attribution absent →
        // outer None) and (attribution present but rule is source-axis
        // → inner None) branches on both sides of the capture
        // boundary.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_ankc_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err_file = crate::provider::ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert!(err_file.failing_attribution().is_some());
        assert_eq!(
            f_file.attribution_name_kind_coordinates(),
            err_file.attribution_name_kind_coordinates(),
        );
        assert_eq!(f_file.attribution_name_kind_coordinates(), None);
    }

    #[test]
    fn coordinates_agrees_with_shikumi_error_accessor_pointwise() {
        // Lossless-capture contract for the coordinate triple
        // (axis × layer-kind × confidence) projection on the
        // cross-thread observable form: the captured envelope's
        // `ReloadFailure::coordinates` projection mirrors the source
        // error's `ShikumiError::coordinates` (the direct live-error
        // accessor added alongside this test) byte-for-byte across
        // every constructible ShikumiError variant. Peer of
        // `attribution_name_kind_coordinates_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `attribution_source_kind_coordinates_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `file_provenance_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `figment_source_kind_agrees_with_underlying_error_pointwise`
        // /
        // `figment_name_tag_kind_agrees_with_shikumi_error_accessor_pointwise`
        // /
        // `layer_kind_agrees_with_underlying_error_pointwise` /
        // `metadata_axis_agrees_with_underlying_error_pointwise` /
        // `attribution_confidence_agrees_with_underlying_error_pointwise`
        // on the sibling axes, closing the same lossless-capture
        // contract at the total-triple altitude — a future refactor of
        // either side (the live `ShikumiError::coordinates` accessor or
        // the captured `ReloadFailure::coordinates` field-forwarder) is
        // bound to move the other in lockstep. This landing completes
        // the cascade: every projection on the captured envelope
        // `ReloadFailure` now has a matching one-hop accessor at the
        // same altitude on the live-error side, and every accessor
        // pair carries a pointwise-agreement pin.
        //
        // Exercises the two rule-axis boundary cases the pointwise
        // contract must reproduce on both sides of the capture
        // boundary: (a) a source-axis FileBySource attribution whose
        // coordinate triple lands on
        // (MetadataSource, File, Exact); (b) a name-axis EnvByPrefix
        // attribution whose coordinate triple lands on the name-axis
        // rule's own three coordinates. Unlike the partial joint-cell
        // pointwise pins, both axes here surface Some — the total-map
        // polarity of `coordinates` means the pointwise contract
        // covers the Some-outer / Some-inner cell across both rule
        // axes with no inner-None branch to distinguish.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.coordinates(),
                err.coordinates(),
                "captured coordinates must mirror source coordinates \
                 for {err:?}",
            );
        }

        // End-to-end pin on the source-axis branch: a real FileBySource
        // Extract failure resolves to Some(rule) with
        // coordinates == Some(FileBySource.coordinates()) on both
        // sides — figment's built-in YAML provider attaches
        // metadata.source as a File source, so the resolver dispatches
        // to FileBySource on the MetadataSource axis and the
        // total-triple projection recovers the rule's three
        // coordinates through the captured rule slot.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_coords_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err_file = crate::provider::ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f_file = ReloadFailure::from_error(&err_file);
        assert!(err_file.failing_attribution().is_some());
        assert_eq!(f_file.coordinates(), err_file.coordinates());
        assert_eq!(
            f_file.coordinates(),
            Some(AttributionRule::FileBySource.coordinates()),
        );

        // End-to-end pin on the name-axis branch: an EnvByPrefix
        // Extract failure resolves to Some(rule) with
        // coordinates == Some(EnvByPrefix.coordinates()) on both sides.
        // Both boundary probes surface Some here (unlike the partial
        // joint-cell pins), pinning that neither rule axis collapses
        // into the outer None-when-unattributed branch.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
        ];
        let err_env = ShikumiError::Extract {
            sources: chain,
            error: crate::source::synthetic_env_metadata_error("MYAPP_"),
        };
        let f_env = ReloadFailure::from_error(&err_env);
        assert!(err_env.failing_attribution().is_some());
        assert_eq!(f_env.coordinates(), err_env.coordinates());
        assert_eq!(
            f_env.coordinates(),
            Some(AttributionRule::EnvByPrefix.coordinates()),
        );
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
            let f = synthetic_failure_with_rule(rule);
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

    #[test]
    fn reload_failure_kind_is_const_callable() {
        // Weld the const-callability of `ReloadFailure::kind` — the
        // sum-type-to-kind projection at the cross-thread observable
        // envelope altitude — at compile time. First const-lift on
        // `impl ReloadFailure`, mirroring altitude-for-altitude the
        // first const-lift on `impl ShikumiError`
        // (`ShikumiError::kind`, const since `4b00851`, welded by
        // `shikumi_error_kind_is_const_callable` in `error::tests`):
        // the two altitudes now share the const-callability parity
        // on the sum-type-to-kind projection surface. A future edit
        // that reaches for a non-const helper on the projection body
        // (an allocator, a runtime-only accessor over the Copy
        // field) fails at THIS line before drifting into the every
        // remaining envelope-altitude forwarder that will lift on
        // top of it in a subsequent step.
        //
        // Const-constructibility on `ReloadFailure` in const context
        // is load-bearing: every payload-carrying field has a
        // const-constructible degenerate (`String::new()`,
        // `Vec::new()`, `None`), so a `static` root binding holds
        // the envelope in const-eval scope. Exercised across three
        // kind arms of `ShikumiErrorKind` (`NotFound` — a
        // non-figment-bearing kind that never carries attribution;
        // `Extract` — the sole figment-bearing kind that can carry a
        // recorded chain; `Validation` — a non-figment-bearing
        // kind that carries neither chain nor path). Each thread
        // through the same `Self::kind` projection at compile time
        // and cross-checks against the underlying `Copy` field
        // read.
        //
        // The `static` rather than `const` receiver is load-bearing
        // for the same E0493 reason as
        // `shikumi_error_kind_is_const_callable`: `ReloadFailure`
        // carries `Drop`-bearing payloads (`String`,
        // `Vec<ConfigSource>`, `Vec<String>`,
        // `Option<ConfigSource>`), so a `const REL: ReloadFailure =
        // ...; const KIND = REL.kind();` spelling drops the const
        // value after the kind projection and rejects. A `static
        // REL: ReloadFailure` is never dropped, so borrowing `&REL`
        // for the `&self` receiver in a `const` initializer stays
        // inside the const-eval envelope.
        static NOT_FOUND_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::NotFound,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static EXTRACT_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static VALIDATION_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Validation,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        const NOT_FOUND_KIND: ShikumiErrorKind = NOT_FOUND_REL.kind();
        const EXTRACT_KIND: ShikumiErrorKind = EXTRACT_REL.kind();
        const VALIDATION_KIND: ShikumiErrorKind = VALIDATION_REL.kind();

        assert_eq!(NOT_FOUND_KIND, ShikumiErrorKind::NotFound);
        assert_eq!(EXTRACT_KIND, ShikumiErrorKind::Extract);
        assert_eq!(VALIDATION_KIND, ShikumiErrorKind::Validation);

        // Cross-check: the const-fn projection stays pointwise
        // agreed with the runtime-side `rel.kind()` call and with
        // the underlying `rel.kind` Copy field read over the three
        // const-welded arms. Redundant with the pointwise pins
        // above (`kind_accessor_agrees_with_field_pointwise`,
        // `kind_agrees_with_underlying_error_kind_pointwise`), but
        // this pin catches a future edit that shifted the const-fn
        // body away from the runtime-fn body or the field read on
        // any of the three welded arms.
        assert_eq!(NOT_FOUND_KIND, NOT_FOUND_REL.kind());
        assert_eq!(EXTRACT_KIND, EXTRACT_REL.kind());
        assert_eq!(VALIDATION_KIND, VALIDATION_REL.kind());
        assert_eq!(NOT_FOUND_KIND, NOT_FOUND_REL.kind);
        assert_eq!(EXTRACT_KIND, EXTRACT_REL.kind);
        assert_eq!(VALIDATION_KIND, VALIDATION_REL.kind);
    }

    #[test]
    fn reload_failure_attribution_confidence_is_const_callable() {
        // Weld the const-callability of `ReloadFailure::attribution_confidence`
        // — the Some-iff-attribution confidence projection at the
        // cross-thread observable envelope altitude — at compile
        // time. Second const-lift on `impl ReloadFailure` after
        // `reload_failure_kind_is_const_callable` (kind axis, total
        // over the envelope; const since `9bc4eb7`); opens the
        // envelope-altitude cascade over the Some-iff-attribution
        // forwarders (layer_kind / metadata_axis / figment-metadata-axis
        // / joint-coordinate / file-provenance) — each lifts by the
        // same `match`-arm rewrite in a subsequent step.
        //
        // Weld across the six attribution scenarios: the `None`
        // scenario (no attribution recorded) plus one welded scenario
        // for each of the five `AttributionRule` variants under the
        // `AttributionRule::ALL`-equivalent enumeration. Each of the
        // six routes the envelope through the const-fn projection at
        // compile time; the pointwise pins cross-check the routed
        // arm against both the runtime-fn projection and the
        // underlying rule-altitude `AttributionRule::confidence`
        // total projection (const since `df3334f`, welded by
        // `attribution_rule_confidence_and_confidence_predicates_are_const_callable`
        // in `error::tests`).
        //
        // The `static` rather than `const` receiver is load-bearing
        // for the same E0493 reason as
        // `reload_failure_kind_is_const_callable`: `ReloadFailure`
        // carries `Drop`-bearing payloads (`String`,
        // `Vec<ConfigSource>`, `Vec<String>`,
        // `Option<ConfigSource>`), so a `const REL: ReloadFailure =
        // ...; const CONF = REL.attribution_confidence();` spelling
        // drops the const value after the projection and rejects. A
        // `static REL: ReloadFailure` is never dropped, so borrowing
        // `&REL` for the `&self` receiver in a `const` initializer
        // stays inside the const-eval envelope.
        static NONE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static FILE_BY_SOURCE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileBySource),
        };
        static FILE_BY_METADATA_NAME_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileByMetadataName),
        };
        static ENV_BY_PREFIX_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByPrefix),
        };
        static ENV_BY_UNIQUENESS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByUniqueness),
        };
        static DEFAULTS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };

        const NONE_CONF: Option<AttributionConfidence> = NONE_REL.attribution_confidence();
        const FILE_BY_SOURCE_CONF: Option<AttributionConfidence> =
            FILE_BY_SOURCE_REL.attribution_confidence();
        const FILE_BY_METADATA_NAME_CONF: Option<AttributionConfidence> =
            FILE_BY_METADATA_NAME_REL.attribution_confidence();
        const ENV_BY_PREFIX_CONF: Option<AttributionConfidence> =
            ENV_BY_PREFIX_REL.attribution_confidence();
        const ENV_BY_UNIQUENESS_CONF: Option<AttributionConfidence> =
            ENV_BY_UNIQUENESS_REL.attribution_confidence();
        const DEFAULTS_CONF: Option<AttributionConfidence> = DEFAULTS_REL.attribution_confidence();

        // Some-iff-attribution discipline holds through the const-fn
        // body: only the None-arm envelope maps to None; every
        // rule-carrying envelope maps to Some(_).
        assert_eq!(NONE_CONF, None);
        assert_eq!(FILE_BY_SOURCE_CONF, Some(AttributionConfidence::Exact));
        assert_eq!(
            FILE_BY_METADATA_NAME_CONF,
            Some(AttributionConfidence::Exact)
        );
        assert_eq!(ENV_BY_PREFIX_CONF, Some(AttributionConfidence::Exact));
        assert_eq!(
            ENV_BY_UNIQUENESS_CONF,
            Some(AttributionConfidence::Fallback)
        );
        assert_eq!(DEFAULTS_CONF, Some(AttributionConfidence::Fallback));

        // Cross-check: the const-fn projection stays pointwise
        // agreed with the runtime-side `rel.attribution_confidence()`
        // call and with the underlying rule-altitude
        // `AttributionRule::confidence` total projection over the
        // five rule arms. Redundant with the pointwise pin above
        // (`attribution_confidence_agrees_with_rule_confidence_pointwise`),
        // but this pin catches a future edit that shifted the
        // const-fn body away from the runtime-fn body or the
        // underlying rule-altitude projection on any of the six
        // welded arms.
        assert_eq!(NONE_CONF, NONE_REL.attribution_confidence());
        assert_eq!(
            FILE_BY_SOURCE_CONF,
            FILE_BY_SOURCE_REL.attribution_confidence()
        );
        assert_eq!(
            FILE_BY_METADATA_NAME_CONF,
            FILE_BY_METADATA_NAME_REL.attribution_confidence()
        );
        assert_eq!(
            ENV_BY_PREFIX_CONF,
            ENV_BY_PREFIX_REL.attribution_confidence()
        );
        assert_eq!(
            ENV_BY_UNIQUENESS_CONF,
            ENV_BY_UNIQUENESS_REL.attribution_confidence()
        );
        assert_eq!(DEFAULTS_CONF, DEFAULTS_REL.attribution_confidence());
        assert_eq!(
            FILE_BY_SOURCE_CONF,
            Some(AttributionRule::FileBySource.confidence())
        );
        assert_eq!(
            FILE_BY_METADATA_NAME_CONF,
            Some(AttributionRule::FileByMetadataName.confidence())
        );
        assert_eq!(
            ENV_BY_PREFIX_CONF,
            Some(AttributionRule::EnvByPrefix.confidence())
        );
        assert_eq!(
            ENV_BY_UNIQUENESS_CONF,
            Some(AttributionRule::EnvByUniqueness.confidence())
        );
        assert_eq!(
            DEFAULTS_CONF,
            Some(AttributionRule::DefaultsByCodeUniqueness.confidence())
        );
    }

    #[test]
    fn reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable() {
        // Weld the const-callability of the four remaining
        // Some-iff-attribution forwarders on `impl ReloadFailure` in
        // one consolidated step:
        //   * `Self::layer_kind`
        //     (file × env × defaults) — non-const
        //     `Option::<AttributionRule>::map(AttributionRule::layer_kind)`
        //     rewritten to the same `match self.attribution_rule`
        //     shape as `Self::attribution_confidence` (`6d160c8`).
        //   * `Self::metadata_axis`
        //     (source × name) — parallel `.map(_)` rewrite.
        //   * `Self::figment_source_kind`
        //     (partial over source-axis rules) —
        //     `Option::<AttributionRule>::and_then(_)` rewritten to a
        //     `match` whose `Some(rule) => rule.figment_source_kind()`
        //     arm composes an already-`Option`-returning const-fn
        //     primitive (no extra `Some` wrap on the `Some` arm).
        //   * `Self::figment_name_tag_kind`
        //     (partial over name-axis rules) — parallel `.and_then(_)`
        //     rewrite; closes the source-axis / name-axis parity.
        //
        // With these four lifted, the four orthogonal projections
        // over the rule space (layer-kind × metadata-axis ×
        // figment-Source-axis kind × figment-name-axis kind) all
        // evaluate at compile time through the envelope, matching the
        // const altitude the peer accessors on the borrowed
        // `FailingSourceAttribution` side already occupy
        // (`fc9e0c6` / `37b71fb` / `b11bca7` / `a4692bc`).
        //
        // Weld structure: six `static ReloadFailure` bindings (one
        // None-arm plus one per `AttributionRule` variant) route
        // through all four const-fn projections in const position.
        // Pointwise pins prove each routed arm stays byte-for-byte
        // agreed with (a) the runtime-side call on the same envelope
        // and (b) the underlying rule-altitude const-fn primitive.
        // The `static` (rather than `const`) receiver is load-bearing
        // for the same E0493 reason as
        // `reload_failure_attribution_confidence_is_const_callable`:
        // `ReloadFailure` carries `Drop`-bearing payloads.
        static NONE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static FILE_BY_SOURCE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileBySource),
        };
        static FILE_BY_METADATA_NAME_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileByMetadataName),
        };
        static ENV_BY_PREFIX_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByPrefix),
        };
        static ENV_BY_UNIQUENESS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByUniqueness),
        };
        static DEFAULTS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };

        // ---- layer_kind (Some-iff-attribution, total on Some arm) ----
        const NONE_LK: Option<ConfigSourceKind> = NONE_REL.layer_kind();
        const FILE_BY_SOURCE_LK: Option<ConfigSourceKind> = FILE_BY_SOURCE_REL.layer_kind();
        const FILE_BY_METADATA_NAME_LK: Option<ConfigSourceKind> =
            FILE_BY_METADATA_NAME_REL.layer_kind();
        const ENV_BY_PREFIX_LK: Option<ConfigSourceKind> = ENV_BY_PREFIX_REL.layer_kind();
        const ENV_BY_UNIQUENESS_LK: Option<ConfigSourceKind> = ENV_BY_UNIQUENESS_REL.layer_kind();
        const DEFAULTS_LK: Option<ConfigSourceKind> = DEFAULTS_REL.layer_kind();
        assert_eq!(NONE_LK, None);
        assert_eq!(FILE_BY_SOURCE_LK, Some(ConfigSourceKind::File));
        assert_eq!(FILE_BY_METADATA_NAME_LK, Some(ConfigSourceKind::File));
        assert_eq!(ENV_BY_PREFIX_LK, Some(ConfigSourceKind::Env));
        assert_eq!(ENV_BY_UNIQUENESS_LK, Some(ConfigSourceKind::Env));
        assert_eq!(DEFAULTS_LK, Some(ConfigSourceKind::Defaults));

        // ---- metadata_axis (Some-iff-attribution, total on Some arm) ----
        const NONE_MA: Option<AttributionAxis> = NONE_REL.metadata_axis();
        const FILE_BY_SOURCE_MA: Option<AttributionAxis> = FILE_BY_SOURCE_REL.metadata_axis();
        const FILE_BY_METADATA_NAME_MA: Option<AttributionAxis> =
            FILE_BY_METADATA_NAME_REL.metadata_axis();
        const ENV_BY_PREFIX_MA: Option<AttributionAxis> = ENV_BY_PREFIX_REL.metadata_axis();
        const ENV_BY_UNIQUENESS_MA: Option<AttributionAxis> = ENV_BY_UNIQUENESS_REL.metadata_axis();
        const DEFAULTS_MA: Option<AttributionAxis> = DEFAULTS_REL.metadata_axis();
        assert_eq!(NONE_MA, None);
        assert_eq!(FILE_BY_SOURCE_MA, Some(AttributionAxis::MetadataSource));
        assert_eq!(
            FILE_BY_METADATA_NAME_MA,
            Some(AttributionAxis::MetadataName)
        );
        assert_eq!(ENV_BY_PREFIX_MA, Some(AttributionAxis::MetadataName));
        assert_eq!(ENV_BY_UNIQUENESS_MA, Some(AttributionAxis::MetadataName));
        assert_eq!(DEFAULTS_MA, Some(AttributionAxis::MetadataSource));

        // ---- figment_source_kind (partial: source-axis rules only) ----
        const NONE_FSK: Option<FigmentSourceKind> = NONE_REL.figment_source_kind();
        const FILE_BY_SOURCE_FSK: Option<FigmentSourceKind> =
            FILE_BY_SOURCE_REL.figment_source_kind();
        const FILE_BY_METADATA_NAME_FSK: Option<FigmentSourceKind> =
            FILE_BY_METADATA_NAME_REL.figment_source_kind();
        const ENV_BY_PREFIX_FSK: Option<FigmentSourceKind> =
            ENV_BY_PREFIX_REL.figment_source_kind();
        const ENV_BY_UNIQUENESS_FSK: Option<FigmentSourceKind> =
            ENV_BY_UNIQUENESS_REL.figment_source_kind();
        const DEFAULTS_FSK: Option<FigmentSourceKind> = DEFAULTS_REL.figment_source_kind();
        assert_eq!(NONE_FSK, None);
        assert_eq!(FILE_BY_SOURCE_FSK, Some(FigmentSourceKind::File));
        assert_eq!(FILE_BY_METADATA_NAME_FSK, None);
        assert_eq!(ENV_BY_PREFIX_FSK, None);
        assert_eq!(ENV_BY_UNIQUENESS_FSK, None);
        assert_eq!(DEFAULTS_FSK, Some(FigmentSourceKind::Code));

        // ---- figment_name_tag_kind (partial: name-axis rules only) ----
        const NONE_FNK: Option<FigmentNameTagKind> = NONE_REL.figment_name_tag_kind();
        const FILE_BY_SOURCE_FNK: Option<FigmentNameTagKind> =
            FILE_BY_SOURCE_REL.figment_name_tag_kind();
        const FILE_BY_METADATA_NAME_FNK: Option<FigmentNameTagKind> =
            FILE_BY_METADATA_NAME_REL.figment_name_tag_kind();
        const ENV_BY_PREFIX_FNK: Option<FigmentNameTagKind> =
            ENV_BY_PREFIX_REL.figment_name_tag_kind();
        const ENV_BY_UNIQUENESS_FNK: Option<FigmentNameTagKind> =
            ENV_BY_UNIQUENESS_REL.figment_name_tag_kind();
        const DEFAULTS_FNK: Option<FigmentNameTagKind> = DEFAULTS_REL.figment_name_tag_kind();
        assert_eq!(NONE_FNK, None);
        assert_eq!(FILE_BY_SOURCE_FNK, None);
        assert_eq!(FILE_BY_METADATA_NAME_FNK, Some(FigmentNameTagKind::Format));
        assert_eq!(ENV_BY_PREFIX_FNK, Some(FigmentNameTagKind::Env));
        assert_eq!(ENV_BY_UNIQUENESS_FNK, Some(FigmentNameTagKind::Env));
        assert_eq!(DEFAULTS_FNK, None);

        // ---- Cross-check parity: const-fn body == runtime call ==
        //      underlying rule-altitude const-fn primitive.
        // Walk the five AttributionRule variants once, comparing each
        // envelope-altitude projection against the same rule's own
        // const-callable projection.
        assert_eq!(NONE_LK, NONE_REL.layer_kind());
        assert_eq!(NONE_MA, NONE_REL.metadata_axis());
        assert_eq!(NONE_FSK, NONE_REL.figment_source_kind());
        assert_eq!(NONE_FNK, NONE_REL.figment_name_tag_kind());
        for (rel, rule) in [
            (&FILE_BY_SOURCE_REL, AttributionRule::FileBySource),
            (
                &FILE_BY_METADATA_NAME_REL,
                AttributionRule::FileByMetadataName,
            ),
            (&ENV_BY_PREFIX_REL, AttributionRule::EnvByPrefix),
            (&ENV_BY_UNIQUENESS_REL, AttributionRule::EnvByUniqueness),
            (&DEFAULTS_REL, AttributionRule::DefaultsByCodeUniqueness),
        ] {
            assert_eq!(rel.layer_kind(), Some(rule.layer_kind()));
            assert_eq!(rel.metadata_axis(), Some(rule.metadata_axis()));
            assert_eq!(rel.figment_source_kind(), rule.figment_source_kind());
            assert_eq!(rel.figment_name_tag_kind(), rule.figment_name_tag_kind());
        }
    }

    #[test]
    fn reload_failure_some_iff_attribution_forwarder_last_quartet_is_const_callable() {
        // Weld the const-callability of the last remaining four
        // Some-iff-attribution forwarders on `impl ReloadFailure` in
        // one consolidated step, closing the envelope-altitude
        // cascade opened by
        // `reload_failure_some_iff_attribution_forwarder_quartet_is_const_callable`:
        //   * `Self::file_provenance`
        //     (partial: file-axis rules only) — non-const
        //     `Option::<AttributionRule>::and_then(AttributionRule::file_provenance)`
        //     rewritten to a `match` whose
        //     `Some(rule) => rule.file_provenance()` arm composes an
        //     already-`Option`-returning const-fn primitive; peer to
        //     `FailingSourceAttribution::file_provenance` (const since
        //     `00daccd`).
        //   * `Self::attribution_source_kind_coordinates`
        //     (partial: source-axis rules only) — parallel `.and_then(_)`
        //     rewrite on the (figment-Source-axis kind × shikumi-
        //     layer-kind) joint-cell surface; peer to
        //     `FailingSourceAttribution::attribution_source_kind_coordinates`
        //     (const since `d24ec4a`).
        //   * `Self::attribution_name_kind_coordinates`
        //     (partial: name-axis rules only) — parallel `.and_then(_)`
        //     rewrite on the (figment-`Metadata::name`-axis kind ×
        //     shikumi-layer-kind) joint-cell surface, closing the
        //     source-axis / name-axis parity on the joint-cell surface;
        //     peer to
        //     `FailingSourceAttribution::attribution_name_kind_coordinates`
        //     (const since `0b7e71d`).
        //   * `Self::coordinates`
        //     (Some-iff-attribution, total on Some arm) — non-const
        //     `Option::<AttributionRule>::map(AttributionRule::coordinates)`
        //     rewritten to the same `match self.attribution_rule`
        //     shape as `Self::attribution_confidence` (`6d160c8`); peer
        //     to `FailingSourceAttribution::coordinates` (const since
        //     `02c5653`).
        //
        // With these four lifted, every envelope-altitude
        // Some-iff-attribution forwarder on `impl ReloadFailure` is
        // const-callable — the cross-thread observable envelope now
        // occupies the same const altitude as the borrowed
        // `FailingSourceAttribution` envelope on every one of its
        // sibling projections
        // (`fc9e0c6` / `37b71fb` / `b11bca7` / `a4692bc` / `00daccd`
        // / `d24ec4a` / `0b7e71d` / `02c5653`).
        //
        // Weld structure: reuse the same six `static ReloadFailure`
        // bindings the prior quartet used (one None-arm plus one per
        // `AttributionRule` variant). The `static` (rather than
        // `const`) receiver is load-bearing for the same E0493 reason
        // as `reload_failure_attribution_confidence_is_const_callable`:
        // `ReloadFailure` carries `Drop`-bearing payloads.
        static NONE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static FILE_BY_SOURCE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileBySource),
        };
        static FILE_BY_METADATA_NAME_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::FileByMetadataName),
        };
        static ENV_BY_PREFIX_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByPrefix),
        };
        static ENV_BY_UNIQUENESS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::EnvByUniqueness),
        };
        static DEFAULTS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };

        // ---- file_provenance (partial: file-axis rules only) ----
        const NONE_FP: Option<crate::FormatProvenance> = NONE_REL.file_provenance();
        const FILE_BY_SOURCE_FP: Option<crate::FormatProvenance> =
            FILE_BY_SOURCE_REL.file_provenance();
        const FILE_BY_METADATA_NAME_FP: Option<crate::FormatProvenance> =
            FILE_BY_METADATA_NAME_REL.file_provenance();
        const ENV_BY_PREFIX_FP: Option<crate::FormatProvenance> =
            ENV_BY_PREFIX_REL.file_provenance();
        const ENV_BY_UNIQUENESS_FP: Option<crate::FormatProvenance> =
            ENV_BY_UNIQUENESS_REL.file_provenance();
        const DEFAULTS_FP: Option<crate::FormatProvenance> = DEFAULTS_REL.file_provenance();
        assert_eq!(NONE_FP, None);
        assert_eq!(
            FILE_BY_SOURCE_FP,
            Some(crate::FormatProvenance::FigmentBuiltin)
        );
        assert_eq!(
            FILE_BY_METADATA_NAME_FP,
            Some(crate::FormatProvenance::ShikumiBuilt)
        );
        assert_eq!(ENV_BY_PREFIX_FP, None);
        assert_eq!(ENV_BY_UNIQUENESS_FP, None);
        assert_eq!(DEFAULTS_FP, None);

        // ---- attribution_source_kind_coordinates (partial: source-axis rules only) ----
        const NONE_ASKC: Option<AttributionSourceKindCoordinates> =
            NONE_REL.attribution_source_kind_coordinates();
        const FILE_BY_SOURCE_ASKC: Option<AttributionSourceKindCoordinates> =
            FILE_BY_SOURCE_REL.attribution_source_kind_coordinates();
        const FILE_BY_METADATA_NAME_ASKC: Option<AttributionSourceKindCoordinates> =
            FILE_BY_METADATA_NAME_REL.attribution_source_kind_coordinates();
        const ENV_BY_PREFIX_ASKC: Option<AttributionSourceKindCoordinates> =
            ENV_BY_PREFIX_REL.attribution_source_kind_coordinates();
        const ENV_BY_UNIQUENESS_ASKC: Option<AttributionSourceKindCoordinates> =
            ENV_BY_UNIQUENESS_REL.attribution_source_kind_coordinates();
        const DEFAULTS_ASKC: Option<AttributionSourceKindCoordinates> =
            DEFAULTS_REL.attribution_source_kind_coordinates();
        assert_eq!(NONE_ASKC, None);
        assert_eq!(
            FILE_BY_SOURCE_ASKC,
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::File,
                layer_kind: ConfigSourceKind::File,
            })
        );
        assert_eq!(FILE_BY_METADATA_NAME_ASKC, None);
        assert_eq!(ENV_BY_PREFIX_ASKC, None);
        assert_eq!(ENV_BY_UNIQUENESS_ASKC, None);
        assert_eq!(
            DEFAULTS_ASKC,
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::Code,
                layer_kind: ConfigSourceKind::Defaults,
            })
        );

        // ---- attribution_name_kind_coordinates (partial: name-axis rules only) ----
        const NONE_ANKC: Option<AttributionNameKindCoordinates> =
            NONE_REL.attribution_name_kind_coordinates();
        const FILE_BY_SOURCE_ANKC: Option<AttributionNameKindCoordinates> =
            FILE_BY_SOURCE_REL.attribution_name_kind_coordinates();
        const FILE_BY_METADATA_NAME_ANKC: Option<AttributionNameKindCoordinates> =
            FILE_BY_METADATA_NAME_REL.attribution_name_kind_coordinates();
        const ENV_BY_PREFIX_ANKC: Option<AttributionNameKindCoordinates> =
            ENV_BY_PREFIX_REL.attribution_name_kind_coordinates();
        const ENV_BY_UNIQUENESS_ANKC: Option<AttributionNameKindCoordinates> =
            ENV_BY_UNIQUENESS_REL.attribution_name_kind_coordinates();
        const DEFAULTS_ANKC: Option<AttributionNameKindCoordinates> =
            DEFAULTS_REL.attribution_name_kind_coordinates();
        assert_eq!(NONE_ANKC, None);
        assert_eq!(FILE_BY_SOURCE_ANKC, None);
        assert_eq!(
            FILE_BY_METADATA_NAME_ANKC,
            Some(AttributionNameKindCoordinates {
                figment_name_tag_kind: FigmentNameTagKind::Format,
                layer_kind: ConfigSourceKind::File,
            })
        );
        assert_eq!(
            ENV_BY_PREFIX_ANKC,
            Some(AttributionNameKindCoordinates {
                figment_name_tag_kind: FigmentNameTagKind::Env,
                layer_kind: ConfigSourceKind::Env,
            })
        );
        assert_eq!(
            ENV_BY_UNIQUENESS_ANKC,
            Some(AttributionNameKindCoordinates {
                figment_name_tag_kind: FigmentNameTagKind::Env,
                layer_kind: ConfigSourceKind::Env,
            })
        );
        assert_eq!(DEFAULTS_ANKC, None);

        // ---- coordinates (Some-iff-attribution, total on Some arm) ----
        const NONE_CO: Option<AttributionCoordinates> = NONE_REL.coordinates();
        const FILE_BY_SOURCE_CO: Option<AttributionCoordinates> = FILE_BY_SOURCE_REL.coordinates();
        const FILE_BY_METADATA_NAME_CO: Option<AttributionCoordinates> =
            FILE_BY_METADATA_NAME_REL.coordinates();
        const ENV_BY_PREFIX_CO: Option<AttributionCoordinates> = ENV_BY_PREFIX_REL.coordinates();
        const ENV_BY_UNIQUENESS_CO: Option<AttributionCoordinates> =
            ENV_BY_UNIQUENESS_REL.coordinates();
        const DEFAULTS_CO: Option<AttributionCoordinates> = DEFAULTS_REL.coordinates();
        assert_eq!(NONE_CO, None);
        assert_eq!(
            FILE_BY_SOURCE_CO,
            Some(AttributionRule::FileBySource.coordinates())
        );
        assert_eq!(
            FILE_BY_METADATA_NAME_CO,
            Some(AttributionRule::FileByMetadataName.coordinates())
        );
        assert_eq!(
            ENV_BY_PREFIX_CO,
            Some(AttributionRule::EnvByPrefix.coordinates())
        );
        assert_eq!(
            ENV_BY_UNIQUENESS_CO,
            Some(AttributionRule::EnvByUniqueness.coordinates())
        );
        assert_eq!(
            DEFAULTS_CO,
            Some(AttributionRule::DefaultsByCodeUniqueness.coordinates())
        );

        // ---- Cross-check parity: const-fn body == runtime call ==
        //      underlying rule-altitude const-fn primitive.
        // Walk the five AttributionRule variants once, comparing each
        // envelope-altitude projection against the same rule's own
        // const-callable projection.
        assert_eq!(NONE_FP, NONE_REL.file_provenance());
        assert_eq!(NONE_ASKC, NONE_REL.attribution_source_kind_coordinates());
        assert_eq!(NONE_ANKC, NONE_REL.attribution_name_kind_coordinates());
        assert_eq!(NONE_CO, NONE_REL.coordinates());
        for (rel, rule) in [
            (&FILE_BY_SOURCE_REL, AttributionRule::FileBySource),
            (
                &FILE_BY_METADATA_NAME_REL,
                AttributionRule::FileByMetadataName,
            ),
            (&ENV_BY_PREFIX_REL, AttributionRule::EnvByPrefix),
            (&ENV_BY_UNIQUENESS_REL, AttributionRule::EnvByUniqueness),
            (&DEFAULTS_REL, AttributionRule::DefaultsByCodeUniqueness),
        ] {
            assert_eq!(rel.file_provenance(), rule.file_provenance());
            assert_eq!(
                rel.attribution_source_kind_coordinates(),
                rule.attribution_source_kind_coordinates()
            );
            assert_eq!(
                rel.attribution_name_kind_coordinates(),
                rule.attribution_name_kind_coordinates()
            );
            assert_eq!(rel.coordinates(), Some(rule.coordinates()));
        }
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
            crate::error::synthetic_parse_error(),
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
    fn reload_failure_field_path_localization_is_const_callable() {
        // Weld the const-callability of `ReloadFailure::field_path_localization`
        // — the tri-state closed-enum classification over the
        // (kind × field_path.is_empty()) pair at the cross-thread
        // observable envelope altitude — at compile time. Sits on
        // `impl ReloadFailure` alongside `Self::kind`
        // (kind axis, const since `9bc4eb7`) and the four Some-iff-
        // attribution forwarders (rule / layer_kind / metadata_axis /
        // confidence, const-lifted through the `d29a3f9` and
        // `57bb750` quartet welds); this lift extends the const-
        // callability envelope on the same `impl` block from the
        // `Copy`-field-only projections onto the ONE projection that
        // reaches for a `Vec::is_empty` probe on `Self::field_path`.
        //
        // The `Vec::is_empty` primitive stabilized as `const fn` in
        // Rust 1.87 (below this crate's 1.89 MSRV per Cargo.toml),
        // so the body — a nested `if` over `kind.is_figment_bearing()`
        // (const since `4b00851` on the underlying `ShikumiErrorKind`
        // partition) and `field_path.is_empty()` — is const-eligible
        // on every path. Distinct from every prior envelope-altitude
        // const-lift, which touched only `Copy` scalar fields
        // (`self.kind`, `self.attribution_rule`, `self.failing_source`):
        // this is the first envelope-altitude projection that probes
        // a `Vec` field through a const-fn primitive.
        //
        // Two of the three `FieldPathLocalization` variants are
        // reachable at const-eval time: `NotApplicable` (a non-
        // figment-bearing kind — `NotFound` / `Validation`) and
        // `FigmentUnlocalized` (the sole figment-bearing kind `Extract`
        // with an empty `Vec<String>` field_path, since `String::new()`
        // stays const-constructible but a non-empty `Vec<String>` does
        // not — no const `String` payloads). The third variant,
        // `Localized`, is reached only at runtime through a real
        // figment extraction failure — pinned by the sibling test
        // `field_path_localization_localized_for_real_yaml_extract`;
        // welding the const-callability of the projection function
        // covers all three branches under the const-fn body identity.
        //
        // The `static` rather than `const` receiver is load-bearing
        // for the same E0493 reason as the sibling
        // `reload_failure_kind_is_const_callable` weld:
        // `ReloadFailure` carries `Drop`-bearing payloads (`String`,
        // `Vec<ConfigSource>`, `Vec<String>`, `Option<ConfigSource>`),
        // so a `const REL: ReloadFailure = ...; const LOC =
        // REL.field_path_localization();` spelling drops the const
        // value after the localization projection and rejects. A
        // `static REL: ReloadFailure` is never dropped, so borrowing
        // `&REL` for the `&self` receiver in a `const` initializer
        // stays inside the const-eval envelope.
        static NOT_FOUND_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::NotFound,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static EXTRACT_EMPTY_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static VALIDATION_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Validation,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        const NOT_FOUND_LOC: FieldPathLocalization = NOT_FOUND_REL.field_path_localization();
        const EXTRACT_EMPTY_LOC: FieldPathLocalization =
            EXTRACT_EMPTY_REL.field_path_localization();
        const VALIDATION_LOC: FieldPathLocalization = VALIDATION_REL.field_path_localization();

        assert_eq!(NOT_FOUND_LOC, FieldPathLocalization::NotApplicable);
        assert_eq!(EXTRACT_EMPTY_LOC, FieldPathLocalization::FigmentUnlocalized);
        assert_eq!(VALIDATION_LOC, FieldPathLocalization::NotApplicable);

        // Cross-check: the const-fn projection stays pointwise agreed
        // with the runtime-side `rel.field_path_localization()` call
        // over the three const-welded arms. Redundant with the
        // pointwise pin
        // `field_path_localization_agrees_with_underlying_error_pointwise`
        // (which welds the const-fn projection against the underlying
        // `ShikumiError::field_path_localization`), but this pin
        // catches a future edit that shifted the const-fn body away
        // from the runtime-fn body on any of the three welded arms.
        assert_eq!(NOT_FOUND_LOC, NOT_FOUND_REL.field_path_localization());
        assert_eq!(
            EXTRACT_EMPTY_LOC,
            EXTRACT_EMPTY_REL.field_path_localization()
        );
        assert_eq!(VALIDATION_LOC, VALIDATION_REL.field_path_localization());
    }

    #[test]
    fn field_path_dotted_agrees_with_underlying_error_pointwise() {
        // Lossless-capture contract for the dotted rendering: the
        // captured envelope's dotted field path equals the source
        // error's, modulo the documented None -> "" collapse the
        // Vec<String> representation imposes. Both sides route through
        // the same `dotted_field_path` join, so they cannot drift.
        for (err, _) in one_per_kind() {
            let f = ReloadFailure::from_error(&err);
            assert_eq!(
                f.field_path_dotted(),
                err.field_path_dotted().unwrap_or_default(),
                "captured dotted path must mirror source for {err:?}"
            );
        }
    }

    #[test]
    fn field_path_dotted_renders_nested_localized_capture() {
        // A real nested-key extraction failure captures into a dotted
        // observable an operator can read directly off
        // last_reload_error, without re-joining field_path.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Inner {
            #[allow(dead_code)]
            padding: u32,
        }
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            options: Inner,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_dotted_nested.yaml");
        std::fs::write(&file, "options:\n  padding: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.field_path_dotted(), "options.padding");
        assert_eq!(f.field_path_dotted(), err.field_path_dotted().unwrap());
    }

    #[test]
    fn field_path_dotted_empty_for_non_figment_capture() {
        let err = crate::error::synthetic_parse_error();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.field_path_dotted(), "");
        assert!(err.field_path_dotted().is_none());
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            let f = synthetic_failure_with_rule(rule);
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
            let f = synthetic_failure_with_rule(rule);
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
            let f = synthetic_failure_with_rule(rule);
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            let f = synthetic_failure_with_rule(rule);
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
            let f = synthetic_failure_with_rule(rule);
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
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
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
            let f = synthetic_failure_with_rule(rule);
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

    // ---- figment_name_tag_kind accessor tests ----
    //
    // The symmetric peer of the figment_source_kind suite on the
    // cross-thread observable form. Together the two accessors close
    // the figment-metadata kind universe on `ReloadFailure`: every
    // attributed envelope surfaces exactly one figment-metadata-kind
    // cell (Some on either source-axis or name-axis); unattributed
    // envelopes surface None on both.

    /// Build a synthetic Extract-shaped `ReloadFailure` populated with an
    /// arbitrary failing source layer and its matching attribution rule.
    ///
    /// One source of truth for the "synthetic attribution-populated
    /// envelope" construction the tests module previously open-coded at
    /// three distinct shapes: the majority `synthetic_failure_with_rule`
    /// suite (which fixes the failing source at `Defaults` and now
    /// delegates here), the file-provenance concrete-pin loop over
    /// `Some(ConfigSource::File(_))` sources, and the
    /// `attribution_name_kind_coordinates` clone-survival pin over
    /// `Some(ConfigSource::Env(_))` sources. Every synthetic Extract
    /// envelope carrying a populated `(failing_source, attribution_rule)`
    /// diagonal cell now routes through here; a future `ReloadFailure`
    /// field addition (the struct is `#[non_exhaustive]` exactly for this)
    /// lands at ONE named site and every call site inherits the new
    /// field by construction rather than failing to compile at each
    /// hand-typed struct literal apart. Idiom-peer of
    /// `synthetic_failure_with_rule` on the fixed-Defaults side of the
    /// same drift-class partition.
    fn synthetic_failure_with_source_and_rule(
        source: ConfigSource,
        rule: AttributionRule,
    ) -> ReloadFailure {
        ReloadFailure {
            message: crate::source::SYNTHETIC_TEST_MESSAGE.to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![],
            field_path: vec![],
            failing_source: Some(source),
            attribution_rule: Some(rule),
        }
    }

    fn synthetic_failure_with_rule(rule: AttributionRule) -> ReloadFailure {
        synthetic_failure_with_source_and_rule(ConfigSource::Defaults, rule)
    }

    #[test]
    fn figment_name_tag_kind_some_for_file_by_metadata_name_rule() {
        // FileByMetadataName fires when the resolver matched the
        // shikumi-built provider's "<format>: <path>" name-axis shape;
        // the rule's identity already pins FigmentNameTagKind::Format.
        let f = synthetic_failure_with_rule(AttributionRule::FileByMetadataName);
        assert_eq!(f.figment_name_tag_kind(), Some(FigmentNameTagKind::Format),);
    }

    #[test]
    fn figment_name_tag_kind_some_for_env_by_prefix_rule() {
        // EnvByPrefix fires when figment's "`PREFIX` environment
        // variable(s)" name-axis shape matched a chain env layer's
        // prefix; the rule's identity already pins FigmentNameTagKind::Env.
        let f = synthetic_failure_with_rule(AttributionRule::EnvByPrefix);
        assert_eq!(f.figment_name_tag_kind(), Some(FigmentNameTagKind::Env));
    }

    #[test]
    fn figment_name_tag_kind_some_for_env_by_uniqueness_rule() {
        // EnvByUniqueness fires on an env-shaped name (prefixed without
        // chain match, or bare) when the chain holds a unique Env layer;
        // the rule's identity pins FigmentNameTagKind::Env.
        let f = synthetic_failure_with_rule(AttributionRule::EnvByUniqueness);
        assert_eq!(f.figment_name_tag_kind(), Some(FigmentNameTagKind::Env));
    }

    #[test]
    fn figment_name_tag_kind_none_for_unattributed_extract() {
        // No metadata to map → no rule → no figment_name_tag_kind.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_rule.is_none());
        assert!(f.figment_name_tag_kind().is_none());
    }

    #[test]
    fn figment_name_tag_kind_none_for_non_extract_variants() {
        // Non-figment-bearing variants and bare Figment never carry
        // attribution → never carry a figment_name_tag_kind.
        for f in [
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert!(f.figment_name_tag_kind().is_none());
        }
    }

    #[test]
    fn figment_name_tag_kind_none_for_source_axis_attribution() {
        // Source-axis attributions (FileBySource, DefaultsByCodeUniqueness)
        // carry an attribution_rule but their identity does not pin a
        // figment-name-axis cell — the accessor returns None even when
        // the rule slot is Some. The dual of
        // `figment_source_kind_none_for_name_axis_attribution`.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = synthetic_failure_with_rule(rule);
            assert!(f.attribution_rule.is_some(), "rule {rule:?}");
            assert!(
                f.figment_name_tag_kind().is_none(),
                "rule {rule:?}: source-axis attribution must yield None figment_name_tag_kind",
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_agrees_with_rule_figment_name_tag_kind_pointwise() {
        // For every constructible rule scenario, the cross-thread
        // accessor result equals
        // attribution_rule.and_then(AttributionRule::figment_name_tag_kind)
        // — pinning the convenience accessor as a pure projection. Peer
        // to `figment_source_kind_agrees_with_rule_figment_source_kind_pointwise`
        // on the name-axis.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            assert_eq!(f.figment_name_tag_kind(), rule.figment_name_tag_kind());
        }
    }

    #[test]
    fn figment_name_tag_kind_some_iff_metadata_axis_metadata_name() {
        // Composition law on the cross-thread envelope: when an
        // attribution is recorded, figment_name_tag_kind is Some
        // exactly when metadata_axis is Some(MetadataName). When no
        // attribution is recorded, both are None and the biconditional
        // still holds vacuously. Pins the same refinement as the
        // AttributionRule-side law, surfaced through the captured
        // envelope. Dual of
        // `figment_source_kind_some_iff_metadata_axis_metadata_source`.
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            assert_eq!(
                f.figment_name_tag_kind().is_some(),
                f.metadata_axis() == Some(AttributionAxis::MetadataName),
                "envelope {:?}: figment_name_tag_kind.is_some() must equal \
                 (metadata_axis == Some(MetadataName))",
                f.attribution_rule,
            );
        }
    }

    #[test]
    fn figment_name_tag_kind_xor_figment_source_kind_on_attributed_envelopes() {
        // Cross-axis partition law on the cross-thread envelope: every
        // attributed failure carries exactly one of figment_source_kind
        // / figment_name_tag_kind as Some (rule identity dispatches on
        // exactly one figment-metadata axis); unattributed failures
        // carry both as None. Closes the figment-metadata kind universe
        // on the ReloadFailure surface — the same partition the
        // AttributionRule side pins via
        // `attribution_rule_figment_name_tag_kind_xor_figment_source_kind`,
        // surfaced through the captured envelope.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            let src_some = f.figment_source_kind().is_some();
            let name_some = f.figment_name_tag_kind().is_some();
            assert!(
                src_some ^ name_some,
                "attributed envelope for rule {rule:?}: exactly one of \
                 figment_source_kind / figment_name_tag_kind must be Some \
                 (got src_some={src_some}, name_some={name_some})",
            );
        }
        // Unattributed envelope: both halves None.
        let f = ReloadFailure::from_error(&crate::error::synthetic_parse_error());
        assert!(f.figment_source_kind().is_none());
        assert!(f.figment_name_tag_kind().is_none());
    }

    #[test]
    fn figment_name_tag_kind_agrees_with_underlying_error_pointwise() {
        // End-to-end lossless-capture: a real Extract error attributing
        // via EnvByPrefix (synthesized through
        // `synthetic_error_with_metadata_name`) produces a captured
        // envelope whose figment_name_tag_kind projection equals the
        // underlying error's failing_attribution()'s
        // figment_name_tag_kind. Peer to
        // `file_provenance_agrees_with_underlying_error_pointwise` on the
        // file-provenance axis, but pinning the agreement law across the
        // error → envelope boundary on the figment-name-tag-kind axis.
        // Uses a synthetic env-prefixed metadata name (the same shape
        // shikumi's tests for EnvByPrefix use in error::tests) so the
        // resolver attributes via EnvByPrefix without needing a live
        // figment::providers::Env in the test process.
        let err = ShikumiError::Extract {
            sources: vec![
                ConfigSource::Defaults,
                ConfigSource::Env("MAXIS_".to_owned()),
            ],
            error: crate::source::synthetic_env_metadata_error("MAXIS_"),
        };
        let f = ReloadFailure::from_error(&err);
        let underlying = err
            .failing_attribution()
            .and_then(FailingSourceAttribution::figment_name_tag_kind);
        assert_eq!(f.figment_name_tag_kind(), underlying);
        assert_eq!(
            f.figment_name_tag_kind(),
            Some(FigmentNameTagKind::Env),
            "env-prefixed extract attributes via EnvByPrefix → FigmentNameTagKind::Env",
        );
    }

    #[test]
    fn figment_name_tag_kind_survives_clone_independent_of_originating_error() {
        // The captured figment_name_tag_kind is derived from the
        // captured rule (Copy) — it must survive cloning and outlive
        // the originating ShikumiError, parallel to the
        // figment_source_kind / metadata_axis / layer_kind clone-survival
        // invariants already pinned on the cross-thread envelope.
        let f = {
            let err = ShikumiError::Extract {
                sources: vec![
                    ConfigSource::Defaults,
                    ConfigSource::Env("CLONED_".to_owned()),
                ],
                error: crate::source::synthetic_env_metadata_error("CLONED_"),
            };
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(g.figment_name_tag_kind(), Some(FigmentNameTagKind::Env));
        assert_eq!(g.figment_name_tag_kind(), f.figment_name_tag_kind());
    }

    #[test]
    fn file_provenance_agrees_with_rule_file_provenance_pointwise() {
        // For every constructible rule scenario, the cross-thread
        // accessor result equals
        // attribution_rule.and_then(AttributionRule::file_provenance) —
        // pinning the convenience accessor as a pure projection over
        // the captured rule slot. Peer to
        // `figment_source_kind_agrees_with_rule_figment_source_kind_pointwise`
        // on the file-provenance axis.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            assert_eq!(f.file_provenance(), rule.file_provenance());
        }
    }

    #[test]
    fn file_provenance_some_iff_layer_kind_file() {
        // Composition law on the cross-thread envelope: when an
        // attribution is recorded, file_provenance is Some exactly
        // when layer_kind is Some(File). When no attribution is
        // recorded, both are None and the biconditional still holds
        // vacuously. Pins the same refinement as the AttributionRule-
        // side `attribution_rule_file_provenance_some_iff_file_layer_kind`
        // biconditional, surfaced through the captured envelope.
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            assert_eq!(
                f.file_provenance().is_some(),
                f.layer_kind() == Some(ConfigSourceKind::File),
                "envelope {:?}: file_provenance.is_some() must equal \
                 (layer_kind == Some(File))",
                f.attribution_rule,
            );
        }
    }

    #[test]
    fn file_provenance_pins_each_file_rule_on_envelope() {
        // Concrete pin: the two file-axis rules map through the
        // envelope to the two recognized FormatProvenance cells in
        // lockstep with the rule-side projection. Peer to
        // `attribution_rule_file_provenance_pins_each_file_rule`
        // surfaced through the captured envelope.
        let cases = [
            (
                AttributionRule::FileBySource,
                crate::FormatProvenance::FigmentBuiltin,
            ),
            (
                AttributionRule::FileByMetadataName,
                crate::FormatProvenance::ShikumiBuilt,
            ),
        ];
        for (rule, provenance) in cases {
            let f = synthetic_failure_with_source_and_rule(
                ConfigSource::File(std::path::PathBuf::from("/etc/x")),
                rule,
            );
            assert_eq!(f.file_provenance(), Some(provenance), "rule {rule:?}");
        }
    }

    #[test]
    fn file_provenance_agrees_with_underlying_error_pointwise() {
        // End-to-end lossless-capture: a real Extract error attributing
        // via FileBySource produces a captured envelope whose
        // file_provenance projection equals the underlying error's
        // failing_attribution()'s file_provenance. Peer to
        // `figment_source_kind_survives_clone_independent_of_originating_error`
        // but pinning the agreement law across the error → envelope
        // boundary.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_fp_agreement.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        let underlying = err
            .failing_attribution()
            .and_then(FailingSourceAttribution::file_provenance);
        assert_eq!(f.file_provenance(), underlying);
        assert_eq!(
            f.file_provenance(),
            Some(crate::FormatProvenance::FigmentBuiltin),
            "YAML extract failure attributes via FileBySource → FigmentBuiltin",
        );
    }

    #[test]
    fn file_provenance_survives_clone_independent_of_originating_error() {
        // The captured file_provenance is derived from the captured
        // rule (Copy) — it must survive cloning and outlive the
        // originating ShikumiError, parallel to the
        // figment_source_kind / metadata_axis / layer_kind clone
        // invariants already pinned on the cross-thread envelope.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let f = {
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("rf_fp_clone.yaml");
            std::fs::write(&file, "count: not_a_number\n").unwrap();
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(
            g.file_provenance(),
            Some(crate::FormatProvenance::FigmentBuiltin),
        );
        assert_eq!(g.file_provenance(), f.file_provenance());
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            let f = synthetic_failure_with_rule(rule);
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
            let f = synthetic_failure_with_rule(rule);
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
            let f = synthetic_failure_with_rule(rule);
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
        let both = synthetic_failure_with_rule(AttributionRule::DefaultsByCodeUniqueness);
        assert!(both.failing_attribution().is_some());

        // Both None: envelope None.
        let neither = ReloadFailure {
            message: crate::source::SYNTHETIC_TEST_MESSAGE.to_owned(),
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
            message: crate::source::SYNTHETIC_TEST_MESSAGE.to_owned(),
            kind: ShikumiErrorKind::Extract,
            sources: vec![],
            field_path: vec![],
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: None,
        };
        assert!(only_source.failing_attribution().is_none());

        // Off-diagonal (only rule): envelope None.
        let only_rule = ReloadFailure {
            message: crate::source::SYNTHETIC_TEST_MESSAGE.to_owned(),
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
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
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
            crate::error::synthetic_parse_error(),
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
            let f = synthetic_failure_with_rule(rule);
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
        let f_parse = ReloadFailure::from_error(&crate::error::synthetic_parse_error());

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

    #[test]
    fn reload_failure_error_localization_coordinates_is_const_callable() {
        // Weld the const-callability of
        // `ReloadFailure::error_localization_coordinates` — the
        // envelope-altitude composition of the two const-fn sub-
        // projections (`Self::kind` / `Self::field_path_localization`)
        // into an `ErrorLocalizationCoordinates { kind, localization }`
        // struct literal — at compile time. Sits on `impl
        // ReloadFailure` alongside the two sub-projections it fuses
        // (both const since `9bc4eb7` and `64de910` respectively);
        // this lift closes the composition gap the `64de910` commit
        // body called out as the immediate next hop: with both
        // sub-projections const, only the struct-literal spelling
        // stayed runtime, and this weld pins the composition itself
        // as const-eligible.
        //
        // The struct literal is const-eligible because both named
        // fields are `Copy` closed-enum types (`ShikumiErrorKind` /
        // `FieldPathLocalization`), no `Drop`-bearing payload is
        // constructed by the composition, and `#[non_exhaustive]` on
        // `ErrorLocalizationCoordinates` does not restrict struct
        // literals inside the defining crate. Two of the three
        // `FieldPathLocalization` variants are reachable at
        // const-eval time (matching the coverage envelope of the
        // sibling `reload_failure_field_path_localization_is_const_callable`
        // weld): `NotApplicable` (any non-figment-bearing kind —
        // `NotFound` / `Validation`) and `FigmentUnlocalized` (the
        // sole figment-bearing kind `Extract` with an empty
        // `Vec<String>` field_path, since no const `String` payload
        // constructor exists). The `Localized` variant is reached
        // only at runtime through a real figment extraction failure,
        // covered by the sibling
        // `error_localization_coordinates_agrees_with_underlying_error_pointwise`
        // pin; welding the const-callability of the composition
        // covers the full envelope under the const-fn body identity.
        //
        // The `static` rather than `const` receiver is load-bearing
        // for the same E0493 reason as the sibling
        // `reload_failure_field_path_localization_is_const_callable`
        // weld: `ReloadFailure` carries `Drop`-bearing payloads
        // (`String`, `Vec<ConfigSource>`, `Vec<String>`,
        // `Option<ConfigSource>`), so a `const REL: ReloadFailure =
        // ...; const CELL = REL.error_localization_coordinates();`
        // spelling drops the const value after the composition and
        // rejects. A `static REL: ReloadFailure` is never dropped,
        // so borrowing `&REL` for the `&self` receiver in a `const`
        // initializer stays inside the const-eval envelope.
        static NOT_FOUND_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::NotFound,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static EXTRACT_EMPTY_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static VALIDATION_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Validation,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        const NOT_FOUND_CELL: ErrorLocalizationCoordinates =
            NOT_FOUND_REL.error_localization_coordinates();
        const EXTRACT_EMPTY_CELL: ErrorLocalizationCoordinates =
            EXTRACT_EMPTY_REL.error_localization_coordinates();
        const VALIDATION_CELL: ErrorLocalizationCoordinates =
            VALIDATION_REL.error_localization_coordinates();

        assert_eq!(
            NOT_FOUND_CELL,
            ErrorLocalizationCoordinates {
                kind: ShikumiErrorKind::NotFound,
                localization: FieldPathLocalization::NotApplicable,
            }
        );
        assert_eq!(
            EXTRACT_EMPTY_CELL,
            ErrorLocalizationCoordinates {
                kind: ShikumiErrorKind::Extract,
                localization: FieldPathLocalization::FigmentUnlocalized,
            }
        );
        assert_eq!(
            VALIDATION_CELL,
            ErrorLocalizationCoordinates {
                kind: ShikumiErrorKind::Validation,
                localization: FieldPathLocalization::NotApplicable,
            }
        );

        // Cross-check: the const-fn composition stays pointwise
        // agreed with the runtime-side
        // `rel.error_localization_coordinates()` call over the three
        // const-welded arms. Redundant with the pointwise pin
        // `error_localization_coordinates_agrees_with_underlying_error_pointwise`
        // (which welds the composition against the underlying
        // `ShikumiError::error_localization_coordinates`), but this
        // pin catches a future edit that shifted the const-fn body
        // away from the runtime-fn body on any of the three welded
        // arms.
        assert_eq!(
            NOT_FOUND_CELL,
            NOT_FOUND_REL.error_localization_coordinates()
        );
        assert_eq!(
            EXTRACT_EMPTY_CELL,
            EXTRACT_EMPTY_REL.error_localization_coordinates()
        );
        assert_eq!(
            VALIDATION_CELL,
            VALIDATION_REL.error_localization_coordinates()
        );

        // Named-field agreement with the two sibling const-fn
        // sub-projections. Redundant with
        // `error_localization_coordinates_mirrors_sibling_accessors_on_capture`
        // on the runtime path; pins the same lossless-decomposition
        // contract at const-eval time so a future edit to the
        // struct-literal field ordering (kind ↔ localization) is
        // caught at compile-time by the pin rather than at runtime
        // by the sibling weld.
        assert_eq!(NOT_FOUND_CELL.kind, NOT_FOUND_REL.kind());
        assert_eq!(
            NOT_FOUND_CELL.localization,
            NOT_FOUND_REL.field_path_localization()
        );
        assert_eq!(EXTRACT_EMPTY_CELL.kind, EXTRACT_EMPTY_REL.kind());
        assert_eq!(
            EXTRACT_EMPTY_CELL.localization,
            EXTRACT_EMPTY_REL.field_path_localization()
        );
        assert_eq!(VALIDATION_CELL.kind, VALIDATION_REL.kind());
        assert_eq!(
            VALIDATION_CELL.localization,
            VALIDATION_REL.field_path_localization()
        );
    }

    #[test]
    fn reload_failure_failing_attribution_is_const_callable() {
        // Weld the const-callability of `ReloadFailure::failing_attribution`
        // — the FIRST envelope-altitude Some-iff-attribution
        // forwarder on the cross-thread observable envelope that
        // *constructs* (rather than projects out of) a borrowed
        // `FailingSourceAttribution`. Closes the last non-const
        // projection on `impl ReloadFailure`: every envelope-altitude
        // projection now evaluates at compile time.
        //
        // The lift required `FailingSourceAttribution::new` const
        // first (const since `3c99e09`, whose commit body named this
        // accessor as its immediate downstream compounding target).
        // The routed body rewrites the tuple-match spelling
        // `match (&self.failing_source, self.attribution_rule)` as a
        // nested match: mixed-by-ref/by-value tuple patterns lean on
        // tuple-construction reductions still unstable under rustc
        // 1.94.1, and the equivalent nested match composes
        // const-supported primitives (an outer field-borrow discriminant
        // read plus an inner `Copy` field load) with the const-fn
        // `FailingSourceAttribution::new` on the joint `Some`-arm.
        //
        // Weld structure: reuse the same static-binding shape the
        // sibling Some-iff-attribution welds use — one None-arm plus
        // one `Some`-attribution arm — with `failing_source` populated
        // to exercise the joint `(Some, Some)` case that the
        // sibling welds could not reach (they left `failing_source:
        // None` because their projections only read
        // `self.attribution_rule`). `ConfigSource::Defaults` is the
        // payload-free variant const-constructible in a `static`
        // binding; `ConfigSource::Env(String::new())` is the second
        // const-constructible variant (`String::new` is const since
        // Rust 1.39), pinning the envelope's carried-source lifetime
        // through a non-payload-free arm.
        //
        // The four scenarios cover the 2 × 2 = 4 legal product cells
        // of the (`failing_source.is_some()` ×
        // `attribution_rule.is_some()`) cube: the diagonal cells
        // (both Some → Some, both None → None) and the two off-
        // diagonal cells (only one Some → None). The off-diagonal
        // cells pin the structural `Some`-iff-both-populated
        // discipline at compile-eval time — a future edit that
        // reversed either match arm's polarity, dropped one of the
        // nested matches, or short-circuited on `attribution_rule`
        // alone (forgetting to check `failing_source`) fails to
        // compile at the pinned `const` binding value rather than
        // drifting through observers reading
        // `ConfigStore::last_reload_error`.
        //
        // The `static` (rather than `const`) receiver is load-bearing
        // for the same E0493 reason as
        // `reload_failure_attribution_confidence_is_const_callable`:
        // `ReloadFailure` carries `Drop`-bearing payloads (`String`,
        // `Vec<ConfigSource>`, `Vec<String>`, `Option<ConfigSource>`),
        // so a `const REL: ReloadFailure = ...` binding drops after
        // the projection and rejects.
        static BOTH_NONE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: None,
        };
        static ONLY_SOURCE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: None,
        };
        static ONLY_RULE_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: None,
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };
        static BOTH_DEFAULTS_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };
        static BOTH_ENV_REL: ReloadFailure = ReloadFailure {
            message: String::new(),
            kind: ShikumiErrorKind::Extract,
            sources: Vec::new(),
            field_path: Vec::new(),
            failing_source: Some(ConfigSource::Env(String::new())),
            attribution_rule: Some(AttributionRule::EnvByUniqueness),
        };

        const BOTH_NONE_ATTR: Option<FailingSourceAttribution<'static>> =
            BOTH_NONE_REL.failing_attribution();
        const ONLY_SOURCE_ATTR: Option<FailingSourceAttribution<'static>> =
            ONLY_SOURCE_REL.failing_attribution();
        const ONLY_RULE_ATTR: Option<FailingSourceAttribution<'static>> =
            ONLY_RULE_REL.failing_attribution();
        const BOTH_DEFAULTS_ATTR: Option<FailingSourceAttribution<'static>> =
            BOTH_DEFAULTS_REL.failing_attribution();
        const BOTH_ENV_ATTR: Option<FailingSourceAttribution<'static>> =
            BOTH_ENV_REL.failing_attribution();

        // Some-iff-both-populated discipline holds through the
        // const-fn body: only the diagonal `(Some, Some)` cells map
        // to Some(_); the two off-diagonal cells collapse to None
        // even though one half is populated.
        assert!(BOTH_NONE_ATTR.is_none());
        assert!(ONLY_SOURCE_ATTR.is_none());
        assert!(ONLY_RULE_ATTR.is_none());
        let both_defaults = BOTH_DEFAULTS_ATTR.expect("both halves populated => envelope some");
        assert!(matches!(both_defaults.source, ConfigSource::Defaults));
        assert_eq!(
            both_defaults.rule,
            AttributionRule::DefaultsByCodeUniqueness
        );
        let both_env = BOTH_ENV_ATTR.expect("both halves populated => envelope some");
        assert!(matches!(both_env.source, ConfigSource::Env(prefix) if prefix.is_empty()));
        assert_eq!(both_env.rule, AttributionRule::EnvByUniqueness);

        // Cross-check: the const-fn body stays pointwise agreed with
        // the runtime-side `rel.failing_attribution()` call over all
        // five welded arms. Redundant with
        // `failing_attribution_some_iff_both_halves_populated` and
        // `failing_attribution_agrees_with_underlying_error_pointwise`
        // on the runtime path, but this pin catches a future edit
        // that shifted the const-fn body away from the runtime-fn
        // body on any of the five welded arms.
        assert_eq!(BOTH_NONE_ATTR, BOTH_NONE_REL.failing_attribution());
        assert_eq!(ONLY_SOURCE_ATTR, ONLY_SOURCE_REL.failing_attribution());
        assert_eq!(ONLY_RULE_ATTR, ONLY_RULE_REL.failing_attribution());
        assert_eq!(BOTH_DEFAULTS_ATTR, BOTH_DEFAULTS_REL.failing_attribution());
        assert_eq!(BOTH_ENV_ATTR, BOTH_ENV_REL.failing_attribution());
    }

    // ---- attribution_source_kind_coordinates accessor tests ----

    #[test]
    fn attribution_source_kind_coordinates_some_for_real_yaml_extract() {
        // A real YAML-file extract failure attributes via FileBySource,
        // whose joint cell is (File, File) — the source-axis rule's
        // identity already pins both halves on the cross-thread
        // observable form.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("rf_askc.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.attribution_rule, Some(AttributionRule::FileBySource));
        assert_eq!(
            f.attribution_source_kind_coordinates(),
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::File,
                layer_kind: ConfigSourceKind::File,
            }),
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_some_for_defaults_only_extract() {
        // A defaults-only extract attributes via DefaultsByCodeUniqueness,
        // whose joint cell is (Code, Defaults). Pins the second
        // realizable cell on the cross-thread observable form.
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
        assert_eq!(
            f.attribution_source_kind_coordinates(),
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::Code,
                layer_kind: ConfigSourceKind::Defaults,
            }),
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_none_for_unattributed_extract() {
        // No metadata to map → no rule → no joint cell. Pins the
        // first stage of the two-stage None discipline on the
        // cross-thread envelope.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_rule.is_none());
        assert!(f.attribution_source_kind_coordinates().is_none());
    }

    #[test]
    fn attribution_source_kind_coordinates_none_for_non_extract_variants() {
        // Non-figment-bearing variants and bare Figment never carry
        // attribution → never carry a joint cell.
        for f in [
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert!(f.attribution_source_kind_coordinates().is_none());
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_none_for_name_axis_attribution() {
        // Name-axis attributions carry an attribution_rule but their
        // identity does not pin the joint cell — the accessor returns
        // None even when the rule slot is Some. Pins the second-stage
        // None arm of the two-stage discipline on the cross-thread
        // envelope, parallel to
        // `figment_source_kind_none_for_name_axis_attribution`.
        for rule in [
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
        ] {
            let f = synthetic_failure_with_rule(rule);
            assert!(f.attribution_rule.is_some(), "rule {rule:?}");
            assert!(
                f.attribution_source_kind_coordinates().is_none(),
                "rule {rule:?}: name-axis attribution must yield None joint cell",
            );
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_agrees_with_rule_pointwise() {
        // For every constructible rule scenario, the accessor result
        // equals
        // attribution_rule.and_then(AttributionRule::attribution_source_kind_coordinates)
        // — pinning the convenience accessor as a pure projection.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            assert_eq!(
                f.attribution_source_kind_coordinates(),
                rule.attribution_source_kind_coordinates(),
            );
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_returns_realizable_cell_when_some() {
        // Every Some return from the cross-thread accessor satisfies
        // AttributionSourceKindCoordinates::is_realizable — the
        // captured envelope's projection never produces an
        // unrealizable cell, no matter which rule was captured.
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            if let Some(cell) = f.attribution_source_kind_coordinates() {
                assert!(
                    cell.is_realizable(),
                    "envelope {:?}: joint cell {cell:?} must be realizable",
                    f.attribution_rule,
                );
            }
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_agrees_with_paired_projections_pointwise() {
        // Lossless-decomposition contract on the cross-thread
        // envelope: the joint cell's named fields agree byte-for-byte
        // with the paired
        // (figment_source_kind, layer_kind)
        // reads on the same envelope. Holds vacuously when the joint
        // cell is None (the paired projection is also None on its
        // figment_source_kind half).
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            let joint = f.attribution_source_kind_coordinates();
            let paired = f.figment_source_kind().map(|figment_source_kind| {
                AttributionSourceKindCoordinates {
                    figment_source_kind,
                    layer_kind: f.layer_kind().expect(
                        "figment_source_kind Some implies layer_kind Some on the cross-thread envelope",
                    ),
                }
            });
            assert_eq!(
                joint, paired,
                "envelope {:?}: joint cell must equal paired projections",
                f.attribution_rule,
            );
        }
    }

    #[test]
    fn attribution_source_kind_coordinates_survives_clone_independent_of_originating_error() {
        // The captured joint cell is derived from the captured rule
        // (Copy) — it must survive cloning and outlive the originating
        // ShikumiError, parallel to the figment_source_kind-clone,
        // metadata-axis-clone, and layer-kind-clone invariants
        // already pinned on the cross-thread envelope.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let f = {
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("rf_askc_clone.yaml");
            std::fs::write(&file, "count: not_a_number\n").unwrap();
            let err = ProviderChain::new()
                .with_file(&file)
                .extract::<Cfg>()
                .unwrap_err();
            ReloadFailure::from_error(&err)
        };
        let g = f.clone();
        assert_eq!(
            g.attribution_source_kind_coordinates(),
            Some(AttributionSourceKindCoordinates {
                figment_source_kind: FigmentSourceKind::File,
                layer_kind: ConfigSourceKind::File,
            }),
        );
        assert_eq!(
            g.attribution_source_kind_coordinates(),
            f.attribution_source_kind_coordinates(),
        );
    }

    // ---- attribution_name_kind_coordinates accessor tests ----

    #[test]
    fn attribution_name_kind_coordinates_none_for_unattributed_extract() {
        // No metadata to map → no rule → no name-axis joint cell. Pins
        // the first stage of the two-stage None discipline on the
        // cross-thread envelope, symmetric peer of
        // `attribution_source_kind_coordinates_none_for_unattributed_extract`.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert!(f.attribution_rule.is_none());
        assert!(f.attribution_name_kind_coordinates().is_none());
    }

    #[test]
    fn attribution_name_kind_coordinates_none_for_non_extract_variants() {
        // Non-figment-bearing variants and bare Figment never carry
        // attribution → never carry a name-axis joint cell.
        for f in [
            ReloadFailure::from_error(&crate::error::synthetic_parse_error()),
            ReloadFailure::from_error(&ShikumiError::Figment(fake_figment_error())),
        ] {
            assert!(f.attribution_name_kind_coordinates().is_none());
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_none_for_source_axis_attribution() {
        // Source-axis attributions carry an attribution_rule but their
        // identity does not pin the name-axis joint cell — the
        // accessor returns None even when the rule slot is Some. Pins
        // the second-stage None arm of the two-stage discipline on the
        // cross-thread envelope, symmetric peer of
        // `attribution_source_kind_coordinates_none_for_name_axis_attribution`.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let f = synthetic_failure_with_rule(rule);
            assert!(f.attribution_rule.is_some(), "rule {rule:?}");
            assert!(
                f.attribution_name_kind_coordinates().is_none(),
                "rule {rule:?}: source-axis attribution must yield None name-axis joint cell",
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_some_for_name_axis_attribution_pins_known_cells() {
        // Name-axis attributions surface their joint cell directly on
        // the cross-thread envelope: FileByMetadataName → (Format, File),
        // EnvByPrefix / EnvByUniqueness → (Env, Env). Pins both
        // realizable cells of the new cube through synthetic
        // ReloadFailure values carrying each name-axis rule.
        let cases: [(AttributionRule, AttributionNameKindCoordinates); 3] = [
            (
                AttributionRule::FileByMetadataName,
                AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Format,
                    layer_kind: ConfigSourceKind::File,
                },
            ),
            (
                AttributionRule::EnvByPrefix,
                AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Env,
                    layer_kind: ConfigSourceKind::Env,
                },
            ),
            (
                AttributionRule::EnvByUniqueness,
                AttributionNameKindCoordinates {
                    figment_name_tag_kind: FigmentNameTagKind::Env,
                    layer_kind: ConfigSourceKind::Env,
                },
            ),
        ];
        for (rule, expected) in cases {
            let f = synthetic_failure_with_rule(rule);
            assert_eq!(
                f.attribution_name_kind_coordinates(),
                Some(expected),
                "rule {rule:?}: name-axis joint cell pin on cross-thread envelope",
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_agrees_with_rule_pointwise() {
        // For every constructible rule scenario, the accessor result
        // equals
        // attribution_rule.and_then(AttributionRule::attribution_name_kind_coordinates)
        // — pinning the convenience accessor as a pure projection.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            assert_eq!(
                f.attribution_name_kind_coordinates(),
                rule.attribution_name_kind_coordinates(),
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_returns_realizable_cell_when_some() {
        // Every Some return from the cross-thread accessor satisfies
        // AttributionNameKindCoordinates::is_realizable — the captured
        // envelope's projection never produces an unrealizable cell,
        // no matter which rule was captured.
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            if let Some(cell) = f.attribution_name_kind_coordinates() {
                assert!(
                    cell.is_realizable(),
                    "envelope {:?}: joint cell {cell:?} must be realizable",
                    f.attribution_rule,
                );
            }
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_agrees_with_paired_projections_pointwise() {
        // Lossless-decomposition contract on the cross-thread
        // envelope: the joint cell's named fields agree byte-for-byte
        // with the paired
        // (figment_name_tag_kind, layer_kind)
        // reads on the same envelope. Holds vacuously when the joint
        // cell is None (the paired projection is also None on its
        // figment_name_tag_kind half).
        let scenarios: Vec<ReloadFailure> = AttributionRule::ALL
            .iter()
            .copied()
            .map(synthetic_failure_with_rule)
            .chain(std::iter::once(ReloadFailure::from_error(
                &crate::error::synthetic_parse_error(),
            )))
            .collect();
        for f in scenarios {
            let joint = f.attribution_name_kind_coordinates();
            let paired = f.figment_name_tag_kind().map(|figment_name_tag_kind| {
                AttributionNameKindCoordinates {
                    figment_name_tag_kind,
                    layer_kind: f.layer_kind().expect(
                        "figment_name_tag_kind Some implies layer_kind Some on the cross-thread envelope",
                    ),
                }
            });
            assert_eq!(
                joint, paired,
                "envelope {:?}: joint cell must equal paired projections",
                f.attribution_rule,
            );
        }
    }

    #[test]
    fn attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates_on_attributed_envelopes()
     {
        // Cross-cube partition law on the cross-thread observable
        // form: every attributed envelope surfaces exactly one of the
        // two figment-metadata × shikumi-layer joint cells as Some;
        // unattributed envelopes surface both as None. Closes the
        // joint-cell universe across the two cubes on the captured
        // envelope, mirror of the rule-side
        // `attribution_rule_attribution_name_kind_coordinates_xor_attribution_source_kind_coordinates`.
        for rule in AttributionRule::ALL.iter().copied() {
            let f = synthetic_failure_with_rule(rule);
            let source = f.attribution_source_kind_coordinates().is_some();
            let name = f.attribution_name_kind_coordinates().is_some();
            assert_ne!(
                source, name,
                "envelope {rule:?}: exactly one of the two joint cells must be Some",
            );
        }
        // Unattributed envelope: both None.
        let unattributed = ReloadFailure::from_error(&crate::error::synthetic_parse_error());
        assert!(unattributed.attribution_source_kind_coordinates().is_none());
        assert!(unattributed.attribution_name_kind_coordinates().is_none());
    }

    #[test]
    fn attribution_name_kind_coordinates_survives_clone_independent_of_originating_error() {
        // The captured joint cell is derived from the captured rule
        // (Copy) — it must survive cloning and outlive the originating
        // ShikumiError, parallel to the figment_name_tag_kind-clone
        // and attribution_source_kind_coordinates-clone invariants
        // already pinned on the cross-thread envelope.
        let f = synthetic_failure_with_source_and_rule(
            ConfigSource::Env("APP_".to_owned()),
            AttributionRule::EnvByPrefix,
        );
        let g = f.clone();
        assert_eq!(
            g.attribution_name_kind_coordinates(),
            Some(AttributionNameKindCoordinates {
                figment_name_tag_kind: FigmentNameTagKind::Env,
                layer_kind: ConfigSourceKind::Env,
            }),
        );
        assert_eq!(
            g.attribution_name_kind_coordinates(),
            f.attribution_name_kind_coordinates(),
        );
    }

    #[test]
    fn reload_tests_route_env_metadata_synthetics_through_env_metadata_name_writer() {
        // Source-text pin, peer of the sibling test on `error.rs`.
        //
        // No test body in this file may re-inline the
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
        // Fail-before-pass-after: at this commit the sites this test
        // protects are the two open-coded `figment::Error::from("synth")`
        // + `figment::Metadata::named(".. environment variable(s)")`
        // constructions in the
        // `figment_name_tag_kind_env_prefixed_extract_matches_underlying_error`
        // / `figment_name_tag_kind_survives_clone_independent_of_originating_error`
        // tests. A future re-inlining fires here first, before the two
        // resolver-arm cross-check tests silently fall back to
        // `EnvByUniqueness` under a shape edit that only lands at the
        // constants.
        //
        // Doc-comment / block-comment mentions of the shape are exempt
        // (they explain the invariant); the check filters lines whose
        // first non-whitespace token is `//`.
        const SRC: &str = include_str!("reload.rs");
        const TAIL_STEM: &str = crate::source::ConfigSource::ENV_METADATA_NAME_TAIL_STEM;
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(TAIL_STEM)
            })
            .filter(|(_, line)| {
                !line.contains("ENV_METADATA_NAME_TAIL_STEM")
                    && !line.contains("reload_tests_route_env_metadata_synthetics")
            })
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "reload.rs re-inlines the `{TAIL_STEM}[…]` env-metadata-name shape at \
             {} non-comment line(s) — route each through \
             `crate::source::synthetic_env_metadata_error(prefix)` so a future \
             shape edit at `ConfigSource::ENV_METADATA_NAME_TAIL` lands there \
             instead of silently desynchronising the synthetic from the writer: \
             {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn reload_tests_route_synth_message_through_shared_const() {
        // Source-text pin on the shared placeholder message body: no
        // test body in this file may re-inline `"synth"` as a `&str`
        // literal for a `ReloadFailure::message` field or a
        // `figment::Error::from(...)` construction.
        //
        // Every synthetic drives the resolver / accessor suite
        // through the shared `crate::source::SYNTHETIC_TEST_MESSAGE`
        // const, so a future placeholder change (rename for grep
        // coverage in captured test logs, per-test discriminator, or
        // reserving the bare `"synth"` for a real error shape figment
        // might emit) lands at ONE named site — the const in
        // `src/source.rs` — and every one of the thirty-three
        // `reload.rs::tests` sites plus the two `error.rs::tests`
        // sites plus the one `source.rs::tests` site inherits the
        // new placeholder by construction.
        //
        // Fail-before-pass-after: at this commit the thirty-three
        // sites this pin protects are every `ReloadFailure {
        // message: crate::source::SYNTHETIC_TEST_MESSAGE.to_owned(),
        // ... }` synthetic in this file's tests
        // (attribution_confidence / layer_kind / figment_source_kind
        // / figment_name_tag_kind / severity / serde accessor bodies
        // plus the `synthetic_failure_with_rule` helper); re-inlining
        // any of them fires here first before the corresponding
        // accessor tests silently observe a stale placeholder shape.
        //
        // Doc-comment / block-comment mentions of the placeholder are
        // exempt (they explain the invariant); the check filters
        // lines whose first non-whitespace token is `//`.
        const SRC: &str = include_str!("reload.rs");
        const NEEDLE: &str = "\"synth\"";
        let offenders: Vec<(usize, &str)> = SRC
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && line.contains(NEEDLE)
            })
            // Exempt this test itself: it mentions the placeholder in
            // its own body (as a needle) so the assertion can name
            // what it is looking for.
            .filter(|(_, line)| !line.contains("reload_tests_route_synth_message"))
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "reload.rs re-inlines the `\"synth\"` placeholder at {} non-comment \
             line(s) — route each through \
             `crate::source::SYNTHETIC_TEST_MESSAGE.to_owned()` so a future \
             placeholder edit at the shared const lands there instead of \
             silently desynchronising the synthetic from every other test-side \
             site in the crate: {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn reload_tests_route_synthetic_defaults_extract_failures_through_helper() {
        // Source-text pin on the synthetic-with-rule + Defaults-failing-
        // source shape: no test body in this file may re-inline the
        // seven-line `ReloadFailure { message: SYNTHETIC_TEST_MESSAGE,
        // kind: Extract, sources: vec![], field_path: vec![],
        // failing_source: Some(ConfigSource::Defaults), attribution_rule:
        // Some(...) }` struct literal at call-site indent (fields at 16
        // spaces).
        //
        // Every synthetic driving the resolver / accessor suite over the
        // full `AttributionRule::ALL` axis with Defaults as the failing
        // source routes through the shared `synthetic_failure_with_rule`
        // helper defined above at 12-space indent, so a future field
        // addition to `ReloadFailure` (the struct is `#[non_exhaustive]`
        // exactly for this) lands at ONE named site — the helper — and
        // every one of the 27 previously-open-coded call sites inherits
        // the new field by construction instead of failing to compile at
        // 27 distinct places, one per hand-typed struct literal.
        //
        // The pin keys on the call-site indent (`\n                ` — 16
        // spaces before `sources: vec![],`) so the helper's own body at
        // 12-space indent is exempt by construction; it does not need a
        // second exemption filter. The `only_source` off-diagonal shape
        // at 12-space indent that legitimately carries
        // `attribution_rule: None` (not `Some(_)`) is also exempt by
        // construction — the pin's needle names `Some(ConfigSource::Defaults),`
        // followed on the next line by `attribution_rule: Some(`, so the
        // `None` off-diagonal is out of scope.
        //
        // Fail-before-pass-after cross-check: the shape count was 27 at
        // the parent commit (before the lift routed each site through
        // `synthetic_failure_with_rule`); this pin fires 27 offenders at
        // that state and 0 here.
        const SRC: &str = include_str!("reload.rs");
        const NEEDLE: &str = "\n                sources: vec![],\n                \
                              field_path: vec![],\n                \
                              failing_source: Some(ConfigSource::Defaults),\n                \
                              attribution_rule: Some(";
        assert_eq!(
            SRC.matches(NEEDLE).count(),
            0,
            "reload.rs re-inlines the 7-line `synthetic_failure_with_rule` \
             shape at call-site indent (fields at 16 spaces) — route each \
             through the shared `synthetic_failure_with_rule(rule)` helper \
             so a future `ReloadFailure` field addition lands at the helper \
             and every call site inherits the new field by construction",
        );
    }

    #[test]
    fn reload_tests_route_synthetic_source_and_rule_extract_failures_through_helper() {
        // Source-text pin on the wider, source-parameterized shape of the
        // sibling `synthetic_failure_with_rule` pin — the same 7-line
        // `ReloadFailure { message: SYNTHETIC_TEST_MESSAGE, kind: Extract,
        // sources: vec![], field_path: vec![], failing_source:
        // Some(ConfigSource::<any variant>(...)), attribution_rule:
        // Some(...) }` struct-literal shape but with any `ConfigSource`
        // variant in the failing-source slot, not only `Defaults`.
        //
        // Every synthetic driving the accessor / clone-survival suite over
        // a non-`Defaults` failing source (concrete `File` paths in the
        // `file_provenance_pins_each_file_rule_on_envelope` loop, concrete
        // `Env` prefixes in the
        // `attribution_name_kind_coordinates_survives_clone_independent_of_originating_error`
        // pin, and any future addition over a `Sexp` / `Nix` / `Bare`
        // failing-source cell) routes through the shared
        // `synthetic_failure_with_source_and_rule(source, rule)` helper
        // defined above, so the same `#[non_exhaustive]`-of-ReloadFailure
        // future-field-addition drift-class the sibling pin closes on the
        // Defaults axis is also closed on the wider ConfigSource-variant
        // axis.
        //
        // The pin keys on the joint two-line signature `failing_source:
        // Some(ConfigSource::` followed on the next line at the same
        // indent by `attribution_rule: Some(` — the two attribution
        // fields' Some/Some diagonal-cell shape. The helper's own body
        // at 8-space indent (the tests-module `fn` body of
        // `synthetic_failure_with_source_and_rule`) is exempt by
        // construction: it uses `Some(source),` (a bare parameter, no
        // `ConfigSource::` path) on the `failing_source` line, so the
        // needle does not match the helper.
        //
        // The three off-diagonal cell literals inside
        // `failing_attribution_some_iff_both_source_and_rule_some_envelope`
        // are exempt by construction: they legitimately carry
        // `attribution_rule: None` (or `failing_source: None`) on the
        // second line, so the `Some(` half of the needle does not match.
        // The `synthetic_failure_with_rule(rule)` fixed-Defaults sibling
        // is guarded by the paired
        // `reload_tests_route_synthetic_defaults_extract_failures_through_helper`
        // pin above; this pin adds the wider ConfigSource-variant axis
        // rather than replacing that one.
        //
        // Fail-before-pass-after cross-check: the wider shape count was
        // 2 at the parent commit (the File-source concrete pin loop plus
        // the Env-source clone-survival pin); this pin fires 2 offenders
        // at that state and 0 here.
        const SRC: &str = include_str!("reload.rs");
        // Two indent variants live in-tree: 16-space (inside the
        // `file_provenance_pins_each_file_rule_on_envelope` `for` loop)
        // and 12-space (inside the top-level clone-survival test body).
        // Both are covered by matching the FULL four-line signature
        // (`sources: vec![],` → `field_path: vec![],` → `failing_source:
        // Some(ConfigSource::` → `attribution_rule: Some(`) on
        // consecutive lines with `line.trim_start()`. A single scan over
        // lines pairs each match with its three-line successor window.
        //
        // The four-line window discipline is what keeps the pin honest
        // against three otherwise-adjacent shapes that legitimately do
        // NOT belong at the helper:
        //   - `clone_preserves_data` populates `sources` and `field_path`
        //     with non-empty vectors, so the first two lines of its
        //     struct literal do NOT match `vec![],` — exempt by
        //     construction.
        //   - The three off-diagonal cells in
        //     `failing_attribution_some_iff_both_source_and_rule_some_envelope`
        //     carry `failing_source: None,` or `attribution_rule: None,`
        //     on the last two lines — the `Some(` sub-pattern rules them
        //     out.
        //   - The sibling `reload_tests_route_synthetic_defaults_extract_failures_through_helper`
        //     pin above contains a multi-line `NEEDLE` string literal
        //     whose visual layout also spells out three of the four
        //     tokens, but the line BEFORE the `sources: vec![],`
        //     fragment is `const NEEDLE: &str = "...` (trim_start starts
        //     with `const`), so the window-based match rooted at
        //     `sources:` never begins there.
        let lines: Vec<&str> = SRC.lines().collect();
        let mut offenders: Vec<usize> = Vec::new();
        for i in 0..lines.len().saturating_sub(3) {
            let l0 = lines[i].trim_start();
            if l0.starts_with("//") || l0 != "sources: vec![]," {
                continue;
            }
            let l1 = lines[i + 1].trim_start();
            let l2 = lines[i + 2].trim_start();
            let l3 = lines[i + 3].trim_start();
            if l1 == "field_path: vec![],"
                && l2.starts_with("failing_source: Some(ConfigSource::")
                && l3.starts_with("attribution_rule: Some(")
            {
                offenders.push(i + 1);
            }
        }
        assert!(
            offenders.is_empty(),
            "reload.rs re-inlines the wider `synthetic_failure_with_source_and_rule` \
             shape at {} non-comment line pair(s) — route each through the shared \
             `synthetic_failure_with_source_and_rule(source, rule)` helper so a \
             future `ReloadFailure` field addition lands at the helper and every \
             call site inherits the new field by construction (offending line \
             numbers: {offenders:?})",
            offenders.len(),
        );
    }

    #[test]
    fn reload_tests_route_synth_parse_through_synthetic_parse_error() {
        // Source-text pin on the shared "synthetic non-`Extract`
        // `ShikumiError`" constructor: no test body in this file may
        // re-inline `ShikumiError::Parse("x".to_owned())` as a literal.
        //
        // Every test that needs a canonical non-`Extract` error class to
        // exercise the fully-unattributed side of the `ReloadFailure`
        // envelope (27 such call sites in this file at the parent
        // commit — the accessor / attribution_confidence / layer_kind /
        // figment_source_kind / figment_name_tag_kind / metadata_axis /
        // field_path_dotted grid) routes through
        // `crate::error::synthetic_parse_error()`, so a future change to
        // the [`crate::ShikumiError::Parse`] variant shape lands at ONE
        // named site — the helper body in `crate::error` — and every
        // one of the 27 previously-open-coded call sites inherits the
        // new shape by construction rather than failing to compile at
        // 27 distinct places one paired edit at a time. Peer of the
        // sibling pins in `error.rs::tests` (6 sites) and
        // `observatory.rs::tests` (7 sites), which close the same drift
        // class on the other two axes of the same substrate.
        //
        // Fail-before-pass-after cross-check: the shape count was 27 at
        // the parent commit (before every site routed through
        // `crate::error::synthetic_parse_error()`); this pin fires 27
        // offenders at that state and 0 here.
        //
        // Doc-comment / block-comment mentions of the pattern are
        // exempt (they explain the invariant); the check filters lines
        // whose first non-whitespace token is `//`.
        const SRC: &str = include_str!("reload.rs");
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
            .filter(|(_, line)| !line.contains("reload_tests_route_synth_parse"))
            .map(|(n, l)| (n + 1, l))
            .collect();
        assert!(
            offenders.is_empty(),
            "reload.rs re-inlines the `ShikumiError::Parse(\"x\".to_owned())` \
             shape at {} non-comment line(s) — route each through \
             `crate::error::synthetic_parse_error()` so a future \
             `ShikumiError::Parse` shape change lands at the helper body \
             instead of at each open-coded literal apart: {offenders:#?}",
            offenders.len(),
        );
    }

    #[test]
    fn reload_tests_route_field_path_synthetics_through_synthetic_field_path_error() {
        // Source-text pin on the shared "synthetic figment error carrying
        // a localized field path" constructor: no test body in this file
        // may open-code the two-token
        // `figment::Error::from(<placeholder>.to_owned()).with_path(<path>)`
        // literal.
        //
        // Every test that needs a canonical
        // `figment::Error`-with-localized-path synthetic to exercise the
        // `ReloadFailure::from_error` field-path capture on both the
        // Extract-with-localized-field arm and the Figment-variant arm
        // (two such call sites in this file at the parent commit —
        // `from_error_captures_field_path_for_extract_with_localized_field`
        // and `from_error_captures_field_path_for_figment_variant`)
        // routes through
        // `crate::source::synthetic_field_path_error(path)`, so a future
        // change to how figment attaches a localized path lands at ONE
        // named site — the helper body in
        // `crate::source::synthetic_field_path_error` — and every one of
        // the two previously-open-coded call sites inherits the new
        // shape by construction. Peer of the sibling pin
        // `error_tests_route_field_path_synthetics_through_synthetic_field_path_error`
        // in `error.rs::tests` which closes the same drift class on the
        // four remaining call sites of the same substrate.
        //
        // Fail-before-pass-after cross-check: the shape count was 2 at
        // the parent commit (before every site routed through the
        // helper); this pin fires 2 offenders at that state and 0 here.
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
        const SRC: &str = include_str!("reload.rs");
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
            "reload.rs re-inlines the \
             `{NEEDLE_A}<placeholder>.to_owned()){NEEDLE_B}<path>)` \
             shape at {} non-comment line(s) — route each through \
             `crate::source::synthetic_field_path_error(path)` so a future \
             `figment::Error::with_path` shape change (or a placeholder-body \
             collapse onto `SYNTHETIC_TEST_MESSAGE`) lands at the helper body \
             instead of at each open-coded literal apart: {offenders:#?}",
            offenders.len(),
        );
    }
}

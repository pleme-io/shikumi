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
    AttributionConfidence, AttributionRule, FieldPathLocalization, ShikumiError, ShikumiErrorKind,
};
use crate::source::{ConfigSource, ConfigSourceKind};

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
}

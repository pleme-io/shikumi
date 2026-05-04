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

use crate::error::{AttributionRule, ShikumiError};
use crate::source::ConfigSource;

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
    /// [`Self::field_path`] (offending key), and
    /// [`Self::attribution_rule`] (why the layer was blamed): when
    /// present, the quadruple pins
    /// `(which-layer × which-field × why)` for the specific failure.
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
            sources: err.sources().map(<[_]>::to_vec).unwrap_or_default(),
            field_path: err.field_path().map(<[_]>::to_vec).unwrap_or_default(),
            failing_source: attribution.map(|a| a.source.clone()),
            attribution_rule: attribution.map(|a| a.rule),
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
            sources: vec![ConfigSource::Defaults],
            field_path: vec!["a".to_owned(), "b".to_owned()],
            failing_source: Some(ConfigSource::Defaults),
            attribution_rule: Some(AttributionRule::DefaultsByCodeUniqueness),
        };
        let g = f.clone();
        assert_eq!(g.message, f.message);
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
}

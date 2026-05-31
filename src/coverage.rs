//! `ConfigCoverage` — fleet invariant: every declared config field has a
//! consumer.
//!
//! A config field declared in a [`TieredConfig`] schema but never *read* by
//! the application is a **dead knob** — it shows up in `config-show` and
//! docs but does nothing, silently misleading operators into thinking it is
//! supported. `ConfigCoverage` turns that into a test failure.
//!
//! The application declares the set of dotted field paths it actually
//! consumes (a `CONSUMED_FIELDS` slice), and this cross-checks that set
//! against the leaf paths of the typed schema — derived by serialising
//! [`TieredConfig::prescribed_default`] to YAML and walking it —
//! **bidirectionally**:
//!
//! - a schema leaf with no consumed entry → **dead knob** (declared, unwired)
//! - a consumed entry with no schema leaf → **stale entry** (field removed/renamed)
//!
//! Either fails. Adding a field without wiring it, or removing/renaming a
//! field without updating its consumer entry, turns the test red — so the
//! config surface can never drift away from what the app honours.
//!
//! ```ignore
//! const CONSUMED_FIELDS: &[&str] = &["window.width", "window.height", /* … */];
//!
//! #[test]
//! fn config_has_no_dead_knobs() {
//!     shikumi::ConfigCoverage::assert_every_field_consumed::<MyConfig>(CONSUMED_FIELDS);
//! }
//! ```

use std::collections::BTreeSet;

use crate::tiered::TieredConfig;

/// Bidirectional coverage result: declared-schema leaf paths vs the
/// application's consumed-field list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Schema leaves with no matching consumed entry — declared config
    /// fields the app never reads (dead knobs). Wire or delete each.
    pub dead_knobs: Vec<String>,
    /// Consumed entries with no matching schema leaf — fields that were
    /// removed/renamed while their consumer entry lingered (stale).
    pub stale_entries: Vec<String>,
}

impl CoverageReport {
    /// True iff every declared field is consumed and every consumed entry
    /// is declared.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.dead_knobs.is_empty() && self.stale_entries.is_empty()
    }
}

/// Coverage checker over a [`TieredConfig`] schema. Stateless; all entry
/// points are associated functions generic over the config type.
pub struct ConfigCoverage;

impl ConfigCoverage {
    /// The sorted dotted leaf paths of `T`'s prescribed schema (e.g.
    /// `window.width`, `appearance.opacity`, `tear.mode`). A nested struct
    /// contributes one path per scalar/sequence leaf; a list field is a
    /// single leaf (the whole list is one knob).
    #[must_use]
    pub fn schema_leaf_paths<T: TieredConfig>() -> Vec<String> {
        let value = serde_yaml::to_value(T::prescribed_default())
            .expect("TieredConfig::prescribed_default must serialise to YAML");
        let mut out = Vec::new();
        collect_leaves(&value, &mut String::new(), &mut out);
        out.sort();
        out
    }

    /// Compute the bidirectional [`CoverageReport`] of `T`'s schema against
    /// the application's `consumed` field-path list.
    #[must_use]
    pub fn report<T: TieredConfig>(consumed: &[&str]) -> CoverageReport {
        let schema: BTreeSet<String> = Self::schema_leaf_paths::<T>().into_iter().collect();
        let consumed_set: BTreeSet<String> = consumed.iter().map(|s| (*s).to_string()).collect();
        CoverageReport {
            dead_knobs: schema.difference(&consumed_set).cloned().collect(),
            stale_entries: consumed_set.difference(&schema).cloned().collect(),
        }
    }

    /// Assert that every declared field of `T` is consumed and vice versa.
    /// Panics with a readable diff on failure — the canonical use is a
    /// `#[test]` in the consuming crate.
    pub fn assert_every_field_consumed<T: TieredConfig>(consumed: &[&str]) {
        let report = Self::report::<T>(consumed);
        assert!(
            report.is_clean(),
            "shikumi::ConfigCoverage: config schema and consumer list disagree.\n  \
             dead knobs (declared but no consumer — wire or delete): {:?}\n  \
             stale entries (consumed but not declared — remove the entry): {:?}",
            report.dead_knobs,
            report.stale_entries
        );
    }
}

/// Walk a serialised config value, pushing the dotted path of every
/// non-mapping leaf. Mappings recurse (nested structs); scalars, sequences,
/// and null are leaves. Built push-based (no `format!`) to keep the walker
/// allocation-light.
fn collect_leaves(value: &serde_yaml::Value, prefix: &mut String, out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, val) in map {
                let key_str = key.as_str().unwrap_or("?");
                let restore = prefix.len();
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(key_str);
                collect_leaves(val, prefix, out);
                prefix.truncate(restore);
            }
        }
        _ => out.push(prefix.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Inner {
        width: u32,
        height: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Demo {
        name: String,
        window: Inner,
        tags: Vec<String>,
    }

    impl TieredConfig for Demo {
        fn bare() -> Self {
            Demo {
                name: String::new(),
                window: Inner { width: 0, height: 0 },
                tags: vec![],
            }
        }
        fn prescribed_default() -> Self {
            Demo {
                name: "mado".into(),
                window: Inner { width: 80, height: 24 },
                tags: vec!["a".into()],
            }
        }
    }

    #[test]
    fn schema_leaf_paths_are_dotted_and_sorted() {
        let paths = ConfigCoverage::schema_leaf_paths::<Demo>();
        assert_eq!(
            paths,
            vec!["name", "tags", "window.height", "window.width"]
        );
    }

    #[test]
    fn fully_consumed_config_is_clean() {
        let report =
            ConfigCoverage::report::<Demo>(&["name", "tags", "window.width", "window.height"]);
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn unconsumed_field_is_a_dead_knob() {
        // Omit window.height from the consumed list — it becomes a dead knob.
        let report = ConfigCoverage::report::<Demo>(&["name", "tags", "window.width"]);
        assert_eq!(report.dead_knobs, vec!["window.height".to_string()]);
        assert!(report.stale_entries.is_empty());
        assert!(!report.is_clean());
    }

    #[test]
    fn consumed_entry_with_no_field_is_stale() {
        let report = ConfigCoverage::report::<Demo>(&[
            "name",
            "tags",
            "window.width",
            "window.height",
            "window.depth",
        ]);
        assert_eq!(report.stale_entries, vec!["window.depth".to_string()]);
        assert!(report.dead_knobs.is_empty());
    }

    #[test]
    #[should_panic(expected = "dead knobs")]
    fn assert_panics_on_dead_knob() {
        ConfigCoverage::assert_every_field_consumed::<Demo>(&["name", "tags", "window.width"]);
    }
}

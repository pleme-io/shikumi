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
    /// `#[test]` in the consuming crate. Each failing entry is paired
    /// with its nearest counterpart across the diff so the diagnostic
    /// tells the operator *which* leaf they mistyped, not just that a
    /// typo exists somewhere.
    pub fn assert_every_field_consumed<T: TieredConfig>(consumed: &[&str]) {
        let hinted = Self::hinted_report::<T>(consumed);
        assert!(
            hinted.is_clean(),
            "shikumi::ConfigCoverage: config schema and consumer list disagree.\n  \
             dead knobs (declared but no consumer — wire or delete): {}\n  \
             stale entries (consumed but not declared — remove or correct): {}",
            render_hint_list(&hinted.dead_knobs),
            render_hint_list(&hinted.stale_entries)
        );
    }

    /// Bidirectional coverage report augmented with a "did you mean"
    /// hint per stale / dead entry. Each stale entry is paired with the
    /// nearest schema leaf (its likely intended path if it is a typo);
    /// each dead knob is paired with the nearest consumed entry (its
    /// likely intended consumer). Hints are only produced when the
    /// nearest counterpart is within the automatic typo-threshold
    /// documented on [`Self::did_you_mean`].
    #[must_use]
    pub fn hinted_report<T: TieredConfig>(consumed: &[&str]) -> HintedCoverageReport {
        let schema = Self::schema_leaf_paths::<T>();
        let consumed_owned: Vec<String> = consumed.iter().map(|s| (*s).to_string()).collect();
        let schema_set: BTreeSet<String> = schema.iter().cloned().collect();
        let consumed_set: BTreeSet<String> = consumed_owned.iter().cloned().collect();
        let dead_knobs = schema_set
            .difference(&consumed_set)
            .map(|entry| CoverageHint {
                entry: entry.clone(),
                did_you_mean: Self::did_you_mean(entry, &consumed_owned).map(str::to_owned),
            })
            .collect();
        let stale_entries = consumed_set
            .difference(&schema_set)
            .map(|entry| CoverageHint {
                entry: entry.clone(),
                did_you_mean: Self::did_you_mean(entry, &schema).map(str::to_owned),
            })
            .collect();
        HintedCoverageReport {
            dead_knobs,
            stale_entries,
        }
    }

    /// Pure Levenshtein edit distance between `a` and `b`, counting
    /// insertions, deletions, and substitutions equally. Exposed as an
    /// associated function so consumers can build their own "did you
    /// mean" hints over any string set (e.g. an env-var name that did
    /// not match any known prefix) without pulling in a separate
    /// similarity crate.
    #[must_use]
    pub fn edit_distance(a: &str, b: &str) -> usize {
        levenshtein(a, b)
    }

    /// The nearest string in `candidates` to `needle` by Levenshtein
    /// distance, if any is within the automatic typo-threshold
    /// `max(1, needle.chars().count() / 3)`. Ties break to the lowest
    /// distance; among equal-distance candidates, the earliest one in
    /// `candidates` wins so the choice is deterministic. Returns
    /// [`None`] when `candidates` is empty or every candidate exceeds
    /// the threshold — a `None` is the correct answer, not a
    /// suppressed match, and callers should treat it as "no
    /// suggestion" rather than degrade to the closest anyway.
    #[must_use]
    pub fn did_you_mean<'a, S: AsRef<str> + 'a>(
        needle: &str,
        candidates: &'a [S],
    ) -> Option<&'a str> {
        let threshold = needle.chars().count().max(3) / 3;
        candidates
            .iter()
            .map(|c| (c.as_ref(), levenshtein(needle, c.as_ref())))
            .filter(|(_, d)| *d <= threshold)
            .min_by_key(|(_, d)| *d)
            .map(|(s, _)| s)
    }
}

/// A single stale/dead entry paired with its closest counterpart across
/// the coverage diff, if any lies within the auto typo-threshold. See
/// [`ConfigCoverage::did_you_mean`] for the threshold rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageHint {
    /// The entry that failed coverage — a stale consumed path or a dead
    /// schema leaf.
    pub entry: String,
    /// Nearest matching counterpart: for a stale entry, the closest
    /// schema leaf; for a dead knob, the closest consumed path. [`None`]
    /// when no counterpart is within the typo threshold.
    pub did_you_mean: Option<String>,
}

/// Bidirectional coverage result with per-entry "did you mean" hints —
/// the hinted mirror of [`CoverageReport`]. Produced by
/// [`ConfigCoverage::hinted_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintedCoverageReport {
    /// Schema leaves with no matching consumed entry — each paired with
    /// its nearest consumed path if one lies within the typo threshold.
    pub dead_knobs: Vec<CoverageHint>,
    /// Consumed entries with no matching schema leaf — each paired with
    /// its nearest schema leaf if one lies within the typo threshold.
    pub stale_entries: Vec<CoverageHint>,
}

impl HintedCoverageReport {
    /// True iff both hint lists are empty — the coverage-clean condition.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.dead_knobs.is_empty() && self.stale_entries.is_empty()
    }
}

/// Render a hint list for the assertion panic message.
fn render_hint_list(hints: &[CoverageHint]) -> String {
    if hints.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&hint.entry);
        out.push('"');
        if let Some(sug) = &hint.did_you_mean {
            out.push_str(" (did you mean \"");
            out.push_str(sug);
            out.push_str("\"?)");
        }
    }
    out.push(']');
    out
}

/// Pure Levenshtein edit distance implemented with a two-row DP over
/// [`char`]s (not bytes), so multi-byte scalar values count as one edit.
/// O(m*n) time, O(min(m,n)) space; ~40 lines is cheaper here than
/// pulling in `strsim` for one use.
fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = if a.chars().count() < b.chars().count() {
        (b, a)
    } else {
        (a, b)
    };
    let b_chars: Vec<char> = b.chars().collect();
    let n = b_chars.len();
    if n == 0 {
        return a.chars().count();
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
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
                window: Inner {
                    width: 0,
                    height: 0,
                },
                tags: vec![],
            }
        }
        fn prescribed_default() -> Self {
            Demo {
                name: "mado".into(),
                window: Inner {
                    width: 80,
                    height: 24,
                },
                tags: vec!["a".into()],
            }
        }
    }

    #[test]
    fn schema_leaf_paths_are_dotted_and_sorted() {
        let paths = ConfigCoverage::schema_leaf_paths::<Demo>();
        assert_eq!(paths, vec!["name", "tags", "window.height", "window.width"]);
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

    #[test]
    fn edit_distance_is_symmetric_and_zero_on_equal_strings() {
        assert_eq!(ConfigCoverage::edit_distance("width", "width"), 0);
        assert_eq!(ConfigCoverage::edit_distance("width", "witdh"), 2);
        assert_eq!(
            ConfigCoverage::edit_distance("width", "witdh"),
            ConfigCoverage::edit_distance("witdh", "width"),
            "Levenshtein must be symmetric"
        );
    }

    #[test]
    fn edit_distance_handles_empty_and_multibyte_correctly() {
        assert_eq!(ConfigCoverage::edit_distance("", ""), 0);
        assert_eq!(ConfigCoverage::edit_distance("abc", ""), 3);
        assert_eq!(ConfigCoverage::edit_distance("", "xyz"), 3);
        // Two 3-char scripts differing entirely: 仕組み → 組仕み (2 swaps)
        assert_eq!(ConfigCoverage::edit_distance("仕組み", "組仕み"), 2);
        // Multi-byte scalars count as 1 char, not 3 bytes:
        assert_eq!(ConfigCoverage::edit_distance("é", "e"), 1);
    }

    #[test]
    fn did_you_mean_finds_close_typo() {
        let candidates: Vec<String> = ["window.width", "window.height", "name", "tags"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            ConfigCoverage::did_you_mean("window.witdh", &candidates),
            Some("window.width"),
            "one transposition inside a 12-char path must be within the typo threshold"
        );
    }

    #[test]
    fn did_you_mean_rejects_distant_string() {
        let candidates: Vec<String> = ["window.width", "window.height"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(
            ConfigCoverage::did_you_mean("abc", &candidates).is_none(),
            "a totally unrelated needle must not degrade to the closest anyway"
        );
    }

    #[test]
    fn did_you_mean_returns_none_on_empty_candidates() {
        let candidates: Vec<String> = vec![];
        assert!(ConfigCoverage::did_you_mean("window.width", &candidates).is_none());
    }

    #[test]
    fn did_you_mean_breaks_ties_by_earliest_candidate() {
        // Two candidates equidistant from "foo" → pick the earlier one so
        // the hint is deterministic across runs (BTreeSet-ordered inputs
        // in hinted_report already do this, but the primitive should too).
        let candidates: Vec<String> = vec!["fob".into(), "fop".into()];
        assert_eq!(
            ConfigCoverage::did_you_mean("foo", &candidates),
            Some("fob"),
            "min_by_key picks the first equal-distance element"
        );
    }

    #[test]
    fn hinted_report_pairs_stale_entry_with_nearest_schema_leaf() {
        // Consumer *also* declared window.width, so no dead knob — only
        // the extra typo entry survives as stale.
        let hinted = ConfigCoverage::hinted_report::<Demo>(&[
            "name",
            "tags",
            "window.width",
            "window.witdh", // typo, extra
            "window.height",
        ]);
        assert_eq!(hinted.stale_entries.len(), 1);
        assert_eq!(hinted.stale_entries[0].entry, "window.witdh");
        assert_eq!(
            hinted.stale_entries[0].did_you_mean.as_deref(),
            Some("window.width"),
            "stale entry must be paired with the closest schema leaf"
        );
        assert!(hinted.dead_knobs.is_empty());
        assert!(!hinted.is_clean());
    }

    #[test]
    fn hinted_report_pairs_dead_knob_with_nearest_consumed_entry() {
        // Consumer wrote "window.witdh" instead of "window.width" — the
        // schema still declares window.width, so it becomes a dead knob
        // AND the typo becomes a stale entry, and both point at each
        // other.
        let hinted = ConfigCoverage::hinted_report::<Demo>(&[
            "name",
            "tags",
            "window.witdh",
            "window.height",
        ]);
        assert_eq!(hinted.dead_knobs.len(), 1);
        assert_eq!(hinted.dead_knobs[0].entry, "window.width");
        assert_eq!(
            hinted.dead_knobs[0].did_you_mean.as_deref(),
            Some("window.witdh"),
            "dead knob must be paired with the closest consumed path — even when that path is itself the typo"
        );
    }

    #[test]
    fn hinted_report_leaves_hint_empty_when_no_close_candidate_exists() {
        // "extra.unrelated" has no close cousin among the schema leaves
        // (name / tags / window.width / window.height) — the hint field
        // must stay None rather than pointing at the closest anyway.
        let hinted = ConfigCoverage::hinted_report::<Demo>(&[
            "name",
            "tags",
            "window.width",
            "window.height",
            "extra.unrelated",
        ]);
        assert_eq!(hinted.stale_entries.len(), 1);
        assert_eq!(hinted.stale_entries[0].entry, "extra.unrelated");
        assert!(
            hinted.stale_entries[0].did_you_mean.is_none(),
            "no near counterpart → no hint (never fall back to the least-bad match)"
        );
    }

    #[test]
    fn hinted_report_is_clean_when_coverage_is_clean() {
        let hinted = ConfigCoverage::hinted_report::<Demo>(&[
            "name",
            "tags",
            "window.width",
            "window.height",
        ]);
        assert!(hinted.is_clean());
        assert!(hinted.dead_knobs.is_empty());
        assert!(hinted.stale_entries.is_empty());
    }

    #[test]
    #[should_panic(expected = "\"window.witdh\" (did you mean \"window.width\"?)")]
    fn assert_panic_message_includes_did_you_mean_hint() {
        // The typo → schema-leaf pairing is what makes the diagnostic
        // actionable; pin the exact phrasing in the panic string so a
        // future refactor cannot silently drop it.
        ConfigCoverage::assert_every_field_consumed::<Demo>(&[
            "name",
            "tags",
            "window.witdh",
            "window.height",
        ]);
    }
}

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

use std::collections::{BTreeMap, BTreeSet};

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

    /// Convert an environment-variable name to the dotted config path
    /// figment would extract it under, matching the transformation
    /// applied by `figment::providers::Env::prefixed(prefix).split("__")`
    /// — the same shape used by [`crate::ProviderChain::with_env`].
    ///
    /// The prefix match is ASCII-case-insensitive (as figment does),
    /// the stem after the prefix is lowercased, and `__` becomes `.`.
    /// Returns [`None`] when `var` does not start with `prefix` under
    /// case-insensitive comparison, so callers can pipe raw
    /// [`std::env::vars`] through this and cheaply filter to the shikumi
    /// slice in one pass:
    ///
    /// ```
    /// use shikumi::ConfigCoverage;
    /// assert_eq!(
    ///     ConfigCoverage::env_var_to_path("MYAPP_", "MYAPP_OPTIONS__PADDING"),
    ///     Some("options.padding".to_string()),
    /// );
    /// assert_eq!(
    ///     ConfigCoverage::env_var_to_path("MYAPP_", "OTHER_KNOB"),
    ///     None,
    /// );
    /// ```
    #[must_use]
    pub fn env_var_to_path(prefix: &str, var: &str) -> Option<String> {
        if var.len() < prefix.len() {
            return None;
        }
        let (head, tail) = var.split_at(prefix.len());
        if !head.eq_ignore_ascii_case(prefix) {
            return None;
        }
        Some(tail.to_ascii_lowercase().replace("__", "."))
    }

    /// The inverse of [`Self::env_var_to_path`]: render a dotted schema
    /// path as the environment-variable name a figment env layer would
    /// pick up. `prefix` is emitted verbatim (operators pick their
    /// convention — usually upper-case-with-trailing-underscore), the
    /// path is uppercased, and each `.` becomes `__`.
    ///
    /// ```
    /// use shikumi::ConfigCoverage;
    /// assert_eq!(
    ///     ConfigCoverage::path_to_env_var("MYAPP_", "options.padding"),
    ///     "MYAPP_OPTIONS__PADDING",
    /// );
    /// ```
    #[must_use]
    pub fn path_to_env_var(prefix: &str, path: &str) -> String {
        let mut out = String::with_capacity(prefix.len() + path.len());
        out.push_str(prefix);
        for (i, part) in path.split('.').enumerate() {
            if i > 0 {
                out.push_str("__");
            }
            for ch in part.chars() {
                out.extend(ch.to_uppercase());
            }
        }
        out
    }

    /// The shared "diff paths against schema + hint each unknown" fold —
    /// the primitive [`Self::audit_value`] and [`Self::audit_env_vars`]
    /// both route through after their surface-specific extraction
    /// (walk-a-value-tree for `audit_value`; normalize-env-vars for
    /// `audit_env_vars`).
    ///
    /// Given an iterator of dotted paths and a schema of `T`: silently
    /// drop every path that corresponds to a schema leaf (they are
    /// legitimate overrides, not typos); return each remainder paired
    /// with the closest schema leaf under the typo threshold documented
    /// on [`Self::did_you_mean`] (or [`None`] when nothing lies within
    /// the threshold — never fall back to the least-bad match).
    ///
    /// The result is sorted by path for diagnostic determinism. The
    /// input is not deduplicated: two identical unknown paths produce
    /// two [`PathHint`] entries. Callers that want set semantics
    /// (`hinted_report`) collect their input into a `BTreeSet` first.
    ///
    /// A downstream audit only needs to lift its surface to
    /// `IntoIterator<Item = String>` to inherit the shared fold; the
    /// surface-specific rendering (rejoining raw env-var names,
    /// wrapping in [`ValueKeyHint`] / [`EnvVarHint`], etc.) is a thin
    /// layer above this primitive.
    #[must_use]
    pub fn audit_paths<T: TieredConfig, I>(paths: I) -> Vec<PathHint>
    where
        I: IntoIterator<Item = String>,
    {
        let schema = Self::schema_leaf_paths::<T>();
        let schema_set: BTreeSet<&str> = schema.iter().map(String::as_str).collect();
        let mut unknown: Vec<PathHint> = paths
            .into_iter()
            .filter(|p| !schema_set.contains(p.as_str()))
            .map(|path| PathHint {
                did_you_mean: Self::did_you_mean(&path, &schema).map(str::to_owned),
                path,
            })
            .collect();
        unknown.sort_by(|a, b| a.path.cmp(&b.path));
        unknown
    }

    /// Audit a deserialized config value (typically what
    /// `serde_yaml::from_str` returns from the operator's YAML/TOML
    /// file — but any `serde_yaml::Value` shape works, including one
    /// crossed over from `toml::Value` via serde) for dotted leaf paths
    /// that do not correspond to any schema leaf of `T`. Each unknown
    /// key is paired with a "did you mean" hint: the closest schema
    /// leaf under the typo threshold documented on [`Self::did_you_mean`],
    /// in dotted-path form.
    ///
    /// The third leg of the coverage-audit family on the file surface:
    /// [`Self::hinted_report`] audits a consumer-declared list;
    /// [`Self::audit_env_vars`] audits env-var-shaped names on the
    /// process-environment surface; `audit_value` audits the user's
    /// serialized config file — the primary surface where serde's
    /// default deserializer silently drops unknown fields, and even
    /// `#[serde(deny_unknown_fields)]` only fails hard on the first
    /// stray key with no typo hint.
    ///
    /// Mappings recurse; sequences are one knob (the whole list is one
    /// leaf, matching [`Self::schema_leaf_paths`]'s convention so a
    /// value round-tripped through the schema's serialised form audits
    /// clean). The audit is deterministic: unknown paths are returned
    /// sorted for diagnostic stability across runs.
    ///
    /// The schema diff + hint pairing is delegated to the shared
    /// [`Self::audit_paths`] fold — this function is the surface-
    /// specific extractor (walk the value tree, wrap each `PathHint`
    /// as a `ValueKeyHint`).
    #[must_use]
    pub fn audit_value<T: TieredConfig>(value: &serde_yaml::Value) -> ValueAudit {
        let mut leaves = Vec::new();
        collect_leaves(value, &mut String::new(), &mut leaves);
        let unknown = Self::audit_paths::<T, _>(leaves)
            .into_iter()
            .map(|PathHint { path, did_you_mean }| ValueKeyHint { path, did_you_mean })
            .collect();
        ValueAudit { unknown }
    }

    /// Audit `env` — a snapshot of `(name, _value)` pairs (typically
    /// [`std::env::vars`] collected once) — for env-var names that
    /// carry the shikumi `prefix` but do not correspond to any schema
    /// leaf of `T`. Each unknown var is paired with a "did you mean"
    /// hint: the closest schema leaf under the typo threshold,
    /// rendered back in env-var form so the operator sees *exactly*
    /// the name they meant to set — not a dotted path they now have to
    /// re-encode by hand.
    ///
    /// Values are ignored on purpose — a typo audit does not need to
    /// deserialize anything, and forcing values in would tie the API
    /// to figment's env-provider surface. The `_value` slot exists so
    /// `std::env::vars().collect()` drops straight in without a
    /// caller-side `map(|(k, _)| k)`.
    ///
    /// The audit is deterministic: unknown vars are returned sorted by
    /// their raw env-var name so the diagnostic is stable across
    /// process launches with a shuffled environment. Env vars that
    /// match a schema leaf are silently dropped — this is a hint
    /// surface, not a listing of every legitimate override.
    ///
    /// The schema diff + hint pairing is delegated to the shared
    /// [`Self::audit_paths`] fold — this function is the surface-
    /// specific extractor (normalize env vars into dotted paths via
    /// [`Self::env_var_to_path`], rejoin the surviving unknowns with
    /// their raw env-var names, and render each hint back to env-var
    /// form via [`Self::path_to_env_var`]).
    #[must_use]
    pub fn audit_env_vars<T: TieredConfig, K, V>(prefix: &str, env: &[(K, V)]) -> EnvVarAudit
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let normalized: Vec<(String, String)> = env
            .iter()
            .filter_map(|(name, _)| {
                let raw = name.as_ref();
                Self::env_var_to_path(prefix, raw).map(|path| (raw.to_owned(), path))
            })
            .collect();
        let path_hints: BTreeMap<String, Option<String>> =
            Self::audit_paths::<T, _>(normalized.iter().map(|(_, p)| p.clone()))
                .into_iter()
                .map(|PathHint { path, did_you_mean }| (path, did_you_mean))
                .collect();
        let mut unknown: Vec<EnvVarHint> = normalized
            .into_iter()
            .filter_map(|(env_var, path)| {
                let hint = path_hints.get(&path)?;
                Some(EnvVarHint {
                    did_you_mean: hint.as_deref().map(|p| Self::path_to_env_var(prefix, p)),
                    env_var,
                    normalized_path: path,
                })
            })
            .collect();
        unknown.sort_by(|a, b| a.env_var.cmp(&b.env_var));
        EnvVarAudit { unknown }
    }
}

/// A single unknown dotted-path entry: a path that does not correspond
/// to any schema leaf, paired with the closest schema leaf under the
/// typo threshold documented on [`ConfigCoverage::did_you_mean`].
/// Produced by [`ConfigCoverage::audit_paths`] — the surface-agnostic
/// primitive [`ConfigCoverage::audit_value`] and
/// [`ConfigCoverage::audit_env_vars`] both route through after their
/// surface-specific extraction (walk-a-value-tree; normalize-env-vars).
///
/// The surface-specific hint types ([`ValueKeyHint`], [`EnvVarHint`])
/// wrap a `PathHint`'s (path, `did_you_mean`) pair with any additional
/// surface state (e.g. `EnvVarHint::env_var`, the raw pre-normalization
/// env-var name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHint {
    /// The unknown dotted path (e.g. `window.witdh`, `unknown.knob`).
    pub path: String,
    /// Closest schema leaf, in dotted-path form. [`None`] when no
    /// schema leaf lies within the typo threshold.
    pub did_you_mean: Option<String>,
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

/// One env-var-shaped typo hint: an env var carrying the shikumi prefix
/// but not corresponding to any schema leaf, paired with the closest
/// schema-leaf-in-env-var-form (if any lies within the typo threshold).
/// Produced by [`ConfigCoverage::audit_env_vars`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVarHint {
    /// The env-var name as observed in the environment (case preserved).
    pub env_var: String,
    /// The dotted path figment would extract this env var under — the
    /// normalized form used for the schema-leaf comparison.
    pub normalized_path: String,
    /// Closest schema leaf, rendered back in env-var form (using the
    /// same `prefix` that produced the audit) so the operator sees the
    /// name they should have set, not a dotted path. [`None`] when no
    /// schema leaf lies within the typo threshold.
    pub did_you_mean: Option<String>,
}

/// Result of [`ConfigCoverage::audit_env_vars`] — every prefixed env var
/// that does not correspond to a schema leaf, each with an optional
/// nearest-neighbour hint. Env vars that *do* correspond to schema
/// leaves are silently dropped (they are legitimate overrides, not
/// typos).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvVarAudit {
    /// Prefixed env vars whose normalized dotted path does not match
    /// any schema leaf, sorted by raw env-var name for determinism.
    pub unknown: Vec<EnvVarHint>,
}

impl EnvVarAudit {
    /// True iff no prefixed env var deviated from the schema — every
    /// operator override in the environment is a real knob.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unknown.is_empty()
    }
}

/// One config-value-shaped typo hint: a dotted leaf path present in the
/// operator's deserialized config value (typically a `serde_yaml::Value`
/// loaded from their YAML/TOML file) but not corresponding to any
/// schema leaf, paired with the closest schema leaf (if any lies within
/// the typo threshold). Produced by [`ConfigCoverage::audit_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueKeyHint {
    /// Dotted path of the unknown leaf in the operator's config value
    /// (e.g. `window.witdh`, `unknown_section.knob`).
    pub path: String,
    /// Closest schema leaf, in dotted-path form. [`None`] when no
    /// schema leaf lies within the typo threshold.
    pub did_you_mean: Option<String>,
}

/// Result of [`ConfigCoverage::audit_value`] — every dotted leaf path in
/// the operator's serialized config value that does not correspond to a
/// schema leaf, each with an optional nearest-neighbour hint. Leaves
/// that *do* correspond to schema leaves are silently dropped (they are
/// legitimate overrides, not typos).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValueAudit {
    /// Unknown leaf paths in the operator's value, sorted by path for
    /// determinism.
    pub unknown: Vec<ValueKeyHint>,
}

impl ValueAudit {
    /// True iff no leaf in the value deviated from the schema — every
    /// operator override in the config file is a real knob.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unknown.is_empty()
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

    #[test]
    fn env_var_to_path_lowercases_and_swaps_separator() {
        assert_eq!(
            ConfigCoverage::env_var_to_path("MYAPP_", "MYAPP_WINDOW__WIDTH"),
            Some("window.width".to_string()),
        );
    }

    #[test]
    fn env_var_to_path_matches_prefix_case_insensitively_like_figment() {
        assert_eq!(
            ConfigCoverage::env_var_to_path("MyApp_", "MYAPP_NAME"),
            Some("name".to_string()),
            "figment env prefix comparison is ASCII-case-insensitive; ours must agree",
        );
    }

    #[test]
    fn env_var_to_path_rejects_var_without_prefix() {
        assert_eq!(
            ConfigCoverage::env_var_to_path("MYAPP_", "OTHER_NAME"),
            None
        );
        assert_eq!(ConfigCoverage::env_var_to_path("MYAPP_", "MYA"), None);
    }

    #[test]
    fn path_to_env_var_is_inverse_of_env_var_to_path_over_schema() {
        // Round-trip every schema leaf through the encoder-then-decoder;
        // the transformation is only useful as a hint if it is a
        // bijection on the schema surface.
        let schema = ConfigCoverage::schema_leaf_paths::<Demo>();
        for path in schema {
            let env = ConfigCoverage::path_to_env_var("MYAPP_", &path);
            assert_eq!(
                ConfigCoverage::env_var_to_path("MYAPP_", &env),
                Some(path.clone()),
                "round-trip failed for {path}",
            );
        }
    }

    #[test]
    fn path_to_env_var_uppercases_and_encodes_separator() {
        assert_eq!(
            ConfigCoverage::path_to_env_var("MYAPP_", "window.width"),
            "MYAPP_WINDOW__WIDTH",
        );
    }

    #[test]
    fn audit_env_vars_drops_env_vars_matching_schema_leaves() {
        // Every env var here corresponds to a real Demo leaf — nothing
        // should surface as unknown.
        let env: Vec<(String, String)> = vec![
            ("MYAPP_NAME".into(), "kanchi".into()),
            ("MYAPP_WINDOW__WIDTH".into(), "100".into()),
            ("MYAPP_WINDOW__HEIGHT".into(), "40".into()),
            ("UNRELATED_VAR".into(), "ignored".into()),
        ];
        let audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        assert!(audit.is_clean(), "no typos → clean audit; got {audit:?}");
        assert!(audit.unknown.is_empty());
    }

    #[test]
    fn audit_env_vars_flags_unknown_and_pairs_with_env_var_form_hint() {
        // MYAPP_WINDOW__WITDH (transposition) should surface as an
        // unknown env var paired with MYAPP_WINDOW__WIDTH in env-var
        // form (not dotted-path form).
        let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        assert_eq!(audit.unknown.len(), 1);
        let hint = &audit.unknown[0];
        assert_eq!(hint.env_var, "MYAPP_WINDOW__WITDH");
        assert_eq!(hint.normalized_path, "window.witdh");
        assert_eq!(
            hint.did_you_mean.as_deref(),
            Some("MYAPP_WINDOW__WIDTH"),
            "hint must be rendered in env-var form the operator can copy-paste",
        );
        assert!(!audit.is_clean());
    }

    #[test]
    fn audit_env_vars_leaves_hint_none_when_no_close_leaf_exists() {
        // A totally-unrelated prefixed env var: still surfaces as
        // unknown, but with no hint (no leaf is within the typo
        // threshold).
        let env: Vec<(String, String)> = vec![("MYAPP_UNRELATED_KNOB".into(), "x".into())];
        let audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        assert_eq!(audit.unknown.len(), 1);
        assert_eq!(audit.unknown[0].env_var, "MYAPP_UNRELATED_KNOB");
        assert!(
            audit.unknown[0].did_you_mean.is_none(),
            "no near schema leaf → no hint, never fall back to closest anyway",
        );
    }

    #[test]
    fn audit_env_vars_is_sorted_by_env_var_name_for_determinism() {
        // Shuffle the input; the output must always emerge in
        // env-var-name order so operators see a stable diagnostic
        // across runs.
        let env: Vec<(String, String)> = vec![
            ("MYAPP_ZZZ_UNKNOWN".into(), "z".into()),
            ("MYAPP_AAA_UNKNOWN".into(), "a".into()),
            ("MYAPP_MMM_UNKNOWN".into(), "m".into()),
        ];
        let audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        let names: Vec<&str> = audit.unknown.iter().map(|h| h.env_var.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "MYAPP_AAA_UNKNOWN",
                "MYAPP_MMM_UNKNOWN",
                "MYAPP_ZZZ_UNKNOWN"
            ],
        );
    }

    #[test]
    fn audit_env_vars_ignores_env_vars_outside_shikumi_prefix() {
        // A misspelt PATH is not shikumi's problem — the audit must
        // silently drop env vars outside its prefix.
        let env: Vec<(String, String)> = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/root".into()),
        ];
        let audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        assert!(audit.is_clean());
    }

    #[test]
    fn audit_value_is_clean_when_value_only_has_schema_leaves() {
        // A YAML value shaped exactly like Demo's schema audits clean.
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: [a, b, c]
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&value);
        assert!(audit.is_clean(), "expected clean audit, got {audit:?}");
        assert!(audit.unknown.is_empty());
    }

    #[test]
    fn audit_value_flags_typoed_key_with_dotted_path_hint() {
        // A one-transposition typo on window.width surfaces as an
        // unknown key with the schema-leaf hint attached.
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&value);
        assert_eq!(audit.unknown.len(), 1);
        assert_eq!(audit.unknown[0].path, "window.witdh");
        assert_eq!(
            audit.unknown[0].did_you_mean.as_deref(),
            Some("window.width"),
            "hint must name the schema leaf the operator almost certainly meant",
        );
        assert!(!audit.is_clean());
    }

    #[test]
    fn audit_value_leaves_hint_none_when_no_close_schema_leaf_exists() {
        // A totally-unrelated key: surfaces as unknown with no hint.
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
unrelated_section:
  some_knob: yes
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&value);
        assert_eq!(audit.unknown.len(), 1);
        assert_eq!(audit.unknown[0].path, "unrelated_section.some_knob");
        assert!(
            audit.unknown[0].did_you_mean.is_none(),
            "no near schema leaf → no hint, never fall back to closest anyway",
        );
    }

    #[test]
    fn audit_value_is_sorted_by_path_for_determinism() {
        // Multiple unknowns: the audit result must always emerge in
        // dotted-path order so operators see a stable diagnostic.
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
zzz_extra: 1
aaa_extra: 1
mmm_extra: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&value);
        let paths: Vec<&str> = audit.unknown.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(paths, vec!["aaa_extra", "mmm_extra", "zzz_extra"]);
    }

    #[test]
    fn audit_value_treats_sequence_as_one_leaf_matching_schema_convention() {
        // The schema treats `tags: Vec<String>` as one leaf (schema
        // path `tags`, not `tags.0` / `tags.1`). audit_value must
        // agree so a YAML value like `tags: [a, b, c]` does not surface
        // three phantom typos.
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: [one, two, three]
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&value);
        assert!(
            audit.is_clean(),
            "list values must map to one schema leaf (`tags`), not per-index — audit: {audit:?}",
        );
    }

    #[test]
    fn audit_value_is_clean_on_serialized_prescribed_default() {
        // The theorem: the schema serialised through its own prescribed
        // default MUST audit clean — schema_leaf_paths and audit_value
        // are derived from the same tree walk (collect_leaves), so a
        // future refactor that drifts the two must turn this red.
        let default_yaml = serde_yaml::to_value(Demo::prescribed_default()).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&default_yaml);
        assert!(
            audit.is_clean(),
            "audit_value(serde_yaml::to_value(T::prescribed_default())) must be clean; got {audit:?}",
        );
    }

    #[test]
    fn audit_value_agrees_with_env_var_audit_on_the_same_override_state() {
        // The invariant that welds audit_value and audit_env_vars into
        // one primitive under two keyings: the SAME set of typoed
        // overrides — expressed once as env vars and once as YAML —
        // must produce the SAME set of unknown dotted paths (modulo
        // the env-var-form rendering that audit_env_vars applies to
        // its hint). If a future refactor drifts the two extractors,
        // this test goes red at the earliest possible seam.
        let env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WITDH".into(), "100".into()),
            ("MYAPP_UNRELATED_KNOB".into(), "x".into()),
        ];
        let env_audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
unrelated_knob: x
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let value_audit = ConfigCoverage::audit_value::<Demo>(&value);
        // Cross-keying: the sorted set of normalized dotted paths must
        // agree between the two audits.
        let env_paths: Vec<&str> = env_audit
            .unknown
            .iter()
            .map(|h| h.normalized_path.as_str())
            .collect();
        let value_paths: Vec<&str> = value_audit
            .unknown
            .iter()
            .map(|h| h.path.as_str())
            .collect();
        assert_eq!(
            env_paths, value_paths,
            "audit_env_vars and audit_value must agree on the unknown-leaf-path set",
        );
        // And the schema-leaf hints must agree in dotted-path form
        // (audit_env_vars renders its hint back to env-var form, so
        // decode it through env_var_to_path for the comparison).
        let env_hints: Vec<Option<String>> = env_audit
            .unknown
            .iter()
            .map(|h| {
                h.did_you_mean
                    .as_deref()
                    .and_then(|e| ConfigCoverage::env_var_to_path("MYAPP_", e))
            })
            .collect();
        let value_hints: Vec<Option<String>> = value_audit
            .unknown
            .iter()
            .map(|h| h.did_you_mean.clone())
            .collect();
        assert_eq!(
            env_hints, value_hints,
            "the two audits must produce the same did-you-mean hint per unknown path (up to env-var rendering)",
        );
    }

    #[test]
    fn audit_paths_filters_known_paths_and_hints_unknown_with_did_you_mean() {
        // The shared fold: given a heterogeneous input, drop schema
        // leaves silently, surface every unknown with a hint against
        // the schema (or None when nothing lies within the threshold),
        // sorted by path.
        let paths = vec![
            "name".to_string(),              // known — filtered
            "window.witdh".to_string(),      // typo — surfaces with hint
            "window.height".to_string(),     // known — filtered
            "totally.unrelated".to_string(), // unknown — no hint (nothing close)
        ];
        let audits = ConfigCoverage::audit_paths::<Demo, _>(paths);
        assert_eq!(audits.len(), 2);
        // Sorted by path: "totally.unrelated" < "window.witdh"
        assert_eq!(audits[0].path, "totally.unrelated");
        assert!(
            audits[0].did_you_mean.is_none(),
            "no near schema leaf → no hint, never fall back to closest anyway",
        );
        assert_eq!(audits[1].path, "window.witdh");
        assert_eq!(audits[1].did_you_mean.as_deref(), Some("window.width"));
    }

    #[test]
    fn audit_paths_returns_empty_when_every_path_is_a_schema_leaf() {
        let paths: Vec<String> = ["name", "tags", "window.width", "window.height"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let audits = ConfigCoverage::audit_paths::<Demo, _>(paths);
        assert!(audits.is_empty(), "all-known input → empty audit");
    }

    #[test]
    fn audit_paths_returns_empty_when_input_is_empty() {
        let audits = ConfigCoverage::audit_paths::<Demo, _>(Vec::<String>::new());
        assert!(audits.is_empty());
    }

    #[test]
    fn audit_paths_preserves_duplicate_unknown_paths() {
        // audit_paths is a fold, not a set operation — two identical
        // unknown paths produce two PathHint entries. This matches the
        // current audit_env_vars behavior (two env vars normalizing to
        // the same path both surface as separate EnvVarHints).
        let audits = ConfigCoverage::audit_paths::<Demo, _>(vec![
            "window.witdh".to_string(),
            "window.witdh".to_string(),
        ]);
        assert_eq!(audits.len(), 2);
        assert_eq!(audits[0].path, "window.witdh");
        assert_eq!(audits[1].path, "window.witdh");
    }

    #[test]
    fn audit_value_equals_audit_paths_on_its_extracted_leaves() {
        // The routing invariant on the file surface: audit_value(v)
        // must equal audit_paths::<T>(leaves(v)) modulo the
        // ValueKeyHint <-> PathHint field rename. A future refactor
        // that drifts audit_value away from audit_paths (e.g. adding a
        // second schema-diff pass, changing the sort order) turns this
        // red at the earliest possible seam.
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
totally_unrelated: x
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let value_audit = ConfigCoverage::audit_value::<Demo>(&value);
        // Hand-encode the leaves audit_value walks — mappings recurse,
        // sequences (`tags`) are one leaf.
        let manual_leaves: Vec<String> = vec![
            "name".into(),
            "window.witdh".into(),
            "window.height".into(),
            "tags".into(),
            "totally_unrelated".into(),
        ];
        let manual = ConfigCoverage::audit_paths::<Demo, _>(manual_leaves);
        let value_pairs: Vec<(String, Option<String>)> = value_audit
            .unknown
            .into_iter()
            .map(|h| (h.path, h.did_you_mean))
            .collect();
        let manual_pairs: Vec<(String, Option<String>)> = manual
            .into_iter()
            .map(|PathHint { path, did_you_mean }| (path, did_you_mean))
            .collect();
        assert_eq!(
            value_pairs, manual_pairs,
            "audit_value must equal audit_paths on its extracted leaves — the primitive is one fold, not two",
        );
    }

    #[test]
    fn audit_env_vars_equals_audit_paths_on_its_normalized_paths() {
        // The routing invariant on the env-var surface: after
        // normalizing env vars into dotted paths, the schema-diff +
        // hint pairing agrees with audit_paths on the same paths. The
        // env-var-form rendering that audit_env_vars applies to its
        // hint is the surface layer above the shared fold, not a
        // separate schema-diff pass.
        let env: Vec<(String, String)> = vec![
            ("MYAPP_NAME".into(), "kanchi".into()), // known → filtered
            ("MYAPP_WINDOW__WITDH".into(), "100".into()), // typo — surfaces
            ("MYAPP_TOTALLY_UNRELATED".into(), "x".into()), // unknown — no hint
            ("PATH".into(), "/usr/bin".into()),     // outside prefix — filtered
        ];
        let env_audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        // The same normalization audit_env_vars applies before routing
        // through audit_paths (drop outside-prefix vars; lowercase +
        // "__" → ".").
        let normalized: Vec<String> = env
            .iter()
            .filter_map(|(name, _)| ConfigCoverage::env_var_to_path("MYAPP_", name))
            .collect();
        let manual = ConfigCoverage::audit_paths::<Demo, _>(normalized);
        // env_audit is sorted by env_var name; manual is sorted by
        // path. Compare via a set of (normalized_path, hint-in-dotted-
        // path-form) pairs so the sort order does not conflate with
        // the actual invariant.
        let env_pairs: BTreeSet<(String, Option<String>)> = env_audit
            .unknown
            .into_iter()
            .map(|h| {
                (
                    h.normalized_path,
                    h.did_you_mean
                        .and_then(|e| ConfigCoverage::env_var_to_path("MYAPP_", &e)),
                )
            })
            .collect();
        let manual_pairs: BTreeSet<(String, Option<String>)> = manual
            .into_iter()
            .map(|PathHint { path, did_you_mean }| (path, did_you_mean))
            .collect();
        assert_eq!(
            env_pairs, manual_pairs,
            "audit_env_vars must equal audit_paths on its normalized paths (up to env-var-form hint rendering)",
        );
    }

    #[test]
    fn audit_value_is_clean_on_serialized_prescribed_default_after_lift() {
        // The schema self-check theorem still holds through the
        // audit_paths lift: a value round-tripped through the schema's
        // own prescribed default audits clean, because both
        // schema_leaf_paths and audit_paths are derived from the same
        // tree walk over the same schema. Redundant with the pre-lift
        // test but pinned again here because audit_value now routes
        // through audit_paths, so a bug in the fold or the primitive
        // must not silently produce false positives on the schema's
        // own output.
        let default_yaml = serde_yaml::to_value(Demo::prescribed_default()).unwrap();
        let audit = ConfigCoverage::audit_value::<Demo>(&default_yaml);
        assert!(
            audit.is_clean(),
            "audit_value(serde_yaml::to_value(T::prescribed_default())) must be clean after the audit_paths lift; got {audit:?}",
        );
    }
}

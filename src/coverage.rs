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
    ///
    /// The panic message routes through the shared
    /// [`fn@render_hint_pairs`] renderer — the same fold [`Self::assert_no_unknown_keys`]
    /// and [`Self::assert_no_unknown_env_vars`] use on their respective
    /// surfaces so every [`ConfigCoverage`] assertion produces
    /// identically-shaped `"entry" (did you mean "suggestion"?)` output.
    ///
    /// # Panics
    ///
    /// Panics with the readable diff described above when any schema leaf
    /// of `T` is not present in `consumed`, or any entry in `consumed` is
    /// not a schema leaf of `T`.
    pub fn assert_every_field_consumed<T: TieredConfig>(consumed: &[&str]) {
        let hinted = Self::hinted_report::<T>(consumed);
        assert!(
            hinted.is_clean(),
            "shikumi::ConfigCoverage: config schema and consumer list disagree.\n  \
             dead knobs (declared but no consumer — wire or delete): {}\n  \
             stale entries (consumed but not declared — remove or correct): {}",
            render_hint_pairs(coverage_hint_pairs(&hinted.dead_knobs)),
            render_hint_pairs(coverage_hint_pairs(&hinted.stale_entries)),
        );
    }

    /// Assert that no leaf path in the operator's deserialized config
    /// value corresponds to something outside `T`'s schema. Panics with
    /// a readable diff on failure — the file-surface peer of
    /// [`Self::assert_every_field_consumed`]. Each unknown key is
    /// paired with its nearest schema leaf under the typo threshold so
    /// the diagnostic names *which* leaf the operator almost certainly
    /// meant, not just that an unknown key exists somewhere.
    ///
    /// The canonical use is a `#[test]` in the consuming crate that
    /// loads each shipped example config through `serde_yaml::from_str`
    /// and asserts it audits clean, so a schema-renamed field caught in
    /// docs but forgotten in the sample config surfaces at test time
    /// instead of at first-run time. Layered above [`Self::audit_value`]
    /// so the underlying schema-diff logic stays single-sourced.
    ///
    /// # Panics
    ///
    /// Panics with the readable diff described above when [`Self::audit_value`]
    /// surfaces any leaf path in `value` that is not a schema leaf of `T`.
    pub fn assert_no_unknown_keys<T: TieredConfig>(value: &serde_yaml::Value) {
        let audit = Self::audit_value::<T>(value);
        assert!(
            audit.is_clean(),
            "shikumi::ConfigCoverage: config value has unknown keys not in schema.\n  \
             unknown keys (remove or correct): {}",
            render_hint_pairs(value_key_hint_pairs(&audit.unknown)),
        );
    }

    /// The one-shot health check: run all three coverage audits on the
    /// three operator-controllable input surfaces (consumer-declared
    /// field list; deserialized config value; prefixed process
    /// environment) and return their combined [`HealthReport`].
    /// [`Self::assert_healthy`] layers above this to render the
    /// merged panic message; consumers that want to inspect the report
    /// structurally (e.g. to attach it to a diagnostics endpoint,
    /// serialize it into a golden fixture, or triage which surface
    /// failed first) call this directly.
    ///
    /// The primitive is one call: `hinted_report::<T>(consumed)` for
    /// the schema-vs-consumer surface; `audit_value::<T>(value)` for
    /// the file surface; `audit_env_vars::<T, K, V>(env_prefix, env)`
    /// for the env surface. The three audits collapse into a single
    /// `HealthReport` with no cross-surface logic — the surfaces
    /// remain independently checkable, and adding a fourth surface
    /// (a TOML value, a CLI argv slice, a fetched-config manifest)
    /// is one field on `HealthReport` and one line here.
    #[must_use]
    pub fn health_report<T, K, V>(
        consumed: &[&str],
        value: &serde_yaml::Value,
        env_prefix: &str,
        env: &[(K, V)],
    ) -> HealthReport
    where
        T: TieredConfig,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        HealthReport {
            coverage: Self::hinted_report::<T>(consumed),
            value: Self::audit_value::<T>(value),
            env: Self::audit_env_vars::<T, K, V>(env_prefix, env),
        }
    }

    /// Assert that all three coverage surfaces are healthy in one shot.
    /// Panics with a merged diff that surfaces every unhealthy surface
    /// simultaneously — an operator sees the complete picture (a
    /// stale consumer entry AND a misspelled env var AND an unknown
    /// key in a shipped example config) in one panic string, not a
    /// game of whack-a-mole one surface at a time.
    ///
    /// The canonical use is a single `#[test]` per config type that
    /// replaces the three ceremony-heavy tests otherwise needed to
    /// exercise [`Self::assert_every_field_consumed`],
    /// [`Self::assert_no_unknown_keys`], and
    /// [`Self::assert_no_unknown_env_vars`] individually.
    ///
    /// All four hint lists (dead knobs, stale entries, unknown value
    /// keys, unknown env vars) render through the same
    /// [`fn@render_hint_pairs`] primitive the individual assertions
    /// use, so a future sharpening of the panic format (adding the
    /// schema-leaf source path, ANSI colour on the suggestion, a
    /// nearest-neighbour tier hint) lands in one place and lifts every
    /// consumer uniformly.
    ///
    /// # Panics
    ///
    /// Panics with the merged diff described above when
    /// [`Self::health_report`] reports any unhealthy surface (a dead
    /// knob, a stale consumer entry, an unknown value key, or an
    /// unknown prefixed env var).
    pub fn assert_healthy<T, K, V>(
        consumed: &[&str],
        value: &serde_yaml::Value,
        env_prefix: &str,
        env: &[(K, V)],
    ) where
        T: TieredConfig,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let report = Self::health_report::<T, K, V>(consumed, value, env_prefix, env);
        assert!(
            report.is_clean(),
            "shikumi::ConfigCoverage: config unhealthy across surfaces.\n  \
             dead knobs (declared but no consumer — wire or delete): {}\n  \
             stale entries (consumed but not declared — remove or correct): {}\n  \
             unknown keys in value (remove or correct): {}\n  \
             unknown env vars {env_prefix}* (remove or correct): {}",
            render_hint_pairs(coverage_hint_pairs(&report.coverage.dead_knobs)),
            render_hint_pairs(coverage_hint_pairs(&report.coverage.stale_entries)),
            render_hint_pairs(value_key_hint_pairs(&report.value.unknown)),
            render_hint_pairs(env_var_hint_pairs(&report.env.unknown)),
        );
    }

    /// Assert that no prefixed environment variable corresponds to
    /// something outside `T`'s schema. Panics with a readable diff on
    /// failure — the env-var-surface peer of
    /// [`Self::assert_every_field_consumed`]. Each unknown env var is
    /// paired with its nearest schema leaf **in env-var form** (so the
    /// operator sees the exact name they should have set, not a dotted
    /// path they have to re-encode by hand).
    ///
    /// The canonical use is a `#[test]` in a consuming crate or an
    /// operator-side preflight that snapshots the current process
    /// environment (`std::env::vars().collect()`) and asserts every
    /// shikumi-prefixed override is a real knob — turning a silent
    /// misspelled `MYAPP_WINDOW__WITDH` (that figment cheerfully
    /// ignores) into a hard test failure. Layered above
    /// [`Self::audit_env_vars`] so the underlying schema-diff logic
    /// stays single-sourced.
    ///
    /// # Panics
    ///
    /// Panics with the readable diff described above when [`Self::audit_env_vars`]
    /// surfaces any `prefix`-carrying env var whose normalized dotted
    /// path is not a schema leaf of `T`.
    pub fn assert_no_unknown_env_vars<T, K, V>(prefix: &str, env: &[(K, V)])
    where
        T: TieredConfig,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let audit = Self::audit_env_vars::<T, K, V>(prefix, env);
        assert!(
            audit.is_clean(),
            "shikumi::ConfigCoverage: environment has unknown {prefix}* vars not in schema.\n  \
             unknown env vars (remove or correct): {}",
            render_hint_pairs(env_var_hint_pairs(&audit.unknown)),
        );
    }

    /// Bidirectional coverage report augmented with a "did you mean"
    /// hint per stale / dead entry. Each stale entry is paired with the
    /// nearest schema leaf (its likely intended path if it is a typo);
    /// each dead knob is paired with the nearest consumed entry (its
    /// likely intended consumer). Hints are only produced when the
    /// nearest counterpart is within the automatic typo-threshold
    /// documented on [`Self::did_you_mean`].
    ///
    /// Both arms route through the shared [`Self::audit_paths_against`]
    /// fold — the coverage-audit family collapses to one primitive with
    /// two applications: `audit_paths_against(schema, &consumed)`
    /// surfaces dead knobs; `audit_paths_against(consumed_deduped,
    /// &schema)` surfaces stale entries. The two directions are the
    /// symmetry of one fold, not two separate set-difference
    /// implementations.
    #[must_use]
    pub fn hinted_report<T: TieredConfig>(consumed: &[&str]) -> HintedCoverageReport {
        let schema = Self::schema_leaf_paths::<T>();
        let consumed_owned: Vec<String> = consumed.iter().map(|s| (*s).to_string()).collect();
        let consumed_set: BTreeSet<String> = consumed_owned.iter().cloned().collect();
        let dead_knobs = Self::audit_paths_against(schema.iter().cloned(), &consumed_owned)
            .into_iter()
            .map(|PathHint { path, did_you_mean }| CoverageHint {
                entry: path,
                did_you_mean,
            })
            .collect();
        let stale_entries = Self::audit_paths_against(consumed_set.iter().cloned(), &schema)
            .into_iter()
            .map(|PathHint { path, did_you_mean }| CoverageHint {
                entry: path,
                did_you_mean,
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
    ///
    /// This is the schema-keyed convenience over the fully general
    /// [`Self::audit_paths_against`] — it wires `known` to the schema
    /// leaves of `T` so the common case (schema-vs-input) is one call.
    /// [`Self::hinted_report`] takes the general form directly to
    /// audit in both directions (schema-vs-consumed for dead knobs;
    /// consumed-vs-schema for stale entries).
    #[must_use]
    pub fn audit_paths<T: TieredConfig, I>(paths: I) -> Vec<PathHint>
    where
        I: IntoIterator<Item = String>,
    {
        Self::audit_paths_against(paths, &Self::schema_leaf_paths::<T>())
    }

    /// The fully general "diff paths against a known set + hint each
    /// unknown" fold. Given an iterator of dotted paths and an
    /// explicit `known` set of strings: silently drop every path that
    /// is present in `known` (legitimate matches, not typos); return
    /// each remainder paired with its closest neighbour in `known`
    /// under the typo threshold documented on [`Self::did_you_mean`]
    /// (or [`None`] when nothing lies within the threshold).
    ///
    /// The result is sorted by path for diagnostic determinism. The
    /// input is not deduplicated (see [`Self::audit_paths`] for the
    /// dedup convention). Tie-breaking in `did_you_mean` follows the
    /// order of `known` as passed in — callers control that by
    /// choosing to pass an already-sorted vec (schema leaves) or an
    /// original-order vec (consumer-declared paths).
    ///
    /// This is the primitive [`Self::audit_paths`] (schema-keyed) and
    /// both arms of [`Self::hinted_report`] (schema-vs-consumed for
    /// dead knobs; consumed-vs-schema for stale entries) route
    /// through. The coverage-audit family is one fold under three
    /// keyings — the surface-specific rendering
    /// ([`ValueKeyHint`] / [`EnvVarHint`] / [`CoverageHint`]) is a
    /// thin layer above this primitive.
    #[must_use]
    pub fn audit_paths_against<I, S>(paths: I, known: &[S]) -> Vec<PathHint>
    where
        I: IntoIterator<Item = String>,
        S: AsRef<str>,
    {
        let known_set: BTreeSet<&str> = known.iter().map(AsRef::as_ref).collect();
        let mut unknown: Vec<PathHint> = paths
            .into_iter()
            .filter(|p| !known_set.contains(p.as_str()))
            .map(|path| PathHint {
                did_you_mean: Self::did_you_mean(&path, known).map(str::to_owned),
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
    /// Total count of unhealthy entries across both hint lists — the
    /// sum of dead knobs and stale entries. The peer of
    /// [`Self::is_clean`] (`is_empty`/`len` shape): `is_clean() ⇔
    /// hint_count() == 0` holds by construction, since `is_clean`
    /// delegates to `hint_count() == 0`.
    ///
    /// Consumers that want to prioritise remediation ("which config
    /// surface has the most typos"), report a total-severity number
    /// to a diagnostics endpoint, or gate CI on a hint-count budget
    /// call this directly instead of hand-summing the hint lists.
    #[must_use]
    pub fn hint_count(&self) -> usize {
        self.dead_knobs.len() + self.stale_entries.len()
    }

    /// True iff both hint lists are empty — the coverage-clean condition.
    /// Equivalent to `hint_count() == 0`, and delegates to it so the
    /// two peers cannot drift.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hint_count() == 0
    }
}

/// Which of the four coverage surfaces a [`SurfaceHint`] came from —
/// the tag [`HealthReport::hint_iter`] pairs with every hint so
/// programmatic consumers can route each hint by surface (into a
/// JSON row, a dashboard column, a per-surface remediation counter)
/// without re-walking the four underlying hint lists themselves.
///
/// Variants map one-to-one to the four hint lists a [`HealthReport`]
/// carries: two on the schema-vs-consumer surface (dead knobs, stale
/// entries — the two directions of that surface's bidirectional
/// diff), one on the file-value surface, one on the env-var surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HintSurface {
    /// From [`HintedCoverageReport::dead_knobs`] — a schema leaf
    /// declared in [`TieredConfig::prescribed_default`] with no
    /// matching entry in the consumer-declared field-path list
    /// (declared but unwired).
    DeadKnob,
    /// From [`HintedCoverageReport::stale_entries`] — a
    /// consumer-declared field path with no matching schema leaf
    /// (consumer entry that outlived its schema field).
    StaleEntry,
    /// From [`ValueAudit::unknown`] — a dotted leaf path present in
    /// the operator's deserialized config value that does not
    /// correspond to any schema leaf.
    ValueKey,
    /// From [`EnvVarAudit::unknown`] — a prefixed env var whose
    /// normalized dotted path does not correspond to any schema
    /// leaf.
    EnvVar,
}

/// Surface-tagged view of one coverage hint, borrowed from a
/// [`HealthReport`]. Produced by [`HealthReport::hint_iter`].
///
/// `entry` is the operator-facing string the hint pertains to,
/// rendered the same way the panic path renders it: the dotted path
/// for [`HintSurface::DeadKnob`], [`HintSurface::StaleEntry`], and
/// [`HintSurface::ValueKey`]; the raw env-var name with case
/// preserved for [`HintSurface::EnvVar`]. `did_you_mean` is the
/// closest counterpart under the typo threshold, rendered in the
/// same form as `entry` — matching exactly the `(entry,
/// did_you_mean)` shape [`ConfigCoverage::assert_healthy`] feeds into
/// the shared `render_hint_pairs` renderer for each of its four
/// per-surface panic-sub-strings, so a consumer that renders through
/// `hint_iter` produces the same text as the panic path without
/// having to parse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceHint<'a> {
    /// Which coverage surface this hint came from.
    pub surface: HintSurface,
    /// The operator-facing string the hint pertains to.
    pub entry: &'a str,
    /// Closest counterpart under the typo threshold, in the same
    /// form as `entry`. [`None`] when nothing lies within.
    pub did_you_mean: Option<&'a str>,
}

/// Combined coverage-and-typo-audit result across all three
/// operator-controllable input surfaces: consumer-declared field list,
/// deserialized config value, prefixed process environment. Produced by
/// [`ConfigCoverage::health_report`].
///
/// A single test that constructs a `HealthReport` and asserts
/// [`Self::is_clean`] is equivalent to running
/// [`ConfigCoverage::assert_every_field_consumed`],
/// [`ConfigCoverage::assert_no_unknown_keys`], and
/// [`ConfigCoverage::assert_no_unknown_env_vars`] in sequence — but
/// surfaces every unhealthy surface in one report instead of stopping
/// at the first failure, so an operator sees the complete picture (a
/// misspelled env var AND a stale consumer entry AND an unknown key
/// in a shipped example config) in one shot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    /// Bidirectional schema-vs-consumer coverage with typo hints.
    pub coverage: HintedCoverageReport,
    /// Unknown leaf paths in the operator's config value with typo hints.
    pub value: ValueAudit,
    /// Unknown prefixed env vars with env-var-form typo hints.
    pub env: EnvVarAudit,
}

impl HealthReport {
    /// Total count of unhealthy entries across every surface — the
    /// sum of [`HintedCoverageReport::hint_count`],
    /// [`ValueAudit::hint_count`], and [`EnvVarAudit::hint_count`].
    /// The peer of [`Self::is_clean`] (`is_empty`/`len` shape):
    /// `is_clean() ⇔ hint_count() == 0` holds by construction, since
    /// `is_clean` delegates to `hint_count() == 0`.
    ///
    /// This is the natural roll-up for a diagnostics endpoint that
    /// reports "N total operator overrides deviate from the schema"
    /// as one number, or for CI to enforce a monotonically-shrinking
    /// hint-count budget across a fleet of consumers without having
    /// to hand-sum the four surface hint lists.
    #[must_use]
    pub fn hint_count(&self) -> usize {
        self.coverage.hint_count() + self.value.hint_count() + self.env.hint_count()
    }

    /// True iff every one of the three surfaces (consumer list, config
    /// value, prefixed environment) is clean — no dead knobs, no stale
    /// consumer entries, no unknown value keys, no unknown env vars.
    /// Equivalent to `hint_count() == 0`, and delegates to it so the
    /// two peers cannot drift.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hint_count() == 0
    }

    /// Iterate every hint across every surface as [`SurfaceHint`]
    /// values, tagged with the [`HintSurface`] each came from — the
    /// enumeration behind [`Self::hint_count`], and the programmatic
    /// peer of the merged panic message [`ConfigCoverage::assert_healthy`]
    /// emits.
    ///
    /// Yields in canonical order — dead knobs, then stale entries,
    /// then unknown value keys, then unknown env vars — matching
    /// the four sub-string order of `assert_healthy`'s panic message.
    /// Within each surface, hints follow the order of their
    /// underlying hint list (sorted by entry / raw env-var name per
    /// the audit primitives, so the enumeration is deterministic
    /// end-to-end).
    ///
    /// `hint_iter().count()` equals [`Self::hint_count`] by
    /// construction — the two share the four underlying hint lists
    /// and cannot drift. Each yielded [`SurfaceHint`]'s
    /// `(entry, did_you_mean)` pair is exactly what
    /// `assert_healthy` would feed the shared `render_hint_pairs`
    /// renderer for that hint, so a consumer routing this iterator
    /// through the same renderer produces the same text as the panic
    /// path — without having to parse the panic string.
    ///
    /// Consumers that want to render the merged unhealthy diff
    /// programmatically (a structured JSON row per hint for a
    /// diagnostics endpoint; a dashboard table grouped by
    /// [`HintSurface`]; a machine-readable golden fixture that
    /// compares clean and dirty runs across a fleet of consumers)
    /// iterate this directly instead of walking the four hint lists
    /// by hand.
    pub fn hint_iter(&self) -> impl Iterator<Item = SurfaceHint<'_>> {
        let dead_knobs = self.coverage.dead_knobs.iter().map(|h| SurfaceHint {
            surface: HintSurface::DeadKnob,
            entry: h.entry.as_str(),
            did_you_mean: h.did_you_mean.as_deref(),
        });
        let stale_entries = self.coverage.stale_entries.iter().map(|h| SurfaceHint {
            surface: HintSurface::StaleEntry,
            entry: h.entry.as_str(),
            did_you_mean: h.did_you_mean.as_deref(),
        });
        let value_keys = self.value.unknown.iter().map(|h| SurfaceHint {
            surface: HintSurface::ValueKey,
            entry: h.path.as_str(),
            did_you_mean: h.did_you_mean.as_deref(),
        });
        let env_vars = self.env.unknown.iter().map(|h| SurfaceHint {
            surface: HintSurface::EnvVar,
            entry: h.env_var.as_str(),
            did_you_mean: h.did_you_mean.as_deref(),
        });
        dead_knobs
            .chain(stale_entries)
            .chain(value_keys)
            .chain(env_vars)
    }

    /// Iterate every hint on ONE [`HintSurface`], as [`SurfaceHint`]
    /// values — the surface-filtered projection of [`Self::hint_iter`]
    /// (and the enumeration behind [`Self::hint_count_by_surface`]).
    ///
    /// Yields exactly the hints whose surface tag matches `surface`,
    /// in the same order [`Self::hint_iter`] would yield them
    /// (deterministic per-surface: sorted by entry / raw env-var name
    /// per the audit primitives). `hint_iter_by_surface(s).count()`
    /// equals [`Self::hint_count_by_surface`]`(s)` by construction,
    /// and `HintSurface`'s four variants partition [`Self::hint_iter`]
    /// — summing the four per-surface counts recovers
    /// [`Self::hint_count`] with NO cross-surface dedup (a typo counted
    /// on both consumer and env surfaces is two hints, not one), the
    /// same fold-composition invariant
    /// [`Self::hint_count`] already promises.
    ///
    /// Delegates through [`Self::hint_iter`] itself — a
    /// `.filter(|h| h.surface == surface)` — so the two enumerations
    /// cannot drift: any future refactor that changes which underlying
    /// hint list feeds a surface tag flows through to this method
    /// automatically.
    ///
    /// Consumers that want a per-surface dashboard tile ("only show me
    /// env-var typos"), a per-surface remediation counter, or a
    /// per-surface JSON row array on a diagnostics endpoint call this
    /// directly instead of `hint_iter().filter(...)` — the named peer
    /// says "this is the supported access pattern" and pairs with
    /// [`Self::hint_count_by_surface`] on the count side.
    pub fn hint_iter_by_surface(
        &self,
        surface: HintSurface,
    ) -> impl Iterator<Item = SurfaceHint<'_>> {
        self.hint_iter().filter(move |h| h.surface == surface)
    }

    /// Count of hints on ONE [`HintSurface`] — the surface-projected
    /// peer of [`Self::hint_count`] (and the count-side peer of
    /// [`Self::hint_iter_by_surface`]).
    ///
    /// Equals `hint_iter_by_surface(surface).count()` by construction,
    /// since it delegates through that iterator so the two peers cannot
    /// drift. Summing the four per-surface counts recovers
    /// [`Self::hint_count`] with NO cross-surface dedup — the same
    /// fold-composition invariant [`Self::hint_count`] promises across
    /// the three sub-reports, re-projected here onto the four hint
    /// surfaces.
    ///
    /// Consumers that want to prioritise remediation by surface ("which
    /// of my four config surfaces has the most typos"), gate CI on a
    /// per-surface hint-count budget, or feed a per-surface severity
    /// number to a diagnostics endpoint call this directly instead of
    /// hand-walking the four hint lists.
    #[must_use]
    pub fn hint_count_by_surface(&self, surface: HintSurface) -> usize {
        self.hint_iter_by_surface(surface).count()
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
    /// Total count of unknown prefixed env vars — every operator
    /// override in the environment that does NOT correspond to a
    /// schema leaf. The peer of [`Self::is_clean`]
    /// (`is_empty`/`len` shape): `is_clean() ⇔ hint_count() == 0`
    /// holds by construction, since `is_clean` delegates to
    /// `hint_count() == 0`.
    #[must_use]
    pub fn hint_count(&self) -> usize {
        self.unknown.len()
    }

    /// True iff no prefixed env var deviated from the schema — every
    /// operator override in the environment is a real knob.
    /// Equivalent to `hint_count() == 0`, and delegates to it so the
    /// two peers cannot drift.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hint_count() == 0
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
    /// Total count of unknown leaf paths in the operator's config
    /// value — every dotted path in their YAML/TOML that does NOT
    /// correspond to a schema leaf. The peer of [`Self::is_clean`]
    /// (`is_empty`/`len` shape): `is_clean() ⇔ hint_count() == 0`
    /// holds by construction, since `is_clean` delegates to
    /// `hint_count() == 0`.
    #[must_use]
    pub fn hint_count(&self) -> usize {
        self.unknown.len()
    }

    /// True iff no leaf in the value deviated from the schema — every
    /// operator override in the config file is a real knob.
    /// Equivalent to `hint_count() == 0`, and delegates to it so the
    /// two peers cannot drift.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hint_count() == 0
    }
}

/// Render a list of `(entry, did_you_mean)` pairs into the shape used
/// by every [`ConfigCoverage`] assertion panic: `["entry", "other" (did
/// you mean "suggestion"?), ...]`. Empty input renders as `"[]"`.
///
/// The three surface hint types ([`CoverageHint`], [`ValueKeyHint`],
/// [`EnvVarHint`]) each adapt to `(&str, Option<&str>)` via the
/// per-surface `_hint_pairs` helpers below, so
/// [`ConfigCoverage::assert_every_field_consumed`],
/// [`ConfigCoverage::assert_no_unknown_keys`], and
/// [`ConfigCoverage::assert_no_unknown_env_vars`] all produce
/// identically-shaped diagnostics.
fn render_hint_pairs<'a, I>(pairs: I) -> String
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>)>,
{
    let mut iter = pairs.into_iter().peekable();
    if iter.peek().is_none() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (i, (entry, suggestion)) in iter.enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(entry);
        out.push('"');
        if let Some(sug) = suggestion {
            out.push_str(" (did you mean \"");
            out.push_str(sug);
            out.push_str("\"?)");
        }
    }
    out.push(']');
    out
}

/// Adapt a slice of `CoverageHint` for [`fn@render_hint_pairs`] — the
/// dead-knob / stale-entry surface.
fn coverage_hint_pairs(hints: &[CoverageHint]) -> impl Iterator<Item = (&str, Option<&str>)> {
    hints
        .iter()
        .map(|h| (h.entry.as_str(), h.did_you_mean.as_deref()))
}

/// Adapt a slice of `ValueKeyHint` for [`fn@render_hint_pairs`] — the
/// file-value surface.
fn value_key_hint_pairs(hints: &[ValueKeyHint]) -> impl Iterator<Item = (&str, Option<&str>)> {
    hints
        .iter()
        .map(|h| (h.path.as_str(), h.did_you_mean.as_deref()))
}

/// Adapt a slice of `EnvVarHint` for [`fn@render_hint_pairs`] — the
/// env-var surface. Uses the raw `env_var` name (case preserved) so
/// operators see the exact string they typed, and renders the
/// suggestion in env-var form (already produced by
/// [`ConfigCoverage::audit_env_vars`]).
fn env_var_hint_pairs(hints: &[EnvVarHint]) -> impl Iterator<Item = (&str, Option<&str>)> {
    hints
        .iter()
        .map(|h| (h.env_var.as_str(), h.did_you_mean.as_deref()))
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
    fn audit_paths_against_filters_known_and_hints_unknown_over_arbitrary_known_set() {
        // The primitive over an arbitrary `known` set (not derived
        // from a schema). Every path present in `known` drops silently;
        // every remainder pairs with its closest known-neighbour under
        // the typo threshold, sorted by path.
        let known = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let paths = vec![
            "alpha".to_string(),             // known — filtered
            "betta".to_string(),             // typo — surfaces with hint
            "totally.different".to_string(), // unknown — no hint
        ];
        let audits = ConfigCoverage::audit_paths_against(paths, &known);
        assert_eq!(audits.len(), 2);
        // Sorted by path: "betta" < "totally.different"
        assert_eq!(audits[0].path, "betta");
        assert_eq!(audits[0].did_you_mean.as_deref(), Some("beta"));
        assert_eq!(audits[1].path, "totally.different");
        assert!(audits[1].did_you_mean.is_none());
    }

    #[test]
    fn audit_paths_against_returns_empty_when_every_path_is_known() {
        let known = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let paths = vec!["a".to_string(), "b".to_string()];
        let audits = ConfigCoverage::audit_paths_against(paths, &known);
        assert!(audits.is_empty());
    }

    #[test]
    fn audit_paths_equals_audit_paths_against_on_schema_leaf_set() {
        // The routing invariant on the schema-keyed convenience:
        // audit_paths::<T>(paths) must equal audit_paths_against(paths,
        // &schema_leaf_paths::<T>()) pointwise. A future refactor that
        // drifts the two (e.g. audit_paths adds a second filter pass,
        // or changes tie-break ordering) turns this red at the
        // earliest possible seam.
        let paths: Vec<String> = vec![
            "name".into(),
            "window.witdh".into(),
            "totally.unrelated".into(),
            "tags".into(),
        ];
        let via_convenience = ConfigCoverage::audit_paths::<Demo, _>(paths.clone());
        let via_general = ConfigCoverage::audit_paths_against(
            paths,
            &ConfigCoverage::schema_leaf_paths::<Demo>(),
        );
        assert_eq!(
            via_convenience, via_general,
            "audit_paths must equal audit_paths_against on the schema leaves — the primitive is one fold with the schema pre-wired",
        );
    }

    #[test]
    fn hinted_report_stale_entries_equal_audit_paths_against_consumed_vs_schema() {
        // The routing invariant on the stale-entries arm of the
        // coverage report: after deduping consumed via BTreeSet, the
        // stale entries must equal audit_paths_against(consumed_set,
        // &schema) pointwise (modulo the PathHint -> CoverageHint
        // field rename). The two-way relationship between "declared"
        // and "consumed" collapses to symmetry through the shared
        // fold.
        let consumed = &[
            "name",
            "tags",
            "window.width",
            "window.witdh", // typo — stale
            "window.height",
            "totally_unrelated", // unknown — stale, no hint
        ];
        let hinted = ConfigCoverage::hinted_report::<Demo>(consumed);
        let schema = ConfigCoverage::schema_leaf_paths::<Demo>();
        let consumed_set: BTreeSet<String> = consumed.iter().map(|s| (*s).to_string()).collect();
        let manual = ConfigCoverage::audit_paths_against(consumed_set.iter().cloned(), &schema);
        let via_report: Vec<(String, Option<String>)> = hinted
            .stale_entries
            .into_iter()
            .map(|h| (h.entry, h.did_you_mean))
            .collect();
        let via_general: Vec<(String, Option<String>)> = manual
            .into_iter()
            .map(|PathHint { path, did_you_mean }| (path, did_you_mean))
            .collect();
        assert_eq!(
            via_report, via_general,
            "hinted_report::stale_entries must equal audit_paths_against(consumed_deduped, &schema) — one fold, one keying",
        );
    }

    #[test]
    fn hinted_report_dead_knobs_equal_audit_paths_against_schema_vs_consumed() {
        // The routing invariant on the dead-knobs arm: schema leaves
        // NOT present in consumed must equal audit_paths_against(
        // schema, &consumed) pointwise. The tie-break for
        // did_you_mean follows consumed's original order (as passed
        // to hinted_report), so pass the same &consumed_owned to the
        // manual call. The mirror direction of the coverage report is
        // the same fold with (paths, known) swapped.
        let consumed = &["name", "tags", "window.witdh"]; // window.width and window.height dead
        let hinted = ConfigCoverage::hinted_report::<Demo>(consumed);
        let schema = ConfigCoverage::schema_leaf_paths::<Demo>();
        let consumed_owned: Vec<String> = consumed.iter().map(|s| (*s).to_string()).collect();
        let manual = ConfigCoverage::audit_paths_against(schema.iter().cloned(), &consumed_owned);
        let via_report: Vec<(String, Option<String>)> = hinted
            .dead_knobs
            .into_iter()
            .map(|h| (h.entry, h.did_you_mean))
            .collect();
        let via_general: Vec<(String, Option<String>)> = manual
            .into_iter()
            .map(|PathHint { path, did_you_mean }| (path, did_you_mean))
            .collect();
        assert_eq!(
            via_report, via_general,
            "hinted_report::dead_knobs must equal audit_paths_against(schema, &consumed) — the mirror direction of the same fold",
        );
    }

    #[test]
    fn hinted_report_symmetry_a_typo_paired_across_both_arms() {
        // The clearest demonstration of the collapsed symmetry: a
        // typoed consumed entry produces BOTH a stale entry (the typo,
        // hinted at the schema leaf) AND a dead knob (the schema
        // leaf, hinted at the typo). Both come from the same primitive
        // with (paths, known) swapped — the two-way pairing is not a
        // bespoke double-set-difference, it is the fold applied twice
        // with the arguments transposed.
        let hinted = ConfigCoverage::hinted_report::<Demo>(&[
            "name",
            "tags",
            "window.witdh", // typo — schema leaf window.width is now dead
            "window.height",
        ]);
        assert_eq!(hinted.stale_entries.len(), 1);
        assert_eq!(hinted.stale_entries[0].entry, "window.witdh");
        assert_eq!(
            hinted.stale_entries[0].did_you_mean.as_deref(),
            Some("window.width"),
        );
        assert_eq!(hinted.dead_knobs.len(), 1);
        assert_eq!(hinted.dead_knobs[0].entry, "window.width");
        assert_eq!(
            hinted.dead_knobs[0].did_you_mean.as_deref(),
            Some("window.witdh"),
            "the mirror direction must pair the dead knob with the typo it lost consumer coverage to",
        );
    }

    #[test]
    fn assert_no_unknown_keys_does_not_panic_on_clean_value() {
        // A value shaped exactly like the schema audits clean and the
        // assertion returns without panicking. The routing invariant on
        // the file surface: assert_no_unknown_keys wraps audit_value's
        // is_clean() with the shared panic-rendering fold, so an audit
        // that is_clean() MUST NOT panic here.
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: [a, b]
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
    }

    #[test]
    #[should_panic(expected = "\"window.witdh\" (did you mean \"window.width\"?)")]
    fn assert_no_unknown_keys_panic_message_includes_did_you_mean_hint() {
        // The value-surface analog of the schema-vs-consumer typo panic
        // test: a one-transposition typo on window.width must surface
        // in the panic string paired with the schema leaf, in the same
        // `"entry" (did you mean "suggestion"?)` shape that
        // assert_every_field_consumed produces.
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
    }

    #[test]
    #[should_panic(expected = "unknown keys (remove or correct):")]
    fn assert_no_unknown_keys_panic_message_includes_headline() {
        // Pin the operator-facing headline verbatim so a future refactor
        // cannot silently drop the "which surface failed" cue that tells
        // the operator the failure is in their YAML file (not their env,
        // not their consumer list).
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
totally.unrelated: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
    }

    #[test]
    fn assert_no_unknown_env_vars_does_not_panic_on_clean_environment() {
        // Every prefixed env var corresponds to a real schema leaf —
        // the assertion returns without panicking. Unrelated env vars
        // outside the prefix are silently dropped (they are not
        // shikumi's problem), so PATH / HOME must not turn this red.
        let env: Vec<(String, String)> = vec![
            ("MYAPP_NAME".into(), "kanchi".into()),
            ("MYAPP_WINDOW__WIDTH".into(), "100".into()),
            ("MYAPP_WINDOW__HEIGHT".into(), "40".into()),
            ("PATH".into(), "/usr/bin".into()),
        ];
        ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
    }

    #[test]
    #[should_panic(expected = "\"MYAPP_WINDOW__WITDH\" (did you mean \"MYAPP_WINDOW__WIDTH\"?)")]
    fn assert_no_unknown_env_vars_panic_message_includes_env_var_form_hint() {
        // The env-var-surface analog: the panic must name BOTH the raw
        // env var the operator typed AND the suggestion **in env-var
        // form** — the operator sees exactly the name they should have
        // set, not a dotted path they have to re-encode. This is the
        // asymmetry with the value/consumer surfaces: env-var hints go
        // through path_to_env_var before rendering.
        let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
    }

    #[test]
    #[should_panic(expected = "unknown env vars (remove or correct):")]
    fn assert_no_unknown_env_vars_panic_message_includes_headline() {
        // Same "which surface failed" cue as the value-surface assertion
        // — the operator instantly knows the failure is in their
        // environment, not in a YAML file or a consumer list. Prevents
        // a future refactor from collapsing the three surface headlines
        // into one indistinguishable message.
        let env: Vec<(String, String)> = vec![("MYAPP_UNRELATED_KNOB".into(), "x".into())];
        ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
    }

    #[test]
    #[should_panic(expected = "\"MYAPP_UNRELATED_KNOB\"")]
    fn assert_no_unknown_env_vars_panic_still_names_entry_without_hint() {
        // A prefixed but totally-unrelated env var has no near
        // schema-leaf neighbour (no hint), but the panic must still
        // name the offending entry — the assertion never silently drops
        // an unknown just because it lacks a suggestion.
        let env: Vec<(String, String)> = vec![("MYAPP_UNRELATED_KNOB".into(), "x".into())];
        ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
    }

    #[test]
    fn assert_panic_messages_use_same_hint_rendering_across_all_three_surfaces() {
        // The routing theorem: all three assertion surfaces
        // (assert_every_field_consumed, assert_no_unknown_keys,
        // assert_no_unknown_env_vars) render their hint list through
        // the same shared render_hint_pairs primitive, so an operator
        // reading a failure message sees identically-shaped output
        // regardless of which surface caught the typo. Verify by
        // catching each panic and comparing the rendered hint substring.
        let consumer_panic = std::panic::catch_unwind(|| {
            ConfigCoverage::assert_every_field_consumed::<Demo>(&[
                "name",
                "tags",
                "window.witdh",
                "window.height",
            ]);
        })
        .expect_err("consumer surface must panic on the typo");
        let value_panic = std::panic::catch_unwind(|| {
            let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
            let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
        })
        .expect_err("value surface must panic on the typo");
        let env_panic = std::panic::catch_unwind(|| {
            let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
            ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
        })
        .expect_err("env surface must panic on the typo");
        let msg = |p: &Box<dyn std::any::Any + Send>| -> String {
            if let Some(s) = p.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                panic!("panic payload was neither &str nor String")
            }
        };
        // All three panic messages contain the shared "(did you mean
        // \"…\"?)" shape produced by render_hint_pairs — the exact leaf
        // name differs by surface (dotted vs env-var form), but the
        // suffix is the tell.
        for m in [msg(&consumer_panic), msg(&value_panic), msg(&env_panic)] {
            assert!(
                m.contains("(did you mean \""),
                "panic message must route through render_hint_pairs: {m}",
            );
            assert!(
                m.contains("\"?)"),
                "panic message must close the render_hint_pairs suggestion: {m}",
            );
        }
    }

    #[test]
    fn assert_no_unknown_keys_and_assert_no_unknown_env_vars_agree_on_same_typo() {
        // The cross-surface twin: the same underlying typo, expressed
        // once as YAML and once as an env var, produces panic messages
        // whose hint suggestions map to the same schema leaf modulo
        // env-var-form rendering. Locks the two new assertions to
        // audit_value / audit_env_vars's shared audit_paths fold — a
        // future refactor drifting either surface turns this red.
        let value_panic = std::panic::catch_unwind(|| {
            let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
            let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
        })
        .expect_err("value surface must panic on the typo");
        let env_panic = std::panic::catch_unwind(|| {
            let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
            ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", &env);
        })
        .expect_err("env surface must panic on the typo");
        let msg = |p: &Box<dyn std::any::Any + Send>| -> String {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&'static str>().map(|s| (*s).to_string()))
                .expect("panic payload was neither &str nor String")
        };
        let v = msg(&value_panic);
        let e = msg(&env_panic);
        assert!(
            v.contains("window.witdh") && v.contains("window.width"),
            "value panic must name both the typo and the schema leaf: {v}",
        );
        assert!(
            e.contains("MYAPP_WINDOW__WITDH") && e.contains("MYAPP_WINDOW__WIDTH"),
            "env panic must name both the typo and the schema leaf in env-var form: {e}",
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

    // ─── health_report / assert_healthy — the one-shot combined check ───

    #[test]
    fn health_report_is_clean_when_every_surface_is_clean() {
        // The fully-healthy state: every consumer entry maps to a
        // schema leaf, the value has no unknown keys, and every
        // prefixed env var is a real knob. `is_clean` must be true
        // and each sub-report must be clean individually.
        let consumed = &["name", "tags", "window.width", "window.height"];
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: [a, b]
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![
            ("MYAPP_NAME".into(), "kanchi".into()),
            ("MYAPP_WINDOW__WIDTH".into(), "100".into()),
            ("PATH".into(), "/usr/bin".into()), // outside prefix — ignored
        ];
        let report = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        assert!(report.is_clean(), "expected clean health, got {report:?}");
        assert!(report.coverage.is_clean());
        assert!(report.value.is_clean());
        assert!(report.env.is_clean());
    }

    #[test]
    fn assert_healthy_does_not_panic_on_healthy_input() {
        let consumed = &["name", "tags", "window.width", "window.height"];
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: [a, b]
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WIDTH".into(), "100".into()),
            ("PATH".into(), "/usr/bin".into()),
        ];
        ConfigCoverage::assert_healthy::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
    }

    #[test]
    fn health_report_equals_running_each_individual_audit() {
        // The fold-composition invariant: health_report.{coverage,
        // value, env} must equal hinted_report / audit_value /
        // audit_env_vars called independently on the same inputs.
        // health_report is the sum of the three primitives with no
        // cross-surface logic — a future refactor that adds hidden
        // coupling between surfaces (e.g. suppressing an env-var
        // typo because the same leaf is present in `consumed`) turns
        // this red at the earliest possible seam.
        let consumed = &["name", "tags", "window.witdh", "window.height"];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
totally_unrelated: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WITDH".into(), "100".into()),
            ("MYAPP_UNRELATED_KNOB".into(), "x".into()),
        ];
        let combined =
            ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        assert_eq!(
            combined.coverage,
            ConfigCoverage::hinted_report::<Demo>(consumed)
        );
        assert_eq!(combined.value, ConfigCoverage::audit_value::<Demo>(&value));
        assert_eq!(
            combined.env,
            ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env),
        );
    }

    #[test]
    fn health_report_is_dirty_when_any_single_surface_is_dirty() {
        // The disjunction invariant: is_clean is false iff ANY surface
        // is dirty. Verify pointwise by dirtying one surface at a time
        // — the two clean surfaces must stay clean, the dirty one
        // surfaces, and is_clean() is false.
        let clean_consumed = &["name", "tags", "window.width", "window.height"];
        let clean_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let clean_value: serde_yaml::Value = serde_yaml::from_str(clean_yaml).unwrap();
        let clean_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())];
        // Only consumer surface dirty (a stale extra entry).
        let dirty_consumed = &[
            "name",
            "tags",
            "window.width",
            "window.height",
            "window.depth",
        ];
        let r = ConfigCoverage::health_report::<Demo, _, _>(
            dirty_consumed,
            &clean_value,
            "MYAPP_",
            &clean_env,
        );
        assert!(!r.is_clean());
        assert!(!r.coverage.is_clean());
        assert!(r.value.is_clean());
        assert!(r.env.is_clean());
        // Only value surface dirty (an unknown YAML key).
        let dirty_yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let dirty_value: serde_yaml::Value = serde_yaml::from_str(dirty_yaml).unwrap();
        let r = ConfigCoverage::health_report::<Demo, _, _>(
            clean_consumed,
            &dirty_value,
            "MYAPP_",
            &clean_env,
        );
        assert!(!r.is_clean());
        assert!(r.coverage.is_clean());
        assert!(!r.value.is_clean());
        assert!(r.env.is_clean());
        // Only env surface dirty (a misspelled prefixed env var).
        let dirty_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let r = ConfigCoverage::health_report::<Demo, _, _>(
            clean_consumed,
            &clean_value,
            "MYAPP_",
            &dirty_env,
        );
        assert!(!r.is_clean());
        assert!(r.coverage.is_clean());
        assert!(r.value.is_clean());
        assert!(!r.env.is_clean());
    }

    #[test]
    #[should_panic(expected = "config unhealthy across surfaces.")]
    fn assert_healthy_panic_message_includes_multi_surface_headline() {
        // Pin the operator-facing multi-surface headline verbatim so a
        // future refactor cannot silently collapse it into
        // one of the single-surface panics — the operator instantly
        // knows the failure crossed surface boundaries and where each
        // sub-diagnostic came from.
        let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        ConfigCoverage::assert_healthy::<Demo, _, _>(
            &["name", "tags", "window.width", "window.height"],
            &value,
            "MYAPP_",
            &env,
        );
    }

    #[test]
    fn assert_healthy_panic_names_every_dirty_surface_in_one_shot() {
        // The multi-surface diagnostic theorem: dirty ALL three
        // surfaces at once and verify the single panic string names
        // the failing entry from each surface — the whole point of
        // the one-shot check is that operators see the complete
        // picture in one panic instead of playing whack-a-mole one
        // assertion at a time. Uses catch_unwind because
        // #[should_panic(expected = …)] can only match one substring.
        let consumed = &[
            "name",
            "tags",
            "window.width",
            "window.height",
            "consumer_only_leaf", // stale entry on consumer surface
        ];
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())];
        let payload = std::panic::catch_unwind(|| {
            ConfigCoverage::assert_healthy::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        })
        .expect_err("all three surfaces dirty → assert_healthy must panic");
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                payload
                    .downcast_ref::<&'static str>()
                    .map(|s| (*s).to_string())
            })
            .expect("panic payload was neither &str nor String");
        assert!(
            msg.contains("consumer_only_leaf"),
            "panic must name the stale consumer entry: {msg}",
        );
        assert!(
            msg.contains("value_only_leaf"),
            "panic must name the unknown value key: {msg}",
        );
        assert!(
            msg.contains("MYAPP_ENV_ONLY_LEAF"),
            "panic must name the unknown env var (raw name): {msg}",
        );
    }

    #[test]
    fn assert_healthy_panic_still_uses_shared_render_hint_pairs_across_surfaces() {
        // Extend the routing theorem to the merged assertion: the
        // did-you-mean-shaped hint suffix produced by render_hint_pairs
        // must appear for at least one entry per dirty surface that
        // had a near neighbour — proving the merged panic path routes
        // ALL surface hints through the same shared renderer, not a
        // bespoke one-off formatter for the combined case.
        let consumed = &[
            "name",
            "tags",
            "window.width",
            "window.height",
            "window.heigth", // typo → nearest schema leaf is window.height
        ];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let payload = std::panic::catch_unwind(|| {
            ConfigCoverage::assert_healthy::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        })
        .expect_err("all three surfaces dirty → assert_healthy must panic");
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                payload
                    .downcast_ref::<&'static str>()
                    .map(|s| (*s).to_string())
            })
            .expect("panic payload was neither &str nor String");
        // Consumer-surface hint (dotted-path form).
        assert!(
            msg.contains("\"window.heigth\" (did you mean \"window.height\"?)"),
            "consumer-surface hint must render through render_hint_pairs: {msg}",
        );
        // Value-surface hint (dotted-path form).
        assert!(
            msg.contains("\"window.witdh\" (did you mean \"window.width\"?)"),
            "value-surface hint must render through render_hint_pairs: {msg}",
        );
        // Env-surface hint (env-var form).
        assert!(
            msg.contains("\"MYAPP_WINDOW__WITDH\" (did you mean \"MYAPP_WINDOW__WIDTH\"?)"),
            "env-surface hint must render through render_hint_pairs: {msg}",
        );
    }

    #[test]
    fn assert_healthy_panics_iff_any_individual_assertion_would_panic() {
        // The equivalence theorem: assert_healthy panics ⇔ any of the
        // three individual assertions would panic on the same inputs.
        // Enumerate the 2³ boolean corners over which surfaces are
        // dirty and verify the equivalence pointwise.
        let clean_consumed = &["name", "tags", "window.width", "window.height"];
        let dirty_consumed = &[
            "name",
            "tags",
            "window.width",
            "window.height",
            "extra_leaf",
        ];
        let clean_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let dirty_yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let clean_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())];
        let dirty_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        for &(c_dirty, v_dirty, e_dirty) in &[
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            let consumed = if c_dirty {
                dirty_consumed.as_slice()
            } else {
                clean_consumed.as_slice()
            };
            let yaml = if v_dirty { dirty_yaml } else { clean_yaml };
            let env = if e_dirty { &dirty_env } else { &clean_env };
            let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            let any_dirty = c_dirty || v_dirty || e_dirty;
            let healthy_panicked = std::panic::catch_unwind(|| {
                ConfigCoverage::assert_healthy::<Demo, _, _>(consumed, &value, "MYAPP_", env);
            })
            .is_err();
            assert_eq!(
                healthy_panicked, any_dirty,
                "assert_healthy must panic iff any surface dirty; corner ({c_dirty},{v_dirty},{e_dirty})",
            );
            // And a spot-check against the individual assertions on
            // the same corner: OR-ing their panic outcomes must equal
            // healthy_panicked.
            let consumer_panicked = std::panic::catch_unwind(|| {
                ConfigCoverage::assert_every_field_consumed::<Demo>(consumed);
            })
            .is_err();
            let value_panicked = std::panic::catch_unwind(|| {
                ConfigCoverage::assert_no_unknown_keys::<Demo>(&value);
            })
            .is_err();
            let env_panicked = std::panic::catch_unwind(|| {
                ConfigCoverage::assert_no_unknown_env_vars::<Demo, _, _>("MYAPP_", env);
            })
            .is_err();
            assert_eq!(
                healthy_panicked,
                consumer_panicked || value_panicked || env_panicked,
                "assert_healthy panic ⇔ OR of individual panics; corner ({c_dirty},{v_dirty},{e_dirty})",
            );
        }
    }

    #[test]
    fn hint_count_is_zero_iff_is_clean_across_every_report_type() {
        // The construction-true equivalence theorem for every report
        // type that carries an `is_clean` predicate: `is_clean() ⇔
        // hint_count() == 0`. Because `is_clean` on all four types
        // delegates to `hint_count() == 0`, this is a construction
        // check — a future refactor that reroutes `is_clean` to any
        // other primitive turns this red at the earliest possible
        // seam. Verified pointwise on both the clean and dirty
        // corner of every report type produced by `ConfigCoverage`.
        //
        // Clean corner: fully-consistent inputs on every surface —
        // all four counts must be zero and every predicate must be
        // true.
        let clean_consumed = &["name", "tags", "window.width", "window.height"];
        let clean_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let clean_value: serde_yaml::Value = serde_yaml::from_str(clean_yaml).unwrap();
        let clean_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())];
        let clean_coverage = ConfigCoverage::hinted_report::<Demo>(clean_consumed);
        let clean_value_audit = ConfigCoverage::audit_value::<Demo>(&clean_value);
        let clean_env_audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &clean_env);
        let clean_health = ConfigCoverage::health_report::<Demo, _, _>(
            clean_consumed,
            &clean_value,
            "MYAPP_",
            &clean_env,
        );
        assert_eq!(clean_coverage.hint_count(), 0);
        assert!(clean_coverage.is_clean());
        assert_eq!(clean_value_audit.hint_count(), 0);
        assert!(clean_value_audit.is_clean());
        assert_eq!(clean_env_audit.hint_count(), 0);
        assert!(clean_env_audit.is_clean());
        assert_eq!(clean_health.hint_count(), 0);
        assert!(clean_health.is_clean());

        // Dirty corner: dirty each surface once — the count must be
        // strictly positive and the predicate must be false. This
        // catches a future refactor that accidentally rewires
        // `is_clean` to a stale AND-of-lists shape while
        // `hint_count` correctly counts, or vice versa.
        let dirty_consumed = &["name", "tags", "window.witdh", "window.height"];
        let dirty_coverage = ConfigCoverage::hinted_report::<Demo>(dirty_consumed);
        assert!(dirty_coverage.hint_count() > 0);
        assert!(!dirty_coverage.is_clean());
        let dirty_yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let dirty_value: serde_yaml::Value = serde_yaml::from_str(dirty_yaml).unwrap();
        let dirty_value_audit = ConfigCoverage::audit_value::<Demo>(&dirty_value);
        assert!(dirty_value_audit.hint_count() > 0);
        assert!(!dirty_value_audit.is_clean());
        let dirty_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let dirty_env_audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &dirty_env);
        assert!(dirty_env_audit.hint_count() > 0);
        assert!(!dirty_env_audit.is_clean());
        let dirty_health = ConfigCoverage::health_report::<Demo, _, _>(
            dirty_consumed,
            &dirty_value,
            "MYAPP_",
            &dirty_env,
        );
        assert!(dirty_health.hint_count() > 0);
        assert!(!dirty_health.is_clean());
    }

    #[test]
    fn hinted_coverage_hint_count_equals_dead_knobs_plus_stale_entries() {
        // The additive-composition invariant on the schema-vs-consumer
        // surface: hint_count is exactly the sum of the two hint
        // lists, verified on an input that populates BOTH arms so a
        // future refactor that collapses one arm out of the sum
        // turns red.
        //
        // `window.witdh` in `consumed` (typo) → 1 stale entry.
        // `window.width` missing from `consumed` → 1 dead knob.
        // Total hint_count == 2.
        let consumed = &["name", "tags", "window.witdh", "window.height"];
        let hinted = ConfigCoverage::hinted_report::<Demo>(consumed);
        assert_eq!(hinted.dead_knobs.len(), 1);
        assert_eq!(hinted.stale_entries.len(), 1);
        assert_eq!(hinted.hint_count(), 2);
        assert_eq!(
            hinted.hint_count(),
            hinted.dead_knobs.len() + hinted.stale_entries.len(),
        );
    }

    #[test]
    fn value_and_env_hint_counts_equal_their_unknown_list_lengths() {
        // The additive-composition invariant on the file-value and
        // env surfaces: each hint_count is exactly the length of the
        // single `unknown` list on its report, verified on an input
        // with a nonzero count so a future refactor cannot silently
        // route hint_count through a stale predicate.
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
  totally_extra: 1
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let value_audit = ConfigCoverage::audit_value::<Demo>(&value);
        assert_eq!(value_audit.hint_count(), value_audit.unknown.len());
        assert!(value_audit.hint_count() >= 2, "{value_audit:?}");
        let env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WITDH".into(), "1".into()),
            ("MYAPP_UNRELATED_KNOB".into(), "x".into()),
            ("MYAPP_ANOTHER_STRAY".into(), "y".into()),
        ];
        let env_audit = ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env);
        assert_eq!(env_audit.hint_count(), env_audit.unknown.len());
        assert_eq!(env_audit.hint_count(), 3);
    }

    #[test]
    fn health_report_hint_count_equals_sum_of_surface_hint_counts() {
        // The fold-composition invariant that makes `HealthReport`
        // safe to interpret as one severity number: its hint_count
        // is exactly the sum of the three surface hint_counts, with
        // NO cross-surface dedup (a typo counted on both consumer
        // and env surfaces is two hints, not one). A future refactor
        // that introduces hidden cross-surface coupling — the same
        // failure mode `health_report_equals_running_each_individual_audit`
        // pins on the report level — turns red here on the count
        // roll-up.
        let consumed = &["name", "tags", "window.witdh", "window.height"];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
totally_unrelated: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WITDH".into(), "1".into()),
            ("MYAPP_UNRELATED_KNOB".into(), "x".into()),
        ];
        let health = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        assert_eq!(
            health.hint_count(),
            health.coverage.hint_count() + health.value.hint_count() + health.env.hint_count(),
        );
        // And the surface counts equal running the primitives in
        // isolation — pins that HealthReport hasn't stolen any count
        // from its sub-reports.
        assert_eq!(
            health.coverage.hint_count(),
            ConfigCoverage::hinted_report::<Demo>(consumed).hint_count(),
        );
        assert_eq!(
            health.value.hint_count(),
            ConfigCoverage::audit_value::<Demo>(&value).hint_count(),
        );
        assert_eq!(
            health.env.hint_count(),
            ConfigCoverage::audit_env_vars::<Demo, _, _>("MYAPP_", &env).hint_count(),
        );
        // Every hint must show up in the total — bound the sum from
        // below.
        assert!(health.hint_count() >= 3, "{health:?}");
    }

    // ─── hint_iter — surface-tagged programmatic enumeration ────────

    #[test]
    fn health_report_hint_iter_count_equals_hint_count() {
        // The construction-true invariant that welds the enumeration
        // to the number: `hint_iter().count()` equals `hint_count()`
        // on both the clean and the fully-dirty corner. A future
        // refactor that drops or duplicates any hint list in either
        // method turns this red on the clean corner (both must be 0)
        // and on the dirty corner (both must be strictly positive and
        // equal).
        let clean_consumed = &["name", "tags", "window.width", "window.height"];
        let clean_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let clean_value: serde_yaml::Value = serde_yaml::from_str(clean_yaml).unwrap();
        let clean_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())];
        let clean_health = ConfigCoverage::health_report::<Demo, _, _>(
            clean_consumed,
            &clean_value,
            "MYAPP_",
            &clean_env,
        );
        assert_eq!(clean_health.hint_iter().count(), clean_health.hint_count());
        assert_eq!(clean_health.hint_iter().count(), 0);

        let dirty_consumed = &[
            "name",
            "tags",
            "window.witdh",
            "window.height",
            "consumer_only_leaf",
        ];
        let dirty_yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let dirty_value: serde_yaml::Value = serde_yaml::from_str(dirty_yaml).unwrap();
        let dirty_env: Vec<(String, String)> = vec![
            ("MYAPP_WINDOW__WITDH".into(), "1".into()),
            ("MYAPP_ENV_ONLY_LEAF".into(), "x".into()),
        ];
        let dirty_health = ConfigCoverage::health_report::<Demo, _, _>(
            dirty_consumed,
            &dirty_value,
            "MYAPP_",
            &dirty_env,
        );
        assert_eq!(dirty_health.hint_iter().count(), dirty_health.hint_count());
        assert!(dirty_health.hint_iter().count() > 0);
    }

    #[test]
    fn health_report_hint_iter_yields_every_hint_tagged_by_surface_of_origin() {
        // Dirty each surface with a distinct entry so the four
        // surface tags each appear exactly once and every entry is
        // uniquely identifiable — pins the routing invariant that
        // hint_iter tags every hint with the surface of its
        // underlying hint list (no cross-surface confusion).
        //
        // `window.witdh` in consumed → StaleEntry (typo).
        // `window.width` missing from consumed → DeadKnob.
        // `value_only_leaf` in YAML → ValueKey.
        // `MYAPP_ENV_ONLY_LEAF` in env → EnvVar.
        let consumed = &["name", "tags", "window.witdh", "window.height"];
        let yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())];
        let health = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        let hints: Vec<SurfaceHint<'_>> = health.hint_iter().collect();
        // Exactly one hint per surface, so the count is 4.
        assert_eq!(hints.len(), 4, "{hints:?}");
        // Each surface tag paired with the expected entry — one and
        // only one per surface.
        let dead: Vec<_> = hints
            .iter()
            .filter(|h| h.surface == HintSurface::DeadKnob)
            .collect();
        assert_eq!(dead.len(), 1, "{hints:?}");
        assert_eq!(dead[0].entry, "window.width");
        let stale: Vec<_> = hints
            .iter()
            .filter(|h| h.surface == HintSurface::StaleEntry)
            .collect();
        assert_eq!(stale.len(), 1, "{hints:?}");
        assert_eq!(stale[0].entry, "window.witdh");
        let value_hints: Vec<_> = hints
            .iter()
            .filter(|h| h.surface == HintSurface::ValueKey)
            .collect();
        assert_eq!(value_hints.len(), 1, "{hints:?}");
        assert_eq!(value_hints[0].entry, "value_only_leaf");
        let env_hints: Vec<_> = hints
            .iter()
            .filter(|h| h.surface == HintSurface::EnvVar)
            .collect();
        assert_eq!(env_hints.len(), 1, "{hints:?}");
        assert_eq!(env_hints[0].entry, "MYAPP_ENV_ONLY_LEAF");
    }

    #[test]
    fn health_report_hint_iter_canonical_order_is_dead_stale_value_env() {
        // Pin the canonical yield order: all DeadKnob hints first,
        // then all StaleEntry, then all ValueKey, then all EnvVar.
        // Mirrors the four sub-string order of assert_healthy's panic
        // message — a future refactor that reorders one against the
        // other turns this red so the two paths cannot drift.
        //
        // Dirty all four surfaces at once.
        let consumed = &[
            "name",
            "tags",
            "window.witdh",
            "window.height",
            "consumer_only_leaf",
        ];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())];
        let health = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        let surfaces: Vec<HintSurface> = health.hint_iter().map(|h| h.surface).collect();
        // Walk the yielded surfaces and check the four groups appear
        // in the canonical order — every occurrence of surface k+1
        // must come strictly after every occurrence of surface k.
        let order = [
            HintSurface::DeadKnob,
            HintSurface::StaleEntry,
            HintSurface::ValueKey,
            HintSurface::EnvVar,
        ];
        let mut last_rank_seen: Option<usize> = None;
        for surface in &surfaces {
            let rank = order
                .iter()
                .position(|s| s == surface)
                .expect("hint_iter yielded an unknown HintSurface variant");
            if let Some(prev) = last_rank_seen {
                assert!(
                    rank >= prev,
                    "hint_iter must yield surfaces in canonical order dead→stale→value→env, \
                     but saw {surface:?} (rank {rank}) after rank {prev} in {surfaces:?}",
                );
            }
            last_rank_seen = Some(rank);
        }
    }

    #[test]
    fn health_report_hint_iter_pairs_route_through_render_hint_pairs_identically_to_assert_healthy()
    {
        // The routing theorem that welds hint_iter to the panic path:
        // grouping hint_iter by surface and rendering each group
        // through render_hint_pairs produces byte-for-byte the same
        // four sub-strings assert_healthy emits from its per-surface
        // *_hint_pairs adapters. A future refactor that drifts either
        // path — hint_iter picking the normalized_path for env vars,
        // assert_healthy switching to a bespoke renderer, either side
        // reordering entries — turns this red on the mismatched
        // sub-string.
        let consumed = &[
            "name",
            "tags",
            "window.width",
            "window.height",
            "window.heigth", // typo → nearest schema leaf is window.height
        ];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WITDH".into(), "100".into())];
        let health = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);
        // Route hint_iter through render_hint_pairs, grouped by
        // surface, into the four sub-strings the panic path emits.
        let render_surface = |surface: HintSurface| -> String {
            render_hint_pairs(
                health
                    .hint_iter()
                    .filter(|h| h.surface == surface)
                    .map(|h| (h.entry, h.did_you_mean)),
            )
        };
        // And route each per-surface *_hint_pairs adapter through
        // render_hint_pairs the way assert_healthy does — this is the
        // canonical source of truth.
        assert_eq!(
            render_surface(HintSurface::DeadKnob),
            render_hint_pairs(coverage_hint_pairs(&health.coverage.dead_knobs)),
        );
        assert_eq!(
            render_surface(HintSurface::StaleEntry),
            render_hint_pairs(coverage_hint_pairs(&health.coverage.stale_entries)),
        );
        assert_eq!(
            render_surface(HintSurface::ValueKey),
            render_hint_pairs(value_key_hint_pairs(&health.value.unknown)),
        );
        assert_eq!(
            render_surface(HintSurface::EnvVar),
            render_hint_pairs(env_var_hint_pairs(&health.env.unknown)),
        );
    }

    #[test]
    fn health_report_hint_iter_env_entry_is_raw_env_var_not_normalized_path() {
        // Pin the env-surface entry choice: hint_iter yields the raw
        // env-var name (case preserved) — the same string the operator
        // typed and the same string env_var_hint_pairs feeds into
        // render_hint_pairs — not the intermediate normalized dotted
        // path. A future refactor that flips to normalized_path would
        // regress operator UX (they see a synthetic path they never
        // set) and turns this red.
        let env: Vec<(String, String)> = vec![("MYAPP_TOTALLY_MADE_UP".into(), "x".into())];
        let health = ConfigCoverage::health_report::<Demo, _, _>(
            &["name", "tags", "window.width", "window.height"],
            &serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            "MYAPP_",
            &env,
        );
        let env_hint = health
            .hint_iter()
            .find(|h| h.surface == HintSurface::EnvVar)
            .expect("dirty env surface must yield an EnvVar hint");
        assert_eq!(env_hint.entry, "MYAPP_TOTALLY_MADE_UP");
        // Sanity: the underlying EnvVarHint's normalized_path is
        // NOT what hint_iter surfaces.
        let underlying = health
            .env
            .unknown
            .iter()
            .find(|h| h.env_var == "MYAPP_TOTALLY_MADE_UP")
            .expect("env audit must carry the hint");
        assert_ne!(
            env_hint.entry, underlying.normalized_path,
            "hint_iter must surface raw env-var, not normalized path",
        );
    }

    // ─── hint_iter_by_surface / hint_count_by_surface — per-surface
    // ─── projection peers of hint_iter / hint_count ────────────────

    /// Every surface a `HealthReport` recognises, in the canonical
    /// yield order pinned by
    /// `health_report_hint_iter_canonical_order_is_dead_stale_value_env`.
    /// Local to these tests; the partition invariants below iterate
    /// this list once so a future surface variant needs to be added
    /// here (and only here) for the partition proofs to keep covering
    /// every variant.
    const ALL_HINT_SURFACES: [HintSurface; 4] = [
        HintSurface::DeadKnob,
        HintSurface::StaleEntry,
        HintSurface::ValueKey,
        HintSurface::EnvVar,
    ];

    #[test]
    fn health_report_hint_iter_by_surface_partitions_hint_iter() {
        // The construction-true partition invariant that welds the
        // four per-surface projections back to the whole:
        //   (a) each hint_iter_by_surface(s) yields ONLY hints tagged
        //       with s (per-surface tag purity — no cross-surface
        //       leak);
        //   (b) each hint_iter_by_surface(s) yields ALL hints tagged
        //       with s (per-surface coverage — no dropped hints);
        //   (c) the four per-surface hints re-chained in canonical
        //       order equal hint_iter itself byte-for-byte on
        //       (surface, entry, did_you_mean).
        // Together these three pin `HintSurface` as the partition tag
        // of hint_iter — the four variants cover every hint exactly
        // once, in the same canonical order.
        //
        // Dirty all four surfaces at once so every variant carries a
        // hint and none of the assertions vacuously pass.
        let consumed = &[
            "name",
            "tags",
            "window.witdh",
            "window.height",
            "consumer_only_leaf",
        ];
        let yaml = "\
name: kanchi
window:
  witdh: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let env: Vec<(String, String)> = vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())];
        let health = ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", &env);

        // (a) + (b): the surface-tag equivalence with the manually
        // filtered projection of hint_iter — everything hint_iter tags
        // as s, and nothing else, appears in hint_iter_by_surface(s).
        for surface in ALL_HINT_SURFACES {
            let projected: Vec<SurfaceHint<'_>> = health.hint_iter_by_surface(surface).collect();
            let manually_filtered: Vec<SurfaceHint<'_>> = health
                .hint_iter()
                .filter(|h| h.surface == surface)
                .collect();
            assert_eq!(projected, manually_filtered, "surface={surface:?}");
            // Every yielded hint really carries the requested tag
            // (belt-and-braces: prevents a filter-side regression from
            // silently passing the equivalence above).
            for hint in &projected {
                assert_eq!(hint.surface, surface, "surface={surface:?} hint={hint:?}");
            }
        }

        // (c): re-chaining the four per-surface projections in
        // canonical order recovers hint_iter itself — no dedup, no
        // reorder, no dropped hint.
        let rechained: Vec<SurfaceHint<'_>> = ALL_HINT_SURFACES
            .iter()
            .flat_map(|s| health.hint_iter_by_surface(*s))
            .collect();
        let straight: Vec<SurfaceHint<'_>> = health.hint_iter().collect();
        assert_eq!(rechained, straight);
    }

    #[test]
    fn health_report_hint_count_by_surface_folds_to_hint_count() {
        // The fold-composition invariant on the count-side peer: the
        // four per-surface counts sum to the whole (no cross-surface
        // dedup, matching the guarantee `hint_count` already promises
        // over the three sub-reports), AND each per-surface count
        // equals its underlying hint list's length (no double-count).
        // Verified on both the clean corner (every count 0) and the
        // dirty corner (every count strictly positive) so a future
        // refactor that drops or duplicates one surface's hints turns
        // this red on whichever corner exposes it.
        let clean_consumed = &["name", "tags", "window.width", "window.height"];
        let clean_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
";
        let clean_value: serde_yaml::Value = serde_yaml::from_str(clean_yaml).unwrap();
        let clean_env: Vec<(String, String)> = vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())];
        let clean_health = ConfigCoverage::health_report::<Demo, _, _>(
            clean_consumed,
            &clean_value,
            "MYAPP_",
            &clean_env,
        );
        // Clean corner: every per-surface count is 0, and the sum
        // matches hint_count() == 0.
        let clean_sum: usize = ALL_HINT_SURFACES
            .iter()
            .map(|s| clean_health.hint_count_by_surface(*s))
            .sum();
        assert_eq!(clean_sum, clean_health.hint_count());
        assert_eq!(clean_sum, 0);
        for surface in ALL_HINT_SURFACES {
            assert_eq!(
                clean_health.hint_count_by_surface(surface),
                0,
                "surface={surface:?}",
            );
        }

        // Dirty corner: every surface carries exactly one hint (the
        // same construction as
        // `health_report_hint_iter_yields_every_hint_tagged_by_surface_of_origin`),
        // so every per-surface count is 1 and the sum is 4.
        let dirty_consumed = &["name", "tags", "window.witdh", "window.height"];
        let dirty_yaml = "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
value_only_leaf: 1
";
        let dirty_value: serde_yaml::Value = serde_yaml::from_str(dirty_yaml).unwrap();
        let dirty_env: Vec<(String, String)> = vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())];
        let dirty_health = ConfigCoverage::health_report::<Demo, _, _>(
            dirty_consumed,
            &dirty_value,
            "MYAPP_",
            &dirty_env,
        );
        for surface in ALL_HINT_SURFACES {
            assert_eq!(
                dirty_health.hint_count_by_surface(surface),
                1,
                "surface={surface:?} health={dirty_health:?}",
            );
        }
        let dirty_sum: usize = ALL_HINT_SURFACES
            .iter()
            .map(|s| dirty_health.hint_count_by_surface(*s))
            .sum();
        assert_eq!(dirty_sum, dirty_health.hint_count());
        assert_eq!(dirty_sum, 4);

        // Cross-check the count-side peer against the underlying hint
        // lists directly — pins that hint_count_by_surface hasn't
        // stolen any hint from its source list.
        assert_eq!(
            dirty_health.hint_count_by_surface(HintSurface::DeadKnob),
            dirty_health.coverage.dead_knobs.len(),
        );
        assert_eq!(
            dirty_health.hint_count_by_surface(HintSurface::StaleEntry),
            dirty_health.coverage.stale_entries.len(),
        );
        assert_eq!(
            dirty_health.hint_count_by_surface(HintSurface::ValueKey),
            dirty_health.value.unknown.len(),
        );
        assert_eq!(
            dirty_health.hint_count_by_surface(HintSurface::EnvVar),
            dirty_health.env.unknown.len(),
        );
    }

    #[test]
    fn health_report_hint_count_by_surface_equals_hint_iter_by_surface_count() {
        // The peer-agreement invariant that pins the iter+count pattern
        // for the surface-projected pair, mirroring the whole-report
        // pair (`hint_iter().count() == hint_count()`): each surface's
        // count-side peer equals its iter-side peer's `.count()`, on
        // both a clean and a dirty corner. Delegating construction
        // (`hint_count_by_surface` calls `hint_iter_by_surface(...)
        // .count()`) enforces this at write time; the test pins it at
        // read time so a future refactor that inlines either method
        // has to keep them in lockstep.
        let inputs: [(&[&str], &str, Vec<(String, String)>); 2] = [
            (
                &["name", "tags", "window.width", "window.height"],
                "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
",
                vec![("MYAPP_WINDOW__WIDTH".into(), "100".into())],
            ),
            (
                &["name", "tags", "window.witdh", "window.height"],
                "\
name: kanchi
window:
  width: 100
  height: 40
tags: []
value_only_leaf: 1
",
                vec![("MYAPP_ENV_ONLY_LEAF".into(), "x".into())],
            ),
        ];
        for (i, (consumed, yaml, env)) in inputs.iter().enumerate() {
            let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            let health =
                ConfigCoverage::health_report::<Demo, _, _>(consumed, &value, "MYAPP_", env);
            for surface in ALL_HINT_SURFACES {
                assert_eq!(
                    health.hint_count_by_surface(surface),
                    health.hint_iter_by_surface(surface).count(),
                    "input#{i} surface={surface:?}",
                );
            }
        }
    }
}

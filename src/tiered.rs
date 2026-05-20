//! Tiered configuration — the fleet-wide pattern every shikumi-typed
//! group implements.
//!
//! # The model
//!
//! Every operator-facing config in the pleme-io fleet has **four
//! discrete tiers** an operator can ask about:
//!
//! 1. **`bare()`** — zero-opinion floor. Every field at empty / zero /
//!    None / least-surprising variant. The deliberate minimum-viable
//!    config. Documented + diffable; rarely used directly.
//!
//! 2. **`discovered()`** — `bare()` + runtime auto-detect outputs
//!    (display dims, system theme, available fonts, GPU class, etc.).
//!    The "what would this app look like with only detection, no
//!    developer opinions?" answer. Default impl returns `bare()` —
//!    consumers override when they have detect helpers.
//!
//! 3. **`prescribed_default()`** — the developer-prescribed default
//!    layered on top of `discovered()`. "App as the developers
//!    believe it should be used." This is what `Default::default()`
//!    returns for the typed config; ~90% of operators land here on
//!    first launch.
//!
//! 4. **`extend(base)`** — operator-supplied overlay on any prior
//!    tier. Sourced from `~/.config/<app>/<app>.yaml` via the
//!    standard shikumi `ConfigStore` discovery chain.
//!
//! # Diff
//!
//! `diff_against(baseline)` computes a structural diff between two
//! values of the same tiered type — typically `bare()` vs
//! `prescribed_default()` so operators can SEE knob-by-knob what
//! defaults bought them. Default impl uses serde-yaml structural
//! diff; consumers can override for a richer presentation.
//!
//! # Operator CLI contract
//!
//! Every app that consumes a `TieredConfig`-implementing type SHOULD
//! ship a subcommand (`<app> config-show <tier>` + `<app> config-diff
//! <from> <to>`) so the contract is discoverable from the terminal,
//! not just code-reading.
//!
//! # Implementor responsibilities
//!
//! 1. `bare()` enumerates **every field** explicitly (no
//!    `..Default::default()`). The function is the operator's
//!    answer to "what does bare mean for this knob?".
//! 2. `prescribed_default()` typically uses `bare()` + per-field
//!    overrides for the prescribed values, OR a hand-written full
//!    enumeration if it's clearer.
//! 3. Tests pin every field of `bare()` (contract). Adding a new
//!    config field without thinking about its bare value fails the
//!    test.

use serde::{de::DeserializeOwned, Serialize};

/// Trait every shikumi-typed config implements to participate in the
/// fleet-wide tier model. See module docs for the full operator
/// contract.
pub trait TieredConfig: Sized + Clone + Serialize + DeserializeOwned {
    /// Tier 0 — the documented floor. Every field at zero-opinion.
    fn bare() -> Self;

    /// Tier 1 — `bare()` overlaid with runtime auto-detect outputs.
    /// Default: returns `bare()` unchanged. Consumers with detect
    /// helpers override.
    fn discovered() -> Self {
        Self::bare()
    }

    /// Tier 2 — `bare()` + curated defaults + `discovered()`. The
    /// prescribed first-launch experience. `Default::default()` on
    /// the implementing type typically delegates here so the standard
    /// idiom (`MyConfig::default()`) Just Works.
    fn prescribed_default() -> Self;

    /// Tier 3 — overlay this config on top of `base`. Default impl
    /// returns `self.clone()` (full replacement). Consumers with
    /// finer-grained per-field merge semantics override.
    fn extend(self, _base: &Self) -> Self {
        self
    }

    /// Diff `self` against `baseline`. Default: serialize both to
    /// YAML and produce a line-oriented diff.
    fn diff_against(&self, baseline: &Self) -> ConfigDiff {
        let a = serde_yaml::to_string(baseline).unwrap_or_default();
        let b = serde_yaml::to_string(self).unwrap_or_default();
        ConfigDiff::from_yaml_pair(&a, &b)
    }
}

/// Line-oriented diff between two YAML serializations of a
/// `TieredConfig` value. Designed for operator-facing CLI output
/// (`<app> config-diff <from> <to>`); not a structural patch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    /// Line present in baseline, absent in candidate.
    Removed(String),
    /// Line absent in baseline, present in candidate.
    Added(String),
    /// Line identical in both (context).
    Context(String),
}

impl ConfigDiff {
    /// Minimum-viable diff: line-by-line walk of two YAML strings.
    /// Lines that match position-wise are Context; non-matching
    /// positions produce paired Removed/Added entries. Sufficient
    /// for the operator UX of "see what changed between two tiers";
    /// not a structural-merge replacement.
    #[must_use]
    pub fn from_yaml_pair(baseline: &str, candidate: &str) -> Self {
        let a: Vec<&str> = baseline.lines().collect();
        let b: Vec<&str> = candidate.lines().collect();
        let mut lines = Vec::with_capacity(a.len().max(b.len()));
        let mut i = 0;
        let mut j = 0;
        while i < a.len() || j < b.len() {
            match (a.get(i), b.get(j)) {
                (Some(la), Some(lb)) if la == lb => {
                    lines.push(DiffLine::Context((*la).to_string()));
                    i += 1;
                    j += 1;
                }
                (Some(la), Some(lb)) => {
                    lines.push(DiffLine::Removed((*la).to_string()));
                    lines.push(DiffLine::Added((*lb).to_string()));
                    i += 1;
                    j += 1;
                }
                (Some(la), None) => {
                    lines.push(DiffLine::Removed((*la).to_string()));
                    i += 1;
                }
                (None, Some(lb)) => {
                    lines.push(DiffLine::Added((*lb).to_string()));
                    j += 1;
                }
                (None, None) => break,
            }
        }
        Self { lines }
    }

    /// Render as a unified-diff-like string for CLI display.
    /// `-` prefix for Removed, `+` for Added, ` ` for Context.
    #[must_use]
    pub fn render_unified(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            match line {
                DiffLine::Context(s) => {
                    out.push(' ');
                    out.push_str(s);
                }
                DiffLine::Removed(s) => {
                    out.push('-');
                    out.push_str(s);
                }
                DiffLine::Added(s) => {
                    out.push('+');
                    out.push_str(s);
                }
            }
            out.push('\n');
        }
        out
    }

    /// True when there are no Added or Removed lines (only Context).
    /// I.e. baseline == candidate.
    #[must_use]
    pub fn is_empty_diff(&self) -> bool {
        !self
            .lines
            .iter()
            .any(|l| matches!(l, DiffLine::Added(_) | DiffLine::Removed(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Toy {
        name: String,
        size: u32,
        flag: bool,
    }

    impl TieredConfig for Toy {
        fn bare() -> Self {
            Self {
                name: String::new(),
                size: 0,
                flag: false,
            }
        }
        fn prescribed_default() -> Self {
            Self {
                name: "default-name".into(),
                size: 42,
                flag: true,
            }
        }
    }

    #[test]
    fn bare_returns_floor_values() {
        let b = Toy::bare();
        assert_eq!(b.name, "");
        assert_eq!(b.size, 0);
        assert!(!b.flag);
    }

    #[test]
    fn prescribed_default_is_different_from_bare() {
        let b = Toy::bare();
        let p = Toy::prescribed_default();
        assert_ne!(b, p);
    }

    #[test]
    fn discovered_default_impl_returns_bare() {
        // No override → discovered is identical to bare.
        let d = Toy::discovered();
        let b = Toy::bare();
        assert_eq!(d, b);
    }

    #[test]
    fn diff_against_self_is_empty() {
        let p = Toy::prescribed_default();
        let diff = p.diff_against(&p);
        assert!(diff.is_empty_diff());
    }

    #[test]
    fn diff_bare_vs_default_yields_added_and_removed_lines() {
        let b = Toy::bare();
        let p = Toy::prescribed_default();
        let diff = p.diff_against(&b);
        assert!(!diff.is_empty_diff());
        let has_added = diff
            .lines
            .iter()
            .any(|l| matches!(l, DiffLine::Added(s) if s.contains("default-name")));
        let has_removed = diff
            .lines
            .iter()
            .any(|l| matches!(l, DiffLine::Removed(s) if s.contains("name: ''")));
        assert!(has_added, "diff should add the prescribed name");
        assert!(has_removed, "diff should remove the bare empty name");
    }

    #[test]
    fn render_unified_uses_diff_prefixes() {
        let b = Toy::bare();
        let p = Toy::prescribed_default();
        let rendered = p.diff_against(&b).render_unified();
        assert!(rendered.contains("-name: ''"));
        assert!(rendered.contains("+name: default-name"));
    }

    #[test]
    fn extend_default_impl_full_replaces_base() {
        let b = Toy::bare();
        let p = Toy::prescribed_default();
        let merged = p.clone().extend(&b);
        assert_eq!(merged, p);
    }
}

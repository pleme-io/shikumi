//! Shikumi (仕組み) — config discovery, hot-reload, and `ArcSwap` store
//! for Nix-managed desktop applications.
//!
//! Extracted from [karakuri](https://github.com/pleme-io/karakuri)'s configuration
//! system, shikumi provides the shared infrastructure for desktop apps that need:
//!
//! - **XDG config discovery** with env var overrides and format preference
//! - **Figment provider chains** (defaults → env vars → config file)
//! - **Lock-free concurrent reads** via `ArcSwap`
//! - **Hot-reload** with symlink-aware file watching (for nix-darwin managed configs)
//!
//! # Quick Start
//!
//! ```no_run
//! use serde::Deserialize;
//! use shikumi::{ConfigDiscovery, ConfigStore, Format};
//!
//! #[derive(Deserialize, Clone, Debug, Default)]
//! struct MyConfig {
//!     window_width: Option<u32>,
//! }
//!
//! let path = ConfigDiscovery::new("myapp")
//!     .env_override("MYAPP_CONFIG")
//!     .formats(&[Format::Yaml, Format::Toml])
//!     .discover()
//!     .expect("config file not found");
//!
//! let store = ConfigStore::<MyConfig>::load(&path, "MYAPP_")
//!     .expect("failed to load config");
//!
//! let config = store.get();
//! println!("width: {:?}", config.window_width);
//! ```

// `macros` MUST be declared first: `#[macro_use]` only makes its `macro_rules!`
// visible to modules declared AFTER it. `cube` + `discovery` call
// `serde_via_display_fromstr!` / `closed_axis_label_string_surface*!` by bare
// name, so the macros module has to precede them or those calls are out of
// scope ("cannot find macro in this scope").
#[macro_use]
pub mod macros;
#[cfg(feature = "blue")]
pub mod blue_provider;
#[cfg(feature = "cli")]
pub mod cli;
pub mod coverage;
mod cube;
pub mod discovered;
mod discovery;
mod error;
#[cfg(feature = "hotswap")]
pub mod hotswap;
#[cfg(feature = "kube-discovery")]
pub mod kube_discovery;
#[cfg(feature = "lisp")]
pub mod lisp_provider;
pub mod nix_provider;
mod observatory;
mod provider;
mod reload;
pub mod secret;
pub mod secret_client;
mod source;
mod store;
pub mod tiered;
mod watcher;

pub use coverage::{
    ConfigCoverage, CoverageHint, CoverageReport, EnvVarAudit, EnvVarHint, HealthReport,
    HintSurface, HintedCoverageReport, PathHint, SurfaceHint, ValueAudit, ValueKeyHint,
};
pub use cube::{
    AxisHistogram, AxisHistogramIntoIter, AxisHistogramIter, AxisHistogramIterMut,
    AxisHistogramNonzero, AxisHistogramObserved, AxisHistogramUnobserved, AxisIter, ClosedAxis,
    ClosedAxisLabel, ForwardIter, ModalityClass, ParseAxisHistogramError, ParseModalityClassError,
    ParsePartitionFaceError, ParsePartitionOrdinalError, ParseSupportBoundaryDistanceError,
    ParseSupportCardinalityClassError, ParseSupportMagnitudeDirectionError, PartialInverseCube,
    PartitionFace, PartitionOrdinal, ProductCube, RealizableImages, RealizableIter,
    SupportBoundaryDistance, SupportCardinalityClass, SupportMagnitudeDirection, UnrealizableIter,
    at_partition_ordinal, axis_at, axis_cardinality, axis_from_label, axis_histogram, axis_iter,
    axis_label, axis_ordinal, forward_iter, partition_ordinal, realizable_at, realizable_count,
    realizable_images, realizable_iter, realizable_ordinal, unrealizable_at, unrealizable_count,
    unrealizable_iter, unrealizable_ordinal,
};
pub use discovered::{
    AxisLayer, ContributorNamesIter, ContributorsAtIter, DiscoveryComposition, DiscoveryLayer,
    LayerAttribution, LayerAttributionIntoIter, LayerAttributionIter,
    LayerAttributionLayerRankingIter, LayerAttributionLayerRankingNamesIter,
    LayerAttributionLeafCountsByLayerIter, LayerAttributionSubtreeIter,
    LayerAttributionSubtreeLayerRankingIter, LayerAttributionSubtreeLayerRankingNamesIter,
    LayerAttributionSubtreeLeafCountsByLayerIter, LayerAttributionSubtreeSurvivingLayerNamesIter,
    LayerAttributionSubtreeWritesByLayerIter, LayerAttributionSubtreeWritesOfLayerIter,
    LayerAttributionSurvivingLayerNamesIter, LayerAttributionWritesByLayerIter,
    LayerAttributionWritesOfLayerIter, LayerNamesIter, NonemptyLayerDictsIter, PathContest,
    PathContestContributorsIter, PathContestSilencedIter, SilencedAtIter, SilentLayerNamesIter,
    coarsest_at, coarsest_silenced_at, compose as compose_discovery, compose_with_provenance,
    contest_at, contributor_count, contributor_count_at, contributor_names, contributor_names_iter,
    contributors_at, contributors_at_iter, decider_at, deep_merge, has_contributor,
    has_multiple_contributors, has_multiple_silent_layers, has_silent_layer, is_contested_at,
    is_multiply_silenced_at, is_touched_at, layer_names, layer_names_iter, nonempty_layer_dicts,
    nonempty_layer_dicts_iter, runner_up_at, silenced_at, silenced_at_iter, silenced_count_at,
    silent_layer_count, silent_layer_names, silent_layer_names_iter,
};
pub use discovery::{
    ConfigDiscovery, ConfiguredExtensions, Format, FormatCoordinates, FormatMetadataTag,
    FormatProvenance, ParseFormatCoordinatesError, ParseFormatMetadataTagError,
};
pub use error::{
    AttributionAxis, AttributionConfidence, AttributionCoordinates, AttributionNameKindCoordinates,
    AttributionRule, AttributionSourceKindCoordinates, ErrorLocalizationCoordinates,
    FailingSourceAttribution, FieldPathLocalization, ShikumiError, ShikumiErrorKind,
};
#[cfg(feature = "hotswap")]
pub use hotswap::{
    ConfigSyncProof, ConfigWatermark, MovedWatermarkDelta, ProofDelta, ProofDeltaWire,
    ProofRelation, ProofRelationWire, Validate, ValidatedTieredConfig, WatermarkDelta,
    WatermarkDeltaWire, WatermarkRelation, WatermarkRelationWire,
};
#[cfg(feature = "kube-discovery")]
pub use kube_discovery::KubeClusterDiscovery;
#[cfg(feature = "kube")]
pub use kube_discovery::KubeSecretReader;
#[cfg(feature = "lisp")]
pub use lisp_provider::{LispProvider, load_from_str as load_lisp_from_str};
#[doc(hidden)]
pub use macros::__tiered_permutation_run;
pub use nix_provider::NixProvider;
pub use provider::ProviderChain;
pub use reload::ReloadFailure;
pub use secret::{SecretBackendKind, SecretRefShape};
pub use secret_client::{SecretClientKind, SecretErrorKind, SecretOperation};
pub use source::{
    ConfigSource, ConfigSourceChain, ConfigSourceKind, EnvMetadataTag, EnvMetadataTagKind,
    FigmentNameTag, FigmentNameTagKind, FigmentSourceKind, FigmentSourceTag,
};
pub use store::ConfigStore;
pub use tiered::{
    ConfigDiff, ConfigTier, ConfigTierKind, DiffLine, DiffLineKind, ProgressiveLayer,
    ProgressiveResolution, Provenance, ProvenanceMap, ProvenanceMapEntries, ProvenanceMapIntoIter,
    TieredConfig,
};
pub use watcher::{ConfigWatcher, WatchEventClass, symlink_target};

#[cfg(test)]
mod check_cfg_tests {
    //! Build-hygiene invariants that pin the `[lints.rust]` `check-cfg`
    //! surface in `Cargo.toml`.
    //!
    //! The `hotswap` feature was removed from `Cargo.toml`'s `[features]`
    //! table because `pleme-hotswap` is not on crates.io — see the
    //! `[lints.rust]` block in `Cargo.toml` for the full "why" — but the
    //! seven `#[cfg(feature = "hotswap")]` gates covering its surface (one
    //! in `src/lib.rs`, six in `src/store.rs`) are deliberately kept
    //! in-tree so re-adding the feature is a one-line change once
    //! `pleme-hotswap` publishes. Every gate on a not-yet-declared feature
    //! would otherwise emit `unexpected_cfg_condition_value` at
    //! `cargo build` — silence-by-noise on any real cfg typo elsewhere,
    //! since a future misspelled `#[cfg(feature = "hotwsap")]` in an
    //! unrelated change would blend into the same 7-warning cluster.
    //!
    //! The fix declares `hotswap` as a KNOWN feature value in
    //! `[lints.rust].unexpected_cfgs.check-cfg`. These tests lock both
    //! halves of the invariant against silent regression — the declaration
    //! itself and the gates that justify keeping it.
    //!
    //! Delete these tests, the `[lints.rust]` entry, and the surviving
    //! gates together — never any subset.

    const CARGO_TOML: &str = include_str!("../Cargo.toml");
    const LIB_RS: &str = include_str!("lib.rs");
    const STORE_RS: &str = include_str!("store.rs");

    const HOTSWAP_CHECK_CFG_DECLARATION: &str = r#"cfg(feature, values("hotswap"))"#;
    const HOTSWAP_GATE_ATTR: &str = r#"#[cfg(feature = "hotswap")]"#;

    #[test]
    fn cargo_toml_declares_hotswap_as_known_check_cfg_value() {
        // Substring pin: the check-cfg literal must appear somewhere in
        // Cargo.toml. If it doesn't, `cargo build --all-features` emits
        // seven `unexpected_cfg_condition_value` warnings that hide any
        // real feature-name typo made elsewhere in the same change.
        assert!(
            CARGO_TOML.contains(HOTSWAP_CHECK_CFG_DECLARATION),
            "Cargo.toml must declare `hotswap` as a known check-cfg value \
             (literal `{HOTSWAP_CHECK_CFG_DECLARATION}` under \
             [lints.rust].unexpected_cfgs.check-cfg) — every \
             `{HOTSWAP_GATE_ATTR}` gate in src/ depends on this \
             declaration to avoid warning-noise pollution",
        );
    }

    #[test]
    fn hotswap_check_cfg_declaration_lives_under_lints_rust_section() {
        // Section pin, not just the substring: a stray literal
        // `cfg(feature, values("hotswap"))` inside a comment or under a
        // different `[lints.*]` / `[dependencies]` / `[features]` table
        // would satisfy `contains(...)` without actually silencing the
        // warning. rustc only reads `check-cfg` from the `[lints.rust]`
        // table; the invariant here matches that reading.
        let after_lints_rust = CARGO_TOML
            .split("[lints.rust]")
            .nth(1)
            .expect("Cargo.toml must have a [lints.rust] section — check-cfg lives there");
        // Take up to the next top-level TOML section marker so the scope
        // does not wander into a later `[dependencies]`/`[features]`
        // table where the literal might legally appear in a comment.
        let scope_end = after_lints_rust
            .find("\n[")
            .unwrap_or(after_lints_rust.len());
        let scope = &after_lints_rust[..scope_end];
        assert!(
            scope.contains(HOTSWAP_CHECK_CFG_DECLARATION),
            "the `hotswap` check-cfg declaration must live inside the \
             [lints.rust] table, not a comment or an unrelated table; \
             scope was: {scope:?}",
        );
    }

    #[test]
    fn src_still_has_gated_hotswap_sites_that_justify_the_check_cfg() {
        // Contract-consistency pin: the check-cfg declaration is a
        // silencer for genuine `#[cfg(feature = "hotswap")]` gates that
        // still live in-tree. If those gates all vanish (e.g. hotswap is
        // dropped from the codebase rather than re-enabled from
        // crates.io), the check-cfg declaration must be removed in the
        // same commit — otherwise it would silence warnings for a
        // typo-shaped feature that no longer has any legitimate use
        // in-tree.
        //
        // The two files carrying the surviving gates at the time of this
        // test's addition (2026-08-05):
        // - `src/lib.rs`   — one `pub use hotswap::…` re-export gate.
        // - `src/store.rs` — five gates around the pending-restart
        //                    record, the `load_and_watch_hotswap`
        //                    constructor + helpers, and one
        //                    `#[cfg(all(test, feature = "hotswap"))]`
        //                    test module.
        assert!(
            LIB_RS.contains(HOTSWAP_GATE_ATTR),
            "src/lib.rs must still carry a `{HOTSWAP_GATE_ATTR}` gate; \
             if it doesn't, drop the check-cfg entry in Cargo.toml too",
        );
        assert!(
            STORE_RS.contains(HOTSWAP_GATE_ATTR),
            "src/store.rs must still carry `{HOTSWAP_GATE_ATTR}` gates; \
             if it doesn't, drop the check-cfg entry in Cargo.toml too",
        );
    }

    #[test]
    fn hotswap_gate_site_count_matches_warning_baseline() {
        // Cardinality pin: 7 warnings on `cargo build --all-features`
        // (measured 2026-08-05, pre-fix) — 1 active attribute in
        // src/lib.rs (the `pub use hotswap::…` re-export gate) plus 5
        // in src/store.rs (the five bare `#[cfg(feature = "hotswap")]`
        // gates around the pending-restart record + the
        // `load_and_watch_hotswap` constructor). The sixth store.rs
        // gate — `#[cfg(all(test, feature = "hotswap"))]` on the
        // hotswap_tests module — is a compound predicate; it also
        // needed the check-cfg silencing, bringing the raw warning
        // count from 6 to 7. Counting bare-attribute lines only (see
        // `count_gate_attribute_lines` below) gives a stable 6 that
        // excludes both the compound-test gate and any mention of the
        // literal inside doc-comments or test message strings.
        //
        // If either count drifts, either update this baseline and note
        // why in the Cargo.toml comment block, or fix the gate whose
        // addition/removal shifted the total.
        // UPDATED 2026-08-06, 1 -> 2, per this test's own instruction.
        // The feature was RESTORED (pleme-hotswap 0.1.1 published
        // 2026-08-05), which meant un-commenting `#[cfg(feature =
        // "hotswap")] pub mod hotswap;` — a real gate that had been
        // carried as a comment for exactly as long as the dep was
        // unavailable. So lib.rs now holds two bare attributes: the module
        // declaration and the `pub use hotswap::…` re-export. store.rs is
        // untouched at 5; nothing about the gated surface changed, only
        // whether the module line is code or a comment.
        //
        // UPDATED 2026-08-08, store.rs 5 -> 6, per this test's own instruction.
        // ONE bare attribute added: the gate on the new `Validate`-bounded
        // `impl<T> ConfigStore<T>` block carrying `replace_validated` +
        // `try_replace` — the validated door beside the unvalidated
        // `ConfigStore::replace`. It is one attribute and not two because
        // both methods live in that single gated block rather than carrying
        // their own; keeping the gate at the block boundary is what holds this
        // count proportional to the gated SURFACE rather than to its method
        // count.
        //
        // UPDATED 2026-08-19, store.rs 6 -> 5, per this test's own instruction.
        // The non-watching `load` / `load_merged` constructors now route
        // their struct-literal body through the new `assemble_unwatched`
        // substrate helper. That collapse removed TWO bare `pending_restart:
        // Arc::new(ArcSwapOption::empty())` gates (one per collapsed
        // constructor body) and added ONE (inside the shared helper's own
        // struct literal). Net drop 6 → 5; the gated SURFACE shrank by one
        // site because the two constructors now reach the pending-restart
        // slot through ONE named substrate helper instead of open-coding
        // it apiece — exactly the drift-class this crate's shared-substrate
        // lifts (e.g. `record_failure_and_log`, `should_reload_on_event`,
        // the `merge_*_layer` tier helpers) spend to close on other seams.
        let lib_hits = count_gate_attribute_lines(LIB_RS);
        let store_hits = count_gate_attribute_lines(STORE_RS);
        assert_eq!(
            lib_hits, 2,
            "src/lib.rs bare `{HOTSWAP_GATE_ATTR}` attribute-line count drifted from 2",
        );
        assert_eq!(
            store_hits, 5,
            "src/store.rs bare `{HOTSWAP_GATE_ATTR}` attribute-line count drifted from 5",
        );
    }

    /// Count lines whose FIRST non-whitespace token is the bare
    /// `#[cfg(feature = "hotswap")]` attribute — a real attribute
    /// application, not a substring embedded in a doc-comment
    /// (`//! … #[cfg(feature = "hotswap")] …`) or a test-message
    /// string literal (`format!("... {HOTSWAP_GATE_ATTR} ...")`) or a
    /// commented-out `// #[cfg(feature = "hotswap")]` line. Anchoring
    /// on trimmed-start over `contains` keeps the count sensitive to
    /// gate additions/removals while ignoring mentions.
    fn count_gate_attribute_lines(src: &str) -> usize {
        src.lines()
            .filter(|l| l.trim_start().starts_with(HOTSWAP_GATE_ATTR))
            .count()
    }

    #[test]
    fn count_gate_attribute_lines_ignores_mentions_in_comments_and_strings() {
        // Fixture pin: the counter must count real attribute
        // applications and skip the six forms of "mention": bare
        // comment mention, doc-comment mention (`///` and `//!`),
        // string-literal mention, raw-string-literal mention, and a
        // gate embedded mid-expression (not attribute position).
        let fixture = concat!(
            "#[cfg(feature = \"hotswap\")]\n",              // real gate — count
            "    #[cfg(feature = \"hotswap\")]\n",          // real gate (indented) — count
            "// #[cfg(feature = \"hotswap\")]\n",           // commented — skip
            "/// mention: #[cfg(feature = \"hotswap\")]\n", // doc-comment — skip
            "//! mention: #[cfg(feature = \"hotswap\")]\n", // module doc — skip
            "let s = \"#[cfg(feature = \\\"hotswap\\\")]\";\n", // string — skip
            "let s = r#\"#[cfg(feature = \"hotswap\")]\"#;\n", // raw string — skip
            "let _ = foo(#[cfg(feature = \"hotswap\")] bar);\n", // mid-expr — skip
        );
        assert_eq!(
            count_gate_attribute_lines(fixture),
            2,
            "counter must match only the two lines whose trimmed-start \
             is the bare attribute, not any of the six mention forms",
        );
    }
}

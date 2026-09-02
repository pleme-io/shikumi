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

// Deny orphaned attribute / doc-comment defects at the crate root, so a
// future edit inserting a new item between an attribute (or `///` doc-
// comment block) and the item the attribute was intended for fires at
// compile time instead of surviving as a `warn`-level notice a busy CI
// gate can miss. Two such orphanings landed in `src/provider.rs` before
// this gate was wired: a `#[must_use]` gate above `merge_env_prefix_layer`
// that a later insertion of `RESERVED_ENV_KEYS`'s doc-comment block re-
// homed onto the constant (rustc rejects `#[must_use]` on constants and
// warned it will become a hard error), and a `///` doc-comment above the
// `text_source_provider!` macro invocation for `MacroFusedProbeProvider`
// that rustc could not attach to a macro invocation (rustdoc rides
// INSIDE the invocation on the `$(#[$attr])*` slot instead). Both are
// fixed at their sites; this gate stops the class recurring.
#![deny(unused_attributes, unused_doc_comments)]

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
/// Daemon startup: answer `--help`/`--version` and refuse unknown argv
/// before any config load or side effect. Ungated -- no clap.
pub mod daemon;
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
    ProvenanceMapPaths, ProvenanceMapProvenances, ProvenanceMapSourceKinds, ProvenanceMapSources,
    ProvenanceMapTiers, TieredConfig,
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
        //
        // UPDATED 2026-08-28, store.rs 5 -> 6, per this test's own instruction.
        // ONE bare attribute added: the split `use tracing::error;` line
        // beside the ungated `use tracing::info;`. `error!` is only ever
        // reached from the hot-swap validation-log path inside the
        // existing `#[cfg(feature = "hotswap")]` block on
        // `load_and_watch_hotswap`; keeping the import same-gated stops
        // `warn(unused_imports)` from firing under default features (10
        // → 0 warnings on `cargo build`, alongside the peer text-source
        // helper/macro gates landed in the same commit). Load-bearing
        // fix on the CLAUDE.md `pending-shikumi-clippy` note — the
        // measured warning burn-down that had to precede any
        // `-D warnings` gate in CI.
        let lib_hits = count_gate_attribute_lines(LIB_RS);
        let store_hits = count_gate_attribute_lines(STORE_RS);
        assert_eq!(
            lib_hits, 2,
            "src/lib.rs bare `{HOTSWAP_GATE_ATTR}` attribute-line count drifted from 2",
        );
        assert_eq!(
            store_hits, 6,
            "src/store.rs bare `{HOTSWAP_GATE_ATTR}` attribute-line count drifted from 6",
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

#[cfg(test)]
mod unused_attribute_gate_tests {
    //! Build-hygiene invariants that pin the crate-level
    //! `#![deny(unused_attributes, unused_doc_comments)]` gate above and
    //! the four `#[must_use]` stamps on the `merge_*_layer` peer helpers
    //! in `src/provider.rs`.
    //!
    //! The gate blocks two orphaning shapes rustc could otherwise let a
    //! future edit reintroduce at `warn` altitude only:
    //!
    //! - `#[must_use]` above a `pub(crate) fn` that a subsequent edit
    //!   pushes DOWN the file by inserting a new item (constant, type
    //!   alias, doc-comment block) between the attribute and its target.
    //!   rustc rehomes the attribute onto the inserted item; if that
    //!   item is a constant, rustc emits
    //!   `#[must_use] attribute cannot be used on constants` — a warning
    //!   that is scheduled to become a hard error but reaches CI as a
    //!   warning today. This is what happened at `provider.rs:1211`
    //!   before this gate: an inserted `RESERVED_ENV_KEYS` block re-
    //!   homed the `#[must_use]` gate for `merge_env_prefix_layer` onto
    //!   the constant.
    //!
    //! - `///` doc-comments above a macro invocation that rustc cannot
    //!   attach to the invocation (rustdoc rides INSIDE the invocation
    //!   on the `$(#[$attr])*` slot). The outer `///` becomes an
    //!   orphaned doc-comment and rustc emits `unused doc comment`.
    //!   This is what happened at `provider.rs:5609` before this gate.
    //!
    //! Delete the crate-level deny only together with the four
    //! `#[must_use]` stamps below — never in isolation.

    const LIB_RS: &str = include_str!("lib.rs");
    const PROVIDER_RS: &str = include_str!("provider.rs");

    const CRATE_LEVEL_DENY: &str = "#![deny(unused_attributes, unused_doc_comments)]";

    /// Every peer helper in the `merge_*_layer` family MUST carry
    /// `#[must_use]` immediately above its `pub(crate) fn` line. The
    /// four helpers take `chain` by value and return `chain` by value —
    /// dropping the returned chain silently discards the just-merged
    /// tier layer, the exact class the attribute guards against.
    const MUST_USE_MERGE_HELPERS: &[&str] = &[
        "pub(crate) fn merge_provider_and_record<",
        "pub(crate) fn merge_serialized_defaults_layer<",
        "pub(crate) fn merge_env_prefix_layer(",
        "pub(crate) fn merge_file_layer<",
    ];

    #[test]
    fn lib_rs_declares_crate_level_unused_attributes_deny() {
        assert!(
            LIB_RS.contains(CRATE_LEVEL_DENY),
            "src/lib.rs must declare `{CRATE_LEVEL_DENY}` at the crate \
             root so the two orphaning shapes at `provider.rs:1211` \
             (`#[must_use]` on a constant) and `provider.rs:5609` \
             (`///` above a macro invocation) — both fixed in the same \
             commit that wired this gate — cannot recur as `warn`-level \
             notices CI overlooks",
        );
    }

    #[test]
    fn merge_layer_helpers_all_carry_must_use() {
        for helper_signature in MUST_USE_MERGE_HELPERS {
            let idx = PROVIDER_RS.find(helper_signature).unwrap_or_else(|| {
                panic!(
                    "src/provider.rs must still declare the peer helper \
                     `{helper_signature}` — if the signature has been \
                     renamed, update MUST_USE_MERGE_HELPERS here in \
                     lockstep"
                )
            });
            // Look at the line immediately preceding the signature: the
            // `#[must_use]` stamp lives on its own line right above the
            // `pub(crate) fn` declaration for all four peers.
            let prefix = &PROVIDER_RS[..idx];
            let prev_line = prefix
                .rsplit_once('\n')
                .and_then(|(before, _)| before.rsplit_once('\n').map(|(_, line)| line))
                .unwrap_or("");
            assert_eq!(
                prev_line.trim(),
                "#[must_use]",
                "peer helper `{helper_signature}` in src/provider.rs must \
                 carry `#[must_use]` on the line immediately above its \
                 signature — dropping the returned chain would silently \
                 discard the merged tier layer, the exact class \
                 `#[must_use]` guards against; the prior line was \
                 {prev_line:?}"
            );
        }
    }

    #[test]
    fn reserved_env_keys_is_not_preceded_by_orphaned_must_use() {
        // Regression pin for the exact 2026-09-02 orphaning at
        // `provider.rs:1211`: an inserted doc-comment block for
        // `RESERVED_ENV_KEYS` re-homed the `#[must_use]` intended for
        // `merge_env_prefix_layer` onto the constant. `RESERVED_ENV_KEYS`
        // is a `pub(crate) const`, and rustc rejects `#[must_use]` on
        // constants — the crate-level deny above catches it going
        // forward, and this pin also catches it in the source string
        // for the specific site the class first appeared at.
        let anchor = "pub(crate) const RESERVED_ENV_KEYS:";
        let idx = PROVIDER_RS
            .find(anchor)
            .expect("src/provider.rs must still declare `RESERVED_ENV_KEYS`");
        let prefix = &PROVIDER_RS[..idx];
        // Scan up to 128 lines above the declaration; the orphaning
        // shape puts `#[must_use]` on its own line just below the
        // helper's doc-comment block. A `#[must_use]` anywhere in that
        // window that is NOT immediately followed by a `pub(crate) fn`
        // is the defect.
        let window = prefix
            .rsplit('\n')
            .take(128)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        for pair in window.windows(2) {
            if pair[0].trim() == "#[must_use]" {
                let next = pair[1].trim();
                assert!(
                    next.starts_with("pub(crate) fn")
                        || next.starts_with("pub fn")
                        || next.starts_with("fn "),
                    "orphaned `#[must_use]` above `RESERVED_ENV_KEYS` — \
                     the next non-empty line after `#[must_use]` was \
                     {next:?}, not a `fn` declaration"
                );
            }
        }
    }
}

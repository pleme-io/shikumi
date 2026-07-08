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
#[cfg(feature = "cli")]
pub mod cli;
pub mod coverage;
mod cube;
pub mod discovered;
mod discovery;
mod error;
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

pub use coverage::{ConfigCoverage, CoverageReport};
pub use cube::{
    AxisHistogram, AxisHistogramIntoIter, AxisHistogramIter, AxisHistogramIterMut, ClosedAxis,
    ClosedAxisLabel, ModalityClass, ParseAxisHistogramError, ParseModalityClassError,
    ParsePartitionFaceError, ParsePartitionOrdinalError, ParseSupportBoundaryDistanceError,
    ParseSupportCardinalityClassError, ParseSupportMagnitudeDirectionError, PartialInverseCube,
    PartitionFace, PartitionOrdinal, ProductCube, SupportBoundaryDistance, SupportCardinalityClass,
    SupportMagnitudeDirection, at_partition_ordinal, axis_at, axis_cardinality, axis_from_label,
    axis_histogram, axis_iter, axis_label, axis_ordinal, forward_iter, partition_ordinal,
    realizable_at, realizable_count, realizable_images, realizable_iter, realizable_ordinal,
    unrealizable_at, unrealizable_count, unrealizable_iter, unrealizable_ordinal,
};
pub use discovered::{
    ContributorNamesIter, ContributorsAtIter, DiscoveryComposition, DiscoveryLayer,
    LayerAttribution, LayerAttributionIntoIter, LayerAttributionIter,
    LayerAttributionLayerRankingIter, LayerAttributionLayerRankingNamesIter,
    LayerAttributionLeafCountsByLayerIter, LayerAttributionSubtreeIter,
    LayerAttributionSubtreeLayerRankingIter, LayerAttributionSubtreeLayerRankingNamesIter,
    LayerAttributionSubtreeLeafCountsByLayerIter, LayerAttributionSubtreeSurvivingLayerNamesIter,
    LayerAttributionSubtreeWritesByLayerIter, LayerAttributionSubtreeWritesOfLayerIter,
    LayerAttributionSurvivingLayerNamesIter, LayerAttributionWritesByLayerIter,
    LayerAttributionWritesOfLayerIter, LayerNamesIter, PathContest, PathContestContributorsIter,
    PathContestSilencedIter, SilencedAtIter, SilentLayerNamesIter, coarsest_at,
    coarsest_silenced_at, compose as compose_discovery, compose_with_provenance, contest_at,
    contributor_count, contributor_count_at, contributor_names, contributor_names_iter,
    contributors_at, contributors_at_iter, decider_at, deep_merge, has_contributor,
    has_multiple_contributors, has_multiple_silent_layers, has_silent_layer, is_contested_at,
    is_multiply_silenced_at, is_touched_at, layer_names, layer_names_iter, nonempty_layer_dicts,
    nonempty_layer_dicts_iter, runner_up_at, silenced_at, silenced_at_iter, silenced_count_at,
    silent_layer_count, silent_layer_names, silent_layer_names_iter,
};
pub use discovery::{
    ConfigDiscovery, Format, FormatCoordinates, FormatMetadataTag, FormatProvenance,
    ParseFormatCoordinatesError, ParseFormatMetadataTagError,
};
pub use error::{
    AttributionAxis, AttributionConfidence, AttributionCoordinates, AttributionNameKindCoordinates,
    AttributionRule, AttributionSourceKindCoordinates, ErrorLocalizationCoordinates,
    FailingSourceAttribution, FieldPathLocalization, ShikumiError, ShikumiErrorKind,
};
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
    ProgressiveResolution, Provenance, ProvenanceMap, TieredConfig,
};
pub use watcher::{ConfigWatcher, WatchEventClass, symlink_target};

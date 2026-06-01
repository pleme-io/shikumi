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

#[cfg(feature = "cli")]
pub mod cli;
pub mod coverage;
mod cube;
mod discovery;
#[macro_use]
pub mod macros;
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
    ClosedAxis, ClosedAxisLabel, PartialInverseCube, PartitionFace, PartitionOrdinal, ProductCube,
    at_partition_ordinal, axis_at, axis_cardinality, axis_from_label, axis_iter, axis_label,
    axis_ordinal, forward_iter, partition_ordinal, realizable_at, realizable_count,
    realizable_images, realizable_iter, realizable_ordinal, unrealizable_at, unrealizable_count,
    unrealizable_iter, unrealizable_ordinal,
};
pub use discovery::{
    ConfigDiscovery, Format, FormatCoordinates, FormatMetadataTag, FormatProvenance,
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
pub use source::{
    ConfigSource, ConfigSourceChain, ConfigSourceKind, EnvMetadataTag, FigmentNameTag,
    FigmentNameTagKind, FigmentSourceKind, FigmentSourceTag,
};
pub use store::ConfigStore;
pub use tiered::{ConfigDiff, ConfigTier, ConfigTierKind, DiffLine, TieredConfig};
pub use watcher::{ConfigWatcher, WatchEventClass, symlink_target};

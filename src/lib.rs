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

mod discovery;
mod error;
pub mod lisp_provider;
pub mod nix_provider;
mod provider;
pub mod secret;
mod store;
mod watcher;

pub use discovery::{ConfigDiscovery, Format};
pub use error::ShikumiError;
pub use lisp_provider::{LispProvider, load_from_str as load_lisp_from_str};
pub use nix_provider::NixProvider;
pub use provider::ProviderChain;
pub use store::ConfigStore;
pub use watcher::{ConfigWatcher, symlink_target};

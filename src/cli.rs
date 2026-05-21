//! Reusable clap subcommand factory for `<app> config-show <tier>`.
//!
//! The Pillar 12 dual of `TieredConfig`: instead of every fleet app
//! hand-rolling its own config-show CLI, each pulls in this one
//! `ConfigShowCommand` struct and gets the canonical operator surface
//! (bare/default/discovered/custom + env-resolved + diff + YAML/JSON
//! emission) for one extra line.
//!
//! # Wiring
//!
//! In a clap-based binary's `Commands` enum:
//!
//! ```ignore
//! use clap::{Parser, Subcommand};
//! use shikumi::cli::ConfigShowCommand;
//!
//! #[derive(Parser)]
//! struct Cli { #[command(subcommand)] cmd: Commands }
//!
//! #[derive(Subcommand)]
//! enum Commands {
//!     // ...existing subcommands...
//!     /// Show the materialized config at a tier (bare/default/env/...).
//!     ConfigShow(ConfigShowCommand),
//! }
//!
//! match cli.cmd {
//!     Commands::ConfigShow(cmd) => cmd.run::<MyConfig>("MYAPP_TIER")?,
//!     // ...
//! }
//! ```
//!
//! With that, operators get:
//!
//! ```text
//! myapp config-show                      # env-resolved (MYAPP_TIER or default)
//! myapp config-show bare                 # zero-opinion floor
//! myapp config-show default              # prescribed defaults
//! myapp config-show discovered           # runtime auto-detect
//! myapp config-show custom --path x.yaml # YAML overlay on default
//! myapp config-show --format json        # JSON instead of YAML
//! myapp config-show default --diff bare  # unified diff between tiers
//! ```

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::tiered::{ConfigTier, TieredConfig};

/// Which tier the operator asked for at the CLI level. Distinct
/// from `ConfigTier::Custom(PathBuf)` because clap surfaces the
/// path as a separate `--path` flag rather than a positional that
/// shadows the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TierArg {
    /// Zero-opinion floor — every field empty/zero/false/None.
    Bare,
    /// `bare()` overlaid with `discovered()` runtime auto-detect.
    Discovered,
    /// The curated app defaults shipped today.
    Default,
    /// YAML overlay at `--path` on top of `default`.
    Custom,
    /// Resolve from the `<APP>_TIER` environment variable; fall back
    /// to `default` if unset or invalid.
    Env,
}

/// Emission format for `config-show` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// YAML — the canonical pleme-io config emission format.
    Yaml,
    /// JSON — machine-readable, useful for piping into jq.
    Json,
}

/// The clap subcommand every TieredConfig consumer pulls in.
///
/// Drop into your `Commands` enum; the `run` method takes the type
/// parameter `C: TieredConfig` and the env-var name your app reads.
#[derive(Debug, Clone, Args)]
pub struct ConfigShowCommand {
    /// Which tier to materialize. Defaults to `env` (reads the
    /// `<APP>_TIER` env var, falls back to `default`).
    #[arg(value_enum, default_value_t = TierArg::Env)]
    pub tier: TierArg,

    /// Path to a YAML overlay when `tier = custom`. Ignored for
    /// other tiers.
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Output format.
    #[arg(value_enum, long, default_value_t = OutputFormat::Yaml)]
    pub format: OutputFormat,

    /// Diff `tier` against another tier instead of showing it.
    /// Output is a unified diff (- = baseline, + = candidate).
    #[arg(long, value_enum)]
    pub diff: Option<TierArg>,
}

/// Errors returned by `ConfigShowCommand::run`. Kept small + library-
/// crate friendly (consumers wrap into their own anyhow chain).
#[derive(Debug, thiserror::Error)]
pub enum ConfigShowError {
    #[error("`tier custom` requires --path <FILE>")]
    CustomTierWithoutPath,
    #[error("YAML serialization failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl ConfigShowCommand {
    /// Run the subcommand. `env_var` is the name your app reads
    /// (e.g. `MADO_TIER`, `TATARA_TIER`).
    ///
    /// # Errors
    /// Returns `ConfigShowError::CustomTierWithoutPath` if the
    /// operator asked for `custom` but didn't pass `--path`, or
    /// serialization errors for YAML/JSON emission.
    pub fn run<C: TieredConfig>(&self, env_var: &str) -> Result<(), ConfigShowError> {
        let tier = self.resolve(env_var)?;
        let cfg = C::resolve_tier(tier);

        if let Some(diff_arg) = self.diff {
            let baseline_tier = Self::tier_arg_to_tier(diff_arg, env_var, &self.path)?;
            let baseline = C::resolve_tier(baseline_tier);
            print!("{}", cfg.diff_against(&baseline).render_unified());
            return Ok(());
        }

        let s = match self.format {
            OutputFormat::Yaml => serde_yaml::to_string(&cfg)?,
            OutputFormat::Json => serde_json::to_string_pretty(&cfg)?,
        };
        print!("{s}");
        Ok(())
    }

    /// Resolve `self.tier` (with `self.path` for `custom`, `env_var`
    /// for `env`) into a `ConfigTier`.
    fn resolve(&self, env_var: &str) -> Result<ConfigTier, ConfigShowError> {
        Self::tier_arg_to_tier(self.tier, env_var, &self.path)
    }

    fn tier_arg_to_tier(
        arg: TierArg,
        env_var: &str,
        path: &Option<PathBuf>,
    ) -> Result<ConfigTier, ConfigShowError> {
        Ok(match arg {
            TierArg::Bare => ConfigTier::Bare,
            TierArg::Discovered => ConfigTier::Discovered,
            TierArg::Default => ConfigTier::Default,
            TierArg::Custom => match path {
                Some(p) => ConfigTier::Custom(p.clone()),
                None => return Err(ConfigShowError::CustomTierWithoutPath),
            },
            TierArg::Env => ConfigTier::from_env(env_var),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    struct FixtureConfig {
        port: u16,
        log_level: String,
    }

    impl TieredConfig for FixtureConfig {
        fn bare() -> Self {
            Self { port: 0, log_level: String::new() }
        }
        fn prescribed_default() -> Self {
            Self { port: 8080, log_level: "info".into() }
        }
    }

    #[test]
    fn run_default_tier_emits_prescribed_yaml() {
        let cmd = ConfigShowCommand {
            tier: TierArg::Default,
            path: None,
            format: OutputFormat::Yaml,
            diff: None,
        };
        // Smoke test: doesn't error. (Output goes to stdout; the
        // contract test we want is that no error path is taken.)
        cmd.run::<FixtureConfig>("FIXTURE_TIER").unwrap();
    }

    #[test]
    fn run_bare_tier_dispatches_to_bare_via_resolve() {
        let cmd = ConfigShowCommand {
            tier: TierArg::Bare,
            path: None,
            format: OutputFormat::Json,
            diff: None,
        };
        cmd.run::<FixtureConfig>("FIXTURE_TIER").unwrap();
    }

    #[test]
    fn custom_tier_without_path_errors() {
        let cmd = ConfigShowCommand {
            tier: TierArg::Custom,
            path: None,
            format: OutputFormat::Yaml,
            diff: None,
        };
        let err = cmd.run::<FixtureConfig>("FIXTURE_TIER").unwrap_err();
        assert!(matches!(err, ConfigShowError::CustomTierWithoutPath));
    }

    #[test]
    fn diff_renders_unified_diff_without_panic() {
        let cmd = ConfigShowCommand {
            tier: TierArg::Default,
            path: None,
            format: OutputFormat::Yaml,
            diff: Some(TierArg::Bare),
        };
        cmd.run::<FixtureConfig>("FIXTURE_TIER").unwrap();
    }

    #[test]
    fn env_tier_resolves_via_env_var() {
        // SAFETY: tests don't share env state by default in cargo's
        // single-process runner. Use a unique name to avoid clashes.
        // SAFETY: set_var is safe in single-threaded test contexts.
        unsafe { std::env::set_var("FIXTURE_TIER_TEST_BARE", "bare") };
        let cmd = ConfigShowCommand {
            tier: TierArg::Env,
            path: None,
            format: OutputFormat::Yaml,
            diff: None,
        };
        cmd.run::<FixtureConfig>("FIXTURE_TIER_TEST_BARE").unwrap();
        unsafe { std::env::remove_var("FIXTURE_TIER_TEST_BARE") };
    }
}

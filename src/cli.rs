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

impl TierArg {
    /// Every [`TierArg`] variant in declaration order — the CLI-side
    /// peer of [`crate::ConfigTierKind::ALL`] on the tier axis. The
    /// per-enum-listing sibling of the [`crate::ClosedAxis`] `ALL`
    /// slices across the crate ([`crate::tiered::ConfigTierKind::ALL`],
    /// [`crate::discovery::Format::ALL`], [`crate::coverage::HintSurface::ALL`],
    /// [`crate::secret::SecretBackendKind::ALL`]) applied to the CLI
    /// operator surface. The [`TierArg::Env`] arm is the CLI-only
    /// cell (no [`crate::ConfigTier::Env`] peer — it dispatches into
    /// [`crate::ConfigTier::from_env`]), so the CLI axis carries five
    /// cells rather than the four-cell [`crate::ConfigTier`] /
    /// [`crate::ConfigTierKind`] pair.
    ///
    /// Consumers iterate this to enumerate every operator-selectable
    /// tier without hand-listing variants — a documentation renderer
    /// covering every `<APP> config-show` tier flag, a shell-completion
    /// helper listing the allowed values, a `for arg in TierArg::ALL`
    /// loop in a fleet-wide smoke test that dispatches every arg
    /// through [`ConfigShowCommand::run`]. A new [`TierArg`] variant is
    /// picked up here in one place and flows through every ALL-driven
    /// caller automatically.
    pub const ALL: &'static [Self] = &[
        Self::Bare,
        Self::Discovered,
        Self::Default,
        Self::Custom,
        Self::Env,
    ];

    /// Returns `true` for [`Self::Bare`]; equivalent to
    /// `self == TierArg::Bare`.
    ///
    /// CLI-side sibling of [`crate::ConfigTierKind::is_bare`] /
    /// [`crate::ConfigTier::is_bare`]: the closed-partition arm on
    /// the CLI tier tag lifts to a `Copy`-taking `const fn` on the
    /// discriminant, so a consumer routing a [`ConfigShowCommand`] by
    /// tier — a fleet-wide operator-facing log line ("resolved from
    /// the bare tier"), a completion helper filtering out the `Env`
    /// arm, a telemetry counter keyed on the operator's tier
    /// selection — can classify without spelling `self.tier ==
    /// TierArg::Bare` at its own site.
    ///
    /// The five sibling predicates form a closed disjoint partition
    /// of [`Self::ALL`] — every variant satisfies exactly one — pinned
    /// by [`tests::tier_arg_predicates_are_a_closed_quinary_partition`].
    /// Agreement with the closed-equality check against each variant
    /// is pinned pointwise over [`Self::ALL`] by
    /// [`tests::tier_arg_predicates_agree_with_equality_pointwise`], so
    /// a future edit whose `matches!` arm silently accepts a second
    /// variant fails there before drifting through any consumer site.
    ///
    /// Peer of the tag-side quartet predicates on
    /// [`crate::ConfigTier`] (`aefc87a`) and the CLI-side operator
    /// surface analog of the quaternary-partition closures on
    /// [`crate::coverage::HintSurface`] (`face7ff`) and
    /// [`crate::tiered::DiffLine`] (`deaa9b4`) — same closed-partition
    /// shape, one cell wider (the CLI-only [`Self::Env`] arm).
    #[must_use]
    pub const fn is_bare(self) -> bool {
        matches!(self, Self::Bare)
    }

    /// Returns `true` for [`Self::Discovered`]. See [`Self::is_bare`]
    /// for the full contract.
    #[must_use]
    pub const fn is_discovered(self) -> bool {
        matches!(self, Self::Discovered)
    }

    /// Returns `true` for [`Self::Default`]. See [`Self::is_bare`] for
    /// the full contract.
    #[must_use]
    pub const fn is_default(self) -> bool {
        matches!(self, Self::Default)
    }

    /// Returns `true` for [`Self::Custom`]. See [`Self::is_bare`] for
    /// the full contract.
    ///
    /// Note: the `Custom` arm carries no payload here — the operator
    /// supplies the path as a separate `--path` flag on
    /// [`ConfigShowCommand`], and the arg → [`crate::ConfigTier`]
    /// dispatch in [`ConfigShowCommand::tier_arg_to_tier`] pairs the
    /// two into a [`crate::ConfigTier::Custom`]`(PathBuf)`. So the
    /// CLI-side `is_custom` is a pure discriminant check with no
    /// payload-independence concern, unlike its
    /// [`crate::ConfigTier::is_custom`] peer.
    #[must_use]
    pub const fn is_custom(self) -> bool {
        matches!(self, Self::Custom)
    }

    /// Returns `true` for [`Self::Env`]; the CLI-only arm with no
    /// [`crate::ConfigTier`] peer. See [`Self::is_bare`] for the full
    /// contract.
    #[must_use]
    pub const fn is_env(self) -> bool {
        matches!(self, Self::Env)
    }
}

/// Emission format for `config-show` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// YAML — the canonical pleme-io config emission format.
    Yaml,
    /// JSON — machine-readable, useful for piping into jq.
    Json,
}

impl OutputFormat {
    /// Every [`OutputFormat`] variant in declaration order — the
    /// CLI-side emission-format peer of [`TierArg::ALL`] (the CLI-side
    /// tier tag) and of [`crate::discovery::Format::ALL`] (the shikumi
    /// config-file-format axis). The emission axis is deliberately
    /// narrower than the read axis: the four-cell parser-format space
    /// (YAML/TOML/lisp/nix/blue) folds down to a two-cell emitter
    /// space (YAML + JSON) because JSON is the ubiquitous machine-
    /// readable escape hatch every jq/downstream-pipeline consumer
    /// speaks, and TOML/lisp/nix/blue add no operator-facing round-
    /// tripping benefit over YAML at emission time.
    ///
    /// Consumers iterate this to enumerate every operator-selectable
    /// `--format` value without hand-listing variants — a shell-
    /// completion helper listing the allowed emissions, a
    /// documentation renderer covering every `<APP> config-show
    /// --format` value, a `for fmt in OutputFormat::ALL` loop in a
    /// fleet-wide smoke test that dispatches every emitter through
    /// [`ConfigShowCommand::run`]. A new [`OutputFormat`] variant is
    /// picked up here in one place and flows through every ALL-driven
    /// caller automatically.
    pub const ALL: &'static [Self] = &[Self::Yaml, Self::Json];

    /// Returns `true` for [`Self::Yaml`]; equivalent to
    /// `self == OutputFormat::Yaml`.
    ///
    /// CLI-side emission-axis sibling of the shikumi-side
    /// [`crate::discovery::Format::is_yaml`] parser-axis predicate —
    /// same closed-partition shape, one axis over (emission not
    /// read). The two-arm partition on the CLI operator-facing
    /// emission tag lifts to a `Copy`-taking `const fn` on the
    /// discriminant, so a consumer routing a [`ConfigShowCommand`]
    /// by emission — a fleet-wide operator-facing log line
    /// ("emitted as yaml"), a completion helper filtering the
    /// `--format` value space, a telemetry counter keyed on the
    /// operator's emission selection — can classify without spelling
    /// `self.format == OutputFormat::Yaml` at its own site.
    ///
    /// The two sibling predicates form a closed disjoint partition
    /// of [`Self::ALL`] — every variant satisfies exactly one —
    /// pinned by
    /// [`tests::output_format_predicates_are_a_closed_binary_partition`].
    /// Agreement with the closed-equality check against each variant
    /// is pinned pointwise over [`Self::ALL`] by
    /// [`tests::output_format_predicates_agree_with_equality_pointwise`],
    /// so a future edit whose `matches!` arm silently accepts a
    /// second variant fails there before drifting through any
    /// consumer site.
    ///
    /// Peer of the binary-partition closures on
    /// [`crate::SecretRefShape`] (`aa30052`) and
    /// [`crate::PartitionFace`] (`990892e`) — same closed-binary
    /// shape, applied to the CLI-side emission format tag.
    #[must_use]
    pub const fn is_yaml(self) -> bool {
        matches!(self, Self::Yaml)
    }

    /// Returns `true` for [`Self::Json`]; equivalent to
    /// `self == OutputFormat::Json`. Sibling of [`Self::is_yaml`];
    /// see [`Self::is_yaml`] for the full contract.
    #[must_use]
    pub const fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
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

impl ConfigShowError {
    /// True iff this rejection is [`Self::CustomTierWithoutPath`] — the
    /// operator asked for `tier custom` but supplied no `--path <FILE>`
    /// to the [`ConfigShowCommand`]. The two payload-bearing
    /// serialization variants ([`Self::Yaml`] and [`Self::Json`]) both
    /// return `false`.
    ///
    /// **The tag-only classifier on the operator-input-versus-emission
    /// polarity axis.** A consumer holding a borrowed
    /// [`ConfigShowError`] previously had two paths for asking "is the
    /// failure the missing `--path` argument, or a per-emitter
    /// serialization failure?", each leaking work: (a)
    /// `matches!(err, ConfigShowError::CustomTierWithoutPath)` inline
    /// at every seam, a shape the exhaustiveness checker cannot help
    /// keep in sync with a future variant addition (a hypothetical
    /// fourth emitter variant would silently keep answering `false` at
    /// every inline `matches!` site); or (b) an outer `match`
    /// decomposing the whole three-arm sum at each classification
    /// site, forcing a re-declaration of the arms a consumer that
    /// only wants the polarity does not care about.
    ///
    /// The tag-only sibling here answers the same question through a
    /// single welded [`matches!`]: adding a fourth variant fails to
    /// compile at this method's pattern in lockstep with
    /// [`Self::is_yaml`] and [`Self::is_json`] via the
    /// ternary-partition pin
    /// [`tests::config_show_error_predicates_are_a_closed_ternary_partition`],
    /// which fires when a new variant collapses the partition sum to
    /// zero at that variant. Operator-facing help-line dispatches that
    /// surface "did you mean `--path <FILE>`?" only on the missing-
    /// argument rejection split from the two serialization arms (which
    /// name a backend rather than an operator input) reach the
    /// polarity through one method call.
    ///
    /// **Idiom-peer of the tag-side sibling-predicate closures on
    /// other closed-partition error primitives.** The direct
    /// methodological analogue of
    /// [`crate::discovery::ParseFormatCoordinatesError`]'s
    /// `is_missing_separator`/`is_unknown_format`/`is_unknown_provenance`
    /// trio (commit `dcc8cb3`), [`crate::ShikumiError`]'s
    /// `is_watch`/`is_io`/`is_figment`/`is_extract`/`is_validation`
    /// septet (commit `f881f6f`), and
    /// [`crate::secret_client::SecretError`]'s
    /// `is_not_found`/`is_unauthorized`/`is_unsupported`/`is_backend`/`is_shikumi`
    /// quintet (commit `bc1db8f`): same routing shape, same closed-
    /// partition contract on the CLI operator surface's payload-
    /// bearing error enum with zero pre-existing tag-side siblings.
    ///
    /// `const`-callable — a compile-time-known [`ConfigShowError`]
    /// projects its polarity at compile time too.
    #[must_use]
    pub const fn is_custom_tier_without_path(&self) -> bool {
        matches!(self, Self::CustomTierWithoutPath)
    }

    /// True iff this rejection is [`Self::Yaml`] — a YAML serialization
    /// failure surfaced from [`serde_yaml::to_string`] on the
    /// materialized-config value. The operator-input variant
    /// [`Self::CustomTierWithoutPath`] and the mirror emitter variant
    /// [`Self::Json`] both return `false`.
    ///
    /// Sibling of [`Self::is_custom_tier_without_path`] and
    /// [`Self::is_json`] on the same closed ternary partition; same
    /// routing rationale (see [`Self::is_custom_tier_without_path`]
    /// docs). A structured-log field that names the failing emission
    /// backend without hand-copying the variant tag, or a
    /// backend-selection retry (fall back to JSON when YAML rejects)
    /// routes on this predicate at the borrowed error without matching
    /// on the whole three-arm sum.
    #[must_use]
    pub const fn is_yaml(&self) -> bool {
        matches!(self, Self::Yaml(_))
    }

    /// True iff this rejection is [`Self::Json`] — a JSON serialization
    /// failure surfaced from [`serde_json::to_string_pretty`] on the
    /// materialized-config value. The operator-input variant
    /// [`Self::CustomTierWithoutPath`] and the mirror emitter variant
    /// [`Self::Yaml`] both return `false`.
    ///
    /// Sibling of [`Self::is_custom_tier_without_path`] and
    /// [`Self::is_yaml`] on the same closed ternary partition; same
    /// routing rationale (see [`Self::is_custom_tier_without_path`]
    /// docs). A structured-log field that names the failing emission
    /// backend without hand-copying the variant tag, or a
    /// backend-selection retry (fall back to YAML when JSON rejects)
    /// routes on this predicate at the borrowed error without matching
    /// on the whole three-arm sum.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::Json(_))
    }
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
            Self {
                port: 0,
                log_level: String::new(),
            }
        }
        fn prescribed_default() -> Self {
            Self {
                port: 8080,
                log_level: "info".into(),
            }
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

    // ─── TierArg sibling predicates — quintet-partition arms on the
    // ─── CLI operator-facing tier tag ───────────────────────────────

    #[test]
    fn tier_arg_all_enumerates_every_variant_in_declaration_order() {
        // Exhaustiveness pin on TierArg::ALL: every variant appears
        // exactly once and in declaration order. The `match` below is
        // the compile-time hook — a future variant landing on TierArg
        // must extend both the match arms and TierArg::ALL in lockstep.
        // Peer of `hint_surface_all_enumerates_every_variant` on the
        // coverage-hint surface tag.
        for arg in TierArg::ALL.iter().copied() {
            match arg {
                TierArg::Bare
                | TierArg::Discovered
                | TierArg::Default
                | TierArg::Custom
                | TierArg::Env => {}
            }
            assert!(
                TierArg::ALL.contains(&arg),
                "TierArg::ALL must contain {arg:?}",
            );
        }
        assert_eq!(TierArg::ALL.len(), 5);
        assert_eq!(TierArg::ALL[0], TierArg::Bare);
        assert_eq!(TierArg::ALL[1], TierArg::Discovered);
        assert_eq!(TierArg::ALL[2], TierArg::Default);
        assert_eq!(TierArg::ALL[3], TierArg::Custom);
        assert_eq!(TierArg::ALL[4], TierArg::Env);
    }

    #[test]
    fn tier_arg_is_bare_true_only_for_bare_variant() {
        // Per-variant polarity pin on the Bare corner of the TierArg
        // quintet. Sibling of `config_tier_is_bare_true_only_for_bare_variant`
        // on the ConfigTier tag-side quartet and of
        // `hint_surface_is_dead_knob_true_only_for_dead_knob_variant`
        // on the HintSurface quartet — same shape, one cell wider (the
        // CLI-only Env arm).
        assert!(TierArg::Bare.is_bare());
        assert!(!TierArg::Discovered.is_bare());
        assert!(!TierArg::Default.is_bare());
        assert!(!TierArg::Custom.is_bare());
        assert!(!TierArg::Env.is_bare());
    }

    #[test]
    fn tier_arg_is_discovered_true_only_for_discovered_variant() {
        assert!(!TierArg::Bare.is_discovered());
        assert!(TierArg::Discovered.is_discovered());
        assert!(!TierArg::Default.is_discovered());
        assert!(!TierArg::Custom.is_discovered());
        assert!(!TierArg::Env.is_discovered());
    }

    #[test]
    fn tier_arg_is_default_true_only_for_default_variant() {
        assert!(!TierArg::Bare.is_default());
        assert!(!TierArg::Discovered.is_default());
        assert!(TierArg::Default.is_default());
        assert!(!TierArg::Custom.is_default());
        assert!(!TierArg::Env.is_default());
    }

    #[test]
    fn tier_arg_is_custom_true_only_for_custom_variant() {
        assert!(!TierArg::Bare.is_custom());
        assert!(!TierArg::Discovered.is_custom());
        assert!(!TierArg::Default.is_custom());
        assert!(TierArg::Custom.is_custom());
        assert!(!TierArg::Env.is_custom());
    }

    #[test]
    fn tier_arg_is_env_true_only_for_env_variant() {
        assert!(!TierArg::Bare.is_env());
        assert!(!TierArg::Discovered.is_env());
        assert!(!TierArg::Default.is_env());
        assert!(!TierArg::Custom.is_env());
        assert!(TierArg::Env.is_env());
    }

    #[test]
    fn tier_arg_predicates_are_a_closed_quinary_partition() {
        // Every TierArg::ALL cell satisfies exactly one of the five
        // sibling predicates: none satisfies two, none satisfies zero.
        // The quinary-partition analogue of the quaternary-partition
        // pins on `HintSurface`
        // (`hint_surface_predicates_are_a_closed_quaternary_partition`)
        // and `ConfigTier`
        // (`config_tier_predicates_are_a_closed_quaternary_partition`),
        // and of the trio-partition pin on `ConfigSourceKind`
        // (`config_source_kind_predicates_are_a_closed_ternary_partition`).
        // A future sixth TierArg variant landing without its own
        // sibling predicate collapses the partition to zero on that
        // variant, failing here before drifting through any operator
        // dispatch site (a `--tier` documentation renderer, a shell-
        // completion helper, `tier_arg_to_tier`).
        for arg in TierArg::ALL.iter().copied() {
            let hits = usize::from(arg.is_bare())
                + usize::from(arg.is_discovered())
                + usize::from(arg.is_default())
                + usize::from(arg.is_custom())
                + usize::from(arg.is_env());
            assert_eq!(
                hits, 1,
                "TierArg::{arg:?} must satisfy exactly one of \
                 is_bare/is_discovered/is_default/is_custom/is_env \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn tier_arg_predicates_agree_with_equality_pointwise() {
        // The tag-alone equality-agreement law over TierArg::ALL,
        // matching the shape of
        // `hint_surface_predicates_agree_with_equality_pointwise` on
        // HintSurface and `config_source_kind_predicates_agree_with_equality_pointwise`
        // on ConfigSourceKind. Catches the dual case where a
        // predicate's `matches!` arm silently accepts a second variant
        // (say a copy-paste that widened `is_custom` to
        // `Self::Custom | Self::Env`) — the closed-quinary-partition
        // pin catches the "zero" side of that drift by flipping the
        // robbed corner's hits from 1 to 0; this pin catches the
        // "two on the same corner" side without needing another
        // corner to change.
        for arg in TierArg::ALL.iter().copied() {
            assert_eq!(arg.is_bare(), arg == TierArg::Bare);
            assert_eq!(arg.is_discovered(), arg == TierArg::Discovered);
            assert_eq!(arg.is_default(), arg == TierArg::Default);
            assert_eq!(arg.is_custom(), arg == TierArg::Custom);
            assert_eq!(arg.is_env(), arg == TierArg::Env);
        }
    }

    // ─── OutputFormat sibling predicates — binary-partition arms
    // ─── on the CLI operator-facing emission-format tag ────────────

    #[test]
    fn output_format_all_enumerates_every_variant_in_declaration_order() {
        // Exhaustiveness pin on OutputFormat::ALL: every variant
        // appears exactly once and in declaration order. The `match`
        // below is the compile-time hook — a future variant landing
        // on OutputFormat must extend both the match arms and
        // OutputFormat::ALL in lockstep. Peer of
        // `tier_arg_all_enumerates_every_variant_in_declaration_order`
        // on the CLI tier tag and of
        // `format_all_covers_every_variant` on the shikumi parser
        // format tag.
        for fmt in OutputFormat::ALL.iter().copied() {
            match fmt {
                OutputFormat::Yaml | OutputFormat::Json => {}
            }
            assert!(
                OutputFormat::ALL.contains(&fmt),
                "OutputFormat::ALL must contain {fmt:?}",
            );
        }
        assert_eq!(OutputFormat::ALL.len(), 2);
        assert_eq!(OutputFormat::ALL[0], OutputFormat::Yaml);
        assert_eq!(OutputFormat::ALL[1], OutputFormat::Json);
    }

    #[test]
    fn output_format_is_yaml_true_only_for_yaml_variant() {
        // Per-variant polarity pin on the Yaml corner of the
        // OutputFormat binary partition. Sibling of
        // `tier_arg_is_bare_true_only_for_bare_variant` on the CLI
        // tier tag and of `format_is_yaml_true_only_for_yaml_variant`
        // on the shikumi parser format tag — same shape, one axis
        // over (emission not read) and three cells narrower (no
        // TOML/lisp/nix/blue emitter arms).
        assert!(OutputFormat::Yaml.is_yaml());
        assert!(!OutputFormat::Json.is_yaml());
    }

    #[test]
    fn output_format_is_json_true_only_for_json_variant() {
        assert!(!OutputFormat::Yaml.is_json());
        assert!(OutputFormat::Json.is_json());
    }

    #[test]
    fn output_format_predicates_are_a_closed_binary_partition() {
        // Every OutputFormat::ALL cell satisfies exactly one of the
        // two sibling predicates: none satisfies two, none satisfies
        // zero. The binary-partition analogue of the quinary-
        // partition pin on TierArg
        // (`tier_arg_predicates_are_a_closed_quinary_partition`) and
        // of the quinary-partition pin on Format
        // (`format_predicates_are_a_closed_quinary_partition`), and
        // the CLI operator-surface peer of the binary-partition
        // closures on SecretRefShape and PartitionFace. A future
        // third OutputFormat variant landing without its own sibling
        // predicate collapses the partition to zero on that variant,
        // failing here before drifting through any operator dispatch
        // site (a `--format` documentation renderer, a shell-
        // completion helper, the [`OutputFormat::Yaml`] / [`OutputFormat::Json`]
        // dispatch inside [`ConfigShowCommand::run`]).
        for fmt in OutputFormat::ALL.iter().copied() {
            let hits = usize::from(fmt.is_yaml()) + usize::from(fmt.is_json());
            assert_eq!(
                hits, 1,
                "OutputFormat::{fmt:?} must satisfy exactly one of \
                 is_yaml/is_json (satisfied {hits})",
            );
        }
    }

    #[test]
    fn output_format_predicates_agree_with_equality_pointwise() {
        // The tag-alone equality-agreement law over OutputFormat::ALL,
        // matching the shape of
        // `tier_arg_predicates_agree_with_equality_pointwise` on the
        // CLI tier tag. Catches the dual case where a predicate's
        // `matches!` arm silently accepts a second variant (say a
        // copy-paste that widened `is_yaml` to `Self::Yaml | Self::Json`)
        // — the closed-binary-partition pin catches the "zero" side
        // of that drift by flipping the robbed corner's hits from 1
        // to 0; this pin catches the "two on the same corner" side
        // without needing another corner to change.
        for fmt in OutputFormat::ALL.iter().copied() {
            assert_eq!(fmt.is_yaml(), fmt == OutputFormat::Yaml);
            assert_eq!(fmt.is_json(), fmt == OutputFormat::Json);
        }
    }

    // ─── ConfigShowError sibling predicates — ternary-partition arms
    // ─── on the CLI-run rejection tag ──────────────────────────────

    /// Helper: build a `serde_yaml::Error` by asking the YAML parser
    /// to decode obviously malformed input, then converting into the
    /// unit variant `bool`. The exact error message is not part of
    /// the pin — only its type identity, so that the `#[from]`
    /// promotion into [`ConfigShowError::Yaml`] fires the same
    /// classifier a runtime `to_string` failure would.
    fn synthetic_yaml_error() -> serde_yaml::Error {
        serde_yaml::from_str::<bool>("[not a bool").expect_err("malformed YAML input must reject")
    }

    /// Helper: build a `serde_json::Error` by asking the JSON parser
    /// to decode obviously malformed input, then converting into the
    /// unit variant `bool`. Mirror of `synthetic_yaml_error` on the
    /// JSON-side promotion.
    fn synthetic_json_error() -> serde_json::Error {
        serde_json::from_str::<bool>("[not a bool").expect_err("malformed JSON input must reject")
    }

    #[test]
    fn config_show_error_is_custom_tier_without_path_true_only_for_missing_path_variant() {
        // Per-variant polarity pin on the CustomTierWithoutPath corner
        // of the `ConfigShowError` tag-side sibling-predicate trio. A
        // future edit that flips the `matches!` arm on
        // `ConfigShowError::is_custom_tier_without_path` fails here
        // before the closed-partition pin below masks it. Direct
        // methodological analogue of
        // `parse_format_coordinates_error_is_missing_separator_true_only_for_missing_separator_variant`
        // (`dcc8cb3`) on `ParseFormatCoordinatesError`, one crate
        // module over — same shape on the operator-input polarity of
        // the CLI rejection axis.
        assert!(ConfigShowError::CustomTierWithoutPath.is_custom_tier_without_path());
        assert!(!ConfigShowError::Yaml(synthetic_yaml_error()).is_custom_tier_without_path());
        assert!(!ConfigShowError::Json(synthetic_json_error()).is_custom_tier_without_path());
    }

    #[test]
    fn config_show_error_is_yaml_true_only_for_yaml_variant() {
        // Mirror per-variant polarity pin on the Yaml corner. The
        // payload is drawn from the `#[from] serde_yaml::Error` path
        // so the pin also structurally binds the enum's `From`
        // conversion to the sibling classifier: a future edit that
        // switched the `#[from]` slot to a different variant would
        // fail here before drifting through any consumer routing on
        // the polarity trio.
        assert!(!ConfigShowError::CustomTierWithoutPath.is_yaml());
        assert!(ConfigShowError::Yaml(synthetic_yaml_error()).is_yaml());
        assert!(!ConfigShowError::Json(synthetic_json_error()).is_yaml());
    }

    #[test]
    fn config_show_error_is_json_true_only_for_json_variant() {
        // Mirror per-variant polarity pin on the Json corner.
        assert!(!ConfigShowError::CustomTierWithoutPath.is_json());
        assert!(!ConfigShowError::Yaml(synthetic_yaml_error()).is_json());
        assert!(ConfigShowError::Json(synthetic_json_error()).is_json());
    }

    #[test]
    fn config_show_error_predicates_are_a_closed_ternary_partition() {
        // Every `ConfigShowError` value in the canonical sample table
        // satisfies exactly one of the three sibling predicates: none
        // satisfies two, none satisfies zero. Ternary-partition
        // analogue of the pin
        // `parse_format_coordinates_error_predicates_are_a_closed_ternary_partition`
        // (`dcc8cb3`) on `ParseFormatCoordinatesError`, lifted here
        // onto the CLI-run rejection tag. A future fourth variant
        // landing on `ConfigShowError` (a hypothetical `Toml(_)` /
        // `Blue(_)` emitter arm, or a second operator-input rejection
        // like `--diff` conflict with `--format`) without its own
        // sibling predicate collapses the partition to zero on that
        // variant, failing here before drifting through any
        // structured-log field, retry-policy dispatch, or
        // operator-facing suggestion engine that routes on the
        // polarity trio.
        let errors = [
            ConfigShowError::CustomTierWithoutPath,
            ConfigShowError::Yaml(synthetic_yaml_error()),
            ConfigShowError::Json(synthetic_json_error()),
        ];
        for err in &errors {
            let hits = usize::from(err.is_custom_tier_without_path())
                + usize::from(err.is_yaml())
                + usize::from(err.is_json());
            assert_eq!(
                hits, 1,
                "ConfigShowError::{err:?} must satisfy exactly one of \
                 is_custom_tier_without_path/is_yaml/is_json (satisfied {hits})",
            );
        }
    }

    #[test]
    fn config_show_error_predicates_agree_with_from_conversions_and_run_rejection() {
        // Cross-cut structural pin between the enum's `#[from]`
        // conversions (`serde_yaml::Error` → [`Self::Yaml`],
        // `serde_json::Error` → [`Self::Json`]) and the
        // `ConfigShowCommand::run` rejection path
        // (`tier=Custom, path=None` → [`Self::CustomTierWithoutPath`])
        // and the new sibling-predicate trio: each canonical
        // rejection origin lands on the predicate that names its
        // rejection mode. Sibling of the per-variant
        // `parse_format_coordinates_error_predicates_agree_with_from_str_rejection_paths`
        // pin (`dcc8cb3`), extended here to bridge the tag-side
        // classifier surface with both the `#[from]` derives and the
        // `run` control-flow contract. A future edit that swapped
        // either `#[from]` slot or changed the `run` rejection path
        // for the missing-`--path` case would fire here before
        // drifting through any consumer routing on the polarity trio.

        // ── operator-input rejection through `run` ────────────────
        let cmd = ConfigShowCommand {
            tier: TierArg::Custom,
            path: None,
            format: OutputFormat::Yaml,
            diff: None,
        };
        let err = cmd
            .run::<FixtureConfig>("FIXTURE_TIER")
            .expect_err("tier=Custom with path=None must reject");
        assert!(
            err.is_custom_tier_without_path(),
            "expected is_custom_tier_without_path for {err:?}",
        );
        assert!(!err.is_yaml());
        assert!(!err.is_json());

        // ── serde_yaml::Error promotion through `#[from]` ─────────
        let promoted_yaml: ConfigShowError = synthetic_yaml_error().into();
        assert!(!promoted_yaml.is_custom_tier_without_path());
        assert!(
            promoted_yaml.is_yaml(),
            "expected is_yaml for {promoted_yaml:?}",
        );
        assert!(!promoted_yaml.is_json());

        // ── serde_json::Error promotion through `#[from]` ─────────
        let promoted_json: ConfigShowError = synthetic_json_error().into();
        assert!(!promoted_json.is_custom_tier_without_path());
        assert!(!promoted_json.is_yaml());
        assert!(
            promoted_json.is_json(),
            "expected is_json for {promoted_json:?}",
        );
    }
}

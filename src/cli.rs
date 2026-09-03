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

    /// Returns `true` for the four computed-defaults arms
    /// ([`Self::Bare`], [`Self::Discovered`], [`Self::Default`],
    /// [`Self::Env`]), `false` for the operator-supplied overlay arm
    /// [`Self::Custom`] — the CLI-side lift of the compound-polarity
    /// sibling [`crate::ConfigTierKind::is_computed`] (commit `7d2825d`)
    /// onto the CLI operator-facing tier tag at this altitude.
    ///
    /// **Names the *computed-defaults* pole on the CLI tag.** A consumer
    /// answering *"does this operator-selected tier resolve WITHOUT the
    /// `--path <FILE>` flag on [`ConfigShowCommand`]?"* previously routed
    /// either through the double-negative `!arg.is_custom()` on the tag
    /// axis or through the four-arm disjunction `arg.is_bare() ||
    /// arg.is_discovered() || arg.is_default() || arg.is_env()` at the
    /// call site — a `--tier` documentation renderer coloring the one
    /// path-requiring arm distinctly from the four path-optional arms, a
    /// shell-completion helper filtering the arms whose `--path` value
    /// is inert, a per-tier telemetry counter bucketing custom overlays
    /// separately from every computed dispatch, a startup-log line
    /// naming which pole the operator's `--tier` selection sits at. The
    /// compound predicate answers the same query at one canonical site
    /// now, matching the vocabulary the sibling ladder for `is_computed`
    /// already carries at the [`crate::ConfigTierKind`] (commit
    /// `7d2825d`), [`crate::ConfigTier`], [`crate::Provenance`], and
    /// [`crate::ProgressiveLayer`] altitudes.
    ///
    /// The dispatch table [`ConfigShowCommand::run`] pointwise witnesses
    /// this polarity: exactly the [`Self::Custom`] arm returns
    /// [`ConfigShowError::CustomTierWithoutPath`] when
    /// [`ConfigShowCommand::path`] is [`None`]; every other arm
    /// (`Bare`/`Discovered`/`Default`/`Env`) resolves without inspecting
    /// `path`. The `is_computed` predicate names that "path-independent"
    /// pole at the type level so a future refactor threading the
    /// path-inspection surface cannot silently widen the arm set that
    /// needs a `--path <FILE>` companion.
    ///
    /// The [`Self::Env`] arm is the CLI-only cell — no
    /// [`crate::ConfigTierKind`] peer — and sits under the *computed*
    /// pole here because the `<APP>_TIER` env-var read is a runtime
    /// dispatch to *another* [`crate::ConfigTier`] rather than a
    /// direct operator-supplied overlay: `TierArg::Env` never carries a
    /// path in its own dispatch (see
    /// [`ConfigShowCommand::tier_arg_to_tier`]), even though the env-var
    /// contents may resolve to a [`crate::ConfigTier::Custom`] downstream
    /// via [`crate::ConfigTier::from_env`]. That distinction — polarity
    /// classified on the *CLI-supplied artifact* axis, not the eventual
    /// resolved-`ConfigTier` — matches the design choice
    /// [`Self::is_custom`]'s docs already flag: on the CLI axis the
    /// `Custom` arm carries no payload here, and the compound-polarity
    /// sibling on this axis lifts the same authored-artifact discipline.
    ///
    /// The modal-pair complement law `is_computed() == !is_custom()`
    /// holds pointwise on every [`Self::ALL`] cell, pinned by
    /// [`tests::tier_arg_is_computed_is_complement_of_is_custom`]. The
    /// compound ↔ four-arm disjunction law
    /// `arg.is_computed() == arg.is_bare() || arg.is_discovered() ||
    /// arg.is_default() || arg.is_env()` is pinned pointwise by
    /// [`tests::tier_arg_is_computed_agrees_with_disjunction_of_computed_siblings`],
    /// and cross-axis agreement with
    /// [`crate::ConfigTierKind::is_computed`] on the four
    /// [`crate::ConfigTierKind`]-peer cells (`Bare`/`Discovered`/
    /// `Default`/`Custom`) is pinned by
    /// [`tests::tier_arg_is_computed_agrees_with_config_tier_kind_on_shared_cells`],
    /// so a future drift of either compound-polarity arm from the shared
    /// semantic fails at the cross-axis boundary rather than at a
    /// per-polarity consumer site.
    ///
    /// A future sixth [`Self`] variant landing without explicit polarity
    /// assignment collapses the complement law immediately — the new
    /// variant is either `true` on both `is_computed` and `is_custom`
    /// (impossible) or `false` on both (the polarity axis has no answer
    /// for it), failing the complement pin before drifting through any
    /// per-polarity CLI consumer.
    #[must_use]
    pub const fn is_computed(self) -> bool {
        matches!(
            self,
            Self::Bare | Self::Discovered | Self::Default | Self::Env
        )
    }

    /// The [`Self::Bare`] pole of the five-way identity meta-partition
    /// on the CLI operator-facing tier tag at the static-slice
    /// altitude — the singleton slice `&[Self::Bare]` mirroring the
    /// shipped boolean predicate [`Self::is_bare`] one altitude down.
    ///
    /// Fresh identity-partition constant, kept independent of any
    /// future compound-polarity slice on this axis (a hypothetical
    /// `COMPUTED: &[Self::Bare, Self::Discovered, Self::Default,
    /// Self::Env]` peer of the CLI compound sibling
    /// [`Self::is_computed`], mirroring the crate-side pair
    /// [`crate::ConfigTierKind::COMPUTED`] / [`crate::ConfigTierKind::CUSTOM`]
    /// at commit `2c0686f`): the two partitions stay independent so a
    /// hypothetical sixth CLI arm (a future `File(PathBuf)` for an
    /// explicit `--tier file --path <FILE>` overlay separate from
    /// `Custom`, a hypothetical `Runtime` for a CLI-visible tick-
    /// reconciler tier) grows the compound-polarity slice in lockstep
    /// with the `is_computed`-family pole contract while
    /// [`Self::ONLY_BARE`] stays a singleton by identity-partition
    /// definition.
    ///
    /// Idiom-peer of [`crate::ConfigTierKind::ONLY_BARE`] (commit
    /// `ff6492b`, the FIRST quaternary identity-partition landing on a
    /// shikumi-native closed-primitive axis and the direct crate-side
    /// peer of this CLI-side axis on the atomic `(tier, source)` pair
    /// one primitive over), lifted here onto the five-way CLI tier tag
    /// as the FIRST quinary identity-partition landing of the per-half
    /// meta-partition slice-constant discipline on the CLI operator-
    /// facing tier tag — one cell wider (the CLI-only [`Self::Env`]
    /// arm) than the crate-side quaternary landing.
    ///
    /// Paired with [`Self::ONLY_DISCOVERED`], [`Self::ONLY_DEFAULT`],
    /// [`Self::ONLY_CUSTOM`], and [`Self::ONLY_ENV`], the five
    /// disjoint singletons partition [`Self::ALL`] at the static-slice
    /// altitude the same way the shipped boolean predicates
    /// [`Self::is_bare`] / [`Self::is_discovered`] /
    /// [`Self::is_default`] / [`Self::is_custom`] / [`Self::is_env`]
    /// meta-partition it at the boolean altitude. The five constants
    /// sit in the same `impl TierArg` block as [`Self::ALL`], and
    /// follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Welded by
    /// [`tests::tier_arg_identity_slices_agree_with_identity_predicates`],
    /// [`tests::tier_arg_identity_slices_partition_all`],
    /// [`tests::tier_arg_identity_slices_preserve_all_order`],
    /// [`tests::tier_arg_identity_slices_have_no_duplicates`],
    /// [`tests::tier_arg_identity_slice_lengths_agree_with_boolean_pole_cardinalities`],
    /// and
    /// [`tests::tier_arg_identity_slices_are_const_addressable`].
    pub const ONLY_BARE: &'static [Self] = &[Self::Bare];

    /// The [`Self::Discovered`] pole of the five-way identity
    /// meta-partition on the CLI operator-facing tier tag at the
    /// static-slice altitude — the singleton slice
    /// `&[Self::Discovered]` mirroring the shipped boolean predicate
    /// [`Self::is_discovered`] one altitude down.
    ///
    /// See [`Self::ONLY_BARE`] for the full contract, the discipline
    /// behind the fresh identity-partition constants (independent of
    /// any future compound-polarity slice), and the load-bearing
    /// agreement, partition, order-preservation, no-duplicates,
    /// cardinality, and const-addressability pins the five `ONLY_*`
    /// singletons share.
    pub const ONLY_DISCOVERED: &'static [Self] = &[Self::Discovered];

    /// The [`Self::Default`] pole of the five-way identity
    /// meta-partition on the CLI operator-facing tier tag at the
    /// static-slice altitude — the singleton slice `&[Self::Default]`
    /// mirroring the shipped boolean predicate [`Self::is_default`]
    /// one altitude down.
    ///
    /// See [`Self::ONLY_BARE`] for the full contract and the load-
    /// bearing agreement, partition, order-preservation,
    /// no-duplicates, cardinality, and const-addressability pins the
    /// five `ONLY_*` singletons share.
    pub const ONLY_DEFAULT: &'static [Self] = &[Self::Default];

    /// The [`Self::Custom`] pole of the five-way identity
    /// meta-partition on the CLI operator-facing tier tag at the
    /// static-slice altitude — the singleton slice `&[Self::Custom]`
    /// mirroring the shipped boolean predicate [`Self::is_custom`]
    /// one altitude down.
    ///
    /// See [`Self::ONLY_BARE`] for the full contract and the load-
    /// bearing agreement, partition, order-preservation,
    /// no-duplicates, cardinality, and const-addressability pins the
    /// five `ONLY_*` singletons share.
    pub const ONLY_CUSTOM: &'static [Self] = &[Self::Custom];

    /// The [`Self::Env`] pole of the five-way identity meta-partition
    /// on the CLI operator-facing tier tag at the static-slice
    /// altitude — the singleton slice `&[Self::Env]` mirroring the
    /// shipped boolean predicate [`Self::is_env`] one altitude down.
    ///
    /// The CLI-only cell (no [`crate::ConfigTierKind`] peer), so this
    /// constant is the CLI-side surface without a crate-side sibling
    /// — the fifth arm the CLI tier tag carries beyond the four
    /// crate-side arms. See [`Self::ONLY_BARE`] for the full contract
    /// and the load-bearing agreement, partition, order-preservation,
    /// no-duplicates, cardinality, and const-addressability pins the
    /// five `ONLY_*` singletons share.
    pub const ONLY_ENV: &'static [Self] = &[Self::Env];
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

    /// The single YAML [`OutputFormat`] variant — [`Self::Yaml`] — in
    /// the SAME relative declaration order it occupies in
    /// [`Self::ALL`], forming one pole of the (yaml × json) closed-
    /// binary polarity at the CLI operator-facing emission-format
    /// primitive's OWN altitude. Mirrors the shipped boolean predicate
    /// [`Self::is_yaml`] one altitude down (per-variant polarity), and
    /// follows the same `pub const &'static [Self]` static-slice
    /// discipline as [`Self::ALL`].
    ///
    /// Written as an explicit one-variant slice literal (rather than
    /// derived by filtering [`Self::ALL`] through [`Self::is_yaml`] at
    /// const-fn altitude), so the two declarations — the slice literal
    /// and the boolean predicate — remain independent load-bearing
    /// witnesses of the same meta-partition. An edit shifting the
    /// polarity of a variant on ONE declaration surface but not the
    /// other diverges at test time on the first format where they
    /// disagree, before drifting through any consumer that reads one
    /// altitude but not the other.
    ///
    /// **Idiom-peer.** Ninth (crate-wide) landing of the per-half
    /// meta-partition slice-constant discipline, matched altitude-for-
    /// altitude with
    /// [`crate::error::AttributionConfidence::EXACT`]
    /// (commit `13c1003`),
    /// [`crate::discovery::FormatProvenance::FIGMENT_BUILTIN`]
    /// (commit `7ef79e4`),
    /// [`crate::SecretRefShape::WHOLE`]
    /// (commit `036673b`),
    /// [`crate::PartitionFace::REALIZABLE`]
    /// (commit `a344056`),
    /// [`crate::ConfigSourceKind::DEFAULTS`]
    /// (commit `2cd8ef8`),
    /// [`crate::ConfigTierKind::COMPUTED`]
    /// (commit `2c0686f`),
    /// [`crate::secret_client::SecretClientKind::CLOUD_SECRET_MANAGER`]
    /// (commit `399ee8a`), and
    /// [`crate::SecretBackendKind::CLOUD_SECRET_MANAGER`]
    /// (commit `04e0f5d`) — the per-half meta-partition slice-constant
    /// discipline applied here to the CLI-side emission-format axis
    /// (the FIRST landing on a `cli.rs`-scoped primitive), lifting the
    /// [`OutputFormat`] closed-binary primitive onto the slice-constant
    /// altitude.
    ///
    /// A future third emitter variant (e.g. a hypothetical `Toml`
    /// class the primitive's own doc-comment already anticipates as a
    /// deliberate narrowing today) lands here either extending one of
    /// the two slices in lockstep with the boolean predicate that
    /// admits it, or introducing a third slice; the partition and
    /// cardinality pins refuse a silent landing under the negation of
    /// one of the existing two.
    ///
    /// The two agreement laws
    /// (`YAML.iter().all(|f| f.is_yaml())` and
    /// `YAML.iter().all(|f| !f.is_json())`) are pinned by
    /// [`tests::output_format_yaml_slice_agrees_with_is_yaml_predicate`].
    /// Partition invariant with [`Self::JSON`]:
    /// [`tests::output_format_yaml_and_json_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::output_format_yaml_and_json_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::output_format_yaml_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::output_format_yaml_and_json_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::output_format_yaml_and_json_slices_are_const_addressable`].
    pub const YAML: &'static [Self] = &[Self::Yaml];

    /// The single JSON [`OutputFormat`] variant — [`Self::Json`] — in
    /// the SAME relative declaration order it occupies in
    /// [`Self::ALL`], the complement pole of [`Self::YAML`] on the
    /// (yaml × json) closed-binary polarity at the emission-format
    /// primitive's OWN altitude. Mirrors the shipped boolean predicate
    /// [`Self::is_json`] one altitude down.
    ///
    /// The partition invariant with [`Self::YAML`] pins the whole-set
    /// cardinality identity `YAML.len() + JSON.len() == ALL.len()`.
    /// Because the emission axis is closed-binary and XOR-
    /// complementary by construction today, a future third emitter
    /// landing (e.g. a `Toml` class) would first fail the two-entry
    /// cardinality pins, then fail the partition and cardinality pins
    /// on this constant pair unless extended in lockstep with the
    /// boolean predicates.
    ///
    /// See [`Self::YAML`] for the full contract, the discipline behind
    /// the explicit slice literal (rather than a filter through
    /// [`Self::is_yaml`]), and the load-bearing agreement and
    /// partition pins.
    pub const JSON: &'static [Self] = &[Self::Json];
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

    // ─── TierArg::is_computed — compound-polarity sibling on the
    // ─── CLI operator-facing tier tag ──────────────────────────────

    #[test]
    fn tier_arg_is_computed_partitions_custom_from_computed_arms() {
        // Per-variant polarity table on the compound-polarity sibling
        // over TierArg::ALL: the four computed-defaults arms answer
        // `true`, the operator-supplied-overlay arm answers `false`.
        // Direct CLI-side lift of the
        // `config_tier_kind_is_computed_partitions_custom_from_computed_defaults`
        // pin on the crate-side [`ConfigTierKind`] compound-polarity
        // sibling (commit `7d2825d`); one cell wider (the CLI-only Env
        // arm sits under the computed pole because the `<APP>_TIER`
        // env-var read is a runtime dispatch, not an operator-supplied
        // overlay artifact — see `TierArg::is_computed` docs). A future
        // sixth TierArg variant landing without explicit polarity
        // assignment breaks the partition here before drifting through
        // any per-polarity CLI consumer.
        assert!(TierArg::Bare.is_computed());
        assert!(TierArg::Discovered.is_computed());
        assert!(TierArg::Default.is_computed());
        assert!(!TierArg::Custom.is_computed());
        assert!(TierArg::Env.is_computed());
    }

    #[test]
    fn tier_arg_is_computed_is_complement_of_is_custom() {
        // The modal-pair complement law
        // `arg.is_computed() == !arg.is_custom()` pointwise on
        // TierArg::ALL. Direct CLI-side analogue of
        // `config_tier_kind_is_computed_is_complement_of_is_custom` on
        // the crate-side [`ConfigTierKind`] axis. A future variant
        // landing without explicit polarity assignment fails here
        // (either it satisfies both is_computed and is_custom —
        // impossible — or neither — the polarity axis has no answer).
        for arg in TierArg::ALL.iter().copied() {
            assert_eq!(
                arg.is_computed(),
                !arg.is_custom(),
                "TierArg::{arg:?}: is_computed() must be the complement of \
                 is_custom()",
            );
        }
    }

    #[test]
    fn tier_arg_is_computed_agrees_with_disjunction_of_computed_siblings() {
        // The compound ↔ four-arm disjunction law
        // `arg.is_computed() == arg.is_bare() || arg.is_discovered() ||
        // arg.is_default() || arg.is_env()` pointwise on TierArg::ALL.
        // A future edit that widened one primitive-arm predicate would
        // drift the compound at that cell, failing here before drifting
        // through any per-polarity consumer site.
        for arg in TierArg::ALL.iter().copied() {
            let disjunction =
                arg.is_bare() || arg.is_discovered() || arg.is_default() || arg.is_env();
            assert_eq!(
                arg.is_computed(),
                disjunction,
                "TierArg::{arg:?}: is_computed() must agree with the four-arm \
                 disjunction is_bare || is_discovered || is_default || is_env",
            );
        }
    }

    #[test]
    fn tier_arg_is_computed_agrees_with_config_tier_kind_on_shared_cells() {
        // Cross-axis agreement law
        // `arg.is_computed() == kind.is_computed()` pointwise on the
        // four cells that TierArg shares with
        // [`crate::ConfigTierKind`] (`Bare`/`Discovered`/`Default`/
        // `Custom`). The CLI-only [`TierArg::Env`] arm has no
        // ConfigTierKind peer to compare against — it's classified
        // separately by
        // `tier_arg_is_computed_partitions_custom_from_computed_arms`.
        // A future drift of either compound-polarity arm from the
        // shared semantic fails here before drifting through the
        // crate-side / CLI-side seam.
        use crate::tiered::ConfigTierKind;
        for (arg, kind) in [
            (TierArg::Bare, ConfigTierKind::Bare),
            (TierArg::Discovered, ConfigTierKind::Discovered),
            (TierArg::Default, ConfigTierKind::Default),
            (TierArg::Custom, ConfigTierKind::Custom),
        ] {
            assert_eq!(
                arg.is_computed(),
                kind.is_computed(),
                "TierArg::{arg:?} and ConfigTierKind::{kind:?} must agree on \
                 is_computed()",
            );
        }
    }

    #[test]
    fn tier_arg_is_computed_is_const_callable() {
        // Compile-time weld: the compound-polarity sibling
        // (`TierArg::is_computed`) is const-callable in every
        // TierArg::ALL cell, matching the const-callability of the
        // primitive-arm siblings (`is_bare`/`is_discovered`/`is_default`/
        // `is_custom`/`is_env`) and of the crate-side compound-polarity
        // siblings [`ConfigTierKind::is_computed`] and
        // [`ConfigTier::is_computed`]. Dropping the `const` qualifier
        // fails the test to compile.
        const BARE_IS_COMPUTED: bool = TierArg::Bare.is_computed();
        const DISCOVERED_IS_COMPUTED: bool = TierArg::Discovered.is_computed();
        const DEFAULT_IS_COMPUTED: bool = TierArg::Default.is_computed();
        const CUSTOM_IS_COMPUTED: bool = TierArg::Custom.is_computed();
        const ENV_IS_COMPUTED: bool = TierArg::Env.is_computed();
        assert!(BARE_IS_COMPUTED);
        assert!(DISCOVERED_IS_COMPUTED);
        assert!(DEFAULT_IS_COMPUTED);
        assert!(!CUSTOM_IS_COMPUTED);
        assert!(ENV_IS_COMPUTED);
    }

    #[test]
    fn tier_arg_is_computed_partition_and_complement_hold_over_all() {
        // Load-bearing invariant on the CLI operator-facing tier tag:
        // `TierArg::ALL` splits into exactly one Custom cell and four
        // computed cells under the compound-polarity sibling. A future
        // rearrangement of TierArg::ALL that dropped an arm or added a
        // sixth without extending the compound arm here fails the
        // cardinality pin before drifting through the dispatch table
        // in [`ConfigShowCommand::tier_arg_to_tier`], where exactly
        // one arm (Custom) returns [`ConfigShowError::CustomTierWithoutPath`]
        // when [`ConfigShowCommand::path`] is [`None`]. The pin ties
        // the polarity to the dispatch surface it names.
        let computed_count = TierArg::ALL.iter().filter(|a| a.is_computed()).count();
        let custom_count = TierArg::ALL.iter().filter(|a| a.is_custom()).count();
        assert_eq!(
            computed_count, 4,
            "exactly four TierArg cells must be is_computed()",
        );
        assert_eq!(
            custom_count, 1,
            "exactly one TierArg cell must be is_custom()",
        );
        assert_eq!(
            computed_count + custom_count,
            TierArg::ALL.len(),
            "compound-polarity partition must cover TierArg::ALL exhaustively",
        );
    }

    // ── TierArg ONLY_* five-way identity meta-partition
    //
    // Static-slice altitude of the five-way (bare × discovered ×
    // default × custom × env) 1/1/1/1/1 identity meta-partition on
    // the CLI operator-facing tier tag. The five singleton slices
    // `ONLY_BARE / ONLY_DISCOVERED / ONLY_DEFAULT / ONLY_CUSTOM /
    // ONLY_ENV` are the identity projection of the shipped boolean
    // predicates `is_bare / is_discovered / is_default / is_custom /
    // is_env` one altitude down.
    //
    // Idiom-peer of the six quaternary identity-partition pins on
    // `ConfigTierKind::ONLY_BARE / ONLY_DISCOVERED / ONLY_DEFAULT /
    // ONLY_CUSTOM` at `config_tier_kind_identity_*` (`ff6492b`, the
    // FIRST quaternary landing of the discipline on a shikumi-native
    // closed-primitive axis and the direct crate-side peer of this
    // CLI-side axis on the atomic `(tier, source)` pair one primitive
    // over), lifted here onto the five-way CLI tier tag. FIRST quinary
    // identity-partition landing of the per-half meta-partition slice-
    // constant discipline on a `cli.rs`-scoped closed-primitive axis —
    // one cell wider than the crate-side quaternary landing (the
    // CLI-only `Self::Env` arm).

    #[test]
    fn tier_arg_identity_slices_agree_with_identity_predicates() {
        // Five-way agreement pin across the (bare × discovered ×
        // default × custom × env) identity meta-partition. Every
        // ONLY_BARE entry satisfies is_bare and none of is_discovered
        // / is_default / is_custom / is_env; every ONLY_DISCOVERED
        // entry satisfies is_discovered alone; every ONLY_DEFAULT
        // entry satisfies is_default alone; every ONLY_CUSTOM entry
        // satisfies is_custom alone; every ONLY_ENV entry satisfies
        // is_env alone. Every TierArg::ALL cell agrees on membership
        // under each of the five boolean predicates. The two
        // independent declaration surfaces (slice literals + boolean
        // predicates) diverge at THIS pin on the first shape where
        // they disagree, before a consumer that reads one altitude
        // but not the other can observe the drift. Quinary peer of
        // the quaternary
        // `config_tier_kind_identity_slices_agree_with_identity_predicates`
        // (`ff6492b`) on the crate-side sibling tier-kind axis.
        for a in TierArg::ONLY_BARE.iter().copied() {
            assert!(
                a.is_bare(),
                "TierArg::ONLY_BARE entry {a:?} must satisfy is_bare()",
            );
            assert!(
                !a.is_discovered(),
                "TierArg::ONLY_BARE entry {a:?} must NOT satisfy is_discovered()",
            );
            assert!(
                !a.is_default(),
                "TierArg::ONLY_BARE entry {a:?} must NOT satisfy is_default()",
            );
            assert!(
                !a.is_custom(),
                "TierArg::ONLY_BARE entry {a:?} must NOT satisfy is_custom()",
            );
            assert!(
                !a.is_env(),
                "TierArg::ONLY_BARE entry {a:?} must NOT satisfy is_env()",
            );
        }
        for a in TierArg::ONLY_DISCOVERED.iter().copied() {
            assert!(
                a.is_discovered(),
                "TierArg::ONLY_DISCOVERED entry {a:?} must satisfy is_discovered()",
            );
            assert!(
                !a.is_bare(),
                "TierArg::ONLY_DISCOVERED entry {a:?} must NOT satisfy is_bare()",
            );
            assert!(
                !a.is_default(),
                "TierArg::ONLY_DISCOVERED entry {a:?} must NOT satisfy is_default()",
            );
            assert!(
                !a.is_custom(),
                "TierArg::ONLY_DISCOVERED entry {a:?} must NOT satisfy is_custom()",
            );
            assert!(
                !a.is_env(),
                "TierArg::ONLY_DISCOVERED entry {a:?} must NOT satisfy is_env()",
            );
        }
        for a in TierArg::ONLY_DEFAULT.iter().copied() {
            assert!(
                a.is_default(),
                "TierArg::ONLY_DEFAULT entry {a:?} must satisfy is_default()",
            );
            assert!(
                !a.is_bare(),
                "TierArg::ONLY_DEFAULT entry {a:?} must NOT satisfy is_bare()",
            );
            assert!(
                !a.is_discovered(),
                "TierArg::ONLY_DEFAULT entry {a:?} must NOT satisfy is_discovered()",
            );
            assert!(
                !a.is_custom(),
                "TierArg::ONLY_DEFAULT entry {a:?} must NOT satisfy is_custom()",
            );
            assert!(
                !a.is_env(),
                "TierArg::ONLY_DEFAULT entry {a:?} must NOT satisfy is_env()",
            );
        }
        for a in TierArg::ONLY_CUSTOM.iter().copied() {
            assert!(
                a.is_custom(),
                "TierArg::ONLY_CUSTOM entry {a:?} must satisfy is_custom()",
            );
            assert!(
                !a.is_bare(),
                "TierArg::ONLY_CUSTOM entry {a:?} must NOT satisfy is_bare()",
            );
            assert!(
                !a.is_discovered(),
                "TierArg::ONLY_CUSTOM entry {a:?} must NOT satisfy is_discovered()",
            );
            assert!(
                !a.is_default(),
                "TierArg::ONLY_CUSTOM entry {a:?} must NOT satisfy is_default()",
            );
            assert!(
                !a.is_env(),
                "TierArg::ONLY_CUSTOM entry {a:?} must NOT satisfy is_env()",
            );
        }
        for a in TierArg::ONLY_ENV.iter().copied() {
            assert!(
                a.is_env(),
                "TierArg::ONLY_ENV entry {a:?} must satisfy is_env()",
            );
            assert!(
                !a.is_bare(),
                "TierArg::ONLY_ENV entry {a:?} must NOT satisfy is_bare()",
            );
            assert!(
                !a.is_discovered(),
                "TierArg::ONLY_ENV entry {a:?} must NOT satisfy is_discovered()",
            );
            assert!(
                !a.is_default(),
                "TierArg::ONLY_ENV entry {a:?} must NOT satisfy is_default()",
            );
            assert!(
                !a.is_custom(),
                "TierArg::ONLY_ENV entry {a:?} must NOT satisfy is_custom()",
            );
        }
        for a in TierArg::ALL.iter().copied() {
            assert_eq!(
                TierArg::ONLY_BARE.contains(&a),
                a.is_bare(),
                "ONLY_BARE membership must agree with is_bare() on TierArg::{a:?}",
            );
            assert_eq!(
                TierArg::ONLY_DISCOVERED.contains(&a),
                a.is_discovered(),
                "ONLY_DISCOVERED membership must agree with is_discovered() on \
                 TierArg::{a:?}",
            );
            assert_eq!(
                TierArg::ONLY_DEFAULT.contains(&a),
                a.is_default(),
                "ONLY_DEFAULT membership must agree with is_default() on \
                 TierArg::{a:?}",
            );
            assert_eq!(
                TierArg::ONLY_CUSTOM.contains(&a),
                a.is_custom(),
                "ONLY_CUSTOM membership must agree with is_custom() on TierArg::{a:?}",
            );
            assert_eq!(
                TierArg::ONLY_ENV.contains(&a),
                a.is_env(),
                "ONLY_ENV membership must agree with is_env() on TierArg::{a:?}",
            );
        }
    }

    #[test]
    fn tier_arg_identity_slices_partition_all() {
        // Quinary partition invariant: the five per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_BARE.len() + ONLY_DISCOVERED.len() + ONLY_DEFAULT.len()
        // + ONLY_CUSTOM.len() + ONLY_ENV.len() == ALL.len()` at the
        // slice altitude on the CLI tier tag's identity projection.
        // Quinary peer of `config_tier_kind_identity_slices_partition_all`
        // (`ff6492b`) on the crate-side sibling tier-kind axis, one
        // cell wider. A variant landing on two slices or on none
        // breaks the partition here before any consumer that reasons
        // about the polarity as a covering meta-partition observes
        // the drift.
        for a in TierArg::ONLY_BARE {
            assert!(
                !TierArg::ONLY_DISCOVERED.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_BARE and ONLY_DISCOVERED",
            );
            assert!(
                !TierArg::ONLY_DEFAULT.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_BARE and ONLY_DEFAULT",
            );
            assert!(
                !TierArg::ONLY_CUSTOM.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_BARE and ONLY_CUSTOM",
            );
            assert!(
                !TierArg::ONLY_ENV.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_BARE and ONLY_ENV",
            );
        }
        for a in TierArg::ONLY_DISCOVERED {
            assert!(
                !TierArg::ONLY_DEFAULT.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_DISCOVERED and ONLY_DEFAULT",
            );
            assert!(
                !TierArg::ONLY_CUSTOM.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_DISCOVERED and ONLY_CUSTOM",
            );
            assert!(
                !TierArg::ONLY_ENV.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_DISCOVERED and ONLY_ENV",
            );
        }
        for a in TierArg::ONLY_DEFAULT {
            assert!(
                !TierArg::ONLY_CUSTOM.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_DEFAULT and ONLY_CUSTOM",
            );
            assert!(
                !TierArg::ONLY_ENV.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_DEFAULT and ONLY_ENV",
            );
        }
        for a in TierArg::ONLY_CUSTOM {
            assert!(
                !TierArg::ONLY_ENV.contains(a),
                "TierArg::{a:?} appears in BOTH ONLY_CUSTOM and ONLY_ENV",
            );
        }
        for a in TierArg::ALL {
            let in_bare = TierArg::ONLY_BARE.contains(a);
            let in_discovered = TierArg::ONLY_DISCOVERED.contains(a);
            let in_default = TierArg::ONLY_DEFAULT.contains(a);
            let in_custom = TierArg::ONLY_CUSTOM.contains(a);
            let in_env = TierArg::ONLY_ENV.contains(a);
            let held = usize::from(in_bare)
                + usize::from(in_discovered)
                + usize::from(in_default)
                + usize::from(in_custom)
                + usize::from(in_env);
            assert_eq!(
                held, 1,
                "TierArg::{a:?} must appear in exactly one of ONLY_BARE / \
                 ONLY_DISCOVERED / ONLY_DEFAULT / ONLY_CUSTOM / ONLY_ENV \
                 (found in {held})",
            );
        }
        assert_eq!(
            TierArg::ONLY_BARE.len()
                + TierArg::ONLY_DISCOVERED.len()
                + TierArg::ONLY_DEFAULT.len()
                + TierArg::ONLY_CUSTOM.len()
                + TierArg::ONLY_ENV.len(),
            TierArg::ALL.len(),
            "ONLY_BARE + ONLY_DISCOVERED + ONLY_DEFAULT + ONLY_CUSTOM + ONLY_ENV \
             slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn tier_arg_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in TierArg::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at THIS
        // pin. Quinary peer of
        // `config_tier_kind_identity_slices_preserve_all_order`
        // (`ff6492b`) on the crate-side sibling tier-kind axis.
        let bare_from_all: Vec<TierArg> = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_bare())
            .collect();
        assert_eq!(
            bare_from_all,
            TierArg::ONLY_BARE.to_vec(),
            "ONLY_BARE must be ALL-filtered by is_bare in declaration order",
        );
        let discovered_from_all: Vec<TierArg> = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_discovered())
            .collect();
        assert_eq!(
            discovered_from_all,
            TierArg::ONLY_DISCOVERED.to_vec(),
            "ONLY_DISCOVERED must be ALL-filtered by is_discovered in declaration order",
        );
        let default_from_all: Vec<TierArg> = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_default())
            .collect();
        assert_eq!(
            default_from_all,
            TierArg::ONLY_DEFAULT.to_vec(),
            "ONLY_DEFAULT must be ALL-filtered by is_default in declaration order",
        );
        let custom_from_all: Vec<TierArg> = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_custom())
            .collect();
        assert_eq!(
            custom_from_all,
            TierArg::ONLY_CUSTOM.to_vec(),
            "ONLY_CUSTOM must be ALL-filtered by is_custom in declaration order",
        );
        let env_from_all: Vec<TierArg> = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_env())
            .collect();
        assert_eq!(
            env_from_all,
            TierArg::ONLY_ENV.to_vec(),
            "ONLY_ENV must be ALL-filtered by is_env in declaration order",
        );
    }

    #[test]
    fn tier_arg_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all five per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set. Quinary peer of
        // `config_tier_kind_identity_slices_have_no_duplicates`
        // (`ff6492b`) on the crate-side sibling tier-kind axis.
        for slice in [
            TierArg::ONLY_BARE,
            TierArg::ONLY_DISCOVERED,
            TierArg::ONLY_DEFAULT,
            TierArg::ONLY_CUSTOM,
            TierArg::ONLY_ENV,
        ] {
            let mut seen: Vec<TierArg> = Vec::with_capacity(slice.len());
            for a in slice {
                assert!(
                    !seen.contains(a),
                    "TierArg identity slice {slice:?} contains duplicate entry {a:?}",
                );
                seen.push(*a);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn tier_arg_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on TierArg::ALL — i.e.,
        // `ONLY_BARE.len() == ALL.iter().filter(is_bare).count()` (and
        // symmetric for the four siblings) — the cardinality
        // projection at the slice altitude agrees with the boolean-
        // altitude projection on all five halves. Concrete positions
        // today: 1 bare + 1 discovered + 1 default + 1 custom + 1 env
        // = 5 = ALL. Quinary peer of
        // `config_tier_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`ff6492b`) on the crate-side sibling tier-kind axis.
        let bare_count = TierArg::ALL.iter().copied().filter(|a| a.is_bare()).count();
        let discovered_count = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_discovered())
            .count();
        let default_count = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_default())
            .count();
        let custom_count = TierArg::ALL
            .iter()
            .copied()
            .filter(|a| a.is_custom())
            .count();
        let env_count = TierArg::ALL.iter().copied().filter(|a| a.is_env()).count();
        assert_eq!(
            TierArg::ONLY_BARE.len(),
            bare_count,
            "ONLY_BARE.len() must match the is_bare count on ALL",
        );
        assert_eq!(
            TierArg::ONLY_DISCOVERED.len(),
            discovered_count,
            "ONLY_DISCOVERED.len() must match the is_discovered count on ALL",
        );
        assert_eq!(
            TierArg::ONLY_DEFAULT.len(),
            default_count,
            "ONLY_DEFAULT.len() must match the is_default count on ALL",
        );
        assert_eq!(
            TierArg::ONLY_CUSTOM.len(),
            custom_count,
            "ONLY_CUSTOM.len() must match the is_custom count on ALL",
        );
        assert_eq!(
            TierArg::ONLY_ENV.len(),
            env_count,
            "ONLY_ENV.len() must match the is_env count on ALL",
        );
        assert_eq!(TierArg::ONLY_BARE.len(), 1);
        assert_eq!(TierArg::ONLY_DISCOVERED.len(), 1);
        assert_eq!(TierArg::ONLY_DEFAULT.len(), 1);
        assert_eq!(TierArg::ONLY_CUSTOM.len(), 1);
        assert_eq!(TierArg::ONLY_ENV.len(), 1);
        assert_eq!(TierArg::ALL.len(), 5);
    }

    #[test]
    fn tier_arg_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the five per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub
        // fn` (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        // Quinary peer of
        // `config_tier_kind_identity_slices_are_const_addressable`
        // (`ff6492b`) on the crate-side sibling tier-kind axis.
        const ONLY_BARE_LEN: usize = TierArg::ONLY_BARE.len();
        const ONLY_DISCOVERED_LEN: usize = TierArg::ONLY_DISCOVERED.len();
        const ONLY_DEFAULT_LEN: usize = TierArg::ONLY_DEFAULT.len();
        const ONLY_CUSTOM_LEN: usize = TierArg::ONLY_CUSTOM.len();
        const ONLY_ENV_LEN: usize = TierArg::ONLY_ENV.len();
        const ALL_LEN: usize = TierArg::ALL.len();
        assert_eq!(ONLY_BARE_LEN, 1);
        assert_eq!(ONLY_DISCOVERED_LEN, 1);
        assert_eq!(ONLY_DEFAULT_LEN, 1);
        assert_eq!(ONLY_CUSTOM_LEN, 1);
        assert_eq!(ONLY_ENV_LEN, 1);
        assert_eq!(
            ONLY_BARE_LEN + ONLY_DISCOVERED_LEN + ONLY_DEFAULT_LEN + ONLY_CUSTOM_LEN + ONLY_ENV_LEN,
            ALL_LEN,
        );
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

    // ─── OutputFormat per-half meta-partition slice constants ──────
    // ─── (YAML / JSON) — the slice-constant altitude peer of the ──
    // ─── boolean-predicate binary partition above ──────────────────

    #[test]
    fn output_format_yaml_slice_agrees_with_is_yaml_predicate() {
        // Bidirectional weld between the slice literal
        // `OutputFormat::YAML` and the boolean predicate
        // `OutputFormat::is_yaml` on the (yaml × json) polarity axis.
        // Every slice entry satisfies the yaml pole (and its
        // complement `!is_json`), and every ALL cell agrees on
        // membership under the boolean predicate. Idiom-peer of
        // `format_provenance_figment_builtin_slice_agrees_with_is_figment_builtin_predicate`
        // (commit `7ef79e4`) and
        // `attribution_confidence_exact_slice_agrees_with_is_exact_predicate`
        // (commit `13c1003`) — the two independent declaration
        // surfaces (slice literal + boolean predicate) diverge at THIS
        // pin on the first format where they disagree, before a
        // consumer that reads one altitude but not the other can
        // observe the drift.
        for fmt in OutputFormat::YAML.iter().copied() {
            assert!(
                fmt.is_yaml(),
                "OutputFormat::YAML entry {fmt:?} must satisfy is_yaml()",
            );
            assert!(
                !fmt.is_json(),
                "OutputFormat::YAML entry {fmt:?} must NOT satisfy is_json()",
            );
        }
        for fmt in OutputFormat::ALL.iter().copied() {
            assert_eq!(
                OutputFormat::YAML.contains(&fmt),
                fmt.is_yaml(),
                "YAML membership must agree with is_yaml() on OutputFormat::{fmt:?}",
            );
            assert_eq!(
                OutputFormat::JSON.contains(&fmt),
                fmt.is_json(),
                "JSON membership must agree with is_json() on OutputFormat::{fmt:?}",
            );
        }
    }

    #[test]
    fn output_format_yaml_and_json_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `YAML.len() + JSON.len() == ALL.len()` at the slice altitude
        // on the CLI emission-format axis. Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_partition_all`
        // (commit `7ef79e4`) — a variant landing on one slice AND the
        // other, or on neither, breaks the partition here before any
        // consumer that reasons about the polarity as a covering meta-
        // partition observes the drift.
        for fmt in OutputFormat::YAML.iter().copied() {
            assert!(
                !OutputFormat::JSON.contains(&fmt),
                "OutputFormat::{fmt:?} appears in BOTH YAML and JSON",
            );
        }
        for fmt in OutputFormat::ALL.iter().copied() {
            let in_yaml = OutputFormat::YAML.contains(&fmt);
            let in_json = OutputFormat::JSON.contains(&fmt);
            assert!(
                in_yaml || in_json,
                "OutputFormat::{fmt:?} is in NEITHER YAML nor JSON",
            );
            assert!(
                !(in_yaml && in_json),
                "OutputFormat::{fmt:?} is in BOTH YAML and JSON",
            );
        }
        assert_eq!(
            OutputFormat::YAML.len() + OutputFormat::JSON.len(),
            OutputFormat::ALL.len(),
            "YAML and JSON slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn output_format_yaml_and_json_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in OutputFormat::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise, so a
        // renderer walking the two half-slices concatenated reproduces
        // the ALL order (`Yaml` first, then `Json`). Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_preserve_all_order`
        // (commit `7ef79e4`) — a reordering of one slice without the
        // other, or a reordering of ALL that shuffles the two poles'
        // variant order without updating the slices, diverges at THIS
        // pin.
        let yaml_from_all: Vec<OutputFormat> = OutputFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.is_yaml())
            .collect();
        assert_eq!(
            yaml_from_all,
            OutputFormat::YAML.to_vec(),
            "YAML must be ALL-filtered by is_yaml in declaration order",
        );
        let json_from_all: Vec<OutputFormat> = OutputFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.is_json())
            .collect();
        assert_eq!(
            json_from_all,
            OutputFormat::JSON.to_vec(),
            "JSON must be ALL-filtered by is_json in declaration order",
        );
    }

    #[test]
    fn output_format_yaml_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into JSON, an accidental re-add of an already-present Yaml
        // cell into YAML) fails at THIS pin before drifting through
        // any consumer that iterates the slice expecting a set. Idiom-
        // peer of
        // `format_provenance_figment_builtin_slice_has_no_duplicates`
        // (commit `7ef79e4`).
        for slice in [OutputFormat::YAML, OutputFormat::JSON] {
            let deduped_len = {
                let mut seen: Vec<OutputFormat> = Vec::with_capacity(slice.len());
                for fmt in slice {
                    if !seen.contains(fmt) {
                        seen.push(*fmt);
                    }
                }
                seen.len()
            };
            assert_eq!(
                deduped_len,
                slice.len(),
                "OutputFormat slice {slice:?} contains duplicate entries",
            );
        }
    }

    #[test]
    fn output_format_yaml_and_json_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on OutputFormat::ALL — i.e.,
        // `YAML.len() == ALL.iter().filter(is_yaml).count()` and
        // `JSON.len() == ALL.iter().filter(is_json).count()` — the
        // cardinality projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete
        // positions today: 1 yaml + 1 json = 2 = ALL. Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (commit `7ef79e4`).
        let yaml_count = OutputFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.is_yaml())
            .count();
        let json_count = OutputFormat::ALL
            .iter()
            .copied()
            .filter(|f| f.is_json())
            .count();
        assert_eq!(
            OutputFormat::YAML.len(),
            yaml_count,
            "YAML.len() must match the is_yaml count on ALL",
        );
        assert_eq!(
            OutputFormat::JSON.len(),
            json_count,
            "JSON.len() must match the is_json count on ALL",
        );
        assert_eq!(OutputFormat::YAML.len(), 1);
        assert_eq!(OutputFormat::JSON.len(), 1);
        assert_eq!(OutputFormat::ALL.len(), 2);
    }

    #[test]
    fn output_format_yaml_and_json_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `format_provenance_figment_builtin_and_shikumi_built_slices_are_const_addressable`
        // (commit `7ef79e4`).
        const YAML_LEN: usize = OutputFormat::YAML.len();
        const JSON_LEN: usize = OutputFormat::JSON.len();
        const ALL_LEN: usize = OutputFormat::ALL.len();
        assert_eq!(YAML_LEN, 1);
        assert_eq!(JSON_LEN, 1);
        assert_eq!(YAML_LEN + JSON_LEN, ALL_LEN);
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

//! Tiered configuration — **the shikumi configuration prime directive**.
//!
//! Every typed configuration shikumi loads MUST implement
//! [`TieredConfig`]. The bare/discovered/prescribed-default tier
//! model is as load-bearing as shikumi's existing YAML+env+nix
//! discovery — the two compose, they don't replace each other.
//!
//! # Operator workflow (the contract every app exposes)
//!
//! ```text
//! <app> config-show bare          # zero-opinion floor
//! <app> config-show discovered    # bare + runtime auto-detect
//! <app> config-show default       # bare + prescribed defaults + discovered
//! diff <(<app> config-show bare) <(<app> config-show default)
//! ```
//!
//! The same env-var convention applies fleet-wide:
//!
//! ```text
//! MADO_TIER=bare mado             # explicit tier override at launch
//! FROST_TIER=discovered frost     # autodetect-only, no prescribed opinions
//! ```
//!
//! # The runtime path
//!
//! ```rust,ignore
//! use shikumi::{ConfigStore, ConfigTier, TieredConfig};
//!
//! // Resolve the tier from env (defaults to Default if unset/invalid).
//! let tier = ConfigTier::from_env("MADO_TIER");
//! let store = ConfigStore::for_app("mado");
//! let cfg: MadoConfig = store.load_tier(tier)?;
//! ```
//!
//! `load_tier` composes the right tier:
//! * `Bare`       → `T::bare()`
//! * `Discovered` → `T::discovered()`
//! * `Default`    → `T::prescribed_default()` (then overlay the
//!                   operator's YAML if present — the standard
//!                   shikumi YAML+env+nix path layers on top)
//! * `Custom`     → load explicit path, layered on `prescribed_default()`
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

use serde::{Serialize, de::DeserializeOwned};
use std::env;

// ── ConfigTierKind — variant-tag projection of ConfigTier

/// Typed variant tag of [`ConfigTier`] — `Bare | Discovered | Default
/// | Custom` lifted into a [`crate::ClosedAxis`] primitive without
/// the `Custom` variant's [`std::path::PathBuf`] payload.
///
/// Stands in the same relation to [`ConfigTier`] as
/// [`crate::PartitionFace`] does to [`crate::PartitionOrdinal`]: the
/// variant tag carried as its own [`Copy`] + [`Hash`] typescape
/// primitive, projectable from the full enum through one named
/// accessor ([`ConfigTier::kind`]).
///
/// **Single source of truth for the four operator-facing tier
/// names.** Both [`as_str`][Self::as_str] (rendering) and
/// [`from_str`][Self::from_str] (parsing) route through this enum,
/// so the strings `"bare"`, `"discovered"`, `"default"`, `"custom"`
/// appear at exactly one site — adding a fifth tier (if the model
/// grows) extends the strings in lockstep with the variants instead
/// of touching three duplicated `match` blocks.
///
/// Consumers that only need "which tier did the operator ask for?"
/// without the `Custom` path (telemetry counters, dashboards keyed by
/// tier, structured-log fields) carry a [`ConfigTierKind`] (one byte,
/// [`Copy`]) rather than the full [`ConfigTier`] (variant tag plus a
/// heap-allocated [`std::path::PathBuf`]). Reaches every closed-axis
/// discipline the typescape closes uniformly — [`crate::axis_iter`],
/// [`crate::axis_cardinality`], [`crate::axis_ordinal`],
/// [`crate::axis_at`] — at the trait impl declaration.
#[non_exhaustive]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    gen_platform::TypedDispatcher,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
    gen_platform::FromStrKind,
)]
#[discriminant(also_display)]
pub enum ConfigTierKind {
    /// Zero-opinion floor.
    Bare,
    /// `bare()` + runtime auto-detect outputs.
    Discovered,
    /// `bare()` + discovered + `prescribed_default()` — the ~90%
    /// case.
    #[allow(clippy::module_name_repetitions)]
    Default,
    /// YAML overlay at a caller-supplied path on top of
    /// `prescribed_default()`.
    Custom,
}

// Fleet-wide dispatcher-catalog registration. TWELFTH consumer
// class adopting gen-platform's typed-dispatcher catamorphism
// (after gen / caixa / wasm-platform / cofre / shigoto / engenho /
// magma / kura / pangea / tatara / hanshi). See
// theory/UNIFIED-COMPUTING-MODEL.md §VI.
gen_platform::register_dispatcher!("shikumi.config-tier-kind", ConfigTierKind);

impl ConfigTierKind {
    /// Every [`ConfigTierKind`] value, in declaration order — the
    /// inherent mirror of [`crate::ClosedAxis::ALL`].
    pub const ALL: &'static [Self] = &[Self::Bare, Self::Discovered, Self::Default, Self::Custom];

    /// Canonical operator-facing lowercase name of the tier kind.
    ///
    /// The single source of truth for the four tier names; both
    /// [`ConfigTier::name`] (rendering) and
    /// [`ConfigTier::from_str_or_default`] / [`ConfigTier::from_env`]
    /// (parsing) route through this method via [`Self::from_str`].
    /// `as_str` round-trips with [`from_str`][Self::from_str] on
    /// every variant — pinned by
    /// [`tests::config_tier_kind_from_str_round_trips_with_as_str`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bare => "bare",
            Self::Discovered => "discovered",
            Self::Default => "default",
            Self::Custom => "custom",
        }
    }

    /// Case-insensitive parse of the four canonical tier-kind
    /// strings. Returns [`None`] for any other input — the caller
    /// decides what to do with unrecognized strings (e.g.
    /// [`ConfigTier::from_str_or_default`] treats them as
    /// path-shaped `Custom(PathBuf)` payloads).
    ///
    /// The trim discipline is the caller's responsibility; this
    /// method matches on the input verbatim after ASCII-lowercasing
    /// so `"Bare"`, `"BARE"`, `"bare"` all parse to [`Self::Bare`].
    /// Empty string returns [`None`] (it's neither a canonical tag
    /// nor a valid path).
    ///
    /// `from_str` returns [`Option`] rather than implementing
    /// [`std::str::FromStr`] (which would force a `Result<_, Err>`
    /// shape and an error-type ceremony for the no-error case where
    /// "not a canonical name" is the only failure mode the caller
    /// cares about).
    ///
    /// Inherent mirror of [`crate::ClosedAxisLabel::from_canonical_str`];
    /// delegates to the trait default so the parse body lives at one
    /// site (the trait default impl in [`crate::cube`]) and the
    /// trait-uniform round-trip law reaches `ConfigTierKind` through
    /// the [`crate::ClosedAxisLabel`] discipline.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s)
    }
}

impl crate::ClosedAxis for ConfigTierKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for ConfigTierKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

// ── ConfigTier — operator-facing enum picking which baseline to load

/// Which tier of a `TieredConfig` to materialize at app startup.
///
/// Apps resolve via [`ConfigTier::from_env`] (default convention:
/// `<APP>_TIER` env var) or via an explicit CLI flag. The four
/// variants mirror the `TieredConfig` trait methods:
///
/// * `Bare`       — zero-opinion floor (every field at empty/zero).
/// * `Discovered` — bare + runtime auto-detect outputs.
/// * `Default`    — bare + discovered + prescribed_default (the
///                  ~90% case; what `Default::default()` returns).
/// * `Custom(path)` — load YAML from `path` overlaid on
///                  `prescribed_default()`. Equivalent to the
///                  standard shikumi YAML discovery path.
///
/// The variant-tag projection — "which tier kind did the operator
/// ask for, ignoring any `Custom` path payload?" — is exposed as the
/// typed [`ConfigTierKind`] primitive through [`Self::kind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigTier {
    Bare,
    Discovered,
    #[allow(clippy::module_name_repetitions)]
    Default,
    Custom(std::path::PathBuf),
}

impl Default for ConfigTier {
    fn default() -> Self {
        Self::Default
    }
}

impl ConfigTier {
    /// Resolve the tier from an env var, falling back to
    /// `ConfigTier::Default` when unset / unparseable.
    ///
    /// Recognized values (case-insensitive):
    ///   * `"bare"` → Bare
    ///   * `"discovered"` → Discovered
    ///   * `"default"` → Default
    ///   * any other non-empty string → Custom(value as path)
    #[must_use]
    pub fn from_env(env_var: &str) -> Self {
        // Missing var → default. Present var goes through the same
        // parse path as the explicit-string entry point, so the two
        // helpers stay in lockstep at one site.
        env::var(env_var)
            .map(|raw| Self::from_str_or_default(&raw))
            .unwrap_or_default()
    }

    /// Resolve from an explicit string (e.g. a CLI flag value).
    /// Same matching rules as [`ConfigTier::from_env`].
    #[must_use]
    pub fn from_str_or_default(s: &str) -> Self {
        // Trim + lowercase once; dispatch through ConfigTierKind so
        // the four canonical tier-name strings live at one site
        // (ConfigTierKind::as_str). The `Custom` kind is encoded
        // here with a string payload — when the operator types the
        // literal word "custom" with no path, it still falls into
        // the path-shaped Custom arm to match prior behavior.
        let normalized = s.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Self::default();
        }
        match ConfigTierKind::from_str(&normalized) {
            Some(ConfigTierKind::Bare) => Self::Bare,
            Some(ConfigTierKind::Discovered) => Self::Discovered,
            Some(ConfigTierKind::Default) => Self::Default,
            Some(ConfigTierKind::Custom) | None => {
                Self::Custom(std::path::PathBuf::from(normalized))
            }
        }
    }

    /// Operator-facing tier name (`"bare"` / `"discovered"` /
    /// `"default"` / `"custom"`) — used in logs + telemetry.
    ///
    /// Delegates to [`ConfigTierKind::as_str`] via [`Self::kind`],
    /// keeping the four tier names at one source of truth.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.kind().as_str()
    }

    /// Typed variant-tag projection — every [`ConfigTier`] value
    /// lands on exactly one [`ConfigTierKind`], with the `Custom`
    /// path payload forgotten.
    ///
    /// The cube-axis analog of [`crate::PartitionOrdinal::face`] for
    /// [`crate::PartitionFace`]: a consumer that only needs "which
    /// tier kind did the operator ask for?" — without the
    /// `Custom(PathBuf)` payload — carries one byte via this
    /// projection rather than re-pattern-matching the enum at every
    /// site. Pinned in lockstep with [`Self::name`] by
    /// [`tests::config_tier_kind_matches_config_tier_name`].
    #[must_use]
    pub const fn kind(&self) -> ConfigTierKind {
        match self {
            Self::Bare => ConfigTierKind::Bare,
            Self::Discovered => ConfigTierKind::Discovered,
            Self::Default => ConfigTierKind::Default,
            Self::Custom(_) => ConfigTierKind::Custom,
        }
    }
}

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

    /// Materialize `self` from a tier selector — the operator-facing
    /// entry point. Wraps the tier methods + env-var resolution +
    /// optional YAML overlay into one call site every fleet app
    /// uses identically.
    ///
    /// `Bare`/`Discovered`/`Default` resolve to the corresponding
    /// trait method. `Custom(path)` attempts to deserialize YAML
    /// at `path` and overlay it on `prescribed_default()`; falls
    /// back to `prescribed_default()` if the file is missing or
    /// malformed (warns via tracing).
    fn resolve_tier(tier: ConfigTier) -> Self {
        match tier {
            ConfigTier::Bare => Self::bare(),
            ConfigTier::Discovered => Self::discovered(),
            ConfigTier::Default => Self::prescribed_default(),
            ConfigTier::Custom(path) => {
                let base = Self::prescribed_default();
                match std::fs::read_to_string(&path) {
                    Ok(s) => match serde_yaml::from_str::<Self>(&s) {
                        Ok(overlay) => overlay.extend(&base),
                        Err(e) => {
                            tracing::warn!(
                                target: "shikumi::tiered",
                                error = %e,
                                path = %path.display(),
                                "custom tier YAML failed to deserialize — falling back to prescribed_default"
                            );
                            base
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            target: "shikumi::tiered",
                            error = %e,
                            path = %path.display(),
                            "custom tier YAML not readable — falling back to prescribed_default"
                        );
                        base
                    }
                }
            }
        }
    }

    /// Convenience: resolve the tier from an env var (default
    /// `<APP>_TIER`) AND materialize the config in one call.
    /// The fleet-wide canonical entry point at app startup.
    fn resolve_from_env(env_var: &str) -> Self {
        Self::resolve_tier(ConfigTier::from_env(env_var))
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

impl DiffLine {
    /// Data-free, `'static` discriminant of this [`DiffLine`]: the kind
    /// of diff cell ([`DiffLineKind::Removed`] / [`DiffLineKind::Added`]
    /// / [`DiffLineKind::Context`]) independent of the inner payload
    /// [`String`].
    ///
    /// One source of truth for the diff-line kind partition over
    /// [`DiffLine`]. Observers that need only the cell-kind axis
    /// (counting added/removed/context lines for stats, filtering for
    /// "show only changes", dispatching per-kind glyph or color at
    /// render time, comparing across thread boundaries without cloning
    /// the borrowed line text) match on this closed enum instead of
    /// pattern-matching against the three payload-carrying variants of
    /// [`DiffLine`].
    ///
    /// Peer of [`ConfigTier::kind`] on the [`ConfigTier`] axis — same
    /// typescape closed-axis discipline (allocation-free,
    /// `Copy + Eq + Hash + #[non_exhaustive]`, exhaustive forward map),
    /// lifted to the diff-line surface so the
    /// `ConfigDiff`-internal partition is named at the type level
    /// rather than lying open-coded in [`ConfigDiff::is_empty_diff`]
    /// and [`ConfigDiff::render_unified`].
    ///
    /// A future [`DiffLine`] variant landing (e.g. a hypothetical
    /// `Header(String)` shape for hunk headers, a `Sep` shape for
    /// inter-hunk separators) forces a corresponding
    /// [`DiffLineKind`] arm through the exhaustive match below.
    #[must_use]
    pub const fn kind(&self) -> DiffLineKind {
        match self {
            Self::Removed(_) => DiffLineKind::Removed,
            Self::Added(_) => DiffLineKind::Added,
            Self::Context(_) => DiffLineKind::Context,
        }
    }

    /// Borrow the inner line text regardless of kind. Companion of
    /// [`Self::kind`]: the (kind, text) pair losslessly reconstructs
    /// the original [`DiffLine`] value, and the two accessors together
    /// replace the three-arm `match` blocks at every renderer site.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Removed(s) | Self::Added(s) | Self::Context(s) => s.as_str(),
        }
    }
}

/// Data-free, `'static` discriminant of [`DiffLine`]: the closed
/// three-way partition over the diff-cell variant space, independent
/// of the inner payload [`String`].
///
/// Returned by [`DiffLine::kind`]. The enum exists so consumers that
/// need only the cell-kind axis (per-kind counters, "only changed
/// lines" filters, per-kind glyph or color rendering at the
/// `ConfigDiff::render_unified` surface, structured-diagnostic
/// legends naming the diff-cell class, comparing across thread
/// boundaries) match on one closed enum instead of pattern-matching
/// against three payload-carrying variants.
///
/// Peer of [`crate::ConfigTierKind`] (variant-tag projection of
/// [`ConfigTier`]), [`crate::WatchEventClass`] (reload-relevance
/// classification of [`notify::EventKind`]), and the other closed-
/// enum kind primitives on the typescape — same discipline (closed,
/// allocation-free, `Copy + Eq + Hash + #[non_exhaustive]`,
/// exhaustive forward map), applied to the diff-cell axis. Before
/// this lift, the three-way kind universe lived only inside
/// [`DiffLine`]'s variant set: every observer wanting the data-free
/// kind class re-pattern-matched against the payload-carrying enum,
/// and the unified-diff glyph (`-`, `+`, ` `) appeared inline at
/// every renderer site rather than at one canonical accessor.
///
/// Adding a future [`DiffLine`] variant (a hypothetical `Header`
/// shape for hunk headers, a `Sep` shape for inter-hunk separators)
/// means adding one [`DiffLineKind`] variant in lockstep — the
/// exhaustive [`DiffLine::kind`] match forces the assignment at
/// compile time.
///
/// `Ord` / `PartialOrd` are declaration-order lex over [`Self::ALL`]
/// (`Removed < Added < Context`): a `BTreeMap<DiffLineKind, T>` keyed
/// on the diff-cell kind (per-cell rebuild-summary histograms keyed
/// over a stable axis, attestation manifests recording the diff-cell
/// cardinality mix of a `ConfigDiff` between two tiers, structured-
/// diagnostic legends bucketing per-cell counters in declaration
/// order) emits rows in that order deterministically without a hand-
/// rolled comparator at the renderer. Idiom-peer of the same derive
/// on [`crate::WatchEventClass`] (commit `94f8a8b`),
/// [`crate::EnvMetadataTagKind`] (commit `b556b75`),
/// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
/// [`crate::FigmentSourceKind`] (commit `5df265c`), and
/// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
/// diff-cell axis closed-enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DiffLineKind {
    /// Maps to [`DiffLine::Removed`] regardless of inner payload —
    /// a line present in the baseline and absent in the candidate.
    /// Rendered with the canonical unified-diff `-` prefix
    /// ([`Self::glyph`]).
    Removed,
    /// Maps to [`DiffLine::Added`] regardless of inner payload —
    /// a line absent in the baseline and present in the candidate.
    /// Rendered with the canonical unified-diff `+` prefix
    /// ([`Self::glyph`]).
    Added,
    /// Maps to [`DiffLine::Context`] regardless of inner payload —
    /// a line identical in both sides. Rendered with the canonical
    /// unified-diff ` ` (space) prefix ([`Self::glyph`]).
    Context,
}

impl DiffLineKind {
    /// Every [`DiffLineKind`] variant, in declaration order
    /// ([`Self::Removed`], [`Self::Added`], [`Self::Context`]).
    ///
    /// The closed list of diff-line kinds shikumi recognizes. Peer of
    /// [`crate::WatchEventClass::ALL`] (also three-cell) on the
    /// watcher axis and the other closed-axis primitives' `ALL`
    /// constants — same typescape discipline (closed `'static` slice,
    /// in declaration order). Adding a new variant to [`Self`] means
    /// extending this slice in lockstep; the cube-test cardinality
    /// pin (`for_each_closed_axis_primitive!` checksum in
    /// `cube::tests`) catches drift before silent dropouts.
    pub const ALL: &'static [Self] = &[Self::Removed, Self::Added, Self::Context];

    /// Canonical operator-facing lowercase name of the diff-line kind —
    /// `"removed"`, `"added"`, or `"context"`.
    ///
    /// The single source of truth for the diff-cell kind label strings
    /// on the [`DiffLineKind`] axis. Inherent mirror of the
    /// [`crate::ClosedAxisLabel`] trait method; the trait impl
    /// delegates here so the canonical names live at one site instead
    /// of being re-stated at every operator-facing surface (per-kind
    /// counters in a CLI `config-diff` summary, structured-log fields
    /// naming the diff-cell class, attestation manifests recording the
    /// diff-cell kind histogram between two config tiers). The
    /// strings match the variant identifiers in ASCII-lowercase form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Added => "added",
            Self::Context => "context",
        }
    }

    /// Canonical unified-diff prefix character — `'-'` for
    /// [`Self::Removed`], `'+'` for [`Self::Added`], `' '` for
    /// [`Self::Context`]. The single source of truth for the per-kind
    /// glyph used by [`ConfigDiff::render_unified`] and every future
    /// renderer that emits the unified-diff line shape.
    ///
    /// Before this lift the three glyph characters lived inline at the
    /// renderer's three-arm `match`; the kind axis names the
    /// (variant → glyph) projection as a typed accessor, so a future
    /// alternative renderer (a Markdown-fenced diff, a color-coded
    /// terminal renderer routing glyph through a palette) reads one
    /// accessor instead of re-stating the three-arm match.
    #[must_use]
    pub const fn glyph(self) -> char {
        match self {
            Self::Removed => '-',
            Self::Added => '+',
            Self::Context => ' ',
        }
    }

    /// Whether this kind represents a structural change between the
    /// two sides (`true` for [`Self::Added`] or [`Self::Removed`],
    /// `false` for [`Self::Context`]).
    ///
    /// Refines [`ConfigDiff::is_empty_diff`]: a diff is empty exactly
    /// when no [`DiffLine`] has a `is_changed` kind. The predicate
    /// previously lived as inline `matches!(l, DiffLine::Added(_) |
    /// DiffLine::Removed(_))` at the call site; the lift names the
    /// (kind → is-it-a-change?) projection at the type level.
    #[must_use]
    pub const fn is_changed(self) -> bool {
        matches!(self, Self::Added | Self::Removed)
    }

    /// Returns `true` for [`Self::Removed`]; equivalent to
    /// `self == DiffLineKind::Removed`.
    #[must_use]
    pub const fn is_removed(self) -> bool {
        matches!(self, Self::Removed)
    }

    /// Returns `true` for [`Self::Added`]; equivalent to
    /// `self == DiffLineKind::Added`.
    #[must_use]
    pub const fn is_added(self) -> bool {
        matches!(self, Self::Added)
    }

    /// Returns `true` for [`Self::Context`]; equivalent to
    /// `self == DiffLineKind::Context`.
    #[must_use]
    pub const fn is_context(self) -> bool {
        matches!(self, Self::Context)
    }
}

impl crate::ClosedAxis for DiffLineKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for DiffLineKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on a ClosedAxisLabel primitive — lifted to one macro after the
// 16+ hand-rolled idiom-peers preceding this commit (WatchEventClass at
// `94f8a8b`, ShikumiErrorKind at `4b53792`). See
// `closed_axis_label_string_surface!` in `crate::macros` for the contract;
// behavior is byte-identical to the hand-rolled impls the macro replaces.
closed_axis_label_string_surface! {
    type = DiffLineKind,
    parse_error = "unknown diff line kind",
    expecting = "a canonical DiffLineKind lowercase label \
                 (`removed`, `added`, `context`; case-insensitive)",
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
    ///
    /// Routes the per-kind glyph through [`DiffLineKind::glyph`] and
    /// the payload through [`DiffLine::text`], so the three magic
    /// `'-' / '+' / ' '` characters live at one site
    /// ([`DiffLineKind::glyph`]) instead of being re-stated at every
    /// renderer's three-arm match.
    #[must_use]
    pub fn render_unified(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push(line.kind().glyph());
            out.push_str(line.text());
            out.push('\n');
        }
        out
    }

    /// True when there are no Added or Removed lines (only Context).
    /// I.e. baseline == candidate.
    ///
    /// Routes through [`DiffLineKind::is_changed`] — the
    /// (variant → is-it-a-change?) projection lives at one site
    /// instead of inlined here.
    #[must_use]
    pub fn is_empty_diff(&self) -> bool {
        !self.lines.iter().any(|l| l.kind().is_changed())
    }

    /// Typed per-kind tally of [`Self::lines`] over the
    /// [`DiffLineKind`] axis — the dense histogram every CLI
    /// `config-diff` summary, dashboard, attestation manifest, and
    /// alerting policy bucketing the (added × removed × context) line
    /// counts has previously re-derived inline.
    ///
    /// Equivalent to
    /// `crate::axis_histogram(self.lines.iter().map(DiffLine::kind))`
    /// but named at the [`ConfigDiff`] surface so consumers reading a
    /// diff don't reach for the cube-level generic helper. The
    /// histogram's `total()` equals `self.lines.len()` pointwise (every
    /// line projects to exactly one kind); `is_empty()` iff
    /// `self.lines.is_empty()`; `count(DiffLineKind::Added) +
    /// count(DiffLineKind::Removed)` equals zero iff [`Self::is_empty_diff`]
    /// returns `true` — pinned by
    /// `kind_histogram_changed_cells_match_is_empty_diff`.
    #[must_use]
    pub fn kind_histogram(&self) -> crate::AxisHistogram<DiffLineKind> {
        crate::axis_histogram(self.lines.iter().map(DiffLine::kind))
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

    // ── ConfigTier + resolve_tier coverage ──────────────────────

    #[test]
    fn config_tier_default_is_default_variant() {
        assert_eq!(ConfigTier::default(), ConfigTier::Default);
    }

    #[test]
    fn config_tier_from_str_recognizes_named_tiers() {
        assert_eq!(ConfigTier::from_str_or_default("bare"), ConfigTier::Bare);
        assert_eq!(
            ConfigTier::from_str_or_default("DISCOVERED"),
            ConfigTier::Discovered
        );
        assert_eq!(
            ConfigTier::from_str_or_default("default"),
            ConfigTier::Default
        );
        assert_eq!(ConfigTier::from_str_or_default(""), ConfigTier::Default);
        match ConfigTier::from_str_or_default("/etc/foo.yaml") {
            ConfigTier::Custom(p) => {
                assert_eq!(p, std::path::PathBuf::from("/etc/foo.yaml"));
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn config_tier_names_are_stable() {
        assert_eq!(ConfigTier::Bare.name(), "bare");
        assert_eq!(ConfigTier::Discovered.name(), "discovered");
        assert_eq!(ConfigTier::Default.name(), "default");
        assert_eq!(
            ConfigTier::Custom(std::path::PathBuf::from("/x")).name(),
            "custom"
        );
    }

    #[test]
    fn config_tier_from_env_resolves_correctly() {
        let key = "SHIKUMI_TIERED_TEST_TIER_X";
        // Set to "bare", verify resolution.
        // SAFETY: tests run single-threaded per test by default;
        // we restore + clear the env var on every branch.
        unsafe {
            std::env::set_var(key, "bare");
        }
        assert_eq!(ConfigTier::from_env(key), ConfigTier::Bare);
        unsafe {
            std::env::set_var(key, "");
        }
        assert_eq!(ConfigTier::from_env(key), ConfigTier::Default);
        unsafe {
            std::env::remove_var(key);
        }
        assert_eq!(ConfigTier::from_env(key), ConfigTier::Default);
    }

    #[test]
    fn resolve_tier_dispatches_to_each_method() {
        assert_eq!(Toy::resolve_tier(ConfigTier::Bare), Toy::bare());
        assert_eq!(Toy::resolve_tier(ConfigTier::Discovered), Toy::discovered());
        assert_eq!(
            Toy::resolve_tier(ConfigTier::Default),
            Toy::prescribed_default()
        );
    }

    #[test]
    fn resolve_tier_custom_missing_file_falls_back_to_default() {
        let phantom = std::path::PathBuf::from("/nonexistent/path/shikumi-tier-fallback-test.yaml");
        let resolved = Toy::resolve_tier(ConfigTier::Custom(phantom));
        assert_eq!(resolved, Toy::prescribed_default());
    }

    // ── ConfigTierKind + ConfigTier::kind coverage ──────────────

    #[test]
    fn config_tier_kind_all_has_four_entries() {
        // Pin today's tier-kind cardinality. A fifth tier kind
        // landing forces the ::ALL slice in lockstep with the
        // enum, and the `for_each_closed_axis_primitive!` macro
        // cardinality checksum in `cube::tests` (axis_cardinality
        // sum) catches the drift before silent dropouts at the
        // trait-uniform test sites.
        assert_eq!(ConfigTierKind::ALL.len(), 4);
        assert_eq!(ConfigTierKind::ALL[0], ConfigTierKind::Bare);
        assert_eq!(ConfigTierKind::ALL[1], ConfigTierKind::Discovered);
        assert_eq!(ConfigTierKind::ALL[2], ConfigTierKind::Default);
        assert_eq!(ConfigTierKind::ALL[3], ConfigTierKind::Custom);
    }

    #[test]
    fn config_tier_kind_trait_all_matches_inherent_all() {
        // Mirror of the per-axis trait/inherent agreement test:
        // <ConfigTierKind as ClosedAxis>::ALL is the same slice as
        // ConfigTierKind::ALL pointwise in declaration order.
        assert_eq!(
            <ConfigTierKind as crate::ClosedAxis>::ALL.len(),
            ConfigTierKind::ALL.len(),
        );
        for (i, (trait_kind, inherent_kind)) in <ConfigTierKind as crate::ClosedAxis>::ALL
            .iter()
            .zip(ConfigTierKind::ALL.iter())
            .enumerate()
        {
            assert_eq!(
                trait_kind, inherent_kind,
                "trait ALL[{i}] must equal inherent ALL[{i}]",
            );
        }
    }

    #[test]
    fn config_tier_kind_as_str_yields_canonical_lowercase_names() {
        assert_eq!(ConfigTierKind::Bare.as_str(), "bare");
        assert_eq!(ConfigTierKind::Discovered.as_str(), "discovered");
        assert_eq!(ConfigTierKind::Default.as_str(), "default");
        assert_eq!(ConfigTierKind::Custom.as_str(), "custom");
    }

    #[test]
    fn config_tier_kind_from_str_round_trips_with_as_str() {
        // Round-trip law: `from_str(kind.as_str()) == Some(kind)`
        // for every kind. Pinned over the full ::ALL slice so a
        // fifth tier kind inherits the law automatically.
        for &kind in ConfigTierKind::ALL {
            assert_eq!(
                ConfigTierKind::from_str(kind.as_str()),
                Some(kind),
                "round-trip failed for kind {kind:?}",
            );
        }
    }

    #[test]
    fn config_tier_kind_from_str_is_case_insensitive() {
        assert_eq!(ConfigTierKind::from_str("BARE"), Some(ConfigTierKind::Bare),);
        assert_eq!(
            ConfigTierKind::from_str("Discovered"),
            Some(ConfigTierKind::Discovered),
        );
        assert_eq!(
            ConfigTierKind::from_str("DeFaUlT"),
            Some(ConfigTierKind::Default),
        );
        assert_eq!(
            ConfigTierKind::from_str("CUSTOM"),
            Some(ConfigTierKind::Custom),
        );
    }

    #[test]
    fn config_tier_kind_from_str_returns_none_on_unknown() {
        assert_eq!(ConfigTierKind::from_str(""), None);
        assert_eq!(ConfigTierKind::from_str("nonexistent"), None);
        assert_eq!(ConfigTierKind::from_str("/etc/foo.yaml"), None);
        // No trim — the caller owns trim policy.
        assert_eq!(ConfigTierKind::from_str(" bare "), None);
    }

    #[test]
    fn config_tier_kind_projection_matches_config_tier_name() {
        // The kind projection and the ConfigTier::name() lookup
        // must agree pointwise — both are routed through
        // ConfigTierKind::as_str. Pins the duplication budget at
        // zero: the four tier-name strings live at one site
        // (ConfigTierKind::as_str).
        let pairs: [(ConfigTier, ConfigTierKind); 4] = [
            (ConfigTier::Bare, ConfigTierKind::Bare),
            (ConfigTier::Discovered, ConfigTierKind::Discovered),
            (ConfigTier::Default, ConfigTierKind::Default),
            (
                ConfigTier::Custom(std::path::PathBuf::from("/x")),
                ConfigTierKind::Custom,
            ),
        ];
        for (tier, expected_kind) in pairs {
            assert_eq!(tier.kind(), expected_kind);
            assert_eq!(tier.name(), expected_kind.as_str());
        }
    }

    #[test]
    fn config_tier_from_env_still_lowercases_unknown_paths() {
        // Behavior preservation: prior implementation lowercased
        // unrecognized strings before wrapping them in Custom.
        // This pin catches any future drift away from that
        // (somewhat surprising) behavior — kept so that the lift
        // is purely structural and doesn't change semantics.
        let key = "SHIKUMI_TIERED_TEST_TIER_PATH";
        unsafe {
            std::env::set_var(key, "/Foo/Bar.YAML");
        }
        let tier = ConfigTier::from_env(key);
        match tier {
            ConfigTier::Custom(p) => assert_eq!(
                p,
                std::path::PathBuf::from("/foo/bar.yaml"),
                "from_env preserves the pre-lift lowercase behavior",
            ),
            other => panic!("expected Custom, got {other:?}"),
        }
        unsafe {
            std::env::remove_var(key);
        }
    }

    // ── DiffLineKind + DiffLine::kind coverage ──────────────────
    //
    // The (DiffLine → DiffLineKind) lift closes the diff-cell kind
    // partition on the third closed three-way classification of the
    // typescape, alongside `ConfigSourceKind` (3 cells), `FieldPathLocalization`
    // (3), and `WatchEventClass` (3). Tests mirror the
    // `EnvMetadataTagKind` suite pointwise on the source axis:
    // forward-map exhaustivity, payload-independence, trait-bounds
    // parity, no-duplicates on the closed list, image containment in
    // `ALL`, declaration-order pin, concrete-position canonical
    // labels, glyph-pin against the operator-facing unified-diff
    // convention, refactor pins on the two consumer sites
    // (`is_empty_diff` / `render_unified`), and the trait-default
    // round-trip.

    fn canonical_diff_line_kind_samples() -> Vec<(DiffLine, DiffLineKind)> {
        vec![
            (DiffLine::Removed("name: ''".into()), DiffLineKind::Removed),
            (
                DiffLine::Added("name: default-name".into()),
                DiffLineKind::Added,
            ),
            (DiffLine::Context("size: 42".into()), DiffLineKind::Context),
            (DiffLine::Removed(String::new()), DiffLineKind::Removed),
            (DiffLine::Added(String::new()), DiffLineKind::Added),
            (DiffLine::Context(String::new()), DiffLineKind::Context),
        ]
    }

    #[test]
    fn diff_line_kind_classifies_each_variant() {
        // The forward map DiffLine → DiffLineKind is exhaustive: every
        // variant pins to exactly one kind.
        assert_eq!(DiffLine::Removed("x".into()).kind(), DiffLineKind::Removed,);
        assert_eq!(DiffLine::Added("y".into()).kind(), DiffLineKind::Added);
        assert_eq!(DiffLine::Context("z".into()).kind(), DiffLineKind::Context,);
    }

    #[test]
    fn diff_line_kind_is_data_free() {
        // Inner payload does not influence kind — every Removed
        // variant maps to DiffLineKind::Removed regardless of the
        // inner String. Mirrors `env_metadata_tag_kind_is_data_free`
        // on the figment-Name env-name sub-axis.
        for payload in ["", "a", "name: 'long value'  ", "\n", "\u{1F600}"] {
            assert_eq!(
                DiffLine::Removed(payload.to_string()).kind(),
                DiffLineKind::Removed,
            );
            assert_eq!(
                DiffLine::Added(payload.to_string()).kind(),
                DiffLineKind::Added,
            );
            assert_eq!(
                DiffLine::Context(payload.to_string()).kind(),
                DiffLineKind::Context,
            );
        }
    }

    #[test]
    fn diff_line_kind_agrees_with_predicates_pointwise() {
        // The kind() projection must agree with the kind-side
        // `is_removed` / `is_added` / `is_context` predicates pointwise
        // on every constructible variant.
        for (line, expected) in canonical_diff_line_kind_samples() {
            let k = line.kind();
            assert_eq!(k, expected);
            assert_eq!(k.is_removed(), k == DiffLineKind::Removed);
            assert_eq!(k.is_added(), k == DiffLineKind::Added);
            assert_eq!(k.is_context(), k == DiffLineKind::Context);
        }
    }

    #[test]
    fn diff_line_kind_is_changed_partitions_added_or_removed() {
        // is_changed() partitions the kind axis: true exactly on the
        // two changed kinds (Added, Removed), false on Context. The
        // partition is the structural law `ConfigDiff::is_empty_diff`
        // refines through `.kind().is_changed()`.
        assert!(DiffLineKind::Removed.is_changed());
        assert!(DiffLineKind::Added.is_changed());
        assert!(!DiffLineKind::Context.is_changed());
    }

    #[test]
    fn diff_line_kind_is_static_and_copy_and_hashable() {
        // The discriminant is `'static` (no lifetime parameter) and
        // Copy + Hash + Eq, so it can be hashed in a `'static` map and
        // cross thread boundaries the borrowed payload `&String`
        // cannot. Trait bounds match the sibling typescape primitives.
        use std::collections::HashSet;
        fn assert_static<T: 'static>() {}
        assert_static::<DiffLineKind>();
        let mut set: HashSet<DiffLineKind> = DiffLineKind::ALL.iter().copied().collect();
        set.insert(DiffLineKind::Removed); // duplicate
        assert_eq!(set.len(), DiffLineKind::ALL.len());
        // Copy: rebind without move.
        let k = DiffLineKind::Added;
        let k2 = k;
        assert_eq!(k, k2);
    }

    #[test]
    fn diff_line_kind_all_has_no_duplicates() {
        // `ALL` is a set on the closed axis — no duplicated variant.
        use std::collections::HashSet;
        let unique: HashSet<DiffLineKind> = DiffLineKind::ALL.iter().copied().collect();
        assert_eq!(unique.len(), DiffLineKind::ALL.len());
    }

    #[test]
    fn diff_line_kind_all_covers_every_constructible_line() {
        // Every kind produced by DiffLine::kind() on the canonical
        // sample table appears in DiffLineKind::ALL. Catches drift if
        // a future DiffLine variant lands without extending ::ALL.
        for (line, _) in canonical_diff_line_kind_samples() {
            assert!(
                DiffLineKind::ALL.contains(&line.kind()),
                "DiffLineKind::ALL must contain the kind of every constructible DiffLine",
            );
        }
    }

    #[test]
    fn diff_line_kind_all_equals_diff_line_kind_image() {
        // Tight image / `ALL` equality: the image of DiffLine::kind
        // over the canonical sample table equals DiffLineKind::ALL as
        // a set — no kind cell is unreachable, no orphan cell exists.
        use std::collections::HashSet;
        let image: HashSet<DiffLineKind> = canonical_diff_line_kind_samples()
            .into_iter()
            .map(|(l, _)| l.kind())
            .collect();
        let all: HashSet<DiffLineKind> = DiffLineKind::ALL.iter().copied().collect();
        assert_eq!(image, all);
    }

    #[test]
    fn diff_line_kind_all_declaration_order_is_removed_added_context() {
        // Declaration order pin. Mirror of the renderer's natural
        // reading order (removed → added → context) so the canonical
        // axis enumeration matches the unified-diff legend operators
        // already read in tools.
        assert_eq!(DiffLineKind::ALL.len(), 3);
        assert_eq!(DiffLineKind::ALL[0], DiffLineKind::Removed);
        assert_eq!(DiffLineKind::ALL[1], DiffLineKind::Added);
        assert_eq!(DiffLineKind::ALL[2], DiffLineKind::Context);
    }

    #[test]
    fn diff_line_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on the canonical operator-facing
        // labels. A rename here would surface a literal string change
        // before drifting through the round-trip law.
        assert_eq!(DiffLineKind::Removed.as_str(), "removed");
        assert_eq!(DiffLineKind::Added.as_str(), "added");
        assert_eq!(DiffLineKind::Context.as_str(), "context");
    }

    #[test]
    fn diff_line_kind_glyph_yields_canonical_unified_diff_prefixes() {
        // Concrete-position pin on the canonical unified-diff glyphs.
        // The three glyph characters previously lived inline at the
        // renderer's three-arm match; pinning them at the kind axis
        // catches any future rename before drifting through the
        // renderer.
        assert_eq!(DiffLineKind::Removed.glyph(), '-');
        assert_eq!(DiffLineKind::Added.glyph(), '+');
        assert_eq!(DiffLineKind::Context.glyph(), ' ');
    }

    #[test]
    fn diff_line_text_returns_inner_payload_pointwise() {
        // The `text` accessor borrows the inner payload regardless of
        // kind. Composes with `.kind()` to losslessly decompose a
        // DiffLine into its (kind, text) pair — the natural shape for
        // any renderer that previously matched on the three variants.
        for payload in ["", "a", "name: value", "  leading spaces"] {
            assert_eq!(DiffLine::Removed(payload.to_string()).text(), payload);
            assert_eq!(DiffLine::Added(payload.to_string()).text(), payload);
            assert_eq!(DiffLine::Context(payload.to_string()).text(), payload);
        }
    }

    #[test]
    fn diff_line_kind_from_canonical_str_round_trips_through_trait() {
        // Trait-default round-trip law: case-insensitively, every
        // canonical label parses back to its kind via the
        // `ClosedAxisLabel` trait default. Mixed-case inputs hit the
        // case-insensitive parse path.
        use crate::ClosedAxisLabel;
        for &k in DiffLineKind::ALL {
            let lower = k.as_str();
            assert_eq!(DiffLineKind::from_canonical_str(lower), Some(k));
            let upper = lower.to_ascii_uppercase();
            assert_eq!(DiffLineKind::from_canonical_str(&upper), Some(k));
            // Mixed: capitalize first letter only.
            let mut mixed = String::new();
            for (i, c) in lower.chars().enumerate() {
                if i == 0 {
                    mixed.extend(c.to_uppercase());
                } else {
                    mixed.push(c);
                }
            }
            assert_eq!(DiffLineKind::from_canonical_str(&mixed), Some(k));
        }
    }

    #[test]
    fn config_diff_is_empty_diff_routes_through_diff_line_kind_is_changed() {
        // Pin the structural refactor: `ConfigDiff::is_empty_diff`
        // returns false iff some line has a `is_changed` kind. A diff
        // composed of only Context lines is empty; any Added or
        // Removed line makes it non-empty regardless of how many
        // Context lines surround it.
        let only_context = ConfigDiff {
            lines: vec![DiffLine::Context("a".into()), DiffLine::Context("b".into())],
        };
        assert!(only_context.is_empty_diff());

        let with_added = ConfigDiff {
            lines: vec![
                DiffLine::Context("a".into()),
                DiffLine::Added("c".into()),
                DiffLine::Context("b".into()),
            ],
        };
        assert!(!with_added.is_empty_diff());

        let with_removed = ConfigDiff {
            lines: vec![DiffLine::Removed("x".into())],
        };
        assert!(!with_removed.is_empty_diff());

        let empty_lines = ConfigDiff { lines: vec![] };
        assert!(empty_lines.is_empty_diff());
    }

    #[test]
    fn config_diff_render_unified_emits_one_glyph_per_kind() {
        // Pin the structural refactor: `ConfigDiff::render_unified`
        // routes each line's glyph through `DiffLineKind::glyph` and
        // each payload through `DiffLine::text`. The rendered output
        // is byte-identical to the prior open-coded three-arm match.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Removed("name: ''".into()),
                DiffLine::Added("name: default-name".into()),
                DiffLine::Context("size: 42".into()),
            ],
        };
        let rendered = diff.render_unified();
        assert_eq!(
            rendered, "-name: ''\n+name: default-name\n size: 42\n",
            "render_unified must emit the canonical glyph per kind",
        );
        // Pointwise: each line's first character equals its kind's glyph.
        for (i, line) in diff.lines.iter().enumerate() {
            let expected_glyph = line.kind().glyph();
            let actual_first = rendered
                .lines()
                .nth(i)
                .and_then(|s| s.chars().next())
                .expect("rendered output must have at least i+1 lines");
            assert_eq!(
                actual_first, expected_glyph,
                "rendered line {i} must start with its kind's glyph",
            );
        }
    }

    #[test]
    fn config_diff_render_unified_byte_identical_to_pre_lift_form() {
        // Strong pin on the refactor: the rendered output must match
        // what the prior three-arm match produced byte-for-byte across
        // every line position (empty payloads, mixed kinds, trailing
        // newlines). Composes with the kind-axis lift without changing
        // the operator-facing surface.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Context(String::new()),
                DiffLine::Removed("a".into()),
                DiffLine::Added("b".into()),
                DiffLine::Context("c".into()),
            ],
        };
        // Pre-lift expected output:
        //   " \n" + "-a\n" + "+b\n" + " c\n"
        assert_eq!(diff.render_unified(), " \n-a\n+b\n c\n");
    }

    #[test]
    fn config_tier_from_str_or_default_via_kind_dispatch() {
        // Smoke pin on the refactored dispatch — same matching
        // rules as before, now routed through ConfigTierKind.
        assert_eq!(ConfigTier::from_str_or_default("bare"), ConfigTier::Bare);
        assert_eq!(
            ConfigTier::from_str_or_default("DISCOVERED"),
            ConfigTier::Discovered,
        );
        assert_eq!(
            ConfigTier::from_str_or_default("default"),
            ConfigTier::Default,
        );
        assert_eq!(ConfigTier::from_str_or_default(""), ConfigTier::Default,);
        // "custom" with no path → Custom(PathBuf::from("custom"))
        // (the literal string becomes the path). Preserves the
        // pre-lift fall-through behavior.
        match ConfigTier::from_str_or_default("custom") {
            ConfigTier::Custom(p) => {
                assert_eq!(p, std::path::PathBuf::from("custom"));
            }
            other => panic!("expected Custom, got {other:?}"),
        }
        match ConfigTier::from_str_or_default("/etc/foo.yaml") {
            ConfigTier::Custom(p) => {
                assert_eq!(p, std::path::PathBuf::from("/etc/foo.yaml"));
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn kind_histogram_counts_each_kind_pointwise() {
        // Concrete pin on the [`ConfigDiff::kind_histogram`] lift: the
        // per-cell counts agree with the manual filter-and-count loop
        // it replaces. The fixture covers the three diff-cell kinds at
        // distinct cardinalities so the per-cell numbers are
        // distinguishable (1 removed, 2 added, 3 context).
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r1".into()),
                DiffLine::Added("a1".into()),
                DiffLine::Added("a2".into()),
                DiffLine::Context("c1".into()),
                DiffLine::Context("c2".into()),
                DiffLine::Context("c3".into()),
            ],
        };
        let hist = diff.kind_histogram();
        assert_eq!(hist.count(DiffLineKind::Removed), 1);
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.count(DiffLineKind::Context), 3);
        assert_eq!(hist.total(), diff.lines.len());
    }

    #[test]
    fn kind_histogram_empty_diff_is_zero_on_every_cell() {
        // An empty [`ConfigDiff`] yields the all-zero histogram: total
        // = 0, every cell = 0, `is_empty()` = true. The identity slot
        // of the histogram monoid on the diff-cell axis.
        let diff = ConfigDiff::default();
        let hist = diff.kind_histogram();
        assert_eq!(hist.total(), 0);
        assert!(hist.is_empty());
        for cell in [
            DiffLineKind::Removed,
            DiffLineKind::Added,
            DiffLineKind::Context,
        ] {
            assert_eq!(hist.count(cell), 0);
        }
    }

    #[test]
    fn kind_histogram_changed_cells_match_is_empty_diff() {
        // Cross-primitive law: the sum of the [`DiffLineKind::Added`]
        // and [`DiffLineKind::Removed`] cells equals zero iff
        // [`ConfigDiff::is_empty_diff`] returns true. Both
        // surfaces project from the same partition over the
        // [`DiffLineKind`] axis (the `is_changed()` half), so the
        // agreement is structural — pinned here on a context-only
        // diff (empty by structure) and on a mixed diff.
        let context_only = ConfigDiff {
            lines: vec![DiffLine::Context("c".into())],
        };
        let h1 = context_only.kind_histogram();
        assert!(context_only.is_empty_diff());
        assert_eq!(
            h1.count(DiffLineKind::Added) + h1.count(DiffLineKind::Removed),
            0
        );

        let with_change = ConfigDiff {
            lines: vec![DiffLine::Context("c".into()), DiffLine::Added("a".into())],
        };
        let h2 = with_change.kind_histogram();
        assert!(!with_change.is_empty_diff());
        assert!(h2.count(DiffLineKind::Added) + h2.count(DiffLineKind::Removed) > 0);
    }

    #[test]
    fn kind_histogram_iter_yields_declaration_order() {
        // The histogram's `iter()` walks
        // [`DiffLineKind::ALL`] in declaration order
        // (Removed, Added, Context) regardless of input ordering.
        // Pinned here against an input that observes Context first,
        // then Added, then Removed — the histogram's iteration order
        // is by axis declaration, not by observation order.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Context("c".into()),
                DiffLine::Added("a".into()),
                DiffLine::Removed("r".into()),
            ],
        };
        let pairs: Vec<(DiffLineKind, usize)> = diff.kind_histogram().iter().collect();
        assert_eq!(
            pairs,
            vec![
                (DiffLineKind::Removed, 1),
                (DiffLineKind::Added, 1),
                (DiffLineKind::Context, 1),
            ],
        );
    }

    #[test]
    fn diff_line_kind_ord_matches_all_declaration_order() {
        // The derived Ord on DiffLineKind is declaration-order lex
        // over ALL: `Removed < Added < Context`. A BTreeMap keyed on
        // the diff-cell kind (per-cell rebuild-summary histograms
        // keyed over a stable axis, attestation manifests recording
        // the diff-cell cardinality mix of a ConfigDiff between two
        // tiers, structured-diagnostic legends bucketing per-cell
        // counters in declaration order) emits rows in that order
        // deterministically without a hand-rolled comparator at the
        // renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds). Idiom-peer
        // of the same pin on WatchEventClass (commit `94f8a8b`),
        // EnvMetadataTagKind (commit `b556b75`), FigmentNameTagKind
        // (commit `64a47e7`), FigmentSourceKind (commit `5df265c`),
        // and ConfigSourceKind (commit `e0b96d1`).
        use std::cmp::Ordering;
        for window in DiffLineKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "DiffLineKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in DiffLineKind::ALL.iter().enumerate() {
            for (j, &b) in DiffLineKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "DiffLineKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "DiffLineKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn diff_line_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<DiffLineKind, _> emits keys
        // in declaration order on `iter()` / `into_iter()`
        // regardless of insertion order, matching
        // `DiffLineKind::ALL`. Idiom-peer of the same pin on
        // WatchEventClass (commit `94f8a8b`), EnvMetadataTagKind
        // (commit `b556b75`), FigmentNameTagKind (commit `64a47e7`),
        // FigmentSourceKind (commit `5df265c`), and ConfigSourceKind
        // (commit `e0b96d1`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<DiffLineKind, u32> = BTreeMap::new();
        counts.insert(DiffLineKind::Context, 3);
        counts.insert(DiffLineKind::Removed, 1);
        counts.insert(DiffLineKind::Added, 2);
        let observed: Vec<DiffLineKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            DiffLineKind::ALL.to_vec(),
            "BTreeMap<DiffLineKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn diff_line_kind_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on WatchEventClass
        // (commit `94f8a8b`), EnvMetadataTagKind (commit `b556b75`),
        // FigmentNameTagKind (commit `64a47e7`), and FigmentSourceKind
        // (commit `5df265c`).
        for k in DiffLineKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn diff_line_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in DiffLineKind::ALL {
            let rendered = k.to_string();
            let parsed: DiffLineKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn diff_line_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into a CLI flag
        // or structured-log filter parse pointwise to the same
        // variant.
        assert_eq!(
            "REMOVED".parse::<DiffLineKind>().unwrap(),
            DiffLineKind::Removed,
        );
        assert_eq!(
            "Added".parse::<DiffLineKind>().unwrap(),
            DiffLineKind::Added,
        );
        assert_eq!(
            "cOnTeXt".parse::<DiffLineKind>().unwrap(),
            DiffLineKind::Context,
        );
        assert_eq!(
            "rEmOvEd".parse::<DiffLineKind>().unwrap(),
            DiffLineKind::Removed,
        );
    }

    #[test]
    fn diff_line_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // WatchEventClass's FromStr surface (commit `94f8a8b`),
        // EnvMetadataTagKind's FromStr surface (commit `b556b75`),
        // FigmentNameTagKind's FromStr surface (commit `64a47e7`),
        // FigmentSourceKind's FromStr surface (commit `5df265c`),
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`),
        // FormatProvenance's FromStr surface (commit `2c7654c`), and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["changed", "deleted", "modified", "", "  removed"] {
            let err = bad
                .parse::<DiffLineKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn diff_line_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the diff-cell axis primitive. A consumer struct
        // holding a DiffLineKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the diff-cell kind of a `ConfigDiff`
        // sample) round-trips without a consumer-side rename helper.
        for k in DiffLineKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: DiffLineKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn diff_line_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for k in DiffLineKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: DiffLineKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn diff_line_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, DiffLineKind)] = &[
            ("Removed", DiffLineKind::Removed),
            ("ADDED", DiffLineKind::Added),
            ("CoNtExT", DiffLineKind::Context),
            ("rEmOvEd", DiffLineKind::Removed),
        ];
        for (input, expected) in cases {
            let parsed: DiffLineKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn diff_line_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized diff-cell kind label surfaces at the serde
        // error site with the offending substring verbatim in the
        // rendered message, lifted through ShikumiError::Parse's
        // Display impl. Same verbatim-rejection discipline as
        // WatchEventClass's serde surface (commit `94f8a8b`),
        // EnvMetadataTagKind's serde surface (commit `b556b75`),
        // FigmentNameTagKind's serde surface (commit `64a47e7`),
        // FigmentSourceKind's serde surface (commit `5df265c`),
        // ConfigSourceKind's serde surface (commit `e0b96d1`), and
        // FormatProvenance's serde surface (commit `2c7654c`).
        for bad in &["changed", "deleted", "modified", "noop"] {
            let err = serde_yaml::from_str::<DiffLineKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn diff_line_kind_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on DiffLineKind's YAML emission:
        // every variant renders as a bare lowercase scalar (no
        // quotes, no tag prefix). Routes through
        // Serializer::collect_str → Display → as_str, so the wire
        // shape is exactly `format!("{k}")` followed by serde_yaml's
        // newline terminator. Pins the serde idiom-peer of the
        // Display surface byte-for-byte at concrete positions across
        // every variant. Idiom-peer of
        // `watch_event_class_serde_yaml_emission_is_bare_scalar`
        // (commit `94f8a8b`).
        assert_eq!(
            serde_yaml::to_string(&DiffLineKind::Removed).unwrap(),
            "removed\n",
        );
        assert_eq!(
            serde_yaml::to_string(&DiffLineKind::Added).unwrap(),
            "added\n",
        );
        assert_eq!(
            serde_yaml::to_string(&DiffLineKind::Context).unwrap(),
            "context\n",
        );
    }
}

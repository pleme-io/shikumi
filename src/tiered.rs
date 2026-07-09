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

use crate::discovered::{DiscoveryLayer, compose, deep_merge, deep_merge_attributed};
use crate::source::ConfigSource;
use figment::value::Dict;
use figment::{Figment, providers::Serialized};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

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

    /// **The sealed progressive fold — the first-class default resolution.**
    ///
    /// Folds every tier in [`ConfigTier`] precedence order —
    /// `bare() → discovered() → prescribed_default()` — into ONE resolved
    /// config, stamping each effective leaf with the typed [`Provenance`]
    /// of the tier that produced it. This is the entry point the ~90%
    /// "default" path should reach for: unlike
    /// [`Self::resolve_tier`]`(`[`ConfigTier::Default`]`)` — which returns
    /// `prescribed_default()` *alone* and so silently skips discovery — the
    /// fold composes the [`Self::discovered`] auto-detect tier *underneath*
    /// the curated defaults, so a value the environment detected shows
    /// through wherever `prescribed_default()` doesn't override it.
    ///
    /// [`Self::resolve_tier`] / [`Self::resolve_from_env`] are unchanged:
    /// they pick ONE baseline tier (legacy single-tier semantics preserved).
    /// This method is the additive, provenance-carrying FOLD across all
    /// tiers — the (value, provenance) pair is co-constructed here and
    /// returned together, so a progressively-resolved value is never
    /// separable from its provenance.
    #[must_use]
    fn resolve_progressive() -> ProgressiveResolution<Self> {
        Self::resolve_progressive_with(&[])
    }

    /// [`Self::resolve_progressive`] with operator `overlays` (file / env /
    /// runtime override) appended above the three trait tiers.
    ///
    /// Each [`ProgressiveLayer`] carries its own [`Provenance`]; the fold
    /// **stable-sorts the whole layer stack by the const [`ConfigTierKind`]
    /// [`crate::ClosedAxis`] precedence ordinal BEFORE merging**, so no
    /// input ordering can let a lower tier beat a higher one — the
    /// precedence IS the ordering, structurally (a mis-ordered overlay is
    /// re-sorted to its tier's rank; same-tier overlays keep caller order).
    ///
    /// Attribution is **last-changer**: a leaf is credited to the highest
    /// tier that set it to its final value, so a `prescribed_default()`
    /// built on `discovered()` that re-emits a detected value unchanged
    /// leaves that leaf credited to `Discovered`, not `Default`.
    #[must_use]
    fn resolve_progressive_with(overlays: &[ProgressiveLayer]) -> ProgressiveResolution<Self> {
        // 1. Assemble the three trait tiers, each serialized to a dict and
        //    tagged with its computed-defaults provenance.
        let mut layers: Vec<(Provenance, Dict)> = vec![
            (
                Provenance::computed(ConfigTierKind::Bare),
                tiered_to_dict(&Self::bare()),
            ),
            (
                Provenance::computed(ConfigTierKind::Discovered),
                tiered_to_dict(&Self::discovered()),
            ),
            (
                Provenance::computed(ConfigTierKind::Default),
                tiered_to_dict(&Self::prescribed_default()),
            ),
        ];
        layers.extend(
            overlays
                .iter()
                .map(|ov| (ov.provenance().clone(), ov.dict().clone())),
        );
        // 2. Order by the const ConfigTierKind ClosedAxis ordinal. A stable
        //    sort keeps same-tier overlays (e.g. two files) in caller order.
        layers.sort_by_key(|(prov, _)| prov.tier_ordinal());

        // 3. Fold with per-leaf, change-aware provenance attribution — the
        //    ONLY construction path for a progressively-resolved provenance
        //    map, so "a lower tier silently beats a higher one" has no path.
        let mut merged = Dict::new();
        let mut attribution: BTreeMap<Vec<String>, Provenance> = BTreeMap::new();
        for (prov, dict) in layers {
            deep_merge_attributed(&mut merged, dict, &[], &prov, &mut attribution, true);
        }

        // 4. Materialize `Self` from the folded dict. Every input is a valid
        //    `Self` serialization (or an operator overlay merged over one),
        //    so extraction succeeds; the defensive fallback keeps totality.
        let value = Figment::new()
            .merge(Serialized::defaults(&merged))
            .extract::<Self>()
            .unwrap_or_else(|_| Self::prescribed_default());
        ProgressiveResolution {
            value,
            provenance: ProvenanceMap { inner: attribution },
        }
    }

    /// Low-ceremony standard seam for wiring the [`Self::discovered`] tier
    /// from a declarative stack of [`DiscoveryLayer`]s (typically one per
    /// `kanchi` axis-group) instead of hand-rolling a struct literal.
    ///
    /// `bare()` is the floor; the [`compose`]d discovery dict deep-merges
    /// over it per leaf, so an undetectable axis (empty dict) degenerates
    /// cleanly to the bare value — **discovery totality by construction**
    /// (`kanchi`'s `Option<T>` + `_or_fallback` never panics, and an
    /// empty-dict layer is a no-op here). A consumer's whole `discovered()`
    /// collapses to:
    ///
    /// ```ignore
    /// fn discovered() -> Self {
    ///     Self::discovered_from_layers(&[&WindowLayer, &FontLayer])
    /// }
    /// ```
    ///
    /// where each layer's [`DiscoveryLayer::discover`] returns a partial
    /// dict built from `kanchi::detect_*_or_fallback()` — no per-consumer
    /// merge code, and the same [`compose`] machinery that already powers
    /// [`crate::ProviderChain::with_discovery_layers`].
    #[must_use]
    fn discovered_from_layers(layers: &[&dyn DiscoveryLayer]) -> Self {
        let mut merged = tiered_to_dict(&Self::bare());
        deep_merge(&mut merged, compose(layers));
        Figment::new()
            .merge(Serialized::defaults(&merged))
            .extract::<Self>()
            .unwrap_or_else(|_| Self::bare())
    }

    /// Diff `self` against `baseline`. Default: serialize both to
    /// YAML and produce a line-oriented diff.
    fn diff_against(&self, baseline: &Self) -> ConfigDiff {
        let a = serde_yaml::to_string(baseline).unwrap_or_default();
        let b = serde_yaml::to_string(self).unwrap_or_default();
        ConfigDiff::from_yaml_pair(&a, &b)
    }
}

/// Serialize a tiered value into a figment [`Dict`] for the progressive
/// fold. A value that serializes to a non-dict shape (no struct-shaped
/// config does) yields an empty dict — the fold then treats that tier as
/// contributing nothing, never panicking. This is the exact
/// `Serialized::defaults(_)` mechanism [`crate::ProviderChain::with_discovered`]
/// already uses, run in the extract direction.
fn tiered_to_dict<T: Serialize>(value: &T) -> Dict {
    Figment::new()
        .merge(Serialized::defaults(value))
        .extract::<Dict>()
        .unwrap_or_default()
}

// ── Provenance — the typed (tier, source) origin of an effective value ──

/// The typed origin of one effective configuration value: **which
/// [`ConfigTier`] and which [`ConfigSource`]** produced it.
///
/// A [`Provenance`] composes the two provenance primitives shikumi already
/// owns — the [`ConfigTierKind`] closed axis (which conceptual tier) and
/// the [`ConfigSource`] closed enum (which provider kind, with its file
/// path / env prefix payload) — into the pair the progressive fold stamps
/// per leaf. The three computed tiers (`bare` / `discovered` / `prescribed`)
/// carry [`ConfigSource::Defaults`] — the same layer-kind
/// [`crate::ProviderChain::with_discovered`] records for machine-derived
/// layers; operator overlays carry [`ConfigSource::File`] /
/// [`ConfigSource::Env`].
///
/// Precedence — "which tier outranks which" — is read from the const
/// [`ConfigTierKind`] [`crate::ClosedAxis`] declaration order via
/// [`Self::tier_ordinal`]; it is never re-minted here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    tier: ConfigTierKind,
    source: ConfigSource,
}

impl Provenance {
    /// Construct a provenance from an explicit `(tier, source)` pair.
    #[must_use]
    pub fn new(tier: ConfigTierKind, source: ConfigSource) -> Self {
        Self { tier, source }
    }

    /// A computed-defaults tier (`bare` / `discovered` / `prescribed`):
    /// source is [`ConfigSource::Defaults`] — machine-derived, not
    /// operator-supplied.
    #[must_use]
    pub fn computed(tier: ConfigTierKind) -> Self {
        Self {
            tier,
            source: ConfigSource::Defaults,
        }
    }

    /// An operator FILE overlay — tier [`ConfigTierKind::Custom`], source
    /// [`ConfigSource::File`].
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            tier: ConfigTierKind::Custom,
            source: ConfigSource::File(path.into()),
        }
    }

    /// An operator ENV overlay — tier [`ConfigTierKind::Custom`], source
    /// [`ConfigSource::Env`] with the given prefix.
    #[must_use]
    pub fn env(prefix: impl Into<String>) -> Self {
        Self {
            tier: ConfigTierKind::Custom,
            source: ConfigSource::Env(prefix.into()),
        }
    }

    /// The conceptual tier that produced the value.
    #[must_use]
    pub fn tier(&self) -> ConfigTierKind {
        self.tier
    }

    /// The provider source that produced the value.
    #[must_use]
    pub fn source(&self) -> &ConfigSource {
        &self.source
    }

    /// The const [`crate::ClosedAxis`] precedence ordinal of this
    /// provenance's tier — the single source of truth for "which tier
    /// outranks which" (reused from [`ConfigTierKind`]'s declaration order,
    /// never re-minted). A higher ordinal wins in the progressive fold.
    #[must_use]
    pub fn tier_ordinal(&self) -> usize {
        crate::axis_ordinal(self.tier)
    }
}

impl std::fmt::Display for Provenance {
    /// Typed emission: the tier label ([`ConfigTierKind::as_str`]) plus the
    /// source detail (env prefix / file path) rendered through the typed
    /// [`ConfigSource`] — no free-form string composition.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tier.as_str())?;
        match &self.source {
            ConfigSource::Defaults => Ok(()),
            ConfigSource::Env(prefix) => write!(f, " (env: {prefix})"),
            ConfigSource::File(path) => write!(f, " (file: {})", path.display()),
        }
    }
}

// ── ProvenanceMap — per-leaf provenance of a resolved config ──

/// Per-leaf provenance for a progressively-resolved config: the
/// [`Provenance`] of the tier that produced every effective leaf.
///
/// Keys are dotted-path components (`Vec<String>`) so keys containing `.`
/// round-trip unambiguously; ordered lexicographically ([`BTreeMap`]
/// iteration) for deterministic dumps. The tier-level peer of
/// [`crate::discovered::LayerAttribution`] (which attributes discovery-layer
/// leaves to a `&'static str` layer name) — both are produced by the one
/// generic [`deep_merge_attributed`] fold, differing only in the
/// attribution codomain.
///
/// Constructed **only** by [`TieredConfig::resolve_progressive`] /
/// [`TieredConfig::resolve_progressive_with`]; seeded from `bare()` (which
/// enumerates every field), so every leaf of the resolved config has a
/// provenance entry by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceMap {
    inner: BTreeMap<Vec<String>, Provenance>,
}

impl ProvenanceMap {
    /// Number of leaves attributed. Equal to the leaf count of the
    /// resolved config (`bare()` seeds every leaf).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no leaves are attributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// [`Provenance`] of the effective leaf named by dotted `path`, or
    /// [`None`] if `path` names no leaf in the resolved config.
    #[must_use]
    pub fn provenance_of(&self, path: &[&str]) -> Option<&Provenance> {
        self.provenance_of_owned(&path.iter().map(|&s| s.to_owned()).collect::<Vec<String>>())
    }

    /// Allocation-free variant of [`Self::provenance_of`] for callers that
    /// already carry an owned path.
    #[must_use]
    pub fn provenance_of_owned(&self, path: &[String]) -> Option<&Provenance> {
        self.inner.get(path)
    }

    /// Sorted `(path, provenance)` entries, lexicographic by path.
    ///
    /// Naming the return type at the API boundary (rather than
    /// `impl Iterator<Item = ...> + '_`) exposes the full trait algebra
    /// the underlying [`BTreeMap::iter`][std::collections::BTreeMap::iter]
    /// walker structurally carries — [`DoubleEndedIterator`],
    /// [`ExactSizeIterator`], [`std::iter::FusedIterator`], and
    /// [`Clone`] — and lets consumers hold the handle in a struct field
    /// or return it up through their own API without smuggling an
    /// unnameable [`impl Trait`][impl-trait] across every seam. The
    /// tier-level peer of the concrete-typed
    /// [`crate::discovered::LayerAttribution::iter`] on the discovered
    /// altitude: both walkers project the same
    /// `(&[String], &Attribution)` pair shape, and both spell their
    /// concrete return type at the API boundary.
    ///
    /// [impl-trait]: https://doc.rust-lang.org/reference/types/impl-trait.html
    #[must_use]
    pub fn entries(&self) -> ProvenanceMapEntries<'_> {
        ProvenanceMapEntries {
            inner: self.inner.iter(),
        }
    }

    /// Idiomatic Rust `iter()` alias for [`Self::entries`] — one seam every
    /// std keyed collection (`BTreeMap::iter`, `HashMap::iter`,
    /// `Vec::iter`) surfaces on its `&Self` reference. The tier-level peer
    /// of [`crate::discovered::LayerAttribution::iter`] on the discovered
    /// altitude: both walkers project the same `(&[String], &Attribution)`
    /// pair shape and both name the same concrete iterator type
    /// ([`ProvenanceMapEntries`] here, [`crate::LayerAttributionIter`]
    /// there) at the API boundary. The seam clippy's
    /// `into_iter_without_iter` lint expects to accompany
    /// [`IntoIterator for &ProvenanceMap`].
    #[must_use]
    pub fn iter(&self) -> ProvenanceMapEntries<'_> {
        self.entries()
    }

    /// Per-tier leaf-count histogram — the shikumi cube-native
    /// [`AxisHistogram<ConfigTierKind>`][crate::AxisHistogram] view over
    /// the tier attribution of each resolved leaf. Every leaf's
    /// [`Provenance::tier`] is one observation on the
    /// [`ConfigTierKind`] closed axis, so the histogram bucketizes the
    /// full [`ProvenanceMap`] over the four tier cells (`Bare |
    /// Discovered | Default | Custom`) in one pass.
    ///
    /// One named site closes the "per-tier leaf shape" summary every
    /// operator-facing consumer previously re-derived inline as
    /// `let mut n = [0usize; 4]; for prov in map.entries() { n[prov.1
    /// .tier_ordinal()] += 1; }` at every render/attestation/dashboard
    /// call site. The tier-level peer of
    /// [`crate::discovered::LayerAttribution::leaf_counts_by_layer`] on
    /// the discovered altitude and of
    /// [`ConfigDiff::kind_histogram`] on the diff altitude — both
    /// project a per-cell histogram off the underlying attribution over
    /// their local closed axis, both name the [`crate::AxisHistogram`]
    /// return type at the API boundary.
    ///
    /// # Full [`crate::AxisHistogram`] surface, for free
    ///
    /// Because [`ConfigTierKind`] is a [`crate::ClosedAxis`], the
    /// returned histogram carries the full per-cell / per-axis surface
    /// [`crate::AxisHistogram`] provides at trait-uniform altitude:
    /// [`count`][crate::AxisHistogram::count] /
    /// [`total`][crate::AxisHistogram::total] /
    /// [`distinct_cells`][crate::AxisHistogram::distinct_cells] /
    /// [`is_full_cover`][crate::AxisHistogram::is_full_cover] (per-tier
    /// shape), [`dominant_cell`][crate::AxisHistogram::dominant_cell] /
    /// [`recessive_cell`][crate::AxisHistogram::recessive_cell] /
    /// [`peak_count`][crate::AxisHistogram::peak_count] /
    /// [`trough_count`][crate::AxisHistogram::trough_count]
    /// (argmax/argmin), [`observed`][crate::AxisHistogram::observed] /
    /// [`unobserved`][crate::AxisHistogram::unobserved] (support /
    /// coverage-gap partition),
    /// [`modality_class`][crate::AxisHistogram::modality_class]
    /// (multiplicity classification). Operators asking "which tier
    /// contributed the most surviving leaves?", "was every tier heard
    /// from?", or "is the surviving-leaf distribution tied at the top?"
    /// route through the shikumi-native primitive without a per-consumer
    /// tally.
    ///
    /// # Invariants
    ///
    /// - `tier_histogram().total() == self.len()` — every leaf projects
    ///   to exactly one tier, so summing the histogram cells recovers
    ///   the total leaf count.
    /// - `tier_histogram().count(t) == self.entries().filter(|(_, p)|
    ///   p.tier() == t).count()` — the per-tier bucket equals the
    ///   entries walk restricted to that tier.
    /// - `tier_histogram().observed().collect::<Vec<_>>() ==
    ///   self.contributing_tiers()` — the observed-cells iter over the
    ///   closed axis in declaration order matches
    ///   [`Self::contributing_tiers`] pointwise (both project the same
    ///   distinct-tier set in `ConfigTier` precedence order). This is
    ///   the pin that lets [`Self::contributing_tiers`] route through
    ///   the histogram without a hand-rolled `Vec::contains` + sort.
    /// - `tier_histogram().is_empty() == self.is_empty()` — the empty
    ///   histogram / empty map boundary agrees at both sites.
    ///
    /// # Cost
    ///
    /// `O(n)` — one pass over `self.inner.values()`, one closed-axis
    /// ordinal increment per leaf. The backing store is a fixed
    /// `axis_cardinality::<ConfigTierKind>()`-sized `Vec<usize>` (four
    /// cells today), so there is no per-leaf allocation and the
    /// histogram size is constant in the axis cardinality regardless of
    /// leaf count.
    #[must_use]
    pub fn tier_histogram(&self) -> crate::AxisHistogram<ConfigTierKind> {
        crate::axis_histogram(self.inner.values().map(|prov| prov.tier))
    }

    /// The distinct tiers that produced ≥1 surviving effective leaf, in
    /// [`ConfigTier`] precedence order — the post-fold dual of "which tiers'
    /// opinions survived".
    ///
    /// Routes through [`Self::tier_histogram`]:
    /// [`crate::AxisHistogram::observed`] iterates the histogram's
    /// support (the closed-axis cells with nonzero count) in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`ConfigTier`] precedence order by construction — the closed-
    /// axis discipline provides the sort + dedup automatically, so this
    /// method reads directly off the shikumi cube-native primitive
    /// instead of hand-rolling `Vec::contains` (`O(n·k)`) + explicit
    /// `sort_by_key(axis_ordinal)`. Pinned by
    /// `contributing_tiers_matches_tier_histogram_observed` in this
    /// module's test cohort.
    #[must_use]
    pub fn contributing_tiers(&self) -> Vec<ConfigTierKind> {
        self.tier_histogram().observed().collect()
    }

    /// The distinct tiers that produced **zero** surviving effective
    /// leaves, in [`ConfigTier`] precedence order — the post-fold dual
    /// of [`Self::contributing_tiers`] and the coverage-gap peer of
    /// [`Self::tier_histogram`] on the tier altitude.
    ///
    /// Routes through [`Self::tier_histogram`]:
    /// [`crate::AxisHistogram::unobserved`] iterates the histogram's
    /// **coverage gap** (the closed-axis cells with zero count) in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`ConfigTier`] precedence order by construction — the closed-
    /// axis discipline provides the sort + dedup automatically, so this
    /// method reads directly off the shikumi cube-native primitive
    /// instead of hand-rolling `ConfigTierKind::ALL.iter().filter(|t|
    /// !self.contributing_tiers().contains(t))` (`O(k·k)` in
    /// axis-cardinality, quadratic on the observed side, plus a
    /// `sort_by_key(axis_ordinal)`) at every operator-facing consumer
    /// asking *"which tiers were never heard from on this resolution?"*
    /// — the fleet dashboard flagging "no operator overlay in play", the
    /// attestation manifest recording the tier coverage gap of a
    /// resolved fold, the diagnostic dump reading *"tiers absent:
    /// [Custom]"* to explain why a hot-reload had no runtime signal.
    ///
    /// The observed-cells peer ([`Self::contributing_tiers`]) and the
    /// coverage-gap peer ([`Self::absent_tiers`]) together form the
    /// **support / coverage-gap partition** on the tier altitude — every
    /// cell of [`ConfigTierKind::ALL`] lies in exactly one of the two,
    /// and the two `Vec<ConfigTierKind>` lengths sum to
    /// [`crate::axis_cardinality::<ConfigTierKind>()`][crate::axis_cardinality].
    /// The tier-altitude dual of the diff-altitude
    /// [`ConfigDiff::present_kinds`] observed-cells peer (whose absent-
    /// cells peer is the natural next lift on the diff altitude) and of
    /// the chain-altitude [`ConfigSourceChain::present_layer_kinds`] /
    /// [`ConfigSourceChain::present_file_formats`] /
    /// [`ConfigSourceChain::present_env_prefix_kinds`] observed-cells
    /// peers.
    ///
    /// # Invariants
    ///
    /// - `absent_tiers().len() == tier_histogram().unobserved_cells()` —
    ///   both project the same coverage-gap cardinality off the
    ///   histogram.
    /// - `contributing_tiers().len() + absent_tiers().len() ==
    ///   crate::axis_cardinality::<ConfigTierKind>()` — the two peers
    ///   partition the closed axis without remainder (every cell is
    ///   either observed or unobserved, never both).
    /// - `contributing_tiers()` and `absent_tiers()` are disjoint: no
    ///   [`ConfigTierKind`] appears in both.
    /// - `absent_tiers().is_empty() == tier_histogram().is_full_cover()`
    ///   — the coverage-gap is empty iff every tier contributed ≥1 leaf.
    /// - `absent_tiers()` on an empty [`ProvenanceMap`] equals
    ///   [`ConfigTierKind::ALL`] (every tier is absent when no leaf
    ///   contributed) — the empty-map / full-coverage-gap boundary.
    /// - `absent_tiers()` is sorted strictly ascending by
    ///   [`crate::axis_ordinal`] on [`ConfigTierKind`] — dedup + sort
    ///   for free from the closed-axis discipline.
    ///
    /// # Cost
    ///
    /// `O(n + k)` where `n = self.inner.len()` (the histogram build)
    /// and `k = crate::axis_cardinality::<ConfigTierKind>()` (the
    /// coverage-gap scan). Both are `O(n)` in practice since the tier
    /// axis carries a fixed four-cell cardinality; the returned
    /// `Vec<ConfigTierKind>` is at most four elements long regardless
    /// of leaf count.
    #[must_use]
    pub fn absent_tiers(&self) -> Vec<ConfigTierKind> {
        self.tier_histogram().unobserved().collect()
    }

    /// The tier whose overlay produced the greatest number of surviving
    /// effective leaves on this resolved fold — the modal cell of
    /// [`Self::tier_histogram`] on the tier altitude. `None` exactly
    /// when the map is empty (no leaf contributed).
    ///
    /// Routes through [`Self::tier_histogram`]:
    /// [`crate::AxisHistogram::dominant_cell`] picks the argmax cell in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`ConfigTier`] precedence order by construction — the closed-
    /// axis discipline provides deterministic tie-breaking automatically,
    /// so this method reads directly off the shikumi cube-native
    /// primitive instead of hand-rolling
    /// `hist.iter().filter(|&(_, c)| c > 0).max_by_key(|&(_, c)| c).map(|(v, _)| v)`
    /// — the inline `max_by_key` form silently picks the *last* tied
    /// cell (per [`Iterator::max_by_key`]'s contract), so two consumers
    /// reading "the dominant tier" off the same fold would disagree
    /// under ties unless every one carefully reversed the comparison.
    /// The lift names the scalar at one site with a documented
    /// tie-breaking rule.
    ///
    /// The tier-altitude scalar-mode peer of [`Self::contributing_tiers`]
    /// (the observed-cells vector peer) and [`Self::absent_tiers`] (the
    /// coverage-gap vector peer): the histogram surface now carries the
    /// natural triple of "*which* tiers surfaced" / "*which* tiers
    /// didn't" / "*which single* tier dominated" projections at the tier
    /// altitude, each a named seam over the shared
    /// [`Self::tier_histogram`] primitive. Operator-facing consumers
    /// answering *"which tier dominated this resolved fold?"* — the
    /// fleet dashboard headlining *"Default tier owns 47 of 53 leaves
    /// this rebuild window"*, the attestation manifest recording the
    /// modal tier of a resolved fold, the diagnostic dump reading *"tier
    /// dominance: Discovered"* to explain why a runtime signal is
    /// steering the resolution — now route through this named seam
    /// instead of a per-consumer `max_by_key` walk.
    ///
    /// **Tie-breaking is deterministic by precedence order.** When
    /// multiple tiers share the maximum leaf count, the tier earliest
    /// in [`ConfigTierKind::ALL`] wins — the same [`ConfigTier`]
    /// precedence order [`Self::contributing_tiers`] and
    /// [`Self::absent_tiers`] walk. A uniform-cover fold (each tier
    /// producing the same nonzero leaf count) therefore reports
    /// `Some(ConfigTierKind::Bare)` — the first cell in declaration
    /// order — pointwise stable regardless of the insertion order of
    /// individual leaves into the underlying [`BTreeMap`].
    ///
    /// # Invariants
    ///
    /// - `dominant_tier().is_some() == !is_empty()` — the dominant tier
    ///   is defined exactly when the fold has at least one leaf. Peer
    ///   to the [`Self::is_empty`] boundary [`Self::contributing_tiers`]
    ///   and [`Self::absent_tiers`] both witness.
    /// - `dominant_tier() == tier_histogram().dominant_cell()` — both
    ///   project the same modal cell off the same primitive; the named
    ///   seam is the cube-native routing of the histogram surface.
    /// - When `Some(t)`, `t` is a member of `contributing_tiers()` —
    ///   the modal cell is by definition observed. Pinned by
    ///   `dominant_tier_is_member_of_contributing_tiers`.
    /// - When `Some(t)`, `t` is **not** a member of `absent_tiers()` —
    ///   the observed / coverage-gap partition is disjoint. Pinned by
    ///   `dominant_tier_is_not_member_of_absent_tiers`.
    /// - `tier_histogram().count(dominant_tier().unwrap()) ==
    ///   tier_histogram().peak_count()` whenever the map is non-empty —
    ///   the modal cell carries the peak observation count. Peer to
    ///   the (`dominant_cell`, `peak_count`) modal pair invariant on
    ///   [`crate::AxisHistogram`].
    /// - `dominant_tier()` on a uniform per-tier fold (one leaf per
    ///   tier) equals `Some(ConfigTierKind::Bare)` — declaration-order
    ///   tie-breaking on the four-cell axis picks the first cell.
    /// - `dominant_tier()` on an empty [`ProvenanceMap`] equals `None`
    ///   — the empty-map / empty-histogram boundary.
    ///
    /// # Cost
    ///
    /// `O(n + k)` where `n = self.inner.len()` (the histogram build)
    /// and `k = crate::axis_cardinality::<ConfigTierKind>()` (the
    /// argmax scan). Both are `O(n)` in practice since the tier axis
    /// carries a fixed four-cell cardinality; the returned
    /// `Option<ConfigTierKind>` reads one cell.
    #[must_use]
    pub fn dominant_tier(&self) -> Option<ConfigTierKind> {
        self.tier_histogram().dominant_cell()
    }
}

/// Zero-allocation `(&[String], &Provenance)` stream over the sorted
/// leaves of a [`ProvenanceMap`], lexicographic by path.
///
/// The concrete return type of [`ProvenanceMap::entries`]. Naming the
/// handle at the API boundary (rather than
/// `impl Iterator<Item = (&[String], &Provenance)> + '_`) exposes the
/// full trait algebra the underlying [`BTreeMap`]-backed walker
/// structurally carries — [`DoubleEndedIterator`],
/// [`ExactSizeIterator`], [`std::iter::FusedIterator`], and
/// [`Clone`] — and lets consumers hold the handle in a struct field or
/// return it up through their own API without smuggling an unnameable
/// [`impl Trait`][impl-trait] across every seam. Closes the last
/// `impl Iterator`-returning surface on `tiered.rs`, matching the
/// concrete-return invariant every free-function iter dual on
/// `discovered.rs` (whole-layer: [`crate::ContributorNamesIter`],
/// [`crate::LayerNamesIter`], [`crate::SilentLayerNamesIter`],
/// [`crate::NonemptyLayerDictsIter`]; point-restricted:
/// [`crate::ContributorsAtIter`], [`crate::SilencedAtIter`]) already
/// carries.
///
/// [impl-trait]: https://doc.rust-lang.org/reference/types/impl-trait.html
///
/// # Trait algebra
///
/// Impls [`Iterator`] + [`DoubleEndedIterator`] +
/// [`ExactSizeIterator`] + [`std::iter::FusedIterator`] + [`Clone`] +
/// [`Debug`][std::fmt::Debug]. The underlying
/// [`std::collections::btree_map::Iter`] carries the same trait algebra
/// on any `(Vec<String>, Provenance)` map, so this newtype forwards
/// each impl seam-for-seam with the projection
/// `(&Vec<String>, &Provenance) → (&[String], &Provenance)` (via
/// [`Vec::as_slice`]) applied at every `.next()` / `.next_back()`
/// pull. The projection preserves element count, so
/// [`ExactSizeIterator`] survives at the type level — the tier-level
/// peer of [`crate::discovered::LayerAttribution::iter`]'s
/// [`crate::LayerAttributionIter`] concrete handle.
///
/// # Field access
///
/// The struct fields are private — the public surface is the
/// `Iterator` / `DoubleEndedIterator` / `ExactSizeIterator` /
/// `FusedIterator` / `Clone` trait impls plus the
/// [`Debug`][std::fmt::Debug] derive.
#[derive(Clone, Debug)]
pub struct ProvenanceMapEntries<'a> {
    inner: std::collections::btree_map::Iter<'a, Vec<String>, Provenance>,
}

impl<'a> Iterator for ProvenanceMapEntries<'a> {
    type Item = (&'a [String], &'a Provenance);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k.as_slice(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for ProvenanceMapEntries<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(k, v)| (k.as_slice(), v))
    }
}

impl ExactSizeIterator for ProvenanceMapEntries<'_> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl std::iter::FusedIterator for ProvenanceMapEntries<'_> {}

/// `for entry in &map` (by-reference) iterates the same borrowed
/// `(&[String], &Provenance)` stream as [`ProvenanceMap::entries`], in
/// the same lex order. The idiomatic dual of the inherent
/// [`ProvenanceMap::entries`] getter — one seam every std collection
/// with an `iter()` method surfaces on its `&Self` reference
/// (`&Vec<T>`, `&BTreeMap<K, V>`, `&HashMap<K, V>`, `&[T]`) — closing
/// the shared idiom on the tiered algebra so consumers reach for the
/// `for`-loop form directly instead of the explicit `.entries()` call.
/// Zero-allocation: forwards to [`ProvenanceMap::entries`], which is
/// `O(1)` per element. Tier-level peer of the discovered-altitude
/// [`IntoIterator for &crate::discovered::LayerAttribution`] impl.
impl<'a> IntoIterator for &'a ProvenanceMap {
    type Item = (&'a [String], &'a Provenance);
    type IntoIter = ProvenanceMapEntries<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries()
    }
}

/// Consuming iterator over the owned `(Vec<String>, Provenance)` pairs
/// of a [`ProvenanceMap`], yielded in lex order on the path.
///
/// The concrete return type of
/// [`<ProvenanceMap as IntoIterator>::into_iter`][IntoIterator] and the
/// canonical Rust idiom-peer of
/// [`std::collections::btree_map::IntoIter`] /
/// [`std::vec::IntoIter`] — every stdlib keyed collection exposes a
/// named consuming iterator alongside the named borrowing iterator on
/// its `&Self` reference. The owned-ownership peer of the borrowing
/// [`ProvenanceMapEntries`] on the ownership boundary: where the
/// borrowing iterator yields `(&'a [String], &'a Provenance)` and lets
/// `self` outlive the walk, this consuming iterator yields
/// `(Vec<String>, Provenance)` and takes `self` with it — the natural
/// choice when the caller wants to move each owned key and provenance
/// elsewhere (e.g. `.into_iter().collect::<BTreeMap<_, _>>()`, an owned
/// `Vec<(Vec<String>, Provenance)>` audit dump, per-leaf
/// `FnMut(Vec<String>, Provenance)` visitor callbacks) without paying
/// an `.entries().map(|(p, prov)| (p.to_vec(), prov.clone()))`
/// intermediate clone per key.
///
/// The **consume-side dual** of the collect-side [`FromIterator`] impl:
/// `map.into_iter().collect::<ProvenanceMap>()` roundtrips through the
/// owned `(Vec<String>, Provenance)` shape and equals the source
/// verbatim, closing the ownership pair every std keyed collection
/// carries alongside its `FromIterator` (a `BTreeMap<K, V>` with
/// `IntoIterator` yielding `(K, V)` alongside its `FromIterator<(K,
/// V)>`, a `Vec<T>` with `IntoIterator` yielding `T` alongside its
/// `FromIterator<T>`). The tier-level peer of the discovered-altitude
/// [`crate::discovered::LayerAttributionIntoIter`] on the same
/// ownership boundary.
///
/// # Trait algebra
///
/// Impls [`Iterator`] + [`DoubleEndedIterator`] +
/// [`ExactSizeIterator`] + [`std::iter::FusedIterator`] +
/// [`Debug`][std::fmt::Debug]. [`Clone`] is *not* carried — the
/// underlying [`std::collections::btree_map::IntoIter`] consumes the
/// source [`BTreeMap`] and is not [`Clone`]-able. This matches the same
/// consuming/borrowing asymmetry
/// [`crate::discovered::LayerAttributionIntoIter`] carries on the
/// discovered algebra and every stdlib consuming iterator carries
/// against its borrowing peer.
///
/// # Field access
///
/// The struct field is private — the public surface is the
/// `Iterator` / `DoubleEndedIterator` / `ExactSizeIterator` /
/// `FusedIterator` trait impls plus the [`Debug`][std::fmt::Debug]
/// derive.
#[derive(Debug)]
pub struct ProvenanceMapIntoIter {
    inner: std::collections::btree_map::IntoIter<Vec<String>, Provenance>,
}

impl Iterator for ProvenanceMapIntoIter {
    type Item = (Vec<String>, Provenance);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }

    fn count(self) -> usize {
        self.inner.count()
    }

    fn last(mut self) -> Option<Self::Item> {
        // Override the default forward-walking `.last()` — the
        // DoubleEnded impl on the underlying `BTreeMap::IntoIter` finds
        // the trailing entry in `O(log n)` instead of draining the
        // whole iterator. Matches the same specialization
        // `LayerAttributionIntoIter::last` carries on the discovered
        // algebra's consuming surface.
        self.inner.next_back()
    }
}

impl DoubleEndedIterator for ProvenanceMapIntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl ExactSizeIterator for ProvenanceMapIntoIter {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl std::iter::FusedIterator for ProvenanceMapIntoIter {}

/// `for entry in map` (by-value) iterates the owned
/// `(Vec<String>, Provenance)` stream in the same lex order on the path
/// as [`ProvenanceMap::entries`] / [`IntoIterator for
/// &ProvenanceMap`][IntoIterator] — the consume-side dual of the
/// borrow-side [`IntoIterator for &ProvenanceMap`] impl above. One seam
/// every std keyed collection surfaces on its owned handle (`Vec<T>`,
/// `BTreeMap<K, V>`, `HashMap<K, V>`, `BTreeSet<T>`), closing the
/// ownership pair on the tiered algebra so consumers reach for the
/// by-value `for`-loop form directly (`for (path, prov) in map { … }`)
/// or `.into_iter().collect::<T>()` chains that move each owned path
/// and provenance into a caller-owned collection without the
/// `.entries().map(|(p, prov)| (p.to_vec(), prov.clone()))`
/// intermediate clone the borrowing form requires.
///
/// # Roundtrip with `FromIterator`
///
/// The pair with [`FromIterator for ProvenanceMap`] roundtrips
/// through the owned `(Vec<String>, Provenance)` shape:
///
/// ```text
/// let map: ProvenanceMap = ...;
/// let round: ProvenanceMap = map.clone().into_iter().collect();
/// assert_eq!(map, round);
/// ```
///
/// # Length
///
/// The returned [`ProvenanceMapIntoIter`] is [`ExactSizeIterator`],
/// so `.len()` returns [`ProvenanceMap::len`] verbatim in `O(1)` —
/// the trait-level parity of the borrowing [`ProvenanceMapEntries`] on
/// the consume-side surface.
impl IntoIterator for ProvenanceMap {
    type Item = (Vec<String>, Provenance);
    type IntoIter = ProvenanceMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        ProvenanceMapIntoIter {
            inner: self.inner.into_iter(),
        }
    }
}

/// Build a [`ProvenanceMap`] from a stream of `(path, provenance)`
/// pairs — the construction-side dual of [`IntoIterator for
/// &ProvenanceMap`] on the reading side. Every path–provenance pair
/// emitted by the source iterator becomes one attributed leaf; the
/// composed [`ProvenanceMap`] stores them in lex order on the owned
/// `Vec<String>` key, the same order [`ProvenanceMap::entries`] emits.
///
/// One seam every std keyed collection with an [`IntoIterator for
/// &Self`] getter surfaces on the ownership boundary
/// ([`FromIterator`][std::iter::FromIterator] on
/// [`BTreeMap`][std::collections::BTreeMap] /
/// [`HashMap`][std::collections::HashMap], on [`Vec`], on
/// [`BTreeSet`][std::collections::BTreeSet]) — closing the shared
/// idiom on the tiered algebra so consumers reach for the `.collect()`
/// form directly instead of naming `ProvenanceMap { inner: ... }` at
/// every construction site. [`ProvenanceMap`]'s inner field stays
/// private; this trait is the substrate-owned build path — the
/// tier-level peer of
/// [`FromIterator for crate::discovered::LayerAttribution`] on the
/// discovered algebra.
///
/// # Roundtrip
///
/// The pair with [`IntoIterator for &ProvenanceMap`] roundtrips
/// through the owned `(Vec<String>, Provenance)` shape:
///
/// ```text
/// let map: ProvenanceMap = ...;
/// let round: ProvenanceMap = map.entries()
///     .map(|(p, prov)| (p.to_vec(), prov.clone()))
///     .collect();
/// assert_eq!(map, round);
/// ```
///
/// # Duplicate paths
///
/// The underlying [`BTreeMap`][std::collections::BTreeMap] insertion
/// discipline holds: repeated pairs at the same path resolve
/// *last-write wins*. An empty source produces
/// [`ProvenanceMap::default`][Default::default].
impl FromIterator<(Vec<String>, Provenance)> for ProvenanceMap {
    fn from_iter<I: IntoIterator<Item = (Vec<String>, Provenance)>>(iter: I) -> Self {
        ProvenanceMap {
            inner: iter.into_iter().collect(),
        }
    }
}

/// Extend a [`ProvenanceMap`] with additional `(path, provenance)`
/// pairs — the grow-in-place dual of [`FromIterator for ProvenanceMap`]
/// and the matching `Extend` impl every std keyed collection carries
/// alongside its `FromIterator` (on
/// [`BTreeMap`][std::collections::BTreeMap] /
/// [`HashMap`][std::collections::HashMap], on
/// [`BTreeSet`][std::collections::BTreeSet]). Every pair inserted keeps
/// the same lex order on the owned `Vec<String>` key
/// [`ProvenanceMap::entries`] emits — the tier-level peer of
/// [`Extend for crate::discovered::LayerAttribution`] on the
/// discovered algebra.
///
/// # Duplicate paths
///
/// Same last-write-wins discipline as [`FromIterator`][Self]: a pair at
/// an existing path replaces the prior attribution. An empty source
/// leaves `self` untouched.
///
/// # Cost
///
/// Forwards to [`BTreeMap::extend`][std::collections::BTreeMap], which
/// is `O(m log(n + m))` where `n` is the current leaf count and `m`
/// the pairs supplied — the same amortized insertion cost every
/// consumer pays by constructing a fresh [`ProvenanceMap`] via
/// [`FromIterator`][Self] and merging by hand.
impl Extend<(Vec<String>, Provenance)> for ProvenanceMap {
    fn extend<I: IntoIterator<Item = (Vec<String>, Provenance)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// ── ProgressiveLayer — one operator overlay in the progressive fold ──

/// One operator overlay contribution to
/// [`TieredConfig::resolve_progressive_with`]: a partial config [`Dict`]
/// tagged with the [`Provenance`] to stamp on every leaf it wins.
///
/// Typically built from the operator's file / env layer via
/// [`Self::file`] / [`Self::env`]; the fold appends it above the three
/// trait tiers and re-sorts by tier precedence, so a caller cannot place
/// an overlay out of precedence order.
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressiveLayer {
    provenance: Provenance,
    dict: Dict,
}

impl ProgressiveLayer {
    /// Construct an overlay from an explicit provenance + partial dict.
    #[must_use]
    pub fn new(provenance: Provenance, dict: Dict) -> Self {
        Self { provenance, dict }
    }

    /// An operator FILE overlay — [`Provenance::file`].
    #[must_use]
    pub fn file(path: impl Into<PathBuf>, dict: Dict) -> Self {
        Self {
            provenance: Provenance::file(path),
            dict,
        }
    }

    /// An operator ENV overlay — [`Provenance::env`].
    #[must_use]
    pub fn env(prefix: impl Into<String>, dict: Dict) -> Self {
        Self {
            provenance: Provenance::env(prefix),
            dict,
        }
    }

    /// The provenance stamped on every leaf this overlay wins.
    #[must_use]
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The partial config dict this overlay contributes.
    #[must_use]
    pub fn dict(&self) -> &Dict {
        &self.dict
    }
}

// ── ProgressiveResolution — the (value, provenance) pair the fold returns ──

/// The atomic result of [`TieredConfig::resolve_progressive`]: the resolved
/// config `value` and the [`ProvenanceMap`] naming which tier produced each
/// effective leaf.
///
/// The two are co-constructed by the fold and returned together, so a
/// progressively-resolved value is never handed out without its provenance
/// — the (value, provenance) pair is atomic at this API boundary.
#[derive(Debug, Clone)]
pub struct ProgressiveResolution<T> {
    value: T,
    provenance: ProvenanceMap,
}

impl<T> ProgressiveResolution<T> {
    /// The resolved config value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The per-leaf provenance map.
    #[must_use]
    pub fn provenance(&self) -> &ProvenanceMap {
        &self.provenance
    }

    /// Consume, yielding the resolved value (dropping provenance).
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Consume, yielding both the value and its provenance map.
    #[must_use]
    pub fn into_parts(self) -> (T, ProvenanceMap) {
        (self.value, self.provenance)
    }
}

impl<T: PartialEq> PartialEq for ProgressiveResolution<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.provenance == other.provenance
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

    /// The distinct [`DiffLineKind`]s that appear as ≥1 line in this
    /// diff, in [`DiffLineKind::ALL`] declaration order — the
    /// diff-altitude dual of "which diff-cell kinds actually surfaced
    /// in this render".
    ///
    /// Routes through [`Self::kind_histogram`]:
    /// [`crate::AxisHistogram::observed`] iterates the histogram's
    /// support (the closed-axis cells with nonzero count) in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`DiffLineKind`] canonical order (`Removed → Added → Context`)
    /// by construction — the closed-axis discipline provides the sort
    /// + dedup automatically, so this method reads directly off the
    /// shikumi cube-native primitive instead of hand-rolling
    /// `Vec::contains` (`O(n·k)` in the line count and distinct-kind
    /// count) + explicit `sort_by_key(axis_ordinal)` at every operator-
    /// facing consumer.
    ///
    /// The diff-altitude peer of
    /// [`crate::ProvenanceMap::contributing_tiers`] on the tier
    /// altitude — both project the observed-support of the underlying
    /// [`crate::AxisHistogram`] over their local closed axis, both
    /// live as a `Vec<CellKind>` collect wrapper alongside their
    /// respective `_histogram()` primitives, and both spell the
    /// closed-axis declaration-order cell iteration at the API
    /// boundary.
    ///
    /// # Invariants
    ///
    /// - `present_kinds().len() ==
    ///   kind_histogram().distinct_cells()` — both project the same
    ///   support-cardinality off the histogram.
    /// - `present_kinds().is_empty() == self.lines.is_empty()` — a
    ///   diff with no lines has no present kinds; a diff with any
    ///   line has ≥1 present kind (every line projects to exactly
    ///   one kind, so the histogram support is nonempty iff the
    ///   line list is).
    /// - `!present_kinds().contains(&DiffLineKind::Added) &&
    ///   !present_kinds().contains(&DiffLineKind::Removed)` iff
    ///   [`Self::is_empty_diff`] returns `true` — the changed-cell
    ///   subset of the present set agrees with the structural-change
    ///   predicate over [`DiffLineKind::is_changed`].
    /// - `present_kinds()` is sorted strictly ascending by
    ///   [`crate::axis_ordinal`] on [`DiffLineKind`] — dedup + sort
    ///   for free from the closed-axis discipline.
    ///
    /// # Cost
    ///
    /// `O(n + k)` where `n = self.lines.len()` (the histogram build)
    /// and `k = crate::axis_cardinality::<DiffLineKind>()` (the
    /// support scan). Both are `O(n)` in practice since the diff-cell
    /// axis carries a fixed three-cell cardinality; the returned
    /// `Vec<DiffLineKind>` is at most three elements long regardless
    /// of line count.
    #[must_use]
    pub fn present_kinds(&self) -> Vec<DiffLineKind> {
        self.kind_histogram().observed().collect()
    }

    /// The distinct [`DiffLineKind`]s that appear as **zero** lines in
    /// this diff, in [`DiffLineKind::ALL`] declaration order — the
    /// coverage-gap peer of [`Self::present_kinds`] and the diff-altitude
    /// dual of [`crate::ProvenanceMap::absent_tiers`] on the tier altitude.
    ///
    /// Routes through [`Self::kind_histogram`]:
    /// [`crate::AxisHistogram::unobserved`] iterates the histogram's
    /// **coverage gap** (the closed-axis cells with zero count) in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`DiffLineKind`] canonical order (`Removed → Added → Context`) by
    /// construction — the closed-axis discipline provides the sort +
    /// dedup automatically, so this method reads directly off the shikumi
    /// cube-native primitive instead of hand-rolling
    /// `DiffLineKind::ALL.iter().filter(|k| !self.present_kinds().
    /// contains(k))` (`O(k·k)` in axis-cardinality, quadratic on the
    /// observed side) at every operator-facing consumer asking *"which
    /// diff-cell kinds are absent from this render?"* — the CLI
    /// `config-diff` summary reading *"no removals; nothing to warn
    /// on"*, the attestation manifest recording the diff-cell coverage
    /// gap between two tiers, the alerting policy suppressing per-kind
    /// bins that never fired for this rebuild window.
    ///
    /// The observed-cells peer ([`Self::present_kinds`]) and the
    /// coverage-gap peer ([`Self::absent_kinds`]) together form the
    /// **support / coverage-gap partition** on the diff altitude — every
    /// cell of [`DiffLineKind::ALL`] lies in exactly one of the two, and
    /// the two `Vec<DiffLineKind>` lengths sum to
    /// [`crate::axis_cardinality::<DiffLineKind>()`][crate::axis_cardinality].
    /// The diff-altitude dual of the tier-altitude
    /// [`crate::ProvenanceMap::absent_tiers`] unobserved-cells peer (whose
    /// observed-cells peer is [`crate::ProvenanceMap::contributing_tiers`])
    /// — every altitude of the shikumi typescape now closes both halves
    /// of the histogram's observed / unobserved partition at one named
    /// `Vec<CellKind>` seam alongside the underlying `_histogram()`
    /// primitive.
    ///
    /// # Invariants
    ///
    /// - `absent_kinds().len() == kind_histogram().unobserved_cells()` —
    ///   both project the same coverage-gap cardinality off the
    ///   histogram.
    /// - `present_kinds().len() + absent_kinds().len() ==
    ///   crate::axis_cardinality::<DiffLineKind>()` — the two peers
    ///   partition the closed axis without remainder (every cell is
    ///   either observed or unobserved, never both).
    /// - `present_kinds()` and `absent_kinds()` are disjoint: no
    ///   [`DiffLineKind`] appears in both.
    /// - `absent_kinds().is_empty() == kind_histogram().is_full_cover()`
    ///   — the coverage-gap is empty iff every diff-cell kind was
    ///   observed at least once (all three of Removed / Added / Context
    ///   appear as ≥1 line).
    /// - `absent_kinds()` on an empty [`ConfigDiff`] (no lines) equals
    ///   [`DiffLineKind::ALL`] — every kind is absent when no line
    ///   contributed, the empty-diff / full-coverage-gap boundary.
    /// - `absent_kinds()` is sorted strictly ascending by
    ///   [`crate::axis_ordinal`] on [`DiffLineKind`] — dedup + sort for
    ///   free from the closed-axis discipline.
    ///
    /// # Cost
    ///
    /// `O(n + k)` where `n = self.lines.len()` (the histogram build)
    /// and `k = crate::axis_cardinality::<DiffLineKind>()` (the
    /// coverage-gap scan). Both are `O(n)` in practice since the
    /// diff-cell axis carries a fixed three-cell cardinality; the
    /// returned `Vec<DiffLineKind>` is at most three elements long
    /// regardless of line count.
    #[must_use]
    pub fn absent_kinds(&self) -> Vec<DiffLineKind> {
        self.kind_histogram().unobserved().collect()
    }

    /// The [`DiffLineKind`] whose lines dominate this diff by count —
    /// the modal cell of [`Self::kind_histogram`] on the diff altitude.
    /// `None` exactly when the diff is empty (no lines).
    ///
    /// Routes through [`Self::kind_histogram`]:
    /// [`crate::AxisHistogram::dominant_cell`] picks the argmax cell in
    /// [`crate::ClosedAxis::ALL`] declaration order, which is the
    /// [`DiffLineKind`] canonical order (`Removed → Added → Context`)
    /// by construction — the closed-axis discipline provides deterministic
    /// tie-breaking automatically, so this method reads directly off the
    /// shikumi cube-native primitive instead of hand-rolling
    /// `hist.iter().filter(|&(_, c)| c > 0).max_by_key(|&(_, c)| c).map(|(v, _)| v)`
    /// — the inline `max_by_key` form silently picks the *last* tied
    /// cell (per [`Iterator::max_by_key`]'s contract), so two consumers
    /// reading "the dominant diff kind" off the same diff would disagree
    /// under ties unless every one carefully reversed the comparison.
    /// The lift names the scalar at one site with a documented
    /// tie-breaking rule.
    ///
    /// The diff-altitude scalar-mode peer of [`Self::present_kinds`]
    /// (the observed-cells vector peer) and [`Self::absent_kinds`] (the
    /// coverage-gap vector peer): the histogram surface at the diff
    /// altitude now carries the natural triple of "*which* diff kinds
    /// surfaced" / "*which* diff kinds didn't" / "*which single* diff
    /// kind dominated" projections, each a named seam over the shared
    /// [`Self::kind_histogram`] primitive. The diff-altitude dual of
    /// [`crate::ProvenanceMap::dominant_tier`] on the tier altitude —
    /// both project the modal cell of their local closed-axis histogram
    /// off the shared [`crate::AxisHistogram::dominant_cell`] primitive,
    /// both live as an `Option<CellKind>` scalar alongside the observed-
    /// cells / coverage-gap vector peers.
    ///
    /// Operator-facing consumers answering *"which diff-cell kind
    /// dominated this render?"* — the CLI `config-diff` summary
    /// headlining *"Context lines dominate: 47 of 53"*, the attestation
    /// manifest recording the modal diff-cell kind between two tiers,
    /// the alerting policy reading *"diff dominance: Added"* to flag a
    /// rebuild window where net-new lines swamp the changed set — now
    /// route through this named seam instead of a per-consumer
    /// `max_by_key` walk.
    ///
    /// **Tie-breaking is deterministic by declaration order.** When
    /// multiple diff-cell kinds share the maximum line count, the kind
    /// earliest in [`DiffLineKind::ALL`] wins (`Removed → Added →
    /// Context`) — the same order [`Self::present_kinds`] and
    /// [`Self::absent_kinds`] walk. A uniform-cover diff (each kind
    /// producing the same nonzero line count) therefore reports
    /// `Some(DiffLineKind::Removed)` — the first cell in declaration
    /// order — pointwise stable regardless of the insertion order of
    /// individual lines into [`Self::lines`].
    ///
    /// # Invariants
    ///
    /// - `dominant_kind().is_some() == !self.lines.is_empty()` — the
    ///   dominant kind is defined exactly when the diff has at least one
    ///   line. Peer to the `is_empty` boundary [`Self::present_kinds`]
    ///   and [`Self::absent_kinds`] both witness.
    /// - `dominant_kind() == kind_histogram().dominant_cell()` — both
    ///   project the same modal cell off the same primitive; the named
    ///   seam is the cube-native routing of the histogram surface.
    /// - When `Some(k)`, `k` is a member of `present_kinds()` — the
    ///   modal cell is by definition observed.
    /// - When `Some(k)`, `k` is **not** a member of `absent_kinds()` —
    ///   the observed / coverage-gap partition is disjoint.
    /// - `kind_histogram().count(dominant_kind().unwrap()) ==
    ///   kind_histogram().peak_count()` whenever the diff is non-empty —
    ///   the modal cell carries the peak observation count. Peer to
    ///   the (`dominant_cell`, `peak_count`) modal pair invariant on
    ///   [`crate::AxisHistogram`].
    /// - `dominant_kind()` on a uniform per-kind diff (one line per kind)
    ///   equals `Some(DiffLineKind::Removed)` — declaration-order
    ///   tie-breaking on the three-cell axis picks the first cell.
    /// - `dominant_kind()` on an empty [`ConfigDiff`] equals `None` —
    ///   the empty-diff / empty-histogram boundary.
    ///
    /// # Cost
    ///
    /// `O(n + k)` where `n = self.lines.len()` (the histogram build) and
    /// `k = crate::axis_cardinality::<DiffLineKind>()` (the argmax scan).
    /// Both are `O(n)` in practice since the diff-cell axis carries a
    /// fixed three-cell cardinality; the returned
    /// `Option<DiffLineKind>` reads one cell.
    #[must_use]
    pub fn dominant_kind(&self) -> Option<DiffLineKind> {
        self.kind_histogram().dominant_cell()
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

    // ── ConfigDiff::present_kinds — observed-cells peer of
    //    ProvenanceMap::contributing_tiers on the diff altitude ──

    #[test]
    fn present_kinds_matches_kind_histogram_observed_pointwise() {
        // The observed-support pin: `present_kinds` routes through
        // `kind_histogram().observed().collect()`, so the two seams
        // must stay pointwise equivalent under every fixture. Catches
        // any future drift where either implementation stops projecting
        // through the shared cube-native primitive.
        let fixtures: [ConfigDiff; 4] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r1".into()),
                    DiffLine::Added("a1".into()),
                    DiffLine::Added("a2".into()),
                    DiffLine::Context("c1".into()),
                    DiffLine::Context("c2".into()),
                    DiffLine::Context("c3".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Removed("r".into())],
            },
        ];
        for diff in fixtures {
            let via_direct = diff.present_kinds();
            let via_histogram: Vec<DiffLineKind> = diff.kind_histogram().observed().collect();
            assert_eq!(
                via_direct, via_histogram,
                "present_kinds must equal kind_histogram().observed().collect() pointwise",
            );
        }
    }

    #[test]
    fn present_kinds_empty_diff_is_empty() {
        // The empty-boundary invariant: a diff with no lines has no
        // present kinds; a diff with any line has ≥1 present kind
        // (every line projects to exactly one kind). Peer of the same
        // empty-boundary pin on `ProvenanceMap::contributing_tiers`
        // and on `ConfigDiff::kind_histogram`.
        let empty = ConfigDiff::default();
        assert!(empty.lines.is_empty());
        assert!(empty.present_kinds().is_empty());
        assert_eq!(empty.present_kinds(), Vec::<DiffLineKind>::new());

        let one_line = ConfigDiff {
            lines: vec![DiffLine::Context("x".into())],
        };
        assert!(!one_line.lines.is_empty());
        assert!(!one_line.present_kinds().is_empty());
    }

    #[test]
    fn present_kinds_iterates_in_declaration_order() {
        // Declaration-order pin: even when the observation order is
        // Context → Added → Removed (the reverse of ::ALL), the
        // returned Vec walks the closed axis in canonical
        // (Removed → Added → Context) order — the closed-axis
        // discipline provides the sort automatically.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Context("c".into()),
                DiffLine::Added("a".into()),
                DiffLine::Removed("r".into()),
            ],
        };
        assert_eq!(
            diff.present_kinds(),
            vec![
                DiffLineKind::Removed,
                DiffLineKind::Added,
                DiffLineKind::Context,
            ],
        );
    }

    #[test]
    fn present_kinds_dedups_across_repeated_observations() {
        // Repeated observations of the same kind collapse to one entry
        // in the returned Vec — the closed-axis discipline provides
        // dedup automatically. Six lines split (2 removed × 3 added ×
        // 1 context) yield three present kinds.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r1".into()),
                DiffLine::Removed("r2".into()),
                DiffLine::Added("a1".into()),
                DiffLine::Added("a2".into()),
                DiffLine::Added("a3".into()),
                DiffLine::Context("c1".into()),
            ],
        };
        assert_eq!(
            diff.present_kinds(),
            vec![
                DiffLineKind::Removed,
                DiffLineKind::Added,
                DiffLineKind::Context,
            ],
        );
    }

    #[test]
    fn present_kinds_context_only_diff_yields_context() {
        // A diff composed only of context lines has exactly Context
        // as its present-kinds set — the changed-cell subset is
        // empty, and `is_empty_diff` returns true concurrently.
        let ctx_only = ConfigDiff {
            lines: vec![
                DiffLine::Context("a".into()),
                DiffLine::Context("b".into()),
                DiffLine::Context("c".into()),
            ],
        };
        assert_eq!(ctx_only.present_kinds(), vec![DiffLineKind::Context]);
        assert!(ctx_only.is_empty_diff());
    }

    #[test]
    fn present_kinds_distinct_cells_matches_histogram() {
        // The support-cardinality invariant: `present_kinds().len()`
        // equals `kind_histogram().distinct_cells()` pointwise. Both
        // project the observed-cell count off the shared histogram
        // over the DiffLineKind closed axis. Peer of the same
        // invariant on `ProvenanceMap::tier_histogram().distinct_cells()
        // == contributing_tiers().len()`.
        let fixtures: [ConfigDiff; 4] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
        ];
        for diff in fixtures {
            assert_eq!(
                diff.present_kinds().len(),
                diff.kind_histogram().distinct_cells(),
                "present_kinds().len() must equal kind_histogram().distinct_cells()",
            );
        }
    }

    #[test]
    fn present_kinds_changed_subset_agrees_with_is_empty_diff() {
        // Cross-primitive law: the changed-cell subset of
        // `present_kinds()` (Added ∪ Removed) is empty iff
        // `is_empty_diff` returns true. Both surfaces project the
        // same partition over the DiffLineKind axis (`is_changed`),
        // so the agreement is structural.
        let context_only = ConfigDiff {
            lines: vec![DiffLine::Context("c".into())],
        };
        assert!(context_only.is_empty_diff());
        let changed_in_ctx_only: Vec<DiffLineKind> = context_only
            .present_kinds()
            .into_iter()
            .filter(|k| k.is_changed())
            .collect();
        assert!(changed_in_ctx_only.is_empty());

        let with_change = ConfigDiff {
            lines: vec![DiffLine::Context("c".into()), DiffLine::Added("a".into())],
        };
        assert!(!with_change.is_empty_diff());
        let changed_in_mixed: Vec<DiffLineKind> = with_change
            .present_kinds()
            .into_iter()
            .filter(|k| k.is_changed())
            .collect();
        assert!(!changed_in_mixed.is_empty());
        assert!(changed_in_mixed.contains(&DiffLineKind::Added));
    }

    #[test]
    fn present_kinds_is_strictly_ascending_by_axis_ordinal() {
        // Structural-sort pin: the returned Vec is strictly ascending
        // by `crate::axis_ordinal` on DiffLineKind — dedup + sort for
        // free from the closed-axis discipline. Every consecutive pair
        // in the returned Vec has strictly increasing axis ordinal.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Context("c".into()),
                DiffLine::Removed("r".into()),
                DiffLine::Context("c2".into()),
                DiffLine::Added("a".into()),
                DiffLine::Removed("r2".into()),
            ],
        };
        let present = diff.present_kinds();
        for window in present.windows(2) {
            let a = crate::axis_ordinal(window[0]);
            let b = crate::axis_ordinal(window[1]);
            assert!(
                a < b,
                "present_kinds must be strictly ascending by axis_ordinal, \
                 but ord({:?})={a} >= ord({:?})={b}",
                window[0],
                window[1],
            );
        }
    }

    // ── ConfigDiff::absent_kinds — unobserved-cells peer of
    //    present_kinds on the diff altitude ──

    #[test]
    fn absent_kinds_matches_kind_histogram_unobserved_pointwise() {
        // The coverage-gap pin: `absent_kinds` routes through
        // `kind_histogram().unobserved().collect()`, so the two seams
        // must stay pointwise equivalent under every fixture. Catches
        // any future drift where either implementation stops projecting
        // through the shared cube-native primitive. Diff-altitude peer
        // of `absent_tiers_matches_tier_histogram_unobserved_pointwise`
        // on the tier altitude.
        let fixtures: [ConfigDiff; 4] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r1".into()),
                    DiffLine::Added("a1".into()),
                    DiffLine::Added("a2".into()),
                    DiffLine::Context("c1".into()),
                    DiffLine::Context("c2".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Removed("r".into())],
            },
        ];
        for diff in fixtures {
            let via_direct = diff.absent_kinds();
            let via_histogram: Vec<DiffLineKind> = diff.kind_histogram().unobserved().collect();
            assert_eq!(
                via_direct, via_histogram,
                "absent_kinds must equal kind_histogram().unobserved().collect() pointwise",
            );
        }
    }

    #[test]
    fn absent_kinds_empty_diff_is_full_axis() {
        // A diff with no lines has no observed kinds — every cell of
        // `DiffLineKind::ALL` lies in the coverage gap. The empty-diff
        // / full-coverage-gap boundary of the observed / unobserved
        // partition, diff-altitude peer of `absent_tiers_empty_map_
        // is_full_axis` on the tier altitude.
        let empty = ConfigDiff::default();
        assert_eq!(empty.absent_kinds(), DiffLineKind::ALL.to_vec());
    }

    #[test]
    fn absent_kinds_iterates_in_declaration_order() {
        // The coverage-gap iter walks `DiffLineKind::ALL` in
        // declaration order (`Removed → Added → Context`) and yields
        // only the cells with zero count. Pinned here on the empty
        // diff, whose gap is the entire axis — the emitted order
        // matches `DiffLineKind::ALL` verbatim.
        let empty = ConfigDiff::default();
        assert_eq!(
            empty.absent_kinds(),
            vec![
                DiffLineKind::Removed,
                DiffLineKind::Added,
                DiffLineKind::Context,
            ],
        );
    }

    #[test]
    fn absent_kinds_context_only_diff_is_added_and_removed() {
        // A diff composed only of Context lines has exactly
        // { Added, Removed } as its coverage gap — the changed-cell
        // subset of the axis is entirely absent, and `is_empty_diff`
        // returns true concurrently. Operator-facing pin on the
        // "nothing changed; only Context lines" render.
        let ctx_only = ConfigDiff {
            lines: vec![
                DiffLine::Context("a".into()),
                DiffLine::Context("b".into()),
                DiffLine::Context("c".into()),
            ],
        };
        assert_eq!(
            ctx_only.absent_kinds(),
            vec![DiffLineKind::Removed, DiffLineKind::Added],
        );
        assert!(ctx_only.is_empty_diff());
    }

    #[test]
    fn absent_kinds_len_matches_unobserved_cells() {
        // The coverage-gap-cardinality invariant on the histogram's
        // support / gap partition: `absent_kinds().len()` equals
        // `kind_histogram().unobserved_cells()` pointwise across every
        // fixture. Any future re-implementation of either seam must
        // keep this equality.
        let fixtures: [ConfigDiff; 5] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Added("b".into())],
            },
        ];
        for diff in fixtures {
            assert_eq!(
                diff.absent_kinds().len(),
                diff.kind_histogram().unobserved_cells(),
                "absent_kinds().len() must equal kind_histogram().unobserved_cells()",
            );
        }
    }

    #[test]
    fn absent_kinds_and_present_kinds_partition_axis() {
        // The support / coverage-gap partition on the closed axis:
        // every cell of `DiffLineKind::ALL` lies in exactly one of
        // (observed, unobserved), so the two Vec lengths sum to the
        // axis cardinality. Diff-altitude peer of
        // `absent_tiers_and_contributing_tiers_partition_axis` on the
        // tier altitude.
        let axis_size = crate::axis_cardinality::<DiffLineKind>();
        let fixtures: [ConfigDiff; 5] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Added("b".into())],
            },
        ];
        for diff in fixtures {
            let observed = diff.present_kinds();
            let absent = diff.absent_kinds();
            assert_eq!(observed.len() + absent.len(), axis_size);
            for kind in &observed {
                assert!(
                    !absent.contains(kind),
                    "kind {kind:?} appears in both present and absent",
                );
            }
            for cell in DiffLineKind::ALL {
                assert!(
                    observed.contains(cell) || absent.contains(cell),
                    "kind {cell:?} appears in neither present nor absent",
                );
            }
        }
    }

    #[test]
    fn absent_kinds_is_empty_iff_is_full_cover() {
        // The coverage-gap is empty iff every diff-cell kind was
        // observed at least once. Pinned across every fixture in the
        // module against `kind_histogram().is_full_cover()`, plus a
        // direct positive pin: a diff carrying one Removed, one Added,
        // and one Context is full-cover; the coverage-gap is empty.
        let fixtures: [ConfigDiff; 5] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Added("b".into())],
            },
        ];
        for diff in fixtures {
            assert_eq!(
                diff.absent_kinds().is_empty(),
                diff.kind_histogram().is_full_cover(),
            );
        }
        let full_cover = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r".into()),
                DiffLine::Added("a".into()),
                DiffLine::Context("c".into()),
            ],
        };
        assert!(full_cover.kind_histogram().is_full_cover());
        assert_eq!(full_cover.absent_kinds(), Vec::<DiffLineKind>::new());
        assert_eq!(full_cover.present_kinds(), DiffLineKind::ALL.to_vec());
    }

    #[test]
    fn absent_kinds_is_strictly_ascending_by_axis_ordinal() {
        // Structural sort pin: the coverage-gap walks the closed axis
        // in declaration order, so `absent_kinds()` is strictly
        // ascending by `crate::axis_ordinal` — the dedup + sort every
        // hand-rolled walk would have to spell explicitly comes for
        // free from the closed-axis discipline.
        let fixtures: [ConfigDiff; 5] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Added("b".into())],
            },
        ];
        for diff in fixtures {
            let absent = diff.absent_kinds();
            for pair in absent.windows(2) {
                assert!(
                    crate::axis_ordinal(pair[0]) < crate::axis_ordinal(pair[1]),
                    "absent_kinds must be strictly ascending: {absent:?}",
                );
            }
        }
    }

    #[test]
    fn absent_kinds_full_cover_yields_empty() {
        // The full-cover positive case: a diff containing ≥1 line of
        // every DiffLineKind has an empty coverage gap. Symmetrically,
        // the observed peer equals `DiffLineKind::ALL` (in declaration
        // order) at full cover.
        let full_cover = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r".into()),
                DiffLine::Added("a".into()),
                DiffLine::Context("c".into()),
            ],
        };
        assert!(full_cover.kind_histogram().is_full_cover());
        assert_eq!(full_cover.absent_kinds(), Vec::<DiffLineKind>::new());
        assert_eq!(full_cover.present_kinds(), DiffLineKind::ALL.to_vec());
    }

    #[test]
    fn absent_kinds_singleton_diff_yields_two_absent() {
        // A diff of a single line has exactly `axis_cardinality - 1`
        // absent kinds — every axis cell except the one carried by that
        // line. Cross-verified against `present_kinds().len() +
        // absent_kinds().len() == axis_cardinality`. Diff-altitude
        // peer of the singleton pins on the chain-altitude present/
        // absent seams.
        let axis_size = crate::axis_cardinality::<DiffLineKind>();
        for (line, present_kind) in [
            (DiffLine::Removed("r".into()), DiffLineKind::Removed),
            (DiffLine::Added("a".into()), DiffLineKind::Added),
            (DiffLine::Context("c".into()), DiffLineKind::Context),
        ] {
            let diff = ConfigDiff { lines: vec![line] };
            let absent = diff.absent_kinds();
            assert_eq!(absent.len(), axis_size - 1);
            assert!(
                !absent.contains(&present_kind),
                "the observed kind {present_kind:?} must not appear in the coverage gap",
            );
            for cell in DiffLineKind::ALL {
                if *cell != present_kind {
                    assert!(
                        absent.contains(cell),
                        "the singleton diff's coverage gap must contain \
                         every non-observed axis cell — missing {cell:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn absent_kinds_agrees_with_open_coded_coverage_gap_walk() {
        // Parity against the exact `DiffLineKind::ALL.iter().filter(|k|
        // !present_kinds().contains(k))` walk this lift replaces —
        // both the named seam and the hand-rolled coverage-gap must
        // pointwise agree over every fixture. Diff-altitude peer of
        // `absent_tiers_agrees_with_open_coded_coverage_gap_walk` on
        // the tier altitude.
        let fixtures: [ConfigDiff; 6] = [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into()), DiffLine::Added("b".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into())],
            },
        ];
        for diff in fixtures {
            let via_seam = diff.absent_kinds();
            let present = diff.present_kinds();
            let hand_rolled: Vec<DiffLineKind> = DiffLineKind::ALL
                .iter()
                .copied()
                .filter(|k| !present.contains(k))
                .collect();
            assert_eq!(via_seam, hand_rolled);
        }
    }

    // ── ConfigDiff::dominant_kind — modal-cell scalar peer on the diff altitude ──

    fn dominant_kind_fixtures() -> [ConfigDiff; 8] {
        [
            ConfigDiff::default(),
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Context("c".into())],
            },
            ConfigDiff {
                lines: vec![DiffLine::Removed("r".into()), DiffLine::Added("a".into())],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Removed("r".into()),
                    DiffLine::Added("a".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Added("a".into()),
                    DiffLine::Added("b".into()),
                    DiffLine::Context("c".into()),
                ],
            },
            ConfigDiff {
                lines: vec![
                    DiffLine::Context("c1".into()),
                    DiffLine::Context("c2".into()),
                    DiffLine::Context("c3".into()),
                    DiffLine::Removed("r".into()),
                ],
            },
        ]
    }

    #[test]
    fn dominant_kind_matches_kind_histogram_dominant_cell_pointwise() {
        // The modal-cell pin: `dominant_kind` routes through
        // `kind_histogram().dominant_cell()`, so the two seams must
        // stay pointwise equivalent under every fixture. Catches any
        // future drift where either implementation stops projecting
        // through the shared cube-native primitive. Diff-altitude peer
        // of `dominant_tier_matches_tier_histogram_dominant_cell_pointwise`
        // on the tier altitude.
        for diff in dominant_kind_fixtures() {
            let via_histogram = diff.kind_histogram().dominant_cell();
            assert_eq!(diff.dominant_kind(), via_histogram);
        }
    }

    #[test]
    fn dominant_kind_context_dominated_fixture_is_context() {
        // Direct pin: a diff of 3 Context + 1 Removed has Context
        // uniquely dominant with 3 of 4 lines. The named seam answers
        // the operator's *"which diff kind dominated this render?"*
        // question at one call, no `max_by_key` walk in the summary.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Context("c1".into()),
                DiffLine::Context("c2".into()),
                DiffLine::Context("c3".into()),
                DiffLine::Removed("r".into()),
            ],
        };
        assert_eq!(diff.dominant_kind(), Some(DiffLineKind::Context));
    }

    #[test]
    fn dominant_kind_added_dominated_fixture_is_added() {
        // Direct pin: a diff of 2 Added + 1 Context has Added uniquely
        // dominant with 2 of 3 lines. Cross-verified against the
        // per-kind count directly on the underlying histogram.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Added("a1".into()),
                DiffLine::Added("a2".into()),
                DiffLine::Context("c".into()),
            ],
        };
        assert_eq!(diff.dominant_kind(), Some(DiffLineKind::Added));
        let hist = diff.kind_histogram();
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.peak_count(), 2);
    }

    #[test]
    fn dominant_kind_empty_diff_is_none() {
        // An empty ConfigDiff has no lines and therefore no modal cell —
        // the empty-diff / empty-histogram boundary of the dominant-cell
        // projection. Diff-altitude peer of `dominant_tier_empty_map_is_none`
        // and the empty-diff boundary on the coverage-gap side
        // (`absent_kinds` returns `DiffLineKind::ALL`).
        let empty = ConfigDiff::default();
        assert_eq!(empty.dominant_kind(), None);
        assert!(empty.lines.is_empty());
    }

    #[test]
    fn dominant_kind_is_some_iff_diff_is_nonempty() {
        // Cross-surface pin: the presence-of-modal-cell predicate
        // agrees with the non-emptiness of `self.lines`. Structural
        // completeness of the `(is_empty, dominant_kind)` boundary — a
        // well-formed diff with ≥1 line always has a modal cell, and an
        // empty diff never does.
        for diff in dominant_kind_fixtures() {
            assert_eq!(diff.dominant_kind().is_some(), !diff.lines.is_empty());
        }
    }

    #[test]
    fn dominant_kind_is_member_of_present_kinds() {
        // Structural pin: whenever `dominant_kind()` is `Some(k)`, `k`
        // must appear in `present_kinds()` (the modal cell is by
        // definition observed). The support / dominance partition on
        // the diff altitude reads consistently between the two named
        // seams. Diff-altitude peer of
        // `dominant_tier_is_member_of_contributing_tiers`.
        for diff in dominant_kind_fixtures() {
            let Some(dominant) = diff.dominant_kind() else {
                continue;
            };
            assert!(
                diff.present_kinds().contains(&dominant),
                "dominant kind {dominant:?} must appear in present_kinds",
            );
        }
    }

    #[test]
    fn dominant_kind_is_not_member_of_absent_kinds() {
        // Structural pin: whenever `dominant_kind()` is `Some(k)`, `k`
        // must NOT appear in `absent_kinds()` — the modal cell lies on
        // the observed side of the observed / coverage-gap partition.
        // Disjointness pin between the two named seams. Diff-altitude
        // peer of `dominant_tier_is_not_member_of_absent_tiers`.
        for diff in dominant_kind_fixtures() {
            let Some(dominant) = diff.dominant_kind() else {
                continue;
            };
            assert!(
                !diff.absent_kinds().contains(&dominant),
                "dominant kind {dominant:?} must not appear in absent_kinds",
            );
        }
    }

    #[test]
    fn dominant_kind_count_equals_peak_count_on_nonempty_diff() {
        // The (dominant_cell, peak_count) modal-pair invariant lifted
        // to the diff altitude: the observation count of the dominant
        // kind equals the histogram's peak count. Pins the fused form
        // of the modal-pair the AxisHistogram surface carries as
        // (dominant_cell(), peak_count()).
        for diff in dominant_kind_fixtures() {
            let Some(dominant) = diff.dominant_kind() else {
                continue;
            };
            let hist = diff.kind_histogram();
            assert_eq!(hist.count(dominant), hist.peak_count());
        }
    }

    #[test]
    fn dominant_kind_ties_broken_by_declaration_order() {
        // Structural tie-breaking pin: on a uniform per-kind diff
        // (each of the three `DiffLineKind` cells contributing exactly
        // one line), `dominant_kind` reports `Some(DiffLineKind::Removed)`
        // — the first cell in `DiffLineKind::ALL` declaration order.
        // Any future switch to a nondeterministic `max_by_key` walk
        // (which silently picks the LAST tied cell) would flip this
        // pin to `Some(Context)` — the seam names the tiebreak once.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r".into()),
                DiffLine::Added("a".into()),
                DiffLine::Context("c".into()),
            ],
        };
        let hist = diff.kind_histogram();
        assert_eq!(hist.count(DiffLineKind::Removed), 1);
        assert_eq!(hist.count(DiffLineKind::Added), 1);
        assert_eq!(hist.count(DiffLineKind::Context), 1);
        assert!(hist.is_full_cover());
        // Tiebreak lands on the first cell in declaration order.
        assert_eq!(diff.dominant_kind(), Some(DiffLineKind::Removed));
    }

    #[test]
    fn dominant_kind_two_way_tie_picks_declaration_order_first() {
        // A two-way tie between Added and Context (2 each) with no
        // Removed lines must still resolve to the declaration-order
        // earliest cell — Added (which precedes Context in ALL) —
        // even though Removed has zero count. Distinguishes the
        // "first tied cell" tiebreak from a naive "first cell of ALL"
        // fallback.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Added("a1".into()),
                DiffLine::Added("a2".into()),
                DiffLine::Context("c1".into()),
                DiffLine::Context("c2".into()),
            ],
        };
        let hist = diff.kind_histogram();
        assert_eq!(hist.count(DiffLineKind::Removed), 0);
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.count(DiffLineKind::Context), 2);
        assert_eq!(diff.dominant_kind(), Some(DiffLineKind::Added));
    }

    #[test]
    fn dominant_kind_agrees_with_open_coded_argmax_walk() {
        // Parity against the exact `hist.iter().filter(|&(_, c)| c > 0)
        // .fold(count-then-declaration-order)` walk this lift replaces —
        // both the named seam and the hand-rolled argmax must
        // pointwise agree over every fixture. The hand-rolled form
        // spells the declaration-order tiebreak explicitly (fold-
        // forward with strict `>` inequality — the first tied cell
        // wins, mirroring `AxisHistogram::dominant_cell` — rather than
        // `max_by_key`'s LAST-tied-cell semantics). Diff-altitude peer
        // of `dominant_tier_agrees_with_open_coded_argmax_walk`.
        for diff in dominant_kind_fixtures() {
            let via_seam = diff.dominant_kind();
            let hist = diff.kind_histogram();
            let mut iter = hist.iter().filter(|&(_, c)| c > 0);
            let hand_rolled = iter.next().map(|first| {
                iter.fold(
                    first,
                    |best, current| {
                        if current.1 > best.1 { current } else { best }
                    },
                )
                .0
            });
            assert_eq!(via_seam, hand_rolled);
        }
    }

    #[test]
    fn dominant_kind_uniform_cover_picks_first_cell() {
        // Trait-uniform invariant: on a full-cover diff where every
        // kind observes the same nonzero count (2 each here), the
        // dominant cell is the first cell of `DiffLineKind::ALL` — the
        // declaration-order tiebreak reduces to `Some(Removed)`. Peer
        // of the trait-uniform
        // `axis_histogram_dominant_cell_axis_cover_picks_first_*` laws
        // in cube tests, and of
        // `dominant_tier_uniform_cover_picks_first_cell` on the tier
        // altitude.
        let diff = ConfigDiff {
            lines: vec![
                DiffLine::Removed("r1".into()),
                DiffLine::Removed("r2".into()),
                DiffLine::Added("a1".into()),
                DiffLine::Added("a2".into()),
                DiffLine::Context("c1".into()),
                DiffLine::Context("c2".into()),
            ],
        };
        assert!(diff.kind_histogram().is_full_cover());
        assert_eq!(diff.dominant_kind(), Some(DiffLineKind::Removed));
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

// ── Progressive-discovery fold + typed provenance coverage ──────────
#[cfg(test)]
mod progressive_tests {
    use super::*;
    use crate::ConfigSource;
    use figment::value::{Dict, Value};
    use serde::{Deserialize, Serialize};

    // A config where `discovered()` detects `a` + `d`, and
    // `prescribed_default()` is built ON discovered(): it re-emits `a`
    // unchanged, curates `b`, and overrides `d`. `c` never rises above the
    // bare floor. This is the canonical last-changer fixture.
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Prog {
        a: u32,
        b: u32,
        c: u32,
        d: u32,
    }

    impl TieredConfig for Prog {
        fn bare() -> Self {
            Self {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
            }
        }
        fn discovered() -> Self {
            Self {
                a: 10,
                b: 0,
                c: 0,
                d: 5,
            }
        }
        fn prescribed_default() -> Self {
            Self {
                a: 10,
                b: 20,
                c: 0,
                d: 7,
            }
        }
    }

    #[test]
    fn progressive_value_folds_all_tiers() {
        let r = Prog::resolve_progressive();
        assert_eq!(
            *r.value(),
            Prog {
                a: 10,
                b: 20,
                c: 0,
                d: 7
            }
        );
    }

    #[test]
    fn progressive_provenance_credits_each_leaf_to_its_producing_tier() {
        let r = Prog::resolve_progressive();
        let p = r.provenance();
        // a: detected at Discovered, re-emitted unchanged by prescribed → Discovered.
        assert_eq!(
            p.provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered
        );
        // b: curated at prescribed → Default.
        assert_eq!(
            p.provenance_of(&["b"]).unwrap().tier(),
            ConfigTierKind::Default
        );
        // c: never rose above the floor → Bare.
        assert_eq!(
            p.provenance_of(&["c"]).unwrap().tier(),
            ConfigTierKind::Bare
        );
        // d: detected 5 at Discovered, OVERRIDDEN to 7 at prescribed → Default.
        assert_eq!(
            p.provenance_of(&["d"]).unwrap().tier(),
            ConfigTierKind::Default
        );
    }

    #[test]
    fn progressive_discovery_shows_through_where_prescribed_does_not_override() {
        // The gap-2 seal: resolve_tier(Default) == prescribed_default() (no
        // discovery); resolve_progressive folds discovered() UNDER prescribed,
        // so a detected value survives where prescribed didn't touch it.
        let r = Prog::resolve_progressive();
        assert_eq!(r.value().a, 10, "discovered a=10 shows through");
        assert_eq!(
            r.provenance().provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered,
        );
        // The legacy single-tier path is unchanged.
        assert_eq!(
            Prog::resolve_tier(ConfigTier::Default),
            Prog::prescribed_default()
        );
    }

    #[test]
    fn progressive_provenance_is_complete_over_every_leaf() {
        let r = Prog::resolve_progressive();
        // Every field of the resolved config has a provenance entry (bare()
        // seeds every leaf) — completeness by construction of the fold.
        assert_eq!(r.provenance().len(), 4);
        for leaf in [["a"], ["b"], ["c"], ["d"]] {
            assert!(
                r.provenance().provenance_of(&leaf).is_some(),
                "leaf {leaf:?} must have provenance"
            );
        }
        assert!(!r.provenance().is_empty());
    }

    #[test]
    fn progressive_higher_tier_beats_lower_on_override() {
        // d: discovered=5, prescribed=7 → the higher tier's value wins.
        let r = Prog::resolve_progressive();
        assert_eq!(r.value().d, 7);
        assert_eq!(
            r.provenance().provenance_of(&["d"]).unwrap().tier(),
            ConfigTierKind::Default
        );
    }

    #[test]
    fn progressive_overlay_file_beats_prescribed_and_carries_file_provenance() {
        let mut d = Dict::new();
        d.insert("b".to_owned(), Value::from(99_u32));
        let r = Prog::resolve_progressive_with(&[ProgressiveLayer::file("/etc/prog.yaml", d)]);
        assert_eq!(r.value().b, 99, "file overlay beats prescribed b=20");
        let prov = r.provenance().provenance_of(&["b"]).unwrap();
        assert_eq!(prov.tier(), ConfigTierKind::Custom);
        assert_eq!(prov.source(), &ConfigSource::File("/etc/prog.yaml".into()));
        // a untouched by the overlay → still Discovered.
        assert_eq!(
            r.provenance().provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered
        );
    }

    #[test]
    fn progressive_fold_reorders_a_misordered_low_tier_overlay() {
        // A caller-supplied overlay carrying a LOW-tier provenance is sorted
        // to its tier rank BEFORE the fold, so it cannot beat a higher tier:
        // a Bare-tagged overlay setting a=999 lands below Discovered's a=10.
        let mut d = Dict::new();
        d.insert("a".to_owned(), Value::from(999_u32));
        let sneaky = ProgressiveLayer::new(
            Provenance::new(ConfigTierKind::Bare, ConfigSource::Defaults),
            d,
        );
        let r = Prog::resolve_progressive_with(&[sneaky]);
        assert_eq!(
            r.value().a,
            10,
            "a low-tier overlay cannot beat the Discovered tier"
        );
        assert_eq!(
            r.provenance().provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered
        );
    }

    #[test]
    fn progressive_contributing_tiers_in_precedence_order() {
        let r = Prog::resolve_progressive();
        // Bare (c), Discovered (a), Default (b, d) all survive.
        assert_eq!(
            r.provenance().contributing_tiers(),
            vec![
                ConfigTierKind::Bare,
                ConfigTierKind::Discovered,
                ConfigTierKind::Default
            ],
        );
    }

    #[test]
    fn progressive_entries_iterate_lexicographically() {
        let r = Prog::resolve_progressive();
        let paths: Vec<Vec<String>> = r.provenance().entries().map(|(p, _)| p.to_vec()).collect();
        assert_eq!(
            paths,
            vec![
                vec!["a".to_string()],
                vec!["b".to_string()],
                vec!["c".to_string()],
                vec!["d".to_string()],
            ],
        );
    }

    #[test]
    fn provenance_map_entries_return_type_is_nameable_provenance_map_entries() {
        // Pin the sharpen at the type-signature level: a struct field bound
        // on `ProvenanceMapEntries<'a>` holds the handle across a return.
        // This test compiles iff the sharpen holds; if `entries()` ever
        // regresses back to `impl Trait`, this ceases to compile because
        // `impl Trait` return types are unnameable at struct-field bounds.
        struct Held<'a> {
            walker: ProvenanceMapEntries<'a>,
        }
        fn hold(map: &ProvenanceMap) -> Held<'_> {
            Held {
                walker: map.entries(),
            }
        }
        let r = Prog::resolve_progressive();
        let mut h = hold(r.provenance());
        assert!(h.walker.next().is_some());
    }

    #[test]
    fn provenance_map_entries_clone_preserves_static_traits() {
        // A static bound accepting Iterator + DoubleEndedIterator +
        // ExactSizeIterator + FusedIterator + Clone verifies the full
        // trait algebra survives the sharpen at compile time — the
        // tier-level dual of the same triple-trait pair pinned on the
        // discovered-altitude siblings, with ExactSizeIterator added
        // because the projection preserves element count (unlike the
        // filtered discovered-side iters). Then a runtime cross-walk
        // asserts the cloned walker yields the same (path, provenance)
        // pair stream as the original.
        fn assert_algebra<'a, I>(_: &I)
        where
            I: Iterator<Item = (&'a [String], &'a Provenance)>
                + DoubleEndedIterator
                + ExactSizeIterator
                + std::iter::FusedIterator
                + Clone,
        {
        }
        let r = Prog::resolve_progressive();
        let it = r.provenance().entries();
        assert_algebra(&it);
        let cloned = it.clone();
        let a: Vec<Vec<String>> = it.map(|(p, _)| p.to_vec()).collect();
        let b: Vec<Vec<String>> = cloned.map(|(p, _)| p.to_vec()).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn provenance_map_entries_next_back_walks_specific_to_coarse() {
        // Pin the DoubleEndedIterator impl at the runtime level: the tail
        // cursor walks the sorted BTreeMap in reverse, yielding leaves
        // from lexicographically last to first. Catches a regression to
        // a single-ended state machine.
        let r = Prog::resolve_progressive();
        let mut it = r.provenance().entries();
        let (last, _) = it.next_back().unwrap();
        assert_eq!(last, &["d".to_string()][..]);
        let (before_last, _) = it.next_back().unwrap();
        assert_eq!(before_last, &["c".to_string()][..]);
        let (head, _) = it.next().unwrap();
        assert_eq!(head, &["a".to_string()][..]);
        // Exhaust: the two remaining pulls from opposite ends meet at the
        // last surviving element `b`, then both cursors report `None`.
        let (mid, _) = it.next_back().unwrap();
        assert_eq!(mid, &["b".to_string()][..]);
        assert!(it.next().is_none());
        assert!(it.next_back().is_none());
    }

    #[test]
    fn provenance_map_entries_len_matches_remaining_pulls() {
        // Pin the ExactSizeIterator impl: `len()` reports the exact
        // remaining count at every seam. The projection
        // `(&Vec<String>, &Provenance) → (&[String], &Provenance)` is
        // element-preserving (unlike the filter-based discovered-side
        // iters), so `len()` is honored at the type level.
        let r = Prog::resolve_progressive();
        let mut it = r.provenance().entries();
        assert_eq!(it.len(), 4);
        it.next();
        assert_eq!(it.len(), 3);
        it.next_back();
        assert_eq!(it.len(), 2);
        it.next();
        it.next_back();
        assert_eq!(it.len(), 0);
        assert!(it.next().is_none());
    }

    #[test]
    fn provenance_map_entries_debug_impl_names_the_struct() {
        // Pin the derived Debug impl at the format-string level: the
        // rendered output names the struct (`ProvenanceMapEntries`).
        // The inner `BTreeMap::Iter` forwards its own Debug, which
        // renders every remaining (path, provenance) pair — enough
        // to distinguish "just started" from "half-way through"
        // without a manual impl.
        let r = Prog::resolve_progressive();
        let it = r.provenance().entries();
        let s = format!("{it:?}");
        assert!(
            s.contains("ProvenanceMapEntries"),
            "Debug output should name the struct type, got: {s}"
        );
    }

    #[test]
    fn progressive_pair_is_atomic_via_into_parts() {
        let (value, prov) = Prog::resolve_progressive().into_parts();
        assert_eq!(value.a, 10);
        assert_eq!(
            prov.provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered
        );
    }

    // -------- IntoIterator / FromIterator / Extend on ProvenanceMap --------

    #[test]
    fn into_iter_ref_forwards_to_entries_pointwise() {
        // `for entry in &map` yields the same pair stream as `map.entries()` —
        // the borrow-side idiomatic dual is a name change, not a shape
        // change. Pins the tier-level `IntoIterator for &ProvenanceMap`
        // impl at the runtime level.
        let r = Prog::resolve_progressive();
        let via_entries: Vec<Vec<String>> =
            r.provenance().entries().map(|(p, _)| p.to_vec()).collect();
        let via_into_iter_ref: Vec<Vec<String>> = r
            .provenance()
            .into_iter()
            .map(|(p, _)| p.to_vec())
            .collect();
        assert_eq!(via_entries, via_into_iter_ref);
    }

    #[test]
    fn into_iter_owned_yields_same_paths_and_provenance_as_entries() {
        // The consume-side dual of the borrow-side entries walk: owning
        // pulls yield `(Vec<String>, Provenance)` in the same lex order,
        // with each provenance equal to what the borrowing walk showed.
        let r = Prog::resolve_progressive();
        let borrowed: Vec<(Vec<String>, Provenance)> = r
            .provenance()
            .entries()
            .map(|(p, prov)| (p.to_vec(), prov.clone()))
            .collect();
        let owned: Vec<(Vec<String>, Provenance)> = r.provenance().clone().into_iter().collect();
        assert_eq!(borrowed, owned);
    }

    #[test]
    fn into_iter_owned_len_matches_provenance_map_len() {
        // ExactSizeIterator on the consuming walker reports the same
        // leaf count as the map — the trait-level parity of
        // `ProvenanceMapEntries::len()` on the consume-side surface.
        let r = Prog::resolve_progressive();
        let n = r.provenance().len();
        let it = r.provenance().clone().into_iter();
        assert_eq!(it.len(), n);
    }

    #[test]
    fn into_iter_owned_next_back_walks_specific_to_coarse() {
        // The DoubleEnded impl on the consuming walker walks the sorted
        // BTreeMap in reverse — the tier-level peer of the same pin on
        // the borrowing ProvenanceMapEntries.
        let r = Prog::resolve_progressive();
        let mut it = r.provenance().clone().into_iter();
        let (last, _) = it.next_back().unwrap();
        assert_eq!(last, vec!["d".to_string()]);
        let (before_last, _) = it.next_back().unwrap();
        assert_eq!(before_last, vec!["c".to_string()]);
        let (head, _) = it.next().unwrap();
        assert_eq!(head, vec!["a".to_string()]);
        let (mid, _) = it.next_back().unwrap();
        assert_eq!(mid, vec!["b".to_string()]);
        assert!(it.next().is_none());
        assert!(it.next_back().is_none());
    }

    #[test]
    fn from_iter_collect_recovers_provenance_map() {
        // The construction-side dual of IntoIterator for &ProvenanceMap:
        // reading the map through `.entries()`, cloning each pair, and
        // `.collect()`-ing back into `ProvenanceMap` recovers the original
        // verbatim. The `FromIterator` seam lets consumers build synthetic
        // provenance maps for tests, mocks, and diagnostics without
        // reaching into a private inner field.
        let r = Prog::resolve_progressive();
        let source: ProvenanceMap = r.provenance().clone();
        let round: ProvenanceMap = source
            .entries()
            .map(|(p, prov)| (p.to_vec(), prov.clone()))
            .collect();
        assert_eq!(source, round);
    }

    #[test]
    fn from_iter_empty_source_is_default() {
        // `.collect()`-ing an empty stream yields the default (empty) map —
        // the same neutral element every keyed collection's `FromIterator`
        // + `Default` pair honors.
        let empty: ProvenanceMap = std::iter::empty::<(Vec<String>, Provenance)>().collect();
        assert_eq!(empty, ProvenanceMap::default());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn from_iter_last_write_wins_on_duplicate_paths() {
        // Duplicate paths in the source resolve last-write-wins — the same
        // `BTreeMap`-insertion discipline the discovered-side
        // `FromIterator for LayerAttribution` honors on its owned key.
        let path = vec!["k".to_string()];
        let first = Provenance::computed(ConfigTierKind::Bare);
        let second = Provenance::computed(ConfigTierKind::Discovered);
        let map: ProvenanceMap = vec![(path.clone(), first), (path.clone(), second.clone())]
            .into_iter()
            .collect();
        assert_eq!(map.len(), 1);
        assert_eq!(map.provenance_of_owned(&path), Some(&second));
    }

    #[test]
    fn extend_adds_new_paths_and_overwrites_at_conflicts() {
        // `Extend` mirrors `FromIterator`'s last-write-wins semantics but
        // grows the map in place. New paths land as fresh entries; a pair
        // at an existing path overwrites, matching what a caller would get
        // by rebuilding via `FromIterator`. Extending with an empty source
        // is a no-op.
        let a = vec!["a".to_string()];
        let b = vec!["b".to_string()];
        let bare = Provenance::computed(ConfigTierKind::Bare);
        let disc = Provenance::computed(ConfigTierKind::Discovered);
        let mut map: ProvenanceMap = vec![(a.clone(), bare.clone())].into_iter().collect();
        assert_eq!(map.len(), 1);
        map.extend(vec![(b.clone(), disc.clone()), (a.clone(), disc.clone())]);
        assert_eq!(map.len(), 2);
        assert_eq!(map.provenance_of_owned(&a), Some(&disc));
        assert_eq!(map.provenance_of_owned(&b), Some(&disc));
        map.extend(std::iter::empty::<(Vec<String>, Provenance)>());
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn into_iter_owned_debug_impl_names_the_struct() {
        // Pin the derived Debug impl at the format-string level: the
        // rendered output names the struct (`ProvenanceMapIntoIter`),
        // matching the same guarantee `ProvenanceMapEntries`'s Debug
        // carries on the borrowing surface.
        let r = Prog::resolve_progressive();
        let it = r.provenance().clone().into_iter();
        let s = format!("{it:?}");
        assert!(
            s.contains("ProvenanceMapIntoIter"),
            "Debug output should name the struct type, got: {s}"
        );
    }

    #[test]
    fn into_iter_owned_return_type_is_nameable_provenance_map_into_iter() {
        // Pin the sharpen at the type-signature level: a struct field
        // bound on `ProvenanceMapIntoIter` holds the handle across a
        // return. This test compiles iff the concrete type is nameable
        // at the API boundary — an `impl Trait` return would fail here.
        struct Held {
            walker: ProvenanceMapIntoIter,
        }
        fn hold(map: ProvenanceMap) -> Held {
            Held {
                walker: map.into_iter(),
            }
        }
        let r = Prog::resolve_progressive();
        let mut h = hold(r.provenance().clone());
        assert!(h.walker.next().is_some());
    }

    #[test]
    fn owned_into_iter_last_returns_trailing_entry() {
        // `.last()` is overridden to route through `next_back` on the
        // underlying `BTreeMap::IntoIter`, so the trailing entry lands
        // in `O(log n)` instead of draining the whole stream. Pin the
        // return value against the last lex-ordered path.
        let r = Prog::resolve_progressive();
        let it = r.provenance().clone().into_iter();
        let (last_path, _) = it.last().unwrap();
        assert_eq!(last_path, vec!["d".to_string()]);
    }

    // ── ProvenanceMap::tier_histogram — cube-native per-tier
    //    leaf-count histogram over the ConfigTierKind closed axis ──

    #[test]
    fn tier_histogram_total_matches_provenance_map_len() {
        // Every leaf projects to exactly one tier cell, so the histogram
        // total is the total leaf count verbatim.
        let r = Prog::resolve_progressive();
        let hist = r.provenance().tier_histogram();
        assert_eq!(hist.total(), r.provenance().len());
        assert_eq!(hist.total(), 4); // Prog has 4 leaves a,b,c,d
    }

    #[test]
    fn tier_histogram_per_tier_count_matches_entries_walk() {
        // Prog fixture: a → Discovered, b → Default, c → Bare, d → Default.
        // Pin the four per-cell counts through the shikumi cube-native
        // per-cell lookup, matching the entries-walk group-by verbatim.
        let r = Prog::resolve_progressive();
        let hist = r.provenance().tier_histogram();
        assert_eq!(hist.count(ConfigTierKind::Bare), 1); // c
        assert_eq!(hist.count(ConfigTierKind::Discovered), 1); // a
        assert_eq!(hist.count(ConfigTierKind::Default), 2); // b, d
        assert_eq!(hist.count(ConfigTierKind::Custom), 0); // no operator overlay
        // The trait-uniform equality against the entries-walk group-by,
        // as documented in the doc-comment invariant table.
        for tier in ConfigTierKind::ALL.iter().copied() {
            let manual = r
                .provenance()
                .entries()
                .filter(|(_, p)| p.tier() == tier)
                .count();
            assert_eq!(
                hist.count(tier),
                manual,
                "per-tier bucket must equal manual entries-walk tally on {tier:?}",
            );
        }
    }

    #[test]
    fn tier_histogram_observed_matches_contributing_tiers_in_precedence_order() {
        // The pin that lets `contributing_tiers` route through the
        // histogram instead of hand-rolling `Vec::contains` + sort:
        // `observed()` yields the histogram's support in closed-axis
        // declaration order, which is `ConfigTier` precedence order.
        let r = Prog::resolve_progressive();
        let observed: Vec<ConfigTierKind> = r.provenance().tier_histogram().observed().collect();
        assert_eq!(observed, r.provenance().contributing_tiers());
        assert_eq!(
            observed,
            vec![
                ConfigTierKind::Bare,
                ConfigTierKind::Discovered,
                ConfigTierKind::Default,
            ],
        );
    }

    #[test]
    fn contributing_tiers_matches_tier_histogram_observed() {
        // The reverse pin: after routing `contributing_tiers` through
        // `tier_histogram().observed().collect()`, the two seams stay
        // pointwise equivalent under every fixture in this module.
        for provenance_map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let via_histogram: Vec<ConfigTierKind> =
                provenance_map.tier_histogram().observed().collect();
            assert_eq!(provenance_map.contributing_tiers(), via_histogram);
        }
    }

    #[test]
    fn tier_histogram_dominant_cell_names_widest_tier() {
        // In the Prog fixture Default wins the most leaves (b + d = 2);
        // the histogram's argmax picks Default without a per-consumer
        // scan. The tier-level peer of
        // `LayerAttribution::dominant_layer` on the discovered algebra.
        let r = Prog::resolve_progressive();
        assert_eq!(
            r.provenance().tier_histogram().dominant_cell(),
            Some(ConfigTierKind::Default),
        );
    }

    #[test]
    fn tier_histogram_unobserved_names_the_absent_tiers() {
        // Prog fixture has no operator overlay, so `Custom` is the sole
        // unobserved tier cell. The coverage-gap partition on the
        // shikumi cube-native primitive answers "which tier was never
        // heard from?" at one named site.
        let r = Prog::resolve_progressive();
        let unobserved: Vec<ConfigTierKind> =
            r.provenance().tier_histogram().unobserved().collect();
        assert_eq!(unobserved, vec![ConfigTierKind::Custom]);
    }

    #[test]
    fn tier_histogram_is_empty_iff_provenance_map_is_empty() {
        // The empty-boundary invariant: an empty ProvenanceMap yields
        // the monoid-identity histogram, and vice versa. Peer of the
        // `ConfigDiff::kind_histogram` empty-boundary law on the diff
        // altitude.
        let empty = ProvenanceMap::default();
        assert!(empty.is_empty());
        assert!(empty.tier_histogram().is_empty());
        assert_eq!(empty.tier_histogram().total(), 0);
        assert_eq!(empty.contributing_tiers(), Vec::<ConfigTierKind>::new());

        let r = Prog::resolve_progressive();
        assert!(!r.provenance().is_empty());
        assert!(!r.provenance().tier_histogram().is_empty());
    }

    #[test]
    fn tier_histogram_distinct_cells_matches_contributing_tiers_len() {
        // The support-cardinality invariant on the histogram's
        // support-vs-total partition: distinct_cells equals the number
        // of contributing tiers. Any future re-implementation of either
        // seam must keep this equality — pinned uniformly.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            assert_eq!(
                map.tier_histogram().distinct_cells(),
                map.contributing_tiers().len(),
            );
        }
    }

    // ── ProvenanceMap::absent_tiers — unobserved-cells peer of
    //    contributing_tiers on the tier altitude ──

    #[test]
    fn absent_tiers_matches_tier_histogram_unobserved_pointwise() {
        // The coverage-gap pin: `absent_tiers` routes through
        // `tier_histogram().unobserved().collect()`, so the two seams
        // must stay pointwise equivalent under every fixture. Catches
        // any future drift where either implementation stops projecting
        // through the shared cube-native primitive.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let via_histogram: Vec<ConfigTierKind> = map.tier_histogram().unobserved().collect();
            assert_eq!(map.absent_tiers(), via_histogram);
        }
    }

    #[test]
    fn absent_tiers_prog_fixture_is_custom_only() {
        // Prog carries no operator overlay: Bare, Discovered, and Default
        // each produce ≥1 leaf, so Custom is the sole coverage-gap cell.
        // The named seam answers the operator's "which tier was never
        // heard from?" question at one call — no `ConfigTierKind::ALL`
        // walk + `Vec::contains` in the fleet dashboard.
        let r = Prog::resolve_progressive();
        assert_eq!(r.provenance().absent_tiers(), vec![ConfigTierKind::Custom]);
    }

    #[test]
    fn absent_tiers_empty_map_is_full_axis() {
        // An empty ProvenanceMap has no leaves and therefore no
        // contributing tiers — every cell of `ConfigTierKind::ALL` lies
        // in the coverage gap. The empty-map / full-coverage-gap
        // boundary of the observed / unobserved partition.
        let empty = ProvenanceMap::default();
        assert_eq!(empty.absent_tiers(), ConfigTierKind::ALL.to_vec());
    }

    #[test]
    fn absent_tiers_iterates_in_declaration_order() {
        // The coverage-gap iter walks `ConfigTierKind::ALL` in
        // declaration order (`Bare → Discovered → Default → Custom`)
        // and yields only the cells with zero count. Pinned here on the
        // empty map, whose gap is the entire axis — the emitted order
        // matches `ConfigTierKind::ALL` verbatim.
        let empty = ProvenanceMap::default();
        assert_eq!(
            empty.absent_tiers(),
            vec![
                ConfigTierKind::Bare,
                ConfigTierKind::Discovered,
                ConfigTierKind::Default,
                ConfigTierKind::Custom,
            ],
        );
    }

    #[test]
    fn absent_tiers_len_matches_unobserved_cells() {
        // The coverage-gap-cardinality invariant on the histogram's
        // support-vs-gap partition: `absent_tiers().len()` equals
        // `tier_histogram().unobserved_cells()` pointwise across every
        // fixture. Any future re-implementation of either seam must
        // keep this equality.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            assert_eq!(
                map.absent_tiers().len(),
                map.tier_histogram().unobserved_cells(),
            );
        }
    }

    #[test]
    fn absent_tiers_and_contributing_tiers_partition_axis() {
        // The support / coverage-gap partition on the closed axis:
        // every cell of `ConfigTierKind::ALL` lies in exactly one of
        // (observed, unobserved), so the two Vec lengths sum to the
        // axis cardinality. Pinned across every fixture in the module.
        let axis_size = crate::axis_cardinality::<ConfigTierKind>();
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let observed = map.contributing_tiers();
            let absent = map.absent_tiers();
            assert_eq!(observed.len() + absent.len(), axis_size);
            // Disjointness: no cell appears in both.
            for tier in &observed {
                assert!(
                    !absent.contains(tier),
                    "tier {tier:?} appears in both contributing and absent",
                );
            }
            // Union covers the axis: every cell of `ALL` is in one side.
            for cell in ConfigTierKind::ALL {
                assert!(
                    observed.contains(cell) || absent.contains(cell),
                    "tier {cell:?} appears in neither contributing nor absent",
                );
            }
        }
    }

    #[test]
    fn absent_tiers_is_empty_iff_is_full_cover() {
        // The coverage-gap is empty iff every tier contributed ≥1 leaf.
        // Pinned on the Prog fixture (Custom is absent, so not full
        // cover) and cross-verified against
        // `tier_histogram().is_full_cover()`.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            assert_eq!(
                map.absent_tiers().is_empty(),
                map.tier_histogram().is_full_cover(),
            );
        }
        // Direct pin: Prog has no Custom overlay → not full cover, and
        // the coverage-gap is nonempty.
        let prog = Prog::resolve_progressive();
        assert!(!prog.provenance().tier_histogram().is_full_cover());
        assert!(!prog.provenance().absent_tiers().is_empty());
    }

    #[test]
    fn absent_tiers_is_strictly_ascending_by_axis_ordinal() {
        // Structural sort pin: the coverage-gap walks the closed axis
        // in declaration order, so `absent_tiers()` is strictly
        // ascending by `crate::axis_ordinal` — the dedup + sort every
        // hand-rolled walk would have to spell explicitly comes for
        // free from the closed-axis discipline.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let absent = map.absent_tiers();
            for pair in absent.windows(2) {
                assert!(
                    crate::axis_ordinal(pair[0]) < crate::axis_ordinal(pair[1]),
                    "absent_tiers must be strictly ascending: {absent:?}",
                );
            }
        }
    }

    #[test]
    fn absent_tiers_full_cover_yields_empty() {
        // The full-cover positive case: a ProvenanceMap containing
        // ≥1 leaf on every tier has an empty coverage-gap. Constructed
        // by overlaying a Custom operator layer on Prog (which already
        // spans Bare + Discovered + Default) — every tier now
        // contributes at least one leaf, so `absent_tiers()` is empty
        // and `tier_histogram()` is full-cover.
        let mut d = Dict::new();
        d.insert("b".to_owned(), Value::from(99_u32));
        let r = Prog::resolve_progressive_with(&[ProgressiveLayer::file("/etc/prog.yaml", d)]);
        assert!(r.provenance().tier_histogram().is_full_cover());
        assert_eq!(r.provenance().absent_tiers(), Vec::<ConfigTierKind>::new());
        // And symmetrically, the observed peer equals `ConfigTierKind::ALL`
        // (in declaration order) at full cover.
        assert_eq!(
            r.provenance().contributing_tiers(),
            ConfigTierKind::ALL.to_vec(),
        );
    }

    #[test]
    fn absent_tiers_agrees_with_open_coded_coverage_gap_walk() {
        // Parity against the exact `ConfigTierKind::ALL.iter().filter(|t|
        // !contributing_tiers().contains(t))` walk this lift replaces —
        // both the named seam and the hand-rolled coverage-gap must
        // pointwise agree over every fixture in the module.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let via_seam = map.absent_tiers();
            let contributing = map.contributing_tiers();
            let hand_rolled: Vec<ConfigTierKind> = ConfigTierKind::ALL
                .iter()
                .copied()
                .filter(|t| !contributing.contains(t))
                .collect();
            assert_eq!(via_seam, hand_rolled);
        }
    }

    #[test]
    fn dominant_tier_matches_tier_histogram_dominant_cell_pointwise() {
        // The modal-cell pin: `dominant_tier` routes through
        // `tier_histogram().dominant_cell()`, so the two seams must
        // stay pointwise equivalent under every fixture. Catches any
        // future drift where either implementation stops projecting
        // through the shared cube-native primitive.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let via_histogram = map.tier_histogram().dominant_cell();
            assert_eq!(map.dominant_tier(), via_histogram);
        }
    }

    #[test]
    fn dominant_tier_prog_fixture_is_default() {
        // Prog attributes 4 leaves: a→Discovered, b→Default, c→Bare,
        // d→Default. Default holds 2 of 4, uniquely dominant on the
        // 4-cell tier axis. Direct pin — the named seam answers the
        // operator's *"which tier dominated this resolved fold?"*
        // question at one call, no `max_by_key` walk in the dashboard.
        let r = Prog::resolve_progressive();
        assert_eq!(
            r.provenance().dominant_tier(),
            Some(ConfigTierKind::Default)
        );
    }

    #[test]
    fn dominant_tier_nested_fixture_is_default() {
        // Nested attributes 3 leaves: win.w→Discovered, win.h→Default,
        // theme→Default. Default holds 2 of 3, uniquely dominant on the
        // tier axis under nested per-leaf attribution — the modal cell
        // reads through the seam whether the fixture is flat or nested.
        let r = Nested::resolve_progressive();
        assert_eq!(
            r.provenance().dominant_tier(),
            Some(ConfigTierKind::Default)
        );
    }

    #[test]
    fn dominant_tier_empty_map_is_none() {
        // An empty ProvenanceMap has no leaves and therefore no modal
        // tier — the empty-map / empty-histogram boundary of the
        // dominant-cell projection. Peer to
        // `absent_tiers_empty_map_is_full_axis` (the same boundary on
        // the coverage-gap side).
        let empty = ProvenanceMap::default();
        assert_eq!(empty.dominant_tier(), None);
    }

    #[test]
    fn dominant_tier_is_some_iff_map_is_nonempty() {
        // Cross-surface pin: the presence-of-modal-cell predicate
        // agrees with the non-emptiness of the underlying map.
        // Structural completeness of the `(is_empty, dominant_tier)`
        // boundary — a well-formed fold with ≥1 leaf always has a
        // modal cell, and an empty fold never does.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            assert_eq!(map.dominant_tier().is_some(), !map.is_empty());
        }
    }

    #[test]
    fn dominant_tier_is_member_of_contributing_tiers() {
        // Structural pin: whenever `dominant_tier()` is `Some(t)`, `t`
        // must appear in `contributing_tiers()` (the modal cell is by
        // definition observed). The support / dominance partition on
        // the tier altitude reads consistently between the two named
        // seams.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
        ] {
            let dominant = map
                .dominant_tier()
                .expect("non-empty map has dominant tier");
            assert!(
                map.contributing_tiers().contains(&dominant),
                "dominant tier {dominant:?} must appear in contributing_tiers",
            );
        }
    }

    #[test]
    fn dominant_tier_is_not_member_of_absent_tiers() {
        // Structural pin: whenever `dominant_tier()` is `Some(t)`, `t`
        // must NOT appear in `absent_tiers()` — the modal cell lies on
        // the observed side of the observed / coverage-gap partition.
        // Disjointness pin between the two named seams.
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
        ] {
            let dominant = map
                .dominant_tier()
                .expect("non-empty map has dominant tier");
            assert!(
                !map.absent_tiers().contains(&dominant),
                "dominant tier {dominant:?} must not appear in absent_tiers",
            );
        }
    }

    #[test]
    fn dominant_tier_count_equals_peak_count_on_nonempty_map() {
        // The (dominant_cell, peak_count) modal-pair invariant lifted
        // to the tier altitude: the observation count of the dominant
        // tier equals the histogram's peak count. Pins the fused form
        // of the modal-pair the AxisHistogram surface carries as
        // (dominant_cell(), peak_count()).
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
        ] {
            let hist = map.tier_histogram();
            let dominant = map
                .dominant_tier()
                .expect("non-empty map has dominant tier");
            assert_eq!(hist.count(dominant), hist.peak_count());
        }
    }

    #[test]
    fn dominant_tier_ties_broken_by_declaration_order() {
        // Structural tie-breaking pin: on a uniform per-tier fold
        // (each of the four `ConfigTierKind` cells contributing
        // exactly one leaf), `dominant_tier` reports
        // `Some(ConfigTierKind::Bare)` — the first cell in
        // `ConfigTierKind::ALL` declaration order. Constructed by
        // overlaying a Custom operator layer on Prog (which spans
        // Bare→Discovered→Default with 4 leaves distributed 1/1/2)
        // that steals the second Default-tier leaf (b) into Custom,
        // yielding a 1-leaf-per-tier full-cover fold. Any future
        // switch to a nondeterministic `max_by_key` walk (which
        // silently picks the LAST tied cell) would flip this pin to
        // `Some(Custom)` — the seam names the tiebreak once.
        let mut d = Dict::new();
        d.insert("b".to_owned(), Value::from(99_u32));
        let r = Prog::resolve_progressive_with(&[ProgressiveLayer::file("/etc/prog.yaml", d)]);
        // Sanity: this construction produces the intended tier-count
        // distribution (each tier owns exactly one leaf).
        let hist = r.provenance().tier_histogram();
        assert_eq!(hist.count(ConfigTierKind::Bare), 1);
        assert_eq!(hist.count(ConfigTierKind::Discovered), 1);
        assert_eq!(hist.count(ConfigTierKind::Default), 1);
        assert_eq!(hist.count(ConfigTierKind::Custom), 1);
        assert!(hist.is_full_cover());
        // Tiebreak lands on the first cell in declaration order.
        assert_eq!(r.provenance().dominant_tier(), Some(ConfigTierKind::Bare));
    }

    #[test]
    fn dominant_tier_agrees_with_open_coded_argmax_walk() {
        // Parity against the exact `hist.iter().filter(|&(_, c)| c > 0)
        // .max_by(count-then-declaration-order)` walk this lift replaces
        // — both the named seam and the hand-rolled argmax must
        // pointwise agree over every fixture in the module. The
        // hand-rolled form spells the declaration-order tiebreak
        // explicitly (fold-forward with strict `>` inequality — the
        // first tied cell wins, mirroring `AxisHistogram::dominant_cell`
        // — rather than `max_by_key`'s LAST-tied-cell semantics).
        for map in [
            Prog::resolve_progressive().provenance().clone(),
            Nested::resolve_progressive().provenance().clone(),
            ProvenanceMap::default(),
        ] {
            let via_seam = map.dominant_tier();
            let hist = map.tier_histogram();
            let mut iter = hist.iter().filter(|&(_, c)| c > 0);
            let hand_rolled = iter.next().map(|first| {
                iter.fold(
                    first,
                    |best, current| {
                        if current.1 > best.1 { current } else { best }
                    },
                )
                .0
            });
            assert_eq!(via_seam, hand_rolled);
        }
    }

    #[test]
    fn dominant_tier_uniform_cover_picks_first_cell() {
        // Trait-uniform invariant: on a full-cover fold where every
        // tier observes the same nonzero count, the dominant cell is
        // the first cell of `ConfigTierKind::ALL` — the declaration-
        // order tiebreak reduces to `Some(Bare)`. Peer of the trait-
        // uniform `axis_histogram_dominant_cell_axis_cover_picks_first_*`
        // laws in cube tests.
        // Direct construction via `FromIterator`: one leaf per tier,
        // full-cover with uniform count 1. `dominant_cell` then reduces
        // to *"first cell of `ConfigTierKind::ALL`"* — the pin lives in
        // the tiered.rs surface for the ProvenanceMap-scoped seam, not
        // just the cube-generic trait law.
        let m: ProvenanceMap = ConfigTierKind::ALL
            .iter()
            .copied()
            .map(|t| (vec![t.as_str().to_owned()], Provenance::computed(t)))
            .collect();
        assert!(m.tier_histogram().is_full_cover());
        assert_eq!(m.dominant_tier(), Some(ConfigTierKind::Bare));
    }

    // ── Nested per-leaf attribution ──

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Win {
        w: u32,
        h: u32,
    }
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Nested {
        win: Win,
        theme: u32,
    }
    impl TieredConfig for Nested {
        fn bare() -> Self {
            Self {
                win: Win { w: 0, h: 0 },
                theme: 0,
            }
        }
        fn discovered() -> Self {
            Self {
                win: Win { w: 100, h: 0 },
                theme: 0,
            }
        }
        fn prescribed_default() -> Self {
            Self {
                win: Win { w: 100, h: 50 },
                theme: 7,
            }
        }
    }

    #[test]
    fn progressive_attributes_nested_leaves_independently() {
        let r = Nested::resolve_progressive();
        assert_eq!(r.value().win.w, 100);
        assert_eq!(r.value().win.h, 50);
        // win.w detected → Discovered; win.h curated → Default; sibling leaves
        // under `win` keep independent credit.
        assert_eq!(
            r.provenance().provenance_of(&["win", "w"]).unwrap().tier(),
            ConfigTierKind::Discovered,
        );
        assert_eq!(
            r.provenance().provenance_of(&["win", "h"]).unwrap().tier(),
            ConfigTierKind::Default,
        );
        assert_eq!(
            r.provenance().provenance_of(&["theme"]).unwrap().tier(),
            ConfigTierKind::Default,
        );
    }

    // ── discovered_from_layers — the low-ceremony kanchi seam ──

    struct AxisLayer {
        key: &'static str,
        val: u32,
    }
    impl DiscoveryLayer for AxisLayer {
        fn name(&self) -> &'static str {
            "axis"
        }
        fn discover(&self) -> Dict {
            let mut d = Dict::new();
            d.insert(self.key.to_owned(), Value::from(self.val));
            d
        }
    }

    // A config whose `discovered()` is wired DECLARATIVELY from layers (the
    // gap-1 seam), and whose `prescribed_default()` is built on discovered()
    // — the mado pattern, without the hand-rolled struct literal.
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Seam {
        a: u32,
        b: u32,
    }
    impl TieredConfig for Seam {
        fn bare() -> Self {
            Self { a: 0, b: 0 }
        }
        fn discovered() -> Self {
            Self::discovered_from_layers(&[&AxisLayer { key: "a", val: 42 }])
        }
        fn prescribed_default() -> Self {
            let mut s = Self::discovered();
            s.b = 2;
            s
        }
    }

    #[test]
    fn discovered_from_layers_overlays_detected_axes_on_bare() {
        let d = Seam::discovered();
        assert_eq!(d.a, 42, "detected axis a overlays bare");
        assert_eq!(d.b, 0, "an axis no layer set keeps the bare floor");
    }

    #[test]
    fn discovered_from_layers_empty_stack_is_bare() {
        // Totality: no layers (or an undetectable axis) degenerates to bare.
        assert_eq!(Seam::discovered_from_layers(&[]), Seam::bare());
    }

    #[test]
    fn seam_progressive_shows_detected_axis_through_prescribed() {
        let r = Seam::resolve_progressive();
        assert_eq!(*r.value(), Seam { a: 42, b: 2 });
        assert_eq!(
            r.provenance().provenance_of(&["a"]).unwrap().tier(),
            ConfigTierKind::Discovered,
        );
        assert_eq!(
            r.provenance().provenance_of(&["b"]).unwrap().tier(),
            ConfigTierKind::Default,
        );
    }

    // ── Provenance primitive surface ──

    #[test]
    fn provenance_display_is_typed() {
        assert_eq!(
            Provenance::computed(ConfigTierKind::Discovered).to_string(),
            "discovered"
        );
        assert_eq!(
            Provenance::file("/x.yaml").to_string(),
            "custom (file: /x.yaml)"
        );
        assert_eq!(Provenance::env("APP_").to_string(), "custom (env: APP_)");
    }

    #[test]
    fn provenance_tier_ordinal_reuses_closed_axis_order() {
        // Precedence reuses the const ConfigTierKind ClosedAxis declaration
        // order — Bare < Discovered < Default < Custom.
        assert!(
            Provenance::computed(ConfigTierKind::Bare).tier_ordinal()
                < Provenance::computed(ConfigTierKind::Discovered).tier_ordinal()
        );
        assert!(
            Provenance::computed(ConfigTierKind::Discovered).tier_ordinal()
                < Provenance::computed(ConfigTierKind::Default).tier_ordinal()
        );
        assert!(
            Provenance::computed(ConfigTierKind::Default).tier_ordinal()
                < Provenance::file("/x").tier_ordinal()
        );
    }
}

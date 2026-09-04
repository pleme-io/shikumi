//! Config file discovery — parameterized XDG path scanning.
//!
//! Extracted from karakuri's `CONFIGURATION_FILE` `LazyLock`. Generalized
//! so any app can use the same discovery logic by providing its name.
//!
//! Supports both single-file discovery (`discover()`) and hierarchical
//! multi-file discovery with merge (`discover_all()`).

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use tracing::warn;

use crate::error::ShikumiError;

/// Supported config file formats, in preference order.
///
/// **Tatara-lisp is a first-class configuration format** alongside YAML, TOML,
/// and Nix. Per the pleme-io tatara-lisp ecosystem standard, every configurable
/// application supports all four natively and auto-detects by extension.
///
/// **Trait surface** — alongside the canonical
/// `Debug + Clone + Copy + PartialEq + Eq + Hash + Default` set, the derive
/// also includes [`Ord`] + [`PartialOrd`]. The total order is the
/// declaration-order lex over [`Self::ALL`]
/// (`Yaml < Toml < Lisp < Nix`), matching the documented "preference
/// order" reading at the type level. A
/// [`BTreeMap<Format, T>`][std::collections::BTreeMap] keyed on the
/// format axis (e.g. per-format resolve-cost telemetry, per-format
/// discovery-hit counts, per-format attestation rollups) emits rows in
/// preference order deterministically without a hand-rolled comparator
/// — idiom-peer of the same `Ord` derive on the typed-cube classifiers
/// ([`crate::ModalityClass`], [`crate::PartitionFace`], …) and pinned by
/// [`tests::format_ord_matches_all_declaration_order`].
///
/// **Serde surface** — [`serde::Serialize`] / [`serde::Deserialize`] are
/// implemented manually as the canonical idiom-peer of the existing
/// [`std::fmt::Display`] / [`std::str::FromStr`] pair. Serialize emits
/// the canonical lowercase label [`Self::as_str`] returns; Deserialize
/// lowers through [`<Self as FromStr>::from_str`], inheriting the
/// alias surface (`yml`/`lsp`/`el`) and case-insensitivity for free. A
/// consumer config carrying a `default_format: yaml` field, an
/// attestation manifest recording which format a config resolved
/// through, or a per-format dispatch table keyed under
/// `#[derive(Serialize, Deserialize)]` reaches the canonical wire form
/// without a consumer-side rename helper. Pinned by
/// [`tests::format_serde_yaml_round_trips_over_every_variant`],
/// [`tests::format_serde_json_round_trips_over_every_variant`],
/// [`tests::format_serde_yaml_accepts_aliases`], and
/// [`tests::format_serde_yaml_unknown_format_error_carries_label_verbatim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Ord, PartialOrd)]
#[non_exhaustive]
pub enum Format {
    /// YAML format (`.yaml` and `.yml` extensions).
    #[default]
    Yaml,
    /// TOML format (`.toml` extension).
    Toml,
    /// Tatara-lisp format (`.lisp` / `.lsp` / `.el` extensions).
    ///
    /// The first top-level `(defX …)` form's kwargs become the config dict;
    /// nested kwargs lists become nested maps. Bare symbols → strings;
    /// nil → null. See [`crate::lisp_provider`] for the full mapping.
    Lisp,
    /// Nix format (`.nix` extension).
    ///
    /// Evaluated via `nix eval --file <path> --json` and parsed as JSON.
    /// The file must evaluate to an attrset; its attrs become the config.
    Nix,
    /// Blue format (`.b` extension).
    ///
    /// blue's Ruby/Elixir-flavoured surface parses to the SAME
    /// `tatara_lisp::Sexp` the [`Self::Lisp`] front-end produces, so both
    /// share one mapping ([`crate::lisp_provider::sexp_to_value_root`])
    /// rather than each carrying a copy that could drift.
    ///
    /// **Parsed and mapped, never executed.** Only `blue-lang-syntax` is a
    /// dependency — the runtime, interpreter and package manager stay out
    /// of shikumi's closure. A config format that can run arbitrary code is
    /// a much larger security surface, and blue additionally has no
    /// execution budget today (its `pipeline` runs the tree-walking
    /// interpreter; `Budget` is VM-only), so a runaway `.b` file would
    /// wedge its host. Evaluation is a later, separately-gated decision.
    Blue,
}

impl Format {
    /// Every [`Format`] variant, in declaration order.
    ///
    /// The closed list of formats shikumi understands. Iterate to
    /// enumerate the format space without listing variants by hand —
    /// e.g. tests that must round-trip every format, or attribution
    /// resolvers that try every shikumi-built provider's metadata-name
    /// shape in turn (see [`Self::strip_metadata_name`]).
    ///
    /// Adding a new variant means extending this slice in lockstep with
    /// the variant itself; the compiler enforces nothing here, so the
    /// `format_all_covers_every_variant` test pins the contract by
    /// matching every variant.
    pub const ALL: &'static [Format] = &[Self::Yaml, Self::Toml, Self::Lisp, Self::Nix, Self::Blue];

    /// The two FEATURE-GATED [`Format`] variants — [`Self::Lisp`]
    /// (behind the `lisp` cargo feature) and [`Self::Blue`] (behind
    /// the `blue` cargo feature) — in the SAME relative declaration
    /// order they occupy in [`Self::ALL`], carrying the
    /// *compile-time-optional* pole of the
    /// (feature-gated × always-available) polarity axis at the primitive's
    /// OWN altitude on the file-format axis, mirroring the shipped
    /// boolean predicate [`Self::is_feature_gated`] one altitude down:
    /// every variant in this slice satisfies `f.is_feature_gated()`,
    /// and no variant outside it does.
    ///
    /// Paired with [`Self::ALWAYS_AVAILABLE`], the two disjoint slices
    /// partition [`Self::ALL`] at the static-slice altitude the same way
    /// the shipped boolean predicates [`Self::is_feature_gated`] /
    /// [`Self::is_always_available`] meta-partition it at the boolean
    /// altitude. The two constants sit in the same `impl Format` block
    /// as [`Self::ALL`] and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit two-variant slice literal in the SAME
    /// relative declaration order the feature-gated pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_feature_gated`] at const-fn altitude — so the
    /// two declarations (the slice literal and the boolean predicate)
    /// remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first shape where they disagree.
    /// A hypothetical sixth variant landing behind a new cargo feature
    /// (a `Cue` behind `cue`, a `Jsonnet` behind `jsonnet`) lands here
    /// in lockstep with [`Self::is_feature_gated`], and the cardinality
    /// pin catches any drift between the slice and the boolean
    /// predicate on the same edit.
    ///
    /// Idiom-peer of [`crate::ConfigTierKind::COMPUTED`] (commit
    /// `2c0686f`), [`crate::source::ConfigSourceKind::DEFAULTS`]
    /// (commit `2cf6dd8`), [`crate::secret_client::SecretOperation::MUTATING`]
    /// (commit `b2cfa2a`), and the per-half slice-constant landings on
    /// [`crate::error::AttributionConfidence::EXACT`] (commit `13c1003`),
    /// [`crate::secret::SecretRefShape::WHOLE`] (commit `036673b`),
    /// [`crate::FormatProvenance::FIGMENT_BUILTIN`] (commit `7ef79e4`),
    /// [`crate::cube::PartitionFace::REALIZABLE`] (commit `a344056`),
    /// [`crate::cli::OutputFormat::YAML`] (commit `292ca1d`),
    /// [`crate::source::EnvMetadataTagKind::PREFIXED`] (commit `13304d0`),
    /// and [`crate::source::FigmentNameTagKind::FORMAT`] (commit
    /// `2d2ef9d`) — the per-half meta-partition slice-constant discipline
    /// applied here to the five-way file-format axis's
    /// (feature-gated × always-available) meta-partition.
    ///
    /// The two agreement laws
    /// (`FEATURE_GATED.iter().all(|f| f.is_feature_gated())` and
    /// `FEATURE_GATED.iter().all(|f| !f.is_always_available())`) are
    /// pinned by
    /// [`tests::format_feature_gated_slice_agrees_with_is_feature_gated_predicate`].
    /// Partition invariant with [`Self::ALWAYS_AVAILABLE`]:
    /// [`tests::format_feature_gated_and_always_available_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::format_feature_gated_and_always_available_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::format_feature_gated_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::format_feature_gated_and_always_available_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::format_feature_gated_and_always_available_slices_are_const_addressable`].
    pub const FEATURE_GATED: &'static [Self] = &[Self::Lisp, Self::Blue];

    /// The three ALWAYS-AVAILABLE [`Format`] variants —
    /// [`Self::Yaml`], [`Self::Toml`], and [`Self::Nix`] — in the SAME
    /// relative declaration order they occupy in [`Self::ALL`], carrying
    /// the *unconditionally-compiled* pole of the
    /// (feature-gated × always-available) polarity axis at the primitive's
    /// OWN altitude on the file-format axis, mirroring the shipped
    /// boolean predicate [`Self::is_always_available`] one altitude
    /// down.
    ///
    /// The declaration-order projection preserves [`Self::ALL`]'s
    /// interleaving on this pole: [`Self::Yaml`] and [`Self::Toml`]
    /// come before [`Self::Lisp`] (skipped — the other pole), and
    /// [`Self::Nix`] comes after [`Self::Lisp`] but before
    /// [`Self::Blue`] (also skipped), so the always-available slice is
    /// [`Self::Yaml`], [`Self::Toml`], [`Self::Nix`] — not a suffix or
    /// prefix of [`Self::ALL`], but the ALL-order filtered projection
    /// under [`Self::is_always_available`]. Any future variant landing
    /// on this pole extends the slice at the ALL-declaration-order
    /// position, not at the tail.
    ///
    /// See [`Self::FEATURE_GATED`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_always_available`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const ALWAYS_AVAILABLE: &'static [Self] = &[Self::Yaml, Self::Toml, Self::Nix];

    /// The three SHIKUMI-PROVIDED [`Format`] variants — [`Self::Lisp`]
    /// (loaded by [`crate::LispProvider`]), [`Self::Nix`] (loaded by
    /// [`crate::NixProvider`]), and [`Self::Blue`] (loaded by
    /// [`crate::blue_provider`]) — in the SAME relative declaration
    /// order they occupy in [`Self::ALL`], carrying the
    /// *shikumi-built-provider* pole of the
    /// (shikumi-provided × figment-builtin-provided) polarity axis at
    /// the primitive's OWN altitude on the file-format axis, mirroring
    /// the shipped boolean predicate [`Self::has_shikumi_provider`] one
    /// altitude down: every variant in this slice satisfies
    /// `f.has_shikumi_provider()`, and no variant outside it does.
    ///
    /// Paired with [`Self::FIGMENT_BUILTIN_PROVIDED`], the two disjoint
    /// slices partition [`Self::ALL`] at the static-slice altitude the
    /// same way the shipped boolean predicates
    /// [`Self::has_shikumi_provider`] /
    /// [`Self::has_figment_builtin_provider`] meta-partition it at the
    /// boolean altitude (per
    /// [`tests::format_provider_class_predicates_are_a_closed_binary_partition`]).
    /// The two constants sit in the same `impl Format` block as
    /// [`Self::ALL`] / [`Self::FEATURE_GATED`] /
    /// [`Self::ALWAYS_AVAILABLE`] and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// **Distinct from the (feature-gated × always-available) polarity
    /// pair** — the two meta-partitions agree on four cells but disagree
    /// on [`Self::Nix`]: `has_shikumi_provider(Nix) == true` (a shikumi-
    /// built provider) while `is_feature_gated(Nix) == false` (Nix
    /// compiles unconditionally, no cargo feature gates it), so
    /// `SHIKUMI_PROVIDED = [Lisp, Nix, Blue]` differs from
    /// `FEATURE_GATED = [Lisp, Blue]` at the middle cell. The two
    /// meta-partitions witness two independent polarities on the same
    /// axis: the provider-class polarity names *how figment attribution
    /// is emitted for values of this format* (metadata-name prefix vs
    /// `Source::File` path), and the feature-gated polarity names
    /// *whether the parser compiles unconditionally*.
    ///
    /// Written as an explicit three-variant slice literal in the SAME
    /// relative declaration order the shikumi-provided pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::has_shikumi_provider`] at const-fn altitude — so
    /// the two declarations (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first shape where they disagree.
    /// A hypothetical sixth variant landing under a new provider class
    /// (a `Vault` or `Http` provider that is neither figment-builtin
    /// nor shikumi-built) would first fail the closed-binary partition
    /// invariant on `has_shikumi_provider` /
    /// `has_figment_builtin_provider` itself, forcing the new class to
    /// declare its own predicate and its own partition arm before
    /// silently landing under the negation of one of the existing two.
    ///
    /// Idiom-peer of [`Self::FEATURE_GATED`] on the sibling
    /// (feature-gated × always-available) axis over the same primitive,
    /// [`crate::ConfigTierKind::COMPUTED`] (commit `2c0686f`) on the
    /// tier-kind axis, [`crate::source::ConfigSourceKind::DEFAULTS`]
    /// on the source-layer axis, and the compound-polarity landings on
    /// [`crate::WatchEventClass::FILE_MUTATIONS`] and
    /// [`crate::tiered::DiffLineKind::CHANGED`] — the per-half
    /// meta-partition slice-constant discipline applied here to the
    /// five-way file-format axis's provider-class polarity, matching
    /// the ladder shape already carried on the parallel feature-gated
    /// polarity one altitude over.
    ///
    /// The two agreement laws
    /// (`SHIKUMI_PROVIDED.iter().all(|f| f.has_shikumi_provider())` and
    /// `SHIKUMI_PROVIDED.iter().all(|f| !f.has_figment_builtin_provider())`)
    /// are pinned by
    /// [`tests::format_shikumi_provided_slice_agrees_with_has_shikumi_provider_predicate`].
    /// Partition invariant with [`Self::FIGMENT_BUILTIN_PROVIDED`]:
    /// [`tests::format_shikumi_provided_and_figment_builtin_provided_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::format_shikumi_provided_and_figment_builtin_provided_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::format_shikumi_provided_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::format_shikumi_provided_and_figment_builtin_provided_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::format_shikumi_provided_and_figment_builtin_provided_slices_are_const_addressable`].
    /// Distinctness from the sibling (feature-gated × always-available)
    /// pair at [`Self::Nix`]:
    /// [`tests::format_shikumi_provided_differs_from_feature_gated_at_nix`].
    pub const SHIKUMI_PROVIDED: &'static [Self] = &[Self::Lisp, Self::Nix, Self::Blue];

    /// The two FIGMENT-BUILTIN-PROVIDED [`Format`] variants —
    /// [`Self::Yaml`] and [`Self::Toml`] — in the SAME relative
    /// declaration order they occupy in [`Self::ALL`], the complement
    /// pole of [`Self::SHIKUMI_PROVIDED`] on the
    /// (shikumi-provided × figment-builtin-provided) closed-binary
    /// polarity at the primitive's OWN altitude on the file-format
    /// axis. Mirrors the shipped boolean predicate
    /// [`Self::has_figment_builtin_provider`] one altitude down.
    ///
    /// Two prefix cells of [`Self::ALL`] today — [`Self::Yaml`] and
    /// [`Self::Toml`] occupy the first two [`Self::ALL`] positions,
    /// with the three shikumi-provided cells ([`Self::Lisp`],
    /// [`Self::Nix`], [`Self::Blue`]) filling the tail — so
    /// [`Self::FIGMENT_BUILTIN_PROVIDED`] is a proper prefix of
    /// [`Self::ALL`] under today's declaration order. A future landing
    /// that reordered [`Self::ALL`] to interleave the polarity (e.g. a
    /// new figment-builtin variant slotted between [`Self::Lisp`] and
    /// [`Self::Nix`]) would extend this slice at the correct
    /// ALL-declaration-order position rather than at the tail.
    ///
    /// The partition invariant with [`Self::SHIKUMI_PROVIDED`] pins the
    /// whole-set cardinality identity
    /// `SHIKUMI_PROVIDED.len() + FIGMENT_BUILTIN_PROVIDED.len() ==
    /// ALL.len()`. Because the axis is a closed binary meta-partition
    /// by construction today, a future third provider class landing
    /// would first fail the three-versus-two cardinality pins, then
    /// fail the partition and cardinality pins on this constant pair
    /// unless extended in lockstep with the boolean predicates.
    ///
    /// See [`Self::SHIKUMI_PROVIDED`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a
    /// filter through [`Self::has_figment_builtin_provider`]), the
    /// distinctness discussion versus the sibling
    /// (feature-gated × always-available) polarity, and the
    /// load-bearing agreement, partition, order-preservation,
    /// no-duplicates, cardinality, and const-addressability pins.
    pub const FIGMENT_BUILTIN_PROVIDED: &'static [Self] = &[Self::Yaml, Self::Toml];

    /// The single [`Self::Yaml`] pole of the five-way identity meta-
    /// partition on the [`Format`] axis at the static-slice altitude —
    /// the singleton slice `&[Self::Yaml]` mirroring the shipped
    /// boolean predicate [`Self::is_yaml`] one altitude down: every
    /// variant in this slice satisfies `f.is_yaml()`, and no variant
    /// outside it does.
    ///
    /// Paired with the four siblings ([`Self::ONLY_TOML`],
    /// [`Self::ONLY_LISP`], [`Self::ONLY_NIX`], [`Self::ONLY_BLUE`]),
    /// the five disjoint singleton slices partition [`Self::ALL`] at
    /// the static-slice altitude the same way the shipped boolean
    /// predicates ([`Self::is_yaml`] / [`Self::is_toml`] /
    /// [`Self::is_lisp`] / [`Self::is_nix`] / [`Self::is_blue`]) meta-
    /// partition it at the boolean altitude. All five constants sit in
    /// the same `impl Format` block as [`Self::ALL`] /
    /// [`Self::FEATURE_GATED`] / [`Self::ALWAYS_AVAILABLE`] and follow
    /// the same `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the five identity poles occupy in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through the five identity predicates at const-fn altitude — so
    /// the two declaration surfaces (the slice literals and the
    /// boolean predicates) remain independent load-bearing witnesses
    /// of the same identity meta-partition, and a future edit that
    /// shifts a variant across an identity pole on ONE surface but not
    /// the other diverges at test time on the first shape where they
    /// disagree.
    ///
    /// Also the first cell of [`Self::ALWAYS_AVAILABLE`] — the two
    /// witnesses agree here (`ONLY_YAML ⊆ ALWAYS_AVAILABLE`) per the
    /// identity-vs-compound cross-check that pins the five identity
    /// singletons against the shipped
    /// (feature-gated × always-available) compound-polarity meta-
    /// partition.
    ///
    /// **Idiom-peer.** Quinary landing of the per-half meta-partition
    /// slice-constant discipline on a shikumi-native closed-primitive
    /// axis, matching altitude-for-altitude the septenary
    /// [`crate::error::ShikumiErrorKind::ONLY_NOT_FOUND`] / … /
    /// `ONLY_VALIDATION` (commit `6e74116`), the quinary
    /// [`crate::secret_client::SecretErrorKind::ONLY_NOT_FOUND`] / … /
    /// `ONLY_SHIKUMI` (commit `1a4ae14`), the senary
    /// [`crate::secret_client::SecretOperation::ONLY_GET`] / … /
    /// `ONLY_GET_VERSION` (commit `bfe3e24`), the septenary
    /// [`crate::secret_client::SecretClientKind::ONLY_MEM`] / … /
    /// `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), the octonary
    /// [`crate::secret::SecretBackendKind::ONLY_LITERAL`] / … /
    /// `ONLY_GCP_SECRET` (commit `19364e3`), the quinary
    /// [`crate::cli::TierArg::ONLY_BARE`] / … / `ONLY_ENV` (commit
    /// `f7f5529`), and the quaternary
    /// [`crate::tiered::ConfigTierKind::ONLY_BARE`] / … /
    /// `ONLY_CUSTOM` (commit `ff6492b`) — the per-half meta-partition
    /// slice-constant discipline applied here to the five-way
    /// [`Format`] axis (the first identity-partition landing on the
    /// config-file-format primitive), lifting the five identity poles
    /// onto the slice-constant altitude alongside the shipped
    /// compound-polarity [`Self::FEATURE_GATED`] /
    /// [`Self::ALWAYS_AVAILABLE`] pair one altitude up.
    ///
    /// The five agreement laws
    /// (`ONLY_YAML.iter().all(|f| f.is_yaml())` and
    /// `ONLY_YAML.iter().all(|f| !f.is_toml() && !f.is_lisp() &&
    /// !f.is_nix() && !f.is_blue())`, symmetric on the four siblings)
    /// are pinned by
    /// [`tests::format_identity_slices_agree_with_identity_predicates`].
    /// Partition invariant across all five:
    /// [`tests::format_identity_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::format_identity_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::format_identity_slices_have_no_duplicates`].
    /// Cardinality-agreement with the five boolean poles:
    /// [`tests::format_identity_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::format_identity_slices_are_const_addressable`].
    /// Cross-altitude weld with the compound-polarity pair:
    /// [`tests::format_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_YAML: &'static [Self] = &[Self::Yaml];

    /// The single [`Self::Toml`] pole of the five-way identity meta-
    /// partition on the [`Format`] axis at the static-slice altitude.
    /// Also the second cell of [`Self::ALWAYS_AVAILABLE`] — the two
    /// witnesses agree here (`ONLY_TOML ⊆ ALWAYS_AVAILABLE`) per the
    /// identity-vs-compound cross-check. See [`Self::ONLY_YAML`] for
    /// the full contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_TOML: &'static [Self] = &[Self::Toml];

    /// The single [`Self::Lisp`] pole of the five-way identity meta-
    /// partition on the [`Format`] axis at the static-slice altitude.
    /// Also the first cell of [`Self::FEATURE_GATED`] — the two
    /// witnesses agree here (`ONLY_LISP ⊆ FEATURE_GATED`) per the
    /// identity-vs-compound cross-check. See [`Self::ONLY_YAML`] for
    /// the full contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_LISP: &'static [Self] = &[Self::Lisp];

    /// The single [`Self::Nix`] pole of the five-way identity meta-
    /// partition on the [`Format`] axis at the static-slice altitude.
    /// Also the third cell of [`Self::ALWAYS_AVAILABLE`] — the two
    /// witnesses agree here (`ONLY_NIX ⊆ ALWAYS_AVAILABLE`), and its
    /// interleaved position in [`Self::ALL`] (between [`Self::Lisp`]
    /// and [`Self::Blue`]) means the identity-slice union on the
    /// always-available pole reproduces [`Self::ALWAYS_AVAILABLE`]'s
    /// neither-prefix-nor-suffix projection over [`Self::ALL`]. See
    /// [`Self::ONLY_YAML`] for the full contract, load-bearing pins,
    /// and idiom-peer landings.
    pub const ONLY_NIX: &'static [Self] = &[Self::Nix];

    /// The single [`Self::Blue`] pole of the five-way identity meta-
    /// partition on the [`Format`] axis at the static-slice altitude.
    /// Also the second cell of [`Self::FEATURE_GATED`] — the two
    /// witnesses agree here (`ONLY_BLUE ⊆ FEATURE_GATED`) per the
    /// identity-vs-compound cross-check. See [`Self::ONLY_YAML`] for
    /// the full contract, load-bearing pins, and idiom-peer landings.
    pub const ONLY_BLUE: &'static [Self] = &[Self::Blue];

    /// Canonical separator between the format token and the path in the
    /// `"<format>: <path>"` shape shikumi-built providers write into
    /// `figment::Metadata::name` for per-value attribution.
    ///
    /// The single source of truth for the separator on both directions of
    /// the metadata-name algebra. [`Self::metadata_name`] emits it after
    /// the [`Self::as_str`] token; [`Self::strip_metadata_name`] (and
    /// through it [`Self::parse_metadata_tag`]) strips it back off between
    /// the token and the trailing path. Before this constant the `": "`
    /// separator lived untypedly at two sites — the emitter's
    /// `format!("{self}: {}", ...)` and the resolver's per-variant
    /// `format!("{f}: ")` — that had to stay in lockstep by hand; a
    /// future change to the separator (e.g. tightening to `": "` with a
    /// tab prefix, or moving to an inequality-safe `" | "` when a `:` in
    /// a Windows path started confusing the leftmost-`:` split) required
    /// a paired edit at both sites. Now both directions route through
    /// this one `&'static str`, so a new shape lives at one site and the
    /// two directions cannot disagree.
    ///
    /// The value is a two-byte ASCII slice (`": "`), so [`str::strip_prefix`]
    /// against it is a byte-wise compare that never allocates — closing
    /// the second half of the drop-per-call `String` allocation the old
    /// [`Self::strip_metadata_name`] shape carried via `format!("{f}: ")`
    /// (the first half being the alias-canonical-name allocation, dropped
    /// by routing through [`Self::as_str`] as `&'static str`).
    ///
    /// Pinned by `tests::format_metadata_name_uses_metadata_name_separator`
    /// (writer routes through this const) and
    /// `tests::format_strip_metadata_name_routes_through_metadata_name_separator`
    /// (reader routes through this const), so the pair inherits the shape
    /// from one source of truth by construction.
    pub const METADATA_NAME_SEPARATOR: &'static str = ": ";

    /// Returns the file extensions associated with this format.
    ///
    /// The single source of truth for the `(Format → extension-alias set)`
    /// map. The first entry is the canonical extension (pinned by
    /// [`Self::as_str`] via
    /// `format_extensions_first_entry_matches_as_str`); the remainder are
    /// aliases the format also accepts. [`Self::from_extension`] is the
    /// inverse lookup — it iterates [`Self::ALL`] and matches an incoming
    /// token against each variant's extension slice ASCII-case-
    /// insensitively, so the alias set for a format lives at exactly one
    /// site rather than duplicated between this table and a mirrored
    /// per-alias match in [`Self::from_extension`]. Adding a new alias
    /// here automatically makes [`Self::from_extension`], [`Self::from_path`],
    /// [`<Self as std::str::FromStr>`], and [`<Self as TryFrom<&Path>>`]
    /// recognize it — no lockstep edit required.
    #[must_use]
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Toml => &["toml"],
            Self::Lisp => &["lisp", "lsp", "el"],
            Self::Nix => &["nix"],
            Self::Blue => &["b"],
        }
    }

    /// Infer format from a file extension string.
    ///
    /// ASCII-case-insensitive: `"YAML"`, `"Yml"`, and `"yaml"` all map to
    /// [`Self::Yaml`]. Returns `None` for unrecognized extensions.
    ///
    /// Derived from [`Self::extensions`] — the inverse lookup iterates
    /// [`Self::ALL`] and returns the first [`Format`] variant whose
    /// extension slice contains `ext` (compared via
    /// [`str::eq_ignore_ascii_case`]). Before this derivation the alias
    /// arms (`"yml"`/`"lsp"`/`"el"`/…) were mirrored in a second `match`
    /// here that had to be kept in lockstep with the extension table by
    /// hand; now the alias set lives at one site (in
    /// [`Self::extensions`]) and the two directions can never disagree —
    /// pinned by `format_from_extension_recognizes_every_declared_alias`
    /// and `format_extensions_and_from_extension_round_trip_over_all`.
    /// The derivation also drops the per-call `to_ascii_lowercase`
    /// allocation: [`str::eq_ignore_ascii_case`] compares byte-wise
    /// without materializing a lowered copy.
    ///
    /// Case-insensitivity matters on the nix-darwin deployment target,
    /// whose default filesystem is case-insensitive: an env-override
    /// path like `Config.YAML` reaches [`Self::from_path`] with an
    /// uppercase extension and must still resolve to YAML rather than
    /// falling through to the conservative TOML fallback in
    /// [`crate::ProviderChain::with_file`]. [`FromStr`] is the
    /// `ok_or_else` error-wrapping shell over this lookup — exactly as
    /// [`TryFrom<&Path>`] is the `ok_or_else` shell over
    /// [`Self::from_path`] — so the string parser inherits the same
    /// alias algebra without re-encoding it.
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|format| {
            format
                .extensions()
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(ext))
        })
    }

    /// Infer format from a path's file extension.
    ///
    /// The single source of truth for the `(path → Format)` detection
    /// triple — `path.extension().and_then(OsStr::to_str)
    /// .and_then(Format::from_extension)` — that
    /// [`crate::ProviderChain::with_file`] and the [`TryFrom<&Path>`] impl
    /// previously open-coded independently. Returns `None` when the path
    /// has no extension or an unrecognized one; [`TryFrom<&Path>`] wraps
    /// the `None` in a [`ShikumiError::Parse`], and `with_file` falls back
    /// to the TOML provider on `None`.
    ///
    /// Infallible counterpart of the [`TryFrom<&Path>`] impl, which is now
    /// the `ok_or_else` wrapper around this. Any future consumer that needs
    /// the extension-declared format of a path (e.g.
    /// [`crate::ConfigSource::file_format`]) routes through this one site,
    /// so a new [`Format`] variant becomes recognizable everywhere by
    /// extending [`Self::from_extension`] alone.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|e| e.to_str())
            .and_then(Self::from_extension)
    }

    /// Canonical operator-facing lowercase name of the format —
    /// `"yaml"`, `"toml"`, `"lisp"`, or `"nix"`.
    ///
    /// The single source of truth for the format-label strings on the
    /// [`Format`] axis. Inherent mirror of the [`crate::ClosedAxisLabel`]
    /// trait method; [`fmt::Display`] and [`Self::extensions`]'s first
    /// entry both delegate here so the canonical name lives at one site
    /// instead of being re-stated.
    ///
    /// `FromStr` accepts the alias extensions (`"yml"`/`"lsp"`/`"el"`) by
    /// delegating to [`Self::from_extension`], which enumerates every
    /// recognized extension case-insensitively; the canonical name is the
    /// `extensions()[0]` of each format, pinned by
    /// `format_extensions_first_entry_matches_as_str`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Toml => "toml",
            Self::Lisp => "lisp",
            Self::Nix => "nix",
            Self::Blue => "b",
        }
    }

    /// Operator-facing English message stating this format's top-level
    /// dict-required contract — the prefix the shikumi-built providers
    /// (`crate::LispProvider`, `crate::NixProvider`) emit when a parsed
    /// [`figment::value::Value`] turns out not to be a [`figment::value::Value::Dict`]
    /// at the root, to which the helper appends `"; got <Value:?>"` for
    /// the concrete diagnostic.
    ///
    /// One source of truth for the per-format "top-level X must be Y"
    /// wording on the shikumi-built-provider failure path:
    /// - [`Self::Yaml`] → `"top-level yaml document must be a mapping"`
    /// - [`Self::Toml`] → `"top-level toml document must be a table"`
    /// - [`Self::Lisp`] → `"top-level lisp form must be a kwargs list"`
    /// - [`Self::Nix`] → `"top-level nix expression must evaluate to an attrset"`
    ///
    /// The Lisp / Nix arms preserve the messages the two providers
    /// previously emitted verbatim — including the per-language verb
    /// ("must be" vs "must evaluate to") and noun ("form" / "expression")
    /// — so the operator-facing diagnostic does not drift on the lift.
    /// The YAML / TOML arms exist for total-coverage discipline: the
    /// figment-builtin file providers handle the dict-required check
    /// internally and never reach this method today, but a future
    /// shikumi-built provider class that wraps a figment-builtin format
    /// (e.g. a templating layer on top of YAML) would route through the
    /// matching arm here, and the YAML / TOML wordings are pinned now so
    /// that future arm cannot drift on the noun choice.
    ///
    /// Routed through by [`crate::provider::provider_data_from_value`],
    /// the value→`Map<Profile, Dict>` projection shared by every
    /// shikumi-built [`figment::Provider::data`] impl. The message lives
    /// at one site here — adding a new [`Format`] variant forces an arm
    /// in the exhaustive match in lockstep at compile time, and the
    /// existing wordings are pinned by
    /// `format_dict_required_message_pins_per_format_wording` so the
    /// lift cannot silently rewrite either provider's diagnostic.
    #[must_use]
    pub const fn dict_required_message(self) -> &'static str {
        match self {
            Self::Yaml => "top-level yaml document must be a mapping",
            Self::Toml => "top-level toml document must be a table",
            Self::Lisp => "top-level lisp form must be a kwargs list",
            Self::Nix => "top-level nix expression must evaluate to an attrset",
            Self::Blue => "top-level blue form must be a kwargs list",
        }
    }

    /// Closed-enum classification of which provider class loads this
    /// format — the typed partition over the [`Format`] variant space
    /// along the (figment-builtin × shikumi-built) axis.
    ///
    /// One source of truth for the provenance axis: consumers route on
    /// the returned [`FormatProvenance`] (in `match`, `HashMap` keys,
    /// log labels, attestation manifest payloads) instead of re-deriving
    /// the partition from per-variant `matches!` against
    /// `Format::Lisp | Format::Nix`. The accessor composes the rule
    /// space with the attribution surface: the (provenance × file-rule)
    /// invariant `format.provenance().file_attribution_rule() ==
    /// AttributionRule` for file-axis attributions is structural, pinned
    /// by [`FormatProvenance::file_attribution_rule`].
    ///
    /// Strict superset of [`Self::has_shikumi_provider`]:
    /// `format.has_shikumi_provider()` is
    /// `format.provenance() == FormatProvenance::ShikumiBuilt`. The
    /// predicate remains as a convenience accessor; new code that needs
    /// to distinguish more than the binary should prefer this one closed
    /// enum, matching the typescape discipline of the sibling closed-enum
    /// primitives ([`crate::AttributionConfidence`],
    /// [`crate::AttributionAxis`], [`crate::ConfigSourceKind`],
    /// [`FormatProvenance`]).
    ///
    /// The implementation is one exhaustive `match`, so a future
    /// [`Format`] variant landing forces a corresponding
    /// [`FormatProvenance`] assignment in lockstep at compile time —
    /// the provenance partition stays coherent by construction. The
    /// `format_provenance_partitions_every_variant` test pins the
    /// partition is total (every variant maps to exactly one provenance).
    ///
    /// `const`-callable — the body is an exhaustive match over the
    /// five payload-free [`Copy`] variants of [`Self`] projecting into
    /// unit variants of [`FormatProvenance`], both const-eligible under
    /// rustc 1.89. Idiom-peer of the sibling per-variant boolean
    /// projections [`Self::is_yaml`] / [`Self::is_toml`] /
    /// [`Self::is_lisp`] / [`Self::is_nix`] / [`Self::is_blue`] (all
    /// const since their landing) and the sibling closed-enum
    /// projection [`crate::AttributionRule::layer_kind`] (const since
    /// commit `52c4a20`): the format axis now carries the same
    /// const-callability discipline on its (format → provenance)
    /// closed-enum projection that the attribution axis carries on
    /// its (rule → layer-kind) projection. A compile-time-known
    /// [`Format`] now projects into [`FormatProvenance`] at compile
    /// time too, so a `static PROVENANCE: FormatProvenance =
    /// Format::_.provenance()` diagnostic table can be wired without
    /// the projection dropping the caller off the const-context edge.
    /// Welded at compile time by
    /// [`tests::format_provenance_projection_is_const_callable`].
    #[must_use]
    pub const fn provenance(self) -> FormatProvenance {
        match self {
            Self::Lisp | Self::Nix | Self::Blue => FormatProvenance::ShikumiBuilt,
            Self::Yaml | Self::Toml => FormatProvenance::FigmentBuiltin,
        }
    }

    /// Forward unifier of the two orthogonal projections over this
    /// format: [`Self`] (the format itself) and [`Self::provenance`]
    /// (the provider class that loads it). Returns the format's
    /// coordinates as a typed [`FormatCoordinates`] envelope.
    ///
    /// One source of truth for the (format, provenance) cell read.
    /// Before this method, observers that wanted the full coordinate
    /// pair inlined two reads (`(format, format.provenance())`) at
    /// every site; the named struct collapses the two reads into one
    /// and surfaces the pair as a typescape-eligible value
    /// (`Copy + Eq + Hash + #[non_exhaustive]`) usable in `match`,
    /// `HashMap` keys, log labels, alerting buckets, and attestation
    /// manifest payloads.
    ///
    /// Pairs with [`FormatCoordinates::format_or_none`] as the partial
    /// inverse: `FormatCoordinates::format_or_none(self.format_coordinates())
    /// == Some(self)` for every [`Format`] variant — the bijection on
    /// the recognized half is pinned by
    /// `format_coordinates_round_trip_through_format_or_none_on_recognized_cells`.
    /// The forward map is total over the format space; the inverse is
    /// partial, returning [`None`] for the four product cells of the
    /// (format × provenance) cube where the cell's provenance
    /// disagrees with the format's declared one.
    ///
    /// Peer to [`crate::AttributionRule::coordinates`]: same forward-
    /// total / inverse-partial discipline lifted on a different sibling
    /// pair. The substrate now has two product-axis envelope shapes
    /// over the typescape primitive set, both following the same
    /// forward-total / inverse-partial round-trip law.
    #[must_use]
    pub fn format_coordinates(self) -> FormatCoordinates {
        FormatCoordinates {
            format: self,
            provenance: self.provenance(),
        }
    }

    /// Whether this format is loaded by a shikumi-built figment provider
    /// (as opposed to delegating to one of figment's built-in providers).
    ///
    /// `true` for [`Format::Lisp`] (loaded by [`crate::LispProvider`])
    /// and [`Format::Nix`] (loaded by [`crate::NixProvider`]); these
    /// providers tag per-value attribution via
    /// `figment::Metadata::name = "<format>: <path>"` (see
    /// [`Self::metadata_name`]).
    ///
    /// `false` for [`Format::Yaml`] and [`Format::Toml`], which
    /// [`crate::ProviderChain::with_file`] hands off to
    /// `figment::providers::Yaml` / `figment::providers::Toml`. Those
    /// providers tag per-value attribution via
    /// `figment::Metadata::source = figment::Source::File(_)` instead,
    /// so [`crate::ShikumiError::failing_source`] resolves them by path
    /// equality rather than by metadata-name prefix.
    ///
    /// Convenience over [`Self::provenance`]; equivalent to
    /// `self.provenance() == FormatProvenance::ShikumiBuilt`. New code
    /// that needs to distinguish more than the binary should prefer the
    /// typed accessor.
    #[must_use]
    pub fn has_shikumi_provider(self) -> bool {
        matches!(self.provenance(), FormatProvenance::ShikumiBuilt)
    }

    /// Whether this format is loaded by one of figment's built-in
    /// providers (as opposed to a shikumi-built provider).
    ///
    /// `true` for [`Format::Yaml`] and [`Format::Toml`], which
    /// [`crate::ProviderChain::with_file`] hands off to
    /// `figment::providers::Yaml` / `figment::providers::Toml`. Those
    /// providers tag per-value attribution via
    /// `figment::Metadata::source = figment::Source::File(_)`, so
    /// [`crate::ShikumiError::failing_source`] resolves them by path
    /// equality rather than by metadata-name prefix.
    ///
    /// `false` for [`Format::Lisp`] (loaded by [`crate::LispProvider`])
    /// and [`Format::Nix`] (loaded by [`crate::NixProvider`]); those
    /// providers tag per-value attribution via
    /// `figment::Metadata::name = "<format>: <path>"` (see
    /// [`Self::metadata_name`]).
    ///
    /// The source-altitude peer of [`FormatProvenance::is_figment_builtin`],
    /// closing the two-corner sibling-predicate pair on the source
    /// altitude that the provenance altitude already closed
    /// ([`FormatProvenance::is_figment_builtin`] /
    /// [`FormatProvenance::is_shikumi_built`]). Peer of the shikumi-side
    /// [`Self::has_shikumi_provider`]: the two predicates form a
    /// closed binary partition over [`Format::ALL`], pinned pointwise
    /// by `format_provider_class_predicates_are_a_closed_binary_partition`.
    /// The partition-symmetric shape means consumers reading the
    /// figment-builtin half of the (figment-builtin × shikumi-built)
    /// axis no longer negate `has_shikumi_provider` — a shape whose
    /// polarity a future tertiary provider class (e.g. a Vault or HTTP
    /// provider that is neither) would silently flip: `!has_shikumi_provider`
    /// would then include the tertiary alongside the figment-builtin
    /// half, whereas the direct predicate stays true only for the
    /// figment-builtin cell and forces the tertiary provider class to
    /// declare its own predicate.
    ///
    /// Convenience over [`Self::provenance`]; equivalent to
    /// `self.provenance() == FormatProvenance::FigmentBuiltin`. New code
    /// that needs to distinguish more than the binary should prefer the
    /// typed accessor.
    #[must_use]
    pub fn has_figment_builtin_provider(self) -> bool {
        matches!(self.provenance(), FormatProvenance::FigmentBuiltin)
    }

    /// The cargo feature that must be enabled for [`crate::ProviderChain::with_file`]
    /// to actually parse a file of this format, or [`None`] when the format
    /// is always available in every build.
    ///
    /// Today's mapping (pinned per-variant by
    /// [`tests::format_required_feature_pinned_per_variant`]):
    ///
    /// - [`Self::Yaml`] / [`Self::Toml`] → [`None`] (figment-builtin;
    ///   parsed by `figment::providers::Yaml` / `figment::providers::Toml`,
    ///   which are unconditional dependencies).
    /// - [`Self::Nix`] → [`None`] (shikumi-built but always shipped;
    ///   [`crate::NixProvider`] shells out to `nix eval`, so it carries no
    ///   extra Rust dep beyond what shikumi already links).
    /// - [`Self::Lisp`] → [`Some("lisp")`] ([`crate::lisp_provider`] is
    ///   `#[cfg(feature = "lisp")]`-gated; the `tatara-lisp` dep is
    ///   optional).
    /// - [`Self::Blue`] → [`Some("blue")`] ([`crate::blue_provider`] is
    ///   `#[cfg(feature = "blue")]`-gated; the `blue-lang-syntax` dep is
    ///   optional).
    ///
    /// One source of truth for the (format → optional-feature) projection.
    /// Before this accessor, the `(Format, required_feature)` correspondence
    /// was implicit — split across the `#[cfg(feature = "…")] mod
    /// <provider>;` gates in [`crate::lib`], the two
    /// `merge_or_warn_missing_feature!` calls inside
    /// [`crate::ProviderChain::with_file`] (which pass the feature literal as
    /// the `feature = "…"` macro arg), and the fallback prose inside
    /// [`crate::provider::missing_feature_warning_body`] — with `Format`
    /// itself carrying no typed knowledge of which feature (if any) any
    /// given variant requires. That's the drift-class the sibling typed
    /// accessors on this type ([`Self::extensions`], [`Self::as_str`],
    /// [`Self::dict_required_message`], [`Self::provenance`],
    /// [`Self::has_shikumi_provider`], [`Self::has_figment_builtin_provider`])
    /// each close on their own axis: pin one typed answer per format-axis
    /// question at ONE named site.
    ///
    /// Widens the compile-time invariant surface: a future [`Format`]
    /// variant landing forces an arm in the exhaustive match here in
    /// lockstep with its module gate — the compiler enforces the axis
    /// declaration. A future rename of an existing feature (e.g. `blue` →
    /// `blue-syntax`) lands as a paired edit at exactly two sites — this
    /// accessor's match arm, and the module gate in [`crate::lib`] — with
    /// [`tests::format_required_feature_agrees_with_lib_rs_module_gates`]
    /// pinning the two sites in lockstep and
    /// [`tests::format_required_feature_agrees_with_provider_macro_call_sites`]
    /// pinning that the two
    /// [`merge_or_warn_missing_feature!`](crate::provider::merge_or_warn_missing_feature)
    /// call sites in [`crate::provider::ProviderChain::with_file`] each pass
    /// the same feature literal this accessor returns.
    ///
    /// **Structural invariants** (pinned by tests):
    ///
    /// - `f.required_feature().is_some()` implies
    ///   `f.has_shikumi_provider()` — every feature-gated format is
    ///   shikumi-built. The converse does not hold (`Format::Nix` is
    ///   shikumi-built but returns [`None`]). Pinned by
    ///   [`tests::format_required_feature_some_implies_shikumi_built`].
    /// - `f.has_figment_builtin_provider()` implies
    ///   `f.required_feature() == None` — figment-builtin formats are
    ///   always available. Pinned by
    ///   [`tests::format_figment_builtin_implies_no_required_feature`].
    /// - Every returned feature literal appears in the crate's `Cargo.toml`
    ///   `[features]` table. Pinned by
    ///   [`tests::format_required_feature_names_appear_in_cargo_toml_features_table`].
    ///
    /// **Composes with the (`Format`, `FormatProvenance`) cube.** The
    /// (`provenance == ShikumiBuilt`, `required_feature == Some`) cells are
    /// the fiber of formats that are both shikumi-built AND feature-gated
    /// (`Lisp`, `Blue`). The (`ShikumiBuilt`, `None`) cell is exactly
    /// [`Self::Nix`]; the (`FigmentBuiltin`, `None`) cells are exactly
    /// [`Self::Yaml`] and [`Self::Toml`]; the (`FigmentBuiltin`, `Some`)
    /// cell is empty by the first invariant above and impossible by
    /// construction.
    ///
    /// **Intended consumers.** A ConfigPlane / fleet diagnostic surface
    /// answering "which cargo features must be enabled to load `.b`?" reads
    /// [`Format::Blue.required_feature()`]. An attestation manifest
    /// recording the feature set a resolved config depended on reads this
    /// accessor over the recorded [`crate::ConfigSource::File`] chain. The
    /// operator-facing missing-feature warning body
    /// ([`crate::provider::missing_feature_warning_body`]) now derives its
    /// feature label through this accessor rather than accepting it as a
    /// caller-passed argument, closing the last duplication between the
    /// macro literal and the warning prose: the
    /// [`merge_or_warn_missing_feature!`](crate::provider::merge_or_warn_missing_feature)
    /// macro's `$feat` literal is now used only for the `#[cfg(feature =
    /// $feat)]` gate itself, and the warning body reads the feature label
    /// off the `$format` argument via this accessor.
    #[must_use]
    pub const fn required_feature(self) -> Option<&'static str> {
        match self {
            Self::Yaml | Self::Toml | Self::Nix => None,
            Self::Lisp => Some("lisp"),
            Self::Blue => Some("blue"),
        }
    }

    /// Canonical `figment::Metadata::name` shape used by shikumi-built
    /// providers for per-value attribution: `"<format>: <path>"` (e.g.
    /// `"lisp: /home/u/.config/app/app.lisp"`,
    /// `"nix: /etc/app/app.nix"`).
    ///
    /// The `<format>` token is the [`fmt::Display`] form of the variant
    /// (which delegates to [`Self::as_str`] via the
    /// `closed_axis_label_string_surface!` macro), so [`Self::as_str`]
    /// is the single source of truth for the token shape on both sides
    /// of attribution. The `": "` separator between the token and the
    /// path routes through [`Self::METADATA_NAME_SEPARATOR`] — the
    /// second single source of truth on the same shape — so a resolver
    /// that consumes the emission ([`Self::strip_metadata_name`] and
    /// [`Self::parse_metadata_tag`]) reads the same bytes the emitter
    /// wrote without a duplicated separator literal that could drift.
    ///
    /// Defined for every [`Format`] variant — including those for which
    /// [`Self::has_shikumi_provider`] returns `false` — so the morphism
    /// is total. Callers that only care about shikumi-built emissions
    /// should gate on `has_shikumi_provider` first; resolvers that need
    /// to invert can use [`Self::strip_metadata_name`] which already
    /// filters to the shikumi-provider subset.
    ///
    /// Composed from [`Self::write_metadata_name`] via
    /// [`FormatMetadataTag`]'s [`fmt::Display`] impl (`ToString`
    /// allocates one `String` and drives the same alloc-free write-side
    /// helper the `Display` surface uses), so the emission shape lives
    /// at ONE named site — `write_metadata_name` — and both this
    /// allocating surface and the alloc-free `Display` path on
    /// [`FormatMetadataTag`] inherit it by construction.
    #[must_use]
    pub fn metadata_name(self, path: &Path) -> String {
        FormatMetadataTag { format: self, path }.to_string()
    }

    /// Alloc-free write-side of [`Self::metadata_name`]: emit the
    /// canonical `"<format>: <path>"` shape into any [`fmt::Write`].
    ///
    /// This is the ONE named site the `<format>` token, the
    /// [`Self::METADATA_NAME_SEPARATOR`], and the [`Path::display`]
    /// projection compose at. Both consumers — [`Self::metadata_name`]
    /// (via a `String` buffer) and the [`fmt::Display`] impl on
    /// [`FormatMetadataTag`] (via a `fmt::Formatter`, no allocation) —
    /// route through this helper, so a future change to the emission
    /// shape (a wider separator, a Windows-safe path renderer, a
    /// version-tagged prefix) lands at one site and every consumer
    /// inherits it by construction. Before this helper the
    /// `write!(f, "{}: {}", self.format, self.path.display())` inside
    /// `Display::fmt` carried a *third* independent `": "` literal that
    /// had to agree with the emitter's `format!("{}{}{}", …,
    /// METADATA_NAME_SEPARATOR, …)` and the resolver's `strip_prefix`
    /// chain by hand — the compiler enforced nothing between them.
    ///
    /// Pinned by
    /// [`tests::format_write_metadata_name_matches_format_metadata_name`]
    /// (byte-equality across every `(Format, Path)` pair) and by
    /// [`tests::format_metadata_tag_display_matches_format_metadata_name`]
    /// (the pre-existing transitive pin on the `Display` surface).
    pub(crate) fn write_metadata_name<W: fmt::Write>(self, w: &mut W, path: &Path) -> fmt::Result {
        write!(
            w,
            "{}{}{}",
            self.as_str(),
            Self::METADATA_NAME_SEPARATOR,
            path.display()
        )
    }

    /// Inverse of [`Self::metadata_name`]: try to recognize `name` as a
    /// shikumi-built provider's metadata-name and recover the
    /// `(format, path_str)` pair.
    ///
    /// Iterates [`FormatProvenance::ShikumiBuilt::formats`] in declaration
    /// order and, for each candidate, strips the format's canonical token
    /// ([`Self::as_str`]) from the head of `name` and then the shared
    /// [`Self::METADATA_NAME_SEPARATOR`] from what remains — the exact
    /// two-step inverse of the `format!("{}{}{}", as_str(), separator,
    /// path.display())` shape [`Self::metadata_name`] writes. The first
    /// matching variant wins; the trailing substring is returned by
    /// reference into `name` so callers don't allocate.
    ///
    /// **Alloc-free.** Prior to routing through [`Self::as_str`] and
    /// [`Self::METADATA_NAME_SEPARATOR`], each candidate iteration built
    /// its `"<format>: "` prefix through `format!("{f}: ")`, allocating a
    /// fresh `String` per variant tried — up to three heap allocations per
    /// call across the [`FormatProvenance::ShikumiBuilt`] cohort even on
    /// the miss path. The classifier now reduces to byte-wise
    /// [`str::strip_prefix`] compares against two `&'static str` slices,
    /// so a resolver iterating a long chain of `figment::Metadata` (the
    /// [`crate::ShikumiError::failing_source`] path) no longer drips
    /// per-cell allocations.
    ///
    /// Returns `None` for `figment::Metadata::name` values produced by
    /// figment's built-in YAML/TOML providers (which use `Source::File`
    /// instead of name-based attribution), for unrelated metadata names,
    /// and for the empty string. Used by
    /// [`crate::ShikumiError::failing_source`] to map figment metadata
    /// back to a [`crate::ConfigSource`] in the recorded chain.
    ///
    /// Untyped sibling of [`Self::parse_metadata_tag`], which returns the
    /// same information as a typed [`FormatMetadataTag`] envelope (named
    /// fields, [`Path`]-typed trailing slice). New code should prefer the
    /// envelope; this function is retained as the lower-level
    /// `(Format, &str)` projection.
    #[must_use]
    pub fn strip_metadata_name(name: &str) -> Option<(Self, &str)> {
        FormatProvenance::ShikumiBuilt
            .formats()
            .iter()
            .find_map(|f| {
                name.strip_prefix(f.as_str())
                    .and_then(|rest| rest.strip_prefix(Self::METADATA_NAME_SEPARATOR))
                    .map(|rest| (*f, rest))
            })
    }

    /// Typed-envelope inverse of [`Self::metadata_name`]: recognize `name`
    /// as a shikumi-built provider's `"<format>: <path>"` shape and
    /// return both the [`Format`] that emitted it and the trailing path
    /// (as a [`Path`], borrowed into `name`).
    ///
    /// Strict superset of [`Self::strip_metadata_name`]: same `Some` /
    /// `None` conditions and same iteration order, but on `Some` returns
    /// a [`FormatMetadataTag`] with named fields and a [`Path`]-typed
    /// trailing slice instead of an `(Self, &str)` positional tuple.
    /// Callers no longer wrap the trailing slice in [`Path::new`] at
    /// every site that wants to compare it against a
    /// [`crate::ConfigSource::File`] entry.
    ///
    /// One source of truth for the metadata-name-axis dispatch on the
    /// shikumi-provider sub-axis; pairs with
    /// [`crate::ConfigSource::strip_env_metadata_name`] (env-name-axis)
    /// and [`crate::FigmentSourceTag::classify`] (figment-Source-axis)
    /// as the third typed primitive on the failing-source attribution
    /// surface. The four typed shapes (`FormatMetadataTag`,
    /// `EnvMetadataTag`, `FigmentSourceTag`, `AttributionRule`) close
    /// the figment-metadata × shikumi-source coordinate space.
    #[must_use]
    pub fn parse_metadata_tag(name: &str) -> Option<FormatMetadataTag<'_>> {
        Self::strip_metadata_name(name).map(|(format, rest)| FormatMetadataTag {
            format,
            path: Path::new(rest),
        })
    }

    /// Returns `true` for [`Self::Yaml`]; equivalent to
    /// `self == Format::Yaml`. Sibling of [`Self::is_toml`],
    /// [`Self::is_lisp`], [`Self::is_nix`], and [`Self::is_blue`] — the
    /// closed quinary partition of the config-file-format axis lifted to
    /// five named `const fn` predicates at the primitive's altitude,
    /// mirror of the tag-side quintet [`crate::cli::TierArg::is_bare`] /
    /// [`crate::cli::TierArg::is_discovered`] /
    /// [`crate::cli::TierArg::is_default`] /
    /// [`crate::cli::TierArg::is_custom`] / [`crate::cli::TierArg::is_env`]
    /// and of the quartet-shape [`crate::ConfigTier::is_bare`] /
    /// [`crate::ConfigTier::is_discovered`] /
    /// [`crate::ConfigTier::is_default`] / [`crate::ConfigTier::is_custom`].
    ///
    /// One source of truth for the "is this the YAML format?" question
    /// over [`Format`] — a consumer that only wants the yes/no answer
    /// (a per-format load-latency histogram bin, an attestation manifest
    /// grouping by format, a doc-render iterating [`Format::ALL`] and
    /// keying rows by format, a CLI flag filtering discovered files by
    /// format) matches on this predicate instead of open-coding
    /// `matches!(f, Format::Yaml)` or `f == Format::Yaml` and paying
    /// the closed-partition bookkeeping tax again. The five sibling
    /// predicates form a closed disjoint partition of the variant space
    /// — every [`Format`] value satisfies exactly one — pinned by
    /// [`tests::format_predicates_are_a_closed_quinary_partition`], the
    /// quinary analogue of the ternary-partition pin on
    /// [`crate::WatchEventClass`] and of the quaternary-partition pins
    /// on [`crate::ConfigTier`] and [`crate::coverage::HintSurface`].
    #[must_use]
    pub const fn is_yaml(self) -> bool {
        matches!(self, Self::Yaml)
    }

    /// Returns `true` for [`Self::Toml`]; equivalent to
    /// `self == Format::Toml`. Sibling of [`Self::is_yaml`];
    /// see [`Self::is_yaml`] for the full contract.
    #[must_use]
    pub const fn is_toml(self) -> bool {
        matches!(self, Self::Toml)
    }

    /// Returns `true` for [`Self::Lisp`]; equivalent to
    /// `self == Format::Lisp`. Sibling of [`Self::is_yaml`];
    /// see [`Self::is_yaml`] for the full contract.
    #[must_use]
    pub const fn is_lisp(self) -> bool {
        matches!(self, Self::Lisp)
    }

    /// Returns `true` for [`Self::Nix`]; equivalent to
    /// `self == Format::Nix`. Sibling of [`Self::is_yaml`];
    /// see [`Self::is_yaml`] for the full contract.
    #[must_use]
    pub const fn is_nix(self) -> bool {
        matches!(self, Self::Nix)
    }

    /// Returns `true` for [`Self::Blue`]; equivalent to
    /// `self == Format::Blue`. Sibling of [`Self::is_yaml`];
    /// see [`Self::is_yaml`] for the full contract.
    #[must_use]
    pub const fn is_blue(self) -> bool {
        matches!(self, Self::Blue)
    }

    /// Returns `true` for the feature-gated pole of the [`Format`] axis —
    /// [`Self::Lisp`] (gated by the `lisp` cargo feature) and
    /// [`Self::Blue`] (gated by the `blue` cargo feature) — `false` for
    /// [`Self::Yaml`], [`Self::Toml`], and [`Self::Nix`].
    ///
    /// Names the *format whose provider is behind an optional cargo
    /// feature* pole of the (feature-gated × always-available) polarity
    /// axis at the type level, so consumers reading *"is loading this
    /// format only possible in a build that opted into an optional
    /// feature, or does it work in every build?"* — a per-format
    /// discovery-cost telemetry counter bucketing feature-gated formats
    /// separately, an attestation manifest recording whether a resolved
    /// config depended on an optional cargo feature, a structured-log
    /// legend routing on the feature-gated pole at the parsed-source
    /// altitude, an operator-facing dashboard row grouping the two
    /// feature-gated formats under one heading — spell the *positive*
    /// form of the query at the call site instead of the two-arm
    /// disjunction `f.is_lisp() || f.is_blue()` or the two-step
    /// composition `f.required_feature().is_some()`.
    ///
    /// Format-axis compound-polarity sibling of
    /// [`crate::SecretBackendKind::is_cloud_secret_manager`] (commit
    /// `3553207`) / [`crate::SecretSource::is_cloud_secret_manager`]
    /// (commit `dc2ee39`) on the secret-backend axis,
    /// [`crate::ConfigTierKind::is_computed`] (commit `7d2825d`) on the
    /// tier axis, and [`crate::ConfigSourceKind::is_overlay`] (commit
    /// `48c625b`) on the source axis — same *the substrate now names
    /// the compound pole* discipline, applied here to the five-way
    /// config-file-format axis. The next-tick candidate the
    /// `SecretSource::is_cloud_secret_manager` commit body (`dc2ee39`)
    /// explicitly flagged.
    ///
    /// The compound ↔ two-arm disjunction law
    /// (`f.is_feature_gated() == f.is_lisp() || f.is_blue()`) and the
    /// compound ↔ [`Self::required_feature`] `is_some` law
    /// (`f.is_feature_gated() == f.required_feature().is_some()`) are
    /// structural invariants pinned by
    /// [`tests::format_is_feature_gated_agrees_with_or_of_individual_siblings`]
    /// and
    /// [`tests::format_is_feature_gated_agrees_with_required_feature_is_some`].
    /// Together they collapse the two composition paths — the two-arm
    /// disjunction on the tag axis and the two-step composition through
    /// the [`Option<&'static str>`] projection — onto ONE named
    /// predicate at the type level.
    ///
    /// The (subset) invariant `f.is_feature_gated()` implies
    /// [`Self::has_shikumi_provider`] — every feature-gated format is
    /// shikumi-built (the figment-builtin providers ship unconditionally
    /// per [`tests::format_required_feature_some_implies_shikumi_built`])
    /// — is pinned by
    /// [`tests::format_is_feature_gated_implies_shikumi_built`], stating
    /// the subset law at the type-level compound predicate rather than
    /// through the [`Option`] projection.
    ///
    /// `const`-callable — matching the `const`-ness of the sibling
    /// per-variant predicates ([`Self::is_yaml`], …, [`Self::is_blue`])
    /// and of [`Self::required_feature`], so a
    /// `f.is_feature_gated()` composition stays const-callable
    /// end-to-end. The compile-time weld is pinned by
    /// [`tests::format_is_feature_gated_is_const_callable`].
    ///
    /// A future sixth [`Format`] variant landing behind an optional
    /// feature (a hypothetical `Cue` behind `cue`, a `Jsonnet` behind
    /// `jsonnet`) must extend the `matches!` arm here in lockstep with
    /// the five-way partition — otherwise the compound ↔ disjunction
    /// law fails on the new variant, catching the drift before it
    /// reaches any per-polarity consumer site.
    #[must_use]
    pub const fn is_feature_gated(self) -> bool {
        matches!(self, Self::Lisp | Self::Blue)
    }

    /// Returns `true` for the always-available pole of the [`Format`]
    /// axis — [`Self::Yaml`], [`Self::Toml`], and [`Self::Nix`] — `false`
    /// for the two feature-gated variants ([`Self::Lisp`], [`Self::Blue`]).
    ///
    /// Complementary pole of [`Self::is_feature_gated`] on the same
    /// (feature-gated × always-available) polarity axis; equivalent to
    /// `!self.is_feature_gated()` and to
    /// `self.required_feature().is_none()`. Named separately (rather
    /// than left as a negation) so consumers reading the
    /// always-available half of the axis no longer negate
    /// [`Self::is_feature_gated`] — a shape whose polarity a future
    /// tertiary axis (e.g. a *runtime-only* provider class that's
    /// neither compile-time feature-gated nor unconditionally
    /// available, like a hypothetical HTTP-config provider requiring
    /// a live network probe) would silently flip: `!is_feature_gated`
    /// would then include the tertiary alongside the always-available
    /// half, whereas the direct predicate stays true only for the
    /// unconditional cells and forces the tertiary class to declare
    /// its own predicate.
    ///
    /// Peer of the (`has_figment_builtin_provider`,
    /// `has_shikumi_provider`) closed binary partition on the same
    /// [`Format`] altitude: both name each pole directly rather than
    /// through the other's negation. Pinned as a closed disjoint
    /// binary partition of [`Format::ALL`] pointwise by
    /// [`tests::format_feature_gating_predicates_are_a_closed_binary_partition`].
    #[must_use]
    pub const fn is_always_available(self) -> bool {
        matches!(self, Self::Yaml | Self::Toml | Self::Nix)
    }
}

/// Closed binary partition over the [`Format`] variant space along the
/// (figment-builtin × shikumi-built) axis: which provider class loads
/// values of this format.
///
/// [`Format::provenance`] is the canonical map. The shape is named
/// (rather than a `bool` flag) so consumers don't re-invent
/// `is_shikumi_built: bool` at every observation site, and so a future
/// tertiary provider class (e.g. an upstream-figment-ecosystem provider
/// that's neither figment's own builtin nor shikumi's own — a Vault
/// provider, an HTTP-config provider) lands as one new variant peer to
/// the existing two.
///
/// Composes with the failing-source attribution surface: the
/// (provenance × file-rule) invariant pins
/// [`Self::FigmentBuiltin`] file failures to attribute via
/// [`crate::AttributionRule::FileBySource`] (path equality on
/// `metadata.source`), and [`Self::ShikumiBuilt`] file failures to
/// attribute via [`crate::AttributionRule::FileByMetadataName`] (path
/// equality on parsed `metadata.name`). [`Self::file_attribution_rule`]
/// is the canonical map; the (axis × provenance) projection
/// [`Self::file_attribution_axis`] mirrors
/// [`crate::AttributionRule::metadata_axis`] on the file sub-axis. Both
/// invariants are pinned by
/// `format_provenance_file_attribution_rule_agrees_with_resolver_pointwise`.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, matching the typescape
/// discipline of the sibling closed-enum primitives
/// ([`crate::AttributionConfidence`], [`crate::AttributionAxis`],
/// [`crate::ConfigSourceKind`], [`crate::ShikumiErrorKind`],
/// [`crate::FieldPathLocalization`]): closed, allocation-free,
/// extensible without breaking exhaustivity at consumer matches when a
/// future provider class lands.
///
/// **Trait surface** — alongside the canonical
/// `Debug + Clone + Copy + PartialEq + Eq + Hash` set, the derive also
/// includes [`Ord`] + [`PartialOrd`]. The total order is the
/// declaration-order lex over [`Self::ALL`]
/// (`FigmentBuiltin < ShikumiBuilt`), so a
/// [`BTreeMap<FormatProvenance, T>`][std::collections::BTreeMap] keyed
/// on the provenance axis (per-provenance attribution histograms,
/// per-provenance failure-rate dashboards, attestation manifests
/// recording provenance-axis cardinality mixes) emits rows in
/// declaration order deterministically without a hand-rolled
/// comparator at the renderer. Idiom-peer of the [`Ord`] derive on
/// [`Format`] (commit `b56b121`) and on the typed-cube classifiers
/// ([`crate::ModalityClass`], [`crate::PartitionFace`], …); pinned by
/// [`tests::format_provenance_ord_matches_all_declaration_order`].
///
/// **Serde surface** — [`serde::Serialize`] / [`serde::Deserialize`]
/// are implemented manually as the canonical idiom-peer of the
/// inherent [`Self::as_str`] / [`std::str::FromStr`] pair. Serialize
/// emits the canonical kebab-case label [`Self::as_str`] returns
/// (`"figment-builtin"` / `"shikumi-built"`); Deserialize lowers
/// through [`<Self as std::str::FromStr>::from_str`], inheriting the
/// trait-default case-insensitivity from
/// [`crate::ClosedAxisLabel::from_canonical_str`]. An attestation
/// manifest field recording which provider class loaded a config, a
/// structured-log payload carrying the resolved provenance, or a
/// consumer struct holding a [`FormatProvenance`] under
/// `#[derive(Serialize, Deserialize)]` round-trips through the
/// canonical label without a consumer-side rename helper. Pinned by
/// [`tests::format_provenance_serde_yaml_round_trips_over_every_variant`],
/// [`tests::format_provenance_serde_json_round_trips_over_every_variant`],
/// [`tests::format_provenance_serde_yaml_is_case_insensitive`], and
/// [`tests::format_provenance_serde_yaml_unknown_provenance_error_carries_label_verbatim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub enum FormatProvenance {
    /// Loaded by one of figment's built-in providers
    /// (`figment::providers::Yaml`, `figment::providers::Toml`).
    /// Per-value attribution arrives as
    /// `figment::Metadata::source = figment::Source::File(_)`; the
    /// failing-source resolver dispatches to
    /// [`crate::AttributionRule::FileBySource`] on the
    /// [`crate::AttributionAxis::MetadataSource`] axis. Today's
    /// inhabitants: [`Format::Yaml`], [`Format::Toml`].
    FigmentBuiltin,
    /// Loaded by a shikumi-built figment provider
    /// ([`crate::LispProvider`] for [`Format::Lisp`],
    /// [`crate::NixProvider`] for [`Format::Nix`]). Per-value
    /// attribution arrives as
    /// `figment::Metadata::name = "<format>: <path>"` (see
    /// [`Format::metadata_name`]); the failing-source resolver
    /// dispatches to [`crate::AttributionRule::FileByMetadataName`] on
    /// the [`crate::AttributionAxis::MetadataName`] axis.
    ShikumiBuilt,
}

impl FormatProvenance {
    /// Every recognized provenance cell, in declaration order
    /// ([`Self::FigmentBuiltin`], [`Self::ShikumiBuilt`]).
    ///
    /// One source of truth for the provenance-axis universe. Peer to
    /// [`Format::ALL`] on the format axis,
    /// [`crate::ShikumiErrorKind::ALL`] on the kind axis,
    /// [`crate::AttributionRule::ALL`] on the rule axis,
    /// [`crate::ConfigSourceKind::ALL`] on the layer-kind axis, and
    /// [`crate::FieldPathLocalization::ALL`] on the
    /// field-path-localization axis: the same typescape discipline
    /// (closed `'static` slice, in declaration order) applied to the
    /// provenance axis. Consumers iterating "every recognized
    /// provenance" (per-cell alert thresholds, dashboards, attestation
    /// manifests recording the provenance space's cardinality,
    /// structured-diagnostics legends, partition-coverage tests) read
    /// this constant instead of hard-coding the variant list, which
    /// would have to be kept manually in lockstep with the enum's
    /// variant set.
    ///
    /// Adding a new variant to [`FormatProvenance`] means extending
    /// this slice in lockstep with the variant itself. The compiler
    /// enforces nothing here directly, so the
    /// `format_provenance_all_covers_every_provenance_over_format_all`
    /// test pins the contract by asserting that every value produced
    /// by [`Format::provenance`] over [`Format::ALL`] appears in
    /// [`Self::ALL`], and the `format_provenance_all_has_no_duplicates`
    /// test pins that the constant is a set (no double-listed
    /// variant). Together they pin the constant to the variant space
    /// the typescape recognizes.
    pub const ALL: &'static [Self] = &[Self::FigmentBuiltin, Self::ShikumiBuilt];

    /// Returns `true` for [`Self::ShikumiBuilt`]; equivalent to
    /// `self == FormatProvenance::ShikumiBuilt`.
    ///
    /// Convenience predicate matching the
    /// [`crate::AttributionRule::is_exact`] /
    /// [`crate::AttributionRule::is_fallback`] sibling pair on
    /// [`crate::AttributionConfidence`]: typescape primitives expose a
    /// per-variant predicate alongside the closed-enum dispatch so the
    /// common "is it this one?" question stays one method call.
    ///
    /// `const`-callable — matching the `const`-ness of the peer per-variant
    /// predicates on the [`Format`] axis ([`Format::is_yaml`], …,
    /// [`Format::is_blue`]) and on the [`crate::AttributionRule`] axis
    /// ([`crate::AttributionRule::is_exact`] /
    /// [`crate::AttributionRule::is_fallback`]). Pinned by
    /// [`tests::format_provenance_predicates_are_const_callable`]. A drop
    /// of `const` at either sibling on this pair fails that test to
    /// compile.
    #[must_use]
    pub const fn is_shikumi_built(self) -> bool {
        matches!(self, Self::ShikumiBuilt)
    }

    /// Returns `true` for [`Self::FigmentBuiltin`]; equivalent to
    /// `self == FormatProvenance::FigmentBuiltin`. Sibling of
    /// [`Self::is_shikumi_built`]; `const`-callable at the same altitude,
    /// pinned by
    /// [`tests::format_provenance_predicates_are_const_callable`].
    #[must_use]
    pub const fn is_figment_builtin(self) -> bool {
        matches!(self, Self::FigmentBuiltin)
    }

    /// The single FIGMENT-BUILTIN [`FormatProvenance`] variant —
    /// [`Self::FigmentBuiltin`] (the `figment::providers::{Yaml, Toml}`
    /// image of the provenance axis) — in the SAME relative declaration
    /// order it occupies in [`Self::ALL`], carrying the *figment-
    /// builtin* pole of the (figment-builtin × shikumi-built) closed-
    /// binary polarity at the provenance primitive's OWN altitude on
    /// the provenance axis, mirroring the shipped boolean predicate
    /// [`Self::is_figment_builtin`] one altitude down: every variant
    /// in this slice satisfies `p.is_figment_builtin()`, and no variant
    /// outside it does.
    ///
    /// Paired with [`Self::SHIKUMI_BUILT`], the two disjoint slices
    /// partition [`Self::ALL`] at the static-slice altitude the same
    /// way the shipped boolean predicates [`Self::is_figment_builtin`]
    /// / [`Self::is_shikumi_built`] meta-partition it at the boolean
    /// altitude. Both sit in the same `impl FormatProvenance` block as
    /// [`Self::ALL`] and follow the same `pub const &'static [Self]`
    /// static-slice discipline.
    ///
    /// Written as an explicit one-variant slice literal in the SAME
    /// relative declaration order the figment-builtin pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_figment_builtin`] at const-fn altitude — so
    /// the two declarations (the slice literal and the boolean
    /// predicate) remain independent load-bearing witnesses of the
    /// same meta-partition, and a future edit that shifts a variant
    /// across the polarity on ONE declaration surface but not the
    /// other diverges at test time on the first provenance where they
    /// disagree.
    ///
    /// Idiom-peer of [`crate::PartitionFace::REALIZABLE`]
    /// (commit `a344056`), [`crate::SecretRefShape::WHOLE`]
    /// (commit `036673b`), [`crate::ConfigSourceKind::DEFAULTS`]
    /// (commit `2cd8ef8`), [`crate::ConfigTierKind::COMPUTED`]
    /// (commit `2c0686f`), [`crate::SecretOperation::MUTATING`]
    /// (commit `b2cfa2a`), [`crate::secret::SecretBackendKind::CLOUD_SECRET_MANAGER`]
    /// (commit `04e0f5d`), and
    /// [`crate::secret_client::SecretClientKind::CLOUD_SECRET_MANAGER`]
    /// (commit `399ee8a`) — the per-half meta-partition slice-constant
    /// discipline applied here to the provenance axis, lifting the
    /// FormatProvenance closed-binary primitive onto the slice-constant
    /// altitude.
    ///
    /// A future tertiary provenance variant (e.g. a `Custom` provider
    /// class the primitive's own doc-comment already anticipates)
    /// lands here either extending one of the two slices in lockstep
    /// with the boolean predicate that admits it, or introducing a
    /// third slice; the partition and cardinality pins refuse a silent
    /// landing under the negation of one of the existing two.
    ///
    /// The two agreement laws
    /// (`FIGMENT_BUILTIN.iter().all(|p| p.is_figment_builtin())` and
    /// `FIGMENT_BUILTIN.iter().all(|p| !p.is_shikumi_built())`) are
    /// pinned by
    /// [`tests::format_provenance_figment_builtin_slice_agrees_with_is_figment_builtin_predicate`].
    /// Partition invariant with [`Self::SHIKUMI_BUILT`]:
    /// [`tests::format_provenance_figment_builtin_and_shikumi_built_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::format_provenance_figment_builtin_and_shikumi_built_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::format_provenance_figment_builtin_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::format_provenance_figment_builtin_and_shikumi_built_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::format_provenance_figment_builtin_and_shikumi_built_slices_are_const_addressable`].
    pub const FIGMENT_BUILTIN: &'static [Self] = &[Self::FigmentBuiltin];

    /// The single SHIKUMI-BUILT [`FormatProvenance`] variant —
    /// [`Self::ShikumiBuilt`] (the `crate::LispProvider` /
    /// `crate::NixProvider` image of the provenance axis) — in the
    /// SAME relative declaration order it occupies in [`Self::ALL`],
    /// the complement pole of [`Self::FIGMENT_BUILTIN`] on the
    /// (figment-builtin × shikumi-built) closed-binary polarity at the
    /// provenance primitive's OWN altitude. Mirrors the shipped boolean
    /// predicate [`Self::is_shikumi_built`] one altitude down.
    ///
    /// The partition invariant with [`Self::FIGMENT_BUILTIN`] pins the
    /// whole-set cardinality identity
    /// `FIGMENT_BUILTIN.len() + SHIKUMI_BUILT.len() == ALL.len()`.
    /// Because the axis is closed-binary and XOR-complementary by
    /// construction today, a future third provenance landing (e.g. a
    /// `Custom` provider class the primitive's own doc-comment
    /// anticipates) would first fail the two-entry cardinality pins,
    /// then fail the partition and cardinality pins on this constant
    /// pair unless extended in lockstep with the boolean predicates.
    ///
    /// See [`Self::FIGMENT_BUILTIN`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a
    /// filter through [`Self::is_figment_builtin`]), and the
    /// load-bearing agreement and partition pins.
    pub const SHIKUMI_BUILT: &'static [Self] = &[Self::ShikumiBuilt];

    /// The [`crate::AttributionRule`] that names a [`crate::ConfigSource::File`]
    /// layer when a per-value figment failure originates from a file of
    /// this provenance:
    /// [`crate::AttributionRule::FileBySource`] for [`Self::FigmentBuiltin`]
    /// (figment's YAML/TOML providers attach `Source::File`, matched by
    /// path equality on `metadata.source`),
    /// [`crate::AttributionRule::FileByMetadataName`] for [`Self::ShikumiBuilt`]
    /// (the shikumi providers attach `metadata.name = "<format>: <path>"`,
    /// matched by parsed-path equality after
    /// [`Format::parse_metadata_tag`]).
    ///
    /// One source of truth for the (provenance → file-rule) projection.
    /// The information was previously implicit — readers had to know
    /// that figment's builtin file providers attach `Source::File` and
    /// that the shikumi-built providers attach the named `"<format>:
    /// <path>"` shape, and chase the two facts through the
    /// failing-source resolver in `error.rs` to confirm which rule
    /// each provenance triggers. Lifting it to a typed accessor pins
    /// "this provenance attributes file failures via rule X" at the
    /// type level, and tests pin the structural law that the resolver
    /// agrees with this projection on every recognized file-axis
    /// attribution
    /// (`format_provenance_file_attribution_rule_agrees_with_resolver_pointwise`).
    ///
    /// Composes with [`Self::file_attribution_axis`]: the latter is the
    /// projection of this rule through
    /// [`crate::AttributionRule::metadata_axis`] — a recognized file
    /// failure of [`Self::FigmentBuiltin`] origin sits at
    /// (`MetadataSource`, `File`, `Exact`) coordinates; a
    /// [`Self::ShikumiBuilt`] one sits at (`MetadataName`, `File`,
    /// `Exact`). Both project to [`crate::AttributionConfidence::Exact`]
    /// since file-axis rules are equality-based on either axis.
    ///
    /// A future variant landing on [`Self`] (e.g. a `Custom` provider
    /// class) forces an arm in the exhaustive match in lockstep — the
    /// typescape pins the partition to one site and any new provider
    /// class must declare which file-axis rule (and therefore which
    /// metadata axis) it dispatches through.
    #[must_use]
    pub fn file_attribution_rule(self) -> crate::AttributionRule {
        match self {
            Self::FigmentBuiltin => crate::AttributionRule::FileBySource,
            Self::ShikumiBuilt => crate::AttributionRule::FileByMetadataName,
        }
    }

    /// The [`crate::AttributionAxis`] of [`Self::file_attribution_rule`]:
    /// which `figment::Metadata` field the resolver dispatches off when
    /// attributing a per-value file failure of this provenance.
    /// [`crate::AttributionAxis::MetadataSource`] for [`Self::FigmentBuiltin`]
    /// (figment's YAML/TOML providers attach `Source::File`, structurally
    /// stable), [`crate::AttributionAxis::MetadataName`] for
    /// [`Self::ShikumiBuilt`] (shikumi providers attach a
    /// human-readable name parsed by shape-matching).
    ///
    /// Convenience over `self.file_attribution_rule().metadata_axis()`;
    /// the two-step composition stays a thin lift, the contract pinned
    /// by `format_provenance_file_attribution_axis_mirrors_rule_axis`.
    /// Diagnostics, dashboards, and attestation manifests that want to
    /// weight name-axis attributions visibly weaker than source-axis ones
    /// (since name-axis attribution is string-shape-dependent — a
    /// renamed upstream provider drops out of resolution silently) can
    /// route on this accessor at the file-format level rather than
    /// retaining a captured [`crate::AttributionRule`].
    #[must_use]
    pub fn file_attribution_axis(self) -> crate::AttributionAxis {
        self.file_attribution_rule().metadata_axis()
    }

    /// Canonical operator-facing lowercase name of the provenance —
    /// `"figment-builtin"` for [`Self::FigmentBuiltin`], `"shikumi-built"`
    /// for [`Self::ShikumiBuilt`].
    ///
    /// The single source of truth for the provenance-label strings on
    /// the [`FormatProvenance`] axis. Inherent mirror of the
    /// [`crate::ClosedAxisLabel`] trait method; the two canonical
    /// strings previously appeared only in doc-prose
    /// (`(figment-builtin × shikumi-built) axis`) — lifting them to a
    /// typed accessor pins the labels at one site so structured-log
    /// fields, attestation manifests recording provenance histograms,
    /// CLI flags that surface "which provider class loaded this value",
    /// and trait-uniform `ClosedAxisLabel` consumers reach the
    /// canonical name through one method call.
    ///
    /// Kebab-case so a future tertiary provider class (e.g. an
    /// upstream-figment-ecosystem provider that's neither figment's own
    /// builtin nor shikumi's own) lands a canonical name following the
    /// same convention; the existing two names are compound nouns whose
    /// punctuation belongs at the type level (operator-facing string)
    /// rather than at the call site.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FigmentBuiltin => "figment-builtin",
            Self::ShikumiBuilt => "shikumi-built",
        }
    }

    /// The closed slice of [`Format`] variants whose [`Format::provenance`]
    /// equals `self` — the fiber of [`Format::provenance`] over this
    /// provenance cell.
    ///
    /// Partial inverse of [`Format::provenance`] on the provenance side:
    /// where [`Format::provenance`] is the total forward map
    /// `Format → FormatProvenance` (every format declares one provenance),
    /// [`Self::formats`] is the closed-image inverse `FormatProvenance →
    /// &'static [Format]` returning the preimage of each provenance value
    /// as a `'static` slice in [`Format::ALL`] declaration order.
    ///
    /// One source of truth for the (provenance → formats) fiber. Before
    /// this method, consumers wanting the fiber inlined
    /// `Format::ALL.iter().filter(|f| f.has_shikumi_provider())` (or its
    /// `!`-negation for the figment-builtin half) at 9+ sites across the
    /// crate — one production callsite in [`Format::strip_metadata_name`]
    /// (the failing-source resolver's name-axis dispatch over the
    /// shikumi-built providers), and 8 test-time sites pinning the
    /// shikumi-built ↔ figment-builtin partition on each downstream
    /// invariant (the env-tag/format-tag disjointness, the metadata-name
    /// shape uniqueness, the format-axis cube coverage). Each duplicated
    /// `filter(…has_shikumi_provider())` had to be manually kept in
    /// lockstep with `Format::provenance`'s match — a future format
    /// landing under [`Self::FigmentBuiltin`] would still need every
    /// `filter(|f| f.has_shikumi_provider())` site to keep returning the
    /// shikumi-built half rather than silently including the new format,
    /// and the discipline was upheld only by reviewer attention.
    ///
    /// Lifting the fiber to one named accessor pins the partition at the
    /// type level. The slices live as `&'static [Format]` constants, so
    /// iteration is allocation-free at every call site and the slice
    /// cardinality (today: 2 + 2 = `Format::ALL.len()`) is pinned at the
    /// type level. A future [`Format`] variant landing forces an arm in
    /// [`Format::provenance`] (compile-time, exhaustive match) AND an
    /// extension of one of the slices here (test-time, pinned by
    /// [`Self`]'s fiber tests) — both extensions land in lockstep through
    /// the type system + the trait-uniform test suite.
    ///
    /// **Fiber law** — for every `(f, p)` pair in
    /// `Format::ALL × FormatProvenance::ALL`:
    /// `f ∈ p.formats() ⇔ Format::provenance(f) == p`. The two directions
    /// (forward map vs. fiber containment) agree pointwise. Pinned by
    /// `format_provenance_formats_is_fiber_of_format_provenance` over the
    /// full `Format::ALL × FormatProvenance::ALL` product. The contract
    /// is structural: a future provenance variant cannot land without
    /// declaring a fiber slice that respects this law on its row.
    ///
    /// **Partition law** — the slices partition [`Format::ALL`]: the
    /// disjoint union of `p.formats()` over `FormatProvenance::ALL` equals
    /// `Format::ALL` as a set (no format missing from every fiber, no
    /// format appearing in two fibers, no fiber holding a format
    /// `Format::ALL` does not). Pinned by
    /// `format_provenance_formats_partition_format_all_disjointly` and
    /// `format_provenance_formats_cardinalities_sum_to_format_all`. Both
    /// laws follow from the fiber law and the totality of
    /// [`Format::provenance`], but stating them as separate tests pins
    /// each side of the law at a single failure site.
    ///
    /// **Declaration order** — each fiber slice lists its formats in the
    /// same relative order as they appear in [`Format::ALL`]. Pinned by
    /// `format_provenance_formats_respects_format_all_declaration_order`.
    /// Consumers that want a deterministic per-provenance ordering for
    /// dashboards / structured-log fields / attestation manifests can
    /// rely on the slice without reordering.
    ///
    /// Today's fibers — [`Self::FigmentBuiltin`] →
    /// `[Format::Yaml, Format::Toml]`, [`Self::ShikumiBuilt`] →
    /// `[Format::Lisp, Format::Nix]` — match the partition pinned by the
    /// `format_provenance_classifies_each_variant` test on the forward
    /// side.
    ///
    /// Composes with [`FormatCoordinates`]: the realizable cells of the
    /// `(format × provenance)` cube ([`FormatCoordinates::ALL`] filtered
    /// by [`FormatCoordinates::is_realizable`]) project onto
    /// `p.formats()` under the format-axis projection — the fiber is the
    /// format-axis slice of the realizable surface restricted to the
    /// `provenance == p` plane. Future cube-cover dashboards rendering
    /// per-provenance format histograms reach the format list through
    /// this accessor instead of re-deriving the slice from a filter over
    /// [`FormatCoordinates::ALL`].
    #[must_use]
    pub const fn formats(self) -> &'static [Format] {
        match self {
            Self::FigmentBuiltin => &[Format::Yaml, Format::Toml],
            Self::ShikumiBuilt => &[Format::Lisp, Format::Nix, Format::Blue],
        }
    }
}

/// Coordinate pair of a [`Format`] over the two orthogonal projections
/// [`Format`] (which on-disk format) and [`FormatProvenance`] (which
/// provider class loads it).
///
/// One named typescape value collapsing the two closed-enum reads into
/// one. The (`format` × `provenance`) cube has 4 × 2 = 8 product cells;
/// today's format space occupies exactly 4 of them (one per [`Format`]
/// variant, paired with the [`FormatProvenance`] declared by
/// [`Format::provenance`]). [`Format::format_coordinates`] is the total
/// forward map from the format space; [`Self::format_or_none`] is the
/// partial inverse, [`Some`] exactly on the four recognized cells.
///
/// Second product-axis named struct on the typescape primitive set,
/// peer to [`crate::AttributionCoordinates`] (the first), but lifted on
/// a different sibling pair (`Format × FormatProvenance` instead of
/// `AttributionAxis × ConfigSourceKind × AttributionConfidence`). Same
/// typescape discipline: named fields collapse the per-axis reads into
/// one envelope value (`Copy + Eq + Hash + #[non_exhaustive]`) usable
/// in `match`, `HashMap` keys, log labels, alerting buckets, and
/// attestation manifest payloads.
///
/// The struct exists (rather than a bare tuple) so call sites document
/// which slot is which — `format` / `provenance` — at the type level
/// rather than relying on positional destructuring discipline. The
/// `Copy + Eq + Hash + #[non_exhaustive]` bounds match the sibling
/// closed-enum primitives ([`crate::AttributionRule`],
/// [`crate::AttributionConfidence`], [`crate::AttributionAxis`],
/// [`crate::ConfigSourceKind`], [`crate::ShikumiErrorKind`],
/// [`crate::FieldPathLocalization`]) and the sibling product-axis
/// envelope [`crate::AttributionCoordinates`].
///
/// Future fidelity work — adding a third axis (e.g. a runtime
/// `loader_health` slot beyond `Format`/`FormatProvenance`) — extends
/// this struct as one new field plus one match arm in
/// [`Format::format_coordinates`] / [`Self::format_or_none`]; existing
/// consumers that destructure on the named fields stay coherent under
/// the `#[non_exhaustive]` discipline.
///
/// **Trait surface** — alongside the canonical
/// `Debug + Clone + Copy + PartialEq + Eq + Hash` set, the derive also
/// includes [`Ord`] + [`PartialOrd`]. The derived order is lex over
/// the struct fields in declaration order (`format` outer, `provenance`
/// inner); because both sibling axes already carry declaration-order
/// [`Ord`] ([`Format`] from commit `b56b121`, [`FormatProvenance`] from
/// commit `2c7654c`), the induced product-cube order matches
/// [`Self::ALL`] pointwise. A
/// [`BTreeMap<FormatCoordinates, T>`][std::collections::BTreeMap] keyed
/// on the (format × provenance) cube emits rows in product order
/// deterministically. Pinned by
/// [`tests::format_coordinates_ord_matches_all_declaration_order`].
///
/// **Canonical-string surface** — [`std::fmt::Display`] /
/// [`std::str::FromStr`] round-trip through the
/// `<format>:<provenance>` scalar (e.g. `"yaml:figment-builtin"`,
/// `"nix:shikumi-built"`). The leftmost-`:`-split parser delegates each
/// half to its axis's [`FromStr`], inheriting case-insensitivity and
/// the format-axis alias surface (`yml`/`lsp`/`el`). Idiom-peer of the
/// (`Display`, `FromStr`) lift on [`crate::PartitionOrdinal`] (commit
/// `6b20041`), now extended onto a (closed-enum × closed-enum) product.
///
/// **Serde surface** — [`serde::Serialize`] / [`serde::Deserialize`]
/// are the canonical idiom-peer of the (`Display`, `FromStr`) pair:
/// Serialize via [`serde::Serializer::collect_str`], Deserialize via
/// [`serde::de::Error::custom`] lowering through `FromStr`. An
/// attestation manifest field recording which (format, provenance)
/// cell loaded a config round-trips through the canonical scalar
/// without a consumer-side rename helper. Pinned by
/// [`tests::format_coordinates_serde_yaml_round_trips_over_all_cells`]
/// and
/// [`tests::format_coordinates_serde_json_round_trips_over_all_cells`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub struct FormatCoordinates {
    /// Which on-disk format the cell describes — see [`Format`] /
    /// [`Format::format_coordinates`].
    pub format: Format,
    /// Which provider class loads that format — see
    /// [`FormatProvenance`] / [`Format::provenance`].
    pub provenance: FormatProvenance,
}

impl FormatCoordinates {
    /// Every cell of the `format × provenance` product cube — the
    /// structural composition of [`Format::ALL`] (4 cells) and
    /// [`FormatProvenance::ALL`] (2 cells) into the `4 × 2 = 8`-cell
    /// coordinate space, in lexicographic order over the two sibling
    /// slices (format outermost, provenance innermost).
    ///
    /// One named typescape value collapsing the two-axis product
    /// enumeration into one constant. Before this lift, every consumer
    /// that wanted the cube — partition tests over the
    /// (format × provenance) plane, future per-cell dashboards,
    /// attestation manifests recording the coordinate space's
    /// cardinality, structured-diagnostics legends rendering different
    /// prose per cell — had to inline a doubly-nested
    /// `for format in Format::ALL { for provenance in
    /// FormatProvenance::ALL { … } }` loop and re-derive the product
    /// on the fly. Iterate [`Self::ALL`] instead.
    ///
    /// Second product-axis `ALL` constant on the typescape primitive
    /// set — peer to [`crate::AttributionCoordinates::ALL`] (the
    /// first), but lifted on a different sibling pair (`Format ×
    /// FormatProvenance` instead of
    /// `AttributionAxis × ConfigSourceKind × AttributionConfidence`).
    /// Same typescape discipline (closed `'static` slice, in
    /// declaration order, `Copy + Eq + Hash + #[non_exhaustive]`
    /// element type) applied to the format-axis product cube.
    ///
    /// Cardinality is pinned by the
    /// `format_coordinates_all_cardinality_matches_product_of_axes`
    /// test against `Format::ALL.len() * FormatProvenance::ALL.len()`,
    /// so any new variant on either sibling axis forces an extension
    /// of this slice in lockstep with the variant itself. The
    /// `format_coordinates_all_equals_axes_cartesian_product` test
    /// pins tight equality against the inline doubly-nested product
    /// over the sibling `ALL` constants — `Self::ALL` is the product,
    /// not a subset and not a superset.
    ///
    /// The partition into recognized and unrecognized cells is the
    /// 4 + 4 split pinned by [`Self::format_or_none`]: 4 cells
    /// (`Format::ALL.len()`) map to a [`Some`] format; 4 cells map to
    /// [`None`]. The
    /// `format_coordinates_all_recognized_image_equals_format_coordinates`
    /// test pins the recognized half as the exact image of
    /// [`Format::format_coordinates`] over [`Format::ALL`], and the
    /// `format_coordinates_all_partitions_into_recognized_and_unrecognized`
    /// test pins the cardinality split.
    pub const ALL: &'static [Self] = &[
        Self {
            format: Format::Yaml,
            provenance: FormatProvenance::FigmentBuiltin,
        },
        Self {
            format: Format::Yaml,
            provenance: FormatProvenance::ShikumiBuilt,
        },
        Self {
            format: Format::Toml,
            provenance: FormatProvenance::FigmentBuiltin,
        },
        Self {
            format: Format::Toml,
            provenance: FormatProvenance::ShikumiBuilt,
        },
        Self {
            format: Format::Lisp,
            provenance: FormatProvenance::FigmentBuiltin,
        },
        Self {
            format: Format::Lisp,
            provenance: FormatProvenance::ShikumiBuilt,
        },
        Self {
            format: Format::Nix,
            provenance: FormatProvenance::FigmentBuiltin,
        },
        Self {
            format: Format::Nix,
            provenance: FormatProvenance::ShikumiBuilt,
        },
        Self {
            format: Format::Blue,
            provenance: FormatProvenance::FigmentBuiltin,
        },
        Self {
            format: Format::Blue,
            provenance: FormatProvenance::ShikumiBuilt,
        },
    ];

    /// Partial inverse of [`Format::format_coordinates`]: re-hydrate a
    /// recognized format from its (format, provenance) cell, or
    /// [`None`] for unrecognized cells where the cell's `provenance`
    /// disagrees with `cell.format.provenance()`.
    ///
    /// The (format × provenance) cube has 4 × 2 = 8 product cells;
    /// today's format space occupies exactly 4 of them (the diagonal
    /// `format.provenance() == provenance`). The inverse map names the
    /// four recognized cells as their `format` slot and returns
    /// [`None`] on the other four (where `provenance` disagrees with
    /// the format's declared provider class).
    ///
    /// Operational use: an attestation manifest, structured-log replay,
    /// or cross-process diagnostic that observes the (format,
    /// provenance) coordinates (e.g. captured into a serialized
    /// snapshot) recovers the typed format by one method call instead
    /// of re-deriving the dispatch inline. Since [`Format::ALL`] and
    /// the recognized-cell set are pinned at the type level, the
    /// inverse stays coherent under future variant additions: a new
    /// format landing forces both an arm in [`Format::provenance`]
    /// (compile-time, exhaustive match on the format variant space)
    /// and a row in the
    /// `format_coordinates_round_trip_through_format_or_none_on_recognized_cells`
    /// and `format_coordinates_format_or_none_returns_none_for_unrecognized_cells`
    /// tests (test-time).
    ///
    /// Strictly stronger than `matches!` against the format space:
    /// `format_or_none` consumes the closed-enum coordinate pair (no
    /// inline tuple destructuring), so the recognized-cell predicate
    /// stays one method call regardless of how many formats the
    /// substrate accumulates.
    #[must_use]
    pub fn format_or_none(self) -> Option<Format> {
        if self.format.provenance() == self.provenance {
            Some(self.format)
        } else {
            None
        }
    }

    /// Realizability predicate over the 8-cell product cube: returns
    /// `true` exactly on the 4 cells some recognized [`Format`]
    /// occupies (the diagonal `format.provenance() == provenance`),
    /// and `false` on the remaining 4 cells (where the cell's
    /// provenance disagrees with the format's declared provider class).
    ///
    /// Equivalent to `FormatCoordinates::format_or_none(self).is_some()`
    /// — the closed-enum lift of the partial-inverse-is-Some test on
    /// this cube. Observers that only need the Boolean membership ("is
    /// this cell observable from a recognized format?") no longer
    /// reach for the partial inverse and discard its [`Some`] payload;
    /// the predicate is one method call regardless of how the format
    /// space dispatch is currently shaped.
    ///
    /// One source of truth for the realizability test on the
    /// (`format × provenance`) cube. Before this method, every site
    /// that wanted "is this a recognized cell?" inlined
    /// `cell.format_or_none().is_some()` (or its negation
    /// `.is_none()`) at the call site — the realizability /
    /// recognized-cell partition was reachable only through the
    /// partial inverse. The named predicate collapses that to a typed
    /// accessor on the cube, matching the realizability-predicate
    /// discipline already established by
    /// [`crate::AttributionCoordinates::is_realizable`] (the
    /// `axis × layer_kind × confidence` cube),
    /// [`crate::ErrorLocalizationCoordinates::is_realizable`] (the
    /// `kind × localization` cube), and
    /// [`crate::AttributionSourceKindCoordinates::is_realizable`] (the
    /// `figment_source_kind × layer_kind` cube). With this lift the
    /// substrate exposes a uniform `is_realizable()` predicate on all
    /// four product cubes of the typescape primitive set — the four-
    /// cube symmetry is now closed under one Boolean interface.
    ///
    /// Operational use: an attestation manifest, structured-log
    /// replay, or cross-process diagnostic that observes the
    /// (format, provenance) coordinates recovers the realizability
    /// classification — "is this cell a valid observation of a
    /// recognized [`Format`], or a cross-axis consistency violation
    /// no recognized format occupies" — by one method call instead of
    /// re-deriving the dispatch from the partial inverse inline.
    /// Future variants land coherently: a new [`Format`] landing in a
    /// previously unrecognized cell extends the realizable image,
    /// forces an arm in [`Format::provenance`] (compile-time), and
    /// forces an extension of the realizable-image expectation in
    /// `format_coordinates_is_realizable_image_equals_format_image`
    /// (test-time) — all three stay in lockstep.
    ///
    /// Peer to [`crate::AttributionCoordinates::is_realizable`]: same
    /// `Copy`-by-value receiver, same Boolean shape, same membership-
    /// over-the-recognized-image semantics. Both cubes have injective
    /// forward maps on the recognized half, so realizability on each
    /// is exactly the partial inverse's [`Some`] domain and the
    /// implementation delegates accordingly; the other two sibling
    /// cubes ([`crate::ErrorLocalizationCoordinates`],
    /// [`crate::AttributionSourceKindCoordinates`]) use direct
    /// pattern matches because their forward maps are non-injective
    /// or partial. The same membership-over-the-recognized-image
    /// contract holds across all four cubes regardless of the
    /// underlying mechanism.
    #[must_use]
    pub fn is_realizable(self) -> bool {
        self.format_or_none().is_some()
    }
}

impl crate::ClosedAxis for Format {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for Format {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl crate::ClosedAxis for FormatProvenance {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for FormatProvenance {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl crate::ClosedAxis for FormatCoordinates {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ProductCube for FormatCoordinates {
    fn is_realizable(self) -> bool {
        Self::is_realizable(self)
    }
}

impl crate::PartialInverseCube for FormatCoordinates {
    type Image = Format;

    fn invert(self) -> Option<Format> {
        self.format_or_none()
    }

    fn forward(image: Format) -> Self {
        image.format_coordinates()
    }
}

impl fmt::Display for FormatCoordinates {
    /// Operator-facing rendering of the product-cube cell as
    /// `<format>:<provenance>` — the canonical [`Format::as_str`] label
    /// (`yaml` / `toml` / `lisp` / `nix`), a `:` separator, and the
    /// canonical [`FormatProvenance::as_str`] kebab-case label
    /// (`figment-builtin` / `shikumi-built`). The colon separator is
    /// unambiguous because neither half contains `:`, so the leftmost
    /// `:` cleanly splits the two axes.
    ///
    /// **Round-trip with [`FromStr`]** — for every
    /// `c: FormatCoordinates`,
    /// `c.to_string().parse::<FormatCoordinates>().unwrap() == c`.
    /// Pinned by
    /// [`tests::format_coordinates_from_str_round_trips_over_all_cells`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.format.as_str(), self.provenance.as_str())
    }
}

/// Typed parse failure of [`<FormatCoordinates as
/// std::str::FromStr>::from_str`] — the offending input was not a
/// canonical `<format>:<provenance>` cell.
///
/// Three rejection modes covering the two halves of the scalar
/// encoding: no `:` separator, an unrecognized format label before
/// `:`, or an unrecognized provenance label after `:`. Each variant
/// captures the offending substring verbatim so a downstream consumer
/// can localize the failure to its surrounding context.
///
/// `#[non_exhaustive]` so a future stricter parse rule lands as a new
/// variant without a SemVer-major bump. Idiom-peer of
/// [`crate::ParsePartitionOrdinalError`] (commit `6b20041`) on the
/// (variant-tag × dense-ordinal) product, lifted here onto the
/// (closed-enum × closed-enum) product whose both halves are
/// label-typed.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseFormatCoordinatesError {
    /// The input carried no `:` separator. The full offending input is
    /// preserved verbatim so the operator-facing error names what was
    /// actually received.
    #[error("FormatCoordinates input missing `:` separator: {input:?}")]
    MissingSeparator {
        /// The offending input substring, verbatim.
        input: String,
    },
    /// The format-label half (before the `:`) did not match a canonical
    /// [`Format`] name (`yaml`, `toml`, `lisp`, `nix`) and was not one
    /// of the recognized aliases (`yml`, `lsp`, `el`). The offending
    /// substring is preserved verbatim.
    #[error("unknown FormatCoordinates format label {label:?}")]
    UnknownFormat {
        /// The offending format-label substring, verbatim.
        label: String,
    },
    /// The provenance-label half (after the `:`) did not match a
    /// canonical [`FormatProvenance`] name (`figment-builtin`,
    /// `shikumi-built`). The offending substring is preserved verbatim.
    #[error("unknown FormatCoordinates provenance label {label:?}")]
    UnknownProvenance {
        /// The offending provenance-label substring, verbatim.
        label: String,
    },
}

impl ParseFormatCoordinatesError {
    /// True iff this rejection is [`Self::MissingSeparator`] — the input
    /// carried no `:` separator between the two halves of the canonical
    /// `<format>:<provenance>` scalar. The two label-check variants
    /// ([`Self::UnknownFormat`] and [`Self::UnknownProvenance`]) both
    /// return `false`.
    ///
    /// **The tag-only classifier on the structural-versus-label
    /// polarity axis.** A consumer holding a freshly returned
    /// [`ParseFormatCoordinatesError`] previously had two paths for
    /// asking "is the failure the structural separator check, or a
    /// per-half label rejection?", each leaking work: (a)
    /// `matches!(err, ParseFormatCoordinatesError::MissingSeparator {
    /// .. })` inline at every seam, a shape the exhaustiveness checker
    /// cannot help keep in sync with a future variant addition (a
    /// hypothetical `LeadingSeparator { .. }` fourth variant would
    /// silently keep answering `false` at every inline `matches!` site);
    /// or (b) an outer `match` decomposing the whole three-arm sum at
    /// each classification site, forcing a re-declaration of the arms a
    /// consumer that only wants the polarity does not care about.
    ///
    /// The tag-only sibling here answers the same question through a
    /// single welded [`matches!`]: adding a fourth variant fails to
    /// compile at this method's pattern in lockstep with
    /// [`Self::is_unknown_format`] and [`Self::is_unknown_provenance`]
    /// via the ternary-partition pin
    /// [`tests::parse_format_coordinates_error_predicates_are_a_closed_ternary_partition`],
    /// which fires when a new variant collapses the partition sum to
    /// zero at that variant. Retry-policy dispatches that treat
    /// separator-missing inputs uniformly (never worth retrying — no
    /// prompt-completion heuristic recovers a missing separator) split
    /// from the two label-check arms (potentially recoverable through
    /// operator suggestions of nearby canonical labels) reach the
    /// polarity through one method call.
    ///
    /// **Idiom-peer of the tag-side sibling-predicate closures on other
    /// closed-partition error primitives.** The direct methodological
    /// analogue of [`crate::ShikumiError`]'s
    /// `is_watch`/`is_io`/`is_figment`/`is_extract`/`is_validation`
    /// septet (commit `f881f6f`) and
    /// [`crate::secret_client::SecretError`]'s
    /// `is_not_found`/`is_unauthorized`/`is_unsupported`/`is_backend`/`is_shikumi`
    /// quintet (commit `bc1db8f`): same routing shape, same
    /// closed-partition contract on a payload-bearing error enum with
    /// zero pre-existing tag-side siblings.
    ///
    /// `const`-callable — a compile-time-known
    /// [`ParseFormatCoordinatesError`] projects its polarity at compile
    /// time too.
    #[must_use]
    pub const fn is_missing_separator(&self) -> bool {
        matches!(self, Self::MissingSeparator { .. })
    }

    /// True iff this rejection is [`Self::UnknownFormat`] — the input
    /// carried a `:` separator, but the format half (before the `:`)
    /// did not match any canonical [`Format`] label (`yaml` / `toml` /
    /// `lisp` / `nix`, or the recognized aliases `yml` / `lsp` / `el`).
    /// The structural-check variant [`Self::MissingSeparator`] and the
    /// mirror label-check variant [`Self::UnknownProvenance`] both
    /// return `false`.
    ///
    /// Sibling of [`Self::is_missing_separator`] and
    /// [`Self::is_unknown_provenance`] on the same closed ternary
    /// partition; same routing rationale (see
    /// [`Self::is_missing_separator`] docs). A retry-policy dispatch or
    /// operator-facing suggestion engine ("did you mean `yaml`?") that
    /// wants to fire only on the format-half rejection routes on this
    /// predicate at the borrowed error without matching on the whole
    /// three-arm sum.
    #[must_use]
    pub const fn is_unknown_format(&self) -> bool {
        matches!(self, Self::UnknownFormat { .. })
    }

    /// True iff this rejection is [`Self::UnknownProvenance`] — the
    /// input carried a `:` separator and a recognized format half, but
    /// the provenance half (after the `:`) did not match any canonical
    /// [`FormatProvenance`] label (`figment-builtin` / `shikumi-built`).
    /// The structural-check variant [`Self::MissingSeparator`] and the
    /// mirror label-check variant [`Self::UnknownFormat`] both return
    /// `false`.
    ///
    /// Sibling of [`Self::is_missing_separator`] and
    /// [`Self::is_unknown_format`] on the same closed ternary partition;
    /// same routing rationale (see [`Self::is_missing_separator`] docs).
    /// The provenance-half rejection is the deepest of the three
    /// precedence levels — reached only when both the separator check
    /// and the format-label check passed — so a diagnostic layer that
    /// wants to surface "the format was recognized but its provenance
    /// tag was not" as a distinct operator-facing hint routes on this
    /// predicate.
    #[must_use]
    pub const fn is_unknown_provenance(&self) -> bool {
        matches!(self, Self::UnknownProvenance { .. })
    }
}

impl FromStr for FormatCoordinates {
    type Err = ParseFormatCoordinatesError;

    /// Parse the canonical `<format>:<provenance>` cell label. The
    /// leftmost `:` splits the input; the format half lowers through
    /// [`<Format as FromStr>::from_str`] (inherits `yml`/`lsp`/`el`
    /// aliases and ASCII case-insensitivity), and the provenance half
    /// lowers through
    /// [`<FormatProvenance as FromStr>::from_str`] (inherits ASCII
    /// case-insensitivity from
    /// [`crate::ClosedAxisLabel::from_canonical_str`]).
    ///
    /// Check order is `MissingSeparator → UnknownFormat →
    /// UnknownProvenance`, mirroring
    /// [`crate::ParsePartitionOrdinalError`]'s
    /// `MissingSeparator → UnknownFace → MalformedOrdinal` precedence:
    /// the structural separator check is strictly more specific than
    /// per-half label checks, and the format half is checked before the
    /// provenance half to match left-to-right reading.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (format_half, provenance_half) =
            s.split_once(':')
                .ok_or_else(|| ParseFormatCoordinatesError::MissingSeparator {
                    input: s.to_owned(),
                })?;
        let format = Format::from_str(format_half).map_err(|_| {
            ParseFormatCoordinatesError::UnknownFormat {
                label: format_half.to_owned(),
            }
        })?;
        let provenance = FormatProvenance::from_str(provenance_half).map_err(|_| {
            ParseFormatCoordinatesError::UnknownProvenance {
                label: provenance_half.to_owned(),
            }
        })?;
        Ok(Self { format, provenance })
    }
}

// Canonical `<format>:<provenance>` serde scalar — Serialize via
// `collect_str` over the `Display` impl, Deserialize via a visitor that
// lowers through `FromStr` and routes `ParseFormatCoordinatesError`
// through `serde::de::Error::custom` (the typed error's `Display` carries
// the offending substring verbatim). Lifted to `serde_via_display_fromstr!`
// — the same canonical serde shape the `ClosedAxisLabel` cohort already
// rides via the explicit-parser arm of `closed_axis_label_string_surface!`,
// extracted here so a typed-composite primitive whose `FromStr::Err` is
// not `ShikumiError` (the three-variant `ParseFormatCoordinatesError`)
// stays on the same single source of truth. Behavior is byte-identical
// to the prior hand-rolled impls: the `collect_str` emission, the
// visitor `expecting` literal, and the `visit_str` lowering through
// `FromStr` all match the prior surface pointwise. Pinned by the
// `format_coordinates_serde_*` round-trip / case-insensitivity /
// verbatim-rejection tests in `tests`.
serde_via_display_fromstr! {
    type = FormatCoordinates,
    expecting = "a canonical FormatCoordinates `<format>:<provenance>` scalar \
                 (e.g. `yaml:figment-builtin`, `nix:shikumi-built`; case-insensitive)",
}

/// Recognized form of a shikumi-built provider's
/// `figment::Metadata::name`, as parsed by [`Format::parse_metadata_tag`].
///
/// Pair-struct over the metadata-name-axis on the shikumi-provider
/// sub-axis: a [`Format`] tag (which provider emitted the name) and a
/// [`Path`] (the file the provider was reading) borrowed into the
/// original metadata-name string.
///
/// The closed shape — named fields, no positional ambiguity, [`Path`]-
/// typed instead of raw `&str` — mirrors
/// [`crate::EnvMetadataTag`] (env-name-axis) and
/// [`crate::FigmentSourceTag`] (figment-Source-axis), so the three
/// metadata-axis primitives compose under one typescape discipline.
///
/// `Copy` and allocation-free; the path borrow lives for the lifetime
/// of the input metadata-name string, since [`Path::new`] reinterprets
/// the bytes without copying them. Marked `#[non_exhaustive]` so a
/// future enrichment (e.g. a parsed numeric checksum suffix, an
/// origin-provider tag distinguishing `LispProvider` from `NixProvider`
/// without re-deriving from `format`) lands as one new field without
/// breaking pattern-bind sites; the named-field shape (rather than a
/// positional tuple) is what makes the extension non-breaking on
/// callers that destructure with `..`.
///
/// **Trait surface** — alongside the canonical
/// `Debug + Clone + Copy + PartialEq + Eq + Hash` set, the derive also
/// includes [`Ord`] + [`PartialOrd`]. The total order is the
/// declaration-order lex over the struct's fields (`format` outer,
/// `path` inner): outer ordering inherits the format-axis declaration
/// order (`Yaml < Toml < Lisp < Nix`) lifted from
/// [`Format`]'s `Ord` derive (commit `b56b121`), and inner ordering is
/// `Path`'s native lex over its underlying byte slice. A
/// [`BTreeMap<FormatMetadataTag, T>`][std::collections::BTreeMap] keyed
/// on the (format, path) envelope (per-tag attribution counters,
/// per-tag failure-rate dashboards, attestation manifests recording
/// per-tag cardinality mixes) emits rows in declaration-then-lex order
/// deterministically without a hand-rolled comparator at the renderer.
/// Pinned by [`tests::format_metadata_tag_ord_matches_format_then_path_lex`]
/// and [`tests::format_metadata_tag_btreemap_emits_in_format_then_path_lex_order`].
///
/// **Display surface** — [`fmt::Display`] writes the canonical
/// `<format>: <path>` shape — exactly the string
/// [`Format::metadata_name`] returns for the same `(format, path)` pair.
/// Lifting the canonical wire form from a method on [`Format`] to a
/// `Display` impl on the typed envelope itself means a consumer holding
/// a typed tag can write `format!("{tag}")` instead of re-deriving
/// `format!("{}: {}", tag.format, tag.path.display())` — the same
/// idiom-peer lift the discovery-layer trio's prior commits landed on
/// [`FormatCoordinates`] (commit `06a2f42`) and on [`FormatProvenance`]
/// (commit `2c7654c`). Pinned by
/// [`tests::format_metadata_tag_display_matches_format_metadata_name`]
/// and
/// [`tests::format_metadata_tag_display_parse_round_trips_for_shikumi_providers`].
///
/// **`TryFrom<&'a str>` surface** — [`TryFrom`] over `&'a str` is the
/// idiom-peer of the inverse [`Format::parse_metadata_tag`]: the
/// envelope's typed parser routes through `parse_metadata_tag` and
/// promotes its `None` arm to a typed
/// [`ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix`]
/// variant carrying the offending input verbatim — same verbatim-rejection
/// discipline as [`ParseFormatCoordinatesError`] (commit `06a2f42`).
/// [`FromStr`] is unavailable because the parsed envelope borrows into
/// the input; [`TryFrom<&'a str>`] threads the lifetime through. Pinned by
/// [`tests::format_metadata_tag_try_from_round_trips_for_shikumi_providers`],
/// [`tests::format_metadata_tag_try_from_rejects_non_shikumi_provider_prefixes`],
/// [`tests::format_metadata_tag_try_from_rejects_unrelated_strings_with_input_verbatim`],
/// and
/// [`tests::format_metadata_tag_try_from_path_borrows_into_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub struct FormatMetadataTag<'a> {
    /// The [`Format`] whose shikumi-built provider emitted the
    /// metadata-name (one of [`Format::Lisp`] / [`Format::Nix`] today;
    /// every variant for which [`Format::has_shikumi_provider`] is
    /// `true`).
    pub format: Format,
    /// The trailing path the provider was reading — borrowed into the
    /// input metadata-name `&str`, no allocation. Matched against
    /// [`crate::ConfigSource::as_path`] in the failing-source resolver.
    pub path: &'a Path,
}

impl fmt::Display for FormatMetadataTag<'_> {
    /// Write the canonical `<format>: <path>` shape — exactly the string
    /// [`Format::metadata_name`] returns for the same `(format, path)`
    /// pair, byte-for-byte. The format token comes from [`Format`]'s own
    /// [`fmt::Display`] (canonical lowercase label
    /// [`Format::as_str`] returns), and the path renders through
    /// [`Path::display`] (the standard library's lossy `OsStr` →
    /// `&str` projection — the same path renderer
    /// [`Format::metadata_name`] uses).
    ///
    /// **Round-trip law** — for every shikumi-built provider's tag
    /// (every `t: FormatMetadataTag<'_>` with
    /// `t.format.has_shikumi_provider() == true` and path bytes that
    /// don't lose information under [`Path::display`]), parsing the
    /// rendered string back through [`Format::parse_metadata_tag`]
    /// yields an envelope structurally equal to the original. Pinned by
    /// [`tests::format_metadata_tag_display_parse_round_trips_for_shikumi_providers`].
    ///
    /// **Idiom-peer of [`Format::metadata_name`]** — pinned by
    /// [`tests::format_metadata_tag_display_matches_format_metadata_name`],
    /// which asserts `format!("{tag}") == tag.format.metadata_name(tag.path)`
    /// pointwise across every `(Format, Path)` pair (both shikumi-provider
    /// and figment-builtin variants). The two surfaces stay
    /// byte-for-byte aligned by construction because both route through
    /// [`Format::write_metadata_name`] — the ONE named write-side
    /// helper the allocating and alloc-free emitters share — so a
    /// future change to the emission shape lands at one site and this
    /// impl inherits it without a lockstep manual edit.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format.write_metadata_name(f, self.path)
    }
}

/// Typed rejection reason emitted by [`FormatMetadataTag`]'s
/// [`TryFrom<&str>`] impl when an input doesn't parse as a shikumi-built
/// provider's `figment::Metadata::name`.
///
/// Single-variant for now: a metadata-name string that doesn't match any
/// shikumi-provider `"<format>: <path>"` prefix has only one rejection
/// shape (no recognized prefix), so the variant carries the offending
/// input verbatim and nothing else. Marked `#[non_exhaustive]` so a
/// future enrichment (e.g. a `MissingSpaceAfterColon { input }` or a
/// `UnknownFormatToken { token }` arm if the parser ever sharpens
/// further) lands as a new variant without breaking exhaustivity at
/// consumer matches.
///
/// **Verbatim-substring rejection discipline** — the `input` field
/// carries the offending substring verbatim into the rendered
/// `Display` message, matching the discipline already established by
/// [`ParseFormatCoordinatesError`] (commit `06a2f42`) and
/// [`crate::ParsePartitionOrdinalError`] (commit `6b20041`). A
/// renderer printing the error doesn't have to scrape the original
/// input from its own context — the offending bytes ride with the
/// error.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseFormatMetadataTagError {
    /// Input doesn't begin with a recognized `"<format>: "` prefix for
    /// any shikumi-built provider (`lisp: ` / `nix: `).
    #[error(
        "FormatMetadataTag input does not match any \
         shikumi-built provider's `<format>: <path>` prefix \
         (one of `lisp: `, `nix: `): {input:?}"
    )]
    NoMatchingShikumiProviderPrefix {
        /// The offending input string, verbatim.
        input: String,
    },
}

impl<'a> TryFrom<&'a str> for FormatMetadataTag<'a> {
    type Error = ParseFormatMetadataTagError;

    /// Parse a `figment::Metadata::name` string into a typed envelope —
    /// idiom-peer of [`Format::parse_metadata_tag`] at the type's own
    /// surface, so a consumer can write
    /// `FormatMetadataTag::try_from(name)?` instead of reaching into
    /// [`Format`] for the parse.
    ///
    /// Routes through [`Format::parse_metadata_tag`] for the parse
    /// (preserving the path-borrow into `name` and the exhaustive sweep
    /// over [`FormatProvenance::ShikumiBuilt`]'s formats), and promotes
    /// the `None` arm to
    /// [`ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix`]
    /// carrying the offending `input` verbatim.
    ///
    /// **Round-trip law** — for every shikumi-built provider's
    /// metadata-name string produced by [`Format::metadata_name`],
    /// `FormatMetadataTag::try_from(&name)?` recovers a structurally
    /// equal envelope. Pinned by
    /// [`tests::format_metadata_tag_try_from_round_trips_for_shikumi_providers`].
    ///
    /// **Same `None` / `Err` boundary as
    /// [`Format::parse_metadata_tag`]** — figment-builtin formats
    /// (Yaml/Toml) and unrelated strings reject through the
    /// `NoMatchingShikumiProviderPrefix` arm. Pinned by
    /// [`tests::format_metadata_tag_try_from_rejects_non_shikumi_provider_prefixes`]
    /// and
    /// [`tests::format_metadata_tag_try_from_rejects_unrelated_strings_with_input_verbatim`].
    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        Format::parse_metadata_tag(input).ok_or_else(|| {
            ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix {
                input: input.to_owned(),
            }
        })
    }
}

impl TryFrom<&Path> for Format {
    type Error = ShikumiError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::from_path(path).ok_or_else(|| {
            ShikumiError::Parse(format!(
                "cannot determine config format from path: {}",
                path.display()
            ))
        })
    }
}

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the format closed-enum, lifted to one macro via the
// explicit-parser arm of `closed_axis_label_string_surface!`. Format is
// the alias-accepting member of the closed-axis cohort — `from_extension`
// accepts `yml`/`lsp`/`el` alongside the canonical `yaml`/`lisp`, so the
// FromStr lowering must route through `Self::from_extension` rather than
// the default `from_canonical_str` parser. The macro's `parser =` slot
// is exactly that affordance. Behavior is byte-identical to the prior
// hand-rolled impls: the verbatim-label `Parse` error body
// (`format!("unknown config format: {s}")` ≡
// `format!("{}: {}", "unknown config format", s)`), the
// `collect_str`-based serde emission, the visitor's `expecting` string,
// and the `visit_str` lowering through `FromStr` all match pointwise.
// Pinned by `tests::format_display_matches_as_str`,
// `tests::format_from_str_*`, `tests::format_serde_yaml_*`, and
// `tests::format_serde_json_*`.
closed_axis_label_string_surface! {
    type = Format,
    parse_error = "unknown config format",
    expecting = "a canonical Format lowercase label \
                 (`yaml`, `toml`, `lisp`, `nix`, `b`; aliases `yml`/`lsp`/`el` accepted)",
    parser = Format::from_extension,
}

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the provenance closed-enum, lifted to one macro after the
// 17+ hand-rolled idiom-peers preceding this commit (WatchEventClass at
// `94f8a8b`, ShikumiErrorKind at `4b53792`, DiffLineKind at `74ee853`,
// ConfigSourceKind at `ae24a13`). See `closed_axis_label_string_surface!`
// in `crate::macros` for the contract; behavior is byte-identical to the
// hand-rolled impls the macro replaces — the verbatim-label `Parse` error
// body, the case-insensitive `from_canonical_str` lowering, the
// `collect_str`-based serde emission, and the visitor's `expecting`
// message all match the prior surface pointwise. Pinned by
// `tests::format_provenance_display_matches_as_str`,
// `tests::format_provenance_from_str_*`, and
// `tests::format_provenance_serde_yaml_*` /
// `tests::format_provenance_serde_json_*`.
closed_axis_label_string_surface! {
    type = FormatProvenance,
    parse_error = "unknown format provenance",
    expecting = "a canonical FormatProvenance kebab-case label \
                 (`figment-builtin`, `shikumi-built`; case-insensitive)",
}

/// Resolve a directory by checking a builder-supplied override first,
/// then falling back to a named environment variable.
///
/// Returns the override path verbatim when `override_dir` is `Some`,
/// regardless of whether `env_var` is set in the process environment —
/// the builder override is load-bearing for deterministic testing
/// (`ConfigDiscovery::xdg_config_home` / `ConfigDiscovery::home_dir`
/// pin the resolution away from the host's `$XDG_CONFIG_HOME` / `$HOME`)
/// and must dominate the env layer in lockstep. On no override, returns
/// the env var's value as a `PathBuf` if the variable is set; `None`
/// otherwise.
///
/// The single source of truth for the
/// `(builder-override → env-var fallback)` resolution shape that
/// [`ConfigDiscovery::resolve_xdg_config_home`] and
/// [`ConfigDiscovery::resolve_home`] previously open-coded as their own
/// `if let Some(ref dir) = self.X { return Some(dir.clone()) } else
/// env::var(NAME).ok().map(PathBuf::from)` chains. Lifting both to one
/// primitive collapses the duplication and pins the override-dominance
/// contract at one site. A future builder-overridable directory env var
/// (e.g. a hypothetical `XDG_DATA_HOME` override, an `XDG_STATE_HOME`
/// override for a future hierarchical layer, an
/// `XDG_RUNTIME_DIR` override for an ephemeral-config layer) calls this
/// primitive instead of inlining a third copy.
///
/// Peer to [`ConfigDiscovery::resolve_env_override`] on the
/// env-override-axis: that primitive maps a builder-named env var
/// straight to a path (no fallback — the env var *is* the path
/// candidate); this primitive uses the env var as a *fallback* when no
/// builder override is supplied. The two shapes are distinct directions
/// on the `(builder override × env var)` axis and stay as separate
/// primitives.
fn dir_override_or_env(override_dir: Option<&Path>, env_var: &str) -> Option<PathBuf> {
    override_dir.map(Path::to_path_buf).or_else(|| {
        // A non-absolute value from the ENVIRONMENT is IGNORED, not joined.
        // This function is the shared resolution primitive for both
        // $XDG_CONFIG_HOME and $HOME, and shikumi is a dependency of 81 fleet
        // repos, so a relative value here made config discovery resolve
        // against the invoking directory everywhere at once — the
        // masked-branch class (theory/MASKED-BRANCH.md) at its widest reach.
        //
        // `env::var` is kept rather than `var_os`: switching would newly
        // accept non-UTF-8 values that today fall through as NotUnicode, and
        // this change is meant to REMOVE a resolution, not add one.
        //
        // The builder-override arm is deliberately untouched. That path is a
        // programmatic choice by the consuming program, not an operator
        // environment; a caller passing a relative Path did so on purpose.
        env::var(env_var)
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    })
}

/// Builder for config file discovery.
///
/// Scans XDG paths, `$HOME/.config/{app}/`, and legacy `$HOME/.{app}`
/// locations. The first existing file wins.
///
/// When `hierarchical()` is enabled, `discover_all()` returns all config
/// files found across multiple layers (system, user, repo-local), plus
/// partial configs (`.{app}-*.yaml`), in merge order (lowest priority first).
pub struct ConfigDiscovery {
    app_name: String,
    env_override: Option<String>,
    formats: Vec<Format>,
    hierarchical: bool,
    start_dir: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    home_dir: Option<PathBuf>,
}

impl ConfigDiscovery {
    /// Create a new discovery for the given app name.
    ///
    /// Default format preference: YAML, then TOML, then the shikumi-built
    /// formats.
    ///
    /// ── ★ THIS DEFAULT USED TO CONTRADICT THE MODULE'S OWN DOC ────────
    /// It was `[Yaml, Toml]`, so `.lisp`, `.nix` and `.b` files were never
    /// DISCOVERED by extension — a provider could be pointed at one, but
    /// nothing found one on its own. The module doc above and the fleet
    /// doctrine both described the richer set, and both read as merely
    /// aspirational rather than wrong.
    ///
    /// **YAML stays first, deliberately.** Extending the SET is the fix;
    /// re-ranking it is a different decision. `format_yaml_first_by_default`
    /// pins that precedence as a contract, and an operator with both a
    /// `config.yaml` and a `config.b` on disk should not have the file their
    /// deployment already resolves silently change underneath them because a
    /// new format landed. A caller who wants blue to win says so with
    /// `.formats(&[Format::Blue, …])`.
    #[must_use]
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
            env_override: None,
            formats: vec![
                Format::Yaml,
                Format::Toml,
                Format::Lisp,
                Format::Nix,
                Format::Blue,
            ],
            hierarchical: false,
            start_dir: None,
            xdg_config_home: None,
            home_dir: None,
        }
    }

    /// Set the environment variable to check first (e.g. `"MYAPP_CONFIG"`).
    #[must_use]
    pub fn env_override(mut self, var: impl Into<String>) -> Self {
        self.env_override = Some(var.into());
        self
    }

    /// Override the format preference order.
    #[must_use]
    pub fn formats(mut self, formats: &[Format]) -> Self {
        self.formats = formats.to_vec();
        self
    }

    /// Return all standard paths that would be checked, in order.
    #[must_use]
    pub fn standard_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let app = &self.app_name;
        let xdg = self.resolve_xdg_config_home();
        let home = self.resolve_home();

        for ext in self.configured_extensions() {
            if let Some(ref xdg) = xdg {
                paths.push(xdg.join(format!("{app}/{app}.{ext}")));
            }
            if let Some(ref home) = home {
                paths.push(home.join(format!(".config/{app}/{app}.{ext}")));
            }
        }

        if let Some(ref home) = home {
            paths.push(home.join(format!(".{app}")));
            paths.push(home.join(format!(".{app}.toml")));
        }

        paths
    }

    /// Enable hierarchical search with merge.
    ///
    /// When enabled, `discover_all()` searches multiple layers in order:
    /// 1. `/etc/{app}/{app}.yaml` (system-wide, lowest priority)
    /// 2. `~/.config/{app}/{app}.yaml` (user-level, via XDG)
    /// 3. Walk up from CWD looking for `.{app}.yaml` at each directory level
    /// 4. Partial configs: `.{app}-*.yaml` files in same directories, merged alphabetically
    #[must_use]
    pub fn hierarchical(mut self) -> Self {
        self.hierarchical = true;
        self
    }

    /// Override the starting directory for hierarchical walk-up discovery.
    ///
    /// By default, hierarchical discovery walks up from the current working
    /// directory. Use this to start from an explicit directory instead,
    /// which is also useful for deterministic testing.
    #[must_use]
    pub fn start_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.start_dir = Some(dir.into());
        self
    }

    /// Override `$XDG_CONFIG_HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the
    /// `XDG_CONFIG_HOME` environment variable. Useful for testing.
    #[must_use]
    pub fn xdg_config_home(mut self, dir: impl Into<PathBuf>) -> Self {
        self.xdg_config_home = Some(dir.into());
        self
    }

    /// Override `$HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the `HOME`
    /// environment variable. Useful for testing.
    #[must_use]
    pub fn home_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.home_dir = Some(dir.into());
        self
    }

    /// Discover the config file path.
    ///
    /// Checks the env override first, then scans standard paths.
    /// Returns the first existing path, or an error listing all tried paths.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::NotFound` if no config file exists at any
    /// of the standard locations.
    pub fn discover(&self) -> Result<PathBuf, ShikumiError> {
        let mut tried: Vec<PathBuf> = Vec::new();

        if let Some(env_path) = self.resolve_env_override() {
            tried.push(env_path.clone());
            if env_path.exists() {
                return Ok(env_path);
            }
            if let Some(ref var) = self.env_override {
                warn!(
                    "${var} is set to {}, but the file does not exist. Falling back to defaults.",
                    env_path.display()
                );
            }
        }

        // 2. Standard XDG / home paths
        let paths = self.standard_paths();
        for path in &paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        tried.extend(paths);

        Err(ShikumiError::NotFound { tried })
    }

    /// Discover the config file, or return a default path if none exists.
    ///
    /// Unlike [`discover()`](Self::discover), this never returns `NotFound`.
    /// Useful when you want to create a config at the preferred location.
    #[must_use]
    pub fn discover_or_default(&self) -> PathBuf {
        self.discover().unwrap_or_else(|_| {
            self.standard_paths()
                .into_iter()
                .next()
                .unwrap_or_else(|| PathBuf::from(format!(".{}.yaml", self.app_name)))
        })
    }

    /// Discover all config files in the hierarchy and return merged paths.
    ///
    /// Returns paths in merge order (lowest priority first, highest priority last).
    /// When `hierarchical()` is enabled, searches:
    /// 1. `/etc/{app}/{app}.yaml` + partials (system-wide)
    /// 2. `~/.config/{app}/{app}.yaml` + partials (user-level)
    /// 3. Walk up from CWD to root: `.{app}.yaml` + partials at each level
    ///    (root = lowest priority, CWD = highest priority)
    ///
    /// Missing files are silently skipped. Only existing files are returned.
    ///
    /// If `hierarchical()` was not called, this behaves like `discover()`
    /// but returns all existing standard paths instead of just the first.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::NotFound` if no config files exist at any
    /// of the searched locations.
    pub fn discover_all(&self) -> Result<Vec<PathBuf>, ShikumiError> {
        let mut found: Vec<PathBuf> = Vec::new();
        // Every main-config candidate path actually checked, in search
        // order. Accumulated alongside `found` so the NotFound report is
        // the search itself, not a re-fabricated guess that can drift from
        // (and lie about) which paths were resolved and which formats were
        // honored.
        let mut tried: Vec<PathBuf> = Vec::new();
        let app = &self.app_name;

        if self.hierarchical {
            // Layer 1: /etc/{app}/{app}.{ext} (system-wide, lowest priority)
            self.collect_configs(
                &PathBuf::from(format!("/etc/{app}")),
                app,
                NameStyle::Bare,
                &mut found,
                &mut tried,
            );

            // Layer 2: ~/.config/{app}/{app}.{ext} (user-level)
            if let Some(config_dir) = self.user_config_dir() {
                self.collect_configs(
                    &config_dir.join(app),
                    app,
                    NameStyle::Bare,
                    &mut found,
                    &mut tried,
                );
            }

            let start = self.start_dir.clone().or_else(|| env::current_dir().ok());

            if let Some(cwd) = start {
                let mut ancestors: Vec<PathBuf> = Vec::new();
                let mut current = Some(cwd.as_path());
                while let Some(dir) = current {
                    ancestors.push(dir.to_path_buf());
                    current = dir.parent();
                }
                ancestors.reverse();

                for dir in &ancestors {
                    self.collect_configs(dir, app, NameStyle::Dotfile, &mut found, &mut tried);
                }
            }
        } else {
            // Non-hierarchical: return all existing standard paths
            if let Some(env_path) = self.resolve_env_override() {
                tried.push(env_path.clone());
                if env_path.exists() {
                    found.push(env_path);
                }
            }

            for path in self.standard_paths() {
                tried.push(path.clone());
                if path.exists() {
                    found.push(path);
                }
            }
        }

        if found.is_empty() {
            Err(ShikumiError::NotFound { tried })
        } else {
            Ok(found)
        }
    }

    /// Resolve the env-override path, if configured and set in the
    /// process environment. Returns `Some(path)` when both
    /// [`Self::env_override`] has named a variable and that variable
    /// is set; `None` otherwise. The returned path is **not** checked
    /// for existence — callers stat it themselves and decide whether
    /// to fall back to the standard search.
    ///
    /// The single source of truth for the
    /// `(env_override var name → resolved candidate path)` lookup.
    /// [`Self::discover`] and [`Self::discover_all`]'s non-hierarchical
    /// branch previously open-coded the same
    /// `if let Some(ref var) = self.env_override
    /// && let Ok(path_str) = env::var(var) { let path =
    /// PathBuf::from(&path_str); … }` shape at both sites — same
    /// var lookup, same `PathBuf::from`, same handling fork between
    /// exists / does-not-exist. Lifting the resolution to one method
    /// collapses the duplication to a single typed primitive and
    /// makes the candidate path observable to the search-derives-
    /// report discipline (see [`Self::discover_all`]'s `tried`
    /// accumulator): the env-override path is now recorded in
    /// `ShikumiError::NotFound::tried` whenever it was actually
    /// checked, so the operator-facing "where did you look?" answer
    /// stays the resolved search rather than dropping the
    /// user-supplied path that was the first place stat'd.
    fn resolve_env_override(&self) -> Option<PathBuf> {
        let var = self.env_override.as_ref()?;
        // Absolute-only, for the same reason as `dir_override_or_env`: this is
        // an operator-set variable naming a config file, and a relative one
        // made which file loads depend on the working directory.
        env::var(var)
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }

    /// Resolve `XDG_CONFIG_HOME`, preferring the builder override.
    ///
    /// Routes through [`dir_override_or_env`], the one
    /// `(builder-override → env-var fallback)` resolution primitive
    /// shared with [`Self::resolve_home`]; the shape lives at one site
    /// rather than two parallel `if let Some(ref dir) = self.X { … }
    /// else env::var(NAME)` chains.
    fn resolve_xdg_config_home(&self) -> Option<PathBuf> {
        dir_override_or_env(self.xdg_config_home.as_deref(), "XDG_CONFIG_HOME")
    }

    /// Resolve `HOME`, preferring the builder override.
    ///
    /// Routes through [`dir_override_or_env`], the one
    /// `(builder-override → env-var fallback)` resolution primitive
    /// shared with [`Self::resolve_xdg_config_home`]; the shape lives
    /// at one site rather than two parallel `if let Some(ref dir) =
    /// self.X { … } else env::var(NAME)` chains.
    fn resolve_home(&self) -> Option<PathBuf> {
        dir_override_or_env(self.home_dir.as_deref(), "HOME")
    }

    /// Resolve the user config directory.
    ///
    /// Prefers `$XDG_CONFIG_HOME`, falls back to `$HOME/.config`.
    fn user_config_dir(&self) -> Option<PathBuf> {
        if let Some(xdg) = self.resolve_xdg_config_home() {
            return Some(xdg);
        }
        self.resolve_home().map(|home| home.join(".config"))
    }

    /// Collect main config + partials from a directory using the given naming style.
    ///
    /// `Bare`: `{dir}/{app}.{ext}` and `{dir}/{app}-*.{ext}` partials.
    /// `Dotfile`: `{dir}/.{app}.{ext}` and `{dir}/.{app}-*.{ext}` partials.
    ///
    /// Every main candidate path is recorded in `tried` (whether or not it
    /// exists) before its existence is tested, so the searched-path list a
    /// [`ShikumiError::NotFound`] reports is derived from the same loop that
    /// does the stat — the report cannot drift from the resolved directories
    /// or the configured formats. Globbed partials are not individual candidate
    /// paths and are not recorded, matching `standard_paths` (which lists
    /// main candidates only).
    fn collect_configs(
        &self,
        dir: &Path,
        app: &str,
        style: NameStyle,
        found: &mut Vec<PathBuf>,
        tried: &mut Vec<PathBuf>,
    ) {
        for ext in self.configured_extensions() {
            let main_path = dir.join(style.main_filename(app, ext));
            tried.push(main_path.clone());
            if main_path.exists() {
                found.push(main_path);
            }
        }
        self.collect_partials(dir, app, style, found);
    }

    /// Collect partial configs matching `[.]{app}-*.{ext}` in a directory.
    fn collect_partials(&self, dir: &Path, app: &str, style: NameStyle, found: &mut Vec<PathBuf>) {
        if !dir.is_dir() {
            return;
        }
        let mut partials: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if self.is_partial_match(&name_str, app, style) {
                    partials.push(entry.path());
                }
            }
        }
        partials.sort();
        found.extend(partials);
    }

    /// Check if a filename matches the partial pattern `[.]{app}-*.{ext}`.
    ///
    /// The extension arm routes through [`Format::from_path`] — the same
    /// path→[`Format`] classifier that [`Self::discover`] /
    /// [`Self::discover_all`]'s primary paths reach via
    /// [`crate::ProviderChain::with_file`] — and then gates the result on
    /// [`Self::formats`] membership. Before this lift the arm iterated
    /// [`Self::configured_extensions`] and called `name.ends_with(&format!(".{ext}"))`
    /// for each extension: two drift-classes ran open in that shape and
    /// this lift closes both together —
    ///
    /// - **Alias-algebra drift with primary discovery.** [`Format::from_path`]
    ///   (and its underlying [`Format::from_extension`]) is ASCII
    ///   case-insensitive; `name.ends_with(&format!(".{ext}"))` is
    ///   case-sensitive. Primary discovery would recognize a file named
    ///   `app-theme.YAML` as YAML — `nix-darwin`'s default filesystem is
    ///   case-insensitive so the on-disk case is not guaranteed to be
    ///   lower — while partial discovery would silently skip it. The
    ///   two directions of one alias algebra now agree by construction:
    ///   [`Format::from_path`] is the single site case-insensitivity is
    ///   defined and both callers reach it.
    /// - **Per-check allocation.** `format!(".{ext}")` allocated one
    ///   [`String`] per configured extension per file name checked — for
    ///   the default 8-alias set (`yaml`, `yml`, `toml`, `lisp`, `lsp`,
    ///   `el`, `nix`, `b`), up to 8 heap allocations per directory entry
    ///   in [`Self::collect_partials`]'s inner loop. [`Format::from_path`]
    ///   composes [`Path::extension`] with the derivation-shipped
    ///   [`Format::from_extension`] (which does byte-wise
    ///   [`str::eq_ignore_ascii_case`] against `&'static` slices), so the
    ///   check is now allocation-free on the classifier side.
    ///
    /// A future [`Format`] variant landing (e.g. `Json`, `Hocon`) becomes
    /// recognizable on the partial-discovery axis by construction, in
    /// lockstep with the primary-discovery axis: both reach
    /// [`Format::from_extension`] as the one alias-set table (shipped by
    /// commit `d90e9dd`, which derived `Format::from_extension` from
    /// `Format::extensions`).
    fn is_partial_match(&self, name: &str, app: &str, style: NameStyle) -> bool {
        name.starts_with(&style.partial_prefix(app))
            && Format::from_path(Path::new(name))
                .is_some_and(|format| self.formats.contains(&format))
    }

    /// Iterator over every file extension this discovery honors, in the
    /// preference order set by [`Self::formats`].
    ///
    /// The flat cartesian product of `self.formats` × `Format::extensions()`:
    /// the default `[Yaml, Toml]` yields `["yaml", "yml", "toml"]`; an
    /// explicit `formats(&[Format::Toml, Format::Yaml])` flips to
    /// `["toml", "yaml", "yml"]`. Empty `formats` yields zero items.
    ///
    /// Naming the return type at the API boundary (rather than the prior
    /// `impl Iterator<Item = &'static str> + '_`) exposes the full trait
    /// algebra the underlying nested-slice walker structurally carries —
    /// [`DoubleEndedIterator`], [`std::iter::FusedIterator`], [`Clone`],
    /// and [`Debug`][std::fmt::Debug] — and lets a caller hold the
    /// walker in a struct field or return it up through their own API
    /// without smuggling an unnameable [`impl Trait`][impl-trait] across
    /// every seam. Closes the last `impl Trait`-returning iter in
    /// shikumi: every iter-returning seam in the codebase now spells its
    /// concrete return type at the API boundary.
    ///
    /// One typed primitive owns the (formats × extensions) shape that
    /// [`Self::standard_paths`], [`Self::collect_configs`], and
    /// [`Self::is_partial_match`] previously open-coded as a nested
    /// `for format in &self.formats { for ext in format.extensions() }`
    /// loop. Adding a new [`Format`] variant (e.g. `Json`, `Hocon`) means
    /// extending [`Format::extensions`] in one place — every consumer
    /// here observes the new extension automatically, and the loop body
    /// at each consumer stays at one level of nesting.
    ///
    /// [impl-trait]: https://doc.rust-lang.org/reference/types/impl-trait.html
    #[must_use]
    pub fn configured_extensions(&self) -> ConfiguredExtensions<'_> {
        ConfiguredExtensions {
            inner: self
                .formats
                .iter()
                .copied()
                .flat_map(format_extensions_copied),
        }
    }
}

/// Free-function projection lifting a [`Format`] to its extension slice
/// as an owned [`std::iter::Copied`] cursor.
///
/// A `fn` item (not a closure): its type is `fn(Format) ->
/// std::iter::Copied<std::slice::Iter<'static, &'static str>>`, which
/// coerces to a `fn` pointer at the [`std::iter::FlatMap`] third-type-
/// parameter position inside [`ConfiguredExtensions`]. A bare
/// closure `|f| f.extensions().iter().copied()` would be equivalent
/// at the value level but carries an unnameable opaque type — using
/// a named `fn` item gives the flat-map a spellable closure-position
/// type, which is what lets [`ConfiguredExtensions`] itself spell its
/// full internal type.
///
/// Takes [`Format`] by value (not `&Format`): [`Format`] is `Copy` and
/// smaller than a pointer, so the value form is the idiomatic call
/// shape (and the shape `clippy::trivially_copy_pass_by_ref` demands
/// for `Copy` types). The upstream [`std::slice::Iter<'_, Format>`]
/// is `.copied()`-lifted to `Copied<Iter<Format>>` so the flat-map's
/// closure position accepts a `Format` value directly.
fn format_extensions_copied(
    f: Format,
) -> std::iter::Copied<std::slice::Iter<'static, &'static str>> {
    f.extensions().iter().copied()
}

/// Zero-allocation `&'static str` stream over the file extensions a
/// [`ConfigDiscovery`] honors, in the preference order set by
/// [`ConfigDiscovery::formats`].
///
/// The concrete return type of
/// [`ConfigDiscovery::configured_extensions`]. Naming the walker at
/// the API boundary (rather than
/// `impl Iterator<Item = &'static str> + '_`) exposes the full trait
/// algebra the underlying nested-slice walker structurally carries —
/// [`DoubleEndedIterator`], [`std::iter::FusedIterator`], [`Clone`],
/// and [`Debug`][std::fmt::Debug] — and lets a caller hold the walker
/// in a struct field or return it up through their own API without
/// smuggling an unnameable [`impl Trait`][impl-trait] across every
/// seam.
///
/// # Trait algebra
///
/// Impls [`Iterator`] + [`DoubleEndedIterator`] +
/// [`std::iter::FusedIterator`] + [`Clone`] + [`Debug`][std::fmt::Debug].
/// The underlying [`std::iter::FlatMap`] structurally carries all five
/// — the outer [`std::slice::Iter<'_, Format>`][slice-iter] and each
/// inner [`std::iter::Copied<std::slice::Iter<'static, &'static str>>`]
/// carry them, and the closure position is materialized as a `fn`
/// pointer (which is `Copy` + `Clone` + `Debug`) via
/// [`format_extensions_copied`].
///
/// [`ExactSizeIterator`] is intentionally NOT impl'd — the inner
/// per-format extensions slice has [`Format`]-dependent variable
/// length (`Yaml` has two, `Lisp` has three, `Toml` and `Nix` have
/// one), so the total-length invariant can't be honored structurally
/// through [`std::iter::FlatMap`]. This matches the trait bundle
/// carried by the filter-based cube-slot peers
/// [`crate::RealizableIter`] / [`crate::UnrealizableIter`] and the
/// histogram-altitude peers [`crate::AxisHistogramNonzero`] /
/// [`crate::AxisHistogramObserved`] /
/// [`crate::AxisHistogramUnobserved`]; strictly weaker than the
/// five-trait element-preserving peers [`crate::AxisIter`] /
/// [`crate::ProvenanceMapEntries`] / [`crate::ForwardIter`], which
/// additionally carry [`ExactSizeIterator`].
///
/// [impl-trait]: https://doc.rust-lang.org/reference/types/impl-trait.html
/// [slice-iter]: std::slice::Iter
///
/// # Field access
///
/// The struct field is private — the public surface is the
/// `Iterator` / `DoubleEndedIterator` / `FusedIterator` / `Clone` trait
/// impls plus the [`Debug`][std::fmt::Debug] derive.
#[derive(Clone, Debug)]
pub struct ConfiguredExtensions<'a> {
    inner: ConfiguredExtensionsInner<'a>,
}

/// Named alias for the [`std::iter::FlatMap`] type
/// [`ConfiguredExtensions`] wraps.
///
/// The alias exists purely so [`ConfiguredExtensions`]'s single field
/// can spell a name that stays under `clippy::type_complexity`; the
/// concrete algebra is unchanged. Two entrance seams (the `Copied`-
/// lifted [`Format`] slice and the per-format extensions inner slice)
/// fold into one `&'static str` stream via [`format_extensions_copied`]
/// as the closure position.
type ConfiguredExtensionsInner<'a> = std::iter::FlatMap<
    std::iter::Copied<std::slice::Iter<'a, Format>>,
    std::iter::Copied<std::slice::Iter<'static, &'static str>>,
    fn(Format) -> std::iter::Copied<std::slice::Iter<'static, &'static str>>,
>;

impl Iterator for ConfiguredExtensions<'_> {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for ConfiguredExtensions<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl std::iter::FusedIterator for ConfiguredExtensions<'_> {}

/// How config files are named within a directory.
///
/// Each variant is a typed morphism `(app, ext) → filename`. Adding a new
/// naming convention (e.g. an `App/config.{ext}` subdirectory style, or a
/// `{app}.{environment}.{ext}` overlay style) means adding a variant — the
/// compiler then forces every call site (main-file construction, partial
/// prefix construction, future filename queries) to handle it.
///
/// This replaces a `dot_prefix: bool` flag previously threaded through
/// `collect_*_configs` / `collect_partials` / `is_partial_match`. The bool
/// was load-bearing — it controlled both the main filename and the partial
/// prefix in lockstep — but its meaning was implicit in every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameStyle {
    /// `{app}.{ext}` and `{app}-*.{ext}` — used in `/etc/{app}/`,
    /// `~/.config/{app}/`, and any structured config directory.
    Bare,
    /// `.{app}.{ext}` and `.{app}-*.{ext}` — used during CWD walk-up
    /// discovery, where dot-prefixed files keep configs out of `ls`.
    Dotfile,
}

impl NameStyle {
    /// The main config filename for this style: `{prefix}{app}.{ext}`.
    fn main_filename(self, app: &str, ext: &str) -> String {
        match self {
            Self::Bare => format!("{app}.{ext}"),
            Self::Dotfile => format!(".{app}.{ext}"),
        }
    }

    /// The partial-config filename prefix for this style: `{prefix}{app}-`.
    ///
    /// A partial filename is anything starting with this prefix and ending
    /// with a recognized config extension.
    fn partial_prefix(self, app: &str) -> String {
        match self {
            Self::Bare => format!("{app}-"),
            Self::Dotfile => format!(".{app}-"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn format_display_round_trip() {
        for fmt in [Format::Yaml, Format::Toml] {
            let s = fmt.to_string();
            let parsed: Format = s.parse().unwrap();
            assert_eq!(fmt, parsed);
        }
    }

    #[test]
    fn format_from_str_case_insensitive() {
        assert_eq!("YAML".parse::<Format>().unwrap(), Format::Yaml);
        assert_eq!("yml".parse::<Format>().unwrap(), Format::Yaml);
        assert_eq!("TOML".parse::<Format>().unwrap(), Format::Toml);
        assert!("json".parse::<Format>().is_err());
    }

    #[test]
    fn format_default_is_yaml() {
        assert_eq!(Format::default(), Format::Yaml);
    }

    #[test]
    fn format_from_extension() {
        assert_eq!(Format::from_extension("yaml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("yml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("toml"), Some(Format::Toml));
        assert_eq!(Format::from_extension("json"), None);
        assert_eq!(Format::from_extension(""), None);
    }

    #[test]
    fn format_from_extension_is_case_insensitive() {
        // The `(extension-token -> Format)` map matches ASCII-case-
        // insensitively, mirroring the long-standing `FromStr` behavior:
        // every recognized extension, in any case, resolves to its format.
        assert_eq!(Format::from_extension("YAML"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("Yml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("TOML"), Some(Format::Toml));
        assert_eq!(Format::from_extension("LISP"), Some(Format::Lisp));
        assert_eq!(Format::from_extension("Lsp"), Some(Format::Lisp));
        assert_eq!(Format::from_extension("EL"), Some(Format::Lisp));
        assert_eq!(Format::from_extension("Nix"), Some(Format::Nix));
        // Unrecognized tokens stay None regardless of case.
        assert_eq!(Format::from_extension("JSON"), None);
    }

    #[test]
    fn format_from_extension_recognizes_every_declared_alias() {
        // Structural pin on the invariant that lets `from_extension` derive
        // from `extensions()` instead of mirroring the alias set in a
        // second match: EVERY extension declared by ANY format resolves
        // back to that format, both in its declared case and lifted to
        // uppercase (the nix-darwin case-insensitive-fs contingency).
        // Adding a new alias to `Format::extensions()` — say
        // `Yaml => &["yaml", "yml", "yaml.j2"]` — is proven end-to-end
        // by this test alone, no lockstep edit to `from_extension`.
        for &format in Format::ALL {
            for &alias in format.extensions() {
                assert_eq!(
                    Format::from_extension(alias),
                    Some(format),
                    "declared alias {alias:?} for {format:?} must round-trip",
                );
                let upper = alias.to_ascii_uppercase();
                assert_eq!(
                    Format::from_extension(&upper),
                    Some(format),
                    "declared alias {alias:?} for {format:?} must round-trip \
                     under ASCII uppercase ({upper:?})",
                );
            }
        }
    }

    #[test]
    fn format_extensions_and_from_extension_round_trip_over_all() {
        // Complements `format_from_extension_recognizes_every_declared_alias`
        // on the same invariant from the OTHER direction: rather than
        // pinning that every declared alias parses back to its declaring
        // format, this pins that the alias set as reached through
        // `from_extension` is the union of `extensions()` — i.e. an
        // alias emitted by `extensions()` for one format cannot silently
        // parse to a different format, and no alias is dropped by the
        // lookup. Together the pair pins the bijection between
        // `Format::extensions()` and the recognized half of
        // `Format::from_extension`, so the sole alias table (in
        // `extensions()`) is the sealed source of truth.
        use std::collections::BTreeSet;
        let mut alias_pairs: BTreeSet<(&'static str, Format)> = BTreeSet::new();
        for &format in Format::ALL {
            for &alias in format.extensions() {
                assert!(
                    alias_pairs.insert((alias, format)),
                    "extensions() double-listed alias {alias:?} for {format:?}",
                );
            }
        }
        for (alias, format) in &alias_pairs {
            assert_eq!(
                Format::from_extension(alias),
                Some(*format),
                "declared alias {alias:?} for {format:?} must reach from_extension",
            );
        }
        // No two distinct formats can claim the same alias: the inverse
        // lookup would be ambiguous. A future variant that duplicates
        // (say) `"yaml"` would break the bijection here rather than
        // silently shadow.
        let mut alias_to_format: std::collections::BTreeMap<&'static str, Format> =
            std::collections::BTreeMap::new();
        for (alias, format) in alias_pairs {
            if let Some(prev) = alias_to_format.insert(alias, format) {
                panic!(
                    "alias {alias:?} declared by both {prev:?} and {format:?} \
                     — the extension→format map would be ambiguous",
                );
            }
        }
    }

    #[test]
    fn format_from_path_case_insensitive_extension() {
        // On the nix-darwin deployment target the default filesystem is
        // case-insensitive, so an env-override path can surface an
        // uppercase extension. Detection must resolve it rather than fall
        // through to the conservative TOML fallback in `with_file`.
        assert_eq!(
            Format::from_path(Path::new("Config.YAML")),
            Some(Format::Yaml)
        );
        assert_eq!(Format::from_path(Path::new("app.YML")), Some(Format::Yaml));
        assert_eq!(Format::from_path(Path::new("App.TOML")), Some(Format::Toml));
        assert_eq!(Format::from_path(Path::new("init.NIX")), Some(Format::Nix));
        assert_eq!(
            Format::try_from(Path::new("Config.YAML")).unwrap(),
            Format::Yaml
        );
    }

    #[test]
    fn format_from_str_agrees_with_from_extension() {
        // `FromStr` is the `ok_or_else` error-wrapping shell over
        // `from_extension`: the alias algebra lives at one site, so the
        // two parsers can never disagree on any input, in any case.
        for s in [
            "yaml", "YAML", "yml", "Yml", "toml", "TOML", "lisp", "lsp", "el", "EL", "nix", "NIX",
            "json", "JSON", "conf", "", "ya ml",
        ] {
            assert_eq!(
                s.parse::<Format>().ok(),
                Format::from_extension(s),
                "FromStr and from_extension disagree on {s:?}"
            );
        }
    }

    #[test]
    fn format_try_from_path() {
        assert_eq!(
            Format::try_from(Path::new("config.yaml")).unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::try_from(Path::new("config.yml")).unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::try_from(Path::new("config.toml")).unwrap(),
            Format::Toml
        );
        assert!(Format::try_from(Path::new("config.json")).is_err());
        assert!(Format::try_from(Path::new("no_extension")).is_err());
    }

    #[test]
    fn format_from_path_recognizes_every_extension() {
        assert_eq!(Format::from_path(Path::new("app.yaml")), Some(Format::Yaml));
        assert_eq!(Format::from_path(Path::new("app.yml")), Some(Format::Yaml));
        assert_eq!(Format::from_path(Path::new("app.toml")), Some(Format::Toml));
        assert_eq!(Format::from_path(Path::new("app.lisp")), Some(Format::Lisp));
        assert_eq!(Format::from_path(Path::new("app.lsp")), Some(Format::Lisp));
        assert_eq!(Format::from_path(Path::new("app.el")), Some(Format::Lisp));
        assert_eq!(Format::from_path(Path::new("app.nix")), Some(Format::Nix));
    }

    #[test]
    fn format_from_path_none_for_unknown_or_absent_extension() {
        assert_eq!(Format::from_path(Path::new("app.json")), None);
        assert_eq!(Format::from_path(Path::new("app.conf")), None);
        assert_eq!(Format::from_path(Path::new("no_extension")), None);
        // A dotfile with no extension (`.app`) has no `OsStr` extension.
        assert_eq!(Format::from_path(Path::new(".app")), None);
    }

    #[test]
    fn format_from_path_respects_full_path() {
        // The detection keys on the final component's extension, not the
        // directory chain — a `.toml` parent dir does not shadow a
        // `.yaml` leaf.
        assert_eq!(
            Format::from_path(Path::new("/etc/app.toml/app.yaml")),
            Some(Format::Yaml)
        );
    }

    #[test]
    fn format_try_from_path_agrees_with_from_path() {
        // `try_from` is the `ok_or_else` wrapper around `from_path`: it
        // succeeds exactly when `from_path` is `Some`, with the same value.
        for path in [
            "a.yaml", "a.yml", "a.toml", "a.lisp", "a.lsp", "a.el", "a.nix", "a.json", "noext",
        ] {
            let p = Path::new(path);
            assert_eq!(
                Format::from_path(p),
                Format::try_from(p).ok(),
                "path: {path}"
            );
        }
    }

    #[test]
    fn standard_paths_contains_xdg_and_home() {
        let d = ConfigDiscovery::new("testapp");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        // Should contain .config/testapp/testapp.yaml somewhere
        assert!(path_strs.iter().any(|p| p.contains("testapp/testapp.yaml")));
        assert!(path_strs.iter().any(|p| p.contains("testapp/testapp.toml")));
    }

    #[test]
    fn discover_finds_existing_file() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("testapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("testapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        // Use env override to point to the file
        let var = "SHIKUMI_TEST_DISCOVER";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("testapp").env_override(var).discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_env_override_nonexistent_falls_back() {
        let var = "SHIKUMI_TEST_NOEXIST";
        unsafe { env::set_var(var, "/nonexistent/path.yaml") };

        let result = ConfigDiscovery::new("shikumi_test_noapp")
            .env_override(var)
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_err());
        match result.unwrap_err() {
            ShikumiError::NotFound { tried } => {
                assert!(!tried.is_empty());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn format_yaml_first_by_default() {
        let d = ConfigDiscovery::new("myapp");
        let paths = d.standard_paths();
        // First path should be yaml (XDG or HOME)
        let first_str = paths[0].display().to_string();
        assert!(
            first_str.ends_with(".yaml") || first_str.ends_with(".yml"),
            "expected yaml first, got: {first_str}"
        );
    }

    #[test]
    fn format_toml_only() {
        let d = ConfigDiscovery::new("myapp").formats(&[Format::Toml]);
        let paths = d.standard_paths();
        // No yaml/yml paths (except legacy)
        for p in &paths {
            let s = p.display().to_string();
            if s.contains(".config/") {
                assert!(s.ends_with(".toml"), "expected toml in XDG paths, got: {s}");
            }
        }
    }

    #[test]
    fn discover_or_default_returns_first_standard_path() {
        let d = ConfigDiscovery::new("shikumi_fallback_xyz");
        let path = d.discover_or_default();
        let s = path.display().to_string();
        assert!(
            s.contains("shikumi_fallback_xyz"),
            "default path should contain app name, got: {s}"
        );
    }

    #[test]
    fn discover_or_default_returns_existing_when_found() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("fallbackapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("fallbackapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_FALLBACK";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let path = ConfigDiscovery::new("fallbackapp")
            .env_override(var)
            .discover_or_default();

        unsafe { env::remove_var(var) };

        assert_eq!(path, config_file);
    }

    #[test]
    fn discover_returns_not_found_with_tried_paths() {
        let result = ConfigDiscovery::new("shikumi_nonexistent_app_xyz").discover();
        assert!(result.is_err());
        if let Err(ShikumiError::NotFound { tried }) = result {
            assert!(!tried.is_empty());
        }
    }

    #[test]
    fn discover_via_xdg_config_home() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("myxdgapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("myxdgapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let result = ConfigDiscovery::new("myxdgapp")
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_via_home_dot_config() {
        let dir = TempDir::new().unwrap();
        let dot_config = dir.path().join(".config").join("homeapp");
        fs::create_dir_all(&dot_config).unwrap();
        let config_file = dot_config.join("homeapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("homeapp")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_legacy_dot_app() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacyapp");
        fs::write(&legacy_file, "some config").unwrap();

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("legacyapp")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_legacy_dot_app_toml() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacytoml.toml");
        fs::write(&legacy_file, "key = \"value\"").unwrap();

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("legacytoml")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_env_override_takes_precedence_over_standard() {
        let env_dir = TempDir::new().unwrap();
        let env_file = env_dir.path().join("override.yaml");
        fs::write(&env_file, "source: env_override").unwrap();

        let xdg_dir = TempDir::new().unwrap();
        let xdg_app_dir = xdg_dir.path().join("precapp");
        fs::create_dir_all(&xdg_app_dir).unwrap();
        let xdg_file = xdg_app_dir.join("precapp.yaml");
        fs::write(&xdg_file, "source: xdg").unwrap();

        let var = "SHIKUMI_TEST_PRECEDENCE";
        unsafe { env::set_var(var, env_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("precapp")
            .env_override(var)
            .xdg_config_home(xdg_dir.path())
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), env_file);
    }

    #[test]
    fn standard_paths_yml_extension_included() {
        let d = ConfigDiscovery::new("ymltest");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.contains("ymltest.yml")),
            "expected .yml variant in standard paths"
        );
    }

    #[test]
    fn discover_prefers_yaml_over_yml() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("preftest");
        fs::create_dir_all(&app_dir).unwrap();
        let yaml_file = app_dir.join("preftest.yaml");
        let yml_file = app_dir.join("preftest.yml");
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&yml_file, "format: yml").unwrap();

        let result = ConfigDiscovery::new("preftest")
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
        assert!(
            result.unwrap().display().to_string().ends_with(".yaml"),
            "expected .yaml to be preferred over .yml"
        );
    }

    #[test]
    fn discover_prefers_yaml_over_toml() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("fmtpref");
        fs::create_dir_all(&app_dir).unwrap();
        let yaml_file = app_dir.join("fmtpref.yaml");
        let toml_file = app_dir.join("fmtpref.toml");
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&toml_file, "format = \"toml\"").unwrap();

        let result = ConfigDiscovery::new("fmtpref")
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
        assert!(
            result.unwrap().display().to_string().ends_with(".yaml"),
            "expected yaml to be preferred over toml by default"
        );
    }

    #[test]
    fn format_toml_before_yaml() {
        let d = ConfigDiscovery::new("revapp").formats(&[Format::Toml, Format::Yaml]);
        let paths = d.standard_paths();
        // Find first .config path; it should be .toml
        let first_config_path = paths
            .iter()
            .find(|p| p.display().to_string().contains(".config/"))
            .expect("should have .config paths");
        assert!(
            first_config_path.display().to_string().ends_with(".toml"),
            "expected toml first when Format::Toml is listed first"
        );
    }

    #[test]
    fn standard_paths_include_legacy_entries() {
        let d = ConfigDiscovery::new("legapp");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".legapp")),
            "expected legacy $HOME/.legapp path"
        );
        assert!(
            path_strs.iter().any(|p| p.ends_with(".legapp.toml")),
            "expected legacy $HOME/.legapp.toml path"
        );
    }

    #[test]
    fn discover_no_env_override_set() {
        // When env_override var is specified but not set in the environment,
        // discovery should fall through to standard paths
        let result = ConfigDiscovery::new("shikumi_test_unset_env_xyz")
            .env_override("SHIKUMI_UNSET_VAR_XYZ")
            .discover();
        // Should fail (no standard files exist for this app name)
        assert!(result.is_err());
    }

    #[test]
    fn formats_empty_still_has_legacy_paths() {
        let d = ConfigDiscovery::new("emptyformats").formats(&[]);
        let paths = d.standard_paths();
        // Even with no formats, legacy paths should still appear
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".emptyformats")),
            "expected legacy path even with empty formats"
        );
    }

    #[test]
    fn format_extensions_yaml() {
        let exts = Format::Yaml.extensions();
        assert_eq!(exts, &["yaml", "yml"]);
    }

    #[test]
    fn format_extensions_toml() {
        let exts = Format::Toml.extensions();
        assert_eq!(exts, &["toml"]);
    }

    #[test]
    fn format_eq_and_clone() {
        let a = Format::Yaml;
        let b = a;
        assert_eq!(a, b);

        let c = Format::Toml;
        assert_ne!(a, c);
    }

    #[test]
    fn not_found_error_lists_all_tried() {
        let result = ConfigDiscovery::new("shikumi_trial_xyz")
            .formats(&[Format::Yaml, Format::Toml])
            .discover();
        if let Err(ShikumiError::NotFound { tried }) = result {
            // Should have XDG yaml, XDG yml, HOME yaml, HOME yml,
            // XDG toml, HOME toml, legacy x2 = multiple paths
            assert!(
                tried.len() >= 4,
                "expected at least 4 tried paths, got {}",
                tried.len()
            );
        } else {
            panic!("expected NotFound error");
        }
    }

    #[test]
    fn discover_not_found_reports_env_override_path_when_set_but_absent() {
        // The env-override path is the first place `discover` stats. The
        // NotFound report must include it — the operator-facing answer to
        // "where did you look?" must not drop the user-supplied path.
        // Pinned at the `discover` site as well as the `discover_all`
        // sites (see `hierarchical_discover_all_not_found_reports_resolved_searched_candidates`).
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let nonexistent_env_path = dir_path.join("absent-env-override.yaml");

        let var = "SHIKUMI_TEST_DISC_NF_ENV_OVERRIDE";
        unsafe { env::set_var(var, nonexistent_env_path.to_str().unwrap()) };

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let nonexistent_home = dir_path.join("nonexistent_home");
        let result = ConfigDiscovery::new("shikumi_disc_envrep_xyz_app")
            .env_override(var)
            .xdg_config_home(&nonexistent_xdg)
            .home_dir(&nonexistent_home)
            .discover();

        unsafe { env::remove_var(var) };

        let ShikumiError::NotFound { tried } = result.expect_err("no files exist") else {
            panic!("expected NotFound");
        };

        assert!(
            tried.contains(&nonexistent_env_path),
            "discover() NotFound.tried must include the env-override path \
             that was checked first (the user-supplied path); got: {tried:?}"
        );
        // The standard search candidates are still reported alongside.
        assert!(
            tried.iter().any(|p| p.starts_with(&nonexistent_xdg)),
            "discover() NotFound.tried must also include the resolved XDG \
             candidates; got: {tried:?}"
        );
    }

    #[test]
    fn discover_not_found_omits_env_override_when_var_unset() {
        // No env-override path was checked, so the report must not
        // fabricate one — the report is the resolved search.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let nonexistent_home = dir_path.join("nonexistent_home");

        // env_override names a var that is intentionally NOT set.
        let result = ConfigDiscovery::new("shikumi_disc_envunset_xyz_app")
            .env_override("SHIKUMI_TEST_DISC_NF_UNSET_VAR_XYZ_GUARANTEED_ABSENT")
            .xdg_config_home(&nonexistent_xdg)
            .home_dir(&nonexistent_home)
            .discover();

        let ShikumiError::NotFound { tried } = result.expect_err("no files exist") else {
            panic!("expected NotFound");
        };

        // No path under the env-override variable was resolved, so none
        // should appear in `tried`. Only the resolved XDG/HOME candidates.
        assert!(
            tried
                .iter()
                .all(|p| p.starts_with(&nonexistent_xdg) || p.starts_with(&nonexistent_home)),
            "discover() NotFound.tried must contain only resolved XDG/HOME \
             candidates when env-override var is unset; got: {tried:?}"
        );
        assert!(
            !tried.is_empty(),
            "standard candidates should still be reported"
        );
    }

    #[test]
    fn discover_all_non_hierarchical_not_found_reports_env_override_path() {
        // Sibling fidelity contract for the non-hierarchical branch of
        // `discover_all`: an env-override path checked-and-absent must
        // appear in `tried`, exactly as it does for `discover`.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let nonexistent_env_path = dir_path.join("absent-env-override.yaml");

        let var = "SHIKUMI_TEST_DISC_ALL_NF_ENV_OVERRIDE";
        unsafe { env::set_var(var, nonexistent_env_path.to_str().unwrap()) };

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let nonexistent_home = dir_path.join("nonexistent_home");
        let result = ConfigDiscovery::new("shikumi_disc_all_envrep_xyz_app")
            .env_override(var)
            .xdg_config_home(&nonexistent_xdg)
            .home_dir(&nonexistent_home)
            .discover_all();

        unsafe { env::remove_var(var) };

        let ShikumiError::NotFound { tried } = result.expect_err("no files exist") else {
            panic!("expected NotFound");
        };

        assert!(
            tried.contains(&nonexistent_env_path),
            "discover_all() non-hierarchical NotFound.tried must include \
             the env-override path that was checked; got: {tried:?}"
        );
    }

    #[test]
    fn resolve_env_override_returns_none_when_var_unconfigured() {
        // No env_override builder call → no var to resolve.
        let d = ConfigDiscovery::new("shikumi_resolve_envov_xyz_none_configured");
        assert!(d.resolve_env_override().is_none());
    }

    #[test]
    fn resolve_env_override_returns_none_when_var_unset() {
        // env_override names a var, but the var is not in the environment.
        let d = ConfigDiscovery::new("shikumi_resolve_envov_xyz_var_unset")
            .env_override("SHIKUMI_RESOLVE_ENVOV_UNSET_VAR_GUARANTEED_ABSENT_XYZ");
        assert!(d.resolve_env_override().is_none());
    }

    #[test]
    fn resolve_env_override_returns_path_when_var_set() {
        // env_override names a var and the var is set: returns the
        // resolved path regardless of whether the file exists.
        let var = "SHIKUMI_RESOLVE_ENVOV_SET_VAR_XYZ";
        let synthetic = "/this/path/need/not/exist.yaml";
        unsafe { env::set_var(var, synthetic) };

        let d = ConfigDiscovery::new("shikumi_resolve_envov_xyz_var_set").env_override(var);
        let resolved = d.resolve_env_override();

        unsafe { env::remove_var(var) };

        assert_eq!(resolved, Some(PathBuf::from(synthetic)));
    }

    // ---- Hierarchical discovery tests ----

    #[test]
    fn hierarchical_builder_returns_self() {
        let d = ConfigDiscovery::new("htest").hierarchical();
        assert!(d.hierarchical);
    }

    #[test]
    fn discover_all_non_hierarchical_returns_existing_standard_paths() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("datest");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("datest.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_DISC_ALL";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("datest")
            .env_override(var)
            .discover_all();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(!paths.is_empty());
        assert!(paths.contains(&config_file));
    }

    #[test]
    fn discover_all_non_hierarchical_missing_returns_error() {
        let result = ConfigDiscovery::new("shikumi_disc_all_noexist_xyz").discover_all();
        assert!(result.is_err());
    }

    #[test]
    fn hierarchical_finds_xdg_config() {
        let dir = TempDir::new().unwrap();
        let app = "hierxdg";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "source: xdg").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .hierarchical()
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &config_file),
            "expected XDG config in results, got: {paths:?}"
        );
    }

    #[test]
    fn hierarchical_walkup_finds_dotfile_in_cwd() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hierwalk";
        let dotfile = dir_path.join(format!(".{app}.yaml"));
        fs::write(&dotfile, "source: cwd").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &dotfile),
            "expected CWD dotfile in results, got: {paths:?}"
        );
    }

    #[test]
    fn hierarchical_merge_order_cwd_wins_over_parent() {
        let parent = TempDir::new().unwrap();
        let parent_path = parent.path().canonicalize().unwrap();
        let child = parent_path.join("child");
        fs::create_dir_all(&child).unwrap();

        let app = "hiermerge";
        let parent_file = parent_path.join(format!(".{app}.yaml"));
        let child_file = child.join(format!(".{app}.yaml"));
        fs::write(&parent_file, "level: parent").unwrap();
        fs::write(&child_file, "level: child").unwrap();

        let nonexistent_xdg = parent_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&child)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&parent_file), "should contain parent config");
        assert!(paths.contains(&child_file), "should contain child config");
        let parent_idx = paths.iter().position(|p| p == &parent_file).unwrap();
        let child_idx = paths.iter().position(|p| p == &child_file).unwrap();
        assert!(
            parent_idx < child_idx,
            "parent ({parent_idx}) should come before child ({child_idx}) in merge order"
        );
    }

    #[test]
    fn hierarchical_partials_merge_alphabetically() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hierpart";

        let partial_b = dir_path.join(format!(".{app}-02-beta.yaml"));
        let partial_a = dir_path.join(format!(".{app}-01-alpha.yaml"));
        fs::write(&partial_a, "alpha: true").unwrap();
        fs::write(&partial_b, "beta: true").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&partial_a), "should contain alpha partial");
        assert!(paths.contains(&partial_b), "should contain beta partial");
        let a_idx = paths.iter().position(|p| p == &partial_a).unwrap();
        let b_idx = paths.iter().position(|p| p == &partial_b).unwrap();
        assert!(
            a_idx < b_idx,
            "alpha ({a_idx}) should come before beta ({b_idx}) in alphabetical order"
        );
    }

    #[test]
    fn hierarchical_main_config_before_partials_in_same_dir() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermainpart";

        let main_file = dir_path.join(format!(".{app}.yaml"));
        let partial = dir_path.join(format!(".{app}-01-extra.yaml"));
        fs::write(&main_file, "main: true").unwrap();
        fs::write(&partial, "extra: true").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        let main_idx = paths.iter().position(|p| p == &main_file).unwrap();
        let partial_idx = paths.iter().position(|p| p == &partial).unwrap();
        assert!(
            main_idx < partial_idx,
            "main config ({main_idx}) should come before partial ({partial_idx})"
        );
    }

    #[test]
    fn hierarchical_missing_files_silently_skipped() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermiss";

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_err());
        match result.unwrap_err() {
            ShikumiError::NotFound { tried } => {
                assert!(!tried.is_empty());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn hierarchical_xdg_partials_in_structured_dir() {
        let dir = TempDir::new().unwrap();
        let app = "hierxdgpart";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();

        let main_file = config_dir.join(format!("{app}.yaml"));
        let partial_a = config_dir.join(format!("{app}-01-db.yaml"));
        let partial_b = config_dir.join(format!("{app}-02-cache.yaml"));
        fs::write(&main_file, "app: base").unwrap();
        fs::write(&partial_a, "db: postgres").unwrap();
        fs::write(&partial_b, "cache: redis").unwrap();

        let empty_dir = TempDir::new().unwrap();
        let empty_path = empty_dir.path().canonicalize().unwrap();

        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(dir.path())
            .hierarchical()
            .start_dir(&empty_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&main_file), "should contain main XDG config");
        assert!(paths.contains(&partial_a), "should contain XDG partial a");
        assert!(paths.contains(&partial_b), "should contain XDG partial b");

        let main_idx = paths.iter().position(|p| p == &main_file).unwrap();
        let a_idx = paths.iter().position(|p| p == &partial_a).unwrap();
        let b_idx = paths.iter().position(|p| p == &partial_b).unwrap();
        assert!(main_idx < a_idx, "main before partial a");
        assert!(a_idx < b_idx, "partial a before partial b");
    }

    #[test]
    fn discover_still_works_after_hierarchical() {
        // Ensure the original discover() method is unaffected by hierarchical flag
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("backcompat");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("backcompat.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_BACKCOMPAT";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        // discover() should still work exactly as before
        let result = ConfigDiscovery::new("backcompat")
            .env_override(var)
            .hierarchical()
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn is_partial_match_correct() {
        let d = ConfigDiscovery::new("myapp");

        // Dot-prefixed partials
        assert!(d.is_partial_match(".myapp-01-db.yaml", "myapp", NameStyle::Dotfile));
        assert!(d.is_partial_match(".myapp-extra.yml", "myapp", NameStyle::Dotfile));
        assert!(d.is_partial_match(".myapp-config.toml", "myapp", NameStyle::Dotfile));
        assert!(!d.is_partial_match(".myapp.yaml", "myapp", NameStyle::Dotfile)); // main, not partial
        assert!(!d.is_partial_match("myapp-01.yaml", "myapp", NameStyle::Dotfile)); // no dot prefix
        assert!(!d.is_partial_match(".myapp-01.txt", "myapp", NameStyle::Dotfile)); // wrong extension

        // Non-dot-prefixed partials
        assert!(d.is_partial_match("myapp-01-db.yaml", "myapp", NameStyle::Bare));
        assert!(d.is_partial_match("myapp-extra.toml", "myapp", NameStyle::Bare));
        assert!(!d.is_partial_match(".myapp-01.yaml", "myapp", NameStyle::Bare)); // has dot prefix
        assert!(!d.is_partial_match("myapp.yaml", "myapp", NameStyle::Bare)); // main, not partial
    }

    // ---- NameStyle typed-primitive tests ----

    #[test]
    fn name_style_bare_main_filename() {
        assert_eq!(NameStyle::Bare.main_filename("myapp", "yaml"), "myapp.yaml");
        assert_eq!(NameStyle::Bare.main_filename("myapp", "yml"), "myapp.yml");
        assert_eq!(NameStyle::Bare.main_filename("myapp", "toml"), "myapp.toml");
        assert_eq!(NameStyle::Bare.main_filename("a", "yaml"), "a.yaml");
    }

    #[test]
    fn name_style_dotfile_main_filename() {
        assert_eq!(
            NameStyle::Dotfile.main_filename("myapp", "yaml"),
            ".myapp.yaml"
        );
        assert_eq!(
            NameStyle::Dotfile.main_filename("myapp", "toml"),
            ".myapp.toml"
        );
        assert_eq!(NameStyle::Dotfile.main_filename("a", "yaml"), ".a.yaml");
    }

    #[test]
    fn name_style_bare_partial_prefix() {
        assert_eq!(NameStyle::Bare.partial_prefix("myapp"), "myapp-");
        assert_eq!(NameStyle::Bare.partial_prefix("a"), "a-");
    }

    #[test]
    fn name_style_dotfile_partial_prefix() {
        assert_eq!(NameStyle::Dotfile.partial_prefix("myapp"), ".myapp-");
        assert_eq!(NameStyle::Dotfile.partial_prefix("a"), ".a-");
    }

    #[test]
    fn name_style_main_and_partial_share_prefix() {
        // Within a style, the main filename and the partial prefix share the
        // same `{[.]?{app}}` head — a partial named exactly like the main
        // (no `-suffix`) is not a partial. This is the contract `collect_*`
        // relies on.
        for style in [NameStyle::Bare, NameStyle::Dotfile] {
            let main = style.main_filename("app", "yaml");
            let prefix = style.partial_prefix("app");
            // main starts with the app head but does NOT have the dash.
            let head = prefix.trim_end_matches('-');
            assert!(
                main.starts_with(head),
                "{main} should start with {head} for {style:?}"
            );
            assert!(
                !main.starts_with(prefix.as_str()),
                "{main} must not start with partial prefix {prefix} for {style:?}"
            );
        }
    }

    #[test]
    fn name_style_is_copy() {
        // NameStyle is a typed value, not a borrow — passing it to multiple
        // collect_* call sites (or holding it in a struct) doesn't move it.
        let style = NameStyle::Dotfile;
        let a = style;
        let b = style;
        assert_eq!(a, b);
        assert_eq!(a, NameStyle::Dotfile);
    }

    #[test]
    fn name_style_match_is_exhaustive() {
        // Renders the (style × format × ext) cartesian product through the
        // typed primitive, exercising both variants for every supported ext
        // — proves no call site has been missed.
        for style in [NameStyle::Bare, NameStyle::Dotfile] {
            for format in [Format::Yaml, Format::Toml] {
                for ext in format.extensions() {
                    let main = style.main_filename("test", ext);
                    let prefix = style.partial_prefix("test");
                    assert!(main.ends_with(&format!(".{ext}")));
                    assert!(prefix.ends_with('-'));
                    assert!(prefix.contains("test"));
                }
            }
        }
    }

    #[test]
    fn collect_configs_bare_finds_main_and_partials() {
        // End-to-end: the unified collect_configs honors NameStyle::Bare
        // exactly as the prior collect_dir_configs did.
        let dir = TempDir::new().unwrap();
        let app = "barecollect";
        let main_file = dir.path().join(format!("{app}.yaml"));
        let partial = dir.path().join(format!("{app}-01-db.yaml"));
        let unrelated = dir.path().join(format!("{app}.txt")); // wrong ext
        let dotted = dir.path().join(format!(".{app}.yaml")); // wrong style
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();
        fs::write(&unrelated, "k: v").unwrap();
        fs::write(&dotted, "k: v").unwrap();

        let mut found = Vec::new();
        let mut tried = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found, &mut tried);

        assert!(found.contains(&main_file));
        assert!(found.contains(&partial));
        assert!(!found.contains(&unrelated));
        assert!(!found.contains(&dotted));
    }

    #[test]
    fn collect_configs_dotfile_finds_main_and_partials() {
        let dir = TempDir::new().unwrap();
        let app = "dotcollect";
        let main_file = dir.path().join(format!(".{app}.yaml"));
        let partial = dir.path().join(format!(".{app}-99-extra.yaml"));
        let bare_main = dir.path().join(format!("{app}.yaml")); // wrong style
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();
        fs::write(&bare_main, "k: v").unwrap();

        let mut found = Vec::new();
        let mut tried = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Dotfile, &mut found, &mut tried);

        assert!(found.contains(&main_file));
        assert!(found.contains(&partial));
        assert!(!found.contains(&bare_main));
    }

    #[test]
    fn collect_configs_main_before_partials() {
        // Ordering invariant the unified function inherits from the prior
        // pair: main config is pushed before any partials in the same dir.
        let dir = TempDir::new().unwrap();
        let app = "ordercheck";
        let main_file = dir.path().join(format!("{app}.yaml"));
        let partial = dir.path().join(format!("{app}-01-extra.yaml"));
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();

        let mut found = Vec::new();
        let mut tried = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found, &mut tried);

        let main_idx = found.iter().position(|p| p == &main_file).unwrap();
        let partial_idx = found.iter().position(|p| p == &partial).unwrap();
        assert!(main_idx < partial_idx, "main must come before partials");
    }

    #[test]
    fn hierarchical_discover_all_not_found_reports_resolved_searched_candidates() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiernf";

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        let ShikumiError::NotFound { tried } = result.expect_err("no files exist") else {
            panic!("expected NotFound");
        };
        assert!(!tried.is_empty());

        // The report is the resolved search, not a fabricated guess: the
        // user-level XDG candidate, the /etc system candidate, and the
        // walk-up dotfile candidate at start_dir all appear by their real
        // resolved paths.
        let xdg_candidate = nonexistent_xdg.join(format!("{app}/{app}.yaml"));
        let etc_candidate = PathBuf::from(format!("/etc/{app}/{app}.yaml"));
        let start_dotfile = dir_path.join(format!(".{app}.yaml"));
        assert!(
            tried.contains(&xdg_candidate),
            "must report resolved XDG candidate {xdg_candidate:?}; got: {tried:?}"
        );
        assert!(
            tried.contains(&etc_candidate),
            "must report /etc candidate {etc_candidate:?}; got: {tried:?}"
        );
        assert!(
            tried.contains(&start_dotfile),
            "must report start_dir dotfile candidate {start_dotfile:?}; got: {tried:?}"
        );

        // No unresolved `~/.config` literal leaks into the report — the
        // old fabricated list embedded one; the resolved search never does.
        assert!(
            !tried
                .iter()
                .any(|p| p.to_string_lossy().contains("~/.config")),
            "report must carry resolved paths, not a `~` literal; got: {tried:?}"
        );
    }

    #[test]
    fn hierarchical_discover_all_not_found_honors_configured_formats() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hierfmt";

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Toml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        let ShikumiError::NotFound { tried } = result.expect_err("no files exist") else {
            panic!("expected NotFound");
        };

        // The fabricated list hardcoded `.yaml`; the resolved search only
        // ever stats the configured formats, so a TOML-only discovery
        // reports TOML candidates and no YAML at all.
        assert!(!tried.is_empty());
        assert!(
            tried
                .iter()
                .all(|p| p.extension().is_some_and(|e| e == "toml")),
            "every reported candidate must be .toml; got: {tried:?}"
        );
        assert!(
            tried.contains(&dir_path.join(format!(".{app}.toml"))),
            "must report the resolved start_dir .toml dotfile candidate; got: {tried:?}"
        );
    }

    // ---- Builder injection tests ----

    #[test]
    fn xdg_config_home_builder_used_in_standard_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("injapp").xdg_config_home(dir.path());
        let paths = d.standard_paths();
        assert!(
            paths.iter().any(|p| p.starts_with(dir.path())),
            "expected XDG override path in standard_paths"
        );
    }

    #[test]
    fn home_dir_builder_used_in_standard_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("homeinj")
            .xdg_config_home(&dir.path().join("nonexistent"))
            .home_dir(dir.path());
        let paths = d.standard_paths();
        assert!(
            paths.iter().any(|p| p.starts_with(dir.path())),
            "expected HOME override path in standard_paths"
        );
    }

    #[test]
    fn home_dir_produces_legacy_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("leginjapp").home_dir(dir.path());
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".leginjapp")),
            "expected legacy path from injected HOME"
        );
        assert!(
            path_strs.iter().any(|p| p.ends_with(".leginjapp.toml")),
            "expected legacy toml path from injected HOME"
        );
    }

    #[test]
    fn xdg_config_home_overrides_env_var() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let app = "xdgovr";
        let config_dir = dir1.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir1.path())
            .home_dir(dir2.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_all_non_hierarchical_with_injected_xdg() {
        let dir = TempDir::new().unwrap();
        let app = "daninj";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&config_file));
    }

    #[test]
    fn start_dir_builder_sets_field() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("sdtest").start_dir(dir.path());
        assert_eq!(d.start_dir, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn discover_with_both_xdg_and_home_prefers_xdg() {
        let xdg_dir = TempDir::new().unwrap();
        let home_dir = TempDir::new().unwrap();
        let app = "bothpref";

        let xdg_config = xdg_dir.path().join(app);
        fs::create_dir_all(&xdg_config).unwrap();
        let xdg_file = xdg_config.join(format!("{app}.yaml"));
        fs::write(&xdg_file, "from: xdg").unwrap();

        let home_config = home_dir.path().join(".config").join(app);
        fs::create_dir_all(&home_config).unwrap();
        let home_file = home_config.join(format!("{app}.yaml"));
        fs::write(&home_file, "from: home").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(xdg_dir.path())
            .home_dir(home_dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            xdg_file,
            "XDG should take precedence over HOME"
        );
    }

    #[test]
    fn format_debug_display() {
        let yaml = Format::Yaml;
        let toml = Format::Toml;
        assert_eq!(format!("{yaml:?}"), "Yaml");
        assert_eq!(format!("{toml:?}"), "Toml");
    }

    #[test]
    fn discover_yml_extension_found_when_yaml_absent() {
        let dir = TempDir::new().unwrap();
        let app = "ymlonly";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let yml_file = config_dir.join(format!("{app}.yml"));
        fs::write(&yml_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
        assert!(result.unwrap().display().to_string().ends_with(".yml"));
    }

    #[test]
    fn hierarchical_toml_format_finds_dotfile() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiertoml";
        let dotfile = dir_path.join(format!(".{app}.toml"));
        fs::write(&dotfile, "key = \"value\"").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Toml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &dotfile),
            "expected .toml dotfile in hierarchical results"
        );
    }

    #[test]
    fn hierarchical_multiple_formats_found() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermulti";

        let yaml_file = dir_path.join(format!(".{app}.yaml"));
        let toml_file = dir_path.join(format!(".{app}.toml"));
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&toml_file, "format = \"toml\"").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml, Format::Toml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&yaml_file), "should find yaml");
        assert!(paths.contains(&toml_file), "should find toml");
    }

    #[test]
    fn discover_all_non_hierarchical_env_override_included() {
        let dir = TempDir::new().unwrap();
        let override_file = dir.path().join("custom.yaml");
        fs::write(&override_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_DA_ENV";
        unsafe { env::set_var(var, override_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("shikumi_nonexist_da_env")
            .env_override(var)
            .discover_all();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&override_file));
    }

    #[test]
    fn standard_paths_with_no_home_or_xdg() {
        let nonexistent = PathBuf::from("/nonexistent_for_test_12345");
        let d = ConfigDiscovery::new("nohome")
            .xdg_config_home(&nonexistent)
            .home_dir(&nonexistent);
        let paths = d.standard_paths();
        assert!(
            paths.iter().all(|p| p.starts_with(&nonexistent)),
            "all paths should be under the injected directories"
        );
    }

    // ---- dir_override_or_env typed-primitive tests ----

    #[test]
    fn dir_override_or_env_returns_override_when_set_and_env_unset() {
        // Override Some, env unset → override wins. The override must be
        // returned verbatim (not derived through the env layer), since
        // the builder override is load-bearing for deterministic testing
        // and operator-specified directory pinning.
        let var = "SHIKUMI_DOE_TEST_OVR_NOENV";
        // Ensure the env var is absent for this branch.
        unsafe { env::remove_var(var) };
        let pinned = PathBuf::from("/pinned/by/builder");
        let resolved = dir_override_or_env(Some(pinned.as_path()), var);
        assert_eq!(resolved, Some(pinned));
    }

    #[test]
    fn dir_override_or_env_override_wins_when_both_set() {
        // Override dominance contract: when both the builder override
        // and the env var are present, the override wins and the env
        // value is ignored. This is the property `xdg_config_home(...)`
        // / `home_dir(...)` builder methods rely on for deterministic
        // testing pinned away from the host's `$XDG_CONFIG_HOME` /
        // `$HOME`.
        let var = "SHIKUMI_DOE_TEST_BOTH_SET";
        unsafe { env::set_var(var, "/from/env/loser") };
        let pinned = PathBuf::from("/from/builder/winner");
        let resolved = dir_override_or_env(Some(pinned.as_path()), var);
        unsafe { env::remove_var(var) };
        assert_eq!(resolved, Some(pinned));
    }

    #[test]
    fn dir_override_or_env_falls_back_to_env_when_override_absent() {
        // Override None, env set → env value lifted into a PathBuf.
        let var = "SHIKUMI_DOE_TEST_ENV_FALLBACK";
        unsafe { env::set_var(var, "/from/env/fallback") };
        let resolved = dir_override_or_env(None, var);
        unsafe { env::remove_var(var) };
        assert_eq!(resolved, Some(PathBuf::from("/from/env/fallback")));
    }

    #[test]
    fn dir_override_or_env_returns_none_when_both_absent() {
        // Override None, env unset → None. The shared "neither layer
        // contributed" terminal state both `resolve_xdg_config_home`
        // and `resolve_home` rely on to signal "no user config dir
        // available" to `user_config_dir` (which then short-circuits
        // and skips XDG/HOME paths in `standard_paths`).
        let var = "SHIKUMI_DOE_TEST_BOTH_ABSENT";
        unsafe { env::remove_var(var) };
        let resolved = dir_override_or_env(None, var);
        assert_eq!(resolved, None);
    }

    #[test]
    fn dir_override_or_env_preserves_override_path_bytes_verbatim() {
        // The override path is returned without canonicalization,
        // normalization, or `..` collapse — the primitive is a pure
        // lookup, the same property the open-coded `dir.clone()`
        // returns held. Relative and dotted paths flow through
        // unchanged.
        let var = "SHIKUMI_DOE_TEST_VERBATIM";
        unsafe { env::remove_var(var) };
        for raw in [
            "/abs/path/with-hyphens",
            "rel/path",
            "../parent/dotdot",
            "./curr/dot",
            "/with/trailing/slash/",
            "",
        ] {
            let pinned = PathBuf::from(raw);
            let resolved = dir_override_or_env(Some(pinned.as_path()), var);
            assert_eq!(resolved, Some(pinned), "raw path: {raw:?}");
        }
    }

    #[test]
    fn dir_override_or_env_agrees_with_open_coded_form_pointwise() {
        // Pin equivalence to the `if let Some(ref dir) = override { Some(dir.clone()) }
        // else env::var(NAME).ok().map(PathBuf::from)` shape the two
        // call sites previously inlined, across the four
        // `(override × env)` cells.
        //
        // NARROWED: the equivalence now holds for an ABSOLUTE env value only.
        // A relative one is deliberately IGNORED rather than resolved against
        // the cwd — see the primitive's own comment. The env value used below
        // is absolute, so this test still pins what it was written to pin; the
        // divergence is covered by
        // `dir_override_or_env_ignores_a_relative_env_value`. A future refactor that drifts the
        // primitive away from the open-coded shape (e.g. swapping the
        // order of resolution, canonicalizing on entry) breaks this
        // test before reaching the call sites. Uses a unique env-var
        // name so the test is safe under parallel cargo-test runs.
        fn open_coded(override_owned: Option<PathBuf>, env_var: &str) -> Option<PathBuf> {
            if let Some(dir) = override_owned {
                return Some(dir);
            }
            env::var(env_var).ok().map(PathBuf::from)
        }

        let var = "SHIKUMI_DOE_TEST_AGREEMENT";
        let pinned = PathBuf::from("/builder/override");

        // (None override, env unset)
        unsafe { env::remove_var(var) };
        assert_eq!(dir_override_or_env(None, var), open_coded(None, var));

        // (None override, env set)
        unsafe { env::set_var(var, "/agreement/env/value") };
        assert_eq!(dir_override_or_env(None, var), open_coded(None, var));

        // (Some override, env set)
        assert_eq!(
            dir_override_or_env(Some(pinned.as_path()), var),
            open_coded(Some(pinned.clone()), var),
        );

        // (Some override, env unset)
        unsafe { env::remove_var(var) };
        assert_eq!(
            dir_override_or_env(Some(pinned.as_path()), var),
            open_coded(Some(pinned), var),
        );
    }

    /// The masked-branch fix, at the widest reach in the fleet: shikumi is a
    /// dependency of 81 repos, and this is the SHARED primitive resolving both
    /// `$XDG_CONFIG_HOME` and `$HOME`. A relative value here made config
    /// discovery resolve against the invoking directory in every one of them.
    #[test]
    fn dir_override_or_env_ignores_a_relative_env_value() {
        let var = "SHIKUMI_DOE_TEST_RELATIVE_IGNORED";
        for bad in ["", "rel/config", "./config", "../config"] {
            unsafe { env::set_var(var, bad) };
            assert_eq!(
                dir_override_or_env(None, var),
                None,
                "{bad:?} must be ignored, not resolved against the cwd"
            );
        }
        // ...while an absolute one is still honoured verbatim.
        unsafe { env::set_var(var, "/abs/config") };
        assert_eq!(
            dir_override_or_env(None, var),
            Some(PathBuf::from("/abs/config"))
        );
        unsafe { env::remove_var(var) };
    }

    /// The builder-override arm is deliberately NOT filtered: that path is a
    /// programmatic choice by the consuming program, not an operator
    /// environment, so a caller passing a relative Path did so on purpose.
    /// Pinned so the asymmetry reads as intentional rather than missed.
    #[test]
    fn a_relative_builder_override_is_still_honoured() {
        let var = "SHIKUMI_DOE_TEST_REL_OVERRIDE";
        unsafe { env::remove_var(var) };
        let rel = PathBuf::from("rel/from/builder");
        assert_eq!(dir_override_or_env(Some(rel.as_path()), var), Some(rel));
    }

    #[test]
    fn resolve_xdg_config_home_honors_builder_override() {
        // End-to-end pin on `resolve_xdg_config_home` through the new
        // primitive: the builder override is returned verbatim. Uses
        // a path absent from any real env so the assertion is
        // independent of the host's `$XDG_CONFIG_HOME`. Does not
        // mutate `$XDG_CONFIG_HOME` itself — that would race with
        // other tests reading it under parallel cargo-test runs.
        let pinned = PathBuf::from("/dir_override_or_env_test/pin/xdg");
        let d = ConfigDiscovery::new("doe_xdg_app").xdg_config_home(&pinned);
        assert_eq!(d.resolve_xdg_config_home(), Some(pinned));
    }

    #[test]
    fn resolve_home_honors_builder_override() {
        // End-to-end pin on `resolve_home` through the new primitive:
        // the builder override is returned verbatim. Uses a path
        // absent from any real env so the assertion is independent of
        // the host's `$HOME`. Does not mutate `$HOME` itself — that
        // would race with other tests reading it under parallel
        // cargo-test runs.
        let pinned = PathBuf::from("/dir_override_or_env_test/pin/home");
        let d = ConfigDiscovery::new("doe_home_app").home_dir(&pinned);
        assert_eq!(d.resolve_home(), Some(pinned));
    }

    // ---- configured_extensions typed-primitive tests ----

    #[test]
    fn configured_extensions_default_yields_yaml_then_toml_in_preference_order() {
        // YAML first (the pinned precedence), then TOML, then the
        // shikumi-built formats. The tail exists because the default used to
        // be `[Yaml, Toml]` alone, which meant `.lisp`, `.nix` and `.b` were
        // never discovered by extension at all — a provider could be pointed
        // at one, but nothing found one on its own.
        let d = ConfigDiscovery::new("ext_default");
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(
            exts,
            vec!["yaml", "yml", "toml", "lisp", "lsp", "el", "nix", "b"]
        );
    }

    #[test]
    fn configured_extensions_honors_custom_format_order() {
        // Flipping the format preference flips the extension iteration order.
        let d = ConfigDiscovery::new("ext_flip").formats(&[Format::Toml, Format::Yaml]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["toml", "yaml", "yml"]);
    }

    #[test]
    fn configured_extensions_flattens_multi_extension_formats() {
        // Format::Yaml owns two extensions (yaml, yml); the cartesian
        // product flattens them into the iterator without losing order.
        let d = ConfigDiscovery::new("ext_yaml_only").formats(&[Format::Yaml]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["yaml", "yml"]);
    }

    #[test]
    fn configured_extensions_includes_lisp_when_configured() {
        let d = ConfigDiscovery::new("ext_lisp").formats(&[Format::Lisp]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["lisp", "lsp", "el"]);
    }

    #[test]
    fn configured_extensions_empty_when_no_formats() {
        let d = ConfigDiscovery::new("ext_empty").formats(&[]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert!(exts.is_empty());
    }

    #[test]
    fn configured_extensions_cardinality_matches_sum_of_format_extensions() {
        // The flat cartesian product must yield exactly
        // sum(format.extensions().len()) items — no dedup, no reordering
        // beyond the format-then-ext nesting.
        for formats in [
            vec![Format::Yaml],
            vec![Format::Toml],
            vec![Format::Yaml, Format::Toml],
            vec![Format::Toml, Format::Yaml, Format::Lisp, Format::Nix],
        ] {
            let expected: usize = formats.iter().map(|f| f.extensions().len()).sum();
            let d = ConfigDiscovery::new("card").formats(&formats);
            assert_eq!(
                d.configured_extensions().count(),
                expected,
                "cardinality must equal sum of format.extensions().len() for {formats:?}"
            );
        }
    }

    #[test]
    fn standard_paths_extensions_match_configured_extensions() {
        // standard_paths is one of the three consumers of the typed
        // primitive; assert the cartesian product surfaces in every
        // generated XDG/HOME path.
        let xdg = PathBuf::from("/xdg_for_invariant");
        let home = PathBuf::from("/home_for_invariant");
        let d = ConfigDiscovery::new("inv")
            .formats(&[Format::Yaml, Format::Toml])
            .xdg_config_home(&xdg)
            .home_dir(&home);
        let paths = d.standard_paths();

        for ext in d.configured_extensions() {
            assert!(
                paths
                    .iter()
                    .any(|p| p.extension().and_then(|e| e.to_str()) == Some(ext)),
                "standard_paths must include a path with extension `.{ext}`"
            );
        }
    }

    #[test]
    fn is_partial_match_accepts_every_configured_extension() {
        // is_partial_match is the second consumer; assert it accepts a
        // partial filename for every extension the typed primitive yields.
        let d = ConfigDiscovery::new("inv2").formats(&[Format::Yaml, Format::Toml, Format::Nix]);
        for ext in d.configured_extensions() {
            let name = format!("inv2-overlay.{ext}");
            assert!(
                d.is_partial_match(&name, "inv2", NameStyle::Bare),
                "is_partial_match must accept partial `{name}` for configured ext `.{ext}`"
            );
        }
    }

    #[test]
    fn is_partial_match_rejects_extensions_outside_configured_set() {
        // The contract has two sides: every configured ext is accepted
        // (above), every non-configured ext is rejected (here). With
        // formats=[Yaml] only, .toml/.json/.nix partials must not match.
        let d = ConfigDiscovery::new("inv3").formats(&[Format::Yaml]);
        for ext in ["toml", "json", "nix", "lisp"] {
            let name = format!("inv3-overlay.{ext}");
            assert!(
                !d.is_partial_match(&name, "inv3", NameStyle::Bare),
                "ext `.{ext}` is not configured; partial `{name}` must be rejected"
            );
        }
    }

    #[test]
    fn is_partial_match_recognizes_uppercase_alias_matching_from_path() {
        // Alias-algebra parity: `Format::from_path` is ASCII case-
        // insensitive (the `nix-darwin` case-insensitive-filesystem
        // contingency named in `Format::from_extension`'s doc), and the
        // 2026-08-20 lift routes `is_partial_match` through it so the
        // two directions of the same alias algebra can no longer disagree.
        // Before the lift `name.ends_with(&format!(".{ext}"))` compared
        // case-sensitively — a partial file named `app-theme.YAML` was
        // silently rejected by partial discovery while primary discovery
        // (which reaches `Format::from_path`) would have accepted it. This
        // test fails on the pre-lift shape and pins the fix.
        let d = ConfigDiscovery::new("myapp").formats(&[Format::Yaml, Format::Toml, Format::Nix]);
        for (name, ext_case) in [
            ("myapp-overlay.YAML", "YAML"),
            ("myapp-overlay.Yml", "Yml"),
            ("myapp-overlay.TOML", "TOML"),
            ("myapp-overlay.Nix", "Nix"),
        ] {
            assert!(
                d.is_partial_match(name, "myapp", NameStyle::Bare),
                "is_partial_match must accept `{name}` — its extension `{ext_case}` \
                 lifts to a configured format via Format::from_path's case-\
                 insensitive alias algebra",
            );
        }
    }

    #[test]
    fn is_partial_match_and_from_path_agree_on_configured_alias_algebra() {
        // Cross-classifier invariant: for every filename shaped like a
        // partial (`{app}-*.<ext>`), `is_partial_match` accepts it iff
        // `Format::from_path` classifies its extension into a format the
        // discovery's `self.formats` includes. The two callers of the
        // (name → is-config-alias?) question — primary discovery via
        // `Format::from_path` (through `ProviderChain::with_file`) and
        // partial discovery via `is_partial_match` — now agree
        // pointwise, so the alias set for a format lives at exactly one
        // site (`Format::extensions`) instead of duplicated between
        // that table and a per-alias `ends_with` scan.
        let d = ConfigDiscovery::new("app").formats(&[Format::Yaml, Format::Toml]);
        // Cover both cases: canonical lowercase, ASCII-uppercase, mixed
        // case, and unconfigured/unknown extensions. The invariant is
        // that BOTH classifiers agree — not that a particular case is
        // accepted or rejected.
        for suffix in [
            "yaml", "YAML", "Yaml", "yml", "YML", "toml", "TOML", "Toml", "nix", "lisp", "lsp",
            "el", "b", "json", "txt", "",
        ] {
            let name = if suffix.is_empty() {
                "app-overlay".to_string()
            } else {
                format!("app-overlay.{suffix}")
            };
            let from_path = Format::from_path(std::path::Path::new(&name))
                .is_some_and(|f| d.formats.contains(&f));
            let via_partial = d.is_partial_match(&name, "app", NameStyle::Bare);
            assert_eq!(
                via_partial, from_path,
                "is_partial_match({name:?}) must agree with Format::from_path \
                 gated on `self.formats`; via_partial={via_partial}, \
                 from_path={from_path}",
            );
        }
    }

    #[test]
    fn collect_configs_extensions_match_configured_extensions() {
        // collect_configs is the third consumer; for every configured ext
        // the helper must surface the corresponding `{app}.{ext}` main file.
        let dir = TempDir::new().unwrap();
        let app = "inv4";
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml, Format::Toml]);
        for ext in d.configured_extensions() {
            fs::write(dir.path().join(format!("{app}.{ext}")), "k: v").unwrap();
        }

        let mut found = Vec::new();
        let mut tried = Vec::new();
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found, &mut tried);
        for ext in d.configured_extensions() {
            let expected = dir.path().join(format!("{app}.{ext}"));
            assert!(
                found.contains(&expected),
                "collect_configs must surface `{}` for configured ext `.{ext}`",
                expected.display()
            );
        }
    }

    #[test]
    fn configured_extensions_return_type_is_nameable_configured_extensions() {
        // Pin the sharpen at the type-signature level: a struct field bound
        // on `ConfiguredExtensions<'a>` holds the handle across a return.
        // This test compiles iff the sharpen holds; if `configured_extensions`
        // ever regresses back to `impl Trait`, this ceases to compile
        // because `impl Trait` return types are unnameable at struct-field
        // bounds.
        struct Held<'a> {
            walker: ConfiguredExtensions<'a>,
        }
        fn hold(d: &ConfigDiscovery) -> Held<'_> {
            Held {
                walker: d.configured_extensions(),
            }
        }
        let d = ConfigDiscovery::new("nameable").formats(&[Format::Yaml, Format::Toml]);
        let mut h = hold(&d);
        assert_eq!(h.walker.next(), Some("yaml"));
        assert_eq!(h.walker.next(), Some("yml"));
        assert_eq!(h.walker.next(), Some("toml"));
        assert_eq!(h.walker.next(), None);
    }

    #[test]
    fn configured_extensions_clone_preserves_static_traits() {
        // A static bound accepting Iterator + DoubleEndedIterator +
        // FusedIterator + Clone verifies the full trait algebra survives
        // the sharpen at compile time — the discovery-altitude peer of
        // the same four-trait pair pinned on the filter-based cube-slot
        // siblings [`RealizableIter`] / [`UnrealizableIter`] and the
        // histogram-altitude siblings [`AxisHistogramNonzero`] /
        // [`AxisHistogramObserved`] / [`AxisHistogramUnobserved`].
        // `ExactSizeIterator` is intentionally omitted — the inner
        // per-format extensions slice has variable length, so the total-
        // length invariant can't be honored structurally through
        // `FlatMap`. Then a runtime cross-walk asserts the cloned walker
        // yields the same `&'static str` stream as the original.
        fn assert_algebra<I>(_: &I)
        where
            I: Iterator<Item = &'static str>
                + DoubleEndedIterator
                + std::iter::FusedIterator
                + Clone,
        {
        }
        let d = ConfigDiscovery::new("algebra").formats(&[
            Format::Yaml,
            Format::Toml,
            Format::Lisp,
            Format::Nix,
        ]);
        let it = d.configured_extensions();
        assert_algebra(&it);
        let cloned = it.clone();
        let a: Vec<&'static str> = it.collect();
        let b: Vec<&'static str> = cloned.collect();
        assert_eq!(a, b);
    }

    #[test]
    fn configured_extensions_next_back_walks_preference_in_reverse() {
        // Pin the DoubleEndedIterator impl at the runtime level: the tail
        // cursor walks the format-then-extension nesting in reverse — for
        // `[Yaml, Toml]` the reverse walk yields `toml`, then `yml`, then
        // `yaml`. Catches an accidental regression to a single-ended
        // state machine or a wrong nesting-order reversal.
        let d = ConfigDiscovery::new("nextback").formats(&[Format::Yaml, Format::Toml]);
        let mut it = d.configured_extensions();
        assert_eq!(it.next_back(), Some("toml"));
        assert_eq!(it.next_back(), Some("yml"));
        assert_eq!(it.next_back(), Some("yaml"));
        assert_eq!(it.next_back(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn configured_extensions_meet_from_both_ends_covers_full_stream() {
        // Pin the DoubleEnded correctness at the meeting seam: pulling
        // alternately from head and tail covers exactly the full ordered
        // stream, with head and tail cursors meeting cleanly at the
        // interior. For `[Yaml, Toml, Nix]` the ordered stream is
        // `[yaml, yml, toml, nix]`; the alternating walk hits `yaml`
        // then `nix` then `yml` then `toml`, and both cursors then
        // report `None`.
        let d = ConfigDiscovery::new("meet").formats(&[Format::Yaml, Format::Toml, Format::Nix]);
        let mut it = d.configured_extensions();
        assert_eq!(it.next(), Some("yaml"));
        assert_eq!(it.next_back(), Some("nix"));
        assert_eq!(it.next(), Some("yml"));
        assert_eq!(it.next_back(), Some("toml"));
        assert_eq!(it.next(), None);
        assert_eq!(it.next_back(), None);
    }

    #[test]
    fn configured_extensions_debug_impl_names_the_struct() {
        // Pin the derived Debug impl at the format-string level: the
        // rendered output names the struct (`ConfiguredExtensions`).
        // Catches an accidental regression to a manual impl that
        // misnames the struct or a rename of the struct itself.
        let d = ConfigDiscovery::new("dbg").formats(&[Format::Yaml]);
        let it = d.configured_extensions();
        let rendered = format!("{it:?}");
        assert!(
            rendered.contains("ConfiguredExtensions"),
            "Debug rendering must name the struct; got {rendered:?}"
        );
    }

    #[test]
    fn configured_extensions_empty_disables_all_three_consumers() {
        // The cross-call-site invariant from the empty side: zero
        // extensions => standard_paths has no XDG/HOME paths,
        // is_partial_match always rejects, collect_configs surfaces nothing.
        let dir = TempDir::new().unwrap();
        let app = "emptycross";
        fs::write(dir.path().join(format!("{app}.yaml")), "k: v").unwrap();
        fs::write(dir.path().join(format!("{app}-x.yaml")), "k: v").unwrap();

        let d = ConfigDiscovery::new(app)
            .formats(&[])
            .xdg_config_home(PathBuf::from("/xdg_empty"))
            .home_dir(PathBuf::from("/home_empty"));

        assert_eq!(d.configured_extensions().count(), 0);
        assert!(
            !d.is_partial_match(&format!("{app}-x.yaml"), app, NameStyle::Bare),
            "no configured exts ⇒ no partial matches"
        );
        let mut found = Vec::new();
        let mut tried = Vec::new();
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found, &mut tried);
        assert!(
            found.is_empty(),
            "no configured exts ⇒ collect_configs surfaces nothing"
        );

        // standard_paths still emits the legacy `~/.{app}` and `~/.{app}.toml`
        // entries (they are not gated on configured_extensions); but no
        // {app}/{app}.{ext} or .config/{app}/{app}.{ext} entries should appear.
        let paths = d.standard_paths();
        let main_name = format!("{app}.yaml");
        assert!(
            paths.iter().all(|p| {
                let by_name = p.file_name().and_then(|n| n.to_str());
                by_name != Some(main_name.as_str())
            }),
            "no configured exts ⇒ no XDG/HOME {app}.{{ext}} paths; got {paths:?}"
        );
    }

    // ---- Format::ALL / has_shikumi_provider / metadata_name /
    // ---- strip_metadata_name typed-primitive tests

    #[test]
    fn format_all_in_declaration_order() {
        assert_eq!(
            Format::ALL,
            &[
                Format::Yaml,
                Format::Toml,
                Format::Lisp,
                Format::Nix,
                Format::Blue
            ]
        );
    }

    #[test]
    fn format_all_covers_every_variant() {
        // The closed list must enumerate every variant exactly once.
        // The match below is the compiler-enforced contract: adding a
        // variant breaks this test until the new variant is wired into
        // both `Format::ALL` and this exhaustivity check.
        for f in [
            Format::Yaml,
            Format::Toml,
            Format::Lisp,
            Format::Nix,
            Format::Blue,
        ] {
            assert!(
                Format::ALL.contains(&f),
                "Format::ALL must contain every variant; missing {f:?}"
            );
            // Exhaustive match — adding a variant requires updating
            // both `Format::ALL` and this arm list.
            match f {
                Format::Yaml | Format::Toml | Format::Lisp | Format::Nix | Format::Blue => {}
            }
        }
        assert_eq!(Format::ALL.len(), 5);
    }

    #[test]
    fn format_has_shikumi_provider_lisp_and_nix_only() {
        assert!(!Format::Yaml.has_shikumi_provider());
        assert!(!Format::Toml.has_shikumi_provider());
        assert!(Format::Lisp.has_shikumi_provider());
        assert!(Format::Nix.has_shikumi_provider());
    }

    #[test]
    fn format_has_figment_builtin_provider_yaml_and_toml_only() {
        // Per-variant polarity pin on the figment-builtin-side
        // sibling predicate: Yaml and Toml route to the figment
        // built-in providers, Lisp and Nix do not. Mirrors the
        // shikumi-side `format_has_shikumi_provider_lisp_and_nix_only`
        // pointwise on the other half of the binary partition.
        assert!(Format::Yaml.has_figment_builtin_provider());
        assert!(Format::Toml.has_figment_builtin_provider());
        assert!(!Format::Lisp.has_figment_builtin_provider());
        assert!(!Format::Nix.has_figment_builtin_provider());
    }

    #[test]
    fn format_has_figment_builtin_provider_agrees_with_provenance_is_figment_builtin() {
        // The source-altitude predicate and the provenance-altitude
        // predicate on the same corner (`FigmentBuiltin`) must agree
        // pointwise across `Format::ALL` — the source-altitude peer
        // is a thin lift of `self.provenance().is_figment_builtin()`,
        // and the two entry points cannot drift. Mirror of the
        // shikumi-side `format_provenance_agrees_with_has_shikumi_provider`
        // on the figment-builtin corner.
        for f in Format::ALL {
            assert_eq!(
                f.has_figment_builtin_provider(),
                f.provenance() == FormatProvenance::FigmentBuiltin,
                "has_figment_builtin_provider and provenance must agree on {f:?}",
            );
            assert_eq!(
                f.has_figment_builtin_provider(),
                f.provenance().is_figment_builtin(),
                "has_figment_builtin_provider and provenance().is_figment_builtin() \
                 must agree on {f:?}",
            );
        }
    }

    #[test]
    fn format_provider_class_predicates_are_a_closed_binary_partition() {
        // The two source-altitude provider-class predicates
        // (`has_shikumi_provider` / `has_figment_builtin_provider`)
        // form a closed binary partition over `Format::ALL`: every
        // variant satisfies exactly one, none satisfy neither, none
        // satisfy both. This is the source-altitude peer of the
        // provenance-altitude XOR pin
        // (`is_shikumi_built` XOR `is_figment_builtin`) inside
        // `format_provenance_all_covers_every_provenance_over_format_all`
        // and its neighbour predicate-disjointness assertion. A future
        // tertiary provider class (e.g. a Vault or HTTP provider) landing
        // as a third `FormatProvenance` variant would fail this test —
        // by design: the new class must declare its own predicate and
        // its own partition arm rather than silently landing under the
        // negation of one of the existing two.
        for f in Format::ALL {
            assert_ne!(
                f.has_shikumi_provider(),
                f.has_figment_builtin_provider(),
                "provider-class is binary; the two predicates must disagree pointwise on {f:?}"
            );
        }
        let shikumi_count = Format::ALL
            .iter()
            .filter(|f| f.has_shikumi_provider())
            .count();
        let figment_count = Format::ALL
            .iter()
            .filter(|f| f.has_figment_builtin_provider())
            .count();
        assert_eq!(
            shikumi_count + figment_count,
            Format::ALL.len(),
            "the two provider-class predicates must partition Format::ALL exhaustively",
        );
    }

    // ---- Format sibling-predicate quintet
    // ---- (is_yaml / is_toml / is_lisp / is_nix / is_blue) ----
    //
    // The closed-axis idiom peer of the ternary `WatchEventClass`
    // predicate closure (`is_reload` / `is_removed` / `is_ignored`,
    // commit `2b5a962`), the quaternary `HintSurface` closure (`face7ff`)
    // and `ConfigTier` closure (`aefc87a`), and the quinary `TierArg`
    // closure (`cc038ef`) lifted onto the config-file-format axis. Every
    // Format value satisfies exactly one of the five predicates.

    #[test]
    fn format_is_yaml_true_only_for_yaml_variant() {
        // Per-variant polarity pin on the Yaml corner. Sibling of
        // `tier_arg_is_bare_true_only_for_bare_variant` and the trio-shape
        // pins on the crate's ternary closed axes; a future edit that
        // flips the `matches!` arm on `is_yaml` fails here before the
        // closed-quinary-partition pin masks it.
        assert!(Format::Yaml.is_yaml());
        assert!(!Format::Toml.is_yaml());
        assert!(!Format::Lisp.is_yaml());
        assert!(!Format::Nix.is_yaml());
        assert!(!Format::Blue.is_yaml());
    }

    #[test]
    fn format_is_toml_true_only_for_toml_variant() {
        assert!(!Format::Yaml.is_toml());
        assert!(Format::Toml.is_toml());
        assert!(!Format::Lisp.is_toml());
        assert!(!Format::Nix.is_toml());
        assert!(!Format::Blue.is_toml());
    }

    #[test]
    fn format_is_lisp_true_only_for_lisp_variant() {
        assert!(!Format::Yaml.is_lisp());
        assert!(!Format::Toml.is_lisp());
        assert!(Format::Lisp.is_lisp());
        assert!(!Format::Nix.is_lisp());
        assert!(!Format::Blue.is_lisp());
    }

    #[test]
    fn format_is_nix_true_only_for_nix_variant() {
        assert!(!Format::Yaml.is_nix());
        assert!(!Format::Toml.is_nix());
        assert!(!Format::Lisp.is_nix());
        assert!(Format::Nix.is_nix());
        assert!(!Format::Blue.is_nix());
    }

    #[test]
    fn format_is_blue_true_only_for_blue_variant() {
        assert!(!Format::Yaml.is_blue());
        assert!(!Format::Toml.is_blue());
        assert!(!Format::Lisp.is_blue());
        assert!(!Format::Nix.is_blue());
        assert!(Format::Blue.is_blue());
    }

    #[test]
    fn format_predicates_are_a_closed_quinary_partition() {
        // Every `Format::ALL` cell satisfies exactly one of the five
        // sibling predicates: none satisfies two, none satisfies zero.
        // Quinary-partition analogue of the quaternary-partition pins on
        // `HintSurface`
        // (`hint_surface_predicates_are_a_closed_quaternary_partition`),
        // `ConfigTier`
        // (`config_tier_predicates_are_a_closed_quaternary_partition`),
        // the ternary-partition pin on `WatchEventClass`
        // (`watch_event_class_predicates_are_a_closed_ternary_partition`),
        // and the quinary-partition pin on `TierArg`
        // (`tier_arg_predicates_are_a_closed_quinary_partition`). A future
        // sixth-format landing without its own sibling predicate collapses
        // the partition to zero on that variant, failing here before
        // drifting through any consumer site.
        for f in Format::ALL.iter().copied() {
            let hits = usize::from(f.is_yaml())
                + usize::from(f.is_toml())
                + usize::from(f.is_lisp())
                + usize::from(f.is_nix())
                + usize::from(f.is_blue());
            assert_eq!(
                hits, 1,
                "format {f:?} must satisfy exactly one sibling predicate, got {hits}",
            );
        }
    }

    #[test]
    fn format_predicates_agree_with_equality_pointwise() {
        // The tag-alone equality-agreement law over `Format::ALL`: for
        // every variant, `f.is_X()` is exactly `f == Format::X`. Catches
        // a future edit whose `matches!` arm silently accepts a second
        // variant on the same predicate while some other corner drops
        // from one hit to zero (the closed-partition pin above catches
        // "zero"; this pin catches "two on the same corner without
        // flipping a second corner's hits down to zero"). Idiom-peer of
        // `tier_arg_predicates_agree_with_equality_pointwise` and
        // `watch_event_class_predicates_agree_with_equality_pointwise`.
        for f in Format::ALL.iter().copied() {
            assert_eq!(f.is_yaml(), f == Format::Yaml);
            assert_eq!(f.is_toml(), f == Format::Toml);
            assert_eq!(f.is_lisp(), f == Format::Lisp);
            assert_eq!(f.is_nix(), f == Format::Nix);
            assert_eq!(f.is_blue(), f == Format::Blue);
        }
    }

    // ---- Format compound-polarity sibling pair
    // ---- (is_feature_gated / is_always_available) ----
    //
    // Format-axis compound-polarity sibling of
    // `SecretBackendKind::is_cloud_secret_manager` (secret-backend axis,
    // commit `3553207`), `ConfigTierKind::is_computed` (tier axis, commit
    // `7d2825d`), and `ConfigSourceKind::is_overlay` (source axis, commit
    // `48c625b`) lifted onto the config-file-format axis. Every `Format`
    // value satisfies exactly one of the two compound-polarity predicates,
    // and each predicate collapses two composition paths — the two-arm
    // disjunction on the tag axis and the `Option<&'static str>::is_some()`
    // projection through `required_feature()` — onto one named type-level
    // predicate.

    #[test]
    fn format_is_feature_gated_partitions_gated_from_always_available() {
        // Per-variant polarity pin on the compound-polarity axis; the
        // pointwise contract mirroring
        // `secret_backend_kind_is_cloud_secret_manager_partitions_cloud_from_non_cloud`
        // on the secret-backend axis. Both feature-gated corners must
        // resolve `true`; all three always-available corners must resolve
        // `false`. A future edit that silently narrowed the compound arm
        // from `Lisp | Blue` to `Lisp` alone (dropping Blue from the
        // compound pole) fails here before drifting through the
        // disjunction / `Option`-polarity agreement laws.
        assert!(!Format::Yaml.is_feature_gated());
        assert!(!Format::Toml.is_feature_gated());
        assert!(Format::Lisp.is_feature_gated());
        assert!(!Format::Nix.is_feature_gated());
        assert!(Format::Blue.is_feature_gated());
    }

    #[test]
    fn format_is_always_available_partitions_always_from_feature_gated() {
        // The always-available pole: the direct predicate on the
        // (feature-gated × always-available) polarity axis, not
        // `!f.is_feature_gated()`. `Yaml`, `Toml`, `Nix` must resolve
        // `true`; `Lisp`, `Blue` must resolve `false`. Named separately
        // so the always-available half of the axis carries its own
        // failure site — a future edit that silently added a tertiary
        // (runtime-only) pole trips this pin on the offending variant
        // rather than being masked by a bare negation.
        assert!(Format::Yaml.is_always_available());
        assert!(Format::Toml.is_always_available());
        assert!(!Format::Lisp.is_always_available());
        assert!(Format::Nix.is_always_available());
        assert!(!Format::Blue.is_always_available());
    }

    #[test]
    fn format_is_feature_gated_agrees_with_or_of_individual_siblings() {
        // Compound ↔ two-arm disjunction law: the compound predicate on
        // the feature-gating axis equals the disjunction of the two
        // tag-side predicates naming the compound pole
        // (`is_lisp() || is_blue()`). Peer of
        // `secret_backend_kind_is_cloud_secret_manager_agrees_with_or_of_individual_siblings`
        // (`is_aws_secret() || is_gcp_secret()`) on the secret-backend
        // axis. A future edit that changed the compound arm without
        // updating the tag-side siblings (or vice versa) fails here on
        // the drifted variant.
        for &f in Format::ALL {
            assert_eq!(
                f.is_feature_gated(),
                f.is_lisp() || f.is_blue(),
                "{f:?}: is_feature_gated must equal is_lisp() || is_blue() — \
                 the compound pole names exactly the two feature-gated formats",
            );
        }
    }

    #[test]
    fn format_is_feature_gated_agrees_with_required_feature_is_some() {
        // Compound ↔ `Option<&'static str>::is_some()` law: the compound
        // predicate agrees pointwise with the two-step composition
        // `required_feature().is_some()`. The (format, required_feature)
        // projection is the underlying `Option<&'static str>` map;
        // this pin routes the "is this format gated on an optional
        // feature?" question through ONE named predicate at the type
        // level rather than the two-step compose at every call site.
        // Catches a future drift where `required_feature()` gained (or
        // dropped) an arm without a paired update to the compound
        // predicate.
        for &f in Format::ALL {
            assert_eq!(
                f.is_feature_gated(),
                f.required_feature().is_some(),
                "{f:?}: is_feature_gated must agree with \
                 required_feature().is_some() — the compound predicate is \
                 the type-level lift of the Option polarity",
            );
        }
    }

    #[test]
    fn format_is_always_available_agrees_with_required_feature_is_none() {
        // Complementary pole of the same Option-polarity law: the
        // always-available predicate agrees pointwise with
        // `required_feature().is_none()`. Named separately from the
        // negation of the feature-gated law so a future tertiary axis
        // landing (a runtime-only provider class) fails HERE at the
        // always-available pole rather than being masked by the
        // negation reading of the feature-gated pole.
        for &f in Format::ALL {
            assert_eq!(
                f.is_always_available(),
                f.required_feature().is_none(),
                "{f:?}: is_always_available must agree with \
                 required_feature().is_none() — the always-available \
                 pole names the unconditional-load half at the type level",
            );
        }
    }

    #[test]
    fn format_feature_gating_predicates_are_a_closed_binary_partition() {
        // Every `Format::ALL` cell satisfies exactly one of the two
        // compound-polarity predicates (`is_feature_gated`,
        // `is_always_available`): none satisfies both, none satisfies
        // zero. Binary-partition analogue of the quinary-partition pin
        // `format_predicates_are_a_closed_quinary_partition` on the
        // tag-side siblings, and idiom-peer of
        // `format_provider_class_predicates_are_a_closed_binary_partition`
        // on the (`has_shikumi_provider`, `has_figment_builtin_provider`)
        // pair at the same altitude. A future sixth format landing without
        // its own compound-axis polarity assignment collapses the
        // partition on that variant, failing here before drifting through
        // any consumer site.
        for &f in Format::ALL {
            let hits = usize::from(f.is_feature_gated()) + usize::from(f.is_always_available());
            assert_eq!(
                hits, 1,
                "format {f:?} must satisfy exactly one compound-polarity predicate, got {hits}",
            );
        }
    }

    #[test]
    fn format_is_feature_gated_implies_shikumi_built() {
        // Subset law at the compound-predicate altitude: every
        // feature-gated format is shikumi-built. The type-level
        // restatement of
        // `format_required_feature_some_implies_shikumi_built` (which
        // states the same invariant through the `Option` projection)
        // routed through the compound predicate — pins the invariant
        // at the compound-polarity altitude rather than the projection
        // altitude, so a future edit that broke the subset relation on
        // a specific cell fires with the offending variant named at
        // this altitude too.
        for &f in Format::ALL {
            if f.is_feature_gated() {
                assert!(
                    f.has_shikumi_provider(),
                    "{f:?}: is_feature_gated but has_shikumi_provider is false — \
                     a figment-builtin format cannot be feature-gated \
                     (its provider ships unconditionally)",
                );
            }
        }
    }

    #[test]
    fn format_is_always_available_covers_every_figment_builtin_format() {
        // Superset law: every figment-builtin format is always-available.
        // Contrapositive of the subset law at the always-available pole:
        // a figment-builtin format cannot be feature-gated (its provider
        // ships unconditionally), so it must sit in the always-available
        // half. Pins the invariant at the always-available pole so a
        // future tertiary provider class (that happened to also be
        // feature-gated) fails HERE rather than being masked by the
        // subset-law reading at the feature-gated pole.
        for &f in Format::ALL {
            if f.has_figment_builtin_provider() {
                assert!(
                    f.is_always_available(),
                    "{f:?}: has_figment_builtin_provider but is_always_available is false — \
                     figment-builtin providers ship unconditionally",
                );
            }
        }
    }

    #[test]
    fn format_is_feature_gated_is_const_callable() {
        // Compile-time weld: the compound-polarity predicate is
        // `const`-callable, matching the `const`-ness of the sibling
        // per-variant predicates (`is_yaml`, …, `is_blue`) and of
        // `required_feature()`. A drop of the `const` qualifier at
        // either altitude fails this test to compile. Peer of
        // `secret_backend_kind_is_cloud_secret_manager_is_const_callable`.
        const fn call_feature_gated(f: Format) -> bool {
            f.is_feature_gated()
        }
        const fn call_always_available(f: Format) -> bool {
            f.is_always_available()
        }
        // Const-evaluated at compile time on the known five variants.
        const LISP_GATED: bool = call_feature_gated(Format::Lisp);
        const BLUE_GATED: bool = call_feature_gated(Format::Blue);
        const YAML_ALWAYS: bool = call_always_available(Format::Yaml);
        const TOML_ALWAYS: bool = call_always_available(Format::Toml);
        const NIX_ALWAYS: bool = call_always_available(Format::Nix);
        assert!(LISP_GATED);
        assert!(BLUE_GATED);
        assert!(YAML_ALWAYS);
        assert!(TOML_ALWAYS);
        assert!(NIX_ALWAYS);
    }

    // ---- Format::FEATURE_GATED / Format::ALWAYS_AVAILABLE slice constants ----
    //
    // Six pins mirror the per-half meta-partition slice-constant discipline
    // that shipped in `2c0686f` (`ConfigTierKind::COMPUTED / CUSTOM`),
    // `2cf6dd8` (`ConfigSourceKind::DEFAULTS / OVERLAY`), `b2cfa2a`
    // (`SecretOperation::MUTATING / NON_MUTATING`), and the recent
    // closed-binary landings on `AttributionConfidence`,
    // `SecretRefShape`, `FormatProvenance`, `PartitionFace`,
    // `OutputFormat`, `EnvMetadataTagKind`, and `FigmentNameTagKind`
    // — applied here to the five-way file-format axis's
    // (feature-gated × always-available) compound-polarity meta-partition.

    #[test]
    fn format_feature_gated_slice_agrees_with_is_feature_gated_predicate() {
        // Bidirectional weld between the slice literal
        // `Format::FEATURE_GATED` and the boolean predicate
        // `Format::is_feature_gated` on the
        // (feature-gated × always-available) polarity axis. Every
        // slice entry satisfies the feature-gated pole (and its
        // complement `!is_always_available`), and every ALL cell
        // agrees on membership under the boolean predicate. Idiom-peer
        // of `config_tier_kind_computed_slice_agrees_with_is_computed_predicate`
        // (`2c0686f`) — the two independent declaration surfaces
        // (slice literal + boolean predicate) diverge at THIS pin on
        // the first shape where they disagree, before a consumer that
        // reads one altitude but not the other can observe the drift.
        for f in Format::FEATURE_GATED.iter().copied() {
            assert!(
                f.is_feature_gated(),
                "Format::FEATURE_GATED entry {f:?} must satisfy is_feature_gated()",
            );
            assert!(
                !f.is_always_available(),
                "Format::FEATURE_GATED entry {f:?} must NOT satisfy is_always_available()",
            );
        }
        for f in Format::ALWAYS_AVAILABLE.iter().copied() {
            assert!(
                f.is_always_available(),
                "Format::ALWAYS_AVAILABLE entry {f:?} must satisfy is_always_available()",
            );
            assert!(
                !f.is_feature_gated(),
                "Format::ALWAYS_AVAILABLE entry {f:?} must NOT satisfy is_feature_gated()",
            );
        }
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                Format::FEATURE_GATED.contains(&f),
                f.is_feature_gated(),
                "FEATURE_GATED membership must agree with is_feature_gated() on Format::{f:?}",
            );
            assert_eq!(
                Format::ALWAYS_AVAILABLE.contains(&f),
                f.is_always_available(),
                "ALWAYS_AVAILABLE membership must agree with is_always_available() on Format::{f:?}",
            );
        }
    }

    #[test]
    fn format_feature_gated_and_always_available_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `FEATURE_GATED.len() + ALWAYS_AVAILABLE.len() == ALL.len()`
        // at the slice altitude on the file-format axis. Idiom-peer of
        // `config_tier_kind_computed_and_custom_slices_partition_all`
        // (`2c0686f`) — a variant landing on one slice AND the other,
        // or on neither, breaks the partition here before any consumer
        // that reasons about the polarity as a covering meta-partition
        // observes the drift.
        for f in Format::FEATURE_GATED.iter().copied() {
            assert!(
                !Format::ALWAYS_AVAILABLE.contains(&f),
                "Format::{f:?} appears in BOTH FEATURE_GATED and ALWAYS_AVAILABLE",
            );
        }
        for f in Format::ALL.iter().copied() {
            let in_feature_gated = Format::FEATURE_GATED.contains(&f);
            let in_always_available = Format::ALWAYS_AVAILABLE.contains(&f);
            assert!(
                in_feature_gated || in_always_available,
                "Format::{f:?} is in NEITHER FEATURE_GATED nor ALWAYS_AVAILABLE",
            );
            assert!(
                !(in_feature_gated && in_always_available),
                "Format::{f:?} is in BOTH FEATURE_GATED and ALWAYS_AVAILABLE",
            );
        }
        assert_eq!(
            Format::FEATURE_GATED.len() + Format::ALWAYS_AVAILABLE.len(),
            Format::ALL.len(),
            "FEATURE_GATED and ALWAYS_AVAILABLE slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn format_feature_gated_and_always_available_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in Format::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. The
        // always-available pole in particular is INTERLEAVED with the
        // feature-gated pole in Format::ALL (Yaml, Toml, Lisp, Nix,
        // Blue — the always-available cells Yaml/Toml/Nix are split
        // by the feature-gated Lisp cell), so a suffix or prefix
        // rewriting of the slices — or a reordering of ALL that
        // shuffled the interleaving — diverges at THIS pin. Idiom-peer
        // of `config_tier_kind_computed_and_custom_slices_preserve_all_order`
        // (`2c0686f`).
        let feature_gated_from_all: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.is_feature_gated())
            .collect();
        assert_eq!(
            feature_gated_from_all,
            Format::FEATURE_GATED.to_vec(),
            "FEATURE_GATED must be ALL-filtered by is_feature_gated in declaration order",
        );
        let always_available_from_all: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.is_always_available())
            .collect();
        assert_eq!(
            always_available_from_all,
            Format::ALWAYS_AVAILABLE.to_vec(),
            "ALWAYS_AVAILABLE must be ALL-filtered by is_always_available in declaration order",
        );
    }

    #[test]
    fn format_feature_gated_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into FEATURE_GATED, an accidental re-add of an already-present
        // cell into ALWAYS_AVAILABLE) fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a set.
        for slice in [Format::FEATURE_GATED, Format::ALWAYS_AVAILABLE] {
            let mut seen: Vec<Format> = Vec::with_capacity(slice.len());
            for f in slice {
                assert!(
                    !seen.contains(f),
                    "Format slice {slice:?} contains duplicate entry {f:?}",
                );
                seen.push(*f);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn format_feature_gated_and_always_available_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on Format::ALL — i.e.,
        // `FEATURE_GATED.len() == ALL.iter().filter(is_feature_gated).count()`
        // and `ALWAYS_AVAILABLE.len() ==
        // ALL.iter().filter(is_always_available).count()` — the
        // cardinality projection at the slice altitude agrees with the
        // boolean-altitude projection on both halves. Concrete positions
        // today: 2 feature-gated + 3 always-available = 5 = ALL.
        // Idiom-peer of
        // `config_tier_kind_computed_and_custom_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`2c0686f`).
        let feature_gated_count = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.is_feature_gated())
            .count();
        let always_available_count = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.is_always_available())
            .count();
        assert_eq!(
            Format::FEATURE_GATED.len(),
            feature_gated_count,
            "FEATURE_GATED.len() must match the is_feature_gated count on ALL",
        );
        assert_eq!(
            Format::ALWAYS_AVAILABLE.len(),
            always_available_count,
            "ALWAYS_AVAILABLE.len() must match the is_always_available count on ALL",
        );
        assert_eq!(Format::FEATURE_GATED.len(), 2);
        assert_eq!(Format::ALWAYS_AVAILABLE.len(), 3);
        assert_eq!(Format::ALL.len(), 5);
    }

    #[test]
    fn format_feature_gated_and_always_available_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `config_tier_kind_computed_and_custom_slices_are_const_addressable`
        // (`2c0686f`).
        const FEATURE_GATED_LEN: usize = Format::FEATURE_GATED.len();
        const ALWAYS_AVAILABLE_LEN: usize = Format::ALWAYS_AVAILABLE.len();
        const ALL_LEN: usize = Format::ALL.len();
        assert_eq!(FEATURE_GATED_LEN, 2);
        assert_eq!(ALWAYS_AVAILABLE_LEN, 3);
        assert_eq!(FEATURE_GATED_LEN + ALWAYS_AVAILABLE_LEN, ALL_LEN);
    }

    // ── Format — provider-class compound-polarity slice constants ────
    //
    // Second compound-polarity slice-constant landing on the five-way
    // Format axis, on the sibling (shikumi-provided ×
    // figment-builtin-provided) provider-class meta-partition (peer of
    // the shipped (feature-gated × always-available) landing above).
    // The two meta-partitions witness two independent polarities on the
    // same primitive; they agree on four cells and disagree on
    // `Format::Nix` (a shikumi-provided but not feature-gated cell), so
    // the two slice pairs are distinct even at today's cardinalities.
    // Idiom-peer of every prior compound-polarity landing on the crate
    // (`WatchEventClass::FILE_MUTATIONS` at `323d6e2`,
    // `DiffLineKind::CHANGED` at `3b43a67`,
    // `ConfigSourceKind::DEFAULTS` at `2cd8ef8`,
    // `ConfigTierKind::COMPUTED` at `2c0686f`,
    // `SecretOperation::MUTATING` at `b2cfa2a`,
    // `SecretBackendKind::CLOUD_SECRET_MANAGER` at `04e0f5d`,
    // `SecretClientKind::CLOUD_SECRET_MANAGER` at `399ee8a`,
    // `HintSurface::COVERAGE_HINTS` at `749a23c`,
    // `TierArg::COMPUTED` at `c54c40c`) — the per-half slice-constant
    // discipline applied here to a second polarity on the file-format
    // primitive.

    #[test]
    fn format_shikumi_provided_slice_agrees_with_has_shikumi_provider_predicate() {
        // Bidirectional weld between the slice literal
        // `Format::SHIKUMI_PROVIDED` and the boolean predicate
        // `Format::has_shikumi_provider` on the
        // (shikumi-provided × figment-builtin-provided) polarity axis.
        // Every slice entry satisfies the shikumi-provider pole (and
        // its complement `!has_figment_builtin_provider`), and every
        // ALL cell agrees on membership under the boolean predicate.
        // Idiom-peer of
        // `format_feature_gated_slice_agrees_with_is_feature_gated_predicate`
        // one polarity over on the same primitive — the two independent
        // declaration surfaces (slice literal + boolean predicate)
        // diverge at THIS pin on the first shape where they disagree,
        // before a consumer that reads one altitude but not the other
        // can observe the drift.
        for f in Format::SHIKUMI_PROVIDED.iter().copied() {
            assert!(
                f.has_shikumi_provider(),
                "Format::SHIKUMI_PROVIDED entry {f:?} must satisfy has_shikumi_provider()",
            );
            assert!(
                !f.has_figment_builtin_provider(),
                "Format::SHIKUMI_PROVIDED entry {f:?} must NOT satisfy \
                 has_figment_builtin_provider()",
            );
        }
        for f in Format::FIGMENT_BUILTIN_PROVIDED.iter().copied() {
            assert!(
                f.has_figment_builtin_provider(),
                "Format::FIGMENT_BUILTIN_PROVIDED entry {f:?} must satisfy \
                 has_figment_builtin_provider()",
            );
            assert!(
                !f.has_shikumi_provider(),
                "Format::FIGMENT_BUILTIN_PROVIDED entry {f:?} must NOT satisfy \
                 has_shikumi_provider()",
            );
        }
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                Format::SHIKUMI_PROVIDED.contains(&f),
                f.has_shikumi_provider(),
                "SHIKUMI_PROVIDED membership must agree with has_shikumi_provider() \
                 on Format::{f:?}",
            );
            assert_eq!(
                Format::FIGMENT_BUILTIN_PROVIDED.contains(&f),
                f.has_figment_builtin_provider(),
                "FIGMENT_BUILTIN_PROVIDED membership must agree with \
                 has_figment_builtin_provider() on Format::{f:?}",
            );
        }
    }

    #[test]
    fn format_shikumi_provided_and_figment_builtin_provided_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint and
        // their union covers ALL. Direct application of the
        // meta-partition sum law
        // `SHIKUMI_PROVIDED.len() + FIGMENT_BUILTIN_PROVIDED.len() ==
        // ALL.len()` at the slice altitude on the file-format axis's
        // provider-class polarity. A variant landing on both slices or
        // on neither breaks the partition here before any consumer that
        // reasons about the polarity as a covering meta-partition
        // observes the drift.
        for f in Format::SHIKUMI_PROVIDED.iter().copied() {
            assert!(
                !Format::FIGMENT_BUILTIN_PROVIDED.contains(&f),
                "Format::{f:?} appears in BOTH SHIKUMI_PROVIDED and \
                 FIGMENT_BUILTIN_PROVIDED",
            );
        }
        for f in Format::ALL.iter().copied() {
            let in_shikumi = Format::SHIKUMI_PROVIDED.contains(&f);
            let in_figment = Format::FIGMENT_BUILTIN_PROVIDED.contains(&f);
            assert!(
                in_shikumi || in_figment,
                "Format::{f:?} is in NEITHER SHIKUMI_PROVIDED nor \
                 FIGMENT_BUILTIN_PROVIDED",
            );
            assert!(
                !(in_shikumi && in_figment),
                "Format::{f:?} is in BOTH SHIKUMI_PROVIDED and \
                 FIGMENT_BUILTIN_PROVIDED",
            );
        }
        assert_eq!(
            Format::SHIKUMI_PROVIDED.len() + Format::FIGMENT_BUILTIN_PROVIDED.len(),
            Format::ALL.len(),
            "SHIKUMI_PROVIDED and FIGMENT_BUILTIN_PROVIDED slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn format_shikumi_provided_and_figment_builtin_provided_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in Format::ALL — i.e. the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. The
        // shikumi-provided pole is a proper suffix of ALL today
        // ([Lisp, Nix, Blue]) and the figment-builtin pole is a proper
        // prefix ([Yaml, Toml]); a future landing that inserted a new
        // figment-builtin variant between Lisp and Nix would force this
        // pin to move the new cell into FIGMENT_BUILTIN_PROVIDED at the
        // matching ALL-declaration-order position rather than at the
        // tail.
        let shikumi_from_all: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.has_shikumi_provider())
            .collect();
        assert_eq!(
            shikumi_from_all,
            Format::SHIKUMI_PROVIDED.to_vec(),
            "SHIKUMI_PROVIDED must be ALL-filtered by has_shikumi_provider in declaration order",
        );
        let figment_from_all: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.has_figment_builtin_provider())
            .collect();
        assert_eq!(
            figment_from_all,
            Format::FIGMENT_BUILTIN_PROVIDED.to_vec(),
            "FIGMENT_BUILTIN_PROVIDED must be ALL-filtered by has_figment_builtin_provider \
             in declaration order",
        );
    }

    #[test]
    fn format_shikumi_provided_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into SHIKUMI_PROVIDED, an accidental re-add of an
        // already-present cell into FIGMENT_BUILTIN_PROVIDED) fails at
        // THIS pin before drifting through any consumer that iterates
        // the slice expecting a set.
        for slice in [Format::SHIKUMI_PROVIDED, Format::FIGMENT_BUILTIN_PROVIDED] {
            let mut seen: Vec<Format> = Vec::with_capacity(slice.len());
            for f in slice {
                assert!(
                    !seen.contains(f),
                    "Format slice {slice:?} contains duplicate entry {f:?}",
                );
                seen.push(*f);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn format_shikumi_provided_and_figment_builtin_provided_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on Format::ALL — i.e.
        // `SHIKUMI_PROVIDED.len() ==
        // ALL.iter().filter(has_shikumi_provider).count()` and
        // `FIGMENT_BUILTIN_PROVIDED.len() ==
        // ALL.iter().filter(has_figment_builtin_provider).count()` —
        // the cardinality projection at the slice altitude agrees with
        // the boolean-altitude projection on both halves. Concrete
        // positions today: 3 shikumi-provided + 2 figment-builtin = 5 =
        // ALL. A future sixth variant lands here in lockstep with the
        // boolean predicate that admits it.
        let shikumi_count = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.has_shikumi_provider())
            .count();
        let figment_count = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.has_figment_builtin_provider())
            .count();
        assert_eq!(
            Format::SHIKUMI_PROVIDED.len(),
            shikumi_count,
            "SHIKUMI_PROVIDED.len() must match the has_shikumi_provider count on ALL",
        );
        assert_eq!(
            Format::FIGMENT_BUILTIN_PROVIDED.len(),
            figment_count,
            "FIGMENT_BUILTIN_PROVIDED.len() must match the has_figment_builtin_provider \
             count on ALL",
        );
        assert_eq!(Format::SHIKUMI_PROVIDED.len(), 3);
        assert_eq!(Format::FIGMENT_BUILTIN_PROVIDED.len(), 2);
        assert_eq!(Format::ALL.len(), 5);
    }

    #[test]
    fn format_shikumi_provided_and_figment_builtin_provided_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer.
        const SHIKUMI_PROVIDED_LEN: usize = Format::SHIKUMI_PROVIDED.len();
        const FIGMENT_BUILTIN_PROVIDED_LEN: usize = Format::FIGMENT_BUILTIN_PROVIDED.len();
        const ALL_LEN: usize = Format::ALL.len();
        assert_eq!(SHIKUMI_PROVIDED_LEN, 3);
        assert_eq!(FIGMENT_BUILTIN_PROVIDED_LEN, 2);
        assert_eq!(SHIKUMI_PROVIDED_LEN + FIGMENT_BUILTIN_PROVIDED_LEN, ALL_LEN);
    }

    #[test]
    fn format_shikumi_provided_differs_from_feature_gated_at_nix() {
        // Distinctness pin between the two compound-polarity meta-
        // partitions on the same primitive. The (shikumi-provided ×
        // figment-builtin-provided) polarity groups `Nix` with `Lisp`
        // and `Blue` (all three are shikumi-built providers), while
        // the (feature-gated × always-available) polarity groups `Nix`
        // with `Yaml` and `Toml` (all three compile unconditionally).
        // A future edit that collapsed the two polarities onto the
        // same slice literals (e.g. by making Nix feature-gated, or by
        // dropping its shikumi provider in favour of a figment-builtin
        // one) would silently make consumers of one polarity read the
        // other; this pin catches that collapse at compile time before
        // it reaches any downstream reader.
        assert!(
            Format::SHIKUMI_PROVIDED.contains(&Format::Nix),
            "Nix must be in SHIKUMI_PROVIDED — it is loaded by NixProvider",
        );
        assert!(
            !Format::FEATURE_GATED.contains(&Format::Nix),
            "Nix must NOT be in FEATURE_GATED — it compiles unconditionally today",
        );
        assert_ne!(
            Format::SHIKUMI_PROVIDED,
            Format::FEATURE_GATED,
            "the provider-class and feature-gated polarities must remain distinct \
             slice literals",
        );
        assert_ne!(
            Format::FIGMENT_BUILTIN_PROVIDED,
            Format::ALWAYS_AVAILABLE,
            "the provider-class and feature-gated polarities' complement halves \
             must remain distinct slice literals",
        );
    }

    // ── Format — identity meta-partition slice constants ─────────────
    //
    // Quinary landing of the per-half meta-partition slice-constant
    // discipline on the five-way Format axis (first identity-partition
    // landing on the config-file-format primitive). Peer of the
    // septenary `ShikumiErrorKind::ONLY_NOT_FOUND` / … /
    // `ONLY_VALIDATION` (commit `6e74116`), the quinary
    // `SecretErrorKind::ONLY_NOT_FOUND` / … / `ONLY_SHIKUMI` (commit
    // `1a4ae14`), and the quinary `TierArg::ONLY_BARE` / … / `ONLY_ENV`
    // (commit `f7f5529`). The seven pins below lock the identity
    // singletons as a coherent meta-partition at the primitive's
    // altitude alongside the shipped compound-polarity FEATURE_GATED /
    // ALWAYS_AVAILABLE pair one altitude up.

    #[test]
    fn format_identity_slices_agree_with_identity_predicates() {
        // Five-way agreement pin across the (yaml × toml × lisp × nix
        // × blue) identity meta-partition. Every ONLY_YAML entry
        // satisfies is_yaml and none of the four sibling predicates;
        // every ONLY_TOML entry satisfies is_toml alone; … and so on
        // across all five halves. The two independent declaration
        // surfaces (slice literals + boolean predicates) diverge at
        // THIS pin on the first shape where they disagree, before a
        // consumer that reads one altitude but not the other can
        // observe the drift. Quinary peer of
        // `shikumi_error_kind_identity_slices_agree_with_identity_predicates`
        // (commit `6e74116`) two cells narrower.
        for f in Format::ONLY_YAML.iter().copied() {
            assert!(f.is_yaml(), "ONLY_YAML {f:?} must satisfy is_yaml");
            assert!(!f.is_toml(), "ONLY_YAML {f:?} must NOT satisfy is_toml");
            assert!(!f.is_lisp(), "ONLY_YAML {f:?} must NOT satisfy is_lisp");
            assert!(!f.is_nix(), "ONLY_YAML {f:?} must NOT satisfy is_nix");
            assert!(!f.is_blue(), "ONLY_YAML {f:?} must NOT satisfy is_blue");
        }
        for f in Format::ONLY_TOML.iter().copied() {
            assert!(f.is_toml(), "ONLY_TOML {f:?} must satisfy is_toml");
            assert!(!f.is_yaml(), "ONLY_TOML {f:?} must NOT satisfy is_yaml");
            assert!(!f.is_lisp(), "ONLY_TOML {f:?} must NOT satisfy is_lisp");
            assert!(!f.is_nix(), "ONLY_TOML {f:?} must NOT satisfy is_nix");
            assert!(!f.is_blue(), "ONLY_TOML {f:?} must NOT satisfy is_blue");
        }
        for f in Format::ONLY_LISP.iter().copied() {
            assert!(f.is_lisp(), "ONLY_LISP {f:?} must satisfy is_lisp");
            assert!(!f.is_yaml(), "ONLY_LISP {f:?} must NOT satisfy is_yaml");
            assert!(!f.is_toml(), "ONLY_LISP {f:?} must NOT satisfy is_toml");
            assert!(!f.is_nix(), "ONLY_LISP {f:?} must NOT satisfy is_nix");
            assert!(!f.is_blue(), "ONLY_LISP {f:?} must NOT satisfy is_blue");
        }
        for f in Format::ONLY_NIX.iter().copied() {
            assert!(f.is_nix(), "ONLY_NIX {f:?} must satisfy is_nix");
            assert!(!f.is_yaml(), "ONLY_NIX {f:?} must NOT satisfy is_yaml");
            assert!(!f.is_toml(), "ONLY_NIX {f:?} must NOT satisfy is_toml");
            assert!(!f.is_lisp(), "ONLY_NIX {f:?} must NOT satisfy is_lisp");
            assert!(!f.is_blue(), "ONLY_NIX {f:?} must NOT satisfy is_blue");
        }
        for f in Format::ONLY_BLUE.iter().copied() {
            assert!(f.is_blue(), "ONLY_BLUE {f:?} must satisfy is_blue");
            assert!(!f.is_yaml(), "ONLY_BLUE {f:?} must NOT satisfy is_yaml");
            assert!(!f.is_toml(), "ONLY_BLUE {f:?} must NOT satisfy is_toml");
            assert!(!f.is_lisp(), "ONLY_BLUE {f:?} must NOT satisfy is_lisp");
            assert!(!f.is_nix(), "ONLY_BLUE {f:?} must NOT satisfy is_nix");
        }
    }

    #[test]
    fn format_identity_slices_partition_all() {
        // Quinary partition invariant: the five per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_YAML.len() + ONLY_TOML.len() + ONLY_LISP.len() +
        //  ONLY_NIX.len() + ONLY_BLUE.len() == ALL.len()`.
        let identity_slices: [&[Format]; 5] = [
            Format::ONLY_YAML,
            Format::ONLY_TOML,
            Format::ONLY_LISP,
            Format::ONLY_NIX,
            Format::ONLY_BLUE,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for f in left.iter() {
                    assert!(
                        !right.contains(f),
                        "Format::{f:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for f in Format::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&f)))
                .sum();
            assert_eq!(
                held, 1,
                "Format::{f:?} must appear in exactly one identity slice \
                 (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            Format::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn format_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in Format::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at THIS
        // pin.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<Format> = Format::ALL
                    .iter()
                    .copied()
                    .filter(|f| f.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(Format::ONLY_YAML, is_yaml);
        pin!(Format::ONLY_TOML, is_toml);
        pin!(Format::ONLY_LISP, is_lisp);
        pin!(Format::ONLY_NIX, is_nix);
        pin!(Format::ONLY_BLUE, is_blue);
    }

    #[test]
    fn format_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all five per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set.
        for slice in [
            Format::ONLY_YAML,
            Format::ONLY_TOML,
            Format::ONLY_LISP,
            Format::ONLY_NIX,
            Format::ONLY_BLUE,
        ] {
            let mut seen: Vec<Format> = Vec::with_capacity(slice.len());
            for f in slice {
                assert!(
                    !seen.contains(f),
                    "Format identity slice {slice:?} contains duplicate entry {f:?}",
                );
                seen.push(*f);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn format_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on Format::ALL — i.e.,
        // `ONLY_YAML.len() == ALL.iter().filter(is_yaml).count()`
        // (and symmetric for the four siblings) — the cardinality
        // projection at the slice altitude agrees with the boolean-
        // altitude projection on all five halves. Concrete positions
        // today: 1 + 1 + 1 + 1 + 1 = 5 = ALL.
        let counts = [
            (
                "is_yaml",
                Format::ONLY_YAML.len(),
                Format::ALL.iter().copied().filter(|f| f.is_yaml()).count(),
            ),
            (
                "is_toml",
                Format::ONLY_TOML.len(),
                Format::ALL.iter().copied().filter(|f| f.is_toml()).count(),
            ),
            (
                "is_lisp",
                Format::ONLY_LISP.len(),
                Format::ALL.iter().copied().filter(|f| f.is_lisp()).count(),
            ),
            (
                "is_nix",
                Format::ONLY_NIX.len(),
                Format::ALL.iter().copied().filter(|f| f.is_nix()).count(),
            ),
            (
                "is_blue",
                Format::ONLY_BLUE.len(),
                Format::ALL.iter().copied().filter(|f| f.is_blue()).count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(Format::ALL.len(), 5);
    }

    #[test]
    fn format_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the five per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        const ONLY_YAML_LEN: usize = Format::ONLY_YAML.len();
        const ONLY_TOML_LEN: usize = Format::ONLY_TOML.len();
        const ONLY_LISP_LEN: usize = Format::ONLY_LISP.len();
        const ONLY_NIX_LEN: usize = Format::ONLY_NIX.len();
        const ONLY_BLUE_LEN: usize = Format::ONLY_BLUE.len();
        const ALL_LEN: usize = Format::ALL.len();
        assert_eq!(ONLY_YAML_LEN, 1);
        assert_eq!(ONLY_TOML_LEN, 1);
        assert_eq!(ONLY_LISP_LEN, 1);
        assert_eq!(ONLY_NIX_LEN, 1);
        assert_eq!(ONLY_BLUE_LEN, 1);
        assert_eq!(
            ONLY_YAML_LEN + ONLY_TOML_LEN + ONLY_LISP_LEN + ONLY_NIX_LEN + ONLY_BLUE_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn format_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the compound-polarity meta-partition
        // (FEATURE_GATED / ALWAYS_AVAILABLE). The union of the two
        // identity singletons on the feature-gated pole
        // (ONLY_LISP + ONLY_BLUE) equals FEATURE_GATED as a sequence
        // in declaration order, and the union of the three always-
        // available identity singletons (ONLY_YAML + ONLY_TOML +
        // ONLY_NIX) equals ALWAYS_AVAILABLE likewise — the
        // interleaved ALL-order projection preserved on the always-
        // available pole ([`Format::Nix`] sits after [`Format::Lisp`]
        // in [`Format::ALL`], so the always-available slice is
        // neither a prefix nor a suffix of ALL). A future
        // rearrangement of one meta-partition without the other (say,
        // reclassifying [`Format::Nix`] as feature-gated without
        // updating the identity → compound aggregation) diverges at
        // THIS pin, before drifting through a consumer that
        // materializes one altitude from the other. Idiom-peer of
        // `shikumi_error_kind_identity_slices_agree_with_compound_polarity_slices`
        // (commit `6e74116`).
        let feature_gated_from_identity: Vec<Format> = [Format::ONLY_LISP, Format::ONLY_BLUE]
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        assert_eq!(
            feature_gated_from_identity,
            Format::FEATURE_GATED.to_vec(),
            "identity singleton union on the feature-gated pole must \
             reproduce FEATURE_GATED in declaration order",
        );
        let always_available_from_identity: Vec<Format> =
            [Format::ONLY_YAML, Format::ONLY_TOML, Format::ONLY_NIX]
                .iter()
                .flat_map(|s| s.iter().copied())
                .collect();
        assert_eq!(
            always_available_from_identity,
            Format::ALWAYS_AVAILABLE.to_vec(),
            "identity singleton union on the always-available pole must \
             reproduce ALWAYS_AVAILABLE in declaration order",
        );
    }

    // ---- required_feature (the format → optional-cargo-feature axis) ----
    //
    // The (format → feature) projection was implicit across three sites
    // before this accessor: the `#[cfg(feature = "…")] mod <provider>;`
    // gates in `src/lib.rs`, the two `merge_or_warn_missing_feature!`
    // invocations in `src/provider.rs` (which pass the feature literal as
    // `feature = "…"`), and the fallback prose inside
    // `crate::provider::missing_feature_warning_body`. Lifting it to a
    // typed accessor on `Format` closes the axis at ONE named site; these
    // tests pin the per-variant mapping, the compile-time invariants that
    // relate it to the sibling axes, and the two source-text agreements
    // that keep it in lockstep with the module gates and the macro literals.

    #[test]
    fn format_required_feature_pinned_per_variant() {
        // Concrete-position pin on the projection: every `Format` variant
        // resolves to a specific `Option<&'static str>` at THIS site,
        // matching the module gates in `src/lib.rs` and the macro
        // literals in `src/provider.rs`'s `ProviderChain::with_file`.
        // A future refactor that renamed either an existing feature or
        // silently reshuffled which formats gate on which trips exactly
        // this test.
        assert_eq!(Format::Yaml.required_feature(), None);
        assert_eq!(Format::Toml.required_feature(), None);
        assert_eq!(Format::Nix.required_feature(), None);
        assert_eq!(Format::Lisp.required_feature(), Some("lisp"));
        assert_eq!(Format::Blue.required_feature(), Some("blue"));
    }

    #[test]
    fn format_required_feature_some_implies_shikumi_built() {
        // Structural invariant: every feature-gated format is loaded by a
        // shikumi-built provider. The figment-builtin providers ship
        // unconditionally, so a Yaml/Toml with `required_feature() =
        // Some(_)` would be a category error. Pinned as a per-variant
        // implication rather than a global filter so a future variant
        // that broke the invariant on a specific cell fires with the
        // offending variant named.
        for &f in Format::ALL {
            if f.required_feature().is_some() {
                assert!(
                    f.has_shikumi_provider(),
                    "{f:?}: required_feature is Some but has_shikumi_provider is false — \
                     a figment-builtin format cannot be feature-gated (its provider ships \
                     unconditionally)",
                );
            }
        }
    }

    #[test]
    fn format_figment_builtin_implies_no_required_feature() {
        // Contrapositive of the above stated directly as its own pin
        // (equivalent by classical logic, but named separately so a
        // future variant that breaks THIS direction reports the
        // figment-builtin corner as the failure site rather than the
        // shikumi-built implication).
        for &f in Format::ALL {
            if f.has_figment_builtin_provider() {
                assert_eq!(
                    f.required_feature(),
                    None,
                    "{f:?}: has_figment_builtin_provider but required_feature is Some — \
                     figment-builtin providers ship unconditionally",
                );
            }
        }
    }

    #[test]
    fn format_required_feature_names_appear_in_cargo_toml_features_table() {
        // Cross-file pin: every feature literal `required_feature()`
        // returns must actually name a feature declared in the crate's
        // `Cargo.toml` `[features]` table. Catches a typo (`"lsp"` vs
        // `"lisp"`) or a rename that drifted only one side. The needle
        // is the `<name> =` shape a `[features]` entry always writes,
        // scoped to the `[features]` section so a coincidental match
        // elsewhere in the manifest (a dep name colliding with a feature
        // name, a comment mentioning the string) does not silently pass.
        const CARGO_TOML: &str = include_str!("../Cargo.toml");
        // Anchor on the `[features]` HEADER (line-start with the leading
        // newline) rather than the bare substring — Cargo.toml elsewhere
        // mentions the word `[features]` inside a `# ...` comment (see the
        // `[lints.rust]` header block), and a bare `.split("[features]")`
        // would split at that comment mention instead of the real section
        // header.
        let after_features = CARGO_TOML
            .split("\n[features]\n")
            .nth(1)
            .expect("Cargo.toml must have a [features] section header on its own line");
        let scope_end = after_features.find("\n[").unwrap_or(after_features.len());
        let features_scope = &after_features[..scope_end];
        for &f in Format::ALL {
            if let Some(feature) = f.required_feature() {
                let needle = format!("\n{feature} =");
                assert!(
                    features_scope.contains(&needle),
                    "{f:?}.required_feature() = Some({feature:?}) but Cargo.toml \
                     [features] table has no `{feature} =` entry — the accessor and \
                     the manifest have drifted",
                );
            }
        }
    }

    #[test]
    fn format_required_feature_agrees_with_lib_rs_module_gates() {
        // Cross-file source-text pin: every feature literal
        // `required_feature()` returns must correspond to a
        // `#[cfg(feature = "…")] pub mod <name>_provider;` gate in
        // `src/lib.rs`. Catches a rename that drifted only one side
        // (e.g. an accessor returning `Some("blue")` while the module
        // gate said `#[cfg(feature = "blue-syntax")]`) — the two axes
        // must move together. Complements the `Cargo.toml` pin above:
        // this one enforces that the accessor and the crate's own
        // module-gating convention agree; the manifest pin enforces
        // that both agree with the [features] table upstream.
        const LIB_RS: &str = include_str!("lib.rs");
        for &f in Format::ALL {
            if let Some(feature) = f.required_feature() {
                let needle = format!("#[cfg(feature = \"{feature}\")]");
                assert!(
                    LIB_RS.contains(&needle),
                    "{f:?}.required_feature() = Some({feature:?}) but src/lib.rs has \
                     no matching `{needle}` module gate — accessor and module gate \
                     have drifted",
                );
            }
        }
    }

    #[test]
    fn format_required_feature_agrees_with_provider_macro_call_sites() {
        // Cross-file source-text pin: every
        // `merge_or_warn_missing_feature!` call site in
        // `src/provider.rs` passes a `feature = "…"` literal that must
        // match `format.required_feature()` for whatever `Format::X`
        // the same call site passes as `format = …`. The pin walks the
        // paired lines and asserts the literals agree with the
        // accessor pointwise, so a future rename or new gate cannot
        // land at the macro literal without a paired edit here.
        //
        // Restricted to the `merge_or_warn_missing_feature!` block —
        // other files may mention `feature = "…"` in unrelated
        // contexts (Cargo.toml comments, doc-strings) and are out of
        // scope for this pin.
        const PROVIDER_RS: &str = include_str!("provider.rs");
        // Every `feature = "<name>",` followed within a few lines by a
        // `format = Format::<Variant>,` pair — the shape both
        // `merge_or_warn_missing_feature!` call sites use inside
        // `with_file`. The `contains` walk is over the whole file; the
        // parser is deliberately minimal because there are only two
        // call sites today.
        let mut pairs_checked = 0usize;
        for (i, line) in PROVIDER_RS.lines().enumerate() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("feature = \"") {
                if let Some(end) = rest.find('"') {
                    let feature = &rest[..end];
                    // Look ahead up to 3 lines for the matching `format =
                    // Format::<Variant>` line inside the same macro
                    // invocation.
                    let format_line = PROVIDER_RS
                        .lines()
                        .skip(i + 1)
                        .take(3)
                        .find_map(|l| l.trim_start().strip_prefix("format = Format::"));
                    let Some(format_ident_rest) = format_line else {
                        continue;
                    };
                    let variant = format_ident_rest.trim_end_matches(',').trim_end();
                    let matched = Format::ALL.iter().copied().find(|f| match f {
                        Format::Yaml => variant == "Yaml",
                        Format::Toml => variant == "Toml",
                        Format::Nix => variant == "Nix",
                        Format::Lisp => variant == "Lisp",
                        Format::Blue => variant == "Blue",
                    });
                    let Some(format) = matched else {
                        continue;
                    };
                    assert_eq!(
                        format.required_feature(),
                        Some(feature),
                        "src/provider.rs line {}: `feature = {feature:?}` paired with \
                         `format = Format::{variant}` but Format::{variant}.required_feature() \
                         = {:?} — macro literal and accessor have drifted",
                        i + 1,
                        format.required_feature(),
                    );
                    pairs_checked += 1;
                }
            }
        }
        assert_eq!(
            pairs_checked, 2,
            "expected exactly 2 `merge_or_warn_missing_feature!`-style feature/format pairs \
             in src/provider.rs (one per feature-gated format arm of ProviderChain::with_file); \
             found {pairs_checked}",
        );
    }

    #[test]
    fn format_required_feature_none_variants_are_always_available() {
        // Structural pin: the None-image of `required_feature` is exactly
        // {Yaml, Toml, Nix} — the three formats `ProviderChain::with_file`
        // reaches through a direct `merge_file_layer(…)` call (no
        // `merge_or_warn_missing_feature!` macro), so their loaders are
        // unconditionally linked. Any future variant that landed in this
        // set without a corresponding unconditional-loader arm in
        // `with_file` would silently fall through the conservative TOML
        // fallback at load-time; pinning the None-image at the type
        // level catches that drift before it ships.
        let none_variants: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.required_feature().is_none())
            .collect();
        assert_eq!(
            none_variants,
            vec![Format::Yaml, Format::Toml, Format::Nix],
            "the always-available format set is {{Yaml, Toml, Nix}}; a fourth cell here \
             means either a new format shipped without its `merge_or_warn_missing_feature!` \
             arm, or an existing feature-gated format quietly lost its gate",
        );
    }

    #[test]
    fn format_required_feature_some_variants_match_feature_gated_modules() {
        // Structural pin on the complementary Some-image: the
        // feature-gated set is exactly {Lisp, Blue} today. Peer of the
        // None-image pin above; catches a drift where a shikumi-built
        // format silently gained or lost its gate.
        let some_variants: Vec<Format> = Format::ALL
            .iter()
            .copied()
            .filter(|f| f.required_feature().is_some())
            .collect();
        assert_eq!(
            some_variants,
            vec![Format::Lisp, Format::Blue],
            "the feature-gated format set is {{Lisp, Blue}}; a change here means either \
             a new gated format landed, or an existing gate was removed",
        );
    }

    #[test]
    fn format_dict_required_message_pins_per_format_wording() {
        // Concrete-position pin on Format::dict_required_message: the
        // four per-format error-message prefixes at one site. The Lisp
        // and Nix wordings are byte-identical to the messages the two
        // shikumi-built providers previously emitted from their `data`
        // impls — pinned here so the open-coded → lifted refactor of
        // `LispProvider::data` and `NixProvider::data` cannot silently
        // rewrite the operator-facing diagnostic. The YAML / TOML
        // wordings exist for total-coverage discipline (the
        // figment-builtin file providers do not route through this
        // method today) and are pinned now so a future provider that
        // does cannot drift on the noun choice.
        assert_eq!(
            Format::Yaml.dict_required_message(),
            "top-level yaml document must be a mapping",
        );
        assert_eq!(
            Format::Toml.dict_required_message(),
            "top-level toml document must be a table",
        );
        assert_eq!(
            Format::Lisp.dict_required_message(),
            "top-level lisp form must be a kwargs list",
        );
        assert_eq!(
            Format::Nix.dict_required_message(),
            "top-level nix expression must evaluate to an attrset",
        );
    }

    #[test]
    fn format_dict_required_message_starts_with_top_level_and_names_format() {
        // Structural pin: every variant's message starts with the
        // shared `"top-level "` prefix and cites the format's canonical
        // name (`as_str`) verbatim. Catches a future format addition
        // that forgets either the shared prefix or the name-citation
        // discipline.
        for f in Format::ALL.iter().copied() {
            let msg = f.dict_required_message();
            assert!(
                msg.starts_with("top-level "),
                "{f:?}: message must start with `top-level `, got `{msg}`",
            );
            assert!(
                msg.contains(f.as_str()),
                "{f:?}: message must cite the format's canonical name `{}`, got `{msg}`",
                f.as_str(),
            );
        }
    }

    #[test]
    fn format_dict_required_message_is_distinct_per_variant() {
        // No two variants share the same dict-required wording. The
        // operator-facing diagnostic distinguishes which format-aware
        // provider rejected the top-level shape; a duplicated message
        // would lose that distinction.
        let mut seen: Vec<&'static str> = Format::ALL
            .iter()
            .map(|f| f.dict_required_message())
            .collect();
        seen.sort_unstable();
        let len_before = seen.len();
        seen.dedup();
        assert_eq!(
            seen.len(),
            len_before,
            "dict_required_message must be distinct for every Format variant",
        );
    }

    #[test]
    fn format_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on Format::as_str: the four canonical
        // labels at one site. The trait-uniform round-trip test in
        // cube::tests pins the labels equal pairwise under
        // from_canonical_str, but this test pins the literal string
        // values themselves so a future rename (e.g. capitalizing
        // "Yaml") would fail here before drifting through the
        // round-trip law.
        assert_eq!(Format::Yaml.as_str(), "yaml");
        assert_eq!(Format::Toml.as_str(), "toml");
        assert_eq!(Format::Lisp.as_str(), "lisp");
        assert_eq!(Format::Nix.as_str(), "nix");
    }

    #[test]
    fn format_display_matches_as_str() {
        // Pin that Display delegates to as_str pointwise across every
        // variant. The Display impl used to carry a duplicated 4-arm
        // match emitting the same four strings; the lift collapses the
        // body to `f.write_str(self.as_str())`, and this test pins the
        // collapse so a future drift between the two surfaces fails
        // here before propagating to every consumer that renders
        // `{format}` via Display.
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                f.to_string(),
                f.as_str(),
                "Display must agree with as_str for {f:?}",
            );
        }
    }

    #[test]
    fn format_extensions_first_entry_matches_as_str() {
        // Pin that the canonical extension (first entry of
        // `extensions()`) equals the canonical operator-facing name
        // (`as_str()`) pointwise across every variant. The two surfaces
        // happen to coincide today (`extensions()[0]` and `as_str()`
        // both emit `"yaml"`/`"toml"`/`"lisp"`/`"nix"`); pinning the
        // invariant catches any future drift between them — e.g. a
        // future rename of the canonical name that forgets to bump the
        // extensions slice, or vice versa.
        for f in Format::ALL.iter().copied() {
            let extensions = f.extensions();
            assert!(
                !extensions.is_empty(),
                "extensions() must never be empty for {f:?}",
            );
            assert_eq!(
                extensions[0],
                f.as_str(),
                "extensions()[0] must equal as_str() for {f:?}",
            );
        }
    }

    #[test]
    fn format_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on Format:
        // each canonical name parses back to its variant. Distinct from
        // the existing `format_from_str_case_insensitive` (which
        // covers the richer `FromStr` impl that also accepts aliases
        // like `"yml"`/`"lsp"`/`"el"`): this pin reaches the
        // canonical-only trait parse that the ClosedAxisLabel default
        // impl provides.
        use crate::ClosedAxisLabel;
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                <Format as ClosedAxisLabel>::from_canonical_str(f.as_str()),
                Some(f),
                "trait from_canonical_str must round-trip for {f:?}",
            );
        }
        // Alias `"yml"` parses through `FromStr` but not through the
        // canonical-only trait parse (which only accepts the canonical
        // name `"yaml"`). The two surfaces are deliberately distinct.
        assert_eq!(
            <Format as ClosedAxisLabel>::from_canonical_str("yml"),
            None,
            "from_canonical_str must reject alias `yml` (FromStr accepts it; the trait does not)",
        );
        assert_eq!(
            <Format as ClosedAxisLabel>::from_canonical_str("lsp"),
            None,
            "from_canonical_str must reject alias `lsp`",
        );
        assert_eq!(
            <Format as ClosedAxisLabel>::from_canonical_str("el"),
            None,
            "from_canonical_str must reject alias `el`",
        );
    }

    #[test]
    fn format_ord_matches_all_declaration_order() {
        // Yaml < Toml < Lisp < Nix under the derived Ord — the
        // declaration-order total order is monotone in the Format::ALL
        // position. A BTreeMap<Format, T> keyed on the format axis
        // emits rows in this order deterministically; pinned here so a
        // silent variant reorder (which would invert the rollup order
        // on every consumer) fails this assertion first. Idiom-peer of
        // the `*_class_ord_matches_all_declaration_order` pins on the
        // typed-cube classifiers (ModalityClass, PartitionFace, …).
        // The order also matches the documented "preference order"
        // reading on the Format doc comment, so a future precedence
        // change at the discovery layer surfaces as a paired drift
        // here.
        assert!(Format::Yaml < Format::Toml);
        assert!(Format::Toml < Format::Lisp);
        assert!(Format::Lisp < Format::Nix);
        for window in Format::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "Ord must be strictly monotone in Format::ALL position: \
                 {:?} < {:?} failed",
                window[0],
                window[1],
            );
        }
    }

    #[test]
    fn format_serde_yaml_round_trips_over_every_variant() {
        // Serialize then deserialize on every variant — the typed
        // format tag survives the YAML scalar round-trip via the
        // canonical label, no consumer-side rename helper at the
        // renderer. Closes the (Serialize, Deserialize) idiom-peer of
        // the existing (Display, FromStr) round-trip on Format.
        for &f in Format::ALL {
            let yaml = serde_yaml::to_string(&f).unwrap();
            let parsed: Format = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("YAML round-trip for {f:?} failed: {e}"));
            assert_eq!(
                parsed, f,
                "serde YAML round-trip must be identity for {f:?}"
            );
        }
    }

    #[test]
    fn format_serde_json_round_trips_over_every_variant() {
        // JSON emission is the quoted canonical lowercase label; the
        // round-trip is identity over every variant. Pins the natural
        // projection an observability payload reaches when carrying a
        // Format field through #[derive(Serialize, Deserialize)] — a
        // consumer config emitting `{"default_format": "yaml"}` lands
        // at the wire shape without a rename helper.
        for &f in Format::ALL {
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", f.as_str()),
                "JSON emission for {f:?} must be the quoted canonical label",
            );
            let parsed: Format = serde_json::from_str(&json).unwrap_or_else(|e| {
                panic!("JSON round-trip for {f:?} failed: {e}\n  json: {json}")
            });
            assert_eq!(
                parsed, f,
                "serde JSON round-trip must be identity for {f:?}"
            );
        }
    }

    #[test]
    fn format_serde_yaml_is_case_insensitive() {
        // Uppercase YAML scalars parse back to the same format via the
        // case-insensitive deserialize path lowering through FromStr
        // (which lowers through Format::from_extension, applying
        // `to_ascii_lowercase` to the input).
        for &f in Format::ALL {
            let upper = f.as_str().to_ascii_uppercase();
            let yaml = format!("\"{upper}\"\n");
            let parsed: Format = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
                panic!("uppercase YAML scalar for {f:?} must deserialize: {e}\n  yaml: {yaml:?}")
            });
            assert_eq!(parsed, f);
        }
    }

    #[test]
    fn format_serde_yaml_accepts_aliases() {
        // The alias surface inherited from Format::from_extension —
        // `yml` for Yaml, `lsp`/`el` for Lisp — parses pointwise on
        // the serde side. An operator-authored manifest field carrying
        // `default_format: yml` (the common short spelling) lands as
        // Format::Yaml without a per-emitter alias-fold.
        let cases: &[(&str, Format)] = &[
            ("yml", Format::Yaml),
            ("lsp", Format::Lisp),
            ("el", Format::Lisp),
        ];
        for &(alias, expected) in cases {
            let yaml = format!("\"{alias}\"\n");
            let parsed: Format = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
                panic!("alias `{alias}` must deserialize to {expected:?}: {e}")
            });
            assert_eq!(
                parsed, expected,
                "alias `{alias}` must deserialize to {expected:?}"
            );
        }
    }

    #[test]
    fn format_serde_yaml_unknown_format_error_carries_label_verbatim() {
        // The deserialize error surface carries the offending label
        // verbatim through ShikumiError::Parse's Display impl, routed
        // via serde::de::Error::custom. Idiom-peer of the same pin on
        // the typed-cube classifier surfaces — a manifest field
        // carrying `default_format: json` rejects on the serde side
        // with the offending substring named in the rendered
        // diagnostic, so the operator can localize the typo without
        // matching on the parse error variant.
        let sentinel = "__shikumi_unknown_format_sentinel__";
        let yaml = format!("\"{sentinel}\"\n");
        let result: Result<Format, _> = serde_yaml::from_str(&yaml);
        match result {
            Err(e) => {
                let rendered = format!("{e}");
                assert!(
                    rendered.contains(sentinel),
                    "serde YAML error must carry the unknown sentinel verbatim, got: {rendered}",
                );
            }
            Ok(other) => panic!("YAML carrying unknown format must reject, got {other:?}"),
        }
    }

    #[test]
    fn format_btreemap_emits_in_preference_order() {
        // The Ord derive's compounding payoff: a BTreeMap<Format, T>
        // keyed on the format axis iterates in declaration order
        // (Yaml < Toml < Lisp < Nix), which matches the documented
        // "preference order" reading on the Format doc comment. A
        // per-format resolve-cost telemetry rollup, a per-format
        // discovery-hit counter, or an attestation manifest's
        // per-format cardinality mix emits rows in preference order
        // without a hand-rolled comparator at the renderer.
        use std::collections::BTreeMap;
        let mut tally: BTreeMap<Format, u32> = BTreeMap::new();
        for &f in Format::ALL {
            tally.insert(f, 0);
        }
        let emitted: Vec<Format> = tally.keys().copied().collect();
        assert_eq!(
            emitted,
            Format::ALL.to_vec(),
            "BTreeMap<Format, _> key order must match Format::ALL (preference order)",
        );
    }

    #[test]
    fn format_metadata_name_uses_display_token() {
        // The shape `"<format-display>: <path>"` is uniform across every
        // variant — `Format::Display` is the single source of truth for
        // the leading token.
        for f in Format::ALL {
            let path = Path::new("/etc/app/app.x");
            let name = f.metadata_name(path);
            let expected = format!("{f}: /etc/app/app.x");
            assert_eq!(
                name, expected,
                "metadata_name must use the Display token for {f:?}"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_round_trips_for_shikumi_providers() {
        // Round-trip for every variant where has_shikumi_provider is true:
        // the prefix the resolver strips matches the prefix the provider emits.
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/srv/cfg/app.cfg");
            let name = f.metadata_name(path);
            let (recovered_format, rest) =
                Format::strip_metadata_name(&name).expect("round-trip must succeed");
            assert_eq!(
                recovered_format, *f,
                "strip must recover the format that emitted the name"
            );
            assert_eq!(
                rest, "/srv/cfg/app.cfg",
                "strip must surface the trailing path verbatim"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_rejects_non_shikumi_provider_prefixes() {
        // Variants without a shikumi-built provider must not be recognized
        // by the inverse — even though `metadata_name` produces a
        // syntactically valid `"<format>: <path>"` for them, the resolver
        // must not claim them, since their figment metadata uses
        // `Source::File` instead and is matched by a different rule
        // (path equality against `metadata.source`).
        for f in Format::ALL.iter().filter(|f| !f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/x.cfg"));
            assert!(
                Format::strip_metadata_name(&name).is_none(),
                "{f:?} has no shikumi-built provider; its `metadata_name` \
                 shape must not be recognized by the inverse resolver"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_rejects_unrelated_strings() {
        // Empty strings, plain paths, env-shaped names, and arbitrary
        // tokens must all fail to match.
        for name in [
            "",
            "/etc/app/app.yaml",
            "`MYAPP_` environment variable",
            "json: /etc/app.json",
            "lisp /etc/app.lisp", // missing colon
            "lisp:/etc/app.lisp", // missing space
        ] {
            assert!(
                Format::strip_metadata_name(name).is_none(),
                "unrelated metadata name `{name}` must not match"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_pins_correct_variant() {
        // The strip must pin the *specific* variant that emitted the
        // prefix, not just any shikumi-built variant.
        let lisp_name = Format::Lisp.metadata_name(Path::new("/a.lisp"));
        let (got_lisp, _) =
            Format::strip_metadata_name(&lisp_name).expect("lisp prefix must match");
        assert_eq!(got_lisp, Format::Lisp);

        let nix_name = Format::Nix.metadata_name(Path::new("/a.nix"));
        let (got_nix, _) = Format::strip_metadata_name(&nix_name).expect("nix prefix must match");
        assert_eq!(got_nix, Format::Nix);
    }

    #[test]
    fn format_strip_metadata_name_returns_borrow_into_input() {
        // The trailing path is a borrow into `name`, not a fresh
        // allocation — observable by checking that the returned `&str`
        // is a sub-slice of the input by pointer arithmetic.
        let name = Format::Lisp.metadata_name(Path::new("/srv/app.lisp"));
        let (_, rest) = Format::strip_metadata_name(&name).unwrap();
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let rest_start = rest.as_ptr() as usize;
        assert!(
            rest_start >= name_start && rest_start < name_end,
            "rest must be a sub-slice of name"
        );
    }

    #[test]
    fn format_metadata_name_uses_metadata_name_separator() {
        // The writer routes through `Format::METADATA_NAME_SEPARATOR`:
        // for every variant, `metadata_name(p)` splits as
        // `<as_str><METADATA_NAME_SEPARATOR><p.display()>` byte-for-byte.
        // A future edit to the separator that skipped either direction
        // would fail this pin — the metadata-name shape is a single
        // source of truth on both halves.
        for f in Format::ALL {
            let path = Path::new("/srv/app.cfg");
            let name = f.metadata_name(path);
            let after_token = name
                .strip_prefix(f.as_str())
                .unwrap_or_else(|| panic!("{f:?} metadata_name must start with the as_str token"));
            let after_sep = after_token
                .strip_prefix(Format::METADATA_NAME_SEPARATOR)
                .unwrap_or_else(|| {
                    panic!(
                        "{f:?} metadata_name must place METADATA_NAME_SEPARATOR \
                         immediately after the as_str token"
                    )
                });
            assert_eq!(
                after_sep,
                path.display().to_string(),
                "metadata_name must end in the path.display() region for {f:?}"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_routes_through_metadata_name_separator() {
        // The reader routes through the same
        // `Format::METADATA_NAME_SEPARATOR`: for every shikumi-built
        // variant, the trailing region `strip_metadata_name` surfaces
        // equals what a hand-written strip that consumes the shared
        // token+separator prefix would return. The two directions of
        // the metadata-name algebra now inherit the shape from one
        // constant, not from two duplicated `": "` literals that could
        // drift.
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/srv/app.cfg");
            let name = f.metadata_name(path);
            let (recovered, rest) =
                Format::strip_metadata_name(&name).expect("round-trip must succeed");
            let expected = name
                .strip_prefix(f.as_str())
                .and_then(|r| r.strip_prefix(Format::METADATA_NAME_SEPARATOR))
                .expect("shared token+separator prefix must strip");
            assert_eq!(recovered, *f);
            assert_eq!(
                rest, expected,
                "strip_metadata_name must consume exactly \
                 <as_str><METADATA_NAME_SEPARATOR> for {f:?}"
            );
        }
    }

    #[test]
    fn format_metadata_name_separator_is_two_byte_ascii_slice() {
        // The separator is a two-byte ASCII slice by design (colon +
        // space): `str::strip_prefix` against it is a byte-wise compare
        // that never allocates, which is exactly the property that
        // closes the second half of the per-call `String` drop in
        // `strip_metadata_name` (the first half being the
        // alias-canonical-name allocation, dropped by routing through
        // `Self::as_str` as `&'static str`).
        assert_eq!(Format::METADATA_NAME_SEPARATOR, ": ");
        assert_eq!(Format::METADATA_NAME_SEPARATOR.len(), 2);
        assert!(Format::METADATA_NAME_SEPARATOR.is_ascii());
    }

    // ---- FormatMetadataTag / parse_metadata_tag tests ----

    #[test]
    fn parse_metadata_tag_round_trips_for_shikumi_providers() {
        // For every shikumi-provider variant, the typed envelope recovers
        // both the format that emitted the name and the trailing path
        // (already typed as `&Path`, no `Path::new` at the call site).
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/srv/cfg/app.cfg");
            let name = f.metadata_name(path);
            let tag = Format::parse_metadata_tag(&name).expect("round-trip must succeed");
            assert_eq!(
                tag.format, *f,
                "envelope must recover the format that emitted the name"
            );
            assert_eq!(
                tag.path, path,
                "envelope must surface the trailing path verbatim, as &Path"
            );
        }
    }

    #[test]
    fn parse_metadata_tag_rejects_non_shikumi_provider_prefixes() {
        // Same `None` contract as `strip_metadata_name`: variants without
        // a shikumi-built provider must not be recognized — even though
        // `metadata_name` produces a syntactically valid string for them.
        for f in Format::ALL.iter().filter(|f| !f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/x.cfg"));
            assert!(
                Format::parse_metadata_tag(&name).is_none(),
                "{f:?} has no shikumi-built provider; the typed envelope \
                 must mirror `strip_metadata_name`'s rejection"
            );
        }
    }

    #[test]
    fn parse_metadata_tag_rejects_unrelated_strings() {
        for name in [
            "",
            "/etc/app/app.yaml",
            "`MYAPP_` environment variable",
            "json: /etc/app.json",
            "lisp /etc/app.lisp", // missing colon
            "lisp:/etc/app.lisp", // missing space
        ] {
            assert!(
                Format::parse_metadata_tag(name).is_none(),
                "unrelated metadata name `{name}` must not match the typed envelope"
            );
        }
    }

    #[test]
    fn parse_metadata_tag_pins_correct_variant() {
        let lisp_name = Format::Lisp.metadata_name(Path::new("/a.lisp"));
        let lisp_tag = Format::parse_metadata_tag(&lisp_name).expect("lisp prefix must match");
        assert_eq!(lisp_tag.format, Format::Lisp);
        assert_eq!(lisp_tag.path, Path::new("/a.lisp"));

        let nix_name = Format::Nix.metadata_name(Path::new("/a.nix"));
        let nix_tag = Format::parse_metadata_tag(&nix_name).expect("nix prefix must match");
        assert_eq!(nix_tag.format, Format::Nix);
        assert_eq!(nix_tag.path, Path::new("/a.nix"));
    }

    #[test]
    fn parse_metadata_tag_path_borrows_into_input() {
        // The path slice in the envelope must be a sub-borrow of the
        // input metadata-name string, not a fresh allocation. Verifies
        // that `Path::new(rest)` preserves the underlying byte borrow.
        let name = Format::Nix.metadata_name(Path::new("/srv/app.nix"));
        let tag = Format::parse_metadata_tag(&name).expect("nix prefix must match");
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let path_start = tag.path.as_os_str().as_encoded_bytes().as_ptr() as usize;
        assert!(
            path_start >= name_start && path_start < name_end,
            "envelope path must borrow into input metadata-name"
        );
    }

    #[test]
    fn parse_metadata_tag_agrees_with_strip_metadata_name() {
        // Cross-API contract: the envelope's `(format, path)` pair must
        // match the lower-level tuple `(format, &str)` byte-for-byte
        // (modulo `Path` vs `&str` typing) on every input that matches.
        for name in [
            Format::Lisp.metadata_name(Path::new("/a.lisp")),
            Format::Nix.metadata_name(Path::new("/etc/app/app.nix")),
            Format::Lisp.metadata_name(Path::new("/srv/cfg/x.lisp")),
        ] {
            let tag = Format::parse_metadata_tag(&name).expect("envelope must match");
            let (legacy_fmt, legacy_rest) =
                Format::strip_metadata_name(&name).expect("legacy must match");
            assert_eq!(tag.format, legacy_fmt, "format must agree across APIs");
            assert_eq!(
                tag.path,
                Path::new(legacy_rest),
                "path must agree across APIs (envelope is &Path; legacy is &str)"
            );
        }
        // None inputs agree too.
        for name in ["", "/etc/app.yaml", "envvar `X_` typo"] {
            assert!(Format::parse_metadata_tag(name).is_none());
            assert!(Format::strip_metadata_name(name).is_none());
        }
    }

    #[test]
    fn format_metadata_tag_is_copy_and_hashable() {
        // Trait-bounds parity with the sibling typed primitives
        // (`EnvMetadataTag`, `FigmentSourceTag`, `AttributionRule`).
        use std::collections::HashSet;
        let name_a = Format::Lisp.metadata_name(Path::new("/a.lisp"));
        let name_b = Format::Nix.metadata_name(Path::new("/b.nix"));
        let tag_a = Format::parse_metadata_tag(&name_a).unwrap();
        let tag_b = Format::parse_metadata_tag(&name_b).unwrap();
        // Copy: rebind without move.
        let tag_a2 = tag_a;
        let tag_a3 = tag_a;
        assert_eq!(tag_a, tag_a2);
        assert_eq!(tag_a2, tag_a3);
        // Hash + Eq: distinct envelopes hash distinctly.
        let mut set = HashSet::new();
        set.insert(tag_a);
        set.insert(tag_a); // duplicate
        set.insert(tag_b);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn format_metadata_tag_ord_matches_format_then_path_lex() {
        // The derived total order is declaration-order lex over the
        // struct's fields: `format` outer (inheriting Format::ALL's
        // declaration order, b56b121), `path` inner (Path's native
        // lex). Pin both legs.
        let path_a = Path::new("/a");
        let path_b = Path::new("/b");
        // Outer leg: format axis dominates path axis when formats differ.
        // Lisp < Nix in declaration order, so (Lisp, /b) < (Nix, /a).
        let lisp_b = FormatMetadataTag {
            format: Format::Lisp,
            path: path_b,
        };
        let nix_a = FormatMetadataTag {
            format: Format::Nix,
            path: path_a,
        };
        assert!(
            lisp_b < nix_a,
            "format axis must dominate path axis: (Lisp,/b) < (Nix,/a)"
        );
        // Inner leg: with the same format, path lex orders the pair.
        // /a < /b in lex order, so (Lisp, /a) < (Lisp, /b).
        let lisp_a = FormatMetadataTag {
            format: Format::Lisp,
            path: path_a,
        };
        assert!(
            lisp_a < lisp_b,
            "with equal format, path lex must order: (Lisp,/a) < (Lisp,/b)"
        );
        // PartialOrd agrees with Ord (the derive guarantees this).
        assert_eq!(lisp_a.cmp(&lisp_b), std::cmp::Ordering::Less);
        assert_eq!(lisp_a.partial_cmp(&lisp_b), Some(std::cmp::Ordering::Less));
        // Reflexivity.
        assert_eq!(lisp_a.cmp(&lisp_a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn format_metadata_tag_display_matches_format_metadata_name() {
        // The Display impl on the typed envelope must agree pointwise
        // with `Format::metadata_name` on the same `(format, path)`
        // pair, byte-for-byte. This is the cross-API contract that
        // pins both surfaces in lockstep — if either re-renders the
        // `<format>: <path>` shape differently, this test catches it.
        // Sweep over every Format variant (not just shikumi-provider
        // ones — `metadata_name` is total over Format::ALL).
        for &f in Format::ALL {
            for path in [
                Path::new("/a"),
                Path::new("/etc/app/app.cfg"),
                Path::new("/srv/cfg/x.lisp"),
                Path::new("relative/path"),
            ] {
                let tag = FormatMetadataTag { format: f, path };
                assert_eq!(
                    tag.to_string(),
                    f.metadata_name(path),
                    "Display must match Format::metadata_name pointwise for {f:?} at {path:?}"
                );
            }
        }
    }

    #[test]
    fn format_write_metadata_name_matches_format_metadata_name() {
        // The alloc-free `write_metadata_name` write-side must emit the
        // exact same bytes as the allocating `metadata_name` surface for
        // every `(Format, Path)` pair. This is the load-bearing pin on
        // the shared-substrate lift: both `metadata_name` (via a String
        // buffer) and `impl fmt::Display for FormatMetadataTag<'_>` (via
        // a `fmt::Formatter`) now route through `write_metadata_name`,
        // so a future change to the emission shape lands at ONE named
        // site and every consumer inherits it by construction. If this
        // test fails, the write-side helper and the allocating façade
        // have drifted — likely because one was edited without the
        // other, exactly the failure mode the helper exists to
        // eliminate. Sweeps every Format variant (the helper is total
        // over Format::ALL, same as `metadata_name`).
        for &f in Format::ALL {
            for path in [
                Path::new("/a"),
                Path::new("/etc/app/app.cfg"),
                Path::new("/srv/cfg/x.lisp"),
                Path::new("relative/path"),
                Path::new(""),
            ] {
                let mut buf = String::new();
                f.write_metadata_name(&mut buf, path)
                    .expect("writing to a String cannot fail");
                assert_eq!(
                    buf,
                    f.metadata_name(path),
                    "write_metadata_name must match metadata_name pointwise for {f:?} at {path:?}"
                );
            }
        }
    }

    #[test]
    fn format_metadata_tag_display_routes_through_write_metadata_name() {
        // Direct pin on the Display → write_metadata_name routing: the
        // Display impl must emit exactly what the write-side helper
        // emits for the same `(format, path)` pair. This is the third
        // vertex of the byte-equality triangle
        // (`Display` ≡ `metadata_name` ≡ `write_metadata_name`); the
        // pre-existing `format_metadata_tag_display_matches_format_metadata_name`
        // pins the top edge, `format_write_metadata_name_matches_format_metadata_name`
        // pins the right edge, and this test pins the left edge so any
        // one drift becomes visible without waiting on the transitive
        // chain to notice. Sweeps every Format variant (both
        // shikumi-provider and figment-builtin — the write-side is
        // total, same as `metadata_name`).
        for &f in Format::ALL {
            for path in [
                Path::new("/a"),
                Path::new("/etc/app/app.cfg"),
                Path::new("/srv/cfg/x.lisp"),
                Path::new("relative/path"),
            ] {
                let tag = FormatMetadataTag { format: f, path };
                let mut buf = String::new();
                f.write_metadata_name(&mut buf, path)
                    .expect("writing to a String cannot fail");
                assert_eq!(
                    tag.to_string(),
                    buf,
                    "Display must route through write_metadata_name for {f:?} at {path:?}"
                );
            }
        }
    }

    #[test]
    fn format_metadata_tag_display_parse_round_trips_for_shikumi_providers() {
        // For every shikumi-provider variant, rendering a tag through
        // Display and parsing the result back through
        // `Format::parse_metadata_tag` recovers a structurally equal
        // envelope. Pins the (render, parse) duality at the envelope's
        // own surface.
        for &f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            for path in [Path::new("/a.lisp"), Path::new("/etc/app/app.nix")] {
                let tag = FormatMetadataTag { format: f, path };
                let rendered = tag.to_string();
                let parsed = Format::parse_metadata_tag(&rendered)
                    .expect("render/parse round-trip must succeed for shikumi-provider tag");
                assert_eq!(
                    parsed.format, tag.format,
                    "round-trip must recover the format for {f:?} at {path:?}"
                );
                assert_eq!(
                    parsed.path, tag.path,
                    "round-trip must recover the path for {f:?} at {path:?}"
                );
            }
        }
    }

    #[test]
    fn format_metadata_tag_btreemap_emits_in_format_then_path_lex_order() {
        // The compounding payoff of the Ord derive: a BTreeMap keyed on
        // the typed envelope iterates in (format, path) lex order
        // pointwise — no hand-rolled comparator at the renderer.
        use std::collections::BTreeMap;
        let tags = [
            FormatMetadataTag {
                format: Format::Nix,
                path: Path::new("/z"),
            },
            FormatMetadataTag {
                format: Format::Lisp,
                path: Path::new("/b"),
            },
            FormatMetadataTag {
                format: Format::Lisp,
                path: Path::new("/a"),
            },
            FormatMetadataTag {
                format: Format::Nix,
                path: Path::new("/a"),
            },
        ];
        let mut map = BTreeMap::new();
        for (i, tag) in tags.iter().enumerate() {
            map.insert(*tag, i);
        }
        let iter_order: Vec<_> = map.keys().copied().collect();
        // Expected: (Lisp,/a) < (Lisp,/b) < (Nix,/a) < (Nix,/z).
        let expected = vec![
            FormatMetadataTag {
                format: Format::Lisp,
                path: Path::new("/a"),
            },
            FormatMetadataTag {
                format: Format::Lisp,
                path: Path::new("/b"),
            },
            FormatMetadataTag {
                format: Format::Nix,
                path: Path::new("/a"),
            },
            FormatMetadataTag {
                format: Format::Nix,
                path: Path::new("/z"),
            },
        ];
        assert_eq!(
            iter_order, expected,
            "BTreeMap<FormatMetadataTag, _> must emit in (format, path) lex order"
        );
    }

    #[test]
    fn format_metadata_tag_try_from_round_trips_for_shikumi_providers() {
        // Idiom-peer of `parse_metadata_tag_round_trips_for_shikumi_providers`
        // at the envelope's own TryFrom surface: a consumer holding a
        // `&str` can write `FormatMetadataTag::try_from(name)?` without
        // reaching into `Format`.
        for &f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/srv/cfg/app.cfg");
            let name = f.metadata_name(path);
            let tag = FormatMetadataTag::try_from(name.as_str())
                .expect("TryFrom round-trip must succeed for shikumi-provider name");
            assert_eq!(
                tag.format, f,
                "TryFrom must recover the format that emitted the name for {f:?}"
            );
            assert_eq!(
                tag.path, path,
                "TryFrom must surface the trailing path verbatim, as &Path for {f:?}"
            );
        }
    }

    #[test]
    fn format_metadata_tag_try_from_rejects_non_shikumi_provider_prefixes() {
        // Same Err contract as `parse_metadata_tag`'s `None`: variants
        // without a shikumi-built provider must not be recognized — even
        // though `metadata_name` produces a syntactically valid string
        // for them. The Err arm carries the offending input verbatim.
        for &f in Format::ALL.iter().filter(|f| !f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/x.cfg"));
            let err = FormatMetadataTag::try_from(name.as_str())
                .expect_err("non-shikumi-provider name must reject");
            match err {
                ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix { input } => {
                    assert_eq!(input, name, "Err must carry the offending input verbatim");
                }
            }
        }
    }

    #[test]
    fn format_metadata_tag_try_from_rejects_unrelated_strings_with_input_verbatim() {
        // Unrelated metadata-name strings reject with the `input` field
        // carrying the offending input verbatim into the rendered
        // Display message — the verbatim-substring rejection discipline
        // established by `ParseFormatCoordinatesError`.
        for name in [
            "",
            "/etc/app/app.yaml",
            "`MYAPP_` environment variable",
            "json: /etc/app.json",
            "lisp /etc/app.lisp", // missing colon
            "lisp:/etc/app.lisp", // missing space after colon
        ] {
            let err =
                FormatMetadataTag::try_from(name).expect_err("unrelated metadata-name must reject");
            match &err {
                ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix { input } => {
                    assert_eq!(input, name, "Err must carry input verbatim for {name:?}");
                }
            }
            // The rendered Display message also embeds the offending
            // input verbatim (via the `{input:?}` debug-format escape),
            // so an operator-facing renderer doesn't need to scrape the
            // original input from context.
            let rendered = err.to_string();
            assert!(
                rendered.contains(&format!("{name:?}")),
                "Display must embed the offending input verbatim: {rendered}"
            );
        }
    }

    #[test]
    fn format_metadata_tag_try_from_path_borrows_into_input() {
        // The path slice in the envelope must be a sub-borrow of the
        // input `&str`, not a fresh allocation — the `&'a str` →
        // `FormatMetadataTag<'a>` lifetime threading preserves the
        // underlying byte borrow through TryFrom. Mirror of
        // `parse_metadata_tag_path_borrows_into_input` on the TryFrom
        // surface.
        let name = Format::Nix.metadata_name(Path::new("/srv/app.nix"));
        let tag =
            FormatMetadataTag::try_from(name.as_str()).expect("nix prefix must match via TryFrom");
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let path_start = tag.path.as_os_str().as_encoded_bytes().as_ptr() as usize;
        assert!(
            path_start >= name_start && path_start < name_end,
            "TryFrom-produced envelope path must borrow into input metadata-name"
        );
    }

    #[test]
    fn format_metadata_tag_try_from_agrees_with_parse_metadata_tag() {
        // Cross-API contract: `FormatMetadataTag::try_from(name)` and
        // `Format::parse_metadata_tag(name)` must agree on every input
        // (Some/Ok on matches, None/Err on non-matches, structurally
        // equal envelopes on matches).
        let shikumi_names = [
            Format::Lisp.metadata_name(Path::new("/a.lisp")),
            Format::Nix.metadata_name(Path::new("/etc/app/app.nix")),
        ];
        for name in &shikumi_names {
            let try_from_tag = FormatMetadataTag::try_from(name.as_str()).unwrap();
            let parse_tag = Format::parse_metadata_tag(name).unwrap();
            assert_eq!(
                try_from_tag, parse_tag,
                "TryFrom and parse_metadata_tag must agree on matches"
            );
        }
        for name in ["", "/etc/app.yaml", "envvar `X_` typo"] {
            assert!(FormatMetadataTag::try_from(name).is_err());
            assert!(Format::parse_metadata_tag(name).is_none());
        }
    }

    #[test]
    fn parse_format_metadata_tag_error_is_std_error() {
        // Trait-bounds parity with `ParseFormatCoordinatesError`: the
        // typed rejection enum implements `std::error::Error` so it
        // composes through `Box<dyn Error>` and `anyhow::Error` at
        // consumer sites.
        fn assert_std_error<E: std::error::Error>(_: &E) {}
        let err = ParseFormatMetadataTagError::NoMatchingShikumiProviderPrefix {
            input: "x".to_owned(),
        };
        assert_std_error(&err);
    }

    // ---- FormatProvenance / Format::provenance typed-primitive tests ----

    #[test]
    fn format_provenance_classifies_each_variant() {
        // Pin the (variant -> provenance) map at the type level. Today's
        // partition: Yaml/Toml -> FigmentBuiltin; Lisp/Nix -> ShikumiBuilt.
        assert_eq!(Format::Yaml.provenance(), FormatProvenance::FigmentBuiltin);
        assert_eq!(Format::Toml.provenance(), FormatProvenance::FigmentBuiltin);
        assert_eq!(Format::Lisp.provenance(), FormatProvenance::ShikumiBuilt);
        assert_eq!(Format::Nix.provenance(), FormatProvenance::ShikumiBuilt);
    }

    #[test]
    fn format_provenance_projection_is_const_callable() {
        // Weld the const-callability of the (format → provenance)
        // projection `Format::provenance` at compile time. Mirrors the
        // shape of `attribution_rule_layer_kind_is_const_callable`
        // (commit `52c4a20`) / `config_tier_name_is_const_callable`
        // (commit `29a2f34`) on the shikumi-crate-wide const-callability
        // discipline over the closed-primitive projection surface: a
        // compile-time-known `Format` now projects into `FormatProvenance`
        // at compile time too — so a `static` per-format provenance
        // table wired through the projection stays wired to compile-time
        // evaluation, and the sibling per-variant boolean projections
        // on the same axis (`Format::is_yaml`, …, `Format::is_blue`,
        // all const since their landing) meet this closed-enum
        // projection at the same const-callability altitude.
        //
        // Five `const` bindings — one per `Format` variant — route each
        // payload-free variant through the const-fn projection in
        // const position. The moment `Format::provenance` loses its
        // const-ness (a future edit that reaches for a non-const
        // helper — a lookup through a runtime table, a `String`-shaped
        // intermediate, an allocator on the mapping path — inside the
        // exhaustive match) one of the five `const` welds below fails
        // to compile at THAT line before the drift can reach
        // downstream consumers that assumed const-ness through the
        // projection, and the five pointwise pins catch a future edit
        // that shifted the format → provenance mapping off the
        // (figment-builtin × shikumi-built) partition before it
        // drifts through observers that read the projection.
        const YAML: FormatProvenance = Format::Yaml.provenance();
        const TOML: FormatProvenance = Format::Toml.provenance();
        const LISP: FormatProvenance = Format::Lisp.provenance();
        const NIX: FormatProvenance = Format::Nix.provenance();
        const BLUE: FormatProvenance = Format::Blue.provenance();

        assert_eq!(YAML, FormatProvenance::FigmentBuiltin);
        assert_eq!(TOML, FormatProvenance::FigmentBuiltin);
        assert_eq!(LISP, FormatProvenance::ShikumiBuilt);
        assert_eq!(NIX, FormatProvenance::ShikumiBuilt);
        assert_eq!(BLUE, FormatProvenance::ShikumiBuilt);

        // Cross-check: the const-fn projection stays pointwise equal
        // on every variant in `Format::ALL` to the runtime-side
        // `format.provenance()` call — the const-context weld only
        // exercises the five variants named at const-binding sites,
        // but the runtime pin threads the full closed list through
        // the same projection to catch a future variant landing
        // whose const-context weld was forgotten upstream.
        for (format, expected) in [
            (Format::Yaml, YAML),
            (Format::Toml, TOML),
            (Format::Lisp, LISP),
            (Format::Nix, NIX),
            (Format::Blue, BLUE),
        ] {
            assert_eq!(format.provenance(), expected, "format {format:?}");
        }
    }

    #[test]
    fn format_provenance_partitions_every_variant() {
        // Every Format variant must classify into exactly one provenance.
        // The exhaustive match below is the compiler-enforced contract:
        // adding a Format variant breaks this test until the new variant
        // is wired into `Format::provenance` (which is itself an
        // exhaustive match — so the contract closes both ways).
        for f in Format::ALL {
            // The provenance accessor is total — never panics, never None.
            let p = f.provenance();
            // Pin the partition: every variant lands on one of the two
            // recognized provenances.
            match p {
                FormatProvenance::FigmentBuiltin | FormatProvenance::ShikumiBuilt => {}
            }
            // Forward + inverse predicate composition.
            assert_eq!(p.is_shikumi_built(), p == FormatProvenance::ShikumiBuilt);
            assert_eq!(
                p.is_figment_builtin(),
                p == FormatProvenance::FigmentBuiltin
            );
            assert_ne!(
                p.is_shikumi_built(),
                p.is_figment_builtin(),
                "provenance is binary; the two predicates must disagree pointwise"
            );
        }
    }

    #[test]
    fn format_provenance_agrees_with_has_shikumi_provider() {
        // The closed-enum projection and the legacy bool predicate are
        // the same function modulo the bool/enum lift. Every variant must
        // agree pointwise — pinned across all of Format::ALL.
        for f in Format::ALL {
            assert_eq!(
                f.has_shikumi_provider(),
                f.provenance() == FormatProvenance::ShikumiBuilt,
                "has_shikumi_provider and provenance must agree on {f:?}",
            );
            assert_eq!(
                f.has_shikumi_provider(),
                f.provenance().is_shikumi_built(),
                "has_shikumi_provider and provenance().is_shikumi_built() \
                 must agree on {f:?}",
            );
        }
    }

    #[test]
    fn format_provenance_file_attribution_rule_pins_each_provenance() {
        // The (provenance -> file-rule) projection: FigmentBuiltin
        // attributes file failures via FileBySource (path equality on
        // metadata.source); ShikumiBuilt attributes via FileByMetadataName
        // (path equality on parsed metadata.name). The structural law
        // pinned at the type level.
        assert_eq!(
            FormatProvenance::FigmentBuiltin.file_attribution_rule(),
            crate::AttributionRule::FileBySource,
        );
        assert_eq!(
            FormatProvenance::ShikumiBuilt.file_attribution_rule(),
            crate::AttributionRule::FileByMetadataName,
        );
    }

    #[test]
    fn format_provenance_file_attribution_rule_layer_kind_is_always_file() {
        // The (provenance -> file-rule -> layer-kind) projection collapses
        // to ConfigSourceKind::File for every provenance — the rule space
        // for file-axis attributions sits entirely on the file layer-kind.
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                p.file_attribution_rule().layer_kind(),
                crate::ConfigSourceKind::File,
                "{p:?}'s file-attribution rule must attribute to a File layer",
            );
        }
    }

    #[test]
    fn format_provenance_file_attribution_axis_mirrors_rule_axis() {
        // The convenience accessor is a thin lift of
        // `file_attribution_rule().metadata_axis()`. Every provenance
        // must agree pointwise.
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                p.file_attribution_axis(),
                p.file_attribution_rule().metadata_axis(),
                "file_attribution_axis must mirror rule.metadata_axis on {p:?}",
            );
        }
        // And pin the named axis per provenance.
        assert_eq!(
            FormatProvenance::FigmentBuiltin.file_attribution_axis(),
            crate::AttributionAxis::MetadataSource,
        );
        assert_eq!(
            FormatProvenance::ShikumiBuilt.file_attribution_axis(),
            crate::AttributionAxis::MetadataName,
        );
    }

    #[test]
    fn format_provenance_file_attribution_rule_is_always_exact() {
        // Both file-axis rules in today's resolver are equality-based
        // (path equality on either metadata.source or the parsed
        // metadata.name). The (provenance -> file-rule -> confidence)
        // projection collapses to AttributionConfidence::Exact for every
        // provenance — file-axis attribution is high-confidence by
        // construction in this resolver.
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                p.file_attribution_rule().confidence(),
                crate::AttributionConfidence::Exact,
                "{p:?}'s file-axis attribution must be Exact",
            );
        }
    }

    #[test]
    fn format_provenance_is_copy_and_hashable() {
        // Trait-bounds parity with the sibling typescape primitives
        // (AttributionConfidence, AttributionAxis, ConfigSourceKind,
        // ShikumiErrorKind, FieldPathLocalization).
        use std::collections::HashSet;
        let p = FormatProvenance::FigmentBuiltin;
        // Copy: rebind without move.
        let p2 = p;
        let p3 = p;
        assert_eq!(p, p2);
        assert_eq!(p2, p3);
        // Hash + Eq: only two distinct values exist.
        let mut set = HashSet::new();
        for f in Format::ALL {
            set.insert(f.provenance());
        }
        for prov in FormatProvenance::ALL.iter().copied() {
            // duplicate of the same value already inserted via
            // Format::provenance; pins the set-collapse property.
            set.insert(prov);
        }
        assert_eq!(
            set.len(),
            FormatProvenance::ALL.len(),
            "the partition has exactly FormatProvenance::ALL.len() cells today",
        );
    }

    // ---- FormatProvenance::ALL tests ----

    #[test]
    fn format_provenance_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every variant appears
        // at most once. Pins the "no double-listed cell" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost provenance contributing twice to a partition tally.
        use std::collections::HashSet;
        let unique: HashSet<FormatProvenance> = FormatProvenance::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            FormatProvenance::ALL.len(),
            "FormatProvenance::ALL must contain no duplicates",
        );
    }

    #[test]
    fn format_provenance_all_covers_every_provenance_over_format_all() {
        // Cross-axis cover law: every provenance produced by
        // `Format::provenance` over `Format::ALL` must appear in
        // `FormatProvenance::ALL`, and `FormatProvenance::ALL` must
        // contain no extras. The mutual-cover statement proves ALL is
        // in 1-1 correspondence with the provenance partition the
        // typescape recognizes — peer to the
        // `shikumi_error_kind_all_covers_every_constructed_variant`,
        // `attribution_rule_all_covers_every_recognized_variant`, and
        // `field_path_localization_all_covers_every_constructed_localization`
        // mutual-cover assertions on their respective axes.
        use std::collections::HashSet;
        let produced: HashSet<FormatProvenance> = Format::ALL
            .iter()
            .copied()
            .map(Format::provenance)
            .collect();
        let listed: HashSet<FormatProvenance> = FormatProvenance::ALL.iter().copied().collect();
        assert_eq!(
            produced, listed,
            "FormatProvenance::ALL must equal the provenance set produced by Format::provenance over Format::ALL",
        );
    }

    #[test]
    fn format_provenance_all_cardinality_matches_format_provenance_partition() {
        // Stronger cardinality statement: the (Format -> provenance)
        // partition over Format::ALL has exactly FormatProvenance::ALL
        // distinct cells. A future provenance variant landing forces
        // both an arm in `Format::provenance` (compile-time, exhaustive
        // match on the format variant space) and an extension of ALL
        // (test-time); this assertion fails until ALL is extended in
        // lockstep, catching forgotten ALL updates.
        use std::collections::HashSet;
        let distinct: HashSet<FormatProvenance> = Format::ALL
            .iter()
            .copied()
            .map(Format::provenance)
            .collect();
        assert_eq!(
            FormatProvenance::ALL.len(),
            distinct.len(),
            "FormatProvenance::ALL.len() must equal the distinct provenance count over Format::ALL",
        );
    }

    #[test]
    fn format_provenance_all_iterates_in_declaration_order() {
        // The constant lists variants in the same order as the enum's
        // declaration (FigmentBuiltin, ShikumiBuilt). Iteration order
        // is observable — consumers (alerting policies, dashboards,
        // structured-diagnostics legends) that want a stable ordering
        // (e.g. source-axis attribution before name-axis attribution
        // in confidence-ranked reports) can route on it.
        assert_eq!(
            FormatProvenance::ALL,
            &[
                FormatProvenance::FigmentBuiltin,
                FormatProvenance::ShikumiBuilt,
            ],
            "ALL must list variants in declaration order",
        );
    }

    #[test]
    fn format_provenance_all_predicates_partition_pointwise() {
        // The is_figment_builtin / is_shikumi_built sibling-predicate
        // pair partitions ALL — exactly one predicate must hold per
        // cell, no cell may be both, none may be neither. Pins the
        // partition contract that a future variant landing must declare
        // its sibling-predicate side in lockstep.
        for p in FormatProvenance::ALL.iter().copied() {
            assert_ne!(
                p.is_figment_builtin(),
                p.is_shikumi_built(),
                "provenance {p:?} must be exactly one of figment-builtin / shikumi-built",
            );
        }
    }

    #[test]
    fn format_provenance_predicates_are_const_callable() {
        // Compile-time weld: the two sibling per-variant predicates on
        // `FormatProvenance` are `const`-callable, matching the
        // `const`-ness of the peer per-variant predicates on the
        // `Format` axis (`Format::is_yaml`, …, `Format::is_blue`,
        // `Format::is_feature_gated`, `Format::is_always_available`)
        // and on the `AttributionRule` / `AttributionConfidence` /
        // `AttributionAxis` axes (`is_exact`, `is_fallback`,
        // `is_file_by_source`, …). A drop of `const` at either sibling
        // fails this test to compile. Peer of
        // `format_is_feature_gated_is_const_callable`.
        const fn call_figment_builtin(p: FormatProvenance) -> bool {
            p.is_figment_builtin()
        }
        const fn call_shikumi_built(p: FormatProvenance) -> bool {
            p.is_shikumi_built()
        }
        // Const-evaluated at compile time on both variants.
        const FB_FB: bool = call_figment_builtin(FormatProvenance::FigmentBuiltin);
        const FB_SB: bool = call_figment_builtin(FormatProvenance::ShikumiBuilt);
        const SB_FB: bool = call_shikumi_built(FormatProvenance::FigmentBuiltin);
        const SB_SB: bool = call_shikumi_built(FormatProvenance::ShikumiBuilt);
        assert!(FB_FB);
        assert!(!FB_SB);
        assert!(!SB_FB);
        assert!(SB_SB);
    }

    #[test]
    fn format_provenance_all_file_attribution_rule_is_injective() {
        // The (provenance -> file-rule) projection is a bijection over
        // FormatProvenance::ALL: distinct provenances map to distinct
        // file-axis attribution rules. Pins the contract that the
        // resolver's file-axis dispatch table has one rule per
        // provenance — adding a future provenance variant landing the
        // same file-rule as an existing one would silently merge
        // attribution provenance at runtime, and this test fails
        // before that ships.
        use std::collections::HashSet;
        let rules: HashSet<crate::AttributionRule> = FormatProvenance::ALL
            .iter()
            .copied()
            .map(FormatProvenance::file_attribution_rule)
            .collect();
        assert_eq!(
            rules.len(),
            FormatProvenance::ALL.len(),
            "file_attribution_rule must be injective over FormatProvenance::ALL",
        );
    }

    #[test]
    fn format_provenance_all_file_attribution_axis_spans_both_metadata_axes() {
        // The (provenance -> file-axis) projection over
        // FormatProvenance::ALL spans both MetadataSource (from
        // FigmentBuiltin) and MetadataName (from ShikumiBuilt). Pins
        // the structural law that the typed provenance partition is
        // not collapsed onto a single metadata axis — diagnostics that
        // weight name-axis attribution as more brittle than source-axis
        // attribution can rely on both axes appearing in the provenance
        // surface. Durable under future variant growth: this is a
        // ≥-style coverage statement, not an injectivity claim.
        use std::collections::HashSet;
        let axes: HashSet<crate::AttributionAxis> = FormatProvenance::ALL
            .iter()
            .copied()
            .map(FormatProvenance::file_attribution_axis)
            .collect();
        assert!(
            axes.contains(&crate::AttributionAxis::MetadataSource),
            "FormatProvenance::ALL must produce a MetadataSource file-axis attribution"
        );
        assert!(
            axes.contains(&crate::AttributionAxis::MetadataName),
            "FormatProvenance::ALL must produce a MetadataName file-axis attribution"
        );
    }

    #[test]
    fn format_provenance_file_attribution_rule_agrees_with_resolver_pointwise() {
        // The structural law: for every Format with a file-axis
        // attribution path, the (provenance -> file-rule) projection
        // must agree byte-for-byte with the rule the failing-source
        // resolver fires for a real per-value extract failure of that
        // format. Pins the typed projection against the runtime resolver
        // end-to-end — so a future drift in either side is caught
        // before it reaches users.
        use crate::ConfigSource;
        use crate::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        // Yaml: figment-builtin path; resolver must fire FileBySource.
        let dir = tempfile::TempDir::new().unwrap();
        let yaml = dir.path().join("provenance_yaml.yaml");
        std::fs::write(&yaml, "count: not_a_number\n").unwrap();
        let yaml_err = ProviderChain::new()
            .with_file(&yaml)
            .extract::<Cfg>()
            .unwrap_err();
        let yaml_attr = yaml_err
            .failing_attribution()
            .expect("yaml extract must attribute");
        assert_eq!(
            yaml_attr.rule,
            Format::Yaml.provenance().file_attribution_rule(),
            "Yaml's resolver-fired rule must equal its provenance-projected rule",
        );
        // Toml: figment-builtin path; same projection.
        let toml = dir.path().join("provenance_toml.toml");
        std::fs::write(&toml, "count = \"not_a_number\"\n").unwrap();
        let toml_err = ProviderChain::new()
            .with_file(&toml)
            .extract::<Cfg>()
            .unwrap_err();
        let toml_attr = toml_err
            .failing_attribution()
            .expect("toml extract must attribute");
        assert_eq!(
            toml_attr.rule,
            Format::Toml.provenance().file_attribution_rule(),
            "Toml's resolver-fired rule must equal its provenance-projected rule",
        );
        // Both must additionally pin to ConfigSource::File (not env, not
        // defaults) under their projected layer-kind.
        for attr in [&yaml_attr, &toml_attr] {
            assert!(matches!(attr.source, ConfigSource::File(_)));
            assert_eq!(
                attr.rule.layer_kind(),
                attr.source.kind(),
                "rule layer_kind must agree with source kind",
            );
        }
    }

    // ---- FormatProvenance::formats fiber tests ----

    #[test]
    fn format_provenance_formats_is_fiber_of_format_provenance() {
        // The fiber law: for every (f, p) in Format::ALL × FormatProvenance::ALL,
        // `f ∈ p.formats() ⇔ Format::provenance(f) == p`. Pinned over the
        // full 4 × 2 = 8-cell product to catch any drift between the
        // forward map and the closed fiber slice.
        for f in Format::ALL.iter().copied() {
            for p in FormatProvenance::ALL.iter().copied() {
                assert_eq!(
                    p.formats().contains(&f),
                    f.provenance() == p,
                    "fiber law: f.provenance() == p iff p.formats() contains f, on ({f:?}, {p:?})",
                );
            }
        }
    }

    #[test]
    fn format_provenance_formats_partition_format_all_disjointly() {
        // The fibers partition Format::ALL into FormatProvenance::ALL.len()
        // disjoint, exhaustive slices. The disjoint-union of `p.formats()`
        // over `FormatProvenance::ALL` equals `Format::ALL` as a set, and
        // no format appears in more than one fiber. Pins the partition law
        // independent of the fiber law: the disjointness and exhaustiveness
        // both fail at this single site if the slices drift.
        use std::collections::HashSet;
        let mut union: HashSet<Format> = HashSet::new();
        let mut total_count = 0_usize;
        for p in FormatProvenance::ALL.iter().copied() {
            for f in p.formats().iter().copied() {
                assert!(
                    union.insert(f),
                    "format {f:?} appears in more than one fiber (provenance {p:?})",
                );
                total_count += 1;
            }
        }
        assert_eq!(
            total_count,
            Format::ALL.len(),
            "the disjoint union of fibers must cover Format::ALL with no duplicates",
        );
        let expected: HashSet<Format> = Format::ALL.iter().copied().collect();
        assert_eq!(
            union, expected,
            "the disjoint union of fibers must equal Format::ALL as a set",
        );
    }

    #[test]
    fn format_provenance_formats_cardinalities_sum_to_format_all() {
        // The fiber cardinalities sum to Format::ALL.len(). Pinned as a
        // cardinality statement independent of disjointness (which follows
        // when combined with disjointness via the
        // `partition_format_all_disjointly` test). A future Format variant
        // landing forces a fiber extension to keep this sum law intact.
        let sum: usize = FormatProvenance::ALL
            .iter()
            .copied()
            .map(|p| p.formats().len())
            .sum();
        assert_eq!(
            sum,
            Format::ALL.len(),
            "the fiber cardinalities must sum to Format::ALL.len()",
        );
    }

    #[test]
    fn format_provenance_formats_respects_format_all_declaration_order() {
        // Each fiber slice lists its formats in the same relative order as
        // they appear in Format::ALL. Consumers (per-provenance dashboards,
        // structured-log fields, attestation manifests) get a deterministic
        // ordering without re-sorting the slice.
        for p in FormatProvenance::ALL.iter().copied() {
            let fiber = p.formats();
            let mut last_position: Option<usize> = None;
            for f in fiber.iter().copied() {
                let position = Format::ALL
                    .iter()
                    .position(|all_f| *all_f == f)
                    .unwrap_or_else(|| panic!("fiber format {f:?} missing from Format::ALL"));
                if let Some(prev) = last_position {
                    assert!(
                        position > prev,
                        "fiber for {p:?} must list formats in Format::ALL declaration order; \
                         {f:?} at Format::ALL position {position} appears after position {prev}",
                    );
                }
                last_position = Some(position);
            }
        }
    }

    #[test]
    fn format_provenance_formats_today_match_recognized_partition() {
        // Concrete-position pin on the fibers today. The fiber law +
        // partition law above are structural over the typescape; this test
        // pins the literal slice values so a future provenance reassignment
        // (e.g. moving Format::Yaml from FigmentBuiltin to ShikumiBuilt via
        // a new shikumi-built YAML provider) fails here before drifting
        // through the structural laws. Mirrors
        // `format_provenance_classifies_each_variant` on the forward side.
        assert_eq!(
            FormatProvenance::FigmentBuiltin.formats(),
            &[Format::Yaml, Format::Toml],
            "FigmentBuiltin fiber must equal [Yaml, Toml] today",
        );
        assert_eq!(
            FormatProvenance::ShikumiBuilt.formats(),
            &[Format::Lisp, Format::Nix, Format::Blue],
            "ShikumiBuilt fiber must equal [Lisp, Nix, Blue] today",
        );
    }

    #[test]
    fn format_provenance_formats_agrees_with_has_shikumi_provider() {
        // The (provenance.formats() → has_shikumi_provider) projection
        // collapses to one boolean per fiber: every format in
        // FormatProvenance::ShikumiBuilt.formats() has has_shikumi_provider()
        // == true; every format in FormatProvenance::FigmentBuiltin.formats()
        // has it == false. Pins the agreement with the legacy bool predicate
        // pointwise across the fiber, so consumers replacing the inlined
        // `Format::ALL.iter().filter(|f| f.has_shikumi_provider())` pattern
        // (8 test sites + 1 production site today) with
        // `FormatProvenance::ShikumiBuilt.formats().iter()` reach the same
        // image by construction.
        for f in FormatProvenance::ShikumiBuilt.formats().iter().copied() {
            assert!(
                f.has_shikumi_provider(),
                "ShikumiBuilt fiber {f:?} must have has_shikumi_provider() == true",
            );
        }
        for f in FormatProvenance::FigmentBuiltin.formats().iter().copied() {
            assert!(
                !f.has_shikumi_provider(),
                "FigmentBuiltin fiber {f:?} must have has_shikumi_provider() == false",
            );
        }
    }

    #[test]
    fn format_provenance_formats_image_equals_realizable_format_axis() {
        // The fiber p.formats() equals the format-axis projection of the
        // realizable cells of FormatCoordinates restricted to the
        // `provenance == p` plane. Pins the join with the cube-coverage
        // discipline: future cube-cover dashboards that build a per-
        // provenance format histogram via the cube projection agree with
        // the direct-fiber accessor by construction.
        use std::collections::HashSet;
        for p in FormatProvenance::ALL.iter().copied() {
            let fiber: HashSet<Format> = p.formats().iter().copied().collect();
            let from_cube: HashSet<Format> = FormatCoordinates::ALL
                .iter()
                .copied()
                .filter(|cell| cell.provenance == p && cell.is_realizable())
                .map(|cell| cell.format)
                .collect();
            assert_eq!(
                fiber, from_cube,
                "fiber for {p:?} must equal the realizable-cube format projection \
                 on the provenance == {p:?} plane",
            );
        }
    }

    #[test]
    fn format_provenance_strip_metadata_name_routes_through_shikumi_built_fiber() {
        // Pin that Format::strip_metadata_name dispatches over exactly the
        // ShikumiBuilt fiber: every Format in the fiber must roundtrip
        // through metadata_name → strip_metadata_name, and no Format outside
        // the fiber can produce a recognized metadata-name today. Pins the
        // production-callsite refactor: the inlined
        // `Format::ALL.iter().filter(|f| f.has_shikumi_provider())` and the
        // new `FormatProvenance::ShikumiBuilt.formats().iter()` route must
        // recognize the same set of metadata-names.
        let path = Path::new("/etc/app/app.cfg");
        for f in FormatProvenance::ShikumiBuilt.formats().iter().copied() {
            let name = f.metadata_name(path);
            let (recovered, rest) = Format::strip_metadata_name(&name).unwrap_or_else(|| {
                panic!("ShikumiBuilt fiber {f:?} must round-trip strip_metadata_name")
            });
            assert_eq!(
                recovered, f,
                "strip_metadata_name must recover the ShikumiBuilt fiber format {f:?}",
            );
            assert_eq!(
                rest,
                path.to_str().unwrap(),
                "strip_metadata_name must return the trailing path verbatim",
            );
        }
        // The FigmentBuiltin fiber emits a metadata_name (the morphism is
        // total per Format::metadata_name's docs), but strip_metadata_name
        // is closed over the ShikumiBuilt fiber alone: those names round-
        // trip to None today because figment's builtin providers attach
        // attribution via Source::File, not metadata.name.
        // The forward emission is well-formed, but the resolver does not
        // recognize it on the name axis — pinning this asymmetry guards
        // against silent widening of the strip on a future refactor.
        for f in FormatProvenance::FigmentBuiltin.formats().iter().copied() {
            let name = f.metadata_name(path);
            // The figment-builtin metadata-name *shape* is the same prefix
            // form, so strip_metadata_name's closed dispatch over
            // ShikumiBuilt rejects it — exactly because the prefix
            // alphabet routes through ShikumiBuilt.formats(). The pin
            // documents that the strip stays closed over the fiber.
            assert!(
                Format::strip_metadata_name(&name).is_none(),
                "strip_metadata_name must not recognize FigmentBuiltin fiber {f:?} \
                 (the resolver routes figment-builtin file attribution through Source::File, \
                 not metadata.name)",
            );
        }
    }

    #[test]
    fn format_provenance_as_str_yields_canonical_kebab_case_names() {
        // Concrete-position pin on FormatProvenance::as_str. The
        // trait-uniform round-trip test in cube::tests pins labels
        // equal pairwise under from_canonical_str, but this test pins
        // the literal string values themselves so a future rename
        // (e.g. dropping the hyphen or capitalizing) fails here before
        // drifting through the trait-uniform round-trip law and the
        // operator-facing rendering surface.
        assert_eq!(FormatProvenance::FigmentBuiltin.as_str(), "figment-builtin",);
        assert_eq!(FormatProvenance::ShikumiBuilt.as_str(), "shikumi-built");
    }

    #[test]
    fn format_provenance_from_canonical_str_round_trips_through_trait() {
        // Pin the trait-default `from_canonical_str` parse on
        // FormatProvenance: each canonical kebab-case name parses back
        // to its variant via the ClosedAxisLabel default impl. The
        // canonical-only trait parse is the round-trip dual of
        // `as_str`; this pin sits at the FormatProvenance site so a
        // future override of `from_canonical_str` (none today) is
        // still held to the law.
        use crate::ClosedAxisLabel;
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                <FormatProvenance as ClosedAxisLabel>::from_canonical_str(p.as_str()),
                Some(p),
                "trait from_canonical_str must round-trip for {p:?}",
            );
        }
        // The compound names must round-trip case-insensitively (the
        // default parse uses `eq_ignore_ascii_case`); mixed-case forms
        // an operator might type in an env var or CLI flag reach the
        // same variant.
        assert_eq!(
            <FormatProvenance as ClosedAxisLabel>::from_canonical_str("Figment-Builtin"),
            Some(FormatProvenance::FigmentBuiltin),
        );
        assert_eq!(
            <FormatProvenance as ClosedAxisLabel>::from_canonical_str("SHIKUMI-BUILT"),
            Some(FormatProvenance::ShikumiBuilt),
        );
        // An unrecognized string returns None — the parse is closed
        // over `FormatProvenance::ALL` and rejects anything else.
        assert_eq!(
            <FormatProvenance as ClosedAxisLabel>::from_canonical_str("custom"),
            None,
        );
    }

    // ---- FormatProvenance Display / FromStr / Ord / serde lift ----

    #[test]
    fn format_provenance_ord_matches_all_declaration_order() {
        // FigmentBuiltin < ShikumiBuilt under the derived Ord — the
        // declaration-order total order is monotone in
        // FormatProvenance::ALL position. A BTreeMap<FormatProvenance,
        // T> keyed on the provenance axis emits rows in this order
        // deterministically; pinned here so a silent variant reorder
        // (which would invert the rollup order on every consumer)
        // fails this assertion first. Idiom-peer of the
        // `format_ord_matches_all_declaration_order` pin on the
        // Format axis (commit b56b121) and the
        // `*_class_ord_matches_all_declaration_order` pins on the
        // typed-cube classifiers.
        assert!(FormatProvenance::FigmentBuiltin < FormatProvenance::ShikumiBuilt);
        for window in FormatProvenance::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "Ord must be strictly monotone in FormatProvenance::ALL position: \
                 {:?} < {:?} failed",
                window[0],
                window[1],
            );
        }
    }

    #[test]
    fn format_provenance_display_matches_as_str() {
        // The Display impl delegates to `as_str` via `f.write_str`
        // pointwise across the provenance space. Pinned so a future
        // Display refactor (none today) cannot drift from the
        // canonical label that the (Serialize, Deserialize) pair
        // routes through.
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                format!("{p}"),
                p.as_str(),
                "Display impl must equal as_str pointwise on {p:?}",
            );
        }
    }

    #[test]
    fn format_provenance_from_str_round_trips_over_every_variant() {
        // The (Display, FromStr) stdlib pair on the provenance axis:
        // each canonical kebab-case label parses back to its variant.
        // Idiom-peer of the (Display, FromStr) round-trip on Format.
        for p in FormatProvenance::ALL.iter().copied() {
            let label = format!("{p}");
            let parsed: FormatProvenance = label
                .parse()
                .unwrap_or_else(|e| panic!("FromStr round-trip for {p:?} failed: {e}"));
            assert_eq!(parsed, p, "FromStr round-trip must be identity for {p:?}",);
        }
    }

    #[test]
    fn format_provenance_from_str_is_case_insensitive() {
        // FromStr inherits ASCII case-insensitivity from the
        // trait-default `from_canonical_str` parse (which uses
        // `eq_ignore_ascii_case` over `FormatProvenance::ALL`). An
        // operator-typed `FIGMENT-BUILTIN` env-override label reaches
        // the same variant as the canonical lowercase form.
        for p in FormatProvenance::ALL.iter().copied() {
            let upper = p.as_str().to_ascii_uppercase();
            let parsed: FormatProvenance = upper.parse().unwrap_or_else(|e| {
                panic!("uppercase FromStr for {p:?} must parse: {e}\n  input: {upper:?}")
            });
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn format_provenance_from_str_unknown_carries_label_verbatim() {
        // FromStr returns ShikumiError::Parse for unrecognized input,
        // with the offending substring embedded verbatim in the
        // rendered diagnostic. Mirror of the
        // `format_serde_yaml_unknown_format_error_carries_label_verbatim`
        // pin on Format; the operator localizes a typo without
        // matching on the parse error variant.
        let sentinel = "__shikumi_unknown_provenance_sentinel__";
        let result: Result<FormatProvenance, _> = sentinel.parse();
        match result {
            Err(e) => {
                let rendered = format!("{e}");
                assert!(
                    rendered.contains(sentinel),
                    "FromStr error must carry the unknown sentinel verbatim, got: {rendered}",
                );
            }
            Ok(other) => panic!("FromStr on unknown provenance must reject, got {other:?}"),
        }
    }

    #[test]
    fn format_provenance_serde_yaml_round_trips_over_every_variant() {
        // Serialize then deserialize on every variant — the typed
        // provenance cell survives the YAML scalar round-trip via the
        // canonical kebab-case label, no consumer-side rename helper
        // at the renderer. Closes the (Serialize, Deserialize)
        // idiom-peer of the (Display, FromStr) round-trip on
        // FormatProvenance, mirroring the same pin on Format.
        for p in FormatProvenance::ALL.iter().copied() {
            let yaml = serde_yaml::to_string(&p).unwrap();
            let parsed: FormatProvenance = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("YAML round-trip for {p:?} failed: {e}"));
            assert_eq!(
                parsed, p,
                "serde YAML round-trip must be identity for {p:?}",
            );
        }
    }

    #[test]
    fn format_provenance_serde_json_round_trips_over_every_variant() {
        // JSON emission is the quoted canonical kebab-case label; the
        // round-trip is identity over every variant. An attestation
        // manifest emitting `{"loaded_by": "shikumi-built"}` lands at
        // the wire shape without a rename helper.
        for p in FormatProvenance::ALL.iter().copied() {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", p.as_str()),
                "JSON emission for {p:?} must be the quoted canonical label",
            );
            let parsed: FormatProvenance = serde_json::from_str(&json).unwrap_or_else(|e| {
                panic!("JSON round-trip for {p:?} failed: {e}\n  json: {json}")
            });
            assert_eq!(
                parsed, p,
                "serde JSON round-trip must be identity for {p:?}",
            );
        }
    }

    #[test]
    fn format_provenance_serde_yaml_is_case_insensitive() {
        // Uppercase YAML scalars parse back to the same provenance via
        // the case-insensitive deserialize path lowering through
        // FromStr (which lowers through the trait-default
        // `from_canonical_str` applying `eq_ignore_ascii_case`).
        for p in FormatProvenance::ALL.iter().copied() {
            let upper = p.as_str().to_ascii_uppercase();
            let yaml = format!("\"{upper}\"\n");
            let parsed: FormatProvenance = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
                panic!("uppercase YAML scalar for {p:?} must deserialize: {e}\n  yaml: {yaml:?}",)
            });
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn format_provenance_serde_yaml_unknown_provenance_error_carries_label_verbatim() {
        // The deserialize error surface carries the offending label
        // verbatim through ShikumiError::Parse's Display impl, routed
        // via serde::de::Error::custom. Idiom-peer of the same pin on
        // the Format surface — a manifest field carrying
        // `loaded_by: vault` rejects on the serde side with the
        // offending substring named in the rendered diagnostic.
        let sentinel = "__shikumi_unknown_provenance_sentinel__";
        let yaml = format!("\"{sentinel}\"\n");
        let result: Result<FormatProvenance, _> = serde_yaml::from_str(&yaml);
        match result {
            Err(e) => {
                let rendered = format!("{e}");
                assert!(
                    rendered.contains(sentinel),
                    "serde YAML error must carry the unknown sentinel verbatim, got: {rendered}",
                );
            }
            Ok(other) => panic!("YAML carrying unknown provenance must reject, got {other:?}",),
        }
    }

    #[test]
    fn format_provenance_btreemap_emits_in_declaration_order() {
        // The Ord derive's compounding payoff: a
        // BTreeMap<FormatProvenance, T> keyed on the provenance axis
        // iterates in declaration order (FigmentBuiltin <
        // ShikumiBuilt). A per-provenance failure-rate dashboard, a
        // per-provenance attribution histogram rollup, or an
        // attestation manifest's per-provenance cardinality mix emits
        // rows in declaration order without a hand-rolled comparator
        // at the renderer. Idiom-peer of the
        // `format_btreemap_emits_in_preference_order` pin on Format.
        use std::collections::BTreeMap;
        let mut tally: BTreeMap<FormatProvenance, u32> = BTreeMap::new();
        for &p in FormatProvenance::ALL {
            tally.insert(p, 0);
        }
        let emitted: Vec<FormatProvenance> = tally.keys().copied().collect();
        assert_eq!(
            emitted,
            FormatProvenance::ALL.to_vec(),
            "BTreeMap<FormatProvenance, _> key order must match FormatProvenance::ALL",
        );
    }

    #[test]
    fn format_provenance_figment_builtin_slice_agrees_with_is_figment_builtin_predicate() {
        // Bidirectional weld between the slice literal
        // `FormatProvenance::FIGMENT_BUILTIN` and the boolean predicate
        // `FormatProvenance::is_figment_builtin` on the
        // (figment-builtin × shikumi-built) polarity axis. Every slice
        // entry satisfies the figment-builtin pole (and its complement
        // `!is_shikumi_built`), and every ALL cell agrees on membership
        // under the boolean predicate. Idiom-peer of
        // `secret_ref_shape_whole_slice_agrees_with_is_whole_predicate`
        // (commit `036673b`) —
        // the two independent declaration surfaces (slice literal +
        // boolean predicate) diverge at THIS pin on the first
        // provenance where they disagree, before a consumer that reads
        // one altitude but not the other can observe the drift.
        for p in FormatProvenance::FIGMENT_BUILTIN.iter().copied() {
            assert!(
                p.is_figment_builtin(),
                "FormatProvenance::FIGMENT_BUILTIN entry {p:?} must satisfy is_figment_builtin()",
            );
            assert!(
                !p.is_shikumi_built(),
                "FormatProvenance::FIGMENT_BUILTIN entry {p:?} must NOT satisfy is_shikumi_built()",
            );
        }
        for p in FormatProvenance::ALL.iter().copied() {
            assert_eq!(
                FormatProvenance::FIGMENT_BUILTIN.contains(&p),
                p.is_figment_builtin(),
                "FIGMENT_BUILTIN membership must agree with is_figment_builtin() on \
                 FormatProvenance::{p:?}",
            );
            assert_eq!(
                FormatProvenance::SHIKUMI_BUILT.contains(&p),
                p.is_shikumi_built(),
                "SHIKUMI_BUILT membership must agree with is_shikumi_built() on \
                 FormatProvenance::{p:?}",
            );
        }
    }

    #[test]
    fn format_provenance_figment_builtin_and_shikumi_built_slices_partition_all() {
        // Partition invariant: the two per-half slices are disjoint
        // and their union covers ALL. Direct application of the
        // meta-partition sum law
        // `FIGMENT_BUILTIN.len() + SHIKUMI_BUILT.len() == ALL.len()`
        // at the slice altitude on the provenance axis. Idiom-peer of
        // `secret_ref_shape_whole_and_field_slices_partition_all`
        // (commit `036673b`) —
        // a variant landing on one slice AND the other, or on neither,
        // breaks the partition here before any consumer that reasons
        // about the polarity as a covering meta-partition observes the
        // drift.
        for p in FormatProvenance::FIGMENT_BUILTIN.iter().copied() {
            assert!(
                !FormatProvenance::SHIKUMI_BUILT.contains(&p),
                "FormatProvenance::{p:?} appears in BOTH FIGMENT_BUILTIN and SHIKUMI_BUILT",
            );
        }
        for p in FormatProvenance::ALL.iter().copied() {
            let in_figment = FormatProvenance::FIGMENT_BUILTIN.contains(&p);
            let in_shikumi = FormatProvenance::SHIKUMI_BUILT.contains(&p);
            assert!(
                in_figment || in_shikumi,
                "FormatProvenance::{p:?} is in NEITHER FIGMENT_BUILTIN nor SHIKUMI_BUILT",
            );
            assert!(
                !(in_figment && in_shikumi),
                "FormatProvenance::{p:?} is in BOTH FIGMENT_BUILTIN and SHIKUMI_BUILT",
            );
        }
        assert_eq!(
            FormatProvenance::FIGMENT_BUILTIN.len() + FormatProvenance::SHIKUMI_BUILT.len(),
            FormatProvenance::ALL.len(),
            "FIGMENT_BUILTIN and SHIKUMI_BUILT slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn format_provenance_figment_builtin_and_shikumi_built_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in FormatProvenance::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise, so a
        // renderer walking the two half-slices concatenated reproduces
        // the ALL order (`FigmentBuiltin` first, then `ShikumiBuilt`).
        // Idiom-peer of
        // `secret_ref_shape_whole_and_field_slices_preserve_all_order`
        // (commit `036673b`) — a reordering of one slice without the
        // other, or a reordering of ALL that shuffles the two poles'
        // variant order without updating the slices, diverges at THIS
        // pin.
        let figment_from_all: Vec<FormatProvenance> = FormatProvenance::ALL
            .iter()
            .copied()
            .filter(|p| p.is_figment_builtin())
            .collect();
        assert_eq!(
            figment_from_all,
            FormatProvenance::FIGMENT_BUILTIN.to_vec(),
            "FIGMENT_BUILTIN must be ALL-filtered by is_figment_builtin in declaration order",
        );
        let shikumi_from_all: Vec<FormatProvenance> = FormatProvenance::ALL
            .iter()
            .copied()
            .filter(|p| p.is_shikumi_built())
            .collect();
        assert_eq!(
            shikumi_from_all,
            FormatProvenance::SHIKUMI_BUILT.to_vec(),
            "SHIKUMI_BUILT must be ALL-filtered by is_shikumi_built in declaration order",
        );
    }

    #[test]
    fn format_provenance_figment_builtin_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into SHIKUMI_BUILT, an accidental re-add of an already-
        // present FigmentBuiltin cell into FIGMENT_BUILTIN) fails at
        // THIS pin before drifting through any consumer that iterates
        // the slice expecting a set. Idiom-peer of
        // `secret_ref_shape_whole_slice_has_no_duplicates`
        // (commit `036673b`).
        for slice in [
            FormatProvenance::FIGMENT_BUILTIN,
            FormatProvenance::SHIKUMI_BUILT,
        ] {
            let mut sorted = slice.to_vec();
            sorted.sort();
            let deduped_len = {
                let mut seen: Vec<FormatProvenance> = Vec::with_capacity(sorted.len());
                for p in &sorted {
                    if !seen.contains(p) {
                        seen.push(*p);
                    }
                }
                seen.len()
            };
            assert_eq!(
                deduped_len,
                slice.len(),
                "FormatProvenance slice {slice:?} contains duplicate entries",
            );
        }
    }

    #[test]
    fn format_provenance_figment_builtin_and_shikumi_built_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on FormatProvenance::ALL — i.e.,
        // `FIGMENT_BUILTIN.len() == ALL.iter().filter(is_figment_builtin).count()`
        // and `SHIKUMI_BUILT.len() == ALL.iter().filter(is_shikumi_built).count()`
        // — the cardinality projection at the slice altitude agrees
        // with the boolean-altitude projection on both halves.
        // Concrete positions today: 1 figment_builtin + 1 shikumi_built
        // = 2 = ALL. Idiom-peer of
        // `secret_ref_shape_whole_and_field_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (commit `036673b`).
        let figment_count = FormatProvenance::ALL
            .iter()
            .copied()
            .filter(|p| p.is_figment_builtin())
            .count();
        let shikumi_count = FormatProvenance::ALL
            .iter()
            .copied()
            .filter(|p| p.is_shikumi_built())
            .count();
        assert_eq!(
            FormatProvenance::FIGMENT_BUILTIN.len(),
            figment_count,
            "FIGMENT_BUILTIN.len() must match the is_figment_builtin count on ALL",
        );
        assert_eq!(
            FormatProvenance::SHIKUMI_BUILT.len(),
            shikumi_count,
            "SHIKUMI_BUILT.len() must match the is_shikumi_built count on ALL",
        );
        assert_eq!(FormatProvenance::FIGMENT_BUILTIN.len(), 1);
        assert_eq!(FormatProvenance::SHIKUMI_BUILT.len(), 1);
        assert_eq!(FormatProvenance::ALL.len(), 2);
    }

    #[test]
    fn format_provenance_figment_builtin_and_shikumi_built_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Idiom-peer of
        // `secret_ref_shape_whole_and_field_slices_are_const_addressable`
        // (commit `036673b`).
        const FIGMENT_LEN: usize = FormatProvenance::FIGMENT_BUILTIN.len();
        const SHIKUMI_LEN: usize = FormatProvenance::SHIKUMI_BUILT.len();
        const ALL_LEN: usize = FormatProvenance::ALL.len();
        assert_eq!(FIGMENT_LEN, 1);
        assert_eq!(SHIKUMI_LEN, 1);
        assert_eq!(FIGMENT_LEN + SHIKUMI_LEN, ALL_LEN);
    }

    // ---- FormatCoordinates / Format::format_coordinates / format_or_none ----

    #[test]
    fn format_coordinates_classifies_each_variant() {
        // Pin the (Format -> FormatCoordinates) forward map at the
        // type level. Today's image: each Format pairs with its
        // declared provenance via Format::provenance.
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                f.format_coordinates(),
                FormatCoordinates {
                    format: f,
                    provenance: f.provenance(),
                },
                "format_coordinates must equal (format, format.provenance()) on {f:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_round_trip() {
        // The bijection statement on the recognized half:
        // FormatCoordinates::format_or_none(format.format_coordinates())
        // == Some(format) for every Format. Pins the forward-total /
        // inverse-partial round-trip law against the format space.
        for f in Format::ALL.iter().copied() {
            assert_eq!(
                f.format_coordinates().format_or_none(),
                Some(f),
                "format_coordinates -> format_or_none round-trip must recover {f:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_format_or_none_returns_none_for_unrecognized_cells() {
        // The 4 + 4 partition of the 8-cell cube: cells where
        // `cell.provenance == cell.format.provenance()` round-trip to
        // Some; the other 4 (where the cell's provenance disagrees
        // with the format's declared one) return None. Iterates the
        // named product cube `FormatCoordinates::ALL` so a future
        // variant on either sibling axis cannot silently widen the
        // unrecognized half.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let recognized = cell.format.provenance() == cell.provenance;
            assert_eq!(
                cell.format_or_none().is_some(),
                recognized,
                "format_or_none must be Some iff cell.provenance matches \
                 cell.format.provenance() on {cell:?}",
            );
        }
    }

    // ---- FormatCoordinates::ALL cover / partition / order ----

    #[test]
    fn format_coordinates_all_has_no_duplicates() {
        // The constant is a set, not a multiset: every cell appears
        // at most once. Pins the "no double-listed cell" invariant the
        // typescape relies on so consumers iterating ALL never see a
        // ghost cell contributing twice to a partition tally.
        use std::collections::HashSet;
        let unique: HashSet<FormatCoordinates> = FormatCoordinates::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            FormatCoordinates::ALL.len(),
            "FormatCoordinates::ALL must contain no duplicates; got: {:?}",
            FormatCoordinates::ALL,
        );
    }

    #[test]
    fn format_coordinates_all_cardinality_matches_product_of_axes() {
        // Cardinality is a product of two sibling axis cardinalities,
        // not a literal integer. Any new variant on either Format or
        // FormatProvenance forces an extension of FormatCoordinates::ALL
        // through this assertion, not through hand-counting.
        assert_eq!(
            FormatCoordinates::ALL.len(),
            Format::ALL.len() * FormatProvenance::ALL.len(),
            "FormatCoordinates::ALL cardinality must equal \
             Format::ALL.len() * FormatProvenance::ALL.len()",
        );
        // Pin today's concrete cardinality — 5 × 2 = 10 — so a future
        // axis growth that updates the product still requires updating
        // this literal explicitly.
        assert_eq!(
            FormatCoordinates::ALL.len(),
            10,
            "FormatCoordinates::ALL cardinality must be 8 today; \
             update both this literal and the cells if axes grow",
        );
    }

    #[test]
    fn format_coordinates_all_equals_axes_cartesian_product() {
        // Tight equality (not subset) against the inline doubly-nested
        // cartesian product over the sibling ALL slices.
        // FormatCoordinates::ALL IS the product, no extras and no
        // omissions.
        use std::collections::HashSet;
        let declared: HashSet<FormatCoordinates> = FormatCoordinates::ALL.iter().copied().collect();
        let mut product: HashSet<FormatCoordinates> = HashSet::new();
        for format in Format::ALL.iter().copied() {
            for provenance in FormatProvenance::ALL.iter().copied() {
                product.insert(FormatCoordinates { format, provenance });
            }
        }
        assert_eq!(
            declared, product,
            "FormatCoordinates::ALL must equal the cartesian product \
             Format::ALL × FormatProvenance::ALL exactly (no extras, no omissions)",
        );
    }

    #[test]
    fn format_coordinates_all_iterates_in_lexicographic_order() {
        // Iteration order is observable: format outermost,
        // provenance innermost. Consumers depending on a stable
        // canonical enumeration (fixture tables, attestation manifests,
        // structured-diagnostics legends) stay coherent.
        let mut expected: Vec<FormatCoordinates> = Vec::new();
        for format in Format::ALL.iter().copied() {
            for provenance in FormatProvenance::ALL.iter().copied() {
                expected.push(FormatCoordinates { format, provenance });
            }
        }
        assert_eq!(
            FormatCoordinates::ALL.to_vec(),
            expected,
            "FormatCoordinates::ALL must list cells in lexicographic \
             order (format outer, provenance inner)",
        );
    }

    #[test]
    fn format_coordinates_all_partitions_into_recognized_and_unrecognized() {
        // The 4 + 4 partition of FormatCoordinates::ALL against
        // FormatCoordinates::format_or_none: 4 cells map to Some
        // (one per Format), 4 map to None, the partition covers
        // FormatCoordinates::ALL exactly.
        let recognized = FormatCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.format_or_none().is_some())
            .count();
        let unrecognized = FormatCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.format_or_none().is_none())
            .count();
        assert_eq!(
            recognized,
            Format::ALL.len(),
            "recognized cell count must equal Format::ALL.len()",
        );
        assert_eq!(
            unrecognized,
            FormatCoordinates::ALL.len() - Format::ALL.len(),
            "unrecognized cell count must equal the cube complement",
        );
        assert_eq!(
            recognized + unrecognized,
            FormatCoordinates::ALL.len(),
            "the partition must cover the cube exactly",
        );
    }

    #[test]
    fn format_coordinates_all_recognized_image_equals_format_coordinates() {
        // Stronger than the cardinality split: the recognized half
        // is the exact image of Format::format_coordinates over
        // Format::ALL — which specific cells (not just how many) are
        // recognized.
        use std::collections::HashSet;
        let image: HashSet<FormatCoordinates> = Format::ALL
            .iter()
            .copied()
            .map(Format::format_coordinates)
            .collect();
        let recognized: HashSet<FormatCoordinates> = FormatCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.format_or_none().is_some())
            .collect();
        assert_eq!(
            image, recognized,
            "the recognized image of FormatCoordinates::ALL must equal \
             the image of Format::format_coordinates over Format::ALL",
        );
    }

    #[test]
    fn format_coordinates_all_round_trips_through_format_or_none_on_recognized_cells() {
        // For every recognized cell c in FormatCoordinates::ALL,
        // c.format_coordinates_after_format_or_none() == c. The
        // bijection statement on the 4-cell recognized subset,
        // enumerated by iterating the product cube.
        for cell in FormatCoordinates::ALL.iter().copied() {
            if let Some(format) = cell.format_or_none() {
                assert_eq!(
                    format.format_coordinates(),
                    cell,
                    "format_or_none -> format_coordinates round-trip \
                     must recover the recognized cell {cell:?}",
                );
            }
        }
    }

    #[test]
    fn format_coordinates_is_copy_and_hashable() {
        // Trait-bounds parity with the sibling typescape primitives
        // (AttributionCoordinates, AttributionConfidence,
        // AttributionAxis, ConfigSourceKind, ShikumiErrorKind,
        // FieldPathLocalization, FormatProvenance).
        use std::collections::HashSet;
        let c = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        // Copy: rebind without move.
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
        // Hash + Eq: cube has FormatCoordinates::ALL.len() distinct
        // cells.
        let set: HashSet<FormatCoordinates> = FormatCoordinates::ALL.iter().copied().collect();
        assert_eq!(set.len(), FormatCoordinates::ALL.len());
    }

    // ---- FormatCoordinates::is_realizable ----

    #[test]
    fn format_coordinates_is_realizable_agrees_with_format_or_none_some() {
        // Pins the realizability invariant pointwise on every cell of
        // the cube:
        //   is_realizable iff FormatCoordinates::format_or_none is Some.
        // The two definitions agree on all 8 cells.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let expected = cell.format_or_none().is_some();
            assert_eq!(
                cell.is_realizable(),
                expected,
                "cell {cell:?}: is_realizable must equal format_or_none().is_some()",
            );
        }
    }

    #[test]
    fn format_coordinates_realizable_partitions_into_5_realizable_and_5_unrealizable() {
        // Pins the 5 + 5 cardinality split:
        // - 5 realizable cells, one per recognized Format
        //   (Yaml, Toml, Lisp, Nix, Blue), each paired with its declared
        //   provenance via Format::provenance.
        // - 5 unrealizable cells covering every (format, provenance)
        //   combination where provenance disagrees with the format's
        //   declared provider class.
        // A future Format landing or a future FormatProvenance variant
        // moves both counts in lockstep through this assertion.
        let realizable = FormatCoordinates::ALL
            .iter()
            .filter(|c| c.is_realizable())
            .count();
        let unrealizable = FormatCoordinates::ALL
            .iter()
            .filter(|c| !c.is_realizable())
            .count();
        assert_eq!(
            realizable,
            Format::ALL.len(),
            "realizable cells must equal Format::ALL cardinality",
        );
        assert_eq!(
            unrealizable,
            FormatCoordinates::ALL.len() - Format::ALL.len(),
            "unrealizable cells must equal cube cardinality minus format cardinality",
        );
        assert_eq!(
            realizable + unrealizable,
            FormatCoordinates::ALL.len(),
            "realizable + unrealizable must cover ALL exactly once",
        );
        // Pin the concrete current values too — the partition is 5 + 5
        // today; future format additions or provenance additions move
        // both counts in lockstep.
        assert_eq!(realizable, 5);
        assert_eq!(unrealizable, 5);
    }

    #[test]
    fn format_coordinates_is_realizable_image_equals_format_image() {
        // The realizable half of ALL is the exact image of
        // Format::format_coordinates over the format space. Pins which
        // specific cells (not just how many) are observable from a
        // recognized Format — a tighter contract than the cardinality
        // split. Future formats land coherently: a new format extends
        // the image and forces an expansion of the realizable subset
        // in lockstep.
        use std::collections::HashSet;
        let observed: HashSet<FormatCoordinates> = Format::ALL
            .iter()
            .copied()
            .map(Format::format_coordinates)
            .collect();
        let realizable: HashSet<FormatCoordinates> = FormatCoordinates::ALL
            .iter()
            .copied()
            .filter(|c| c.is_realizable())
            .collect();
        assert_eq!(
            observed, realizable,
            "observed image over Format::ALL must equal the realizable cells",
        );
    }

    #[test]
    fn format_format_coordinates_always_lies_on_realizable_cell() {
        // Forward-total / image-realizable contract: every cell
        // produced by Format::format_coordinates must satisfy
        // is_realizable. The forward map never escapes into the
        // unrealizable half of the cube, no matter which format is
        // queried.
        for format in Format::ALL.iter().copied() {
            assert!(
                format.format_coordinates().is_realizable(),
                "format {format:?}: format_coordinates() must produce a realizable cell",
            );
        }
    }

    #[test]
    fn format_coordinates_unrealizable_cells_have_no_inverse() {
        // Symmetric of the forward-total contract: every unrealizable
        // cell has no inverse format. Closes the partial-inverse /
        // Boolean-predicate equivalence in the unrealizable direction:
        // `!c.is_realizable() iff c.format_or_none().is_none()`.
        // Pointwise verification across the 8-cell cube.
        for cell in FormatCoordinates::ALL.iter().copied() {
            if !cell.is_realizable() {
                assert!(
                    cell.format_or_none().is_none(),
                    "unrealizable cell {cell:?}: format_or_none must be None",
                );
            }
        }
    }

    // ---- FormatCoordinates: Ord / Display / FromStr / serde ----

    #[test]
    fn format_coordinates_ord_matches_all_declaration_order() {
        // The derived Ord on FormatCoordinates is lex over the struct's
        // declaration order (format outer, provenance inner). Because
        // both sibling axes already carry declaration-order Ord under
        // the same trait-uniform discipline (Format from commit b56b121,
        // FormatProvenance from commit 2c7654c), the induced
        // product-cube order matches FormatCoordinates::ALL pointwise.
        // Pinned here so a silent variant reorder on either axis (which
        // would invert the rollup order on every consumer) fails this
        // assertion first.
        for window in FormatCoordinates::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "Ord must be strictly monotone in FormatCoordinates::ALL position: \
                 {:?} < {:?} failed",
                window[0],
                window[1],
            );
        }
    }

    #[test]
    fn format_coordinates_display_renders_canonical_format_colon_provenance() {
        // The Display impl writes `<format>:<provenance>` using the
        // canonical lowercase labels from each sibling axis. Pin the
        // wire shape on every cell of the cube so a future format /
        // provenance variant landing cannot drift the separator or
        // label casing.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let rendered = format!("{cell}");
            let expected = format!("{}:{}", cell.format.as_str(), cell.provenance.as_str());
            assert_eq!(
                rendered, expected,
                "Display must render canonical <format>:<provenance> on {cell:?}",
            );
            assert!(
                rendered.contains(':'),
                "Display output for {cell:?} must contain the `:` separator: {rendered}",
            );
        }
    }

    #[test]
    fn format_coordinates_from_str_round_trips_over_all_cells() {
        // The (Display, FromStr) stdlib pair on the product cube: every
        // cell's canonical pair label parses back to the same cell. The
        // round-trip holds across the full 8-cell cube — realizable and
        // unrealizable alike — because Display / FromStr operate on the
        // closed-enum labels, not on the realizability predicate.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let rendered = cell.to_string();
            let parsed: FormatCoordinates = rendered
                .parse()
                .unwrap_or_else(|e| panic!("FromStr round-trip for {cell:?} failed: {e}"));
            assert_eq!(
                parsed, cell,
                "FromStr round-trip must be identity for {cell:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_from_str_inherits_case_insensitivity_per_axis() {
        // Both halves of the canonical pair label parse
        // case-insensitively: the format half inherits ASCII
        // case-insensitivity from Format::from_extension (via
        // to_ascii_lowercase), the provenance half inherits ASCII
        // case-insensitivity from the trait-default
        // ClosedAxisLabel::from_canonical_str. An operator-typed
        // uppercased cell label reaches the same cell as the canonical
        // lowercase form.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let upper = cell.to_string().to_ascii_uppercase();
            let parsed: FormatCoordinates = upper.parse().unwrap_or_else(|e| {
                panic!("uppercase FromStr for {cell:?} must parse: {e}\n  input: {upper:?}")
            });
            assert_eq!(
                parsed, cell,
                "case-insensitive parse must round-trip {cell:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_from_str_inherits_format_alias_surface() {
        // The format half of the pair label routes through
        // Format::from_str, which accepts the alias extensions `yml`,
        // `lsp`, `el` alongside the canonical names. An operator-typed
        // `yml:figment-builtin` pair label reaches the same cell as the
        // canonical `yaml:figment-builtin` form — the alias surface on
        // the format axis lifts onto the product cube without a
        // consumer-side rewrite.
        let parsed: FormatCoordinates = "yml:figment-builtin".parse().unwrap();
        assert_eq!(
            parsed,
            FormatCoordinates {
                format: Format::Yaml,
                provenance: FormatProvenance::FigmentBuiltin,
            },
        );
        let parsed: FormatCoordinates = "lsp:shikumi-built".parse().unwrap();
        assert_eq!(
            parsed,
            FormatCoordinates {
                format: Format::Lisp,
                provenance: FormatProvenance::ShikumiBuilt,
            },
        );
    }

    #[test]
    fn format_coordinates_from_str_rejects_missing_separator() {
        // Input without `:` rejects with MissingSeparator carrying the
        // full input substring verbatim. The structural separator check
        // is strictly more specific than per-half label checks, so a
        // bare label like `yaml` (a valid Format) still rejects on the
        // product-cube surface for missing the colon.
        let sentinel = "no-colon-here-at-all";
        let result: Result<FormatCoordinates, _> = sentinel.parse();
        match result {
            Err(ParseFormatCoordinatesError::MissingSeparator { input }) => {
                assert_eq!(input, sentinel);
                let rendered = format!(
                    "{}",
                    ParseFormatCoordinatesError::MissingSeparator {
                        input: sentinel.to_owned(),
                    }
                );
                assert!(
                    rendered.contains(sentinel),
                    "Display must carry the offending input verbatim, got: {rendered}",
                );
            }
            other => {
                panic!("missing-separator input must reject with MissingSeparator: {other:?}",)
            }
        }
    }

    #[test]
    fn format_coordinates_from_str_rejects_unknown_format_with_label_verbatim() {
        // Input with a `:` separator but an unrecognized format half
        // rejects with UnknownFormat carrying the offending format
        // substring verbatim. The provenance half is not checked at
        // this point — the format-half check is strictly more specific
        // and runs first to match left-to-right reading.
        let result: Result<FormatCoordinates, _> = "vault:shikumi-built".parse();
        match result {
            Err(ParseFormatCoordinatesError::UnknownFormat { label }) => {
                assert_eq!(label, "vault");
                let rendered = format!(
                    "{}",
                    ParseFormatCoordinatesError::UnknownFormat {
                        label: "vault".to_owned(),
                    }
                );
                assert!(
                    rendered.contains("vault"),
                    "Display must carry the offending format label verbatim, got: {rendered}",
                );
            }
            other => panic!("unknown-format input must reject with UnknownFormat: {other:?}",),
        }
    }

    #[test]
    fn format_coordinates_from_str_rejects_unknown_provenance_with_label_verbatim() {
        // Input with a `:` separator and a recognized format half but
        // an unrecognized provenance half rejects with UnknownProvenance
        // carrying the offending provenance substring verbatim. This is
        // the third precedence level after MissingSeparator and
        // UnknownFormat.
        let result: Result<FormatCoordinates, _> = "yaml:upstream-figment".parse();
        match result {
            Err(ParseFormatCoordinatesError::UnknownProvenance { label }) => {
                assert_eq!(label, "upstream-figment");
                let rendered = format!(
                    "{}",
                    ParseFormatCoordinatesError::UnknownProvenance {
                        label: "upstream-figment".to_owned(),
                    }
                );
                assert!(
                    rendered.contains("upstream-figment"),
                    "Display must carry the offending provenance label verbatim, got: {rendered}",
                );
            }
            other => {
                panic!("unknown-provenance input must reject with UnknownProvenance: {other:?}",)
            }
        }
    }

    #[test]
    fn parse_format_coordinates_error_is_missing_separator_true_only_for_missing_separator_variant()
    {
        // Per-variant polarity pin on the MissingSeparator corner of
        // the `ParseFormatCoordinatesError` tag-side sibling-predicate
        // trio. A future edit that flips the `matches!` arm on
        // `ParseFormatCoordinatesError::is_missing_separator` fails
        // here before the closed-partition pin below masks it.
        // Payload-independence sub-pin: the answer is the same for
        // every `MissingSeparator { input }` regardless of the input
        // content — empty, short, structured, whitespace-only,
        // unicode. Direct methodological analogue of
        // `diff_line_is_removed_true_only_for_removed_variant` on the
        // `DiffLine` tag-side trio (`deaa9b4`).
        for payload in ["", "x", "yaml-no-colon", "  leading spaces", "no:c\u{2028}"] {
            assert!(
                ParseFormatCoordinatesError::MissingSeparator {
                    input: payload.into(),
                }
                .is_missing_separator(),
                "MissingSeparator {{ input: {payload:?} }} must satisfy is_missing_separator",
            );
            assert!(
                !ParseFormatCoordinatesError::UnknownFormat {
                    label: payload.into(),
                }
                .is_missing_separator(),
                "UnknownFormat {{ label: {payload:?} }} must not satisfy is_missing_separator",
            );
            assert!(
                !ParseFormatCoordinatesError::UnknownProvenance {
                    label: payload.into(),
                }
                .is_missing_separator(),
                "UnknownProvenance {{ label: {payload:?} }} must not satisfy \
                 is_missing_separator",
            );
        }
    }

    #[test]
    fn parse_format_coordinates_error_is_unknown_format_true_only_for_unknown_format_variant() {
        // Mirror per-variant polarity pin on the UnknownFormat corner.
        for payload in ["", "vault", "YAML", "  yaml  ", "yaml-with-suffix"] {
            assert!(
                !ParseFormatCoordinatesError::MissingSeparator {
                    input: payload.into(),
                }
                .is_unknown_format(),
                "MissingSeparator {{ input: {payload:?} }} must not satisfy is_unknown_format",
            );
            assert!(
                ParseFormatCoordinatesError::UnknownFormat {
                    label: payload.into(),
                }
                .is_unknown_format(),
                "UnknownFormat {{ label: {payload:?} }} must satisfy is_unknown_format",
            );
            assert!(
                !ParseFormatCoordinatesError::UnknownProvenance {
                    label: payload.into(),
                }
                .is_unknown_format(),
                "UnknownProvenance {{ label: {payload:?} }} must not satisfy is_unknown_format",
            );
        }
    }

    #[test]
    fn parse_format_coordinates_error_is_unknown_provenance_true_only_for_unknown_provenance_variant()
     {
        // Mirror per-variant polarity pin on the UnknownProvenance
        // corner — the deepest of the three precedence levels.
        for payload in [
            "",
            "upstream-figment",
            "SHIKUMI-BUILT",
            "figment-builtin:extra",
            "unknown-provenance-with-unicode-仕組み",
        ] {
            assert!(
                !ParseFormatCoordinatesError::MissingSeparator {
                    input: payload.into(),
                }
                .is_unknown_provenance(),
                "MissingSeparator {{ input: {payload:?} }} must not satisfy \
                 is_unknown_provenance",
            );
            assert!(
                !ParseFormatCoordinatesError::UnknownFormat {
                    label: payload.into(),
                }
                .is_unknown_provenance(),
                "UnknownFormat {{ label: {payload:?} }} must not satisfy is_unknown_provenance",
            );
            assert!(
                ParseFormatCoordinatesError::UnknownProvenance {
                    label: payload.into(),
                }
                .is_unknown_provenance(),
                "UnknownProvenance {{ label: {payload:?} }} must satisfy is_unknown_provenance",
            );
        }
    }

    #[test]
    fn parse_format_coordinates_error_predicates_are_a_closed_ternary_partition() {
        // Every `ParseFormatCoordinatesError` value in the canonical
        // sample table satisfies exactly one of the three sibling
        // predicates: none satisfies two, none satisfies zero.
        // Ternary-partition analogue of the pin
        // `diff_line_predicates_are_a_closed_ternary_partition`
        // (`deaa9b4`) on `DiffLine`, lifted here onto a payload-bearing
        // parse-error primitive. A future fourth variant landing under
        // `#[non_exhaustive]` without its own sibling predicate
        // collapses the partition to zero on that variant, failing
        // here before drifting through any retry-policy dispatch or
        // operator-facing suggestion engine that routes on the polarity
        // trio.
        let errors = [
            ParseFormatCoordinatesError::MissingSeparator {
                input: String::new(),
            },
            ParseFormatCoordinatesError::MissingSeparator {
                input: "no-colon-here-at-all".into(),
            },
            ParseFormatCoordinatesError::MissingSeparator {
                input: "unicode\u{2028}no colon 仕組み".into(),
            },
            ParseFormatCoordinatesError::UnknownFormat {
                label: String::new(),
            },
            ParseFormatCoordinatesError::UnknownFormat {
                label: "vault".into(),
            },
            ParseFormatCoordinatesError::UnknownFormat {
                label: "  yaml  ".into(),
            },
            ParseFormatCoordinatesError::UnknownProvenance {
                label: String::new(),
            },
            ParseFormatCoordinatesError::UnknownProvenance {
                label: "upstream-figment".into(),
            },
            ParseFormatCoordinatesError::UnknownProvenance {
                label: "figment-builtin:extra".into(),
            },
        ];
        for err in &errors {
            let hits = usize::from(err.is_missing_separator())
                + usize::from(err.is_unknown_format())
                + usize::from(err.is_unknown_provenance());
            assert_eq!(
                hits, 1,
                "ParseFormatCoordinatesError::{err:?} must satisfy exactly one of \
                 is_missing_separator/is_unknown_format/is_unknown_provenance (satisfied {hits})",
            );
        }
    }

    #[test]
    fn parse_format_coordinates_error_predicates_agree_with_from_str_rejection_paths() {
        // The three canonical rejection paths through
        // `<FormatCoordinates as FromStr>::from_str` each land on the
        // sibling predicate that names their rejection mode: an input
        // with no `:` fires `is_missing_separator`; an input with a
        // colon and an unrecognized format half fires
        // `is_unknown_format`; an input with a colon, a recognized
        // format half, and an unrecognized provenance half fires
        // `is_unknown_provenance`. Cross-cuts the parser's
        // precedence-order contract
        // (`MissingSeparator → UnknownFormat → UnknownProvenance`)
        // and pins that a future precedence swap between the two
        // label-check arms would surface here before drifting through
        // any consumer routing on the polarity trio. Sibling of the
        // per-variant `format_coordinates_from_str_rejects_*` pins
        // above, extended to the tag-side classifier surface.
        let missing_sep: Result<FormatCoordinates, _> = "no-colon-here-at-all".parse();
        let err = missing_sep.expect_err("input without `:` must reject");
        assert!(
            err.is_missing_separator(),
            "expected is_missing_separator for {err:?}"
        );
        assert!(!err.is_unknown_format());
        assert!(!err.is_unknown_provenance());

        let unknown_fmt: Result<FormatCoordinates, _> = "vault:shikumi-built".parse();
        let err = unknown_fmt.expect_err("input with unrecognized format half must reject");
        assert!(!err.is_missing_separator());
        assert!(
            err.is_unknown_format(),
            "expected is_unknown_format for {err:?}"
        );
        assert!(!err.is_unknown_provenance());

        let unknown_prov: Result<FormatCoordinates, _> = "yaml:upstream-figment".parse();
        let err = unknown_prov.expect_err("input with unrecognized provenance half must reject");
        assert!(!err.is_missing_separator());
        assert!(!err.is_unknown_format());
        assert!(
            err.is_unknown_provenance(),
            "expected is_unknown_provenance for {err:?}"
        );
    }

    #[test]
    fn format_coordinates_from_str_uses_leftmost_colon_only() {
        // The parser uses `split_once(':')` which splits on the
        // leftmost `:`. Any additional `:` characters fall into the
        // provenance half; since the canonical provenance labels
        // contain no `:`, such input rejects with UnknownProvenance
        // carrying the multi-colon trailing slice verbatim. Pins the
        // split semantics so a future parser change cannot silently
        // swap to rsplit_once.
        let result: Result<FormatCoordinates, _> = "yaml:figment-builtin:extra".parse();
        match result {
            Err(ParseFormatCoordinatesError::UnknownProvenance { label }) => {
                assert_eq!(label, "figment-builtin:extra");
            }
            other => panic!("multi-colon input must reject with UnknownProvenance: {other:?}",),
        }
    }

    #[test]
    fn format_coordinates_serde_yaml_round_trips_over_all_cells() {
        // The (Serialize, Deserialize) serde idiom-peer of the
        // (Display, FromStr) round-trip: every cell of the cube
        // serializes to its canonical `<format>:<provenance>` scalar
        // and deserializes back to the same cell. The round-trip holds
        // across the full 8-cell cube.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let yaml = serde_yaml::to_string(&cell).unwrap();
            let parsed: FormatCoordinates = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("YAML round-trip for {cell:?} failed: {e}"));
            assert_eq!(
                parsed, cell,
                "serde YAML round-trip must be identity for {cell:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_serde_json_round_trips_over_all_cells() {
        // JSON emission is the quoted canonical pair label; the
        // round-trip is identity over every cell. An attestation
        // manifest emitting `{"loaded_by": "nix:shikumi-built"}` lands
        // at the wire shape without a rename helper.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let json = serde_json::to_string(&cell).unwrap();
            assert_eq!(
                json,
                format!("\"{}:{}\"", cell.format.as_str(), cell.provenance.as_str()),
                "JSON emission for {cell:?} must be the quoted canonical pair label",
            );
            let parsed: FormatCoordinates = serde_json::from_str(&json).unwrap_or_else(|e| {
                panic!("JSON round-trip for {cell:?} failed: {e}\n  json: {json}")
            });
            assert_eq!(
                parsed, cell,
                "serde JSON round-trip must be identity for {cell:?}",
            );
        }
    }

    #[test]
    fn format_coordinates_serde_yaml_is_case_insensitive() {
        // Uppercase YAML scalars parse back to the same cell via the
        // case-insensitive deserialize path lowering through FromStr.
        // Both halves inherit ASCII case-insensitivity from their
        // respective axes; the product cube composes the inheritance
        // pointwise without re-stating it at the cell parser.
        for cell in FormatCoordinates::ALL.iter().copied() {
            let upper = format!("{cell}").to_ascii_uppercase();
            let yaml = format!("\"{upper}\"\n");
            let parsed: FormatCoordinates = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
                panic!("uppercase YAML scalar for {cell:?} must deserialize: {e}\n  yaml: {yaml:?}",)
            });
            assert_eq!(parsed, cell);
        }
    }

    #[test]
    fn format_coordinates_serde_yaml_unknown_format_error_carries_label_verbatim() {
        // The deserialize error surface carries the offending format
        // label verbatim through ParseFormatCoordinatesError's Display
        // impl, routed via serde::de::Error::custom. A manifest field
        // carrying `loaded_by: vault:shikumi-built` rejects on the
        // serde side with the offending format substring named in the
        // rendered diagnostic.
        let yaml = "\"vault:shikumi-built\"\n";
        let result: Result<FormatCoordinates, _> = serde_yaml::from_str(yaml);
        match result {
            Err(e) => {
                let rendered = format!("{e}");
                assert!(
                    rendered.contains("vault"),
                    "serde YAML error must carry the unknown format label verbatim, \
                     got: {rendered}",
                );
            }
            Ok(other) => panic!("YAML carrying unknown format half must reject, got {other:?}",),
        }
    }

    #[test]
    fn format_coordinates_serde_yaml_unknown_provenance_error_carries_label_verbatim() {
        // Symmetric pin on the provenance half: a manifest field
        // carrying `loaded_by: yaml:upstream-figment` rejects on the
        // serde side with the offending provenance substring named in
        // the rendered diagnostic.
        let yaml = "\"yaml:upstream-figment\"\n";
        let result: Result<FormatCoordinates, _> = serde_yaml::from_str(yaml);
        match result {
            Err(e) => {
                let rendered = format!("{e}");
                assert!(
                    rendered.contains("upstream-figment"),
                    "serde YAML error must carry the unknown provenance label verbatim, \
                     got: {rendered}",
                );
            }
            Ok(other) => {
                panic!("YAML carrying unknown provenance half must reject, got {other:?}",)
            }
        }
    }

    #[test]
    fn format_coordinates_btreemap_emits_in_cube_order() {
        // The Ord derive's compounding payoff on the product cube: a
        // BTreeMap<FormatCoordinates, T> keyed on the (format ×
        // provenance) cube iterates in product order pointwise matching
        // FormatCoordinates::ALL. A per-cell discovery-cost telemetry
        // rollup, a per-cell failure-rate dashboard, or an attestation
        // manifest's per-cell cardinality mix emits rows in product
        // order without a hand-rolled comparator at the renderer. Same
        // BTreeMap-emission pin as on the sibling axes
        // (`format_btreemap_emits_in_preference_order`,
        // `format_provenance_btreemap_emits_in_declaration_order`),
        // lifted onto the product cube.
        use std::collections::BTreeMap;
        let mut tally: BTreeMap<FormatCoordinates, u32> = BTreeMap::new();
        for &cell in FormatCoordinates::ALL {
            tally.insert(cell, 0);
        }
        let emitted: Vec<FormatCoordinates> = tally.keys().copied().collect();
        assert_eq!(
            emitted,
            FormatCoordinates::ALL.to_vec(),
            "BTreeMap<FormatCoordinates, _> key order must match FormatCoordinates::ALL",
        );
    }
}

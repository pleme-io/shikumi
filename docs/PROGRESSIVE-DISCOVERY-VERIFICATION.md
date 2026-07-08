# PROGRESSIVE-DISCOVERY-VERIFICATION

Tier-honest seal ledger for shikumi's **tiered progressive-discovery**
configuration surface — the sealed fold
`bare() → discovered() → prescribed_default() → file → env → runtime-override`
in which every effective value carries a typed [`Provenance`].

> **The bright line (never round up).** A `Result::Err` / runtime check is
> **only-mitigated**. An `Err` at a parse boundary + sealed construction is
> **parse-time-rejected**. A compile error / absent code path is
> **truly-unrep**. Ceilings `C1–C6` per `theory/UNREPRESENTABILITY.md`
> (`C1` no dependent types; `C-map` a path-keyed side-map is not a per-field
> type wrapper). Each row states the tier it *actually* sits at.

Surface: `shikumi::{TieredConfig::resolve_progressive, resolve_progressive_with,
discovered_from_layers, Provenance, ProvenanceMap, ProgressiveLayer,
ProgressiveResolution}` (`src/tiered.rs`) over the one generic per-leaf
attributed fold `deep_merge_attributed<A>` (`src/discovered.rs`).

---

## The sealed invariants

| # | Invariant | Best-fit construction | Tier | Ceiling | Evidence (test) |
|---|-----------|-----------------------|------|---------|-----------------|
| I1 | **Precedence order is total + typed** — "which tier outranks which" is fixed and cannot be got wrong. | Reuse the const `ConfigTierKind` `ClosedAxis` **declaration order** (`Bare < Discovered < Default < Custom`) via `crate::axis_ordinal`; `Provenance::tier_ordinal` reads it, the fold sorts by it. No parallel order minted. | **truly-unrep** | — | `provenance_tier_ordinal_reuses_closed_axis_order`; the `ClosedAxis` declaration-order + cardinality pins already in `tiered::tests` (`config_tier_kind_all_has_four_entries`, `…_trait_all_matches_inherent_all`). Getting the order "wrong" requires reordering the enum — a source edit the axis pins catch. |
| I2 | **Discovery totality** — an undetectable axis degenerates to its documented fallback; never a panic/partial. | `kanchi` `defaxes!` emits `Option<T>` + `detect_*_or_fallback()` (`unwrap_or(FALLBACK)`); a `DiscoveryLayer` with no answer returns an **empty `Dict`**, a no-op in the deep-merge; `discovered_from_layers(&[])` = `bare()`. No `unwrap`/`expect`/`panic` on the resolve path. | **truly-unrep** (totality of the fallback) | — | `discovered_from_layers_empty_stack_is_bare`; `discovered_from_layers_overlays_detected_axes_on_bare`; kanchi's `fallback_when_none` / `detect_or_fallback_always_returns_usable`. |
| I3 | **Lower tier can't beat higher — via the fold.** | `resolve_progressive_with` **stable-sorts the whole layer stack by the const tier ordinal (I1) *before* merging**, then folds; a mis-ordered / mis-tagged overlay is re-sorted to its rank, so no input ordering makes a lower tier win. The fold is the only constructor of a `ProgressiveResolution`. | **truly-unrep** *for the `resolve_progressive*` path* | — | `progressive_higher_tier_beats_lower_on_override`; `progressive_fold_reorders_a_misordered_low_tier_overlay` (a `Bare`-tagged overlay setting `a=999` still loses to `Discovered`'s `a=10`). |
| I3′ | **Lower can't beat higher — at the crate surface.** | The underlying `deep_merge` is `pub`; a consumer *can* hand-merge dicts in any order — but that bypasses the sealed fold entirely (it is not a progressive resolution and carries no `Provenance`). | **only-mitigated** | `C-api` (a public merge primitive exists for direct `ProviderChain` use; sealing it would break the shipped `with_discovered` surface) | — (by construction of `deep_merge`'s signature; the escape is *using a different API*, not mis-driving this one). |
| I4 | **Provenance — the (value, provenance) pair is atomic.** | `resolve_progressive*` co-constructs `ProgressiveResolution { value, provenance }` and returns them together; a progressively-resolved value is never handed out without its map (the struct's only constructors are the two fold entries). | **parse-time / construction-stamped** (the pair) | — | `progressive_pair_is_atomic_via_into_parts`; `into_parts` / `value()` / `provenance()` only exist on the co-constructed struct. |
| I5 | **Provenance completeness — every effective leaf has a provenance.** | The fold **seeds from `bare()`** (which enumerates every field) with change-aware attribution, so every leaf present in the resolved config has an entry; the map is co-constructed in the same pass. | **construction-complete** (truly-unrep that a leaf is *missing*; the map covers exactly the resolved leaf-set) | `C-map` — provenance is a **path-keyed side-map**, not a per-field *type* wrapper: "field F's provenance" is a `BTreeMap` lookup, not `F`'s type. Closing that needs a proc-macro that wraps every field in `Sourced<T>` (design backlog). | `progressive_provenance_is_complete_over_every_leaf` (4 leaves ⇒ 4 entries); `progressive_attributes_nested_leaves_independently` (nested leaves each attributed). |
| I6 | **Provenance is meaningful (last-changer, not last-writer).** | A leaf is credited to the **highest tier that set it to its final value**: the change-aware fold skips a leaf whose incoming value equals the accumulated one, so a `prescribed_default()` built on `discovered()` that re-emits a detected value leaves that leaf credited to `Discovered`. | **truly-unrep** for the *label* (a value equal to the tier-below's is structurally not re-attributed) | — | `progressive_provenance_credits_each_leaf_to_its_producing_tier`; `seam_progressive_shows_detected_axis_through_prescribed`. |

---

## Gap closure (against the three stated gaps)

- **Gap 1 — `discovered()` hand-wired only in mado.** Closed by
  `TieredConfig::discovered_from_layers(&[&dyn DiscoveryLayer])` — a provided
  method reusing the existing `compose` machinery. A consumer's whole
  `discovered()` becomes one declarative layer list; no per-consumer merge
  code. See *before/after* below.
- **Gap 2 — `Default` tier skips discovery.** `resolve_tier(Default)` is
  **unchanged** (legacy single-tier; pinned tests stay green). The new
  **first-class default resolution** is `resolve_progressive()`, which folds
  `discovered()` *underneath* `prescribed_default()`, so a detected value
  shows through wherever prescribed doesn't override it
  (`progressive_discovery_shows_through_where_prescribed_does_not_override`).
- **Gap 3 — no typed provenance.** `Provenance{tier: ConfigTierKind,
  source: ConfigSource}` + `ProvenanceMap` + `resolve_progressive*` fold in
  `ConfigTier` `ClosedAxis` order, stamping provenance per leaf (I4–I6).

## Before / after — the kanchi seam (Gap 1)

```rust
// BEFORE (mado, hand-rolled struct literal — src/config.rs bare_plus_discovered):
fn discovered() -> Self {
    let mut c = Self::bare();
    let (w, h) = detect_window_dims_or_fallback();
    c.window.width = w; c.window.height = h;
    c.font_family  = detect_font_family_or_fallback().to_string();
    c.font_size    = detect_font_size_or_fallback();
    c.window.padding = detect_padding_or_fallback();
    c.behavior.scrollback_lines = detect_scrollback_lines_or_fallback() as usize;
    c // …8 hand-set fields, no provenance, no reuse
}

// AFTER (declarative — one DiscoveryLayer per kanchi axis-group):
fn discovered() -> Self {
    Self::discovered_from_layers(&[&WindowLayer, &FontLayer, &BehaviorLayer])
}
// where each layer's `discover()` builds a partial Dict from
// `kanchi::detect_*_or_fallback()`; the empty-Dict case degenerates to bare (I2),
// and `compose_with_provenance` over the same layers yields free per-leaf attribution.
```

## Burn-down backlog (named only-mitigated → deeper seal)

1. **I3′ → truly-unrep:** the escape is that `deep_merge` is `pub`. A future
   `SealedFold` type-state (the merged `Dict` reachable only through the
   ordered fold, `deep_merge` demoted to `pub(crate)`) would remove the
   out-of-order hand-merge path — gated on the `ProviderChain::with_discovered`
   consumers that call `compose` directly.
2. **I5 `C-map` → per-field type wrapper:** a `#[derive(Sourced)]` proc-macro
   emitting a parallel `struct FooProvenance { field: Provenance, … }` (or
   wrapping each field in `Sourced<T>`) makes "field F carries its provenance"
   a *type*, not a map lookup. Lives with the EMITTER SUBSTRATE macro farm.
3. **Provenance serde / attestation:** `Provenance` is serde-free today
   (`ConfigSource` carries no serde derive; adding it touches a heavily-pinned
   enum). An attestation manifest recording the tier-provenance histogram of a
   resolved config wants `Serialize` on both — a focused follow-up.

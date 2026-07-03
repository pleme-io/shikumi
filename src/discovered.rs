//! The **discovered-defaults tier** — environment-discovered layered defaults,
//! merged into a config chain *above* the developer's prescribed defaults but
//! *below* operator file/env config.
//!
//! A [`DiscoveryLayer`] inspects the running environment along one axis
//! (platform, cloud, orchestrator, instance class, tenancy, …) and emits a
//! *partial* config [`Dict`] — only the keys that axis wants to influence,
//! empty when its axis is undetectable. [`compose`] deep-merges an ordered
//! stack of layers coarse→specific (a more-specific layer overrides a coarser
//! one per leaf key), and [`crate::ProviderChain::with_discovered`] merges the
//! composed dict into the figment chain at the discovered-tier precedence:
//!
//! ```text
//! serde-defaults → prescribed_default() → DISCOVERED → file → env
//!    (floor)         (developer opinion)   (this tier)   (operator wins)
//! ```
//!
//! `kanchi` (the fleet environment-probe primitive) provides the typed axis
//! facts a layer reads; this module owns only the *composition* — kept here so
//! the merge precedence and the deep-merge semantics live in one place beside
//! [`crate::ProviderChain`].

use std::collections::BTreeMap;

use figment::value::{Dict, Value};

/// One environment axis that contributes a partial defaults layer.
///
/// Implementors read the environment (typically via `kanchi` probes) and
/// return only the config keys they want to shape. An axis that can't answer
/// returns an empty [`Dict`] — the clean degenerate (it contributes nothing,
/// so the next tier shows through), never a guess.
pub trait DiscoveryLayer {
    /// A stable, human-facing name for this layer (provenance / debugging).
    fn name(&self) -> &'static str;
    /// The partial config this layer contributes, given the current
    /// environment. Empty ⇒ this axis is undetectable / has no opinion.
    fn discover(&self) -> Dict;
}

/// Deep-merge `overlay` into `base`: nested dicts recurse (per-leaf-key,
/// overlay wins), every other value — scalars **and arrays** — replaces
/// wholesale.
///
/// This matches the observable semantics of figment's own `.merge()` (used by
/// [`crate::ProviderChain::with_discovered`]) for the cases config layers
/// actually hit: dict+dict recurses, scalar/array replaces (figment's
/// `Order::Merge` likewise replaces arrays — only `adjoin`/`admerge` concatenate,
/// which the chain never uses). So a coarse layer and a specific layer combine
/// the way the discovered tier later combines with the file tier. One caveat:
/// [`compose`] collapses all layers into one dict *before* the single figment
/// merge, so under a cross-layer key whose *type* changes between layers the
/// grouped result can differ from a strict sequential per-layer merge — benign
/// for the type-consistent axes a [`DiscoveryLayer`] emits.
pub fn deep_merge(base: &mut Dict, overlay: Dict) {
    for (key, incoming) in overlay {
        match (base.get_mut(&key), incoming) {
            // Two maps at the same key: recurse so sibling keys survive.
            (Some(Value::Dict(_, base_inner)), Value::Dict(_, over_inner)) => {
                deep_merge(base_inner, over_inner);
            }
            // Anything else: the overlay value wins wholesale.
            (_, incoming) => {
                base.insert(key, incoming);
            }
        }
    }
}

/// Compose an ordered stack of [`DiscoveryLayer`]s into one partial config
/// dict.
///
/// Layers are applied **coarse→specific**: later layers override earlier ones
/// per leaf key (deep-merged), so order the slice from the most general axis
/// (platform) to the most specific (instance class / tenancy). Empty-dict
/// layers contribute nothing — an undetectable axis is invisible, not a
/// clobber.
///
/// This is the [`compose_with_provenance`] projection that discards
/// attribution: `compose(layers) == compose_with_provenance(layers).dict`
/// for every input. Callers that need to answer "which layer wrote this
/// leaf?" (config-show renderers, discovered-tier attribution) reach for
/// [`compose_with_provenance`] directly; callers that only need the merged
/// [`Dict`] stay on this projection so the attribution [`BTreeMap`] is
/// dropped at the boundary.
#[must_use]
pub fn compose(layers: &[&dyn DiscoveryLayer]) -> Dict {
    compose_with_provenance(layers).dict
}

/// The provenance names of an ordered layer stack, in application order.
#[must_use]
pub fn layer_names(layers: &[&dyn DiscoveryLayer]) -> Vec<&'static str> {
    layers.iter().map(|layer| layer.name()).collect()
}

/// Per-leaf provenance for a composed [`DiscoveryLayer`] stack: the name
/// of the winning layer at every leaf path of the merged dict.
///
/// Keys are dotted-path components (`Vec<String>`, not a flat `"a.b"`
/// string) so keys containing `.` roundtrip unambiguously. Ordered
/// lexicographically ([`BTreeMap`] iteration), giving deterministic
/// iteration for debug dumps, config-show renderers, and tests. A
/// "leaf" is any non-dict value — scalars, arrays, and figment
/// [`Value::Empty`] all attribute at their own path; sibling keys
/// under a common dict prefix are attributed independently, so two
/// layers that touch different leaves under the same subtree each keep
/// credit for what they wrote.
///
/// This is the [`ConfigSource::Discovered`]-flavored substrate for the
/// future discovery-provenance thread noted on
/// [`crate::ProviderChain::with_discovered`]: a downstream store can
/// consult [`LayerAttribution::layer_of`] to answer "which
/// [`DiscoveryLayer`] shaped this leaf?" in `O(log n · path.len())`
/// without re-running the discovery pass, invert with
/// [`LayerAttribution::writes_by_layer`] to answer "which leaves did
/// each layer shape?" in one pass — closing the leaf↔layer
/// bidirectional query surface at one primitive — collapse that
/// inverse onto a per-layer count with
/// [`LayerAttribution::leaf_counts_by_layer`] to answer "how many
/// leaves did each layer shape?" in `O(n log k)` and `O(k)` space
/// (`k` = distinct-writer count) without materializing a
/// `Vec<&[String]>` per writer, further collapse that count onto the
/// bare surviving-writer name-set with
/// [`LayerAttribution::surviving_layer_names`] to answer "which axes'
/// opinions survived the merge?" in `O(n log k)` and `O(k)` space
/// without materializing the counters either — the post-merge dual
/// of the pre-merge [`contributor_names`] — or restrict any of those
/// directions to a subtree with [`LayerAttribution::subtree_iter`] /
/// [`LayerAttribution::subtree`] to answer "under this config path,
/// who wrote what?" in `O(log n + m · path.len())` (`m` matching
/// leaves) via a single [`BTreeMap::range`] seek plus a linear walk
/// that halts at the subtree boundary.
///
/// [`ConfigSource::Discovered`]: crate::ConfigSource
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerAttribution {
    inner: BTreeMap<Vec<String>, &'static str>,
}

impl LayerAttribution {
    /// Number of leaves attributed. Zero when every layer emitted an
    /// empty [`Dict`] (or no layers were composed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no leaves are attributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Name of the winning [`DiscoveryLayer`] at the leaf named by
    /// dotted `path`, or [`None`] if `path` names no leaf in the
    /// composed dict.
    ///
    /// **Cost.** `O(log n · path.len())` — one [`BTreeMap::get`]
    /// against an owned key allocated once per call. Allocation is
    /// bounded by the path depth (typically 1–5 for config paths),
    /// not by the total leaf count `n`. Callers that already carry an
    /// owned path reach for [`Self::layer_of_owned`] to skip the
    /// per-call allocation.
    #[must_use]
    pub fn layer_of(&self, path: &[&str]) -> Option<&'static str> {
        // `BTreeMap<Vec<String>, _>::get<Q>(&Q)` requires
        // `Vec<String>: Borrow<Q>`. The Borrow chain is
        // `Vec<T>: Borrow<[T]>`, so `[String]` is the smallest key
        // type the map accepts — an allocated `Vec<String>` at each
        // call, discarded on return. The `&str` → `String` mapping
        // is unavoidable at this seam: the map's keys are owned
        // (they outlive any single composition pass), but the
        // caller's path is borrowed and cannot be compared against
        // an owned Ord key without materializing owned strings
        // somewhere.
        self.layer_of_owned(&path.iter().map(|&s| s.to_owned()).collect::<Vec<String>>())
    }

    /// Allocation-free variant of [`Self::layer_of`] for callers that
    /// already carry an owned path (`&[String]`), typically iterating
    /// a composed dict's own keys.
    ///
    /// **Cost.** `O(log n · path.len())` — one [`BTreeMap::get`] on
    /// the borrowed slice, no allocation.
    #[must_use]
    pub fn layer_of_owned(&self, path: &[String]) -> Option<&'static str> {
        self.inner.get(path).copied()
    }

    /// Sorted iterator over `(path, layer)` entries. Ordering is
    /// lexicographic by path — the [`BTreeMap`] iteration order.
    ///
    /// # Reverse walk
    ///
    /// The returned iterator is [`DoubleEndedIterator`]: the backing
    /// `BTreeMap<Vec<String>, _>::iter()` is `DoubleEndedIterator +
    /// Clone` and [`Iterator::map`] preserves both because the closure
    /// captures nothing (a zero-size, `Copy` function pointer under the
    /// hood). Consumers that render the attribution in
    /// specific→coarse order — a config-show pane that walks the
    /// leaves right-to-left in lex order — reach for `iter().rev()`
    /// directly, skipping the full `.collect::<Vec<_>>()` →
    /// `.into_iter().rev()` roundtrip the prior bare-`impl Iterator`
    /// return forced.
    ///
    /// # Independent walks
    ///
    /// The returned iterator is [`Clone`]. Cloning the handle produces
    /// an independent walk over the same underlying [`BTreeMap`] — no
    /// second `Vec` materialization for callers that need to iterate
    /// twice (render once, then find a position on a re-walk).
    #[must_use]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&[String], &'static str)> + Clone + '_ {
        self.inner.iter().map(|(p, l)| (p.as_slice(), *l))
    }

    /// Inverse projection of [`Self::layer_of`]: for every
    /// [`DiscoveryLayer`] that wrote at least one leaf, the sorted
    /// list of paths credited to it.
    ///
    /// Peer to [`Self::layer_of`] on the (path → layer) axis — this
    /// closes the leaf↔layer bidirectional query surface. A
    /// config-show renderer walks
    /// [`Self::writes_by_layer`]`().iter()` once to dump every
    /// leaf under its writing layer; a diagnostics pass that reports
    /// "layer `X` shaped these leaves" reaches for this map directly.
    ///
    /// **Structure.** The outer [`BTreeMap`] is keyed by layer name
    /// (sorted lex on `&'static str`, deterministic iteration); each
    /// inner `Vec<&[String]>` lists that layer's paths in the same
    /// lex order [`Self::iter`] would emit them (the underlying
    /// [`BTreeMap`]'s ordering). Cost `O(n log k)` where `n` is the
    /// leaf count and `k` is the distinct-layer count — one pass
    /// over the attribution map, one [`BTreeMap`] insertion per
    /// leaf.
    ///
    /// **Partition law.** The union of every inner `Vec` equals
    /// [`Self::iter`]`().map(|(p, _)| p)` verbatim (every leaf
    /// belongs to exactly one layer); the sum of every inner
    /// `Vec::len()` equals [`Self::len`]; for every
    /// `(layer, paths)` entry, every `path` in `paths` satisfies
    /// [`Self::layer_of_owned`]`(path) == Some(layer)`. Pinned by
    /// `writes_by_layer_partitions_leaves_by_writer` in
    /// `src/discovered.rs`'s test module.
    ///
    /// Callers that only need the outer name-set — "which writers
    /// survived the merge?" without the per-writer path lists —
    /// reach for [`Self::surviving_layer_names`], which collects
    /// the same lex-ordered keys via a `BTreeSet` without
    /// allocating the `Vec<&[String]>` buckets this seam builds.
    ///
    /// **Subtree altitude.** [`Self::subtree_writes_by_layer`]
    /// extends this wide seam to a `prefix`, answering the same
    /// "which paths did each layer shape?" question restricted to a
    /// single subtree — the paths-carrying companion to
    /// [`Self::subtree_surviving_layer_names`] (name-set) and
    /// [`Self::subtree_leaf_counts_by_layer`] (histogram), computed
    /// directly on [`Self::subtree_iter`] without materializing a
    /// fresh restricted attribution.
    ///
    /// **Single-layer altitude.** [`Self::writes_of_layer`] restricts
    /// this wide seam to *one* writer, answering the same "which
    /// paths did each layer shape?" question focused on a single
    /// axis — the layer-axis dual of the path-axis
    /// [`Self::subtree_writes_by_layer`], computed by a single
    /// filtered pass over `self.inner` without materializing the
    /// full per-writer map or paying the `O(n log k)` `BTreeMap`
    /// construction cost across peer writers just to keep one
    /// bucket.
    #[must_use]
    pub fn writes_by_layer(&self) -> BTreeMap<&'static str, Vec<&[String]>> {
        let mut out: BTreeMap<&'static str, Vec<&[String]>> = BTreeMap::new();
        for (path, layer) in &self.inner {
            out.entry(*layer).or_default().push(path.as_slice());
        }
        out
    }

    /// Compact histogram companion to [`Self::writes_by_layer`]: for
    /// every [`DiscoveryLayer`] that wrote at least one leaf, the
    /// number of leaves credited to it. `O(n log k)` time, `O(k)`
    /// space — one pass over the attribution map, one [`BTreeMap`]
    /// counter increment per leaf. `k` is the distinct-layer count.
    ///
    /// Peer to [`Self::writes_by_layer`] on the sizing axis: callers
    /// that need only "how many leaves did each layer shape?" — audit
    /// dashboards, size badges on a config-show pane, a diagnostics
    /// pass that reports the top-writing layer — reach for this map
    /// directly instead of paying the `O(n)` `Vec<&[String]>`
    /// allocation per writer that [`Self::writes_by_layer`] performs
    /// just to call [`Vec::len`] on it. Two `BTreeMap<&'static str,
    /// _>` seams onto the same attribution — one carries the paths,
    /// one carries the counts — and both share the outer lex order
    /// on layer name (deterministic iteration).
    ///
    /// **Partition-count law.** The sum of every value equals
    /// [`Self::len`], the map's key set equals
    /// [`Self::writes_by_layer`]`().keys()` verbatim, and each value
    /// equals the corresponding [`Self::writes_by_layer`] bucket's
    /// [`Vec::len`]. Pinned by
    /// `leaf_counts_by_layer_partition_count_law` and
    /// `leaf_counts_by_layer_agrees_with_writes_by_layer_sizes` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Empty layer.** A layer that emitted an empty [`Dict`]
    /// contributes no leaves, so no bucket key — mirrors the
    /// "undetectable axis is invisible" invariant
    /// [`compose_with_provenance`] already upholds on the merged
    /// dict and [`Self::writes_by_layer`] mirrors on the paths axis.
    ///
    /// **Subtree altitude.** [`Self::subtree_leaf_counts_by_layer`]
    /// extends this compact histogram to a `prefix`, answering the
    /// same "how many leaves did each layer shape?" question
    /// restricted to a single subtree — the histogram companion to
    /// [`Self::subtree_surviving_layer_names`], computed directly on
    /// [`Self::subtree_iter`] without materializing a fresh restricted
    /// attribution.
    ///
    /// **Single-layer altitude.** [`Self::leaf_count_of_layer`]
    /// restricts this compact histogram to *one* writer, answering
    /// the same "how many leaves did each layer shape?" question
    /// focused on a single axis — the layer-axis dual of the
    /// path-axis [`Self::subtree_leaf_counts_by_layer`], computed
    /// by a single counted pass over `self.inner.values()` with
    /// zero allocation, sparing the peer-writer counter entries
    /// [`Self::leaf_counts_by_layer`] materializes.
    ///
    /// **Argmax altitude.** [`Self::dominant_layer`] collapses this
    /// histogram to its argmax — the scalar single-writer
    /// projection answering "who owns the largest share?" with
    /// deterministic lex-name tie-break — the audit query one step
    /// past the wide/count seams, at [`Option<&'static str>`]
    /// altitude.
    #[must_use]
    pub fn leaf_counts_by_layer(&self) -> BTreeMap<&'static str, usize> {
        let mut out: BTreeMap<&'static str, usize> = BTreeMap::new();
        for layer in self.inner.values() {
            *out.entry(*layer).or_insert(0) += 1;
        }
        out
    }

    /// Compact name-set companion to [`Self::writes_by_layer`] and
    /// [`Self::leaf_counts_by_layer`]: every [`DiscoveryLayer`] with
    /// at least one live leaf in the attribution, in the same lex
    /// order on layer name the wide/count seams share.
    ///
    /// The **post-merge** dual of the top-level [`contributor_names`]:
    /// that primitive answers "which axes had an opinion in the
    /// discover pass" (application order, may include writers wholly
    /// overridden downstream); this projection answers "which axes'
    /// opinions survived the merge" (lex on layer name, drops writers
    /// whose writes were purged by a later wholesale replace at the
    /// same or an ancestor path). The two coincide iff no writer was
    /// wholly overridden.
    ///
    /// **Cost.** One pass over `self.inner.values()`, one
    /// [`BTreeSet`] insertion per leaf, one [`Vec`] collect.
    /// `O(n log k)` time and `O(k)` space — where `k` is the
    /// distinct-writer count and `n` the leaf count.
    /// [`Self::writes_by_layer`]`().into_keys().collect()` would pay
    /// `O(n)` extra allocations on the per-writer `Vec<&[String]>`
    /// buckets, and [`Self::leaf_counts_by_layer`]`().into_keys().collect()`
    /// would pay `O(k)` extra on the counters — both allocate map
    /// values just to discard them. Callers that need only the writer
    /// name-set (audit lists, "which axes survive the merge" banners,
    /// health-check gauges over a fixed layer stack) reach for this
    /// seam directly.
    ///
    /// **Partition-name law.** The result equals
    /// [`Self::writes_by_layer`]`().into_keys().collect()` verbatim
    /// and [`Self::leaf_counts_by_layer`]`().into_keys().collect()`
    /// verbatim (both lex on layer name); its length equals
    /// [`Self::writes_by_layer`]`().len()` and
    /// [`Self::leaf_counts_by_layer`]`().len()`. An empty
    /// attribution yields the empty vector. Pinned by
    /// `surviving_layer_names_agrees_with_writes_by_layer_keys`,
    /// `surviving_layer_names_agrees_with_leaf_counts_by_layer_keys`,
    /// and `surviving_layer_names_empty_when_no_leaves` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Subset invariant vs. [`contributor_names`].** For every
    /// layer stack `layers`, the set of names returned by
    /// `compose_with_provenance(layers).attribution.surviving_layer_names()`
    /// is a subset of `contributor_names(layers)`. Strict subset iff
    /// at least one contributor's writes were all purged by a later
    /// layer (wholesale replace at the top-level key, or a
    /// dict-over-scalar / scalar-over-dict reshape at an ancestor
    /// path). Pinned by `surviving_layer_names_subset_of_contributor_names`.
    ///
    /// **Subtree altitude.** [`Self::subtree_surviving_layer_names`]
    /// extends this compact projection to a `prefix`, answering the
    /// same "which axes' opinions survived" question restricted to a
    /// single sub-tree — the natural pane a per-subsystem config-show
    /// renderer reaches for.
    ///
    /// **Argmax altitude.** [`Self::dominant_layer`] collapses the
    /// name-set to its top counter-holder — the scalar
    /// single-writer projection answering "which of these survivors
    /// owns the largest share?" with deterministic lex-name
    /// tie-break, one step down from this compact name-set.
    #[must_use]
    pub fn surviving_layer_names(&self) -> Vec<&'static str> {
        use std::collections::BTreeSet;
        let mut set: BTreeSet<&'static str> = BTreeSet::new();
        for &layer in self.inner.values() {
            set.insert(layer);
        }
        set.into_iter().collect()
    }

    /// Iterator over the `(path, layer)` entries whose path descends
    /// from (or equals) `prefix` — the leaves of the sub-tree rooted
    /// at `prefix`, in the same lex order [`Self::iter`] emits. A
    /// `prefix` of `&[]` matches every entry and yields the same
    /// sequence as [`Self::iter`]; a `prefix` that names an existing
    /// leaf yields that leaf plus every descendant; a `prefix` that
    /// names no subtree yields the empty iterator.
    ///
    /// **Cost.** `O(log n + m · path.len())` where `n` is the total
    /// leaf count and `m` is the number of matching leaves — one
    /// [`BTreeMap::range`] seek to the subtree's first entry, then a
    /// linear walk that halts at the first non-prefixed key.
    /// Callers that would otherwise walk [`Self::iter`] and filter
    /// pay a full `O(n)` scan even when the subtree is small; this
    /// primitive owns the range-based walk once, so consumers don't
    /// re-implement the [`BTreeMap`] range idiom on every config-show
    /// pane.
    ///
    /// **Contiguity.** In the underlying `BTreeMap<Vec<String>, _>`'s
    /// lex order every entry prefixed by `prefix` occupies a
    /// contiguous run, and the take-while formulation reads the
    /// `path_has_prefix` invariant directly rather than computing a
    /// lex successor of `prefix` — so a prefix-extending sibling
    /// (e.g. leaf at `["breatheZ"]` when the subtree is `["breathe"]`,
    /// which lands lex-adjacent but is *not* a descendant) is
    /// correctly excluded at the boundary. Pinned by
    /// `subtree_iter_stops_at_prefix_extending_sibling_key` in this
    /// module's test cohort.
    ///
    /// # Independent walks
    ///
    /// The returned iterator is [`Clone`]. The backing
    /// `BTreeMap::range` is `Clone`, the `take_while` closure captures
    /// only the `Copy` reborrow `prefix: &'a [String]`, and the `map`
    /// closure captures nothing — so the compound iterator carries
    /// `Clone` at zero runtime cost. Callers that need to walk the
    /// subtree twice (render once, then re-walk to find a positional
    /// match) clone the handle up front instead of allocating an
    /// intermediate `Vec` or re-invoking the range seek.
    ///
    /// # No reverse walk
    ///
    /// The returned iterator is *not* [`DoubleEndedIterator`]: while
    /// the underlying [`BTreeMap`] range yields both ends in
    /// `O(log n)`, [`Iterator::take_while`] has no back-end — it
    /// cannot know where the "would-stop" boundary sits without
    /// walking forward. Callers that need the subtree in reverse
    /// order [`Iterator::collect`] into an owned [`Vec`] and reverse
    /// it, or reach for [`Self::subtree`] to materialize the
    /// restricted attribution whose [`Self::iter`] is
    /// double-ended.
    pub fn subtree_iter<'a>(
        &'a self,
        prefix: &'a [String],
    ) -> impl Iterator<Item = (&'a [String], &'static str)> + Clone + 'a {
        use std::ops::Bound;
        self.inner
            .range::<[String], _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(move |(k, _)| path_has_prefix(k, prefix))
            .map(|(k, l)| (k.as_slice(), *l))
    }

    /// Projection: a fresh [`LayerAttribution`] restricted to the
    /// leaves reachable from `prefix` — the [`Self::subtree_iter`]
    /// walk collected into a new [`BTreeMap`] with keys allocated
    /// fresh. Every method on the returned attribution
    /// ([`Self::layer_of`], [`Self::writes_by_layer`], [`Self::iter`],
    /// [`Self::len`], recursive [`Self::subtree`]) sees only the
    /// restricted set — the substrate reuses itself at the subtree
    /// altitude with no per-consumer filter to write.
    ///
    /// Equal to [`Self::subtree_iter`] `.collect()` with the same
    /// paths and layers. `subtree(&[])` equals `self`; `subtree` of a
    /// prefix that names no subtree is empty; a leaf at `prefix`
    /// itself is included (the reflexive case).
    ///
    /// **Cost.** `O(log n + m · path.len())` for the range seek plus
    /// the walk, then `O(m)` allocations for the fresh owned keys.
    #[must_use]
    pub fn subtree(&self, prefix: &[String]) -> LayerAttribution {
        LayerAttribution {
            inner: self
                .subtree_iter(prefix)
                .map(|(p, l)| (p.to_vec(), l))
                .collect(),
        }
    }

    /// The **subtree-restricted** dual of [`Self::surviving_layer_names`]:
    /// every [`DiscoveryLayer`] with at least one live leaf under (or
    /// at) `prefix`, in the same lex order on layer name the top-level
    /// projection uses. A `prefix` of `&[]` matches every entry and
    /// equals [`Self::surviving_layer_names`] verbatim; a `prefix` that
    /// names no subtree yields the empty vector.
    ///
    /// Extends the compact name-set family to the subtree altitude,
    /// answering "which axes' opinions survived the merge *under this
    /// config path*?" — the natural diagnostic pane for a config-show
    /// renderer that groups per-subtree writers, or a health-check
    /// gauge that watches a single subsystem's writer set. The wide
    /// dual is [`Self::subtree_writes_by_layer`]`(prefix)` (direct on
    /// [`Self::subtree_iter`]) and the count dual is
    /// [`Self::subtree_leaf_counts_by_layer`]`(prefix)` (also direct
    /// on [`Self::subtree_iter`]) — the same outer key set, carrying
    /// per-writer path lists / per-writer counters instead of the
    /// bare name-set this projection returns.
    ///
    /// **Cost.** `O(log n + m log k)` where `n` is the total leaf
    /// count, `m` is the number of matching leaves, and `k` is the
    /// distinct-writer count *under the subtree* — one
    /// [`BTreeMap::range`] seek to the subtree's first entry, a linear
    /// walk that halts at the first non-prefixed key (via
    /// [`Self::subtree_iter`]'s take-while), one [`BTreeSet`]
    /// insertion per leaf. Skips the `O(m)` owned-key allocations
    /// [`Self::subtree`]`(prefix).surviving_layer_names()` would pay
    /// on the fresh restricted attribution just to discard the paths.
    ///
    /// **Partition-name law.** The result equals
    /// [`Self::subtree`]`(prefix).surviving_layer_names()` verbatim on
    /// every input (same lex order, same name-set); its length equals
    /// [`Self::subtree`]`(prefix).surviving_layer_names().len()`. An
    /// empty subtree yields the empty vector. Pinned by
    /// `subtree_surviving_layer_names_agrees_with_subtree_surviving_layer_names`,
    /// `subtree_surviving_layer_names_empty_prefix_equals_surviving_layer_names`,
    /// and `subtree_surviving_layer_names_absent_prefix_is_empty` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Subset invariant vs. [`Self::surviving_layer_names`].** For
    /// every prefix, `subtree_surviving_layer_names(prefix)` is a
    /// subset of `surviving_layer_names()`. Strict subset iff at least
    /// one global-surviving writer wrote nothing under `prefix`.
    /// Pinned by
    /// `subtree_surviving_layer_names_subset_of_surviving_layer_names`.
    ///
    /// **Prefix-extending sibling boundary.** Inherited from
    /// [`Self::subtree_iter`]: a lex-adjacent sibling that shares the
    /// string prefix of the last `prefix` element but is not a path
    /// descendant (e.g. `["breatheZ"]` vs prefix `["breathe"]`) is
    /// correctly excluded — the writer of that sibling is not credited
    /// against this subtree. Pinned by
    /// `subtree_surviving_layer_names_stops_at_prefix_extending_sibling_key`.
    ///
    /// **Argmax altitude.** [`Self::subtree_dominant_layer`]`(prefix)`
    /// collapses this subtree-restricted name-set to its top
    /// counter-holder — the scalar single-writer projection answering
    /// "which of these subtree-survivors owns the largest share
    /// here?" with deterministic lex-name tie-break, at
    /// [`Option<&'static str>`] altitude — the natural
    /// top-writer-per-subsystem gauge one step past this compact
    /// name-set.
    ///
    /// [`writes_by_layer`]: Self::writes_by_layer
    /// [`leaf_counts_by_layer`]: Self::leaf_counts_by_layer
    #[must_use]
    pub fn subtree_surviving_layer_names(&self, prefix: &[String]) -> Vec<&'static str> {
        use std::collections::BTreeSet;
        let mut set: BTreeSet<&'static str> = BTreeSet::new();
        for (_, layer) in self.subtree_iter(prefix) {
            set.insert(layer);
        }
        set.into_iter().collect()
    }

    /// The **subtree-restricted** dual of [`Self::leaf_counts_by_layer`]:
    /// for every [`DiscoveryLayer`] that wrote at least one leaf under
    /// (or at) `prefix`, the number of leaves credited to it under the
    /// subtree, in the same lex order on layer name the top-level
    /// projection uses. A `prefix` of `&[]` matches every entry and
    /// equals [`Self::leaf_counts_by_layer`] verbatim; a `prefix` that
    /// names no subtree yields the empty map.
    ///
    /// The **count seam** on the subtree ladder, complementing the
    /// compact name-set [`Self::subtree_surviving_layer_names`] and
    /// the direct wide seam [`Self::subtree_writes_by_layer`] — both
    /// also direct on [`Self::subtree_iter`]. Direct on
    /// [`Self::subtree_iter`] — one range seek, a take-while walk over
    /// matching leaves, one [`BTreeMap`] counter increment per leaf —
    /// so it skips the `O(m)` owned-key allocations
    /// [`Self::subtree`]`(prefix).leaf_counts_by_layer()` would perform
    /// on a materialized restricted attribution just to discard the
    /// paths. Consumers that only need per-layer counts under a
    /// subtree (audit dashboards per subsystem, size badges on a
    /// config-show pane grouped by writer, a diagnostics gauge
    /// reporting "which axis wrote the most leaves under `breathe.*`?")
    /// reach for this seam directly.
    ///
    /// **Cost.** `O(log n + m + k)` where `n` is the total leaf count,
    /// `m` is the number of matching leaves under the subtree, and `k`
    /// is the distinct-writer count *under the subtree* — one
    /// [`BTreeMap::range`] seek to the subtree's first entry, a linear
    /// walk that halts at the first non-prefixed key (via
    /// [`Self::subtree_iter`]'s take-while), one [`BTreeMap`]
    /// counter increment per leaf.
    ///
    /// **Partition-count law.** The sum of every value equals the
    /// number of leaves under the subtree, i.e.
    /// [`Self::subtree_iter`]`(prefix).count()` and
    /// [`Self::subtree`]`(prefix).len()` — the per-layer histogram
    /// partitions the subtree's leaf set by winning layer.
    ///
    /// **Cross-projection identities.** The result equals
    /// [`Self::subtree`]`(prefix).leaf_counts_by_layer()` verbatim
    /// (same lex order on layer name, same counter values), and its
    /// key set equals [`Self::subtree_surviving_layer_names`]`(prefix)`
    /// verbatim — the three subtree-restricted seams share their outer
    /// key column.
    ///
    /// **Subset invariant vs. [`Self::leaf_counts_by_layer`].** For
    /// every prefix and every writer `w`,
    /// `subtree_leaf_counts_by_layer(prefix).get(w) <=
    /// leaf_counts_by_layer().get(w)` — a subtree can only credit a
    /// writer with a subset of the leaves the parent credits it with.
    /// Strict `<` iff `w` wrote at least one leaf outside the subtree.
    ///
    /// **Prefix-extending sibling boundary.** Inherited from
    /// [`Self::subtree_iter`]: a lex-adjacent sibling that shares the
    /// string prefix of the last `prefix` element but is not a path
    /// descendant (e.g. `["breatheZ"]` vs prefix `["breathe"]`) is
    /// correctly excluded — the writer of that sibling is not counted
    /// against this subtree.
    ///
    /// **Single-layer altitude.** The single-writer dual at this
    /// altitude is [`Self::subtree_leaf_count_of_layer`]`(prefix,
    /// layer)` — the compact scalar for one writer under one subtree.
    /// A consumer that only cares about one writer's count under one
    /// subtree reaches for that seam directly at zero allocation cost
    /// instead of paying the per-writer counter map this primitive
    /// builds across peer axes just to keep one entry.
    ///
    /// **Argmax altitude.** [`Self::subtree_dominant_layer`]`(prefix)`
    /// collapses this histogram to its argmax — the scalar
    /// single-writer projection answering "who owns the largest
    /// share under this subtree?" with deterministic lex-name
    /// tie-break, at [`Option<&'static str>`] altitude — the natural
    /// top-writer-per-subsystem gauge one step past this histogram.
    ///
    /// [`writes_by_layer`]: Self::writes_by_layer
    #[must_use]
    pub fn subtree_leaf_counts_by_layer(&self, prefix: &[String]) -> BTreeMap<&'static str, usize> {
        let mut out: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (_, layer) in self.subtree_iter(prefix) {
            *out.entry(layer).or_insert(0) += 1;
        }
        out
    }

    /// The **subtree-restricted** dual of [`Self::writes_by_layer`]:
    /// for every [`DiscoveryLayer`] that wrote at least one leaf under
    /// (or at) `prefix`, the sorted list of paths credited to it under
    /// the subtree, in the same lex order on layer name the top-level
    /// projection uses. A `prefix` of `&[]` matches every entry and
    /// equals [`Self::writes_by_layer`] verbatim; a `prefix` that names
    /// no subtree yields the empty map.
    ///
    /// The **wide seam** on the subtree ladder — the paths-carrying
    /// companion to the compact name-set
    /// [`Self::subtree_surviving_layer_names`] and the count histogram
    /// [`Self::subtree_leaf_counts_by_layer`]. All three seams factor
    /// through [`Self::subtree_iter`] (one [`BTreeMap::range`] seek +
    /// take-while walk that halts at the subtree boundary), so this
    /// primitive skips the `O(m)` owned-key allocations
    /// [`Self::subtree`]`(prefix).writes_by_layer()` would perform to
    /// materialize a fresh restricted attribution just to expose its
    /// borrowed paths. Consumers that need the per-writer path lists
    /// under a subtree (a config-show pane dumping every leaf under a
    /// subsystem grouped by writer, a diagnostics pass that prints
    /// "layer `X` shaped these leaves under `breathe.*`") reach for
    /// this seam directly.
    ///
    /// **Cost.** `O(log n + m log k)` where `n` is the total leaf
    /// count, `m` is the number of matching leaves under the subtree,
    /// and `k` is the distinct-writer count *under the subtree* — one
    /// [`BTreeMap::range`] seek to the subtree's first entry, a linear
    /// walk that halts at the first non-prefixed key (via
    /// [`Self::subtree_iter`]'s take-while), one [`BTreeMap`] entry
    /// lookup + [`Vec`] push per leaf.
    ///
    /// **Partition law.** For every prefix, the union of every inner
    /// [`Vec`] equals [`Self::subtree_iter`]`(prefix).map(|(p, _)| p)`
    /// verbatim (every subtree leaf belongs to exactly one bucket);
    /// the sum of every inner [`Vec::len`] equals
    /// [`Self::subtree_iter`]`(prefix).count()` and
    /// [`Self::subtree`]`(prefix).len()`; for every `(layer, paths)`
    /// entry, every `path` in `paths` satisfies
    /// [`Self::layer_of_owned`]`(path) == Some(layer)` on the parent
    /// attribution. Within each inner [`Vec`], paths are in the lex
    /// order [`Self::subtree_iter`] emits them (the underlying
    /// [`BTreeMap`]'s ordering).
    ///
    /// **Cross-projection identities.** The result equals
    /// [`Self::subtree`]`(prefix).writes_by_layer()` on every input up
    /// to the borrow lifetime (paths under this primitive borrow from
    /// `self`; paths under the composition borrow from the freshly
    /// materialized subtree — the underlying dotted components are
    /// pointwise equal). Its key set equals
    /// [`Self::subtree_surviving_layer_names`]`(prefix)` verbatim and
    /// [`Self::subtree_leaf_counts_by_layer`]`(prefix).into_keys()`
    /// verbatim — the three subtree-restricted seams share their
    /// outer key column. For every `(layer, paths)` entry,
    /// `paths.len()` equals
    /// [`Self::subtree_leaf_counts_by_layer`]`(prefix).get(layer)`
    /// unwrapped.
    ///
    /// **Subset invariant vs. [`Self::writes_by_layer`].** For every
    /// prefix and every writer `w`,
    /// `subtree_writes_by_layer(prefix).get(w)` is a subsequence of
    /// `writes_by_layer().get(w)` (both lex-ordered, subtree paths ⊆
    /// parent paths). Strict subsequence iff `w` wrote at least one
    /// leaf outside the subtree.
    ///
    /// **Prefix-extending sibling boundary.** Inherited from
    /// [`Self::subtree_iter`]: a lex-adjacent sibling that shares the
    /// string prefix of the last `prefix` element but is not a path
    /// descendant (e.g. `["breatheZ"]` vs prefix `["breathe"]`) is
    /// correctly excluded — the writer of that sibling's bucket does
    /// not carry that path under this subtree, even though the parent
    /// [`Self::writes_by_layer`] does.
    ///
    /// **Single-layer altitude.** The single-writer dual at this
    /// altitude is [`Self::subtree_writes_of_layer`]`(prefix, layer)`
    /// — the wide seam for one writer under one subtree. A consumer
    /// that only cares about one writer's paths under one subtree
    /// reaches for that seam directly to skip the per-writer bucket
    /// this primitive materializes across peer axes just to expose
    /// one bucket.
    #[must_use]
    pub fn subtree_writes_by_layer<'a>(
        &'a self,
        prefix: &'a [String],
    ) -> BTreeMap<&'static str, Vec<&'a [String]>> {
        let mut out: BTreeMap<&'static str, Vec<&'a [String]>> = BTreeMap::new();
        for (path, layer) in self.subtree_iter(prefix) {
            out.entry(layer).or_default().push(path);
        }
        out
    }

    /// The **single-layer** dual of [`Self::writes_by_layer`]: the
    /// paths credited to `layer`, in lex path order, without
    /// materializing the full per-writer map. A `layer` name that
    /// contributed no surviving leaf yields the empty vector.
    ///
    /// The **layer-axis** wide seam — the counterpart of the
    /// **path-axis** wide seam [`Self::subtree_writes_by_layer`].
    /// Where the subtree ladder restricts the attribution to a
    /// prefix, this primitive restricts it to a single writer. Both
    /// factor through one filtered pass over `self.inner` so that a
    /// focused query never pays the cost of the peer axis: a
    /// per-layer config-show pane, an audit dashboard slicing by
    /// axis, a diagnostics pass that reports "here's every leaf
    /// axis `X` shaped" reaches for this seam directly instead of
    /// paying the `O(n log k)` [`BTreeMap`]-construction cost
    /// [`Self::writes_by_layer`] pays across every writer just to
    /// keep one bucket.
    ///
    /// **Cost.** `O(n)` time and `O(m)` space, where `n` is the total
    /// leaf count and `m` is the number of leaves this writer shaped
    /// — one pass over `self.inner`, one predicate check per entry,
    /// one [`Vec`] push per match. The full per-writer map is never
    /// materialized: peer writers pay no allocation.
    ///
    /// **Cross-projection identity.** The result equals
    /// [`Self::writes_by_layer`]`().get(layer).cloned().unwrap_or_default()`
    /// verbatim on every input, and its length equals
    /// [`Self::leaf_count_of_layer`]`(layer)` and
    /// [`Self::leaf_counts_by_layer`]`().get(layer).copied().unwrap_or(0)`.
    /// Pinned by `writes_of_layer_agrees_with_writes_by_layer_bucket`
    /// in `src/discovered.rs`'s test module.
    ///
    /// **Lex order preservation.** Paths land in the same lex order
    /// [`Self::iter`] emits them (the underlying [`BTreeMap`]'s
    /// ordering) — the identity property one axis restriction shares
    /// with the top-level projection it filters. Pinned by
    /// `writes_of_layer_preserves_lex_order`.
    ///
    /// **Missing writer.** A `layer` name that never appears in the
    /// attribution — whether because it never contributed or its
    /// writes were purged by a later wholesale replace — yields the
    /// empty vector, mirroring `writes_by_layer().get(layer)`
    /// returning [`None`]. Distinguishing "wrote-but-purged" from
    /// "never-wrote-in-the-first-place" is [`contributor_names`]'s
    /// job at the pre-merge altitude; this projection is purely
    /// post-merge.
    ///
    /// **Subtree altitude.** The subtree-restricted counterpart is
    /// [`Self::subtree_writes_of_layer`]`(prefix, layer)` — the
    /// **2D-restricted** cell on the {path axis, layer axis} ×
    /// {restricted, free} grid. A consumer scoped to a subsystem
    /// (e.g. "which paths did axis `X` shape under `breathe.*`?")
    /// reaches for that seam directly to skip both the peer-writer
    /// allocation this primitive pays across peer axes and the
    /// extra-subtree scan the top-level layer-axis restriction
    /// pays across leaves outside the prefix.
    #[must_use]
    pub fn writes_of_layer<'a>(&'a self, layer: &str) -> Vec<&'a [String]> {
        self.inner
            .iter()
            .filter_map(|(p, l)| (*l == layer).then_some(p.as_slice()))
            .collect()
    }

    /// The **single-layer** dual of [`Self::leaf_counts_by_layer`]:
    /// the number of leaves credited to `layer`, without materializing
    /// the full per-writer counter map. A `layer` name that
    /// contributed no surviving leaf yields zero.
    ///
    /// The compact scalar companion to [`Self::writes_of_layer`] on
    /// the layer axis — the counterpart of the path-axis
    /// [`Self::subtree_leaf_counts_by_layer`]. Consumers that need
    /// only "how many leaves did axis `X` shape?" — a size badge on a
    /// per-layer config-show pane, a health-check gauge on one
    /// writer, a "top-writer" ranking loop — reach for this scalar
    /// seam directly instead of paying the `O(n log k)` counter map
    /// allocation [`Self::leaf_counts_by_layer`] pays across every
    /// writer just to keep one entry.
    ///
    /// **Cost.** `O(n)` time and no allocation — one pass over
    /// `self.inner.values()`, one predicate check per entry, one
    /// counter increment per match.
    ///
    /// **Cross-projection identity.** The result equals
    /// [`Self::writes_of_layer`]`(layer).len()` and
    /// [`Self::leaf_counts_by_layer`]`().get(layer).copied().unwrap_or(0)`
    /// verbatim on every input. Pinned by
    /// `leaf_count_of_layer_agrees_with_leaf_counts_by_layer_bucket`
    /// and `leaf_count_of_layer_agrees_with_writes_of_layer_len`.
    ///
    /// **Partition-count law.** The sum of `leaf_count_of_layer(l)`
    /// over every `l` in [`Self::surviving_layer_names`] equals
    /// [`Self::len`] — every leaf belongs to exactly one surviving
    /// writer's counter. Pinned by
    /// `leaf_count_of_layer_partition_count_law`.
    ///
    /// **Missing writer.** A `layer` name that never appears in the
    /// attribution yields zero, mirroring
    /// `leaf_counts_by_layer().get(layer)` returning [`None`].
    ///
    /// **Subtree altitude.** The subtree-restricted counterpart is
    /// [`Self::subtree_leaf_count_of_layer`]`(prefix, layer)` — the
    /// **2D-restricted** count seam on the {path axis, layer axis} ×
    /// {restricted, free} grid. A consumer scoped to a subsystem
    /// (e.g. "how many leaves did axis `X` shape under `breathe.*`?")
    /// reaches for that seam directly to skip both the peer-writer
    /// counter map [`Self::subtree_leaf_counts_by_layer`]`(prefix)`
    /// allocates and the extra-subtree scan this primitive pays across
    /// leaves outside the prefix.
    #[must_use]
    pub fn leaf_count_of_layer(&self, layer: &str) -> usize {
        self.inner.values().filter(|l| **l == layer).count()
    }

    /// The **subtree × single-layer** dual of [`Self::writes_by_layer`]:
    /// the paths credited to `layer` under (or at) `prefix`, in lex path
    /// order, without materializing the full per-writer map at either
    /// altitude. A `prefix` of `&[]` and any `layer` equals
    /// [`Self::writes_of_layer`]`(layer)` verbatim; a `layer` name that
    /// contributed no surviving leaf under `prefix` yields the empty
    /// vector; a `prefix` that names no subtree yields the empty vector.
    ///
    /// The **2D-restricted** seam completing the four-cell grid of {path
    /// axis, layer axis} × {restricted, free}: [`Self::writes_by_layer`]
    /// covers (free, free), [`Self::subtree_writes_by_layer`] covers
    /// (subtree, free), [`Self::writes_of_layer`] covers (free,
    /// single-layer), and this primitive covers (subtree, single-layer).
    /// Every cell factors through one filtered pass at its altitude so
    /// that a focused query never pays the cost of the peer axis — a
    /// per-writer config-show pane scoped to one subsystem, an audit
    /// dashboard slicing "which paths did axis `X` shape under
    /// `breathe.*`?", a diagnostics pass rendering "layer `Y`'s
    /// contribution to the `network.*` subtree" reaches for this seam
    /// directly instead of paying the `O(m log k)` [`BTreeMap`]-construction
    /// cost [`Self::subtree_writes_by_layer`]`(prefix)` pays across peer
    /// writers under the subtree, or the `O(n − m)` extra-subtree scan
    /// [`Self::writes_of_layer`]`(layer)` pays across leaves outside
    /// `prefix`.
    ///
    /// **Cost.** `O(log n + m)` time and `O(w)` space, where `n` is the
    /// total leaf count, `m` is the number of matching leaves *under
    /// the subtree*, and `w` is the number of those matching leaves
    /// this writer shaped — one [`BTreeMap::range`] seek to the
    /// subtree's first entry (via [`Self::subtree_iter`]), a linear
    /// walk that halts at the first non-prefixed key (via
    /// [`Self::subtree_iter`]'s take-while), one predicate check per
    /// entry, one [`Vec`] push per match. Peer writers under the
    /// subtree and leaves outside `prefix` both pay no allocation.
    ///
    /// **Cross-projection identities.** The result equals
    /// [`Self::subtree_writes_by_layer`]`(prefix).get(layer).cloned().unwrap_or_default()`
    /// verbatim on every input, and its length equals
    /// [`Self::subtree_leaf_count_of_layer`]`(prefix, layer)` and
    /// [`Self::subtree_leaf_counts_by_layer`]`(prefix).get(layer).copied().unwrap_or(0)`.
    /// `subtree_writes_of_layer(&[], layer)` equals
    /// [`Self::writes_of_layer`]`(layer)` verbatim (empty-prefix corner).
    ///
    /// **Lex order preservation.** Paths land in the same lex order
    /// [`Self::subtree_iter`] emits them (the underlying [`BTreeMap`]'s
    /// ordering restricted to the subtree) — the identity property
    /// axis restriction shares with the parent projection it filters.
    ///
    /// **Subset invariants.** For every prefix and every writer:
    /// `subtree_writes_of_layer(prefix, layer)` is a subsequence of
    /// [`Self::writes_of_layer`]`(layer)` (subtree paths ⊆ parent
    /// paths); its length is `≤` [`Self::leaf_count_of_layer`]`(layer)`
    /// and `≤` [`Self::subtree_leaf_counts_by_layer`]`(prefix)`'s
    /// value for `layer`.
    ///
    /// **Missing writer / missing subtree.** A `layer` name that never
    /// appears under the subtree — whether the writer was silent
    /// globally, was purged under this subtree, or never wrote here —
    /// yields the empty vector, mirroring
    /// `subtree_writes_by_layer(prefix).get(layer)` returning [`None`].
    /// A `prefix` that names no subtree yields the empty vector for
    /// every writer.
    ///
    /// **Prefix-extending sibling boundary.** Inherited from
    /// [`Self::subtree_iter`]: a lex-adjacent sibling that shares the
    /// string prefix of the last `prefix` element but is not a path
    /// descendant (e.g. `["breatheZ"]` vs prefix `["breathe"]`) is
    /// correctly excluded — even when it belongs to `layer` in the
    /// parent's [`Self::writes_of_layer`]`(layer)`.
    #[must_use]
    pub fn subtree_writes_of_layer<'a>(
        &'a self,
        prefix: &'a [String],
        layer: &str,
    ) -> Vec<&'a [String]> {
        self.subtree_iter(prefix)
            .filter_map(|(p, l)| (l == layer).then_some(p))
            .collect()
    }

    /// The **subtree × single-layer** dual of
    /// [`Self::leaf_counts_by_layer`]: the number of leaves credited
    /// to `layer` under (or at) `prefix`, without materializing the
    /// full per-writer counter map at either altitude. A `prefix` of
    /// `&[]` and any `layer` equals [`Self::leaf_count_of_layer`]`(layer)`
    /// verbatim; a `layer` name that contributed no surviving leaf
    /// under `prefix` yields zero; a `prefix` that names no subtree
    /// yields zero for every writer.
    ///
    /// The compact scalar companion to [`Self::subtree_writes_of_layer`]
    /// on the 2D-restricted cell of the {path axis, layer axis} ×
    /// {restricted, free} grid. Consumers that need only "how many
    /// leaves did axis `X` shape under `breathe.*`?" — a size badge on
    /// a per-writer config-show pane scoped to one subsystem, a
    /// health-check gauge on one writer under one subtree, a
    /// "top-writer-under-subtree" ranking loop — reach for this scalar
    /// seam directly instead of paying the `O(m log k)` counter map
    /// allocation [`Self::subtree_leaf_counts_by_layer`]`(prefix)` pays
    /// across peer writers under the subtree, or the `O(n − m)`
    /// extra-subtree scan [`Self::leaf_count_of_layer`]`(layer)` pays
    /// across leaves outside `prefix`.
    ///
    /// **Cost.** `O(log n + m)` time and no allocation — one
    /// [`BTreeMap::range`] seek to the subtree's first entry (via
    /// [`Self::subtree_iter`]), a linear walk that halts at the first
    /// non-prefixed key (via [`Self::subtree_iter`]'s take-while), one
    /// predicate check per entry, one counter increment per match.
    ///
    /// **Cross-projection identities.** The result equals
    /// [`Self::subtree_writes_of_layer`]`(prefix, layer).len()` and
    /// [`Self::subtree_leaf_counts_by_layer`]`(prefix).get(layer).copied().unwrap_or(0)`
    /// verbatim on every input. `subtree_leaf_count_of_layer(&[],
    /// layer)` equals [`Self::leaf_count_of_layer`]`(layer)` verbatim
    /// (empty-prefix corner).
    ///
    /// **Partition-count law.** The sum of
    /// `subtree_leaf_count_of_layer(prefix, l)` over every `l` in
    /// [`Self::subtree_surviving_layer_names`]`(prefix)` equals
    /// [`Self::subtree_iter`]`(prefix).count()` (equivalently
    /// [`Self::subtree`]`(prefix).len()`) — every subtree leaf belongs
    /// to exactly one surviving writer's counter under the subtree.
    ///
    /// **Subset invariants.** For every prefix and every writer:
    /// `subtree_leaf_count_of_layer(prefix, layer)` is `≤`
    /// [`Self::leaf_count_of_layer`]`(layer)` (subtree ⊆ parent) and
    /// `≤` [`Self::subtree_iter`]`(prefix).count()` (this writer's
    /// share ⊆ the subtree's total).
    ///
    /// **Missing writer / missing subtree.** A `layer` that never
    /// appears under the subtree yields zero; a `prefix` that names
    /// no subtree yields zero for every writer.
    #[must_use]
    pub fn subtree_leaf_count_of_layer(&self, prefix: &[String], layer: &str) -> usize {
        self.subtree_iter(prefix)
            .filter(|(_, l)| *l == layer)
            .count()
    }

    /// The **argmax** of [`Self::leaf_counts_by_layer`]: the
    /// [`DiscoveryLayer`] that wrote the most surviving leaves in the
    /// composed attribution, or [`None`] on an empty attribution.
    ///
    /// The **scalar single-writer** projection on the count axis — the
    /// "who owns the largest share of the config?" audit query at the
    /// altitude the {path × layer} × {free × restricted} grid answers
    /// its "which writers survived?" (name-set) and "how much did each
    /// writer contribute?" (histogram) questions. Where
    /// [`Self::surviving_layer_names`] carries every survivor by name
    /// (name-set altitude) and [`Self::leaf_counts_by_layer`] carries
    /// every survivor with its counter (histogram altitude), this
    /// primitive collapses the histogram to its argmax — the natural
    /// top-of-ranking / one-writer-dominates diagnostic on the
    /// attribution.
    ///
    /// **Deterministic tie-break.** When two or more writers share the
    /// maximum count, the winner is the smallest layer name in lex
    /// order on `&'static str` — the same order
    /// [`Self::surviving_layer_names`] emits, and the same order every
    /// `BTreeMap<&'static str, _>` seam ([`Self::writes_by_layer`],
    /// [`Self::leaf_counts_by_layer`]) already iterates. So the result
    /// is stable across identical attributions and stable across
    /// counters with tied maxima, at zero extra cost.
    ///
    /// **Cost.** `O(n log k)` time and `O(k)` space where `n` is the
    /// total leaf count and `k` is the distinct-writer count — one pass
    /// over `self.inner.values()` to build the [`BTreeMap`] counter
    /// map (via [`Self::leaf_counts_by_layer`]), one linear pass with a
    /// running-max tracker to find the argmax. The counter map is
    /// consumed, not returned, so callers that only need the top writer
    /// pay no per-writer allocation the caller then discards.
    ///
    /// **Cross-projection identity.** The result is [`Some`] iff
    /// [`Self::is_empty`] is `false`, its unwrapped value is a member of
    /// [`Self::surviving_layer_names`], and
    /// [`Self::leaf_count_of_layer`]`(dominant_layer().unwrap())` equals
    /// the maximum value of [`Self::leaf_counts_by_layer`]. Pinned by
    /// `dominant_layer_agrees_with_leaf_counts_argmax`,
    /// `dominant_layer_is_member_of_surviving_layer_names`, and
    /// `dominant_layer_empty_attribution_is_none` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Single-writer identity.** When exactly one writer survives
    /// (whether because the stack has one layer, or because every
    /// other layer's writes were purged), this primitive returns that
    /// writer's name. Pinned by
    /// `dominant_layer_single_writer_is_that_writer`.
    ///
    /// **Subtree altitude.** [`Self::subtree_dominant_layer`] extends
    /// this scalar to a `prefix`, answering the same "who owns the
    /// largest share?" question restricted to a single sub-tree — the
    /// natural top-writer-per-subsystem gauge a per-subtree config-show
    /// pane reaches for.
    #[must_use]
    pub fn dominant_layer(&self) -> Option<&'static str> {
        self.leaf_counts_by_layer()
            .into_iter()
            .max_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
            .map(|(name, _)| name)
    }

    /// The **subtree-restricted** dual of [`Self::dominant_layer`]:
    /// the [`DiscoveryLayer`] that wrote the most surviving leaves
    /// under (or at) `prefix`, or [`None`] when the subtree is empty
    /// (`prefix` names no subtree, or every writer under it was
    /// purged).
    ///
    /// The **scalar** cell on the count axis at the subtree altitude
    /// — the compact companion to [`Self::subtree_surviving_layer_names`]
    /// (name-set) and [`Self::subtree_leaf_counts_by_layer`]
    /// (histogram). Consumers that only need the top writer under one
    /// subsystem — a per-subtree health-check gauge, a
    /// "who dominates `breathe.*`?" audit query, a
    /// top-writer-per-subsystem ladder on a config-show pane — reach
    /// for this seam directly instead of iterating
    /// [`Self::subtree_leaf_counts_by_layer`] and tracking a running
    /// max in the consumer.
    ///
    /// **Deterministic tie-break.** As for [`Self::dominant_layer`],
    /// tied maxima are broken by the smallest layer name in lex order
    /// on `&'static str` — stable across identical subtrees.
    ///
    /// **Cost.** `O(log n + m + k')` time and `O(k')` space where `n`
    /// is the total leaf count, `m` is the number of matching leaves
    /// under the subtree, and `k'` is the distinct-writer count *under
    /// the subtree* — one [`BTreeMap::range`] seek to the subtree's
    /// first entry (via [`Self::subtree_iter`]), a linear walk that
    /// halts at the first non-prefixed key, one [`BTreeMap`] counter
    /// increment per leaf, one linear argmax pass over the counter
    /// map.
    ///
    /// **Cross-projection identities.** The result is [`Some`] iff
    /// [`Self::subtree_iter`]`(prefix).next()` is [`Some`]; its
    /// unwrapped value is a member of
    /// [`Self::subtree_surviving_layer_names`]`(prefix)`; and
    /// [`Self::subtree_leaf_count_of_layer`]`(prefix,
    /// subtree_dominant_layer(prefix).unwrap())` equals the maximum
    /// value of [`Self::subtree_leaf_counts_by_layer`]`(prefix)`.
    /// `subtree_dominant_layer(&[])` equals [`Self::dominant_layer`]
    /// verbatim (the empty-prefix corner).
    ///
    /// **Subset invariants.** For every prefix and every attribution:
    /// `subtree_dominant_layer(prefix)` is [`None`] whenever
    /// [`Self::subtree_iter`]`(prefix).next()` is [`None`], and is a
    /// member of [`Self::surviving_layer_names`] (the top-level writer
    /// set) when [`Some`] — the subtree cannot pick a name that never
    /// wrote anywhere. The scalar can differ from
    /// [`Self::dominant_layer`] under a subtree that a non-globally-
    /// dominant writer nonetheless owns locally.
    #[must_use]
    pub fn subtree_dominant_layer(&self, prefix: &[String]) -> Option<&'static str> {
        self.subtree_leaf_counts_by_layer(prefix)
            .into_iter()
            .max_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
            .map(|(name, _)| name)
    }

    /// The **ranked** projection of [`Self::leaf_counts_by_layer`]:
    /// every surviving [`DiscoveryLayer`] paired with its leaf count,
    /// sorted by count descending with a deterministic
    /// lex-name-ascending tie-break.
    ///
    /// The **sorted-by-dominance view** on the count axis — one step
    /// past [`Self::dominant_layer`]'s scalar argmax. Where the histogram
    /// [`Self::leaf_counts_by_layer`] iterates by *layer name* (the
    /// underlying [`BTreeMap`]'s ordering) and the scalar
    /// [`Self::dominant_layer`] collapses the histogram to its top
    /// entry, this projection carries every survivor pre-sorted by
    /// dominance. Consumers that need the runner-up, a top-`k` list, or
    /// the minimum contributor — a config-show pane rendering "top 3
    /// writers", a diagnostics banner reporting the two loudest axes, a
    /// ranking-diff between compositions — reach for this seam directly
    /// instead of re-sorting the histogram themselves.
    ///
    /// **Cost.** `O(n log k + k log k)` time and `O(k)` space where `n`
    /// is the total leaf count and `k` is the distinct-writer count —
    /// one pass over `self.inner.values()` to build the [`BTreeMap`]
    /// counter map (via [`Self::leaf_counts_by_layer`]), one collect
    /// into a [`Vec`], one stable [`sort_by`] on the vector. The counter
    /// map is consumed, not returned, so callers that only need the
    /// ranking pay no per-writer allocation the caller then discards.
    ///
    /// [`sort_by`]: Vec::sort_by
    ///
    /// **Deterministic tie-break.** When two or more writers share the
    /// same count, they are ordered by smallest layer name in lex order
    /// on `&'static str` — the same order every other
    /// `BTreeMap<&'static str, _>` seam on [`LayerAttribution`]
    /// ([`Self::writes_by_layer`], [`Self::leaf_counts_by_layer`],
    /// [`Self::surviving_layer_names`]) already iterates, and the same
    /// primary/secondary key [`Self::dominant_layer`] uses to pick a
    /// single winner. So the result is stable across identical
    /// attributions and stable across counters with tied runs, at zero
    /// extra cost.
    ///
    /// **Cross-projection identities.** The result is empty iff
    /// [`Self::is_empty`]; its length equals
    /// [`Self::leaf_counts_by_layer`]`().len()` and
    /// [`Self::surviving_layer_names`]`().len()`; the sum of every
    /// paired count equals [`Self::len`]; every `(layer, count)` entry
    /// satisfies `count == leaf_count_of_layer(layer)` and
    /// `count == leaf_counts_by_layer().get(layer).copied().unwrap()`;
    /// the set of `layer` names equals
    /// [`Self::surviving_layer_names`] verbatim (as a set). Pinned by
    /// `layer_ranking_agrees_with_leaf_counts_by_layer`,
    /// `layer_ranking_len_equals_surviving_layer_names_len`,
    /// `layer_ranking_counts_sum_to_len`, and
    /// `layer_ranking_empty_iff_attribution_is_empty` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Argmax law.**
    /// `layer_ranking().first().map(|(n, _)| *n)` equals
    /// [`Self::dominant_layer`] verbatim on every input — the ranking
    /// is a strict generalization of the scalar argmax. Pinned by
    /// `layer_ranking_first_equals_dominant_layer`.
    ///
    /// **Monotone order.** Counts are non-increasing along the vector;
    /// within any tied run, names are strictly increasing. Pinned by
    /// `layer_ranking_counts_are_non_increasing` and
    /// `layer_ranking_ties_are_lex_ascending`.
    ///
    /// **Subtree altitude.** [`Self::subtree_layer_ranking`] extends
    /// this ranked projection to a `prefix`, answering the same "who
    /// dominates?" question restricted to a single sub-tree — the
    /// natural top-of-ranking pane a per-subsystem config-show renderer
    /// reaches for.
    #[must_use]
    pub fn layer_ranking(&self) -> Vec<(&'static str, usize)> {
        let mut ranking: Vec<(&'static str, usize)> =
            self.leaf_counts_by_layer().into_iter().collect();
        ranking.sort_by(|(a_name, a_count), (b_name, b_count)| {
            b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
        });
        ranking
    }

    /// The **subtree-restricted** dual of [`Self::layer_ranking`]:
    /// every [`DiscoveryLayer`] that wrote at least one leaf under (or
    /// at) `prefix`, paired with its subtree leaf count, sorted by
    /// count descending with a deterministic lex-name-ascending
    /// tie-break. A `prefix` of `&[]` equals [`Self::layer_ranking`]
    /// verbatim; a `prefix` that names no subtree yields the empty
    /// vector.
    ///
    /// The **sorted-by-dominance view** at the subtree altitude — one
    /// step past [`Self::subtree_dominant_layer`]'s scalar argmax.
    /// Consumers that need a per-subtree top-`k` list, a runner-up
    /// under a subsystem, or the minimum contributor scoped to one
    /// prefix — a per-subtree config-show pane ranking writers, a
    /// diagnostics banner reporting the two loudest axes under
    /// `breathe.*`, a subtree-restricted ranking-diff — reach for this
    /// seam directly instead of re-sorting
    /// [`Self::subtree_leaf_counts_by_layer`] themselves.
    ///
    /// **Deterministic tie-break.** As for [`Self::layer_ranking`],
    /// tied counts are ordered by smallest layer name in lex order on
    /// `&'static str` — stable across identical subtrees.
    ///
    /// **Cost.** `O(log n + m + k' log k')` time and `O(k')` space where
    /// `n` is the total leaf count, `m` is the number of matching
    /// leaves under the subtree, and `k'` is the distinct-writer count
    /// *under the subtree* — one [`BTreeMap::range`] seek to the
    /// subtree's first entry (via [`Self::subtree_iter`]), a linear
    /// walk that halts at the first non-prefixed key, one [`BTreeMap`]
    /// counter increment per leaf, one collect into a [`Vec`], one
    /// stable [`sort_by`] on the vector.
    ///
    /// [`sort_by`]: Vec::sort_by
    ///
    /// **Cross-projection identities.** The result is empty iff
    /// [`Self::subtree_iter`]`(prefix).next()` is [`None`]; its length
    /// equals [`Self::subtree_leaf_counts_by_layer`]`(prefix).len()`
    /// and [`Self::subtree_surviving_layer_names`]`(prefix).len()`;
    /// the sum of every paired count equals
    /// [`Self::subtree_iter`]`(prefix).count()`; every `(layer, count)`
    /// entry satisfies
    /// `count == subtree_leaf_count_of_layer(prefix, layer)` and
    /// `count == subtree_leaf_counts_by_layer(prefix).get(layer).copied().unwrap()`;
    /// the set of `layer` names equals
    /// [`Self::subtree_surviving_layer_names`]`(prefix)` verbatim (as a
    /// set). `subtree_layer_ranking(&[])` equals [`Self::layer_ranking`]
    /// verbatim (the empty-prefix corner).
    ///
    /// **Argmax law.**
    /// `subtree_layer_ranking(prefix).first().map(|(n, _)| *n)` equals
    /// [`Self::subtree_dominant_layer`]`(prefix)` verbatim on every
    /// input — the subtree ranking is a strict generalization of the
    /// subtree scalar argmax.
    ///
    /// **Subset invariants.** For every prefix, the set of `layer`
    /// names in `subtree_layer_ranking(prefix)` is a subset of
    /// [`Self::surviving_layer_names`] (the top-level writer set) — the
    /// subtree cannot rank a name that never wrote anywhere. Each
    /// paired count is `≤` [`Self::leaf_count_of_layer`]`(layer)`
    /// (subtree ⊆ parent).
    ///
    /// **Monotone order.** Counts are non-increasing along the vector;
    /// within any tied run, names are strictly increasing — mirrors
    /// [`Self::layer_ranking`]'s ordering contract.
    #[must_use]
    pub fn subtree_layer_ranking(&self, prefix: &[String]) -> Vec<(&'static str, usize)> {
        let mut ranking: Vec<(&'static str, usize)> = self
            .subtree_leaf_counts_by_layer(prefix)
            .into_iter()
            .collect();
        ranking.sort_by(|(a_name, a_count), (b_name, b_count)| {
            b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
        });
        ranking
    }

    /// The **argmin** on the count axis: the [`DiscoveryLayer`] that
    /// wrote the fewest surviving leaves in the composed attribution,
    /// or [`None`] when the attribution is empty (no leaves survived).
    ///
    /// The **bottom-endpoint** dual of [`Self::dominant_layer`] — where
    /// that scalar answers "who owns the largest share?" at the top of
    /// [`Self::layer_ranking`], this one answers "who owns the smallest
    /// share?" at the bottom. Consumers that need the minimum
    /// contributor — a diagnostics gauge flagging under-used writers, a
    /// "least-active axis" audit banner, a coverage report that names
    /// the writer at risk of falling silent — reach for this seam
    /// directly instead of iterating [`Self::leaf_counts_by_layer`] and
    /// tracking a running min in the consumer.
    ///
    /// **Deterministic tie-break.** When two or more writers share the
    /// minimum count, the winner is the *largest* layer name in lex
    /// order on `&'static str` — the same endpoint
    /// [`Self::layer_ranking`]`.last()` names. So both endpoints of
    /// the ranking factor through the ranking's own tie-break
    /// convention (count DESC, name ASC): the first is the smallest
    /// lex name at max count, the last is the largest lex name at min
    /// count. The result is stable across identical attributions and
    /// stable across counters with tied minima at zero extra cost.
    ///
    /// **Cost.** `O(n log k)` time and `O(k)` space where `n` is the
    /// leaf count and `k` is the distinct-writer count — one pass over
    /// `self.inner.values()` to build the counter map (via
    /// [`Self::leaf_counts_by_layer`]), one linear argmin pass over its
    /// `k` entries. The counter map is consumed, not returned, so
    /// callers pay no per-writer allocation they then discard.
    ///
    /// **Cross-projection identities.** The result is [`Some`] iff
    /// [`Self::is_empty`] is `false`; its unwrapped value is a member
    /// of [`Self::surviving_layer_names`]; and
    /// [`Self::leaf_count_of_layer`]`(weakest_layer().unwrap())` equals
    /// the minimum value of [`Self::leaf_counts_by_layer`]. Pinned by
    /// `weakest_layer_agrees_with_leaf_counts_argmin`,
    /// `weakest_layer_empty_attribution_is_none`, and
    /// `weakest_layer_is_member_of_surviving_layer_names` in
    /// `src/discovered.rs`'s test module.
    ///
    /// **Endpoint identity.**
    /// `weakest_layer()` equals
    /// `layer_ranking().last().map(|(n, _)| *n)` verbatim on every
    /// input — the argmin is the last entry of the sorted-by-dominance
    /// view. Pinned by `weakest_layer_equals_layer_ranking_last`.
    ///
    /// **Bookend law.** For every attribution with at least one live
    /// writer, `dominant_layer() == weakest_layer()` iff every
    /// surviving writer has the same leaf count (the ranking is flat).
    /// Pinned indirectly by
    /// `weakest_layer_equals_dominant_layer_on_single_writer_or_flat`.
    ///
    /// **Subtree altitude.** [`Self::subtree_weakest_layer`] extends
    /// this scalar to a `prefix`, answering the same "who owns the
    /// smallest share?" question restricted to a single sub-tree — the
    /// natural pane a per-subsystem diagnostics gauge reaches for.
    #[must_use]
    pub fn weakest_layer(&self) -> Option<&'static str> {
        self.leaf_counts_by_layer()
            .into_iter()
            .min_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
            .map(|(name, _)| name)
    }

    /// The **subtree-restricted** dual of [`Self::weakest_layer`]: the
    /// [`DiscoveryLayer`] that wrote the fewest surviving leaves under
    /// (or at) `prefix`, or [`None`] when the subtree is empty
    /// (`prefix` names no subtree, or every writer under it was
    /// purged).
    ///
    /// The **bottom-endpoint** dual on the subtree ladder — the
    /// compact companion to [`Self::subtree_surviving_layer_names`]
    /// (name-set), [`Self::subtree_leaf_counts_by_layer`] (histogram),
    /// [`Self::subtree_dominant_layer`] (top endpoint), and
    /// [`Self::subtree_layer_ranking`] (sorted view). Consumers that
    /// only need the smallest contributor under one subsystem — a
    /// per-subtree health-check gauge flagging under-used axes, a
    /// "who barely wrote `breathe.*`?" audit query — reach for this
    /// seam directly instead of iterating
    /// [`Self::subtree_leaf_counts_by_layer`] and tracking a running
    /// min in the consumer.
    ///
    /// **Deterministic tie-break.** As for [`Self::weakest_layer`],
    /// tied minima are broken by the *largest* layer name in lex
    /// order on `&'static str` — stable across identical subtrees,
    /// and matching the endpoint
    /// [`Self::subtree_layer_ranking`]`(prefix).last()` names.
    ///
    /// **Cost.** `O(log n + m + k')` time and `O(k')` space where `n`
    /// is the total leaf count, `m` is the number of matching leaves
    /// under the subtree, and `k'` is the distinct-writer count *under
    /// the subtree* — one [`BTreeMap::range`] seek to the subtree's
    /// first entry (via [`Self::subtree_iter`]), a linear walk that
    /// halts at the first non-prefixed key, one [`BTreeMap`] counter
    /// increment per leaf, one linear argmin pass over the counter
    /// map.
    ///
    /// **Cross-projection identities.** The result is [`Some`] iff
    /// [`Self::subtree_iter`]`(prefix).next()` is [`Some`]; its
    /// unwrapped value is a member of
    /// [`Self::subtree_surviving_layer_names`]`(prefix)`; and
    /// [`Self::subtree_leaf_count_of_layer`]`(prefix,
    /// subtree_weakest_layer(prefix).unwrap())` equals the minimum
    /// value of [`Self::subtree_leaf_counts_by_layer`]`(prefix)`.
    /// `subtree_weakest_layer(&[])` equals [`Self::weakest_layer`]
    /// verbatim (the empty-prefix corner).
    ///
    /// **Endpoint identity.**
    /// `subtree_weakest_layer(prefix)` equals
    /// `subtree_layer_ranking(prefix).last().map(|(n, _)| *n)` verbatim
    /// on every input — the subtree argmin is the last entry of the
    /// subtree sorted-by-dominance view.
    ///
    /// **Subset invariants.** For every prefix and every attribution:
    /// `subtree_weakest_layer(prefix)` is [`None`] whenever
    /// [`Self::subtree_iter`]`(prefix).next()` is [`None`], and is a
    /// member of [`Self::surviving_layer_names`] (the top-level writer
    /// set) when [`Some`] — the subtree cannot pick a name that never
    /// wrote anywhere. The scalar can differ from
    /// [`Self::weakest_layer`] under a subtree that a globally-dominant
    /// writer nonetheless barely touches (or wholly skips).
    #[must_use]
    pub fn subtree_weakest_layer(&self, prefix: &[String]) -> Option<&'static str> {
        self.subtree_leaf_counts_by_layer(prefix)
            .into_iter()
            .min_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
            .map(|(name, _)| name)
    }

    /// The **atomic row** at the top endpoint of [`Self::layer_ranking`]:
    /// the `(name, count)` tuple naming the winning
    /// [`DiscoveryLayer`] and its surviving-leaf count, or [`None`] when
    /// the attribution is empty (no leaves survived).
    ///
    /// The **entry** dual on the name-and-count axis — where
    /// [`Self::dominant_layer`] returns the argmax *name* and
    /// [`Self::leaf_count_of_layer`]`(dominant_layer().unwrap())` returns
    /// the argmax *count*, this primitive returns both in a single pass.
    /// Consumers rendering "dominant: nix (5 leaves)" on a diagnostics
    /// banner, a "top writer + share" gauge on a config-show pane, or a
    /// composition-diff row pairing name and count — reach for this seam
    /// directly instead of walking two calls (`dominant_layer` +
    /// `leaf_count_of_layer`) or picking `layer_ranking().first()` (which
    /// pays an extra `O(k log k)` sort the entry itself does not need).
    ///
    /// **Deterministic tie-break.** When two or more writers share the
    /// maximum count, the winner is the *smallest* layer name in lex
    /// order on `&'static str` — matches [`Self::dominant_layer`] and
    /// [`Self::layer_ranking`]`().first()` verbatim.
    ///
    /// **Cost.** `O(n log k)` time and `O(k)` space where `n` is the leaf
    /// count and `k` is the distinct-writer count — one pass over
    /// `self.inner.values()` to build the counter map (via
    /// [`Self::leaf_counts_by_layer`]), one linear argmax pass over its
    /// `k` entries. The counter map is consumed, not returned, so
    /// callers pay no per-writer allocation they then discard. Strictly
    /// cheaper than [`Self::layer_ranking`]`().first()`, which pays an
    /// additional `O(k log k)` stable sort to build the whole vector.
    ///
    /// **Endpoint identity.** `dominant_entry()` equals
    /// `layer_ranking().first().copied()` verbatim on every input — the
    /// entry is the top row of the sorted-by-dominance view, extracted
    /// without materializing the sort. Pinned by
    /// `dominant_entry_equals_layer_ranking_first`.
    ///
    /// **Name-and-count decomposition.** For every attribution:
    /// `dominant_entry().map(|(n, _)| n)` equals [`Self::dominant_layer`]
    /// verbatim, and `dominant_entry().map(|(_, c)| c)` equals the
    /// maximum value of [`Self::leaf_counts_by_layer`] verbatim (or
    /// [`None`] when empty). So the two existing scalars factor through
    /// this one entry — `dominant_layer` is the name-axis projection,
    /// and the count scalar is the value-axis projection.
    ///
    /// **Cross-projection identity.** When [`Some`], the returned
    /// `count` equals [`Self::leaf_count_of_layer`]`(name)` verbatim and
    /// equals `leaf_counts_by_layer().get(name).copied().unwrap()` — the
    /// entry's count is byte-identical to the histogram value at its
    /// name. Pinned by `dominant_entry_count_agrees_with_leaf_count_of_layer`.
    ///
    /// **Subtree altitude.** [`Self::subtree_dominant_entry`] extends
    /// this entry to a `prefix`, answering the same "top writer + share?"
    /// question restricted to a single sub-tree — the natural row a
    /// per-subsystem gauge or ranking-diff renderer reaches for.
    #[must_use]
    pub fn dominant_entry(&self) -> Option<(&'static str, usize)> {
        self.leaf_counts_by_layer()
            .into_iter()
            .max_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
    }

    /// The **subtree-restricted** dual of [`Self::dominant_entry`]: the
    /// `(name, count)` tuple naming the [`DiscoveryLayer`] that wrote
    /// the most surviving leaves under (or at) `prefix` paired with its
    /// subtree leaf count, or [`None`] when the subtree is empty
    /// (`prefix` names no subtree, or every writer under it was purged).
    ///
    /// The **atomic row** at the top endpoint of
    /// [`Self::subtree_layer_ranking`] — the compact entry companion to
    /// [`Self::subtree_dominant_layer`] (name), the maximum value of
    /// [`Self::subtree_leaf_counts_by_layer`] (count), and
    /// [`Self::subtree_layer_ranking`] (sorted view). Consumers that only
    /// need the top row under one subsystem — a per-subtree config-show
    /// pane rendering "top writer + share under `breathe.*`", a
    /// composition-diff row pairing name and count at a subtree — reach
    /// for this seam directly instead of walking
    /// `subtree_dominant_layer` + `subtree_leaf_count_of_layer` or paying
    /// the extra sort of `subtree_layer_ranking(prefix).first()`.
    ///
    /// **Deterministic tie-break.** As for [`Self::dominant_entry`],
    /// tied maxima are broken by the smallest layer name in lex order on
    /// `&'static str` — matches [`Self::subtree_dominant_layer`] and
    /// [`Self::subtree_layer_ranking`]`(prefix).first()` verbatim.
    ///
    /// **Cost.** `O(log n + m + k')` time and `O(k')` space where `n`
    /// is the total leaf count, `m` is the number of matching leaves
    /// under the subtree, and `k'` is the distinct-writer count *under
    /// the subtree* — one [`BTreeMap::range`] seek to the subtree's
    /// first entry (via [`Self::subtree_iter`]), a linear walk that
    /// halts at the first non-prefixed key, one [`BTreeMap`] counter
    /// increment per leaf, one linear argmax pass over the counter map.
    /// Strictly cheaper than [`Self::subtree_layer_ranking`]`(prefix)
    /// .first()`, which pays an additional `O(k' log k')` sort.
    ///
    /// **Endpoint identity.** `subtree_dominant_entry(prefix)` equals
    /// `subtree_layer_ranking(prefix).first().copied()` verbatim on
    /// every input — the entry is the top row of the subtree
    /// sorted-by-dominance view, extracted without materializing the
    /// sort. `subtree_dominant_entry(&[])` equals
    /// [`Self::dominant_entry`] verbatim (the empty-prefix corner).
    ///
    /// **Name-and-count decomposition.** For every prefix and every
    /// attribution: `subtree_dominant_entry(prefix).map(|(n, _)| n)`
    /// equals [`Self::subtree_dominant_layer`]`(prefix)` verbatim, and
    /// `subtree_dominant_entry(prefix).map(|(_, c)| c)` equals the
    /// maximum value of [`Self::subtree_leaf_counts_by_layer`]`(prefix)`
    /// verbatim (or [`None`] when empty).
    ///
    /// **Cross-projection identity.** When [`Some`], the returned
    /// `count` equals [`Self::subtree_leaf_count_of_layer`]`(prefix,
    /// name)` verbatim and equals `subtree_leaf_counts_by_layer(prefix)
    /// .get(name).copied().unwrap()` — the entry's count is
    /// byte-identical to the subtree histogram value at its name.
    ///
    /// **Subset invariants.** For every prefix and every attribution:
    /// `subtree_dominant_entry(prefix)` is [`None`] whenever
    /// [`Self::subtree_iter`]`(prefix).next()` is [`None`], its name is
    /// a member of [`Self::surviving_layer_names`] when [`Some`] (the
    /// subtree cannot pick a writer that never wrote anywhere), and its
    /// count is `≤` [`Self::leaf_count_of_layer`]`(name)` (subtree ⊆
    /// parent).
    #[must_use]
    pub fn subtree_dominant_entry(&self, prefix: &[String]) -> Option<(&'static str, usize)> {
        self.subtree_leaf_counts_by_layer(prefix)
            .into_iter()
            .max_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
    }

    /// The **atomic row** at the bottom endpoint of [`Self::layer_ranking`]:
    /// the `(name, count)` tuple naming the losing [`DiscoveryLayer`] and
    /// its surviving-leaf count, or [`None`] when the attribution is empty
    /// (no leaves survived).
    ///
    /// The **entry** dual on the bottom-endpoint (name, count) axis —
    /// where [`Self::weakest_layer`] returns the argmin *name* and
    /// [`Self::leaf_count_of_layer`]`(weakest_layer().unwrap())` returns
    /// the argmin *count*, this primitive returns both in a single pass.
    /// Consumers rendering "least: platform (1 leaf)" on a
    /// diagnostics banner, a "bottom writer + share" gauge on a
    /// config-show pane, or a composition-diff row pairing name and count
    /// at the tail of the ranking — reach for this seam directly instead
    /// of walking two calls (`weakest_layer` + `leaf_count_of_layer`) or
    /// picking `layer_ranking().last()` (which pays an extra `O(k log k)`
    /// sort the entry itself does not need).
    ///
    /// **Deterministic tie-break.** When two or more writers share the
    /// minimum count, the winner is the *largest* layer name in lex
    /// order on `&'static str` — matches [`Self::weakest_layer`] and
    /// [`Self::layer_ranking`]`().last()` verbatim.
    ///
    /// **Cost.** `O(n log k)` time and `O(k)` space where `n` is the leaf
    /// count and `k` is the distinct-writer count — one pass over
    /// `self.inner.values()` to build the counter map (via
    /// [`Self::leaf_counts_by_layer`]), one linear argmin pass over its
    /// `k` entries. The counter map is consumed, not returned, so
    /// callers pay no per-writer allocation they then discard. Strictly
    /// cheaper than [`Self::layer_ranking`]`().last()`, which pays an
    /// additional `O(k log k)` stable sort to build the whole vector.
    ///
    /// **Endpoint identity.** `weakest_entry()` equals
    /// `layer_ranking().last().copied()` verbatim on every input — the
    /// entry is the bottom row of the sorted-by-dominance view, extracted
    /// without materializing the sort. Pinned by
    /// `weakest_entry_equals_layer_ranking_last`.
    ///
    /// **Name-and-count decomposition.** For every attribution:
    /// `weakest_entry().map(|(n, _)| n)` equals [`Self::weakest_layer`]
    /// verbatim, and `weakest_entry().map(|(_, c)| c)` equals the
    /// minimum value of [`Self::leaf_counts_by_layer`] verbatim (or
    /// [`None`] when empty). So the two existing bottom-endpoint scalars
    /// factor through this one entry — `weakest_layer` is the name-axis
    /// projection, and the count scalar is the value-axis projection.
    ///
    /// **Cross-projection identity.** When [`Some`], the returned
    /// `count` equals [`Self::leaf_count_of_layer`]`(name)` verbatim and
    /// equals `leaf_counts_by_layer().get(name).copied().unwrap()` — the
    /// entry's count is byte-identical to the histogram value at its
    /// name. Pinned by `weakest_entry_count_agrees_with_leaf_count_of_layer`.
    ///
    /// **Bookend law.** For every attribution with at least one live
    /// writer, `dominant_entry() == weakest_entry()` iff every surviving
    /// writer has the same leaf count *and* only one writer survives
    /// (the ranking collapses to a single row). On any flat multi-writer
    /// ranking, both entries share a count but disagree on the name by
    /// the opposing tie-break rules — dominant picks smallest lex,
    /// weakest picks largest.
    ///
    /// **Subtree altitude.** [`Self::subtree_weakest_entry`] extends this
    /// entry to a `prefix`, answering the same "bottom writer + share?"
    /// question restricted to a single sub-tree — the natural row a
    /// per-subsystem underuse-gauge or ranking-diff renderer reaches for.
    #[must_use]
    pub fn weakest_entry(&self) -> Option<(&'static str, usize)> {
        self.leaf_counts_by_layer()
            .into_iter()
            .min_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
    }

    /// The **subtree-restricted** dual of [`Self::weakest_entry`]: the
    /// `(name, count)` tuple naming the [`DiscoveryLayer`] that wrote
    /// the fewest surviving leaves under (or at) `prefix` paired with
    /// its subtree leaf count, or [`None`] when the subtree is empty
    /// (`prefix` names no subtree, or every writer under it was purged).
    ///
    /// The **atomic row** at the bottom endpoint of
    /// [`Self::subtree_layer_ranking`] — the compact entry companion to
    /// [`Self::subtree_weakest_layer`] (name), the minimum value of
    /// [`Self::subtree_leaf_counts_by_layer`] (count), and
    /// [`Self::subtree_layer_ranking`] (sorted view). Consumers that only
    /// need the bottom row under one subsystem — a per-subtree config-show
    /// pane rendering "least writer + share under `breathe.*`", a
    /// composition-diff row pairing name and count at the tail of a
    /// subtree ranking — reach for this seam directly instead of walking
    /// `subtree_weakest_layer` + `subtree_leaf_count_of_layer` or paying
    /// the extra sort of `subtree_layer_ranking(prefix).last()`.
    ///
    /// **Deterministic tie-break.** As for [`Self::weakest_entry`],
    /// tied minima are broken by the *largest* layer name in lex order
    /// on `&'static str` — matches [`Self::subtree_weakest_layer`] and
    /// [`Self::subtree_layer_ranking`]`(prefix).last()` verbatim.
    ///
    /// **Cost.** `O(log n + m + k')` time and `O(k')` space where `n`
    /// is the total leaf count, `m` is the number of matching leaves
    /// under the subtree, and `k'` is the distinct-writer count *under
    /// the subtree* — one [`BTreeMap::range`] seek to the subtree's
    /// first entry (via [`Self::subtree_iter`]), a linear walk that
    /// halts at the first non-prefixed key, one [`BTreeMap`] counter
    /// increment per leaf, one linear argmin pass over the counter map.
    /// Strictly cheaper than [`Self::subtree_layer_ranking`]`(prefix)
    /// .last()`, which pays an additional `O(k' log k')` sort.
    ///
    /// **Endpoint identity.** `subtree_weakest_entry(prefix)` equals
    /// `subtree_layer_ranking(prefix).last().copied()` verbatim on
    /// every input — the entry is the bottom row of the subtree
    /// sorted-by-dominance view, extracted without materializing the
    /// sort. `subtree_weakest_entry(&[])` equals [`Self::weakest_entry`]
    /// verbatim (the empty-prefix corner).
    ///
    /// **Name-and-count decomposition.** For every prefix and every
    /// attribution: `subtree_weakest_entry(prefix).map(|(n, _)| n)`
    /// equals [`Self::subtree_weakest_layer`]`(prefix)` verbatim, and
    /// `subtree_weakest_entry(prefix).map(|(_, c)| c)` equals the
    /// minimum value of [`Self::subtree_leaf_counts_by_layer`]`(prefix)`
    /// verbatim (or [`None`] when empty).
    ///
    /// **Cross-projection identity.** When [`Some`], the returned
    /// `count` equals [`Self::subtree_leaf_count_of_layer`]`(prefix,
    /// name)` verbatim and equals `subtree_leaf_counts_by_layer(prefix)
    /// .get(name).copied().unwrap()` — the entry's count is
    /// byte-identical to the subtree histogram value at its name.
    ///
    /// **Subset invariants.** For every prefix and every attribution:
    /// `subtree_weakest_entry(prefix)` is [`None`] whenever
    /// [`Self::subtree_iter`]`(prefix).next()` is [`None`], its name is
    /// a member of [`Self::surviving_layer_names`] when [`Some`] (the
    /// subtree cannot pick a writer that never wrote anywhere), and its
    /// count is `≤` [`Self::leaf_count_of_layer`]`(name)` (subtree ⊆
    /// parent).
    #[must_use]
    pub fn subtree_weakest_entry(&self, prefix: &[String]) -> Option<(&'static str, usize)> {
        self.subtree_leaf_counts_by_layer(prefix)
            .into_iter()
            .min_by(|(a_name, a_count), (b_name, b_count)| {
                a_count.cmp(b_count).then_with(|| b_name.cmp(a_name))
            })
    }
}

/// The result of composing a stack of [`DiscoveryLayer`]s with per-leaf
/// provenance tracking.
///
/// `dict` is byte-identical to [`compose`]`(layers)` — the same
/// primitive powers both — and `attribution` records the name of the
/// [`DiscoveryLayer`] that last wrote each leaf. Peer to [`compose`]
/// on the no-attribution path.
///
/// `PartialEq` but not `Eq`: figment's [`Value`] does not implement
/// [`Eq`] (its floating-point variants preclude reflexive equality
/// on `NaN`), so [`Dict`] and therefore [`DiscoveryComposition`] carry
/// only the partial contract. [`LayerAttribution`] is [`Eq`]
/// independently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryComposition {
    /// The merged dict. Equals `compose(layers)` for every input.
    pub dict: Dict,
    /// One entry per leaf in `dict`, naming the winning layer.
    pub attribution: LayerAttribution,
}

/// Compose an ordered stack of [`DiscoveryLayer`]s while tracking
/// per-leaf provenance — the name of the layer that last wrote each
/// leaf in the merged dict.
///
/// Layers are applied coarse→specific (same order as [`compose`]).
/// The returned [`DiscoveryComposition`] carries both the merged
/// [`Dict`] and a [`LayerAttribution`] keyed by dotted-path
/// components. [`compose`] is `compose_with_provenance(...).dict` by
/// construction — one primitive owns the merge semantics.
///
/// # Attribution semantics
///
/// - **Leaf overwrite** — a later layer writing a leaf at the same
///   path replaces the prior attribution.
/// - **Dict-over-scalar** / **scalar-over-dict** — the wholesale
///   replace that [`deep_merge`] performs at cross-shape boundaries
///   purges any prior sub-leaf attribution at the replaced path and
///   re-attributes every new leaf under it to the writing layer.
/// - **Empty layer** — a layer emitting an empty [`Dict`] contributes
///   no attributions; the earlier stack is preserved verbatim.
/// - **Sibling keys** — two layers that touch different leaves under
///   the same subtree each keep credit for what they wrote (the
///   recursive dict-merge stays granular per leaf).
#[must_use]
pub fn compose_with_provenance(layers: &[&dyn DiscoveryLayer]) -> DiscoveryComposition {
    let mut dict = Dict::new();
    let mut attribution: BTreeMap<Vec<String>, &'static str> = BTreeMap::new();
    for layer in layers {
        deep_merge_attributed(
            &mut dict,
            layer.discover(),
            &[],
            layer.name(),
            &mut attribution,
        );
    }
    DiscoveryComposition {
        dict,
        attribution: LayerAttribution { inner: attribution },
    }
}

/// Deep-merge helper that mirrors [`deep_merge`] while threading
/// per-leaf attribution. Kept private: the public seam is
/// [`compose_with_provenance`], which owns the `prefix` / `layer` /
/// `attribution` protocol.
fn deep_merge_attributed(
    base: &mut Dict,
    overlay: Dict,
    prefix: &[String],
    layer: &'static str,
    attribution: &mut BTreeMap<Vec<String>, &'static str>,
) {
    for (key, incoming) in overlay {
        let mut path = Vec::with_capacity(prefix.len() + 1);
        path.extend_from_slice(prefix);
        path.push(key.clone());
        match (base.get_mut(&key), incoming) {
            // Two maps: recurse so sibling keys keep their prior
            // attribution.
            (Some(Value::Dict(_, base_inner)), Value::Dict(_, over_inner)) => {
                deep_merge_attributed(base_inner, over_inner, &path, layer, attribution);
            }
            // Anything else: wholesale replace. Any prior sub-leaves
            // under this path are gone from the merged dict, so their
            // attribution goes with them; then re-attribute the new
            // value's leaves before installing.
            (_, incoming) => {
                attribution.retain(|p, _| !path_has_prefix(p, &path));
                attribute_leaves(&incoming, &path, layer, attribution);
                base.insert(key, incoming);
            }
        }
    }
}

/// True iff `path` names a descendant of (or equals) `prefix` in the
/// dotted-path lattice.
fn path_has_prefix(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

/// Record `layer` as the writer of every leaf reachable from `path`
/// inside `v`. Recurses into [`Value::Dict`]; every other variant is a
/// leaf that gets attributed at `path` itself.
fn attribute_leaves(
    v: &Value,
    path: &[String],
    layer: &'static str,
    attribution: &mut BTreeMap<Vec<String>, &'static str>,
) {
    match v {
        Value::Dict(_, inner) => {
            for (k, sub) in inner {
                let mut sub_path = path.to_vec();
                sub_path.push(k.clone());
                attribute_leaves(sub, &sub_path, layer, attribution);
            }
        }
        _ => {
            attribution.insert(path.to_vec(), layer);
        }
    }
}

/// The names of layers that *actually* contributed to the composed dict
/// — those whose [`DiscoveryLayer::discover`] returned a non-empty
/// [`Dict`] — in application order.
///
/// The diagnostic dual of [`layer_names`]: `layer_names` enumerates
/// every axis the caller declared (contributor or not); this projection
/// filters to the subset the environment answered. Every entry of
/// `contributor_names(layers)` also appears in `layer_names(layers)`
/// (subset invariant), with `contributor_names ⇒ layer_names` on the
/// per-name axis; the reverse holds iff every axis is detectable.
///
/// The complement within `layer_names` is [`silent_layer_names`] —
/// the axes that returned an empty [`Dict`]. Together the two
/// projections disjointly partition [`layer_names`]: every declared
/// axis is either a contributor or a silent one, never both, never
/// neither.
///
/// # Semantics
///
/// A "contributor" is a layer whose `discover()` wrote *something* into
/// the merge — the same predicate [`compose`] uses to decide whether a
/// layer participates. It says nothing about surviving leaves: a coarse
/// contributor wholly overridden by a specific one is still counted, so
/// the metric answers "which axes had an opinion" rather than "which
/// axes' opinions survived". `compose(layers).is_empty()` iff
/// `contributor_names(layers).is_empty()` whenever every contributor
/// writes at least one top-level key (the discipline every
/// [`DiscoveryLayer`] implementation satisfies by contract).
///
/// # Cost
///
/// Calls `discover()` once per layer. Callers that want the contributed
/// dicts alongside the names — for a per-layer config-show pane, or to
/// derive [`compose`] + [`contributor_names`] together without paying
/// the discover cost twice — reach for [`nonempty_layer_dicts`], which
/// captures both projections in the same sweep. Callers that want the
/// **post-merge** dual — the writers whose leaves *survived* the merge,
/// not just those who wrote into it — reach for
/// [`LayerAttribution::surviving_layer_names`] on a
/// [`compose_with_provenance`] result; the subset chain
/// `surviving ⊆ contributors ⊆ layer_names` holds by construction.
#[must_use]
pub fn contributor_names(layers: &[&dyn DiscoveryLayer]) -> Vec<&'static str> {
    layers
        .iter()
        .filter(|layer| !layer.discover().is_empty())
        .map(|layer| layer.name())
        .collect()
}

/// The names of layers whose [`DiscoveryLayer::discover`] returned an
/// *empty* [`Dict`] — axes that were declared but couldn't answer in
/// the running environment. The diagnostic dual of [`contributor_names`]
/// within [`layer_names`], in application order.
///
/// # Partition law
///
/// For every layer stack, `silent_layer_names(layers)` and
/// `contributor_names(layers)` form a disjoint partition of
/// `layer_names(layers)` — every declared name belongs to exactly one
/// of the two projections, and their union equals `layer_names(layers)`
/// as sets. The [`DiscoveryLayer::discover`] result is decisive:
/// non-empty ⇒ contributor, empty ⇒ silent. No name can appear in both
/// (a single boolean predicate splits the stack), and no declared name
/// can be missing from both (the two filters together cover every
/// element). Pinned by
/// `silent_layer_names_partitions_layer_names_disjointly` in
/// `src/discovered.rs`'s test module.
///
/// # Semantics
///
/// A "silent" axis is one whose environment probe couldn't answer —
/// `kanchi`-style detection returned `None` and the layer emitted the
/// clean degenerate empty [`Dict`] rather than guessing. The projection
/// answers "which declared axes were undetectable in the running
/// environment?" — the natural diagnostic pane on a config-show renderer
/// that groups axes by whether the environment fed them or not.
/// Application order is preserved (coarse→specific), matching
/// [`contributor_names`] on the surviving-name axis and
/// [`layer_names`] on the declared-name axis; the [`LayerAttribution`]
/// projections switch to lex order at the merge boundary.
///
/// # Cost
///
/// Calls `discover()` once per layer, `O(n)` on the layer count — the
/// mirror of [`contributor_names`]'s cost on the same axis. Callers
/// that want *both* projections in one sweep reach for
/// [`nonempty_layer_dicts`] and derive the silent set as the complement
/// of the pair-set's names within [`layer_names`].
#[must_use]
pub fn silent_layer_names(layers: &[&dyn DiscoveryLayer]) -> Vec<&'static str> {
    layers
        .iter()
        .filter(|layer| layer.discover().is_empty())
        .map(|layer| layer.name())
        .collect()
}

/// The `(name, discovered dict)` pairs for every layer whose
/// [`DiscoveryLayer::discover`] returned a non-empty [`Dict`], in
/// application order (coarse→specific).
///
/// The root primitive on the (name, contributed-dict) axis: it captures
/// what each contributor actually wrote, from which the substrate's
/// other layer-stack projections factor through in a single `discover()`
/// sweep. [`contributor_names`] is
/// `nonempty_layer_dicts(layers).into_iter().map(|(n, _)| n).collect()`;
/// [`compose`] is `nonempty_layer_dicts(layers).into_iter().fold(...)`
/// with [`deep_merge`]; the [`contributor_count`] scalar is this call's
/// `.len()`. Callers that need any two of those pay 2× the
/// discover cost when reaching for the two separate seams; reaching for
/// this primitive once and deriving both pays 1×.
///
/// # Semantics
///
/// The layered discipline is preserved verbatim: a contributor whose
/// top-level key is wholly overridden by a later specific layer is still
/// present in the output (the "had an opinion" semantics
/// [`contributor_names`] pins). Empty layers filter out — an
/// undetectable axis is invisible on the pair projection just as it is
/// invisible in the composed dict. Application order is
/// caller-declared, not alphabetical: `[coarse, specific]` and
/// `[specific, coarse]` yield the same pair set but in opposite orders,
/// matching how [`compose`] would apply them.
///
/// # Cost
///
/// Calls `discover()` once per layer, `O(n)` on the layer count. Owns
/// every returned [`Dict`] (no borrowed data), so callers can consume
/// them without threading a lifetime back to the layer stack. Each
/// contributor's dict is byte-identical to what its `discover()`
/// returned on this call — no pre-merge, no filtering of inner keys.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to Lightbend HOCON's
/// `Config.entrySet()` grouped by [origin], but at the *layer* granularity
/// this substrate exposes: one entry per contributing axis, each carrying
/// its full partial view of the config. A "config-show grouped by
/// origin" pane reaches for this primitive once and iterates the pairs.
///
/// [origin]: https://lightbend.github.io/config/latest/api/com/typesafe/config/ConfigOrigin.html
#[must_use]
pub fn nonempty_layer_dicts(layers: &[&dyn DiscoveryLayer]) -> Vec<(&'static str, Dict)> {
    layers
        .iter()
        .filter_map(|layer| {
            let dict = layer.discover();
            if dict.is_empty() {
                None
            } else {
                Some((layer.name(), dict))
            }
        })
        .collect()
}

/// The **number of layers** whose [`DiscoveryLayer::discover`] returned a
/// non-empty [`Dict`] — the count of axes that had *some* opinion in the
/// running environment.
///
/// The **scalar-cardinality endpoint** of the whole-layer touchers axis:
/// [`contributor_names`] returns the ordered list of contributor names,
/// [`nonempty_layer_dicts`] returns those names paired with their
/// contributed dicts, and this primitive returns their cardinality
/// directly — the length-fold of both projections on the same
/// `discover()` sweep, with a **zero-allocation** walker on top.
///
/// The **root specialization** of [`contributor_count_at`]: at the empty
/// path (the root), every "toucher" of `&[]` is exactly a layer with a
/// non-empty `discover()` dict — the same predicate this primitive
/// folds. The equality
///
/// ```text
/// contributor_count(layers) == contributor_count_at(layers, &[])
/// ```
///
/// holds by construction, and closes the root endpoint of the (path,
/// layer) scalar-cardinality axis onto the (layer) axis.
///
/// # Identities
///
/// The four scalar-cardinality projections on the whole-layer axis
/// collapse onto one substrate-owned primitive with a **zero-allocation**
/// walk:
///
/// - `contributor_count(layers) == `[`contributor_names`]`(layers).len()`
///   (length-fold on the ordered-names axis)
/// - `contributor_count(layers) == `[`nonempty_layer_dicts`]`(layers).len()`
///   (length-fold on the (name, dict) pair axis)
/// - `contributor_count(layers) == `[`contributor_count_at`]`(layers, &[])`
///   (root-path specialization of the point primitive)
/// - `contributor_count(layers) + `[`silent_layer_names`]`(layers).len() ==
///   `[`layer_names`]`(layers).len()` (partition-count identity — every
///   declared layer belongs to exactly one of the two subsets)
/// - `contributor_count(layers) + `[`silent_layer_count`]`(layers) ==
///   `[`layer_names`]`(layers).len()` (**pure-scalar** partition-count
///   identity — the silent-side length is now folded on its own scalar
///   dual, so the entire two-subset partition arithmetic reads with
///   zero allocation on both addends)
///
/// The cardinality-threshold endpoints of the whole-layer axis read off
/// the scalar directly:
///
/// ```text
/// contributor_count(layers) == 0   ⇔  !is_touched_at(layers, &[])
/// contributor_count(layers) >= 1   ⇔   is_touched_at(layers, &[])
/// ```
///
/// All four routes are algebraically identical on their shared scalar
/// output; this primitive is the strictly-cheapest route when the caller
/// wants only the count and does not need the ordered names, the
/// (name, dict) pairs, the point primitive's per-path walker, or the
/// silent-axis complement.
///
/// # Cost
///
/// Calls `discover()` once per layer and folds with
/// [`Iterator::count`] — worst-case `O(n)` on the layer count, **zero
/// allocation** on the walker itself. Strictly cheaper than every
/// alternative on the same axis:
///
/// - [`contributor_names`]`(layers).len()` walks every layer and
///   allocates the full `Vec<&'static str>` of names, then reads its
///   length off the fat pointer.
/// - [`nonempty_layer_dicts`]`(layers).len()` walks every layer,
///   allocates the full `Vec<(&'static str, Dict)>` of pairs (cloning
///   every contributor's dict on the way), then reads its length off the
///   fat pointer.
/// - [`contributor_count_at`]`(layers, &[])` calls `touches_path(&d,
///   &[])` — the general point primitive with an extra empty-slice
///   dispatch on every layer that this root primitive avoids.
/// - [`layer_names`]`(layers).len() - `[`silent_layer_names`]`(layers).len()`
///   walks every layer twice and allocates two `Vec<&'static str>`s only
///   to fold both to their lengths.
///
/// This primitive short-circuits nothing (the whole layer stack must be
/// walked to know the total) but allocates nothing either — the
/// [`Iterator::count`] adapter compiles to a bump-a-`usize` walk.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "how many sources contributed to
/// this configuration?" — Lightbend HOCON callers reconstruct this by
/// iterating `Config.origins()` per merged source and filtering to those
/// that opened any value. `contributor_count` packages the count as one
/// substrate-owned primitive over the same non-empty-source predicate
/// that [`contributor_names`] pins, with the whole-layer boundary
/// invariant `count == 0 ⇔ every layer is silent` pinned against every
/// neighboring endpoint on the lattice.
#[must_use]
pub fn contributor_count(layers: &[&dyn DiscoveryLayer]) -> usize {
    layers
        .iter()
        .filter(|layer| !layer.discover().is_empty())
        .count()
}

/// The **number of layers** whose [`DiscoveryLayer::discover`] returned an
/// *empty* [`Dict`] — the count of declared axes the running environment
/// couldn't answer.
///
/// The **scalar-cardinality endpoint** of the whole-layer silent axis: the
/// dual of [`contributor_count`] on the same partition, standing to
/// [`silent_layer_names`] as [`contributor_count`] stands to
/// [`contributor_names`]. [`silent_layer_names`] returns the ordered
/// list of silent-layer names; this primitive returns their cardinality
/// directly — the length-fold of that projection on the same
/// `discover()` sweep, with a **zero-allocation** walker on top.
///
/// # Identities
///
/// The whole-layer partition now closes onto **two** substrate-owned
/// scalar primitives with a **zero-allocation** walk on both sides,
/// pinning the partition-count law entirely in scalar arithmetic
/// without materializing either name list:
///
/// - `silent_layer_count(layers) == `[`silent_layer_names`]`(layers).len()`
///   (length-fold on the silent-names axis — the dual of
///   [`contributor_count`]'s length-fold on the contributor-names axis)
/// - `silent_layer_count(layers) + `[`contributor_count`]`(layers) ==
///   `[`layer_names`]`(layers).len()` (the **pure-scalar** partition-count
///   identity: every declared layer belongs to exactly one of the two
///   subsets, and neither the numerator nor the denominator materializes
///   a name `Vec` — the whole-layer partition arithmetic collapses to
///   three bare `Iterator::count` walks)
/// - `silent_layer_count(layers) == `[`layer_names`]`(layers).len() -
///   `[`contributor_count`]`(layers)` (the complement identity: the
///   silent count is the missing addend on the partition when the
///   contributor count and the declared count are already in hand)
///
/// The cardinality-threshold endpoints of the silent axis at the root
/// read off the scalar directly:
///
/// ```text
/// silent_layer_count(layers) == 0                            ⇔   every declared layer is a contributor
/// silent_layer_count(layers) == layer_names(layers).len()    ⇔   every declared layer is silent
/// silent_layer_count(layers) >= 1                            ⇔   at least one declared layer is silent
/// ```
///
/// All three routes on the length-fold axis are algebraically identical
/// on their shared scalar output; this primitive is the strictly-cheapest
/// route when the caller wants only the count and does not need the
/// ordered silent-layer names or the declared-layer name list.
///
/// # Cost
///
/// Calls `discover()` once per layer and folds with [`Iterator::count`]
/// — worst-case `O(n)` on the layer count, **zero allocation** on the
/// walker itself. Strictly cheaper than every alternative on the same
/// axis:
///
/// - [`silent_layer_names`]`(layers).len()` walks every layer and
///   allocates the full `Vec<&'static str>` of silent names, then reads
///   its length off the fat pointer.
/// - [`layer_names`]`(layers).len() - `[`contributor_count`]`(layers)`
///   walks every layer twice — once for the declared-name `Vec`
///   allocation, once for the contributor filter — only to fold both to
///   arithmetic on the second walk.
///
/// This primitive short-circuits nothing (the whole layer stack must be
/// walked to know the total) but allocates nothing either — the
/// [`Iterator::count`] adapter compiles to a bump-a-`usize` walk over
/// the same non-empty-discover predicate that
/// [`contributor_count`] folds, only inverted.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "how many declared configuration
/// sources were undetectable in the running environment?" — Lightbend
/// HOCON has no direct equivalent (its `ConfigFactory.parseResources`
/// silently drops missing sources), so the answer is not recoverable
/// from a merged `Config` at all. Figment 0.10 tracks a `Tag` per leaf
/// but reports no whole-provider-silent count. `silent_layer_count`
/// packages that diagnostic count as one substrate-owned primitive over
/// the same silence predicate that [`silent_layer_names`] pins, with
/// the whole-layer boundary invariant `silent_layer_count +
/// contributor_count == layer_names.len()` pinned in pure-scalar
/// arithmetic against every neighboring endpoint on the lattice.
#[must_use]
pub fn silent_layer_count(layers: &[&dyn DiscoveryLayer]) -> usize {
    layers
        .iter()
        .filter(|layer| layer.discover().is_empty())
        .count()
}

/// True iff **at least one declared layer** contributed a non-empty
/// [`DiscoveryLayer::discover`] dict — the whole-layer "≥ 1" boolean
/// predicate on the contributors axis.
///
/// The **whole-layer specialization of [`is_touched_at`] at the empty
/// path**: on `path = &[]` the general point predicate collapses to the
/// same non-empty-discover filter this primitive uses directly, with
/// one fewer function-call boundary and no path slice traversal:
///
/// ```text
/// has_contributor(layers) == is_touched_at(layers, &[])
/// ```
///
/// The **boolean-cardinality-threshold endpoint** of the whole-layer
/// contributors axis: [`contributor_count`] returns the exact scalar
/// count (folded with [`Iterator::count`]); this primitive returns the
/// "one or more" bit directly (folded with [`Iterator::any`]) — the
/// same short-circuit distinction that [`is_touched_at`] carries over
/// [`contributor_count_at`] at the point altitude.
///
/// The **presence dual** of every neighboring emptiness endpoint on the
/// whole-layer contributors axis: [`contributor_names`] carries the
/// [`Vec::is_empty`] boundary as `.is_empty()`; [`nonempty_layer_dicts`]
/// carries it on the (name, dict) pair `Vec` at the same partition; and
/// [`contributor_count`] carries it at the arithmetic zero. This
/// primitive returns the same bit directly as a [`bool`], without
/// materializing a name (which the caller then discards) or an owned
/// [`Vec`], and short-circuits at the first non-empty layer rather than
/// walking the full stack.
///
/// # Identities
///
/// The five presence-boundary projections on the whole-layer
/// contributors axis collapse onto one substrate-owned primitive with
/// a **short-circuit forward walk**:
///
/// - `has_contributor(layers) == `[`contributor_count`]`(layers) >= 1`
///   (cardinality-threshold identity at "≥ 1")
/// - `has_contributor(layers) == !`[`contributor_names`]`(layers).is_empty()`
///   (ordered-list emptiness dual on the contributors axis)
/// - `has_contributor(layers) == !`[`nonempty_layer_dicts`]`(layers).is_empty()`
///   (ordered-pair emptiness dual on the (name, dict) axis)
/// - `has_contributor(layers) == `[`is_touched_at`]`(layers, &[])`
///   (whole-layer→point-path root-specialization identity)
/// - `has_contributor(layers) == (`[`silent_layer_count`]`(layers) < `[`layer_names`]`(layers).len())`
///   (partition-complement identity: some declared layer is a
///   contributor iff not every declared layer is silent, holding across
///   both the empty stack — where both sides are `false` — and the
///   fully-populated stack in pure-scalar arithmetic against the
///   partition-count law)
///
/// The monotonic chain against the whole-layer partition-count law
/// (`contributor_count + silent_layer_count == layer_names.len()`):
///
/// ```text
/// has_contributor(layers)  =>  contributor_count(layers) >= 1
/// !has_contributor(layers) =>  contributor_count(layers) == 0
///                          =>  silent_layer_count(layers) == layer_names(layers).len()
/// ```
///
/// The 2×2 truth table on the whole-layer partition against
/// [`silent_layer_count`]`(layers) >= 1`:
///
/// ```text
/// !has_contributor && silent_layer_count == 0    ⇔  layers.is_empty()
///                                                    (empty stack — nothing declared)
/// has_contributor && silent_layer_count == 0     ⇔  every declared layer contributes
///                                                    (upper contributors-axis endpoint)
/// !has_contributor && silent_layer_count >= 1    ⇔  every declared layer is silent
///                                                    (upper silent-axis endpoint)
/// has_contributor && silent_layer_count >= 1     ⇔  mixed stack (some contribute, some silent)
/// ```
///
/// All five projection routes are algebraically identical on their
/// shared boolean output; this primitive is the strictly-cheapest route
/// when the caller wants only the presence predicate and does not need
/// the ordered contributor names, the (name, dict) pair list, the
/// exact contributor count, or a point-path traversal through
/// [`is_touched_at`].
///
/// # Semantics
///
/// The set of contributors is exactly the [`contributor_names`]
/// projection: every layer whose `discover()` returns a non-empty
/// [`Dict`]. One contributor is the true-boundary; the zero-contributor
/// cases — the empty layer stack and the all-silent stack — are the
/// two false-boundaries, collapsed under the same `false` return.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the first
/// contributor** — worst-case `O(n)` on the layer count (nobody
/// contributes, so [`Iterator::any`] runs the full stack), best-case
/// `O(1)` (the coarsest layer contributes and short-circuits the
/// walk). Zero allocation on the walker itself. Strictly cheaper than
/// every alternative on the same axis:
///
/// - [`contributor_names`]`(layers).is_empty()` walks every layer and
///   allocates the full `Vec<&'static str>` of names, then reads the
///   emptiness bit off the fat pointer — no short-circuit at any hit.
/// - [`nonempty_layer_dicts`]`(layers).is_empty()` walks every layer,
///   allocates the full `Vec<(&'static str, Dict)>` of pairs (cloning
///   every contributor's dict on the way), then reads the emptiness
///   bit off the fat pointer.
/// - [`contributor_count`]`(layers) >= 1` walks every layer with
///   [`Iterator::count`] and reads a scalar comparison off the total —
///   no short-circuit at any hit.
/// - [`is_touched_at`]`(layers, &[])` calls `touches_path(&d, &[])` —
///   the general point primitive with an extra empty-slice dispatch
///   on every layer that this whole-layer primitive avoids.
///
/// This primitive short-circuits at the first contributor *and*
/// returns the boolean directly without projecting through an owned
/// name — the [`Iterator::any`] adapter compiles to a single-branch
/// forward walk over the same non-empty-discover predicate that
/// [`contributor_count`] folds, only stopped at the first hit.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "did any declared configuration
/// source contribute anything?" — Lightbend HOCON has no direct
/// equivalent (its `ConfigFactory.parseResources` silently drops
/// missing sources, so the answer requires iterating each source's
/// `entrySet()` and checking that at least one is non-empty). Figment
/// 0.10 tracks a `Tag` per leaf but reports no whole-provider
/// presence bit. `has_contributor` packages the diagnostic bit as one
/// substrate-owned primitive over the same non-empty-source predicate
/// that [`contributor_names`] and [`contributor_count`] fold, with a
/// short-circuiting `.any()` walk that matches [`is_touched_at`]'s
/// point-level short-circuit semantics one altitude up.
#[must_use]
pub fn has_contributor(layers: &[&dyn DiscoveryLayer]) -> bool {
    layers.iter().any(|layer| !layer.discover().is_empty())
}

/// True iff **at least one declared layer** returned an empty
/// [`DiscoveryLayer::discover`] dict — the whole-layer "≥ 1" boolean
/// predicate on the *silent* axis.
///
/// The **silent-axis dual of [`has_contributor`]**: that primitive folds
/// the "one or more contributors" bit over the `!discover().is_empty()`
/// predicate; this primitive folds the "one or more silent layers" bit
/// over the inverted `discover().is_empty()` predicate — the same
/// short-circuit forward walk [`silent_layer_count`] would perform if its
/// [`Iterator::count`] fold were replaced by [`Iterator::any`] on the
/// losing side of the whole-layer partition.
///
/// The **boolean-cardinality-threshold endpoint** of the whole-layer
/// silent axis: [`silent_layer_count`] returns the exact scalar count
/// (folded with [`Iterator::count`]); this primitive returns the "one or
/// more" bit directly (folded with [`Iterator::any`]) — the same
/// short-circuit distinction that [`has_contributor`] carries over
/// [`contributor_count`] on the contributors axis.
///
/// The **presence dual** of every neighboring emptiness endpoint on the
/// whole-layer silent axis: [`silent_layer_names`] carries the
/// [`Vec::is_empty`] boundary as `.is_empty()`; [`silent_layer_count`]
/// carries it at the arithmetic zero. This primitive returns the same bit
/// directly as a [`bool`], without materializing a name (which the caller
/// then discards) or walking the full stack, and short-circuits at the
/// first silent layer rather than folding a count off the total.
///
/// # Identities
///
/// The four presence-boundary projections on the whole-layer silent axis
/// collapse onto one substrate-owned primitive with a **short-circuit
/// forward walk**:
///
/// - `has_silent_layer(layers) == `[`silent_layer_count`]`(layers) >= 1`
///   (cardinality-threshold identity at "≥ 1")
/// - `has_silent_layer(layers) == !`[`silent_layer_names`]`(layers).is_empty()`
///   (ordered-list emptiness dual on the silent-names axis)
/// - `has_silent_layer(layers) == (`[`contributor_count`]`(layers) < `[`layer_names`]`(layers).len())`
///   (partition-complement identity: some declared layer is silent iff
///   not every declared layer is a contributor, holding across both the
///   empty stack — where both sides are `false` — and the fully-populated
///   stack in pure-scalar arithmetic against the partition-count law)
/// - `has_silent_layer(layers) == (`[`nonempty_layer_dicts`]`(layers).len() < `[`layer_names`]`(layers).len())`
///   (pair-partition-complement identity: the contributor-side
///   `Vec::len` folded through the same partition-count law)
///
/// The monotonic chain against the whole-layer partition-count law
/// (`contributor_count + silent_layer_count == layer_names.len()`):
///
/// ```text
/// has_silent_layer(layers)  =>  silent_layer_count(layers) >= 1
/// !has_silent_layer(layers) =>  silent_layer_count(layers) == 0
///                           =>  contributor_count(layers) == layer_names(layers).len()
/// ```
///
/// The **2×2 truth table** over `(`[`has_contributor`]`, has_silent_layer)`
/// closes the whole-layer partition in short-circuiting boolean arithmetic
/// against both partition subsets at once, replacing the mixed
/// scalar/boolean formulation on [`has_contributor`]'s doc block:
///
/// ```text
/// !has_contributor && !has_silent_layer  ⇔  layers.is_empty()
///                                             (empty stack — nothing declared)
/// has_contributor  && !has_silent_layer  ⇔  every declared layer contributes
///                                             (upper contributors-axis endpoint)
/// !has_contributor && has_silent_layer   ⇔  every declared layer is silent
///                                             (upper silent-axis endpoint)
/// has_contributor  && has_silent_layer   ⇔  mixed stack (some contribute, some silent)
/// ```
///
/// All four projection routes on the silent axis are algebraically
/// identical on their shared boolean output; this primitive is the
/// strictly-cheapest route when the caller wants only the presence
/// predicate and does not need the ordered silent-layer names, the exact
/// silent count, or the contributors-side partition scalar.
///
/// # Semantics
///
/// The set of silent layers is exactly the [`silent_layer_names`]
/// projection: every layer whose `discover()` returns an empty [`Dict`].
/// One silent layer is the true-boundary; the zero-silent-layer cases —
/// the empty layer stack and the every-layer-contributes stack — are the
/// two false-boundaries, collapsed under the same `false` return.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the first silent
/// layer** — worst-case `O(n)` on the layer count (every layer
/// contributes, so [`Iterator::any`] runs the full stack), best-case
/// `O(1)` (the coarsest layer is silent and short-circuits the walk).
/// Zero allocation on the walker itself. Strictly cheaper than every
/// alternative on the same axis:
///
/// - [`silent_layer_names`]`(layers).is_empty()` walks every layer and
///   allocates the full `Vec<&'static str>` of silent names, then reads
///   the emptiness bit off the fat pointer — no short-circuit at any hit.
/// - [`silent_layer_count`]`(layers) >= 1` walks every layer with
///   [`Iterator::count`] and reads a scalar comparison off the total —
///   no short-circuit at any hit.
/// - [`contributor_count`]`(layers) < `[`layer_names`]`(layers).len()`
///   walks every layer twice — once for the declared-name `Vec`
///   allocation, once for the contributor filter — then reads a scalar
///   comparison off the two totals.
///
/// This primitive short-circuits at the first silent layer *and* returns
/// the boolean directly without projecting through an owned name — the
/// [`Iterator::any`] adapter compiles to a single-branch forward walk
/// over the same is-empty-discover predicate that [`silent_layer_count`]
/// folds, only stopped at the first hit.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "did any declared configuration
/// source fail to contribute anything?" — Lightbend HOCON has no direct
/// equivalent (its `ConfigFactory.parseResources` silently drops missing
/// sources, so the answer is not recoverable from a merged `Config`
/// at all). Figment 0.10 tracks a `Tag` per leaf but reports no
/// whole-provider-silent presence bit. `has_silent_layer` packages the
/// diagnostic bit as one substrate-owned primitive over the same
/// silence predicate that [`silent_layer_names`] and [`silent_layer_count`]
/// share, with a short-circuiting `.any()` walk that matches
/// [`has_contributor`]'s presence-axis short-circuit semantics on the
/// complementary partition subset.
#[must_use]
pub fn has_silent_layer(layers: &[&dyn DiscoveryLayer]) -> bool {
    layers.iter().any(|layer| layer.discover().is_empty())
}

/// True iff **at least two declared layers** contributed a non-empty
/// [`DiscoveryLayer::discover`] dict — the whole-layer "≥ 2" boolean
/// predicate on the contributors axis.
///
/// The **whole-layer specialization of [`is_contested_at`] at the empty
/// path**: on `path = &[]` the general point predicate collapses to the
/// same non-empty-discover filter this primitive uses directly, with
/// one fewer function-call boundary and no path slice traversal:
///
/// ```text
/// has_multiple_contributors(layers) == is_contested_at(layers, &[])
/// ```
///
/// The **boolean-cardinality-threshold "≥ 2" endpoint** of the whole-layer
/// contributors axis: [`has_contributor`] closes the "≥ 1" endpoint of the
/// same axis (with an [`Iterator::any`] short-circuit at the first hit);
/// this primitive closes the "≥ 2" endpoint (with an [`Iterator::nth`]
/// short-circuit at the second hit). Together the pair partitions the
/// exact-cardinality trichotomy on the whole-layer contributors axis:
///
/// ```text
/// contributor_count(layers) == 0   ⇔  !has_contributor(layers)
/// contributor_count(layers) == 1   ⇔   has_contributor(layers) && !has_multiple_contributors(layers)
/// contributor_count(layers) >= 2   ⇔   has_multiple_contributors(layers)
/// ```
///
/// the whole-layer analog of the (`is_touched_at`, `is_contested_at`)
/// trichotomy [`is_touched_at`] carries at the point altitude, with the
/// monotonic chain `has_multiple_contributors ⇒ has_contributor` shifting
/// the predicate axis by exactly one hit.
///
/// The **necessary-and-not-sufficient condition** for any leaf-level
/// override contest: no leaf `p` can carry an override contest unless
/// `has_multiple_contributors(layers)` — at most one non-empty layer means
/// every touched leaf has at most one toucher, so
/// `is_contested_at(layers, p)` is `false` for every path `p`. The
/// converse fails at disjoint-key layered configs (two contributors that
/// touch disjoint leaves — the pair is layered at the config level but no
/// leaf is contested). The one-way implication
///
/// ```text
/// (∃ path p : is_contested_at(layers, p))  =>  has_multiple_contributors(layers)
/// ```
///
/// holds by construction and is the diagnostic gate every "did any
/// override happen anywhere in this config?" walk short-circuits behind.
///
/// # Identities
///
/// The five presence-boundary projections on the whole-layer contributors
/// axis at the "≥ 2" cardinality-threshold collapse onto one
/// substrate-owned primitive with a **short-circuit forward walk**:
///
/// - `has_multiple_contributors(layers) == `[`contributor_count`]`(layers) >= 2`
///   (cardinality-threshold identity at "≥ 2")
/// - `has_multiple_contributors(layers) == `[`is_contested_at`]`(layers, &[])`
///   (whole-layer→point-path root-specialization identity)
/// - `has_multiple_contributors(layers) == (`[`contributor_names`]`(layers).len() >= 2)`
///   (ordered-list cardinality-threshold dual on the contributors axis)
/// - `has_multiple_contributors(layers) == (`[`nonempty_layer_dicts`]`(layers).len() >= 2)`
///   (ordered-pair cardinality-threshold dual on the (name, dict) axis)
/// - `has_multiple_contributors(layers) == `[`has_contributor`]`(layers) && (`[`contributor_count`]`(layers) != 1)`
///   (trichotomy identity: "≥ 2" iff "≥ 1" and "not exactly 1", holding
///   in short-circuiting boolean arithmetic against the "≥ 1" endpoint)
///
/// The monotonic chain against the "≥ 1" endpoint:
///
/// ```text
/// has_multiple_contributors(layers)  =>  has_contributor(layers)
/// !has_contributor(layers)           =>  !has_multiple_contributors(layers)
/// ```
///
/// The singleton characterization on the exact-cardinality axis:
///
/// ```text
/// has_contributor(layers) && !has_multiple_contributors(layers)
///     <=>  contributor_count(layers) == 1
/// ```
///
/// — the whole-layer analog of the point-altitude singleton
/// characterization
/// `is_touched_at(layers, p) && !is_contested_at(layers, p)
///   <=> contributor_count_at(layers, p) == 1`.
///
/// All five routes are algebraically identical on their shared boolean
/// output; this primitive is the strictly-cheapest route when the caller
/// wants only the "layered ≥ 2" presence predicate and does not need the
/// ordered contributor names, the (name, dict) pair list, the exact
/// contributor count, or a point-path traversal through
/// [`is_contested_at`].
///
/// # Semantics
///
/// The set of contributors is exactly the [`contributor_names`] projection:
/// every layer whose `discover()` returns a non-empty [`Dict`]. Two
/// contributors is the true-boundary; the zero-contributor and
/// one-contributor cases (nothing declared, everything silent, single
/// non-silent axis) are the two false-boundaries, collapsed under the
/// same `false` return. A `true` return says the config was assembled
/// from **more than one non-empty axis** — the necessary condition for
/// any layered-override diagnostic.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the second contributor**
/// — worst-case `O(n)` on the layer count (fewer than two contributors,
/// so [`Iterator::nth`] runs the full stack), best-case `O(2)` (the two
/// coarsest layers both contribute and short-circuit the walk at the
/// second hit). Zero allocation on the walker itself. Strictly cheaper
/// than every alternative on the same axis:
///
/// - [`contributor_names`]`(layers).len() >= 2` walks every layer and
///   allocates the full `Vec<&'static str>` of names, then reads the
///   length off the fat pointer and compares — no short-circuit at any hit.
/// - [`nonempty_layer_dicts`]`(layers).len() >= 2` walks every layer,
///   allocates the full `Vec<(&'static str, Dict)>` of pairs (cloning
///   every contributor's dict on the way), then reads the length off the
///   fat pointer and compares.
/// - [`contributor_count`]`(layers) >= 2` walks every layer with
///   [`Iterator::count`] and reads a scalar comparison off the total —
///   no short-circuit at the second hit.
/// - [`is_contested_at`]`(layers, &[])` calls `touches_path(&d, &[])` —
///   the general point primitive with an extra empty-slice dispatch on
///   every layer that this whole-layer primitive avoids.
///
/// This primitive short-circuits at the second contributor *and* returns
/// the boolean directly without projecting through an owned name — the
/// [`Iterator::nth`] adapter compiles to a single-branch forward walk
/// over the same non-empty-discover predicate that [`contributor_count`]
/// folds, only stopped at the second hit.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "did more than one declared
/// configuration source contribute?" — Lightbend HOCON has no direct
/// equivalent (its `ConfigFactory.parseResources` silently drops missing
/// sources, so the answer requires iterating each source's `entrySet()`
/// and counting the non-empty entries). Figment 0.10 tracks a `Tag` per
/// leaf but reports no whole-provider "at least two sources contributed"
/// bit. `has_multiple_contributors` packages the diagnostic gate as one
/// substrate-owned primitive over the same non-empty-source predicate
/// that [`contributor_names`] and [`contributor_count`] fold, with a
/// short-circuiting `.nth(1).is_some()` walk that matches
/// [`is_contested_at`]'s point-level short-circuit semantics one altitude
/// up.
#[must_use]
pub fn has_multiple_contributors(layers: &[&dyn DiscoveryLayer]) -> bool {
    layers
        .iter()
        .filter(|layer| !layer.discover().is_empty())
        .nth(1)
        .is_some()
}

/// True iff **at least two declared layers** returned an empty
/// [`DiscoveryLayer::discover`] dict — the whole-layer "≥ 2" boolean
/// predicate on the *silent* axis.
///
/// The **silent-axis dual of [`has_multiple_contributors`]**: that
/// primitive folds the "two or more contributors" bit over the
/// `!discover().is_empty()` predicate with an [`Iterator::nth`]
/// short-circuit at the second hit; this primitive folds the "two or
/// more silent layers" bit over the inverted `discover().is_empty()`
/// predicate with the same [`Iterator::nth`] short-circuit — the exact
/// walk [`silent_layer_count`] would perform if its [`Iterator::count`]
/// fold were replaced by [`Iterator::nth(1).is_some()`] on the losing
/// side of the whole-layer partition.
///
/// The **boolean-cardinality-threshold "≥ 2" endpoint** of the
/// whole-layer silent axis: [`has_silent_layer`] closes the "≥ 1"
/// endpoint of the same axis (with an [`Iterator::any`] short-circuit
/// at the first silent layer); this primitive closes the "≥ 2"
/// endpoint (with an [`Iterator::nth`] short-circuit at the second
/// silent layer). Together the pair partitions the exact-cardinality
/// trichotomy on the whole-layer silent axis:
///
/// ```text
/// silent_layer_count(layers) == 0   ⇔  !has_silent_layer(layers)
/// silent_layer_count(layers) == 1   ⇔   has_silent_layer(layers) && !has_multiple_silent_layers(layers)
/// silent_layer_count(layers) >= 2   ⇔   has_multiple_silent_layers(layers)
/// ```
///
/// the silent-axis mirror of the
/// `(has_contributor, has_multiple_contributors)` trichotomy on the
/// contributors axis, with the monotonic chain
/// `has_multiple_silent_layers ⇒ has_silent_layer` shifting the
/// predicate axis by exactly one hit.
///
/// The **3×3 truth table** over
/// `(has_multiple_contributors, has_multiple_silent_layers)` closes
/// the whole-layer "≥ 2" cardinality-threshold partition in
/// short-circuiting boolean arithmetic on both partition subsets at
/// once — the "≥ 2" analog of the
/// `(has_contributor, has_silent_layer)` 2×2 truth table on the "≥ 1"
/// endpoints. Every reachable state — empty stack, one-contributor,
/// two-contributor, mixed one-and-one, all-silent — is distinguished
/// by an ordered-pair of two short-circuiting boolean reads without
/// folding either partition scalar.
///
/// # Identities
///
/// The four presence-boundary projections on the whole-layer silent
/// axis at the "≥ 2" cardinality-threshold collapse onto one
/// substrate-owned primitive with a **short-circuit forward walk**:
///
/// - `has_multiple_silent_layers(layers) == `[`silent_layer_count`]`(layers) >= 2`
///   (cardinality-threshold identity at "≥ 2")
/// - `has_multiple_silent_layers(layers) == (`[`silent_layer_names`]`(layers).len() >= 2)`
///   (ordered-list cardinality-threshold dual on the silent-names axis)
/// - `has_multiple_silent_layers(layers) == (`[`layer_names`]`(layers).len() >= `[`contributor_count`]`(layers) + 2)`
///   (partition-complement identity: "≥ 2 silent" iff "declared
///   denominator exceeds the contributor scalar by at least 2",
///   holding across the empty stack in pure-scalar arithmetic against
///   the partition-count law
///   `contributor_count + silent_layer_count == layer_names.len()`)
/// - `has_multiple_silent_layers(layers) == (`[`layer_names`]`(layers).len() >= `[`nonempty_layer_dicts`]`(layers).len() + 2)`
///   (pair-partition-complement identity: the contributor-side
///   `Vec::len` folded through the same partition-count law at the
///   "≥ 2" threshold)
///
/// The monotonic chain against the "≥ 1" endpoint:
///
/// ```text
/// has_multiple_silent_layers(layers)  =>  has_silent_layer(layers)
/// !has_silent_layer(layers)           =>  !has_multiple_silent_layers(layers)
/// ```
///
/// The singleton characterization on the exact-cardinality silent axis:
///
/// ```text
/// has_silent_layer(layers) && !has_multiple_silent_layers(layers)
///     <=>  silent_layer_count(layers) == 1
/// ```
///
/// — the silent-axis mirror of the point-altitude singleton
/// characterization
/// `has_contributor(layers) && !has_multiple_contributors(layers)
///   <=> contributor_count(layers) == 1`.
///
/// All four routes are algebraically identical on their shared
/// boolean output; this primitive is the strictly-cheapest route when
/// the caller wants only the "≥ 2 silent axes" presence predicate and
/// does not need the ordered silent-layer names, the exact silent
/// count, or the contributors-side partition scalar.
///
/// # Semantics
///
/// The set of silent layers is exactly the [`silent_layer_names`]
/// projection: every layer whose `discover()` returns an empty
/// [`Dict`]. Two silent layers is the true-boundary; the
/// zero-silent-layer and one-silent-layer cases (every declared axis
/// contributes, or exactly one is silent) are the two false-boundaries,
/// collapsed under the same `false` return. A `true` return says the
/// declared axis surface has **more than one undetectable axis** — the
/// necessary condition for a discovery diagnostic that wants to
/// distinguish "one axis is unavailable" from "many axes are
/// unavailable" without folding the silent scalar.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the second silent
/// layer** — worst-case `O(n)` on the layer count (fewer than two
/// silent layers, so [`Iterator::nth`] runs the full stack),
/// best-case `O(2)` (the two coarsest layers are both silent and
/// short-circuit the walk at the second hit). Zero allocation on the
/// walker itself. Strictly cheaper than every alternative on the
/// same axis:
///
/// - [`silent_layer_names`]`(layers).len() >= 2` walks every layer
///   and allocates the full `Vec<&'static str>` of silent names, then
///   reads the length off the fat pointer and compares — no
///   short-circuit at any hit.
/// - [`silent_layer_count`]`(layers) >= 2` walks every layer with
///   [`Iterator::count`] and reads a scalar comparison off the total —
///   no short-circuit at the second hit.
/// - `layer_names(layers).len() >= contributor_count(layers) + 2`
///   walks every layer twice — once for the declared-name `Vec`
///   allocation, once for the contributor filter — then reads a
///   scalar comparison off the two totals.
///
/// This primitive short-circuits at the second silent layer *and*
/// returns the boolean directly without projecting through an owned
/// name — the [`Iterator::nth`] adapter compiles to a single-branch
/// forward walk over the same is-empty-discover predicate that
/// [`silent_layer_count`] folds, only stopped at the second hit.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "did more than one declared
/// configuration source fail to contribute?" — Lightbend HOCON's
/// `ConfigFactory.parseResources` silently drops missing sources, so
/// the answer is not recoverable from a merged `Config` at all.
/// Figment 0.10's per-value `Tag` names surviving-leaf origins but
/// exposes no whole-provider "≥ 2 silent sources" bit — a Figment
/// diagnostic pane that wants to say "many declared providers had
/// nothing to say" iterates the provider stack by hand, walks each
/// provider's `data()`, and counts empty results.
/// `has_multiple_silent_layers` packages that bit as one
/// substrate-owned primitive over the same is-empty-source predicate
/// that [`silent_layer_names`] and [`silent_layer_count`] share, with
/// the short-circuiting `.nth(1).is_some()` walk that matches
/// [`has_multiple_contributors`]'s presence-axis short-circuit
/// semantics on the complementary partition subset.
#[must_use]
pub fn has_multiple_silent_layers(layers: &[&dyn DiscoveryLayer]) -> bool {
    layers
        .iter()
        .filter(|layer| layer.discover().is_empty())
        .nth(1)
        .is_some()
}

/// True iff `dict` has *some* value along `path` — the layer holds an
/// opinion about the leaf at `path`. Zero allocation, `O(path.len())`.
///
/// The four semantically distinct cases collapse to a single boolean:
///
/// - A key or value exists at exactly `path` (leaf or dict container)
///   → `true`.
/// - A scalar/array sits at a *proper prefix* of `path`, so the
///   wholesale-replace semantic erases every deeper leaf including
///   the one at `path` — the layer is nonetheless the *decider* of
///   that erasure → `true`.
/// - No key at any prefix → `false`.
/// - Empty `path` (root): `true` iff `dict` is non-empty; the root
///   dict is the container every non-empty layer opens, and every
///   contributor-at-root aligns with the [`contributor_names`]
///   predicate on the whole-layer axis.
fn touches_path(dict: &Dict, path: &[&str]) -> bool {
    let Some((head, tail)) = path.split_first() else {
        return !dict.is_empty();
    };
    let Some(value) = dict.get(*head) else {
        return false;
    };
    if tail.is_empty() {
        return true;
    }
    match value {
        Value::Dict(_, inner) => touches_path(inner, tail),
        _ => true,
    }
}

/// The names of layers whose [`DiscoveryLayer::discover`] dict has any
/// opinion at `path` — placed a leaf here, opened a dict container
/// here, or wholesale-replaced a subtree containing `path` — in
/// application order (coarse→specific).
///
/// The **per-path** dual of [`contributor_names`]: that primitive
/// filters layers by `!discover().is_empty()` — "which axes had *any*
/// opinion?" — this one filters by `touches_path(discover(), path)` —
/// "which axes had opinions about *this* leaf?" A layer that answers
/// non-empty in general but has no key on the walk down `path` is a
/// contributor-in-general but not a contributor-at-`path`; it's
/// filtered out here while [`contributor_names`] would keep it.
///
/// The **pre-merge** dual of [`LayerAttribution::layer_of`]: that
/// primitive names the single **winner** at `path` in the composed
/// dict; this one names every layer that had *tried* to shape `path`,
/// winners and losers alike. Application order is preserved, so the
/// last element (when non-empty) is the most specific layer with an
/// opinion — and, when the effective outcome at `path` is a leaf, it
/// equals
/// [`compose_with_provenance`]`(layers).attribution.layer_of(path)`
/// verbatim.
///
/// # Semantics
///
/// A layer *touches* `path` when its `discover()` dict:
///
/// - places a leaf at exactly `path` (scalar or array),
/// - opens a dict container at `path` (its inner leaves live one
///   level deeper, but this layer's opinion at `path` is "there is
///   structure here"),
/// - or covers `path` with a scalar/array at a proper prefix of
///   `path` (wholesale-replace — the layer decided that no leaf
///   exists at `path`).
///
/// Layers with no key at any prefix of `path` are filtered out.
/// Empty `path` (the root) collapses to the [`contributor_names`]
/// filter itself: every layer with any content is a contributor.
///
/// # Subset chains
///
/// For every layer stack and every path `p`:
///
/// - `contributors_at(layers, p) ⊆ contributor_names(layers)` — a
///   contributor at some leaf must be a contributor in general.
/// - When [`compose_with_provenance`]`(layers).attribution
///   .layer_of(p)` is `Some(w)`, then `w` is the last element of
///   `contributors_at(layers, p)` — the effective writer is always
///   the most-specific-with-an-opinion.
/// - `contributors_at(layers, &[]) == contributor_names(layers)` on
///   the same layer stack.
///
/// # Cost
///
/// Calls `discover()` once per layer and walks each dict along `path`
/// once — `O(layers × path.len())` time, `O(contributors_at.len())`
/// allocation on the returned `Vec`. For per-leaf provenance over
/// *many* paths, prefer [`compose_with_provenance`] to materialize
/// the attribution once and query [`LayerAttribution::layer_of`] /
/// [`LayerAttribution::writes_by_layer`] on it; this primitive is
/// the diagnostic seam that answers the *pre-merge* question the
/// materialized attribution can't reach — the losers, not just the
/// winner.
///
/// # HOCON analogue
///
/// The path-parameterized companion to Lightbend HOCON's
/// [`Config.entrySet()`] grouped by origin: HOCON's origin projection
/// answers "which sources touched *any* key?" at whole-config scale;
/// `contributors_at` restricts the same question to a single leaf
/// coordinate.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
#[must_use]
pub fn contributors_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Vec<&'static str> {
    layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .map(|layer| layer.name())
        .collect()
}

/// The names of layers whose [`DiscoveryLayer::discover`] dict had an
/// opinion at `path` but were **overridden** by a later layer whose
/// `discover()` dict also had an opinion at `path` — the losers of the
/// per-path override contest, in application order (coarse→specific).
///
/// The point-restricted dual of the "losing-layer" projection on the
/// (path, layer) axis: [`contributors_at`] names every layer that
/// *tried* to shape `path` — winners and losers — and this primitive
/// drops the single trailing element (the most-specific-with-an-opinion,
/// i.e. the effective decider) to leave the losers alone.
///
/// The **pre-merge** dual of the surviving-layer axis at a point.
/// [`LayerAttribution::layer_of`] names the winner at a *surviving*
/// leaf; this primitive names everyone who *lost* the contest for the
/// same path, including the case where the "winner" wholesale-erased
/// the subtree (the erasure decider is dropped from the returned list;
/// every earlier toucher is credited as silenced).
///
/// # Semantics
///
/// For a path with `k` touchers ordered coarse→specific, the returned
/// list is the first `k − 1` names — every layer whose opinion at
/// `path` was superseded by a later toucher on the same path. When
/// `k ∈ {0, 1}` (nobody touched, or only one toucher = no override
/// contest), the returned list is empty.
///
/// Application order is preserved: the returned names appear
/// coarse→specific, matching [`contributors_at`] and
/// [`contributor_names`] on the same axis. Erasure via
/// wholesale-replace at a proper prefix counts as touching, so a coarse
/// layer that placed a leaf at `path` is credited as silenced when a
/// later layer's prefix-scalar erases the whole subtree — the erasure
/// decider is the (dropped) last element.
///
/// # Partition law
///
/// For every layer stack and every path `p`, the disjoint union
///
/// ```text
/// silenced_at(layers, p) ⊎ {last of contributors_at(layers, p)}
///     == contributors_at(layers, p)
/// ```
///
/// holds as an ordered-vector equality (with the singleton empty when
/// no layer touches `p`). The `⊆` chain
/// `silenced_at ⊆ contributors_at ⊆ contributor_names` extends the
/// [`contributors_at`] subset chain to a three-tier one, and
/// `silenced_at.len() == contributors_at.len().saturating_sub(1)`
/// tracks it on the scalar axis.
///
/// When [`compose_with_provenance`]`(layers).attribution.layer_of(p)`
/// is `Some(w)`, `w` equals the (dropped) last element of
/// [`contributors_at`] and therefore does *not* appear in
/// `silenced_at(layers, p)`. When `layer_of(p)` is `None` (the path
/// resolves to a dict container or is erased by a prefix-scalar),
/// `silenced_at` is still well-defined: it credits every non-effective
/// toucher and drops the decider.
///
/// # Cost
///
/// Calls `discover()` once per layer and walks each dict along `path`
/// once — `O(layers × path.len())` time, `O(silenced_at.len())`
/// allocation on the returned `Vec`. The pop step is amortized `O(1)`;
/// total allocation matches [`contributors_at`] minus one slot.
///
/// # HOCON analogue
///
/// The path-parameterized dual of Lightbend HOCON's "which sources
/// were shadowed by later sources at this key?" question: HOCON's
/// `Config.entrySet()` grouped by [`ConfigOrigin`] surfaces winners
/// wholesale; the *losers* are recovered by set-differencing pre-merge
/// origins against post-merge origins. `silenced_at` is the point,
/// pre-merge primitive that answers the same question at a single leaf
/// coordinate — with the disjoint-union invariant against
/// [`contributors_at`] pinning the algebra shut.
///
/// [`ConfigOrigin`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/ConfigOrigin.html
#[must_use]
pub fn silenced_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .map(|layer| layer.name())
        .collect();
    names.pop();
    names
}

/// The name of the layer that *decides* `path` — the most-specific
/// (last-applied) layer whose [`DiscoveryLayer::discover`] dict has an
/// opinion at `path`. `None` when no layer touches `path`.
///
/// The point-restricted **decider projection** on the (path, layer)
/// axis: [`contributors_at`] names every layer that *tried* to shape
/// `path` — winners and losers — and this primitive picks the single
/// trailing element (the effective decider). Combined with
/// [`silenced_at`] (the losers projection), it closes the per-path
/// override contest under the disjoint-union partition
/// `silenced_at ⊎ decider_at == contributors_at`.
///
/// The **pre-merge** dual of [`LayerAttribution::layer_of`]. That
/// primitive names the writer at a *surviving* leaf; this primitive
/// names the decider even when the effective outcome at `path` is *no
/// leaf* — erasure by a prefix-scalar, a dict container at `path`, or
/// a path that runs below the leaves the composed dict actually
/// contains. On surviving leaves the two agree; on non-leaf paths,
/// `layer_of` is `None` while `decider_at` still names the responsible
/// layer.
///
/// The **whole-layer→point-path** specialization of
/// [`contributor_names`] at the empty path:
/// `decider_at(layers, &[]) == contributor_names(layers).last().copied()`
/// — the most-specific non-empty layer decides the root.
///
/// # Semantics
///
/// A layer *decides* `path` when its `discover()` dict:
///
/// - places a leaf at exactly `path` (scalar or array),
/// - opens a dict container at `path` (its inner leaves live one level
///   deeper, but this layer's opinion at `path` is "there is structure
///   here"),
/// - or covers `path` with a scalar/array at a proper prefix of `path`
///   (wholesale-replace — the layer decided that no leaf exists at
///   `path`),
///
/// and no later-applied layer touches `path`. Ties don't exist — the
/// last-in-application-order toucher is always the decider.
///
/// # Partition law
///
/// For every layer stack and every path `p`:
///
/// ```text
/// silenced_at(layers, p) ⊎ decider_at(layers, p).into_iter().collect()
///     == contributors_at(layers, p)
/// ```
///
/// holds as an ordered-vector equality (with the singleton empty when
/// no layer touches `p`). Equivalently,
/// `contributors_at(layers, p).last().copied() == decider_at(layers, p)`.
/// When [`compose_with_provenance`]`(layers).attribution.layer_of(p)`
/// is `Some(w)`, `decider_at(layers, p)` is also `Some(w)`; when
/// `layer_of(p)` is `None`, `decider_at(layers, p)` is `None` iff no
/// layer touches `p`, and `Some(erasure_agent)` when a prefix-scalar
/// erases the subtree or `p` resolves to a dict container.
///
/// # Cost
///
/// Walks layers in **reverse** and short-circuits on the first hit —
/// worst-case `O(layers × path.len())` (nobody touched, or the coarsest
/// is the sole toucher), best-case `O(path.len())` (the most-specific
/// layer touches). Zero allocation on the walker itself. Cheaper than
/// [`contributors_at`] plus a `.last().copied()` for the point-decider
/// query workload, which always walks every layer regardless.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to Lightbend HOCON's
/// [`Config.getValue(path).origin()`]: HOCON's post-merge origin
/// projection reports the winner at surviving leaves but is silent when
/// the value has been resolved away (a nested key covered by a parent
/// scalar assignment has no `ConfigValue` node to hang an origin off
/// of). `decider_at` covers both cases uniformly by projecting the
/// last pre-merge toucher, and short-circuits at the first (deepest)
/// hit — a property HOCON's per-key origin walk doesn't offer.
///
/// [`Config.getValue(path).origin()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#getValue-java.lang.String-
#[must_use]
pub fn decider_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Option<&'static str> {
    layers
        .iter()
        .rev()
        .find(|layer| touches_path(&layer.discover(), path))
        .map(|layer| layer.name())
}

/// The name of the layer that *opened* `path` — the least-specific
/// (first-applied) layer whose [`DiscoveryLayer::discover`] dict has an
/// opinion at `path`. `None` when no layer touches `path`.
///
/// The point-restricted **coarsest projection** on the (path, layer)
/// axis: [`contributors_at`] names every layer that *tried* to shape
/// `path` — winners and losers — and this primitive picks the single
/// *leading* element (the effective opener). The **leading-element
/// dual** of [`decider_at`]'s trailing-element projection on the same
/// axis.
///
/// The **coarsest / trailing** pair `(coarsest_at, decider_at)` frames
/// the override cascade for diagnostic renderers at the point level —
/// "`platform` opened this key, `tenancy` decided its final value"
/// reads directly off `(coarsest_at(layers, p), decider_at(layers, p))`
/// without materializing [`contributors_at`], allocating a `Vec`, or
/// pattern-matching through a [`PathContest`] wrapper. Symmetric,
/// short-circuiting counterparts on the two ends of the ordered
/// touchers vector.
///
/// The **point-primitive dual** of [`PathContest::coarsest`]: that
/// method is the leading projection off a materialized fused pair;
/// this function is the identical projection computed **without
/// materializing the pair** — one forward-walking short-circuit vs
/// one forward walk that collects every toucher and then reads the
/// first. When the caller only wants the leading name and does not
/// need the losers list, this primitive is strictly cheaper.
///
/// The **whole-layer→point-path** specialization of
/// [`contributor_names`] at the empty path:
/// `coarsest_at(layers, &[]) == contributor_names(layers).first().copied()`
/// — the least-specific non-empty layer opens the root.
///
/// # Semantics
///
/// A layer *opens* `path` when it is the first-in-application-order
/// layer whose `discover()` dict:
///
/// - places a leaf at exactly `path` (scalar or array),
/// - opens a dict container at `path` (its inner leaves live one level
///   deeper, but this layer's opinion at `path` is "there is structure
///   here"),
/// - or covers `path` with a scalar/array at a proper prefix of `path`
///   (wholesale-replace — this layer decided the shape of `path`).
///
/// Later-applied layers that also touch `path` do not affect the
/// answer — the *opener* is fixed by the ordered layer stack and is
/// the coarsest name in [`contributors_at`], irrespective of who
/// ultimately decided.
///
/// # Identities
///
/// The leading-element identity against [`contributors_at`]:
///
/// ```text
/// coarsest_at(layers, p) == contributors_at(layers, p).first().copied()
/// ```
///
/// pins the projection to the ordered coarse→specific writers axis at
/// the leading endpoint. The [`None`] boundary lines up:
///
/// ```text
/// coarsest_at(layers, p).is_none()
///     == contributors_at(layers, p).is_empty()
///     == decider_at(layers, p).is_none()
///     == contest_at(layers, p).is_none()
/// ```
///
/// The fused-value identity against [`PathContest::coarsest`]:
///
/// ```text
/// coarsest_at(layers, p) == contest_at(layers, p).map(|c| c.coarsest())
/// ```
///
/// which extends across the [`None`] boundary by both sides mapping to
/// [`None`] on no-toucher paths.
///
/// The pairing identity with [`decider_at`]:
///
/// ```text
/// coarsest_at(layers, p) == decider_at(layers, p)
///     <=>  contributors_at(layers, p).len() <= 1
/// ```
///
/// — coarsest and decider coincide **iff** the touchers list has at
/// most one element (nobody touched, or exactly one toucher = the
/// uncontested-singleton degenerate). When two or more layers touch,
/// coarsest and decider are structurally distinct (coarsest is
/// `contributors_at.first()`, decider is `contributors_at.last()`,
/// and the two indices differ).
///
/// # Cost
///
/// Walks layers **forward** and short-circuits on the first hit —
/// worst-case `O(layers × path.len())` (nobody touched, or the
/// most-specific is the sole toucher), best-case `O(path.len())` (the
/// coarsest layer touches). Zero allocation on the walker itself.
/// Symmetric to [`decider_at`]'s reverse short-circuit; strictly
/// cheaper than [`contributors_at`] plus a `.first().copied()` for the
/// point-opener query workload, which always walks every layer
/// regardless of where the coarsest hit lives.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to Lightbend HOCON's "which source
/// first introduced this key?" question: HOCON exposes per-source
/// [`Config.entrySet()`] with a [`ConfigOrigin`] per value, but the
/// *opener* at a specific path — the first source in application
/// order that touched the key — is recovered only by iterating each
/// source's `entrySet()` in order and picking the first toucher per
/// key. `coarsest_at` packages the same query as one substrate-owned
/// primitive with a short-circuiting forward walk. Figment 0.10's
/// per-value [`Tag`] names the surviving-leaf's origin (the trailing
/// / most-specific opinion) but exposes no companion for the coarsest
/// opinion; `coarsest_at` closes that missing leading-endpoint seam.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`ConfigOrigin`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/ConfigOrigin.html
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn coarsest_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Option<&'static str> {
    layers
        .iter()
        .find(|layer| touches_path(&layer.discover(), path))
        .map(|layer| layer.name())
}

/// The name of the layer that would have decided `path` **if the actual
/// decider hadn't touched it** — the second-to-last (most-specific-among-
/// silenced) layer whose [`DiscoveryLayer::discover`] dict has an opinion
/// at `path`. `None` when fewer than two layers touch `path`.
///
/// The point-restricted **runner-up projection** on the (path, layer)
/// axis: [`contributors_at`] names every layer that *tried* to shape
/// `path` (winners and losers, coarse→specific), and this primitive
/// picks the single element **one step back from the trailing decider** —
/// equivalently, the trailing element of [`silenced_at`].
///
/// The **one-step-back sibling of [`decider_at`]** on the touchers axis.
/// Together with the two endpoints, the triple
/// `(coarsest_at, runner_up_at, decider_at)` frames the three ordered
/// specificity positions callers actually name when rendering the
/// override cascade at a point — "the coarsest layer that opened this
/// key" / "the closest challenger the decider silenced" / "the layer
/// that decided its final value". `runner_up_at` answers the
/// diagnostic question "what would this key have been if the decider
/// hadn't touched it?" — the "*next-in-line*" name behind the winner.
///
/// The **point-primitive dual** of [`PathContest::runner_up`]: that
/// method is the trailing projection off a materialized fused pair
/// in `O(1)`; this function is the identical projection computed
/// **without materializing the pair** — one reverse-walking
/// short-circuit at the second hit vs one forward walk that collects
/// every toucher, pops the trailing decider, and reads the trailing
/// element of the remaining losers `Vec`. When the caller only wants
/// the runner-up name and does not need the ordered losers list, the
/// decider, or the fused [`PathContest`], this primitive is strictly
/// cheaper.
///
/// # Semantics
///
/// A layer is the *runner-up* at `path` when it is the
/// second-in-reverse-application-order layer whose `discover()` dict:
///
/// - places a leaf at exactly `path` (scalar or array),
/// - opens a dict container at `path` (its inner leaves live one level
///   deeper, but this layer's opinion at `path` is "there is structure
///   here"),
/// - or covers `path` with a scalar/array at a proper prefix of `path`
///   (wholesale-replace).
///
/// Zero touchers (nobody opened this key) and one toucher (uncontested
/// singleton path — the sole toucher *is* the decider, so there is
/// nothing one step back from it) collapse under the same [`None`]
/// return. Two or more touchers give a [`Some`] with the
/// second-to-last name in application order.
///
/// # Identities
///
/// The trailing-of-losers identity against [`silenced_at`] on the
/// loose axis:
///
/// ```text
/// runner_up_at(layers, p) == silenced_at(layers, p).last().copied()
/// ```
///
/// The one-step-back identity against [`contributors_at`]:
///
/// ```text
/// runner_up_at(layers, p) == contributors_at(layers, p).iter().nth_back(1).copied()
/// ```
///
/// The fused-value identity across the [`None`] boundary:
///
/// ```text
/// runner_up_at(layers, p) == contest_at(layers, p).and_then(|c| c.runner_up())
/// ```
///
/// — the free-fn is exactly the trailing-loser projection off
/// [`PathContest::runner_up`], and both sides map to [`None`] on the
/// zero-or-one-toucher no-contest boundary.
///
/// The presence-boundary identity against [`is_contested_at`]:
///
/// ```text
/// runner_up_at(layers, p).is_some() == is_contested_at(layers, p)
/// runner_up_at(layers, p).is_none() == !is_contested_at(layers, p)
/// ```
///
/// The pairing identity with [`coarsest_at`] on the shared touchers
/// axis:
///
/// ```text
/// silenced_count_at(layers, p) == 1  =>  runner_up_at(layers, p) == coarsest_at(layers, p)
/// silenced_count_at(layers, p) >= 2  =>  runner_up_at(layers, p) != coarsest_at(layers, p)
/// ```
///
/// — singly contested paths alias the runner-up onto the coarsest
/// (the sole silenced layer occupies both endpoints of the losers
/// list); multiply silenced paths place them at structurally distinct
/// positions on the ordered touchers vector.
///
/// The [`None`] boundary aligns with the "no runner-up" cell of the
/// broader lattice — [`is_contested_at`]`(layers, p) == false`
/// straddles zero-toucher and one-toucher paths, and this primitive
/// collapses the same two cells under the same [`None`] return.
///
/// The strict-decider non-alias invariant on the [`Some`] branch:
///
/// ```text
/// runner_up_at(layers, p) == Some(name)  =>  Some(name) != decider_at(layers, p)
/// ```
///
/// — the runner-up is drawn from the silenced list, structurally
/// distinct from the decider under the [`DiscoveryLayer::name`]
/// `&'static str` distinctness contract on the substrate-owned layer
/// stack.
///
/// # Cost
///
/// Walks layers in **reverse** with a **short-circuit on the second
/// hit** — worst-case `O(layers × path.len())` (fewer than two
/// touchers, so [`Iterator::nth`] runs the full reverse walk),
/// best-case `O(2 × path.len())` (the two most-specific layers
/// touch and the walker halts at the second reverse hit). Zero
/// allocation on the walker itself. Strictly cheaper than every
/// alternative on the same axis:
///
/// - [`silenced_at`]`(layers, p).last().copied()` walks every layer
///   forward, allocates the losers [`Vec<&'static str>`], then reads
///   the trailing element — no short-circuit on the second reverse
///   hit.
/// - [`contributors_at`]`(layers, p).iter().nth_back(1).copied()`
///   walks every layer forward, allocates the touchers
///   [`Vec<&'static str>`], then reads the second-to-last element.
/// - [`contest_at`]`(layers, p).and_then(|c| c.runner_up())` walks
///   every layer, allocates the [`PathContest`]'s `overridden`
///   [`Vec`], then reads a single trailing name off the fused
///   struct.
///
/// This primitive short-circuits at the second reverse hit *and*
/// returns the name directly without projecting through a materialized
/// [`Vec`] or fused pair — the [`Iterator::nth`] adapter on the
/// reversed touchers filter compiles to a single-branch reverse walk
/// over the same predicate [`decider_at`] runs, only stopped at the
/// second reverse hit rather than the first. Symmetric in
/// short-circuit semantics to [`decider_at`] (first reverse hit) at
/// the trailing endpoint; the two together give the substrate a
/// pair of tightly-scoped reverse-walking primitives at the two
/// specificity positions consumers actually name.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "what would this key have been
/// if the winning source hadn't set it?" — Lightbend HOCON's
/// [`Config.getValue(path).origin()`] exposes only the surviving-leaf's
/// origin; the *runner-up origin* (the source one step back from the
/// decider on the specificity axis) is unreachable without a per-source
/// [`Config.entrySet()`] re-walk, filtering to sources that touched
/// the key, and picking the second-to-last in application order.
/// `runner_up_at` packages the one-step-back projection as a single
/// substrate-owned primitive with a short-circuiting reverse walk.
/// Figment 0.10's per-value [`Tag`] names the surviving-leaf's origin
/// (the trailing / most-specific opinion) but exposes no companion
/// for the next-in-line origin; `runner_up_at` closes that missing
/// runner-up-endpoint seam on the same axis [`coarsest_at`] closes
/// the coarsest-endpoint seam.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`Config.getValue(path).origin()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#getValue-java.lang.String-
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn runner_up_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Option<&'static str> {
    layers
        .iter()
        .rev()
        .filter(|layer| touches_path(&layer.discover(), path))
        .nth(1)
        .map(|layer| layer.name())
}

/// The name of the layer that **opened the override cascade at `path`** —
/// the first-in-application-order (coarse-most) layer whose
/// [`DiscoveryLayer::discover`] dict has an opinion at `path`, *restricted
/// to the silenced list*. `None` when fewer than two layers touch `path`.
///
/// The point-restricted **coarsest-silenced projection** on the
/// (path, layer) axis: [`silenced_at`] names every layer whose opinion at
/// `path` was overridden by the decider (losers, coarse→specific), and
/// this primitive picks the single element **at the leading end of that
/// losers list** — equivalently, the leading element of [`contributors_at`]
/// on the contested branch (where the coarsest overall toucher is always
/// a loser).
///
/// The **leading-of-silenced sibling of [`runner_up_at`]** on the losers
/// axis. Together, the pair
/// `(coarsest_silenced_at, runner_up_at)` frames the two ordered
/// endpoints on the silenced list — "the coarsest layer the decider
/// silenced" and "the closest challenger the decider silenced" — at
/// exact structural symmetry with `(coarsest_at, decider_at)` on the
/// contributors list. `coarsest_silenced_at` answers the diagnostic
/// question "which layer *first* placed an opinion here that the decider
/// overrode?" — the opener of the override cascade.
///
/// The **point-primitive dual** of [`PathContest::coarsest_silenced`]:
/// that method is the leading projection off a materialized fused pair
/// in `O(1)`; this function is the identical projection computed
/// **without materializing the pair** — one forward walk that
/// short-circuits at the second hit rather than collecting every
/// toucher into an `overridden` [`Vec`] and popping the trailing
/// decider. When the caller only wants the coarsest silenced name and
/// does not need the ordered losers list, the decider, or the fused
/// [`PathContest`], this primitive is strictly cheaper.
///
/// # Semantics
///
/// A layer is the *coarsest silenced* at `path` when it is the
/// first-in-application-order layer whose `discover()` dict touches
/// `path` **and** at least one strictly-more-specific layer also
/// touches `path` (the decider). Zero touchers (nobody opened this key)
/// and one toucher (uncontested singleton path — the sole toucher *is*
/// the decider, so there is nothing on the losers list to open) collapse
/// under the same [`None`] return. Two or more touchers give a [`Some`]
/// with the first name in application order.
///
/// # Identities
///
/// The leading-of-losers identity against [`silenced_at`]:
///
/// ```text
/// coarsest_silenced_at(layers, p) == silenced_at(layers, p).first().copied()
/// ```
///
/// The fused-value identity across the [`None`] boundary:
///
/// ```text
/// coarsest_silenced_at(layers, p)
///     == contest_at(layers, p).and_then(|c| c.coarsest_silenced())
/// ```
///
/// The presence-boundary identity against [`is_contested_at`]:
///
/// ```text
/// coarsest_silenced_at(layers, p).is_some() == is_contested_at(layers, p)
/// coarsest_silenced_at(layers, p).is_none() == !is_contested_at(layers, p)
/// ```
///
/// The pairing identities with [`coarsest_at`] and [`runner_up_at`] on
/// the shared touchers axis:
///
/// ```text
/// is_contested_at(layers, p)         =>  coarsest_silenced_at(layers, p) == coarsest_at(layers, p)
/// !is_contested_at(layers, p)        =>  coarsest_silenced_at(layers, p) == None
///                                       && coarsest_at(layers, p) == decider_at(layers, p)
/// silenced_count_at(layers, p) == 1  =>  coarsest_silenced_at(layers, p) == runner_up_at(layers, p)
/// silenced_count_at(layers, p) >= 2  =>  coarsest_silenced_at(layers, p) != runner_up_at(layers, p)
/// ```
///
/// — the contested branch aliases the coarsest silenced onto the
/// coarsest overall (the sole toucher on the *decider*-only branch
/// evaporates from the losers axis); the singly-contested cell aliases
/// the two silenced endpoints (leading and trailing coincide); the
/// multiply-silenced branch places them at structurally distinct
/// positions on the ordered losers vector.
///
/// The strict-decider non-alias invariant on the [`Some`] branch:
///
/// ```text
/// coarsest_silenced_at(layers, p) == Some(name)
///     =>  Some(name) != decider_at(layers, p)
/// ```
///
/// — the coarsest silenced is drawn from the losers list, structurally
/// distinct from the decider under the [`DiscoveryLayer::name`]
/// `&'static str` distinctness contract on the substrate-owned layer
/// stack.
///
/// # Cost
///
/// Walks layers **forward** with a **short-circuit on the second hit** —
/// worst-case `O(layers × path.len())` (fewer than two touchers, so the
/// walker runs the full forward walk), best-case `O(2 × path.len())`
/// (the first two layers touch and the walker halts at the second hit).
/// Zero allocation on the walker itself. Strictly cheaper than every
/// alternative on the same axis:
///
/// - [`silenced_at`]`(layers, p).first().copied()` walks every layer
///   forward, allocates the losers [`Vec<&'static str>`], then reads
///   the leading element — no short-circuit at the second hit.
/// - [`contest_at`]`(layers, p).and_then(|c| c.coarsest_silenced())`
///   walks every layer forward, allocates the [`PathContest`]'s
///   `overridden` [`Vec`], then reads a single leading name off the
///   fused struct.
///
/// Symmetric in short-circuit semantics to [`is_contested_at`] (both
/// halt at the second forward hit), and structurally the leading-end
/// mirror of [`runner_up_at`] (which halts at the second *reverse* hit
/// on the same touchers stack).
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "which source *first* opened this
/// key that the winning source later overrode?" — Lightbend HOCON's
/// [`Config.getValue(path).origin()`] exposes only the surviving-leaf's
/// origin; the *opener origin* (the source at the leading end of the
/// specificity axis whose value was overridden) is unreachable without
/// a per-source [`Config.entrySet()`] re-walk, filtering to sources
/// that touched the key, and picking the first in application order
/// while confirming at least a second source also touched it.
/// `coarsest_silenced_at` packages the opener-projection as a single
/// substrate-owned primitive with a short-circuiting forward walk.
/// Figment 0.10's per-value [`Tag`] names the surviving-leaf's origin
/// (the trailing / most-specific opinion) but exposes no companion for
/// the opener origin at the leading end of the silenced list;
/// `coarsest_silenced_at` closes that missing opener-endpoint seam on
/// the losers axis, at exact structural symmetry with
/// [`runner_up_at`]'s closing of the runner-up-endpoint seam at the
/// trailing end.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`Config.getValue(path).origin()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#getValue-java.lang.String-
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn coarsest_silenced_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Option<&'static str> {
    let mut iter = layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path));
    let first = iter.next()?;
    // Require ≥ 2 touchers: with a sole toucher, the coarsest overall
    // IS the decider, and the losers list is empty — no coarsest
    // silenced name exists at that path.
    iter.next()?;
    Some(first.name())
}

/// `true` iff at least two layers touched `path` — the point-restricted
/// **contest predicate** on the (path, layer) axis.
///
/// The point-primitive dual of [`PathContest::is_contested`]: that method
/// reads a boolean off a materialized [`PathContest`] value in `O(1)`;
/// this function answers the same question **without materializing the
/// fused pair**, short-circuiting on the second toucher rather than
/// walking every layer and allocating the `overridden` [`Vec`] for a
/// scalar answer.
///
/// The four boolean projections on the point-primitive lattice collapse
/// onto one substrate-owned primitive with the same short-circuit
/// semantics as [`decider_at`] / [`coarsest_at`] on their scalar axes:
///
/// - `is_contested_at(layers, p) == !`[`silenced_at`]`(layers, p).is_empty()`
///   (losers-non-empty predicate on the loose axis)
/// - `is_contested_at(layers, p) == `[`contest_at`]`(layers, p).map_or(false,
///   |c| c.is_contested())` (fused-value method call)
/// - `is_contested_at(layers, p) == `[`contributors_at`]`(layers, p).len() >= 2`
///   (cardinality predicate on the ordered-touchers axis)
/// - `is_contested_at(layers, p) == (`[`coarsest_at`]`(layers, p) !=
///   `[`decider_at`]`(layers, p))` (endpoint-inequality predicate — holds
///   because both-`None` collapses to zero touchers and both-`Some(same)`
///   collapses to one toucher; two+ distinct-named touchers give distinct
///   leading/trailing endpoints under the [`DiscoveryLayer::name`]
///   `&'static str` distinctness contract).
///
/// All four routes are algebraically identical on their shared boolean
/// output; this primitive is the strictly-cheapest route when the caller
/// wants only the contest predicate and does not need the touchers list,
/// the decider name, or the losers list.
///
/// # Semantics
///
/// The set of touchers is exactly the [`contributors_at`] projection:
/// every layer whose `discover()` places a leaf at `path`, opens a dict
/// container at `path`, or covers `path` with a scalar/array at a proper
/// prefix (wholesale-replace). Two touchers is the true-boundary; zero
/// touchers (no layer opinions) and one toucher (uncontested singleton
/// path) are the false-boundary — the two are collapsed under the same
/// return value because both admit a single [`PathContest`]-shaped
/// answer with an empty `overridden` (or no [`PathContest`] at all).
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the second hit** —
/// worst-case `O(layers × path.len())` (nobody touched, or exactly one
/// layer touched at the very end of the stack), best-case
/// `O(path.len())` (the first two layers touch). Zero allocation on the
/// walker itself. Strictly cheaper than [`contributors_at`] plus a
/// `.len() >= 2` (which walks every layer and allocates the full
/// touchers `Vec`), [`silenced_at`] plus `.is_empty()` (same allocation,
/// plus a `pop` at the end), and [`contest_at`] plus `.is_contested()`
/// (walks every layer, allocates the `overridden` `Vec`, then reads a
/// single bit off the fused struct). Symmetric in short-circuit
/// semantics to [`decider_at`] / [`coarsest_at`] on the boolean axis.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to Lightbend HOCON's "is this key
/// shadowed across sources?" query: HOCON exposes per-source
/// [`Config.entrySet()`] with a [`ConfigOrigin`] per value, but the
/// *contested-at-path* predicate — "did more than one source touch this
/// key?" — is recovered only by iterating each source's `entrySet()`
/// and counting hits, or by set-differencing per-source origins against
/// the merged value's origin. `is_contested_at` packages the predicate
/// as one substrate-owned primitive with a short-circuiting forward
/// walk, and the two false-boundary cases (zero touchers, one toucher)
/// are collapsed under the same `false` return so the caller doesn't
/// have to disambiguate the two. Figment 0.10's per-value [`Tag`] names
/// the surviving-leaf's origin but exposes no predicate for the
/// "someone else was shadowed" question; `is_contested_at` closes that
/// missing predicate-endpoint seam.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`ConfigOrigin`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/ConfigOrigin.html
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn is_contested_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> bool {
    layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .nth(1)
        .is_some()
}

/// The **number of layers** whose [`DiscoveryLayer::discover`] dict has
/// an opinion at `path` — placed a leaf here, opened a dict container
/// here, or wholesale-replaced a subtree containing `path`. Zero when
/// no layer touches `path`; one for an uncontested singleton; two or
/// more for a contested path.
///
/// The **scalar-cardinality endpoint** of the point-primitive lattice
/// on the (path, layer) axis: [`contributors_at`] returns the ordered
/// list of touchers, [`is_contested_at`] returns the boolean predicate
/// "two or more of them," and this primitive returns their cardinality
/// directly — the length-fold of [`contributors_at`] and the counting
/// dual of [`is_contested_at`] on the same walk.
///
/// # Identities
///
/// The four scalar-cardinality projections on the lattice collapse onto
/// one substrate-owned primitive with a **zero-allocation** walk:
///
/// - `contributor_count_at(layers, p) == `[`contributors_at`]`(layers, p).len()`
///   (length-fold on the ordered-touchers axis)
/// - `contributor_count_at(layers, p) == `[`contest_at`]`(layers, p).map_or(0,
///   |c| c.contributor_count())` (folded-value method call)
/// - `contributor_count_at(layers, p) == `[`silenced_at`]`(layers, p).len() +
///   usize::from(`[`decider_at`]`(layers, p).is_some())` (partition-count
///   identity: losers plus decider-count)
/// - `contributor_count_at(layers, p) >= 2 == `[`is_contested_at`]`(layers, p)`
///   (cardinality-threshold identity — the boolean dual reads off the
///   scalar with a `>= 2` comparison, and every four zero-boundary
///   endpoints ([`contest_at`], [`decider_at`], [`coarsest_at`],
///   [`contributors_at`]) pin their `.is_none()` / `.is_empty()` boundary
///   to `contributor_count_at == 0` in agreement)
///
/// All four routes are algebraically identical on their shared scalar
/// output; this primitive is the strictly-cheapest route when the caller
/// wants only the count and does not need the ordered touchers list, the
/// decider name, the losers list, or the fused [`PathContest`].
///
/// # Semantics
///
/// The set of touchers is exactly the [`contributors_at`] projection:
/// every layer whose `discover()` places a leaf at `path`, opens a dict
/// container at `path`, or covers `path` with a scalar/array at a proper
/// prefix (wholesale-replace). Silent layers between contributors are
/// filtered (same walk as [`contributors_at`] / [`is_contested_at`]).
///
/// # Cost
///
/// Walks layers forward with `Iterator::count` — worst-case
/// `O(layers × path.len())`, **zero allocation** on the walker itself.
/// Strictly cheaper than every alternative on the same axis:
///
/// - [`contributors_at`]`(layers, p).len()` walks every layer and
///   allocates the full `Vec<&'static str>` of touchers, then reads its
///   length off the fat pointer.
/// - [`silenced_at`]`(layers, p).len() + usize::from(`[`decider_at`]
///   `(layers, p).is_some())` walks every layer twice (once forward
///   allocating the losers `Vec`, once in reverse for the decider) and
///   still allocates the losers list only to fold it to a length.
/// - [`contest_at`]`(layers, p).map_or(0, |c| c.contributor_count())`
///   walks every layer once, allocates the [`PathContest`]'s `overridden`
///   `Vec`, then reads a `.len() + 1` off the fused struct.
///
/// This primitive short-circuits nothing (the whole layer stack must
/// be walked to know the total) but allocates nothing either — the
/// [`Iterator::count`] adapter compiles to a bump-a-`usize` walk.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to the "how many sources touched
/// this key?" query that Lightbend HOCON callers reconstruct by
/// iterating each source's [`Config.entrySet()`] and counting hits at
/// the given key. `contributor_count_at` packages that count as one
/// substrate-owned primitive over the same pre-merge touchers set,
/// with the boundary invariant `count == 0 ⇔ nobody touched` pinned
/// against every neighboring None-endpoint on the lattice.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
#[must_use]
pub fn contributor_count_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> usize {
    layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .count()
}

/// The **number of layers** whose opinion at `path` was overridden by
/// the effective decider — the count of losers in the per-path
/// override contest, exclusive of the winner. Zero when no layer
/// touches `path` (no toucher, no contest) or when the sole toucher
/// is the uncontested decider (single toucher, no losers); one or
/// more for a contested path.
///
/// The **scalar-cardinality endpoint** of the losers axis at the
/// point altitude: [`silenced_at`] returns the ordered list of
/// overridden touchers, [`is_contested_at`] returns the boolean
/// predicate "one or more of them," and this primitive returns their
/// cardinality directly — the length-fold of [`silenced_at`] on the
/// same touchers walk, and the losers-side scalar dual of
/// [`contributor_count_at`] on the shared `overridden ⊎ {decider}`
/// partition.
///
/// # Identities
///
/// The four losers-cardinality projections on the lattice collapse
/// onto one substrate-owned primitive with a **zero-allocation** walk:
///
/// - `silenced_count_at(layers, p) == `[`silenced_at`]`(layers, p).len()`
///   (length-fold on the ordered-losers axis — the zero-allocation
///   dual of the ordered-list projection)
/// - `silenced_count_at(layers, p) + usize::from(`[`is_touched_at`]`(layers, p))
///   == `[`contributor_count_at`]`(layers, p)` (**partition-count**
///   identity: the ordered partition `overridden ⊎ {decider}` when a
///   decider exists, `∅ ⊎ ∅` otherwise; pinned in pure-scalar
///   arithmetic on both sides against the presence bit — the no-toucher
///   branch collapses both addends to zero, the uncontested-singleton
///   branch collapses the losers addend to zero and the presence
///   addend to one)
/// - `silenced_count_at(layers, p) == `[`contributor_count_at`]`(layers, p)
///   .saturating_sub(1)` (**complement** identity: the losers count is
///   the total touchers minus the trailing decider; the saturating
///   arithmetic covers the no-toucher branch cleanly, since the
///   naive `- 1` would underflow on `usize`)
/// - `silenced_count_at(layers, p) >= 1 == `[`is_contested_at`]`(layers, p)`
///   (cardinality-threshold identity: the boolean dual reads off the
///   scalar with a `>= 1` comparison — the same "≥ 1 loser" endpoint
///   that [`is_contested_at`] pins as a bare `bool`)
/// - `silenced_count_at(layers, p) == 0 == !`[`is_contested_at`]`(layers, p)`
///   (zero-boundary identity: no losers ⇔ no override contest,
///   collapsing both the no-toucher and the uncontested-singleton
///   cases onto the same arithmetic zero)
/// - `silenced_count_at(layers, p) == `[`contest_at`]`(layers, p)
///   .map_or(0, |c| c.silenced_count())` (folded-value method call:
///   the `None` branch on the fused side maps to zero in agreement
///   with the no-toucher zero branch on the primitive side)
///
/// All six routes are algebraically identical on their shared scalar
/// output; this primitive is the strictly-cheapest route when the
/// caller wants only the losers count and does not need the ordered
/// losers list, the decider name, the coarsest name, the total
/// touchers count, or the fused [`PathContest`].
///
/// # Semantics
///
/// The set of losers is the leading prefix of the [`contributors_at`]
/// projection with the trailing decider popped: every layer whose
/// `discover()` touched `path` and whose opinion was subsequently
/// overridden by a more-specific toucher. On the empty-path root the
/// walk collapses to the [`silent_layer_names`]-adjacent "every
/// non-empty layer touches the root" filter minus the trailing
/// non-empty layer (the whole-config decider). Silent layers between
/// contributors are filtered on the touchers walk, matching every
/// other point primitive on the (path, layer) axis.
///
/// # Cost
///
/// Walks layers forward with [`Iterator::count`] and one
/// [`usize::saturating_sub`] — worst-case `O(layers × path.len())`,
/// **zero allocation** on the walker itself. Strictly cheaper than
/// every alternative on the same axis:
///
/// - [`silenced_at`]`(layers, p).len()` walks every layer, allocates
///   the full losers `Vec<&'static str>`, then reads its length off
///   the fat pointer.
/// - [`contest_at`]`(layers, p).map_or(0, |c| c.silenced_count())`
///   walks every layer once and allocates the fused [`PathContest`]'s
///   `overridden` `Vec` only to fold it to a `.len()`.
/// - [`contributor_count_at`]`(layers, p).saturating_sub(1)` performs
///   the same walk as this primitive and the same saturating
///   subtraction, but reads through a second function-call boundary.
///
/// This primitive short-circuits nothing (the whole layer stack must
/// be walked to know the total) but allocates nothing either — the
/// [`Iterator::count`] adapter compiles to a bump-a-`usize` walk over
/// the same touchers filter that [`contributor_count_at`] folds.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "how many sources at this key
/// were overridden?" — Lightbend HOCON callers reconstruct this by
/// iterating each source's [`Config.entrySet()`] at the key, counting
/// hits, and subtracting one (or zero if nobody touched).
/// `silenced_count_at` packages that count as one substrate-owned
/// primitive with the losers-axis boundary invariant
/// `silenced_count_at + usize::from(is_touched_at) == contributor_count_at`
/// pinned in pure-scalar arithmetic against every neighboring
/// endpoint on the point-primitive lattice.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
#[must_use]
pub fn silenced_count_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> usize {
    layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .count()
        .saturating_sub(1)
}

/// True iff **at least one layer** touches `path` — placed a leaf here,
/// opened a dict container here, or wholesale-replaced a subtree
/// containing `path`. False iff no layer has an opinion at `path`.
///
/// The **"≥ 1" endpoint** of the cardinality-threshold predicate lattice
/// on the (path, layer) axis: [`is_contested_at`] returns the "≥ 2"
/// threshold ("more than one toucher — an override contest exists"), and
/// this primitive returns the "≥ 1" threshold ("any toucher at all — the
/// path was touched"). Together with the exact-cardinality endpoint
/// [`contributor_count_at`], the three primitives partition the
/// three-way outcome
///
/// ```text
/// contributor_count_at(layers, p) == 0   ⇔  !is_touched_at(layers, p)
/// contributor_count_at(layers, p) == 1   ⇔   is_touched_at(layers, p) && !is_contested_at(layers, p)
/// contributor_count_at(layers, p) >= 2   ⇔   is_contested_at(layers, p)
/// ```
///
/// with the monotonic chain `is_contested_at ⇒ is_touched_at` shifting
/// the predicate axis by exactly one hit.
///
/// The **boolean dual** of every neighboring None-endpoint on the
/// point-primitive lattice: [`contest_at`] / [`decider_at`] /
/// [`coarsest_at`] all carry an [`Option`] boundary that maps
/// [`None`] ↔ "no toucher"; [`contributors_at`] carries the
/// [`Vec::is_empty`] boundary at the same point. This primitive returns
/// the same bit directly as a [`bool`], without materializing a name
/// (which the caller then discards) or an owned [`Vec`].
///
/// # Identities
///
/// The five presence-boundary projections on the lattice collapse onto
/// one substrate-owned primitive with a **short-circuit forward walk**:
///
/// - `is_touched_at(layers, p) == `[`contributor_count_at`]`(layers, p) >= 1`
///   (cardinality-threshold identity at "≥ 1")
/// - `is_touched_at(layers, p) == `[`contest_at`]`(layers, p).is_some()`
///   (fused-value presence bit)
/// - `is_touched_at(layers, p) == `[`decider_at`]`(layers, p).is_some()`
///   (trailing-scalar presence bit)
/// - `is_touched_at(layers, p) == `[`coarsest_at`]`(layers, p).is_some()`
///   (leading-scalar presence bit)
/// - `is_touched_at(layers, p) == !`[`contributors_at`]`(layers, p).is_empty()`
///   (ordered-list emptiness dual)
///
/// The monotonic chain against the "≥ 2" endpoint:
///
/// ```text
/// is_contested_at(layers, p)  =>   is_touched_at(layers, p)
/// !is_touched_at(layers, p)   =>  !is_contested_at(layers, p)
/// ```
///
/// The singleton characterization on the exact-cardinality axis:
///
/// ```text
/// is_touched_at(layers, p) && !is_contested_at(layers, p)
///     <=>  contributor_count_at(layers, p) == 1
/// ```
///
/// All five routes are algebraically identical on their shared boolean
/// output; this primitive is the strictly-cheapest route when the caller
/// wants only the presence predicate and does not need the touchers list,
/// the decider name, the coarsest name, or the losers list.
///
/// # Semantics
///
/// The set of touchers is exactly the [`contributors_at`] projection:
/// every layer whose `discover()` places a leaf at `path`, opens a dict
/// container at `path`, or covers `path` with a scalar/array at a proper
/// prefix (wholesale-replace). One toucher is the true-boundary; the
/// zero-toucher case (no layer opinions at all along `path`) is the sole
/// false case.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the first hit** —
/// worst-case `O(layers × path.len())` (nobody touched), best-case
/// `O(path.len())` (the coarsest layer touches). Zero allocation on the
/// walker itself. Strictly cheaper than every alternative on the same
/// axis:
///
/// - [`contributors_at`]`(layers, p).is_empty()` walks every layer and
///   allocates the full `Vec<&'static str>` of touchers, then reads the
///   emptiness bit off the fat pointer — no short-circuit at any hit.
/// - [`contributor_count_at`]`(layers, p) >= 1` walks every layer with
///   [`Iterator::count`] and reads a scalar comparison off the total —
///   no short-circuit at any hit.
/// - [`contest_at`]`(layers, p).is_some()` walks every layer, allocates
///   the [`PathContest`]'s `overridden` `Vec`, then reads the
///   [`Option`] discriminant.
/// - [`decider_at`]`(layers, p).is_some()` walks layers in **reverse**
///   and short-circuits at the first hit — tied in traversal cost but
///   materializes a `&'static str` name only to discard it via
///   `.is_some()`.
/// - [`coarsest_at`]`(layers, p).is_some()` walks layers forward and
///   short-circuits at the first hit — tied in traversal cost but
///   materializes a `&'static str` name only to discard it via
///   `.is_some()`.
///
/// This primitive short-circuits at the first hit *and* returns the
/// boolean directly without projecting through an owned name — the
/// [`Iterator::any`] adapter compiles to a single-branch forward walk.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to Lightbend HOCON's
/// [`Config.hasPath`] predicate, extended to the pre-merge axis: HOCON's
/// `hasPath` reports whether the post-merge value tree has anything at
/// `path`, but the pre-merge presence question — "did *any* source ever
/// touch this key, even if its opinion was later erased by a
/// prefix-scalar?" — is recovered only by iterating each source's
/// [`Config.entrySet()`] and checking. `is_touched_at` packages the
/// pre-merge presence predicate as one substrate-owned primitive with a
/// short-circuiting forward walk, and covers the erasure case uniformly
/// by projecting the *touched* set rather than the *surviving* set.
/// Figment 0.10's per-value [`Tag`] names the surviving-leaf's origin
/// but reports nothing when the leaf was erased upstream;
/// `is_touched_at` remains `true` in that case because the pre-merge
/// touch happened.
///
/// [`Config.hasPath`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#hasPath-java.lang.String-
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn is_touched_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> bool {
    layers
        .iter()
        .any(|layer| touches_path(&layer.discover(), path))
}

/// True iff **at least two layers** have their opinion at `path`
/// overridden by the effective decider — the point-restricted
/// **"≥ 2" silenced-axis boolean** on the (path, layer) axis.
///
/// The **losers-axis "≥ 2" endpoint** of the point-primitive
/// cardinality-threshold lattice: [`silenced_at`] returns the
/// ordered list of overridden touchers, [`silenced_count_at`]
/// returns their scalar cardinality, and this primitive returns
/// the boolean predicate "two or more of them" — the losers-axis
/// analog of [`is_contested_at`] shifted one hit deeper along the
/// same touchers filter. Where [`is_contested_at`] closes the
/// "≥ 1 silenced" endpoint (equivalently "≥ 2 touchers"), this
/// primitive closes the "≥ 2 silenced" endpoint (equivalently
/// "≥ 3 touchers") on the same walk.
///
/// The **cardinality-threshold strict refinement** of
/// [`is_contested_at`] on the shared touchers filter:
///
/// ```text
/// contributor_count_at(layers, p) == 0   ⇔  !is_touched_at(layers, p)
/// contributor_count_at(layers, p) == 1   ⇔   is_touched_at(layers, p)
///                                           && !is_contested_at(layers, p)
/// contributor_count_at(layers, p) == 2   ⇔   is_contested_at(layers, p)
///                                           && !is_multiply_silenced_at(layers, p)
/// contributor_count_at(layers, p) >= 3   ⇔   is_multiply_silenced_at(layers, p)
/// ```
///
/// The **four-way partition** of the point-primitive touchers axis
/// closes with three short-circuiting boolean reads —
/// `(is_touched_at, is_contested_at, is_multiply_silenced_at)` —
/// each running the same `touches_path` filter with a progressively
/// deeper [`Iterator::nth`] termination
/// (`.any()` / `.nth(1).is_some()` / `.nth(2).is_some()`). The
/// monotonic chain
/// `is_multiply_silenced_at ⇒ is_contested_at ⇒ is_touched_at`
/// shifts the predicate axis by exactly one hit at each step.
///
/// # Identities
///
/// The five presence-boundary projections on the silenced axis at
/// the "≥ 2" cardinality-threshold collapse onto one substrate-owned
/// primitive with a **short-circuit forward walk**:
///
/// - `is_multiply_silenced_at(layers, p) == `[`silenced_count_at`]`(layers, p) >= 2`
///   (cardinality-threshold identity at "≥ 2" on the silenced axis)
/// - `is_multiply_silenced_at(layers, p) == (`[`silenced_at`]`(layers, p).len() >= 2)`
///   (ordered-list length-threshold dual on the losers axis)
/// - `is_multiply_silenced_at(layers, p) == (`[`contributor_count_at`]`(layers, p) >= 3)`
///   (contributors-side cardinality-threshold dual: the partition-count
///   law `silenced_count_at + usize::from(is_touched_at) ==
///   contributor_count_at` shifts the "≥ 2 silenced" threshold by
///   exactly one against the touchers scalar)
/// - `is_multiply_silenced_at(layers, p) == (`[`contributors_at`]`(layers, p).len() >= 3)`
///   (ordered-touchers cardinality-threshold dual)
/// - `is_multiply_silenced_at(layers, p) == `[`contest_at`]`(layers, p)
///   .is_some_and(|c| c.silenced_count() >= 2)` (folded-value method call:
///   the [`None`] branch on the fused side maps to `false` in agreement
///   with the no-toucher `false` branch on the primitive side)
///
/// The monotonic chain against the "≥ 1 silenced" endpoint (which
/// [`is_contested_at`] closes on the shared filter):
///
/// ```text
/// is_multiply_silenced_at(layers, p)  =>   is_contested_at(layers, p)
/// !is_contested_at(layers, p)         =>  !is_multiply_silenced_at(layers, p)
/// ```
///
/// The singleton characterization on the exact-cardinality silenced
/// axis:
///
/// ```text
/// is_contested_at(layers, p) && !is_multiply_silenced_at(layers, p)
///     <=>  silenced_count_at(layers, p) == 1
///     <=>  contributor_count_at(layers, p) == 2
/// ```
///
/// pins the "exactly one loser" state — a single override contest
/// with no chain of overrides — as an ordered-pair of two
/// short-circuiting boolean reads.
///
/// All five routes are algebraically identical on their shared
/// boolean output; this primitive is the strictly-cheapest route
/// when the caller wants only the "≥ 2 overridden touchers" presence
/// predicate and does not need the ordered losers list, the exact
/// losers count, the ordered touchers list, or the fused
/// [`PathContest`].
///
/// # Semantics
///
/// The set of losers is the leading prefix of the [`contributors_at`]
/// projection with the trailing decider popped: every layer whose
/// `discover()` touched `path` and whose opinion was subsequently
/// overridden by a more-specific toucher. Two losers is the
/// true-boundary; zero losers (no toucher or single uncontested
/// toucher) and one loser (single override contest) are collapsed
/// under the same `false` return. A `true` return says the path
/// carries a **chain of overrides** — at least three layers had an
/// opinion, two of which were silenced by the trailing decider.
///
/// # Cost
///
/// Walks layers forward with a **short-circuit on the third toucher**
/// — worst-case `O(layers × path.len())` (fewer than three touchers,
/// so [`Iterator::nth`] runs the full stack), best-case
/// `O(3 × path.len())` (the three coarsest layers all touch and
/// short-circuit the walk at the third hit). Zero allocation on the
/// walker itself. Strictly cheaper than every alternative on the
/// same axis:
///
/// - [`silenced_at`]`(layers, p).len() >= 2` walks every layer,
///   allocates the losers `Vec<&'static str>`, then reads a length
///   comparison off the fat pointer — no short-circuit at the third
///   hit.
/// - [`silenced_count_at`]`(layers, p) >= 2` walks every layer with
///   [`Iterator::count`] and one saturating subtraction, then reads
///   a scalar comparison — no short-circuit at the third hit.
/// - [`contributor_count_at`]`(layers, p) >= 3` walks every layer
///   with [`Iterator::count`] and reads a scalar comparison — no
///   short-circuit at the third hit.
/// - [`contest_at`]`(layers, p).is_some_and(|c| c.silenced_count() >= 2)`
///   walks every layer, allocates the [`PathContest`]'s `overridden`
///   `Vec`, then reads a `.len() >= 2` off the fused struct.
///
/// This primitive short-circuits at the third toucher *and* returns
/// the boolean directly without projecting through an owned name or
/// scalar — the [`Iterator::nth`] adapter compiles to a
/// single-branch forward walk over the same touchers filter
/// [`is_contested_at`] runs, only stopped at the third hit rather
/// than the second.
///
/// # HOCON analogue
///
/// The substrate-owned counterpart to "did this key get overridden
/// more than once?" — Lightbend HOCON callers reconstruct the answer
/// by iterating each source's [`Config.entrySet()`] at the key,
/// counting hits, and comparing against a threshold.
/// `is_multiply_silenced_at` packages the "≥ 2 overrides" bit as one
/// substrate-owned primitive over the same pre-merge touchers set
/// that [`silenced_at`], [`silenced_count_at`], and
/// [`is_contested_at`] share, with the short-circuiting
/// `.nth(2).is_some()` walk that closes the silenced-axis
/// cardinality-threshold lattice at the "≥ 2" endpoint. Figment
/// 0.10's per-value [`Tag`] names the surviving-leaf's origin but
/// exposes no predicate for a chain of overrides — the "did several
/// sources shadow this key?" question is unreachable without a
/// per-source `entrySet()` walk. `is_multiply_silenced_at` closes
/// that missing chain-of-overrides predicate seam.
///
/// [`Config.entrySet()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#entrySet--
/// [`Tag`]: https://docs.rs/figment/latest/figment/value/struct.Tag.html
#[must_use]
pub fn is_multiply_silenced_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> bool {
    layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .nth(2)
        .is_some()
}

/// A per-path override contest — the decider (winner) and the ordered
/// losers along `path`. Returned by [`contest_at`]; the typed fusion of
/// the pre-merge point primitives [`decider_at`] (winner projection)
/// and [`silenced_at`] (loser projection) into one value the *type
/// enforces* well-formedness of.
///
/// The [`Option<PathContest>`] return shape carries the "some toucher /
/// no toucher" boundary at the outer layer; inside a `PathContest`,
/// the `decider` field is unconditionally present — a `None` decider
/// is *unrepresentable*. That's the structural gain over the split
/// pair: a caller pattern-matching on `Option<PathContest>` handles
/// every case exhaustively, and the "there are losers but no winner"
/// state (which the loose pair `(Option<&'static str>,
/// Vec<&'static str>)` would silently admit as
/// `(None, ["a", "b"])`) cannot occur.
///
/// The relationship to the loose pair is the identity
///
/// ```text
/// contest_at(layers, p).map(|c| c.decider)     == decider_at(layers, p)
/// contest_at(layers, p).map(|c| c.overridden)  == Some(silenced_at(layers, p))
///                                              // when contest_at is Some
/// contest_at(layers, p).is_none()              == decider_at(layers, p).is_none()
///                                              == silenced_at(layers, p).is_empty()
///                                              &&  contributors_at(layers, p).is_empty()
/// ```
///
/// The reconstruction identity
///
/// ```text
/// [contest.overridden.clone(), vec![contest.decider]].concat()
///     == contributors_at(layers, p)
/// ```
///
/// pins the pair back to the ordered coarse→specific
/// [`contributors_at`] projection: `overridden` is the leading prefix,
/// `decider` is the trailing element. `contributor_count()` folds
/// the pair to its scalar cardinality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContest {
    /// Name of the effective decider — the most-specific-with-an-opinion
    /// layer along the queried path. Always the [`Some`] side of the
    /// [`decider_at`] projection; an empty decider is unrepresentable.
    pub decider: &'static str,
    /// The layers whose opinion at the queried path was overridden by
    /// `decider`, in application order (coarse→specific) — the
    /// [`silenced_at`] projection. Empty iff `decider` was the sole
    /// toucher (uncontested single-writer path).
    pub overridden: Vec<&'static str>,
}

impl PathContest {
    /// True iff at least one layer's opinion at the queried path was
    /// overridden — i.e. `overridden` is non-empty. The `false` case
    /// is "single toucher, no override contest"; the "no toucher"
    /// case is unrepresentable (mapped to [`None`] at the
    /// [`contest_at`] boundary).
    #[must_use]
    pub fn is_contested(&self) -> bool {
        !self.overridden.is_empty()
    }

    /// True iff **two or more** layers' opinions at the queried path were
    /// overridden — i.e. `overridden.len() >= 2`. The `PathContest`
    /// method-altitude dual of the free-fn [`is_multiply_silenced_at`]
    /// and the "≥ 2 silenced" endpoint of the losers-side boolean
    /// cardinality-threshold lattice at the point altitude, sibling to
    /// [`Self::is_contested`] (the "≥ 1 silenced" boolean, arithmetically
    /// equivalent to the "≥ 2 contributors" strict-contest predicate).
    /// Cannot short-circuit before `is_contested`: an uncontested contest
    /// (`overridden.is_empty()`) collapses this predicate to `false`
    /// by inspection.
    ///
    /// # Identities
    ///
    /// The three-way cardinality-threshold lattice on `overridden.len()`
    /// closes at the method surface:
    ///
    /// ```text
    /// is_contested()              <=>  silenced_count() >= 1
    ///                             <=>  overridden.len() >= 1
    ///                             <=>  contributor_count() >= 2
    /// is_multiply_silenced()      <=>  silenced_count() >= 2
    ///                             <=>  overridden.len() >= 2
    ///                             <=>  contributor_count() >= 3
    /// is_multiply_silenced()      =>   is_contested()
    /// !is_contested()             =>   !is_multiply_silenced()
    /// ```
    ///
    /// The [`Option<PathContest>`] boundary against the free-fn peer:
    ///
    /// ```text
    /// contest_at(layers, p).is_some_and(|c| c.is_multiply_silenced())
    ///     == is_multiply_silenced_at(layers, p)
    /// contest_at(layers, p).map_or(false, |c| c.is_multiply_silenced())
    ///     == is_multiply_silenced_at(layers, p)
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — one field-length read on `overridden` and one
    /// comparison. No allocation, no walk of the layer stack. Strictly
    /// cheaper than [`is_multiply_silenced_at`] (which calls
    /// `discover()` on every layer); strictly cheaper than chaining
    /// [`Self::silenced_count`] with `>= 2` (still `O(1)` but two
    /// method calls, one integer materialization) — the point of the
    /// dedicated boolean is that a caller predicating on the "≥ 2
    /// silenced" threshold names the intent structurally rather than
    /// spelling out the arithmetic at every consumer.
    #[must_use]
    pub fn is_multiply_silenced(&self) -> bool {
        self.overridden.len() >= 2
    }

    /// Total number of layers that touched the queried path — the
    /// decider plus every overridden toucher. Equals
    /// `contributors_at(layers, path).len()` on the same input. Never
    /// zero: a `PathContest` value always carries a decider, and the
    /// no-toucher case is [`None`] at the [`contest_at`] boundary.
    #[must_use]
    pub fn contributor_count(&self) -> usize {
        self.overridden.len() + 1
    }

    /// The **number of layers** whose opinion at the queried path was
    /// overridden by [`Self::decider`] — the field-length projection
    /// of [`Self::overridden`], the losers-side scalar dual of
    /// [`Self::contributor_count`] on the same touchers partition.
    /// Zero iff the contest is uncontested (the sole toucher is the
    /// decider); one or more for a contested path. Never subtracts
    /// from `1` — a `PathContest` value always carries a decider, so
    /// `silenced_count == contributor_count - 1` holds arithmetically
    /// without saturation.
    ///
    /// # Identities
    ///
    /// The losers-scalar endpoint of the per-path override contest
    /// pins onto the winners-scalar endpoint and the boolean predicate
    /// with a single field-length read:
    ///
    /// ```text
    /// silenced_count()               == overridden.len()
    /// silenced_count() + 1           == contributor_count()
    /// contributor_count()            == silenced_count() + 1     // never saturates
    /// silenced_count() >= 1          == is_contested()
    /// silenced_count() == 0          == !is_contested()
    /// ```
    ///
    /// The [`Option<PathContest>`] boundary against the free-fn
    /// scalar-cardinality dual on the losers axis:
    ///
    /// ```text
    /// contest_at(layers, p).map_or(0, |c| c.silenced_count())
    ///     == silenced_at(layers, p).len()
    ///     == silenced_count_at(layers, p)
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — a [`Vec::len`] read on `overridden`. No allocation,
    /// no walk of the layer stack. Strictly cheaper than re-invoking
    /// [`silenced_at`] or [`silenced_count_at`] (which each walk the
    /// full layer stack); strictly cheaper than materializing
    /// [`Self::contributors`] and subtracting one.
    #[must_use]
    pub fn silenced_count(&self) -> usize {
        self.overridden.len()
    }

    /// The full ordered contributor list — every layer that touched
    /// the queried path, in application order (coarse→specific). The
    /// reconstruction identity: the leading `overridden.len()` entries
    /// are exactly `overridden` in order, and the trailing entry is
    /// `decider`.
    ///
    /// The reconstruction identity as a method — a `PathContest` value
    /// is now self-sufficient for every projection off the (path,
    /// layer) axis. No re-walk of the layer stack needed. The identity
    /// against [`contributors_at`]:
    ///
    /// ```text
    /// contest_at(layers, p).map(|c| c.contributors())
    ///     == Some(contributors_at(layers, p))       // when contest_at(layers, p).is_some()
    /// contest_at(layers, p).map_or(vec![], |c| c.contributors())
    ///     == contributors_at(layers, p)             // total on both sides
    /// ```
    ///
    /// # Cost
    ///
    /// One `Vec` allocation of length `overridden.len() + 1`. `&'static
    /// str` slices are `Copy` so no per-element clone. Strictly cheaper
    /// than a fresh [`contributors_at`] call, which walks every layer
    /// again — this projection reads off the already-materialized
    /// `PathContest` in `O(overridden.len())` time.
    #[must_use]
    pub fn contributors(&self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(self.overridden.len() + 1);
        out.extend_from_slice(&self.overridden);
        out.push(self.decider);
        out
    }

    /// The full ordered contributor stream — every layer that touched
    /// the queried path, in application order (coarse→specific), as a
    /// zero-allocation iterator. The lazy dual of [`Self::contributors`]
    /// (which materializes the same sequence into a fresh
    /// `Vec<&'static str>` of length `overridden.len() + 1`) and the
    /// iterator-shaped sibling of [`Self::silenced`] (which returns a
    /// zero-alloc slice over the losers only). Together, the pair
    /// `(silenced, contributors_iter)` closes the zero-allocation
    /// accessor surface for both projections of the touchers partition:
    /// losers as a slice, winners+losers as an iterator, decider as a
    /// scalar field.
    ///
    /// The concatenation identity holds against [`Self::silenced`] and
    /// [`Self::decider`]:
    ///
    /// ```text
    /// contributors_iter()
    ///     == silenced().iter().copied().chain(std::iter::once(decider))
    /// ```
    ///
    /// # Identities
    ///
    /// The materialization identity against [`Self::contributors`]:
    ///
    /// ```text
    /// contributors_iter().collect::<Vec<_>>()  ==  contributors()
    /// ```
    ///
    /// The cardinality identity against [`Self::contributor_count`]:
    ///
    /// ```text
    /// contributors_iter().count()              ==  contributor_count()
    ///                                          ==  silenced_count() + 1
    /// ```
    ///
    /// The endpoint identities against [`Self::coarsest`] /
    /// [`Self::decider`]:
    ///
    /// ```text
    /// contributors_iter().next()               ==  Some(coarsest())
    /// contributors_iter().last()               ==  Some(decider)
    /// ```
    ///
    /// The one-step-back identity against [`Self::runner_up`]:
    ///
    /// ```text
    /// contributors_iter().nth(contributor_count() - 2)
    ///     == runner_up().or(Some(coarsest()))    // aliases coarsest when uncontested (len == 1)
    /// ```
    ///
    /// # Reverse walk
    ///
    /// The returned iterator is a [`DoubleEndedIterator`]: callers that
    /// want the trailing-first (specific→coarse) order — the diagnostic
    /// walk a "decider X overrides runner-up Y overrides coarsest Z"
    /// renderer wants — chain `.rev()` and pay zero allocation for the
    /// reversal. The reverse-endpoint identities against
    /// [`Self::decider`] / [`Self::coarsest`]:
    ///
    /// ```text
    /// contributors_iter().rev().next()         ==  Some(decider)
    /// contributors_iter().rev().last()         ==  Some(coarsest())
    /// contributors_iter().rev().collect::<Vec<_>>()
    ///     == { let mut v = contributors(); v.reverse(); v }
    /// ```
    ///
    /// # Independent walks
    ///
    /// The returned iterator is [`Clone`]: consumers that need to walk
    /// the contributor stream twice (e.g. render once, then re-walk to
    /// find a positional match) clone the iterator handle up front and
    /// pay two independent zero-allocation walks against the same
    /// substrate-owned [`Self::overridden`] slice, versus materializing
    /// [`Self::contributors`] once and holding the owned [`Vec`] for the
    /// second walk. The clone-then-walk equality:
    ///
    /// ```text
    /// let a = contributors_iter();
    /// let b = a.clone();
    /// a.collect::<Vec<_>>() == b.collect::<Vec<_>>() == contributors()
    /// ```
    ///
    /// The [`Option<PathContest>`] boundary against the free-fn
    /// contributor-list dual on the same axis:
    ///
    /// ```text
    /// contest_at(layers, p).map(|c| c.contributors_iter().collect::<Vec<_>>())
    ///     == Some(contributors_at(layers, p))          // when contest_at(layers, p).is_some()
    /// contest_at(layers, p)
    ///     .map_or(vec![], |c| c.contributors_iter().collect::<Vec<_>>())
    ///     == contributors_at(layers, p)                // total on both sides
    /// ```
    ///
    /// # Length
    ///
    /// The returned [`PathContestContributorsIter`] is an
    /// [`ExactSizeIterator`], so `.len()` returns
    /// `overridden.len() + 1` in `O(1)` — the trait-level parity of
    /// [`Self::contributor_count`] on the iterator surface. Callers
    /// that want the length without materializing the sequence write
    /// `.contributors_iter().len()` directly instead of
    /// `.contributors_iter().count()` (walks the stream) or the
    /// method-altitude peer [`Self::contributor_count`]:
    ///
    /// ```text
    /// contributors_iter().len()               ==  contributor_count()
    /// contributors_iter().size_hint()         ==  (n, Some(n))
    ///                                          where n == contributor_count()
    /// ```
    ///
    /// The iterator is also [`std::iter::FusedIterator`]: once
    /// exhausted, every further `.next()` / `.next_back()` returns
    /// [`None`] — the invariant every closed-form iterator carries at
    /// the trait surface, matching the pair on
    /// [`Self::silenced_iter`].
    ///
    /// # Cost
    ///
    /// `O(1)` per element, zero heap allocation. The concrete return
    /// type ([`PathContestContributorsIter`]) is a two-field stack
    /// value — a [`std::iter::Copied`] over the [`Self::overridden`]
    /// slice plus an [`Option<&'static str>`] holding the decider
    /// until it is consumed at either end — all stack-allocated.
    /// Strictly cheaper than [`Self::contributors`] (which pays a
    /// `+1`-length [`Vec`] allocation to fuse the same sequence into
    /// an owned handle); strictly cheaper than [`contributors_at`]
    /// (which walks every layer again and allocates afresh).
    /// Consumers that need an owned value chain
    /// `.contributors_iter().collect::<Vec<_>>()` at parity with
    /// [`Self::contributors`]'s allocation cost; consumers that only
    /// iterate — for renderers, `for` loops, `.count()` /
    /// `.enumerate()` / `.position()` walks — pay zero allocation for
    /// the full contributor stream, versus [`Self::contributors`]'s
    /// obligatory [`Vec`] materialization.
    #[must_use]
    pub fn contributors_iter(&self) -> PathContestContributorsIter<'_> {
        PathContestContributorsIter {
            overridden: self.overridden.iter().copied(),
            decider: Some(self.decider),
        }
    }

    /// The **silenced** list — the ordered names of every layer whose
    /// opinion at the queried path was overridden by [`Self::decider`],
    /// in application order (coarse→specific). The method-altitude,
    /// naming-consistent, zero-allocation dual of the [`silenced_at`]
    /// free-function on the losers axis of the touchers partition and
    /// the method-altitude sibling of [`Self::contributors`] (winners
    /// ∪ losers) on the winners+losers axis.
    ///
    /// Names, not renames. The underlying storage is the [`Self::overridden`]
    /// field — a caller reading directly off `.overridden` gets the same
    /// slice bytes. What `silenced` adds is *vocabulary uniformity*: the
    /// substrate's point-primitive naming register (`silenced_at`,
    /// `silenced_count`, `is_multiply_silenced`, `silenced_count_at`,
    /// `silent_layer_count`, `silent_layer_names`, `has_silent_layer`,
    /// `has_multiple_silent_layers`, `is_multiply_silenced_at`) speaks
    /// of *silenced* touchers on the losers axis. `.silenced()`
    /// completes the accessor register at the method altitude so the
    /// diagnostic seam — "which layers did the decider silence?" —
    /// reads structurally the same at every altitude, without a
    /// caller-side `overridden`↔`silenced` translation and without
    /// forcing consumers to reach past the method surface into a
    /// raw field.
    ///
    /// The reconstruction identity holds against [`Self::contributors`]
    /// with the trailing-of-touchers position for the decider:
    ///
    /// ```text
    /// [silenced(), &[decider]].concat()  ==  contributors()
    /// contributors()[..contributors().len() - 1]
    ///     == silenced()                        // total, since contributors().len() >= 1
    /// ```
    ///
    /// # Identities
    ///
    /// The zero-allocation slice equality against [`Self::overridden`]:
    ///
    /// ```text
    /// silenced()                        == overridden.as_slice()
    /// silenced().len()                  == overridden.len()
    ///                                    == silenced_count()
    /// silenced().is_empty()             == !is_contested()
    /// silenced().first().copied()       == coarsest_of_silenced           // Some iff is_contested()
    /// silenced().last().copied()        == runner_up()
    /// ```
    ///
    /// The [`Option<PathContest>`] boundary against the free-fn
    /// losers-list dual on the same axis:
    ///
    /// ```text
    /// contest_at(layers, p).map(|c| c.silenced().to_vec())
    ///     == Some(silenced_at(layers, p))              // when contest_at(layers, p).is_some()
    /// contest_at(layers, p).map_or(vec![], |c| c.silenced().to_vec())
    ///     == silenced_at(layers, p)                    // total on both sides
    /// ```
    ///
    /// The pairing with [`Self::is_contested`] on the same losers axis:
    ///
    /// ```text
    /// silenced().is_empty()             == !is_contested()
    /// silenced().is_empty()             == (silenced_count() == 0)
    /// silenced().len() >= 2             == is_multiply_silenced()
    /// ```
    ///
    /// The specificity endpoint identities (leading/trailing of losers):
    ///
    /// ```text
    /// silenced().first().copied()       == overridden.first().copied()
    /// silenced().last().copied()        == overridden.last().copied()
    ///                                    == runner_up()
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — one slice-reference read of [`Self::overridden`]. No
    /// allocation, no per-element copy, no walk of the layer stack.
    /// Strictly cheaper than [`silenced_at`] (which walks every layer
    /// once and allocates a fresh [`Vec`]); strictly cheaper than
    /// [`Self::contributors`] (which allocates a `+1`-length `Vec` to
    /// fuse the losers with the decider); strictly cheaper than
    /// materializing [`Self::contributors`] and taking its leading
    /// `.len() - 1` entries. Consumers that need an owned value chain
    /// `.silenced().to_vec()` at parity with [`silenced_at`]'s
    /// allocation cost; consumers that only iterate or index chain
    /// nothing and pay zero allocation for the loser list, versus
    /// [`silenced_at`]'s obligatory `Vec` materialization.
    #[must_use]
    pub fn silenced(&self) -> &[&'static str] {
        &self.overridden
    }

    /// The **silenced** stream — the ordered names of every layer whose
    /// opinion at the queried path was overridden by [`Self::decider`],
    /// in application order (coarse→specific), as a zero-allocation
    /// iterator. The iterator-shaped dual of [`Self::silenced`] (which
    /// returns a zero-alloc slice over the same substrate) and the
    /// losers-only sibling of [`Self::contributors_iter`] (the
    /// winners+losers iterator over the same touchers partition).
    /// Together, the pair `(contributors_iter, silenced_iter)` gives the
    /// touchers partition uniform iterator-shaped access at the method
    /// surface — winners+losers as an iterator, losers as an iterator —
    /// with [`Self::silenced`] (slice) and [`Self::contributors`] (owned
    /// [`Vec`]) retained for call sites that want the substrate handle or
    /// an owned copy.
    ///
    /// The naming register at the method altitude. Before this method,
    /// consumers wanting a losers-side iterator matching the shape of
    /// [`Self::contributors_iter`] (`impl DoubleEndedIterator<Item =
    /// &'static str> + Clone + '_`) open-coded one of two forms —
    /// `contest.silenced().iter().copied()` (three chained calls off
    /// the slice seam) or `contest.contributors_iter().take(contest
    /// .silenced_count())` (walk the full contributors stream and cut
    /// at the decider). The lift names the projection at one site so
    /// that call sites reach for `.silenced_iter()` symmetrically with
    /// `.contributors_iter()`, and the pair reads structurally the
    /// same at every altitude the diagnostic seams switch across.
    ///
    /// # Identities
    ///
    /// The materialization equality against [`Self::silenced`]:
    ///
    /// ```text
    /// silenced_iter().collect::<Vec<_>>()     ==  silenced().to_vec()
    /// silenced_iter().count()                 ==  silenced().len()
    ///                                          ==  silenced_count()
    /// ```
    ///
    /// The concatenation identity against [`Self::contributors_iter`]:
    ///
    /// ```text
    /// silenced_iter().chain(std::iter::once(decider))
    ///                                          ==  contributors_iter()
    /// ```
    ///
    /// The presence-boundary identity against [`Self::is_contested`]:
    ///
    /// ```text
    /// silenced_iter().next().is_none()        ==  !is_contested()
    /// silenced_iter().next().is_some()        ==  is_contested()
    /// ```
    ///
    /// The endpoint identities against [`Self::coarsest_silenced`] /
    /// [`Self::runner_up`]:
    ///
    /// ```text
    /// silenced_iter().next()                  ==  coarsest_silenced()
    /// silenced_iter().last()                  ==  runner_up()
    /// ```
    ///
    /// The [`Option<PathContest>`] boundary against the free-fn
    /// losers-list dual on the same axis:
    ///
    /// ```text
    /// contest_at(layers, p).map_or(vec![], |c| c.silenced_iter().collect())
    ///     ==  silenced_at(layers, p)
    /// ```
    ///
    /// # Reverse walk
    ///
    /// The returned iterator is [`DoubleEndedIterator`]: consumers
    /// rendering the losers specific→coarse (trailing-first, "runner-up
    /// first, coarsest silenced last") walk chain `.rev()` and pay zero
    /// allocation for the reversal. The reverse-endpoint identities
    /// against [`Self::runner_up`] / [`Self::coarsest_silenced`]:
    ///
    /// ```text
    /// silenced_iter().rev().next()            ==  runner_up()
    /// silenced_iter().rev().last()            ==  coarsest_silenced()
    /// ```
    ///
    /// # Length in constant time
    ///
    /// The returned iterator is [`ExactSizeIterator`]: the underlying
    /// [`slice::Iter`] carries the exact length and [`Iterator::copied`]
    /// preserves it. Consumers that need the losers count without
    /// exhausting the iterator reach `.len()` in `O(1)` on the handle
    /// directly, at parity with [`Self::silenced_count`].
    ///
    /// # Independent walks
    ///
    /// The returned iterator is [`Clone`]: consumers that need to walk
    /// the silenced stream twice (e.g. render once, then re-walk to find
    /// a positional match) clone the iterator handle up front and pay two
    /// independent zero-allocation walks over the same substrate-owned
    /// [`Self::overridden`] slice, versus [`Self::silenced`]`.to_vec()`
    /// then reusing the owned [`Vec`] for the second walk.
    ///
    /// # Cost
    ///
    /// `O(1)` per element, zero heap allocation. A single
    /// [`std::iter::Copied`] adapter over the [`Self::overridden`] slice
    /// — stack-only. Strictly cheaper than [`silenced_at`] (which walks
    /// every layer again and allocates a fresh [`Vec`]); strictly cheaper
    /// than [`Self::silenced`]`.to_vec()` for iterate-only consumers
    /// (`.silenced_iter()` skips the owned-`Vec` materialization);
    /// pointwise equal to [`Self::silenced`]`.iter().copied()` on the
    /// substrate side.
    #[must_use]
    pub fn silenced_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &'static str> + ExactSizeIterator + Clone + '_ {
        self.overridden.iter().copied()
    }

    /// The **coarsest** toucher — the first-in-application-order layer
    /// that placed an opinion at the queried path. Named dually to
    /// [`Self::decider`]: `decider` is the most-specific opinion (the
    /// trailing element of [`Self::contributors`]); `coarsest` is the
    /// most-general opinion (the *leading* element). Together, the
    /// pair frames the override cascade for diagnostic renderers —
    /// "`platform` opened this key, `tenancy` decided its final
    /// value" reads directly off `(coarsest, decider)`.
    ///
    /// Semantically the leading-element dual of [`Self::decider`]'s
    /// trailing-element projection. Never [`Option`]: a `PathContest`
    /// value always carries a decider, and when `overridden` is empty
    /// the sole toucher (`decider`) *is* the coarsest — the
    /// uncontested-singleton degenerate collapses cleanly rather
    /// than requiring the caller to `unwrap_or(decider)`.
    ///
    /// # Identities
    ///
    /// The leading-element identity against [`Self::contributors`]:
    ///
    /// ```text
    /// coarsest()                        == contributors().first().copied().unwrap()
    /// contest_at(layers, p).map(|c| c.coarsest())
    ///     == contributors_at(layers, p).first().copied()
    ///     == coarsest_at(layers, p)                        // total on both boundaries
    /// ```
    ///
    /// The uncontested-singleton degenerate:
    ///
    /// ```text
    /// !is_contested()  =>  coarsest() == decider
    /// ```
    ///
    /// which follows structurally: when `overridden.is_empty()`,
    /// `overridden.first()` is [`None`] and the `unwrap_or` branch
    /// returns `decider`.
    ///
    /// The pairing with [`Self::decider`]:
    ///
    /// ```text
    /// !is_contested()      <=>  coarsest() == decider
    /// is_contested()       =>   coarsest() != decider    (loosely — the
    ///                            two axes may coincidentally alias, but
    ///                            structurally coarsest is overridden[0])
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — one pointer read (`Vec::first`) and one branch. No
    /// allocation, no walk of the layer stack. Strictly cheaper than
    /// re-invoking any pre-merge point primitive; strictly cheaper
    /// than materializing [`Self::contributors`] and reading its
    /// leading element.
    #[must_use]
    pub fn coarsest(&self) -> &'static str {
        self.overridden.first().copied().unwrap_or(self.decider)
    }

    /// The **runner-up** — the most-specific-with-an-opinion layer whose
    /// vote was directly overridden by [`Self::decider`]. `None` iff the
    /// contest is uncontested (the sole toucher is the decider, so nothing
    /// stood one-step-back from it on the specificity axis).
    ///
    /// The trailing-element projection of [`Self::overridden`] and the
    /// one-step-back sibling of [`Self::decider`] on the touchers axis —
    /// where [`Self::coarsest`] is the *leading* element of the ordered
    /// touchers list, `runner_up` is the *second-to-last* element on that
    /// same list. Together, `(coarsest, runner_up, decider)` frame the
    /// three ordered specificity endpoints callers actually name when
    /// rendering the override cascade: "the coarsest layer that opened
    /// this key" / "the closest challenger the decider silenced" / "the
    /// layer that decided its final value".
    ///
    /// The diagnostic seam. In a HOCON-shaped cascade
    /// `platform → cloud → orchestrator → tenancy` where `tenancy`
    /// decides, `runner_up` is `orchestrator` — the answer to "what
    /// would this key have been if the decider hadn't touched it?".
    /// A renderer producing "expected: one of {…}; got: {…} at
    /// breathe.mode; decider: tenancy; overridden most directly:
    /// orchestrator" reads `.decider` and `.runner_up()` off the
    /// same value with no re-walk of the layer stack.
    ///
    /// # Identities
    ///
    /// The trailing-of-losers identity against [`Self::overridden`]:
    ///
    /// ```text
    /// runner_up()                       == overridden.last().copied()
    /// ```
    ///
    /// The one-step-back identity against [`Self::contributors`]:
    ///
    /// ```text
    /// runner_up()
    ///     == contributors().iter().nth_back(1).copied()   // second-to-last of contributors
    /// ```
    ///
    /// The presence-boundary identity against [`Self::is_contested`]:
    ///
    /// ```text
    /// runner_up().is_some()             == is_contested()
    /// runner_up().is_none()             == !is_contested()
    /// runner_up().is_some()             == (silenced_count() >= 1)
    /// ```
    ///
    /// The pairing with [`Self::coarsest`] on the shared touchers axis:
    ///
    /// ```text
    /// !is_contested()          =>  runner_up() == None
    ///                              && coarsest() == decider
    /// silenced_count() == 1    =>  runner_up() == Some(coarsest())        // singly contested: runner-up and coarsest alias
    /// silenced_count() >= 2    =>  runner_up() != Some(coarsest())        // structurally distinct positions on `overridden`
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — one [`Vec::last`] pointer read on `overridden` and one
    /// [`Option::copied`] on `&&'static str` (a scalar copy). No
    /// allocation, no walk of the layer stack. Strictly cheaper than
    /// re-invoking any point-primitive projection; strictly cheaper
    /// than materializing [`Self::contributors`] and reading its
    /// second-to-last element.
    #[must_use]
    pub fn runner_up(&self) -> Option<&'static str> {
        self.overridden.last().copied()
    }

    /// The **coarsest silenced** toucher — the first-in-application-order
    /// layer whose vote at the queried path was overridden by
    /// [`Self::decider`]. `None` iff the contest is uncontested (the sole
    /// toucher is the decider, so nothing on the losers list opens the
    /// override cascade).
    ///
    /// The leading-element projection of [`Self::overridden`] and the
    /// leading-of-silenced sibling of [`Self::runner_up`] (the
    /// trailing-of-silenced projection). Together, the pair
    /// `(coarsest_silenced, runner_up)` frames the two ordered endpoints
    /// on the silenced list — "the coarsest layer the decider silenced"
    /// and "the closest challenger the decider silenced" — at exact
    /// structural symmetry with `(coarsest, decider)` on the contributors
    /// list. Where [`Self::coarsest`] is total (the sole toucher *is* the
    /// coarsest when uncontested, so it collapses cleanly), `coarsest_silenced`
    /// is [`Option`]: with no silenced touchers there is no coarsest
    /// silenced name to give.
    ///
    /// The diagnostic seam. In a HOCON-shaped cascade
    /// `platform → cloud → orchestrator → tenancy` where `tenancy`
    /// decides, `coarsest_silenced` is `platform` — the answer to
    /// "which layer *first* placed an opinion here that the decider
    /// overrode?". A renderer producing "decider: tenancy; opened at:
    /// platform; runner-up: orchestrator" reads `.decider`, `.coarsest_silenced()`,
    /// and `.runner_up()` off the same value with no re-walk of the
    /// layer stack.
    ///
    /// # Identities
    ///
    /// The leading-of-losers identity against [`Self::overridden`] and
    /// [`Self::silenced`]:
    ///
    /// ```text
    /// coarsest_silenced()               == overridden.first().copied()
    /// coarsest_silenced()               == silenced().first().copied()
    /// ```
    ///
    /// The point-primitive boundary identity against
    /// [`coarsest_silenced_at`]:
    ///
    /// ```text
    /// contest_at(layers, p).and_then(|c| c.coarsest_silenced())
    ///     == coarsest_silenced_at(layers, p)         // total on both sides
    /// ```
    ///
    /// The presence-boundary identity against [`Self::is_contested`]:
    ///
    /// ```text
    /// coarsest_silenced().is_some()     == is_contested()
    /// coarsest_silenced().is_none()     == !is_contested()
    /// coarsest_silenced().is_some()     == (silenced_count() >= 1)
    /// ```
    ///
    /// The pairing identities with [`Self::coarsest`] and [`Self::runner_up`]
    /// on the shared touchers axis:
    ///
    /// ```text
    /// is_contested()          =>  coarsest_silenced() == Some(coarsest())
    /// !is_contested()         =>  coarsest_silenced() == None
    ///                             && coarsest() == decider
    /// silenced_count() == 1   =>  coarsest_silenced() == runner_up()       // singly contested: two endpoints alias
    /// silenced_count() >= 2   =>  coarsest_silenced() != runner_up()       // structurally distinct positions on `overridden`
    /// ```
    ///
    /// The total totalization identity across the [`Option`] boundary:
    ///
    /// ```text
    /// coarsest_silenced().unwrap_or(decider) == coarsest()
    /// ```
    ///
    /// — the sole-toucher degenerate collapses cleanly: with an empty
    /// `overridden`, the [`Option::unwrap_or`] branch returns the
    /// decider, which is exactly what [`Self::coarsest`] returns on that
    /// same branch.
    ///
    /// The strict-decider non-alias invariant on the [`Some`] branch:
    ///
    /// ```text
    /// coarsest_silenced() == Some(name)  =>  name != decider
    /// ```
    ///
    /// # Cost
    ///
    /// `O(1)` — one [`slice::first`] pointer read on `overridden` and
    /// one [`Option::copied`] on `&&'static str` (a scalar copy). No
    /// allocation, no walk of the layer stack. Strictly cheaper than
    /// re-invoking [`coarsest_silenced_at`] (which walks every layer
    /// with a short-circuit at the second hit); strictly cheaper than
    /// materializing [`Self::silenced`] and reading its leading element
    /// (already `O(1)` on the method surface, but this projection reads
    /// the copied name directly rather than a slice reference the
    /// caller must then `.first().copied()` off).
    #[must_use]
    pub fn coarsest_silenced(&self) -> Option<&'static str> {
        self.overridden.first().copied()
    }
}

/// Zero-allocation contributor stream — the ordered names of every
/// layer that touched the queried path, coarse→specific, yielded as
/// `&'static str`. The concrete return type of
/// [`PathContest::contributors_iter`] and the winners+losers dual of
/// [`PathContest::silenced_iter`]'s losers-only stream.
///
/// Naming the return type at the API boundary (rather than
/// `impl Trait + ...`) closes the full trait algebra the substrate
/// structurally holds: [`ExactSizeIterator`] over `overridden.len() + 1`
/// (the O(1) parity of [`PathContest::contributor_count`] at the trait
/// level) and [`std::iter::FusedIterator`] (calls after `None` stay
/// `None` — the invariant every closed-form iterator ought to name at
/// the trait surface). Callers writing `let n = contest
/// .contributors_iter().len()` now get the O(1) length directly instead
/// of walking to `.count()` or reaching for the sibling
/// [`PathContest::contributor_count`] method. The pair
/// (`PathContestContributorsIter`, [`PathContest::silenced_iter`]) reads
/// structurally symmetric at the type-signature level — both carry
/// `DoubleEndedIterator + ExactSizeIterator + FusedIterator + Clone` on
/// the `&'static str` item — closing the shape asymmetry the prior
/// `impl DoubleEndedIterator + Clone` return on `contributors_iter`
/// carried (`Chain<Copied<slice::Iter>, Once>` does not implement
/// [`ExactSizeIterator`] in stable Rust — the two halves' `usize` sum
/// may in principle overflow, so [`std::iter::Chain`] does not carry
/// the impl even when both halves do; the fusion state a
/// `PathContestContributorsIter` owns directly avoids that issue).
///
/// Follows the same idiom as [`AxisHistogramIter`][crate::AxisHistogramIter] /
/// [`AxisHistogramIntoIter`][crate::AxisHistogramIntoIter] on the cube
/// algebra — every zero-allocation iterator return on the discovered
/// substrate now carries a named concrete type at the API boundary.
#[derive(Debug, Clone)]
pub struct PathContestContributorsIter<'a> {
    overridden: std::iter::Copied<std::slice::Iter<'a, &'static str>>,
    decider: Option<&'static str>,
}

impl Iterator for PathContestContributorsIter<'_> {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        self.overridden.next().or_else(|| self.decider.take())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }

    fn count(self) -> usize {
        self.len()
    }

    fn last(mut self) -> Option<Self::Item> {
        // The decider — when still held — is the trailing element of the
        // forward walk; otherwise the trailing element sits at the back of
        // whatever remains of the overridden slice.
        if self.decider.is_some() {
            self.decider.take()
        } else {
            self.overridden.last()
        }
    }
}

impl DoubleEndedIterator for PathContestContributorsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.decider.take().or_else(|| self.overridden.next_back())
    }
}

impl ExactSizeIterator for PathContestContributorsIter<'_> {
    fn len(&self) -> usize {
        self.overridden.len() + usize::from(self.decider.is_some())
    }
}

impl std::iter::FusedIterator for PathContestContributorsIter<'_> {}

/// The full **per-path override contest** at `path` — decider (winner)
/// and losers, fused into one [`PathContest`]. `None` iff no layer
/// touches `path`.
///
/// The typed fusion of the pre-merge point primitives [`decider_at`]
/// and [`silenced_at`]: rather than calling both and re-composing the
/// pair at every consumer, this primitive owns the single walk that
/// produces both projections, and its return type
/// ([`Option<PathContest>`]) structurally forbids the ill-formed pair
/// "losers without a winner". Error-path renderers producing
/// `expected: one of {...}; got: {…} at breathe.mode; decider:
/// tenancy; overridden: platform, cloud` reach for this primitive
/// once and read `.decider` and `.overridden` off the returned struct.
///
/// The `is_contested_at` / cardinality queries collapse onto method
/// calls on the returned [`PathContest`]:
///
/// ```text
/// contest_at(layers, p).map_or(false, |c| c.is_contested())      // strict contest predicate
/// contest_at(layers, p).map_or(0, |c| c.contributor_count())     // contributors_at.len() equivalent
/// ```
///
/// # Semantics
///
/// The set of touchers is exactly the [`contributors_at`] projection:
/// every layer whose `discover()` places a leaf at `path`, opens a
/// dict container at `path`, or covers `path` with a scalar/array at
/// a proper prefix (wholesale-replace). The trailing (most-specific)
/// toucher becomes `decider`; the leading (coarse) touchers become
/// `overridden`, order preserved.
///
/// # Partition law
///
/// For every layer stack and every path `p`:
///
/// ```text
/// contest_at(layers, p).map(|c| c.decider)      == decider_at(layers, p)
/// contest_at(layers, p).map(|c| c.coarsest())   == coarsest_at(layers, p)
/// contest_at(layers, p).map(|c| c.overridden)   == Some(silenced_at(layers, p))
///                                               // when contest_at is Some
/// contest_at(layers, p).map_or(0, |c| c.contributor_count())
///     == contributors_at(layers, p).len()
/// ```
///
/// The reconstruction identity holds as ordered-vector equality:
///
/// ```text
/// let mut recomposed = c.overridden.clone();
/// recomposed.push(c.decider);
/// recomposed == contributors_at(layers, p)
/// ```
///
/// When [`compose_with_provenance`]`(layers).attribution
/// .layer_of(p)` is `Some(w)`, `contest_at(layers, p)` is `Some(c)`
/// with `c.decider == w`; when `layer_of(p)` is `None` (path is a
/// dict container or was erased by a prefix-scalar), `contest_at`
/// still names the responsible decider whenever any layer touches
/// `p`.
///
/// # Cost
///
/// Calls `discover()` once per layer and walks each dict along `path`
/// once — `O(layers × path.len())` time, `O(overridden.len())`
/// allocation on the `PathContest`'s inner `Vec` (the trailing pop
/// is amortized `O(1)`). Strictly one traversal, versus the two
/// traversals a naive `(decider_at(p), silenced_at(p))` pair would
/// do — a fixed 2× cost win for the common "render both projections
/// at one path" workload the diagnostic seam actually hits.
///
/// # HOCON analogue
///
/// The typed fusion of Lightbend HOCON's post-merge
/// [`Config.getValue(path).origin()`] with a synthesized "shadowed
/// origins at this key" projection HOCON does not expose directly —
/// callers reconstruct the latter by set-differencing per-source
/// `entrySet()` origins against the merged value's origin. `contest_at`
/// packages both into one substrate-owned value, computed in one
/// walk, whose type forbids the "shadowed origins with no surviving
/// value's origin" pair that HOCON's caller code has to guard
/// against by convention.
///
/// [`Config.getValue(path).origin()`]: https://lightbend.github.io/config/latest/api/com/typesafe/config/Config.html#getValue-java.lang.String-
#[must_use]
pub fn contest_at(layers: &[&dyn DiscoveryLayer], path: &[&str]) -> Option<PathContest> {
    let mut names: Vec<&'static str> = layers
        .iter()
        .filter(|layer| touches_path(&layer.discover(), path))
        .map(|layer| layer.name())
        .collect();
    let decider = names.pop()?;
    Some(PathContest {
        decider,
        overridden: names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::value::Value;

    /// A test layer that emits a fixed dict under a fixed name.
    struct Fixed(&'static str, Dict);
    impl DiscoveryLayer for Fixed {
        fn name(&self) -> &'static str {
            self.0
        }
        fn discover(&self) -> Dict {
            self.1.clone()
        }
    }

    fn dict(pairs: &[(&str, Value)]) -> Dict {
        let mut d = Dict::new();
        for (k, v) in pairs {
            d.insert((*k).to_owned(), v.clone());
        }
        d
    }

    #[test]
    fn deep_merge_overlay_wins_scalars_and_keeps_siblings() {
        let mut base = dict(&[("a", Value::from(1i64)), ("b", Value::from(2i64))]);
        deep_merge(
            &mut base,
            dict(&[("b", Value::from(20i64)), ("c", Value::from(3i64))]),
        );
        assert_eq!(
            base.get("a"),
            Some(&Value::from(1i64)),
            "untouched sibling kept"
        );
        assert_eq!(base.get("b"), Some(&Value::from(20i64)), "overlay wins");
        assert_eq!(base.get("c"), Some(&Value::from(3i64)), "new key added");
    }

    #[test]
    fn deep_merge_recurses_into_nested_dicts() {
        let mut base = dict(&[(
            "breathe",
            Value::from(dict(&[
                ("setpoint", Value::from(0.80)),
                ("mode", Value::from("live")),
            ])),
        )]);
        // Overlay only changes mode; setpoint must survive the nested merge.
        deep_merge(
            &mut base,
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let Some(Value::Dict(_, inner)) = base.get("breathe") else {
            panic!("nested dict preserved");
        };
        assert_eq!(
            inner.get("setpoint"),
            Some(&Value::from(0.80)),
            "sibling survives"
        );
        assert_eq!(
            inner.get("mode"),
            Some(&Value::from("shadow")),
            "leaf overridden"
        );
    }

    #[test]
    fn deep_merge_dict_replaces_scalar_and_vice_versa() {
        // scalar base, dict overlay → overlay replaces (not a type-confused merge).
        let mut base = dict(&[("x", Value::from(1i64))]);
        deep_merge(
            &mut base,
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        assert!(
            matches!(base.get("x"), Some(Value::Dict(..))),
            "dict replaced scalar"
        );

        // dict base, scalar overlay → overlay replaces (the reverse direction).
        let mut base = dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]);
        deep_merge(&mut base, dict(&[("x", Value::from(9i64))]));
        assert_eq!(
            base.get("x"),
            Some(&Value::from(9i64)),
            "scalar replaced dict"
        );
    }

    #[test]
    fn deep_merge_replaces_arrays_wholesale() {
        // Arrays REPLACE (matching figment's Order::Merge); they are not
        // concatenated. A discovered list-valued key (e.g. an ingress list) from
        // a specific layer fully supersedes a coarser one.
        let mut base = dict(&[(
            "xs",
            Value::from(vec![Value::from(1i64), Value::from(2i64)]),
        )]);
        deep_merge(
            &mut base,
            dict(&[("xs", Value::from(vec![Value::from(9i64)]))]),
        );
        let Some(Value::Array(_, arr)) = base.get("xs") else {
            panic!("array value");
        };
        assert_eq!(arr.len(), 1, "array replaced wholesale, not concatenated");
        assert_eq!(arr[0], Value::from(9i64));
    }

    #[test]
    fn deep_merge_recurses_three_levels_preserving_each_sibling() {
        let mut base = dict(&[(
            "a",
            Value::from(dict(&[(
                "b",
                Value::from(dict(&[
                    ("keep", Value::from(1i64)),
                    ("change", Value::from(2i64)),
                ])),
            )])),
        )]);
        deep_merge(
            &mut base,
            dict(&[(
                "a",
                Value::from(dict(&[(
                    "b",
                    Value::from(dict(&[("change", Value::from(20i64))])),
                )])),
            )]),
        );
        let Some(Value::Dict(_, a)) = base.get("a") else {
            panic!("a")
        };
        let Some(Value::Dict(_, b)) = a.get("b") else {
            panic!("b")
        };
        assert_eq!(
            b.get("keep"),
            Some(&Value::from(1i64)),
            "level-3 sibling survives"
        );
        assert_eq!(
            b.get("change"),
            Some(&Value::from(20i64)),
            "level-3 leaf overridden"
        );
    }

    #[test]
    fn compose_specific_layer_overrides_coarse() {
        let coarse = Fixed(
            "platform",
            dict(&[
                ("setpoint", Value::from(0.80)),
                ("floor", Value::from("256Mi")),
            ]),
        );
        let specific = Fixed("tenancy", dict(&[("setpoint", Value::from(0.70))]));
        let out = compose(&[&coarse, &specific]);
        assert_eq!(
            out.get("setpoint"),
            Some(&Value::from(0.70)),
            "specific (later) wins"
        );
        assert_eq!(
            out.get("floor"),
            Some(&Value::from("256Mi")),
            "coarse-only key retained"
        );
    }

    #[test]
    fn compose_empty_layer_contributes_nothing() {
        let real = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        assert_eq!(
            compose(&[&real, &empty]),
            compose(&[&real]),
            "empty axis invisible"
        );
    }

    #[test]
    fn compose_no_layers_is_empty() {
        assert!(compose(&[]).is_empty());
    }

    #[test]
    fn layer_names_in_application_order() {
        let a = Fixed("platform", Dict::new());
        let b = Fixed("tenancy", Dict::new());
        assert_eq!(layer_names(&[&a, &b]), vec!["platform", "tenancy"]);
    }

    // -------- compose_with_provenance --------

    #[test]
    fn compose_with_provenance_attributes_each_leaf_to_its_writer() {
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.dict,
            compose(&[&a, &b]),
            "dict projection agrees with compose"
        );
        assert_eq!(out.attribution.layer_of(&["k1"]), Some("platform"));
        assert_eq!(
            out.attribution.layer_of(&["k2"]),
            Some("tenancy"),
            "later layer wins per leaf"
        );
        assert_eq!(out.attribution.layer_of(&["k3"]), Some("tenancy"));
        assert_eq!(
            out.attribution.layer_of(&["never"]),
            None,
            "unset paths are unattributed"
        );
        assert_eq!(out.attribution.len(), 3);
        assert!(!out.attribution.is_empty());
    }

    #[test]
    fn compose_with_provenance_recurses_into_nested_dicts_per_leaf() {
        let a = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        // Overlay only touches `breathe.mode`; the sibling `breathe.setpoint`
        // stays attributed to the coarse layer.
        let b = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["breathe", "setpoint"]),
            Some("platform"),
            "sibling under nested dict retains coarse writer"
        );
        assert_eq!(
            out.attribution.layer_of(&["breathe", "mode"]),
            Some("tenancy"),
            "overwritten nested leaf gets the specific writer"
        );
        assert_eq!(out.attribution.len(), 2);
    }

    #[test]
    fn compose_with_provenance_dict_replaces_scalar_purges_prior_attribution() {
        // Layer A writes a scalar at `x`; layer B replaces it with a dict.
        // The prior `x` leaf attribution is purged (there's no `x` leaf
        // anymore — `x` is now a dict node), and the new `x.y` leaf is
        // attributed to B.
        let a = Fixed("first", dict(&[("x", Value::from(1i64))]));
        let b = Fixed(
            "second",
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["x"]),
            None,
            "scalar leaf attribution purged when replaced by a dict"
        );
        assert_eq!(out.attribution.layer_of(&["x", "y"]), Some("second"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_scalar_replaces_dict_purges_sub_attributions() {
        // Layer A writes a dict subtree; layer B replaces it wholesale
        // with a scalar. Every sub-leaf attribution under `x` is purged,
        // and the new leaf at `x` is attributed to B.
        let a = Fixed(
            "first",
            dict(&[(
                "x",
                Value::from(dict(&[("y", Value::from(1i64)), ("z", Value::from(2i64))])),
            )]),
        );
        let b = Fixed("second", dict(&[("x", Value::from(99i64))]));
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["x", "y"]),
            None,
            "sub-leaf attribution purged when parent replaced by scalar"
        );
        assert_eq!(out.attribution.layer_of(&["x", "z"]), None);
        assert_eq!(
            out.attribution.layer_of(&["x"]),
            Some("second"),
            "replacing scalar attributed at the flattened path"
        );
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_arrays_replace_wholesale_and_reattribute() {
        // Matches deep_merge's array-replace-wholesale semantics: the
        // whole array leaf is credited to the later writer.
        let a = Fixed(
            "first",
            dict(&[("xs", Value::from(vec![Value::from(1i64)]))]),
        );
        let b = Fixed(
            "second",
            dict(&[(
                "xs",
                Value::from(vec![Value::from(9i64), Value::from(10i64)]),
            )]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["xs"]), Some("second"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_empty_layer_preserves_prior_attribution() {
        // An undetectable axis contributes nothing — the earlier stack
        // is preserved verbatim, including attribution.
        let a = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&a, &empty]);
        assert_eq!(out.attribution.layer_of(&["k"]), Some("real"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_no_layers_is_empty_and_unattributed() {
        let out = compose_with_provenance(&[]);
        assert!(out.dict.is_empty());
        assert!(out.attribution.is_empty());
        assert_eq!(out.attribution.len(), 0);
    }

    #[test]
    fn compose_with_provenance_iter_yields_lexicographic_order() {
        // BTreeMap keyed on Vec<String> sorts lex on the whole vector:
        // ["a","y"] < ["m"] < ["z"] (element-wise ordering; shorter
        // prefixes come first only when the compared elements tie).
        let a = Fixed("A", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "B",
            dict(&[("a", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let c = Fixed("C", dict(&[("m", Value::from(3i64))]));
        let out = compose_with_provenance(&[&a, &b, &c]);
        let observed: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(
            observed,
            vec![
                (vec!["a".to_owned(), "y".to_owned()], "B"),
                (vec!["m".to_owned()], "C"),
                (vec!["z".to_owned()], "A"),
            ]
        );
    }

    #[test]
    fn compose_with_provenance_dict_matches_independent_deep_merge_walk() {
        // `compose` now routes through `compose_with_provenance` (one
        // primitive owns the merge semantics), so comparing
        // `out.dict == compose(layers)` alone would be tautological.
        // This test walks the layers through the standalone
        // [`deep_merge`] primitive as an independent reference —
        // pinning the attributed primitive's dict against a merge
        // implementation that carries none of its state.
        let a = Fixed(
            "A",
            dict(&[
                ("outer", Value::from(dict(&[("a", Value::from(1i64))]))),
                ("scalar", Value::from(1i64)),
            ]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("outer", Value::from(dict(&[("b", Value::from(2i64))]))),
                // Cross-shape: overwrites scalar with dict.
                ("scalar", Value::from(dict(&[("inner", Value::from(9i64))]))),
            ]),
        );
        let via_prov = compose_with_provenance(&[&a, &b]).dict;
        let mut via_plain = Dict::new();
        deep_merge(&mut via_plain, a.discover());
        deep_merge(&mut via_plain, b.discover());
        assert_eq!(
            via_prov, via_plain,
            "attributed compose dict matches independent deep_merge walk"
        );
    }

    // -------- LayerAttribution::layer_of / layer_of_owned --------

    #[test]
    fn layer_of_owned_agrees_with_layer_of_pointwise() {
        // The allocation-free `layer_of_owned` and the borrowed-str
        // `layer_of` are two seams onto the same BTreeMap lookup —
        // they must agree at every path (present and absent).
        let a = Fixed(
            "A",
            dict(&[(
                "outer",
                Value::from(dict(&[("a", Value::from(1i64)), ("b", Value::from(2i64))])),
            )]),
        );
        let b = Fixed("B", dict(&[("scalar", Value::from(3i64))]));
        let out = compose_with_provenance(&[&a, &b]);

        // Every present leaf: both accessors return the same layer.
        for (path_slice, layer) in out.attribution.iter() {
            let borrowed: Vec<&str> = path_slice.iter().map(String::as_str).collect();
            assert_eq!(
                out.attribution.layer_of(&borrowed),
                Some(layer),
                "layer_of at {path_slice:?} must match iter()",
            );
            assert_eq!(
                out.attribution.layer_of_owned(path_slice),
                Some(layer),
                "layer_of_owned at {path_slice:?} must match iter()",
            );
        }
        // Absent path: both return None.
        let absent: [&str; 2] = ["outer", "never"];
        assert_eq!(out.attribution.layer_of(&absent), None);
        let absent_owned: Vec<String> = absent.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(out.attribution.layer_of_owned(&absent_owned), None);
    }

    #[test]
    fn layer_of_is_not_a_prefix_match_only_exact_leaves() {
        // A dict subtree exists at `outer` but the leaf lives at
        // `outer.a`. A lookup at `outer` alone must miss — this pins
        // that `layer_of` never returns a spurious hit on an interior
        // node (a bug the prior linear scan would also have avoided,
        // now preserved under the BTreeMap::get seam).
        let a = Fixed(
            "A",
            dict(&[("outer", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let out = compose_with_provenance(&[&a]);
        assert_eq!(out.attribution.layer_of(&["outer", "a"]), Some("A"));
        assert_eq!(
            out.attribution.layer_of(&["outer"]),
            None,
            "interior nodes are not leaves and must not resolve",
        );
    }

    #[test]
    fn layer_of_owned_skips_allocation_on_owned_paths() {
        // The primitive contract on `layer_of_owned`: pass in a path
        // sourced from `iter()`'s own owned `Vec<String>` and get an
        // O(log n) hit without materializing intermediate owned
        // strings. The equivalence-with-`layer_of` test above already
        // pins the semantic identity; this test pins the ergonomic
        // seam a real caller uses (walk `iter()`, thread each path
        // straight back into `layer_of_owned`).
        let a = Fixed(
            "A",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed("B", dict(&[("k3", Value::from(3i64))]));
        let out = compose_with_provenance(&[&a, &b]);

        let owned_paths: Vec<Vec<String>> = out
            .attribution
            .iter()
            .map(|(path_slice, _)| path_slice.to_vec())
            .collect();
        for path in &owned_paths {
            assert!(
                out.attribution.layer_of_owned(path).is_some(),
                "every iter()-sourced path must resolve on layer_of_owned",
            );
        }
    }

    // -------- LayerAttribution::iter (DoubleEndedIterator + Clone) --------

    /// Shared fixture for the sharpened-trait-algebra tests: three
    /// layers, six live leaves, mixed sole/overridden writers — enough
    /// entries that the reverse walk and the clone-independence tests
    /// exercise more than the trivial one-entry case.
    fn iter_fixture() -> DiscoveryComposition {
        let coarse = Fixed(
            "coarse",
            dict(&[
                ("alpha", Value::from(1i64)),
                ("beta", Value::from(2i64)),
                (
                    "breathe",
                    Value::from(dict(&[
                        ("mode", Value::from("live")),
                        ("setpoint", Value::from(0.80)),
                    ])),
                ),
            ]),
        );
        let mid = Fixed("mid", dict(&[("gamma", Value::from(3i64))]));
        let specific = Fixed(
            "specific",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[("setpoint", Value::from(0.70))])),
                ),
                ("delta", Value::from(4i64)),
            ]),
        );
        compose_with_provenance(&[&coarse, &mid, &specific])
    }

    #[test]
    fn attribution_iter_rev_reverses_forward_walk() {
        // Reverse-walk identity: iter().rev().collect() equals
        // iter().collect().reversed(). The DoubleEndedIterator bound
        // on the sharpened signature is the underlying
        // BTreeMap::Iter's — reversing walks from the largest key back
        // to the smallest in lex order.
        let out = iter_fixture();
        let forward: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let reverse: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .rev()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let mut expected = forward.clone();
        expected.reverse();
        assert_eq!(reverse, expected, "iter().rev() reverses iter() pointwise");
    }

    #[test]
    fn attribution_iter_rev_endpoints_alias_first_and_last_key() {
        // Reverse-endpoint identities: rev().next() yields the largest
        // key (lex-last leaf), rev().last() yields the smallest key
        // (lex-first leaf). This is the DoubleEndedIterator's
        // observable behavior on a `Map<BTreeMap::Iter, F>` — the
        // capability the sharpened signature exposes at the API
        // boundary.
        let out = iter_fixture();
        let forward: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let mut back = out.attribution.iter();
        let last = back.next_back().expect("non-empty");
        assert_eq!(
            (last.0.to_vec(), last.1),
            forward.last().cloned().expect("non-empty"),
            "next_back() yields the lex-last (path, layer)",
        );
        let front = back.next_back().expect("more than one entry");
        assert_eq!(
            (front.0.to_vec(), front.1),
            forward[forward.len() - 2].clone(),
            "successive next_back walks specific→coarse in lex order",
        );
    }

    #[test]
    fn attribution_iter_clone_yields_independent_walks() {
        // Clone-independence: two clones collect to the same result,
        // and interleaved advance preserves per-clone position — the
        // Clone bound on the sharpened signature gives two independent
        // walks over the same BTreeMap without a second collect().
        let out = iter_fixture();
        let a = out.attribution.iter();
        let b = a.clone();
        let a_collected: Vec<(Vec<String>, &'static str)> =
            a.map(|(p, l)| (p.to_vec(), l)).collect();
        let b_collected: Vec<(Vec<String>, &'static str)> =
            b.map(|(p, l)| (p.to_vec(), l)).collect();
        assert_eq!(
            a_collected, b_collected,
            "cloned handles yield the same walk"
        );

        // Interleaved advance: one clone advances, the other stays.
        let mut left = out.attribution.iter();
        let mut right = left.clone();
        let l0 = left.next().expect("non-empty");
        let r0 = right.next().expect("non-empty");
        assert_eq!(
            (l0.0.to_vec(), l0.1),
            (r0.0.to_vec(), r0.1),
            "both clones observe the same first entry — position is per-clone",
        );
        // Advance left twice more; right's position must be unaffected.
        let _ = left.next();
        let _ = left.next();
        let r1 = right.next().expect("second entry present");
        assert_eq!(
            (r1.0.to_vec(), r1.1),
            a_collected[1],
            "right sees the second entry regardless of left's advance",
        );
    }

    #[test]
    fn attribution_iter_clone_and_rev_compose() {
        // Composition test: `.clone().rev()` and `.rev().clone()` yield
        // the same reversed stream — pinning that Clone and
        // DoubleEndedIterator compose commutatively on the Map<Iter, F>
        // return type the sharpened signature exposes.
        let out = iter_fixture();
        let base: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .rev()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let via_clone_then_rev: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .clone()
            .rev()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let via_rev_then_clone: Vec<(Vec<String>, &'static str)> = {
            let rev = out.attribution.iter().rev();
            rev.clone().map(|(p, l)| (p.to_vec(), l)).collect()
        };
        assert_eq!(base, via_clone_then_rev);
        assert_eq!(base, via_rev_then_clone);
    }

    // -------- LayerAttribution::writes_by_layer --------

    #[test]
    fn writes_by_layer_groups_leaves_under_their_writer() {
        // Two layers, four leaves — the inverse projection gathers
        // each layer's paths in one bucket.
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let groups = out.attribution.writes_by_layer();

        // Two distinct writers.
        let layers: Vec<&&'static str> = groups.keys().collect();
        assert_eq!(
            layers,
            vec![&"platform", &"tenancy"],
            "outer BTreeMap keys sort lex on layer name",
        );

        // Platform kept `k1`; tenancy wrote `k2` (overwriting) and `k3`.
        let platform = groups.get("platform").expect("platform bucket");
        let tenancy = groups.get("tenancy").expect("tenancy bucket");
        assert_eq!(
            platform,
            &vec![["k1".to_owned()].as_slice()],
            "platform kept k1 only",
        );
        assert_eq!(
            tenancy,
            &vec![["k2".to_owned()].as_slice(), ["k3".to_owned()].as_slice(),],
            "tenancy holds k2 (overwritten) and k3, in lex path order",
        );
    }

    #[test]
    fn writes_by_layer_partitions_leaves_by_writer() {
        // The partition law from the rustdoc: every leaf belongs to
        // exactly one layer, the flattened union equals `iter()`
        // verbatim, and the sum of bucket lens equals `len()`.
        let a = Fixed(
            "A",
            dict(&[(
                "outer",
                Value::from(dict(&[
                    ("keep", Value::from("k")),
                    ("change", Value::from(1i64)),
                ])),
            )]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("outer", Value::from(dict(&[("change", Value::from(9i64))]))),
                ("array", Value::from(vec![Value::from(0i64)])),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let groups = out.attribution.writes_by_layer();

        // Bucket-len sum equals overall leaf count.
        let bucket_sum: usize = groups.values().map(Vec::len).sum();
        assert_eq!(bucket_sum, out.attribution.len());

        // Flattened union equals `iter()`'s path set.
        let mut flattened: Vec<&[String]> = groups
            .values()
            .flat_map(|paths| paths.iter().copied())
            .collect();
        flattened.sort();
        let mut iter_paths: Vec<&[String]> = out.attribution.iter().map(|(p, _)| p).collect();
        iter_paths.sort();
        assert_eq!(
            flattened, iter_paths,
            "the flattened bucket union equals iter()'s path set",
        );

        // Every (layer, path) in a bucket satisfies layer_of_owned(path) == Some(layer).
        for (layer, paths) in &groups {
            for path in paths {
                assert_eq!(
                    out.attribution.layer_of_owned(path),
                    Some(*layer),
                    "layer_of_owned must agree with the bucket layer",
                );
            }
        }
    }

    #[test]
    fn writes_by_layer_empty_when_no_layers() {
        let out = compose_with_provenance(&[]);
        assert!(
            out.attribution.writes_by_layer().is_empty(),
            "no layers ⇒ no buckets",
        );
    }

    #[test]
    fn writes_by_layer_empty_layer_drops_out_of_buckets() {
        // A layer that contributed nothing (empty dict) does not appear
        // as a bucket key — the map is keyed on writers only. This
        // mirrors the `compose_with_provenance_empty_layer` invariant
        // on the leaf-count axis: an undetectable axis is invisible in
        // both the merged dict and the inverse projection.
        let real = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&real, &empty]);
        let groups = out.attribution.writes_by_layer();
        assert_eq!(groups.len(), 1);
        assert!(
            groups.contains_key("real"),
            "the real writer keeps its bucket",
        );
        assert!(
            !groups.contains_key("undetectable"),
            "an empty-dict layer contributes no leaves, so no bucket",
        );
    }

    #[test]
    fn writes_by_layer_yields_deterministic_layer_and_path_order() {
        // Outer keys sort lex on `&'static str` (BTreeMap iteration);
        // inner Vec<&[String]> lands in the same lex path order the
        // underlying BTreeMap<Vec<String>, _> iteration emits.
        let a = Fixed("Z", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "A",
            dict(&[
                ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
                ("m", Value::from(3i64)),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let groups = out.attribution.writes_by_layer();

        // Outer key order: "A" < "Z".
        let layers: Vec<&&'static str> = groups.keys().collect();
        assert_eq!(layers, vec![&"A", &"Z"]);

        // A's paths, in lex order: ["a","y"] < ["m"].
        let a_paths = groups.get("A").expect("A bucket");
        assert_eq!(
            a_paths,
            &vec![
                ["a".to_owned(), "y".to_owned()].as_slice(),
                ["m".to_owned()].as_slice(),
            ],
        );
        // Z's single path.
        let z_paths = groups.get("Z").expect("Z bucket");
        assert_eq!(z_paths, &vec![["z".to_owned()].as_slice()]);
    }

    // -------- LayerAttribution::leaf_counts_by_layer --------

    #[test]
    fn leaf_counts_by_layer_counts_writes_per_layer() {
        // Two layers, four leaves — the compact histogram companion
        // returns one count per writer, in the same lex order on
        // layer name as `writes_by_layer`.
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let counts = out.attribution.leaf_counts_by_layer();

        let layers: Vec<&&'static str> = counts.keys().collect();
        assert_eq!(
            layers,
            vec![&"platform", &"tenancy"],
            "outer BTreeMap keys sort lex on layer name",
        );
        assert_eq!(
            counts.get("platform").copied(),
            Some(1),
            "platform kept k1 only",
        );
        assert_eq!(
            counts.get("tenancy").copied(),
            Some(2),
            "tenancy holds k2 (overwritten) and k3",
        );
    }

    #[test]
    fn leaf_counts_by_layer_partition_count_law() {
        // The partition-count law: the sum of every value equals
        // `len()` (every leaf belongs to exactly one layer's count).
        let a = Fixed(
            "A",
            dict(&[(
                "outer",
                Value::from(dict(&[
                    ("keep", Value::from("k")),
                    ("change", Value::from(1i64)),
                ])),
            )]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("outer", Value::from(dict(&[("change", Value::from(9i64))]))),
                ("array", Value::from(vec![Value::from(0i64)])),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let counts = out.attribution.leaf_counts_by_layer();
        let sum: usize = counts.values().sum();
        assert_eq!(sum, out.attribution.len());
    }

    #[test]
    fn leaf_counts_by_layer_agrees_with_writes_by_layer_sizes() {
        // Cross-projection identity: `leaf_counts_by_layer` and
        // `writes_by_layer` are two seams onto the same underlying
        // BTreeMap — the compact seam must equal the wide seam's
        // per-bucket len() at every writer, and the two must share
        // the same key set verbatim.
        let a = Fixed("Z", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "A",
            dict(&[
                ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
                ("m", Value::from(3i64)),
            ]),
        );
        let c = Fixed("M", dict(&[("q", Value::from(4i64))]));
        let out = compose_with_provenance(&[&a, &b, &c]);

        let counts = out.attribution.leaf_counts_by_layer();
        let groups = out.attribution.writes_by_layer();
        let counts_keys: Vec<&&'static str> = counts.keys().collect();
        let groups_keys: Vec<&&'static str> = groups.keys().collect();
        assert_eq!(
            counts_keys, groups_keys,
            "compact and wide seams share the outer key set verbatim",
        );
        for (layer, paths) in &groups {
            assert_eq!(
                counts.get(layer).copied(),
                Some(paths.len()),
                "leaf_counts_by_layer[{layer}] == writes_by_layer[{layer}].len()",
            );
        }
    }

    #[test]
    fn leaf_counts_by_layer_empty_when_no_layers() {
        let out = compose_with_provenance(&[]);
        assert!(
            out.attribution.leaf_counts_by_layer().is_empty(),
            "no layers ⇒ no counters",
        );
    }

    #[test]
    fn leaf_counts_by_layer_empty_layer_drops_out_of_counters() {
        // A layer with an empty dict contributes no leaves — no bucket
        // key — mirrors the corresponding `writes_by_layer` invariant
        // on the sizing seam.
        let real = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&real, &empty]);
        let counts = out.attribution.leaf_counts_by_layer();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts.get("real").copied(), Some(1));
        assert!(
            !counts.contains_key("undetectable"),
            "an empty-dict layer contributes no leaves, so no counter",
        );
    }

    #[test]
    fn leaf_counts_by_layer_reflects_dict_over_scalar_reshape() {
        // Cross-shape reshape: layer A writes a scalar at `x`; layer B
        // replaces it with a dict `{x.y}`. `compose_with_provenance`
        // purges the stale `["x"]` attribution and re-attributes
        // `["x", "y"]` to B. The compact histogram reads only the live
        // attribution map, so B gets 1 count and A drops out entirely.
        let a = Fixed("first", dict(&[("x", Value::from(1i64))]));
        let b = Fixed(
            "second",
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let counts = out.attribution.leaf_counts_by_layer();
        assert_eq!(counts.get("second").copied(), Some(1));
        assert!(
            !counts.contains_key("first"),
            "purged scalar attribution drops A from the counters",
        );
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn compose_with_provenance_dict_matches_compose_projection_across_shape_transitions() {
        // Invariant: compose_with_provenance(...).dict == compose(...) for
        // every input — pins the "one primitive owns the merge semantics"
        // property across scalars, nested dicts, arrays, and cross-shape
        // replacement.
        let a = Fixed(
            "A",
            dict(&[
                ("scalar", Value::from(1i64)),
                (
                    "nested",
                    Value::from(dict(&[
                        ("keep", Value::from("k")),
                        ("change", Value::from("A")),
                    ])),
                ),
            ]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("nested", Value::from(dict(&[("change", Value::from("B"))]))),
                ("array", Value::from(vec![Value::from(1i64)])),
                // Cross-shape: overwrite scalar with dict.
                ("scalar", Value::from(dict(&[("inner", Value::from(2i64))]))),
            ]),
        );
        let c = Fixed(
            "C",
            dict(&[
                ("array", Value::from(vec![Value::from(9i64)])),
                // Cross-shape: overwrite dict with scalar.
                ("scalar", Value::from(99i64)),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b, &c]);
        assert_eq!(
            out.dict,
            compose(&[&a, &b, &c]),
            "dict projection equals plain compose across shape transitions"
        );
        // Spot-check attribution follows the same replacements.
        assert_eq!(out.attribution.layer_of(&["nested", "keep"]), Some("A"));
        assert_eq!(out.attribution.layer_of(&["nested", "change"]), Some("B"));
        assert_eq!(out.attribution.layer_of(&["array"]), Some("C"));
        assert_eq!(out.attribution.layer_of(&["scalar"]), Some("C"));
        // The intermediate B-written `scalar.inner` sub-leaf is purged by C.
        assert_eq!(out.attribution.layer_of(&["scalar", "inner"]), None);
    }

    // -------- LayerAttribution::subtree_iter / subtree --------

    fn s(x: &str) -> String {
        x.to_owned()
    }

    /// A rich two-layer fixture reused across the subtree cohort:
    /// nested dicts under `breathe.*`, a scalar sibling at `alpha`,
    /// and a specific-layer key `breatheZ` whose lex ordering lands
    /// immediately after `breathe.setpoint` — the prefix-extending
    /// sibling that pins the take_while boundary condition.
    fn subtree_fixture() -> DiscoveryComposition {
        let coarse = Fixed(
            "coarse",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[
                        ("mode", Value::from("live")),
                        ("setpoint", Value::from(0.80)),
                    ])),
                ),
                ("alpha", Value::from(1i64)),
            ]),
        );
        let specific = Fixed(
            "specific",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[("setpoint", Value::from(0.70))])),
                ),
                // `["breatheZ"]` follows `["breathe", "setpoint"]` in
                // Vec<String> lex order but is NOT a descendant of
                // `["breathe"]` — the substring "breathe" prefixes
                // "breatheZ" as a string, but path_has_prefix compares
                // the whole element, not string prefixes.
                ("breatheZ", Value::from(9i64)),
            ]),
        );
        compose_with_provenance(&[&coarse, &specific])
    }

    #[test]
    fn subtree_iter_at_root_prefix_matches_iter() {
        // `subtree_iter(&[])` is the identity: every leaf prefixes
        // itself with `[]`, and `Bound::Included(&[])` seeks to the
        // very first BTreeMap entry — so the range walk yields every
        // entry, in the same order as `iter()`.
        let out = subtree_fixture();
        let full: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .subtree_iter(&[])
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        let via_iter: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(full, via_iter, "empty prefix ⇒ full iter, same order");
        assert_eq!(
            out.attribution.subtree(&[]).len(),
            out.attribution.len(),
            "subtree(&[]) equals self on the len() axis",
        );
    }

    #[test]
    fn subtree_iter_at_named_prefix_yields_only_that_subtree_in_lex_order() {
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let observed: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .subtree_iter(&prefix)
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(
            observed,
            vec![
                (vec![s("breathe"), s("mode")], "coarse"),
                (vec![s("breathe"), s("setpoint")], "specific"),
            ],
            "subtree yields only breathe.* leaves in lex order",
        );
    }

    #[test]
    fn subtree_iter_stops_at_prefix_extending_sibling_key() {
        // The critical boundary case: `["breatheZ"]` immediately follows
        // `["breathe", "setpoint"]` in Vec<String> lex order (the string
        // "breathe" is a proper prefix of "breatheZ", so
        // `["breathe", ...]` all sort before `["breatheZ"]`, and no
        // other key sits between them). But `["breatheZ"]` is NOT a
        // descendant of `["breathe"]` — its first element is a
        // different string, not the same element extended. The
        // take_while must halt at `["breatheZ"]`. A range formulation
        // that computed a lex successor of `["breathe"]` and stopped
        // there would need to be careful about exactly this case;
        // reading `path_has_prefix` directly reads the invariant we
        // actually want.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let observed: Vec<Vec<String>> = out
            .attribution
            .subtree_iter(&prefix)
            .map(|(p, _)| p.to_vec())
            .collect();
        assert!(
            !observed.contains(&vec![s("breatheZ")]),
            "prefix-extending sibling `breatheZ` is NOT a descendant of `breathe`",
        );
        assert_eq!(
            observed.len(),
            2,
            "only the two `breathe.*` leaves are yielded, not `breatheZ`",
        );
        // And the parent attribution DOES hold `breatheZ` — this pins
        // that the exclusion is a subtree-scope decision, not a leaf
        // that never landed.
        assert_eq!(
            out.attribution.layer_of(&["breatheZ"]),
            Some("specific"),
            "the excluded sibling is still attributed in the parent",
        );
    }

    #[test]
    fn subtree_iter_empty_when_prefix_names_no_subtree() {
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_iter(&[s("nonexistent")]).count(),
            0,
            "absent prefix ⇒ empty iterator",
        );
        assert!(
            out.attribution.subtree(&[s("nonexistent")]).is_empty(),
            "absent prefix ⇒ empty projection",
        );
    }

    #[test]
    fn subtree_iter_at_exact_leaf_yields_that_leaf_only() {
        // Reflexive case: `path_has_prefix(&["alpha"], &["alpha"])` is
        // true, so a prefix that exactly names a scalar leaf resolves
        // to that leaf alone.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        let observed: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .subtree_iter(&prefix)
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(observed, vec![(vec![s("alpha")], "coarse")]);
    }

    #[test]
    fn subtree_agrees_with_subtree_iter_pointwise() {
        // The projection primitive is `subtree_iter().collect()`; a
        // restricted attribution must expose the same (path, layer)
        // pairs the iterator does, and `layer_of_owned` on the child
        // must agree with `layer_of_owned` on the parent for every
        // path in the subtree.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub = out.attribution.subtree(&prefix);
        let via_projection: Vec<(Vec<String>, &'static str)> =
            sub.iter().map(|(p, l)| (p.to_vec(), l)).collect();
        let via_iter: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .subtree_iter(&prefix)
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(via_projection, via_iter);
        assert_eq!(sub.len(), 2);
        for (path, layer) in &via_iter {
            assert_eq!(sub.layer_of_owned(path), Some(*layer));
            assert_eq!(out.attribution.layer_of_owned(path), Some(*layer));
        }
    }

    #[test]
    fn subtree_writes_by_layer_is_subset_of_parent() {
        // `subtree(prefix).writes_by_layer()` is the inverse projection
        // restricted to the subtree; every bucket ⊆ the parent's
        // bucket for the same layer, and every layer that appears in
        // the subtree also appears in the parent. The substrate
        // reuses itself at the sub-altitude — no per-consumer filter.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub = out.attribution.subtree(&prefix);
        let sub_groups = sub.writes_by_layer();
        let parent_groups = out.attribution.writes_by_layer();
        for (layer, sub_paths) in &sub_groups {
            let parent_paths = parent_groups
                .get(layer)
                .expect("every subtree layer appears in the parent");
            for path in sub_paths {
                assert!(
                    parent_paths.contains(path),
                    "sub-bucket paths are a subset of parent-bucket paths",
                );
            }
        }
        // Two writers under `breathe.*` — `coarse` (mode) and
        // `specific` (setpoint) — both appear.
        assert!(sub_groups.contains_key("coarse"));
        assert!(sub_groups.contains_key("specific"));
    }

    #[test]
    fn subtree_leaf_counts_by_layer_composes_at_sub_altitude() {
        // The compact histogram composes on `subtree` at zero cost:
        // `attribution.subtree(prefix).leaf_counts_by_layer()` is the
        // per-layer size of the sub-tree rooted at `prefix`. Under
        // `breathe.*` in the fixture, `coarse` wrote `mode` and
        // `specific` wrote `setpoint` — each 1. The parent's totals
        // include `alpha` (coarse) and `breatheZ` (specific) too, so
        // the sub-counts are strictly `≤` the parent's counts for
        // each layer that appears in the subtree.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub_counts = out.attribution.subtree(&prefix).leaf_counts_by_layer();
        assert_eq!(sub_counts.get("coarse").copied(), Some(1));
        assert_eq!(sub_counts.get("specific").copied(), Some(1));
        assert_eq!(sub_counts.len(), 2);

        let parent_counts = out.attribution.leaf_counts_by_layer();
        for (layer, sub_count) in &sub_counts {
            let parent_count = parent_counts
                .get(layer)
                .copied()
                .expect("every subtree layer appears in the parent");
            assert!(
                *sub_count <= parent_count,
                "sub-count for {layer} ({sub_count}) must not exceed parent count ({parent_count})",
            );
        }
    }

    #[test]
    fn subtree_iter_reflects_dict_over_scalar_reshape() {
        // Layer A writes a scalar at `x`; layer B replaces it with a
        // dict `{x.y}`. The compose primitive purges the stale
        // scalar attribution at `["x"]` and re-attributes the sub-leaf
        // at `["x", "y"]` to B. `subtree_iter(&["x"])` must reflect
        // the reshape: yield only `["x", "y"]`, never a stale `["x"]`.
        let a = Fixed("first", dict(&[("x", Value::from(1i64))]));
        let b = Fixed(
            "second",
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let observed: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .subtree_iter(&[s("x")])
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(observed, vec![(vec![s("x"), s("y")], "second")]);
    }

    #[test]
    fn subtree_iter_clone_yields_independent_walks() {
        // Clone-independence: two clones over the same range walk
        // collect to the same result and interleaved advance preserves
        // per-clone position. The Clone bound on the sharpened
        // signature gives two independent walks over the same
        // BTreeMap::range without re-invoking the O(log n) range seek
        // or allocating an intermediate Vec.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let a = out.attribution.subtree_iter(&prefix);
        let b = a.clone();
        let a_collected: Vec<(Vec<String>, &'static str)> =
            a.map(|(p, l)| (p.to_vec(), l)).collect();
        let b_collected: Vec<(Vec<String>, &'static str)> =
            b.map(|(p, l)| (p.to_vec(), l)).collect();
        assert_eq!(
            a_collected, b_collected,
            "cloned handles yield the same subtree walk"
        );

        // Interleaved advance across the two-leaf breathe.* subtree.
        let mut left = out.attribution.subtree_iter(&prefix);
        let mut right = left.clone();
        let l0 = left.next().expect("breathe.mode");
        let r0 = right.next().expect("breathe.mode");
        assert_eq!(
            (l0.0.to_vec(), l0.1),
            (r0.0.to_vec(), r0.1),
            "both clones observe the same first entry",
        );
        // Advance left to exhaustion; right's next() must still see the
        // second entry — its position is per-clone, not shared.
        let _ = left.next();
        assert!(left.next().is_none(), "left is exhausted after two entries");
        let r1 = right.next().expect("right still has breathe.setpoint");
        assert_eq!(
            (r1.0.to_vec(), r1.1),
            a_collected[1],
            "right's position is independent of left's",
        );
    }

    #[test]
    fn subtree_iter_clone_at_root_prefix_matches_iter_clone() {
        // Empty-prefix identity extended to the Clone axis: cloning
        // `subtree_iter(&[])` yields the same stream as cloning
        // `iter()` — both wrap the same BTreeMap::iter substrate at
        // the empty prefix (BTreeMap::range with unbounded ends
        // degenerates to full iteration), and both carry Clone at
        // zero runtime cost.
        let out = iter_fixture();
        let via_subtree = out.attribution.subtree_iter(&[]);
        let via_subtree_clone = via_subtree.clone();
        let via_iter_clone = out.attribution.iter().clone();
        let sub_collected: Vec<(Vec<String>, &'static str)> =
            via_subtree.map(|(p, l)| (p.to_vec(), l)).collect();
        let sub_clone_collected: Vec<(Vec<String>, &'static str)> =
            via_subtree_clone.map(|(p, l)| (p.to_vec(), l)).collect();
        let iter_clone_collected: Vec<(Vec<String>, &'static str)> =
            via_iter_clone.map(|(p, l)| (p.to_vec(), l)).collect();
        assert_eq!(sub_collected, sub_clone_collected);
        assert_eq!(sub_collected, iter_clone_collected);
    }

    // -------- LayerAttribution::subtree_surviving_layer_names --------

    #[test]
    fn subtree_surviving_layer_names_empty_prefix_equals_surviving_layer_names() {
        // `subtree_surviving_layer_names(&[])` matches every entry (via
        // `subtree_iter(&[])`'s identity behavior) and therefore agrees
        // with the top-level `surviving_layer_names` verbatim on both
        // order and content.
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&[]),
            out.attribution.surviving_layer_names(),
            "empty prefix ⇒ same lex name-set as the top-level projection",
        );
    }

    #[test]
    fn subtree_surviving_layer_names_at_named_prefix_lists_writers_under_it() {
        // Under `breathe.*` the two live leaves are `breathe.mode`
        // (coarse) and `breathe.setpoint` (specific) — both writers
        // appear, in lex order on layer name (not application order).
        // The `alpha` leaf under `coarse` and the `breatheZ` sibling
        // under `specific` land in the parent's name-set but must NOT
        // show up here just because their writer names do — this
        // projection reads through the subtree, not through the writer
        // set.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&prefix),
            vec!["coarse", "specific"],
        );
    }

    #[test]
    fn subtree_surviving_layer_names_agrees_with_subtree_surviving_layer_names() {
        // Identity with the naive composition
        // `subtree(prefix).surviving_layer_names()`: same lex order,
        // same name-set — pins that the range-walk-plus-BTreeSet path
        // and the fresh-attribution-then-surviving path are semantic
        // duals, and the direct primitive skips the intermediate
        // allocation the composition performs.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            assert_eq!(
                out.attribution.subtree_surviving_layer_names(&prefix),
                out.attribution.subtree(&prefix).surviving_layer_names(),
                "direct seam agrees with the subtree-then-surviving composition at {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_surviving_layer_names_absent_prefix_is_empty() {
        // A prefix that names no subtree ⇒ the range walk yields
        // nothing ⇒ no writers accumulate ⇒ empty vector. Mirrors
        // `subtree_iter_empty_when_prefix_names_no_subtree` on the
        // name-set axis.
        let out = subtree_fixture();
        assert!(
            out.attribution
                .subtree_surviving_layer_names(&[s("nonexistent")])
                .is_empty(),
            "absent prefix ⇒ empty name-set",
        );
    }

    #[test]
    fn subtree_surviving_layer_names_at_exact_scalar_leaf_lists_only_its_writer() {
        // Reflexive case: a prefix that exactly names a scalar leaf
        // yields exactly that leaf's writer, singleton. Under
        // `alpha` in the fixture that is `coarse` alone.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&prefix),
            vec!["coarse"],
        );
    }

    #[test]
    fn subtree_surviving_layer_names_stops_at_prefix_extending_sibling_key() {
        // The take_while boundary inherited from `subtree_iter`:
        // `["breatheZ"]` (specific's write) shares the string prefix
        // "breathe" but is not a path descendant of `["breathe"]`. Its
        // writer `specific` must still appear in the subtree's name
        // set here — because `["breathe", "setpoint"]` (also specific)
        // IS under the subtree — but if we swap the specific layer to
        // ONLY write the sibling, that specific-writer must drop from
        // the subtree name-set.
        let coarse = Fixed(
            "coarse",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        // `specific` writes ONLY the prefix-extending sibling, never a
        // real descendant of `breathe`. Its writer must NOT appear in
        // the subtree name-set.
        let specific_only_sibling = Fixed("specific", dict(&[("breatheZ", Value::from(9i64))]));
        let out = compose_with_provenance(&[&coarse, &specific_only_sibling]);
        let prefix = vec![s("breathe")];
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&prefix),
            vec!["coarse"],
            "the prefix-extending sibling's writer is NOT credited against the subtree",
        );
        // Sanity: the top-level projection DOES list `specific` — it
        // wrote a live leaf at `["breatheZ"]`, just not one under the
        // `breathe.*` subtree.
        assert_eq!(
            out.attribution.surviving_layer_names(),
            vec!["coarse", "specific"],
        );
    }

    #[test]
    fn subtree_surviving_layer_names_deduplicates_multi_write_writer() {
        // A writer with several live leaves under the subtree appears
        // exactly once — the BTreeSet collapses duplicates the way
        // the top-level `surviving_layer_names` does at global scope.
        // Under `svc.*` here, `only` writes three leaves — the result
        // is `["only"]`, singleton.
        let only = Fixed(
            "only",
            dict(&[(
                "svc",
                Value::from(dict(&[
                    ("a", Value::from(1i64)),
                    ("b", Value::from(2i64)),
                    ("c", Value::from(3i64)),
                ])),
            )]),
        );
        let out = compose_with_provenance(&[&only]);
        let prefix = vec![s("svc")];
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&prefix),
            vec!["only"],
        );
    }

    #[test]
    fn subtree_surviving_layer_names_returns_lex_order_on_layer_name() {
        // Application order is [Z-layer, A-layer]; the compact
        // projection sorts lex on layer name (BTreeSet iteration),
        // matching `surviving_layer_names` at the top-level altitude.
        // Both writers touch leaves under the `svc.*` subtree.
        let z_layer = Fixed(
            "Z",
            dict(&[("svc", Value::from(dict(&[("k1", Value::from(1i64))])))]),
        );
        let a_layer = Fixed(
            "A",
            dict(&[("svc", Value::from(dict(&[("k2", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&z_layer, &a_layer]);
        let prefix = vec![s("svc")];
        assert_eq!(
            out.attribution.subtree_surviving_layer_names(&prefix),
            vec!["A", "Z"],
            "lex order, not application order",
        );
    }

    #[test]
    fn subtree_surviving_layer_names_subset_of_surviving_layer_names() {
        // Subset invariant: for every prefix,
        //   subtree_surviving_layer_names(prefix) ⊆ surviving_layer_names()
        // The fixture's `alpha`-only subtree pins the STRICT direction:
        // `specific` writes only under `breathe.*` and `breatheZ`, so
        // under `["alpha"]` it has no live leaves and drops from the
        // subtree name-set while remaining in the top-level one.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        let sub_set: std::collections::BTreeSet<_> = out
            .attribution
            .subtree_surviving_layer_names(&prefix)
            .into_iter()
            .collect();
        let top_set: std::collections::BTreeSet<_> = out
            .attribution
            .surviving_layer_names()
            .into_iter()
            .collect();
        assert!(sub_set.is_subset(&top_set), "sub ⊆ top on every prefix");
        assert!(
            sub_set.len() < top_set.len(),
            "the `alpha`-only subtree drops `specific` — strict subset",
        );
        assert!(
            !sub_set.contains("specific"),
            "specific has no leaf under alpha"
        );
    }

    #[test]
    fn subtree_surviving_layer_names_empty_when_no_leaves() {
        // No layers ⇒ empty attribution ⇒ empty name-set at every prefix.
        let empty = compose_with_provenance(&[]);
        assert!(
            empty
                .attribution
                .subtree_surviving_layer_names(&[])
                .is_empty()
        );
        assert!(
            empty
                .attribution
                .subtree_surviving_layer_names(&[s("any")])
                .is_empty(),
        );
    }

    // -------- contributor_names --------

    #[test]
    fn contributor_names_filters_empty_layers() {
        // The middle axis is undetectable ⇒ it is invisible on the
        // contributor projection just as it is invisible in the composed
        // dict.
        let a = Fixed("platform", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("undetectable", Dict::new());
        let c = Fixed("tenancy", dict(&[("k", Value::from(2i64))]));
        assert_eq!(
            contributor_names(&[&a, &b, &c]),
            vec!["platform", "tenancy"]
        );
    }

    #[test]
    fn contributor_names_preserves_application_order() {
        // Order is application order (coarse→specific), NOT alphabetical
        // — the caller's declared ordering survives the projection.
        let a = Fixed("tenancy", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("platform", dict(&[("k", Value::from(2i64))]));
        assert_eq!(contributor_names(&[&a, &b]), vec!["tenancy", "platform"]);
    }

    #[test]
    fn contributor_names_empty_when_all_layers_undetectable() {
        let a = Fixed("a", Dict::new());
        let b = Fixed("b", Dict::new());
        assert!(contributor_names(&[&a, &b]).is_empty());
    }

    #[test]
    fn contributor_names_empty_when_no_layers() {
        assert!(contributor_names(&[]).is_empty());
    }

    #[test]
    fn contributor_names_is_subset_of_layer_names() {
        // The subset invariant on the (name → contributor?) axis:
        // every contributor name is one of the declared layer names.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", Dict::new());
        let c = Fixed("c", dict(&[("k", Value::from(2i64))]));
        let all: std::collections::BTreeSet<_> = layer_names(&[&a, &b, &c]).into_iter().collect();
        let contributors: std::collections::BTreeSet<_> =
            contributor_names(&[&a, &b, &c]).into_iter().collect();
        assert!(
            contributors.is_subset(&all),
            "contributors ⊆ declared names"
        );
        assert_eq!(
            contributors.len(),
            2,
            "the empty middle layer is filtered out"
        );
    }

    #[test]
    fn contributor_names_emptiness_matches_composed_emptiness() {
        // The composition-emptiness ↔ contributor-emptiness identity on
        // fixtures where contributors write distinct top-level keys
        // (the discipline every DiscoveryLayer satisfies): the composed
        // dict is empty iff no layer contributed.
        let a_empty = Fixed("a", Dict::new());
        let b_empty = Fixed("b", Dict::new());
        let empty_stack: [&dyn DiscoveryLayer; 2] = [&a_empty, &b_empty];
        assert!(contributor_names(&empty_stack).is_empty());
        assert!(compose(&empty_stack).is_empty());

        let a = Fixed("a", dict(&[("x", Value::from(1i64))]));
        let b = Fixed("b", Dict::new());
        let c = Fixed("c", dict(&[("y", Value::from(2i64))]));
        let stack: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(!contributor_names(&stack).is_empty());
        assert!(!compose(&stack).is_empty());
    }

    #[test]
    fn contributor_names_counts_overridden_writers_too() {
        // The "had an opinion" semantics: a coarse contributor whose
        // top-level key is wholly overridden by a specific one is still
        // a contributor — the count reflects who wrote into the merge,
        // not whose leaves survived.
        let coarse = Fixed("platform", dict(&[("setpoint", Value::from(0.80))]));
        let specific = Fixed("tenancy", dict(&[("setpoint", Value::from(0.70))]));
        assert_eq!(
            contributor_names(&[&coarse, &specific]),
            vec!["platform", "tenancy"],
            "both writers show up even when specific wholly overrides coarse",
        );
        // Compose retains only the specific value on the shared key.
        assert_eq!(
            compose(&[&coarse, &specific]).get("setpoint"),
            Some(&Value::from(0.70)),
        );
    }

    // -------- nonempty_layer_dicts --------

    #[test]
    fn nonempty_layer_dicts_filters_empty_layers_and_carries_the_dicts() {
        // The middle axis is undetectable ⇒ invisible on the pair
        // projection just as it is invisible in the composed dict; the
        // surviving pairs carry each contributor's discover() output
        // byte-identically (no pre-merge, no filtering of inner keys).
        let a_dict = dict(&[("k", Value::from(1i64)), ("side", Value::from("A"))]);
        let c_dict = dict(&[("k", Value::from(2i64))]);
        let a = Fixed("platform", a_dict.clone());
        let b = Fixed("undetectable", Dict::new());
        let c = Fixed("tenancy", c_dict.clone());
        assert_eq!(
            nonempty_layer_dicts(&[&a, &b, &c]),
            vec![("platform", a_dict), ("tenancy", c_dict)],
        );
    }

    #[test]
    fn nonempty_layer_dicts_preserves_application_order() {
        // Order is caller-declared (coarse→specific), NOT alphabetical
        // — same discipline as compose and contributor_names.
        let a = Fixed("tenancy", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("platform", dict(&[("k", Value::from(2i64))]));
        let names: Vec<&'static str> = nonempty_layer_dicts(&[&a, &b])
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(names, vec!["tenancy", "platform"]);
    }

    #[test]
    fn nonempty_layer_dicts_empty_when_no_layers() {
        assert!(nonempty_layer_dicts(&[]).is_empty());
    }

    #[test]
    fn nonempty_layer_dicts_empty_when_all_layers_undetectable() {
        let a = Fixed("a", Dict::new());
        let b = Fixed("b", Dict::new());
        assert!(nonempty_layer_dicts(&[&a, &b]).is_empty());
    }

    #[test]
    fn nonempty_layer_dicts_projects_to_contributor_names() {
        // The (name → contributor?) projection factors through the root
        // primitive: consumers that want just the names can derive them
        // from this call and skip a second discover() sweep.
        let a = Fixed("platform", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("undetectable", Dict::new());
        let c = Fixed("tenancy", dict(&[("k", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        let derived: Vec<&'static str> = nonempty_layer_dicts(&layers)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(derived, contributor_names(&layers));
    }

    #[test]
    fn nonempty_layer_dicts_projects_to_compose_via_deep_merge() {
        // The (name → merged-dict) projection also factors through the
        // root primitive: consumers that want compose() can fold
        // deep_merge over the pairs and get the same merged dict.
        let coarse = Fixed(
            "platform",
            dict(&[
                ("setpoint", Value::from(0.80)),
                ("floor", Value::from("256Mi")),
            ]),
        );
        let mid = Fixed("undetectable", Dict::new());
        let specific = Fixed("tenancy", dict(&[("setpoint", Value::from(0.70))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &mid, &specific];
        let mut derived = Dict::new();
        for (_, d) in nonempty_layer_dicts(&layers) {
            deep_merge(&mut derived, d);
        }
        assert_eq!(derived, compose(&layers), "fold(deep_merge) == compose");
        assert_eq!(derived.get("setpoint"), Some(&Value::from(0.70)));
        assert_eq!(derived.get("floor"), Some(&Value::from("256Mi")));
    }

    #[test]
    fn nonempty_layer_dicts_length_equals_contributor_names_length() {
        // The compact scalar projection ("how many axes contributed?")
        // is `.len()` on the same primitive — no separate contributor_count
        // pass required.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", Dict::new());
        let c = Fixed("c", dict(&[("k", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(
            nonempty_layer_dicts(&layers).len(),
            contributor_names(&layers).len()
        );
    }

    #[test]
    fn nonempty_layer_dicts_carries_overridden_writers_dicts_unchanged() {
        // "had an opinion" semantics on the dict axis: a coarse writer
        // whose key is later overridden still shows up with its
        // pre-merge dict verbatim. The pair projection reports the
        // write-set, not the surviving-leaf set, mirroring
        // contributor_names_counts_overridden_writers_too on the paired
        // seam.
        let coarse_dict = dict(&[("setpoint", Value::from(0.80))]);
        let specific_dict = dict(&[("setpoint", Value::from(0.70))]);
        let coarse = Fixed("platform", coarse_dict.clone());
        let specific = Fixed("tenancy", specific_dict.clone());
        assert_eq!(
            nonempty_layer_dicts(&[&coarse, &specific]),
            vec![("platform", coarse_dict), ("tenancy", specific_dict)],
        );
    }

    // -------- LayerAttribution::surviving_layer_names --------

    #[test]
    fn surviving_layer_names_lists_layers_with_live_leaves() {
        // Two distinct writers, four leaves — the compact name-set
        // projection lists both, in lex order on layer name.
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.surviving_layer_names(),
            vec!["platform", "tenancy"],
            "both writers survive; result sorted lex on layer name",
        );
    }

    #[test]
    fn surviving_layer_names_lex_order_regardless_of_application_order() {
        // Application order is [Z, A]; the compact projection is lex
        // on layer name (BTreeSet iteration), matching
        // `writes_by_layer` and `leaf_counts_by_layer`, NOT the
        // application-order discipline `contributor_names` upholds.
        let a = Fixed("Z", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "A",
            dict(&[
                ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
                ("m", Value::from(3i64)),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.surviving_layer_names(),
            vec!["A", "Z"],
            "lex order, not application order",
        );
    }

    #[test]
    fn surviving_layer_names_drops_wholly_overridden_writer() {
        // Layer `coarse` writes `{setpoint: 0.80}`; layer `specific`
        // writes `{setpoint: 0.70}` at the same leaf. The compose
        // primitive overwrites the `["setpoint"]` attribution — no
        // live leaf remains attributed to `coarse`, so it drops out
        // of the surviving name-set. `contributor_names` still
        // reports both writers on the pre-merge axis.
        let coarse = Fixed("coarse", dict(&[("setpoint", Value::from(0.80))]));
        let specific = Fixed("specific", dict(&[("setpoint", Value::from(0.70))]));
        let out = compose_with_provenance(&[&coarse, &specific]);
        assert_eq!(
            out.attribution.surviving_layer_names(),
            vec!["specific"],
            "wholly-overridden writer drops off the surviving axis",
        );
        // Pre-merge dual: both writers had an opinion.
        assert_eq!(
            contributor_names(&[&coarse, &specific]),
            vec!["coarse", "specific"],
            "pre-merge contributor_names still lists the overridden writer",
        );
    }

    #[test]
    fn surviving_layer_names_drops_writer_purged_by_dict_over_scalar() {
        // Cross-shape reshape: layer A writes a scalar at `x`; layer
        // B replaces it with a dict `{x.y}`. `compose_with_provenance`
        // purges the stale `["x"]` attribution and re-attributes
        // `["x", "y"]` to B. A has no live leaves, so it drops out.
        let a = Fixed("first", dict(&[("x", Value::from(1i64))]));
        let b = Fixed(
            "second",
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.surviving_layer_names(),
            vec!["second"],
            "dict-over-scalar reshape purges A's only leaf",
        );
    }

    #[test]
    fn surviving_layer_names_empty_when_no_leaves() {
        // No layers ⇒ empty attribution ⇒ empty name-set.
        let empty = compose_with_provenance(&[]);
        assert!(empty.attribution.surviving_layer_names().is_empty());
        // All layers empty ⇒ same result on a non-degenerate stack.
        let a_empty = Fixed("a", Dict::new());
        let b_empty = Fixed("b", Dict::new());
        let out = compose_with_provenance(&[&a_empty, &b_empty]);
        assert!(
            out.attribution.surviving_layer_names().is_empty(),
            "empty-only stack ⇒ no surviving writers",
        );
    }

    #[test]
    fn surviving_layer_names_agrees_with_writes_by_layer_keys() {
        // Cross-projection identity on the outer-key axis: the
        // compact name-set equals `writes_by_layer().into_keys()`
        // verbatim, and its length equals `writes_by_layer().len()`.
        let a = Fixed("Z", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "A",
            dict(&[
                ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
                ("m", Value::from(3i64)),
            ]),
        );
        let c = Fixed("M", dict(&[("q", Value::from(4i64))]));
        let out = compose_with_provenance(&[&a, &b, &c]);
        let via_wide: Vec<&'static str> = out.attribution.writes_by_layer().into_keys().collect();
        assert_eq!(
            out.attribution.surviving_layer_names(),
            via_wide,
            "compact and wide seams share the outer key set verbatim",
        );
        assert_eq!(
            out.attribution.surviving_layer_names().len(),
            out.attribution.writes_by_layer().len(),
        );
    }

    #[test]
    fn surviving_layer_names_agrees_with_leaf_counts_by_layer_keys() {
        // Cross-projection identity on the outer-key axis vs the
        // count seam: the compact name-set equals
        // `leaf_counts_by_layer().into_keys()` verbatim.
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let via_counts: Vec<&'static str> =
            out.attribution.leaf_counts_by_layer().into_keys().collect();
        assert_eq!(
            out.attribution.surviving_layer_names(),
            via_counts,
            "compact and count seams share the outer key set verbatim",
        );
        assert_eq!(
            out.attribution.surviving_layer_names().len(),
            out.attribution.leaf_counts_by_layer().len(),
        );
    }

    #[test]
    fn surviving_layer_names_subset_of_contributor_names() {
        // Subset invariant on the writer-name axis:
        //   surviving ⊆ contributors ⊆ layer_names
        // Strict subset when at least one contributor is wholly
        // overridden (here: `coarse` gets clobbered at the only key
        // it wrote), which pins the `<` direction of the chain.
        let coarse = Fixed("coarse", dict(&[("setpoint", Value::from(0.80))]));
        let specific = Fixed("specific", dict(&[("setpoint", Value::from(0.70))]));
        let empty = Fixed("undetectable", Dict::new());
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &specific, &empty];

        let all: std::collections::BTreeSet<_> = layer_names(&layers).into_iter().collect();
        let contribs: std::collections::BTreeSet<_> =
            contributor_names(&layers).into_iter().collect();
        let survivors: std::collections::BTreeSet<_> = compose_with_provenance(&layers)
            .attribution
            .surviving_layer_names()
            .into_iter()
            .collect();
        assert!(survivors.is_subset(&contribs), "survivors ⊆ contributors");
        assert!(contribs.is_subset(&all), "contributors ⊆ declared names");
        assert!(
            survivors.len() < contribs.len(),
            "coarse wholly overridden ⇒ strict subset on this fixture",
        );
        assert!(
            contribs.len() < all.len(),
            "the undetectable layer is filtered from contributors but not from declared names",
        );
    }

    #[test]
    fn surviving_layer_names_coincides_with_contributor_names_when_no_writer_overridden() {
        // Distinct top-level keys per writer ⇒ nothing purged ⇒
        // survivors = contributors (as sets). The chain's equality
        // case, complementing the strict-subset test above.
        let a = Fixed("A", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("B", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("C", dict(&[("k3", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        let contribs: std::collections::BTreeSet<_> =
            contributor_names(&layers).into_iter().collect();
        let survivors: std::collections::BTreeSet<_> = compose_with_provenance(&layers)
            .attribution
            .surviving_layer_names()
            .into_iter()
            .collect();
        assert_eq!(
            survivors, contribs,
            "no writer overridden ⇒ survivors and contributors agree as sets",
        );
    }

    // -------- silent_layer_names --------

    #[test]
    fn silent_layer_names_lists_axes_that_returned_empty_dicts() {
        // The middle and last axes are undetectable ⇒ they show up on
        // the silent projection while the first shows up on the
        // contributor one — the two together cover the declared set.
        let a = Fixed("platform", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("undetectable", Dict::new());
        let c = Fixed("also-empty", Dict::new());
        assert_eq!(
            silent_layer_names(&[&a, &b, &c]),
            vec!["undetectable", "also-empty"],
        );
    }

    #[test]
    fn silent_layer_names_preserves_application_order() {
        // Order is application order (coarse→specific), mirroring
        // `contributor_names` and `layer_names` on the same axis —
        // NOT alphabetical.
        let a = Fixed("tenancy", Dict::new());
        let b = Fixed("platform", Dict::new());
        assert_eq!(silent_layer_names(&[&a, &b]), vec!["tenancy", "platform"]);
    }

    #[test]
    fn silent_layer_names_empty_when_every_layer_contributes() {
        // Every axis wrote something ⇒ the silent projection is empty
        // (the complementary edge of the disjoint partition).
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        assert!(silent_layer_names(&[&a, &b]).is_empty());
    }

    #[test]
    fn silent_layer_names_empty_when_no_layers() {
        assert!(silent_layer_names(&[]).is_empty());
    }

    #[test]
    fn silent_layer_names_covers_layer_names_when_all_undetectable() {
        // Every axis returned an empty dict ⇒ the silent projection
        // equals `layer_names` verbatim.
        let a = Fixed("a", Dict::new());
        let b = Fixed("b", Dict::new());
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert_eq!(silent_layer_names(&layers), layer_names(&layers));
    }

    #[test]
    fn silent_layer_names_is_subset_of_layer_names() {
        // Subset invariant on the (name → silent?) axis: every silent
        // name is one of the declared layer names.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", Dict::new());
        let c = Fixed("c", Dict::new());
        let all: std::collections::BTreeSet<_> = layer_names(&[&a, &b, &c]).into_iter().collect();
        let silent: std::collections::BTreeSet<_> =
            silent_layer_names(&[&a, &b, &c]).into_iter().collect();
        assert!(silent.is_subset(&all), "silent ⊆ declared names");
        assert_eq!(silent.len(), 2, "two undetectable axes");
    }

    #[test]
    fn silent_layer_names_disjoint_from_contributor_names() {
        // Disjointness law: no name can appear in both projections
        // (a single boolean predicate on `discover().is_empty()`
        // splits the stack).
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", Dict::new());
        let c = Fixed("c", dict(&[("k", Value::from(2i64))]));
        let d = Fixed("d", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &d];
        let contribs: std::collections::BTreeSet<_> =
            contributor_names(&layers).into_iter().collect();
        let silent: std::collections::BTreeSet<_> =
            silent_layer_names(&layers).into_iter().collect();
        assert!(
            contribs.is_disjoint(&silent),
            "contributor and silent projections share no elements",
        );
    }

    #[test]
    fn silent_layer_names_partitions_layer_names_disjointly() {
        // Partition law: `silent ∪ contributors == layer_names` as
        // sets, and the two are disjoint (checked separately). The
        // union covers every declared name, and the sum of the two
        // lengths equals `layer_names.len()` when all names are
        // distinct.
        let a = Fixed("platform", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("undetectable", Dict::new());
        let c = Fixed("tenancy", dict(&[("k", Value::from(2i64))]));
        let d = Fixed("also-empty", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &d];

        let all: std::collections::BTreeSet<_> = layer_names(&layers).into_iter().collect();
        let contribs: std::collections::BTreeSet<_> =
            contributor_names(&layers).into_iter().collect();
        let silent: std::collections::BTreeSet<_> =
            silent_layer_names(&layers).into_iter().collect();

        let union: std::collections::BTreeSet<_> = contribs.union(&silent).copied().collect();
        assert_eq!(union, all, "contributors ∪ silent == declared names");
        assert!(contribs.is_disjoint(&silent), "contributors ∩ silent == ∅",);
        assert_eq!(
            contribs.len() + silent.len(),
            layer_names(&layers).len(),
            "distinct names ⇒ length sum matches",
        );
    }

    #[test]
    fn silent_layer_names_agrees_with_layer_names_minus_contributor_names() {
        // The projection factors through the set difference: silent =
        // layer_names - contributor_names (as sets), even though the
        // Vec forms preserve application order rather than lex order.
        // This is the compact, single-pass computation of the
        // complement.
        let a = Fixed("z-first", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("m-empty", Dict::new());
        let c = Fixed("a-third", dict(&[("k", Value::from(2i64))]));
        let d = Fixed("q-empty", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &d];

        let all: std::collections::BTreeSet<_> = layer_names(&layers).into_iter().collect();
        let contribs: std::collections::BTreeSet<_> =
            contributor_names(&layers).into_iter().collect();
        let silent: std::collections::BTreeSet<_> =
            silent_layer_names(&layers).into_iter().collect();
        let derived: std::collections::BTreeSet<_> = all.difference(&contribs).copied().collect();
        assert_eq!(silent, derived, "silent == layer_names − contributors");
    }

    #[test]
    fn silent_layer_names_disjoint_from_surviving_layer_names() {
        // Cross-projection disjointness: a silent axis has no leaves,
        // so it cannot appear on the post-merge surviving-writer axis
        // either. `silent ∩ surviving == ∅` for every fixture — the
        // silent set is bounded away from *both* pre-merge and
        // post-merge writer projections.
        let coarse = Fixed("coarse", dict(&[("setpoint", Value::from(0.80))]));
        let specific = Fixed("specific", dict(&[("setpoint", Value::from(0.70))]));
        let empty = Fixed("undetectable", Dict::new());
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &specific, &empty];
        let silent: std::collections::BTreeSet<_> =
            silent_layer_names(&layers).into_iter().collect();
        let survivors: std::collections::BTreeSet<_> = compose_with_provenance(&layers)
            .attribution
            .surviving_layer_names()
            .into_iter()
            .collect();
        assert!(
            silent.is_disjoint(&survivors),
            "silent axes cannot survive the merge (they wrote nothing)",
        );
        assert_eq!(silent, std::collections::BTreeSet::from(["undetectable"]));
        assert_eq!(survivors, std::collections::BTreeSet::from(["specific"]));
    }

    #[test]
    fn subtree_leaf_counts_by_layer_empty_prefix_equals_leaf_counts_by_layer() {
        // `prefix = &[]` matches every entry; the direct primitive
        // must equal the top-level histogram verbatim on every input
        // (same lex order on layer name, same counter values).
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_leaf_counts_by_layer(&[]),
            out.attribution.leaf_counts_by_layer(),
        );
    }

    #[test]
    fn subtree_leaf_counts_by_layer_at_named_prefix_counts_only_leaves_under_it() {
        // Under `breathe.*`, `coarse` wrote `mode` (1 leaf) and
        // `specific` wrote `setpoint` (1 leaf) — both credited once
        // in the subtree histogram. `alpha` (`coarse`) and `breatheZ`
        // (`specific`) live outside the subtree and do NOT bump the
        // per-writer counters — the direct primitive counts only
        // leaves whose path descends from (or equals) the prefix.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
        assert_eq!(counts.get("coarse").copied(), Some(1));
        assert_eq!(counts.get("specific").copied(), Some(1));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn subtree_leaf_counts_by_layer_agrees_with_subtree_leaf_counts_by_layer() {
        // The cross-projection identity: the direct primitive equals
        // `subtree(prefix).leaf_counts_by_layer()` verbatim on every
        // input — root, named, exact-leaf, and absent prefixes each
        // pin one arm of the equivalence.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            assert_eq!(
                out.attribution.subtree_leaf_counts_by_layer(&prefix),
                out.attribution.subtree(&prefix).leaf_counts_by_layer(),
                "direct vs composition must agree at prefix {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_leaf_counts_by_layer_absent_prefix_is_empty() {
        // A prefix naming no subtree ⇒ `subtree_iter` yields nothing
        // ⇒ no counter is ever incremented ⇒ the histogram is the
        // empty map. Mirrors `subtree_iter_empty_when_prefix_names_no_subtree`
        // and `subtree_surviving_layer_names_absent_prefix_is_empty`.
        let out = subtree_fixture();
        assert!(
            out.attribution
                .subtree_leaf_counts_by_layer(&[s("nonexistent")])
                .is_empty(),
        );
    }

    #[test]
    fn subtree_leaf_counts_by_layer_at_exact_scalar_leaf_counts_one() {
        // Reflexive case: `path_has_prefix(&["alpha"], &["alpha"])` is
        // true (a path prefixes itself), so a prefix that exactly names
        // a scalar leaf yields that leaf's writer with count 1.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        let counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
        assert_eq!(counts.get("coarse").copied(), Some(1));
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn subtree_leaf_counts_by_layer_stops_at_prefix_extending_sibling_key() {
        // The take_while boundary inherited from `subtree_iter`:
        // `["breatheZ"]` (written by `specific`) is lex-adjacent to
        // `["breathe", ...]` and its string starts with "breathe", but
        // it is NOT a path descendant of the prefix `["breathe"]`. So
        // `specific`'s bucket under the subtree carries only the one
        // leaf it actually wrote there (`setpoint`), not the extra
        // sibling. And the parent's histogram DOES credit `specific`
        // with two leaves — one under the subtree, one outside.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub_counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
        let parent_counts = out.attribution.leaf_counts_by_layer();
        assert_eq!(sub_counts.get("specific").copied(), Some(1));
        assert_eq!(parent_counts.get("specific").copied(), Some(2));
    }

    #[test]
    fn subtree_leaf_counts_by_layer_partition_count_law() {
        // The sum of the histogram's values equals the number of
        // leaves under the subtree (i.e. `subtree_iter(prefix).count()`
        // and `subtree(prefix).len()`) — the per-layer histogram
        // partitions the subtree's leaf set by winning layer.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
            let sum: usize = counts.values().copied().sum();
            let subtree_len = out.attribution.subtree(&prefix).len();
            assert_eq!(
                sum, subtree_len,
                "partition-count law failed at prefix {prefix:?}",
            );
            assert_eq!(
                sum,
                out.attribution.subtree_iter(&prefix).count(),
                "sum must equal subtree_iter count at prefix {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_leaf_counts_by_layer_keys_equal_subtree_surviving_layer_names() {
        // The three subtree-restricted seams — the compact name-set,
        // the count histogram, and the fully-composed writes_by_layer
        // — share their outer key column. This cross-projection
        // identity pins the key set of the histogram against the
        // compact name-set primitive at multiple prefixes.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let via_counts: Vec<&'static str> = out
                .attribution
                .subtree_leaf_counts_by_layer(&prefix)
                .into_keys()
                .collect();
            let via_names = out.attribution.subtree_surviving_layer_names(&prefix);
            assert_eq!(
                via_counts, via_names,
                "histogram key set must equal name-set at prefix {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_leaf_counts_by_layer_is_leq_leaf_counts_by_layer_pointwise() {
        // Subset invariant vs. the top-level histogram: for every
        // prefix and every writer w, the subtree's per-writer count is
        // <= the parent's per-writer count. A subtree can only credit a
        // writer with a subset of the leaves the parent credits it
        // with. Strict `<` iff `w` wrote at least one leaf outside the
        // subtree — pinned separately on `specific` under
        // `breathe.*` (2 parent, 1 sub).
        let out = subtree_fixture();
        let parent_counts = out.attribution.leaf_counts_by_layer();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let sub_counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
            for (layer, sub_count) in &sub_counts {
                let parent_count = parent_counts
                    .get(layer)
                    .copied()
                    .expect("every subtree layer appears in the parent");
                assert!(
                    *sub_count <= parent_count,
                    "sub-count for {layer} at {prefix:?} ({sub_count}) must not exceed parent count ({parent_count})",
                );
            }
        }
    }

    /// Small helper: materialize a `BTreeMap<&'static str, Vec<&[String]>>`
    /// as a `BTreeMap<&'static str, Vec<Vec<String>>>` so nested-borrow
    /// buckets from two different `LayerAttribution` values (the direct
    /// primitive and the `subtree(prefix).writes_by_layer()`
    /// composition, each with its own lifetime) can be compared as
    /// owned values.
    fn own_writes(
        writes: BTreeMap<&'static str, Vec<&[String]>>,
    ) -> BTreeMap<&'static str, Vec<Vec<String>>> {
        writes
            .into_iter()
            .map(|(layer, paths)| (layer, paths.into_iter().map(<[String]>::to_vec).collect()))
            .collect()
    }

    #[test]
    fn subtree_writes_by_layer_empty_prefix_equals_writes_by_layer() {
        // `prefix = &[]` matches every entry; the direct primitive
        // must equal the top-level wide seam verbatim (same lex order
        // on layer name, same per-writer path lists, same lex order
        // within each bucket).
        let out = subtree_fixture();
        assert_eq!(
            own_writes(out.attribution.subtree_writes_by_layer(&[])),
            own_writes(out.attribution.writes_by_layer()),
        );
    }

    #[test]
    fn subtree_writes_by_layer_at_named_prefix_lists_paths_under_it() {
        // Under `breathe.*`, `coarse` wrote `["breathe", "mode"]` and
        // `specific` wrote `["breathe", "setpoint"]` — both credited
        // once in the subtree's wide seam. `alpha` (`coarse`) and
        // `breatheZ` (`specific`) live outside the subtree and do NOT
        // appear in the subtree's per-writer path lists.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
        assert_eq!(
            writes.get("coarse"),
            Some(&vec![vec![s("breathe"), s("mode")]]),
        );
        assert_eq!(
            writes.get("specific"),
            Some(&vec![vec![s("breathe"), s("setpoint")]]),
        );
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn subtree_writes_by_layer_agrees_with_subtree_writes_by_layer_composition() {
        // The cross-projection identity: the direct primitive equals
        // `subtree(prefix).writes_by_layer()` verbatim on every input
        // — root, named, exact-leaf, and absent prefixes each pin one
        // arm of the equivalence. Ownership normalization is required
        // because the direct primitive's paths borrow from `self` while
        // the composition's paths borrow from the freshly materialized
        // subtree; the underlying dotted components are pointwise
        // equal.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let sub = out.attribution.subtree(&prefix);
            assert_eq!(
                own_writes(out.attribution.subtree_writes_by_layer(&prefix)),
                own_writes(sub.writes_by_layer()),
                "direct vs composition must agree at prefix {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_writes_by_layer_absent_prefix_is_empty() {
        // A prefix naming no subtree ⇒ `subtree_iter` yields nothing
        // ⇒ no bucket is ever created ⇒ the map is empty. Mirrors
        // `subtree_iter_empty_when_prefix_names_no_subtree` and the
        // absent-prefix corners on the name-set and count seams.
        let out = subtree_fixture();
        assert!(
            out.attribution
                .subtree_writes_by_layer(&[s("nonexistent")])
                .is_empty(),
        );
    }

    #[test]
    fn subtree_writes_by_layer_at_exact_scalar_leaf_yields_that_path_only() {
        // Reflexive case: `path_has_prefix(&["alpha"], &["alpha"])` is
        // true, so a prefix that exactly names a scalar leaf yields
        // that leaf's writer's bucket carrying just that one path.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        let writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
        assert_eq!(writes.get("coarse"), Some(&vec![vec![s("alpha")]]));
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn subtree_writes_by_layer_stops_at_prefix_extending_sibling_key() {
        // The take_while boundary inherited from `subtree_iter`:
        // `["breatheZ"]` (written by `specific`) is lex-adjacent to
        // `["breathe", ...]` and its string starts with "breathe", but
        // it is NOT a path descendant of the prefix `["breathe"]`. So
        // `specific`'s bucket under the subtree carries only the one
        // path it actually wrote there (`["breathe", "setpoint"]`),
        // not the extra sibling — while the parent's wide seam DOES
        // include `["breatheZ"]` in `specific`'s bucket.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub_writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
        let parent_writes = own_writes(out.attribution.writes_by_layer());
        assert_eq!(
            sub_writes.get("specific"),
            Some(&vec![vec![s("breathe"), s("setpoint")]]),
        );
        let parent_specific = parent_writes
            .get("specific")
            .expect("specific wrote at least one leaf globally");
        assert!(
            parent_specific.contains(&vec![s("breatheZ")]),
            "the excluded sibling IS in the parent's bucket",
        );
        assert!(
            !sub_writes
                .get("specific")
                .expect("specific wrote a leaf under the subtree")
                .contains(&vec![s("breatheZ")]),
            "the excluded sibling is NOT in the subtree's bucket",
        );
    }

    #[test]
    fn subtree_writes_by_layer_partition_law() {
        // The sum of every inner Vec::len equals the number of leaves
        // under the subtree (i.e. `subtree_iter(prefix).count()` and
        // `subtree(prefix).len()`), and the union of every inner Vec
        // equals `subtree_iter(prefix).map(|(p, _)| p)` verbatim as a
        // multiset — the per-writer path lists partition the subtree's
        // leaf set by winning layer.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
            let sum: usize = writes.values().map(Vec::len).sum();
            let subtree_len = out.attribution.subtree(&prefix).len();
            assert_eq!(
                sum, subtree_len,
                "partition law failed at prefix {prefix:?}",
            );
            assert_eq!(
                sum,
                out.attribution.subtree_iter(&prefix).count(),
                "sum must equal subtree_iter count at prefix {prefix:?}",
            );
            let mut union_paths: Vec<Vec<String>> =
                writes.values().flat_map(|v| v.iter().cloned()).collect();
            union_paths.sort();
            let mut walk_paths: Vec<Vec<String>> = out
                .attribution
                .subtree_iter(&prefix)
                .map(|(p, _)| p.to_vec())
                .collect();
            walk_paths.sort();
            assert_eq!(
                union_paths, walk_paths,
                "union of inner Vecs must equal subtree_iter's path multiset at {prefix:?}",
            );
        }
    }

    #[test]
    fn subtree_writes_by_layer_keys_and_bucket_lengths_agree_with_peers() {
        // The three subtree-restricted seams share their outer key
        // column, and the wide seam's per-writer bucket length equals
        // the count seam's per-writer counter at every layer. This
        // pins the "same partition, three projections" invariant
        // across the whole subtree ladder.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
            let via_keys: Vec<&'static str> = writes.keys().copied().collect();
            let via_names = out.attribution.subtree_surviving_layer_names(&prefix);
            assert_eq!(
                via_keys, via_names,
                "wide seam key set must equal name-set at prefix {prefix:?}",
            );
            let counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
            for (layer, paths) in &writes {
                assert_eq!(
                    counts.get(layer).copied(),
                    Some(paths.len()),
                    "wide-seam bucket len must equal count-seam counter for {layer} at {prefix:?}",
                );
            }
        }
    }

    #[test]
    fn subtree_writes_by_layer_is_subsequence_of_writes_by_layer_pointwise() {
        // Subset invariant vs. the top-level wide seam: for every
        // prefix and every writer w, the subtree's per-writer path
        // list is a subsequence of the parent's (both are lex-ordered
        // by path, so subset ⇒ subsequence via BTreeMap iteration
        // order). Strict subsequence iff w wrote at least one leaf
        // outside the subtree — pinned on `specific` under `breathe.*`
        // (1 sub path vs 2 parent paths).
        let out = subtree_fixture();
        let parent_writes = own_writes(out.attribution.writes_by_layer());
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let sub_writes = own_writes(out.attribution.subtree_writes_by_layer(&prefix));
            for (layer, sub_paths) in &sub_writes {
                let parent_paths = parent_writes
                    .get(layer)
                    .expect("every subtree layer appears in the parent");
                assert!(
                    sub_paths.len() <= parent_paths.len(),
                    "sub-bucket length for {layer} at {prefix:?} exceeds parent",
                );
                for path in sub_paths {
                    assert!(
                        parent_paths.contains(path),
                        "sub path {path:?} for {layer} at {prefix:?} missing from parent bucket",
                    );
                    assert_eq!(
                        out.attribution.layer_of_owned(path),
                        Some(*layer),
                        "sub-bucket path {path:?} must attribute to {layer} on the parent",
                    );
                }
            }
        }
        let specific_sub = own_writes(out.attribution.subtree_writes_by_layer(&[s("breathe")]))
            .remove("specific")
            .expect("specific wrote under `breathe`");
        let specific_parent = own_writes(out.attribution.writes_by_layer())
            .remove("specific")
            .expect("specific wrote globally");
        assert!(
            specific_sub.len() < specific_parent.len(),
            "strict subsequence pinned on `specific` under `breathe.*` (sub {} < parent {})",
            specific_sub.len(),
            specific_parent.len(),
        );
    }

    // -------- LayerAttribution::writes_of_layer / leaf_count_of_layer --------

    /// Two-layer fixture that spans both single-write and
    /// override-and-siblings shapes: `platform` wrote only `k1` (the
    /// override-loser at `k2` is purged) and `tenancy` wrote `k2`
    /// (overriding) plus `k3`. Reused by the layer-axis single-writer
    /// tests below so lex order and per-writer counts are pinned
    /// against a shared shape.
    fn layer_axis_fixture() -> DiscoveryComposition {
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        compose_with_provenance(&[&a, &b])
    }

    #[test]
    fn writes_of_layer_agrees_with_writes_by_layer_bucket() {
        // The cross-projection identity from the rustdoc: the
        // single-layer wide seam equals the per-writer bucket of the
        // multi-layer seam verbatim on every input.
        let out = layer_axis_fixture();
        let groups = out.attribution.writes_by_layer();
        for layer in out.attribution.surviving_layer_names() {
            let single: Vec<&[String]> = out.attribution.writes_of_layer(layer);
            let bucket: Vec<&[String]> = groups.get(layer).cloned().unwrap_or_default();
            assert_eq!(
                single, bucket,
                "single-layer wide seam equals writes_by_layer[{layer}] verbatim",
            );
        }
    }

    #[test]
    fn writes_of_layer_preserves_lex_order() {
        // The axis-restricted result lands in the same lex order
        // `iter()` emits: filtering the value column out of the
        // BTreeMap iteration preserves the underlying key order.
        let a = Fixed(
            "A",
            dict(&[
                ("m", Value::from(3i64)),
                ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
            ]),
        );
        let b = Fixed("Z", dict(&[("z", Value::from(1i64))]));
        let out = compose_with_provenance(&[&a, &b]);
        // A's leaves in the underlying BTreeMap lex order: ["a","y"] < ["m"].
        let a_paths = out.attribution.writes_of_layer("A");
        assert_eq!(
            a_paths,
            vec![
                ["a".to_owned(), "y".to_owned()].as_slice(),
                ["m".to_owned()].as_slice(),
            ],
            "single-layer wide seam preserves lex path order",
        );
        // Every returned path attributes back to the same writer.
        for path in &a_paths {
            let owned: Vec<String> = path.iter().map(std::borrow::ToOwned::to_owned).collect();
            assert_eq!(
                out.attribution.layer_of_owned(&owned),
                Some("A"),
                "every path in writes_of_layer(A) attributes to A",
            );
        }
    }

    #[test]
    fn writes_of_layer_missing_writer_is_empty() {
        // A layer name that never appears in the attribution yields
        // the empty vector — whether because it was never declared,
        // was declared but silent, or was declared and had every
        // write overridden.
        let real = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&real, &silent]);
        assert!(
            out.attribution.writes_of_layer("undetectable").is_empty(),
            "silent writer yields empty writes",
        );
        assert!(
            out.attribution.writes_of_layer("never-declared").is_empty(),
            "never-declared writer yields empty writes",
        );
    }

    #[test]
    fn writes_of_layer_empty_attribution_is_empty() {
        let out = compose_with_provenance(&[]);
        assert!(
            out.attribution.writes_of_layer("anything").is_empty(),
            "empty attribution yields empty writes for any writer",
        );
    }

    #[test]
    fn leaf_count_of_layer_agrees_with_leaf_counts_by_layer_bucket() {
        // The cross-projection identity from the rustdoc: the
        // single-layer count seam equals the per-writer counter of
        // the multi-layer count seam verbatim.
        let out = layer_axis_fixture();
        let counts = out.attribution.leaf_counts_by_layer();
        for layer in out.attribution.surviving_layer_names() {
            let single = out.attribution.leaf_count_of_layer(layer);
            let bucket = counts.get(layer).copied().unwrap_or(0);
            assert_eq!(
                single, bucket,
                "single-layer count seam equals leaf_counts_by_layer[{layer}] verbatim",
            );
        }
    }

    #[test]
    fn leaf_count_of_layer_agrees_with_writes_of_layer_len() {
        // The count is exactly the length of the corresponding
        // path list — the compact scalar companion to the wide seam.
        let out = layer_axis_fixture();
        for layer in out.attribution.surviving_layer_names() {
            assert_eq!(
                out.attribution.leaf_count_of_layer(layer),
                out.attribution.writes_of_layer(layer).len(),
                "leaf_count_of_layer({layer}) == writes_of_layer({layer}).len()",
            );
        }
    }

    #[test]
    fn leaf_count_of_layer_partition_count_law() {
        // Sum over every surviving writer equals the total leaf
        // count: every leaf belongs to exactly one surviving
        // writer's counter, the layer-axis dual of the path-axis
        // partition-count law on `subtree_leaf_counts_by_layer`.
        let out = layer_axis_fixture();
        let survivors = out.attribution.surviving_layer_names();
        let total: usize = survivors
            .iter()
            .map(|l| out.attribution.leaf_count_of_layer(l))
            .sum();
        assert_eq!(
            total,
            out.attribution.len(),
            "sum of per-writer counts equals total leaf count",
        );
    }

    #[test]
    fn leaf_count_of_layer_missing_writer_is_zero() {
        let real = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&real, &silent]);
        assert_eq!(
            out.attribution.leaf_count_of_layer("undetectable"),
            0,
            "silent writer yields count zero",
        );
        assert_eq!(
            out.attribution.leaf_count_of_layer("never-declared"),
            0,
            "never-declared writer yields count zero",
        );

        let empty = compose_with_provenance(&[]);
        assert_eq!(
            empty.attribution.leaf_count_of_layer("anything"),
            0,
            "empty attribution yields count zero for any writer",
        );
    }

    // -------- LayerAttribution::subtree_writes_of_layer /
    // -------- subtree_leaf_count_of_layer

    #[test]
    fn subtree_writes_of_layer_empty_prefix_equals_writes_of_layer() {
        // Empty-prefix corner: the 2D-restricted seam collapses to the
        // top-level layer-axis restriction verbatim, on both surviving
        // writers and never-declared names.
        let out = layer_axis_fixture();
        for layer in out.attribution.surviving_layer_names() {
            assert_eq!(
                out.attribution.subtree_writes_of_layer(&[], layer),
                out.attribution.writes_of_layer(layer),
                "empty prefix ⇒ subtree_writes_of_layer({layer}) equals writes_of_layer({layer})",
            );
        }
        assert!(
            out.attribution
                .subtree_writes_of_layer(&[], "never-declared")
                .is_empty(),
            "empty prefix + never-declared writer ⇒ empty",
        );
    }

    #[test]
    fn subtree_writes_of_layer_agrees_with_subtree_writes_by_layer_bucket() {
        // The cross-projection identity from the rustdoc: the
        // 2D-restricted single-writer seam equals the per-writer bucket
        // of the subtree-restricted multi-writer seam verbatim on every
        // input, across every surviving writer under the subtree.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let groups = out.attribution.subtree_writes_by_layer(&prefix);
            for layer in out.attribution.subtree_surviving_layer_names(&prefix) {
                let single: Vec<&[String]> =
                    out.attribution.subtree_writes_of_layer(&prefix, layer);
                let bucket: Vec<&[String]> = groups.get(layer).cloned().unwrap_or_default();
                assert_eq!(
                    single, bucket,
                    "single-writer seam at prefix {prefix:?} equals subtree_writes_by_layer[{layer}]",
                );
            }
        }
    }

    #[test]
    fn subtree_writes_of_layer_at_named_prefix_lists_only_this_writer_under_it() {
        // Under `breathe.*` in the subtree fixture, `coarse` wrote
        // `["breathe","mode"]` (its top-level `alpha` write sits
        // *outside* the subtree) and `specific` wrote
        // `["breathe","setpoint"]` (its `breatheZ` write is the
        // prefix-extending sibling, *outside* the subtree). Each
        // writer's 2D-restricted seam carries only the one path it
        // actually shaped under the subtree.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let coarse: Vec<Vec<String>> = out
            .attribution
            .subtree_writes_of_layer(&prefix, "coarse")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert_eq!(coarse, vec![vec![s("breathe"), s("mode")]]);
        let specific: Vec<Vec<String>> = out
            .attribution
            .subtree_writes_of_layer(&prefix, "specific")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert_eq!(specific, vec![vec![s("breathe"), s("setpoint")]]);
    }

    #[test]
    fn subtree_writes_of_layer_stops_at_prefix_extending_sibling_key() {
        // The take_while boundary inherited from `subtree_iter`:
        // `["breatheZ"]` (written by `specific`) is a top-level
        // writes_of_layer("specific") entry but is NOT a descendant of
        // `["breathe"]`. The 2D-restricted seam correctly excludes it,
        // even though the top-level `writes_of_layer("specific")` does
        // include it.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        let sub: Vec<Vec<String>> = out
            .attribution
            .subtree_writes_of_layer(&prefix, "specific")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert!(
            !sub.contains(&vec![s("breatheZ")]),
            "prefix-extending sibling is excluded from the 2D-restricted seam",
        );
        // The parent's layer-axis seam DOES carry it — this pins that
        // the exclusion is a subtree-scope decision, not a leaf that
        // was never written.
        let parent: Vec<Vec<String>> = out
            .attribution
            .writes_of_layer("specific")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert!(
            parent.contains(&vec![s("breatheZ")]),
            "the excluded sibling IS in the top-level layer-axis seam",
        );
    }

    #[test]
    fn subtree_writes_of_layer_preserves_lex_order() {
        // The 2D-restricted result lands in the same lex order
        // `subtree_iter` emits: paths under the subtree, filtered on
        // the value column, keep the underlying BTreeMap key order.
        // Compose `A` writing three leaves under `["s","a","y"]`,
        // `["s","m"]`, and `["t"]`; `B` writing `["s","p"]` (an
        // override-adjacent sibling under the same subtree). Under
        // prefix `["s"]`, A's leaves land in lex path order and B's
        // sibling does not intrude.
        let a = Fixed(
            "A",
            dict(&[
                (
                    "s",
                    Value::from(dict(&[
                        ("m", Value::from(3i64)),
                        ("a", Value::from(dict(&[("y", Value::from(2i64))]))),
                    ])),
                ),
                ("t", Value::from(4i64)),
            ]),
        );
        let b = Fixed(
            "B",
            dict(&[("s", Value::from(dict(&[("p", Value::from(9i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        let prefix = vec![s("s")];
        // Under `["s"]`, A wrote `["s","a","y"]` and `["s","m"]`; the
        // top-level `["t"]` write sits outside the subtree.
        let a_paths: Vec<Vec<String>> = out
            .attribution
            .subtree_writes_of_layer(&prefix, "A")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert_eq!(
            a_paths,
            vec![vec![s("s"), s("a"), s("y")], vec![s("s"), s("m")],],
            "2D-restricted seam preserves lex path order under the subtree",
        );
        // Every returned path attributes back to A on the parent.
        for path in &a_paths {
            assert_eq!(
                out.attribution.layer_of_owned(path),
                Some("A"),
                "every path attributes to A on the parent",
            );
        }
    }

    #[test]
    fn subtree_writes_of_layer_absent_prefix_is_empty() {
        // A prefix naming no subtree ⇒ `subtree_iter` yields nothing
        // ⇒ every writer's 2D-restricted seam is empty. Mirrors the
        // absent-prefix corners on the multi-writer subtree seams.
        let out = subtree_fixture();
        for layer in ["coarse", "specific", "never-declared"] {
            assert!(
                out.attribution
                    .subtree_writes_of_layer(&[s("nonexistent")], layer)
                    .is_empty(),
                "absent prefix ⇒ subtree_writes_of_layer({layer}) is empty",
            );
        }
    }

    #[test]
    fn subtree_writes_of_layer_missing_writer_is_empty() {
        // A layer that never wrote under the subtree yields the empty
        // vector — whether it wrote elsewhere, was silent globally, or
        // was never declared.
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        assert!(
            out.attribution
                .subtree_writes_of_layer(&prefix, "never-declared")
                .is_empty(),
        );
        // `alpha` is a `coarse` leaf outside the subtree; a fresh
        // three-layer fixture pins a writer that wrote *elsewhere*
        // but nothing under the queried subtree.
        let elsewhere = Fixed("elsewhere", dict(&[("outside", Value::from(1i64))]));
        let under = Fixed(
            "under",
            dict(&[("root", Value::from(dict(&[("leaf", Value::from(2i64))])))]),
        );
        let out2 = compose_with_provenance(&[&elsewhere, &under]);
        assert!(
            out2.attribution
                .subtree_writes_of_layer(&[s("root")], "elsewhere")
                .is_empty(),
            "writer active elsewhere but silent under the subtree ⇒ empty",
        );
    }

    #[test]
    fn subtree_leaf_count_of_layer_empty_prefix_equals_leaf_count_of_layer() {
        let out = layer_axis_fixture();
        for layer in out.attribution.surviving_layer_names() {
            assert_eq!(
                out.attribution.subtree_leaf_count_of_layer(&[], layer),
                out.attribution.leaf_count_of_layer(layer),
                "empty prefix ⇒ subtree_leaf_count_of_layer({layer}) equals leaf_count_of_layer({layer})",
            );
        }
        assert_eq!(
            out.attribution
                .subtree_leaf_count_of_layer(&[], "never-declared"),
            0,
            "empty prefix + never-declared writer ⇒ zero",
        );
    }

    #[test]
    fn subtree_leaf_count_of_layer_agrees_with_subtree_writes_of_layer_len() {
        // The count seam matches the length of the wide seam across
        // every (prefix, layer) — compact scalar companion pinned.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            for layer in ["coarse", "specific", "never-declared"] {
                assert_eq!(
                    out.attribution.subtree_leaf_count_of_layer(&prefix, layer),
                    out.attribution
                        .subtree_writes_of_layer(&prefix, layer)
                        .len(),
                    "count seam == wide seam length at prefix {prefix:?} × layer {layer}",
                );
            }
        }
    }

    #[test]
    fn subtree_leaf_count_of_layer_agrees_with_subtree_leaf_counts_by_layer_bucket() {
        // Cross-projection identity vs the multi-writer count seam at
        // the same altitude: the 2D-restricted single-writer count
        // equals the per-writer counter of `subtree_leaf_counts_by_layer`
        // verbatim on every input.
        let out = subtree_fixture();
        for prefix in [
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("nonexistent")],
        ] {
            let counts = out.attribution.subtree_leaf_counts_by_layer(&prefix);
            for layer in out.attribution.subtree_surviving_layer_names(&prefix) {
                let single = out.attribution.subtree_leaf_count_of_layer(&prefix, layer);
                let bucket = counts.get(layer).copied().unwrap_or(0);
                assert_eq!(
                    single, bucket,
                    "single-writer count at prefix {prefix:?} equals subtree_leaf_counts_by_layer[{layer}]",
                );
            }
        }
    }

    #[test]
    fn subtree_leaf_count_of_layer_partition_count_law() {
        // Sum over every surviving writer under the subtree equals the
        // subtree's total leaf count: every subtree leaf belongs to
        // exactly one surviving writer's counter — the 2D-restricted
        // dual of the top-level layer-axis partition-count law.
        let out = subtree_fixture();
        for prefix in [vec![], vec![s("breathe")], vec![s("alpha")]] {
            let survivors = out.attribution.subtree_surviving_layer_names(&prefix);
            let total: usize = survivors
                .iter()
                .map(|l| out.attribution.subtree_leaf_count_of_layer(&prefix, l))
                .sum();
            let expected = out.attribution.subtree_iter(&prefix).count();
            assert_eq!(
                total, expected,
                "sum of per-writer counts at prefix {prefix:?} equals subtree leaf count",
            );
        }
    }

    #[test]
    fn subtree_leaf_count_of_layer_absent_prefix_is_zero() {
        let out = subtree_fixture();
        for layer in ["coarse", "specific", "never-declared"] {
            assert_eq!(
                out.attribution
                    .subtree_leaf_count_of_layer(&[s("nonexistent")], layer),
                0,
                "absent prefix ⇒ zero for every writer ({layer})",
            );
        }
    }

    #[test]
    fn subtree_leaf_count_of_layer_missing_writer_is_zero() {
        let out = subtree_fixture();
        let prefix = vec![s("breathe")];
        assert_eq!(
            out.attribution
                .subtree_leaf_count_of_layer(&prefix, "never-declared"),
            0,
            "never-declared writer under a real subtree ⇒ zero",
        );

        let empty = compose_with_provenance(&[]);
        assert_eq!(
            empty
                .attribution
                .subtree_leaf_count_of_layer(&[s("anything")], "anyone"),
            0,
            "empty attribution ⇒ zero for every (prefix, writer)",
        );
    }

    #[test]
    fn subtree_leaf_count_of_layer_is_leq_leaf_count_of_layer_pointwise() {
        // The 2D-restricted count is bounded above by the top-level
        // layer-axis count for the same writer: a subtree can only
        // credit a writer with a subset of the leaves the parent
        // credits it with. Pinned across every (prefix, layer) with
        // strict inequality when the writer wrote leaves outside the
        // subtree.
        let out = subtree_fixture();
        for prefix in [vec![], vec![s("breathe")], vec![s("alpha")]] {
            for layer in ["coarse", "specific"] {
                let sub = out.attribution.subtree_leaf_count_of_layer(&prefix, layer);
                let parent = out.attribution.leaf_count_of_layer(layer);
                assert!(
                    sub <= parent,
                    "sub count for {layer} at prefix {prefix:?} ({sub}) must not exceed parent count ({parent})",
                );
            }
        }
        // Strict `<` when the writer has leaves outside the subtree:
        // under `["breathe"]`, `coarse` wrote only `breathe.mode`
        // (1 leaf) but globally wrote `alpha` too (2 leaves); the
        // sub-count is strictly less than the parent count.
        let strict_prefix = vec![s("breathe")];
        assert!(
            out.attribution
                .subtree_leaf_count_of_layer(&strict_prefix, "coarse")
                < out.attribution.leaf_count_of_layer("coarse"),
            "strict inequality when coarse wrote leaves outside `breathe.*`",
        );
    }

    #[test]
    fn subtree_writes_of_layer_at_exact_scalar_leaf_yields_that_leaf_only() {
        // Reflexive case: a prefix that exactly names a scalar leaf
        // resolves to that leaf alone for its writer, and empty for
        // every other writer.
        let out = subtree_fixture();
        let prefix = vec![s("alpha")];
        let coarse: Vec<Vec<String>> = out
            .attribution
            .subtree_writes_of_layer(&prefix, "coarse")
            .into_iter()
            .map(<[String]>::to_vec)
            .collect();
        assert_eq!(coarse, vec![vec![s("alpha")]]);
        assert!(
            out.attribution
                .subtree_writes_of_layer(&prefix, "specific")
                .is_empty(),
            "the leaf's non-writer gets no bucket at the exact-leaf prefix",
        );
        assert_eq!(
            out.attribution
                .subtree_leaf_count_of_layer(&prefix, "coarse"),
            1,
            "the leaf's writer gets count 1 at the exact-leaf prefix",
        );
        assert_eq!(
            out.attribution
                .subtree_leaf_count_of_layer(&prefix, "specific"),
            0,
            "non-writer's count at the exact-leaf prefix is zero",
        );
    }

    // -------- LayerAttribution::dominant_layer /
    // -------- subtree_dominant_layer

    /// Deterministic tie-break fixture: three single-leaf writers with
    /// names `aaa`, `bbb`, `ccc` at disjoint top-level keys. Every
    /// writer has count 1, so both `dominant_layer` and every
    /// `subtree_dominant_layer` call under a subtree that catches
    /// multiple writers must break by ascending lex name.
    fn three_way_tie_fixture() -> DiscoveryComposition {
        let a = Fixed("aaa", dict(&[("ka", Value::from(1i64))]));
        let b = Fixed("bbb", dict(&[("kb", Value::from(2i64))]));
        let c = Fixed("ccc", dict(&[("kc", Value::from(3i64))]));
        compose_with_provenance(&[&a, &b, &c])
    }

    /// Global-vs-subtree inversion fixture: writer `coarse` wins the
    /// top-level count (four leaves) but writer `specific` wins under
    /// the `["small"]` subtree (two leaves vs one). Exercises the
    /// non-trivial cell where `subtree_dominant_layer` disagrees with
    /// `dominant_layer`.
    fn inversion_fixture() -> DiscoveryComposition {
        let coarse = Fixed(
            "coarse",
            dict(&[
                (
                    "big",
                    Value::from(dict(&[
                        ("a", Value::from(1i64)),
                        ("b", Value::from(2i64)),
                        ("c", Value::from(3i64)),
                    ])),
                ),
                ("small", Value::from(dict(&[("x", Value::from(4i64))]))),
            ]),
        );
        let specific = Fixed(
            "specific",
            dict(&[(
                "small",
                Value::from(dict(&[("y", Value::from(5i64)), ("z", Value::from(6i64))])),
            )]),
        );
        compose_with_provenance(&[&coarse, &specific])
    }

    #[test]
    fn dominant_layer_agrees_with_leaf_counts_argmax() {
        // Cross-projection identity from the rustdoc: the scalar
        // single-writer argmax equals the argmax of `leaf_counts_by_layer`
        // verbatim. On layer_axis_fixture (platform: 1 leaf, tenancy:
        // 2 leaves), the top writer is "tenancy" with count 2 = max.
        let out = layer_axis_fixture();
        let dominant = out.attribution.dominant_layer().expect("non-empty");
        assert_eq!(dominant, "tenancy", "tenancy owns 2 leaves > platform's 1");
        let counts = out.attribution.leaf_counts_by_layer();
        let max_count = counts.values().copied().max().expect("non-empty");
        assert_eq!(
            counts.get(dominant).copied().unwrap_or(0),
            max_count,
            "dominant writer's count equals the max of leaf_counts_by_layer",
        );
        assert_eq!(
            out.attribution.leaf_count_of_layer(dominant),
            max_count,
            "leaf_count_of_layer(dominant) also equals the max",
        );
    }

    #[test]
    fn dominant_layer_ties_broken_by_lex_name_ascending() {
        // Three-way tie fixture: aaa, bbb, ccc all at count 1. The
        // smallest lex name wins deterministically — the same order
        // every other `BTreeMap<&'static str, _>` seam iterates.
        let out = three_way_tie_fixture();
        assert_eq!(
            out.attribution.dominant_layer(),
            Some("aaa"),
            "on a three-way tie, the smallest lex name wins",
        );
    }

    #[test]
    fn dominant_layer_empty_attribution_is_none() {
        let empty = compose_with_provenance(&[]);
        assert_eq!(
            empty.attribution.dominant_layer(),
            None,
            "empty attribution ⇒ no dominant layer",
        );
        // Also on a stack of empty-dict layers — every writer is
        // silent, so the attribution is empty.
        let silent = Fixed("silent-a", Dict::new());
        let more_silent = Fixed("silent-b", Dict::new());
        let silent_out = compose_with_provenance(&[&silent, &more_silent]);
        assert_eq!(
            silent_out.attribution.dominant_layer(),
            None,
            "silent-only stack ⇒ no dominant layer",
        );
    }

    #[test]
    fn dominant_layer_single_writer_is_that_writer() {
        // One live writer ⇒ dominant_layer returns that writer's
        // name regardless of leaf count.
        let solo = Fixed(
            "solo",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let silent = Fixed("silent", Dict::new());
        let out = compose_with_provenance(&[&solo, &silent]);
        assert_eq!(
            out.attribution.dominant_layer(),
            Some("solo"),
            "the only surviving writer is the dominant one",
        );
    }

    #[test]
    fn dominant_layer_is_member_of_surviving_layer_names() {
        // The rustdoc invariant: whenever `dominant_layer` returns
        // `Some(name)`, `name` is in `surviving_layer_names`. Across
        // every non-empty fixture in the cohort.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            if let Some(dominant) = out.attribution.dominant_layer() {
                assert!(
                    out.attribution.surviving_layer_names().contains(&dominant),
                    "dominant_layer must be a member of surviving_layer_names",
                );
            }
        }
    }

    #[test]
    fn subtree_dominant_layer_empty_prefix_equals_dominant_layer() {
        // Empty-prefix corner from the rustdoc: the subtree-restricted
        // scalar collapses to the top-level scalar verbatim across
        // every fixture — non-empty and empty alike.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.subtree_dominant_layer(&[]),
                out.attribution.dominant_layer(),
                "empty prefix ⇒ subtree_dominant_layer equals dominant_layer",
            );
        }
    }

    #[test]
    fn subtree_dominant_layer_at_named_prefix_narrows_the_argmax() {
        // Under subtree_fixture's `["breathe"]`: coarse:1, specific:1
        // ⇒ tie ⇒ "coarse" (lex ascending). Under `["alpha"]`:
        // coarse:1 alone ⇒ "coarse".
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_dominant_layer(&[s("breathe")]),
            Some("coarse"),
            "under breathe.*, coarse and specific tie at 1 leaf each — coarse wins by lex",
        );
        assert_eq!(
            out.attribution.subtree_dominant_layer(&[s("alpha")]),
            Some("coarse"),
            "under alpha (a leaf), coarse alone is dominant",
        );
    }

    #[test]
    fn subtree_dominant_layer_absent_prefix_is_none() {
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_dominant_layer(&[s("nonexistent")]),
            None,
            "absent prefix ⇒ empty subtree ⇒ None",
        );
    }

    #[test]
    fn subtree_dominant_layer_agrees_with_argmax_of_subtree_counts() {
        // Cross-projection identity across every prefix on every
        // fixture: the scalar single-writer argmax equals the argmax
        // of `subtree_leaf_counts_by_layer` verbatim, and the winning
        // count equals `subtree_leaf_count_of_layer(prefix, winner)`.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [subtree_fixture(), inversion_fixture(), layer_axis_fixture()] {
            for prefix in &prefixes {
                let counts = out.attribution.subtree_leaf_counts_by_layer(prefix);
                let dominant = out.attribution.subtree_dominant_layer(prefix);
                if let Some(name) = dominant {
                    let max_count = counts.values().copied().max().unwrap_or(0);
                    assert_eq!(
                        counts.get(name).copied().unwrap_or(0),
                        max_count,
                        "at prefix {prefix:?}, dominant {name}'s subtree count equals the max",
                    );
                    assert_eq!(
                        out.attribution.subtree_leaf_count_of_layer(prefix, name),
                        max_count,
                        "at prefix {prefix:?}, subtree_leaf_count_of_layer({name}) also equals the max",
                    );
                    // And the winner is the smallest lex name among tied maxima.
                    let tied_at_max: Vec<&'static str> = counts
                        .iter()
                        .filter_map(|(k, v)| (*v == max_count).then_some(*k))
                        .collect();
                    assert_eq!(
                        tied_at_max.first().copied(),
                        Some(name),
                        "the winner is the smallest lex name among tied maxima",
                    );
                } else {
                    assert!(
                        counts.is_empty(),
                        "None ⇒ empty subtree_leaf_counts_by_layer at prefix {prefix:?}",
                    );
                    assert_eq!(
                        out.attribution.subtree_iter(prefix).count(),
                        0,
                        "None ⇒ empty subtree_iter at prefix {prefix:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_dominant_layer_is_member_of_subtree_surviving_layer_names_when_some() {
        // The rustdoc invariant: whenever `subtree_dominant_layer`
        // returns `Some(name)`, `name` is in
        // `subtree_surviving_layer_names(prefix)`. Across every prefix
        // on every fixture.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [subtree_fixture(), inversion_fixture(), layer_axis_fixture()] {
            for prefix in &prefixes {
                if let Some(dominant) = out.attribution.subtree_dominant_layer(prefix) {
                    assert!(
                        out.attribution
                            .subtree_surviving_layer_names(prefix)
                            .contains(&dominant),
                        "at prefix {prefix:?}, dominant {dominant} must be in subtree_surviving_layer_names",
                    );
                    // And still in the top-level surviving set — the
                    // subtree cannot pick a writer that never wrote.
                    assert!(
                        out.attribution.surviving_layer_names().contains(&dominant),
                        "at prefix {prefix:?}, dominant {dominant} must be in surviving_layer_names",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_dominant_layer_can_differ_from_dominant_layer() {
        // The non-trivial cell: a writer that loses the top-level
        // argmax can still win under a subtree it owns locally.
        // inversion_fixture: coarse has 4 leaves globally (big.a,
        // big.b, big.c, small.x), specific has 2 (small.y, small.z);
        // under `["small"]`, coarse has 1 (small.x) and specific has
        // 2 (small.y, small.z) — argmax flips.
        let out = inversion_fixture();
        assert_eq!(
            out.attribution.dominant_layer(),
            Some("coarse"),
            "coarse owns the top-level argmax (4 leaves)",
        );
        assert_eq!(
            out.attribution.subtree_dominant_layer(&[s("small")]),
            Some("specific"),
            "specific owns the ['small'] subtree (2 leaves vs coarse's 1)",
        );
        // And the two globally-dominant subtree the writer keeps: `big`.
        assert_eq!(
            out.attribution.subtree_dominant_layer(&[s("big")]),
            Some("coarse"),
            "coarse still owns the ['big'] subtree (3 leaves vs specific's 0)",
        );
    }

    #[test]
    fn layer_ranking_agrees_with_leaf_counts_by_layer() {
        // Cross-projection identity from the rustdoc: every
        // `(layer, count)` entry in the ranking matches the histogram
        // and `leaf_count_of_layer` verbatim, on every fixture.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            let ranking = out.attribution.layer_ranking();
            let counts = out.attribution.leaf_counts_by_layer();
            for (name, count) in &ranking {
                assert_eq!(
                    counts.get(name).copied(),
                    Some(*count),
                    "ranking entry ({name}, {count}) must match leaf_counts_by_layer",
                );
                assert_eq!(
                    out.attribution.leaf_count_of_layer(name),
                    *count,
                    "ranking entry ({name}, {count}) must match leaf_count_of_layer",
                );
            }
            // And the ranking's name-set equals leaf_counts_by_layer's
            // key-set verbatim (as a set).
            let ranking_names: std::collections::BTreeSet<&'static str> =
                ranking.iter().map(|(n, _)| *n).collect();
            let counts_names: std::collections::BTreeSet<&'static str> =
                counts.into_keys().collect();
            assert_eq!(
                ranking_names, counts_names,
                "ranking names ≡ leaf_counts_by_layer keys (as a set)",
            );
        }
    }

    #[test]
    fn layer_ranking_len_equals_surviving_layer_names_len() {
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.layer_ranking().len(),
                out.attribution.surviving_layer_names().len(),
                "|layer_ranking| = |surviving_layer_names|",
            );
            assert_eq!(
                out.attribution.layer_ranking().len(),
                out.attribution.leaf_counts_by_layer().len(),
                "|layer_ranking| = |leaf_counts_by_layer|",
            );
        }
    }

    #[test]
    fn layer_ranking_counts_sum_to_len() {
        // Partition-count law: the sum of every paired count equals
        // the total leaf count (every leaf belongs to exactly one
        // surviving writer's bucket).
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let sum: usize = out.attribution.layer_ranking().iter().map(|(_, c)| c).sum();
            assert_eq!(sum, out.attribution.len(), "Σ counts = attribution.len()");
        }
    }

    #[test]
    fn layer_ranking_empty_iff_attribution_is_empty() {
        // An empty attribution has an empty ranking; a non-empty
        // attribution has a non-empty ranking.
        assert!(
            compose_with_provenance(&[])
                .attribution
                .layer_ranking()
                .is_empty(),
            "empty attribution ⇒ empty ranking",
        );
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            assert!(
                !out.attribution.layer_ranking().is_empty(),
                "non-empty attribution ⇒ non-empty ranking",
            );
        }
    }

    #[test]
    fn layer_ranking_first_equals_dominant_layer() {
        // Argmax law: the top of the ranking is the scalar argmax
        // verbatim, across every fixture.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let ranking_first: Option<&'static str> =
                out.attribution.layer_ranking().first().map(|(n, _)| *n);
            assert_eq!(
                ranking_first,
                out.attribution.dominant_layer(),
                "ranking.first().name ≡ dominant_layer()",
            );
        }
    }

    #[test]
    fn layer_ranking_counts_are_non_increasing() {
        // Ordering contract: counts descend monotonically along the
        // vector — every adjacent pair satisfies prev >= next.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            let ranking = out.attribution.layer_ranking();
            for window in ranking.windows(2) {
                assert!(
                    window[0].1 >= window[1].1,
                    "counts must be non-increasing: {} !>= {}",
                    window[0].1,
                    window[1].1,
                );
            }
        }
    }

    #[test]
    fn layer_ranking_ties_are_lex_ascending() {
        // Within any tied run of counts, names are strictly increasing.
        // The three_way_tie_fixture puts aaa/bbb/ccc all at count 1 —
        // ranking must emit them in lex-ascending order.
        let out = three_way_tie_fixture();
        assert_eq!(
            out.attribution.layer_ranking(),
            vec![("aaa", 1), ("bbb", 1), ("ccc", 1)],
            "three-way tie orders by lex ascending",
        );
        // General invariant: for every adjacent pair with equal
        // counts, the earlier name is lex-smaller.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            let ranking = out.attribution.layer_ranking();
            for window in ranking.windows(2) {
                if window[0].1 == window[1].1 {
                    assert!(
                        window[0].0 < window[1].0,
                        "tied names must be lex-ascending: {} !< {}",
                        window[0].0,
                        window[1].0,
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_layer_ranking_empty_prefix_equals_layer_ranking() {
        // Empty-prefix corner: the subtree-restricted ranking collapses
        // to the top-level ranking verbatim across every fixture.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.subtree_layer_ranking(&[]),
                out.attribution.layer_ranking(),
                "empty prefix ⇒ subtree_layer_ranking equals layer_ranking",
            );
        }
    }

    #[test]
    fn subtree_layer_ranking_absent_prefix_is_empty() {
        let out = subtree_fixture();
        assert!(
            out.attribution
                .subtree_layer_ranking(&[s("nonexistent")])
                .is_empty(),
            "absent prefix ⇒ empty subtree ⇒ empty ranking",
        );
    }

    #[test]
    fn subtree_layer_ranking_first_equals_subtree_dominant_layer() {
        // Argmax law at the subtree altitude: the top of the ranking
        // is the scalar argmax verbatim, across every fixture and every
        // prefix — non-empty and empty subtrees alike.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let ranking_first: Option<&'static str> = out
                    .attribution
                    .subtree_layer_ranking(prefix)
                    .first()
                    .map(|(n, _)| *n);
                assert_eq!(
                    ranking_first,
                    out.attribution.subtree_dominant_layer(prefix),
                    "at prefix {prefix:?}, subtree ranking.first().name ≡ subtree_dominant_layer",
                );
            }
        }
    }

    #[test]
    fn subtree_layer_ranking_agrees_with_subtree_leaf_counts() {
        // Cross-projection identity across every prefix on every fixture:
        // every `(layer, count)` entry matches the subtree histogram and
        // subtree_leaf_count_of_layer verbatim; the counts sum to
        // subtree_iter(prefix).count(); the name-set equals
        // subtree_surviving_layer_names verbatim.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [subtree_fixture(), inversion_fixture(), layer_axis_fixture()] {
            for prefix in &prefixes {
                let ranking = out.attribution.subtree_layer_ranking(prefix);
                let counts = out.attribution.subtree_leaf_counts_by_layer(prefix);
                let sum: usize = ranking.iter().map(|(_, c)| c).sum();
                assert_eq!(
                    sum,
                    out.attribution.subtree_iter(prefix).count(),
                    "at prefix {prefix:?}, Σ counts = subtree_iter count",
                );
                for (name, count) in &ranking {
                    assert_eq!(
                        counts.get(name).copied(),
                        Some(*count),
                        "at prefix {prefix:?}, ranking entry ({name}, {count}) matches subtree_leaf_counts_by_layer",
                    );
                    assert_eq!(
                        out.attribution.subtree_leaf_count_of_layer(prefix, name),
                        *count,
                        "at prefix {prefix:?}, ranking entry ({name}, {count}) matches subtree_leaf_count_of_layer",
                    );
                }
                let ranking_names: std::collections::BTreeSet<&'static str> =
                    ranking.iter().map(|(n, _)| *n).collect();
                let survivor_names: std::collections::BTreeSet<&'static str> = out
                    .attribution
                    .subtree_surviving_layer_names(prefix)
                    .into_iter()
                    .collect();
                assert_eq!(
                    ranking_names, survivor_names,
                    "at prefix {prefix:?}, ranking names ≡ subtree_surviving_layer_names (as a set)",
                );
            }
        }
    }

    #[test]
    fn subtree_layer_ranking_counts_are_non_increasing_and_ties_lex_ascending() {
        // Ordering contract at subtree altitude.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let ranking = out.attribution.subtree_layer_ranking(prefix);
                for window in ranking.windows(2) {
                    assert!(
                        window[0].1 >= window[1].1,
                        "at prefix {prefix:?}, counts non-increasing: {} !>= {}",
                        window[0].1,
                        window[1].1,
                    );
                    if window[0].1 == window[1].1 {
                        assert!(
                            window[0].0 < window[1].0,
                            "at prefix {prefix:?}, tied names lex-ascending: {} !< {}",
                            window[0].0,
                            window[1].0,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn subtree_layer_ranking_narrows_at_named_prefix() {
        // Concrete inspection at the non-trivial cell: on
        // inversion_fixture, `["small"]` puts specific (2 leaves) above
        // coarse (1 leaf); `["big"]` has only coarse (3 leaves).
        let out = inversion_fixture();
        assert_eq!(
            out.attribution.subtree_layer_ranking(&[s("small")]),
            vec![("specific", 2), ("coarse", 1)],
            "under small.*, specific tops the ranking (2 vs 1)",
        );
        assert_eq!(
            out.attribution.subtree_layer_ranking(&[s("big")]),
            vec![("coarse", 3)],
            "under big.*, only coarse contributes (3 leaves)",
        );
    }

    #[test]
    fn subtree_layer_ranking_name_set_subset_of_surviving_layer_names() {
        // Subset invariant: subtree ranking cannot pick a name that
        // never wrote anywhere globally.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [subtree_fixture(), inversion_fixture(), layer_axis_fixture()] {
            let global: std::collections::BTreeSet<&'static str> = out
                .attribution
                .surviving_layer_names()
                .into_iter()
                .collect();
            for prefix in &prefixes {
                let ranking = out.attribution.subtree_layer_ranking(prefix);
                for (name, count) in &ranking {
                    assert!(
                        global.contains(name),
                        "at prefix {prefix:?}, subtree ranking name {name} must survive globally",
                    );
                    assert!(
                        *count <= out.attribution.leaf_count_of_layer(name),
                        "at prefix {prefix:?}, subtree count {count} ≤ global {} for {name}",
                        out.attribution.leaf_count_of_layer(name),
                    );
                }
            }
        }
    }

    // -------- weakest_layer / subtree_weakest_layer

    #[test]
    fn weakest_layer_agrees_with_leaf_counts_argmin() {
        // Cross-projection identity: the scalar argmin equals the
        // argmin of `leaf_counts_by_layer`. On layer_axis_fixture
        // (platform: 1 leaf, tenancy: 2 leaves), the weakest is
        // "platform" with count 1 = min.
        let out = layer_axis_fixture();
        let weakest = out.attribution.weakest_layer().expect("non-empty");
        assert_eq!(weakest, "platform", "platform owns 1 leaf < tenancy's 2");
        let counts = out.attribution.leaf_counts_by_layer();
        let min_count = counts.values().copied().min().expect("non-empty");
        assert_eq!(
            counts.get(weakest).copied().unwrap_or(0),
            min_count,
            "weakest writer's count equals the min of leaf_counts_by_layer",
        );
        assert_eq!(
            out.attribution.leaf_count_of_layer(weakest),
            min_count,
            "leaf_count_of_layer(weakest) also equals the min",
        );
    }

    #[test]
    fn weakest_layer_ties_broken_by_lex_name_descending() {
        // Three-way tie fixture: aaa, bbb, ccc all at count 1. The
        // largest lex name wins deterministically — the same endpoint
        // `layer_ranking().last()` names.
        let out = three_way_tie_fixture();
        assert_eq!(
            out.attribution.weakest_layer(),
            Some("ccc"),
            "on a three-way tie, the largest lex name wins the argmin",
        );
    }

    #[test]
    fn weakest_layer_empty_attribution_is_none() {
        // Empty attribution ⇒ no writers ⇒ no weakest layer.
        let empty = compose_with_provenance(&[]);
        assert_eq!(empty.attribution.weakest_layer(), None);
        // Silent-only stack — every writer emitted an empty dict, so
        // the attribution is empty.
        let silent = Fixed("silent-a", Dict::new());
        let more_silent = Fixed("silent-b", Dict::new());
        let silent_out = compose_with_provenance(&[&silent, &more_silent]);
        assert_eq!(silent_out.attribution.weakest_layer(), None);
    }

    #[test]
    fn weakest_layer_single_writer_is_that_writer() {
        // One live writer ⇒ that writer is both the dominant and the
        // weakest — the ranking is a single row.
        let solo = Fixed(
            "solo",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let silent = Fixed("silent", Dict::new());
        let out = compose_with_provenance(&[&solo, &silent]);
        assert_eq!(out.attribution.weakest_layer(), Some("solo"));
        assert_eq!(
            out.attribution.weakest_layer(),
            out.attribution.dominant_layer(),
            "single-writer bookend collapse",
        );
    }

    #[test]
    fn weakest_layer_is_member_of_surviving_layer_names() {
        // Rustdoc invariant across every non-empty fixture: whenever
        // `weakest_layer` returns `Some(name)`, `name` is in
        // `surviving_layer_names`.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            if let Some(weakest) = out.attribution.weakest_layer() {
                assert!(
                    out.attribution.surviving_layer_names().contains(&weakest),
                    "weakest_layer must be a member of surviving_layer_names",
                );
            }
        }
    }

    #[test]
    fn weakest_layer_equals_layer_ranking_last() {
        // Endpoint identity: the argmin equals the last entry of the
        // sorted-by-dominance view verbatim, across every fixture.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let ranking_last: Option<&'static str> =
                out.attribution.layer_ranking().last().map(|(n, _)| *n);
            assert_eq!(
                ranking_last,
                out.attribution.weakest_layer(),
                "ranking.last().name ≡ weakest_layer()",
            );
        }
    }

    #[test]
    fn weakest_layer_equals_dominant_layer_on_single_writer_or_flat() {
        // Bookend law: `weakest_layer == dominant_layer` iff the
        // ranking is flat (every surviving writer has the same count).
        // Solo writer ⇒ trivially flat ⇒ they coincide.
        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let out = compose_with_provenance(&[&solo]);
        assert_eq!(
            out.attribution.weakest_layer(),
            out.attribution.dominant_layer(),
            "single-writer ⇒ bookends coincide",
        );
        // Three-way tie ⇒ flat ranking at count 1 ⇒ bookends differ
        // (dominant picks smallest lex, weakest picks largest).
        let tied = three_way_tie_fixture();
        assert_ne!(
            tied.attribution.weakest_layer(),
            tied.attribution.dominant_layer(),
            "flat but multi-writer ⇒ bookends disagree by tie-break rule",
        );
        assert_eq!(tied.attribution.dominant_layer(), Some("aaa"));
        assert_eq!(tied.attribution.weakest_layer(), Some("ccc"));
        // Distinct counts ⇒ bookends differ.
        let axis = layer_axis_fixture();
        assert_ne!(
            axis.attribution.weakest_layer(),
            axis.attribution.dominant_layer(),
            "distinct counts ⇒ bookends differ",
        );
    }

    #[test]
    fn subtree_weakest_layer_empty_prefix_equals_weakest_layer() {
        // Empty-prefix corner: the subtree-restricted argmin collapses
        // to the top-level argmin verbatim across every fixture —
        // non-empty and empty alike.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.subtree_weakest_layer(&[]),
                out.attribution.weakest_layer(),
                "empty prefix ⇒ subtree_weakest_layer equals weakest_layer",
            );
        }
    }

    #[test]
    fn subtree_weakest_layer_at_named_prefix_narrows_the_argmin() {
        // Under subtree_fixture's `["breathe"]`: coarse:1 (mode),
        // specific:1 (setpoint) ⇒ tie ⇒ "specific" (lex descending).
        // Under `["alpha"]`: coarse:1 alone ⇒ "coarse".
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_weakest_layer(&[s("breathe")]),
            Some("specific"),
            "under breathe.*, tied at 1 leaf each — specific wins by largest lex",
        );
        assert_eq!(
            out.attribution.subtree_weakest_layer(&[s("alpha")]),
            Some("coarse"),
            "under alpha (a leaf), coarse alone is trivially weakest",
        );
        // Under inversion_fixture's `["small"]`: specific:2, coarse:1
        // ⇒ weakest is coarse.
        let inv = inversion_fixture();
        assert_eq!(
            inv.attribution.subtree_weakest_layer(&[s("small")]),
            Some("coarse"),
            "under small.*, coarse (1 leaf) is weaker than specific (2)",
        );
        assert_eq!(
            inv.attribution.subtree_weakest_layer(&[s("big")]),
            Some("coarse"),
            "under big.*, coarse alone is trivially weakest",
        );
    }

    #[test]
    fn subtree_weakest_layer_absent_prefix_is_none() {
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_weakest_layer(&[s("nonexistent")]),
            None,
            "absent prefix ⇒ empty subtree ⇒ None",
        );
    }

    #[test]
    fn subtree_weakest_layer_agrees_with_argmin_of_subtree_counts() {
        // Cross-projection identity across every prefix on every
        // fixture: when `Some(name)`, `name`'s subtree count equals
        // the min of `subtree_leaf_counts_by_layer`, and `name` is
        // the last (largest-lex) entry among writers tied at that min.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let weakest = out.attribution.subtree_weakest_layer(prefix);
                let counts = out.attribution.subtree_leaf_counts_by_layer(prefix);
                if let Some(name) = weakest {
                    let min_count = counts
                        .values()
                        .copied()
                        .min()
                        .expect("non-empty subtree ⇒ non-empty counter map");
                    assert_eq!(
                        counts.get(name).copied(),
                        Some(min_count),
                        "at prefix {prefix:?}, weakest {name} owns the min count",
                    );
                    assert_eq!(
                        out.attribution.subtree_leaf_count_of_layer(prefix, name),
                        min_count,
                        "at prefix {prefix:?}, subtree_leaf_count_of_layer({name}) equals the min",
                    );
                    // Tie-break: among writers at the min count,
                    // `name` is the largest lex.
                    let tied_at_min: Vec<&'static str> = counts
                        .iter()
                        .filter_map(|(n, c)| (*c == min_count).then_some(*n))
                        .collect();
                    assert_eq!(
                        tied_at_min.last().copied(),
                        Some(name),
                        "at prefix {prefix:?}, weakest picks the largest lex name among tied minima",
                    );
                } else {
                    assert!(
                        counts.is_empty(),
                        "at prefix {prefix:?}, None ⇒ counter map is empty",
                    );
                    assert_eq!(
                        out.attribution.subtree_iter(prefix).count(),
                        0,
                        "at prefix {prefix:?}, None ⇒ subtree_iter is empty",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_weakest_layer_is_member_of_subtree_surviving_layer_names_when_some() {
        // Two subset invariants across every prefix on every fixture:
        // the returned name lives in the subtree's surviving names AND
        // in the top-level surviving names (the subtree cannot pick a
        // writer that never wrote anywhere).
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            let global: std::collections::BTreeSet<&'static str> = out
                .attribution
                .surviving_layer_names()
                .into_iter()
                .collect();
            for prefix in &prefixes {
                if let Some(weakest) = out.attribution.subtree_weakest_layer(prefix) {
                    let subtree_set: std::collections::BTreeSet<&'static str> = out
                        .attribution
                        .subtree_surviving_layer_names(prefix)
                        .into_iter()
                        .collect();
                    assert!(
                        subtree_set.contains(weakest),
                        "at prefix {prefix:?}, weakest {weakest} lives in subtree_surviving_layer_names",
                    );
                    assert!(
                        global.contains(weakest),
                        "at prefix {prefix:?}, weakest {weakest} lives in the global surviving set",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_weakest_layer_equals_subtree_layer_ranking_last() {
        // Endpoint identity at the subtree altitude: the argmin equals
        // the last entry of the subtree sorted-by-dominance view
        // verbatim, across every fixture and every prefix.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let ranking_last: Option<&'static str> = out
                    .attribution
                    .subtree_layer_ranking(prefix)
                    .last()
                    .map(|(n, _)| *n);
                assert_eq!(
                    ranking_last,
                    out.attribution.subtree_weakest_layer(prefix),
                    "at prefix {prefix:?}, subtree ranking.last().name ≡ subtree_weakest_layer",
                );
            }
        }
    }

    #[test]
    fn subtree_weakest_layer_can_differ_from_weakest_layer() {
        // The non-trivial cell: the top-level weakest differs from a
        // subtree weakest. On inversion_fixture, the top-level weakest
        // is "specific" (2 leaves) — but under `["big"]`, "specific"
        // wrote nothing, so the local weakest is "coarse".
        let out = inversion_fixture();
        assert_eq!(out.attribution.weakest_layer(), Some("specific"));
        assert_eq!(
            out.attribution.subtree_weakest_layer(&[s("big")]),
            Some("coarse"),
            "under big.*, specific is absent — coarse is the only (and weakest) writer",
        );
        // Under `["small"]`: specific:2, coarse:1 — the weakest flips
        // to "coarse" locally.
        assert_eq!(
            out.attribution.subtree_weakest_layer(&[s("small")]),
            Some("coarse"),
            "under small.*, coarse (1 leaf) is weaker than specific (2)",
        );
    }

    // -------- dominant_entry / subtree_dominant_entry

    #[test]
    fn dominant_entry_agrees_with_leaf_counts_argmax() {
        // The atomic row identity: on layer_axis_fixture (platform:1,
        // tenancy:2), `dominant_entry` returns Some(("tenancy", 2)) —
        // the (name, count) tuple at the argmax of leaf_counts_by_layer.
        let out = layer_axis_fixture();
        let entry = out.attribution.dominant_entry().expect("non-empty");
        assert_eq!(entry, ("tenancy", 2));
        let counts = out.attribution.leaf_counts_by_layer();
        let max_count = counts.values().copied().max().expect("non-empty");
        assert_eq!(entry.1, max_count);
        assert_eq!(counts.get(entry.0).copied(), Some(entry.1));
    }

    #[test]
    fn dominant_entry_ties_broken_by_lex_name_ascending() {
        // Three-way tie fixture: aaa/bbb/ccc all at count 1. The
        // smallest lex name wins — the entry pairs "aaa" with 1.
        let out = three_way_tie_fixture();
        assert_eq!(
            out.attribution.dominant_entry(),
            Some(("aaa", 1)),
            "on a three-way tie, smallest lex name wins with its count",
        );
    }

    #[test]
    fn dominant_entry_empty_attribution_is_none() {
        // Empty attribution and silent-only stack — no writers — both
        // yield None.
        let empty = compose_with_provenance(&[]);
        assert_eq!(empty.attribution.dominant_entry(), None);
        let silent = Fixed("silent-a", Dict::new());
        let more_silent = Fixed("silent-b", Dict::new());
        let silent_out = compose_with_provenance(&[&silent, &more_silent]);
        assert_eq!(silent_out.attribution.dominant_entry(), None);
    }

    #[test]
    fn dominant_entry_single_writer_pairs_writer_with_its_leaf_count() {
        // One live writer ⇒ entry pairs that writer's name with its
        // full leaf count.
        let solo = Fixed(
            "solo",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let silent = Fixed("silent", Dict::new());
        let out = compose_with_provenance(&[&solo, &silent]);
        assert_eq!(out.attribution.dominant_entry(), Some(("solo", 2)));
    }

    #[test]
    fn dominant_entry_equals_layer_ranking_first() {
        // Endpoint identity across every fixture: the entry is the top
        // row of the sorted-by-dominance view, extracted without
        // materializing the sort.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let via_ranking: Option<(&'static str, usize)> =
                out.attribution.layer_ranking().first().copied();
            assert_eq!(
                out.attribution.dominant_entry(),
                via_ranking,
                "dominant_entry() ≡ layer_ranking().first().copied()",
            );
        }
    }

    #[test]
    fn dominant_entry_name_projection_equals_dominant_layer() {
        // Name-axis projection: dropping the count returns the
        // pre-existing `dominant_layer` scalar verbatim, across every
        // fixture including the empty attribution.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let entry_name: Option<&'static str> = out.attribution.dominant_entry().map(|(n, _)| n);
            assert_eq!(
                entry_name,
                out.attribution.dominant_layer(),
                "dominant_entry().map(|(n, _)| n) ≡ dominant_layer()",
            );
        }
    }

    #[test]
    fn dominant_entry_count_projection_equals_leaf_counts_max() {
        // Count-axis projection: dropping the name returns the max of
        // `leaf_counts_by_layer` verbatim, or None when empty. So the
        // implicit "dominant_count" scalar is a direct projection.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let entry_count: Option<usize> = out.attribution.dominant_entry().map(|(_, c)| c);
            let max_count: Option<usize> = out
                .attribution
                .leaf_counts_by_layer()
                .values()
                .copied()
                .max();
            assert_eq!(
                entry_count, max_count,
                "dominant_entry().map(|(_, c)| c) ≡ leaf_counts_by_layer().values().max()",
            );
        }
    }

    #[test]
    fn dominant_entry_count_agrees_with_leaf_count_of_layer() {
        // Cross-projection identity: for every non-empty fixture, the
        // returned count equals `leaf_count_of_layer(name)` verbatim —
        // the entry's two axes are consistent with the single-writer
        // count seam.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            let (name, count) = out.attribution.dominant_entry().expect("non-empty fixture");
            assert_eq!(
                count,
                out.attribution.leaf_count_of_layer(name),
                "dominant_entry count ≡ leaf_count_of_layer(name)",
            );
        }
    }

    #[test]
    fn subtree_dominant_entry_empty_prefix_equals_dominant_entry() {
        // Empty-prefix corner: the subtree entry collapses to the
        // top-level entry verbatim across every fixture — including
        // the empty attribution where both return None.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.subtree_dominant_entry(&[]),
                out.attribution.dominant_entry(),
                "empty prefix ⇒ subtree_dominant_entry ≡ dominant_entry",
            );
        }
    }

    #[test]
    fn subtree_dominant_entry_at_named_prefix_narrows_the_argmax() {
        // subtree_fixture under `["breathe"]`: coarse:1 (mode),
        // specific:1 (setpoint) ⇒ tie ⇒ "coarse" (lex ascending) with
        // count 1. Under `["alpha"]`: coarse:1 alone ⇒ ("coarse", 1).
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_dominant_entry(&[s("breathe")]),
            Some(("coarse", 1)),
            "under breathe.*, tied at 1 leaf each — coarse wins by smallest lex",
        );
        assert_eq!(
            out.attribution.subtree_dominant_entry(&[s("alpha")]),
            Some(("coarse", 1)),
            "under alpha (a leaf), coarse alone owns the row",
        );
        // inversion_fixture under `["small"]`: coarse:1, specific:2 ⇒
        // ("specific", 2). Under `["big"]`: coarse:3 alone ⇒
        // ("coarse", 3).
        let inv = inversion_fixture();
        assert_eq!(
            inv.attribution.subtree_dominant_entry(&[s("small")]),
            Some(("specific", 2)),
            "under small.*, specific (2 leaves) beats coarse (1)",
        );
        assert_eq!(
            inv.attribution.subtree_dominant_entry(&[s("big")]),
            Some(("coarse", 3)),
            "under big.*, coarse alone owns the row with 3 leaves",
        );
    }

    #[test]
    fn subtree_dominant_entry_absent_prefix_is_none() {
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_dominant_entry(&[s("nonexistent")]),
            None,
            "absent prefix ⇒ empty subtree ⇒ None",
        );
    }

    #[test]
    fn subtree_dominant_entry_agrees_with_argmax_of_subtree_counts() {
        // Cross-projection identity across every prefix on every
        // fixture: when Some((name, count)), count equals the max of
        // `subtree_leaf_counts_by_layer` AND equals
        // `subtree_leaf_count_of_layer(prefix, name)`; when None, the
        // subtree is empty.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let entry = out.attribution.subtree_dominant_entry(prefix);
                let counts = out.attribution.subtree_leaf_counts_by_layer(prefix);
                if let Some((name, count)) = entry {
                    let max_count = counts
                        .values()
                        .copied()
                        .max()
                        .expect("non-empty subtree ⇒ non-empty counter map");
                    assert_eq!(
                        count, max_count,
                        "at prefix {prefix:?}, entry count equals subtree argmax",
                    );
                    assert_eq!(
                        counts.get(name).copied(),
                        Some(count),
                        "at prefix {prefix:?}, entry count equals the histogram bucket",
                    );
                    assert_eq!(
                        out.attribution.subtree_leaf_count_of_layer(prefix, name),
                        count,
                        "at prefix {prefix:?}, entry count ≡ subtree_leaf_count_of_layer",
                    );
                    // Tie-break: among writers at the max count, `name`
                    // is the smallest lex name (BTreeMap iteration is
                    // already ascending on names).
                    let tied_at_max: Vec<&'static str> = counts
                        .iter()
                        .filter_map(|(n, c)| (*c == max_count).then_some(*n))
                        .collect();
                    assert_eq!(
                        tied_at_max.first().copied(),
                        Some(name),
                        "at prefix {prefix:?}, entry picks smallest lex name among tied maxima",
                    );
                } else {
                    assert!(
                        counts.is_empty(),
                        "at prefix {prefix:?}, None ⇒ counter map is empty",
                    );
                    assert_eq!(
                        out.attribution.subtree_iter(prefix).count(),
                        0,
                        "at prefix {prefix:?}, None ⇒ subtree_iter is empty",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_dominant_entry_equals_subtree_layer_ranking_first() {
        // Endpoint identity at the subtree altitude: the entry equals
        // the first row of the subtree sorted-by-dominance view
        // verbatim, across every fixture and every prefix.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let via_ranking: Option<(&'static str, usize)> = out
                    .attribution
                    .subtree_layer_ranking(prefix)
                    .first()
                    .copied();
                assert_eq!(
                    out.attribution.subtree_dominant_entry(prefix),
                    via_ranking,
                    "at prefix {prefix:?}, subtree_dominant_entry ≡ subtree_layer_ranking.first().copied()",
                );
            }
        }
    }

    #[test]
    fn subtree_dominant_entry_projections_equal_scalars() {
        // Name-and-count decomposition at subtree altitude across every
        // prefix on every fixture:
        //   entry.map(|(n, _)| n) ≡ subtree_dominant_layer(prefix)
        //   entry.map(|(_, c)| c) ≡ subtree_leaf_counts_by_layer(prefix)
        //                              .values().max()
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
            compose_with_provenance(&[]),
        ] {
            for prefix in &prefixes {
                let entry = out.attribution.subtree_dominant_entry(prefix);
                assert_eq!(
                    entry.map(|(n, _)| n),
                    out.attribution.subtree_dominant_layer(prefix),
                    "at prefix {prefix:?}, name projection ≡ subtree_dominant_layer",
                );
                let counts_max: Option<usize> = out
                    .attribution
                    .subtree_leaf_counts_by_layer(prefix)
                    .values()
                    .copied()
                    .max();
                assert_eq!(
                    entry.map(|(_, c)| c),
                    counts_max,
                    "at prefix {prefix:?}, count projection ≡ subtree histogram max",
                );
            }
        }
    }

    #[test]
    fn subtree_dominant_entry_name_in_surviving_and_count_le_global() {
        // Two subset invariants across every prefix on every fixture:
        // when Some((name, count)), (a) `name` lives in the top-level
        // `surviving_layer_names` (the subtree cannot pick a writer that
        // never wrote anywhere), and (b) `count` ≤
        // `leaf_count_of_layer(name)` (subtree ⊆ parent).
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            let global: std::collections::BTreeSet<&'static str> = out
                .attribution
                .surviving_layer_names()
                .into_iter()
                .collect();
            for prefix in &prefixes {
                if let Some((name, count)) = out.attribution.subtree_dominant_entry(prefix) {
                    assert!(
                        global.contains(name),
                        "at prefix {prefix:?}, entry name {name} lives in the global surviving set",
                    );
                    assert!(
                        count <= out.attribution.leaf_count_of_layer(name),
                        "at prefix {prefix:?}, subtree count {count} ≤ global {} for {name}",
                        out.attribution.leaf_count_of_layer(name),
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_dominant_entry_can_differ_from_dominant_entry() {
        // The non-trivial cell: the top-level dominant entry differs
        // from a subtree dominant entry. On inversion_fixture, the top
        // entry is ("coarse", 4) — but under `["small"]`, coarse owns
        // only 1 leaf and specific owns 2, so the local entry is
        // ("specific", 2).
        let out = inversion_fixture();
        assert_eq!(out.attribution.dominant_entry(), Some(("coarse", 4)));
        assert_eq!(
            out.attribution.subtree_dominant_entry(&[s("small")]),
            Some(("specific", 2)),
            "under small.*, specific owns the top row locally",
        );
        // Under `["big"]`: coarse:3 alone ⇒ ("coarse", 3) — same name
        // but a smaller local count than the global entry's 4.
        assert_eq!(
            out.attribution.subtree_dominant_entry(&[s("big")]),
            Some(("coarse", 3)),
            "under big.*, coarse alone with 3 leaves — count narrows",
        );
    }

    // -------- weakest_entry / subtree_weakest_entry

    #[test]
    fn weakest_entry_agrees_with_leaf_counts_argmin() {
        // The atomic row identity at the bottom endpoint: on
        // layer_axis_fixture (platform:1, tenancy:2), weakest_entry
        // returns Some(("platform", 1)) — the (name, count) tuple at
        // the argmin of leaf_counts_by_layer.
        let out = layer_axis_fixture();
        let entry = out.attribution.weakest_entry().expect("non-empty");
        assert_eq!(entry, ("platform", 1));
        let counts = out.attribution.leaf_counts_by_layer();
        let min_count = counts.values().copied().min().expect("non-empty");
        assert_eq!(entry.1, min_count);
        assert_eq!(counts.get(entry.0).copied(), Some(entry.1));
    }

    #[test]
    fn weakest_entry_ties_broken_by_lex_name_descending() {
        // Three-way tie fixture: aaa/bbb/ccc all at count 1. The
        // largest lex name wins deterministically — the entry pairs
        // "ccc" with 1, matching the endpoint layer_ranking().last()
        // names.
        let out = three_way_tie_fixture();
        assert_eq!(
            out.attribution.weakest_entry(),
            Some(("ccc", 1)),
            "on a three-way tie, the largest lex name wins with its count",
        );
    }

    #[test]
    fn weakest_entry_empty_attribution_is_none() {
        // Empty attribution and silent-only stack — no writers — both
        // yield None.
        let empty = compose_with_provenance(&[]);
        assert_eq!(empty.attribution.weakest_entry(), None);
        let silent = Fixed("silent-a", Dict::new());
        let more_silent = Fixed("silent-b", Dict::new());
        let silent_out = compose_with_provenance(&[&silent, &more_silent]);
        assert_eq!(silent_out.attribution.weakest_entry(), None);
    }

    #[test]
    fn weakest_entry_single_writer_pairs_writer_with_its_leaf_count() {
        // One live writer ⇒ entry pairs that writer's name with its
        // full leaf count. The single-writer bookend collapse: the
        // weakest entry equals the dominant entry verbatim.
        let solo = Fixed(
            "solo",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let silent = Fixed("silent", Dict::new());
        let out = compose_with_provenance(&[&solo, &silent]);
        assert_eq!(out.attribution.weakest_entry(), Some(("solo", 2)));
        assert_eq!(
            out.attribution.weakest_entry(),
            out.attribution.dominant_entry(),
            "single-writer ⇒ bookend entries coincide",
        );
    }

    #[test]
    fn weakest_entry_equals_layer_ranking_last() {
        // Endpoint identity across every fixture: the entry is the
        // bottom row of the sorted-by-dominance view, extracted
        // without materializing the sort.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let via_ranking: Option<(&'static str, usize)> =
                out.attribution.layer_ranking().last().copied();
            assert_eq!(
                out.attribution.weakest_entry(),
                via_ranking,
                "weakest_entry() ≡ layer_ranking().last().copied()",
            );
        }
    }

    #[test]
    fn weakest_entry_name_projection_equals_weakest_layer() {
        // Name-axis projection: dropping the count returns the
        // pre-existing `weakest_layer` scalar verbatim, across every
        // fixture including the empty attribution.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let entry_name: Option<&'static str> = out.attribution.weakest_entry().map(|(n, _)| n);
            assert_eq!(
                entry_name,
                out.attribution.weakest_layer(),
                "weakest_entry().map(|(n, _)| n) ≡ weakest_layer()",
            );
        }
    }

    #[test]
    fn weakest_entry_count_projection_equals_leaf_counts_min() {
        // Count-axis projection: dropping the name returns the min of
        // `leaf_counts_by_layer` verbatim, or None when empty. So the
        // implicit "weakest_count" scalar is a direct projection.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            let entry_count: Option<usize> = out.attribution.weakest_entry().map(|(_, c)| c);
            let min_count: Option<usize> = out
                .attribution
                .leaf_counts_by_layer()
                .values()
                .copied()
                .min();
            assert_eq!(
                entry_count, min_count,
                "weakest_entry().map(|(_, c)| c) ≡ leaf_counts_by_layer().values().min()",
            );
        }
    }

    #[test]
    fn weakest_entry_count_agrees_with_leaf_count_of_layer() {
        // Cross-projection identity: for every non-empty fixture, the
        // returned count equals `leaf_count_of_layer(name)` verbatim —
        // the entry's two axes are consistent with the single-writer
        // count seam.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
        ] {
            let (name, count) = out.attribution.weakest_entry().expect("non-empty fixture");
            assert_eq!(
                count,
                out.attribution.leaf_count_of_layer(name),
                "weakest_entry count ≡ leaf_count_of_layer(name)",
            );
        }
    }

    #[test]
    fn weakest_entry_bookend_law_vs_dominant_entry() {
        // Bookend law: `weakest_entry == dominant_entry` iff only one
        // writer survives. On any flat multi-writer ranking, both
        // share a count but disagree on the name by the opposing
        // tie-break rules — dominant picks smallest lex, weakest
        // picks largest. On distinct-count rankings, both disagree
        // on the whole (name, count) tuple.
        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let solo_out = compose_with_provenance(&[&solo]);
        assert_eq!(
            solo_out.attribution.weakest_entry(),
            solo_out.attribution.dominant_entry(),
            "single-writer ⇒ bookend entries coincide",
        );
        // Three-way tie ⇒ flat ranking at count 1 ⇒ names differ but
        // counts agree.
        let tied = three_way_tie_fixture();
        let dom = tied.attribution.dominant_entry().expect("non-empty");
        let weak = tied.attribution.weakest_entry().expect("non-empty");
        assert_ne!(dom.0, weak.0, "flat but multi-writer ⇒ names disagree");
        assert_eq!(dom.1, weak.1, "flat ⇒ counts agree");
        assert_eq!(dom, ("aaa", 1));
        assert_eq!(weak, ("ccc", 1));
        // Distinct counts ⇒ both name and count disagree.
        let axis = layer_axis_fixture();
        assert_ne!(
            axis.attribution.weakest_entry(),
            axis.attribution.dominant_entry(),
            "distinct counts ⇒ bookend entries disagree",
        );
    }

    #[test]
    fn subtree_weakest_entry_empty_prefix_equals_weakest_entry() {
        // Empty-prefix corner: the subtree-restricted entry collapses
        // to the top-level entry verbatim across every fixture —
        // including the empty attribution where both return None.
        for out in [
            layer_axis_fixture(),
            subtree_fixture(),
            three_way_tie_fixture(),
            inversion_fixture(),
            compose_with_provenance(&[]),
        ] {
            assert_eq!(
                out.attribution.subtree_weakest_entry(&[]),
                out.attribution.weakest_entry(),
                "empty prefix ⇒ subtree_weakest_entry ≡ weakest_entry",
            );
        }
    }

    #[test]
    fn subtree_weakest_entry_at_named_prefix_narrows_the_argmin() {
        // subtree_fixture under `["breathe"]`: coarse:1 (mode),
        // specific:1 (setpoint) ⇒ tie at 1 ⇒ "specific" (lex
        // descending) with count 1. Under `["alpha"]`: coarse:1
        // alone ⇒ ("coarse", 1) — trivially weakest.
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_weakest_entry(&[s("breathe")]),
            Some(("specific", 1)),
            "under breathe.*, tied at 1 leaf each — specific wins by largest lex",
        );
        assert_eq!(
            out.attribution.subtree_weakest_entry(&[s("alpha")]),
            Some(("coarse", 1)),
            "under alpha (a leaf), coarse alone owns the row",
        );
        // inversion_fixture under `["small"]`: specific:2, coarse:1
        // ⇒ ("coarse", 1). Under `["big"]`: coarse:3 alone ⇒
        // ("coarse", 3).
        let inv = inversion_fixture();
        assert_eq!(
            inv.attribution.subtree_weakest_entry(&[s("small")]),
            Some(("coarse", 1)),
            "under small.*, coarse (1 leaf) is the weakest row",
        );
        assert_eq!(
            inv.attribution.subtree_weakest_entry(&[s("big")]),
            Some(("coarse", 3)),
            "under big.*, coarse alone owns the row with 3 leaves",
        );
    }

    #[test]
    fn subtree_weakest_entry_absent_prefix_is_none() {
        let out = subtree_fixture();
        assert_eq!(
            out.attribution.subtree_weakest_entry(&[s("nonexistent")]),
            None,
            "absent prefix ⇒ empty subtree ⇒ None",
        );
    }

    #[test]
    fn subtree_weakest_entry_agrees_with_argmin_of_subtree_counts() {
        // Cross-projection identity across every prefix on every
        // fixture: when Some((name, count)), (a) `count` equals the
        // min of `subtree_leaf_counts_by_layer`, (b) the histogram
        // bucket equals count, (c) `subtree_leaf_count_of_layer` at
        // (prefix, name) equals count, (d) `name` is the last
        // (largest-lex) entry among writers tied at that min; when
        // None, both `subtree_leaf_counts_by_layer` and
        // `subtree_iter` are empty at that prefix.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let entry = out.attribution.subtree_weakest_entry(prefix);
                let counts = out.attribution.subtree_leaf_counts_by_layer(prefix);
                if let Some((name, count)) = entry {
                    let min_count = counts
                        .values()
                        .copied()
                        .min()
                        .expect("non-empty subtree ⇒ non-empty counter map");
                    assert_eq!(
                        count, min_count,
                        "at prefix {prefix:?}, entry count equals subtree argmin",
                    );
                    assert_eq!(
                        counts.get(name).copied(),
                        Some(count),
                        "at prefix {prefix:?}, entry count equals the histogram bucket",
                    );
                    assert_eq!(
                        out.attribution.subtree_leaf_count_of_layer(prefix, name),
                        count,
                        "at prefix {prefix:?}, entry count ≡ subtree_leaf_count_of_layer",
                    );
                    // Tie-break: among writers at the min count,
                    // `name` is the largest lex. BTreeMap iteration is
                    // ascending on names, so the last entry at the min
                    // count is the largest lex.
                    let tied_at_min: Vec<&'static str> = counts
                        .iter()
                        .filter_map(|(n, c)| (*c == min_count).then_some(*n))
                        .collect();
                    assert_eq!(
                        tied_at_min.last().copied(),
                        Some(name),
                        "at prefix {prefix:?}, entry picks largest lex name among tied minima",
                    );
                } else {
                    assert!(
                        counts.is_empty(),
                        "at prefix {prefix:?}, None ⇒ counter map is empty",
                    );
                    assert_eq!(
                        out.attribution.subtree_iter(prefix).count(),
                        0,
                        "at prefix {prefix:?}, None ⇒ subtree_iter is empty",
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_weakest_entry_equals_subtree_layer_ranking_last() {
        // Endpoint identity at subtree altitude, across every prefix
        // on every fixture.
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            for prefix in &prefixes {
                let via_ranking: Option<(&'static str, usize)> = out
                    .attribution
                    .subtree_layer_ranking(prefix)
                    .last()
                    .copied();
                assert_eq!(
                    out.attribution.subtree_weakest_entry(prefix),
                    via_ranking,
                    "at prefix {prefix:?}, subtree_weakest_entry ≡ subtree_layer_ranking.last().copied()",
                );
            }
        }
    }

    #[test]
    fn subtree_weakest_entry_projections_equal_scalars() {
        // Name-and-count decomposition at subtree altitude across
        // every prefix on every fixture:
        //   entry.map(|(n, _)| n) ≡ subtree_weakest_layer(prefix)
        //   entry.map(|(_, c)| c) ≡ subtree_leaf_counts_by_layer(prefix)
        //                              .values().min()
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
            compose_with_provenance(&[]),
        ] {
            for prefix in &prefixes {
                let entry = out.attribution.subtree_weakest_entry(prefix);
                assert_eq!(
                    entry.map(|(n, _)| n),
                    out.attribution.subtree_weakest_layer(prefix),
                    "at prefix {prefix:?}, name projection ≡ subtree_weakest_layer",
                );
                let counts_min: Option<usize> = out
                    .attribution
                    .subtree_leaf_counts_by_layer(prefix)
                    .values()
                    .copied()
                    .min();
                assert_eq!(
                    entry.map(|(_, c)| c),
                    counts_min,
                    "at prefix {prefix:?}, count projection ≡ subtree histogram min",
                );
            }
        }
    }

    #[test]
    fn subtree_weakest_entry_name_in_surviving_and_count_le_global() {
        // Two subset invariants across every prefix on every fixture:
        // when Some((name, count)), (a) `name` lives in the top-level
        // `surviving_layer_names` (subtree cannot pick a writer that
        // never wrote anywhere), and (b) `count` ≤
        // `leaf_count_of_layer(name)` (subtree ⊆ parent).
        let prefixes: Vec<Vec<String>> = vec![
            vec![],
            vec![s("breathe")],
            vec![s("alpha")],
            vec![s("small")],
            vec![s("big")],
            vec![s("nonexistent")],
        ];
        for out in [
            subtree_fixture(),
            inversion_fixture(),
            layer_axis_fixture(),
            three_way_tie_fixture(),
        ] {
            let global: std::collections::BTreeSet<&'static str> = out
                .attribution
                .surviving_layer_names()
                .into_iter()
                .collect();
            for prefix in &prefixes {
                if let Some((name, count)) = out.attribution.subtree_weakest_entry(prefix) {
                    assert!(
                        global.contains(name),
                        "at prefix {prefix:?}, entry name {name} lives in the global surviving set",
                    );
                    assert!(
                        count <= out.attribution.leaf_count_of_layer(name),
                        "at prefix {prefix:?}, subtree count {count} ≤ global {} for {name}",
                        out.attribution.leaf_count_of_layer(name),
                    );
                }
            }
        }
    }

    #[test]
    fn subtree_weakest_entry_can_differ_from_weakest_entry() {
        // The non-trivial cell: the top-level weakest entry differs
        // from a subtree weakest entry. On inversion_fixture, the top
        // weakest is ("specific", 2) — but under `["big"]`, specific
        // wrote nothing, so the local weakest is ("coarse", 3). Under
        // `["small"]`, specific:2, coarse:1 flips the weakest name
        // locally to coarse with count 1.
        let out = inversion_fixture();
        assert_eq!(out.attribution.weakest_entry(), Some(("specific", 2)));
        assert_eq!(
            out.attribution.subtree_weakest_entry(&[s("big")]),
            Some(("coarse", 3)),
            "under big.*, specific is absent — coarse alone owns the row",
        );
        assert_eq!(
            out.attribution.subtree_weakest_entry(&[s("small")]),
            Some(("coarse", 1)),
            "under small.*, coarse (1 leaf) is weakest locally",
        );
    }

    #[test]
    fn contributors_at_lists_layers_that_touched_leaf_in_application_order() {
        // Baseline: two layers write the same leaf, one writes a
        // disjoint leaf, one is silent. The path-restricted contributors
        // are the two who touched `k`, in application order.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("other", Value::from(3i64))]));
        let silent = Fixed("silent", Dict::new());
        assert_eq!(
            contributors_at(&[&a, &b, &c, &silent], &["k"]),
            vec!["a", "b"],
        );
        assert_eq!(
            contributors_at(&[&a, &b, &c, &silent], &["other"]),
            vec!["c"]
        );
        assert_eq!(
            contributors_at(&[&a, &b, &c, &silent], &["nope"]),
            Vec::<&'static str>::new(),
        );
    }

    #[test]
    fn contributors_at_includes_prefix_scalar_and_dict_container_touchers() {
        // Wholesale-replace still counts as touching: layer B writes
        // scalar at `x`, which erases the leaf at ["x", "a"]. B is
        // nonetheless the decider of that erasure and belongs in
        // contributors_at at the deeper leaf. Layer A opens a dict
        // container at `x`; the inner leaf ["x", "a"] belongs to A,
        // so A also touches ["x", "a"].
        let a = Fixed(
            "a",
            dict(&[("x", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("x", Value::from(9i64))]));
        assert_eq!(contributors_at(&[&a, &b], &["x", "a"]), vec!["a", "b"]);
        // Cross-check the effective writer: B's scalar wins at ["x"],
        // erasing the deeper leaf. LayerAttribution::layer_of at the
        // deeper leaf returns None (no leaf survives) — the
        // contributors list correctly includes B as the decider even
        // though B has no attributed leaf at that path.
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["x", "a"]), None);
    }

    #[test]
    fn contributors_at_last_element_equals_layer_of_when_leaf_survives() {
        // Subset chain: when the effective outcome at path is a
        // leaf, the last element of contributors_at is the
        // LayerAttribution.layer_of winner. Nested-dict, sibling-
        // preservation flavor.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let out = compose_with_provenance(&layers);

        // Contested leaf: both touched.
        let contested = contributors_at(&layers, &["breathe", "mode"]);
        assert_eq!(contested, vec!["platform", "tenancy"]);
        assert_eq!(
            contested.last().copied(),
            out.attribution.layer_of(&["breathe", "mode"])
        );

        // Uncontested leaf: only the coarser layer touched.
        let uncontested = contributors_at(&layers, &["breathe", "setpoint"]);
        assert_eq!(uncontested, vec!["platform"]);
        assert_eq!(
            uncontested.last().copied(),
            out.attribution.layer_of(&["breathe", "setpoint"]),
        );
    }

    #[test]
    fn contributors_at_root_equals_contributor_names() {
        // Subset chain at the root path: contributors_at(layers, &[])
        // is contributor_names(layers). Every layer with any content
        // opens the root dict.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &silent, &specific];
        assert_eq!(contributors_at(&layers, &[]), contributor_names(&layers));
        assert_eq!(contributors_at(&layers, &[]), vec!["platform", "tenancy"]);
    }

    #[test]
    fn contributors_at_is_subset_of_contributor_names() {
        // Subset chain on every path: any contributor at a leaf must
        // be a contributor in general. Rendered as a set comparison
        // so declaration order doesn't matter.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("other", Value::from(3i64))]));
        let silent = Fixed("silent", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &silent];
        let all: std::collections::BTreeSet<_> = contributor_names(&layers).into_iter().collect();
        for path in [&["k"][..], &["other"][..], &["nope"][..], &[][..]] {
            let restricted: std::collections::BTreeSet<_> =
                contributors_at(&layers, path).into_iter().collect();
            assert!(
                restricted.is_subset(&all),
                "contributors_at({path:?}) = {restricted:?} not ⊆ contributor_names = {all:?}",
            );
        }
    }

    #[test]
    fn contributors_at_empty_layers_is_empty() {
        assert_eq!(contributors_at(&[], &["k"]), Vec::<&'static str>::new());
        assert_eq!(contributors_at(&[], &[]), Vec::<&'static str>::new());
    }

    #[test]
    fn contributors_at_ignores_layers_with_disjoint_content() {
        // Under `deep_merge`, a layer whose top-level key doesn't
        // match any prefix of `path` contributes nothing to that leaf
        // and must be filtered out. The point primitive maps 1:1 onto
        // that no-opinion filter.
        let match_layer = Fixed(
            "match",
            dict(&[("a", Value::from(dict(&[("b", Value::from(1i64))])))]),
        );
        let disjoint = Fixed("disjoint", dict(&[("z", Value::from(9i64))]));
        assert_eq!(
            contributors_at(&[&match_layer, &disjoint], &["a", "b"]),
            vec!["match"],
        );
    }

    // -------- silenced_at --------

    #[test]
    fn silenced_at_lists_overridden_touchers_in_application_order() {
        // Three layers write the same leaf coarse→specific; a fourth
        // is disjoint. The two coarse touchers are silenced by the
        // most-specific-with-an-opinion; the disjoint layer never
        // enters the contest.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k", Value::from(3i64))]));
        let disjoint = Fixed("disjoint", dict(&[("other", Value::from(9i64))]));
        assert_eq!(
            silenced_at(&[&a, &b, &c, &disjoint], &["k"]),
            vec!["a", "b"],
        );
    }

    #[test]
    fn silenced_at_empty_when_single_toucher_or_no_toucher() {
        // Single toucher: no override contest, nothing silenced.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let disjoint = Fixed("z", dict(&[("other", Value::from(9i64))]));
        assert_eq!(
            silenced_at(&[&a, &disjoint], &["k"]),
            Vec::<&'static str>::new(),
        );
        // No toucher: nothing to silence.
        assert_eq!(
            silenced_at(&[&a, &disjoint], &["nope"]),
            Vec::<&'static str>::new(),
        );
        // Empty layer stack: both silenced_at and contributors_at are
        // empty; the partition law holds trivially.
        assert_eq!(silenced_at(&[], &["k"]), Vec::<&'static str>::new());
        assert_eq!(silenced_at(&[], &[]), Vec::<&'static str>::new());
    }

    #[test]
    fn silenced_at_partitions_contributors_at_disjointly() {
        // Disjoint-union law: silenced_at ⊎ [decider] == contributors_at
        // (ordered-vector equality). The decider is the last element
        // of contributors_at — the effective writer when the leaf
        // survives, the erasure decider when a prefix-scalar wipes
        // the subtree. Checked across four paths: contested leaf,
        // uncontested leaf, dict-container path, no-toucher path.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let contributors = contributors_at(&layers, path);
            let mut recomposed = silenced_at(&layers, path);
            if let Some(&decider) = contributors.last() {
                recomposed.push(decider);
            }
            assert_eq!(
                recomposed, contributors,
                "silenced_at ⊎ decider != contributors_at at {path:?}",
            );
            assert_eq!(
                silenced_at(&layers, path).len(),
                contributors.len().saturating_sub(1),
                "silenced_at.len() != contributors_at.len() - 1 at {path:?}",
            );
        }
    }

    #[test]
    fn silenced_at_excludes_layer_of_winner_when_leaf_survives() {
        // When the leaf at path survives the merge,
        // LayerAttribution::layer_of(path) is Some(w) and w is the
        // effective writer. silenced_at must NOT contain w — it must
        // contain every other toucher.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let out = compose_with_provenance(&layers);

        // Contested leaf: platform is silenced by tenancy.
        let winner = out.attribution.layer_of(&["breathe", "mode"]);
        assert_eq!(winner, Some("tenancy"));
        let silenced = silenced_at(&layers, &["breathe", "mode"]);
        assert_eq!(silenced, vec!["platform"]);
        assert!(
            !silenced.contains(&"tenancy"),
            "winner never appears silenced"
        );

        // Uncontested leaf: only platform touched; nothing silenced.
        let winner = out.attribution.layer_of(&["breathe", "setpoint"]);
        assert_eq!(winner, Some("platform"));
        assert_eq!(
            silenced_at(&layers, &["breathe", "setpoint"]),
            Vec::<&'static str>::new(),
        );
    }

    #[test]
    fn silenced_at_credits_earlier_writer_when_prefix_scalar_erases_subtree() {
        // Layer a opens a leaf at ["x", "a"]; layer b's scalar at
        // ["x"] wholesale-erases the deeper subtree. Both touch
        // ["x", "a"] (b is the erasure decider); a is silenced by
        // that erasure. layer_of on the erased path is None — the
        // primitive is still well-defined via the last-toucher
        // convention.
        let a = Fixed(
            "a",
            dict(&[("x", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("x", Value::from(9i64))]));
        assert_eq!(silenced_at(&[&a, &b], &["x", "a"]), vec!["a"]);
        // Cross-check: the effective attribution surface returns None
        // at the erased leaf, so the disjoint-union invariant threads
        // through the last-toucher convention rather than layer_of.
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["x", "a"]), None);
        assert_eq!(
            contributors_at(&[&a, &b], &["x", "a"]),
            vec!["a", "b"],
            "contributors_at includes both toucher and erasure decider",
        );
    }

    #[test]
    fn silenced_at_at_root_equals_contributor_names_minus_last() {
        // Root-path boundary condition: silenced_at at the empty path
        // equals contributor_names minus its last element. The
        // partition law specialized to the whole-layer axis.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let mut expected = contributor_names(&layers);
        expected.pop();
        assert_eq!(silenced_at(&layers, &[]), expected);
        assert_eq!(silenced_at(&layers, &[]), vec!["platform", "cloud"]);
    }

    #[test]
    fn silenced_at_is_subset_of_contributors_at() {
        // Subset chain on every path: silenced_at ⊆ contributors_at.
        // Rendered as a set comparison so the pop ordering can't hide
        // an off-by-one in the filter that produces the underlying
        // list.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("other", Value::from(3i64))]));
        let silent = Fixed("silent", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &silent];
        for path in [&["k"][..], &["other"][..], &["nope"][..], &[][..]] {
            let contributors: std::collections::BTreeSet<_> =
                contributors_at(&layers, path).into_iter().collect();
            let silenced: std::collections::BTreeSet<_> =
                silenced_at(&layers, path).into_iter().collect();
            assert!(
                silenced.is_subset(&contributors),
                "silenced_at({path:?}) = {silenced:?} not ⊆ contributors_at = {contributors:?}",
            );
        }
    }

    // -------- decider_at --------

    #[test]
    fn decider_at_names_most_specific_toucher() {
        // Three writers coarse→specific; the last is the decider. A
        // disjoint fourth layer never enters the contest.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k", Value::from(3i64))]));
        let disjoint = Fixed("disjoint", dict(&[("other", Value::from(9i64))]));
        assert_eq!(decider_at(&[&a, &b, &c, &disjoint], &["k"]), Some("c"));
    }

    #[test]
    fn decider_at_none_on_no_toucher_and_empty_stack() {
        // No layer touches path → None. Empty layer stack → None on
        // any path (root included) — nobody to decide anything.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let disjoint = Fixed("z", dict(&[("other", Value::from(9i64))]));
        assert_eq!(decider_at(&[&a, &disjoint], &["nope"]), None);
        assert_eq!(decider_at(&[], &["k"]), None);
        assert_eq!(decider_at(&[], &[]), None);
    }

    #[test]
    fn decider_at_single_toucher_is_that_toucher() {
        // One toucher, no contest — the sole toucher decides.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let disjoint = Fixed("z", dict(&[("other", Value::from(9i64))]));
        assert_eq!(decider_at(&[&a, &disjoint], &["k"]), Some("a"));
    }

    #[test]
    fn decider_at_order_sensitivity() {
        // Reversing layer order flips the decider — the primitive is
        // application-order-sensitive, not set-based.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        assert_eq!(decider_at(&[&a, &b], &["k"]), Some("b"));
        assert_eq!(decider_at(&[&b, &a], &["k"]), Some("a"));
    }

    #[test]
    fn decider_at_partitions_contributors_at_disjointly_with_silenced_at() {
        // Partition law:
        //   silenced_at(p) ⊎ decider_at(p).into_iter() == contributors_at(p)
        // as ordered-vector equality; the decider sits at the end.
        // Checked across five paths: contested leaf, uncontested leaf,
        // dict container, absent path, and root.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let contributors = contributors_at(&layers, path);
            let mut recomposed = silenced_at(&layers, path);
            recomposed.extend(decider_at(&layers, path));
            assert_eq!(
                recomposed, contributors,
                "silenced_at ⊎ decider_at != contributors_at at {path:?}",
            );
            assert_eq!(
                decider_at(&layers, path),
                contributors.last().copied(),
                "decider_at != contributors_at.last() at {path:?}",
            );
        }
    }

    #[test]
    fn decider_at_agrees_with_layer_of_on_surviving_leaves() {
        // On any path where the composed leaf survives,
        // decider_at == layer_of. The two axes only diverge on
        // erased-leaf / dict-container paths (covered separately below).
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let out = compose_with_provenance(&layers);
        for path in [&["breathe", "mode"][..], &["breathe", "setpoint"][..]] {
            assert_eq!(
                decider_at(&layers, path),
                out.attribution.layer_of(path),
                "decider_at != layer_of on surviving leaf {path:?}",
            );
        }
    }

    #[test]
    fn decider_at_names_erasure_agent_when_prefix_scalar_wipes_subtree() {
        // Layer a opens ["x", "a"]; layer b's scalar at ["x"] wipes the
        // deeper subtree wholesale. layer_of on the erased path is None
        // (post-merge: no leaf) but decider_at is Some("b") — the
        // erasure decider. The primitive covers the case layer_of can't
        // reach.
        let a = Fixed(
            "a",
            dict(&[("x", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("x", Value::from(9i64))]));
        assert_eq!(decider_at(&[&a, &b], &["x", "a"]), Some("b"));
        // On the erasure-target path itself, b is also the decider —
        // its scalar wholesale-replaces a's dict subtree.
        assert_eq!(decider_at(&[&a, &b], &["x"]), Some("b"));
        // Cross-check: post-merge attribution is None at the erased
        // deep path.
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["x", "a"]), None);
    }

    #[test]
    fn decider_at_at_root_equals_last_contributor_name() {
        // Root-path boundary: decider_at at the empty path equals the
        // last element of contributor_names — the most-specific
        // non-empty layer. The partition law specialized to the
        // whole-layer axis, paired with silenced_at_at_root.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        assert_eq!(
            decider_at(&layers, &[]),
            contributor_names(&layers).last().copied(),
        );
        assert_eq!(decider_at(&layers, &[]), Some("tenancy"));
    }

    #[test]
    fn decider_at_matches_contributors_at_last_across_all_path_shapes() {
        // The trailing-element identity decider_at ≡ contributors_at
        // .last().copied() holds across contested, uncontested, absent,
        // root, and prefix-erased paths — checked explicitly so an
        // off-by-one in the reverse walker or short-circuit can't hide
        // behind a specific-path test.
        let a = Fixed(
            "a",
            dict(&[("x", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("x", Value::from(9i64))]));
        let c = Fixed("c", dict(&[("k", Value::from(3i64))]));
        let d = Fixed("d", dict(&[("k", Value::from(4i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &d];
        for path in [
            &["k"][..],
            &["x"][..],
            &["x", "a"][..],
            &["nope"][..],
            &[][..],
        ] {
            assert_eq!(
                decider_at(&layers, path),
                contributors_at(&layers, path).last().copied(),
                "decider_at != contributors_at.last() at {path:?}",
            );
        }
    }

    // -------- contest_at / PathContest --------

    #[test]
    fn contest_at_none_on_no_toucher_and_empty_stack() {
        // No layer touches path → None. Empty layer stack → None at
        // every path (root included). The outer Option carries the
        // no-toucher boundary; a `PathContest` value with a `None`
        // decider is *unrepresentable* — the type enforces
        // well-formedness.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let disjoint = Fixed("z", dict(&[("other", Value::from(9i64))]));
        assert_eq!(contest_at(&[&a, &disjoint], &["nope"]), None);
        assert_eq!(contest_at(&[], &["k"]), None);
        assert_eq!(contest_at(&[], &[]), None);
    }

    #[test]
    fn contest_at_single_toucher_is_uncontested_with_that_decider() {
        // One toucher → Some(PathContest { decider: it, overridden: [] }).
        // `is_contested()` is false; `contributor_count()` is 1. The
        // distinction between "no toucher" and "uncontested" is
        // structural, not conventional — one is None, the other is
        // Some with an empty overridden vec.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let disjoint = Fixed("z", dict(&[("other", Value::from(9i64))]));
        let contest = contest_at(&[&a, &disjoint], &["k"]).expect("some toucher");
        assert_eq!(contest.decider, "a");
        assert!(contest.overridden.is_empty(), "no override contest");
        assert!(!contest.is_contested(), "single toucher is not contested");
        assert_eq!(contest.contributor_count(), 1);
    }

    #[test]
    fn contest_at_lists_overridden_in_application_order() {
        // Three writers coarse→specific plus a disjoint fourth. The
        // decider is the last-in-order toucher; the overridden list
        // is the coarse-to-specific prefix, ordered.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k", Value::from(3i64))]));
        let disjoint = Fixed("disjoint", dict(&[("other", Value::from(9i64))]));
        let contest = contest_at(&[&a, &b, &c, &disjoint], &["k"]).expect("some toucher");
        assert_eq!(contest.decider, "c");
        assert_eq!(contest.overridden, vec!["a", "b"]);
        assert!(contest.is_contested());
        assert_eq!(contest.contributor_count(), 3);
    }

    #[test]
    fn contest_at_covers_erasure_case() {
        // Prefix-scalar erases a deeper subtree; the decider is the
        // erasure agent even where `layer_of` returns None. The
        // structural fusion covers a case the loose `(decider,
        // silenced)` pair could — but only via disciplined callers.
        let a = Fixed(
            "a",
            dict(&[("x", Value::from(dict(&[("a", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("x", Value::from(9i64))]));
        let contest = contest_at(&[&a, &b], &["x", "a"]).expect("erasure decider is a toucher");
        assert_eq!(
            contest.decider, "b",
            "erasure agent decides the erased path"
        );
        assert_eq!(contest.overridden, vec!["a"]);
        // Cross-check post-merge attribution: layer_of is None at the
        // erased path — the primitive covers what LayerAttribution
        // cannot reach.
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["x", "a"]), None);
    }

    #[test]
    fn contest_at_projections_match_decider_and_silenced_axes() {
        // The two loose primitives factor through the fused one:
        //   contest_at.map(.decider)     == decider_at
        //   contest_at.map(.overridden)  == Some(silenced_at)   [when Some]
        //   contest_at.is_none()         iff  decider_at.is_none()
        //                                and  contributors_at.is_empty()
        // Checked across five paths spanning every branch of
        // `touches_path`: contested leaf, uncontested leaf, dict
        // container, absent path, and root.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let contest = contest_at(&layers, path);
            assert_eq!(
                contest.as_ref().map(|c| c.decider),
                decider_at(&layers, path),
                "contest.decider != decider_at at {path:?}",
            );
            match &contest {
                Some(c) => assert_eq!(
                    c.overridden,
                    silenced_at(&layers, path),
                    "contest.overridden != silenced_at at {path:?}",
                ),
                None => assert!(
                    silenced_at(&layers, path).is_empty()
                        && contributors_at(&layers, path).is_empty(),
                    "contest_at is None but touchers exist at {path:?}",
                ),
            }
        }
    }

    #[test]
    fn contest_at_reconstructs_contributors_at() {
        // Reconstruction identity: [overridden..., decider] ==
        // contributors_at, as ordered-vector equality. Pins the
        // pair back to the coarse→specific ordering the primitive
        // has to preserve to be sound.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let contributors = contributors_at(&layers, path);
            let recomposed = contest_at(&layers, path).map_or_else(Vec::new, |c| {
                let mut v = c.overridden.clone();
                v.push(c.decider);
                v
            });
            assert_eq!(
                recomposed, contributors,
                "reconstructed != contributors_at at {path:?}",
            );
        }
    }

    #[test]
    fn contest_at_contributor_count_matches_contributors_at_len() {
        // Scalar invariant on the count axis: the fused primitive's
        // cardinality method equals the loose primitive's Vec length,
        // with None mapped to 0.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("other", Value::from(3i64))]));
        let silent = Fixed("silent", Dict::new());
        let layers: [&dyn DiscoveryLayer; 4] = [&a, &b, &c, &silent];
        for path in [&["k"][..], &["other"][..], &["nope"][..], &[][..]] {
            assert_eq!(
                contest_at(&layers, path).map_or(0, |c| c.contributor_count()),
                contributors_at(&layers, path).len(),
                "contributor_count != contributors_at.len() at {path:?}",
            );
        }
    }

    #[test]
    fn contest_at_is_contested_iff_silenced_non_empty() {
        // Boolean equivalence pinning the "contested" predicate to
        // the silenced-non-empty predicate on the loose axis. Also
        // pins the pairing to "single toucher is not contested".
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("other", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [&["k"][..], &["other"][..], &["nope"][..], &[][..]] {
            let contested_via_fused = contest_at(&layers, path).is_some_and(|c| c.is_contested());
            let contested_via_loose = !silenced_at(&layers, path).is_empty();
            assert_eq!(
                contested_via_fused, contested_via_loose,
                "is_contested() != !silenced_at.is_empty() at {path:?}",
            );
        }
    }

    #[test]
    fn contest_at_root_boundary() {
        // Root-path specialization: decider is the last
        // contributor_name; overridden is contributor_names minus
        // the last element.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let contest = contest_at(&layers, &[]).expect("some non-empty layer at root");
        assert_eq!(contest.decider, "tenancy");
        assert_eq!(contest.overridden, vec!["platform", "cloud"]);
        let mut expected_overridden = contributor_names(&layers);
        expected_overridden.pop();
        assert_eq!(contest.overridden, expected_overridden);
    }

    #[test]
    fn contest_at_agrees_with_layer_of_on_surviving_leaves() {
        // Fused primitive's decider equals LayerAttribution.layer_of
        // whenever a leaf survives at path. On erased-leaf / dict-
        // container paths the two axes correctly diverge — covered
        // separately by contest_at_covers_erasure_case.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let out = compose_with_provenance(&layers);
        for path in [&["breathe", "mode"][..], &["breathe", "setpoint"][..]] {
            let contest = contest_at(&layers, path).expect("surviving leaf has toucher");
            assert_eq!(
                Some(contest.decider),
                out.attribution.layer_of(path),
                "contest.decider != layer_of on surviving leaf {path:?}",
            );
        }
    }

    // -------- PathContest::contributors --------

    #[test]
    fn path_contest_contributors_uncontested_returns_singleton_decider() {
        // Single toucher → contributors() is [decider], length 1.
        let contest = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        assert_eq!(contest.contributors(), vec!["solo"]);
        assert!(!contest.is_contested());
        assert_eq!(contest.contributors().len(), 1);
        assert_eq!(contest.contributors().len(), contest.contributor_count());
    }

    #[test]
    fn path_contest_contributors_three_writers_ordered_coarse_to_specific() {
        // Three touchers at breathe.mode; contributors() enumerates
        // them coarse→specific with `tenancy` last (the decider).
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("aws"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let disjoint = Fixed("logger", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&platform, &cloud, &tenancy, &disjoint];
        let contest = contest_at(&layers, &["breathe", "mode"]).expect("three touchers");
        assert_eq!(
            contest.contributors(),
            vec!["platform", "cloud", "tenancy"],
            "contributors() enumerates touchers coarse→specific",
        );
    }

    #[test]
    fn path_contest_contributors_matches_contributors_at() {
        // Reconstruction identity: contest_at(layers, p).map(|c| c.contributors())
        // == Some(contributors_at(layers, p))  when contest_at is Some.
        // The total-on-both-sides identity holds too:
        // contest_at(layers, p).map_or(vec![], |c| c.contributors())
        //   == contributors_at(layers, p).
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let expected = contributors_at(&layers, path);
            let via_fused = contest_at(&layers, path).map_or_else(Vec::new, |c| c.contributors());
            assert_eq!(
                via_fused, expected,
                "contest.contributors() != contributors_at at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_contributors_len_matches_contributor_count() {
        // contributors().len() == contributor_count() == contributors_at.len() across all paths.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let c = Fixed(
            "c",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(3i64))])))]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [&[][..], &["k"][..], &["k", "leaf"][..], &["absent"][..]] {
            let expected = contributors_at(&layers, path).len();
            let via_contributors = contest_at(&layers, path).map_or(0, |c| c.contributors().len());
            let via_count = contest_at(&layers, path).map_or(0, |c| c.contributor_count());
            assert_eq!(via_contributors, expected, "len mismatch at {path:?}");
            assert_eq!(via_count, expected, "count mismatch at {path:?}");
        }
    }

    #[test]
    fn path_contest_contributors_trailing_element_is_decider() {
        // The last element of contributors() is always .decider — the
        // trailing-projection identity `contributors().last() ==
        // Some(decider)` holds by construction (decider is push()'d last).
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed(
            "c",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [&["breathe"][..], &["breathe", "mode"][..], &[][..]] {
            let contest = contest_at(&layers, path).expect("some toucher");
            let contributors = contest.contributors();
            assert_eq!(
                contributors.last().copied(),
                Some(contest.decider),
                "trailing element != decider at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_contributors_leading_prefix_is_overridden() {
        // The leading contributors().len() - 1 == overridden.len()
        // entries of contributors() are exactly `overridden` in order.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed(
            "c",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [&["breathe"][..], &["breathe", "mode"][..], &[][..]] {
            let contest = contest_at(&layers, path).expect("some toucher");
            let contributors = contest.contributors();
            let leading = &contributors[..contest.overridden.len()];
            assert_eq!(
                leading,
                contest.overridden.as_slice(),
                "leading prefix != overridden at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_contributors_covers_erasure_case() {
        // Prefix-scalar erasure: layer `a` wrote k.leaf, layer `b`
        // wholesale-replaces k with a scalar. Both touch k.leaf;
        // contributors() lists both with `b` last (the erasure agent).
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        let contest = contest_at(&layers, &["k", "leaf"]).expect("erasure decider is a toucher");
        assert_eq!(contest.contributors(), vec!["a", "b"]);
        assert_eq!(contest.decider, "b");
        assert_eq!(contest.overridden, vec!["a"]);
    }

    // -------- PathContest::contributors_iter --------

    #[test]
    fn path_contest_contributors_iter_singleton_yields_decider_only() {
        // Uncontested singleton: 1 toucher, 0 silenced. The iterator
        // yields exactly one element — the decider itself. This pins
        // the empty-losers boundary: with `overridden.is_empty()`, the
        // `Copied<Iter>` half of the chain yields nothing, and the
        // `Once<decider>` tail is the only element materialized.
        let contest = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        let materialized: Vec<&'static str> = contest.contributors_iter().collect();
        assert_eq!(
            materialized,
            vec!["solo"],
            "sole toucher yields exactly [decider]",
        );
        assert_eq!(
            contest.contributors_iter().count(),
            1,
            ".count() aliases contributor_count() on the uncontested singleton",
        );
        assert_eq!(
            contest.contributors_iter().count(),
            contest.contributor_count(),
            "count identity holds on the empty-losers boundary",
        );
    }

    #[test]
    fn path_contest_contributors_iter_matches_contributors_across_fixture() {
        // Materialization identity: `.contributors_iter().collect() ==
        // .contributors()` pointwise across the {0, 1, ≥ 2} silenced-
        // cardinality partition. Pins the lazy/eager pair as
        // extensionally equal on every fixture cell.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            let lazy: Vec<&'static str> = contest.contributors_iter().collect();
            assert_eq!(
                lazy,
                contest.contributors(),
                "iter().collect() disagrees with contributors() on a {}-toucher fixture",
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_contributors_iter_matches_silenced_chain_decider() {
        // The concatenation identity on the substrate side:
        //   contributors_iter() == silenced().iter().copied().chain(once(decider))
        // Pins the lazy composition as literally equal to the
        // hand-rolled chain a caller would otherwise open-code — the
        // structural rationale for exposing the iterator at all.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            let via_method: Vec<&'static str> = contest.contributors_iter().collect();
            let via_hand: Vec<&'static str> = contest
                .silenced()
                .iter()
                .copied()
                .chain(std::iter::once(contest.decider))
                .collect();
            assert_eq!(
                via_method, via_hand,
                "iter() disagrees with the substrate-side concat chain",
            );
        }
    }

    #[test]
    fn path_contest_contributors_iter_endpoints_alias_coarsest_and_decider() {
        // Endpoint identities: `.next() == Some(coarsest())` and
        // `.last() == Some(decider)`. On the uncontested singleton both
        // aliases collapse onto the sole toucher; on the contested
        // triple they diverge structurally.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        // Singleton branch: leading == trailing == decider.
        let layers: [&dyn DiscoveryLayer; 1] = [sole.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert_eq!(contest.contributors_iter().next(), Some(contest.coarsest()));
        assert_eq!(contest.contributors_iter().last(), Some(contest.decider));
        assert_eq!(contest.coarsest(), contest.decider, "singleton collapse");
        // Contested-triple branch: leading != trailing.
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert_eq!(contest.contributors_iter().next(), Some(contest.coarsest()));
        assert_eq!(contest.contributors_iter().last(), Some(contest.decider));
        assert_ne!(
            contest.coarsest(),
            contest.decider,
            "contested-triple endpoints are structurally distinct",
        );
    }

    #[test]
    fn path_contest_contributors_iter_count_matches_contributor_count() {
        // Cardinality identity across the fixture spectrum:
        //   contributors_iter().count() == contributor_count()
        //                                == silenced_count() + 1
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            assert_eq!(
                contest.contributors_iter().count(),
                contest.contributor_count(),
            );
            assert_eq!(
                contest.contributors_iter().count(),
                contest.silenced_count() + 1,
            );
        }
    }

    #[test]
    fn path_contest_contributors_iter_matches_contributors_at_across_paths() {
        // Option<PathContest> boundary identity across a multi-path
        // grid: the lazy method peer folds through `contest_at` and
        // `.map_or(vec![], collect)` to the free-fn point primitive
        // `contributors_at`. Pins the accessor-boundary contract on
        // every fixture cell.
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&platform, &cloud, &tenancy];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["absent"][..],
        ] {
            let via_method: Vec<&'static str> =
                contest_at(&layers, path).map_or(vec![], |c| c.contributors_iter().collect());
            let via_free_fn = contributors_at(&layers, path);
            assert_eq!(
                via_method, via_free_fn,
                "iter().collect() disagrees with contributors_at at path {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_contributors_iter_enumerate_pins_positions() {
        // Positional identities on the enumerated stream — the
        // consumer-side workload the iterator exists to serve without
        // materializing the full `Vec`. Pins:
        //   - index 0 == coarsest() (leading endpoint)
        //   - index contributor_count() - 1 == decider (trailing endpoint)
        //   - index contributor_count() - 2 == runner_up() on the
        //     contested branch (one-step-back-from-decider identity)
        //   - the enumerated pairs align with contributors()[i]
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        let materialized = contest.contributors();
        for (idx, name) in contest.contributors_iter().enumerate() {
            assert_eq!(
                name, materialized[idx],
                "enumerated iterator diverges from contributors() at index {idx}",
            );
        }
        let last_idx = contest.contributor_count() - 1;
        assert_eq!(contest.contributors_iter().nth(0), Some(contest.coarsest()),);
        assert_eq!(
            contest.contributors_iter().nth(last_idx),
            Some(contest.decider),
        );
        assert_eq!(
            contest.contributors_iter().nth(last_idx - 1),
            contest.runner_up(),
            "index n-2 aliases runner_up() on the contested branch",
        );
    }

    #[test]
    fn path_contest_contributors_iter_root_specialization_matches_contributor_names() {
        // Root altitude: at the empty path, every layer that returns a
        // non-empty dict is a toucher, so `.contributors_iter().collect()`
        // aliases `contributor_names` on the same stack — the whole-
        // layer projection this iterator method-altitude specializes to
        // at the root.
        let a = Fixed("a", dict(&[("x", Value::from(1i64))]));
        let silent = Fixed("silent", Dict::new());
        let b = Fixed("b", dict(&[("y", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &silent, &b];
        let contest = contest_at(&layers, &[]).expect("root is touched");
        let iter_collected: Vec<&'static str> = contest.contributors_iter().collect();
        assert_eq!(iter_collected, contributor_names(&layers));
        assert_eq!(iter_collected, vec!["a", "b"]);
    }

    #[test]
    fn path_contest_contributors_iter_rev_reverses_forward_walk_across_fixture() {
        // The reverse walk is the ordered inverse of the forward walk:
        // `.rev().collect()` equals `contributors()` with `Vec::reverse`
        // applied to it. Pins the DoubleEndedIterator sharpening against
        // the `Vec::reverse` semantics on the same materialized value
        // across the {0, 1, ≥ 2} silenced-cardinality partition.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            vec![sole.as_ref()],
            vec![pair_coarse.as_ref(), pair_specific.as_ref()],
            vec![sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()],
        ] {
            let contest = contest_at(&layers, &["k"]).expect("k is touched");
            let mut expected = contest.contributors();
            expected.reverse();
            let reversed: Vec<&'static str> = contest.contributors_iter().rev().collect();
            assert_eq!(reversed, expected);
        }
    }

    #[test]
    fn path_contest_contributors_iter_rev_endpoints_alias_decider_and_coarsest() {
        // Reverse-endpoint identities on the DoubleEndedIterator: the
        // *back* end of the reverse walk emits `coarsest` (the original
        // leading element), and the *front* end emits `decider` (the
        // original trailing element). Aliased against the O(1) accessors
        // on both the uncontested-singleton and multi-writer branches.
        let uncontested = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        assert_eq!(uncontested.contributors_iter().rev().next(), Some("solo"));
        assert_eq!(uncontested.contributors_iter().rev().last(), Some("solo"));
        assert_eq!(
            uncontested.contributors_iter().rev().next(),
            Some(uncontested.decider),
        );
        assert_eq!(
            uncontested.contributors_iter().rev().last(),
            Some(uncontested.coarsest()),
        );

        let multi = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        assert_eq!(multi.contributors_iter().rev().next(), Some("tenancy"));
        assert_eq!(multi.contributors_iter().rev().last(), Some("platform"));
        assert_eq!(multi.contributors_iter().rev().next(), Some(multi.decider),);
        assert_eq!(
            multi.contributors_iter().rev().last(),
            Some(multi.coarsest()),
        );
    }

    #[test]
    fn path_contest_contributors_iter_rev_nth_walks_specific_to_coarse() {
        // Positional identities on the reverse walk: index 0 aliases
        // `decider`, index 1 aliases `runner_up` (on the contested
        // branch), index n-1 aliases `coarsest`. Pins the diagnostic
        // renderer's specific→coarse walk against the three ordered
        // endpoints callers actually name.
        let multi = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        assert_eq!(multi.contributors_iter().rev().nth(0), Some(multi.decider));
        assert_eq!(multi.contributors_iter().rev().nth(1), multi.runner_up());
        let last_idx = multi.contributor_count() - 1;
        assert_eq!(
            multi.contributors_iter().rev().nth(last_idx),
            Some(multi.coarsest()),
        );
    }

    #[test]
    fn path_contest_contributors_iter_clone_yields_independent_walks() {
        // The Clone bound closes the "two independent walks over the
        // same substrate-owned slice" seam without materializing the
        // owned Vec. The two clones each walk the full stream and yield
        // the same result; interleaving them (advance one, then the
        // other) preserves per-clone position.
        let contest = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        let a = contest.contributors_iter();
        let b = a.clone();
        let a_collected: Vec<&'static str> = a.collect();
        let b_collected: Vec<&'static str> = b.collect();
        assert_eq!(a_collected, b_collected);
        assert_eq!(a_collected, contest.contributors());

        // Interleaved walk: one clone advances, the other stays behind.
        let mut left = contest.contributors_iter();
        let mut right = left.clone();
        assert_eq!(left.next(), Some(contest.coarsest()));
        // Right is still at the head — hasn't seen the first name.
        assert_eq!(right.next(), Some(contest.coarsest()));
        assert_eq!(left.next(), Some("cloud"));
        assert_eq!(right.next(), Some("cloud"));
        assert_eq!(left.next(), Some("orchestrator"));
        assert_eq!(left.next(), Some(contest.decider));
        assert_eq!(left.next(), None);
        // Right still has orchestrator + decider to go — position is
        // per-clone, not shared.
        assert_eq!(right.next(), Some("orchestrator"));
        assert_eq!(right.next(), Some(contest.decider));
        assert_eq!(right.next(), None);
    }

    #[test]
    fn path_contest_contributors_iter_clone_and_rev_compose_across_fixture() {
        // Composition test: `.clone().rev()` and `.rev().clone()` yield
        // the same reversed stream, and the reverse of a clone matches
        // the reverse of the original — pinning that Clone and
        // DoubleEndedIterator compose commutatively at the trait level
        // across the {0, 1, ≥ 2} silenced-cardinality partition.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            vec![sole.as_ref()],
            vec![pair_coarse.as_ref(), pair_specific.as_ref()],
            vec![sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()],
        ] {
            let contest = contest_at(&layers, &["k"]).expect("k is touched");
            let base: Vec<&'static str> = contest.contributors_iter().rev().collect();
            let via_clone_then_rev: Vec<&'static str> =
                contest.contributors_iter().clone().rev().collect();
            let via_rev_then_clone: Vec<&'static str> = {
                let rev = contest.contributors_iter().rev();
                rev.clone().collect()
            };
            assert_eq!(base, via_clone_then_rev);
            assert_eq!(base, via_rev_then_clone);
        }
    }

    // -------- PathContest::contributors_iter — ExactSizeIterator sharpening --------

    #[test]
    fn path_contest_contributors_iter_len_matches_contributor_count_across_fixture() {
        // ExactSizeIterator sharpening: the O(1) `.len()` on the concrete
        // return type equals `contributor_count()` on every branch of the
        // {0, 1, ≥ 2} silenced-cardinality partition. Before this change
        // the return type was `Chain<Copied<slice::Iter>, Once<_>>` (via
        // `impl DoubleEndedIterator + Clone`), which stable Rust does not
        // impl `ExactSizeIterator` for — the sum of the two halves' `usize`
        // lengths could in principle overflow, so `Chain` structurally
        // opts out. The concrete `PathContestContributorsIter` fuses the
        // two halves into a two-field state and can carry the trait.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            vec![sole.as_ref()],
            vec![pair_coarse.as_ref(), pair_specific.as_ref()],
            vec![sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()],
        ] {
            let contest = contest_at(&layers, &["k"]).expect("k is touched");
            let iter = contest.contributors_iter();
            assert_eq!(iter.len(), contest.contributor_count());
            // A fresh iter's `.count()` (which consumes the iterator) must
            // agree with the O(1) `.len()` on the same-shaped iter.
            assert_eq!(
                contest.contributors_iter().count(),
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_contributors_iter_size_hint_reports_exact_length() {
        // ExactSizeIterator implies `.size_hint()` returns `(n, Some(n))`
        // where `n == contributor_count()` — the trait-level guarantee
        // consumers reach for when pre-allocating output buffers via
        // `Vec::with_capacity(iter.size_hint().0)`. Pinned across the
        // uncontested-singleton and multi-writer branches to prove the
        // exact-length hint is not a fortunate size_hint coincidence but
        // the structural guarantee the trait now names.
        let uncontested = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        let hint = uncontested.contributors_iter().size_hint();
        assert_eq!(hint, (1, Some(1)));

        let multi = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        let hint = multi.contributors_iter().size_hint();
        assert_eq!(hint, (4, Some(4)));
    }

    #[test]
    fn path_contest_contributors_iter_len_decreases_by_one_per_advance() {
        // ExactSizeIterator + Iterator contract: `.len()` decreases by
        // exactly 1 on every `.next()`/`.next_back()` that yields a
        // `Some`, and stays 0 once exhausted. Pins the size-hint /
        // remaining-length bookkeeping across mixed forward+backward
        // walks — the state machine `PathContestContributorsIter` owns
        // (a `Copied<slice::Iter>` plus an `Option<&'static str>`) must
        // report the correct remaining length at every partial-consumption
        // point, not just at the endpoints.
        let multi = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        let mut iter = multi.contributors_iter();
        assert_eq!(iter.len(), 4);
        assert_eq!(iter.next(), Some("platform"));
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next_back(), Some("tenancy"));
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.next(), Some("cloud"));
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.next_back(), Some("orchestrator"));
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next_back(), None);
        assert_eq!(iter.len(), 0);
    }

    #[test]
    fn path_contest_contributors_iter_is_fused_past_exhaustion() {
        // `PathContestContributorsIter` is `FusedIterator` — every call
        // after the first `None` continues to return `None`, on both
        // `.next()` and `.next_back()`. The trait carries a semantic
        // guarantee (chained adapters like `.fuse()` are no-ops), so
        // pinning the observable behaviour at the value level guards
        // against a future refactor that swaps in a non-fused inner
        // state and silently regresses the trait promise.
        let uncontested = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        let mut iter = uncontested.contributors_iter();
        assert_eq!(iter.next(), Some("solo"));
        for _ in 0..4 {
            assert_eq!(iter.next(), None);
            assert_eq!(iter.next_back(), None);
        }

        let pair = PathContest {
            decider: "tenancy",
            overridden: vec!["platform"],
        };
        let mut iter = pair.contributors_iter();
        assert_eq!(iter.next(), Some("platform"));
        assert_eq!(iter.next(), Some("tenancy"));
        for _ in 0..4 {
            assert_eq!(iter.next(), None);
            assert_eq!(iter.next_back(), None);
        }
    }

    #[test]
    fn path_contest_contributors_iter_last_returns_decider_end_of_forward_walk() {
        // `.last()` is a specialization on the Iterator trait — for
        // ExactSizeIterator + DoubleEndedIterator implementations that
        // want O(1) trailing-element access without walking the whole
        // stream. The default `Iterator::last` would loop `.next()` to
        // exhaustion; the specialization on `PathContestContributorsIter`
        // reaches for the trailing element directly. Pinned against the
        // forward-walk trailing element (decider) on the multi-writer
        // branch and the sole-toucher branch, and against the
        // partially-consumed branch (where next_back has already taken
        // the decider, so `.last()` falls through to the overridden
        // slice's own trailing element).
        let multi = PathContest {
            decider: "tenancy",
            overridden: vec!["platform", "cloud", "orchestrator"],
        };
        assert_eq!(multi.contributors_iter().last(), Some("tenancy"));

        let uncontested = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        assert_eq!(uncontested.contributors_iter().last(), Some("solo"));

        // After `next_back()` consumes the decider, `.last()` returns
        // the trailing element of the remaining overridden slice.
        let mut partially = multi.contributors_iter();
        assert_eq!(partially.next_back(), Some("tenancy"));
        assert_eq!(partially.last(), Some("orchestrator"));
    }

    #[test]
    fn path_contest_contributors_iter_named_type_carries_trait_algebra() {
        // The concrete return type carries the full trait algebra at
        // the API boundary: `PathContestContributorsIter<'_>` implements
        // `Iterator + DoubleEndedIterator + ExactSizeIterator +
        // FusedIterator + Clone + Debug`. The `is_x` helpers below
        // compile only if the corresponding trait is implemented — a
        // regression that erases any of the traits from the concrete
        // type would fail to compile, pinning the algebra invariant
        // at the type-signature level rather than at a value-level
        // behaviour check.
        fn is_iter<I: Iterator<Item = &'static str>>(_: &I) {}
        fn is_double_ended<I: DoubleEndedIterator<Item = &'static str>>(_: &I) {}
        fn is_exact_size<I: ExactSizeIterator<Item = &'static str>>(_: &I) {}
        fn is_fused<I: std::iter::FusedIterator<Item = &'static str>>(_: &I) {}
        fn is_clone<T: Clone>(_: &T) {}
        fn is_debug<T: std::fmt::Debug>(_: &T) {}

        let contest = PathContest {
            decider: "d",
            overridden: vec!["o0", "o1"],
        };
        let iter: PathContestContributorsIter<'_> = contest.contributors_iter();
        is_iter(&iter);
        is_double_ended(&iter);
        is_exact_size(&iter);
        is_fused(&iter);
        is_clone(&iter);
        is_debug(&iter);
    }

    // -------- PathContest::silenced_iter --------

    #[test]
    fn path_contest_silenced_iter_empty_on_uncontested_singleton() {
        // Empty-losers boundary: with `overridden.is_empty()`, the
        // `Copied<Iter>` over the empty slice yields nothing — the
        // dual of `contributors_iter()` collapsing to just the decider
        // on the same input.
        let contest = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        assert_eq!(contest.silenced_iter().count(), 0);
        assert!(contest.silenced_iter().next().is_none());
        assert!(contest.silenced_iter().last().is_none());
        assert_eq!(
            contest.silenced_iter().count(),
            contest.silenced_count(),
            "count identity holds on the empty-losers boundary",
        );
    }

    #[test]
    fn path_contest_silenced_iter_matches_silenced_across_fixture() {
        // Materialization equality: `silenced_iter().collect() ==
        // silenced().to_vec()` pointwise across the {0, 1, ≥ 2}
        // silenced-cardinality partition. Pins the iterator dual as
        // extensionally equal to the slice seam on every fixture cell.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            let via_iter: Vec<&'static str> = contest.silenced_iter().collect();
            assert_eq!(
                via_iter,
                contest.silenced().to_vec(),
                "silenced_iter().collect() disagrees with silenced().to_vec() on a {}-silenced fixture",
                contest.silenced_count(),
            );
        }
    }

    #[test]
    fn path_contest_silenced_iter_chain_once_decider_matches_contributors_iter() {
        // Concatenation identity on the substrate side:
        //   silenced_iter().chain(once(decider)) == contributors_iter()
        // Pins the (winners+losers, losers) iterator pair as literally
        // composable at the method surface across the fixture spectrum.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            let via_chain: Vec<&'static str> = contest
                .silenced_iter()
                .chain(std::iter::once(contest.decider))
                .collect();
            let via_contributors: Vec<&'static str> = contest.contributors_iter().collect();
            assert_eq!(
                via_chain, via_contributors,
                "chain(once(decider)) disagrees with contributors_iter()",
            );
        }
    }

    #[test]
    fn path_contest_silenced_iter_endpoints_alias_coarsest_silenced_and_runner_up() {
        // Endpoint identities: `.next() == coarsest_silenced()` and
        // `.last() == runner_up()`. On the uncontested singleton both
        // aliases collapse onto `None`; on the singly contested pair the
        // two endpoints alias each other and the sole silenced layer; on
        // the multiply-silenced triple they diverge structurally.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        // Uncontested: both endpoints None.
        let layers: [&dyn DiscoveryLayer; 1] = [sole.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert_eq!(contest.silenced_iter().next(), contest.coarsest_silenced());
        assert_eq!(contest.silenced_iter().last(), contest.runner_up());
        assert!(contest.silenced_iter().next().is_none());
        // Singly contested: single silenced layer at both endpoints.
        let layers: [&dyn DiscoveryLayer; 2] = [pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert_eq!(contest.silenced_iter().next(), contest.coarsest_silenced());
        assert_eq!(contest.silenced_iter().last(), contest.runner_up());
        assert_eq!(
            contest.silenced_iter().next(),
            contest.silenced_iter().last(),
            "singly silenced: endpoints alias",
        );
        // Multiply silenced: structurally distinct endpoints.
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert_eq!(contest.silenced_iter().next(), contest.coarsest_silenced());
        assert_eq!(contest.silenced_iter().last(), contest.runner_up());
        assert_ne!(
            contest.silenced_iter().next(),
            contest.silenced_iter().last(),
            "multiply silenced: endpoints structurally distinct",
        );
    }

    #[test]
    fn path_contest_silenced_iter_count_and_len_match_silenced_count() {
        // Cardinality identity across the fixture spectrum:
        //   silenced_iter().count() == silenced_count()
        //   silenced_iter().len()   == silenced_count()    (ExactSizeIterator)
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            assert_eq!(contest.silenced_iter().count(), contest.silenced_count());
            assert_eq!(contest.silenced_iter().len(), contest.silenced_count());
            // Consistency between the two Iterator/ExactSizeIterator
            // readings of the same length.
            assert_eq!(
                contest.silenced_iter().count(),
                contest.silenced_iter().len()
            );
        }
    }

    #[test]
    fn path_contest_silenced_iter_matches_silenced_at_across_paths() {
        // Option<PathContest> boundary identity across a multi-path grid:
        //   contest_at(layers, p).map_or(vec![], |c| c.silenced_iter().collect())
        //     == silenced_at(layers, p)
        // Pins the accessor-boundary contract on every fixture cell.
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&platform, &cloud, &tenancy];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["absent"][..],
        ] {
            let via_method: Vec<&'static str> =
                contest_at(&layers, path).map_or(vec![], |c| c.silenced_iter().collect());
            let via_free_fn = silenced_at(&layers, path);
            assert_eq!(
                via_method, via_free_fn,
                "silenced_iter().collect() disagrees with silenced_at at path {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_silenced_iter_rev_reverses_forward_walk_across_fixture() {
        // The reverse walk is the ordered inverse of the forward walk:
        // `.rev().collect()` equals `silenced().to_vec()` with
        // `Vec::reverse` applied to it. Pins the DoubleEndedIterator
        // sharpening against `Vec::reverse` semantics on the same
        // materialized value across the fixture partition.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            vec![sole.as_ref()],
            vec![pair_coarse.as_ref(), pair_specific.as_ref()],
            vec![sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()],
        ] {
            let contest = contest_at(&layers, &["k"]).expect("k is touched");
            let mut expected = contest.silenced().to_vec();
            expected.reverse();
            let reversed: Vec<&'static str> = contest.silenced_iter().rev().collect();
            assert_eq!(reversed, expected);
        }
    }

    #[test]
    fn path_contest_silenced_iter_rev_endpoints_swap_endpoints() {
        // Reverse-endpoint identities on the DoubleEndedIterator: the
        // *back* end of the reverse walk emits `coarsest_silenced` (the
        // original leading element), and the *front* end emits
        // `runner_up` (the original trailing element). The trailing-
        // first specificity walk a diagnostic renderer wants.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).expect("k is touched");
        assert_eq!(contest.silenced_iter().rev().next(), contest.runner_up());
        assert_eq!(
            contest.silenced_iter().rev().last(),
            contest.coarsest_silenced(),
        );
    }

    #[test]
    fn path_contest_silenced_iter_clone_yields_independent_walks() {
        // Clone-then-walk equality: two independent walks over the same
        // substrate-owned overridden slice yield the same sequence,
        // without materializing an owned Vec for the second pass.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).expect("k is touched");
        let a = contest.silenced_iter();
        let b = a.clone();
        let via_a: Vec<&'static str> = a.collect();
        let via_b: Vec<&'static str> = b.collect();
        assert_eq!(via_a, via_b);
        assert_eq!(via_a, contest.silenced().to_vec());
    }

    // -------- PathContest::coarsest --------

    #[test]
    fn path_contest_coarsest_uncontested_singleton_equals_decider() {
        // Structural degenerate: `overridden.is_empty()` ⇒
        // `overridden.first()` is None ⇒ `unwrap_or(decider)` picks
        // `decider`. The identity holds by construction.
        let contest = PathContest {
            decider: "solo",
            overridden: vec![],
        };
        assert_eq!(contest.coarsest(), "solo");
        assert_eq!(contest.coarsest(), contest.decider);
        assert!(!contest.is_contested());
    }

    #[test]
    fn path_contest_coarsest_three_writers_returns_leading_overridden() {
        // Three touchers coarse→specific at breathe.mode.
        // `contributors()` == [platform, cloud, tenancy]; `coarsest`
        // is the leading element `platform`, `decider` is the
        // trailing element `tenancy`, and the two axes are distinct.
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("aws"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let disjoint = Fixed("logger", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&platform, &cloud, &tenancy, &disjoint];
        let contest = contest_at(&layers, &["breathe", "mode"]).expect("three touchers");
        assert_eq!(contest.coarsest(), "platform");
        assert_eq!(contest.decider, "tenancy");
        assert_ne!(contest.coarsest(), contest.decider);
        assert_eq!(
            contest.coarsest(),
            contest.overridden[0],
            "coarsest is the leading overridden entry when contested",
        );
    }

    #[test]
    fn path_contest_coarsest_matches_contributors_first() {
        // Leading-element identity: coarsest() == contributors().first().copied().unwrap()
        // across every branch of touches_path — contested leaf,
        // uncontested leaf, dict container, root, and (skipped) absent.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
        ] {
            let contest = contest_at(&layers, path).expect("some toucher");
            let leading = contest
                .contributors()
                .first()
                .copied()
                .expect("contest is non-empty");
            assert_eq!(
                contest.coarsest(),
                leading,
                "coarsest() != contributors().first() at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_coarsest_matches_contributors_at_first() {
        // Point-primitive identity: contest_at.map(|c| c.coarsest())
        // == contributors_at.first().copied() across every path,
        // including the None boundary (contest_at is None iff
        // contributors_at is empty iff first().copied() is None).
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_fused = contest_at(&layers, path).map(|c| c.coarsest());
            let via_loose = contributors_at(&layers, path).first().copied();
            assert_eq!(
                via_fused, via_loose,
                "coarsest() != contributors_at.first() at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_coarsest_equals_decider_iff_uncontested() {
        // Boolean identity across every touched path: coarsest() ==
        // decider iff overridden is empty. When contested, the two
        // are structurally distinct (coarsest is overridden[0], decider
        // is the trailing toucher).
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],            // only `a` touches — uncontested
            &["breathe"][..],         // dict container both touch — contested
            &["breathe", "mode"][..], // leaf both touch — contested
        ] {
            let contest = contest_at(&layers, path).expect("some toucher");
            let uncontested = !contest.is_contested();
            let coarsest_is_decider = contest.coarsest() == contest.decider;
            assert_eq!(
                uncontested, coarsest_is_decider,
                "!is_contested() != (coarsest == decider) at {path:?}",
            );
        }
    }

    #[test]
    fn path_contest_coarsest_covers_erasure_case() {
        // Prefix-scalar erasure: `a` wrote the deep subtree, `b`
        // erased it with a shallow scalar. Both touch the erased
        // leaf; coarsest names `a` (the axis that opened this key
        // originally, before erasure). Symmetric to the erasure
        // test on contributors(): coarsest gives the leading toucher
        // regardless of whether the trailing toucher is an erasure
        // agent.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        let contest = contest_at(&layers, &["k", "leaf"]).expect("erasure decider is a toucher");
        assert_eq!(contest.coarsest(), "a");
        assert_eq!(contest.decider, "b");
        assert_ne!(contest.coarsest(), contest.decider);
    }

    #[test]
    fn path_contest_coarsest_root_boundary() {
        // Root-path specialization: coarsest is the first
        // contributor_name; decider is the last. Silent layers
        // between them are filtered out on both axes.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let contest = contest_at(&layers, &[]).expect("some non-empty layer at root");
        let names = contributor_names(&layers);
        assert_eq!(
            contest.coarsest(),
            *names.first().expect("some contributor"),
            "root coarsest is first contributor_name",
        );
        assert_eq!(
            contest.decider,
            *names.last().expect("some contributor"),
            "root decider is last contributor_name",
        );
        assert_eq!(contest.coarsest(), "platform");
        assert_eq!(contest.decider, "tenancy");
    }

    // -------- coarsest_at (point primitive) --------

    #[test]
    fn coarsest_at_none_boundary_matches_decider_at_and_contributors_at() {
        // The four None-boundary predicates line up on the same input.
        // coarsest_at is None iff decider_at is None iff contest_at is
        // None iff contributors_at is empty. Structurally: forward-walk
        // finds no toucher exactly when reverse-walk finds none.
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        // No toucher — path is absent.
        assert_eq!(coarsest_at(&layers, &["absent"]), None);
        assert_eq!(decider_at(&layers, &["absent"]), None);
        assert!(contributors_at(&layers, &["absent"]).is_empty());
        assert!(contest_at(&layers, &["absent"]).is_none());
        // Empty layers — no toucher on any path, including root.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(coarsest_at(&empty, &[]), None);
        assert_eq!(decider_at(&empty, &[]), None);
    }

    #[test]
    fn coarsest_at_matches_contributors_at_first_across_paths() {
        // Leading-element identity, the load-bearing point-primitive
        // pin: coarsest_at(layers, p) == contributors_at(layers, p)
        // .first().copied() across every branch of touches_path —
        // contested leaf, uncontested leaf, dict container, root, and
        // the absent (None) boundary.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = coarsest_at(&layers, path);
            let via_loose = contributors_at(&layers, path).first().copied();
            assert_eq!(
                via_primitive, via_loose,
                "coarsest_at != contributors_at.first() at {path:?}",
            );
        }
    }

    #[test]
    fn coarsest_at_matches_contest_at_coarsest_across_paths() {
        // Fused-value identity across the None boundary:
        // coarsest_at(layers, p) == contest_at(layers, p).map(|c|
        // c.coarsest()) — the point primitive is exactly the leading
        // projection off contest_at, and both sides map to None on
        // no-toucher paths. Exercised on the same five-path grid the
        // PathContest::coarsest identity uses.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_primitive = coarsest_at(&layers, path);
            let via_fused = contest_at(&layers, path).map(|c| c.coarsest());
            assert_eq!(
                via_primitive, via_fused,
                "coarsest_at != contest_at.map(|c| c.coarsest()) at {path:?}",
            );
        }
    }

    #[test]
    fn coarsest_at_three_writers_returns_leading_toucher() {
        // Three touchers coarse→specific at breathe.mode. coarsest_at
        // is the leading name `platform`; decider_at is the trailing
        // name `tenancy`; the two are structurally distinct when at
        // least two layers touch. Silent-in-scope layers (`disjoint`
        // touches a different key) do not shift either endpoint.
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("aws"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let disjoint = Fixed("logger", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&platform, &cloud, &tenancy, &disjoint];
        assert_eq!(coarsest_at(&layers, &["breathe", "mode"]), Some("platform"));
        assert_eq!(decider_at(&layers, &["breathe", "mode"]), Some("tenancy"));
        assert_ne!(
            coarsest_at(&layers, &["breathe", "mode"]),
            decider_at(&layers, &["breathe", "mode"]),
        );
    }

    #[test]
    fn coarsest_at_equals_decider_at_iff_at_most_one_toucher() {
        // Pairing identity across every path:
        // coarsest_at == decider_at  iff  contributors_at.len() <= 1.
        // Covers uncontested singletons (equal), no-touchers boundary
        // (both None → equal), and contested (distinct endpoints).
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],            // only `a` touches — uncontested
            &["absent"][..],          // no toucher — both None
            &["breathe"][..],         // dict container both touch — contested
            &["breathe", "mode"][..], // leaf both touch — contested
        ] {
            let coarsest = coarsest_at(&layers, path);
            let decider = decider_at(&layers, path);
            let at_most_one = contributors_at(&layers, path).len() <= 1;
            assert_eq!(
                coarsest == decider,
                at_most_one,
                "coarsest_at == decider_at != (contributors_at.len() <= 1) at {path:?}",
            );
        }
    }

    #[test]
    fn coarsest_at_covers_prefix_scalar_erasure() {
        // Prefix-scalar erasure: `a` opened the deep subtree, `b`
        // erased it with a shallow scalar. Both touch the erased
        // leaf. coarsest_at names `a` (the axis that opened the key
        // originally, before erasure); decider_at names `b` (the
        // erasure agent). Diagnostic renderers reach for the pair to
        // render "opened by `a`, erased by `b`" without materializing
        // the contributors vector or the PathContest wrapper.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert_eq!(coarsest_at(&layers, &["k", "leaf"]), Some("a"));
        assert_eq!(decider_at(&layers, &["k", "leaf"]), Some("b"));
        assert_ne!(
            coarsest_at(&layers, &["k", "leaf"]),
            decider_at(&layers, &["k", "leaf"]),
        );
    }

    #[test]
    fn coarsest_at_root_boundary_equals_first_contributor_name() {
        // Root specialization: coarsest_at(layers, &[]) ==
        // contributor_names(layers).first().copied(). Silent layers
        // between contributors are filtered out on both axes, so an
        // empty layer inserted between two non-empty layers does not
        // shift the endpoint. Dual of decider_at's root
        // specialization at the trailing endpoint.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let names = contributor_names(&layers);
        assert_eq!(coarsest_at(&layers, &[]), names.first().copied());
        assert_eq!(decider_at(&layers, &[]), names.last().copied());
        assert_eq!(coarsest_at(&layers, &[]), Some("platform"));
        assert_eq!(decider_at(&layers, &[]), Some("tenancy"));
    }

    // -------- is_contested_at (point primitive) --------

    #[test]
    fn is_contested_at_false_boundary_on_zero_or_one_toucher() {
        // The false-boundary collapses two structurally distinct cases
        // under the same return: no toucher (contributors_at.is_empty())
        // and single toucher (contributors_at.len() == 1). Both admit
        // an uncontested answer; is_contested_at names the collapsed
        // predicate without disambiguating between them.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed("b", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        // Zero touchers → false.
        assert!(!is_contested_at(&layers, &["absent"]));
        // One toucher (only a) → false.
        assert!(!is_contested_at(&layers, &["solo"]));
        assert!(!is_contested_at(&layers, &["breathe"]));
        assert!(!is_contested_at(&layers, &["breathe", "mode"]));
        // One toucher (only b) → false.
        assert!(!is_contested_at(&layers, &["logger"]));
        // Empty layer stack — no toucher on any path, including root.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!is_contested_at(&empty, &[]));
        assert!(!is_contested_at(&empty, &["absent"]));
    }

    #[test]
    fn is_contested_at_matches_silenced_non_empty_across_paths() {
        // Losers-non-empty identity: is_contested_at(layers, p) ==
        // !silenced_at(layers, p).is_empty(). Both sides pin to the
        // "at least one overridden toucher" predicate on the loose
        // axis. Covers no-toucher, one-toucher, two-toucher, and
        // dict-container paths.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = is_contested_at(&layers, path);
            let via_loose = !silenced_at(&layers, path).is_empty();
            assert_eq!(
                via_primitive, via_loose,
                "is_contested_at != !silenced_at.is_empty() at {path:?}",
            );
        }
    }

    #[test]
    fn is_contested_at_matches_contest_at_is_contested_across_paths() {
        // Fused-value identity across the None boundary:
        // is_contested_at(layers, p) == contest_at(layers, p)
        // .map_or(false, |c| c.is_contested()) — the point primitive
        // is exactly the boolean projection off contest_at, and the
        // None branch on the fused side maps to false in agreement
        // with the no-toucher false branch on the primitive side.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_primitive = is_contested_at(&layers, path);
            let via_fused = contest_at(&layers, path).is_some_and(|c| c.is_contested());
            assert_eq!(
                via_primitive, via_fused,
                "is_contested_at != contest_at.is_some_and(is_contested) at {path:?}",
            );
        }
    }

    #[test]
    fn is_contested_at_matches_contributors_len_ge_two_across_paths() {
        // Cardinality-threshold identity, the load-bearing point-primitive
        // pin: is_contested_at(layers, p) == contributors_at(layers, p)
        // .len() >= 2 across every branch of touches_path. Both sides
        // walk the same filter; the primitive short-circuits at the
        // second hit while the loose Vec walks every layer and then
        // reads the length.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = is_contested_at(&layers, path);
            let via_len = contributors_at(&layers, path).len() >= 2;
            assert_eq!(
                via_primitive, via_len,
                "is_contested_at != contributors_at.len() >= 2 at {path:?}",
            );
        }
    }

    #[test]
    fn is_contested_at_matches_endpoint_inequality_across_paths() {
        // Endpoint-inequality identity: is_contested_at(layers, p) ==
        // (coarsest_at(layers, p) != decider_at(layers, p)). Holds
        // because both-None ⇒ equal ⇒ false (zero touchers, not
        // contested); both-Some(same) ⇒ equal ⇒ false (one toucher,
        // not contested); both-Some with distinct-in-order names ⇒
        // not equal ⇒ true (two+ touchers, contested — decider is
        // reverse-first, coarsest is forward-first, and the two
        // indices differ under the layer-name distinctness contract).
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],            // only `a` touches — uncontested
            &["absent"][..],          // no toucher — both None
            &["breathe"][..],         // dict container both touch — contested
            &["breathe", "mode"][..], // leaf both touch — contested
        ] {
            let via_primitive = is_contested_at(&layers, path);
            let via_endpoints = coarsest_at(&layers, path) != decider_at(&layers, path);
            assert_eq!(
                via_primitive, via_endpoints,
                "is_contested_at != (coarsest_at != decider_at) at {path:?}",
            );
        }
    }

    #[test]
    fn is_contested_at_covers_prefix_scalar_erasure() {
        // Prefix-scalar erasure: `a` opened the deep subtree, `b`
        // erased it with a shallow scalar. Both touch the erased
        // leaf, so is_contested_at is true — the predicate does not
        // require both touchers to survive on the composed dict, only
        // that both touched the path pre-merge. Symmetric to
        // coarsest_at / decider_at's erasure test on their scalar
        // axes.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert!(is_contested_at(&layers, &["k", "leaf"]));
        assert_eq!(coarsest_at(&layers, &["k", "leaf"]), Some("a"));
        assert_eq!(decider_at(&layers, &["k", "leaf"]), Some("b"));
    }

    #[test]
    fn is_contested_at_root_boundary_filters_silent_layers() {
        // Root specialization: silent layers between contributors are
        // filtered on both axes, so a silent layer inserted between
        // two non-empty layers does not shift the predicate — the
        // stack with two non-empty layers is contested at root; the
        // stack with only one non-empty layer is not, regardless of
        // how many silent layers sit alongside it.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers_four: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        assert!(is_contested_at(&layers_four, &[]));
        // Only one non-empty layer at root — silent siblings do not
        // shift the endpoint or the predicate.
        let layers_one: [&dyn DiscoveryLayer; 2] = [&coarse, &silent];
        assert!(!is_contested_at(&layers_one, &[]));
        let layers_zero: [&dyn DiscoveryLayer; 2] = [&silent, &silent];
        assert!(!is_contested_at(&layers_zero, &[]));
    }

    // -------- contributor_count_at (point primitive) --------

    #[test]
    fn contributor_count_at_matches_contributors_len_across_paths() {
        // Length-fold identity: contributor_count_at(layers, p) ==
        // contributors_at(layers, p).len(). Both sides walk the same
        // filter; the primitive folds to usize without allocating the
        // Vec of &'static str.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = contributor_count_at(&layers, path);
            let via_len = contributors_at(&layers, path).len();
            assert_eq!(
                via_primitive, via_len,
                "contributor_count_at != contributors_at.len() at {path:?}",
            );
        }
    }

    #[test]
    fn contributor_count_at_matches_contest_at_contributor_count_across_paths() {
        // Folded-value identity across the None boundary:
        // contributor_count_at(layers, p) == contest_at(layers, p)
        // .map_or(0, |c| c.contributor_count()). The None branch on
        // the fused side maps to 0 in agreement with the no-toucher
        // zero branch on the primitive side.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_primitive = contributor_count_at(&layers, path);
            let via_fused = contest_at(&layers, path).map_or(0, |c| c.contributor_count());
            assert_eq!(
                via_primitive, via_fused,
                "contributor_count_at != contest_at.map_or(0, contributor_count) at {path:?}",
            );
        }
    }

    #[test]
    fn contributor_count_at_matches_partition_across_paths() {
        // Partition-count identity: contributor_count_at(layers, p) ==
        // silenced_at(layers, p).len() + usize::from(decider_at(layers, p)
        // .is_some()). Reads the total off the ordered partition
        // `silenced ⊎ {decider}` in agreement with the direct fold; the
        // zero-toucher branch collapses both terms to zero.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["solo"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = contributor_count_at(&layers, path);
            let via_partition =
                silenced_at(&layers, path).len() + usize::from(decider_at(&layers, path).is_some());
            assert_eq!(
                via_primitive, via_partition,
                "contributor_count_at != silenced_at.len() + decider_at.is_some() at {path:?}",
            );
        }
    }

    #[test]
    fn contributor_count_at_matches_is_contested_threshold_across_paths() {
        // Cardinality-threshold identity: is_contested_at(layers, p) ==
        // (contributor_count_at(layers, p) >= 2). Reads the boolean
        // dual off the scalar with a `>= 2` comparison — the boolean
        // and scalar endpoints of the point-primitive lattice pin
        // to the same touchers walk.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],
            &["absent"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
        ] {
            let via_scalar = contributor_count_at(&layers, path) >= 2;
            let via_bool = is_contested_at(&layers, path);
            assert_eq!(
                via_scalar, via_bool,
                "(contributor_count_at >= 2) != is_contested_at at {path:?}",
            );
        }
    }

    #[test]
    fn contributor_count_at_zero_pins_every_none_endpoint() {
        // Zero-boundary identity: contributor_count_at(layers, p) == 0
        // agrees with contest_at.is_none(), decider_at.is_none(), and
        // coarsest_at.is_none() across every branch. The four
        // None-endpoints on the lattice collapse to the same
        // no-toucher condition; the scalar makes the collapse
        // arithmetic (zero) rather than boolean.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],
            &["absent"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &[][..],
        ] {
            let zero = contributor_count_at(&layers, path) == 0;
            assert_eq!(
                zero,
                contest_at(&layers, path).is_none(),
                "zero != contest_at.is_none() at {path:?}",
            );
            assert_eq!(
                zero,
                decider_at(&layers, path).is_none(),
                "zero != decider_at.is_none() at {path:?}",
            );
            assert_eq!(
                zero,
                coarsest_at(&layers, path).is_none(),
                "zero != coarsest_at.is_none() at {path:?}",
            );
            assert_eq!(
                zero,
                contributors_at(&layers, path).is_empty(),
                "zero != contributors_at.is_empty() at {path:?}",
            );
        }
        // Empty layer stack: no touchers anywhere; count is zero at
        // every path, including the root.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(contributor_count_at(&empty, &[]), 0);
        assert_eq!(contributor_count_at(&empty, &["absent"]), 0);
    }

    #[test]
    fn contributor_count_at_credits_prefix_scalar_erasure_toucher() {
        // Prefix-scalar erasure: `a` opened the deep subtree, `b`
        // erased it with a shallow scalar. Both touch the erased
        // leaf pre-merge, so contributor_count_at at the erased leaf
        // is 2 — the count credits every layer that opined at the
        // path pre-merge, regardless of whether their opinion survived
        // the merge.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert_eq!(contributor_count_at(&layers, &["k", "leaf"]), 2);
        assert_eq!(contributor_count_at(&layers, &["k"]), 2);
    }

    #[test]
    fn contributor_count_at_root_boundary_filters_silent_layers() {
        // Root specialization: silent layers between contributors are
        // filtered on the touchers walk, so a silent layer inserted
        // between two non-empty layers does not shift the count —
        // the stack with three non-empty layers is count-3 at root;
        // the stack with only one non-empty layer is count-1;
        // an all-silent stack is count-0. Symmetric to
        // is_contested_at_root_boundary_filters_silent_layers on the
        // boolean axis.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers_four: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        assert_eq!(contributor_count_at(&layers_four, &[]), 3);
        let layers_one: [&dyn DiscoveryLayer; 2] = [&coarse, &silent];
        assert_eq!(contributor_count_at(&layers_one, &[]), 1);
        let layers_zero: [&dyn DiscoveryLayer; 2] = [&silent, &silent];
        assert_eq!(contributor_count_at(&layers_zero, &[]), 0);
    }

    // -------- silenced_count_at (point primitive losers scalar dual) --------

    #[test]
    fn silenced_count_at_matches_silenced_len_across_paths() {
        // Length-fold identity: silenced_count_at(layers, p) ==
        // silenced_at(layers, p).len(). Both sides walk the same
        // touchers filter; the primitive folds to usize without
        // allocating the losers Vec of &'static str.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = silenced_count_at(&layers, path);
            let via_len = silenced_at(&layers, path).len();
            assert_eq!(
                via_primitive, via_len,
                "silenced_count_at != silenced_at.len() at {path:?}",
            );
        }
    }

    #[test]
    fn silenced_count_at_pins_partition_against_touched_across_paths() {
        // Partition-count identity: silenced_count_at(layers, p) +
        // usize::from(is_touched_at(layers, p)) == contributor_count_at
        // (layers, p). The touchers partition `overridden ⊎ {decider}`
        // reads in pure-scalar arithmetic across every branch of the
        // presence bit.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["absent"][..],
        ] {
            let losers = silenced_count_at(&layers, path);
            let touched = usize::from(is_touched_at(&layers, path));
            let total = contributor_count_at(&layers, path);
            assert_eq!(
                losers + touched,
                total,
                "silenced_count_at + is_touched_at.into() != contributor_count_at at {path:?}",
            );
        }
    }

    #[test]
    fn silenced_count_at_matches_saturating_complement_across_paths() {
        // Complement identity: silenced_count_at(layers, p) ==
        // contributor_count_at(layers, p).saturating_sub(1). The
        // saturating branch collapses the no-toucher zero on the
        // total to zero on the losers count without underflowing.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["solo"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = silenced_count_at(&layers, path);
            let via_complement = contributor_count_at(&layers, path).saturating_sub(1);
            assert_eq!(
                via_primitive, via_complement,
                "silenced_count_at != contributor_count_at.saturating_sub(1) at {path:?}",
            );
        }
        // No-toucher: primitive folds to zero without underflow.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(silenced_count_at(&empty, &[]), 0);
        assert_eq!(silenced_count_at(&empty, &["absent"]), 0);
        assert_eq!(silenced_count_at(&empty, &["a", "b", "c"]), 0);
    }

    #[test]
    fn silenced_count_at_matches_is_contested_threshold_across_paths() {
        // Cardinality-threshold identity: is_contested_at(layers, p) ==
        // (silenced_count_at(layers, p) >= 1). The boolean predicate
        // endpoint of the losers axis pins onto its scalar cardinality
        // with a `>= 1` comparison, and the zero-boundary identity
        // silenced_count_at(layers, p) == 0 ⇔ !is_contested_at
        // collapses both the no-toucher and the uncontested-singleton
        // cases onto the same arithmetic zero.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &["solo"][..],
            &["absent"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
        ] {
            let via_scalar_ge_one = silenced_count_at(&layers, path) >= 1;
            let via_bool = is_contested_at(&layers, path);
            assert_eq!(
                via_scalar_ge_one, via_bool,
                "(silenced_count_at >= 1) != is_contested_at at {path:?}",
            );
            let via_scalar_zero = silenced_count_at(&layers, path) == 0;
            assert_eq!(
                via_scalar_zero, !via_bool,
                "(silenced_count_at == 0) != !is_contested_at at {path:?}",
            );
        }
    }

    #[test]
    fn silenced_count_at_matches_contest_at_silenced_count_across_paths() {
        // Folded-value identity across the None boundary:
        // silenced_count_at(layers, p) == contest_at(layers, p)
        // .map_or(0, |c| c.silenced_count()). The `None` branch on the
        // fused side maps to zero in agreement with the no-toucher
        // zero branch on the primitive side.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_primitive = silenced_count_at(&layers, path);
            let via_fused = contest_at(&layers, path).map_or(0, |c| c.silenced_count());
            assert_eq!(
                via_primitive, via_fused,
                "silenced_count_at != contest_at.map_or(0, silenced_count) at {path:?}",
            );
        }
    }

    #[test]
    fn silenced_count_at_credits_prefix_scalar_erasure_toucher() {
        // Prefix-scalar erasure: `a` opened the deep subtree, `b`
        // erased it with a shallow scalar. Both touch the erased leaf
        // pre-merge, so contributor_count_at is 2 and silenced_count_at
        // is 1 at the erased leaf — `a` is the coarsest toucher and
        // its opinion at the deep leaf lost the contest even though
        // no leaf survived at that path in the composed dict. The
        // losers-scalar credits every layer whose pre-merge touch was
        // overridden regardless of leaf survival.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert_eq!(silenced_count_at(&layers, &["k", "leaf"]), 1);
        assert_eq!(silenced_count_at(&layers, &["k"]), 1);
        // Sibling nobody touched: the losers-scalar is zero, matching
        // the no-toucher branch of the touchers partition.
        assert_eq!(silenced_count_at(&layers, &["unrelated"]), 0);
    }

    #[test]
    fn silenced_count_at_root_boundary_filters_silent_layers() {
        // Root specialization: silent layers between contributors are
        // filtered on the touchers walk, so a silent layer inserted
        // between two non-empty layers does not shift the losers
        // count — the stack with three non-empty layers is losers-2
        // at root; the stack with only one non-empty layer is
        // losers-0 (uncontested singleton); an all-silent stack is
        // losers-0 (no-toucher). Symmetric to
        // contributor_count_at_root_boundary_filters_silent_layers on
        // the winners+losers axis.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers_four: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        assert_eq!(silenced_count_at(&layers_four, &[]), 2);
        let layers_one: [&dyn DiscoveryLayer; 2] = [&coarse, &silent];
        assert_eq!(silenced_count_at(&layers_one, &[]), 0);
        let layers_zero: [&dyn DiscoveryLayer; 2] = [&silent, &silent];
        assert_eq!(silenced_count_at(&layers_zero, &[]), 0);
    }

    #[test]
    fn path_contest_silenced_count_field_length_projection() {
        // Method identity on the PathContest struct: c.silenced_count()
        // == c.overridden.len() and c.silenced_count() + 1 ==
        // c.contributor_count(). The winners-scalar is the losers-scalar
        // plus exactly one for the decider — a PathContest value
        // always carries a decider, so the arithmetic never saturates.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];

        // Contested path (three touchers): silenced_count == 2.
        let contested = contest_at(&layers, &["breathe", "mode"]).expect("some toucher");
        assert_eq!(contested.silenced_count(), contested.overridden.len());
        assert_eq!(contested.silenced_count(), 2);
        assert_eq!(
            contested.silenced_count() + 1,
            contested.contributor_count()
        );
        assert!(contested.silenced_count() >= 1);
        assert!(contested.is_contested());

        // Uncontested singleton: silenced_count == 0.
        let singleton = contest_at(&layers, &["breathe", "setpoint"]).expect("some toucher");
        assert_eq!(singleton.silenced_count(), 0);
        assert_eq!(
            singleton.silenced_count() + 1,
            singleton.contributor_count()
        );
        assert!(!singleton.is_contested());
    }

    #[test]
    fn is_touched_at_matches_contributor_count_ge_one_across_paths() {
        // Cardinality-threshold identity at "≥ 1": is_touched_at(layers,
        // p) == (contributor_count_at(layers, p) >= 1). The "≥ 1"
        // predicate endpoint of the point-primitive lattice reads off
        // the scalar cardinality with the same walk as `is_contested_at`
        // reads its "≥ 2" endpoint.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &[][..],
            &["solo"][..],
            &["absent"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
        ] {
            let via_bool = is_touched_at(&layers, path);
            let via_scalar = contributor_count_at(&layers, path) >= 1;
            assert_eq!(
                via_bool, via_scalar,
                "is_touched_at != (contributor_count_at >= 1) at {path:?}",
            );
        }
    }

    #[test]
    fn is_touched_at_pins_every_none_endpoint_across_paths() {
        // Presence-boundary identity: is_touched_at agrees with
        // contest_at.is_some(), decider_at.is_some(), coarsest_at
        // .is_some(), and !contributors_at.is_empty() at every path.
        // The five presence-projections on the lattice collapse onto
        // one boolean answer; the primitive returns it as a bare
        // `bool` without materializing a name or an owned Vec.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["absent"][..],
            &["breathe", "absent"][..],
        ] {
            let touched = is_touched_at(&layers, path);
            assert_eq!(
                touched,
                contest_at(&layers, path).is_some(),
                "is_touched_at != contest_at.is_some() at {path:?}",
            );
            assert_eq!(
                touched,
                decider_at(&layers, path).is_some(),
                "is_touched_at != decider_at.is_some() at {path:?}",
            );
            assert_eq!(
                touched,
                coarsest_at(&layers, path).is_some(),
                "is_touched_at != coarsest_at.is_some() at {path:?}",
            );
            assert_eq!(
                touched,
                !contributors_at(&layers, path).is_empty(),
                "is_touched_at != !contributors_at.is_empty() at {path:?}",
            );
        }
        // Empty layer stack: no touchers anywhere; the predicate is
        // false at every path, including the root.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!is_touched_at(&empty, &[]));
        assert!(!is_touched_at(&empty, &["absent"]));
    }

    #[test]
    fn is_touched_at_matches_monotonic_chain_against_is_contested_at() {
        // Monotonic chain: is_contested_at(p) ⇒ is_touched_at(p) and
        // !is_touched_at(p) ⇒ !is_contested_at(p). The two boolean
        // endpoints of the cardinality-threshold lattice at "≥ 2" and
        // "≥ 1" shift the predicate axis by exactly one hit, so the
        // implication is one-directional on every branch of every path.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        for path in [
            &[][..],
            &["solo"][..],
            &["absent"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
        ] {
            let touched = is_touched_at(&layers, path);
            let contested = is_contested_at(&layers, path);
            assert!(
                !contested || touched,
                "is_contested_at ⇒ is_touched_at broken at {path:?}",
            );
            assert!(
                touched || !contested,
                "!is_touched_at ⇒ !is_contested_at broken at {path:?}",
            );
        }
    }

    #[test]
    fn is_touched_at_singleton_characterization_across_paths() {
        // Singleton characterization: is_touched_at && !is_contested_at
        // ⇔ contributor_count_at == 1. The intersection of the two
        // boolean endpoints selects exactly the exact-cardinality-one
        // branch of the three-way partition (0 / 1 / ≥ 2).
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["solo"][..],
            &["logger"][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["absent"][..],
        ] {
            let singleton_via_bools =
                is_touched_at(&layers, path) && !is_contested_at(&layers, path);
            let singleton_via_scalar = contributor_count_at(&layers, path) == 1;
            assert_eq!(
                singleton_via_bools, singleton_via_scalar,
                "singleton characterization broken at {path:?}",
            );
        }
    }

    #[test]
    fn is_touched_at_credits_prefix_scalar_erasure_toucher() {
        // Prefix-scalar erasure: `a` opened the deep subtree, `b`
        // erased it with a shallow scalar. Both pre-merge touch the
        // erased leaf, so is_touched_at at the erased leaf is true
        // — the predicate credits the pre-merge touch even though
        // the leaf does not survive the merge. Same semantics as
        // `contributor_count_at` (which counts to 2 here); the
        // predicate collapses the count-2 outcome to the ≥ 1 branch.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert!(is_touched_at(&layers, &["k", "leaf"]));
        assert!(is_touched_at(&layers, &["k"]));
        // A sibling key nobody touched: no layer has an opinion at
        // `unrelated`, so the predicate is false. The prefix-scalar
        // `b` at `k` only propagates touches *below* `k`, not to
        // sibling keys.
        assert!(!is_touched_at(&layers, &["unrelated"]));
        assert!(!is_touched_at(&layers, &["unrelated", "deep"]));
    }

    #[test]
    fn is_touched_at_root_boundary_filters_silent_layers() {
        // Root specialization: any non-empty layer flips the predicate
        // to true at the root; an all-silent stack keeps it false.
        // Silent layers between contributors don't shift the answer,
        // matching the touchers-walk semantics of every other point
        // primitive on the (path, layer) axis.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers_two_non_empty: [&dyn DiscoveryLayer; 3] = [&coarse, &silent, &specific];
        assert!(is_touched_at(&layers_two_non_empty, &[]));
        let layers_one: [&dyn DiscoveryLayer; 2] = [&coarse, &silent];
        assert!(is_touched_at(&layers_one, &[]));
        let layers_only_silent: [&dyn DiscoveryLayer; 2] = [&silent, &silent];
        assert!(!is_touched_at(&layers_only_silent, &[]));
    }

    // -------- contributor_count (root scalar-cardinality) --------

    fn count_contributor_fixture() -> [Box<dyn DiscoveryLayer>; 6] {
        // Two contributors, one silent, another contributor, another
        // silent, another contributor — a stack with three non-empty
        // layers and two empty ones. Order preserves the coarse→specific
        // discipline.
        [
            Box::new(Fixed("platform", dict(&[("a", Value::from(1i64))]))),
            Box::new(Fixed("undetectable_kanchi", Dict::new())),
            Box::new(Fixed(
                "tenancy",
                dict(&[("b", Value::from(dict(&[("nested", Value::from(2i64))])))]),
            )),
            Box::new(Fixed("host_silent", Dict::new())),
            Box::new(Fixed("user", dict(&[("c", Value::from("v"))]))),
            Box::new(Fixed("undetectable_hostgroup", Dict::new())),
        ]
    }

    fn as_refs(layers: &[Box<dyn DiscoveryLayer>]) -> Vec<&dyn DiscoveryLayer> {
        layers.iter().map(std::convert::AsRef::as_ref).collect()
    }

    #[test]
    fn contributor_count_matches_contributor_names_len() {
        // Length-fold identity: contributor_count(layers) ==
        // contributor_names(layers).len(). Both sides read from the same
        // non-empty-discover predicate; the scalar folds the ordered
        // Vec<&'static str> to its length without allocating it.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = contributor_count(&layers);
        let via_names_len = contributor_names(&layers).len();
        assert_eq!(
            via_primitive, via_names_len,
            "contributor_count != contributor_names.len()",
        );
        assert_eq!(via_primitive, 3, "three non-empty layers in the fixture");
    }

    #[test]
    fn contributor_count_matches_nonempty_layer_dicts_len() {
        // Length-fold identity on the (name, dict) pair axis:
        // contributor_count(layers) == nonempty_layer_dicts(layers).len().
        // The pair projection allocates each contributor's dict on the
        // way to its `Vec`; the scalar avoids the clone entirely.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = contributor_count(&layers);
        let via_pairs_len = nonempty_layer_dicts(&layers).len();
        assert_eq!(
            via_primitive, via_pairs_len,
            "contributor_count != nonempty_layer_dicts.len()",
        );
    }

    #[test]
    fn contributor_count_matches_contributor_count_at_root() {
        // Root-specialization identity: contributor_count(layers) ==
        // contributor_count_at(layers, &[]). The point primitive at the
        // empty path folds to the same non-empty-discover predicate this
        // root primitive uses directly.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_root = contributor_count(&layers);
        let via_point_at_root = contributor_count_at(&layers, &[]);
        assert_eq!(
            via_root, via_point_at_root,
            "contributor_count != contributor_count_at(layers, &[])",
        );

        // Also holds on degenerate stacks — the empty layer stack and
        // the all-silent stack both fold to zero on both sides.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(contributor_count(&empty), 0);
        assert_eq!(contributor_count(&empty), contributor_count_at(&empty, &[]));

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(contributor_count(&all_silent), 0);
        assert_eq!(
            contributor_count(&all_silent),
            contributor_count_at(&all_silent, &[]),
        );
    }

    #[test]
    fn contributor_count_partition_pins_layer_names_len() {
        // Partition-count identity: contributor_count(layers) +
        // silent_layer_names(layers).len() == layer_names(layers).len().
        // Every declared axis belongs to exactly one of the two subsets
        // (non-empty ⇒ contributor, empty ⇒ silent) by the
        // silent-layer partition law in silent_layer_names's doc.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let contributors = contributor_count(&layers);
        let silent_len = silent_layer_names(&layers).len();
        let declared = layer_names(&layers).len();
        assert_eq!(
            contributors + silent_len,
            declared,
            "contributor_count + silent_layer_names.len() != layer_names.len()",
        );
        assert_eq!(contributors, 3, "three contributors");
        assert_eq!(silent_len, 3, "three silent layers");
        assert_eq!(declared, 6, "six declared layers");
    }

    #[test]
    fn contributor_count_zero_pins_root_presence_endpoints() {
        // Cardinality-threshold identity at the whole-layer boundary:
        // contributor_count(layers) == 0 ⇔ !is_touched_at(layers, &[]).
        // Every neighboring root-boundary endpoint (contributor_names,
        // nonempty_layer_dicts) collapses to the same emptiness bit at
        // the same partition, so the scalar's zero is the whole-layer
        // presence bit read arithmetically.
        let empty_stack: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(contributor_count(&empty_stack), 0);
        assert!(!is_touched_at(&empty_stack, &[]));
        assert!(contributor_names(&empty_stack).is_empty());
        assert!(nonempty_layer_dicts(&empty_stack).is_empty());

        let silent = Fixed("undetectable", Dict::new());
        let only_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(contributor_count(&only_silent), 0);
        assert!(!is_touched_at(&only_silent, &[]));
        assert!(contributor_names(&only_silent).is_empty());
        assert!(nonempty_layer_dicts(&only_silent).is_empty());

        // One-contributor stack lifts the count to 1 and every
        // neighboring endpoint out of its zero-boundary in lockstep.
        let one = Fixed("only", dict(&[("k", Value::from(1i64))]));
        let one_and_silence: [&dyn DiscoveryLayer; 3] = [&silent, &one, &silent];
        assert_eq!(contributor_count(&one_and_silence), 1);
        assert!(is_touched_at(&one_and_silence, &[]));
        assert_eq!(contributor_names(&one_and_silence).len(), 1);
        assert_eq!(nonempty_layer_dicts(&one_and_silence).len(), 1);
    }

    #[test]
    fn contributor_count_bounded_by_layer_names_len() {
        // Bound invariant: 0 <= contributor_count(layers) <=
        // layer_names(layers).len(). The upper bound is achieved when
        // every declared layer is a contributor; the lower bound when
        // every declared layer is silent. Both endpoints hit the
        // partition-count identity on their respective boundaries.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);
        let total_declared = layer_names(&layers).len();
        let contributors = contributor_count(&layers);
        assert!(
            contributors <= total_declared,
            "contributor_count > layer_names.len()",
        );

        // Upper-bound endpoint: every layer is a contributor.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(
            contributor_count(&all_contribute),
            layer_names(&all_contribute).len(),
            "upper bound: every layer is a contributor",
        );

        // Lower-bound endpoint: every layer is silent.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(contributor_count(&all_silent), 0, "lower bound: all silent");
    }

    // -------- silent_layer_count (root scalar-cardinality dual) --------

    #[test]
    fn silent_layer_count_matches_silent_layer_names_len() {
        // Length-fold identity on the silent-names axis:
        // silent_layer_count(layers) == silent_layer_names(layers).len().
        // Both sides read from the same is-empty-discover predicate; the
        // scalar folds the ordered Vec<&'static str> to its length
        // without allocating it.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = silent_layer_count(&layers);
        let via_names_len = silent_layer_names(&layers).len();
        assert_eq!(
            via_primitive, via_names_len,
            "silent_layer_count != silent_layer_names.len()",
        );
        assert_eq!(via_primitive, 3, "three silent layers in the fixture");
    }

    #[test]
    fn silent_layer_count_pure_scalar_partition_pins_layer_names_len() {
        // Pure-scalar partition-count identity:
        //   silent_layer_count(layers) + contributor_count(layers)
        //       == layer_names(layers).len().
        // Every declared axis belongs to exactly one of the two subsets
        // by the silent-layer partition law. Neither addend materializes
        // a name Vec; the whole-layer partition arithmetic reads with
        // zero allocation on both sides.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let silent = silent_layer_count(&layers);
        let contributors = contributor_count(&layers);
        let declared = layer_names(&layers).len();
        assert_eq!(
            silent + contributors,
            declared,
            "silent_layer_count + contributor_count != layer_names.len()",
        );
        assert_eq!(silent, 3, "three silent layers");
        assert_eq!(contributors, 3, "three contributors");
        assert_eq!(declared, 6, "six declared layers");
    }

    #[test]
    fn silent_layer_count_complements_contributor_count() {
        // Complement identity: silent_layer_count(layers) ==
        // layer_names(layers).len() - contributor_count(layers). The
        // partition law rewritten as subtraction — the silent count is
        // the missing addend on the declared-count denominator when the
        // contributor count is already in hand.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = silent_layer_count(&layers);
        let via_complement = layer_names(&layers).len() - contributor_count(&layers);
        assert_eq!(
            via_primitive, via_complement,
            "silent_layer_count != layer_names.len() - contributor_count",
        );

        // Complement identity holds on the two degenerate stacks as
        // well: on the empty stack, both sides fold to zero; on the
        // all-silent stack, both sides fold to the declared length.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(silent_layer_count(&empty), 0);
        assert_eq!(
            silent_layer_count(&empty),
            layer_names(&empty).len() - contributor_count(&empty),
        );

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(silent_layer_count(&all_silent), 3);
        assert_eq!(
            silent_layer_count(&all_silent),
            layer_names(&all_silent).len() - contributor_count(&all_silent),
        );
    }

    #[test]
    fn silent_layer_count_zero_pins_all_contribute_endpoint() {
        // Cardinality-threshold endpoint at the silent-axis lower
        // boundary: silent_layer_count == 0 ⇔ every declared layer is a
        // contributor ⇔ silent_layer_names is empty. Every neighboring
        // silent-axis endpoint collapses to the same emptiness bit at
        // the same partition, so the scalar's zero is the "no undetected
        // axes" bit read arithmetically.
        let empty_stack: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(silent_layer_count(&empty_stack), 0);
        assert!(silent_layer_names(&empty_stack).is_empty());

        // Every-layer-contributes stack lifts contributor_count to the
        // declared length and pins silent_layer_count to zero in
        // lockstep.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(silent_layer_count(&all_contribute), 0);
        assert!(silent_layer_names(&all_contribute).is_empty());
        assert_eq!(
            contributor_count(&all_contribute),
            layer_names(&all_contribute).len(),
        );
    }

    #[test]
    fn silent_layer_count_saturates_at_all_silent_endpoint() {
        // Cardinality-threshold endpoint at the silent-axis upper
        // boundary: silent_layer_count == layer_names.len() ⇔ every
        // declared layer is silent ⇔ contributor_count == 0 ⇔
        // !is_touched_at(layers, &[]). Every neighboring endpoint
        // collapses to the same emptiness bit at the same partition, so
        // the scalar's saturation is the "no contributor axes" bit read
        // arithmetically.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(silent_layer_count(&all_silent), 3);
        assert_eq!(
            silent_layer_count(&all_silent),
            layer_names(&all_silent).len()
        );
        assert_eq!(contributor_count(&all_silent), 0);
        assert!(!is_touched_at(&all_silent, &[]));
        assert!(contributor_names(&all_silent).is_empty());
        assert!(nonempty_layer_dicts(&all_silent).is_empty());
    }

    #[test]
    fn silent_layer_count_bounded_by_layer_names_len() {
        // Bound invariant: 0 <= silent_layer_count(layers) <=
        // layer_names(layers).len(). The upper bound is achieved when
        // every declared layer is silent; the lower bound when every
        // declared layer is a contributor. Both endpoints hit the
        // partition-count identity on their respective boundaries.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);
        let total_declared = layer_names(&layers).len();
        let silent = silent_layer_count(&layers);
        assert!(
            silent <= total_declared,
            "silent_layer_count > layer_names.len()",
        );

        // Upper-bound endpoint: every layer is silent.
        let silent_layer = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent_layer, &silent_layer, &silent_layer];
        assert_eq!(
            silent_layer_count(&all_silent),
            layer_names(&all_silent).len(),
            "upper bound: every layer is silent",
        );

        // Lower-bound endpoint: every layer is a contributor.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(
            silent_layer_count(&all_contribute),
            0,
            "lower bound: every layer is a contributor",
        );
    }

    // -------- has_contributor (root ≥1 boolean predicate) --------

    #[test]
    fn has_contributor_matches_contributor_names_nonempty() {
        // Ordered-list emptiness dual on the contributors axis:
        // has_contributor(layers) == !contributor_names(layers).is_empty().
        // Both sides read from the same non-empty-discover predicate; the
        // boolean returns the first-hit bit without allocating the name Vec.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_contributor(&layers);
        let via_names_nonempty = !contributor_names(&layers).is_empty();
        assert_eq!(
            via_primitive, via_names_nonempty,
            "has_contributor != !contributor_names.is_empty()",
        );
        assert!(via_primitive, "the fixture has three contributors");
    }

    #[test]
    fn has_contributor_matches_contributor_count_threshold() {
        // Cardinality-threshold identity at "≥ 1":
        // has_contributor(layers) == contributor_count(layers) >= 1.
        // Both routes share the non-empty-discover predicate; the boolean
        // short-circuits at the first contributor, the scalar walks the
        // whole stack.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_contributor(&layers);
        let via_threshold = contributor_count(&layers) >= 1;
        assert_eq!(
            via_primitive, via_threshold,
            "has_contributor != contributor_count >= 1",
        );

        // Threshold identity holds on both degenerate stacks: the empty
        // stack (count == 0 ⇒ false) and the all-silent stack (count == 0
        // ⇒ false) both collapse the "≥ 1" bit and the boolean to false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_contributor(&empty));
        assert_eq!(has_contributor(&empty), contributor_count(&empty) >= 1);

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!has_contributor(&all_silent));
        assert_eq!(
            has_contributor(&all_silent),
            contributor_count(&all_silent) >= 1,
        );
    }

    #[test]
    fn has_contributor_matches_nonempty_layer_dicts_nonempty() {
        // Ordered-pair emptiness dual on the (name, dict) axis:
        // has_contributor(layers) == !nonempty_layer_dicts(layers).is_empty().
        // Both sides share the non-empty-discover predicate; the boolean
        // avoids cloning any contributor's dict on the way to the bit.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_contributor(&layers);
        let via_pairs_nonempty = !nonempty_layer_dicts(&layers).is_empty();
        assert_eq!(
            via_primitive, via_pairs_nonempty,
            "has_contributor != !nonempty_layer_dicts.is_empty()",
        );
    }

    #[test]
    fn has_contributor_matches_is_touched_at_root() {
        // Whole-layer→point-path root-specialization identity:
        // has_contributor(layers) == is_touched_at(layers, &[]).
        // The general point predicate at the empty path folds through
        // touches_path(&dict, &[]) == !dict.is_empty() — the same
        // non-empty-discover predicate this root primitive uses directly.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_root = has_contributor(&layers);
        let via_point_at_root = is_touched_at(&layers, &[]);
        assert_eq!(
            via_root, via_point_at_root,
            "has_contributor != is_touched_at(layers, &[])",
        );

        // Root-specialization identity holds on both degenerate stacks.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(has_contributor(&empty), is_touched_at(&empty, &[]));
        assert!(!has_contributor(&empty));

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(
            has_contributor(&all_silent),
            is_touched_at(&all_silent, &[]),
        );
        assert!(!has_contributor(&all_silent));
    }

    #[test]
    fn has_contributor_partition_complement_matches_silent_layer_count() {
        // Partition-complement identity:
        //   has_contributor(layers) == (silent_layer_count(layers)
        //                              < layer_names(layers).len()).
        // "Some declared layer contributes" iff "not every declared layer
        // is silent", which is the partition-count law rewritten as a
        // strict inequality between the silent-side scalar and the
        // declared denominator. Holds across the empty stack (0 < 0 is
        // false; has_contributor is also false) and the fully-populated
        // stacks in pure-scalar arithmetic.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_contributor(&layers);
        let via_complement = silent_layer_count(&layers) < layer_names(&layers).len();
        assert_eq!(
            via_primitive, via_complement,
            "has_contributor != (silent_layer_count < layer_names.len())",
        );

        // Empty stack: 0 < 0 is false; has_contributor is also false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(
            has_contributor(&empty),
            silent_layer_count(&empty) < layer_names(&empty).len(),
        );
        assert!(!has_contributor(&empty));

        // All-silent stack: silent_layer_count == layer_names.len(), so
        // the strict inequality is false; has_contributor is also false.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(
            has_contributor(&all_silent),
            silent_layer_count(&all_silent) < layer_names(&all_silent).len(),
        );
        assert!(!has_contributor(&all_silent));

        // All-contribute stack: silent_layer_count == 0 < layer_names.len(),
        // so the strict inequality is true; has_contributor is also true.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(
            has_contributor(&all_contribute),
            silent_layer_count(&all_contribute) < layer_names(&all_contribute).len(),
        );
        assert!(has_contributor(&all_contribute));
    }

    #[test]
    fn has_contributor_partition_truth_table() {
        // 2×2 truth table over (has_contributor, silent_layer_count >= 1)
        // covering the four disjoint states of the whole-layer partition:
        //   (F, F) ⇔ empty stack (nothing declared)
        //   (T, F) ⇔ every declared layer contributes
        //   (F, T) ⇔ every declared layer is silent
        //   (T, T) ⇔ mixed stack (some contribute, some silent)
        //
        // Each state is reached by a distinct fixture; the pair pins the
        // whole-layer partition's boolean row as an ordered-pair equality
        // against a hand-computed truth table.

        // (F, F): the empty stack — nothing declared.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_contributor(&empty));
        assert!(silent_layer_count(&empty) == 0);

        // (T, F): every declared layer contributes.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(has_contributor(&all_contribute));
        assert!(silent_layer_count(&all_contribute) == 0);

        // (F, T): every declared layer is silent.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!has_contributor(&all_silent));
        assert!(silent_layer_count(&all_silent) >= 1);

        // (T, T): mixed stack (the fixture — three contributors and three
        // silent layers interleaved).
        let owned = count_contributor_fixture();
        let mixed = as_refs(&owned);
        assert!(has_contributor(&mixed));
        assert!(silent_layer_count(&mixed) >= 1);
    }

    #[test]
    fn has_contributor_short_circuits_on_coarsest_hit() {
        // Short-circuit correctness: a stack with the coarsest layer as
        // the sole contributor and every later layer silent still returns
        // true. Iterator::any's short-circuit compiles to the same output
        // as a full walk on the correctness axis; this test pins the bit
        // rather than the walk length (which is not observable from the
        // returned bool), covering the best-case O(1) endpoint by
        // constructing a stack where any::any() logically terminates on
        // the first element.
        let head = Fixed("platform", dict(&[("k", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let coarsest_hit: [&dyn DiscoveryLayer; 4] = [&head, &silent, &silent, &silent];
        assert!(has_contributor(&coarsest_hit));
        assert_eq!(
            has_contributor(&coarsest_hit),
            contributor_count(&coarsest_hit) >= 1
        );

        // Dual short-circuit: the trailing contributor case — every
        // earlier layer is silent and the last is the sole contributor —
        // still folds to true (no short-circuit, worst-case walk on the
        // any::any() path, but the returned bit is unchanged).
        let tail_only: [&dyn DiscoveryLayer; 4] = [&silent, &silent, &silent, &head];
        assert!(has_contributor(&tail_only));
        assert_eq!(
            has_contributor(&tail_only),
            contributor_count(&tail_only) >= 1
        );
    }

    // -------- has_silent_layer (root ≥1 boolean predicate on the silent axis) --------

    #[test]
    fn has_silent_layer_matches_silent_layer_names_nonempty() {
        // Ordered-list emptiness dual on the silent axis:
        // has_silent_layer(layers) == !silent_layer_names(layers).is_empty().
        // Both sides read from the same is-empty-discover predicate; the
        // boolean returns the first-hit bit without allocating the name Vec.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_silent_layer(&layers);
        let via_names_nonempty = !silent_layer_names(&layers).is_empty();
        assert_eq!(
            via_primitive, via_names_nonempty,
            "has_silent_layer != !silent_layer_names.is_empty()",
        );
        assert!(via_primitive, "the fixture has three silent layers");
    }

    #[test]
    fn has_silent_layer_matches_silent_layer_count_threshold() {
        // Cardinality-threshold identity at "≥ 1":
        // has_silent_layer(layers) == silent_layer_count(layers) >= 1.
        // Both routes share the is-empty-discover predicate; the boolean
        // short-circuits at the first silent layer, the scalar walks the
        // whole stack.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_silent_layer(&layers);
        let via_threshold = silent_layer_count(&layers) >= 1;
        assert_eq!(
            via_primitive, via_threshold,
            "has_silent_layer != silent_layer_count >= 1",
        );

        // Threshold identity holds on both zero-silent-layer degenerate
        // stacks: the empty stack (count == 0 ⇒ false) and the
        // all-contribute stack (count == 0 ⇒ false) both collapse the
        // "≥ 1" bit and the boolean to false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_silent_layer(&empty));
        assert_eq!(has_silent_layer(&empty), silent_layer_count(&empty) >= 1);

        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(!has_silent_layer(&all_contribute));
        assert_eq!(
            has_silent_layer(&all_contribute),
            silent_layer_count(&all_contribute) >= 1,
        );
    }

    #[test]
    fn has_silent_layer_partition_complement_matches_contributor_count() {
        // Partition-complement identity:
        //   has_silent_layer(layers) == (contributor_count(layers)
        //                                < layer_names(layers).len()).
        // "Some declared layer is silent" iff "not every declared layer
        // is a contributor", which is the partition-count law rewritten
        // as a strict inequality between the contributor-side scalar and
        // the declared denominator. Holds across the empty stack (0 < 0 is
        // false; has_silent_layer is also false) and the fully-populated
        // stacks in pure-scalar arithmetic.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_silent_layer(&layers);
        let via_complement = contributor_count(&layers) < layer_names(&layers).len();
        assert_eq!(
            via_primitive, via_complement,
            "has_silent_layer != (contributor_count < layer_names.len())",
        );

        // Empty stack: 0 < 0 is false; has_silent_layer is also false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(
            has_silent_layer(&empty),
            contributor_count(&empty) < layer_names(&empty).len(),
        );
        assert!(!has_silent_layer(&empty));

        // All-contribute stack: contributor_count == layer_names.len(),
        // so the strict inequality is false; has_silent_layer is also
        // false.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(
            has_silent_layer(&all_contribute),
            contributor_count(&all_contribute) < layer_names(&all_contribute).len(),
        );
        assert!(!has_silent_layer(&all_contribute));

        // All-silent stack: contributor_count == 0 < layer_names.len(),
        // so the strict inequality is true; has_silent_layer is also
        // true.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(
            has_silent_layer(&all_silent),
            contributor_count(&all_silent) < layer_names(&all_silent).len(),
        );
        assert!(has_silent_layer(&all_silent));
    }

    #[test]
    fn has_silent_layer_matches_nonempty_layer_dicts_partition() {
        // Pair-partition-complement identity:
        //   has_silent_layer(layers) == (nonempty_layer_dicts(layers).len()
        //                                < layer_names(layers).len()).
        // The (name, dict) pair Vec has one entry per contributor, so its
        // length is the same partition scalar as contributor_count; the
        // identity closes the strict inequality against layer_names on
        // the pair-projection altitude.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_silent_layer(&layers);
        let via_pairs = nonempty_layer_dicts(&layers).len() < layer_names(&layers).len();
        assert_eq!(
            via_primitive, via_pairs,
            "has_silent_layer != (nonempty_layer_dicts.len() < layer_names.len())",
        );
    }

    #[test]
    fn has_silent_layer_partition_truth_table_vs_has_contributor() {
        // 2×2 truth table over (has_contributor, has_silent_layer)
        // covering the four disjoint states of the whole-layer partition:
        //   (F, F) ⇔ empty stack (nothing declared)
        //   (T, F) ⇔ every declared layer contributes
        //   (F, T) ⇔ every declared layer is silent
        //   (T, T) ⇔ mixed stack (some contribute, some silent)
        //
        // Each state is reached by a distinct fixture; the pair pins the
        // whole-layer partition as an ordered-pair equality against a
        // hand-computed truth table, closing the partition in
        // short-circuiting boolean arithmetic on both subsets at once
        // (replacing the mixed scalar/boolean formulation in
        // has_contributor's prior truth table against silent_layer_count).

        // (F, F): the empty stack — nothing declared.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_contributor(&empty));
        assert!(!has_silent_layer(&empty));

        // (T, F): every declared layer contributes.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(has_contributor(&all_contribute));
        assert!(!has_silent_layer(&all_contribute));

        // (F, T): every declared layer is silent.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!has_contributor(&all_silent));
        assert!(has_silent_layer(&all_silent));

        // (T, T): mixed stack (the fixture — three contributors and
        // three silent layers interleaved).
        let owned = count_contributor_fixture();
        let mixed = as_refs(&owned);
        assert!(has_contributor(&mixed));
        assert!(has_silent_layer(&mixed));
    }

    #[test]
    fn has_silent_layer_short_circuits_on_coarsest_silent() {
        // Short-circuit correctness: a stack with the coarsest layer as
        // the sole silent one and every later layer contributing still
        // returns true. Iterator::any's short-circuit compiles to the
        // same output as a full walk on the correctness axis; this test
        // pins the bit rather than the walk length (which is not
        // observable from the returned bool), covering the best-case O(1)
        // endpoint by constructing a stack where any::any() logically
        // terminates on the first element.
        let silent = Fixed("undetectable", Dict::new());
        let contrib = Fixed("k", dict(&[("k", Value::from(1i64))]));
        let coarsest_silent: [&dyn DiscoveryLayer; 4] = [&silent, &contrib, &contrib, &contrib];
        assert!(has_silent_layer(&coarsest_silent));
        assert_eq!(
            has_silent_layer(&coarsest_silent),
            silent_layer_count(&coarsest_silent) >= 1
        );

        // Dual short-circuit: the trailing-silent case — every earlier
        // layer contributes and the last is the sole silent one — still
        // folds to true (no short-circuit, worst-case walk on the
        // any::any() path, but the returned bit is unchanged).
        let tail_only: [&dyn DiscoveryLayer; 4] = [&contrib, &contrib, &contrib, &silent];
        assert!(has_silent_layer(&tail_only));
        assert_eq!(
            has_silent_layer(&tail_only),
            silent_layer_count(&tail_only) >= 1
        );
    }

    // -------- has_multiple_contributors (root ≥2 boolean predicate on the contributors axis) --------

    #[test]
    fn has_multiple_contributors_matches_contributor_count_threshold() {
        // Cardinality-threshold identity at "≥ 2":
        // has_multiple_contributors(layers) == contributor_count(layers) >= 2.
        // Both routes share the non-empty-discover predicate; the boolean
        // short-circuits at the second contributor, the scalar walks the
        // whole stack.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_multiple_contributors(&layers);
        let via_threshold = contributor_count(&layers) >= 2;
        assert_eq!(
            via_primitive, via_threshold,
            "has_multiple_contributors != contributor_count >= 2",
        );
        assert!(
            via_primitive,
            "the fixture has three contributors — the ≥ 2 threshold holds",
        );

        // Threshold identity holds on every zero/one-contributor
        // degenerate stack: the empty stack (count == 0 ⇒ false), the
        // all-silent stack (count == 0 ⇒ false), and the single-
        // contributor stack (count == 1 ⇒ false) all collapse the
        // "≥ 2" bit and the boolean to false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_multiple_contributors(&empty));
        assert_eq!(
            has_multiple_contributors(&empty),
            contributor_count(&empty) >= 2,
        );

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!has_multiple_contributors(&all_silent));
        assert_eq!(
            has_multiple_contributors(&all_silent),
            contributor_count(&all_silent) >= 2,
        );

        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let single: [&dyn DiscoveryLayer; 4] = [&silent, &solo, &silent, &silent];
        assert!(!has_multiple_contributors(&single));
        assert_eq!(
            has_multiple_contributors(&single),
            contributor_count(&single) >= 2,
        );
    }

    #[test]
    fn has_multiple_contributors_matches_is_contested_at_root() {
        // Whole-layer→point-path root-specialization identity:
        // has_multiple_contributors(layers) == is_contested_at(layers, &[]).
        // On path == &[] the general point predicate collapses to the
        // same non-empty-discover filter this primitive uses directly.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_root = has_multiple_contributors(&layers);
        let via_point = is_contested_at(&layers, &[]);
        assert_eq!(
            via_root, via_point,
            "has_multiple_contributors != is_contested_at(layers, &[])",
        );

        // Root-specialization holds on every degenerate stack: empty,
        // all-silent, single-contributor, and the multi-contributor
        // fixture all agree on both sides.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(
            has_multiple_contributors(&empty),
            is_contested_at(&empty, &[]),
        );
        assert!(!has_multiple_contributors(&empty));

        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert_eq!(
            has_multiple_contributors(&all_silent),
            is_contested_at(&all_silent, &[]),
        );
        assert!(!has_multiple_contributors(&all_silent));

        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let single: [&dyn DiscoveryLayer; 2] = [&solo, &silent];
        assert_eq!(
            has_multiple_contributors(&single),
            is_contested_at(&single, &[]),
        );
        assert!(!has_multiple_contributors(&single));
    }

    #[test]
    fn has_multiple_contributors_matches_contributor_names_len_threshold() {
        // Ordered-list cardinality-threshold dual on the contributors axis:
        // has_multiple_contributors(layers) == contributor_names(layers).len() >= 2.
        // The list-length reduction pins the same "≥ 2" boundary the
        // boolean returns without materializing the name Vec.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_multiple_contributors(&layers);
        let via_names_len = contributor_names(&layers).len() >= 2;
        assert_eq!(
            via_primitive, via_names_len,
            "has_multiple_contributors != contributor_names.len() >= 2",
        );
    }

    #[test]
    fn has_multiple_contributors_matches_nonempty_layer_dicts_len_threshold() {
        // Ordered-pair cardinality-threshold dual on the (name, dict) axis:
        // has_multiple_contributors(layers) == nonempty_layer_dicts(layers).len() >= 2.
        // The (name, dict) pair Vec has one entry per contributor, so its
        // length is the same partition scalar as contributor_count; the
        // identity closes the "≥ 2" threshold at the pair altitude.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_multiple_contributors(&layers);
        let via_pairs_len = nonempty_layer_dicts(&layers).len() >= 2;
        assert_eq!(
            via_primitive, via_pairs_len,
            "has_multiple_contributors != nonempty_layer_dicts.len() >= 2",
        );
    }

    #[test]
    fn has_multiple_contributors_partitions_trichotomy_with_has_contributor() {
        // Trichotomy on (has_contributor, has_multiple_contributors) —
        // the whole-layer analog of (is_touched_at, is_contested_at):
        //   (F, F) ⇔ contributor_count == 0 (nothing declared, or all silent)
        //   (T, F) ⇔ contributor_count == 1 (single-source config)
        //   (T, T) ⇔ contributor_count >= 2 (layered / multi-source)
        //   (F, T) ⇔ impossible (monotonic chain)
        //
        // Each state is reached by a distinct fixture; the pair pins the
        // trichotomy as an ordered-pair equality against a hand-computed
        // truth table, closing the exact-cardinality partition in
        // short-circuiting boolean arithmetic on both endpoints at once.

        // (F, F): empty stack — nothing declared.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_contributor(&empty));
        assert!(!has_multiple_contributors(&empty));

        // (F, F): all-silent stack — count == 0 collapses both bits.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!has_contributor(&all_silent));
        assert!(!has_multiple_contributors(&all_silent));

        // (T, F): single-source config — exactly one non-empty layer,
        // the sole toucher; no override contest is representable.
        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let single: [&dyn DiscoveryLayer; 3] = [&silent, &solo, &silent];
        assert!(has_contributor(&single));
        assert!(!has_multiple_contributors(&single));
        assert_eq!(contributor_count(&single), 1);

        // (T, T): multi-source / layered — the fixture — three
        // contributors, so the ≥ 2 endpoint fires.
        let owned = count_contributor_fixture();
        let layered = as_refs(&owned);
        assert!(has_contributor(&layered));
        assert!(has_multiple_contributors(&layered));
        assert!(contributor_count(&layered) >= 2);

        // Singleton characterization on the exact-cardinality axis:
        //   has_contributor && !has_multiple_contributors
        //     <=> contributor_count == 1
        // holds pointwise across each fixture.
        for fixture in [
            &empty as &[&dyn DiscoveryLayer],
            &all_silent as &[&dyn DiscoveryLayer],
            &single as &[&dyn DiscoveryLayer],
            &layered,
        ] {
            let via_pair = has_contributor(fixture) && !has_multiple_contributors(fixture);
            let via_scalar = contributor_count(fixture) == 1;
            assert_eq!(
                via_pair,
                via_scalar,
                "singleton characterization mismatched on fixture with \
                 contributor_count == {}",
                contributor_count(fixture),
            );
        }
    }

    #[test]
    fn has_multiple_contributors_monotonic_chain_with_has_contributor() {
        // Monotonic implication `has_multiple_contributors ⇒ has_contributor`
        // and its contrapositive `!has_contributor ⇒ !has_multiple_contributors`
        // hold across every fixture — the "≥ 2" threshold is a strict
        // refinement of the "≥ 1" threshold on the same axis.
        let silent = Fixed("undetectable", Dict::new());
        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));

        let empty: [&dyn DiscoveryLayer; 0] = [];
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        let single: [&dyn DiscoveryLayer; 3] = [&silent, &solo, &silent];
        let pair: [&dyn DiscoveryLayer; 2] = [&a, &b];
        let owned = count_contributor_fixture();
        let layered = as_refs(&owned);

        for fixture in [
            &empty as &[&dyn DiscoveryLayer],
            &all_silent as &[&dyn DiscoveryLayer],
            &single as &[&dyn DiscoveryLayer],
            &pair as &[&dyn DiscoveryLayer],
            &layered,
        ] {
            if has_multiple_contributors(fixture) {
                assert!(
                    has_contributor(fixture),
                    "has_multiple_contributors ⇒ has_contributor was violated",
                );
            }
            if !has_contributor(fixture) {
                assert!(
                    !has_multiple_contributors(fixture),
                    "!has_contributor ⇒ !has_multiple_contributors was violated",
                );
            }
        }
    }

    #[test]
    fn has_multiple_contributors_gates_leaf_override_contests() {
        // Necessary-and-not-sufficient condition for any leaf-level
        // override contest:
        //   (∃ path p : is_contested_at(layers, p))
        //       ⇒ has_multiple_contributors(layers).
        // The converse fails at disjoint-key layered configs — two
        // contributors that touch disjoint leaves — where the pair is
        // layered at the config level but no leaf is contested. Both
        // directions are pinned here.

        // Forward direction: a contested leaf implies ≥ 2 contributors.
        // The fixture has three contributors and the deep-merge overlap
        // at key "b" produces a contest.
        let a = Fixed("shared", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("shared", dict(&[("k", Value::from(2i64))]));
        let overlapping: [&dyn DiscoveryLayer; 2] = [&a, &b];
        assert!(is_contested_at(&overlapping, &["k"]));
        assert!(has_multiple_contributors(&overlapping));

        // Reverse direction (converse) fails: disjoint-key contributors
        // — the pair is layered (≥ 2 contributors) but no leaf is
        // contested (each contributor touches its own key).
        let x = Fixed("x_only", dict(&[("x", Value::from(1i64))]));
        let y = Fixed("y_only", dict(&[("y", Value::from(2i64))]));
        let disjoint: [&dyn DiscoveryLayer; 2] = [&x, &y];
        assert!(has_multiple_contributors(&disjoint));
        assert!(!is_contested_at(&disjoint, &["x"]));
        assert!(!is_contested_at(&disjoint, &["y"]));

        // The gate direction holds on the single-contributor stack: no
        // leaf can be contested when only one layer touches anything.
        let silent = Fixed("undetectable", Dict::new());
        let solo = Fixed("solo", dict(&[("k", Value::from(1i64))]));
        let single: [&dyn DiscoveryLayer; 3] = [&silent, &solo, &silent];
        assert!(!has_multiple_contributors(&single));
        assert!(!is_contested_at(&single, &["k"]));
    }

    #[test]
    fn has_multiple_contributors_short_circuits_on_early_pair() {
        // Short-circuit correctness: a stack whose two coarsest layers
        // both contribute short-circuits to true at the second hit.
        // Iterator::nth(1).is_some() terminates on the second element on
        // this fixture; the test pins the returned bit (not the walk
        // length, which is not observable from the returned bool).
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let early_pair: [&dyn DiscoveryLayer; 5] = [&a, &b, &silent, &silent, &silent];
        assert!(has_multiple_contributors(&early_pair));
        assert_eq!(
            has_multiple_contributors(&early_pair),
            contributor_count(&early_pair) >= 2,
        );

        // Dual short-circuit: the two trailing contributors — every
        // earlier layer is silent — still folds to true (worst-case walk
        // on the filter path, but the returned bit is unchanged).
        let late_pair: [&dyn DiscoveryLayer; 5] = [&silent, &silent, &silent, &a, &b];
        assert!(has_multiple_contributors(&late_pair));
        assert_eq!(
            has_multiple_contributors(&late_pair),
            contributor_count(&late_pair) >= 2,
        );

        // Boundary at the single-contributor stack: only one non-empty
        // layer means .nth(1) returns None and the bit collapses to
        // false, matching the "≥ 2" scalar boundary.
        let single: [&dyn DiscoveryLayer; 5] = [&silent, &silent, &a, &silent, &silent];
        assert!(!has_multiple_contributors(&single));
        assert_eq!(
            has_multiple_contributors(&single),
            contributor_count(&single) >= 2,
        );
    }

    // -------- has_multiple_silent_layers (root ≥2 boolean predicate on the silent axis) --------

    #[test]
    fn has_multiple_silent_layers_matches_silent_layer_count_threshold() {
        // Cardinality-threshold identity at "≥ 2":
        // has_multiple_silent_layers(layers) == silent_layer_count(layers) >= 2.
        // Both routes share the is-empty-discover predicate; the
        // boolean short-circuits at the second silent layer, the
        // scalar walks the whole stack.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_multiple_silent_layers(&layers);
        let via_threshold = silent_layer_count(&layers) >= 2;
        assert_eq!(
            via_primitive, via_threshold,
            "has_multiple_silent_layers != silent_layer_count >= 2",
        );
        assert!(
            via_primitive,
            "the fixture has three silent layers — the ≥ 2 threshold holds",
        );

        // Threshold identity holds on every zero/one-silent-layer
        // degenerate stack: the empty stack (count == 0 ⇒ false),
        // the every-layer-contributes stack (count == 0 ⇒ false),
        // and the single-silent-layer stack (count == 1 ⇒ false)
        // all collapse the "≥ 2" bit and the boolean to false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_multiple_silent_layers(&empty));
        assert_eq!(
            has_multiple_silent_layers(&empty),
            silent_layer_count(&empty) >= 2,
        );

        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &a];
        assert!(!has_multiple_silent_layers(&all_contribute));
        assert_eq!(
            has_multiple_silent_layers(&all_contribute),
            silent_layer_count(&all_contribute) >= 2,
        );

        let silent = Fixed("undetectable", Dict::new());
        let single: [&dyn DiscoveryLayer; 4] = [&a, &silent, &b, &a];
        assert!(!has_multiple_silent_layers(&single));
        assert_eq!(
            has_multiple_silent_layers(&single),
            silent_layer_count(&single) >= 2,
        );
    }

    #[test]
    fn has_multiple_silent_layers_matches_silent_names_len_threshold() {
        // Ordered-list cardinality-threshold dual on the silent axis:
        // has_multiple_silent_layers(layers) == silent_layer_names(layers).len() >= 2.
        // The list-length reduction pins the same "≥ 2" boundary
        // the boolean returns without materializing the name Vec.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);

        let via_primitive = has_multiple_silent_layers(&layers);
        let via_names_len = silent_layer_names(&layers).len() >= 2;
        assert_eq!(
            via_primitive, via_names_len,
            "has_multiple_silent_layers != silent_layer_names.len() >= 2",
        );
    }

    #[test]
    fn has_multiple_silent_layers_matches_partition_complement() {
        // Partition-complement identity against the partition-count law
        // `contributor_count + silent_layer_count == layer_names.len()`:
        //   has_multiple_silent_layers(layers)
        //     == layer_names(layers).len() >= contributor_count(layers) + 2.
        // Holding across every degenerate stack in pure-scalar arithmetic
        // against the declared denominator.
        let owned = count_contributor_fixture();
        let layers = as_refs(&owned);
        let via_primitive = has_multiple_silent_layers(&layers);
        let via_complement = layer_names(&layers).len() >= contributor_count(&layers) + 2;
        assert_eq!(
            via_primitive, via_complement,
            "has_multiple_silent_layers != layer_names.len() >= contributor_count + 2",
        );

        // Empty stack: both sides false.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(
            has_multiple_silent_layers(&empty),
            layer_names(&empty).len() >= contributor_count(&empty) + 2,
        );

        // All-silent stack: three silent layers, zero contributors,
        // declared denominator 3, so 3 >= 0 + 2 = true. Silent scalar
        // is 3 and the bit fires.
        let silent = Fixed("undetectable", Dict::new());
        let all_silent: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(has_multiple_silent_layers(&all_silent));
        assert_eq!(
            has_multiple_silent_layers(&all_silent),
            layer_names(&all_silent).len() >= contributor_count(&all_silent) + 2,
        );

        // Pair-partition-complement identity through
        // nonempty_layer_dicts.len(): the (name, dict) pair Vec has
        // one entry per contributor, so its length is the same
        // partition scalar as contributor_count; the identity closes
        // the "≥ 2 silent" threshold at the pair altitude.
        let via_pair_complement =
            layer_names(&layers).len() >= nonempty_layer_dicts(&layers).len() + 2;
        assert_eq!(
            via_primitive, via_pair_complement,
            "has_multiple_silent_layers != layer_names.len() >= nonempty_layer_dicts.len() + 2",
        );
    }

    #[test]
    fn has_multiple_silent_layers_partitions_trichotomy_with_has_silent_layer() {
        // Trichotomy on (has_silent_layer, has_multiple_silent_layers)
        // — the silent-axis mirror of
        // (has_contributor, has_multiple_contributors):
        //   (F, F) ⇔ silent_layer_count == 0 (empty stack or all
        //             contribute)
        //   (T, F) ⇔ silent_layer_count == 1 (exactly one undetectable
        //             axis)
        //   (T, T) ⇔ silent_layer_count >= 2 (many undetectable axes)
        //   (F, T) ⇔ impossible (monotonic chain)
        //
        // Each state is reached by a distinct fixture; the pair pins
        // the trichotomy as an ordered-pair equality against a
        // hand-computed truth table.

        // (F, F): empty stack — no declared layers, no silent layers.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert!(!has_silent_layer(&empty));
        assert!(!has_multiple_silent_layers(&empty));

        // (F, F): every-layer-contributes stack — three contributors,
        // no silent layers.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k3", Value::from(3i64))]));
        let all_contribute: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(!has_silent_layer(&all_contribute));
        assert!(!has_multiple_silent_layers(&all_contribute));

        // (T, F): exactly one silent layer — the sole undetectable
        // axis; the "≥ 2" bit is unreachable.
        let silent = Fixed("undetectable", Dict::new());
        let single_silent: [&dyn DiscoveryLayer; 3] = [&a, &silent, &b];
        assert!(has_silent_layer(&single_silent));
        assert!(!has_multiple_silent_layers(&single_silent));
        assert_eq!(silent_layer_count(&single_silent), 1);

        // (T, T): the fixture — three silent layers — both endpoints
        // fire.
        let owned = count_contributor_fixture();
        let layered = as_refs(&owned);
        assert!(has_silent_layer(&layered));
        assert!(has_multiple_silent_layers(&layered));
        assert!(silent_layer_count(&layered) >= 2);

        // Singleton characterization on the exact-cardinality silent
        // axis:
        //   has_silent_layer && !has_multiple_silent_layers
        //     <=> silent_layer_count == 1
        // holds pointwise across each fixture.
        for fixture in [
            &empty as &[&dyn DiscoveryLayer],
            &all_contribute as &[&dyn DiscoveryLayer],
            &single_silent as &[&dyn DiscoveryLayer],
            &layered,
        ] {
            let via_pair = has_silent_layer(fixture) && !has_multiple_silent_layers(fixture);
            let via_scalar = silent_layer_count(fixture) == 1;
            assert_eq!(
                via_pair,
                via_scalar,
                "singleton characterization mismatched on fixture with \
                 silent_layer_count == {}",
                silent_layer_count(fixture),
            );
        }
    }

    #[test]
    fn has_multiple_silent_layers_monotonic_chain_with_has_silent_layer() {
        // Monotonic implication
        // `has_multiple_silent_layers ⇒ has_silent_layer` and its
        // contrapositive
        // `!has_silent_layer ⇒ !has_multiple_silent_layers` hold across
        // every fixture — the "≥ 2" threshold is a strict refinement
        // of the "≥ 1" threshold on the same axis.
        let silent = Fixed("undetectable", Dict::new());
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));

        let empty: [&dyn DiscoveryLayer; 0] = [];
        let all_contribute: [&dyn DiscoveryLayer; 2] = [&a, &b];
        let single_silent: [&dyn DiscoveryLayer; 3] = [&a, &silent, &b];
        let pair_silent: [&dyn DiscoveryLayer; 2] = [&silent, &silent];
        let owned = count_contributor_fixture();
        let layered = as_refs(&owned);

        for fixture in [
            &empty as &[&dyn DiscoveryLayer],
            &all_contribute as &[&dyn DiscoveryLayer],
            &single_silent as &[&dyn DiscoveryLayer],
            &pair_silent as &[&dyn DiscoveryLayer],
            &layered,
        ] {
            if has_multiple_silent_layers(fixture) {
                assert!(
                    has_silent_layer(fixture),
                    "has_multiple_silent_layers ⇒ has_silent_layer was violated",
                );
            }
            if !has_silent_layer(fixture) {
                assert!(
                    !has_multiple_silent_layers(fixture),
                    "!has_silent_layer ⇒ !has_multiple_silent_layers was violated",
                );
            }
        }
    }

    #[test]
    fn has_multiple_silent_layers_dual_of_has_multiple_contributors() {
        // Silent-axis mirror of the contributors-axis "≥ 2" primitive.
        // Swapping every layer's discover result between empty and
        // non-empty flips the boolean partition: the "≥ 2 silent" bit
        // on the original stack equals the "≥ 2 contributor" bit on
        // the swapped stack, since both walks fold the same predicate
        // shape under one hop of inversion.
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k2", Value::from(2i64))]));
        let silent = Fixed("undetectable", Dict::new());

        // Two silent + one contributor: multi-silent fires,
        // multi-contributor does not.
        let two_silent_one_contrib: [&dyn DiscoveryLayer; 3] = [&silent, &a, &silent];
        assert!(has_multiple_silent_layers(&two_silent_one_contrib));
        assert!(!has_multiple_contributors(&two_silent_one_contrib));

        // Swap: two contributors + one silent: the mirror holds.
        let two_contrib_one_silent: [&dyn DiscoveryLayer; 3] = [&a, &silent, &b];
        assert!(!has_multiple_silent_layers(&two_contrib_one_silent));
        assert!(has_multiple_contributors(&two_contrib_one_silent));
    }

    #[test]
    fn has_multiple_silent_layers_short_circuits_on_early_pair() {
        // Short-circuit correctness: a stack whose two coarsest
        // layers are both silent short-circuits to true at the second
        // hit. Iterator::nth(1).is_some() terminates on the second
        // element on this fixture; the test pins the returned bit
        // (not the walk length, which is not observable from the
        // returned bool).
        let a = Fixed("a", dict(&[("k1", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let early_pair: [&dyn DiscoveryLayer; 5] = [&silent, &silent, &a, &a, &a];
        assert!(has_multiple_silent_layers(&early_pair));
        assert_eq!(
            has_multiple_silent_layers(&early_pair),
            silent_layer_count(&early_pair) >= 2,
        );

        // Dual short-circuit: the two trailing silent layers — every
        // earlier layer contributes — still folds to true (worst-case
        // walk on the filter path, but the returned bit is unchanged).
        let late_pair: [&dyn DiscoveryLayer; 5] = [&a, &a, &a, &silent, &silent];
        assert!(has_multiple_silent_layers(&late_pair));
        assert_eq!(
            has_multiple_silent_layers(&late_pair),
            silent_layer_count(&late_pair) >= 2,
        );

        // Boundary at the single-silent stack: only one silent layer
        // means .nth(1) returns None and the bit collapses to false,
        // matching the "≥ 2" scalar boundary.
        let single: [&dyn DiscoveryLayer; 5] = [&a, &a, &silent, &a, &a];
        assert!(!has_multiple_silent_layers(&single));
        assert_eq!(
            has_multiple_silent_layers(&single),
            silent_layer_count(&single) >= 2,
        );
    }

    // -------- is_multiply_silenced_at (point ≥2 boolean predicate on the silenced axis) --------

    /// A three-layer fixture where each point exercises a distinct
    /// cell of the four-way `(is_touched_at, is_contested_at,
    /// is_multiply_silenced_at)` partition:
    ///
    /// - `["absent"]` — zero touchers (F, F, F)
    /// - `["solo"]` — one toucher, `a` only (T, F, F)
    /// - `["pair", "mode"]` — two touchers, `a` and `b` (T, T, F)
    /// - `["chain", "mode"]` — three touchers, `a`, `b`, `c` (T, T, T)
    fn multi_silenced_fixture() -> [Box<dyn DiscoveryLayer>; 3] {
        let a: Box<dyn DiscoveryLayer> = Box::new(Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                ("pair", Value::from(dict(&[("mode", Value::from("live"))]))),
                ("chain", Value::from(dict(&[("mode", Value::from("live"))]))),
            ]),
        ));
        let b: Box<dyn DiscoveryLayer> = Box::new(Fixed(
            "b",
            dict(&[
                (
                    "pair",
                    Value::from(dict(&[("mode", Value::from("shadow"))])),
                ),
                (
                    "chain",
                    Value::from(dict(&[("mode", Value::from("staging"))])),
                ),
            ]),
        ));
        let c: Box<dyn DiscoveryLayer> = Box::new(Fixed(
            "c",
            dict(&[(
                "chain",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        ));
        [a, b, c]
    }

    #[test]
    fn is_multiply_silenced_at_matches_silenced_count_threshold() {
        // Cardinality-threshold identity at "≥ 2" on the silenced axis:
        //   is_multiply_silenced_at(layers, p) ==
        //     silenced_count_at(layers, p) >= 2.
        // Both routes share the same touches_path filter; the primitive
        // short-circuits at the third toucher, the scalar walks the
        // whole stack and applies one saturating subtraction.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);
        for path in [
            &[][..],
            &["absent"][..],
            &["solo"][..],
            &["pair"][..],
            &["pair", "mode"][..],
            &["chain"][..],
            &["chain", "mode"][..],
        ] {
            let via_primitive = is_multiply_silenced_at(&layers, path);
            let via_threshold = silenced_count_at(&layers, path) >= 2;
            assert_eq!(
                via_primitive, via_threshold,
                "is_multiply_silenced_at != silenced_count_at >= 2 at {path:?}",
            );
        }

        // The four-way partition on the chain path fires the deepest
        // endpoint: three contributors, two silenced.
        assert!(is_multiply_silenced_at(&layers, &["chain", "mode"]));
        assert_eq!(silenced_count_at(&layers, &["chain", "mode"]), 2);

        // The pair path fires is_contested but not is_multiply_silenced:
        // two contributors, one silenced.
        assert!(!is_multiply_silenced_at(&layers, &["pair", "mode"]));
        assert!(is_contested_at(&layers, &["pair", "mode"]));
    }

    #[test]
    fn is_multiply_silenced_at_matches_silenced_len_threshold() {
        // Ordered-list length-threshold dual on the losers axis:
        //   is_multiply_silenced_at(layers, p) ==
        //     silenced_at(layers, p).len() >= 2.
        // The list-length reduction pins the same "≥ 2 losers" boundary
        // the boolean returns without materializing the losers Vec.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);
        for path in [
            &[][..],
            &["absent"][..],
            &["solo"][..],
            &["pair", "mode"][..],
            &["chain", "mode"][..],
        ] {
            let via_primitive = is_multiply_silenced_at(&layers, path);
            let via_len = silenced_at(&layers, path).len() >= 2;
            assert_eq!(
                via_primitive, via_len,
                "is_multiply_silenced_at != silenced_at.len() >= 2 at {path:?}",
            );
        }
    }

    #[test]
    fn is_multiply_silenced_at_matches_contributor_count_at_ge_three() {
        // Contributors-side cardinality-threshold dual: the partition-count
        // law silenced_count_at + usize::from(is_touched_at) ==
        // contributor_count_at shifts the "≥ 2 silenced" threshold by
        // exactly one hit against the touchers scalar. So:
        //   is_multiply_silenced_at(layers, p) ==
        //     contributor_count_at(layers, p) >= 3.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);
        for path in [
            &[][..],
            &["absent"][..],
            &["solo"][..],
            &["pair"][..],
            &["pair", "mode"][..],
            &["chain"][..],
            &["chain", "mode"][..],
        ] {
            let via_primitive = is_multiply_silenced_at(&layers, path);
            let via_touchers = contributor_count_at(&layers, path) >= 3;
            assert_eq!(
                via_primitive, via_touchers,
                "is_multiply_silenced_at != contributor_count_at >= 3 at {path:?}",
            );
            let via_touchers_vec = contributors_at(&layers, path).len() >= 3;
            assert_eq!(
                via_primitive, via_touchers_vec,
                "is_multiply_silenced_at != contributors_at.len() >= 3 at {path:?}",
            );
        }
    }

    #[test]
    fn is_multiply_silenced_at_matches_contest_at_folded_projection() {
        // Folded-value method call: is_multiply_silenced_at(layers, p) ==
        // contest_at(layers, p).is_some_and(|c| c.silenced_count() >= 2).
        // The None branch on the fused side maps to false in agreement
        // with the no-toucher false branch on the primitive side; the
        // single-toucher (Some, silenced_count=0) branch collapses to
        // false too.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);
        for path in [
            &[][..],
            &["absent"][..],
            &["solo"][..],
            &["pair"][..],
            &["pair", "mode"][..],
            &["chain"][..],
            &["chain", "mode"][..],
        ] {
            let via_primitive = is_multiply_silenced_at(&layers, path);
            let via_fused = contest_at(&layers, path).is_some_and(|c| c.silenced_count() >= 2);
            assert_eq!(
                via_primitive, via_fused,
                "is_multiply_silenced_at != contest_at.is_some_and(silenced_count >= 2) at {path:?}",
            );
        }
    }

    #[test]
    fn is_multiply_silenced_at_partitions_four_way_touchers_axis() {
        // Four-way partition of the point touchers axis via three
        // short-circuiting boolean reads:
        //   (F, F, F) ⇔ 0 touchers  — nobody touched
        //   (T, F, F) ⇔ 1 toucher   — uncontested singleton
        //   (T, T, F) ⇔ 2 touchers  — single override contest
        //   (T, T, T) ⇔ 3+ touchers — chain of overrides
        // Every other triple is unreachable under the monotonic chain.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);

        // (F, F, F) — path absent from every layer.
        assert!(!is_touched_at(&layers, &["absent"]));
        assert!(!is_contested_at(&layers, &["absent"]));
        assert!(!is_multiply_silenced_at(&layers, &["absent"]));

        // (T, F, F) — only `a` touches "solo".
        assert!(is_touched_at(&layers, &["solo"]));
        assert!(!is_contested_at(&layers, &["solo"]));
        assert!(!is_multiply_silenced_at(&layers, &["solo"]));

        // (T, T, F) — `a` and `b` touch "pair/mode"; `c` doesn't.
        assert!(is_touched_at(&layers, &["pair", "mode"]));
        assert!(is_contested_at(&layers, &["pair", "mode"]));
        assert!(!is_multiply_silenced_at(&layers, &["pair", "mode"]));

        // (T, T, T) — all three touch "chain/mode".
        assert!(is_touched_at(&layers, &["chain", "mode"]));
        assert!(is_contested_at(&layers, &["chain", "mode"]));
        assert!(is_multiply_silenced_at(&layers, &["chain", "mode"]));

        // Singleton characterization on the exact-cardinality silenced
        // axis:
        //   is_contested_at && !is_multiply_silenced_at
        //     <=> silenced_count_at == 1
        //     <=> contributor_count_at == 2
        // holds pointwise across each cell of the partition.
        for path in [
            &["absent"][..],
            &["solo"][..],
            &["pair", "mode"][..],
            &["chain", "mode"][..],
        ] {
            let via_pair =
                is_contested_at(&layers, path) && !is_multiply_silenced_at(&layers, path);
            let via_silenced = silenced_count_at(&layers, path) == 1;
            let via_touchers = contributor_count_at(&layers, path) == 2;
            assert_eq!(
                via_pair, via_silenced,
                "singleton characterization != silenced_count_at == 1 at {path:?}",
            );
            assert_eq!(
                via_pair, via_touchers,
                "singleton characterization != contributor_count_at == 2 at {path:?}",
            );
        }
    }

    #[test]
    fn is_multiply_silenced_at_monotonic_chain_with_is_contested_at() {
        // Monotonic implications along the touchers axis:
        //   is_multiply_silenced_at ⇒ is_contested_at
        //   is_multiply_silenced_at ⇒ is_touched_at
        //   !is_contested_at        ⇒ !is_multiply_silenced_at
        //   !is_touched_at          ⇒ !is_multiply_silenced_at
        // The "≥ 2 silenced" endpoint is a strict refinement of every
        // shallower cardinality-threshold endpoint on the same filter.
        let owned = multi_silenced_fixture();
        let layers = as_refs(&owned);
        for path in [
            &[][..],
            &["absent"][..],
            &["solo"][..],
            &["pair"][..],
            &["pair", "mode"][..],
            &["chain"][..],
            &["chain", "mode"][..],
        ] {
            if is_multiply_silenced_at(&layers, path) {
                assert!(
                    is_contested_at(&layers, path),
                    "is_multiply_silenced_at ⇒ is_contested_at was violated at {path:?}",
                );
                assert!(
                    is_touched_at(&layers, path),
                    "is_multiply_silenced_at ⇒ is_touched_at was violated at {path:?}",
                );
            }
            if !is_contested_at(&layers, path) {
                assert!(
                    !is_multiply_silenced_at(&layers, path),
                    "!is_contested_at ⇒ !is_multiply_silenced_at was violated at {path:?}",
                );
            }
            if !is_touched_at(&layers, path) {
                assert!(
                    !is_multiply_silenced_at(&layers, path),
                    "!is_touched_at ⇒ !is_multiply_silenced_at was violated at {path:?}",
                );
            }
        }
    }

    #[test]
    fn is_multiply_silenced_at_covers_prefix_scalar_erasure() {
        // Prefix-scalar erasure: three layers each cover the deep leaf
        // via a wholesale-replace or a proper subtree; every one
        // touches the deep path pre-merge even though only the trailing
        // scalar survives on the composed dict. is_multiply_silenced_at
        // fires because ≥ 3 layers touched pre-merge — symmetric to
        // is_contested_at's erasure coverage.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed("b", dict(&[("k", Value::from("shadowed"))]));
        let c = Fixed("c", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert!(is_multiply_silenced_at(&layers, &["k", "leaf"]));
        assert!(is_multiply_silenced_at(&layers, &["k"]));
        assert_eq!(contributor_count_at(&layers, &["k"]), 3);
        assert_eq!(silenced_count_at(&layers, &["k"]), 2);
    }

    #[test]
    fn is_multiply_silenced_at_root_specialization_filters_silent_layers() {
        // Root specialization at path=[]: touches_path collapses to
        // !dict.is_empty(), so is_multiply_silenced_at(layers, &[])
        // == contributor_count(layers) >= 3. Silent layers between
        // contributors are filtered on the touchers walk and do not
        // shift the endpoint.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));

        // Three contributors interleaved with silent layers — root
        // is multi-silenced.
        let three: [&dyn DiscoveryLayer; 5] = [&coarse, &silent, &middle, &silent, &specific];
        assert!(is_multiply_silenced_at(&three, &[]));
        assert_eq!(
            is_multiply_silenced_at(&three, &[]),
            contributor_count(&three) >= 3,
        );

        // Two contributors interleaved with silent layers — root is
        // contested but not multi-silenced.
        let two: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &silent];
        assert!(!is_multiply_silenced_at(&two, &[]));
        assert!(is_contested_at(&two, &[]));
        assert_eq!(
            is_multiply_silenced_at(&two, &[]),
            contributor_count(&two) >= 3,
        );

        // Only silent layers — no contributor touches root.
        let none: [&dyn DiscoveryLayer; 3] = [&silent, &silent, &silent];
        assert!(!is_multiply_silenced_at(&none, &[]));
        assert!(!is_contested_at(&none, &[]));
        assert!(!is_touched_at(&none, &[]));
    }

    #[test]
    fn is_multiply_silenced_at_short_circuits_on_early_triple() {
        // Short-circuit correctness: a stack whose three coarsest
        // layers all touch the path short-circuits to true at the
        // third hit. Iterator::nth(2).is_some() terminates on the
        // third element on this fixture; the test pins the returned
        // bit (not the walk length, which is not observable from the
        // returned bool).
        let a = Fixed("a", dict(&[("k", Value::from(1i64))]));
        let b = Fixed("b", dict(&[("k", Value::from(2i64))]));
        let c = Fixed("c", dict(&[("k", Value::from(3i64))]));
        let silent = Fixed("undetectable", Dict::new());

        // Three coarsest layers touch; the trailing silent tail does
        // not extend the walk beyond the third hit.
        let early_triple: [&dyn DiscoveryLayer; 5] = [&a, &b, &c, &silent, &silent];
        assert!(is_multiply_silenced_at(&early_triple, &["k"]));

        // Dual short-circuit: three trailing touchers, two coarser
        // silent layers. The full stack walks past the silent prefix
        // but the returned bit is unchanged.
        let late_triple: [&dyn DiscoveryLayer; 5] = [&silent, &silent, &a, &b, &c];
        assert!(is_multiply_silenced_at(&late_triple, &["k"]));

        // Boundary at exactly two touchers: only `a` and `b` touch,
        // so .nth(2) returns None and the bit collapses to false. The
        // "≥ 2 silenced" scalar boundary agrees.
        let two_touchers: [&dyn DiscoveryLayer; 5] = [&a, &silent, &b, &silent, &silent];
        assert!(!is_multiply_silenced_at(&two_touchers, &["k"]));
        assert!(is_contested_at(&two_touchers, &["k"]));
        assert_eq!(
            is_multiply_silenced_at(&two_touchers, &["k"]),
            silenced_count_at(&two_touchers, &["k"]) >= 2,
        );
    }

    // ---- PathContest::is_multiply_silenced ------------------------------

    /// The three-way touchers-count fixture reused across the
    /// `path_contest_is_multiply_silenced_*` battery: an uncontested
    /// singleton (1 toucher / 0 silenced), a strict-contest pair
    /// (2 touchers / 1 silenced — contested but not multiply silenced),
    /// and a multiply-silenced triple (3 touchers / 2 silenced). The
    /// three points span the {< 1, = 1, ≥ 2} silenced cardinality
    /// partition on the losers axis, so every method-altitude boolean
    /// primitive on that axis has one pinning input for each cell.
    fn contest_fixture() -> (
        Box<dyn DiscoveryLayer>,
        Box<dyn DiscoveryLayer>,
        Box<dyn DiscoveryLayer>,
    ) {
        let sole = Fixed("sole", dict(&[("k", Value::from(1i64))]));
        let pair_coarse = Fixed("pair_coarse", dict(&[("k", Value::from(1i64))]));
        let pair_specific = Fixed("pair_specific", dict(&[("k", Value::from(2i64))]));
        (
            Box::new(sole),
            Box::new(pair_coarse),
            Box::new(pair_specific),
        )
    }

    #[test]
    fn path_contest_is_multiply_silenced_false_when_uncontested() {
        // Uncontested singleton: 1 toucher, 0 silenced → both
        // is_contested and is_multiply_silenced collapse to false.
        let (sole, _, _) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 1] = [sole.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(!contest.is_contested(), "uncontested singleton");
        assert!(
            !contest.is_multiply_silenced(),
            "≥ 2 silenced predicate collapses to false on uncontested singleton"
        );
    }

    #[test]
    fn path_contest_is_multiply_silenced_false_when_singly_contested() {
        // Strict-contest pair: 2 touchers, 1 silenced → is_contested
        // is true (≥ 1 silenced), is_multiply_silenced is false (< 2
        // silenced). Pins the "contested but not multiply silenced"
        // cell that distinguishes the two boolean thresholds.
        let (_, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 2] = [pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(contest.is_contested(), "strict contest");
        assert!(
            !contest.is_multiply_silenced(),
            "≥ 2 silenced predicate collapses to false at exactly one silenced"
        );
    }

    #[test]
    fn path_contest_is_multiply_silenced_true_when_multiply_silenced() {
        // Multiply-silenced triple: 3 touchers, 2 silenced → both
        // is_contested and is_multiply_silenced are true.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(contest.is_contested(), "still strictly contested");
        assert!(
            contest.is_multiply_silenced(),
            "≥ 2 silenced predicate is true"
        );
    }

    #[test]
    fn path_contest_is_multiply_silenced_matches_silenced_count_threshold() {
        // Method-level identity: is_multiply_silenced() <=>
        // silenced_count() >= 2 pointwise across the fixture spectrum.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let three: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&three, &["k"]).unwrap();
        assert_eq!(
            contest.is_multiply_silenced(),
            contest.silenced_count() >= 2
        );
        let two: [&dyn DiscoveryLayer; 2] = [pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&two, &["k"]).unwrap();
        assert_eq!(
            contest.is_multiply_silenced(),
            contest.silenced_count() >= 2
        );
        let one: [&dyn DiscoveryLayer; 1] = [sole.as_ref()];
        let contest = contest_at(&one, &["k"]).unwrap();
        assert_eq!(
            contest.is_multiply_silenced(),
            contest.silenced_count() >= 2
        );
    }

    #[test]
    fn path_contest_is_multiply_silenced_matches_contributor_count_ge_three() {
        // Cross-side identity: is_multiply_silenced() <=>
        // contributor_count() >= 3 (i.e. the losers-side ≥ 2 threshold
        // aligns arithmetically with the touchers-side ≥ 3 threshold,
        // because contributor_count() == silenced_count() + 1 on any
        // PathContest — the decider always adds exactly one to the
        // touchers-side).
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            assert_eq!(
                contest.is_multiply_silenced(),
                contest.contributor_count() >= 3,
                "method identity fails on {}-toucher fixture",
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_is_multiply_silenced_matches_is_multiply_silenced_at_via_contest_at() {
        // Option<PathContest> boundary identity — the method peer folds
        // through `contest_at` to the free-fn point primitive:
        //   contest_at(layers, p).is_some_and(|c| c.is_multiply_silenced())
        //       == is_multiply_silenced_at(layers, p)
        // Also covers the no-toucher case: contest_at returns None,
        // is_some_and collapses to false, is_multiply_silenced_at also
        // returns false.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let silent = Fixed("silent", Dict::new());
        for layers in [
            &[silent.clone_boxed().as_ref()][..], // untouched path -> None
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let via_method = contest_at(layers, &["k"]).is_some_and(|c| c.is_multiply_silenced());
            let via_free_fn = is_multiply_silenced_at(layers, &["k"]);
            assert_eq!(
                via_method, via_free_fn,
                "method peer disagrees with free-fn point primitive"
            );
        }
    }

    #[test]
    fn path_contest_is_multiply_silenced_implies_is_contested() {
        // Cardinality-threshold monotonicity: the ≥ 2 predicate on any
        // scalar always implies the ≥ 1 predicate on that same scalar.
        // On the losers axis at the PathContest method surface, that
        // reads: is_multiply_silenced() ⇒ is_contested(). Pinned
        // pointwise across the fixture spectrum.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            if contest.is_multiply_silenced() {
                assert!(
                    contest.is_contested(),
                    "≥ 2 silenced must imply ≥ 1 silenced"
                );
            }
        }
    }

    // ---- PathContest::runner_up -----------------------------------------

    #[test]
    fn path_contest_runner_up_none_when_uncontested() {
        // Uncontested singleton: overridden is empty, so runner_up
        // collapses to None. Pins the presence-boundary at the "no
        // silenced" endpoint — the sole toucher is the decider itself
        // and there is nothing one step back from it on the touchers
        // axis.
        let (sole, _, _) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 1] = [sole.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(!contest.is_contested(), "uncontested singleton");
        assert_eq!(
            contest.runner_up(),
            None,
            "runner_up is None on the no-silenced boundary",
        );
    }

    #[test]
    fn path_contest_runner_up_some_when_singly_contested() {
        // Strict-contest pair: overridden = [pair_coarse], so
        // runner_up = Some("pair_coarse"). At exactly one silenced,
        // runner_up and coarsest alias structurally — the sole silenced
        // layer occupies both the leading and trailing positions of
        // `overridden` at once.
        let (_, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 2] = [pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(contest.is_contested(), "strict contest");
        assert_eq!(
            contest.runner_up(),
            Some("pair_coarse"),
            "runner_up is the sole silenced layer",
        );
        assert_eq!(
            contest.runner_up(),
            Some(contest.coarsest()),
            "at exactly one silenced, runner_up == Some(coarsest)",
        );
    }

    #[test]
    fn path_contest_runner_up_multiply_silenced_returns_finest_loser() {
        // Multiply-silenced triple: overridden = [sole, pair_coarse],
        // decider = pair_specific. runner_up returns the trailing
        // (most-specific) silenced layer — pair_coarse — which is
        // structurally distinct from coarsest (sole). Pins the ≥ 2
        // silenced cell where the leading and trailing endpoints of
        // `overridden` diverge.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        let layers: [&dyn DiscoveryLayer; 3] =
            [sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()];
        let contest = contest_at(&layers, &["k"]).unwrap();
        assert!(contest.is_multiply_silenced(), "≥ 2 silenced");
        assert_eq!(
            contest.runner_up(),
            Some("pair_coarse"),
            "runner_up is the finest (most-specific) silenced layer",
        );
        assert_ne!(
            contest.runner_up(),
            Some(contest.coarsest()),
            "at ≥ 2 silenced, runner_up and coarsest occupy distinct positions",
        );
        assert_ne!(
            contest.runner_up(),
            Some(contest.decider),
            "runner_up is never the decider — the decider is the winner, not a loser",
        );
    }

    #[test]
    fn path_contest_runner_up_matches_overridden_last() {
        // Identity: runner_up() == overridden.last().copied() pointwise
        // across the fixture spectrum. Pins the field-projection
        // definition against every cell of the {0, 1, ≥ 2} silenced
        // partition.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            assert_eq!(
                contest.runner_up(),
                contest.overridden.last().copied(),
                "runner_up disagrees with overridden.last() on {}-toucher fixture",
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_runner_up_matches_contributors_nth_back_one() {
        // Cross-axis identity: runner_up() ==
        // contributors().iter().nth_back(1).copied() — the touchers-axis
        // "one step back from decider" projection. Since contributors()
        // is overridden ++ [decider], nth_back(1) picks the second-to-last
        // toucher = overridden.last() (or None when overridden is empty).
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            let via_contributors = contest.contributors().iter().nth_back(1).copied();
            assert_eq!(
                contest.runner_up(),
                via_contributors,
                "runner_up disagrees with contributors().nth_back(1) on {}-toucher fixture",
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_runner_up_is_some_iff_is_contested() {
        // Presence-boundary identity: runner_up().is_some() ==
        // is_contested() pointwise across the fixture spectrum. The
        // {0, ≥ 1} silenced partition on the runner_up presence bit
        // aligns exactly with the {≤ 0, ≥ 1} silenced partition on the
        // is_contested boolean — same boundary, two projections of the
        // same fact.
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            assert_eq!(
                contest.runner_up().is_some(),
                contest.is_contested(),
                "runner_up presence disagrees with is_contested on {}-toucher fixture",
                contest.contributor_count(),
            );
        }
    }

    #[test]
    fn path_contest_runner_up_never_equals_decider() {
        // Structural invariant: runner_up is drawn exclusively from the
        // losers list — the decider is the winner and never appears
        // there. When runner_up is Some, its value is one of the
        // overridden layers, structurally distinct from the decider.
        // (The layer-name spelling could coincidentally alias in
        // exotic fixtures, but on the substrate-owned contest_at all
        // touchers have distinct names by construction of the test
        // Fixed layers.)
        let (sole, pair_coarse, pair_specific) = contest_fixture();
        for layers in [
            &[sole.as_ref()][..],
            &[pair_coarse.as_ref(), pair_specific.as_ref()][..],
            &[sole.as_ref(), pair_coarse.as_ref(), pair_specific.as_ref()][..],
        ] {
            let contest = contest_at(layers, &["k"]).unwrap();
            if let Some(runner) = contest.runner_up() {
                assert_ne!(
                    runner,
                    contest.decider,
                    "runner_up must not alias decider on {}-toucher fixture",
                    contest.contributor_count(),
                );
                assert!(
                    contest.overridden.contains(&runner),
                    "runner_up must be drawn from the overridden list",
                );
            }
        }
    }

    // ---- runner_up_at (point primitive) ---------------------------------

    #[test]
    fn runner_up_at_none_boundary_matches_is_contested_at() {
        // The false-boundary of the point-primitive lattice collapses
        // two structurally distinct cases under the same None return:
        // zero touchers (nobody opened the key) and one toucher
        // (uncontested singleton — the sole toucher is the decider,
        // nothing sits one step back). Both cells align with
        // is_contested_at(...) == false pointwise.
        let a = Fixed(
            "a",
            dict(&[
                ("solo", Value::from(1i64)),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("live"))])),
                ),
            ]),
        );
        let b = Fixed("b", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&a, &b];
        // Zero touchers → None, not contested.
        assert_eq!(runner_up_at(&layers, &["absent"]), None);
        assert!(!is_contested_at(&layers, &["absent"]));
        // One toucher (only a) → None, not contested.
        assert_eq!(runner_up_at(&layers, &["solo"]), None);
        assert!(!is_contested_at(&layers, &["solo"]));
        // One toucher (only b) → None, not contested.
        assert_eq!(runner_up_at(&layers, &["logger"]), None);
        assert!(!is_contested_at(&layers, &["logger"]));
        // Empty layer stack — no toucher on any path, including root.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(runner_up_at(&empty, &[]), None);
        assert_eq!(runner_up_at(&empty, &["absent"]), None);
    }

    #[test]
    fn runner_up_at_matches_silenced_at_last_across_paths() {
        // Trailing-of-losers identity, the load-bearing point-primitive
        // pin: runner_up_at(layers, p) == silenced_at(layers, p)
        // .last().copied() across every branch of touches_path —
        // contested leaf, uncontested leaf, dict container, root, and
        // the absent (None) boundary.
        let a = Fixed(
            "a",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("live")),
                    ("setpoint", Value::from(0.80)),
                ])),
            )]),
        );
        let b = Fixed(
            "b",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let c = Fixed("c", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["logger"][..],
            &["absent"][..],
        ] {
            let via_primitive = runner_up_at(&layers, path);
            let via_loose = silenced_at(&layers, path).last().copied();
            assert_eq!(
                via_primitive, via_loose,
                "runner_up_at != silenced_at.last() at {path:?}",
            );
        }
    }

    #[test]
    fn runner_up_at_matches_contest_at_runner_up_across_paths() {
        // Fused-value identity across the None boundary:
        // runner_up_at(layers, p) == contest_at(layers, p)
        // .and_then(|c| c.runner_up()) — the point primitive is exactly
        // the trailing-loser projection off contest_at, and both sides
        // map to None on no-contest paths (zero or one toucher).
        // Exercised on the same five-path grid the coarsest_at fused
        // identity uses.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        let middle = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("staging"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&coarse, &middle, &specific];
        for path in [
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["breathe"][..],
            &["absent"][..],
            &[][..],
        ] {
            let via_primitive = runner_up_at(&layers, path);
            let via_fused = contest_at(&layers, path).and_then(|c| c.runner_up());
            assert_eq!(
                via_primitive, via_fused,
                "runner_up_at != contest_at.and_then(|c| c.runner_up()) at {path:?}",
            );
        }
    }

    #[test]
    fn runner_up_at_three_writers_returns_middle_toucher() {
        // Three touchers coarse→specific at breathe.mode. runner_up_at
        // is the middle name `cloud` — one step back from decider
        // (`tenancy`), one step forward from coarsest (`platform`).
        // Silent-in-scope layers (`disjoint` touches a different key)
        // do not shift the runner-up endpoint. Structurally distinct
        // from both coarsest_at and decider_at when at least three
        // layers touch.
        let platform = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let cloud = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("aws"))])),
            )]),
        );
        let tenancy = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("prod"))])),
            )]),
        );
        let disjoint = Fixed("logger", dict(&[("logger", Value::from("info"))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&platform, &cloud, &tenancy, &disjoint];
        assert_eq!(
            runner_up_at(&layers, &["breathe", "mode"]),
            Some("cloud"),
            "runner_up_at is the second-to-last toucher"
        );
        assert_eq!(coarsest_at(&layers, &["breathe", "mode"]), Some("platform"));
        assert_eq!(decider_at(&layers, &["breathe", "mode"]), Some("tenancy"));
        assert_ne!(
            runner_up_at(&layers, &["breathe", "mode"]),
            coarsest_at(&layers, &["breathe", "mode"]),
            "at ≥ 2 silenced, runner_up_at and coarsest_at diverge",
        );
        assert_ne!(
            runner_up_at(&layers, &["breathe", "mode"]),
            decider_at(&layers, &["breathe", "mode"]),
            "runner_up_at is drawn from the losers list, never aliases decider_at",
        );
    }

    #[test]
    fn runner_up_at_singly_contested_aliases_coarsest_at() {
        // Singly contested pairing: at exactly one silenced (two total
        // touchers), the runner-up and the coarsest occupy the same
        // position — the sole silenced layer sits at both endpoints
        // of `overridden` at once. Pins the {silenced_count_at == 1}
        // cell where runner_up_at == coarsest_at ≠ decider_at.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        assert_eq!(silenced_count_at(&layers, &["breathe", "mode"]), 1);
        assert_eq!(
            runner_up_at(&layers, &["breathe", "mode"]),
            coarsest_at(&layers, &["breathe", "mode"]),
            "at exactly one silenced, runner_up_at aliases coarsest_at",
        );
        assert_eq!(
            runner_up_at(&layers, &["breathe", "mode"]),
            Some("platform"),
        );
        assert_ne!(
            runner_up_at(&layers, &["breathe", "mode"]),
            decider_at(&layers, &["breathe", "mode"]),
            "runner_up_at ≠ decider_at even on the singly-contested cell",
        );
    }

    #[test]
    fn runner_up_at_covers_prefix_scalar_erasure() {
        // Prefix-scalar erasure with three touchers: `a` opened the
        // deep subtree, `b` overrode it with a competing subtree, `c`
        // erased everything with a shallow scalar. All three touch
        // the erased leaf. coarsest_at names `a` (opener), runner_up_at
        // names `b` (the closest challenger `c` silenced), decider_at
        // names `c` (erasure agent). Diagnostic renderers reach for
        // the triple to render "opened by a; the closest challenger
        // was b; erased by c" without materializing the contributors
        // vector or the PathContest wrapper.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed(
            "b",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(2i64))])))]),
        );
        let c = Fixed("c", dict(&[("k", Value::from("erased"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        assert_eq!(coarsest_at(&layers, &["k", "leaf"]), Some("a"));
        assert_eq!(runner_up_at(&layers, &["k", "leaf"]), Some("b"));
        assert_eq!(decider_at(&layers, &["k", "leaf"]), Some("c"));
        // Sanity: the three specificity positions are pairwise
        // distinct when at least three layers touch a path.
        let leading = coarsest_at(&layers, &["k", "leaf"]);
        let middle = runner_up_at(&layers, &["k", "leaf"]);
        let trailing = decider_at(&layers, &["k", "leaf"]);
        assert_ne!(leading, middle, "coarsest ≠ runner_up at ≥ 3 touchers");
        assert_ne!(middle, trailing, "runner_up ≠ decider structurally");
        assert_ne!(leading, trailing, "coarsest ≠ decider at ≥ 2 touchers");
    }

    #[test]
    fn runner_up_at_root_boundary_equals_contributor_names_nth_back_one() {
        // Root specialization: runner_up_at(layers, &[]) ==
        // contributor_names(layers).iter().nth_back(1).copied() —
        // the one-step-back-from-decider projection at the empty-path
        // whole-layer specialization. Silent layers between
        // contributors are filtered out on both axes, so an empty
        // layer inserted between two non-empty layers does not shift
        // the endpoint. Dual of decider_at's root specialization at
        // the trailing endpoint; sibling of coarsest_at's root
        // specialization at the leading endpoint.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let names = contributor_names(&layers);
        assert_eq!(
            runner_up_at(&layers, &[]),
            names.iter().nth_back(1).copied()
        );
        assert_eq!(runner_up_at(&layers, &[]), Some("cloud"));
        // Sibling endpoints alignment on the root triple.
        assert_eq!(coarsest_at(&layers, &[]), Some("platform"));
        assert_eq!(decider_at(&layers, &[]), Some("tenancy"));
    }

    #[test]
    fn path_contest_silenced_empty_iff_uncontested() {
        // Uncontested contest (sole toucher is the decider): silenced()
        // is an empty slice, aliasing the boolean !is_contested() and
        // the scalar silenced_count() == 0 on the same losers axis.
        // Structural empty-boundary identity at the method surface.
        let sole = Fixed("only", dict(&[("k", Value::from(1i64))]));
        let layers: [&dyn DiscoveryLayer; 1] = [&sole];
        let contest = contest_at(&layers, &["k"]).expect("sole toucher yields Some");
        assert!(contest.silenced().is_empty(), "no silenced touchers");
        assert_eq!(contest.silenced().len(), 0);
        assert_eq!(contest.silenced().len(), contest.silenced_count());
        assert_eq!(contest.silenced().is_empty(), !contest.is_contested());
    }

    #[test]
    fn path_contest_silenced_singleton_holds_leading_and_trailing_at_once() {
        // Singly-contested cell (one silenced toucher): silenced() is a
        // one-element slice whose leading and trailing entries alias.
        // Structurally, silenced().last() == runner_up() and
        // silenced().first() names the sole loser — which are the same
        // name at silenced_count() == 1.
        let coarse = Fixed("platform", dict(&[("mode", Value::from("live"))]));
        let specific = Fixed("tenancy", dict(&[("mode", Value::from("dry"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let contest = contest_at(&layers, &["mode"]).expect("two touchers yield Some");
        let silenced = contest.silenced();
        assert_eq!(silenced, &["platform"]);
        assert_eq!(silenced.len(), 1);
        assert_eq!(silenced.first().copied(), Some("platform"));
        assert_eq!(silenced.last().copied(), contest.runner_up());
        assert_eq!(silenced.first().copied(), silenced.last().copied());
    }

    #[test]
    fn path_contest_silenced_multi_preserves_coarse_to_specific_order() {
        // Multiply-silenced contest (two or more silenced touchers):
        // silenced() preserves the coarse→specific application order,
        // and its trailing entry equals runner_up(), while its leading
        // entry is structurally distinct from its trailing entry —
        // pinning the ≥ 2 threshold at the method surface.
        let l0 = Fixed("platform", dict(&[("mode", Value::from(0i64))]));
        let l1 = Fixed("cloud", dict(&[("mode", Value::from(1i64))]));
        let l2 = Fixed("orchestrator", dict(&[("mode", Value::from(2i64))]));
        let l3 = Fixed("tenancy", dict(&[("mode", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&l0, &l1, &l2, &l3];
        let contest = contest_at(&layers, &["mode"]).expect("four touchers yield Some");
        let silenced = contest.silenced();
        assert_eq!(silenced, &["platform", "cloud", "orchestrator"]);
        assert_eq!(silenced.last().copied(), contest.runner_up());
        assert_eq!(silenced.first().copied(), Some(contest.coarsest()));
        assert_ne!(silenced.first().copied(), silenced.last().copied());
        assert_eq!(silenced.len() >= 2, contest.is_multiply_silenced());
    }

    #[test]
    fn path_contest_silenced_matches_silenced_at_across_paths() {
        // Cross-path Option-boundary identity between the method and
        // free-function siblings: for every path,
        // contest_at(..).map_or(vec![], |c| c.silenced().to_vec()) ==
        // silenced_at(..). Grid: root (whole-layer), dict-container,
        // multi-writer leaf, single-writer leaf, absent path.
        let base = Fixed(
            "platform",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[
                        ("setpoint", Value::from(0.80)),
                        ("mode", Value::from("live")),
                    ])),
                ),
                ("only_in_base", Value::from(0i64)),
            ]),
        );
        let overlay = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("dry")),
                    ("only_in_overlay", Value::from(1i64)),
                ])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&base, &overlay];
        for path in [
            vec![],
            vec!["breathe"],
            vec!["breathe", "mode"],
            vec!["breathe", "only_in_overlay"],
            vec!["only_in_base"],
            vec!["missing"],
        ] {
            let free = silenced_at(&layers, &path);
            let method_owned =
                contest_at(&layers, &path).map_or_else(Vec::new, |c| c.silenced().to_vec());
            assert_eq!(
                method_owned, free,
                "silenced().to_vec() == silenced_at at path {path:?}"
            );
        }
    }

    #[test]
    fn path_contest_silenced_plus_decider_reconstructs_contributors() {
        // Reconstruction identity at the method surface:
        // [c.silenced(), &[c.decider]].concat() == c.contributors(). The
        // structural symmetry ".silenced() ⊎ {decider}" makes the
        // partition arithmetic hold at the accessor altitude without
        // ever touching the underlying `overridden` field name.
        let l0 = Fixed("platform", dict(&[("k", Value::from(0i64))]));
        let l1 = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let l2 = Fixed("tenancy", dict(&[("k", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&l0, &l1, &l2];
        let contest = contest_at(&layers, &["k"]).expect("three touchers yield Some");
        let mut recomposed: Vec<&'static str> = contest.silenced().to_vec();
        recomposed.push(contest.decider);
        assert_eq!(recomposed, contest.contributors());
    }

    #[test]
    fn path_contest_silenced_aliases_overridden_field_slice() {
        // The zero-allocation body identity: silenced() and
        // overridden.as_slice() return bit-identical slice contents.
        // This test pins the "names, not renames" property — a rename
        // of the field or a future re-storage of the losers list must
        // preserve this equality by construction.
        let l0 = Fixed("platform", dict(&[("k", Value::from(0i64))]));
        let l1 = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let l2 = Fixed("orchestrator", dict(&[("k", Value::from(2i64))]));
        let l3 = Fixed("tenancy", dict(&[("k", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&l0, &l1, &l2, &l3];
        let contest = contest_at(&layers, &["k"]).expect("four touchers yield Some");
        assert_eq!(contest.silenced(), contest.overridden.as_slice());
    }

    #[test]
    fn path_contest_silenced_root_specialization_matches_silenced_at_root() {
        // Root specialization: contest_at at &[] projects the
        // whole-layer touchers partition, and silenced() at that
        // altitude equals silenced_at(&[]) modulo owned/borrowed. Silent
        // (empty) layers between contributors are filtered by both
        // sides, so an empty layer inserted between two non-empty
        // layers does not perturb the losers list.
        let coarse = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let middle = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let specific = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&coarse, &silent, &middle, &specific];
        let contest = contest_at(&layers, &[]).expect("root has touchers");
        assert_eq!(contest.silenced(), &["platform", "cloud"]);
        assert_eq!(contest.silenced().to_vec(), silenced_at(&layers, &[]));
    }

    // ---- PathContest::coarsest_silenced ---------------------------------

    #[test]
    fn path_contest_coarsest_silenced_none_when_uncontested() {
        // Sole-toucher (uncontested contest): coarsest_silenced() is None,
        // aliasing !is_contested() and silenced_count() == 0 on the same
        // losers axis; simultaneously, coarsest() collapses to the sole
        // toucher (equal to decider) — the total identity
        // coarsest_silenced().unwrap_or(decider) == coarsest() holds
        // trivially on this branch.
        let sole = Fixed("only", dict(&[("k", Value::from(1i64))]));
        let layers: [&dyn DiscoveryLayer; 1] = [&sole];
        let contest = contest_at(&layers, &["k"]).expect("sole toucher yields Some");
        assert_eq!(contest.coarsest_silenced(), None);
        assert_eq!(
            contest.coarsest_silenced().is_some(),
            contest.is_contested()
        );
        assert_eq!(contest.coarsest(), contest.decider);
        assert_eq!(
            contest.coarsest_silenced().unwrap_or(contest.decider),
            contest.coarsest(),
        );
    }

    #[test]
    fn path_contest_coarsest_silenced_singly_contested_aliases_runner_up_and_coarsest() {
        // Singly-contested cell (silenced_count() == 1): the sole loser
        // occupies both endpoints of the losers list, so
        // coarsest_silenced() == runner_up() == Some(coarsest()) — all
        // three names alias, and the alias holds structurally against
        // the free-fn coarsest_silenced_at.
        let coarse = Fixed("platform", dict(&[("mode", Value::from("live"))]));
        let specific = Fixed("tenancy", dict(&[("mode", Value::from("dry"))]));
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        let contest = contest_at(&layers, &["mode"]).expect("two touchers yield Some");
        assert_eq!(contest.coarsest_silenced(), Some("platform"));
        assert_eq!(contest.coarsest_silenced(), contest.runner_up());
        assert_eq!(contest.coarsest_silenced(), Some(contest.coarsest()));
        assert_eq!(
            contest.coarsest_silenced(),
            coarsest_silenced_at(&layers, &["mode"]),
        );
    }

    #[test]
    fn path_contest_coarsest_silenced_multi_diverges_from_runner_up() {
        // Multiply-silenced (silenced_count() >= 2): the two silenced
        // endpoints are structurally distinct, so
        // coarsest_silenced() != runner_up(). Simultaneously, on the
        // shared touchers axis, coarsest_silenced() == Some(coarsest())
        // because the coarsest overall toucher is a loser on this
        // branch.
        let l0 = Fixed("platform", dict(&[("mode", Value::from(0i64))]));
        let l1 = Fixed("cloud", dict(&[("mode", Value::from(1i64))]));
        let l2 = Fixed("orchestrator", dict(&[("mode", Value::from(2i64))]));
        let l3 = Fixed("tenancy", dict(&[("mode", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&l0, &l1, &l2, &l3];
        let contest = contest_at(&layers, &["mode"]).expect("four touchers yield Some");
        assert_eq!(contest.coarsest_silenced(), Some("platform"));
        assert_ne!(contest.coarsest_silenced(), contest.runner_up());
        assert_eq!(contest.coarsest_silenced(), Some(contest.coarsest()));
        assert!(contest.is_multiply_silenced());
    }

    #[test]
    fn path_contest_coarsest_silenced_matches_overridden_first() {
        // Zero-allocation body identity: coarsest_silenced() ==
        // overridden.first().copied() == silenced().first().copied().
        // Pins the "names, not renames" property — a future re-storage
        // of the losers list must preserve first-element equality by
        // construction.
        let l0 = Fixed("platform", dict(&[("k", Value::from(0i64))]));
        let l1 = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let l2 = Fixed("orchestrator", dict(&[("k", Value::from(2i64))]));
        let l3 = Fixed("tenancy", dict(&[("k", Value::from(3i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&l0, &l1, &l2, &l3];
        let contest = contest_at(&layers, &["k"]).expect("four touchers yield Some");
        assert_eq!(
            contest.coarsest_silenced(),
            contest.overridden.first().copied()
        );
        assert_eq!(
            contest.coarsest_silenced(),
            contest.silenced().first().copied()
        );
    }

    #[test]
    fn path_contest_coarsest_silenced_matches_free_fn_across_paths() {
        // Cross-path Option-boundary identity between the method and
        // free-function siblings: for every path,
        // contest_at(..).and_then(|c| c.coarsest_silenced()) ==
        // coarsest_silenced_at(..). Grid: root (whole-layer),
        // dict-container, multi-writer leaf, single-writer leaf,
        // absent path.
        let base = Fixed(
            "platform",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[
                        ("setpoint", Value::from(0.80)),
                        ("mode", Value::from("live")),
                    ])),
                ),
                ("only_in_base", Value::from(0i64)),
            ]),
        );
        let overlay = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("dry")),
                    ("only_in_overlay", Value::from(1i64)),
                ])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&base, &overlay];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "only_in_overlay"][..],
            &["only_in_base"][..],
            &["missing"][..],
        ] {
            let free = coarsest_silenced_at(&layers, path);
            let method = contest_at(&layers, path).and_then(|c| c.coarsest_silenced());
            assert_eq!(
                method, free,
                "coarsest_silenced() != coarsest_silenced_at at path {path:?}"
            );
        }
    }

    #[test]
    fn path_contest_coarsest_silenced_totalization_holds_across_paths() {
        // Total totalization identity across the Option boundary:
        // coarsest_silenced().unwrap_or(decider) == coarsest(). The
        // sole-toucher degenerate collapses cleanly on the method
        // surface without a caller-side match.
        let l0 = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let l1 = Fixed("cloud", dict(&[("a", Value::from(2i64))]));
        let l2 = Fixed(
            "tenancy",
            dict(&[("a", Value::from(3i64)), ("b", Value::from(0i64))]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&l0, &l1, &l2];
        // Contested path.
        let cont = contest_at(&layers, &["a"]).expect("three touchers yield Some");
        assert_eq!(
            cont.coarsest_silenced().unwrap_or(cont.decider),
            cont.coarsest()
        );
        // Uncontested path: only l2 touches "b".
        let uncont = contest_at(&layers, &["b"]).expect("sole toucher yields Some");
        assert_eq!(
            uncont.coarsest_silenced().unwrap_or(uncont.decider),
            uncont.coarsest(),
        );
        assert_eq!(uncont.coarsest_silenced(), None);
        assert_eq!(uncont.coarsest(), uncont.decider);
    }

    // ---- coarsest_silenced_at (point primitive) --------------------------

    #[test]
    fn coarsest_silenced_at_none_boundary_matches_is_contested_at() {
        // The None-branch of coarsest_silenced_at collapses zero-toucher
        // and one-toucher paths under the same return, aliased against
        // is_contested_at's negative branch across every no-contest
        // cell.
        let l0 = Fixed("platform", dict(&[("solo", Value::from(1i64))]));
        let l1 = Fixed(
            "tenancy",
            dict(&[
                ("logger", Value::from("json")),
                (
                    "breathe",
                    Value::from(dict(&[("mode", Value::from("dry"))])),
                ),
            ]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&l0, &l1];
        // Absent path — zero touchers.
        assert_eq!(coarsest_silenced_at(&layers, &["absent"]), None);
        assert!(!is_contested_at(&layers, &["absent"]));
        // Solo path — one toucher (l0).
        assert_eq!(coarsest_silenced_at(&layers, &["solo"]), None);
        assert!(!is_contested_at(&layers, &["solo"]));
        // Logger path — one toucher (l1).
        assert_eq!(coarsest_silenced_at(&layers, &["logger"]), None);
        assert!(!is_contested_at(&layers, &["logger"]));
        // Empty stack — nobody opens anything.
        let empty: [&dyn DiscoveryLayer; 0] = [];
        assert_eq!(coarsest_silenced_at(&empty, &[]), None);
        assert_eq!(coarsest_silenced_at(&empty, &["absent"]), None);
    }

    #[test]
    fn coarsest_silenced_at_matches_silenced_at_first_across_paths() {
        // Leading-of-losers identity across a mixed grid:
        // coarsest_silenced_at(l, p) == silenced_at(l, p).first().copied()
        // at every path.
        let base = Fixed(
            "platform",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[
                        ("setpoint", Value::from(0.80)),
                        ("mode", Value::from("live")),
                    ])),
                ),
                ("only_in_base", Value::from(0i64)),
            ]),
        );
        let overlay = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("mode", Value::from("dry")),
                    ("only_in_overlay", Value::from(1i64)),
                ])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&base, &overlay];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "only_in_overlay"][..],
            &["only_in_base"][..],
            &["missing"][..],
        ] {
            let via_primitive = coarsest_silenced_at(&layers, path);
            let via_silenced_first = silenced_at(&layers, path).first().copied();
            assert_eq!(
                via_primitive, via_silenced_first,
                "coarsest_silenced_at != silenced_at.first() at {path:?}",
            );
        }
    }

    #[test]
    fn coarsest_silenced_at_matches_contest_at_projection_across_paths() {
        // Fused-value identity across the None boundary:
        // coarsest_silenced_at(l, p) == contest_at(l, p).and_then(|c|
        // c.coarsest_silenced()) at every path.
        let l0 = Fixed(
            "platform",
            dict(&[
                (
                    "breathe",
                    Value::from(dict(&[
                        ("mode", Value::from("live")),
                        ("setpoint", Value::from(0.80)),
                    ])),
                ),
                ("solo", Value::from(0i64)),
            ]),
        );
        let l1 = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let l2 = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("dry"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&l0, &l1, &l2];
        for path in [
            &[][..],
            &["breathe"][..],
            &["breathe", "mode"][..],
            &["breathe", "setpoint"][..],
            &["solo"][..],
            &["absent"][..],
        ] {
            let via_primitive = coarsest_silenced_at(&layers, path);
            let via_contest = contest_at(&layers, path).and_then(|c| c.coarsest_silenced());
            assert_eq!(
                via_primitive, via_contest,
                "coarsest_silenced_at != contest_at.and_then(|c| c.coarsest_silenced()) at {path:?}",
            );
        }
    }

    #[test]
    fn coarsest_silenced_at_three_writers_returns_leading_toucher() {
        // Three touchers coarse→specific at breathe.mode.
        // coarsest_silenced_at returns the leading (coarsest) toucher —
        // structurally distinct from runner_up_at (trailing loser =
        // middle) and from decider_at (trailing = tenancy), and equal
        // to coarsest_at (leading toucher overall = leading loser on
        // this contested branch).
        let l0 = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let l1 = Fixed(
            "cloud",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let l2 = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("dry"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 3] = [&l0, &l1, &l2];
        assert_eq!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            Some("platform"),
            "coarsest_silenced_at is the leading (coarsest) toucher",
        );
        assert_ne!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            runner_up_at(&layers, &["breathe", "mode"]),
            "at ≥ 2 silenced, coarsest_silenced_at and runner_up_at diverge",
        );
        assert_ne!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            decider_at(&layers, &["breathe", "mode"]),
            "coarsest_silenced_at is drawn from the losers list, never aliases decider_at",
        );
        assert_eq!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            coarsest_at(&layers, &["breathe", "mode"]),
            "on the contested branch, the coarsest overall IS the coarsest silenced",
        );
    }

    #[test]
    fn coarsest_silenced_at_singly_contested_aliases_runner_up_at() {
        // Singly-contested cell: coarsest_silenced_at aliases
        // runner_up_at (the sole silenced layer occupies both endpoints
        // of the losers list). This is the equality boundary of the
        // silenced-endpoint pair at silenced_count_at == 1.
        let coarse = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("live"))])),
            )]),
        );
        let specific = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("dry"))])),
            )]),
        );
        let layers: [&dyn DiscoveryLayer; 2] = [&coarse, &specific];
        assert_eq!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            Some("platform"),
        );
        assert_eq!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            runner_up_at(&layers, &["breathe", "mode"]),
            "at exactly one silenced, coarsest_silenced_at aliases runner_up_at",
        );
        assert_eq!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            coarsest_at(&layers, &["breathe", "mode"]),
        );
        assert_ne!(
            coarsest_silenced_at(&layers, &["breathe", "mode"]),
            decider_at(&layers, &["breathe", "mode"]),
            "coarsest_silenced_at ≠ decider_at even on the singly-contested cell",
        );
    }

    #[test]
    fn coarsest_silenced_at_covers_prefix_scalar_erasure() {
        // Prefix-scalar erasure: a layer covering a subtree with a
        // scalar/array at a proper prefix silences per-leaf opinions
        // beneath the erased leaf. coarsest_silenced_at names the
        // opener (leading loser) — the layer whose deep-leaf opinion
        // was later covered by a shallower-prefix scalar.
        let a = Fixed(
            "a",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(1i64))])))]),
        );
        let b = Fixed(
            "b",
            dict(&[("k", Value::from(dict(&[("leaf", Value::from(2i64))])))]),
        );
        // Wholesale-replace `k` with a scalar at layer c.
        let c = Fixed("c", dict(&[("k", Value::from("scalar"))]));
        let layers: [&dyn DiscoveryLayer; 3] = [&a, &b, &c];
        // At k.leaf, three touchers walk in: a and b (deep leaf) and c
        // (via prefix-scalar erasure). coarsest_silenced_at names `a`
        // (opener); runner_up_at names `b` (finest silenced); decider
        // is `c`.
        assert_eq!(coarsest_silenced_at(&layers, &["k", "leaf"]), Some("a"));
        assert_eq!(runner_up_at(&layers, &["k", "leaf"]), Some("b"));
        assert_eq!(decider_at(&layers, &["k", "leaf"]), Some("c"));
        // Structural distinctness of the three specificity positions
        // on the multiply-silenced branch.
        assert_ne!(
            coarsest_silenced_at(&layers, &["k", "leaf"]),
            runner_up_at(&layers, &["k", "leaf"]),
        );
    }

    #[test]
    fn coarsest_silenced_at_root_boundary_equals_contributor_names_first() {
        // Root specialization: coarsest_silenced_at(layers, &[]) ==
        // contributor_names(layers).first().copied() iff the whole-layer
        // touchers partition is contested. Silent (empty) layers between
        // contributors are filtered by both sides, so an empty layer
        // inserted between two non-empty layers does not perturb the
        // opener.
        let l0 = Fixed("platform", dict(&[("a", Value::from(1i64))]));
        let silent = Fixed("undetectable", Dict::new());
        let l1 = Fixed("cloud", dict(&[("c", Value::from(3i64))]));
        let l2 = Fixed("tenancy", dict(&[("b", Value::from(2i64))]));
        let layers: [&dyn DiscoveryLayer; 4] = [&l0, &silent, &l1, &l2];
        assert_eq!(coarsest_silenced_at(&layers, &[]), Some("platform"));
        assert_eq!(
            coarsest_silenced_at(&layers, &[]),
            contributor_names(&layers).first().copied(),
        );
        // Sibling endpoints alignment on the root triple.
        assert_eq!(coarsest_at(&layers, &[]), Some("platform"));
        assert_eq!(runner_up_at(&layers, &[]), Some("cloud"));
        assert_eq!(decider_at(&layers, &[]), Some("tenancy"));
    }

    /// Test-side clone helper — the `Fixed` layer is deliberately
    /// non-`Clone` at the type-signature level (the trait is
    /// object-safe and callers should always use `&dyn DiscoveryLayer`),
    /// so this trait extends the boxed handle with a per-test-only
    /// deep-clone used by the mixed-fixture identity test above. Not
    /// exported.
    trait CloneBoxed {
        fn clone_boxed(&self) -> Box<dyn DiscoveryLayer>;
    }
    impl CloneBoxed for Fixed {
        fn clone_boxed(&self) -> Box<dyn DiscoveryLayer> {
            Box::new(Fixed(self.0, self.1.clone()))
        }
    }
}

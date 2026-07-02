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
    pub fn iter(&self) -> impl Iterator<Item = (&[String], &'static str)> + '_ {
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
    pub fn subtree_iter<'a>(
        &'a self,
        prefix: &'a [String],
    ) -> impl Iterator<Item = (&'a [String], &'static str)> + 'a {
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
/// with [`deep_merge`]; the future `contributor_count(layers)` scalar is
/// this call's `.len()`. Callers that need any two of those pay 2× the
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
}

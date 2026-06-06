//! Closed-axis and product-cube discipline traits — close the
//! `const ALL: &'static [Self]` enumeration discipline (axis-level) and
//! the realizability surface (cube-level) across the typescape
//! primitive set under two trait interfaces.
//!
//! Every closed-axis primitive on the typescape primitive set — the
//! nine `#[non_exhaustive]` enums [`crate::Format`],
//! [`crate::FormatProvenance`], [`crate::ConfigSourceKind`],
//! [`crate::FigmentSourceKind`], [`crate::ShikumiErrorKind`],
//! [`crate::FieldPathLocalization`], [`crate::AttributionRule`],
//! [`crate::AttributionConfidence`], [`crate::AttributionAxis`] — and
//! the four product-cube structs [`crate::FormatCoordinates`],
//! [`crate::AttributionCoordinates`],
//! [`crate::ErrorLocalizationCoordinates`],
//! [`crate::AttributionSourceKindCoordinates`] expose a closed
//! `Self::ALL: &'static [Self]` slice enumerating every value, in
//! declaration order, with cardinality pinned at the type level. The
//! [`ClosedAxis`] trait closes that discipline structurally: a tenth
//! axis primitive landing on the typescape primitive set is required by
//! the compiler to provide `const ALL` once it
//! `impl ClosedAxis for NewAxis { … }`, and the generic helpers
//! [`axis_iter`] / [`axis_cardinality`] are inherited at the impl
//! declaration without re-writing the per-axis
//! `<Axis>::ALL.iter().copied()` / `<Axis>::ALL.len()` pattern at every
//! consumer (98+ inlined `::ALL.iter().copied()` sites and 378+ inlined
//! `<Axis>::ALL` references across the crate today).
//!
//! Every product cube additionally exposes a
//! `fn is_realizable(self) -> bool` membership predicate over the subset
//! of cells some recognized typescape value occupies, with the
//! realizable cells partitioning `ALL` into the recognized image and
//! the cross-axis consistency-violation complement. The
//! [`ProductCube`]: [`ClosedAxis`] sub-trait closes that discipline
//! structurally on top of the axis-level discipline: a fifth product
//! cube landing on the typescape (e.g. a future
//! `(figment_source_kind × axis × confidence)` cube refining the
//! source-axis attribution rule space, or a `(format × name_style)`
//! cube refining the discovery axis) is required by the compiler to
//! provide `is_realizable` once it `impl ProductCube for NewCube { … }`
//! — the discipline becomes structural rather than
//! convention-by-naming.
//!
//! Generic helpers [`realizable_iter`] / [`unrealizable_iter`] /
//! [`realizable_count`] / [`unrealizable_count`] consolidate the
//! per-cube `ALL.iter().copied().filter(|c| c.is_realizable())` /
//! `… filter(|c| !c.is_realizable()).count()` patterns that appeared
//! at three sites per cube in the per-cube test suites
//! (12 inlined filters across the four cubes today). Consumers route
//! through the generic helper with the cube type as a turbofish
//! parameter instead of re-deriving the filter inline.

use std::hash::Hash;

/// Closed discipline trait every typescape closed-axis primitive and
/// every typescape product cube satisfies.
///
/// A closed axis is any `Copy + Eq + Hash + 'static` type — typically a
/// `#[non_exhaustive]` enum or a struct over closed-enum fields — that
/// exposes a closed `Self::ALL: &'static [Self]` slice enumerating
/// every value, in declaration order. The slice cardinality is pinned
/// at the type level (the variant count for an enum, the Cartesian
/// product of the constituent axis cardinalities for a product cube).
///
/// Implementors today: the nine closed-enum axis primitives on the
/// typescape primitive set ([`crate::Format`],
/// [`crate::FormatProvenance`], [`crate::ConfigSourceKind`],
/// [`crate::FigmentSourceKind`], [`crate::ShikumiErrorKind`],
/// [`crate::FieldPathLocalization`], [`crate::AttributionRule`],
/// [`crate::AttributionConfidence`], [`crate::AttributionAxis`]) plus
/// the four product cubes ([`crate::FormatCoordinates`],
/// [`crate::AttributionCoordinates`],
/// [`crate::ErrorLocalizationCoordinates`],
/// [`crate::AttributionSourceKindCoordinates`]). All thirteen plug
/// into [`axis_iter`] / [`axis_cardinality`] uniformly.
///
/// The trait bounds (`Copy + Eq + Hash + 'static`) match the hand-
/// disciplined `derive`-set on every existing implementor
/// (`Debug, Clone, Copy, PartialEq, Eq, Hash` on each closed enum;
/// the same set plus `#[non_exhaustive]` on each cube struct), so the
/// abstraction is zero-overhead: generic helpers re-use the same
/// `Copy`-by-value receiver pattern as the per-axis inherent methods.
///
/// `Sized` is implied by the `'static` bound; the `'static` bound is
/// required by `const ALL: &'static [Self]`. The trait is intentionally
/// not object-safe (`const` items) — consumers route generically over
/// the axis type parameter, not over `dyn ClosedAxis` trait objects.
pub trait ClosedAxis: Copy + Eq + Hash + 'static {
    /// Every value of the closed-axis primitive (or every cell of the
    /// product cube), in declaration order over the inherent
    /// `Self::ALL` constant.
    ///
    /// Mirror of the inherent `Self::ALL` constant every implementor
    /// already exposes. The trait re-export lets generic helpers
    /// ([`axis_iter`], [`axis_cardinality`], [`realizable_iter`],
    /// [`realizable_count`], future cube-cover dashboards) reach the
    /// constant without naming the concrete axis type — the per-axis
    /// `*_trait_all_matches_inherent_all` tests pin the two slices to
    /// the same contents pointwise.
    const ALL: &'static [Self];
}

/// Iterate every value of a [`ClosedAxis`] — `A::ALL.iter().copied()`
/// collapsed to one named helper.
///
/// Consolidates the `A::ALL.iter().copied()` pattern that appears at
/// 98+ sites across the crate (per-axis cover/partition tests,
/// cube-coverage loops, dashboard initializers, attestation manifest
/// builders). Generic in the axis type so the helper is inherited
/// uniformly across the closed-axis discipline.
pub fn axis_iter<A: ClosedAxis>() -> impl Iterator<Item = A> {
    A::ALL.iter().copied()
}

/// Cardinality of a [`ClosedAxis`] — `A::ALL.len()` collapsed to one
/// named helper.
///
/// Today's axis cardinalities — 4 ([`crate::Format`]),
/// 2 ([`crate::FormatProvenance`]), 3 ([`crate::ConfigSourceKind`]),
/// 3 ([`crate::FigmentSourceKind`]), 6 ([`crate::ShikumiErrorKind`]),
/// 3 ([`crate::FieldPathLocalization`]), 5 ([`crate::AttributionRule`]),
/// 2 ([`crate::AttributionConfidence`]),
/// 2 ([`crate::AttributionAxis`]) — and today's cube cardinalities — 8
/// ([`crate::FormatCoordinates`]), 12 ([`crate::AttributionCoordinates`]),
/// 18 ([`crate::ErrorLocalizationCoordinates`]),
/// 9 ([`crate::AttributionSourceKindCoordinates`]) — reachable as one
/// method call across all thirteen implementors uniformly.
#[must_use]
pub fn axis_cardinality<A: ClosedAxis>() -> usize {
    A::ALL.len()
}

/// Structural ordinal of a [`ClosedAxis`] value — the position of
/// `value` in `A::ALL`, in declaration order.
///
/// Dual of [`axis_iter`]: where [`axis_iter`] is the forward map
/// `ordinal → value` (`A::ALL[i] = value`), [`axis_ordinal`] is the
/// inverse `value → ordinal` (`A::ALL.iter().position(value)`). The two
/// directions close a structural bijection between every
/// [`ClosedAxis`] implementor and the prefix `0..axis_cardinality::<A>()`
/// of the natural numbers — a stable, deterministic embedding of every
/// typescape primitive into a dense integer range.
///
/// **Totality** — the [`ClosedAxis`] discipline pins that `A::ALL`
/// enumerates every value of the axis in declaration order, so every
/// `value: A` has a unique position in the slice. The helper returns
/// `usize` (not `Option<usize>`) because the discipline guarantees
/// totality; a `None` return would witness a discipline violation
/// (`A::ALL` missing a value the type system says exists). The
/// fallback `unreachable!` exists only to satisfy the compiler — it
/// would fire if a future `impl ClosedAxis` lied about `ALL`, in
/// which case the per-axis `axis_ordinal_round_trips_*` invariant
/// would also fail at the trait-uniform test site.
///
/// **Injectivity** — `A::ALL` carries no duplicates (every existing
/// implementor's per-axis `*_all_has_no_duplicates` test pins this
/// pointwise, and the trait-uniform
/// [`tests::axis_ordinal_injective_for_every_closed_axis_implementor`]
/// re-states it once across all 13 implementors), so distinct values
/// land at distinct positions. The ordinal is a structural injection
/// `A → ℕ` whose image equals `0..axis_cardinality::<A>()` as a set —
/// the canonical dense embedding of the axis.
///
/// **Round-trip law** — `A::ALL[axis_ordinal(v)] == v` for every
/// `v: A`, and dually `axis_ordinal(A::ALL[i]) == i` for every
/// `i < axis_cardinality::<A>()`. Both directions pinned by the
/// trait-uniform tests reaching every implementor.
///
/// **Consumers** — dense bitsets / arrays sized by
/// [`axis_cardinality::<A>()`][axis_cardinality] index through the
/// ordinal without a `HashMap<A, usize>` per call site; canonical
/// attestation manifests (THEORY.md §III.1.8 module manifests, §V.3
/// three-pillar attestation) hash typescape cells in stable
/// declaration order pinned by the ordinal; future cube-cover
/// dashboards order rows by the ordinal of each axis cell instead of
/// re-deriving the position lookup inline.
///
/// # Panics
///
/// Panics — via `unreachable!` — only if a `ClosedAxis` implementor
/// violates the discipline by omitting a reachable value from
/// `Self::ALL`. The trait-uniform `axis_ordinal_round_trips_*` tests
/// would fail at the same site; in practice this branch is unreachable
/// for any well-formed implementor.
#[must_use]
pub fn axis_ordinal<A: ClosedAxis>(value: A) -> usize {
    match A::ALL.iter().position(|&v| v == value) {
        Some(i) => i,
        None => unreachable!(
            "ClosedAxis::ALL must contain every value of the axis (discipline violation: \
             `Self::ALL` omitted a reachable value)",
        ),
    }
}

/// Structural ordinal lookup for a [`ClosedAxis`] — the value at
/// position `ordinal` in `A::ALL`, or [`None`] if the index is
/// out-of-range.
///
/// Safe forward dual of [`axis_ordinal`]: where [`axis_ordinal`] is
/// the total inverse `value → ordinal` over the closed axis, [`axis_at`]
/// is the partial forward `ordinal → Option<value>` over `usize`,
/// returning [`Some`] exactly on the prefix `0..axis_cardinality::<A>()`
/// and [`None`] outside it.
///
/// The pair ([`axis_ordinal`], [`axis_at`]) closes the bijection
/// between every [`ClosedAxis`] implementor and the natural-number
/// prefix `0..axis_cardinality::<A>()` in both directions, with
/// out-of-range indices reported as [`None`] rather than panicking on
/// the slice index. Where [`axis_iter`] streams `A::ALL` in
/// declaration order (the total forward map keyed implicitly by
/// position), [`axis_at`] is the same map keyed explicitly by a
/// caller-provided index — a content-addressable lookup that hands
/// the `ordinal` axis to the caller without re-deriving
/// `A::ALL.get(ordinal).copied()` at every consumer.
///
/// **Bijection laws** — pinned by trait-uniform tests reaching every
/// implementor pointwise:
///
/// 1. **Round-trip from the value side** —
///    `axis_at::<A>(axis_ordinal::<A>(v)) == Some(v)` for every
///    `v: A`. The ordinal-then-lookup composition is the identity on
///    `A`.
/// 2. **Round-trip from the ordinal side** —
///    `axis_at::<A>(i).map(axis_ordinal::<A>) == Some(i)` for every
///    `i < axis_cardinality::<A>()`. The lookup-then-ordinal
///    composition is the identity on the in-range prefix.
/// 3. **Partiality on out-of-range** —
///    `axis_at::<A>(i).is_none()` for every
///    `i >= axis_cardinality::<A>()`. The forward map is total over
///    the prefix and undefined outside it; the [`Option`] return
///    surfaces the partiality at the type level instead of by
///    convention.
///
/// **Consumers** — deserializing attestation manifests
/// (THEORY.md §III.1.8 module manifests, §V.3 three-pillar
/// attestation) that carry typescape cells by stable declaration
/// ordinal recover the typed value via [`axis_at`] without an
/// `A::ALL.get(i).copied()` inline at every loader site. Dense
/// arrays sized by [`axis_cardinality::<A>()`][axis_cardinality]
/// look up the typed value at a given position safely. Future
/// cube-cover dashboards that render rows keyed by ordinal index
/// recover the row's typescape cell through one named helper rather
/// than re-deriving the slice-`get` per renderer.
#[must_use]
pub fn axis_at<A: ClosedAxis>(ordinal: usize) -> Option<A> {
    A::ALL.get(ordinal).copied()
}

/// Dense, declaration-ordered per-cell observation tally over a
/// [`ClosedAxis`] — the typed histogram every fleet observer reaches for
/// when bucketing observations by axis cell.
///
/// The histogram's value space is sized by
/// [`axis_cardinality::<A>()`][axis_cardinality]: one [`usize`] slot per
/// axis cell, laid out in declaration order over [`ClosedAxis::ALL`]
/// (i.e. indexed by [`axis_ordinal`]). Every observation increments
/// exactly one slot through [`Self::observe`] (or [`Self::from_iter`] in
/// bulk).
///
/// **Why one typed primitive.** The per-axis observation-mix histogram
/// is named as a use case in seventeen-plus doc-strings across the crate
/// — `crate::ConfigDiff::render_unified`'s per-kind summary on the
/// diff-cell axis ([`crate::DiffLineKind`]; "this rebuild added 12,
/// removed 4"), per-backend telemetry on
/// [`crate::SecretBackendKind`], per-class reload-trigger counts on
/// [`crate::WatchEventClass`], per-kind reload-failure buckets on
/// [`crate::ShikumiErrorKind`], per-confidence attribution mix on
/// [`crate::AttributionConfidence`], attestation manifests recording the
/// per-axis cardinality mix of resolved values — yet no typed lift
/// existed. Every observer re-derived the count loop inline as
/// `items.iter().filter(|x| x.kind() == k).count()` per cell, or
/// `items.iter().fold(HashMap::new(), |mut m, x| { *m.entry(x).or_insert(0) += 1; m })`
/// with the indeterminate ordering and one-allocation-per-key overhead a
/// `HashMap` brings. The lift names the (closed-axis × iterable
/// observations → per-cell counts) projection at one site, indexed by
/// [`axis_ordinal`] so the dense layout agrees with [`axis_iter`] /
/// [`axis_at`] pointwise.
///
/// **Type-level axis tagging.** The [`std::marker::PhantomData<A>`] slot
/// keeps the histogram parameterized by axis at the type level: a
/// `AxisHistogram<DiffLineKind>` cannot be passed where an
/// `AxisHistogram<WatchEventClass>` is expected. Cross-axis confusion
/// (rendering a diff-kind histogram through a reload-event renderer, or
/// vice versa) is structurally impossible — the compiler catches the
/// swap at the call site rather than silently mis-attributing counts.
///
/// **Algebraic structure.** The histogram is a free commutative monoid
/// over the axis cells under pointwise addition: [`Self::empty`] is the
/// identity, [`Self::merge`] is the binary operation. Both are pinned by
/// the trait-uniform invariant tests reaching every [`ClosedAxis`]
/// implementor uniformly.
///
/// **Implementor coverage.** Generic over the [`ClosedAxis`] trait
/// bound, so every closed-axis primitive on the typescape (the twenty
/// closed-enum kinds plus the five product cubes — twenty-five
/// implementors uniformly) inherits the histogram primitive at no
/// per-axis cost. Trait-uniform laws reach every implementor through
/// `for_each_closed_axis_implementor!` in [`tests`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxisHistogram<A: ClosedAxis> {
    counts: Vec<usize>,
    _marker: std::marker::PhantomData<A>,
}

impl<A: ClosedAxis> Default for AxisHistogram<A> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<A: ClosedAxis> AxisHistogram<A> {
    /// The all-zero histogram — every cell at zero, [`Self::total`] = 0,
    /// [`Self::is_empty`] = `true`. The monoid identity under
    /// [`Self::merge`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            counts: vec![0usize; axis_cardinality::<A>()],
            _marker: std::marker::PhantomData,
        }
    }

    /// Record one observation: bump the cell at `value` by one.
    pub fn observe(&mut self, value: A) {
        self.counts[axis_ordinal(value)] += 1;
    }

    /// Number of observations recorded on `value`. Defined on every
    /// axis cell (returns zero for cells no observation landed on);
    /// total over the axis space without an out-of-range case.
    #[must_use]
    pub fn count(&self, value: A) -> usize {
        self.counts[axis_ordinal(value)]
    }

    /// Sum of every cell — the total number of observations recorded.
    /// Equal to the length of the input iterator passed to
    /// [`Self::from_iter`] or to [`axis_histogram`]; pinned by the
    /// trait-uniform `axis_histogram_total_equals_input_length_*` law
    /// in [`tests`].
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.iter().sum()
    }

    /// `true` when every cell is zero — equivalent to
    /// `self.total() == 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.iter().all(|&c| c == 0)
    }

    /// Iterate every `(axis-value, count)` pair in declaration order
    /// over [`ClosedAxis::ALL`]. Length equals
    /// [`axis_cardinality::<A>()`][axis_cardinality] regardless of how
    /// many cells are nonzero — the iteration covers the full axis,
    /// not just observed cells. The ordering agrees with
    /// [`axis_iter::<A>()`][axis_iter] pointwise.
    pub fn iter(&self) -> impl Iterator<Item = (A, usize)> + '_ {
        axis_iter::<A>()
            .enumerate()
            .map(|(i, v)| (v, self.counts[i]))
    }

    /// Iterate only the nonzero `(axis-value, count)` pairs in
    /// declaration order — the complement of the zero-cells. Useful
    /// for rendering compact operator-facing summaries that skip
    /// unobserved categories (a CLI `config-diff` summary listing
    /// `"added: 12, removed: 4"` without the `context: 53` cell, a
    /// structured-log field listing only the error classes that fired
    /// in the last reload window). Pointwise prefix of [`Self::iter`]
    /// filtered by `count > 0`.
    pub fn nonzero(&self) -> impl Iterator<Item = (A, usize)> + '_ {
        self.iter().filter(|&(_, c)| c > 0)
    }

    /// Iterate the axis cells that received no observations — the
    /// structural complement of [`Self::nonzero`] over the closed
    /// axis, in declaration order over [`ClosedAxis::ALL`]. The cells
    /// for which `self.count(v) == 0`.
    ///
    /// The **"coverage gap"** projection on the histogram — the
    /// natural typed primitive for diagnostic dumps, attestation
    /// manifests, and dashboards asking *"which kinds were never
    /// observed in this window?"*: the unfired error classes in a
    /// per-window `AxisHistogram<crate::ShikumiErrorKind>` (the
    /// "we never saw a Parse error this reload" attestation), the
    /// unused file formats in a chain's
    /// [`crate::ConfigSourceChain::file_format_histogram`] (the
    /// "this chain never realized a `.lisp` layer" coverage gap),
    /// the layer kinds the chain never produced in
    /// [`crate::ConfigSourceChain::layer_kind_histogram`] (the
    /// "no Env layer this rebuild" diagnostic), the diff-line
    /// classes absent from a window in
    /// [`crate::ConfigDiff::kind_histogram`] (the "no Removed
    /// lines in this rebuild" attestation). Before this lift, every
    /// such consumer re-derived the projection inline as
    /// `hist.iter().filter(|&(_, c)| c == 0).map(|(v, _)| v)` at
    /// every site, with the (zero-count → unobserved) filter open-
    /// coded at each call site. The lift names the projection at
    /// one site.
    ///
    /// **Structural complement of [`Self::nonzero`]** — every cell
    /// of the closed axis lies in exactly one of the two iterators:
    /// `nonzero().count() + unobserved().count() ==
    /// axis_cardinality::<A>()`, and the cell-set yielded by
    /// `nonzero().map(|(v, _)| v)` is disjoint from the cell-set
    /// yielded by `unobserved()`. The (observed, unobserved)
    /// partition closes the histogram's support boundary at the
    /// surface: `Self::nonzero` reads the *support* (the multiset's
    /// observed kinds), `Self::unobserved` reads the *coverage gap*
    /// (the unobserved kinds), and the closed axis partitions into
    /// the two without remainder. Pinned uniformly by
    /// [`tests::axis_histogram_unobserved_and_nonzero_partition_axis_for_every_closed_axis_implementor`].
    ///
    /// **Counts are zero, omitted from the item shape** — the
    /// iterator yields just `A` (the cell), not `(A, usize)`: every
    /// yielded cell has count zero by definition, so the count
    /// carries no information and an unconditional `(v, 0)` pair
    /// would noise the call sites (`for missing in hist.unobserved()`
    /// reads cleanly without a `let (m, _) = …` destructure). The
    /// asymmetry with [`Self::nonzero`] is intentional: the
    /// observed-cells iterator carries counts because they vary; the
    /// unobserved-cells iterator drops them because they don't.
    ///
    /// **Empty-histogram convention** — the empty histogram has
    /// every cell unobserved, so [`Self::unobserved`] iterates the
    /// full axis (pointwise equal to [`axis_iter::<A>()`][axis_iter])
    /// and [`Self::nonzero`] is empty. The full-cover histogram (every
    /// cell observed at least once) is the dual boundary:
    /// [`Self::unobserved`] is empty and [`Self::nonzero`] iterates
    /// the full axis. The two boundaries pin the partition's tight
    /// witnesses.
    ///
    /// **Companion invariant** with [`Self::distinct_cells`] and
    /// [`axis_cardinality`]:
    /// - `unobserved().count() == axis_cardinality::<A>() -
    ///   distinct_cells()` — the coverage-gap size reads off the
    ///   support cardinality through subtraction from the axis size.
    /// - `unobserved().next().is_none()` ⇔ `distinct_cells() ==
    ///   axis_cardinality::<A>()` — the full-cover predicate (every
    ///   cell observed at least once) reaches the same boolean as the
    ///   support-equals-axis-cardinality equality.
    /// - `unobserved().count() == axis_cardinality::<A>()` ⇔
    ///   [`Self::is_empty`] — the empty-histogram boundary, peer to
    ///   `distinct_cells() == 0 ⇔ is_empty()`.
    ///
    /// **Monotonicity under [`Self::merge`]** — merging never grows
    /// the coverage gap: every cell observed in either side is
    /// observed in the merge, so
    /// `merge(self, other).unobserved().count() <=
    /// self.unobserved().count().min(other.unobserved().count())`.
    /// The dual of the monotone-support law on [`Self::distinct_cells`]
    /// (merging never shrinks the support).
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits
    /// the projection at no per-axis cost. The four trait-uniform
    /// laws pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_unobserved_empty_is_full_axis_*`,
    /// `axis_histogram_unobserved_axis_cover_is_empty_*`,
    /// `axis_histogram_unobserved_singleton_omits_observed_cell_*`,
    /// `axis_histogram_unobserved_and_nonzero_partition_axis_*`).
    pub fn unobserved(&self) -> impl Iterator<Item = A> + '_ {
        self.iter().filter(|&(_, c)| c == 0).map(|(v, _)| v)
    }

    /// Number of distinct axis cells that received at least one
    /// observation — the **support cardinality** of the histogram.
    /// Equivalent to `self.nonzero().count()`; the structural
    /// cardinality peer to [`Self::total`].
    ///
    /// Where [`Self::total`] sums observation counts (the *size*
    /// aggregate over the multiset of observations),
    /// `distinct_cells` counts the cells that received any
    /// observation (the *support* of the multiset — the cardinality
    /// of the underlying set of observed cells). Together they form
    /// the natural pair of scalar projections every typed histogram
    /// carries: `total` reads "how many observations", `distinct_cells`
    /// reads "how many *kinds* of observation", `dominant_cell` reads
    /// "*which* kind dominates". Before this lift, every consumer
    /// asking "did the chain see at least N distinct kinds?" re-derived
    /// the projection inline as `hist.iter().filter(|&(_, c)| c > 0).count()`
    /// or `hist.nonzero().count()`; the lift names the projection at
    /// one site so a future consumer's coverage check, attestation
    /// manifest support count, or diagnostic "N of M kinds observed"
    /// summary reads off one method call.
    ///
    /// **Structural bounds.** The return value is always in the
    /// interval `[0, axis_cardinality::<A>()]`. Tight at both ends:
    /// the empty histogram reads `0`, the uniform axis-cover
    /// histogram reads `axis_cardinality::<A>()`. The projection
    /// connects the histogram surface to the typescape's structural
    /// axis size — `distinct_cells == axis_cardinality::<A>()` is the
    /// "*every* cell observed" coverage predicate, reachable as a
    /// single equality.
    ///
    /// **Companion invariants.**
    /// - `distinct_cells() == 0` ⇔ [`Self::is_empty`] is `true`
    ///   (peer to the empty-histogram boundary equivalence
    ///   [`Self::dominant_cell`] carries).
    /// - `distinct_cells() <= total()` always: each distinct cell
    ///   contributes at least one observation, so the support is
    ///   bounded by the multiset's size.
    /// - `distinct_cells() == total()` iff every observed cell
    ///   appears exactly once — the "uniform-singleton" shape.
    /// - `distinct_cells() <= axis_cardinality::<A>()` always: the
    ///   support is bounded by the axis size.
    /// - `merge(self, other).distinct_cells() >=
    ///   self.distinct_cells().max(other.distinct_cells())`: the
    ///   support is monotone under [`Self::merge`] — merging never
    ///   shrinks the set of observed cells.
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_distinct_cells_empty_is_zero_*`,
    /// `axis_histogram_distinct_cells_singleton_is_one_*`,
    /// `axis_histogram_distinct_cells_axis_cover_equals_cardinality_*`).
    #[must_use]
    pub fn distinct_cells(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// Number of axis cells that received no observations — the
    /// **coverage-gap cardinality** of the histogram. The scalar peer of
    /// the [`Self::unobserved`] iterator on the count side and the
    /// structural complement of [`Self::distinct_cells`] over the closed
    /// axis: every cell of [`ClosedAxis::ALL`] lies in exactly one of
    /// the (observed, unobserved) sub-axes, and the two scalar counts
    /// partition the axis without remainder
    /// (`distinct_cells() + unobserved_cells() == axis_cardinality::<A>()`).
    ///
    /// The natural typed primitive for diagnostic dumps, coverage
    /// dashboards, and attestation manifests asking *"how many axis
    /// kinds were missing from this observation window?"*: the unfired
    /// error-class count in a per-window
    /// `AxisHistogram<crate::ShikumiErrorKind>` (the "N of M error
    /// classes never fired this reload" attestation), the unused
    /// file-format count in a chain's
    /// [`crate::ConfigSourceChain::file_format_histogram`] (the
    /// "N formats unused in this chain" coverage cell), the absent
    /// layer-kind count in a chain's
    /// [`crate::ConfigSourceChain::layer_kind_histogram`] (the "N layer
    /// kinds the chain never produced" diagnostic — the natural pair to
    /// the "M layer kinds observed" cell on the same row), the absent
    /// diff-line class count in
    /// [`crate::ConfigDiff::kind_histogram`] (the "N diff classes absent
    /// from this rebuild" attestation). Before this lift, every such
    /// consumer re-derived the projection inline as
    /// `hist.unobserved().count()` — which walked the histogram through
    /// the `iter().filter(|&(_, c)| c == 0).map(|(v, _)| v)` chain plus
    /// the trailing `.count()` (a five-stage iterator adaptor when a
    /// single-pass `.filter(|&&c| c == 0).count()` over the raw counts
    /// vector reads the same scalar). The lift names the projection at
    /// one site, consumers route through one method call, and the
    /// (observed, unobserved) cardinality partition becomes a typed
    /// equality between two named scalars rather than one named scalar
    /// against a generic helper.
    ///
    /// **Underflow-safe by construction.** The pointwise equivalent
    /// derivation `axis_cardinality::<A>() - distinct_cells()` is
    /// guaranteed non-negative on every histogram (the support is
    /// bounded above by the axis size — pinned by the
    /// `distinct_cells <= axis_cardinality` invariant on
    /// [`Self::distinct_cells`]), so the subtraction never wraps. The
    /// named scalar surfaces the bound; consumers do not re-prove
    /// monotonicity at the call site.
    ///
    /// **Structural bounds.** The return value is always in the
    /// interval `[0, axis_cardinality::<A>()]`. Tight at both ends: the
    /// uniform axis-cover histogram reads `0` (every cell observed, no
    /// gap), the empty histogram reads `axis_cardinality::<A>()`
    /// (every cell unobserved, the full gap). The projection connects
    /// the histogram surface to the typescape's structural axis size —
    /// `unobserved_cells == 0` is the "*every* cell observed" coverage
    /// predicate, reachable as a single equality.
    ///
    /// **Companion invariants.**
    /// - `unobserved_cells() == axis_cardinality::<A>() - distinct_cells()`
    ///   always: the coverage-gap cardinality reads off the support
    ///   cardinality through one subtraction from the axis size. The
    ///   (observed, unobserved) cardinality partition.
    /// - `unobserved_cells() == axis_cardinality::<A>()` ⇔
    ///   [`Self::is_empty`] is `true` (peer to `distinct_cells() == 0 ⇔
    ///   is_empty()` on the dual side of the partition).
    /// - `unobserved_cells() == 0` ⇔ `distinct_cells() ==
    ///   axis_cardinality::<A>()` — the full-cover predicate (every
    ///   cell observed at least once), peer to
    ///   `unobserved().next().is_none()` on the iterator side.
    /// - `unobserved_cells() == self.unobserved().count()` always:
    ///   pointwise equal to the iterator's length, lifting the
    ///   five-stage `iter().filter().map().filter().count()` chain to a
    ///   single-pass count on the raw counts vector.
    /// - `merge(self, other).unobserved_cells() <=
    ///   self.unobserved_cells().min(other.unobserved_cells())`: the
    ///   coverage gap is *monotone-decreasing* under [`Self::merge`] —
    ///   merging never grows the gap (every cell observed in either
    ///   side is observed in the merge, so the unobserved set is the
    ///   intersection of the two sides' unobserved sets). The dual of
    ///   the monotone-growth law on [`Self::distinct_cells`].
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_unobserved_cells_empty_equals_cardinality_*`,
    /// `axis_histogram_unobserved_cells_singleton_is_cardinality_minus_one_*`,
    /// `axis_histogram_unobserved_cells_axis_cover_is_zero_*`).
    ///
    /// Peer to [`Self::total`] (the *sum* over every cell),
    /// [`Self::distinct_cells`] (the *observed-cells cardinality* —
    /// dual side of the partition), [`Self::peak_count`] (the *modal*
    /// count scalar), [`Self::trough_count`] (the *rarest-observed*
    /// count scalar), and [`Self::spread`] (the *observed-distribution
    /// skew* scalar): the scalar surface of the histogram now carries
    /// the natural sextuple of
    /// `(how many observations, how many kinds, how many gaps, how many
    /// on the peak, how many on the trough, how much spread)`
    /// projections — every operator-facing summary reads off one method
    /// call each, and the *full-cover* predicate (`unobserved_cells()
    /// == 0`) reads off a single equality on the closed scalar surface.
    #[must_use]
    pub fn unobserved_cells(&self) -> usize {
        self.counts.iter().filter(|&&c| c == 0).count()
    }

    /// The first axis cell (in declaration order over [`ClosedAxis::ALL`])
    /// whose observation count equals the maximum count over the
    /// histogram; `None` when no cell carries any observation
    /// (i.e. [`Self::is_empty`] is `true`).
    ///
    /// The "argmax" / "modal cell" projection on the histogram — the
    /// natural typed primitive for diagnostic dumps, dashboards, and
    /// attestation manifests asking *"which cell dominates this
    /// observation window?"*: the dominant layer kind in a chain's
    /// [`crate::ConfigSourceChain::layer_kind_histogram`], the most
    /// common file format in
    /// [`crate::ConfigSourceChain::file_format_histogram`], the
    /// dominant diff-line class in
    /// [`crate::ConfigDiff::kind_histogram`] for a "rebuild summary"
    /// line, the most common reload-failure kind in a per-window
    /// `AxisHistogram<crate::ShikumiErrorKind>`. Before this lift, every
    /// such consumer re-derived the loop inline as
    /// `hist.iter().filter(|&(_, c)| c > 0).max_by_key(|&(_, c)| c).map(|(v, _)| v)`
    /// — and the inline `max_by_key` form silently returned the *last*
    /// tied cell rather than the first (per
    /// [`Iterator::max_by_key`]'s contract), so two consumers reading
    /// "the dominant cell" off the same histogram could disagree under
    /// ties unless every one carefully reversed the comparison. The
    /// lift names the projection at one site with a documented
    /// tie-breaking rule.
    ///
    /// **Tie-breaking is deterministic by declaration order.** When
    /// multiple cells share the maximum count, the cell earliest in
    /// [`ClosedAxis::ALL`] wins — pointwise consistent with the order
    /// [`Self::iter`] yields. The same histogram observed under
    /// different observation orders therefore yields the same
    /// dominant cell: observation order does not leak through the
    /// projection.
    ///
    /// **Empty-histogram convention.** Returns `None` exactly when
    /// [`Self::is_empty`] is `true`. A histogram with even a single
    /// observation always has a dominant cell (the observed one). A
    /// histogram whose every cell observes the same nonzero count
    /// returns `Some(first cell)` — the unique cell in declaration
    /// order with the maximum.
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_dominant_cell_empty_is_none_*`,
    /// `axis_histogram_dominant_cell_singleton_picks_observed_*`,
    /// `axis_histogram_dominant_cell_axis_cover_picks_first_*`).
    ///
    /// Peer to [`Self::total`] (the *aggregate* over every cell) and
    /// [`Self::nonzero`] (the *subset* of cells with observations):
    /// `Self::total` reads the scalar sum, `Self::nonzero` reads the
    /// subset, `Self::dominant_cell` reads the modal cell — the three
    /// natural aggregate projections of a typed histogram.
    #[must_use]
    pub fn dominant_cell(&self) -> Option<A> {
        let mut iter = self.iter().filter(|&(_, c)| c > 0);
        let first = iter.next()?;
        Some(
            iter.fold(
                first,
                |best, current| {
                    if current.1 > best.1 { current } else { best }
                },
            )
            .0,
        )
    }

    /// The first axis cell (in declaration order over [`ClosedAxis::ALL`])
    /// whose observation count equals the minimum *positive* count over
    /// the histogram; `None` when no cell carries any observation
    /// (i.e. [`Self::is_empty`] is `true`).
    ///
    /// The "argmin" / "rarest observed cell" projection on the
    /// histogram — the structural dual of [`Self::dominant_cell`] on
    /// the *minority* side. The natural typed primitive for diagnostic
    /// dumps and dashboards asking *"which cell is the rarest in this
    /// observation window?"*: the rarest observed layer kind in a
    /// chain's [`crate::ConfigSourceChain::layer_kind_histogram`] (a
    /// reload that fires once with a single Defaults entry on an
    /// otherwise File-dominated chain), the least common file format
    /// in [`crate::ConfigSourceChain::file_format_histogram`] (a single
    /// `.lisp` layer among many `.yaml`), the rarest reload-failure
    /// kind in a per-window `AxisHistogram<crate::ShikumiErrorKind>`
    /// (the outlier classification on a stream dominated by `Parse`
    /// errors). Before this lift, every such consumer re-derived the
    /// loop inline as
    /// `hist.iter().filter(|&(_,c)|c>0).min_by_key(|&(_,c)|c).map(|(v,_)|v)`
    /// — and the inline `min_by_key` form silently returns the *first*
    /// tied cell (per [`Iterator::min_by_key`]'s contract, which
    /// reverses [`Iterator::max_by_key`]'s "last on ties" behavior), so
    /// the open-coded argmin and the open-coded argmax in
    /// [`Self::dominant_cell`] disagreed on which tied cell to pick.
    /// The pair of lifts pins one consistent tie-breaking rule across
    /// both projections.
    ///
    /// **Zero cells are excluded from the search.** The argmin is taken
    /// over the histogram's *support* (the set of observed cells), not
    /// over the full axis. Zero-count cells are trivially the minimum
    /// over the full axis and would shadow the rarest *observed* kind;
    /// excluding them surfaces the rarest cell some observation
    /// actually fell on — the question the rendering, diagnostic, and
    /// dashboard sites ask. This matches [`Self::dominant_cell`]'s
    /// symmetry on the maximum side: both projections operate over the
    /// nonzero support, so the empty-histogram convention is identical
    /// (both return `None`) and the singleton case is identical (both
    /// return the observed cell).
    ///
    /// **Tie-breaking is deterministic by declaration order.** When
    /// multiple observed cells share the minimum count, the cell
    /// earliest in [`ClosedAxis::ALL`] wins — pointwise consistent
    /// with [`Self::dominant_cell`]'s tie-breaking rule and the order
    /// [`Self::iter`] yields. The same histogram observed under
    /// different observation orders therefore yields the same
    /// recessive cell: observation order does not leak through the
    /// projection.
    ///
    /// **Empty-histogram convention.** Returns `None` exactly when
    /// [`Self::is_empty`] is `true`. A histogram with even a single
    /// observation always has a recessive cell (the observed one). A
    /// histogram whose every cell observes the same nonzero count
    /// returns `Some(first cell)` — the unique cell in declaration
    /// order with the minimum positive count, identical to the
    /// dominant cell on a uniform histogram. Pinned by
    /// [`tests::axis_histogram_dominant_and_recessive_agree_on_uniform_axis_cover_for_every_implementor`].
    ///
    /// **Companion invariants** with [`Self::dominant_cell`] and
    /// [`Self::distinct_cells`]:
    /// - `recessive_cell().is_some() == dominant_cell().is_some()`:
    ///   both projections are defined on the same support
    ///   (`!is_empty()`).
    /// - `dominant_cell() == recessive_cell()` whenever
    ///   `distinct_cells() == 1` (a single observed cell is both the
    ///   maximum and the minimum) — the singleton-support law.
    /// - `count(recessive_cell().unwrap()) <= count(dominant_cell().unwrap())`
    ///   whenever the histogram is non-empty: the rarest cell's count
    ///   is bounded above by the dominant cell's count.
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_recessive_cell_empty_is_none_*`,
    /// `axis_histogram_recessive_cell_singleton_picks_observed_*`,
    /// `axis_histogram_recessive_cell_axis_cover_picks_first_*`).
    ///
    /// Peer to [`Self::dominant_cell`] (the *modal* cell on the maximum
    /// side) and [`Self::distinct_cells`] (the *count* of observed
    /// cells): the histogram surface now carries the natural triple of
    /// "*which* cell" / "*which other* cell" / "*how many* cells"
    /// projections over the observed support.
    #[must_use]
    pub fn recessive_cell(&self) -> Option<A> {
        let mut iter = self.iter().filter(|&(_, c)| c > 0);
        let first = iter.next()?;
        Some(
            iter.fold(
                first,
                |best, current| {
                    if current.1 < best.1 { current } else { best }
                },
            )
            .0,
        )
    }

    /// The maximum observation count across every cell of the closed
    /// axis — the **height of the histogram's peak**. Returns `0` exactly
    /// when [`Self::is_empty`] is `true`; otherwise returns the count
    /// carried by [`Self::dominant_cell`] (and pointwise equal to it).
    ///
    /// The "scalar peer" of [`Self::dominant_cell`] on the count side —
    /// the natural typed primitive for diagnostic dumps, dashboards, and
    /// attestation manifests asking *"how many observations did the
    /// dominant cell collect?"*: the dominant-format observation count in
    /// a chain's [`crate::ConfigSourceChain::file_format_histogram`]
    /// (the "47 of 53 layers were `.yaml`" headline number), the
    /// dominant-error count in a per-window
    /// `AxisHistogram<crate::ShikumiErrorKind>` (the "12 of 14 reload
    /// failures were Parse this window" alarm-threshold input), the
    /// peak-layer-kind count in a chain's
    /// [`crate::ConfigSourceChain::layer_kind_histogram`] (the operator
    /// table's "the chain's heaviest layer kind fired N times" cell).
    /// Before this lift, every such consumer re-derived the projection
    /// inline as `hist.dominant_cell().map_or(0, |c| hist.count(c))` —
    /// which walked the histogram *twice* (once to argmax, once to read
    /// the count back through the [`Self::count`] indexing). The lift
    /// names the scalar at one site with a single pass over the counts
    /// vector.
    ///
    /// **Empty-histogram convention** — returns `0` (not `Option<usize>`)
    /// matching the [`Self::total`] and [`Self::distinct_cells`] empty
    /// conventions; the scalar peer triple `(total, distinct_cells,
    /// peak_count)` is therefore uniformly `(0, 0, 0)` on the empty
    /// histogram. The dual-form `dominant_cell` carries `Option<A>`
    /// because the *cell* is undefined when no observation has landed;
    /// the *count* is well-defined as zero on the empty cells of the
    /// vector. The asymmetry is intentional: every scalar projection
    /// reads zero on empty; every cell projection reads `None`.
    ///
    /// **Closes the (cell, count) modal pair** with [`Self::dominant_cell`]:
    /// `(dominant_cell(), peak_count())` reads off the histogram's peak
    /// as a typed `(Option<A>, usize)` pair. When [`Self::dominant_cell`]
    /// is `Some(v)`, `self.count(v) == self.peak_count()` (the dominant
    /// cell's count equals the maximum). When [`Self::dominant_cell`] is
    /// `None`, `peak_count() == 0` and the pair witnesses the
    /// empty-histogram boundary uniformly.
    ///
    /// **Companion invariants** with [`Self::total`],
    /// [`Self::distinct_cells`], [`Self::dominant_cell`], and
    /// [`Self::recessive_cell`]:
    /// - `peak_count() == 0` ⇔ [`Self::is_empty`] is `true`
    ///   (peer to the empty-histogram boundary [`Self::distinct_cells`]
    ///   and [`Self::dominant_cell`] both carry).
    /// - `peak_count() <= total()` always: the peak is bounded above by
    ///   the multiset's size (every cell contributes at most every
    ///   observation, and the others contribute zero — equality holds
    ///   when [`Self::distinct_cells`] is `1`).
    /// - `peak_count() == total()` iff `distinct_cells() <= 1`: a single
    ///   observed cell carries every observation, so the peak equals
    ///   the total. Distinct = 0 (empty) reads 0 == 0; distinct = 1
    ///   reads N == N; distinct >= 2 reads peak < total strictly.
    /// - `peak_count() >= recessive_count` whenever the histogram is
    ///   non-empty, where `recessive_count =
    ///   count(recessive_cell().unwrap())`: the dominant count bounds
    ///   the rarest-observed count above (peer to the
    ///   `count(recessive_cell) <= count(dominant_cell)` invariant on
    ///   [`Self::recessive_cell`]).
    /// - `merge(self, other).peak_count() >=
    ///   self.peak_count().max(other.peak_count())`: the peak is
    ///   monotone under [`Self::merge`] — merging adds counts pointwise,
    ///   and adding non-negative deltas to the larger side's peak cell
    ///   cannot shrink it. The peer to the monotone-support law on
    ///   [`Self::distinct_cells`] and the monotone-coverage law on
    ///   [`Self::unobserved`].
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_peak_count_empty_is_zero_*`,
    /// `axis_histogram_peak_count_singleton_is_one_*`,
    /// `axis_histogram_peak_count_axis_cover_is_one_*`).
    ///
    /// Peer to [`Self::total`] (the *sum* over every cell) and
    /// [`Self::distinct_cells`] (the *support cardinality*): the scalar
    /// surface of the histogram now carries the natural triple of
    /// `(how many observations, how many kinds, how many on the peak)`
    /// projections — every operator-facing summary reads off one method
    /// call each.
    #[must_use]
    pub fn peak_count(&self) -> usize {
        self.counts.iter().copied().max().unwrap_or(0)
    }

    /// The minimum observation count across the histogram's *observed*
    /// support — the **height of the histogram's trough**. Returns `0`
    /// exactly when [`Self::is_empty`] is `true`; otherwise returns the
    /// count carried by [`Self::recessive_cell`] (and pointwise equal to
    /// it).
    ///
    /// The "scalar peer" of [`Self::recessive_cell`] on the count side —
    /// the structural dual of [`Self::peak_count`] on the *minority*
    /// side. The natural typed primitive for diagnostic dumps,
    /// dashboards, and attestation manifests asking *"how many
    /// observations did the rarest observed cell collect?"*: the
    /// rarest-format observation count in a chain's
    /// [`crate::ConfigSourceChain::file_format_histogram`] (the "the
    /// chain's least-used file format fired N times" cell), the
    /// rarest-error count in a per-window
    /// `AxisHistogram<crate::ShikumiErrorKind>` (the floor of the
    /// observed error-class distribution), the trough-layer-kind count
    /// in a chain's [`crate::ConfigSourceChain::layer_kind_histogram`]
    /// (the operator table's "the chain's lightest layer kind fired N
    /// times" cell). Before this lift, every such consumer re-derived
    /// the projection inline as
    /// `hist.recessive_cell().map_or(0, |c| hist.count(c))` — which
    /// walked the histogram *twice* (once to argmin over the support,
    /// once to read the count back through the [`Self::count`]
    /// indexing). The lift names the scalar at one site with a single
    /// pass over the counts vector.
    ///
    /// **Zero cells are excluded from the search.** The minimum is
    /// taken over the histogram's *support* (the set of observed cells),
    /// not over the full axis. Zero-count cells are trivially the
    /// minimum over the full axis and would shadow the rarest-observed
    /// count; excluding them surfaces the count of the rarest cell some
    /// observation actually fell on — the question the rendering,
    /// diagnostic, and dashboard sites ask. This matches
    /// [`Self::recessive_cell`]'s zero-cell-exclusion rule pointwise so
    /// the `(recessive_cell(), trough_count())` pair reads off the
    /// histogram's trough consistently with [`Self::peak_count`] /
    /// [`Self::dominant_cell`] reading the peak.
    ///
    /// **Empty-histogram convention** — returns `0` (not
    /// `Option<usize>`) matching the [`Self::total`],
    /// [`Self::distinct_cells`], and [`Self::peak_count`] empty
    /// conventions; the scalar peer quadruple `(total, distinct_cells,
    /// peak_count, trough_count)` is therefore uniformly `(0, 0, 0, 0)`
    /// on the empty histogram. The dual-form [`Self::recessive_cell`]
    /// carries `Option<A>` because the *cell* is undefined when no
    /// observation has landed; the *count* is well-defined as zero on
    /// the empty cells of the vector. The asymmetry is intentional and
    /// pointwise consistent with the `(peak_count, dominant_cell)` pair.
    ///
    /// **Closes the (cell, count) modal pair** with
    /// [`Self::recessive_cell`]:
    /// `(recessive_cell(), trough_count())` reads off the histogram's
    /// trough as a typed `(Option<A>, usize)` pair, pointwise dual to
    /// `(dominant_cell(), peak_count())` reading the peak. When
    /// [`Self::recessive_cell`] is `Some(v)`,
    /// `self.count(v) == self.trough_count()` (the recessive cell's
    /// count equals the minimum-over-support). When
    /// [`Self::recessive_cell`] is `None`, `trough_count() == 0` and
    /// the pair witnesses the empty-histogram boundary uniformly.
    ///
    /// **Companion invariants** with [`Self::total`],
    /// [`Self::distinct_cells`], [`Self::peak_count`],
    /// [`Self::dominant_cell`], and [`Self::recessive_cell`]:
    /// - `trough_count() == 0` ⇔ [`Self::is_empty`] is `true`
    ///   (peer to the empty-histogram boundary [`Self::peak_count`],
    ///   [`Self::distinct_cells`], and [`Self::dominant_cell`] all
    ///   carry).
    /// - `trough_count() <= peak_count()` always: the trough is bounded
    ///   above by the peak (the minimum over a non-empty support is
    ///   bounded above by the maximum over the same support). Equality
    ///   holds iff every observed cell carries the same count (the
    ///   *uniform-observed-count* shape — every singleton-support
    ///   histogram, every uniform axis-cover histogram, every
    ///   `k`-cell histogram observed `k` times each-once).
    /// - `trough_count() >= 1` whenever the histogram is non-empty:
    ///   every observed cell carries at least one observation by
    ///   construction, so the minimum over the support is at least
    ///   one. The peer to the `peak_count() >= 1` non-emptiness floor.
    /// - The merge behavior is *non-monotonic* (in deliberate contrast
    ///   to [`Self::peak_count`]'s strict monotonicity under
    ///   [`Self::merge`]): merging two histograms can either grow the
    ///   trough (when the supports coincide, every cell's count grows
    ///   and so does the minimum) or shrink it (when one side observes
    ///   a cell the other does not, the new cell enters the merged
    ///   support carrying that side's count and can pull the merged
    ///   trough below either side's). The empty-identity law still
    ///   holds: `merge(self, empty).trough_count() == self.trough_count()`.
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_trough_count_empty_is_zero_*`,
    /// `axis_histogram_trough_count_singleton_is_one_*`,
    /// `axis_histogram_trough_count_axis_cover_is_one_*`).
    ///
    /// Peer to [`Self::total`] (the *sum* over every cell),
    /// [`Self::distinct_cells`] (the *support cardinality*), and
    /// [`Self::peak_count`] (the *modal-count scalar* on the majority
    /// side): the scalar surface of the histogram now carries the
    /// natural quadruple of
    /// `(how many observations, how many kinds, how many on the peak,
    /// how many on the trough)` projections — every operator-facing
    /// summary reads off one method call each, and the *spread* of the
    /// observed distribution (`peak_count - trough_count`) reads off a
    /// single subtraction on the closed scalar surface.
    #[must_use]
    pub fn trough_count(&self) -> usize {
        self.counts
            .iter()
            .copied()
            .filter(|&c| c > 0)
            .min()
            .unwrap_or(0)
    }

    /// The **observed-distribution spread** — the difference between the
    /// maximum and minimum observation counts over the histogram's
    /// observed support. Equal to
    /// `self.peak_count() - self.trough_count()` by construction; named
    /// at the trait level so consumers reading off the
    /// observed-distribution skew route through one scalar projection
    /// rather than re-deriving the (peak, trough) subtraction at every
    /// diagnostic / dashboard / alarm site.
    ///
    /// The natural typed primitive for the *balanced-vs-skewed* question
    /// every operator-facing summary asks of an observation window:
    /// *"how unevenly distributed are the observations across the
    /// observed kinds?"*: the spread of an
    /// `AxisHistogram<crate::ShikumiErrorKind>` reload-window error
    /// distribution ("dominant Parse fired 12×, rarest Io fired 1×,
    /// spread = 11" — the natural input to an outlier-threshold
    /// classifier), the spread of a
    /// [`crate::ConfigSourceChain::file_format_histogram`] (the chain's
    /// "is one format dominating the chain or are they balanced?"
    /// summary line), the spread of a
    /// [`crate::ConfigDiff::kind_histogram`] (the diff's "is this
    /// rebuild adding/removing in roughly equal numbers or strongly
    /// skewed?" diagnostic). Before this lift, every consumer asking
    /// "what is the spread of this observation window?" re-derived the
    /// projection inline as
    /// `hist.peak_count() - hist.trough_count()` — two method calls
    /// plus a subtraction at every site, with the silent-underflow risk
    /// every consumer has to reason about independently
    /// (`peak_count >= trough_count` is a structural invariant of the
    /// histogram but not of the inline subtraction surface).
    ///
    /// **Underflow-safe by construction.** The subtraction
    /// `peak_count() - trough_count()` is guaranteed non-negative
    /// (`peak_count >= trough_count` holds structurally on every
    /// histogram — both equal 0 on the empty histogram, both are the
    /// same positive count on a uniform-observed-count histogram,
    /// otherwise `peak_count > trough_count`). The named scalar
    /// surfaces the bound; consumers do not need to re-prove
    /// monotonicity at the call site.
    ///
    /// **Empty-histogram convention** — returns `0`, matching the
    /// [`Self::total`], [`Self::distinct_cells`], [`Self::peak_count`],
    /// and [`Self::trough_count`] empty conventions. The scalar peer
    /// quintuple
    /// `(total, distinct_cells, peak_count, trough_count, spread)` is
    /// therefore uniformly `(0, 0, 0, 0, 0)` on the empty histogram.
    ///
    /// **Structural-skew predicate.** `spread() == 0` is the typed
    /// *uniformly-observed-count* predicate on the histogram surface:
    /// every observed cell carries the same count. The predicate holds
    /// on three distinct shapes — the empty histogram (vacuously: no
    /// observed cells); every singleton-support histogram (only one
    /// observed cell, trivially balanced); every histogram whose
    /// support is observed at a uniform count, including the
    /// k-cell-observed-k-times-each-once shape and every uniform
    /// axis-cover histogram. The predicate is pointwise equivalent to
    /// `dominant_cell() == recessive_cell()` on every non-empty
    /// histogram — `spread()` lifts the same predicate from the
    /// `(cell, cell)` pair on the modal-pair surface to the scalar
    /// surface, so a future "balanced-distribution" diagnostic reads
    /// off a single equality `hist.spread() == 0` instead of routing
    /// through both cell-form projections and an `Option<A>` equality.
    ///
    /// **Companion invariants** with [`Self::total`],
    /// [`Self::distinct_cells`], [`Self::peak_count`], and
    /// [`Self::trough_count`]:
    /// - `spread() == 0` ⇔ every observed cell carries the same count
    ///   (the *uniformly-observed-count* shape — including the empty
    ///   histogram, every singleton-support histogram, every uniform
    ///   axis-cover histogram).
    /// - `spread() <= peak_count()` always: the trough is non-negative,
    ///   so the subtraction is bounded above by the minuend. Equality
    ///   holds iff the trough is zero — i.e. on the empty histogram.
    /// - `spread() <= total()` always: composition of
    ///   `peak_count <= total` with `trough_count >= 0`.
    /// - The merge behavior is *non-monotonic*: merging two histograms
    ///   can either grow the spread (when one side carries a heavy
    ///   tail the other lacks, the merged peak grows faster than the
    ///   merged trough) or shrink it (when merging an empty-support
    ///   addition restores the trough to a value closer to the peak).
    ///   The empty-identity law holds: `merge(self, empty).spread() ==
    ///   self.spread()`.
    ///
    /// Trait-uniform: every [`ClosedAxis`] implementor (the twenty
    /// closed-enum axis primitives plus the five product cubes —
    /// twenty-five today, reached uniformly through
    /// `for_each_closed_axis_implementor!` in [`tests`]) inherits the
    /// projection at no per-axis cost. The three trait-uniform laws
    /// pinned in [`tests`] hold across the implementor set
    /// (`axis_histogram_spread_empty_is_zero_*`,
    /// `axis_histogram_spread_singleton_is_zero_*`,
    /// `axis_histogram_spread_axis_cover_is_zero_*`).
    ///
    /// Peer to [`Self::total`] (the *sum* over every cell),
    /// [`Self::distinct_cells`] (the *support cardinality*),
    /// [`Self::peak_count`] (the *modal* count scalar), and
    /// [`Self::trough_count`] (the *rarest-observed* count scalar): the
    /// scalar surface of the histogram now carries the natural
    /// quintuple of
    /// `(how many observations, how many kinds, how many on the peak,
    /// how many on the trough, how much spread)` projections — every
    /// operator-facing summary reads off one method call each, and the
    /// *balanced-distribution* predicate (`spread() == 0`) reads off a
    /// single equality on the closed scalar surface.
    #[must_use]
    pub fn spread(&self) -> usize {
        self.peak_count() - self.trough_count()
    }

    /// Pointwise sum with `other` — the monoid operation. Every cell
    /// becomes `self.count(v) + other.count(v)`. Commutative,
    /// associative, identity at [`Self::empty`]. The natural shape for
    /// merging histograms across thread boundaries / observation
    /// windows / sub-batches before rendering a fleet-wide summary.
    #[must_use]
    pub fn merge(mut self, other: &Self) -> Self {
        for (slot, &delta) in self.counts.iter_mut().zip(other.counts.iter()) {
            *slot += delta;
        }
        self
    }
}

impl<A: ClosedAxis> FromIterator<A> for AxisHistogram<A> {
    /// Build a histogram by recording every observation in `iter`. The
    /// canonical entry point — every consumer that wants a per-cell
    /// tally from a stream of axis values pipes the stream through
    /// [`Iterator::collect`] into [`AxisHistogram`]. Equivalent to
    /// [`axis_histogram`] applied to the same iterator.
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        let mut hist = Self::empty();
        for value in iter {
            hist.observe(value);
        }
        hist
    }
}

/// Lift an iterator of axis observations into a typed
/// [`AxisHistogram<A>`] — the dense per-cell tally over
/// [`ClosedAxis::ALL`].
///
/// Generic over the [`ClosedAxis`] trait bound so the helper is
/// inherited uniformly across every implementor: a CLI `config-diff`
/// summary tallying added/removed/context lines on
/// [`crate::DiffLineKind`], a structured-diagnostic legend bucketing
/// reload failures by [`crate::ShikumiErrorKind`], a dashboard
/// initializing a per-axis counter from a snapshot of observations on
/// [`crate::SecretBackendKind`], an attestation manifest recording the
/// per-axis observation-mix histogram on
/// [`crate::WatchEventClass`] — each previously re-derived the
/// (filter, count) loop inline at every observation site. The lift
/// names the (closed-axis × iterable observations → per-cell counts)
/// projection at one site.
///
/// Convenience wrapper over `iter.into_iter().collect::<AxisHistogram<A>>()`
/// — same shape, named for symmetry with [`axis_iter`] / [`axis_at`] /
/// [`axis_ordinal`] / [`axis_cardinality`] on the closed-axis
/// generic-helper surface.
#[must_use]
pub fn axis_histogram<A: ClosedAxis, I: IntoIterator<Item = A>>(items: I) -> AxisHistogram<A> {
    items.into_iter().collect()
}

/// Closed labeling discipline trait — adds the canonical operator-facing
/// string label on top of [`ClosedAxis`].
///
/// Every typescape primitive that carries a canonical operator-facing
/// name (the string an operator types on the CLI, reads in a log line,
/// keys a dashboard column by) implements this trait. The trait is a
/// strict refinement of [`ClosedAxis`]: implementors close both the
/// `Self::ALL` enumeration discipline and the `(label → value)` /
/// `(value → label)` discipline through one trait, with the round-trip
/// law structural rather than per-primitive convention.
///
/// Implementors today: [`PartitionFace`] (the variant-tag projection of
/// [`PartitionOrdinal`]), [`crate::ConfigTierKind`] (the variant-tag
/// projection of [`crate::ConfigTier`]), [`crate::Format`] (the
/// operator-facing config file format axis — yaml/toml/lisp/nix),
/// [`crate::FormatProvenance`] (which provider class loads the format
/// — figment-builtin/shikumi-built), [`crate::ConfigSourceKind`] (the
/// kind axis of the resolved figment layer — defaults/env/file),
/// [`crate::FigmentSourceKind`] (the kind axis of the underlying
/// [`figment::Source`] — file/code/custom),
/// [`crate::AttributionConfidence`] (the equality-vs-uniqueness
/// confidence class of the resolver attribution — exact/fallback),
/// [`crate::AttributionAxis`] (the `figment::Metadata` field that
/// drove the resolver attribution — metadata-source/metadata-name),
/// [`crate::ShikumiErrorKind`] (the data-free discriminant of
/// [`crate::ShikumiError`] — not-found/parse/watch/io/figment/extract),
/// [`crate::FieldPathLocalization`] (the tri-state
/// figment-field-path localization axis of a [`crate::ShikumiError`]
/// — localized/figment-unlocalized/not-applicable), and
/// [`crate::AttributionRule`] (the closed five-rule resolver dispatch
/// axis —
/// file-by-source/file-by-metadata-name/env-by-prefix/env-by-uniqueness/defaults-by-code-uniqueness).
/// The eleven primitives share the same shape —
/// `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]`,
/// [`ClosedAxis`] over `Self::ALL`, operator-facing lowercase or
/// kebab-case canonical name — and the trait closes the labeling
/// discipline across all eleven uniformly. Every axis of every product
/// cube on the typescape now labels through the trait: both axes of
/// the 18-cell [`crate::ErrorLocalizationCoordinates`] cube
/// (`ShikumiErrorKind` × `FieldPathLocalization`), every axis of the
/// 12-cell [`crate::AttributionCoordinates`] cube
/// (`AttributionAxis` × `ConfigSourceKind` × `AttributionConfidence`),
/// both axes of the 9-cell [`crate::AttributionSourceKindCoordinates`]
/// cube (`FigmentSourceKind` × `ConfigSourceKind`), and both axes of
/// the 8-cell [`crate::FormatCoordinates`] cube
/// (`Format` × `FormatProvenance`) — every cell of every cube is
/// nameable through the trait without re-deriving a string mapping at
/// any cube-renderer site. The canonical implementor list lives in the
/// `for_each_closed_axis_label_implementor!` callback macro
/// (`cube::tests`) so every trait-uniform invariant test reaches the
/// implementor set by macro expansion rather than by repeated inline
/// listing.
///
/// **Round-trip law** — for every `v: Self`,
/// `Self::from_canonical_str(v.as_str()) == Some(v)`. Pinned by the
/// trait-uniform [`tests::closed_axis_label_round_trips_for_every_implementor`]
/// test, which reaches every implementor through the
/// [`for_each_closed_axis_label_implementor`] macro.
///
/// **Case insensitivity** — for every `v: Self`,
/// `Self::from_canonical_str(v.as_str().to_ascii_uppercase()) == Some(v)`.
/// The default [`Self::from_canonical_str`] uses
/// [`str::eq_ignore_ascii_case`], so the law is structural in the
/// default impl; implementors that override [`from_canonical_str`]
/// (none today) re-state the law via the same trait-uniform test.
///
/// **Distinctness** — `a.as_str() != b.as_str()` for `a != b: Self`.
/// The labels are an injection from the axis into the canonical-name
/// space; a duplicated label would collapse two variants to one parse
/// result. Pinned by
/// [`tests::closed_axis_label_as_str_distinct_for_every_implementor`].
///
/// **Non-emptiness** — `!v.as_str().is_empty()` for every `v: Self`.
/// The empty string is reserved for "missing label" at the consumer
/// boundary (e.g. an unset env var, an unfilled struct field) and must
/// never collide with a canonical name. Pinned by
/// [`tests::closed_axis_label_as_str_nonempty_for_every_implementor`].
///
/// **Empty parse** — `Self::from_canonical_str("") == None` for every
/// implementor. Composes with non-emptiness: the empty string can never
/// be a canonical label, so the parse rejects it uniformly. Pinned by
/// [`tests::closed_axis_label_rejects_empty_string_for_every_implementor`].
///
/// Future implementors (lift sites): with the
/// [`crate::AttributionRule`] lift landing, every closed-axis
/// primitive the typescape recognizes today labels through the trait,
/// and every axis of every product cube
/// ([`crate::FormatCoordinates`], [`crate::AttributionCoordinates`],
/// [`crate::ErrorLocalizationCoordinates`],
/// [`crate::AttributionSourceKindCoordinates`]) labels through the
/// trait on every axis. A future closed-axis primitive (a new
/// resolver-side discriminant, a new error-side discriminant, a new
/// figment-side classification) picks up the round-trip law + every
/// trait-uniform invariant test by adding one
/// `impl ClosedAxisLabel for X { fn as_str(self) -> &'static str { … } }`
/// declaration plus one arm to [`for_each_closed_axis_label_implementor`].
/// The default [`Self::from_canonical_str`] suffices on every
/// canonical-name-only parse; primitives that accept aliases (e.g.
/// [`crate::Format`]'s [`std::str::FromStr`] impl which accepts
/// `"yml"`/`"lsp"`/`"el"`) keep their richer [`std::str::FromStr`] in
/// addition to the canonical-only trait parse.
pub trait ClosedAxisLabel: ClosedAxis {
    /// Canonical operator-facing lowercase name of the axis value.
    ///
    /// The single source of truth for the value's string label —
    /// renderers, log formatters, structured-diagnostic legends, CLI
    /// help text, and parse helpers all route through this one method.
    /// `&'static str` so the label is allocation-free at every call
    /// site; no heap allocations for the rendering path.
    ///
    /// Implementors typically return a lowercase ASCII string matching
    /// the operator-facing convention (the same form an operator would
    /// type into an env var or CLI flag); [`Self::from_canonical_str`]
    /// is case-insensitive over ASCII, so the rendering vs. parsing
    /// asymmetry stays on the parse side only.
    fn as_str(self) -> &'static str;

    /// Case-insensitive ASCII parse of the canonical name produced by
    /// [`Self::as_str`]. Returns [`None`] for any other input.
    ///
    /// The default impl is a linear scan of [`ClosedAxis::ALL`] matching
    /// pointwise via [`str::eq_ignore_ascii_case`]. The implementation
    /// is structural: adding a variant only extends [`Self::as_str`];
    /// the parse picks the new variant up automatically through
    /// [`ClosedAxis::ALL`]. Implementors override only when the parse
    /// surface diverges from the rendering surface (e.g. when the
    /// canonical name has aliases on the parse side — none of the
    /// trait's current implementors do).
    ///
    /// `from_canonical_str` returns [`Option`] rather than implementing
    /// [`std::str::FromStr`] (which would force a `Result<_, Err>` shape
    /// and an error-type ceremony for the no-error case where "not a
    /// canonical name" is the only failure mode the caller cares about).
    /// Primitives that need a [`std::str::FromStr`] impl with a typed
    /// error (e.g. [`crate::Format`]) keep their inherent impl in
    /// addition; the trait parse stays focused on the round-trip-with-
    /// [`as_str`][Self::as_str] case.
    ///
    /// **Round-trip law** —
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` for every
    /// `v: Self`. Pinned by
    /// [`tests::closed_axis_label_round_trips_for_every_implementor`].
    /// The default impl satisfies the law by construction over the
    /// [`ClosedAxis`] discipline.
    fn from_canonical_str(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

/// Canonical operator-facing label of a [`ClosedAxisLabel`] value —
/// [`ClosedAxisLabel::as_str`] reached as a free function generic over
/// the axis type.
///
/// Mirror of [`realizable_count`]/[`axis_cardinality`]: the trait method
/// reached through a named helper so generic code routes over the label
/// surface without naming the [`ClosedAxisLabel`] trait at the call site.
/// Where [`axis_label`] resolves a typed axis value to its canonical
/// name, [`axis_from_label`] is its partial inverse over the
/// canonical-name space; the pair closes the label bijection on the
/// recognized-name image the same way [`axis_ordinal`]/[`axis_at`] close
/// the ordinal bijection on the natural-number prefix.
///
/// **Agreement** — `axis_label(v) == v.as_str()` for every `v: L`,
/// pinned by the trait-uniform
/// [`tests::axis_label_free_fn_matches_trait_as_str_for_every_implementor`]
/// across every [`ClosedAxisLabel`] implementor. The free function adds
/// no behavior; it only relocates the call to a generic, trait-name-free
/// site.
///
/// **Consumers** — structured-diagnostic legends, log formatters, and
/// cube-cover dashboards that already route over a `ClosedAxis` /
/// `ProductCube` type parameter via [`axis_iter`] / [`realizable_iter`]
/// name the same cell's canonical label through [`axis_label`] without
/// adding a `where L: ClosedAxisLabel` import of the trait method into
/// the call site — the label join stays at the free-function layer with
/// the rest of the typescape vocabulary.
#[must_use]
pub fn axis_label<L: ClosedAxisLabel>(value: L) -> &'static str {
    value.as_str()
}

/// Parse a [`ClosedAxisLabel`] value from its canonical operator-facing
/// label — [`ClosedAxisLabel::from_canonical_str`] reached as a free
/// function generic over the axis type.
///
/// Partial inverse of [`axis_label`] over the canonical-name space:
/// returns [`Some`] exactly on a case-insensitive match against some
/// `v.as_str()`, [`None`] on every other input (including the empty
/// string — no canonical label is empty). Stands to [`axis_label`] as
/// [`axis_at`] stands to [`axis_ordinal`]: the safe, partial direction of
/// the bijection surfaced as a free function so deserializers of
/// attestation manifests (THEORY.md §III.1.8 module manifests, §V.3
/// three-pillar attestation) that carry typescape cells by canonical
/// name recover the typed value without naming the [`ClosedAxisLabel`]
/// trait at the loader site.
///
/// **Agreement** — `axis_from_label::<L>(s) == L::from_canonical_str(s)`
/// for every `s`, pinned by the trait-uniform
/// [`tests::axis_from_label_free_fn_matches_trait_for_every_implementor`].
///
/// **Round-trip law** — `axis_from_label::<L>(axis_label(v)) == Some(v)`
/// for every `v: L` — the free-function form of the
/// [`ClosedAxisLabel`] round-trip law, pinned by
/// [`tests::axis_label_free_fn_round_trips_for_every_implementor`].
#[must_use]
pub fn axis_from_label<L: ClosedAxisLabel>(s: &str) -> Option<L> {
    L::from_canonical_str(s)
}

/// Closed discipline trait every typescape product cube satisfies — a
/// refinement of [`ClosedAxis`] that additionally pins the
/// realizability predicate over the recognized-image cells.
///
/// A product cube is a `Copy + Eq + Hash + #[non_exhaustive]` struct
/// whose fields are typescape axis primitives (each itself a closed
/// `#[non_exhaustive]` enum with its own `::ALL` constant via
/// [`ClosedAxis`]), enumerating every cell of the structural Cartesian
/// product over the axis constituent enums.
///
/// Implementors:
///
/// - [`crate::FormatCoordinates`] —
///   `Format × FormatProvenance` (4 × 2 = 8 cells, 4 realizable).
/// - [`crate::AttributionCoordinates`] —
///   `AttributionAxis × ConfigSourceKind × AttributionConfidence`
///   (2 × 3 × 2 = 12 cells, 5 realizable).
/// - [`crate::ErrorLocalizationCoordinates`] —
///   `ShikumiErrorKind × FieldPathLocalization` (6 × 3 = 18 cells,
///   8 realizable).
/// - [`crate::AttributionSourceKindCoordinates`] —
///   `FigmentSourceKind × ConfigSourceKind` (3 × 3 = 9 cells,
///   2 realizable).
///
/// The trait is intentionally not object-safe (`Self`-by-value method)
/// — consumers route generically over the cube type parameter, not
/// over `dyn ProductCube` trait objects.
pub trait ProductCube: ClosedAxis {
    /// Realizability predicate: `true` exactly on the cells some
    /// recognized typescape value occupies, `false` on the cross-axis
    /// consistency-violation complement.
    ///
    /// Mirror of the inherent `Self::is_realizable` method every
    /// implementor already exposes. The trait re-export lets generic
    /// helpers (`realizable_iter`, `unrealizable_iter`,
    /// `realizable_count`, `unrealizable_count`) reach the predicate
    /// without naming the concrete cube type — the per-cube
    /// `inherent_is_realizable_matches_trait_is_realizable` tests pin
    /// the two methods to the same image pointwise.
    fn is_realizable(self) -> bool;
}

/// Iterate the realizable cells of a [`ProductCube`] —
/// `C::ALL.iter().copied().filter(|c| c.is_realizable())` collapsed to
/// one named helper.
///
/// Consolidates the per-cube `ALL.iter().copied().filter(|c|
/// c.is_realizable())` pattern that appeared at the
/// `*_is_realizable_image_equals_*` test site on each cube. Generic in
/// the cube type so a future fifth cube inherits the helper at the
/// `impl ProductCube` declaration.
pub fn realizable_iter<C: ProductCube>() -> impl Iterator<Item = C> {
    C::ALL.iter().copied().filter(|c| c.is_realizable())
}

/// Iterate the unrealizable cells of a [`ProductCube`] —
/// `C::ALL.iter().copied().filter(|c| !c.is_realizable())` collapsed
/// to one named helper.
///
/// Consolidates the per-cube `ALL.iter().copied().filter(|c|
/// !c.is_realizable())` pattern that appeared at the
/// `*_unrealizable_cells_have_no_inverse` test site on each cube.
/// Generic in the cube type so a future fifth cube inherits the helper
/// at the `impl ProductCube` declaration.
pub fn unrealizable_iter<C: ProductCube>() -> impl Iterator<Item = C> {
    C::ALL.iter().copied().filter(|c| !c.is_realizable())
}

/// Count the realizable cells of a [`ProductCube`].
///
/// Today's image cardinalities — 4 (`FormatCoordinates`), 5
/// (`AttributionCoordinates`), 8 (`ErrorLocalizationCoordinates`), 2
/// (`AttributionSourceKindCoordinates`) — reachable as one method call
/// without re-deriving the count from the partial inverse or the
/// inherent `is_realizable` filter inline. Future variant additions on
/// any constituent axis enum extend the count in lockstep with the
/// realizable image.
#[must_use]
pub fn realizable_count<C: ProductCube>() -> usize {
    realizable_iter::<C>().count()
}

/// Count the unrealizable cells of a [`ProductCube`] —
/// `C::ALL.len() - realizable_count::<C>()` collapsed to one named
/// helper.
///
/// Today's complement cardinalities — 4 (`FormatCoordinates`), 7
/// (`AttributionCoordinates`), 10 (`ErrorLocalizationCoordinates`), 7
/// (`AttributionSourceKindCoordinates`) — reachable as one method call
/// without re-deriving the count from the cube-cardinality-minus-image
/// formula inline.
#[must_use]
pub fn unrealizable_count<C: ProductCube>() -> usize {
    unrealizable_iter::<C>().count()
}

/// Dense ordinal of a [`ProductCube`] cell over the realizable surface
/// — the position of `cell` in [`realizable_iter::<C>()`], or [`None`]
/// on the cross-axis consistency-violation complement.
///
/// Cube-level dense embedding analog of [`axis_ordinal`]: where
/// [`axis_ordinal`] is the total inverse `value → ordinal` over the
/// closed axis with image `0..axis_cardinality::<A>()`, [`realizable_ordinal`]
/// is the partial inverse `cell → Option<ordinal>` over the cube with
/// image `0..realizable_count::<C>()` on realizable cells and [`None`]
/// on the unrealizable complement. The realizable surface is the
/// recognized-image half of the cube — the cells some typescape value
/// occupies — and the dense ordinal indexes that half in
/// declaration order over the underlying [`ClosedAxis::ALL`] slice,
/// skipping the interleaved unrealizable cells.
///
/// Concretely, [`crate::FormatCoordinates::ALL`] lays its 8 cells in
/// lex order over (`format × provenance`); the 4 realizable cells sit
/// at full-cube indices 0, 2, 5, 7 (the ones where
/// `provenance == format.provenance()`). [`axis_ordinal`] returns 0,
/// 2, 5, 7 on those cells (the position in `FormatCoordinates::ALL`);
/// [`realizable_ordinal`] returns 0, 1, 2, 3 (the dense position in
/// `realizable_iter::<FormatCoordinates>()`). The two ordinals differ
/// whenever the realizable cells are interleaved with unrealizable
/// ones in `C::ALL` — i.e. on every cube whose `is_realizable`
/// surface is not a prefix of `C::ALL`.
///
/// **Partiality on the value side** —
/// `realizable_ordinal::<C>(cell).is_some() == ProductCube::is_realizable(cell)`,
/// pinned by [`tests::realizable_ordinal_some_iff_is_realizable`].
/// The dense ordinal is defined exactly on the realizable surface;
/// unrealizable cells return [`None`] uniformly.
///
/// **Image equals the realizable prefix** — the ordinal image over
/// the realizable surface equals `0..realizable_count::<C>()` as a
/// set, pinned by
/// [`tests::realizable_ordinal_image_equals_realizable_prefix`]. The
/// embedding is a dense injection onto the natural-number prefix,
/// with the prefix length equal to the realizable-cell count.
///
/// **Round-trip with [`realizable_at`]** —
/// `realizable_at::<C>(realizable_ordinal::<C>(cell).unwrap()) == Some(cell)`
/// for every realizable cell, pinned by
/// [`tests::realizable_round_trips_cell_side`]. The pair
/// ([`realizable_ordinal`], [`realizable_at`]) closes the partial
/// bijection between the realizable surface and the natural-number
/// prefix `0..realizable_count::<C>()`.
///
/// **Consumers** — future cube-cover dashboards that order rows by
/// the dense ordinal over the realizable surface (instead of by the
/// full-cube ordinal that interleaves the unrealizable complement)
/// reach the position through one helper; attestation manifests
/// (THEORY.md §III.1.8 module manifests, §V.3 three-pillar
/// attestation) that hash the realizable surface in stable dense
/// declaration order index through the dense ordinal without an
/// inline `realizable_iter::<C>().position(|c| c == cell)` per
/// hasher; dense arrays sized by
/// [`realizable_count::<C>()`][realizable_count] (one slot per
/// realizable cell, rather than `axis_cardinality::<C>()` slots that
/// waste one per unrealizable cell) index through the dense ordinal.
#[must_use]
pub fn realizable_ordinal<C: ProductCube>(cell: C) -> Option<usize> {
    realizable_iter::<C>().position(|c| c == cell)
}

/// Dense ordinal lookup over the realizable surface of a
/// [`ProductCube`] — the realizable cell at position `ordinal` in
/// [`realizable_iter::<C>()`], or [`None`] if the index is
/// out-of-range.
///
/// Safe forward dual of [`realizable_ordinal`]: where
/// [`realizable_ordinal`] is the partial inverse `cell → Option<ordinal>`
/// over the cube (`Some` exactly on the realizable surface,
/// [`None`] on the unrealizable complement), [`realizable_at`] is the
/// partial forward `ordinal → Option<cell>` over `usize`, returning
/// [`Some`] exactly on the prefix `0..realizable_count::<C>()` and
/// [`None`] outside it. The pair ([`realizable_ordinal`],
/// [`realizable_at`]) closes the bijection between the realizable
/// surface and the natural-number prefix in both directions, the
/// cube-level analog of the ([`axis_ordinal`], [`axis_at`]) pair
/// over the closed axis.
///
/// **Bijection laws** — pinned by trait-uniform tests reaching every
/// implementor pointwise:
///
/// 1. **Round-trip from the cell side** —
///    `realizable_at::<C>(realizable_ordinal::<C>(cell).unwrap()) == Some(cell)`
///    for every realizable `cell: C`. The ordinal-then-lookup
///    composition is the identity on the realizable surface.
/// 2. **Round-trip from the ordinal side** —
///    `realizable_at::<C>(i).and_then(realizable_ordinal::<C>) == Some(i)`
///    for every `i < realizable_count::<C>()`. The lookup-then-ordinal
///    composition is the identity on the in-range prefix.
/// 3. **Partiality on out-of-range** —
///    `realizable_at::<C>(i).is_none()` for every
///    `i >= realizable_count::<C>()`. The forward map is total over
///    the prefix and undefined outside it; the [`Option`] return
///    surfaces the partiality at the type level instead of by
///    convention.
/// 4. **Image is realizable** —
///    `realizable_at::<C>(i).map(ProductCube::is_realizable) == Some(true)`
///    for every in-range `i`. The forward map lands on the
///    realizable surface by construction.
///
/// **Consumers** — deserializing attestation manifests
/// (THEORY.md §III.1.8 module manifests, §V.3 three-pillar
/// attestation) that carry realizable cells by stable dense
/// declaration ordinal recover the typed cell via [`realizable_at`]
/// without a `realizable_iter::<C>().nth(i)` inline at every loader
/// site. Dense arrays sized by [`realizable_count::<C>()`][realizable_count]
/// (one slot per realizable cell, indexed by dense ordinal) look up
/// the typed cell at a given position safely. Future cube-cover
/// dashboards that render rows keyed by dense ordinal index recover
/// the row's typescape cell through one named helper rather than
/// re-deriving the iterator-`nth` per renderer.
#[must_use]
pub fn realizable_at<C: ProductCube>(ordinal: usize) -> Option<C> {
    realizable_iter::<C>().nth(ordinal)
}

/// Dense ordinal of a [`ProductCube`] cell over the unrealizable
/// complement — the position of `cell` in [`unrealizable_iter::<C>()`],
/// or [`None`] on the recognized-image realizable surface.
///
/// Symmetric dual of [`realizable_ordinal`]: where
/// [`realizable_ordinal`] is the partial inverse
/// `cell → Option<ordinal>` over the cube with image
/// `0..realizable_count::<C>()` on realizable cells and [`None`] on the
/// unrealizable complement, [`unrealizable_ordinal`] is the same
/// partial inverse over the opposite half of the cube — `Some(ordinal)`
/// with image `0..unrealizable_count::<C>()` on the cross-axis
/// consistency-violation cells and [`None`] on the realizable surface.
/// The unrealizable surface is the complement of the recognized image —
/// the cells no typescape value occupies — and the dense ordinal indexes
/// that half in declaration order over the underlying [`ClosedAxis::ALL`]
/// slice, skipping the interleaved realizable cells.
///
/// Concretely, [`crate::FormatCoordinates::ALL`] lays its 8 cells in
/// lex order over (`format × provenance`); the 4 unrealizable cells sit
/// at full-cube indices 1, 3, 4, 6 (the ones where
/// `provenance != format.provenance()`). [`axis_ordinal`] returns 1, 3,
/// 4, 6 on those cells (the position in `FormatCoordinates::ALL`);
/// [`unrealizable_ordinal`] returns 0, 1, 2, 3 (the dense position in
/// `unrealizable_iter::<FormatCoordinates>()`).
///
/// **Partiality on the value side** —
/// `unrealizable_ordinal::<C>(cell).is_some() == !ProductCube::is_realizable(cell)`,
/// pinned by [`tests::unrealizable_ordinal_some_iff_not_is_realizable`].
/// The dense ordinal is defined exactly on the unrealizable complement;
/// realizable cells return [`None`] uniformly. Together with
/// [`realizable_ordinal`], the two ordinals partition the cube cleanly:
/// every cell has exactly one defined ordinal (either dense-realizable
/// or dense-unrealizable, never both), pinned by
/// [`tests::realizable_and_unrealizable_ordinals_partition_cube`].
///
/// **Image equals the unrealizable prefix** — the ordinal image over
/// the unrealizable complement equals `0..unrealizable_count::<C>()`
/// as a set, pinned by
/// [`tests::unrealizable_ordinal_image_equals_unrealizable_prefix`].
/// The embedding is a dense injection onto the natural-number prefix.
///
/// **Round-trip with [`unrealizable_at`]** —
/// `unrealizable_at::<C>(unrealizable_ordinal::<C>(cell).unwrap()) == Some(cell)`
/// for every unrealizable cell, pinned by
/// [`tests::unrealizable_round_trips_cell_side`]. The pair
/// ([`unrealizable_ordinal`], [`unrealizable_at`]) closes the partial
/// bijection between the unrealizable complement and the natural-number
/// prefix `0..unrealizable_count::<C>()`, mirroring the realizable-half
/// bijection on the cube's opposite face.
///
/// **Consumers** — error-path messaging that reports cross-axis
/// consistency violations by stable dense violation-ordinal (e.g.
/// "consistency violation #N of M for cube C") indexes through the
/// ordinal without an inline
/// `unrealizable_iter::<C>().position(|c| c == cell)` per call site;
/// dense observability counters sized by
/// [`unrealizable_count::<C>()`][unrealizable_count] (one slot per
/// consistency-violation cell, rather than [`axis_cardinality::<C>()`][axis_cardinality]
/// slots that waste one per realizable cell) index through the dense
/// ordinal; future cube-cover dashboards that render the complement
/// half symmetrically with the realizable half reach the position
/// through one helper rather than re-deriving the iterator-`position`
/// per renderer.
#[must_use]
pub fn unrealizable_ordinal<C: ProductCube>(cell: C) -> Option<usize> {
    unrealizable_iter::<C>().position(|c| c == cell)
}

/// Dense ordinal lookup over the unrealizable complement of a
/// [`ProductCube`] — the unrealizable cell at position `ordinal` in
/// [`unrealizable_iter::<C>()`], or [`None`] if the index is
/// out-of-range.
///
/// Safe forward dual of [`unrealizable_ordinal`] and symmetric dual of
/// [`realizable_at`]: where [`unrealizable_ordinal`] is the partial
/// inverse `cell → Option<ordinal>` over the cube (`Some` exactly on
/// the unrealizable complement, [`None`] on the realizable surface),
/// [`unrealizable_at`] is the partial forward
/// `ordinal → Option<cell>` over `usize`, returning [`Some`] exactly
/// on the prefix `0..unrealizable_count::<C>()` and [`None`] outside
/// it. The pair ([`unrealizable_ordinal`], [`unrealizable_at`]) closes
/// the bijection between the unrealizable complement and the
/// natural-number prefix in both directions, mirroring the
/// ([`realizable_ordinal`], [`realizable_at`]) pair on the cube's
/// opposite face. Together the two pairs close the cube's surface
/// algebra symmetrically: every full-cube cell has exactly one defined
/// dense ordinal (realizable or unrealizable, never both), and every
/// in-range dense ordinal on either side lands on a cell of the
/// matching realizability.
///
/// **Bijection laws** — pinned by trait-uniform tests reaching every
/// implementor pointwise:
///
/// 1. **Round-trip from the cell side** —
///    `unrealizable_at::<C>(unrealizable_ordinal::<C>(cell).unwrap()) == Some(cell)`
///    for every unrealizable `cell: C`. The ordinal-then-lookup
///    composition is the identity on the unrealizable complement.
/// 2. **Round-trip from the ordinal side** —
///    `unrealizable_at::<C>(i).and_then(unrealizable_ordinal::<C>) == Some(i)`
///    for every `i < unrealizable_count::<C>()`. The
///    lookup-then-ordinal composition is the identity on the in-range
///    prefix.
/// 3. **Partiality on out-of-range** —
///    `unrealizable_at::<C>(i).is_none()` for every
///    `i >= unrealizable_count::<C>()`. The forward map is total over
///    the prefix and undefined outside it; the [`Option`] return
///    surfaces the partiality at the type level instead of by
///    convention.
/// 4. **Image is unrealizable** —
///    `unrealizable_at::<C>(i).map(ProductCube::is_realizable) == Some(false)`
///    for every in-range `i`. The forward map lands on the
///    unrealizable complement by construction — the dual of the
///    realizable-image invariant on [`realizable_at`].
///
/// **Consumers** — error-path messaging that decodes a captured
/// dense violation-ordinal back into the typed
/// `(axis, layer_kind, confidence)` (or analogous) cell — e.g. a
/// reload-failure observability slot stamped with the dense ordinal
/// of the consistency violation hit — recovers the typed cell via
/// [`unrealizable_at`] without an
/// `unrealizable_iter::<C>().nth(i)` inline at every decoder site.
/// Dense observability arrays sized by
/// [`unrealizable_count::<C>()`][unrealizable_count] (one slot per
/// violation cell, indexed by dense ordinal) look up the typed cell at
/// a given position safely.
#[must_use]
pub fn unrealizable_at<C: ProductCube>(ordinal: usize) -> Option<C> {
    unrealizable_iter::<C>().nth(ordinal)
}

/// Typed witness of which half of a [`ProductCube`] a cell occupies —
/// the recognized-image realizable surface or the cross-axis
/// consistency-violation unrealizable complement. The variant tag of
/// [`PartitionOrdinal`] lifted into its own closed-axis typescape
/// primitive.
///
/// Two variants, in declaration order:
///
/// - [`PartitionFace::Realizable`] — the cube's recognized-image half;
///   `ProductCube::is_realizable(cell) == true`.
/// - [`PartitionFace::Unrealizable`] — the cube's cross-axis
///   consistency-violation complement;
///   `ProductCube::is_realizable(cell) == false`.
///
/// [`PartitionOrdinal`] carries a [`PartitionFace`] tag plus a dense
/// inner ordinal on that face; [`PartitionOrdinal::face`] projects the
/// tag without unpacking the inner ordinal. A consumer that only needs
/// "which half does this cell sit on?" — a face-keyed observability
/// counter, a manifest field discriminating recognized cells from
/// consistency-violation cells without addressing the specific cell —
/// carries a [`PartitionFace`] (one byte, [`Copy`]) rather than the
/// full [`PartitionOrdinal`] (the variant tag plus the dense
/// inner-ordinal `usize`) at every slot. The tag is in lockstep with
/// the cube's [`ProductCube::is_realizable`] predicate pointwise —
/// pinned by [`tests::partition_ordinal_face_agrees_with_is_realizable`]
/// over every cell of every cube via [`for_each_product_cube`].
///
/// [`PartitionFace`] is itself a [`ClosedAxis`] primitive (the tenth on
/// the typescape) — exposes `Self::ALL = &[Realizable, Unrealizable]`
/// and inherits the [`axis_iter`], [`axis_cardinality`], [`axis_ordinal`],
/// [`axis_at`] generic helpers at the trait-impl declaration. A
/// face-keyed dashboard row iterates the two faces uniformly through
/// [`axis_iter::<PartitionFace>()`][axis_iter] rather than re-deriving
/// `[Realizable, Unrealizable]` inline at every renderer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionFace {
    /// The cube's recognized-image realizable surface — cells some
    /// typescape value occupies. Matches
    /// [`ProductCube::is_realizable`] returning `true`.
    Realizable,
    /// The cube's cross-axis consistency-violation complement — cells
    /// no typescape value occupies. Matches
    /// [`ProductCube::is_realizable`] returning `false`.
    Unrealizable,
}

impl PartitionFace {
    /// Every [`PartitionFace`] value, in declaration order.
    ///
    /// Mirror of the [`ClosedAxis::ALL`] trait constant; consumers
    /// reach the same slice through either path. Length 2 — pinned by
    /// [`tests::partition_face_all_has_two_entries`] and by the
    /// [`for_each_closed_axis_primitive`] macro cardinality checksum.
    pub const ALL: &'static [Self] = &[Self::Realizable, Self::Unrealizable];

    /// `true` exactly on [`PartitionFace::Realizable`].
    ///
    /// The face-level dual of [`ProductCube::is_realizable`]: where
    /// the cube method classifies a cell on a specific cube, this
    /// method classifies the face tag itself, regardless of which cube
    /// the face was produced from. Pinned in lockstep with the cube
    /// predicate by
    /// [`tests::partition_ordinal_face_agrees_with_is_realizable`].
    #[must_use]
    pub const fn is_realizable(self) -> bool {
        matches!(self, Self::Realizable)
    }

    /// Canonical operator-facing lowercase name of the face —
    /// `"realizable"` or `"unrealizable"`.
    ///
    /// The single source of truth for the face-label strings on the
    /// [`PartitionFace`] axis. Inherent mirror of the [`ClosedAxisLabel`]
    /// trait method; the trait impl delegates here so both routes (the
    /// inherent `face.as_str()` and the trait-generic
    /// `<PartitionFace as ClosedAxisLabel>::as_str(face)`) return the
    /// same `&'static str` pointwise — pinned by
    /// [`tests::closed_axis_label_round_trips_for_every_implementor`]
    /// over the [`ClosedAxisLabel::from_canonical_str`] round-trip law.
    ///
    /// Used by face-keyed dashboard headers, structured-log fields
    /// recording which half of a [`ProductCube`] a captured cell sits
    /// on, and operator-facing CLI emissions of
    /// `partition_face_iter` rendering output without inlining the two
    /// strings `"realizable"`/`"unrealizable"` at each renderer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Realizable => "realizable",
            Self::Unrealizable => "unrealizable",
        }
    }
}

impl ClosedAxis for PartitionFace {
    const ALL: &'static [Self] = Self::ALL;
}

impl ClosedAxisLabel for PartitionFace {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

/// Typed witness of which half of a [`ProductCube`] a cell occupies,
/// carrying the dense ordinal on that half.
///
/// Every cell of every [`ProductCube`] falls into exactly one variant —
/// `Realizable(i)` with `i < realizable_count::<C>()` on the recognized
/// surface, or `Unrealizable(i)` with `i < unrealizable_count::<C>()`
/// on the cross-axis consistency-violation complement. The two halves
/// are XOR-complementary (pinned by
/// [`tests::realizable_and_unrealizable_ordinals_partition_cube`]), so
/// the enum is a typed encoding of that partition: one value per cell,
/// no ambiguity about which face the dense ordinal addresses.
///
/// This is the cube-level disjoint-union counterpart of [`axis_ordinal`]
/// — where [`axis_ordinal`] returns one dense `usize` over the full
/// cube `ALL` slice (interleaving realizable and unrealizable cells),
/// `PartitionOrdinal` returns a typed variant tagged with which face
/// the cell sits on, plus the dense ordinal restricted to that face
/// only. The encoding wastes no slot on the opposite half: a future
/// observability counter sized by [`realizable_count::<C>()`][realizable_count]
/// or [`unrealizable_count::<C>()`][unrealizable_count] picks the
/// correct dimension via the variant tag at runtime, without separate
/// dense-half encoders at every call site.
///
/// Built and decoded uniformly across every [`ProductCube`] implementor
/// through [`partition_ordinal`] and [`at_partition_ordinal`]; a fifth
/// product cube landing on the typescape inherits both helpers at the
/// `impl ProductCube` declaration without re-deriving the
/// `if is_realizable(cell) { Realizable(...) } else { Unrealizable(...) }`
/// branch at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionOrdinal {
    /// Cell sits on the recognized-image realizable surface; carries
    /// the dense ordinal in the prefix `0..realizable_count::<C>()`.
    Realizable(usize),
    /// Cell sits on the cross-axis consistency-violation unrealizable
    /// complement; carries the dense ordinal in the prefix
    /// `0..unrealizable_count::<C>()`.
    Unrealizable(usize),
}

impl PartitionOrdinal {
    /// Project the variant tag of a [`PartitionOrdinal`] into the
    /// typed [`PartitionFace`] primitive — `Realizable(_) → Realizable`,
    /// `Unrealizable(_) → Unrealizable`.
    ///
    /// One named projection of the two-arm `match` that was previously
    /// inlined at every consumer that needed only the face tag without
    /// the dense inner ordinal. Total over [`PartitionOrdinal`]: every
    /// value lands on exactly one [`PartitionFace`] (no [`Option`]
    /// wrapper). Pinned in lockstep with
    /// [`ProductCube::is_realizable`] over every cell of every cube by
    /// [`tests::partition_ordinal_face_agrees_with_is_realizable`].
    ///
    /// **Consumers** — a face-keyed observability counter
    /// (`HashMap<PartitionFace, usize>`) records the face of a captured
    /// cube cell through one call; a manifest field that distinguishes
    /// the realizable image from the consistency-violation complement
    /// at the face level (without addressing the specific cell)
    /// carries one [`PartitionFace`] byte rather than the full
    /// [`PartitionOrdinal`] (variant tag + dense inner ordinal).
    #[must_use]
    pub const fn face(self) -> PartitionFace {
        match self {
            Self::Realizable(_) => PartitionFace::Realizable,
            Self::Unrealizable(_) => PartitionFace::Unrealizable,
        }
    }

    /// Project the inner dense ordinal of a [`PartitionOrdinal`] —
    /// `Realizable(i) → i`, `Unrealizable(i) → i`.
    ///
    /// One named projection of the two-arm `match` that was previously
    /// inlined at every consumer that needed only the dense inner
    /// ordinal without the face tag. The returned `usize` lies in
    /// `0..realizable_count::<C>()` on a [`PartitionFace::Realizable`]
    /// face and `0..unrealizable_count::<C>()` on a
    /// [`PartitionFace::Unrealizable`] face — the face is implicit in
    /// the variant the projection forgets. Consumers that carry the
    /// face tag separately (e.g. as a [`PartitionFace`]-keyed
    /// dashboard column) reach the inner ordinal through this
    /// projection without re-pattern-matching.
    #[must_use]
    pub const fn face_ordinal(self) -> usize {
        match self {
            Self::Realizable(i) | Self::Unrealizable(i) => i,
        }
    }
}

/// Typed partition ordinal of a [`ProductCube`] cell — fuses
/// ([`realizable_ordinal`], [`unrealizable_ordinal`]) into one total
/// helper returning a [`PartitionOrdinal`] variant tagged with which
/// face of the cube the cell sits on.
///
/// Total over `C::ALL`: every cell of every product cube has a defined
/// partition ordinal (no [`Option`] wrapper at the return type), because
/// the XOR-complementary partition discipline pins that exactly one of
/// [`realizable_ordinal`] / [`unrealizable_ordinal`] returns [`Some`]
/// on every cell. The variant tag distinguishes the two faces; the
/// inner `usize` is the dense ordinal restricted to that face.
///
/// **Variant agreement** — pinned by
/// [`tests::partition_ordinal_variant_agrees_with_is_realizable`]:
/// `partition_ordinal::<C>(cell)` returns
/// [`PartitionOrdinal::Realizable`] exactly on realizable cells and
/// [`PartitionOrdinal::Unrealizable`] exactly on unrealizable cells.
///
/// **Inner ordinal agreement** — pinned by
/// [`tests::partition_ordinal_inner_matches_dense_ordinal`]: the
/// inner `usize` on each variant equals the corresponding dense ordinal
/// from [`realizable_ordinal`] or [`unrealizable_ordinal`] pointwise.
///
/// **Round-trip with [`at_partition_ordinal`]** — pinned by
/// [`tests::partition_ordinal_round_trips_cell_side`]:
/// `at_partition_ordinal::<C>(partition_ordinal::<C>(cell)) == Some(cell)`
/// for every cell of every cube — the cube-level dual of the
/// ([`axis_ordinal`], [`axis_at`]) round-trip, but on the typed
/// disjoint-union encoding rather than the interleaved full-cube
/// ordinal.
///
/// **Consumers** — a future single-slot observability counter or
/// error-path field carrying "the cube cell address" stores one
/// [`PartitionOrdinal`] value instead of two separate
/// `Option<usize>` fields (one per face). Decoders take the typed
/// enum and produce the cell through one named helper. Manifest
/// serializers (THEORY.md §III.1.8 module manifests, §V.3
/// three-pillar attestation) that distinguish the realizable image
/// from the consistency-violation complement at the address level
/// carry the variant tag and the dense ordinal in lockstep without
/// re-deriving the predicate.
///
/// # Panics
///
/// Panics — via `.expect(...)` on the inner dense-ordinal lookup —
/// only if a [`ProductCube`] implementor violates the discipline by
/// returning `is_realizable(cell) == true` for a cell on which
/// [`realizable_ordinal`] returns [`None`], or dually
/// `is_realizable(cell) == false` for a cell on which
/// [`unrealizable_ordinal`] returns [`None`]. The XOR-complementary
/// partition discipline pins that exactly one of the two dense
/// ordinals is [`Some`] on every cell, and the variant agreement
/// invariant ([`tests::partition_ordinal_variant_agrees_with_is_realizable`])
/// pins that the predicate-driven branch selects the side that
/// returns [`Some`]; in practice both branches are reachable only
/// when the implementor lies about `is_realizable`, which the
/// trait-uniform tests would catch at the same site.
#[must_use]
pub fn partition_ordinal<C: ProductCube>(cell: C) -> PartitionOrdinal {
    if ProductCube::is_realizable(cell) {
        PartitionOrdinal::Realizable(
            realizable_ordinal::<C>(cell).expect(
                "ProductCube discipline: is_realizable(cell) => realizable_ordinal is Some",
            ),
        )
    } else {
        PartitionOrdinal::Unrealizable(
            unrealizable_ordinal::<C>(cell).expect(
                "ProductCube discipline: !is_realizable(cell) => unrealizable_ordinal is Some",
            ),
        )
    }
}

/// Decode a [`PartitionOrdinal`] into the cell it addresses on a
/// [`ProductCube`] — fuses ([`realizable_at`], [`unrealizable_at`])
/// into one helper routed by the variant tag.
///
/// Safe forward dual of [`partition_ordinal`]: where
/// [`partition_ordinal`] is the total inverse `cell → PartitionOrdinal`
/// over the cube, [`at_partition_ordinal`] is the partial forward
/// `PartitionOrdinal → Option<cell>` over the typed disjoint-union
/// encoding, returning [`Some`] exactly when the inner `usize` falls
/// in-range on the face the variant tag selects and [`None`] when the
/// inner `usize` exceeds the face's count.
///
/// **Bijection laws** — pinned by trait-uniform tests reaching every
/// implementor pointwise:
///
/// 1. **Round-trip from the cell side** —
///    `at_partition_ordinal::<C>(partition_ordinal::<C>(cell)) == Some(cell)`
///    for every cell of every cube. The
///    `partition_ordinal`-then-`at_partition_ordinal` composition is
///    the identity on `C::ALL`.
/// 2. **Round-trip from the partition-ordinal side** —
///    `at_partition_ordinal::<C>(p).map(partition_ordinal::<C>) == Some(p)`
///    for every in-range `p: PartitionOrdinal`. The
///    `at_partition_ordinal`-then-`partition_ordinal` composition is
///    the identity on the in-range domain.
/// 3. **Partiality on out-of-range** —
///    `at_partition_ordinal::<C>(PartitionOrdinal::Realizable(i)).is_none()`
///    for `i >= realizable_count::<C>()` and dually
///    `at_partition_ordinal::<C>(PartitionOrdinal::Unrealizable(i)).is_none()`
///    for `i >= unrealizable_count::<C>()`. The forward map is defined
///    over each variant's restricted prefix and undefined outside it.
/// 4. **Image realizability matches the variant tag** —
///    `at_partition_ordinal::<C>(PartitionOrdinal::Realizable(i)).map(is_realizable) == Some(true)`
///    for in-range `i`, and dually for [`PartitionOrdinal::Unrealizable`]
///    with `Some(false)`. The forward map's variant tag and the
///    cell's realizability are in lockstep.
///
/// **Consumers** — manifest decoders, error-path consumers, and
/// observability dashboards recover the typed cell from a
/// [`PartitionOrdinal`] address through one named helper rather than
/// branching on the variant and calling [`realizable_at`] /
/// [`unrealizable_at`] inline at every site.
#[must_use]
pub fn at_partition_ordinal<C: ProductCube>(p: PartitionOrdinal) -> Option<C> {
    match p {
        PartitionOrdinal::Realizable(i) => realizable_at::<C>(i),
        PartitionOrdinal::Unrealizable(i) => unrealizable_at::<C>(i),
    }
}

/// Closed discipline trait for the [`ProductCube`] subset whose
/// forward map from the recognized-image type into the cube is
/// injective, so the cube carries a partial inverse back into the
/// image: `invert(cell) = Some(image)` exactly on the realizable
/// cells, `None` on the cross-axis consistency-violation complement.
///
/// Two cubes satisfy this sub-discipline today:
///
/// - [`crate::FormatCoordinates`] —
///   [`crate::FormatCoordinates::format_or_none`] is the partial
///   inverse of [`crate::Format::format_coordinates`].
/// - [`crate::AttributionCoordinates`] —
///   [`crate::AttributionRule::from_coordinates`] is the partial
///   inverse of [`crate::AttributionRule::coordinates`].
///
/// The other two cubes on the typescape primitive set —
/// [`crate::ErrorLocalizationCoordinates`] and
/// [`crate::AttributionSourceKindCoordinates`] — carry an
/// `is_realizable` predicate but no partial inverse: their forward
/// maps are non-injective or their realizable image is not in
/// one-to-one correspondence with a single typescape value (the error-
/// localization image collapses many `(kind, localization)` pairs onto
/// the same `(kind, observable-failure)` observation, and the
/// source-axis-kind image collapses pairs of source-axis rules onto
/// the same `(figment_source_kind, layer_kind)` joint cell only when
/// the rule space stays at its current two-element source-axis
/// subset).
///
/// The trait binds [`Self::Image`] to the recognized-image type
/// — itself a [`ClosedAxis`] on the typescape primitive set
/// (`Format` for [`crate::FormatCoordinates`], `AttributionRule` for
/// [`crate::AttributionCoordinates`]) — so generic helpers
/// ([`realizable_images`], [`forward_iter`]) can iterate the image
/// without naming the concrete cube type, and generic bijection tests
/// reach `Self::Image::ALL` through the [`ClosedAxis`] discipline the
/// image type already satisfies. `Debug` is added so generic
/// invariant helpers can `assert_eq!` against image values without
/// per-implementor harness boilerplate.
///
/// Two structural invariants — pinned by trait-uniform tests reaching
/// every implementor pointwise:
///
/// 1. **`invert`-realizability agreement** —
///    `cell.invert().is_some() == ProductCube::is_realizable(cell)`,
///    pinned by [`tests::partial_inverse_some_iff_is_realizable`].
/// 2. **`forward`-`invert` bijection on the recognized half** —
///    `Self::forward(image).invert() == Some(image)` for every
///    `image: Self::Image`, and dually
///    `forward(invert(cell).unwrap()) == cell` for every realizable
///    cell; pinned by the round-trip helpers in the test module.
///    Equivalently, the forward image of `Self::Image::ALL` under
///    [`Self::forward`] equals `realizable_iter::<Self>()` as a set,
///    pinned by
///    [`tests::forward_image_of_image_all_equals_realizable_iter`].
///
/// A third (or fourth) implementor landing — a future
/// `(figment_source_kind × axis × confidence)` refinement cube with a
/// bijection to a source-axis rule subset, or a `(format ×
/// name_style)` discovery refinement cube with a bijection to a typed
/// discovery-key envelope — picks up both invariants and the generic
/// helpers ([`realizable_images`], [`forward_iter`]) at the
/// `impl PartialInverseCube` declaration, with the invariants enforced
/// by the same trait-uniform tests reaching every implementor pointwise.
pub trait PartialInverseCube: ProductCube {
    /// The recognized-image type — the typescape value the partial
    /// inverse re-hydrates on realizable cells (`Format` for
    /// [`crate::FormatCoordinates`], `AttributionRule` for
    /// [`crate::AttributionCoordinates`]).
    ///
    /// Bound to [`ClosedAxis`] so the image is itself a typescape
    /// primitive — generic helpers reach `Self::Image::ALL` through
    /// the same trait discipline the cube does, and the bijection
    /// invariant (forward image of `Image::ALL` equals realizable
    /// cells) is stated in trait-uniform language. `Debug` is added so
    /// generic invariant tests can `assert_eq!` against image values
    /// without per-implementor harness boilerplate.
    type Image: ClosedAxis + std::fmt::Debug;

    /// Partial inverse: `Some(image)` for realizable cells, `None`
    /// for the cross-axis consistency-violation complement.
    ///
    /// Mirror of the inherent partial-inverse method every implementor
    /// already exposes
    /// ([`crate::FormatCoordinates::format_or_none`],
    /// [`crate::AttributionRule::from_coordinates`]). The trait
    /// re-export lets generic helpers ([`realizable_images`]) reach
    /// the inverse without naming the concrete cube or image type.
    fn invert(self) -> Option<Self::Image>;

    /// Forward (total) map from [`Self::Image`] into the cube — the
    /// dual of [`Self::invert`] on the recognized half. Mirror of the
    /// inherent image→cube method every implementor already exposes
    /// ([`crate::Format::format_coordinates`],
    /// [`crate::AttributionRule::coordinates`]).
    ///
    /// Total over `Self::Image`: every image lands on a realizable
    /// cell of the cube (pinned by the per-implementor
    /// `*_forward_always_lands_on_realizable_cell` tests). The pair
    /// (`forward`, `invert`) closes the bijection discipline on the
    /// recognized half of the cube — `invert(forward(image)) ==
    /// Some(image)` for every image, and dually
    /// `forward(invert(cell).unwrap()) == cell` for every realizable
    /// cell; both round-trip laws are pinned by trait-uniform tests
    /// reaching each implementor pointwise.
    ///
    /// One named entry point for the image→cube morphism, regardless
    /// of how the implementor names the inherent method. Before this
    /// lift, generic code that wanted the forward map had to name the
    /// concrete inherent method (`Format::format_coordinates`,
    /// `AttributionRule::coordinates`); the trait re-export lets the
    /// [`forward_iter`] generic helper and the bijection invariant
    /// tests dispatch over the cube type parameter alone.
    fn forward(image: Self::Image) -> Self;
}

/// Iterate the realized images of a [`PartialInverseCube`] — the
/// `Some` outputs of [`PartialInverseCube::invert`] over [`ClosedAxis::ALL`],
/// in cube-declaration order.
///
/// Generic in the cube type so a future
/// [`PartialInverseCube`] implementor inherits the helper at its
/// `impl PartialInverseCube` declaration. The output cardinality
/// equals [`realizable_count::<C>()`][realizable_count] by the
/// `invert().is_some() == is_realizable()` invariant the trait pins.
pub fn realizable_images<C: PartialInverseCube>() -> impl Iterator<Item = C::Image> {
    C::ALL
        .iter()
        .copied()
        .filter_map(PartialInverseCube::invert)
}

/// Iterate the forward image of every image under
/// [`PartialInverseCube::forward`] — `C::Image::ALL.iter().copied()
/// .map(C::forward)` collapsed to one named helper.
///
/// The output is a length-`Image::ALL.len()` sequence of realizable
/// cells (the forward map is total over the image space and lands on
/// realizable cells, pinned per implementor by
/// `*_forward_always_lands_on_realizable_cell`). As a set the output
/// equals `realizable_iter::<C>()`, pinned generically by
/// [`tests::forward_image_of_image_all_equals_realizable_iter`].
///
/// Generic in the cube type so a future [`PartialInverseCube`]
/// implementor inherits the helper at its `impl PartialInverseCube`
/// declaration. Consolidates the inline
/// `Image::ALL.iter().copied().map(Image::<inherent_forward>)`
/// pattern that appeared at the `*_realizable_image_equals_*_image`
/// test site on each cube (two such inline `.map` sites today; future
/// cubes pick up the helper at the trait impl rather than re-deriving
/// the map inline).
pub fn forward_iter<C: PartialInverseCube>() -> impl Iterator<Item = C> {
    <C::Image as ClosedAxis>::ALL
        .iter()
        .copied()
        .map(C::forward)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AttributionAxis, AttributionConfidence, AttributionCoordinates,
        AttributionNameKindCoordinates, AttributionRule, AttributionSourceKindCoordinates,
        ConfigSourceKind, ConfigTierKind, DiffLineKind, EnvMetadataTagKind,
        ErrorLocalizationCoordinates, FieldPathLocalization, FigmentNameTagKind, FigmentSourceKind,
        Format, FormatCoordinates, FormatProvenance, SecretBackendKind, SecretRefShape,
        ShikumiErrorKind, WatchEventClass,
        secret_client::{SecretClientKind, SecretErrorKind, SecretOperation},
    };

    // ---- Implementor-list macros ----
    //
    // The shikumi typescape has one declared, stable set of
    // [`ClosedAxis`] implementors today — nine closed-enum axis
    // primitives ([`Format`], [`FormatProvenance`], [`ConfigSourceKind`],
    // [`FigmentSourceKind`], [`ShikumiErrorKind`],
    // [`FieldPathLocalization`], [`AttributionRule`],
    // [`AttributionConfidence`], [`AttributionAxis`]) and four product
    // cubes ([`FormatCoordinates`], [`AttributionCoordinates`],
    // [`ErrorLocalizationCoordinates`], [`AttributionSourceKindCoordinates`]).
    // Two of the cubes additionally satisfy [`PartialInverseCube`]
    // ([`FormatCoordinates`], [`AttributionCoordinates`]).
    //
    // These three lists previously appeared inlined at every
    // trait-uniform `for every implementor` test site (more than ten
    // sites today across the `axis_iter`, `axis_cardinality`,
    // `axis_ordinal`, `axis_at`, `realizable_*`, and `forward_*`
    // helpers); each duplicated list had to be manually kept in
    // lockstep with the typescape's implementor set, so a tenth axis
    // primitive or fifth cube landing meant editing every site by
    // hand. Lifting them into three callback macros — one per
    // trait-implementor set — keeps the lists at one site each:
    // a future axis primitive lands as one new arm in
    // [`for_each_closed_axis_primitive`], picks up every trait-uniform
    // invariant test by macro expansion, and the per-test inline
    // listing disappears. The macros expand at every call site to the
    // same `cb!(TypeName);` sequence the inline listings carried, so
    // the runtime behavior is identical and the compiler still type-
    // checks each expanded `assert_*::<TypeName>()` call against the
    // trait bound.
    //
    // The macros are deliberately scoped to the test module —
    // implementor-list discipline is a test-time concern (no runtime
    // code dispatches over the list since [`ClosedAxis`] is not
    // object-safe). The `for_each_closed_axis_implementor` superset
    // macro composes the two ClosedAxis-implementor sets (nine
    // primitive enums + four cubes) so a "reach every implementor"
    // test can list one macro call instead of two.

    /// Invokes `$cb!(TypeName)` for each [`ClosedAxis`] axis-primitive
    /// enum — the fifteen closed-enum axis primitives the typescape
    /// recognizes today, in declaration order. [`PartitionFace`],
    /// [`ConfigTierKind`], [`WatchEventClass`], [`FigmentNameTagKind`],
    /// [`SecretBackendKind`], and [`SecretRefShape`] sit at the tail as
    /// the six non-cube-axis primitives (the first a variant-tag
    /// projection of [`PartitionOrdinal`], the second of
    /// [`crate::ConfigTier`], the third the reload-relevance
    /// classification of a raw [`notify::Event`] kind, the fourth the
    /// `'static` discriminant of [`crate::FigmentNameTag`] on the
    /// figment-`Metadata::name` axis — the symmetric peer of
    /// [`FigmentSourceKind`] on the figment-`Source` axis, the fifth
    /// the `'static` discriminant of [`crate::secret::SecretBackend`]
    /// on the secret-resolution backend axis — peer of
    /// [`ConfigSourceKind`] / [`FigmentNameTagKind`] /
    /// [`FigmentSourceKind`] on their respective discriminant axes, the
    /// sixth the shared (whole-reference × extracted-field) variant-tag
    /// projection over the untagged-enum `*Ref` pair
    /// `(crate::secret::SopsRef, crate::secret::VaultRef)` — the first
    /// cross-type closed-axis primitive on the typescape, naming the
    /// extraction-shape equivalence between the two `*Ref` enums at the
    /// type level rather than in the dispatch table only); the leading
    /// nine are the per-axis-of-the-cube primitives.
    macro_rules! for_each_closed_axis_primitive {
        ($cb:ident) => {
            $cb!(Format);
            $cb!(FormatProvenance);
            $cb!(ConfigSourceKind);
            $cb!(FigmentSourceKind);
            $cb!(ShikumiErrorKind);
            $cb!(FieldPathLocalization);
            $cb!(AttributionRule);
            $cb!(AttributionConfidence);
            $cb!(AttributionAxis);
            $cb!(PartitionFace);
            $cb!(ConfigTierKind);
            $cb!(WatchEventClass);
            $cb!(FigmentNameTagKind);
            $cb!(EnvMetadataTagKind);
            $cb!(SecretBackendKind);
            $cb!(SecretRefShape);
            $cb!(SecretOperation);
            $cb!(SecretErrorKind);
            $cb!(SecretClientKind);
            $cb!(DiffLineKind);
        };
    }

    /// Invokes `$cb!(TypeName)` for each [`ProductCube`] implementor —
    /// the five product cubes the typescape recognizes today, in
    /// declaration order. [`AttributionNameKindCoordinates`] sits at
    /// the tail as the symmetric peer of
    /// [`AttributionSourceKindCoordinates`] on the figment-
    /// `Metadata::name` axis.
    macro_rules! for_each_product_cube {
        ($cb:ident) => {
            $cb!(FormatCoordinates);
            $cb!(AttributionCoordinates);
            $cb!(ErrorLocalizationCoordinates);
            $cb!(AttributionSourceKindCoordinates);
            $cb!(AttributionNameKindCoordinates);
        };
    }

    /// Invokes `$cb!(TypeName)` for each [`PartialInverseCube`]
    /// implementor — the two cubes whose forward map carries an
    /// inverse on the recognized half, in declaration order.
    macro_rules! for_each_partial_inverse_cube {
        ($cb:ident) => {
            $cb!(FormatCoordinates);
            $cb!(AttributionCoordinates);
        };
    }

    /// Invokes `$cb!(TypeName)` for each [`ClosedAxis`] implementor —
    /// the nine axis primitives plus the four product cubes, thirteen
    /// in total, in declaration order. Composes
    /// [`for_each_closed_axis_primitive`] with [`for_each_product_cube`].
    macro_rules! for_each_closed_axis_implementor {
        ($cb:ident) => {
            for_each_closed_axis_primitive!($cb);
            for_each_product_cube!($cb);
        };
    }

    /// Invokes `$cb!(TypeName)` for each [`ClosedAxisLabel`]
    /// implementor — the twelve closed-axis primitives that carry a
    /// canonical operator-facing string label today
    /// ([`PartitionFace`], [`ConfigTierKind`], [`Format`],
    /// [`FormatProvenance`], [`ConfigSourceKind`],
    /// [`FigmentSourceKind`], [`AttributionConfidence`],
    /// [`AttributionAxis`], [`crate::ShikumiErrorKind`],
    /// [`crate::FieldPathLocalization`], [`crate::AttributionRule`],
    /// [`WatchEventClass`]), in declaration order. The two variant-tag
    /// projections sit at the head ([`PartitionFace`] of
    /// [`PartitionOrdinal`], [`ConfigTierKind`] of
    /// [`crate::ConfigTier`]); the nine cube-axis primitives ([`Format`],
    /// operator-facing config file format; [`FormatProvenance`], which
    /// provider class loads the format; [`ConfigSourceKind`], the kind
    /// axis of the resolved figment layer; [`FigmentSourceKind`], the
    /// kind axis of the underlying `figment::Source`;
    /// [`AttributionConfidence`], the equality-vs-uniqueness
    /// confidence class of the resolver attribution;
    /// [`AttributionAxis`], which `figment::Metadata` field drove the
    /// resolver attribution; [`crate::ShikumiErrorKind`], the data-free
    /// discriminant of [`crate::ShikumiError`];
    /// [`crate::FieldPathLocalization`], the tri-state
    /// figment-field-path localization axis of a
    /// [`crate::ShikumiError`]; [`crate::AttributionRule`], the closed
    /// five-rule resolver dispatch axis) close the labeling discipline
    /// on their respective axes through the trait. [`WatchEventClass`]
    /// sits at the tail as the watcher-side reload-relevance
    /// classification — the third non-cube-axis primitive after the
    /// two variant-tag projections, lifting the hot-reload trigger
    /// predicate to one labeled closed three-way partition. With the
    /// [`crate::AttributionRule`] lift, every axis of every product
    /// cube on the typescape now labels through the trait: both axes
    /// of the 18-cell [`crate::ErrorLocalizationCoordinates`] cube,
    /// every axis of the 12-cell [`crate::AttributionCoordinates`]
    /// cube, both axes of the 9-cell
    /// [`crate::AttributionSourceKindCoordinates`] cube, and both axes
    /// of the 8-cell [`crate::FormatCoordinates`] cube — every cell
    /// of every cube is nameable through the trait without re-deriving
    /// a string mapping at any cube-renderer site.
    ///
    /// A thirteenth [`ClosedAxisLabel`] implementor landing on the
    /// typescape (a future closed-axis primitive — a new resolver-side
    /// discriminant, a new error-side discriminant, a new figment-side
    /// classification, a new watcher-side classification) extends the
    /// macro in lockstep with the `impl ClosedAxisLabel` declaration;
    /// the pin in
    /// [`tests::for_each_closed_axis_label_implementor_macro_covers_twelve_implementors`]
    /// catches the discipline violation before silent dropouts at the
    /// five trait-uniform `closed_axis_label_*` test sites below.
    macro_rules! for_each_closed_axis_label_implementor {
        ($cb:ident) => {
            $cb!(PartitionFace);
            $cb!(ConfigTierKind);
            $cb!(Format);
            $cb!(FormatProvenance);
            $cb!(ConfigSourceKind);
            $cb!(FigmentSourceKind);
            $cb!(AttributionConfidence);
            $cb!(AttributionAxis);
            $cb!(ShikumiErrorKind);
            $cb!(FieldPathLocalization);
            $cb!(AttributionRule);
            $cb!(WatchEventClass);
            $cb!(FigmentNameTagKind);
            $cb!(EnvMetadataTagKind);
            $cb!(SecretBackendKind);
            $cb!(SecretRefShape);
            $cb!(SecretOperation);
            $cb!(SecretErrorKind);
            $cb!(SecretClientKind);
            $cb!(DiffLineKind);
        };
    }

    // ---- Trait re-exports match inherent constants/methods pointwise ----

    fn assert_trait_matches_inherent<A>(inherent_all: &[A])
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // The trait ALL is the same slice (by content, in the same
        // order) as the inherent ALL — pointwise equality across the
        // whole axis. Reaches every ClosedAxis implementor uniformly:
        // the nine closed-enum axis primitives and the four product
        // cubes.
        assert_eq!(
            <A as ClosedAxis>::ALL.len(),
            inherent_all.len(),
            "trait ALL cardinality must equal inherent ALL cardinality",
        );
        for (i, (trait_cell, inherent_cell)) in <A as ClosedAxis>::ALL
            .iter()
            .zip(inherent_all.iter())
            .enumerate()
        {
            assert_eq!(
                trait_cell, inherent_cell,
                "trait ALL[{i}] must equal inherent ALL[{i}]",
            );
        }
    }

    fn assert_trait_is_realizable_matches_inherent<C>(
        inherent_all: &[C],
        inherent_is_realizable: fn(C) -> bool,
    ) where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell of the cube, the trait method and the inherent
        // method agree pointwise. Pins that the trait impl forwards to
        // the inherent method without silently flipping the predicate
        // or losing an arm.
        for cell in inherent_all.iter().copied() {
            assert_eq!(
                ProductCube::is_realizable(cell),
                inherent_is_realizable(cell),
                "cell {cell:?}: trait is_realizable must equal inherent is_realizable",
            );
        }
    }

    #[test]
    fn format_coordinates_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<FormatCoordinates>(FormatCoordinates::ALL);
    }

    #[test]
    fn attribution_coordinates_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<AttributionCoordinates>(AttributionCoordinates::ALL);
    }

    #[test]
    fn error_localization_coordinates_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<ErrorLocalizationCoordinates>(
            ErrorLocalizationCoordinates::ALL,
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<AttributionSourceKindCoordinates>(
            AttributionSourceKindCoordinates::ALL,
        );
    }

    #[test]
    fn format_coordinates_trait_is_realizable_matches_inherent() {
        assert_trait_is_realizable_matches_inherent::<FormatCoordinates>(
            FormatCoordinates::ALL,
            FormatCoordinates::is_realizable,
        );
    }

    #[test]
    fn attribution_coordinates_trait_is_realizable_matches_inherent() {
        assert_trait_is_realizable_matches_inherent::<AttributionCoordinates>(
            AttributionCoordinates::ALL,
            AttributionCoordinates::is_realizable,
        );
    }

    #[test]
    fn error_localization_coordinates_trait_is_realizable_matches_inherent() {
        assert_trait_is_realizable_matches_inherent::<ErrorLocalizationCoordinates>(
            ErrorLocalizationCoordinates::ALL,
            ErrorLocalizationCoordinates::is_realizable,
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_trait_is_realizable_matches_inherent() {
        assert_trait_is_realizable_matches_inherent::<AttributionSourceKindCoordinates>(
            AttributionSourceKindCoordinates::ALL,
            AttributionSourceKindCoordinates::is_realizable,
        );
    }

    // ---- Generic helpers cover ALL exactly once ----

    fn assert_realizable_partitions_all<C>(inherent_all: &[C])
    where
        C: ProductCube + std::fmt::Debug,
    {
        // realizable_iter and unrealizable_iter together cover ALL
        // exactly once, in the same order ALL is laid out. The
        // partition is total (every cell is one or the other) and
        // disjoint (no cell is both).
        let realizable: Vec<C> = realizable_iter::<C>().collect();
        let unrealizable: Vec<C> = unrealizable_iter::<C>().collect();
        assert_eq!(
            realizable.len() + unrealizable.len(),
            inherent_all.len(),
            "realizable + unrealizable cardinalities must sum to ALL cardinality",
        );
        for cell in &realizable {
            assert!(
                ProductCube::is_realizable(*cell),
                "cell {cell:?} in realizable_iter must satisfy is_realizable",
            );
            assert!(
                !unrealizable.contains(cell),
                "cell {cell:?} must not appear in both partitions",
            );
        }
        for cell in &unrealizable {
            assert!(
                !ProductCube::is_realizable(*cell),
                "cell {cell:?} in unrealizable_iter must not satisfy is_realizable",
            );
        }
    }

    #[test]
    fn format_coordinates_generic_realizable_partitions_all() {
        assert_realizable_partitions_all::<FormatCoordinates>(FormatCoordinates::ALL);
    }

    #[test]
    fn attribution_coordinates_generic_realizable_partitions_all() {
        assert_realizable_partitions_all::<AttributionCoordinates>(AttributionCoordinates::ALL);
    }

    #[test]
    fn error_localization_coordinates_generic_realizable_partitions_all() {
        assert_realizable_partitions_all::<ErrorLocalizationCoordinates>(
            ErrorLocalizationCoordinates::ALL,
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_generic_realizable_partitions_all() {
        assert_realizable_partitions_all::<AttributionSourceKindCoordinates>(
            AttributionSourceKindCoordinates::ALL,
        );
    }

    // ---- Generic count helpers pin today's image cardinalities ----

    #[test]
    fn format_coordinates_generic_realizable_count_is_four() {
        assert_eq!(realizable_count::<FormatCoordinates>(), 4);
        assert_eq!(unrealizable_count::<FormatCoordinates>(), 4);
        assert_eq!(
            realizable_count::<FormatCoordinates>() + unrealizable_count::<FormatCoordinates>(),
            FormatCoordinates::ALL.len(),
        );
    }

    #[test]
    fn attribution_coordinates_generic_realizable_count_is_five() {
        assert_eq!(realizable_count::<AttributionCoordinates>(), 5);
        assert_eq!(unrealizable_count::<AttributionCoordinates>(), 7);
        assert_eq!(
            realizable_count::<AttributionCoordinates>()
                + unrealizable_count::<AttributionCoordinates>(),
            AttributionCoordinates::ALL.len(),
        );
    }

    #[test]
    fn error_localization_coordinates_generic_realizable_count_is_eight() {
        assert_eq!(realizable_count::<ErrorLocalizationCoordinates>(), 8);
        assert_eq!(unrealizable_count::<ErrorLocalizationCoordinates>(), 10);
        assert_eq!(
            realizable_count::<ErrorLocalizationCoordinates>()
                + unrealizable_count::<ErrorLocalizationCoordinates>(),
            ErrorLocalizationCoordinates::ALL.len(),
        );
    }

    #[test]
    fn attribution_source_kind_coordinates_generic_realizable_count_is_two() {
        assert_eq!(realizable_count::<AttributionSourceKindCoordinates>(), 2);
        assert_eq!(unrealizable_count::<AttributionSourceKindCoordinates>(), 7);
        assert_eq!(
            realizable_count::<AttributionSourceKindCoordinates>()
                + unrealizable_count::<AttributionSourceKindCoordinates>(),
            AttributionSourceKindCoordinates::ALL.len(),
        );
    }

    // ---- All four cubes plug into the trait uniformly ----

    #[test]
    fn all_four_product_cubes_have_nonempty_all() {
        // Trivially-true sanity check that reaches into each cube
        // through the trait ALL — pins that all four impls compile and
        // are linked into the binary. A fifth cube landing without an
        // `impl ProductCube` arm would not be reached here, but the
        // trait bound on the future generic consumer would fail to
        // compile, which is the structural enforcement of the
        // discipline.
        assert!(!<FormatCoordinates as ClosedAxis>::ALL.is_empty());
        assert!(!<AttributionCoordinates as ClosedAxis>::ALL.is_empty());
        assert!(!<ErrorLocalizationCoordinates as ClosedAxis>::ALL.is_empty());
        assert!(!<AttributionSourceKindCoordinates as ClosedAxis>::ALL.is_empty());
    }

    // ---- PartialInverseCube invariants ----
    //
    // The trait invariant — `cell.invert().is_some() ==
    // ProductCube::is_realizable(cell)` for every cell of every
    // implementor — is asserted by one trait-uniform helper reaching
    // each implementor pointwise. A third (or fourth) implementor
    // landing picks up the invariant test by adding one call to the
    // helper, not by re-deriving the loop body inline.

    fn assert_partial_inverse_some_iff_is_realizable<C>()
    where
        C: PartialInverseCube + std::fmt::Debug,
    {
        for cell in <C as ClosedAxis>::ALL.iter().copied() {
            assert_eq!(
                cell.invert().is_some(),
                ProductCube::is_realizable(cell),
                "cell {cell:?}: invert().is_some() must equal is_realizable()",
            );
        }
    }

    #[test]
    fn format_coordinates_partial_inverse_some_iff_is_realizable() {
        assert_partial_inverse_some_iff_is_realizable::<FormatCoordinates>();
    }

    #[test]
    fn attribution_coordinates_partial_inverse_some_iff_is_realizable() {
        assert_partial_inverse_some_iff_is_realizable::<AttributionCoordinates>();
    }

    #[test]
    fn format_coordinates_realizable_images_cardinality_matches_realizable_count() {
        // The generic realizable_images iterator has the same
        // cardinality as the realizable-cell count — proven by the
        // trait invariant invert().is_some() == is_realizable() that
        // assert_partial_inverse_some_iff_is_realizable pins.
        assert_eq!(
            realizable_images::<FormatCoordinates>().count(),
            realizable_count::<FormatCoordinates>(),
        );
    }

    #[test]
    fn attribution_coordinates_realizable_images_cardinality_matches_realizable_count() {
        assert_eq!(
            realizable_images::<AttributionCoordinates>().count(),
            realizable_count::<AttributionCoordinates>(),
        );
    }

    fn assert_realizable_images_equals_image_all<C>()
    where
        C: PartialInverseCube + std::fmt::Debug,
    {
        // For an injective forward map (each implementor's inherent
        // `Image::<forward>` is injective on `Image::ALL`), the
        // realizable-images iterator produces every image exactly
        // once. Pins that the partial inverse covers Image::ALL
        // pointwise — generic over the cube type so today's two
        // PartialInverseCube implementors and any future implementor
        // share one helper instead of duplicating the body per cube.
        use std::collections::HashSet;
        let images: HashSet<C::Image> = realizable_images::<C>().collect();
        let expected: HashSet<C::Image> = <C::Image as ClosedAxis>::ALL.iter().copied().collect();
        assert_eq!(
            images, expected,
            "realizable_images must equal Image::ALL as a set",
        );
    }

    #[test]
    fn format_coordinates_realizable_images_equals_format_all() {
        assert_realizable_images_equals_image_all::<FormatCoordinates>();
    }

    #[test]
    fn attribution_coordinates_realizable_images_equals_rule_all() {
        assert_realizable_images_equals_image_all::<AttributionCoordinates>();
    }

    // ---- ClosedAxis invariants reach all thirteen implementors ----
    //
    // The nine closed-enum axis primitives plus the four product cubes
    // plug into the same trait. One trait-uniform helper, one
    // generic-helper agreement check, and one cardinality check pin
    // the discipline pointwise on every implementor.

    fn assert_axis_iter_matches_trait_all<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // axis_iter::<A>() is the named lift of A::ALL.iter().copied();
        // pin the two produce the same sequence in the same order. The
        // helper consolidates the 98+ inline `::ALL.iter().copied()`
        // sites the crate carries across cover / partition / cube-
        // coverage tests.
        let iter_collected: Vec<A> = axis_iter::<A>().collect();
        let all_collected: Vec<A> = <A as ClosedAxis>::ALL.to_vec();
        assert_eq!(
            iter_collected.len(),
            all_collected.len(),
            "axis_iter cardinality must equal trait ALL cardinality",
        );
        for (i, (from_iter, from_all)) in
            iter_collected.iter().zip(all_collected.iter()).enumerate()
        {
            assert_eq!(
                from_iter, from_all,
                "axis_iter[{i}] must equal trait ALL[{i}]",
            );
        }
    }

    fn assert_axis_cardinality_matches_trait_all<A>(expected: usize)
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // axis_cardinality::<A>() is the named lift of A::ALL.len();
        // pin agreement with the trait constant slice length and with
        // the today-pinned variant count so a future variant landing
        // (a tenth typescape axis primitive variant on any of the nine
        // enums, or a fifth cell axis on any of the four cubes) moves
        // the expected count in lockstep.
        assert_eq!(
            axis_cardinality::<A>(),
            <A as ClosedAxis>::ALL.len(),
            "axis_cardinality must equal trait ALL slice length",
        );
        assert_eq!(
            axis_cardinality::<A>(),
            expected,
            "axis_cardinality must equal today's pinned variant count",
        );
    }

    // ---- The nine closed-enum axis primitives ----

    #[test]
    fn format_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<Format>(Format::ALL);
    }

    #[test]
    fn format_provenance_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<FormatProvenance>(FormatProvenance::ALL);
    }

    #[test]
    fn config_source_kind_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<ConfigSourceKind>(ConfigSourceKind::ALL);
    }

    #[test]
    fn figment_source_kind_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<FigmentSourceKind>(FigmentSourceKind::ALL);
    }

    #[test]
    fn shikumi_error_kind_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<ShikumiErrorKind>(ShikumiErrorKind::ALL);
    }

    #[test]
    fn field_path_localization_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<FieldPathLocalization>(FieldPathLocalization::ALL);
    }

    #[test]
    fn attribution_rule_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<AttributionRule>(AttributionRule::ALL);
    }

    #[test]
    fn attribution_confidence_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<AttributionConfidence>(AttributionConfidence::ALL);
    }

    #[test]
    fn attribution_axis_trait_all_matches_inherent_all() {
        assert_trait_matches_inherent::<AttributionAxis>(AttributionAxis::ALL);
    }

    #[test]
    fn partition_face_trait_all_matches_inherent_all() {
        // PartitionFace is the tenth closed-axis primitive — the
        // variant-tag projection of `PartitionOrdinal`. The trait
        // `ALL` slice is the inherent `ALL` slice (pointwise equal,
        // same declaration order: Realizable, Unrealizable). A future
        // variant landing on `PartitionFace` extends both slices in
        // lockstep, but no expansion is anticipated: the two-element
        // {realizable, unrealizable} partition is structural to
        // `ProductCube::is_realizable`.
        assert_trait_matches_inherent::<PartitionFace>(PartitionFace::ALL);
    }

    #[test]
    fn watch_event_class_trait_all_matches_inherent_all() {
        // `WatchEventClass` is the twelfth closed-axis primitive — the
        // reload-relevance classification of a raw `notify::Event`
        // kind, lifted by `crate::watcher` into the typescape primitive
        // set. The trait `ALL` slice is the inherent `ALL` slice
        // (pointwise equal, same declaration order: `Reload`,
        // `Removed`, `Ignored`). A future variant landing on
        // `WatchEventClass` (e.g. a `Quiesced` class for a debounced
        // window with no triggers) extends both slices in lockstep.
        // Pins that the trait-uniform invariant suite reaching every
        // `for_each_closed_axis_*` macro arm now reaches the
        // watcher-side classification on the same proof harness as
        // every other axis primitive on the typescape.
        assert_trait_matches_inherent::<WatchEventClass>(WatchEventClass::ALL);
    }

    #[test]
    fn figment_name_tag_kind_trait_all_matches_inherent_all() {
        // `FigmentNameTagKind` is the thirteenth closed-axis primitive
        // — the `'static` discriminant of `crate::FigmentNameTag` on
        // figment's `Metadata::name` axis, the symmetric peer of
        // `FigmentSourceKind` on the `Metadata::source` axis. The
        // trait `ALL` slice is the inherent `ALL` slice (pointwise
        // equal, same declaration order: `Format`, `Env`). A future
        // variant landing on `FigmentNameTagKind` (e.g. a hypothetical
        // `Url` kind in lockstep with a `FigmentNameTag::Url` if
        // figment's name axis grows one) extends both slices in
        // lockstep. Pins that the trait-uniform invariant suite
        // reaching every `for_each_closed_axis_*` macro arm now
        // reaches the figment-name-axis kind classification on the
        // same proof harness as the figment-Source-axis kind and
        // every other axis primitive on the typescape.
        assert_trait_matches_inherent::<FigmentNameTagKind>(FigmentNameTagKind::ALL);
    }

    // ---- axis_iter agrees with trait ALL for every implementor ----

    #[test]
    fn axis_iter_matches_trait_all_for_every_closed_enum_axis() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_iter_matches_trait_all::<$ty>();
            };
        }
        for_each_closed_axis_primitive!(check);
    }

    #[test]
    fn axis_iter_matches_trait_all_for_every_product_cube() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_iter_matches_trait_all::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    // ---- axis_cardinality pins today's variant / cell counts ----

    #[test]
    fn axis_cardinality_pins_todays_counts_across_twenty_implementors() {
        // Twenty closed-enum axis primitives. A new variant landing
        // on any of these enums extends the expected count in
        // lockstep.
        assert_axis_cardinality_matches_trait_all::<Format>(4);
        assert_axis_cardinality_matches_trait_all::<FormatProvenance>(2);
        assert_axis_cardinality_matches_trait_all::<ConfigSourceKind>(3);
        assert_axis_cardinality_matches_trait_all::<FigmentSourceKind>(3);
        assert_axis_cardinality_matches_trait_all::<ShikumiErrorKind>(6);
        assert_axis_cardinality_matches_trait_all::<FieldPathLocalization>(3);
        assert_axis_cardinality_matches_trait_all::<AttributionRule>(5);
        assert_axis_cardinality_matches_trait_all::<AttributionConfidence>(2);
        assert_axis_cardinality_matches_trait_all::<AttributionAxis>(2);
        assert_axis_cardinality_matches_trait_all::<PartitionFace>(2);
        assert_axis_cardinality_matches_trait_all::<ConfigTierKind>(4);
        assert_axis_cardinality_matches_trait_all::<WatchEventClass>(3);
        assert_axis_cardinality_matches_trait_all::<FigmentNameTagKind>(2);
        assert_axis_cardinality_matches_trait_all::<EnvMetadataTagKind>(2);
        assert_axis_cardinality_matches_trait_all::<DiffLineKind>(3);
        // Five product cubes. A new cell-axis landing on any cube
        // extends the expected count by the product of the new axis's
        // cardinality with the cube's prior cardinality.
        assert_axis_cardinality_matches_trait_all::<FormatCoordinates>(8);
        assert_axis_cardinality_matches_trait_all::<AttributionCoordinates>(12);
        assert_axis_cardinality_matches_trait_all::<ErrorLocalizationCoordinates>(18);
        assert_axis_cardinality_matches_trait_all::<AttributionSourceKindCoordinates>(9);
        assert_axis_cardinality_matches_trait_all::<AttributionNameKindCoordinates>(6);
    }

    // ---- axis_ordinal closes the dense-embedding round-trip ----
    //
    // `axis_ordinal::<A>(v)` is the dual of `axis_iter::<A>()`:
    // iteration yields `A::ALL[i]`; ordinal recovers `i` from the value.
    // Two trait-uniform invariants reach every implementor pointwise:
    //
    //   (a) round-trip — `A::ALL[axis_ordinal(v)] == v` for every
    //       `v: A`, and dually `axis_ordinal(A::ALL[i]) == i` for every
    //       `i < axis_cardinality::<A>()`;
    //   (b) injectivity — distinct values land at distinct ordinals,
    //       equivalently the ordinal image equals
    //       `0..axis_cardinality::<A>()` as a set (no duplicates in
    //       `A::ALL`).
    //
    // A tenth axis primitive or fifth product cube landing picks up
    // both invariants by adding one line to each helper-bundle test.

    fn assert_axis_ordinal_round_trips<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Forward law: `A::ALL[axis_ordinal(v)] == v` for every
        // `v: A`. Iterates A::ALL once, recomputes the ordinal of
        // each value, and re-indexes A::ALL with it.
        for (i, value) in A::ALL.iter().copied().enumerate() {
            let ordinal = axis_ordinal::<A>(value);
            assert_eq!(
                ordinal, i,
                "axis_ordinal(A::ALL[{i}]) must equal {i}; got {ordinal}",
            );
            assert_eq!(
                A::ALL[ordinal],
                value,
                "A::ALL[axis_ordinal(v)] must equal v for v = A::ALL[{i}]",
            );
        }
    }

    fn assert_axis_ordinal_injective<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Injectivity: distinct values land at distinct ordinals.
        // Equivalently, the ordinal image over A::ALL equals
        // `0..axis_cardinality::<A>()` as a set — the canonical dense
        // embedding of the axis into the natural-number prefix. Pins
        // the no-duplicates discipline on A::ALL uniformly across all
        // implementors at one site (replaces the per-axis
        // `*_all_has_no_duplicates` invariant at the trait level
        // without removing the per-axis tests).
        use std::collections::HashSet;
        let ordinals: HashSet<usize> = axis_iter::<A>().map(axis_ordinal::<A>).collect();
        let expected: HashSet<usize> = (0..axis_cardinality::<A>()).collect();
        assert_eq!(
            ordinals, expected,
            "axis_ordinal image over A::ALL must equal 0..axis_cardinality::<A>() as a set",
        );
    }

    #[test]
    fn axis_ordinal_round_trips_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_ordinal_round_trips::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_ordinal_injective_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_ordinal_injective::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_ordinal_pins_first_and_last_positions_for_every_implementor() {
        // For every ClosedAxis implementor, the first value of
        // `A::ALL` lands at ordinal 0 and the last lands at
        // `axis_cardinality::<A>() - 1`. Pins the endpoints of the
        // dense embedding so a future re-ordering of `::ALL` (the
        // declaration-order discipline) is caught at the
        // first/last call site, not only by the round-trip law.
        fn assert_endpoints<A: ClosedAxis>() {
            let n = axis_cardinality::<A>();
            assert!(n > 0, "ClosedAxis::ALL must be non-empty");
            assert_eq!(axis_ordinal::<A>(A::ALL[0]), 0);
            assert_eq!(axis_ordinal::<A>(A::ALL[n - 1]), n - 1);
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_endpoints::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    // ---- axis_at closes the safe forward direction of the
    // ---- (axis_ordinal, axis_at) bijection ----
    //
    // `axis_at::<A>(i)` is the safe forward dual of `axis_ordinal::<A>`:
    // where `axis_ordinal` is the total inverse `value → ordinal` over
    // the closed axis, `axis_at` is the partial forward
    // `ordinal → Option<value>` over `usize`, returning `Some` on the
    // prefix `0..axis_cardinality::<A>()` and `None` outside it. Three
    // trait-uniform invariants reach every implementor pointwise:
    //
    //   (a) round-trip from the value side —
    //       `axis_at(axis_ordinal(v)) == Some(v)` for every `v: A`;
    //   (b) round-trip from the ordinal side —
    //       `axis_at(i).map(axis_ordinal) == Some(i)` for every
    //       `i < axis_cardinality::<A>()`;
    //   (c) partiality on out-of-range —
    //       `axis_at(i).is_none()` for every
    //       `i >= axis_cardinality::<A>()`.
    //
    // Together (a)+(b)+(c) state the bijection between every
    // ClosedAxis implementor and the prefix `0..axis_cardinality::<A>()`
    // of the natural numbers, with the partiality at the OOB boundary
    // surfaced at the type level via the `Option` return rather than
    // by `A::ALL[i]` panicking on the slice index. A tenth axis
    // primitive or fifth product cube landing picks up all three
    // invariants by adding one line to each helper-bundle test.

    fn assert_axis_at_round_trips_value_side<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every value of A, ordinal-then-lookup recovers the value.
        // The composition `axis_at ∘ axis_ordinal` is the identity on A.
        for value in axis_iter::<A>() {
            let ordinal = axis_ordinal::<A>(value);
            assert_eq!(
                axis_at::<A>(ordinal),
                Some(value),
                "axis_at(axis_ordinal({value:?})) must equal Some({value:?})",
            );
        }
    }

    fn assert_axis_at_round_trips_ordinal_side<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every in-range ordinal, lookup-then-ordinal recovers the
        // ordinal. The composition `axis_ordinal ∘ axis_at` is the
        // identity on the prefix `0..axis_cardinality::<A>()`.
        for i in 0..axis_cardinality::<A>() {
            let recovered = axis_at::<A>(i).map(axis_ordinal::<A>);
            assert_eq!(
                recovered,
                Some(i),
                "axis_at({i}).map(axis_ordinal) must equal Some({i}) for in-range ordinal",
            );
        }
    }

    fn assert_axis_at_none_on_out_of_range<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every out-of-range ordinal, the forward map returns None.
        // Pins the partiality boundary: axis_at is defined exactly on
        // the prefix `0..axis_cardinality::<A>()`. Checks the immediate
        // boundary (n, n+1) plus a comfortable margin (n+7) and the
        // `usize::MAX` extreme to catch any silent saturation.
        let n = axis_cardinality::<A>();
        for i in [n, n + 1, n + 7, usize::MAX] {
            assert!(
                axis_at::<A>(i).is_none(),
                "axis_at({i}) must be None for ordinal >= axis_cardinality (n = {n})",
            );
        }
    }

    #[test]
    fn axis_at_round_trips_value_side_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_at_round_trips_value_side::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_at_round_trips_ordinal_side_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_at_round_trips_ordinal_side::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_at_returns_none_on_out_of_range_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_at_none_on_out_of_range::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_at_agrees_with_axis_iter_pointwise_for_every_implementor() {
        // `axis_at::<A>(i)` and the `i`-th element of `axis_iter::<A>()`
        // must agree pointwise. Pins that `axis_at` indexes through the
        // same declaration-order surface that `axis_iter` streams; a
        // future re-ordering of `::ALL` would fail here as well as in
        // the round-trip tests, but at the per-position site rather
        // than only at the bijection level.
        fn assert_pointwise<A>()
        where
            A: ClosedAxis + std::fmt::Debug,
        {
            for (i, from_iter) in axis_iter::<A>().enumerate() {
                assert_eq!(
                    axis_at::<A>(i),
                    Some(from_iter),
                    "axis_at({i}) must equal Some(axis_iter[{i}]) = Some({from_iter:?})",
                );
            }
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_pointwise::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_iter_for_product_cube_agrees_with_realizable_plus_unrealizable() {
        // For any ProductCube, axis_iter::<C>() is the disjoint union
        // of realizable_iter::<C>() and unrealizable_iter::<C>() in the
        // declaration-order interleaving the underlying ClosedAxis::ALL
        // pins. The realizability filter cuts ALL into the two halves,
        // and axis_iter recovers the whole.
        fn assert_axis_iter_recovers_partition<C>()
        where
            C: ProductCube + std::fmt::Debug,
        {
            use std::collections::HashSet;
            let whole: HashSet<C> = axis_iter::<C>().collect();
            let realizable: HashSet<C> = realizable_iter::<C>().collect();
            let unrealizable: HashSet<C> = unrealizable_iter::<C>().collect();
            assert!(
                realizable.is_disjoint(&unrealizable),
                "realizable and unrealizable halves must be disjoint",
            );
            let recovered: HashSet<C> = realizable.union(&unrealizable).copied().collect();
            assert_eq!(
                whole, recovered,
                "axis_iter must equal realizable ∪ unrealizable as a set",
            );
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_iter_recovers_partition::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    // ---- realizable_ordinal / realizable_at close the dense bijection
    // ---- between the realizable surface and 0..realizable_count ----
    //
    // The pair (realizable_ordinal, realizable_at) is the cube-level
    // analog of (axis_ordinal, axis_at): a dense embedding of the
    // recognized-image half of the cube into the natural-number prefix
    // `0..realizable_count::<C>()`. Where (axis_ordinal, axis_at) close
    // the total/partial bijection between every ClosedAxis implementor
    // and `0..axis_cardinality::<A>()`, the cube-level pair closes the
    // partial/partial bijection between the realizable surface and
    // `0..realizable_count::<C>()`, with the unrealizable complement
    // returning None on both sides. Four trait-uniform invariants reach
    // every implementor pointwise:
    //
    //   (a) realizable_ordinal partiality —
    //       `realizable_ordinal(cell).is_some() == is_realizable(cell)`;
    //   (b) realizable_at partiality —
    //       `realizable_at(i).is_some() == (i < realizable_count)`;
    //   (c) round-trip — `realizable_at(realizable_ordinal(c).unwrap()) == Some(c)`
    //       for every realizable cell, and dually
    //       `realizable_at(i).and_then(realizable_ordinal) == Some(i)`
    //       for every in-range ordinal;
    //   (d) image realizability — every `realizable_at(i)` for in-range
    //       `i` returns Some(cell) with is_realizable(cell) true.
    //
    // A fifth product cube landing picks up all four invariants by
    // adding one line to each helper-bundle test.

    fn assert_realizable_ordinal_some_iff_is_realizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell of the cube, the dense ordinal is Some exactly
        // when the cell is realizable. The ordinal is defined precisely
        // on the realizable surface; the unrealizable complement
        // uniformly returns None. Equivalent to `is_realizable` at the
        // partiality boundary — pins that the dense embedding's domain
        // equals the realizable surface, not a different subset.
        for cell in axis_iter::<C>() {
            assert_eq!(
                realizable_ordinal::<C>(cell).is_some(),
                ProductCube::is_realizable(cell),
                "cell {cell:?}: realizable_ordinal(...).is_some() must equal is_realizable(...)",
            );
        }
    }

    fn assert_realizable_at_some_iff_in_realizable_prefix<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i < realizable_count::<C>()`, the
        // dense lookup returns Some; for every out-of-range ordinal, it
        // returns None. The boundary check exercises the immediate
        // boundary (`n`, `n+1`), a comfortable margin (`n+7`), and the
        // `usize::MAX` extreme to catch any silent saturation. Pins
        // that the dense embedding's image equals `0..realizable_count`
        // and that the Option return surfaces the partiality cleanly.
        let n = realizable_count::<C>();
        for i in 0..n {
            assert!(
                realizable_at::<C>(i).is_some(),
                "realizable_at({i}) must be Some for in-range ordinal (n = {n})",
            );
        }
        for i in [n, n + 1, n + 7, usize::MAX] {
            assert!(
                realizable_at::<C>(i).is_none(),
                "realizable_at({i}) must be None for ordinal >= realizable_count (n = {n})",
            );
        }
    }

    fn assert_realizable_round_trips_cell_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every realizable cell `c`, ordinal-then-lookup recovers
        // the cell: `realizable_at(realizable_ordinal(c).unwrap()) ==
        // Some(c)`. The composition `realizable_at ∘ realizable_ordinal`
        // is the identity on the realizable surface — the cube-level
        // analog of `axis_at ∘ axis_ordinal` being the identity on A.
        for cell in realizable_iter::<C>() {
            let ordinal = realizable_ordinal::<C>(cell)
                .expect("realizable_iter must yield only ordinal-Some cells");
            assert_eq!(
                realizable_at::<C>(ordinal),
                Some(cell),
                "realizable_at(realizable_ordinal({cell:?}).unwrap()) must equal Some({cell:?})",
            );
        }
    }

    fn assert_realizable_round_trips_ordinal_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i < realizable_count::<C>()`,
        // lookup-then-ordinal recovers the ordinal: `realizable_at(i)
        // .and_then(realizable_ordinal) == Some(i)`. The composition
        // `realizable_ordinal ∘ realizable_at` is the identity on the
        // in-range prefix — the cube-level analog of `axis_ordinal ∘
        // axis_at` being the identity on `0..axis_cardinality::<A>()`.
        for i in 0..realizable_count::<C>() {
            let recovered = realizable_at::<C>(i).and_then(realizable_ordinal::<C>);
            assert_eq!(
                recovered,
                Some(i),
                "realizable_at({i}).and_then(realizable_ordinal) must equal Some({i})",
            );
        }
    }

    fn assert_realizable_at_image_is_realizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i`, the dense lookup lands on a
        // realizable cell: `realizable_at(i).map(is_realizable) ==
        // Some(true)`. Pins that the forward map's image is the
        // realizable surface, not the full cube `ALL`. Stated separately
        // from the partiality invariant so a future helper change that
        // accidentally exposes unrealizable cells in the in-range
        // prefix would fail here as well as in the round-trip law.
        for i in 0..realizable_count::<C>() {
            let cell = realizable_at::<C>(i)
                .expect("in-range realizable_at must yield Some by partiality invariant");
            assert!(
                ProductCube::is_realizable(cell),
                "realizable_at({i}) = {cell:?} must satisfy is_realizable",
            );
        }
    }

    fn assert_realizable_ordinal_image_equals_realizable_prefix<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // The ordinal image over the realizable surface equals
        // `0..realizable_count::<C>()` as a set. Equivalent to the
        // injectivity statement: distinct realizable cells land at
        // distinct ordinals, and the dense embedding is a bijection
        // (not merely an injection) onto the prefix. Pins that
        // `realizable_iter::<C>()` carries no duplicates — the cube-
        // level dual of the no-duplicates invariant on `A::ALL`.
        use std::collections::HashSet;
        let ordinals: HashSet<usize> = realizable_iter::<C>()
            .map(|c| {
                realizable_ordinal::<C>(c)
                    .expect("realizable_iter must yield only ordinal-Some cells")
            })
            .collect();
        let expected: HashSet<usize> = (0..realizable_count::<C>()).collect();
        assert_eq!(
            ordinals, expected,
            "realizable_ordinal image over realizable_iter must equal 0..realizable_count as a set",
        );
    }

    #[test]
    fn realizable_ordinal_some_iff_is_realizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_ordinal_some_iff_is_realizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_at_some_iff_in_realizable_prefix() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_at_some_iff_in_realizable_prefix::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_round_trips_cell_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_round_trips_cell_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_round_trips_ordinal_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_round_trips_ordinal_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_at_image_is_realizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_at_image_is_realizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_ordinal_image_equals_realizable_prefix() {
        macro_rules! check {
            ($ty:ident) => {
                assert_realizable_ordinal_image_equals_realizable_prefix::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_ordinal_pins_format_coordinates_dense_ordinals() {
        // FormatCoordinates::ALL lays the 8 cells in lex order over
        // (format × provenance); the 4 realizable cells sit at full-cube
        // indices 0, 2, 5, 7 (where `provenance == format.provenance()`).
        // axis_ordinal returns those positions in the full-cube slice;
        // realizable_ordinal returns the dense positions 0, 1, 2, 3 in
        // realizable_iter, skipping the interleaved unrealizable cells.
        // The two ordinals differ on cells whose realizable surface is
        // not a prefix of `C::ALL` — pinning that here so a future
        // re-ordering of `FormatCoordinates::ALL` or change to
        // `is_realizable` is caught at the concrete-position level, not
        // only at the abstract bijection level.
        use crate::{FormatCoordinates, FormatProvenance};
        let yaml_figment = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        let toml_figment = FormatCoordinates {
            format: Format::Toml,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        let lisp_shikumi = FormatCoordinates {
            format: Format::Lisp,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        let nix_shikumi = FormatCoordinates {
            format: Format::Nix,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        assert_eq!(
            realizable_ordinal::<FormatCoordinates>(yaml_figment),
            Some(0)
        );
        assert_eq!(
            realizable_ordinal::<FormatCoordinates>(toml_figment),
            Some(1)
        );
        assert_eq!(
            realizable_ordinal::<FormatCoordinates>(lisp_shikumi),
            Some(2)
        );
        assert_eq!(
            realizable_ordinal::<FormatCoordinates>(nix_shikumi),
            Some(3)
        );
        // axis_ordinal pins the full-cube positions on the same cells;
        // the gap (0,2,5,7) versus the dense ordinals (0,1,2,3) is
        // exactly the interleaving the dense embedding collapses.
        assert_eq!(axis_ordinal::<FormatCoordinates>(yaml_figment), 0);
        assert_eq!(axis_ordinal::<FormatCoordinates>(toml_figment), 2);
        assert_eq!(axis_ordinal::<FormatCoordinates>(lisp_shikumi), 5);
        assert_eq!(axis_ordinal::<FormatCoordinates>(nix_shikumi), 7);
        // Unrealizable cells return None on the dense ordinal — pinned
        // for one mid-cube unrealizable cell as a concrete witness.
        let yaml_shikumi = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        assert_eq!(realizable_ordinal::<FormatCoordinates>(yaml_shikumi), None);
        // The full-cube ordinal stays defined on the unrealizable
        // cell (it is in `ALL`), surfacing the partiality difference
        // between axis_ordinal (total over `ALL`) and realizable_ordinal
        // (partial over the realizable surface).
        assert_eq!(axis_ordinal::<FormatCoordinates>(yaml_shikumi), 1);
    }

    // ---- unrealizable_ordinal / unrealizable_at close the dense
    // ---- bijection between the unrealizable complement and
    // ---- 0..unrealizable_count ----
    //
    // The pair (unrealizable_ordinal, unrealizable_at) is the symmetric
    // dual of (realizable_ordinal, realizable_at) on the cube's opposite
    // face — a dense embedding of the consistency-violation complement
    // into the natural-number prefix `0..unrealizable_count::<C>()`.
    // Together the two pairs partition the cube cleanly: every
    // full-cube cell has exactly one defined dense ordinal (realizable
    // or unrealizable, never both), and every in-range dense ordinal
    // on either side lands on a cell of the matching realizability.
    // Four trait-uniform invariants reach every implementor pointwise:
    //
    //   (a) unrealizable_ordinal partiality —
    //       `unrealizable_ordinal(cell).is_some() == !is_realizable(cell)`;
    //   (b) unrealizable_at partiality —
    //       `unrealizable_at(i).is_some() == (i < unrealizable_count)`;
    //   (c) round-trip — `unrealizable_at(unrealizable_ordinal(c).unwrap()) == Some(c)`
    //       for every unrealizable cell, and dually
    //       `unrealizable_at(i).and_then(unrealizable_ordinal) == Some(i)`
    //       for every in-range ordinal;
    //   (d) image unrealizability — every `unrealizable_at(i)` for
    //       in-range `i` returns Some(cell) with is_realizable(cell)
    //       false.
    //
    // A fifth product cube landing picks up all four invariants by
    // adding one line to each helper-bundle test through the
    // `for_each_product_cube!` macro.

    fn assert_unrealizable_ordinal_some_iff_not_is_realizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell of the cube, the dense unrealizable ordinal is
        // Some exactly when the cell is NOT realizable. The ordinal is
        // defined precisely on the unrealizable complement; the
        // realizable surface uniformly returns None. The Boolean dual
        // of `realizable_ordinal_some_iff_is_realizable` — pins that
        // the dense embedding's domain equals the unrealizable
        // complement, not a different subset.
        for cell in axis_iter::<C>() {
            assert_eq!(
                unrealizable_ordinal::<C>(cell).is_some(),
                !ProductCube::is_realizable(cell),
                "cell {cell:?}: unrealizable_ordinal(...).is_some() must equal !is_realizable(...)",
            );
        }
    }

    fn assert_unrealizable_at_some_iff_in_unrealizable_prefix<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i < unrealizable_count::<C>()`,
        // the dense lookup returns Some; for every out-of-range
        // ordinal, it returns None. The boundary check exercises the
        // immediate boundary (`n`, `n+1`), a comfortable margin
        // (`n+7`), and the `usize::MAX` extreme to catch any silent
        // saturation — mirrors `realizable_at_some_iff_in_realizable_prefix`
        // on the opposite face of the cube.
        let n = unrealizable_count::<C>();
        for i in 0..n {
            assert!(
                unrealizable_at::<C>(i).is_some(),
                "unrealizable_at({i}) must be Some for in-range ordinal (n = {n})",
            );
        }
        for i in [n, n + 1, n + 7, usize::MAX] {
            assert!(
                unrealizable_at::<C>(i).is_none(),
                "unrealizable_at({i}) must be None for ordinal >= unrealizable_count (n = {n})",
            );
        }
    }

    fn assert_unrealizable_round_trips_cell_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every unrealizable cell `c`, ordinal-then-lookup recovers
        // the cell: `unrealizable_at(unrealizable_ordinal(c).unwrap())
        // == Some(c)`. The composition `unrealizable_at ∘
        // unrealizable_ordinal` is the identity on the unrealizable
        // complement — the symmetric dual of `realizable_at ∘
        // realizable_ordinal` being the identity on the realizable
        // surface.
        for cell in unrealizable_iter::<C>() {
            let ordinal = unrealizable_ordinal::<C>(cell)
                .expect("unrealizable_iter must yield only ordinal-Some cells");
            assert_eq!(
                unrealizable_at::<C>(ordinal),
                Some(cell),
                "unrealizable_at(unrealizable_ordinal({cell:?}).unwrap()) must equal Some({cell:?})",
            );
        }
    }

    fn assert_unrealizable_round_trips_ordinal_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i < unrealizable_count::<C>()`,
        // lookup-then-ordinal recovers the ordinal:
        // `unrealizable_at(i).and_then(unrealizable_ordinal) ==
        // Some(i)`. The composition `unrealizable_ordinal ∘
        // unrealizable_at` is the identity on the in-range prefix —
        // the symmetric dual of `realizable_ordinal ∘ realizable_at`
        // being the identity on `0..realizable_count::<C>()`.
        for i in 0..unrealizable_count::<C>() {
            let recovered = unrealizable_at::<C>(i).and_then(unrealizable_ordinal::<C>);
            assert_eq!(
                recovered,
                Some(i),
                "unrealizable_at({i}).and_then(unrealizable_ordinal) must equal Some({i})",
            );
        }
    }

    fn assert_unrealizable_at_image_is_unrealizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range ordinal `i`, the dense lookup lands on an
        // unrealizable cell: `unrealizable_at(i).map(is_realizable) ==
        // Some(false)`. Pins that the forward map's image is the
        // unrealizable complement, not the full cube `ALL`. The
        // Boolean dual of `realizable_at_image_is_realizable` — stated
        // separately from the partiality invariant so a future helper
        // change that accidentally exposes realizable cells in the
        // in-range prefix would fail here as well as in the round-trip
        // law.
        for i in 0..unrealizable_count::<C>() {
            let cell = unrealizable_at::<C>(i)
                .expect("in-range unrealizable_at must yield Some by partiality invariant");
            assert!(
                !ProductCube::is_realizable(cell),
                "unrealizable_at({i}) = {cell:?} must NOT satisfy is_realizable",
            );
        }
    }

    fn assert_unrealizable_ordinal_image_equals_unrealizable_prefix<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // The ordinal image over the unrealizable complement equals
        // `0..unrealizable_count::<C>()` as a set. Equivalent to the
        // injectivity statement: distinct unrealizable cells land at
        // distinct ordinals, and the dense embedding is a bijection
        // (not merely an injection) onto the prefix. Pins that
        // `unrealizable_iter::<C>()` carries no duplicates — the cube-
        // level dual of the no-duplicates invariant on `A::ALL` and
        // the symmetric dual of `realizable_ordinal_image_equals_realizable_prefix`
        // on the opposite face.
        use std::collections::HashSet;
        let ordinals: HashSet<usize> = unrealizable_iter::<C>()
            .map(|c| {
                unrealizable_ordinal::<C>(c)
                    .expect("unrealizable_iter must yield only ordinal-Some cells")
            })
            .collect();
        let expected: HashSet<usize> = (0..unrealizable_count::<C>()).collect();
        assert_eq!(
            ordinals, expected,
            "unrealizable_ordinal image over unrealizable_iter must equal 0..unrealizable_count as a set",
        );
    }

    #[test]
    fn unrealizable_ordinal_some_iff_not_is_realizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_ordinal_some_iff_not_is_realizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_at_some_iff_in_unrealizable_prefix() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_at_some_iff_in_unrealizable_prefix::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_round_trips_cell_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_round_trips_cell_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_round_trips_ordinal_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_round_trips_ordinal_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_at_image_is_unrealizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_at_image_is_unrealizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_ordinal_image_equals_unrealizable_prefix() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unrealizable_ordinal_image_equals_unrealizable_prefix::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn realizable_and_unrealizable_ordinals_partition_cube() {
        // The two dense-ordinal pairs (realizable_ordinal, realizable_at)
        // and (unrealizable_ordinal, unrealizable_at) close the cube's
        // surface algebra symmetrically: every full-cube cell has
        // exactly one defined dense ordinal — `realizable_ordinal` is
        // Some on the realizable surface and None on the unrealizable
        // complement, while `unrealizable_ordinal` is None on the
        // realizable surface and Some on the unrealizable complement.
        // The two `Option<usize>` values are XOR-complementary on every
        // cell of every cube. Pins the symmetric-partition discipline
        // at the per-cell level — a future helper change that flipped
        // either ordinal's partiality or that double-counted any cell
        // would fail here as well as in the per-half tests.
        fn assert_xor_complementary<C>()
        where
            C: ProductCube + std::fmt::Debug,
        {
            for cell in axis_iter::<C>() {
                let r = realizable_ordinal::<C>(cell).is_some();
                let u = unrealizable_ordinal::<C>(cell).is_some();
                assert!(
                    r ^ u,
                    "cell {cell:?}: exactly one of realizable_ordinal / unrealizable_ordinal \
                     must be Some (got realizable={r}, unrealizable={u})",
                );
            }
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_xor_complementary::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn unrealizable_ordinal_pins_format_coordinates_dense_ordinals() {
        // FormatCoordinates::ALL lays the 8 cells in lex order over
        // (format × provenance); the 4 unrealizable cells sit at
        // full-cube indices 1, 3, 4, 6 (the ones where
        // `provenance != format.provenance()`).
        // axis_ordinal returns those positions in the full-cube slice;
        // unrealizable_ordinal returns the dense positions 0, 1, 2, 3
        // in unrealizable_iter, skipping the interleaved realizable
        // cells. Symmetric concrete-position pin to the realizable
        // counterpart above — caught at the per-position level if a
        // future re-ordering of `FormatCoordinates::ALL` or change to
        // `is_realizable` shifts the unrealizable interleaving.
        use crate::{FormatCoordinates, FormatProvenance};
        let yaml_shikumi = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        let toml_shikumi = FormatCoordinates {
            format: Format::Toml,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        let lisp_figment = FormatCoordinates {
            format: Format::Lisp,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        let nix_figment = FormatCoordinates {
            format: Format::Nix,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        assert_eq!(
            unrealizable_ordinal::<FormatCoordinates>(yaml_shikumi),
            Some(0),
        );
        assert_eq!(
            unrealizable_ordinal::<FormatCoordinates>(toml_shikumi),
            Some(1),
        );
        assert_eq!(
            unrealizable_ordinal::<FormatCoordinates>(lisp_figment),
            Some(2),
        );
        assert_eq!(
            unrealizable_ordinal::<FormatCoordinates>(nix_figment),
            Some(3),
        );
        // axis_ordinal pins the full-cube positions on the same cells;
        // the gap (1,3,4,6) versus the dense unrealizable ordinals
        // (0,1,2,3) is exactly the interleaving the dense embedding
        // collapses on the opposite face.
        assert_eq!(axis_ordinal::<FormatCoordinates>(yaml_shikumi), 1);
        assert_eq!(axis_ordinal::<FormatCoordinates>(toml_shikumi), 3);
        assert_eq!(axis_ordinal::<FormatCoordinates>(lisp_figment), 4);
        assert_eq!(axis_ordinal::<FormatCoordinates>(nix_figment), 6);
        // Realizable cells return None on the unrealizable ordinal —
        // pinned for one mid-cube realizable cell as the symmetric
        // dual of the realizable-side partiality witness.
        let yaml_figment = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        assert_eq!(
            unrealizable_ordinal::<FormatCoordinates>(yaml_figment),
            None,
        );
    }

    // ---- PartitionOrdinal fuses (realizable_ordinal, unrealizable_ordinal)
    // ---- into a single typed witness over the cube's full surface ----
    //
    // The pair (partition_ordinal, at_partition_ordinal) is the typed-
    // disjoint-union counterpart to (axis_ordinal, axis_at): where the
    // axis-level pair carries one dense `usize` over the full cube
    // `ALL` slice (interleaving realizable and unrealizable cells),
    // PartitionOrdinal carries a typed variant tag plus the dense
    // ordinal restricted to the variant's face. Every cell of every
    // cube has a defined PartitionOrdinal (totality), the variant
    // agrees with is_realizable pointwise (variant agreement), and
    // the inner usize equals the corresponding dense-half ordinal
    // pointwise (inner agreement). Four trait-uniform invariants reach
    // every implementor pointwise:
    //
    //   (a) variant agreement — `partition_ordinal(cell)` is
    //       Realizable(_) iff is_realizable(cell);
    //   (b) inner-ordinal agreement — the inner usize on each variant
    //       equals the corresponding realizable_/unrealizable_ordinal
    //       pointwise;
    //   (c) round-trip from the cell side —
    //       at_partition_ordinal(partition_ordinal(cell)) == Some(cell)
    //       for every cell of the cube;
    //   (d) round-trip from the partition-ordinal side —
    //       at_partition_ordinal(p).map(partition_ordinal) == Some(p)
    //       for every in-range p (Realizable(i) with i < realizable_count
    //       or Unrealizable(i) with i < unrealizable_count), plus the
    //       partiality boundary (out-of-range p returns None on the
    //       forward map).
    //
    // A fifth product cube landing picks up all four invariants by
    // adding one line to each helper-bundle test through the
    // `for_each_product_cube!` macro.

    fn assert_partition_ordinal_variant_agrees_with_is_realizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell, the PartitionOrdinal variant agrees with the
        // realizability predicate: Realizable iff is_realizable, dually
        // Unrealizable iff !is_realizable. Pins the typed-partition
        // discipline: the variant tag and the predicate are in lockstep
        // pointwise, no cell can be tagged with the wrong face.
        for cell in axis_iter::<C>() {
            match partition_ordinal::<C>(cell) {
                PartitionOrdinal::Realizable(_) => assert!(
                    ProductCube::is_realizable(cell),
                    "cell {cell:?}: partition_ordinal returned Realizable but is_realizable is false",
                ),
                PartitionOrdinal::Unrealizable(_) => assert!(
                    !ProductCube::is_realizable(cell),
                    "cell {cell:?}: partition_ordinal returned Unrealizable but is_realizable is true",
                ),
            }
        }
    }

    fn assert_partition_ordinal_inner_matches_dense_ordinal<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell, the inner usize on each PartitionOrdinal
        // variant equals the corresponding dense-half ordinal pointwise.
        // Pins that the fused helper produces the same number the
        // dense-half helpers do — no silent off-by-one or face-swap
        // between the constituent ordinals and the merged encoding.
        for cell in axis_iter::<C>() {
            match partition_ordinal::<C>(cell) {
                PartitionOrdinal::Realizable(i) => assert_eq!(
                    Some(i),
                    realizable_ordinal::<C>(cell),
                    "cell {cell:?}: PartitionOrdinal::Realizable({i}) must equal realizable_ordinal",
                ),
                PartitionOrdinal::Unrealizable(i) => assert_eq!(
                    Some(i),
                    unrealizable_ordinal::<C>(cell),
                    "cell {cell:?}: PartitionOrdinal::Unrealizable({i}) must equal unrealizable_ordinal",
                ),
            }
        }
    }

    fn assert_partition_ordinal_round_trips_cell_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell of the cube, partition_ordinal-then-
        // at_partition_ordinal recovers the cell. The composition
        // `at_partition_ordinal ∘ partition_ordinal` is the identity on
        // `C::ALL` — the typed-disjoint-union analog of `axis_at ∘
        // axis_ordinal` being the identity on A. Reaches every cell of
        // every cube (not just the realizable surface or the
        // unrealizable complement separately, but the full cube
        // uniformly), so a fifth cube landing inherits totality with
        // one line in `for_each_product_cube!`.
        for cell in axis_iter::<C>() {
            let p = partition_ordinal::<C>(cell);
            assert_eq!(
                at_partition_ordinal::<C>(p),
                Some(cell),
                "cell {cell:?}: at_partition_ordinal(partition_ordinal(cell)) must equal Some(cell)",
            );
        }
    }

    fn assert_partition_ordinal_round_trips_ordinal_side<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range PartitionOrdinal, at_partition_ordinal-
        // then-partition_ordinal recovers the partition ordinal. The
        // composition `partition_ordinal ∘ at_partition_ordinal` is the
        // identity on the in-range domain — covering Realizable(i) with
        // i < realizable_count AND Unrealizable(i) with i <
        // unrealizable_count, exercising both faces of the bijection at
        // one site. Out-of-range partition ordinals are checked
        // separately in the partiality test.
        for i in 0..realizable_count::<C>() {
            let p = PartitionOrdinal::Realizable(i);
            let recovered = at_partition_ordinal::<C>(p).map(partition_ordinal::<C>);
            assert_eq!(
                recovered,
                Some(p),
                "at_partition_ordinal(Realizable({i})).map(partition_ordinal) must equal Some(Realizable({i}))",
            );
        }
        for i in 0..unrealizable_count::<C>() {
            let p = PartitionOrdinal::Unrealizable(i);
            let recovered = at_partition_ordinal::<C>(p).map(partition_ordinal::<C>);
            assert_eq!(
                recovered,
                Some(p),
                "at_partition_ordinal(Unrealizable({i})).map(partition_ordinal) must equal Some(Unrealizable({i}))",
            );
        }
    }

    fn assert_at_partition_ordinal_none_on_out_of_range<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every out-of-range PartitionOrdinal (Realizable(i) with
        // i >= realizable_count, or Unrealizable(i) with i >=
        // unrealizable_count), the forward map returns None. The
        // boundary check exercises the immediate boundary (n, n+1), a
        // comfortable margin (n+7), and the `usize::MAX` extreme to
        // catch any silent saturation on either face. Pins that the
        // forward map is defined precisely on each variant's restricted
        // prefix and the Option return surfaces the partiality at the
        // type level rather than by convention.
        let nr = realizable_count::<C>();
        for i in [nr, nr + 1, nr + 7, usize::MAX] {
            assert!(
                at_partition_ordinal::<C>(PartitionOrdinal::Realizable(i)).is_none(),
                "at_partition_ordinal(Realizable({i})) must be None for ordinal >= realizable_count (n = {nr})",
            );
        }
        let nu = unrealizable_count::<C>();
        for i in [nu, nu + 1, nu + 7, usize::MAX] {
            assert!(
                at_partition_ordinal::<C>(PartitionOrdinal::Unrealizable(i)).is_none(),
                "at_partition_ordinal(Unrealizable({i})) must be None for ordinal >= unrealizable_count (n = {nu})",
            );
        }
    }

    fn assert_at_partition_ordinal_image_matches_variant_tag<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every in-range PartitionOrdinal, the cell the forward map
        // lands on has realizability matching the variant tag:
        // Realizable(i) lands on an is_realizable=true cell;
        // Unrealizable(i) lands on an is_realizable=false cell. Pins
        // that the variant tag and the cell's realizability are in
        // lockstep — the typed-partition encoding cannot smuggle an
        // unrealizable cell behind a Realizable tag, nor vice versa.
        for i in 0..realizable_count::<C>() {
            let cell = at_partition_ordinal::<C>(PartitionOrdinal::Realizable(i))
                .expect("in-range Realizable(i) must yield Some by partiality invariant");
            assert!(
                ProductCube::is_realizable(cell),
                "at_partition_ordinal(Realizable({i})) = {cell:?} must satisfy is_realizable",
            );
        }
        for i in 0..unrealizable_count::<C>() {
            let cell = at_partition_ordinal::<C>(PartitionOrdinal::Unrealizable(i))
                .expect("in-range Unrealizable(i) must yield Some by partiality invariant");
            assert!(
                !ProductCube::is_realizable(cell),
                "at_partition_ordinal(Unrealizable({i})) = {cell:?} must NOT satisfy is_realizable",
            );
        }
    }

    #[test]
    fn partition_ordinal_variant_agrees_with_is_realizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_variant_agrees_with_is_realizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn partition_ordinal_inner_matches_dense_ordinal() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_inner_matches_dense_ordinal::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn partition_ordinal_round_trips_cell_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_round_trips_cell_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn partition_ordinal_round_trips_ordinal_side() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_round_trips_ordinal_side::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn at_partition_ordinal_none_on_out_of_range() {
        macro_rules! check {
            ($ty:ident) => {
                assert_at_partition_ordinal_none_on_out_of_range::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn at_partition_ordinal_image_matches_variant_tag() {
        macro_rules! check {
            ($ty:ident) => {
                assert_at_partition_ordinal_image_matches_variant_tag::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    #[test]
    fn partition_ordinal_pins_format_coordinates_dense_ordinals() {
        // Concrete-position pin on FormatCoordinates: the 8 cells of
        // ALL split into 4 realizable (at full-cube ordinals 0, 2, 5,
        // 7; dense realizable ordinals 0, 1, 2, 3) and 4 unrealizable
        // (at full-cube ordinals 1, 3, 4, 6; dense unrealizable
        // ordinals 0, 1, 2, 3). The PartitionOrdinal encoding pins
        // each cell's variant tag and dense ordinal in one helper —
        // the symmetric concrete-position pin to the realizable and
        // unrealizable counterparts above, but on the merged typed-
        // disjoint-union encoding rather than the per-face Option<usize>
        // halves.
        use crate::{FormatCoordinates, FormatProvenance};
        let yaml_figment = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        let yaml_shikumi = FormatCoordinates {
            format: Format::Yaml,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        let nix_shikumi = FormatCoordinates {
            format: Format::Nix,
            provenance: FormatProvenance::ShikumiBuilt,
        };
        let nix_figment = FormatCoordinates {
            format: Format::Nix,
            provenance: FormatProvenance::FigmentBuiltin,
        };
        // Realizable side — variant tag matches is_realizable.
        assert_eq!(
            partition_ordinal::<FormatCoordinates>(yaml_figment),
            PartitionOrdinal::Realizable(0),
        );
        assert_eq!(
            partition_ordinal::<FormatCoordinates>(nix_shikumi),
            PartitionOrdinal::Realizable(3),
        );
        // Unrealizable side — variant tag matches !is_realizable.
        assert_eq!(
            partition_ordinal::<FormatCoordinates>(yaml_shikumi),
            PartitionOrdinal::Unrealizable(0),
        );
        assert_eq!(
            partition_ordinal::<FormatCoordinates>(nix_figment),
            PartitionOrdinal::Unrealizable(3),
        );
        // Round-trip witness on one cell from each face.
        assert_eq!(
            at_partition_ordinal::<FormatCoordinates>(PartitionOrdinal::Realizable(0)),
            Some(yaml_figment),
        );
        assert_eq!(
            at_partition_ordinal::<FormatCoordinates>(PartitionOrdinal::Unrealizable(3)),
            Some(nix_figment),
        );
    }

    // ---- PartitionFace algebra and PartitionOrdinal projections ----
    //
    // `PartitionFace` is the tenth closed-axis primitive — the
    // variant-tag projection of `PartitionOrdinal`. Three invariants
    // pin its algebra:
    //
    //   (a) `PartitionFace::ALL = [Realizable, Unrealizable]` (two
    //       entries, in declaration order; mirrored by the trait `ALL`
    //       via the `partition_face_trait_all_matches_inherent_all`
    //       test above);
    //   (b) `PartitionFace::is_realizable` matches the variant pointwise
    //       on the two-element axis;
    //   (c) trait-uniform over every cube: for every cell,
    //       `partition_ordinal::<C>(cell).face().is_realizable() ==
    //       ProductCube::is_realizable(cell)`. The face tag and the
    //       cube predicate are in lockstep on every cell of every
    //       cube — pinned by the helper through `for_each_product_cube!`.
    //
    // `PartitionOrdinal::face_ordinal` is the dual projection: forgets
    // the face tag, recovers the inner dense ordinal. A round-trip
    // invariant — `PartitionOrdinal::Realizable(i).face_ordinal() == i`
    // and dually for `Unrealizable` — is pinned by the synthetic
    // round-trip helper across every in-range dense ordinal on every
    // face of every cube via `for_each_product_cube!`.

    #[test]
    fn partition_face_all_has_two_entries() {
        // Pin the typescape's tenth axis primitive's cardinality at
        // two: Realizable + Unrealizable, in declaration order. A
        // third face landing (which is not anticipated — the
        // partition is XOR-complementary by construction) would
        // require extending `PartitionOrdinal` with a matching variant
        // and `ProductCube::is_realizable` from `bool` to a ternary
        // predicate, both of which are structural changes that fail
        // this assertion first.
        assert_eq!(PartitionFace::ALL.len(), 2);
        assert_eq!(PartitionFace::ALL[0], PartitionFace::Realizable);
        assert_eq!(PartitionFace::ALL[1], PartitionFace::Unrealizable);
    }

    #[test]
    fn partition_face_is_realizable_matches_variant() {
        // `PartitionFace::is_realizable` returns `true` exactly on
        // `Realizable`. The face-level predicate decouples "which half"
        // from "which cube" — a consumer that carries a face tag
        // without the cube type parameter classifies it through this
        // method without re-pattern-matching.
        assert!(PartitionFace::Realizable.is_realizable());
        assert!(!PartitionFace::Unrealizable.is_realizable());
    }

    fn assert_partition_ordinal_face_agrees_with_is_realizable<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // The face tag projected from `partition_ordinal(cell)` is in
        // lockstep with `ProductCube::is_realizable(cell)` on every
        // cell of every cube. The cube predicate, the variant tag, and
        // `PartitionFace::is_realizable` are three readings of the same
        // bit — pinned pointwise here through one trait-uniform
        // helper.
        for cell in <C as ClosedAxis>::ALL.iter().copied() {
            let face = partition_ordinal::<C>(cell).face();
            assert_eq!(
                face.is_realizable(),
                ProductCube::is_realizable(cell),
                "cell {cell:?}: partition_ordinal(cell).face().is_realizable() must equal \
                 ProductCube::is_realizable(cell)",
            );
            // Face tag and variant agree at the construction level:
            // realizable cells produce a `Realizable` tag, unrealizable
            // cells produce an `Unrealizable` tag.
            let expected = if ProductCube::is_realizable(cell) {
                PartitionFace::Realizable
            } else {
                PartitionFace::Unrealizable
            };
            assert_eq!(
                face, expected,
                "cell {cell:?}: face tag must match is_realizable-derived expected face",
            );
        }
    }

    #[test]
    fn partition_ordinal_face_agrees_with_is_realizable() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_face_agrees_with_is_realizable::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    fn assert_partition_ordinal_face_ordinal_round_trips<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // Round-trip on the dense-ordinal projection: for every
        // in-range dense ordinal on each face, the synthetic
        // `PartitionOrdinal` recovers the same dense ordinal through
        // `face_ordinal`. The face-tag projection forgets the inner
        // ordinal; the face-ordinal projection forgets the face tag;
        // together they are the two halves of the typed disjoint-union
        // encoding.
        for i in 0..realizable_count::<C>() {
            let p = PartitionOrdinal::Realizable(i);
            assert_eq!(
                p.face(),
                PartitionFace::Realizable,
                "Realizable({i}): face must be Realizable",
            );
            assert_eq!(
                p.face_ordinal(),
                i,
                "Realizable({i}): face_ordinal must be {i}"
            );
        }
        for i in 0..unrealizable_count::<C>() {
            let p = PartitionOrdinal::Unrealizable(i);
            assert_eq!(
                p.face(),
                PartitionFace::Unrealizable,
                "Unrealizable({i}): face must be Unrealizable",
            );
            assert_eq!(
                p.face_ordinal(),
                i,
                "Unrealizable({i}): face_ordinal must be {i}",
            );
        }
    }

    #[test]
    fn partition_ordinal_face_ordinal_round_trips_across_every_cube() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_face_ordinal_round_trips::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    fn assert_partition_ordinal_recomposes_from_face_and_ordinal<C>()
    where
        C: ProductCube + std::fmt::Debug,
    {
        // For every cell of every cube, the typed-disjoint-union
        // encoding (`partition_ordinal(cell)`) is reconstructible from
        // its two projections (`face` and `face_ordinal`). The two
        // projections form a faithful encoding: no information loss
        // when the face tag and the dense inner ordinal are carried
        // separately, then recombined through the matching variant
        // constructor.
        for cell in <C as ClosedAxis>::ALL.iter().copied() {
            let p = partition_ordinal::<C>(cell);
            let face = p.face();
            let ordinal = p.face_ordinal();
            let recombined = match face {
                PartitionFace::Realizable => PartitionOrdinal::Realizable(ordinal),
                PartitionFace::Unrealizable => PartitionOrdinal::Unrealizable(ordinal),
            };
            assert_eq!(
                recombined, p,
                "cell {cell:?}: recombining (face, face_ordinal) must equal partition_ordinal(cell)",
            );
        }
    }

    #[test]
    fn partition_ordinal_recomposes_from_face_and_ordinal_across_every_cube() {
        macro_rules! check {
            ($ty:ident) => {
                assert_partition_ordinal_recomposes_from_face_and_ordinal::<$ty>();
            };
        }
        for_each_product_cube!(check);
    }

    // ---- PartialInverseCube forward/invert bijection invariants ----
    //
    // The (forward, invert) pair closes a bijection on the recognized
    // half of the cube. Three trait-uniform invariants reach every
    // implementor pointwise:
    //
    //   (a) forward always lands on a realizable cell;
    //   (b) invert(forward(image)) == Some(image) for every image
    //       (round-trip from the image side);
    //   (c) forward(invert(cell).unwrap()) == cell for every realizable
    //       cell (round-trip from the cube side).
    //
    // Equivalently, the forward image of `Image::ALL` under `forward`
    // equals `realizable_iter::<Self>()` as a set — pinned by
    // `forward_image_of_image_all_equals_realizable_iter`. A third
    // PartialInverseCube implementor picks up all three invariants by
    // adding one call to each helper at the trait-uniform site.

    fn assert_forward_always_lands_on_realizable<C>()
    where
        C: PartialInverseCube + std::fmt::Debug,
    {
        for image in <C::Image as ClosedAxis>::ALL.iter().copied() {
            let cell = C::forward(image);
            assert!(
                ProductCube::is_realizable(cell),
                "image {image:?}: forward must land on a realizable cell of the cube",
            );
        }
    }

    fn assert_round_trip_invert_after_forward<C>()
    where
        C: PartialInverseCube + std::fmt::Debug,
    {
        for image in <C::Image as ClosedAxis>::ALL.iter().copied() {
            let recovered = C::forward(image).invert();
            assert_eq!(
                recovered,
                Some(image),
                "image {image:?}: invert(forward(image)) must equal Some(image)",
            );
        }
    }

    fn assert_round_trip_forward_after_invert<C>()
    where
        C: PartialInverseCube + std::fmt::Debug,
    {
        for cell in realizable_iter::<C>() {
            let image = cell
                .invert()
                .expect("realizable_iter must yield only invert-Some cells");
            let recovered = C::forward(image);
            assert_eq!(
                recovered, cell,
                "cell {cell:?}: forward(invert(cell).unwrap()) must equal cell",
            );
        }
    }

    #[test]
    fn format_coordinates_forward_always_lands_on_realizable_cell() {
        assert_forward_always_lands_on_realizable::<FormatCoordinates>();
    }

    #[test]
    fn attribution_coordinates_forward_always_lands_on_realizable_cell() {
        assert_forward_always_lands_on_realizable::<AttributionCoordinates>();
    }

    #[test]
    fn format_coordinates_round_trip_invert_after_forward() {
        assert_round_trip_invert_after_forward::<FormatCoordinates>();
    }

    #[test]
    fn attribution_coordinates_round_trip_invert_after_forward() {
        assert_round_trip_invert_after_forward::<AttributionCoordinates>();
    }

    #[test]
    fn format_coordinates_round_trip_forward_after_invert() {
        assert_round_trip_forward_after_invert::<FormatCoordinates>();
    }

    #[test]
    fn attribution_coordinates_round_trip_forward_after_invert() {
        assert_round_trip_forward_after_invert::<AttributionCoordinates>();
    }

    #[test]
    fn forward_image_of_image_all_equals_realizable_iter() {
        // Pin that for any PartialInverseCube implementor, the forward
        // image of Image::ALL under `forward` equals `realizable_iter`
        // as a set. This is the trait-uniform statement of the
        // bijection on the recognized half: forward is total onto the
        // realizable cells, and invert is total onto the image. The
        // helper reaches both today's implementors at once; a third
        // implementor picks it up with one new call.
        fn assert_forward_image_equals_realizable<C>()
        where
            C: PartialInverseCube + std::fmt::Debug,
        {
            use std::collections::HashSet;
            let from_forward: HashSet<C> = forward_iter::<C>().collect();
            let from_realizable: HashSet<C> = realizable_iter::<C>().collect();
            assert_eq!(
                from_forward, from_realizable,
                "forward_iter must equal realizable_iter as a set",
            );
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_forward_image_equals_realizable::<$ty>();
            };
        }
        for_each_partial_inverse_cube!(check);
    }

    #[test]
    fn forward_iter_cardinality_equals_image_all_cardinality() {
        // forward_iter::<C>() iterates Image::ALL once with no filter,
        // so its length equals the image axis cardinality. By the
        // bijection invariant, that also equals realizable_count::<C>().
        // Two readings of the same number pinned in lockstep across
        // every implementor.
        fn assert_cardinalities_agree<C: PartialInverseCube>() {
            assert_eq!(
                forward_iter::<C>().count(),
                axis_cardinality::<<C as PartialInverseCube>::Image>(),
            );
            assert_eq!(forward_iter::<C>().count(), realizable_count::<C>());
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_cardinalities_agree::<$ty>();
            };
        }
        for_each_partial_inverse_cube!(check);
    }

    // ---- Implementor-list macro cardinalities ----
    //
    // The three implementor-list macros (`for_each_closed_axis_primitive`,
    // `for_each_product_cube`, `for_each_partial_inverse_cube`) are the
    // single source of truth for the trait-implementor sets in the
    // `for every implementor` tests. Pin today's cardinality on each
    // macro so a future axis primitive or product cube landing forces
    // the macro arm in lockstep — a `for_each_*` invocation that
    // doesn't include a newly-added implementor will fail the
    // cardinality check here, surfacing the discipline violation
    // before any silent dropouts at the trait-uniform test sites.

    #[test]
    fn for_each_closed_axis_primitive_macro_covers_twenty_axes() {
        // Pin that the macro expands to exactly twenty arms — the
        // nineteen pre-existing axis primitives plus
        // [`crate::DiffLineKind`], the `'static` closed three-way
        // classification over the [`crate::DiffLine`] variant space —
        // the removed/added/context peer of [`WatchEventClass`] on the
        // diff-cell axis of [`crate::ConfigDiff`]. A twenty-first axis
        // primitive landing extends the macro in lockstep with the
        // `impl ClosedAxis` declaration; this assertion fails until
        // the macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_closed_axis_primitive!(tally);
        assert_eq!(
            count, 20,
            "for_each_closed_axis_primitive! must expand to twenty arms",
        );
    }

    #[test]
    fn for_each_product_cube_macro_covers_five_cubes() {
        // Pin that the macro expands to exactly five arms — the five
        // product cubes the typescape recognizes today
        // ([`FormatCoordinates`], [`AttributionCoordinates`],
        // [`ErrorLocalizationCoordinates`],
        // [`AttributionSourceKindCoordinates`],
        // [`AttributionNameKindCoordinates`]). A sixth cube landing
        // extends the macro in lockstep with the `impl ProductCube`
        // declaration; this assertion fails until the macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_product_cube!(tally);
        assert_eq!(count, 5, "for_each_product_cube! must expand to five arms");
    }

    #[test]
    fn for_each_partial_inverse_cube_macro_covers_two_cubes() {
        // Pin that the macro expands to exactly two arms — the two
        // cubes whose forward map carries an inverse on the recognized
        // half. A third PartialInverseCube implementor landing extends
        // the macro in lockstep with the `impl PartialInverseCube`
        // declaration; this assertion fails until the macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_partial_inverse_cube!(tally);
        assert_eq!(
            count, 2,
            "for_each_partial_inverse_cube! must expand to two arms",
        );
    }

    #[test]
    fn for_each_closed_axis_implementor_macro_covers_twenty_five_types() {
        // Pin that the superset macro expands to exactly twenty-five
        // arms — the twenty axis primitives plus the five product
        // cubes. A twenty-first axis primitive OR a sixth cube landing
        // extends the composed macro in lockstep through one of its
        // two component macros; this assertion fails until the arm
        // lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_closed_axis_implementor!(tally);
        assert_eq!(
            count, 25,
            "for_each_closed_axis_implementor! must expand to twenty-five arms (20 axes + 5 cubes)",
        );
    }

    #[test]
    fn for_each_closed_axis_implementor_expands_to_distinct_closed_axis_types() {
        // Pin that every type the macro yields satisfies the trait
        // bound it advertises (ClosedAxis) and that the expansion
        // produces no duplicates. Distinctness is pinned via
        // axis_cardinality summed across the implementors — the sum
        // matches the today-pinned 79 only when the macro emits each
        // implementor exactly once. A duplicated arm would
        // double-count one cardinality; a missing arm would
        // under-count. The sum is a checksum over the macro's image.
        fn axis_card<A: ClosedAxis>() -> usize {
            axis_cardinality::<A>()
        }
        let mut total = 0usize;
        macro_rules! add {
            ($ty:ident) => {
                total += axis_card::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(add);
        // 20-axis sum: Format=4, FormatProvenance=2, ConfigSourceKind=3,
        // FigmentSourceKind=3, ShikumiErrorKind=6, FieldPathLocalization=3,
        // AttributionRule=5, AttributionConfidence=2, AttributionAxis=2,
        // PartitionFace=2, ConfigTierKind=4, WatchEventClass=3,
        // FigmentNameTagKind=2, EnvMetadataTagKind=2, SecretBackendKind=8,
        // SecretRefShape=2, SecretOperation=6, SecretErrorKind=5,
        // SecretClientKind=7, DiffLineKind=3 → 74.
        // 5-cube sum: FormatCoordinates=8, AttributionCoordinates=12,
        // ErrorLocalizationCoordinates=18, AttributionSourceKindCoordinates=9,
        // AttributionNameKindCoordinates=6 → 53. Grand total 74+53 = 127.
        assert_eq!(
            total, 127,
            "macro must emit each implementor exactly once \
             (today's axis_cardinality checksum is 127)",
        );
    }

    // ---- ClosedAxisLabel — trait-uniform invariants over every implementor ----
    //
    // The five invariants the labeling discipline pins (round-trip law,
    // case insensitivity, distinctness, non-emptiness, empty-string
    // rejection) each appear once below, with the per-implementor loop
    // dispatched through `for_each_closed_axis_label_implementor!`. A
    // third [`ClosedAxisLabel`] implementor landing extends every
    // invariant in lockstep by adding one arm to the macro — no
    // per-test edits required.

    fn assert_round_trips_through_canonical_str<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Round-trip law: `L::from_canonical_str(v.as_str()) == Some(v)`
        // for every `v: L`. The default `from_canonical_str` impl
        // satisfies this by construction over `ClosedAxis::ALL`;
        // implementors that override `from_canonical_str` are still
        // pinned here. Iterates `L::ALL` (every value of the axis) and
        // re-parses the rendered label, asserting the parse recovers
        // the original value pointwise.
        for value in L::ALL.iter().copied() {
            let rendered = value.as_str();
            let parsed = <L as ClosedAxisLabel>::from_canonical_str(rendered);
            assert_eq!(
                parsed,
                Some(value),
                "round-trip failed for {value:?}: as_str={rendered:?} did not parse back to Some({value:?})",
            );
        }
    }

    fn assert_round_trips_case_insensitively<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Case-insensitivity law: the rendered label uppercased parses
        // back to the same value. The default `from_canonical_str` uses
        // `eq_ignore_ascii_case`, so the law is structural on the
        // default impl; the pin re-states it once across every
        // implementor so override impls (none today) still satisfy it.
        for value in L::ALL.iter().copied() {
            let rendered_upper = value.as_str().to_ascii_uppercase();
            let parsed = <L as ClosedAxisLabel>::from_canonical_str(&rendered_upper);
            assert_eq!(
                parsed,
                Some(value),
                "case-insensitive round-trip failed for {value:?}: uppercase {rendered_upper:?} did not parse back",
            );
        }
    }

    fn assert_labels_pairwise_distinct<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Distinctness law: `a.as_str() != b.as_str()` for `a != b: L`.
        // Pinned via a quadratic walk over `L::ALL × L::ALL` —
        // cardinalities are tiny (≤6 today), so the quadratic cost is
        // negligible.
        let labels: Vec<(L, &'static str)> =
            L::ALL.iter().copied().map(|v| (v, v.as_str())).collect();
        for (i, (a, label_a)) in labels.iter().enumerate() {
            for (b, label_b) in labels.iter().skip(i + 1) {
                assert_ne!(
                    label_a, label_b,
                    "distinct values {a:?} and {b:?} must have distinct labels (both produced {label_a:?})",
                );
            }
        }
    }

    fn assert_labels_nonempty<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Non-emptiness law: `!v.as_str().is_empty()` for every `v: L`.
        // Composes with the empty-parse-rejection law: the empty
        // string can never collide with a canonical label.
        for value in L::ALL.iter().copied() {
            let rendered = value.as_str();
            assert!(
                !rendered.is_empty(),
                "as_str must never return empty for {value:?}",
            );
        }
    }

    fn assert_rejects_empty_string<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Empty-parse-rejection law: `L::from_canonical_str("") == None`
        // for every implementor. Composes with non-emptiness above:
        // because no canonical label is empty, the parse rejects "" by
        // construction. The pin holds the trait default impl honest
        // (and any override) at one site.
        assert_eq!(
            <L as ClosedAxisLabel>::from_canonical_str(""),
            None,
            "from_canonical_str(\"\") must be None",
        );
    }

    #[test]
    fn closed_axis_label_round_trips_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_round_trips_through_canonical_str::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn closed_axis_label_round_trips_case_insensitively_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_round_trips_case_insensitively::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn closed_axis_label_as_str_distinct_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_labels_pairwise_distinct::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn closed_axis_label_as_str_nonempty_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_labels_nonempty::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn closed_axis_label_rejects_empty_string_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_rejects_empty_string::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn for_each_closed_axis_label_implementor_macro_covers_twenty_implementors() {
        // Pin that the macro expands to exactly twenty arms — the
        // nineteen pre-existing [`ClosedAxisLabel`] implementors plus
        // [`crate::DiffLineKind`], the removed/added/context classification
        // over the [`crate::DiffLine`] variant space (labels
        // `"removed"` / `"added"` / `"context"`). A twenty-first
        // implementor landing extends the macro in lockstep with the
        // `impl ClosedAxisLabel` declaration; this assertion fails
        // until the macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_closed_axis_label_implementor!(tally);
        assert_eq!(
            count, 20,
            "for_each_closed_axis_label_implementor! must expand to twenty arms",
        );
    }

    #[test]
    fn for_each_closed_axis_label_implementor_expands_to_distinct_label_axes() {
        // Pin that every type the macro yields satisfies the trait
        // bound it advertises (ClosedAxisLabel) and that the expansion
        // produces no duplicates. Distinctness is pinned via the same
        // axis_cardinality checksum pattern used for the superset
        // ClosedAxis macro:
        // PartitionFace=2 + ConfigTierKind=4 + Format=4 + FormatProvenance=2
        // + ConfigSourceKind=3 + FigmentSourceKind=3 + AttributionConfidence=2
        // + AttributionAxis=2 + ShikumiErrorKind=6 + FieldPathLocalization=3
        // + AttributionRule=5 + WatchEventClass=3 = 39. A duplicated
        // arm would double-count one cardinality; a missing arm would
        // under-count.
        fn axis_card<L: ClosedAxisLabel>() -> usize {
            axis_cardinality::<L>()
        }
        let mut total = 0usize;
        macro_rules! add {
            ($ty:ident) => {
                total += axis_card::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(add);
        assert_eq!(
            total, 74,
            "macro must emit each ClosedAxisLabel implementor exactly once \
             (today's axis_cardinality checksum is 74: \
             PartitionFace=2 + ConfigTierKind=4 + Format=4 + FormatProvenance=2 \
             + ConfigSourceKind=3 + FigmentSourceKind=3 + AttributionConfidence=2 \
             + AttributionAxis=2 + ShikumiErrorKind=6 + FieldPathLocalization=3 \
             + AttributionRule=5 + WatchEventClass=3 + FigmentNameTagKind=2 \
             + EnvMetadataTagKind=2 + SecretBackendKind=8 + SecretRefShape=2 \
             + SecretOperation=6 + SecretErrorKind=5 + SecretClientKind=7 \
             + DiffLineKind=3)",
        );
    }

    #[test]
    fn partition_face_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on PartitionFace::as_str: the two
        // canonical labels at one site. The trait-uniform round-trip
        // test above pins the labels equal pairwise under
        // from_canonical_str, but this test pins the literal string
        // values themselves so a future rename (e.g. capitalizing
        // "Realizable") would fail here before drifting through the
        // round-trip law.
        assert_eq!(PartitionFace::Realizable.as_str(), "realizable");
        assert_eq!(PartitionFace::Unrealizable.as_str(), "unrealizable");
    }

    // ---- axis_label / axis_from_label — free-fn mirrors of the
    // ClosedAxisLabel trait methods ----
    //
    // The two free functions add no behavior over the trait methods; the
    // tests below pin that they agree with the trait methods pointwise
    // (so a future divergence is caught at one site) and re-state the
    // round-trip law at the free-function layer. Each test dispatches
    // through `for_each_closed_axis_label_implementor!`, so a future
    // implementor inherits all three by adding one macro arm.

    fn assert_axis_label_free_fn_matches_trait<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // `axis_label(v) == v.as_str()` for every `v: L`.
        for value in L::ALL.iter().copied() {
            assert_eq!(
                axis_label(value),
                value.as_str(),
                "axis_label free fn must agree with ClosedAxisLabel::as_str for {value:?}",
            );
        }
    }

    fn assert_axis_from_label_free_fn_matches_trait<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // `axis_from_label::<L>(s) == L::from_canonical_str(s)` over the
        // canonical labels, their uppercase form (the case-insensitive
        // path), and two guaranteed-miss probes (the empty string and a
        // sentinel that no canonical label can equal).
        for value in L::ALL.iter().copied() {
            let rendered = value.as_str();
            assert_eq!(
                axis_from_label::<L>(rendered),
                <L as ClosedAxisLabel>::from_canonical_str(rendered),
                "axis_from_label must agree with from_canonical_str on {rendered:?}",
            );
            let upper = rendered.to_ascii_uppercase();
            assert_eq!(
                axis_from_label::<L>(&upper),
                <L as ClosedAxisLabel>::from_canonical_str(&upper),
                "axis_from_label must agree with from_canonical_str on {upper:?}",
            );
        }
        for probe in ["", "\u{0}not-a-canonical-label\u{0}"] {
            assert_eq!(
                axis_from_label::<L>(probe),
                <L as ClosedAxisLabel>::from_canonical_str(probe),
                "axis_from_label must agree with from_canonical_str on non-label {probe:?}",
            );
        }
    }

    fn assert_axis_label_free_fn_round_trips<L>()
    where
        L: ClosedAxisLabel + std::fmt::Debug,
    {
        // Free-function form of the round-trip law:
        // `axis_from_label(axis_label(v)) == Some(v)`.
        for value in L::ALL.iter().copied() {
            assert_eq!(
                axis_from_label::<L>(axis_label(value)),
                Some(value),
                "free-fn round-trip failed for {value:?}",
            );
        }
    }

    #[test]
    fn axis_label_free_fn_matches_trait_as_str_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_label_free_fn_matches_trait::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn axis_from_label_free_fn_matches_trait_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_from_label_free_fn_matches_trait::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    #[test]
    fn axis_label_free_fn_round_trips_for_every_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_axis_label_free_fn_round_trips::<$ty>();
            };
        }
        for_each_closed_axis_label_implementor!(check);
    }

    // ---- AxisHistogram trait-uniform invariants ----
    //
    // Reach every [`ClosedAxis`] implementor — the twenty axis primitives
    // and the five product cubes — through
    // [`for_each_closed_axis_implementor`] so the per-axis histogram
    // primitive's laws hold uniformly without per-axis test duplication.

    fn assert_empty_histogram_is_zero_on_every_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.total(),
            0,
            "empty histogram total must be 0 for axis {}",
            std::any::type_name::<A>(),
        );
        assert!(
            hist.is_empty(),
            "empty histogram is_empty must be true for axis {}",
            std::any::type_name::<A>(),
        );
        for value in axis_iter::<A>() {
            assert_eq!(
                hist.count(value),
                0,
                "empty histogram count must be 0 for cell {value:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
        assert_eq!(
            hist.nonzero().count(),
            0,
            "empty histogram must have no nonzero cells on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_singleton_histogram_pins_observed_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has count=1 on it and count=0
        // elsewhere; total=1, is_empty=false.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(hist.total(), 1, "singleton total must equal 1");
            assert!(!hist.is_empty(), "singleton must not be empty");
            for cell in axis_iter::<A>() {
                let expected = usize::from(cell == observed);
                assert_eq!(
                    hist.count(cell),
                    expected,
                    "singleton on {observed:?}: count({cell:?}) must be {expected}",
                );
            }
            let nonzero: Vec<(A, usize)> = hist.nonzero().collect();
            assert_eq!(nonzero, vec![(observed, 1)], "singleton nonzero set");
        }
    }

    fn assert_all_observed_once_yields_uniform_histogram<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once yields a histogram with
        // every cell at 1 and total = cardinality.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.total(),
            axis_cardinality::<A>(),
            "axis-cover histogram total must equal axis_cardinality on {}",
            std::any::type_name::<A>(),
        );
        for cell in axis_iter::<A>() {
            assert_eq!(hist.count(cell), 1, "every cell must be 1 in axis-cover");
        }
        assert_eq!(
            hist.nonzero().count(),
            axis_cardinality::<A>(),
            "every cell nonzero in axis-cover",
        );
    }

    fn assert_iter_matches_axis_iter_pointwise<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // `iter()` is the dense axis_iter sequence joined with the
        // per-cell counts; the value-side projection equals
        // axis_iter::<A>() pointwise.
        let hist = AxisHistogram::<A>::empty();
        let values_via_hist: Vec<A> = hist.iter().map(|(v, _)| v).collect();
        let values_via_axis: Vec<A> = axis_iter::<A>().collect();
        assert_eq!(
            values_via_hist,
            values_via_axis,
            "AxisHistogram::iter value sequence must equal axis_iter on {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_total_equals_input_length<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // The free-function `axis_histogram` constructor: total over the
        // resulting histogram equals the input iterator length pointwise.
        // Pinned over a synthetic input that observes every cell twice
        // (length 2*cardinality) to cover the bulk-observation path.
        let input: Vec<A> = axis_iter::<A>().chain(axis_iter::<A>()).collect();
        let expected = input.len();
        let hist = axis_histogram(input);
        assert_eq!(
            hist.total(),
            expected,
            "axis_histogram total must equal input length on {}",
            std::any::type_name::<A>(),
        );
        for cell in axis_iter::<A>() {
            assert_eq!(hist.count(cell), 2, "every cell observed twice");
        }
    }

    fn assert_merge_is_pointwise_sum<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Merge law: count(a, lhs.merge(rhs)) == count(a, lhs) + count(a, rhs)
        // for every cell. Identity at empty:
        // lhs.merge(empty) == lhs (cell-wise).
        let lhs: AxisHistogram<A> = axis_iter::<A>().collect();
        let rhs: AxisHistogram<A> = axis_iter::<A>().chain(axis_iter::<A>()).collect();
        let merged = lhs.clone().merge(&rhs);
        for cell in axis_iter::<A>() {
            assert_eq!(
                merged.count(cell),
                lhs.count(cell) + rhs.count(cell),
                "merge must be pointwise sum on {cell:?} for axis {}",
                std::any::type_name::<A>(),
            );
        }
        assert_eq!(
            merged.total(),
            lhs.total() + rhs.total(),
            "merged total equals sum of totals on {}",
            std::any::type_name::<A>(),
        );
        let id_right = lhs.clone().merge(&AxisHistogram::<A>::empty());
        assert_eq!(
            id_right,
            lhs,
            "empty is right identity under merge on {}",
            std::any::type_name::<A>(),
        );
        let id_left = AxisHistogram::<A>::empty().merge(&lhs);
        assert_eq!(
            id_left,
            lhs,
            "empty is left identity under merge on {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_empty_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_empty_histogram_is_zero_on_every_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_singleton_pins_observed_cell_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_singleton_histogram_pins_observed_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_axis_cover_is_uniform_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_all_observed_once_yields_uniform_histogram::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_iter_matches_axis_iter_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_iter_matches_axis_iter_pointwise::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_total_equals_input_length_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_total_equals_input_length::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_merge_is_monoid_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_merge_is_pointwise_sum::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_default_equals_empty() {
        // `Default::default()` and `AxisHistogram::empty()` produce
        // pointwise-equal histograms — the all-zero state on the
        // identity slot of the monoid.
        let via_default: AxisHistogram<DiffLineKind> = AxisHistogram::default();
        let via_empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert_eq!(via_default, via_empty);
    }

    #[test]
    fn axis_histogram_free_fn_equals_collect_for_diff_line_kind() {
        // `axis_histogram(iter)` and `iter.collect::<AxisHistogram<_>>()`
        // produce pointwise-equal histograms. Pinned concretely on
        // [`DiffLineKind`] so the implementation contract is named at
        // one site (the trait-uniform laws above cover every axis).
        let input = [
            DiffLineKind::Removed,
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Context,
        ];
        let via_fn = axis_histogram::<DiffLineKind, _>(input.iter().copied());
        let via_collect: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
        assert_eq!(via_fn, via_collect);
        assert_eq!(via_fn.count(DiffLineKind::Removed), 1);
        assert_eq!(via_fn.count(DiffLineKind::Added), 2);
        assert_eq!(via_fn.count(DiffLineKind::Context), 1);
        assert_eq!(via_fn.total(), 4);
    }

    #[test]
    fn axis_histogram_observe_bumps_only_target_cell() {
        // The single-observation primitive: observe(v) increments
        // count(v) by 1, leaves every other cell unchanged. Composes
        // with merge / FromIterator / axis_histogram as the atomic
        // operation underneath each.
        let mut hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        hist.observe(DiffLineKind::Added);
        assert_eq!(hist.count(DiffLineKind::Added), 1);
        assert_eq!(hist.count(DiffLineKind::Removed), 0);
        assert_eq!(hist.count(DiffLineKind::Context), 0);
        hist.observe(DiffLineKind::Added);
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        hist.observe(DiffLineKind::Removed);
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.count(DiffLineKind::Removed), 1);
        assert_eq!(hist.total(), 3);
    }

    #[test]
    fn axis_histogram_indexes_through_axis_ordinal() {
        // Pin the layout invariant: `hist.count(cell)` reads through
        // `axis_ordinal(cell)` on the internal Vec. Pinned via the
        // axis-cover construction, which lays one count at every
        // ordinal in `0..axis_cardinality::<DiffLineKind>()`.
        let hist: AxisHistogram<DiffLineKind> = axis_iter::<DiffLineKind>().collect();
        for cell in axis_iter::<DiffLineKind>() {
            let ordinal = axis_ordinal::<DiffLineKind>(cell);
            assert!(
                ordinal < axis_cardinality::<DiffLineKind>(),
                "ordinal must be in-range for {cell:?}",
            );
            assert_eq!(hist.count(cell), 1, "cell {cell:?} count must equal 1");
        }
    }

    // ---- AxisHistogram::dominant_cell trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // dominant_cell projection's contract holds uniformly without
    // per-axis test duplication: empty → None; singleton → Some(K) on
    // every cell K; uniform axis-cover → Some(first cell in
    // declaration order). Concrete tie-breaking and merge-interaction
    // pins follow below on [`DiffLineKind`].

    fn assert_dominant_cell_empty_is_none<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.dominant_cell(),
            None,
            "empty histogram dominant_cell must be None on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_dominant_cell_singleton_picks_observed_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has dominant_cell = Some(cell).
        // Pins the (singleton → unique-max) law uniformly: every
        // closed-axis implementor's `dominant_cell` recovers the
        // observed cell from a one-observation history.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.dominant_cell(),
                Some(observed),
                "singleton dominant_cell must equal the observed cell {observed:?} \
                 on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_dominant_cell_axis_cover_picks_first_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // Observing every cell exactly once produces a uniform
        // histogram (every cell at 1, count maximum tied across the
        // axis); `dominant_cell` must return the first cell in
        // declaration order — the documented tie-breaking rule.
        // Pinned uniformly: every closed-axis implementor's
        // declaration-order tie-breaking lands at the head of
        // [`ClosedAxis::ALL`].
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        let first = axis_iter::<A>().next().expect(
            "every ClosedAxis implementor has at least one variant per the ClosedAxis contract",
        );
        assert_eq!(
            hist.dominant_cell(),
            Some(first),
            "uniform axis-cover histogram dominant_cell must be the first cell \
             in declaration order on axis {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_dominant_cell_empty_is_none_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_dominant_cell_empty_is_none::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_dominant_cell_singleton_picks_observed_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_dominant_cell_singleton_picks_observed_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_dominant_cell_axis_cover_picks_first_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_dominant_cell_axis_cover_picks_first_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_dominant_cell_returns_strict_max_when_unique() {
        // Concrete pin on the unique-maximum case: observing Added
        // twice and Removed / Context once each yields the strict max
        // at Added. The cell returned must be the unique-max cell
        // regardless of declaration order.
        let input = [
            DiffLineKind::Removed,
            DiffLineKind::Added,
            DiffLineKind::Context,
            DiffLineKind::Added,
        ];
        let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.count(DiffLineKind::Removed), 1);
        assert_eq!(hist.count(DiffLineKind::Context), 1);
        assert_eq!(hist.dominant_cell(), Some(DiffLineKind::Added));
    }

    #[test]
    fn axis_histogram_dominant_cell_breaks_ties_in_declaration_order() {
        // Concrete pin on the tie-breaking rule: when multiple cells
        // share the maximum count, the first in [`ClosedAxis::ALL`]
        // declaration order wins. [`DiffLineKind::ALL`] starts with
        // [`DiffLineKind::Context`]; observing every cell once at the
        // same count must return [`DiffLineKind::Context`] regardless
        // of observation order. Pinned by varying observation order
        // (Added, Removed, Context vs Context, Removed, Added) and
        // asserting the result is invariant — observation order does
        // not leak through the projection.
        let first = DiffLineKind::ALL[0];
        let by_observation_order_a: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Removed,
            DiffLineKind::Context,
        ]
        .into_iter()
        .collect();
        let by_observation_order_b: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Context,
            DiffLineKind::Removed,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        assert_eq!(by_observation_order_a, by_observation_order_b);
        assert_eq!(by_observation_order_a.dominant_cell(), Some(first));
        assert_eq!(by_observation_order_b.dominant_cell(), Some(first));
    }

    #[test]
    fn axis_histogram_dominant_cell_after_merge_reflects_combined_counts() {
        // The (merge, dominant_cell) composition: dominant_cell on a
        // merged histogram reflects the pointwise-summed counts, not
        // either side's individual maximum. Pinned by constructing two
        // histograms with disagreeing maxima (lhs dominant at Added,
        // rhs dominant at Removed with a heavier tail), so the merge's
        // dominant cell is Removed even though Added is the lhs max.
        let lhs: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let rhs: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Removed,
            DiffLineKind::Removed,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        assert_eq!(lhs.dominant_cell(), Some(DiffLineKind::Added));
        assert_eq!(rhs.dominant_cell(), Some(DiffLineKind::Removed));
        let merged = lhs.merge(&rhs);
        assert_eq!(merged.count(DiffLineKind::Added), 2);
        assert_eq!(merged.count(DiffLineKind::Removed), 3);
        assert_eq!(merged.dominant_cell(), Some(DiffLineKind::Removed));
    }

    #[test]
    fn axis_histogram_dominant_cell_iff_is_empty_is_false() {
        // Boundary pin: dominant_cell is Some iff is_empty is false.
        // Equivalence holds across both directions — an observation
        // history of any length yields Some, an empty history yields
        // None. Pinned concretely so the boundary discipline is named
        // at one site; the trait-uniform empty law above pins the
        // None direction across every implementor.
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.dominant_cell(), None);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Context).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.dominant_cell().is_some());
    }

    // ---- AxisHistogram::distinct_cells trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // distinct_cells projection's contract holds uniformly without
    // per-axis test duplication: empty → 0; singleton → 1 on every
    // cell K; uniform axis-cover → axis_cardinality::<A>(). Concrete
    // bound and merge-interaction pins follow below on
    // [`DiffLineKind`].

    fn assert_distinct_cells_empty_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.distinct_cells(),
            0,
            "empty histogram distinct_cells must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_distinct_cells_singleton_is_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has exactly one observed cell —
        // the singleton support law uniformly across implementors.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.distinct_cells(),
                1,
                "singleton distinct_cells must equal 1 \
                 for observed cell {observed:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_distinct_cells_axis_cover_equals_cardinality<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // histogram; distinct_cells must equal the axis cardinality —
        // the maximum-coverage law. Pinned uniformly across every
        // closed-axis implementor.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.distinct_cells(),
            axis_cardinality::<A>(),
            "axis-cover histogram distinct_cells must equal \
             axis_cardinality on {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_distinct_cells_empty_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_distinct_cells_empty_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_distinct_cells_singleton_is_one_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_distinct_cells_singleton_is_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_distinct_cells_axis_cover_equals_cardinality_for_every_closed_axis_implementor()
     {
        macro_rules! check {
            ($ty:ident) => {
                assert_distinct_cells_axis_cover_equals_cardinality::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_distinct_cells_equals_nonzero_count() {
        // The lift's defining equivalence: distinct_cells reads the
        // same scalar as the open-coded nonzero().count() pattern the
        // test laws and consumer-side coverage checks re-derive.
        // Pinned pointwise across the canonical observation-mix shapes
        // (empty, singleton, two-cell uneven, three-cell uniform,
        // two-of-three with one heavy) so a future regression in
        // either side surfaces here.
        let inputs: [&[DiffLineKind]; 5] = [
            &[],
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.distinct_cells(),
                hist.nonzero().count(),
                "distinct_cells must equal nonzero().count() on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_distinct_cells_is_bounded_above_by_total_and_axis_cardinality() {
        // Structural-bound pin: distinct_cells ∈ [0, total] ∩
        // [0, axis_cardinality::<A>()]. Each distinct cell contributes
        // at least one observation, so the support is bounded above
        // by the multiset size; the support is also bounded by the
        // axis size. Pinned over four observation shapes (empty,
        // singleton, axis-cover, heavy-tail mix) so both bounds get a
        // tight witness (empty: 0 == 0, singleton: 1 <= 1, axis-cover:
        // 3 == 3, heavy-tail: 2 <= 5).
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let support = hist.distinct_cells();
            assert!(
                support <= hist.total(),
                "distinct_cells {support} must be <= total {} on input of length {}",
                hist.total(),
                input.len(),
            );
            assert!(
                support <= axis_cardinality::<DiffLineKind>(),
                "distinct_cells {support} must be <= axis_cardinality {} on input of length {}",
                axis_cardinality::<DiffLineKind>(),
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_distinct_cells_equals_total_iff_every_observation_is_unique() {
        // Equality case of the bound: distinct_cells == total iff
        // every observed cell appears exactly once. The "uniform-
        // singleton" shape — every nonzero count is 1. Pinned by two
        // witnesses on each side of the equality, so a future
        // regression in the predicate surfaces at the boundary.
        // Equality witnesses (every observed cell appears once):
        let unique_a: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        let unique_b: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Context).collect();
        let unique_c: AxisHistogram<DiffLineKind> = axis_iter::<DiffLineKind>().collect();
        for hist in [&unique_a, &unique_b, &unique_c] {
            assert_eq!(
                hist.distinct_cells(),
                hist.total(),
                "uniform-singleton histogram must satisfy distinct_cells == total",
            );
        }
        // Strict-inequality witnesses (some observed cell has count > 1):
        let dup_a: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let dup_b: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Context,
            DiffLineKind::Context,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        for hist in [&dup_a, &dup_b] {
            assert!(
                hist.distinct_cells() < hist.total(),
                "duplicated-observation histogram must satisfy distinct_cells < total",
            );
        }
    }

    #[test]
    fn axis_histogram_distinct_cells_iff_is_empty_is_zero() {
        // Boundary pin: distinct_cells == 0 iff is_empty is true.
        // Equivalence holds across both directions — an empty
        // history reads 0, a non-empty history reads at least 1.
        // Peer to the same boundary equivalence dominant_cell carries
        // on the Some/None side.
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.distinct_cells(), 0);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.distinct_cells() >= 1);
    }

    #[test]
    fn axis_histogram_distinct_cells_after_merge_is_monotone_and_equals_support_union() {
        // The (merge, distinct_cells) composition: the support of a
        // merged histogram equals the union of either side's support
        // (set-theoretic union of observed-cell sets), so the
        // distinct_cells is at least each side's, and equal to the
        // union cardinality. Pinned with disjoint-support, overlapping-
        // support, and identity (empty-rhs) shapes so the merge
        // monotonicity gets a tight witness at each boundary.
        let added_only: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let removed_only: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        let context_and_added: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Context,
            DiffLineKind::Added,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        let empty_hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();

        // Disjoint supports: union is the sum of distinct counts.
        let disjoint = added_only.clone().merge(&removed_only);
        assert_eq!(disjoint.distinct_cells(), 2);
        assert!(disjoint.distinct_cells() >= added_only.distinct_cells());
        assert!(disjoint.distinct_cells() >= removed_only.distinct_cells());

        // Overlapping supports: union is strictly less than sum on the
        // shared cell (Added appears in both).
        let overlap = added_only.clone().merge(&context_and_added);
        assert_eq!(overlap.distinct_cells(), 2); // {Added, Context}, not 3
        assert!(overlap.distinct_cells() >= added_only.distinct_cells());
        assert!(overlap.distinct_cells() >= context_and_added.distinct_cells());

        // Identity (empty-rhs): merge leaves the support unchanged.
        let with_empty = added_only.clone().merge(&empty_hist);
        assert_eq!(with_empty.distinct_cells(), added_only.distinct_cells());
    }

    #[test]
    fn axis_histogram_dominant_cell_equals_open_coded_first_max_loop() {
        // The lift collapses the inline scan
        // `iter().filter(|&(_,c)|c>0).fold(first, |best,cur| if cur.1>best.1 {cur} else {best})`
        // pattern the consumers re-derived per observation site. Pin
        // pointwise equivalence over the typed `DiffLineKind` cells
        // across the four canonical observation-mix shapes (empty,
        // unique-max, tied-max, three-way uniform) so a future
        // regression in either side surfaces here.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Added,
            ],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let manual = {
                let mut iter = hist.iter().filter(|&(_, c)| c > 0);
                iter.next().map(|first| {
                    iter.fold(
                        first,
                        |best, current| {
                            if current.1 > best.1 { current } else { best }
                        },
                    )
                    .0
                })
            };
            assert_eq!(
                hist.dominant_cell(),
                manual,
                "dominant_cell must equal the open-coded first-max scan over input \
                 of length {}",
                input.len(),
            );
        }
    }

    // ---- AxisHistogram::recessive_cell trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // recessive_cell projection's contract holds uniformly without
    // per-axis test duplication: empty → None; singleton → Some(K) on
    // every cell K (identical to dominant_cell on the singleton case);
    // uniform axis-cover → Some(first cell in declaration order)
    // (identical to dominant_cell on a tied histogram). Concrete
    // tie-breaking and merge-interaction pins follow below on
    // [`DiffLineKind`].

    fn assert_recessive_cell_empty_is_none<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.recessive_cell(),
            None,
            "empty histogram recessive_cell must be None on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_recessive_cell_singleton_picks_observed_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has recessive_cell = Some(cell).
        // Pins the (singleton → unique-min) law uniformly. Identical
        // to the dominant_cell case on a singleton: the rarest and
        // the dominant cell coincide when only one cell is observed.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.recessive_cell(),
                Some(observed),
                "singleton recessive_cell must equal the observed cell {observed:?} \
                 on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_recessive_cell_axis_cover_picks_first_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // Observing every cell exactly once produces a uniform
        // histogram (every cell at 1, count minimum tied across the
        // axis); `recessive_cell` must return the first cell in
        // declaration order — the documented tie-breaking rule, same
        // as `dominant_cell` on the same input. Pinned uniformly:
        // every closed-axis implementor's declaration-order
        // tie-breaking lands at the head of [`ClosedAxis::ALL`] on
        // *both* the maximum and the minimum side, so the two
        // projections agree on every tied-uniform input.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        let first = axis_iter::<A>().next().expect(
            "every ClosedAxis implementor has at least one variant per the ClosedAxis contract",
        );
        assert_eq!(
            hist.recessive_cell(),
            Some(first),
            "uniform axis-cover histogram recessive_cell must be the first cell \
             in declaration order on axis {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_recessive_cell_empty_is_none_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_recessive_cell_empty_is_none::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_recessive_cell_singleton_picks_observed_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_recessive_cell_singleton_picks_observed_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_recessive_cell_axis_cover_picks_first_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_recessive_cell_axis_cover_picks_first_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_dominant_and_recessive_agree_on_uniform_axis_cover_for_every_implementor() {
        // Joint pin: on a uniform axis-cover histogram (every cell
        // observed once), `dominant_cell` and `recessive_cell` must
        // return the same cell — the first in declaration order.
        // The two projections coincide whenever every observed cell
        // shares the same count; the uniform axis-cover is the
        // tightest witness of that equality. Reaches every
        // closed-axis implementor uniformly so the
        // dominant-equals-recessive-on-uniform discipline is named
        // structurally rather than per-axis.
        fn assert_agree<A>()
        where
            A: ClosedAxis + std::fmt::Debug + PartialEq,
        {
            let hist: AxisHistogram<A> = axis_iter::<A>().collect();
            assert_eq!(
                hist.dominant_cell(),
                hist.recessive_cell(),
                "uniform axis-cover histogram must satisfy dominant_cell == \
                 recessive_cell on axis {}",
                std::any::type_name::<A>(),
            );
        }
        macro_rules! check {
            ($ty:ident) => {
                assert_agree::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_recessive_cell_returns_strict_min_when_unique() {
        // Concrete pin on the unique-minimum case: observing Added
        // twice and Removed three times yields the strict positive
        // min at Added. The cell returned must be the unique-min cell
        // regardless of declaration order. (Context is zero, so it
        // does not enter the argmin — zero cells are excluded from
        // the search, as documented on `recessive_cell`.)
        let input = [
            DiffLineKind::Removed,
            DiffLineKind::Added,
            DiffLineKind::Removed,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ];
        let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.count(DiffLineKind::Removed), 3);
        assert_eq!(hist.count(DiffLineKind::Context), 0);
        assert_eq!(hist.recessive_cell(), Some(DiffLineKind::Added));
    }

    #[test]
    fn axis_histogram_recessive_cell_breaks_ties_in_declaration_order() {
        // Concrete pin on the tie-breaking rule: when multiple
        // observed cells share the minimum count, the first in
        // [`ClosedAxis::ALL`] declaration order wins. [`DiffLineKind::ALL`]
        // starts with [`DiffLineKind::Context`]; observing every cell
        // once at the same count must return [`DiffLineKind::Context`]
        // regardless of observation order — identical to
        // [`Self::dominant_cell`]'s tie-breaking on the same input.
        // Pinned by varying observation order (Added, Removed,
        // Context vs Context, Removed, Added) and asserting the
        // result is invariant — observation order does not leak
        // through the projection.
        let first = DiffLineKind::ALL[0];
        let by_observation_order_a: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Removed,
            DiffLineKind::Context,
        ]
        .into_iter()
        .collect();
        let by_observation_order_b: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Context,
            DiffLineKind::Removed,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        assert_eq!(by_observation_order_a, by_observation_order_b);
        assert_eq!(by_observation_order_a.recessive_cell(), Some(first));
        assert_eq!(by_observation_order_b.recessive_cell(), Some(first));
    }

    #[test]
    fn axis_histogram_recessive_cell_excludes_zero_cells() {
        // Boundary pin: `recessive_cell` searches the positive
        // support only — zero-count cells are not eligible. A
        // histogram with Added = 2 and every other cell at 0 returns
        // Some(Added), not Some(Context) (the first cell in
        // declaration order, which is at count 0 and thus excluded).
        // The pin distinguishes `recessive_cell` from a
        // "argmin-over-all-cells" reading that would silently treat
        // unobserved cells as the minimum.
        let input = [DiffLineKind::Added, DiffLineKind::Added];
        let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
        assert_eq!(hist.count(DiffLineKind::Context), 0);
        assert_eq!(hist.count(DiffLineKind::Removed), 0);
        assert_eq!(hist.count(DiffLineKind::Added), 2);
        assert_eq!(hist.recessive_cell(), Some(DiffLineKind::Added));
    }

    #[test]
    fn axis_histogram_recessive_cell_after_merge_reflects_combined_counts() {
        // The (merge, recessive_cell) composition: recessive_cell on
        // a merged histogram reflects the pointwise-summed counts,
        // not either side's individual minimum. Pinned by
        // constructing two histograms with disagreeing minima — the
        // merge's recessive cell follows the combined counts, not
        // either side's rarest cell in isolation.
        //
        // `DiffLineKind::ALL` declaration order is
        // `[Removed, Added, Context]` (per
        // `diff_line_kind_all_declaration_order_is_removed_added_context`
        // in `src/tiered.rs`); witness shapes are constructed
        // accordingly.
        let lhs: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Removed,
            DiffLineKind::Removed,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        // lhs counts: Removed=2, Added=1, Context=0 →
        //   recessive = Added (strict min positive = 1, unique).
        let rhs: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Context,
        ]
        .into_iter()
        .collect();
        // rhs counts: Removed=0, Added=2, Context=1 →
        //   recessive = Context (strict min positive = 1, unique).
        assert_eq!(lhs.recessive_cell(), Some(DiffLineKind::Added));
        assert_eq!(rhs.recessive_cell(), Some(DiffLineKind::Context));
        let merged = lhs.merge(&rhs);
        assert_eq!(merged.count(DiffLineKind::Removed), 2);
        assert_eq!(merged.count(DiffLineKind::Added), 3);
        assert_eq!(merged.count(DiffLineKind::Context), 1);
        // merged: Removed=2, Added=3, Context=1 →
        //   recessive = Context (strict min positive = 1, unique).
        // The merge takes the rhs's Context cell as the global
        // recessive even though lhs's recessive was Added — the
        // projection depends on the combined counts, not on either
        // side's individual recessive in isolation.
        assert_eq!(merged.recessive_cell(), Some(DiffLineKind::Context));
    }

    #[test]
    fn axis_histogram_recessive_cell_iff_is_empty_is_false() {
        // Boundary pin: recessive_cell is Some iff is_empty is false
        // — identical companion to the dominant_cell boundary law.
        // The two projections are defined on the same support, so
        // their Some/None alignment is structural.
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.recessive_cell(), None);
        assert_eq!(empty.dominant_cell(), None);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Context).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.recessive_cell().is_some());
        assert!(singleton.dominant_cell().is_some());
    }

    #[test]
    fn axis_histogram_recessive_count_bounded_above_by_dominant_count() {
        // Companion-bound pin: the rarest cell's count is bounded
        // above by the dominant cell's count on every non-empty
        // histogram. Pinned over four observation-mix shapes
        // (singleton, strict skew, three-way uniform, two-way tie)
        // so the bound gets tight witnesses at the equality
        // boundaries (singleton: 1 == 1, uniform: 1 == 1) and at the
        // strict-inequality boundaries (skew: rare < dominant).
        let inputs: [&[DiffLineKind]; 4] = [
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let rare = hist
                .recessive_cell()
                .expect("non-empty histogram must have a recessive cell");
            let dom = hist
                .dominant_cell()
                .expect("non-empty histogram must have a dominant cell");
            assert!(
                hist.count(rare) <= hist.count(dom),
                "recessive count {} must be <= dominant count {} on input of length {}",
                hist.count(rare),
                hist.count(dom),
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_recessive_cell_equals_open_coded_first_min_loop() {
        // The lift collapses the inline scan
        // `iter().filter(|&(_,c)|c>0).fold(first, |best,cur| if cur.1<best.1 {cur} else {best})`
        // pattern an open-coded argmin consumer would re-derive per
        // observation site. Pin pointwise equivalence over the typed
        // `DiffLineKind` cells across the four canonical
        // observation-mix shapes (empty, unique-min, tied-min,
        // three-way uniform) so a future regression in either side
        // surfaces here.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Added,
            ],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let manual = {
                let mut iter = hist.iter().filter(|&(_, c)| c > 0);
                iter.next().map(|first| {
                    iter.fold(
                        first,
                        |best, current| {
                            if current.1 < best.1 { current } else { best }
                        },
                    )
                    .0
                })
            };
            assert_eq!(
                hist.recessive_cell(),
                manual,
                "recessive_cell must equal the open-coded first-min scan over input \
                 of length {}",
                input.len(),
            );
        }
    }

    // ---- AxisHistogram::unobserved closes the (observed, unobserved)
    // ---- partition over the closed axis ----
    //
    // [`AxisHistogram::unobserved`] is the structural complement of
    // [`AxisHistogram::nonzero`] over the closed axis: every cell of
    // the axis lies in exactly one of the two iterators. Four trait-
    // uniform laws reach every `ClosedAxis` implementor pointwise:
    //
    //   (a) empty histogram → unobserved iterates the full axis;
    //   (b) uniform axis-cover histogram → unobserved is empty;
    //   (c) singleton histogram → unobserved omits exactly the
    //       observed cell;
    //   (d) partition law — for every histogram and every implementor,
    //       `unobserved().count() + nonzero().count() ==
    //        axis_cardinality::<A>()`, and the two cell-sets are
    //       disjoint.

    fn assert_unobserved_empty_is_full_axis<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // The empty histogram observes no cell; every cell of the axis
        // is unobserved. The iterator yields the full axis in
        // declaration order, pointwise equal to `axis_iter::<A>()`.
        let hist: AxisHistogram<A> = AxisHistogram::empty();
        let unobserved: Vec<A> = hist.unobserved().collect();
        let full_axis: Vec<A> = axis_iter::<A>().collect();
        assert_eq!(
            unobserved,
            full_axis,
            "empty histogram unobserved must iterate the full axis on {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_unobserved_axis_cover_is_empty<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // axis-cover histogram (every cell at 1, support is the full
        // axis); `unobserved` is empty — the dual boundary of the
        // empty-histogram convention. The full-cover histogram has
        // no coverage gap.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.unobserved().count(),
            0,
            "uniform axis-cover histogram unobserved must be empty on {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_unobserved_singleton_omits_observed_cell<A>()
    where
        A: ClosedAxis + std::fmt::Debug + PartialEq,
    {
        // A singleton-support histogram (one cell observed) has the
        // full axis minus the observed cell as its coverage gap. Pin
        // pointwise across every cell of every axis: the unobserved
        // iterator yields `axis_iter::<A>()` with the observed cell
        // removed, in declaration order.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            let unobserved: Vec<A> = hist.unobserved().collect();
            let expected: Vec<A> = axis_iter::<A>().filter(|&v| v != observed).collect();
            assert_eq!(
                unobserved,
                expected,
                "singleton histogram unobserved must omit exactly the observed cell {observed:?} \
                 on axis {}",
                std::any::type_name::<A>(),
            );
            // Companion bound on the cardinality of the gap.
            assert_eq!(
                hist.unobserved().count(),
                axis_cardinality::<A>() - 1,
                "singleton histogram unobserved cardinality must equal axis_cardinality - 1 on {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_unobserved_and_nonzero_partition_axis<A>()
    where
        A: ClosedAxis + std::fmt::Debug + std::hash::Hash + Eq,
    {
        // Partition law: every cell of the axis lies in exactly one of
        // `unobserved()` and `nonzero().map(|(v, _)| v)`. Witnessed at
        // three boundary shapes — empty (gap = full axis), singleton
        // (support = {first}, gap = axis - {first}), uniform axis-
        // cover (support = full axis, gap = empty) — so the partition
        // holds at both extremes (full gap, no gap) and at a generic
        // proper-subset support.
        use std::collections::HashSet;
        let first = axis_iter::<A>()
            .next()
            .expect("ClosedAxis::ALL is non-empty by trait contract");
        let histograms: [AxisHistogram<A>; 3] = [
            AxisHistogram::empty(),
            std::iter::once(first).collect(),
            axis_iter::<A>().collect(),
        ];
        let n = axis_cardinality::<A>();
        for hist in histograms {
            let observed: HashSet<A> = hist.nonzero().map(|(v, _)| v).collect();
            let unobserved: HashSet<A> = hist.unobserved().collect();
            // Cardinality partition: |observed| + |unobserved| = n.
            assert_eq!(
                observed.len() + unobserved.len(),
                n,
                "observed.len() + unobserved.len() must equal axis_cardinality on {}",
                std::any::type_name::<A>(),
            );
            // Disjointness: observed ∩ unobserved = ∅.
            assert!(
                observed.is_disjoint(&unobserved),
                "observed and unobserved cell-sets must be disjoint on {}",
                std::any::type_name::<A>(),
            );
            // Cover: observed ∪ unobserved = axis.
            let full_axis: HashSet<A> = axis_iter::<A>().collect();
            let union: HashSet<A> = observed.union(&unobserved).copied().collect();
            assert_eq!(
                union,
                full_axis,
                "observed ∪ unobserved must equal the full axis on {}",
                std::any::type_name::<A>(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_empty_is_full_axis_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_empty_is_full_axis::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_axis_cover_is_empty_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_axis_cover_is_empty::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_singleton_omits_observed_cell_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_singleton_omits_observed_cell::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_and_nonzero_partition_axis_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_and_nonzero_partition_axis::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_equals_open_coded_filter_zero_loop() {
        // The lift collapses the inline scan
        // `iter().filter(|&(_, c)| c == 0).map(|(v, _)| v)` an open-
        // coded coverage-gap consumer would re-derive per observation
        // site. Pin pointwise equivalence over the typed
        // `DiffLineKind` cells across four canonical observation-mix
        // shapes (empty, singleton, two-of-three, axis-cover) so a
        // future regression in either side surfaces here.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Added,
            ],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let actual: Vec<DiffLineKind> = hist.unobserved().collect();
            let manual: Vec<DiffLineKind> = hist
                .iter()
                .filter(|&(_, c)| c == 0)
                .map(|(v, _)| v)
                .collect();
            assert_eq!(
                actual,
                manual,
                "unobserved must equal the open-coded filter-zero scan over input \
                 of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_complements_nonzero_pointwise() {
        // Concrete pin of the (observed, unobserved) partition on
        // `DiffLineKind`: nonzero cells and unobserved cells partition
        // the axis. Pinned at three shapes — empty (gap = full axis),
        // a strict-subset support (Added only, gap = Removed + Context),
        // and the axis-cover (gap = ∅) — so the partition is witnessed
        // at both boundaries and at a generic proper subset.
        use std::collections::HashSet;
        let cases: [(&[DiffLineKind], usize); 3] = [
            (&[], 0),
            (&[DiffLineKind::Added, DiffLineKind::Added], 1),
            (
                &[
                    DiffLineKind::Added,
                    DiffLineKind::Removed,
                    DiffLineKind::Context,
                ],
                3,
            ),
        ];
        for (input, expected_support) in cases {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let observed: HashSet<DiffLineKind> = hist.nonzero().map(|(v, _)| v).collect();
            let unobserved: HashSet<DiffLineKind> = hist.unobserved().collect();
            assert_eq!(observed.len(), expected_support);
            assert_eq!(observed.len() + unobserved.len(), DiffLineKind::ALL.len());
            assert!(observed.is_disjoint(&unobserved));
            let union: HashSet<DiffLineKind> = observed.union(&unobserved).copied().collect();
            let full_axis: HashSet<DiffLineKind> = DiffLineKind::ALL.iter().copied().collect();
            assert_eq!(union, full_axis);
        }
    }

    #[test]
    fn axis_histogram_unobserved_count_equals_cardinality_minus_distinct() {
        // Companion-invariant pin: `unobserved().count() ==
        // axis_cardinality::<A>() - distinct_cells()`. The coverage-
        // gap size reads off the support cardinality through one
        // subtraction from the axis size. Pinned across the same four
        // shapes the trait-uniform laws witness on (empty, singleton,
        // partial, full-cover) so the equality holds at every
        // distinct-cells value in the histogram's range.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Added],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        let n = axis_cardinality::<DiffLineKind>();
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.unobserved().count(),
                n - hist.distinct_cells(),
                "unobserved count must equal axis_cardinality - distinct_cells on input \
                 of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_after_merge_shrinks_monotonically() {
        // The (merge, unobserved) composition: merging never grows the
        // coverage gap. The unobserved set of a merged histogram is
        // the *intersection* of the two sides' unobserved sets — a cell
        // is unobserved in the merge iff it is unobserved in both
        // sides. Pinned by constructing two histograms whose supports
        // partially overlap and asserting the merge's unobserved set
        // equals the set intersection.
        //
        // `DiffLineKind::ALL` declaration order is
        // `[Removed, Added, Context]`.
        use std::collections::HashSet;
        let lhs: AxisHistogram<DiffLineKind> = [DiffLineKind::Removed, DiffLineKind::Added]
            .into_iter()
            .collect();
        // lhs support: {Removed, Added}; unobserved: {Context}.
        let rhs: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Context]
            .into_iter()
            .collect();
        // rhs support: {Added, Context}; unobserved: {Removed}.
        let lhs_gap: HashSet<DiffLineKind> = lhs.unobserved().collect();
        let rhs_gap: HashSet<DiffLineKind> = rhs.unobserved().collect();
        let lhs_gap_count = lhs.unobserved().count();
        let rhs_gap_count = rhs.unobserved().count();
        assert_eq!(lhs_gap, HashSet::from([DiffLineKind::Context]));
        assert_eq!(rhs_gap, HashSet::from([DiffLineKind::Removed]));
        let merged = lhs.merge(&rhs);
        let merged_gap: HashSet<DiffLineKind> = merged.unobserved().collect();
        // Intersection of {Context} and {Removed} is empty: the merge
        // covers every cell, so unobserved is empty.
        let expected: HashSet<DiffLineKind> = lhs_gap.intersection(&rhs_gap).copied().collect();
        assert_eq!(merged_gap, expected);
        assert!(merged_gap.is_empty());
        // Monotonicity bound: merged gap size <= min of side gap sizes.
        assert!(merged.unobserved().count() <= lhs_gap_count);
        assert!(merged.unobserved().count() <= rhs_gap_count);
    }

    // ---- AxisHistogram::peak_count trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // peak_count projection's contract holds uniformly without
    // per-axis test duplication: empty → 0; singleton → 1 on every
    // cell K; uniform axis-cover → 1 (every cell observed exactly
    // once, so the maximum count is 1). Concrete merge-monotonicity
    // and (cell, count) pairing pins follow below on [`DiffLineKind`].

    fn assert_peak_count_empty_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.peak_count(),
            0,
            "empty histogram peak_count must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_peak_count_singleton_is_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has peak count exactly 1 —
        // the singleton-support peak law uniformly across implementors.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.peak_count(),
                1,
                "singleton peak_count must equal 1 \
                 for observed cell {observed:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_peak_count_axis_cover_is_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // histogram; the maximum cell count is 1 — the uniform-axis-
        // cover peak law. Peer to the uniform-axis-cover law on
        // `dominant_cell` (which picks the first cell on ties): here
        // the *count* at that cell is 1, pinned uniformly across every
        // closed-axis implementor.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.peak_count(),
            1,
            "uniform axis-cover histogram peak_count must equal 1 on {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_peak_count_empty_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_peak_count_empty_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_peak_count_singleton_is_one_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_peak_count_singleton_is_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_peak_count_axis_cover_is_one_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_peak_count_axis_cover_is_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_peak_count_equals_dominant_cell_count_when_non_empty() {
        // The lift's defining pairing law: on every non-empty histogram
        // the scalar `peak_count` equals the count carried by the
        // dominant cell (i.e. `count(dominant_cell().unwrap())`). Pin
        // pointwise equivalence over the typed `DiffLineKind` cells
        // across four canonical observation-mix shapes (singleton,
        // unique-max, tied-max, three-way uniform) so a future
        // regression in either side surfaces here. The empty boundary
        // is pinned separately by the trait-uniform empty-is-zero law
        // above and the dedicated `peak_count_iff_is_empty_is_zero`
        // test below.
        let inputs: [&[DiffLineKind]; 4] = [
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Added,
            ],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let dominant = hist
                .dominant_cell()
                .expect("non-empty histogram has a dominant cell");
            assert_eq!(
                hist.peak_count(),
                hist.count(dominant),
                "peak_count must equal count(dominant_cell()) on non-empty input \
                 of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_peak_count_iff_is_empty_is_zero() {
        // Boundary pin: peak_count == 0 iff is_empty is true.
        // Equivalence holds across both directions — an empty history
        // reads 0, a non-empty history reads at least 1. Peer to the
        // same boundary equivalence distinct_cells and dominant_cell
        // both carry.
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.peak_count(), 0);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.peak_count() >= 1);
    }

    #[test]
    fn axis_histogram_peak_count_is_bounded_above_by_total() {
        // Structural-bound pin: peak_count ∈ [0, total] on every
        // histogram, with equality iff distinct_cells <= 1. Pinned
        // over four observation shapes (empty, singleton,
        // single-cell-multi-observation, multi-cell) so both the bound
        // and the equality case get tight witnesses.
        let single_cell_two_observations: &[DiffLineKind] =
            &[DiffLineKind::Added, DiffLineKind::Added];
        let multi_cell: &[DiffLineKind] = &[
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ];
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Removed],
            single_cell_two_observations,
            multi_cell,
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert!(
                hist.peak_count() <= hist.total(),
                "peak_count {} must be <= total {} on input of length {}",
                hist.peak_count(),
                hist.total(),
                input.len(),
            );
            if hist.distinct_cells() <= 1 {
                assert_eq!(
                    hist.peak_count(),
                    hist.total(),
                    "peak_count must equal total when distinct_cells <= 1 \
                     on input of length {}",
                    input.len(),
                );
            } else {
                assert!(
                    hist.peak_count() < hist.total(),
                    "peak_count must be strictly less than total when \
                     distinct_cells >= 2 on input of length {}",
                    input.len(),
                );
            }
        }
    }

    #[test]
    fn axis_histogram_peak_count_after_merge_is_monotone() {
        // The (merge, peak_count) composition: merging never shrinks
        // the peak. Adding non-negative deltas pointwise to the side
        // with the higher peak cannot lower its count; on every cell
        // the merge's count is the sum of the sides' counts, and the
        // maximum of pointwise sums is at least each side's maximum
        // pointwise. Pinned with disjoint-support, overlapping-support
        // (where the merge's peak strictly grows), and identity
        // (empty-rhs) shapes so the monotonicity gets a tight witness
        // at each boundary.
        let added_two: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let removed_one: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        let context_and_added_two: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Context,
            DiffLineKind::Added,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        let empty_hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();

        // Disjoint supports: peak equals the larger side's peak
        // (Added's two beats Removed's one).
        let disjoint = added_two.clone().merge(&removed_one);
        assert_eq!(disjoint.peak_count(), 2);
        assert!(disjoint.peak_count() >= added_two.peak_count());
        assert!(disjoint.peak_count() >= removed_one.peak_count());

        // Overlapping supports: the shared Added cell grows from
        // (2, 2) → 4, so the merge's peak strictly grows past each
        // side's peak.
        let overlap = added_two.clone().merge(&context_and_added_two);
        assert_eq!(overlap.peak_count(), 4);
        assert!(overlap.peak_count() >= added_two.peak_count());
        assert!(overlap.peak_count() >= context_and_added_two.peak_count());

        // Identity (empty-rhs): merge leaves the peak unchanged.
        let with_empty = added_two.clone().merge(&empty_hist);
        assert_eq!(with_empty.peak_count(), added_two.peak_count());
    }

    // ---- AxisHistogram::trough_count trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // trough_count projection's contract holds uniformly without
    // per-axis test duplication: empty → 0; singleton → 1 on every
    // cell; uniform axis-cover → 1 (every cell observed exactly once,
    // so the minimum over the support equals 1). Concrete (cell, count)
    // pairing, structural bound, and merge non-monotonicity pins
    // follow below on [`DiffLineKind`].

    fn assert_trough_count_empty_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.trough_count(),
            0,
            "empty histogram trough_count must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_trough_count_singleton_is_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has trough count exactly 1 — the
        // singleton-support trough law uniformly across implementors.
        // Pointwise equal to `peak_count` on the singleton support
        // (every singleton is uniform, so peak and trough agree).
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.trough_count(),
                1,
                "singleton trough_count must equal 1 \
                 for observed cell {observed:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_trough_count_axis_cover_is_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // histogram; the minimum cell count over the support is 1 —
        // the uniform-axis-cover trough law. Peer to the
        // uniform-axis-cover law on `peak_count` (which also reads 1
        // on the same input): the (peak, trough) pair agrees pointwise
        // on every uniform histogram, pinned uniformly across every
        // closed-axis implementor.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.trough_count(),
            1,
            "uniform axis-cover histogram trough_count must equal 1 on {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_trough_count_empty_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_trough_count_empty_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_trough_count_singleton_is_one_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_trough_count_singleton_is_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_trough_count_axis_cover_is_one_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_trough_count_axis_cover_is_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_trough_count_equals_recessive_cell_count_when_non_empty() {
        // The lift's defining pairing law: on every non-empty histogram
        // the scalar `trough_count` equals the count carried by the
        // recessive cell (i.e. `count(recessive_cell().unwrap())`). The
        // structural dual of the
        // `peak_count == count(dominant_cell())` law on the majority
        // side. Pin pointwise equivalence over typed `DiffLineKind`
        // cells across four canonical observation-mix shapes
        // (singleton, unique-min, tied-min, three-way uniform) so a
        // future regression in either side surfaces here. The empty
        // boundary is pinned separately by the trait-uniform
        // empty-is-zero law above and the dedicated
        // `trough_count_iff_is_empty_is_zero` test below.
        let inputs: [&[DiffLineKind]; 4] = [
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Added,
            ],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let recessive = hist
                .recessive_cell()
                .expect("non-empty histogram has a recessive cell");
            assert_eq!(
                hist.trough_count(),
                hist.count(recessive),
                "trough_count must equal count(recessive_cell()) on non-empty input \
                 of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_trough_count_iff_is_empty_is_zero() {
        // Boundary pin: trough_count == 0 iff is_empty is true.
        // Equivalence holds across both directions — an empty history
        // reads 0, a non-empty history reads at least 1 (every observed
        // cell carries at least one observation by construction). Peer
        // to the same boundary equivalence peak_count, distinct_cells,
        // and dominant_cell all carry.
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.trough_count(), 0);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.trough_count() >= 1);
    }

    #[test]
    fn axis_histogram_trough_count_is_bounded_above_by_peak_count() {
        // Structural-bound pin: trough_count ∈ [0, peak_count] on every
        // histogram, with equality iff every observed cell carries the
        // same count (the *uniform-observed-count* shape). Pinned over
        // five observation shapes — empty (0 == 0); singleton
        // (uniform, trough == peak == 1); single-cell-multi-observation
        // (uniform-support, trough == peak == 2); k-cell uniform
        // (axis-cover by hand, trough == peak == 1); skew (strict
        // inequality witness, trough == 1 < peak == 2) — so both the
        // bound and the equality case get tight witnesses across the
        // boundary spectrum.
        let single_cell_two_observations: &[DiffLineKind] =
            &[DiffLineKind::Added, DiffLineKind::Added];
        let two_cell_uniform: &[DiffLineKind] = &[DiffLineKind::Added, DiffLineKind::Removed];
        let skew: &[DiffLineKind] = &[
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ];
        let inputs: [&[DiffLineKind]; 5] = [
            &[],
            &[DiffLineKind::Removed],
            single_cell_two_observations,
            two_cell_uniform,
            skew,
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert!(
                hist.trough_count() <= hist.peak_count(),
                "trough_count {} must be <= peak_count {} on input of length {}",
                hist.trough_count(),
                hist.peak_count(),
                input.len(),
            );
            // Equality case — every observed cell carries the same count.
            let observed_counts: Vec<usize> = hist.nonzero().map(|(_, count)| count).collect();
            let uniform = observed_counts
                .first()
                .is_some_and(|&first| observed_counts.iter().all(|&c| c == first));
            if uniform || hist.is_empty() {
                assert_eq!(
                    hist.trough_count(),
                    hist.peak_count(),
                    "trough_count must equal peak_count when observed counts \
                     are uniform on input of length {}",
                    input.len(),
                );
            } else {
                assert!(
                    hist.trough_count() < hist.peak_count(),
                    "trough_count must be strictly less than peak_count when \
                     observed counts are non-uniform on input of length {}",
                    input.len(),
                );
            }
        }
    }

    #[test]
    fn axis_histogram_trough_count_after_merge_is_non_monotonic() {
        // The (merge, trough_count) composition: in deliberate contrast
        // to peak_count's strict monotonicity under merge, trough_count
        // can either *grow* (when the supports coincide, every observed
        // cell's count grows so does the minimum) or *shrink* (when one
        // side observes a cell the other does not, the new cell enters
        // the merged support carrying that side's count and can pull
        // the merged trough below either side's). The empty-identity
        // law still holds. Pinned with overlapping-support (grow),
        // disjoint-support (shrink-or-equal), and identity (empty-rhs)
        // shapes so each branch of the non-monotonic behavior gets a
        // tight witness.
        let added_two: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let added_three: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        let removed_one: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        let empty_hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();

        // Overlapping (identical) supports {Added}: trough grows from
        // (2, 3) → 5, strictly past each side's trough.
        let overlap = added_two.clone().merge(&added_three);
        assert_eq!(overlap.trough_count(), 5);
        assert!(overlap.trough_count() > added_two.trough_count());
        assert!(overlap.trough_count() > added_three.trough_count());

        // Disjoint supports {Added:2} and {Removed:1}: the merged
        // support {Added:2, Removed:1} pulls the merged trough down to
        // 1 — strictly below the higher side's trough (2). Witnesses
        // the *shrink* branch of non-monotonicity.
        let disjoint = added_two.clone().merge(&removed_one);
        assert_eq!(disjoint.trough_count(), 1);
        assert!(disjoint.trough_count() < added_two.trough_count());
        assert_eq!(disjoint.trough_count(), removed_one.trough_count());

        // Identity (empty-rhs): merge leaves the trough unchanged.
        let with_empty = added_two.clone().merge(&empty_hist);
        assert_eq!(with_empty.trough_count(), added_two.trough_count());
    }

    // ---- AxisHistogram::spread trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // `spread` projection's contract holds uniformly without per-axis
    // test duplication: empty → 0; singleton → 0 on every cell K
    // (one observed cell with count 1, trivially balanced); uniform
    // axis-cover → 0 (every cell at one, perfectly balanced).
    // Concrete strict-skew, defining-equivalence, bound, and merge-
    // interaction pins follow below on [`DiffLineKind`].

    fn assert_spread_empty_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.spread(),
            0,
            "empty histogram spread must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_spread_singleton_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has spread = 0 — the
        // singleton-support case is trivially balanced (one observed
        // cell at count 1, peak = trough = 1, spread = 0). Pinned
        // uniformly across every closed-axis implementor.
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.spread(),
                0,
                "singleton spread must be 0 for observed cell {observed:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_spread_axis_cover_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // histogram (every cell at 1, peak = trough = 1, spread = 0)
        // — the structural "every observed kind fired the same number
        // of times" boundary at the maximum-coverage shape. Pinned
        // uniformly across every closed-axis implementor.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.spread(),
            0,
            "axis-cover histogram spread must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_spread_empty_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_spread_empty_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_spread_singleton_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_spread_singleton_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_spread_axis_cover_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_spread_axis_cover_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_spread_equals_peak_minus_trough() {
        // The lift's defining equivalence: spread reads the same
        // scalar as the open-coded `peak_count - trough_count`
        // subtraction every consumer re-derived inline. Pinned
        // pointwise across the canonical observation-mix shapes
        // (empty, singleton, uniform-tied, strict-skew, heavy-tail)
        // so a future regression in either side surfaces here.
        let inputs: [&[DiffLineKind]; 5] = [
            &[],
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.spread(),
                hist.peak_count() - hist.trough_count(),
                "spread must equal peak_count - trough_count on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_spread_zero_iff_uniformly_observed_count() {
        // The structural-skew predicate: spread == 0 iff every
        // observed cell carries the same count — the "uniformly-
        // observed-count" shape. Pinned at both sides of the
        // equivalence across the boundary shapes:
        //   - empty (vacuously uniform — no observed cells),
        //   - singleton (one observed cell, trivially balanced),
        //   - uniform axis-cover (every cell at one),
        //   - k-cell-observed-k-times-each-once (multiple observed
        //     cells at the same count — the non-trivial balanced
        //     shape),
        //   - strict-skew (two cells, one observed twice and one
        //     once — the canonical skew witness),
        //   - heavy-tail (one dominant cell with multiple, one
        //     rarest observed at one — strong skew).
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert_eq!(empty.spread(), 0);

        let singleton: AxisHistogram<DiffLineKind> = std::iter::once(DiffLineKind::Added).collect();
        assert_eq!(singleton.spread(), 0);

        let axis_cover: AxisHistogram<DiffLineKind> = axis_iter::<DiffLineKind>().collect();
        assert_eq!(axis_cover.spread(), 0);

        let two_each: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        assert_eq!(two_each.spread(), 0);

        let skewed: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        assert!(skewed.spread() > 0);
        assert_eq!(skewed.spread(), 1);

        let heavy_tail: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        assert!(heavy_tail.spread() > 0);
        assert_eq!(heavy_tail.spread(), 3);
    }

    #[test]
    fn axis_histogram_spread_agrees_with_dominant_recessive_cell_equality() {
        // The cross-projection coincidence law: on every non-empty
        // histogram, `spread() == 0` iff `dominant_cell() ==
        // recessive_cell()` — the scalar surface lifts the same
        // "uniformly-observed-count" predicate the modal-pair surface
        // carries on the `(Option<A>, Option<A>)` form. Pinned at
        // three boundary shapes (singleton, uniform axis-cover, and a
        // strict-skew shape) so the two surfaces agree across every
        // branch of the predicate.
        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        assert_eq!(
            singleton.spread() == 0,
            singleton.dominant_cell() == singleton.recessive_cell(),
        );

        let uniform: AxisHistogram<DiffLineKind> = axis_iter::<DiffLineKind>().collect();
        assert_eq!(
            uniform.spread() == 0,
            uniform.dominant_cell() == uniform.recessive_cell(),
        );

        let skewed: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            skewed.spread() == 0,
            skewed.dominant_cell() == skewed.recessive_cell(),
        );
    }

    #[test]
    fn axis_histogram_spread_is_bounded_above_by_peak_count_and_total() {
        // Structural-bound pin: spread <= peak_count <= total, both
        // bounds via the non-negative trough subtraction. Pinned at
        // four shapes (empty, singleton, balanced, strict-skew) so
        // both bounds get a tight witness. Equality with peak_count
        // holds exactly when trough_count == 0 — i.e. on the empty
        // histogram, the sole shape with trough_count == 0.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Added],
            &[
                DiffLineKind::Added,
                DiffLineKind::Removed,
                DiffLineKind::Context,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert!(
                hist.spread() <= hist.peak_count(),
                "spread {} must be <= peak_count {} on input of length {}",
                hist.spread(),
                hist.peak_count(),
                input.len(),
            );
            assert!(
                hist.spread() <= hist.total(),
                "spread {} must be <= total {} on input of length {}",
                hist.spread(),
                hist.total(),
                input.len(),
            );
            assert_eq!(
                hist.spread() == hist.peak_count(),
                hist.trough_count() == 0,
                "spread == peak_count iff trough_count == 0 on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_spread_after_merge_is_non_monotonic() {
        // The (merge, spread) composition: in deliberate contrast to
        // peak_count's strict monotonicity under merge, spread can
        // either *grow* (when one side carries a heavy tail the
        // other lacks, the merged peak grows faster than the merged
        // trough) or *shrink* (when merging two strict-skew sides
        // restores a uniformly-observed-count merge). The
        // empty-identity law still holds. Pinned with grow,
        // shrink-or-equal, and identity (empty-rhs) shapes so each
        // branch of the non-monotonic behavior gets a tight witness.
        let added_two: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Added]
            .into_iter()
            .collect();
        let added_two_removed_one: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Added,
            DiffLineKind::Added,
            DiffLineKind::Removed,
        ]
        .into_iter()
        .collect();
        let removed_two: AxisHistogram<DiffLineKind> =
            [DiffLineKind::Removed, DiffLineKind::Removed]
                .into_iter()
                .collect();
        let empty_hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();

        // Grow branch: merging a balanced {Added:2} with a skewed
        // {Added:2, Removed:1} grows the spread strictly past either
        // side. lhs spread = 0 (balanced singleton-support), rhs
        // spread = 1 (Added:2 vs Removed:1), merged = {Added:4,
        // Removed:1} with peak 4, trough 1, spread 3 — strictly
        // greater than each side.
        let grow = added_two.clone().merge(&added_two_removed_one);
        assert_eq!(grow.spread(), 3);
        assert!(grow.spread() > added_two.spread());
        assert!(grow.spread() > added_two_removed_one.spread());

        // Shrink branch: merging two strict-skew supports
        // {Added:2, Removed:1} and {Removed:2, ???} — pick the
        // canonical witness: lhs {Added:2, Removed:1} (spread 1)
        // with rhs {Removed:2, Added:1} (spread 1) merges to
        // {Added:3, Removed:3} with peak 3, trough 3, spread 0 —
        // strictly *below* each side's spread. The non-monotonic
        // shrink branch.
        let added_two_removed_one_b: AxisHistogram<DiffLineKind> = [
            DiffLineKind::Removed,
            DiffLineKind::Removed,
            DiffLineKind::Added,
        ]
        .into_iter()
        .collect();
        let shrink = added_two_removed_one
            .clone()
            .merge(&added_two_removed_one_b);
        assert_eq!(shrink.spread(), 0);
        assert!(shrink.spread() < added_two_removed_one.spread());
        assert!(shrink.spread() < added_two_removed_one_b.spread());

        // Equal-or-bracketed branch: merging two disjoint singleton-
        // support sides produces a balanced merge — spread stays at
        // 0. (Witnesses the identity boundary where spread agrees on
        // both sides and the merge.)
        let two_singletons = added_two.clone().merge(&removed_two);
        assert_eq!(two_singletons.spread(), 0);
        assert_eq!(two_singletons.spread(), added_two.spread());

        // Identity (empty-rhs): merge leaves the spread unchanged.
        let with_empty = added_two_removed_one.clone().merge(&empty_hist);
        assert_eq!(with_empty.spread(), added_two_removed_one.spread());
    }

    // ---- AxisHistogram::unobserved_cells trait-uniform laws ----
    //
    // Three trait-uniform laws reach every [`ClosedAxis`] implementor
    // through [`for_each_closed_axis_implementor`] so the per-axis
    // unobserved_cells projection's contract holds uniformly without
    // per-axis test duplication: empty → axis_cardinality (every cell
    // unobserved, the full gap); singleton → axis_cardinality - 1 on
    // every cell K (exactly the observed cell drops out of the gap);
    // axis-cover → 0 (every cell observed, no gap). Concrete defining-
    // equivalence, partition-law, structural-bound, boundary-equivalence,
    // and merge-monotonicity pins follow below on [`DiffLineKind`].

    fn assert_unobserved_cells_empty_equals_cardinality<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        let hist = AxisHistogram::<A>::empty();
        assert_eq!(
            hist.unobserved_cells(),
            axis_cardinality::<A>(),
            "empty histogram unobserved_cells must equal axis_cardinality on axis {}",
            std::any::type_name::<A>(),
        );
    }

    fn assert_unobserved_cells_singleton_is_cardinality_minus_one<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // For every cell of the axis: a histogram built from one
        // observation of that cell has exactly one observed cell — the
        // observed cell drops out of the gap, leaving the gap at
        // `axis_cardinality - 1`. Pinned uniformly across every
        // closed-axis implementor.
        let n = axis_cardinality::<A>();
        for observed in axis_iter::<A>() {
            let hist: AxisHistogram<A> = std::iter::once(observed).collect();
            assert_eq!(
                hist.unobserved_cells(),
                n - 1,
                "singleton unobserved_cells must equal axis_cardinality - 1 \
                 for observed cell {observed:?} on axis {}",
                std::any::type_name::<A>(),
            );
        }
    }

    fn assert_unobserved_cells_axis_cover_is_zero<A>()
    where
        A: ClosedAxis + std::fmt::Debug,
    {
        // Observing every cell exactly once produces a uniform
        // axis-cover histogram (every cell observed at least once,
        // support is the full axis); the coverage gap is empty — the
        // dual boundary of the empty-histogram convention. The
        // full-cover histogram has no unobserved cells.
        let hist: AxisHistogram<A> = axis_iter::<A>().collect();
        assert_eq!(
            hist.unobserved_cells(),
            0,
            "axis-cover histogram unobserved_cells must be 0 on axis {}",
            std::any::type_name::<A>(),
        );
    }

    #[test]
    fn axis_histogram_unobserved_cells_empty_equals_cardinality_for_every_closed_axis_implementor()
    {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_cells_empty_equals_cardinality::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_cells_singleton_is_cardinality_minus_one_for_every_closed_axis_implementor()
     {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_cells_singleton_is_cardinality_minus_one::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_cells_axis_cover_is_zero_for_every_closed_axis_implementor() {
        macro_rules! check {
            ($ty:ident) => {
                assert_unobserved_cells_axis_cover_is_zero::<$ty>();
            };
        }
        for_each_closed_axis_implementor!(check);
    }

    #[test]
    fn axis_histogram_unobserved_cells_equals_unobserved_iterator_count() {
        // The lift's defining equivalence: unobserved_cells reads the
        // same scalar as the open-coded `unobserved().count()` chain
        // every consumer re-derived inline. Pinned pointwise across the
        // canonical observation-mix shapes (empty, singleton, partial,
        // full-cover, heavy-tail mix) so a future regression in either
        // side surfaces here.
        let inputs: [&[DiffLineKind]; 5] = [
            &[],
            &[DiffLineKind::Added],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.unobserved_cells(),
                hist.unobserved().count(),
                "unobserved_cells must equal unobserved().count() on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_distinct_cells_plus_unobserved_cells_equals_cardinality() {
        // The (observed, unobserved) cardinality partition: every cell
        // of the closed axis lies in exactly one of the two scalar
        // counts, so their sum reads off the axis size at every
        // histogram. The scalar-level peer to the
        // `nonzero ⊔ unobserved = axis` set-level partition pinned on
        // [`AxisHistogram::unobserved`]. Pinned across the same
        // observation-mix shapes the trait-uniform laws witness on
        // (empty, singleton, partial, full-cover, heavy-tail) so the
        // equality holds at every distinct-cells value in the
        // histogram's range.
        let inputs: [&[DiffLineKind]; 5] = [
            &[],
            &[DiffLineKind::Added],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        let n = axis_cardinality::<DiffLineKind>();
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.distinct_cells() + hist.unobserved_cells(),
                n,
                "distinct_cells + unobserved_cells must equal axis_cardinality \
                 on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_cells_equals_cardinality_minus_distinct_cells() {
        // The structural-complement derivation: unobserved_cells reads
        // off the support cardinality through one subtraction from the
        // axis size — pointwise equivalent to the underflow-safe form
        // `axis_cardinality - distinct_cells`. Pinned across the same
        // boundary shapes the partition law witnesses on so the
        // subtraction is exercised at every support-size in the
        // histogram's range.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Added],
            &[DiffLineKind::Added, DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        let n = axis_cardinality::<DiffLineKind>();
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            assert_eq!(
                hist.unobserved_cells(),
                n - hist.distinct_cells(),
                "unobserved_cells must equal axis_cardinality - distinct_cells \
                 on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_cells_is_bounded_above_by_axis_cardinality() {
        // Structural-bound pin: unobserved_cells ∈ [0,
        // axis_cardinality::<A>()]. Tight at both ends — the empty
        // histogram reads N (every cell unobserved, full gap), the
        // axis-cover histogram reads 0 (no gap). Pinned over four
        // observation shapes (empty, singleton, axis-cover, heavy-tail
        // mix) so both bounds get a tight witness.
        let inputs: [&[DiffLineKind]; 4] = [
            &[],
            &[DiffLineKind::Removed],
            &[
                DiffLineKind::Context,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
            &[
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Added,
                DiffLineKind::Removed,
            ],
        ];
        let n = axis_cardinality::<DiffLineKind>();
        for input in inputs {
            let hist: AxisHistogram<DiffLineKind> = input.iter().copied().collect();
            let gap = hist.unobserved_cells();
            assert!(
                gap <= n,
                "unobserved_cells {gap} must be <= axis_cardinality {n} \
                 on input of length {}",
                input.len(),
            );
        }
    }

    #[test]
    fn axis_histogram_unobserved_cells_full_cover_iff_distinct_equals_cardinality() {
        // The full-cover predicate at the scalar surface: every cell
        // observed iff the coverage gap is empty. Pinned at both sides
        // of the equivalence — full-cover witnesses (gap == 0,
        // distinct == cardinality) and proper-subset witnesses (gap > 0,
        // distinct < cardinality) — so the predicate holds at every
        // branch.
        let n = axis_cardinality::<DiffLineKind>();
        // Full-cover witness: every cell observed.
        let full_cover: AxisHistogram<DiffLineKind> = axis_iter::<DiffLineKind>().collect();
        assert_eq!(full_cover.unobserved_cells(), 0);
        assert_eq!(full_cover.distinct_cells(), n);
        assert_eq!(
            full_cover.unobserved_cells() == 0,
            full_cover.distinct_cells() == n,
        );
        // Proper-subset witness: only some cells observed.
        let partial: AxisHistogram<DiffLineKind> = std::iter::once(DiffLineKind::Added).collect();
        assert!(partial.unobserved_cells() > 0);
        assert!(partial.distinct_cells() < n);
        assert_eq!(
            partial.unobserved_cells() == 0,
            partial.distinct_cells() == n,
        );
    }

    #[test]
    fn axis_histogram_unobserved_cells_iff_is_empty_equals_cardinality() {
        // Boundary pin: unobserved_cells == axis_cardinality iff
        // is_empty is true. Equivalence holds across both directions —
        // an empty history reads N (every cell unobserved), a non-empty
        // history reads at most N - 1. Peer to the same boundary
        // equivalence distinct_cells / dominant_cell carry on the dual
        // side of the partition.
        let n = axis_cardinality::<DiffLineKind>();
        let empty: AxisHistogram<DiffLineKind> = AxisHistogram::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.unobserved_cells(), n);

        let singleton: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Removed).collect();
        assert!(!singleton.is_empty());
        assert!(singleton.unobserved_cells() <= n - 1);
    }

    #[test]
    fn axis_histogram_unobserved_cells_after_merge_is_monotone_decreasing() {
        // The (merge, unobserved_cells) composition: the coverage gap
        // of a merged histogram is the *intersection* of the two sides'
        // gaps (a cell is unobserved in the merge iff unobserved in
        // both sides), so the merged gap size is at most each side's.
        // Pinned with disjoint-support, overlapping-support, and
        // identity (empty-rhs) shapes so the merge monotone-decreasing
        // law gets a tight witness at each boundary.
        //
        // `DiffLineKind::ALL` declaration order is
        // `[Removed, Added, Context]` (axis_cardinality = 3).
        let lhs: AxisHistogram<DiffLineKind> = [DiffLineKind::Removed, DiffLineKind::Added]
            .into_iter()
            .collect();
        // lhs: support {Removed, Added}; gap = 1 ({Context}).
        let rhs: AxisHistogram<DiffLineKind> = [DiffLineKind::Added, DiffLineKind::Context]
            .into_iter()
            .collect();
        // rhs: support {Added, Context}; gap = 1 ({Removed}).
        let empty_hist: AxisHistogram<DiffLineKind> = AxisHistogram::empty();

        // Overlapping-support: the merge covers every cell, so the gap
        // collapses to 0 — strictly below each side's gap.
        let merged = lhs.clone().merge(&rhs);
        assert_eq!(merged.unobserved_cells(), 0);
        assert!(merged.unobserved_cells() <= lhs.unobserved_cells());
        assert!(merged.unobserved_cells() <= rhs.unobserved_cells());

        // Disjoint singleton supports: the gap shrinks from
        // axis_cardinality - 1 = 2 on each side to 1 on the merge.
        let solo_added: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Added).collect();
        let solo_context: AxisHistogram<DiffLineKind> =
            std::iter::once(DiffLineKind::Context).collect();
        let disjoint = solo_added.clone().merge(&solo_context);
        assert_eq!(disjoint.unobserved_cells(), 1);
        assert!(disjoint.unobserved_cells() <= solo_added.unobserved_cells());
        assert!(disjoint.unobserved_cells() <= solo_context.unobserved_cells());

        // Identity (empty-rhs): merge leaves the gap unchanged.
        let with_empty = lhs.clone().merge(&empty_hist);
        assert_eq!(with_empty.unobserved_cells(), lhs.unobserved_cells());
    }
}

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
}

impl ClosedAxis for PartitionFace {
    const ALL: &'static [Self] = Self::ALL;
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
        AttributionAxis, AttributionConfidence, AttributionCoordinates, AttributionRule,
        AttributionSourceKindCoordinates, ConfigSourceKind, ErrorLocalizationCoordinates,
        FieldPathLocalization, FigmentSourceKind, Format, FormatCoordinates, FormatProvenance,
        ShikumiErrorKind,
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
    /// enum — the ten closed-enum axis primitives the typescape
    /// recognizes today, in declaration order. [`PartitionFace`] sits
    /// at the tail as the cube-derived axis (the variant-tag projection
    /// of [`PartitionOrdinal`]), while the leading nine are the
    /// per-axis-of-the-cube primitives.
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
        };
    }

    /// Invokes `$cb!(TypeName)` for each [`ProductCube`] implementor —
    /// the four product cubes the typescape recognizes today, in
    /// declaration order.
    macro_rules! for_each_product_cube {
        ($cb:ident) => {
            $cb!(FormatCoordinates);
            $cb!(AttributionCoordinates);
            $cb!(ErrorLocalizationCoordinates);
            $cb!(AttributionSourceKindCoordinates);
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
    fn axis_cardinality_pins_todays_counts_across_fourteen_implementors() {
        // Ten closed-enum axis primitives. A new variant landing on
        // any of these enums extends the expected count in lockstep.
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
        // Four product cubes. A new cell-axis landing on any cube
        // extends the expected count by the product of the new axis's
        // cardinality with the cube's prior cardinality.
        assert_axis_cardinality_matches_trait_all::<FormatCoordinates>(8);
        assert_axis_cardinality_matches_trait_all::<AttributionCoordinates>(12);
        assert_axis_cardinality_matches_trait_all::<ErrorLocalizationCoordinates>(18);
        assert_axis_cardinality_matches_trait_all::<AttributionSourceKindCoordinates>(9);
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
    fn for_each_closed_axis_primitive_macro_covers_ten_axes() {
        // Pin that the macro expands to exactly ten arms — the ten
        // closed-enum axis primitives the typescape recognizes today
        // (the nine per-axis-of-the-cube primitives plus
        // `PartitionFace`, the variant-tag projection of
        // `PartitionOrdinal`). An eleventh axis primitive landing
        // extends the macro in lockstep with the `impl ClosedAxis`
        // declaration; this assertion fails until the macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_closed_axis_primitive!(tally);
        assert_eq!(
            count, 10,
            "for_each_closed_axis_primitive! must expand to ten arms",
        );
    }

    #[test]
    fn for_each_product_cube_macro_covers_four_cubes() {
        // Pin that the macro expands to exactly four arms — the four
        // product cubes the typescape recognizes today. A fifth cube
        // landing extends the macro in lockstep with the `impl
        // ProductCube` declaration; this assertion fails until the
        // macro arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_product_cube!(tally);
        assert_eq!(count, 4, "for_each_product_cube! must expand to four arms");
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
    fn for_each_closed_axis_implementor_macro_covers_fourteen_types() {
        // Pin that the superset macro expands to exactly fourteen arms
        // — the ten axis primitives plus the four product cubes. An
        // eleventh axis primitive OR a fifth cube landing extends the
        // composed macro in lockstep through one of its two component
        // macros; this assertion fails until the arm lands.
        let mut count = 0usize;
        macro_rules! tally {
            ($ty:ident) => {
                count += 1;
            };
        }
        for_each_closed_axis_implementor!(tally);
        assert_eq!(
            count, 14,
            "for_each_closed_axis_implementor! must expand to fourteen arms (10 axes + 4 cubes)",
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
        // 10-axis sum: Format=4, FormatProvenance=2, ConfigSourceKind=3,
        // FigmentSourceKind=3, ShikumiErrorKind=6, FieldPathLocalization=3,
        // AttributionRule=5, AttributionConfidence=2, AttributionAxis=2,
        // PartitionFace=2 → 32.
        // 4-cube sum: FormatCoordinates=8, AttributionCoordinates=12,
        // ErrorLocalizationCoordinates=18, AttributionSourceKindCoordinates=9
        // → 47. Grand total 32+47 = 79.
        assert_eq!(
            total, 79,
            "macro must emit each implementor exactly once \
             (today's axis_cardinality checksum is 79)",
        );
    }
}

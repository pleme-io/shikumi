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
        AttributionCoordinates, AttributionSourceKindCoordinates, ErrorLocalizationCoordinates,
        FormatCoordinates,
    };

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

    use crate::{
        AttributionAxis, AttributionConfidence, AttributionRule, ConfigSourceKind,
        FieldPathLocalization, FigmentSourceKind, Format, FormatProvenance, ShikumiErrorKind,
    };

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

    // ---- axis_iter agrees with trait ALL for every implementor ----

    #[test]
    fn axis_iter_matches_trait_all_for_every_closed_enum_axis() {
        assert_axis_iter_matches_trait_all::<Format>();
        assert_axis_iter_matches_trait_all::<FormatProvenance>();
        assert_axis_iter_matches_trait_all::<ConfigSourceKind>();
        assert_axis_iter_matches_trait_all::<FigmentSourceKind>();
        assert_axis_iter_matches_trait_all::<ShikumiErrorKind>();
        assert_axis_iter_matches_trait_all::<FieldPathLocalization>();
        assert_axis_iter_matches_trait_all::<AttributionRule>();
        assert_axis_iter_matches_trait_all::<AttributionConfidence>();
        assert_axis_iter_matches_trait_all::<AttributionAxis>();
    }

    #[test]
    fn axis_iter_matches_trait_all_for_every_product_cube() {
        assert_axis_iter_matches_trait_all::<FormatCoordinates>();
        assert_axis_iter_matches_trait_all::<AttributionCoordinates>();
        assert_axis_iter_matches_trait_all::<ErrorLocalizationCoordinates>();
        assert_axis_iter_matches_trait_all::<AttributionSourceKindCoordinates>();
    }

    // ---- axis_cardinality pins today's variant / cell counts ----

    #[test]
    fn axis_cardinality_pins_todays_counts_across_thirteen_implementors() {
        // Nine closed-enum axis primitives. A new variant landing on
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
        // Nine closed-enum axis primitives.
        assert_axis_ordinal_round_trips::<Format>();
        assert_axis_ordinal_round_trips::<FormatProvenance>();
        assert_axis_ordinal_round_trips::<ConfigSourceKind>();
        assert_axis_ordinal_round_trips::<FigmentSourceKind>();
        assert_axis_ordinal_round_trips::<ShikumiErrorKind>();
        assert_axis_ordinal_round_trips::<FieldPathLocalization>();
        assert_axis_ordinal_round_trips::<AttributionRule>();
        assert_axis_ordinal_round_trips::<AttributionConfidence>();
        assert_axis_ordinal_round_trips::<AttributionAxis>();
        // Four product cubes.
        assert_axis_ordinal_round_trips::<FormatCoordinates>();
        assert_axis_ordinal_round_trips::<AttributionCoordinates>();
        assert_axis_ordinal_round_trips::<ErrorLocalizationCoordinates>();
        assert_axis_ordinal_round_trips::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn axis_ordinal_injective_for_every_closed_axis_implementor() {
        // Nine closed-enum axis primitives.
        assert_axis_ordinal_injective::<Format>();
        assert_axis_ordinal_injective::<FormatProvenance>();
        assert_axis_ordinal_injective::<ConfigSourceKind>();
        assert_axis_ordinal_injective::<FigmentSourceKind>();
        assert_axis_ordinal_injective::<ShikumiErrorKind>();
        assert_axis_ordinal_injective::<FieldPathLocalization>();
        assert_axis_ordinal_injective::<AttributionRule>();
        assert_axis_ordinal_injective::<AttributionConfidence>();
        assert_axis_ordinal_injective::<AttributionAxis>();
        // Four product cubes.
        assert_axis_ordinal_injective::<FormatCoordinates>();
        assert_axis_ordinal_injective::<AttributionCoordinates>();
        assert_axis_ordinal_injective::<ErrorLocalizationCoordinates>();
        assert_axis_ordinal_injective::<AttributionSourceKindCoordinates>();
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
        assert_endpoints::<Format>();
        assert_endpoints::<FormatProvenance>();
        assert_endpoints::<ConfigSourceKind>();
        assert_endpoints::<FigmentSourceKind>();
        assert_endpoints::<ShikumiErrorKind>();
        assert_endpoints::<FieldPathLocalization>();
        assert_endpoints::<AttributionRule>();
        assert_endpoints::<AttributionConfidence>();
        assert_endpoints::<AttributionAxis>();
        assert_endpoints::<FormatCoordinates>();
        assert_endpoints::<AttributionCoordinates>();
        assert_endpoints::<ErrorLocalizationCoordinates>();
        assert_endpoints::<AttributionSourceKindCoordinates>();
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
        // Nine closed-enum axis primitives.
        assert_axis_at_round_trips_value_side::<Format>();
        assert_axis_at_round_trips_value_side::<FormatProvenance>();
        assert_axis_at_round_trips_value_side::<ConfigSourceKind>();
        assert_axis_at_round_trips_value_side::<FigmentSourceKind>();
        assert_axis_at_round_trips_value_side::<ShikumiErrorKind>();
        assert_axis_at_round_trips_value_side::<FieldPathLocalization>();
        assert_axis_at_round_trips_value_side::<AttributionRule>();
        assert_axis_at_round_trips_value_side::<AttributionConfidence>();
        assert_axis_at_round_trips_value_side::<AttributionAxis>();
        // Four product cubes.
        assert_axis_at_round_trips_value_side::<FormatCoordinates>();
        assert_axis_at_round_trips_value_side::<AttributionCoordinates>();
        assert_axis_at_round_trips_value_side::<ErrorLocalizationCoordinates>();
        assert_axis_at_round_trips_value_side::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn axis_at_round_trips_ordinal_side_for_every_closed_axis_implementor() {
        // Nine closed-enum axis primitives.
        assert_axis_at_round_trips_ordinal_side::<Format>();
        assert_axis_at_round_trips_ordinal_side::<FormatProvenance>();
        assert_axis_at_round_trips_ordinal_side::<ConfigSourceKind>();
        assert_axis_at_round_trips_ordinal_side::<FigmentSourceKind>();
        assert_axis_at_round_trips_ordinal_side::<ShikumiErrorKind>();
        assert_axis_at_round_trips_ordinal_side::<FieldPathLocalization>();
        assert_axis_at_round_trips_ordinal_side::<AttributionRule>();
        assert_axis_at_round_trips_ordinal_side::<AttributionConfidence>();
        assert_axis_at_round_trips_ordinal_side::<AttributionAxis>();
        // Four product cubes.
        assert_axis_at_round_trips_ordinal_side::<FormatCoordinates>();
        assert_axis_at_round_trips_ordinal_side::<AttributionCoordinates>();
        assert_axis_at_round_trips_ordinal_side::<ErrorLocalizationCoordinates>();
        assert_axis_at_round_trips_ordinal_side::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn axis_at_returns_none_on_out_of_range_for_every_closed_axis_implementor() {
        // Nine closed-enum axis primitives.
        assert_axis_at_none_on_out_of_range::<Format>();
        assert_axis_at_none_on_out_of_range::<FormatProvenance>();
        assert_axis_at_none_on_out_of_range::<ConfigSourceKind>();
        assert_axis_at_none_on_out_of_range::<FigmentSourceKind>();
        assert_axis_at_none_on_out_of_range::<ShikumiErrorKind>();
        assert_axis_at_none_on_out_of_range::<FieldPathLocalization>();
        assert_axis_at_none_on_out_of_range::<AttributionRule>();
        assert_axis_at_none_on_out_of_range::<AttributionConfidence>();
        assert_axis_at_none_on_out_of_range::<AttributionAxis>();
        // Four product cubes.
        assert_axis_at_none_on_out_of_range::<FormatCoordinates>();
        assert_axis_at_none_on_out_of_range::<AttributionCoordinates>();
        assert_axis_at_none_on_out_of_range::<ErrorLocalizationCoordinates>();
        assert_axis_at_none_on_out_of_range::<AttributionSourceKindCoordinates>();
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
        assert_pointwise::<Format>();
        assert_pointwise::<FormatProvenance>();
        assert_pointwise::<ConfigSourceKind>();
        assert_pointwise::<FigmentSourceKind>();
        assert_pointwise::<ShikumiErrorKind>();
        assert_pointwise::<FieldPathLocalization>();
        assert_pointwise::<AttributionRule>();
        assert_pointwise::<AttributionConfidence>();
        assert_pointwise::<AttributionAxis>();
        assert_pointwise::<FormatCoordinates>();
        assert_pointwise::<AttributionCoordinates>();
        assert_pointwise::<ErrorLocalizationCoordinates>();
        assert_pointwise::<AttributionSourceKindCoordinates>();
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
        assert_axis_iter_recovers_partition::<FormatCoordinates>();
        assert_axis_iter_recovers_partition::<AttributionCoordinates>();
        assert_axis_iter_recovers_partition::<ErrorLocalizationCoordinates>();
        assert_axis_iter_recovers_partition::<AttributionSourceKindCoordinates>();
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
        assert_realizable_ordinal_some_iff_is_realizable::<FormatCoordinates>();
        assert_realizable_ordinal_some_iff_is_realizable::<AttributionCoordinates>();
        assert_realizable_ordinal_some_iff_is_realizable::<ErrorLocalizationCoordinates>();
        assert_realizable_ordinal_some_iff_is_realizable::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn realizable_at_some_iff_in_realizable_prefix() {
        assert_realizable_at_some_iff_in_realizable_prefix::<FormatCoordinates>();
        assert_realizable_at_some_iff_in_realizable_prefix::<AttributionCoordinates>();
        assert_realizable_at_some_iff_in_realizable_prefix::<ErrorLocalizationCoordinates>();
        assert_realizable_at_some_iff_in_realizable_prefix::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn realizable_round_trips_cell_side() {
        assert_realizable_round_trips_cell_side::<FormatCoordinates>();
        assert_realizable_round_trips_cell_side::<AttributionCoordinates>();
        assert_realizable_round_trips_cell_side::<ErrorLocalizationCoordinates>();
        assert_realizable_round_trips_cell_side::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn realizable_round_trips_ordinal_side() {
        assert_realizable_round_trips_ordinal_side::<FormatCoordinates>();
        assert_realizable_round_trips_ordinal_side::<AttributionCoordinates>();
        assert_realizable_round_trips_ordinal_side::<ErrorLocalizationCoordinates>();
        assert_realizable_round_trips_ordinal_side::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn realizable_at_image_is_realizable() {
        assert_realizable_at_image_is_realizable::<FormatCoordinates>();
        assert_realizable_at_image_is_realizable::<AttributionCoordinates>();
        assert_realizable_at_image_is_realizable::<ErrorLocalizationCoordinates>();
        assert_realizable_at_image_is_realizable::<AttributionSourceKindCoordinates>();
    }

    #[test]
    fn realizable_ordinal_image_equals_realizable_prefix() {
        assert_realizable_ordinal_image_equals_realizable_prefix::<FormatCoordinates>();
        assert_realizable_ordinal_image_equals_realizable_prefix::<AttributionCoordinates>();
        assert_realizable_ordinal_image_equals_realizable_prefix::<ErrorLocalizationCoordinates>();
        assert_realizable_ordinal_image_equals_realizable_prefix::<AttributionSourceKindCoordinates>(
        );
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
        assert_forward_image_equals_realizable::<FormatCoordinates>();
        assert_forward_image_equals_realizable::<AttributionCoordinates>();
    }

    #[test]
    fn forward_iter_cardinality_equals_image_all_cardinality() {
        // forward_iter::<C>() iterates Image::ALL once with no filter,
        // so its length equals the image axis cardinality. By the
        // bijection invariant, that also equals realizable_count::<C>().
        // Two readings of the same number pinned in lockstep across
        // every implementor.
        assert_eq!(
            forward_iter::<FormatCoordinates>().count(),
            axis_cardinality::<<FormatCoordinates as PartialInverseCube>::Image>(),
        );
        assert_eq!(
            forward_iter::<FormatCoordinates>().count(),
            realizable_count::<FormatCoordinates>(),
        );
        assert_eq!(
            forward_iter::<AttributionCoordinates>().count(),
            axis_cardinality::<<AttributionCoordinates as PartialInverseCube>::Image>(),
        );
        assert_eq!(
            forward_iter::<AttributionCoordinates>().count(),
            realizable_count::<AttributionCoordinates>(),
        );
    }
}

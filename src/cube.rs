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

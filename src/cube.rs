//! Product-cube discipline trait — closes the realizability surface
//! across the four typescape product cubes
//! ([`crate::FormatCoordinates`], [`crate::AttributionCoordinates`],
//! [`crate::ErrorLocalizationCoordinates`],
//! [`crate::AttributionSourceKindCoordinates`]) under one trait
//! interface.
//!
//! Every product cube on the typescape primitive set shares two
//! structural invariants by hand-discipline:
//!
//! 1. A closed `Self::ALL: &'static [Self]` slice enumerating every
//!    cell of the product space, in declaration order, with cardinality
//!    pinned as the product of the constituent axis cardinalities.
//! 2. A `fn is_realizable(self) -> bool` membership predicate over the
//!    subset of cells some recognized typescape value occupies, with
//!    the realizable cells partitioning `ALL` into the recognized image
//!    and the cross-axis consistency-violation complement.
//!
//! Both invariants are unified here as one [`ProductCube`] trait. Each
//! cube implements the trait by re-exporting its inherent `ALL`
//! constant and its inherent `is_realizable` method through the trait
//! interface. A fifth product cube landing on the typescape primitive
//! set (e.g. a future `(figment_source_kind × axis × confidence)` cube
//! refining the source-axis attribution rule space, or a
//! `(format × name_style)` cube refining the discovery axis) is
//! required by the compiler to provide both invariants once it
//! `impl ProductCube for NewCube { … }` — the discipline becomes
//! structural rather than convention-by-naming.
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

/// Closed discipline trait every typescape product cube satisfies.
///
/// A product cube is a `Copy + Eq + Hash + #[non_exhaustive]` struct
/// whose fields are typescape axis primitives (each itself a closed
/// `#[non_exhaustive]` enum with its own `::ALL` constant), enumerating
/// every cell of the structural Cartesian product over the axis
/// constituent enums.
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
/// The trait bounds (`Copy + Eq + Hash + 'static`) match the hand-
/// disciplined `derive`-set on every existing implementor, so the
/// abstraction is zero-overhead: generic helpers re-use the same
/// `Copy`-by-value receiver pattern as the per-cube inherent methods.
///
/// `Sized` is implied by the `Self`-by-value trait methods; the
/// `'static` bound is required by `const ALL: &'static [Self]`. The
/// trait is intentionally not object-safe (`const` items + `Self`-by-
/// value method) — consumers route generically over the cube type
/// parameter, not over `dyn ProductCube` trait objects.
pub trait ProductCube: Copy + Eq + Hash + 'static {
    /// Every cell of the product cube, in declaration order over the
    /// constituent axis `::ALL` slices (outermost axis outermost).
    ///
    /// Mirror of the inherent `Self::ALL` constant every implementor
    /// already exposes. The trait re-export lets generic helpers
    /// (`realizable_iter`, `realizable_count`, future cube-cover
    /// dashboards) reach the constant without naming the concrete cube
    /// type — the per-cube `inherent_all_matches_trait_all` tests pin
    /// the two slices to the same contents pointwise.
    const ALL: &'static [Self];

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
/// (`Copy + Eq + Hash + 'static + Debug` matching the typescape-axis
/// primitives) so generic helpers ([`realizable_images`]) can iterate
/// the image without naming the concrete cube type. The required
/// invariant — pinned by the test
/// [`tests::partial_inverse_some_iff_is_realizable`] across all
/// implementors — is
/// `cell.invert().is_some() == ProductCube::is_realizable(cell)`,
/// closing the structural agreement between the partial-inverse-
/// `Some` domain and the realizability predicate that today's two
/// implementors satisfy by hand-discipline.
///
/// A third (or fourth) implementor landing — a future
/// `(figment_source_kind × axis × confidence)` refinement cube with a
/// bijection to a source-axis rule subset, or a `(format ×
/// name_style)` discovery refinement cube with a bijection to a typed
/// discovery-key envelope — picks up the discipline and the generic
/// helpers at the `impl PartialInverseCube` declaration, with the
/// invariant enforced by the same trait-uniform test reaching every
/// implementor pointwise.
pub trait PartialInverseCube: ProductCube {
    /// The recognized-image type — the typescape value the partial
    /// inverse re-hydrates on realizable cells (`Format` for
    /// [`crate::FormatCoordinates`], `AttributionRule` for
    /// [`crate::AttributionCoordinates`]).
    ///
    /// `Copy + Eq + Hash + 'static`: matches the typescape-axis
    /// primitive discipline so generic image consumers route by value
    /// without lifetime gymnastics. `Debug` is included so generic
    /// invariant tests can `assert_eq!` against image values without
    /// per-implementor harness boilerplate.
    type Image: Copy + Eq + std::fmt::Debug + 'static;

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
}

/// Iterate the realized images of a [`PartialInverseCube`] — the
/// `Some` outputs of [`PartialInverseCube::invert`] over [`ProductCube::ALL`],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AttributionCoordinates, AttributionSourceKindCoordinates, ErrorLocalizationCoordinates,
        FormatCoordinates,
    };

    // ---- Trait re-exports match inherent constants/methods pointwise ----

    fn assert_trait_matches_inherent<C>(inherent_all: &[C])
    where
        C: ProductCube + std::fmt::Debug,
    {
        // The trait ALL is the same slice (by content, in the same
        // order) as the inherent ALL — pointwise equality across the
        // whole cube.
        assert_eq!(
            <C as ProductCube>::ALL.len(),
            inherent_all.len(),
            "trait ALL cardinality must equal inherent ALL cardinality",
        );
        for (i, (trait_cell, inherent_cell)) in <C as ProductCube>::ALL
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
        assert!(!<FormatCoordinates as ProductCube>::ALL.is_empty());
        assert!(!<AttributionCoordinates as ProductCube>::ALL.is_empty());
        assert!(!<ErrorLocalizationCoordinates as ProductCube>::ALL.is_empty());
        assert!(!<AttributionSourceKindCoordinates as ProductCube>::ALL.is_empty());
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
        for cell in <C as ProductCube>::ALL.iter().copied() {
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

    #[test]
    fn format_coordinates_realizable_images_equals_format_all() {
        // For an injective forward map (Format::format_coordinates is
        // injective on Format::ALL), the realizable-images iterator
        // produces every Format exactly once. Pins that the partial
        // inverse covers Format::ALL pointwise.
        use std::collections::HashSet;
        let images: HashSet<crate::Format> = realizable_images::<FormatCoordinates>().collect();
        let expected: HashSet<crate::Format> = crate::Format::ALL.iter().copied().collect();
        assert_eq!(
            images, expected,
            "realizable_images::<FormatCoordinates>() must equal Format::ALL as a set",
        );
    }

    #[test]
    fn attribution_coordinates_realizable_images_equals_rule_all() {
        // Same discipline for the AttributionCoordinates cube:
        // AttributionRule::coordinates is injective on
        // AttributionRule::ALL, so the realizable-images iterator
        // produces every AttributionRule exactly once.
        use std::collections::HashSet;
        let images: HashSet<crate::AttributionRule> =
            realizable_images::<AttributionCoordinates>().collect();
        let expected: HashSet<crate::AttributionRule> =
            crate::AttributionRule::ALL.iter().copied().collect();
        assert_eq!(
            images, expected,
            "realizable_images::<AttributionCoordinates>() must equal AttributionRule::ALL as a set",
        );
    }
}

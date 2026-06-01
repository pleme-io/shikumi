//! Declarative macros over the closed-axis / product-cube / tiered-config
//! discipline — `perm_cube!` and `tiered_permutation_test!`.
//!
//! # `perm_cube!`
//!
//! [`crate::ProductCube`] is a *closed-discipline trait*, not a generic
//! builder: every product cube the typescape ships
//! ([`crate::FormatCoordinates`], [`crate::AttributionCoordinates`], …)
//! is a hand-authored `#[non_exhaustive]` struct with a hand-written
//! `const ALL: &'static [Self]` enumerating the Cartesian product of its
//! sibling axes plus a hand-written `impl ClosedAxis` / `impl
//! ProductCube`. There is NO `Cube::axes(A::ALL, B::ALL, …)` API.
//!
//! `perm_cube!` mechanically emits that bespoke-struct-per-cube
//! boilerplate for the common case where the axes are **independent**
//! (every cell realizable). Given a list of `field: Axis` pairs over
//! [`ClosedAxis`][crate::ClosedAxis] enums, it emits:
//!
//! - a `#[derive(Copy, Eq, Hash)]` product struct with one field per axis,
//! - `const CARDINALITY: usize` = the product of the axis cardinalities,
//! - `const ALL: [Self; CARDINALITY]` = the full Cartesian product in
//!   lexicographic order (first field outermost), computed at const-eval
//!   time via mixed-radix index decomposition (no nested loops, any N),
//! - `impl ClosedAxis for Self` (trait `ALL` = the inherent `ALL` slice),
//! - `impl ProductCube for Self` with `is_realizable(self) -> bool { true }`
//!   — every cell is realizable for independent axes.
//!
//! ```
//! use shikumi::{perm_cube, ClosedAxis, axis_cardinality};
//!
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
//! enum CursorStyle { Block, Bar, Underline }
//! impl ClosedAxis for CursorStyle {
//!     const ALL: &'static [Self] = &[Self::Block, Self::Bar, Self::Underline];
//! }
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
//! enum TearRuntime { Embedded, Daemon }
//! impl ClosedAxis for TearRuntime {
//!     const ALL: &'static [Self] = &[Self::Embedded, Self::Daemon];
//! }
//!
//! perm_cube!(MadoCube { cursor: CursorStyle, runtime: TearRuntime });
//! assert_eq!(axis_cardinality::<MadoCube>(), 6); // 3 × 2
//! ```
//!
//! # `tiered_permutation_test!`
//!
//! Fuses (a) cube iteration, (b) the three-tier loop
//! (`bare` / `discovered` / `prescribed_default`), (c) a per-cell serde
//! round-trip, (d) a user `apply(config, cell) -> config` closure, and
//! (e) failure-aggregation-before-assert into ONE matrix `#[test]` —
//! the CLOSED-LOOP MASS-SYNTHESIS "verification matrix as forcing
//! function" rule applied to the config space. Every shikumi-typed fleet
//! tool (mado/tear/frost/tend/kikai/kurage/namimado) wants exactly this;
//! it is a fleet-wide config-test primitive, not a one-off.
//!
//! The optional `coverage = &[...]` arm additionally runs
//! [`crate::ConfigCoverage::assert_every_field_consumed`] so the same
//! test surfaces dead config knobs.
//!
//! ```
//! use shikumi::{perm_cube, tiered_permutation_test, ClosedAxis, TieredConfig};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
//! enum Mode { A, B }
//! impl ClosedAxis for Mode { const ALL: &'static [Self] = &[Self::A, Self::B]; }
//!
//! perm_cube!(Cube { mode: Mode });
//!
//! #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//! struct Cfg { mode: Mode, name: String }
//! impl TieredConfig for Cfg {
//!     fn bare() -> Self { Self { mode: Mode::A, name: String::new() } }
//!     fn prescribed_default() -> Self { Self { mode: Mode::B, name: "d".into() } }
//! }
//!
//! tiered_permutation_test! {
//!     name = cfg_permutations,
//!     config = Cfg,
//!     cube = Cube,
//!     apply = |mut c: Cfg, cell: Cube| -> Cfg { c.mode = cell.mode; c },
//! }
//! ```

/// Mechanically emit a [`crate::ProductCube`] over independent
/// [`crate::ClosedAxis`] enums — the product struct + `const ALL`
/// (full Cartesian product) + `impl ClosedAxis` + `impl ProductCube`.
///
/// See the [module docs][self] for the full contract and an example.
///
/// **Cardinality + ordering.** `Self::CARDINALITY` is the product of the
/// per-axis cardinalities; `Self::ALL` lays the cells in lexicographic
/// order (first declared field outermost, last innermost) — identical to
/// the nested `for a in A::ALL { for b in B::ALL { … } }` product. The
/// cell at flat index `idx` decomposes by mixed-radix: each field reads
/// `Axis::ALL[(idx / radix) % Axis::ALL.len()]` where `radix` is the
/// product of the cardinalities of the axes to its right (computed
/// forward as `CARDINALITY / running_prefix_product`).
///
/// **Realizability.** Every cell is realizable (`is_realizable → true`)
/// because the axes are treated as independent. A cube with cross-axis
/// consistency constraints (some cells unrealizable) is a hand-authored
/// `ProductCube` — `perm_cube!` deliberately does not model it.
#[macro_export]
macro_rules! perm_cube {
    ( $(#[$meta:meta])* $name:ident { $( $field:ident : $axis:ty ),+ $(,)? } ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            $( pub $field : $axis ),+
        }

        impl $name {
            /// Product of the per-axis cardinalities — the number of cells.
            pub const CARDINALITY: usize =
                1 $( * <$axis as $crate::ClosedAxis>::ALL.len() )+;

            /// Every cell of the Cartesian product, in lexicographic
            /// order (first field outermost). Computed at const-eval time
            /// via mixed-radix index decomposition.
            pub const ALL: [Self; Self::CARDINALITY] = {
                let mut __out = [
                    $name { $( $field: <$axis as $crate::ClosedAxis>::ALL[0] ),+ };
                    Self::CARDINALITY
                ];
                let mut __idx = 0usize;
                while __idx < Self::CARDINALITY {
                    // Forward prefix-inclusive product → each field's radix
                    // is `CARDINALITY / prefix`, i.e. the product of the
                    // cardinalities of the axes to its right.
                    let mut __prefix = 1usize;
                    __out[__idx] = $name {
                        $( $field: {
                            __prefix *= <$axis as $crate::ClosedAxis>::ALL.len();
                            let __radix = Self::CARDINALITY / __prefix;
                            <$axis as $crate::ClosedAxis>::ALL
                                [(__idx / __radix) % <$axis as $crate::ClosedAxis>::ALL.len()]
                        } ),+
                    };
                    __idx += 1;
                }
                __out
            };
        }

        impl $crate::ClosedAxis for $name {
            const ALL: &'static [Self] = &$name::ALL;
        }

        impl $crate::ProductCube for $name {
            #[inline]
            fn is_realizable(self) -> bool {
                // Independent axes ⇒ every cell realizable.
                true
            }
        }
    };
}

/// Emit ONE matrix `#[test]` that stamps every cube cell onto every
/// config tier, serde-round-trips each, runs a user `apply` closure, and
/// aggregates EVERY failure before asserting.
///
/// See the [module docs][self] for the full contract and an example.
///
/// Forms:
///
/// ```ignore
/// tiered_permutation_test! {
///     name   = my_test,
///     config = MyConfig,        // : TieredConfig + Serialize + Deserialize + PartialEq
///     cube   = MyCube,          // : ClosedAxis (typically via perm_cube!)
///     apply  = |cfg, cell| ...,  // Fn(MyConfig, MyCube) -> MyConfig
/// }
///
/// // …with a fused ConfigCoverage gate:
/// tiered_permutation_test! {
///     name     = my_test,
///     config   = MyConfig,
///     cube     = MyCube,
///     apply    = |cfg, cell| ...,
///     coverage = &["window.width", "appearance.theme"],  // consumed leaf paths
/// }
/// ```
///
/// The test fails (with an aggregated, per-cell report) if any cell fails
/// to serialize, fails to deserialize, or is not round-trip-idempotent.
/// With `coverage`, it also asserts every declared config leaf is
/// consumed (and vice versa) via
/// [`crate::ConfigCoverage::assert_every_field_consumed`].
#[macro_export]
macro_rules! tiered_permutation_test {
    // Core form (no coverage gate).
    (
        $(#[$meta:meta])*
        name   = $name:ident,
        config = $cfg:ty,
        cube   = $cube:ty,
        apply  = $apply:expr $(,)?
    ) => {
        $(#[$meta])*
        #[test]
        fn $name() {
            $crate::__tiered_permutation_run::<$cfg, $cube, _>($apply);
        }
    };

    // Fused-coverage form.
    (
        $(#[$meta:meta])*
        name     = $name:ident,
        config   = $cfg:ty,
        cube     = $cube:ty,
        apply    = $apply:expr,
        coverage = $consumed:expr $(,)?
    ) => {
        $(#[$meta])*
        #[test]
        fn $name() {
            $crate::__tiered_permutation_run::<$cfg, $cube, _>($apply);
            $crate::ConfigCoverage::assert_every_field_consumed::<$cfg>($consumed);
        }
    };
}

/// Backing runner for [`tiered_permutation_test!`]. Kept as a real `fn`
/// (not inlined into the macro) so the heavy logic lives in a typed,
/// independently-testable surface; the macro is the thin authoring shell.
///
/// Iterates every `(tier, cell)` pair, applies `apply` to a fresh
/// per-tier base config, serde-round-trips the result, and aggregates
/// every failure before panicking with a per-cell report. Generic over
/// the config type `C`, the cube axis type `K`, and the apply closure.
///
/// # Panics
///
/// Panics with an aggregated multi-line report if any permutation fails
/// to serialize, deserialize, or round-trip idempotently.
pub fn __tiered_permutation_run<C, K, F>(apply: F)
where
    C: crate::TieredConfig + serde::Serialize + serde::de::DeserializeOwned,
    K: crate::ClosedAxis + std::fmt::Debug,
    F: Fn(C, K) -> C,
{
    let tiers: [(&str, fn() -> C); 3] = [
        ("bare", <C as crate::TieredConfig>::bare),
        ("discovered", <C as crate::TieredConfig>::discovered),
        (
            "prescribed_default",
            <C as crate::TieredConfig>::prescribed_default,
        ),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (tier_name, tier_fn) in tiers {
        for cell in crate::axis_iter::<K>() {
            let base = tier_fn();
            let cfg: C = apply(base, cell);
            let yaml = match serde_yaml::to_string(&cfg) {
                Ok(y) => y,
                Err(e) => {
                    failures.push(format!("tier={tier_name} cell={cell:?}: serialize: {e}"));
                    continue;
                }
            };
            let back: C = match serde_yaml::from_str(&yaml) {
                Ok(b) => b,
                Err(e) => {
                    failures.push(format!("tier={tier_name} cell={cell:?}: deserialize: {e}"));
                    continue;
                }
            };
            match serde_yaml::to_string(&back) {
                Ok(y2) if y2 == yaml => {}
                Ok(_) => failures.push(format!(
                    "tier={tier_name} cell={cell:?}: serde round-trip not idempotent"
                )),
                Err(e) => {
                    failures.push(format!("tier={tier_name} cell={cell:?}: re-serialize: {e}"));
                }
            }
        }
    }
    let total = K::ALL.len() * tiers.len();
    assert!(
        failures.is_empty(),
        "{}/{total} config permutations failed:\n  - {}",
        failures.len(),
        failures.join("\n  - "),
    );
}

#[cfg(test)]
// The test axis enums are module-private; `perm_cube!` emits `pub`
// cube structs (the right contract for real public config enums), so
// the private test axes trip `private_interfaces`. Real consumers use
// public axes — no warning there.
#[allow(private_interfaces)]
mod tests {
    use crate::{ClosedAxis, ProductCube, TieredConfig, axis_cardinality, axis_iter};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    enum CursorStyle {
        Block,
        Bar,
        Underline,
    }
    impl ClosedAxis for CursorStyle {
        const ALL: &'static [Self] = &[Self::Block, Self::Bar, Self::Underline];
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    enum TearRuntime {
        Embedded,
        Daemon,
    }
    impl ClosedAxis for TearRuntime {
        const ALL: &'static [Self] = &[Self::Embedded, Self::Daemon];
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    enum Edge {
        Top,
        Bottom,
        Left,
        Right,
        Center,
    }
    impl ClosedAxis for Edge {
        const ALL: &'static [Self] = &[
            Self::Top,
            Self::Bottom,
            Self::Left,
            Self::Right,
            Self::Center,
        ];
    }

    // 3 × 2 × 5 = 30-cell cube.
    perm_cube!(TestCube {
        cursor: CursorStyle,
        runtime: TearRuntime,
        edge: Edge,
    });

    #[test]
    fn perm_cube_cardinality_is_product_of_axes() {
        assert_eq!(TestCube::CARDINALITY, 3 * 2 * 5);
        assert_eq!(axis_cardinality::<TestCube>(), 30);
        assert_eq!(TestCube::ALL.len(), 30);
        assert_eq!(<TestCube as ClosedAxis>::ALL.len(), 30);
    }

    #[test]
    fn perm_cube_all_equals_explicit_cartesian_product() {
        let mut explicit = Vec::new();
        for c in CursorStyle::ALL {
            for r in TearRuntime::ALL {
                for e in Edge::ALL {
                    explicit.push(TestCube {
                        cursor: *c,
                        runtime: *r,
                        edge: *e,
                    });
                }
            }
        }
        let via_macro: Vec<_> = axis_iter::<TestCube>().collect();
        assert_eq!(via_macro, explicit);
    }

    #[test]
    fn perm_cube_first_and_last_cells_pin_lexicographic_order() {
        let all = TestCube::ALL;
        assert_eq!(
            all[0],
            TestCube {
                cursor: CursorStyle::Block,
                runtime: TearRuntime::Embedded,
                edge: Edge::Top
            }
        );
        assert_eq!(
            all[29],
            TestCube {
                cursor: CursorStyle::Underline,
                runtime: TearRuntime::Daemon,
                edge: Edge::Center
            }
        );
    }

    #[test]
    fn perm_cube_cells_are_unique() {
        let all = TestCube::ALL;
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "duplicate cell in perm_cube ALL");
            }
        }
    }

    #[test]
    fn perm_cube_every_cell_realizable_for_independent_axes() {
        assert!(axis_iter::<TestCube>().all(ProductCube::is_realizable));
        assert_eq!(crate::realizable_count::<TestCube>(), 30);
        assert_eq!(crate::unrealizable_count::<TestCube>(), 0);
    }

    // Single-axis degenerate cube.
    perm_cube!(SingleCube { only: TearRuntime });

    #[test]
    fn perm_cube_single_axis_mirrors_the_axis() {
        assert_eq!(SingleCube::CARDINALITY, 2);
        let cells: Vec<_> = axis_iter::<SingleCube>().collect();
        assert_eq!(cells[0].only, TearRuntime::Embedded);
        assert_eq!(cells[1].only, TearRuntime::Daemon);
    }

    // tiered_permutation_test! integration.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct DemoConfig {
        cursor: CursorStyle,
        runtime: TearRuntime,
        edge: Edge,
        label: String,
    }
    impl TieredConfig for DemoConfig {
        fn bare() -> Self {
            Self {
                cursor: CursorStyle::Block,
                runtime: TearRuntime::Embedded,
                edge: Edge::Top,
                label: String::new(),
            }
        }
        fn prescribed_default() -> Self {
            Self {
                cursor: CursorStyle::Bar,
                runtime: TearRuntime::Daemon,
                edge: Edge::Center,
                label: "default".into(),
            }
        }
    }

    fn stamp(mut cfg: DemoConfig, cell: TestCube) -> DemoConfig {
        cfg.cursor = cell.cursor;
        cfg.runtime = cell.runtime;
        cfg.edge = cell.edge;
        cfg
    }

    tiered_permutation_test! {
        name = demo_config_permutations_round_trip,
        config = DemoConfig,
        cube = TestCube,
        apply = stamp,
    }

    tiered_permutation_test! {
        name = demo_config_permutations_with_coverage,
        config = DemoConfig,
        cube = TestCube,
        apply = stamp,
        // Every leaf of DemoConfig::prescribed_default() is consumed.
        coverage = &["cursor", "runtime", "edge", "label"],
    }

    // The backing runner aggregates failures before asserting — a config
    // whose serde is non-idempotent trips it with a per-cell report.
    #[test]
    #[should_panic(expected = "config permutations failed")]
    fn runner_aggregates_failures_before_assert() {
        // A config that does NOT round-trip idempotently: serialize emits
        // a growing string, so re-serialization differs. We model it with
        // an inline type whose serialize is keyed on an external toggle.
        use std::cell::Cell;
        thread_local!(static FLIP: Cell<bool> = const { Cell::new(false) });

        #[derive(Debug, Clone, PartialEq)]
        struct Flipper;
        impl Serialize for Flipper {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let v = FLIP.with(|f| {
                    let cur = f.get();
                    f.set(!cur);
                    cur
                });
                s.serialize_str(if v { "x" } else { "y" })
            }
        }
        impl<'de> Deserialize<'de> for Flipper {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let _ = <String as Deserialize>::deserialize(d)?;
                Ok(Flipper)
            }
        }
        impl TieredConfig for Flipper {
            fn bare() -> Self {
                Flipper
            }
            fn prescribed_default() -> Self {
                Flipper
            }
        }

        super::__tiered_permutation_run::<Flipper, TestCube, _>(|c, _cell: TestCube| c);
    }
}

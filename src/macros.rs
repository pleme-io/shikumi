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

/// Emit the canonical `(Display, FromStr, Serialize, Deserialize)`
/// string-surface quartet for a [`crate::ClosedAxisLabel`] implementor.
///
/// The pattern is structurally identical across every closed-axis
/// primitive that has lifted the quartet (15+ commits since `b56b121`
/// landed it on [`crate::Format`]): write the canonical label via
/// [`crate::ClosedAxisLabel::as_str`] from `Display`, parse via
/// [`crate::ClosedAxisLabel::from_canonical_str`] from `FromStr` with a
/// verbatim-label `Parse` error, route serde `Serialize` through
/// [`serde::Serializer::collect_str`] and `Deserialize` through a visitor
/// that lowers to `FromStr`. Lifting it to one macro collapses ~120 lines
/// of hand-rolled boilerplate per primitive into one invocation, makes the
/// canonical-label discipline a single source of truth, and lets every
/// future closed-axis primitive land all four surfaces in one call.
///
/// # Contract
///
/// - `$ty` must be `Copy` and implement [`crate::ClosedAxisLabel`].
/// - [`std::fmt::Display`] writes `<Self as ClosedAxisLabel>::as_str(*self)`.
/// - [`std::str::FromStr`] (`Err = crate::ShikumiError`) routes through
///   the parser — by default
///   [`crate::ClosedAxisLabel::from_canonical_str`], or an explicit
///   `parser = $expr` slot of type `Fn(&str) -> Option<Self>` (used for
///   primitives whose parse surface diverges from the rendering surface,
///   e.g. [`crate::Format`] accepting `yml`/`lsp`/`el` aliases via
///   [`crate::Format::from_extension`]); on miss returns
///   [`crate::ShikumiError::Parse`] with body
///   `format!("{}: {}", $parse_error, input)` — the offending label embeds
///   verbatim.
/// - [`serde::Serialize`] emits the canonical label via
///   [`serde::Serializer::collect_str`].
/// - [`serde::Deserialize`] reads a `str` and lowers through `FromStr`,
///   surfacing the [`crate::ShikumiError`] via [`serde::de::Error::custom`].
///   The visitor's `expecting` message is the literal `$expecting`
///   argument.
///
/// **Round-trip law** —
/// `<$ty as FromStr>::from_str(&v.to_string()) == Ok(v)` and
/// `serde_yaml::from_str::<$ty>(&serde_yaml::to_string(&v)?)? == v` for
/// every `v: $ty`, inherited from the [`crate::ClosedAxisLabel`]
/// round-trip law by construction. With an explicit `parser`, the law
/// holds iff `parser(<v as ClosedAxisLabel>::as_str()) == Some(v)` for
/// every `v: $ty` — a contract every alias-accepting parser already
/// satisfies (the canonical label is one of the parser's accepted
/// inputs).
///
/// # Example — default parser
///
/// ```
/// use shikumi::{closed_axis_label_string_surface, ClosedAxis, ClosedAxisLabel};
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// enum Mode { On, Off }
///
/// impl ClosedAxis for Mode {
///     const ALL: &'static [Self] = &[Self::On, Self::Off];
/// }
///
/// impl ClosedAxisLabel for Mode {
///     fn as_str(self) -> &'static str {
///         match self { Self::On => "on", Self::Off => "off" }
///     }
/// }
///
/// closed_axis_label_string_surface! {
///     type = Mode,
///     parse_error = "unknown mode",
///     expecting = "a canonical Mode label (`on`, `off`; case-insensitive)",
/// }
///
/// assert_eq!(format!("{}", Mode::On), "on");
/// assert_eq!("OFF".parse::<Mode>().unwrap(), Mode::Off);
/// assert_eq!(serde_yaml::to_string(&Mode::On).unwrap(), "on\n");
/// assert_eq!(serde_yaml::from_str::<Mode>("off").unwrap(), Mode::Off);
/// let err = "nope".parse::<Mode>().unwrap_err().to_string();
/// assert!(err.contains("nope"));
/// ```
///
/// # Example — explicit parser with aliases
///
/// ```
/// use shikumi::{closed_axis_label_string_surface, ClosedAxis, ClosedAxisLabel};
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// enum Tag { Yaml, Toml }
///
/// impl ClosedAxis for Tag {
///     const ALL: &'static [Self] = &[Self::Yaml, Self::Toml];
/// }
///
/// impl ClosedAxisLabel for Tag {
///     fn as_str(self) -> &'static str {
///         match self { Self::Yaml => "yaml", Self::Toml => "toml" }
///     }
/// }
///
/// impl Tag {
///     fn from_alias(s: &str) -> Option<Self> {
///         match s.to_ascii_lowercase().as_str() {
///             "yaml" | "yml" => Some(Self::Yaml),
///             "toml" => Some(Self::Toml),
///             _ => None,
///         }
///     }
/// }
///
/// closed_axis_label_string_surface! {
///     type = Tag,
///     parse_error = "unknown tag",
///     expecting = "a canonical Tag label (`yaml`, `toml`; alias `yml` accepted)",
///     parser = Tag::from_alias,
/// }
///
/// assert_eq!("yml".parse::<Tag>().unwrap(), Tag::Yaml);
/// assert_eq!("YAML".parse::<Tag>().unwrap(), Tag::Yaml);
/// ```
#[macro_export]
macro_rules! closed_axis_label_string_surface {
    // Default arm — forwards to the explicit-parser arm with the
    // canonical-label parser from `ClosedAxisLabel::from_canonical_str`.
    (
        type = $ty:ty,
        parse_error = $parse_error:expr,
        expecting = $expecting:expr $(,)?
    ) => {
        $crate::closed_axis_label_string_surface! {
            type = $ty,
            parse_error = $parse_error,
            expecting = $expecting,
            parser = <$ty as $crate::ClosedAxisLabel>::from_canonical_str,
        }
    };

    // Explicit-parser arm — `$parser` is any `Fn(&str) -> Option<Self>`
    // expression (path to an associated function, free function, or
    // closure). Primitives whose parse surface diverges from the
    // canonical-label surface (e.g. `Format` accepting `yml`/`lsp`/`el`
    // aliases) ride this arm.
    //
    // Serde is delegated to `serde_via_display_fromstr!` so the
    // `(Serialize via collect_str + Deserialize via visit_str→FromStr)`
    // shape is a single source of truth across both the closed-axis
    // cohort and the typed-composite cohort (FormatCoordinates,
    // PartitionOrdinal, the closed-axis-classifier cube primitives).
    (
        type = $ty:ty,
        parse_error = $parse_error:expr,
        expecting = $expecting:expr,
        parser = $parser:expr $(,)?
    ) => {
        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(<Self as $crate::ClosedAxisLabel>::as_str(*self))
            }
        }

        impl ::core::str::FromStr for $ty {
            type Err = $crate::ShikumiError;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                ($parser)(s).ok_or_else(|| {
                    $crate::ShikumiError::Parse(::std::format!("{}: {}", $parse_error, s,))
                })
            }
        }

        $crate::serde_via_display_fromstr! {
            type = $ty,
            expecting = $expecting,
        }
    };
}

/// Emit the canonical `(Serialize, Deserialize)` serde pair for any type
/// whose canonical scalar form is its [`std::fmt::Display`] and whose
/// canonical parse is its [`std::str::FromStr`].
///
/// The serde half of [`closed_axis_label_string_surface!`] lifted into
/// its own primitive: this macro requires nothing about the
/// [`FromStr::Err`][std::str::FromStr::Err] type beyond
/// [`std::fmt::Display`] (so [`serde::de::Error::custom`] can lower it),
/// which lets typed-composite primitives whose `FromStr` returns a
/// bespoke error variant cohort (e.g. [`crate::FormatCoordinates`]'s
/// [`crate::ParseFormatCoordinatesError`], `PartitionOrdinal`'s
/// `ParsePartitionOrdinalError`) ride the same canonical serde shape
/// the [`crate::ClosedAxisLabel`] cohort already enjoys — without
/// forcing every primitive's `FromStr::Err` onto the
/// [`crate::ShikumiError::Parse`] surface.
///
/// # Arms
///
/// The macro has two arms.
///
/// **Concrete arm** — `type = $ty:ty, expecting = $expecting:expr` —
/// the original lift. Emits the `(Serialize, Deserialize)` pair for a
/// concrete (non-generic) type. The `expecting` slot is a literal
/// `&str` expression the visitor's `expecting` method writes via
/// [`std::fmt::Formatter::write_str`]. Every closed-axis-label
/// implementor (14 primitives via [`closed_axis_label_string_surface!`])
/// plus the seven typed-composite-and-classifier primitives migrated by
/// the prior lift cycle (`ModalityClass`, `SupportCardinalityClass`,
/// `SupportBoundaryDistance`, `SupportMagnitudeDirection`,
/// `PartitionFace`, `PartitionOrdinal`, [`crate::FormatCoordinates`])
/// ride this arm.
///
/// **Generic arm** —
/// `type = $ty:ty, generics = ($($param),+), bounds = ($($bound)+),
/// expecting_fn = |$f:ident| $body:expr` — the generalized lift for
/// generic types whose `expecting` body is *computed* (uses a type
/// parameter at runtime via [`std::any::type_name`] or similar) and
/// therefore cannot be a literal `&str`. The `generics` slot lists the
/// type parameters (just the names; bounds go in the `bounds` slot —
/// e.g. `generics = (A), bounds = (A: ClosedAxisLabel)`), the
/// `expecting_fn` slot is a closure-style binder `|f| <body>` where
/// `$body` evaluates to [`std::fmt::Result`] (typically a `write!(f,
/// "…", …)` invocation reaching the generic params), and the macro
/// emits the same `(Serialize, Deserialize)` pair with `impl<$($param)+>`
/// / `impl<'de, $($param)+>` and a generic `__Visitor<$($param)+>`
/// carrying [`std::marker::PhantomData`]`<fn() -> ($($param)+)>`. The
/// only consumer today is [`crate::AxisHistogram<A>`] (whose
/// `expecting` body interpolates `std::any::type_name::<A>()` so the
/// serde error legend names the offending axis); a future lift on the
/// same shape (a generic [`crate::AttributionCoordinates`]-style
/// composite, a parameterized [`crate::ParseAxisHistogramError`]
/// wrapper) inherits the surface from one macro arm.
///
/// # Contract (both arms)
///
/// - `$ty` must implement [`std::fmt::Display`] and [`std::str::FromStr`]
///   with `<$ty as FromStr>::Err: ::core::fmt::Display`.
/// - [`serde::Serialize`] emits the canonical scalar via
///   [`serde::Serializer::collect_str`] (no intermediate allocation).
/// - [`serde::Deserialize`] reads a `str` via a visitor whose `visit_str`
///   lowers through `FromStr`, routing the typed error through
///   [`serde::de::Error::custom`]. The visitor's `expecting` writes the
///   literal `$expecting` argument (concrete arm) or evaluates the
///   `$body` expression (generic arm).
///
/// **Round-trip law** —
/// `serde_yaml::from_str::<$ty>(&serde_yaml::to_string(&v)?)? == v`
/// for every `v: $ty`, inherited from the `(Display, FromStr)`
/// round-trip law by construction.
///
/// # Example — concrete arm
///
/// ```
/// use shikumi::serde_via_display_fromstr;
/// use std::{fmt, str::FromStr};
///
/// #[derive(Debug, Clone, Copy, PartialEq)]
/// struct Hex(u8);
///
/// impl fmt::Display for Hex {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "0x{:02x}", self.0)
///     }
/// }
///
/// #[derive(Debug)]
/// struct ParseHexError(String);
/// impl fmt::Display for ParseHexError {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "not a hex byte: {:?}", self.0)
///     }
/// }
///
/// impl FromStr for Hex {
///     type Err = ParseHexError;
///     fn from_str(s: &str) -> Result<Self, Self::Err> {
///         let body = s.strip_prefix("0x").ok_or_else(|| ParseHexError(s.into()))?;
///         u8::from_str_radix(body, 16)
///             .map(Hex)
///             .map_err(|_| ParseHexError(s.into()))
///     }
/// }
///
/// serde_via_display_fromstr! {
///     type = Hex,
///     expecting = "a `0x`-prefixed hex byte (e.g. `0x2a`)",
/// }
///
/// assert_eq!(serde_yaml::to_string(&Hex(0x2a)).unwrap(), "0x2a\n");
/// assert_eq!(serde_yaml::from_str::<Hex>("0xff").unwrap(), Hex(0xff));
/// let err = serde_yaml::from_str::<Hex>("nope").unwrap_err().to_string();
/// assert!(err.contains("nope"));
/// ```
///
/// # Example — generic arm with computed `expecting`
///
/// ```
/// use shikumi::serde_via_display_fromstr;
/// use std::{fmt, marker::PhantomData, str::FromStr};
///
/// trait Tag: 'static {
///     fn label() -> &'static str;
/// }
///
/// #[derive(Debug, Clone, Copy, PartialEq)]
/// struct Yaml;
/// impl Tag for Yaml {
///     fn label() -> &'static str { "yaml" }
/// }
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct Tagged<T: Tag>(u32, PhantomData<fn() -> T>);
///
/// impl<T: Tag> Tagged<T> {
///     fn new(v: u32) -> Self { Self(v, PhantomData) }
/// }
///
/// impl<T: Tag> fmt::Display for Tagged<T> {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "{}:{}", T::label(), self.0)
///     }
/// }
///
/// #[derive(Debug)]
/// struct ParseTaggedError(String);
/// impl fmt::Display for ParseTaggedError {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "not a tagged value: {:?}", self.0)
///     }
/// }
///
/// impl<T: Tag> FromStr for Tagged<T> {
///     type Err = ParseTaggedError;
///     fn from_str(s: &str) -> Result<Self, Self::Err> {
///         let (tag, n) = s.split_once(':').ok_or_else(|| ParseTaggedError(s.into()))?;
///         if tag != T::label() { return Err(ParseTaggedError(s.into())); }
///         n.parse::<u32>().map(Tagged::new).map_err(|_| ParseTaggedError(s.into()))
///     }
/// }
///
/// serde_via_display_fromstr! {
///     type = Tagged<T>,
///     generics = (T),
///     bounds = (T: Tag),
///     expecting_fn = |f| write!(
///         f,
///         "a `<label>:<count>` tagged value for label {}",
///         T::label(),
///     ),
/// }
///
/// let v: Tagged<Yaml> = Tagged::new(42);
/// assert_eq!(serde_yaml::to_string(&v).unwrap(), "yaml:42\n");
/// let back: Tagged<Yaml> = serde_yaml::from_str("yaml:42").unwrap();
/// assert_eq!(back, v);
/// let err = serde_yaml::from_str::<Tagged<Yaml>>("nope").unwrap_err().to_string();
/// assert!(err.contains("nope"));
/// ```
#[macro_export]
macro_rules! serde_via_display_fromstr {
    // Concrete arm — non-generic type with literal `expecting`.
    (
        type = $ty:ty,
        expecting = $expecting:expr $(,)?
    ) => {
        impl ::serde::Serialize for $ty {
            fn serialize<__S: ::serde::Serializer>(
                &self,
                serializer: __S,
            ) -> ::core::result::Result<__S::Ok, __S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<__D: ::serde::Deserializer<'de>>(
                deserializer: __D,
            ) -> ::core::result::Result<Self, __D::Error> {
                struct __Visitor;

                impl ::serde::de::Visitor<'_> for __Visitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<__E: ::serde::de::Error>(
                        self,
                        v: &str,
                    ) -> ::core::result::Result<$ty, __E> {
                        v.parse::<$ty>().map_err(__E::custom)
                    }
                }

                deserializer.deserialize_str(__Visitor)
            }
        }
    };

    // Generic arm — type with type parameters and a computed
    // `expecting` body. The `expecting_fn = |f| <body>` slot binds the
    // formatter as `$f` so `$body` can reach the generic params (e.g.
    // via `write!(f, "...", ::std::any::type_name::<A>())`).
    //
    // `generics = ($($param),+)` lists the type-parameter names only;
    // `bounds = ($($bound)+)` is the full `where`-clause-style bound
    // list (e.g. `bounds = (A: ClosedAxisLabel)`).
    (
        type = $ty:ty,
        generics = ( $( $param:ident ),+ $(,)? ),
        bounds = ( $( $bound:tt )+ ),
        expecting_fn = | $f:ident | $body:expr $(,)?
    ) => {
        impl< $( $param ),+ > ::serde::Serialize for $ty
        where
            $( $bound )+
        {
            fn serialize<__S: ::serde::Serializer>(
                &self,
                serializer: __S,
            ) -> ::core::result::Result<__S::Ok, __S::Error> {
                serializer.collect_str(self)
            }
        }

        impl< 'de, $( $param ),+ > ::serde::Deserialize<'de> for $ty
        where
            $( $bound )+
        {
            fn deserialize<__D: ::serde::Deserializer<'de>>(
                deserializer: __D,
            ) -> ::core::result::Result<Self, __D::Error> {
                struct __Visitor< $( $param ),+ >(
                    ::core::marker::PhantomData<fn() -> ( $( $param, )+ )>,
                )
                where
                    $( $bound )+;

                impl< $( $param ),+ > ::serde::de::Visitor<'_> for __Visitor< $( $param ),+ >
                where
                    $( $bound )+
                {
                    type Value = $ty;

                    fn expecting(
                        &self,
                        $f: &mut ::core::fmt::Formatter<'_>,
                    ) -> ::core::fmt::Result {
                        $body
                    }

                    fn visit_str<__E: ::serde::de::Error>(
                        self,
                        v: &str,
                    ) -> ::core::result::Result<$ty, __E> {
                        v.parse::<$ty>().map_err(__E::custom)
                    }
                }

                deserializer.deserialize_str(__Visitor::< $( $param ),+ >(
                    ::core::marker::PhantomData,
                ))
            }
        }
    };
}

/// Emit the canonical
/// `(Display, FromStr, Serialize, Deserialize)` string-surface quartet
/// for a closed-axis-label primitive whose `FromStr::Err` is a bespoke
/// typed label-carrying error struct — the sibling lift of
/// [`closed_axis_label_string_surface!`] for the typed-error cohort
/// (the [`crate::ModalityClass`], [`crate::SupportCardinalityClass`],
/// [`crate::SupportBoundaryDistance`],
/// [`crate::SupportMagnitudeDirection`], and [`crate::PartitionFace`]
/// typed cube classifiers, plus any future closed-axis primitive whose
/// parse-rejection diagnostic needs a typed `Result<_, _>` shape rather
/// than the [`crate::ShikumiError::Parse`] surface the
/// [`closed_axis_label_string_surface!`] cohort routes through).
///
/// # Contract
///
/// The macro presumes the caller has already defined:
///
/// - the primitive `$ty`, with an inherent or
///   [`crate::ClosedAxisLabel`]-trait `as_str(self) -> &'static str`
///   reachable through unqualified `Self::as_str(*self)` (inherent
///   methods shadow trait methods, so both the inherent-method case and
///   the trait-only case work without disambiguation), and
/// - the typed parse-error struct `$error`, which MUST be a struct with
///   one named field `label: String` (the verbatim offending substring).
///   The struct, its derives (typically
///   `#[derive(Debug, Clone, PartialEq, Eq)]` + `#[non_exhaustive]`),
///   its rich rustdoc, and the field's docs stay hand-rolled — the
///   macro lifts only the mechanical impl scaffolding.
///
/// The macro emits, in order:
///
/// 1. [`std::fmt::Display`] for `$error`, writing
///    `"{} {:?}", $error_legend, self.label` — the same byte-string the
///    prior hand-rolled impl wrote (`write!(f, "<legend> {:?}",
///    self.label)`).
/// 2. [`std::error::Error`] for `$error` with the default empty body.
/// 3. [`std::fmt::Display`] for `$ty`, writing `Self::as_str(*self)`.
/// 4. [`std::str::FromStr`] for `$ty` with `type Err = $error`, routing
///    through `($parser)(s)` (any `Fn(&str) -> Option<Self>` expression)
///    and lifting the [`None`] case to
///    `$error { label: s.to_owned() }`.
/// 5. The serde pair via [`serde_via_display_fromstr!`] with
///    `expecting = $expecting`.
///
/// **Round-trip law** — inherited from the
/// `(as_str, $parser)` round-trip law on `$ty`: if
/// `$parser(<$ty as Self>::as_str(v)) == Some(v)` for every `v: $ty`,
/// then `v.to_string().parse::<$ty>() == Ok(v)` and
/// `serde_yaml::from_str::<$ty>(&serde_yaml::to_string(&v)?)? == v`.
///
/// # Example
///
/// ```
/// use shikumi::closed_axis_label_string_surface_typed_err;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// enum Phase { Boot, Run, Halt }
///
/// impl Phase {
///     const ALL: &'static [Self] = &[Self::Boot, Self::Run, Self::Halt];
///
///     fn as_str(self) -> &'static str {
///         match self { Self::Boot => "boot", Self::Run => "run", Self::Halt => "halt" }
///     }
///
///     fn from_canonical_str(s: &str) -> Option<Self> {
///         Self::ALL.iter().copied().find(|v| v.as_str().eq_ignore_ascii_case(s))
///     }
/// }
///
/// #[derive(Debug, Clone, PartialEq, Eq)]
/// #[non_exhaustive]
/// pub struct ParsePhaseError {
///     pub label: String,
/// }
///
/// closed_axis_label_string_surface_typed_err! {
///     type = Phase,
///     parser = Phase::from_canonical_str,
///     error = ParsePhaseError,
///     error_legend = "unknown phase label",
///     expecting = "a canonical Phase lowercase label (`boot`, `run`, `halt`)",
/// }
///
/// assert_eq!(format!("{}", Phase::Run), "run");
/// assert_eq!("HALT".parse::<Phase>().unwrap(), Phase::Halt);
/// assert_eq!(serde_yaml::to_string(&Phase::Boot).unwrap(), "boot\n");
/// assert_eq!(serde_yaml::from_str::<Phase>("run").unwrap(), Phase::Run);
/// let err = "nope".parse::<Phase>().unwrap_err();
/// assert_eq!(err.label, "nope");
/// assert!(err.to_string().contains("nope"));
/// ```
#[macro_export]
macro_rules! closed_axis_label_string_surface_typed_err {
    (
        type = $ty:ty,
        parser = $parser:expr,
        error = $error:path,
        error_legend = $error_legend:expr,
        expecting = $expecting:expr $(,)?
    ) => {
        impl ::core::fmt::Display for $error {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{} {:?}", $error_legend, self.label)
            }
        }

        impl ::std::error::Error for $error {}

        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(Self::as_str(*self))
            }
        }

        // Internal constructor on the typed error. The FromStr impl
        // below calls it via UFCS instead of constructing the struct
        // directly: a struct literal `$error { … }` would put the
        // `:path` metavariable in expression position followed by `{`,
        // which Rust's macro grammar disallows (the FOLLOW set of
        // `:path` excludes `{`, so the parser would interpret the
        // brace as a stray block opener — "struct literal body without
        // path"). Routing construction through `<$error>::…(…)` works
        // because `:path` permits `::` in FOLLOW. Named with a
        // double-underscore `__shikumi_` prefix so it can't accidentally
        // collide with user-authored inherent methods on the error
        // type, and `#[doc(hidden)]` to keep it out of the public docs.
        impl $error {
            #[doc(hidden)]
            #[inline]
            fn __shikumi_with_label(label: ::std::string::String) -> Self {
                Self { label }
            }
        }

        impl ::core::str::FromStr for $ty {
            type Err = $error;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                ($parser)(s).ok_or_else(|| <$error>::__shikumi_with_label(s.to_owned()))
            }
        }

        $crate::serde_via_display_fromstr! {
            type = $ty,
            expecting = $expecting,
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

//! Figment provider chain builder.
//!
//! Extracted from karakuri's `InnerConfig::from_figment`. Assembles a
//! layered figment configuration: defaults → env vars → config file,
//! with auto-detection of YAML vs TOML by file extension.

use std::path::Path;

use figment::{
    Error as FigmentError, Figment, Metadata, Profile,
    providers::{Env, Format as _, Serialized, Toml as FigToml, Yaml as FigYaml},
    value::{Dict, Map, Value},
};

use crate::discovery::Format;
use serde::{Deserialize, Serialize};

use crate::error::ShikumiError;
use crate::source::ConfigSource;

/// Wrap a shikumi-built provider's parsed [`figment::value::Value`] into
/// the [`Map<Profile, Dict>`] shape [`figment::Provider::data`] requires.
///
/// On [`Value::Dict`], returns `Ok({ Profile::Default => dict })` — the
/// one-shot `Map::new()` + `insert(Profile::Default, dict)` shape every
/// shikumi-built provider's `data` impl previously open-coded at its tail.
/// On any other [`Value`] variant, returns a [`FigmentError`] whose
/// message routes through [`Format::dict_required_message`] for the
/// format-specific "top-level <format> X must be Y" wording and appends
/// `"; got <other:?>"` so the operator-facing diagnostic identifies the
/// concrete shape figment received.
///
/// One source of truth for the value→provider-data projection on
/// shikumi-built providers. `LispProvider::data` (feature-gated under
/// `lisp`) and [`crate::nix_provider::NixProvider::data`] each
/// previously inlined the four-line shape — the dict-extracting
/// `match`, the format-prose error path, the `Map::new()` allocation,
/// and the `Profile::Default` key — once per provider. Lifting collapses
/// the duplication to one site beside [`ProviderChain`], the
/// consumer-facing peer that owns the layered figment composition; a
/// future shikumi-built provider class — an `HTTP` config endpoint, a
/// `Vault` secret store, a Kubernetes `ConfigMap` reader — implements
/// its own value-producing `load()` and routes its `data()` through this
/// helper, inheriting the dict-required contract and the operator-facing
/// error wording by construction.
///
/// The format argument supplies the per-format wording slot; the helper
/// itself does not parse or validate the file. Callers pass the
/// [`Format`] their provider declares (e.g. [`Format::Lisp`] for the
/// Lisp provider) so the failure path agrees with the metadata-name
/// the provider's `figment::Provider::metadata` impl already emits
/// through [`Format::metadata_name`].
// The return shape is dictated by `figment::Provider::data`; the size of
// `figment::Error` is figment's choice, not shikumi's. Boxing here would
// fork the helper's `Err` from the trait method's `Err` and force every
// call site to unbox at the trait boundary.
#[allow(clippy::result_large_err)]
pub(crate) fn provider_data_from_value(
    value: Value,
    format: Format,
) -> Result<Map<Profile, Dict>, FigmentError> {
    let dict = match value {
        Value::Dict(_, d) => d,
        other => {
            return Err(FigmentError::from(format!(
                "{}; got {other:?}",
                format.dict_required_message(),
            )));
        }
    };
    let mut map = Map::new();
    map.insert(Profile::Default, dict);
    Ok(map)
}

/// End-to-end projection from a shikumi-built provider's [`ShikumiError`]-
/// bearing load result to the [`Map<Profile, Dict>`] shape
/// [`figment::Provider::data`] requires.
///
/// Fuses the two open-coded steps every shikumi-built provider's `data`
/// impl still carried after [`provider_data_from_value`] was lifted:
///
/// 1. Convert the [`ShikumiError`] returned by the provider's `load` into
///    a [`FigmentError`] via `FigmentError::from(err.to_string())` — the
///    same string projection every consumer of a shikumi Provider observes
///    through figment's own Display path.
/// 2. Route the resulting [`Value`] through [`provider_data_from_value`]
///    for the format-typed dict-required wording.
///
/// The two consumers today — [`crate::lisp_provider::LispProvider::data`]
/// (`lisp` feature) and [`crate::nix_provider::NixProvider::data`] — each
/// previously wrote the `.map_err(|e| FigmentError::from(e.to_string()))`
/// glue at the head of their `data()` body, immediately before the
/// [`provider_data_from_value`] call. Two open-coded conversions were two
/// places a future refinement of the [`ShikumiError`] → [`FigmentError`]
/// projection (structured spans, source-chain, miette-style annotations)
/// would have to be applied in lockstep, which is exactly the drift-class
/// this crate spends load-bearing lifts to close.
///
/// A future shikumi-built provider — an `HTTP` config endpoint, a `Vault`
/// secret store, a Kubernetes `ConfigMap` reader — implements its own
/// [`ShikumiError`]-bearing `load()` and routes `data()` through this
/// single helper, inheriting both the error-projection contract and the
/// format-typed dict-required wording by construction. Sharpening the
/// [`ShikumiError`] → [`FigmentError`] surface (adding [`figment::Error`]
/// spans, threading provenance) then lands at one site instead of once
/// per provider.
///
/// `format` is the same argument accepted by [`provider_data_from_value`]
/// — passed through so the dict-required wording agrees with the
/// metadata-name the provider's [`figment::Provider::metadata`] impl
/// already emits via [`Format::metadata_name`].
///
/// # Errors
///
/// Returns [`FigmentError`] if the load result was [`Err`]
/// (`ShikumiError` string-projected onto the figment error), OR if the
/// loaded [`Value`] is not a [`Value::Dict`] (format-typed dict-required
/// wording via [`provider_data_from_value`]).
// Same rationale as `provider_data_from_value` for the `result_large_err`
// silence: figment picks its error size; boxing would fork the helper's
// `Err` from the trait method's `Err` and force every call site to unbox
// at the trait boundary.
#[allow(clippy::result_large_err)]
pub(crate) fn provider_data_from_shikumi_load(
    result: Result<Value, ShikumiError>,
    format: Format,
) -> Result<Map<Profile, Dict>, FigmentError> {
    let value = result.map_err(|e| FigmentError::from(e.to_string()))?;
    provider_data_from_value(value, format)
}

/// Build the [`figment::Metadata`] a shikumi-built provider's
/// [`figment::Provider::metadata`] impl declares — the [`Format`]-typed
/// path→name projection wrapped in the [`Metadata::named`] shape figment
/// requires.
///
/// One source of truth for the metadata-construction shape shared by
/// every shikumi-built provider's `metadata` impl.
/// [`crate::lisp_provider::LispProvider::metadata`] (feature = "lisp",
/// `src/lisp_provider.rs`) and [`crate::nix_provider::NixProvider::metadata`]
/// each previously inlined the two-step
/// `Metadata::named(Format::X.metadata_name(&self.path))` construction —
/// two places a future refinement of the name-shape (structured spans,
/// source annotations, richer [`Metadata`] attributes) would have to be
/// applied in lockstep, which is exactly the drift-class this crate
/// spends load-bearing lifts to close. Idiom-peer of
/// [`provider_data_from_shikumi_load`], the sibling fusion helper that
/// closed the `data()`-body drift class; together they name both halves
/// of the shikumi-built provider's [`figment::Provider`] surface at one
/// site each.
///
/// The metadata-name round-trip contract remains: the emitted
/// [`Metadata::name`] equals what [`Format::metadata_name`] produces for
/// the same `(format, path)` pair, and therefore
/// [`Format::strip_metadata_name`] and [`Format::parse_metadata_tag`]
/// invert it back to the same `(format, path_display)` pair the provider
/// was constructed from. A future shikumi-built provider — an `HTTP`
/// config endpoint, a `Vault` secret store, a Kubernetes `ConfigMap`
/// reader — implements its `metadata()` by routing through this single
/// helper, inheriting the round-trip contract by construction.
///
/// `path` is the same [`Path`] the provider stores from its `file(...)`
/// constructor; passed by reference so no allocation happens beyond the
/// one [`Format::metadata_name`] itself performs.
#[must_use]
pub(crate) fn provider_metadata_for(format: Format, path: &Path) -> Metadata {
    Metadata::named(format.metadata_name(path))
}

/// Read a text config source file into a [`String`], projecting an I/O
/// error onto the [`ShikumiError::Parse`] shape every text-source
/// shikumi-built provider produces on a `read_to_string` failure.
///
/// One source of truth for the file-read step shared by every text-source
/// shikumi-built provider. [`crate::lisp_provider::LispProvider::load`]
/// (feature = "lisp") and [`crate::blue_provider::BlueProvider::load`]
/// (feature = "blue") each previously open-coded the identical two-step
/// `fs::read_to_string(path).map_err(|e| ShikumiError::Parse(format!(
/// "reading {}: {e}", path.display())))?` at the head of their `load`
/// body — two places a future refinement of the read-side diagnostic
/// (path canonicalization, [`io::ErrorKind`](std::io::ErrorKind) triage
/// naming `NotFound`/`PermissionDenied` explicitly, structured provenance
/// on the path) would have to be applied in lockstep, which is exactly
/// the drift-class this crate spends load-bearing lifts to close.
///
/// A future text-source shikumi-built provider — a Ruby-syntax `.rb`
/// front-end, a HOCON reader, a JSON5 or KDL provider — implements its
/// own `load()` by routing through this helper, inheriting the
/// path-bearing I/O error contract by construction. Idiom-peer of
/// [`provider_data_from_shikumi_load`] / [`provider_metadata_for`] /
/// [`json_value_to_figment`]: those close the `data()` / `metadata()` /
/// value-mapping legs of the shikumi-built provider surface; this closes
/// the source-reading leg.
///
/// # Errors
///
/// Returns [`ShikumiError::Parse`] with the operator-facing message
/// `"reading {path}: {io_error}"` if [`std::fs::read_to_string`] fails —
/// the exact wording every text-source shikumi-built provider previously
/// produced from the open-coded step, kept verbatim so the operator-
/// visible diagnostic does not change across this lift.
pub(crate) fn read_source_or_parse_err(path: &Path) -> Result<String, ShikumiError> {
    std::fs::read_to_string(path)
        .map_err(|e| ShikumiError::Parse(format!("reading {}: {e}", path.display())))
}

/// End-to-end fusion of the read-then-map cascade every text-source
/// shikumi-built provider's `load(path)` body performs: read the file into a
/// [`String`] via [`read_source_or_parse_err`], then hand the source to the
/// caller-supplied `map` closure to produce a [`Value`].
///
/// One source of truth for the two-step read+map shape shared by every
/// text-source shikumi-built provider. Idiom-peer of
/// [`read_source_or_parse_err`] (the read leg, lifted 2026-08-15 in
/// commit `8119f42`), [`json_value_to_figment`] (the JSON-to-figment leg,
/// lifted 2026-08-15 in commit `c793596`), and
/// [`provider_data_from_shikumi_load`] / [`provider_metadata_for`] (the
/// `data()`/`metadata()` legs): those close each of the other legs of
/// the shikumi-built provider surface; this closes the fused
/// `read + map` leg the [`crate::lisp_provider::LispProvider::load`]
/// (feature = "lisp") and [`crate::blue_provider::BlueProvider::load`]
/// (feature = "blue") impls each previously open-coded as
///
/// ```text
/// let src = crate::provider::read_source_or_parse_err(path)?;
/// load_from_str(&src)
/// ```
///
/// at the head of their `load` body — two places a future refinement of
/// the read+map protocol (path canonicalization emitted alongside the
/// source, a BOM-strip pass before the map runs, a
/// [`std::fs::metadata`]-guarded pre-check for a size limit, structured
/// provenance threaded from the read step into the map step) would have
/// to be applied in lockstep, which is exactly the drift-class this
/// crate spends load-bearing lifts to close.
///
/// A future text-source shikumi-built provider — a Ruby-syntax `.rb`
/// front-end, a HOCON reader, a JSON5 or KDL provider — implements its
/// `load(path)` as a single call through this helper (`load_text_source(
/// path, load_from_str)`), inheriting the read+map protocol by
/// construction. Sharpening the protocol (adding source-tracking spans,
/// threading a per-file diagnostic context, gating the size of the read
/// source) then lands at one site instead of once per provider.
///
/// The `map` argument is intentionally a bare `fn` pointer rather than an
/// `FnOnce` closure trait: the caller is always the provider's own
/// module-level `load_from_str` free function (never a stateful closure
/// capturing per-provider fields), so the concrete `fn(&str) -> …` type
/// preserves the direct-call ABI at the fusion site while ruling out an
/// accidental capture that would otherwise slip in and force a
/// per-callsite specialization on the type-checker.
///
/// # Errors
///
/// Returns [`ShikumiError::Parse`] on the read-step failure, verbatim
/// through [`read_source_or_parse_err`] — the `"reading {path}: {e}"`
/// operator-facing message is not rewritten in the fusion. Returns
/// whatever [`ShikumiError`] the caller-supplied `map` produces on a
/// map-step failure; the fusion does not alter, prefix, or synthesize
/// that error path.
pub(crate) fn load_text_source(
    path: &Path,
    map: fn(&str) -> Result<Value, ShikumiError>,
) -> Result<Value, ShikumiError> {
    let src = read_source_or_parse_err(path)?;
    map(&src)
}

/// End-to-end fusion of the read-then-map-then-project cascade every
/// text-source shikumi-built provider's [`figment::Provider::data`] body
/// performs: route `path` through [`load_text_source`] with the
/// caller-supplied `map` closure to produce a [`Value`], then project
/// the resulting [`ShikumiError`]-bearing [`Result`] through
/// [`provider_data_from_shikumi_load`] with the caller-supplied
/// [`Format`] for the format-typed dict-required wording.
///
/// Idiom-peer of the other text-source-provider substrate helpers:
/// [`read_source_or_parse_err`] closed the read leg (`8119f42`);
/// [`load_text_source`] closed the fused `read + map` leg (`5d07b1a`);
/// [`provider_data_from_shikumi_load`] closed the `data()`-body
/// error+dict projection; this helper closes the whole
/// `data()`-body-of-a-text-source-provider fusion. Both text-source
/// callers today — [`crate::blue_provider::BlueProvider`] and
/// [`crate::lisp_provider::LispProvider`] — previously wrote the
/// three-step composition
///
/// ```text
/// crate::provider::provider_data_from_shikumi_load(Self::load(&self.path), Format::X)
/// ```
///
/// which itself resolved to
///
/// ```text
/// provider_data_from_shikumi_load(load_text_source(&self.path, load_from_str), Format::X)
/// ```
///
/// at the tail of their `Provider::data` body — two places a future
/// refinement of the text-source-provider `data()` protocol (e.g.
/// threading a per-file provenance span from the read step through the
/// map step into the projected [`FigmentError`], gating on source size
/// before the map runs, structured miette annotations on either leg)
/// would have to be applied in lockstep, which is exactly the
/// drift-class this crate spends load-bearing lifts to close.
///
/// A future text-source shikumi-built provider — a Ruby-syntax `.rb`
/// front-end, a HOCON reader, a JSON5 or KDL provider — implements its
/// [`figment::Provider::data`] body as a single call through this
/// helper (`text_source_provider_data(&self.path, Format::X,
/// load_from_str)`), inheriting the read+map+project protocol by
/// construction. The provider's public `load(&Path) -> Result<Value,
/// ShikumiError>` static method — the ergonomic one-shot every
/// text-source provider exposes for tests and direct callers — is
/// unaffected and continues to route through [`load_text_source`]
/// directly.
///
/// The `map` argument is a bare `fn` pointer for the same reason
/// [`load_text_source`]'s is: the caller is always the provider's own
/// module-level `load_from_str` free function, and pinning the ABI at
/// the fusion site keeps the read+map+project cascade a direct call
/// rather than a per-callsite specialization.
///
/// # Errors
///
/// Returns [`FigmentError`] on read-step failure (string-projected from
/// the [`ShikumiError::Parse`] [`read_source_or_parse_err`] emits),
/// map-step failure (string-projected from whatever [`ShikumiError`]
/// the caller-supplied `map` produces), or dict-required failure
/// (format-typed wording via [`provider_data_from_value`]).
// Same rationale as `provider_data_from_value` for the `result_large_err`
// silence: figment picks its error size; boxing would fork the helper's
// `Err` from the trait method's `Err` and force every call site to unbox
// at the trait boundary.
#[allow(clippy::result_large_err)]
pub(crate) fn text_source_provider_data(
    path: &Path,
    format: Format,
    map: fn(&str) -> Result<Value, ShikumiError>,
) -> Result<Map<Profile, Dict>, FigmentError> {
    provider_data_from_shikumi_load(load_text_source(path, map), format)
}

/// Emit the whole shape a text-source shikumi-built provider carries
/// beyond its per-provider constructor: the [`figment::Provider`] impl
/// block routed through [`provider_metadata_for`] +
/// [`text_source_provider_data`], AND the static
/// `pub fn load(path: &Path) -> Result<Value, ShikumiError>` one-shot
/// routed through [`load_text_source`].
///
/// One source of truth for the shape of a text-source provider's
/// [`figment::Provider`] impl AND its ergonomic static-load one-shot.
/// After [`read_source_or_parse_err`] (`8119f42`), [`load_text_source`]
/// (`5d07b1a`), and [`text_source_provider_data`] (`e535174`) closed the
/// read / read+map / read+map+project cascades, and [`Self`] (`1988106`)
/// closed the [`figment::Provider`] impl-block body itself, each of the
/// two text-source callers still carried an identical two-line static
/// method
///
/// ```text
/// impl $Ty {
///     pub fn load(path: &Path) -> Result<Value, ShikumiError> {
///         crate::provider::load_text_source(path, load_from_str)
///     }
/// }
/// ```
///
/// modulo the module-local `load_from_str` — two places a future
/// refinement of the static-load convention (path canonicalization on
/// the way in, a `LoadedSource<Value>` return threading provenance,
/// gating on source size before the map runs) would have to be applied
/// in lockstep, which is exactly the drift-class this crate spends
/// load-bearing lifts to close. Emitting the static leg alongside the
/// impl-block leg from this same macro is idiom-peer to how
/// [`text_source_provider_data`] fuses the read+map+project cascade at
/// one site — the macro is now the fused emitter for BOTH ends of the
/// text-source provider's public surface, and cannot leave one
/// text-source caller riding an old shape while the other rides the
/// new.
///
/// A future text-source shikumi-built provider — a Ruby-syntax `.rb`
/// front-end, a HOCON reader, a JSON5 or KDL provider — implements its
/// entire [`figment::Provider`] surface AND its ergonomic
/// `load(&Path) -> Result<Value, ShikumiError>` one-shot as ONE macro
/// invocation
/// (`text_source_provider_impl!(MyProvider, Format::MyFormat, load_from_str);`),
/// inheriting the metadata + data + static-load protocol by
/// construction — zero authored per-provider boilerplate beyond the
/// struct declaration and its `file(path)` constructor. That closes
/// the last two lines of per-caller drift on the text-source provider
/// surface after the four prior lifts.
///
/// Idiom-peer to the sibling substrate helpers each closing one leg of
/// the text-source provider surface. This closes the fused
/// `impl Provider` body AND the static-load one-shot at one call site,
/// the last pieces of authored boilerplate left after the earlier lifts
/// collapsed the per-method bodies and the impl-block body.
///
/// # Contract
///
/// - `$ty` must be a struct type with a `path` field of a type that
///   [`std::borrow::Borrow`]s [`Path`] (typically `PathBuf`) — the
///   [`figment::Provider::metadata`] and [`figment::Provider::data`]
///   bodies both borrow `&self.path`, matching the convention every
///   text-source provider in-tree already uses. The emitted static
///   `load(&Path)` one-shot is a free-function-style method (no
///   `&self` receiver), so it does not touch the `path` field — it
///   takes its own `&Path` argument for the read step.
/// - `$format` is any [`Format`]-typed expression (`const` or value).
/// - `$mapper` is a `fn(&str) -> Result<Value, ShikumiError>` path — a
///   free function, not a stateful closure, matching the ABI both
///   [`text_source_provider_data`]'s and [`load_text_source`]'s
///   bare-`fn` parameters declare. The caller is expected to pass its
///   own module-level `load_from_str`, and both the emitted
///   `impl Provider::data` body and the emitted static
///   `load(&Path)` one-shot route through it.
///
/// The macro is `pub(crate)` because both substrate helpers it routes
/// through are `pub(crate)`; a `#[macro_export]` variant would emit
/// paths unreachable from outside the crate.
///
/// # Example
///
/// ```ignore
/// use crate::provider::text_source_provider_impl;
///
/// pub struct MyProvider { path: PathBuf }
/// impl MyProvider { pub fn file(p: impl Into<PathBuf>) -> Self { Self { path: p.into() } } }
///
/// fn load_from_str(src: &str) -> Result<Value, ShikumiError> { /* … */ }
///
/// // Emits both the `impl Provider for MyProvider` block AND the
/// // ergonomic `impl MyProvider { pub fn load(&Path) -> ... }` static
/// // one-shot. Consumers of `MyProvider::load(path)` continue to work
/// // as before; the difference is that the body is now defined at
/// // ONE substrate site instead of once per provider.
/// text_source_provider_impl!(MyProvider, Format::MyFormat, load_from_str);
/// ```
macro_rules! text_source_provider_impl {
    ($ty:ty, $format:expr, $mapper:path $(,)?) => {
        impl ::figment::Provider for $ty {
            fn metadata(&self) -> ::figment::Metadata {
                $crate::provider::provider_metadata_for($format, &self.path)
            }

            fn data(
                &self,
            ) -> ::core::result::Result<
                ::figment::value::Map<::figment::Profile, ::figment::value::Dict>,
                ::figment::Error,
            > {
                $crate::provider::text_source_provider_data(&self.path, $format, $mapper)
            }
        }

        impl $ty {
            /// Read + parse the file at `path`, routing through the
            /// shared [`load_text_source`](crate::provider::load_text_source)
            /// substrate helper — which itself calls
            /// [`read_source_or_parse_err`](crate::provider::read_source_or_parse_err)
            /// for the read step (so the `"reading {path}: {e}"` I/O
            /// error wording is defined once) and hands the source to
            /// this provider's `$mapper` for the parse step. The whole
            /// body is a single call, and cannot drift out of lockstep
            /// with the peer text-source providers riding the same
            /// [`text_source_provider_impl!`](crate::provider::text_source_provider_impl)
            /// macro.
            ///
            /// # Errors
            ///
            /// Returns
            /// [`ShikumiError::Parse`](crate::error::ShikumiError::Parse)
            /// on read-step failure (verbatim from `read_source_or_parse_err`)
            /// or whatever [`ShikumiError`](crate::error::ShikumiError)
            /// this provider's `$mapper` produces on a parse-step failure.
            pub fn load(
                path: &::std::path::Path,
            ) -> ::core::result::Result<::figment::value::Value, $crate::error::ShikumiError> {
                $crate::provider::load_text_source(path, $mapper)
            }
        }
    };
}
pub(crate) use text_source_provider_impl;

/// Emit the shared struct + `file(path)` ctor a text-source
/// shikumi-built provider carries at its head — the last two-line
/// pattern still open-coded at each caller after
/// [`text_source_provider_impl!`] closed the `impl Provider` body and
/// the [`Self::load`](crate::lisp_provider::LispProvider::load)
/// static-load one-shot legs.
///
/// Every text-source shikumi-built provider in-tree carries the SAME
/// `#[derive(Debug, Clone)] pub struct $Ty { path: PathBuf }` +
/// `pub fn file(path: impl Into<PathBuf>) -> Self { Self { path:
/// path.into() } }` pair — until this macro,
/// [`crate::lisp_provider::LispProvider`] (`lisp` feature) and
/// [`crate::blue_provider::BlueProvider`] (`blue` feature) each carried
/// a byte-identical copy of that ~15-line block. Two places any future
/// refinement of the carrier shape (a canonicalized-path cache in a
/// `OnceLock<PathBuf>`, a `figment::Metadata::source`-populated
/// [`figment::Source`] stashed at construction, an `Arc<Path>` interned
/// path for zero-alloc metadata cloning) would have to be applied in
/// lockstep — exactly the drift class this crate spends load-bearing
/// lifts to close. Idiom-peer of [`text_source_provider_impl!`], which
/// closed the `impl Provider` body + static-load one-shot legs at ONE
/// substrate site; this macro closes the last per-caller boilerplate on
/// the same surface. A future text-source shikumi-built provider — a
/// Ruby-syntax `.rb` front-end whose surface lowers to a
/// [`tatara_lisp::Sexp`], a HOCON reader, a JSON5 or KDL provider —
/// authors ZERO struct-level boilerplate beyond its module-level
/// `load_from_str` free function, its call to this macro, and its call
/// to [`text_source_provider_impl!`].
///
/// [`crate::nix_provider::NixProvider`] deliberately does NOT ride this
/// macro: it carries a second `nix_binary: String` field beside `path`
/// (overridable through the `with_binary` builder for hermetic tests),
/// so its ctor is legitimately per-provider. This is the same asymmetry
/// [`text_source_provider_impl!`] declares: text-source callers ride
/// the fused impl-block macro; the non-text-source `NixProvider` rides
/// the more general [`path_provider_impl!`] macro. The two-macro
/// partition is deliberate — every text-source rider inherits BOTH
/// halves of the shared surface, and the non-text-source rider inherits
/// only the halves it can share by construction.
///
/// The struct field `path: PathBuf` is left private-in-module; both
/// substrate helpers this crate ships that need to borrow it
/// ([`text_source_provider_impl!`]'s emitted `impl Provider::metadata`
/// / `impl Provider::data` bodies) expand in the same module as the
/// struct, so same-module visibility already reaches them without
/// widening the field's exposure.
///
/// # Contract
///
/// - The emitted struct derives `Debug + Clone`, the two bounds every
///   text-source provider in-tree carried pre-lift.
/// - The emitted ctor is `pub`, `#[must_use]`, and takes
///   `impl Into<PathBuf>`, matching the pre-lift convention that a
///   caller may pass either a `&Path` (via `Path::to_path_buf`) or an
///   owned [`PathBuf`].
/// - Any struct-level doc / cfg / derive attributes the caller places in
///   front of the macro (typically ONE `///` block) are forwarded
///   verbatim onto the emitted struct via `$(#[$attr])*`, so a caller
///   whose provider needs a bespoke `#[non_exhaustive]` or
///   `#[cfg(...)]` on the struct itself can still declare it at the
///   invocation site.
///
/// The macro is `pub(crate)` — the emitted struct is `pub`, but the
/// macro itself is only reachable from within this crate, matching
/// [`text_source_provider_impl!`]'s own visibility.
///
/// # Example
///
/// ```ignore
/// use crate::provider::{text_source_provider_impl, text_source_provider_struct};
///
/// text_source_provider_struct! {
///     /// Figment provider that reads a `.myfmt` config file.
///     MyProvider
/// }
///
/// fn load_from_str(src: &str) -> Result<Value, ShikumiError> { /* … */ }
///
/// text_source_provider_impl!(MyProvider, Format::MyFormat, load_from_str);
/// ```
macro_rules! text_source_provider_struct {
    (
        $(#[$attr:meta])*
        $ty:ident $(,)?
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone)]
        pub struct $ty {
            path: ::std::path::PathBuf,
        }

        impl $ty {
            /// Construct the provider from `path`. The file is not
            /// touched until either the [`::figment::Provider::data`]
            /// impl this struct rides through
            /// [`text_source_provider_impl!`](crate::provider::text_source_provider_impl)
            /// is called (via `Figment::merge`), or the ergonomic
            /// `Self::load(&Path)` static one-shot the same peer macro
            /// emits runs directly. The ctor performs one
            /// [`::std::path::PathBuf`] allocation via `Into` and
            /// nothing else.
            #[must_use]
            pub fn file(path: impl ::core::convert::Into<::std::path::PathBuf>) -> Self {
                Self { path: path.into() }
            }
        }
    };
}
pub(crate) use text_source_provider_struct;

/// Emit the FULL text-source shikumi-built provider surface — both the
/// struct-half (the `#[derive(Debug, Clone)] pub struct $Ty { path:
/// PathBuf }` carrier and its `pub fn file(path)` ctor) via
/// [`text_source_provider_struct!`], AND the impl-half (the whole
/// `impl ::figment::Provider for $Ty { fn metadata … fn data … }` block
/// alongside the ergonomic `pub fn load(&Path)` static one-shot) via
/// [`text_source_provider_impl!`] — from ONE macro invocation.
///
/// The fused-invocation peer of the two half-side macros. Before this
/// lift every text-source shikumi-built provider in-tree
/// ([`crate::lisp_provider::LispProvider`] under `lisp`,
/// [`crate::blue_provider::BlueProvider`] under `blue`) carried TWO
/// distinct macro calls — one call to [`text_source_provider_struct!`]
/// wrapping the doc block and the type name, then one call to
/// [`text_source_provider_impl!`] wiring `(Ty, Format, mapper)` — with
/// the type name `$Ty` and its `use crate::provider::{…}` import list
/// duplicated across the two invocations. Two invocations were two
/// places any future refinement of the fused shape (e.g. adding a third
/// half-side substrate macro on the same surface, or reordering the
/// struct/impl emission to matter to macro hygiene) would have to be
/// applied in lockstep at every caller — exactly the drift class the
/// two half-side macros themselves exist to close on the per-method
/// bodies.
///
/// This macro closes the last per-caller shape a text-source provider
/// carries. A future text-source shikumi-built provider — a
/// Ruby-syntax `.rb` front-end whose surface lowers to a
/// [`tatara_lisp::Sexp`], a HOCON reader, a JSON5 or KDL provider —
/// authors ZERO struct-level OR impl-level boilerplate beyond its
/// module-level `load_from_str` free function, its `use` line for this
/// one macro, and this one invocation.
///
/// # Contract
///
/// - `$(#[$attr:meta])*` forwards struct-level doc / cfg / derive
///   attributes verbatim to the emitted struct — the same forwarding
///   [`text_source_provider_struct!`] does at its head, so a caller
///   whose provider needs a bespoke `#[non_exhaustive]` or `#[cfg(...)]`
///   on the struct itself can still declare it at the invocation site.
/// - `$ty:ident` is the provider type name; it is emitted verbatim to
///   both half-side macros. Same convention (`Debug + Clone`,
///   private-in-module `path: PathBuf`, `pub` `#[must_use]`
///   `file(impl Into<PathBuf>)` ctor) as
///   [`text_source_provider_struct!`].
/// - `format = $format:expr` is any [`Format`]-typed expression
///   (`const` or value); it flows through the emitted `impl Provider`
///   body to [`provider_metadata_for`] for the metadata name and to
///   [`text_source_provider_data`] for the format-typed dict-required
///   wording.
/// - `mapper = $mapper:path` is the free-function path (a `fn` pointer,
///   not a closure) `(src: &str) -> Result<Value, ShikumiError>` this
///   provider's parse step routes through — the same slot
///   [`text_source_provider_impl!`] takes.
///
/// The macro is `pub(crate)` for the same reason the two half-side
/// macros are: both substrate helpers the impl-half routes through
/// ([`provider_metadata_for`], [`text_source_provider_data`],
/// [`load_text_source`]) are `pub(crate)`; a `#[macro_export]` variant
/// would emit paths unreachable from outside the crate.
///
/// # Example
///
/// ```ignore
/// use crate::provider::text_source_provider;
///
/// text_source_provider! {
///     /// Figment provider that reads a `.myfmt` config file.
///     MyProvider,
///     format = Format::MyFormat,
///     mapper = load_from_str,
/// }
/// ```
///
/// Which is byte-for-byte equivalent to the two-invocation shape every
/// pre-lift caller wrote by hand:
///
/// ```ignore
/// use crate::provider::{text_source_provider_impl, text_source_provider_struct};
///
/// text_source_provider_struct! {
///     /// Figment provider that reads a `.myfmt` config file.
///     MyProvider
/// }
///
/// text_source_provider_impl!(MyProvider, Format::MyFormat, load_from_str);
/// ```
macro_rules! text_source_provider {
    (
        $(#[$attr:meta])*
        $ty:ident,
        format = $format:expr,
        mapper = $mapper:path $(,)?
    ) => {
        $crate::provider::text_source_provider_struct! {
            $(#[$attr])*
            $ty
        }

        $crate::provider::text_source_provider_impl!($ty, $format, $mapper);
    };
}
pub(crate) use text_source_provider;

/// Emit `impl ::figment::Provider for $ty { fn metadata … fn data … }` —
/// the [`figment::Provider`] impl block a shikumi-built provider carries
/// when it produces a [`Result<Value, ShikumiError>`] from a `&self`
/// receiver, routed through the substrate helpers
/// [`provider_metadata_for`] and [`provider_data_from_shikumi_load`].
///
/// The general peer of [`text_source_provider_impl`]: where the
/// text-source macro fixes the load leg as `load_text_source(&self.path,
/// mapper)` — a signature that only fits providers whose upstream is a
/// text file the caller-supplied mapper parses — this macro takes an
/// arbitrary caller-supplied `|this| $load` block, so any provider whose
/// `load` produces a [`Result<Value, ShikumiError>`] from `&self` rides
/// the substrate. Today [`crate::nix_provider::NixProvider`] is the
/// caller: its upstream is `nix eval --json`, so the load leg goes
/// through [`std::process::Command`] rather than a text mapper, and it
/// carried the last remaining open-coded four-line `impl Provider` block
/// on the shikumi-built provider surface after the four prior lifts
/// ([`read_source_or_parse_err`] `8119f42`, [`load_text_source`]
/// `5d07b1a`, [`text_source_provider_data`] `e535174`,
/// [`text_source_provider_impl`] `1988106`) collapsed the per-method
/// bodies for the text-source callers. With this macro, that block is a
/// single call site whose data and metadata halves BOTH route through
/// the same substrate helpers the text-source macro does — so a future
/// refinement of either half (an added [`figment::Provider::profile`]
/// override, a [`figment::Metadata::source`]-populated metadata builder,
/// structured miette annotations on the data path, richer per-file
/// diagnostic context threaded through both surfaces) lands at ONE site
/// and every macro-emitted `Provider` impl inherits it by construction —
/// text-source and command-source callers alike.
///
/// A future shikumi-built provider whose load side is NOT a text-source
/// mapper — a Kubernetes `ConfigMap` reader whose upstream is a
/// [`kube`](https://docs.rs/kube) API call, a Vault secret store whose
/// upstream is an HTTP GET, an HTTP `/config` endpoint that produces a
/// figment [`Value`] directly, a [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
/// central-authority broadcast layer whose upstream is a subscription
/// stream — implements its whole [`figment::Provider`] surface as ONE
/// macro invocation:
///
/// ```ignore
/// path_provider_impl!(MyProvider, Format::MyFormat, |this| this.load());
/// ```
///
/// inheriting the metadata + data protocol by construction. The
/// provider's own [`Result<Value, ShikumiError>`]-bearing load method is
/// unaffected — the macro's `|this| $load` arm binds `this` to `&$ty`
/// inside the emitted `data()` body and calls whatever expression the
/// caller supplied on it, so a method-taking `&self`, a free function
/// taking `&$ty`, a caller-side fusion of both, or any other expression
/// producing a `Result<Value, ShikumiError>` all fit.
///
/// # Contract
///
/// - `$ty` must be a struct type with a `path` field of a type that
///   [`std::borrow::Borrow`]s [`Path`] (typically `PathBuf`) — the
///   [`figment::Provider::metadata`] body borrows `&self.path`, matching
///   the convention every shikumi-built provider in-tree already
///   follows. This is the SAME `path`-field contract
///   [`text_source_provider_impl`] declares; the two macros are
///   idiom-peers on the metadata half.
/// - `$format` is any [`Format`]-typed expression (`const` or value).
/// - The `|$this| $load` arm binds `$this` to `&$ty` inside `$load`,
///   which must be an expression producing a
///   `Result<Value, ShikumiError>`. The bound identifier `$this` is
///   a `let` binding at the head of the emitted `data()` body — not a
///   real closure — so borrows of `$this.<field>` inside `$load` reach
///   the same lifetime the `data(&self)` receiver already grants.
///
/// The macro is `pub(crate)` because both substrate helpers it routes
/// through are `pub(crate)`; a `#[macro_export]` variant would emit
/// paths unreachable from outside the crate.
///
/// # Example
///
/// ```ignore
/// use crate::provider::path_provider_impl;
///
/// pub struct MyProvider { path: PathBuf }
/// impl MyProvider {
///     pub fn file(p: impl Into<PathBuf>) -> Self { Self { path: p.into() } }
///     pub fn load(&self) -> Result<Value, ShikumiError> { /* … */ }
/// }
///
/// path_provider_impl!(MyProvider, Format::MyFormat, |this| this.load());
/// ```
macro_rules! path_provider_impl {
    ($ty:ty, $format:expr, |$this:ident| $load:expr $(,)?) => {
        impl ::figment::Provider for $ty {
            fn metadata(&self) -> ::figment::Metadata {
                $crate::provider::provider_metadata_for($format, &self.path)
            }

            fn data(
                &self,
            ) -> ::core::result::Result<
                ::figment::value::Map<::figment::Profile, ::figment::value::Dict>,
                ::figment::Error,
            > {
                let $this: &$ty = self;
                $crate::provider::provider_data_from_shikumi_load($load, $format)
            }
        }
    };
}
pub(crate) use path_provider_impl;

/// Wrap `dict` in the [`Value::Dict`] variant tagged with the canonical
/// [`figment::value::Tag::Default`] every shikumi-built provider that
/// constructs a fresh figment [`Value`] uses.
///
/// One source of truth for the "default-tagged fresh [`Value::Dict`]"
/// choice every shikumi-built provider makes when it hands figment a
/// map it built itself. Before this lift both
/// [`json_value_to_figment`] (the JSON-object arm) and the
/// [`crate::lisp_provider::sexp_to_value_root`] / peer
/// `sexp_to_value` sites (the kwargs-list arms) open-coded
/// `Value::Dict(figment::value::Tag::Default, <dict>)` directly at
/// each of five in-crate constructor sites — each site an
/// independent decision to reach for the `Tag::Default` inhabitant,
/// and therefore an independent place any future refinement of the
/// tag (source-span provenance threaded through
/// [`figment::value::Tag`], a per-provider synthetic identifier for
/// downstream error messages, a construction-side attribution site)
/// would have to be applied in lockstep.
///
/// Idiom-peer of [`figment_default_array`] (the [`Value::Array`]
/// sibling for a freshly-built [`Vec<Value>`]) and
/// [`figment_default_empty_none`] (the sole-inhabitant sibling for
/// the JSON-null / `Sexp::Nil` case). All three close the same
/// drift-class the peer provider-surface substrate helpers close on
/// their own legs ([`provider_data_from_value`] on the projection
/// leg, [`provider_metadata_for`] on the metadata leg,
/// [`read_source_or_parse_err`] on the read leg, [`load_text_source`]
/// / [`text_source_provider_data`] on the read+map / read+map+project
/// legs): factor the "shikumi's own choice" out of every caller and
/// name it once, so a future sharpening lands at one site rather
/// than fanning out across every constructor.
///
/// Zero-cost by construction: the emitted body is the two-argument
/// tuple constructor for [`Value::Dict`], marked `#[inline]` so the
/// call collapses at the caller. The alternative of routing through
/// [`figment`]'s own `impl From<Map<K, V>> for Value` copies every
/// key ([`AsRef::as_ref`] `->` [`String::to_string`]) and re-`Into`s
/// every value — an O(n) allocation walk we deliberately do not pay
/// on a caller that already owns the exact [`Dict`] figment stores.
///
/// A future shikumi-built provider whose upstream produces a fresh
/// figment [`Dict`] — an HTTP `/config` endpoint whose body is a
/// JSON object, a Kubernetes `ConfigMap` reader whose keys are the
/// data-key names, a ConfigPlane broadcast layer whose payload is a
/// per-tick config snapshot — hands the built [`Dict`] to this
/// helper and inherits the tag choice by construction.
#[inline]
#[must_use]
pub(crate) fn figment_default_dict(dict: Dict) -> Value {
    Value::Dict(figment::value::Tag::Default, dict)
}

/// Wrap `items` in the [`Value::Array`] variant tagged with the
/// canonical [`figment::value::Tag::Default`] — the [`Value::Array`]
/// sibling of [`figment_default_dict`], closing the SAME drift-class
/// on the array-variant leg.
///
/// Idiom-peer of [`figment_default_dict`] and
/// [`figment_default_empty_none`]. Before this lift both
/// [`json_value_to_figment`] (the JSON-array arm) and the
/// [`crate::lisp_provider`] `sexp_to_value` non-kwargs list arm
/// open-coded `Value::Array(figment::value::Tag::Default, <items>)`
/// directly. Each site is one place any future refinement of the
/// tag choice (source-span provenance, per-element attribution) would
/// have to be applied in lockstep.
///
/// Zero-cost by construction: the emitted body is the two-argument
/// tuple constructor for [`Value::Array`], marked `#[inline]` so the
/// call collapses at the caller. Prefers this ownership shape over
/// [`figment`]'s own `impl From<Vec<T: Into<Value>>> for Value`,
/// which re-`.into()`s every element in an [`Iterator::map`]-`collect`
/// round-trip that the type-checker cannot always erase for a caller
/// that already owns the exact [`Vec<Value>`] figment stores.
#[inline]
#[must_use]
pub(crate) fn figment_default_array(items: Vec<Value>) -> Value {
    Value::Array(figment::value::Tag::Default, items)
}

/// The canonical [`figment::value::Empty::None`] [`Value`] tagged with
/// [`figment::value::Tag::Default`] — the sole-inhabitant sibling of
/// [`figment_default_dict`] / [`figment_default_array`], closing the
/// SAME drift-class on the `Empty::None` leg every shikumi-built
/// provider produces when its upstream renderer emits a JSON `null`,
/// a [`tatara_lisp::Sexp::Nil`], or an unreachable-arm fallback that
/// figment's own serde deserializer will treat as [`Option::None`].
///
/// Idiom-peer of [`figment_default_dict`] and [`figment_default_array`].
/// Before this lift [`json_value_to_figment`] (the JSON-null arm AND
/// the unreachable [`serde_json::Number`]-cascade fallback arm) and
/// the [`crate::lisp_provider`] `sexp_to_value` [`tatara_lisp::Sexp::Nil`]
/// arm each open-coded
/// `Value::Empty(figment::value::Tag::Default, figment::value::Empty::None)`
/// directly. Three sites; one shared decision. A future refinement of
/// the empty inhabitant (a switch to [`figment::value::Empty::Unit`]
/// for a caller whose upstream distinguishes JSON `null` from an
/// omitted key, richer per-callsite provenance on the tag) then lands
/// at one site rather than three.
///
/// Zero-cost by construction: `#[inline]`, the emitted body is the
/// two-argument constructor for [`Value::Empty`]. Not routed through
/// [`figment`]'s own `impl From<Empty> for Value` because that impl's
/// signature accepts any `Into<Empty>`, so a call site that reaches
/// for a bare `Value::from(Empty::None)` still has to name
/// `Empty::None` — this helper names it once.
#[inline]
#[must_use]
pub(crate) fn figment_default_empty_none() -> Value {
    Value::Empty(figment::value::Tag::Default, figment::value::Empty::None)
}

/// Merge a serde-serializable Defaults-tier layer into `chain`: the
/// two-step "extend `chain.figment` with `Serialized::defaults(defaults)`
/// and append [`ConfigSource::Defaults`] to `chain.sources`" that every
/// Defaults-class [`ProviderChain`] builder previously open-coded at its
/// own site.
///
/// One source of truth for the "figment `Serialized::defaults` merge +
/// `ConfigSource::Defaults` provenance push" two-step both
/// [`ProviderChain::with_defaults`] (the developer-defaults builder) and
/// [`ProviderChain::with_discovered`] (the discovered-tier builder,
/// recorded as Defaults-class per that doc) previously open-coded. Two
/// callers wrote the same three-line body — `self.figment =
/// self.figment.merge(Serialized::defaults(<layer>))`, `self.sources.push(
/// ConfigSource::Defaults)`, `self` — with the only difference being
/// whether the caller passed a `&T: Serialize` reference or a
/// `Dict`-typed owned map (which itself is `Serialize`, so the merge
/// half of the body is byte-for-byte identical). Two places any future
/// refinement of the Defaults-tier merge protocol (an idempotence guard
/// preventing a double-Defaults merge, a `figment::Metadata::source`
/// annotation on the Serialized provider, a shared per-tier telemetry
/// counter, a canonicalizing wrap around the caller-supplied value) would
/// have to be applied in lockstep — exactly the drift-class the peer
/// substrate helpers on the same file
/// ([`provider_metadata_for`], [`provider_data_from_shikumi_load`],
/// [`text_source_provider_data`], [`figment_default_dict`],
/// [`json_value_to_figment`]) close on the provider-surface side.
///
/// A future Defaults-class [`ProviderChain`] builder — a
/// `with_prescribed_default(&T)` tier-aligned peer for the sealed
/// `bare → discovered → prescribed_default → file → env → runtime`
/// fold [`crate::tiered::resolve_progressive`] declares (per the
/// destination roadmap in `CLAUDE.md`), a
/// `with_bare_default(&T)` counterpart naming the `bare()` tier —
/// authors ZERO merge-side boilerplate: it routes its body through this
/// helper (or its own peer helper that pushes the tier-specific
/// [`ConfigSource`] variant) and inherits both the `Serialized::defaults`
/// merge and the provenance-push convention by construction. The
/// `ConfigSource::Defaults` push half is what pins THIS helper to the
/// Defaults-class today; a future dedicated `Discovered` provenance
/// variant (per [`ProviderChain::with_discovered`]'s own doc) would
/// stop routing that caller through this helper and instead route it
/// through its own tier-specific peer — the drift-closure is inside
/// the two `ProviderChain` builders that name the shared helper, not
/// inside the helper itself.
///
/// # Contract
///
/// - `defaults` is any `T: Serialize` value the caller wants to merge as
///   the Defaults-class layer. The helper does not inspect, canonicalize,
///   or clone `defaults`; it hands it directly to
///   [`Serialized::defaults`], preserving figment's own borrow-vs-own
///   contract on the [`figment::providers::Serialized`] side.
/// - The recorded [`ConfigSource`] is [`ConfigSource::Defaults`],
///   verbatim — the Defaults-class provenance-tier every current caller
///   records. A future caller whose provenance is NOT the Defaults tier
///   (a hypothetical `Discovered` variant, a `Prescribed` variant, or a
///   `Bare` variant) must not route through this helper — it must add its
///   own peer helper that pushes its tier-specific variant, so the
///   variant push stays a structural decision instead of a runtime
///   parameter that could be miscalled.
///
/// The return shape and by-value ownership convention match the
/// `with_*` builder methods on [`ProviderChain`]: `chain` is taken by
/// value and returned by value, preserving the fluent-chain
/// `.with_defaults(&d).with_env("APP_")` composition every caller
/// relies on.
///
/// # Zero-cost by construction
///
/// The helper is a plain function performing exactly the same two
/// statements the pre-lift open-coded bodies performed — one figment
/// `merge` and one `Vec::push` — so the substrate lift adds zero
/// per-call overhead the compiler cannot inline away.
#[must_use]
pub(crate) fn merge_serialized_defaults_layer<T: Serialize>(
    mut chain: ProviderChain,
    defaults: &T,
) -> ProviderChain {
    chain.figment = chain.figment.merge(Serialized::defaults(defaults));
    chain.sources.push(ConfigSource::Defaults);
    chain
}

/// Total mapping from a [`serde_json::Value`] to a [`figment::value::Value`].
///
/// The one-shot JSON → figment projection every shikumi-built provider
/// whose upstream renderer produces JSON routes through. Today
/// [`crate::nix_provider::NixProvider::load`] is the only consumer — it
/// shells out to `nix eval --json` and hands the parsed
/// [`serde_json::Value`] here. Sits beside the [`provider_data_from_value`]
/// / [`provider_data_from_shikumi_load`] / [`provider_metadata_for`]
/// substrate helpers for the exact same reason those exist: any future
/// shikumi-built provider whose upstream speaks JSON — a
/// [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
/// central-authority broadcast layer, an HTTP `/config` endpoint, a
/// Kubernetes `ConfigMap` reader whose values arrive as JSON strings, a
/// Vault secret store — routes its `load()` body through this single site
/// instead of open-coding the mapping a second time. A future sharpening
/// (source spans threaded via [`figment::value::Tag`], structured
/// provenance for the number arm, a compact-string path for repeated
/// keys) then lands at one site instead of once per provider.
///
/// # Number arm precision
///
/// A [`serde_json::Number`] can outlive an [`i64`]: JSON permits any
/// integer up to 20-plus digits, and `serde_json` will happily materialise
/// `18_446_744_073_709_551_615` as its internal `u64` inhabitant. The
/// helper preserves that precision by trying [`serde_json::Number::as_i64`]
/// first (which covers negatives and the whole `i64` range), then
/// [`serde_json::Number::as_u64`] (which covers `i64::MAX + 1 ..= u64::MAX`
/// — a range the [`i64`]-only path fell through to lossy [`f64`] on),
/// then [`serde_json::Number::as_f64`] as the true float arm. The `f64`
/// arm is total on `serde_json::Number` per its docs (a JSON number is
/// always representable as an `f64`, with possible loss for integers
/// outside `[-2^53, 2^53]`), so no third fallback is reachable — an
/// unreachable arm here would silently swallow a future format-level bug
/// under a default value. The pre-lift version of this helper carried
/// exactly that trap: a `Value::from(0i64)` catch-all sat behind an
/// `as_i64` → `as_f64` cascade, so any `u64` above `i64::MAX` lost
/// precision to the `f64` arm instead of surfacing on the natively-typed
/// path figment already supports (`Value::from(u64)` exists — see
/// [`figment::value::Num::U64`]).
///
/// # Value-variant mapping
///
/// - `Null` → `Value::Empty(Tag::Default, Empty::None)` — figment has no
///   dedicated JSON-null inhabitant; `Empty::None` is the canonical
///   `Option::None` counterpart the deserializer already expects.
/// - `Bool` → `Value::Bool`.
/// - `Number` → `Value::Num`, per the precision cascade above.
/// - `String` → `Value::String`.
/// - `Array` → `Value::Array`, recursively via this same helper.
/// - `Object` → `Value::Dict`, recursively via this same helper.
///
/// The recursion is a homomorphism on the JSON tree: every scalar leaf
/// maps pointwise to its figment counterpart with no reordering,
/// dropping, or synthesis of intermediate structure. The
/// `json_value_to_figment_is_pointwise_homomorphic_on_nested_shapes` test
/// pins that pointwise contract; the number-arm precision tests pin the
/// u64/i64/float boundaries.
pub(crate) fn json_value_to_figment(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => figment_default_empty_none(),
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                // Preserves precision for JSON integers in
                // (i64::MAX, u64::MAX] — the pre-lift `as_i64() -> as_f64()`
                // cascade lost these to lossy floats.
                Value::from(u)
            } else if let Some(f) = n.as_f64() {
                Value::from(f)
            } else {
                // Unreachable per `serde_json::Number::as_f64`'s docs: a
                // JSON number is always representable as an `f64`. Emit
                // `Empty::None` rather than a silent `0` so a future
                // format-level bug would surface as a missing key rather
                // than a wrong-but-plausible value.
                figment_default_empty_none()
            }
        }
        serde_json::Value::String(s) => Value::from(s.clone()),
        serde_json::Value::Array(items) => {
            figment_default_array(items.iter().map(json_value_to_figment).collect())
        }
        serde_json::Value::Object(map) => {
            let mut dict = Dict::new();
            for (k, v) in map {
                dict.insert(k.clone(), json_value_to_figment(v));
            }
            figment_default_dict(dict)
        }
    }
}

/// Full body of the missing-feature warning every feature-gated arm of
/// [`ProviderChain::with_file`]'s `#[cfg(not(feature = "…"))]` branch
/// emits — the whole `"shikumi built without the `<feature>` feature;
/// skipping .<ext> config. Enable the feature or convert to
/// <alternatives>."` sentence assembled from the substrate helpers, with
/// `<feature>` taken verbatim from the caller-supplied `feature` label,
/// `<ext>` derived from [`Format::as_str`] on `format` (dot-prefixed),
/// and `<alternatives>` derived through [`missing_feature_alternatives`].
///
/// One source of truth for the missing-feature warning shape. Before this
/// lift each of the two feature-gated arms of [`ProviderChain::with_file`]
/// carried an open-coded 6-line block that hard-coded three pieces
/// separately — the feature name literal (`"lisp"` / `"blue"`), the
/// skipped-extension literal (`.lisp` / `.b`), and a call to
/// [`missing_feature_alternatives`] — with the whole `"shikumi built
/// without the …"` sentence re-typed at each site. Three hard-coded
/// pieces × two arms × the future third caller a `.rb` / HOCON / JSON5
/// / KDL front-end lands as (per the doc-lift roadmap on the peer
/// substrate helpers) equals nine places any refinement of the
/// operator-facing sentence (adding an `--enable-lisp` hint, a link to
/// the migration doc, an explicit `.<ext>` extension list per format, a
/// richer skipped-count structured field) would have to be applied in
/// lockstep. That is exactly the drift-class this crate spends
/// load-bearing lifts to close — the [`Lisp`](Format::Lisp) arm's
/// pre-lift `.yaml/.toml/.nix` alternatives-list was staled by exactly
/// the same drift-mechanism on the [`Blue`](Format::Blue) variant lift
/// [`missing_feature_alternatives`] already closed.
///
/// A future feature-gated shikumi-built provider — a Ruby-syntax `.rb`
/// front-end whose parser dependency is optional, a HOCON reader riding
/// an optional-feature crate — declares its whole missing-feature
/// warning as ONE macro call
/// (`merge_or_warn_missing_feature!(chain = self, path = path,
/// feature = "ruby", format = Format::Ruby, provider =
/// crate::ruby_provider::RubyProvider)`), inheriting the sentence
/// derivation by construction; the feature label, skipped-extension,
/// and alternatives-list all derive at this single site, with zero
/// re-typed prose at the caller.
///
/// The output is a [`String`] rather than an `&'static str` because both
/// the alternatives phrase and the format-name are runtime-assembled
/// from [`Format::ALL`] / [`Format::as_str`]; the missing-feature
/// warning path is not a hot loop, so the one small allocation on the
/// diagnostic edge is invisible to the caller. Idiom-peer of
/// [`missing_feature_alternatives`] (which produces the sub-phrase
/// this helper embeds).
///
/// The helper is `cfg`-gated to exactly the builds that have at least
/// one caller — the two `merge_or_warn_missing_feature!` invocations
/// that reach it live inside `#[cfg(not(feature = "…"))]` branches, so
/// when BOTH `lisp` and `blue` are enabled the fn has no live consumer
/// and the gate keeps `warn(dead_code)` honest. `#[cfg(test)]` is
/// bundled in so the pin-tests below (which reference the helper
/// unconditionally) still compile. Adding a third gated caller
/// (e.g. `ruby`) requires extending both this gate and
/// [`missing_feature_alternatives`]'s peer gate with `not(feature =
/// "ruby")` — the same lockstep obligation the peer helper already
/// declares.
#[cfg(any(test, not(feature = "lisp"), not(feature = "blue")))]
#[must_use]
pub(crate) fn missing_feature_warning_body(feature: &str, format: Format) -> String {
    let ext = format.as_str();
    let alternatives = missing_feature_alternatives(format);
    format!(
        "shikumi built without the `{feature}` feature; skipping .{ext} config. \
         Enable the feature or convert to {alternatives}."
    )
}

/// The "alternative extensions" phrase for a missing-feature warning
/// about `missing` — every OTHER format's primary extension
/// (from [`Format::extensions`]'s first entry, canonicalized through
/// [`Format::as_str`]), dot-prefixed and `/`-joined in
/// [`Format::ALL`] declaration order.
///
/// One source of truth for the alternatives list every feature-gated
/// arm of [`ProviderChain::with_file`]'s `#[cfg(not(feature = "…"))]`
/// warning previously hard-coded — an `.a/.b/.c`-shaped operator hint
/// telling the reader which other formats the current build can still
/// load. Two open-coded copies of the list (the `Lisp` arm's
/// `.yaml/.toml/.nix` and the `Blue` arm's `.yaml/.toml/.lisp/.nix`)
/// were two places any future [`Format`] variant landing would silently
/// stale each existing warning — exactly what the `Lisp` arm's list did
/// on the `Blue` variant lift: it never learned about `.b` and kept
/// suggesting the pre-`Blue` set, so an operator whose build lacked
/// `lisp` was told to `convert to .yaml/.toml/.nix` even though `.b`
/// was equally an option.
///
/// A future [`Format`] variant lands ONE arm in the exhaustive match
/// in [`Format::extensions`] / [`Format::as_str`] / [`Format::ALL`] —
/// pinned by the existing `format_all_covers_every_variant` test — and
/// every existing warning's alternatives list automatically extends to
/// include it, without touching either open-coded warning site. Sits
/// beside the other shared substrate helpers on the provider surface
/// ([`provider_data_from_value`], [`provider_data_from_shikumi_load`],
/// [`provider_metadata_for`], [`read_source_or_parse_err`],
/// [`load_text_source`], [`text_source_provider_data`],
/// [`json_value_to_figment`]) for the same reason those exist: any
/// future shikumi-built provider whose format is feature-gated —
/// a Ruby-syntax `.rb` front-end whose parser dependency is optional,
/// a HOCON or JSON5 reader riding an optional-feature crate — routes
/// its own missing-feature warning through this single site instead of
/// hard-coding the alternatives list a fourth time.
///
/// The output is a [`String`] rather than an `&'static str` because the
/// per-format list can only be assembled at runtime from the
/// [`Format::ALL`] slice; the missing-feature warning path is not a
/// hot loop, so the one small allocation on the diagnostic edge is
/// invisible to the caller.
///
/// The helper is `cfg`-gated to exactly the builds that have at least
/// one caller — the two `ProviderChain::with_file` arms that reach it
/// live inside `#[cfg(not(feature = "…"))]` branches, so when BOTH
/// `lisp` and `blue` are enabled the fn has no live consumer and the
/// gate keeps `warn(dead_code)` honest. `#[cfg(test)]` is bundled in
/// so the pin-tests below (which reference the helper unconditionally)
/// still compile.
#[cfg(any(test, not(feature = "lisp"), not(feature = "blue")))]
#[must_use]
pub(crate) fn missing_feature_alternatives(missing: Format) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(Format::ALL.len().saturating_sub(1));
    for &f in Format::ALL {
        if f == missing {
            continue;
        }
        parts.push(format!(".{}", f.as_str()));
    }
    parts.join("/")
}

/// Fold the two-branch `Some(Format::X) => { #[cfg(feature = "…")] merge; \
/// #[cfg(not(feature = "…"))] warn }` shape every feature-gated arm of
/// [`ProviderChain::with_file`] carries into ONE macro invocation.
///
/// One source of truth for the feature-gated file-merge shape.
/// Idiom-peer of the other in-crate substrate macros
/// ([`text_source_provider_impl!`], [`text_source_provider_struct!`],
/// [`path_provider_impl!`]) — each closed one leg of the shikumi-built
/// provider surface at ONE site; this macro closes the last leg the
/// feature-gated formats carry inside [`ProviderChain::with_file`]'s
/// `match` — the branch that decides at *cfg* time whether the
/// provider's ctor is compiled in or an operator-facing missing-feature
/// warning is emitted instead.
///
/// Before this lift the two arms in-tree ([`Format::Lisp`],
/// [`Format::Blue`]) each carried an open-coded 14-line block of the
/// SAME two-branch shape, with the feature name hard-coded in three
/// places (the `#[cfg]` attribute, the `#[cfg(not)]` attribute, and the
/// warning body's `"`…`"`) and the skipped-extension hard-coded in
/// the warning body — six places any future refinement of either half
/// (a `--enable-<feature>` hint, a richer structured field, a
/// canonicalized-path pre-check on the enabled branch, a `tracing::debug`
/// on the skipped one) would have to be applied in lockstep. That is
/// exactly the drift-class this crate spends load-bearing lifts to close
/// — and it is the same drift that already staled the [`Lisp`](Format::Lisp)
/// arm's alternatives list on the [`Blue`](Format::Blue) variant lift
/// [`missing_feature_alternatives`] closed. A future feature-gated
/// shikumi-built provider — a Ruby-syntax `.rb` front-end whose parser
/// dependency is optional, a HOCON reader riding an optional-feature
/// crate — lands as ONE macro invocation on the same shape, inheriting
/// both the merge branch and the missing-feature warning body by
/// construction; zero authored boilerplate on either half beyond the
/// [`Format`] variant declaration + this line inside `with_file`.
///
/// # Contract
///
/// - `$chain` binds the [`ProviderChain`]-typed `&mut Self` receiver
///   (spelled `self` at the two in-tree callers); the enabled branch
///   assigns `$chain.figment = $chain.figment.merge(…)` in place.
/// - `$path` is any `&`[`Path`]-typed expression the enabled branch
///   passes into `<$prov>::file(…)` and the disabled branch passes into
///   the structured `path = %$path.display()` [`tracing::warn!`] field.
/// - `$feat` is the [`str`] literal naming the feature — a `:literal`
///   because the enabled and disabled `#[cfg(feature = $feat)]` /
///   `#[cfg(not(feature = $feat))]` attributes both require a literal
///   token; it also flows into the warning body as the operator-facing
///   feature label through [`missing_feature_warning_body`].
/// - `$format` is any [`Format`]-typed expression (`const` or value);
///   the disabled branch passes it to [`missing_feature_warning_body`]
///   for both the skipped-extension (derived via [`Format::as_str`]) and
///   the alternatives list (derived via [`missing_feature_alternatives`]).
/// - `$prov` is any type expression naming the provider constructor
///   (typically `crate::lisp_provider::LispProvider`), whose
///   `file(&Path) -> Self` ctor the enabled branch calls.
///
/// The macro is `pub(crate)` because the substrate helpers it routes
/// through ([`missing_feature_warning_body`]) are `pub(crate)`; a
/// `#[macro_export]` variant would emit paths unreachable from outside
/// the crate.
///
/// # Example
///
/// ```ignore
/// match Format::from_path(path) {
///     Some(Format::Lisp) => merge_or_warn_missing_feature!(
///         chain = self,
///         path = path,
///         feature = "lisp",
///         format = Format::Lisp,
///         provider = crate::lisp_provider::LispProvider,
///     ),
///     // …
/// }
/// ```
macro_rules! merge_or_warn_missing_feature {
    (
        chain = $chain:expr,
        path = $path:expr,
        feature = $feat:literal,
        format = $format:expr,
        provider = $prov:ty $(,)?
    ) => {{
        #[cfg(feature = $feat)]
        {
            $chain.figment = $chain.figment.merge(<$prov>::file($path));
        }
        #[cfg(not(feature = $feat))]
        {
            ::tracing::warn!(
                path = %$path.display(),
                "{}",
                $crate::provider::missing_feature_warning_body($feat, $format),
            );
        }
    }};
}

/// Builder for a figment provider chain.
///
/// Layers are merged in order — later layers override earlier ones.
/// The typical pattern: defaults → env vars → config file.
///
/// Each `with_*` call also records a typed [`ConfigSource`] entry in
/// merge order, queryable via [`Self::sources`].
pub struct ProviderChain {
    figment: Figment,
    sources: Vec<ConfigSource>,
}

impl ProviderChain {
    /// Start with an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            figment: Figment::new(),
            sources: Vec::new(),
        }
    }

    /// Merge serde-serializable defaults as the base layer.
    ///
    /// The body is a single call through
    /// [`merge_serialized_defaults_layer`] — the shared "figment
    /// `Serialized::defaults` merge + `ConfigSource::Defaults` provenance
    /// push" substrate the peer [`Self::with_discovered`] tier-builder also
    /// routes through, so the two callers cannot drift on either half of
    /// the Defaults-class merge protocol.
    #[must_use]
    pub fn with_defaults<T: Serialize>(self, defaults: &T) -> Self {
        merge_serialized_defaults_layer(self, defaults)
    }

    /// Merge an environment-**discovered** partial config as the discovered
    /// tier.
    ///
    /// The discovered tier sits *above* serde/prescribed defaults and *below*
    /// operator file/env config: call it after [`Self::with_defaults`] and
    /// before [`Self::with_env`] / [`Self::with_file`]. The **load-bearing
    /// guarantee** is that the discovered tier is below *both* env and file;
    /// their mutual order then follows shikumi's own convention (file merged
    /// last wins, per [`Self::with_file`]'s "defaults → env → file" pattern):
    ///
    /// ```text
    /// serde/prescribed defaults → DISCOVERED → env → file   (later wins per key)
    /// ```
    ///
    /// `dict` is typically [`crate::discovered::compose`]d from a stack of
    /// [`crate::discovered::DiscoveryLayer`]s. Merged with figment's deep
    /// per-key semantics (the same `Serialized::defaults(_).merge()` mechanism
    /// as [`Self::with_defaults`]), so it overrides the developer's defaults
    /// only on the keys it actually sets.
    ///
    /// Provenance is recorded as [`ConfigSource::Defaults`] — the discovered
    /// tier is a *computed-defaults* layer (the same class as serde defaults:
    /// machine-derived, not operator-supplied). A dedicated `Discovered`
    /// provenance variant is a deliberate future refinement (it would thread
    /// through the attribution typescape); recording it as `Defaults` keeps the
    /// layer-kind partition honest today.
    ///
    /// **Precondition — do not wire this into a [`crate::ConfigStore`] *reload*
    /// path yet.** Reload replays the recorded [`ConfigSource`] chain through
    /// [`Self::with_source`], where `Defaults` is the identity (it carries no
    /// reconstructable value). A discovered layer recorded as `Defaults` would
    /// therefore be **dropped on reload**. This primitive is for *direct* chain
    /// construction (compute the dict, merge it each build); a reload-stable
    /// `ConfigStore` integration must first land the `Discovered` provenance
    /// variant so the layer survives replay.
    ///
    /// The body is a single call through
    /// [`merge_serialized_defaults_layer`] — the shared "figment
    /// `Serialized::defaults` merge + `ConfigSource::Defaults` provenance
    /// push" substrate the peer [`Self::with_defaults`] developer-defaults
    /// builder also routes through, so the two callers cannot drift on
    /// either half of the Defaults-class merge protocol.
    #[must_use]
    pub fn with_discovered(self, dict: Dict) -> Self {
        merge_serialized_defaults_layer(self, &dict)
    }

    /// Compose a stack of [`crate::discovered::DiscoveryLayer`]s and merge the
    /// result as the discovered tier — convenience over
    /// [`crate::discovered::compose`] + [`Self::with_discovered`].
    #[must_use]
    pub fn with_discovery_layers(self, layers: &[&dyn crate::discovered::DiscoveryLayer]) -> Self {
        self.with_discovered(crate::discovered::compose(layers))
    }

    /// Merge environment variables with the given prefix.
    ///
    /// Nested keys use `__` as separator (e.g. `MYAPP_OPTIONS__PADDING=10`).
    #[must_use]
    pub fn with_env(mut self, prefix: &str) -> Self {
        self.figment = self.figment.merge(Env::prefixed(prefix).split("__"));
        self.sources.push(ConfigSource::Env(prefix.to_owned()));
        self
    }

    /// Merge a config file, auto-detecting format by extension.
    ///
    /// - `.yaml` / `.yml` → YAML provider
    /// - `.toml` → TOML provider
    /// - `.lisp` / `.lsp` / `.el` → Tatara-lisp provider ([`crate::LispProvider`])
    /// - `.nix` → Nix provider ([`crate::NixProvider`], shells out to `nix eval`)
    /// - anything else → TOML provider (conservative fallback)
    #[must_use]
    pub fn with_file(mut self, path: &Path) -> Self {
        let format = Format::from_path(path);

        match format {
            Some(Format::Yaml) => {
                self.figment = self.figment.merge(FigYaml::file(path));
            }
            Some(Format::Lisp) => merge_or_warn_missing_feature!(
                chain = self,
                path = path,
                feature = "lisp",
                format = Format::Lisp,
                provider = crate::lisp_provider::LispProvider,
            ),
            Some(Format::Nix) => {
                self.figment = self
                    .figment
                    .merge(crate::nix_provider::NixProvider::file(path));
            }
            // Gated INSIDE the arm, exactly as `Lisp` above: a `.b` file on a
            // build without the feature is a warning and a skipped layer, not
            // a hard error. Erroring would make an optional dependency
            // load-bearing for anyone who merely has a `.b` sitting in a
            // config directory. Both halves — the enabled `.merge(...)` and
            // the disabled operator-facing warning body — are emitted by the
            // shared `merge_or_warn_missing_feature!` substrate macro, so
            // the [`Lisp`] and [`Blue`] arms cannot drift on either half.
            Some(Format::Blue) => merge_or_warn_missing_feature!(
                chain = self,
                path = path,
                feature = "blue",
                format = Format::Blue,
                provider = crate::blue_provider::BlueProvider,
            ),
            Some(Format::Toml) | None => {
                self.figment = self.figment.merge(FigToml::file(path));
            }
        }
        self.sources.push(ConfigSource::File(path.to_path_buf()));
        self
    }

    /// Replay one recorded [`ConfigSource`] back into the chain.
    ///
    /// This is the structural inverse of the `with_*` builders: where
    /// [`Self::with_file`] / [`Self::with_env`] each *record* a
    /// [`ConfigSource`] as a side effect of merging a layer, `with_source`
    /// *reads one back* and re-applies the matching builder. It is the
    /// per-layer primitive behind store reload —
    /// [`crate::ConfigStore::reload`] folds its recorded chain (the
    /// construction recipe) through this method to reproduce the exact
    /// layered merge that first built the store, rather than rebuilding
    /// from a single primary path (which would silently drop every other
    /// file in a merged chain).
    ///
    /// Co-locating the inverse with the forward builders keeps the
    /// record↔replay correspondence at one site. The `match` is exhaustive
    /// in-crate (`#[non_exhaustive]` relaxes exhaustivity only for
    /// downstream crates), so a future [`ConfigSource`] variant cannot be
    /// added without teaching its replay here, in the same file as the
    /// builder that records it — closing the seam that once let reload drop
    /// layers, now as a compile-time obligation rather than a convention.
    ///
    /// [`ConfigSource::Defaults`] is the identity: the serde-default base
    /// layer is implicit and its serialized value is not retained on the
    /// recorded chain, so there is nothing to re-inject. Replaying a chain
    /// that carries no explicit defaults value leaves that base intact,
    /// which matches the original load.
    #[must_use]
    pub fn with_source(self, source: &ConfigSource) -> Self {
        match source {
            ConfigSource::File(path) => self.with_file(path),
            ConfigSource::Env(prefix) => self.with_env(prefix),
            ConfigSource::Defaults => self,
        }
    }

    /// Recorded sources in merge order (lowest priority first).
    ///
    /// Each `with_*` builder call appends one [`ConfigSource`] entry. The
    /// list is the structural record of which layers contributed to the
    /// final configuration; consumers can show it in errors, debug
    /// dumps, or attestation manifests.
    #[must_use]
    pub fn sources(&self) -> &[ConfigSource] {
        &self.sources
    }

    /// Extract the final configuration along with the recorded
    /// [`ConfigSource`] chain.
    ///
    /// On success returns `(value, sources)`; on failure returns
    /// [`ShikumiError::Extract`], which embeds the same chain so callers
    /// can show *which* layers contributed to the failure without
    /// re-walking discovery.
    ///
    /// This is the primitive; [`Self::extract`] is the convenience
    /// wrapper that drops sources on success.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Extract`] if extraction fails (missing
    /// required fields, type mismatches, malformed file, etc.).
    pub fn extract_with_sources<T: for<'de> Deserialize<'de>>(
        self,
    ) -> Result<(T, Vec<ConfigSource>), ShikumiError> {
        let Self { figment, sources } = self;
        match figment.extract::<T>() {
            Ok(value) => Ok((value, sources)),
            Err(error) => Err(ShikumiError::Extract {
                sources,
                error: Box::new(error),
            }),
        }
    }

    /// Extract the final configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Extract`] if extraction fails (missing
    /// required fields, type mismatches, etc.). The error carries the
    /// typed source chain that produced the failure; use
    /// [`Self::extract_with_sources`] if you also need the chain on
    /// success.
    pub fn extract<T: for<'de> Deserialize<'de>>(self) -> Result<T, ShikumiError> {
        self.extract_with_sources().map(|(value, _)| value)
    }

    /// Escape hatch: return the raw `Figment` for advanced use.
    #[must_use]
    pub fn build(self) -> Figment {
        self.figment
    }
}

impl Default for ProviderChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use tempfile::TempDir;

    #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
    struct TestConfig {
        name: Option<String>,
        count: Option<u32>,
    }

    // ---- figment_default_{dict,array,empty_none} ----
    //
    // The three "default-tagged fresh figment Value" constructor helpers
    // every shikumi-built provider that hands figment a Value it
    // constructed itself routes through. Before the lift both
    // `json_value_to_figment` (the JSON-object/array/null arms) and the
    // `lisp_provider::sexp_to_value_root` / `sexp_to_value` sites (the
    // kwargs-list / Nil / non-kwargs-list arms) open-coded the same
    // two-argument tuple constructor with `figment::value::Tag::Default`
    // named at each callsite — the drift-class these helpers close.
    // These pins keep the helpers' shape (variant + tag + payload) at
    // ONE substrate site: a future drift that changed the tag or
    // swapped the variant would fire here before it could reach a
    // provider caller.

    /// The [`Value::Dict`] variant is tagged with
    /// [`figment::value::Tag::Default`] and carries the caller-supplied
    /// [`Dict`] verbatim — no key or value is re-`.into()`'d,
    /// re-allocated, or reordered. The two-arm assertion pins both
    /// halves of the drift-class: the variant chosen AND the tag
    /// chosen.
    #[test]
    fn figment_default_dict_wraps_the_caller_dict_verbatim_with_the_default_tag() {
        let mut d = Dict::new();
        d.insert("k".to_string(), Value::from("v"));
        d.insert("n".to_string(), Value::from(42i64));
        let owned = d.clone();
        let v = figment_default_dict(d);
        let Value::Dict(tag, out) = v else {
            panic!("figment_default_dict must construct a Value::Dict");
        };
        assert_eq!(
            tag,
            figment::value::Tag::Default,
            "the tag must be Tag::Default; a drift here means the helper started \
             synthesizing a bespoke tag and the drift-class it closes reopened"
        );
        assert_eq!(
            out, owned,
            "the emitted dict must equal the caller-supplied dict byte-for-byte"
        );
    }

    /// The empty-dict case (used by `sexp_to_value_root` on `(defX)` with
    /// no fields) MUST still route through the same helper — no
    /// specialized `Value::Dict(_, Dict::new())` sidepath. This pins
    /// the callsite convention: every construction goes through the
    /// helper, even for the empty-payload case.
    #[test]
    fn figment_default_dict_on_an_empty_dict_yields_a_default_tagged_empty_value_dict() {
        let v = figment_default_dict(Dict::new());
        let Value::Dict(tag, out) = v else {
            panic!("figment_default_dict must construct a Value::Dict even for an empty payload");
        };
        assert_eq!(tag, figment::value::Tag::Default);
        assert!(
            out.is_empty(),
            "the emitted dict must be empty when the input is empty"
        );
    }

    /// The [`Value::Array`] variant is tagged with
    /// [`figment::value::Tag::Default`] and carries the caller-supplied
    /// [`Vec<Value>`] verbatim — no element is re-`.into()`'d,
    /// re-allocated, or reordered. Same two-arm shape as the
    /// dict-side pin.
    #[test]
    fn figment_default_array_wraps_the_caller_vec_verbatim_with_the_default_tag() {
        let items: Vec<Value> = vec![Value::from(1i64), Value::from("two"), Value::from(3.5f64)];
        let owned = items.clone();
        let v = figment_default_array(items);
        let Value::Array(tag, out) = v else {
            panic!("figment_default_array must construct a Value::Array");
        };
        assert_eq!(
            tag,
            figment::value::Tag::Default,
            "the tag must be Tag::Default; a drift here means the helper started \
             synthesizing a bespoke tag and the drift-class it closes reopened"
        );
        assert_eq!(
            out, owned,
            "the emitted array must equal the caller-supplied vec element-for-element"
        );
    }

    /// The [`Value::Empty`] variant is tagged with
    /// [`figment::value::Tag::Default`] and carries
    /// [`figment::value::Empty::None`] — the canonical
    /// [`Option::None`] counterpart figment's own deserializer
    /// expects. Three arms pinned in one assertion: variant, tag,
    /// and empty-inhabitant.
    #[test]
    fn figment_default_empty_none_is_default_tagged_value_empty_of_empty_none() {
        let v = figment_default_empty_none();
        let Value::Empty(tag, empty) = v else {
            panic!("figment_default_empty_none must construct a Value::Empty");
        };
        assert_eq!(tag, figment::value::Tag::Default);
        assert!(
            matches!(empty, figment::value::Empty::None),
            "the empty inhabitant must be Empty::None so figment's deserializer treats \
             the projection as Option::None; a drift to Empty::Unit here would silently \
             change the JSON-null / Sexp::Nil semantics every text-source and \
             JSON-source shikumi-built provider rides"
        );
    }

    /// The two `figment_default_empty_none()` sites inside
    /// [`json_value_to_figment`] — the JSON-null arm and the
    /// unreachable [`serde_json::Number`]-cascade fallback arm — must
    /// each emit the exact byte-identical [`Value`] the helper does,
    /// not an ad-hoc copy of the same two-argument constructor. If a
    /// future refactor of `json_value_to_figment` reintroduces the
    /// open-coded form, this cross-callsite pin fires.
    #[test]
    fn json_value_to_figment_null_arm_routes_through_figment_default_empty_none() {
        let via_helper = figment_default_empty_none();
        let via_json = json_value_to_figment(&serde_json::Value::Null);
        assert_eq!(
            via_json, via_helper,
            "json_value_to_figment(Null) must route through figment_default_empty_none() \
             — drift means the JSON-null arm reintroduced an open-coded \
             Value::Empty(Tag::Default, Empty::None)"
        );
    }

    // ---- text_source_provider_struct! (struct + `file(path)` ctor) ----
    //
    // The shared struct declaration + `file(path)` ctor every text-source
    // shikumi-built provider carries. Before this lift both
    // `LispProvider` (`lisp` feature) and `BlueProvider` (`blue` feature)
    // open-coded byte-identical `#[derive(Debug, Clone)] pub struct X
    // { path: PathBuf }` + `pub fn file(path: impl Into<PathBuf>) -> Self
    // { Self { path: path.into() } }` bodies. These tests pin the
    // fusion at ONE substrate site so a caller sensing shape changes
    // still trips them.

    /// The emitted struct MUST derive both `Debug` and `Clone`. Both are
    /// load-bearing: `Debug` is what an operator sees on a figment
    /// extract-error path (via `#[derive(Debug)]` on `figment::Error`'s
    /// `Metadata` tree); `Clone` is what every builder-style consumer
    /// (`Figment::merge`, per-tick reload) relies on to fan the
    /// provider into multiple chains without moving the caller's
    /// handle. A future drift of the macro that drops either bound
    /// fires this compile-time trait pin.
    ///
    /// Written as a monomorphizing free function on `T: Debug + Clone`,
    /// invoked with the macro-emitted type. If either bound goes away
    /// the invocation fails to typecheck, so this is a compile-time
    /// obligation, not a runtime assertion.
    #[cfg(feature = "lisp")]
    #[test]
    fn text_source_provider_struct_lisp_derives_debug_and_clone() {
        fn assert_debug_and_clone<T: ::std::fmt::Debug + ::std::clone::Clone>() {}
        assert_debug_and_clone::<crate::lisp_provider::LispProvider>();
    }

    /// Blue-side peer of the derive-pin above — pinned in the SAME
    /// substrate-site module (not blue's own tests) so a future
    /// hand-edit that reintroduces a bespoke `pub struct BlueProvider
    /// { … }` without `#[derive(Debug, Clone)]` fires from this file,
    /// alongside the lisp-side derive-pin.
    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_struct_blue_derives_debug_and_clone() {
        fn assert_debug_and_clone<T: ::std::fmt::Debug + ::std::clone::Clone>() {}
        assert_debug_and_clone::<crate::blue_provider::BlueProvider>();
    }

    /// The emitted `file(path)` ctor MUST accept both `&Path` and owned
    /// `PathBuf` (per the `impl Into<PathBuf>` bound) AND MUST store
    /// the path such that `Provider::metadata()` renders it verbatim
    /// through `Format::metadata_name`. The metadata round-trip is
    /// the observable proof that the `path` field the emitted ctor
    /// wrote is the same one the emitted `impl Provider::metadata`
    /// body reads.
    ///
    /// Written as a live drift-closure against
    /// `LispProvider::file(&Path)` and `LispProvider::file(PathBuf)`:
    /// a future macro-body edit that stops storing the caller's path
    /// (a canonicalization pass silently normalising away symlinks, a
    /// [`OnceLock`] wrapper hiding the raw string) fires this test
    /// with the concrete-vs-expected mismatch, not a downstream
    /// resolver failure.
    #[cfg(feature = "lisp")]
    #[test]
    fn text_source_provider_struct_lisp_ctor_accepts_ref_and_owned_and_stores_path() {
        use ::figment::Provider;
        let path = ::std::path::PathBuf::from("/tmp/some/lisp-ctor.lisp");

        let from_ref = crate::lisp_provider::LispProvider::file(&path);
        let md_ref = from_ref.metadata();
        assert_eq!(
            md_ref.name.as_ref(),
            Format::Lisp.metadata_name(&path),
            "ctor from &Path must store the path so Provider::metadata renders it",
        );

        let from_owned = crate::lisp_provider::LispProvider::file(path.clone());
        let md_owned = from_owned.metadata();
        assert_eq!(
            md_owned.name.as_ref(),
            Format::Lisp.metadata_name(&path),
            "ctor from PathBuf must store the same path as the &Path form",
        );
    }

    /// Blue-side peer of the ctor-round-trip pin above. Blue rides the
    /// SAME `text_source_provider_struct!` macro emission, so the
    /// pre-lift byte-identical shape is asserted here (not at blue's
    /// own tests) — a future hand-edit that reintroduces a bespoke
    /// `impl BlueProvider { pub fn file(path) -> Self { … } }`
    /// dropping the `impl Into<PathBuf>` bound, or the `#[must_use]`
    /// attribute, or the store-then-emit shape, fires from this file
    /// alongside the lisp-side counterpart.
    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_struct_blue_ctor_accepts_ref_and_owned_and_stores_path() {
        use ::figment::Provider;
        let path = ::std::path::PathBuf::from("/tmp/some/blue-ctor.b");

        let from_ref = crate::blue_provider::BlueProvider::file(&path);
        let md_ref = from_ref.metadata();
        assert_eq!(
            md_ref.name.as_ref(),
            Format::Blue.metadata_name(&path),
            "ctor from &Path must store the path so Provider::metadata renders it",
        );

        let from_owned = crate::blue_provider::BlueProvider::file(path.clone());
        let md_owned = from_owned.metadata();
        assert_eq!(
            md_owned.name.as_ref(),
            Format::Blue.metadata_name(&path),
            "ctor from PathBuf must store the same path as the &Path form",
        );
    }

    /// The emitted `Clone` impl MUST preserve the stored path — a
    /// derived `Clone` on a `PathBuf` field trivially satisfies this,
    /// but a future refinement of the carrier shape (a
    /// non-`Clone`-transparent wrapper around `PathBuf`, a
    /// hand-written `Clone` impl for structural sharing) could
    /// silently drift the invariant. Pinned pointwise against both
    /// text-source callers here (not at each caller's own tests) so
    /// the substrate site owns the equivalence.
    #[cfg(feature = "lisp")]
    #[test]
    fn text_source_provider_struct_lisp_clone_preserves_metadata_path() {
        use ::figment::Provider;
        let path = ::std::path::PathBuf::from("/tmp/some/lisp-clone.lisp");
        let original = crate::lisp_provider::LispProvider::file(&path);
        let cloned = original.clone();
        assert_eq!(
            original.metadata().name,
            cloned.metadata().name,
            "Clone must preserve the stored path verbatim",
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_struct_blue_clone_preserves_metadata_path() {
        use ::figment::Provider;
        let path = ::std::path::PathBuf::from("/tmp/some/blue-clone.b");
        let original = crate::blue_provider::BlueProvider::file(&path);
        let cloned = original.clone();
        assert_eq!(
            original.metadata().name,
            cloned.metadata().name,
            "Clone must preserve the stored path verbatim",
        );
    }

    // ---- missing_feature_alternatives (per-format alternatives phrase) ----
    //
    // The `.a/.b/.c` operator hint the two feature-gated arms of
    // `ProviderChain::with_file` emit inside their `#[cfg(not(feature =
    // "…"))]` warning branches. Before this lift both arms hard-coded
    // their own alternatives list — the `Lisp` arm's `.yaml/.toml/.nix`
    // never learned about the `Blue` variant when it landed, so an
    // operator whose build lacked `lisp` was told to convert to a set
    // that omitted `.b`. These tests pin the derivation at ONE substrate
    // site so a new `Format` variant automatically extends every
    // existing warning's alternatives list.

    /// The helper MUST omit the caller-supplied missing format from the
    /// output — the whole point of the "alternatives" framing is to
    /// suggest formats the current build can still load. A future
    /// regression that forgot the exclusion would tell an operator to
    /// convert `.lisp` to `.lisp`.
    #[test]
    fn missing_feature_alternatives_omits_the_missing_format() {
        for &missing in Format::ALL {
            let alt = missing_feature_alternatives(missing);
            let self_ext = format!(".{}", missing.as_str());
            assert!(
                !alt.contains(&self_ext),
                "alternatives for {missing:?} must not contain `{self_ext}`; got `{alt}`",
            );
        }
    }

    /// The helper MUST include every OTHER format's primary extension —
    /// the fix the pre-lift `Lisp` arm quietly missed on the `Blue`
    /// landing. Pinned against `Format::ALL`, so a future variant is
    /// covered by construction rather than by memory.
    #[test]
    fn missing_feature_alternatives_includes_every_other_format() {
        for &missing in Format::ALL {
            let alt = missing_feature_alternatives(missing);
            for &other in Format::ALL {
                if other == missing {
                    continue;
                }
                let other_ext = format!(".{}", other.as_str());
                assert!(
                    alt.contains(&other_ext),
                    "alternatives for {missing:?} must contain `{other_ext}`; got `{alt}`",
                );
            }
        }
    }

    /// Each entry MUST be dot-prefixed and `/`-joined, matching the
    /// pre-lift open-coded shape the two `with_file` warnings emitted —
    /// what the operator sees on the diagnostic edge does not drift
    /// across the lift. A future refinement (space-separated, quoted,
    /// listed on newlines) lands at one site now instead of two.
    #[test]
    fn missing_feature_alternatives_is_slash_joined_dot_prefixed() {
        for &missing in Format::ALL {
            let alt = missing_feature_alternatives(missing);
            let expected_count = Format::ALL.len() - 1;
            let actual_count = alt.split('/').count();
            assert_eq!(
                actual_count, expected_count,
                "alternatives for {missing:?} must contain exactly {expected_count} `/`-joined \
                 entries; got `{alt}`",
            );
            for entry in alt.split('/') {
                assert!(
                    entry.starts_with('.'),
                    "each alternatives entry must be dot-prefixed; got `{entry}` in `{alt}`",
                );
            }
        }
    }

    /// The alternatives list MUST honour `Format::ALL` declaration
    /// order — the same order every other `Format::ALL`-driven surface
    /// on this axis already renders in (`BTreeMap<Format, T>` iteration,
    /// per-format telemetry rollups, attestation manifest rows). A
    /// future implementation that sorts alphabetically, or drops in an
    /// arbitrary iteration order, would fire this pin.
    #[test]
    fn missing_feature_alternatives_preserves_format_all_declaration_order() {
        for &missing in Format::ALL {
            let alt = missing_feature_alternatives(missing);
            let expected: Vec<String> = Format::ALL
                .iter()
                .filter(|&&f| f != missing)
                .map(|f| format!(".{}", f.as_str()))
                .collect();
            assert_eq!(
                alt,
                expected.join("/"),
                "alternatives for {missing:?} must equal `Format::ALL` \\ {{missing}} \
                 in declaration order, joined by `/`",
            );
        }
    }

    /// Each alternatives entry MUST use `Format::as_str` verbatim as its
    /// suffix — the same canonical lowercase label every other
    /// [`Format`]-axis surface projects through. A future implementation
    /// that switches to the extensions()[1] alias (`.yml`, `.lsp`,
    /// `.el`), or fabricates a per-format nickname, would fire this
    /// drift-closure. Pins the (helper × `Format::as_str`) invariant at
    /// the substrate site.
    #[test]
    fn missing_feature_alternatives_uses_format_as_str_verbatim() {
        for &missing in Format::ALL {
            let alt = missing_feature_alternatives(missing);
            let entries: Vec<&str> = alt.split('/').collect();
            let mut cursor = 0;
            for &other in Format::ALL {
                if other == missing {
                    continue;
                }
                let expected_entry = format!(".{}", other.as_str());
                assert_eq!(
                    entries[cursor],
                    expected_entry,
                    "alternatives[{cursor}] for {missing:?} must be `.{as_str}` verbatim from \
                     Format::as_str; got `{got}`",
                    as_str = other.as_str(),
                    got = entries[cursor],
                );
                cursor += 1;
            }
        }
    }

    /// A hard-coded reproduction of what each of the five `Format`
    /// variants MUST render to today, byte-for-byte. Complements the
    /// per-variant structural pins above: those enforce the
    /// derivation-rule invariants (omit self, include others, dot-
    /// prefixed, `/`-joined, `Format::ALL` order, `Format::as_str`
    /// verbatim); this table pins the exact strings so a future
    /// refactor whose per-invariant behavior still passes but whose
    /// rendered output has drifted (an added trailing space, a swapped
    /// separator) fires here. New `Format` variants will require
    /// updating this table alongside `Format::ALL` — the same
    /// lockstep-with-`ALL` obligation `format_all_covers_every_variant`
    /// already enforces on the primitive itself.
    #[test]
    fn missing_feature_alternatives_renders_verbatim_for_every_variant() {
        assert_eq!(
            missing_feature_alternatives(Format::Yaml),
            ".toml/.lisp/.nix/.b",
        );
        assert_eq!(
            missing_feature_alternatives(Format::Toml),
            ".yaml/.lisp/.nix/.b",
        );
        assert_eq!(
            missing_feature_alternatives(Format::Lisp),
            ".yaml/.toml/.nix/.b",
        );
        assert_eq!(
            missing_feature_alternatives(Format::Nix),
            ".yaml/.toml/.lisp/.b",
        );
        assert_eq!(
            missing_feature_alternatives(Format::Blue),
            ".yaml/.toml/.lisp/.nix",
        );
    }

    // ---- missing_feature_warning_body (full missing-feature warning sentence) ----
    //
    // The whole `"shikumi built without the `<feature>` feature; skipping
    // .<ext> config. Enable the feature or convert to <alternatives>."`
    // sentence every feature-gated arm of `ProviderChain::with_file`
    // emits from its `#[cfg(not(feature = "…"))]` branch. Before this
    // lift each of the two in-tree arms hard-coded the whole sentence
    // (feature literal + skipped-ext literal + explicit call to
    // `missing_feature_alternatives`), so a third gated caller — a
    // `.rb` / HOCON / JSON5 / KDL front-end per the doc roadmap — would
    // have re-typed the same shape a third time. These tests pin the
    // derivation at ONE substrate site so a future refinement of the
    // operator-facing sentence lands once instead of once per caller.

    /// The body MUST embed the caller-supplied `feature` label verbatim
    /// inside a `` `…` `` pair — the operator-facing name of the missing
    /// build feature. A future regression that misprints the label
    /// (drops the backticks, prints the format's name instead of the
    /// feature's name, quietly translates the label) fires this pin.
    /// Pinned for the two feature names both in-tree arms use plus a
    /// third label a future gated caller might use (`ruby`), so the
    /// invariant is checked across the exact class of literals the
    /// macro accepts.
    #[test]
    fn missing_feature_warning_body_embeds_feature_label_verbatim() {
        for &feature in &["lisp", "blue", "ruby"] {
            let body = missing_feature_warning_body(feature, Format::Yaml);
            let quoted = format!("`{feature}`");
            assert!(
                body.contains(&quoted),
                "body must embed feature label `{feature}` inside backticks; got `{body}`",
            );
        }
    }

    /// The body's skipped-extension MUST derive from [`Format::as_str`]
    /// as `.<as_str>`, matching the pre-lift `.lisp` / `.b` literals
    /// exactly. A future implementation that switches to the
    /// [`Format::extensions`]`[1]` alias (`.yml`, `.lsp`, `.el`), or
    /// fabricates a per-format nickname, or drops the leading dot,
    /// fires this drift-closure. Pins the (helper × `Format::as_str`)
    /// invariant at the substrate site.
    #[test]
    fn missing_feature_warning_body_derives_skipped_ext_from_format_as_str() {
        for &format in Format::ALL {
            let body = missing_feature_warning_body("lisp", format);
            let expected = format!("skipping .{ext} config", ext = format.as_str());
            assert!(
                body.contains(&expected),
                "body for {format:?} must contain `{expected}`; got `{body}`",
            );
        }
    }

    /// The body's alternatives phrase MUST equal
    /// [`missing_feature_alternatives`]`(format)` verbatim — the peer
    /// substrate helper is the single source of truth for the
    /// alternatives list, and a future regression that hard-coded the
    /// list a second time in this helper would silently stale on the
    /// next [`Format`] variant. Pins the (helper × peer helper)
    /// composition at the substrate site so both halves cannot drift.
    #[test]
    fn missing_feature_warning_body_embeds_missing_feature_alternatives_verbatim() {
        for &format in Format::ALL {
            let body = missing_feature_warning_body("lisp", format);
            let alt = missing_feature_alternatives(format);
            let expected_tail = format!("convert to {alt}.");
            assert!(
                body.contains(&expected_tail),
                "body for {format:?} must contain `{expected_tail}`; got `{body}`",
            );
        }
    }

    /// A hard-coded reproduction of what each of the five `Format`
    /// variants MUST render to today, byte-for-byte, for the two
    /// feature labels both in-tree arms use. Complements the
    /// per-invariant structural pins above: those enforce the
    /// derivation-rule invariants (feature verbatim, skipped-ext via
    /// `Format::as_str`, alternatives via `missing_feature_alternatives`);
    /// this table pins the exact rendered strings so a future refactor
    /// whose per-invariant behavior still passes but whose rendered
    /// output has drifted (an added trailing space, a swapped phrase, a
    /// dropped period) fires here. New `Format` variants require
    /// updating this table alongside `Format::ALL`, the same lockstep-
    /// with-`ALL` obligation `format_all_covers_every_variant` enforces
    /// on the primitive itself and
    /// `missing_feature_alternatives_renders_verbatim_for_every_variant`
    /// enforces on the peer sub-phrase helper.
    #[test]
    fn missing_feature_warning_body_renders_verbatim_for_every_variant() {
        // The `lisp` feature label, one row per `Format` variant.
        assert_eq!(
            missing_feature_warning_body("lisp", Format::Yaml),
            "shikumi built without the `lisp` feature; skipping .yaml config. \
             Enable the feature or convert to .toml/.lisp/.nix/.b.",
        );
        assert_eq!(
            missing_feature_warning_body("lisp", Format::Toml),
            "shikumi built without the `lisp` feature; skipping .toml config. \
             Enable the feature or convert to .yaml/.lisp/.nix/.b.",
        );
        assert_eq!(
            missing_feature_warning_body("lisp", Format::Lisp),
            "shikumi built without the `lisp` feature; skipping .lisp config. \
             Enable the feature or convert to .yaml/.toml/.nix/.b.",
        );
        assert_eq!(
            missing_feature_warning_body("lisp", Format::Nix),
            "shikumi built without the `lisp` feature; skipping .nix config. \
             Enable the feature or convert to .yaml/.toml/.lisp/.b.",
        );
        assert_eq!(
            missing_feature_warning_body("lisp", Format::Blue),
            "shikumi built without the `lisp` feature; skipping .b config. \
             Enable the feature or convert to .yaml/.toml/.lisp/.nix.",
        );
        // The `blue` feature label, same variants — pins the two
        // in-tree caller-relevant `(feature, format)` pairs verbatim.
        // `("lisp", Format::Lisp)` above and `("blue", Format::Blue)`
        // below are the ONLY two combinations `ProviderChain::with_file`
        // ever reaches today; the others exist so a third gated caller
        // (a `ruby`/`hocon`/`json5`/`kdl` front-end) inherits a body
        // shape whose derivation is pinned across every `Format`
        // variant it could land under.
        assert_eq!(
            missing_feature_warning_body("blue", Format::Blue),
            "shikumi built without the `blue` feature; skipping .b config. \
             Enable the feature or convert to .yaml/.toml/.lisp/.nix.",
        );
    }

    #[test]
    fn defaults_only() {
        let defaults = TestConfig {
            name: Some("default".into()),
            count: Some(42),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("default"));
        assert_eq!(config.count, Some(42));
    }

    #[test]
    fn yaml_file_overrides_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.yaml");
        fs::write(&file, "name: from_yaml\ncount: 99\n").unwrap();

        let defaults = TestConfig {
            name: Some("default".into()),
            count: Some(1),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_file(&file)
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("from_yaml"));
        assert_eq!(config.count, Some(99));
    }

    #[test]
    fn toml_file_overrides_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.toml");
        fs::write(&file, "name = \"from_toml\"\ncount = 7\n").unwrap();

        let config: TestConfig = ProviderChain::new().with_file(&file).extract().unwrap();
        assert_eq!(config.name.as_deref(), Some("from_toml"));
        assert_eq!(config.count, Some(7));
    }

    #[test]
    fn env_overrides_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.yaml");
        fs::write(&file, "name: from_file\ncount: 1\n").unwrap();

        let var = "SHIKUMI_PTEST_NAME";
        unsafe { std::env::set_var(var, "from_env") };

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .with_env("SHIKUMI_PTEST_")
            .extract()
            .unwrap();

        unsafe { std::env::remove_var(var) };

        // env is merged after file, so it wins
        assert_eq!(config.name.as_deref(), Some("from_env"));
        assert_eq!(config.count, Some(1));
    }

    #[test]
    fn file_overrides_env_when_layered_last() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.yaml");
        fs::write(&file, "name: from_file\n").unwrap();

        let var = "SHIKUMI_PTEST2_NAME";
        unsafe { std::env::set_var(var, "from_env") };

        let config: TestConfig = ProviderChain::new()
            .with_env("SHIKUMI_PTEST2_")
            .with_file(&file)
            .extract()
            .unwrap();

        unsafe { std::env::remove_var(var) };

        // file is merged after env, so file wins
        assert_eq!(config.name.as_deref(), Some("from_file"));
    }

    #[test]
    fn extract_error_on_invalid_type() {
        #[derive(Deserialize)]
        struct Strict {
            #[allow(dead_code)]
            required_field: String,
        }

        let result = ProviderChain::new().extract::<Strict>();
        assert!(result.is_err());
    }

    #[test]
    fn build_returns_raw_figment() {
        let figment = ProviderChain::new()
            .with_defaults(&TestConfig::default())
            .build();
        let config: TestConfig = figment.extract().unwrap();
        assert_eq!(config, TestConfig::default());
    }

    #[test]
    fn yml_extension_treated_as_yaml() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.yml");
        fs::write(&file, "name: from_yml\ncount: 55\n").unwrap();

        let config: TestConfig = ProviderChain::new().with_file(&file).extract().unwrap();
        assert_eq!(config.name.as_deref(), Some("from_yml"));
        assert_eq!(config.count, Some(55));
    }

    #[test]
    fn empty_yaml_file_produces_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.yaml");
        fs::write(&file, "").unwrap();

        let config: TestConfig = ProviderChain::new().with_file(&file).extract().unwrap();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn empty_toml_file_produces_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.toml");
        fs::write(&file, "").unwrap();

        let config: TestConfig = ProviderChain::new().with_file(&file).extract().unwrap();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn defaults_partially_overridden_by_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("partial.yaml");
        // Only override name, not count
        fs::write(&file, "name: overridden\n").unwrap();

        let defaults = TestConfig {
            name: Some("original".into()),
            count: Some(100),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_file(&file)
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("overridden"));
        // count should retain the default
        assert_eq!(config.count, Some(100));
    }

    #[test]
    fn nested_env_var_with_double_underscore() {
        #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
        struct NestedConfig {
            options: Option<NestedOptions>,
        }
        #[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
        struct NestedOptions {
            padding: Option<u32>,
            color: Option<String>,
        }

        let prefix = "SHIKUMI_NESTED_TEST_";
        unsafe { std::env::set_var("SHIKUMI_NESTED_TEST_OPTIONS__PADDING", "42") };
        unsafe { std::env::set_var("SHIKUMI_NESTED_TEST_OPTIONS__COLOR", "blue") };

        let config: NestedConfig = ProviderChain::new().with_env(prefix).extract().unwrap();

        unsafe { std::env::remove_var("SHIKUMI_NESTED_TEST_OPTIONS__PADDING") };
        unsafe { std::env::remove_var("SHIKUMI_NESTED_TEST_OPTIONS__COLOR") };

        let opts = config.options.expect("nested options should be present");
        assert_eq!(opts.padding, Some(42));
        assert_eq!(opts.color.as_deref(), Some("blue"));
    }

    #[test]
    fn env_overrides_defaults_no_file() {
        let prefix = "SHIKUMI_ENVDEF_";
        unsafe { std::env::set_var("SHIKUMI_ENVDEF_NAME", "env_only") };

        let defaults = TestConfig {
            name: Some("default".into()),
            count: Some(10),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_env(prefix)
            .extract()
            .unwrap();

        unsafe { std::env::remove_var("SHIKUMI_ENVDEF_NAME") };

        assert_eq!(config.name.as_deref(), Some("env_only"));
        assert_eq!(config.count, Some(10));
    }

    #[test]
    fn nonexistent_file_silently_ignored() {
        // Figment file providers silently return empty when file doesn't exist
        let config: TestConfig = ProviderChain::new()
            .with_file(Path::new("/nonexistent/config.yaml"))
            .extract()
            .unwrap();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn invalid_yaml_causes_extract_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("invalid.yaml");
        fs::write(&file, "name: [unclosed bracket\n").unwrap();

        let result = ProviderChain::new()
            .with_file(&file)
            .extract::<TestConfig>();
        assert!(result.is_err(), "expected error for invalid YAML");
    }

    #[test]
    fn invalid_toml_causes_extract_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("invalid.toml");
        fs::write(&file, "name = [unclosed").unwrap();

        let result = ProviderChain::new()
            .with_file(&file)
            .extract::<TestConfig>();
        assert!(result.is_err(), "expected error for invalid TOML");
    }

    #[test]
    fn unicode_values_preserved() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("unicode.yaml");
        fs::write(&file, "name: \"仕組み config 🔧\"\n").unwrap();

        let config: TestConfig = ProviderChain::new().with_file(&file).extract().unwrap();
        assert_eq!(config.name.as_deref(), Some("仕組み config 🔧"));
    }

    #[test]
    fn type_mismatch_causes_extract_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("mismatch.yaml");
        // count expects u32, provide a string
        fs::write(&file, "count: not_a_number\n").unwrap();

        let result = ProviderChain::new()
            .with_file(&file)
            .extract::<TestConfig>();
        assert!(result.is_err(), "expected error for type mismatch");
    }

    #[test]
    fn multiple_files_last_wins() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("first.yaml");
        let file2 = dir.path().join("second.yaml");
        fs::write(&file1, "name: first\ncount: 1\n").unwrap();
        fs::write(&file2, "name: second\n").unwrap();

        let config: TestConfig = ProviderChain::new()
            .with_file(&file1)
            .with_file(&file2)
            .extract()
            .unwrap();
        // second file overrides name
        assert_eq!(config.name.as_deref(), Some("second"));
        // count from first file preserved (second doesn't set it)
        assert_eq!(config.count, Some(1));
    }

    #[test]
    fn default_provider_chain_is_empty() {
        let chain = ProviderChain::default();
        let config: TestConfig = chain.extract().unwrap();
        assert_eq!(config, TestConfig::default());
    }

    #[test]
    fn sources_empty_for_new_chain() {
        let chain = ProviderChain::new();
        assert!(chain.sources().is_empty());
    }

    #[test]
    fn sources_records_defaults() {
        let defaults = TestConfig::default();
        let chain = ProviderChain::new().with_defaults(&defaults);
        assert_eq!(chain.sources(), &[crate::ConfigSource::Defaults]);
    }

    #[test]
    fn sources_records_env_with_prefix() {
        let chain = ProviderChain::new().with_env("MYAPP_");
        assert_eq!(
            chain.sources(),
            &[crate::ConfigSource::Env("MYAPP_".to_owned())]
        );
    }

    #[test]
    fn sources_records_file_path() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("c.yaml");
        fs::write(&file, "name: x\n").unwrap();
        let chain = ProviderChain::new().with_file(&file);
        assert_eq!(chain.sources(), &[crate::ConfigSource::File(file)]);
    }

    #[test]
    fn sources_records_full_chain_in_merge_order() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("c.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let defaults = TestConfig::default();
        let chain = ProviderChain::new()
            .with_defaults(&defaults)
            .with_env("APP_")
            .with_file(&file);

        let s = chain.sources();
        assert_eq!(s.len(), 3);
        assert!(s[0].is_defaults());
        assert!(s[1].is_env());
        assert_eq!(s[1].as_env_prefix(), Some("APP_"));
        assert!(s[2].is_file());
        assert_eq!(s[2].as_path(), Some(file.as_path()));
    }

    #[test]
    fn sources_persist_after_clone_via_build() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("c.yaml");
        fs::write(&file, "name: x\n").unwrap();
        let chain = ProviderChain::new().with_file(&file).with_env("X_");
        let recorded = chain.sources().to_vec();
        // build() consumes; recorded survives.
        let _ = chain.build();
        assert_eq!(recorded.len(), 2);
    }

    // ---- extract_with_sources / source-annotated error tests ----

    #[test]
    fn extract_with_sources_returns_value_and_chain() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("ews.yaml");
        fs::write(&file, "name: ok\ncount: 3\n").unwrap();

        let (config, sources): (TestConfig, _) = ProviderChain::new()
            .with_defaults(&TestConfig::default())
            .with_file(&file)
            .extract_with_sources()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("ok"));
        assert_eq!(config.count, Some(3));
        assert_eq!(sources.len(), 2);
        assert!(sources[0].is_defaults());
        assert!(sources[1].is_file());
    }

    #[test]
    fn extract_with_sources_attaches_chain_on_failure() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("ews_bad.yaml");
        fs::write(&file, "count: not_a_number\n").unwrap();

        let err = ProviderChain::new()
            .with_env("EWS_BAD_")
            .with_file(&file)
            .extract_with_sources::<TestConfig>()
            .unwrap_err();

        let attached = err.sources().expect("Extract carries provenance");
        assert_eq!(attached.len(), 2, "env + file");
        assert_eq!(attached[0].as_env_prefix(), Some("EWS_BAD_"));
        assert_eq!(attached[1].as_path(), Some(file.as_path()));
    }

    #[test]
    fn extract_failure_emits_extract_variant_with_sources_in_display() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("ews_disp.yaml");
        fs::write(&file, "count: not_a_number\n").unwrap();

        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<TestConfig>()
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("config extraction failed"));
        assert!(
            msg.contains(&file.display().to_string()),
            "error must cite the failing file path; got: {msg}"
        );
    }

    #[test]
    fn extract_with_sources_empty_chain_on_failure() {
        // No layers added at all → still an Extract with an empty chain
        // so callers can distinguish "shikumi-routed failure" from
        // legacy `Figment` conversions.
        #[derive(Deserialize, Debug)]
        struct Strict {
            #[allow(dead_code)]
            required: String,
        }
        let err = ProviderChain::new()
            .extract_with_sources::<Strict>()
            .unwrap_err();
        let attached = err.sources().expect("Extract carries provenance");
        assert!(attached.is_empty(), "no layers, but provenance is recorded");
    }

    #[test]
    fn full_three_layer_chain() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("layers.yaml");
        fs::write(&file, "name: from_file\n").unwrap();

        let prefix = "SHIKUMI_3LAYER_";
        unsafe { std::env::set_var("SHIKUMI_3LAYER_COUNT", "77") };

        let defaults = TestConfig {
            name: Some("default_name".into()),
            count: Some(0),
        };

        // defaults -> file -> env
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_file(&file)
            .with_env(prefix)
            .extract()
            .unwrap();

        unsafe { std::env::remove_var("SHIKUMI_3LAYER_COUNT") };

        // name: file overrides default
        assert_eq!(config.name.as_deref(), Some("from_file"));
        // count: env overrides default (file doesn't set count)
        assert_eq!(config.count, Some(77));
    }

    // ---- discovered tier (with_discovered / with_discovery_layers) ----

    #[test]
    fn discovered_overrides_defaults_per_key() {
        let mut d = Dict::new();
        d.insert("name".to_owned(), Value::from("from_discovered"));
        let defaults = TestConfig {
            name: Some("dev_default".into()),
            count: Some(5),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_discovered(d)
            .extract()
            .unwrap();
        assert_eq!(
            config.name.as_deref(),
            Some("from_discovered"),
            "discovered beats developer defaults"
        );
        assert_eq!(
            config.count,
            Some(5),
            "key the discovered layer didn't set keeps the default"
        );
    }

    #[test]
    fn file_and_env_both_override_discovered() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("over.yaml");
        fs::write(&file, "name: from_file\n").unwrap();
        let var = "SHIKUMI_DISC_COUNT";
        unsafe { std::env::set_var(var, "9") };

        let mut d = Dict::new();
        d.insert("name".to_owned(), Value::from("from_discovered"));
        d.insert("count".to_owned(), Value::from(1i64));

        // defaults → discovered → env → file: operator layers (file, env) win.
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&TestConfig::default())
            .with_discovered(d)
            .with_env("SHIKUMI_DISC_")
            .with_file(&file)
            .extract()
            .unwrap();
        unsafe { std::env::remove_var(var) };
        assert_eq!(
            config.name.as_deref(),
            Some("from_file"),
            "file beats discovered"
        );
        assert_eq!(config.count, Some(9), "env beats discovered");
    }

    #[test]
    fn empty_discovered_is_noop_over_defaults() {
        let defaults = TestConfig {
            name: Some("keep".into()),
            count: Some(7),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_discovered(Dict::new())
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("keep"));
        assert_eq!(config.count, Some(7));
    }

    #[test]
    fn discovered_records_defaults_class_provenance() {
        let chain = ProviderChain::new().with_discovered(Dict::new());
        assert_eq!(chain.sources(), &[ConfigSource::Defaults]);
    }

    #[test]
    fn with_discovery_layers_composes_specific_over_coarse() {
        use crate::discovered::DiscoveryLayer;

        struct Layer(&'static str, &'static str);
        impl DiscoveryLayer for Layer {
            fn name(&self) -> &'static str {
                "test"
            }
            fn discover(&self) -> Dict {
                let mut d = Dict::new();
                d.insert(self.0.to_owned(), Value::from(self.1));
                d
            }
        }

        let coarse = Layer("name", "coarse");
        let specific = Layer("name", "specific");
        let config: TestConfig = ProviderChain::new()
            .with_discovery_layers(&[&coarse, &specific])
            .extract()
            .unwrap();
        assert_eq!(
            config.name.as_deref(),
            Some("specific"),
            "later (more-specific) layer wins under composition"
        );
    }

    #[test]
    fn with_source_file_records_and_loads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("replay.yaml");
        fs::write(&file, "name: replayed\ncount: 3\n").unwrap();

        let chain = ProviderChain::new().with_source(&ConfigSource::File(file.clone()));
        assert_eq!(chain.sources(), &[ConfigSource::File(file.clone())]);

        let config: TestConfig = chain.extract().unwrap();
        assert_eq!(config.name.as_deref(), Some("replayed"));
        assert_eq!(config.count, Some(3));
    }

    #[test]
    fn with_source_env_records_env_layer() {
        let chain = ProviderChain::new().with_source(&ConfigSource::Env("REPLAY_ENV_".to_owned()));
        assert_eq!(
            chain.sources(),
            &[ConfigSource::Env("REPLAY_ENV_".to_owned())]
        );
    }

    #[test]
    fn with_source_defaults_is_identity() {
        // Defaults carries no reconstructable value, so replaying it is the
        // identity: no layer merged, nothing recorded.
        let chain = ProviderChain::new().with_source(&ConfigSource::Defaults);
        assert!(
            chain.sources().is_empty(),
            "Defaults must replay as the identity"
        );
    }

    #[test]
    fn with_source_agrees_with_with_file_pointwise() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("agree.yaml");
        fs::write(&file, "name: agree\ncount: 5\n").unwrap();

        let via_builder = ProviderChain::new().with_file(&file);
        let via_source = ProviderChain::new().with_source(&ConfigSource::File(file.clone()));
        assert_eq!(via_builder.sources(), via_source.sources());

        let a: TestConfig = via_builder.extract().unwrap();
        let b: TestConfig = via_source.extract().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn with_source_agrees_with_with_env_pointwise() {
        let prefix = "SHIKUMI_REPLAY_AGREE_";
        let via_builder = ProviderChain::new().with_env(prefix);
        let via_source = ProviderChain::new().with_source(&ConfigSource::Env(prefix.to_owned()));
        assert_eq!(via_builder.sources(), via_source.sources());
    }

    #[test]
    fn with_source_exhaustive_over_every_kind() {
        use crate::ConfigSourceKind;
        for kind in ConfigSourceKind::ALL.iter().copied() {
            let (source, expected): (ConfigSource, Vec<ConfigSource>) = match kind {
                ConfigSourceKind::Defaults => (ConfigSource::Defaults, vec![]),
                ConfigSourceKind::Env => {
                    let s = ConfigSource::Env("K_".to_owned());
                    (s.clone(), vec![s])
                }
                ConfigSourceKind::File => {
                    let s = ConfigSource::File("/tmp/k.toml".into());
                    (s.clone(), vec![s])
                }
            };
            let chain = ProviderChain::new().with_source(&source);
            assert_eq!(
                chain.sources(),
                expected.as_slice(),
                "with_source replay for {kind:?} must match the matching builder's record"
            );
        }
    }

    #[test]
    fn replay_round_trips_recorded_chain() {
        // The reload-fidelity property at the ProviderChain level: read a
        // recorded chain back through with_source and the rebuilt chain
        // reproduces both the merge order and the extracted value.
        let dir = TempDir::new().unwrap();
        let lo = dir.path().join("lo.yaml");
        let hi = dir.path().join("hi.toml");
        fs::write(&lo, "name: low\ncount: 1\n").unwrap();
        fs::write(&hi, "count = 2\n").unwrap();

        let original = ProviderChain::new().with_file(&lo).with_file(&hi);
        let recipe = original.sources().to_vec();
        let original_value: TestConfig = original.extract().unwrap();

        let rebuilt = recipe
            .iter()
            .fold(ProviderChain::new(), ProviderChain::with_source);
        assert_eq!(rebuilt.sources(), recipe.as_slice());

        let rebuilt_value: TestConfig = rebuilt.extract().unwrap();
        assert_eq!(rebuilt_value, original_value);
        assert_eq!(rebuilt_value.name.as_deref(), Some("low"));
        assert_eq!(rebuilt_value.count, Some(2));
    }

    // ---- merge_serialized_defaults_layer (Defaults-tier merge substrate) ----
    //
    // The two-step "extend the figment with `Serialized::defaults(<layer>)`
    // + push `ConfigSource::Defaults` onto the recorded chain" body every
    // Defaults-class `ProviderChain` builder previously open-coded at its
    // own site. Before this lift both `ProviderChain::with_defaults` (the
    // developer-defaults builder) and `ProviderChain::with_discovered`
    // (the discovered-tier builder, recorded as Defaults-class per that
    // doc) wrote the same three-line body inline — two places any future
    // refinement of the Defaults-tier merge protocol would have to be
    // applied in lockstep. These tests pin the fusion at ONE substrate
    // site so a future hand-edit that reintroduces an open-coded body at
    // either caller fires from this file.
    //
    // The peer of the other same-file "shared decision" substrate
    // helpers (`provider_metadata_for`, `provider_data_from_shikumi_load`,
    // `text_source_provider_data`, `figment_default_dict`,
    // `json_value_to_figment`): each closed one leg of the provider or
    // provider-surface drift class at one site; this closes the leg on
    // the chain-builder-side Defaults-tier merge.

    /// The helper MUST record exactly ONE `ConfigSource::Defaults` entry
    /// per call — the load-bearing provenance every Defaults-class
    /// caller pushes. A future regression that pushed the wrong variant,
    /// or dropped the push, or duplicated it, would silently change the
    /// recorded chain shape callers reconstruct through
    /// [`ProviderChain::with_source`] on reload.
    #[test]
    fn merge_serialized_defaults_layer_pushes_config_source_defaults() {
        let defaults = TestConfig::default();
        let chain = merge_serialized_defaults_layer(ProviderChain::new(), &defaults);
        assert_eq!(
            chain.sources(),
            &[ConfigSource::Defaults],
            "helper must record exactly one ConfigSource::Defaults per call"
        );
    }

    /// The merged layer MUST be observable through the extracted
    /// [`TestConfig`] — a caller that hands the helper a serializable
    /// value expects that value's fields to appear in the extract, per
    /// figment's `Serialized::defaults` semantics. A future regression
    /// that dropped the merge half (recorded the source push but did
    /// not merge) would silently lose every default the caller supplied.
    #[test]
    fn merge_serialized_defaults_layer_merges_the_serializable_layer() {
        let defaults = TestConfig {
            name: Some("layered".into()),
            count: Some(11),
        };
        let chain = merge_serialized_defaults_layer(ProviderChain::new(), &defaults);
        let extracted: TestConfig = chain.extract().unwrap();
        assert_eq!(extracted.name.as_deref(), Some("layered"));
        assert_eq!(extracted.count, Some(11));
    }

    /// Drift-closure against the LIVE [`ProviderChain::with_defaults`]
    /// caller: building a chain via `with_defaults(&d)` records the same
    /// sources AND extracts the same [`TestConfig`] as building it via
    /// `merge_serialized_defaults_layer(chain, &d)` directly. A future
    /// hand-edit that reintroduces an open-coded `Serialized::defaults`
    /// merge + `sources.push(Defaults)` body at
    /// [`ProviderChain::with_defaults`] fires this test with the
    /// observable-behavior mismatch, not a downstream extract failure.
    #[test]
    fn with_defaults_routes_through_merge_serialized_defaults_layer() {
        let defaults = TestConfig {
            name: Some("developer".into()),
            count: Some(3),
        };

        let via_builder = ProviderChain::new().with_defaults(&defaults);
        let via_helper = merge_serialized_defaults_layer(ProviderChain::new(), &defaults);

        assert_eq!(
            via_builder.sources(),
            via_helper.sources(),
            "with_defaults must record the same ConfigSource chain as the substrate helper"
        );

        let a: TestConfig = via_builder.extract().unwrap();
        let b: TestConfig = via_helper.extract().unwrap();
        assert_eq!(
            a, b,
            "with_defaults must extract the same TestConfig as the substrate helper"
        );
    }

    /// Peer drift-closure against the LIVE
    /// [`ProviderChain::with_discovered`] caller: building a chain via
    /// `with_discovered(dict)` records the same sources AND extracts the
    /// same [`TestConfig`] as building it via
    /// `merge_serialized_defaults_layer(chain, &dict)` directly. Pinned
    /// alongside the peer `with_defaults` drift-closure so the substrate
    /// site owns BOTH callers' routing pins — a future hand-edit that
    /// reintroduces an open-coded body at EITHER caller fires from this
    /// file, not from that caller's own test module.
    #[test]
    fn with_discovered_routes_through_merge_serialized_defaults_layer() {
        let mut dict = Dict::new();
        dict.insert("name".to_owned(), Value::from("discovered"));
        dict.insert("count".to_owned(), Value::from(19i64));

        let via_builder = ProviderChain::new().with_discovered(dict.clone());
        let via_helper = merge_serialized_defaults_layer(ProviderChain::new(), &dict);

        assert_eq!(
            via_builder.sources(),
            via_helper.sources(),
            "with_discovered must record the same ConfigSource chain as the substrate helper"
        );

        let a: TestConfig = via_builder.extract().unwrap();
        let b: TestConfig = via_helper.extract().unwrap();
        assert_eq!(
            a, b,
            "with_discovered must extract the same TestConfig as the substrate helper"
        );
    }

    /// Cross-caller drift-closure: `with_defaults(&d)` and
    /// `with_discovered(dict)` — the two Defaults-class builders on
    /// [`ProviderChain`] — MUST record byte-identical
    /// `[ConfigSource::Defaults]` sources when handed shape-equivalent
    /// inputs. A future hand-edit that changed the pushed variant at
    /// either caller (a hypothetical eager switch to a not-yet-added
    /// `Discovered` variant at the `with_discovered` site alone) fires
    /// this cross-caller pin. The observable contract the current
    /// helper name declares — both callers push `Defaults` — is thus
    /// pinned end-to-end, not just at the helper site.
    #[test]
    fn with_defaults_and_with_discovered_record_identical_defaults_class_sources() {
        let defaults = TestConfig::default();
        let dict = Dict::new();

        let via_defaults = ProviderChain::new().with_defaults(&defaults);
        let via_discovered = ProviderChain::new().with_discovered(dict);

        assert_eq!(
            via_defaults.sources(),
            via_discovered.sources(),
            "with_defaults and with_discovered must record the same Defaults-class provenance"
        );
        assert_eq!(
            via_defaults.sources(),
            &[ConfigSource::Defaults],
            "both callers must record exactly one ConfigSource::Defaults entry"
        );
    }

    /// The helper MUST preserve the caller-supplied chain's prior
    /// [`ConfigSource`] entries — a caller mid-fluent-chain
    /// (`.with_defaults(&d)` following `.with_env("APP_")`) expects the
    /// helper to APPEND its Defaults entry, not to reset the chain. A
    /// future regression that overwrote `chain.sources` (a `let sources
    /// = vec![...]` shadowing typo, an accidental
    /// `std::mem::take(&mut chain.sources)` before push) would fire this
    /// pin.
    #[test]
    fn merge_serialized_defaults_layer_appends_to_existing_sources() {
        let prefix = "SHIKUMI_MSDL_APPEND_";
        let chain = ProviderChain::new().with_env(prefix);
        let extended = merge_serialized_defaults_layer(chain, &TestConfig::default());
        assert_eq!(
            extended.sources(),
            &[ConfigSource::Env(prefix.to_owned()), ConfigSource::Defaults,],
            "helper must append its Defaults entry after the caller's prior entries \
             — a reset or prepend would break the fluent-chain composition contract"
        );
    }

    // ---- provider_data_from_value (shikumi-built-provider Value -> Map projection) ----

    #[test]
    fn provider_data_from_value_wraps_dict_under_profile_default() {
        // Value::Dict input lifts to the single-entry { Profile::Default => dict }
        // shape — the exact wrapper figment::Provider::data requires, with the
        // contained dict preserved verbatim (no key rewriting, no allocation
        // beyond the outer Map).
        let mut inner = Dict::new();
        inner.insert("k".to_owned(), Value::from("v"));
        let input = Value::Dict(figment::value::Tag::Default, inner.clone());

        let map = provider_data_from_value(input, Format::Lisp).expect("Dict input must succeed");
        assert_eq!(map.len(), 1, "exactly one profile entry");
        let dict = map
            .get(&Profile::Default)
            .expect("Profile::Default present");
        assert_eq!(dict, &inner, "inner dict preserved verbatim");
    }

    #[test]
    fn provider_data_from_value_errors_on_non_dict_value() {
        // Any non-Dict Value variant must yield a FigmentError. The
        // structural-shape check is the helper's contract; the precise
        // wording is pinned in the adjacent `_uses_format_message` test.
        let cases = [
            Value::Empty(figment::value::Tag::Default, figment::value::Empty::None),
            Value::Array(figment::value::Tag::Default, vec![Value::from(1i64)]),
            Value::from("not a dict"),
            Value::from(42i64),
            Value::from(true),
        ];
        for input in cases {
            let kind = format!("{input:?}");
            let err = provider_data_from_value(input, Format::Lisp)
                .expect_err(&format!("non-Dict input must error: {kind}"));
            // FigmentError surfaces the message via Display.
            assert!(
                !err.to_string().is_empty(),
                "non-Dict error must carry a message ({kind})"
            );
        }
    }

    #[test]
    fn provider_data_from_value_uses_format_dict_required_message() {
        // The helper's error path delegates the format-specific wording
        // to Format::dict_required_message — pin pointwise that the
        // emitted message starts with the format-typed prefix and
        // appends `"; got <Value:?>"` for the concrete shape.
        let probe = Value::Empty(figment::value::Tag::Default, figment::value::Empty::None);
        for format in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            let err = provider_data_from_value(probe.clone(), format)
                .expect_err("non-Dict input must error so the format-aware message is observable");
            let msg = err.to_string();
            let prefix = format.dict_required_message();
            assert!(
                msg.starts_with(prefix),
                "{format:?}: message must start with `{prefix}`, got `{msg}`",
            );
            assert!(
                msg.contains("; got "),
                "{format:?}: message must append `; got <Value>` segment, got `{msg}`",
            );
        }
    }

    #[test]
    fn provider_data_from_value_preserves_nested_dict_structure() {
        // The helper does not flatten or rewrite nested Dict values —
        // the inner shape figment passed in lands in the Map verbatim.
        // Pins that the helper is a pure projection: dict in, same dict
        // out under Profile::Default.
        let mut nested = Dict::new();
        nested.insert("inner_a".to_owned(), Value::from(1i64));
        nested.insert("inner_b".to_owned(), Value::from("two"));
        let mut top = Dict::new();
        top.insert(
            "nested".to_owned(),
            Value::Dict(figment::value::Tag::Default, nested.clone()),
        );
        let input = Value::Dict(figment::value::Tag::Default, top.clone());

        let map =
            provider_data_from_value(input, Format::Nix).expect("nested Dict input must succeed");
        let stored = map
            .get(&Profile::Default)
            .expect("Profile::Default present");
        assert_eq!(stored, &top, "nested dict structure preserved verbatim");
        // And the round-trip through the inner Dict survives.
        let Value::Dict(_, recovered_inner) =
            stored.get("nested").expect("nested key present").clone()
        else {
            panic!("nested entry must remain Value::Dict");
        };
        assert_eq!(recovered_inner, nested);
    }

    // ---- provider_data_from_shikumi_load (load-result -> Map projection) ----
    //
    // These tests pin the end-to-end fusion helper that
    // `LispProvider::data` / `NixProvider::data` route through: the
    // `.map_err(|e| FigmentError::from(e.to_string()))` glue that used to
    // live at the head of each `data()` body now happens at one site here,
    // and the format-typed dict-required wording is delegated to
    // `provider_data_from_value` (already pinned above). A future shikumi-
    // built provider inherits both projections by routing its `data()`
    // through this single helper — that's the compounding lift.

    #[test]
    fn provider_data_from_shikumi_load_forwards_ok_dict_verbatim() {
        // Ok(Dict) → same `{ Profile::Default => dict }` shape the
        // downstream `provider_data_from_value` helper emits — the
        // fusion helper must be a pointwise-equal composition on the
        // success path.
        let mut inner = Dict::new();
        inner.insert("k".to_owned(), Value::from("v"));
        let value = Value::Dict(figment::value::Tag::Default, inner.clone());

        let via_fusion = provider_data_from_shikumi_load(Ok(value.clone()), Format::Lisp)
            .expect("Ok(Dict) must succeed via the fusion helper");
        let via_direct = provider_data_from_value(value, Format::Lisp)
            .expect("Ok(Dict) must succeed via the direct helper");
        assert_eq!(
            via_fusion, via_direct,
            "fusion path must equal direct path on Ok(Dict)",
        );
        assert_eq!(via_fusion.len(), 1, "exactly one profile entry");
        assert_eq!(
            via_fusion.get(&Profile::Default),
            Some(&inner),
            "inner dict preserved verbatim under Profile::Default",
        );
    }

    #[test]
    fn provider_data_from_shikumi_load_projects_err_via_display() {
        // Err(ShikumiError) is projected through the same string surface
        // every consumer of a shikumi Provider observes today —
        // `FigmentError::from(err.to_string())` — so the fusion helper
        // must emit exactly what the open-coded `.map_err` would.
        let err = ShikumiError::Parse("boom".into());
        let expected = err.to_string();

        let fig_err =
            provider_data_from_shikumi_load(Err(err), Format::Lisp).expect_err("Err must project");
        assert_eq!(
            fig_err.to_string(),
            expected,
            "the projected FigmentError must Display exactly like the source ShikumiError",
        );
    }

    #[test]
    fn provider_data_from_shikumi_load_delegates_non_dict_wording_to_format_helper() {
        // Ok(non-Dict) → the downstream helper's format-typed
        // dict-required wording must reach the operator verbatim. Pins
        // that the fusion helper does not re-word or wrap the message
        // — the shape must start with `Format::X.dict_required_message()`
        // and append `"; got <Value:?>"` for every format.
        let probe = Value::Empty(figment::value::Tag::Default, figment::value::Empty::None);
        for format in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            let err = provider_data_from_shikumi_load(Ok(probe.clone()), format)
                .expect_err("Ok(non-Dict) must error via the fusion helper");
            let msg = err.to_string();
            let prefix = format.dict_required_message();
            assert!(
                msg.starts_with(prefix),
                "{format:?}: fusion-helper message must start with `{prefix}`, got `{msg}`",
            );
            assert!(
                msg.contains("; got "),
                "{format:?}: fusion-helper message must append `; got <Value>` tail, got `{msg}`",
            );
        }
    }

    #[test]
    // The open-coded arm this test re-runs is exactly the arm we lifted
    // away, and reconstructing it is what pins the fusion helper to
    // pointwise-equal semantics; silence the closure-Err-size pedantic
    // hit at the one call site — same rationale as the production
    // helper's `#[allow]` above, and confined to test scope.
    #[allow(clippy::result_large_err)]
    fn provider_data_from_shikumi_load_agrees_with_open_coded_composition() {
        // Pointwise-equal composition pin: for every load result the
        // fusion helper's output must equal what the two open-coded
        // steps produced verbatim — `.map_err(...)` then
        // `provider_data_from_value`. This is the drift-closure the
        // lift exists for. `ShikumiError` intentionally does not derive
        // `Clone`, so each case is a thunk that mints a fresh
        // `Result<Value, ShikumiError>` per invocation instead of a
        // cloneable value.
        #[allow(clippy::type_complexity)]
        let cases: [(&str, fn() -> Result<Value, ShikumiError>); 3] = [
            ("Ok(Dict)", || {
                let mut inner = Dict::new();
                inner.insert("x".to_owned(), Value::from(1i64));
                Ok(Value::Dict(figment::value::Tag::Default, inner))
            }),
            ("Err(ShikumiError)", || {
                Err(ShikumiError::Parse("nix eval failed".into()))
            }),
            ("Ok(non-Dict)", || {
                Ok(Value::Array(
                    figment::value::Tag::Default,
                    vec![Value::from(2i64)],
                ))
            }),
        ];

        for (label, mk) in cases {
            for format in [Format::Lisp, Format::Nix] {
                let via_fusion = provider_data_from_shikumi_load(mk(), format);
                let via_open_coded = mk()
                    .map_err(|e| FigmentError::from(e.to_string()))
                    .and_then(|value| provider_data_from_value(value, format));

                match (via_fusion, via_open_coded) {
                    (Ok(a), Ok(b)) => assert_eq!(
                        a, b,
                        "{label}/{format:?}: fusion Ok must equal open-coded Ok",
                    ),
                    (Err(a), Err(b)) => assert_eq!(
                        a.to_string(),
                        b.to_string(),
                        "{label}/{format:?}: fusion Err message must equal open-coded Err message",
                    ),
                    (a, b) => panic!(
                        "{label}/{format:?}: fusion and open-coded disagree on Ok/Err arm: \
                         fusion={a:?}, open_coded={b:?}",
                    ),
                }
            }
        }
    }

    // ---- provider_metadata_for (Format × Path -> Metadata construction) ----
    //
    // The `metadata()` half of the shikumi-built provider surface. Before
    // this lift `LispProvider::metadata` and `NixProvider::metadata` each
    // open-coded `Metadata::named(Format::X.metadata_name(&self.path))`
    // — two places a future refinement of the metadata-name shape would
    // have to be applied in lockstep. The helper closes that drift class;
    // these tests pin the closure at the fusion site so the two call
    // sites remain a pointwise-equal composition and the round-trip
    // through `Format::strip_metadata_name` / `parse_metadata_tag` is
    // preserved by construction.

    #[test]
    fn provider_metadata_for_agrees_with_open_coded_composition_pointwise() {
        // For every shikumi-built format the helper's output must
        // exactly equal what the two open-coded steps produced:
        // `Metadata::named(format.metadata_name(&path))`. The equality
        // is on `Metadata::name` (the only field either construction
        // sets), and it must hold across the full path shape that
        // reaches a real provider — absolute-with-extension,
        // relative-no-parent, and empty are the three concrete corners
        // `LispProvider::file` / `NixProvider::file` will accept.
        let paths: [&Path; 3] = [
            Path::new("/etc/app/app.lisp"),
            Path::new("relative.nix"),
            Path::new(""),
        ];
        for format in [Format::Lisp, Format::Nix] {
            for path in paths {
                let via_helper = provider_metadata_for(format, path);
                let via_open_coded = Metadata::named(format.metadata_name(path));
                assert_eq!(
                    via_helper.name, via_open_coded.name,
                    "{format:?}/{path:?}: helper Metadata::name must equal open-coded name",
                );
            }
        }
    }

    #[test]
    fn provider_metadata_for_round_trips_through_strip_metadata_name() {
        // The whole point of the metadata name is that it inverts:
        // `Format::strip_metadata_name` must recover `(format, path_display)`
        // from the helper's output for every shikumi-built format.
        // Pinning it at the fusion site guarantees that a future
        // shikumi-built provider routing its `metadata()` through the
        // helper inherits the round-trip contract by construction.
        let path = Path::new("/var/lib/app/conf.lisp");
        for format in [Format::Lisp, Format::Nix] {
            let md = provider_metadata_for(format, path);
            let (recovered_format, rest) = Format::strip_metadata_name(md.name.as_ref())
                .unwrap_or_else(|| panic!("{format:?}: metadata name must round-trip"));
            assert_eq!(
                recovered_format, format,
                "{format:?}: strip_metadata_name must recover the constructor format",
            );
            assert_eq!(
                rest,
                path.display().to_string(),
                "{format:?}: strip_metadata_name must recover the constructor path display",
            );
        }
    }

    #[test]
    fn provider_metadata_for_round_trips_through_parse_metadata_tag() {
        // Idiom-peer of the `strip_metadata_name` round-trip test:
        // `Format::parse_metadata_tag` is the typed-envelope inverse of
        // `Format::metadata_name`, and the helper's output must
        // invert through it to a `FormatMetadataTag` whose `(format, path)`
        // pair equals the constructor `(format, &path)` pair — the same
        // load-bearing contract, expressed on the typed surface.
        let path = Path::new("/opt/app/conf.nix");
        for format in [Format::Lisp, Format::Nix] {
            let md = provider_metadata_for(format, path);
            let tag = Format::parse_metadata_tag(md.name.as_ref())
                .unwrap_or_else(|| panic!("{format:?}: metadata name must parse to a typed tag"));
            assert_eq!(
                tag.format, format,
                "{format:?}: parse_metadata_tag must recover the constructor format",
            );
            assert_eq!(
                tag.path,
                Path::new(&path.display().to_string()),
                "{format:?}: parse_metadata_tag must recover the constructor path",
            );
        }
    }

    // ---- json_value_to_figment (serde_json::Value -> figment::Value) ----
    //
    // The JSON → figment homomorphism NixProvider's `load()` body routes
    // through — and the substrate a future JSON-transport provider
    // (ConfigPlane broadcast, HTTP config endpoint, Kubernetes ConfigMap
    // JSON-valued key) inherits. These tests pin two invariants at the
    // fusion site:
    //
    //   1. The number arm preserves precision across the whole JSON
    //      integer range, including the (i64::MAX, u64::MAX] slice that
    //      the pre-lift version lost to lossy `f64` — a real behavior
    //      sharpening, not just a refactor.
    //   2. The compound-arm recursion is a pointwise homomorphism: the
    //      figment tree agrees with the JSON tree shape-for-shape, so a
    //      caller reasoning about JSON structure keeps that reasoning at
    //      the figment layer.

    #[test]
    fn json_value_to_figment_maps_null_to_empty_none() {
        // `Empty::None` is figment's canonical `Option::None` counterpart;
        // there is no dedicated JSON-null inhabitant, so the mapping must
        // land here for a downstream deserializer that models nullable
        // fields as `Option<T>` to see the absence.
        let out = json_value_to_figment(&serde_json::Value::Null);
        assert!(
            matches!(out, Value::Empty(_, figment::value::Empty::None)),
            "Null must map to Value::Empty(_, Empty::None), got {out:?}",
        );
    }

    #[test]
    fn json_value_to_figment_bool_round_trips_both_polarities() {
        // Both polarities land in `Value::Bool` verbatim — pins that the
        // helper does not swap sign or emit a numeric coercion.
        for b in [true, false] {
            let out = json_value_to_figment(&serde_json::Value::Bool(b));
            let Value::Bool(_, got) = out else {
                panic!("Bool({b}) must map to Value::Bool, got {out:?}");
            };
            assert_eq!(got, b, "Bool polarity must survive");
        }
    }

    #[test]
    fn json_value_to_figment_string_round_trips_verbatim() {
        // The string arm clones the underlying `String`; the mapped
        // Value must Display exactly the same bytes.
        for probe in ["", "ascii", "unicode-仕組み", "with\nnewline"] {
            let out = json_value_to_figment(&serde_json::Value::String(probe.to_owned()));
            let Value::String(_, got) = out else {
                panic!("String({probe:?}) must map to Value::String, got {out:?}");
            };
            assert_eq!(got, probe, "String bytes must survive");
        }
    }

    #[test]
    fn json_value_to_figment_preserves_negative_i64() {
        // Pins the negative-integer branch: `as_i64()` covers the whole
        // signed range including `i64::MIN`. Regression guard against a
        // future refactor that reorders the number arm and lands
        // `as_u64()` first (which would return `None` for negatives and
        // silently fall through to lossy `f64`).
        for probe in [-1i64, -42, i64::MIN, i64::MIN + 1] {
            let json = serde_json::Value::Number(serde_json::Number::from(probe));
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            let via_i128 = got.to_i128().unwrap_or_else(|| {
                panic!("Num({probe}) must round-trip through to_i128, got {got:?}")
            });
            assert_eq!(via_i128, i128::from(probe), "signed integer must survive");
        }
    }

    #[test]
    fn json_value_to_figment_preserves_u64_above_i64_max() {
        // The load-bearing sharpening: JSON integers in
        // (i64::MAX, u64::MAX] must land in `Value::Num(_, Num::U64(_))`
        // (or a numerically-equivalent unsigned width) — the pre-lift
        // cascade tried `as_i64()` then jumped straight to `as_f64()`,
        // silently losing precision for any value above 2^53 and
        // rounding away exact bits above 2^63 entirely. `u64::MAX` is
        // the sharpest probe: an `f64` round-trip loses ~10 low bits.
        //
        // Pin both `i64::MAX + 1` (the boundary the pre-lift version
        // began losing) and `u64::MAX` (the loudest failure case).
        let probes: [u64; 3] = [(i64::MAX as u64) + 1, (i64::MAX as u64) + 42, u64::MAX];
        for probe in probes {
            let json = serde_json::Value::Number(serde_json::Number::from(probe));
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            // `Num::to_u128` returns `Some` **only for the unsigned Num
            // variants** (per figment's own docs: `Num::U8..=U128`, `USize`
            // — a signed or float variant returns `None`). This is
            // therefore the sharpest available structural probe that the
            // JSON `u64` landed in a genuinely unsigned Num rather than
            // being funneled through the lossy `f64` arm the pre-lift
            // cascade fell to.
            let via_u128 = got.to_u128().unwrap_or_else(|| {
                panic!(
                    "Num({probe}) must land in an unsigned Num variant \
                     (to_u128 must be Some), got {got:?} — regression: \
                     pre-lift `as_i64() -> as_f64()` cascade lost u64 \
                     values above i64::MAX to lossy f64",
                )
            });
            assert_eq!(
                via_u128,
                u128::from(probe),
                "u64 above i64::MAX must survive without precision loss",
            );
        }
    }

    #[test]
    fn json_value_to_figment_preserves_f64_when_json_is_float() {
        // The float arm is the true last-resort: it must fire only when
        // the JSON number is a genuine float (has a fractional part or
        // is a scientific-notation literal), and it must preserve the
        // exact f64 bits.
        for probe in [0.0f64, -2.5, 1e20, f64::MIN_POSITIVE, f64::EPSILON] {
            let json = serde_json::Value::Number(
                serde_json::Number::from_f64(probe)
                    .unwrap_or_else(|| panic!("probe {probe} must round-trip through serde_json")),
            );
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            let as_f64 = got
                .to_f64()
                .unwrap_or_else(|| panic!("Num({probe}) must be a float variant, got {got:?}"));
            assert!(
                (as_f64 - probe).abs() <= f64::EPSILON.max(probe.abs() * f64::EPSILON),
                "float must survive f64 arm: sent {probe}, got {as_f64}",
            );
        }
    }

    #[test]
    fn json_value_to_figment_object_dispatches_to_dict() {
        // The object arm must produce a `Value::Dict` whose keys are the
        // JSON keys verbatim (no case-folding, no reordering into an
        // implicit iteration order) — the same expectation the shared
        // `provider_data_from_value` helper further downstream imposes.
        let json: serde_json::Value =
            serde_json::from_str(r#"{"alpha":1,"beta":true,"gamma":null,"delta":"d"}"#).unwrap();
        let out = json_value_to_figment(&json);
        let Value::Dict(_, d) = out else {
            panic!("Object must map to Value::Dict, got {out:?}");
        };
        for k in ["alpha", "beta", "gamma", "delta"] {
            assert!(d.contains_key(k), "key `{k}` must survive verbatim");
        }
        assert!(matches!(d.get("alpha"), Some(Value::Num(_, _))));
        assert!(matches!(d.get("beta"), Some(Value::Bool(_, true))));
        assert!(matches!(
            d.get("gamma"),
            Some(Value::Empty(_, figment::value::Empty::None)),
        ));
        assert!(matches!(d.get("delta"), Some(Value::String(_, _))));
    }

    #[test]
    fn json_value_to_figment_array_dispatches_to_array_pointwise() {
        // The array arm must map pointwise: `arr[i]` at the JSON layer
        // becomes the mapped-value at the same index in the figment
        // `Value::Array`. Empty array must survive as an empty
        // `Value::Array`, not degrade to `Value::Empty`.
        let empty = json_value_to_figment(&serde_json::Value::Array(vec![]));
        let Value::Array(_, items) = empty else {
            panic!("empty Array must map to Value::Array, got {empty:?}");
        };
        assert!(items.is_empty(), "empty array must survive as empty Array");

        let mixed: serde_json::Value =
            serde_json::from_str(r#"[1,"two",true,null,[3,4]]"#).unwrap();
        let out = json_value_to_figment(&mixed);
        let Value::Array(_, items) = out else {
            panic!("mixed Array must map to Value::Array, got {out:?}");
        };
        assert_eq!(items.len(), 5, "arity must survive");
        assert!(matches!(items[0], Value::Num(_, _)));
        assert!(matches!(items[1], Value::String(_, _)));
        assert!(matches!(items[2], Value::Bool(_, true)));
        assert!(matches!(
            items[3],
            Value::Empty(_, figment::value::Empty::None)
        ));
        assert!(matches!(items[4], Value::Array(_, _)));
    }

    #[test]
    fn json_value_to_figment_is_pointwise_homomorphic_on_nested_shapes() {
        // The recursion must be a homomorphism: for a deeply-nested
        // JSON tree the mapped figment tree agrees leaf-by-leaf. Pins
        // that the helper does not flatten, reorder, drop, or synthesize
        // structure — a `dict[a][b][c] = 42` in JSON reaches the
        // deserializer as the exact same key-path with the same integer
        // value. This is the load-bearing property NixProvider's tests
        // implicitly relied on but did not name.
        let json: serde_json::Value = serde_json::from_str(
            r#"{
              "outer": {
                "middle": {
                  "inner": {
                    "n_i64": -7,
                    "n_u64_over_i64_max": 18446744073709551610,
                    "n_float": 3.5,
                    "list": [1, 2, [3, 4]],
                    "empty_list": [],
                    "empty_obj": {},
                    "null_leaf": null
                  }
                }
              }
            }"#,
        )
        .unwrap();
        let out = json_value_to_figment(&json);
        let Value::Dict(_, top) = out else {
            panic!("top must be Dict");
        };
        let Value::Dict(_, mid) = top.get("outer").expect("outer").clone() else {
            panic!("outer must be Dict");
        };
        let Value::Dict(_, inner_wrap) = mid.get("middle").expect("middle").clone() else {
            panic!("middle must be Dict");
        };
        let Value::Dict(_, inner) = inner_wrap.get("inner").expect("inner").clone() else {
            panic!("inner must be Dict");
        };

        // Negative integer preserved as signed.
        let Value::Num(_, signed_leaf) = inner.get("n_i64").expect("n_i64").clone() else {
            panic!("n_i64 must be Num");
        };
        assert_eq!(signed_leaf.to_i128(), Some(-7));

        // u64 above i64::MAX preserved losslessly.
        let Value::Num(_, unsigned_leaf) = inner
            .get("n_u64_over_i64_max")
            .expect("n_u64_over_i64_max")
            .clone()
        else {
            panic!("n_u64_over_i64_max must be Num");
        };
        // `to_u128` returns `Some` only for the unsigned Num variants,
        // so this asserts BOTH the value survived losslessly AND the
        // number arm reached the u64 leg of the cascade (not the lossy
        // f64 arm the pre-lift cascade fell to for u64 > i64::MAX).
        assert_eq!(
            unsigned_leaf.to_u128(),
            Some(18_446_744_073_709_551_610u128),
        );

        // Float survives the f64 arm.
        let Value::Num(_, n_float) = inner.get("n_float").expect("n_float").clone() else {
            panic!("n_float must be Num");
        };
        assert!(matches!(n_float, figment::value::Num::F64(_)));

        // Nested list preserves inner arity.
        let Value::Array(_, list) = inner.get("list").expect("list").clone() else {
            panic!("list must be Array");
        };
        assert_eq!(list.len(), 3);
        let Value::Array(_, inner_pair) = list[2].clone() else {
            panic!("list[2] must be nested Array");
        };
        assert_eq!(inner_pair.len(), 2);

        // Empty compound values survive as their compound counterparts.
        assert!(matches!(
            inner.get("empty_list"),
            Some(Value::Array(_, v)) if v.is_empty(),
        ));
        assert!(matches!(
            inner.get("empty_obj"),
            Some(Value::Dict(_, d)) if d.is_empty(),
        ));

        // Null leaf lands in `Empty::None`.
        assert!(matches!(
            inner.get("null_leaf"),
            Some(Value::Empty(_, figment::value::Empty::None)),
        ));
    }

    // ---- read_source_or_parse_err (text-source file read → String) ----
    //
    // The `read_to_string` half of the text-source shikumi-built provider
    // surface. Before this lift `LispProvider::load` and
    // `BlueProvider::load` each open-coded the identical
    // `fs::read_to_string(path).map_err(|e| ShikumiError::Parse(format!(
    // "reading {}: {e}", path.display())))?` step at the head of their
    // body — two places a future refinement of the read-side diagnostic
    // would have to be applied in lockstep. The helper closes that drift
    // class; these tests pin the closure at the fusion site so a caller
    // sensing shape changes still trips them.

    #[test]
    fn read_source_or_parse_err_round_trips_valid_ascii() {
        // Happy path: contents come back byte-for-byte, no error path
        // reached. Uses the same tempfile substrate the peer provider
        // tests already use so the fixture surface is uniform.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.txt");
        fs::write(&path, "hello world\n").unwrap();
        let src = read_source_or_parse_err(&path).expect("valid ascii must round-trip");
        assert_eq!(src, "hello world\n");
    }

    #[test]
    fn read_source_or_parse_err_round_trips_utf8_multibyte_content() {
        // A config source can legitimately contain multi-byte UTF-8
        // (Japanese identifiers in shikumi's own dogfood configs, e.g.
        // `仕組み`; kebab-quoted strings; emoji in comments). The helper
        // must preserve those bytes verbatim so downstream parsers see
        // the same source the file holds — anything less would silently
        // corrupt the input under a wrapper whose job is I/O only.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("multibyte.txt");
        let content = "shikumi: 仕組み — 🎯 «configuration» é û ñ\n";
        fs::write(&path, content).unwrap();
        let src = read_source_or_parse_err(&path).expect("valid utf-8 must round-trip");
        assert_eq!(src, content);
    }

    #[test]
    fn read_source_or_parse_err_returns_empty_string_for_empty_file() {
        // An empty file is a valid text source (a downstream parser will
        // reject it with its own front-end-named message — see
        // `blue_provider::tests::an_empty_source_is_a_typed_error_not_a_panic`);
        // the read-side helper must not conflate empty-file-on-disk with
        // an I/O error and must return an empty `String`, not `Err`.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty.txt");
        fs::write(&path, b"").unwrap();
        let src = read_source_or_parse_err(&path).expect("empty file must not error");
        assert!(
            src.is_empty(),
            "empty file must round-trip to empty String; got {src:?}"
        );
    }

    #[test]
    fn read_source_or_parse_err_errors_as_parse_variant_on_missing_file() {
        // Missing file must surface as `ShikumiError::Parse`, not as any
        // other variant — that's the shape the two callers' `load()`
        // bodies previously produced and downstream `data()` impls
        // project through `provider_data_from_shikumi_load`. A future
        // helper edit that widened this to `ShikumiError::Io` would flip
        // the projected `FigmentError` prose across every text-source
        // provider at once; the assertion pins the variant.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.txt");
        let err = read_source_or_parse_err(&path).expect_err("missing file must not read");
        assert!(
            matches!(err, ShikumiError::Parse(_)),
            "missing-file error must be Parse variant; got {err:?}",
        );
    }

    #[test]
    fn read_source_or_parse_err_names_the_path_in_the_missing_file_error() {
        // The operator-facing diagnostic must contain BOTH the
        // `"reading "` read-side tag AND the path's `Display` form —
        // the two load-bearing halves of the pre-lift wording. Together
        // they let an operator running several shikumi providers tell
        // (a) which side the failure came from (`reading` vs a parse-
        // side `blue:` / `lisp:` prefix) and (b) which file was
        // involved, without opening the source. Testing both halves
        // side-by-side pins that neither can silently vanish under a
        // future edit. The `contains` (rather than `starts_with`) check
        // on the read-side tag is deliberate: the outer
        // `ShikumiError::Parse` `Display` impl prepends its own
        // `"config parse error: "` framing (see `error.rs`), and that
        // framing is the shape every `ShikumiError::Parse` consumer
        // has always seen — the invariant is that `"reading {path}: "`
        // appears verbatim inside the projected message, not that it
        // begins the whole string.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nope").join("also-nope.txt");
        let err = read_source_or_parse_err(&path).expect_err("missing file must not read");
        let msg = err.to_string();
        let read_side_tag = format!("reading {}: ", path.display());
        assert!(
            msg.contains(&read_side_tag),
            "error must contain the read-side `{read_side_tag}` tag verbatim; got `{msg}`",
        );
    }

    #[test]
    fn read_source_or_parse_err_missing_file_message_matches_pre_lift_composition_verbatim() {
        // The strongest drift-closure: reproduce the pre-lift open-coded
        // composition here, compare its error string to the helper's on
        // the same missing path, and require byte equality. If the two
        // ever disagree the drift is between the fusion site and its
        // extraction, which is exactly what this lift exists to prevent.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("still-missing.txt");
        let helper_err =
            read_source_or_parse_err(&path).expect_err("missing file must not read (helper leg)");
        let open_coded_err: ShikumiError = std::fs::read_to_string(&path)
            .map(|_| ())
            .map_err(|e| ShikumiError::Parse(format!("reading {}: {e}", path.display())))
            .expect_err("missing file must not read (open-coded leg)");
        assert_eq!(
            helper_err.to_string(),
            open_coded_err.to_string(),
            "helper must produce the same operator-facing wording as the pre-lift composition",
        );
    }

    // ---- load_text_source (fused read + map cascade) ----

    #[test]
    fn load_text_source_reads_then_maps_the_source() {
        // Happy path: the helper reads the file, hands the source string
        // to the mapper, and returns whatever Value the mapper produced.
        // Pins the two-step order (read first, map second) at the fusion
        // site, with the source string reaching the mapper verbatim.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "hello world").unwrap();

        fn map_identity(src: &str) -> Result<Value, ShikumiError> {
            Ok(Value::from(src.to_owned()))
        }

        let v = load_text_source(&path, map_identity).expect("read + map must succeed");
        let Value::String(_, s) = v else {
            panic!("expected String, got {v:?}")
        };
        assert_eq!(s, "hello world", "mapper must see the source verbatim");
    }

    #[test]
    fn load_text_source_read_error_is_helper_wording_verbatim() {
        // Missing-path leg: the helper must NOT swallow, prefix, or
        // rewrite the read-side ShikumiError::Parse the read-step
        // helper emits — pins the routing at the fusion site.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope").join("still-nope.txt");

        fn map_never_called(_: &str) -> Result<Value, ShikumiError> {
            panic!("mapper must not run when the read step fails")
        }
        let fused_err = load_text_source(&path, map_never_called)
            .expect_err("missing file must not read → mapper unreachable");

        let read_side_err = read_source_or_parse_err(&path)
            .expect_err("read-step helper must fail on the same missing path");
        assert_eq!(
            fused_err.to_string(),
            read_side_err.to_string(),
            "fused helper must forward the read-step wording verbatim",
        );
    }

    #[test]
    fn load_text_source_map_error_is_forwarded_unchanged() {
        // Map-step failure: the helper must not prefix, wrap, or
        // synthesize the mapper's error — the fusion is transparent on
        // the map leg. Pins the map-side routing at the fusion site.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "unused").unwrap();

        fn map_always_errors(_: &str) -> Result<Value, ShikumiError> {
            Err(ShikumiError::Parse("mapper-side wording".into()))
        }
        let fused_err = load_text_source(&path, map_always_errors)
            .expect_err("mapper failure must surface as the fused error");

        let ShikumiError::Parse(msg) = &fused_err else {
            panic!("expected Parse, got {fused_err:?}")
        };
        assert_eq!(
            msg, "mapper-side wording",
            "mapper's wording must reach the caller unchanged",
        );
    }

    #[test]
    fn load_text_source_read_error_short_circuits_the_mapper() {
        // Structural: on a read-step failure the mapper must NOT run —
        // otherwise a future map-side helper that opens a peer file or
        // logs on entry could execute on a doomed path. The mapper
        // panics so any reachability fires as a test failure with a
        // named message, not a silent no-op.
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.txt");

        fn map_panicking(_: &str) -> Result<Value, ShikumiError> {
            panic!("mapper reached on a read-failed path — short-circuit invariant broken")
        }

        let _ = load_text_source(&missing, map_panicking)
            .expect_err("missing file must short-circuit before the mapper");
    }

    #[test]
    fn load_text_source_matches_pre_lift_open_coded_composition_verbatim() {
        // The strongest drift-closure: reproduce the pre-lift open-coded
        // composition here (the exact two-line body BlueProvider::load
        // and LispProvider::load previously carried) and require the
        // fused helper produce a byte-equal error string on the same
        // missing path. If the two ever disagree, the drift is between
        // the fusion site and its extraction — which is exactly what
        // this lift exists to prevent.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.cfg");

        fn map_unreachable(_: &str) -> Result<Value, ShikumiError> {
            unreachable!("read step guaranteed to fail on this path")
        }

        let fused_err = load_text_source(&path, map_unreachable)
            .expect_err("fused helper must fail on missing path");
        let open_coded_err = {
            match read_source_or_parse_err(&path) {
                Ok(src) => {
                    map_unreachable(&src).expect_err("open-coded leg must fail on missing path")
                }
                Err(e) => e,
            }
        };
        assert_eq!(
            fused_err.to_string(),
            open_coded_err.to_string(),
            "fused helper must produce the same wording as the pre-lift open-coded composition",
        );
    }

    #[test]
    fn load_text_source_hands_multibyte_source_to_the_mapper_intact() {
        // Unicode-preservation invariant: the read step already
        // preserves multi-byte content (pinned separately for
        // read_source_or_parse_err); the fusion must not silently
        // truncate, re-encode, or normalize on its way to the mapper.
        // Pins that the source string reaching the mapper is
        // byte-identical to what was written.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multibyte.txt");
        let payload = "仕組み ✓ hot-reload 🔧";
        fs::write(&path, payload).unwrap();

        fn map_identity(src: &str) -> Result<Value, ShikumiError> {
            Ok(Value::from(src.to_owned()))
        }

        let v = load_text_source(&path, map_identity).expect("multi-byte read + map must succeed");
        let Value::String(_, s) = v else {
            panic!("expected String, got {v:?}")
        };
        assert_eq!(
            s, payload,
            "multi-byte source must reach the mapper byte-identical",
        );
    }

    #[test]
    fn load_text_source_hands_empty_source_to_the_mapper() {
        // Empty-file corner: the read step returns `Ok(String::new())`
        // for a zero-byte file (pinned separately for
        // read_source_or_parse_err — the downstream parser owns the
        // empty-source diagnostic). Pins that the fusion forwards the
        // empty string to the mapper rather than short-circuiting on
        // its own, so the parse-side "empty config" diagnostic each
        // provider defines (blue: "empty config — expected one
        // top-level form"; lisp: "empty config — expected one
        // top-level (defX …) form") remains reachable through the
        // fusion.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.txt");
        fs::write(&path, "").unwrap();

        fn map_captures_len(src: &str) -> Result<Value, ShikumiError> {
            Ok(Value::from(i64::try_from(src.len()).unwrap()))
        }

        let v = load_text_source(&path, map_captures_len)
            .expect("empty file must reach the mapper as an empty string");
        assert_eq!(
            v.to_i128(),
            Some(0),
            "mapper must see the source's true length (0), not a short-circuited None",
        );
    }

    // ---- text_source_provider_data (fused read + map + project cascade) ----
    //
    // The `data()` half of the text-source shikumi-built provider surface.
    // Before this lift `BlueProvider::data` and `LispProvider::data` each
    // open-coded the identical `provider_data_from_shikumi_load(
    // load_text_source(&self.path, load_from_str), Format::X)` composition
    // at the tail of their `Provider::data` body — two places a future
    // refinement of the read+map+project protocol would have to be applied
    // in lockstep. The helper closes that drift class; these tests pin the
    // closure at the fusion site so a caller sensing shape changes still
    // trips them.

    #[test]
    // The open-coded arms these tests re-run are exactly the arms we
    // lifted away, and reconstructing them is what pins the fusion helper
    // to pointwise-equal semantics; silence the closure-Err-size pedantic
    // hit at the fused call site under the same rationale as the
    // production helper's `#[allow]` above, and confined to test scope.
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_reads_then_maps_then_projects() {
        // Happy path: the fused helper reads the file, hands the source
        // string to the mapper, projects the mapper's Dict output through
        // `provider_data_from_shikumi_load`, and returns the
        // `{ Profile::Default => dict }` shape figment's `Provider::data`
        // requires — with the mapper's dict preserved verbatim under
        // `Profile::Default`.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "unused-by-mapper").unwrap();

        fn map_to_dict(_: &str) -> Result<Value, ShikumiError> {
            let mut d = Dict::new();
            d.insert("k".to_owned(), Value::from("v"));
            Ok(Value::Dict(figment::value::Tag::Default, d))
        }

        let map = text_source_provider_data(&path, Format::Lisp, map_to_dict)
            .expect("read + map + project must succeed");
        assert_eq!(map.len(), 1, "exactly one profile entry");
        let dict = map
            .get(&Profile::Default)
            .expect("Profile::Default present");
        assert_eq!(dict.get("k"), Some(&Value::from("v")));
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_read_error_is_string_projected_via_display() {
        // Read-step failure leg: the read error surfaces through the
        // shared `ShikumiError` → `FigmentError` string projection every
        // consumer of a shikumi Provider observes today. Pins that the
        // fused helper does NOT swallow, prefix, or wrap the read-side
        // wording on its way through the projection.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope").join("still-nope.txt");

        fn map_unreachable(_: &str) -> Result<Value, ShikumiError> {
            unreachable!("read step guaranteed to fail on this path")
        }

        let fig_err = text_source_provider_data(&path, Format::Lisp, map_unreachable)
            .expect_err("missing file must not read → mapper unreachable");
        let expected = read_source_or_parse_err(&path)
            .expect_err("read-step helper must fail on the same missing path")
            .to_string();
        assert_eq!(
            fig_err.to_string(),
            expected,
            "fused helper must forward the read-step wording verbatim through the projection",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_map_error_is_string_projected_verbatim() {
        // Map-step failure leg: whatever ShikumiError the mapper produces
        // must reach the projected FigmentError verbatim. The fusion
        // does not prefix, wrap, or synthesize a message on top of it —
        // pins the map-side transparency through the projection.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "unused").unwrap();

        fn map_always_errors(_: &str) -> Result<Value, ShikumiError> {
            Err(ShikumiError::Parse("mapper-side wording".into()))
        }

        let fig_err = text_source_provider_data(&path, Format::Lisp, map_always_errors)
            .expect_err("mapper failure must project through the fused helper");
        let expected = ShikumiError::Parse("mapper-side wording".into()).to_string();
        assert_eq!(
            fig_err.to_string(),
            expected,
            "mapper's wording must reach the caller as the projected FigmentError verbatim",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_non_dict_value_uses_format_dict_required_wording() {
        // Structural-shape leg: on a mapper that returns a non-Dict
        // Value, the projected FigmentError message must start with
        // `Format::X.dict_required_message()` and carry the `; got …`
        // concrete-Value tail — the exact contract
        // `provider_data_from_value` already declares and the fused
        // helper routes through. Pins that the format-typed wording
        // reaches the operator identically on every format the two
        // text-source providers cover today, plus the sibling formats.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "unused").unwrap();

        fn map_to_array(_: &str) -> Result<Value, ShikumiError> {
            Ok(Value::Array(
                figment::value::Tag::Default,
                vec![Value::from(1i64)],
            ))
        }

        for format in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            let fig_err = text_source_provider_data(&path, format, map_to_array)
                .expect_err("non-Dict mapper output must error via the fused helper");
            let msg = fig_err.to_string();
            let prefix = format.dict_required_message();
            assert!(
                msg.starts_with(prefix),
                "{format:?}: fused-helper message must start with `{prefix}`, got `{msg}`",
            );
            assert!(
                msg.contains("; got "),
                "{format:?}: fused-helper message must append `; got <Value>` tail, got `{msg}`",
            );
        }
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_read_error_short_circuits_the_mapper() {
        // Structural: on a read-step failure the mapper must NOT run —
        // otherwise a future map-side helper that opens a peer file or
        // logs on entry could execute on a doomed path. The mapper
        // panics so any reachability fires as a test failure with a
        // named message, not a silent no-op.
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.txt");

        fn map_panicking(_: &str) -> Result<Value, ShikumiError> {
            panic!(
                "mapper reached on a read-failed path — short-circuit invariant broken through \
                 the fused helper"
            )
        }

        let _ = text_source_provider_data(&missing, Format::Lisp, map_panicking)
            .expect_err("missing file must short-circuit before the mapper");
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_data_matches_pre_lift_open_coded_composition_verbatim() {
        // The strongest drift-closure: reproduce the pre-lift open-coded
        // three-step composition here — `provider_data_from_shikumi_load(
        // load_text_source(&path, map), format)` — and require the fused
        // helper produce a byte-equal FigmentError string on the same
        // missing path, for every format the two text-source providers
        // cover. If the two ever disagree, the drift is between the
        // fusion site and its extraction — which is exactly what this
        // lift exists to prevent.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.cfg");

        fn map_unreachable(_: &str) -> Result<Value, ShikumiError> {
            unreachable!("read step guaranteed to fail on this path")
        }

        for format in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            let fused_err = text_source_provider_data(&path, format, map_unreachable)
                .expect_err("fused helper must fail on missing path");
            let open_coded_err =
                provider_data_from_shikumi_load(load_text_source(&path, map_unreachable), format)
                    .expect_err("open-coded composition must fail on missing path");
            assert_eq!(
                fused_err.to_string(),
                open_coded_err.to_string(),
                "{format:?}: fused helper must produce the same wording as the pre-lift open-coded \
                 composition",
            );
        }
    }

    // ---- Cross-caller drift-closure ----
    //
    // These pins are the whole point of lifting a duplicated shape into
    // shared substrate: prove BOTH text-source providers now produce
    // *identical* I/O-error wording on the same missing path. A future
    // divergence between the two provider `load` bodies — a hand edit
    // that reintroduces the open-coded step at one site — would flip
    // one caller's message and the assertion would fire. Gated on the
    // `blue` feature so both `BlueProvider` and its implied `lisp`-
    // feature peer `LispProvider` are in scope at once.

    #[cfg(feature = "blue")]
    #[test]
    fn blue_and_lisp_providers_produce_identical_missing_file_wording() {
        use crate::blue_provider::BlueProvider;
        use crate::lisp_provider::LispProvider;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("missing.cfg");

        let blue_err =
            BlueProvider::load(&path).expect_err("BlueProvider::load must fail on missing path");
        let lisp_err =
            LispProvider::load(&path).expect_err("LispProvider::load must fail on missing path");

        assert_eq!(
            blue_err.to_string(),
            lisp_err.to_string(),
            "BlueProvider and LispProvider must share the shared read-side wording",
        );

        let expected = read_source_or_parse_err(&path)
            .expect_err("helper must fail on the same missing path")
            .to_string();
        assert_eq!(
            blue_err.to_string(),
            expected,
            "the shared wording must be the helper's wording verbatim (Blue leg)",
        );
        assert_eq!(
            lisp_err.to_string(),
            expected,
            "the shared wording must be the helper's wording verbatim (Lisp leg)",
        );
    }

    // ---- text_source_provider_impl! (impl Provider block emitter) ----
    //
    // The last remaining open-coded duplication on the text-source provider
    // surface after the four prior lifts closed the per-method bodies. The
    // macro emits the whole `impl Provider for $Ty` block from
    // `(Ty, Format, mapper)`; these tests pin the emission on a synthetic
    // caller so the macro's contract is verified independently of the
    // production `BlueProvider` / `LispProvider` callers that inherit from
    // it.

    /// Synthetic text-source provider used only to exercise the emitted
    /// impl. Carries a `path: PathBuf` field (the convention every
    /// text-source provider follows and the macro's contract requires).
    struct MacroProbeProvider {
        path: std::path::PathBuf,
    }

    /// Free-function mapper the macro requires — a `fn` pointer, not a
    /// closure — that yields a dict for the happy path.
    fn macro_probe_mapper(src: &str) -> Result<Value, ShikumiError> {
        let mut d = Dict::new();
        d.insert("src_len".to_owned(), Value::from(src.len() as i64));
        Ok(Value::Dict(figment::value::Tag::Default, d))
    }

    text_source_provider_impl!(MacroProbeProvider, Format::Lisp, macro_probe_mapper);

    #[test]
    fn text_source_provider_impl_emits_metadata_that_matches_the_substrate_helper() {
        // Pins that the macro's `metadata()` body routes through
        // `provider_metadata_for(format, &self.path)` verbatim — the same
        // bytes the substrate helper produces from the same `(format, path)`
        // pair, so the metadata-name round-trip through
        // `Format::strip_metadata_name` / `Format::parse_metadata_tag` is
        // preserved by construction.
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/macro-probe.cfg");
        let provider = MacroProbeProvider { path: path.clone() };
        let via_macro = provider.metadata();
        let via_helper = provider_metadata_for(Format::Lisp, &path);
        assert_eq!(
            via_macro.name.as_ref(),
            via_helper.name.as_ref(),
            "macro-emitted metadata name must equal substrate-helper metadata name",
        );
        // And the round-trip via the resolver-side primitive surfaces
        // the same (Format, path) pair the macro was parameterized with.
        let (recovered_format, rest) = Format::strip_metadata_name(&via_macro.name)
            .expect("macro-emitted metadata name must round-trip");
        assert_eq!(recovered_format, Format::Lisp);
        assert_eq!(rest, path.display().to_string());
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_impl_emits_data_that_matches_the_substrate_helper() {
        // Pins that the macro's `data()` body routes through
        // `text_source_provider_data(&self.path, format, mapper)` verbatim
        // — the same `Map<Profile, Dict>` the substrate helper produces
        // from the same `(path, format, mapper)` triple.
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "hello, world").unwrap();

        let provider = MacroProbeProvider { path: path.clone() };
        let via_macro = provider.data().expect("macro-emitted data() must succeed");
        let via_helper = text_source_provider_data(&path, Format::Lisp, macro_probe_mapper)
            .expect("substrate-helper data() must succeed");
        assert_eq!(
            via_macro, via_helper,
            "macro-emitted data() must equal substrate-helper data() on the happy path",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_impl_emits_data_error_matching_the_substrate_helper() {
        // Read-step failure leg: the macro must forward whatever the
        // substrate helper emits on a missing path, byte-for-byte, so a
        // future refinement of the error path lands at one substrate
        // site and every macro-emitted `Provider::data` inherits it by
        // construction.
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.cfg");

        let provider = MacroProbeProvider { path: path.clone() };
        let via_macro = provider
            .data()
            .expect_err("macro-emitted data() must fail on missing path");
        let via_helper = text_source_provider_data(&path, Format::Lisp, macro_probe_mapper)
            .expect_err("substrate-helper data() must fail on missing path");
        assert_eq!(
            via_macro.to_string(),
            via_helper.to_string(),
            "macro-emitted data() error must equal substrate-helper error verbatim",
        );
    }

    #[test]
    fn text_source_provider_impl_metadata_agrees_across_all_shikumi_built_formats() {
        // Every shikumi-built `Format` variant must route through the
        // macro to the same metadata name the substrate helper produces.
        // The macro is parameterized on `$format:expr`, so no format is
        // baked in — this pin proves the parameter reaches the emitted
        // body unchanged. A per-format macro invocation would be circular
        // (the macro under test would participate in its own oracle), so
        // the invariant is asserted through the substrate helper both
        // callers ride: if the macro's `metadata()` body were ever
        // hand-inlined to a different `Format` than its parameter, the
        // byte-for-byte cross-format pin below on the substrate helper
        // would catch the drift on the two real callers.
        //
        // Restricted to `FormatProvenance::ShikumiBuilt` formats:
        // `strip_metadata_name` filters to that subset, because the
        // figment-builtin formats (`Yaml`, `Toml`) attribute via
        // `figment::Source::File` rather than the shikumi
        // `"<format>: <path>"` name shape, and would return `None` here.
        for format in crate::discovery::FormatProvenance::ShikumiBuilt.formats() {
            let path = std::path::PathBuf::from("/tmp/format-scan.cfg");
            let helper_name = provider_metadata_for(*format, &path).name;
            let (recovered_format, rest) = Format::strip_metadata_name(&helper_name)
                .expect("substrate helper's metadata name must round-trip");
            assert_eq!(recovered_format, *format);
            assert_eq!(rest, path.display().to_string());
        }
    }

    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_impl_matches_both_real_callers_on_metadata_and_data() {
        // The macro's real load-bearing test is the two production
        // callers it emits code for. This pin proves both of them go
        // through the macro-emitted body and land the same wording on
        // the substrate helper the macro routes to — the drift-closure
        // that would fire if a hand edit re-introduced the open-coded
        // impl block at either site.
        use crate::blue_provider::BlueProvider;
        use crate::lisp_provider::LispProvider;
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.cfg");

        for (label, format, provider_err) in [
            (
                "blue",
                Format::Blue,
                BlueProvider::file(&missing).data().expect_err("blue"),
            ),
            (
                "lisp",
                Format::Lisp,
                LispProvider::file(&missing).data().expect_err("lisp"),
            ),
        ] {
            let helper_err = text_source_provider_data(
                &missing,
                format,
                // The specific mapper doesn't matter on the read-step
                // failure leg — the read fails before any mapper runs
                // (the short-circuit invariant `text_source_provider_data_
                // read_error_short_circuits_the_mapper` pins above).
                crate::lisp_provider::load_from_str,
            )
            .expect_err("substrate helper must fail on the same missing path");
            assert_eq!(
                provider_err.to_string(),
                helper_err.to_string(),
                "{label}: macro-emitted data() error must equal the substrate helper's on the \
                 same missing path — drift here means the impl block was hand-inlined at the \
                 caller and no longer routes through `text_source_provider_impl!`",
            );
        }
    }

    #[test]
    fn text_source_provider_impl_emits_static_load_that_matches_the_substrate_helper() {
        // Pins that the macro's emitted `pub fn load(&Path)` static
        // one-shot routes through `load_text_source(path, mapper)`
        // verbatim — the same `Value` the substrate helper produces
        // from the same `(path, mapper)` pair on the happy path. This is
        // the load-bearing pin for the second leg of the macro's
        // emission: after this lift, the whole ergonomic
        // `Ty::load(&Path) -> Result<Value, ShikumiError>` static
        // method every text-source provider previously open-coded is
        // gone from every caller and lives at one substrate site.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "hello, world").unwrap();

        let via_macro = MacroProbeProvider::load(&path).expect("macro-emitted load() must succeed");
        let via_helper = load_text_source(&path, macro_probe_mapper)
            .expect("substrate-helper load_text_source() must succeed");
        assert_eq!(
            via_macro, via_helper,
            "macro-emitted static load() must equal substrate-helper load_text_source() on the \
             happy path — drift here means the emitted body no longer routes through \
             `load_text_source`",
        );
    }

    #[test]
    fn text_source_provider_impl_emits_static_load_error_matching_the_substrate_helper() {
        // Read-step failure leg on the emitted static `load(&Path)`: the
        // macro must forward whatever the substrate helper emits on a
        // missing path, byte-for-byte, so a future refinement of the
        // read-side wording (path canonicalization, `io::ErrorKind`
        // triage, structured provenance) lands at one substrate site and
        // every macro-emitted `Ty::load(&Path)` inherits it by
        // construction — the same drift-closure the `Provider::data`
        // error-leg pin above establishes on the other half of the
        // macro's emission.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.cfg");

        let via_macro = MacroProbeProvider::load(&path)
            .expect_err("macro-emitted load() must fail on missing path");
        let via_helper = load_text_source(&path, macro_probe_mapper)
            .expect_err("substrate-helper load_text_source() must fail on missing path");
        assert_eq!(
            via_macro.to_string(),
            via_helper.to_string(),
            "macro-emitted static load() error must equal substrate-helper error verbatim",
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_impl_static_load_matches_both_real_callers() {
        // The load-bearing drift-closure for the static-load leg on the
        // two production callers. If a hand edit at either
        // `blue_provider` or `lisp_provider` re-introduced an open-coded
        // `pub fn load(path: &Path) -> Result<Value, ShikumiError> {
        // crate::provider::load_text_source(path, load_from_str) }`
        // static method on the type, this pin would still hold on the
        // happy path — it exercises the byte-shape of the emitted body,
        // not the source-code shape of the caller — so its load-bearing
        // aim is on the error path, where the shared substrate helper's
        // wording is defined once and the drift-closure fires if a hand
        // edit swaps it for a bespoke string. Both callers ride the same
        // macro, so both errors match the substrate helper's byte-for-
        // byte, and the two callers agree with each other by transitivity.
        use crate::blue_provider::BlueProvider;
        use crate::lisp_provider::LispProvider;

        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.cfg");

        let blue_err =
            BlueProvider::load(&missing).expect_err("BlueProvider::load must fail on missing path");
        let lisp_err =
            LispProvider::load(&missing).expect_err("LispProvider::load must fail on missing path");
        let helper_err = load_text_source(&missing, crate::lisp_provider::load_from_str)
            .expect_err("substrate-helper load_text_source() must fail on the same missing path");

        assert_eq!(
            blue_err.to_string(),
            helper_err.to_string(),
            "BlueProvider::load error must equal load_text_source() error verbatim — drift here \
             means BlueProvider re-introduced an open-coded static load and no longer routes \
             through `text_source_provider_impl!`",
        );
        assert_eq!(
            lisp_err.to_string(),
            helper_err.to_string(),
            "LispProvider::load error must equal load_text_source() error verbatim — drift here \
             means LispProvider re-introduced an open-coded static load and no longer routes \
             through `text_source_provider_impl!`",
        );
        assert_eq!(
            blue_err.to_string(),
            lisp_err.to_string(),
            "BlueProvider and LispProvider must agree on static-load wording by transitivity",
        );
    }

    // ---- path_provider_impl! (general impl Provider block emitter) ----
    //
    // The general peer of `text_source_provider_impl!`: emits the whole
    // `impl Provider for $Ty` block from `(Ty, Format, |this| load_expr)`,
    // where `load_expr` produces a `Result<Value, ShikumiError>` from a
    // `&$Ty` bound as `this`. Fits any provider whose load side is NOT a
    // text-source mapper — today `NixProvider` is the caller, and its
    // whole `impl Provider` block reduces to one macro invocation.
    //
    // The pins below prove the macro's contract on a synthetic caller
    // (so the invariants are checked independently of the production
    // `NixProvider` caller that inherits from it) plus one drift-closure
    // against the real `NixProvider` caller, matching the pattern the
    // `text_source_provider_impl!` pins above already follow.

    /// Synthetic non-text-source provider used only to exercise the
    /// emitted impl. Carries a `path: PathBuf` field (the convention
    /// every shikumi-built provider follows and the macro's contract
    /// requires) plus a boxed load closure so each test can drive the
    /// load side without any filesystem or subprocess dependency.
    struct PathMacroProbeProvider {
        path: std::path::PathBuf,
        loader: fn(&PathMacroProbeProvider) -> Result<Value, ShikumiError>,
    }

    fn path_macro_probe_load(this: &PathMacroProbeProvider) -> Result<Value, ShikumiError> {
        (this.loader)(this)
    }

    path_provider_impl!(PathMacroProbeProvider, Format::Nix, |this| {
        path_macro_probe_load(this)
    });

    fn path_macro_probe_ok_dict(_this: &PathMacroProbeProvider) -> Result<Value, ShikumiError> {
        let mut d = Dict::new();
        d.insert("k".to_owned(), Value::from("v"));
        Ok(Value::Dict(figment::value::Tag::Default, d))
    }

    fn path_macro_probe_ok_array(_this: &PathMacroProbeProvider) -> Result<Value, ShikumiError> {
        Ok(Value::Array(
            figment::value::Tag::Default,
            vec![Value::from("only-element")],
        ))
    }

    fn path_macro_probe_err(_this: &PathMacroProbeProvider) -> Result<Value, ShikumiError> {
        Err(ShikumiError::Parse(
            "path_provider_impl! test: forced load-step failure".to_owned(),
        ))
    }

    #[test]
    fn path_provider_impl_emits_metadata_that_matches_the_substrate_helper() {
        // The macro's `metadata()` body must route through
        // `provider_metadata_for(format, &self.path)` verbatim — the same
        // bytes the substrate helper produces from the same `(format, path)`
        // pair, so the metadata-name round-trip through
        // `Format::strip_metadata_name` / `Format::parse_metadata_tag` is
        // preserved by construction.
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/path-macro-probe.cfg");
        let provider = PathMacroProbeProvider {
            path: path.clone(),
            loader: path_macro_probe_ok_dict,
        };
        let via_macro = provider.metadata();
        let via_helper = provider_metadata_for(Format::Nix, &path);
        assert_eq!(
            via_macro.name.as_ref(),
            via_helper.name.as_ref(),
            "path_provider_impl! metadata name must equal substrate-helper metadata name",
        );
        let (recovered_format, rest) = Format::strip_metadata_name(&via_macro.name)
            .expect("macro-emitted metadata name must round-trip");
        assert_eq!(recovered_format, Format::Nix);
        assert_eq!(rest, path.display().to_string());
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn path_provider_impl_emits_data_that_matches_the_substrate_helper() {
        // Happy path: the macro's `data()` body must route through
        // `provider_data_from_shikumi_load(load_expr, format)` verbatim —
        // the same `Map<Profile, Dict>` the substrate helper produces
        // from the same `(load_result, format)` pair.
        use figment::Provider;

        let provider = PathMacroProbeProvider {
            path: std::path::PathBuf::from("/tmp/path-macro-probe.cfg"),
            loader: path_macro_probe_ok_dict,
        };
        let via_macro = provider.data().expect("macro-emitted data() must succeed");
        let via_helper =
            provider_data_from_shikumi_load(path_macro_probe_ok_dict(&provider), Format::Nix)
                .expect("substrate-helper data() must succeed");
        assert_eq!(
            via_macro, via_helper,
            "path_provider_impl! data() must equal substrate-helper data() on the happy path",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn path_provider_impl_emits_data_error_matching_the_substrate_helper() {
        // Load-step failure leg: the macro must forward whatever the
        // substrate helper emits on a `ShikumiError` load result,
        // byte-for-byte, so a future refinement of the error path lands
        // at one substrate site and every macro-emitted `Provider::data`
        // inherits it by construction.
        use figment::Provider;

        let provider = PathMacroProbeProvider {
            path: std::path::PathBuf::from("/tmp/path-macro-probe.cfg"),
            loader: path_macro_probe_err,
        };
        let via_macro = provider
            .data()
            .expect_err("macro-emitted data() must fail on a load-step error");
        let via_helper =
            provider_data_from_shikumi_load(path_macro_probe_err(&provider), Format::Nix)
                .expect_err("substrate-helper data() must fail on the same load-step error");
        assert_eq!(
            via_macro.to_string(),
            via_helper.to_string(),
            "path_provider_impl! data() error must equal substrate-helper error verbatim",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn path_provider_impl_data_non_dict_value_uses_format_dict_required_wording() {
        // Non-Dict load result leg: the macro must forward whatever the
        // substrate helper's `provider_data_from_value` arm emits, so the
        // format-typed dict-required wording reaches the operator through
        // this macro identically to how it reaches them through the
        // text-source macro or a direct substrate-helper call.
        use figment::Provider;

        let provider = PathMacroProbeProvider {
            path: std::path::PathBuf::from("/tmp/path-macro-probe.cfg"),
            loader: path_macro_probe_ok_array,
        };
        let via_macro = provider
            .data()
            .expect_err("macro-emitted data() must fail on a non-Dict load result");
        let via_helper =
            provider_data_from_shikumi_load(path_macro_probe_ok_array(&provider), Format::Nix)
                .expect_err("substrate-helper data() must fail on the same non-Dict result");
        assert_eq!(
            via_macro.to_string(),
            via_helper.to_string(),
            "path_provider_impl! data() non-Dict error must equal substrate-helper wording",
        );
        assert!(
            via_macro
                .to_string()
                .starts_with(Format::Nix.dict_required_message()),
            "non-Dict error must start with `Format::Nix.dict_required_message()`",
        );
    }

    #[test]
    fn path_provider_impl_metadata_agrees_across_all_shikumi_built_formats() {
        // Every shikumi-built `Format` variant must route through the
        // macro to the same metadata name the substrate helper produces.
        // The macro is parameterized on `$format:expr`, so no format is
        // baked in — this pin proves the parameter reaches the emitted
        // body unchanged. A per-format macro invocation would be circular
        // (the macro under test would participate in its own oracle), so
        // the invariant is asserted through the substrate helper the
        // real callers ride: if the macro's `metadata()` body were ever
        // hand-inlined to a different `Format` than its parameter, the
        // byte-for-byte cross-format pin below on the substrate helper
        // would catch the drift on the real caller (`NixProvider`).
        //
        // Restricted to `FormatProvenance::ShikumiBuilt` formats — see
        // the sibling `text_source_provider_impl_metadata_agrees_across_
        // all_shikumi_built_formats` pin for the rationale.
        for format in crate::discovery::FormatProvenance::ShikumiBuilt.formats() {
            let path = std::path::PathBuf::from("/tmp/path-macro-format-scan.cfg");
            let helper_name = provider_metadata_for(*format, &path).name;
            let (recovered_format, rest) = Format::strip_metadata_name(&helper_name)
                .expect("substrate helper's metadata name must round-trip");
            assert_eq!(recovered_format, *format);
            assert_eq!(rest, path.display().to_string());
        }
    }

    #[test]
    fn path_provider_impl_matches_nix_provider_on_metadata() {
        // The macro's real load-bearing test is the production
        // `NixProvider` caller it emits code for. Metadata leg: the
        // macro-emitted `metadata()` on `NixProvider` must equal
        // `provider_metadata_for(Format::Nix, &path)` verbatim — the
        // drift-closure that would fire if a hand edit re-introduced the
        // open-coded impl block at the caller and quietly changed the
        // metadata-name shape away from what `Format::metadata_name`
        // declares.
        use crate::nix_provider::NixProvider;
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/path-macro-nix-caller.nix");
        let provider = NixProvider::file(&path);
        let via_caller = provider.metadata();
        let via_helper = provider_metadata_for(Format::Nix, &path);
        assert_eq!(
            via_caller.name.as_ref(),
            via_helper.name.as_ref(),
            "NixProvider metadata name must equal substrate-helper metadata name — drift here \
             means the impl block was hand-inlined at the caller and no longer routes through \
             `path_provider_impl!`",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn path_provider_impl_matches_nix_provider_on_data_error() {
        // The macro's real load-bearing test is the production
        // `NixProvider` caller it emits code for. Data leg: the
        // macro-emitted `data()` on `NixProvider` must forward whatever
        // `provider_data_from_shikumi_load(NixProvider::load(...), Format::Nix)`
        // emits, byte-for-byte, so a future refinement of the
        // load→project cascade lands at the substrate site and the
        // caller inherits it by construction.
        //
        // Uses a nonexistent binary so `NixProvider::load` produces a
        // deterministic `ShikumiError::Parse` without a real `nix`
        // process on `$PATH` — the same load path the sibling
        // `nix_provider::tests::missing_nix_binary_errors_gracefully`
        // pin already exercises directly.
        use crate::nix_provider::NixProvider;
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.nix");
        let provider =
            NixProvider::file(&path).with_binary("/nonexistent/nix-binary-that-does-not-exist");
        let via_caller = provider
            .data()
            .expect_err("NixProvider::data() must fail on a nonexistent nix binary");
        let via_helper = provider_data_from_shikumi_load(provider.load(), Format::Nix)
            .expect_err("substrate-helper data() must fail on the same load error");
        assert_eq!(
            via_caller.to_string(),
            via_helper.to_string(),
            "NixProvider data() error must equal substrate-helper's on the same load failure \
             — drift here means the impl block was hand-inlined at the caller and no longer \
             routes through `path_provider_impl!`",
        );
    }

    // ---- text_source_provider! (fused struct + impl emitter) ----
    //
    // The fused-invocation peer of `text_source_provider_struct!` +
    // `text_source_provider_impl!`: emits BOTH halves of the text-source
    // shikumi-built provider surface — the `#[derive(Debug, Clone)] pub
    // struct $Ty { path: PathBuf }` + `pub fn file(path)` ctor half AND
    // the `impl Provider for $Ty` block + the ergonomic `pub fn
    // load(&Path)` static one-shot half — from ONE macro invocation.
    //
    // The pins below prove the fused macro composes to the exact same
    // emission as the two half-side macros on a synthetic caller (so the
    // fusion's contract is verified independently of the production
    // `LispProvider` / `BlueProvider` callers that inherit from it) plus
    // drift-closures against the real callers so a hand-edit
    // re-introducing the two-macro shape at either site would trip a
    // pin.

    /// Synthetic fused-emitter probe. Byte-for-byte equivalent to what
    /// the pre-lift two-invocation shape would emit for the same
    /// `(Ty, Format, mapper)` triple — so every pin below can compare
    /// this fixture against either of the two half-side macros' probes
    /// (`MacroProbeProvider` above, `PathMacroProbeProvider` below —
    /// the ones the sibling `text_source_provider_impl!` /
    /// `path_provider_impl!` pins already exercise).
    text_source_provider! {
        /// A fixture doc — forwarded verbatim through the fused macro's
        /// `$(#[$attr])*` slot into the emitted struct's front matter,
        /// same as the sibling `text_source_provider_struct!` does at
        /// its head. If the fused macro ever drops the forwarding, the
        /// pin `text_source_provider_forwards_struct_attributes` below
        /// fires (this doc would otherwise become unreachable from
        /// `MacroFusedProbeProvider`'s rustdoc).
        MacroFusedProbeProvider,
        format = Format::Lisp,
        mapper = macro_probe_mapper,
    }

    #[test]
    fn text_source_provider_emits_ctor_matching_the_half_side_struct_macro() {
        // Pins that the fused macro's struct-half emission yields the
        // same private-in-module `path: PathBuf` carrier + `pub` `#[must_use]`
        // `file(impl Into<PathBuf>)` ctor the sibling `text_source_
        // provider_struct!` emits — the two-invocation shape's struct
        // half. If the fused macro ever stops forwarding to the sibling
        // (e.g. hand-inlines a different derive set or drops the ctor's
        // `Into<PathBuf>` bound), the constructor call below either
        // stops compiling or produces a mismatched carrier shape.
        let path = std::path::PathBuf::from("/tmp/fused-probe.cfg");
        let fused = MacroFusedProbeProvider::file(&path);
        let half_side = MacroProbeProvider { path: path.clone() };
        // The two carriers must expose the SAME `path: PathBuf` field
        // through the SAME `Debug` shape — the pre-lift equality every
        // text-source provider satisfied on carrier construction.
        assert_eq!(
            format!("{fused:?}").contains(&path.display().to_string()),
            true,
            "fused macro's ctor must produce a Debug-visible `path` field",
        );
        // The half-side probe is not `Debug`, but both carriers ride
        // the same emitted `pub fn file(impl Into<PathBuf>)` shape by
        // construction — the assertion above pins that the fused
        // macro's ctor produces a carrier whose `path` reads back the
        // caller-supplied `PathBuf` verbatim.
        let _ = half_side; // participation only
    }

    #[test]
    fn text_source_provider_emits_metadata_matching_the_half_side_impl_macro() {
        // Pins that the fused macro's impl-half emission routes through
        // `provider_metadata_for(format, &self.path)` verbatim — the
        // same substrate helper the sibling `text_source_provider_impl!`
        // routes through. If the fused macro ever hand-inlines a
        // metadata body different from what the sibling emits, the
        // metadata-name round-trip through
        // `Format::strip_metadata_name` would drift on the fused
        // caller while the sibling caller stayed put.
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/fused-probe.cfg");
        let fused = MacroFusedProbeProvider::file(&path);
        let half_side = MacroProbeProvider { path: path.clone() };
        assert_eq!(
            fused.metadata().name.as_ref(),
            half_side.metadata().name.as_ref(),
            "fused-macro metadata name must equal half-side-macro metadata name",
        );
        // And both must equal the substrate helper's direct emission.
        let via_helper = provider_metadata_for(Format::Lisp, &path);
        assert_eq!(
            fused.metadata().name.as_ref(),
            via_helper.name.as_ref(),
            "fused-macro metadata name must equal substrate-helper metadata name",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_emits_data_matching_the_half_side_impl_macro() {
        // Happy path: the fused macro's `data()` body must produce the
        // same `Map<Profile, Dict>` on the same `(path, format, mapper)`
        // triple as the half-side-only macro's does — the substrate
        // helper `text_source_provider_data` both routes through is one
        // source of truth for the read+map+project cascade.
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "fused-macro-probe").unwrap();

        let fused = MacroFusedProbeProvider::file(&path);
        let half_side = MacroProbeProvider { path: path.clone() };
        assert_eq!(
            fused.data().expect("fused-macro data() must succeed"),
            half_side
                .data()
                .expect("half-side-macro data() must succeed"),
            "fused-macro data() must equal half-side-macro data() on the happy path — drift \
             here means the fused emission stopped routing through `text_source_provider_impl!`",
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn text_source_provider_emits_data_error_matching_the_half_side_impl_macro() {
        // Read-step failure leg: the fused macro must forward whatever
        // the sibling `text_source_provider_impl!` emits on a missing
        // path, byte-for-byte, so a future refinement of the error path
        // lands at the substrate site and every fused emission inherits
        // it in lockstep with the half-side emissions.
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.cfg");

        let fused = MacroFusedProbeProvider::file(&path);
        let half_side = MacroProbeProvider { path: path.clone() };
        assert_eq!(
            fused
                .data()
                .expect_err("fused-macro data() must fail on missing path")
                .to_string(),
            half_side
                .data()
                .expect_err("half-side-macro data() must fail on missing path")
                .to_string(),
            "fused-macro data() error must equal half-side-macro data() error verbatim",
        );
    }

    #[test]
    fn text_source_provider_emits_static_load_matching_the_half_side_impl_macro() {
        // Pins that the fused macro's emitted `pub fn load(&Path)`
        // static one-shot routes through `load_text_source(path, mapper)`
        // verbatim — the same `Value` the sibling `text_source_provider_impl!`
        // static load emits on the same `(path, mapper)` pair. If the
        // fused macro were ever to hand-inline a different static-load
        // body, this pin would fire on the divergence.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("payload.txt");
        fs::write(&path, "fused-macro-probe").unwrap();

        let via_fused =
            MacroFusedProbeProvider::load(&path).expect("fused-macro load() must succeed");
        let via_half_side =
            MacroProbeProvider::load(&path).expect("half-side-macro load() must succeed");
        assert_eq!(
            via_fused, via_half_side,
            "fused-macro static load() must equal half-side-macro static load() on the happy \
             path — drift here means the emitted body no longer routes through \
             `load_text_source`",
        );
    }

    #[test]
    fn text_source_provider_forwards_struct_attributes() {
        // The fused macro's `$(#[$attr])*` slot must forward
        // struct-level attributes verbatim to the emitted struct's
        // front matter — the pre-lift `text_source_provider_struct!`
        // contract. `#[derive(Clone)]` is the load-bearing predicate:
        // the fixture at the head of this test module is cloned here,
        // and if the fused macro ever silently dropped either the
        // `$(#[$attr])*` forwarding OR the baseline `#[derive(Clone)]`
        // the sibling struct-macro emits, this line stops compiling.
        let path = std::path::PathBuf::from("/tmp/fused-probe-clone.cfg");
        let fused = MacroFusedProbeProvider::file(&path);
        let cloned: MacroFusedProbeProvider = fused.clone();
        // Both clones must observe the same path — the private-in-module
        // `path: PathBuf` field survived the Clone.
        assert_eq!(
            format!("{fused:?}"),
            format!("{cloned:?}"),
            "fused-macro-emitted struct must derive Clone identically to the half-side-macro-\
             emitted struct — a divergence here means the `$(#[$attr])*` forwarding or the \
             baseline derive set drifted between the fused and half-side emissions",
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_matches_both_real_callers_on_metadata_and_data() {
        // The fused macro's real load-bearing test is the two
        // production callers it emits code for. This pin proves both of
        // them go through the fused-macro-emitted body (which internally
        // routes through the sibling `text_source_provider_impl!`) and
        // land the same wording on the substrate helper — the
        // drift-closure that would fire if a hand edit reintroduced the
        // pre-fusion two-invocation shape (or worse, the open-coded
        // impl block) at either site.
        use crate::blue_provider::BlueProvider;
        use crate::lisp_provider::LispProvider;
        use figment::Provider;

        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.cfg");

        for (label, format, provider_err) in [
            (
                "blue",
                Format::Blue,
                BlueProvider::file(&missing).data().expect_err("blue"),
            ),
            (
                "lisp",
                Format::Lisp,
                LispProvider::file(&missing).data().expect_err("lisp"),
            ),
        ] {
            let helper_err =
                text_source_provider_data(&missing, format, crate::lisp_provider::load_from_str)
                    .expect_err("substrate helper must fail on the same missing path");
            assert_eq!(
                provider_err.to_string(),
                helper_err.to_string(),
                "{label}: fused-macro-emitted data() error must equal the substrate helper's \
                 on the same missing path — drift here means the impl block was hand-inlined \
                 at the caller and no longer routes through `text_source_provider!`",
            );
        }
    }

    #[cfg(feature = "blue")]
    #[test]
    fn text_source_provider_matches_both_real_callers_on_static_load() {
        // The fused macro's static-load leg on the two production
        // callers: `LispProvider::load(&Path)` and
        // `BlueProvider::load(&Path)` must both route through
        // `load_text_source(path, load_from_str)` verbatim on a missing
        // path. This mirrors the sibling pin
        // `text_source_provider_impl_matches_both_real_callers_on_
        // static_load_wording` but tests the same invariant through the
        // fused emission specifically — so a hand-edit that reintroduces
        // the two-invocation shape at either site (still routes through
        // `text_source_provider_impl!` on the impl half, so the sibling
        // pin still passes) fires here on the fused-side pin.
        use crate::blue_provider::BlueProvider;
        use crate::lisp_provider::LispProvider;

        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.cfg");

        let blue_err = BlueProvider::load(&missing)
            .expect_err("BlueProvider::load() must fail on missing path");
        let lisp_err = LispProvider::load(&missing)
            .expect_err("LispProvider::load() must fail on missing path");
        let helper_err = load_text_source(&missing, crate::lisp_provider::load_from_str)
            .expect_err("substrate-helper load_text_source() must fail on the same missing path");
        assert_eq!(
            blue_err.to_string(),
            helper_err.to_string(),
            "BlueProvider::load error must equal load_text_source() error verbatim — drift \
             here means BlueProvider reintroduced an open-coded static load and no longer \
             routes through `text_source_provider!`",
        );
        assert_eq!(
            lisp_err.to_string(),
            helper_err.to_string(),
            "LispProvider::load error must equal load_text_source() error verbatim — drift \
             here means LispProvider reintroduced an open-coded static load and no longer \
             routes through `text_source_provider!`",
        );
    }
}

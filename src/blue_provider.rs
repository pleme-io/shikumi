//! blue (`.b`) config files — the pleme-io language as a configuration citizen.
//!
//! ## Why this file is ~20 lines and not ~400
//!
//! blue's surface syntax parses to a **tatara-lisp `Sexp`**:
//! `blue-lang-syntax` re-exports `tatara_lisp::{Atom, Sexp}` and
//! `parse_program` returns `Vec<Sexp>`. shikumi already ships the
//! `Sexp` → [`figment::value::Value`] mapping for `.lisp` in
//! [`crate::lisp_provider`].
//!
//! So blue is a **front-end on the existing provider, not a second provider**:
//!
//! ```text
//! lisp:  tatara_lisp::read(src)           -> Vec<Sexp> -> sexp_to_value_root
//! blue:  blue_lang_syntax::parse_program  -> Vec<Sexp> -> sexp_to_value_root
//!                                                        ^^^ the SAME fn
//! ```
//!
//! One mapping, two front-ends — they cannot drift apart, because there is
//! nothing to keep in lockstep. Two parallel mappings would be exactly the
//! drift class this crate is careful about.
//!
//! **Shared AST is NOT shared syntax** (corrected 2026-08-01, after the first
//! draft of this header implied it was). blue's surface is Ruby-like
//! (`def … end`, `x = 5`); it REJECTS tatara-lisp keyword syntax. The same
//! *text* does not parse both ways — what is shared is the `Sexp` each surface
//! lowers to, and the mapping applied after that.
//!
//! **OPEN, and stated rather than glossed:** which blue surface form lowers to
//! a kwargs-list `Sexp` that `sexp_to_value_root` accepts is NOT yet verified.
//! The plumbing is proven; the ergonomic config shape is not. Until a real
//! `.b` config round-trips, treat this provider as wired-but-unproven.
//!
//! That shared `Sexp` is also the first hard evidence that blue's founding
//! claim — *Ruby/Elixir surface → tatara-lisp AST* — is **load-bearing rather
//! than aspirational**: because the AST is genuinely shared, a consumer that
//! already understands tatara-lisp understands blue for one parser call.
//!
//! ## What is deliberately NOT here
//!
//! Only `blue-lang-syntax` is a dependency. The runtime, interpreter, LSP and
//! package manager stay out of shikumi's closure, because **a config file is
//! parsed and mapped, never executed.** A config format that can run arbitrary
//! code is a much larger security surface than one that cannot, and that
//! boundary is a decision rather than an accident of what happened to compile.
//!
//! The `tatara-lisp` version is pinned to match what `blue-lang-syntax`
//! resolves. Two semver-compatible-*looking* versions are **distinct types**
//! to rustc, so this integration does not typecheck across a skew (`E0308`).
//! One AST version fleet-wide is the whole point of a shared AST.
//!
//! ## Shape
//!
//! Identical to the lisp provider's: the first top-level form's kwargs become
//! the config dict. The atom mapping is NOT restated here — see
//! [`crate::lisp_provider`]. Restating it is how two copies of one rule begin
//! to disagree.

use std::path::{Path, PathBuf};

use figment::value::Value;
use figment::{Metadata, Profile, Provider, error::Error as FigmentError, value::Dict, value::Map};

use crate::discovery::Format;
use crate::error::ShikumiError;

/// Figment provider that reads a blue (`.b`) config file.
///
/// The exact shape of [`crate::lisp_provider::LispProvider`], deliberately:
/// both halves route through the shared helpers in [`crate::provider`], so a
/// front-end adds ZERO bespoke metadata or error code and cannot drift the
/// operator-facing diagnostics away from what [`Format`] declares.
///
/// Until this existed, `.b` support was a free function nothing could reach by
/// extension — the provider was wired to the mapping but not to the format
/// primitive, so a `.b` file on disk fell through
/// [`crate::ProviderChain::with_file`]'s conservative arm and was parsed as
/// TOML.
#[derive(Debug, Clone)]
pub struct BlueProvider {
    path: PathBuf,
}

impl BlueProvider {
    /// Read blue config from `path`.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Load and map a blue file, or fail with a `blue:`-prefixed error.
    ///
    /// Both legs — the file-read step and the fused read+map cascade —
    /// route through the shared [`crate::provider::load_text_source`]
    /// substrate helper, which in turn calls
    /// [`crate::provider::read_source_or_parse_err`] for the read step
    /// (so the `"reading {path}: {e}"` I/O error wording is defined once)
    /// and delegates to the mapper for the parse step. The whole `load`
    /// body is a single call, and cannot drift out of lockstep with the
    /// peer text-source provider
    /// [`crate::lisp_provider::LispProvider::load`], which routes through
    /// the same helper.
    pub fn load(path: &Path) -> Result<Value, ShikumiError> {
        crate::provider::load_text_source(path, load_from_str)
    }
}

impl Provider for BlueProvider {
    fn metadata(&self) -> Metadata {
        crate::provider::provider_metadata_for(Format::Blue, &self.path)
    }

    fn data(&self) -> Result<Map<Profile, Dict>, FigmentError> {
        crate::provider::provider_data_from_shikumi_load(Self::load(&self.path), Format::Blue)
    }
}

/// Parse a blue source string into a figment [`Value`].
///
/// Errors carry a `blue:` prefix, so an operator running both `.b` and `.lisp`
/// can tell which front-end complained even though both reach one mapping.
pub fn load_from_str(src: &str) -> Result<Value, ShikumiError> {
    let forms = blue_lang_syntax::parse_program(src)
        .map_err(|e| ShikumiError::Parse(format!("blue: {e}")))?;
    let first = forms.first().ok_or_else(|| {
        ShikumiError::Parse("blue: empty config — expected one top-level form".into())
    })?;
    crate::lisp_provider::sexp_to_value_root(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// blue and lisp are DIFFERENT SURFACES over one AST — corrected 2026-08-01.
    ///
    /// This test originally fed `(defconfig :name "x")` to both and asserted
    /// equal values. It failed, and the failure is the useful part:
    ///
    /// ```text
    /// blue: expected `)`, found Sym("name") at 11..16
    /// ```
    ///
    /// blue REJECTS tatara-lisp keyword syntax, because blue's surface is
    /// Ruby-like (`def … end`, `x = 5` — see `blue/spec/*.b`). The founding
    /// claim is *surface → tatara-lisp AST*, and "shared AST" was never
    /// "shared syntax". The module header said otherwise and has been fixed.
    ///
    /// What is genuinely shared, and all this provider relies on, is the
    /// MAPPING: whatever `Sexp` blue lowers to goes through the same
    /// `sexp_to_value_root` as lisp's. That is asserted structurally here.
    #[test]
    fn blue_rejects_lisp_surface_syntax_because_the_surfaces_differ() {
        let lisp_src = r#"(defconfig :name "x" :port 8080)"#;
        assert!(
            crate::lisp_provider::load_from_str(lisp_src).is_ok(),
            "precondition: this IS valid tatara-lisp"
        );
        let err = load_from_str(lisp_src).expect_err(
            "blue must not accept lisp keyword syntax — if it does, \
                         the surfaces converged and this doc is stale",
        );
        let ShikumiError::Parse(msg) = &err else {
            panic!("expected Parse, got {err:?}")
        };
        assert!(msg.starts_with("blue:"), "must name the front-end: {msg}");
    }

    #[test]
    fn an_empty_source_is_a_typed_error_not_a_panic() {
        let err = load_from_str("").expect_err("empty must not parse");
        assert!(matches!(err, ShikumiError::Parse(_)), "got {err:?}");
    }

    /// A malformed source is rejected at the parse boundary, and the message
    /// names the front-end that rejected it.
    #[test]
    fn a_malformed_source_names_the_blue_front_end() {
        let err = load_from_str("(defconfig :name").expect_err("unbalanced must not parse");
        let ShikumiError::Parse(msg) = &err else {
            panic!("expected Parse, got {err:?}")
        };
        assert!(msg.starts_with("blue:"), "must name the front-end: {msg}");
    }
}

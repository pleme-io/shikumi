//! Figment provider for tatara-lisp configuration files.
//!
//! Parses a `.lisp` / `.lsp` / `.el` file via `tatara-lisp::read`, lifts the
//! first top-level form's kwargs into a figment `Dict`, and feeds it into
//! the same provider chain as YAML / TOML / Nix configs.
//!
//! ## Conversion
//!
//! | Lisp                          | Figment Value       |
//! |-------------------------------|---------------------|
//! | `"hello"`                     | String              |
//! | `42`                          | Integer             |
//! | `3.14`                        | Float               |
//! | `#t` / `#f`                   | Bool                |
//! | `nil`                         | Empty               |
//! | `foo` (bare symbol)           | String `"foo"`      |
//! | `:keyword`                    | String `":keyword"` |
//! | `(a b c)` (non-kwargs list)   | Array               |
//! | `(:k v :k v)` (kwargs list)   | Dict                |
//! | `'x` / `` `x `` / `,x` / `,@x`| (strips outer quote)|
//!
//! The first top-level form must be a list; its kwargs are the root dict.
//! If the head is a symbol like `defescriba`, that symbol is stripped and
//! the remaining kwargs become the dict (matches TataraDomain convention).

use figment::value::{Dict, Value};
use tatara_lisp::{Atom, Sexp};

use crate::discovery::Format;
use crate::error::ShikumiError;
use crate::provider::text_source_provider;

// Emits BOTH the `#[derive(Debug, Clone)] pub struct LispProvider {
// path: PathBuf }` + `pub fn file(path)` ctor half AND the whole
// `impl Provider for LispProvider` block + the ergonomic `pub fn
// load(&Path)` static one-shot half through ONE call to the fused
// `text_source_provider!` substrate macro. Before this fusion this
// module (and its peer `crate::blue_provider`) carried TWO distinct
// macro calls — `text_source_provider_struct!` for the struct/ctor and
// `text_source_provider_impl!` for the impl block — with `LispProvider`
// and the `use` line duplicated across the two invocations. The peer
// `BlueProvider` rides the same fused macro; the two cannot drift on
// the carrier shape, the impl-block shape, or the static-load body.
// See `crate::provider::text_source_provider` for the full lift
// rationale.
text_source_provider! {
    /// Figment provider that reads a tatara-lisp config file.
    ///
    /// The whole surface — struct declaration + `file(path)` ctor + the
    /// [`figment::Provider`] impl block + the ergonomic `load(&Path)`
    /// static one-shot — is emitted by the fused
    /// [`text_source_provider!`](crate::provider::text_source_provider)
    /// substrate macro. The peer
    /// [`crate::blue_provider::BlueProvider`] rides the same fused
    /// macro, so a future refinement of the carrier shape OR the impl
    /// block OR the static load body lands at one site and cannot drift
    /// the two apart.
    LispProvider,
    format = Format::Lisp,
    mapper = load_from_str,
}

/// Parse a tatara-lisp source string into a figment [`Value`].
///
/// The body is a single call through [`sexp_source_to_value_root`], the
/// shared Sexp-source substrate fusion the peer [`crate::blue_provider`]
/// front-end also routes through — the two callers cannot drift on the
/// parse-error projection, the first-form pick, or the root mapping.
pub fn load_from_str(src: &str) -> Result<Value, ShikumiError> {
    sexp_source_to_value_root(
        tatara_lisp::read(src),
        "lisp",
        "empty config — expected one top-level (defX …) form",
    )
}

/// `pub(crate)` so [`crate::blue_provider`] reuses it: blue parses to the
/// same tatara-lisp `Sexp`, so the two front-ends SHARE one mapping instead
/// of each carrying a copy that could drift.
/// Drop a leading bare-symbol head, if there is one.
///
/// `(defjanela :largura 120)` → `(:largura 120)`; `(:a 1)` and
/// `(alpha beta)` are returned untouched — the first because its head is a
/// Keyword, the second because the tail is not a kwargs list and the caller
/// falls back to the ORIGINAL slice.
///
/// ── ★ WHY THIS IS SHARED RATHER THAN INLINE ──────────────────────────
/// This used to live inline in [`sexp_to_value_root`] only, so the strip was
/// a strictly ROOT-ONLY affordance. A nested `(defX …)` — the same form one
/// level down — hit [`sexp_to_value`], failed `is_kwargs_list` (its first
/// element is a Symbol, not a Keyword), and degraded to an array of strings:
///
/// ```text
/// Array([String("defjanela"), String(":largura"), Num(I64(120)), …])
/// ```
///
/// Note the keywords degrade too, so the whole form flattens. The author
/// sees no error — just a wrong shape that fails much later at `Deserialize`
/// time naming a field rather than the form. Fixing it at one site is what
/// keeps root and nested from having two different mapping rules.
fn strip_head(items: &[Sexp]) -> &[Sexp] {
    match items.first() {
        Some(Sexp::Atom(Atom::Symbol(_))) => &items[1..],
        _ => items,
    }
}

/// End-to-end fusion of the "parse to `Vec<Sexp>` → take first form →
/// route through [`sexp_to_value_root`]" cascade every Sexp-source
/// shikumi-built provider carries at the tail of its `load_from_str`.
///
/// One source of truth for the three-step Sexp-source pattern shared by
/// every text-source provider whose front-end lowers to a
/// [`tatara_lisp::Sexp`]. Before this lift both
/// [`LispProvider::load_from_str`] and
/// [`crate::blue_provider::load_from_str`] open-coded the same three
/// lines — parse via their own front-end, project the parse error onto
/// [`ShikumiError::Parse`] with a front-end-named prefix, take the first
/// form or emit a per-front-end empty-config wording, and hand the first
/// [`Sexp`] to the SAME [`sexp_to_value_root`]. Two places any future
/// refinement of that cascade (a span-carrying `ParsedProgram` return
/// threading source locations into the mapper, a fail-fast on
/// `forms.len() > 1` so a stray second top-level form surfaces rather
/// than being silently dropped, a structured miette annotation on the
/// front-end wording) would have to be applied in lockstep — exactly
/// the drift class the peer text-source substrate helpers
/// ([`crate::provider::read_source_or_parse_err`],
/// [`crate::provider::load_text_source`],
/// [`crate::provider::text_source_provider_data`], and the
/// `text_source_provider_impl!` / `path_provider_impl!` macros)
/// exist to close on the other legs of the provider surface.
///
/// This helper closes it at ONE Sexp-source substrate site. A future
/// Sexp-lowering shikumi-built provider — a Ruby-syntax `.rb` front-end
/// whose surface lowers to the same [`Sexp`], a Clojure-flavored EDN
/// reader, an org-mode config lifter — implements its `load_from_str`
/// as ONE call through this helper, inheriting the three-step protocol
/// by construction. Sharpening the protocol then lands at one site
/// instead of once per front-end. Idiom-peer of
/// [`crate::provider::load_text_source`], which closed the analogous
/// read+map cascade on the file side of the same providers.
///
/// # Contract
///
/// - `parse_result` is the raw [`Result`] the caller's front-end parser
///   returned. `E: Display` covers both concrete parse-error types
///   in-tree today ([`tatara_lisp::LispError`] via
///   [`tatara_lisp::read`]'s `Result<Vec<Sexp>>` alias, and
///   `blue_lang_syntax::ParseError` via
///   [`blue_lang_syntax::parse_program`]) as well as any future
///   Sexp-lowering front-end whose error type carries the same trait —
///   the fusion prints the parse error through its [`Display`] impl on
///   the failure leg.
/// - `parse_error_prefix` is prepended verbatim to the parse-error
///   [`Display`], colon-space-separated (`"{prefix}: {e}"`), so the
///   pre-lift caller wordings (`"lisp: {e}"`, `"blue: {e}"`) reach the
///   operator unchanged. Passing `""` would emit `": {e}"`; the caller
///   is expected to pass its own front-end name.
/// - `empty_config_msg` is the exact [`ShikumiError::Parse`] payload the
///   fusion emits when the parsed `Vec<Sexp>` is empty. The per-front-end
///   wordings are load-bearing (blue's tests pin the `"blue:"` front-end
///   name; the empty-config test comment in `src/provider.rs` names both
///   wordings), so the fusion carries them verbatim rather than
///   synthesizing a single shared string.
///
/// # Errors
///
/// - [`ShikumiError::Parse`] with wording `"{parse_error_prefix}: {e}"`
///   if `parse_result` was [`Err`], where `{e}` is the parse error's
///   [`Display`].
/// - [`ShikumiError::Parse`] with wording `empty_config_msg` verbatim if
///   the parsed program has no top-level forms.
/// - Whatever [`ShikumiError`] [`sexp_to_value_root`] produces on a
///   first-form mapping failure; the fusion does not alter, prefix, or
///   synthesize on that leg.
pub(crate) fn sexp_source_to_value_root<E: std::fmt::Display>(
    parse_result: Result<Vec<Sexp>, E>,
    parse_error_prefix: &'static str,
    empty_config_msg: &'static str,
) -> Result<Value, ShikumiError> {
    let forms =
        parse_result.map_err(|e| ShikumiError::Parse(format!("{parse_error_prefix}: {e}")))?;
    let first = forms
        .first()
        .ok_or_else(|| ShikumiError::Parse(empty_config_msg.into()))?;
    sexp_to_value_root(first)
}

pub(crate) fn sexp_to_value_root(sexp: &Sexp) -> Result<Value, ShikumiError> {
    // Top-level form: (defX :k v :k v …) — strip the head symbol.
    match sexp {
        Sexp::List(items) => {
            let rest = strip_head(items);
            let stripped = rest.len() != items.len();
            if is_kwargs_list(rest) {
                Ok(crate::provider::figment_default_dict(kwargs_to_dict(rest)?))
            } else if items.len() == 1 && stripped {
                // `(defX)` with no fields — empty dict.
                Ok(crate::provider::figment_default_dict(Dict::new()))
            } else {
                Ok(sexp_to_value(sexp))
            }
        }
        other => Ok(sexp_to_value(other)),
    }
}

fn sexp_to_value(sexp: &Sexp) -> Value {
    match sexp {
        Sexp::Nil => crate::provider::figment_default_empty_none(),
        Sexp::Atom(Atom::Str(s)) => Value::from(s.clone()),
        Sexp::Atom(Atom::Int(n)) => Value::from(*n),
        Sexp::Atom(Atom::Float(f)) => Value::from(*f),
        Sexp::Atom(Atom::Bool(b)) => Value::from(*b),
        Sexp::Atom(Atom::Symbol(s)) => Value::from(s.clone()),
        Sexp::Atom(Atom::Keyword(s)) => Value::from(format!(":{s}")),
        Sexp::List(items) => {
            // A bare kwargs list `(:a 1 :b 2)` maps directly; a HEADED form
            // `(defX :a 1)` maps the same way once its head is dropped, so
            // nested `(defX …)` behaves exactly like a top-level one. The
            // array fallback deliberately uses the ORIGINAL `items`, never
            // the stripped tail — otherwise a plain symbol list like
            // `(alpha beta gamma)` would silently lose `alpha`.
            let rest = strip_head(items);
            if is_kwargs_list(items) {
                crate::provider::figment_default_dict(kwargs_to_dict(items).unwrap_or_default())
            } else if is_kwargs_list(rest) {
                crate::provider::figment_default_dict(kwargs_to_dict(rest).unwrap_or_default())
            } else {
                crate::provider::figment_default_array(items.iter().map(sexp_to_value).collect())
            }
        }
        Sexp::Quote(inner)
        | Sexp::Quasiquote(inner)
        | Sexp::Unquote(inner)
        | Sexp::UnquoteSplice(inner) => sexp_to_value(inner),
    }
}

fn is_kwargs_list(items: &[Sexp]) -> bool {
    !items.is_empty()
        && items.len() % 2 == 0
        && items
            .iter()
            .step_by(2)
            .all(|s| matches!(s, Sexp::Atom(Atom::Keyword(_))))
}

fn kwargs_to_dict(items: &[Sexp]) -> Result<Dict, ShikumiError> {
    let mut out = Dict::new();
    let mut i = 0;
    while i + 1 < items.len() {
        let key = match &items[i] {
            Sexp::Atom(Atom::Keyword(k)) => kebab_to_snake(k),
            _ => {
                return Err(ShikumiError::Parse(format!(
                    "expected keyword at position {i}",
                )));
            }
        };
        out.insert(key, sexp_to_value(&items[i + 1]));
        i += 2;
    }
    Ok(out)
}

/// Figment's default serde deserializer expects snake_case keys, matching
/// the Rust field naming convention. Shikumi converts kebab→snake here so
/// users author `:my-field` in Lisp and `my_field: T` in Rust seamlessly.
fn kebab_to_snake(s: &str) -> String {
    s.replace('-', "_")
}

// The `impl Provider for LispProvider` block AND the ergonomic
// `impl LispProvider { pub fn load(&Path) -> ... }` static one-shot are
// now emitted by the fused `text_source_provider!` macro invocation at
// the head of this module, together with the struct declaration and
// its `file(path)` ctor. Prior to the fusion this file carried a
// SECOND macro call at this site — `text_source_provider_impl!(
// LispProvider, Format::Lisp, load_from_str);` — that duplicated the
// type name and the `(Format, mapper)` pair the head-of-module
// `text_source_provider_struct!` already declared. See
// `crate::provider::text_source_provider` for the full lift rationale.

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ A NESTED `(defX …)` MUST MAP LIKE A TOP-LEVEL ONE.
    ///
    /// [`sexp_to_value_root`] strips a leading bare-symbol head so
    /// `(defescriba :tema "nord")` becomes a dict. The recursive
    /// [`sexp_to_value`] had no such arm, so the SAME form one level down
    /// fell through `is_kwargs_list` (its first element is a Symbol, not a
    /// Keyword) and became a `Value::Array` whose first element was the
    /// literal string `"defjanela"` — the head leaking into the data.
    ///
    /// That is broader than collection literals: any nested call form was
    /// affected, which is most of what a real config nests. A config author
    /// gets no error, just a wrong shape that fails far away at
    /// `Deserialize` time naming a field rather than the form.
    #[test]
    fn a_nested_def_form_maps_to_a_dict_not_an_array_of_its_head() {
        let src = r#"
(defescriba
  :tema "nord"
  :janela (defjanela :largura 120 :altura 40))
"#;
        let v = load_from_str(src).expect("parses");
        let Value::Dict(_, d) = v else {
            panic!("expected top-level dict")
        };

        let janela = d.get("janela").expect("janela key present");
        let Value::Dict(_, inner) = janela else {
            panic!(
                "nested (defjanela …) must be a Dict, got {janela:?} \
                 — the head symbol leaked into the value"
            )
        };
        assert_eq!(inner.get("largura").and_then(Value::to_i128), Some(120));
        assert_eq!(inner.get("altura").and_then(Value::to_i128), Some(40));
    }

    /// The counter-case that keeps the fix honest: a plain list of bare
    /// symbols is NOT a headed form, and must survive intact as an array.
    /// A head-strip that fired here would silently eat the first element.
    #[test]
    fn a_plain_symbol_list_is_not_head_stripped() {
        let src = r#"(defapp :plugins (alpha beta gamma))"#;
        let v = load_from_str(src).expect("parses");
        let Value::Dict(_, d) = v else {
            panic!("expected dict")
        };
        let Value::Array(_, items) = d.get("plugins").expect("plugins") else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 3, "no element may be eaten as a head");
        assert_eq!(items[0].to_actual_str(), Some("alpha"));
    }

    #[test]
    fn parses_defescriba_with_strings_and_numbers() {
        let src = r#"
(defescriba
  :tema "nord"
  :largura-tab 2
  :numeros-linha #t)
"#;
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else {
            panic!("expected dict")
        };
        assert_eq!(d.get("tema").and_then(Value::to_actual_str), Some("nord"));
        assert_eq!(d.get("largura_tab").and_then(Value::to_i128), Some(2));
        assert_eq!(d.get("numeros_linha").and_then(Value::to_bool), Some(true));
    }

    #[test]
    fn kebab_keys_become_snake() {
        let src = r#"(defapp :window-width 1200 :show-status-line #t)"#;
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else { panic!() };
        assert!(d.contains_key("window_width"));
        assert!(d.contains_key("show_status_line"));
    }

    #[test]
    fn nested_kwargs_become_nested_dicts() {
        let src = r#"
(defapp
  :window (:width 1200 :height 800)
  :theme (:name "nord" :contrast "dark"))
"#;
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else { panic!() };
        let Value::Dict(_, window) = d.get("window").unwrap().clone() else {
            panic!("expected nested window dict")
        };
        assert_eq!(window.get("width").and_then(Value::to_i128), Some(1200));
        assert_eq!(window.get("height").and_then(Value::to_i128), Some(800));
    }

    #[test]
    fn bare_symbols_become_strings() {
        let src = r#"(defapp :kind Biblioteca :severity Critical)"#;
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else { panic!() };
        assert_eq!(
            d.get("kind").and_then(Value::to_actual_str),
            Some("Biblioteca")
        );
        assert_eq!(
            d.get("severity").and_then(Value::to_actual_str),
            Some("Critical")
        );
    }

    #[test]
    fn lists_become_arrays() {
        let src = r#"(defapp :tags ("prod" "observability" "alerts"))"#;
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else { panic!() };
        let Value::Array(_, arr) = d.get("tags").unwrap().clone() else {
            panic!("expected array")
        };
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].to_actual_str(), Some("prod"));
    }

    #[test]
    fn empty_form_is_empty_dict() {
        let src = "(defapp)";
        let v = load_from_str(src).unwrap();
        let Value::Dict(_, d) = v else { panic!() };
        assert!(d.is_empty());
    }

    #[test]
    fn file_provider_round_trip() {
        use figment::Figment;
        use serde::Deserialize;

        #[derive(Debug, Deserialize, PartialEq)]
        struct Conf {
            tema: String,
            largura_tab: u32,
        }

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app.lisp");
        std::fs::write(&path, r#"(defapp :tema "nord" :largura-tab 4)"#).unwrap();
        let conf: Conf = Figment::new()
            .merge(LispProvider::file(&path))
            .extract()
            .unwrap();
        assert_eq!(
            conf,
            Conf {
                tema: "nord".into(),
                largura_tab: 4,
            }
        );
    }

    #[test]
    fn data_error_routes_through_provider_data_from_value_helper() {
        // A top-level lisp form that yields a non-Dict figment Value
        // (`(defapp foo)` has one non-keyword argument, which
        // `is_kwargs_list` rejects, so `sexp_to_value_root` falls back
        // to `sexp_to_value` and produces `Value::Array`).
        // `Provider::data` then routes through
        // `provider_data_from_value`, which emits the format-specific
        // wording sourced from `Format::Lisp.dict_required_message`.
        // This test pins the routing: the message the operator sees on
        // a Lisp-side top-level-shape failure is the one
        // `Format::dict_required_message(Format::Lisp)` declares — the
        // open-coded `"top-level lisp form must be a kwargs list"`
        // wording the previous inline `match` emitted lives at one site
        // now, and the lift cannot drift the diagnostic away from it.
        use figment::Provider;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("not_kwargs.lisp");
        std::fs::write(&path, "(defapp foo)").unwrap();

        let provider = LispProvider::file(&path);
        let err = provider
            .data()
            .expect_err("non-kwargs top-level form must error");
        let msg = err.to_string();
        let prefix = Format::Lisp.dict_required_message();
        assert!(
            msg.starts_with(prefix),
            "Lisp data() error must start with `{prefix}`, got `{msg}`",
        );
        assert!(
            msg.contains("; got "),
            "data() error must append the concrete-Value tail; got `{msg}`",
        );
    }

    #[test]
    fn metadata_name_matches_format_primitive() {
        // The `Provider::metadata` impl must use `Format::Lisp.metadata_name`
        // verbatim — the cross-call-site invariant the resolver relies on
        // when stripping the prefix back via `Format::strip_metadata_name`.
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/some/lisp.cfg.lisp");
        let provider = LispProvider::file(&path);
        let md = provider.metadata();
        assert_eq!(
            md.name.as_ref(),
            Format::Lisp.metadata_name(&path),
            "LispProvider metadata name must equal Format::Lisp.metadata_name(path)"
        );
        // And the round-trip via the resolver-side primitive surfaces
        // the same path the provider was constructed from.
        let (recovered_format, rest) =
            Format::strip_metadata_name(&md.name).expect("LispProvider name must round-trip");
        assert_eq!(recovered_format, Format::Lisp);
        assert_eq!(rest, path.display().to_string());
    }

    // ---- sexp_source_to_value_root (parse → first → sexp_to_value_root) ----
    //
    // The three-step Sexp-source fusion shared by `LispProvider::load_from_str`
    // and `BlueProvider::load_from_str`. Before this lift each caller
    // open-coded the same body — parse via its front-end, project the parse
    // error onto `ShikumiError::Parse` with a per-front-end prefix, take the
    // first form or emit a per-front-end empty-config wording, and hand it
    // to `sexp_to_value_root`. These tests pin the fusion at ONE substrate
    // site so a caller sensing shape changes still trips them.

    /// Front-end-labeled parse errors: whatever the caller-supplied parse
    /// error's `Display` renders, the fusion prepends `"{prefix}: "` to it
    /// verbatim.
    #[test]
    fn sexp_source_to_value_root_projects_parse_error_with_prefix() {
        #[derive(Debug)]
        struct FakeParseError(&'static str);
        impl std::fmt::Display for FakeParseError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }

        let parsed: Result<Vec<Sexp>, FakeParseError> = Err(FakeParseError("expected `)`"));
        let err = super::sexp_source_to_value_root(parsed, "frontend", "unused")
            .expect_err("parse error must propagate");
        let ShikumiError::Parse(msg) = &err else {
            panic!("expected Parse, got {err:?}")
        };
        assert_eq!(
            msg, "frontend: expected `)`",
            "wording is `{{prefix}}: {{parse_error_display}}` verbatim",
        );
    }

    /// Empty programs: the caller-supplied `empty_config_msg` is the
    /// verbatim `ShikumiError::Parse` payload.
    #[test]
    fn sexp_source_to_value_root_projects_empty_program_verbatim() {
        let parsed: Result<Vec<Sexp>, std::convert::Infallible> = Ok(Vec::new());
        let err = super::sexp_source_to_value_root(parsed, "unused", "the-empty-config-wording")
            .expect_err("empty program must not map");
        let ShikumiError::Parse(msg) = &err else {
            panic!("expected Parse, got {err:?}")
        };
        assert_eq!(
            msg, "the-empty-config-wording",
            "empty_config_msg must reach the caller verbatim",
        );
    }

    /// Happy path: a single top-level `(defX :k v)` form routes through
    /// `sexp_to_value_root` and produces the same Dict every direct caller
    /// of `sexp_to_value_root` would.
    #[test]
    fn sexp_source_to_value_root_routes_first_form_through_sexp_to_value_root() {
        let forms = tatara_lisp::read(r#"(defapp :name "x" :count 7)"#)
            .expect("precondition: parses to one form");
        let via_fusion =
            super::sexp_source_to_value_root::<std::convert::Infallible>(Ok(forms.clone()), "", "")
                .expect("first form maps");
        let via_direct = super::sexp_to_value_root(&forms[0]).expect("direct call maps");
        assert_eq!(
            via_fusion, via_direct,
            "fusion must produce the same Value as a direct sexp_to_value_root call \
             on the first form",
        );
    }

    /// Multi-form programs: only the FIRST form is mapped. The pre-lift
    /// callers relied on this behavior too — the fusion preserves it, so a
    /// program with a stray trailing form does not surface as a hard error
    /// through this leg.
    #[test]
    fn sexp_source_to_value_root_maps_only_the_first_form() {
        let forms = tatara_lisp::read(r#"(defapp :name "first") (defapp :name "second")"#)
            .expect("precondition: parses to two forms");
        assert_eq!(forms.len(), 2, "precondition: two top-level forms");
        let v = super::sexp_source_to_value_root::<std::convert::Infallible>(Ok(forms), "", "")
            .expect("first form maps");
        let Value::Dict(_, d) = v else {
            panic!("expected dict, got {v:?}")
        };
        assert_eq!(
            d.get("name").and_then(Value::to_actual_str),
            Some("first"),
            "only the first form's kwargs contribute to the root dict",
        );
    }

    /// Drift-closure against the LIVE `LispProvider::load_from_str` caller:
    /// its parse-error wording is byte-equal to what the fusion emits with
    /// the pre-lift `("lisp", "empty config — expected one top-level (defX
    /// …) form")` arguments. Reintroducing an open-coded parse-error
    /// projection at `LispProvider::load_from_str` fires this test.
    #[test]
    fn lisp_load_from_str_parse_error_matches_the_fusion_verbatim() {
        // `(unclosed` — front-end can't finish, guaranteed parse error.
        let src = "(unclosed";
        let live = load_from_str(src).expect_err("precondition: parse must fail");
        let fused = super::sexp_source_to_value_root(
            tatara_lisp::read(src),
            "lisp",
            "empty config — expected one top-level (defX …) form",
        )
        .expect_err("fusion must fail identically");
        assert_eq!(
            live.to_string(),
            fused.to_string(),
            "LispProvider::load_from_str must route through sexp_source_to_value_root \
             with the load-bearing (\"lisp\", lisp-empty-wording) arguments",
        );
    }

    /// Empty-program drift-closure against the LIVE
    /// `LispProvider::load_from_str` caller: the empty wording routes
    /// through the fusion with the same `empty_config_msg` argument the
    /// pre-lift open-coded body used. A future refactor that changes the
    /// empty wording at either site fires this test.
    #[test]
    fn lisp_load_from_str_empty_error_matches_the_fusion_verbatim() {
        let live = load_from_str("").expect_err("precondition: empty must fail");
        let fused = super::sexp_source_to_value_root(
            tatara_lisp::read(""),
            "lisp",
            "empty config — expected one top-level (defX …) form",
        )
        .expect_err("fusion must fail identically");
        assert_eq!(
            live.to_string(),
            fused.to_string(),
            "LispProvider::load_from_str's empty wording must be the fusion's \
             empty_config_msg verbatim",
        );
    }

    /// Cross-caller drift-closure: the blue peer front-end must route
    /// through the SAME fusion with its own `("blue", blue-empty-wording)`
    /// arguments — pinned here (not at blue's own test module) so the
    /// substrate site sees both callers pinned together and a future
    /// hand-edit that reintroduces an open-coded body at EITHER caller
    /// fires from this file.
    #[cfg(feature = "blue")]
    #[test]
    fn blue_load_from_str_parse_error_matches_the_fusion_verbatim() {
        let src = "(defconfig :name"; // unbalanced, guaranteed parse error
        let live = crate::blue_provider::load_from_str(src)
            .expect_err("precondition: blue parse must fail");
        let fused = super::sexp_source_to_value_root(
            blue_lang_syntax::parse_program(src),
            "blue",
            "blue: empty config — expected one top-level form",
        )
        .expect_err("fusion must fail identically");
        assert_eq!(
            live.to_string(),
            fused.to_string(),
            "BlueProvider::load_from_str must route through sexp_source_to_value_root \
             with the load-bearing (\"blue\", blue-empty-wording) arguments",
        );
    }

    /// Empty-program drift-closure against the LIVE
    /// `blue_provider::load_from_str` caller: pinned alongside the lisp
    /// peer so the substrate site owns BOTH callers' empty wordings.
    #[cfg(feature = "blue")]
    #[test]
    fn blue_load_from_str_empty_error_matches_the_fusion_verbatim() {
        let live = crate::blue_provider::load_from_str("")
            .expect_err("precondition: blue empty must fail");
        let fused = super::sexp_source_to_value_root(
            blue_lang_syntax::parse_program(""),
            "blue",
            "blue: empty config — expected one top-level form",
        )
        .expect_err("fusion must fail identically");
        assert_eq!(
            live.to_string(),
            fused.to_string(),
            "BlueProvider::load_from_str's empty wording must be the fusion's \
             empty_config_msg verbatim",
        );
    }

    /// Helper trait for test assertions — figment's Value API is verbose.
    trait ValueHelpers {
        fn to_actual_str(&self) -> Option<&str>;
        fn to_i128(&self) -> Option<i128>;
        fn to_bool(&self) -> Option<bool>;
    }

    impl ValueHelpers for Value {
        fn to_actual_str(&self) -> Option<&str> {
            match self {
                Value::String(_, s) => Some(s),
                _ => None,
            }
        }
        fn to_i128(&self) -> Option<i128> {
            match self {
                Value::Num(_, n) => n.to_i128(),
                _ => None,
            }
        }
        fn to_bool(&self) -> Option<bool> {
            match self {
                Value::Bool(_, b) => Some(*b),
                _ => None,
            }
        }
    }
}

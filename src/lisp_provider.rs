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

use std::path::{Path, PathBuf};

use figment::value::{Dict, Map, Value};
use figment::{Error as FigmentError, Metadata, Profile, Provider};
use tatara_lisp::{Atom, Sexp};

use crate::discovery::Format;
use crate::error::ShikumiError;

/// Figment provider that reads a tatara-lisp config file.
#[derive(Debug, Clone)]
pub struct LispProvider {
    path: PathBuf,
}

impl LispProvider {
    /// Create a provider from a path. The file is not read until
    /// [`figment::Provider::data`] is called.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Read + parse + convert in one shot — useful for tests.
    ///
    /// The file-read step routes through the shared
    /// [`crate::provider::read_source_or_parse_err`] substrate helper, so
    /// the `"reading {path}: {e}"` I/O error wording is defined once
    /// beside the other shikumi-built-provider primitives and cannot
    /// drift out of lockstep with the peer text-source provider
    /// [`crate::blue_provider::BlueProvider::load`].
    pub fn load(path: &Path) -> Result<Value, ShikumiError> {
        let src = crate::provider::read_source_or_parse_err(path)?;
        load_from_str(&src)
    }
}

/// Parse a tatara-lisp source string into a figment [`Value`].
pub fn load_from_str(src: &str) -> Result<Value, ShikumiError> {
    let forms = tatara_lisp::read(src).map_err(|e| ShikumiError::Parse(format!("lisp: {e}")))?;
    let first = forms.first().ok_or_else(|| {
        ShikumiError::Parse("empty config — expected one top-level (defX …) form".into())
    })?;
    sexp_to_value_root(first)
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

pub(crate) fn sexp_to_value_root(sexp: &Sexp) -> Result<Value, ShikumiError> {
    // Top-level form: (defX :k v :k v …) — strip the head symbol.
    match sexp {
        Sexp::List(items) => {
            let rest = strip_head(items);
            let stripped = rest.len() != items.len();
            if is_kwargs_list(rest) {
                Ok(Value::Dict(
                    figment::value::Tag::Default,
                    kwargs_to_dict(rest)?,
                ))
            } else if items.len() == 1 && stripped {
                // `(defX)` with no fields — empty dict.
                Ok(Value::Dict(figment::value::Tag::Default, Dict::new()))
            } else {
                Ok(sexp_to_value(sexp))
            }
        }
        other => Ok(sexp_to_value(other)),
    }
}

fn sexp_to_value(sexp: &Sexp) -> Value {
    match sexp {
        Sexp::Nil => Value::Empty(figment::value::Tag::Default, figment::value::Empty::None),
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
                Value::Dict(
                    figment::value::Tag::Default,
                    kwargs_to_dict(items).unwrap_or_default(),
                )
            } else if is_kwargs_list(rest) {
                Value::Dict(
                    figment::value::Tag::Default,
                    kwargs_to_dict(rest).unwrap_or_default(),
                )
            } else {
                Value::Array(
                    figment::value::Tag::Default,
                    items.iter().map(sexp_to_value).collect(),
                )
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

impl Provider for LispProvider {
    fn metadata(&self) -> Metadata {
        crate::provider::provider_metadata_for(Format::Lisp, &self.path)
    }

    fn data(&self) -> Result<Map<Profile, Dict>, FigmentError> {
        crate::provider::provider_data_from_shikumi_load(Self::load(&self.path), Format::Lisp)
    }
}

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

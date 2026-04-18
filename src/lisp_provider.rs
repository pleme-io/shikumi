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
    pub fn load(path: &Path) -> Result<Value, ShikumiError> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| ShikumiError::Parse(format!("reading {}: {e}", path.display())))?;
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

fn sexp_to_value_root(sexp: &Sexp) -> Result<Value, ShikumiError> {
    // Top-level form: (defX :k v :k v …) — strip the head symbol.
    match sexp {
        Sexp::List(items) => {
            let start = match items.first() {
                Some(Sexp::Atom(Atom::Symbol(_))) => 1,
                _ => 0,
            };
            let rest = &items[start..];
            if is_kwargs_list(rest) {
                Ok(Value::Dict(
                    figment::value::Tag::Default,
                    kwargs_to_dict(rest)?,
                ))
            } else if items.len() == 1 && start == 1 {
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
            if is_kwargs_list(items) {
                Value::Dict(
                    figment::value::Tag::Default,
                    kwargs_to_dict(items).unwrap_or_default(),
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
        Metadata::named(format!("lisp: {}", self.path.display()))
    }

    fn data(&self) -> Result<Map<Profile, Dict>, FigmentError> {
        let value = Self::load(&self.path).map_err(|e| FigmentError::from(e.to_string()))?;
        let dict = match value {
            Value::Dict(_, d) => d,
            other => {
                return Err(FigmentError::from(format!(
                    "top-level lisp form must be a kwargs list; got {other:?}"
                )));
            }
        };
        let mut map = Map::new();
        map.insert(Profile::Default, dict);
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

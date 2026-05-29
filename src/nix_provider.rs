//! Figment provider for Nix expression configs.
//!
//! Evaluates a `.nix` file via `nix eval --file <path> --json` and feeds
//! the resulting attrset as a figment `Dict`. Requires the `nix` binary
//! on `$PATH` — consumers that can't assume that should stick to YAML /
//! Lisp configs, which parse in-process.
//!
//! Per the tatara-lisp ecosystem standard, Nix sits alongside YAML and
//! Lisp as a first-class config format.

use std::path::{Path, PathBuf};
use std::process::Command;

use figment::value::{Dict, Map, Value};
use figment::{Error as FigmentError, Metadata, Profile, Provider};

use crate::discovery::Format;
use crate::error::ShikumiError;

/// Figment provider that evaluates a Nix config file via `nix eval`.
#[derive(Debug, Clone)]
pub struct NixProvider {
    path: PathBuf,
    nix_binary: String,
}

impl NixProvider {
    /// Create a provider from a path. The file is not evaluated until
    /// [`figment::Provider::data`] is called.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            nix_binary: "nix".to_string(),
        }
    }

    /// Override the nix binary (default `nix`). Useful for hermetic tests
    /// and non-standard installations (`nix-command` experimental feature
    /// requires Nix 2.4+).
    #[must_use]
    pub fn with_binary(mut self, nix: impl Into<String>) -> Self {
        self.nix_binary = nix.into();
        self
    }

    /// Evaluate the file and return the parsed JSON as a figment Value.
    pub fn load(&self) -> Result<Value, ShikumiError> {
        let output = Command::new(&self.nix_binary)
            .args([
                "eval",
                "--file",
                self.path
                    .to_str()
                    .ok_or_else(|| ShikumiError::Parse("non-utf8 nix path".into()))?,
                "--json",
                "--impure",
            ])
            .output()
            .map_err(|e| {
                ShikumiError::Parse(format!(
                    "spawning '{}': {e} — is nix on $PATH?",
                    self.nix_binary
                ))
            })?;

        if !output.status.success() {
            return Err(ShikumiError::Parse(format!(
                "nix eval failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
            )));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| ShikumiError::Parse(format!("parsing nix JSON output: {e}")))?;
        Ok(json_to_figment_value(&json))
    }

    /// One-shot: eval + extract into a typed value, no figment layering.
    pub fn load_path(path: &Path) -> Result<Value, ShikumiError> {
        Self::file(path.to_path_buf()).load()
    }
}

fn json_to_figment_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => {
            Value::Empty(figment::value::Tag::Default, figment::value::Empty::None)
        }
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(f) = n.as_f64() {
                Value::from(f)
            } else {
                Value::from(0i64)
            }
        }
        serde_json::Value::String(s) => Value::from(s.clone()),
        serde_json::Value::Array(items) => Value::Array(
            figment::value::Tag::Default,
            items.iter().map(json_to_figment_value).collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut dict = Dict::new();
            for (k, v) in map {
                dict.insert(k.clone(), json_to_figment_value(v));
            }
            Value::Dict(figment::value::Tag::Default, dict)
        }
    }
}

impl Provider for NixProvider {
    fn metadata(&self) -> Metadata {
        Metadata::named(Format::Nix.metadata_name(&self.path))
    }

    fn data(&self) -> Result<Map<Profile, Dict>, FigmentError> {
        let value = self.load().map_err(|e| FigmentError::from(e.to_string()))?;
        crate::provider::provider_data_from_value(value, Format::Nix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_to_figment_maps_types() {
        let j: serde_json::Value = serde_json::from_str(
            r#"{"name":"demo","count":42,"enabled":true,"tags":["a","b"],"nested":{"k":"v"}}"#,
        )
        .unwrap();
        let v = json_to_figment_value(&j);
        let Value::Dict(_, d) = v else {
            panic!("expected dict")
        };
        assert_eq!(
            d.get("name").and_then(|v| match v {
                Value::String(_, s) => Some(s.as_str()),
                _ => None,
            }),
            Some("demo")
        );
        assert!(matches!(d.get("count"), Some(Value::Num(_, _))));
        assert!(matches!(d.get("enabled"), Some(Value::Bool(_, true))));
        assert!(matches!(d.get("tags"), Some(Value::Array(_, _))));
        assert!(matches!(d.get("nested"), Some(Value::Dict(_, _))));
    }

    #[test]
    fn missing_nix_binary_errors_gracefully() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("demo.nix");
        std::fs::write(&path, "{ hello = \"world\"; }").unwrap();
        let err = NixProvider::file(&path)
            .with_binary("/nonexistent/nix-binary-that-does-not-exist")
            .load()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nix") || msg.contains("spawning"));
    }

    #[test]
    fn metadata_name_matches_format_primitive() {
        // The `Provider::metadata` impl must use `Format::Nix.metadata_name`
        // verbatim — the cross-call-site invariant the resolver relies on
        // when stripping the prefix back via `Format::strip_metadata_name`.
        use figment::Provider;

        let path = std::path::PathBuf::from("/tmp/some/conf.nix");
        let provider = NixProvider::file(&path);
        let md = provider.metadata();
        assert_eq!(
            md.name.as_ref(),
            Format::Nix.metadata_name(&path),
            "NixProvider metadata name must equal Format::Nix.metadata_name(path)"
        );
        // And the round-trip via the resolver-side primitive surfaces
        // the same path the provider was constructed from.
        let (recovered_format, rest) =
            Format::strip_metadata_name(&md.name).expect("NixProvider name must round-trip");
        assert_eq!(recovered_format, Format::Nix);
        assert_eq!(rest, path.display().to_string());
    }
}

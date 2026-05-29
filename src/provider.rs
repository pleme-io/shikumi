//! Figment provider chain builder.
//!
//! Extracted from karakuri's `InnerConfig::from_figment`. Assembles a
//! layered figment configuration: defaults → env vars → config file,
//! with auto-detection of YAML vs TOML by file extension.

use std::path::Path;

use figment::{
    providers::{Env, Format as _, Serialized, Toml as FigToml, Yaml as FigYaml},
    value::{Dict, Map, Value},
    Error as FigmentError, Figment, Profile,
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
    #[must_use]
    pub fn with_defaults<T: Serialize>(mut self, defaults: &T) -> Self {
        self.figment = self.figment.merge(Serialized::defaults(defaults));
        self.sources.push(ConfigSource::Defaults);
        self
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
            Some(Format::Lisp) => {
                #[cfg(feature = "lisp")]
                {
                    self.figment = self
                        .figment
                        .merge(crate::lisp_provider::LispProvider::file(path));
                }
                #[cfg(not(feature = "lisp"))]
                {
                    tracing::warn!(
                        path = %path.display(),
                        "shikumi built without the `lisp` feature; skipping .lisp config. \
                         Enable the feature or convert to .yaml/.toml/.nix."
                    );
                }
            }
            Some(Format::Nix) => {
                self.figment = self
                    .figment
                    .merge(crate::nix_provider::NixProvider::file(path));
            }
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
}

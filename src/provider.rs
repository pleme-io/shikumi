//! Figment provider chain builder.
//!
//! Extracted from karakuri's `InnerConfig::from_figment`. Assembles a
//! layered figment configuration: defaults → env vars → config file,
//! with auto-detection of YAML vs TOML by file extension.

use std::path::Path;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml as FigToml, Yaml as FigYaml},
};
use serde::{Deserialize, Serialize};

use crate::error::ShikumiError;

/// Builder for a figment provider chain.
///
/// Layers are merged in order — later layers override earlier ones.
/// The typical pattern: defaults → env vars → config file.
pub struct ProviderChain {
    figment: Figment,
}

impl ProviderChain {
    /// Start with an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            figment: Figment::new(),
        }
    }

    /// Merge serde-serializable defaults as the base layer.
    #[must_use]
    pub fn with_defaults<T: Serialize>(mut self, defaults: &T) -> Self {
        self.figment = self.figment.merge(Serialized::defaults(defaults));
        self
    }

    /// Merge environment variables with the given prefix.
    ///
    /// Nested keys use `__` as separator (e.g. `MYAPP_OPTIONS__PADDING=10`).
    #[must_use]
    pub fn with_env(mut self, prefix: &str) -> Self {
        self.figment = self.figment.merge(Env::prefixed(prefix).split("__"));
        self
    }

    /// Merge a config file, auto-detecting format by extension.
    ///
    /// - `.yaml` / `.yml` → YAML provider
    /// - anything else → TOML provider
    #[must_use]
    pub fn with_file(mut self, path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml" | "yml") => {
                self.figment = self.figment.merge(FigYaml::file(path));
            }
            _ => {
                self.figment = self.figment.merge(FigToml::file(path));
            }
        }
        self
    }

    /// Extract the final configuration.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::Figment` if extraction fails (missing required
    /// fields, type mismatches, etc.).
    pub fn extract<T: for<'de> Deserialize<'de>>(self) -> Result<T, ShikumiError> {
        Ok(self.figment.extract()?)
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

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .extract()
            .unwrap();
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

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("from_yml"));
        assert_eq!(config.count, Some(55));
    }

    #[test]
    fn empty_yaml_file_produces_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.yaml");
        fs::write(&file, "").unwrap();

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .extract()
            .unwrap();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn empty_toml_file_produces_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.toml");
        fs::write(&file, "").unwrap();

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .extract()
            .unwrap();
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

        let config: NestedConfig = ProviderChain::new()
            .with_env(prefix)
            .extract()
            .unwrap();

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

        let config: TestConfig = ProviderChain::new()
            .with_file(&file)
            .extract()
            .unwrap();
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
}

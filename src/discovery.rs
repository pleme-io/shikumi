//! Config file discovery — parameterized XDG path scanning.
//!
//! Extracted from karakuri's `CONFIGURATION_FILE` LazyLock. Generalized
//! so any app can use the same discovery logic by providing its name.

use std::env;
use std::path::PathBuf;

use tracing::warn;

use crate::error::ShikumiError;

/// Supported config file formats, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Toml,
}

impl Format {
    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Toml => &["toml"],
        }
    }
}

/// Builder for config file discovery.
///
/// Scans XDG paths, `$HOME/.config/{app}/`, and legacy `$HOME/.{app}`
/// locations. The first existing file wins.
pub struct ConfigDiscovery {
    app_name: String,
    env_override: Option<String>,
    formats: Vec<Format>,
}

impl ConfigDiscovery {
    /// Create a new discovery for the given app name.
    ///
    /// Default format preference: YAML first, then TOML.
    #[must_use]
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_owned(),
            env_override: None,
            formats: vec![Format::Yaml, Format::Toml],
        }
    }

    /// Set the environment variable to check first (e.g. `"MYAPP_CONFIG"`).
    #[must_use]
    pub fn env_override(mut self, var: &str) -> Self {
        self.env_override = Some(var.to_owned());
        self
    }

    /// Override the format preference order.
    #[must_use]
    pub fn formats(mut self, formats: &[Format]) -> Self {
        self.formats = formats.to_vec();
        self
    }

    /// Return all standard paths that would be checked, in order.
    #[must_use]
    pub fn standard_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let app = &self.app_name;

        for format in &self.formats {
            for ext in format.extensions() {
                // $XDG_CONFIG_HOME/{app}/{app}.{ext}
                if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
                    paths.push(PathBuf::from(&xdg).join(format!("{app}/{app}.{ext}")));
                }
                // $HOME/.config/{app}/{app}.{ext}
                if let Ok(home) = env::var("HOME") {
                    paths.push(PathBuf::from(&home).join(format!(".config/{app}/{app}.{ext}")));
                }
            }
        }

        // Legacy: $HOME/.{app} and $HOME/.{app}.toml
        if let Ok(home) = env::var("HOME") {
            paths.push(PathBuf::from(&home).join(format!(".{app}")));
            paths.push(PathBuf::from(&home).join(format!(".{app}.toml")));
        }

        paths
    }

    /// Discover the config file path.
    ///
    /// Checks the env override first, then scans standard paths.
    /// Returns the first existing path, or an error listing all tried paths.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::NotFound` if no config file exists at any
    /// of the standard locations.
    pub fn discover(&self) -> Result<PathBuf, ShikumiError> {
        // 1. Environment variable override
        if let Some(ref var) = self.env_override {
            if let Ok(path_str) = env::var(var) {
                let path = PathBuf::from(&path_str);
                if path.exists() {
                    return Ok(path);
                }
                warn!(
                    "${var} is set to {}, but the file does not exist. Falling back to defaults.",
                    path.display()
                );
            }
        }

        // 2. Standard XDG / home paths
        let paths = self.standard_paths();
        for path in &paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(ShikumiError::NotFound {
            tried: paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn standard_paths_contains_xdg_and_home() {
        let d = ConfigDiscovery::new("testapp");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        // Should contain .config/testapp/testapp.yaml somewhere
        assert!(path_strs.iter().any(|p| p.contains("testapp/testapp.yaml")));
        assert!(path_strs.iter().any(|p| p.contains("testapp/testapp.toml")));
    }

    #[test]
    fn discover_finds_existing_file() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("testapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("testapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        // Use env override to point to the file
        let var = "SHIKUMI_TEST_DISCOVER";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("testapp")
            .env_override(var)
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_env_override_nonexistent_falls_back() {
        let var = "SHIKUMI_TEST_NOEXIST";
        unsafe { env::set_var(var, "/nonexistent/path.yaml") };

        let result = ConfigDiscovery::new("shikumi_test_noapp")
            .env_override(var)
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_err());
        match result.unwrap_err() {
            ShikumiError::NotFound { tried } => {
                assert!(!tried.is_empty());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn format_yaml_first_by_default() {
        let d = ConfigDiscovery::new("myapp");
        let paths = d.standard_paths();
        // First path should be yaml (XDG or HOME)
        let first_str = paths[0].display().to_string();
        assert!(
            first_str.ends_with(".yaml") || first_str.ends_with(".yml"),
            "expected yaml first, got: {first_str}"
        );
    }

    #[test]
    fn format_toml_only() {
        let d = ConfigDiscovery::new("myapp").formats(&[Format::Toml]);
        let paths = d.standard_paths();
        // No yaml/yml paths (except legacy)
        for p in &paths {
            let s = p.display().to_string();
            if s.contains(".config/") {
                assert!(s.ends_with(".toml"), "expected toml in XDG paths, got: {s}");
            }
        }
    }

    #[test]
    fn discover_returns_not_found_with_tried_paths() {
        let result = ConfigDiscovery::new("shikumi_nonexistent_app_xyz").discover();
        assert!(result.is_err());
        if let Err(ShikumiError::NotFound { tried }) = result {
            assert!(!tried.is_empty());
        }
    }

    #[test]
    fn discover_via_xdg_config_home() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("myxdgapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("myxdgapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::set_var(xdg_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("myxdgapp").discover();

        // Restore previous XDG_CONFIG_HOME
        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => unsafe { env::remove_var(xdg_var) },
        }

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_via_home_dot_config() {
        let dir = TempDir::new().unwrap();
        let dot_config = dir.path().join(".config").join("homeapp");
        fs::create_dir_all(&dot_config).unwrap();
        let config_file = dot_config.join("homeapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let home_var = "HOME";
        let old_home = env::var(home_var).ok();
        // Temporarily unset XDG_CONFIG_HOME to force HOME fallback
        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::remove_var(xdg_var) };
        unsafe { env::set_var(home_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("homeapp").discover();

        // Restore
        match old_home {
            Some(val) => unsafe { env::set_var(home_var, &val) },
            None => unsafe { env::remove_var(home_var) },
        }
        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => {} // was already unset
        }

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_legacy_dot_app() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacyapp");
        fs::write(&legacy_file, "some config").unwrap();

        let home_var = "HOME";
        let old_home = env::var(home_var).ok();
        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::remove_var(xdg_var) };
        unsafe { env::set_var(home_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("legacyapp").discover();

        match old_home {
            Some(val) => unsafe { env::set_var(home_var, &val) },
            None => unsafe { env::remove_var(home_var) },
        }
        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => {}
        }

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_legacy_dot_app_toml() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacytoml.toml");
        fs::write(&legacy_file, "key = \"value\"").unwrap();

        let home_var = "HOME";
        let old_home = env::var(home_var).ok();
        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::remove_var(xdg_var) };
        unsafe { env::set_var(home_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("legacytoml").discover();

        match old_home {
            Some(val) => unsafe { env::set_var(home_var, &val) },
            None => unsafe { env::remove_var(home_var) },
        }
        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => {}
        }

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_env_override_takes_precedence_over_standard() {
        // Create both an env-pointed file and a standard XDG file
        let env_dir = TempDir::new().unwrap();
        let env_file = env_dir.path().join("override.yaml");
        fs::write(&env_file, "source: env_override").unwrap();

        let xdg_dir = TempDir::new().unwrap();
        let xdg_app_dir = xdg_dir.path().join("precapp");
        fs::create_dir_all(&xdg_app_dir).unwrap();
        let xdg_file = xdg_app_dir.join("precapp.yaml");
        fs::write(&xdg_file, "source: xdg").unwrap();

        let var = "SHIKUMI_TEST_PRECEDENCE";
        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::set_var(var, env_file.to_str().unwrap()) };
        unsafe { env::set_var(xdg_var, xdg_dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("precapp")
            .env_override(var)
            .discover();

        unsafe { env::remove_var(var) };
        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => unsafe { env::remove_var(xdg_var) },
        }

        assert!(result.is_ok());
        // Env override should win
        assert_eq!(result.unwrap(), env_file);
    }

    #[test]
    fn standard_paths_yml_extension_included() {
        let d = ConfigDiscovery::new("ymltest");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.contains("ymltest.yml")),
            "expected .yml variant in standard paths"
        );
    }

    #[test]
    fn discover_prefers_yaml_over_yml() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("preftest");
        fs::create_dir_all(&app_dir).unwrap();
        // Create both .yaml and .yml
        let yaml_file = app_dir.join("preftest.yaml");
        let yml_file = app_dir.join("preftest.yml");
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&yml_file, "format: yml").unwrap();

        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::set_var(xdg_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("preftest").discover();

        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => unsafe { env::remove_var(xdg_var) },
        }

        assert!(result.is_ok());
        // .yaml comes before .yml in Format::Yaml extensions
        assert!(
            result.unwrap().display().to_string().ends_with(".yaml"),
            "expected .yaml to be preferred over .yml"
        );
    }

    #[test]
    fn discover_prefers_yaml_over_toml() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("fmtpref");
        fs::create_dir_all(&app_dir).unwrap();
        let yaml_file = app_dir.join("fmtpref.yaml");
        let toml_file = app_dir.join("fmtpref.toml");
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&toml_file, "format = \"toml\"").unwrap();

        let xdg_var = "XDG_CONFIG_HOME";
        let old_xdg = env::var(xdg_var).ok();
        unsafe { env::set_var(xdg_var, dir.path().to_str().unwrap()) };

        let result = ConfigDiscovery::new("fmtpref").discover();

        match old_xdg {
            Some(val) => unsafe { env::set_var(xdg_var, &val) },
            None => unsafe { env::remove_var(xdg_var) },
        }

        assert!(result.is_ok());
        assert!(
            result.unwrap().display().to_string().ends_with(".yaml"),
            "expected yaml to be preferred over toml by default"
        );
    }

    #[test]
    fn format_toml_before_yaml() {
        let d = ConfigDiscovery::new("revapp").formats(&[Format::Toml, Format::Yaml]);
        let paths = d.standard_paths();
        // Find first .config path; it should be .toml
        let first_config_path = paths
            .iter()
            .find(|p| p.display().to_string().contains(".config/"))
            .expect("should have .config paths");
        assert!(
            first_config_path.display().to_string().ends_with(".toml"),
            "expected toml first when Format::Toml is listed first"
        );
    }

    #[test]
    fn standard_paths_include_legacy_entries() {
        let d = ConfigDiscovery::new("legapp");
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".legapp")),
            "expected legacy $HOME/.legapp path"
        );
        assert!(
            path_strs.iter().any(|p| p.ends_with(".legapp.toml")),
            "expected legacy $HOME/.legapp.toml path"
        );
    }

    #[test]
    fn discover_no_env_override_set() {
        // When env_override var is specified but not set in the environment,
        // discovery should fall through to standard paths
        let result = ConfigDiscovery::new("shikumi_test_unset_env_xyz")
            .env_override("SHIKUMI_UNSET_VAR_XYZ")
            .discover();
        // Should fail (no standard files exist for this app name)
        assert!(result.is_err());
    }

    #[test]
    fn formats_empty_still_has_legacy_paths() {
        let d = ConfigDiscovery::new("emptyformats").formats(&[]);
        let paths = d.standard_paths();
        // Even with no formats, legacy paths should still appear
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".emptyformats")),
            "expected legacy path even with empty formats"
        );
    }

    #[test]
    fn format_extensions_yaml() {
        let exts = Format::Yaml.extensions();
        assert_eq!(exts, &["yaml", "yml"]);
    }

    #[test]
    fn format_extensions_toml() {
        let exts = Format::Toml.extensions();
        assert_eq!(exts, &["toml"]);
    }

    #[test]
    fn format_eq_and_clone() {
        let a = Format::Yaml;
        let b = a;
        assert_eq!(a, b);

        let c = Format::Toml;
        assert_ne!(a, c);
    }

    #[test]
    fn not_found_error_lists_all_tried() {
        let result = ConfigDiscovery::new("shikumi_trial_xyz")
            .formats(&[Format::Yaml, Format::Toml])
            .discover();
        if let Err(ShikumiError::NotFound { tried }) = result {
            // Should have XDG yaml, XDG yml, HOME yaml, HOME yml,
            // XDG toml, HOME toml, legacy x2 = multiple paths
            assert!(
                tried.len() >= 4,
                "expected at least 4 tried paths, got {}",
                tried.len()
            );
        } else {
            panic!("expected NotFound error");
        }
    }
}

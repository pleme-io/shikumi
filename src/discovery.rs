//! Config file discovery — parameterized XDG path scanning.
//!
//! Extracted from karakuri's `CONFIGURATION_FILE` `LazyLock`. Generalized
//! so any app can use the same discovery logic by providing its name.
//!
//! Supports both single-file discovery (`discover()`) and hierarchical
//! multi-file discovery with merge (`discover_all()`).

use std::env;
use std::path::{Path, PathBuf};

use tracing::warn;

use crate::error::ShikumiError;

/// Supported config file formats, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// YAML format (`.yaml` and `.yml` extensions).
    Yaml,
    /// TOML format (`.toml` extension).
    Toml,
}

impl Format {
    /// Returns the file extensions associated with this format.
    #[must_use]
    pub fn extensions(self) -> &'static [&'static str] {
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
///
/// When `hierarchical()` is enabled, `discover_all()` returns all config
/// files found across multiple layers (system, user, repo-local), plus
/// partial configs (`.{app}-*.yaml`), in merge order (lowest priority first).
pub struct ConfigDiscovery {
    app_name: String,
    env_override: Option<String>,
    formats: Vec<Format>,
    hierarchical: bool,
    start_dir: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    home_dir: Option<PathBuf>,
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
            hierarchical: false,
            start_dir: None,
            xdg_config_home: None,
            home_dir: None,
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
        let xdg = self.resolve_xdg_config_home();
        let home = self.resolve_home();

        for format in &self.formats {
            for ext in format.extensions() {
                if let Some(ref xdg) = xdg {
                    paths.push(xdg.join(format!("{app}/{app}.{ext}")));
                }
                if let Some(ref home) = home {
                    paths.push(home.join(format!(".config/{app}/{app}.{ext}")));
                }
            }
        }

        if let Some(ref home) = home {
            paths.push(home.join(format!(".{app}")));
            paths.push(home.join(format!(".{app}.toml")));
        }

        paths
    }

    /// Enable hierarchical search with merge.
    ///
    /// When enabled, `discover_all()` searches multiple layers in order:
    /// 1. `/etc/{app}/{app}.yaml` (system-wide, lowest priority)
    /// 2. `~/.config/{app}/{app}.yaml` (user-level, via XDG)
    /// 3. Walk up from CWD looking for `.{app}.yaml` at each directory level
    /// 4. Partial configs: `.{app}-*.yaml` files in same directories, merged alphabetically
    #[must_use]
    pub fn hierarchical(mut self) -> Self {
        self.hierarchical = true;
        self
    }

    /// Override the starting directory for hierarchical walk-up discovery.
    ///
    /// By default, hierarchical discovery walks up from the current working
    /// directory. Use this to start from an explicit directory instead,
    /// which is also useful for deterministic testing.
    #[must_use]
    pub fn start_dir(mut self, dir: &Path) -> Self {
        self.start_dir = Some(dir.to_owned());
        self
    }

    /// Override `$XDG_CONFIG_HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the
    /// `XDG_CONFIG_HOME` environment variable. Useful for testing.
    #[must_use]
    pub fn xdg_config_home(mut self, dir: &Path) -> Self {
        self.xdg_config_home = Some(dir.to_owned());
        self
    }

    /// Override `$HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the `HOME`
    /// environment variable. Useful for testing.
    #[must_use]
    pub fn home_dir(mut self, dir: &Path) -> Self {
        self.home_dir = Some(dir.to_owned());
        self
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
        if let Some(ref var) = self.env_override
            && let Ok(path_str) = env::var(var)
        {
            let path = PathBuf::from(&path_str);
            if path.exists() {
                return Ok(path);
            }
            warn!(
                "${var} is set to {}, but the file does not exist. Falling back to defaults.",
                path.display()
            );
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

    /// Discover all config files in the hierarchy and return merged paths.
    ///
    /// Returns paths in merge order (lowest priority first, highest priority last).
    /// When `hierarchical()` is enabled, searches:
    /// 1. `/etc/{app}/{app}.yaml` + partials (system-wide)
    /// 2. `~/.config/{app}/{app}.yaml` + partials (user-level)
    /// 3. Walk up from CWD to root: `.{app}.yaml` + partials at each level
    ///    (root = lowest priority, CWD = highest priority)
    ///
    /// Missing files are silently skipped. Only existing files are returned.
    ///
    /// If `hierarchical()` was not called, this behaves like `discover()`
    /// but returns all existing standard paths instead of just the first.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::NotFound` if no config files exist at any
    /// of the searched locations.
    pub fn discover_all(&self) -> Result<Vec<PathBuf>, ShikumiError> {
        let mut found: Vec<PathBuf> = Vec::new();
        let app = &self.app_name;

        if self.hierarchical {
            // Layer 1: /etc/{app}/{app}.yaml (system-wide, lowest priority)
            self.collect_dir_configs(&PathBuf::from(format!("/etc/{app}")), app, &mut found);

            // Layer 2: ~/.config/{app}/{app}.yaml (user-level)
            if let Some(config_dir) = self.user_config_dir() {
                self.collect_dir_configs(&config_dir.join(app), app, &mut found);
            }

            let start = self
                .start_dir
                .clone()
                .or_else(|| env::current_dir().ok());

            if let Some(cwd) = start {
                let mut ancestors: Vec<PathBuf> = Vec::new();
                let mut current = Some(cwd.as_path());
                while let Some(dir) = current {
                    ancestors.push(dir.to_path_buf());
                    current = dir.parent();
                }
                ancestors.reverse();

                for dir in &ancestors {
                    self.collect_walkup_configs(dir, app, &mut found);
                }
            }
        } else {
            // Non-hierarchical: return all existing standard paths
            if let Some(ref var) = self.env_override
                && let Ok(path_str) = env::var(var)
            {
                let path = PathBuf::from(&path_str);
                if path.exists() {
                    found.push(path);
                }
            }

            for path in self.standard_paths() {
                if path.exists() {
                    found.push(path);
                }
            }
        }

        if found.is_empty() {
            Err(ShikumiError::NotFound {
                tried: if self.hierarchical {
                    vec![
                        PathBuf::from(format!("/etc/{app}/{app}.yaml")),
                        PathBuf::from(format!("~/.config/{app}/{app}.yaml")),
                        PathBuf::from(format!(".{app}.yaml")),
                    ]
                } else {
                    self.standard_paths()
                },
            })
        } else {
            Ok(found)
        }
    }

    /// Resolve `XDG_CONFIG_HOME`, preferring the builder override.
    fn resolve_xdg_config_home(&self) -> Option<PathBuf> {
        if let Some(ref dir) = self.xdg_config_home {
            return Some(dir.clone());
        }
        env::var("XDG_CONFIG_HOME").ok().map(PathBuf::from)
    }

    /// Resolve `HOME`, preferring the builder override.
    fn resolve_home(&self) -> Option<PathBuf> {
        if let Some(ref dir) = self.home_dir {
            return Some(dir.clone());
        }
        env::var("HOME").ok().map(PathBuf::from)
    }

    /// Resolve the user config directory.
    ///
    /// Prefers `$XDG_CONFIG_HOME`, falls back to `$HOME/.config`.
    fn user_config_dir(&self) -> Option<PathBuf> {
        if let Some(xdg) = self.resolve_xdg_config_home() {
            return Some(xdg);
        }
        self.resolve_home().map(|home| home.join(".config"))
    }

    /// Collect main config + partials from a structured config directory.
    ///
    /// Looks for `{dir}/{app}.yaml` and `{dir}/{app}-*.yaml` partials.
    fn collect_dir_configs(&self, dir: &Path, app: &str, found: &mut Vec<PathBuf>) {
        for format in &self.formats {
            for ext in format.extensions() {
                let main_path = dir.join(format!("{app}.{ext}"));
                if main_path.exists() {
                    found.push(main_path);
                }
            }
        }
        self.collect_partials(dir, app, false, found);
    }

    /// Collect walk-up configs from a directory (dot-prefixed).
    ///
    /// Looks for `.{app}.yaml` and `.{app}-*.yaml` partials.
    fn collect_walkup_configs(&self, dir: &Path, app: &str, found: &mut Vec<PathBuf>) {
        for format in &self.formats {
            for ext in format.extensions() {
                let main_path = dir.join(format!(".{app}.{ext}"));
                if main_path.exists() {
                    found.push(main_path);
                }
            }
        }
        self.collect_partials(dir, app, true, found);
    }

    /// Collect partial configs matching `[.]{app}-*.{ext}` in a directory.
    fn collect_partials(
        &self,
        dir: &Path,
        app: &str,
        dot_prefix: bool,
        found: &mut Vec<PathBuf>,
    ) {
        if !dir.is_dir() {
            return;
        }
        let mut partials: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if self.is_partial_match(&name_str, app, dot_prefix) {
                    partials.push(entry.path());
                }
            }
        }
        partials.sort();
        found.extend(partials);
    }

    /// Check if a filename matches the partial pattern `[.]{app}-*.{ext}`.
    fn is_partial_match(&self, name: &str, app: &str, dot_prefix: bool) -> bool {
        let prefix = if dot_prefix {
            format!(".{app}-")
        } else {
            format!("{app}-")
        };
        if !name.starts_with(&prefix) {
            return false;
        }
        // Must end with a known extension
        for format in &self.formats {
            for ext in format.extensions() {
                if name.ends_with(&format!(".{ext}")) {
                    return true;
                }
            }
        }
        false
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

        let result = ConfigDiscovery::new("myxdgapp")
            .xdg_config_home(dir.path())
            .discover();

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

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("homeapp")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_legacy_dot_app() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacyapp");
        fs::write(&legacy_file, "some config").unwrap();

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("legacyapp")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_legacy_dot_app_toml() {
        let dir = TempDir::new().unwrap();
        let legacy_file = dir.path().join(".legacytoml.toml");
        fs::write(&legacy_file, "key = \"value\"").unwrap();

        let nonexistent = dir.path().join("nonexistent_xdg");
        let result = ConfigDiscovery::new("legacytoml")
            .xdg_config_home(&nonexistent)
            .home_dir(dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), legacy_file);
    }

    #[test]
    fn discover_env_override_takes_precedence_over_standard() {
        let env_dir = TempDir::new().unwrap();
        let env_file = env_dir.path().join("override.yaml");
        fs::write(&env_file, "source: env_override").unwrap();

        let xdg_dir = TempDir::new().unwrap();
        let xdg_app_dir = xdg_dir.path().join("precapp");
        fs::create_dir_all(&xdg_app_dir).unwrap();
        let xdg_file = xdg_app_dir.join("precapp.yaml");
        fs::write(&xdg_file, "source: xdg").unwrap();

        let var = "SHIKUMI_TEST_PRECEDENCE";
        unsafe { env::set_var(var, env_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("precapp")
            .env_override(var)
            .xdg_config_home(xdg_dir.path())
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
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
        let yaml_file = app_dir.join("preftest.yaml");
        let yml_file = app_dir.join("preftest.yml");
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&yml_file, "format: yml").unwrap();

        let result = ConfigDiscovery::new("preftest")
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
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

        let result = ConfigDiscovery::new("fmtpref")
            .xdg_config_home(dir.path())
            .discover();

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

    // ---- Hierarchical discovery tests ----

    #[test]
    fn hierarchical_builder_returns_self() {
        let d = ConfigDiscovery::new("htest").hierarchical();
        assert!(d.hierarchical);
    }

    #[test]
    fn discover_all_non_hierarchical_returns_existing_standard_paths() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("datest");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("datest.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_DISC_ALL";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("datest")
            .env_override(var)
            .discover_all();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(!paths.is_empty());
        assert!(paths.contains(&config_file));
    }

    #[test]
    fn discover_all_non_hierarchical_missing_returns_error() {
        let result = ConfigDiscovery::new("shikumi_disc_all_noexist_xyz")
            .discover_all();
        assert!(result.is_err());
    }

    #[test]
    fn hierarchical_finds_xdg_config() {
        let dir = TempDir::new().unwrap();
        let app = "hierxdg";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "source: xdg").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .hierarchical()
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &config_file),
            "expected XDG config in results, got: {paths:?}"
        );
    }

    #[test]
    fn hierarchical_walkup_finds_dotfile_in_cwd() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hierwalk";
        let dotfile = dir_path.join(format!(".{app}.yaml"));
        fs::write(&dotfile, "source: cwd").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &dotfile),
            "expected CWD dotfile in results, got: {paths:?}"
        );
    }

    #[test]
    fn hierarchical_merge_order_cwd_wins_over_parent() {
        let parent = TempDir::new().unwrap();
        let parent_path = parent.path().canonicalize().unwrap();
        let child = parent_path.join("child");
        fs::create_dir_all(&child).unwrap();

        let app = "hiermerge";
        let parent_file = parent_path.join(format!(".{app}.yaml"));
        let child_file = child.join(format!(".{app}.yaml"));
        fs::write(&parent_file, "level: parent").unwrap();
        fs::write(&child_file, "level: child").unwrap();

        let nonexistent_xdg = parent_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&child)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&parent_file), "should contain parent config");
        assert!(paths.contains(&child_file), "should contain child config");
        let parent_idx = paths.iter().position(|p| p == &parent_file).unwrap();
        let child_idx = paths.iter().position(|p| p == &child_file).unwrap();
        assert!(
            parent_idx < child_idx,
            "parent ({parent_idx}) should come before child ({child_idx}) in merge order"
        );
    }

    #[test]
    fn hierarchical_partials_merge_alphabetically() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hierpart";

        let partial_b = dir_path.join(format!(".{app}-02-beta.yaml"));
        let partial_a = dir_path.join(format!(".{app}-01-alpha.yaml"));
        fs::write(&partial_a, "alpha: true").unwrap();
        fs::write(&partial_b, "beta: true").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&partial_a), "should contain alpha partial");
        assert!(paths.contains(&partial_b), "should contain beta partial");
        let a_idx = paths.iter().position(|p| p == &partial_a).unwrap();
        let b_idx = paths.iter().position(|p| p == &partial_b).unwrap();
        assert!(
            a_idx < b_idx,
            "alpha ({a_idx}) should come before beta ({b_idx}) in alphabetical order"
        );
    }

    #[test]
    fn hierarchical_main_config_before_partials_in_same_dir() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermainpart";

        let main_file = dir_path.join(format!(".{app}.yaml"));
        let partial = dir_path.join(format!(".{app}-01-extra.yaml"));
        fs::write(&main_file, "main: true").unwrap();
        fs::write(&partial, "extra: true").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        let main_idx = paths.iter().position(|p| p == &main_file).unwrap();
        let partial_idx = paths.iter().position(|p| p == &partial).unwrap();
        assert!(
            main_idx < partial_idx,
            "main config ({main_idx}) should come before partial ({partial_idx})"
        );
    }

    #[test]
    fn hierarchical_missing_files_silently_skipped() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermiss";

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_err());
        match result.unwrap_err() {
            ShikumiError::NotFound { tried } => {
                assert!(!tried.is_empty());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn hierarchical_xdg_partials_in_structured_dir() {
        let dir = TempDir::new().unwrap();
        let app = "hierxdgpart";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();

        let main_file = config_dir.join(format!("{app}.yaml"));
        let partial_a = config_dir.join(format!("{app}-01-db.yaml"));
        let partial_b = config_dir.join(format!("{app}-02-cache.yaml"));
        fs::write(&main_file, "app: base").unwrap();
        fs::write(&partial_a, "db: postgres").unwrap();
        fs::write(&partial_b, "cache: redis").unwrap();

        let empty_dir = TempDir::new().unwrap();
        let empty_path = empty_dir.path().canonicalize().unwrap();

        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml])
            .xdg_config_home(dir.path())
            .hierarchical()
            .start_dir(&empty_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&main_file), "should contain main XDG config");
        assert!(paths.contains(&partial_a), "should contain XDG partial a");
        assert!(paths.contains(&partial_b), "should contain XDG partial b");

        let main_idx = paths.iter().position(|p| p == &main_file).unwrap();
        let a_idx = paths.iter().position(|p| p == &partial_a).unwrap();
        let b_idx = paths.iter().position(|p| p == &partial_b).unwrap();
        assert!(main_idx < a_idx, "main before partial a");
        assert!(a_idx < b_idx, "partial a before partial b");
    }

    #[test]
    fn discover_still_works_after_hierarchical() {
        // Ensure the original discover() method is unaffected by hierarchical flag
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("backcompat");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("backcompat.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_BACKCOMPAT";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        // discover() should still work exactly as before
        let result = ConfigDiscovery::new("backcompat")
            .env_override(var)
            .hierarchical()
            .discover();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn is_partial_match_correct() {
        let d = ConfigDiscovery::new("myapp");

        // Dot-prefixed partials
        assert!(d.is_partial_match(".myapp-01-db.yaml", "myapp", true));
        assert!(d.is_partial_match(".myapp-extra.yml", "myapp", true));
        assert!(d.is_partial_match(".myapp-config.toml", "myapp", true));
        assert!(!d.is_partial_match(".myapp.yaml", "myapp", true)); // main, not partial
        assert!(!d.is_partial_match("myapp-01.yaml", "myapp", true)); // no dot prefix
        assert!(!d.is_partial_match(".myapp-01.txt", "myapp", true)); // wrong extension

        // Non-dot-prefixed partials
        assert!(d.is_partial_match("myapp-01-db.yaml", "myapp", false));
        assert!(d.is_partial_match("myapp-extra.toml", "myapp", false));
        assert!(!d.is_partial_match(".myapp-01.yaml", "myapp", false)); // has dot prefix
        assert!(!d.is_partial_match("myapp.yaml", "myapp", false)); // main, not partial
    }

    #[test]
    fn hierarchical_discover_all_returns_not_found_with_representative_paths() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiernf";

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_err());
        if let Err(ShikumiError::NotFound { tried }) = result {
            assert!(!tried.is_empty(), "should list representative paths");
        }
    }
}

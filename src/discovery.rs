//! Config file discovery — parameterized XDG path scanning.
//!
//! Extracted from karakuri's `CONFIGURATION_FILE` `LazyLock`. Generalized
//! so any app can use the same discovery logic by providing its name.
//!
//! Supports both single-file discovery (`discover()`) and hierarchical
//! multi-file discovery with merge (`discover_all()`).

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use tracing::warn;

use crate::error::ShikumiError;

/// Supported config file formats, in preference order.
///
/// **Tatara-lisp is a first-class configuration format** alongside YAML, TOML,
/// and Nix. Per the pleme-io tatara-lisp ecosystem standard, every configurable
/// application supports all four natively and auto-detects by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Format {
    /// YAML format (`.yaml` and `.yml` extensions).
    #[default]
    Yaml,
    /// TOML format (`.toml` extension).
    Toml,
    /// Tatara-lisp format (`.lisp` / `.lsp` / `.el` extensions).
    ///
    /// The first top-level `(defX …)` form's kwargs become the config dict;
    /// nested kwargs lists become nested maps. Bare symbols → strings;
    /// nil → null. See [`crate::lisp_provider`] for the full mapping.
    Lisp,
    /// Nix format (`.nix` extension).
    ///
    /// Evaluated via `nix eval --file <path> --json` and parsed as JSON.
    /// The file must evaluate to an attrset; its attrs become the config.
    Nix,
}

impl Format {
    /// Every [`Format`] variant, in declaration order.
    ///
    /// The closed list of formats shikumi understands. Iterate to
    /// enumerate the format space without listing variants by hand —
    /// e.g. tests that must round-trip every format, or attribution
    /// resolvers that try every shikumi-built provider's metadata-name
    /// shape in turn (see [`Self::strip_metadata_name`]).
    ///
    /// Adding a new variant means extending this slice in lockstep with
    /// the variant itself; the compiler enforces nothing here, so the
    /// `format_all_covers_every_variant` test pins the contract by
    /// matching every variant.
    pub const ALL: &'static [Format] = &[Self::Yaml, Self::Toml, Self::Lisp, Self::Nix];

    /// Returns the file extensions associated with this format.
    #[must_use]
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Toml => &["toml"],
            Self::Lisp => &["lisp", "lsp", "el"],
            Self::Nix => &["nix"],
        }
    }

    /// Infer format from a file extension string.
    ///
    /// Returns `None` for unrecognized extensions.
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            "lisp" | "lsp" | "el" => Some(Self::Lisp),
            "nix" => Some(Self::Nix),
            _ => None,
        }
    }

    /// Whether this format is loaded by a shikumi-built figment provider
    /// (as opposed to delegating to one of figment's built-in providers).
    ///
    /// `true` for [`Format::Lisp`] (loaded by [`crate::LispProvider`])
    /// and [`Format::Nix`] (loaded by [`crate::NixProvider`]); these
    /// providers tag per-value attribution via
    /// `figment::Metadata::name = "<format>: <path>"` (see
    /// [`Self::metadata_name`]).
    ///
    /// `false` for [`Format::Yaml`] and [`Format::Toml`], which
    /// [`crate::ProviderChain::with_file`] hands off to
    /// `figment::providers::Yaml` / `figment::providers::Toml`. Those
    /// providers tag per-value attribution via
    /// `figment::Metadata::source = figment::Source::File(_)` instead,
    /// so [`crate::ShikumiError::failing_source`] resolves them by path
    /// equality rather than by metadata-name prefix.
    #[must_use]
    pub fn has_shikumi_provider(self) -> bool {
        match self {
            Self::Lisp | Self::Nix => true,
            Self::Yaml | Self::Toml => false,
        }
    }

    /// Canonical `figment::Metadata::name` shape used by shikumi-built
    /// providers for per-value attribution: `"<format>: <path>"` (e.g.
    /// `"lisp: /home/u/.config/app/app.lisp"`,
    /// `"nix: /etc/app/app.nix"`).
    ///
    /// The `<format>` token is the [`fmt::Display`] form of the variant,
    /// so [`Format::Display`] is the single source of truth for the
    /// token shape on both sides of attribution: providers emit it via
    /// this constructor, and [`Self::strip_metadata_name`] inverts it
    /// for resolution back to a [`crate::ConfigSource`].
    ///
    /// Defined for every [`Format`] variant — including those for which
    /// [`Self::has_shikumi_provider`] returns `false` — so the morphism
    /// is total. Callers that only care about shikumi-built emissions
    /// should gate on `has_shikumi_provider` first; resolvers that need
    /// to invert can use [`Self::strip_metadata_name`] which already
    /// filters to the shikumi-provider subset.
    #[must_use]
    pub fn metadata_name(self, path: &Path) -> String {
        format!("{self}: {}", path.display())
    }

    /// Inverse of [`Self::metadata_name`]: try to recognize `name` as a
    /// shikumi-built provider's metadata-name and recover the
    /// `(format, path_str)` pair.
    ///
    /// Iterates [`Self::ALL`] in declaration order, restricted to
    /// variants for which [`Self::has_shikumi_provider`] returns `true`,
    /// and tries the `"<format>: "` prefix from [`Self::metadata_name`]
    /// against `name`. The first matching variant wins; the trailing
    /// substring is returned by reference into `name` so callers don't
    /// allocate.
    ///
    /// Returns `None` for `figment::Metadata::name` values produced by
    /// figment's built-in YAML/TOML providers (which use `Source::File`
    /// instead of name-based attribution), for unrelated metadata names,
    /// and for the empty string. Used by
    /// [`crate::ShikumiError::failing_source`] to map figment metadata
    /// back to a [`crate::ConfigSource`] in the recorded chain.
    #[must_use]
    pub fn strip_metadata_name(name: &str) -> Option<(Self, &str)> {
        Self::ALL
            .iter()
            .filter(|f| f.has_shikumi_provider())
            .find_map(|f| {
                let prefix = format!("{f}: ");
                name.strip_prefix(&prefix).map(|rest| (*f, rest))
            })
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml => f.write_str("yaml"),
            Self::Toml => f.write_str("toml"),
            Self::Lisp => f.write_str("lisp"),
            Self::Nix => f.write_str("nix"),
        }
    }
}

impl TryFrom<&Path> for Format {
    type Error = ShikumiError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        path.extension()
            .and_then(|e| e.to_str())
            .and_then(Self::from_extension)
            .ok_or_else(|| {
                ShikumiError::Parse(format!(
                    "cannot determine config format from path: {}",
                    path.display()
                ))
            })
    }
}

impl FromStr for Format {
    type Err = ShikumiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Ok(Self::Yaml),
            "toml" => Ok(Self::Toml),
            "lisp" | "lsp" | "el" => Ok(Self::Lisp),
            "nix" => Ok(Self::Nix),
            _ => Err(ShikumiError::Parse(format!("unknown config format: {s}"))),
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
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
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
    pub fn env_override(mut self, var: impl Into<String>) -> Self {
        self.env_override = Some(var.into());
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

        for ext in self.configured_extensions() {
            if let Some(ref xdg) = xdg {
                paths.push(xdg.join(format!("{app}/{app}.{ext}")));
            }
            if let Some(ref home) = home {
                paths.push(home.join(format!(".config/{app}/{app}.{ext}")));
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
    pub fn start_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.start_dir = Some(dir.into());
        self
    }

    /// Override `$XDG_CONFIG_HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the
    /// `XDG_CONFIG_HOME` environment variable. Useful for testing.
    #[must_use]
    pub fn xdg_config_home(mut self, dir: impl Into<PathBuf>) -> Self {
        self.xdg_config_home = Some(dir.into());
        self
    }

    /// Override `$HOME` for path resolution.
    ///
    /// When set, this value is used instead of reading the `HOME`
    /// environment variable. Useful for testing.
    #[must_use]
    pub fn home_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.home_dir = Some(dir.into());
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

        Err(ShikumiError::NotFound { tried: paths })
    }

    /// Discover the config file, or return a default path if none exists.
    ///
    /// Unlike [`discover()`](Self::discover), this never returns `NotFound`.
    /// Useful when you want to create a config at the preferred location.
    #[must_use]
    pub fn discover_or_default(&self) -> PathBuf {
        self.discover().unwrap_or_else(|_| {
            self.standard_paths()
                .into_iter()
                .next()
                .unwrap_or_else(|| PathBuf::from(format!(".{}.yaml", self.app_name)))
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
            self.collect_configs(
                &PathBuf::from(format!("/etc/{app}")),
                app,
                NameStyle::Bare,
                &mut found,
            );

            // Layer 2: ~/.config/{app}/{app}.yaml (user-level)
            if let Some(config_dir) = self.user_config_dir() {
                self.collect_configs(&config_dir.join(app), app, NameStyle::Bare, &mut found);
            }

            let start = self.start_dir.clone().or_else(|| env::current_dir().ok());

            if let Some(cwd) = start {
                let mut ancestors: Vec<PathBuf> = Vec::new();
                let mut current = Some(cwd.as_path());
                while let Some(dir) = current {
                    ancestors.push(dir.to_path_buf());
                    current = dir.parent();
                }
                ancestors.reverse();

                for dir in &ancestors {
                    self.collect_configs(dir, app, NameStyle::Dotfile, &mut found);
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

    /// Collect main config + partials from a directory using the given naming style.
    ///
    /// `Bare`: `{dir}/{app}.{ext}` and `{dir}/{app}-*.{ext}` partials.
    /// `Dotfile`: `{dir}/.{app}.{ext}` and `{dir}/.{app}-*.{ext}` partials.
    fn collect_configs(&self, dir: &Path, app: &str, style: NameStyle, found: &mut Vec<PathBuf>) {
        for ext in self.configured_extensions() {
            let main_path = dir.join(style.main_filename(app, ext));
            if main_path.exists() {
                found.push(main_path);
            }
        }
        self.collect_partials(dir, app, style, found);
    }

    /// Collect partial configs matching `[.]{app}-*.{ext}` in a directory.
    fn collect_partials(&self, dir: &Path, app: &str, style: NameStyle, found: &mut Vec<PathBuf>) {
        if !dir.is_dir() {
            return;
        }
        let mut partials: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if self.is_partial_match(&name_str, app, style) {
                    partials.push(entry.path());
                }
            }
        }
        partials.sort();
        found.extend(partials);
    }

    /// Check if a filename matches the partial pattern `[.]{app}-*.{ext}`.
    fn is_partial_match(&self, name: &str, app: &str, style: NameStyle) -> bool {
        name.starts_with(&style.partial_prefix(app))
            && self
                .configured_extensions()
                .any(|ext| name.ends_with(&format!(".{ext}")))
    }

    /// Iterator over every file extension this discovery honors, in the
    /// preference order set by [`Self::formats`].
    ///
    /// The flat cartesian product of `self.formats` × `Format::extensions()`:
    /// the default `[Yaml, Toml]` yields `["yaml", "yml", "toml"]`; an
    /// explicit `formats(&[Format::Toml, Format::Yaml])` flips to
    /// `["toml", "yaml", "yml"]`. Empty `formats` yields zero items.
    ///
    /// One typed primitive owns the (formats × extensions) shape that
    /// [`Self::standard_paths`], [`Self::collect_configs`], and
    /// [`Self::is_partial_match`] previously open-coded as a nested
    /// `for format in &self.formats { for ext in format.extensions() }`
    /// loop. Adding a new [`Format`] variant (e.g. `Json`, `Hocon`) means
    /// extending [`Format::extensions`] in one place — every consumer
    /// here observes the new extension automatically, and the loop body
    /// at each consumer stays at one level of nesting.
    fn configured_extensions(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.formats
            .iter()
            .flat_map(|f| f.extensions().iter().copied())
    }
}

/// How config files are named within a directory.
///
/// Each variant is a typed morphism `(app, ext) → filename`. Adding a new
/// naming convention (e.g. an `App/config.{ext}` subdirectory style, or a
/// `{app}.{environment}.{ext}` overlay style) means adding a variant — the
/// compiler then forces every call site (main-file construction, partial
/// prefix construction, future filename queries) to handle it.
///
/// This replaces a `dot_prefix: bool` flag previously threaded through
/// `collect_*_configs` / `collect_partials` / `is_partial_match`. The bool
/// was load-bearing — it controlled both the main filename and the partial
/// prefix in lockstep — but its meaning was implicit in every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameStyle {
    /// `{app}.{ext}` and `{app}-*.{ext}` — used in `/etc/{app}/`,
    /// `~/.config/{app}/`, and any structured config directory.
    Bare,
    /// `.{app}.{ext}` and `.{app}-*.{ext}` — used during CWD walk-up
    /// discovery, where dot-prefixed files keep configs out of `ls`.
    Dotfile,
}

impl NameStyle {
    /// The main config filename for this style: `{prefix}{app}.{ext}`.
    fn main_filename(self, app: &str, ext: &str) -> String {
        match self {
            Self::Bare => format!("{app}.{ext}"),
            Self::Dotfile => format!(".{app}.{ext}"),
        }
    }

    /// The partial-config filename prefix for this style: `{prefix}{app}-`.
    ///
    /// A partial filename is anything starting with this prefix and ending
    /// with a recognized config extension.
    fn partial_prefix(self, app: &str) -> String {
        match self {
            Self::Bare => format!("{app}-"),
            Self::Dotfile => format!(".{app}-"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn format_display_round_trip() {
        for fmt in [Format::Yaml, Format::Toml] {
            let s = fmt.to_string();
            let parsed: Format = s.parse().unwrap();
            assert_eq!(fmt, parsed);
        }
    }

    #[test]
    fn format_from_str_case_insensitive() {
        assert_eq!("YAML".parse::<Format>().unwrap(), Format::Yaml);
        assert_eq!("yml".parse::<Format>().unwrap(), Format::Yaml);
        assert_eq!("TOML".parse::<Format>().unwrap(), Format::Toml);
        assert!("json".parse::<Format>().is_err());
    }

    #[test]
    fn format_default_is_yaml() {
        assert_eq!(Format::default(), Format::Yaml);
    }

    #[test]
    fn format_from_extension() {
        assert_eq!(Format::from_extension("yaml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("yml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("toml"), Some(Format::Toml));
        assert_eq!(Format::from_extension("json"), None);
        assert_eq!(Format::from_extension(""), None);
    }

    #[test]
    fn format_try_from_path() {
        assert_eq!(
            Format::try_from(Path::new("config.yaml")).unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::try_from(Path::new("config.yml")).unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::try_from(Path::new("config.toml")).unwrap(),
            Format::Toml
        );
        assert!(Format::try_from(Path::new("config.json")).is_err());
        assert!(Format::try_from(Path::new("no_extension")).is_err());
    }

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

        let result = ConfigDiscovery::new("testapp").env_override(var).discover();

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
    fn discover_or_default_returns_first_standard_path() {
        let d = ConfigDiscovery::new("shikumi_fallback_xyz");
        let path = d.discover_or_default();
        let s = path.display().to_string();
        assert!(
            s.contains("shikumi_fallback_xyz"),
            "default path should contain app name, got: {s}"
        );
    }

    #[test]
    fn discover_or_default_returns_existing_when_found() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().join("fallbackapp");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("fallbackapp.yaml");
        fs::write(&config_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_FALLBACK";
        unsafe { env::set_var(var, config_file.to_str().unwrap()) };

        let path = ConfigDiscovery::new("fallbackapp")
            .env_override(var)
            .discover_or_default();

        unsafe { env::remove_var(var) };

        assert_eq!(path, config_file);
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
        let result = ConfigDiscovery::new("shikumi_disc_all_noexist_xyz").discover_all();
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
        assert!(d.is_partial_match(".myapp-01-db.yaml", "myapp", NameStyle::Dotfile));
        assert!(d.is_partial_match(".myapp-extra.yml", "myapp", NameStyle::Dotfile));
        assert!(d.is_partial_match(".myapp-config.toml", "myapp", NameStyle::Dotfile));
        assert!(!d.is_partial_match(".myapp.yaml", "myapp", NameStyle::Dotfile)); // main, not partial
        assert!(!d.is_partial_match("myapp-01.yaml", "myapp", NameStyle::Dotfile)); // no dot prefix
        assert!(!d.is_partial_match(".myapp-01.txt", "myapp", NameStyle::Dotfile)); // wrong extension

        // Non-dot-prefixed partials
        assert!(d.is_partial_match("myapp-01-db.yaml", "myapp", NameStyle::Bare));
        assert!(d.is_partial_match("myapp-extra.toml", "myapp", NameStyle::Bare));
        assert!(!d.is_partial_match(".myapp-01.yaml", "myapp", NameStyle::Bare)); // has dot prefix
        assert!(!d.is_partial_match("myapp.yaml", "myapp", NameStyle::Bare)); // main, not partial
    }

    // ---- NameStyle typed-primitive tests ----

    #[test]
    fn name_style_bare_main_filename() {
        assert_eq!(NameStyle::Bare.main_filename("myapp", "yaml"), "myapp.yaml");
        assert_eq!(NameStyle::Bare.main_filename("myapp", "yml"), "myapp.yml");
        assert_eq!(NameStyle::Bare.main_filename("myapp", "toml"), "myapp.toml");
        assert_eq!(NameStyle::Bare.main_filename("a", "yaml"), "a.yaml");
    }

    #[test]
    fn name_style_dotfile_main_filename() {
        assert_eq!(
            NameStyle::Dotfile.main_filename("myapp", "yaml"),
            ".myapp.yaml"
        );
        assert_eq!(
            NameStyle::Dotfile.main_filename("myapp", "toml"),
            ".myapp.toml"
        );
        assert_eq!(NameStyle::Dotfile.main_filename("a", "yaml"), ".a.yaml");
    }

    #[test]
    fn name_style_bare_partial_prefix() {
        assert_eq!(NameStyle::Bare.partial_prefix("myapp"), "myapp-");
        assert_eq!(NameStyle::Bare.partial_prefix("a"), "a-");
    }

    #[test]
    fn name_style_dotfile_partial_prefix() {
        assert_eq!(NameStyle::Dotfile.partial_prefix("myapp"), ".myapp-");
        assert_eq!(NameStyle::Dotfile.partial_prefix("a"), ".a-");
    }

    #[test]
    fn name_style_main_and_partial_share_prefix() {
        // Within a style, the main filename and the partial prefix share the
        // same `{[.]?{app}}` head — a partial named exactly like the main
        // (no `-suffix`) is not a partial. This is the contract `collect_*`
        // relies on.
        for style in [NameStyle::Bare, NameStyle::Dotfile] {
            let main = style.main_filename("app", "yaml");
            let prefix = style.partial_prefix("app");
            // main starts with the app head but does NOT have the dash.
            let head = prefix.trim_end_matches('-');
            assert!(
                main.starts_with(head),
                "{main} should start with {head} for {style:?}"
            );
            assert!(
                !main.starts_with(prefix.as_str()),
                "{main} must not start with partial prefix {prefix} for {style:?}"
            );
        }
    }

    #[test]
    fn name_style_is_copy() {
        // NameStyle is a typed value, not a borrow — passing it to multiple
        // collect_* call sites (or holding it in a struct) doesn't move it.
        let style = NameStyle::Dotfile;
        let a = style;
        let b = style;
        assert_eq!(a, b);
        assert_eq!(a, NameStyle::Dotfile);
    }

    #[test]
    fn name_style_match_is_exhaustive() {
        // Renders the (style × format × ext) cartesian product through the
        // typed primitive, exercising both variants for every supported ext
        // — proves no call site has been missed.
        for style in [NameStyle::Bare, NameStyle::Dotfile] {
            for format in [Format::Yaml, Format::Toml] {
                for ext in format.extensions() {
                    let main = style.main_filename("test", ext);
                    let prefix = style.partial_prefix("test");
                    assert!(main.ends_with(&format!(".{ext}")));
                    assert!(prefix.ends_with('-'));
                    assert!(prefix.contains("test"));
                }
            }
        }
    }

    #[test]
    fn collect_configs_bare_finds_main_and_partials() {
        // End-to-end: the unified collect_configs honors NameStyle::Bare
        // exactly as the prior collect_dir_configs did.
        let dir = TempDir::new().unwrap();
        let app = "barecollect";
        let main_file = dir.path().join(format!("{app}.yaml"));
        let partial = dir.path().join(format!("{app}-01-db.yaml"));
        let unrelated = dir.path().join(format!("{app}.txt")); // wrong ext
        let dotted = dir.path().join(format!(".{app}.yaml")); // wrong style
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();
        fs::write(&unrelated, "k: v").unwrap();
        fs::write(&dotted, "k: v").unwrap();

        let mut found = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found);

        assert!(found.contains(&main_file));
        assert!(found.contains(&partial));
        assert!(!found.contains(&unrelated));
        assert!(!found.contains(&dotted));
    }

    #[test]
    fn collect_configs_dotfile_finds_main_and_partials() {
        let dir = TempDir::new().unwrap();
        let app = "dotcollect";
        let main_file = dir.path().join(format!(".{app}.yaml"));
        let partial = dir.path().join(format!(".{app}-99-extra.yaml"));
        let bare_main = dir.path().join(format!("{app}.yaml")); // wrong style
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();
        fs::write(&bare_main, "k: v").unwrap();

        let mut found = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Dotfile, &mut found);

        assert!(found.contains(&main_file));
        assert!(found.contains(&partial));
        assert!(!found.contains(&bare_main));
    }

    #[test]
    fn collect_configs_main_before_partials() {
        // Ordering invariant the unified function inherits from the prior
        // pair: main config is pushed before any partials in the same dir.
        let dir = TempDir::new().unwrap();
        let app = "ordercheck";
        let main_file = dir.path().join(format!("{app}.yaml"));
        let partial = dir.path().join(format!("{app}-01-extra.yaml"));
        fs::write(&main_file, "k: v").unwrap();
        fs::write(&partial, "k: v").unwrap();

        let mut found = Vec::new();
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml]);
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found);

        let main_idx = found.iter().position(|p| p == &main_file).unwrap();
        let partial_idx = found.iter().position(|p| p == &partial).unwrap();
        assert!(main_idx < partial_idx, "main must come before partials");
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

    // ---- Builder injection tests ----

    #[test]
    fn xdg_config_home_builder_used_in_standard_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("injapp").xdg_config_home(dir.path());
        let paths = d.standard_paths();
        assert!(
            paths.iter().any(|p| p.starts_with(dir.path())),
            "expected XDG override path in standard_paths"
        );
    }

    #[test]
    fn home_dir_builder_used_in_standard_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("homeinj")
            .xdg_config_home(&dir.path().join("nonexistent"))
            .home_dir(dir.path());
        let paths = d.standard_paths();
        assert!(
            paths.iter().any(|p| p.starts_with(dir.path())),
            "expected HOME override path in standard_paths"
        );
    }

    #[test]
    fn home_dir_produces_legacy_paths() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("leginjapp").home_dir(dir.path());
        let paths = d.standard_paths();
        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(
            path_strs.iter().any(|p| p.ends_with(".leginjapp")),
            "expected legacy path from injected HOME"
        );
        assert!(
            path_strs.iter().any(|p| p.ends_with(".leginjapp.toml")),
            "expected legacy toml path from injected HOME"
        );
    }

    #[test]
    fn xdg_config_home_overrides_env_var() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let app = "xdgovr";
        let config_dir = dir1.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir1.path())
            .home_dir(dir2.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn discover_all_non_hierarchical_with_injected_xdg() {
        let dir = TempDir::new().unwrap();
        let app = "daninj";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join(format!("{app}.yaml"));
        fs::write(&config_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&config_file));
    }

    #[test]
    fn start_dir_builder_sets_field() {
        let dir = TempDir::new().unwrap();
        let d = ConfigDiscovery::new("sdtest").start_dir(dir.path());
        assert_eq!(d.start_dir, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn discover_with_both_xdg_and_home_prefers_xdg() {
        let xdg_dir = TempDir::new().unwrap();
        let home_dir = TempDir::new().unwrap();
        let app = "bothpref";

        let xdg_config = xdg_dir.path().join(app);
        fs::create_dir_all(&xdg_config).unwrap();
        let xdg_file = xdg_config.join(format!("{app}.yaml"));
        fs::write(&xdg_file, "from: xdg").unwrap();

        let home_config = home_dir.path().join(".config").join(app);
        fs::create_dir_all(&home_config).unwrap();
        let home_file = home_config.join(format!("{app}.yaml"));
        fs::write(&home_file, "from: home").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(xdg_dir.path())
            .home_dir(home_dir.path())
            .discover();

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            xdg_file,
            "XDG should take precedence over HOME"
        );
    }

    #[test]
    fn format_debug_display() {
        let yaml = Format::Yaml;
        let toml = Format::Toml;
        assert_eq!(format!("{yaml:?}"), "Yaml");
        assert_eq!(format!("{toml:?}"), "Toml");
    }

    #[test]
    fn discover_yml_extension_found_when_yaml_absent() {
        let dir = TempDir::new().unwrap();
        let app = "ymlonly";
        let config_dir = dir.path().join(app);
        fs::create_dir_all(&config_dir).unwrap();
        let yml_file = config_dir.join(format!("{app}.yml"));
        fs::write(&yml_file, "key: value").unwrap();

        let result = ConfigDiscovery::new(app)
            .xdg_config_home(dir.path())
            .discover();

        assert!(result.is_ok());
        assert!(result.unwrap().display().to_string().ends_with(".yml"));
    }

    #[test]
    fn hierarchical_toml_format_finds_dotfile() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiertoml";
        let dotfile = dir_path.join(format!(".{app}.toml"));
        fs::write(&dotfile, "key = \"value\"").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Toml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p == &dotfile),
            "expected .toml dotfile in hierarchical results"
        );
    }

    #[test]
    fn hierarchical_multiple_formats_found() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let app = "hiermulti";

        let yaml_file = dir_path.join(format!(".{app}.yaml"));
        let toml_file = dir_path.join(format!(".{app}.toml"));
        fs::write(&yaml_file, "format: yaml").unwrap();
        fs::write(&toml_file, "format = \"toml\"").unwrap();

        let nonexistent_xdg = dir_path.join("nonexistent_xdg");
        let result = ConfigDiscovery::new(app)
            .formats(&[Format::Yaml, Format::Toml])
            .xdg_config_home(&nonexistent_xdg)
            .hierarchical()
            .start_dir(&dir_path)
            .discover_all();

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&yaml_file), "should find yaml");
        assert!(paths.contains(&toml_file), "should find toml");
    }

    #[test]
    fn discover_all_non_hierarchical_env_override_included() {
        let dir = TempDir::new().unwrap();
        let override_file = dir.path().join("custom.yaml");
        fs::write(&override_file, "key: value").unwrap();

        let var = "SHIKUMI_TEST_DA_ENV";
        unsafe { env::set_var(var, override_file.to_str().unwrap()) };

        let result = ConfigDiscovery::new("shikumi_nonexist_da_env")
            .env_override(var)
            .discover_all();

        unsafe { env::remove_var(var) };

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(paths.contains(&override_file));
    }

    #[test]
    fn standard_paths_with_no_home_or_xdg() {
        let nonexistent = PathBuf::from("/nonexistent_for_test_12345");
        let d = ConfigDiscovery::new("nohome")
            .xdg_config_home(&nonexistent)
            .home_dir(&nonexistent);
        let paths = d.standard_paths();
        assert!(
            paths.iter().all(|p| p.starts_with(&nonexistent)),
            "all paths should be under the injected directories"
        );
    }

    // ---- configured_extensions typed-primitive tests ----

    #[test]
    fn configured_extensions_default_yields_yaml_then_toml_in_preference_order() {
        let d = ConfigDiscovery::new("ext_default");
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["yaml", "yml", "toml"]);
    }

    #[test]
    fn configured_extensions_honors_custom_format_order() {
        // Flipping the format preference flips the extension iteration order.
        let d = ConfigDiscovery::new("ext_flip").formats(&[Format::Toml, Format::Yaml]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["toml", "yaml", "yml"]);
    }

    #[test]
    fn configured_extensions_flattens_multi_extension_formats() {
        // Format::Yaml owns two extensions (yaml, yml); the cartesian
        // product flattens them into the iterator without losing order.
        let d = ConfigDiscovery::new("ext_yaml_only").formats(&[Format::Yaml]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["yaml", "yml"]);
    }

    #[test]
    fn configured_extensions_includes_lisp_when_configured() {
        let d = ConfigDiscovery::new("ext_lisp").formats(&[Format::Lisp]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert_eq!(exts, vec!["lisp", "lsp", "el"]);
    }

    #[test]
    fn configured_extensions_empty_when_no_formats() {
        let d = ConfigDiscovery::new("ext_empty").formats(&[]);
        let exts: Vec<&'static str> = d.configured_extensions().collect();
        assert!(exts.is_empty());
    }

    #[test]
    fn configured_extensions_cardinality_matches_sum_of_format_extensions() {
        // The flat cartesian product must yield exactly
        // sum(format.extensions().len()) items — no dedup, no reordering
        // beyond the format-then-ext nesting.
        for formats in [
            vec![Format::Yaml],
            vec![Format::Toml],
            vec![Format::Yaml, Format::Toml],
            vec![Format::Toml, Format::Yaml, Format::Lisp, Format::Nix],
        ] {
            let expected: usize = formats.iter().map(|f| f.extensions().len()).sum();
            let d = ConfigDiscovery::new("card").formats(&formats);
            assert_eq!(
                d.configured_extensions().count(),
                expected,
                "cardinality must equal sum of format.extensions().len() for {formats:?}"
            );
        }
    }

    #[test]
    fn standard_paths_extensions_match_configured_extensions() {
        // standard_paths is one of the three consumers of the typed
        // primitive; assert the cartesian product surfaces in every
        // generated XDG/HOME path.
        let xdg = PathBuf::from("/xdg_for_invariant");
        let home = PathBuf::from("/home_for_invariant");
        let d = ConfigDiscovery::new("inv")
            .formats(&[Format::Yaml, Format::Toml])
            .xdg_config_home(&xdg)
            .home_dir(&home);
        let paths = d.standard_paths();

        for ext in d.configured_extensions() {
            assert!(
                paths
                    .iter()
                    .any(|p| p.extension().and_then(|e| e.to_str()) == Some(ext)),
                "standard_paths must include a path with extension `.{ext}`"
            );
        }
    }

    #[test]
    fn is_partial_match_accepts_every_configured_extension() {
        // is_partial_match is the second consumer; assert it accepts a
        // partial filename for every extension the typed primitive yields.
        let d = ConfigDiscovery::new("inv2").formats(&[Format::Yaml, Format::Toml, Format::Nix]);
        for ext in d.configured_extensions() {
            let name = format!("inv2-overlay.{ext}");
            assert!(
                d.is_partial_match(&name, "inv2", NameStyle::Bare),
                "is_partial_match must accept partial `{name}` for configured ext `.{ext}`"
            );
        }
    }

    #[test]
    fn is_partial_match_rejects_extensions_outside_configured_set() {
        // The contract has two sides: every configured ext is accepted
        // (above), every non-configured ext is rejected (here). With
        // formats=[Yaml] only, .toml/.json/.nix partials must not match.
        let d = ConfigDiscovery::new("inv3").formats(&[Format::Yaml]);
        for ext in ["toml", "json", "nix", "lisp"] {
            let name = format!("inv3-overlay.{ext}");
            assert!(
                !d.is_partial_match(&name, "inv3", NameStyle::Bare),
                "ext `.{ext}` is not configured; partial `{name}` must be rejected"
            );
        }
    }

    #[test]
    fn collect_configs_extensions_match_configured_extensions() {
        // collect_configs is the third consumer; for every configured ext
        // the helper must surface the corresponding `{app}.{ext}` main file.
        let dir = TempDir::new().unwrap();
        let app = "inv4";
        let d = ConfigDiscovery::new(app).formats(&[Format::Yaml, Format::Toml]);
        for ext in d.configured_extensions() {
            fs::write(dir.path().join(format!("{app}.{ext}")), "k: v").unwrap();
        }

        let mut found = Vec::new();
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found);
        for ext in d.configured_extensions() {
            let expected = dir.path().join(format!("{app}.{ext}"));
            assert!(
                found.contains(&expected),
                "collect_configs must surface `{}` for configured ext `.{ext}`",
                expected.display()
            );
        }
    }

    #[test]
    fn configured_extensions_empty_disables_all_three_consumers() {
        // The cross-call-site invariant from the empty side: zero
        // extensions => standard_paths has no XDG/HOME paths,
        // is_partial_match always rejects, collect_configs surfaces nothing.
        let dir = TempDir::new().unwrap();
        let app = "emptycross";
        fs::write(dir.path().join(format!("{app}.yaml")), "k: v").unwrap();
        fs::write(dir.path().join(format!("{app}-x.yaml")), "k: v").unwrap();

        let d = ConfigDiscovery::new(app)
            .formats(&[])
            .xdg_config_home(PathBuf::from("/xdg_empty"))
            .home_dir(PathBuf::from("/home_empty"));

        assert_eq!(d.configured_extensions().count(), 0);
        assert!(
            !d.is_partial_match(&format!("{app}-x.yaml"), app, NameStyle::Bare),
            "no configured exts ⇒ no partial matches"
        );
        let mut found = Vec::new();
        d.collect_configs(dir.path(), app, NameStyle::Bare, &mut found);
        assert!(
            found.is_empty(),
            "no configured exts ⇒ collect_configs surfaces nothing"
        );

        // standard_paths still emits the legacy `~/.{app}` and `~/.{app}.toml`
        // entries (they are not gated on configured_extensions); but no
        // {app}/{app}.{ext} or .config/{app}/{app}.{ext} entries should appear.
        let paths = d.standard_paths();
        let main_name = format!("{app}.yaml");
        assert!(
            paths.iter().all(|p| {
                let by_name = p.file_name().and_then(|n| n.to_str());
                by_name != Some(main_name.as_str())
            }),
            "no configured exts ⇒ no XDG/HOME {app}.{{ext}} paths; got {paths:?}"
        );
    }

    // ---- Format::ALL / has_shikumi_provider / metadata_name /
    // ---- strip_metadata_name typed-primitive tests

    #[test]
    fn format_all_in_declaration_order() {
        assert_eq!(
            Format::ALL,
            &[Format::Yaml, Format::Toml, Format::Lisp, Format::Nix]
        );
    }

    #[test]
    fn format_all_covers_every_variant() {
        // The closed list must enumerate every variant exactly once.
        // The match below is the compiler-enforced contract: adding a
        // variant breaks this test until the new variant is wired into
        // both `Format::ALL` and this exhaustivity check.
        for f in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            assert!(
                Format::ALL.contains(&f),
                "Format::ALL must contain every variant; missing {f:?}"
            );
            // Exhaustive match — adding a variant requires updating
            // both `Format::ALL` and this arm list.
            match f {
                Format::Yaml | Format::Toml | Format::Lisp | Format::Nix => {}
            }
        }
        assert_eq!(Format::ALL.len(), 4);
    }

    #[test]
    fn format_has_shikumi_provider_lisp_and_nix_only() {
        assert!(!Format::Yaml.has_shikumi_provider());
        assert!(!Format::Toml.has_shikumi_provider());
        assert!(Format::Lisp.has_shikumi_provider());
        assert!(Format::Nix.has_shikumi_provider());
    }

    #[test]
    fn format_metadata_name_uses_display_token() {
        // The shape `"<format-display>: <path>"` is uniform across every
        // variant — `Format::Display` is the single source of truth for
        // the leading token.
        for f in Format::ALL {
            let path = Path::new("/etc/app/app.x");
            let name = f.metadata_name(path);
            let expected = format!("{f}: /etc/app/app.x");
            assert_eq!(
                name, expected,
                "metadata_name must use the Display token for {f:?}"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_round_trips_for_shikumi_providers() {
        // Round-trip for every variant where has_shikumi_provider is true:
        // the prefix the resolver strips matches the prefix the provider emits.
        for f in Format::ALL.iter().filter(|f| f.has_shikumi_provider()) {
            let path = Path::new("/srv/cfg/app.cfg");
            let name = f.metadata_name(path);
            let (recovered_format, rest) =
                Format::strip_metadata_name(&name).expect("round-trip must succeed");
            assert_eq!(
                recovered_format, *f,
                "strip must recover the format that emitted the name"
            );
            assert_eq!(
                rest, "/srv/cfg/app.cfg",
                "strip must surface the trailing path verbatim"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_rejects_non_shikumi_provider_prefixes() {
        // Variants without a shikumi-built provider must not be recognized
        // by the inverse — even though `metadata_name` produces a
        // syntactically valid `"<format>: <path>"` for them, the resolver
        // must not claim them, since their figment metadata uses
        // `Source::File` instead and is matched by a different rule
        // (path equality against `metadata.source`).
        for f in Format::ALL.iter().filter(|f| !f.has_shikumi_provider()) {
            let name = f.metadata_name(Path::new("/x.cfg"));
            assert!(
                Format::strip_metadata_name(&name).is_none(),
                "{f:?} has no shikumi-built provider; its `metadata_name` \
                 shape must not be recognized by the inverse resolver"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_rejects_unrelated_strings() {
        // Empty strings, plain paths, env-shaped names, and arbitrary
        // tokens must all fail to match.
        for name in [
            "",
            "/etc/app/app.yaml",
            "`MYAPP_` environment variable",
            "json: /etc/app.json",
            "lisp /etc/app.lisp", // missing colon
            "lisp:/etc/app.lisp", // missing space
        ] {
            assert!(
                Format::strip_metadata_name(name).is_none(),
                "unrelated metadata name `{name}` must not match"
            );
        }
    }

    #[test]
    fn format_strip_metadata_name_pins_correct_variant() {
        // The strip must pin the *specific* variant that emitted the
        // prefix, not just any shikumi-built variant.
        let lisp_name = Format::Lisp.metadata_name(Path::new("/a.lisp"));
        let (got_lisp, _) =
            Format::strip_metadata_name(&lisp_name).expect("lisp prefix must match");
        assert_eq!(got_lisp, Format::Lisp);

        let nix_name = Format::Nix.metadata_name(Path::new("/a.nix"));
        let (got_nix, _) = Format::strip_metadata_name(&nix_name).expect("nix prefix must match");
        assert_eq!(got_nix, Format::Nix);
    }

    #[test]
    fn format_strip_metadata_name_returns_borrow_into_input() {
        // The trailing path is a borrow into `name`, not a fresh
        // allocation — observable by checking that the returned `&str`
        // is a sub-slice of the input by pointer arithmetic.
        let name = Format::Lisp.metadata_name(Path::new("/srv/app.lisp"));
        let (_, rest) = Format::strip_metadata_name(&name).unwrap();
        let name_start = name.as_ptr() as usize;
        let name_end = name_start + name.len();
        let rest_start = rest.as_ptr() as usize;
        assert!(
            rest_start >= name_start && rest_start < name_end,
            "rest must be a sub-slice of name"
        );
    }
}

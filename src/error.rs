use std::path::PathBuf;

use crate::discovery::Format;
use crate::source::{ConfigSource, EnvMetadataTag, FigmentSourceTag};

/// Errors produced by shikumi's config discovery, loading, and watching.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ShikumiError {
    /// No config file was found at any of the searched locations.
    #[error("config file not found; tried: {}", tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    NotFound { tried: Vec<PathBuf> },

    /// The config file could not be parsed.
    #[error("config parse error: {0}")]
    Parse(String),

    /// The file watcher encountered an error.
    #[error("file watch error: {0}")]
    Watch(#[from] notify::Error),

    /// An I/O error occurred during config file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Figment extraction or merge failed without source attribution.
    ///
    /// Produced by direct `From<Box<figment::Error>>` conversions — e.g.
    /// when a consumer hands a raw figment error to shikumi. Boxed to keep
    /// `ShikumiError` small (`figment::Error` is ~208 bytes).
    ///
    /// New code should prefer [`ShikumiError::Extract`], which carries the
    /// [`ConfigSource`] chain that produced the failure.
    #[error("figment error: {0}")]
    Figment(#[from] Box<figment::Error>),

    /// Configuration extraction through a [`crate::ProviderChain`] failed.
    ///
    /// Carries the typed [`ConfigSource`] chain in merge order (lowest
    /// priority first) so the failure can be traced back to the layers
    /// that produced it without grepping logs or re-walking discovery.
    /// The dotted field path of the offending key (when figment can
    /// localize it) and — when figment's per-value `Metadata` can be
    /// matched against an entry in the recorded chain — the specific
    /// failing source layer are also embedded in the rendered display.
    #[error(
        "config extraction failed [layers: {}]{}{}: {error}",
        display_sources(sources),
        display_failing_source(sources, error),
        display_field_path(&error.path)
    )]
    Extract {
        /// The provider chain in merge order at the moment of failure.
        sources: Vec<ConfigSource>,
        /// Boxed underlying figment error (kept small; `figment::Error` is ~208 bytes).
        #[source]
        error: Box<figment::Error>,
    },
}

fn display_sources(sources: &[ConfigSource]) -> String {
    if sources.is_empty() {
        "<empty>".to_owned()
    } else {
        sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

fn display_field_path(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" at field `{}`", path.join("."))
    }
}

fn display_failing_source(sources: &[ConfigSource], error: &figment::Error) -> String {
    resolve_failing_source(error, sources)
        .map(|s| format!(" from {s}"))
        .unwrap_or_default()
}

/// Map a figment error's per-value [`figment::Metadata`] back to the
/// specific [`ConfigSource`] in the recorded chain that produced the
/// offending value.
///
/// Returns a borrowed reference into `chain` so callers share its
/// lifetime. `None` when figment did not attach metadata (e.g. an
/// `Error::from(String)` constructed without a provider context), or
/// when the metadata cannot be matched to any recorded entry.
///
/// Resolution rules, applied in order:
/// 1. If `metadata.source` classifies (per [`FigmentSourceTag::classify`])
///    as [`FigmentSourceTag::File`], match by exact path equality against
///    [`ConfigSource::File`] entries.
/// 2. If `metadata.name` matches a shikumi-built provider's
///    `"<format>: <path>"` shape (per [`Format::strip_metadata_name`]),
///    extract the trailing path and match against [`ConfigSource::File`].
/// 3. If `metadata.name` matches figment's
///    [`figment::providers::Env`] tag shape (per
///    [`ConfigSource::strip_env_metadata_name`]), match against the
///    [`ConfigSource::Env`] entry by uppercased prefix when the tag
///    carries one; otherwise return the unique `Env` entry if exactly
///    one exists.
/// 4. If `metadata.source` classifies as [`FigmentSourceTag::Code`]
///    (the shape produced by [`figment::providers::Serialized`]),
///    match the unique [`ConfigSource::Defaults`] entry if exactly one
///    exists.
fn resolve_failing_source<'a>(
    error: &figment::Error,
    chain: &'a [ConfigSource],
) -> Option<&'a ConfigSource> {
    let md = error.metadata.as_ref()?;
    let source_tag = md.source.as_ref().and_then(FigmentSourceTag::classify);

    if let Some(FigmentSourceTag::File(p)) = source_tag
        && let Some(hit) = chain.iter().find(|s| s.as_path() == Some(p))
    {
        return Some(hit);
    }

    let name = md.name.as_ref();
    if let Some((_format, rest)) = Format::strip_metadata_name(name) {
        let p = std::path::Path::new(rest);
        if let Some(hit) = chain.iter().find(|s| s.as_path() == Some(p)) {
            return Some(hit);
        }
    }

    if let Some(tag) = ConfigSource::strip_env_metadata_name(name) {
        if let EnvMetadataTag::Prefixed(prefix_upper) = tag
            && let Some(hit) = chain.iter().find(|s| {
                s.as_env_prefix()
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix_upper))
            })
        {
            return Some(hit);
        }
        let mut envs = chain.iter().filter(|s| s.is_env());
        if let Some(only) = envs.next()
            && envs.next().is_none()
        {
            return Some(only);
        }
    }

    if matches!(source_tag, Some(FigmentSourceTag::Code(_))) {
        let mut defaults = chain.iter().filter(|s| s.is_defaults());
        if let Some(only) = defaults.next()
            && defaults.next().is_none()
        {
            return Some(only);
        }
    }

    None
}

impl ShikumiError {
    /// Returns `true` if this is a `NotFound` error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if this is a `Parse` error.
    #[must_use]
    pub fn is_parse(&self) -> bool {
        matches!(self, Self::Parse(_))
    }

    /// Returns the list of paths that were tried, if this is a `NotFound` error.
    #[must_use]
    pub fn tried_paths(&self) -> Option<&[PathBuf]> {
        match self {
            Self::NotFound { tried } => Some(tried),
            _ => None,
        }
    }

    /// Returns the typed [`ConfigSource`] chain attached to this error.
    ///
    /// Currently populated only by [`ShikumiError::Extract`]; future
    /// variants may attach a chain too. Callers should treat `None` as
    /// "no provenance recorded," not "no sources contributed."
    #[must_use]
    pub fn sources(&self) -> Option<&[ConfigSource]> {
        match self {
            Self::Extract { sources, .. } => Some(sources),
            _ => None,
        }
    }

    /// Returns the dotted field path that produced the failure, if known.
    ///
    /// Drawn from the wrapped [`figment::Error::path`] for variants that
    /// box one ([`Self::Extract`], [`Self::Figment`]). Returned as a
    /// borrowed slice so callers can inspect the raw segments
    /// (`["window", "size"]`) rather than re-parsing the rendered
    /// "at field" Display segment.
    ///
    /// `None` for variants that do not wrap a figment error
    /// ([`Self::Parse`], [`Self::NotFound`], [`Self::Watch`],
    /// [`Self::Io`]). An empty slice means figment did not localize the
    /// offending field — typically a top-level type mismatch or an error
    /// the deserializer reported without a key context — and is
    /// distinct from `None`.
    ///
    /// Pairs with [`Self::sources`] to form the (where × what) failure
    /// surface: provenance answers "which layer chain contributed?"
    /// while this answers "which field inside the produced value did
    /// the deserializer reject?".
    #[must_use]
    pub fn field_path(&self) -> Option<&[String]> {
        match self {
            Self::Extract { error, .. } | Self::Figment(error) => Some(&error.path),
            _ => None,
        }
    }

    /// Returns the specific [`ConfigSource`] in the recorded chain that
    /// produced the failure, if attribution is possible.
    ///
    /// Distinct from [`Self::sources`], which returns the whole chain:
    /// `failing_source` pinpoints the *one* layer figment's per-value
    /// metadata blames for the offending field. Returned by reference
    /// into the recorded chain so it shares the error's lifetime.
    ///
    /// Pairs with [`Self::sources`] (full chain) and [`Self::field_path`]
    /// (offending key) to form the closed (which-layer × which-field)
    /// failure coordinate inside the (where × what) surface.
    ///
    /// Returns `None` for variants that do not record a chain
    /// ([`Self::Parse`], [`Self::NotFound`], [`Self::Watch`],
    /// [`Self::Io`], [`Self::Figment`]); for [`Self::Extract`] errors
    /// when figment did not attach `Metadata` (e.g. a manually
    /// constructed `figment::Error::from(string)`); and when the
    /// metadata cannot be matched to any entry in the recorded chain
    /// (callers should fall back to [`Self::sources`]).
    #[must_use]
    pub fn failing_source(&self) -> Option<&ConfigSource> {
        match self {
            Self::Extract { sources, error } => resolve_failing_source(error, sources),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display_lists_paths() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/a/b.yaml"), PathBuf::from("/c/d.toml")],
        };
        let msg = err.to_string();
        assert!(msg.contains("/a/b.yaml"), "error should list first path");
        assert!(msg.contains("/c/d.toml"), "error should list second path");
        assert!(msg.contains(", "), "paths should be comma-separated");
    }

    #[test]
    fn not_found_empty_tried() {
        let err = ShikumiError::NotFound { tried: vec![] };
        let msg = err.to_string();
        assert!(msg.contains("config file not found"));
    }

    #[test]
    fn parse_error_display() {
        let err = ShikumiError::Parse("unexpected token".to_owned());
        let msg = err.to_string();
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn figment_error_from_conversion() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();

        let shikumi_err: ShikumiError = Box::new(figment_err).into();
        assert!(
            matches!(shikumi_err, ShikumiError::Figment(_)),
            "expected Figment variant"
        );
        let msg = shikumi_err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn is_not_found_helper() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/a")],
        };
        assert!(err.is_not_found());
        assert!(!err.is_parse());
    }

    #[test]
    fn is_parse_helper() {
        let err = ShikumiError::Parse("bad".to_owned());
        assert!(err.is_parse());
        assert!(!err.is_not_found());
    }

    #[test]
    fn tried_paths_returns_paths_for_not_found() {
        let paths = vec![PathBuf::from("/x"), PathBuf::from("/y")];
        let err = ShikumiError::NotFound {
            tried: paths.clone(),
        };
        assert_eq!(err.tried_paths(), Some(paths.as_slice()));

        let parse_err = ShikumiError::Parse("bad".to_owned());
        assert_eq!(parse_err.tried_paths(), None);
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let shikumi_err: ShikumiError = io_err.into();
        assert!(matches!(shikumi_err, ShikumiError::Io(_)));
        assert!(shikumi_err.to_string().contains("file gone"));
    }

    #[test]
    fn error_is_debug_printable() {
        let err = ShikumiError::Parse("test".to_owned());
        let debug = format!("{err:?}");
        assert!(debug.contains("Parse"));
    }

    #[test]
    fn watch_error_from_conversion() {
        let notify_err = notify::Error::generic("test watcher error");
        let shikumi_err: ShikumiError = notify_err.into();
        assert!(
            matches!(shikumi_err, ShikumiError::Watch(_)),
            "expected Watch variant"
        );
        let msg = shikumi_err.to_string();
        assert!(msg.contains("test watcher error"));
    }

    #[test]
    fn watch_error_display() {
        let notify_err = notify::Error::generic("poll failed");
        let err: ShikumiError = notify_err.into();
        let msg = err.to_string();
        assert!(msg.contains("file watch error"));
        assert!(msg.contains("poll failed"));
    }

    #[test]
    fn figment_error_display_contains_context() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();
        let err: ShikumiError = Box::new(figment_err).into();
        let msg = err.to_string();
        assert!(msg.contains("figment error"), "should have figment prefix");
    }

    #[test]
    fn error_source_chain() {
        use std::error::Error;

        let notify_err = notify::Error::generic("test");
        let err: ShikumiError = notify_err.into();
        assert!(err.source().is_some(), "Watch variant should have a source");

        let parse_err = ShikumiError::Parse("test".to_owned());
        assert!(
            parse_err.source().is_none(),
            "Parse variant should not have a source"
        );
    }

    #[test]
    fn not_found_single_path() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/only/one.yaml")],
        };
        let msg = err.to_string();
        assert!(msg.contains("/only/one.yaml"));
        assert!(!msg.contains(", "), "single path should have no comma");
    }

    // ---- Extract variant tests ----

    fn fake_figment_error() -> Box<figment::Error> {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        Box::new(result.unwrap_err())
    }

    #[test]
    fn extract_display_lists_layers_in_order() {
        let err = ShikumiError::Extract {
            sources: vec![
                ConfigSource::Defaults,
                ConfigSource::Env("APP_".to_owned()),
                ConfigSource::File(PathBuf::from("/etc/app.yaml")),
            ],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(msg.contains("config extraction failed"));
        assert!(msg.contains("defaults"));
        assert!(msg.contains("env(APP_)"));
        assert!(msg.contains("file(/etc/app.yaml)"));
        // Order matters: defaults first, then env, then file.
        let d = msg.find("defaults").unwrap();
        let e = msg.find("env(APP_)").unwrap();
        let f = msg.find("file(/etc/app.yaml)").unwrap();
        assert!(d < e && e < f, "layers must render in merge order");
    }

    #[test]
    fn extract_display_with_empty_sources() {
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(msg.contains("config extraction failed"));
        assert!(msg.contains("<empty>"));
    }

    #[test]
    fn extract_carries_source_chain_via_helper() {
        let chain = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/x.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain.clone(),
            error: fake_figment_error(),
        };
        assert_eq!(err.sources(), Some(chain.as_slice()));
    }

    #[test]
    fn sources_helper_returns_none_for_other_variants() {
        assert!(ShikumiError::Parse("x".to_owned()).sources().is_none());
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .sources()
            .is_none()
        );
        assert!(
            ShikumiError::Figment(fake_figment_error())
                .sources()
                .is_none()
        );
    }

    #[test]
    fn extract_source_chain_preserves_figment_error() {
        use std::error::Error;
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let src = err.source().expect("Extract should expose a #[source]");
        // The wrapped figment error should be reachable.
        assert!(!format!("{src}").is_empty());
    }

    #[test]
    fn extract_is_distinct_from_figment_variant() {
        let extract = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let figment = ShikumiError::Figment(fake_figment_error());
        assert!(matches!(extract, ShikumiError::Extract { .. }));
        assert!(matches!(figment, ShikumiError::Figment(_)));
        assert_ne!(extract.to_string(), figment.to_string());
    }

    // ---- field_path() tests ----

    /// Build a real extraction failure that figment can attach a path to:
    /// type mismatch on a typed field. The deserializer reports the offending
    /// key, so figment fills in `error.path`.
    fn extract_error_with_typed_field_path() -> ShikumiError {
        use crate::provider::ProviderChain;
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("typed.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        // Keep the temp dir alive long enough for the caller to read the error.
        // (figment loads the file synchronously inside `extract`, so the file is
        // no longer needed after this point.)
        drop(dir);
        err
    }

    #[test]
    fn field_path_none_for_non_figment_variants() {
        assert!(ShikumiError::Parse("x".to_owned()).field_path().is_none());
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .field_path()
            .is_none()
        );
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let io_err: ShikumiError = io.into();
        assert!(io_err.field_path().is_none());
    }

    #[test]
    fn field_path_some_empty_for_extract_without_localized_field() {
        // Bare Figment::new() failure: no provider, no path attribution.
        let err = ShikumiError::Extract {
            sources: vec![],
            error: fake_figment_error(),
        };
        let path = err
            .field_path()
            .expect("Extract always exposes a (possibly empty) field path");
        assert!(
            path.is_empty(),
            "no localized field, but accessor is Some(&[])"
        );
    }

    #[test]
    fn field_path_some_empty_for_figment_variant_without_localized_field() {
        let err = ShikumiError::Figment(fake_figment_error());
        let path = err
            .field_path()
            .expect("Figment always exposes a (possibly empty) field path");
        assert!(path.is_empty());
    }

    #[test]
    fn field_path_carries_offending_field_for_typed_failure() {
        let err = extract_error_with_typed_field_path();
        let path = err.field_path().expect("Extract exposes field path");
        assert_eq!(
            path,
            &["count".to_owned()],
            "figment should localize the offending key"
        );
    }

    #[test]
    fn extract_display_includes_field_path_segment_when_localized() {
        let err = extract_error_with_typed_field_path();
        let msg = err.to_string();
        assert!(
            msg.contains("at field `count`"),
            "rendered error must cite the failing field; got: {msg}"
        );
    }

    #[test]
    fn extract_display_omits_field_path_segment_when_empty() {
        // Bare Figment::new() extraction failure has no path; ensure the
        // segment is omitted (no stray `at field`` `` slot, no double colons).
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(!msg.contains("at field"), "no path → no `at field` segment");
        assert!(msg.contains("[layers: defaults]:"));
    }

    // ---- failing_source() tests ----

    fn extract_error_with_file_path_failure() -> (tempfile::TempDir, ShikumiError) {
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("typed.yaml");
        std::fs::write(&file, "count: not_a_number\n").unwrap();
        let err = ProviderChain::new()
            .with_env("FAILING_SRC_FILE_NOTSET_")
            .with_file(&file)
            .extract::<Cfg>()
            .unwrap_err();
        (dir, err)
    }

    #[test]
    fn failing_source_pins_file_layer_for_typed_file_failure() {
        let (dir, err) = extract_error_with_file_path_failure();
        let s = err
            .failing_source()
            .expect("Extract attributes failure to a recorded source");
        assert!(s.is_file(), "expected failing source to be a file layer");
        assert_eq!(s.as_path(), Some(dir.path().join("typed.yaml").as_path()));
    }

    #[test]
    fn failing_source_pins_env_layer_when_env_provides_offending_field() {
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let var = "FAILSRC_ENV_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_env("FAILSRC_ENV_")
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };

        let s = err
            .failing_source()
            .expect("env-only failure must attribute to the env layer");
        assert!(s.is_env(), "expected failing source to be the env layer");
        assert_eq!(s.as_env_prefix(), Some("FAILSRC_ENV_"));
    }

    #[test]
    fn failing_source_distinguishes_env_from_file_in_layered_chain() {
        // Both env and file are present; only env supplies `count`.
        // figment's per-value metadata pins the failure to env, not file.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("ok.yaml");
        std::fs::write(&file, "name: present\n").unwrap();

        let var = "FAILSRC_DISCRIM_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_file(&file)
            .with_env("FAILSRC_DISCRIM_")
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };

        let s = err
            .failing_source()
            .expect("Extract must attribute the failure");
        assert_eq!(
            s.as_env_prefix(),
            Some("FAILSRC_DISCRIM_"),
            "env (the actual offender) must win over the unrelated file layer"
        );
    }

    #[test]
    fn failing_source_none_for_figment_variant() {
        // `Figment` carries no recorded chain; `failing_source` requires
        // a chain to resolve into, so it returns None even if the
        // wrapped error has metadata.
        let err = ShikumiError::Figment(fake_figment_error());
        assert!(err.failing_source().is_none());
    }

    #[test]
    fn failing_source_none_for_non_figment_variants() {
        assert!(
            ShikumiError::Parse("x".to_owned())
                .failing_source()
                .is_none()
        );
        assert!(
            ShikumiError::NotFound {
                tried: vec![PathBuf::from("/a")]
            }
            .failing_source()
            .is_none()
        );
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let io_err: ShikumiError = io.into();
        assert!(io_err.failing_source().is_none());
    }

    #[test]
    fn failing_source_none_when_no_metadata_attached() {
        // Manually constructed figment::Error has no metadata; even with
        // a recorded chain, attribution cannot be resolved.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults, ConfigSource::Env("X_".to_owned())],
            error: fake_figment_error(),
        };
        assert!(
            err.failing_source().is_none(),
            "no metadata → no attribution"
        );
    }

    #[test]
    fn failing_source_none_when_chain_missing_matching_entry() {
        // Build a figment error whose metadata points at a file path that
        // is *not* in the recorded chain. The resolver must not fabricate
        // a match.
        let (_dir, real) = extract_error_with_file_path_failure();
        let ShikumiError::Extract { error: inner, .. } = real else {
            unreachable!();
        };
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults], // no File entry
            error: inner,
        };
        assert!(err.failing_source().is_none());
    }

    #[test]
    fn extract_display_includes_failing_source_segment_when_known() {
        let (dir, err) = extract_error_with_file_path_failure();
        let path_disp = dir.path().join("typed.yaml").display().to_string();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("from file({path_disp})")),
            "rendered error must cite the failing layer; got: {msg}"
        );
    }

    #[test]
    fn extract_display_omits_failing_source_segment_when_unknown() {
        // No metadata attached → no `from <src>` segment.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults],
            error: fake_figment_error(),
        };
        let msg = err.to_string();
        assert!(
            !msg.contains(" from "),
            "no attribution → no `from` segment; got: {msg}"
        );
    }

    #[test]
    fn extract_display_orders_segments_layers_then_from_then_field() {
        let (_dir, err) = extract_error_with_file_path_failure();
        let msg = err.to_string();
        let l = msg.find("[layers:").expect("layers segment");
        let f = msg.find(" from ").expect("from segment");
        let a = msg.find(" at field ").expect("field segment");
        assert!(l < f && f < a, "segment order: layers -> from -> at field");
    }

    #[test]
    fn failing_source_env_match_is_case_insensitive() {
        // figment uppercases prefixes when emitting metadata names; our
        // recorded ConfigSource keeps the original casing. Ensure the
        // resolver bridges both.
        use crate::provider::ProviderChain;
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let var = "FAILSRC_CASE_COUNT";
        unsafe { std::env::set_var(var, "not_a_number") };
        let err = ProviderChain::new()
            .with_env("failsrc_case_") // lowercase user input
            .extract::<Cfg>()
            .unwrap_err();
        unsafe { std::env::remove_var(var) };
        let s = err.failing_source().expect("env attribution");
        assert_eq!(s.as_env_prefix(), Some("failsrc_case_"));
    }

    #[test]
    fn field_path_preserves_dotted_segments_via_with_path() {
        // figment's Error::with_path splits on '.'; verify the accessor
        // preserves segment shape rather than collapsing back to a string.
        let raw = figment::Error::from("typed".to_owned()).with_path("window.size");
        let err = ShikumiError::Extract {
            sources: vec![],
            error: Box::new(raw),
        };
        let path = err.field_path().expect("Extract exposes field path");
        assert_eq!(
            path,
            &["window".to_owned(), "size".to_owned()],
            "segments must be preserved, not collapsed"
        );
        // And Display joins them with '.' for the human-readable form.
        assert!(err.to_string().contains("at field `window.size`"));
    }
}

use std::path::PathBuf;

use crate::source::{ConfigSource, EnvMetadataTag, FigmentNameTag, FigmentSourceTag};

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
        .map(|a| format!(" from {}", a.source))
        .unwrap_or_default()
}

/// Reason a [`figment::Error`] was attributed to a specific layer in the
/// recorded [`ConfigSource`] chain by [`resolve_failing_source`].
///
/// The resolver dispatches over five distinct rules, applied in order;
/// the first that matches produces the attribution. Before this enum,
/// the resolver returned just `Option<&ConfigSource>`, collapsing the
/// rule that fired into its result.
///
/// Lifting the rule into the type lets observers distinguish *exact*
/// attribution (path / prefix equality) from *fallback* attribution
/// (uniqueness in the chain) — a partition formalized by
/// [`AttributionConfidence`] and recoverable from any rule via
/// [`Self::confidence`]. The distinction matters for:
///
/// - Structured diagnostics that want to render different prose for
///   "blamed via file path equality" vs. "blamed via env-prefix
///   uniqueness fallback".
/// - Attestation manifests that record per-failure attribution
///   provenance alongside the chain.
/// - Tests that pin exactly which rule a scenario exercises (rather
///   than checking only that *some* layer was attributed).
///
/// Variants are `#[non_exhaustive]` so future resolution rules — e.g.
/// custom-source attribution for [`FigmentSourceTag::Custom`] when a
/// matching `ConfigSource::External(_)` lands — extend the enum without
/// breaking exhaustivity at consumer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionRule {
    /// `metadata.source` classified as [`FigmentSourceTag::File`];
    /// matched by exact path equality against a [`ConfigSource::File`]
    /// entry. The shape figment's built-in YAML/TOML providers attach.
    FileBySource,
    /// `metadata.name` matched a shikumi-built provider's
    /// `"<format>: <path>"` shape (per [`Format::strip_metadata_name`]);
    /// matched by extracted path equality against a
    /// [`ConfigSource::File`] entry. The shape [`crate::NixProvider`]
    /// (and [`crate::LispProvider`] when the `lisp` feature is on) attach.
    FileByMetadataName,
    /// `metadata.name` was env-tag shaped with a prefix (per
    /// [`ConfigSource::strip_env_metadata_name`] returning
    /// [`EnvMetadataTag::Prefixed`]); matched by case-insensitive
    /// prefix equality against a [`ConfigSource::Env`] entry. The
    /// shape `figment::providers::Env::prefixed(_)` attaches.
    EnvByPrefix,
    /// `metadata.name` was env-tag shaped (prefixed-without-match or
    /// bare); no prefix equality match in the chain, but exactly one
    /// [`ConfigSource::Env`] is recorded — attributed to that unique
    /// entry as a fallback.
    EnvByUniqueness,
    /// `metadata.source` classified as [`FigmentSourceTag::Code`] (the
    /// shape [`figment::providers::Serialized`] attaches, behind
    /// [`crate::ProviderChain::with_defaults`]), and exactly one
    /// [`ConfigSource::Defaults`] is recorded in the chain.
    DefaultsByCodeUniqueness,
}

impl AttributionRule {
    /// Confidence class of this rule: [`AttributionConfidence::Exact`]
    /// for equality-based attributions ([`Self::FileBySource`],
    /// [`Self::FileByMetadataName`], [`Self::EnvByPrefix`]), or
    /// [`AttributionConfidence::Fallback`] for uniqueness-based
    /// attributions ([`Self::EnvByUniqueness`],
    /// [`Self::DefaultsByCodeUniqueness`]).
    ///
    /// One source of truth for the exact-vs-fallback partition over
    /// the rule space. Before this method, the partition was
    /// re-stated in prose at three doc sites
    /// ([`Self`], [`ShikumiError::failing_attribution`],
    /// [`crate::ReloadFailure::attribution_rule`]) and re-derived
    /// inline by every observer that wanted to weight fallback
    /// attributions weaker than equality-based ones (dashboards,
    /// alerting policies, miette diagnostic renderers). Now it
    /// composes as one method call: `rule.confidence()`.
    ///
    /// When a new resolution rule lands as a [`Self`] variant, the
    /// exhaustive match below forces a confidence assignment in
    /// lockstep — the typescape pins the partition to one site, and
    /// the `attribution_rule_confidence_*` tests pin which side each
    /// rule sits on.
    #[must_use]
    pub fn confidence(self) -> AttributionConfidence {
        match self {
            Self::FileBySource | Self::FileByMetadataName | Self::EnvByPrefix => {
                AttributionConfidence::Exact
            }
            Self::EnvByUniqueness | Self::DefaultsByCodeUniqueness => {
                AttributionConfidence::Fallback
            }
        }
    }

    /// Returns `true` if this rule is equality-based; equivalent to
    /// `self.confidence() == AttributionConfidence::Exact`.
    #[must_use]
    pub fn is_exact(self) -> bool {
        matches!(self.confidence(), AttributionConfidence::Exact)
    }

    /// Returns `true` if this rule is uniqueness-based; equivalent to
    /// `self.confidence() == AttributionConfidence::Fallback`.
    #[must_use]
    pub fn is_fallback(self) -> bool {
        matches!(self.confidence(), AttributionConfidence::Fallback)
    }
}

/// Confidence class of an [`AttributionRule`].
///
/// Closed binary partition over the rule space:
/// [`AttributionRule::confidence`] is the canonical map. The shape
/// is named (rather than a `bool` flag) so consumers don't re-invent
/// `is_exact_attribution: bool` at every observation site, and so
/// future tertiary classifications (e.g. a `Heuristic` confidence
/// for resolver paths that combine equality with structural hints)
/// land as one new variant peer to the existing two.
///
/// `Copy + Eq + Hash + #[non_exhaustive]`, matching the typescape
/// discipline of the sibling primitives [`AttributionRule`],
/// [`FigmentSourceTag`], and [`crate::FigmentNameTag`]: closed,
/// allocation-free, extensible without breaking exhaustivity at
/// consumer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionConfidence {
    /// Equality-based attribution — `metadata.source` or
    /// `metadata.name` matched a recorded [`ConfigSource`] by exact
    /// equality (path, prefix). The substrate has high confidence
    /// the named layer is the actual source of the offending value.
    Exact,
    /// Uniqueness-based attribution — `metadata` did not match any
    /// recorded layer by equality, but exactly one layer of the
    /// matching kind exists in the chain, so it is named by
    /// elimination. The substrate has lower confidence; consumers
    /// (dashboards, miette diagnostic renderers, alerting policies)
    /// may want to weight or render this differently.
    Fallback,
}

/// Typed envelope returned by [`ShikumiError::failing_attribution`]:
/// the attributed [`ConfigSource`] and the [`AttributionRule`] that
/// produced the attribution.
///
/// The source borrows into the recorded chain so the envelope shares
/// the error's lifetime; the rule is `Copy`. Pair-struct over the
/// `(which-layer × why)` axis: the (where × what) failure surface
/// (chain × field-path) gains a third axis (rule) that pins the
/// attribution mechanism to one of the five typed cases in
/// [`AttributionRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FailingSourceAttribution<'a> {
    /// The recorded [`ConfigSource`] entry blamed for the failure.
    pub source: &'a ConfigSource,
    /// The rule under which `source` was attributed.
    pub rule: AttributionRule,
}

impl<'a> FailingSourceAttribution<'a> {
    fn new(source: &'a ConfigSource, rule: AttributionRule) -> Self {
        Self { source, rule }
    }

    /// Confidence class of [`Self::rule`]; convenience over
    /// [`AttributionRule::confidence`]. One method call answers
    /// "is the named layer attributed by equality or by elimination?"
    /// without destructuring the envelope.
    #[must_use]
    pub fn confidence(self) -> AttributionConfidence {
        self.rule.confidence()
    }
}

/// Map a figment error's per-value [`figment::Metadata`] back to the
/// specific [`ConfigSource`] in the recorded chain that produced the
/// offending value, alongside the [`AttributionRule`] that fired.
///
/// Returns a [`FailingSourceAttribution`] borrowed into `chain` so
/// callers share its lifetime. `None` when figment did not attach
/// metadata (e.g. an `Error::from(String)` constructed without a
/// provider context), or when the metadata cannot be matched to any
/// recorded entry under any rule.
///
/// Resolution rules, applied in order; the first that matches wins:
/// 1. [`AttributionRule::FileBySource`] — `metadata.source` classifies
///    (per [`FigmentSourceTag::classify`]) as
///    [`FigmentSourceTag::File`], and a [`ConfigSource::File`] entry's
///    path equals it.
/// 2. [`AttributionRule::FileByMetadataName`] — `metadata.name` matches
///    a shikumi-built provider's `"<format>: <path>"` shape (per
///    [`Format::strip_metadata_name`]), and a [`ConfigSource::File`]
///    entry's path equals the extracted path.
/// 3. [`AttributionRule::EnvByPrefix`] — `metadata.name` is env-tag
///    shaped with a prefix (per
///    [`ConfigSource::strip_env_metadata_name`] returning
///    [`EnvMetadataTag::Prefixed`]), and a [`ConfigSource::Env`]
///    entry's prefix matches case-insensitively.
/// 4. [`AttributionRule::EnvByUniqueness`] — `metadata.name` is env-tag
///    shaped (prefixed-without-match or bare), no prefix match in the
///    chain, and exactly one [`ConfigSource::Env`] entry exists.
/// 5. [`AttributionRule::DefaultsByCodeUniqueness`] — `metadata.source`
///    classifies as [`FigmentSourceTag::Code`], and exactly one
///    [`ConfigSource::Defaults`] entry exists.
fn resolve_failing_source<'a>(
    error: &figment::Error,
    chain: &'a [ConfigSource],
) -> Option<FailingSourceAttribution<'a>> {
    let md = error.metadata.as_ref()?;
    let source_tag = md.source.as_ref().and_then(FigmentSourceTag::classify);

    if let Some(FigmentSourceTag::File(p)) = source_tag
        && let Some(hit) = chain.iter().find(|s| s.as_path() == Some(p))
    {
        return Some(FailingSourceAttribution::new(
            hit,
            AttributionRule::FileBySource,
        ));
    }

    match FigmentNameTag::classify(md.name.as_ref()) {
        Some(FigmentNameTag::Format(tag)) => {
            if let Some(hit) = chain.iter().find(|s| s.as_path() == Some(tag.path)) {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::FileByMetadataName,
                ));
            }
        }
        Some(FigmentNameTag::Env(env_tag)) => {
            if let EnvMetadataTag::Prefixed(prefix_upper) = env_tag
                && let Some(hit) = chain.iter().find(|s| {
                    s.as_env_prefix()
                        .is_some_and(|p| p.eq_ignore_ascii_case(prefix_upper))
                })
            {
                return Some(FailingSourceAttribution::new(
                    hit,
                    AttributionRule::EnvByPrefix,
                ));
            }
            let mut envs = chain.iter().filter(|s| s.is_env());
            if let Some(only) = envs.next()
                && envs.next().is_none()
            {
                return Some(FailingSourceAttribution::new(
                    only,
                    AttributionRule::EnvByUniqueness,
                ));
            }
        }
        None => {}
    }

    if matches!(source_tag, Some(FigmentSourceTag::Code(_))) {
        let mut defaults = chain.iter().filter(|s| s.is_defaults());
        if let Some(only) = defaults.next()
            && defaults.next().is_none()
        {
            return Some(FailingSourceAttribution::new(
                only,
                AttributionRule::DefaultsByCodeUniqueness,
            ));
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
    ///
    /// Wraps [`Self::failing_attribution`], dropping the
    /// [`AttributionRule`]; callers that need to distinguish exact
    /// attribution (path / prefix equality) from fallback attribution
    /// (uniqueness in the chain) should use the envelope directly.
    #[must_use]
    pub fn failing_source(&self) -> Option<&ConfigSource> {
        self.failing_attribution().map(|a| a.source)
    }

    /// Returns the typed attribution envelope — the
    /// [`ConfigSource`] in the recorded chain blamed for the failure
    /// and the [`AttributionRule`] that produced the attribution — if
    /// attribution is possible.
    ///
    /// Strict superset of [`Self::failing_source`]: same `None`
    /// conditions, but on `Some` carries the rule alongside the source.
    /// Pair the rule with the source to render rule-aware structured
    /// diagnostics (e.g. mark fallback attributions like
    /// [`AttributionRule::EnvByUniqueness`] /
    /// [`AttributionRule::DefaultsByCodeUniqueness`] visibly weaker
    /// than equality-based ones), or to record per-failure attribution
    /// provenance in attestation manifests.
    ///
    /// Borrowed reference into the recorded chain, so the envelope
    /// shares this error's lifetime.
    #[must_use]
    pub fn failing_attribution(&self) -> Option<FailingSourceAttribution<'_>> {
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

    // ---- failing_attribution() / AttributionRule tests ----

    /// Synthesize a `figment::Error` pre-tagged with the given metadata
    /// name. Used to drive resolver paths that depend on
    /// `metadata.name`-shape (`FileByMetadataName`, `Env*`) without
    /// needing a live shikumi-built provider in the test process.
    fn synthetic_error_with_metadata_name(name: &'static str) -> Box<figment::Error> {
        let mut e = figment::Error::from("synth".to_owned());
        e.metadata = Some(figment::Metadata::named(name));
        Box::new(e)
    }

    #[test]
    fn failing_attribution_rule_file_by_source_for_yaml_extract() {
        // figment's built-in YAML provider attaches Source::File; the
        // resolver matches by path equality and reports FileBySource.
        let (dir, err) = extract_error_with_file_path_failure();
        let attr = err
            .failing_attribution()
            .expect("typed file failure must attribute");
        assert_eq!(attr.rule, AttributionRule::FileBySource);
        assert_eq!(
            attr.source.as_path(),
            Some(dir.path().join("typed.yaml").as_path())
        );
    }

    #[test]
    fn failing_attribution_rule_file_by_metadata_name_for_shikumi_provider() {
        // shikumi-built providers tag attribution via
        // `metadata.name = "<format>: <path>"`. The resolver inverts via
        // `Format::strip_metadata_name` and reports FileByMetadataName.
        let path = PathBuf::from("/etc/app/app.nix");
        let name = "nix: /etc/app/app.nix";
        let chain = vec![ConfigSource::Defaults, ConfigSource::File(path.clone())];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name(name),
        };
        let attr = err
            .failing_attribution()
            .expect("shikumi-provider tag must attribute");
        assert_eq!(attr.rule, AttributionRule::FileByMetadataName);
        assert_eq!(attr.source.as_path(), Some(path.as_path()));
    }

    #[test]
    fn failing_attribution_rule_env_by_prefix_when_chain_has_matching_env() {
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("MYAPP_".to_owned()),
            ConfigSource::Env("OTHER_".to_owned()),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`MYAPP_` environment variable(s)"),
        };
        let attr = err
            .failing_attribution()
            .expect("env-prefix tag must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByPrefix);
        assert_eq!(attr.source.as_env_prefix(), Some("MYAPP_"));
    }

    #[test]
    fn failing_attribution_rule_env_by_uniqueness_for_unmatched_prefix() {
        // Tag carries a prefix the chain doesn't record, but exactly one
        // Env entry exists — fall back to EnvByUniqueness on that entry.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`UNRELATED_` environment variable(s)"),
        };
        let attr = err
            .failing_attribution()
            .expect("unique-env fallback must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.source.as_env_prefix(), Some("ONLY_"));
    }

    #[test]
    fn failing_attribution_rule_env_by_uniqueness_for_bare_env_tag() {
        // Bare env tag (figment's Env::raw shape): no prefix to match;
        // unique Env entry wins via EnvByUniqueness.
        let chain = vec![ConfigSource::Env("BARE_".to_owned())];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("environment variable(s)"),
        };
        let attr = err.failing_attribution().expect("bare-env must attribute");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.source.as_env_prefix(), Some("BARE_"));
    }

    #[test]
    fn failing_attribution_rule_defaults_by_code_uniqueness_for_serialized() {
        // figment's Serialized provider attaches Source::Code; the
        // resolver dispatches to defaults-by-code-uniqueness when
        // exactly one Defaults layer is recorded.
        use crate::provider::ProviderChain;
        use serde::Serialize;
        #[derive(Serialize)]
        struct Bad {
            count: String, // typed mismatch when extracted as Cfg::count: u32
        }
        #[derive(serde::Deserialize, Debug)]
        struct Cfg {
            #[allow(dead_code)]
            count: u32,
        }
        let err = ProviderChain::new()
            .with_defaults(&Bad {
                count: "not_a_number".into(),
            })
            .extract::<Cfg>()
            .unwrap_err();
        let attr = err
            .failing_attribution()
            .expect("defaults-only failure must attribute");
        assert_eq!(attr.rule, AttributionRule::DefaultsByCodeUniqueness);
        assert!(attr.source.is_defaults());
    }

    #[test]
    fn failing_attribution_none_for_no_metadata() {
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::Defaults, ConfigSource::Env("X_".to_owned())],
            error: fake_figment_error(),
        };
        assert!(err.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_none_when_chain_lacks_matching_entry() {
        // metadata.name names a file the chain doesn't carry, and no
        // env / defaults fallback applies — must be None, not fabricated.
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::File(PathBuf::from("/other.yaml"))],
            error: synthetic_error_with_metadata_name("nix: /etc/app/app.nix"),
        };
        assert!(err.failing_attribution().is_none());
    }

    #[test]
    fn failing_attribution_borrows_into_chain() {
        // The envelope's source must be a sub-borrow of the recorded
        // chain — not a fresh allocation, not a clone.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("BORROWED_".to_owned()),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`BORROWED_` environment variable(s)"),
        };
        let ShikumiError::Extract {
            sources: ref recorded,
            ..
        } = err
        else {
            unreachable!();
        };
        let recorded_ptr = recorded.as_ptr();
        let attr = err.failing_attribution().expect("attribution");
        let attr_ptr = std::ptr::from_ref::<ConfigSource>(attr.source);
        // attr.source must point inside the recorded Vec (specifically,
        // at the second entry).
        unsafe {
            assert_eq!(attr_ptr, recorded_ptr.add(1));
        }
    }

    #[test]
    fn failing_source_agrees_with_failing_attribution_source() {
        // The legacy `failing_source` helper must equal the envelope's
        // `.source` field on every attributed Extract.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        let legacy = err.failing_source().expect("legacy attribution");
        assert!(std::ptr::eq(attr.source, legacy));
    }

    #[test]
    fn failing_attribution_rule_resolution_order_prefers_file_by_source_over_name() {
        // If both a Source::File classification and a metadata-name match
        // could resolve, the source-axis rule wins (it's tried first).
        // Synthesize a metadata that has *both* a Source::File pointing
        // at one chain entry and a name pointing at a *different* chain
        // entry — observe the source-axis rule fires.
        let path_a = PathBuf::from("/a/app.yaml");
        let path_b = PathBuf::from("/b/app.nix");
        let chain = vec![
            ConfigSource::File(path_a.clone()),
            ConfigSource::File(path_b.clone()),
        ];
        let mut e = figment::Error::from("synth".to_owned());
        let mut md = figment::Metadata::named("nix: /b/app.nix");
        md.source = Some(figment::Source::File(path_a.clone()));
        e.metadata = Some(md);
        let err = ShikumiError::Extract {
            sources: chain,
            error: Box::new(e),
        };
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::FileBySource);
        assert_eq!(attr.source.as_path(), Some(path_a.as_path()));
    }

    #[test]
    fn attribution_rule_is_copy_and_hashable() {
        // The enum is part of the typescape; the trait bounds match the
        // sibling primitives (FigmentSourceTag, EnvMetadataTag).
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributionRule::FileBySource);
        set.insert(AttributionRule::FileByMetadataName);
        set.insert(AttributionRule::EnvByPrefix);
        set.insert(AttributionRule::EnvByUniqueness);
        set.insert(AttributionRule::DefaultsByCodeUniqueness);
        assert_eq!(set.len(), 5);
        // Copy: rebind without move.
        let r = AttributionRule::FileBySource;
        let r2 = r;
        let r3 = r;
        assert_eq!(r, r2);
        assert_eq!(r2, r3);
    }

    // ---- AttributionConfidence / AttributionRule::confidence tests ----

    #[test]
    fn attribution_rule_confidence_exact_for_equality_rules() {
        // The three equality-based rules — file-path equality (both
        // axes) and env-prefix equality — must classify as Exact.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
        ] {
            assert_eq!(rule.confidence(), AttributionConfidence::Exact);
            assert!(rule.is_exact());
            assert!(!rule.is_fallback());
        }
    }

    #[test]
    fn attribution_rule_confidence_fallback_for_uniqueness_rules() {
        // The two uniqueness-based rules — env-by-uniqueness and
        // defaults-by-code-uniqueness — must classify as Fallback.
        for rule in [
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_eq!(rule.confidence(), AttributionConfidence::Fallback);
            assert!(rule.is_fallback());
            assert!(!rule.is_exact());
        }
    }

    #[test]
    fn attribution_rule_confidence_partitions_every_variant() {
        // Every AttributionRule variant must classify into exactly one
        // AttributionConfidence variant — no rule may be both exact and
        // fallback, none may be neither. Pins the partition contract
        // that the typescape lifts: a future variant added to
        // AttributionRule forces a confidence assignment in the
        // exhaustive match (compile-time), and this test pins the
        // resulting partition (test-time).
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            assert_ne!(
                rule.is_exact(),
                rule.is_fallback(),
                "rule {rule:?} must be exactly one of exact / fallback"
            );
        }
    }

    #[test]
    fn attribution_confidence_is_copy_and_hashable() {
        // Typescape bounds parity with sibling primitives.
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributionConfidence::Exact);
        set.insert(AttributionConfidence::Fallback);
        set.insert(AttributionConfidence::Exact); // duplicate
        assert_eq!(set.len(), 2);
        // Copy: rebind without move.
        let c = AttributionConfidence::Exact;
        let c2 = c;
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn failing_source_attribution_confidence_mirrors_rule_confidence() {
        // The envelope's confidence() method must agree with the
        // rule's, byte-for-byte, on every recognized rule. Pins the
        // contract that the convenience accessor stays a thin
        // forwarder.
        for rule in [
            AttributionRule::FileBySource,
            AttributionRule::FileByMetadataName,
            AttributionRule::EnvByPrefix,
            AttributionRule::EnvByUniqueness,
            AttributionRule::DefaultsByCodeUniqueness,
        ] {
            let src = ConfigSource::Defaults;
            let attr = FailingSourceAttribution::new(&src, rule);
            assert_eq!(attr.confidence(), rule.confidence());
        }
    }

    #[test]
    fn failing_attribution_confidence_exact_for_yaml_extract() {
        // End-to-end: a real YAML-file extract failure attributes via
        // FileBySource (Exact). The envelope's confidence accessor
        // must surface that without the consumer destructuring the
        // rule.
        let (_dir, err) = extract_error_with_file_path_failure();
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.confidence(), AttributionConfidence::Exact);
        assert!(attr.confidence() == attr.rule.confidence());
    }

    #[test]
    fn failing_attribution_confidence_fallback_for_unmatched_env_prefix() {
        // End-to-end: a synthetic env-prefixed metadata name with no
        // matching env prefix in the chain falls back to
        // EnvByUniqueness (Fallback). The envelope reports Fallback.
        let chain = vec![
            ConfigSource::Defaults,
            ConfigSource::Env("ONLY_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain,
            error: synthetic_error_with_metadata_name("`UNRELATED_` environment variable(s)"),
        };
        let attr = err.failing_attribution().expect("attribution");
        assert_eq!(attr.rule, AttributionRule::EnvByUniqueness);
        assert_eq!(attr.confidence(), AttributionConfidence::Fallback);
    }
}

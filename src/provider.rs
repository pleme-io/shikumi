//! Figment provider chain builder.
//!
//! Extracted from karakuri's `InnerConfig::from_figment`. Assembles a
//! layered figment configuration: defaults → env vars → config file,
//! with auto-detection of YAML vs TOML by file extension.

use std::path::Path;

use figment::{
    Error as FigmentError, Figment, Metadata, Profile,
    providers::{Env, Format as _, Serialized, Toml as FigToml, Yaml as FigYaml},
    value::{Dict, Map, Value},
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

/// End-to-end projection from a shikumi-built provider's [`ShikumiError`]-
/// bearing load result to the [`Map<Profile, Dict>`] shape
/// [`figment::Provider::data`] requires.
///
/// Fuses the two open-coded steps every shikumi-built provider's `data`
/// impl still carried after [`provider_data_from_value`] was lifted:
///
/// 1. Convert the [`ShikumiError`] returned by the provider's `load` into
///    a [`FigmentError`] via `FigmentError::from(err.to_string())` — the
///    same string projection every consumer of a shikumi Provider observes
///    through figment's own Display path.
/// 2. Route the resulting [`Value`] through [`provider_data_from_value`]
///    for the format-typed dict-required wording.
///
/// The two consumers today — [`crate::lisp_provider::LispProvider::data`]
/// (`lisp` feature) and [`crate::nix_provider::NixProvider::data`] — each
/// previously wrote the `.map_err(|e| FigmentError::from(e.to_string()))`
/// glue at the head of their `data()` body, immediately before the
/// [`provider_data_from_value`] call. Two open-coded conversions were two
/// places a future refinement of the [`ShikumiError`] → [`FigmentError`]
/// projection (structured spans, source-chain, miette-style annotations)
/// would have to be applied in lockstep, which is exactly the drift-class
/// this crate spends load-bearing lifts to close.
///
/// A future shikumi-built provider — an `HTTP` config endpoint, a `Vault`
/// secret store, a Kubernetes `ConfigMap` reader — implements its own
/// [`ShikumiError`]-bearing `load()` and routes `data()` through this
/// single helper, inheriting both the error-projection contract and the
/// format-typed dict-required wording by construction. Sharpening the
/// [`ShikumiError`] → [`FigmentError`] surface (adding [`figment::Error`]
/// spans, threading provenance) then lands at one site instead of once
/// per provider.
///
/// `format` is the same argument accepted by [`provider_data_from_value`]
/// — passed through so the dict-required wording agrees with the
/// metadata-name the provider's [`figment::Provider::metadata`] impl
/// already emits via [`Format::metadata_name`].
///
/// # Errors
///
/// Returns [`FigmentError`] if the load result was [`Err`]
/// (`ShikumiError` string-projected onto the figment error), OR if the
/// loaded [`Value`] is not a [`Value::Dict`] (format-typed dict-required
/// wording via [`provider_data_from_value`]).
// Same rationale as `provider_data_from_value` for the `result_large_err`
// silence: figment picks its error size; boxing would fork the helper's
// `Err` from the trait method's `Err` and force every call site to unbox
// at the trait boundary.
#[allow(clippy::result_large_err)]
pub(crate) fn provider_data_from_shikumi_load(
    result: Result<Value, ShikumiError>,
    format: Format,
) -> Result<Map<Profile, Dict>, FigmentError> {
    let value = result.map_err(|e| FigmentError::from(e.to_string()))?;
    provider_data_from_value(value, format)
}

/// Build the [`figment::Metadata`] a shikumi-built provider's
/// [`figment::Provider::metadata`] impl declares — the [`Format`]-typed
/// path→name projection wrapped in the [`Metadata::named`] shape figment
/// requires.
///
/// One source of truth for the metadata-construction shape shared by
/// every shikumi-built provider's `metadata` impl.
/// [`crate::lisp_provider::LispProvider::metadata`] (feature = "lisp",
/// `src/lisp_provider.rs`) and [`crate::nix_provider::NixProvider::metadata`]
/// each previously inlined the two-step
/// `Metadata::named(Format::X.metadata_name(&self.path))` construction —
/// two places a future refinement of the name-shape (structured spans,
/// source annotations, richer [`Metadata`] attributes) would have to be
/// applied in lockstep, which is exactly the drift-class this crate
/// spends load-bearing lifts to close. Idiom-peer of
/// [`provider_data_from_shikumi_load`], the sibling fusion helper that
/// closed the `data()`-body drift class; together they name both halves
/// of the shikumi-built provider's [`figment::Provider`] surface at one
/// site each.
///
/// The metadata-name round-trip contract remains: the emitted
/// [`Metadata::name`] equals what [`Format::metadata_name`] produces for
/// the same `(format, path)` pair, and therefore
/// [`Format::strip_metadata_name`] and [`Format::parse_metadata_tag`]
/// invert it back to the same `(format, path_display)` pair the provider
/// was constructed from. A future shikumi-built provider — an `HTTP`
/// config endpoint, a `Vault` secret store, a Kubernetes `ConfigMap`
/// reader — implements its `metadata()` by routing through this single
/// helper, inheriting the round-trip contract by construction.
///
/// `path` is the same [`Path`] the provider stores from its `file(...)`
/// constructor; passed by reference so no allocation happens beyond the
/// one [`Format::metadata_name`] itself performs.
#[must_use]
pub(crate) fn provider_metadata_for(format: Format, path: &Path) -> Metadata {
    Metadata::named(format.metadata_name(path))
}

/// Total mapping from a [`serde_json::Value`] to a [`figment::value::Value`].
///
/// The one-shot JSON → figment projection every shikumi-built provider
/// whose upstream renderer produces JSON routes through. Today
/// [`crate::nix_provider::NixProvider::load`] is the only consumer — it
/// shells out to `nix eval --json` and hands the parsed
/// [`serde_json::Value`] here. Sits beside the [`provider_data_from_value`]
/// / [`provider_data_from_shikumi_load`] / [`provider_metadata_for`]
/// substrate helpers for the exact same reason those exist: any future
/// shikumi-built provider whose upstream speaks JSON — a
/// [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
/// central-authority broadcast layer, an HTTP `/config` endpoint, a
/// Kubernetes `ConfigMap` reader whose values arrive as JSON strings, a
/// Vault secret store — routes its `load()` body through this single site
/// instead of open-coding the mapping a second time. A future sharpening
/// (source spans threaded via [`figment::value::Tag`], structured
/// provenance for the number arm, a compact-string path for repeated
/// keys) then lands at one site instead of once per provider.
///
/// # Number arm precision
///
/// A [`serde_json::Number`] can outlive an [`i64`]: JSON permits any
/// integer up to 20-plus digits, and `serde_json` will happily materialise
/// `18_446_744_073_709_551_615` as its internal `u64` inhabitant. The
/// helper preserves that precision by trying [`serde_json::Number::as_i64`]
/// first (which covers negatives and the whole `i64` range), then
/// [`serde_json::Number::as_u64`] (which covers `i64::MAX + 1 ..= u64::MAX`
/// — a range the [`i64`]-only path fell through to lossy [`f64`] on),
/// then [`serde_json::Number::as_f64`] as the true float arm. The `f64`
/// arm is total on `serde_json::Number` per its docs (a JSON number is
/// always representable as an `f64`, with possible loss for integers
/// outside `[-2^53, 2^53]`), so no third fallback is reachable — an
/// unreachable arm here would silently swallow a future format-level bug
/// under a default value. The pre-lift version of this helper carried
/// exactly that trap: a `Value::from(0i64)` catch-all sat behind an
/// `as_i64` → `as_f64` cascade, so any `u64` above `i64::MAX` lost
/// precision to the `f64` arm instead of surfacing on the natively-typed
/// path figment already supports (`Value::from(u64)` exists — see
/// [`figment::value::Num::U64`]).
///
/// # Value-variant mapping
///
/// - `Null` → `Value::Empty(Tag::Default, Empty::None)` — figment has no
///   dedicated JSON-null inhabitant; `Empty::None` is the canonical
///   `Option::None` counterpart the deserializer already expects.
/// - `Bool` → `Value::Bool`.
/// - `Number` → `Value::Num`, per the precision cascade above.
/// - `String` → `Value::String`.
/// - `Array` → `Value::Array`, recursively via this same helper.
/// - `Object` → `Value::Dict`, recursively via this same helper.
///
/// The recursion is a homomorphism on the JSON tree: every scalar leaf
/// maps pointwise to its figment counterpart with no reordering,
/// dropping, or synthesis of intermediate structure. The
/// `json_value_to_figment_is_pointwise_homomorphic_on_nested_shapes` test
/// pins that pointwise contract; the number-arm precision tests pin the
/// u64/i64/float boundaries.
pub(crate) fn json_value_to_figment(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => {
            Value::Empty(figment::value::Tag::Default, figment::value::Empty::None)
        }
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                // Preserves precision for JSON integers in
                // (i64::MAX, u64::MAX] — the pre-lift `as_i64() -> as_f64()`
                // cascade lost these to lossy floats.
                Value::from(u)
            } else if let Some(f) = n.as_f64() {
                Value::from(f)
            } else {
                // Unreachable per `serde_json::Number::as_f64`'s docs: a
                // JSON number is always representable as an `f64`. Emit
                // `Empty::None` rather than a silent `0` so a future
                // format-level bug would surface as a missing key rather
                // than a wrong-but-plausible value.
                Value::Empty(figment::value::Tag::Default, figment::value::Empty::None)
            }
        }
        serde_json::Value::String(s) => Value::from(s.clone()),
        serde_json::Value::Array(items) => Value::Array(
            figment::value::Tag::Default,
            items.iter().map(json_value_to_figment).collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut dict = Dict::new();
            for (k, v) in map {
                dict.insert(k.clone(), json_value_to_figment(v));
            }
            Value::Dict(figment::value::Tag::Default, dict)
        }
    }
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

    /// Merge an environment-**discovered** partial config as the discovered
    /// tier.
    ///
    /// The discovered tier sits *above* serde/prescribed defaults and *below*
    /// operator file/env config: call it after [`Self::with_defaults`] and
    /// before [`Self::with_env`] / [`Self::with_file`]. The **load-bearing
    /// guarantee** is that the discovered tier is below *both* env and file;
    /// their mutual order then follows shikumi's own convention (file merged
    /// last wins, per [`Self::with_file`]'s "defaults → env → file" pattern):
    ///
    /// ```text
    /// serde/prescribed defaults → DISCOVERED → env → file   (later wins per key)
    /// ```
    ///
    /// `dict` is typically [`crate::discovered::compose`]d from a stack of
    /// [`crate::discovered::DiscoveryLayer`]s. Merged with figment's deep
    /// per-key semantics (the same `Serialized::defaults(_).merge()` mechanism
    /// as [`Self::with_defaults`]), so it overrides the developer's defaults
    /// only on the keys it actually sets.
    ///
    /// Provenance is recorded as [`ConfigSource::Defaults`] — the discovered
    /// tier is a *computed-defaults* layer (the same class as serde defaults:
    /// machine-derived, not operator-supplied). A dedicated `Discovered`
    /// provenance variant is a deliberate future refinement (it would thread
    /// through the attribution typescape); recording it as `Defaults` keeps the
    /// layer-kind partition honest today.
    ///
    /// **Precondition — do not wire this into a [`crate::ConfigStore`] *reload*
    /// path yet.** Reload replays the recorded [`ConfigSource`] chain through
    /// [`Self::with_source`], where `Defaults` is the identity (it carries no
    /// reconstructable value). A discovered layer recorded as `Defaults` would
    /// therefore be **dropped on reload**. This primitive is for *direct* chain
    /// construction (compute the dict, merge it each build); a reload-stable
    /// `ConfigStore` integration must first land the `Discovered` provenance
    /// variant so the layer survives replay.
    #[must_use]
    pub fn with_discovered(mut self, dict: Dict) -> Self {
        self.figment = self.figment.merge(Serialized::defaults(&dict));
        self.sources.push(ConfigSource::Defaults);
        self
    }

    /// Compose a stack of [`crate::discovered::DiscoveryLayer`]s and merge the
    /// result as the discovered tier — convenience over
    /// [`crate::discovered::compose`] + [`Self::with_discovered`].
    #[must_use]
    pub fn with_discovery_layers(self, layers: &[&dyn crate::discovered::DiscoveryLayer]) -> Self {
        self.with_discovered(crate::discovered::compose(layers))
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
            Some(Format::Blue) => {
                // Gated INSIDE the arm, exactly as `Lisp` above: a `.b` file
                // on a build without the feature is a warning and a skipped
                // layer, not a hard error. Erroring would make an optional
                // dependency load-bearing for anyone who merely has a `.b`
                // sitting in a config directory.
                #[cfg(feature = "blue")]
                {
                    self.figment = self
                        .figment
                        .merge(crate::blue_provider::BlueProvider::file(path));
                }
                #[cfg(not(feature = "blue"))]
                {
                    tracing::warn!(
                        path = %path.display(),
                        "shikumi built without the `blue` feature; skipping .b config. \
                         Enable the feature or convert to .yaml/.toml/.lisp/.nix."
                    );
                }
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

    // ---- discovered tier (with_discovered / with_discovery_layers) ----

    #[test]
    fn discovered_overrides_defaults_per_key() {
        let mut d = Dict::new();
        d.insert("name".to_owned(), Value::from("from_discovered"));
        let defaults = TestConfig {
            name: Some("dev_default".into()),
            count: Some(5),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_discovered(d)
            .extract()
            .unwrap();
        assert_eq!(
            config.name.as_deref(),
            Some("from_discovered"),
            "discovered beats developer defaults"
        );
        assert_eq!(
            config.count,
            Some(5),
            "key the discovered layer didn't set keeps the default"
        );
    }

    #[test]
    fn file_and_env_both_override_discovered() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("over.yaml");
        fs::write(&file, "name: from_file\n").unwrap();
        let var = "SHIKUMI_DISC_COUNT";
        unsafe { std::env::set_var(var, "9") };

        let mut d = Dict::new();
        d.insert("name".to_owned(), Value::from("from_discovered"));
        d.insert("count".to_owned(), Value::from(1i64));

        // defaults → discovered → env → file: operator layers (file, env) win.
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&TestConfig::default())
            .with_discovered(d)
            .with_env("SHIKUMI_DISC_")
            .with_file(&file)
            .extract()
            .unwrap();
        unsafe { std::env::remove_var(var) };
        assert_eq!(
            config.name.as_deref(),
            Some("from_file"),
            "file beats discovered"
        );
        assert_eq!(config.count, Some(9), "env beats discovered");
    }

    #[test]
    fn empty_discovered_is_noop_over_defaults() {
        let defaults = TestConfig {
            name: Some("keep".into()),
            count: Some(7),
        };
        let config: TestConfig = ProviderChain::new()
            .with_defaults(&defaults)
            .with_discovered(Dict::new())
            .extract()
            .unwrap();
        assert_eq!(config.name.as_deref(), Some("keep"));
        assert_eq!(config.count, Some(7));
    }

    #[test]
    fn discovered_records_defaults_class_provenance() {
        let chain = ProviderChain::new().with_discovered(Dict::new());
        assert_eq!(chain.sources(), &[ConfigSource::Defaults]);
    }

    #[test]
    fn with_discovery_layers_composes_specific_over_coarse() {
        use crate::discovered::DiscoveryLayer;

        struct Layer(&'static str, &'static str);
        impl DiscoveryLayer for Layer {
            fn name(&self) -> &'static str {
                "test"
            }
            fn discover(&self) -> Dict {
                let mut d = Dict::new();
                d.insert(self.0.to_owned(), Value::from(self.1));
                d
            }
        }

        let coarse = Layer("name", "coarse");
        let specific = Layer("name", "specific");
        let config: TestConfig = ProviderChain::new()
            .with_discovery_layers(&[&coarse, &specific])
            .extract()
            .unwrap();
        assert_eq!(
            config.name.as_deref(),
            Some("specific"),
            "later (more-specific) layer wins under composition"
        );
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

    // ---- provider_data_from_shikumi_load (load-result -> Map projection) ----
    //
    // These tests pin the end-to-end fusion helper that
    // `LispProvider::data` / `NixProvider::data` route through: the
    // `.map_err(|e| FigmentError::from(e.to_string()))` glue that used to
    // live at the head of each `data()` body now happens at one site here,
    // and the format-typed dict-required wording is delegated to
    // `provider_data_from_value` (already pinned above). A future shikumi-
    // built provider inherits both projections by routing its `data()`
    // through this single helper — that's the compounding lift.

    #[test]
    fn provider_data_from_shikumi_load_forwards_ok_dict_verbatim() {
        // Ok(Dict) → same `{ Profile::Default => dict }` shape the
        // downstream `provider_data_from_value` helper emits — the
        // fusion helper must be a pointwise-equal composition on the
        // success path.
        let mut inner = Dict::new();
        inner.insert("k".to_owned(), Value::from("v"));
        let value = Value::Dict(figment::value::Tag::Default, inner.clone());

        let via_fusion = provider_data_from_shikumi_load(Ok(value.clone()), Format::Lisp)
            .expect("Ok(Dict) must succeed via the fusion helper");
        let via_direct = provider_data_from_value(value, Format::Lisp)
            .expect("Ok(Dict) must succeed via the direct helper");
        assert_eq!(
            via_fusion, via_direct,
            "fusion path must equal direct path on Ok(Dict)",
        );
        assert_eq!(via_fusion.len(), 1, "exactly one profile entry");
        assert_eq!(
            via_fusion.get(&Profile::Default),
            Some(&inner),
            "inner dict preserved verbatim under Profile::Default",
        );
    }

    #[test]
    fn provider_data_from_shikumi_load_projects_err_via_display() {
        // Err(ShikumiError) is projected through the same string surface
        // every consumer of a shikumi Provider observes today —
        // `FigmentError::from(err.to_string())` — so the fusion helper
        // must emit exactly what the open-coded `.map_err` would.
        let err = ShikumiError::Parse("boom".into());
        let expected = err.to_string();

        let fig_err =
            provider_data_from_shikumi_load(Err(err), Format::Lisp).expect_err("Err must project");
        assert_eq!(
            fig_err.to_string(),
            expected,
            "the projected FigmentError must Display exactly like the source ShikumiError",
        );
    }

    #[test]
    fn provider_data_from_shikumi_load_delegates_non_dict_wording_to_format_helper() {
        // Ok(non-Dict) → the downstream helper's format-typed
        // dict-required wording must reach the operator verbatim. Pins
        // that the fusion helper does not re-word or wrap the message
        // — the shape must start with `Format::X.dict_required_message()`
        // and append `"; got <Value:?>"` for every format.
        let probe = Value::Empty(figment::value::Tag::Default, figment::value::Empty::None);
        for format in [Format::Yaml, Format::Toml, Format::Lisp, Format::Nix] {
            let err = provider_data_from_shikumi_load(Ok(probe.clone()), format)
                .expect_err("Ok(non-Dict) must error via the fusion helper");
            let msg = err.to_string();
            let prefix = format.dict_required_message();
            assert!(
                msg.starts_with(prefix),
                "{format:?}: fusion-helper message must start with `{prefix}`, got `{msg}`",
            );
            assert!(
                msg.contains("; got "),
                "{format:?}: fusion-helper message must append `; got <Value>` tail, got `{msg}`",
            );
        }
    }

    #[test]
    // The open-coded arm this test re-runs is exactly the arm we lifted
    // away, and reconstructing it is what pins the fusion helper to
    // pointwise-equal semantics; silence the closure-Err-size pedantic
    // hit at the one call site — same rationale as the production
    // helper's `#[allow]` above, and confined to test scope.
    #[allow(clippy::result_large_err)]
    fn provider_data_from_shikumi_load_agrees_with_open_coded_composition() {
        // Pointwise-equal composition pin: for every load result the
        // fusion helper's output must equal what the two open-coded
        // steps produced verbatim — `.map_err(...)` then
        // `provider_data_from_value`. This is the drift-closure the
        // lift exists for. `ShikumiError` intentionally does not derive
        // `Clone`, so each case is a thunk that mints a fresh
        // `Result<Value, ShikumiError>` per invocation instead of a
        // cloneable value.
        #[allow(clippy::type_complexity)]
        let cases: [(&str, fn() -> Result<Value, ShikumiError>); 3] = [
            ("Ok(Dict)", || {
                let mut inner = Dict::new();
                inner.insert("x".to_owned(), Value::from(1i64));
                Ok(Value::Dict(figment::value::Tag::Default, inner))
            }),
            ("Err(ShikumiError)", || {
                Err(ShikumiError::Parse("nix eval failed".into()))
            }),
            ("Ok(non-Dict)", || {
                Ok(Value::Array(
                    figment::value::Tag::Default,
                    vec![Value::from(2i64)],
                ))
            }),
        ];

        for (label, mk) in cases {
            for format in [Format::Lisp, Format::Nix] {
                let via_fusion = provider_data_from_shikumi_load(mk(), format);
                let via_open_coded = mk()
                    .map_err(|e| FigmentError::from(e.to_string()))
                    .and_then(|value| provider_data_from_value(value, format));

                match (via_fusion, via_open_coded) {
                    (Ok(a), Ok(b)) => assert_eq!(
                        a, b,
                        "{label}/{format:?}: fusion Ok must equal open-coded Ok",
                    ),
                    (Err(a), Err(b)) => assert_eq!(
                        a.to_string(),
                        b.to_string(),
                        "{label}/{format:?}: fusion Err message must equal open-coded Err message",
                    ),
                    (a, b) => panic!(
                        "{label}/{format:?}: fusion and open-coded disagree on Ok/Err arm: \
                         fusion={a:?}, open_coded={b:?}",
                    ),
                }
            }
        }
    }

    // ---- provider_metadata_for (Format × Path -> Metadata construction) ----
    //
    // The `metadata()` half of the shikumi-built provider surface. Before
    // this lift `LispProvider::metadata` and `NixProvider::metadata` each
    // open-coded `Metadata::named(Format::X.metadata_name(&self.path))`
    // — two places a future refinement of the metadata-name shape would
    // have to be applied in lockstep. The helper closes that drift class;
    // these tests pin the closure at the fusion site so the two call
    // sites remain a pointwise-equal composition and the round-trip
    // through `Format::strip_metadata_name` / `parse_metadata_tag` is
    // preserved by construction.

    #[test]
    fn provider_metadata_for_agrees_with_open_coded_composition_pointwise() {
        // For every shikumi-built format the helper's output must
        // exactly equal what the two open-coded steps produced:
        // `Metadata::named(format.metadata_name(&path))`. The equality
        // is on `Metadata::name` (the only field either construction
        // sets), and it must hold across the full path shape that
        // reaches a real provider — absolute-with-extension,
        // relative-no-parent, and empty are the three concrete corners
        // `LispProvider::file` / `NixProvider::file` will accept.
        let paths: [&Path; 3] = [
            Path::new("/etc/app/app.lisp"),
            Path::new("relative.nix"),
            Path::new(""),
        ];
        for format in [Format::Lisp, Format::Nix] {
            for path in paths {
                let via_helper = provider_metadata_for(format, path);
                let via_open_coded = Metadata::named(format.metadata_name(path));
                assert_eq!(
                    via_helper.name, via_open_coded.name,
                    "{format:?}/{path:?}: helper Metadata::name must equal open-coded name",
                );
            }
        }
    }

    #[test]
    fn provider_metadata_for_round_trips_through_strip_metadata_name() {
        // The whole point of the metadata name is that it inverts:
        // `Format::strip_metadata_name` must recover `(format, path_display)`
        // from the helper's output for every shikumi-built format.
        // Pinning it at the fusion site guarantees that a future
        // shikumi-built provider routing its `metadata()` through the
        // helper inherits the round-trip contract by construction.
        let path = Path::new("/var/lib/app/conf.lisp");
        for format in [Format::Lisp, Format::Nix] {
            let md = provider_metadata_for(format, path);
            let (recovered_format, rest) = Format::strip_metadata_name(md.name.as_ref())
                .unwrap_or_else(|| panic!("{format:?}: metadata name must round-trip"));
            assert_eq!(
                recovered_format, format,
                "{format:?}: strip_metadata_name must recover the constructor format",
            );
            assert_eq!(
                rest,
                path.display().to_string(),
                "{format:?}: strip_metadata_name must recover the constructor path display",
            );
        }
    }

    #[test]
    fn provider_metadata_for_round_trips_through_parse_metadata_tag() {
        // Idiom-peer of the `strip_metadata_name` round-trip test:
        // `Format::parse_metadata_tag` is the typed-envelope inverse of
        // `Format::metadata_name`, and the helper's output must
        // invert through it to a `FormatMetadataTag` whose `(format, path)`
        // pair equals the constructor `(format, &path)` pair — the same
        // load-bearing contract, expressed on the typed surface.
        let path = Path::new("/opt/app/conf.nix");
        for format in [Format::Lisp, Format::Nix] {
            let md = provider_metadata_for(format, path);
            let tag = Format::parse_metadata_tag(md.name.as_ref())
                .unwrap_or_else(|| panic!("{format:?}: metadata name must parse to a typed tag"));
            assert_eq!(
                tag.format, format,
                "{format:?}: parse_metadata_tag must recover the constructor format",
            );
            assert_eq!(
                tag.path,
                Path::new(&path.display().to_string()),
                "{format:?}: parse_metadata_tag must recover the constructor path",
            );
        }
    }

    // ---- json_value_to_figment (serde_json::Value -> figment::Value) ----
    //
    // The JSON → figment homomorphism NixProvider's `load()` body routes
    // through — and the substrate a future JSON-transport provider
    // (ConfigPlane broadcast, HTTP config endpoint, Kubernetes ConfigMap
    // JSON-valued key) inherits. These tests pin two invariants at the
    // fusion site:
    //
    //   1. The number arm preserves precision across the whole JSON
    //      integer range, including the (i64::MAX, u64::MAX] slice that
    //      the pre-lift version lost to lossy `f64` — a real behavior
    //      sharpening, not just a refactor.
    //   2. The compound-arm recursion is a pointwise homomorphism: the
    //      figment tree agrees with the JSON tree shape-for-shape, so a
    //      caller reasoning about JSON structure keeps that reasoning at
    //      the figment layer.

    #[test]
    fn json_value_to_figment_maps_null_to_empty_none() {
        // `Empty::None` is figment's canonical `Option::None` counterpart;
        // there is no dedicated JSON-null inhabitant, so the mapping must
        // land here for a downstream deserializer that models nullable
        // fields as `Option<T>` to see the absence.
        let out = json_value_to_figment(&serde_json::Value::Null);
        assert!(
            matches!(out, Value::Empty(_, figment::value::Empty::None)),
            "Null must map to Value::Empty(_, Empty::None), got {out:?}",
        );
    }

    #[test]
    fn json_value_to_figment_bool_round_trips_both_polarities() {
        // Both polarities land in `Value::Bool` verbatim — pins that the
        // helper does not swap sign or emit a numeric coercion.
        for b in [true, false] {
            let out = json_value_to_figment(&serde_json::Value::Bool(b));
            let Value::Bool(_, got) = out else {
                panic!("Bool({b}) must map to Value::Bool, got {out:?}");
            };
            assert_eq!(got, b, "Bool polarity must survive");
        }
    }

    #[test]
    fn json_value_to_figment_string_round_trips_verbatim() {
        // The string arm clones the underlying `String`; the mapped
        // Value must Display exactly the same bytes.
        for probe in ["", "ascii", "unicode-仕組み", "with\nnewline"] {
            let out = json_value_to_figment(&serde_json::Value::String(probe.to_owned()));
            let Value::String(_, got) = out else {
                panic!("String({probe:?}) must map to Value::String, got {out:?}");
            };
            assert_eq!(got, probe, "String bytes must survive");
        }
    }

    #[test]
    fn json_value_to_figment_preserves_negative_i64() {
        // Pins the negative-integer branch: `as_i64()` covers the whole
        // signed range including `i64::MIN`. Regression guard against a
        // future refactor that reorders the number arm and lands
        // `as_u64()` first (which would return `None` for negatives and
        // silently fall through to lossy `f64`).
        for probe in [-1i64, -42, i64::MIN, i64::MIN + 1] {
            let json = serde_json::Value::Number(serde_json::Number::from(probe));
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            let via_i128 = got.to_i128().unwrap_or_else(|| {
                panic!("Num({probe}) must round-trip through to_i128, got {got:?}")
            });
            assert_eq!(via_i128, i128::from(probe), "signed integer must survive");
        }
    }

    #[test]
    fn json_value_to_figment_preserves_u64_above_i64_max() {
        // The load-bearing sharpening: JSON integers in
        // (i64::MAX, u64::MAX] must land in `Value::Num(_, Num::U64(_))`
        // (or a numerically-equivalent unsigned width) — the pre-lift
        // cascade tried `as_i64()` then jumped straight to `as_f64()`,
        // silently losing precision for any value above 2^53 and
        // rounding away exact bits above 2^63 entirely. `u64::MAX` is
        // the sharpest probe: an `f64` round-trip loses ~10 low bits.
        //
        // Pin both `i64::MAX + 1` (the boundary the pre-lift version
        // began losing) and `u64::MAX` (the loudest failure case).
        let probes: [u64; 3] = [(i64::MAX as u64) + 1, (i64::MAX as u64) + 42, u64::MAX];
        for probe in probes {
            let json = serde_json::Value::Number(serde_json::Number::from(probe));
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            // `Num::to_u128` returns `Some` **only for the unsigned Num
            // variants** (per figment's own docs: `Num::U8..=U128`, `USize`
            // — a signed or float variant returns `None`). This is
            // therefore the sharpest available structural probe that the
            // JSON `u64` landed in a genuinely unsigned Num rather than
            // being funneled through the lossy `f64` arm the pre-lift
            // cascade fell to.
            let via_u128 = got.to_u128().unwrap_or_else(|| {
                panic!(
                    "Num({probe}) must land in an unsigned Num variant \
                     (to_u128 must be Some), got {got:?} — regression: \
                     pre-lift `as_i64() -> as_f64()` cascade lost u64 \
                     values above i64::MAX to lossy f64",
                )
            });
            assert_eq!(
                via_u128,
                u128::from(probe),
                "u64 above i64::MAX must survive without precision loss",
            );
        }
    }

    #[test]
    fn json_value_to_figment_preserves_f64_when_json_is_float() {
        // The float arm is the true last-resort: it must fire only when
        // the JSON number is a genuine float (has a fractional part or
        // is a scientific-notation literal), and it must preserve the
        // exact f64 bits.
        for probe in [0.0f64, -2.5, 1e20, f64::MIN_POSITIVE, f64::EPSILON] {
            let json = serde_json::Value::Number(
                serde_json::Number::from_f64(probe)
                    .unwrap_or_else(|| panic!("probe {probe} must round-trip through serde_json")),
            );
            let out = json_value_to_figment(&json);
            let Value::Num(_, got) = out else {
                panic!("Number({probe}) must map to Value::Num, got {out:?}");
            };
            let as_f64 = got
                .to_f64()
                .unwrap_or_else(|| panic!("Num({probe}) must be a float variant, got {got:?}"));
            assert!(
                (as_f64 - probe).abs() <= f64::EPSILON.max(probe.abs() * f64::EPSILON),
                "float must survive f64 arm: sent {probe}, got {as_f64}",
            );
        }
    }

    #[test]
    fn json_value_to_figment_object_dispatches_to_dict() {
        // The object arm must produce a `Value::Dict` whose keys are the
        // JSON keys verbatim (no case-folding, no reordering into an
        // implicit iteration order) — the same expectation the shared
        // `provider_data_from_value` helper further downstream imposes.
        let json: serde_json::Value =
            serde_json::from_str(r#"{"alpha":1,"beta":true,"gamma":null,"delta":"d"}"#).unwrap();
        let out = json_value_to_figment(&json);
        let Value::Dict(_, d) = out else {
            panic!("Object must map to Value::Dict, got {out:?}");
        };
        for k in ["alpha", "beta", "gamma", "delta"] {
            assert!(d.contains_key(k), "key `{k}` must survive verbatim");
        }
        assert!(matches!(d.get("alpha"), Some(Value::Num(_, _))));
        assert!(matches!(d.get("beta"), Some(Value::Bool(_, true))));
        assert!(matches!(
            d.get("gamma"),
            Some(Value::Empty(_, figment::value::Empty::None)),
        ));
        assert!(matches!(d.get("delta"), Some(Value::String(_, _))));
    }

    #[test]
    fn json_value_to_figment_array_dispatches_to_array_pointwise() {
        // The array arm must map pointwise: `arr[i]` at the JSON layer
        // becomes the mapped-value at the same index in the figment
        // `Value::Array`. Empty array must survive as an empty
        // `Value::Array`, not degrade to `Value::Empty`.
        let empty = json_value_to_figment(&serde_json::Value::Array(vec![]));
        let Value::Array(_, items) = empty else {
            panic!("empty Array must map to Value::Array, got {empty:?}");
        };
        assert!(items.is_empty(), "empty array must survive as empty Array");

        let mixed: serde_json::Value =
            serde_json::from_str(r#"[1,"two",true,null,[3,4]]"#).unwrap();
        let out = json_value_to_figment(&mixed);
        let Value::Array(_, items) = out else {
            panic!("mixed Array must map to Value::Array, got {out:?}");
        };
        assert_eq!(items.len(), 5, "arity must survive");
        assert!(matches!(items[0], Value::Num(_, _)));
        assert!(matches!(items[1], Value::String(_, _)));
        assert!(matches!(items[2], Value::Bool(_, true)));
        assert!(matches!(
            items[3],
            Value::Empty(_, figment::value::Empty::None)
        ));
        assert!(matches!(items[4], Value::Array(_, _)));
    }

    #[test]
    fn json_value_to_figment_is_pointwise_homomorphic_on_nested_shapes() {
        // The recursion must be a homomorphism: for a deeply-nested
        // JSON tree the mapped figment tree agrees leaf-by-leaf. Pins
        // that the helper does not flatten, reorder, drop, or synthesize
        // structure — a `dict[a][b][c] = 42` in JSON reaches the
        // deserializer as the exact same key-path with the same integer
        // value. This is the load-bearing property NixProvider's tests
        // implicitly relied on but did not name.
        let json: serde_json::Value = serde_json::from_str(
            r#"{
              "outer": {
                "middle": {
                  "inner": {
                    "n_i64": -7,
                    "n_u64_over_i64_max": 18446744073709551610,
                    "n_float": 3.5,
                    "list": [1, 2, [3, 4]],
                    "empty_list": [],
                    "empty_obj": {},
                    "null_leaf": null
                  }
                }
              }
            }"#,
        )
        .unwrap();
        let out = json_value_to_figment(&json);
        let Value::Dict(_, top) = out else {
            panic!("top must be Dict");
        };
        let Value::Dict(_, mid) = top.get("outer").expect("outer").clone() else {
            panic!("outer must be Dict");
        };
        let Value::Dict(_, inner_wrap) = mid.get("middle").expect("middle").clone() else {
            panic!("middle must be Dict");
        };
        let Value::Dict(_, inner) = inner_wrap.get("inner").expect("inner").clone() else {
            panic!("inner must be Dict");
        };

        // Negative integer preserved as signed.
        let Value::Num(_, signed_leaf) = inner.get("n_i64").expect("n_i64").clone() else {
            panic!("n_i64 must be Num");
        };
        assert_eq!(signed_leaf.to_i128(), Some(-7));

        // u64 above i64::MAX preserved losslessly.
        let Value::Num(_, unsigned_leaf) = inner
            .get("n_u64_over_i64_max")
            .expect("n_u64_over_i64_max")
            .clone()
        else {
            panic!("n_u64_over_i64_max must be Num");
        };
        // `to_u128` returns `Some` only for the unsigned Num variants,
        // so this asserts BOTH the value survived losslessly AND the
        // number arm reached the u64 leg of the cascade (not the lossy
        // f64 arm the pre-lift cascade fell to for u64 > i64::MAX).
        assert_eq!(
            unsigned_leaf.to_u128(),
            Some(18_446_744_073_709_551_610u128),
        );

        // Float survives the f64 arm.
        let Value::Num(_, n_float) = inner.get("n_float").expect("n_float").clone() else {
            panic!("n_float must be Num");
        };
        assert!(matches!(n_float, figment::value::Num::F64(_)));

        // Nested list preserves inner arity.
        let Value::Array(_, list) = inner.get("list").expect("list").clone() else {
            panic!("list must be Array");
        };
        assert_eq!(list.len(), 3);
        let Value::Array(_, inner_pair) = list[2].clone() else {
            panic!("list[2] must be nested Array");
        };
        assert_eq!(inner_pair.len(), 2);

        // Empty compound values survive as their compound counterparts.
        assert!(matches!(
            inner.get("empty_list"),
            Some(Value::Array(_, v)) if v.is_empty(),
        ));
        assert!(matches!(
            inner.get("empty_obj"),
            Some(Value::Dict(_, d)) if d.is_empty(),
        ));

        // Null leaf lands in `Empty::None`.
        assert!(matches!(
            inner.get("null_leaf"),
            Some(Value::Empty(_, figment::value::Empty::None)),
        ));
    }
}

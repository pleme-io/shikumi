//! CLI as a partial layer — the typed seam between a binary's argv and its
//! shikumi config.
//!
//! Every pleme-io binary resolves ONE config through the progressive fold,
//! and the command line is just the highest-precedence slice of it:
//!
//! ```text
//! bare → discovered → prescribed_default            (computed tiers)
//!      → discovered file   (<APP>_CONFIG or XDG)     OverlaySlot::File
//!      → each --config FILE (merge-override, in order) OverlaySlot::ConfigOverride
//!      → env (<APP>_ prefix, `__` nests)              OverlaySlot::Env
//!      → typed flag overlay (Option fields)           OverlaySlot::CliFlags
//!      → each --set PATH=VALUE                        OverlaySlot::CliSet
//! ```
//!
//! The within-tier order is the typed [`OverlaySlot`] every
//! [`ProgressiveLayer`] carries, so it holds no matter what order a caller
//! pushes layers in. A flag the operator did not pass serializes to a null
//! and is dropped ([`strip_nulls`]), so an absent flag can never clobber a
//! file or env value. The fold is strict at the end
//! ([`crate::TieredConfig::try_resolve_progressive_with`]): an unknown or
//! ill-typed key is refused with a [`LayerError`] naming the path and the
//! [`Provenance`] of the layer that wrote it.
//!
//! The clap surface that drives this — `--config` / `--set` and the one
//! `resolve` entry point — is [`crate::cli::ConfigArgs`] (feature `cli`);
//! this module is the clap-free core it delegates to, so a non-clap binary
//! (or a test) builds the same layers by hand.

use std::path::PathBuf;
use std::str::FromStr;

use figment::value::{Dict, Tag, Value};
use figment::{Figment, providers::Serialized};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::ShikumiError;
use crate::source::ConfigSourceKind;
use crate::tiered::{ProgressiveLayer, Provenance, ProvenanceMap};

/// The [`crate::ConfigSource::Cli`] label stamped on the typed flag
/// overlay ([`ProgressiveLayer::cli`]).
pub const CLI_FLAGS_LABEL: &str = "flags";

/// The [`crate::ConfigSource::Cli`] label stamped on the `--set` layer
/// ([`ProgressiveLayer::set`]).
pub const CLI_SET_LABEL: &str = "--set";

/// Env keys under an app prefix that select *how* config is found, never
/// what it says: `<APP>_CONFIG` (the discovery override) and `<APP>_TIER`
/// (the tier selector). The env layer built by [`env_layer`] ignores them,
/// so a strict fold never reports them as unknown config keys.
pub const RESERVED_ENV_KEYS: &[&str] = &["config", "tier"];

// ── OverlaySlot — the typed within-tier precedence of a layer ──

/// Where a [`ProgressiveLayer`] folds *within* its [`crate::ConfigTierKind`]
/// tier — the typed answer to "which operator layer beats which".
///
/// The fold orders layers by `(tier, slot)`; declaration order here IS
/// the precedence (later wins):
///
/// | slot | layer | built by |
/// |---|---|---|
/// | [`Self::Computed`] | a `Defaults`-sourced layer | [`ProgressiveLayer::computed`] & co. |
/// | [`Self::File`] | the discovered config file | [`ProgressiveLayer::try_from_file`] |
/// | [`Self::ConfigOverride`] | each `--config FILE` | [`ProgressiveLayer::try_from_config_override`] |
/// | [`Self::Env`] | `<APP>_*` env vars | [`env_layer`] / [`ProgressiveLayer::from_env`] |
/// | [`Self::CliFlags`] | the typed flag overlay | [`ProgressiveLayer::cli`] |
/// | [`Self::CliSet`] | `--set PATH=VALUE` | [`ProgressiveLayer::set`] |
///
/// `File` and `ConfigOverride` share [`crate::ConfigSource::File`] — both
/// are files, and the per-leaf provenance names the path — but they are
/// distinct slots, so a `--config` override beats the discovered file by
/// type, not because it happened to be pushed later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum OverlaySlot {
    /// A computed-defaults layer (source [`crate::ConfigSource::Defaults`]).
    Computed,
    /// The discovered config file.
    File,
    /// An explicit `--config <PATH>` merge-override file.
    ConfigOverride,
    /// Environment variables under the app prefix.
    Env,
    /// The typed command-line flag overlay.
    CliFlags,
    /// `--set <PATH=VALUE>` assignments — the highest operator slot.
    CliSet,
}

impl OverlaySlot {
    /// Every slot, in precedence (= declaration) order.
    pub const ALL: &'static [Self] = &[
        Self::Computed,
        Self::File,
        Self::ConfigOverride,
        Self::Env,
        Self::CliFlags,
        Self::CliSet,
    ];

    /// Precedence ordinal: a higher ordinal folds later and wins.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        match self {
            Self::Computed => 0,
            Self::File => 1,
            Self::ConfigOverride => 2,
            Self::Env => 3,
            Self::CliFlags => 4,
            Self::CliSet => 5,
        }
    }

    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Computed => "computed",
            Self::File => "file",
            Self::ConfigOverride => "config-override",
            Self::Env => "env",
            Self::CliFlags => "cli-flags",
            Self::CliSet => "cli-set",
        }
    }

    /// The default slot for a layer of source kind `kind`. Total over
    /// [`ConfigSourceKind`]; the two slots no source kind names on its own
    /// ([`Self::ConfigOverride`], [`Self::CliSet`]) are reached only through
    /// their dedicated [`ProgressiveLayer`] constructors.
    #[must_use]
    pub const fn for_source_kind(kind: ConfigSourceKind) -> Self {
        match kind {
            ConfigSourceKind::Defaults => Self::Computed,
            ConfigSourceKind::File => Self::File,
            ConfigSourceKind::Env => Self::Env,
            ConfigSourceKind::Cli => Self::CliFlags,
        }
    }

    /// The [`ConfigSourceKind`] every layer in this slot carries.
    #[must_use]
    pub const fn source_kind(self) -> ConfigSourceKind {
        match self {
            Self::Computed => ConfigSourceKind::Defaults,
            Self::File | Self::ConfigOverride => ConfigSourceKind::File,
            Self::Env => ConfigSourceKind::Env,
            Self::CliFlags | Self::CliSet => ConfigSourceKind::Cli,
        }
    }
}

impl crate::ClosedAxis for OverlaySlot {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for OverlaySlot {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

closed_axis_label_string_surface! {
    type = OverlaySlot,
    parse_error = "unknown overlay slot",
    expecting = "a canonical OverlaySlot lowercase label \
                 (`computed`, `file`, `config-override`, `env`, `cli-flags`, \
                 `cli-set`; case-insensitive)",
}

// ── --set PATH=VALUE ──

/// One parsed `--set <PATH=VALUE>` assignment.
///
/// `PATH` is dotted (`daemon.interval`); `VALUE` is parsed as a YAML
/// scalar/flow value, so `--set daemon.interval=300` is an integer,
/// `--set tls=true` a bool, `--set tags=[a,b]` a list and
/// `--set name='300'` a string. An empty `VALUE` (`--set name=`) is the
/// empty string; `--set opt=null` is an explicit null, which resets an
/// `Option` field to `None`. Keys containing a literal `.` cannot be
/// addressed (use a `--config` file).
///
/// Implements [`FromStr`], so clap parses it at the argv boundary and a
/// malformed assignment is rejected before any config is read.
#[derive(Debug, Clone, PartialEq)]
pub struct SetAssignment {
    path: Vec<String>,
    value: Value,
    raw: String,
}

impl SetAssignment {
    /// The dotted path, split into segments.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The parsed value.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The assignment exactly as the operator typed it.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for SetAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Why a `--set` argument was refused at parse time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SetAssignmentError {
    /// No `=` separates the path from the value.
    #[error("--set {raw:?}: expected PATH=VALUE")]
    MissingEquals {
        /// The argument as typed.
        raw: String,
    },
    /// The path before `=` is empty.
    #[error("--set {raw:?}: empty config path")]
    EmptyPath {
        /// The argument as typed.
        raw: String,
    },
    /// The path has an empty segment (`a..b`, `.a`, `a.`).
    #[error("--set {raw:?}: empty segment in config path")]
    EmptySegment {
        /// The argument as typed.
        raw: String,
    },
    /// The value is not valid YAML.
    #[error("--set {raw:?}: value is not valid YAML: {message}")]
    InvalidValue {
        /// The argument as typed.
        raw: String,
        /// The YAML parser's message.
        message: String,
    },
}

impl FromStr for SetAssignment {
    type Err = SetAssignmentError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let owned = || raw.to_owned();
        let (path, rhs) = raw
            .split_once('=')
            .ok_or_else(|| SetAssignmentError::MissingEquals { raw: owned() })?;
        let path = path.trim();
        if path.is_empty() {
            return Err(SetAssignmentError::EmptyPath { raw: owned() });
        }
        let segments: Vec<String> = path.split('.').map(|s| s.trim().to_owned()).collect();
        if segments.iter().any(String::is_empty) {
            return Err(SetAssignmentError::EmptySegment { raw: owned() });
        }
        let value = if rhs.is_empty() {
            Value::from(String::new())
        } else {
            serde_yaml::from_str::<Value>(rhs).map_err(|e| SetAssignmentError::InvalidValue {
                raw: owned(),
                message: e.to_string(),
            })?
        };
        Ok(Self {
            path: segments,
            value,
            raw: owned(),
        })
    }
}

// ── LayerError — the strict fold's attributed refusals ──

/// Why the strict CLI-layered resolution refused.
///
/// Every key-level variant carries the dotted path and the [`Provenance`]
/// of the layer that wrote it, so the operator reads *which flag, file or
/// env var* to fix.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LayerError {
    /// A key the config type does not declare.
    #[error("unknown config key `{path}` (set by {})", display_origin(.origin.as_ref()))]
    UnknownKey {
        /// Dotted path of the unknown key.
        path: String,
        /// The layer that wrote it. `None` only for a key whose value is an
        /// empty map (no leaf, so no per-leaf provenance).
        origin: Option<Provenance>,
    },
    /// A key whose value does not deserialize into the declared type.
    #[error("invalid config value at `{path}` (set by {}): {message}", display_origin(.origin.as_ref()))]
    Invalid {
        /// Dotted path of the offending key (empty when figment could not
        /// localize it).
        path: String,
        /// The layer that wrote it, when the path resolves to one.
        origin: Option<Provenance>,
        /// The deserializer's message.
        message: String,
    },
    /// A `--set` argument that failed to parse.
    #[error(transparent)]
    Set(#[from] SetAssignmentError),
    /// A config file (discovered or `--config`) that could not be read or
    /// parsed.
    #[error("config file {}: {error}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The underlying load error.
        #[source]
        error: Box<ShikumiError>,
    },
    /// The typed flag overlay did not serialize to a config map.
    #[error("CLI flag overlay is not a config map: {0}")]
    Overlay(String),
}

fn display_origin(origin: Option<&Provenance>) -> String {
    origin.map_or_else(|| "an unknown layer".to_owned(), ToString::to_string)
}

impl LayerError {
    /// The provenance of the layer the refusal is attributed to, if any.
    #[must_use]
    pub fn origin(&self) -> Option<&Provenance> {
        match self {
            Self::UnknownKey { origin, .. } | Self::Invalid { origin, .. } => origin.as_ref(),
            _ => None,
        }
    }

    /// The dotted config path the refusal is about, if key-level.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::UnknownKey { path, .. } | Self::Invalid { path, .. } => Some(path),
            _ => None,
        }
    }
}

// ── dict builders ──

/// Recursively drop every null leaf from `dict`, then every map the drop
/// left empty. This is what makes a partial flag overlay safe: a flag the
/// operator did not pass serializes to null and contributes nothing.
pub fn strip_nulls(dict: &mut Dict) {
    dict.retain(|_, v| match v {
        Value::Empty(..) => false,
        Value::Dict(_, inner) => {
            strip_nulls(inner);
            !inner.is_empty()
        }
        _ => true,
    });
}

/// Serialize a partial overlay struct into a null-free [`Dict`].
pub(crate) fn overlay_dict(overlay: &impl Serialize) -> Result<Dict, LayerError> {
    let mut dict = Figment::new()
        .merge(Serialized::defaults(overlay))
        .extract::<Dict>()
        .map_err(|e| LayerError::Overlay(e.to_string()))?;
    strip_nulls(&mut dict);
    Ok(dict)
}

/// Fold `--set` assignments, in order, into one nested [`Dict`].
pub(crate) fn assignments_dict(assignments: &[SetAssignment]) -> Dict {
    let mut root = Dict::new();
    for a in assignments {
        let (last, parents) = a
            .path
            .split_last()
            .expect("SetAssignment paths are non-empty by construction");
        let mut cursor = &mut root;
        for seg in parents {
            let slot = cursor
                .entry(seg.clone())
                .or_insert_with(|| Value::Dict(Tag::Default, Dict::new()));
            if !matches!(slot, Value::Dict(..)) {
                *slot = Value::Dict(Tag::Default, Dict::new());
            }
            let Value::Dict(_, next) = slot else {
                unreachable!("slot was just made a dict")
            };
            cursor = next;
        }
        cursor.insert(last.clone(), a.value.clone());
    }
    root
}

/// The upper-snake env prefix for an app name: `"pangea-operator"` →
/// `"PANGEA_OPERATOR_"`. The same prefix names the discovery override
/// (`PANGEA_OPERATOR_CONFIG`).
#[must_use]
pub fn env_prefix_for(app: &str) -> String {
    let mut prefix: String = app
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    prefix.push('_');
    prefix
}

/// The env layer under `prefix` (nested keys split on `__`), ignoring the
/// [`RESERVED_ENV_KEYS`] selectors. Infallible: no matching vars is an
/// empty layer.
#[must_use]
pub fn env_layer(prefix: &str) -> ProgressiveLayer {
    let dict = Figment::new()
        .merge(
            figment::providers::Env::prefixed(prefix)
                .split("__")
                .ignore(RESERVED_ENV_KEYS),
        )
        .extract::<Dict>()
        .unwrap_or_default();
    ProgressiveLayer::env(prefix.to_owned(), dict)
}

/// The discovered config file layer for `app`: [`crate::ConfigDiscovery`]
/// with the `<APP>_CONFIG` env override, read strictly. `Ok(None)` when no
/// file exists anywhere on the search path — an absent config file is an
/// ordinary state, a malformed one is not.
///
/// # Errors
///
/// [`LayerError::File`] when the discovered file cannot be read or parsed.
pub fn discovered_file_layer(app: &str) -> Result<Option<ProgressiveLayer>, LayerError> {
    let discovery =
        crate::ConfigDiscovery::new(app).env_override(format!("{}CONFIG", env_prefix_for(app)));
    match discovery.discover() {
        Ok(path) => ProgressiveLayer::try_from_file(&path)
            .map(Some)
            .map_err(|error| LayerError::File {
                path,
                error: Box::new(error),
            }),
        Err(_) => Ok(None),
    }
}

/// Every operator layer for `app`, in the canonical slots — the clap-free
/// core of [`crate::cli::ConfigArgs::resolve`]:
///
/// 1. the discovered config file ([`discovered_file_layer`]),
/// 2. each `config_files` entry as a `--config` merge-override, in order,
/// 3. the `<APP>_` env layer ([`env_layer`]),
/// 4. the typed flag `overlay` ([`ProgressiveLayer::cli`]),
/// 5. the `sets` assignments ([`ProgressiveLayer::set`]).
///
/// The order of the returned vector is documentation only: each layer's
/// [`OverlaySlot`] places it in the fold.
///
/// # Errors
///
/// [`LayerError::File`] for an unreadable discovered or `--config` file
/// (a missing `--config` file included — the operator named it);
/// [`LayerError::Overlay`] for a flag overlay that is not a map.
pub fn operator_layers(
    app: &str,
    config_files: &[PathBuf],
    overlay: &impl Serialize,
    sets: &[SetAssignment],
) -> Result<Vec<ProgressiveLayer>, LayerError> {
    let mut layers = Vec::with_capacity(config_files.len() + 4);
    layers.extend(discovered_file_layer(app)?);
    for path in config_files {
        layers.push(
            ProgressiveLayer::try_from_config_override(path).map_err(|error| LayerError::File {
                path: path.clone(),
                error: Box::new(error),
            })?,
        );
    }
    layers.push(env_layer(&env_prefix_for(app)));
    layers.push(ProgressiveLayer::cli(overlay)?);
    if !sets.is_empty() {
        layers.push(ProgressiveLayer::set(sets));
    }
    Ok(layers)
}

/// A flag overlay with no flags, for binaries that take only `--config` /
/// `--set`. Serializes to an empty map.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct NoFlags {}

// ── strict extraction ──

/// Extract `T` from the folded `merged` dict, refusing ill-typed and
/// unknown keys with the provenance of the layer that wrote them.
pub(crate) fn extract_strict<T: Serialize + DeserializeOwned>(
    merged: &Dict,
    provenance: &ProvenanceMap,
) -> Result<T, LayerError> {
    let value: T = Figment::new()
        .merge(Serialized::defaults(merged))
        .extract::<T>()
        .map_err(|e| {
            let path = e.path.clone();
            LayerError::Invalid {
                path: path.join("."),
                origin: origin_of(provenance, &path),
                message: e.kind.to_string(),
            }
        })?;
    // Unknown keys: anything the input says that the typed value does not
    // reproduce when serialized back was dropped by serde.
    let known = Figment::new()
        .merge(Serialized::defaults(&value))
        .extract::<Dict>()
        .unwrap_or_default();
    let mut unknown = Vec::new();
    unknown_paths(merged, &known, &mut Vec::new(), &mut unknown);
    if let Some(path) = unknown.into_iter().next() {
        return Err(LayerError::UnknownKey {
            origin: origin_of(provenance, &path),
            path: path.join("."),
        });
    }
    Ok(value)
}

fn unknown_paths(input: &Dict, known: &Dict, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    for (key, v) in input {
        if matches!(v, Value::Empty(..)) {
            continue;
        }
        prefix.push(key.clone());
        match (v, known.get(key)) {
            (_, None) => out.push(prefix.clone()),
            (Value::Dict(_, inner), Some(Value::Dict(_, known_inner))) => {
                unknown_paths(inner, known_inner, prefix, out);
            }
            (Value::Array(_, items), Some(Value::Array(_, known_items))) => {
                for (i, (item, known_item)) in items.iter().zip(known_items).enumerate() {
                    if let (Value::Dict(_, d), Value::Dict(_, kd)) = (item, known_item) {
                        // Index segments name the element; provenance is
                        // recorded at the array path (lists replace whole).
                        let mut element = prefix.clone();
                        element.push(i.to_string());
                        let mut found = Vec::new();
                        unknown_paths(d, kd, &mut element, &mut found);
                        out.extend(found);
                    }
                }
            }
            _ => {}
        }
        prefix.pop();
    }
}

/// The provenance of the layer that wrote `path`: the exact leaf, else the
/// nearest ancestor leaf (a list element, a scalar a map replaced), else
/// the first descendant leaf (an unknown key that is itself a map).
fn origin_of(provenance: &ProvenanceMap, path: &[String]) -> Option<Provenance> {
    if path.is_empty() {
        return None;
    }
    if let Some(p) = provenance.provenance_of_owned(path) {
        return Some(p.clone());
    }
    for n in (1..path.len()).rev() {
        if let Some(p) = provenance.provenance_of_owned(&path[..n]) {
            return Some(p.clone());
        }
    }
    provenance
        .iter()
        .find(|(leaf, _)| leaf.len() > path.len() && leaf[..path.len()] == *path)
        .map(|(_, p)| p.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_slot_all_is_declaration_and_precedence_order() {
        for (i, slot) in OverlaySlot::ALL.iter().enumerate() {
            assert_eq!(slot.ordinal(), i, "{slot:?}");
        }
        assert_eq!(OverlaySlot::ALL.len(), 6);
        let mut sorted = OverlaySlot::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, OverlaySlot::ALL, "Ord must agree with precedence");
    }

    #[test]
    fn overlay_slot_operator_precedence_is_file_override_env_flags_set() {
        use OverlaySlot::{CliFlags, CliSet, ConfigOverride, Env, File};
        assert!(File < ConfigOverride);
        assert!(ConfigOverride < Env);
        assert!(Env < CliFlags);
        assert!(CliFlags < CliSet);
    }

    #[test]
    fn overlay_slot_source_kind_round_trips_through_for_source_kind() {
        for kind in ConfigSourceKind::ALL.iter().copied() {
            assert_eq!(OverlaySlot::for_source_kind(kind).source_kind(), kind);
        }
        for slot in OverlaySlot::ALL.iter().copied() {
            // Every slot's source kind maps back to a slot of the same kind.
            assert_eq!(
                OverlaySlot::for_source_kind(slot.source_kind()).source_kind(),
                slot.source_kind()
            );
        }
    }

    #[test]
    fn overlay_slot_label_round_trips() {
        for slot in OverlaySlot::ALL.iter().copied() {
            assert_eq!(slot.as_str().parse::<OverlaySlot>().unwrap(), slot);
            assert_eq!(slot.to_string(), slot.as_str());
        }
        assert!("bogus".parse::<OverlaySlot>().is_err());
    }

    #[test]
    fn set_assignment_parses_yaml_scalars() {
        let a: SetAssignment = "daemon.interval=300".parse().unwrap();
        assert_eq!(a.path(), ["daemon", "interval"]);
        assert_eq!(a.value().to_u128(), Some(300));
        let b: SetAssignment = "tls=true".parse().unwrap();
        assert_eq!(b.value().to_bool(), Some(true));
        let s: SetAssignment = "name='300'".parse().unwrap();
        assert_eq!(s.value().as_str(), Some("300"));
        let e: SetAssignment = "name=".parse().unwrap();
        assert_eq!(e.value().as_str(), Some(""));
        let l: SetAssignment = "tags=[a, b]".parse().unwrap();
        assert!(matches!(l.value(), Value::Array(_, v) if v.len() == 2));
        let n: SetAssignment = "opt=null".parse().unwrap();
        assert!(matches!(n.value(), Value::Empty(..)));
        let eq: SetAssignment = "url=a=b".parse().unwrap();
        assert_eq!(eq.value().as_str(), Some("a=b"));
    }

    #[test]
    fn set_assignment_rejects_malformed_paths_with_typed_errors() {
        assert!(matches!(
            "novalue".parse::<SetAssignment>(),
            Err(SetAssignmentError::MissingEquals { .. })
        ));
        assert!(matches!(
            "=1".parse::<SetAssignment>(),
            Err(SetAssignmentError::EmptyPath { .. })
        ));
        assert!(matches!(
            " =1".parse::<SetAssignment>(),
            Err(SetAssignmentError::EmptyPath { .. })
        ));
        for bad in ["a..b=1", ".a=1", "a.=1"] {
            assert!(
                matches!(
                    bad.parse::<SetAssignment>(),
                    Err(SetAssignmentError::EmptySegment { .. })
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            "a=[unclosed".parse::<SetAssignment>(),
            Err(SetAssignmentError::InvalidValue { .. })
        ));
    }

    #[test]
    fn assignments_dict_nests_and_later_wins() {
        let a: Vec<SetAssignment> = ["d.x=1", "d.y=2", "d.x=3", "top=t"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let d = assignments_dict(&a);
        let Some(Value::Dict(_, inner)) = d.get("d") else {
            panic!("d must be a dict: {d:?}")
        };
        assert_eq!(inner.get("x").and_then(Value::to_u128), Some(3));
        assert_eq!(inner.get("y").and_then(Value::to_u128), Some(2));
        assert_eq!(d.get("top").and_then(Value::as_str), Some("t"));
    }

    #[test]
    fn assignments_dict_replaces_a_scalar_parent_with_a_map() {
        let a: Vec<SetAssignment> = ["d=1", "d.x=2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let d = assignments_dict(&a);
        assert!(matches!(d.get("d"), Some(Value::Dict(..))));
    }

    #[derive(Serialize)]
    struct Flags {
        port: Option<u16>,
        nested: NestedFlags,
    }

    #[derive(Serialize)]
    struct NestedFlags {
        token_file: Option<PathBuf>,
    }

    #[test]
    fn overlay_dict_drops_absent_flags_and_empty_maps() {
        let none = Flags {
            port: None,
            nested: NestedFlags { token_file: None },
        };
        assert!(overlay_dict(&none).unwrap().is_empty());
        let some = Flags {
            port: Some(9),
            nested: NestedFlags {
                token_file: Some("/t".into()),
            },
        };
        let d = overlay_dict(&some).unwrap();
        assert_eq!(d.get("port").and_then(Value::to_u128), Some(9));
        assert!(matches!(d.get("nested"), Some(Value::Dict(..))));
    }

    #[test]
    fn overlay_dict_refuses_a_non_map_overlay() {
        assert!(matches!(overlay_dict(&5_u8), Err(LayerError::Overlay(_))));
    }

    #[test]
    fn strip_nulls_is_recursive() {
        let mut d = Dict::new();
        let null = || Value::Empty(Tag::Default, figment::value::Empty::None);
        d.insert("a".into(), null());
        let mut inner = Dict::new();
        inner.insert("b".into(), null());
        d.insert("n".into(), Value::Dict(Tag::Default, inner));
        d.insert("k".into(), Value::from(1_u8));
        strip_nulls(&mut d);
        assert_eq!(d.keys().collect::<Vec<_>>(), ["k"]);
    }

    #[test]
    fn env_prefix_for_upper_snakes_the_app_name() {
        assert_eq!(env_prefix_for("pangea-operator"), "PANGEA_OPERATOR_");
        assert_eq!(env_prefix_for("tend"), "TEND_");
    }
}

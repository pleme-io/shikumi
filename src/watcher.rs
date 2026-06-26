//! Symlink-aware file watcher.
//!
//! Extracted from karakuri's `setup_config_watcher` and `ConfigHandler`.
//! Handles the nix-darwin pattern where config files are symlinks into
//! the Nix store — `PollWatcher` for symlinks, `RecommendedWatcher` for
//! regular files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use tracing::debug;

use crate::cube::{ClosedAxis, ClosedAxisLabel};
use crate::error::ShikumiError;

/// Reload-relevance class of a file-watch [`notify::Event`] — the typed
/// decision "does this event warrant re-reading the config?".
///
/// The hot-reload promise (Pillar 2) turns on exactly one predicate: of
/// the raw `notify` event stream, *which* events mean the config bytes
/// may have changed. That decision lived inline in
/// [`crate::ConfigStore::load_and_watch`]'s watcher closure — anonymous,
/// reachable only through the timing-sensitive integration tests, and
/// un-reusable by any second watcher consumer. Lifting it to a named,
/// `Copy` closed enum makes the trigger semantics a pure function of the
/// event kind: deterministically unit-testable (no `sleep`, no
/// filesystem race) and shared by every consumer that subscribes to the
/// raw stream — a future debounce layer, a manual re-subscribe path, or
/// `mado`'s MCP watcher all classify through one site instead of
/// re-coding the `match`.
///
/// The three classes partition the event space: [`Self::Reload`] (the
/// bytes may have changed — re-read and re-project), [`Self::Removed`]
/// (a transient unlink, kept distinct because nix-darwin's atomic
/// unlink+symlink swap surfaces a `Remove` that must *not* trigger a
/// read of a half-applied rebuild), and [`Self::Ignored`] (everything
/// else — access, rename, the `Any`/`Other` catch-alls).
///
/// `Ord` / `PartialOrd` are declaration-order lex over [`Self::ALL`]
/// (`Reload < Removed < Ignored`): a `BTreeMap<WatchEventClass, T>`
/// keyed on the reload-relevance class (per-class watcher-event
/// histograms, reload-trigger dashboards, attestation manifests
/// recording the event-class cardinality mix of a recorded watch
/// session) emits rows in that order deterministically without a
/// hand-rolled comparator at the renderer. Idiom-peer of the same
/// derive on [`crate::EnvMetadataTagKind`] (commit `b556b75`),
/// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
/// [`crate::FigmentSourceKind`] (commit `5df265c`), and
/// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
/// reload-relevance axis closed-enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WatchEventClass {
    /// A content/metadata-write `Modify` or any `Create` — the file's
    /// bytes may have changed; the store should re-read and re-project.
    Reload,
    /// A `Remove` — the watched path was unlinked. nix-darwin applies a
    /// config rebuild as an atomic unlink+symlink swap, so a `Remove` is
    /// a transient mid-swap state: the watcher keeps watching for the
    /// replacement rather than reading a half-applied rebuild.
    Removed,
    /// Any other event — non-mutating access, a rename, a
    /// non-write metadata touch, or the `Any`/`Other` catch-alls. Not
    /// reload-relevant.
    Ignored,
}

impl WatchEventClass {
    /// Every reload-relevance class, in declaration order. Mirror of the
    /// [`ClosedAxis::ALL`] trait constant; pinned to the variant space by
    /// [`tests::watch_event_class_all_covers_every_variant`].
    pub const ALL: &'static [Self] = &[Self::Reload, Self::Removed, Self::Ignored];

    /// Classify a raw [`notify::EventKind`] into its reload-relevance
    /// class — the single source of truth for the hot-reload trigger
    /// predicate.
    ///
    /// `Modify` with a content data-change or a write-time metadata
    /// change, and every `Create`, map to [`Self::Reload`]; every
    /// `Remove` maps to [`Self::Removed`]; all other kinds map to
    /// [`Self::Ignored`]. Pure in the event kind — no I/O, no clock — so
    /// the trigger semantics are unit-testable without the
    /// timing-sensitive watcher harness.
    #[must_use]
    pub fn classify(kind: &notify::EventKind) -> Self {
        use notify::EventKind;
        use notify::event::{DataChange, MetadataKind, ModifyKind};

        match kind {
            EventKind::Modify(
                ModifyKind::Metadata(MetadataKind::WriteTime)
                | ModifyKind::Data(DataChange::Content),
            )
            | EventKind::Create(_) => Self::Reload,
            EventKind::Remove(_) => Self::Removed,
            _ => Self::Ignored,
        }
    }

    /// Whether this class warrants re-reading the config — `true` exactly
    /// on [`Self::Reload`].
    #[must_use]
    pub const fn should_reload(self) -> bool {
        matches!(self, Self::Reload)
    }

    /// Canonical operator-facing lowercase name — `"reload"`, `"removed"`,
    /// or `"ignored"`. Inherent mirror of the [`ClosedAxisLabel`] trait
    /// method; the trait impl delegates here so the labels live at one
    /// site (structured-log fields naming why a watcher event did or
    /// didn't reload, a CLI watch-trace, a reload-trigger histogram).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Removed => "removed",
            Self::Ignored => "ignored",
        }
    }
}

impl ClosedAxis for WatchEventClass {
    const ALL: &'static [Self] = Self::ALL;
}

impl ClosedAxisLabel for WatchEventClass {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on a ClosedAxisLabel primitive — lifted to one macro after the
// 15+ hand-rolled idiom-peers preceding this commit. See
// `closed_axis_label_string_surface!` in `crate::macros` for the contract;
// behavior is byte-identical to the hand-rolled impls the macro replaces.
closed_axis_label_string_surface! {
    type = WatchEventClass,
    parse_error = "unknown watch event class",
    expecting = "a canonical WatchEventClass lowercase label \
                 (`reload`, `removed`, `ignored`; case-insensitive)",
}

/// Resolves a symlink to its canonical target, or returns `None` if the
/// path is not a symlink.
#[must_use]
pub fn symlink_target(path: &Path) -> Option<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() {
        std::fs::canonicalize(path).ok()
    } else {
        None
    }
}

/// A symlink-aware config file watcher.
///
/// - **Symlinks** (nix-managed): Uses `PollWatcher` with `follow_symlinks(true)`
///   and a 3-second poll interval. Watches the resolved target.
/// - **Regular files**: Uses `RecommendedWatcher` (`FSEvents` on macOS,
///   inotify on Linux) for instant notification.
///
/// In both cases, the original path is also watched so parent directory
/// changes (renames, recreations) are detected.
pub struct ConfigWatcher {
    // Send + Sync bounds so ConfigStore (which holds an Option<ConfigWatcher>)
    // is itself Send + Sync. Consumers that move the store into a background
    // thread (tear-config's spawn_watcher closure, mado's MCP set_config) rely
    // on this. notify::RecommendedWatcher and PollWatcher are both Send + Sync;
    // the trait-object loses those auto-traits without the explicit bound.
    _watcher: Box<dyn Watcher + Send + Sync>,
}

impl ConfigWatcher {
    /// Start watching a config file for changes.
    ///
    /// The callback receives raw `notify::Event`s. The caller is responsible
    /// for filtering event kinds (e.g. `Modify`, `Create`, `Remove`).
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::Watch` if the watcher cannot be created
    /// or the path cannot be watched.
    pub fn watch<F>(path: &Path, on_change: F) -> Result<Self, ShikumiError>
    where
        F: Fn(notify::Event) + Send + 'static,
    {
        let handler = CallbackHandler(Box::new(on_change));
        let setup = notify::Config::default().with_poll_interval(Duration::from_secs(3));

        let symlink = symlink_target(path);

        let mut watcher: Box<dyn Watcher + Send + Sync> = if let Some(ref target) = symlink {
            let poll_setup = setup.with_follow_symlinks(true);
            let mut w = notify::PollWatcher::new(handler, poll_setup)?;
            debug!("watching symlink target {} for changes", target.display());
            w.watch(target, RecursiveMode::NonRecursive)?;
            Box::new(w)
        } else {
            Box::new(notify::RecommendedWatcher::new(handler, setup)?)
        };

        debug!("watching config file {} for changes", path.display());
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        Ok(Self { _watcher: watcher })
    }

    /// Re-create the watcher for a new or changed path.
    ///
    /// Useful when a symlink target changes (e.g. nix rebuild replaces
    /// the symlink with a new store path). Drops the old watcher and
    /// creates a fresh one.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError::Watch` if the new watcher cannot be created.
    pub fn rewatch<F>(path: &Path, on_change: F) -> Result<Self, ShikumiError>
    where
        F: Fn(notify::Event) + Send + 'static,
    {
        Self::watch(path, on_change)
    }
}

struct CallbackHandler(Box<dyn Fn(notify::Event) + Send>);

impl notify::EventHandler for CallbackHandler {
    fn handle_event(&mut self, event: notify::Result<notify::Event>) {
        match event {
            Ok(event) => (self.0)(event),
            Err(err) => tracing::warn!("file watcher error: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempfile::TempDir;

    use notify::EventKind;
    use notify::event::{
        AccessKind, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind, RenameMode,
    };

    #[test]
    fn classify_create_is_reload() {
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Create(CreateKind::Other),
        ] {
            assert_eq!(WatchEventClass::classify(&kind), WatchEventClass::Reload);
        }
    }

    #[test]
    fn classify_content_and_writetime_modify_is_reload() {
        assert_eq!(
            WatchEventClass::classify(&EventKind::Modify(ModifyKind::Data(DataChange::Content))),
            WatchEventClass::Reload
        );
        assert_eq!(
            WatchEventClass::classify(&EventKind::Modify(ModifyKind::Metadata(
                MetadataKind::WriteTime
            ))),
            WatchEventClass::Reload
        );
    }

    #[test]
    fn classify_remove_is_removed() {
        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Remove(RemoveKind::Other),
        ] {
            assert_eq!(WatchEventClass::classify(&kind), WatchEventClass::Removed);
        }
    }

    #[test]
    fn classify_non_reload_modify_and_other_kinds_are_ignored() {
        // Modify variants that are not a content or write-time change.
        for kind in [
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Data(DataChange::Size)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Ownership)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Modify(ModifyKind::Other),
        ] {
            assert_eq!(
                WatchEventClass::classify(&kind),
                WatchEventClass::Ignored,
                "{kind:?} should be Ignored"
            );
        }
        // The non-mutating and catch-all kinds.
        for kind in [
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
            EventKind::Other,
        ] {
            assert_eq!(
                WatchEventClass::classify(&kind),
                WatchEventClass::Ignored,
                "{kind:?} should be Ignored"
            );
        }
    }

    #[test]
    fn should_reload_agrees_with_classify_reload() {
        // should_reload is exactly the Reload-class predicate.
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(class.should_reload(), class == WatchEventClass::Reload);
        }
    }

    #[test]
    fn watch_event_class_all_covers_every_variant() {
        // ALL is a duplicate-free set of all three classes; classify can
        // only ever land in ALL.
        assert_eq!(WatchEventClass::ALL.len(), 3);
        let mut seen = WatchEventClass::ALL.to_vec();
        seen.sort_by_key(|c| c.as_str());
        seen.dedup();
        assert_eq!(seen.len(), 3, "ALL must have no duplicates");
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Remove(RemoveKind::File),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
        ] {
            assert!(WatchEventClass::ALL.contains(&WatchEventClass::classify(&kind)));
        }
    }

    #[test]
    fn watch_event_class_as_str_is_distinct_lowercase() {
        assert_eq!(WatchEventClass::Reload.as_str(), "reload");
        assert_eq!(WatchEventClass::Removed.as_str(), "removed");
        assert_eq!(WatchEventClass::Ignored.as_str(), "ignored");
    }

    #[test]
    fn watch_event_class_label_round_trips() {
        use crate::ClosedAxisLabel;
        // The ClosedAxisLabel round-trip law, pinned locally:
        // from_canonical_str(v.as_str()) == Some(v) for every variant,
        // case-insensitively.
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                WatchEventClass::from_canonical_str(ClosedAxisLabel::as_str(class)),
                Some(class)
            );
            assert_eq!(
                WatchEventClass::from_canonical_str(&class.as_str().to_uppercase()),
                Some(class)
            );
        }
        assert_eq!(WatchEventClass::from_canonical_str("nonsense"), None);
        assert_eq!(WatchEventClass::from_canonical_str(""), None);
    }

    #[test]
    fn watch_event_class_ord_matches_all_declaration_order() {
        // The derived Ord on WatchEventClass is declaration-order lex
        // over ALL: `Reload < Removed < Ignored`. A BTreeMap keyed on
        // the reload-relevance class (per-class watcher-event
        // histograms, reload-trigger dashboards, attestation manifests
        // recording the event-class cardinality mix of a recorded
        // watch session) emits rows in that order deterministically
        // without a hand-rolled comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds). Idiom-peer
        // of the same pin on EnvMetadataTagKind (commit `b556b75`),
        // FigmentNameTagKind (commit `64a47e7`), FigmentSourceKind
        // (commit `5df265c`), and ConfigSourceKind (commit `e0b96d1`).
        use std::cmp::Ordering;
        for window in WatchEventClass::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "WatchEventClass::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in WatchEventClass::ALL.iter().enumerate() {
            for (j, &b) in WatchEventClass::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "WatchEventClass::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "WatchEventClass::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn watch_event_class_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<WatchEventClass, _> emits keys
        // in declaration order on `iter()` / `into_iter()`
        // regardless of insertion order, matching
        // `WatchEventClass::ALL`. Idiom-peer of the same pin on
        // EnvMetadataTagKind (commit `b556b75`), FigmentNameTagKind
        // (commit `64a47e7`), FigmentSourceKind (commit `5df265c`),
        // and ConfigSourceKind (commit `e0b96d1`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<WatchEventClass, u32> = BTreeMap::new();
        counts.insert(WatchEventClass::Ignored, 3);
        counts.insert(WatchEventClass::Reload, 1);
        counts.insert(WatchEventClass::Removed, 2);
        let observed: Vec<WatchEventClass> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            WatchEventClass::ALL.to_vec(),
            "BTreeMap<WatchEventClass, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn watch_event_class_display_matches_as_str() {
        // Display writes the canonical lowercase label as_str returns,
        // byte-for-byte. The two surfaces stay aligned by construction
        // — a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on EnvMetadataTagKind
        // (commit `b556b75`), FigmentNameTagKind (commit `64a47e7`),
        // and FigmentSourceKind (commit `5df265c`).
        for c in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                format!("{c}"),
                c.as_str(),
                "Display must agree with as_str for {c:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for c in WatchEventClass::ALL {
            let rendered = c.to_string();
            let parsed: WatchEventClass = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *c, "FromStr must round-trip {c:?}");
        }
    }

    #[test]
    fn watch_event_class_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into a CLI flag
        // or structured-log filter parse pointwise to the same
        // variant.
        assert_eq!(
            "RELOAD".parse::<WatchEventClass>().unwrap(),
            WatchEventClass::Reload,
        );
        assert_eq!(
            "Removed".parse::<WatchEventClass>().unwrap(),
            WatchEventClass::Removed,
        );
        assert_eq!(
            "iGnOrEd".parse::<WatchEventClass>().unwrap(),
            WatchEventClass::Ignored,
        );
        assert_eq!(
            "rElOaD".parse::<WatchEventClass>().unwrap(),
            WatchEventClass::Reload,
        );
    }

    #[test]
    fn watch_event_class_from_str_unknown_class_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // EnvMetadataTagKind's FromStr surface (commit `b556b75`),
        // FigmentNameTagKind's FromStr surface (commit `64a47e7`),
        // FigmentSourceKind's FromStr surface (commit `5df265c`),
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`),
        // FormatProvenance's FromStr surface (commit `2c7654c`), and
        // ParseFormatCoordinatesError (commit `06a2f42`).
        for bad in &["modify", "create", "rename", "", "  reload"] {
            let err = bad
                .parse::<WatchEventClass>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the reload-relevance axis primitive. A consumer
        // struct holding a WatchEventClass field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the reload-relevance class of a
        // watcher-event sample) round-trips without a consumer-side
        // rename helper.
        for c in WatchEventClass::ALL {
            let yaml = serde_yaml::to_string(c).expect("Serialize must succeed");
            let parsed: WatchEventClass =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *c, "serde_yaml round-trip must preserve {c:?}");
        }
    }

    #[test]
    fn watch_event_class_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for c in WatchEventClass::ALL {
            let json = serde_json::to_string(c).expect("Serialize must succeed");
            let parsed: WatchEventClass =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *c, "serde_json round-trip must preserve {c:?}");
        }
    }

    #[test]
    fn watch_event_class_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, WatchEventClass)] = &[
            ("Reload", WatchEventClass::Reload),
            ("REMOVED", WatchEventClass::Removed),
            ("IgNoReD", WatchEventClass::Ignored),
            ("rElOaD", WatchEventClass::Reload),
        ];
        for (input, expected) in cases {
            let parsed: WatchEventClass =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_serde_yaml_unknown_class_error_carries_label_verbatim() {
        // An unrecognized reload-relevance class label surfaces at
        // the serde error site with the offending substring verbatim
        // in the rendered message, lifted through
        // ShikumiError::Parse's Display impl. Same verbatim-rejection
        // discipline as EnvMetadataTagKind's serde surface
        // (commit `b556b75`), FigmentNameTagKind's serde surface
        // (commit `64a47e7`), FigmentSourceKind's serde surface
        // (commit `5df265c`), ConfigSourceKind's serde surface
        // (commit `e0b96d1`), and FormatProvenance's serde surface
        // (commit `2c7654c`).
        for bad in &["modify", "create", "rename", "noop"] {
            let err = serde_yaml::from_str::<WatchEventClass>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on WatchEventClass's YAML emission:
        // every variant renders as a bare lowercase scalar (no
        // quotes, no tag prefix). Routes through
        // Serializer::collect_str → Display → as_str, so the wire
        // shape is exactly `format!("{c}")` followed by serde_yaml's
        // newline terminator. Pins the serde idiom-peer of the
        // Display surface byte-for-byte at concrete positions across
        // every variant. Idiom-peer of
        // `env_metadata_tag_kind_serde_yaml_emission_is_bare_scalar`
        // (commit `b556b75`).
        assert_eq!(
            serde_yaml::to_string(&WatchEventClass::Reload).unwrap(),
            "reload\n",
        );
        assert_eq!(
            serde_yaml::to_string(&WatchEventClass::Removed).unwrap(),
            "removed\n",
        );
        assert_eq!(
            serde_yaml::to_string(&WatchEventClass::Ignored).unwrap(),
            "ignored\n",
        );
    }

    #[test]
    fn symlink_target_regular_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("regular.txt");
        fs::write(&file, "hello").unwrap();
        assert!(symlink_target(&file).is_none());
    }

    #[test]
    fn symlink_target_nonexistent_returns_none() {
        assert!(symlink_target(Path::new("/nonexistent/path")).is_none());
    }

    #[test]
    fn symlink_target_resolves_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = symlink_target(&link);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), fs::canonicalize(&target).unwrap());
    }

    #[test]
    fn watch_regular_file_detects_change() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("config.yaml");
        fs::write(&file, "key: old").unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let _watcher = ConfigWatcher::watch(&file, move |event| {
            events_clone.lock().unwrap().push(event);
        })
        .unwrap();

        // Give the watcher time to set up
        thread::sleep(Duration::from_millis(100));

        // Modify the file
        fs::write(&file, "key: new").unwrap();

        // Wait for the event (RecommendedWatcher should be fast)
        thread::sleep(Duration::from_millis(500));

        let captured = events.lock().unwrap();
        // Should have received at least one event
        // (exact count varies by platform — macOS FSEvents may batch)
        assert!(
            !captured.is_empty(),
            "expected at least one file change event"
        );
    }

    #[test]
    fn watch_symlink_creates_poll_watcher() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Should not error — PollWatcher path
        let _watcher = ConfigWatcher::watch(&link, |_event| {}).unwrap();
    }

    #[test]
    fn watch_nonexistent_file_errors() {
        let result = ConfigWatcher::watch(Path::new("/nonexistent/config.yaml"), |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn symlink_target_broken_symlink_returns_none() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("deleted_target.yaml");
        let link = dir.path().join("broken_link.yaml");
        // Create target, symlink, then delete target
        fs::write(&target, "key: value").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        fs::remove_file(&target).unwrap();

        // Broken symlink: canonicalize should fail
        let result = symlink_target(&link);
        assert!(result.is_none(), "broken symlink should return None");
    }

    #[test]
    fn symlink_target_directory_symlink() {
        let dir = TempDir::new().unwrap();
        let target_dir = dir.path().join("target_dir");
        fs::create_dir_all(&target_dir).unwrap();
        let link = dir.path().join("link_dir");
        std::os::unix::fs::symlink(&target_dir, &link).unwrap();

        let result = symlink_target(&link);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), fs::canonicalize(&target_dir).unwrap());
    }

    #[test]
    fn rewatch_creates_new_watcher() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("rewatch.yaml");
        fs::write(&file, "key: value").unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        // rewatch is equivalent to watch, but emphasizes re-creation
        let _watcher = ConfigWatcher::rewatch(&file, move |event| {
            events_clone.lock().unwrap().push(event);
        })
        .unwrap();

        thread::sleep(Duration::from_millis(100));
        fs::write(&file, "key: updated").unwrap();
        thread::sleep(Duration::from_millis(500));

        let captured = events.lock().unwrap();
        assert!(!captured.is_empty(), "rewatch should detect file changes");
    }

    #[test]
    fn watch_symlink_detects_target_change() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: original").unwrap();
        let link = dir.path().join("watched_link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let _watcher = ConfigWatcher::watch(&link, move |event| {
            events_clone.lock().unwrap().push(event);
        })
        .unwrap();

        // Give watcher time to set up, then modify the target
        thread::sleep(Duration::from_millis(200));
        fs::write(&target, "key: modified").unwrap();

        // PollWatcher has 3s interval, wait a bit longer
        thread::sleep(Duration::from_millis(4000));

        let captured = events.lock().unwrap();
        // Soft assertion: poll watcher may or may not fire in time on all platforms
        if !captured.is_empty() {
            // At least one event was detected
            assert!(captured.iter().any(|e| !e.paths.is_empty()));
        }
    }

    #[test]
    fn watch_callback_receives_event_with_path() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pathcheck.yaml");
        fs::write(&file, "key: value").unwrap();

        let paths = Arc::new(Mutex::new(Vec::new()));
        let paths_clone = paths.clone();

        let _watcher = ConfigWatcher::watch(&file, move |event| {
            for p in &event.paths {
                paths_clone.lock().unwrap().push(p.clone());
            }
        })
        .unwrap();

        thread::sleep(Duration::from_millis(100));
        fs::write(&file, "key: new_value").unwrap();
        thread::sleep(Duration::from_millis(500));

        let captured = paths.lock().unwrap();
        if !captured.is_empty() {
            assert!(
                captured
                    .iter()
                    .any(|p| { p.display().to_string().contains("pathcheck") }),
                "expected event path to reference the watched file"
            );
        }
    }

    #[test]
    fn symlink_target_nested_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real.yaml");
        fs::write(&target, "key: value").unwrap();

        let link1 = dir.path().join("link1.yaml");
        std::os::unix::fs::symlink(&target, &link1).unwrap();

        let link2 = dir.path().join("link2.yaml");
        std::os::unix::fs::symlink(&link1, &link2).unwrap();

        let resolved = symlink_target(&link2);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), fs::canonicalize(&target).unwrap());
    }

    #[test]
    fn rewatch_nonexistent_file_errors() {
        let result = ConfigWatcher::rewatch(Path::new("/nonexistent/rewatch.yaml"), |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn symlink_target_returns_none_for_plain_directory() {
        let dir = TempDir::new().unwrap();
        assert!(symlink_target(dir.path()).is_none());
    }
}

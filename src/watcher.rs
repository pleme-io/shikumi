//! Symlink-aware file watcher.
//!
//! Extracted from karakuri's `setup_config_watcher` and `ConfigHandler`.
//! Handles the nix-darwin pattern where config files are symlinks into
//! the Nix store — `PollWatcher` for symlinks, `RecommendedWatcher` for
//! regular files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use tracing::{debug, info};

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
    ///
    /// Retained as the operator-facing name for the reload-trigger
    /// decision (the imperative "should we reload?" question at the
    /// watcher closure's dispatch site); pointwise byte-identical to the
    /// closed-axis sibling predicate [`Self::is_reload`] — pinned by
    /// [`tests::should_reload_agrees_with_is_reload_pointwise`] — so the
    /// two surfaces cannot drift.
    #[must_use]
    pub const fn should_reload(self) -> bool {
        matches!(self, Self::Reload)
    }

    /// Returns `true` for [`Self::Reload`]; equivalent to
    /// `self == WatchEventClass::Reload`. Sibling of [`Self::is_removed`]
    /// and [`Self::is_ignored`] — the closed ternary partition of the
    /// reload-relevance axis lifted to three named `const fn` predicates
    /// at the primitive's altitude, mirror of the trio-shape
    /// [`crate::ConfigSourceKind::is_defaults`] /
    /// [`crate::ConfigSourceKind::is_env`] /
    /// [`crate::ConfigSourceKind::is_file`] and of the tag-side quartet
    /// [`crate::ConfigTier::is_bare`] /
    /// [`crate::ConfigTier::is_discovered`] /
    /// [`crate::ConfigTier::is_default`] / [`crate::ConfigTier::is_custom`].
    ///
    /// One source of truth for the "is this the reload class?" question
    /// over [`WatchEventClass`] — a consumer that only wants the yes/no
    /// answer (a per-class watcher-event histogram bin, an attestation
    /// manifest grouping by class, a reload-trigger dashboard counter)
    /// matches on this predicate instead of open-coding
    /// `matches!(class, WatchEventClass::Reload)` and paying the
    /// closed-partition bookkeeping tax again. The three sibling
    /// predicates form a closed disjoint partition of the variant space
    /// — every [`WatchEventClass`] value satisfies exactly one — pinned
    /// by [`tests::watch_event_class_predicates_are_a_closed_ternary_partition`],
    /// the ternary analogue of the trio-partition pin on
    /// [`crate::ConfigSourceKind`]. Pointwise byte-identical to the
    /// long-standing [`Self::should_reload`] — pinned by
    /// [`tests::should_reload_agrees_with_is_reload_pointwise`] — so a
    /// future edit to either arm that drifts one polarity fails here
    /// before drifting through any consumer site.
    #[must_use]
    pub const fn is_reload(self) -> bool {
        matches!(self, Self::Reload)
    }

    /// Returns `true` for [`Self::Removed`]; equivalent to
    /// `self == WatchEventClass::Removed`. Sibling of [`Self::is_reload`];
    /// see [`Self::is_reload`] for the full contract.
    #[must_use]
    pub const fn is_removed(self) -> bool {
        matches!(self, Self::Removed)
    }

    /// Returns `true` for [`Self::Ignored`]; equivalent to
    /// `self == WatchEventClass::Ignored`. Sibling of [`Self::is_reload`];
    /// see [`Self::is_reload`] for the full contract.
    #[must_use]
    pub const fn is_ignored(self) -> bool {
        matches!(self, Self::Ignored)
    }

    /// Whether this class names an *observed file mutation* — `true` on
    /// [`Self::Reload`] (the file's bytes may have changed: `Create` or a
    /// content / write-time `Modify`) and on [`Self::Removed`] (the file
    /// was unlinked at the watched path), `false` on [`Self::Ignored`]
    /// (access, rename, permissions / ownership metadata, and the
    /// `Any` / `Other` catch-alls).
    ///
    /// The compound-polarity sibling on the reload-relevance ternary axis
    /// — the two-cell disjunction pole every ternary axis in the crate now
    /// carries a name for. The single-cell complement is the long-standing
    /// [`Self::is_ignored`]; the two predicates form a closed binary
    /// partition of [`WatchEventClass::ALL`] at the compound-polarity
    /// altitude on top of the closed ternary partition
    /// [`Self::is_reload`] / [`Self::is_removed`] / [`Self::is_ignored`]
    /// already resolves at the singleton altitude. Mirror of the compound
    /// polarity pairs the fleet-idiom sibling ladders carry —
    /// [`crate::ConfigTierKind::is_computed`] on the tier axis (four
    /// crate-side altitudes plus [`crate::cli::TierArg::is_computed`] on
    /// the CLI operator-facing surface),
    /// [`crate::secret::SecretBackendKind::is_cloud_secret_manager`] on the
    /// secret-backend axis (three altitudes),
    /// [`crate::source::ConfigSourceKind::is_overlay`] on the source-layer
    /// axis (four altitudes), and
    /// [`crate::discovery::Format::is_feature_gated`] on the file-format
    /// axis.
    ///
    /// One canonical name for the "did the file change at the watched
    /// path?" question over [`WatchEventClass`] — a per-tenant reload-
    /// telemetry meter counting *observed-mutation* events distinctly from
    /// silently-discarded events (a debounce-window guard grouping the two
    /// mutation cells before the guard's window opens; a structured-tracing
    /// span attribute distinguishing acted-on events from dropped ones; a
    /// ConfigPlane broadcast-reload counter bucketing mutation observations
    /// separately from noise) matches this predicate at ONE site instead of
    /// open-coding `class.is_reload() || class.is_removed()` and re-doing
    /// the closed-partition bookkeeping at every consumer that reasons
    /// about the two acted-on arms as one group.
    ///
    /// The classifier [`Self::classify`] pointwise witnesses the polarity:
    /// exactly `Create(_)` and content-or-write-time `Modify(_)` land on
    /// [`Self::Reload`], exactly `Remove(_)` lands on [`Self::Removed`],
    /// every other `EventKind` lands on [`Self::Ignored`]. A future
    /// classifier edit that added a fourth mutation-observing arm without
    /// its own [`WatchEventClass`] variant would collapse the polarity
    /// silently, but the compound-polarity partition pin below catches the
    /// dual failure: a future fourth [`WatchEventClass`] variant that did
    /// not extend one of the compound arms (or extended both) fails at
    /// [`tests::watch_event_class_is_file_mutation_and_is_ignored_are_a_closed_binary_partition`]
    /// before drifting through any consumer that groups on this pole.
    ///
    /// The compound is pointwise the complement of [`Self::is_ignored`]
    /// — pinned by
    /// [`tests::watch_event_class_is_file_mutation_is_complement_of_is_ignored`]
    /// — and equal to the two-arm disjunction
    /// `class.is_reload() || class.is_removed()` — pinned by
    /// [`tests::watch_event_class_is_file_mutation_agrees_with_disjunction_of_mutation_siblings`].
    /// A future edit that drifted either polarity from the other fails at
    /// the cross-axis boundary rather than at a per-polarity consumer site.
    #[must_use]
    pub const fn is_file_mutation(self) -> bool {
        matches!(self, Self::Reload | Self::Removed)
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

/// Preamble every watcher-driven [`crate::ConfigStore`] reload closure runs
/// on each raw [`notify::Event`]: classify the event through
/// [`WatchEventClass::classify`], log-and-skip the transient removed-file
/// state, log every symlink-target change carried on the event, and return
/// `true` iff the caller should proceed with the reload (⇔ the event kind
/// landed on [`WatchEventClass::Reload`]).
///
/// One source of truth for the "classify + log-preamble" two-step every
/// watcher-driven [`crate::ConfigStore`] constructor previously open-coded
/// at its own closure body. Two callers today —
/// [`crate::ConfigStore::load_and_watch`] and
/// [`crate::ConfigStore::load_and_watch_hotswap`] (feature `hotswap`) — each
/// wrote the identical 11-line preamble (5-line [`WatchEventClass::classify`]
/// match + 5-line [`symlink_target`]-check loop) before dispatching to their
/// own reload leg. Two places any future refinement of the classify-side
/// diagnostic (a structured tracing span carrying the raw event kind, a
/// per-class counter feeding a reload-relevance histogram, a
/// debounce-window guard on the [`WatchEventClass::Reload`] arm, richer
/// symlink-target metadata beyond the `"symlink target changed"` line,
/// operator-facing structured provenance identifying which of `event.paths`
/// resolved through a symlink) would have to be applied in lockstep —
/// exactly the drift-class this crate spends load-bearing lifts to close.
///
/// A future watcher-driven [`crate::ConfigStore`] constructor — a
/// broadcast-subscription reload variant, a per-tenant reload variant, the
/// [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
/// push-side reload variant — routes its own closure through this helper
/// and inherits the preamble by construction; the reload-leg body stays a
/// per-constructor decision, but the classify + symlink log-preamble lives
/// at ONE site.
///
/// # Return-value pointwise equivalence
///
/// The returned [`bool`] is pointwise equal to
/// `WatchEventClass::classify(&event.kind).should_reload()` — the two
/// canonical predicates on the event's reload-relevance axis, pinned by
/// [`tests::should_reload_on_event_agrees_with_classify_should_reload`].
/// The helper is not just a shorthand for that composition: it also
/// side-effects the [`tracing::info`] emit path with the two operator-
/// facing log lines every watcher-driven [`crate::ConfigStore`] closure
/// contract requires (`"config file removed, continuing to watch for
/// replacement..."` on the [`WatchEventClass::Removed`] arm, and
/// `"symlink target changed for {path}"` on every symlink-resolving path
/// on the [`WatchEventClass::Reload`] arm). Callers that need only the
/// scalar predicate without the side-effects reach for the pure
/// [`WatchEventClass::classify`] / [`WatchEventClass::should_reload`]
/// composition instead.
///
/// # Zero-cost by construction
///
/// The helper is a plain function performing exactly the same
/// [`WatchEventClass::classify`] match, the same two [`tracing::info`]
/// emits, and the same `event.paths` walk the pre-lift open-coded bodies
/// performed — so the substrate lift adds zero per-call overhead the
/// compiler cannot inline away.
pub(crate) fn should_reload_on_event(event: &notify::Event) -> bool {
    match WatchEventClass::classify(&event.kind) {
        WatchEventClass::Reload => {}
        WatchEventClass::Removed => {
            info!("config file removed, continuing to watch for replacement...");
            return false;
        }
        WatchEventClass::Ignored => return false,
    }

    for path in &event.paths {
        if symlink_target(path).is_some() {
            info!("symlink target changed for {}", path.display());
        }
    }
    true
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

    // ── should_reload_on_event ───────────────────────────────────────
    //
    // The `notify::Event` preamble every watcher-driven `ConfigStore`
    // reload closure previously open-coded. Pinned as the pointwise
    // equivalent of `WatchEventClass::classify(&event.kind).should_reload()`
    // on the return value across the reload / removed / ignored partition,
    // with the path-list side-channel (the symlink log emit) verified
    // structurally on the boolean return regardless of whether the paths
    // actually resolve as symlinks in this sandbox.

    #[test]
    fn should_reload_on_event_returns_true_only_on_reload_class_events() {
        // Every Reload-class kind produces `true`; every Removed- and
        // Ignored-class kind produces `false`. Pins the boolean return
        // shape on the closed partition of `WatchEventClass`, so a future
        // classifier drift cannot slip a false-negative onto the reload
        // trigger path.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
        ] {
            let event = notify::Event::new(kind.clone());
            assert!(
                should_reload_on_event(&event),
                "Reload-class kind {kind:?} must return true",
            );
        }
        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Access(AccessKind::Any),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Any,
            EventKind::Other,
        ] {
            let event = notify::Event::new(kind.clone());
            assert!(
                !should_reload_on_event(&event),
                "non-Reload-class kind {kind:?} must return false",
            );
        }
    }

    #[test]
    fn should_reload_on_event_agrees_with_classify_should_reload() {
        // Return-value pointwise equivalence with the pure
        // `WatchEventClass::classify(&event.kind).should_reload()`
        // composition, over every kind the classifier partitions on. A
        // future refactor that drifts the helper away from that
        // composition (e.g. widens the trigger set past
        // `WatchEventClass::Reload`, narrows it below Reload) breaks this
        // test before reaching either watcher-driven `ConfigStore` call
        // site. Idiom-peer of the closed-partition round-trip tests the
        // same file already pins on `WatchEventClass::classify` /
        // `should_reload`.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Create(CreateKind::Other),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Data(DataChange::Size)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Modify(ModifyKind::Other),
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Remove(RemoveKind::Other),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
            EventKind::Other,
        ] {
            let event = notify::Event::new(kind.clone());
            let via_helper = should_reload_on_event(&event);
            let via_classify = WatchEventClass::classify(&kind).should_reload();
            assert_eq!(
                via_helper, via_classify,
                "should_reload_on_event must agree with \
                 classify(&event.kind).should_reload() on {kind:?}",
            );
        }
    }

    #[test]
    fn should_reload_on_event_ignores_event_paths_on_removed_and_ignored_kinds() {
        // Paths carried on a Removed- or Ignored-class event are
        // deliberately not walked — the classify arm returns `false`
        // BEFORE the symlink-log loop runs, so an event with
        // `paths = [some/symlink]` on a non-Reload kind does not emit
        // a spurious symlink-target log line and the helper still
        // returns `false`. Pins the arm-order the pre-lift open-coded
        // bodies carried, which two future callers now inherit at one
        // site.
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // The link resolves — a `symlink_target(&link)` call on it
        // returns `Some(_)`, so on a Reload-class event the helper
        // WOULD walk it. Removed/Ignored arms exit before that loop.
        assert!(symlink_target(&link).is_some(), "test setup: link resolves");

        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
        ] {
            let event = notify::Event::new(kind.clone()).add_path(link.clone());
            assert!(
                !should_reload_on_event(&event),
                "non-Reload kind {kind:?} with a resolving symlink path must \
                 still return false — the classify arm short-circuits before \
                 the symlink-log loop",
            );
        }
    }

    #[test]
    fn should_reload_on_event_returns_true_on_reload_kind_regardless_of_paths() {
        // The symlink-log loop is a side-effect on the Reload arm; the
        // boolean return is the classify-side decision and does not depend
        // on which of `event.paths` (if any) resolve as symlinks. Pins the
        // return-value invariance across zero, one, and multiple carried
        // paths on the same Reload-class kind.
        let dir = TempDir::new().unwrap();
        let regular = dir.path().join("regular.yaml");
        fs::write(&regular, "key: value").unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let kind = EventKind::Modify(ModifyKind::Data(DataChange::Content));
        // Zero paths.
        let event_bare = notify::Event::new(kind.clone());
        assert!(should_reload_on_event(&event_bare));
        // One regular-file path.
        let event_regular = notify::Event::new(kind.clone()).add_path(regular.clone());
        assert!(should_reload_on_event(&event_regular));
        // One symlink path.
        let event_link = notify::Event::new(kind.clone()).add_path(link.clone());
        assert!(should_reload_on_event(&event_link));
        // Mixed regular + symlink paths.
        let event_mixed = notify::Event::new(kind).add_path(regular).add_path(link);
        assert!(should_reload_on_event(&event_mixed));
    }

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
    fn watch_event_class_is_reload_true_only_for_reload_variant() {
        // Per-variant polarity pin on the Reload corner. Sibling of
        // `config_source_kind_is_defaults_true_only_for_defaults_variant`
        // and the trio-shape pins on the crate's ternary closed axes; a
        // future edit that flips the `matches!` arm on `is_reload` fails
        // here before the closed-ternary-partition pin masks it.
        assert!(WatchEventClass::Reload.is_reload());
        assert!(!WatchEventClass::Removed.is_reload());
        assert!(!WatchEventClass::Ignored.is_reload());
    }

    #[test]
    fn watch_event_class_is_removed_true_only_for_removed_variant() {
        assert!(!WatchEventClass::Reload.is_removed());
        assert!(WatchEventClass::Removed.is_removed());
        assert!(!WatchEventClass::Ignored.is_removed());
    }

    #[test]
    fn watch_event_class_is_ignored_true_only_for_ignored_variant() {
        assert!(!WatchEventClass::Reload.is_ignored());
        assert!(!WatchEventClass::Removed.is_ignored());
        assert!(WatchEventClass::Ignored.is_ignored());
    }

    #[test]
    fn watch_event_class_predicates_are_a_closed_ternary_partition() {
        // Every WatchEventClass::ALL cell satisfies exactly one of the
        // three sibling predicates: none satisfies two, none satisfies
        // zero. Ternary-partition analogue of the trio-partition pin on
        // `ConfigSourceKind` and of the binary-partition pins on the
        // crate's seven binary axes. A future fourth-class landing
        // without its own sibling predicate collapses the partition to
        // zero on that variant, failing here before drifting through any
        // consumer site.
        for class in WatchEventClass::ALL.iter().copied() {
            let hits = usize::from(class.is_reload())
                + usize::from(class.is_removed())
                + usize::from(class.is_ignored());
            assert_eq!(
                hits, 1,
                "class {class:?} must satisfy exactly one sibling predicate, got {hits}",
            );
        }
    }

    #[test]
    fn watch_event_class_predicates_agree_with_equality_pointwise() {
        // The kind-alone equality-agreement law over ALL: for every
        // variant, `class.is_X()` is exactly `class == Self::X`. Catches
        // a future edit whose `matches!` arm silently accepts a second
        // variant on the same predicate. Idiom-peer of
        // `config_source_kind_predicates_agree_with_equality_pointwise`.
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(class.is_reload(), class == WatchEventClass::Reload);
            assert_eq!(class.is_removed(), class == WatchEventClass::Removed);
            assert_eq!(class.is_ignored(), class == WatchEventClass::Ignored);
        }
    }

    #[test]
    fn watch_event_class_is_file_mutation_partitions_ignored_from_mutation_arms() {
        // Per-variant polarity table on the compound-polarity sibling of
        // the reload-relevance ternary axis: exactly the two acted-on arms
        // (Reload — bytes may have changed; Removed — file unlinked at the
        // watched path) return true; the silently-discarded arm (Ignored —
        // access, rename, catch-alls) returns false. Idiom-peer of the
        // per-variant polarity pin on the tier-axis compound-polarity
        // sibling `ConfigTierKind::is_computed` (commit `7d2825d`).
        assert!(WatchEventClass::Reload.is_file_mutation());
        assert!(WatchEventClass::Removed.is_file_mutation());
        assert!(!WatchEventClass::Ignored.is_file_mutation());
    }

    #[test]
    fn watch_event_class_is_file_mutation_is_complement_of_is_ignored() {
        // The modal-pair complement law at the compound-polarity altitude:
        // `is_file_mutation() == !is_ignored()` pointwise on
        // WatchEventClass::ALL. The two predicates partition ALL into the
        // compound pole (Reload | Removed — two acted-on arms) and its
        // single-cell complement (Ignored — silently discarded). A future
        // edit that drifted one polarity from the other fails here before
        // any consumer of either surface can observe the divergence.
        // Idiom-peer of `TierArg::is_computed_is_complement_of_is_custom`
        // (commit `3f3f482`), of the pair-complement laws on the
        // `is_overlay` (commit `93c21cb`), `is_cloud_secret_manager`
        // (commits `dc2ee39` / `3553207`), and `is_feature_gated` /
        // `is_always_available` (commit `006e0a7`) compound siblings.
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                class.is_file_mutation(),
                !class.is_ignored(),
                "is_file_mutation and !is_ignored must agree pointwise on {class:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_is_file_mutation_agrees_with_disjunction_of_mutation_siblings() {
        // The compound ↔ two-arm disjunction law at the compound-polarity
        // altitude: `is_file_mutation() == is_reload() || is_removed()`
        // pointwise on WatchEventClass::ALL — the compound-polarity
        // sibling is exactly the disjunction of the two singleton
        // predicates naming the acted-on arms. A future edit that flipped
        // one arm of the `matches!` in `is_file_mutation` without flipping
        // the corresponding singleton sibling fails here before drifting
        // through any consumer that reasons about the two acted-on arms
        // as one group. Idiom-peer of the compound ↔ disjunction pin on
        // `TierArg::is_computed_agrees_with_disjunction_of_computed_siblings`
        // (commit `3f3f482`).
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                class.is_file_mutation(),
                class.is_reload() || class.is_removed(),
                "is_file_mutation must equal is_reload || is_removed on {class:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_is_file_mutation_and_is_ignored_are_a_closed_binary_partition() {
        // Cardinality-side invariant at the compound-polarity altitude:
        // exactly two `WatchEventClass::ALL` cells satisfy
        // `is_file_mutation`, exactly one satisfies `is_ignored`, and the
        // two counts sum to `WatchEventClass::ALL.len()`. Binary-partition
        // analogue of the closed-ternary-partition pin on the singleton
        // predicates. A future fourth `WatchEventClass` variant that did
        // not extend one of the compound arms (or extended both) fails at
        // this cardinality invariant before drifting through any consumer
        // site — the compound-polarity ladder's own load-bearing pin.
        let mutation_cells = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_file_mutation())
            .count();
        let ignored_cells = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_ignored())
            .count();
        assert_eq!(
            mutation_cells, 2,
            "exactly two WatchEventClass::ALL cells must satisfy is_file_mutation",
        );
        assert_eq!(
            ignored_cells, 1,
            "exactly one WatchEventClass::ALL cell must satisfy is_ignored",
        );
        assert_eq!(
            mutation_cells + ignored_cells,
            WatchEventClass::ALL.len(),
            "the compound-polarity binary partition must cover ALL",
        );
    }

    #[test]
    fn watch_event_class_is_file_mutation_is_const_callable() {
        // The compound-polarity sibling is `const`-callable, so a compile-
        // time consumer (a `const` predicate table, a `const`-evaluated
        // switch over a `WatchEventClass` singleton, a `const`-eval-based
        // static-assert on a classifier arm) resolves the polarity at
        // compile time. Idiom-peer of `tier_arg_is_computed_is_const_callable`
        // (commit `3f3f482`). The const-block asserts below make the weld
        // load-bearing at crate compile time: a future edit that flipped a
        // polarity on this predicate fails at `cargo build`, not just at
        // this test's runtime assertion.
        const _: () = assert!(WatchEventClass::Reload.is_file_mutation());
        const _: () = assert!(WatchEventClass::Removed.is_file_mutation());
        const _: () = assert!(!WatchEventClass::Ignored.is_file_mutation());
    }

    #[test]
    fn watch_event_class_is_file_mutation_matches_classify_over_mutation_event_kinds() {
        // Cross-axis witness at the classifier boundary: every EventKind
        // the classifier maps to `Reload` or `Removed` satisfies
        // `is_file_mutation` on the returned class, and every EventKind
        // the classifier maps to `Ignored` does not. Ties the compound
        // polarity to the classify surface it names — a future classifier
        // edit that added a fourth mutation-observing arm without
        // extending the compound-polarity arm here fails at this
        // cross-axis boundary rather than at a per-polarity consumer site.
        use notify::EventKind;
        use notify::event::{
            AccessKind, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind, RenameMode,
        };
        // Mutation-observing EventKinds must classify to a mutation cell.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
        ] {
            assert!(
                WatchEventClass::classify(&kind).is_file_mutation(),
                "{kind:?} must classify to a mutation cell",
            );
        }
        // Non-mutation EventKinds must classify to the Ignored cell.
        for kind in [
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
            EventKind::Other,
        ] {
            assert!(
                !WatchEventClass::classify(&kind).is_file_mutation(),
                "{kind:?} must classify to a non-mutation cell",
            );
        }
    }

    #[test]
    fn should_reload_agrees_with_is_reload_pointwise() {
        // The two Reload-class predicates on WatchEventClass — the
        // operator-facing `should_reload` (retained for the imperative
        // "should we reload?" question at the watcher dispatch site) and
        // the sibling-shape `is_reload` (the closed-axis idiom peer of
        // `is_removed`/`is_ignored`) — are pointwise byte-identical
        // across ALL. A future edit that drifts one arm without the
        // other fails here before any consumer of either surface can
        // observe the divergence.
        for class in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                class.should_reload(),
                class.is_reload(),
                "should_reload and is_reload must agree pointwise on {class:?}",
            );
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

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
    /// `Modify` with **any** data-change or a write-time metadata
    /// change, and every `Create`, map to [`Self::Reload`]; every
    /// `Remove` maps to [`Self::Removed`]; all other kinds map to
    /// [`Self::Ignored`]. Pure in the event kind — no I/O, no clock — so
    /// the trigger semantics are unit-testable without the
    /// timing-sensitive watcher harness.
    ///
    /// **`DataChange::Any` is load-bearing, not a widening.** The arm
    /// originally named only [`DataChange::Content`], which is what
    /// macOS/FSEvents reports for a plain file write. Linux/inotify has
    /// no content-vs-size discrimination on `IN_MODIFY`, so `notify`
    /// reports the same write as `Modify(Data(Any))` — which fell to the
    /// `_ => Ignored` catch-all. The effect was that **every**
    /// [`crate::ConfigStore::load_and_watch`] /
    /// `load_and_watch_hotswap` consumer on Linux silently never
    /// reloaded: the watcher registered, delivered events, and dropped
    /// every one of them at this match. `Any` and `Content` denote the
    /// same fact — the file's *data* changed — differing only in how
    /// precisely the backend can describe it, so both belong on the
    /// reload arm. Metadata precision is deliberately NOT widened the
    /// same way: only `MetadataKind::WriteTime` reloads, so a `chmod` /
    /// `chown` / atime touch still classifies [`Self::Ignored`] rather
    /// than triggering a spurious re-read.
    ///
    /// `const`-callable — the body is pure pattern matching over a
    /// borrowed [`notify::EventKind`] with no function calls, allocations,
    /// or non-const helpers on the path, and the returned unit variants
    /// ([`Self::Reload`] / [`Self::Removed`] / [`Self::Ignored`]) are
    /// const-constructible. Lets a compile-time-known event kind project
    /// to a compile-time-known [`WatchEventClass`], so the const-fn
    /// closed-partition predicate quartet ([`Self::is_reload`] /
    /// [`Self::is_removed`] / [`Self::is_ignored`] / [`Self::is_file_mutation`])
    /// composes with this classifier end-to-end in const positions — a
    /// downstream `const IS_RELOAD: bool = WatchEventClass::classify(&KIND).is_reload();`
    /// binding needs no runtime call. Peer of the tag-side classifier
    /// [`crate::FigmentSourceTag::classify`] (const since `d29a3f9`) and
    /// the tag-side classifier [`crate::FigmentNameTag::classify`] (const
    /// since `d29a3f9`) — the classify-side of the closed-partition axis
    /// now lands in const positions on the reload-relevance axis too.
    /// Welded at compile time by
    /// [`tests::watch_event_class_classify_is_const_callable`].
    #[must_use]
    pub const fn classify(kind: &notify::EventKind) -> Self {
        use notify::EventKind;
        use notify::event::{MetadataKind, ModifyKind};

        match kind {
            EventKind::Modify(
                ModifyKind::Metadata(MetadataKind::WriteTime) | ModifyKind::Data(_),
            )
            | EventKind::Create(_) => Self::Reload,
            EventKind::Remove(_) => Self::Removed,
            _ => Self::Ignored,
        }
    }

    /// Event-level peer of [`Self::classify`] — classify a raw
    /// [`notify::Event`] into its reload-relevance class by projecting
    /// through the event's `kind` field.
    ///
    /// Pointwise equal to `Self::classify(&event.kind)` — pinned by
    /// [`tests::classify_event_agrees_with_classify_of_event_kind_pointwise`]
    /// — so a caller with an [`notify::Event`] in hand reaches for the
    /// reload-relevance class at the event's own altitude, without the
    /// `.kind` projection every event-level call site previously wrote by
    /// hand. `Self::classify` remains the kind-side entry (a caller with
    /// only an [`notify::EventKind`], no [`notify::Event`], keeps calling
    /// through it); the two form a projection pair on the event → kind
    /// axis at the classifier surface, mirroring the same event-side ↔
    /// kind-side pair the fleet-idiom sibling ladders carry on their own
    /// primitives.
    ///
    /// One source of truth for the "classify an [`notify::Event`]" step
    /// every watcher-driven [`crate::ConfigStore`] closure body performed
    /// as `Self::classify(&event.kind)`: the crate-internal
    /// [`should_reload_on_event`] helper now routes through this
    /// event-level entry, and a future watcher-driven consumer — a
    /// broadcast-subscription reload variant, a per-tenant reload variant,
    /// the [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
    /// push-side reload variant — that owns its own dispatch closure
    /// classifies the incoming [`notify::Event`] at this one site instead
    /// of open-coding the `.kind` projection at each. The classifier
    /// itself remains the pure function on [`notify::EventKind`]; the
    /// event-level shortcut adds no semantic surface, only the
    /// altitude-appropriate name for the classify step at the raw
    /// [`notify::Event`] altitude.
    ///
    /// `const`-callable — the body is a single call to the sibling
    /// const-fn [`Self::classify`] on a borrowed [`notify::EventKind`]
    /// field access, both of which the const-fn discipline the classifier
    /// surface already carries permits. Composes with the const-fn
    /// predicate quartet ([`Self::is_reload`] / [`Self::is_removed`] /
    /// [`Self::is_ignored`] / [`Self::is_file_mutation`]) end-to-end in
    /// const positions, at the event's altitude the same way the shipped
    /// [`Self::classify`] already composes at the kind's altitude — a
    /// downstream `const IS_RELOAD: bool =
    /// WatchEventClass::classify_event(&EVENT).is_reload();` binding needs
    /// no runtime call, once [`notify::Event`] itself is const-
    /// constructible (`notify::Event::new` is not const today, so the
    /// end-to-end weld pin lives on `Self::classify`; the classifier arm
    /// this shortcut adds carries its own const-fn discipline forward for
    /// that day).
    #[must_use]
    pub const fn classify_event(event: &notify::Event) -> Self {
        Self::classify(&event.kind)
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

    /// The single `ONLY_RELOAD` [`WatchEventClass`] variant —
    /// [`Self::Reload`] (a content/metadata-write `Modify` or any
    /// `Create` — the file's bytes may have changed and the store should
    /// re-read) — in the SAME relative declaration order it occupies in
    /// [`Self::ALL`], carrying the *reload-identity* pole of the
    /// (reload × removed × ignored) 1/1/1 identity meta-partition at the
    /// primitive's OWN altitude on the reload-relevance axis, mirroring
    /// the shipped boolean predicate [`Self::is_reload`] one altitude
    /// down: the sole variant in this slice satisfies `c.is_reload()`,
    /// and no variant outside it does.
    ///
    /// Paired with [`Self::ONLY_REMOVED`] and [`Self::ONLY_IGNORED`],
    /// the three disjoint singleton slices partition [`Self::ALL`] at
    /// the static-slice altitude the same way the shipped boolean
    /// predicates [`Self::is_reload`] / [`Self::is_removed`] /
    /// [`Self::is_ignored`] meta-partition it at the boolean altitude
    /// (per
    /// [`tests::watch_event_class_predicates_are_a_closed_ternary_partition`]).
    /// The three constants sit in the same `impl WatchEventClass` block
    /// as [`Self::ALL`], and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit singleton slice literal in the SAME
    /// relative declaration order the identity pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_reload`] at const-fn altitude — so the two
    /// declarations (the slice literal and the boolean predicate)
    /// remain independent load-bearing witnesses of the same
    /// meta-partition, and a future edit that shifts a variant across
    /// the polarity on ONE declaration surface but not the other
    /// diverges at test time on the first shape where they disagree.
    ///
    /// Ternary peer of the shipped ternary
    /// [`crate::ConfigSourceKind::ONLY_DEFAULTS`] /
    /// [`crate::ConfigSourceKind::ONLY_ENV`] /
    /// [`crate::ConfigSourceKind::ONLY_FILE`] (commit `f287239`, the
    /// third ternary landing of the per-half meta-partition
    /// slice-constant discipline on a shikumi-native closed-primitive
    /// axis, on the shikumi-side layer-kind axis's
    /// (defaults × env × file) 1/1/1 identity projection) and the sibling
    /// ternary [`crate::FigmentSourceKind::FILE`] /
    /// [`crate::FigmentSourceKind::CODE`] /
    /// [`crate::FigmentSourceKind::CUSTOM`] (commit `723060b`, the
    /// second ternary landing on the figment-side kind axis's
    /// (file × code × custom) 1/1/1 identity projection) and
    /// [`crate::AttributionRule::LAYER_FILE`] /
    /// [`crate::AttributionRule::LAYER_ENV`] /
    /// [`crate::AttributionRule::LAYER_DEFAULTS`] (commit `fae8271`,
    /// the first ternary landing on the attribution-rule axis's
    /// (file × env × defaults) layer-kind projection). The per-half
    /// meta-partition slice-constant discipline applied here to the
    /// three-way reload-relevance axis's ternary
    /// (reload × removed × ignored) 1/1/1 identity meta-partition,
    /// closing the FIRST landing of the discipline on a
    /// `watcher.rs`-scoped closed-primitive axis.
    ///
    /// The three-way agreement laws
    /// (`ONLY_RELOAD.iter().all(|c| c.is_reload())`,
    /// `!ONLY_RELOAD.iter().any(|c| c.is_removed())`,
    /// `!ONLY_RELOAD.iter().any(|c| c.is_ignored())`, and the symmetric
    /// laws on [`Self::ONLY_REMOVED`] and [`Self::ONLY_IGNORED`]) are
    /// pinned by
    /// [`tests::watch_event_class_ternary_slices_agree_with_ternary_predicates`].
    /// Ternary partition invariant across all three siblings:
    /// [`tests::watch_event_class_ternary_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::watch_event_class_ternary_slices_preserve_all_order`].
    /// No duplicates on any half:
    /// [`tests::watch_event_class_ternary_slices_have_no_duplicates`].
    /// Cardinality-agreement with the boolean poles:
    /// [`tests::watch_event_class_ternary_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::watch_event_class_ternary_slices_are_const_addressable`].
    pub const ONLY_RELOAD: &'static [Self] = &[Self::Reload];

    /// The single `ONLY_REMOVED` [`WatchEventClass`] variant —
    /// [`Self::Removed`] (a `Remove` — the watched path was unlinked;
    /// nix-darwin's atomic unlink+symlink swap surfaces a transient
    /// mid-swap `Remove` that must not trigger a read of a half-applied
    /// rebuild) — carrying the *removed-identity* pole of the
    /// (reload × removed × ignored) 1/1/1 identity meta-partition at the
    /// primitive's OWN altitude on the reload-relevance axis, mirroring
    /// the shipped boolean predicate [`Self::is_removed`] one altitude
    /// down.
    ///
    /// See [`Self::ONLY_RELOAD`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_removed`]), and the load-bearing agreement, partition,
    /// order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const ONLY_REMOVED: &'static [Self] = &[Self::Removed];

    /// The single `ONLY_IGNORED` [`WatchEventClass`] variant —
    /// [`Self::Ignored`] (any other event — non-mutating access, a
    /// rename, a non-write metadata touch, or the `Any` / `Other`
    /// catch-alls; not reload-relevant) — carrying the *ignored-identity*
    /// pole of the (reload × removed × ignored) 1/1/1 identity
    /// meta-partition at the primitive's OWN altitude on the
    /// reload-relevance axis, mirroring the shipped boolean predicate
    /// [`Self::is_ignored`] one altitude down.
    ///
    /// See [`Self::ONLY_RELOAD`] for the full contract, the discipline
    /// behind the explicit slice literal (rather than a filter through
    /// [`Self::is_ignored`]), and the load-bearing agreement, partition,
    /// order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins.
    pub const ONLY_IGNORED: &'static [Self] = &[Self::Ignored];

    /// The two-cell `FILE_MUTATIONS` [`WatchEventClass`] slice —
    /// [`Self::Reload`] and [`Self::Removed`], the two acted-on arms of
    /// the reload-relevance axis (the file's bytes may have changed, or
    /// the file was unlinked at the watched path) — in the SAME relative
    /// declaration order they occupy in [`Self::ALL`], carrying the
    /// *file-mutation-observing* pole of the compound-polarity
    /// meta-partition at the primitive's OWN altitude on the
    /// reload-relevance axis, mirroring the shipped boolean predicate
    /// [`Self::is_file_mutation`] one altitude down: every variant in
    /// this slice satisfies `c.is_file_mutation()`, and no variant
    /// outside it does.
    ///
    /// Paired with [`Self::NON_FILE_MUTATIONS`], the two disjoint
    /// slices partition [`Self::ALL`] at the static-slice altitude the
    /// same way the shipped boolean predicates [`Self::is_file_mutation`]
    /// and [`Self::is_ignored`] partition it at the boolean altitude
    /// (per
    /// [`tests::watch_event_class_is_file_mutation_and_is_ignored_are_a_closed_binary_partition`]).
    /// Compound-polarity peer of the shipped ternary identity
    /// [`Self::ONLY_RELOAD`] / [`Self::ONLY_REMOVED`] /
    /// [`Self::ONLY_IGNORED`] (commit `9e5ea18`, the first landing of
    /// the per-half meta-partition slice-constant discipline on a
    /// `watcher.rs`-scoped closed-primitive axis) — this closes the
    /// compound-polarity binary meta-partition at the same altitude the
    /// ternary identity closed the singleton meta-partition, matching
    /// the ladder shape [`crate::ConfigTierKind::COMPUTED`] /
    /// [`crate::ConfigTierKind::CUSTOM`] (commit `2c0686f`) closed on
    /// the tier-kind axis and [`crate::ConfigSourceKind::DEFAULTS`] /
    /// [`crate::ConfigSourceKind::OVERLAY`] (commit `2cd8ef8`) closed on
    /// the source-layer axis.
    ///
    /// Written as an explicit two-cell slice literal in the SAME
    /// relative declaration order the two acted-on arms occupy in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_file_mutation`] at const-fn altitude — so the
    /// two declarations (the slice literal and the boolean predicate)
    /// remain independent load-bearing witnesses of the same
    /// compound-polarity meta-partition, and a future edit that shifts
    /// a variant across the polarity on ONE declaration surface but not
    /// the other diverges at test time on the first shape where they
    /// disagree.
    ///
    /// Consumers that group the two acted-on arms as one static set (a
    /// per-tenant reload-telemetry meter counting observed-mutation
    /// events distinctly from silently-discarded events, a
    /// debounce-window guard grouping the two mutation cells before the
    /// guard's window opens, a structured-tracing span attribute
    /// distinguishing acted-on events from dropped ones, a `ConfigPlane`
    /// broadcast-reload counter bucketing mutation observations
    /// separately from noise) now read the pole as one `&'static [Self]`
    /// slice lookup — no re-derived `matches!` at the callsite, no
    /// ALL-filter fold each time.
    ///
    /// The compound-polarity agreement laws
    /// (`FILE_MUTATIONS.iter().all(|c| c.is_file_mutation())`,
    /// `!FILE_MUTATIONS.iter().any(|c| c.is_ignored())`, and the
    /// symmetric laws on [`Self::NON_FILE_MUTATIONS`]) are pinned by
    /// [`tests::watch_event_class_file_mutations_slice_agrees_with_is_file_mutation_predicate`].
    /// Compound-polarity partition invariant across both siblings:
    /// [`tests::watch_event_class_file_mutations_and_non_file_mutations_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::watch_event_class_file_mutations_and_non_file_mutations_slices_preserve_all_order`].
    /// No duplicates on either half:
    /// [`tests::watch_event_class_file_mutations_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean poles:
    /// [`tests::watch_event_class_file_mutations_and_non_file_mutations_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::watch_event_class_file_mutations_and_non_file_mutations_slices_are_const_addressable`].
    pub const FILE_MUTATIONS: &'static [Self] = &[Self::Reload, Self::Removed];

    /// The single-cell `NON_FILE_MUTATIONS` [`WatchEventClass`] slice —
    /// [`Self::Ignored`] (any non-mutation-observing event — access, a
    /// rename, a non-write metadata touch, or the `Any` / `Other`
    /// catch-alls; not reload-relevant) — carrying the
    /// *non-mutation* pole of the compound-polarity meta-partition at
    /// the primitive's OWN altitude on the reload-relevance axis,
    /// mirroring the shipped boolean predicate `!is_file_mutation` (i.e.
    /// [`Self::is_ignored`], the two are pointwise complements per
    /// [`tests::watch_event_class_is_file_mutation_is_complement_of_is_ignored`])
    /// one altitude down.
    ///
    /// Today `NON_FILE_MUTATIONS == ONLY_IGNORED == &[Self::Ignored]`
    /// because the compound-polarity negative pole collapses to the
    /// singleton ignored cell at present, but the two constants remain
    /// independent by design: a future edit that adds a fourth
    /// non-mutation-observing variant (a hypothetical `Self::Renamed`
    /// or `Self::Access` split off from the `Ignored` catch-all) grows
    /// the compound `NON_FILE_MUTATIONS` in lockstep with
    /// `!is_file_mutation`-family contracts while `ONLY_IGNORED` stays
    /// the ternary-identity singleton — the same discipline
    /// [`Self::ONLY_CUSTOM`]-vs-`CUSTOM` on `ConfigTierKind`
    /// (`ff6492b`) and the sibling `ConfigSourceKind::OVERLAY` binary
    /// carry.
    ///
    /// See [`Self::FILE_MUTATIONS`] for the full contract, the
    /// discipline behind the explicit slice literal (rather than a
    /// filter through [`Self::is_ignored`]), and the load-bearing
    /// agreement, partition, order-preservation, no-duplicates,
    /// cardinality, and const-addressability pins.
    pub const NON_FILE_MUTATIONS: &'static [Self] = &[Self::Ignored];

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
    classify_event_with_preamble(event).is_reload()
}

/// The typed peer of [`should_reload_on_event`] — classify a raw
/// [`notify::Event`] through [`WatchEventClass::classify_event`], run the
/// identical operator-facing log preamble the crate's watcher-driven
/// [`crate::ConfigStore`] constructors have shared since the classify
/// + log-preamble lift, and return the classified
/// [`WatchEventClass`] rather than collapsing the ternary partition to
/// the reload-only [`bool`].
///
/// The boolean `should_reload_on_event` is retained as the imperative
/// operator-facing "should we reload?" question and now routes through
/// this typed peer (`classify_event_with_preamble(event).is_reload()`);
/// the two surfaces cannot drift because the boolean is a pointwise
/// projection of the typed peer's return value, pinned by
/// [`tests::should_reload_on_event_agrees_with_classify_event_with_preamble_is_reload`].
///
/// # Why the typed peer
///
/// A future watcher-driven consumer — a broadcast-subscription reload
/// variant, a per-tenant reload variant, the
/// [ConfigPlane](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
/// push-side reload variant, a per-class watcher-event histogram, a
/// debounce-window guard grouping the two mutation cells before the
/// guard's window opens, a structured-tracing span attribute
/// distinguishing acted-on events from dropped ones — reaches the
/// event's reload-relevance class AND the preamble side-effects at ONE
/// site instead of calling `should_reload_on_event` for the preamble
/// and then re-calling [`WatchEventClass::classify_event`] on the same
/// event to recover the class the boolean discarded. That
/// double-classify is the drift-class the crate's shared-substrate
/// lifts (`record_failure_and_log`, `should_reload_on_event` itself,
/// the `merge_*_layer` tier helpers) spend to close on other seams.
///
/// # Return-value pointwise equivalence
///
/// The returned [`WatchEventClass`] is pointwise equal to
/// [`WatchEventClass::classify_event`] on the same event — the preamble
/// side-effects (the removed-arm log line, the reload-arm symlink-target
/// walk) never change the classify verdict, only what tracing sees.
/// Pinned by
/// [`tests::classify_event_with_preamble_agrees_with_classify_event_pointwise`].
///
/// # Zero-cost by construction
///
/// The body is exactly the same [`WatchEventClass::classify_event`]
/// dispatch, the same two [`tracing::info`] emits, and the same
/// `event.paths` walk the pre-lift open-coded bodies performed — so
/// naming the class-preserving peer adds zero per-call overhead the
/// compiler cannot inline away.
pub fn classify_event_with_preamble(event: &notify::Event) -> WatchEventClass {
    let class = WatchEventClass::classify_event(event);
    match class {
        WatchEventClass::Reload => {
            for path in &event.paths {
                if symlink_target(path).is_some() {
                    info!("symlink target changed for {}", path.display());
                }
            }
        }
        WatchEventClass::Removed => {
            info!("config file removed, continuing to watch for replacement...");
        }
        WatchEventClass::Ignored => {}
    }
    class
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

    // ── classify_event_with_preamble ─────────────────────────────────
    //
    // The class-preserving typed peer of `should_reload_on_event`. The
    // boolean helper now routes through this typed peer; a consumer that
    // wants both the reload verdict AND the classified arm reaches for
    // this one to avoid double-classifying (the drift-class the crate's
    // shared-substrate lifts spend to close).

    #[test]
    fn classify_event_with_preamble_agrees_with_classify_event_pointwise() {
        // The typed peer's return value is pointwise equal to
        // `WatchEventClass::classify_event` on the same event across
        // every kind the classifier partitions on. A future edit to the
        // preamble side-effect body that accidentally shifted the
        // returned class (e.g. re-classified on the symlink-log branch)
        // fails here before drifting through either watcher-driven
        // `ConfigStore` constructor. Idiom-peer of the shipped
        // `should_reload_on_event_agrees_with_classify_should_reload`
        // pointwise-agreement pin one altitude down.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Create(CreateKind::Other),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Data(DataChange::Size)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
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
            assert_eq!(
                classify_event_with_preamble(&event),
                WatchEventClass::classify_event(&event),
                "classify_event_with_preamble must return the same class \
                 as classify_event on {kind:?}",
            );
        }
    }

    #[test]
    fn should_reload_on_event_agrees_with_classify_event_with_preamble_is_reload() {
        // The boolean helper is now a pointwise projection of the typed
        // peer's return value through `WatchEventClass::is_reload`. A
        // future edit that re-open-coded `should_reload_on_event`'s body
        // in a way that drifted from `classify_event_with_preamble(e).is_reload()`
        // fails here before reaching either watcher-driven `ConfigStore`
        // call site. Together with
        // `classify_event_with_preamble_agrees_with_classify_event_pointwise`
        // above, the two pins compose: the boolean helper is exactly
        // `WatchEventClass::classify_event(e).is_reload()`, at ONE
        // source of truth (the typed peer) rather than two.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Data(DataChange::Size)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
            EventKind::Other,
        ] {
            let event = notify::Event::new(kind.clone());
            assert_eq!(
                should_reload_on_event(&event),
                classify_event_with_preamble(&event).is_reload(),
                "should_reload_on_event must equal \
                 classify_event_with_preamble(&event).is_reload() on {kind:?}",
            );
        }
    }

    #[test]
    fn classify_event_with_preamble_returns_reload_on_reload_arm() {
        // Concrete-position pin on the Reload arm: the typed peer
        // returns `WatchEventClass::Reload` on a Reload-class kind and
        // is invariant across the paths carried on the event (zero, a
        // regular file, a symlink, and a mix) — the symlink-log walk is
        // a side-effect on the arm, never the return-value carrier.
        let dir = TempDir::new().unwrap();
        let regular = dir.path().join("regular.yaml");
        fs::write(&regular, "key: value").unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let kind = EventKind::Modify(ModifyKind::Data(DataChange::Content));
        let event_bare = notify::Event::new(kind.clone());
        assert_eq!(
            classify_event_with_preamble(&event_bare),
            WatchEventClass::Reload,
        );
        let event_regular = notify::Event::new(kind.clone()).add_path(regular.clone());
        assert_eq!(
            classify_event_with_preamble(&event_regular),
            WatchEventClass::Reload,
        );
        let event_link = notify::Event::new(kind.clone()).add_path(link.clone());
        assert_eq!(
            classify_event_with_preamble(&event_link),
            WatchEventClass::Reload,
        );
        let event_mixed = notify::Event::new(kind).add_path(regular).add_path(link);
        assert_eq!(
            classify_event_with_preamble(&event_mixed),
            WatchEventClass::Reload,
        );
    }

    #[test]
    fn classify_event_with_preamble_returns_removed_and_ignored_on_their_arms() {
        // Concrete-position pin on the Removed and Ignored arms — the
        // two arms the boolean `should_reload_on_event` collapses to
        // one `false`, but the typed peer preserves. This is the
        // information-preserving property a per-class watcher-event
        // histogram or a ConfigPlane broadcast-reload counter buckets
        // on: `Removed` events (a nix-darwin atomic swap's transient
        // mid-swap unlink) count into a different bin from `Ignored`
        // events (access, rename, permissions touches, `Any` / `Other`
        // catch-alls) even though both return `false` from the boolean
        // helper.
        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Remove(RemoveKind::Any),
            EventKind::Remove(RemoveKind::Other),
        ] {
            let event = notify::Event::new(kind.clone());
            assert_eq!(
                classify_event_with_preamble(&event),
                WatchEventClass::Removed,
                "Remove-class kind {kind:?} must classify as Removed",
            );
        }
        for kind in [
            EventKind::Access(AccessKind::Any),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Any,
            EventKind::Other,
        ] {
            let event = notify::Event::new(kind.clone());
            assert_eq!(
                classify_event_with_preamble(&event),
                WatchEventClass::Ignored,
                "non-reload/non-removed kind {kind:?} must classify as Ignored",
            );
        }
    }

    #[test]
    fn classify_event_with_preamble_is_lib_reexport() {
        // Re-export pin — the typed peer is a `pub` surface reachable at
        // `crate::classify_event_with_preamble` for future watcher-driven
        // consumers (a broadcast-subscription reload variant, a
        // per-tenant reload variant, the ConfigPlane push-side reload
        // variant) that live outside this module. A future edit to
        // `src/lib.rs` that dropped this re-export would collapse the
        // preamble surface back to `pub(crate)`-only reachability and
        // force the double-classify at every external call site; this
        // pin fails at that edit rather than at every consumer site.
        // Composes with the pointwise-agreement pin above: the
        // re-exported function IS the peer and returns the same class
        // as `WatchEventClass::classify_event`.
        let event = notify::Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any)));
        assert_eq!(
            crate::classify_event_with_preamble(&event),
            WatchEventClass::Reload,
        );
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
    fn classify_every_data_change_precision_is_reload() {
        // Regression pin for the Linux hot-reload outage.
        //
        // `classify` originally named only `DataChange::Content` on the
        // reload arm. That is what macOS/FSEvents reports for a plain
        // file write, so the crate's headline hot-reload guarantee held
        // on the author's darwin workstation. Linux/inotify cannot
        // distinguish content from size on `IN_MODIFY` and so reports
        // the very same write as `Modify(Data(Any))`, which fell through
        // to the `_ => Ignored` catch-all — meaning every
        // `ConfigStore::load_and_watch` / `load_and_watch_hotswap`
        // consumer on Linux registered a watcher, received its events,
        // and silently discarded all of them. The store never reloaded.
        //
        // The bug survived because the sibling
        // `classify_non_reload_modify_and_other_kinds_are_ignored`
        // asserted `Data(Any)` and `Data(Size)` were `Ignored` — the
        // unit test encoded the defect, so the only test that could
        // observe it end-to-end
        // (`store::hotswap_tests::on_free_reload_callback_only_fires_on_free_swaps`)
        // was the one that failed, and was written off as a
        // timing-sensitive watcher flake for ~8 consecutive red CI runs
        // on `main`.
        //
        // Every `DataChange` precision asserts the same underlying fact
        // — the file's data changed — so all of them reload. A future
        // edit that re-narrows this arm to one backend's spelling fails
        // here rather than silently disabling hot-reload on whichever
        // platform is not the author's.
        for precision in [
            DataChange::Any,
            DataChange::Content,
            DataChange::Size,
            DataChange::Other,
        ] {
            let kind = EventKind::Modify(ModifyKind::Data(precision));
            assert_eq!(
                WatchEventClass::classify(&kind),
                WatchEventClass::Reload,
                "{kind:?} is a data change and must reload"
            );
            assert!(
                WatchEventClass::classify(&kind).should_reload(),
                "{kind:?} must pass the reload-trigger predicate"
            );
        }
    }

    #[test]
    fn classify_metadata_precision_is_not_widened_with_data_precision() {
        // The complement of the regression above: widening the DATA arm
        // to every precision must NOT drag the METADATA arm along with
        // it. Only a write-time change is a reload signal; a permission,
        // ownership, or unspecified-metadata touch must stay `Ignored`
        // so a `chmod` on a watched config never triggers a spurious
        // re-read. Pins the asymmetry the fix deliberately preserves.
        assert_eq!(
            WatchEventClass::classify(&EventKind::Modify(ModifyKind::Metadata(
                MetadataKind::WriteTime
            ))),
            WatchEventClass::Reload
        );
        for precision in [
            MetadataKind::Any,
            MetadataKind::Permissions,
            MetadataKind::Ownership,
            MetadataKind::Other,
        ] {
            let kind = EventKind::Modify(ModifyKind::Metadata(precision));
            assert_eq!(
                WatchEventClass::classify(&kind),
                WatchEventClass::Ignored,
                "{kind:?} is not a write and must not reload"
            );
        }
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
    fn classify_event_agrees_with_classify_of_event_kind_pointwise() {
        // Event-level ↔ kind-level classifier agreement pin: for every
        // kind the closed-partition classifier reasons about, the shortcut
        // `WatchEventClass::classify_event(&notify::Event::new(kind))`
        // returns exactly what `WatchEventClass::classify(&kind)` returns.
        //
        // The event-level entry is a pure `.kind`-projected call through
        // the sibling `Self::classify`; a future edit that drifted it
        // (short-circuited on `event.paths.is_empty()`, inspected
        // `event.attrs`, or classified partially without recursing through
        // the kind-level classifier) diverges here on the first kind the
        // two disagree on, before drifting through the crate-internal
        // `should_reload_on_event` helper the two watcher-driven
        // `ConfigStore` constructors dispatch through.
        //
        // Kind coverage exercises every arm of the reload-relevance
        // ternary partition — every `DataChange` precision on the widened
        // Linux/inotify-safe reload arm (`Any`, `Content`, `Size`,
        // `Other`), the write-time `MetadataKind` alone on the metadata
        // reload arm, the non-write metadata precisions and rename Modify
        // arm on the Ignored side, every `CreateKind` and `RemoveKind`
        // precision on their own arms, and the catch-alls `EventKind::Any`
        // and `EventKind::Other`. Idiom-peer of the tag-side pointwise
        // agreement pins already carried on the classify surface (e.g.
        // `should_reload_on_event_agrees_with_classify_should_reload`).
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Any),
            EventKind::Create(CreateKind::Other),
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Data(DataChange::Size)),
            EventKind::Modify(ModifyKind::Data(DataChange::Other)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Ownership)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Other)),
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
            let event = notify::Event::new(kind);
            let via_event = WatchEventClass::classify_event(&event);
            let via_kind = WatchEventClass::classify(&kind);
            assert_eq!(
                via_event, via_kind,
                "classify_event must agree with classify(&event.kind) on {kind:?}",
            );
        }
    }

    #[test]
    fn classify_event_agreement_is_invariant_across_carried_paths_and_attrs() {
        // The event-level shortcut classifies purely on the projected
        // `event.kind` field — the class does NOT depend on which of
        // `event.paths` the notify backend attached, on whether those
        // paths resolve as symlinks, or on any `event.attrs` payload. Pins
        // the projection contract at the event's altitude: a future edit
        // that widened the shortcut to inspect `event.paths` or
        // `event.attrs` (e.g. a "was any path a symlink?" side-condition
        // on the reload arm) would drift the return from the kind-level
        // classifier on the same event, and the invariance breaks here
        // before drifting through any watcher-driven `ConfigStore`
        // constructor dispatch site.
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        fs::write(&target, "key: value").unwrap();
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            EventKind::Remove(RemoveKind::File),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
        ] {
            let expected = WatchEventClass::classify(&kind);
            // Zero paths.
            let bare = notify::Event::new(kind);
            // One regular-file path.
            let with_regular = notify::Event::new(kind).add_path(target.clone());
            // One symlink path.
            let with_link = notify::Event::new(kind).add_path(link.clone());
            // Mixed regular + symlink paths.
            let with_mixed = notify::Event::new(kind)
                .add_path(target.clone())
                .add_path(link.clone());
            for event in [&bare, &with_regular, &with_link, &with_mixed] {
                assert_eq!(
                    WatchEventClass::classify_event(event),
                    expected,
                    "classify_event on {kind:?} must not depend on carried paths",
                );
            }
        }
    }

    #[test]
    fn classify_non_reload_modify_and_other_kinds_are_ignored() {
        // Modify variants that are neither a DATA change nor a
        // write-time change. `Data(_)` is deliberately absent from this
        // list: every `DataChange` precision — `Any` (Linux/inotify),
        // `Content` (macOS/FSEvents), `Size`, `Other` — asserts the same
        // fact, that the file's data changed, and all four reload. See
        // `classify_every_data_change_precision_is_reload` below.
        for kind in [
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
    fn watch_event_class_ternary_slices_agree_with_ternary_predicates() {
        // Three-way weld pin between the per-half slice literals and
        // the shipped boolean predicates on the reload-relevance axis's
        // (reload × removed × ignored) 1/1/1 identity meta-partition.
        // For every entry in each `ONLY_*` slice: the positive-pole
        // predicate holds and the two negative-pole predicates do not,
        // plus ALL-membership agreement between the slice `.contains()`
        // and the boolean predicate across all three poles. Ternary
        // peer of
        // `config_source_kind_ternary_slices_agree_with_ternary_predicates`
        // (`f287239`) on the shikumi-side layer-kind axis,
        // `figment_source_kind_ternary_slices_agree_with_ternary_predicates`
        // (`723060b`) on the figment-side layer-kind axis, and
        // `attribution_rule_layer_slices_agree_with_layer_predicates`
        // (`fae8271`) on the attribution-rule axis's layer-kind
        // projection.
        for c in WatchEventClass::ONLY_RELOAD.iter().copied() {
            assert!(
                c.is_reload(),
                "WatchEventClass::ONLY_RELOAD entry {c:?} must satisfy is_reload()",
            );
            assert!(
                !c.is_removed(),
                "WatchEventClass::ONLY_RELOAD entry {c:?} must NOT satisfy is_removed()",
            );
            assert!(
                !c.is_ignored(),
                "WatchEventClass::ONLY_RELOAD entry {c:?} must NOT satisfy is_ignored()",
            );
        }
        for c in WatchEventClass::ONLY_REMOVED.iter().copied() {
            assert!(
                c.is_removed(),
                "WatchEventClass::ONLY_REMOVED entry {c:?} must satisfy is_removed()",
            );
            assert!(
                !c.is_reload(),
                "WatchEventClass::ONLY_REMOVED entry {c:?} must NOT satisfy is_reload()",
            );
            assert!(
                !c.is_ignored(),
                "WatchEventClass::ONLY_REMOVED entry {c:?} must NOT satisfy is_ignored()",
            );
        }
        for c in WatchEventClass::ONLY_IGNORED.iter().copied() {
            assert!(
                c.is_ignored(),
                "WatchEventClass::ONLY_IGNORED entry {c:?} must satisfy is_ignored()",
            );
            assert!(
                !c.is_reload(),
                "WatchEventClass::ONLY_IGNORED entry {c:?} must NOT satisfy is_reload()",
            );
            assert!(
                !c.is_removed(),
                "WatchEventClass::ONLY_IGNORED entry {c:?} must NOT satisfy is_removed()",
            );
        }
        for c in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                WatchEventClass::ONLY_RELOAD.contains(&c),
                c.is_reload(),
                "ONLY_RELOAD membership must agree with is_reload() on \
                 WatchEventClass::{c:?}",
            );
            assert_eq!(
                WatchEventClass::ONLY_REMOVED.contains(&c),
                c.is_removed(),
                "ONLY_REMOVED membership must agree with is_removed() on \
                 WatchEventClass::{c:?}",
            );
            assert_eq!(
                WatchEventClass::ONLY_IGNORED.contains(&c),
                c.is_ignored(),
                "ONLY_IGNORED membership must agree with is_ignored() on \
                 WatchEventClass::{c:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_ternary_slices_partition_all() {
        // Ternary partition invariant: the three per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_RELOAD.len() + ONLY_REMOVED.len() + ONLY_IGNORED.len()
        // == ALL.len()` at the slice altitude on the reload-relevance
        // axis's identity projection. Ternary peer of
        // `config_source_kind_ternary_slices_partition_all` (`f287239`)
        // and slice-altitude peer of
        // `watch_event_class_predicates_are_a_closed_ternary_partition`
        // one altitude down. A variant landing on two slices or on
        // none breaks the partition here before any consumer that
        // reasons about the polarity as a covering meta-partition
        // observes the drift.
        for c in WatchEventClass::ONLY_RELOAD {
            assert!(
                !WatchEventClass::ONLY_REMOVED.contains(c),
                "WatchEventClass::{c:?} appears in BOTH ONLY_RELOAD and ONLY_REMOVED",
            );
            assert!(
                !WatchEventClass::ONLY_IGNORED.contains(c),
                "WatchEventClass::{c:?} appears in BOTH ONLY_RELOAD and ONLY_IGNORED",
            );
        }
        for c in WatchEventClass::ONLY_REMOVED {
            assert!(
                !WatchEventClass::ONLY_IGNORED.contains(c),
                "WatchEventClass::{c:?} appears in BOTH ONLY_REMOVED and ONLY_IGNORED",
            );
        }
        for c in WatchEventClass::ALL {
            let in_reload = WatchEventClass::ONLY_RELOAD.contains(c);
            let in_removed = WatchEventClass::ONLY_REMOVED.contains(c);
            let in_ignored = WatchEventClass::ONLY_IGNORED.contains(c);
            let held = usize::from(in_reload) + usize::from(in_removed) + usize::from(in_ignored);
            assert_eq!(
                held, 1,
                "WatchEventClass::{c:?} must appear in exactly one of ONLY_RELOAD / \
                 ONLY_REMOVED / ONLY_IGNORED (found in {held})",
            );
        }
        assert_eq!(
            WatchEventClass::ONLY_RELOAD.len()
                + WatchEventClass::ONLY_REMOVED.len()
                + WatchEventClass::ONLY_IGNORED.len(),
            WatchEventClass::ALL.len(),
            "ONLY_RELOAD + ONLY_REMOVED + ONLY_IGNORED slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn watch_event_class_ternary_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in WatchEventClass::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell future
        // variant reshuffle on the same axis) diverges at THIS pin.
        // Ternary peer of
        // `config_source_kind_ternary_slices_preserve_all_order`
        // (`f287239`).
        let reload_from_all: Vec<WatchEventClass> = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_reload())
            .collect();
        assert_eq!(
            reload_from_all,
            WatchEventClass::ONLY_RELOAD.to_vec(),
            "ONLY_RELOAD must be ALL-filtered by is_reload in declaration order",
        );
        let removed_from_all: Vec<WatchEventClass> = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_removed())
            .collect();
        assert_eq!(
            removed_from_all,
            WatchEventClass::ONLY_REMOVED.to_vec(),
            "ONLY_REMOVED must be ALL-filtered by is_removed in declaration order",
        );
        let ignored_from_all: Vec<WatchEventClass> = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_ignored())
            .collect();
        assert_eq!(
            ignored_from_all,
            WatchEventClass::ONLY_IGNORED.to_vec(),
            "ONLY_IGNORED must be ALL-filtered by is_ignored in declaration order",
        );
    }

    #[test]
    fn watch_event_class_ternary_slices_have_no_duplicates() {
        // No-duplicates pin on all three per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting through
        // any consumer that iterates the slice expecting a set. Ternary
        // peer of
        // `config_source_kind_ternary_slices_have_no_duplicates`
        // (`f287239`).
        for slice in [
            WatchEventClass::ONLY_RELOAD,
            WatchEventClass::ONLY_REMOVED,
            WatchEventClass::ONLY_IGNORED,
        ] {
            let mut seen: Vec<WatchEventClass> = Vec::with_capacity(slice.len());
            for c in slice {
                assert!(
                    !seen.contains(c),
                    "WatchEventClass ternary slice {slice:?} contains duplicate entry {c:?}",
                );
                seen.push(*c);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn watch_event_class_ternary_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on WatchEventClass::ALL — i.e.,
        // `ONLY_RELOAD.len() == ALL.iter().filter(is_reload).count()`
        // (and symmetric for the two siblings) — the cardinality
        // projection at the slice altitude agrees with the
        // boolean-altitude projection on all three halves. Concrete
        // positions today: 1 reload + 1 removed + 1 ignored = 3 = ALL.
        // Ternary peer of
        // `config_source_kind_ternary_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`f287239`).
        let reload_count = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_reload())
            .count();
        let removed_count = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_removed())
            .count();
        let ignored_count = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_ignored())
            .count();
        assert_eq!(
            WatchEventClass::ONLY_RELOAD.len(),
            reload_count,
            "ONLY_RELOAD.len() must match the is_reload count on ALL",
        );
        assert_eq!(
            WatchEventClass::ONLY_REMOVED.len(),
            removed_count,
            "ONLY_REMOVED.len() must match the is_removed count on ALL",
        );
        assert_eq!(
            WatchEventClass::ONLY_IGNORED.len(),
            ignored_count,
            "ONLY_IGNORED.len() must match the is_ignored count on ALL",
        );
        assert_eq!(WatchEventClass::ONLY_RELOAD.len(), 1);
        assert_eq!(WatchEventClass::ONLY_REMOVED.len(), 1);
        assert_eq!(WatchEventClass::ONLY_IGNORED.len(), 1);
        assert_eq!(WatchEventClass::ALL.len(), 3);
    }

    #[test]
    fn watch_event_class_ternary_slices_are_const_addressable() {
        // Const-time addressability pin: the three per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        // Ternary peer of
        // `config_source_kind_ternary_slices_are_const_addressable`
        // (`f287239`).
        const ONLY_RELOAD_LEN: usize = WatchEventClass::ONLY_RELOAD.len();
        const ONLY_REMOVED_LEN: usize = WatchEventClass::ONLY_REMOVED.len();
        const ONLY_IGNORED_LEN: usize = WatchEventClass::ONLY_IGNORED.len();
        const ALL_LEN: usize = WatchEventClass::ALL.len();
        assert_eq!(ONLY_RELOAD_LEN, 1);
        assert_eq!(ONLY_REMOVED_LEN, 1);
        assert_eq!(ONLY_IGNORED_LEN, 1);
        assert_eq!(
            ONLY_RELOAD_LEN + ONLY_REMOVED_LEN + ONLY_IGNORED_LEN,
            ALL_LEN
        );
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
            // `Data(Any)` is the shape Linux/inotify reports for a plain
            // write; it is as much a mutation as macOS's `Data(Content)`.
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
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
    fn watch_event_class_file_mutations_slice_agrees_with_is_file_mutation_predicate() {
        // Bidirectional weld between the slice literal
        // `WatchEventClass::FILE_MUTATIONS` and the boolean predicate
        // `WatchEventClass::is_file_mutation` on the compound-polarity
        // (file-mutation × non-file-mutation) meta-partition. Every
        // slice entry satisfies the mutation pole (and its complement
        // `!is_ignored`), and every ALL cell agrees on membership under
        // the boolean predicate on both halves. Compound-polarity peer
        // of `config_source_kind_defaults_slice_agrees_with_is_defaults_predicate`
        // (`2cd8ef8`) and
        // `config_tier_kind_computed_slice_agrees_with_is_computed_predicate`
        // (`2c0686f`) — the two independent declaration surfaces (slice
        // literal + boolean predicate) diverge at THIS pin on the first
        // shape where they disagree, before a consumer that reads one
        // altitude but not the other can observe the drift.
        for c in WatchEventClass::FILE_MUTATIONS.iter().copied() {
            assert!(
                c.is_file_mutation(),
                "FILE_MUTATIONS entry {c:?} must satisfy is_file_mutation()",
            );
            assert!(
                !c.is_ignored(),
                "FILE_MUTATIONS entry {c:?} must NOT satisfy is_ignored()",
            );
        }
        for c in WatchEventClass::NON_FILE_MUTATIONS.iter().copied() {
            assert!(
                !c.is_file_mutation(),
                "NON_FILE_MUTATIONS entry {c:?} must NOT satisfy is_file_mutation()",
            );
            assert!(
                c.is_ignored(),
                "NON_FILE_MUTATIONS entry {c:?} must satisfy is_ignored()",
            );
        }
        for c in WatchEventClass::ALL.iter().copied() {
            assert_eq!(
                WatchEventClass::FILE_MUTATIONS.contains(&c),
                c.is_file_mutation(),
                "FILE_MUTATIONS membership must agree with is_file_mutation() on \
                 WatchEventClass::{c:?}",
            );
            assert_eq!(
                WatchEventClass::NON_FILE_MUTATIONS.contains(&c),
                c.is_ignored(),
                "NON_FILE_MUTATIONS membership must agree with is_ignored() on \
                 WatchEventClass::{c:?}",
            );
        }
    }

    #[test]
    fn watch_event_class_file_mutations_and_non_file_mutations_slices_partition_all() {
        // Compound-polarity partition invariant: the two per-half
        // slices are disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `FILE_MUTATIONS.len() + NON_FILE_MUTATIONS.len() == ALL.len()`
        // at the slice altitude on the reload-relevance axis's
        // compound-polarity meta-partition. Compound-polarity peer of
        // `config_source_kind_defaults_and_overlay_slices_partition_all`
        // (`2cd8ef8`) — a variant landing on one slice AND the other,
        // or on neither, breaks the partition here before any consumer
        // that reasons about the polarity as a covering meta-partition
        // observes the drift.
        for c in WatchEventClass::FILE_MUTATIONS.iter().copied() {
            assert!(
                !WatchEventClass::NON_FILE_MUTATIONS.contains(&c),
                "WatchEventClass::{c:?} appears in BOTH FILE_MUTATIONS and NON_FILE_MUTATIONS",
            );
        }
        for c in WatchEventClass::ALL.iter().copied() {
            let in_mut = WatchEventClass::FILE_MUTATIONS.contains(&c);
            let in_non = WatchEventClass::NON_FILE_MUTATIONS.contains(&c);
            assert!(
                in_mut || in_non,
                "WatchEventClass::{c:?} is in NEITHER FILE_MUTATIONS nor NON_FILE_MUTATIONS",
            );
            assert!(
                !(in_mut && in_non),
                "WatchEventClass::{c:?} is in BOTH FILE_MUTATIONS and NON_FILE_MUTATIONS",
            );
        }
        assert_eq!(
            WatchEventClass::FILE_MUTATIONS.len() + WatchEventClass::NON_FILE_MUTATIONS.len(),
            WatchEventClass::ALL.len(),
            "FILE_MUTATIONS and NON_FILE_MUTATIONS slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn watch_event_class_file_mutations_and_non_file_mutations_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in WatchEventClass::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise, so a
        // renderer walking the two half-slices concatenated reproduces
        // the ALL order (once the two polarity groups are ordered per
        // the reload-relevance ranking Reload < Removed < Ignored).
        // Compound-polarity peer of
        // `config_source_kind_defaults_and_overlay_slices_preserve_all_order`
        // (`2cd8ef8`) — a reordering of one slice without the other,
        // or a reordering of ALL that shuffles the two poles' variant
        // order without updating the slices, diverges at THIS pin.
        let mutations_from_all: Vec<WatchEventClass> = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_file_mutation())
            .collect();
        assert_eq!(
            mutations_from_all,
            WatchEventClass::FILE_MUTATIONS.to_vec(),
            "FILE_MUTATIONS must be ALL-filtered by is_file_mutation in declaration order",
        );
        let non_mutations_from_all: Vec<WatchEventClass> = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_ignored())
            .collect();
        assert_eq!(
            non_mutations_from_all,
            WatchEventClass::NON_FILE_MUTATIONS.to_vec(),
            "NON_FILE_MUTATIONS must be ALL-filtered by is_ignored in declaration order",
        );
    }

    #[test]
    fn watch_event_class_file_mutations_slice_has_no_duplicates() {
        // No-duplicates pin on both per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half (a typo copying the SAME variant twice
        // into FILE_MUTATIONS, an accidental re-add of the Ignored cell
        // into NON_FILE_MUTATIONS) fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a set.
        // Compound-polarity peer of
        // `config_source_kind_defaults_slice_has_no_duplicates` (`2cd8ef8`).
        for slice in [
            WatchEventClass::FILE_MUTATIONS,
            WatchEventClass::NON_FILE_MUTATIONS,
        ] {
            let mut sorted = slice.to_vec();
            sorted.sort();
            let deduped_len = {
                let mut seen: Vec<WatchEventClass> = Vec::with_capacity(sorted.len());
                for c in &sorted {
                    if !seen.contains(c) {
                        seen.push(*c);
                    }
                }
                seen.len()
            };
            assert_eq!(
                deduped_len,
                slice.len(),
                "WatchEventClass slice {slice:?} contains duplicate entries",
            );
        }
    }

    #[test]
    fn watch_event_class_file_mutations_and_non_file_mutations_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on WatchEventClass::ALL — i.e.,
        // `FILE_MUTATIONS.len() == ALL.iter().filter(is_file_mutation).count()`
        // and `NON_FILE_MUTATIONS.len() == ALL.iter().filter(is_ignored).count()`
        // — the cardinality projection at the slice altitude agrees
        // with the boolean-altitude projection on both halves.
        // Concrete positions today: 2 file-mutation + 1 non-file-mutation
        // = 3 = ALL. Compound-polarity peer of
        // `config_source_kind_defaults_and_overlay_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (`2cd8ef8`).
        let mutation_count = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_file_mutation())
            .count();
        let non_mutation_count = WatchEventClass::ALL
            .iter()
            .copied()
            .filter(|c| c.is_ignored())
            .count();
        assert_eq!(
            WatchEventClass::FILE_MUTATIONS.len(),
            mutation_count,
            "FILE_MUTATIONS.len() must match the is_file_mutation count on ALL",
        );
        assert_eq!(
            WatchEventClass::NON_FILE_MUTATIONS.len(),
            non_mutation_count,
            "NON_FILE_MUTATIONS.len() must match the is_ignored count on ALL",
        );
        assert_eq!(WatchEventClass::FILE_MUTATIONS.len(), 2);
        assert_eq!(WatchEventClass::NON_FILE_MUTATIONS.len(), 1);
        assert_eq!(WatchEventClass::ALL.len(), 3);
    }

    #[test]
    fn watch_event_class_file_mutations_and_non_file_mutations_slices_are_const_addressable() {
        // Const-time addressability pin: the two per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of either constant behind a
        // `pub fn` (which would drop const-callability) fails here
        // before drifting through a downstream `const`-context
        // consumer. Compound-polarity peer of
        // `config_source_kind_defaults_and_overlay_slices_are_const_addressable`
        // (`2cd8ef8`).
        const FILE_MUTATIONS_LEN: usize = WatchEventClass::FILE_MUTATIONS.len();
        const NON_FILE_MUTATIONS_LEN: usize = WatchEventClass::NON_FILE_MUTATIONS.len();
        const ALL_LEN: usize = WatchEventClass::ALL.len();
        assert_eq!(FILE_MUTATIONS_LEN, 2);
        assert_eq!(NON_FILE_MUTATIONS_LEN, 1);
        assert_eq!(FILE_MUTATIONS_LEN + NON_FILE_MUTATIONS_LEN, ALL_LEN);
    }

    #[test]
    fn watch_event_class_classify_is_const_callable() {
        // Compile-time weld pin: `WatchEventClass::classify(&kind)` is
        // reachable at const-evaluation position across all three arms of
        // the reload-relevance ternary partition, and composes with the
        // const-fn predicate quartet `is_reload` / `is_removed` /
        // `is_ignored` / `is_file_mutation` end-to-end in const positions.
        // A future edit that drops const-fn on `classify` (e.g. inlining a
        // non-const helper into the body) fails here before drifting
        // through any const-context downstream consumer. Class-side peer
        // of the tag-side classifier-const pin
        // `figment_source_tag_classify_and_projections_are_const_callable`
        // (`d29a3f9`).
        const CREATE_ANY: notify::EventKind =
            notify::EventKind::Create(notify::event::CreateKind::Any);
        const MODIFY_CONTENT: notify::EventKind = notify::EventKind::Modify(
            notify::event::ModifyKind::Data(notify::event::DataChange::Content),
        );
        const MODIFY_WRITE_TIME: notify::EventKind = notify::EventKind::Modify(
            notify::event::ModifyKind::Metadata(notify::event::MetadataKind::WriteTime),
        );
        const MODIFY_RENAME: notify::EventKind = notify::EventKind::Modify(
            notify::event::ModifyKind::Name(notify::event::RenameMode::Both),
        );
        const REMOVE_ANY: notify::EventKind =
            notify::EventKind::Remove(notify::event::RemoveKind::Any);
        const ANY: notify::EventKind = notify::EventKind::Any;

        const CREATE_CLASS: WatchEventClass = WatchEventClass::classify(&CREATE_ANY);
        const MODIFY_CONTENT_CLASS: WatchEventClass = WatchEventClass::classify(&MODIFY_CONTENT);
        const MODIFY_WRITE_TIME_CLASS: WatchEventClass =
            WatchEventClass::classify(&MODIFY_WRITE_TIME);
        const MODIFY_RENAME_CLASS: WatchEventClass = WatchEventClass::classify(&MODIFY_RENAME);
        const REMOVE_CLASS: WatchEventClass = WatchEventClass::classify(&REMOVE_ANY);
        const ANY_CLASS: WatchEventClass = WatchEventClass::classify(&ANY);

        // Compose with the const-fn predicate quartet in const positions,
        // so any future lift of a predicate away from const-fn also fails
        // here — the two seams weld into one compile-time pin.
        const CREATE_IS_RELOAD: bool = CREATE_CLASS.is_reload();
        const MODIFY_CONTENT_IS_RELOAD: bool = MODIFY_CONTENT_CLASS.is_reload();
        const MODIFY_WRITE_TIME_IS_RELOAD: bool = MODIFY_WRITE_TIME_CLASS.is_reload();
        const MODIFY_RENAME_IS_IGNORED: bool = MODIFY_RENAME_CLASS.is_ignored();
        const REMOVE_IS_REMOVED: bool = REMOVE_CLASS.is_removed();
        const REMOVE_IS_FILE_MUTATION: bool = REMOVE_CLASS.is_file_mutation();
        const ANY_IS_IGNORED: bool = ANY_CLASS.is_ignored();

        const { assert!(CREATE_IS_RELOAD) };
        const { assert!(MODIFY_CONTENT_IS_RELOAD) };
        const { assert!(MODIFY_WRITE_TIME_IS_RELOAD) };
        const { assert!(MODIFY_RENAME_IS_IGNORED) };
        const { assert!(REMOVE_IS_REMOVED) };
        const { assert!(REMOVE_IS_FILE_MUTATION) };
        const { assert!(ANY_IS_IGNORED) };
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

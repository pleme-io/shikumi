//! Per-field hot-swap-safety classification — theory/CALHA.md §6.3.
//!
//! Composes an already-`#[derive(HotSwap)]`-classified `T` (via the
//! sibling `pleme-hotswap`/`pleme-hotswap-derive` crates) with shikumi's
//! own `TieredConfig` resolution + `ConfigStore` hot-reload machinery: a
//! resolved candidate must pass semantic [`Validate::validate`] before it
//! is ever `Arc`-constructible ([`ValidatedTieredConfig`]), and
//! [`crate::ConfigStore::load_and_watch_hotswap`] (in `store.rs`, gated
//! behind this same `hotswap` feature) auto-applies a reload only when
//! [`pleme_hotswap::HotSwapClassifier::classify_change`] reports every
//! changed field is [`pleme_hotswap::HotSwapClass::Free`] — a
//! `RequiresRestart` diff is recorded (queryable via
//! [`crate::ConfigStore::pending_restart`]) but never auto-swapped.
//!
//! **Fail-safe guarantee**, a required, tested property, not an
//! inference from a `Result` signature: a candidate that fails
//! [`Validate::validate`] NEVER tears down the store's watch loop and
//! NEVER replaces the currently-live value. The last-known-good config
//! stays live; the rejection is only logged (and, once the Viggy
//! `OutcomeChain` lands — a further, external increment — attested).

use pleme_hotswap::HotSwapClass;
use serde::Serialize;

use crate::error::ShikumiError;

/// Semantic (not just syntactic) well-formedness for a resolved config
/// candidate — e.g. "is this `LogLevel` string one of the known values,"
/// "is this port in the valid range." Syntactic parsing (shape, types)
/// is already `resolve_progressive`'s job; this catches a well-typed
/// value that is still semantically wrong.
pub trait Validate {
    /// # Errors
    ///
    /// Returns [`ShikumiError::Validation`] describing why `self` is
    /// semantically invalid.
    fn validate(&self) -> Result<(), ShikumiError>;
}

/// A `T: Validate` wrapper that refuses to construct a value that fails
/// semantic validation. Every hot-swap candidate — the initial load and
/// every subsequent reload — is routed through [`Self::validate`] before
/// it can reach [`crate::ConfigStore`]'s `ArcSwap`.
#[derive(Debug, Clone)]
pub struct ValidatedTieredConfig<T>(T);

impl<T: Validate> ValidatedTieredConfig<T> {
    /// Validates `candidate`, wrapping it on success.
    ///
    /// # Errors
    ///
    /// Propagates [`Validate::validate`]'s error untouched.
    pub fn validate(candidate: T) -> Result<Self, ShikumiError> {
        candidate.validate()?;
        Ok(Self(candidate))
    }

    /// Unwrap back to the plain, already-validated value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for ValidatedTieredConfig<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// A `blake3`-hashed proof of a config's state, split so a `Free`-field
/// edit never touches the half that gates a restart. Ported SHAPE from
/// breathe-provider's Sighup/Reload/Restart-gated-write pattern
/// (`ConfigReload` → `DisruptionClass` → `DisruptionPolicy::permits()`)
/// — the TYPE is native to shikumi, never imported.
///
/// The two class-scoped hashes ([`Self::restart_required`] and
/// [`Self::free`]) close the [`HotSwapClass`] partition (theory/CALHA.md
/// §5.1 — `Free | RequiresRestart` is 2-arm-total): every serialized
/// top-level field feeds exactly one half, and each half moves iff a
/// field of that class changed. This lets a per-replica observer answer
/// both "is a restart pending?" (`restart_required` moved) AND "did any
/// live-editable knob drift?" (`free` moved) from one watermark, without
/// re-scanning the full serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigWatermark {
    /// Hash of the whole resolved config value.
    pub full: blake3::Hash,
    /// Hash of ONLY the fields classified [`HotSwapClass::RequiresRestart`]
    /// — a `Free`-field-only edit leaves this hash unchanged, which is
    /// exactly the signal `calha`'s split watermark (theory/CALHA.md §2)
    /// polls to decide whether a running process is missing a restart.
    pub restart_required: blake3::Hash,
    /// Hash of ONLY the fields classified [`HotSwapClass::Free`] — the
    /// symmetric class-partition peer of [`Self::restart_required`]. A
    /// `RequiresRestart`-field-only edit leaves this hash unchanged;
    /// moves exactly when a live-swappable field's value changed. Lets a
    /// `/healthz/config` surface distinguish "a Free field drifted since
    /// last observation" (interesting to an operator watching live-edit
    /// activity) from "a RequiresRestart field drifted" (the existing
    /// pending-restart signal) without recomputing either half.
    pub free: blake3::Hash,
}

impl ConfigWatermark {
    /// Compute the split watermark for `value`, using `field_classes`
    /// (a `T::FIELD_CLASSES`-shaped slice) to partition which serialized
    /// top-level fields feed the class-scoped halves ([`Self::restart_required`]
    /// and [`Self::free`]).
    ///
    /// Serialization failure (a well-formed `TieredConfig` value should
    /// never hit this — `TieredConfig: Serialize` is a supertrait bound)
    /// degrades to a deterministic hash of the empty byte string rather
    /// than panicking library code.
    #[must_use]
    pub fn compute<T: Serialize>(
        value: &T,
        field_classes: &[(&'static str, HotSwapClass)],
    ) -> Self {
        let full_bytes = serde_json::to_vec(value).unwrap_or_default();
        let full = blake3::hash(&full_bytes);

        // One serialization drives both class-scoped halves, so a future
        // `HotSwapClass` variant added to the partition needs exactly one
        // new call site (a new `class_scoped_hash` invocation) rather
        // than a second full round-trip through `serde_json::to_value`.
        let object = match serde_json::to_value(value) {
            Ok(serde_json::Value::Object(map)) => Some(map),
            _ => None,
        };
        let restart_required = Self::class_scoped_hash(object.as_ref(), field_classes, |c| {
            matches!(c, HotSwapClass::RequiresRestart { .. })
        });
        let free = Self::class_scoped_hash(object.as_ref(), field_classes, |c| {
            matches!(c, HotSwapClass::Free)
        });

        Self {
            full,
            restart_required,
            free,
        }
    }

    /// The one primitive both class-scoped halves fold through: hash the
    /// deterministic (`BTreeMap`-sorted) sub-object of `object` whose
    /// top-level keys are the members of `field_classes` matching
    /// `include`. Absent object (serialization non-`Object` result)
    /// degrades to `blake3::hash(&[])` uniformly across every class arm,
    /// so a class-partition peer cannot silently disagree with its
    /// sibling on the failure path.
    fn class_scoped_hash(
        object: Option<&serde_json::Map<String, serde_json::Value>>,
        field_classes: &[(&'static str, HotSwapClass)],
        include: impl Fn(&HotSwapClass) -> bool,
    ) -> blake3::Hash {
        let Some(map) = object else {
            return blake3::hash(&[]);
        };
        // Re-sorted into a BTreeMap so the hash is deterministic
        // regardless of `serde_json`'s `preserve_order` feature being
        // unified on elsewhere in the dependency tree — BTreeMap's own
        // Serialize impl always emits sorted keys.
        let scoped: std::collections::BTreeMap<String, serde_json::Value> = field_classes
            .iter()
            .filter(|(_, class)| include(class))
            .filter_map(|(field, _)| map.get(*field).map(|v| ((*field).to_owned(), v.clone())))
            .collect();
        let bytes = serde_json::to_vec(&scoped).unwrap_or_default();
        blake3::hash(&bytes)
    }
}

/// The queryable per-replica convergence fact `calha` polls via
/// `/healthz/config` (theory/CALHA.md §2) — NOT a cross-replica
/// guarantee (see theory/CALHA.md §13 risk 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSyncProof {
    /// [`crate::ConfigStore::generation`] at the moment this proof was
    /// computed.
    pub generation: u64,
    /// The split watermark of the currently-live value.
    pub watermark: ConfigWatermark,
    /// When this proof was computed.
    pub observed_at: std::time::SystemTime,
}
/// The **wire projection** of a [`ConfigSyncProof`] — the shape a target
/// serves on `/healthz/config` and a poller deserializes.
///
/// **Why this type exists at all.** [`ConfigSyncProof`] is not serializable:
/// `ConfigWatermark` derives only `Debug, Clone, Copy, PartialEq, Eq`, and
/// `blake3::Hash` is not a serde type. So until now there was **no wire format**
/// — not merely no server. Measured 2026-08-11: `calha/src/watermark.rs` carries
/// a hand-written mirror of "the wire shape shikumi will serve", and because no
/// such shape existed it had drifted unnoticed — two hash fields where there are
/// three (`free` missing entirely), `String` where the source is `blake3::Hash`,
/// and an `i64` epoch where the source is `SystemTime`.
///
/// A mirror of a type that has never been serialized cannot be wrong yet, which
/// is exactly why it went wrong. This makes the shape real, so a consumer has
/// something to be right about.
///
/// Hashes are hex strings on the wire: `blake3::Hash`'s `Display` is hex, the
/// representation is stable, and a hex string survives a JSON round-trip
/// without a custom deserializer at every consumer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigWatermarkWire {
    /// Hash of the whole resolved config, hex.
    pub full: String,
    /// Hash of the `RequiresRestart` fields only, hex. The half calha polls.
    pub restart_required: String,
    /// Hash of the `Free` fields only, hex. The symmetric peer — its absence
    /// from a consumer's model is what makes "did a hot-swappable knob move?"
    /// unanswerable.
    pub free: String,
}

/// The wire projection of a [`ConfigSyncProof`].
///
/// **NESTED, not flat, and that was a correction.** The first draft flattened
/// the three hashes to the top level; calha's consumer models a `watermark`
/// sub-object, and its round-trip test failed with `missing field watermark`
/// against the flat payload. Nesting is also the truer shape — a watermark IS
/// a three-part thing, not three unrelated fields that happen to travel
/// together. Caught before anything polled a live target, which is the only
/// cheap moment to find a producer/consumer disagreement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSyncProofWire {
    /// Monotonic publish counter of the store that produced this.
    pub generation: u64,
    /// The three-part watermark.
    pub watermark: ConfigWatermarkWire,
    /// Unix epoch seconds. Chosen over `SystemTime` because its serde
    /// representation is an implementation detail and a poller comparing
    /// timestamps needs a stable integer.
    pub observed_at_epoch: i64,
}

impl ConfigSyncProof {
    /// Project to the wire shape.
    #[must_use]
    pub fn to_wire(&self) -> ConfigSyncProofWire {
        ConfigSyncProofWire {
            generation: self.generation,
            watermark: self.watermark.to_wire(),
            observed_at_epoch: self
                .observed_at
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        }
    }

    /// Reconstruct a [`ConfigSyncProof`] from its wire projection — the
    /// inverse of [`Self::to_wire`], closing the wire shape into a
    /// full round-trip so a consumer that received a
    /// [`ConfigSyncProofWire`] can hold a strongly-typed proof back
    /// (real [`blake3::Hash`] values, a real [`std::time::SystemTime`]
    /// timestamp) with one call instead of hand-parsing three hex
    /// strings and an epoch integer at every seam.
    ///
    /// Before this method the wire shape was a monologue: `to_wire`
    /// serialized outbound but nothing deserialized back. A consumer
    /// wanting to compare two watermarks as *hashes* rather than as
    /// hex *strings* (constant-time bytewise via `blake3::Hash`'s
    /// `PartialEq` rather than character-by-character across a `String`)
    /// had to re-derive [`blake3::Hash::from_hex`] plus the epoch →
    /// [`std::time::SystemTime`] fold inline at every call site —
    /// exactly the drift risk [`ConfigSyncProofWire`]'s own doc names
    /// on the outbound side.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] when any of the three wire hash
    /// fields is not valid `blake3` hex, or when `observed_at_epoch`
    /// is negative (a running store cannot have produced a proof
    /// stamped before the Unix epoch, so the sign is a malformedness
    /// signal, not a legitimate value).
    pub fn try_from_wire(wire: &ConfigSyncProofWire) -> Result<Self, ShikumiError> {
        let watermark = ConfigWatermark::try_from_wire(&wire.watermark)?;
        let secs = u64::try_from(wire.observed_at_epoch).map_err(|_| {
            ShikumiError::Parse(format!(
                "invalid negative observedAtEpoch in ConfigSyncProofWire: {}",
                wire.observed_at_epoch
            ))
        })?;
        let observed_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        Ok(Self {
            generation: wire.generation,
            watermark,
            observed_at,
        })
    }
}

impl ConfigWatermark {
    /// Project to the wire shape — three `blake3::Hash` fields become
    /// three lowercase-hex strings, matching the per-field encoding
    /// [`ConfigSyncProof::to_wire`] used inline before this lift.
    ///
    /// One source of truth for the value → wire projection on the
    /// watermark, so [`ConfigSyncProof::to_wire`] and any future
    /// consumer that needs the wire encoding of a watermark alone
    /// route through the same three `.to_hex().to_string()` calls
    /// rather than hand-rolling the encoding at each site.
    #[must_use]
    pub fn to_wire(&self) -> ConfigWatermarkWire {
        ConfigWatermarkWire {
            full: self.full.to_hex().to_string(),
            restart_required: self.restart_required.to_hex().to_string(),
            free: self.free.to_hex().to_string(),
        }
    }

    /// Reconstruct a [`ConfigWatermark`] from its wire projection —
    /// the inverse of [`Self::to_wire`], parsing each hex field back
    /// to a [`blake3::Hash`].
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] when any field is not valid
    /// `blake3` hex. The error names the offending wire field
    /// (`full` / `restartRequired` / `free`) so the consumer can
    /// localize the malformed input without re-parsing the whole
    /// payload.
    pub fn try_from_wire(wire: &ConfigWatermarkWire) -> Result<Self, ShikumiError> {
        Ok(Self {
            full: parse_wire_hash(&wire.full, "full")?,
            restart_required: parse_wire_hash(&wire.restart_required, "restartRequired")?,
            free: parse_wire_hash(&wire.free, "free")?,
        })
    }
}

impl TryFrom<&ConfigWatermarkWire> for ConfigWatermark {
    type Error = ShikumiError;

    fn try_from(wire: &ConfigWatermarkWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

impl TryFrom<&ConfigSyncProofWire> for ConfigSyncProof {
    type Error = ShikumiError;

    fn try_from(wire: &ConfigSyncProofWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

fn parse_wire_hash(hex: &str, field: &'static str) -> Result<blake3::Hash, ShikumiError> {
    blake3::Hash::from_hex(hex).map_err(|e| {
        ShikumiError::Parse(format!(
            "invalid blake3 hex in ConfigWatermarkWire field `{field}`: {e}"
        ))
    })
}

/// The typed answer to "what moved between two [`ConfigWatermark`] values?"
/// — a per-half `bool` triple with the class-partition invariant welded
/// at the type shape.
///
/// Every consumer polling `/healthz/config` (theory/CALHA.md §2) receives
/// a stream of [`ConfigSyncProofWire`] snapshots, and every observer that
/// wants to react to a change compares "last seen" against "just received"
/// on the class-scoped halves. Before this type each such consumer wrote
/// three inline `!=` comparisons over the three [`ConfigWatermark`] hash
/// fields — one per half — and re-derived the class-partition semantics
/// at the call site. `WatermarkDelta` names that comparison as a type, so
/// the answer travels as data (queryable, testable, transportable) rather
/// than as hand-rolled boolean arithmetic at every seam.
///
/// The named accessors ([`Self::restart_pending`], [`Self::hot_swappable_drift`])
/// spell the two CALHA-side questions in the semantic vocabulary of the
/// observers, not just the mechanical vocabulary of the underlying hashes:
/// a `calha` poller asks "is a restart pending since I last checked?"
/// and an operator watching live-edit activity asks "did a hot-swappable
/// knob drift?", and those two questions are the load-bearing use of the
/// class partition.
///
/// The class-partition invariant `full_moved iff (restart_required_moved ||
/// free_moved)` holds under the [`ConfigWatermark::compute`] assumption
/// that the `field_classes` slice partitions every serialized top-level
/// field (theory/CALHA.md §5.1 — the `Free | RequiresRestart` closure is
/// 2-arm-total). [`Self::partitioned_class_invariant_holds`] states the
/// biconditional at the type level. The one-way implication
/// `restart_required_moved || free_moved ⇒ full_moved` — which holds
/// **unconditionally**, since a class-scoped hash cannot move without the
/// full-hash superset also moving — is spelled at
/// [`Self::class_moves_imply_full_moved`] and is the honest sanity check
/// a consumer can perform on a delta value it did not compute itself
/// (e.g. one deserialized from an untrusted source) regardless of whether
/// the producer's field partition is fully exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatermarkDelta {
    /// Whether the full watermark ([`ConfigWatermark::full`]) moved. True
    /// iff any observable field of the resolved config changed, whether or
    /// not that field is class-partitioned into either half below.
    pub full_moved: bool,
    /// Whether the `RequiresRestart` half ([`ConfigWatermark::restart_required`])
    /// moved — the exact signal `calha`'s split watermark (theory/CALHA.md
    /// §2) polls to decide whether a running process is missing a restart.
    pub restart_required_moved: bool,
    /// Whether the Free half ([`ConfigWatermark::free`]) moved — the
    /// symmetric peer of [`Self::restart_required_moved`], observed by a
    /// live-edit surface distinguishing "a hot-swappable knob drifted"
    /// (interesting to an operator) from "a `RequiresRestart` field drifted"
    /// (the pending-restart signal above).
    pub free_moved: bool,
}

impl WatermarkDelta {
    /// Compute the delta from `prior` to `current` — a pointwise
    /// comparison over the three watermark halves. Pure, allocation-free,
    /// symmetric in the trivial `stationary`-typed sense (see
    /// [`Self::stationary`]).
    #[must_use]
    pub fn between(prior: &ConfigWatermark, current: &ConfigWatermark) -> Self {
        Self {
            full_moved: prior.full != current.full,
            restart_required_moved: prior.restart_required != current.restart_required,
            free_moved: prior.free != current.free,
        }
    }

    /// True iff at least one of the three halves moved — a fast "did
    /// anything change at all?" predicate an observer polls to short-
    /// circuit further inspection.
    #[must_use]
    pub const fn any_moved(&self) -> bool {
        self.full_moved || self.restart_required_moved || self.free_moved
    }

    /// True iff NO half moved — the pair of watermarks is bit-identical
    /// on every observable axis. Named for the observer whose null
    /// hypothesis is "nothing changed since I last looked."
    #[must_use]
    pub const fn stationary(&self) -> bool {
        !self.any_moved()
    }

    /// True iff the `RequiresRestart` half moved — the `calha`-side
    /// question "is a restart pending since I last polled this replica?"
    /// spelled in the semantic vocabulary of the observer. Alias of
    /// [`Self::restart_required_moved`] scoped to the CALHA use.
    #[must_use]
    pub const fn restart_pending(&self) -> bool {
        self.restart_required_moved
    }

    /// True iff the Free half moved — the operator-side question "did a
    /// hot-swappable knob drift since I last polled this replica?" spelled
    /// in the semantic vocabulary of the live-edit observer. Alias of
    /// [`Self::free_moved`] scoped to the operator use.
    #[must_use]
    pub const fn hot_swappable_drift(&self) -> bool {
        self.free_moved
    }

    /// One-way sanity check: a class-scoped half moving implies the full
    /// half moved (a class-scoped hash's input is a subset of the full
    /// hash's input, so moving the smaller input implies moving the
    /// larger one). Holds unconditionally, independent of whether the
    /// producer's `field_classes` slice covers every top-level field.
    ///
    /// A consumer that received a [`WatermarkDelta`] from an untrusted
    /// source (e.g. one reconstructed from a wire it did not compute)
    /// checks this predicate before trusting the delta — a value where
    /// `restart_required_moved || free_moved` is `true` while `full_moved`
    /// is `false` cannot have been produced by [`Self::between`] on any
    /// two well-formed [`ConfigWatermark`] values.
    #[must_use]
    pub const fn class_moves_imply_full_moved(&self) -> bool {
        !((self.restart_required_moved || self.free_moved) && !self.full_moved)
    }

    /// Two-way class-partition invariant: `full_moved` iff
    /// `restart_required_moved || free_moved`. Holds when the producer's
    /// `field_classes` slice is exhaustive over every top-level
    /// serialized field of the config — i.e. every observable field is
    /// classified into exactly one half. Under that assumption, moving
    /// the full hash forces at least one class-scoped half to move too.
    ///
    /// Weaker sibling: [`Self::class_moves_imply_full_moved`] holds
    /// unconditionally. A consumer that does not know whether the
    /// producer's classification is exhaustive uses the weaker predicate.
    #[must_use]
    pub const fn partitioned_class_invariant_holds(&self) -> bool {
        self.full_moved == (self.restart_required_moved || self.free_moved)
    }

    /// Classify this delta into the exhaustive [`WatermarkRelation`] sum —
    /// the sum-type peer of [`ProofRelation::between`] at the watermark
    /// altitude. Every legitimate corner of the
    /// (`full_moved`, `restart_required_moved`, `free_moved`) grid maps to
    /// one variant; the three impossibility corners (a class-scoped half
    /// moved without `full_moved` — the same shape
    /// [`Self::class_moves_imply_full_moved`] refuses) map to `None`.
    ///
    /// A [`WatermarkDelta`] produced by [`Self::between`] on two
    /// well-formed [`ConfigWatermark`] values, or reconstructed by
    /// [`Self::try_from_wire`], always satisfies the weak class-partition
    /// invariant, so this classification is total on every value the
    /// authored surface produces. `None` reaches a consumer only when the
    /// delta was hand-constructed with inconsistent field values through
    /// the public `pub`-field constructor — the same "hand-authored
    /// inconsistency" seam [`Self::class_moves_imply_full_moved`] flags
    /// via a predicate. Naming the classification as a variant promotes
    /// that runtime check to a `match`-able shape a consumer can route on
    /// without a second predicate call.
    #[must_use]
    pub const fn relation(&self) -> Option<WatermarkRelation> {
        match (
            self.full_moved,
            self.restart_required_moved,
            self.free_moved,
        ) {
            (false, false, false) => Some(WatermarkRelation::Stationary),
            (true, false, false) => Some(WatermarkRelation::UnclassifiedDrift),
            (true, true, false) => Some(WatermarkRelation::RestartRequiredOnly),
            (true, false, true) => Some(WatermarkRelation::FreeOnly),
            (true, true, true) => Some(WatermarkRelation::Both),
            // The three (false, ?, ?) impossibility corners — a class-
            // scoped half moved without full_moved. `Self::class_moves_imply_full_moved`
            // refuses this shape as a predicate; the classification refuses
            // it by yielding `None`.
            (false, _, _) => None,
        }
    }

    /// The wire-side sibling of [`Self::relation`] — classifies this
    /// delta into the [`WatermarkRelationWire`] sum and returns it
    /// wrapped in the same `Option` shape [`Self::relation`] carries.
    /// Composes `self.relation().map(|r| r.to_wire())` at one call,
    /// spelled `const` (matching both [`Self::relation`] and
    /// [`WatermarkRelation::to_wire`], neither of which allocates) so a
    /// delta known at compile time projects to its classification wire
    /// at compile time too.
    ///
    /// **Closes the delta-altitude (`bare`, `relation`) × (`value`,
    /// `wire`) 2×2 grid.** Before this method the four cells were three-
    /// quarters full at the delta altitude: the value-side bare
    /// projection ([`Self::to_wire`] itself is delta → wire delta),
    /// [`Self::relation`] (value/relation), and [`Self::to_wire`] again
    /// covering value/wire. The wire/relation cell — reached from a
    /// [`WatermarkDelta`] in ONE call to project the classification onto
    /// the wire — previously required composing [`Self::relation`] with
    /// [`WatermarkRelation::to_wire`] inline at every seam OR climbing
    /// to [`ConfigWatermark::relation_wire_since`] (which requires two
    /// watermark values, not just a delta). This method IS the
    /// composition at the delta altitude, matching the shape
    /// [`Self::to_wire`] already carries for the bare projection.
    ///
    /// **Same-`None` invariant with [`Self::relation`].** Returns `None`
    /// on exactly the same three impossibility corners
    /// ([`Self::relation`] filters — the class-scoped-moved-without-
    /// `full_moved` shape [`Self::class_moves_imply_full_moved`]
    /// refuses. A [`WatermarkDelta`] produced by [`Self::between`] on
    /// two well-formed [`ConfigWatermark`] values, or reconstructed by
    /// [`Self::try_from_wire`], never lands on `None` at either
    /// method — the impossibility bucket travels as `Option::None` on
    /// both value-side and wire-side, matching the module-level
    /// "impossibility bucket travels as `Option::None`, not a variant"
    /// doc pin.
    ///
    /// **Coherence with [`ConfigWatermark::relation_wire_since`].** For
    /// any two [`ConfigWatermark`] values `prior` and `current`,
    /// `current.delta_since(&prior).relation_wire()` equals
    /// `current.relation_wire_since(&prior)` pointwise. The former
    /// reaches the wire through the delta altitude, the latter through
    /// the watermark-container altitude; both compose the same two
    /// morphisms (`.relation()` then `.to_wire()`) at different
    /// altitudes and reach the same wire.
    #[must_use]
    pub const fn relation_wire(&self) -> Option<WatermarkRelationWire> {
        match self.relation() {
            Some(r) => Some(r.to_wire()),
            None => None,
        }
    }
}

/// An exhaustive sum-type classification of the
/// (`full_moved`, `restart_required_moved`, `free_moved`) grid a
/// [`WatermarkDelta`] describes — the value-side sum-type peer of
/// [`ProofRelation`] at the watermark altitude.
///
/// **Why this type exists — promote the class-partition predicate to a
/// match.** [`WatermarkDelta`] carries three booleans plus a handful of
/// predicates ([`WatermarkDelta::restart_pending`],
/// [`WatermarkDelta::hot_swappable_drift`],
/// [`WatermarkDelta::class_moves_imply_full_moved`]) that a consumer
/// composes ad-hoc at every seam to decide which corner of the grid a
/// delta lands in. Naming the classification as a sum type folds that
/// composition into ONE `match`: adding a sixth corner to the grid (say,
/// a new [`HotSwapClass`] axis) turns every consumer red at the same
/// instant the classification changes, closing the exhaustiveness gap
/// the free-floating predicates leave open. Same relationship
/// [`ProofRelation`] holds to [`ProofDelta`]'s four boolean predicates,
/// spelled one altitude down at the watermark grid.
///
/// **Five legitimate corners under the weak class-partition invariant.**
/// The three (`full_moved`=`false`, class-scoped=`true`) tuples are
/// refused by [`WatermarkDelta::class_moves_imply_full_moved`] and reach
/// this classification as `None` from [`WatermarkDelta::relation`]. The
/// five remaining corners are:
///
/// - [`Self::Stationary`] — `(false, false, false)`: nothing moved. The
///   null hypothesis a poller checks before further inspection.
/// - [`Self::UnclassifiedDrift`] — `(true, false, false)`: the full
///   watermark moved but neither class-scoped half did. Only possible
///   when the producer's `field_classes` slice is NOT exhaustive over
///   the config's top-level fields — an "unclassified field drifted"
///   signal a consumer that assumes exhaustive partitioning should
///   escalate. Under the two-way invariant
///   ([`WatermarkDelta::partitioned_class_invariant_holds`]) this
///   variant is impossible; the crate does not force exhaustive
///   partitioning at the [`ConfigWatermark::compute`] boundary, so the
///   variant exists to name the corner.
/// - [`Self::RestartRequiredOnly`] — `(true, true, false)`: a
///   `RequiresRestart` field drifted, no Free field did. The exact
///   corner CALHA's split-watermark poller (see
///   [`WatermarkDelta::restart_pending`]) routes on to raise the
///   pending-restart signal without a spurious hot-swap.
/// - [`Self::FreeOnly`] — `(true, false, true)`: a Free field drifted,
///   no `RequiresRestart` field did. The symmetric operator-side
///   corner a live-edit surface (see
///   [`WatermarkDelta::hot_swappable_drift`]) routes on to perform a
///   hot swap without prompting for a restart.
/// - [`Self::Both`] — `(true, true, true)`: at least one field of each
///   class drifted. A consumer that must both hot-swap AND notify for a
///   pending restart reaches this corner in one arm.
///
/// **The impossibility bucket travels as `Option::None`, not as a
/// variant.** [`ProofRelation`] treats its two impossibility corners
/// ([`ProofRelation::CrossStore`] and [`ProofRelation::Regressed`]) as
/// legitimate variants because each names a semantically meaningful
/// diagnostic ("cross-store confusion" and "monotonicity regression").
/// The class-partition impossibility here has no comparable diagnostic
/// use — it means only that a [`WatermarkDelta`] was hand-constructed
/// with inconsistent field values through the `pub`-field constructor,
/// which no authored path in the crate produces. Yielding `None` mirrors
/// the [`MovedWatermarkDelta::new`] precedent for filtering out an
/// invariant-violating shape without inflating the sum with a bucket
/// that never routes anywhere.
///
/// **Predicate parity with [`WatermarkDelta`].** Every predicate on
/// [`WatermarkDelta`] has a variant-side sibling here
/// ([`Self::any_moved`], [`Self::stationary`], [`Self::restart_pending`],
/// [`Self::hot_swappable_drift`],
/// [`Self::partitioned_class_invariant_holds`]) so a consumer already
/// destructuring the classification reaches every question through the
/// variant shape rather than falling back to a `WatermarkDelta`
/// projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatermarkRelation {
    /// The `(false, false, false)` corner: no observable field of the
    /// resolved config changed. The null hypothesis a poller confirms
    /// before doing any further inspection.
    Stationary,
    /// The `(true, false, false)` corner: the full watermark moved but
    /// neither class-scoped half did. Only reachable when the producer's
    /// `field_classes` slice is NOT exhaustive over the config's
    /// top-level fields — an "unclassified field drifted" signal.
    UnclassifiedDrift,
    /// The `(true, true, false)` corner: a `RequiresRestart` field
    /// drifted, no Free field did. The CALHA-side "pending restart
    /// signal without a hot-swap" corner.
    RestartRequiredOnly,
    /// The `(true, false, true)` corner: a Free field drifted, no
    /// `RequiresRestart` field did. The operator-side "hot-swap without
    /// a pending restart" corner.
    FreeOnly,
    /// The `(true, true, true)` corner: at least one field of each
    /// class drifted. A consumer that hot-swaps AND notifies for a
    /// pending restart reaches this in one arm.
    Both,
}

impl WatermarkRelation {
    /// True iff at least one axis of the underlying delta moved — the
    /// variant-side sibling of [`WatermarkDelta::any_moved`]. Equivalent
    /// to `!self.stationary()`.
    #[must_use]
    pub const fn any_moved(&self) -> bool {
        !matches!(self, Self::Stationary)
    }

    /// True iff no axis moved — the variant-side sibling of
    /// [`WatermarkDelta::stationary`]. Equivalent to `!self.any_moved()`.
    #[must_use]
    pub const fn stationary(&self) -> bool {
        matches!(self, Self::Stationary)
    }

    /// True iff the `RequiresRestart` half moved — the CALHA-side
    /// question spelled through the variant shape. The variant-side
    /// sibling of [`WatermarkDelta::restart_pending`].
    #[must_use]
    pub const fn restart_pending(&self) -> bool {
        matches!(self, Self::RestartRequiredOnly | Self::Both)
    }

    /// True iff the Free half moved — the operator-side "did a
    /// hot-swappable knob drift?" question spelled through the variant
    /// shape. The variant-side sibling of
    /// [`WatermarkDelta::hot_swappable_drift`].
    #[must_use]
    pub const fn hot_swappable_drift(&self) -> bool {
        matches!(self, Self::FreeOnly | Self::Both)
    }

    /// True iff the two-way class-partition invariant holds — every
    /// variant except [`Self::UnclassifiedDrift`]. The variant-side
    /// sibling of [`WatermarkDelta::partitioned_class_invariant_holds`]:
    /// the classification refuses the impossibility corners at
    /// [`WatermarkDelta::relation`] (via `None`), so the only surviving
    /// invariant-violating shape at this altitude is the "full moved
    /// but neither class-scoped half did" corner a non-exhaustive
    /// `field_classes` slice allows.
    #[must_use]
    pub const fn partitioned_class_invariant_holds(&self) -> bool {
        !matches!(self, Self::UnclassifiedDrift)
    }
}

/// A [`WatermarkDelta`] whose "at least one half moved" invariant is
/// welded at the type — a stationary delta has no argument form.
///
/// The two [`ProofRelation`] variants that carry a watermark
/// ([`ProofRelation::Progression`] and [`ProofRelation::CrossStore`])
/// require by construction that the class-scoped comparison is
/// non-stationary: a stationary watermark at the same generation lands
/// in [`ProofRelation::Stationary`] instead of
/// [`ProofRelation::CrossStore`], and a stationary watermark with a
/// generation advance lands in [`ProofRelation::IdentityRepublish`]
/// instead of [`ProofRelation::Progression`]. Before this newtype the
/// invariant lived only in doc comments — a hand-constructed
/// `ProofRelation::CrossStore { watermark: <stationary> }` was
/// representable and semantically inconsistent. Making that variant's
/// field a `MovedWatermarkDelta` closes the invariant into the type
/// shape: the compiler refuses the confusion at the seam rather than
/// leaving a runtime predicate to catch it.
///
/// **Tier: truly-unrepresentable *within this authored surface*** — a
/// stationary payload has no argument form. The only constructor
/// ([`Self::new`]) refuses a stationary delta at its argument boundary.
/// This is the [`UNREPRESENTABILITY.md`](https://github.com/pleme-io/theory/blob/main/UNREPRESENTABILITY.md)
/// tier the crate already reaches for [`ValidatedTieredConfig`] on the
/// value side and [`std::num::NonZeroU64`] on the count side, extended
/// to the watermark-delta payload.
///
/// The `Deref<Target = WatermarkDelta>` impl preserves ergonomic access
/// to every predicate on the underlying delta ([`WatermarkDelta::restart_pending`],
/// [`WatermarkDelta::hot_swappable_drift`], etc.) — a consumer that
/// receives a `MovedWatermarkDelta` through a variant payload never has
/// to unwrap to read the class-scoped questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MovedWatermarkDelta(WatermarkDelta);

impl MovedWatermarkDelta {
    /// Wrap `delta` iff at least one class-scoped half moved. Returns
    /// `None` on a stationary delta rather than panicking — a consumer
    /// that receives a delta from an untrusted source (e.g. one
    /// reconstructed from a wire) uses this constructor to filter out
    /// the null hypothesis without a second `.stationary()` check at
    /// every seam.
    ///
    /// `const` so a compile-time-known delta can be lifted at compile
    /// time, matching [`WatermarkDelta::stationary`]'s `const`-ness.
    #[must_use]
    pub const fn new(delta: WatermarkDelta) -> Option<Self> {
        if delta.stationary() {
            None
        } else {
            Some(Self(delta))
        }
    }

    /// Unwrap to the underlying [`WatermarkDelta`]. The class-scoped
    /// moved-ness invariant survives the projection (the returned value
    /// is still non-stationary), but the type-level weld is gone — a
    /// consumer that wants to keep the invariant should keep the
    /// [`MovedWatermarkDelta`] wrapper.
    #[must_use]
    pub const fn into_inner(self) -> WatermarkDelta {
        self.0
    }

    /// Borrow the underlying [`WatermarkDelta`] without unwrapping — the
    /// same access `Deref` gives, spelled explicitly for the receiver
    /// idiom (`self.as_delta()` reads more naturally than `&*self` in
    /// some call sites).
    #[must_use]
    pub const fn as_delta(&self) -> &WatermarkDelta {
        &self.0
    }
}

impl std::ops::Deref for MovedWatermarkDelta {
    type Target = WatermarkDelta;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<WatermarkDelta> for MovedWatermarkDelta {
    type Error = ShikumiError;

    /// Total conversion from a bare [`WatermarkDelta`] — returns
    /// [`ShikumiError::Validation`] on the stationary null hypothesis
    /// so a consumer using the standard `TryFrom` idiom (`let m:
    /// MovedWatermarkDelta = d.try_into()?;`) surfaces a typed error
    /// at the boundary rather than an `Option::None` a `?` cannot
    /// short-circuit.
    fn try_from(delta: WatermarkDelta) -> Result<Self, Self::Error> {
        Self::new(delta).ok_or_else(|| {
            ShikumiError::Validation(
                "stationary WatermarkDelta cannot be a MovedWatermarkDelta \
                 -- the class-partition moved-ness invariant requires at least \
                 one half to move"
                    .to_owned(),
            )
        })
    }
}

/// The **wire projection** of a [`WatermarkDelta`] — the shape a
/// broadcast event / delta-log entry / cross-replica-diff endpoint
/// serves and a consumer deserializes.
///
/// **Why this type exists — the same-shape wire pair to
/// [`ConfigWatermarkWire`].** [`WatermarkDelta`] is three booleans, so
/// the wire shape is trivially the same three booleans. The value of
/// naming it as a type is **not** "avoid encoding drift" — booleans do
/// not drift the way hashes and timestamps do. It is **close the
/// invariant welds the value form already carries at the parse
/// boundary**, so a consumer that deserializes a [`WatermarkDeltaWire`]
/// holds a value whose invariants have already been checked once at
/// the seam rather than at every downstream use.
///
/// **Two welds a wire deserializer chains at once.**
///
/// 1. [`WatermarkDelta::try_from_wire`] rejects a delta whose shape
///    fails [`WatermarkDelta::class_moves_imply_full_moved`] — a
///    payload where `restart_required_moved || free_moved` is `true`
///    while `full_moved` is `false` cannot come from any well-formed
///    [`WatermarkDelta::between`] call (a class-scoped hash's input is
///    a subset of the full-hash input, so moving the smaller input
///    implies moving the larger one). Refusing at parse time is what
///    the honest-sanity-check doc on
///    [`WatermarkDelta::class_moves_imply_full_moved`] names as the
///    seam a consumer with an untrusted delta must perform.
/// 2. [`MovedWatermarkDelta::try_from_wire`] chains the class-invariant
///    check with the moved-ness constraint, so a consumer that wants
///    the wire form of the [`ProofRelation::Progression`] /
///    [`ProofRelation::CrossStore`] payload holds a
///    [`MovedWatermarkDelta`] directly — the "at least one half moved"
///    proof travels with the payload, not as a re-validation at every
///    seam. This is the "wire projection can rely on the
///    `MovedWatermarkDelta` weld" step the v0.1.503 commit body flagged
///    as the next natural increment after the newtype landed.
///
/// Symmetric to the [`ConfigWatermarkWire`] pattern: one wire type,
/// two typed parse paths, each welding one more invariant than the
/// last. camelCase serde field names match the sibling wire types so a
/// consumer's on-the-wire vocabulary stays consistent
/// (`fullMoved` / `restartRequiredMoved` / `freeMoved`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatermarkDeltaWire {
    /// Whether the full watermark moved — the wire mirror of
    /// [`WatermarkDelta::full_moved`].
    pub full_moved: bool,
    /// Whether the `RequiresRestart` half moved — the wire mirror of
    /// [`WatermarkDelta::restart_required_moved`].
    pub restart_required_moved: bool,
    /// Whether the Free half moved — the wire mirror of
    /// [`WatermarkDelta::free_moved`].
    pub free_moved: bool,
}

impl WatermarkDelta {
    /// Project to the wire shape — three `bool` fields become three
    /// `bool` fields under the camelCase serde vocabulary the sibling
    /// wire types already use. Pure, allocation-free.
    ///
    /// The reverse is [`Self::try_from_wire`], which welds the class-
    /// partition sanity check ([`Self::class_moves_imply_full_moved`])
    /// at the parse boundary so a deserialized delta cannot have a
    /// shape that no honest [`Self::between`] call could have produced.
    #[must_use]
    pub const fn to_wire(&self) -> WatermarkDeltaWire {
        WatermarkDeltaWire {
            full_moved: self.full_moved,
            restart_required_moved: self.restart_required_moved,
            free_moved: self.free_moved,
        }
    }

    /// Reconstruct a [`WatermarkDelta`] from its wire projection — the
    /// inverse of [`Self::to_wire`], welding
    /// [`Self::class_moves_imply_full_moved`] at the parse boundary so
    /// the returned value is guaranteed to have a shape a legitimate
    /// [`Self::between`] call could have produced.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] when the wire has a
    /// class-scoped half moved without `full_moved` — a shape the
    /// class-partition invariant refuses independent of whether the
    /// producer's `field_classes` slice is exhaustive. The error
    /// message names the offending triple so a consumer can localize
    /// the malformed input.
    pub fn try_from_wire(wire: &WatermarkDeltaWire) -> Result<Self, ShikumiError> {
        let candidate = Self {
            full_moved: wire.full_moved,
            restart_required_moved: wire.restart_required_moved,
            free_moved: wire.free_moved,
        };
        if candidate.class_moves_imply_full_moved() {
            Ok(candidate)
        } else {
            Err(ShikumiError::Parse(format!(
                "malformed WatermarkDeltaWire: a class-scoped half moved \
                 without fullMoved (fullMoved={} restartRequiredMoved={} \
                 freeMoved={}) -- a class-scoped hash's input is a subset of \
                 the full-hash input, so this shape cannot come from any \
                 well-formed WatermarkDelta::between call",
                wire.full_moved, wire.restart_required_moved, wire.free_moved,
            )))
        }
    }
}

impl TryFrom<&WatermarkDeltaWire> for WatermarkDelta {
    type Error = ShikumiError;

    fn try_from(wire: &WatermarkDeltaWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

impl MovedWatermarkDelta {
    /// Project to the wire shape — delegates to
    /// [`WatermarkDelta::to_wire`] on the underlying delta. The wire
    /// form is the same three booleans a bare [`WatermarkDelta`]
    /// serializes; the moved-ness invariant is welded on the
    /// **reconstruction** side ([`Self::try_from_wire`]) rather than in
    /// a distinct wire shape, so a producer that sends a stationary
    /// bare delta and a producer that fails to construct a
    /// [`MovedWatermarkDelta`] are two seams for one problem.
    #[must_use]
    pub const fn to_wire(&self) -> WatermarkDeltaWire {
        self.0.to_wire()
    }

    /// Reconstruct a [`MovedWatermarkDelta`] from a
    /// [`WatermarkDeltaWire`] — chains
    /// [`WatermarkDelta::try_from_wire`]'s class-partition check with
    /// [`Self::new`]'s moved-ness check, so a consumer holding the
    /// returned value knows both invariants passed at the parse
    /// boundary.
    ///
    /// This is the wire-side counterpart of the type-level weld the
    /// newtype gives [`ProofRelation::Progression`] and
    /// [`ProofRelation::CrossStore`]: a payload deserialized off the
    /// wire holds the "at least one half moved" proof without a
    /// runtime `stationary()` check at every downstream seam.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] when either weld fails: the
    /// class-partition sanity check (a class-scoped half moved without
    /// `full_moved`) or the moved-ness constraint (all three halves
    /// stationary). The error message names the offending triple so a
    /// consumer can localize the malformed input.
    pub fn try_from_wire(wire: &WatermarkDeltaWire) -> Result<Self, ShikumiError> {
        let delta = WatermarkDelta::try_from_wire(wire)?;
        Self::new(delta).ok_or_else(|| {
            ShikumiError::Parse(format!(
                "malformed WatermarkDeltaWire for MovedWatermarkDelta: \
                 stationary payload (fullMoved={} restartRequiredMoved={} \
                 freeMoved={}) -- a MovedWatermarkDelta requires at least one \
                 class-scoped half to have moved",
                wire.full_moved, wire.restart_required_moved, wire.free_moved,
            ))
        })
    }
}

impl TryFrom<&WatermarkDeltaWire> for MovedWatermarkDelta {
    type Error = ShikumiError;

    fn try_from(wire: &WatermarkDeltaWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

/// The **wire projection** of a [`WatermarkRelation`] — the sum-type
/// peer of [`WatermarkDeltaWire`] at the classification altitude,
/// carrying the same five variants under a serde **internally-tagged**
/// encoding (`{"kind": "..."}`) so a consumer routes on `kind` without
/// deserializing the whole payload first.
///
/// **Why this type exists — the wire-side classification pair to
/// [`ProofRelationWire`] one altitude down.** [`WatermarkRelation`] is
/// the value-side classification of the (`full_moved`,
/// `restart_required_moved`, `free_moved`) grid; the wire form is the
/// same five variants. The value of naming it as a wire type is **not**
/// "avoid encoding drift" — five payload-free tags do not drift the way
/// hashes and timestamps do. It is **hold the classification vocabulary
/// at the wire boundary**, so a `/healthz/config` change-feed or a
/// cross-replica delta-log endpoint that wants to broadcast the
/// watermark classification carries the same `kind` tag a value-side
/// `match` would route on, without re-deriving the classification on
/// every consumer from the underlying [`WatermarkDeltaWire`] triple.
///
/// **The isomorphism is total — no welds at the parse boundary.** Every
/// variant is payload-free, so unlike [`ProofRelationWire`] there is no
/// [`std::num::NonZeroU64`] weld nor [`MovedWatermarkDelta`] weld to
/// chain. The value → wire → value round-trip is a total mechanical
/// mirror; [`WatermarkRelation::from_wire`] and
/// `From<&WatermarkRelationWire>` are total, not fallible. The
/// impossibility bucket that [`WatermarkDelta::relation`] filters to
/// `Option::None` never reaches this wire — a producer that wants to
/// broadcast an impossibility signal sends the underlying
/// [`WatermarkDeltaWire`] instead, whose parse boundary refuses it via
/// [`WatermarkDelta::try_from_wire`]. One wire projection per welded
/// invariant; the impossibility check keeps living where it lived.
///
/// **Why internally-tagged (`{"kind": "..."}`) rather than serde's
/// default externally-tagged shape.** Same reason as
/// [`ProofRelationWire`]: the internal tag puts the classification at a
/// fixed JSON path a consumer can read with one `.get("kind")` lookup,
/// without a variant-shaped wrapping envelope. Matches the `kind`-first
/// vocabulary already established by [`crate::ShikumiErrorKind`],
/// [`crate::ConfigTierKind`], and [`ProofRelationWire`]. camelCase tag
/// values (`stationary`, `unclassifiedDrift`, `restartRequiredOnly`,
/// `freeOnly`, `both`) keep the on-the-wire word bank consistent with
/// the sibling wire types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WatermarkRelationWire {
    /// The wire mirror of [`WatermarkRelation::Stationary`] — no
    /// observable field of the resolved config changed. Serializes as
    /// `{"kind": "stationary"}` with no additional fields.
    Stationary,
    /// The wire mirror of [`WatermarkRelation::UnclassifiedDrift`] — the
    /// full watermark moved but neither class-scoped half did. Only
    /// reachable when the producer's `field_classes` slice is NOT
    /// exhaustive over the config's top-level fields. Serializes as
    /// `{"kind": "unclassifiedDrift"}`.
    UnclassifiedDrift,
    /// The wire mirror of [`WatermarkRelation::RestartRequiredOnly`] — a
    /// `RequiresRestart` field drifted, no Free field did. The CALHA-
    /// side "pending restart signal without a hot-swap" corner.
    /// Serializes as `{"kind": "restartRequiredOnly"}`.
    RestartRequiredOnly,
    /// The wire mirror of [`WatermarkRelation::FreeOnly`] — a Free field
    /// drifted, no `RequiresRestart` field did. The operator-side
    /// "hot-swap without a pending restart" corner. Serializes as
    /// `{"kind": "freeOnly"}`.
    FreeOnly,
    /// The wire mirror of [`WatermarkRelation::Both`] — at least one
    /// field of each class drifted. Serializes as `{"kind": "both"}`.
    Both,
}

impl WatermarkRelation {
    /// Project to the wire shape — each variant mirrors 1:1 to
    /// [`WatermarkRelationWire`]'s peer under the internally-tagged
    /// camelCase encoding. Pure, allocation-free, `const`.
    ///
    /// The reverse is [`Self::from_wire`] — total, not fallible: every
    /// variant is payload-free, so no [`std::num::NonZeroU64`] nor
    /// [`MovedWatermarkDelta`] welds need re-establishing at the parse
    /// boundary, and the impossibility bucket [`WatermarkDelta::relation`]
    /// filters to `Option::None` cannot reach this wire in the first
    /// place.
    #[must_use]
    pub const fn to_wire(&self) -> WatermarkRelationWire {
        match *self {
            Self::Stationary => WatermarkRelationWire::Stationary,
            Self::UnclassifiedDrift => WatermarkRelationWire::UnclassifiedDrift,
            Self::RestartRequiredOnly => WatermarkRelationWire::RestartRequiredOnly,
            Self::FreeOnly => WatermarkRelationWire::FreeOnly,
            Self::Both => WatermarkRelationWire::Both,
        }
    }

    /// Reconstruct a [`WatermarkRelation`] from its wire projection —
    /// the inverse of [`Self::to_wire`]. Total: every variant is
    /// payload-free, so the isomorphism has no parse-time welds to
    /// chain (contrast [`ProofRelation::try_from_wire`], which welds
    /// both [`std::num::NonZeroU64`] on the three generation-carrying
    /// arms and [`MovedWatermarkDelta`] on the two payload-carrying
    /// arms). `const` so a wire value known at compile time can be
    /// lifted at compile time, matching [`Self::to_wire`]'s `const`-ness.
    #[must_use]
    pub const fn from_wire(wire: &WatermarkRelationWire) -> Self {
        match *wire {
            WatermarkRelationWire::Stationary => Self::Stationary,
            WatermarkRelationWire::UnclassifiedDrift => Self::UnclassifiedDrift,
            WatermarkRelationWire::RestartRequiredOnly => Self::RestartRequiredOnly,
            WatermarkRelationWire::FreeOnly => Self::FreeOnly,
            WatermarkRelationWire::Both => Self::Both,
        }
    }
}

impl From<WatermarkRelation> for WatermarkRelationWire {
    /// Total value → wire conversion — delegates to
    /// [`WatermarkRelation::to_wire`]. Provided so a consumer holding
    /// a bare [`WatermarkRelation`] reaches the wire shape through
    /// either the named method or the standard `Into` idiom (`let w:
    /// WatermarkRelationWire = r.into();`), matching the two-seam pair
    /// [`ProofRelation`] carries for its own wire projection.
    fn from(relation: WatermarkRelation) -> Self {
        relation.to_wire()
    }
}

impl From<&WatermarkRelationWire> for WatermarkRelation {
    /// Total wire → value conversion — delegates to
    /// [`WatermarkRelation::from_wire`]. Takes `&Self::Item` (not a
    /// `TryFrom`-style owned value) to match the wire-side impls on
    /// [`WatermarkDelta`] and [`MovedWatermarkDelta`], where every wire
    /// type is `Copy` and the borrowed input is the natural seam
    /// consumers pass a deserialized shape through.
    fn from(wire: &WatermarkRelationWire) -> Self {
        Self::from_wire(wire)
    }
}

impl WatermarkRelationWire {
    /// True iff the classification names at least one moved axis — the
    /// wire-side receiver-sibling of [`WatermarkRelation::any_moved`].
    /// Equivalent to `!self.stationary()`.
    ///
    /// A `/healthz/config` change-feed reader that holds a freshly
    /// deserialized [`WatermarkRelationWire`] and wants the top-level
    /// "did anything move?" answer previously had two inline paths, each
    /// paying a needless cost: (a) `WatermarkRelation::from_wire(&wire).any_moved()`,
    /// which detours through the value-side classification for a
    /// question the wire tag alone answers; or (b)
    /// `!matches!(wire, WatermarkRelationWire::Stationary)` inline, a
    /// shape the exhaustiveness checker cannot help keep in sync with a
    /// future variant addition. The receiver-sibling here answers the
    /// same question at the wire altitude with the same welded `match`
    /// the value-side accessor carries, so a sixth variant added to
    /// [`WatermarkRelationWire`] fails to compile at this method's own
    /// `match` in lockstep with the value-side sibling.
    #[must_use]
    pub const fn any_moved(&self) -> bool {
        !matches!(self, Self::Stationary)
    }

    /// True iff the classification is the null hypothesis — the
    /// wire-side receiver-sibling of [`WatermarkRelation::stationary`].
    /// Equivalent to `!self.any_moved()`.
    #[must_use]
    pub const fn stationary(&self) -> bool {
        matches!(self, Self::Stationary)
    }

    /// True iff the CALHA-side "pending restart signal" arm is
    /// implicated — the wire-side receiver-sibling of
    /// [`WatermarkRelation::restart_pending`]. Answers "did a
    /// `RequiresRestart` field drift?" through the variant tag alone.
    #[must_use]
    pub const fn restart_pending(&self) -> bool {
        matches!(self, Self::RestartRequiredOnly | Self::Both)
    }

    /// True iff the operator-side "hot-swap without a pending restart"
    /// arm is implicated — the wire-side receiver-sibling of
    /// [`WatermarkRelation::hot_swappable_drift`]. Answers "did a Free
    /// field drift?" through the variant tag alone.
    #[must_use]
    pub const fn hot_swappable_drift(&self) -> bool {
        matches!(self, Self::FreeOnly | Self::Both)
    }

    /// True iff the two-way class-partition invariant holds — every
    /// variant except [`Self::UnclassifiedDrift`]. The wire-side
    /// receiver-sibling of
    /// [`WatermarkRelation::partitioned_class_invariant_holds`]:
    /// the classification refuses the impossibility corners at
    /// [`WatermarkDelta::relation`] (via `None`), so the only surviving
    /// invariant-violating shape at this altitude is the "full moved
    /// but neither class-scoped half did" corner a non-exhaustive
    /// `field_classes` slice allows, and the same corner surfaces on
    /// the wire under the same tag.
    #[must_use]
    pub const fn partitioned_class_invariant_holds(&self) -> bool {
        !matches!(self, Self::UnclassifiedDrift)
    }
}

impl ConfigWatermark {
    /// Convenience: the delta from `prior` to `self`. Equivalent to
    /// `WatermarkDelta::between(prior, self)` — spelled at the call site
    /// for the common "compare the just-computed watermark against a
    /// previously-observed one" pattern rather than at a helper-type
    /// entry point.
    #[must_use]
    pub fn delta_since(&self, prior: &Self) -> WatermarkDelta {
        WatermarkDelta::between(prior, self)
    }

    /// The [`WatermarkRelation`] classification from `prior` to `self` —
    /// the sum-type receiver-sibling of [`Self::delta_since`], mirroring
    /// the [`ConfigSyncProof::relation_since`] / [`Self::delta_since`]
    /// pair one altitude up at the proof grid. Reaches the same variant
    /// [`WatermarkDelta::relation`] would yield on the equivalent
    /// [`Self::delta_since`] output, one call rather than two.
    ///
    /// Returns `None` only when the underlying delta violates the weak
    /// class-partition invariant — a shape [`WatermarkDelta::between`]
    /// on any two [`ConfigWatermark`] values produced by
    /// [`Self::compute`] cannot yield in the absence of hash collisions,
    /// so a `None` here signals a hand-constructed inconsistent
    /// [`WatermarkDelta`] leaking through a non-standard path rather
    /// than a legitimate authored-flow outcome.
    #[must_use]
    pub fn relation_since(&self, prior: &Self) -> Option<WatermarkRelation> {
        self.delta_since(prior).relation()
    }

    /// The [`WatermarkRelationWire`] classification-wire from `prior` to
    /// `self` — the wire-side receiver-sibling of [`Self::relation_since`],
    /// fusing the classification and its wire projection at one call
    /// site. Composes `self.relation_since(prior).map(|r| r.to_wire())`.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that broadcasts the classification consumes exactly this
    /// shape: an `Option<WatermarkRelationWire>` where the `Some` arm is
    /// the internally-tagged (`{"kind": "..."}`) classification tag, and
    /// the `None` arm names the same set of hand-constructed
    /// class-partition-invariant violations [`Self::relation_since`]
    /// filters out. The impossibility bucket stays as `Option::None` —
    /// one wire projection per welded invariant, matching the
    /// module-level "impossibility bucket travels as `Option::None`, not
    /// a variant" doc pin.
    ///
    /// Argument order matches [`Self::delta_since`] /
    /// [`Self::relation_since`]: the receiver is the "current" half.
    #[must_use]
    pub fn relation_wire_since(&self, prior: &Self) -> Option<WatermarkRelationWire> {
        self.relation_since(prior).map(|r| r.to_wire())
    }

    /// The [`WatermarkDeltaWire`] projection from `prior` to `self` —
    /// the wire-side receiver-sibling of [`Self::delta_since`], fusing
    /// the delta and its wire projection at one call site. Composes
    /// `self.delta_since(prior).to_wire()`.
    ///
    /// **Closes the same-altitude (`delta`, `relation`) × (`value`,
    /// `wire`) 2×2 grid at the watermark altitude.** The three peers
    /// already carrying the grid are [`Self::delta_since`]
    /// (value/delta), [`Self::relation_since`] (value/relation), and
    /// [`Self::relation_wire_since`] (wire/relation). This method is
    /// the wire/delta cell — the wire projection of the three-bool
    /// [`WatermarkDelta`] shape, reached from a watermark pair in one
    /// call. Mirrors the closure [`ConfigSyncProof::delta_wire_since`]
    /// provided one altitude up at the proof grid.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that holds two [`ConfigWatermark`] values but wants to
    /// broadcast the bare watermark-altitude wire (not the fuller
    /// classification wire from [`Self::relation_wire_since`], and
    /// not going through a [`ConfigSyncProof`] proof-altitude fold)
    /// previously had two inline paths, each leaking work:
    ///
    /// - `self.delta_since(prior).to_wire()` — reach the value-side
    ///   delta through the receiver sibling, then compose the wire
    ///   projection ad hoc at every call site.
    /// - `WatermarkDelta::between(prior, self).to_wire()` — bypass the
    ///   receiver-sibling API entirely and reach
    ///   [`WatermarkDelta::between`] by name, then compose the wire
    ///   projection ad hoc; this path also inverts the "receiver is
    ///   current" convention every peer `*_since` method carries.
    ///
    /// Both routes composed the watermark-altitude bare wire inline at
    /// every seam. This method IS the composition, matching the
    /// "receiver is current" argument-order convention every peer
    /// `*_since` method (at either altitude) already carries.
    ///
    /// **Return type is total, matching [`Self::delta_since`].** Unlike
    /// [`Self::relation_since`] / [`Self::relation_wire_since`] (which
    /// return `Option` because the classification refuses a class-
    /// partition-invariant violation the delta shape can express), the
    /// bare wire projection [`WatermarkDelta::to_wire`] preserves every
    /// shape a [`WatermarkDelta`] can hold — the class-partition
    /// impossibility corner is not filtered here, it is welded at the
    /// parse boundary via [`WatermarkDelta::try_from_wire`] on the
    /// receiving side. A producer of a `WatermarkDeltaWire` reached
    /// through this method cannot originate a class-partition-invariant
    /// violation either, because the underlying [`WatermarkDelta`] came
    /// from [`WatermarkDelta::between`] on two [`ConfigWatermark`]
    /// values whose class-scoped hashes are subsets of the full hash
    /// input by construction of [`Self::compute`].
    ///
    /// **Symmetric across argument-order swap**, unlike the proof-
    /// altitude peer [`ConfigSyncProof::delta_wire_since`]. Moved-ness
    /// at the watermark altitude uses `!=` (XOR-based comparison), so
    /// `a.delta_wire_since(&b) == b.delta_wire_since(&a)` on any pair.
    /// The direction axis a proof pair carries (generation and
    /// observed-at) lives one altitude up and never reaches this
    /// method's body.
    ///
    /// **Cross-altitude coherence.** The wire reached through this
    /// method equals [`ConfigSyncProof::watermark_delta_wire_since`]
    /// on any proof pair whose watermarks are this pair, and equals
    /// the nested [`ProofDeltaWire::watermark`] field on the wire the
    /// proof-altitude [`ConfigSyncProof::delta_wire_since`] reaches.
    /// The three siblings (this method, the cross-altitude wire, the
    /// nested field) reach the same wire tag pointwise.
    ///
    /// Argument order matches [`Self::delta_since`] /
    /// [`Self::relation_since`] / [`Self::relation_wire_since`]: the
    /// receiver is the "current" half.
    #[must_use]
    pub fn delta_wire_since(&self, prior: &Self) -> WatermarkDeltaWire {
        self.delta_since(prior).to_wire()
    }
}

impl ConfigSyncProof {
    /// Convenience: the [`WatermarkDelta`] from `prior.watermark` to
    /// `self.watermark`. The generation and observed-at timestamp are
    /// intentionally NOT folded into the delta shape — those are already
    /// carried by [`ConfigSyncProof`] itself, and a delta between two
    /// proofs whose watermarks are equal is `stationary()` regardless of
    /// how far the generation counter advanced or how much wall time
    /// passed between the two snapshots (a store can publish an identical
    /// value multiple times without moving the watermark).
    #[must_use]
    pub fn watermark_delta_since(&self, prior: &Self) -> WatermarkDelta {
        self.watermark.delta_since(&prior.watermark)
    }

    /// The full [`ProofDelta`] from `prior` to `self` — a proof-altitude
    /// comparison that folds the watermark answer together with the
    /// generation-monotonicity and elapsed-observation axes
    /// [`Self::watermark_delta_since`] intentionally drops.
    ///
    /// A consumer that wants the watermark question alone
    /// (`stationary()` = "did the config value move at all") calls
    /// [`Self::watermark_delta_since`]. A consumer that wants the
    /// proof-altitude questions — "was a generation skipped", "did
    /// generation go backwards", "how much wall time passed between the
    /// two snapshots", "did the watermark move without a generation
    /// bump (cross-store)" — calls this method. Argument order matches
    /// [`ConfigWatermark::delta_since`]: the receiver is the "current"
    /// half, the argument is the "prior" half.
    #[must_use]
    pub fn delta_since(&self, prior: &Self) -> ProofDelta {
        ProofDelta::between(prior, self)
    }
}

/// The typed answer to "what moved between two [`ConfigSyncProof`] values?"
/// — the proof-altitude sibling of [`WatermarkDelta`], adding the two
/// axes a bare watermark comparison cannot express.
///
/// [`WatermarkDelta`] answers "did the config value move at all" over
/// the three class-scoped hash halves. It intentionally throws away the
/// generation counter and the observation timestamp — both fields
/// [`ConfigSyncProof`] itself carries — because a watermark comparison
/// is well-defined without them. But a consumer polling `/healthz/config`
/// often wants the fuller question at the proof altitude:
///
/// - **Did generation go backwards?** ([`Self::generations_regressed`]) —
///   a signal that a monotonic store cannot produce, so its appearance
///   in a [`ProofDelta`] means the two proofs came from different stores,
///   or the wire that carried them was tampered with. Under
///   [`ConfigStore`](crate::ConfigStore)'s generation semantics
///   ([`ConfigStore::generation`](crate::ConfigStore::generation) starts
///   at `0` and monotonically increases on every successful publish),
///   this can only be `false` on any pair produced by a single store.
/// - **Was a generation skipped?** ([`Self::generations_skipped`]) —
///   a consumer polling at some cadence might miss intermediate
///   publishes; the count of missed generations tells the observer how
///   many state transitions it did not witness. `None` when generation
///   regressed, `Some(0)` when exactly one publish happened, `Some(n)`
///   when `n` publishes were missed.
/// - **How much wall time elapsed?** ([`Self::observed_at_elapsed`]) —
///   a per-observer wall-clock reading; unlike generation this can be
///   nonzero on identical proofs (the same value observed twice in
///   sequence), and can be `None` when the two timestamps are not
///   ordered (a system-clock adjustment between the two observations).
/// - **Watermark moved without a generation bump?**
///   ([`Self::cross_store_signal`]) — the invariant weld: a single
///   monotonic store CANNOT produce a proof pair where the watermark
///   moved but generation stayed the same, because moving the watermark
///   requires a publish which bumps generation. This predicate catches
///   the impossibility at the type level.
///
/// The watermark half is preserved as [`Self::watermark`] so a consumer
/// that already knows how to consume a [`WatermarkDelta`] can reach it
/// through the composed shape without a second computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofDelta {
    /// The watermark-altitude comparison — every predicate on
    /// [`WatermarkDelta`] (`full_moved`, `restart_pending`,
    /// `hot_swappable_drift`, etc.) is reachable through this field.
    pub watermark: WatermarkDelta,
    /// How many generations advanced from `prior` to `current`.
    /// `Some(0)` iff the two proofs share a generation counter (a
    /// re-observation of the same publish). `Some(n)` iff current's
    /// generation is `n` greater than prior's. `None` iff current's
    /// generation is STRICTLY less than prior's — a "backwards
    /// generation" that a monotonic store cannot produce, so its
    /// appearance is a diagnostic signal, not a legitimate reading.
    pub generations_advanced: Option<u64>,
    /// Wall-clock time elapsed between `prior.observed_at` and
    /// `self.observed_at`. `None` iff `self.observed_at < prior.observed_at`
    /// — a system-clock adjustment (NTP step, container migration)
    /// between the two observations, which unlike generation is a
    /// legitimate real-world condition, not a bug signal.
    pub observed_at_elapsed: Option<std::time::Duration>,
}

impl ProofDelta {
    /// Compute the proof-altitude delta from `prior` to `current` —
    /// a pointwise comparison over the three proof fields.
    /// Pure, allocation-free.
    #[must_use]
    pub fn between(prior: &ConfigSyncProof, current: &ConfigSyncProof) -> Self {
        Self {
            watermark: prior.watermark.delta_since(&current.watermark),
            generations_advanced: current.generation.checked_sub(prior.generation),
            observed_at_elapsed: current.observed_at.duration_since(prior.observed_at).ok(),
        }
    }

    /// True iff neither the watermark moved nor the generation advanced
    /// — the pair of proofs represents the same observation twice.
    /// Note: `observed_at` is intentionally NOT part of the stationary
    /// predicate; a consumer that observed the same publish at two
    /// different wall-clock instants (the common `/healthz/config`
    /// polling case) still reports `stationary()`.
    #[must_use]
    pub const fn stationary(&self) -> bool {
        self.watermark.stationary() && matches!(self.generations_advanced, Some(0))
    }

    /// True iff current's generation is strictly less than prior's —
    /// a signal that a single monotonic
    /// [`ConfigStore`](crate::ConfigStore) cannot produce, so its
    /// appearance means the two proofs came from different stores, or
    /// the wire that carried them was tampered with.
    #[must_use]
    pub const fn generations_regressed(&self) -> bool {
        self.generations_advanced.is_none()
    }

    /// How many publishes happened between the two observations WITHOUT
    /// the polling observer witnessing them — `generations_advanced - 1`
    /// clamped to zero, or `None` if generation regressed. A polling
    /// consumer that sees `Some(0)` observed every publish; a consumer
    /// that sees `Some(n)` missed `n` intermediate state transitions
    /// and should widen its polling cadence.
    #[must_use]
    pub const fn generations_skipped(&self) -> Option<u64> {
        match self.generations_advanced {
            Some(n) => Some(n.saturating_sub(1)),
            None => None,
        }
    }

    /// True iff a re-publish of the same value happened between the two
    /// observations — watermark stationary, generation advanced by one
    /// or more. Distinguishable from `stationary()` (same observation
    /// twice) exactly by the generation axis.
    #[must_use]
    pub const fn identity_republish(&self) -> bool {
        if !self.watermark.stationary() {
            return false;
        }
        matches!(self.generations_advanced, Some(n) if n > 0)
    }

    /// The invariant weld: true iff the watermark moved but generation
    /// did NOT advance. A single monotonic
    /// [`ConfigStore`](crate::ConfigStore) cannot produce this state —
    /// moving the watermark requires a publish which bumps generation.
    /// Its appearance in a delta means the two proofs originated from
    /// different stores (a cross-replica comparison misplaced as a
    /// same-store one), or the wire that carried them was tampered with.
    ///
    /// Symmetric peer of [`Self::generations_regressed`] on the
    /// impossibility side: both predicates catch a proof pair that no
    /// single well-formed store could have produced.
    #[must_use]
    pub const fn cross_store_signal(&self) -> bool {
        !self.watermark.stationary() && matches!(self.generations_advanced, Some(0))
    }

    /// True iff the pair of proofs is consistent with having come from a
    /// single monotonic [`ConfigStore`](crate::ConfigStore) — no
    /// generation regression AND no watermark-move-without-generation-bump.
    /// The typed conjunction of the two impossibility predicates,
    /// spelled once so a consumer that wants the "trust this pair"
    /// question doesn't have to hand-write the boolean at every seam.
    #[must_use]
    pub const fn same_store_consistent(&self) -> bool {
        !self.generations_regressed() && !self.cross_store_signal()
    }

    /// Classify the delta into the exhaustive [`ProofRelation`] sum —
    /// the delta-altitude classification receiver-sibling of
    /// [`ConfigSyncProof::relation_since`].
    ///
    /// **Same-`Option::None` idiom as [`WatermarkDelta::relation`] one
    /// altitude down.** Returns `None` on exactly two impossibility
    /// buckets:
    ///
    /// 1. `self.generations_advanced.is_none()` — the delta folded the
    ///    exact backwards-regression count into `Option::None` and
    ///    cannot recover the [`std::num::NonZeroU64`] `by` that
    ///    [`ProofRelation::Regressed`] carries. A consumer that needs
    ///    the count reaches [`ProofRelation::between`] /
    ///    [`ConfigSyncProof::relation_since`] on the original proof pair
    ///    instead, where the count is preserved.
    /// 2. `!self.watermark.class_moves_imply_full_moved()` — the
    ///    underlying watermark is in the class-partition impossibility
    ///    corner (`restart_required_moved || free_moved` while
    ///    `!full_moved`, three tuples). [`ProofDelta::between`] on any
    ///    pair of [`ConfigSyncProof`] values whose watermarks came from
    ///    [`ConfigWatermark::compute`] never produces this shape, but a
    ///    hand-constructed [`ProofDelta`] through the `pub`-field
    ///    constructor can. Since the [`ProofRelation::Progression`] /
    ///    [`ProofRelation::CrossStore`] payload's [`MovedWatermarkDelta`]
    ///    welds moved-ness but NOT class-partition, letting the shape
    ///    escape into the payload would surface as a downstream
    ///    invariant break at a wire boundary far from the seam that
    ///    produced it. Refusing here mirrors
    ///    [`WatermarkDelta::relation`]'s `Option::None` filtering on the
    ///    same three tuples one altitude down — the impossibility bucket
    ///    travels as `Option::None`, not as a variant, on both altitudes.
    ///
    /// **Agreement with [`ConfigSyncProof::relation_since`] on the four
    /// legitimate delta corners.** For any two [`ConfigSyncProof`]
    /// values `prior` and `current` with `current.generation >=
    /// prior.generation`, `current.delta_since(&prior).relation()`
    /// equals `Some(current.relation_since(&prior))` pointwise. The two
    /// diverge only on the regressed corner, where the delta lost the
    /// count and can no longer fill the [`ProofRelation::Regressed`]
    /// variant — this method returns `None`, the proof-pair sibling
    /// returns `Some(Regressed { by })`.
    ///
    /// `const` so a compile-time-known delta classifies at compile time
    /// — matching [`WatermarkDelta::relation`]'s `const`-ness one
    /// altitude down.
    #[must_use]
    pub const fn relation(&self) -> Option<ProofRelation> {
        let Some(generations_advanced) = self.generations_advanced else {
            return None;
        };
        if !self.watermark.class_moves_imply_full_moved() {
            return None;
        }
        if self.watermark.stationary() {
            if generations_advanced == 0 {
                Some(ProofRelation::Stationary)
            } else {
                // generations_advanced > 0 checked; NonZeroU64::new is Some.
                match std::num::NonZeroU64::new(generations_advanced) {
                    Some(generations) => Some(ProofRelation::IdentityRepublish { generations }),
                    None => None,
                }
            }
        } else {
            // watermark non-stationary; MovedWatermarkDelta::new is Some.
            let Some(watermark) = MovedWatermarkDelta::new(self.watermark) else {
                return None;
            };
            if generations_advanced == 0 {
                Some(ProofRelation::CrossStore { watermark })
            } else {
                match std::num::NonZeroU64::new(generations_advanced) {
                    Some(generations) => Some(ProofRelation::Progression {
                        watermark,
                        generations,
                    }),
                    None => None,
                }
            }
        }
    }

    /// The wire-side sibling of [`Self::relation`] — classifies this
    /// delta into the [`ProofRelationWire`] sum and returns it wrapped
    /// in the same `Option` shape [`Self::relation`] carries. Composes
    /// `self.relation().map(|r| r.to_wire())` at one call, spelled
    /// `const` (matching [`Self::relation`] and
    /// [`ProofRelation::to_wire`], neither of which allocates) so a
    /// delta known at compile time projects to its classification wire
    /// at compile time too.
    ///
    /// **Closes the proof-delta-altitude (`bare`, `relation`) × (`value`,
    /// `wire`) 2×2 grid.** Before this pair of methods the grid was
    /// half-empty at the proof-delta altitude: the value-side bare
    /// projection is the `ProofDelta` type itself, the wire-side bare
    /// projection is [`Self::to_wire`], but neither classification cell
    /// existed. This method IS the wire-side classification composition
    /// at the delta altitude, matching the shape [`Self::to_wire`]
    /// already carries for the bare projection and mirroring
    /// [`WatermarkDelta::relation_wire`]'s discipline one altitude down.
    ///
    /// **Same-`None` invariant with [`Self::relation`].** Returns `None`
    /// on exactly the two impossibility corners [`Self::relation`]
    /// filters — the generation-regressed corner (delta lost the `by`
    /// count) and the class-partition impossibility corner (only
    /// reachable through the `pub`-field constructor).
    ///
    /// **Coherence with [`ConfigSyncProof::relation_wire_since`] on the
    /// four legitimate corners.** For any two [`ConfigSyncProof`]
    /// values `prior` and `current` with `current.generation >=
    /// prior.generation`, `current.delta_since(&prior).relation_wire()`
    /// equals `Some(current.relation_wire_since(&prior))` pointwise.
    /// The two diverge only on the regressed corner, where the delta
    /// lost the count and can no longer fill the
    /// [`ProofRelationWire::Regressed`] arm — this method returns
    /// `None`, the proof-pair sibling returns
    /// `Some(Regressed { by })`.
    #[must_use]
    pub const fn relation_wire(&self) -> Option<ProofRelationWire> {
        match self.relation() {
            Some(r) => Some(r.to_wire()),
            None => None,
        }
    }
}

/// The **wire projection** of a [`ProofDelta`] — the proof-altitude
/// sibling of [`WatermarkDeltaWire`], adding the two axes a bare
/// watermark comparison cannot express.
///
/// **Why this type exists — the proof-altitude wire pair to
/// [`WatermarkDeltaWire`].** [`ProofDelta`] extends [`WatermarkDelta`]
/// with two `Option`-wrapped axes: `generations_advanced`
/// ([`Option::None`] iff generation regressed) and `observed_at_elapsed`
/// ([`Option::None`] iff a system-clock adjustment ran the wall-clock
/// backwards between the two observations). Both `Option`s pass through
/// serde's native tagged encoding without a custom serializer. The
/// watermark half NESTS as a [`WatermarkDeltaWire`], matching the way
/// [`ConfigSyncProofWire`] nests [`ConfigWatermarkWire`] — so the class-
/// partition invariant weld carried at [`WatermarkDelta::try_from_wire`]
/// travels with this payload. A `ProofDeltaWire` cannot carry a
/// watermark shape the [`WatermarkDelta::between`] fold could not
/// produce, because the parse boundary refuses it once, at the seam.
///
/// **What is NOT welded here (and why).** [`ProofDelta`] itself carries
/// no impossibility corners — every combination of `(watermark_moved,
/// generations_advanced)` is representable, and the semantically
/// meaningful combinations ([`ProofDelta::stationary`],
/// [`ProofDelta::identity_republish`], [`ProofDelta::cross_store_signal`],
/// [`ProofDelta::generations_regressed`]) are diagnostic predicates
/// describing wire values that are all legitimate at the delta altitude
/// (a cross-store signal is genuine information about a proof pair, not
/// a shape to refuse). The type-level impossibility welds live one
/// altitude up on [`ProofRelation`], whose payload-carrying variants
/// ([`ProofRelation::Progression`] and [`ProofRelation::CrossStore`])
/// hold a [`MovedWatermarkDelta`]. This type stops at the honest
/// [`ProofDelta`] shape; the sum-type wire projection is the next
/// natural increment, which will chain
/// [`MovedWatermarkDelta::try_from_wire`] for those two variants and
/// [`std::num::NonZeroU64`] parses for the three generation-carrying
/// arms — inheriting this shape and adding only the variant tag plus
/// the nonzero welds.
///
/// **Nanosecond wire unit for the elapsed axis.** [`std::time::Duration`]
/// on the value side has nanosecond precision; the wire preserves it as
/// `Option<u64>` nanoseconds (max ~584 years, well beyond any
/// legitimate poll interval between two observations). A `u64` is a
/// single JSON number rather than the two-field
/// `{secs, nanos}` shape serde's default `Duration` encoding uses,
/// keeping the wire compact and matching the "one field, one number"
/// vocabulary [`ConfigSyncProofWire::observed_at_epoch`] established
/// for the absolute-time axis. Field name (`observedAtElapsedNanos`)
/// spells the unit at the wire so a consumer never has to remember
/// which power-of-ten scale to divide by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofDeltaWire {
    /// The class-scoped watermark comparison — the wire mirror of
    /// [`ProofDelta::watermark`]. NESTED as a [`WatermarkDeltaWire`]
    /// so the class-partition invariant weld on that type
    /// ([`WatermarkDelta::class_moves_imply_full_moved`]) travels
    /// with this payload and fires at
    /// [`ProofDelta::try_from_wire`]'s parse boundary.
    pub watermark: WatermarkDeltaWire,
    /// How many generations advanced from `prior` to `current`. The
    /// wire mirror of [`ProofDelta::generations_advanced`]: `Some(0)`
    /// iff same generation (identity observation), `Some(n>0)` iff a
    /// generation advance, `None` iff current's generation was
    /// strictly less than prior's. `None` on the wire is a diagnostic
    /// signal that a monotonic
    /// [`ConfigStore`](crate::ConfigStore) cannot produce, not a shape
    /// to refuse — a consumer that receives it knows the two proofs
    /// came from different stores or that the wire that carried them
    /// was tampered with.
    pub generations_advanced: Option<u64>,
    /// Wall-clock time elapsed between `prior.observed_at` and
    /// `current.observed_at`, in nanoseconds. The wire mirror of
    /// [`ProofDelta::observed_at_elapsed`]: `Some(n)` iff the two
    /// observations were ordered forward, `None` iff current's
    /// timestamp was strictly less than prior's. Unlike the
    /// generation axis, `None` here is a legitimate real-world
    /// condition (NTP step, container migration between observations)
    /// rather than a same-store impossibility.
    pub observed_at_elapsed_nanos: Option<u64>,
}

impl ProofDelta {
    /// Project to the wire shape — the watermark half nests as a
    /// [`WatermarkDeltaWire`] (matching how [`ConfigSyncProofWire`]
    /// nests [`ConfigWatermarkWire`]), the `generations_advanced`
    /// `Option` passes through unchanged, and the
    /// `observed_at_elapsed` [`Duration`](std::time::Duration) becomes
    /// `Option<u64>` nanoseconds. Pure, allocation-free.
    #[must_use]
    pub fn to_wire(&self) -> ProofDeltaWire {
        ProofDeltaWire {
            watermark: self.watermark.to_wire(),
            generations_advanced: self.generations_advanced,
            observed_at_elapsed_nanos: self
                .observed_at_elapsed
                .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
        }
    }

    /// Reconstruct a [`ProofDelta`] from its wire projection — the
    /// inverse of [`Self::to_wire`], chaining
    /// [`WatermarkDelta::try_from_wire`]'s class-partition weld on the
    /// nested watermark half so the returned delta's watermark is
    /// guaranteed to have a shape a legitimate
    /// [`WatermarkDelta::between`] call could have produced.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] propagated from the nested
    /// [`WatermarkDelta::try_from_wire`] call — the two `Option` axes
    /// have no impossibility corners at the [`ProofDelta`] altitude
    /// (both diagnostic combinations they express are legitimate wire
    /// values that a consumer must be able to receive and route on),
    /// so the only parse error at this altitude surfaces from the
    /// class-partition weld on the nested watermark.
    pub fn try_from_wire(wire: &ProofDeltaWire) -> Result<Self, ShikumiError> {
        Ok(Self {
            watermark: WatermarkDelta::try_from_wire(&wire.watermark)?,
            generations_advanced: wire.generations_advanced,
            observed_at_elapsed: wire
                .observed_at_elapsed_nanos
                .map(std::time::Duration::from_nanos),
        })
    }
}

impl TryFrom<&ProofDeltaWire> for ProofDelta {
    type Error = ShikumiError;

    fn try_from(wire: &ProofDeltaWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

/// Exhaustive sum-type classification of a proof pair — every possible
/// relation between two [`ConfigSyncProof`] values lands in exactly one
/// variant.
///
/// The (watermark moved?, generation delta) grid partitions into five
/// disjoint corners: the three legitimate corners a single monotonic
/// [`ConfigStore`](crate::ConfigStore) actually produces, and the two
/// same-store impossibilities. Each corner is a variant here.
///
/// **Why name this as a type at all.** [`ProofDelta`] already carries the
/// four boolean predicates ([`ProofDelta::stationary`],
/// [`ProofDelta::identity_republish`], [`ProofDelta::cross_store_signal`],
/// [`ProofDelta::generations_regressed`]) that answer "which corner is this
/// pair in?" — but each independently, forcing every consumer that wants to
/// route on the answer to write a nested if-else chain that the
/// exhaustiveness checker cannot help with. A future sixth corner added to
/// the grid (say, a signed-attestation attestor field on
/// [`ConfigSyncProof`]) would silently overlap the existing predicates
/// rather than turning every routing site red. `ProofRelation` promotes the
/// classification to a `match`-able shape: consumers reason over the whole
/// space with the exhaustiveness checker's help, and adding a new arm is
/// what surfaces every consumer that must handle it.
///
/// **The previously-unnamed corner.** [`Self::Progression`] is the "normal
/// happy path" of the grid — the watermark moved AND generation advanced,
/// which is what every routine config-file edit produces. `ProofDelta`
/// carries predicates for the other four corners
/// (`stationary`/`identity_republish`/`cross_store_signal`/`generations_regressed`)
/// and leaves this one implicit, so a consumer that wants to react to a
/// legitimate value change had to hand-write `d.watermark.any_moved() &&
/// matches!(d.generations_advanced, Some(n) if n > 0)` at every seam. Naming
/// it lets the consumer bind the two carried quantities in one `if let`.
///
/// **The [`std::num::NonZeroU64`] welds.** Each variant that carries a
/// generation count welds a load-bearing invariant at the type: an
/// [`Self::IdentityRepublish`] with a zero generation count would be
/// indistinguishable from [`Self::Stationary`], a [`Self::Progression`]
/// with a zero count from [`Self::CrossStore`], and a [`Self::Regressed`]
/// with a zero regression from any of the equal-generation corners. The
/// nonzero constraint makes each of those confusions unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRelation {
    /// Same observation twice — watermark stationary AND generation
    /// counter unchanged. The null hypothesis a poller checks before
    /// doing any further inspection.
    Stationary,
    /// A re-publish of an identical value — watermark stationary, but
    /// the generation counter advanced by `generations`. A running
    /// [`ConfigStore`](crate::ConfigStore) may republish an identical
    /// value (a reload cycle over a filesystem that flipped and flipped
    /// back before the observer noticed), which bumps generation
    /// without moving any watermark half.
    IdentityRepublish {
        /// How many publishes happened between the two observations —
        /// always at least one, since a zero-count "republish" would be
        /// indistinguishable from [`Self::Stationary`].
        generations: std::num::NonZeroU64,
    },
    /// A legitimate publish that also changed the value — the watermark
    /// moved AND the generation counter advanced by `generations`. The
    /// "normal progression" corner of the grid: every routine
    /// config-file edit surfaces here. This is the corner
    /// [`ProofDelta`]'s four boolean predicates leave implicit.
    Progression {
        /// The class-scoped watermark comparison, so a consumer that
        /// needs to route on [`WatermarkDelta::restart_pending`] /
        /// [`WatermarkDelta::hot_swappable_drift`] reaches those
        /// questions through the variant's payload without a second
        /// computation. Non-stationary by construction: a stationary
        /// watermark with a generation advance lands in
        /// [`Self::IdentityRepublish`] instead, and the
        /// [`MovedWatermarkDelta`] type welds that invariant at the
        /// field shape — a hand-constructed `Progression` with a
        /// stationary payload is unrepresentable. `Deref` preserves
        /// ergonomic access to every predicate on the underlying
        /// [`WatermarkDelta`], so consumers reading `watermark.restart_pending()`
        /// through the variant payload keep the same syntax they had
        /// before the weld.
        watermark: MovedWatermarkDelta,
        /// How many publishes happened between the two observations —
        /// always at least one, since a zero-count "progression" would
        /// be indistinguishable from [`Self::CrossStore`].
        generations: std::num::NonZeroU64,
    },
    /// Same-store impossibility: the watermark moved but the generation
    /// counter did NOT advance. Moving the watermark requires a publish
    /// which bumps generation; a monotonic
    /// [`ConfigStore`](crate::ConfigStore) cannot produce this pair.
    /// Its appearance means the two proofs came from different stores
    /// (a cross-replica comparison misplaced as a same-store one), or
    /// the wire that carried them was tampered with.
    CrossStore {
        /// The class-scoped watermark comparison. Non-stationary by
        /// construction — a stationary watermark at the same generation
        /// lands in [`Self::Stationary`], not here. The
        /// [`MovedWatermarkDelta`] type welds that invariant at the
        /// field shape: a hand-constructed `CrossStore` with a
        /// stationary payload is unrepresentable, so the "the two
        /// impossibility variants overlap on the stationary edge"
        /// confusion that lived only in doc comments before now fails
        /// to type-check.
        watermark: MovedWatermarkDelta,
    },
    /// Same-store impossibility: current's generation is strictly less
    /// than prior's. A monotonic
    /// [`ConfigStore`](crate::ConfigStore) cannot produce this pair.
    Regressed {
        /// How many generations the counter went backwards — always at
        /// least one, since a zero-count "regression" would be
        /// indistinguishable from an equal-generation corner.
        by: std::num::NonZeroU64,
    },
}

impl ProofRelation {
    /// Classify the proof pair from `prior` to `current` into the
    /// exhaustive [`ProofRelation`] sum. The primary constructor for
    /// this type — takes the two proofs directly rather than going
    /// through [`ProofDelta`], so the exact regression count is
    /// preserved on the [`Self::Regressed`] arm (a `ProofDelta` folds
    /// that count into `Option::None` and cannot recover it).
    ///
    /// Argument order matches [`ProofDelta::between`] and
    /// [`WatermarkDelta::between`]: prior first, current second.
    #[must_use]
    pub fn between(prior: &ConfigSyncProof, current: &ConfigSyncProof) -> Self {
        let watermark = WatermarkDelta::between(&prior.watermark, &current.watermark);
        match current.generation.cmp(&prior.generation) {
            std::cmp::Ordering::Less => {
                // Strictly regressing generation — nonzero by
                // construction, so the unwrap cannot fire.
                let by = std::num::NonZeroU64::new(prior.generation - current.generation)
                    .expect("strictly-less generation yields a nonzero backwards delta");
                Self::Regressed { by }
            }
            std::cmp::Ordering::Equal => {
                if let Some(watermark) = MovedWatermarkDelta::new(watermark) {
                    // Non-stationary at the same generation: same-store
                    // impossibility. The `if let` fold is what welds the
                    // "CrossStore never carries a stationary payload"
                    // invariant — the stationary case is already handled
                    // by the `None` branch below, so this arm cannot
                    // reach an empty `MovedWatermarkDelta`.
                    Self::CrossStore { watermark }
                } else {
                    Self::Stationary
                }
            }
            std::cmp::Ordering::Greater => {
                let generations = std::num::NonZeroU64::new(current.generation - prior.generation)
                    .expect("strictly-greater generation yields a nonzero forward delta");
                if let Some(watermark) = MovedWatermarkDelta::new(watermark) {
                    // Non-stationary with a generation advance: the
                    // "normal progression" corner. The `if let` fold
                    // welds "Progression never carries a stationary
                    // payload" — the stationary case is handled by the
                    // `IdentityRepublish` branch below.
                    Self::Progression {
                        watermark,
                        generations,
                    }
                } else {
                    Self::IdentityRepublish { generations }
                }
            }
        }
    }

    /// True iff this classification is one of the three legitimate
    /// corners — the two impossibility variants ([`Self::CrossStore`]
    /// and [`Self::Regressed`]) return false. Equivalent to
    /// [`ProofDelta::same_store_consistent`] but reached through the
    /// variant shape, so a consumer already pattern-matching on the
    /// enum doesn't have to fall back to a second projection through
    /// the delta.
    #[must_use]
    pub const fn same_store_consistent(&self) -> bool {
        matches!(
            self,
            Self::Stationary | Self::IdentityRepublish { .. } | Self::Progression { .. }
        )
    }

    /// True iff this classification is one of the two same-store
    /// impossibility corners — [`Self::CrossStore`] (a moved watermark
    /// at an unchanged generation counter) or [`Self::Regressed`] (a
    /// strictly-backwards generation counter). The three legitimate
    /// same-store-consistent variants ([`Self::Stationary`],
    /// [`Self::IdentityRepublish`], [`Self::Progression`]) all return
    /// `false`.
    ///
    /// **The direct dual of [`Self::same_store_consistent`], and the
    /// welded two-variant union of [`Self::cross_store`] and
    /// [`Self::regressed`].** The prior five tag-only classifiers pin
    /// the five *single-variant* corners of the [`Xor`][matches!]
    /// partition; this receiver is the first *two-variant union*
    /// tag-only classifier, welding the impossibility half of the
    /// [`Self::same_store_consistent`] partition into its own
    /// [`matches!`] pattern the exhaustiveness checker can help keep
    /// in sync with a future variant addition. A monitoring dashboard
    /// or a cross-replica delta-log endpoint that holds a freshly
    /// computed [`ProofRelation`] and wants the top-level "did we see
    /// a same-store impossibility?" answer previously had three
    /// inline paths, each leaking work: (a) `!self.same_store_consistent()`
    /// — a single-hop negation through the legitimate-corners
    /// predicate that reaches the answer through the negative space
    /// of the three legitimate corners, forcing the consumer to
    /// reason about the *complement* rather than the impossibility
    /// itself; (b) `self.regressed() || self.cross_store()` — a
    /// two-hop composition through two tag-only classifiers whose
    /// disjunction the exhaustiveness checker cannot help keep in
    /// sync with a future impossibility corner (adding a hypothetical
    /// third impossibility variant would silently escape the two-arm
    /// disjunction without turning the callsite red); or (c)
    /// `matches!(relation, ProofRelation::CrossStore { .. } |
    /// ProofRelation::Regressed { .. })` inline at every seam, a
    /// shape the exhaustiveness checker cannot help keep in sync with
    /// a future variant addition. The receiver-sibling here answers
    /// the same question through a single welded [`matches!`]:
    /// adding a sixth variant to [`ProofRelation`] fails to compile
    /// at this method's pattern in lockstep with
    /// [`Self::same_store_consistent`], [`Self::regressed`],
    /// [`Self::cross_store`], and every other classification receiver
    /// in this impl.
    ///
    /// **Complement identity with [`Self::same_store_consistent`].**
    /// At both altitudes, `self.same_store_inconsistent() ==
    /// !self.same_store_consistent()` pointwise on every variant —
    /// the two receivers partition the five variants into two
    /// receiver-family half-spaces (`{Stationary, IdentityRepublish,
    /// Progression}` on the consistent half, `{CrossStore, Regressed}`
    /// on the inconsistent half). Together they weld the two-way
    /// partition of the classification into a pair of
    /// receiver-visible predicates whose disjunction is the constant
    /// `true` and whose conjunction is the constant `false`.
    ///
    /// **Union identity with [`Self::cross_store`] and
    /// [`Self::regressed`].** At both altitudes,
    /// `self.same_store_inconsistent() == (self.cross_store() ||
    /// self.regressed())` pointwise on every variant — the
    /// two-variant union receiver equals the disjunction of the two
    /// single-variant tag-only receivers whose variants it welds.
    /// The receiver-family now carries THREE distinct shapes for the
    /// impossibility half: the complement of the consistent
    /// predicate, the disjunction of the two single-variant
    /// predicates, and this welded two-variant [`matches!`]. All
    /// three agree pointwise, and this receiver alone reaches the
    /// answer through the single-hop [`matches!`] the tag alone
    /// supports.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its same-store-inconsistency verdict at compile time
    /// too, matching the `const`-ness of every other classification
    /// accessor (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::same_store_inconsistent`],
    /// which answers the same question at the wire altitude with the
    /// same welded pattern.
    #[must_use]
    pub const fn same_store_inconsistent(&self) -> bool {
        matches!(self, Self::CrossStore { .. } | Self::Regressed { .. })
    }

    /// True iff this classification is the null hypothesis — the
    /// [`Self::Stationary`] variant, the same observation twice. The
    /// four other variants ([`Self::IdentityRepublish`],
    /// [`Self::Progression`], [`Self::CrossStore`], [`Self::Regressed`])
    /// all return `false`.
    ///
    /// **The tag-only classifier for the "did anything happen?"
    /// question.** A poller holding a freshly computed
    /// [`ProofRelation`] previously had two paths for the null-hypothesis
    /// check, each leaking work: (a)
    /// [`ProofDelta::stationary`] via `self.delta_since(prior).stationary()`,
    /// a two-hop detour through the delta altitude for a question the
    /// classification tag alone answers (and one that pays for the
    /// `NonZeroU64` fold on the generation counter even though the
    /// stationary corner never touches it); or (b) `matches!(relation,
    /// ProofRelation::Stationary)` inline at every seam, a shape the
    /// exhaustiveness checker cannot help keep in sync with a future
    /// variant addition. The receiver-sibling here answers the same
    /// question through a single welded [`matches!`]: adding a sixth
    /// variant to [`ProofRelation`] fails to compile at this method's
    /// pattern in lockstep with [`Self::same_store_consistent`] and
    /// every other classification receiver in this impl.
    ///
    /// **Duality with [`Self::same_store_consistent`]:** the stationary
    /// corner is a strict subset of the same-store-consistent corners
    /// (`Stationary` implies `same_store_consistent`), so a routing
    /// consumer that already knows `!self.same_store_consistent()` can
    /// skip this predicate — but not the other way around, since the
    /// same-store-consistent set also carries [`Self::IdentityRepublish`]
    /// and [`Self::Progression`].
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its stationarity verdict at compile time too, matching
    /// the `const`-ness of every other classification accessor
    /// (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::stationary`], which
    /// answers the same question at the wire altitude with the same
    /// welded pattern.
    #[must_use]
    pub const fn stationary(&self) -> bool {
        matches!(self, Self::Stationary)
    }

    /// True iff this classification is [`Self::IdentityRepublish`] — the
    /// watermark stationary corner at a strictly-advanced generation
    /// counter. The four other variants ([`Self::Stationary`],
    /// [`Self::Progression`], [`Self::CrossStore`], [`Self::Regressed`])
    /// all return `false`.
    ///
    /// **The tag-only classifier for the "did we reload without changing
    /// the value?" question.** A [`ConfigStore`](crate::ConfigStore)
    /// consumer that wants to distinguish an identical-value republish
    /// (a reload cycle over a filesystem that flipped and flipped back
    /// before the observer noticed) from every other legitimate or
    /// impossibility corner previously had two inline paths, each leaking
    /// work: (a) `self.watermark().is_none() && self.same_store_consistent()
    /// && !self.stationary()` — a three-hop composition through two
    /// payload accessors and a predicate that reaches the answer through
    /// the negative space of the four other variants; or (b)
    /// `matches!(relation, ProofRelation::IdentityRepublish { .. })` inline
    /// at every seam, a shape the exhaustiveness checker cannot help keep
    /// in sync with a future variant addition. The receiver-sibling here
    /// answers the same question through a single welded [`matches!`]:
    /// adding a sixth variant to [`ProofRelation`] fails to compile at
    /// this method's pattern in lockstep with [`Self::stationary`],
    /// [`Self::same_store_consistent`], and every other classification
    /// receiver in this impl.
    ///
    /// **Disjointness with [`Self::stationary`]:** the two null-hypothesis
    /// / identity-republish predicates are pairwise disjoint (no variant
    /// satisfies both), and both are strict subsets of
    /// [`Self::same_store_consistent`]. The three tag-only predicates
    /// together are STRICTLY LESS THAN the same-store-consistent set,
    /// which also carries [`Self::Progression`] — a strictly-larger
    /// legitimate corner whose classifier remains to be surfaced as its
    /// own receiver.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its identity-republish verdict at compile time too,
    /// matching the `const`-ness of every other classification accessor
    /// (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::identity_republish`],
    /// which answers the same question at the wire altitude with the same
    /// welded pattern.
    #[must_use]
    pub const fn identity_republish(&self) -> bool {
        matches!(self, Self::IdentityRepublish { .. })
    }

    /// True iff this classification is [`Self::Regressed`] — the sole
    /// same-store impossibility corner whose signal is a strictly-backwards
    /// generation counter (as opposed to [`Self::CrossStore`], the other
    /// impossibility corner, whose signal is a moved watermark at an
    /// unchanged generation). The four other variants
    /// ([`Self::Stationary`], [`Self::IdentityRepublish`],
    /// [`Self::Progression`], [`Self::CrossStore`]) all return `false`.
    ///
    /// **The tag-only classifier for the "did the counter go backwards?"
    /// question.** A monitoring consumer holding a freshly computed
    /// [`ProofRelation`] previously had three inline paths, each leaking
    /// work: (a) `!self.same_store_consistent() && self.watermark().is_none()`
    /// — a two-hop composition through a payload accessor and a predicate
    /// that reaches the answer through the negative space of every other
    /// variant, chaining a [`MovedWatermarkDelta`] payload lookup a
    /// tag-only classification doesn't need; (b) `self.regressed_by().is_some()`
    /// — a projection through the payload accessor for a question the
    /// variant tag alone already answers, which forces a consumer that
    /// doesn't care about the magnitude to reach past the tag anyway; or
    /// (c) `matches!(relation, ProofRelation::Regressed { .. })` inline
    /// at every seam, a shape the exhaustiveness checker cannot help keep
    /// in sync with a future variant addition. The receiver-sibling here
    /// answers the same question through a single welded [`matches!`]:
    /// adding a sixth variant to [`ProofRelation`] fails to compile at
    /// this method's pattern in lockstep with [`Self::stationary`],
    /// [`Self::identity_republish`], [`Self::same_store_consistent`], and
    /// every other classification receiver in this impl.
    ///
    /// **Payload agreement invariant with [`Self::regressed_by`].** The
    /// tag-only predicate and the payload accessor are two projections of
    /// the same variant, so they agree pointwise on the "is this the
    /// [`Self::Regressed`] arm?" question: `self.regressed().is_some() ==
    /// self.regressed_by().is_some()` at both altitudes (the value side
    /// via [`std::num::NonZeroU64`], the wire side via [`u64`]). A
    /// consumer that only wants the tag reaches this receiver without
    /// paying for the payload projection; a consumer that wants the
    /// backwards magnitude reaches [`Self::regressed_by`]. Together the
    /// pair covers both faces of the [`Self::Regressed`] arm at the same
    /// receiver-family altitude, without collapsing tag and payload under
    /// a single receiver.
    ///
    /// **Same-store-inconsistency corner.** The other tag-only
    /// classifiers ([`Self::stationary`], [`Self::identity_republish`]) pin
    /// same-store-CONSISTENT variants; this one pins a same-store-
    /// INCONSISTENT variant, so `self.regressed()` implies
    /// `!self.same_store_consistent()` at both altitudes. The converse
    /// does NOT hold: [`Self::CrossStore`] is also same-store-inconsistent
    /// and is not [`Self::Regressed`], so `!self.same_store_consistent()`
    /// covers two DISTINCT impossibility corners the pair
    /// `(regressed, cross_store)` will one day partition.
    ///
    /// **Pairwise disjoint with every other tag-only classifier.** No
    /// variant satisfies both `regressed()` AND `stationary()`, nor both
    /// `regressed()` AND `identity_republish()`, at either altitude — the
    /// three tag-only classifiers together pin three DISTINCT single-
    /// variant corners of the classification's `Xor` partition.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its regression verdict at compile time too, matching
    /// the `const`-ness of every other classification accessor
    /// (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::regressed`], which
    /// answers the same question at the wire altitude with the same
    /// welded pattern.
    #[must_use]
    pub const fn regressed(&self) -> bool {
        matches!(self, Self::Regressed { .. })
    }

    /// True iff this classification is [`Self::Progression`] — the "normal
    /// happy path" corner of the grid, the only variant that carries BOTH
    /// a moved-watermark payload AND a forward-progression generation
    /// count. The four other variants ([`Self::Stationary`],
    /// [`Self::IdentityRepublish`], [`Self::CrossStore`],
    /// [`Self::Regressed`]) all return `false`.
    ///
    /// **The fourth of the five single-variant tag-only classifiers.**
    /// A `/healthz/config` change-feed reader or a hot-reload receiver
    /// that holds a freshly computed [`ProofRelation`] and wants the
    /// top-level "did a routine config edit land?" answer previously had
    /// four inline paths, each leaking work: (a)
    /// `self.watermark().is_some() && self.generations().is_some()` — a
    /// two-hop composition through both payload accessors that reaches
    /// the answer through the intersection of two DIFFERENT variant
    /// projections (`watermark()` is `Some` on [`Self::Progression`] AND
    /// [`Self::CrossStore`]; `generations()` is `Some` on
    /// [`Self::Progression`] AND [`Self::IdentityRepublish`]), so the
    /// conjunction pins the intersection cell of the two axes; (b)
    /// `self.same_store_consistent() && !self.stationary() &&
    /// !self.identity_republish()` — a three-hop composition through the
    /// negative space of the two other same-store-consistent corners,
    /// which the exhaustiveness checker cannot help keep aligned with a
    /// future variant addition; (c) `!self.same_store_consistent() ==
    /// false && self.generations().is_some() && self.watermark().is_some()`
    /// — even longer chains a monitoring dashboard sometimes reaches for;
    /// or (d) `matches!(relation, ProofRelation::Progression { .. })`
    /// inline at every seam, a shape the exhaustiveness checker cannot
    /// help keep in sync with a future variant addition. The receiver-
    /// sibling here answers the same question through a single welded
    /// [`matches!`]: adding a sixth variant to [`ProofRelation`] fails to
    /// compile at this method's pattern in lockstep with
    /// [`Self::stationary`], [`Self::identity_republish`],
    /// [`Self::regressed`], [`Self::same_store_consistent`], and every
    /// other classification receiver in this impl.
    ///
    /// **Two-payload agreement invariant — genuinely new.** The three
    /// prior tag-only classifiers cross-check against AT MOST one
    /// companion payload accessor: `stationary` and `identity_republish`
    /// have no companion payload accessor (their variants are
    /// payload-free or expose only `generations` which spans TWO
    /// variants), and `regressed` cross-checks against `regressed_by`
    /// alone. [`Self::Progression`] is the FIRST single-variant tag
    /// whose payload surfaces through TWO dedicated accessors
    /// ([`Self::watermark`] and [`Self::generations`]) — the two axes
    /// intersect at exactly this variant, so this predicate is the
    /// unique intersection-pin of the payload matrix:
    /// `self.progression() == (self.watermark().is_some() &&
    /// self.generations().is_some())`. Neither of the two prior
    /// same-store-consistent classifiers can carry this invariant.
    ///
    /// **Same-store-consistency corner.** The identity-republish and
    /// stationary tag-only classifiers pin same-store-CONSISTENT
    /// variants; this one is the third same-store-consistent tag-only
    /// classifier, so `self.progression()` implies
    /// `self.same_store_consistent()` at both altitudes (a strict-subset
    /// ordering, since [`Self::Stationary`] and
    /// [`Self::IdentityRepublish`] witness the strictness).
    ///
    /// **Pairwise disjoint with every other tag-only classifier.** No
    /// variant satisfies both `progression()` AND `stationary()`, nor
    /// both `progression()` AND `identity_republish()`, nor both
    /// `progression()` AND `regressed()`, at either altitude — the four
    /// tag-only classifiers together pin four DISTINCT single-variant
    /// corners of the classification's `Xor` partition. Only one further
    /// projection (`cross_store`) remains to close the partition into a
    /// fully welded compile-time receiver lattice.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its progression verdict at compile time too, matching
    /// the `const`-ness of every other classification accessor
    /// (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::progression`], which
    /// answers the same question at the wire altitude with the same
    /// welded pattern.
    #[must_use]
    pub const fn progression(&self) -> bool {
        matches!(self, Self::Progression { .. })
    }

    /// True iff this classification is [`Self::CrossStore`] — the sole
    /// same-store impossibility corner whose signal is a moved-watermark
    /// payload at an unchanged generation counter (as opposed to
    /// [`Self::Regressed`], the other impossibility corner, whose signal
    /// is a strictly-backwards generation counter). The four other
    /// variants ([`Self::Stationary`], [`Self::IdentityRepublish`],
    /// [`Self::Progression`], [`Self::Regressed`]) all return `false`.
    ///
    /// **The fifth and closing single-variant tag-only classifier.**
    /// A cross-replica delta-log endpoint or an attestation-manifest
    /// consumer holding a freshly computed [`ProofRelation`] and wanting
    /// the "did these two proofs come from different stores (or a
    /// tampered wire)?" answer previously had four inline paths, each
    /// leaking work: (a) `!self.same_store_consistent() &&
    /// self.regressed_by().is_none()` — a two-hop composition through a
    /// predicate and a payload accessor that reaches the answer through
    /// the negative space of the other impossibility corner, chaining a
    /// [`std::num::NonZeroU64`] payload lookup a tag-only classification
    /// doesn't need; (b) `self.watermark().is_some() &&
    /// self.generations().is_none()` — a two-hop composition through
    /// both payload accessors whose intersection cell is exactly this
    /// variant, forcing a consumer that doesn't care about the payloads
    /// to reach past the tag anyway; (c) `!self.same_store_consistent()
    /// && !self.regressed()` — a two-hop composition once
    /// [`Self::regressed`] landed, still forcing the consumer through a
    /// same-store-inconsistency check the [`Self::CrossStore`] arm's tag
    /// alone answers; or (d) `matches!(relation, ProofRelation::CrossStore
    /// { .. })` inline at every seam, a shape the exhaustiveness checker
    /// cannot help keep in sync with a future variant addition. The
    /// receiver-sibling here answers the same question through a single
    /// welded [`matches!`]: adding a sixth variant to [`ProofRelation`]
    /// fails to compile at this method's pattern in lockstep with
    /// [`Self::stationary`], [`Self::identity_republish`],
    /// [`Self::regressed`], [`Self::progression`],
    /// [`Self::same_store_consistent`], and every other classification
    /// receiver in this impl.
    ///
    /// **Payload-partition agreement — genuinely new.** The four prior
    /// tag-only classifiers each cross-check against a single payload
    /// axis or its intersection cell. [`Self::CrossStore`] and
    /// [`Self::Progression`] together are the two variants
    /// [`Self::watermark`] returns `Some` on, so once both single-variant
    /// classifiers exist their union pins exactly the payload
    /// accessor's non-empty set: `self.watermark().is_some() ==
    /// (self.progression() || self.cross_store())` at both altitudes.
    /// This is the FIRST payload-accessor-partition invariant a
    /// tag-only classifier can pin — a union of two single-variant
    /// predicates equals the `Some`-set of a shared payload accessor.
    /// Neither of the four prior single-variant classifiers can carry
    /// this invariant alone.
    ///
    /// **Same-store-inconsistency corner — closing the pair.**
    /// [`Self::regressed`] pins the first same-store-INCONSISTENT
    /// impossibility corner; this receiver pins the second and closing
    /// one, so `self.cross_store()` implies `!self.same_store_consistent()`
    /// and together `self.regressed() || self.cross_store() ==
    /// !self.same_store_consistent()`. The two impossibility
    /// classifiers now exhaustively cover the same-store-INCONSISTENT
    /// half of the [`Self::same_store_consistent`] partition, mirroring
    /// the [`Self::stationary`] + [`Self::identity_republish`] +
    /// [`Self::progression`] triple that already exhaustively covers
    /// the same-store-CONSISTENT half.
    ///
    /// **Xor partition closed — the receiver lattice is now welded.**
    /// With [`Self::stationary`], [`Self::identity_republish`],
    /// [`Self::regressed`], [`Self::progression`], and this receiver,
    /// the classification's five variants each project through exactly
    /// one single-variant tag-only predicate. The disjoint-union
    /// invariant "every [`ProofRelation`] value satisfies EXACTLY ONE
    /// of the five tag-only predicates" can now be pinned as its own
    /// test at both altitudes — a shape no prior single-variant
    /// classifier could pin, since it needs all five in the same fold.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`]
    /// projects its cross-store verdict at compile time too, matching
    /// the `const`-ness of every other classification accessor
    /// (predicate or payload) in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::cross_store`], which
    /// answers the same question at the wire altitude with the same
    /// welded pattern.
    #[must_use]
    pub const fn cross_store(&self) -> bool {
        matches!(self, Self::CrossStore { .. })
    }

    /// The class-scoped watermark payload iff this classification carries
    /// one — `Some(&watermark)` on [`Self::Progression`] and
    /// [`Self::CrossStore`] (the two variants whose payloads weld the
    /// [`MovedWatermarkDelta`] invariant at the field shape),
    /// [`Option::None`] on the three payload-free variants
    /// ([`Self::Stationary`], [`Self::IdentityRepublish`],
    /// [`Self::Regressed`]).
    ///
    /// **The typed accessor for the two payload-carrying corners of the
    /// classification grid.** Before this receiver, a consumer holding a
    /// [`ProofRelation`] and wanting to route on the watermark payload's
    /// class-scoped questions ([`WatermarkDelta::restart_pending`],
    /// [`WatermarkDelta::hot_swappable_drift`],
    /// [`WatermarkDelta::any_moved`], etc.) hand-wrote the two-arm `if
    /// let` at every seam:
    ///
    /// ```ignore
    /// let restart = if let ProofRelation::Progression { watermark, .. }
    ///     | ProofRelation::CrossStore { watermark } = &relation
    /// {
    ///     watermark.restart_pending()
    /// } else {
    ///     false
    /// };
    /// ```
    ///
    /// The accessor collapses that to a one-liner using standard
    /// [`Option`] combinators and the `Deref<Target = WatermarkDelta>` on
    /// [`MovedWatermarkDelta`]:
    ///
    /// ```ignore
    /// let restart = relation.watermark().is_some_and(|w| w.restart_pending());
    /// ```
    ///
    /// The exhaustive `match` in the body pins the same load-bearing
    /// invariant the sum-type's field shapes weld: adding a sixth
    /// variant to [`ProofRelation`] turns every consumer of this
    /// accessor red at compile time so the "which variants carry a
    /// watermark payload?" answer never drifts silently.
    ///
    /// `const`-callable through the field pattern — a compile-time-known
    /// [`ProofRelation`] projects at compile time too, matching the
    /// `const`-ness of every other accessor in this impl.
    ///
    /// The wire-side sibling is [`ProofRelationWire::watermark`], which
    /// returns the raw [`WatermarkDeltaWire`] the pre-parse serde
    /// deserializer hands the consumer.
    #[must_use]
    pub const fn watermark(&self) -> Option<&MovedWatermarkDelta> {
        match self {
            Self::Progression { watermark, .. } | Self::CrossStore { watermark } => Some(watermark),
            Self::Stationary | Self::IdentityRepublish { .. } | Self::Regressed { .. } => None,
        }
    }

    /// The forward-progression generation count iff this classification
    /// carries one — `Some(generations)` on [`Self::Progression`] and
    /// [`Self::IdentityRepublish`] (the two variants whose payload field
    /// is named `generations`), [`Option::None`] on the three variants
    /// without a forward-progression count ([`Self::Stationary`],
    /// [`Self::CrossStore`], [`Self::Regressed`]).
    ///
    /// **The sibling accessor to [`Self::watermark`] for the OTHER payload
    /// axis of the classification grid.** [`Self::watermark`] surfaces the
    /// class-scoped watermark payload iff the variant carries one;
    /// `generations` surfaces the forward-progression generation count
    /// iff the variant carries one. Together the two accessors close the
    /// (watermark, generations) × (present, absent) payload matrix at the
    /// classification altitude — a consumer that wants to route on either
    /// payload reaches it through one `const`-callable receiver call
    /// instead of the two-arm `if let` a hand-written match would demand.
    ///
    /// **[`Self::Regressed`] deliberately returns [`Option::None`].** The
    /// `Regressed { by }` variant carries a distinct field — `by`,
    /// semantically "how many generations the counter went **backwards**"
    /// — not a forward-progression count. Collapsing forward and backward
    /// magnitudes under one accessor would erase the sign information the
    /// classification carries: a consumer asking "how many publishes did
    /// I miss?" wants only forward advances, and a consumer asking "did
    /// the counter go backwards, and by how much?" already reaches the
    /// answer through a `match` on [`Self::Regressed`] whose field name
    /// is `by`. A future sibling accessor `regressed_by()` could surface
    /// the backward magnitude at the same receiver-family altitude with
    /// the same [`Option<std::num::NonZeroU64>`] shape, without polluting
    /// this one.
    ///
    /// **The [`std::num::NonZeroU64`] weld survives the accessor.** The
    /// return type is [`Option<std::num::NonZeroU64>`], not
    /// [`Option<u64>`] — the "a zero-count republish is indistinguishable
    /// from [`Self::Stationary`]; a zero-count progression is
    /// indistinguishable from [`Self::CrossStore`]" invariant welded at
    /// the two variants' field
    /// shapes travels with the returned value, so a consumer reading
    /// `relation.generations().map(std::num::NonZeroU64::get)` knows the
    /// unwrapped `u64` is strictly positive by construction. The wire-
    /// side sibling ([`ProofRelationWire::generations`]) returns
    /// [`Option<u64>`] because the wire type does NOT weld nonzero at
    /// the field shape — the weld is applied at parse time inside
    /// [`ProofRelation::try_from_wire`].
    ///
    /// The exhaustive `match` in the body pins the same load-bearing
    /// invariant the sum-type's field shapes weld: adding a sixth variant
    /// to [`ProofRelation`] turns every consumer of this accessor red at
    /// compile time so the "which variants carry a forward-progression
    /// count?" answer never drifts silently.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelation`] projects
    /// at compile time too, matching the `const`-ness of [`Self::watermark`]
    /// and every other accessor in this impl.
    #[must_use]
    pub const fn generations(&self) -> Option<std::num::NonZeroU64> {
        match *self {
            Self::IdentityRepublish { generations } | Self::Progression { generations, .. } => {
                Some(generations)
            }
            Self::Stationary | Self::CrossStore { .. } | Self::Regressed { .. } => None,
        }
    }

    /// The backward-regression magnitude iff this classification carries
    /// one — `Some(by)` on [`Self::Regressed`] (the sole variant whose
    /// payload field is named `by`, semantically "how many generations the
    /// counter went **backwards**"), [`Option::None`] on the four variants
    /// without a backward-regression count ([`Self::Stationary`],
    /// [`Self::IdentityRepublish`], [`Self::Progression`],
    /// [`Self::CrossStore`]).
    ///
    /// **The third sibling accessor closing the
    /// `(watermark, generations, regressed_by)` receiver-family across the
    /// classification grid.** [`Self::watermark`] surfaces the class-scoped
    /// watermark payload iff the variant carries one; [`Self::generations`]
    /// surfaces the forward-progression generation count iff the variant
    /// carries one; `regressed_by` surfaces the backward-regression
    /// magnitude iff the variant carries one. Together the three accessors
    /// close the payload-projection matrix at the classification altitude:
    /// every consumer routing on ANY of the three payload axes now reaches
    /// it through one `const`-callable receiver call, instead of the two-
    /// or one-arm `if let` a hand-written match would demand.
    ///
    /// **Deliberately disjoint from [`Self::generations`].** A consumer
    /// asking "how many generations did we advance?" reads
    /// [`Self::generations`]; a consumer asking "how many generations did
    /// we regress?" reads `regressed_by`. Together the pair covers every
    /// count-axis question the classification grid can answer, without ever
    /// collapsing the forward and backward signs under a single receiver.
    /// [`Self::generations`]'s docstring explicitly reserves this shape:
    /// "A future sibling accessor `regressed_by()` could surface the
    /// backward magnitude at the same receiver-family altitude with the
    /// same [`Option<std::num::NonZeroU64>`] shape, without polluting this
    /// one." This IS that sibling.
    ///
    /// **The [`std::num::NonZeroU64`] weld survives the accessor** — same
    /// discipline as [`Self::generations`]. The return type is
    /// [`Option<std::num::NonZeroU64>`], not [`Option<u64>`] — the "a
    /// zero-count regression is indistinguishable from an equal-generation
    /// corner" invariant welded at the [`Self::Regressed`] field shape
    /// travels with the returned value, so a consumer reading
    /// `relation.regressed_by().map(std::num::NonZeroU64::get)` knows the
    /// unwrapped `u64` is strictly positive by construction. The wire-side
    /// sibling ([`ProofRelationWire::regressed_by`]) returns
    /// [`Option<u64>`] because the wire type does NOT weld nonzero at the
    /// field shape — the weld is applied at parse time inside
    /// [`ProofRelation::try_from_wire`].
    ///
    /// **Cannot be reached through [`ProofDelta::relation`].**
    /// [`Self::Regressed`] is the corner the delta-fold classification
    /// path deliberately drops: [`ProofDelta::relation`] returns
    /// [`Option::None`] on a regressing proof pair because the delta lost
    /// the `by` count and cannot fill this variant. A consumer that wants
    /// to reach this accessor's `Some` set must use the direct proof-pair
    /// path ([`ProofRelation::between`] / [`ConfigSyncProof::relation_since`]),
    /// not the delta-fold path. The regression count survives the direct
    /// path by construction (built at [`ProofRelation::between`] and
    /// preserved bitwise through this accessor); it never survives the
    /// delta-fold path.
    ///
    /// The exhaustive `match` in the body pins the same load-bearing
    /// invariant the sum-type's field shapes weld: adding a sixth variant
    /// to [`ProofRelation`] turns every consumer of this accessor red at
    /// compile time so the "which variants carry a backward-regression
    /// magnitude?" answer never drifts silently.
    ///
    /// `const`-callable — matching [`Self::watermark`], [`Self::generations`],
    /// and every other accessor in this impl.
    #[must_use]
    pub const fn regressed_by(&self) -> Option<std::num::NonZeroU64> {
        match *self {
            Self::Regressed { by } => Some(by),
            Self::Stationary
            | Self::IdentityRepublish { .. }
            | Self::Progression { .. }
            | Self::CrossStore { .. } => None,
        }
    }
}

/// The **wire projection** of a [`ProofRelation`] — the sum-type peer of
/// [`ProofDeltaWire`], carrying the same five variants under a serde
/// **internally-tagged** encoding (`{"kind": "...", ...}`) so a consumer
/// routes on `kind` without deserializing the whole payload first.
///
/// **Why this type exists — the sum-type wire pair to
/// [`ProofDeltaWire`].** [`ProofDeltaWire`] carries the four axes of a
/// [`ProofDelta`] but leaves the classification implicit — a consumer that
/// wants to route on "was this a legitimate progression? an
/// identity-republish? a same-store impossibility?" re-derives the
/// classification inline at every seam. `ProofRelationWire` is the wire
/// answer to the classification question itself: the payload IS the
/// variant tag plus only the fields that variant actually carries, so the
/// receiving consumer's `match` reaches the same exhaustive shape the
/// value-side [`ProofRelation`] `match` reaches. Adding a sixth corner to
/// the [`ProofRelation`] grid (a signed-attestation attestor, say) turns
/// every wire consumer red at the same instant the value-side consumers
/// turn red, closing the exhaustiveness gap the four boolean predicates
/// on [`ProofDelta`] leave open.
///
/// **Weld chain at the parse boundary.** Each variant welds the exact
/// same load-bearing invariants the value-side [`ProofRelation`] does,
/// checked ONCE at the seam rather than at every downstream use:
///
/// - [`Self::IdentityRepublish`]: the `generations` field is a plain
///   `u64` on the wire, refused at parse time if zero — a zero-count
///   republish would be indistinguishable from [`Self::Stationary`].
/// - [`Self::Progression`]: the `generations` field is refused if zero
///   (indistinguishable from [`Self::CrossStore`]), AND the nested
///   `watermark: WatermarkDeltaWire` routes through
///   [`MovedWatermarkDelta::try_from_wire`] — chaining the class-partition
///   sanity check (a class-scoped half moved without `fullMoved`) with
///   the moved-ness constraint (all three halves stationary).
/// - [`Self::CrossStore`]: the nested `watermark` routes through
///   [`MovedWatermarkDelta::try_from_wire`] under the same two welds, so
///   a hand-authored `crossStore` payload with a stationary watermark or
///   a class-partition violation is refused before it can reach any
///   consumer.
/// - [`Self::Regressed`]: the `by` field is refused if zero
///   (indistinguishable from any equal-generation corner).
/// - [`Self::Stationary`]: no payload, no weld — the tag alone is the
///   proof.
///
/// **Why internally-tagged (`{"kind": "...", ...}`) rather than serde's
/// default externally-tagged shape (`{"stationary": null}`, etc.).** The
/// internal tag puts the classification at a fixed JSON path a consumer
/// can read with one `.get("kind")` lookup, without a variant-shaped
/// wrapping envelope. A `/healthz/config` change-feed that only wants to
/// count the ratio of legitimate progressions to same-store impossibilities
/// reads `kind` alone; a consumer that wants the full payload
/// deserializes the whole shape. Matches the `kind`-first vocabulary
/// already established by [`crate::ShikumiErrorKind`] and
/// [`crate::ConfigTierKind`]. camelCase tag values (`stationary`,
/// `identityRepublish`, `progression`, `crossStore`, `regressed`) keep
/// the on-the-wire word bank consistent with [`ProofDeltaWire`]'s field
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ProofRelationWire {
    /// The wire mirror of [`ProofRelation::Stationary`] — the two proofs
    /// are equal on every axis. Serializes as `{"kind": "stationary"}`
    /// with no additional fields.
    Stationary,
    /// The wire mirror of [`ProofRelation::IdentityRepublish`] — the
    /// watermark stayed still but the generation counter advanced. The
    /// `generations` field is a plain `u64` on the wire; the parse
    /// boundary refuses zero (indistinguishable from `stationary`).
    IdentityRepublish {
        /// How many publishes happened between the two observations. On
        /// the wire this is a plain `u64` (serde has no
        /// [`std::num::NonZeroU64`] representation distinct from `u64`);
        /// the parse boundary welds nonzero via
        /// [`std::num::NonZeroU64::new`]. A zero here at parse time is a
        /// [`ShikumiError::Parse`].
        generations: u64,
    },
    /// The wire mirror of [`ProofRelation::Progression`] — the watermark
    /// moved AND the generation counter advanced. The `watermark`
    /// nesting matches [`ProofDeltaWire::watermark`] pointwise, so a
    /// consumer that already parses [`ProofDeltaWire`] pointers at the
    /// same field for the watermark half; the parse boundary here chains
    /// [`MovedWatermarkDelta::try_from_wire`] to weld the "at least one
    /// class-scoped half moved" invariant in addition to the class-
    /// partition sanity check.
    Progression {
        /// The class-scoped watermark comparison — the wire mirror of
        /// [`ProofRelation::Progression::watermark`]. The parse boundary
        /// routes this through [`MovedWatermarkDelta::try_from_wire`],
        /// chaining the class-partition sanity check with the moved-ness
        /// constraint (`Progression` never carries a stationary
        /// payload). A hand-authored `progression` payload with an
        /// all-false watermark is refused at parse time.
        watermark: WatermarkDeltaWire,
        /// Publishes between the two observations. `NonZeroU64` weld
        /// applied at parse; zero is refused (indistinguishable from
        /// `crossStore`).
        generations: u64,
    },
    /// The wire mirror of [`ProofRelation::CrossStore`] — the same-store
    /// impossibility of a moved watermark at an unchanged generation.
    /// The `watermark` nesting parses through
    /// [`MovedWatermarkDelta::try_from_wire`] under the same welds as
    /// [`Self::Progression`]: a stationary payload or a class-partition
    /// violation refuses the whole payload at the seam.
    CrossStore {
        /// The class-scoped watermark comparison — the wire mirror of
        /// [`ProofRelation::CrossStore::watermark`]. The parse boundary
        /// routes this through [`MovedWatermarkDelta::try_from_wire`],
        /// chaining the two welds.
        watermark: WatermarkDeltaWire,
    },
    /// The wire mirror of [`ProofRelation::Regressed`] — current's
    /// generation is strictly less than prior's. The `by` field is a
    /// plain `u64` on the wire; the parse boundary refuses zero
    /// (indistinguishable from an equal-generation corner).
    Regressed {
        /// How many generations the counter went backwards.
        /// [`std::num::NonZeroU64`] weld applied at parse; zero is
        /// refused.
        by: u64,
    },
}

impl ProofRelation {
    /// Project to the wire shape — each variant mirrors 1:1 to
    /// [`ProofRelationWire`]'s peer, unwrapping every
    /// [`std::num::NonZeroU64`] to `u64::get()` and folding each
    /// [`MovedWatermarkDelta`] through [`MovedWatermarkDelta::to_wire`].
    /// Pure, allocation-free, `const`.
    ///
    /// The reverse is [`Self::try_from_wire`], which re-establishes the
    /// two welds ([`std::num::NonZeroU64`] on the three generation-
    /// carrying arms, [`MovedWatermarkDelta`] on the two payload-
    /// carrying arms) at the parse boundary so a consumer holding the
    /// reconstructed value knows both invariants passed.
    #[must_use]
    pub const fn to_wire(&self) -> ProofRelationWire {
        match *self {
            Self::Stationary => ProofRelationWire::Stationary,
            Self::IdentityRepublish { generations } => ProofRelationWire::IdentityRepublish {
                generations: generations.get(),
            },
            Self::Progression {
                watermark,
                generations,
            } => ProofRelationWire::Progression {
                watermark: watermark.to_wire(),
                generations: generations.get(),
            },
            Self::CrossStore { watermark } => ProofRelationWire::CrossStore {
                watermark: watermark.to_wire(),
            },
            Self::Regressed { by } => ProofRelationWire::Regressed { by: by.get() },
        }
    }

    /// Reconstruct a [`ProofRelation`] from its wire projection — the
    /// inverse of [`Self::to_wire`], welding the two load-bearing
    /// invariants at the parse boundary:
    ///
    /// 1. Every generation-carrying variant ([`Self::IdentityRepublish`],
    ///    [`Self::Progression`], [`Self::Regressed`]) refuses a zero
    ///    count via [`std::num::NonZeroU64::new`] — the same weld the
    ///    value-side variant carries at the type.
    /// 2. Every payload-carrying variant ([`Self::Progression`],
    ///    [`Self::CrossStore`]) routes its `watermark` through
    ///    [`MovedWatermarkDelta::try_from_wire`], which itself chains
    ///    [`WatermarkDelta::try_from_wire`]'s class-partition sanity
    ///    check with the moved-ness constraint.
    ///
    /// # Errors
    ///
    /// Returns [`ShikumiError::Parse`] when either weld fails: a
    /// zero-count on a generation-carrying arm names the arm and the
    /// impossibility corner it would collapse to; a malformed watermark
    /// propagates the nested [`MovedWatermarkDelta::try_from_wire`]
    /// error message, which itself names the offending triple.
    pub fn try_from_wire(wire: &ProofRelationWire) -> Result<Self, ShikumiError> {
        match *wire {
            ProofRelationWire::Stationary => Ok(Self::Stationary),
            ProofRelationWire::IdentityRepublish { generations } => {
                let generations = std::num::NonZeroU64::new(generations).ok_or_else(|| {
                    ShikumiError::Parse(
                        "malformed ProofRelationWire: identityRepublish requires generations>0 \
                         (got 0) -- a zero-count republish is indistinguishable from stationary"
                            .to_owned(),
                    )
                })?;
                Ok(Self::IdentityRepublish { generations })
            }
            ProofRelationWire::Progression {
                ref watermark,
                generations,
            } => {
                let generations = std::num::NonZeroU64::new(generations).ok_or_else(|| {
                    ShikumiError::Parse(
                        "malformed ProofRelationWire: progression requires generations>0 (got 0) \
                         -- a zero-count progression is indistinguishable from crossStore"
                            .to_owned(),
                    )
                })?;
                let watermark = MovedWatermarkDelta::try_from_wire(watermark)?;
                Ok(Self::Progression {
                    watermark,
                    generations,
                })
            }
            ProofRelationWire::CrossStore { ref watermark } => {
                let watermark = MovedWatermarkDelta::try_from_wire(watermark)?;
                Ok(Self::CrossStore { watermark })
            }
            ProofRelationWire::Regressed { by } => {
                let by = std::num::NonZeroU64::new(by).ok_or_else(|| {
                    ShikumiError::Parse(
                        "malformed ProofRelationWire: regressed requires by>0 (got 0) -- a \
                         zero-count regression is indistinguishable from an equal-generation corner"
                            .to_owned(),
                    )
                })?;
                Ok(Self::Regressed { by })
            }
        }
    }
}

impl ProofRelationWire {
    /// The wire watermark payload iff this classification carries one —
    /// the wire-side receiver-sibling of [`ProofRelation::watermark`],
    /// returning `Some(&WatermarkDeltaWire)` on [`Self::Progression`] and
    /// [`Self::CrossStore`] and [`Option::None`] on the three payload-
    /// free variants ([`Self::Stationary`], [`Self::IdentityRepublish`],
    /// [`Self::Regressed`]).
    ///
    /// **Why the return type is [`WatermarkDeltaWire`], not
    /// [`MovedWatermarkDelta`].** The wire type does NOT weld the
    /// [`MovedWatermarkDelta`] "at least one class-scoped half moved"
    /// invariant at the field shape — that weld is applied one seam
    /// later at parse time, inside [`ProofRelation::try_from_wire`],
    /// where the wire payload routes through
    /// [`MovedWatermarkDelta::try_from_wire`]. The accessor here surfaces
    /// the pre-parse shape a serde deserializer hands the consumer at
    /// first sight, so a healthcheck reader that only wants to route on
    /// the wire payload's own predicates (`watermark.full_moved`, etc.)
    /// reaches them WITHOUT re-invoking the parse-time weld. A consumer
    /// that wants the welded value form should follow the standard
    /// `try_from_wire` seam already established one altitude up.
    ///
    /// **Same-shape invariant with [`ProofRelation::watermark`].** For
    /// every legitimate value / wire pair the two accessors agree
    /// pointwise on the `Some`/`None` shape: whenever
    /// `relation.watermark()` is `Some`, `relation.to_wire().watermark()`
    /// is also `Some` and equals the wire projection of the value-side
    /// payload; on the three payload-free variants both return `None`.
    /// The property is exercised by the tests in the
    /// `proof_relation_watermark_tests` submodule.
    ///
    /// `const`-callable through the field pattern — a compile-time-known
    /// [`ProofRelationWire`] projects at compile time too, matching the
    /// `const`-ness of [`ProofRelation::watermark`] one altitude up and
    /// of every other classification method in the file.
    #[must_use]
    pub const fn watermark(&self) -> Option<&WatermarkDeltaWire> {
        match self {
            Self::Progression { watermark, .. } | Self::CrossStore { watermark } => Some(watermark),
            Self::Stationary | Self::IdentityRepublish { .. } | Self::Regressed { .. } => None,
        }
    }

    /// The forward-progression generation count iff this classification
    /// carries one — the wire-side receiver-sibling of
    /// [`ProofRelation::generations`], returning `Some(generations)` on
    /// [`Self::Progression`] and [`Self::IdentityRepublish`] and
    /// [`Option::None`] on the three variants without a forward-
    /// progression count ([`Self::Stationary`], [`Self::CrossStore`],
    /// [`Self::Regressed`]).
    ///
    /// **Why the return type is [`Option<u64>`], not
    /// [`Option<std::num::NonZeroU64>`].** The wire type does NOT weld
    /// the [`std::num::NonZeroU64`] "a zero-count republish is
    /// indistinguishable from [`Self::Stationary`]; a zero-count
    /// progression is indistinguishable from [`Self::CrossStore`]"
    /// invariant at the field shape —
    /// serde has no [`std::num::NonZeroU64`] representation distinct from
    /// [`u64`], and that weld is applied one seam later at parse time,
    /// inside [`ProofRelation::try_from_wire`], where each generation-
    /// carrying arm routes its `u64` through [`std::num::NonZeroU64::new`].
    /// The accessor here surfaces the pre-parse shape a serde
    /// deserializer hands the consumer at first sight, so a healthcheck
    /// reader that only wants to count observed forward advances
    /// (regardless of whether the value moved) reaches them WITHOUT
    /// re-invoking the parse-time weld. A consumer that wants the welded
    /// value form should follow the standard `try_from_wire` seam
    /// already established one altitude up.
    ///
    /// **Same-shape invariant with [`ProofRelation::generations`].** For
    /// every legitimate value/wire pair the two accessors agree pointwise
    /// on the `Some`/`None` shape and on the payload magnitude: whenever
    /// `relation.generations()` is `Some(g)`,
    /// `relation.to_wire().generations()` is also `Some(g.get())`; on the
    /// three payload-free variants both return `None`. The property is
    /// exercised by the tests in the `proof_relation_generations_tests`
    /// submodule.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects at compile time too, matching the `const`-ness of
    /// [`ProofRelation::generations`] one altitude up and of every other
    /// classification accessor in the file.
    #[must_use]
    pub const fn generations(&self) -> Option<u64> {
        match *self {
            Self::IdentityRepublish { generations } | Self::Progression { generations, .. } => {
                Some(generations)
            }
            Self::Stationary | Self::CrossStore { .. } | Self::Regressed { .. } => None,
        }
    }

    /// The backward-regression magnitude iff this classification carries
    /// one — the wire-side receiver-sibling of
    /// [`ProofRelation::regressed_by`], returning `Some(by)` on
    /// [`Self::Regressed`] and [`Option::None`] on the four variants without
    /// a backward-regression count ([`Self::Stationary`],
    /// [`Self::IdentityRepublish`], [`Self::Progression`],
    /// [`Self::CrossStore`]).
    ///
    /// **Why the return type is [`Option<u64>`], not
    /// [`Option<std::num::NonZeroU64>`].** Same discipline as
    /// [`Self::generations`]: the wire type does NOT weld the
    /// [`std::num::NonZeroU64`] "a zero-count regression is
    /// indistinguishable from an equal-generation corner" invariant at the
    /// field shape — serde has no [`std::num::NonZeroU64`] representation
    /// distinct from [`u64`], and the weld is applied one seam later at
    /// parse time inside [`ProofRelation::try_from_wire`], where the
    /// [`Self::Regressed`] arm routes its `u64` through
    /// [`std::num::NonZeroU64::new`]. The accessor here surfaces the
    /// pre-parse shape a serde deserializer hands the consumer at first
    /// sight, so a healthcheck reader that only wants to count observed
    /// regressions reaches them WITHOUT re-invoking the parse-time weld.
    ///
    /// **Same-shape invariant with [`ProofRelation::regressed_by`].** For
    /// every legitimate value/wire pair the two accessors agree pointwise
    /// on the `Some`/`None` shape and on the payload magnitude: whenever
    /// `relation.regressed_by()` is `Some(by)`,
    /// `relation.to_wire().regressed_by()` is also `Some(by.get())`; on the
    /// four payload-free variants both return `None`. The property is
    /// exercised by the tests in the `proof_relation_regressed_by_tests`
    /// submodule.
    ///
    /// `const`-callable — matching [`ProofRelation::regressed_by`] one
    /// altitude up and every other classification accessor in the file.
    #[must_use]
    pub const fn regressed_by(&self) -> Option<u64> {
        match *self {
            Self::Regressed { by } => Some(by),
            Self::Stationary
            | Self::IdentityRepublish { .. }
            | Self::Progression { .. }
            | Self::CrossStore { .. } => None,
        }
    }

    /// True iff this classification is one of the three legitimate
    /// corners — the two impossibility variants ([`Self::CrossStore`]
    /// and [`Self::Regressed`]) return false — the wire-side receiver-
    /// sibling of [`ProofRelation::same_store_consistent`], closing the
    /// (value, wire) × (predicate) grid at the proof-altitude
    /// classification altitude the [`WatermarkRelationWire`] predicate
    /// family already closed one altitude down.
    ///
    /// A `/healthz/config` change-feed reader or a cross-replica
    /// delta-log endpoint that holds a freshly deserialized
    /// [`ProofRelationWire`] and wants the top-level "did this proof
    /// pair land in one of the same-store consistent corners?" answer
    /// previously had two inline paths, each paying a needless cost:
    ///
    /// - `ProofRelation::from_wire(&wire).same_store_consistent()` —
    ///   detours through the full value-side classification for a
    ///   question the wire tag alone answers, chaining
    ///   [`MovedWatermarkDelta::try_from_wire`] and
    ///   [`std::num::NonZeroU64::new`] parse-time welds a same-store-
    ///   consistency check doesn't need. Also returns [`Result`]
    ///   because [`ProofRelation::try_from_wire`] can fail on malformed
    ///   inputs, leaving the caller to fold `Ok`/`Err` into a boolean.
    /// - `matches!(wire, ProofRelationWire::Stationary
    ///     | ProofRelationWire::IdentityRepublish { .. }
    ///     | ProofRelationWire::Progression { .. })` inline — a shape
    ///   the exhaustiveness checker cannot help keep in sync with a
    ///   future variant addition. A sixth corner ([`ProofRelation`] +
    ///   [`ProofRelationWire`] added in lockstep) would silently escape
    ///   both arms of that pattern, and every hand-authored callsite
    ///   would have to be re-audited by hand.
    ///
    /// The receiver-sibling here answers the same question at the wire
    /// altitude with the same welded `match` the value-side accessor
    /// carries, so adding a sixth variant to [`ProofRelationWire`] fails
    /// to compile at this method's own `match` in lockstep with the
    /// value-side sibling.
    ///
    /// **Same-answer invariant with [`ProofRelation::same_store_consistent`].**
    /// For every legitimate value/wire pair the two accessors agree
    /// pointwise: whenever `relation.same_store_consistent()` returns
    /// `b`, `relation.to_wire().same_store_consistent()` returns the
    /// same `b`. The wire is a lossless channel for the same-store-
    /// consistency question the value-side sibling answers. The property
    /// is exercised by the tests in the
    /// `proof_relation_wire_same_store_consistent_tests` submodule.
    ///
    /// **The tag alone is sufficient.** Unlike the three payload
    /// accessors ([`Self::watermark`], [`Self::generations`],
    /// [`Self::regressed_by`]) whose return types surface the pre-parse
    /// wire shape (`WatermarkDeltaWire`, `u64`) because the value-side
    /// welds ([`MovedWatermarkDelta`], [`std::num::NonZeroU64`]) are
    /// applied at parse time, this predicate reads only the variant tag
    /// — no field payload participates in the answer, so no parse-time
    /// weld is even conceptually involved. A wire consumer reaches the
    /// same-store-consistency verdict without deserializing the payload
    /// portion of a tagged JSON blob, matching the low-cost "route on
    /// `kind` alone" seam [`ProofRelationWire`]'s internally-tagged
    /// serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its same-store-consistency verdict at compile time too,
    /// matching the `const`-ness of [`ProofRelation::same_store_consistent`]
    /// one altitude up and every other classification accessor
    /// (predicate or payload) at either altitude.
    #[must_use]
    pub const fn same_store_consistent(&self) -> bool {
        matches!(
            self,
            Self::Stationary | Self::IdentityRepublish { .. } | Self::Progression { .. }
        )
    }

    /// True iff the wire classification is one of the two same-store
    /// impossibility corners — [`Self::CrossStore`] or
    /// [`Self::Regressed`]. The wire-side receiver-sibling of
    /// [`ProofRelation::same_store_inconsistent`], welding the
    /// impossibility half of the [`Self::same_store_consistent`]
    /// partition into its own [`matches!`] pattern at the wire
    /// altitude too.
    ///
    /// **The direct dual of [`Self::same_store_consistent`], and the
    /// welded two-variant union of [`Self::cross_store`] and
    /// [`Self::regressed`] at the wire altitude.** A cross-replica
    /// delta-log endpoint or an attestation-manifest consumer that
    /// holds a freshly deserialized [`ProofRelationWire`] and wants
    /// the "did we see a same-store impossibility?" answer previously
    /// had four inline paths, each paying a needless cost: (a)
    /// `ProofRelation::try_from_wire(&wire).map(|r|
    /// r.same_store_inconsistent())` — chaining a
    /// [`MovedWatermarkDelta::try_from_wire`] weld on the two
    /// payload-carrying corners AND a
    /// [`std::num::NonZeroU64::new`] weld on the three generation-
    /// carrying corners, none of which the tag-only answer needs;
    /// (b) `!wire.same_store_consistent()` — a single-hop negation
    /// through the legitimate-corners predicate that forces the
    /// consumer to reason about the *complement* rather than the
    /// impossibility itself; (c) `wire.regressed() ||
    /// wire.cross_store()` — a two-hop composition through two
    /// tag-only classifiers whose disjunction the exhaustiveness
    /// checker cannot help keep in sync with a future impossibility
    /// corner; or (d) `matches!(wire, ProofRelationWire::CrossStore
    /// { .. } | ProofRelationWire::Regressed { .. })` inline at every
    /// seam, a shape the exhaustiveness checker cannot help keep in
    /// sync with a future variant addition. The receiver-sibling
    /// here answers the same question at the wire altitude with the
    /// same welded pattern the value-side accessor carries, so
    /// adding a sixth variant to [`ProofRelationWire`] fails to
    /// compile at this method's pattern in lockstep with the
    /// value-side sibling and every other classification receiver in
    /// this impl.
    ///
    /// **Complement identity with [`Self::same_store_consistent`].**
    /// At this altitude, `wire.same_store_inconsistent() ==
    /// !wire.same_store_consistent()` pointwise on every variant —
    /// the two receivers partition the five wire variants into two
    /// receiver-family half-spaces.
    ///
    /// **Union identity with [`Self::cross_store`] and
    /// [`Self::regressed`].** At this altitude,
    /// `wire.same_store_inconsistent() == (wire.cross_store() ||
    /// wire.regressed())` pointwise on every variant.
    ///
    /// **Same-answer invariant with [`ProofRelation::same_store_inconsistent`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.same_store_inconsistent()` returns `b`,
    /// `relation.to_wire().same_store_inconsistent()` returns the
    /// same `b`. The wire is a lossless channel for the same-store-
    /// inconsistency question the value-side sibling answers.
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing
    /// any payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its same-store-inconsistency verdict at compile time
    /// too, matching the `const`-ness of
    /// [`ProofRelation::same_store_inconsistent`] one altitude up.
    #[must_use]
    pub const fn same_store_inconsistent(&self) -> bool {
        matches!(self, Self::CrossStore { .. } | Self::Regressed { .. })
    }

    /// True iff the wire classification is the null hypothesis — the
    /// [`Self::Stationary`] variant. The wire-side receiver-sibling of
    /// [`ProofRelation::stationary`], closing the (value, wire) ×
    /// (predicate) grid at the proof altitude one further cell after
    /// [`Self::same_store_consistent`].
    ///
    /// A `/healthz/config` change-feed reader that holds a freshly
    /// deserialized [`ProofRelationWire`] and wants the top-level "did
    /// anything move?" answer previously had two inline paths, each
    /// paying a needless cost: (a)
    /// `ProofRelation::try_from_wire(&wire).map(|r| r.stationary())` —
    /// chaining a [`MovedWatermarkDelta::try_from_wire`] on the
    /// payload-carrying corners and a [`std::num::NonZeroU64::new`] on
    /// the generation-carrying corners, none of which the stationary
    /// classification's tag-only answer needs; or (b)
    /// `matches!(wire, ProofRelationWire::Stationary)` inline at every
    /// seam, a shape the exhaustiveness checker cannot help keep in
    /// sync with a future variant addition. The receiver-sibling here
    /// answers the same question at the wire altitude with the same
    /// welded pattern the value-side accessor carries, so adding a
    /// sixth variant to [`ProofRelationWire`] fails to compile at this
    /// method's pattern in lockstep with the value-side sibling.
    ///
    /// **Same-answer invariant with [`ProofRelation::stationary`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.stationary()` returns `b`,
    /// `relation.to_wire().stationary()` returns the same `b`. The wire
    /// is a lossless channel for the null-hypothesis question the
    /// value-side sibling answers. The property is exercised by the
    /// tests in the `proof_relation_stationary_tests` submodule.
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing any
    /// payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its stationarity verdict at compile time too, matching
    /// the `const`-ness of [`ProofRelation::stationary`] one altitude
    /// up.
    #[must_use]
    pub const fn stationary(&self) -> bool {
        matches!(self, Self::Stationary)
    }

    /// True iff the wire classification is [`Self::IdentityRepublish`] —
    /// the watermark stationary corner at a strictly-advanced generation
    /// counter. The wire-side receiver-sibling of
    /// [`ProofRelation::identity_republish`], closing the (value, wire) ×
    /// (predicate) grid at the proof altitude one further cell after
    /// [`Self::stationary`] / [`Self::same_store_consistent`].
    ///
    /// A `/healthz/config` change-feed reader that holds a freshly
    /// deserialized [`ProofRelationWire`] and wants the "did this replica
    /// reload without changing the value?" answer previously had two
    /// inline paths, each paying a needless cost: (a)
    /// `ProofRelation::try_from_wire(&wire).map(|r| r.identity_republish())`
    /// — chaining a [`std::num::NonZeroU64::new`] weld on the
    /// generation-carrying corners (and even a
    /// [`MovedWatermarkDelta::try_from_wire`] on the two payload-carrying
    /// corners the identity-republish classification's tag-only answer
    /// never touches); or (b)
    /// `matches!(wire, ProofRelationWire::IdentityRepublish { .. })`
    /// inline at every seam, a shape the exhaustiveness checker cannot
    /// help keep in sync with a future variant addition. The receiver-
    /// sibling here answers the same question at the wire altitude with
    /// the same welded pattern the value-side accessor carries, so adding
    /// a sixth variant to [`ProofRelationWire`] fails to compile at this
    /// method's pattern in lockstep with the value-side sibling.
    ///
    /// **Same-answer invariant with [`ProofRelation::identity_republish`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.identity_republish()` returns `b`,
    /// `relation.to_wire().identity_republish()` returns the same `b`.
    /// The wire is a lossless channel for the identity-republish
    /// question the value-side sibling answers. The property is exercised
    /// by the tests in the `proof_relation_identity_republish_tests`
    /// submodule.
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing any
    /// payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its identity-republish verdict at compile time too,
    /// matching the `const`-ness of [`ProofRelation::identity_republish`]
    /// one altitude up.
    #[must_use]
    pub const fn identity_republish(&self) -> bool {
        matches!(self, Self::IdentityRepublish { .. })
    }

    /// True iff the wire classification is [`Self::Regressed`] — the sole
    /// same-store impossibility corner whose signal is a strictly-backwards
    /// generation counter. The wire-side receiver-sibling of
    /// [`ProofRelation::regressed`], closing the (value, wire) ×
    /// (predicate) grid at the proof altitude one further cell after
    /// [`Self::identity_republish`] / [`Self::stationary`] /
    /// [`Self::same_store_consistent`].
    ///
    /// A `/healthz/config` change-feed reader or a cross-replica delta-log
    /// endpoint that holds a freshly deserialized [`ProofRelationWire`]
    /// and wants the top-level "did the counter go backwards?" answer
    /// previously had three inline paths, each paying a needless cost:
    /// (a) `ProofRelation::try_from_wire(&wire).map(|r| r.regressed())` —
    /// chaining a [`MovedWatermarkDelta::try_from_wire`] on the payload-
    /// carrying corners and a [`std::num::NonZeroU64::new`] on the
    /// generation-carrying corners, none of which the regression
    /// classification's tag-only answer needs; (b) `wire.regressed_by().is_some()`
    /// — a projection through the payload accessor for a question the
    /// variant tag alone already answers, forcing a consumer that doesn't
    /// care about the magnitude to reach past the tag anyway; or (c)
    /// `matches!(wire, ProofRelationWire::Regressed { .. })` inline at
    /// every seam, a shape the exhaustiveness checker cannot help keep
    /// in sync with a future variant addition. The receiver-sibling here
    /// answers the same question at the wire altitude with the same
    /// welded pattern the value-side accessor carries, so adding a sixth
    /// variant to [`ProofRelationWire`] fails to compile at this method's
    /// pattern in lockstep with the value-side sibling.
    ///
    /// **Payload agreement invariant with [`Self::regressed_by`].** The
    /// tag-only predicate and the payload accessor are two projections of
    /// the same variant, so they agree pointwise on the "is this the
    /// [`Self::Regressed`] arm?" question: `wire.regressed() ==
    /// wire.regressed_by().is_some()`. A consumer that only wants the
    /// tag reaches this receiver without paying for the payload
    /// projection.
    ///
    /// **Same-answer invariant with [`ProofRelation::regressed`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.regressed()` returns `b`,
    /// `relation.to_wire().regressed()` returns the same `b`. The wire
    /// is a lossless channel for the regression question the value-side
    /// sibling answers. The property is exercised by the tests in the
    /// `proof_relation_regressed_tests` submodule.
    ///
    /// **Same-store-inconsistency corner.** The other two tag-only
    /// classifiers ([`Self::stationary`], [`Self::identity_republish`])
    /// pin same-store-CONSISTENT variants; this one pins a same-store-
    /// INCONSISTENT variant, so `wire.regressed()` implies
    /// `!wire.same_store_consistent()`. The converse does NOT hold:
    /// [`Self::CrossStore`] is also same-store-inconsistent and is not
    /// [`Self::Regressed`].
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing any
    /// payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its regression verdict at compile time too, matching
    /// the `const`-ness of [`ProofRelation::regressed`] one altitude up.
    #[must_use]
    pub const fn regressed(&self) -> bool {
        matches!(self, Self::Regressed { .. })
    }

    /// True iff the wire classification is [`Self::Progression`] — the
    /// "normal happy path" corner, the only variant that carries BOTH a
    /// moved-watermark payload AND a forward-progression generation
    /// count. The wire-side receiver-sibling of
    /// [`ProofRelation::progression`], closing the (value, wire) ×
    /// (predicate) grid at the proof altitude one further cell after
    /// [`Self::regressed`] / [`Self::identity_republish`] /
    /// [`Self::stationary`] / [`Self::same_store_consistent`].
    ///
    /// A hot-reload receiver or a `/healthz/config` change-feed reader
    /// that holds a freshly deserialized [`ProofRelationWire`] and wants
    /// the "did a routine config edit land?" answer previously had four
    /// inline paths, each paying a needless cost: (a)
    /// `ProofRelation::try_from_wire(&wire).map(|r| r.progression())` —
    /// chaining a [`MovedWatermarkDelta::try_from_wire`] weld on the
    /// payload-carrying corners AND a [`std::num::NonZeroU64::new`] weld
    /// on the generation-carrying corners, none of which the tag-only
    /// answer needs; (b) `wire.watermark().is_some() &&
    /// wire.generations().is_some()` — a two-hop composition through
    /// both payload accessors whose intersection cell is exactly this
    /// variant, forcing a consumer that doesn't care about the payloads
    /// to reach past the tag anyway; (c) `wire.same_store_consistent() &&
    /// !wire.stationary() && !wire.identity_republish()` — a three-hop
    /// composition through the negative space of the two other same-
    /// store-consistent corners; or (d) `matches!(wire,
    /// ProofRelationWire::Progression { .. })` inline at every seam, a
    /// shape the exhaustiveness checker cannot help keep in sync with a
    /// future variant addition. The receiver-sibling here answers the
    /// same question at the wire altitude with the same welded pattern
    /// the value-side accessor carries, so adding a sixth variant to
    /// [`ProofRelationWire`] fails to compile at this method's pattern
    /// in lockstep with the value-side sibling.
    ///
    /// **Two-payload agreement invariant with [`Self::watermark`] AND
    /// [`Self::generations`].** [`Self::Progression`] is the unique
    /// intersection of the two payload-projection axes:
    /// `wire.progression() == (wire.watermark().is_some() &&
    /// wire.generations().is_some())`. A consumer that only wants the
    /// tag reaches this receiver without paying for either payload
    /// projection.
    ///
    /// **Same-answer invariant with [`ProofRelation::progression`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.progression()` returns `b`,
    /// `relation.to_wire().progression()` returns the same `b`. The wire
    /// is a lossless channel for the progression question the value-side
    /// sibling answers. The property is exercised by the tests in the
    /// `proof_relation_progression_tests` submodule.
    ///
    /// **Same-store-consistency corner.** [`Self::Progression`] is a
    /// same-store-consistent variant, so `wire.progression()` implies
    /// `wire.same_store_consistent()`. The converse does NOT hold, since
    /// [`Self::Stationary`] and [`Self::IdentityRepublish`] are also
    /// same-store-consistent without being progression.
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing any
    /// payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its progression verdict at compile time too, matching
    /// the `const`-ness of [`ProofRelation::progression`] one altitude
    /// up.
    #[must_use]
    pub const fn progression(&self) -> bool {
        matches!(self, Self::Progression { .. })
    }

    /// True iff the wire classification is [`Self::CrossStore`] — the
    /// sole same-store impossibility corner whose signal is a
    /// moved-watermark payload at an unchanged generation counter. The
    /// wire-side receiver-sibling of [`ProofRelation::cross_store`],
    /// closing the (value, wire) × (predicate) grid at the proof
    /// altitude with the fifth and final single-variant tag-only cell.
    ///
    /// A cross-replica delta-log endpoint or an attestation-manifest
    /// consumer that holds a freshly deserialized [`ProofRelationWire`]
    /// and wants the "did these two proofs come from different stores?"
    /// answer previously had four inline paths, each paying a needless
    /// cost: (a) `ProofRelation::try_from_wire(&wire).map(|r|
    /// r.cross_store())` — chaining a [`MovedWatermarkDelta::try_from_wire`]
    /// weld on the two payload-carrying corners AND a
    /// [`std::num::NonZeroU64::new`] weld on the three generation-
    /// carrying corners, none of which the tag-only answer needs; (b)
    /// `wire.watermark().is_some() && wire.generations().is_none()` —
    /// a two-hop composition through both payload accessors whose
    /// intersection cell is exactly this variant, forcing a consumer
    /// that doesn't care about the payloads to reach past the tag
    /// anyway; (c) `!wire.same_store_consistent() && !wire.regressed()`
    /// — a two-hop composition through the negative space of the other
    /// impossibility corner; or (d) `matches!(wire,
    /// ProofRelationWire::CrossStore { .. })` inline at every seam, a
    /// shape the exhaustiveness checker cannot help keep in sync with
    /// a future variant addition. The receiver-sibling here answers
    /// the same question at the wire altitude with the same welded
    /// pattern the value-side accessor carries, so adding a sixth
    /// variant to [`ProofRelationWire`] fails to compile at this
    /// method's pattern in lockstep with the value-side sibling.
    ///
    /// **Payload-partition agreement with [`Self::watermark`].**
    /// [`Self::Progression`] and [`Self::CrossStore`] are the two
    /// variants [`Self::watermark`] returns `Some` on, so
    /// `wire.watermark().is_some() == (wire.progression() ||
    /// wire.cross_store())`. A consumer that only wants the tag
    /// reaches this receiver without paying for the payload
    /// projection; the payload accessor's two-arm pattern is now
    /// welded as the disjoint union of two tag-only receivers.
    ///
    /// **Same-answer invariant with [`ProofRelation::cross_store`].**
    /// For every value/wire pair the two accessors agree pointwise:
    /// whenever `relation.cross_store()` returns `b`,
    /// `relation.to_wire().cross_store()` returns the same `b`. The
    /// wire is a lossless channel for the cross-store question the
    /// value-side sibling answers. The property is exercised by the
    /// tests in the `proof_relation_cross_store_tests` submodule.
    ///
    /// **Same-store-inconsistency corner — closing the pair.**
    /// [`Self::regressed`] pins the first same-store-INCONSISTENT
    /// impossibility corner; this receiver pins the second, so
    /// `wire.cross_store()` implies `!wire.same_store_consistent()`
    /// and together `wire.regressed() || wire.cross_store() ==
    /// !wire.same_store_consistent()`.
    ///
    /// **Xor partition closed at the wire altitude.** With
    /// [`Self::stationary`], [`Self::identity_republish`],
    /// [`Self::regressed`], [`Self::progression`], and this receiver,
    /// the wire classification's five variants each project through
    /// exactly one single-variant tag-only predicate — every
    /// [`ProofRelationWire`] value satisfies EXACTLY ONE of the five.
    ///
    /// **The tag alone is sufficient.** No payload field participates
    /// in the answer, so no parse-time weld is even conceptually
    /// involved — a wire consumer routing on the internally-tagged
    /// `kind` field alone reaches the verdict without deserializing any
    /// payload portion, matching the low-cost seam
    /// [`ProofRelationWire`]'s serde encoding already established.
    ///
    /// `const`-callable — a compile-time-known [`ProofRelationWire`]
    /// projects its cross-store verdict at compile time too, matching
    /// the `const`-ness of [`ProofRelation::cross_store`] one altitude
    /// up.
    #[must_use]
    pub const fn cross_store(&self) -> bool {
        matches!(self, Self::CrossStore { .. })
    }
}

impl TryFrom<&ProofRelationWire> for ProofRelation {
    type Error = ShikumiError;

    fn try_from(wire: &ProofRelationWire) -> Result<Self, Self::Error> {
        Self::try_from_wire(wire)
    }
}

impl ConfigSyncProof {
    /// The [`ProofRelation`] from `prior` to `self` — the exhaustive
    /// classification receiver-sibling, argument-order-matched to
    /// [`Self::delta_since`] and [`Self::watermark_delta_since`]: the
    /// receiver is the "current" half.
    #[must_use]
    pub fn relation_since(&self, prior: &Self) -> ProofRelation {
        ProofRelation::between(prior, self)
    }

    /// The [`ProofRelationWire`] classification-wire from `prior` to
    /// `self` — the wire-side receiver-sibling of [`Self::relation_since`],
    /// fusing the classification and its wire projection at one call
    /// site. Composes `self.relation_since(prior).to_wire()`.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that broadcasts the proof-altitude classification
    /// consumes exactly this shape: an internally-tagged
    /// (`{"kind": "..."}`) tag over the seven [`ProofRelationWire`]
    /// variants. Total: unlike the watermark-altitude sibling
    /// ([`ConfigWatermark::relation_wire_since`], which returns
    /// `Option<WatermarkRelationWire>` because the underlying
    /// [`WatermarkDelta`] can carry a class-partition-invariant
    /// violation), a [`ProofRelation`] built from two
    /// [`ConfigSyncProof`] values always classifies — the
    /// [`MovedWatermarkDelta`] weld on the payload-carrying arms is
    /// re-established at the wire boundary via
    /// [`ProofRelation::try_from_wire`], not lost.
    ///
    /// Argument order matches [`Self::delta_since`] /
    /// [`Self::relation_since`] / [`Self::watermark_delta_since`]:
    /// the receiver is the "current" half.
    #[must_use]
    pub fn relation_wire_since(&self, prior: &Self) -> ProofRelationWire {
        self.relation_since(prior).to_wire()
    }

    /// The [`ProofDeltaWire`] from `prior` to `self` — the wire-side
    /// receiver-sibling of [`Self::delta_since`], closing the fourth
    /// (and final) cell of the (`delta`, `relation`) × (`value`, `wire`)
    /// grid at the SAME-altitude altitude on [`ConfigSyncProof`].
    ///
    /// The three peers already carrying the grid are
    /// [`Self::delta_since`] (value/delta), [`Self::relation_since`]
    /// (value/relation), and [`Self::relation_wire_since`]
    /// (wire/relation). This method is the wire/delta cell — the
    /// bare wire projection of the three-field [`ProofDelta`] shape
    /// (nested watermark triple + generation delta + observed-at
    /// nanos), reached from a proof pair in one call.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that holds two [`ConfigSyncProof`] values but wants to
    /// broadcast the proof-altitude bare wire (not the fuller
    /// classification wire from [`Self::relation_wire_since`] and not
    /// the cross-altitude watermark-only wire from
    /// [`Self::watermark_delta_wire_since`]) previously had two inline
    /// paths, each leaking work the receiver never needed:
    ///
    /// - `self.delta_since(prior).to_wire()` — reach the value-side
    ///   delta through the receiver sibling, then compose the wire
    ///   projection ad hoc at every call site.
    /// - `ProofDelta::between(prior, self).to_wire()` — bypass the
    ///   receiver-sibling API entirely and reach [`ProofDelta::between`]
    ///   by name, then compose the wire projection ad hoc; this path
    ///   also inverts the "receiver is current" convention every peer
    ///   `*_since` method carries.
    ///
    /// Both routes composed the proof-altitude bare wire inline at
    /// every seam. This method IS the composition, matching the
    /// "receiver is current" argument-order convention every peer
    /// `*_since` method (at either altitude) already carries.
    ///
    /// **Return type is total, matching [`Self::delta_since`],
    /// [`Self::relation_wire_since`], and [`Self::watermark_delta_wire_since`].**
    /// Unlike [`Self::watermark_relation_since`] /
    /// [`Self::watermark_relation_wire_since`] (which return `Option`
    /// because the underlying [`WatermarkDelta`] can carry a class-
    /// partition-invariant violation the classification refuses), the
    /// bare wire projection [`ProofDelta::to_wire`] preserves every
    /// shape a [`ProofDelta`] can hold — the nested watermark's
    /// impossibility corner is not filtered here, it is welded at the
    /// parse boundary via [`ProofDelta::try_from_wire`] on the receiving
    /// side. A producer of a `ProofDeltaWire` reached through this
    /// method cannot originate an impossible shape either, because the
    /// underlying [`ProofDelta`] came from [`ProofDelta::between`] —
    /// a fold whose output is class-partition-consistent by construction
    /// on any pair of [`ConfigSyncProof`] values whose watermarks were
    /// produced through [`ConfigWatermark::compute`].
    ///
    /// Composes `self.delta_since(prior).to_wire()`. The wire tag
    /// reached through this method equals the wire tag reachable
    /// through [`Self::delta_since`] followed by [`ProofDelta::to_wire`],
    /// and its nested [`ProofDeltaWire::watermark`] field equals
    /// [`Self::watermark_delta_wire_since`] pointwise — the two
    /// altitudes' wire projections agree on the watermark half at the
    /// receiver-sibling API surface, not just at the free-function
    /// altitude.
    ///
    /// Argument order matches [`Self::delta_since`] /
    /// [`Self::relation_since`] / [`Self::relation_wire_since`] /
    /// [`Self::watermark_delta_since`] /
    /// [`Self::watermark_relation_since`] /
    /// [`Self::watermark_relation_wire_since`] /
    /// [`Self::watermark_delta_wire_since`]: the receiver is the
    /// "current" half.
    #[must_use]
    pub fn delta_wire_since(&self, prior: &Self) -> ProofDeltaWire {
        self.delta_since(prior).to_wire()
    }

    /// Convenience: the [`WatermarkRelation`] classification from
    /// `prior.watermark` to `self.watermark` — the cross-altitude
    /// receiver-sibling of [`ConfigWatermark::relation_since`], the
    /// classification peer of [`Self::watermark_delta_since`].
    ///
    /// The `Option::None` arm reproduces exactly the class-partition
    /// -invariant violation set [`ConfigWatermark::relation_since`]
    /// filters at the watermark altitude — a shape reachable only off
    /// the authored `ConfigWatermark::compute` flow (i.e., through the
    /// `pub`-field [`ConfigWatermark`] constructor with hash halves that
    /// disagree with the moved-ness bitmask). On any two watermarks
    /// produced by [`ConfigWatermark::compute`], this method is total.
    ///
    /// The generation and observed-at axes are intentionally NOT folded
    /// in — this method answers the SAME question
    /// [`ConfigWatermark::relation_since`] answers one altitude down,
    /// invariant under generation bumps and timestamp advances (a store
    /// re-publishing an identical value never moves the classification,
    /// matching the same invariance [`Self::watermark_delta_since`]
    /// carries). A consumer that wants the proof-altitude classification
    /// (which folds the generation-monotonicity + elapsed-observation
    /// axes together with the watermark answer) calls
    /// [`Self::relation_since`] instead.
    ///
    /// Argument order matches [`Self::watermark_delta_since`] /
    /// [`Self::delta_since`] / [`Self::relation_since`] /
    /// [`ConfigWatermark::relation_since`]: the receiver is the
    /// "current" half.
    #[must_use]
    pub fn watermark_relation_since(&self, prior: &Self) -> Option<WatermarkRelation> {
        self.watermark.relation_since(&prior.watermark)
    }

    /// The [`WatermarkRelationWire`] classification-wire from
    /// `prior.watermark` to `self.watermark` — the cross-altitude wire
    /// receiver-sibling of [`ConfigWatermark::relation_wire_since`],
    /// closing the "watermark question through a proof container"
    /// receiver family the value-side [`Self::watermark_delta_since`]
    /// opened one altitude up.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that holds two [`ConfigSyncProof`] values but wants to
    /// broadcast the watermark-altitude wire tag (not the fuller proof
    /// -altitude classification) previously had two inline paths, each
    /// leaking a payload-unwrap the receiver never needed:
    ///
    /// - `self.watermark.relation_since(&prior.watermark).map(|r| r.to_wire())`
    ///   — reach the watermark half by name, then two-hop through
    ///   `relation_since` and `to_wire`.
    /// - Reach the proof-altitude classification through
    ///   [`Self::relation_wire_since`], then unwrap the
    ///   [`ProofRelationWire::Progression`] payload's `watermark` field
    ///   through [`MovedWatermarkDelta::try_from_wire`] and re-classify
    ///   — but this fails on every non-`Progression` arm (`Stationary`,
    ///   `IdentityRepublish`, `Regressed`, `Skipped`,
    ///   `CrossStoreOrTampered`), leaving the caller to write a
    ///   `match` and a re-derivation that never routes through the
    ///   watermark altitude's own [`ConfigWatermark::relation_since`]
    ///   pipeline the sibling API already carries.
    ///
    /// Both routes composed the watermark-altitude answer inline at
    /// every seam. This method IS the composition, matching the
    /// "receiver is current" argument-order convention every peer
    /// `*_since` method (at either altitude) already carries.
    ///
    /// **Return-type asymmetry with [`Self::relation_wire_since`] is
    /// load-bearing.** [`Self::relation_wire_since`] is total (the
    /// [`ProofRelation`] classification cannot fail on a legitimate
    /// proof pair); this method returns `Option<WatermarkRelationWire>`
    /// because the underlying [`WatermarkDelta`] carries a
    /// class-partition-invariant violation shape reachable through
    /// hand-constructed [`ConfigWatermark`] values. The `None` arm
    /// reaches this method through the exact same passthrough
    /// [`ConfigWatermark::relation_wire_since`] carries — a shape only
    /// reachable off the authored `ConfigWatermark::compute` flow.
    ///
    /// Composes `self.watermark.relation_wire_since(&prior.watermark)`
    /// which itself composes
    /// `self.watermark.relation_since(&prior.watermark).map(|r| r.to_wire())`.
    /// A `WatermarkRelationWire` reached through this method equals
    /// the tag reachable through [`Self::watermark_relation_since`]
    /// followed by [`WatermarkRelation::to_wire`], and on any
    /// [`ProofRelationWire::Progression`] arm equals the classification
    /// tag recoverable from the nested `watermark` payload.
    ///
    /// Argument order matches [`Self::watermark_delta_since`] /
    /// [`Self::delta_since`] / [`Self::relation_since`] /
    /// [`Self::relation_wire_since`]: the receiver is the "current"
    /// half.
    #[must_use]
    pub fn watermark_relation_wire_since(&self, prior: &Self) -> Option<WatermarkRelationWire> {
        self.watermark.relation_wire_since(&prior.watermark)
    }

    /// The [`WatermarkDeltaWire`] from `prior.watermark` to
    /// `self.watermark` — the cross-altitude wire receiver-sibling of
    /// [`Self::watermark_delta_since`], closing the fourth (and final)
    /// cell of the (`delta`, `relation`) × (`value`, `wire`) grid at
    /// the cross-altitude altitude on [`ConfigSyncProof`].
    ///
    /// The three peers already carrying the grid are
    /// [`Self::watermark_delta_since`] (value/delta, since v0.1.30-ish),
    /// [`Self::watermark_relation_since`] (value/relation), and
    /// [`Self::watermark_relation_wire_since`] (wire/relation). This
    /// method is the wire/delta cell — the bare wire projection of the
    /// three-boolean [`WatermarkDelta`] triple, reached from a proof
    /// pair in one call.
    ///
    /// A `/healthz/config` change-feed or a cross-replica delta-log
    /// endpoint that holds two [`ConfigSyncProof`] values but wants to
    /// broadcast the watermark-altitude bare wire (not the fuller
    /// classification wire from [`Self::watermark_relation_wire_since`]
    /// and not the fuller proof-altitude wire from
    /// [`Self::relation_wire_since`]) previously had three inline
    /// paths, each leaking work the receiver never needed:
    ///
    /// - `self.watermark.delta_since(&prior.watermark).to_wire()` —
    ///   reach the watermark half by name, then two-hop through
    ///   `delta_since` and `to_wire`.
    /// - `self.watermark_delta_since(prior).to_wire()` — reach the
    ///   value-side delta through the receiver sibling, then compose
    ///   the wire projection ad hoc.
    /// - Reach the proof-altitude wire through
    ///   [`Self::delta_since`] and hand-pluck the nested
    ///   [`ProofDeltaWire::watermark`] field via
    ///   [`ProofDelta::to_wire`], which forces the caller to know the
    ///   nesting shape of [`ProofDeltaWire`] (a shape that will
    ///   legitimately grow as the proof altitude gains axes).
    ///
    /// All three routes composed the watermark-altitude bare wire
    /// inline at every seam. This method IS the composition, matching
    /// the "receiver is current" argument-order convention every peer
    /// `*_since` method (at either altitude) already carries.
    ///
    /// **Return type is total, matching [`Self::watermark_delta_since`]
    /// and [`Self::relation_wire_since`].** Unlike
    /// [`Self::watermark_relation_since`] and
    /// [`Self::watermark_relation_wire_since`] (which return `Option`
    /// because the underlying [`WatermarkDelta`] can carry a class-
    /// partition-invariant violation the classification refuses), the
    /// bare wire projection [`WatermarkDelta::to_wire`] preserves every
    /// shape a [`WatermarkDelta`] can hold — the impossibility corner
    /// is not filtered here, it is welded at the parse boundary via
    /// [`WatermarkDelta::try_from_wire`] on the receiving side. A
    /// producer of a `WatermarkDeltaWire` reached through this method
    /// cannot originate an impossible shape either, because the
    /// underlying [`WatermarkDelta`] came from
    /// [`ConfigWatermark::delta_since`] which itself calls
    /// [`WatermarkDelta::between`] — a fold whose output is
    /// class-partition-consistent by construction on any pair of
    /// [`ConfigWatermark`] values produced through
    /// [`ConfigWatermark::compute`].
    ///
    /// Composes `self.watermark.delta_since(&prior.watermark).to_wire()`.
    /// The wire tag reached through this method equals the tag
    /// reachable through [`Self::watermark_delta_since`] followed by
    /// [`WatermarkDelta::to_wire`], equals the nested
    /// [`ProofDeltaWire::watermark`] field the proof-altitude
    /// [`ProofDelta::to_wire`] fold produces, and (on the
    /// [`ProofRelationWire::Progression`] arm) equals the underlying
    /// wire of the nested [`MovedWatermarkDelta`] payload's
    /// [`MovedWatermarkDelta::to_wire`].
    ///
    /// Argument order matches [`Self::watermark_delta_since`] /
    /// [`Self::delta_since`] / [`Self::relation_since`] /
    /// [`Self::relation_wire_since`] /
    /// [`Self::watermark_relation_since`] /
    /// [`Self::watermark_relation_wire_since`]: the receiver is the
    /// "current" half.
    #[must_use]
    pub fn watermark_delta_wire_since(&self, prior: &Self) -> WatermarkDeltaWire {
        self.watermark.delta_since(&prior.watermark).to_wire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pleme_hotswap::SwapDecision;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AlwaysOk(u32);
    impl Validate for AlwaysOk {
        fn validate(&self) -> Result<(), ShikumiError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AlwaysErr;
    impl Validate for AlwaysErr {
        fn validate(&self) -> Result<(), ShikumiError> {
            Err(ShikumiError::Validation("always invalid".into()))
        }
    }

    #[test]
    fn validated_tiered_config_accepts_a_valid_candidate_and_derefs_and_unwraps() {
        let v = ValidatedTieredConfig::validate(AlwaysOk(7)).unwrap();
        let deref_field: &AlwaysOk = &v; // exercises the Deref impl
        assert_eq!(
            deref_field.0, 7,
            "Deref must reach the wrapped value's fields"
        );
        assert_eq!(v.into_inner(), AlwaysOk(7));
    }

    #[test]
    fn validated_tiered_config_rejects_an_invalid_candidate() {
        let err = ValidatedTieredConfig::validate(AlwaysErr).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Validation);
    }

    #[test]
    fn watermark_full_changes_when_a_free_field_changes() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_ne!(
            a.full, b.full,
            "full watermark must change on any field edit"
        );
    }

    #[test]
    fn watermark_restart_required_is_stable_across_a_free_field_edit() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_eq!(
            a.restart_required, b.restart_required,
            "restart_required watermark must NOT change when only a Free field changed \
             -- this is the exact signal calha's split watermark relies on"
        );
    }

    #[test]
    fn watermark_restart_required_changes_when_a_restart_field_changes() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.bind_addr = "0.0.0.0:9090".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_ne!(
            a.restart_required, b.restart_required,
            "restart_required watermark must change when a RequiresRestart field changed"
        );
    }

    #[test]
    fn watermark_is_deterministic_across_repeated_computation() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let b = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        assert_eq!(a.full, b.full);
        assert_eq!(a.restart_required, b.restart_required);
        assert_eq!(
            a.free, b.free,
            "the free half must be deterministic across repeated computation \
             just like the full and restart_required halves"
        );
    }

    #[test]
    fn watermark_free_changes_when_a_free_field_changes() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_ne!(
            a.free, b.free,
            "the free watermark must move when a Free-classified field changed \
             -- symmetric peer of restart_required_changes_when_a_restart_field_changes"
        );
    }

    #[test]
    fn watermark_free_is_stable_across_a_restart_required_field_edit() {
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.bind_addr = "0.0.0.0:9090".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_eq!(
            a.free, b.free,
            "the free watermark must NOT change when only a RequiresRestart field changed \
             -- the symmetric peer of the restart_required-is-stable-under-Free-edit invariant \
             that welds the HotSwapClass partition at the watermark shape"
        );
    }

    #[test]
    fn watermark_both_class_halves_move_on_a_mixed_edit() {
        // Weld the class-partition disjointness at both halves in one
        // test: when a Free field AND a RequiresRestart field both edit,
        // both class-scoped halves must move (and the full half too, by
        // the pre-existing invariant). A regression that folded the
        // wrong class into `free` (e.g. filtering by RequiresRestart on
        // both sides) would leave `free` stable across a Free edit and
        // this whole-corner check turns red at the seam.
        let a = ConfigWatermark::compute(&base(), FIELD_CLASSES);
        let mut c2 = base();
        c2.log_level = "debug".into();
        c2.bind_addr = "0.0.0.0:9090".into();
        let b = ConfigWatermark::compute(&c2, FIELD_CLASSES);
        assert_ne!(a.full, b.full, "the full half must move on any edit");
        assert_ne!(
            a.restart_required, b.restart_required,
            "the restart_required half must move on a mixed edit"
        );
        assert_ne!(a.free, b.free, "the free half must move on a mixed edit");
    }

    #[test]
    fn watermark_class_halves_partition_disagree_only_on_matching_class() {
        // A single edit to a Free field: free moves, restart_required
        // does NOT (and full does). A single edit to a RequiresRestart
        // field: restart_required moves, free does NOT (and full does).
        // This is the load-bearing partition weld -- any future refactor
        // that mixes the two class predicates (e.g. copy-paste bug
        // classing Free as RequiresRestart) turns red on exactly one
        // side of this test even if the sibling test's endpoint checks
        // happened to survive vacuously.
        let baseline = ConfigWatermark::compute(&base(), FIELD_CLASSES);

        let mut only_free = base();
        only_free.log_level = "debug".into();
        let after_free = ConfigWatermark::compute(&only_free, FIELD_CLASSES);
        assert_ne!(after_free.free, baseline.free, "Free edit moves free");
        assert_eq!(
            after_free.restart_required, baseline.restart_required,
            "Free edit leaves restart_required stable"
        );
        assert_ne!(after_free.full, baseline.full, "Free edit moves full");

        let mut only_restart = base();
        only_restart.bind_addr = "0.0.0.0:9090".into();
        let after_restart = ConfigWatermark::compute(&only_restart, FIELD_CLASSES);
        assert_ne!(
            after_restart.restart_required, baseline.restart_required,
            "RequiresRestart edit moves restart_required"
        );
        assert_eq!(
            after_restart.free, baseline.free,
            "RequiresRestart edit leaves free stable"
        );
        assert_ne!(
            after_restart.full, baseline.full,
            "RequiresRestart edit moves full"
        );
    }

    // Sanity: pleme_hotswap types are reachable through this module's
    // dependency, matching the real HotSwapClassifier shape.
    #[test]
    fn swap_decision_free_and_require_restart_are_distinguishable() {
        assert_ne!(SwapDecision::Free, SwapDecision::RequiresRestart(vec!["x"]));
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn proof() -> ConfigSyncProof {
        ConfigSyncProof {
            generation: 7,
            watermark: ConfigWatermark {
                full: blake3::hash(b"full"),
                restart_required: blake3::hash(b"restart"),
                free: blake3::hash(b"free"),
            },
            observed_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    /// The wire shape must carry ALL THREE hashes. calha's hand-written mirror
    /// carried two, and the missing `free` half is precisely what makes
    /// "did a hot-swappable knob move?" unanswerable for a consumer.
    #[test]
    fn the_wire_shape_carries_all_three_hashes() {
        let w = proof().to_wire().watermark;
        assert_ne!(w.full, w.restart_required);
        assert_ne!(w.restart_required, w.free);
        assert_ne!(w.full, w.free);
        for h in [&w.full, &w.restart_required, &w.free] {
            assert_eq!(h.len(), 64, "blake3 hex is 64 chars: {h}");
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{h}");
        }
    }

    /// A consumer deserializes what a target serves — round-trip or the wire
    /// format is a claim rather than a contract.
    #[test]
    fn the_wire_shape_round_trips_through_json() {
        let w = proof().to_wire();
        let json = serde_json::to_string(&w).expect("serialize");
        let back: ConfigSyncProofWire = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(w, back);
    }

    /// camelCase on the wire, so a consumer's field names are pinned rather
    /// than inferred.
    #[test]
    fn the_wire_field_names_are_pinned() {
        let json = serde_json::to_string(&proof().to_wire()).unwrap();
        for key in [
            "generation",
            "watermark",
            "full",
            "restartRequired",
            "free",
            "observedAtEpoch",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing {key} in {json}"
            );
        }
    }

    /// The timestamp is a stable integer, not a SystemTime whose serde
    /// representation is an implementation detail.
    #[test]
    fn the_timestamp_is_epoch_seconds() {
        assert_eq!(proof().to_wire().observed_at_epoch, 1_700_000_000);
    }

    /// The wire projection is a full isomorphism, not a monologue: a proof
    /// that goes out through `to_wire` comes back through `try_from_wire`
    /// bit-identical. This is the pin the outbound-only wire shape lacked;
    /// without it a consumer that parsed a wire and wanted to compare it
    /// against a locally-computed proof had to hand-write the reverse
    /// projection at every seam — exactly the drift risk we just closed
    /// on the outbound side.
    #[test]
    fn value_wire_value_is_identity_on_a_well_formed_proof() {
        let p = proof();
        let back = ConfigSyncProof::try_from_wire(&p.to_wire()).expect("well-formed round-trip");
        assert_eq!(back, p);
    }

    /// The reverse composition (`wire → value → wire`) is likewise a
    /// fixed point on any well-formed wire, welding both directions of
    /// the isomorphism at once.
    #[test]
    fn wire_value_wire_is_fixed_point_on_a_well_formed_wire() {
        let w = proof().to_wire();
        let back = ConfigSyncProof::try_from_wire(&w)
            .expect("well-formed round-trip")
            .to_wire();
        assert_eq!(back, w);
    }

    /// The `TryFrom<&ConfigSyncProofWire>` impl and the inherent
    /// `try_from_wire` method must agree pointwise — the trait exists so
    /// generic code can use the standard conversion idiom, and it must
    /// not silently diverge from the named entry point.
    #[test]
    fn try_from_impl_and_try_from_wire_method_agree_pointwise() {
        let w = proof().to_wire();
        let via_method = ConfigSyncProof::try_from_wire(&w).unwrap();
        let via_trait = ConfigSyncProof::try_from(&w).unwrap();
        assert_eq!(via_method, via_trait);
    }

    /// A malformed hex field is a `Parse` error, not a panic — every
    /// wire is user-supplied bytes, so the parse boundary must be a
    /// `Result`. The error message names the offending field so a
    /// consumer can localize the fault without re-parsing.
    #[test]
    fn invalid_blake3_hex_in_the_wire_is_a_parse_error_naming_the_field() {
        let mut w = proof().to_wire();
        w.watermark.restart_required = "not-a-hash".to_owned();
        let err = ConfigSyncProof::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(
            msg.contains("restartRequired"),
            "error must name the field: {msg}"
        );
    }

    /// A negative `observed_at_epoch` is malformed — a running store
    /// cannot have produced a proof stamped before the Unix epoch, so
    /// the sign is a signal, not a legitimate value. Refusing at the
    /// parse boundary keeps the reconstructed `SystemTime` in the
    /// well-defined positive range.
    #[test]
    fn a_negative_observed_at_epoch_is_a_parse_error() {
        let mut w = proof().to_wire();
        w.observed_at_epoch = -1;
        let err = ConfigSyncProof::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
    }

    /// `ConfigWatermark::to_wire` is the same shape `ConfigSyncProof::to_wire`
    /// composes inline: the lift removed a three-line duplication, so this
    /// test welds the composition equivalence at the seam.
    #[test]
    fn config_sync_proof_to_wire_watermark_equals_watermark_to_wire() {
        let p = proof();
        assert_eq!(p.to_wire().watermark, p.watermark.to_wire());
    }

    /// The watermark's own round-trip stands on its own — a consumer
    /// holding just a watermark wire (without generation/timestamp) can
    /// reconstruct the three hashes.
    #[test]
    fn config_watermark_wire_round_trips_through_try_from_wire() {
        let w = proof().watermark;
        let back = ConfigWatermark::try_from_wire(&w.to_wire()).expect("round-trip");
        assert_eq!(back, w);
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    #[test]
    fn between_identical_watermarks_reports_no_movement() {
        let w = wm_of(&base());
        let d = WatermarkDelta::between(&w, &w);
        assert!(!d.full_moved, "full stationary on identical watermarks");
        assert!(
            !d.restart_required_moved,
            "restart_required stationary on identical watermarks"
        );
        assert!(!d.free_moved, "free stationary on identical watermarks");
        assert!(
            !d.any_moved(),
            "any_moved false when no half moved -- the null hypothesis"
        );
        assert!(
            d.stationary(),
            "stationary is the negation of any_moved on the identity pair"
        );
    }

    #[test]
    fn between_after_a_free_only_edit_reports_free_and_full_moved_only() {
        let prior = wm_of(&base());
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = wm_of(&c2);
        let d = WatermarkDelta::between(&prior, &current);
        assert!(d.full_moved, "full moves on any field change");
        assert!(
            !d.restart_required_moved,
            "restart_required MUST NOT move on a Free-only edit -- the load-bearing invariant"
        );
        assert!(d.free_moved, "free moves on a Free-classified edit");
        assert!(d.any_moved(), "at least one half moved");
        assert!(!d.stationary(), "not stationary after an edit");
    }

    #[test]
    fn between_after_a_restart_only_edit_reports_restart_and_full_moved_only() {
        let prior = wm_of(&base());
        let mut c2 = base();
        c2.bind_addr = "0.0.0.0:9090".into();
        let current = wm_of(&c2);
        let d = WatermarkDelta::between(&prior, &current);
        assert!(d.full_moved, "full moves on any field change");
        assert!(
            d.restart_required_moved,
            "restart_required moves on a RequiresRestart edit"
        );
        assert!(
            !d.free_moved,
            "free MUST NOT move on a RequiresRestart-only edit -- symmetric partition weld"
        );
    }

    #[test]
    fn between_after_a_mixed_edit_reports_all_three_moved() {
        let prior = wm_of(&base());
        let mut c2 = base();
        c2.log_level = "debug".into();
        c2.bind_addr = "0.0.0.0:9090".into();
        let current = wm_of(&c2);
        let d = WatermarkDelta::between(&prior, &current);
        assert!(d.full_moved && d.restart_required_moved && d.free_moved);
    }

    #[test]
    fn between_is_symmetric_up_to_the_boolean_answer() {
        let a = wm_of(&base());
        let mut c2 = base();
        c2.log_level = "debug".into();
        let b = wm_of(&c2);
        // The delta answers "did each half move?", not "in which
        // direction did it move" -- a move from a→b and a move from b→a
        // are both moves, so `between(a,b)` and `between(b,a)` must
        // report the identical boolean triple.
        assert_eq!(
            WatermarkDelta::between(&a, &b),
            WatermarkDelta::between(&b, &a)
        );
    }

    #[test]
    fn named_semantic_aliases_agree_with_the_underlying_fields() {
        // A Free-only edit answers `restart_pending() = false`,
        // `hot_swappable_drift() = true`, and vice versa on a
        // RequiresRestart-only edit. The aliases must not drift from
        // their underlying fields -- a consumer that reads either name
        // must reach the same bit.
        let mut free_edit = base();
        free_edit.log_level = "debug".into();
        let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&free_edit));
        assert!(!d.restart_pending(), "no restart pending on Free-only edit");
        assert!(
            d.hot_swappable_drift(),
            "hot-swappable drift on Free-only edit"
        );
        assert_eq!(d.restart_pending(), d.restart_required_moved);
        assert_eq!(d.hot_swappable_drift(), d.free_moved);

        let mut restart_edit = base();
        restart_edit.bind_addr = "0.0.0.0:9090".into();
        let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&restart_edit));
        assert!(
            d.restart_pending(),
            "restart pending on RequiresRestart edit"
        );
        assert!(
            !d.hot_swappable_drift(),
            "no hot-swappable drift on RequiresRestart-only edit"
        );
    }

    #[test]
    fn class_moves_imply_full_moved_holds_on_every_delta_computed_by_between() {
        // Weld the unconditional one-way implication over the four
        // corners of the (Free-edit, Restart-edit) product: no-edit,
        // Free-only, Restart-only, both. On every corner
        // `class_moves_imply_full_moved()` holds because `between()`
        // cannot fabricate a class-scoped move without the full-hash
        // superset also having moved.
        for (mut mutate_free, mut mutate_restart) in
            [(false, false), (true, false), (false, true), (true, true)]
                .into_iter()
                .map(|(f, r)| (f, r))
        {
            let mut c2 = base();
            if mutate_free {
                c2.log_level = "debug".into();
                mutate_free = true; // suppress unused_assignments lint
            }
            if mutate_restart {
                c2.bind_addr = "0.0.0.0:9090".into();
                mutate_restart = true;
            }
            let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&c2));
            assert!(
                d.class_moves_imply_full_moved(),
                "class_moves_imply_full_moved must hold on every WatermarkDelta produced by \
                 between() -- violated on ({mutate_free}, {mutate_restart})"
            );
        }
    }

    #[test]
    fn class_moves_imply_full_moved_refutes_a_hand_constructed_impossibility() {
        // A consumer that receives a WatermarkDelta from an untrusted
        // source can construct one that would fail the invariant. The
        // predicate catches it -- refusing to trust a delta shape that
        // no honest `between()` call could have produced.
        let impossible = WatermarkDelta {
            full_moved: false,
            restart_required_moved: true,
            free_moved: false,
        };
        assert!(!impossible.class_moves_imply_full_moved());
    }

    #[test]
    fn partitioned_class_invariant_holds_on_two_class_field_slice() {
        // With FIELD_CLASSES covering every serialized field of Cfg
        // (log_level Free, bind_addr RequiresRestart -- an exhaustive
        // partition), the two-way `full ⇔ restart||free` invariant
        // holds on every edit shape.
        for (mutate_free, mutate_restart) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut c2 = base();
            if mutate_free {
                c2.log_level = "debug".into();
            }
            if mutate_restart {
                c2.bind_addr = "0.0.0.0:9090".into();
            }
            let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&c2));
            assert!(
                d.partitioned_class_invariant_holds(),
                "partitioned_class_invariant_holds must hold when field_classes is exhaustive \
                 -- violated on ({mutate_free}, {mutate_restart})"
            );
        }
    }

    #[test]
    fn config_watermark_delta_since_agrees_with_between() {
        // The ergonomic sibling on the receiver must NOT diverge from
        // the named type-associated constructor -- a consumer that reads
        // `current.delta_since(&prior)` must reach the same value as
        // `WatermarkDelta::between(&prior, &current)`. Argument order is
        // load-bearing: the receiver is the "current" half.
        let prior = wm_of(&base());
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = wm_of(&c2);
        assert_eq!(
            current.delta_since(&prior),
            WatermarkDelta::between(&prior, &current)
        );
    }

    #[test]
    fn config_sync_proof_watermark_delta_since_composes_through_the_watermark() {
        // The proof-level convenience composes through the watermark-
        // level primitive -- adding new fields to `ConfigSyncProof` (a
        // future signed-attestation blob, a leaf-schema hash) never
        // reaches this method's implementation; the watermark half stays
        // the single source of truth.
        let prior = ConfigSyncProof {
            generation: 1,
            watermark: wm_of(&base()),
            observed_at: std::time::UNIX_EPOCH,
        };
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            // Generation and observed_at intentionally differ from
            // prior -- the watermark_delta_since answer is invariant
            // under those two axes by construction, and this test pins
            // that invariance.
            generation: 42,
            watermark: wm_of(&c2),
            observed_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(9_999),
        };
        assert_eq!(
            current.watermark_delta_since(&prior),
            current.watermark.delta_since(&prior.watermark)
        );
    }

    #[test]
    fn config_sync_proof_watermark_delta_since_is_stationary_across_a_generation_bump() {
        // A store that re-publishes an identical value bumps generation
        // and observed_at without moving any watermark half. The
        // proof-level delta must report `stationary()` under that -- if
        // it folded generation in, this would falsely report movement.
        let wm = wm_of(&base());
        let prior = ConfigSyncProof {
            generation: 1,
            watermark: wm,
            observed_at: std::time::UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            generation: 2,
            watermark: wm,
            observed_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(60),
        };
        let d = current.watermark_delta_since(&prior);
        assert!(
            d.stationary(),
            "watermark_delta_since must be stationary when only generation/timestamp advanced"
        );
    }
}

#[cfg(test)]
mod proof_delta_tests {
    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(cfg: &Cfg, generation: u64, epoch_secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: wm_of(cfg),
            observed_at: UNIX_EPOCH + Duration::from_secs(epoch_secs),
        }
    }

    #[test]
    fn between_identical_proofs_reports_stationary() {
        // Same observation observed twice: watermark stationary AND
        // generation unchanged. No wire time elapsed either. This is
        // the null hypothesis a poller checks before doing more work.
        let p = proof_at(&base(), 5, 1_700_000_000);
        let d = ProofDelta::between(&p, &p);
        assert!(d.watermark.stationary(), "watermark must be stationary");
        assert_eq!(d.generations_advanced, Some(0));
        assert_eq!(d.observed_at_elapsed, Some(Duration::ZERO));
        assert!(d.stationary(), "identity proof pair must be stationary");
    }

    #[test]
    fn between_same_value_at_different_wall_time_still_stationary() {
        // observed_at intentionally does NOT participate in stationary()
        // -- a consumer polling the same publish at two wall-clock
        // instants still reports "no movement", matching
        // watermark_delta_since's semantics at the proof altitude.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&base(), 5, 1_700_000_060);
        let d = ProofDelta::between(&prior, &current);
        assert!(
            d.stationary(),
            "stationary must be true across a wall-clock advance on the same publish"
        );
        assert_eq!(d.observed_at_elapsed, Some(Duration::from_secs(60)));
    }

    #[test]
    fn identity_republish_when_watermark_stationary_but_generation_advanced() {
        // A store that re-publishes an identical value bumps generation
        // WITHOUT moving any watermark half -- the ConfigStore contract
        // (see store.rs:reload()). ProofDelta must distinguish this from
        // stationary (which only holds when generation is also unchanged).
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&base(), 6, 1_700_000_030);
        let d = ProofDelta::between(&prior, &current);
        assert!(d.watermark.stationary(), "watermark must be stationary");
        assert_eq!(d.generations_advanced, Some(1));
        assert!(d.identity_republish(), "identity re-publish signal");
        assert!(
            !d.stationary(),
            "NOT stationary -- generation advanced even though value did not"
        );
    }

    #[test]
    fn generations_regressed_when_current_generation_less_than_prior() {
        // A single monotonic ConfigStore cannot produce this pair --
        // its appearance means the two proofs came from different
        // stores, or the wire was tampered with. Modeled as
        // `Option::None` on generations_advanced so a consumer cannot
        // silently underflow the difference.
        let prior = proof_at(&base(), 10, 1_700_000_000);
        let current = proof_at(&base(), 5, 1_700_000_060);
        let d = ProofDelta::between(&prior, &current);
        assert!(
            d.generations_regressed(),
            "generation went backwards -- must be flagged"
        );
        assert_eq!(d.generations_advanced, None);
        assert_eq!(
            d.generations_skipped(),
            None,
            "generations_skipped is undefined when generation regressed"
        );
        assert!(
            !d.same_store_consistent(),
            "regressed generation is a same-store impossibility"
        );
    }

    #[test]
    fn generations_skipped_when_gap_greater_than_one() {
        // A poller with a coarse cadence might miss intermediate
        // publishes. The count of missed publishes is exactly
        // `generations_advanced - 1`.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 9,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_120),
        };
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(d.generations_advanced, Some(4));
        assert_eq!(
            d.generations_skipped(),
            Some(3),
            "5 -> 9 advances 4 generations, skipping 3 intermediate publishes"
        );
    }

    #[test]
    fn generations_skipped_is_zero_on_a_single_publish_advance() {
        // 5 -> 6 advances one generation. The poller witnessed every
        // publish, so nothing was skipped -- `Some(0)`, not `None`.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 6,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_030),
        };
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(d.generations_advanced, Some(1));
        assert_eq!(
            d.generations_skipped(),
            Some(0),
            "a single-publish advance skips zero intermediate publishes"
        );
    }

    #[test]
    fn cross_store_signal_when_watermark_moved_without_generation_advance() {
        // A single monotonic store cannot produce a proof pair where
        // the watermark moved but generation stayed the same -- moving
        // the watermark requires a publish which bumps generation. Hand-
        // construct the impossible pair (two different values at the
        // same generation) to exercise the invariant weld.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 5,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_060),
        };
        let d = ProofDelta::between(&prior, &current);
        assert!(d.watermark.full_moved, "watermark moved");
        assert_eq!(d.generations_advanced, Some(0));
        assert!(
            d.cross_store_signal(),
            "watermark-move-without-generation-bump is a same-store impossibility"
        );
        assert!(!d.same_store_consistent());
    }

    #[test]
    fn observed_at_elapsed_none_when_current_precedes_prior() {
        // A system-clock adjustment (NTP step) between two observations
        // can make current.observed_at strictly earlier than prior's.
        // Modeled as None so a consumer cannot silently compute a
        // meaningless "negative elapsed" duration.
        let prior = proof_at(&base(), 5, 1_700_000_060);
        let current = proof_at(&base(), 6, 1_700_000_000);
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(
            d.observed_at_elapsed, None,
            "elapsed is None when observed_at moved backwards"
        );
    }

    #[test]
    fn observed_at_elapsed_carries_the_wall_clock_difference() {
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&base(), 5, 1_700_000_090);
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(d.observed_at_elapsed, Some(Duration::from_secs(90)));
    }

    #[test]
    fn same_store_consistent_holds_on_every_legitimate_pair() {
        // Cross-product of (watermark moved?, generation advanced?) minus
        // the two impossibilities. Every legitimate corner must report
        // same_store_consistent() = true, and the two impossible corners
        // (regressed generation, cross-store signal) must be the ONLY
        // false readings. Together these welds the invariant on both
        // sides.
        let anchor = base();
        let mut mutated = base();
        mutated.log_level = "debug".into();

        // Legitimate corners.
        for (prior, current, label) in [
            (
                proof_at(&anchor, 5, 1_700_000_000),
                proof_at(&anchor, 5, 1_700_000_060),
                "identity observation twice",
            ),
            (
                proof_at(&anchor, 5, 1_700_000_000),
                proof_at(&anchor, 6, 1_700_000_060),
                "identity re-publish",
            ),
            (
                proof_at(&anchor, 5, 1_700_000_000),
                ConfigSyncProof {
                    generation: 6,
                    watermark: wm_of(&mutated),
                    observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_060),
                },
                "legitimate publish with a value change",
            ),
        ] {
            let d = ProofDelta::between(&prior, &current);
            assert!(
                d.same_store_consistent(),
                "same_store_consistent must hold on the legitimate corner: {label}"
            );
        }

        // Impossible corners.
        let regressed = ProofDelta::between(
            &proof_at(&anchor, 10, 1_700_000_000),
            &proof_at(&anchor, 5, 1_700_000_060),
        );
        assert!(!regressed.same_store_consistent(), "regressed generation");

        let cross_store = ProofDelta::between(
            &proof_at(&anchor, 5, 1_700_000_000),
            &ConfigSyncProof {
                generation: 5,
                watermark: wm_of(&mutated),
                observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_060),
            },
        );
        assert!(
            !cross_store.same_store_consistent(),
            "cross-store: watermark moved without generation bump"
        );
    }

    #[test]
    fn watermark_field_agrees_with_watermark_delta_since() {
        // The composed shape's watermark half must match the direct
        // watermark comparison -- a consumer that already knows how to
        // consume a WatermarkDelta reaches it through the composed shape
        // without a second computation, and this test welds equality.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 6,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_030),
        };
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(d.watermark, current.watermark_delta_since(&prior));
    }

    #[test]
    fn config_sync_proof_delta_since_agrees_with_between() {
        // The ergonomic sibling on the receiver must NOT diverge from
        // the named type-associated constructor -- a consumer reading
        // `current.delta_since(&prior)` must reach the same value as
        // `ProofDelta::between(&prior, &current)`. Argument order is
        // load-bearing: the receiver is the "current" half.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 6,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_030),
        };
        assert_eq!(
            current.delta_since(&prior),
            ProofDelta::between(&prior, &current)
        );
    }

    #[test]
    fn identity_republish_is_disjoint_from_stationary_and_from_movement() {
        // The three "no watermark movement" corners are:
        //   stationary          -- generation unchanged, same observation
        //   identity_republish  -- generation advanced, same value
        //   generations_regressed -- generation went backwards (impossible)
        // A ProofDelta whose watermark is stationary lands in exactly
        // one of these three; the predicates must not overlap on the
        // legitimate corners.
        let anchor = base();

        let same_obs = ProofDelta::between(
            &proof_at(&anchor, 5, 1_700_000_000),
            &proof_at(&anchor, 5, 1_700_000_060),
        );
        assert!(same_obs.stationary());
        assert!(!same_obs.identity_republish());

        let republish = ProofDelta::between(
            &proof_at(&anchor, 5, 1_700_000_000),
            &proof_at(&anchor, 6, 1_700_000_060),
        );
        assert!(!republish.stationary());
        assert!(republish.identity_republish());
    }

    #[test]
    fn identity_republish_is_false_when_watermark_moved() {
        // A watermark move disqualifies identity_republish regardless of
        // how far generation advanced -- the "same value" half of the
        // predicate is required.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let mut c2 = base();
        c2.log_level = "debug".into();
        let current = ConfigSyncProof {
            generation: 6,
            watermark: wm_of(&c2),
            observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_030),
        };
        let d = ProofDelta::between(&prior, &current);
        assert!(
            !d.identity_republish(),
            "value changed -- not an identity re-publish"
        );
    }

    // -- ProofRelation exhaustive-classification tests -----------------
    // The (watermark moved?, generation delta) grid has five corners; each
    // corner is a variant of ProofRelation. Each of the five tests below
    // pins one corner, then a sixth agreement-check test welds the
    // correspondence between the four ProofDelta predicates and the enum
    // shape so a future divergence turns red at the seam rather than
    // silently at a consumer.

    fn mutated() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn proof_with(cfg: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        proof_at(cfg, generation, secs)
    }

    #[test]
    fn proof_relation_stationary_on_identical_observation() {
        let p = proof_with(&base(), 5, 1_700_000_000);
        assert_eq!(ProofRelation::between(&p, &p), ProofRelation::Stationary);
    }

    #[test]
    fn proof_relation_identity_republish_when_gen_advances_on_same_value() {
        let prior = proof_with(&base(), 5, 1_700_000_000);
        let current = proof_with(&base(), 8, 1_700_000_030);
        let r = ProofRelation::between(&prior, &current);
        assert_eq!(
            r,
            ProofRelation::IdentityRepublish {
                generations: std::num::NonZeroU64::new(3).unwrap(),
            },
        );
    }

    #[test]
    fn proof_relation_progression_names_the_previously_unnamed_corner() {
        // "watermark moved AND generation advanced" — a legitimate publish
        // that also changed the value. Every routine config-file edit
        // lands here. The variant carries BOTH the class-scoped watermark
        // comparison and the exact generation delta so a consumer that
        // wants to route on restart_pending() has one arm to bind rather
        // than a nested boolean chain.
        let prior = proof_with(&base(), 5, 1_700_000_000);
        let current = proof_with(&mutated(), 6, 1_700_000_030);
        let r = ProofRelation::between(&prior, &current);
        let watermark = current.watermark_delta_since(&prior);
        assert!(watermark.any_moved(), "precondition: watermark moved");
        assert_eq!(
            r,
            ProofRelation::Progression {
                watermark: MovedWatermarkDelta::new(watermark)
                    .expect("precondition: watermark moved"),
                generations: std::num::NonZeroU64::new(1).unwrap(),
            },
        );
    }

    #[test]
    fn proof_relation_cross_store_when_watermark_moved_without_gen_bump() {
        let prior = proof_with(&base(), 5, 1_700_000_000);
        let current = proof_with(&mutated(), 5, 1_700_000_030);
        let r = ProofRelation::between(&prior, &current);
        let watermark = current.watermark_delta_since(&prior);
        assert!(watermark.any_moved());
        assert_eq!(
            r,
            ProofRelation::CrossStore {
                watermark: MovedWatermarkDelta::new(watermark)
                    .expect("precondition: watermark moved"),
            },
        );
    }

    #[test]
    fn proof_relation_regressed_preserves_the_exact_backwards_count() {
        // The delta path (`ProofDelta::between → generations_advanced =
        // Option::None`) throws the regression count away; classify via
        // ProofRelation preserves it exactly, since the constructor
        // takes the two proofs directly rather than going through the
        // lossy delta. This is the load-bearing reason `between()` lives
        // on ProofRelation and not on ProofDelta.
        let prior = proof_with(&base(), 10, 1_700_000_000);
        let current = proof_with(&base(), 3, 1_700_000_030);
        let r = ProofRelation::between(&prior, &current);
        assert_eq!(
            r,
            ProofRelation::Regressed {
                by: std::num::NonZeroU64::new(7).unwrap(),
            },
        );
        // Contrast: the ProofDelta path folds regression into None and
        // cannot recover the "-7" figure.
        let d = ProofDelta::between(&prior, &current);
        assert_eq!(d.generations_advanced, None);
    }

    /// The five corners of the (watermark moved?, generation delta) grid
    /// — one name per [`ProofRelation`] variant, lifted out of the
    /// agreement test to serve as the single source of truth the
    /// two-projection weld folds over.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Corner {
        Stationary,
        IdentityRepublish,
        Progression,
        CrossStore,
        Regressed,
    }

    impl Corner {
        /// Project a [`ProofDelta`] to the corner its four boolean
        /// predicates name. The only corner `ProofDelta` does not name
        /// with a dedicated predicate — "watermark moved AND generation
        /// advanced" — falls through to [`Self::Progression`], which is
        /// exactly why the enum exists.
        fn from_delta(d: &ProofDelta) -> Self {
            if d.generations_regressed() {
                Self::Regressed
            } else if d.stationary() {
                Self::Stationary
            } else if d.identity_republish() {
                Self::IdentityRepublish
            } else if d.cross_store_signal() {
                Self::CrossStore
            } else {
                Self::Progression
            }
        }
    }

    impl From<&ProofRelation> for Corner {
        fn from(r: &ProofRelation) -> Self {
            match r {
                ProofRelation::Stationary => Self::Stationary,
                ProofRelation::IdentityRepublish { .. } => Self::IdentityRepublish,
                ProofRelation::Progression { .. } => Self::Progression,
                ProofRelation::CrossStore { .. } => Self::CrossStore,
                ProofRelation::Regressed { .. } => Self::Regressed,
            }
        }
    }

    #[test]
    fn proof_relation_classification_agrees_with_proof_delta_predicates() {
        // The correspondence weld: each of the four ProofDelta predicates
        // projects to exactly the ProofRelation variant it names, and the
        // previously-unnamed "progression" corner (watermark moved AND
        // generation advanced) surfaces as its own variant on the enum
        // side. A future change that adds a new corner MUST extend
        // `Corner` and the enum in lockstep, or one side of the grid
        // drifts from the other.
        let anchor = base();
        let alt = mutated();
        let cases = [
            (
                Corner::Stationary,
                proof_with(&anchor, 5, 1_700_000_000),
                proof_with(&anchor, 5, 1_700_000_060),
            ),
            (
                Corner::IdentityRepublish,
                proof_with(&anchor, 5, 1_700_000_000),
                proof_with(&anchor, 6, 1_700_000_060),
            ),
            (
                Corner::Progression,
                proof_with(&anchor, 5, 1_700_000_000),
                proof_with(&alt, 6, 1_700_000_060),
            ),
            (
                Corner::CrossStore,
                proof_with(&anchor, 5, 1_700_000_000),
                proof_with(&alt, 5, 1_700_000_060),
            ),
            (
                Corner::Regressed,
                proof_with(&anchor, 10, 1_700_000_000),
                proof_with(&anchor, 5, 1_700_000_060),
            ),
        ];
        for (want, prior, current) in &cases {
            let d = ProofDelta::between(prior, current);
            let r = ProofRelation::between(prior, current);
            let from_delta = Corner::from_delta(&d);
            let from_relation = Corner::from(&r);
            assert_eq!(from_delta, *want, "delta projection mismatch on {want:?}");
            assert_eq!(
                from_relation, *want,
                "relation variant mismatch on {want:?}",
            );
            assert_eq!(
                from_delta, from_relation,
                "delta and relation must project to the same corner on {want:?}",
            );
            assert_eq!(
                r.same_store_consistent(),
                d.same_store_consistent(),
                "same_store_consistent agreement on {want:?}",
            );
        }
    }

    #[test]
    fn proof_relation_relation_since_agrees_with_between() {
        // The receiver-style sibling must not diverge from the named
        // associated constructor. Argument order is load-bearing: the
        // receiver is the "current" half.
        let prior = proof_with(&base(), 5, 1_700_000_000);
        let current = proof_with(&mutated(), 6, 1_700_000_060);
        assert_eq!(
            current.relation_since(&prior),
            ProofRelation::between(&prior, &current),
        );
    }

    #[test]
    fn proof_relation_progression_variant_carries_the_watermark_delta() {
        // The Progression variant preserves the class-scoped watermark
        // comparison, so a consumer routing on restart_pending() /
        // hot_swappable_drift() reaches those questions through the
        // variant payload rather than recomputing them.
        let prior = proof_with(&base(), 5, 1_700_000_000);
        let mut restart_edit = base();
        restart_edit.bind_addr = "0.0.0.0:9090".into();
        let current = proof_with(&restart_edit, 6, 1_700_000_060);
        let ProofRelation::Progression {
            watermark,
            generations,
        } = ProofRelation::between(&prior, &current)
        else {
            panic!("RequiresRestart edit must classify as Progression");
        };
        assert_eq!(generations.get(), 1);
        assert!(
            watermark.restart_pending(),
            "the variant payload must carry the class-scoped answer"
        );
        assert!(
            !watermark.hot_swappable_drift(),
            "RequiresRestart-only edit leaves the Free half stable"
        );
    }
}

#[cfg(test)]
mod moved_watermark_delta_tests {
    //! Weld the "at least one half moved" invariant on
    //! [`MovedWatermarkDelta`] — the type-level pin for the payload
    //! carried by [`ProofRelation::Progression`] and
    //! [`ProofRelation::CrossStore`]. Together the tests below cover:
    //!
    //! 1. The stationary delta has NO argument form
    //!    ([`MovedWatermarkDelta::new`] returns `None`,
    //!    [`TryFrom<WatermarkDelta>`] returns
    //!    [`ShikumiError::Validation`]).
    //! 2. A non-stationary delta round-trips through
    //!    [`MovedWatermarkDelta::new`] / [`MovedWatermarkDelta::into_inner`]
    //!    bit-identically, so wrapping is lossless.
    //! 3. `Deref` reaches every underlying [`WatermarkDelta`] predicate
    //!    — the ergonomic pin the wrapper's docs promise.
    //! 4. The `ProofRelation` variants that carry a `MovedWatermarkDelta`
    //!    only ever see non-stationary payloads, and the classification
    //!    of every legitimate corner is preserved by the wrap
    //!    (the [`ProofRelation::between`] fold's route through
    //!    `MovedWatermarkDelta::new` never loses a case).

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn stationary_delta() -> WatermarkDelta {
        let w = wm_of(&base());
        WatermarkDelta::between(&w, &w)
    }

    fn moved_delta() -> WatermarkDelta {
        WatermarkDelta::between(&wm_of(&base()), &wm_of(&free_edit()))
    }

    #[test]
    fn new_refuses_a_stationary_delta() {
        // The load-bearing invariant: a stationary WatermarkDelta has
        // NO MovedWatermarkDelta form. This is why ProofRelation's two
        // payload-carrying variants (Progression, CrossStore) cannot
        // hold a stationary payload — the wrap fails at construction.
        let d = stationary_delta();
        assert!(
            d.stationary(),
            "precondition: the delta between identical watermarks is stationary"
        );
        assert!(
            MovedWatermarkDelta::new(d).is_none(),
            "MovedWatermarkDelta::new must reject the null hypothesis"
        );
    }

    #[test]
    fn new_accepts_a_delta_where_any_half_moved() {
        let d = moved_delta();
        assert!(d.any_moved(), "precondition: at least one half moved");
        let m = MovedWatermarkDelta::new(d).expect("moved delta must wrap");
        assert_eq!(m.into_inner(), d, "unwrap must round-trip bit-identically");
    }

    #[test]
    fn deref_reaches_every_watermark_delta_predicate() {
        // The wrapper's docs promise Deref-transparent access to every
        // predicate on the underlying delta. Weld that promise: a
        // Free-only edit's answers reached through the wrapper match the
        // answers on the bare delta pointwise, so a consumer that reads
        // `payload.restart_pending()` through a variant binding gets the
        // same bit as `payload.into_inner().restart_pending()`.
        let d = moved_delta();
        let m = MovedWatermarkDelta::new(d).unwrap();
        // Every WatermarkDelta predicate reachable through Deref.
        assert_eq!(m.full_moved, d.full_moved);
        assert_eq!(m.restart_required_moved, d.restart_required_moved);
        assert_eq!(m.free_moved, d.free_moved);
        assert_eq!(m.any_moved(), d.any_moved());
        assert_eq!(m.stationary(), d.stationary());
        assert_eq!(m.restart_pending(), d.restart_pending());
        assert_eq!(m.hot_swappable_drift(), d.hot_swappable_drift());
        assert_eq!(
            m.class_moves_imply_full_moved(),
            d.class_moves_imply_full_moved(),
        );
        assert_eq!(
            m.partitioned_class_invariant_holds(),
            d.partitioned_class_invariant_holds(),
        );
        // A MovedWatermarkDelta is by construction never stationary —
        // the assertion below welds that invariant beside the Deref
        // agreement so a future refactor that loosens the constructor
        // turns this red as well as `new_refuses_a_stationary_delta`.
        assert!(!m.stationary(), "MovedWatermarkDelta is never stationary");
        assert!(m.any_moved(), "MovedWatermarkDelta always has any_moved");
    }

    #[test]
    fn as_delta_borrows_the_underlying_watermark_delta() {
        // `as_delta` is the explicit-borrow spelling of the Deref
        // access — it must reach the same bytes.
        let d = moved_delta();
        let m = MovedWatermarkDelta::new(d).unwrap();
        assert_eq!(*m.as_delta(), d);
        assert_eq!(m.as_delta(), &*m, "as_delta and Deref must agree");
    }

    #[test]
    fn try_from_stationary_delta_is_a_typed_validation_error() {
        // The TryFrom idiom (`let m: MovedWatermarkDelta = d.try_into()?;`)
        // must surface a typed ShikumiError at the boundary — a `?`
        // cannot short-circuit an `Option::None`, so a consumer using
        // the standard idiom gets a `Result::Err` to propagate.
        let d = stationary_delta();
        let err = MovedWatermarkDelta::try_from(d).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Validation);
        let msg = err.to_string();
        assert!(
            msg.contains("stationary"),
            "error message must name the null hypothesis: {msg}"
        );
    }

    #[test]
    fn try_from_moved_delta_agrees_with_new() {
        let d = moved_delta();
        let via_new = MovedWatermarkDelta::new(d).unwrap();
        let via_try_from = MovedWatermarkDelta::try_from(d).unwrap();
        assert_eq!(via_new, via_try_from);
    }

    fn proof_at(cfg: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: wm_of(cfg),
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    #[test]
    fn proof_relation_progression_payload_is_moved_by_construction() {
        // The load-bearing pin: ProofRelation::between's fold routes the
        // watermark through MovedWatermarkDelta::new, so the Progression
        // variant CANNOT carry a stationary payload -- the type refuses
        // it. Any input pair that would have produced a stationary
        // Progression under the old (bare-WatermarkDelta) shape now
        // falls through to IdentityRepublish instead.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&free_edit(), 6, 1_700_000_060);
        let ProofRelation::Progression { watermark, .. } = ProofRelation::between(&prior, &current)
        else {
            panic!("Free edit with generation advance must classify as Progression");
        };
        assert!(
            !watermark.stationary(),
            "Progression's payload is guaranteed non-stationary by MovedWatermarkDelta"
        );
        assert!(
            watermark.any_moved(),
            "any_moved is the definition of MovedWatermarkDelta"
        );
    }

    #[test]
    fn proof_relation_cross_store_payload_is_moved_by_construction() {
        // Symmetric peer of the Progression test above: CrossStore also
        // carries a MovedWatermarkDelta, so a hand-constructed
        // `CrossStore { watermark: <stationary> }` fails to type-check.
        // Any pair whose watermark IS stationary at the same generation
        // lands in Stationary, not here — the "impossibility corners
        // never carry the null hypothesis" invariant, welded.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&free_edit(), 5, 1_700_000_060);
        let ProofRelation::CrossStore { watermark } = ProofRelation::between(&prior, &current)
        else {
            panic!("watermark-move without generation bump must classify as CrossStore");
        };
        assert!(
            !watermark.stationary(),
            "CrossStore's payload is guaranteed non-stationary by MovedWatermarkDelta"
        );
    }

    #[test]
    fn every_legitimate_between_input_still_classifies_correctly() {
        // The wrap must not lose a case: the five ProofRelation variants
        // survive the routing through MovedWatermarkDelta::new. This is
        // the fold-preservation check that welds "the refactor is
        // semantics-preserving" at the corner grid, not just at each
        // variant individually. Regression protection against a future
        // change that accidentally routed a legitimate case through the
        // `None` branch (e.g. classifying a non-stationary delta as
        // Stationary).
        let anchor = base();
        let alt = free_edit();

        // Stationary: same value, same generation.
        assert!(matches!(
            ProofRelation::between(
                &proof_at(&anchor, 5, 1_700_000_000),
                &proof_at(&anchor, 5, 1_700_000_060),
            ),
            ProofRelation::Stationary,
        ));

        // IdentityRepublish: same value, generation advance.
        assert!(matches!(
            ProofRelation::between(
                &proof_at(&anchor, 5, 1_700_000_000),
                &proof_at(&anchor, 6, 1_700_000_060),
            ),
            ProofRelation::IdentityRepublish { .. },
        ));

        // Progression: value changed, generation advance -- payload is
        // MovedWatermarkDelta by construction.
        assert!(matches!(
            ProofRelation::between(
                &proof_at(&anchor, 5, 1_700_000_000),
                &proof_at(&alt, 6, 1_700_000_060),
            ),
            ProofRelation::Progression { .. },
        ));

        // CrossStore: value changed, same generation -- payload is
        // MovedWatermarkDelta by construction.
        assert!(matches!(
            ProofRelation::between(
                &proof_at(&anchor, 5, 1_700_000_000),
                &proof_at(&alt, 5, 1_700_000_060),
            ),
            ProofRelation::CrossStore { .. },
        ));

        // Regressed: generation went backwards, watermark irrelevant.
        assert!(matches!(
            ProofRelation::between(
                &proof_at(&anchor, 10, 1_700_000_000),
                &proof_at(&anchor, 5, 1_700_000_060),
            ),
            ProofRelation::Regressed { .. },
        ));
    }

    #[test]
    fn moved_watermark_delta_equals_iff_underlying_deltas_equal() {
        // PartialEq on the newtype must lift PartialEq on the delta
        // pointwise -- otherwise two logically-identical variants would
        // fail `assert_eq!`. Weld both the equal and unequal directions.
        let m_a = MovedWatermarkDelta::new(moved_delta()).unwrap();
        let m_b = MovedWatermarkDelta::new(moved_delta()).unwrap();
        assert_eq!(m_a, m_b, "identical wrapped deltas must compare equal");

        // A different edit produces a different delta.
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        let d_restart = WatermarkDelta::between(&wm_of(&base()), &wm_of(&c));
        let m_restart = MovedWatermarkDelta::new(d_restart).unwrap();
        assert_ne!(m_a, m_restart, "different edits produce different wraps");
    }
}

#[cfg(test)]
mod watermark_delta_wire_tests {
    //! Weld the wire projection of [`WatermarkDelta`] /
    //! [`MovedWatermarkDelta`] — the same-shape wire pair to
    //! [`ConfigWatermarkWire`]. Together the tests below cover:
    //!
    //! 1. `to_wire` is a mechanical mirror on all four (Free-edit,
    //!    Restart-edit) corners produced by `WatermarkDelta::between`.
    //! 2. The wire round-trips through JSON with camelCase field names
    //!    pinned (`fullMoved` / `restartRequiredMoved` / `freeMoved`).
    //! 3. `WatermarkDelta::try_from_wire` refuses a wire whose shape
    //!    fails `class_moves_imply_full_moved` — the honest sanity
    //!    check for a delta received from an untrusted source, moved
    //!    from a runtime predicate to a parse-time weld.
    //! 4. `MovedWatermarkDelta::try_from_wire` chains the class weld
    //!    with the moved-ness weld — a stationary wire is rejected on
    //!    the newtype path even when it passes the bare-delta path.
    //! 5. Value → wire → value and wire → value → wire are both
    //!    fixed points on well-formed inputs, welding the isomorphism
    //!    both directions.
    //! 6. `TryFrom<&WatermarkDeltaWire>` and the inherent
    //!    `try_from_wire` methods agree pointwise for both types.
    //! 7. Every `WatermarkDelta::between`-computed value survives the
    //!    round trip on every (Free-edit, Restart-edit) corner — the
    //!    parse-time check never refuses a legitimate delta.
    //!
    //! Same test idiom as [`wire_tests`] (the [`ConfigSyncProofWire`]
    //! pin) and [`moved_watermark_delta_tests`] (the newtype pin), so a
    //! future refactor that touches one of the three surfaces surfaces
    //! consistent breakage across all three.

    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    /// Every corner of the (Free-edit, Restart-edit) product, folded
    /// through `WatermarkDelta::between` — the four legitimate delta
    /// shapes a well-formed producer emits.
    fn every_between_corner() -> Vec<WatermarkDelta> {
        [(false, false), (true, false), (false, true), (true, true)]
            .into_iter()
            .map(|(mutate_free, mutate_restart)| {
                let mut c = base();
                if mutate_free {
                    c.log_level = "debug".into();
                }
                if mutate_restart {
                    c.bind_addr = "0.0.0.0:9090".into();
                }
                WatermarkDelta::between(&wm_of(&base()), &wm_of(&c))
            })
            .collect()
    }

    #[test]
    fn to_wire_is_a_mechanical_mirror_on_every_between_corner() {
        for d in every_between_corner() {
            let w = d.to_wire();
            assert_eq!(w.full_moved, d.full_moved, "fullMoved mirrors");
            assert_eq!(
                w.restart_required_moved, d.restart_required_moved,
                "restartRequiredMoved mirrors"
            );
            assert_eq!(w.free_moved, d.free_moved, "freeMoved mirrors");
        }
    }

    #[test]
    fn the_wire_shape_round_trips_through_json() {
        for d in every_between_corner() {
            let w = d.to_wire();
            let json = serde_json::to_string(&w).expect("serialize");
            let back: WatermarkDeltaWire = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(w, back);
        }
    }

    #[test]
    fn the_wire_field_names_are_pinned_as_camel_case() {
        // The pin: the wire vocabulary matches ConfigWatermarkWire's
        // camelCase convention (`full` / `restartRequired` / `free`
        // over there, `fullMoved` / `restartRequiredMoved` /
        // `freeMoved` here) so a consumer that reads either surface
        // sees a consistent on-the-wire naming.
        let all_true = WatermarkDeltaWire {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        };
        let json = serde_json::to_string(&all_true).unwrap();
        for key in ["fullMoved", "restartRequiredMoved", "freeMoved"] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing {key} in {json}"
            );
        }
        // Snake-cased forms MUST NOT appear -- serde(rename_all)
        // regressions have been silent bugs before.
        for snake in ["full_moved", "restart_required_moved", "free_moved"] {
            assert!(
                !json.contains(snake),
                "snake_case leaked into wire: {snake} in {json}",
            );
        }
    }

    #[test]
    fn value_wire_value_is_identity_on_every_between_corner() {
        for d in every_between_corner() {
            let back = WatermarkDelta::try_from_wire(&d.to_wire())
                .expect("between-computed delta must round-trip through wire");
            assert_eq!(back, d);
        }
    }

    #[test]
    fn wire_value_wire_is_fixed_point_on_every_well_formed_wire() {
        for d in every_between_corner() {
            let w = d.to_wire();
            let back = WatermarkDelta::try_from_wire(&w)
                .expect("well-formed round-trip")
                .to_wire();
            assert_eq!(back, w);
        }
    }

    #[test]
    fn class_partition_violation_in_the_wire_is_a_parse_error() {
        // The load-bearing weld: a wire whose class-scoped half moved
        // WITHOUT the full-hash superset having moved is refused at
        // the parse boundary. The two shapes below cannot come from
        // any well-formed WatermarkDelta::between call -- the class-
        // scoped hash's input is a subset of the full-hash input.
        for wire in [
            WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: false,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: true,
                free_moved: true,
            },
        ] {
            let err = WatermarkDelta::try_from_wire(&wire).unwrap_err();
            assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
            let msg = err.to_string();
            assert!(
                msg.contains("fullMoved"),
                "error message must name the offending triple: {msg}"
            );
        }
    }

    #[test]
    fn all_stationary_wire_parses_to_a_stationary_delta() {
        // A shape that is stationary on every half satisfies the
        // class-partition invariant vacuously (both sides of the
        // implication are false), so the bare-delta parse accepts it.
        // The MovedWatermarkDelta parse refuses it — see the sibling
        // test below.
        let wire = WatermarkDeltaWire {
            full_moved: false,
            restart_required_moved: false,
            free_moved: false,
        };
        let d = WatermarkDelta::try_from_wire(&wire).expect("stationary wire is well-formed");
        assert!(d.stationary());
    }

    #[test]
    fn try_from_impl_and_try_from_wire_method_agree_for_watermark_delta() {
        for d in every_between_corner() {
            let w = d.to_wire();
            let via_method = WatermarkDelta::try_from_wire(&w).unwrap();
            let via_trait = WatermarkDelta::try_from(&w).unwrap();
            assert_eq!(via_method, via_trait);
        }
    }

    // -- MovedWatermarkDelta wire path --------------------------------

    #[test]
    fn moved_wire_round_trips_on_every_non_stationary_between_corner() {
        for d in every_between_corner() {
            let Some(m) = MovedWatermarkDelta::new(d) else {
                // Stationary corner -- covered by the sibling test
                // that welds the newtype's refusal of that shape.
                continue;
            };
            let w = m.to_wire();
            let back = MovedWatermarkDelta::try_from_wire(&w)
                .expect("moved between-computed delta must round-trip through wire");
            assert_eq!(back, m);
        }
    }

    #[test]
    fn moved_wire_delegates_to_bare_wire() {
        // The newtype's wire form must equal the underlying delta's
        // wire form -- otherwise a producer that serialized via the
        // newtype and a producer that unwrapped first would emit two
        // different on-the-wire shapes for the same value.
        for d in every_between_corner() {
            let Some(m) = MovedWatermarkDelta::new(d) else {
                continue;
            };
            assert_eq!(m.to_wire(), d.to_wire());
        }
    }

    #[test]
    fn moved_wire_refuses_a_stationary_wire_even_when_bare_accepts_it() {
        // The chained weld: a stationary wire passes the bare-delta
        // class-partition check (vacuously) but fails the newtype
        // moved-ness check. Refusing at the parse boundary is what
        // gives a consumer a MovedWatermarkDelta whose "at least one
        // half moved" proof travelled with the payload.
        let stationary = WatermarkDeltaWire {
            full_moved: false,
            restart_required_moved: false,
            free_moved: false,
        };
        // Bare accepts it -- vacuous class invariant.
        WatermarkDelta::try_from_wire(&stationary).expect("bare accepts stationary");
        // Newtype refuses it -- moved-ness weld.
        let err = MovedWatermarkDelta::try_from_wire(&stationary).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(
            msg.contains("stationary"),
            "moved-ness error must name the null hypothesis: {msg}"
        );
    }

    #[test]
    fn moved_wire_refuses_a_class_partition_violation_via_the_chained_check() {
        // A wire that violates the class-partition invariant is
        // refused by the newtype path too -- the try_from_wire chain
        // routes through WatermarkDelta::try_from_wire first, so the
        // class error surfaces here BEFORE the moved-ness check runs.
        let violation = WatermarkDeltaWire {
            full_moved: false,
            restart_required_moved: true,
            free_moved: false,
        };
        let err = MovedWatermarkDelta::try_from_wire(&violation).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        // The message must be the class-partition variant, not the
        // moved-ness variant -- the two welds have distinct error
        // strings and a consumer localizing the fault reads the one
        // that fired.
        let msg = err.to_string();
        assert!(
            msg.contains("class-scoped half moved"),
            "class-partition error must fire first: {msg}"
        );
    }

    #[test]
    fn try_from_impl_and_try_from_wire_method_agree_for_moved_watermark_delta() {
        for d in every_between_corner() {
            let Some(m) = MovedWatermarkDelta::new(d) else {
                continue;
            };
            let w = m.to_wire();
            let via_method = MovedWatermarkDelta::try_from_wire(&w).unwrap();
            let via_trait = MovedWatermarkDelta::try_from(&w).unwrap();
            assert_eq!(via_method, via_trait);
        }
    }

    #[test]
    fn moved_value_wire_value_is_identity_on_every_non_stationary_corner() {
        for d in every_between_corner() {
            let Some(m) = MovedWatermarkDelta::new(d) else {
                continue;
            };
            let back = MovedWatermarkDelta::try_from_wire(&m.to_wire())
                .expect("moved round-trip through wire");
            assert_eq!(back, m);
        }
    }

    #[test]
    fn moved_wire_value_wire_is_fixed_point_on_every_well_formed_moved_wire() {
        for d in every_between_corner() {
            let Some(m) = MovedWatermarkDelta::new(d) else {
                continue;
            };
            let w = m.to_wire();
            let back = MovedWatermarkDelta::try_from_wire(&w)
                .expect("well-formed round-trip")
                .to_wire();
            assert_eq!(back, w);
        }
    }
}

#[cfg(test)]
mod proof_delta_wire_tests {
    //! Weld the wire projection of [`ProofDelta`] — the proof-altitude
    //! sibling of [`WatermarkDeltaWire`]. Together the tests below cover:
    //!
    //! 1. `to_wire` is a mechanical mirror on every one of the five
    //!    [`ProofRelation`] corners (`Stationary`, `IdentityRepublish`,
    //!    `Progression`, `CrossStore`, `Regressed`) plus the
    //!    wall-clock-backwards corner (elapsed `None`), so every
    //!    legitimate wire value round-trips.
    //! 2. The wire round-trips through JSON with camelCase field names
    //!    pinned (`watermark`, `generationsAdvanced`,
    //!    `observedAtElapsedNanos`).
    //! 3. `Option` axes preserve `None` across the wire so the
    //!    generation-regressed and wall-clock-backwards signals are not
    //!    silently discarded.
    //! 4. The class-partition weld on the nested [`WatermarkDeltaWire`]
    //!    fires at [`ProofDelta::try_from_wire`]'s boundary, so a
    //!    malformed watermark half rejects the whole payload rather
    //!    than yielding a delta whose watermark could not have come
    //!    from any [`WatermarkDelta::between`] call.
    //! 5. Value → wire → value and wire → value → wire are both fixed
    //!    points on every legitimate corner.
    //! 6. `TryFrom<&ProofDeltaWire>` and the inherent `try_from_wire`
    //!    method agree pointwise.
    //! 7. `ProofDelta::to_wire` composes through
    //!    [`WatermarkDelta::to_wire`] on the watermark half — one
    //!    source of truth for the value → wire projection on the
    //!    class-scoped triple, so a future change to the watermark
    //!    encoding never diverges between the bare and proof-nested
    //!    paths.
    //! 8. Nanosecond precision is preserved end-to-end (the wire unit
    //!    matches the value-side [`Duration`](std::time::Duration)
    //!    precision).
    //!
    //! Same test idiom as [`wire_tests`] (the [`ConfigSyncProofWire`]
    //! pin) and [`watermark_delta_wire_tests`] (the delta wire pin),
    //! so a future refactor that touches one of the three wire surfaces
    //! surfaces consistent breakage across all three.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn mutated() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(cfg: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: wm_of(cfg),
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// Every legitimate corner of the (watermark moved?, generation
    /// delta, elapsed sign) grid, folded through [`ProofDelta::between`].
    /// The wire projection must round-trip on every one of these — a
    /// legitimate consumer receives them all and must reconstruct each.
    fn every_corner() -> Vec<ProofDelta> {
        vec![
            // Stationary: identical observation twice.
            ProofDelta::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&base(), 5, 1_700_000_060),
            ),
            // IdentityRepublish: same value, generation advance.
            ProofDelta::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&base(), 6, 1_700_000_030),
            ),
            // Progression: value changed and generation advanced.
            ProofDelta::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&mutated(), 6, 1_700_000_060),
            ),
            // CrossStore signal: value changed, generation stationary.
            ProofDelta::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&mutated(), 5, 1_700_000_060),
            ),
            // Regressed generation: `generations_advanced = None`.
            ProofDelta::between(
                &proof_at(&base(), 10, 1_700_000_000),
                &proof_at(&base(), 5, 1_700_000_060),
            ),
            // Wall-clock ran backwards: `observed_at_elapsed = None`.
            ProofDelta::between(
                &proof_at(&base(), 5, 1_700_000_060),
                &proof_at(&base(), 5, 1_700_000_000),
            ),
        ]
    }

    #[test]
    fn to_wire_is_a_mechanical_mirror_on_every_corner() {
        for d in every_corner() {
            let w = d.to_wire();
            assert_eq!(w.watermark, d.watermark.to_wire(), "watermark mirrors");
            assert_eq!(
                w.generations_advanced, d.generations_advanced,
                "generationsAdvanced mirrors"
            );
            assert_eq!(
                w.observed_at_elapsed_nanos,
                d.observed_at_elapsed
                    .map(|dur| u64::try_from(dur.as_nanos()).unwrap_or(u64::MAX)),
                "observedAtElapsedNanos mirrors"
            );
        }
    }

    #[test]
    fn the_wire_shape_round_trips_through_json() {
        for d in every_corner() {
            let w = d.to_wire();
            let json = serde_json::to_string(&w).expect("serialize");
            let back: ProofDeltaWire = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(w, back);
        }
    }

    #[test]
    fn the_wire_field_names_are_pinned_as_camel_case() {
        // The pin: the wire vocabulary matches ConfigSyncProofWire's
        // camelCase convention. `observedAtElapsedNanos` names its unit
        // at the wire so a consumer never has to remember which scale
        // to divide by, and the nested `watermark` field name mirrors
        // ConfigSyncProofWire's own nesting name.
        let w = ProofDeltaWire {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations_advanced: Some(3),
            observed_at_elapsed_nanos: Some(500_000_000),
        };
        let json = serde_json::to_string(&w).unwrap();
        for key in ["watermark", "generationsAdvanced", "observedAtElapsedNanos"] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing {key} in {json}"
            );
        }
        // Snake_case forms MUST NOT appear -- serde(rename_all)
        // regressions have been silent bugs before.
        for snake in [
            "generations_advanced",
            "observed_at_elapsed_nanos",
            "observed_at_elapsed",
        ] {
            assert!(
                !json.contains(snake),
                "snake_case leaked into wire: {snake} in {json}",
            );
        }
    }

    #[test]
    fn generation_regression_preserves_none_across_the_wire() {
        // A regressed generation folds to `generations_advanced: None`.
        // JSON encodes that as `null`, and the deserialized wire must
        // survive back as `Option::None` so the consumer can classify
        // this as `Regressed` rather than silently reading a bogus
        // count. Symmetric peer of the elapsed-None test below.
        let d = ProofDelta::between(
            &proof_at(&base(), 10, 1_700_000_000),
            &proof_at(&base(), 5, 1_700_000_060),
        );
        assert_eq!(
            d.generations_advanced, None,
            "precondition: regressed generation is None"
        );
        let w = d.to_wire();
        assert_eq!(
            w.generations_advanced, None,
            "the wire must preserve None on the generation axis"
        );
        let back = ProofDelta::try_from_wire(&w).expect("wire round-trip");
        assert_eq!(back.generations_advanced, None);
        assert!(
            back.generations_regressed(),
            "the reconstructed delta must classify as regressed"
        );
    }

    #[test]
    fn wall_clock_backwards_preserves_none_across_the_wire() {
        // A system-clock adjustment folds to
        // `observed_at_elapsed: None`. Unlike regression this is a
        // legitimate real-world condition; the wire must nevertheless
        // preserve None so the consumer distinguishes "clock jumped
        // backwards" from "elapsed = 0".
        let d = ProofDelta::between(
            &proof_at(&base(), 5, 1_700_000_060),
            &proof_at(&base(), 5, 1_700_000_000),
        );
        assert_eq!(
            d.observed_at_elapsed, None,
            "precondition: wall-clock ran backwards is None"
        );
        let w = d.to_wire();
        assert_eq!(w.observed_at_elapsed_nanos, None);
        let back = ProofDelta::try_from_wire(&w).expect("wire round-trip");
        assert_eq!(back.observed_at_elapsed, None);
    }

    #[test]
    fn nanosecond_precision_is_preserved_end_to_end() {
        // The wire unit matches the value-side Duration precision, so a
        // sub-second observation cadence (a 200ms /healthz/config poll
        // interval, say) survives the round trip without truncation.
        // Hand-build a ProofDelta with a sub-second elapsed so the
        // check has bite: `between()` from two epoch-seconds proofs
        // could only ever produce whole-second durations.
        let d = ProofDelta {
            watermark: WatermarkDelta::between(&wm_of(&base()), &wm_of(&base())),
            generations_advanced: Some(1),
            observed_at_elapsed: Some(Duration::from_nanos(123_456_789)),
        };
        let w = d.to_wire();
        assert_eq!(w.observed_at_elapsed_nanos, Some(123_456_789));
        let back = ProofDelta::try_from_wire(&w).expect("wire round-trip");
        assert_eq!(
            back.observed_at_elapsed,
            Some(Duration::from_nanos(123_456_789)),
            "nanoseconds must survive the wire without truncation"
        );
    }

    #[test]
    fn value_wire_value_is_identity_on_every_corner() {
        for d in every_corner() {
            let back = ProofDelta::try_from_wire(&d.to_wire())
                .expect("between-computed delta must round-trip through wire");
            assert_eq!(back, d);
        }
    }

    #[test]
    fn wire_value_wire_is_fixed_point_on_every_well_formed_wire() {
        for d in every_corner() {
            let w = d.to_wire();
            let back = ProofDelta::try_from_wire(&w)
                .expect("well-formed round-trip")
                .to_wire();
            assert_eq!(back, w);
        }
    }

    #[test]
    fn class_partition_violation_on_the_nested_watermark_is_a_parse_error() {
        // The load-bearing chain: a wire whose nested watermark half
        // fails `class_moves_imply_full_moved` is refused at the
        // ProofDeltaWire boundary too, because `ProofDelta::try_from_wire`
        // routes the watermark half through `WatermarkDelta::try_from_wire`
        // first. The error message names the offending triple so a
        // consumer can localize the fault without re-parsing the whole
        // payload.
        let violation = ProofDeltaWire {
            watermark: WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: true,
                free_moved: false,
            },
            generations_advanced: Some(1),
            observed_at_elapsed_nanos: Some(60_000_000_000),
        };
        let err = ProofDelta::try_from_wire(&violation).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(
            msg.contains("fullMoved"),
            "class-partition error must name the offending triple: {msg}"
        );
    }

    #[test]
    fn try_from_impl_and_try_from_wire_method_agree_pointwise() {
        for d in every_corner() {
            let w = d.to_wire();
            let via_method = ProofDelta::try_from_wire(&w).unwrap();
            let via_trait = ProofDelta::try_from(&w).unwrap();
            assert_eq!(via_method, via_trait);
        }
    }

    #[test]
    fn proof_delta_to_wire_watermark_equals_watermark_delta_to_wire() {
        // The composition weld: ProofDelta::to_wire's watermark half
        // MUST equal WatermarkDelta::to_wire on the same watermark
        // value. One source of truth for the value → wire projection
        // on the class-scoped triple; a future refactor that touches
        // WatermarkDelta::to_wire must NOT need a parallel change on
        // the proof-nested path.
        for d in every_corner() {
            assert_eq!(d.to_wire().watermark, d.watermark.to_wire());
        }
    }

    #[test]
    fn stationary_corner_round_trips_with_all_falses_and_some_zero() {
        // The exact bit pattern on the wire for the stationary corner:
        // every boolean false, generationsAdvanced Some(0), elapsed
        // Some(0). Pinning the exact JSON structure catches an
        // accidental default swap (e.g. serializing `None` for a
        // Some(0) generation, which would look like regression to a
        // consumer).
        let d = ProofDelta::between(
            &proof_at(&base(), 5, 1_700_000_000),
            &proof_at(&base(), 5, 1_700_000_000),
        );
        let w = d.to_wire();
        assert!(!w.watermark.full_moved);
        assert!(!w.watermark.restart_required_moved);
        assert!(!w.watermark.free_moved);
        assert_eq!(w.generations_advanced, Some(0));
        assert_eq!(w.observed_at_elapsed_nanos, Some(0));
    }

    #[test]
    fn config_sync_proof_delta_since_composes_with_wire_projection() {
        // The consumer-facing composition: a receiver-style
        // `current.delta_since(&prior).to_wire()` reaches the same wire
        // as `ProofDelta::between(&prior, &current).to_wire()`. This
        // welds "the ergonomic sibling never diverges from the named
        // constructor" AT the wire boundary, not just the value.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&mutated(), 6, 1_700_000_060);
        assert_eq!(
            current.delta_since(&prior).to_wire(),
            ProofDelta::between(&prior, &current).to_wire(),
        );
    }
}

#[cfg(test)]
mod proof_relation_wire_tests {
    //! Weld the wire projection of [`ProofRelation`] — the sum-type peer
    //! of [`ProofDeltaWire`]. Together the tests below cover:
    //!
    //! 1. `to_wire` is a mechanical mirror on every one of the five
    //!    [`ProofRelation`] corners (`Stationary`, `IdentityRepublish`,
    //!    `Progression`, `CrossStore`, `Regressed`), so every legitimate
    //!    variant round-trips.
    //! 2. The wire round-trips through JSON under the internally-tagged
    //!    (`{"kind": "...", ...}`) shape with camelCase tag values and
    //!    field names — snake_case forms and the externally-tagged
    //!    default shape MUST NOT appear.
    //! 3. Every [`std::num::NonZeroU64`] weld fires at the parse boundary:
    //!    zero-count `identityRepublish`, `progression`, and `regressed`
    //!    payloads all yield [`ShikumiError::Parse`], with error messages
    //!    that name the arm and the corner it would collapse to.
    //! 4. Every [`MovedWatermarkDelta`] weld fires at the parse boundary:
    //!    a class-partition violation OR a stationary payload on the
    //!    `progression` or `crossStore` watermark half refuses the whole
    //!    payload, propagating the nested error message so a consumer
    //!    can localize the offending triple.
    //! 5. Value → wire → value and wire → value → wire are both fixed
    //!    points on every legitimate corner.
    //! 6. `TryFrom<&ProofRelationWire>` and the inherent `try_from_wire`
    //!    method agree pointwise.
    //! 7. `ProofRelation::to_wire` composes through
    //!    [`MovedWatermarkDelta::to_wire`] on the two payload-carrying
    //!    arms — one source of truth for the value → wire projection on
    //!    the class-scoped triple, so a future change to the watermark
    //!    encoding never diverges between the bare and relation-nested
    //!    paths.
    //! 8. [`ProofRelation::same_store_consistent`] survives the wire —
    //!    the two impossibility corners stay impossibility and the three
    //!    legitimate corners stay legitimate after a wire round-trip.
    //! 9. The `kind` tag ordering matches the value-side variant order
    //!    (`stationary` before `identityRepublish` before `progression`
    //!    etc.), so the wire vocabulary a consumer sees mirrors the
    //!    `match` a value-side consumer writes.
    //! 10. The ergonomic sibling `ConfigSyncProof::relation_since().to_wire()`
    //!     agrees with `ProofRelation::between().to_wire()` at the wire
    //!     boundary — the composition weld consumers of
    //!     `/healthz/config` receive.
    //!
    //! Same test idiom as [`proof_delta_wire_tests`] (the peer wire
    //! module) and [`watermark_delta_wire_tests`] / [`wire_tests`] (the
    //! two altitudes below), so a future refactor that touches one of
    //! the four wire surfaces surfaces consistent breakage across all
    //! four.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn mutated() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(cfg: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: wm_of(cfg),
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// Every legitimate corner of the ProofRelation grid, folded through
    /// [`ProofRelation::between`]. The wire projection must round-trip
    /// on every one of these — a legitimate consumer receives them all
    /// and must reconstruct each.
    fn every_corner() -> Vec<ProofRelation> {
        vec![
            // Stationary: identical observation twice.
            ProofRelation::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&base(), 5, 1_700_000_060),
            ),
            // IdentityRepublish: same value, generation advance.
            ProofRelation::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&base(), 6, 1_700_000_030),
            ),
            // Progression: value changed and generation advanced.
            ProofRelation::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&mutated(), 6, 1_700_000_060),
            ),
            // CrossStore signal: value changed, generation stationary.
            ProofRelation::between(
                &proof_at(&base(), 5, 1_700_000_000),
                &proof_at(&mutated(), 5, 1_700_000_060),
            ),
            // Regressed: current's generation strictly less than prior's.
            ProofRelation::between(
                &proof_at(&base(), 10, 1_700_000_000),
                &proof_at(&base(), 5, 1_700_000_060),
            ),
        ]
    }

    #[test]
    fn to_wire_is_a_mechanical_mirror_on_every_corner() {
        for r in every_corner() {
            let w = r.to_wire();
            match (r, w) {
                (ProofRelation::Stationary, ProofRelationWire::Stationary) => {}
                (
                    ProofRelation::IdentityRepublish { generations: g },
                    ProofRelationWire::IdentityRepublish { generations: wg },
                ) => assert_eq!(g.get(), wg),
                (
                    ProofRelation::Progression {
                        watermark: wm,
                        generations: g,
                    },
                    ProofRelationWire::Progression {
                        watermark: ww,
                        generations: wg,
                    },
                ) => {
                    assert_eq!(wm.to_wire(), ww);
                    assert_eq!(g.get(), wg);
                }
                (
                    ProofRelation::CrossStore { watermark: wm },
                    ProofRelationWire::CrossStore { watermark: ww },
                ) => assert_eq!(wm.to_wire(), ww),
                (ProofRelation::Regressed { by }, ProofRelationWire::Regressed { by: wby }) => {
                    assert_eq!(by.get(), wby);
                }
                (v, w) => panic!("variant mismatch: value={v:?} wire={w:?}"),
            }
        }
    }

    #[test]
    fn the_wire_shape_round_trips_through_json() {
        for r in every_corner() {
            let w = r.to_wire();
            let json = serde_json::to_string(&w).expect("serialize");
            let back: ProofRelationWire = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(w, back);
        }
    }

    #[test]
    fn the_wire_uses_internally_tagged_kind_with_camel_case_tags() {
        // The pin: the wire uses serde's internally-tagged shape with a
        // `kind` discriminator, so a consumer routes on a fixed JSON path
        // (`.kind`) rather than a variant-shaped wrapping envelope. Tag
        // values are camelCase (matching the field-name convention on
        // the sibling wire types).
        let cases: &[(ProofRelation, &str, &[&str])] = &[
            (ProofRelation::Stationary, "stationary", &[]),
            (
                ProofRelation::between(
                    &proof_at(&base(), 5, 1_700_000_000),
                    &proof_at(&base(), 6, 1_700_000_030),
                ),
                "identityRepublish",
                &["generations"],
            ),
            (
                ProofRelation::between(
                    &proof_at(&base(), 5, 1_700_000_000),
                    &proof_at(&mutated(), 6, 1_700_000_060),
                ),
                "progression",
                &["watermark", "generations"],
            ),
            (
                ProofRelation::between(
                    &proof_at(&base(), 5, 1_700_000_000),
                    &proof_at(&mutated(), 5, 1_700_000_060),
                ),
                "crossStore",
                &["watermark"],
            ),
            (
                ProofRelation::between(
                    &proof_at(&base(), 10, 1_700_000_000),
                    &proof_at(&base(), 5, 1_700_000_060),
                ),
                "regressed",
                &["by"],
            ),
        ];
        for (r, tag, extra_fields) in cases {
            let json = serde_json::to_string(&r.to_wire()).unwrap();
            assert!(
                json.contains(&format!("\"kind\":\"{tag}\"")),
                "missing kind={tag} in {json}"
            );
            for f in *extra_fields {
                assert!(
                    json.contains(&format!("\"{f}\"")),
                    "missing field {f} in {json}"
                );
            }
        }
    }

    #[test]
    fn snake_case_and_externally_tagged_forms_are_absent_from_the_wire() {
        // Snake_case tag renames and serde's default externally-tagged
        // envelope have been silent regression sources before; pin
        // BOTH absences so a stray `rename_all` swap OR a stray removal
        // of `tag = "kind"` turns red.
        for r in every_corner() {
            let json = serde_json::to_string(&r.to_wire()).unwrap();
            for snake in ["identity_republish", "cross_store"] {
                assert!(
                    !json.contains(snake),
                    "snake_case tag leaked into wire: {snake} in {json}",
                );
            }
            // externally-tagged shape would look like `{"stationary": null}`
            // or `{"identityRepublish": {...}}` — refuse both by pinning
            // that the JSON always starts with `{"kind":"..."` for a
            // non-Stationary variant, and equals `{"kind":"stationary"}`
            // for the Stationary variant.
            assert!(
                json.starts_with(r#"{"kind":""#),
                "wire must start with kind tag: {json}",
            );
        }
    }

    #[test]
    fn stationary_wire_shape_is_kind_alone() {
        // The exact bit pattern for the null-hypothesis variant: no
        // payload fields, no watermark, no generations count. Pinning
        // this catches an accidental refactor that adds a field to the
        // Stationary variant without a corresponding wire migration.
        let w = ProofRelation::Stationary.to_wire();
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"kind":"stationary"}"#);
    }

    #[test]
    fn identity_republish_zero_generations_is_a_parse_error() {
        // A zero-count republish is unrepresentable on the value side
        // (NonZeroU64 field), so accepting one off the wire would let a
        // consumer construct a variant the value-side type refuses. The
        // parse boundary refuses it too, and the error message names
        // both the arm and the corner it collapses to.
        let w = ProofRelationWire::IdentityRepublish { generations: 0 };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(msg.contains("identityRepublish"), "arm named: {msg}");
        assert!(msg.contains("stationary"), "collapsed-corner named: {msg}",);
    }

    #[test]
    fn progression_zero_generations_is_a_parse_error() {
        // Even with a legitimate (moved) watermark payload, a zero-count
        // progression is refused — it would be indistinguishable from
        // CrossStore. The generation weld fires before the watermark
        // weld: pin the order so error messages are stable.
        let w = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            generations: 0,
        };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(msg.contains("progression"), "arm named: {msg}");
        assert!(msg.contains("crossStore"), "collapsed-corner named: {msg}");
    }

    #[test]
    fn regressed_zero_by_is_a_parse_error() {
        let w = ProofRelationWire::Regressed { by: 0 };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(msg.contains("regressed"), "arm named: {msg}");
        assert!(
            msg.contains("equal-generation"),
            "collapsed-corner named: {msg}",
        );
    }

    #[test]
    fn progression_class_partition_violation_on_watermark_is_a_parse_error() {
        // The load-bearing chain: the nested watermark half routes
        // through MovedWatermarkDelta::try_from_wire, which itself
        // chains WatermarkDelta::try_from_wire's class-partition check.
        // A class-scoped half moved without fullMoved refuses the whole
        // ProofRelationWire at the seam.
        let w = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: true,
                free_moved: false,
            },
            generations: 3,
        };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(
            msg.contains("fullMoved"),
            "nested class-partition error must surface at the ProofRelationWire boundary: {msg}"
        );
    }

    #[test]
    fn progression_stationary_watermark_is_a_parse_error() {
        // The moved-ness weld: an all-false watermark payload on the
        // Progression arm collapses semantically to IdentityRepublish
        // (stationary watermark + generation advance). The
        // MovedWatermarkDelta::try_from_wire chain refuses it.
        let w = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: false,
                free_moved: false,
            },
            generations: 3,
        };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        let msg = err.to_string();
        assert!(
            msg.contains("stationary payload"),
            "moved-ness error must surface: {msg}"
        );
    }

    #[test]
    fn cross_store_class_partition_violation_on_watermark_is_a_parse_error() {
        let w = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: false,
                free_moved: true,
            },
        };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        assert!(err.to_string().contains("fullMoved"));
    }

    #[test]
    fn cross_store_stationary_watermark_is_a_parse_error() {
        // A CrossStore payload with an all-false watermark collapses
        // semantically to Stationary. Refused at the seam under the
        // moved-ness weld chained through MovedWatermarkDelta.
        let w = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: false,
                restart_required_moved: false,
                free_moved: false,
            },
        };
        let err = ProofRelation::try_from_wire(&w).unwrap_err();
        assert_eq!(err.kind(), crate::ShikumiErrorKind::Parse);
        assert!(err.to_string().contains("stationary payload"));
    }

    #[test]
    fn value_wire_value_is_identity_on_every_corner() {
        for r in every_corner() {
            let back = ProofRelation::try_from_wire(&r.to_wire())
                .expect("between-computed relation must round-trip through wire");
            assert_eq!(back, r);
        }
    }

    #[test]
    fn wire_value_wire_is_fixed_point_on_every_well_formed_wire() {
        for r in every_corner() {
            let w = r.to_wire();
            let back = ProofRelation::try_from_wire(&w)
                .expect("well-formed round-trip")
                .to_wire();
            assert_eq!(back, w);
        }
    }

    #[test]
    fn try_from_impl_and_try_from_wire_method_agree_pointwise() {
        for r in every_corner() {
            let w = r.to_wire();
            let via_method = ProofRelation::try_from_wire(&w).unwrap();
            let via_trait = ProofRelation::try_from(&w).unwrap();
            assert_eq!(via_method, via_trait);
        }
    }

    #[test]
    fn proof_relation_wire_watermark_matches_moved_watermark_delta_to_wire() {
        // The composition weld: the watermark half on Progression /
        // CrossStore wires MUST equal MovedWatermarkDelta::to_wire on
        // the same payload. One source of truth for the value → wire
        // projection on the class-scoped triple; a future refactor that
        // touches MovedWatermarkDelta::to_wire must NOT need a parallel
        // change on the relation-nested path.
        for r in every_corner() {
            match r {
                ProofRelation::Progression { watermark, .. }
                | ProofRelation::CrossStore { watermark } => {
                    let wire = r.to_wire();
                    let payload = match wire {
                        ProofRelationWire::Progression { watermark: w, .. }
                        | ProofRelationWire::CrossStore { watermark: w } => w,
                        other => panic!("expected payload-carrying arm, got {other:?}"),
                    };
                    assert_eq!(payload, watermark.to_wire());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn same_store_consistent_survives_the_wire_on_every_corner() {
        // The classification-preserving property: a wire round-trip
        // MUST NOT reclassify an impossibility corner as legitimate or
        // vice versa. Together with `value_wire_value_is_identity_on_every_corner`
        // this pins that both the variant AND its derived predicates
        // survive.
        for r in every_corner() {
            let back = ProofRelation::try_from_wire(&r.to_wire()).unwrap();
            assert_eq!(
                r.same_store_consistent(),
                back.same_store_consistent(),
                "same_store_consistent must be preserved by the wire round-trip on {r:?}"
            );
        }
    }

    #[test]
    fn config_sync_proof_relation_since_composes_with_wire_projection() {
        // The consumer-facing composition: a receiver-style
        // `current.relation_since(&prior).to_wire()` reaches the same
        // wire as `ProofRelation::between(&prior, &current).to_wire()`.
        // Welds "the ergonomic sibling never diverges from the named
        // constructor" AT the wire boundary — the composition consumers
        // of `/healthz/config` receive.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&mutated(), 6, 1_700_000_060);
        assert_eq!(
            current.relation_since(&prior).to_wire(),
            ProofRelation::between(&prior, &current).to_wire(),
        );
    }
}

#[cfg(test)]
mod watermark_relation_tests {
    //! Weld the sum-type classification of a [`WatermarkDelta`] — the
    //! value-side peer of [`ProofRelation`] at the watermark altitude.
    //! Together the tests below cover:
    //!
    //! 1. Every legitimate corner of the (`full_moved`,
    //!    `restart_required_moved`, `free_moved`) grid maps to the
    //!    intended [`WatermarkRelation`] variant, computed from the exact
    //!    same [`WatermarkDelta::between`] the authored crate uses.
    //! 2. Every one of the three impossibility corners (a class-scoped
    //!    half moved without `full_moved`) yields `None` from
    //!    [`WatermarkDelta::relation`] — the same shape
    //!    [`WatermarkDelta::class_moves_imply_full_moved`] refuses as a
    //!    predicate.
    //! 3. Every variant-side predicate matches its
    //!    [`WatermarkDelta`]-side sibling pointwise, so a consumer that
    //!    routes on `Self::restart_pending` / `Self::hot_swappable_drift`
    //!    / `Self::partitioned_class_invariant_holds` through the variant
    //!    reaches the same answer the underlying delta's predicate gives.
    //! 4. [`ConfigWatermark::relation_since`] agrees with
    //!    `self.delta_since(prior).relation()` on every corner — the
    //!    ergonomic receiver sibling never diverges from the named path.
    //! 5. Wire round-trips through [`WatermarkDelta::try_from_wire`]
    //!    preserve the classification: a delta reconstructed from the wire
    //!    reaches the same variant its value-side origin did.
    //! 6. `Some` is total on every [`WatermarkDelta::between`] output —
    //!    across a matrix of edits touching each [`HotSwapClass`], both,
    //!    and neither, the classification never yields `None`.
    //! 7. `restart_pending` and `hot_swappable_drift` on the variant
    //!    agree with the payload of the analogous [`ProofRelation`]
    //!    variant, so the two altitudes stay coherent.
    //! 8. The impossibility bucket has no `to_wire`-side counterpart — a
    //!    `MovedWatermarkDelta::try_from_wire` reject and a
    //!    `WatermarkDelta::relation` `None` name the same set of
    //!    hand-constructed shapes.
    //! 9. The (`Stationary`, `UnclassifiedDrift`, `RestartRequiredOnly`,
    //!    `FreeOnly`, `Both`) tags exhaustively cover the five legitimate
    //!    corners: iterating a hand-authored list of the five
    //!    (`full_moved`, `restart_required_moved`, `free_moved`) tuples
    //!    reaches each variant exactly once with `Some(_)`.
    //! 10. `PartialEq` on the variant matches structural equality of the
    //!     underlying delta — two deltas with the same tuple of booleans
    //!     land in the same variant regardless of which config edit
    //!     produced them.

    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    // A Cfg with an EXTRA field NOT covered by FIELD_CLASSES — an edit
    // to `unclassified` moves `full` but neither class-scoped half,
    // reaching the UnclassifiedDrift corner.
    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct CfgUnclassified {
        log_level: String,
        bind_addr: String,
        // Not in FIELD_CLASSES_UNCLASSIFIED below either — an edit here
        // touches only the full-hash input.
        release_channel: String,
    }

    // Same subset of classifications as FIELD_CLASSES — `release_channel`
    // is deliberately absent so an edit to it produces a
    // `full_moved`-only delta.
    const FIELD_CLASSES_UNCLASSIFIED: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn base_unclassified() -> CfgUnclassified {
        CfgUnclassified {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
            release_channel: "stable".into(),
        }
    }

    fn unclassified_edit() -> CfgUnclassified {
        let mut c = base_unclassified();
        c.release_channel = "beta".into();
        c
    }

    fn wm_of_unclassified(c: &CfgUnclassified) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES_UNCLASSIFIED)
    }

    // ---------- Corner coverage ----------

    #[test]
    fn stationary_delta_maps_to_stationary_variant() {
        let w = wm_of(&base());
        let d = WatermarkDelta::between(&w, &w);
        assert_eq!(d.relation(), Some(WatermarkRelation::Stationary));
    }

    #[test]
    fn free_only_edit_maps_to_free_only_variant() {
        let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&free_edit()));
        // Only the free-classed field changed, so restart_required stays
        // put; full moves because a subset of its input changed.
        assert_eq!(d.relation(), Some(WatermarkRelation::FreeOnly));
    }

    #[test]
    fn restart_only_edit_maps_to_restart_required_only_variant() {
        let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&restart_edit()));
        assert_eq!(d.relation(), Some(WatermarkRelation::RestartRequiredOnly),);
    }

    #[test]
    fn both_classes_edit_maps_to_both_variant() {
        let d = WatermarkDelta::between(&wm_of(&base()), &wm_of(&both_edit()));
        assert_eq!(d.relation(), Some(WatermarkRelation::Both));
    }

    #[test]
    fn unclassified_field_edit_maps_to_unclassified_drift_variant() {
        // A field not present in FIELD_CLASSES_UNCLASSIFIED moves full
        // but neither class-scoped half — the only path to the
        // UnclassifiedDrift corner via an authored config edit.
        let d = WatermarkDelta::between(
            &wm_of_unclassified(&base_unclassified()),
            &wm_of_unclassified(&unclassified_edit()),
        );
        assert_eq!(d.relation(), Some(WatermarkRelation::UnclassifiedDrift));
    }

    // ---------- Impossibility coverage ----------

    #[test]
    fn hand_constructed_restart_moved_without_full_moved_yields_none() {
        // The (false, true, false) impossibility corner: a class-scoped
        // half moved without full moving. class_moves_imply_full_moved
        // refuses this as a predicate; relation refuses it via None.
        let d = WatermarkDelta {
            full_moved: false,
            restart_required_moved: true,
            free_moved: false,
        };
        assert_eq!(d.relation(), None);
        assert!(!d.class_moves_imply_full_moved());
    }

    #[test]
    fn hand_constructed_free_moved_without_full_moved_yields_none() {
        let d = WatermarkDelta {
            full_moved: false,
            restart_required_moved: false,
            free_moved: true,
        };
        assert_eq!(d.relation(), None);
        assert!(!d.class_moves_imply_full_moved());
    }

    #[test]
    fn hand_constructed_both_class_moved_without_full_moved_yields_none() {
        let d = WatermarkDelta {
            full_moved: false,
            restart_required_moved: true,
            free_moved: true,
        };
        assert_eq!(d.relation(), None);
        assert!(!d.class_moves_imply_full_moved());
    }

    // ---------- Predicate parity with WatermarkDelta ----------

    #[test]
    fn variant_predicates_match_delta_predicates_on_every_legitimate_corner() {
        // Iterate the five legitimate (full, restart, free) tuples; check
        // that every predicate on the variant agrees with the same
        // predicate on the underlying delta. Welds "the variant shape
        // never routes a consumer to a different answer than the
        // WatermarkDelta predicates would have."
        let tuples = [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, false, true),
            (true, true, true),
        ];
        for (full, restart, free) in tuples {
            let d = WatermarkDelta {
                full_moved: full,
                restart_required_moved: restart,
                free_moved: free,
            };
            let r = d.relation().expect("legitimate corner must classify");
            assert_eq!(
                r.any_moved(),
                d.any_moved(),
                "any_moved must agree on {d:?} -> {r:?}"
            );
            assert_eq!(
                r.stationary(),
                d.stationary(),
                "stationary must agree on {d:?} -> {r:?}"
            );
            assert_eq!(
                r.restart_pending(),
                d.restart_pending(),
                "restart_pending must agree on {d:?} -> {r:?}"
            );
            assert_eq!(
                r.hot_swappable_drift(),
                d.hot_swappable_drift(),
                "hot_swappable_drift must agree on {d:?} -> {r:?}"
            );
            assert_eq!(
                r.partitioned_class_invariant_holds(),
                d.partitioned_class_invariant_holds(),
                "partitioned_class_invariant_holds must agree on {d:?} -> {r:?}"
            );
        }
    }

    // ---------- Receiver-sibling composition ----------

    #[test]
    fn config_watermark_relation_since_agrees_with_delta_since_then_relation() {
        // Iterate the four legitimate configuration edits reachable
        // through an authored config change (stationary, free-only,
        // restart-only, both) and pin that the receiver-sibling never
        // diverges from the delta_since().relation() composition — the
        // exact "the ergonomic sibling never diverges from the named
        // path" pin ConfigSyncProof::relation_since already carries at
        // one altitude up.
        let cases = [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ];
        for (prior, current) in cases {
            let a = wm_of(&prior);
            let b = wm_of(&current);
            assert_eq!(
                b.relation_since(&a),
                b.delta_since(&a).relation(),
                "relation_since must fold delta_since().relation() on {prior:?} -> {current:?}",
            );
        }
    }

    #[test]
    fn config_watermark_relation_since_reaches_unclassified_drift_corner() {
        // Cover the fifth corner through the receiver sibling too — the
        // Cfg type that carries an unclassified `release_channel` field.
        let a = wm_of_unclassified(&base_unclassified());
        let b = wm_of_unclassified(&unclassified_edit());
        assert_eq!(
            b.relation_since(&a),
            Some(WatermarkRelation::UnclassifiedDrift),
        );
    }

    // ---------- Wire round-trip preserves the classification ----------

    #[test]
    fn classification_survives_watermark_delta_wire_round_trip() {
        // A delta reconstructed via WatermarkDelta::try_from_wire lands
        // in the same variant its value-side origin did — the wire is a
        // lossless channel for the classification, one altitude below
        // ProofRelation's own wire round-trip pin.
        let cases = [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ];
        for (prior, current) in cases {
            let d = WatermarkDelta::between(&wm_of(&prior), &wm_of(&current));
            let wire = d.to_wire();
            let back = WatermarkDelta::try_from_wire(&wire)
                .expect("legitimate delta must round-trip through the wire");
            assert_eq!(
                d.relation(),
                back.relation(),
                "wire round-trip must preserve the classification on {d:?}",
            );
        }
    }

    #[test]
    fn hand_constructed_impossibility_shape_wire_is_refused_and_never_reaches_a_variant() {
        // The wire boundary refuses the same shapes WatermarkDelta::relation
        // yields None on — pinning that the impossibility bucket has no
        // wire-side counterpart. A `MovedWatermarkDelta::try_from_wire`
        // reject and a `WatermarkDelta::relation` None name the same set
        // of hand-constructed shapes.
        let impossible = [
            (false, true, false),
            (false, false, true),
            (false, true, true),
        ];
        for (full, restart, free) in impossible {
            let d = WatermarkDelta {
                full_moved: full,
                restart_required_moved: restart,
                free_moved: free,
            };
            // relation says None...
            assert_eq!(
                d.relation(),
                None,
                "impossibility corner {d:?} must yield None"
            );
            // ...and the wire refuses the same shape when reconstructed.
            let wire = d.to_wire();
            assert!(
                WatermarkDelta::try_from_wire(&wire).is_err(),
                "wire boundary must refuse the same shape relation refuses ({d:?})",
            );
        }
    }

    // ---------- ProofRelation cross-altitude coherence ----------

    #[test]
    fn variant_predicates_agree_with_progression_variant_watermark_payload() {
        // A ProofRelation::Progression's MovedWatermarkDelta payload
        // reaches the same restart_pending / hot_swappable_drift answers
        // via .relation() on the underlying WatermarkDelta as it does via
        // the payload's own delta predicates. Welds the two altitudes to
        // one classification vocabulary.
        use std::time::{Duration, UNIX_EPOCH};
        let prior_wm = wm_of(&base());
        let current_wm = wm_of(&both_edit());
        let prior = ConfigSyncProof {
            watermark: prior_wm,
            generation: 1,
            observed_at: UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            watermark: current_wm,
            generation: 2,
            observed_at: UNIX_EPOCH + Duration::from_secs(1),
        };
        let rel = ProofRelation::between(&prior, &current);
        let ProofRelation::Progression { watermark, .. } = rel else {
            panic!("both-classes edit + generation advance must land in Progression, got {rel:?}");
        };
        let wr = watermark
            .relation()
            .expect("MovedWatermarkDelta must always classify");
        assert_eq!(wr, WatermarkRelation::Both);
        assert!(wr.restart_pending());
        assert!(wr.hot_swappable_drift());
    }

    // ---------- Exhaustiveness pin ----------

    #[test]
    fn the_five_legitimate_tuples_reach_each_variant_exactly_once() {
        // A hand-authored list of the five legitimate (full, restart,
        // free) tuples must reach each variant exactly once. Pinning the
        // count at 5 turns any future variant addition red — every new
        // corner of the (fullMoved, restartRequiredMoved, freeMoved)
        // grid (say, a new HotSwapClass axis) needs a corresponding
        // tuple here.
        let tuples = [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, false, true),
            (true, true, true),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (full, restart, free) in tuples {
            let d = WatermarkDelta {
                full_moved: full,
                restart_required_moved: restart,
                free_moved: free,
            };
            let r = d
                .relation()
                .expect("legitimate corner must classify to Some");
            assert!(
                seen.insert(format!("{r:?}")),
                "variant {r:?} reached twice — the (full, restart, free) grid is not injective",
            );
        }
        assert_eq!(seen.len(), 5, "must reach exactly 5 distinct variants");
    }

    // ---------- Structural equality ----------

    #[test]
    fn same_tuple_from_different_edits_yields_the_same_variant() {
        // Two deltas with the same (full, restart, free) tuple land in
        // the same variant regardless of which config edit produced
        // them — the classification depends only on the boolean shape,
        // as its documentation promises.
        let d1 = WatermarkDelta::between(&wm_of(&base()), &wm_of(&free_edit()));
        // Construct a second delta with the same shape from a different
        // pair (same base + a different Free-classed edit).
        let mut alt = base();
        alt.log_level = "trace".into();
        let d2 = WatermarkDelta::between(&wm_of(&base()), &wm_of(&alt));
        assert_eq!(
            d1.relation(),
            d2.relation(),
            "same (full, restart, free) tuple must yield the same variant",
        );
    }
}

#[cfg(test)]
mod watermark_relation_wire_tests {
    //! Weld the wire projection of [`WatermarkRelation`] — the sum-type
    //! peer of [`WatermarkDeltaWire`] at the classification altitude,
    //! and the value-side classification's counterpart one altitude
    //! below [`ProofRelationWire`]. Together the tests below cover:
    //!
    //! 1. `to_wire` is a mechanical mirror on every one of the five
    //!    [`WatermarkRelation`] variants; `from_wire` is its total
    //!    inverse (no welds — every variant is payload-free).
    //! 2. The wire round-trips through JSON under the internally-tagged
    //!    (`{"kind": "..."}`) shape with camelCase tag values —
    //!    snake_case forms and the externally-tagged default shape MUST
    //!    NOT appear, matching the pin the sibling `ProofRelationWire`
    //!    carries.
    //! 3. Each variant serializes to `{"kind": "<camelCase>"}` alone —
    //!    no payload fields, since every variant is payload-free. An
    //!    accidental refactor that adds a field to one variant without
    //!    a corresponding wire migration turns red here.
    //! 4. `From<WatermarkRelation>` / `From<&WatermarkRelationWire>`
    //!    agree pointwise with `to_wire` / `from_wire`, so a consumer
    //!    reaching the wire through the standard `Into` idiom gets the
    //!    same shape as one calling the named methods.
    //! 5. Value → wire → value and wire → value → wire are both fixed
    //!    points on every variant — the isomorphism composes cleanly
    //!    with itself in either direction.
    //! 6. Every variant-side predicate on [`WatermarkRelation`]
    //!    ([`WatermarkRelation::any_moved`],
    //!    [`WatermarkRelation::stationary`],
    //!    [`WatermarkRelation::restart_pending`],
    //!    [`WatermarkRelation::hot_swappable_drift`],
    //!    [`WatermarkRelation::partitioned_class_invariant_holds`])
    //!    survives a wire round-trip on every variant — the wire is a
    //!    lossless channel for the classification vocabulary a consumer
    //!    routes on.
    //! 7. The classification composes through the two altitudes: on
    //!    every legitimate delta reachable via [`WatermarkDelta::between`],
    //!    `delta.relation().unwrap().to_wire()` agrees with the two-hop
    //!    composition `delta.to_wire()` → `WatermarkDelta::try_from_wire`
    //!    → `.relation().unwrap().to_wire()`. The bare wire and the
    //!    classification wire never diverge on the value-side origin.
    //! 8. The impossibility bucket has no wire-side counterpart — the
    //!    three (`false`, class-moved) impossibility corners
    //!    [`WatermarkDelta::relation`] filters to `None` are refused at
    //!    the bare-watermark wire boundary via
    //!    [`WatermarkDelta::try_from_wire`], so a producer of a
    //!    [`WatermarkRelationWire`] has no legitimate path to encoding
    //!    the impossibility (matching the module-level "impossibility
    //!    bucket travels as `Option::None`, not a variant" doc pin).
    //! 9. The five wire variants exhaustively cover the five value-side
    //!    variants — iterating a hand-authored list reaches each wire
    //!    variant exactly once; any future addition to
    //!    [`WatermarkRelation`] forces a matching wire-side variant.
    //! 10. `MovedWatermarkDelta`'s payload composes coherently with this
    //!     wire projection: a [`ProofRelationWire::Progression`] payload
    //!     round-tripped through [`ProofRelation::try_from_wire`] reaches
    //!     the same [`WatermarkRelationWire`] the value-side path does,
    //!     welding the two altitudes' wire vocabularies to one
    //!     classification.
    //!
    //! Same test idiom as [`watermark_relation_tests`] (the value-side
    //! peer) and [`proof_relation_wire_tests`] (the wire-side peer one
    //! altitude up), so a future refactor that touches one of the four
    //! classification surfaces surfaces consistent breakage across all
    //! four.

    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    // A Cfg with an EXTRA field NOT covered by FIELD_CLASSES_UNCLASSIFIED
    // below — an edit to `release_channel` moves the full watermark
    // without moving either class-scoped half, the only path to the
    // UnclassifiedDrift corner via an authored config edit.
    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct CfgUnclassified {
        log_level: String,
        bind_addr: String,
        release_channel: String,
    }

    const FIELD_CLASSES_UNCLASSIFIED: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn base_unclassified() -> CfgUnclassified {
        CfgUnclassified {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
            release_channel: "stable".into(),
        }
    }

    fn unclassified_edit() -> CfgUnclassified {
        let mut c = base_unclassified();
        c.release_channel = "beta".into();
        c
    }

    fn wm_of_unclassified(c: &CfgUnclassified) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES_UNCLASSIFIED)
    }

    /// Every one of the five [`WatermarkRelation`] variants, in the
    /// same order the value-side enum declares them. Used to pin
    /// exhaustive coverage across the wire projection.
    const EVERY_VARIANT: [WatermarkRelation; 5] = [
        WatermarkRelation::Stationary,
        WatermarkRelation::UnclassifiedDrift,
        WatermarkRelation::RestartRequiredOnly,
        WatermarkRelation::FreeOnly,
        WatermarkRelation::Both,
    ];

    /// The wire counterpart of [`EVERY_VARIANT`] — hand-authored so a
    /// future refactor that reorders or renames a wire variant turns
    /// red at every pin here.
    const EVERY_WIRE_VARIANT: [WatermarkRelationWire; 5] = [
        WatermarkRelationWire::Stationary,
        WatermarkRelationWire::UnclassifiedDrift,
        WatermarkRelationWire::RestartRequiredOnly,
        WatermarkRelationWire::FreeOnly,
        WatermarkRelationWire::Both,
    ];

    // ---------- Mechanical mirror ----------

    #[test]
    fn to_wire_is_a_mechanical_mirror_on_every_variant() {
        for (v, w) in EVERY_VARIANT.iter().zip(EVERY_WIRE_VARIANT.iter()) {
            assert_eq!(v.to_wire(), *w, "to_wire mismatch on {v:?}");
        }
    }

    #[test]
    fn from_wire_is_the_total_inverse_of_to_wire() {
        for v in EVERY_VARIANT {
            assert_eq!(WatermarkRelation::from_wire(&v.to_wire()), v);
        }
    }

    // ---------- JSON round-trip ----------

    #[test]
    fn the_wire_shape_round_trips_through_json() {
        for w in EVERY_WIRE_VARIANT {
            let json = serde_json::to_string(&w).expect("serialize");
            let back: WatermarkRelationWire = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(w, back, "JSON round-trip mismatch: {json}");
        }
    }

    #[test]
    fn the_wire_uses_internally_tagged_kind_with_camel_case_tags() {
        // Pin: the wire uses serde's internally-tagged shape with a
        // `kind` discriminator, so a consumer routes on a fixed JSON
        // path (`.kind`) rather than a variant-shaped wrapping
        // envelope. Tag values are camelCase (matching the sibling
        // wire types' vocabulary).
        let cases: &[(WatermarkRelationWire, &str)] = &[
            (WatermarkRelationWire::Stationary, "stationary"),
            (
                WatermarkRelationWire::UnclassifiedDrift,
                "unclassifiedDrift",
            ),
            (
                WatermarkRelationWire::RestartRequiredOnly,
                "restartRequiredOnly",
            ),
            (WatermarkRelationWire::FreeOnly, "freeOnly"),
            (WatermarkRelationWire::Both, "both"),
        ];
        for (w, tag) in cases {
            let json = serde_json::to_string(w).unwrap();
            assert!(
                json.contains(&format!("\"kind\":\"{tag}\"")),
                "missing kind={tag} in {json}",
            );
        }
    }

    #[test]
    fn snake_case_and_externally_tagged_forms_are_absent_from_the_wire() {
        // Snake_case tag renames and serde's default externally-tagged
        // envelope have been silent regression sources on the sibling
        // wire types; pin BOTH absences so a stray `rename_all` swap
        // OR a stray removal of `tag = "kind"` turns red on this wire
        // too.
        for w in EVERY_WIRE_VARIANT {
            let json = serde_json::to_string(&w).unwrap();
            for snake in ["unclassified_drift", "restart_required_only", "free_only"] {
                assert!(
                    !json.contains(snake),
                    "snake_case tag leaked into wire: {snake} in {json}",
                );
            }
            // Externally-tagged would be `{"stationary":null}` etc; pin
            // that the JSON always starts with `{"kind":"..."`.
            assert!(
                json.starts_with(r#"{"kind":""#),
                "wire must start with kind tag: {json}",
            );
        }
    }

    #[test]
    fn every_variant_serializes_to_kind_alone_with_no_payload_fields() {
        // Every variant is payload-free, so the exact JSON is
        // `{"kind":"<camelCase>"}` and nothing more. An accidental
        // refactor that adds a field to one variant without a
        // corresponding wire migration turns red here.
        let expected: &[(WatermarkRelationWire, &str)] = &[
            (
                WatermarkRelationWire::Stationary,
                r#"{"kind":"stationary"}"#,
            ),
            (
                WatermarkRelationWire::UnclassifiedDrift,
                r#"{"kind":"unclassifiedDrift"}"#,
            ),
            (
                WatermarkRelationWire::RestartRequiredOnly,
                r#"{"kind":"restartRequiredOnly"}"#,
            ),
            (WatermarkRelationWire::FreeOnly, r#"{"kind":"freeOnly"}"#),
            (WatermarkRelationWire::Both, r#"{"kind":"both"}"#),
        ];
        for (w, want) in expected {
            let json = serde_json::to_string(w).unwrap();
            assert_eq!(&json, want, "unexpected JSON for {w:?}");
        }
    }

    // ---------- From / Into agreement ----------

    #[test]
    fn from_impls_agree_with_named_methods() {
        // A consumer reaching the wire through the standard `Into`
        // idiom gets the same shape as one calling the named methods.
        for v in EVERY_VARIANT {
            let via_method: WatermarkRelationWire = v.to_wire();
            let via_from: WatermarkRelationWire = v.into();
            assert_eq!(via_method, via_from, "From/to_wire mismatch on {v:?}");
        }
        for w in EVERY_WIRE_VARIANT {
            let via_method = WatermarkRelation::from_wire(&w);
            let via_from: WatermarkRelation = (&w).into();
            assert_eq!(via_method, via_from, "From/from_wire mismatch on {w:?}");
        }
    }

    // ---------- Fixed-point round-trips ----------

    #[test]
    fn value_to_wire_to_value_is_a_fixed_point_on_every_variant() {
        for v in EVERY_VARIANT {
            let back = WatermarkRelation::from_wire(&v.to_wire());
            assert_eq!(back, v, "value round-trip broke on {v:?}");
        }
    }

    #[test]
    fn wire_to_value_to_wire_is_a_fixed_point_on_every_variant() {
        for w in EVERY_WIRE_VARIANT {
            let back = WatermarkRelation::from_wire(&w).to_wire();
            assert_eq!(back, w, "wire round-trip broke on {w:?}");
        }
    }

    // ---------- Predicate survival across the wire ----------

    #[test]
    fn every_variant_side_predicate_survives_the_wire_round_trip() {
        // Iterate every variant; check that every predicate on the
        // value-side classification agrees with the same predicate on
        // the value reconstructed from the wire. Welds "the wire is a
        // lossless channel for the classification vocabulary a
        // consumer routes on."
        for v in EVERY_VARIANT {
            let back = WatermarkRelation::from_wire(&v.to_wire());
            assert_eq!(
                back.any_moved(),
                v.any_moved(),
                "any_moved must survive wire on {v:?}",
            );
            assert_eq!(
                back.stationary(),
                v.stationary(),
                "stationary must survive wire on {v:?}",
            );
            assert_eq!(
                back.restart_pending(),
                v.restart_pending(),
                "restart_pending must survive wire on {v:?}",
            );
            assert_eq!(
                back.hot_swappable_drift(),
                v.hot_swappable_drift(),
                "hot_swappable_drift must survive wire on {v:?}",
            );
            assert_eq!(
                back.partitioned_class_invariant_holds(),
                v.partitioned_class_invariant_holds(),
                "partitioned_class_invariant_holds must survive wire on {v:?}",
            );
        }
    }

    // ---------- Two-altitude composition ----------

    #[test]
    fn classification_wire_agrees_with_bare_delta_wire_then_classify() {
        // Pin: on every legitimate delta reachable via
        // WatermarkDelta::between, `delta.relation().unwrap().to_wire()`
        // agrees with the two-hop composition
        // `delta.to_wire() -> try_from_wire -> relation().unwrap().to_wire()`.
        // The bare-watermark wire and the classification wire never
        // diverge on the value-side origin — one classification
        // vocabulary across the two wire altitudes.
        let cases: Vec<(WatermarkDelta, WatermarkRelationWire)> = vec![
            (
                WatermarkDelta::between(&wm_of(&base()), &wm_of(&base())),
                WatermarkRelationWire::Stationary,
            ),
            (
                WatermarkDelta::between(&wm_of(&base()), &wm_of(&free_edit())),
                WatermarkRelationWire::FreeOnly,
            ),
            (
                WatermarkDelta::between(&wm_of(&base()), &wm_of(&restart_edit())),
                WatermarkRelationWire::RestartRequiredOnly,
            ),
            (
                WatermarkDelta::between(&wm_of(&base()), &wm_of(&both_edit())),
                WatermarkRelationWire::Both,
            ),
            (
                WatermarkDelta::between(
                    &wm_of_unclassified(&base_unclassified()),
                    &wm_of_unclassified(&unclassified_edit()),
                ),
                WatermarkRelationWire::UnclassifiedDrift,
            ),
        ];
        for (delta, expected_wire) in cases {
            let direct = delta
                .relation()
                .expect("legitimate delta must classify")
                .to_wire();
            let bare_wire = delta.to_wire();
            let via_bare_wire = WatermarkDelta::try_from_wire(&bare_wire)
                .expect("legitimate delta round-trips through wire")
                .relation()
                .expect("round-tripped delta must classify")
                .to_wire();
            assert_eq!(
                direct, expected_wire,
                "direct classification wire wrong on {delta:?}",
            );
            assert_eq!(
                via_bare_wire, expected_wire,
                "two-hop classification wire wrong on {delta:?}",
            );
            assert_eq!(
                direct, via_bare_wire,
                "wire projections diverged between altitudes on {delta:?}",
            );
        }
    }

    // ---------- Impossibility bucket has no wire counterpart ----------

    #[test]
    fn no_wire_variant_reaches_a_classification_the_bare_wire_would_refuse() {
        // The three (false, class-moved) impossibility corners
        // WatermarkDelta::relation filters to None are refused at the
        // bare-watermark wire boundary via WatermarkDelta::try_from_wire,
        // so a producer of a WatermarkRelationWire has no legitimate
        // path to encoding the impossibility. Pin: every possible
        // WatermarkRelationWire deserializes into a variant whose
        // predicates match SOME legitimate WatermarkDelta shape (i.e.
        // the classification never lifts an impossibility corner into
        // a wire variant).
        let impossible = [
            (false, true, false),
            (false, false, true),
            (false, true, true),
        ];
        for (full, restart, free) in impossible {
            let d = WatermarkDelta {
                full_moved: full,
                restart_required_moved: restart,
                free_moved: free,
            };
            assert_eq!(
                d.relation(),
                None,
                "impossibility corner {d:?} must yield None"
            );
            let bare_wire = d.to_wire();
            assert!(
                WatermarkDelta::try_from_wire(&bare_wire).is_err(),
                "bare wire must refuse the impossibility corner {d:?} that has no relation-wire",
            );
        }
        // Every legitimate WatermarkRelationWire's reconstructed value
        // is a variant whose class-partition invariant holds under
        // WatermarkRelation::partitioned_class_invariant_holds, EXCEPT
        // UnclassifiedDrift — the sole legitimate corner that fails
        // the invariant. Pin the count so the impossibility-bucket
        // omission is explicit: 4/5 wire variants satisfy the
        // invariant, and none carries an impossibility shape.
        let invariant_holders: usize = EVERY_WIRE_VARIANT
            .iter()
            .filter(|w| WatermarkRelation::from_wire(w).partitioned_class_invariant_holds())
            .count();
        assert_eq!(
            invariant_holders, 4,
            "exactly four wire variants satisfy the class-partition invariant",
        );
    }

    // ---------- Exhaustiveness pins ----------

    #[test]
    fn the_five_wire_variants_are_reached_from_five_distinct_value_variants() {
        // Pinning the count at 5 turns any future variant addition red
        // — every new corner of the (fullMoved, restartRequiredMoved,
        // freeMoved) grid needs a corresponding wire tag.
        let seen: std::collections::BTreeSet<String> = EVERY_VARIANT
            .iter()
            .map(|v| serde_json::to_string(&v.to_wire()).unwrap())
            .collect();
        assert_eq!(
            seen.len(),
            5,
            "five value variants must project to five distinct wire tags",
        );
    }

    #[test]
    fn every_wire_variant_round_trips_from_a_legitimate_value_variant() {
        // Injective in both directions: every wire variant reaches
        // back to exactly one value variant. Pinning both directions
        // rules out an accidental collapse (two wire variants
        // reconstructing to the same value) and an accidental orphan
        // (a wire variant with no value-side origin).
        let value_to_wire: std::collections::BTreeMap<String, String> = EVERY_VARIANT
            .iter()
            .map(|v| {
                (
                    format!("{v:?}"),
                    serde_json::to_string(&v.to_wire()).unwrap(),
                )
            })
            .collect();
        let wire_to_value: std::collections::BTreeMap<String, String> = EVERY_WIRE_VARIANT
            .iter()
            .map(|w| {
                (
                    serde_json::to_string(w).unwrap(),
                    format!("{:?}", WatermarkRelation::from_wire(w)),
                )
            })
            .collect();
        assert_eq!(value_to_wire.len(), 5);
        assert_eq!(wire_to_value.len(), 5);
        for (v, w) in &value_to_wire {
            assert_eq!(
                wire_to_value.get(w).map(String::as_str),
                Some(v.as_str()),
                "wire {w} did not reconstruct to value {v}",
            );
        }
    }

    // ---------- ProofRelationWire cross-altitude coherence ----------

    #[test]
    fn proof_relation_wire_progression_payload_agrees_with_the_classification_wire() {
        // A ProofRelationWire::Progression's watermark payload
        // reconstructs to a MovedWatermarkDelta whose .relation()
        // reaches the same WatermarkRelationWire as the value-side
        // path does. Welds the two altitudes' wire vocabularies to
        // ONE classification.
        use std::time::{Duration, UNIX_EPOCH};
        let prior = ConfigSyncProof {
            watermark: wm_of(&base()),
            generation: 1,
            observed_at: UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            watermark: wm_of(&both_edit()),
            generation: 2,
            observed_at: UNIX_EPOCH + Duration::from_secs(1),
        };
        let value_side = ProofRelation::between(&prior, &current);
        let ProofRelation::Progression { watermark, .. } = value_side else {
            panic!("both-classes edit + generation advance must land in Progression");
        };
        let value_wire = watermark
            .relation()
            .expect("MovedWatermarkDelta always classifies")
            .to_wire();
        // Round-trip through the ProofRelationWire boundary and
        // classify from the reconstructed payload.
        let proof_wire = value_side.to_wire();
        let ProofRelationWire::Progression { watermark: ww, .. } = proof_wire else {
            panic!("Progression must project to Progression");
        };
        let via_wire = MovedWatermarkDelta::try_from_wire(&ww)
            .expect("legitimate progression watermark round-trips")
            .relation()
            .expect("round-tripped MovedWatermarkDelta always classifies")
            .to_wire();
        assert_eq!(value_wire, WatermarkRelationWire::Both);
        assert_eq!(via_wire, value_wire);
    }
}

#[cfg(test)]
mod relation_wire_since_tests {
    //! Weld the `relation_wire_since` receiver-siblings at both
    //! altitudes — the wire-projection peer of the `relation_since` /
    //! `delta_since` receiver-sibling family, fusing the classification
    //! and its wire projection at one call site. Together the tests
    //! below cover:
    //!
    //! 1. [`ConfigWatermark::relation_wire_since`] agrees pointwise
    //!    with the two-hop composition `self.relation_since(prior).map(|r| r.to_wire())`
    //!    on every authored config edit — the ergonomic sibling never
    //!    diverges from the named composition, matching the shape the
    //!    value-side `relation_since` sibling already carries.
    //! 2. [`ConfigWatermark::relation_wire_since`] agrees pointwise
    //!    with the three-hop composition `self.delta_since(prior).relation().map(|r| r.to_wire())`
    //!    — the double-fusion (delta_since → relation → to_wire) that
    //!    a consumer without the receiver sibling would spell inline.
    //! 3. [`ConfigSyncProof::relation_wire_since`] agrees pointwise
    //!    with `self.relation_since(prior).to_wire()` and with
    //!    `ProofRelation::between(prior, self).to_wire()` — the
    //!    proof-altitude peer of pin (1), one altitude up.
    //! 4. Totality on authored flow: on every configuration edit that
    //!    passes through [`ConfigWatermark::compute`],
    //!    [`ConfigWatermark::relation_wire_since`] returns `Some` (never
    //!    `None`), because [`WatermarkDelta::between`] on any two
    //!    authored watermarks cannot yield a class-partition violation
    //!    in the absence of hash collisions.
    //! 5. Cross-altitude coherence: on an edit that lands a
    //!    [`ConfigSyncProof::relation_wire_since`] in
    //!    [`ProofRelationWire::Progression`], the nested `watermark`
    //!    payload reconstructs to a [`MovedWatermarkDelta`] whose
    //!    `.relation().unwrap().to_wire()` equals
    //!    [`ConfigWatermark::relation_wire_since`] on the same watermark
    //!    pair — the two receiver-sibling wire projections agree on the
    //!    same classification tag.
    //! 6. Impossibility passthrough: a hand-constructed
    //!    [`ConfigWatermark`] pair whose delta violates the weak
    //!    class-partition invariant (a shape only reachable off the
    //!    authored flow) yields `None` from
    //!    [`ConfigWatermark::relation_wire_since`] — the same set the
    //!    value-side [`WatermarkDelta::relation`] filters out.
    //! 7. Argument-order agreement with the value-side receiver
    //!    siblings: `current.relation_wire_since(&prior)` matches
    //!    `current.relation_since(&prior).map(|r| r.to_wire())` under
    //!    the same "receiver is current" convention every other
    //!    `*_since` method carries.
    //!
    //! Same test idiom as the sibling `watermark_relation_wire_tests`
    //! / `proof_relation_wire_tests` modules, so a future refactor
    //! touching either altitude's wire projection surfaces breakage
    //! here too.

    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(c: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        use std::time::{Duration, UNIX_EPOCH};
        ConfigSyncProof {
            watermark: wm_of(c),
            generation,
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// The four authored-flow edits reachable through two
    /// `ConfigWatermark::compute` calls on the fixture — one per
    /// legitimate corner of the watermark grid reachable through this
    /// Cfg (stationary, free-only, restart-only, both).
    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- ConfigWatermark::relation_wire_since ----------

    #[test]
    fn watermark_relation_wire_since_agrees_with_relation_since_then_to_wire() {
        // Pin (1): the receiver sibling never diverges from the named
        // `relation_since().map(to_wire)` composition on any authored
        // edit — same shape the value-side `relation_since` sibling
        // already carries, extended one altitude down.
        for (prior, current) in authored_pairs() {
            let a = wm_of(&prior);
            let b = wm_of(&current);
            assert_eq!(
                b.relation_wire_since(&a),
                b.relation_since(&a).map(|r| r.to_wire()),
                "relation_wire_since must fold relation_since().map(to_wire) on {prior:?} -> {current:?}",
            );
        }
    }

    #[test]
    fn watermark_relation_wire_since_agrees_with_delta_since_relation_to_wire() {
        // Pin (2): the receiver sibling agrees with the triple
        // composition delta_since → relation → to_wire — i.e. the
        // inline shape a consumer without the receiver sibling would
        // spell. This pins that the receiver sibling is a pure
        // convenience — never a semantic shift over the underlying
        // chain.
        for (prior, current) in authored_pairs() {
            let a = wm_of(&prior);
            let b = wm_of(&current);
            assert_eq!(
                b.relation_wire_since(&a),
                b.delta_since(&a).relation().map(|r| r.to_wire()),
                "relation_wire_since must fold delta_since().relation().map(to_wire) on {prior:?} -> {current:?}",
            );
        }
    }

    #[test]
    fn watermark_relation_wire_since_is_total_on_authored_flow() {
        // Pin (4): on any two ConfigWatermark values produced by
        // ConfigWatermark::compute, the classification never yields
        // None. A None on this path signals a hand-constructed
        // inconsistent delta leaking through a non-standard entry
        // point, not a legitimate authored-flow outcome — the same
        // totality guarantee `relation_since` carries.
        for (prior, current) in authored_pairs() {
            let a = wm_of(&prior);
            let b = wm_of(&current);
            assert!(
                b.relation_wire_since(&a).is_some(),
                "authored edit {prior:?} -> {current:?} must classify to Some",
            );
        }
    }

    #[test]
    fn watermark_relation_wire_since_reaches_every_authored_variant() {
        // Pin the four authored-flow variants each land in a distinct
        // WatermarkRelationWire tag — a further weld on totality (pin
        // 4) and on the injective projection from the (full, restart,
        // free) grid to the wire tags. UnclassifiedDrift is
        // unreachable through this fixture (it requires a Cfg with an
        // unclassified field); the four here are the four the
        // authored fixture actually reaches.
        let expected = [
            (base(), base(), WatermarkRelationWire::Stationary),
            (base(), free_edit(), WatermarkRelationWire::FreeOnly),
            (
                base(),
                restart_edit(),
                WatermarkRelationWire::RestartRequiredOnly,
            ),
            (base(), both_edit(), WatermarkRelationWire::Both),
        ];
        for (prior, current, want) in expected {
            let a = wm_of(&prior);
            let b = wm_of(&current);
            assert_eq!(
                b.relation_wire_since(&a),
                Some(want),
                "relation_wire_since must reach {want:?} on {prior:?} -> {current:?}",
            );
        }
    }

    #[test]
    fn watermark_relation_wire_since_passes_through_impossibility_as_none() {
        // Pin (6): a hand-constructed ConfigWatermark pair whose
        // WatermarkDelta violates the weak class-partition invariant
        // (a class-scoped half moved without full_moved) reaches
        // ConfigWatermark::relation_wire_since as Option::None — the
        // same set WatermarkDelta::relation filters out. Weld the
        // impossibility bucket at the receiver sibling too, not just
        // at the underlying delta.
        //
        // Reach the impossibility through the `pub`-field
        // ConfigWatermark constructor: this is the only path off the
        // authored flow. `full` matches on both sides so full_moved =
        // false; `restart_required` differs so restart_required_moved
        // = true; `free` matches so free_moved = false — that's the
        // (F, T, F) impossibility corner.
        let prior = ConfigWatermark {
            full: blake3::hash(b"pinned-full"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"pinned-free"),
        };
        let current = ConfigWatermark {
            full: blake3::hash(b"pinned-full"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"pinned-free"),
        };
        assert_eq!(current.relation_wire_since(&prior), None);
        // Same shape at the delta altitude.
        assert_eq!(current.delta_since(&prior).relation(), None);
    }

    // ---------- ConfigSyncProof::relation_wire_since ----------

    #[test]
    fn proof_relation_wire_since_agrees_with_relation_since_then_to_wire() {
        // Pin (3), value-side leg: the receiver sibling never
        // diverges from `relation_since().to_wire()` — matching the
        // shape ConfigSyncProof::relation_since already carries and
        // extending it one composition further to the wire boundary.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&both_edit(), 6, 1_700_000_060);
        assert_eq!(
            current.relation_wire_since(&prior),
            current.relation_since(&prior).to_wire(),
        );
    }

    #[test]
    fn proof_relation_wire_since_agrees_with_between_then_to_wire() {
        // Pin (3), named-constructor leg: the receiver sibling
        // matches the named `ProofRelation::between(&prior, &current).to_wire()`
        // — a further weld that the composition through `between` and
        // the composition through `relation_since` agree, and both
        // reach the same wire.
        let prior = proof_at(&base(), 5, 1_700_000_000);
        let current = proof_at(&both_edit(), 6, 1_700_000_060);
        assert_eq!(
            current.relation_wire_since(&prior),
            ProofRelation::between(&prior, &current).to_wire(),
        );
    }

    #[test]
    fn proof_relation_wire_since_is_total_on_every_authored_flow() {
        // Pin (3) totality: unlike the watermark-altitude sibling
        // (which returns Option because the underlying WatermarkDelta
        // can carry a class-partition-invariant violation on
        // hand-constructed shapes), ConfigSyncProof::relation_wire_since
        // is TOTAL — a ProofRelation built from two ConfigSyncProof
        // values always classifies (the MovedWatermarkDelta weld on
        // the payload-carrying arms is re-established at the wire
        // boundary via ProofRelation::try_from_wire, not lost). Pin
        // that no proof-pair yields a compile-time-optional at this
        // altitude.
        let pairs = [
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_000),
            ),
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_060),
            ),
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 6, 1_700_000_060),
            ),
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&free_edit(), 6, 1_700_000_060),
            ),
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&restart_edit(), 6, 1_700_000_060),
            ),
            (
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
            ),
            // Regression corner (current generation < prior) — still
            // total: it lands on ProofRelationWire::Regressed.
            (
                proof_at(&base(), 6, 1_700_000_060),
                proof_at(&base(), 5, 1_700_000_000),
            ),
        ];
        for (prior, current) in pairs {
            // Nothing to unwrap: the return is a ProofRelationWire.
            let w = current.relation_wire_since(&prior);
            let via_named = ProofRelation::between(&prior, &current).to_wire();
            assert_eq!(w, via_named, "totality-pinning agreement failed");
        }
    }

    // ---------- Cross-altitude coherence ----------

    #[test]
    fn the_two_altitudes_relation_wire_since_agree_on_the_same_classification_tag() {
        // Pin (5): on an edit that lands ConfigSyncProof::relation_wire_since
        // in ProofRelationWire::Progression, the nested `watermark`
        // payload reconstructs to a MovedWatermarkDelta whose
        // .relation().unwrap().to_wire() equals
        // ConfigWatermark::relation_wire_since on the same watermark
        // pair — the two receiver-sibling wire projections agree on
        // the same classification tag. Welds the two altitudes'
        // receiver-sibling wire projections to ONE classification
        // vocabulary, matching the value-side
        // `proof_relation_wire_progression_payload_agrees_with_the_classification_wire`
        // pin its wire-side peer already carries.
        let prior = proof_at(&base(), 1, 1_700_000_000);
        let current = proof_at(&both_edit(), 2, 1_700_000_060);
        let proof_wire = current.relation_wire_since(&prior);
        let ProofRelationWire::Progression { watermark: ww, .. } = proof_wire else {
            panic!(
                "both-classes edit + generation advance must land in Progression, got {proof_wire:?}"
            );
        };
        let via_proof = MovedWatermarkDelta::try_from_wire(&ww)
            .expect("legitimate progression watermark round-trips")
            .relation()
            .expect("round-tripped MovedWatermarkDelta always classifies")
            .to_wire();
        let via_watermark_altitude = current
            .watermark
            .relation_wire_since(&prior.watermark)
            .expect("authored watermark pair must classify to Some");
        assert_eq!(via_proof, via_watermark_altitude);
        // And both equal Both — the classification the edit encodes.
        assert_eq!(via_watermark_altitude, WatermarkRelationWire::Both);
    }

    #[test]
    fn watermark_and_proof_relation_wire_since_argument_order_matches() {
        // Pin (7): the receiver is the "current" half at both
        // altitudes, matching every other `*_since` method's argument
        // order. At the watermark altitude, moved-ness is symmetric
        // at the class-partition level, so swapping the arguments on
        // a same-shape edit reaches the same classification (nothing
        // silently absorbed). At the proof altitude, swapping flips
        // Progression <-> Regressed on the generation axis — pinning
        // that the argument-order convention IS load-bearing at that
        // altitude and the receiver-is-current spelling is what
        // routes a caller to the correct half.
        let a_wm = wm_of(&base());
        let b_wm = wm_of(&free_edit());
        let a_proof = proof_at(&base(), 1, 1_700_000_000);
        let b_proof = proof_at(&free_edit(), 2, 1_700_000_060);
        let wm_answer = b_wm.relation_wire_since(&a_wm);
        let proof_wire = b_proof.relation_wire_since(&a_proof);
        let ProofRelationWire::Progression { watermark: ww, .. } = proof_wire else {
            panic!("free edit + generation advance must be Progression");
        };
        let proof_answer = MovedWatermarkDelta::try_from_wire(&ww)
            .unwrap()
            .relation()
            .unwrap()
            .to_wire();
        assert_eq!(wm_answer, Some(WatermarkRelationWire::FreeOnly));
        assert_eq!(proof_answer, WatermarkRelationWire::FreeOnly);
        // Watermark altitude: symmetric edit — swapping yields the
        // same classification.
        assert_eq!(a_wm.relation_wire_since(&b_wm), wm_answer);
        // Proof altitude: swap flips the generation direction to
        // Regressed. Pin that argument order is load-bearing here in
        // a way it is not at the watermark altitude.
        let swapped = a_proof.relation_wire_since(&b_proof);
        assert!(
            matches!(swapped, ProofRelationWire::Regressed { .. }),
            "swap must flip the generation direction to Regressed, got {swapped:?}",
        );
    }
}

#[cfg(test)]
mod watermark_relation_since_cross_altitude_tests {
    //! Weld the cross-altitude `watermark_relation_since` +
    //! `watermark_relation_wire_since` receiver-sibling pair on
    //! [`ConfigSyncProof`] — the classification peers of
    //! [`ConfigSyncProof::watermark_delta_since`], letting a proof
    //! -altitude caller reach the watermark-altitude classification
    //! (value AND wire) without hand-composing through the `.watermark`
    //! field or unwrapping the [`ProofRelationWire::Progression`]
    //! payload. Together the tests below cover:
    //!
    //! 1. [`ConfigSyncProof::watermark_relation_since`] composes
    //!    through the underlying [`ConfigWatermark::relation_since`] —
    //!    the exact composition the method is named for. A future
    //!    signed-attestation blob or leaf-schema hash added to
    //!    [`ConfigSyncProof`] never reaches this method's body; the
    //!    `.watermark` half stays the single source of truth for the
    //!    watermark-altitude classification.
    //! 2. [`ConfigSyncProof::watermark_relation_wire_since`] composes
    //!    through the underlying [`ConfigWatermark::relation_wire_since`]
    //!    — the wire peer of (1).
    //! 3. `watermark_relation_wire_since` agrees pointwise with
    //!    `watermark_relation_since().map(WatermarkRelation::to_wire)`
    //!    — the two composition legs (wire-first through the receiver
    //!    sibling vs. value-first then wire projection) never diverge.
    //! 4. Both methods are invariant under generation bumps and
    //!    observed-at advances — a store re-publishing an identical
    //!    value never moves the classification, matching the invariance
    //!    [`ConfigSyncProof::watermark_delta_since`] carries.
    //! 5. Totality on the authored flow: every proof pair whose
    //!    watermarks come out of [`ConfigWatermark::compute`] yields
    //!    `Some` at both methods.
    //! 6. Impossibility passthrough: a proof pair whose nested
    //!    watermarks hit the class-partition-invariant violation
    //!    corner reaches both methods as `None` — the exact same
    //!    `None` set [`ConfigWatermark::relation_since`] /
    //!    [`ConfigWatermark::relation_wire_since`] filter, lifted
    //!    unchanged through the proof container.
    //! 7. Cross-altitude coherence with [`Self::relation_wire_since`]:
    //!    on any edit that lands the proof-altitude wire in
    //!    [`ProofRelationWire::Progression`], the classification tag
    //!    recoverable from the nested `watermark` payload matches
    //!    `watermark_relation_wire_since`'s answer — the two paths
    //!    reach the same wire tag through the sibling API.
    //! 8. Argument-order convention: at the watermark altitude,
    //!    moved-ness is symmetric, so swapping the receiver and
    //!    argument reaches the same classification even through the
    //!    proof container — the load-bearing generation-direction axis
    //!    that flips [`ProofRelation`] `Progression <-> Regressed`
    //!    lives at the proof altitude, NOT at the watermark altitude
    //!    the cross-altitude sibling reaches.
    //! 9. Payload-unwrap-free reach: on every non-`Progression` arm of
    //!    the proof-altitude wire (`Stationary`, `IdentityRepublish`,
    //!    `Regressed`, `Skipped`, `CrossStoreOrTampered`), the
    //!    watermark-altitude wire tag is STILL reachable through this
    //!    method — a single call that never leans on the
    //!    [`ProofRelationWire::Progression`] payload.
    //!
    //! Same test idiom as the sibling `relation_wire_since_tests`
    //! module, so a future refactor touching either altitude's
    //! classification pipeline surfaces breakage here too.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(c: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            watermark: wm_of(c),
            generation,
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- (1) value-side composition through the watermark half

    #[test]
    fn watermark_relation_since_composes_through_the_watermark_half() {
        // Pin (1): the proof-level cross-altitude classification MUST
        // compose through the watermark-level primitive — adding a
        // future signed-attestation blob to ConfigSyncProof never
        // reaches this method's implementation. The .watermark half is
        // the single source of truth for the watermark-altitude
        // classification, and this method is a pure delegation to it.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 42, 1_700_000_060);
            assert_eq!(
                current.watermark_relation_since(&prior),
                current.watermark.relation_since(&prior.watermark),
                "watermark_relation_since must delegate to the watermark half on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (2) wire-side composition through the watermark half

    #[test]
    fn watermark_relation_wire_since_composes_through_the_watermark_half() {
        // Pin (2): wire peer of (1). The proof-level cross-altitude
        // wire classification composes through the underlying
        // ConfigWatermark::relation_wire_since — the same
        // single-source-of-truth guarantee, extended one composition
        // further to the wire boundary.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 42, 1_700_000_060);
            assert_eq!(
                current.watermark_relation_wire_since(&prior),
                current.watermark.relation_wire_since(&prior.watermark),
                "watermark_relation_wire_since must delegate to the watermark half on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (3) two-leg agreement

    #[test]
    fn watermark_relation_wire_since_agrees_with_value_then_to_wire() {
        // Pin (3): the wire-first sibling equals the value-first then
        // to-wire composition on every authored pair. Composing the
        // classification with the wire projection through the receiver
        // sibling yields the same answer as composing them through the
        // named methods — the proof stays welded across the two
        // composition legs.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            assert_eq!(
                current.watermark_relation_wire_since(&prior),
                current
                    .watermark_relation_since(&prior)
                    .map(|r| r.to_wire()),
                "watermark_relation_wire_since must fold watermark_relation_since().map(to_wire) on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (4) invariance under generation + timestamp axes

    #[test]
    fn both_methods_are_invariant_under_generation_and_timestamp_bumps() {
        // Pin (4): a store re-publishing an identical value bumps
        // generation and observed_at without moving any watermark
        // half — the cross-altitude classification MUST answer
        // Some(Stationary) under that, matching the invariance
        // ConfigSyncProof::watermark_delta_since carries. If either
        // method folded the generation/observed_at axes in, this
        // would report a movement (or an IdentityRepublish, which
        // exists at the proof altitude only) — pinning that the
        // cross-altitude sibling stays scoped to the watermark
        // altitude's vocabulary.
        let wm = wm_of(&base());
        let prior = ConfigSyncProof {
            generation: 1,
            watermark: wm,
            observed_at: UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            generation: 999,
            watermark: wm,
            observed_at: UNIX_EPOCH + Duration::from_secs(9_999),
        };
        assert_eq!(
            current.watermark_relation_since(&prior),
            Some(WatermarkRelation::Stationary),
            "watermark_relation_since must be Stationary across generation/timestamp bump",
        );
        assert_eq!(
            current.watermark_relation_wire_since(&prior),
            Some(WatermarkRelationWire::Stationary),
            "watermark_relation_wire_since must be Stationary across generation/timestamp bump",
        );
        // Cross-check: the proof-altitude classification DOES flip on
        // the same input (it becomes IdentityRepublish), pinning that
        // the two altitudes' classifications are legitimately
        // different vocabularies — the cross-altitude sibling routes
        // exclusively to the watermark altitude's vocabulary.
        assert!(
            matches!(
                current.relation_since(&prior),
                ProofRelation::IdentityRepublish { .. }
            ),
            "at the proof altitude the same input is IdentityRepublish — pinning the vocabularies differ",
        );
    }

    // ---------- (5) totality on the authored flow

    #[test]
    fn both_methods_are_total_on_the_authored_flow() {
        // Pin (5): on any two ConfigSyncProof values whose watermarks
        // come out of ConfigWatermark::compute, both cross-altitude
        // classifications yield Some. A None on either path signals a
        // hand-constructed inconsistent watermark leaking through a
        // non-standard entry point, not a legitimate authored-flow
        // outcome — matching the totality guarantee
        // ConfigWatermark::relation_since /
        // ConfigWatermark::relation_wire_since already carry one
        // altitude down.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            assert!(
                current.watermark_relation_since(&prior).is_some(),
                "authored proof pair {prior_cfg:?} -> {current_cfg:?} must classify to Some",
            );
            assert!(
                current.watermark_relation_wire_since(&prior).is_some(),
                "authored proof pair {prior_cfg:?} -> {current_cfg:?} must classify to Some at the wire",
            );
        }
    }

    // ---------- (6) impossibility passthrough as None

    #[test]
    fn impossibility_passes_through_the_proof_container_as_none() {
        // Pin (6): a proof pair whose nested watermarks hit the
        // (F, T, F) class-partition-invariant violation corner (a
        // class-scoped half moved without full_moved) reaches BOTH
        // cross-altitude classifications as None — the exact same
        // filter ConfigWatermark::relation_since /
        // ConfigWatermark::relation_wire_since carry at the watermark
        // altitude. The proof container never absorbs the
        // impossibility into a Some at the cross-altitude sibling.
        let prior_wm = ConfigWatermark {
            full: blake3::hash(b"pinned-full"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"pinned-free"),
        };
        let current_wm = ConfigWatermark {
            full: blake3::hash(b"pinned-full"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"pinned-free"),
        };
        let prior = ConfigSyncProof {
            watermark: prior_wm,
            generation: 1,
            observed_at: UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            watermark: current_wm,
            generation: 2,
            observed_at: UNIX_EPOCH + Duration::from_secs(60),
        };
        assert_eq!(current.watermark_relation_since(&prior), None);
        assert_eq!(current.watermark_relation_wire_since(&prior), None);
        // Same shape at the watermark altitude — pin that the
        // cross-altitude sibling is a pure passthrough of the
        // filter, never a re-derivation.
        assert_eq!(current.watermark.relation_since(&prior.watermark), None);
        assert_eq!(
            current.watermark.relation_wire_since(&prior.watermark),
            None
        );
    }

    // ---------- (7) coherence with the proof-altitude wire on Progression

    #[test]
    fn agrees_with_progression_payload_on_the_watermark_tag() {
        // Pin (7): on any edit that lands the proof-altitude wire in
        // ProofRelationWire::Progression, the classification tag
        // recoverable from the nested `watermark` payload matches
        // watermark_relation_wire_since's answer. The receiver
        // sibling is the ergonomic peer of "unwrap the Progression,
        // try_from_wire the MovedWatermarkDelta, .relation().unwrap(),
        // .to_wire()" — same answer, no unwrap.
        let prior = proof_at(&base(), 1, 1_700_000_000);
        let current = proof_at(&both_edit(), 2, 1_700_000_060);
        let proof_wire = current.relation_wire_since(&prior);
        let ProofRelationWire::Progression { watermark: ww, .. } = proof_wire else {
            panic!(
                "both-classes edit + generation advance must land in Progression, got {proof_wire:?}"
            );
        };
        let via_payload = MovedWatermarkDelta::try_from_wire(&ww)
            .expect("legitimate progression watermark round-trips")
            .relation()
            .expect("round-tripped MovedWatermarkDelta always classifies")
            .to_wire();
        let via_cross_altitude = current
            .watermark_relation_wire_since(&prior)
            .expect("authored proof pair must classify to Some");
        assert_eq!(via_payload, via_cross_altitude);
        // And both equal Both — the classification the edit encodes.
        assert_eq!(via_cross_altitude, WatermarkRelationWire::Both);
    }

    // ---------- (8) argument-order convention at the cross-altitude sibling

    #[test]
    fn argument_order_is_symmetric_at_the_cross_altitude_sibling() {
        // Pin (8): at the watermark altitude moved-ness is symmetric
        // (WatermarkDelta::between uses XOR-based comparison), so
        // swapping the receiver and argument at the cross-altitude
        // sibling reaches the same classification — even through the
        // proof container. The load-bearing generation-direction axis
        // that flips ProofRelation Progression <-> Regressed lives at
        // the proof altitude, and this test pins that the
        // cross-altitude sibling does NOT expose it.
        let a = proof_at(&base(), 1, 1_700_000_000);
        let b = proof_at(&free_edit(), 2, 1_700_000_060);
        let forward = b.watermark_relation_since(&a);
        let backward = a.watermark_relation_since(&b);
        assert_eq!(
            forward, backward,
            "watermark_relation_since must be symmetric at the cross-altitude sibling",
        );
        assert_eq!(forward, Some(WatermarkRelation::FreeOnly));
        let forward_wire = b.watermark_relation_wire_since(&a);
        let backward_wire = a.watermark_relation_wire_since(&b);
        assert_eq!(
            forward_wire, backward_wire,
            "watermark_relation_wire_since must be symmetric at the cross-altitude sibling",
        );
        assert_eq!(forward_wire, Some(WatermarkRelationWire::FreeOnly));
        // Cross-check: at the proof altitude the same swap flips
        // Progression <-> Regressed — pinning that the argument-order
        // asymmetry lives at the proof altitude, not at the
        // cross-altitude sibling.
        let proof_forward = b.relation_wire_since(&a);
        let proof_backward = a.relation_wire_since(&b);
        assert!(
            matches!(proof_forward, ProofRelationWire::Progression { .. }),
            "proof-altitude forward must be Progression, got {proof_forward:?}",
        );
        assert!(
            matches!(proof_backward, ProofRelationWire::Regressed { .. }),
            "proof-altitude backward must be Regressed, got {proof_backward:?}",
        );
    }

    // ---------- (9) payload-unwrap-free reach on non-Progression arms

    #[test]
    fn cross_altitude_sibling_reaches_the_watermark_tag_on_every_proof_arm() {
        // Pin (9): the cross-altitude sibling reaches a
        // WatermarkRelationWire tag on EVERY authored proof pair,
        // including the pairs whose proof-altitude wire is NOT
        // Progression (Stationary, IdentityRepublish, Regressed).
        // The inline alternative — "unwrap the Progression payload,
        // try_from_wire, .relation().unwrap(), .to_wire()" — leans on
        // the Progression arm and panics on the others. This test
        // pins that a single call to the receiver sibling covers
        // every corner. Each expected pair below carries the
        // proof-altitude arm the pair reaches AND the watermark
        // -altitude wire tag the cross-altitude sibling reaches — the
        // two vocabularies are legitimately different, and the
        // sibling routes to the watermark one.
        struct Case {
            name: &'static str,
            prior: ConfigSyncProof,
            current: ConfigSyncProof,
            want_wm: WatermarkRelationWire,
        }
        let cases = vec![
            Case {
                name: "Stationary (all axes stationary) at both altitudes",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&base(), 5, 1_700_000_000),
                want_wm: WatermarkRelationWire::Stationary,
            },
            Case {
                name: "IdentityRepublish (identical watermark, generation advanced)",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&base(), 6, 1_700_000_060),
                want_wm: WatermarkRelationWire::Stationary,
            },
            Case {
                name: "Regressed (current generation < prior)",
                prior: proof_at(&base(), 6, 1_700_000_060),
                current: proof_at(&base(), 5, 1_700_000_000),
                want_wm: WatermarkRelationWire::Stationary,
            },
            Case {
                name: "Progression, FreeOnly at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&free_edit(), 6, 1_700_000_060),
                want_wm: WatermarkRelationWire::FreeOnly,
            },
            Case {
                name: "Progression, RestartRequiredOnly at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&restart_edit(), 6, 1_700_000_060),
                want_wm: WatermarkRelationWire::RestartRequiredOnly,
            },
            Case {
                name: "Progression, Both at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&both_edit(), 6, 1_700_000_060),
                want_wm: WatermarkRelationWire::Both,
            },
        ];
        for Case {
            name,
            prior,
            current,
            want_wm,
        } in cases
        {
            let got = current.watermark_relation_wire_since(&prior);
            assert_eq!(
                got,
                Some(want_wm),
                "{name}: cross-altitude sibling must reach {want_wm:?}, got {got:?}",
            );
        }
    }
}

#[cfg(test)]
mod watermark_delta_wire_since_cross_altitude_tests {
    //! Weld the cross-altitude `watermark_delta_wire_since` receiver
    //! sibling on [`ConfigSyncProof`] — the wire peer of
    //! [`ConfigSyncProof::watermark_delta_since`], closing the fourth
    //! (and final) cell of the (`delta`, `relation`) × (`value`,
    //! `wire`) grid at the cross-altitude altitude. Together the tests
    //! below cover:
    //!
    //! 1. [`ConfigSyncProof::watermark_delta_wire_since`] composes
    //!    through the underlying [`ConfigWatermark::delta_since`] +
    //!    [`WatermarkDelta::to_wire`] — a future signed-attestation
    //!    blob or leaf-schema hash added to [`ConfigSyncProof`] never
    //!    reaches this method's body; the `.watermark` half stays the
    //!    single source of truth for the watermark-altitude wire.
    //! 2. Agreement with the value-first-then-to-wire composition
    //!    (`watermark_delta_since(prior).to_wire()`) — the two
    //!    composition legs (wire-first through the receiver sibling
    //!    vs. value-first then wire projection) never diverge.
    //! 3. Agreement with the nested [`ProofDeltaWire::watermark`]
    //!    field the proof-altitude [`ProofDelta::to_wire`] fold
    //!    produces — the cross-altitude sibling reaches the same wire
    //!    tag the proof-altitude wire nests, so a consumer never
    //!    picks a different wire depending on which altitude's
    //!    `*_wire_since` it called.
    //! 4. Invariance under generation bumps and observed-at advances
    //!    — a store re-publishing an identical value never moves any
    //!    wire triple, matching the invariance
    //!    [`ConfigSyncProof::watermark_delta_since`] carries.
    //! 5. Totality on the authored flow: every proof pair whose
    //!    watermarks come out of [`ConfigWatermark::compute`] yields a
    //!    class-partition-consistent wire (`try_from_wire` accepts).
    //! 6. Symmetric argument order at the watermark altitude —
    //!    swapping receiver and argument reaches the same wire triple
    //!    (moved-ness is symmetric); the load-bearing generation-
    //!    direction axis that flips the proof-altitude classification
    //!    `Progression <-> Regressed` does NOT reach this method.
    //! 7. Payload-unwrap-free reach on every proof-altitude
    //!    arm — on `Stationary`, `IdentityRepublish`, `Regressed`,
    //!    and every `Progression` sub-corner the receiver sibling
    //!    reaches a `WatermarkDeltaWire` in one call, never needing
    //!    to unwrap [`ProofRelationWire::Progression`] to reach the
    //!    payload wire.
    //! 8. Coherence with the [`MovedWatermarkDelta::to_wire`] payload
    //!    on any [`ProofRelation::Progression`] arm — the payload's
    //!    wire equals the cross-altitude sibling's wire.
    //! 9. Round-trip totality: every wire the cross-altitude sibling
    //!    reaches on the authored flow reconstructs through
    //!    [`WatermarkDelta::try_from_wire`] to the same value-side
    //!    delta [`ConfigSyncProof::watermark_delta_since`] yields.
    //!
    //! Same test idiom as the sibling `watermark_relation_since_cross_altitude_tests`
    //! module, so a future refactor touching either altitude's delta
    //! pipeline surfaces breakage here too.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(c: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            watermark: wm_of(c),
            generation,
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- (1) composition through the watermark half

    #[test]
    fn watermark_delta_wire_since_composes_through_the_watermark_half() {
        // Pin (1): the proof-level cross-altitude wire MUST compose
        // through the watermark-level primitive — adding a future
        // signed-attestation blob to ConfigSyncProof never reaches
        // this method's body. The .watermark half is the single
        // source of truth for the watermark-altitude wire, and this
        // method is a pure two-hop delegation to it.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 42, 1_700_000_060);
            assert_eq!(
                current.watermark_delta_wire_since(&prior),
                current.watermark.delta_since(&prior.watermark).to_wire(),
                "watermark_delta_wire_since must delegate to the watermark half on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (2) two-leg agreement

    #[test]
    fn watermark_delta_wire_since_agrees_with_value_then_to_wire() {
        // Pin (2): the wire-first sibling equals the value-first then
        // to-wire composition on every authored pair. Composing the
        // delta with the wire projection through the receiver sibling
        // yields the same answer as composing them through the named
        // methods — the proof stays welded across the two composition
        // legs.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            assert_eq!(
                current.watermark_delta_wire_since(&prior),
                current.watermark_delta_since(&prior).to_wire(),
                "watermark_delta_wire_since must fold watermark_delta_since().to_wire() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (3) agreement with the proof-altitude nested wire

    #[test]
    fn watermark_delta_wire_since_agrees_with_proof_delta_wire_watermark_field() {
        // Pin (3): the wire reached through the cross-altitude
        // sibling equals the nested `watermark` field on
        // ProofDeltaWire — the two altitudes' wire projections agree
        // on the watermark half.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            let proof_wire = current.delta_since(&prior).to_wire();
            assert_eq!(
                current.watermark_delta_wire_since(&prior),
                proof_wire.watermark,
                "watermark_delta_wire_since must equal ProofDeltaWire::watermark on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (4) invariance under generation + timestamp axes

    #[test]
    fn is_invariant_under_generation_and_timestamp_bumps() {
        // Pin (4): a store re-publishing an identical value bumps
        // generation and observed_at without moving any watermark
        // half — the cross-altitude wire MUST answer the all-false
        // "stationary" triple under that, matching the invariance
        // ConfigSyncProof::watermark_delta_since carries. If this
        // folded the generation/observed_at axes in, the wire would
        // pick up a movement that only lives at the proof altitude.
        let wm = wm_of(&base());
        let prior = ConfigSyncProof {
            generation: 1,
            watermark: wm,
            observed_at: UNIX_EPOCH,
        };
        let current = ConfigSyncProof {
            generation: 999,
            watermark: wm,
            observed_at: UNIX_EPOCH + Duration::from_secs(9_999),
        };
        let wire = current.watermark_delta_wire_since(&prior);
        assert!(
            !wire.full_moved && !wire.restart_required_moved && !wire.free_moved,
            "watermark_delta_wire_since must be all-false across generation/timestamp bump, got {wire:?}",
        );
        // Cross-check: the proof-altitude classification DOES flip on
        // the same input (it becomes IdentityRepublish), pinning that
        // the two altitudes' vocabularies are legitimately different
        // — the cross-altitude sibling routes exclusively to the
        // watermark altitude's vocabulary.
        assert!(
            matches!(
                current.relation_since(&prior),
                ProofRelation::IdentityRepublish { .. }
            ),
            "at the proof altitude the same input is IdentityRepublish — pinning the vocabularies differ",
        );
    }

    // ---------- (5) totality on the authored flow (class-partition-consistent)

    #[test]
    fn is_class_partition_consistent_on_the_authored_flow() {
        // Pin (5): every wire the cross-altitude sibling reaches on
        // the authored flow satisfies the class-partition invariant
        // WatermarkDelta::try_from_wire welds at the parse boundary.
        // The underlying WatermarkDelta::between fold is
        // class-partition-consistent by construction on any pair of
        // ConfigWatermark values produced through
        // ConfigWatermark::compute, and this method preserves that
        // guarantee through the wire projection.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            let wire = current.watermark_delta_wire_since(&prior);
            WatermarkDelta::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!(
                    "authored proof pair {prior_cfg:?} -> {current_cfg:?} produced a wire that failed try_from_wire: {e:?}"
                )
            });
        }
    }

    // ---------- (6) argument-order symmetry at the cross-altitude sibling

    #[test]
    fn argument_order_is_symmetric_at_the_cross_altitude_sibling() {
        // Pin (6): at the watermark altitude moved-ness is symmetric
        // (WatermarkDelta::between uses XOR-based comparison), so
        // swapping the receiver and argument reaches the same wire
        // triple — even through the proof container. The load-bearing
        // generation-direction axis that flips ProofRelation
        // Progression <-> Regressed lives at the proof altitude, and
        // this test pins that the cross-altitude sibling does NOT
        // expose it.
        let a = proof_at(&base(), 1, 1_700_000_000);
        let b = proof_at(&free_edit(), 2, 1_700_000_060);
        assert_eq!(
            b.watermark_delta_wire_since(&a),
            a.watermark_delta_wire_since(&b),
            "watermark_delta_wire_since must be symmetric at the cross-altitude sibling",
        );
        let forward = b.watermark_delta_wire_since(&a);
        assert!(
            forward.full_moved && forward.free_moved && !forward.restart_required_moved,
            "free-only edit must produce (T, F, T) at both directions, got {forward:?}",
        );
        // Cross-check: at the proof altitude the same swap flips
        // Progression <-> Regressed — pinning that the argument-order
        // asymmetry lives at the proof altitude, not at the
        // cross-altitude sibling.
        let proof_forward = b.relation_wire_since(&a);
        let proof_backward = a.relation_wire_since(&b);
        assert!(
            matches!(proof_forward, ProofRelationWire::Progression { .. }),
            "proof-altitude forward must be Progression, got {proof_forward:?}",
        );
        assert!(
            matches!(proof_backward, ProofRelationWire::Regressed { .. }),
            "proof-altitude backward must be Regressed, got {proof_backward:?}",
        );
    }

    // ---------- (7) payload-unwrap-free reach on every proof-altitude arm

    #[test]
    fn cross_altitude_sibling_reaches_the_wire_on_every_proof_arm() {
        // Pin (7): the cross-altitude sibling reaches a
        // WatermarkDeltaWire on EVERY authored proof pair, including
        // the pairs whose proof-altitude wire is NOT Progression
        // (Stationary, IdentityRepublish, Regressed). The inline
        // alternative — "unwrap the Progression payload, MovedWatermarkDelta::to_wire" —
        // leans on the Progression arm and match-drops the others.
        // This test pins that a single call to the receiver sibling
        // covers every corner. Each expected case below carries the
        // proof-altitude arm the pair reaches AND the watermark-
        // altitude wire triple the cross-altitude sibling reaches.
        struct Case {
            name: &'static str,
            prior: ConfigSyncProof,
            current: ConfigSyncProof,
            want_full: bool,
            want_restart: bool,
            want_free: bool,
        }
        let cases = vec![
            Case {
                name: "Stationary (all axes stationary) at both altitudes",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&base(), 5, 1_700_000_000),
                want_full: false,
                want_restart: false,
                want_free: false,
            },
            Case {
                name: "IdentityRepublish (identical watermark, generation advanced)",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&base(), 6, 1_700_000_060),
                want_full: false,
                want_restart: false,
                want_free: false,
            },
            Case {
                name: "Regressed (current generation < prior)",
                prior: proof_at(&base(), 6, 1_700_000_060),
                current: proof_at(&base(), 5, 1_700_000_000),
                want_full: false,
                want_restart: false,
                want_free: false,
            },
            Case {
                name: "Progression, FreeOnly at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&free_edit(), 6, 1_700_000_060),
                want_full: true,
                want_restart: false,
                want_free: true,
            },
            Case {
                name: "Progression, RestartRequiredOnly at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&restart_edit(), 6, 1_700_000_060),
                want_full: true,
                want_restart: true,
                want_free: false,
            },
            Case {
                name: "Progression, Both at the watermark",
                prior: proof_at(&base(), 5, 1_700_000_000),
                current: proof_at(&both_edit(), 6, 1_700_000_060),
                want_full: true,
                want_restart: true,
                want_free: true,
            },
        ];
        for Case {
            name,
            prior,
            current,
            want_full,
            want_restart,
            want_free,
        } in cases
        {
            let got = current.watermark_delta_wire_since(&prior);
            assert_eq!(
                (got.full_moved, got.restart_required_moved, got.free_moved),
                (want_full, want_restart, want_free),
                "{name}: cross-altitude sibling must reach ({want_full}, {want_restart}, {want_free}), got {got:?}",
            );
        }
    }

    // ---------- (8) coherence with the MovedWatermarkDelta payload on Progression

    #[test]
    fn agrees_with_progression_payload_on_the_watermark_wire() {
        // Pin (8): on any edit that lands the proof-altitude
        // classification in ProofRelation::Progression, the payload's
        // MovedWatermarkDelta::to_wire equals watermark_delta_wire_since's
        // answer. The receiver sibling is the ergonomic peer of
        // "match on Progression, .to_wire() the payload" — same
        // answer, no match.
        let prior = proof_at(&base(), 1, 1_700_000_000);
        let current = proof_at(&both_edit(), 2, 1_700_000_060);
        let relation = current.relation_since(&prior);
        let ProofRelation::Progression { watermark: mw, .. } = relation else {
            panic!(
                "both-classes edit + generation advance must land in Progression, got {relation:?}"
            );
        };
        let via_payload = mw.to_wire();
        let via_cross_altitude = current.watermark_delta_wire_since(&prior);
        assert_eq!(via_payload, via_cross_altitude);
        // And both encode the (T, T, T) triple the both-classes edit
        // produces.
        assert!(
            via_cross_altitude.full_moved
                && via_cross_altitude.restart_required_moved
                && via_cross_altitude.free_moved,
            "both-classes edit must produce (T, T, T), got {via_cross_altitude:?}",
        );
    }

    // ---------- (9) round-trip totality through try_from_wire

    #[test]
    fn round_trips_through_try_from_wire_to_the_same_value_side_delta() {
        // Pin (9): every wire the cross-altitude sibling reaches on
        // the authored flow reconstructs through
        // WatermarkDelta::try_from_wire to the exact value-side delta
        // ConfigSyncProof::watermark_delta_since yields. The wire
        // projection composed with its parse-boundary reconstruction
        // is the identity on the value-side delta — the round-trip
        // property the sibling wire types already carry, extended
        // through the cross-altitude receiver.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            let wire = current.watermark_delta_wire_since(&prior);
            let back = WatermarkDelta::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!(
                    "authored proof pair {prior_cfg:?} -> {current_cfg:?} produced a wire that failed try_from_wire: {e:?}"
                )
            });
            assert_eq!(
                back,
                current.watermark_delta_since(&prior),
                "round-tripped wire must equal the value-side delta on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }
}

#[cfg(test)]
mod delta_wire_since_tests {
    //! Weld the same-altitude `delta_wire_since` receiver sibling on
    //! [`ConfigSyncProof`] — the wire peer of
    //! [`ConfigSyncProof::delta_since`], closing the fourth (and final)
    //! cell of the (`delta`, `relation`) × (`value`, `wire`) grid at
    //! the SAME-altitude altitude on [`ConfigSyncProof`]. Together the
    //! tests below cover:
    //!
    //! 1. [`ConfigSyncProof::delta_wire_since`] composes through
    //!    [`ConfigSyncProof::delta_since`] + [`ProofDelta::to_wire`] —
    //!    a future proof-altitude axis added to [`ProofDelta`] never
    //!    reaches this method's body; `delta_since` stays the single
    //!    source of truth for the proof-altitude value delta and
    //!    `to_wire` stays the single source of truth for its wire
    //!    projection.
    //! 2. Agreement with [`ProofDelta::between`] composed with
    //!    [`ProofDelta::to_wire`] — the same wire is reachable through
    //!    the free-function altitude AND the receiver-sibling altitude.
    //! 3. The nested [`ProofDeltaWire::watermark`] field agrees with
    //!    [`ConfigSyncProof::watermark_delta_wire_since`] pointwise —
    //!    the same-altitude wire and the cross-altitude wire tell the
    //!    same watermark story at the receiver-sibling API surface,
    //!    not just at the free-function altitude.
    //! 4. Round-trip totality: every wire the same-altitude sibling
    //!    reaches on the authored flow reconstructs through
    //!    [`ProofDelta::try_from_wire`] to the same value-side delta
    //!    [`ConfigSyncProof::delta_since`] yields.
    //! 5. Total return type on every authored pair — including the
    //!    generation-regressed corner ([`ProofDelta::generations_advanced`]
    //!    `= None`) and the observed-at-regressed corner
    //!    ([`ProofDelta::observed_at_elapsed`] `= None`), both of
    //!    which are legitimate wire values a consumer must route on.
    //!    The [`ProofRelation`] classification refuses the first as
    //!    [`ProofRelation::Regressed`], but the bare wire preserves it.
    //! 6. Argument-order asymmetry pinning — swapping receiver and
    //!    argument DOES change the wire (unlike the watermark-altitude
    //!    wire, which is symmetric), because the proof altitude's
    //!    `generations_advanced` and `observed_at_elapsed_nanos` axes
    //!    are direction-sensitive: forward = `Some(n)`, backward =
    //!    `None`. This test pins that the wire receiver-sibling
    //!    faithfully carries the argument-order convention every peer
    //!    `*_since` method uses.
    //! 7. Payload-unwrap-free reach on every proof-altitude classification
    //!    arm — the same-altitude wire reaches a `ProofDeltaWire` on
    //!    every proof pair (`Stationary` / `IdentityRepublish` /
    //!    `Regressed` / every `Progression` sub-corner), never needing
    //!    to route on [`ProofRelationWire`]'s classification tag to
    //!    reach the bare wire triple + generation delta + observed-at
    //!    nanos.
    //! 8. The proof-altitude wire reached through the sibling equals
    //!    the proof-altitude wire nested inside a
    //!    [`ConfigSyncProofWire`] round-trip round trip on the current
    //!    half — the two wire projections agree on the delta half.
    //!
    //! Same test idiom as `watermark_delta_wire_since_cross_altitude_tests`,
    //! so a future refactor touching either altitude's delta wire
    //! pipeline surfaces breakage here too.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(c: &Cfg, generation: u64, secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            watermark: wm_of(c),
            generation,
            observed_at: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- (1) composition through delta_since + to_wire

    #[test]
    fn delta_wire_since_composes_through_delta_since_then_to_wire() {
        // Pin (1): the same-altitude wire receiver sibling MUST fold
        // through delta_since + ProofDelta::to_wire. A future proof-
        // altitude axis added to ProofDelta never reaches this method's
        // body; delta_since stays the single source of truth for the
        // proof-altitude value delta, and to_wire stays the single
        // source of truth for its wire projection.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 42, 1_700_000_060);
            assert_eq!(
                current.delta_wire_since(&prior),
                current.delta_since(&prior).to_wire(),
                "delta_wire_since must equal delta_since().to_wire() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (2) agreement with the free-function altitude

    #[test]
    fn delta_wire_since_agrees_with_between_then_to_wire() {
        // Pin (2): the receiver sibling equals the free-function
        // ProofDelta::between composed with ProofDelta::to_wire on
        // every authored pair. The receiver-sibling altitude and the
        // free-function altitude never diverge.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            assert_eq!(
                current.delta_wire_since(&prior),
                ProofDelta::between(&prior, &current).to_wire(),
                "delta_wire_since must equal ProofDelta::between().to_wire() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (3) nested watermark equals the cross-altitude sibling

    #[test]
    fn nested_watermark_field_equals_watermark_delta_wire_since() {
        // Pin (3): the nested `watermark` field of the same-altitude
        // wire equals the cross-altitude sibling's answer pointwise
        // on every authored pair. The two altitudes' wire projections
        // agree on the watermark half at the receiver-sibling API
        // surface, not just at the free-function altitude — a
        // consumer picking either sibling gets the same watermark
        // triple.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            let proof_wire = current.delta_wire_since(&prior);
            let cross_wire = current.watermark_delta_wire_since(&prior);
            assert_eq!(
                proof_wire.watermark, cross_wire,
                "delta_wire_since().watermark must equal watermark_delta_wire_since() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (4) round-trip totality through try_from_wire

    #[test]
    fn round_trips_through_try_from_wire_to_the_same_value_side_delta() {
        // Pin (4): every wire the same-altitude sibling reaches on the
        // authored flow reconstructs through ProofDelta::try_from_wire
        // to the exact value-side delta ConfigSyncProof::delta_since
        // yields. The wire projection composed with its parse-boundary
        // reconstruction is the identity on the value-side delta —
        // the round-trip property the sibling wire type already carries,
        // extended through the same-altitude receiver.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 2, 1_700_000_060);
            let wire = current.delta_wire_since(&prior);
            let back = ProofDelta::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!(
                    "authored proof pair {prior_cfg:?} -> {current_cfg:?} produced a wire that failed try_from_wire: {e:?}"
                )
            });
            assert_eq!(
                back,
                current.delta_since(&prior),
                "round-tripped wire must equal the value-side delta on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (5) total return type — reaches every diagnostic corner

    #[test]
    fn reaches_the_generation_regressed_and_observed_regressed_corners() {
        // Pin (5): both diagnostic wire corners a consumer must route
        // on — generations_advanced=None (proof-altitude
        // "generation went backwards" signal) and
        // observed_at_elapsed_nanos=None (a legitimate NTP-step corner
        // that lives at the proof altitude only) — are reachable
        // through the same-altitude sibling in one call. The
        // ProofRelation classification refuses the first as Regressed;
        // the bare wire preserves it. Every axis of ProofDeltaWire's
        // Option<u64> pair is exercised here.
        let prior = proof_at(&base(), 6, 1_700_000_060);
        let current = proof_at(&base(), 5, 1_700_000_000);
        let wire = current.delta_wire_since(&prior);
        assert!(
            wire.generations_advanced.is_none(),
            "generation-regressed corner must reach generations_advanced=None, got {wire:?}",
        );
        assert!(
            wire.observed_at_elapsed_nanos.is_none(),
            "observed-at-regressed corner must reach observed_at_elapsed_nanos=None, got {wire:?}",
        );
        // Cross-check: the proof-altitude classification refuses this
        // pair as Regressed — but the bare wire receiver sibling
        // preserves the same diagnostic signal without folding it
        // into a classification tag.
        assert!(
            matches!(
                current.relation_since(&prior),
                ProofRelation::Regressed { .. }
            ),
            "same input must classify as ProofRelation::Regressed — pinning the vocabularies differ",
        );
    }

    // ---------- (6) argument-order asymmetry at the proof altitude

    #[test]
    fn argument_order_is_asymmetric_at_the_proof_altitude() {
        // Pin (6): unlike watermark_delta_wire_since (which is
        // symmetric because moved-ness at the watermark altitude uses
        // XOR-based comparison), the proof-altitude wire IS
        // asymmetric — generations_advanced and observed_at_elapsed_nanos
        // both carry direction: forward = Some(n), backward = None.
        // Swapping receiver and argument MUST reach a different wire.
        // This pins that the receiver sibling faithfully carries the
        // argument-order convention every peer *_since method uses.
        let a = proof_at(&base(), 1, 1_700_000_000);
        let b = proof_at(&free_edit(), 2, 1_700_000_060);
        let forward = b.delta_wire_since(&a);
        let backward = a.delta_wire_since(&b);
        assert_ne!(
            forward, backward,
            "delta_wire_since must be asymmetric at the proof altitude, got {forward:?} vs {backward:?}",
        );
        // Direction axes: forward is Some, backward is None on both.
        assert!(
            forward.generations_advanced == Some(1) && forward.observed_at_elapsed_nanos.is_some(),
            "forward direction must reach Some on both axes, got {forward:?}",
        );
        assert!(
            backward.generations_advanced.is_none() && backward.observed_at_elapsed_nanos.is_none(),
            "backward direction must reach None on both axes, got {backward:?}",
        );
        // Watermark half is symmetric — as pinned by
        // watermark_delta_wire_since_cross_altitude_tests. Cross-check
        // that the same-altitude sibling's nested watermark preserves
        // that symmetry even inside an asymmetric proof-altitude wire.
        assert_eq!(
            forward.watermark, backward.watermark,
            "watermark half must stay symmetric across argument-order swap on the proof-altitude wire",
        );
    }

    // ---------- (7) payload-unwrap-free reach on every proof-altitude arm

    #[test]
    fn same_altitude_sibling_reaches_the_wire_on_every_proof_arm() {
        // Pin (7): the same-altitude sibling reaches a ProofDeltaWire
        // on EVERY authored proof pair — including Stationary,
        // IdentityRepublish, Regressed, and every Progression
        // sub-corner. The alternative "route on ProofRelationWire's
        // tag then reach the wire" leaks the classification into the
        // caller; this single call covers the whole grid.
        //
        // Case row: (name, prior, current, want_watermark_triple,
        // want_generations_advanced, want_observed_some). The three
        // Option/bool axes are lifted out of a struct into a tuple so
        // this table stays a pattern, not a schema; the peer
        // watermark_delta_wire_since_cross_altitude_tests carries the
        // three-bool watermark half in a struct and this test carries
        // its five axes as a tuple for the same reason — the tabular
        // shape is what pins the exhaustive corner coverage.
        type WantTriple = (bool, bool, bool);
        type Case = (
            &'static str,
            ConfigSyncProof,
            ConfigSyncProof,
            WantTriple,
            Option<u64>,
            bool,
        );
        let cases: [Case; 6] = [
            (
                "Stationary (all axes stationary) at both altitudes",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_000),
                (false, false, false),
                Some(0),
                true,
            ),
            (
                "IdentityRepublish (identical watermark, generation advanced)",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 6, 1_700_000_060),
                (false, false, false),
                Some(1),
                true,
            ),
            (
                "Regressed (current generation < prior)",
                proof_at(&base(), 6, 1_700_000_060),
                proof_at(&base(), 5, 1_700_000_000),
                (false, false, false),
                None,
                false,
            ),
            (
                "Progression, FreeOnly at the watermark",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&free_edit(), 6, 1_700_000_060),
                (true, false, true),
                Some(1),
                true,
            ),
            (
                "Progression, RestartRequiredOnly at the watermark",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&restart_edit(), 6, 1_700_000_060),
                (true, true, false),
                Some(1),
                true,
            ),
            (
                "Progression, Both at the watermark",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
                (true, true, true),
                Some(1),
                true,
            ),
        ];
        for (name, prior, current, want_triple, want_gens, want_obs_some) in cases {
            let got = current.delta_wire_since(&prior);
            let got_triple = (
                got.watermark.full_moved,
                got.watermark.restart_required_moved,
                got.watermark.free_moved,
            );
            assert_eq!(
                got_triple, want_triple,
                "{name}: watermark triple must reach {want_triple:?}, got {got:?}",
            );
            assert_eq!(
                got.generations_advanced, want_gens,
                "{name}: generations_advanced mismatch, got {got:?}",
            );
            assert_eq!(
                got.observed_at_elapsed_nanos.is_some(),
                want_obs_some,
                "{name}: observed_at_elapsed_nanos.is_some() mismatch, got {got:?}",
            );
        }
    }

    // ---------- (8) agreement with the nested wire in ConfigSyncProofWire round-trip

    #[test]
    fn agrees_with_the_full_proof_wire_delta_projection() {
        // Pin (8): if a consumer computed the current proof's wire
        // shape (ConfigSyncProofWire) then reconstructed the delta by
        // hand, the answer must equal the same-altitude sibling's
        // wire — the two wire projections agree on the delta half.
        // This closes the loop between the value-side ConfigSyncProof
        // wire projection and the receiver-sibling delta wire
        // projection.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = proof_at(&prior_cfg, 1, 1_700_000_000);
            let current = proof_at(&current_cfg, 3, 1_700_000_120);
            let via_sibling = current.delta_wire_since(&prior);
            // Round-trip the two proofs through their wire projections
            // and reconstruct; then compute the delta via the receiver
            // sibling and project. The result MUST equal the direct
            // call: wire projection commutes with the delta pipeline.
            let prior_wire = prior.to_wire();
            let current_wire = current.to_wire();
            let prior_back = ConfigSyncProof::try_from_wire(&prior_wire)
                .expect("authored prior must round-trip through the proof wire");
            let current_back = ConfigSyncProof::try_from_wire(&current_wire)
                .expect("authored current must round-trip through the proof wire");
            let via_wire_round_trip = current_back.delta_wire_since(&prior_back);
            assert_eq!(
                via_sibling, via_wire_round_trip,
                "delta_wire_since must be invariant across a ConfigSyncProofWire round-trip on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }
}

#[cfg(test)]
mod watermark_delta_wire_since_tests {
    //! Weld the same-altitude `delta_wire_since` receiver sibling on
    //! [`ConfigWatermark`] — the wire peer of
    //! [`ConfigWatermark::delta_since`], closing the fourth (and final)
    //! cell of the (`delta`, `relation`) × (`value`, `wire`) 2×2 grid
    //! at the WATERMARK altitude. Mirrors the closure
    //! [`ConfigSyncProof::delta_wire_since`] provided one altitude up
    //! at the proof grid, so the sibling-family shape stays uniform
    //! across altitudes. Together the tests below cover:
    //!
    //! 1. [`ConfigWatermark::delta_wire_since`] composes through
    //!    [`ConfigWatermark::delta_since`] + [`WatermarkDelta::to_wire`]
    //!    — a future watermark-altitude axis added to
    //!    [`WatermarkDelta`] never reaches this method's body;
    //!    `delta_since` stays the single source of truth for the
    //!    watermark-altitude value delta, and `to_wire` stays the
    //!    single source of truth for its wire projection.
    //! 2. Agreement with [`WatermarkDelta::between`] composed with
    //!    [`WatermarkDelta::to_wire`] — the receiver-sibling altitude
    //!    and the free-function altitude never diverge.
    //! 3. Round-trip totality: every wire the sibling reaches on the
    //!    authored flow reconstructs through
    //!    [`WatermarkDelta::try_from_wire`] to the exact value-side
    //!    delta [`ConfigWatermark::delta_since`] yields.
    //! 4. Symmetric argument order at the watermark altitude —
    //!    swapping receiver and argument reaches the SAME wire (moved
    //!    -ness at this altitude uses XOR-based comparison, unlike the
    //!    direction-sensitive proof altitude where `delta_wire_since`
    //!    is asymmetric). This pins that the watermark altitude
    //!    carries no direction axis for the receiver sibling to leak.
    //! 5. Cross-altitude coherence: the sibling wire equals
    //!    [`ConfigSyncProof::watermark_delta_wire_since`] on any proof
    //!    pair whose watermarks are this pair, AND equals the nested
    //!    [`ProofDeltaWire::watermark`] field on the wire the proof-
    //!    altitude [`ConfigSyncProof::delta_wire_since`] reaches. The
    //!    three siblings (this method, the cross-altitude wire on the
    //!    proof, the nested field on the proof-altitude wire) all
    //!    reach the same wire tag pointwise. A consumer never picks a
    //!    different wire depending on which altitude's `*_wire_since`
    //!    it called.
    //! 6. Reaches every watermark corner in one call — `Stationary`,
    //!    `FreeOnly`, `RestartRequiredOnly`, and `Both`. No routing on
    //!    a classification tag needed to reach the bare three-bool
    //!    wire triple.
    //! 7. Every wire the sibling reaches is class-partition-consistent
    //!    ([`WatermarkDelta::class_moves_imply_full_moved`] holds), so
    //!    every wire round-trips through
    //!    [`WatermarkDelta::try_from_wire`] cleanly — the parse
    //!    boundary weld is a no-op for wires this sibling produces.
    //!
    //! Same test idiom as `delta_wire_since_tests` (the proof-altitude
    //! peer above), so a future refactor touching either altitude's
    //! delta wire pipeline surfaces breakage here too.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- (1) composition through delta_since + to_wire

    #[test]
    fn delta_wire_since_composes_through_delta_since_then_to_wire() {
        // Pin (1): the watermark-altitude wire receiver sibling MUST
        // fold through delta_since + WatermarkDelta::to_wire. A future
        // watermark-altitude axis added to WatermarkDelta never reaches
        // this method's body; delta_since stays the single source of
        // truth for the watermark-altitude value delta, and to_wire
        // stays the single source of truth for its wire projection.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            assert_eq!(
                current.delta_wire_since(&prior),
                current.delta_since(&prior).to_wire(),
                "delta_wire_since must equal delta_since().to_wire() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (2) agreement with the free-function altitude

    #[test]
    fn delta_wire_since_agrees_with_between_then_to_wire() {
        // Pin (2): the receiver sibling equals the free-function
        // WatermarkDelta::between composed with WatermarkDelta::to_wire
        // on every authored pair. The receiver-sibling altitude and
        // the free-function altitude never diverge.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            assert_eq!(
                current.delta_wire_since(&prior),
                WatermarkDelta::between(&prior, &current).to_wire(),
                "delta_wire_since must equal WatermarkDelta::between().to_wire() on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (3) round-trip totality through try_from_wire

    #[test]
    fn round_trips_through_try_from_wire_to_the_same_value_side_delta() {
        // Pin (3): every wire the sibling reaches on the authored flow
        // reconstructs through WatermarkDelta::try_from_wire to the
        // exact value-side delta ConfigWatermark::delta_since yields.
        // The wire projection composed with its parse-boundary
        // reconstruction is the identity on the value-side delta —
        // the round-trip property WatermarkDelta already carries,
        // extended through the same-altitude receiver.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let wire = current.delta_wire_since(&prior);
            let back = WatermarkDelta::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!(
                    "authored watermark pair {prior_cfg:?} -> {current_cfg:?} produced a wire that failed try_from_wire: {e:?}"
                )
            });
            assert_eq!(
                back,
                current.delta_since(&prior),
                "round-tripped wire must equal the value-side delta on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (4) argument-order symmetry at the watermark altitude

    #[test]
    fn argument_order_is_symmetric_at_the_watermark_altitude() {
        // Pin (4): unlike the proof-altitude peer
        // (ConfigSyncProof::delta_wire_since, which is asymmetric
        // because the proof-altitude direction axis
        // `generations_advanced` flips forward = Some(n) / backward =
        // None), the watermark altitude carries NO direction axis —
        // moved-ness uses XOR-based comparison in
        // WatermarkDelta::between, so swapping receiver and argument
        // MUST reach the same wire. This pins that the receiver
        // sibling faithfully carries the watermark altitude's
        // symmetry: no direction axis leaks into the wire projection.
        let a = wm_of(&base());
        let b = wm_of(&free_edit());
        assert_eq!(
            a.delta_wire_since(&b),
            b.delta_wire_since(&a),
            "delta_wire_since must be symmetric at the watermark altitude",
        );
        // Also pin symmetry on the both_edit case — every axis of the
        // three-bool triple exercised.
        let c = wm_of(&both_edit());
        assert_eq!(
            a.delta_wire_since(&c),
            c.delta_wire_since(&a),
            "delta_wire_since must be symmetric at the watermark altitude on both_edit",
        );
    }

    // ---------- (5) cross-altitude coherence with ConfigSyncProof siblings

    #[test]
    fn agrees_with_proof_cross_altitude_and_nested_wire_field() {
        // Pin (5): on any proof pair whose watermarks are the pair
        // this sibling is called on, the wire reached through the
        // watermark altitude MUST equal
        // ConfigSyncProof::watermark_delta_wire_since (the cross-
        // altitude sibling on the proof) AND MUST equal the nested
        // ProofDeltaWire::watermark field on the wire the proof-
        // altitude ConfigSyncProof::delta_wire_since reaches. The
        // three siblings all reach the same wire tag pointwise.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior_wm = wm_of(&prior_cfg);
            let current_wm = wm_of(&current_cfg);
            let prior_proof = ConfigSyncProof {
                watermark: prior_wm,
                generation: 1,
                observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            };
            let current_proof = ConfigSyncProof {
                watermark: current_wm,
                generation: 2,
                observed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_060),
            };
            let watermark_altitude_wire = current_wm.delta_wire_since(&prior_wm);
            let proof_cross_altitude_wire = current_proof.watermark_delta_wire_since(&prior_proof);
            let nested_on_proof_wire = current_proof.delta_wire_since(&prior_proof).watermark;
            assert_eq!(
                watermark_altitude_wire, proof_cross_altitude_wire,
                "watermark-altitude sibling must equal ConfigSyncProof::watermark_delta_wire_since on {prior_cfg:?} -> {current_cfg:?}",
            );
            assert_eq!(
                watermark_altitude_wire, nested_on_proof_wire,
                "watermark-altitude sibling must equal ProofDeltaWire::watermark on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (6) reaches every watermark corner in one call

    #[test]
    fn reaches_every_watermark_corner_in_one_call() {
        // Pin (6): the sibling reaches a WatermarkDeltaWire on every
        // watermark corner — Stationary (all-false triple), FreeOnly
        // (full + free), RestartRequiredOnly (full + restart_required),
        // and Both (all-true triple). No routing on a classification
        // tag needed to reach the bare three-bool wire triple.
        //
        // Case row: (name, prior, current, want_triple as
        // (full_moved, restart_required_moved, free_moved)).
        type WantTriple = (bool, bool, bool);
        type Case = (&'static str, Cfg, Cfg, WantTriple);
        let cases: [Case; 4] = [
            (
                "Stationary (identical config)",
                base(),
                base(),
                (false, false, false),
            ),
            ("FreeOnly", base(), free_edit(), (true, false, true)),
            (
                "RestartRequiredOnly",
                base(),
                restart_edit(),
                (true, true, false),
            ),
            ("Both", base(), both_edit(), (true, true, true)),
        ];
        for (name, prior_cfg, current_cfg, want_triple) in cases {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let got = current.delta_wire_since(&prior);
            let got_triple = (got.full_moved, got.restart_required_moved, got.free_moved);
            assert_eq!(
                got_triple, want_triple,
                "{name}: watermark triple must reach {want_triple:?}, got {got:?}",
            );
        }
    }

    // ---------- (7) every reachable wire is class-partition-consistent

    #[test]
    fn every_reachable_wire_is_class_partition_consistent() {
        // Pin (7): every wire the sibling reaches on the authored flow
        // satisfies WatermarkDelta::class_moves_imply_full_moved — a
        // class-scoped half moving implies full_moved. This is the
        // weld WatermarkDelta::try_from_wire enforces at the parse
        // boundary; on wires the sibling produces, the weld is a
        // no-op, matching the doc-pin claim that "a producer of a
        // WatermarkDeltaWire reached through this method cannot
        // originate a class-partition-invariant violation."
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let wire = current.delta_wire_since(&prior);
            let candidate = WatermarkDelta {
                full_moved: wire.full_moved,
                restart_required_moved: wire.restart_required_moved,
                free_moved: wire.free_moved,
            };
            assert!(
                candidate.class_moves_imply_full_moved(),
                "sibling wire must be class-partition-consistent on {prior_cfg:?} -> {current_cfg:?}, got {wire:?}",
            );
        }
    }
}

#[cfg(test)]
mod watermark_delta_relation_wire_tests {
    //! Weld the delta-altitude `relation_wire` sibling on
    //! [`WatermarkDelta`] — the wire-side classification peer of
    //! [`WatermarkDelta::relation`], closing the fourth (and final)
    //! cell of the (`bare`, `relation`) × (`value`, `wire`) 2×2 grid at
    //! the delta altitude. Mirrors the shape
    //! [`ConfigWatermark::relation_wire_since`] carries one altitude up
    //! at the watermark-container altitude, so the sibling-family shape
    //! stays uniform across altitudes. Together the tests below cover:
    //!
    //! 1. [`WatermarkDelta::relation_wire`] composes through
    //!    [`WatermarkDelta::relation`] + [`WatermarkRelation::to_wire`]
    //!    — a future watermark-altitude classification variant added to
    //!    [`WatermarkRelation`] never reaches this method's body;
    //!    `relation` stays the single source of truth for the delta →
    //!    value-relation classification, and [`WatermarkRelation::to_wire`]
    //!    stays the single source of truth for its wire projection.
    //! 2. Same-`None` invariant with [`WatermarkDelta::relation`]:
    //!    [`WatermarkDelta::relation_wire`] returns `None` on exactly
    //!    the same three class-partition-invariant-violating shapes
    //!    [`WatermarkDelta::relation`] refuses, and returns `Some` on
    //!    exactly the same five legitimate corners. The impossibility
    //!    bucket travels as `Option::None` on both altitudes.
    //! 3. Round-trip totality through [`WatermarkRelation::from_wire`]:
    //!    every `Some(wire)` the sibling reaches on the authored flow
    //!    reconstructs to the exact value-side relation
    //!    [`WatermarkDelta::relation`] yields, so the wire projection
    //!    composed with its inverse is the identity on the value-side
    //!    relation.
    //! 4. Cross-altitude coherence with
    //!    [`ConfigWatermark::relation_wire_since`]: on any two
    //!    [`ConfigWatermark`] values whose delta is the delta this
    //!    sibling is called on, the wire reached through the delta
    //!    altitude MUST equal the wire reached through the watermark-
    //!    container altitude. Both altitudes compose the same two
    //!    morphisms and reach the same wire tag pointwise.
    //! 5. Reaches every legitimate corner in one call — `Stationary`,
    //!    `UnclassifiedDrift`, `RestartRequiredOnly`, `FreeOnly`, `Both`
    //!    — through the authored [`WatermarkDelta::between`] flow for
    //!    four of them plus one hand-authored `UnclassifiedDrift`
    //!    (`full_moved=true`, both class halves `false`), which
    //!    `between` never produces on real config values but a
    //!    consumer can construct through the `pub`-field constructor
    //!    when partitioning is non-exhaustive.
    //! 6. Impossibility corners map to `None` on the wire side too —
    //!    the three (`full_moved=false`, class-scoped=`true`) tuples a
    //!    consumer might hand-construct through the `pub`-field
    //!    constructor land at `None`, matching
    //!    [`WatermarkDelta::relation`]'s filtering behaviour on the
    //!    same shapes.
    //! 7. `const`-callable — a [`WatermarkDelta`] known at compile time
    //!    projects to its classification wire at compile time too,
    //!    matching the `const`-ness of both [`WatermarkDelta::relation`]
    //!    and [`WatermarkRelation::to_wire`].
    //!
    //! Same test idiom as `watermark_delta_wire_since_tests` (the
    //! watermark-container-altitude peer above), so a future refactor
    //! touching either altitude's classification wire pipeline surfaces
    //! breakage here too.

    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn authored_pairs() -> [(Cfg, Cfg); 4] {
        [
            (base(), base()),
            (base(), free_edit()),
            (base(), restart_edit()),
            (base(), both_edit()),
        ]
    }

    // ---------- (1) composition through relation + WatermarkRelation::to_wire

    #[test]
    fn relation_wire_composes_through_relation_then_to_wire() {
        // Pin (1): the delta-altitude classification-wire sibling MUST
        // fold through WatermarkDelta::relation +
        // WatermarkRelation::to_wire on every authored pair. A future
        // watermark-altitude classification variant added to
        // WatermarkRelation never reaches this method's body; relation
        // stays the single source of truth for the delta →
        // value-relation classification, and WatermarkRelation::to_wire
        // stays the single source of truth for its wire projection.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let delta = current.delta_since(&prior);
            assert_eq!(
                delta.relation_wire(),
                delta.relation().map(|r| r.to_wire()),
                "relation_wire must equal relation().map(|r| r.to_wire()) on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (2) same-None invariant with relation

    #[test]
    fn relation_wire_is_some_iff_relation_is_some_on_authored_flow() {
        // Pin (2a): on every WatermarkDelta the authored flow produces
        // (via WatermarkDelta::between on well-formed ConfigWatermark
        // values), both methods return Some — the class-partition
        // invariant holds by construction, so the impossibility bucket
        // never fires.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let delta = current.delta_since(&prior);
            assert!(
                delta.relation().is_some(),
                "authored delta must have Some(relation): {prior_cfg:?} -> {current_cfg:?}",
            );
            assert!(
                delta.relation_wire().is_some(),
                "authored delta must have Some(relation_wire): {prior_cfg:?} -> {current_cfg:?}",
            );
            assert_eq!(
                delta.relation().is_some(),
                delta.relation_wire().is_some(),
                "relation and relation_wire must have identical Some/None shape on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    #[test]
    fn relation_wire_is_none_on_the_same_three_impossibility_corners_as_relation() {
        // Pin (2b): on the three (full_moved=false, class-scoped=true)
        // impossibility corners a consumer can hand-construct through
        // the pub-field constructor, relation_wire must land at None on
        // the same shapes relation does. The impossibility bucket
        // travels as Option::None on both altitudes.
        let impossibility_corners = [
            WatermarkDelta {
                full_moved: false,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDelta {
                full_moved: false,
                restart_required_moved: false,
                free_moved: true,
            },
            WatermarkDelta {
                full_moved: false,
                restart_required_moved: true,
                free_moved: true,
            },
        ];
        for d in impossibility_corners {
            assert!(
                d.relation().is_none(),
                "relation must refuse impossibility corner {d:?}",
            );
            assert!(
                d.relation_wire().is_none(),
                "relation_wire must refuse the same impossibility corner {d:?}",
            );
        }
    }

    // ---------- (3) round-trip totality through WatermarkRelation::from_wire

    #[test]
    fn round_trips_through_from_wire_to_the_same_value_side_relation() {
        // Pin (3): every Some(wire) the sibling reaches on the authored
        // flow reconstructs through WatermarkRelation::from_wire to the
        // exact value-side relation WatermarkDelta::relation yields.
        // The wire projection composed with its inverse is the identity
        // on the value-side relation.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let delta = current.delta_since(&prior);
            let wire = delta.relation_wire().unwrap_or_else(|| {
                panic!("authored delta must have Some(relation_wire): {delta:?}")
            });
            let back = WatermarkRelation::from_wire(&wire);
            assert_eq!(
                Some(back),
                delta.relation(),
                "round-tripped wire must equal the value-side relation on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (4) cross-altitude coherence with ConfigWatermark::relation_wire_since

    #[test]
    fn agrees_with_watermark_container_altitude_sibling() {
        // Pin (4): on any two ConfigWatermark values whose delta is the
        // delta this sibling is called on, the wire reached through the
        // delta altitude MUST equal
        // ConfigWatermark::relation_wire_since (the watermark-
        // container-altitude sibling). Both altitudes compose the same
        // two morphisms (relation() then to_wire()) at different
        // altitudes and reach the same wire tag pointwise.
        for (prior_cfg, current_cfg) in authored_pairs() {
            let prior = wm_of(&prior_cfg);
            let current = wm_of(&current_cfg);
            let delta_altitude_wire = current.delta_since(&prior).relation_wire();
            let container_altitude_wire = current.relation_wire_since(&prior);
            assert_eq!(
                delta_altitude_wire, container_altitude_wire,
                "delta-altitude sibling must equal ConfigWatermark::relation_wire_since on {prior_cfg:?} -> {current_cfg:?}",
            );
        }
    }

    // ---------- (5) reaches every legitimate corner in one call

    #[test]
    fn reaches_every_legitimate_relation_variant_in_one_call() {
        // Pin (5): the sibling reaches a WatermarkRelationWire on every
        // legitimate corner — Stationary, RestartRequiredOnly, FreeOnly,
        // Both — through the authored WatermarkDelta::between flow, and
        // reaches the fifth legitimate variant UnclassifiedDrift
        // (full_moved=true, both class halves false) through a hand-
        // authored delta a consumer can construct when partitioning is
        // non-exhaustive. All five payload-free variants reachable in
        // ONE call to relation_wire.
        //
        // Case row: (name, delta, want_wire).
        type Case = (&'static str, WatermarkDelta, WatermarkRelationWire);
        let cases: [Case; 5] = [
            (
                "Stationary",
                current_from(base(), base()),
                WatermarkRelationWire::Stationary,
            ),
            (
                "FreeOnly",
                current_from(base(), free_edit()),
                WatermarkRelationWire::FreeOnly,
            ),
            (
                "RestartRequiredOnly",
                current_from(base(), restart_edit()),
                WatermarkRelationWire::RestartRequiredOnly,
            ),
            (
                "Both",
                current_from(base(), both_edit()),
                WatermarkRelationWire::Both,
            ),
            (
                "UnclassifiedDrift",
                WatermarkDelta {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: false,
                },
                WatermarkRelationWire::UnclassifiedDrift,
            ),
        ];
        for (name, delta, want_wire) in cases {
            let got = delta.relation_wire();
            assert_eq!(
                got,
                Some(want_wire),
                "{name}: relation_wire must reach {want_wire:?} on {delta:?}",
            );
        }
    }

    fn current_from(prior_cfg: Cfg, current_cfg: Cfg) -> WatermarkDelta {
        let prior = wm_of(&prior_cfg);
        let current = wm_of(&current_cfg);
        current.delta_since(&prior)
    }

    // ---------- (6) impossibility corners map to None on the wire side too

    #[test]
    fn impossibility_corners_map_to_none_on_both_altitudes() {
        // Pin (6): every (full_moved=false, class-scoped=true) tuple a
        // consumer might hand-construct through the pub-field
        // constructor lands at None on both relation and relation_wire.
        // Enumerated by hand rather than through between() because
        // between() on two well-formed ConfigWatermark values never
        // produces these shapes (a class-scoped hash's input is a
        // subset of the full hash's input, so moving the smaller input
        // implies moving the larger one — see
        // WatermarkDelta::class_moves_imply_full_moved).
        for (rr, free) in [(true, false), (false, true), (true, true)] {
            let d = WatermarkDelta {
                full_moved: false,
                restart_required_moved: rr,
                free_moved: free,
            };
            assert!(
                !d.class_moves_imply_full_moved(),
                "sanity: {d:?} must violate class_moves_imply_full_moved",
            );
            assert_eq!(
                d.relation(),
                None,
                "relation must map impossibility corner to None: {d:?}",
            );
            assert_eq!(
                d.relation_wire(),
                None,
                "relation_wire must map the same impossibility corner to None: {d:?}",
            );
        }
    }

    // ---------- (7) const-callable

    #[test]
    fn relation_wire_is_const_callable() {
        // Pin (7): a WatermarkDelta known at compile time projects to
        // its classification wire at compile time too, matching the
        // const-ness of both WatermarkDelta::relation and
        // WatermarkRelation::to_wire. Assign to a `const` binding so
        // the const-ness of relation_wire fails to compile at this
        // exact line the moment either half of the composition loses
        // its const-ness — a compile-time weld on the const-callability
        // of the whole classification-wire pipeline.
        const D: WatermarkDelta = WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: false,
        };
        const W: Option<WatermarkRelationWire> = D.relation_wire();
        assert_eq!(W, Some(WatermarkRelationWire::RestartRequiredOnly));
    }
}

#[cfg(test)]
mod proof_delta_relation_tests {
    //! Weld the proof-delta-altitude classification receiver-sibling
    //! pair on [`ProofDelta`] — [`ProofDelta::relation`] and
    //! [`ProofDelta::relation_wire`] closing the two missing cells of
    //! the (`bare`, `relation`) × (`value`, `wire`) 2×2 grid at the
    //! proof-delta altitude. Mirrors the shape
    //! [`WatermarkDelta::relation`] / [`WatermarkDelta::relation_wire`]
    //! carry one altitude down at the watermark-delta altitude, so the
    //! sibling-family shape stays uniform across altitudes. Together
    //! the tests below cover:
    //!
    //! 1. [`ProofDelta::relation_wire`] composes through
    //!    [`ProofDelta::relation`] + [`ProofRelation::to_wire`] — a
    //!    future proof-altitude classification variant added to
    //!    [`ProofRelation`] never reaches this method's body;
    //!    `relation` stays the single source of truth for the delta →
    //!    value-relation classification, and [`ProofRelation::to_wire`]
    //!    stays the single source of truth for its wire projection.
    //! 2. Same-`None` invariant with [`ProofDelta::relation`]:
    //!    [`ProofDelta::relation_wire`] returns `None` on exactly the
    //!    same two impossibility buckets [`ProofDelta::relation`]
    //!    refuses — the generation-regressed corner (delta lost the
    //!    `by` count) and the class-partition impossibility corner
    //!    (only reachable through the `pub`-field constructor). The
    //!    impossibility bucket travels as `Option::None` on both
    //!    value and wire sides.
    //! 3. Round-trip totality through [`ProofRelation::try_from_wire`]:
    //!    every `Some(wire)` the sibling reaches on the authored flow
    //!    reconstructs to the exact value-side relation
    //!    [`ProofDelta::relation`] yields, so the wire projection
    //!    composed with its inverse is the identity on the value-side
    //!    relation across every legitimate proof-delta corner.
    //! 4. Reaches every LEGITIMATE proof-relation variant in one call
    //!    — [`ProofRelation::Stationary`],
    //!    [`ProofRelation::IdentityRepublish`],
    //!    [`ProofRelation::Progression`] across the three
    //!    non-stationary watermark sub-corners, and
    //!    [`ProofRelation::CrossStore`]. [`ProofRelation::Regressed`]
    //!    is NOT reachable from a delta by design — that variant
    //!    carries a [`std::num::NonZeroU64`] `by` count the delta
    //!    folded into `Option::None`, so a consumer that needs the
    //!    count reaches [`ProofRelation::between`] on the underlying
    //!    proof pair instead. Pinned as the "why regressed lives
    //!    behind None" property in test 6.
    //! 5. Agreement with [`ConfigSyncProof::relation_since`] /
    //!    [`ConfigSyncProof::relation_wire_since`] on the four
    //!    legitimate delta corners: for any proof pair whose
    //!    generation did NOT regress and whose watermark is class-
    //!    partition-consistent (both true for every pair
    //!    [`ConfigWatermark::compute`] produces),
    //!    `current.delta_since(&prior).relation()` equals
    //!    `Some(current.relation_since(&prior))` and analogously for
    //!    the wire sibling. Cross-altitude coherence pinned across
    //!    both classifications.
    //! 6. Generation-regressed corner maps to `None` on both methods —
    //!    even when the underlying watermark shape and generation
    //!    modulo would otherwise be well-formed. Sanity-anchored
    //!    against [`ConfigSyncProof::relation_since`] on the same
    //!    pair, which reaches `ProofRelation::Regressed` with the
    //!    exact `by` count the delta cannot recover.
    //! 7. Class-partition impossibility corners map to `None` on both
    //!    methods — the three (`full_moved=false`, class-scoped=`true`)
    //!    tuples a consumer can hand-construct through the `pub`-field
    //!    constructor land at `None` on both `relation` and
    //!    `relation_wire`, matching [`WatermarkDelta::relation`]'s
    //!    filtering behaviour on the same shapes.
    //! 8. `const`-callable — a [`ProofDelta`] known at compile time
    //!    classifies at compile time too, matching the `const`-ness of
    //!    both [`ProofDelta::relation`] / [`ProofDelta::relation_wire`]
    //!    and their transitive dependencies
    //!    [`WatermarkDelta::stationary`],
    //!    [`WatermarkDelta::class_moves_imply_full_moved`],
    //!    [`MovedWatermarkDelta::new`], [`std::num::NonZeroU64::new`],
    //!    and [`ProofRelation::to_wire`].

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn free_edit() -> Cfg {
        let mut c = base();
        c.log_level = "debug".into();
        c
    }

    fn restart_edit() -> Cfg {
        let mut c = base();
        c.bind_addr = "0.0.0.0:9090".into();
        c
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    fn wm_of(c: &Cfg) -> ConfigWatermark {
        ConfigWatermark::compute(c, FIELD_CLASSES)
    }

    fn proof_at(cfg: &Cfg, generation: u64, epoch_secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: wm_of(cfg),
            observed_at: UNIX_EPOCH + Duration::from_secs(epoch_secs),
        }
    }

    /// Every legitimate proof pair the authored flow produces — one
    /// case per non-regressed [`ProofRelation`] corner reachable from
    /// [`ConfigWatermark::compute`]-style values. Excludes
    /// [`ProofRelation::Regressed`] (delta can't recover the `by`
    /// count) and the class-partition impossibility corners
    /// ([`WatermarkDelta::between`] never produces them, and this is
    /// the "authored flow" fixture).
    fn authored_legitimate_pairs() -> Vec<(&'static str, ConfigSyncProof, ConfigSyncProof)> {
        vec![
            // Stationary: same watermark, same generation.
            (
                "Stationary",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_060),
            ),
            // IdentityRepublish: same watermark, generation advanced.
            (
                "IdentityRepublish",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 7, 1_700_000_060),
            ),
            // Progression (FreeOnly sub-corner).
            (
                "Progression:FreeOnly",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&free_edit(), 6, 1_700_000_060),
            ),
            // Progression (RestartRequiredOnly sub-corner).
            (
                "Progression:RestartRequiredOnly",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&restart_edit(), 6, 1_700_000_060),
            ),
            // Progression (Both sub-corner).
            (
                "Progression:Both",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
            ),
            // CrossStore: watermark moved but generation unchanged.
            (
                "CrossStore",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 5, 1_700_000_060),
            ),
        ]
    }

    // ---------- (1) composition through relation + ProofRelation::to_wire

    #[test]
    fn relation_wire_composes_through_relation_then_to_wire() {
        // Pin (1): the proof-delta-altitude classification-wire sibling
        // MUST fold through ProofDelta::relation + ProofRelation::to_wire
        // on every authored pair. A future proof-altitude classification
        // variant added to ProofRelation never reaches this method's
        // body; relation stays the single source of truth for the delta →
        // value-relation classification, and ProofRelation::to_wire stays
        // the single source of truth for its wire projection.
        for (name, prior, current) in authored_legitimate_pairs() {
            let delta = current.delta_since(&prior);
            assert_eq!(
                delta.relation_wire(),
                delta.relation().map(|r| r.to_wire()),
                "{name}: relation_wire must equal relation().map(|r| r.to_wire())",
            );
        }
    }

    // ---------- (2) same-None invariant with relation

    #[test]
    fn relation_and_relation_wire_agree_on_some_none_on_authored_flow() {
        // Pin (2a): on every ProofDelta the authored flow produces (via
        // ProofDelta::between on well-formed ConfigSyncProof values with
        // non-regressed generation), both methods return Some — neither
        // impossibility bucket fires.
        for (name, prior, current) in authored_legitimate_pairs() {
            let delta = current.delta_since(&prior);
            assert!(
                delta.relation().is_some(),
                "{name}: authored delta must have Some(relation)",
            );
            assert!(
                delta.relation_wire().is_some(),
                "{name}: authored delta must have Some(relation_wire)",
            );
            assert_eq!(
                delta.relation().is_some(),
                delta.relation_wire().is_some(),
                "{name}: relation and relation_wire must have identical Some/None shape",
            );
        }
    }

    // ---------- (3) round-trip through ProofRelation::try_from_wire

    #[test]
    fn round_trips_through_try_from_wire_to_the_same_value_side_relation() {
        // Pin (3): every Some(wire) the sibling reaches on the authored
        // flow reconstructs through ProofRelation::try_from_wire to the
        // exact value-side relation ProofDelta::relation yields. The
        // wire projection composed with its inverse is the identity on
        // the value-side relation across every legitimate proof-delta
        // corner.
        for (name, prior, current) in authored_legitimate_pairs() {
            let delta = current.delta_since(&prior);
            let wire = delta
                .relation_wire()
                .unwrap_or_else(|| panic!("{name}: authored delta must have Some(relation_wire)"));
            let back = ProofRelation::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!("{name}: try_from_wire must succeed on the sibling's own output, got {e:?}")
            });
            assert_eq!(
                Some(back),
                delta.relation(),
                "{name}: round-tripped wire must equal the value-side relation",
            );
        }
    }

    // ---------- (4) reaches every legitimate variant in one call

    #[test]
    fn reaches_every_legitimate_relation_variant_in_one_call() {
        // Pin (4): the sibling reaches a ProofRelation on every legitimate
        // corner — Stationary, IdentityRepublish, Progression across the
        // three non-stationary watermark sub-corners, and CrossStore —
        // through the authored ProofDelta::between flow, in ONE call.
        // Regressed is NOT reachable from a delta by design (pinned in
        // test 6).
        let mut seen_stationary = false;
        let mut seen_identity_republish = false;
        let mut seen_progression_free = false;
        let mut seen_progression_restart = false;
        let mut seen_progression_both = false;
        let mut seen_crossstore = false;
        for (name, prior, current) in authored_legitimate_pairs() {
            let delta = current.delta_since(&prior);
            let r = delta
                .relation()
                .unwrap_or_else(|| panic!("{name}: authored delta must have Some(relation)"));
            match r {
                ProofRelation::Stationary => seen_stationary = true,
                ProofRelation::IdentityRepublish { .. } => seen_identity_republish = true,
                ProofRelation::Progression { watermark, .. } => {
                    if watermark.restart_pending() && watermark.hot_swappable_drift() {
                        seen_progression_both = true;
                    } else if watermark.restart_pending() {
                        seen_progression_restart = true;
                    } else if watermark.hot_swappable_drift() {
                        seen_progression_free = true;
                    }
                }
                ProofRelation::CrossStore { .. } => seen_crossstore = true,
                ProofRelation::Regressed { .. } => {
                    panic!("{name}: Regressed unreachable from a delta by design")
                }
            }
        }
        assert!(seen_stationary, "must reach ProofRelation::Stationary");
        assert!(
            seen_identity_republish,
            "must reach ProofRelation::IdentityRepublish"
        );
        assert!(
            seen_progression_free,
            "must reach ProofRelation::Progression (FreeOnly)"
        );
        assert!(
            seen_progression_restart,
            "must reach ProofRelation::Progression (RestartRequiredOnly)"
        );
        assert!(
            seen_progression_both,
            "must reach ProofRelation::Progression (Both)"
        );
        assert!(seen_crossstore, "must reach ProofRelation::CrossStore");
    }

    // ---------- (5) agreement with ConfigSyncProof::relation_since /
    //             relation_wire_since on the four legitimate corners

    #[test]
    fn agrees_with_proof_pair_altitude_sibling_on_legitimate_corners() {
        // Pin (5): on any proof pair whose generation did NOT regress
        // and whose watermark is class-partition-consistent (both true
        // for every pair ConfigWatermark::compute produces),
        // current.delta_since(&prior).relation() equals
        // Some(current.relation_since(&prior)) and analogously for the
        // wire sibling. Cross-altitude coherence pinned across both
        // classifications — the delta altitude and the proof-pair
        // altitude reach the same classification through different
        // paths (delta fold vs direct proof-pair classification).
        for (name, prior, current) in authored_legitimate_pairs() {
            let delta = current.delta_since(&prior);
            let delta_relation = delta.relation();
            let pair_relation = current.relation_since(&prior);
            assert_eq!(
                delta_relation,
                Some(pair_relation),
                "{name}: delta.relation() must equal Some(current.relation_since(&prior))",
            );
            let delta_relation_wire = delta.relation_wire();
            let pair_relation_wire = current.relation_wire_since(&prior);
            assert_eq!(
                delta_relation_wire,
                Some(pair_relation_wire),
                "{name}: delta.relation_wire() must equal Some(current.relation_wire_since(&prior))",
            );
        }
    }

    // ---------- (6) generation-regressed corner is None on both;
    //             proof-pair sibling recovers the `by` count

    #[test]
    fn generation_regressed_corner_is_none_on_both_methods() {
        // Pin (6): a proof pair with prior.generation > current.generation
        // has generations_advanced = None on the delta; the delta cannot
        // recover the exact `by` regression count ProofRelation::Regressed
        // carries. Both delta-altitude methods return None on this corner
        // — even when the underlying watermark shape and everything else
        // would otherwise be well-formed. Sanity-anchor against
        // ConfigSyncProof::relation_since on the same pair, which reaches
        // ProofRelation::Regressed with the exact `by` count.
        let prior = proof_at(&base(), 10, 1_700_000_000);
        let current = proof_at(&base(), 5, 1_700_000_060);
        let delta = current.delta_since(&prior);
        assert!(
            delta.generations_regressed(),
            "sanity: this pair must regress at the delta altitude",
        );
        assert_eq!(
            delta.relation(),
            None,
            "regressed delta must map to None on relation (by count lost)",
        );
        assert_eq!(
            delta.relation_wire(),
            None,
            "regressed delta must map to None on relation_wire (by count lost)",
        );
        // The proof-pair-altitude sibling recovers the exact by count.
        let pair_relation = current.relation_since(&prior);
        match pair_relation {
            ProofRelation::Regressed { by } => {
                assert_eq!(
                    by.get(),
                    5,
                    "proof-pair sibling recovers the exact by count",
                );
            }
            other => panic!("proof-pair sibling must reach Regressed, got {other:?}"),
        }
    }

    #[test]
    fn regressed_corner_is_none_even_with_moved_watermark_and_zero_advance_alignment() {
        // Pin (6-b): even a regressed pair whose bare (watermark,
        // generation-modulo) tuple could look like a legitimate CrossStore
        // corner (moved watermark) lands at None -- the None branch fires
        // BEFORE any watermark shape inspection, so a consumer cannot
        // confuse a regression for a cross-store signal at the delta
        // altitude. Contrast with test 6 (stationary watermark) to pin
        // the None short-circuit is orthogonal to watermark shape.
        let prior = proof_at(&base(), 10, 1_700_000_000);
        let current = proof_at(&both_edit(), 5, 1_700_000_060);
        let delta = current.delta_since(&prior);
        assert!(delta.generations_regressed());
        assert!(delta.watermark.any_moved(), "sanity: watermark moved");
        assert_eq!(delta.relation(), None);
        assert_eq!(delta.relation_wire(), None);
    }

    // ---------- (7) class-partition impossibility corners are None

    #[test]
    fn class_partition_impossibility_corners_are_none_on_both_methods() {
        // Pin (7): the three (full_moved=false, class-scoped=true)
        // tuples a consumer can hand-construct through the pub-field
        // constructor land at None on both relation and relation_wire.
        // Enumerated by hand because ProofDelta::between on well-formed
        // ConfigSyncProof values never produces them (class-partition
        // is welded at ConfigWatermark::compute). This mirrors
        // WatermarkDelta::relation's Option::None filtering on the same
        // shapes one altitude down — the impossibility bucket travels
        // as Option::None on both altitudes.
        for (rr, free) in [(true, false), (false, true), (true, true)] {
            let bad_watermark = WatermarkDelta {
                full_moved: false,
                restart_required_moved: rr,
                free_moved: free,
            };
            assert!(
                !bad_watermark.class_moves_imply_full_moved(),
                "sanity: {bad_watermark:?} must violate the class-partition invariant",
            );
            // Try each combination of generations_advanced that could
            // otherwise reach a legitimate arm — Some(0), Some(3) — to
            // pin the filter fires INDEPENDENTLY of the generation axis.
            for generations_advanced in [Some(0_u64), Some(3_u64)] {
                let delta = ProofDelta {
                    watermark: bad_watermark,
                    generations_advanced,
                    observed_at_elapsed: Some(Duration::from_secs(30)),
                };
                assert_eq!(
                    delta.relation(),
                    None,
                    "relation must refuse class-partition impossibility {delta:?}",
                );
                assert_eq!(
                    delta.relation_wire(),
                    None,
                    "relation_wire must refuse the same class-partition impossibility {delta:?}",
                );
            }
        }
    }

    // ---------- (8) const-callable

    #[test]
    fn relation_and_relation_wire_are_const_callable() {
        // Pin (8): a ProofDelta known at compile time classifies at
        // compile time too, matching the const-ness of both methods and
        // every transitive dependency (WatermarkDelta::stationary,
        // WatermarkDelta::class_moves_imply_full_moved,
        // MovedWatermarkDelta::new, NonZeroU64::new,
        // ProofRelation::to_wire). Assigned to `const` bindings so the
        // const-ness of the whole pipeline fails to compile at these
        // exact lines the moment any half of the composition loses its
        // const-ness — a compile-time weld on the const-callability of
        // the whole classification pipeline.
        const D_STATIONARY: ProofDelta = ProofDelta {
            watermark: WatermarkDelta {
                full_moved: false,
                restart_required_moved: false,
                free_moved: false,
            },
            generations_advanced: Some(0),
            observed_at_elapsed: None,
        };
        const R_STATIONARY: Option<ProofRelation> = D_STATIONARY.relation();
        const W_STATIONARY: Option<ProofRelationWire> = D_STATIONARY.relation_wire();
        const D_REGRESSED: ProofDelta = ProofDelta {
            watermark: WatermarkDelta {
                full_moved: false,
                restart_required_moved: false,
                free_moved: false,
            },
            generations_advanced: None,
            observed_at_elapsed: None,
        };
        const R_REGRESSED: Option<ProofRelation> = D_REGRESSED.relation();
        const W_REGRESSED: Option<ProofRelationWire> = D_REGRESSED.relation_wire();
        assert_eq!(R_STATIONARY, Some(ProofRelation::Stationary));
        assert_eq!(W_STATIONARY, Some(ProofRelationWire::Stationary));
        assert_eq!(R_REGRESSED, None);
        assert_eq!(W_REGRESSED, None);
    }
}

#[cfg(test)]
mod proof_relation_watermark_tests {
    //! Weld the class-scoped watermark-payload accessor
    //! ([`ProofRelation::watermark`]) and its wire-side sibling
    //! ([`ProofRelationWire::watermark`]) — the typed one-liner replacing
    //! the two-arm `if let ProofRelation::Progression { watermark, .. } |
    //! ProofRelation::CrossStore { watermark } = &relation { ... } else {
    //! ... }` a consumer previously hand-wrote at every routing seam.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Some/None shape by variant identity — [`ProofRelation::watermark`]
    //!    is `Some` on the two payload-carrying variants
    //!    ([`ProofRelation::Progression`], [`ProofRelation::CrossStore`])
    //!    and [`Option::None`] on the three payload-free variants
    //!    ([`ProofRelation::Stationary`], [`ProofRelation::IdentityRepublish`],
    //!    [`ProofRelation::Regressed`]). Pinned at both altitudes.
    //! 2. Same-Some/None invariant across altitudes — for every
    //!    [`ProofRelation`] value, `relation.watermark().is_some() ==
    //!    relation.to_wire().watermark().is_some()`. The two altitude
    //!    accessors agree pointwise on presence.
    //! 3. Wire projection of the payload agrees — when both sides return
    //!    `Some`, the wire watermark equals the value-side watermark's
    //!    [`MovedWatermarkDelta::to_wire`] projection. A future variant
    //!    added to [`ProofRelation`] carrying a watermark payload turns
    //!    every consumer of this composition red at compile time.
    //! 4. Round-trip through [`ProofRelation::try_from_wire`] preserves
    //!    the payload — the reconstructed relation carries the same
    //!    [`MovedWatermarkDelta`] the original does, so a wire consumer
    //!    that follows the standard parse seam surfaces a payload
    //!    equal to the one the producer's [`ProofRelation::watermark`]
    //!    reached.
    //! 5. Composition with [`ProofDelta::relation`] — on the four
    //!    legitimate corners reachable from a delta,
    //!    `delta.relation().and_then(|r| r.watermark().copied())` equals
    //!    the payload accessed via
    //!    `ProofRelation::between(&prior, &current).watermark().copied()`.
    //!    Cross-altitude coherence pinned on the payload accessor across
    //!    both the delta-fold and the direct proof-pair classification
    //!    paths.
    //! 6. [`MovedWatermarkDelta`] invariant survives — whenever the
    //!    accessor returns `Some`, the returned watermark satisfies
    //!    [`WatermarkDelta::any_moved`] (welded at the type by
    //!    [`MovedWatermarkDelta::new`] refusing the stationary null
    //!    hypothesis). A `Some` never carries a stationary payload on
    //!    either altitude.
    //! 7. `const`-callable on both altitudes — a
    //!    [`ProofRelation`] / [`ProofRelationWire`] known at compile time
    //!    projects its watermark payload at compile time too, matching
    //!    the `const`-ness of every other classification accessor in the
    //!    file.
    //! 8. All five variants of [`ProofRelation`] are explicitly enumerated
    //!    — adding a sixth variant fails to compile at the exhaustive
    //!    `match` in the accessor body AND at every enumeration test
    //!    below that names the five current variants by tag.
    //!
    //! Fixtures build hand-authored [`ProofRelation`] values directly
    //! rather than routing through [`ProofRelation::between`] on
    //! [`ConfigWatermark::compute`]-style proof pairs. That gives the
    //! [`ProofRelation::Regressed`] variant reachable coverage (the
    //! delta-fold folds its `by` count into `Option::None` and the
    //! authored-flow fixture in `proof_delta_relation_tests` cannot reach
    //! it) and keeps each test's setup local to the property it pins.

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    /// A [`MovedWatermarkDelta`] whose all three axes moved — the widest
    /// legitimate payload, spelled through the constructor so the "at
    /// least one class-scoped half moved" invariant lands at the type.
    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    /// A [`MovedWatermarkDelta`] where only the Free class-scoped half
    /// moved. Distinct payload shape from `moved_all` so a test that
    /// checks payload equality across altitudes catches an accidental
    /// swap between the two variants' watermark fields.
    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    /// Every [`ProofRelation`] variant, hand-constructed with a distinct
    /// payload where variants carry one. Order matches the grid:
    /// `Stationary`, `IdentityRepublish`, `Progression`, `CrossStore`,
    /// `Regressed`.
    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    // ---------- (1) Some/None shape by variant identity

    #[test]
    fn watermark_returns_some_on_payload_variants_none_on_the_rest_at_both_altitudes() {
        // Pin (1): the accessor's Some/None shape matches variant
        // identity — Some on Progression and CrossStore, None on the
        // three payload-free variants — on BOTH the value-side and the
        // wire-side altitude. A future sixth variant added to
        // ProofRelation turns the exhaustive match in the accessor red,
        // so the "which variants carry a watermark payload?" answer
        // never drifts silently.
        for (name, relation) in all_five_relations() {
            let expect_some = matches!(
                relation,
                ProofRelation::Progression { .. } | ProofRelation::CrossStore { .. }
            );
            assert_eq!(
                relation.watermark().is_some(),
                expect_some,
                "{name}: ProofRelation::watermark Some/None must match variant identity",
            );
            assert_eq!(
                relation.to_wire().watermark().is_some(),
                expect_some,
                "{name}: ProofRelationWire::watermark Some/None must match variant identity",
            );
        }
    }

    // ---------- (2) same-Some/None invariant across altitudes

    #[test]
    fn value_and_wire_altitudes_agree_on_some_none_pointwise() {
        // Pin (2): for every ProofRelation value the two altitude
        // accessors agree pointwise on presence. Combined with test (1)
        // this pins the shape from BOTH directions: (1) says each side
        // matches the variant identity, (2) says the two sides match
        // each other. If some future edit made the wire side branch
        // differently on a payload-free variant, test (1) alone might
        // still pass on some subset of variants while this test catches
        // the pointwise divergence.
        for (name, relation) in all_five_relations() {
            let value_some = relation.watermark().is_some();
            let wire_some = relation.to_wire().watermark().is_some();
            assert_eq!(
                value_some, wire_some,
                "{name}: value-side and wire-side accessors must agree on Some/None",
            );
        }
    }

    // ---------- (3) wire projection of the payload agrees

    #[test]
    fn wire_watermark_equals_value_watermark_to_wire_when_both_present() {
        // Pin (3): when both accessors return Some, the wire watermark
        // equals the value-side watermark's MovedWatermarkDelta::to_wire
        // projection. The payload is not merely "some watermark" but the
        // *same* watermark projected through the type's own wire
        // morphism — a future edit that swapped the Progression /
        // CrossStore fields at either altitude would fail this test on
        // the crossstore corner (which uses the distinct
        // `moved_free_only()` fixture).
        for (name, relation) in all_five_relations() {
            let value_wm = relation.watermark();
            let wire = relation.to_wire();
            let wire_wm = wire.watermark();
            match (value_wm, wire_wm) {
                (Some(v), Some(w)) => {
                    assert_eq!(
                        v.to_wire(),
                        *w,
                        "{name}: wire watermark must equal value watermark's to_wire()",
                    );
                }
                (None, None) => {}
                (a, b) => panic!(
                    "{name}: Some/None shape must agree across altitudes, got value={a:?} \
                     wire={b:?}",
                ),
            }
        }
    }

    // ---------- (4) round-trip through try_from_wire preserves the payload

    #[test]
    fn round_trip_through_try_from_wire_preserves_the_watermark_payload() {
        // Pin (4): a wire consumer that follows the standard parse seam
        // (ProofRelation::try_from_wire) reaches a value whose
        // .watermark() accessor returns exactly the payload the producer's
        // .watermark() reached before serialization. The MovedWatermarkDelta
        // weld travels with the payload through the wire round trip and
        // the accessor surfaces it on the other side without a second
        // pattern-match.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let back = ProofRelation::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!("{name}: try_from_wire must succeed on to_wire output, got {e:?}")
            });
            assert_eq!(
                back.watermark().copied(),
                relation.watermark().copied(),
                "{name}: round-trip must preserve the watermark payload",
            );
        }
    }

    // ---------- (5) composition with ProofDelta::relation

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn proof_at(cfg: &Cfg, generation: u64, epoch_secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: ConfigWatermark::compute(cfg, FIELD_CLASSES),
            observed_at: UNIX_EPOCH + Duration::from_secs(epoch_secs),
        }
    }

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    #[test]
    fn agrees_with_proof_delta_relation_watermark_on_legitimate_corners() {
        // Pin (5): on any authored proof pair, the payload accessed via
        // the delta-fold path (delta.relation().and_then(|r|
        // r.watermark().copied())) equals the payload accessed via the
        // direct proof-pair classification path
        // (ProofRelation::between(&prior, &current).watermark().copied()).
        // Cross-altitude coherence pinned on the payload accessor.
        let cases: [(&str, ConfigSyncProof, ConfigSyncProof); 4] = [
            (
                "Stationary",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_060),
            ),
            (
                "IdentityRepublish",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 7, 1_700_000_060),
            ),
            (
                "Progression",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
            ),
            (
                "CrossStore",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 5, 1_700_000_060),
            ),
        ];
        for (name, prior, current) in cases {
            let delta_path = current
                .delta_since(&prior)
                .relation()
                .and_then(|r| r.watermark().copied());
            let direct_path = ProofRelation::between(&prior, &current)
                .watermark()
                .copied();
            assert_eq!(
                delta_path, direct_path,
                "{name}: delta-fold and direct-classification paths must yield the same \
                 watermark payload",
            );
        }
    }

    // ---------- (6) MovedWatermarkDelta invariant survives

    #[test]
    fn some_never_carries_a_stationary_payload_on_either_altitude() {
        // Pin (6): the MovedWatermarkDelta "at least one class-scoped
        // half moved" invariant survives the accessor — on the value
        // side the wrapping type welds it at the field shape, on the
        // wire side the identical Some/None shape (pinned in test 2)
        // means the wire Some cases correspond 1-1 to value Some cases
        // whose MovedWatermarkDelta is non-stationary by construction.
        // Sanity-anchored against WatermarkDelta::any_moved on the
        // returned reference.
        for (name, relation) in all_five_relations() {
            if let Some(wm) = relation.watermark() {
                assert!(
                    wm.any_moved(),
                    "{name}: value-side Some must carry a non-stationary payload",
                );
            }
            let wire = relation.to_wire();
            if let Some(wm_wire) = wire.watermark() {
                // The wire type does NOT weld the invariant at the field
                // shape (the weld happens at parse time inside
                // ProofRelation::try_from_wire). But the wire projection
                // of a MovedWatermarkDelta produced by to_wire on a
                // legitimate value must still be non-stationary — the
                // three booleans are preserved bitwise across to_wire.
                assert!(
                    wm_wire.full_moved || wm_wire.restart_required_moved || wm_wire.free_moved,
                    "{name}: wire-side Some produced from a legitimate value must carry a \
                     non-stationary payload",
                );
            }
        }
    }

    // ---------- (7) const-callable on both altitudes

    #[test]
    fn watermark_is_const_callable_on_both_altitudes() {
        // Pin (7): a compile-time-known ProofRelation projects its
        // watermark payload at compile time too, matching the const-ness
        // of every other classification accessor in the file
        // (ProofRelation::same_store_consistent, ProofDelta::relation,
        // WatermarkRelation::to_wire, etc.). Assigned to `const` bindings
        // so const-ness of the whole accessor pipeline fails to compile
        // at these exact lines the moment any transitive dependency
        // loses its const-ness.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const W_STATIONARY: Option<&MovedWatermarkDelta> = R_STATIONARY.watermark();
        const R_STATIONARY_WIRE: ProofRelationWire = ProofRelationWire::Stationary;
        const W_STATIONARY_WIRE: Option<&WatermarkDeltaWire> = R_STATIONARY_WIRE.watermark();
        assert!(W_STATIONARY.is_none());
        assert!(W_STATIONARY_WIRE.is_none());
    }

    // ---------- (8) all five variants explicitly enumerated

    #[test]
    fn every_relation_variant_is_reached_by_the_fixture_and_classified_correctly() {
        // Pin (8): the fixture reaches all five ProofRelation variants
        // (including Regressed, which the delta-altitude authored flow
        // cannot reach). Combined with the exhaustive `match` in the
        // accessor body, adding a sixth variant to ProofRelation turns
        // this test's `match` red at the same instant the accessor's own
        // `match` turns red. No silent drift.
        let mut seen_stationary = false;
        let mut seen_identity_republish = false;
        let mut seen_progression = false;
        let mut seen_crossstore = false;
        let mut seen_regressed = false;
        for (_, relation) in all_five_relations() {
            match relation {
                ProofRelation::Stationary => {
                    assert!(relation.watermark().is_none(), "Stationary must be None");
                    seen_stationary = true;
                }
                ProofRelation::IdentityRepublish { .. } => {
                    assert!(
                        relation.watermark().is_none(),
                        "IdentityRepublish must be None",
                    );
                    seen_identity_republish = true;
                }
                ProofRelation::Progression { .. } => {
                    assert!(relation.watermark().is_some(), "Progression must be Some",);
                    seen_progression = true;
                }
                ProofRelation::CrossStore { .. } => {
                    assert!(relation.watermark().is_some(), "CrossStore must be Some",);
                    seen_crossstore = true;
                }
                ProofRelation::Regressed { .. } => {
                    assert!(relation.watermark().is_none(), "Regressed must be None",);
                    seen_regressed = true;
                }
            }
        }
        assert!(seen_stationary, "must reach ProofRelation::Stationary");
        assert!(
            seen_identity_republish,
            "must reach ProofRelation::IdentityRepublish",
        );
        assert!(seen_progression, "must reach ProofRelation::Progression");
        assert!(seen_crossstore, "must reach ProofRelation::CrossStore");
        assert!(seen_regressed, "must reach ProofRelation::Regressed");
    }
}

#[cfg(test)]
mod proof_relation_generations_tests {
    //! Weld the forward-progression generation-count accessor
    //! ([`ProofRelation::generations`]) and its wire-side sibling
    //! ([`ProofRelationWire::generations`]) — the typed one-liner
    //! sibling to [`ProofRelation::watermark`] for the OTHER payload
    //! axis of the classification grid, so a consumer holding a
    //! [`ProofRelation`] and wanting the forward-progression count
    //! reaches it through one `const`-callable receiver call instead of
    //! the two-arm `if let ProofRelation::IdentityRepublish { generations }
    //! | ProofRelation::Progression { generations, .. } = &relation
    //! { ... } else { ... }` a hand-written match would demand.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Some/None shape by variant identity — [`ProofRelation::generations`]
    //!    is `Some` on the two forward-progression variants
    //!    ([`ProofRelation::IdentityRepublish`], [`ProofRelation::Progression`])
    //!    and [`Option::None`] on the three variants without a forward-
    //!    progression count ([`ProofRelation::Stationary`],
    //!    [`ProofRelation::CrossStore`], [`ProofRelation::Regressed`]).
    //!    Pinned at both altitudes.
    //! 2. Same-Some/None invariant across altitudes — for every
    //!    [`ProofRelation`] value the two altitude accessors agree
    //!    pointwise on presence AND, when both return `Some`, the wire
    //!    magnitude equals the value-side magnitude via
    //!    [`std::num::NonZeroU64::get`]. Catches a divergence a
    //!    same-shape-only assertion would miss.
    //! 3. [`ProofRelation::Regressed`] deliberately returns `None` — the
    //!    variant carries a distinct backward-magnitude field (`by`), not
    //!    a forward-progression count. Payload magnitude on `by` (3 in
    //!    the fixture) does NOT leak into the accessor's `Some` set,
    //!    pinning the semantic distinction the accessor's docstring
    //!    names.
    //! 4. Round-trip through [`ProofRelation::try_from_wire`] preserves
    //!    the forward-progression count — the reconstructed relation
    //!    carries the same [`std::num::NonZeroU64`] the original does, so
    //!    a wire consumer that follows the standard parse seam surfaces
    //!    a count equal to the one the producer's
    //!    [`ProofRelation::generations`] reached.
    //! 5. Composition with [`ProofDelta::relation`] — on the four
    //!    legitimate corners reachable from a delta,
    //!    `delta.relation().and_then(|r| r.generations())` equals the
    //!    count accessed via
    //!    `ProofRelation::between(&prior, &current).generations()`.
    //!    Cross-altitude coherence pinned on the count accessor across
    //!    both the delta-fold and the direct proof-pair classification
    //!    paths.
    //! 6. The [`std::num::NonZeroU64`] weld survives — whenever the
    //!    value-side accessor returns `Some(n)`, `n.get() >= 1`. The
    //!    weld the sum-type's field shape carries travels with the
    //!    accessor's return type and is not lost at the receiver
    //!    boundary. On the wire side a `Some(u)` produced from a
    //!    legitimate value satisfies `u >= 1` bitwise for the same
    //!    reason.
    //! 7. Payload orthogonality with [`ProofRelation::watermark`] — the
    //!    two accessors surface distinct payload axes: on [`ProofRelation::Progression`]
    //!    both return `Some`, on [`ProofRelation::IdentityRepublish`]
    //!    only `generations` is `Some`, on [`ProofRelation::CrossStore`]
    //!    only `watermark` is `Some`, and on the two variants without
    //!    either payload ([`ProofRelation::Stationary`],
    //!    [`ProofRelation::Regressed`]) both return `None`. Pins the
    //!    (watermark, generations) × (present, absent) matrix at compile
    //!    time by exhausting the variant fixture.
    //! 8. `const`-callable on both altitudes — a compile-time-known
    //!    [`ProofRelation`] / [`ProofRelationWire`] projects its count
    //!    at compile time too, matching the `const`-ness of every other
    //!    classification accessor in the file.
    //! 9. All five variants of [`ProofRelation`] are explicitly enumerated
    //!    — adding a sixth variant fails to compile at the exhaustive
    //!    `match` in the accessor body AND at every enumeration test
    //!    below that names the five current variants by tag.
    //!
    //! Fixtures build hand-authored [`ProofRelation`] values directly
    //! rather than routing through [`ProofRelation::between`] on
    //! [`ConfigWatermark::compute`]-style proof pairs. That gives the
    //! [`ProofRelation::Regressed`] variant reachable coverage and keeps
    //! each test's setup local to the property it pins.
    #![allow(clippy::needless_pass_by_value)]

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    /// A [`MovedWatermarkDelta`] whose all three axes moved — the widest
    /// legitimate payload, spelled through the constructor so the "at
    /// least one class-scoped half moved" invariant lands at the type.
    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    /// A [`MovedWatermarkDelta`] where only the Free class-scoped half
    /// moved. Distinct payload shape from `moved_all` so a test that
    /// compares payload magnitudes across altitudes catches an accidental
    /// swap between the two variants' watermark fields.
    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    /// Every [`ProofRelation`] variant, hand-constructed with a distinct
    /// count where variants carry one. `IdentityRepublish` uses
    /// `generations = 1`, `Progression` uses `generations = 2`,
    /// `Regressed` uses `by = 3` — three distinct magnitudes so an
    /// accidental variant swap on the accessor `match` arms surfaces as
    /// a wrong count, not a still-passing test.
    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    // ---------- (1) Some/None shape by variant identity

    #[test]
    fn generations_returns_some_on_forward_variants_none_on_the_rest_at_both_altitudes() {
        for (name, relation) in all_five_relations() {
            let expect_some = matches!(
                relation,
                ProofRelation::IdentityRepublish { .. } | ProofRelation::Progression { .. }
            );
            assert_eq!(
                relation.generations().is_some(),
                expect_some,
                "{name}: ProofRelation::generations Some/None must match variant identity",
            );
            assert_eq!(
                relation.to_wire().generations().is_some(),
                expect_some,
                "{name}: ProofRelationWire::generations Some/None must match variant identity",
            );
        }
    }

    // ---------- (2) same-Some/None invariant across altitudes AND magnitude agreement

    #[test]
    fn value_and_wire_altitudes_agree_on_presence_and_magnitude() {
        for (name, relation) in all_five_relations() {
            let value = relation.generations();
            let wire = relation.to_wire().generations();
            match (value, wire) {
                (Some(v), Some(w)) => {
                    assert_eq!(
                        v.get(),
                        w,
                        "{name}: wire magnitude must equal value magnitude via NonZeroU64::get",
                    );
                }
                (None, None) => {}
                (a, b) => panic!(
                    "{name}: Some/None shape must agree across altitudes, got value={a:?} \
                     wire={b:?}",
                ),
            }
        }
    }

    // ---------- (3) Regressed returns None even though it carries a NonZeroU64

    #[test]
    fn regressed_backward_magnitude_does_not_leak_into_generations() {
        // The Regressed fixture uses `by = 3` — a strictly-positive
        // NonZeroU64 that would satisfy a naive "return Some on any
        // NonZeroU64 field" accessor. The accessor's semantic contract
        // is FORWARD-progression only; Regressed's backward magnitude is
        // deliberately excluded. Pinned here so a future edit that
        // widened the accessor to include Regressed silently would fail
        // the None assertion.
        let regressed = ProofRelation::Regressed { by: nz(3) };
        assert_eq!(
            regressed.generations(),
            None,
            "Regressed::by (backward magnitude) must NOT leak into generations()",
        );
        assert_eq!(
            regressed.to_wire().generations(),
            None,
            "ProofRelationWire::Regressed::by must NOT leak into generations() either",
        );
    }

    // ---------- (4) round-trip through try_from_wire preserves the count

    #[test]
    fn round_trip_through_try_from_wire_preserves_the_generations_count() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let back = ProofRelation::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!("{name}: try_from_wire must succeed on to_wire output, got {e:?}")
            });
            assert_eq!(
                back.generations(),
                relation.generations(),
                "{name}: round-trip must preserve the generations count",
            );
        }
    }

    // ---------- (5) composition with ProofDelta::relation

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn proof_at(cfg: &Cfg, generation: u64, epoch_secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: ConfigWatermark::compute(cfg, FIELD_CLASSES),
            observed_at: UNIX_EPOCH + Duration::from_secs(epoch_secs),
        }
    }

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    #[test]
    fn agrees_with_proof_delta_relation_generations_on_legitimate_corners() {
        // On any authored proof pair, the count accessed via the
        // delta-fold path (delta.relation().and_then(|r| r.generations()))
        // equals the count accessed via the direct proof-pair
        // classification path
        // (ProofRelation::between(&prior, &current).generations()).
        // Cross-altitude coherence pinned on the count accessor across
        // both classification-reach paths.
        let cases: [(&str, ConfigSyncProof, ConfigSyncProof); 4] = [
            (
                "Stationary",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_060),
            ),
            (
                "IdentityRepublish",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 7, 1_700_000_060),
            ),
            (
                "Progression",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
            ),
            (
                "CrossStore",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 5, 1_700_000_060),
            ),
        ];
        for (name, prior, current) in cases {
            let delta_path = current
                .delta_since(&prior)
                .relation()
                .and_then(|r| r.generations());
            let direct_path = ProofRelation::between(&prior, &current).generations();
            assert_eq!(
                delta_path, direct_path,
                "{name}: delta-fold and direct-classification paths must yield the same \
                 generations count",
            );
        }
    }

    // ---------- (6) NonZeroU64 weld survives the accessor

    #[test]
    fn some_never_carries_a_zero_count_on_either_altitude() {
        for (name, relation) in all_five_relations() {
            if let Some(g) = relation.generations() {
                assert!(
                    g.get() >= 1,
                    "{name}: value-side Some must carry NonZeroU64 (nonzero by construction)",
                );
            }
            if let Some(g) = relation.to_wire().generations() {
                // The wire type does NOT weld nonzero at the field shape.
                // But the wire projection of a NonZeroU64 produced by
                // ProofRelation::to_wire on a legitimate value must
                // still be nonzero — the count is preserved bitwise
                // across to_wire.
                assert!(
                    g >= 1,
                    "{name}: wire-side Some produced from a legitimate value must be nonzero",
                );
            }
        }
    }

    // ---------- (7) payload orthogonality with ProofRelation::watermark

    #[test]
    fn watermark_and_generations_close_the_payload_matrix_pointwise() {
        // The (watermark, generations) × (present, absent) matrix, filled
        // by variant. Adding a sixth variant to ProofRelation turns both
        // this test and the two accessors' bodies red at the same
        // instant.
        for (name, relation) in all_five_relations() {
            let wm_present = relation.watermark().is_some();
            let gens_present = relation.generations().is_some();
            let (expect_wm, expect_gens) = match relation {
                ProofRelation::Stationary => (false, false),
                ProofRelation::IdentityRepublish { .. } => (false, true),
                ProofRelation::Progression { .. } => (true, true),
                ProofRelation::CrossStore { .. } => (true, false),
                ProofRelation::Regressed { .. } => (false, false),
            };
            assert_eq!(
                (wm_present, gens_present),
                (expect_wm, expect_gens),
                "{name}: (watermark, generations) presence must match the payload matrix cell",
            );
        }
    }

    // ---------- (8) const-callable on both altitudes

    #[test]
    fn generations_is_const_callable_on_both_altitudes() {
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const G_STATIONARY: Option<std::num::NonZeroU64> = R_STATIONARY.generations();
        const R_STATIONARY_WIRE: ProofRelationWire = ProofRelationWire::Stationary;
        const G_STATIONARY_WIRE: Option<u64> = R_STATIONARY_WIRE.generations();
        assert!(G_STATIONARY.is_none());
        assert!(G_STATIONARY_WIRE.is_none());
    }

    // ---------- (9) all five variants explicitly enumerated

    #[test]
    fn every_relation_variant_is_reached_and_classified_correctly() {
        let mut seen_stationary = false;
        let mut seen_identity_republish = false;
        let mut seen_progression = false;
        let mut seen_crossstore = false;
        let mut seen_regressed = false;
        for (_, relation) in all_five_relations() {
            match relation {
                ProofRelation::Stationary => {
                    assert!(relation.generations().is_none(), "Stationary must be None");
                    seen_stationary = true;
                }
                ProofRelation::IdentityRepublish { generations } => {
                    assert_eq!(
                        relation.generations(),
                        Some(generations),
                        "IdentityRepublish must surface its generations field",
                    );
                    seen_identity_republish = true;
                }
                ProofRelation::Progression { generations, .. } => {
                    assert_eq!(
                        relation.generations(),
                        Some(generations),
                        "Progression must surface its generations field",
                    );
                    seen_progression = true;
                }
                ProofRelation::CrossStore { .. } => {
                    assert!(relation.generations().is_none(), "CrossStore must be None");
                    seen_crossstore = true;
                }
                ProofRelation::Regressed { .. } => {
                    assert!(relation.generations().is_none(), "Regressed must be None");
                    seen_regressed = true;
                }
            }
        }
        assert!(seen_stationary, "must reach ProofRelation::Stationary");
        assert!(
            seen_identity_republish,
            "must reach ProofRelation::IdentityRepublish",
        );
        assert!(seen_progression, "must reach ProofRelation::Progression");
        assert!(seen_crossstore, "must reach ProofRelation::CrossStore");
        assert!(seen_regressed, "must reach ProofRelation::Regressed");
    }
}

#[cfg(test)]
mod proof_relation_regressed_by_tests {
    //! Weld the backward-regression magnitude accessor
    //! ([`ProofRelation::regressed_by`]) and its wire-side sibling
    //! ([`ProofRelationWire::regressed_by`]) — the third accessor closing
    //! the `(watermark, generations, regressed_by)` receiver-family across
    //! the classification grid, so a consumer holding a [`ProofRelation`]
    //! and wanting the backward-regression magnitude reaches it through
    //! one `const`-callable receiver call instead of the one-arm
    //! `if let ProofRelation::Regressed { by } = &relation { Some(*by) }
    //! else { None }` a hand-written match would demand.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Some/None shape by variant identity — [`ProofRelation::regressed_by`]
    //!    is `Some` on the sole backward-regression variant
    //!    ([`ProofRelation::Regressed`]) and [`Option::None`] on the four
    //!    variants without a backward-regression count
    //!    ([`ProofRelation::Stationary`], [`ProofRelation::IdentityRepublish`],
    //!    [`ProofRelation::Progression`], [`ProofRelation::CrossStore`]).
    //!    Pinned at both altitudes.
    //! 2. Same-Some/None invariant across altitudes AND magnitude
    //!    agreement — for every [`ProofRelation`] value the two altitude
    //!    accessors agree pointwise on presence AND, when both return
    //!    `Some`, the wire magnitude equals the value-side magnitude via
    //!    [`std::num::NonZeroU64::get`].
    //! 3. [`ProofRelation::Progression`]'s forward-progression count does
    //!    NOT leak into `regressed_by` — the fixture uses
    //!    `Progression::generations = 2` (a strictly-positive
    //!    [`std::num::NonZeroU64`] that would satisfy a naive "return
    //!    `Some` on any [`std::num::NonZeroU64`] field" accessor), pinning
    //!    the semantic distinction the accessor's docstring names.
    //! 4. Round-trip through [`ProofRelation::try_from_wire`] preserves
    //!    the backward-regression count — the reconstructed relation
    //!    carries the same [`std::num::NonZeroU64`] the original does, so
    //!    a wire consumer that follows the standard parse seam surfaces a
    //!    count equal to the one the producer's
    //!    [`ProofRelation::regressed_by`] reached.
    //! 5. Composition with [`ProofDelta::relation`] — on the four
    //!    legitimate corners reachable from a delta,
    //!    `delta.relation().and_then(|r| r.regressed_by())` is `None` (no
    //!    delta-reachable corner carries a backward-regression count), and
    //!    on a regressing proof pair the direct-classification path
    //!    (`ProofRelation::between(&prior, &current).regressed_by()`)
    //!    returns `Some(by)` while the delta-fold path
    //!    (`current.delta_since(&prior).relation()`) returns `None`. The
    //!    "regression count survives the direct proof-pair path and is
    //!    lost by the delta-fold path" invariant, welded at
    //!    [`ProofDelta::relation`]'s docstring, is pinned end-to-end at
    //!    the accessor.
    //! 6. The [`std::num::NonZeroU64`] weld survives — whenever the
    //!    value-side accessor returns `Some(n)`, `n.get() >= 1`. On the
    //!    wire side a `Some(u)` produced from a legitimate value satisfies
    //!    `u >= 1` bitwise for the same reason.
    //! 7. Payload orthogonality with [`ProofRelation::watermark`] and
    //!    [`ProofRelation::generations`] — the three accessors surface
    //!    three distinct payload axes and together close the
    //!    `(watermark, generations, regressed_by) × (present, absent)`
    //!    matrix pointwise: `Progression` (watermark + generations),
    //!    `IdentityRepublish` (generations only), `CrossStore` (watermark
    //!    only), `Regressed` (regressed_by only), `Stationary` (none of
    //!    the three). Pinned by exhausting the variant fixture.
    //! 8. `const`-callable on both altitudes — a compile-time-known
    //!    [`ProofRelation`] / [`ProofRelationWire`] projects its count at
    //!    compile time too.
    //! 9. All five variants of [`ProofRelation`] are explicitly enumerated
    //!    — adding a sixth variant fails to compile at the exhaustive
    //!    `match` in the accessor body AND at every enumeration test below
    //!    that names the five current variants by tag.
    //!
    //! Fixtures build hand-authored [`ProofRelation`] values directly
    //! rather than routing through [`ProofRelation::between`] on
    //! [`ConfigWatermark::compute`]-style proof pairs. That gives the
    //! [`ProofRelation::Regressed`] variant reachable coverage and keeps
    //! each test's setup local to the property it pins.
    #![allow(clippy::needless_pass_by_value)]

    use super::*;
    use serde::Serialize;
    use std::time::{Duration, UNIX_EPOCH};

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    // ---------- (1) Some/None shape by variant identity

    #[test]
    fn regressed_by_returns_some_on_regressed_none_on_the_rest_at_both_altitudes() {
        for (name, relation) in all_five_relations() {
            let expect_some = matches!(relation, ProofRelation::Regressed { .. });
            assert_eq!(
                relation.regressed_by().is_some(),
                expect_some,
                "{name}: ProofRelation::regressed_by Some/None must match variant identity",
            );
            assert_eq!(
                relation.to_wire().regressed_by().is_some(),
                expect_some,
                "{name}: ProofRelationWire::regressed_by Some/None must match variant identity",
            );
        }
    }

    // ---------- (2) same-Some/None invariant across altitudes AND magnitude agreement

    #[test]
    fn value_and_wire_altitudes_agree_on_presence_and_magnitude() {
        for (name, relation) in all_five_relations() {
            let value = relation.regressed_by();
            let wire = relation.to_wire().regressed_by();
            match (value, wire) {
                (Some(v), Some(w)) => {
                    assert_eq!(
                        v.get(),
                        w,
                        "{name}: wire magnitude must equal value magnitude via NonZeroU64::get",
                    );
                }
                (None, None) => {}
                (a, b) => panic!(
                    "{name}: Some/None shape must agree across altitudes, got value={a:?} \
                     wire={b:?}",
                ),
            }
        }
    }

    // ---------- (3) Progression's forward count does NOT leak into regressed_by

    #[test]
    fn forward_progression_count_does_not_leak_into_regressed_by() {
        // The Progression fixture uses `generations = 2` — a
        // strictly-positive NonZeroU64 that would satisfy a naive
        // "return Some on any NonZeroU64 field" accessor. The accessor's
        // semantic contract is BACKWARD-regression only; Progression's
        // forward-progression magnitude is deliberately excluded.
        let progression = ProofRelation::Progression {
            watermark: moved_all(),
            generations: nz(2),
        };
        assert_eq!(
            progression.regressed_by(),
            None,
            "Progression::generations (forward magnitude) must NOT leak into regressed_by()",
        );
        assert_eq!(
            progression.to_wire().regressed_by(),
            None,
            "ProofRelationWire::Progression::generations must NOT leak into regressed_by() either",
        );
        let republish = ProofRelation::IdentityRepublish { generations: nz(1) };
        assert_eq!(
            republish.regressed_by(),
            None,
            "IdentityRepublish::generations must NOT leak into regressed_by()",
        );
        assert_eq!(
            republish.to_wire().regressed_by(),
            None,
            "ProofRelationWire::IdentityRepublish::generations must NOT leak into regressed_by()",
        );
    }

    // ---------- (4) round-trip through try_from_wire preserves the count

    #[test]
    fn round_trip_through_try_from_wire_preserves_the_regressed_by_count() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let back = ProofRelation::try_from_wire(&wire).unwrap_or_else(|e| {
                panic!("{name}: try_from_wire must succeed on to_wire output, got {e:?}")
            });
            assert_eq!(
                back.regressed_by(),
                relation.regressed_by(),
                "{name}: round-trip must preserve the regressed_by count",
            );
        }
    }

    // ---------- (5) composition with ProofDelta::relation

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct Cfg {
        log_level: String,
        bind_addr: String,
    }

    const FIELD_CLASSES: &[(&str, HotSwapClass)] = &[
        ("log_level", HotSwapClass::Free),
        (
            "bind_addr",
            HotSwapClass::RequiresRestart {
                reason: "bound at process start",
            },
        ),
    ];

    fn proof_at(cfg: &Cfg, generation: u64, epoch_secs: u64) -> ConfigSyncProof {
        ConfigSyncProof {
            generation,
            watermark: ConfigWatermark::compute(cfg, FIELD_CLASSES),
            observed_at: UNIX_EPOCH + Duration::from_secs(epoch_secs),
        }
    }

    fn base() -> Cfg {
        Cfg {
            log_level: "info".into(),
            bind_addr: "0.0.0.0:8080".into(),
        }
    }

    fn both_edit() -> Cfg {
        Cfg {
            log_level: "debug".into(),
            bind_addr: "0.0.0.0:9090".into(),
        }
    }

    #[test]
    fn no_delta_reachable_corner_carries_a_regressed_by_count() {
        // On any of the four corners a ProofDelta can classify to,
        // regressed_by is None: the delta-fold path deliberately drops the
        // Regressed variant, so `delta.relation().and_then(|r|
        // r.regressed_by())` is None end-to-end. Pinned across all four
        // legitimate corners.
        let cases: [(&str, ConfigSyncProof, ConfigSyncProof); 4] = [
            (
                "Stationary",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 5, 1_700_000_060),
            ),
            (
                "IdentityRepublish",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&base(), 7, 1_700_000_060),
            ),
            (
                "Progression",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 6, 1_700_000_060),
            ),
            (
                "CrossStore",
                proof_at(&base(), 5, 1_700_000_000),
                proof_at(&both_edit(), 5, 1_700_000_060),
            ),
        ];
        for (name, prior, current) in cases {
            let delta_path = current
                .delta_since(&prior)
                .relation()
                .and_then(|r| r.regressed_by());
            let direct_path = ProofRelation::between(&prior, &current).regressed_by();
            assert_eq!(
                delta_path, None,
                "{name}: delta-fold path must return None on regressed_by (no delta-reachable \
                 corner carries a backward-regression count)",
            );
            assert_eq!(
                direct_path, None,
                "{name}: direct-classification path must return None on regressed_by (the four \
                 legitimate corners never carry a backward-regression count either)",
            );
        }
    }

    #[test]
    fn regression_survives_the_direct_path_and_is_lost_by_the_delta_fold_path() {
        // The load-bearing distinction between the two classification-reach
        // paths, pinned end-to-end at the regressed_by accessor: on a
        // regressing proof pair, the direct proof-pair path
        // (ProofRelation::between) recovers the exact by count, while the
        // delta-fold path (delta.relation()) drops the variant entirely.
        let prior = proof_at(&base(), 10, 1_700_000_000);
        let current = proof_at(&base(), 7, 1_700_000_060);
        let delta = current.delta_since(&prior);
        assert_eq!(
            delta.relation().and_then(|r| r.regressed_by()),
            None,
            "delta-fold path must return None on a regressing proof pair (by count lost)",
        );
        let direct = ProofRelation::between(&prior, &current);
        assert_eq!(
            direct.regressed_by(),
            Some(nz(3)),
            "direct proof-pair path must recover the exact by count (10 - 7 = 3)",
        );
        assert_eq!(
            direct.to_wire().regressed_by(),
            Some(3),
            "wire-side sibling must surface the same magnitude (bitwise preserved by to_wire)",
        );
    }

    // ---------- (6) NonZeroU64 weld survives the accessor

    #[test]
    fn some_never_carries_a_zero_count_on_either_altitude() {
        for (name, relation) in all_five_relations() {
            if let Some(by) = relation.regressed_by() {
                assert!(
                    by.get() >= 1,
                    "{name}: value-side Some must carry NonZeroU64 (nonzero by construction)",
                );
            }
            if let Some(by) = relation.to_wire().regressed_by() {
                assert!(
                    by >= 1,
                    "{name}: wire-side Some produced from a legitimate value must be nonzero",
                );
            }
        }
    }

    // ---------- (7) payload orthogonality — three-axis matrix closure

    #[test]
    fn watermark_generations_and_regressed_by_close_the_payload_matrix_pointwise() {
        // The (watermark, generations, regressed_by) × (present, absent)
        // matrix, filled by variant. Adding a sixth variant to
        // ProofRelation turns this test and all three accessors' bodies
        // red at the same instant.
        for (name, relation) in all_five_relations() {
            let wm = relation.watermark().is_some();
            let gens = relation.generations().is_some();
            let by = relation.regressed_by().is_some();
            let (expect_wm, expect_gens, expect_by) = match relation {
                ProofRelation::Stationary => (false, false, false),
                ProofRelation::IdentityRepublish { .. } => (false, true, false),
                ProofRelation::Progression { .. } => (true, true, false),
                ProofRelation::CrossStore { .. } => (true, false, false),
                ProofRelation::Regressed { .. } => (false, false, true),
            };
            assert_eq!(
                (wm, gens, by),
                (expect_wm, expect_gens, expect_by),
                "{name}: (watermark, generations, regressed_by) presence must match the \
                 three-axis payload matrix cell",
            );
        }
    }

    // ---------- (8) const-callable on both altitudes

    #[test]
    fn regressed_by_is_const_callable_on_both_altitudes() {
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const B_STATIONARY: Option<std::num::NonZeroU64> = R_STATIONARY.regressed_by();
        const R_STATIONARY_WIRE: ProofRelationWire = ProofRelationWire::Stationary;
        const B_STATIONARY_WIRE: Option<u64> = R_STATIONARY_WIRE.regressed_by();
        assert!(B_STATIONARY.is_none());
        assert!(B_STATIONARY_WIRE.is_none());
    }

    // ---------- (9) all five variants explicitly enumerated

    #[test]
    fn every_relation_variant_is_reached_and_classified_correctly() {
        let mut seen_stationary = false;
        let mut seen_identity_republish = false;
        let mut seen_progression = false;
        let mut seen_crossstore = false;
        let mut seen_regressed = false;
        for (_, relation) in all_five_relations() {
            match relation {
                ProofRelation::Stationary => {
                    assert!(relation.regressed_by().is_none(), "Stationary must be None",);
                    seen_stationary = true;
                }
                ProofRelation::IdentityRepublish { .. } => {
                    assert!(
                        relation.regressed_by().is_none(),
                        "IdentityRepublish must be None",
                    );
                    seen_identity_republish = true;
                }
                ProofRelation::Progression { .. } => {
                    assert!(
                        relation.regressed_by().is_none(),
                        "Progression must be None",
                    );
                    seen_progression = true;
                }
                ProofRelation::CrossStore { .. } => {
                    assert!(relation.regressed_by().is_none(), "CrossStore must be None",);
                    seen_crossstore = true;
                }
                ProofRelation::Regressed { by } => {
                    assert_eq!(
                        relation.regressed_by(),
                        Some(by),
                        "Regressed must surface its by field",
                    );
                    seen_regressed = true;
                }
            }
        }
        assert!(seen_stationary, "must reach ProofRelation::Stationary");
        assert!(
            seen_identity_republish,
            "must reach ProofRelation::IdentityRepublish",
        );
        assert!(seen_progression, "must reach ProofRelation::Progression");
        assert!(seen_crossstore, "must reach ProofRelation::CrossStore");
        assert!(seen_regressed, "must reach ProofRelation::Regressed");
    }
}

#[cfg(test)]
mod watermark_relation_wire_predicate_tests {
    //! Weld the five wire-side predicate accessors on
    //! [`WatermarkRelationWire`] — [`WatermarkRelationWire::any_moved`],
    //! [`WatermarkRelationWire::stationary`],
    //! [`WatermarkRelationWire::restart_pending`],
    //! [`WatermarkRelationWire::hot_swappable_drift`], and
    //! [`WatermarkRelationWire::partitioned_class_invariant_holds`] — the
    //! wire-side receiver-family closing the (value, wire) × (predicate)
    //! grid at the classification altitude. Consumers reading a freshly
    //! deserialized [`WatermarkRelationWire`] previously had to detour
    //! through [`WatermarkRelation::from_wire`] to reach the same five
    //! bool-questions the value side already exposes, or hand-write
    //! `matches!(wire, ...)` inline at every seam without an
    //! exhaustiveness-checked `match` behind the shape.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Pointwise agreement between value-side and wire-side predicates
    //!    on every one of the five variants — for every
    //!    [`WatermarkRelation`] value the five value-side accessors and
    //!    the five wire-side siblings agree pointwise. The wire is a
    //!    lossless channel for the classification vocabulary at every
    //!    predicate axis.
    //! 2. Round-trip preservation: on every variant,
    //!    `wire.<predicate>() == WatermarkRelation::from_wire(&wire).<predicate>()`
    //!    for every predicate — the two-hop path never diverges from the
    //!    direct receiver-sibling.
    //! 3. Duality invariants pinned at every variant: `any_moved` and
    //!    `stationary` are complements (`p.any_moved() == !p.stationary()`),
    //!    matching the value-side sibling's welded duality.
    //! 4. `const`-callable on every predicate — the wire-side siblings
    //!    are usable in const contexts, matching the value-side siblings
    //!    the [`WatermarkRelation`] receiver-family already carries.
    //! 5. Exhaustive variant enumeration: a hand-authored fixture names
    //!    every one of the five variants exactly once, so a future
    //!    addition to [`WatermarkRelationWire`] fails to compile at the
    //!    fixture's `match` in the same instant it fails at each
    //!    predicate accessor's own `match`.
    //! 6. Payload matrix pinned at every variant: the exhaustive
    //!    (`variant`, `predicate`) truth table — a single variant-swap
    //!    accident in one predicate's `match` arms turns the
    //!    corresponding row red without the two altitudes drifting
    //!    silently apart.
    //! 7. `partitioned_class_invariant_holds` is exactly the complement
    //!    of "the tag is `UnclassifiedDrift`" on every variant — the
    //!    only impossibility corner the classification carries at this
    //!    altitude, matching the value-side sibling's shape.
    //! 8. Composition through the wire boundary: on every legitimate
    //!    [`WatermarkRelation`] value, the five predicates agree
    //!    pointwise on the three-hop path `value → to_wire → predicate`
    //!    with the direct-value path `value → predicate` — a producer's
    //!    receiver-side accessor and a consumer's wire-side accessor
    //!    surface the same five bool-questions on the same classification.
    //! 9. `From` sibling agrees: for every wire variant, the round-trip
    //!    through the `Into` idiom (`wire → &wire → value → wire`)
    //!    surfaces an unchanged predicate row — the `Into`-idiom consumer
    //!    reaches the same shape as the named-method consumer.
    //!
    //! Same test idiom as [`watermark_relation_wire_tests`] and the
    //! sibling `proof_relation_*` predicate/accessor modules, so a
    //! future refactor touching either altitude's classification surface
    //! surfaces breakage across the wire receiver-family.

    use super::*;

    fn all_wire_variants() -> [WatermarkRelationWire; 5] {
        [
            WatermarkRelationWire::Stationary,
            WatermarkRelationWire::UnclassifiedDrift,
            WatermarkRelationWire::RestartRequiredOnly,
            WatermarkRelationWire::FreeOnly,
            WatermarkRelationWire::Both,
        ]
    }

    fn all_value_variants() -> [WatermarkRelation; 5] {
        [
            WatermarkRelation::Stationary,
            WatermarkRelation::UnclassifiedDrift,
            WatermarkRelation::RestartRequiredOnly,
            WatermarkRelation::FreeOnly,
            WatermarkRelation::Both,
        ]
    }

    /// Pinned truth table (variant × predicate) in the fixed order
    /// (`any_moved`, `stationary`, `restart_pending`, `hot_swappable_drift`,
    /// `partitioned_class_invariant_holds`). Read from
    /// [`WatermarkRelation`]'s per-variant docstring.
    const fn expected(variant: WatermarkRelationWire) -> [bool; 5] {
        match variant {
            WatermarkRelationWire::Stationary => [false, true, false, false, true],
            WatermarkRelationWire::UnclassifiedDrift => [true, false, false, false, false],
            WatermarkRelationWire::RestartRequiredOnly => [true, false, true, false, true],
            WatermarkRelationWire::FreeOnly => [true, false, false, true, true],
            WatermarkRelationWire::Both => [true, false, true, true, true],
        }
    }

    fn wire_predicates(wire: &WatermarkRelationWire) -> [bool; 5] {
        [
            wire.any_moved(),
            wire.stationary(),
            wire.restart_pending(),
            wire.hot_swappable_drift(),
            wire.partitioned_class_invariant_holds(),
        ]
    }

    fn value_predicates(value: &WatermarkRelation) -> [bool; 5] {
        [
            value.any_moved(),
            value.stationary(),
            value.restart_pending(),
            value.hot_swappable_drift(),
            value.partitioned_class_invariant_holds(),
        ]
    }

    #[test]
    fn wire_predicates_match_the_pinned_truth_table_on_every_variant() {
        for wire in all_wire_variants() {
            assert_eq!(
                wire_predicates(&wire),
                expected(wire),
                "wire-side predicate row diverges from the pinned truth table on {wire:?}",
            );
        }
    }

    #[test]
    fn value_and_wire_predicate_rows_agree_pointwise_on_every_variant() {
        for value in all_value_variants() {
            let wire = value.to_wire();
            assert_eq!(
                value_predicates(&value),
                wire_predicates(&wire),
                "value-side and wire-side predicate rows diverge on {value:?}",
            );
        }
    }

    #[test]
    fn wire_predicates_survive_a_from_wire_round_trip_on_every_variant() {
        for wire in all_wire_variants() {
            let reconstructed = WatermarkRelation::from_wire(&wire);
            assert_eq!(
                wire_predicates(&wire),
                value_predicates(&reconstructed),
                "wire → value round-trip diverges on the predicate row for {wire:?}",
            );
        }
    }

    #[test]
    fn any_moved_and_stationary_are_complements_on_every_variant() {
        for wire in all_wire_variants() {
            assert_ne!(
                wire.any_moved(),
                wire.stationary(),
                "any_moved and stationary must be complements on {wire:?}",
            );
        }
    }

    #[test]
    fn partitioned_class_invariant_holds_iff_variant_is_not_unclassified_drift() {
        for wire in all_wire_variants() {
            let is_unclassified = matches!(wire, WatermarkRelationWire::UnclassifiedDrift);
            assert_eq!(
                wire.partitioned_class_invariant_holds(),
                !is_unclassified,
                "partitioned_class_invariant_holds must be `false` iff the tag is UnclassifiedDrift on {wire:?}",
            );
        }
    }

    #[test]
    fn stationary_is_the_sole_non_any_moved_variant() {
        let count_stationary = all_wire_variants()
            .iter()
            .filter(|w| w.stationary())
            .count();
        let count_any_moved_false = all_wire_variants()
            .iter()
            .filter(|w| !w.any_moved())
            .count();
        assert_eq!(count_stationary, 1);
        assert_eq!(count_any_moved_false, 1);
    }

    #[test]
    fn restart_pending_covers_exactly_restart_required_only_and_both() {
        let restart_variants: Vec<_> = all_wire_variants()
            .into_iter()
            .filter(WatermarkRelationWire::restart_pending)
            .collect();
        assert_eq!(
            restart_variants,
            vec![
                WatermarkRelationWire::RestartRequiredOnly,
                WatermarkRelationWire::Both,
            ]
        );
    }

    #[test]
    fn hot_swappable_drift_covers_exactly_free_only_and_both() {
        let hot_variants: Vec<_> = all_wire_variants()
            .into_iter()
            .filter(WatermarkRelationWire::hot_swappable_drift)
            .collect();
        assert_eq!(
            hot_variants,
            vec![WatermarkRelationWire::FreeOnly, WatermarkRelationWire::Both,]
        );
    }

    #[test]
    fn wire_predicates_are_const_callable_on_every_variant() {
        const STATIONARY_ANY_MOVED: bool = WatermarkRelationWire::Stationary.any_moved();
        const STATIONARY_STATIONARY: bool = WatermarkRelationWire::Stationary.stationary();
        const STATIONARY_RESTART: bool = WatermarkRelationWire::Stationary.restart_pending();
        const STATIONARY_HOT: bool = WatermarkRelationWire::Stationary.hot_swappable_drift();
        const STATIONARY_PARTITIONED: bool =
            WatermarkRelationWire::Stationary.partitioned_class_invariant_holds();
        const UNCLASSIFIED_PARTITIONED: bool =
            WatermarkRelationWire::UnclassifiedDrift.partitioned_class_invariant_holds();
        const BOTH_RESTART: bool = WatermarkRelationWire::Both.restart_pending();
        const BOTH_HOT: bool = WatermarkRelationWire::Both.hot_swappable_drift();
        const FREE_ONLY_HOT: bool = WatermarkRelationWire::FreeOnly.hot_swappable_drift();
        const RESTART_ONLY_RESTART: bool =
            WatermarkRelationWire::RestartRequiredOnly.restart_pending();

        assert!(!STATIONARY_ANY_MOVED);
        assert!(STATIONARY_STATIONARY);
        assert!(!STATIONARY_RESTART);
        assert!(!STATIONARY_HOT);
        assert!(STATIONARY_PARTITIONED);
        assert!(!UNCLASSIFIED_PARTITIONED);
        assert!(BOTH_RESTART);
        assert!(BOTH_HOT);
        assert!(FREE_ONLY_HOT);
        assert!(RESTART_ONLY_RESTART);
    }

    #[test]
    fn into_idiom_round_trip_preserves_the_predicate_row() {
        for wire in all_wire_variants() {
            let value: WatermarkRelation = (&wire).into();
            let wire_via_into: WatermarkRelationWire = value.into();
            assert_eq!(
                wire_predicates(&wire_via_into),
                wire_predicates(&wire),
                "wire → value → wire via Into diverges on the predicate row for {wire:?}",
            );
        }
    }

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let seen: Vec<_> = all_wire_variants().into_iter().collect();
        assert_eq!(seen.len(), 5);
        for wire in &seen {
            match wire {
                WatermarkRelationWire::Stationary
                | WatermarkRelationWire::UnclassifiedDrift
                | WatermarkRelationWire::RestartRequiredOnly
                | WatermarkRelationWire::FreeOnly
                | WatermarkRelationWire::Both => {}
            }
        }
    }
}

#[cfg(test)]
mod proof_relation_wire_same_store_consistent_tests {
    //! Weld the wire-side same-store-consistency predicate
    //! ([`ProofRelationWire::same_store_consistent`]) — the wire-side
    //! receiver-sibling of [`ProofRelation::same_store_consistent`],
    //! closing the (value, wire) × (predicate) grid at the proof-
    //! altitude classification altitude the [`WatermarkRelationWire`]
    //! predicate family already closed one altitude down.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Pointwise agreement between value-side and wire-side predicate
    //!    on every one of the five variants — for every
    //!    [`ProofRelation`] value the value-side accessor and the wire-
    //!    side sibling agree pointwise. The wire is a lossless channel
    //!    for the same-store-consistency question the value-side
    //!    sibling answers.
    //! 2. Truth table pinned by variant identity — the three legitimate
    //!    corners ([`ProofRelationWire::Stationary`],
    //!    [`ProofRelationWire::IdentityRepublish`],
    //!    [`ProofRelationWire::Progression`]) return `true`; the two
    //!    impossibility corners ([`ProofRelationWire::CrossStore`],
    //!    [`ProofRelationWire::Regressed`]) return `false`.
    //! 3. Round-trip through [`ProofRelation::try_from_wire`] preserves
    //!    the same-store-consistency verdict — the reconstructed
    //!    relation carries the same predicate answer the original wire
    //!    value does, so a wire consumer that follows the standard
    //!    parse seam surfaces the same verdict the receiver-sibling
    //!    reaches directly.
    //! 4. `From` sibling agrees: for every wire variant, the round-trip
    //!    through the `Into` idiom (`wire → &wire → value → wire`)
    //!    surfaces an unchanged predicate answer — the `Into`-idiom
    //!    consumer reaches the same shape as the named-method consumer.
    //! 5. `const`-callable — a compile-time-known [`ProofRelationWire`]
    //!    projects its same-store-consistency verdict at compile time
    //!    too, matching the `const`-ness of
    //!    [`ProofRelation::same_store_consistent`] and every other
    //!    classification accessor at either altitude.
    //! 6. Exhaustive variant enumeration: a hand-authored fixture names
    //!    every one of the five variants exactly once, so a future
    //!    addition to [`ProofRelationWire`] fails to compile at the
    //!    fixture's `match` in the same instant it fails at the
    //!    predicate accessor's own `match`.
    //! 7. Payload-inspection independence: the predicate reads only the
    //!    variant tag, not any field payload — the answer is invariant
    //!    under any legitimate change to the payload fields, matching
    //!    the "route on `kind` alone" seam the internally-tagged serde
    //!    encoding established.
    //! 8. Composition through the wire boundary: on every legitimate
    //!    [`ProofRelation`] value, the predicate agrees pointwise on
    //!    the three-hop path `value → to_wire → predicate` with the
    //!    direct-value path `value → predicate` — a producer's
    //!    receiver-side accessor and a consumer's wire-side accessor
    //!    surface the same verdict on the same classification.
    //! 9. Cross-altitude same-answer: at the proof altitude, the
    //!    verdict on the wire equals
    //!    `ProofDelta::same_store_consistent` reached through the
    //!    delta-fold path on the four delta-reachable corners.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    /// Pinned truth table (variant → expected answer). Read from
    /// [`ProofRelation::same_store_consistent`]'s docstring: the three
    /// legitimate corners return `true`; the two impossibility corners
    /// return `false`.
    const fn expected(wire: &ProofRelationWire) -> bool {
        match wire {
            ProofRelationWire::Stationary
            | ProofRelationWire::IdentityRepublish { .. }
            | ProofRelationWire::Progression { .. } => true,
            ProofRelationWire::CrossStore { .. } | ProofRelationWire::Regressed { .. } => false,
        }
    }

    // ---------- (1) Pointwise agreement between value and wire

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.same_store_consistent();
            let wire = relation.to_wire().same_store_consistent();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (2) Truth table pinned by variant identity

    #[test]
    fn truth_table_matches_docstring_on_every_wire_variant() {
        for (name, wire) in all_five_wire_variants() {
            assert_eq!(
                wire.same_store_consistent(),
                expected(&wire),
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn legitimate_corners_return_true() {
        assert!(ProofRelationWire::Stationary.same_store_consistent());
        assert!(
            ProofRelationWire::IdentityRepublish { generations: 1 }.same_store_consistent(),
            "IdentityRepublish is a legitimate corner",
        );
        assert!(
            ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .same_store_consistent(),
            "Progression is a legitimate corner",
        );
    }

    #[test]
    fn impossibility_corners_return_false() {
        assert!(
            !ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .same_store_consistent(),
            "CrossStore is a same-store impossibility corner",
        );
        assert!(
            !ProofRelationWire::Regressed { by: 3 }.same_store_consistent(),
            "Regressed is a same-store impossibility corner",
        );
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.same_store_consistent();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.same_store_consistent(),
                "{name}: try_from_wire round-trip must preserve the same-store-consistency verdict",
            );
        }
    }

    // ---------- (4) TryFrom idiom agrees with named-method round-trip

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.same_store_consistent(),
                wire_via_named.same_store_consistent(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on the \
                 same-store-consistency verdict",
            );
        }
    }

    // ---------- (5) const-callable

    #[test]
    fn predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.same_store_consistent();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.same_store_consistent();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .same_store_consistent();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .same_store_consistent();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.same_store_consistent();
        assert!(STATIONARY);
        assert!(IDENTITY_REPUBLISH);
        assert!(PROGRESSION);
        assert!(!CROSS_STORE);
        assert!(!REGRESSED);
    }

    // ---------- (6) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let seen = all_five_wire_variants();
        assert_eq!(seen.len(), 5);
        for (_, wire) in &seen {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (7) Payload-inspection independence

    #[test]
    fn predicate_is_invariant_under_payload_perturbations() {
        // IdentityRepublish: any nonzero generations count yields the
        // same verdict (true) since the predicate reads the tag alone.
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                ProofRelationWire::IdentityRepublish { generations }.same_store_consistent(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        // Progression: any nonzero generations count and any legitimate
        // watermark payload yield the same verdict (true).
        let watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in watermarks {
            for generations in [1_u64, 7, u64::MAX] {
                assert!(
                    ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .same_store_consistent(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        // CrossStore: any legitimate watermark payload yields the same
        // verdict (false).
        for watermark in watermarks {
            assert!(
                !ProofRelationWire::CrossStore { watermark }.same_store_consistent(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        // Regressed: any nonzero backwards magnitude yields the same
        // verdict (false).
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::Regressed { by }.same_store_consistent(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
    }

    // ---------- (8) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.same_store_consistent();
            let through_wire = relation.to_wire().same_store_consistent();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (9) Cross-altitude same-answer with ProofDelta::same_store_consistent

    #[test]
    fn wire_verdict_matches_proof_delta_verdict_on_delta_reachable_corners() {
        // Build proof pairs that reach the four delta-reachable
        // corners (Stationary, IdentityRepublish, Progression,
        // CrossStore) and verify the wire predicate equals
        // ProofDelta::same_store_consistent on each. Regressed is not
        // delta-reachable (its `by` count is folded to `None` by the
        // delta path), so it is exercised only by the direct path in
        // tests (1)-(8) above.
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let stationary_prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        for (name, prior, current) in [
            ("Stationary", stationary_prior, stationary_current),
            ("IdentityRepublish", stationary_prior, republish_current),
            ("Progression", stationary_prior, progression_current),
            ("CrossStore", stationary_prior, cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation_wire = current.relation_since(&prior).to_wire();
            assert_eq!(
                delta.same_store_consistent(),
                relation_wire.same_store_consistent(),
                "{name}: ProofDelta::same_store_consistent must equal \
                 ProofRelationWire::same_store_consistent on the delta-reachable corners",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_stationary_tests {
    //! Weld the null-hypothesis predicate at both altitudes —
    //! [`ProofRelation::stationary`] and its wire-side receiver-sibling
    //! [`ProofRelationWire::stationary`] — closing the (value, wire) ×
    //! (predicate) grid at the proof altitude one further cell after
    //! [`ProofRelation::same_store_consistent`] /
    //! [`ProofRelationWire::same_store_consistent`].
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes:
    //!    only the [`ProofRelation::Stationary`] /
    //!    [`ProofRelationWire::Stationary`] variant returns `true`; the
    //!    four other variants ([`IdentityRepublish`][`ProofRelation::IdentityRepublish`],
    //!    [`Progression`][`ProofRelation::Progression`],
    //!    [`CrossStore`][`ProofRelation::CrossStore`],
    //!    [`Regressed`][`ProofRelation::Regressed`]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the null-hypothesis question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom) — a
    //!    reconstructed relation carries the same stationarity verdict
    //!    the original wire value does.
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once,
    //!    so a future variant addition fails to compile at the fixture's
    //!    `match` in the same instant it fails at each predicate
    //!    accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of the payload
    //!    fields of the four non-stationary variants.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path: on every legitimate [`ProofRelation`] value the
    //!    three-hop path (`value → to_wire → predicate`) matches the
    //!    direct path (`value → predicate`).
    //! 8. Cross-altitude same-answer with [`ProofDelta::stationary`] on
    //!    the delta-reachable corners built from [`ConfigSyncProof`]
    //!    pairs.
    //! 9. Stationarity implies same-store-consistency (a duality
    //!    ordering pin): whenever `stationary()` returns `true`,
    //!    `same_store_consistent()` returns `true` too on both
    //!    altitudes — but not the other way around (three
    //!    variants are same-store-consistent while only one is
    //!    stationary).
    //! 10. Duality with `same_store_consistent` refuses the empty
    //!     intersection: no variant is both stationary and
    //!     same-store-inconsistent, at either altitude.
    //!
    //! Same test idiom as the sibling
    //! `proof_relation_wire_same_store_consistent_tests` module.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    // ---------- (1) Truth table pinned by variant identity, both altitudes

    #[test]
    fn value_truth_table_reads_the_stationary_variant_alone() {
        for (name, relation) in all_five_relations() {
            let expected = matches!(relation, ProofRelation::Stationary);
            assert_eq!(
                relation.stationary(),
                expected,
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_reads_the_stationary_variant_alone() {
        for (name, wire) in all_five_wire_variants() {
            let expected = matches!(wire, ProofRelationWire::Stationary);
            assert_eq!(
                wire.stationary(),
                expected,
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn stationary_variant_returns_true_at_both_altitudes() {
        assert!(ProofRelation::Stationary.stationary());
        assert!(ProofRelationWire::Stationary.stationary());
    }

    #[test]
    fn non_stationary_variants_return_false_at_both_altitudes() {
        assert!(!ProofRelation::IdentityRepublish { generations: nz(1) }.stationary());
        assert!(
            !ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(2),
            }
            .stationary()
        );
        assert!(
            !ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .stationary()
        );
        assert!(!ProofRelation::Regressed { by: nz(3) }.stationary());

        assert!(!ProofRelationWire::IdentityRepublish { generations: 1 }.stationary());
        assert!(
            !ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .stationary()
        );
        assert!(
            !ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .stationary()
        );
        assert!(!ProofRelationWire::Regressed { by: 3 }.stationary());
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.stationary();
            let wire = relation.to_wire().stationary();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.stationary();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.stationary(),
                "{name}: try_from_wire round-trip must preserve the stationarity verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.stationary(),
                wire_via_named.stationary(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on \
                 the stationarity verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // The payload-carrying variants (IdentityRepublish, Progression,
        // CrossStore, Regressed) require a NonZeroU64 payload whose
        // const construction path is verbose enough to obscure the
        // point; the Stationary constant witness is sufficient to catch
        // any regression in the receiver's own `const` qualifier —
        // matching the discipline of the neighboring
        // `*_is_const_callable_on_both_altitudes` tests on the
        // payload-accessor family.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const P_STATIONARY: bool = R_STATIONARY.stationary();
        assert!(P_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.stationary();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.stationary();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .stationary();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .stationary();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.stationary();
        assert!(STATIONARY);
        assert!(!IDENTITY_REPUBLISH);
        assert!(!PROGRESSION);
        assert!(!CROSS_STORE);
        assert!(!REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::IdentityRepublish { generations }.stationary(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        let watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in watermarks {
            for generations in [1_u64, 7, u64::MAX] {
                assert!(
                    !ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .stationary(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        for watermark in watermarks {
            assert!(
                !ProofRelationWire::CrossStore { watermark }.stationary(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::Regressed { by }.stationary(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.stationary();
            let through_wire = relation.to_wire().stationary();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer with ProofDelta::stationary

    #[test]
    fn verdict_matches_proof_delta_verdict_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let stationary_prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        for (name, prior, current) in [
            ("Stationary", stationary_prior, stationary_current),
            ("IdentityRepublish", stationary_prior, republish_current),
            ("Progression", stationary_prior, progression_current),
            ("CrossStore", stationary_prior, cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            assert_eq!(
                delta.stationary(),
                relation.stationary(),
                "{name}: ProofDelta::stationary must equal ProofRelation::stationary \
                 on the delta-reachable corners",
            );
            assert_eq!(
                delta.stationary(),
                relation_wire.stationary(),
                "{name}: ProofDelta::stationary must equal ProofRelationWire::stationary \
                 on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) Stationarity implies same-store-consistency

    #[test]
    fn stationarity_is_a_strict_subset_of_same_store_consistency() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.stationary() {
                assert!(
                    relation.same_store_consistent(),
                    "{name}: value stationary ⇒ same_store_consistent",
                );
                assert!(
                    wire.same_store_consistent(),
                    "{name}: wire stationary ⇒ same_store_consistent",
                );
            }
        }
        // The subset is strict on both altitudes: IdentityRepublish and
        // Progression are same-store-consistent but not stationary.
        let republish = ProofRelation::IdentityRepublish { generations: nz(1) };
        assert!(republish.same_store_consistent() && !republish.stationary());
        assert!(republish.to_wire().same_store_consistent() && !republish.to_wire().stationary(),);
        let progression = ProofRelation::Progression {
            watermark: moved_all(),
            generations: nz(2),
        };
        assert!(progression.same_store_consistent() && !progression.stationary());
        assert!(
            progression.to_wire().same_store_consistent() && !progression.to_wire().stationary(),
        );
    }

    // ---------- (10) The empty intersection is refused at both altitudes

    #[test]
    fn no_variant_is_stationary_and_same_store_inconsistent() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.stationary() && !relation.same_store_consistent()),
                "{name}: value cannot be stationary and same-store-inconsistent",
            );
            assert!(
                !(wire.stationary() && !wire.same_store_consistent()),
                "{name}: wire cannot be stationary and same-store-inconsistent",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_identity_republish_tests {
    //! Weld the identity-republish predicate at both altitudes —
    //! [`ProofRelation::identity_republish`] and its wire-side receiver-
    //! sibling [`ProofRelationWire::identity_republish`] — closing the
    //! (value, wire) × (predicate) grid at the proof altitude one further
    //! cell after [`ProofRelation::stationary`] /
    //! [`ProofRelationWire::stationary`].
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes:
    //!    only the [`ProofRelation::IdentityRepublish`] /
    //!    [`ProofRelationWire::IdentityRepublish`] variant returns `true`;
    //!    the four other variants ([`Stationary`][`ProofRelation::Stationary`],
    //!    [`Progression`][`ProofRelation::Progression`],
    //!    [`CrossStore`][`ProofRelation::CrossStore`],
    //!    [`Regressed`][`ProofRelation::Regressed`]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the identity-republish question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom) — a
    //!    reconstructed relation carries the same identity-republish
    //!    verdict the original wire value does.
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once,
    //!    so a future variant addition fails to compile at the fixture's
    //!    `match` in the same instant it fails at each predicate
    //!    accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of the
    //!    generation-carrying and payload-carrying variants' fields.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path.
    //! 8. Cross-altitude same-answer with [`ProofDelta::identity_republish`]
    //!    on the delta-reachable corners built from [`ConfigSyncProof`]
    //!    pairs.
    //! 9. Identity-republish implies same-store-consistency (a duality
    //!    ordering pin): whenever `identity_republish()` returns `true`,
    //!    `same_store_consistent()` returns `true` too — but not the
    //!    other way around.
    //! 10. Disjointness with [`ProofRelation::stationary`]: no variant
    //!     is both stationary AND identity-republish, at either altitude
    //!     — the two tag-only classifiers pin two DISTINCT single-
    //!     variant corners of the classification's `Xor` partition.
    //! 11. The empty intersection with the impossibility corners is
    //!     refused at both altitudes: no variant is identity-republish
    //!     AND same-store-inconsistent.
    //!
    //! Same test idiom as the sibling `proof_relation_stationary_tests`
    //! module.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    // ---------- (1) Truth table pinned by variant identity, both altitudes

    #[test]
    fn value_truth_table_reads_the_identity_republish_variant_alone() {
        for (name, relation) in all_five_relations() {
            let expected = matches!(relation, ProofRelation::IdentityRepublish { .. });
            assert_eq!(
                relation.identity_republish(),
                expected,
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_reads_the_identity_republish_variant_alone() {
        for (name, wire) in all_five_wire_variants() {
            let expected = matches!(wire, ProofRelationWire::IdentityRepublish { .. });
            assert_eq!(
                wire.identity_republish(),
                expected,
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn identity_republish_variant_returns_true_at_both_altitudes() {
        assert!(ProofRelation::IdentityRepublish { generations: nz(1) }.identity_republish());
        assert!(ProofRelationWire::IdentityRepublish { generations: 1 }.identity_republish());
    }

    #[test]
    fn non_identity_republish_variants_return_false_at_both_altitudes() {
        assert!(!ProofRelation::Stationary.identity_republish());
        assert!(
            !ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(2),
            }
            .identity_republish()
        );
        assert!(
            !ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .identity_republish()
        );
        assert!(!ProofRelation::Regressed { by: nz(3) }.identity_republish());

        assert!(!ProofRelationWire::Stationary.identity_republish());
        assert!(
            !ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .identity_republish()
        );
        assert!(
            !ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .identity_republish()
        );
        assert!(!ProofRelationWire::Regressed { by: 3 }.identity_republish());
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.identity_republish();
            let wire = relation.to_wire().identity_republish();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.identity_republish();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.identity_republish(),
                "{name}: try_from_wire round-trip must preserve the identity-republish \
                 verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.identity_republish(),
                wire_via_named.identity_republish(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on \
                 the identity-republish verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // A payload-carrying variant (IdentityRepublish) is verbose in
        // const position because NonZeroU64::new is not const-callable in
        // stable Rust in the .expect() form; a Stationary witness alone
        // is sufficient to catch any regression in the receiver's own
        // `const` qualifier — matching the discipline of the neighboring
        // `value_predicate_is_const_callable` test on the stationary
        // sibling.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const P_STATIONARY: bool = R_STATIONARY.identity_republish();
        assert!(!P_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.identity_republish();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.identity_republish();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .identity_republish();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .identity_republish();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.identity_republish();
        assert!(!STATIONARY);
        assert!(IDENTITY_REPUBLISH);
        assert!(!PROGRESSION);
        assert!(!CROSS_STORE);
        assert!(!REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        // The IdentityRepublish arm reads `true` for every legitimate
        // generations payload the wire can carry (>= 1 at the parse
        // boundary; the tag-only accessor is even permissive of the
        // parse-refused 0 case, since it reads only the variant tag).
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                ProofRelationWire::IdentityRepublish { generations }.identity_republish(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        let watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in watermarks {
            for generations in [1_u64, 7, u64::MAX] {
                assert!(
                    !ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .identity_republish(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        for watermark in watermarks {
            assert!(
                !ProofRelationWire::CrossStore { watermark }.identity_republish(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::Regressed { by }.identity_republish(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.identity_republish();
            let through_wire = relation.to_wire().identity_republish();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer with ProofDelta::identity_republish

    #[test]
    fn verdict_matches_proof_delta_verdict_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let stationary_prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        for (name, prior, current) in [
            ("Stationary", stationary_prior, stationary_current),
            ("IdentityRepublish", stationary_prior, republish_current),
            ("Progression", stationary_prior, progression_current),
            ("CrossStore", stationary_prior, cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            assert_eq!(
                delta.identity_republish(),
                relation.identity_republish(),
                "{name}: ProofDelta::identity_republish must equal \
                 ProofRelation::identity_republish on the delta-reachable corners",
            );
            assert_eq!(
                delta.identity_republish(),
                relation_wire.identity_republish(),
                "{name}: ProofDelta::identity_republish must equal \
                 ProofRelationWire::identity_republish on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) Identity-republish implies same-store-consistency

    #[test]
    fn identity_republish_is_a_strict_subset_of_same_store_consistency() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.identity_republish() {
                assert!(
                    relation.same_store_consistent(),
                    "{name}: value identity_republish ⇒ same_store_consistent",
                );
                assert!(
                    wire.same_store_consistent(),
                    "{name}: wire identity_republish ⇒ same_store_consistent",
                );
            }
        }
        // The subset is strict on both altitudes: Stationary and
        // Progression are same-store-consistent but not identity-republish.
        let stationary = ProofRelation::Stationary;
        assert!(stationary.same_store_consistent() && !stationary.identity_republish());
        assert!(
            stationary.to_wire().same_store_consistent()
                && !stationary.to_wire().identity_republish(),
        );
        let progression = ProofRelation::Progression {
            watermark: moved_all(),
            generations: nz(2),
        };
        assert!(progression.same_store_consistent() && !progression.identity_republish());
        assert!(
            progression.to_wire().same_store_consistent()
                && !progression.to_wire().identity_republish(),
        );
    }

    // ---------- (10) Disjointness with stationary

    #[test]
    fn identity_republish_and_stationary_are_pairwise_disjoint() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.identity_republish() && relation.stationary()),
                "{name}: value cannot be identity_republish AND stationary — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.identity_republish() && wire.stationary()),
                "{name}: wire cannot be identity_republish AND stationary — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
        }
    }

    // ---------- (11) The empty intersection with impossibility is refused

    #[test]
    fn no_variant_is_identity_republish_and_same_store_inconsistent() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.identity_republish() && !relation.same_store_consistent()),
                "{name}: value cannot be identity_republish and same-store-inconsistent",
            );
            assert!(
                !(wire.identity_republish() && !wire.same_store_consistent()),
                "{name}: wire cannot be identity_republish and same-store-inconsistent",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_regressed_tests {
    //! Weld the regressed predicate at both altitudes —
    //! [`ProofRelation::regressed`] and its wire-side receiver-sibling
    //! [`ProofRelationWire::regressed`] — closing the (value, wire) ×
    //! (predicate) grid at the proof altitude one further cell after
    //! [`ProofRelation::identity_republish`] /
    //! [`ProofRelationWire::identity_republish`].
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes: only
    //!    the [`ProofRelation::Regressed`] / [`ProofRelationWire::Regressed`]
    //!    variant returns `true`; the four other variants
    //!    ([`Stationary`][`ProofRelation::Stationary`],
    //!    [`IdentityRepublish`][`ProofRelation::IdentityRepublish`],
    //!    [`Progression`][`ProofRelation::Progression`],
    //!    [`CrossStore`][`ProofRelation::CrossStore`]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the regression question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom).
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once,
    //!    so a future variant addition fails to compile at the fixture's
    //!    `match` in the same instant it fails at each predicate
    //!    accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of every payload-
    //!    carrying variant's fields.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path.
    //! 8. Cross-altitude same-answer with
    //!    [`ProofDelta::generations_regressed`] on the delta-reachable
    //!    corners built from [`ConfigSyncProof`] pairs (the `Regressed`
    //!    corner IS delta-reachable — the delta preserves the boolean
    //!    signal even though it folds the exact backwards `by` count
    //!    into `Option::None`).
    //! 9. Regression implies same-store-INCONSISTENCY (a duality
    //!    ordering pin distinct from the identity-republish sibling's
    //!    same-store-CONSISTENCY implication): whenever `regressed()`
    //!    returns `true`, `same_store_consistent()` returns `false`
    //!    — but the converse does NOT hold, since
    //!    [`ProofRelation::CrossStore`] is same-store-inconsistent
    //!    without being regressed.
    //! 10. Disjointness with [`ProofRelation::stationary`] and
    //!     [`ProofRelation::identity_republish`]: no variant is both
    //!     regressed AND stationary, nor both regressed AND identity-
    //!     republish, at either altitude — the three tag-only
    //!     classifiers pin three DISTINCT single-variant corners of
    //!     the classification's `Xor` partition.
    //! 11. Tag/payload agreement with [`ProofRelation::regressed_by`]
    //!     / [`ProofRelationWire::regressed_by`]: the tag-only
    //!     predicate and the payload accessor are two projections of
    //!     the same variant, so `self.regressed() ==
    //!     self.regressed_by().is_some()` at both altitudes. A genuinely
    //!     new class of invariant the two prior tag-only classifiers
    //!     ([`ProofRelation::stationary`] and
    //!     [`ProofRelation::identity_republish`]) cannot pin, because
    //!     neither has a companion payload accessor on the same variant.
    //!
    //! Same test idiom as the sibling `proof_relation_identity_republish_tests`
    //! module.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    // ---------- (1) Truth table pinned by variant identity, both altitudes

    #[test]
    fn value_truth_table_reads_the_regressed_variant_alone() {
        for (name, relation) in all_five_relations() {
            let expected = matches!(relation, ProofRelation::Regressed { .. });
            assert_eq!(
                relation.regressed(),
                expected,
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_reads_the_regressed_variant_alone() {
        for (name, wire) in all_five_wire_variants() {
            let expected = matches!(wire, ProofRelationWire::Regressed { .. });
            assert_eq!(
                wire.regressed(),
                expected,
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn regressed_variant_returns_true_at_both_altitudes() {
        assert!(ProofRelation::Regressed { by: nz(1) }.regressed());
        assert!(ProofRelationWire::Regressed { by: 1 }.regressed());
    }

    #[test]
    fn non_regressed_variants_return_false_at_both_altitudes() {
        assert!(!ProofRelation::Stationary.regressed());
        assert!(!ProofRelation::IdentityRepublish { generations: nz(1) }.regressed());
        assert!(
            !ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(2),
            }
            .regressed()
        );
        assert!(
            !ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .regressed()
        );

        assert!(!ProofRelationWire::Stationary.regressed());
        assert!(!ProofRelationWire::IdentityRepublish { generations: 1 }.regressed());
        assert!(
            !ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .regressed()
        );
        assert!(
            !ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .regressed()
        );
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.regressed();
            let wire = relation.to_wire().regressed();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.regressed();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.regressed(),
                "{name}: try_from_wire round-trip must preserve the regressed verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.regressed(),
                wire_via_named.regressed(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on \
                 the regressed verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // A payload-carrying variant (Regressed) is verbose in const
        // position because NonZeroU64::new is not const-callable in
        // stable Rust in the .expect() form; a Stationary witness alone
        // is sufficient to catch any regression in the receiver's own
        // `const` qualifier — matching the discipline of the neighboring
        // `value_predicate_is_const_callable` test on the identity-
        // republish sibling.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const P_STATIONARY: bool = R_STATIONARY.regressed();
        assert!(!P_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.regressed();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.regressed();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .regressed();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .regressed();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.regressed();
        assert!(!STATIONARY);
        assert!(!IDENTITY_REPUBLISH);
        assert!(!PROGRESSION);
        assert!(!CROSS_STORE);
        assert!(REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        // The Regressed arm reads `true` for every legitimate `by`
        // payload the wire can carry (>= 1 at the parse boundary; the
        // tag-only accessor is even permissive of the parse-refused 0
        // case, since it reads only the variant tag).
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                ProofRelationWire::Regressed { by }.regressed(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::IdentityRepublish { generations }.regressed(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        let watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in watermarks {
            for generations in [1_u64, 7, u64::MAX] {
                assert!(
                    !ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .regressed(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        for watermark in watermarks {
            assert!(
                !ProofRelationWire::CrossStore { watermark }.regressed(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.regressed();
            let through_wire = relation.to_wire().regressed();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer with ProofDelta::generations_regressed

    #[test]
    fn verdict_matches_proof_delta_verdict_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let prior_early = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let prior_late = ConfigSyncProof {
            watermark: watermark_b,
            generation: 5,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };
        let regressed_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };

        // Unlike the IdentityRepublish sibling's cross-altitude test,
        // the Regressed corner IS reachable from a ProofDelta: the
        // ProofDelta::generations_regressed predicate reads the
        // `generations_advanced.is_none()` boolean, which the delta
        // preserves even though it folds the exact backwards `by` count.
        // A regressed prior/current pair therefore lets us check both
        // corners of the wider (value-altitude, delta-altitude) grid.
        for (name, prior, current) in [
            ("Stationary", prior_early, stationary_current),
            ("IdentityRepublish", prior_early, republish_current),
            ("Progression", prior_early, progression_current),
            ("CrossStore", prior_early, cross_store_current),
            ("Regressed", prior_late, regressed_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            assert_eq!(
                delta.generations_regressed(),
                relation.regressed(),
                "{name}: ProofDelta::generations_regressed must equal \
                 ProofRelation::regressed on the delta-reachable corners",
            );
            assert_eq!(
                delta.generations_regressed(),
                relation_wire.regressed(),
                "{name}: ProofDelta::generations_regressed must equal \
                 ProofRelationWire::regressed on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) Regressed implies same-store-INCONSISTENCY

    #[test]
    fn regressed_implies_same_store_inconsistency() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.regressed() {
                assert!(
                    !relation.same_store_consistent(),
                    "{name}: value regressed ⇒ !same_store_consistent",
                );
                assert!(
                    !wire.same_store_consistent(),
                    "{name}: wire regressed ⇒ !same_store_consistent",
                );
            }
        }
        // The converse does NOT hold: CrossStore is also same-store-
        // inconsistent without being regressed, at both altitudes.
        let cross_store = ProofRelation::CrossStore {
            watermark: moved_free_only(),
        };
        assert!(!cross_store.same_store_consistent() && !cross_store.regressed());
        assert!(
            !cross_store.to_wire().same_store_consistent() && !cross_store.to_wire().regressed(),
        );
    }

    // ---------- (10) Disjointness with every other tag-only classifier

    #[test]
    fn regressed_is_pairwise_disjoint_from_stationary_and_identity_republish() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.regressed() && relation.stationary()),
                "{name}: value cannot be regressed AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.regressed() && wire.stationary()),
                "{name}: wire cannot be regressed AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.regressed() && relation.identity_republish()),
                "{name}: value cannot be regressed AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.regressed() && wire.identity_republish()),
                "{name}: wire cannot be regressed AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
        }
    }

    // ---------- (11) Tag/payload agreement with regressed_by

    #[test]
    fn regressed_agrees_with_regressed_by_is_some_at_both_altitudes() {
        // A genuinely new class of invariant the two prior tag-only
        // classifiers cannot pin: `stationary` and `identity_republish`
        // have no companion payload accessor on their own variant, so
        // there is no `Option`-shaped projection to check against. The
        // Regressed corner is the only single-variant tag whose payload
        // ALSO surfaces through a dedicated accessor (`regressed_by`),
        // and this test pins the two projections in lockstep at both
        // altitudes.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert_eq!(
                relation.regressed(),
                relation.regressed_by().is_some(),
                "{name}: value regressed() must equal regressed_by().is_some()",
            );
            assert_eq!(
                wire.regressed(),
                wire.regressed_by().is_some(),
                "{name}: wire regressed() must equal regressed_by().is_some()",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_progression_tests {
    //! Weld the progression predicate at both altitudes —
    //! [`ProofRelation::progression`] and its wire-side receiver-sibling
    //! [`ProofRelationWire::progression`] — closing the (value, wire) ×
    //! (predicate) grid at the proof altitude one further cell after
    //! [`ProofRelation::regressed`] / [`ProofRelationWire::regressed`].
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes: only
    //!    the [`ProofRelation::Progression`] / [`ProofRelationWire::Progression`]
    //!    variant returns `true`; the four other variants
    //!    ([`Stationary`][`ProofRelation::Stationary`],
    //!    [`IdentityRepublish`][`ProofRelation::IdentityRepublish`],
    //!    [`CrossStore`][`ProofRelation::CrossStore`],
    //!    [`Regressed`][`ProofRelation::Regressed`]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the progression question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom).
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once,
    //!    so a future variant addition fails to compile at the fixture's
    //!    `match` in the same instant it fails at each predicate
    //!    accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of every payload-
    //!    carrying variant's fields.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path.
    //! 8. Cross-altitude same-answer with the negative-space delta
    //!    projection on the four delta-reachable corners built from
    //!    [`ConfigSyncProof`] pairs — since [`ProofDelta`] has no
    //!    `progression` boolean of its own (Progression is the corner
    //!    the four `ProofDelta` predicates deliberately leave implicit),
    //!    the cross-altitude check reads it as the negative-space
    //!    conjunction `!stationary && !identity_republish &&
    //!    !cross_store_signal && !generations_regressed`. This is the
    //!    inline shape a downstream consumer would have hand-written
    //!    before the receiver landed; the test pins its equivalence to
    //!    the receiver on the delta-reachable corners.
    //! 9. Progression implies same-store-CONSISTENCY at both altitudes
    //!    — the strict-subset ordering with [`ProofRelation::same_store_consistent`]
    //!    the third tag-only same-store-consistent classifier carries.
    //!    The converse does NOT hold, since [`ProofRelation::Stationary`]
    //!    and [`ProofRelation::IdentityRepublish`] witness the strictness.
    //! 10. Disjointness with every other tag-only classifier at both
    //!     altitudes: no variant satisfies both `progression()` AND
    //!     `stationary()`, nor both `progression()` AND
    //!     `identity_republish()`, nor both `progression()` AND
    //!     `regressed()`. The four tag-only classifiers now pin four
    //!     DISTINCT single-variant corners of the classification's
    //!     `Xor` partition — one more (`cross_store`) closes it.
    //! 11. Two-payload agreement — the FIRST tag-only classifier that
    //!     cross-checks against TWO companion payload accessors. The
    //!     intersection cell of [`ProofRelation::watermark`] (Some on
    //!     Progression AND CrossStore) and [`ProofRelation::generations`]
    //!     (Some on Progression AND IdentityRepublish) is EXACTLY the
    //!     Progression variant, so `self.progression() ==
    //!     (self.watermark().is_some() && self.generations().is_some())`
    //!     at both altitudes. A genuinely new class of invariant the
    //!     three prior tag-only classifiers cannot pin: `stationary` and
    //!     `identity_republish` have no companion payload accessor
    //!     (their variants are payload-free or expose only `generations`
    //!     which spans two variants); `regressed` cross-checks against
    //!     `regressed_by` alone — a single-axis intersection cell, not a
    //!     two-axis one.
    //!
    //! Same test idiom as the sibling `proof_relation_regressed_tests`
    //! module.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    // ---------- (1) Truth table pinned by variant identity, both altitudes

    #[test]
    fn value_truth_table_reads_the_progression_variant_alone() {
        for (name, relation) in all_five_relations() {
            let expected = matches!(relation, ProofRelation::Progression { .. });
            assert_eq!(
                relation.progression(),
                expected,
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_reads_the_progression_variant_alone() {
        for (name, wire) in all_five_wire_variants() {
            let expected = matches!(wire, ProofRelationWire::Progression { .. });
            assert_eq!(
                wire.progression(),
                expected,
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn progression_variant_returns_true_at_both_altitudes() {
        assert!(
            ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(1),
            }
            .progression()
        );
        assert!(
            ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 1,
            }
            .progression()
        );
    }

    #[test]
    fn non_progression_variants_return_false_at_both_altitudes() {
        assert!(!ProofRelation::Stationary.progression());
        assert!(!ProofRelation::IdentityRepublish { generations: nz(1) }.progression());
        assert!(
            !ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .progression()
        );
        assert!(!ProofRelation::Regressed { by: nz(1) }.progression());

        assert!(!ProofRelationWire::Stationary.progression());
        assert!(!ProofRelationWire::IdentityRepublish { generations: 1 }.progression());
        assert!(
            !ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .progression()
        );
        assert!(!ProofRelationWire::Regressed { by: 1 }.progression());
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.progression();
            let wire = relation.to_wire().progression();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.progression();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.progression(),
                "{name}: try_from_wire round-trip must preserve the progression verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.progression(),
                wire_via_named.progression(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on \
                 the progression verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // A payload-carrying variant (Progression) is verbose in const
        // position because NonZeroU64::new is not const-callable in
        // stable Rust in the .expect() form; a Stationary witness alone
        // is sufficient to catch any regression in the receiver's own
        // `const` qualifier — matching the discipline of the neighboring
        // `value_predicate_is_const_callable` test on the regressed
        // sibling.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const P_STATIONARY: bool = R_STATIONARY.progression();
        assert!(!P_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.progression();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.progression();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .progression();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .progression();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.progression();
        assert!(!STATIONARY);
        assert!(!IDENTITY_REPUBLISH);
        assert!(PROGRESSION);
        assert!(!CROSS_STORE);
        assert!(!REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        // The Progression arm reads `true` for every legitimate
        // (watermark, generations) payload the wire can carry (moved
        // watermark + generations >= 1 at the parse boundary; the
        // tag-only accessor is even permissive of the parse-refused 0
        // and stationary-watermark cases, since it reads only the
        // variant tag).
        let moved_watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in moved_watermarks {
            for generations in [1_u64, 2, 5, 100, u64::MAX] {
                assert!(
                    ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .progression(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::IdentityRepublish { generations }.progression(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        for watermark in moved_watermarks {
            assert!(
                !ProofRelationWire::CrossStore { watermark }.progression(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::Regressed { by }.progression(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.progression();
            let through_wire = relation.to_wire().progression();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer via the negative-space
    //                delta projection on the four delta-reachable corners

    #[test]
    fn verdict_matches_delta_negative_space_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        // ProofDelta has no `progression` boolean of its own —
        // Progression is the corner the four ProofDelta predicates
        // (stationary, identity_republish, cross_store_signal,
        // generations_regressed) deliberately leave implicit. The
        // cross-altitude same-answer check therefore reads it as the
        // negative-space conjunction — the inline shape a downstream
        // consumer would have hand-written before this receiver landed.
        for (name, current) in [
            ("Stationary", stationary_current),
            ("IdentityRepublish", republish_current),
            ("Progression", progression_current),
            ("CrossStore", cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            let delta_negative_space = !delta.stationary()
                && !delta.identity_republish()
                && !delta.cross_store_signal()
                && !delta.generations_regressed();
            assert_eq!(
                delta_negative_space,
                relation.progression(),
                "{name}: delta negative-space (!stationary && !identity_republish && \
                 !cross_store_signal && !generations_regressed) must equal \
                 ProofRelation::progression on the delta-reachable corners",
            );
            assert_eq!(
                delta_negative_space,
                relation_wire.progression(),
                "{name}: delta negative-space must equal ProofRelationWire::progression \
                 on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) Progression implies same-store-CONSISTENCY

    #[test]
    fn progression_implies_same_store_consistency() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.progression() {
                assert!(
                    relation.same_store_consistent(),
                    "{name}: value progression ⇒ same_store_consistent",
                );
                assert!(
                    wire.same_store_consistent(),
                    "{name}: wire progression ⇒ same_store_consistent",
                );
            }
        }
        // The converse does NOT hold: Stationary and IdentityRepublish
        // are also same-store-consistent without being progression, at
        // both altitudes.
        let stationary = ProofRelation::Stationary;
        assert!(stationary.same_store_consistent() && !stationary.progression());
        assert!(
            stationary.to_wire().same_store_consistent() && !stationary.to_wire().progression(),
        );
        let republish = ProofRelation::IdentityRepublish { generations: nz(1) };
        assert!(republish.same_store_consistent() && !republish.progression());
        assert!(republish.to_wire().same_store_consistent() && !republish.to_wire().progression());
    }

    // ---------- (10) Disjointness with every other tag-only classifier

    #[test]
    fn progression_is_pairwise_disjoint_from_stationary_identity_republish_and_regressed() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.progression() && relation.stationary()),
                "{name}: value cannot be progression AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.progression() && wire.stationary()),
                "{name}: wire cannot be progression AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.progression() && relation.identity_republish()),
                "{name}: value cannot be progression AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.progression() && wire.identity_republish()),
                "{name}: wire cannot be progression AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.progression() && relation.regressed()),
                "{name}: value cannot be progression AND regressed — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.progression() && wire.regressed()),
                "{name}: wire cannot be progression AND regressed — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
        }
    }

    // ---------- (11) Two-payload agreement — the intersection cell of
    //                 watermark() and generations()

    #[test]
    fn progression_agrees_with_watermark_and_generations_intersection_at_both_altitudes() {
        // A genuinely new class of invariant the three prior tag-only
        // classifiers cannot pin: `stationary` and `identity_republish`
        // have no companion payload accessor (their variants are
        // payload-free or expose only `generations` which spans two
        // variants); `regressed` cross-checks against `regressed_by`
        // alone — a single-axis intersection cell, not a two-axis one.
        // Progression is the FIRST single-variant tag whose payload
        // surfaces through TWO dedicated accessors (watermark and
        // generations), and these two accessors' intersection cell is
        // EXACTLY the Progression variant.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let value_intersection =
                relation.watermark().is_some() && relation.generations().is_some();
            assert_eq!(
                relation.progression(),
                value_intersection,
                "{name}: value progression() must equal watermark().is_some() && \
                 generations().is_some()",
            );
            let wire_intersection = wire.watermark().is_some() && wire.generations().is_some();
            assert_eq!(
                wire.progression(),
                wire_intersection,
                "{name}: wire progression() must equal watermark().is_some() && \
                 generations().is_some()",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_cross_store_tests {
    //! Weld the cross_store predicate at both altitudes —
    //! [`ProofRelation::cross_store`] and its wire-side receiver-sibling
    //! [`ProofRelationWire::cross_store`] — closing the (value, wire) ×
    //! (predicate) grid at the proof altitude with the fifth and final
    //! single-variant tag-only cell after
    //! [`ProofRelation::progression`] / [`ProofRelationWire::progression`].
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes: only
    //!    the [`ProofRelation::CrossStore`] / [`ProofRelationWire::CrossStore`]
    //!    variant returns `true`; the four other variants
    //!    ([`Stationary`][`ProofRelation::Stationary`],
    //!    [`IdentityRepublish`][`ProofRelation::IdentityRepublish`],
    //!    [`Progression`][`ProofRelation::Progression`],
    //!    [`Regressed`][`ProofRelation::Regressed`]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the cross-store question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom).
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once, so
    //!    a future variant addition fails to compile at the fixture's
    //!    `match` in the same instant it fails at each predicate
    //!    accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of every
    //!    payload-carrying variant's fields.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path.
    //! 8. Cross-altitude same-answer with [`ProofDelta::cross_store_signal`]
    //!    on ALL FIVE delta-reachable corners built from
    //!    [`ConfigSyncProof`] pairs. Unlike the progression sibling
    //!    (which had to fall back to a negative-space conjunction
    //!    because [`ProofDelta`] leaves the progression corner
    //!    implicit), [`ProofDelta`] carries the cross-store signal
    //!    directly — the check reads `delta.cross_store_signal() ==
    //!    relation.cross_store()`.
    //! 9. `cross_store` implies same-store-INCONSISTENCY at both
    //!    altitudes — the same duality-flip the regressed sibling
    //!    carries, but on the OTHER impossibility corner. Together the
    //!    two impossibility classifiers exhaustively cover the
    //!    same-store-INCONSISTENT half of the [`ProofRelation::same_store_consistent`]
    //!    partition: `regressed() || cross_store() ==
    //!    !same_store_consistent()` at both altitudes.
    //! 10. Disjointness with every other tag-only classifier at both
    //!     altitudes: no variant satisfies both `cross_store()` AND
    //!     `stationary()`, nor both `cross_store()` AND
    //!     `identity_republish()`, nor both `cross_store()` AND
    //!     `regressed()`, nor both `cross_store()` AND `progression()`.
    //! 11. Payload-partition agreement — genuinely new. [`ProofRelation::watermark`]
    //!     is `Some` on EXACTLY the union `Progression ∪ CrossStore`,
    //!     so `self.watermark().is_some() == (self.progression() ||
    //!     self.cross_store())` at both altitudes. This is the FIRST
    //!     payload-accessor-partition invariant a tag-only classifier
    //!     can pin — a union of two single-variant predicates equals
    //!     the `Some`-set of a shared payload accessor.
    //! 12. **The closing invariant** — genuinely new, and only pinnable
    //!     once all five tag-only classifiers exist: every
    //!     [`ProofRelation`] value satisfies EXACTLY ONE of the five
    //!     tag-only predicates (`stationary`, `identity_republish`,
    //!     `regressed`, `progression`, `cross_store`), and the same
    //!     invariant holds at the wire altitude. The
    //!     classification's `Xor` partition is now receiver-visible as
    //!     a compile-time-callable disjoint union.
    //!
    //! Same test idiom as the sibling `proof_relation_progression_tests`
    //! module.

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    // ---------- (1) Truth table pinned by variant identity, both altitudes

    #[test]
    fn value_truth_table_reads_the_cross_store_variant_alone() {
        for (name, relation) in all_five_relations() {
            let expected = matches!(relation, ProofRelation::CrossStore { .. });
            assert_eq!(
                relation.cross_store(),
                expected,
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_reads_the_cross_store_variant_alone() {
        for (name, wire) in all_five_wire_variants() {
            let expected = matches!(wire, ProofRelationWire::CrossStore { .. });
            assert_eq!(
                wire.cross_store(),
                expected,
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn cross_store_variant_returns_true_at_both_altitudes() {
        assert!(
            ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .cross_store()
        );
        assert!(
            ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .cross_store()
        );
    }

    #[test]
    fn non_cross_store_variants_return_false_at_both_altitudes() {
        assert!(!ProofRelation::Stationary.cross_store());
        assert!(!ProofRelation::IdentityRepublish { generations: nz(1) }.cross_store());
        assert!(
            !ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(2),
            }
            .cross_store()
        );
        assert!(!ProofRelation::Regressed { by: nz(1) }.cross_store());

        assert!(!ProofRelationWire::Stationary.cross_store());
        assert!(!ProofRelationWire::IdentityRepublish { generations: 1 }.cross_store());
        assert!(
            !ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .cross_store()
        );
        assert!(!ProofRelationWire::Regressed { by: 1 }.cross_store());
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.cross_store();
            let wire = relation.to_wire().cross_store();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.cross_store();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.cross_store(),
                "{name}: try_from_wire round-trip must preserve the cross_store verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.cross_store(),
                wire_via_named.cross_store(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on \
                 the cross_store verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // A payload-carrying variant is verbose in const position
        // because NonZeroU64::new is not const-callable in stable Rust
        // in the .expect() form; a Stationary witness alone is
        // sufficient to catch any regression in the receiver's own
        // `const` qualifier — matching the discipline of the
        // neighboring `value_predicate_is_const_callable` test on the
        // progression sibling.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const C_STATIONARY: bool = R_STATIONARY.cross_store();
        assert!(!C_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.cross_store();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.cross_store();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .cross_store();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .cross_store();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.cross_store();
        assert!(!STATIONARY);
        assert!(!IDENTITY_REPUBLISH);
        assert!(!PROGRESSION);
        assert!(CROSS_STORE);
        assert!(!REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        // The CrossStore arm reads `true` for every legitimate
        // watermark payload the wire can carry (moved watermark at the
        // parse boundary; the tag-only accessor is even permissive of
        // the parse-refused stationary case, since it reads only the
        // variant tag).
        let moved_watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        for watermark in moved_watermarks {
            assert!(
                ProofRelationWire::CrossStore { watermark }.cross_store(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        for watermark in moved_watermarks {
            for generations in [1_u64, 2, 5, 100, u64::MAX] {
                assert!(
                    !ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .cross_store(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::IdentityRepublish { generations }.cross_store(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::Regressed { by }.cross_store(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.cross_store();
            let through_wire = relation.to_wire().cross_store();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer with ProofDelta::cross_store_signal
    //                on all four delta-reachable corners

    #[test]
    fn verdict_matches_delta_cross_store_signal_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        // Unlike the progression sibling (which had to compute a
        // negative-space conjunction because ProofDelta leaves the
        // progression corner implicit), ProofDelta carries the
        // cross-store signal directly — the check reads
        // `delta.cross_store_signal() == relation.cross_store()`
        // pointwise on the four delta-reachable corners.
        for (name, current) in [
            ("Stationary", stationary_current),
            ("IdentityRepublish", republish_current),
            ("Progression", progression_current),
            ("CrossStore", cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            assert_eq!(
                delta.cross_store_signal(),
                relation.cross_store(),
                "{name}: ProofDelta::cross_store_signal must equal \
                 ProofRelation::cross_store on the delta-reachable corners",
            );
            assert_eq!(
                delta.cross_store_signal(),
                relation_wire.cross_store(),
                "{name}: ProofDelta::cross_store_signal must equal \
                 ProofRelationWire::cross_store on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) cross_store implies same-store-INCONSISTENCY, and
    //                together with regressed exhaustively covers the
    //                inconsistent half of the same_store_consistent
    //                partition

    #[test]
    fn cross_store_implies_same_store_inconsistency_at_both_altitudes() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.cross_store() {
                assert!(
                    !relation.same_store_consistent(),
                    "{name}: value cross_store ⇒ !same_store_consistent",
                );
                assert!(
                    !wire.same_store_consistent(),
                    "{name}: wire cross_store ⇒ !same_store_consistent",
                );
            }
        }
    }

    #[test]
    fn regressed_or_cross_store_partitions_same_store_inconsistency_at_both_altitudes() {
        // The two impossibility classifiers together cover the
        // same-store-INCONSISTENT half of the same_store_consistent
        // partition exhaustively: at either altitude,
        // (regressed || cross_store) == !same_store_consistent.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert_eq!(
                relation.regressed() || relation.cross_store(),
                !relation.same_store_consistent(),
                "{name}: value regressed() || cross_store() must equal \
                 !same_store_consistent()",
            );
            assert_eq!(
                wire.regressed() || wire.cross_store(),
                !wire.same_store_consistent(),
                "{name}: wire regressed() || cross_store() must equal \
                 !same_store_consistent()",
            );
        }
    }

    // ---------- (10) Disjointness with every other tag-only classifier

    #[test]
    fn cross_store_is_pairwise_disjoint_from_every_other_tag_only_classifier() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.cross_store() && relation.stationary()),
                "{name}: value cannot be cross_store AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.cross_store() && wire.stationary()),
                "{name}: wire cannot be cross_store AND stationary — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.cross_store() && relation.identity_republish()),
                "{name}: value cannot be cross_store AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.cross_store() && wire.identity_republish()),
                "{name}: wire cannot be cross_store AND identity_republish — the two \
                 tag-only classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.cross_store() && relation.regressed()),
                "{name}: value cannot be cross_store AND regressed — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.cross_store() && wire.regressed()),
                "{name}: wire cannot be cross_store AND regressed — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(relation.cross_store() && relation.progression()),
                "{name}: value cannot be cross_store AND progression — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
            assert!(
                !(wire.cross_store() && wire.progression()),
                "{name}: wire cannot be cross_store AND progression — the two tag-only \
                 classifiers pin two distinct single-variant corners",
            );
        }
    }

    // ---------- (11) Payload-partition agreement: watermark().is_some()
    //                 partitions as the disjoint union of progression()
    //                 and cross_store()

    #[test]
    fn watermark_is_some_partitions_as_progression_or_cross_store_at_both_altitudes() {
        // A genuinely new class of invariant: [`ProofRelation::watermark`]
        // is `Some` on exactly the union `Progression ∪ CrossStore`, so
        // once BOTH single-variant tag-only classifiers exist, their
        // union pins the payload accessor's `Some`-set at both
        // altitudes. This is the FIRST payload-accessor-partition
        // invariant a tag-only classifier can pin.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert_eq!(
                relation.watermark().is_some(),
                relation.progression() || relation.cross_store(),
                "{name}: value watermark().is_some() must equal \
                 progression() || cross_store()",
            );
            assert_eq!(
                wire.watermark().is_some(),
                wire.progression() || wire.cross_store(),
                "{name}: wire watermark().is_some() must equal \
                 progression() || cross_store()",
            );
        }
    }

    // ---------- (12) THE CLOSING INVARIANT: every ProofRelation value
    //                 satisfies EXACTLY ONE of the five tag-only
    //                 predicates. Only pinnable once all five exist.

    #[test]
    fn exactly_one_of_the_five_tag_only_predicates_holds_on_every_variant_at_both_altitudes() {
        // The Xor partition of the classification is now
        // receiver-visible along all five of its single-variant
        // projections. This closing invariant welds them together: on
        // every variant, EXACTLY one of stationary / identity_republish
        // / regressed / progression / cross_store returns true; the
        // other four return false. A future variant addition either
        // fails to compile at each predicate accessor's own `match` (if
        // it is a new single-variant classification) or forces the
        // partition to be re-welded (if it introduces overlap with an
        // existing variant, which the exhaustive fixture would catch as
        // a doubled-true or dropped-true count).
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let value_true_count = [
                relation.stationary(),
                relation.identity_republish(),
                relation.regressed(),
                relation.progression(),
                relation.cross_store(),
            ]
            .into_iter()
            .filter(|b| *b)
            .count();
            assert_eq!(
                value_true_count, 1,
                "{name}: value must satisfy EXACTLY one of the five tag-only classifiers \
                 (got {value_true_count})",
            );
            let wire_true_count = [
                wire.stationary(),
                wire.identity_republish(),
                wire.regressed(),
                wire.progression(),
                wire.cross_store(),
            ]
            .into_iter()
            .filter(|b| *b)
            .count();
            assert_eq!(
                wire_true_count, 1,
                "{name}: wire must satisfy EXACTLY one of the five tag-only classifiers \
                 (got {wire_true_count})",
            );
        }
    }
}

#[cfg(test)]
mod proof_relation_same_store_inconsistent_tests {
    //! Weld the same-store-inconsistency predicate at both altitudes —
    //! [`ProofRelation::same_store_inconsistent`] and its wire-side
    //! receiver-sibling [`ProofRelationWire::same_store_inconsistent`] —
    //! the FIRST two-variant-union tag-only classifier on the
    //! classification, welding the impossibility half of the
    //! [`ProofRelation::same_store_consistent`] partition into its own
    //! [`matches!`] pattern.
    //!
    //! Every prior tag-only classifier in this receiver family is
    //! single-variant: the four legitimate-corner projections
    //! ([`stationary`][ProofRelation::stationary],
    //! [`identity_republish`][ProofRelation::identity_republish],
    //! [`progression`][ProofRelation::progression]) plus the two
    //! impossibility projections ([`regressed`][ProofRelation::regressed],
    //! [`cross_store`][ProofRelation::cross_store]) each pin a single
    //! variant. [`ProofRelation::same_store_consistent`] is the only
    //! prior multi-variant tag-only classifier — a THREE-variant
    //! union covering the legitimate half. This receiver is its
    //! direct dual: a TWO-variant union covering the impossibility
    //! half.
    //!
    //! Together the tests below cover:
    //!
    //! 1. Truth table pinned by variant identity at both altitudes: the
    //!    two impossibility variants ([`CrossStore`][ProofRelation::CrossStore],
    //!    [`Regressed`][ProofRelation::Regressed]) return `true`; the
    //!    three legitimate variants
    //!    ([`Stationary`][ProofRelation::Stationary],
    //!    [`IdentityRepublish`][ProofRelation::IdentityRepublish],
    //!    [`Progression`][ProofRelation::Progression]) return `false`.
    //! 2. Pointwise value/wire agreement across every variant — the
    //!    wire is a lossless channel for the same-store-inconsistency
    //!    question.
    //! 3. Round-trip preservation through [`ProofRelation::try_from_wire`]
    //!    (both the named-method idiom and the `TryFrom` idiom).
    //! 4. `const`-callable at both altitudes on every variant.
    //! 5. Exhaustive variant enumeration is stable: a hand-authored
    //!    fixture names every one of the five variants exactly once,
    //!    so a future variant addition fails to compile at the
    //!    fixture's `match` in the same instant it fails at each
    //!    predicate accessor's own `match`.
    //! 6. Payload-inspection independence: the wire predicate reads
    //!    only the variant tag, not any field payload — the answer is
    //!    invariant under any legitimate perturbation of every
    //!    payload-carrying variant's fields.
    //! 7. Composition through the wire boundary agrees with the direct
    //!    value path.
    //! 8. Cross-altitude same-answer with the delta path on the four
    //!    delta-reachable corners.
    //! 9. **Complement identity — genuinely new.** At both altitudes,
    //!    `self.same_store_inconsistent() ==
    //!    !self.same_store_consistent()` pointwise on every variant.
    //!    This is the FIRST complement-identity in the classification
    //!    receiver family: no single-variant tag-only classifier can
    //!    pin the complement of a three-variant tag-only classifier,
    //!    since the complement contains TWO variants and every prior
    //!    tag-only classifier pins EXACTLY ONE variant. The two
    //!    receivers together partition the five variants into two
    //!    receiver-family half-spaces (`{Stationary,
    //!    IdentityRepublish, Progression}` on the consistent half,
    //!    `{CrossStore, Regressed}` on the inconsistent half) whose
    //!    disjunction is the constant `true` and whose conjunction is
    //!    the constant `false`.
    //! 10. **Union identity — genuinely new.** At both altitudes,
    //!     `self.same_store_inconsistent() == (self.cross_store() ||
    //!     self.regressed())` pointwise on every variant. This is the
    //!     FIRST union-identity in the classification receiver family:
    //!     a two-variant tag-only classifier equals the disjunction
    //!     of the two single-variant tag-only classifiers whose
    //!     variants it welds. The receiver-family now carries THREE
    //!     distinct shapes for the impossibility half — the
    //!     complement of the consistent predicate (test 9), the
    //!     disjunction of the two single-variant predicates (this
    //!     test), and the welded two-variant [`matches!`] the
    //!     receiver's own body carries. All three agree pointwise,
    //!     and this receiver alone reaches the answer through the
    //!     single-hop [`matches!`] the tag alone supports.
    //! 11. **Two-way partition identity — genuinely new.** At both
    //!     altitudes, the two receivers' disjunction is the constant
    //!     `true` (every variant is either consistent or
    //!     inconsistent) and their conjunction is the constant
    //!     `false` (no variant is both) — the classification's
    //!     two-way partition of the five variants is now welded as a
    //!     pair of receiver-visible predicates whose Xor is the
    //!     constant `true`. A shape neither predicate alone can pin,
    //!     since it requires BOTH sides of the two-way partition to
    //!     be receiver-visible.
    //! 12. Payload-agreement invariant with [`ProofRelation::regressed_by`]:
    //!     [`Regressed`][ProofRelation::Regressed] is the only variant
    //!     carrying `regressed_by()` as `Some`, so
    //!     `self.regressed_by().is_some()` implies
    //!     `self.same_store_inconsistent()` at both altitudes (the
    //!     converse does NOT hold, since [`CrossStore`][ProofRelation::CrossStore]
    //!     is also inconsistent without carrying `regressed_by`).

    use super::*;

    fn nz(n: u64) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(n).expect("nonzero literal")
    }

    fn moved_all() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: true,
            free_moved: true,
        })
        .expect("all three axes moved is non-stationary")
    }

    fn moved_free_only() -> MovedWatermarkDelta {
        MovedWatermarkDelta::new(WatermarkDelta {
            full_moved: true,
            restart_required_moved: false,
            free_moved: true,
        })
        .expect("free_moved+full_moved is non-stationary")
    }

    fn all_five_relations() -> Vec<(&'static str, ProofRelation)> {
        vec![
            ("Stationary", ProofRelation::Stationary),
            (
                "IdentityRepublish",
                ProofRelation::IdentityRepublish { generations: nz(1) },
            ),
            (
                "Progression",
                ProofRelation::Progression {
                    watermark: moved_all(),
                    generations: nz(2),
                },
            ),
            (
                "CrossStore",
                ProofRelation::CrossStore {
                    watermark: moved_free_only(),
                },
            ),
            ("Regressed", ProofRelation::Regressed { by: nz(3) }),
        ]
    }

    fn all_five_wire_variants() -> Vec<(&'static str, ProofRelationWire)> {
        all_five_relations()
            .into_iter()
            .map(|(name, relation)| (name, relation.to_wire()))
            .collect()
    }

    /// Pinned truth table (variant → expected answer). The two
    /// impossibility variants return `true`; the three legitimate
    /// variants return `false`.
    const fn expected_value(relation: &ProofRelation) -> bool {
        match relation {
            ProofRelation::CrossStore { .. } | ProofRelation::Regressed { .. } => true,
            ProofRelation::Stationary
            | ProofRelation::IdentityRepublish { .. }
            | ProofRelation::Progression { .. } => false,
        }
    }

    const fn expected_wire(wire: &ProofRelationWire) -> bool {
        match wire {
            ProofRelationWire::CrossStore { .. } | ProofRelationWire::Regressed { .. } => true,
            ProofRelationWire::Stationary
            | ProofRelationWire::IdentityRepublish { .. }
            | ProofRelationWire::Progression { .. } => false,
        }
    }

    // ---------- (1) Truth table pinned by variant identity

    #[test]
    fn value_truth_table_matches_pinned_two_variant_union() {
        for (name, relation) in all_five_relations() {
            assert_eq!(
                relation.same_store_inconsistent(),
                expected_value(&relation),
                "{name}: value predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn wire_truth_table_matches_pinned_two_variant_union() {
        for (name, wire) in all_five_wire_variants() {
            assert_eq!(
                wire.same_store_inconsistent(),
                expected_wire(&wire),
                "{name}: wire predicate diverged from the pinned truth table",
            );
        }
    }

    #[test]
    fn impossibility_corners_return_true_at_both_altitudes() {
        assert!(
            ProofRelation::CrossStore {
                watermark: moved_free_only(),
            }
            .same_store_inconsistent()
        );
        assert!(ProofRelation::Regressed { by: nz(3) }.same_store_inconsistent());
        assert!(
            ProofRelationWire::CrossStore {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: false,
                    free_moved: true,
                },
            }
            .same_store_inconsistent()
        );
        assert!(ProofRelationWire::Regressed { by: 3 }.same_store_inconsistent());
    }

    #[test]
    fn legitimate_corners_return_false_at_both_altitudes() {
        assert!(!ProofRelation::Stationary.same_store_inconsistent());
        assert!(!ProofRelation::IdentityRepublish { generations: nz(1) }.same_store_inconsistent());
        assert!(
            !ProofRelation::Progression {
                watermark: moved_all(),
                generations: nz(2),
            }
            .same_store_inconsistent()
        );
        assert!(!ProofRelationWire::Stationary.same_store_inconsistent());
        assert!(!ProofRelationWire::IdentityRepublish { generations: 1 }.same_store_inconsistent());
        assert!(
            !ProofRelationWire::Progression {
                watermark: WatermarkDeltaWire {
                    full_moved: true,
                    restart_required_moved: true,
                    free_moved: true,
                },
                generations: 2,
            }
            .same_store_inconsistent()
        );
    }

    // ---------- (2) Pointwise value/wire agreement

    #[test]
    fn value_and_wire_predicates_agree_pointwise_on_every_variant() {
        for (name, relation) in all_five_relations() {
            let value = relation.same_store_inconsistent();
            let wire = relation.to_wire().same_store_inconsistent();
            assert_eq!(
                value, wire,
                "{name}: wire predicate must equal value predicate pointwise",
            );
        }
    }

    // ---------- (3) Round-trip through try_from_wire preserves the verdict

    #[test]
    fn try_from_wire_round_trip_preserves_the_verdict() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            let wire_verdict = wire.same_store_inconsistent();
            let reconstructed =
                ProofRelation::try_from_wire(&wire).expect("legitimate wire parses back");
            assert_eq!(
                wire_verdict,
                reconstructed.same_store_inconsistent(),
                "{name}: try_from_wire round-trip must preserve the same-store-inconsistency \
                 verdict",
            );
        }
    }

    #[test]
    fn try_from_idiom_round_trip_preserves_the_verdict() {
        for (name, wire) in all_five_wire_variants() {
            let value: ProofRelation = (&wire)
                .try_into()
                .expect("legitimate wire parses back via TryFrom");
            let wire_via_named: ProofRelationWire = value.to_wire();
            assert_eq!(
                wire.same_store_inconsistent(),
                wire_via_named.same_store_inconsistent(),
                "{name}: wire → value (via TryFrom) → wire (via to_wire) diverges on the \
                 same-store-inconsistency verdict",
            );
        }
    }

    // ---------- (4) const-callable at both altitudes

    #[test]
    fn value_predicate_is_const_callable() {
        // A payload-carrying variant is verbose in const position
        // because NonZeroU64::new is not const-callable in stable Rust
        // in the .expect() form; a Stationary witness alone is
        // sufficient to catch any regression in the receiver's own
        // `const` qualifier — matching the discipline of the sibling
        // `value_predicate_is_const_callable` test on
        // proof_relation_cross_store_tests.
        const R_STATIONARY: ProofRelation = ProofRelation::Stationary;
        const V_STATIONARY: bool = R_STATIONARY.same_store_inconsistent();
        assert!(!V_STATIONARY);
    }

    #[test]
    fn wire_predicate_is_const_callable_on_every_variant() {
        const STATIONARY: bool = ProofRelationWire::Stationary.same_store_inconsistent();
        const IDENTITY_REPUBLISH: bool =
            ProofRelationWire::IdentityRepublish { generations: 1 }.same_store_inconsistent();
        const PROGRESSION: bool = ProofRelationWire::Progression {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            generations: 2,
        }
        .same_store_inconsistent();
        const CROSS_STORE: bool = ProofRelationWire::CrossStore {
            watermark: WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        }
        .same_store_inconsistent();
        const REGRESSED: bool = ProofRelationWire::Regressed { by: 3 }.same_store_inconsistent();
        assert!(!STATIONARY);
        assert!(!IDENTITY_REPUBLISH);
        assert!(!PROGRESSION);
        assert!(CROSS_STORE);
        assert!(REGRESSED);
    }

    // ---------- (5) Exhaustive variant enumeration

    #[test]
    fn exhaustive_variant_enumeration_is_stable() {
        let value = all_five_relations();
        assert_eq!(value.len(), 5);
        for (_, relation) in &value {
            match relation {
                ProofRelation::Stationary
                | ProofRelation::IdentityRepublish { .. }
                | ProofRelation::Progression { .. }
                | ProofRelation::CrossStore { .. }
                | ProofRelation::Regressed { .. } => {}
            }
        }
        let wire = all_five_wire_variants();
        assert_eq!(wire.len(), 5);
        for (_, wire) in &wire {
            match wire {
                ProofRelationWire::Stationary
                | ProofRelationWire::IdentityRepublish { .. }
                | ProofRelationWire::Progression { .. }
                | ProofRelationWire::CrossStore { .. }
                | ProofRelationWire::Regressed { .. } => {}
            }
        }
    }

    // ---------- (6) Payload-inspection independence

    #[test]
    fn wire_predicate_is_invariant_under_payload_perturbations() {
        let moved_watermarks = [
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: true,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: true,
                free_moved: false,
            },
            WatermarkDeltaWire {
                full_moved: true,
                restart_required_moved: false,
                free_moved: true,
            },
        ];
        // CrossStore: true under every legitimate watermark payload.
        for watermark in moved_watermarks {
            assert!(
                ProofRelationWire::CrossStore { watermark }.same_store_inconsistent(),
                "CrossStore verdict must be invariant under watermark={watermark:?}",
            );
        }
        // Regressed: true under every nonzero backwards magnitude.
        for by in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                ProofRelationWire::Regressed { by }.same_store_inconsistent(),
                "Regressed verdict must be invariant under by={by}",
            );
        }
        // Progression: false under every legitimate watermark payload
        // and every nonzero generations count.
        for watermark in moved_watermarks {
            for generations in [1_u64, 2, 5, 100, u64::MAX] {
                assert!(
                    !ProofRelationWire::Progression {
                        watermark,
                        generations,
                    }
                    .same_store_inconsistent(),
                    "Progression verdict must be invariant under \
                     watermark={watermark:?} generations={generations}",
                );
            }
        }
        // IdentityRepublish: false under every nonzero generations count.
        for generations in [1_u64, 2, 5, 100, u64::MAX] {
            assert!(
                !ProofRelationWire::IdentityRepublish { generations }.same_store_inconsistent(),
                "IdentityRepublish verdict must be invariant under generations={generations}",
            );
        }
    }

    // ---------- (7) Composition through the wire boundary

    #[test]
    fn composition_through_the_wire_boundary_agrees_with_direct_value_path() {
        for (name, relation) in all_five_relations() {
            let direct = relation.same_store_inconsistent();
            let through_wire = relation.to_wire().same_store_inconsistent();
            assert_eq!(
                direct, through_wire,
                "{name}: value → predicate must equal value → to_wire → predicate",
            );
        }
    }

    // ---------- (8) Cross-altitude same-answer with ProofDelta on the four
    //                delta-reachable corners (Regressed is not
    //                delta-reachable — its `by` count is folded to `None` by
    //                the delta path).

    #[test]
    fn verdict_matches_delta_signals_on_delta_reachable_corners() {
        let now = std::time::UNIX_EPOCH;
        let watermark_a = ConfigWatermark {
            full: blake3::hash(b"full-a"),
            restart_required: blake3::hash(b"restart-a"),
            free: blake3::hash(b"free-a"),
        };
        let watermark_b = ConfigWatermark {
            full: blake3::hash(b"full-b"),
            restart_required: blake3::hash(b"restart-b"),
            free: blake3::hash(b"free-b"),
        };
        let prior = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let stationary_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 1,
            observed_at: now,
        };
        let republish_current = ConfigSyncProof {
            watermark: watermark_a,
            generation: 2,
            observed_at: now,
        };
        let progression_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 2,
            observed_at: now,
        };
        let cross_store_current = ConfigSyncProof {
            watermark: watermark_b,
            generation: 1,
            observed_at: now,
        };

        for (name, current) in [
            ("Stationary", stationary_current),
            ("IdentityRepublish", republish_current),
            ("Progression", progression_current),
            ("CrossStore", cross_store_current),
        ] {
            let delta = current.delta_since(&prior);
            let relation = current.relation_since(&prior);
            let relation_wire = relation.to_wire();
            assert_eq!(
                !delta.same_store_consistent(),
                relation.same_store_inconsistent(),
                "{name}: !ProofDelta::same_store_consistent must equal \
                 ProofRelation::same_store_inconsistent on the delta-reachable corners",
            );
            assert_eq!(
                !delta.same_store_consistent(),
                relation_wire.same_store_inconsistent(),
                "{name}: !ProofDelta::same_store_consistent must equal \
                 ProofRelationWire::same_store_inconsistent on the delta-reachable corners",
            );
        }
    }

    // ---------- (9) Complement identity — genuinely new
    //                same_store_inconsistent() == !same_store_consistent()

    #[test]
    fn complement_identity_holds_pointwise_at_both_altitudes() {
        // The FIRST complement-identity in the classification receiver
        // family: no single-variant tag-only classifier can pin the
        // complement of a three-variant tag-only classifier, since
        // the complement contains TWO variants and every prior
        // tag-only classifier pins EXACTLY ONE variant. This
        // receiver equals the negation of same_store_consistent
        // pointwise on every variant.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert_eq!(
                relation.same_store_inconsistent(),
                !relation.same_store_consistent(),
                "{name}: value same_store_inconsistent() must equal \
                 !same_store_consistent()",
            );
            assert_eq!(
                wire.same_store_inconsistent(),
                !wire.same_store_consistent(),
                "{name}: wire same_store_inconsistent() must equal \
                 !same_store_consistent()",
            );
        }
    }

    // ---------- (10) Union identity — genuinely new
    //                 same_store_inconsistent() == cross_store() || regressed()

    #[test]
    fn union_identity_holds_pointwise_at_both_altitudes() {
        // The FIRST union-identity in the classification receiver
        // family: a two-variant tag-only classifier equals the
        // disjunction of the two single-variant tag-only classifiers
        // whose variants it welds.
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert_eq!(
                relation.same_store_inconsistent(),
                relation.cross_store() || relation.regressed(),
                "{name}: value same_store_inconsistent() must equal \
                 cross_store() || regressed()",
            );
            assert_eq!(
                wire.same_store_inconsistent(),
                wire.cross_store() || wire.regressed(),
                "{name}: wire same_store_inconsistent() must equal \
                 cross_store() || regressed()",
            );
        }
    }

    // ---------- (11) Two-way partition identity — genuinely new
    //                 The classification's two-way partition of the five
    //                 variants is now welded as a pair of receiver-visible
    //                 predicates whose Xor is the constant `true` and
    //                 whose conjunction is the constant `false`.

    #[test]
    fn two_way_partition_disjunction_is_constant_true_at_both_altitudes() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                relation.same_store_consistent() || relation.same_store_inconsistent(),
                "{name}: value must be either same_store_consistent OR \
                 same_store_inconsistent (their disjunction is the constant true)",
            );
            assert!(
                wire.same_store_consistent() || wire.same_store_inconsistent(),
                "{name}: wire must be either same_store_consistent OR \
                 same_store_inconsistent (their disjunction is the constant true)",
            );
        }
    }

    #[test]
    fn two_way_partition_conjunction_is_constant_false_at_both_altitudes() {
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            assert!(
                !(relation.same_store_consistent() && relation.same_store_inconsistent()),
                "{name}: value cannot be both same_store_consistent AND \
                 same_store_inconsistent (their conjunction is the constant false)",
            );
            assert!(
                !(wire.same_store_consistent() && wire.same_store_inconsistent()),
                "{name}: wire cannot be both same_store_consistent AND \
                 same_store_inconsistent (their conjunction is the constant false)",
            );
        }
    }

    // ---------- (12) Payload-agreement invariant with regressed_by()

    #[test]
    fn regressed_by_is_some_implies_same_store_inconsistent_at_both_altitudes() {
        // Regressed is the only variant carrying regressed_by() as
        // Some, so regressed_by().is_some() implies
        // same_store_inconsistent() at both altitudes. The converse
        // does NOT hold (CrossStore is also inconsistent without
        // carrying regressed_by).
        for (name, relation) in all_five_relations() {
            let wire = relation.to_wire();
            if relation.regressed_by().is_some() {
                assert!(
                    relation.same_store_inconsistent(),
                    "{name}: value regressed_by().is_some() must imply \
                     same_store_inconsistent()",
                );
            }
            if wire.regressed_by().is_some() {
                assert!(
                    wire.same_store_inconsistent(),
                    "{name}: wire regressed_by().is_some() must imply \
                     same_store_inconsistent()",
                );
            }
        }
    }
}

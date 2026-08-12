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

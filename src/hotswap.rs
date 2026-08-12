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
}

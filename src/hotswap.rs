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
            watermark: ConfigWatermarkWire {
                full: self.watermark.full.to_hex().to_string(),
                restart_required: self.watermark.restart_required.to_hex().to_string(),
                free: self.watermark.free.to_hex().to_string(),
            },
            observed_at_epoch: self
                .observed_at
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        }
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
        for key in ["generation", "watermark", "full", "restartRequired", "free", "observedAtEpoch"] {
            assert!(json.contains(&format!("\"{key}\"")), "missing {key} in {json}");
        }
    }

    /// The timestamp is a stable integer, not a SystemTime whose serde
    /// representation is an implementation detail.
    #[test]
    fn the_timestamp_is_epoch_seconds() {
        assert_eq!(proof().to_wire().observed_at_epoch, 1_700_000_000);
    }
}

//! Typed reload-observation bag for [`crate::ConfigStore`].
//!
//! `ReloadObservatory` owns the five atomic slots that pin every reload
//! event on a [`crate::ConfigStore`]:
//!
//! - `generation` — monotonic count of successful reloads (success cardinality)
//! - `failure_count` — monotonic count of failed reloads (failure cardinality)
//! - `last_reload_error` — most recent unrecovered failure (failure content)
//! - `last_publish_at` — when the currently-published value became current
//! - `last_failure_at` — when the most recent unrecovered failure was caught
//!
//! The two reload primitives — [`Self::record_success`] and
//! [`Self::record_failure`] — are the one canonical funnel each path
//! flows through; both [`crate::ConfigStore::reload`] and the
//! [`crate::ConfigStore::load_and_watch`] watcher closure tail-call them.
//! Each primitive holds the load-bearing atomic-ordering contract:
//! observing the generation / failure-count bump (with `Acquire`)
//! guarantees the matching value, error, and timestamps are visible.
//!
//! The whole bag is cloneable as a single typed value: cross-thread
//! funnels (the watcher closure) clone one [`ReloadObservatory`] instead
//! of five separate `Arc<...>` handles. Adding a future observability
//! slot — last-recovery-attempt timestamp, retry counter, debounce-skip
//! counter — adds one field here and zero parameters to the reload
//! call sites.
//!
//! `pub(crate)` scope: the struct is shikumi's internal primitive. The
//! public observation surface stays where it is — typed accessors on
//! [`crate::ConfigStore`] (`generation()`, `failure_count()`,
//! `last_reload_error()`, `last_publish_at()`, `last_failure_at()`,
//! `shared_*` cross-thread handles) — and now delegates here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};

use crate::error::ShikumiError;
use crate::reload::ReloadFailure;

/// The five-slot reload-observation primitive owned by every
/// [`crate::ConfigStore`].
///
/// All slots are `Arc<...>`-backed so they can be observed concurrently
/// from worker threads via cross-thread handles ([`Self::shared_generation`]
/// et al.). [`Clone`] is the cross-thread funnel itself: cloning the
/// observatory clones all five `Arc`s in lockstep, so a watcher closure
/// captures the whole bag in one move.
pub(crate) struct ReloadObservatory {
    generation: Arc<AtomicU64>,
    failure_count: Arc<AtomicU64>,
    last_reload_error: Arc<ArcSwapOption<ReloadFailure>>,
    last_publish_at: Arc<ArcSwap<Instant>>,
    last_failure_at: Arc<ArcSwapOption<Instant>>,
}

impl ReloadObservatory {
    /// Build a fresh observatory: counters at `0`, error/failure-at
    /// slots empty, publish-at stamped to `Instant::now()`.
    ///
    /// Single point of initialization for all three constructors of
    /// [`crate::ConfigStore`] ([`crate::ConfigStore::load`],
    /// [`crate::ConfigStore::load_merged`],
    /// [`crate::ConfigStore::load_and_watch`]).
    pub(crate) fn new() -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(0)),
            failure_count: Arc::new(AtomicU64::new(0)),
            last_reload_error: Arc::new(ArcSwapOption::empty()),
            last_publish_at: Arc::new(ArcSwap::from_pointee(Instant::now())),
            last_failure_at: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// Publish a new value, clear the failure slots, stamp the publish
    /// time, and bump the generation counter.
    ///
    /// Atomic step order is load-bearing:
    ///
    /// 1. `inner.store(new)` — the value becomes visible.
    /// 2. `last_reload_error.store(None)` — failure content cleared.
    /// 3. `last_failure_at.store(None)` — failure-time cleared.
    /// 4. `last_publish_at.store(now)` — publish-time stamped.
    /// 5. `generation.fetch_add(1, Release)` — cardinality bumped.
    ///
    /// A reader observing the new generation via [`Self::generation`]
    /// (with `Acquire`) is guaranteed (via the underlying `ArcSwap`
    /// Release/Acquire) to also observe the freshly-stored value, the
    /// cleared error and failure-at slots, and the freshly-stamped
    /// publish-at. This is the canonical "successful reload" primitive
    /// — both [`crate::ConfigStore::reload`] and the
    /// [`crate::ConfigStore::load_and_watch`] watcher closure tail-call it.
    pub(crate) fn record_success<T>(&self, inner: &ArcSwap<T>, new: T) {
        inner.store(Arc::new(new));
        self.last_reload_error.store(None);
        self.last_failure_at.store(None);
        self.last_publish_at.store(Arc::new(Instant::now()));
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Capture a failure into the failure-content slot, stamp the
    /// failure-time slot, and bump the cumulative failure-count counter.
    ///
    /// Atomic step order is load-bearing:
    ///
    /// 1. `last_failure_at.store(Some(now))` — failure-time stamped.
    /// 2. `failure_count.fetch_add(1, Release)` — cardinality bumped.
    /// 3. `last_reload_error.store(Some(failure))` — failure published.
    ///
    /// A reader observing `last_reload_error.is_some()` is guaranteed
    /// (via the underlying `ArcSwap` Release/Acquire) to also observe a
    /// populated `last_failure_at` and a `failure_count` that has
    /// advanced past any value sampled before the failure.
    ///
    /// Replaces any prior failure: only the most recent unrecovered
    /// failure is observable through the failure / failure-at slots.
    /// `failure_count` is monotonic and never cleared, so recovery does
    /// not erase the cardinality record.
    pub(crate) fn record_failure(&self, err: &ShikumiError) {
        self.last_failure_at.store(Some(Arc::new(Instant::now())));
        self.failure_count.fetch_add(1, Ordering::Release);
        self.last_reload_error
            .store(Some(Arc::new(ReloadFailure::from_error(err))));
    }

    /// Monotonic count of successful reloads. See
    /// [`crate::ConfigStore::generation`].
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Monotonic count of failed reloads. See
    /// [`crate::ConfigStore::failure_count`].
    pub(crate) fn failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Acquire)
    }

    /// Most recent unrecovered failure, or `None` after a successful
    /// reload. See [`crate::ConfigStore::last_reload_error`].
    pub(crate) fn last_reload_error(&self) -> Option<Arc<ReloadFailure>> {
        self.last_reload_error.load_full()
    }

    /// When the currently-published value became current. See
    /// [`crate::ConfigStore::last_publish_at`].
    pub(crate) fn last_publish_at(&self) -> Instant {
        **self.last_publish_at.load()
    }

    /// How long the currently-published value has been live.
    /// Convenience over [`Self::last_publish_at`].
    pub(crate) fn time_since_publish(&self) -> Duration {
        self.last_publish_at().elapsed()
    }

    /// When the most recent unrecovered failure was caught. See
    /// [`crate::ConfigStore::last_failure_at`].
    pub(crate) fn last_failure_at(&self) -> Option<Instant> {
        self.last_failure_at.load_full().map(|arc| *arc)
    }

    /// How long ago the most recent unrecovered failure was caught.
    /// Convenience over [`Self::last_failure_at`].
    pub(crate) fn time_since_failure(&self) -> Option<Duration> {
        self.last_failure_at().map(|t| t.elapsed())
    }

    /// Cross-thread handle to the generation counter.
    pub(crate) fn shared_generation(&self) -> Arc<AtomicU64> {
        self.generation.clone()
    }

    /// Cross-thread handle to the failure-count counter.
    pub(crate) fn shared_failure_count(&self) -> Arc<AtomicU64> {
        self.failure_count.clone()
    }

    /// Cross-thread handle to the last-reload-error slot.
    pub(crate) fn shared_last_reload_error(&self) -> Arc<ArcSwapOption<ReloadFailure>> {
        self.last_reload_error.clone()
    }

    /// Cross-thread handle to the last-publish-at slot.
    pub(crate) fn shared_last_publish_at(&self) -> Arc<ArcSwap<Instant>> {
        self.last_publish_at.clone()
    }

    /// Cross-thread handle to the last-failure-at slot.
    pub(crate) fn shared_last_failure_at(&self) -> Arc<ArcSwapOption<Instant>> {
        self.last_failure_at.clone()
    }
}

impl Clone for ReloadObservatory {
    /// Clone the whole observatory as a single typed value.
    ///
    /// All five `Arc<...>` handles are cloned in lockstep, so the cloned
    /// observatory points at the same atomics as the original — a
    /// `record_success` / `record_failure` call on either is visible
    /// through both. This is the cross-thread funnel: the
    /// [`crate::ConfigStore::load_and_watch`] watcher closure clones one
    /// observatory instead of five separate `Arc<...>` handles.
    fn clone(&self) -> Self {
        Self {
            generation: self.generation.clone(),
            failure_count: self.failure_count.clone(),
            last_reload_error: self.last_reload_error.clone(),
            last_publish_at: self.last_publish_at.clone(),
            last_failure_at: self.last_failure_at.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ConfigSource;
    use std::path::PathBuf;
    use std::thread;

    #[test]
    fn new_initializes_all_slots_to_zero_or_empty() {
        let obs = ReloadObservatory::new();
        assert_eq!(obs.generation(), 0);
        assert_eq!(obs.failure_count(), 0);
        assert!(obs.last_reload_error().is_none());
        assert!(obs.last_failure_at().is_none());
        assert!(obs.time_since_failure().is_none());
        // last_publish_at is stamped now; elapsed must be small.
        assert!(obs.time_since_publish() < Duration::from_secs(1));
    }

    #[test]
    fn new_stamps_publish_at_within_construction_window() {
        let before = Instant::now();
        let obs = ReloadObservatory::new();
        let after = Instant::now();
        let stamped = obs.last_publish_at();
        assert!(stamped >= before && stamped <= after);
    }

    #[test]
    fn record_success_publishes_value_and_bumps_generation() {
        let obs = ReloadObservatory::new();
        let inner = ArcSwap::from_pointee(0u32);
        obs.record_success(&inner, 42);
        assert_eq!(**inner.load(), 42);
        assert_eq!(obs.generation(), 1);
        assert_eq!(obs.failure_count(), 0);
    }

    #[test]
    fn record_success_clears_failure_slots() {
        let obs = ReloadObservatory::new();
        let inner = ArcSwap::from_pointee(0u32);
        let err = ShikumiError::Parse("bad".to_owned());
        obs.record_failure(&err);
        assert!(obs.last_reload_error().is_some());
        assert!(obs.last_failure_at().is_some());

        obs.record_success(&inner, 1);
        assert!(obs.last_reload_error().is_none());
        assert!(obs.last_failure_at().is_none());
    }

    #[test]
    fn record_success_advances_publish_at() {
        let obs = ReloadObservatory::new();
        let inner = ArcSwap::from_pointee(0u32);
        let t0 = obs.last_publish_at();
        thread::sleep(Duration::from_millis(20));
        obs.record_success(&inner, 1);
        let t1 = obs.last_publish_at();
        assert!(t1 > t0, "successful record must advance publish-at");
    }

    #[test]
    fn record_failure_stamps_and_publishes() {
        let obs = ReloadObservatory::new();
        let err = ShikumiError::Parse("oops".to_owned());
        let before = Instant::now();
        obs.record_failure(&err);
        let after = Instant::now();

        let stamp = obs.last_failure_at().expect("stamp populated");
        assert!(stamp >= before && stamp <= after);
        let captured = obs.last_reload_error().expect("error populated");
        assert_eq!(captured.message, err.to_string());
        assert_eq!(obs.failure_count(), 1);
    }

    #[test]
    fn record_failure_does_not_touch_value_or_generation() {
        let obs = ReloadObservatory::new();
        let inner = ArcSwap::from_pointee(99u32);
        let err = ShikumiError::Parse("oops".to_owned());
        obs.record_failure(&err);
        assert_eq!(**inner.load(), 99);
        assert_eq!(obs.generation(), 0);
    }

    #[test]
    fn record_failure_preserves_publish_at() {
        let obs = ReloadObservatory::new();
        let t0 = obs.last_publish_at();
        thread::sleep(Duration::from_millis(15));
        obs.record_failure(&ShikumiError::Parse("oops".to_owned()));
        let t1 = obs.last_publish_at();
        assert_eq!(
            t0, t1,
            "failed record must preserve publish-at byte-for-byte"
        );
    }

    #[test]
    fn record_failure_is_monotonic() {
        let obs = ReloadObservatory::new();
        let err = ShikumiError::Parse("x".to_owned());
        for i in 1..=5 {
            obs.record_failure(&err);
            assert_eq!(obs.failure_count(), i);
        }
    }

    #[test]
    fn record_success_does_not_clear_failure_count() {
        // failure_count is the lifetime cardinality counter and never resets.
        let obs = ReloadObservatory::new();
        let inner = ArcSwap::from_pointee(0u32);
        obs.record_failure(&ShikumiError::Parse("bad".to_owned()));
        obs.record_failure(&ShikumiError::Parse("bad2".to_owned()));
        assert_eq!(obs.failure_count(), 2);

        obs.record_success(&inner, 1);
        assert_eq!(
            obs.failure_count(),
            2,
            "recovery must not erase the lifetime failure-count"
        );
        assert_eq!(obs.generation(), 1);
    }

    #[test]
    fn ordering_contract_failure_state_pinned_when_error_visible() {
        // The stamp-then-bump-then-publish order means: if
        // last_reload_error.is_some(), then failure_count must already
        // have advanced and last_failure_at must already be Some.
        let obs = ReloadObservatory::new();
        let err = ShikumiError::Parse("oops".to_owned());
        obs.record_failure(&err);
        if obs.last_reload_error().is_some() {
            assert!(obs.failure_count() >= 1);
            assert!(obs.last_failure_at().is_some());
        }
    }

    #[test]
    fn clone_shares_underlying_atomics_with_original() {
        // The cross-thread funnel contract: cloning the observatory
        // shares the underlying atomics, not copies. A bump on either
        // side is visible from both.
        let obs = ReloadObservatory::new();
        let cloned = obs.clone();
        let inner = ArcSwap::from_pointee(0u32);

        obs.record_success(&inner, 1);
        assert_eq!(cloned.generation(), 1);
        assert_eq!(obs.generation(), 1);

        cloned.record_failure(&ShikumiError::Parse("x".to_owned()));
        assert_eq!(obs.failure_count(), 1);
        assert!(obs.last_reload_error().is_some());
    }

    #[test]
    fn shared_handles_point_at_same_atomics() {
        let obs = ReloadObservatory::new();
        let g = obs.shared_generation();
        let fc = obs.shared_failure_count();
        let err_handle = obs.shared_last_reload_error();
        let pub_handle = obs.shared_last_publish_at();
        let fail_handle = obs.shared_last_failure_at();

        let inner = ArcSwap::from_pointee(0u32);
        obs.record_success(&inner, 5);
        assert_eq!(g.load(Ordering::Acquire), 1);
        assert_eq!(**pub_handle.load(), obs.last_publish_at());

        obs.record_failure(&ShikumiError::Parse("x".to_owned()));
        assert_eq!(fc.load(Ordering::Acquire), 1);
        assert!(err_handle.load_full().is_some());
        assert!(fail_handle.load_full().is_some());
    }

    #[test]
    fn shared_handles_outlive_observatory() {
        // Drop the observatory; the shared handles still observe the
        // last published values, mirroring the ArcSwap / AtomicU64 lifetime
        // contract the public ConfigStore accessors rely on.
        let inner = ArcSwap::from_pointee(0u32);
        let (g, fc, err_h, pub_h, fail_h, gen_observed) = {
            let obs = ReloadObservatory::new();
            obs.record_failure(&ShikumiError::Parse("x".to_owned()));
            obs.record_success(&inner, 1);
            (
                obs.shared_generation(),
                obs.shared_failure_count(),
                obs.shared_last_reload_error(),
                obs.shared_last_publish_at(),
                obs.shared_last_failure_at(),
                obs.generation(),
            )
        };
        assert_eq!(g.load(Ordering::Acquire), gen_observed);
        assert_eq!(fc.load(Ordering::Acquire), 1);
        // Last operation was a success, so error + failure-at are cleared.
        assert!(err_h.load_full().is_none());
        assert!(fail_h.load_full().is_none());
        // publish-at survives.
        let _ = **pub_h.load();
    }

    #[test]
    fn record_failure_captures_full_failure_content() {
        // The captured ReloadFailure carries chain + field path + failing
        // source from the underlying ShikumiError — same observability the
        // public ConfigStore accessors expose.
        let obs = ReloadObservatory::new();
        let chain = vec![
            ConfigSource::Env("OBS_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/x.yaml")),
        ];
        let figment_err = {
            let figment = figment::Figment::new();
            figment.extract::<String>().unwrap_err()
        };
        let err = ShikumiError::Extract {
            sources: chain.clone(),
            error: Box::new(figment_err),
        };
        obs.record_failure(&err);
        let captured = obs.last_reload_error().expect("captured");
        assert_eq!(captured.sources, chain);
        assert_eq!(captured.message, err.to_string());
    }

    #[test]
    fn time_since_publish_grows_without_record() {
        let obs = ReloadObservatory::new();
        let e0 = obs.time_since_publish();
        thread::sleep(Duration::from_millis(20));
        let e1 = obs.time_since_publish();
        assert!(e1 > e0);
    }

    #[test]
    fn time_since_failure_none_until_first_failure() {
        let obs = ReloadObservatory::new();
        assert!(obs.time_since_failure().is_none());
        obs.record_failure(&ShikumiError::Parse("x".to_owned()));
        assert!(obs.time_since_failure().is_some());
    }

    #[test]
    fn cross_thread_funnel_via_clone() {
        // The watcher closure pattern: clone the observatory, hand it to
        // a thread that calls record_success / record_failure, observe
        // the result through the original.
        let obs = ReloadObservatory::new();
        let inner = Arc::new(ArcSwap::from_pointee(0u32));
        let cloned = obs.clone();
        let inner_clone = inner.clone();
        let handle = thread::spawn(move || {
            cloned.record_success(&inner_clone, 7);
            cloned.record_failure(&ShikumiError::Parse("from-thread".to_owned()));
        });
        handle.join().expect("worker thread");
        assert_eq!(**inner.load(), 7);
        assert_eq!(obs.generation(), 1);
        assert_eq!(obs.failure_count(), 1);
        let captured = obs.last_reload_error().expect("captured from thread");
        assert!(captured.message.contains("from-thread"));
    }
}

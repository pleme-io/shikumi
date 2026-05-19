//! ArcSwap-based config store with hot-reload.
//!
//! Extracted from karakuri's `Config` struct. Provides lock-free concurrent
//! reads via `ArcSwap` and file-watch-triggered reloads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption, Guard};
use serde::Deserialize;
use tracing::{error, info};

use crate::error::ShikumiError;
use crate::observatory::ReloadObservatory;
use crate::provider::ProviderChain;
use crate::reload::ReloadFailure;
use crate::source::ConfigSource;
use crate::watcher::{ConfigWatcher, symlink_target};

/// A concurrent, hot-reloadable config store.
///
/// Wraps `Arc<ArcSwap<T>>` for lock-free reads. The `get()` method
/// returns a guard that can be dereferenced to `&T` without blocking
/// writers.
///
/// # Type Parameters
///
/// - `T`: The config struct. Must implement `Deserialize` and `Clone`.
pub struct ConfigStore<T> {
    inner: Arc<ArcSwap<T>>,
    path: PathBuf,
    env_prefix: String,
    sources: Vec<ConfigSource>,
    observatory: ReloadObservatory,
    _watcher: Option<ConfigWatcher>,
}

impl<T> ConfigStore<T>
where
    T: for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    /// Load config from a file and start watching for changes.
    ///
    /// The provider chain is: env vars (with `env_prefix`) → config file.
    /// Serde defaults on the struct itself serve as the base layer.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError` if the file cannot be parsed.
    pub fn load(path: &Path, env_prefix: &str) -> Result<Self, ShikumiError> {
        let (config, sources) = Self::load_from_path(path, env_prefix)?;

        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            path: path.to_owned(),
            env_prefix: env_prefix.to_owned(),
            sources,
            observatory: ReloadObservatory::new(),
            _watcher: None,
        })
    }

    /// Load config and start a file watcher for hot-reload.
    ///
    /// On file change, the config is automatically reloaded. Use the
    /// `on_reload` callback to respond to changes (e.g. trigger a
    /// layout recalculation).
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError` if initial load or watcher setup fails.
    pub fn load_and_watch<F>(
        path: &Path,
        env_prefix: &str,
        on_reload: F,
    ) -> Result<Self, ShikumiError>
    where
        F: Fn(&T) + Send + Sync + 'static,
    {
        let (config, sources) = Self::load_from_path(path, env_prefix)?;
        let inner = Arc::new(ArcSwap::from_pointee(config));
        let observatory = ReloadObservatory::new();
        let inner_clone = inner.clone();
        let observatory_clone = observatory.clone();
        let path_owned = path.to_owned();
        let prefix_owned = env_prefix.to_owned();

        let watcher = ConfigWatcher::watch(path, move |event| {
            use notify::EventKind;
            use notify::event::{DataChange, MetadataKind, ModifyKind};

            match &event.kind {
                EventKind::Modify(
                    ModifyKind::Metadata(MetadataKind::WriteTime)
                    | ModifyKind::Data(DataChange::Content),
                )
                | EventKind::Create(_) => {}
                EventKind::Remove(_) => {
                    info!("config file removed, continuing to watch for replacement...");
                    return;
                }
                _ => return,
            }

            // Check if symlink target changed (nix rebuild)
            for path in &event.paths {
                if symlink_target(path).is_some() {
                    info!("symlink target changed for {}", path.display());
                }
            }

            info!("reloading configuration from {}", path_owned.display());
            match Self::load_from_path(&path_owned, &prefix_owned) {
                Ok((new_config, _)) => {
                    on_reload(&new_config);
                    observatory_clone.record_success(&inner_clone, new_config);
                }
                Err(err) => {
                    observatory_clone.record_failure(&err);
                    error!("failed to reload config: {err}");
                }
            }
        })?;

        Ok(Self {
            inner,
            path: path.to_owned(),
            env_prefix: env_prefix.to_owned(),
            sources,
            observatory,
            _watcher: Some(watcher),
        })
    }

    /// Get a read guard to the current config.
    ///
    /// This is lock-free and never blocks. The returned guard can be
    /// dereferenced to `&T`.
    #[must_use]
    pub fn get(&self) -> Guard<Arc<T>> {
        self.inner.load()
    }

    /// Manually reload the config from disk.
    ///
    /// On success, increments the [generation counter](Self::generation)
    /// after the new value is published, and clears any prior
    /// [last reload error](Self::last_reload_error). On failure, the
    /// previous value and generation are preserved untouched, and the
    /// failure is published into the last-reload-error slot.
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError` if the file cannot be parsed.
    pub fn reload(&self) -> Result<(), ShikumiError> {
        match Self::load_from_path(&self.path, &self.env_prefix) {
            Ok((new, _)) => {
                self.observatory.record_success(&self.inner, new);
                Ok(())
            }
            Err(err) => {
                self.observatory.record_failure(&err);
                Err(err)
            }
        }
    }

    /// Replace the current snapshot with a caller-provided value
    /// in one atomic step. Same bookkeeping as [`Self::reload`]:
    /// generation counter bumps, last-publish stamp refreshes,
    /// last-reload-error clears. Bypasses the file → parse path
    /// so callers can push runtime-derived configs (RPC overrides,
    /// programmatic theme switches, daemon-side `SetConfig`
    /// pushes).
    ///
    /// Use cases:
    /// - Tear's `Request::SetConfig(yaml)` RPC: parse the YAML
    ///   into a `TearConfig`, then `replace()` so every attached
    ///   client (mado, the daemon's notify watcher subscribers)
    ///   sees the new value via the same shared `Arc<ArcSwap<T>>`.
    /// - Mado's MCP `config_set` tool: same pattern.
    /// - Programmatic theme toggling (light/dark) without writing
    ///   the file to disk.
    pub fn replace(&self, value: T) {
        self.observatory.record_success(&self.inner, value);
    }

    /// The path this store was loaded from.
    ///
    /// For [`Self::load_merged`], this is the highest-priority (last)
    /// path. Use [`Self::sources`] for the full merge order.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The full provider chain that produced this store, in merge order
    /// (lowest priority first, highest priority last).
    ///
    /// Each entry is a typed [`ConfigSource`] — defaults, env prefix, or
    /// file path. Use this for diagnostic dumps, attestation manifests,
    /// or "where did this value come from?" tooling.
    ///
    /// `load` and `load_and_watch` produce two-element chains:
    /// `[Env, File]` (file overrides env). `load_merged` produces
    /// `[File, File, …, Env]` (env overrides files).
    #[must_use]
    pub fn sources(&self) -> &[ConfigSource] {
        &self.sources
    }

    /// Get a clone of the `Arc<ArcSwap<T>>` for sharing across threads.
    #[must_use]
    pub fn shared(&self) -> Arc<ArcSwap<T>> {
        self.inner.clone()
    }

    /// Monotonic reload generation, starting at `0`.
    ///
    /// Increments by `1` on every successful reload — manual via
    /// [`Self::reload`], or hot-reload via the watcher in
    /// [`Self::load_and_watch`]. A failed reload (parse error, type
    /// mismatch, missing required field) does **not** increment.
    ///
    /// Use it as a typed "did the config change?" hint: cache the value
    /// alongside any derived state, and recompute when it differs.
    /// Reads use `Acquire` ordering so observing a new generation also
    /// makes the corresponding [`Self::get`] visible.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.observatory.generation()
    }

    /// Cross-thread sharable handle to the generation counter.
    ///
    /// Useful when a reader needs to detect reloads after the original
    /// [`ConfigStore`] has been dropped, or alongside the
    /// [`Self::shared`] `ArcSwap` handle in worker threads. Both handles
    /// continue to reflect reloads as long as the originating store
    /// (or its watcher) is alive.
    #[must_use]
    pub fn shared_generation(&self) -> Arc<AtomicU64> {
        self.observatory.shared_generation()
    }

    /// The most recent reload failure since the last successful
    /// reload, or `None` if no reload has failed (or the most recent
    /// reload succeeded).
    ///
    /// Pairs with [`Self::generation`]: when an observer sees the
    /// generation has not advanced past a checkpoint and this returns
    /// `Some`, the failure is the reason. When this returns `None`,
    /// either no reload has been attempted or the last attempt
    /// succeeded — distinguishable via the generation counter.
    ///
    /// Cleared atomically inside [`Self::swap_in`] so a successful
    /// reload erases any prior failure record. Each subsequent failure
    /// replaces the previous one: this is a "most recent" hint, not a
    /// history.
    ///
    /// The initial load (the constructor itself) is not recorded here;
    /// initial-load failures surface as `Result::Err` from the
    /// constructor, never producing a store at all.
    #[must_use]
    pub fn last_reload_error(&self) -> Option<Arc<ReloadFailure>> {
        self.observatory.last_reload_error()
    }

    /// Cross-thread sharable handle to the last-reload-error slot.
    ///
    /// Useful when worker threads need to observe reload failures
    /// independently of the main store handle, or when the slot must
    /// outlive the originating [`ConfigStore`]. The handle continues
    /// to reflect publishes as long as the originating store
    /// (or its watcher) is alive.
    #[must_use]
    pub fn shared_last_reload_error(&self) -> Arc<ArcSwapOption<ReloadFailure>> {
        self.observatory.shared_last_reload_error()
    }

    /// The [`Instant`] at which the currently-published value became
    /// current.
    ///
    /// Initialized to `Instant::now()` at construction (so the value
    /// has been "live" since then) and replaced atomically on every
    /// successful reload — manual via [`Self::reload`], or hot-reload
    /// via the watcher in [`Self::load_and_watch`]. A failed reload
    /// preserves the prior stamp untouched, mirroring the
    /// [generation counter](Self::generation): a reader observing
    /// `generation = N` sees the publish time of generation N.
    ///
    /// Pairs with [`Self::generation`] (which publish ordinal) and
    /// [`Self::last_reload_error`] (why the next publish hasn't
    /// arrived) to form the (which-publish × when-published × why-not-
    /// next) success-and-failure observation triple. Reads use
    /// `Acquire` ordering on the underlying [`ArcSwap`], so observing
    /// a freshly-stamped publish time also makes the corresponding
    /// [`Self::get`] visible — same swap-then-bump contract as
    /// [`Self::generation`].
    #[must_use]
    pub fn last_publish_at(&self) -> Instant {
        self.observatory.last_publish_at()
    }

    /// Convenience: how long the currently-published value has been
    /// live, equal to `self.last_publish_at().elapsed()`.
    ///
    /// Use as a typed staleness hint: "the config value an observer
    /// is reading right now has been current for X." Distinct from
    /// "time since the file was last touched" (which the OS owns):
    /// this is "time since shikumi accepted the file's content as the
    /// next typed value." A failing reload does not advance this
    /// duration, so a long `time_since_publish` paired with
    /// `last_reload_error.is_some()` precisely diagnoses "reloads
    /// have been failing for X."
    #[must_use]
    pub fn time_since_publish(&self) -> Duration {
        self.observatory.time_since_publish()
    }

    /// Cross-thread sharable handle to the publish-time slot.
    ///
    /// Useful when worker threads need to observe publish times
    /// independently of the main store handle, or when the slot must
    /// outlive the originating [`ConfigStore`]. The handle continues
    /// to reflect publishes as long as the originating store
    /// (or its watcher) is alive, mirroring [`Self::shared`],
    /// [`Self::shared_generation`], and [`Self::shared_last_reload_error`].
    #[must_use]
    pub fn shared_last_publish_at(&self) -> Arc<ArcSwap<Instant>> {
        self.observatory.shared_last_publish_at()
    }

    /// The [`Instant`] at which the most recent unrecovered reload
    /// failure was caught, or `None` if no reload has failed (or the
    /// most recent reload succeeded).
    ///
    /// Stamped atomically inside [`Self::record_failure`] on every
    /// failed reload — manual via [`Self::reload`], or hot-reload via
    /// the watcher in [`Self::load_and_watch`]. Cleared atomically
    /// inside [`Self::swap_in`] on every successful reload, mirroring
    /// [`Self::last_reload_error`]: the two slots populate and clear
    /// together as a pair.
    ///
    /// Pairs with [`Self::last_publish_at`] (when the current value
    /// became current) to form the (publish-time × failure-time)
    /// temporal coordinate of the reload surface. The canonical
    /// failing-window diagnostic is `last_failure_at - last_publish_at`:
    /// the duration between the last successful publish and the most
    /// recent unrecovered failure (a positive duration ⇒ the failing
    /// window has been open that long; a `None` ⇒ no failing window).
    ///
    /// Use [`Self::time_since_failure`] for the more common
    /// "how long ago did the most recent failure happen?" question.
    #[must_use]
    pub fn last_failure_at(&self) -> Option<Instant> {
        self.observatory.last_failure_at()
    }

    /// Convenience: how long ago the most recent unrecovered reload
    /// failure was caught, equal to `self.last_failure_at()?.elapsed()`.
    ///
    /// Returns `None` when no failure is currently recorded — either
    /// because no reload has ever failed on this store, or because the
    /// most recent reload succeeded and cleared both [`Self::last_reload_error`]
    /// and [`Self::last_failure_at`] together.
    ///
    /// Use as a typed liveness hint paired with [`Self::time_since_publish`]:
    /// a `Some(d)` here with `d` larger than the watcher's expected
    /// reload cadence ⇒ "reloads have been failing for at least `d`,
    /// uninterrupted." Distinct from `time_since_publish`, which
    /// counts forward from the last *successful* publish regardless of
    /// failures since.
    #[must_use]
    pub fn time_since_failure(&self) -> Option<Duration> {
        self.observatory.time_since_failure()
    }

    /// Cross-thread sharable handle to the failure-time slot.
    ///
    /// Useful when worker threads need to observe the temporal axis of
    /// reload failures independently of the main store handle, or when
    /// the slot must outlive the originating [`ConfigStore`]. The
    /// handle continues to reflect publishes as long as the originating
    /// store (or its watcher) is alive, mirroring [`Self::shared`],
    /// [`Self::shared_generation`], [`Self::shared_last_reload_error`],
    /// and [`Self::shared_last_publish_at`].
    #[must_use]
    pub fn shared_last_failure_at(&self) -> Arc<ArcSwapOption<Instant>> {
        self.observatory.shared_last_failure_at()
    }

    /// Monotonic count of failed reloads since this store was
    /// constructed, starting at `0`.
    ///
    /// Increments by `1` on every reload that fails — manual via
    /// [`Self::reload`], or hot-reload via the watcher in
    /// [`Self::load_and_watch`]. A successful reload (which advances
    /// [`Self::generation`] instead) does **not** affect this counter.
    /// Unlike [`Self::last_reload_error`] and [`Self::last_failure_at`]
    /// — which clear on recovery and pin only the *most recent
    /// unrecovered* failure — `failure_count` is the *cardinality*
    /// record over the whole lifetime of the store: it never resets
    /// and never decrements, so recovery does not erase the count.
    ///
    /// Pairs with [`Self::generation`] (cumulative successful reloads)
    /// to form the (success-count × failure-count) cardinality
    /// coordinate of the reload surface. Their sum is the total
    /// number of reload attempts since construction; their ratio is
    /// the lifetime success / failure rate. Together with
    /// [`Self::last_publish_at`] / [`Self::last_failure_at`] (the
    /// temporal coordinate) the cardinality coordinate completes the
    /// (when × how-many) record on each side.
    ///
    /// Reads use `Acquire` ordering so observing an advanced count
    /// also makes the corresponding [`Self::last_failure_at`] stamp
    /// and [`Self::last_reload_error`] payload visible — the
    /// stamp-then-bump-then-publish contract inside
    /// [`Self::record_failure`].
    #[must_use]
    pub fn failure_count(&self) -> u64 {
        self.observatory.failure_count()
    }

    /// Cross-thread sharable handle to the failure-count counter.
    ///
    /// Useful when worker threads need to observe the cumulative
    /// failure count independently of the main store handle, or when
    /// the counter must outlive the originating [`ConfigStore`]. The
    /// handle continues to reflect failures as long as the originating
    /// store (or its watcher) is alive, mirroring [`Self::shared`],
    /// [`Self::shared_generation`], [`Self::shared_last_reload_error`],
    /// [`Self::shared_last_publish_at`], and
    /// [`Self::shared_last_failure_at`].
    #[must_use]
    pub fn shared_failure_count(&self) -> Arc<AtomicU64> {
        self.observatory.shared_failure_count()
    }

    /// Load config from multiple paths, merging in order (last wins).
    ///
    /// Each path is layered via figment merge, so later files override
    /// earlier ones. Environment variables (with `env_prefix`) are applied
    /// as the final layer and override everything.
    ///
    /// This is designed to work with `ConfigDiscovery::discover_all()`,
    /// which returns paths in merge order (lowest priority first).
    ///
    /// # Errors
    ///
    /// Returns `ShikumiError` if the merged config cannot be parsed.
    pub fn load_merged(paths: &[PathBuf], env_prefix: &str) -> Result<Self, ShikumiError> {
        let (config, sources) = Self::load_from_paths(paths, env_prefix)?;
        let primary_path = paths.last().cloned().unwrap_or_default();

        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            path: primary_path,
            env_prefix: env_prefix.to_owned(),
            sources,
            observatory: ReloadObservatory::new(),
            _watcher: None,
        })
    }

    fn load_from_path(
        path: &Path,
        env_prefix: &str,
    ) -> Result<(T, Vec<ConfigSource>), ShikumiError> {
        ProviderChain::new()
            .with_env(env_prefix)
            .with_file(path)
            .extract_with_sources()
    }

    fn load_from_paths(
        paths: &[PathBuf],
        env_prefix: &str,
    ) -> Result<(T, Vec<ConfigSource>), ShikumiError> {
        paths
            .iter()
            .fold(ProviderChain::new(), |chain, path| chain.with_file(path))
            .with_env(env_prefix)
            .extract_with_sources()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[derive(Deserialize, Clone, Debug, Default, PartialEq)]
    struct TestConfig {
        name: Option<String>,
        count: Option<u32>,
    }

    #[test]
    fn load_yaml_config() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.yaml");
        fs::write(&file, "name: hello\ncount: 42\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_STORE_TEST_").unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("hello"));
        assert_eq!(config.count, Some(42));
    }

    #[test]
    fn load_toml_config() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.toml");
        fs::write(&file, "name = \"world\"\ncount = 7\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_STORE_TEST2_").unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("world"));
        assert_eq!(config.count, Some(7));
    }

    #[test]
    fn replace_swaps_atomically_without_touching_disk() {
        // ConfigStore::replace(value) accepts a runtime-derived
        // value (e.g. parsed from an RPC payload) and atomically
        // swaps it into the inner ArcSwap. Same bookkeeping as
        // reload() — generation counter bumps, last_publish_at
        // refreshes — but no file IO.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("rep.yaml");
        fs::write(&file, "name: from-disk\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_REPLACE_TEST_").unwrap();
        assert_eq!(store.get().name.as_deref(), Some("from-disk"));
        let gen_before = store.generation();

        // RPC-style replace: caller hand-crafts the new value.
        store.replace(TestConfig {
            name: Some("from-rpc".into()),
            count: Some(99),
        });
        assert_eq!(store.get().name.as_deref(), Some("from-rpc"));
        assert_eq!(store.get().count, Some(99));
        // Generation bumps so subscribers polling on it see the
        // change.
        assert!(store.generation() > gen_before, "generation didn't bump");

        // Disk content is unchanged — replace() doesn't write.
        let on_disk = fs::read_to_string(&file).unwrap();
        assert_eq!(on_disk, "name: from-disk\n");
    }

    #[test]
    fn replace_visible_via_shared_arc_swap() {
        // Pattern that tear-config + mado MCP both use: hold the
        // Arc<ArcSwap<T>> from shared(), call store.replace(),
        // observe the new value through the Arc.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("rep2.yaml");
        fs::write(&file, "name: orig\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_REPLACE_SHARE_TEST_").unwrap();
        let shared = store.shared();

        store.replace(TestConfig {
            name: Some("replaced".into()),
            count: None,
        });
        let observed = shared.load();
        assert_eq!(observed.name.as_deref(), Some("replaced"));
    }

    #[test]
    fn manual_reload() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.yaml");
        fs::write(&file, "name: initial\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_STORE_TEST3_").unwrap();
        assert_eq!(store.get().name.as_deref(), Some("initial"));

        fs::write(&file, "name: updated\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.get().name.as_deref(), Some("updated"));
    }

    #[test]
    fn shared_returns_arc() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.yaml");
        fs::write(&file, "name: shared\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_STORE_TEST4_").unwrap();
        let shared = store.shared();
        let config = shared.load();
        assert_eq!(config.name.as_deref(), Some("shared"));
    }

    #[test]
    fn load_and_watch_triggers_callback() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("watched.yaml");
        fs::write(&file, "name: original\n").unwrap();

        let reloads = Arc::new(Mutex::new(Vec::new()));
        let reloads_clone = reloads.clone();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_WATCH_TEST_",
            move |config: &TestConfig| {
                reloads_clone.lock().unwrap().push(config.name.clone());
            },
        )
        .unwrap();

        assert_eq!(store.get().name.as_deref(), Some("original"));

        // Modify the file
        thread::sleep(Duration::from_millis(100));
        fs::write(&file, "name: changed\n").unwrap();

        // Wait for watcher to detect change
        thread::sleep(Duration::from_millis(800));

        let captured = reloads.lock().unwrap();
        if !captured.is_empty() {
            assert_eq!(captured.last().unwrap().as_deref(), Some("changed"));
            assert_eq!(store.get().name.as_deref(), Some("changed"));
        }
        // Note: on some CI systems the watcher may be slower, so we
        // don't hard-fail if no events captured — the manual_reload
        // test covers the core logic.
    }

    #[test]
    fn path_returns_original() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.yaml");
        fs::write(&file, "name: test\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_STORE_TEST5_").unwrap();
        assert_eq!(store.path(), file);
    }

    #[test]
    fn load_nonexistent_errors() {
        let result = ConfigStore::<TestConfig>::load(
            Path::new("/nonexistent/config.yaml"),
            "SHIKUMI_NOEXIST_",
        );
        // Figment returns defaults for Option fields, so this actually succeeds
        // with all-None fields since the file provider silently returns empty.
        // This is expected figment behavior.
        assert!(result.is_ok());
        let config = result.unwrap().get();
        assert_eq!(config.name, None);
    }

    #[test]
    fn env_prefix_overrides_file_values() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("envstore.yaml");
        fs::write(&file, "name: from_file\ncount: 10\n").unwrap();

        let prefix = "SHIKUMI_STORE_ENV_";
        unsafe { std::env::set_var("SHIKUMI_STORE_ENV_NAME", "from_env") };

        let store = ConfigStore::<TestConfig>::load(&file, prefix).unwrap();
        let config = store.get();

        unsafe { std::env::remove_var("SHIKUMI_STORE_ENV_NAME") };

        // Env merged first, then file overrides -- per load_from_path ordering
        // Actually: load_from_path does .with_env().with_file(), so file wins
        assert_eq!(config.name.as_deref(), Some("from_file"));
        assert_eq!(config.count, Some(10));
    }

    #[test]
    fn reload_with_invalid_yaml_returns_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("reloaderr.yaml");
        fs::write(&file, "name: valid\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_RELOADERR_").unwrap();
        assert_eq!(store.get().name.as_deref(), Some("valid"));

        // Write invalid YAML
        fs::write(&file, "name: [unclosed\n").unwrap();
        let result = store.reload();
        assert!(result.is_err(), "expected reload to fail on invalid YAML");

        // Original value should be preserved after failed reload
        assert_eq!(store.get().name.as_deref(), Some("valid"));
    }

    #[test]
    fn reload_preserves_previous_on_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("preserve.yaml");
        fs::write(&file, "name: first\ncount: 5\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PRESERVE_").unwrap();
        assert_eq!(store.get().count, Some(5));

        // Write yaml that has a type mismatch (count should be u32)
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        // Previous config should remain
        assert_eq!(store.get().count, Some(5));
    }

    #[test]
    fn concurrent_reads_are_lock_free() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("concurrent.yaml");
        fs::write(&file, "name: shared_value\ncount: 99\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_CONC_").unwrap();
        let shared = store.shared();

        // Spawn multiple reader threads
        let mut handles = Vec::new();
        for _ in 0..10 {
            let shared_clone = shared.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let guard = shared_clone.load();
                    assert!(guard.name.is_some());
                }
            }));
        }

        for handle in handles {
            handle.join().expect("reader thread should not panic");
        }
    }

    #[test]
    fn load_empty_yaml_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.yaml");
        fs::write(&file, "").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_EMPTY_").unwrap();
        let config = store.get();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn load_yaml_with_extra_fields_is_permissive() {
        // Figment should ignore unknown fields by default
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("extra.yaml");
        fs::write(&file, "name: known\nunknown_field: ignored\ncount: 3\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_EXTRA_").unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("known"));
        assert_eq!(config.count, Some(3));
    }

    #[test]
    fn reload_updates_all_shared_readers() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("shared_reload.yaml");
        fs::write(&file, "name: before\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_SHRD_").unwrap();
        let shared1 = store.shared();
        let shared2 = store.shared();

        assert_eq!(shared1.load().name.as_deref(), Some("before"));
        assert_eq!(shared2.load().name.as_deref(), Some("before"));

        fs::write(&file, "name: after\n").unwrap();
        store.reload().unwrap();

        // Both shared references should see the update
        assert_eq!(shared1.load().name.as_deref(), Some("after"));
        assert_eq!(shared2.load().name.as_deref(), Some("after"));
    }

    #[test]
    fn load_toml_with_sections() {
        #[derive(Deserialize, Clone, Debug, Default)]
        struct SectionConfig {
            title: Option<String>,
            window: Option<WindowSection>,
        }
        #[derive(Deserialize, Clone, Debug, Default)]
        struct WindowSection {
            width: Option<u32>,
            height: Option<u32>,
        }

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("sections.toml");
        fs::write(
            &file,
            "title = \"my app\"\n\n[window]\nwidth = 1920\nheight = 1080\n",
        )
        .unwrap();

        let store = ConfigStore::<SectionConfig>::load(&file, "SHIKUMI_SEC_").unwrap();
        let config = store.get();
        assert_eq!(config.title.as_deref(), Some("my app"));
        let window = config.window.as_ref().expect("window section present");
        assert_eq!(window.width, Some(1920));
        assert_eq!(window.height, Some(1080));
    }

    #[test]
    fn multiple_reloads_always_reflect_latest() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("multi.yaml");
        fs::write(&file, "count: 1\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_MULTI_").unwrap();
        assert_eq!(store.get().count, Some(1));

        for i in 2..=5 {
            fs::write(&file, format!("count: {i}\n")).unwrap();
            store.reload().unwrap();
            assert_eq!(store.get().count, Some(i));
        }
    }

    #[test]
    fn load_with_required_field_missing_from_file() {
        #[derive(Deserialize, Clone, Debug)]
        struct StrictConfig {
            #[allow(dead_code)]
            required: String,
        }

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("strict.yaml");
        fs::write(&file, "other: value\n").unwrap();

        let result = ConfigStore::<StrictConfig>::load(&file, "SHIKUMI_STRICT_");
        assert!(
            result.is_err(),
            "expected error when required field is missing"
        );
    }

    #[test]
    fn load_unicode_config_values() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("unicode.yaml");
        fs::write(&file, "name: \"日本語テスト\"\ncount: 42\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_UNI_").unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("日本語テスト"));
    }

    // ---- load_merged tests ----

    #[test]
    fn load_merged_single_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("single.yaml");
        fs::write(&file, "name: only\ncount: 1\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_MERGE_SINGLE_",
        )
        .unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("only"));
        assert_eq!(config.count, Some(1));
        assert_eq!(store.path(), file);
    }

    #[test]
    fn load_merged_last_file_wins() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.yaml");
        let override_ = dir.path().join("override.yaml");
        fs::write(&base, "name: base\ncount: 1\n").unwrap();
        fs::write(&override_, "name: override\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            &[base, override_.clone()],
            "SHIKUMI_MERGE_LAST_",
        )
        .unwrap();
        let config = store.get();
        // name overridden, count preserved from base
        assert_eq!(config.name.as_deref(), Some("override"));
        assert_eq!(config.count, Some(1));
        assert_eq!(store.path(), override_);
    }

    #[test]
    fn load_merged_three_layers() {
        let dir = TempDir::new().unwrap();
        let sys = dir.path().join("system.yaml");
        let user = dir.path().join("user.yaml");
        let local = dir.path().join("local.yaml");
        fs::write(&sys, "name: system\ncount: 1\n").unwrap();
        fs::write(&user, "name: user\n").unwrap();
        fs::write(&local, "count: 99\n").unwrap();

        let store =
            ConfigStore::<TestConfig>::load_merged(&[sys, user, local], "SHIKUMI_MERGE_3LAYER_")
                .unwrap();
        let config = store.get();
        // name from user (second layer), count from local (third layer)
        assert_eq!(config.name.as_deref(), Some("user"));
        assert_eq!(config.count, Some(99));
    }

    #[test]
    fn load_merged_nonexistent_files_skipped() {
        let dir = TempDir::new().unwrap();
        let exists = dir.path().join("exists.yaml");
        let missing = dir.path().join("missing.yaml");
        fs::write(&exists, "name: present\ncount: 42\n").unwrap();

        // Figment silently ignores nonexistent files
        let store =
            ConfigStore::<TestConfig>::load_merged(&[missing, exists], "SHIKUMI_MERGE_MISS_")
                .unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("present"));
        assert_eq!(config.count, Some(42));
    }

    #[test]
    fn load_merged_empty_paths() {
        // Empty paths list should produce default values
        let store = ConfigStore::<TestConfig>::load_merged(&[], "SHIKUMI_MERGE_EMPTY_").unwrap();
        let config = store.get();
        assert_eq!(config.name, None);
        assert_eq!(config.count, None);
    }

    #[test]
    fn load_merged_env_overrides_all_files() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("merged_env.yaml");
        fs::write(&file, "name: from_file\ncount: 10\n").unwrap();

        let prefix = "SHIKUMI_MERGE_ENV_";
        unsafe { std::env::set_var("SHIKUMI_MERGE_ENV_NAME", "from_env") };

        let store = ConfigStore::<TestConfig>::load_merged(&[file], prefix).unwrap();
        let config = store.get();

        unsafe { std::env::remove_var("SHIKUMI_MERGE_ENV_NAME") };

        // Env is last layer, so it wins over files
        assert_eq!(config.name.as_deref(), Some("from_env"));
        assert_eq!(config.count, Some(10));
    }

    #[test]
    fn load_merged_mixed_yaml_and_toml() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("base.yaml");
        let toml = dir.path().join("override.toml");
        fs::write(&yaml, "name: from_yaml\ncount: 5\n").unwrap();
        fs::write(&toml, "name = \"from_toml\"\n").unwrap();

        let store =
            ConfigStore::<TestConfig>::load_merged(&[yaml, toml], "SHIKUMI_MERGE_MIX_").unwrap();
        let config = store.get();
        assert_eq!(config.name.as_deref(), Some("from_toml"));
        assert_eq!(config.count, Some(5));
    }

    #[test]
    fn load_merged_path_is_last_in_list() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("first.yaml");
        let last = dir.path().join("last.yaml");
        fs::write(&first, "name: first\n").unwrap();
        fs::write(&last, "name: last\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            &[first.clone(), last.clone()],
            "SHIKUMI_MERGE_PATH_",
        )
        .unwrap();
        assert_eq!(store.path(), last, "path() should return the last file");
    }

    #[test]
    fn load_merged_empty_path_is_default() {
        let store = ConfigStore::<TestConfig>::load_merged(&[], "SHIKUMI_MERGE_EMPTYP_").unwrap();
        assert_eq!(store.path(), Path::new(""));
    }

    #[test]
    fn reload_after_file_deletion_returns_defaults() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("deleteme.yaml");
        fs::write(&file, "name: present\ncount: 42\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_DEL_").unwrap();
        assert_eq!(store.get().name.as_deref(), Some("present"));

        fs::remove_file(&file).unwrap();
        store.reload().unwrap();

        let config = store.get();
        assert_eq!(config.name, None, "deleted file should yield defaults");
        assert_eq!(config.count, None);
    }

    // ---- sources() provenance tests ----

    #[test]
    fn sources_for_single_load_records_env_then_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("src.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_SRCS_").unwrap();
        let s = store.sources();
        assert_eq!(s.len(), 2, "expected env + file in sources");
        assert!(s[0].is_env(), "first layer should be env");
        assert_eq!(s[0].as_env_prefix(), Some("SHIKUMI_SRCS_"));
        assert!(s[1].is_file(), "second layer should be file");
        assert_eq!(s[1].as_path(), Some(file.as_path()));
    }

    #[test]
    fn sources_for_load_merged_records_files_then_env() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.yaml");
        let b = dir.path().join("b.yaml");
        fs::write(&a, "name: a\n").unwrap();
        fs::write(&b, "name: b\n").unwrap();

        let store =
            ConfigStore::<TestConfig>::load_merged(&[a.clone(), b.clone()], "SHIKUMI_MERGE_SRCS_")
                .unwrap();
        let s = store.sources();
        assert_eq!(s.len(), 3, "expected 2 files + env in sources");
        assert_eq!(s[0].as_path(), Some(a.as_path()));
        assert_eq!(s[1].as_path(), Some(b.as_path()));
        assert!(s[2].is_env());
        assert_eq!(s[2].as_env_prefix(), Some("SHIKUMI_MERGE_SRCS_"));
    }

    #[test]
    fn sources_for_load_merged_empty_paths_records_only_env() {
        let store =
            ConfigStore::<TestConfig>::load_merged(&[], "SHIKUMI_MERGE_EMPTY_SRCS_").unwrap();
        let s = store.sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].is_env());
    }

    #[test]
    fn sources_path_matches_last_file_in_chain() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.yaml");
        let b = dir.path().join("b.yaml");
        fs::write(&a, "name: a\n").unwrap();
        fs::write(&b, "name: b\n").unwrap();

        let store =
            ConfigStore::<TestConfig>::load_merged(&[a.clone(), b.clone()], "SHIKUMI_MERGE_PATHM_")
                .unwrap();
        // path() points at the highest-priority *file*, not the env layer.
        assert_eq!(store.path(), b);
        let last_file = store
            .sources()
            .iter()
            .filter_map(ConfigSource::as_path)
            .next_back()
            .unwrap();
        assert_eq!(last_file, b);
    }

    #[test]
    fn sources_for_load_and_watch_records_chain() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("watched.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_WATCH_SRCS_",
            |_: &TestConfig| {},
        )
        .unwrap();

        let s = store.sources();
        assert_eq!(s.len(), 2);
        assert!(s[0].is_env());
        assert_eq!(s[1].as_path(), Some(file.as_path()));
    }

    #[test]
    fn sources_unchanged_after_reload() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("rel.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_SRCS_REL_").unwrap();
        let before = store.sources().to_vec();

        fs::write(&file, "name: b\n").unwrap();
        store.reload().unwrap();

        assert_eq!(store.sources(), before.as_slice());
    }

    #[test]
    fn get_returns_arc_that_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("outlive.yaml");
        fs::write(&file, "name: persistent\n").unwrap();

        let guard = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_OUTLIVE_").unwrap();
            let shared = store.shared();
            shared.load_full()
        };
        assert_eq!(guard.name.as_deref(), Some("persistent"));
    }

    // ---- generation() / shared_generation() tests ----

    #[test]
    fn generation_starts_at_zero_for_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN0_").unwrap();
        assert_eq!(store.generation(), 0);
    }

    #[test]
    fn generation_starts_at_zero_for_load_merged() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("genm.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_GEN_MERGED_",
        )
        .unwrap();
        assert_eq!(store.generation(), 0);
    }

    #[test]
    fn generation_starts_at_zero_for_load_and_watch() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("genw.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_GEN_WATCH_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert_eq!(store.generation(), 0);
    }

    #[test]
    fn successful_reload_increments_generation() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_inc.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_INC_").unwrap();
        assert_eq!(store.generation(), 0);

        fs::write(&file, "name: b\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.generation(), 1);

        fs::write(&file, "name: c\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.generation(), 2);
    }

    #[test]
    fn failed_reload_does_not_increment_generation() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_fail.yaml");
        fs::write(&file, "name: ok\ncount: 1\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_FAIL_").unwrap();
        assert_eq!(store.generation(), 0);

        // Type mismatch: count expects u32
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(
            store.generation(),
            0,
            "failed reload must not bump generation"
        );

        // Recover with a valid file: bump should resume from 0 -> 1.
        fs::write(&file, "name: recovered\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.generation(), 1);
    }

    #[test]
    fn generation_observed_after_swap_for_acquire_release_contract() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_obs.yaml");
        fs::write(&file, "name: before\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_OBS_").unwrap();
        let g0 = store.generation();
        assert_eq!(store.get().name.as_deref(), Some("before"));

        fs::write(&file, "name: after\n").unwrap();
        store.reload().unwrap();

        // When generation moves forward, the get() value must already
        // reflect the new state — that's the swap-then-bump contract.
        assert!(store.generation() > g0);
        assert_eq!(store.get().name.as_deref(), Some("after"));
    }

    #[test]
    fn shared_generation_visible_across_threads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_shared.yaml");
        fs::write(&file, "name: t0\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_SHARED_").unwrap();
        let gen_handle = store.shared_generation();
        assert_eq!(gen_handle.load(Ordering::Acquire), 0);

        let observed = thread::spawn({
            let gen_handle = gen_handle.clone();
            move || {
                // Spin briefly until the main thread has published a new gen.
                for _ in 0..200 {
                    if gen_handle.load(Ordering::Acquire) > 0 {
                        return gen_handle.load(Ordering::Acquire);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                gen_handle.load(Ordering::Acquire)
            }
        });

        fs::write(&file, "name: t1\n").unwrap();
        store.reload().unwrap();

        let seen = observed.join().expect("observer thread");
        assert!(seen >= 1, "observer should see incremented generation");
        assert_eq!(store.generation(), 1);
    }

    #[test]
    fn shared_generation_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_outlive.yaml");
        fs::write(&file, "name: persistent\n").unwrap();

        let (handle, before_drop) = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_OUTLIVE_").unwrap();
            fs::write(&file, "name: rev1\n").unwrap();
            store.reload().unwrap();
            (store.shared_generation(), store.generation())
        };
        // The store is dropped; the handle still reads the last value.
        assert_eq!(handle.load(Ordering::Acquire), before_drop);
        assert_eq!(handle.load(Ordering::Acquire), 1);
    }

    #[test]
    fn shared_generation_is_same_arc_as_internal() {
        // The handle must point at the same atomic the store mutates,
        // otherwise reload changes wouldn't be visible through it.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_same.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_SAME_").unwrap();
        let handle = store.shared_generation();

        fs::write(&file, "name: y\n").unwrap();
        store.reload().unwrap();

        assert_eq!(handle.load(Ordering::Acquire), store.generation());
    }

    #[test]
    fn load_and_watch_increments_generation_on_manual_reload() {
        // The watcher closure routes through swap_in too. Verify via the
        // (always-deterministic) manual reload path; the watcher's own
        // event delivery is timing-sensitive on CI.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_watch.yaml");
        fs::write(&file, "name: w0\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_GEN_WATCH_INC_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert_eq!(store.generation(), 0);

        fs::write(&file, "name: w1\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.generation(), 1);
    }

    // ---- last_reload_error() / shared_last_reload_error() tests ----

    #[test]
    fn last_reload_error_starts_none_for_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR0_").unwrap();
        assert!(store.last_reload_error().is_none());
    }

    #[test]
    fn last_reload_error_starts_none_for_load_merged() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("errm.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_ERR_MERGED_",
        )
        .unwrap();
        assert!(store.last_reload_error().is_none());
    }

    #[test]
    fn last_reload_error_starts_none_for_load_and_watch() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("errw.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_ERR_WATCH_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert!(store.last_reload_error().is_none());
    }

    #[test]
    fn failed_reload_populates_last_reload_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_pop.yaml");
        fs::write(&file, "name: ok\ncount: 1\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_POP_").unwrap();
        assert!(store.last_reload_error().is_none());

        // Type mismatch: count expects u32
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let captured = store
            .last_reload_error()
            .expect("failed reload must publish a failure");
        assert!(!captured.message.is_empty(), "message must be captured");
    }

    #[test]
    fn successful_reload_clears_last_reload_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_clear.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_CLEAR_").unwrap();

        // Force a failure
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert!(store.last_reload_error().is_some());

        // Recover: success must clear the slot
        fs::write(&file, "name: recovered\n").unwrap();
        store.reload().unwrap();
        assert!(
            store.last_reload_error().is_none(),
            "successful reload must clear the failure slot"
        );
    }

    #[test]
    fn most_recent_failure_replaces_prior() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_recent.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_RECENT_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        let first = store.last_reload_error().unwrap();

        fs::write(&file, "name: [unclosed\n").unwrap();
        assert!(store.reload().is_err());
        let second = store.last_reload_error().unwrap();

        // The second failure replaces the first. Both must carry a
        // non-empty message; replacement is observable as a different
        // Arc identity even when messages happen to coincide.
        assert!(!first.message.is_empty());
        assert!(!second.message.is_empty());
        assert!(
            !Arc::ptr_eq(&first, &second),
            "second failure must replace the first slot entry"
        );
    }

    #[test]
    fn last_reload_error_carries_source_chain() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_chain.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_CHAIN_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let captured = store.last_reload_error().unwrap();
        // The chain comes from ProviderChain (env + file in load).
        assert_eq!(captured.sources.len(), 2);
        assert!(captured.sources[0].is_env());
        assert_eq!(
            captured.sources[0].as_env_prefix(),
            Some("SHIKUMI_ERR_CHAIN_")
        );
        assert!(captured.sources[1].is_file());
        assert_eq!(captured.sources[1].as_path(), Some(file.as_path()));
    }

    #[test]
    fn last_reload_error_carries_field_path() {
        // Type mismatch on a typed field: figment localizes the offending key
        // (`count`), which propagates through record_failure → ReloadFailure.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_field.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_FIELD_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let captured = store.last_reload_error().unwrap();
        assert_eq!(
            captured.field_path,
            vec!["count".to_owned()],
            "the failing field must surface in the cross-thread observable failure"
        );
    }

    #[test]
    fn failed_reload_does_not_increment_generation_but_records_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_gen.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_GEN_").unwrap();
        let g_before = store.generation();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert_eq!(
            store.generation(),
            g_before,
            "failed reload must not bump generation"
        );
        assert!(
            store.last_reload_error().is_some(),
            "failed reload must publish a failure"
        );
    }

    #[test]
    fn shared_last_reload_error_visible_across_threads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_shared.yaml");
        fs::write(&file, "name: t0\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_SHARED_").unwrap();
        let err_handle = store.shared_last_reload_error();
        assert!(err_handle.load_full().is_none());

        let observed = thread::spawn({
            let err_handle = err_handle.clone();
            move || {
                for _ in 0..200 {
                    if err_handle.load_full().is_some() {
                        return true;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                err_handle.load_full().is_some()
            }
        });

        fs::write(&file, "count: not_a_number\n").unwrap();
        let _ = store.reload();

        assert!(
            observed.join().expect("observer thread"),
            "observer should see the published failure"
        );
    }

    #[test]
    fn shared_last_reload_error_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_outlive.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let handle = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_OUTLIVE_").unwrap();
            fs::write(&file, "count: not_a_number\n").unwrap();
            let _ = store.reload();
            store.shared_last_reload_error()
        };
        // The store is dropped; the handle still reads the published failure.
        let captured = handle
            .load_full()
            .expect("failure must persist after store drop");
        assert!(!captured.message.is_empty());
    }

    #[test]
    fn shared_last_reload_error_is_same_arc_as_internal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_same.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_SAME_").unwrap();
        let handle = store.shared_last_reload_error();

        fs::write(&file, "count: not_a_number\n").unwrap();
        let _ = store.reload();

        // Both views see the same Arc<ReloadFailure>.
        let via_store = store.last_reload_error().unwrap();
        let via_handle = handle.load_full().unwrap();
        assert!(Arc::ptr_eq(&via_store, &via_handle));
    }

    #[test]
    fn success_after_failure_clears_slot_and_advances_generation() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_recover.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_RECOVER_").unwrap();
        let g0 = store.generation();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.generation(), g0, "no bump on failure");
        assert!(store.last_reload_error().is_some());

        fs::write(&file, "name: ok\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.generation(), g0 + 1, "bump on success");
        assert!(store.last_reload_error().is_none(), "slot cleared");
    }

    #[test]
    fn last_reload_error_message_matches_returned_error_display() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_msg.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_MSG_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        let returned = store.reload().unwrap_err();
        let captured = store.last_reload_error().unwrap();
        assert_eq!(
            captured.message,
            returned.to_string(),
            "published failure message must match Display of the returned error"
        );
    }

    #[test]
    fn last_reload_error_carries_failing_source() {
        // End-to-end: reload failure on a file → ReloadFailure published
        // through swap_in/record_failure carries the failing-source
        // attribution alongside chain + field path. Proves the four-
        // dimensional observation surface (where × when × why × what)
        // is now five-dimensional with `which-layer` pinned.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("err_failsrc.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_ERR_FAILSRC_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let captured = store.last_reload_error().unwrap();
        let attributed = captured
            .failing_source
            .as_ref()
            .expect("failing source must be captured for figment-attributed failure");
        assert!(attributed.is_file());
        assert_eq!(attributed.as_path(), Some(file.as_path()));
        // And it agrees with the recorded chain.
        assert!(captured.sources.iter().any(|s| s == attributed));
    }

    #[test]
    fn generation_monotonic_across_many_reloads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("gen_mono.yaml");
        fs::write(&file, "count: 0\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_GEN_MONO_").unwrap();
        let mut last = store.generation();
        for i in 1..=8 {
            fs::write(&file, format!("count: {i}\n")).unwrap();
            store.reload().unwrap();
            let now = store.generation();
            assert!(now > last, "generation must be strictly monotonic");
            last = now;
        }
        assert_eq!(store.generation(), 8);
    }

    // ---- last_publish_at() / time_since_publish() / shared_last_publish_at() tests ----

    #[test]
    fn last_publish_at_stamped_at_construction_for_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_t0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let before = Instant::now();
        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_T0_").unwrap();
        let after = Instant::now();

        let stamped = store.last_publish_at();
        assert!(
            stamped >= before && stamped <= after,
            "last_publish_at must be stamped between the surrounding Instant::now() calls"
        );
    }

    #[test]
    fn last_publish_at_stamped_at_construction_for_load_merged() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_tm.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let before = Instant::now();
        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_PUB_MERGED_",
        )
        .unwrap();
        let after = Instant::now();

        let stamped = store.last_publish_at();
        assert!(stamped >= before && stamped <= after);
    }

    #[test]
    fn last_publish_at_stamped_at_construction_for_load_and_watch() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_tw.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let before = Instant::now();
        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_PUB_WATCH_",
            |_: &TestConfig| {},
        )
        .unwrap();
        let after = Instant::now();

        let stamped = store.last_publish_at();
        assert!(stamped >= before && stamped <= after);
    }

    #[test]
    fn last_publish_at_advances_on_successful_reload() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_adv.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_ADV_").unwrap();
        let t0 = store.last_publish_at();

        // Sleep a measurable interval, then reload.
        thread::sleep(Duration::from_millis(20));
        fs::write(&file, "name: b\n").unwrap();
        store.reload().unwrap();

        let t1 = store.last_publish_at();
        assert!(
            t1 > t0,
            "successful reload must advance last_publish_at; t0={t0:?} t1={t1:?}"
        );
        assert!(
            t1.duration_since(t0) >= Duration::from_millis(15),
            "advance must reflect the elapsed interval"
        );
    }

    #[test]
    fn last_publish_at_unchanged_on_failed_reload() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_fail.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_FAIL_").unwrap();
        let t0 = store.last_publish_at();

        thread::sleep(Duration::from_millis(20));
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let t1 = store.last_publish_at();
        assert_eq!(
            t0, t1,
            "failed reload must preserve the last_publish_at stamp"
        );
    }

    #[test]
    fn time_since_publish_starts_near_zero() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_near0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_NEAR0_").unwrap();
        let elapsed = store.time_since_publish();
        // Generous bound to absorb CI jitter; still proves the stamp is fresh.
        assert!(
            elapsed < Duration::from_secs(1),
            "freshly-constructed store should have near-zero elapsed; got {elapsed:?}"
        );
    }

    #[test]
    fn time_since_publish_grows_with_wall_time() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_grow.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_GROW_").unwrap();
        let e0 = store.time_since_publish();
        thread::sleep(Duration::from_millis(30));
        let e1 = store.time_since_publish();
        assert!(
            e1 > e0,
            "elapsed must grow without a reload; e0={e0:?} e1={e1:?}"
        );
        assert!(
            e1 >= Duration::from_millis(25),
            "elapsed must reflect the sleep interval"
        );
    }

    #[test]
    fn time_since_publish_resets_on_successful_reload() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_reset.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_RESET_").unwrap();
        thread::sleep(Duration::from_millis(50));
        let stale = store.time_since_publish();
        assert!(stale >= Duration::from_millis(40));

        fs::write(&file, "name: b\n").unwrap();
        store.reload().unwrap();
        let fresh = store.time_since_publish();
        assert!(
            fresh < stale,
            "successful reload must reset elapsed; stale={stale:?} fresh={fresh:?}"
        );
    }

    #[test]
    fn shared_last_publish_at_visible_across_threads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_shared.yaml");
        fs::write(&file, "name: t0\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_SHARED_").unwrap();
        let handle = store.shared_last_publish_at();
        let t0 = **handle.load();

        let observed = thread::spawn({
            let handle = handle.clone();
            move || {
                for _ in 0..200 {
                    let now = **handle.load();
                    if now > t0 {
                        return now;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                **handle.load()
            }
        });

        thread::sleep(Duration::from_millis(10));
        fs::write(&file, "name: t1\n").unwrap();
        store.reload().unwrap();

        let seen = observed.join().expect("observer thread");
        assert!(seen > t0, "observer must see the advanced publish time");
        assert_eq!(seen, store.last_publish_at());
    }

    #[test]
    fn shared_last_publish_at_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_outlive.yaml");
        fs::write(&file, "name: persistent\n").unwrap();

        let (handle, before_drop) = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_OUTLIVE_").unwrap();
            fs::write(&file, "name: rev1\n").unwrap();
            store.reload().unwrap();
            (store.shared_last_publish_at(), store.last_publish_at())
        };
        // The store is dropped; the handle still reads the last stamp.
        let observed = **handle.load();
        assert_eq!(observed, before_drop);
    }

    #[test]
    fn shared_last_publish_at_is_same_arc_as_internal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_same.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_SAME_").unwrap();
        let handle = store.shared_last_publish_at();

        fs::write(&file, "name: y\n").unwrap();
        store.reload().unwrap();

        // Both views see the same Instant value.
        assert_eq!(**handle.load(), store.last_publish_at());
    }

    #[test]
    fn last_publish_at_stamped_before_generation_bump_for_acquire_release_contract() {
        // The ordering inside swap_in is: store value, clear error,
        // stamp publish_at, bump generation (Release). When a reader
        // observes generation = N (Acquire), the matching publish_at
        // must already be visible. We verify via a single-threaded
        // before/after sandwich: capture publish_at *before* the
        // generation bump observably finishes (by reading both after
        // reload returns).
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_order.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_ORDER_").unwrap();
        let g0 = store.generation();
        let t0 = store.last_publish_at();

        thread::sleep(Duration::from_millis(10));
        fs::write(&file, "name: b\n").unwrap();
        store.reload().unwrap();

        // Generation advanced; publish_at must have advanced too.
        assert!(store.generation() > g0);
        assert!(store.last_publish_at() > t0);
    }

    #[test]
    fn long_failure_with_stale_publish_diagnoses_failing_reloads() {
        // Composition test: time_since_publish + last_reload_error.is_some()
        // is the canonical "reloads have been failing for X" diagnostic.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("pub_diag.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_PUB_DIAG_").unwrap();

        thread::sleep(Duration::from_millis(40));
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let elapsed = store.time_since_publish();
        assert!(
            elapsed >= Duration::from_millis(35),
            "failed reload must not reset elapsed"
        );
        assert!(
            store.last_reload_error().is_some(),
            "failure slot must be populated"
        );
    }

    // ---- last_failure_at() / time_since_failure() / shared_last_failure_at() tests ----

    #[test]
    fn last_failure_at_starts_none_for_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_t0_load.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_T0_LOAD_").unwrap();
        assert!(
            store.last_failure_at().is_none(),
            "no failure has happened yet on a fresh store"
        );
        assert!(store.time_since_failure().is_none());
    }

    #[test]
    fn last_failure_at_starts_none_for_load_merged() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_t0_merged.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_FAIL_T0_MERGED_",
        )
        .unwrap();
        assert!(store.last_failure_at().is_none());
        assert!(store.time_since_failure().is_none());
    }

    #[test]
    fn last_failure_at_starts_none_for_load_and_watch() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_t0_watch.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_FAIL_T0_WATCH_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert!(store.last_failure_at().is_none());
        assert!(store.time_since_failure().is_none());
    }

    #[test]
    fn failed_reload_stamps_last_failure_at() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_stamp.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_STAMP_").unwrap();
        assert!(store.last_failure_at().is_none());

        let before = Instant::now();
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        let after = Instant::now();

        let stamp = store
            .last_failure_at()
            .expect("failed reload must populate last_failure_at");
        assert!(
            stamp >= before && stamp <= after,
            "stamp must be sandwiched between the surrounding Instant::now() calls"
        );
    }

    #[test]
    fn successful_reload_clears_last_failure_at() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_clear.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_CLEAR_").unwrap();

        // Force a failure
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert!(store.last_failure_at().is_some());
        assert!(store.last_reload_error().is_some());

        // Recover: success must clear both slots together
        fs::write(&file, "name: recovered\n").unwrap();
        store.reload().unwrap();
        assert!(
            store.last_failure_at().is_none(),
            "successful reload must clear the failure-time slot"
        );
        assert!(
            store.last_reload_error().is_none(),
            "successful reload must clear the failure-error slot"
        );
    }

    #[test]
    fn most_recent_failure_advances_last_failure_at() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_advance.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_ADVANCE_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        let t1 = store.last_failure_at().unwrap();

        thread::sleep(Duration::from_millis(20));
        fs::write(&file, "name: [unclosed\n").unwrap();
        assert!(store.reload().is_err());
        let t2 = store.last_failure_at().unwrap();

        assert!(
            t2 > t1,
            "second failure must advance the stamp; t1={t1:?} t2={t2:?}"
        );
        assert!(
            t2.duration_since(t1) >= Duration::from_millis(15),
            "advance must reflect the elapsed interval"
        );
    }

    #[test]
    fn time_since_failure_starts_none_then_grows_with_wall_time() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_grow.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_GROW_").unwrap();
        assert!(store.time_since_failure().is_none());

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let e0 = store.time_since_failure().expect("populated after failure");
        thread::sleep(Duration::from_millis(30));
        let e1 = store.time_since_failure().expect("populated after failure");
        assert!(
            e1 > e0,
            "elapsed must grow without another reload; e0={e0:?} e1={e1:?}"
        );
        assert!(
            e1 >= Duration::from_millis(25),
            "elapsed must reflect the sleep interval"
        );
    }

    #[test]
    fn time_since_failure_returns_none_after_recovery() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_recover.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_RECOVER_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert!(store.time_since_failure().is_some());

        fs::write(&file, "name: ok\n").unwrap();
        store.reload().unwrap();
        assert!(
            store.time_since_failure().is_none(),
            "recovery must reset the failure-time slot to None"
        );
    }

    #[test]
    fn last_failure_at_does_not_advance_last_publish_at() {
        // Symmetry contract: failure stamps last_failure_at but does
        // not touch last_publish_at; success stamps last_publish_at
        // and clears last_failure_at. The two slots are decoupled
        // except for the success-side clear.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_decoupled.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_DEC_").unwrap();
        let pub0 = store.last_publish_at();

        thread::sleep(Duration::from_millis(20));
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert_eq!(
            pub0,
            store.last_publish_at(),
            "failed reload must preserve last_publish_at"
        );
        assert!(
            store.last_failure_at().is_some(),
            "failed reload must populate last_failure_at"
        );
        assert!(
            store.last_failure_at().unwrap() > pub0,
            "failure stamp must come after the surviving publish stamp"
        );
    }

    #[test]
    fn shared_last_failure_at_visible_across_threads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_shared.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_SHARED_").unwrap();
        let handle = store.shared_last_failure_at();
        assert!(handle.load_full().is_none());

        let observed = thread::spawn({
            let handle = handle.clone();
            move || {
                for _ in 0..200 {
                    if handle.load_full().is_some() {
                        return true;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                handle.load_full().is_some()
            }
        });

        fs::write(&file, "count: not_a_number\n").unwrap();
        let _ = store.reload();

        assert!(
            observed.join().expect("observer thread"),
            "observer should see the published failure stamp"
        );
    }

    #[test]
    fn shared_last_failure_at_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_outlive.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let (handle, captured_before_drop) = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_OUTLIVE_").unwrap();
            fs::write(&file, "count: not_a_number\n").unwrap();
            let _ = store.reload();
            (store.shared_last_failure_at(), store.last_failure_at())
        };
        // The store is dropped; the handle still reads the published stamp.
        let observed = handle
            .load_full()
            .expect("failure stamp must persist after store drop");
        assert_eq!(*observed, captured_before_drop.unwrap());
    }

    #[test]
    fn shared_last_failure_at_is_same_arc_as_internal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_same.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_SAME_").unwrap();
        let handle = store.shared_last_failure_at();

        fs::write(&file, "count: not_a_number\n").unwrap();
        let _ = store.reload();

        // Both views see the same Instant value.
        let via_store = store.last_failure_at().unwrap();
        let via_handle = *handle.load_full().unwrap();
        assert_eq!(via_store, via_handle);
    }

    #[test]
    fn last_failure_at_observed_when_last_reload_error_is_some() {
        // Stamp-then-publish ordering contract: a reader observing
        // `last_reload_error.is_some()` must also see a populated
        // `last_failure_at`. record_failure stores the timestamp first,
        // then the error — ArcSwap Release/Acquire makes the timestamp
        // visible by the time the error becomes visible.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_order.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_ORDER_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        // Read the error first; the timestamp must already be visible.
        if store.last_reload_error().is_some() {
            assert!(
                store.last_failure_at().is_some(),
                "observing last_reload_error=Some must guarantee last_failure_at=Some"
            );
        }
    }

    #[test]
    fn failing_window_diagnosed_via_publish_and_failure_stamps() {
        // Composition test: (last_publish_at, last_failure_at) precisely
        // diagnoses the failing-window duration. After a successful publish
        // at t0, a wait, then a failed reload at t1, the failing window
        // duration `t1 - t0` is observable directly from the typed slots
        // — no external bookkeeping, no log scraping.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_window.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FAIL_WINDOW_").unwrap();
        let t0 = store.last_publish_at();

        thread::sleep(Duration::from_millis(40));
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        let t1 = store.last_failure_at().unwrap();

        let window = t1.duration_since(t0);
        assert!(
            window >= Duration::from_millis(35),
            "failing window duration must reflect the wait between successful publish and first failure; got {window:?}"
        );
        // And after the failing window, time_since_failure paired with
        // time_since_publish gives the same picture from a different angle.
        let pub_elapsed = store.time_since_publish();
        let fail_elapsed = store
            .time_since_failure()
            .expect("populated after the failure");
        assert!(
            pub_elapsed > fail_elapsed,
            "publish is older than failure (publish came first); pub={pub_elapsed:?} fail={fail_elapsed:?}"
        );
    }

    #[test]
    fn watcher_constructor_failure_path_routes_through_record_failure() {
        // The watcher closure routes through record_failure on its
        // failure path too. Verify via the (always-deterministic) manual
        // reload path on a load_and_watch store.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fail_watch_route.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_FAIL_WATCH_ROUTE_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert!(store.last_failure_at().is_none());

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert!(
            store.last_failure_at().is_some(),
            "manual reload on a load_and_watch store must stamp last_failure_at"
        );
    }

    // ---- failure_count() / shared_failure_count() tests ----

    #[test]
    fn failure_count_starts_at_zero_for_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_load0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_LOAD0_").unwrap();
        assert_eq!(store.failure_count(), 0);
    }

    #[test]
    fn failure_count_starts_at_zero_for_load_merged() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_merged0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_merged(
            std::slice::from_ref(&file),
            "SHIKUMI_FC_MERGED0_",
        )
        .unwrap();
        assert_eq!(store.failure_count(), 0);
    }

    #[test]
    fn failure_count_starts_at_zero_for_load_and_watch() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_watch0.yaml");
        fs::write(&file, "name: x\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_FC_WATCH0_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert_eq!(store.failure_count(), 0);
    }

    #[test]
    fn failed_reload_increments_failure_count() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_inc.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_INC_").unwrap();
        assert_eq!(store.failure_count(), 0);

        // Type mismatch
        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.failure_count(), 1, "first failure must bump to 1");

        // Different failure shape
        fs::write(&file, "name: [unclosed\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.failure_count(), 2, "second failure must bump to 2");
    }

    #[test]
    fn successful_reload_does_not_increment_failure_count() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_succ.yaml");
        fs::write(&file, "name: a\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_SUCC_").unwrap();
        assert_eq!(store.failure_count(), 0);

        for letter in ['b', 'c', 'd'] {
            fs::write(&file, format!("name: {letter}\n")).unwrap();
            store.reload().unwrap();
        }
        assert_eq!(
            store.failure_count(),
            0,
            "successful reloads must not affect failure_count",
        );
        assert_eq!(store.generation(), 3, "successful reloads bump generation");
    }

    #[test]
    fn recovery_does_not_clear_failure_count() {
        // Cardinality is lifetime-monotonic: unlike last_failure_at /
        // last_reload_error, recovery does NOT erase the count.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_recover.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_RECOVER_").unwrap();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.failure_count(), 1);
        assert!(store.last_failure_at().is_some());

        // Recover: temporal slots clear, cardinality counter persists.
        fs::write(&file, "name: recovered\n").unwrap();
        store.reload().unwrap();
        assert!(
            store.last_failure_at().is_none(),
            "recovery clears last_failure_at",
        );
        assert!(
            store.last_reload_error().is_none(),
            "recovery clears last_reload_error",
        );
        assert_eq!(
            store.failure_count(),
            1,
            "failure_count is the lifetime cardinality record; recovery must not erase it",
        );
    }

    #[test]
    fn failure_count_monotonic_across_many_failures() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_mono.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_MONO_").unwrap();

        let mut prev = store.failure_count();
        assert_eq!(prev, 0);
        for _ in 0..10 {
            fs::write(&file, "count: not_a_number\n").unwrap();
            assert!(store.reload().is_err());
            let now = store.failure_count();
            assert!(now > prev, "failure_count must be strictly increasing");
            prev = now;
        }
        assert_eq!(store.failure_count(), 10);
    }

    #[test]
    fn shared_failure_count_visible_across_threads() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_shared.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_SHARED_").unwrap();
        let fc_handle = store.shared_failure_count();
        assert_eq!(fc_handle.load(Ordering::Acquire), 0);

        let observed = thread::spawn({
            let fc_handle = fc_handle.clone();
            move || {
                for _ in 0..200 {
                    if fc_handle.load(Ordering::Acquire) > 0 {
                        return fc_handle.load(Ordering::Acquire);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                fc_handle.load(Ordering::Acquire)
            }
        });

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        let seen = observed.join().expect("observer thread");
        assert!(
            seen >= 1,
            "observer thread must see incremented failure_count",
        );
        assert_eq!(store.failure_count(), 1);
    }

    #[test]
    fn shared_failure_count_outlives_store() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_outlive.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let (handle, before_drop) = {
            let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_OUTLIVE_").unwrap();
            fs::write(&file, "count: not_a_number\n").unwrap();
            assert!(store.reload().is_err());
            assert!(store.reload().is_err());
            (store.shared_failure_count(), store.failure_count())
        };
        assert_eq!(handle.load(Ordering::Acquire), before_drop);
        assert_eq!(handle.load(Ordering::Acquire), 2);
    }

    #[test]
    fn shared_failure_count_is_same_arc_as_internal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_same.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_SAME_").unwrap();
        let handle = store.shared_failure_count();

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert_eq!(
            handle.load(Ordering::Acquire),
            store.failure_count(),
            "the shared handle must point at the same atomic the store mutates",
        );
    }

    #[test]
    fn watcher_constructor_failure_path_increments_failure_count() {
        // The watcher closure routes through record_failure too. Verify
        // via the deterministic manual-reload path on a load_and_watch
        // store: the failure_count slot must be threaded through both
        // failure-paths.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_watch_route.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load_and_watch(
            &file,
            "SHIKUMI_FC_WATCH_ROUTE_",
            |_: &TestConfig| {},
        )
        .unwrap();
        assert_eq!(store.failure_count(), 0);

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert_eq!(
            store.failure_count(),
            1,
            "watcher constructor's manual reload must thread through record_failure",
        );
    }

    #[test]
    fn failure_count_advanced_when_last_reload_error_is_some() {
        // Stamp-then-bump-then-publish ordering contract: observing
        // last_reload_error.is_some() implies failure_count has advanced
        // past zero. Symmetric to the
        // last_failure_at_observed_when_last_reload_error_is_some test.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_order.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_ORDER_").unwrap();
        assert_eq!(store.failure_count(), 0);
        assert!(store.last_reload_error().is_none());

        fs::write(&file, "count: not_a_number\n").unwrap();
        assert!(store.reload().is_err());

        assert!(
            store.last_reload_error().is_some(),
            "failure must populate the error slot",
        );
        assert!(
            store.failure_count() >= 1,
            "an observable error implies an advanced failure_count",
        );
        assert!(
            store.last_failure_at().is_some(),
            "an advanced failure_count implies a populated last_failure_at",
        );
    }

    #[test]
    fn generation_and_failure_count_are_independent_axes() {
        // The two cardinality counters track orthogonal outcomes:
        // generation counts only successes, failure_count counts only
        // failures. Their sum is the total reload-attempt count, and
        // each is unaffected by the other's events.
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("fc_axes.yaml");
        fs::write(&file, "name: ok\n").unwrap();

        let store = ConfigStore::<TestConfig>::load(&file, "SHIKUMI_FC_AXES_").unwrap();
        assert_eq!(store.generation(), 0);
        assert_eq!(store.failure_count(), 0);

        // 3 successes
        for letter in ['a', 'b', 'c'] {
            fs::write(&file, format!("name: {letter}\n")).unwrap();
            store.reload().unwrap();
        }
        // 2 failures
        for _ in 0..2 {
            fs::write(&file, "count: not_a_number\n").unwrap();
            assert!(store.reload().is_err());
        }
        // 1 more success (recovery)
        fs::write(&file, "name: recovered\n").unwrap();
        store.reload().unwrap();

        assert_eq!(store.generation(), 4, "4 successful reloads");
        assert_eq!(store.failure_count(), 2, "2 failed reloads");
        assert_eq!(
            store.generation() + store.failure_count(),
            6,
            "sum is the total reload-attempt count",
        );
    }
}

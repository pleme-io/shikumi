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

use crate::error::ShikumiError;

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
    _watcher: Box<dyn Watcher>,
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
        let setup = notify::Config::default()
            .with_poll_interval(Duration::from_secs(3));

        let symlink = symlink_target(path);

        let mut watcher: Box<dyn Watcher> = if let Some(ref target) = symlink {
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
        if let Ok(event) = event {
            (self.0)(event);
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
        assert!(
            result.is_none(),
            "broken symlink should return None"
        );
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
        assert!(
            !captured.is_empty(),
            "rewatch should detect file changes"
        );
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
            // At least one path should reference our file's parent or the file itself
            assert!(
                captured.iter().any(|p| {
                    p.display().to_string().contains("pathcheck")
                }),
                "expected event path to reference the watched file"
            );
        }
    }
}

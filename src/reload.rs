//! Observable reload failure summary.
//!
//! [`ReloadFailure`] is the typed, [`Clone`]-able shape that
//! [`crate::ConfigStore`] publishes when a reload — manual
//! ([`crate::ConfigStore::reload`]) or hot-reload (the watcher in
//! [`crate::ConfigStore::load_and_watch`]) — fails. The slot is cleared
//! atomically when a subsequent reload succeeds, so observers get a
//! "most recent unrecovered failure" hint, not a history.
//!
//! [`crate::ShikumiError`] itself is not [`Clone`] (it boxes
//! `figment::Error`, which is not Clone). `ReloadFailure` is the
//! cross-thread observable form: a typed value that captures the
//! display string and the [`crate::ConfigSource`] chain at the moment
//! the failure was caught.

use std::fmt;

use crate::error::ShikumiError;
use crate::source::ConfigSource;

/// A clone-able summary of the most recent reload failure on a
/// [`crate::ConfigStore`].
///
/// Pairs with [`crate::ConfigStore::generation`]: when an observer sees
/// the generation has not advanced past a checkpoint and a
/// [`ReloadFailure`] is present, the failure is the reason the
/// expected publish did not happen.
///
/// `#[non_exhaustive]` so future fidelity work (per-field path,
/// file/line spans, source provenance for non-`Extract` variants)
/// lands additively.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReloadFailure {
    /// Human-readable display of the underlying error, captured via
    /// [`std::fmt::Display`] at the moment the failure was caught.
    pub message: String,
    /// Provider chain in merge order at the moment of failure.
    /// Populated for [`crate::ShikumiError::Extract`]; empty for
    /// variants that do not record a chain (see
    /// [`crate::ShikumiError::sources`]).
    pub sources: Vec<ConfigSource>,
}

impl ReloadFailure {
    /// Capture a [`ReloadFailure`] from a [`ShikumiError`] reference.
    ///
    /// The error itself is not consumed — only its display string and
    /// recorded source chain (if any) are copied. This is the one
    /// canonical constructor; both [`crate::ConfigStore::reload`] and
    /// the [`crate::ConfigStore::load_and_watch`] watcher closure use
    /// it on the failure path.
    #[must_use]
    pub fn from_error(err: &ShikumiError) -> Self {
        Self {
            message: err.to_string(),
            sources: err.sources().map(<[_]>::to_vec).unwrap_or_default(),
        }
    }
}

impl fmt::Display for ReloadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_figment_error() -> Box<figment::Error> {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        Box::new(result.unwrap_err())
    }

    #[test]
    fn from_error_captures_display_message() {
        let err = ShikumiError::Parse("oops".to_owned());
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.message, err.to_string());
        assert!(f.message.contains("oops"));
    }

    #[test]
    fn from_error_captures_sources_for_extract_variant() {
        let chain = vec![
            ConfigSource::Env("APP_".to_owned()),
            ConfigSource::File(PathBuf::from("/etc/app.yaml")),
        ];
        let err = ShikumiError::Extract {
            sources: chain.clone(),
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.sources, chain);
    }

    #[test]
    fn from_error_yields_empty_sources_for_non_extract_variant() {
        let err = ShikumiError::Parse("x".to_owned());
        let f = ReloadFailure::from_error(&err);
        assert!(f.sources.is_empty());
    }

    #[test]
    fn from_error_yields_empty_sources_for_figment_variant() {
        let err = ShikumiError::Figment(fake_figment_error());
        let f = ReloadFailure::from_error(&err);
        assert!(f.sources.is_empty());
    }

    #[test]
    fn display_renders_message() {
        let f = ReloadFailure {
            message: "broken pipe".to_owned(),
            sources: vec![],
        };
        assert_eq!(f.to_string(), "broken pipe");
    }

    #[test]
    fn clone_preserves_data() {
        let f = ReloadFailure {
            message: "bad".to_owned(),
            sources: vec![ConfigSource::Defaults],
        };
        let g = f.clone();
        assert_eq!(g.message, f.message);
        assert_eq!(g.sources, f.sources);
    }

    #[test]
    fn from_error_does_not_consume_source() {
        let err = ShikumiError::Parse("keepable".to_owned());
        let _f = ReloadFailure::from_error(&err);
        // err still usable
        assert!(err.is_parse());
    }

    #[test]
    fn from_error_carries_path_provenance() {
        let path = PathBuf::from("/srv/cfg/app.yaml");
        let err = ShikumiError::Extract {
            sources: vec![ConfigSource::File(path.clone())],
            error: fake_figment_error(),
        };
        let f = ReloadFailure::from_error(&err);
        assert_eq!(f.sources.len(), 1);
        assert_eq!(f.sources[0].as_path(), Some(path.as_path()));
    }
}

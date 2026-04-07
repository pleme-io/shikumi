use std::path::PathBuf;

/// Errors produced by shikumi's config discovery, loading, and watching.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ShikumiError {
    /// No config file was found at any of the searched locations.
    #[error("config file not found; tried: {}", tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    NotFound { tried: Vec<PathBuf> },

    /// The config file could not be parsed.
    #[error("config parse error: {0}")]
    Parse(String),

    /// The file watcher encountered an error.
    #[error("file watch error: {0}")]
    Watch(#[from] notify::Error),

    /// An I/O error occurred during config file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Figment extraction or merge failed.
    ///
    /// Boxed to keep `ShikumiError` small (`figment::Error` is ~208 bytes).
    #[error("figment error: {0}")]
    Figment(#[from] Box<figment::Error>),
}

impl ShikumiError {
    /// Returns `true` if this is a `NotFound` error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if this is a `Parse` error.
    #[must_use]
    pub fn is_parse(&self) -> bool {
        matches!(self, Self::Parse(_))
    }

    /// Returns the list of paths that were tried, if this is a `NotFound` error.
    #[must_use]
    pub fn tried_paths(&self) -> Option<&[PathBuf]> {
        match self {
            Self::NotFound { tried } => Some(tried),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display_lists_paths() {
        let err = ShikumiError::NotFound {
            tried: vec![
                PathBuf::from("/a/b.yaml"),
                PathBuf::from("/c/d.toml"),
            ],
        };
        let msg = err.to_string();
        assert!(msg.contains("/a/b.yaml"), "error should list first path");
        assert!(msg.contains("/c/d.toml"), "error should list second path");
        assert!(msg.contains(", "), "paths should be comma-separated");
    }

    #[test]
    fn not_found_empty_tried() {
        let err = ShikumiError::NotFound { tried: vec![] };
        let msg = err.to_string();
        assert!(msg.contains("config file not found"));
    }

    #[test]
    fn parse_error_display() {
        let err = ShikumiError::Parse("unexpected token".to_owned());
        let msg = err.to_string();
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn figment_error_from_conversion() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();

        let shikumi_err: ShikumiError = Box::new(figment_err).into();
        assert!(
            matches!(shikumi_err, ShikumiError::Figment(_)),
            "expected Figment variant"
        );
        let msg = shikumi_err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn is_not_found_helper() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/a")],
        };
        assert!(err.is_not_found());
        assert!(!err.is_parse());
    }

    #[test]
    fn is_parse_helper() {
        let err = ShikumiError::Parse("bad".to_owned());
        assert!(err.is_parse());
        assert!(!err.is_not_found());
    }

    #[test]
    fn tried_paths_returns_paths_for_not_found() {
        let paths = vec![PathBuf::from("/x"), PathBuf::from("/y")];
        let err = ShikumiError::NotFound {
            tried: paths.clone(),
        };
        assert_eq!(err.tried_paths(), Some(paths.as_slice()));

        let parse_err = ShikumiError::Parse("bad".to_owned());
        assert_eq!(parse_err.tried_paths(), None);
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let shikumi_err: ShikumiError = io_err.into();
        assert!(matches!(shikumi_err, ShikumiError::Io(_)));
        assert!(shikumi_err.to_string().contains("file gone"));
    }

    #[test]
    fn error_is_debug_printable() {
        let err = ShikumiError::Parse("test".to_owned());
        let debug = format!("{err:?}");
        assert!(debug.contains("Parse"));
    }

    #[test]
    fn watch_error_from_conversion() {
        let notify_err = notify::Error::generic("test watcher error");
        let shikumi_err: ShikumiError = notify_err.into();
        assert!(
            matches!(shikumi_err, ShikumiError::Watch(_)),
            "expected Watch variant"
        );
        let msg = shikumi_err.to_string();
        assert!(msg.contains("test watcher error"));
    }

    #[test]
    fn watch_error_display() {
        let notify_err = notify::Error::generic("poll failed");
        let err: ShikumiError = notify_err.into();
        let msg = err.to_string();
        assert!(msg.contains("file watch error"));
        assert!(msg.contains("poll failed"));
    }

    #[test]
    fn figment_error_display_contains_context() {
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();
        let err: ShikumiError = Box::new(figment_err).into();
        let msg = err.to_string();
        assert!(msg.contains("figment error"), "should have figment prefix");
    }

    #[test]
    fn error_source_chain() {
        use std::error::Error;

        let notify_err = notify::Error::generic("test");
        let err: ShikumiError = notify_err.into();
        assert!(err.source().is_some(), "Watch variant should have a source");

        let parse_err = ShikumiError::Parse("test".to_owned());
        assert!(
            parse_err.source().is_none(),
            "Parse variant should not have a source"
        );
    }

    #[test]
    fn not_found_single_path() {
        let err = ShikumiError::NotFound {
            tried: vec![PathBuf::from("/only/one.yaml")],
        };
        let msg = err.to_string();
        assert!(msg.contains("/only/one.yaml"));
        assert!(!msg.contains(", "), "single path should have no comma");
    }
}

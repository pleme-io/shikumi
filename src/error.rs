use std::path::PathBuf;

/// Errors produced by shikumi's config discovery, loading, and watching.
#[derive(thiserror::Error, Debug)]
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

    /// Figment extraction or merge failed.
    ///
    /// Boxed to keep `ShikumiError` small (`figment::Error` is ~208 bytes).
    #[error("figment error: {0}")]
    Figment(#[from] Box<figment::Error>),
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
    fn error_is_debug_printable() {
        let err = ShikumiError::Parse("test".to_owned());
        let debug = format!("{err:?}");
        assert!(debug.contains("Parse"));
    }
}

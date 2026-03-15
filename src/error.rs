use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum ShikumiError {
    #[error("config file not found; tried: {}", tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    NotFound { tried: Vec<PathBuf> },

    #[error("config parse error: {0}")]
    Parse(String),

    #[error("file watch error: {0}")]
    Watch(#[from] notify::Error),

    #[error("figment error: {0}")]
    Figment(#[from] figment::Error),
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
        // Create a figment error by extracting a missing required field
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();

        let shikumi_err: ShikumiError = figment_err.into();
        assert!(
            matches!(shikumi_err, ShikumiError::Figment(_)),
            "expected Figment variant"
        );
        // Should have a meaningful display message
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

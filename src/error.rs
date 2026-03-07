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

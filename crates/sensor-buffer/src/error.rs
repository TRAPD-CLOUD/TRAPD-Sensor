use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("buffer io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("record of {0} bytes exceeds the maximum record size")]
    RecordTooLarge(usize),

    #[error("failed to encode event: {0}")]
    Encode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BufferError>;

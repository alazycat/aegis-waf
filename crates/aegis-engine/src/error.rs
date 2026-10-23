use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{file}:{line}:{column}: {message}")]
    Parse {
        file: PathBuf,
        line: usize,
        column: usize,
        message: String,
    },
    #[error("{file}:{line}:{column}: {message}")]
    Compile {
        file: PathBuf,
        line: usize,
        column: usize,
        message: String,
    },
    #[error("failed to read {file}: {source}")]
    Io {
        file: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{file}:{line}: Include pattern {pattern} matched no files")]
    IncludeNoMatch {
        file: PathBuf,
        line: usize,
        pattern: String,
    },
    #[error("{file}:{line}: invalid Include glob: {message}")]
    IncludeGlob {
        file: PathBuf,
        line: usize,
        message: String,
    },
    #[error("Include depth exceeded while loading {0}")]
    IncludeDepth(PathBuf),
    #[error("Include cycle detected at {0}")]
    IncludeCycle(PathBuf),
    #[error("failed to build rule prefilter: {0}")]
    Prefilter(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EngineError {
    #[error("internal engine error: {0}")]
    Internal(String),
}

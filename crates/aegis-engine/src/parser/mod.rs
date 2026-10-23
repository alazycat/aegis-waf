pub mod args;
pub mod directive;
pub mod scanner;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::LoadError;

pub use directive::Directive;

pub const MAX_INCLUDE_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct LocatedDirective {
    pub file: PathBuf,
    pub directive: Directive,
}

pub fn parse_files(files: &[PathBuf]) -> Result<Vec<LocatedDirective>, LoadError> {
    let mut output = Vec::new();
    for file in files {
        let mut visited = HashSet::new();
        parse_one(file, 0, &mut visited, &mut output)?;
    }
    Ok(output)
}

fn parse_one(
    path: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    output: &mut Vec<LocatedDirective>,
) -> Result<(), LoadError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(LoadError::IncludeDepth(path.to_path_buf()));
    }
    let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(identity) {
        return Err(LoadError::IncludeCycle(path.to_path_buf()));
    }

    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        file: path.to_path_buf(),
        source,
    })?;

    for logical in scanner::split_logical_lines(&text) {
        match directive::parse_directive(&logical) {
            Ok(Directive::Include(pattern)) => {
                let base = path.parent().unwrap_or_else(|| Path::new("."));
                let pattern_path = base.join(&pattern);
                let pattern_text = pattern_path.to_string_lossy().replace('\\', "/");
                let entries =
                    glob::glob(&pattern_text).map_err(|error| LoadError::IncludeGlob {
                        file: path.to_path_buf(),
                        line: logical.line,
                        message: error.to_string(),
                    })?;
                let mut included = Vec::new();
                for entry in entries {
                    let entry = entry.map_err(|error| LoadError::IncludeGlob {
                        file: path.to_path_buf(),
                        line: logical.line,
                        message: error.to_string(),
                    })?;
                    if entry.is_file() {
                        included.push(entry);
                    }
                }
                if included.is_empty() {
                    return Err(LoadError::IncludeNoMatch {
                        file: path.to_path_buf(),
                        line: logical.line,
                        pattern,
                    });
                }
                included.sort();
                for entry in included {
                    parse_one(&entry, depth + 1, visited, output)?;
                }
            }
            Ok(directive) => output.push(LocatedDirective {
                file: path.to_path_buf(),
                directive,
            }),
            Err(error) => {
                return Err(LoadError::Parse {
                    file: path.to_path_buf(),
                    line: error.line,
                    column: error.column,
                    message: error.message,
                });
            }
        }
    }
    Ok(())
}

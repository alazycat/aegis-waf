use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub upstream: UpstreamConfig,
    pub admin: AdminConfig,
    pub rules: RulesConfig,
    pub limits: LimitsConfig,
    #[serde(default)]
    pub on_error: OnError,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub url: String,
    #[serde(default)]
    pub host_header: HostHeader,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub listen: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    pub files: Vec<String>,
    #[serde(default)]
    pub lenient: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_max_uri_bytes")]
    pub max_uri_bytes: usize,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    #[serde(default = "default_body_read_timeout_ms")]
    pub body_read_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub sink: AuditSink,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub mode: AuditMode,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default)]
    pub include_query: bool,
    #[serde(default = "default_matched_rules_limit")]
    pub matched_rules_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostHeader {
    #[default]
    Preserve,
    Rewrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    #[default]
    Block,
    Pass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSink {
    File,
    Stdout,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    #[default]
    BlockedOnly,
    All,
}

fn default_connect_timeout_ms() -> u64 {
    3000
}

fn default_total_timeout_ms() -> u64 {
    30000
}

fn default_max_header_bytes() -> usize {
    65536
}

fn default_max_uri_bytes() -> usize {
    8192
}

fn default_max_body_bytes() -> usize {
    1048576
}

fn default_header_read_timeout_ms() -> u64 {
    10000
}

fn default_body_read_timeout_ms() -> u64 {
    15000
}

fn default_queue_capacity() -> usize {
    8192
}

fn default_matched_rules_limit() -> usize {
    16
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid listen address {value}: {source}")]
    InvalidListen {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("invalid admin listen address {value}: {source}")]
    InvalidAdminListen {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("invalid upstream URL {value}: {reason}")]
    InvalidUpstream { value: String, reason: String },
    #[error("upstream URL must use http scheme: {0}")]
    UpstreamScheme(String),
    #[error("upstream URL must not contain a path, query, or fragment: {0}")]
    UpstreamPathUnsupported(String),
    #[error("admin listener {0} is not loopback and admin.token is not set")]
    AdminTokenRequired(String),
    #[error("admin.token must not be empty")]
    EmptyAdminToken,
    #[error("rules.files must not be empty")]
    EmptyRuleFiles,
    #[error("no rule files matched pattern {0}")]
    NoRuleFiles(String),
    #[error("invalid glob pattern {pattern}: {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },
    #[error("failed to read glob entry for {pattern}: {source}")]
    GlobEntry {
        pattern: String,
        #[source]
        source: glob::GlobError,
    },
    #[error("audit.path is required when audit.sink = file")]
    AuditPathRequired,
    #[error("{field} must be greater than zero")]
    ZeroValue { field: &'static str },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_yaml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn validate(&self) -> Result<Vec<PathBuf>, ConfigError> {
        self.listen
            .parse::<SocketAddr>()
            .map_err(|source| ConfigError::InvalidListen {
                value: self.listen.clone(),
                source,
            })?;

        let admin_addr = self.admin.listen.parse::<SocketAddr>().map_err(|source| {
            ConfigError::InvalidAdminListen {
                value: self.admin.listen.clone(),
                source,
            }
        })?;
        match self.admin.token.as_deref() {
            Some("") => return Err(ConfigError::EmptyAdminToken),
            Some(_) => {}
            None if !admin_addr.ip().is_loopback() => {
                return Err(ConfigError::AdminTokenRequired(self.admin.listen.clone()));
            }
            None => {}
        }

        let uri: http::Uri =
            self.upstream
                .url
                .parse()
                .map_err(
                    |source: http::uri::InvalidUri| ConfigError::InvalidUpstream {
                        value: self.upstream.url.clone(),
                        reason: source.to_string(),
                    },
                )?;
        if uri.scheme_str() != Some("http") {
            return Err(ConfigError::UpstreamScheme(self.upstream.url.clone()));
        }
        if uri.authority().is_none() {
            return Err(ConfigError::InvalidUpstream {
                value: self.upstream.url.clone(),
                reason: "missing authority".to_string(),
            });
        }
        if uri.query().is_some() {
            return Err(ConfigError::UpstreamPathUnsupported(
                self.upstream.url.clone(),
            ));
        }
        if !matches!(uri.path(), "" | "/") {
            return Err(ConfigError::UpstreamPathUnsupported(
                self.upstream.url.clone(),
            ));
        }

        if self.rules.files.is_empty() {
            return Err(ConfigError::EmptyRuleFiles);
        }
        for (field, value) in [
            ("limits.max_header_bytes", self.limits.max_header_bytes),
            ("limits.max_uri_bytes", self.limits.max_uri_bytes),
            ("limits.max_body_bytes", self.limits.max_body_bytes),
            (
                "limits.header_read_timeout_ms",
                self.limits.header_read_timeout_ms as usize,
            ),
            (
                "limits.body_read_timeout_ms",
                self.limits.body_read_timeout_ms as usize,
            ),
            ("audit.queue_capacity", self.audit.queue_capacity),
            ("audit.matched_rules_limit", self.audit.matched_rules_limit),
        ] {
            if value == 0 {
                return Err(ConfigError::ZeroValue { field });
            }
        }
        if self.audit.sink == AuditSink::File && self.audit.path.as_deref().unwrap_or("").is_empty()
        {
            return Err(ConfigError::AuditPathRequired);
        }

        resolve_rule_files(&self.rules.files)
    }
}

pub fn resolve_rule_files(patterns: &[String]) -> Result<Vec<PathBuf>, ConfigError> {
    if patterns.is_empty() {
        return Err(ConfigError::EmptyRuleFiles);
    }
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pattern in patterns {
        let entries = glob::glob(pattern).map_err(|source| ConfigError::InvalidGlob {
            pattern: pattern.clone(),
            source,
        })?;
        let mut pattern_files = Vec::new();
        for entry in entries {
            let path = entry.map_err(|source| ConfigError::GlobEntry {
                pattern: pattern.clone(),
                source,
            })?;
            if path.is_file() {
                pattern_files.push(path);
            }
        }
        if pattern_files.is_empty() {
            return Err(ConfigError::NoRuleFiles(pattern.clone()));
        }
        pattern_files.sort();
        for path in pattern_files {
            if seen.insert(path.clone()) {
                files.push(path);
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    const FULL_CONFIG: &str = r#"
listen: "0.0.0.0:8080"
upstream:
  url: "http://127.0.0.1:3000"
  host_header: preserve
  connect_timeout_ms: 3000
  total_timeout_ms: 30000
admin:
  listen: "127.0.0.1:9001"
  token: null
rules:
  files: ["rules/*.conf"]
  lenient: false
limits:
  max_header_bytes: 65536
  max_uri_bytes: 8192
  max_body_bytes: 1048576
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000
on_error: block
audit:
  sink: file
  path: "logs/audit.jsonl"
  mode: blocked_only
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 16
"#;

    fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, contents).unwrap();
        (dir, path)
    }

    fn rule_dir() -> (tempfile::TempDir, String) {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.conf"), "").unwrap();
        let pattern = format!(
            "{}/*.conf",
            dir.path().display().to_string().replace('\\', "/")
        );
        (dir, pattern)
    }

    #[test]
    fn parses_full_config() {
        let (_dir, path) = write_config(FULL_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.upstream.url, "http://127.0.0.1:3000");
        assert_eq!(config.limits.max_body_bytes, 1048576);
        assert_eq!(config.audit.mode, AuditMode::BlockedOnly);
    }

    #[test]
    fn applies_defaults_for_optional_fields() {
        let yaml = r#"
listen: "127.0.0.1:8080"
upstream:
  url: "http://127.0.0.1:3000"
admin:
  listen: "127.0.0.1:9001"
rules:
  files: ["rules/*.conf"]
limits: {}
audit:
  sink: none
"#;
        let (_dir, path) = write_config(yaml);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.upstream.host_header, HostHeader::Preserve);
        assert_eq!(config.upstream.connect_timeout_ms, 3000);
        assert_eq!(config.limits.max_body_bytes, 1048576);
        assert_eq!(config.on_error, OnError::Block);
        assert_eq!(config.audit.mode, AuditMode::BlockedOnly);
        assert_eq!(config.audit.queue_capacity, 8192);
    }

    #[test]
    fn rejects_unknown_fields() {
        let yaml = FULL_CONFIG.replace("on_error: block", "on_error: block\nunknown_field: 1");
        let (_dir, path) = write_config(&yaml);
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn rejects_non_loopback_admin_without_token() {
        let (_rules_dir, pattern) = rule_dir();
        let yaml = FULL_CONFIG
            .replace("127.0.0.1:9001", "0.0.0.0:9001")
            .replace("rules/*.conf", &pattern);
        let (_dir, path) = write_config(&yaml);
        let config = Config::load(&path).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::AdminTokenRequired(_))
        ));
    }

    #[test]
    fn accepts_non_loopback_admin_with_token() {
        let (_rules_dir, pattern) = rule_dir();
        let yaml = FULL_CONFIG
            .replace("127.0.0.1:9001", "0.0.0.0:9001")
            .replace("token: null", "token: secret")
            .replace("rules/*.conf", &pattern);
        let (_dir, path) = write_config(&yaml);
        let config = Config::load(&path).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_non_http_upstream() {
        let (_rules_dir, pattern) = rule_dir();
        let yaml = FULL_CONFIG
            .replace("http://127.0.0.1:3000", "https://127.0.0.1:3000")
            .replace("rules/*.conf", &pattern);
        let (_dir, path) = write_config(&yaml);
        let config = Config::load(&path).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UpstreamScheme(_))
        ));
    }

    #[test]
    fn resolves_glob_rule_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.conf"), "").unwrap();
        fs::write(dir.path().join("b.conf"), "").unwrap();
        let pattern = format!(
            "{}/*.conf",
            dir.path().display().to_string().replace('\\', "/")
        );
        let files = resolve_rule_files(&[pattern]).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn rejects_pattern_with_no_matches() {
        let dir = tempdir().unwrap();
        let pattern = format!(
            "{}/*.conf",
            dir.path().display().to_string().replace('\\', "/")
        );
        assert!(matches!(
            resolve_rule_files(&[pattern]),
            Err(ConfigError::NoRuleFiles(_))
        ));
    }

    #[test]
    fn preserves_explicit_pattern_order() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.conf"), "").unwrap();
        fs::write(dir.path().join("b.conf"), "").unwrap();
        let base = dir.path().display().to_string().replace('\\', "/");
        let files =
            resolve_rule_files(&[format!("{base}/b.conf"), format!("{base}/a.conf")]).unwrap();
        assert_eq!(
            files[0].file_name().and_then(|name| name.to_str()),
            Some("b.conf")
        );
        assert_eq!(
            files[1].file_name().and_then(|name| name.to_str()),
            Some("a.conf")
        );
    }
}

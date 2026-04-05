//! Typed configuration for Polaris loaded from TOML.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolarisConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub resolver: ResolverConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub readiness: ReadinessConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl PolarisConfig {
    /// Loads and parses a TOML configuration file from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Internal bind address for the HTTP server.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolverConfig {
    /// Root hints file path. Polaris fails startup if this file is missing or empty.
    #[serde(default = "default_root_hints_path")]
    pub root_hints_path: PathBuf,
    /// Optional DNSSEC trust anchor file override.
    #[serde(default)]
    pub trust_anchor_path: Option<PathBuf>,
    #[serde(default = "default_ns_cache_size")]
    pub ns_cache_size: usize,
    #[serde(default = "default_record_cache_size")]
    pub record_cache_size: usize,
    #[serde(default = "default_recursion_limit")]
    pub recursion_limit: u8,
    #[serde(default = "default_ns_recursion_limit")]
    pub ns_recursion_limit: u8,
    #[serde(default = "default_resolve_timeout_ms")]
    pub resolve_timeout_ms: u64,
    #[serde(default)]
    pub nameserver_allow_cidrs: Vec<String>,
    #[serde(default)]
    pub nameserver_deny_cidrs: Vec<String>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            root_hints_path: default_root_hints_path(),
            trust_anchor_path: None,
            ns_cache_size: default_ns_cache_size(),
            record_cache_size: default_record_cache_size(),
            recursion_limit: default_recursion_limit(),
            ns_recursion_limit: default_ns_recursion_limit(),
            resolve_timeout_ms: default_resolve_timeout_ms(),
            nameserver_allow_cidrs: Vec::new(),
            nameserver_deny_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    #[serde(default)]
    pub exact_allow: Vec<String>,
    #[serde(default)]
    pub exact_block: Vec<String>,
    #[serde(default)]
    pub suffix_allow: Vec<String>,
    #[serde(default)]
    pub suffix_block: Vec<String>,
    #[serde(default)]
    pub block_mode: BlockMode,
    #[serde(default = "default_sinkhole_ipv4")]
    pub sinkhole_ipv4: String,
    #[serde(default = "default_sinkhole_ipv6")]
    pub sinkhole_ipv6: String,
    #[serde(default = "default_sinkhole_ttl")]
    pub sinkhole_ttl: u32,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            exact_allow: Vec::new(),
            exact_block: Vec::new(),
            suffix_allow: Vec::new(),
            suffix_block: Vec::new(),
            block_mode: BlockMode::NxDomain,
            sinkhole_ipv4: default_sinkhole_ipv4(),
            sinkhole_ipv6: default_sinkhole_ipv6(),
            sinkhole_ttl: default_sinkhole_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// Synthesize NXDOMAIN for blocked names.
    #[default]
    NxDomain,
    /// Synthesize sinkhole A/AAAA records for blocked names.
    Sinkhole,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_post_body_bytes")]
    pub max_post_body_bytes: usize,
    #[serde(default = "default_max_get_dns_param_bytes")]
    pub max_get_dns_param_bytes: usize,
    #[serde(default = "default_max_dns_wire_bytes")]
    pub max_dns_wire_bytes: usize,
    #[serde(default = "default_max_json_name_bytes")]
    pub max_json_name_bytes: usize,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_http_request_timeout_ms")]
    pub http_request_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_post_body_bytes: default_max_post_body_bytes(),
            max_get_dns_param_bytes: default_max_get_dns_param_bytes(),
            max_dns_wire_bytes: default_max_dns_wire_bytes(),
            max_json_name_bytes: default_max_json_name_bytes(),
            max_concurrent_requests: default_max_concurrent_requests(),
            http_request_timeout_ms: default_http_request_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReadinessConfig {
    #[serde(default = "default_startup_self_check")]
    pub startup_self_check: bool,
    #[serde(default = "default_self_check_name")]
    pub self_check_name: String,
}

impl Default for ReadinessConfig {
    fn default() -> Self {
        Self {
            startup_self_check: default_startup_self_check(),
            self_check_name: default_self_check_name(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub json: bool,
    #[serde(default = "default_log_filter")]
    pub filter: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            json: false,
            filter: default_log_filter(),
        }
    }
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8053".parse().expect("valid bind")
}

fn default_root_hints_path() -> PathBuf {
    PathBuf::from("config/root.hints")
}

fn default_ns_cache_size() -> usize {
    2048
}

fn default_record_cache_size() -> usize {
    1_048_576
}

fn default_recursion_limit() -> u8 {
    16
}

fn default_ns_recursion_limit() -> u8 {
    16
}

fn default_resolve_timeout_ms() -> u64 {
    3500
}

fn default_sinkhole_ipv4() -> String {
    "0.0.0.0".to_string()
}

fn default_sinkhole_ipv6() -> String {
    "::".to_string()
}

fn default_sinkhole_ttl() -> u32 {
    60
}

fn default_max_post_body_bytes() -> usize {
    4096
}

fn default_max_get_dns_param_bytes() -> usize {
    8192
}

fn default_max_dns_wire_bytes() -> usize {
    4096
}

fn default_max_json_name_bytes() -> usize {
    255
}

fn default_max_concurrent_requests() -> usize {
    10_000
}

fn default_http_request_timeout_ms() -> u64 {
    5000
}

fn default_startup_self_check() -> bool {
    true
}

fn default_self_check_name() -> String {
    ".".to_string()
}

fn default_log_filter() -> String {
    "info,polaris=info".to_string()
}

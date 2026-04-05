//! Custom in-memory domain filter with atomic snapshot semantics.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use anyhow::{bail, Context};
use hickory_proto::rr::Name;

use crate::config::{BlockMode, FilterConfig};

#[derive(Debug, Clone)]
pub struct NormalizedName {
    canonical: String,
    fqdn: Name,
}

impl NormalizedName {
    /// Parses an input name into a canonical lowercase A-label form and FQDN `Name`.
    pub fn parse(name: &str) -> anyhow::Result<Self> {
        let mut trimmed = name.trim().trim_end_matches('.').to_string();
        if trimmed.is_empty() {
            return Ok(Self {
                canonical: String::new(),
                fqdn: Name::root(),
            });
        }

        trimmed = idna::domain_to_ascii(&trimmed)
            .with_context(|| format!("invalid idn in name: {name}"))?
            .to_ascii_lowercase();

        let fqdn_text = format!("{trimmed}.");
        let fqdn = Name::from_ascii(&fqdn_text)
            .with_context(|| format!("invalid dns name: {name}"))?
            .to_lowercase();

        Ok(Self {
            canonical: trimmed,
            fqdn,
        })
    }

    /// Builds a normalized view from a parsed wire-format DNS name.
    pub fn from_wire_name(name: &Name) -> anyhow::Result<Self> {
        Self::parse(&name.to_ascii())
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn fqdn(&self) -> &Name {
        &self.fqdn
    }
}

#[derive(Debug, Clone)]
pub enum FilterDecision {
    /// Continue with recursive resolution.
    Allow,
    /// Block and return NXDOMAIN.
    BlockNxDomain,
    /// Block and return local sinkhole records.
    BlockSinkhole {
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        ttl: u32,
    },
}

#[derive(Debug, Clone)]
pub struct FilterSnapshot {
    exact_allow: HashSet<String>,
    exact_block: HashSet<String>,
    suffix_allow: Vec<String>,
    suffix_block: Vec<String>,
    block_mode: BlockMode,
    sinkhole_ipv4: Ipv4Addr,
    sinkhole_ipv6: Ipv6Addr,
    sinkhole_ttl: u32,
}

impl FilterSnapshot {
    /// Creates an immutable rule snapshot from config.
    pub fn from_config(cfg: &FilterConfig) -> anyhow::Result<Self> {
        let exact_allow = cfg
            .exact_allow
            .iter()
            .map(|v| normalize_exact_rule(v))
            .collect::<anyhow::Result<HashSet<_>>>()?;

        let exact_block = cfg
            .exact_block
            .iter()
            .map(|v| normalize_exact_rule(v))
            .collect::<anyhow::Result<HashSet<_>>>()?;

        let suffix_allow = cfg
            .suffix_allow
            .iter()
            .map(|v| normalize_suffix_rule(v))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let suffix_block = cfg
            .suffix_block
            .iter()
            .map(|v| normalize_suffix_rule(v))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let sinkhole_ipv4 = Ipv4Addr::from_str(cfg.sinkhole_ipv4.as_str())
            .with_context(|| format!("invalid sinkhole_ipv4: {}", cfg.sinkhole_ipv4))?;
        let sinkhole_ipv6 = Ipv6Addr::from_str(cfg.sinkhole_ipv6.as_str())
            .with_context(|| format!("invalid sinkhole_ipv6: {}", cfg.sinkhole_ipv6))?;

        Ok(Self {
            exact_allow,
            exact_block,
            suffix_allow,
            suffix_block,
            block_mode: cfg.block_mode.clone(),
            sinkhole_ipv4,
            sinkhole_ipv6,
            sinkhole_ttl: cfg.sinkhole_ttl,
        })
    }

    /// Evaluates a normalized name using precedence:
    /// exact allow > exact block > suffix allow > suffix block > allow.
    pub fn evaluate(&self, name: &NormalizedName) -> FilterDecision {
        let key = name.canonical();

        if self.exact_allow.contains(key) {
            return FilterDecision::Allow;
        }

        if self.exact_block.contains(key) {
            return self.block_decision();
        }

        if self
            .suffix_allow
            .iter()
            .any(|suffix| suffix_match(key, suffix))
        {
            return FilterDecision::Allow;
        }

        if self
            .suffix_block
            .iter()
            .any(|suffix| suffix_match(key, suffix))
        {
            return self.block_decision();
        }

        FilterDecision::Allow
    }

    fn block_decision(&self) -> FilterDecision {
        match self.block_mode {
            BlockMode::NxDomain => FilterDecision::BlockNxDomain,
            BlockMode::Sinkhole => FilterDecision::BlockSinkhole {
                ipv4: self.sinkhole_ipv4,
                ipv6: self.sinkhole_ipv6,
                ttl: self.sinkhole_ttl,
            },
        }
    }
}

fn normalize_exact_rule(value: &str) -> anyhow::Result<String> {
    if value.trim().starts_with("*.") {
        bail!("exact rule cannot start with '*.': {value}");
    }

    let normalized = NormalizedName::parse(value)?;
    Ok(normalized.canonical)
}

fn normalize_suffix_rule(value: &str) -> anyhow::Result<String> {
    let raw = value.trim();
    let without_wildcard = raw
        .strip_prefix("*.")
        .or_else(|| raw.strip_prefix('.'))
        .unwrap_or(raw);

    if without_wildcard.is_empty() {
        bail!("suffix rule cannot be empty: {value}");
    }

    let normalized = NormalizedName::parse(without_wildcard)?;
    if normalized.canonical.is_empty() {
        bail!("suffix rule resolves to root and is not allowed: {value}");
    }

    Ok(normalized.canonical)
}

fn suffix_match(name: &str, suffix: &str) -> bool {
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

#[cfg(test)]
mod tests {
    use crate::config::{BlockMode, FilterConfig};

    use super::{FilterDecision, FilterSnapshot, NormalizedName};

    #[test]
    fn precedence_works() {
        let cfg = FilterConfig {
            exact_allow: vec!["allow.blocked.example".into()],
            exact_block: vec!["allow.blocked.example".into(), "x.example".into()],
            suffix_allow: vec!["*.safe.example".into()],
            suffix_block: vec!["*.example".into()],
            block_mode: BlockMode::NxDomain,
            ..FilterConfig::default()
        };

        let snap = FilterSnapshot::from_config(&cfg).unwrap();

        let exact_allow = NormalizedName::parse("allow.blocked.example").unwrap();
        assert!(matches!(snap.evaluate(&exact_allow), FilterDecision::Allow));

        let exact_block = NormalizedName::parse("x.example").unwrap();
        assert!(matches!(
            snap.evaluate(&exact_block),
            FilterDecision::BlockNxDomain
        ));

        let suffix_allow = NormalizedName::parse("www.safe.example").unwrap();
        assert!(matches!(
            snap.evaluate(&suffix_allow),
            FilterDecision::Allow
        ));

        let suffix_block = NormalizedName::parse("www.anything.example").unwrap();
        assert!(matches!(
            snap.evaluate(&suffix_block),
            FilterDecision::BlockNxDomain
        ));

        let default_allow = NormalizedName::parse("www.other.net").unwrap();
        assert!(matches!(
            snap.evaluate(&default_allow),
            FilterDecision::Allow
        ));
    }

    #[test]
    fn idn_is_normalized() {
        let name = NormalizedName::parse("b\u{00FC}cher.Example").unwrap();
        assert_eq!(name.canonical(), "xn--bcher-kva.example");
        assert_eq!(name.fqdn().to_ascii(), "xn--bcher-kva.example.");
    }
}

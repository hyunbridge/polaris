//! Resolver generation management built on top of `hickory-recursor`.

use std::{
    fs,
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use hickory_proto::{
    dnssec::TrustAnchors,
    op::{Query, ResponseCode},
    rr::Record,
};
use hickory_recursor::{DnssecPolicy, NameServerConfigGroup, Recursor};
use ipnet::IpNet;

use crate::config::ResolverConfig;

#[derive(Debug, Clone)]
pub struct ResolverBuildInfo {
    pub generation: u64,
    pub root_hints_source: String,
    pub root_hints_count: usize,
    pub trust_anchor_source: String,
    pub trust_anchor_count: usize,
    pub loaded_at: SystemTime,
}

pub struct ResolverGeneration {
    pub id: u64,
    pub recursor: Arc<Recursor>,
    pub info: ResolverBuildInfo,
}

#[derive(Debug, Clone)]
pub enum ResolveOutcome {
    Answer {
        records: Vec<Record>,
    },
    Negative {
        response_code: ResponseCode,
        soa: Option<Box<Record>>,
        authorities: Vec<Record>,
    },
}

#[derive(Debug, Clone)]
pub enum ResolveFailure {
    Timeout,
    ServFail,
}

pub struct ResolverManager {
    generations: ArcSwap<ResolverGeneration>,
    next_generation: AtomicU64,
    cfg: ResolverConfig,
}

impl ResolverManager {
    /// Builds the initial resolver generation.
    pub fn new(cfg: ResolverConfig) -> anyhow::Result<Self> {
        let generation = build_generation(1, &cfg)?;

        Ok(Self {
            generations: ArcSwap::from_pointee(generation),
            next_generation: AtomicU64::new(2),
            cfg,
        })
    }

    /// Returns metadata about the active resolver generation.
    pub fn active_info(&self) -> ResolverBuildInfo {
        self.generations.load().info.clone()
    }

    /// Resolves a query with timeout and normalizes Hickory outcomes.
    pub async fn resolve(
        &self,
        query: Query,
        query_has_dnssec_ok: bool,
        timeout: Duration,
    ) -> Result<ResolveOutcome, ResolveFailure> {
        let generation = self.generations.load_full();
        let fut = generation
            .recursor
            .resolve(query, Instant::now(), query_has_dnssec_ok);

        let resolved = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ResolveFailure::Timeout)?;

        match resolved {
            Ok(lookup) => Ok(ResolveOutcome::Answer {
                records: lookup.records().to_vec(),
            }),
            Err(err) => {
                if err.is_nx_domain() || err.is_no_records_found() {
                    let response_code = if err.is_nx_domain() {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NoError
                    };
                    let soa = err
                        .clone()
                        .into_soa()
                        .map(|record| Box::new((*record).into_record_of_rdata()));
                    let authorities = err
                        .clone()
                        .authorities()
                        .map(|records| records.to_vec())
                        .unwrap_or_default();

                    Ok(ResolveOutcome::Negative {
                        response_code,
                        soa,
                        authorities,
                    })
                } else {
                    Err(ResolveFailure::ServFail)
                }
            }
        }
    }

    /// Purges cache by swapping in a fresh resolver generation.
    pub fn purge_generation(&self) -> anyhow::Result<ResolverBuildInfo> {
        let generation_id = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let generation = build_generation(generation_id, &self.cfg)?;
        let info = generation.info.clone();

        self.generations.store(Arc::new(generation));
        Ok(info)
    }
}

fn build_generation(id: u64, cfg: &ResolverConfig) -> anyhow::Result<ResolverGeneration> {
    let (roots, root_hints_source, root_hints_count) = load_root_hints(&cfg.root_hints_path)?;
    let (trust_anchor, trust_anchor_source, trust_anchor_count) = load_trust_anchor(cfg)?;

    let allow_cidrs = cfg
        .nameserver_allow_cidrs
        .iter()
        .map(|v| IpNet::from_str(v).with_context(|| format!("invalid allow cidr: {v}")))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let deny_cidrs = cfg
        .nameserver_deny_cidrs
        .iter()
        .map(|v| IpNet::from_str(v).with_context(|| format!("invalid deny cidr: {v}")))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let recursor = Recursor::builder()
        .ns_cache_size(cfg.ns_cache_size)
        .record_cache_size(cfg.record_cache_size)
        .recursion_limit(Some(cfg.recursion_limit))
        .ns_recursion_limit(Some(cfg.ns_recursion_limit))
        .dnssec_policy(DnssecPolicy::ValidateWithStaticKey {
            trust_anchor: Some(trust_anchor),
        })
        .nameserver_filter(allow_cidrs.iter(), deny_cidrs.iter())
        .build(roots)
        .context("failed to build hickory recursor")?;

    let loaded_at = SystemTime::now();
    let info = ResolverBuildInfo {
        generation: id,
        root_hints_source,
        root_hints_count,
        trust_anchor_source,
        trust_anchor_count,
        loaded_at,
    };

    Ok(ResolverGeneration {
        id,
        recursor: Arc::new(recursor),
        info,
    })
}

fn load_trust_anchor(cfg: &ResolverConfig) -> anyhow::Result<(Arc<TrustAnchors>, String, usize)> {
    let (anchor, source) = if let Some(path) = cfg.trust_anchor_path.as_ref() {
        let anchors = TrustAnchors::from_file(path)
            .with_context(|| format!("failed to load trust anchor file: {}", path.display()))?;
        (anchors, format!("file:{}", path.display()))
    } else {
        (
            TrustAnchors::default(),
            "builtin:hickory-default".to_string(),
        )
    };

    let count = anchor.len();
    if count == 0 {
        bail!("trust anchors are empty");
    }

    Ok((Arc::new(anchor), source, count))
}

fn load_root_hints(path: &Path) -> anyhow::Result<(NameServerConfigGroup, String, usize)> {
    if !path.exists() {
        bail!("root hints file not found: {}", path.display());
    }

    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read root hints: {}", path.display()))?;
    let ips = parse_root_hint_ips(&data);
    if ips.is_empty() {
        bail!(
            "root hints file does not contain any IP addresses: {}",
            path.display()
        );
    }

    let count = ips.len();
    let roots = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
    Ok((roots, format!("file:{}", path.display()), count))
}

fn parse_root_hint_ips(content: &str) -> Vec<IpAddr> {
    let mut result = Vec::new();
    // Root hint files contain mixed records; keep only tokens parseable as IPs.
    for token in content.split_whitespace() {
        let clean = token.trim().trim_end_matches('.');
        if let Ok(ip) = IpAddr::from_str(clean) {
            result.push(ip);
        }
    }
    result.sort_unstable();
    result.dedup();
    result
}

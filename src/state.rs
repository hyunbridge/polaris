//! Shared application state and cross-module orchestration.

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use hickory_proto::{op::Query, rr::RecordType};

use crate::{
    config::PolarisConfig,
    filter::{FilterDecision, FilterSnapshot, NormalizedName},
    readiness::ReadinessState,
    resolver::{ResolveFailure, ResolveOutcome, ResolverBuildInfo, ResolverManager},
};

pub struct AppState {
    pub config: Arc<PolarisConfig>,
    pub filters: ArcSwap<FilterSnapshot>,
    pub resolver: Arc<ResolverManager>,
    pub readiness: Arc<ReadinessState>,
    pub resolve_timeout: Duration,
}

impl AppState {
    /// Builds app state, filter snapshot, resolver manager, and readiness baseline.
    pub fn new(config: PolarisConfig) -> anyhow::Result<Self> {
        let filter_snapshot = FilterSnapshot::from_config(&config.filter)?;
        let resolver = Arc::new(ResolverManager::new(config.resolver.clone())?);
        let readiness = Arc::new(ReadinessState::new());

        let info = resolver.active_info();
        readiness.set_from_build_info(&info);

        let resolve_timeout = Duration::from_millis(config.resolver.resolve_timeout_ms);

        Ok(Self {
            config: Arc::new(config),
            filters: ArcSwap::from_pointee(filter_snapshot),
            resolver,
            readiness,
            resolve_timeout,
        })
    }

    /// Evaluates filter decision for a normalized name.
    pub fn evaluate_filter(&self, name: &NormalizedName) -> FilterDecision {
        self.filters.load().evaluate(name)
    }

    /// Resolves a query through the active resolver generation.
    pub async fn resolve(
        &self,
        query: Query,
        query_has_dnssec_ok: bool,
    ) -> Result<ResolveOutcome, ResolveFailure> {
        self.resolver
            .resolve(query, query_has_dnssec_ok, self.resolve_timeout)
            .await
    }

    /// Purges cache by swapping to a fresh resolver generation.
    pub fn purge_cache_generation(&self) -> anyhow::Result<ResolverBuildInfo> {
        let info = self.resolver.purge_generation()?;
        self.readiness.set_from_build_info(&info);
        Ok(info)
    }

    /// Optional startup self-check used by `/readyz`.
    pub async fn run_startup_self_check(&self) {
        if !self.config.readiness.startup_self_check {
            self.readiness.set_self_check(true);
            return;
        }

        let result = (|| -> anyhow::Result<Query> {
            let normalized = NormalizedName::parse(self.config.readiness.self_check_name.as_str())?;
            let qname = if normalized.canonical().is_empty() {
                hickory_proto::rr::Name::root()
            } else {
                normalized.fqdn().clone()
            };
            Ok(Query::query(qname, RecordType::NS))
        })();

        let ok = match result {
            Ok(query) => self.resolve(query, true).await.is_ok(),
            Err(_) => false,
        };

        self.readiness.set_self_check(ok);
    }
}

//! Readiness state model exposed by `/readyz`.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        RwLock,
    },
    time::SystemTime,
};

use serde::Serialize;

use crate::resolver::ResolverBuildInfo;

pub struct ReadinessState {
    recursor_initialized: AtomicBool,
    root_hints_loaded: AtomicBool,
    trust_anchor_loaded: AtomicBool,
    self_check_ok: AtomicBool,
    details: RwLock<ReadinessDetails>,
}

#[derive(Debug, Clone)]
struct ReadinessDetails {
    generation: u64,
    root_hints_source: String,
    trust_anchor_source: String,
    root_hints_count: usize,
    trust_anchor_count: usize,
    loaded_at: Option<SystemTime>,
    last_self_check: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessSnapshot {
    pub ready: bool,
    pub recursor_initialized: bool,
    pub root_hints_loaded: bool,
    pub trust_anchor_loaded: bool,
    pub self_check_ok: bool,
    pub generation: u64,
    pub root_hints_source: String,
    pub trust_anchor_source: String,
    pub root_hints_count: usize,
    pub trust_anchor_count: usize,
}

impl ReadinessState {
    /// Creates a new readiness state in "not ready" mode.
    pub fn new() -> Self {
        Self {
            recursor_initialized: AtomicBool::new(false),
            root_hints_loaded: AtomicBool::new(false),
            trust_anchor_loaded: AtomicBool::new(false),
            self_check_ok: AtomicBool::new(false),
            details: RwLock::new(ReadinessDetails {
                generation: 0,
                root_hints_source: "uninitialized".to_string(),
                trust_anchor_source: "uninitialized".to_string(),
                root_hints_count: 0,
                trust_anchor_count: 0,
                loaded_at: None,
                last_self_check: None,
            }),
        }
    }

    /// Updates resolver/root/trust-anchor readiness fields from a build event.
    pub fn set_from_build_info(&self, info: &ResolverBuildInfo) {
        self.recursor_initialized.store(true, Ordering::Release);
        self.root_hints_loaded
            .store(info.root_hints_count > 0, Ordering::Release);
        self.trust_anchor_loaded
            .store(info.trust_anchor_count > 0, Ordering::Release);

        if let Ok(mut details) = self.details.write() {
            details.generation = info.generation;
            details.root_hints_source = info.root_hints_source.clone();
            details.trust_anchor_source = info.trust_anchor_source.clone();
            details.root_hints_count = info.root_hints_count;
            details.trust_anchor_count = info.trust_anchor_count;
            details.loaded_at = Some(info.loaded_at);
        }
    }

    /// Stores the result of startup self-check.
    pub fn set_self_check(&self, ok: bool) {
        self.self_check_ok.store(ok, Ordering::Release);
        if let Ok(mut details) = self.details.write() {
            details.last_self_check = Some(SystemTime::now());
        }
    }

    /// Returns a serializable readiness snapshot for HTTP responses.
    pub fn snapshot(&self) -> ReadinessSnapshot {
        let details = self
            .details
            .read()
            .expect("readiness details lock poisoned");
        let recursor_initialized = self.recursor_initialized.load(Ordering::Acquire);
        let root_hints_loaded = self.root_hints_loaded.load(Ordering::Acquire);
        let trust_anchor_loaded = self.trust_anchor_loaded.load(Ordering::Acquire);
        let self_check_ok = self.self_check_ok.load(Ordering::Acquire);

        ReadinessSnapshot {
            ready: recursor_initialized
                && root_hints_loaded
                && trust_anchor_loaded
                && self_check_ok,
            recursor_initialized,
            root_hints_loaded,
            trust_anchor_loaded,
            self_check_ok,
            generation: details.generation,
            root_hints_source: details.root_hints_source.clone(),
            trust_anchor_source: details.trust_anchor_source.clone(),
            root_hints_count: details.root_hints_count,
            trust_anchor_count: details.trust_anchor_count,
        }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

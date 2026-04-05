//! Polaris library modules.

/// HTTP router wiring and middleware.
pub mod app;
/// Runtime configuration schema and defaults.
pub mod config;
/// DNS message parsing and response synthesis helpers.
pub mod dns;
/// In-memory pre-resolution allow/block filter engine.
pub mod filter;
/// HTTP handlers for DoH, health, and readiness endpoints.
pub mod handlers;
/// Readiness model and snapshot serialization.
pub mod readiness;
/// Hickory recursor wrapper and generation lifecycle.
pub mod resolver;
/// Shared application state.
pub mod state;

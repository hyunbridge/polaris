//! HTTP router construction.

use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, routing::get, Router};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::{handlers, state::AppState};

/// Builds the application router and middleware stack.
pub fn build_router(state: Arc<AppState>) -> Router {
    let max_body = state.config.limits.max_post_body_bytes;
    let max_concurrency = state.config.limits.max_concurrent_requests;
    Router::new()
        .route(
            "/dns-query",
            get(handlers::doh_query_get).post(handlers::doh_query_post),
        )
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(ConcurrencyLimitLayer::new(max_concurrency))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

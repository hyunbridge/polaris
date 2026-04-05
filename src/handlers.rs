//! Axum handlers for RFC 8484 wire DoH, JSON compatibility mode, and probes.

use std::{future::Future, str::FromStr, time::Duration};

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query as DnsQuery, ResponseCode},
    rr::{Name, Record, RecordType},
};
use serde::{Deserialize, Serialize};

use crate::{
    dns::{
        blocked_response, parse_dns_message, prepare_dns_request, prepared_error_response,
        resolved_response, response_to_wire, PreparedDnsRequest, DOH_WIRE_CONTENT_TYPE,
    },
    filter::{FilterDecision, NormalizedName},
    resolver::ResolveFailure,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct DnsQueryGetParams {
    pub dns: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    pub cd: Option<String>,
    #[serde(rename = "do")]
    pub dnssec_ok: Option<String>,
}

/// Handles `GET /dns-query` in wire (`dns=`) or JSON-compat (`name=`) mode.
pub async fn doh_query_get(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<DnsQueryGetParams>,
) -> Response {
    if let Some(dns) = params.dns {
        if dns.len() > state.config.limits.max_get_dns_param_bytes {
            return (StatusCode::URI_TOO_LONG, "dns query parameter too large").into_response();
        }

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(dns.as_bytes())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(dns.as_bytes()));

        let payload = match decoded {
            Ok(v) => v,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "invalid base64url dns parameter").into_response()
            }
        };

        return with_request_timeout(&state, run_wire_query(&state, &payload)).await;
    }

    let Some(name) = params.name else {
        return (
            StatusCode::BAD_REQUEST,
            "either 'dns' or 'name' query parameter is required",
        )
            .into_response();
    };

    let request = match (JsonGetParams {
        name,
        record_type: params.record_type,
        cd: params.cd,
        dnssec_ok: params.dnssec_ok,
    })
    .into_request()
    {
        Ok(req) => req,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    with_request_timeout(&state, run_json_query(&state, request)).await
}

/// Handles `POST /dns-query` for wire (`application/dns-message`) or JSON (`application/json`).
pub async fn doh_query_post(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or_default().trim())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if content_type == DOH_WIRE_CONTENT_TYPE {
        return with_request_timeout(&state, run_wire_query(&state, body.as_ref())).await;
    }

    if content_type == "application/json" {
        let request: JsonPostRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json body").into_response(),
        };
        let request = match request.into_request() {
            Ok(req) => req,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        };
        return with_request_timeout(&state, run_json_query(&state, request)).await;
    }

    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Content-Type must be application/dns-message or application/json",
    )
        .into_response()
}

pub async fn doh_json_get(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<JsonGetParams>,
) -> Response {
    let request = match params.into_request() {
        Ok(req) => req,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    with_request_timeout(&state, run_json_query(&state, request)).await
}

pub async fn doh_json_post(
    State(state): State<std::sync::Arc<AppState>>,
    Json(request): Json<JsonPostRequest>,
) -> Response {
    let request = match request.into_request() {
        Ok(req) => req,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    with_request_timeout(&state, run_json_query(&state, request)).await
}

/// Liveness probe endpoint.
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthzResponse {
            status: "ok",
            service: "polaris",
        }),
    )
}

/// Readiness probe endpoint.
pub async fn readyz(State(state): State<std::sync::Arc<AppState>>) -> Response {
    let snapshot = state.readiness.snapshot();
    if snapshot.ready {
        (StatusCode::OK, Json(snapshot)).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(snapshot)).into_response()
    }
}

async fn run_wire_query(state: &AppState, payload: &[u8]) -> Response {
    let message = match parse_dns_message(payload, state.config.limits.max_dns_wire_bytes) {
        Ok(msg) => msg,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid DNS wire query").into_response(),
    };

    let prepared = match prepare_dns_request(message) {
        Ok(p) => p,
        Err(protocol_error) => return wire_response(*protocol_error),
    };

    let dns_response = execute_request(state, prepared).await;
    wire_response(dns_response)
}

async fn run_json_query(state: &AppState, request: JsonResolvedRequest) -> Response {
    if request.name.len() > state.config.limits.max_json_name_bytes {
        return (StatusCode::BAD_REQUEST, "name is too long").into_response();
    }

    let normalized_name = match NormalizedName::parse(request.name.as_str()) {
        Ok(name) => name,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid domain name").into_response(),
    };

    let qname = if normalized_name.canonical().is_empty() {
        Name::root()
    } else {
        normalized_name.fqdn().clone()
    };

    let mut message = Message::new();
    message
        .set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_checking_disabled(request.cd)
        .add_query(DnsQuery::query(qname, request.record_type));

    if request.dnssec_ok {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        message.set_edns(edns);
    }

    let prepared = match prepare_dns_request(message) {
        Ok(p) => p,
        Err(protocol_error) => {
            let json_resp = JsonDohResponse::from_message(&protocol_error);
            return (StatusCode::OK, Json(json_resp)).into_response();
        }
    };

    let dns_response = execute_request(state, prepared).await;
    let json_resp = JsonDohResponse::from_message(&dns_response);
    (StatusCode::OK, Json(json_resp)).into_response()
}

async fn execute_request(state: &AppState, prepared: PreparedDnsRequest) -> Message {
    // Filter always runs before recursion to avoid upstream leakage for blocked names.
    match state.evaluate_filter(&prepared.normalized_name) {
        FilterDecision::Allow => {}
        blocked => return blocked_response(&prepared, blocked),
    }

    match state
        .resolve(prepared.recursive_query.clone(), prepared.dnssec_ok)
        .await
    {
        Ok(outcome) => resolved_response(&prepared, outcome),
        Err(ResolveFailure::Timeout | ResolveFailure::ServFail) => {
            prepared_error_response(&prepared, ResponseCode::ServFail)
        }
    }
}

fn wire_response(message: Message) -> Response {
    match response_to_wire(&message) {
        Ok(wire) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, DOH_WIRE_CONTENT_TYPE)],
            wire,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode dns response",
        )
            .into_response(),
    }
}

async fn with_request_timeout<F>(state: &AppState, fut: F) -> Response
where
    F: Future<Output = Response>,
{
    let timeout = Duration::from_millis(state.config.limits.http_request_timeout_ms);
    match tokio::time::timeout(timeout, fut).await {
        Ok(response) => response,
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "request timeout").into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonGetParams {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    pub cd: Option<String>,
    #[serde(rename = "do")]
    pub dnssec_ok: Option<String>,
}

impl JsonGetParams {
    fn into_request(self) -> Result<JsonResolvedRequest, &'static str> {
        Ok(JsonResolvedRequest {
            name: self.name,
            record_type: parse_record_type(self.record_type.as_deref())?,
            cd: parse_boolish(self.cd.as_deref()).unwrap_or(false),
            dnssec_ok: parse_boolish(self.dnssec_ok.as_deref()).unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonPostRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: Option<serde_json::Value>,
    pub cd: Option<bool>,
    #[serde(rename = "do")]
    pub dnssec_ok: Option<bool>,
}

impl JsonPostRequest {
    fn into_request(self) -> Result<JsonResolvedRequest, &'static str> {
        let record_type = match self.record_type {
            Some(value) => parse_record_type_value(&value)?,
            None => RecordType::A,
        };

        Ok(JsonResolvedRequest {
            name: self.name,
            record_type,
            cd: self.cd.unwrap_or(false),
            dnssec_ok: self.dnssec_ok.unwrap_or(false),
        })
    }
}

#[derive(Debug)]
struct JsonResolvedRequest {
    name: String,
    record_type: RecordType,
    cd: bool,
    dnssec_ok: bool,
}

fn parse_record_type(raw: Option<&str>) -> Result<RecordType, &'static str> {
    let Some(raw) = raw else {
        return Ok(RecordType::A);
    };

    let normalized = raw.trim();
    if normalized.is_empty() {
        return Ok(RecordType::A);
    }

    if let Ok(value) = normalized.parse::<u16>() {
        return Ok(RecordType::from(value));
    }

    RecordType::from_str(normalized).map_err(|_| "invalid record type")
}

fn parse_record_type_value(value: &serde_json::Value) -> Result<RecordType, &'static str> {
    match value {
        serde_json::Value::String(s) => parse_record_type(Some(s)),
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .map(RecordType::from)
            .ok_or("invalid numeric record type"),
        _ => Err("invalid record type"),
    }
}

fn parse_boolish(raw: Option<&str>) -> Option<bool> {
    let raw = raw?.trim();
    match raw {
        "1" | "true" | "TRUE" | "True" => Some(true),
        "0" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
struct JsonDohResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC")]
    tc: bool,
    #[serde(rename = "RD")]
    rd: bool,
    #[serde(rename = "RA")]
    ra: bool,
    #[serde(rename = "AD")]
    ad: bool,
    #[serde(rename = "CD")]
    cd: bool,
    #[serde(rename = "Question")]
    question: Vec<JsonQuestion>,
    #[serde(rename = "Answer", skip_serializing_if = "Option::is_none")]
    answer: Option<Vec<JsonRecord>>,
    #[serde(rename = "Authority", skip_serializing_if = "Option::is_none")]
    authority: Option<Vec<JsonRecord>>,
    #[serde(rename = "Additional", skip_serializing_if = "Option::is_none")]
    additional: Option<Vec<JsonRecord>>,
}

#[derive(Debug, Serialize)]
struct JsonQuestion {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[derive(Debug, Serialize)]
struct JsonRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Debug, Serialize)]
struct HealthzResponse {
    status: &'static str,
    service: &'static str,
}

impl JsonDohResponse {
    fn from_message(message: &Message) -> Self {
        let question = message
            .queries()
            .iter()
            .map(|q| JsonQuestion {
                name: q.name().to_ascii(),
                record_type: u16::from(q.query_type()),
            })
            .collect::<Vec<_>>();

        let answer = records_to_json(message.answers());
        let authority = records_to_json(message.name_servers());
        let additional = records_to_json(message.additionals());

        Self {
            status: u16::from(message.response_code()),
            tc: message.truncated(),
            rd: message.recursion_desired(),
            ra: message.recursion_available(),
            ad: message.authentic_data(),
            cd: message.checking_disabled(),
            question,
            answer,
            authority,
            additional,
        }
    }
}

fn records_to_json(records: &[Record]) -> Option<Vec<JsonRecord>> {
    if records.is_empty() {
        return None;
    }

    Some(
        records
            .iter()
            .map(|r| JsonRecord {
                name: r.name().to_ascii(),
                record_type: u16::from(r.record_type()),
                ttl: r.ttl(),
                data: format!("{}", r.data()),
            })
            .collect(),
    )
}

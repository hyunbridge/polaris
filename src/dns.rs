//! DNS wire parsing/validation and response synthesis helpers.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        DNSClass, RData, Record, RecordType,
    },
};

use crate::{
    filter::{FilterDecision, NormalizedName},
    resolver::ResolveOutcome,
};

pub const DOH_WIRE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Debug, Clone)]
pub struct PreparedDnsRequest {
    pub original_query: Query,
    pub recursive_query: Query,
    pub normalized_name: NormalizedName,
    pub dnssec_ok: bool,
    id: u16,
    op_code: OpCode,
    recursion_desired: bool,
    checking_disabled: bool,
}

pub fn parse_dns_message(bytes: &[u8], max_dns_wire_bytes: usize) -> anyhow::Result<Message> {
    if bytes.is_empty() {
        anyhow::bail!("empty DNS message");
    }
    if bytes.len() > max_dns_wire_bytes {
        anyhow::bail!(
            "DNS message larger than max limit: {} > {}",
            bytes.len(),
            max_dns_wire_bytes
        );
    }

    Message::from_vec(bytes).context("invalid DNS wire message")
}

/// Validates a DNS request and prepares normalized state for resolution/filtering.
pub fn prepare_dns_request(message: Message) -> Result<PreparedDnsRequest, Box<Message>> {
    if message.message_type() != MessageType::Query {
        return Err(Box::new(error_response(&message, ResponseCode::FormErr)));
    }

    if message.op_code() != OpCode::Query {
        return Err(Box::new(error_response(&message, ResponseCode::NotImp)));
    }

    if message.queries().len() != 1 {
        return Err(Box::new(error_response(&message, ResponseCode::FormErr)));
    }

    let query = message.queries()[0].clone();
    if query.query_class() != DNSClass::IN {
        return Err(Box::new(error_response(&message, ResponseCode::Refused)));
    }

    let normalized_name = match NormalizedName::from_wire_name(query.name()) {
        Ok(name) => name,
        Err(_) => return Err(Box::new(error_response(&message, ResponseCode::FormErr))),
    };

    let mut recursive_query = query.clone();
    recursive_query.set_name(normalized_name.fqdn().clone());

    let dnssec_ok = message
        .extensions()
        .as_ref()
        .map(|edns| edns.flags().dnssec_ok)
        .unwrap_or(false);

    Ok(PreparedDnsRequest {
        original_query: query,
        recursive_query,
        normalized_name,
        dnssec_ok,
        id: message.id(),
        op_code: message.op_code(),
        recursion_desired: message.recursion_desired(),
        checking_disabled: message.checking_disabled(),
    })
}

/// Creates a local response for blocked names.
pub fn blocked_response(prepared: &PreparedDnsRequest, filter_decision: FilterDecision) -> Message {
    match filter_decision {
        FilterDecision::Allow => {
            unreachable!("blocked_response called with allow decision")
        }
        FilterDecision::BlockNxDomain => {
            let mut resp = response_shell(prepared, ResponseCode::NXDomain);
            resp.add_query(prepared.original_query.clone());
            resp
        }
        FilterDecision::BlockSinkhole { ipv4, ipv6, ttl } => {
            sinkhole_response(prepared, ipv4, ipv6, ttl)
        }
    }
}

/// Converts resolver output to a DNS response message.
pub fn resolved_response(prepared: &PreparedDnsRequest, outcome: ResolveOutcome) -> Message {
    match outcome {
        ResolveOutcome::Answer { records } => {
            let mut resp = response_shell(prepared, ResponseCode::NoError);
            resp.add_query(prepared.original_query.clone());
            resp.add_answers(records);
            resp
        }
        ResolveOutcome::Negative {
            response_code,
            soa,
            authorities,
        } => {
            let mut resp = response_shell(prepared, response_code);
            resp.add_query(prepared.original_query.clone());
            if let Some(soa) = soa {
                resp.add_name_server(*soa);
            }
            if !authorities.is_empty() {
                resp.add_name_servers(authorities);
            }
            resp
        }
    }
}

/// Creates a response from a prepared request and response code.
pub fn prepared_error_response(prepared: &PreparedDnsRequest, code: ResponseCode) -> Message {
    let mut resp = response_shell(prepared, code);
    resp.add_query(prepared.original_query.clone());
    resp
}

/// Serializes DNS message into wire format.
pub fn response_to_wire(message: &Message) -> anyhow::Result<Vec<u8>> {
    message.to_vec().context("failed to serialize DNS response")
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_checking_disabled(request.checking_disabled())
        .set_response_code(code);

    if let Some(first_query) = request.queries().first() {
        message.add_query(first_query.clone());
    }

    message
}

fn response_shell(prepared: &PreparedDnsRequest, code: ResponseCode) -> Message {
    let mut message = Message::new();
    message
        .set_id(prepared.id)
        .set_message_type(MessageType::Response)
        .set_op_code(prepared.op_code)
        .set_recursion_desired(prepared.recursion_desired)
        .set_recursion_available(true)
        .set_checking_disabled(prepared.checking_disabled)
        .set_response_code(code);
    message
}

fn sinkhole_response(
    prepared: &PreparedDnsRequest,
    sinkhole_ipv4: Ipv4Addr,
    sinkhole_ipv6: Ipv6Addr,
    ttl: u32,
) -> Message {
    let mut response = response_shell(prepared, ResponseCode::NoError);
    response.add_query(prepared.original_query.clone());

    let qname = prepared.recursive_query.name().clone();
    let qtype = prepared.recursive_query.query_type();

    if qtype == RecordType::A || qtype == RecordType::ANY {
        response.add_answer(Record::from_rdata(
            qname.clone(),
            ttl,
            RData::A(A::from(sinkhole_ipv4)),
        ));
    }

    if qtype == RecordType::AAAA || qtype == RecordType::ANY {
        response.add_answer(Record::from_rdata(
            qname,
            ttl,
            RData::AAAA(AAAA::from(sinkhole_ipv6)),
        ));
    }

    response
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };

    use crate::filter::FilterDecision;

    use super::{blocked_response, response_to_wire, sinkhole_response, PreparedDnsRequest};

    fn sample_prepared(qtype: RecordType) -> PreparedDnsRequest {
        let name = Name::from_ascii("blocked.example.").unwrap();
        let query = Query::query(name.clone(), qtype);

        PreparedDnsRequest {
            original_query: query.clone(),
            recursive_query: query,
            normalized_name: crate::filter::NormalizedName::parse("blocked.example").unwrap(),
            dnssec_ok: false,
            id: 7,
            op_code: hickory_proto::op::OpCode::Query,
            recursion_desired: true,
            checking_disabled: false,
        }
    }

    #[test]
    fn nxdomain_block_response_serializes() {
        let prepared = sample_prepared(RecordType::A);
        let resp = blocked_response(&prepared, FilterDecision::BlockNxDomain);
        let wire = response_to_wire(&resp).unwrap();
        assert!(!wire.is_empty());
        assert_eq!(
            resp.response_code(),
            hickory_proto::op::ResponseCode::NXDomain
        );
    }

    #[test]
    fn sinkhole_adds_expected_answer_types() {
        let prepared_a = sample_prepared(RecordType::A);
        let resp_a = sinkhole_response(
            &prepared_a,
            "0.0.0.0".parse().unwrap(),
            "::".parse().unwrap(),
            60,
        );
        assert_eq!(resp_a.answers().len(), 1);

        let prepared_any = sample_prepared(RecordType::ANY);
        let resp_any = sinkhole_response(
            &prepared_any,
            "0.0.0.0".parse().unwrap(),
            "::".parse().unwrap(),
            60,
        );
        assert_eq!(resp_any.answers().len(), 2);
    }
}

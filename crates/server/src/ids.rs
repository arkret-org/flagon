//! UUIDv7-prefixed identifiers used by teabay.
//!
//! All teabay-issued ids are `cx:<class>:<uuidv7>`. UUIDv7 is time-ordered,
//! which gives us natural ordering for audit logs without a separate
//! sequence column, and keeps these service-internal ids aligned with the
//! protocol-wide UUIDv7 typed-id form (`contrix_sdk::new_prefixed_uuid7`).
//!
//! ## CXP-0007 `cx:circle:` tolerance (P2E.7)
//!
//! `cx:circle:` is a recognised typed-id prefix in the wider Contrix
//! identifier space, but the directory MUST NEVER store, project, or
//! advertise any Circle. teabay deliberately **does not** add a
//! `Circle` variant to [`IdClass`]: the only correct response to an
//! incoming `cx:circle:<uuid>` is a reject at the ingest edge (see
//! [`crate::filter::circle_isolation`]), not a parse-and-store. The
//! parser tolerance is "recognise the shape to refuse it",
//! implemented via the substring sentinel in
//! `circle_isolation::CIRCLE_TYPED_ID_PREFIX`.

use contrix_sdk::identifiers::is_lowercase_uuidv7;
use contrix_sdk::new_prefixed_uuid7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdClass {
    Announce,
    Withdraw,
    Subscription,
    AuditAck,
}

impl IdClass {
    fn prefix(self) -> &'static str {
        match self {
            Self::Announce => "cx:announce:",
            Self::Withdraw => "cx:withdraw:",
            Self::Subscription => "cx:subscription:",
            Self::AuditAck => "cx:audit_ack:",
        }
    }
}

pub fn new_id(class: IdClass) -> String {
    new_prefixed_uuid7(class.prefix())
}

/// Recognise a teabay-issued id and its class. The suffix is validated as a
/// canonical lower-case UUIDv7 so malformed ids are rejected.
pub fn parse(id: &str) -> Option<IdClass> {
    for class in [
        IdClass::Announce,
        IdClass::Withdraw,
        IdClass::Subscription,
        IdClass::AuditAck,
    ] {
        if let Some(rest) = id.strip_prefix(class.prefix())
            && is_lowercase_uuidv7(rest)
        {
            return Some(class);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_id_round_trips_through_parse() {
        for class in [
            IdClass::Announce,
            IdClass::Withdraw,
            IdClass::Subscription,
            IdClass::AuditAck,
        ] {
            let id = new_id(class);
            assert_eq!(parse(&id), Some(class));
        }
    }

    #[test]
    fn audit_ack_prefix_is_not_abbreviated() {
        assert!(new_id(IdClass::AuditAck).starts_with("cx:audit_ack:"));
    }

    #[test]
    fn parse_rejects_non_uuidv7_suffix() {
        assert_eq!(parse("cx:announce:not-a-uuid"), None);
    }
}

//! ULID-prefixed identifiers used by teabay.
//!
//! All teabay-issued ids are `cx:<class>:<ULID>`. The ULID is monotonic
//! within a single process, which gives us natural ordering for audit logs
//! without a separate sequence column.
//!
//! ## CXP-0007 `cx:circle:` tolerance (P2E.7)
//!
//! `cx:circle:` is a recognised typed-id prefix in the wider Contrix
//! identifier space, but the directory MUST NEVER store, project, or
//! advertise any Circle. teabay deliberately **does not** add a
//! `Circle` variant to [`IdClass`]: the only correct response to an
//! incoming `cx:circle:<ulid>` is a reject at the ingest edge (see
//! [`crate::filter::circle_isolation`]), not a parse-and-store. The
//! parser tolerance is "recognise the shape to refuse it",
//! implemented via the substring sentinel in
//! `circle_isolation::CIRCLE_TYPED_ID_PREFIX`.

use ulid::Ulid;

#[derive(Clone, Copy, Debug)]
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
            Self::AuditAck => "cx:ack:",
        }
    }
}

pub fn new_id(class: IdClass) -> String {
    format!("{}{}", class.prefix(), Ulid::new())
}

pub fn parse(id: &str) -> Option<(IdClass, Ulid)> {
    for class in [
        IdClass::Announce,
        IdClass::Withdraw,
        IdClass::Subscription,
        IdClass::AuditAck,
    ] {
        if let Some(rest) = id.strip_prefix(class.prefix()) {
            if let Ok(ulid) = Ulid::from_string(rest) {
                return Some((class, ulid));
            }
        }
    }
    None
}

//! ULID-prefixed identifiers used by chadex.
//!
//! All chadex-issued ids are `cx:<class>:<ULID>`. The ULID is monotonic
//! within a single process, which gives us natural ordering for audit logs
//! without a separate sequence column.

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

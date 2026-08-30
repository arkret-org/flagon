//! UUIDv7-prefixed identifiers used by teabay.
//!
//! `ak:announce:` and `ak:subscription:` are registered protocol typed ids. Other teabay-issued
//! ids are Directory-local references and deliberately stay outside the
//! reserved `ak:` namespace.
//!
//! ## AKP-0007 `ak:circle:` tolerance (P2E.7)
//!
//! `ak:circle:` is a recognised typed-id prefix in the wider Arkret
//! identifier space, but teabay MUST NOT generate or store Circle as a
//! top-level directory resource. teabay deliberately **does not** add a
//! `Circle` variant to [`IdClass`]: Circle directory preview/stub handling is
//! a projection concern in [`crate::filter::circle_directory`], while
//! [`crate::filter::circle_isolation`] still rejects every Circle typed-id
//! occurrence outside the narrow announce preview-entry id field.

use arkret_sdk::identifiers::is_lowercase_typed_uuid;
use arkret_sdk::new_prefixed_uuid7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdClass {
    Announce,
    Withdraw,
    Appeal,
    Subscription,
    AuditAck,
}

impl IdClass {
    fn prefix(self) -> &'static str {
        match self {
            Self::Announce => "ak:announce:",
            Self::Withdraw => "withdrawal:",
            Self::Appeal => "teabay:appeal:",
            Self::Subscription => "ak:subscription:",
            Self::AuditAck => "teabay:audit_ack:",
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
        IdClass::Appeal,
        IdClass::Subscription,
        IdClass::AuditAck,
    ] {
        if let Some(rest) = id.strip_prefix(class.prefix())
            && is_lowercase_typed_uuid(rest, b'7')
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
            IdClass::Appeal,
            IdClass::Subscription,
            IdClass::AuditAck,
        ] {
            let id = new_id(class);
            assert_eq!(parse(&id), Some(class));
        }
    }

    #[test]
    fn audit_ack_prefix_is_not_abbreviated() {
        assert!(new_id(IdClass::AuditAck).starts_with("teabay:audit_ack:"));
    }

    #[test]
    fn subscription_ids_match_the_registered_sdk_wire_type() {
        let id = new_id(IdClass::Subscription);
        let typed = arkret_sdk::SubscriptionId::new(id.clone()).unwrap();
        assert_eq!(typed.as_str(), id);
        assert_eq!(parse(&id), Some(IdClass::Subscription));
        let retired = id.replacen("ak:subscription:", "teabay:subscription:", 1);
        assert!(arkret_sdk::SubscriptionId::new(retired.clone()).is_err());
        assert!(parse(&retired).is_none());
    }

    #[test]
    fn withdrawal_references_use_the_closed_public_dto_prefix() {
        let reference = new_id(IdClass::Withdraw);
        assert!(reference.starts_with("withdrawal:"));
        assert_eq!(parse(&reference), Some(IdClass::Withdraw));
        assert!(!reference.starts_with("ak:"));
    }

    #[test]
    fn parse_rejects_non_uuidv7_suffix() {
        assert_eq!(parse("ak:announce:not-a-uuid"), None);
    }
}

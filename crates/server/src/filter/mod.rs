//! Authorization, freshness, and anti-enumeration filters.
//!
//! Spec references:
//!   - §3 / §11 anti-enumeration (member-count buckets, blinded `not_found`, timing equalization)
//!   - §9.1 normative result envelope (`as_of`, `source_refs`, `policy_revision`, `stale?`,
//!     `divergent?`, `via_services`)

pub mod circle_isolation;
pub mod discoverers;
pub mod enumeration;
pub mod result;
pub mod selector;

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::{LdDatabase, LdListChecks, LdRefreshCw, LdShield};

#[component]
pub fn RefreshIcon() -> Element {
    rsx! { Icon { icon: LdRefreshCw, class: "button-icon", title: Some("Refresh".to_string()), style: None } }
}

#[component]
pub fn ListIcon() -> Element {
    rsx! { Icon { icon: LdListChecks, class: "button-icon", title: Some("Verify".to_string()), style: None } }
}

#[component]
pub fn ShieldIcon() -> Element {
    rsx! { Icon { icon: LdShield, class: "button-icon", title: Some("Status".to_string()), style: None } }
}

#[component]
pub fn DatabaseIcon() -> Element {
    rsx! { Icon { icon: LdDatabase, class: "button-icon", title: Some("Status".to_string()), style: None } }
}

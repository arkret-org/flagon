use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::{
    LdDatabase, LdFileText, LdLayoutDashboard, LdListChecks, LdPlus, LdRefreshCw, LdSave, LdSearch,
    LdSend, LdShield, LdTrash2,
};

#[component]
pub fn RefreshIcon() -> Element {
    rsx! {
        Icon {
            icon: LdRefreshCw,
            class: "button-icon",
            title: Some("Refresh".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn SearchIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSearch,
            class: "button-icon",
            title: Some("Search".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn SaveIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSave,
            class: "button-icon",
            title: Some("Save".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn TrashIcon() -> Element {
    rsx! {
        Icon {
            icon: LdTrash2,
            class: "button-icon",
            title: Some("Delete".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn SendIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSend,
            class: "button-icon",
            title: Some("Submit".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn ListIcon() -> Element {
    rsx! {
        Icon {
            icon: LdListChecks,
            class: "button-icon",
            title: Some("Load".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn ShieldIcon() -> Element {
    rsx! {
        Icon {
            icon: LdShield,
            class: "button-icon",
            title: Some("Status".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn DashboardIcon() -> Element {
    rsx! {
        Icon {
            icon: LdLayoutDashboard,
            class: "button-icon",
            title: Some("Dashboard".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn DatabaseIcon() -> Element {
    rsx! {
        Icon {
            icon: LdDatabase,
            class: "button-icon",
            title: Some("Status".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn FileIcon() -> Element {
    rsx! {
        Icon {
            icon: LdFileText,
            class: "button-icon",
            title: Some("File".to_string()),
            style: None,
        }
    }
}

#[component]
pub fn PlusIcon() -> Element {
    rsx! {
        Icon {
            icon: LdPlus,
            class: "button-icon",
            title: Some("Add".to_string()),
            style: None,
        }
    }
}

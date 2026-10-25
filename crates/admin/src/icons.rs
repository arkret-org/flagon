use glory::prelude::*;

pub fn icon(name: &str) -> impl Widget + use<> {
    text()
        .kind(TextKind::Inline)
        .class(format!("button-icon icon-{name}"))
        .content("")
}

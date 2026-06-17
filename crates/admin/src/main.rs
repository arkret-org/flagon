mod api;
mod icons;
mod model;
mod panels;
mod shell;

use crate::shell::App;

fn main() {
    dioxus::launch(App);
}

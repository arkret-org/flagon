mod api;
mod icons;
mod model;
mod shell;

pub use shell::app;

#[cfg(target_arch = "wasm32")]
thread_local! {
    static APP: std::cell::RefCell<Option<glory::web::WebApp>> = const { std::cell::RefCell::new(None) };
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() -> Result<(), wasm_bindgen::JsValue> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or("missing document")?;
    let root = document
        .get_element_by_id("app")
        .ok_or("missing app root")?;
    let app = glory::web::launch_with(root, shell::app)
        .map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))?;
    // Application rules must follow the host's semantic reset.
    if let Some(stylesheet) = document.query_selector("link[href='/main.css']")?
        && let Some(parent) = stylesheet.parent_node()
    {
        parent.append_child(&stylesheet)?;
    }
    APP.with(|slot| *slot.borrow_mut() = Some(app));
    Ok(())
}

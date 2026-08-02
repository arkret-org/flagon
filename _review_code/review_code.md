# Review code

## 2026-08-01 — directory describe used a retired free-form binding literal

- Surface: canonical `ServiceDescribe.supported_bindings`.
- Regression: Teabay passed `"http_json"` to `SupportedBinding::new` after the protocol SDK made
  binding kinds a closed generated enum, so the service no longer compiled on the current kernel.
- Correction: the directory now constructs the entry with `BindingKind::HttpJson`.
- Prevention dimension: registry-owned transport discriminators must use generated enums at every
  service boundary; string literals conceal kernel migrations until a downstream workspace build.

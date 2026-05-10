# teabay-admin

Dioxus web console for teabay operator workflows.

Run with Dioxus CLI:

```powershell
dx serve --platform web --port 8080
```

Use `dx` 0.7.9+ for a clean dev-server run with the 0.7.9 app crate.
Point the API base field at the teabay service, usually `http://localhost:7781`,
and use `TEABAY_ADMIN_TOKEN` as the bearer token.

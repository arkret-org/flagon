# admin

Dioxus web console for teabay operator workflows and direct data management.

Run with Dioxus CLI:

```powershell
cd crates/admin
dx serve --platform web --port 8080
```

Use `dx` 0.7.9+ for a clean dev-server run with the 0.7.9 app crate.
Point the API base field at the teabay service, usually `http://localhost:7781`,
and use the development `TEABAY_ADMIN_TOKEN` or a production rotating HMAC
bearer as the token. The `Resources` tab can now
create, edit, and delete indexed directory rows in addition to browsing them.

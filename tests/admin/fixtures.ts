import type { Page } from "@playwright/test";
export const events = [
  {
    audit_id: 14,
    occurred_at: "2026-10-25T09:20:00Z",
    kind: "directory.query",
    resource_kind: "realm",
    resource_id: "ak:realm:AUwZORI60DxE1STM676ap_m1sIzBcRRCjoewWDPyAjx-",
    actor_id: "ak:did_core:web:alice.example",
    authenticated_credential_id: "operator-1",
    asserted_operator_localpart: "alice",
    authentication_method: "bearer_hmac",
    detail: { query: "engineering", result_count: 8 },
  },
  {
    audit_id: 15,
    occurred_at: "2026-10-25T10:05:00Z",
    kind: "admin.audit.verify",
    resource_kind: null,
    resource_id: null,
    actor_id: "ak:did_core:web:admin.example",
    authenticated_credential_id: "operator-1",
    asserted_operator_localpart: "operator",
    authentication_method: "bearer_hmac",
    detail: {
      reason: "Scheduled append-only chain verification",
      checked_rows: 1284,
    },
  },
];
export const verified = {
  ok: true,
  checked_rows: 1284,
  chain_rows: 1284,
  first_audit_id: 1,
  last_audit_id: 1284,
  head_digest: "sha256:" + "a".repeat(64),
  failure: null,
};
export const failed = {
  ...verified,
  ok: false,
  checked_rows: 14,
  failure: {
    audit_id: 15,
    reason: "previous_digest_mismatch",
    expected: "sha256:" + "a".repeat(64),
    actual: "sha256:" + "b".repeat(64),
  },
};
export async function setup(page: Page) {
  const requests: { url: string; authorization: string | undefined }[] = [];
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error" && /Glory|flagon region/.test(m.text()))
      errors.push(m.text());
  });
  await page.route("**/_flagon/admin/**", async (route) => {
    const request = route.request();
    requests.push({
      url: request.url(),
      authorization: request.headers().authorization,
    });
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/audit/verify"))
      return route.fulfill({ json: verified });
    if (path.endsWith("/audit"))
      return route.fulfill({ json: { events, next_since: null } });
    return route.fulfill({
      status: 404,
      json: { error: "unexpected fixture request" },
    });
  });
  return { requests, errors };
}

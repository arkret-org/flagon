import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { events, failed, setup, verified } from "./fixtures";

async function openConnectionSettings(page: Page) {
  const connection = page.getByRole("button", {
    name: "Connection settings",
    exact: true,
  });
  if ((await connection.getAttribute("aria-expanded")) === "false") {
    await connection.click();
  }
}
async function capture(page: any, name: string) {
  await page.screenshot({
    path: test.info().outputPath(name + ".png"),
    fullPage: true,
  });
  const viewport = page.viewportSize();
  expect(viewport).not.toBeNull();
  const documentWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(documentWidth).toBeLessThanOrEqual(viewport!.width);
  await expect(page.locator("h1")).toHaveCSS("font-weight", "700");
  await expect(page.getByRole("columnheader")).toHaveText([
    "Time",
    "Kind",
    "Resource",
    "Actor",
    "Detail",
  ]);
}

test("responsive audit controls retain rows, verification and failure states", async ({
  page,
}) => {
  test.setTimeout(90000);
  const { errors } = await setup(page);
  for (const [name, width, height] of [
    ["desktop", 1440, 900],
    ["mobile", 390, 844],
  ] as const) {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Audit log", exact: true }),
    ).toBeVisible();
    await expect(page.locator(".status-line")).toHaveText(
      "Connection changed. Load the audit log or verify the full chain.",
    );
    await capture(page, "idle-" + name);
    await page.getByRole("button", { name: /Load/ }).click();
    await expect(page.getByRole("row")).toHaveCount(3);
    await expect(page.locator(".status-line")).toContainText("2 audit events");
    await capture(page, "loaded-" + name);
    await page.getByRole("button", { name: /Verify/ }).click();
    await expect(page.locator(".result-box")).toContainText("chain_rows: 1284");
    await capture(page, "verified-" + name);
    await page.route("**/_flagon/admin/audit/verify", (r) =>
      r.fulfill({ json: failed }),
    );
    await page.getByRole("button", { name: /Verify/ }).click();
    await expect(page.locator(".result-box")).toContainText(
      "previous_digest_mismatch",
    );
    await capture(page, "chain-failure-" + name);
    await page.route("**/_flagon/admin/audit?*", (r) =>
      r.fulfill({ status: 503, body: "Upstream unavailable" }),
    );
    await page.getByRole("button", { name: /Load/ }).click();
    await expect(page.locator(".status-line")).toContainText("HTTP 503");
    await expect(page.getByRole("row")).toHaveCount(3);
    await capture(page, "query-error-" + name);
    await page.route("**/_flagon/admin/audit?*", (r) =>
      r.fulfill({ json: { events: [], next_since: null } }),
    );
    await page.getByRole("button", { name: /Load/ }).click();
    await expect(page.getByRole("row")).toHaveCount(1);
    await capture(page, "empty-" + name);
    await page.unroute("**/_flagon/admin/audit?*");
    await page.unroute("**/_flagon/admin/audit/verify");
  }
  expect(errors).toEqual([]);
});

test("current settings and filters reach typed requests without exposing the token", async ({
  page,
}) => {
  const { requests, errors } = await setup(page);
  await page.goto("/");
  const apiBase = page.getByRole("textbox", { name: "API base", exact: true });
  const token = page.getByLabel("Bearer token", { exact: true });
  const connection = page.getByRole("button", {
    name: "Connection settings",
    exact: true,
  });
  await expect(connection).toBeVisible();
  if ((await connection.getAttribute("aria-expanded")) === "false") {
    await connection.click();
  }
  await apiBase.fill("http://directory.example/");
  await token.fill("  private-operator-token  ");
  await page.getByLabel("Since", { exact: true }).fill("2026-10-25T00:00:00Z");
  await page.getByLabel("Limit", { exact: true }).fill("25");
  await page.getByRole("button", { name: /Load/ }).click();
  await expect(page.getByRole("row")).toHaveCount(3);
  expect(new URL(requests.at(-1)!.url).origin).toBe("http://directory.example");
  expect(new URL(requests.at(-1)!.url).searchParams.get("limit")).toBe("25");
  expect(new URL(requests.at(-1)!.url).searchParams.get("since")).toBe(
    "2026-10-25T00:00:00Z",
  );
  expect(requests.at(-1)!.authorization).toBe("Bearer private-operator-token");
  await expect(token).toHaveAttribute("type", "password");
  expect(await page.locator("body").innerText()).not.toContain(
    "private-operator-token",
  );
  expect(errors).toEqual([]);
});

test("loading fences both actions and retry retains query inputs", async ({
  page,
}) => {
  const { requests, errors } = await setup(page);
  let release: any;
  await page.route("**/_flagon/admin/audit?*", async (route) => {
    await new Promise((resolve) => (release = resolve));
    await route.fulfill({ status: 503, body: "Retry later" });
  });
  await page.goto("/");
  await page.locator(".toolbar input").nth(0).fill("2026-10-20T00:00:00Z");
  await page.getByRole("button", { name: /Load/ }).click();
  await expect(page.getByRole("button", { name: /Load/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Verify/ })).toBeDisabled();
  await expect.poll(() => typeof release).toBe("function");
  release();
  await expect(page.locator(".status-line")).toContainText("HTTP 503");
  await expect(page.locator(".toolbar input").nth(0)).toHaveValue(
    "2026-10-20T00:00:00Z",
  );
  await page.unroute("**/_flagon/admin/audit?*");
  await page.getByRole("button", { name: /Load/ }).click();
  await expect(page.getByRole("row")).toHaveCount(3);
  expect(requests.filter((r) => r.url.includes("/audit?"))).toHaveLength(1);
  expect(errors).toEqual([]);
});

test("invalid limits cannot submit and Unicode details stay bounded plain text", async ({
  page,
}) => {
  const { errors } = await setup(page);
  let query = "";
  await page.route("**/_flagon/admin/audit?*", async (r) => {
    query = r.request().url();
    await r.fulfill({
      json: {
        events: [
          {
            ...events[0],
            detail: {
              message: "<img src=x onerror=alert(1)>秘密🙂".repeat(60),
            },
          },
        ],
        next_since: null,
      },
    });
  });
  await page.goto("/");
  const limit = page.getByLabel("Limit", { exact: true });
  const load = page.getByRole("button", { name: "Load", exact: true });
  for (const invalid of ["", "0", "501"]) {
    await limit.fill(invalid);
    await expect(load).toBeDisabled();
    await expect(page.locator(".query-error")).not.toBeEmpty();
    expect(query).toBe("");
  }
  await page.getByRole("button", { name: "100", exact: true }).click();
  await expect(limit).toHaveValue("100");
  const since = page.getByLabel("Since", { exact: true });
  await since.fill("2026-11-14T10:00:00");
  await expect(load).toBeDisabled();
  expect(query).toBe("");
  await since.fill("2026-11-14T10:00:00+08:00");
  await expect(load).toBeEnabled();
  await load.click();
  await expect(page.getByRole("row")).toHaveCount(2);
  expect(new URL(query).searchParams.get("limit")).toBe("100");
  expect(new URL(query).searchParams.get("since")).toBe(
    "2026-11-14T10:00:00+08:00",
  );
  await expect(page.locator(".query-context")).toContainText(
    "2026-11-14T10:00:00+08:00",
  );
  const excerpt = await page.locator(".audit-excerpt").innerText();
  expect(Array.from(excerpt)).toHaveLength(220);
  expect(excerpt).toContain("<img src=x onerror=alert(1)>秘密🙂");
  expect(excerpt).not.toContain("\uFFFD");
  expect(await page.locator("tbody img").count()).toBe(0);
  expect(errors).toEqual([]);
});

test("verification stays with the current connection after a delayed previous response", async ({
  page,
}) => {
  const { errors } = await setup(page);
  const digestA = "a".repeat(64);
  const digestB = "b".repeat(64);
  let delay = false;
  let held = false;
  let unavailable = false;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  await page.route("**/_flagon/admin/audit/verify", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (delay && path.startsWith("/service-a/")) {
      held = true;
      await gate;
    }
    if (unavailable) {
      return route.fulfill({ status: 503, body: "Try later" });
    }
    return route.fulfill({
      json: {
        ...verified,
        head_digest: path.startsWith("/service-b/") ? digestB : digestA,
      },
    });
  });
  try {
    await page.goto("/");
    const base = new URL(page.url()).origin;
    const address = page.getByLabel("API base", { exact: true });
    const verify = page.getByRole("button", { name: "Verify", exact: true });
    const result = page.locator(".result-box");
    await address.fill(base + "/service-a");
    await verify.click();
    await expect(result).toContainText(base + "/service-a");
    await expect(result).toContainText(digestA);
    await expect(result).toContainText(/Completed at .*UTC.*\d{4}-\d{2}-\d{2}T/);
    await expect(result).toContainText("independently of the list filters");
    await page.getByRole("button", { name: "Load", exact: true }).click();
    await expect(result).toHaveCount(0);
    await expect(page.getByRole("row")).toHaveCount(3);

    delay = true;
    await verify.click();
    await expect.poll(() => held).toBe(true);
    await openConnectionSettings(page);
    await address.fill(base + "/service-b");
    await expect(page.getByRole("row")).toHaveCount(1);
    await expect(verify).toBeEnabled();
    await verify.click();
    await expect(result).toContainText(digestB);
    const oldResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname ===
        "/service-a/_flagon/admin/audit/verify",
    );
    release();
    await (await oldResponse).finished();
    await page.evaluate(
      () => new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
    );
    await expect(result).toContainText(base + "/service-b");
    await expect(result).not.toContainText(digestA);

    await openConnectionSettings(page);
    const token = "unpersisted-operator-token";
    await page.getByLabel("Bearer token", { exact: true }).fill(token);
    await expect(result).toHaveCount(0);
    unavailable = true;
    await verify.click();
    await expect(page.locator(".status-line")).toContainText("HTTP 503");
    await expect(result).toHaveCount(0);
    expect(
      await page.evaluate(
        (secret) => Object.values(localStorage).some((value) => value.includes(secret)),
        token,
      ),
    ).toBe(false);
    expect(errors).toEqual([]);
  } finally {
    release();
  }
});

test("full audit records preserve Unicode, clipboard content and large details", async ({
  page,
  context,
}) => {
  const { errors } = await setup(page);
  let detail: Record<string, unknown> = {
    reason: "完整授权详情 / Unicode — END",
    nested: { values: [1, 2, "原文"] },
    long: "long-detail-".repeat(1000),
  };
  let unauthorized = false;
  await page.route("**/_flagon/admin/audit?*", (route) =>
    unauthorized
      ? route.fulfill({
          status: 401,
          json: { type: "about:blank", title: "Unauthorized", status: 401 },
        })
      : route.fulfill({
          json: { events: [{ ...events[0], detail }], next_since: null },
        }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const load = page.getByRole("button", { name: "Load", exact: true });
  const open = page.getByRole("button", { name: "View full record", exact: true });
  const field = page.getByRole("textbox", { name: "Full audit record JSON", exact: true });
  await load.click();
  await expect(open).toBeVisible();
  await expect(page.getByRole("button", { name: "Connection settings", exact: true }))
    .toHaveAttribute("aria-expanded", "false");
  await open.click();
  await expect(field).toHaveValue(/完整授权详情/);
  const original = await field.inputValue();
  expect(JSON.parse(original)).toEqual({ ...events[0], detail });
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.getByRole("button", { name: "Copy full JSON", exact: true }).click();
  await expect(page.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
  // Windows clipboard text uses CRLF while textarea values use LF.
  await expect.poll(async () =>
    (await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n"),
  ).toBe(original);
  await page.screenshot({ path: test.info().outputPath("full-record-mobile.png"), fullPage: true });
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(open).toBeFocused();
  await open.click();
  await expect(field).toHaveValue(original);
  await page.keyboard.press("Escape");
  await expect(field).toHaveCount(0);

  detail = { huge: "大记录".repeat(25000), last: "FULL_RECORD_END" };
  await load.click();
  await expect(page.locator(".audit-excerpt")).toContainText("大记录");
  await open.click();
  await expect(field).toHaveValue(/FULL_RECORD_END/);
  expect(JSON.parse(await field.inputValue())).toEqual({ ...events[0], detail });
  await expect(page.getByRole("button", { name: "Copy full JSON", exact: true }))
    .toHaveCount(0);
  await expect(page.getByText(/Large record: select/)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(field).toHaveCount(0);
  unauthorized = true;
  await load.click();
  await expect(page.locator(".status-line")).toContainText("HTTP 401");
  expect(errors).toEqual([]);
});

test("public audit controls have labels and keyboard access without serious accessibility violations", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/");
  await page.getByRole("textbox", { name: "API base", exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Bearer token", { exact: true })).toBeFocused();
  const audit = await new AxeBuilder({ page }).analyze();
  expect(
    audit.violations.filter((v) =>
      ["critical", "serious"].includes(v.impact || ""),
    ),
  ).toEqual([]);
});

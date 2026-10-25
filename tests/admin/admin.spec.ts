import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { writeFile } from "node:fs/promises";
import { events, failed, setup } from "./fixtures";
async function capture(page: any, name: string) {
  await page.screenshot({
    path: test.info().outputPath(name + ".png"),
    fullPage: true,
  });
  const metrics = await page.evaluate(() => {
    const out: any = {
      viewport: innerWidth,
      documentWidth: document.documentElement.scrollWidth,
    };
    for (const name of [
      ".topbar",
      ".brand-title",
      ".workspace",
      ".panel-head",
      "h1",
      ".toolbar",
      ".table-wrap",
      "input",
      "th",
      "td",
    ]) {
      const el = document.querySelector(name);
      if (el) {
        const box = el.getBoundingClientRect(),
          css = getComputedStyle(el);
        out[name] = {
          x: box.x,
          y: box.y,
          width: box.width,
          height: box.height,
          fontSize: css.fontSize,
          lineHeight: css.lineHeight,
          fontWeight: css.fontWeight,
        };
      }
    }
    return out;
  });
  await writeFile(
    test.info().outputPath(name + ".json"),
    JSON.stringify(metrics, null, 2),
  );
  if (!process.env.FLAGON_E2E_BASELINE) {
    expect(metrics.documentWidth).toBeLessThanOrEqual(metrics.viewport);
    expect(metrics.h1.fontWeight).toBe("700");
  }
  await expect(page.getByRole("columnheader")).toHaveText([
    "Time",
    "Kind",
    "Resource",
    "Actor",
    "Detail",
  ]);
}

test("original-page-layout retains audit controls, rows, verification and failure states", async ({
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
    await expect(page.locator(".status-line")).toContainText("Idle");
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
  await page.locator(".topbar input").nth(0).fill("http://directory.example/");
  await page.locator(".topbar input").nth(1).fill("  private-operator-token  ");
  await page.locator(".toolbar input").nth(0).fill("2026-10-25T00:00:00Z");
  await page.locator(".toolbar input").nth(1).fill("25");
  await page.getByRole("button", { name: /Load/ }).click();
  await expect(page.getByRole("row")).toHaveCount(3);
  expect(new URL(requests.at(-1)!.url).origin).toBe("http://directory.example");
  expect(new URL(requests.at(-1)!.url).searchParams.get("limit")).toBe("25");
  expect(new URL(requests.at(-1)!.url).searchParams.get("since")).toBe(
    "2026-10-25T00:00:00Z",
  );
  expect(requests.at(-1)!.authorization).toBe("Bearer private-operator-token");
  await expect(page.locator(".topbar input").nth(1)).toHaveAttribute(
    "type",
    "password",
  );
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

test("empty limits use the original default and Unicode details stay bounded plain text", async ({
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
            detail: { message: "<img src=x onerror=alert(1)>秘密".repeat(60) },
          },
        ],
        next_since: null,
      },
    });
  });
  await page.goto("/");
  await page.locator(".toolbar input").nth(1).fill("");
  await page.getByRole("button", { name: /Load/ }).click();
  await expect(page.getByRole("row")).toHaveCount(2);
  expect(new URL(query).searchParams.get("limit")).toBe("100");
  expect(await page.locator("tbody td").last().innerText()).toHaveLength(220);
  expect(await page.locator("tbody img").count()).toBe(0);
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

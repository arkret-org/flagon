const { chromium, expect } = require(process.env.FLAGON_PLAYWRIGHT_MODULE || '@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const base = process.env.FLAGON_TEST_URL || 'http://127.0.0.1:4184';
const out = path.resolve(process.env.FLAGON_TEST_ARTIFACTS || path.join(__dirname, '../artifacts/frontend-design'));
const verdict = digest => ({ ok: true, checked_rows: 1, chain_rows: 1, first_audit_id: 1, last_audit_id: 1, head_digest: digest, failure: null });

(async () => {
  await fs.mkdir(out, { recursive: true });
  const browser = await chromium.launch({ channel: process.env.FLAGON_BROWSER_CHANNEL || 'msedge' });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  let delayed = false, failed = false, release;
  let pending;
  await page.route('**/_flagon/admin/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/verify')) {
      if (delayed && url.pathname.startsWith('/service-a/')) {
        pending = route;
        await new Promise(resolve => { release = resolve; });
      }
      if (failed) return route.fulfill({ status: 503, contentType: 'application/problem+json', body: JSON.stringify({ type: 'about:blank', title: 'Try later', status: 503 }) });
      return route.fulfill({ json: verdict(url.pathname.startsWith('/service-b/') ? 'service-b-digest' : 'service-a-digest') });
    }
    return route.fulfill({ json: { events: [{ audit_id: 1, occurred_at: '2026-11-14T10:00:00Z', kind: 'test.audit', resource_kind: 'record', resource_id: 'record-1', actor_id: null, authenticated_credential_id: null, asserted_operator_localpart: null, authentication_method: null, detail: { reason: 'Visible authorized audit detail' } }], next_since: null } });
  });
  try {
    await page.goto(base);
    const address = page.getByLabel('API base', { exact: true });
    const verify = page.getByRole('button', { name: 'Verify', exact: true });
    const result = page.locator('.result-box');
    await address.fill(base + '/service-a');
    await verify.click();
    await expect(result).toContainText(base + '/service-a');
    await expect(result).toContainText(/Completed at .*UTC.*\d{4}-\d{2}-\d{2}T/);
    await expect(result).toContainText('independently of the list filters');
    await page.getByLabel('Since', { exact: true }).fill('2026-11-14T00:00:00Z');
    await page.getByRole('button', { name: 'Load', exact: true }).click();
    await expect(result).toHaveCount(0);
    await expect(page.getByText('record-1', { exact: true })).toBeVisible();

    delayed = true;
    await verify.click();
    await expect.poll(() => Boolean(pending)).toBe(true);
    await address.fill(base + '/service-b');
    await expect(page.getByText('record-1', { exact: true })).toHaveCount(0);
    await expect(verify).toBeEnabled();
    await verify.click();
    await expect(result).toContainText('service-b-digest');
    const response = page.waitForResponse(response => response.url().includes('/service-a/') && response.url().endsWith('/verify'));
    release();
    await response;
    await expect(result).toContainText(base + '/service-b');
    await expect(result).not.toContainText('service-a-digest');
    await page.screenshot({ path: path.join(out, 'verification-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(out, 'verification-mobile.png'), fullPage: true });

    await page.getByLabel('Bearer token', { exact: true }).fill('test-only-token');
    await expect(result).toHaveCount(0);
    failed = true;
    await verify.click();
    await expect(page.getByRole('status')).toContainText('HTTP 503');
    await expect(result).toHaveCount(0);
    expect(errors).toEqual([]);
    await fs.writeFile(path.join(out, 'verification-results.json'), JSON.stringify({ passed: true, current_service: 'service-b', delayed_previous_result_rejected: true, token_change_invalidates: true, failure_clears_success: true }, null, 2));
  } finally {
    if (release) release();
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

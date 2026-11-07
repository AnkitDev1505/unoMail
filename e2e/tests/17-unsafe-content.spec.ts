import { expect, test } from '@playwright/test';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { DOMAIN, login, logout, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so these messages do not show up in the other specs.
const ERIN = `erin@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

function phishing(subject: string, attachment: string) {
  return [
    `From: "support@paypal.com" <jane@evil.test>`,
    `To: ${ERIN}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Your account is locked. <a href="https://evil.test/login">https://paypal.com/login</a></p><p><a href="https://example.org/help">Help</a></p>',
    '--b1',
    'Content-Type: application/octet-stream',
    `Content-Disposition: attachment; filename="${attachment}"`,
    'Content-Transfer-Encoding: base64',
    '',
    'UEsDBAoAAAAAAA==',
    '--b1--',
    '',
  ].join('\n');
}

test.describe('unsafe content', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(ERIN);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByText(/already exists/).first())).toBeVisible();
    await page.close();
  });

  test('deceptive links, risky attachments and misleading names are flagged', async ({ page }) => {
    await smtpDeliver('jane@evil.test', ERIN, phishing('Account locked', 'budget.xlsm'));
    await login(page, ERIN, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Account locked' }).click();

    await expect(page.getByTestId('sender-name-warning')).toContainText('support@paypal.com');

    // The link names paypal.com but goes elsewhere: the reader asks first, Cancel is the default.
    const body = page.frameLocator('iframe[title="Message body"]');
    await body.getByRole('link', { name: 'https://paypal.com/login' }).click();
    const linkDialog = page.getByRole('dialog', { name: 'Careful with this link' });
    await expect(linkDialog).toContainText('The link says paypal.com, but it goes to evil.test.');
    await expect(linkDialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
    const popups: string[] = [];
    page.context().on('page', (popup) => popups.push(popup.url()));
    await linkDialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(linkDialog).toBeHidden();
    // An honest link shows its destination and opens without a question.
    await expect(body.getByRole('link', { name: 'Help' })).toHaveAttribute('title', 'https://example.org/help');

    // A macro-enabled document is marked and needs a confirmation before it is saved.
    const chip = page.locator('[data-risk="caution"]').filter({ hasText: 'budget.xlsm' });
    await expect(chip).toBeVisible();
    await chip.click();
    const fileDialog = page.getByRole('dialog', { name: 'Download budget.xlsm?' });
    await expect(fileDialog).toContainText('macros');
    const download = page.waitForEvent('download');
    await fileDialog.getByRole('button', { name: 'Download anyway' }).click();
    expect((await download).suggestedFilename()).toBe('budget.xlsm');
    expect(popups).toEqual([]);
  });

  test('programs are refused by the server, inbound and from the web client', async ({ page }) => {
    await expect(smtpDeliver('jane@evil.test', ERIN, phishing('Your invoice', 'Invoice.pdf.exe'))).rejects.toThrow(
      /552 5\.7\.0 Message refused: it contains an executable attachment \(Invoice\.pdf\.exe\)/,
    );
    await expect(smtpDeliver('jane@evil.test', ERIN, phishing('Zipped invoice', 'invoice.zip'))).resolves.toBeUndefined();

    await login(page, ERIN, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(ERIN);
    await composer.getByLabel('Subject').fill('Here is the tool');
    await composer.getByLabel('Attachment files').setInputFiles({ name: 'tool.scr', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ') });
    await expect(composer.getByText(/tool\.scr/)).toBeVisible();
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText(/executable attachment \(tool\.scr\)/)).toBeVisible({ timeout: 20_000 });
  });

  test('the administrator is told when mail is not scanned for viruses', async ({ page }) => {
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin');
    await expect(page.getByTestId('no-virus-scanner')).toContainText('not scanned for viruses');
    await openAdmin(page, 'Diagnostics');
    await expect(page.getByTestId('virus-scanner-status')).toContainText('not scanned for malware', { timeout: 30_000 });
    await openAdmin(page, 'Server settings');
    await expect(page.getByLabel('Refuse executable attachments')).toBeChecked();
  });

  test('links to listed phishing domains are flagged and tracking parameters removed', async ({ page }) => {
    // A feed of our own instead of Phishing Army, so the run needs no internet.
    const feed = createServer((_request, response) => response.end('# e2e feed\nphish.test\n'));
    await new Promise<void>((resolve) => feed.listen(0, '127.0.0.1', resolve));
    const feedUrl = `http://127.0.0.1:${(feed.address() as AddressInfo).port}/list.txt`;
    try {
      await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
      await openAdmin(page, 'Server settings');
      await page.getByRole('textbox', { name: 'List address' }).fill(feedUrl);
      await page.getByRole('row', { name: /List address/ }).getByRole('button', { name: 'Save' }).click();
      await expect(page.getByText('Setting saved')).toBeVisible();
      await page.getByRole('button', { name: 'Download now' }).click();
      await expect(page.getByTestId('phishing-list-status')).toContainText('Domains on the list: 1', { timeout: 20_000 });
      await logout(page);

      await smtpDeliver('news@shop.test', ERIN, [
        'From: Shop <news@shop.test>',
        `To: ${ERIN}`,
        'Subject: Verify your account',
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<p><a href="https://login.phish.test/verify">Verify now</a></p>',
        '<p><a href="https://shop.test/offer?id=7&amp;utm_source=newsletter&amp;fbclid=abc">Our offer</a></p>',
        '',
      ].join('\n'));
      await login(page, ERIN, USER_PASSWORD);
      await page.getByTestId('email-row').filter({ hasText: 'Verify your account' }).click();
      await expect(page.getByTestId('phishing-warning')).toContainText('known phishing sites');

      const body = page.frameLocator('iframe[title="Message body"]');
      await expect(body.getByRole('link', { name: 'Our offer' })).toHaveAttribute('href', 'https://shop.test/offer?id=7');
      await body.getByRole('link', { name: 'Verify now' }).click();
      const linkDialog = page.getByRole('dialog', { name: 'Careful with this link' });
      await expect(linkDialog).toContainText('login.phish.test is on a list of known phishing sites (phish.test)');
      await linkDialog.getByRole('button', { name: 'Cancel' }).click();
    } finally {
      feed.close();
    }
    // Back to the default list for the specs that follow.
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openAdmin(page, 'Server settings');
    await page.getByRole('button', { name: 'Reset List address' }).click();
    await expect(page.getByText('Reset to default')).toBeVisible();
  });
});

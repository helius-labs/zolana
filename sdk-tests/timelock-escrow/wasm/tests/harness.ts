import { test as base, expect, type Page } from "@playwright/test";

export type Harness = { page: Page };

export const test = base.extend<{ harness: Harness }, { escrowPage: Harness }>({
  escrowPage: [
    async ({ browser }, use) => {
      const page = await browser.newPage();
      await page.goto("/");
      await page.waitForFunction(() => "escrow" in window, undefined, { timeout: 60_000 });
      await use({ page });
      await page.close();
    },
    { scope: "worker" },
  ],
  harness: async ({ escrowPage }, use) => {
    const noise: string[] = [];
    const onPageError = (error: Error) => noise.push(`pageerror: ${error.message}`);
    const onConsole = (message: { type(): string; text(): string }) => {
      if (message.type() === "error") {
        noise.push(`console: ${message.text()}`);
      }
    };
    escrowPage.page.on("pageerror", onPageError);
    escrowPage.page.on("console", onConsole);
    await use(escrowPage);
    escrowPage.page.off("pageerror", onPageError);
    escrowPage.page.off("console", onConsole);
    expect(noise, "the page reported errors during this test").toEqual([]);
  },
});

export { expect };

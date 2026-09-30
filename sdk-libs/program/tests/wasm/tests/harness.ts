import { test as base, expect, type Page } from "@playwright/test";

export type Harness = { page: Page; threads: number };

export const test = base.extend<{ harness: Harness }, { programPage: Harness }>({
  programPage: [
    async ({ browser }, use) => {
      const page = await browser.newPage();
      await page.goto("/");
      await page.waitForFunction(() => "zkProgram" in window, undefined, { timeout: 60_000 });
      expect(
        await page.evaluate(() => self.crossOriginIsolated),
        "the page is not cross-origin isolated: check the COOP/COEP headers in tools/serve.mjs",
      ).toBe(true);
      const info = await page.evaluate(() => window.zkProgram.workerInfo());
      expect(info.crossOriginIsolated, "the prover worker is not cross-origin isolated").toBe(true);
      expect(info.threads, "the prover runs single-threaded: build with --threads").toBeGreaterThan(1);
      await use({ page, threads: info.threads });
      await page.close();
    },
    { scope: "worker" },
  ],
  harness: async ({ programPage }, use) => {
    const noise: string[] = [];
    const onPageError = (error: Error) => noise.push(`pageerror: ${error.message}`);
    const onConsole = (message: { type(): string; text(): string }) => {
      if (message.type() === "error") {
        noise.push(`console: ${message.text()}`);
      }
    };
    programPage.page.on("pageerror", onPageError);
    programPage.page.on("console", onConsole);
    await use(programPage);
    programPage.page.off("pageerror", onPageError);
    programPage.page.off("console", onConsole);
    expect(noise, "the page reported errors during this test").toEqual([]);
  },
});

export { expect };

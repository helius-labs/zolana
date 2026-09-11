// Runs the actual transfer circuit, one foreground browser session at a time.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";
import { proofStatistics } from "../../core/src/proof-benchmark.ts";
import { profileKernel } from "./profile-kernel.mjs";

const counts = (process.argv[2] || "2,4,8,16").split(",").map(Number);
const sessions = Number(process.argv[3] || "1");
const mode = process.argv[4] || "prove";
assert.ok(["prove", "profile", "checks"].includes(mode));
const profile = mode === "profile";
assert.ok(counts.every((n) => Number.isInteger(n) && n >= 1 && n <= 64));
assert.ok(Number.isInteger(sessions) && sessions >= 1 && sessions <= 10);
const out = resolve(process.env.DEMO_REPORT_DIR || "target/mopro-device-benchmark");
await mkdir(out, { recursive: true });
for (let session = 1; session <= sessions; session++) {
  // Reverse alternate session order to reduce systematic order effects.
  for (const count of session % 2 ? counts : [...counts].reverse()) {
    const options = new chrome.Options().addArguments("--headless", "--window-size=1200,900");
    if (process.env.CHROME_BIN) options.setChromeBinaryPath(process.env.CHROME_BIN);
    if (process.env.CHROME_NO_SANDBOX === "1") options.addArguments("--no-sandbox");
    let builder = new Builder().forBrowser("chrome").setChromeOptions(options);
    if (process.env.CHROMEDRIVER_BIN)
      builder = builder.setChromeService(new chrome.ServiceBuilder(process.env.CHROMEDRIVER_BIN));
    const driver = await builder.build();
    try {
      const url = new URL(process.env.DEMO_URL || "http://127.0.0.1:3220/benchmark.html");
      url.searchParams.set("threads", count);
      await driver.get(url.href);
      await driver.wait(until.elementLocated(By.id("run")), 30000);
      const environment = await driver.executeScript(
        "return {userAgent: navigator.userAgent, reportedThreads: navigator.hardwareConcurrency, isolated: crossOriginIsolated}",
      );
      assert.equal(environment.isolated, true);
      if (mode === "checks") {
        await driver.manage().window().setRect({ width: 390, height: 844 });
        assert.equal(
          await driver.executeScript("return document.documentElement.scrollWidth > innerWidth"),
          false,
        );
        await driver.findElement(By.id("run")).click();
        await driver.findElement(By.id("run")).click();
        await driver.wait(
          until.elementTextIs(driver.findElement(By.id("run")), "Run benchmark"),
          15000,
        );
        assert.match(await driver.findElement(By.id("error")).getText(), /Cancelled/);
        assert.equal(
          await driver.executeScript("return !!globalThis.__zolanaDeviceBenchmark"),
          false,
        );
        await driver.findElement(By.id("run")).click();
        const original = await driver.getWindowHandle();
        await driver.switchTo().newWindow("tab");
        await driver.get("about:blank");
        await driver.switchTo().window(original);
        await driver.wait(
          until.elementTextIs(driver.findElement(By.id("run")), "Run benchmark"),
          15000,
        );
        assert.match(await driver.findElement(By.id("error")).getText(), /hidden/);
        assert.equal(
          await driver.executeScript("return !!globalThis.__zolanaDeviceBenchmark"),
          false,
        );
        console.log(
          "PASS: mobile layout, cancellation, hidden-tab cancellation, no partial success report",
        );
        continue;
      }
      let report;
      if (profile) {
        const result = await profileKernel(driver, count, {
          samples: 30,
          warmups: 3,
          kernelBase: process.env.BENCH_KERNEL_BASE,
          wasmUrl: process.env.BENCH_WASM_URL,
        });
        assert.ok(!result.error, result.error);
        report = {
          environment,
          session,
          ...result,
          proof: proofStatistics(result.samples.map((x) => x.totalMs)),
          kernel: proofStatistics(result.samples.map((x) => x.kernelMs)),
          other: proofStatistics(result.samples.map((x) => x.otherMs)),
        };
      } else {
        if (process.env.BENCH_DEVICE_LABEL)
          await driver.findElement(By.id("device")).sendKeys(process.env.BENCH_DEVICE_LABEL);
        await driver.findElement(By.id("run")).click();
        await driver.wait(async () => {
          const error = await driver.findElement(By.id("error"));
          if (await error.isDisplayed()) throw new Error(await error.getText());
          return driver.executeScript("return !!globalThis.__zolanaDeviceBenchmark");
        }, 300000);
        report = await driver.executeScript("return globalThis.__zolanaDeviceBenchmark");
        assert.equal(report.samples.length, 30);
        assert.equal(report.warmups.length, 3);
        assert.equal(report.environment.workers, count);
        assert.ok(report.setup.startupMs > 0);
        assert.ok(report.setup.keyPreparationMs > 0);
        assert.equal(new Set([...report.warmups, ...report.samples].map((x) => x.proof)).size, 33);
        assert.deepEqual(report.proof, proofStatistics(report.samples.map((x) => x.proveMs)));
      }
      const name = `${profile ? "profile" : "proof"}-${count}-${session}`;
      await writeFile(`${out}/${name}.json`, JSON.stringify(report, null, 2));
      await writeFile(
        `${out}/${name}-proofs.json`,
        JSON.stringify(
          [...report.warmups, ...report.samples].map((x) => JSON.parse(x.proof)),
          null,
          2,
        ),
      );
      console.log(
        JSON.stringify({ name, proof: report.proof, kernel: report.kernel, other: report.other }),
      );
    } finally {
      await driver.quit();
    }
  }
}

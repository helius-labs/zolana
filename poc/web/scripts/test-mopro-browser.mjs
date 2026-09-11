import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";

const out =
  process.env.DEMO_REPORT_DIR ||
  fileURLToPath(new URL("../../../target/mopro-browser-ui/", import.meta.url));
await mkdir(out, { recursive: true });
const options = new chrome.Options().addArguments("--headless", "--window-size=1440,1100");
if (process.env.CHROME_BIN) options.setChromeBinaryPath(process.env.CHROME_BIN);
if (process.env.CHROME_NO_SANDBOX === "1") options.addArguments("--no-sandbox");
const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
const proofs = [];
const results = [];
const button = (text) => driver.findElement(By.xpath(`//button[normalize-space(.)='${text}']`));
const openOptions = () => driver.findElement(By.css('button[aria-label="Options"]')).click();
const closeOptions = () => driver.findElement(By.css('button[aria-label="Close options"]')).click();
async function editValue(element, value) {
  await driver.executeScript(
    function (el, next) {
      const proto =
        el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, next);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    element,
    value,
  );
}
async function run(expectedEngine) {
  await driver.findElement(By.css(".main-action .primary-button")).click();
  await driver.wait(async () => {
    const errors = await driver.findElements(By.css('[role="alert"]'));
    if (errors.length) throw new Error(await errors[0].getText());
    return (await driver.findElements(By.css(".verified"))).length > 0;
  }, 180000);
  await (await button("View proof")).click();
  const details = await driver.findElement(By.css(".proof-facts")).getText();
  assert.ok(details.includes(expectedEngine), details);
  const proof = await driver.findElement(By.css(".proof-json")).getText();
  proofs.push(JSON.parse(proof));
  results.push({ details, result: await driver.findElement(By.css(".result-area")).getText() });
  await driver.findElement(By.css('button[aria-label="Close proof"]')).click();
  console.log(results.at(-1).result.replaceAll("\n", " "));
}
try {
  await driver.get(process.env.DEMO_URL || "http://127.0.0.1:5178/");
  await driver.wait(until.elementLocated(By.css(".primary-button")), 30000);
  await driver.wait(async () => (await button("Generate proof")).isEnabled(), 30000);
  const visible = await driver.findElement(By.css("body")).getText();
  assert.doesNotMatch(
    visible,
    /Cross-origin|Funding|Endpoints|localnet|transaction|Ready when|One sample|Powered by|On your device/i,
  );
  assert.equal(await driver.executeScript("return crossOriginIsolated"), true);
  const automaticThreads = await driver.executeScript(
    "return Math.min(18, navigator.hardwareConcurrency || 4)",
  );
  await writeFile(`${out}/desktop-idle.png`, await driver.takeScreenshot(), "base64");

  await (await button("Generate proof")).click();
  await (await button("Cancel")).click();
  await driver.wait(async () => (await button("Generate proof")).isEnabled(), 10000);
  await run(`Arkworks · ${automaticThreads} threads`);
  await writeFile(`${out}/desktop-result.png`, await driver.takeScreenshot(), "base64");
  await (await button("Benchmark")).click();
  await run(`Arkworks · ${automaticThreads} threads`);
  assert.match(await driver.findElement(By.css(".verified")).getText(), /5 proofs verified/);
  await (await button("Single proof")).click();

  await openOptions();
  await driver.findElement(By.css(".input-details summary")).click();
  const textarea = await driver.findElement(By.id("proof-input"));
  const invalid = JSON.parse(await textarea.getAttribute("value"));
  invalid.publicInputHash = "0x01";
  await editValue(textarea, JSON.stringify(invalid));
  await closeOptions();
  await (await button("Generate proof")).click();
  await driver.wait(until.elementLocated(By.css('[role="alert"]')), 180000);
  assert.equal((await driver.findElements(By.css(".verified"))).length, 0);
  await openOptions();
  await (await button("Restore sample")).click();
  await driver.wait(
    async () => JSON.parse(await textarea.getAttribute("value")).publicInputHash !== "0x01",
    10000,
  );
  await closeOptions();
  await run(`Arkworks · ${automaticThreads} threads`);

  await openOptions();
  const mode = await driver.findElement(By.id("proving-mode"));
  await mode.findElement(By.css('option[value="custom"]')).click();
  await editValue(await driver.findElement(By.id("thread-count")), "2");
  await closeOptions();
  await run("Arkworks · 2 threads");
  await openOptions();
  await mode.findElement(By.css('option[value="go"]')).click();
  await closeOptions();
  await run("Go");
  await openOptions();
  await mode.findElement(By.css('option[value="auto"]')).click();
  await closeOptions();

  const requests = await driver.executeScript(
    'return performance.getEntriesByType("resource").map(r=>r.name)',
  );
  assert.ok(requests.some((url) => url.includes("prover.worker")));
  assert.ok(
    requests.every(
      (url) =>
        new URL(url).origin === new URL(process.env.DEMO_URL || "http://127.0.0.1:5178/").origin,
    ),
  );
  assert.ok(requests.every((url) => !/\/devnet\//.test(url)));
  await driver.manage().window().setRect({ width: 390, height: 844 });
  assert.equal(
    await driver.executeScript("return document.documentElement.scrollWidth > innerWidth"),
    false,
  );
  await writeFile(`${out}/mobile.png`, await driver.takeScreenshot(), "base64");
  await openOptions();
  await writeFile(`${out}/mobile-options.png`, await driver.takeScreenshot(), "base64");
  await driver.actions().sendKeys("\uE00C").perform();
  assert.equal(
    await driver.executeScript('return !!document.querySelector("dialog[open]")'),
    false,
  );
  assert.equal(
    await driver.executeScript('return document.activeElement.getAttribute("aria-label")'),
    "Options",
  );
  await writeFile(`${out}/proofs.json`, JSON.stringify(proofs, null, 2));
  await writeFile(`${out}/results.json`, JSON.stringify(results, null, 2));
  console.log(
    "PASS: proving, benchmark, cancellation, invalid input recovery, automatic/custom threads, Go, mobile dialog, focus return, and no external API requests.",
  );
} catch (error) {
  await writeFile(`${out}/failure.png`, await driver.takeScreenshot(), "base64");
  console.error(await driver.findElement(By.css("body")).getText());
  throw error;
} finally {
  await driver.quit();
}

// Compare warmed proof timings in fresh browser profiles, one browser at a time.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Builder, By, until } from 'selenium-webdriver';
import chrome from 'selenium-webdriver/chrome.js';
import firefox from 'selenium-webdriver/firefox.js';
import { profileKernel } from './profile-kernel.mjs';

const browserName = process.argv[2] || 'brave';
if (!['brave', 'firefox'].includes(browserName)) throw new Error('Choose brave or firefox');
const counts = (process.argv[3] || '18,6,1').split(',').map(Number);
const profile = process.argv[4] === 'profile';
assert.ok(counts.every(count => Number.isInteger(count) && count >= 1 && count <= 64));
const out = fileURLToPath(new URL('../../../target/mopro-browser-comparison/', import.meta.url));
await mkdir(out, { recursive: true });
let builder = new Builder();
if (browserName === 'firefox') {
  builder = builder.forBrowser('firefox').setFirefoxOptions(new firefox.Options()
    .setBinary(process.env.FIREFOX_BIN || '/Applications/Firefox.app/Contents/MacOS/firefox')
    .addArguments('-headless', '--width=1440', '--height=1100'));
} else {
  builder = builder.forBrowser('chrome').setChromeOptions(new chrome.Options()
    .setChromeBinaryPath(process.env.CHROME_BIN || '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser')
    .addArguments('--headless', '--window-size=1440,1100'));
}
const driver = await builder.build();
const results = { browser: browserName, runs: [] };
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
async function prove() {
  await driver.findElement(By.css('.proof-panel .primary')).click();
  await driver.wait(async () => {
    const errors = await driver.findElements(By.css('[role="alert"]'));
    if (errors.length) throw new Error(await errors[0].getText());
    return (await driver.findElement(By.css('.proof-panel [role="status"]')).getText()).includes('Proof generated');
  }, 180000);
  assert.equal((await driver.findElements(By.css('.verified'))).length, 1);
  const log = await driver.findElement(By.css('.log')).getAttribute('textContent');
  const matches = [...log.matchAll(/Proof 1\/1: ([\d.]+) ms; verified in ([\d.]+) ms/g)];
  assert.ok(matches.length);
  const last = matches.at(-1);
  return { proveMs: Number(last[1]), verifyMs: Number(last[2]) };
}
try {
  await driver.get(process.env.DEMO_URL || 'http://127.0.0.1:5178/');
  await driver.wait(until.elementLocated(By.css('textarea')), 30000);
  await driver.wait(async () => (await driver.findElement(By.css('textarea')).getAttribute('value')).length > 100, 30000);
  results.environment = await driver.executeScript('return { userAgent: navigator.userAgent, reportedThreads: navigator.hardwareConcurrency, isolated: crossOriginIsolated }');
  assert.equal(results.environment.isolated, true);
  console.log(browserName, JSON.stringify(results.environment));
  const mode = await driver.findElement(By.css('select[aria-label="Proving threads"]'));
  await mode.findElement(By.css('option[value="custom"]')).click();
  for (const count of counts) {
    if (profile) {
      const run = await profileKernel(driver, count);
      if (run.error) throw new Error(run.error);
      results.runs.push(run);
      await writeFile(out + browserName + '-profile.json', JSON.stringify(results, null, 2));
      console.log(JSON.stringify({ browser: browserName, count, rustSolver: run.rustSolver,
        totalMs: median(run.samples.map(x => x.totalMs)), kernelMs: median(run.samples.map(x => x.kernelMs)), otherMs: median(run.samples.map(x => x.otherMs)) }));
      continue;
    }
    const input = await driver.findElement(By.css('input[aria-label="Thread count"]'));
    await driver.executeScript(function(el, value) {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, String(value));
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }, input, count);
    const warmups = [];
    for (let i = 0; i < 3; i++) warmups.push(await prove());
    assert.ok((await driver.findElement(By.css('.runtime-pill')).getText()).includes(`${count} workers`));
    const samples = [];
    for (let i = 0; i < 15; i++) samples.push(await prove());
    const run = { count, warmups, samples, medianMs: median(samples.map(x => x.proveMs)), verifyMedianMs: median(samples.map(x => x.verifyMs)) };
    results.runs.push(run);
    await writeFile(out + browserName + '.json', JSON.stringify(results, null, 2));
    console.log(JSON.stringify({ browser: browserName, count, firstMs: warmups[0].proveMs, medianMs: run.medianMs, verifyMedianMs: run.verifyMedianMs }));
  }
} finally { await driver.quit(); }

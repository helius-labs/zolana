import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Builder, By, until } from 'selenium-webdriver';
import chrome from 'selenium-webdriver/chrome.js';
const out = fileURLToPath(new URL('../../../target/mopro-browser-ui/', import.meta.url));
await mkdir(out, {recursive:true});
const options = new chrome.Options().addArguments('--headless', '--window-size=1440,1100');
if (process.env.CHROME_BIN) options.setChromeBinaryPath(process.env.CHROME_BIN);
const driver = await new Builder().forBrowser('chrome').setChromeOptions(options).build();
const proofs = [];
async function button(text) { return driver.findElement(By.xpath(`//button[normalize-space(.)='${text}']`)); }
async function run(label) {
  await (await button(label)).click();
  await driver.wait(async () => (await driver.findElements(By.css('[role="alert"]'))).length || (await driver.findElements(By.css('.verified'))).length, 180000);
  const errors = await driver.findElements(By.css('[role="alert"]'));
  if (errors.length) throw new Error(await errors[0].getText());
  await driver.wait(async () => (await driver.findElement(By.css('.proof-panel [role="status"]')).getText()).includes('Proof generated'), 180000);
  const proof = await driver.findElement(By.css('.proof-output pre')).getText();
  proofs.push(JSON.parse(proof));
  console.log(label, await driver.findElement(By.css('.metrics')).getText());
}
try {
  await driver.get(process.env.DEMO_URL || 'http://127.0.0.1:5178/');
  await driver.wait(until.elementLocated(By.css('textarea[aria-label="Proof request JSON"]')),30000);
  await driver.wait(async () => (await driver.findElement(By.css('textarea')).getAttribute('value')).length > 100, 30000);
  assert.equal(await driver.executeScript('return crossOriginIsolated'), true);
  const mode = await driver.findElement(By.css('select[aria-label="Proving threads"]'));
  assert.equal(await mode.getAttribute('value'), 'auto');
  const automaticThreads = await driver.executeScript('return Math.min(18, navigator.hardwareConcurrency || 4)');
  await run('Generate & verify proof');
  assert.ok((await driver.findElement(By.css('.runtime-pill')).getText()).includes(`${automaticThreads} workers`));
  await writeFile(out+'desktop.png', await driver.takeScreenshot(), 'base64');
  await run('Benchmark 5 proofs');
  assert.match(await driver.findElement(By.css('.metrics')).getText(), /5 proofs generated/);
  await driver.findElement(By.css('.request-editor summary')).click();
  const textarea = await driver.findElement(By.css('textarea'));
  const invalid = JSON.parse(await textarea.getAttribute('value')); invalid.publicInputHash = '0x01';
  // Use the DOM setter and input event so React observes the edited request.
  await driver.executeScript(function(el,value){ const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set; set.call(el,value); el.dispatchEvent(new Event('input',{bubbles:true})); }, textarea, JSON.stringify(invalid));
  await (await button('Generate & verify proof')).click();
  await driver.wait(until.elementLocated(By.css('[role="alert"]')),180000);
  assert.equal((await driver.findElements(By.css('.verified'))).length,0);
  console.log('Invalid witness rejected');
  await (await button('Load sample request')).click();
  await run('Generate & verify proof');
  await mode.findElement(By.css('option[value="custom"]')).click();
  assert.equal((await driver.findElements(By.css('.verified'))).length,0);
  const workers = await driver.findElement(By.css('input[aria-label="Thread count"]'));
  await driver.executeScript(function(el){ const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; set.call(el,'2'); el.dispatchEvent(new Event('input',{bubbles:true})); }, workers);
  await run('Generate & verify proof');
  assert.match(await driver.findElement(By.css('.runtime-pill')).getText(), /2 workers/);
  await mode.findElement(By.css('option[value="go"]')).click();
  await run('Generate & verify proof');
  assert.match(await driver.findElement(By.css('.runtime-pill')).getText(), /Go fallback/);
  await mode.findElement(By.css('option[value="auto"]')).click();
  assert.equal((await driver.findElements(By.css('.verified'))).length,0);
  await driver.manage().window().setRect({width:390,height:844});
  await driver.executeScript('window.scrollTo(0,0)');
  assert.equal(await driver.executeScript('return document.documentElement.scrollWidth > innerWidth'),false);
  await writeFile(out+'mobile.png', await driver.takeScreenshot(),'base64');
  await writeFile(out+'proofs.json',JSON.stringify(proofs,null,2));
  console.log('Browser UI, automatic/custom threads, Go fallback, invalid-witness recovery and mobile layout passed.');
} catch (error) {
  await writeFile(out+'failure.png', await driver.takeScreenshot(),'base64');
  console.error(await driver.findElement(By.css('body')).getText());
  throw error;
} finally { await driver.quit(); }

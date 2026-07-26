// Executes the cryptographic vector suites in headless Chromium.
//
// `browser-check.mjs` greps the bundle for Node imports. This script is the
// half that actually runs: it bundles the harness for `platform: browser`,
// serves it, and asserts the same Rust vectors the Node suites pin. A wrong
// digest in the browser fails here even when every Node test is green.
//
//   node sdk-libs/ts/config/browser-runtime-check.mjs

import { build } from "esbuild";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const configDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(configDir, "../../..");
const harnessSource = path.join(configDir, "browser-runtime-harness.mjs");

const directory = await mkdtemp(path.join(tmpdir(), "zolana-browser-runtime-"));
const bundlePath = path.join(directory, "harness.mjs");
const htmlPath = path.join(directory, "index.html");

try {
  await build({
    entryPoints: [harnessSource],
    outfile: bundlePath,
    bundle: true,
    conditions: ["browser", "import"],
    format: "esm",
    platform: "browser",
    target: "es2022",
    nodePaths: [path.resolve(workspaceRoot, "node_modules")],
  });

  // A file: URL cannot instantiate the inlined WebAssembly the way an HTTP
  // origin can, so the check always serves over loopback.
  await writeFile(
    htmlPath,
    `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>zolana browser runtime</title></head>
  <body>
    <script type="module" src="./harness.mjs"></script>
  </body>
</html>
`,
  );

  const files = new Map([
    ["/", htmlPath],
    ["/index.html", htmlPath],
    ["/harness.mjs", bundlePath],
  ]);
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const filePath = files.get(url.pathname);
    if (filePath === undefined) {
      response.writeHead(404).end();
      return;
    }
    const body = await readFile(filePath);
    const type = filePath.endsWith(".mjs") ? "text/javascript" : "text/html";
    response.writeHead(200, { "content-type": type });
    response.end(body);
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  const origin = `http://127.0.0.1:${String(port)}`;

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) => {
      pageErrors.push(error);
    });
    await page.goto(origin, { waitUntil: "networkidle" });
    await page.waitForFunction(() => globalThis.__zolanaBrowserRuntime !== undefined);
    const result = await page.evaluate(async () => globalThis.__zolanaBrowserRuntime.run());
    if (pageErrors.length > 0) {
      throw new Error(`browser page error: ${pageErrors.map((error) => error.message).join("; ")}`);
    }
    if (!result.ok) {
      const detail = result.failures
        .slice(0, 20)
        .map((failure) => `${failure.name}: expected ${failure.expected}, got ${failure.actual}`)
        .join("\n");
      throw new Error(
        `browser runtime check failed (${String(result.failures.length)} mismatches)\n${detail}`,
      );
    }
    console.log(`browser runtime check passed (${JSON.stringify(result.checks)})`);
  } finally {
    await browser?.close();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}

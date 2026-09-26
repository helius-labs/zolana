import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "../../..");
const WEB_ROOT = join(PACKAGE_ROOT, "web");
const FIXTURE_ROOT = join(PACKAGE_ROOT, "tests", "fixtures");
const KEY_ROOT = join(REPO_ROOT, "target", "escrow-wasm-fixtures");
const PORT = Number(process.env.PORT ?? 4327);

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};

if (!existsSync(join(WEB_ROOT, "pkg", "timelock_escrow_wasm.js"))) {
  console.error("web/pkg is missing: build the module first (npm run build:test)");
  process.exit(1);
}

const MOUNTS = [
  ["/fixtures/", FIXTURE_ROOT],
  ["/keys/", KEY_ROOT],
  ["/vendor/", join(PACKAGE_ROOT, "node_modules")],
];

function resolveRequest(pathname) {
  const decoded = decodeURIComponent(pathname);
  if (decoded === "/") {
    return join(WEB_ROOT, "index.html");
  }
  const mount = MOUNTS.find(([prefix]) => decoded.startsWith(prefix));
  const [root, rest] = mount
    ? [mount[1], decoded.slice(mount[0].length)]
    : [WEB_ROOT, decoded.slice(1)];
  const candidate = resolve(root, rest);
  if (candidate !== root && !candidate.startsWith(root + sep)) {
    return null;
  }
  return candidate;
}

createServer((request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405).end();
    return;
  }
  const { pathname } = new URL(request.url ?? "/", `http://${request.headers.host}`);
  if (pathname === "/favicon.ico") {
    response.writeHead(204).end();
    return;
  }
  const file = resolveRequest(pathname);
  if (file === null) {
    response.writeHead(403).end();
    return;
  }
  if (!existsSync(file) || !statSync(file).isFile()) {
    response.writeHead(404, { "Content-Type": "text/plain" }).end(`not found: ${pathname}`);
    return;
  }
  response.writeHead(200, {
    "Content-Type": CONTENT_TYPES[extname(file)] ?? "application/octet-stream",
    "Content-Length": statSync(file).size,
    "Cache-Control": "no-store",
  });
  if (request.method === "HEAD") {
    response.end();
    return;
  }
  createReadStream(file).pipe(response);
}).listen(PORT, "127.0.0.1", () => {
  console.log(`serving ${WEB_ROOT} on http://127.0.0.1:${PORT}`);
});

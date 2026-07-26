// States the merge-tier scope of `npm run check` and fails when package.json
// drifts from that statement. Suites that need a localnet or the pinned Rust
// toolchain stay named sub-scripts: CI runs each as its own job rather than
// forcing one wall-clock process to host every service.
//
//   node sdk-libs/ts/config/check-scope.mjs

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

/** @type {readonly { name: string, contains: string, needs: string }[]} */
export const CHECK_PARTS = Object.freeze([
  {
    name: "check:static",
    contains: "build, typecheck, lint, lint:packages (package-lint), format:check",
    needs: "Node",
  },
  {
    name: "check:suites",
    contains: "test:unit, test:vectors, test:property, test:cross, test:prover",
    needs: "Node (prover suite is offline against committed vectors; no live prover)",
  },
  {
    name: "check:packaging",
    contains:
      "test:inventory, test:exports, test:dependencies, api:check, test:browser, pack:check",
    needs: "Node (packed-package consumer + static browser bundle scan)",
  },
  {
    name: "check:browser-runtime",
    contains: "test:browser-runtime",
    needs: "Node + Playwright Chromium",
  },
  {
    name: "check:fixtures",
    contains: "fixtures:check",
    needs: "pinned Rust toolchain and frozen baseline blobs in git history",
  },
  {
    name: "check:e2e",
    contains: "test:e2e:actions, test:e2e:instructions, test:e2e:photon",
    needs: "Solana validator, same-revision Photon, local prover, built programs",
  },
]);

const expectedCheck = CHECK_PARTS.map((part) => `npm run ${part.name}`).join(" && ");

const { scripts } = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
if (scripts.check !== expectedCheck) {
  throw new Error(
    `package.json check runs ${JSON.stringify(scripts.check)}; documented scope is ${JSON.stringify(expectedCheck)}`,
  );
}

// `contains` is documentation unless it is checked against the sub-script. The
// Photon suite was in `check:e2e` while this file still listed only actions and
// instructions; nothing failed until a reader compared the two by hand.
for (const part of CHECK_PARTS) {
  const script = scripts[part.name];
  if (typeof script !== "string") {
    throw new Error(`package.json lacks scripts.${part.name}`);
  }
  for (const token of part.contains.split(",").map((value) => value.trim())) {
    const npmScript = token.replace(/\s*\(.*\)$/u, "");
    if (!script.includes(npmScript)) {
      throw new Error(
        `${part.name} is documented to contain ${JSON.stringify(token)} but runs ${JSON.stringify(script)}`,
      );
    }
  }
}

console.log("npm run check — merge-tier composition");
console.log("CI splits these into jobs by service needs (.github/workflows/typescript.yml).");
console.log("Locally, prefer the named sub-script when you lack a service.\n");
for (const part of CHECK_PARTS) {
  console.log(`${part.name}`);
  console.log(`  contains: ${part.contains}`);
  console.log(`  needs:    ${part.needs}`);
}
console.log("\ncheck scope ok");

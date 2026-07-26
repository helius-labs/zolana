// Control-edit harness: apply a literal source substitution, run a test
// selection, restore the file, and report whether the tests caught the edit.
// Usage: node tools/control-edit.mjs [--build] <file> <from-file> <to-file> -- <vitest args...>
//
// Cross-package imports resolve through each package's `dist/`, so an edit
// outside the package under test is invisible until `--build` reruns the build.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const argv = process.argv.slice(2);
const build = argv[0] === "--build";
const [file, fromPath, toPath, ...rest] = build ? argv.slice(1) : argv;
const testArgs = rest[0] === "--" ? rest.slice(1) : rest;
const original = readFileSync(file, "utf8");
const from = readFileSync(fromPath, "utf8").replace(/\n$/, "");
const to = readFileSync(toPath, "utf8").replace(/\n$/, "");

if (!original.includes(from)) {
  console.log("PATCH DID NOT APPLY");
  process.exit(2);
}
const rebuild = () => {
  if (build) execFileSync("npm", ["run", "build"], { stdio: ["ignore", "ignore", "inherit"] });
};

writeFileSync(file, original.replace(from, to));
try {
  rebuild();
  const out = execFileSync("npx", ["vitest", "run", ...testArgs], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  console.log(`NOT CAUGHT: ${/Tests +.*/.exec(out)?.[0] ?? "passed"}`);
} catch (error) {
  const out = `${error.stdout ?? ""}${error.stderr ?? ""}`;
  console.log(`CAUGHT: ${/Tests +.*/.exec(out)?.[0] ?? "failed"}`);
  for (const line of out.split("\n").filter((l) => /^\s+[×✗]/.test(l)))
    console.log(`   ${line.trim()}`);
} finally {
  writeFileSync(file, original);
  rebuild();
}

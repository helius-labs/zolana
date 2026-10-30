import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export async function bundleBrowserTrust() {
  const sdk = fileURLToPath(new URL("../", import.meta.url));
  const source = join(sdk, "src/client/prover/tee/browser");
  const output = join(sdk, "dist/client/prover/tee/browser/core.js");
  const result = await build({
    entryPoints: [join(source, "core.ts")],
    outfile: output,
    bundle: true,
    platform: "browser",
    format: "esm",
    target: "es2022",
    metafile: true,
    alias: { crypto: join(source, "crypto.ts"), util: join(source, "equality.ts") },
    inject: [join(source, "buffer.ts")],
    legalComments: "eof",
  });
  if (Object.values(result.metafile.outputs).some((item) => item.imports.length)) {
    throw new Error("browser TUF engine must be self-contained");
  }
  const packages = new Set();
  for (const input of Object.keys(result.metafile.inputs)) {
    const absolute = resolve(input);
    const marker = absolute.lastIndexOf("/node_modules/");
    if (marker < 0) continue;
    const parts = absolute.slice(marker + 14).split("/");
    packages.add(
      join(absolute.slice(0, marker + 14), ...parts.slice(0, parts[0].startsWith("@") ? 2 : 1)),
    );
  }
  const notices = [];
  for (const directory of [...packages].sort()) {
    const pkg = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
    const files = [
      "LICENSE",
      "LICENSE.txt",
      "LICENSE.md",
      "LICENSE-MIT",
      "LICENSE-MIT.txt",
      "LICENCE",
      "license",
    ];
    let license;
    for (const file of files) {
      try {
        license = await readFile(join(directory, file), "utf8");
        break;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    if (!license) throw new Error(`missing license for browser dependency ${pkg.name}`);
    notices.push(`${pkg.name}@${pkg.version}\n${"=".repeat(72)}\n${license}`);
  }
  await writeFile(join(dirname(output), "THIRD_PARTY_LICENSES.txt"), notices.join("\n\n"));
}

import { resolve } from "node:path";
import { build } from "esbuild";
import { expect, it } from "vitest";

it("keeps the public client dependency graph free of the Node TUF adapter and Node imports", async () => {
  const bundled = await build({
    entryPoints: [resolve(import.meta.dirname, "../src/client/index.ts")],
    bundle: true,
    write: false,
    metafile: true,
    format: "esm",
    platform: "browser",
    packages: "external",
  });
  const metadata = bundled.metafile;
  if (metadata === undefined) throw new Error("missing bundle metadata");
  const imports = Object.values(metadata.outputs).flatMap((output) =>
    output.imports.map((entry) => entry.path),
  );
  expect(
    imports.filter(
      (path) => path.startsWith("node:") || path.startsWith("tuf-js") || path.startsWith("@tufjs/"),
    ),
  ).toEqual([]);
  expect(Object.keys(metadata.inputs).filter((path) => path.endsWith("tuf-node.ts"))).toEqual([]);
});

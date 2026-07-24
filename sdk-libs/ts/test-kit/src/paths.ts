/// <reference types="node" />

import path from "node:path";

export function programBinaryPath(
  workspace: string,
  input: Readonly<{ environmentVariable: string; fileName: string }>,
): string {
  const override = process.env[input.environmentVariable]?.trim();
  return override && override !== ""
    ? path.resolve(override)
    : path.resolve(workspace, "target/deploy", input.fileName);
}

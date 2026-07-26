import path from "node:path";
import { fileURLToPath } from "node:url";

// Resolved from this file rather than written relative in each config: the
// suites run from a package directory and from the repository root, so a
// relative path is right for one caller and outside the repository for the
// other.
const configRoot = path.dirname(fileURLToPath(import.meta.url));

export const poseidonSetupFile = path.join(configRoot, "poseidon.setup.mjs");
export const propertySetupFile = path.join(configRoot, "property.setup.mjs");
export const groth16VerifyGlobalSetupFile = path.join(
  configRoot,
  "groth16-verify.global-setup.mjs",
);

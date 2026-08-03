import { copyFile, mkdir } from "node:fs/promises";

const licenseSource = new URL("../../../LICENSE", import.meta.url);
const distDirectory = new URL("../dist/", import.meta.url);

await mkdir(distDirectory, { recursive: true });
await copyFile(licenseSource, new URL("LICENSE", distDirectory));

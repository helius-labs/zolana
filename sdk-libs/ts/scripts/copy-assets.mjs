import { copyFile, mkdir, cp } from "node:fs/promises";

const licenseSource = new URL("../../../LICENSE", import.meta.url);
const distDirectory = new URL("../dist/", import.meta.url);

await mkdir(distDirectory, { recursive: true });
await copyFile(licenseSource, new URL("LICENSE", distDirectory));

await cp(new URL("../idl/", import.meta.url), new URL("idl/", distDirectory), { recursive: true });

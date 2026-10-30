import { writeFile } from "node:fs/promises";

export function writeJson(path, value) {
  return writeFile(path, JSON.stringify(value, null, 2) + "\n");
}

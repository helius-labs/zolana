// Refuses a release whose version has no changelog entry. `--release` also
// demands the publish date, so `prepublishOnly` blocks an undated publish.
import { readFileSync } from "node:fs";

const release = process.argv.includes("--release");
const version = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
const heading = changelog.split("\n").find((line) => line.startsWith("## "));
const escaped = version.replace(/[.\\^$*+?()[\]{}|]/g, "\\$&");
const date = release ? "\\d{4}-\\d{2}-\\d{2}" : "(\\d{4}-\\d{2}-\\d{2}|unreleased)";
const expected = new RegExp(`^## ${escaped} — ${date}$`);
if (heading === undefined || !expected.test(heading)) {
  console.error(
    `CHANGELOG.md first entry must be "## ${version} — ${release ? "YYYY-MM-DD" : "YYYY-MM-DD or unreleased"}", found "${heading ?? "none"}". See CHANGELOG-RULES.md.`,
  );
  process.exit(1);
}

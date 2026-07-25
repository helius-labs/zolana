// Gate on planning/typescript-sdk-port/review-checklist.md, which records a
// verdict per row twice: once in the queue tables and once in the session log.
// The two desynchronize structurally, because table edits sit in the file from
// the moment they are made and get carried by whoever commits next, while a log
// entry is written at the end of a session and is lost when another agent
// commits first. The rules that forbid that already exist and did not hold, so
// this reads the file back and refuses the states they were meant to prevent.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const checklistPath = path.join(repoRoot, "planning/typescript-sdk-port/review-checklist.md");
const displayPath = path.relative(repoRoot, checklistPath);

const DONE_STATUS = "done";
const PARITY_VERDICT = "PARITY";
// A verdict that does not claim parity. Anything else in the vocabulary is
// adverse: it records a gap, a conflict, or evidence that cannot settle the row.
const NON_ADVERSE_VERDICTS = new Set([PARITY_VERDICT, "NOT_APPLICABLE"]);
// The table's own marker for a column with nothing in it yet.
const ABSENT = "-";

const ROW_ID = /\b([A-Z])(\d{2})\b/g;
const ROW_ID_RANGE = /\b([A-Z])(\d{2})\s*-\s*\1?(\d{2})\b/g;

// Fields a log entry uses to record a verdict. Every other field is ignored,
// including `Exact next file`, which names the *next* row in the queue: a body
// scan that reads it attributes this entry's verdict to the following row.
const VERDICT_FIELDS = new Set(["verdict", "verdicts"]);

const problems = [];
const fail = (message) => problems.push(message);

const source = await readFile(checklistPath, "utf8");
const lines = source.split("\n");

/**
 * Read a closed vocabulary out of the document itself, so the check follows the
 * checklist rather than a second copy of it that can drift.
 */
function readVocabulary(intro, label) {
  const start = lines.findIndex((line) => line.trim() === intro);
  if (start === -1) throw new Error(`${displayPath} no longer states "${intro}"`);

  const terms = new Set();
  for (const line of lines.slice(start + 1)) {
    const term = /^- `([A-Za-z_]+)`:/.exec(line);
    if (term) terms.add(term[1]);
    else if (terms.size > 0 && line.trim() !== "") break;
  }
  if (terms.size < 3) throw new Error(`${displayPath} lists no ${label} under "${intro}"`);
  return terms;
}

const statuses = readVocabulary("Use only these row statuses:", "row statuses");
const verdicts = readVocabulary("Assign one verdict after each review:", "verdicts");

// Queue rows. Nine fixed columns, one row per canonical Rust source file.
const rows = new Map();
for (const [index, line] of lines.entries()) {
  if (!/^\| [A-Z]\d{2} \|/.test(line)) continue;
  const cells = line.split("|").map((cell) => cell.trim());
  const [, id, , , status, verdict] = cells;
  if (rows.has(id)) fail(`row ${id} appears twice in the queue tables`);
  rows.set(id, { id, status, verdict, line: index + 1 });
}
if (rows.size === 0) throw new Error(`${displayPath} holds no queue rows`);

for (const row of rows.values()) {
  if (!statuses.has(row.status)) {
    fail(
      `${displayPath}:${row.line} ${row.id} has Status \`${row.status}\`, which the vocabulary does not define. Use one of: ${[...statuses].join(", ")}`,
    );
  }
  if (row.verdict !== ABSENT && !verdicts.has(row.verdict)) {
    fail(
      `${displayPath}:${row.line} ${row.id} has Verdict \`${row.verdict}\`, which the vocabulary does not define. Use one of: ${[...verdicts].join(", ")}, or \`${ABSENT}\` when no review has assigned one`,
    );
  }
}

// The mutable baseline summarizes the table a few hundred lines above it and is
// hand-edited, so it drifts. Its `done` count is the number reviewers cite.
const doneRows = [...rows.values()].filter(
  (row) => row.status === DONE_STATUS && row.verdict === PARITY_VERDICT,
);
const progressLine = lines.findIndex((line) => line.startsWith("- Progress: `"));
const claimed = /`(\d+) done/.exec(lines[progressLine] ?? "");
if (!claimed) {
  fail(`${displayPath} mutable baseline has no \`<n> done\` progress count`);
} else if (Number(claimed[1]) !== doneRows.length) {
  fail(
    `${displayPath}:${progressLine + 1} the baseline reports ${claimed[1]} done; the queue tables hold ${doneRows.length} rows that are \`${DONE_STATUS}\` and \`${PARITY_VERDICT}\``,
  );
}

/**
 * Split the append-only session log into entries, skipping fenced blocks so the
 * copy-me template does not parse as a real entry.
 */
function readLogEntries() {
  const logStart = lines.findIndex((line) => line.startsWith("## Append-only session log"));
  if (logStart === -1) throw new Error(`${displayPath} has no session log`);

  const entries = [];
  let fenced = false;
  for (const [index, line] of lines.slice(logStart).entries()) {
    if (line.startsWith("```")) fenced = !fenced;
    if (fenced) continue;
    if (line.startsWith("### ")) {
      entries.push({ heading: line.slice(4).trim(), line: logStart + index + 1, body: [] });
    } else if (entries.length > 0) {
      entries.at(-1).body.push(line);
    }
  }
  return entries;
}

function rowIdsIn(text) {
  const found = new Set();
  // `T01-T31` names a span of the queue rather than two rows.
  for (const [, prefix, from, to] of text.matchAll(ROW_ID_RANGE)) {
    for (let n = Number(from); n <= Number(to); n += 1) {
      found.add(`${prefix}${String(n).padStart(2, "0")}`);
    }
  }
  for (const [id] of text.matchAll(ROW_ID)) found.add(id);
  return [...found].filter((id) => rows.has(id));
}

/**
 * Verdicts an entry records, by row. Attribution is deliberately narrow: only a
 * verdict field, and only when the line carries a single verdict, so a line
 * reading "the 13 named rows are PARITY; I07 and I10 are BLOCKED" attributes
 * nothing rather than attributing the wrong one.
 */
function verdictsIn(entry) {
  const headingRows = rowIdsIn(entry.heading);
  const assigned = new Map();

  for (const line of entry.body) {
    const field = /^- ([A-Za-z_ ]+):/.exec(line);
    if (!field) continue;
    const label = field[1].trim();
    const isVerdictField = VERDICT_FIELDS.has(label.toLowerCase()) || verdicts.has(label);
    if (!isVerdictField) continue;

    const named = [...verdicts].filter((verdict) => new RegExp(`\\b${verdict}\\b`).test(line));
    if (named.length !== 1) continue;

    const bodyRows = rowIdsIn(line);
    for (const id of bodyRows.length > 0 ? bodyRows : headingRows) assigned.set(id, named[0]);
  }
  return assigned;
}

// Later entries supersede earlier ones. The log is append-only, so its own
// order is the record of what was concluded last.
const latest = new Map();
for (const entry of readLogEntries()) {
  for (const [id, verdict] of verdictsIn(entry)) {
    latest.set(id, { verdict, heading: entry.heading, line: entry.line });
  }
}

// The property worth enforcing is not that an entry exists. 31 of the 36 rows
// this check was written for had one, so presence passes the rows that matter.
// A row claimed complete must not be contradicted by the last verdict recorded
// against it.
for (const row of doneRows) {
  const record = latest.get(row.id);
  if (!record || !verdicts.has(record.verdict) || NON_ADVERSE_VERDICTS.has(record.verdict))
    continue;
  fail(
    `${displayPath}:${row.line} ${row.id} is \`${DONE_STATUS}\` / \`${PARITY_VERDICT}\`, but the last session-log entry that assigns it a verdict records \`${record.verdict}\`: line ${record.line}, "${record.heading}". Record the review that upgraded it, or re-open the row.`,
  );
}

// `--explain` prints what the log attributed to each row, which is the first
// thing to read when a failure below looks wrong.
if (process.argv.includes("--explain")) {
  for (const id of [...rows.keys()].sort()) {
    const record = latest.get(id);
    console.log(
      `${id}\t${rows.get(id).status}/${rows.get(id).verdict}\t${record ? `${record.verdict} from line ${record.line}, ${record.heading}` : "no attributable verdict"}`,
    );
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  console.error(`\n${problems.length} checklist problem(s). See ${displayPath}.`);
  process.exit(1);
}

console.log(
  `${displayPath}: ${rows.size} rows, ${doneRows.length} done/${PARITY_VERDICT}, ${latest.size} rows carry an attributable session-log verdict.`,
);

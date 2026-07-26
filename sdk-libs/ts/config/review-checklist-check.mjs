// Gate on the review checklist, which records a verdict per row twice: once in
// the queue tables and once in the session log. The two desynchronize, because a
// table edit sits in the tree from the moment it is made and gets carried by
// whoever commits next, while a log entry is written at the end of a session and
// is lost when another agent commits first. The rules that forbid that already
// exist and did not hold, so this reads the record back and refuses the states
// they were meant to prevent.
//
// The log lives in planning/typescript-sdk-port/log/, one file per entry, so an
// entry can no longer be carried off by a commit that meant to take only the
// table. Entries are ordered by the timestamp in their filename.

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const planningDir = path.join(repoRoot, "planning/typescript-sdk-port");
const checklistPath = path.join(planningDir, "review-checklist.md");
const logDir = path.join(planningDir, "log");
const displayPath = path.relative(repoRoot, checklistPath);
const displayLogDir = path.relative(repoRoot, logDir);

const DONE_STATUS = "done";
const PARITY_VERDICT = "PARITY";
// A verdict that does not claim parity. Anything else in the vocabulary is
// adverse: it records a gap, a conflict, or evidence that cannot settle the row.
const NON_ADVERSE_VERDICTS = new Set([PARITY_VERDICT, "NOT_APPLICABLE"]);
// The table's own marker for a column with nothing in it yet.
const ABSENT = "-";

// One or two letter prefixes: package letters (`H15`) and annex seats (`TK01`).
const ROW_ID = /\b([A-Z]{1,2})(\d{2})\b/g;
const ROW_ID_RANGE = /\b([A-Z]{1,2})(\d{2})\s*-\s*\1?(\d{2})\b/g;

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
  if (!/^\| [A-Z]{1,2}\d{2} \|/.test(line)) continue;
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
 * One entry per file, ordered by the timestamp its name starts with. Document
 * order used to carry that meaning and carried it badly, because workers wrote
 * per-row entries in row order rather than in time order.
 */
async function readLogEntries() {
  const names = (await readdir(logDir)).filter(
    (name) => name.endsWith(".md") && name !== "README.md",
  );
  if (names.length === 0) throw new Error(`${displayLogDir} holds no entries`);

  const entries = [];
  for (const name of names) {
    const stamp = /^(\d{4}-\d{2}-\d{2})T(\d{4})-/.exec(name);
    if (!stamp) {
      fail(
        `${displayLogDir}/${name} is not named \`<YYYY-MM-DD>T<HHMM>-<row>.md\`, so it has no place in the order`,
      );
      continue;
    }
    const [heading, ...body] = (await readFile(path.join(logDir, name), "utf8")).split("\n");
    entries.push({
      heading: heading.replace(/^#+\s*/, "").trim(),
      body,
      file: `${displayLogDir}/${name}`,
      // Same-minute entries keep a stable relative order by filename.
      sort: `${stamp[1]}T${stamp[2]}|${name}`,
    });
  }
  return entries.sort((a, b) => a.sort.localeCompare(b.sort));
}

// The old section must stay empty. Left parseable, the habit resumes and entries
// drift back into the file they were split out of, invisible to everything below.
const logSection = lines.findIndex((line) => line.startsWith("## Append-only session log"));
if (logSection !== -1) {
  const stray = lines.findIndex((line, index) => index > logSection && line.startsWith("### "));
  if (stray !== -1) {
    fail(
      `${displayPath}:${stray + 1} holds a session-log entry. Entries live in ${displayLogDir}, one file per entry, and this one is read by nothing.`,
    );
  }
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

// Later entries supersede earlier ones.
const latest = new Map();
for (const entry of await readLogEntries()) {
  for (const [id, verdict] of verdictsIn(entry)) {
    latest.set(id, { verdict, heading: entry.heading, file: entry.file });
  }
}

// The property worth enforcing is not that an entry exists. 31 of the 36 rows
// this check was written for had one, so presence passes the rows that matter,
// and splitting the log into one file per row makes presence easier still to
// satisfy without saying anything. A row claimed complete must not be
// contradicted by the last verdict recorded against it.
for (const row of doneRows) {
  const record = latest.get(row.id);
  if (!record || !verdicts.has(record.verdict) || NON_ADVERSE_VERDICTS.has(record.verdict))
    continue;
  fail(
    `${displayPath}:${row.line} ${row.id} is \`${DONE_STATUS}\` / \`${PARITY_VERDICT}\`, but the last log entry that assigns it a verdict records \`${record.verdict}\`: ${record.file}, "${record.heading}". Record the review that upgraded it, or re-open the row.`,
  );
}

// `--explain` prints what the log attributed to each row, which is the first
// thing to read when a failure below looks wrong.
if (process.argv.includes("--explain")) {
  for (const id of [...rows.keys()].sort()) {
    const record = latest.get(id);
    console.log(
      `${id}\t${rows.get(id).status}/${rows.get(id).verdict}\t${record ? `${record.verdict} from ${record.file}` : "no attributable verdict"}`,
    );
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  console.error(`\n${problems.length} checklist problem(s). See ${displayPath}.`);
  process.exit(1);
}

console.log(
  `${displayPath}: ${rows.size} rows, ${doneRows.length} done/${PARITY_VERDICT}, ${latest.size} rows carry an attributable verdict from ${displayLogDir}.`,
);

// Decide whether the cryptographic certification phase may begin.
//
// `proof-and-key-parity.md` states four entry criteria in prose. Prose is read
// by whoever is looking, and the thing this project keeps getting wrong is not
// reading the criteria but believing they are met: for most of this port's life
// "CI is green" meant "the four gates I run locally are green", while every job
// on the pull request was skipping because it was a draft. So the criteria are
// evaluated here instead, and a phase that costs days does not start on someone's
// impression that the phase before it finished.
//
// Exit 0 means all four hold and PKP-00 may start. Exit 1 means at least one does
// not, and the report says which. Exit 2 means the gate could not decide, which is
// not the same as a refusal and must not be treated as one.
//
//   node sdk-libs/ts/config/pkp-entry-gate.mjs            evaluate and report
//   node sdk-libs/ts/config/pkp-entry-gate.mjs --json     machine-readable
//   node sdk-libs/ts/config/pkp-entry-gate.mjs --skip-ci  criteria 1-3 only

import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const checklistPath = path.join(repoRoot, "planning/typescript-sdk-port/review-checklist.md");

const PULL_REQUEST = "159";
// A row in one of these states makes no claim that needs closing. Everything
// else in the vocabulary records a gap, a conflict, or evidence that cannot
// settle the row, and the phase may not start over it.
const SETTLED_VERDICTS = new Set(["PARITY", "NOT_APPLICABLE"]);
const ABSENT = "-";

const json = process.argv.includes("--json");
const skipCi = process.argv.includes("--skip-ci");

const lines = (await readFile(checklistPath, "utf8")).split("\n");
const rows = [];
for (const [index, line] of lines.entries()) {
  if (!/^\| [A-Z]{1,2}\d{2} \|/.test(line)) continue;
  const [, id, , , status, verdict] = line.split("|").map((cell) => cell.trim());
  rows.push({ id, status, verdict, line: index + 1 });
}

if (rows.length === 0) {
  console.error(`${path.relative(repoRoot, checklistPath)} holds no queue rows; cannot decide.`);
  process.exit(2);
}

const criteria = [];

// 1. Every row reviewed. A row with no verdict was never looked at, which is a
//    different failure from a row that was looked at and found wanting.
const unreviewed = rows.filter((row) => row.verdict === ABSENT);
criteria.push({
  id: 1,
  name: "every row reviewed",
  pass: unreviewed.length === 0,
  detail:
    unreviewed.length === 0
      ? `all ${rows.length} rows carry a verdict`
      : `${unreviewed.length} of ${rows.length} rows have no verdict: ${unreviewed.map((row) => row.id).join(", ")}`,
});

// 2. Adverse rows implemented and re-reviewed.
const adverse = rows.filter((row) => row.verdict !== ABSENT && !SETTLED_VERDICTS.has(row.verdict));
const byVerdict = new Map();
for (const row of adverse) byVerdict.set(row.verdict, (byVerdict.get(row.verdict) ?? 0) + 1);
criteria.push({
  id: 2,
  name: "no adverse rows remain",
  pass: adverse.length === 0,
  detail:
    adverse.length === 0
      ? `all ${rows.length} rows are PARITY or NOT_APPLICABLE`
      : `${adverse.length} adverse: ${[...byVerdict].map(([verdict, count]) => `${count} ${verdict}`).join(", ")}`,
});

// 3. Specification-authority blockers decided. Subsumed by criterion 2, and
//    reported separately because it fails for a different reason and is fixed by
//    a ruling rather than by work.
const blocked = rows.filter((row) => row.verdict === "BLOCKED");
criteria.push({
  id: 3,
  name: "no specification-authority blockers",
  pass: blocked.length === 0,
  detail:
    blocked.length === 0
      ? "no row is BLOCKED"
      : `${blocked.length} BLOCKED, each needing a ruling rather than work: ${blocked.map((row) => row.id).join(", ")}`,
});

// 4. Continuous integration green. Read from the pull request rather than from a
//    local run, because the two disagreed for this branch's whole life.
if (skipCi) {
  criteria.push({ id: 4, name: "CI green", pass: false, skipped: true, detail: "not evaluated" });
} else {
  try {
    const { stdout } = await run(
      "gh",
      ["pr", "checks", PULL_REQUEST, "--json", "name,state,link"],
      { cwd: repoRoot, timeout: 60_000 },
    );
    const checks = JSON.parse(stdout);
    const failing = checks.filter((check) => /fail|error|cancel|timed/i.test(check.state));
    const pending = checks.filter((check) => /pending|queued|progress|waiting/i.test(check.state));
    const passing = checks.filter((check) => /pass|success|neutral|skipp/i.test(check.state));

    criteria.push({
      id: 4,
      name: "CI green",
      pass: checks.length > 0 && failing.length === 0 && pending.length === 0,
      detail:
        checks.length === 0
          ? "the pull request reports no checks at all, which usually means a merge conflict stopped GitHub building the merge commit"
          : `${passing.length} passing, ${failing.length} failing, ${pending.length} pending` +
            (failing.length > 0
              ? `. Failing: ${failing.map((check) => check.name).join(", ")}`
              : ""),
      failing: failing.map((check) => check.name),
    });
  } catch (error) {
    // A gate that cannot reach GitHub has not learned that CI is red.
    console.error(`Could not read CI for pull request ${PULL_REQUEST}: ${error.message}`);
    process.exit(2);
  }
}

// A skipped criterion is unevaluated, not failed, so it cannot report `pass` and
// must not be counted against readiness either. Counting it made `--skip-ci`
// unable to report ready under any circumstances, which is the only thing the
// flag exists to allow.
const ready = criteria.every((criterion) => criterion.skipped || criterion.pass);

if (json) {
  console.log(JSON.stringify({ ready, rows: rows.length, criteria }, null, 2));
} else {
  console.log(`Cryptographic certification entry gate, pull request ${PULL_REQUEST}\n`);
  for (const criterion of criteria) {
    const mark = criterion.skipped ? "skip" : criterion.pass ? "pass" : "FAIL";
    console.log(`  [${mark}] ${criterion.id}. ${criterion.name}`);
    console.log(`         ${criterion.detail}`);
  }
  console.log(
    ready
      ? "\nAll four criteria hold. PKP-00 may start."
      : "\nNot ready. The phase does not start until every criterion above passes.",
  );
}

process.exit(ready ? 0 : 1);

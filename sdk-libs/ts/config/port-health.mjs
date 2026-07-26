// Report the three ways the coordinator's picture of this port goes wrong.
//
// All three failures are silent, which is what makes them expensive. An agent
// dropped by the platform leaves no error and no completion message; its
// transcript simply stops, most often part-way through a tool call whose result
// never arrives. A document that was accurate when it was written goes stale
// without changing, so it keeps reading as true. And two agents dispatched
// against one row never hear it from each other; they find out at merge, if the
// loser's work survives that long.
//
// Three agents died in one evening and were found only because their branches
// happened to sit at the same commit, which is luck rather than method. The
// reconciler died an hour before anyone noticed, and because it is the single
// writer of the review checklist, the adverse-row count the entry gate reads was
// frozen that whole time while the work behind it kept moving. Three pairs of
// agents duplicated each other that same evening, and nothing caught any of it.
//
// Exit 0 means nothing needs attention. Exit 1 means something does, and the
// report says what. Exit 2 means the check could not run, which is not the same
// as a clean bill of health and must not be read as one.
//
//   node sdk-libs/ts/config/port-health.mjs
//   node sdk-libs/ts/config/port-health.mjs --json

import { readdir, readFile, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const planDir = "planning/typescript-sdk-port";

const CONVERSATION = "107c3460-8ada-4fe1-bac5-8c28020faad2";
const transcriptDir = path.join(
  process.env.HOME ?? "",
  ".cursor/projects/Users-tilohelius-Workspace-zolana/agent-transcripts",
  CONVERSATION,
  "subagents",
);

// Quiet for this long, having ended mid-tool-call, is the signature of a drop.
// Set above the slowest gate in this repository rather than at the median,
// because a working agent waiting on a build is also silent.
const SUSPECT_MINUTES = 15;
// Below this an agent cannot have produced anything worth salvaging, so a drop
// here can be relaunched immediately rather than recovered first.
const TRIVIAL_KILOBYTES = 20;
// A worker branch left unmerged longer than this is a merge that was forgotten
// rather than one still being written.
const MERGE_BACKLOG_MINUTES = 45;

const json = process.argv.includes("--json");

// Reading another agent's worktree must never be the reason its build fails, so
// every command aimed at one runs with --no-optional-locks and leaves the index
// alone.
const gitIn = async (cwd, ...args) =>
  (await execFileAsync("git", ["--no-optional-locks", ...args], { cwd })).stdout.trim();
const git = (...args) => gitIn(repoRoot, ...args);
const minutesSince = (epochSeconds) => Math.round((Date.now() / 1000 - epochSeconds) / 60);

const problems = [];
const report = [];

// ---------------------------------------------------------------- dead agents

let workers = [];
try {
  const files = (await readdir(transcriptDir)).filter((name) => name.endsWith(".jsonl"));
  for (const file of files) {
    const info = await stat(path.join(transcriptDir, file));
    const quietMinutes = Math.round((Date.now() - info.mtimeMs) / 60_000);
    if (quietMinutes > 240) continue; // Long finished; not this evening's business.

    const text = await readFile(path.join(transcriptDir, file), "utf8").catch(() => "");
    // An agent that reaches the end of its work writes a closing record. An
    // agent that is dropped does not, and its transcript stops on whatever it
    // was saying at the time. That distinction, rather than how the text reads,
    // is what separates finished from dead: a first pass at this check looked
    // for a trailing tool call and called two agents dead that had in fact
    // finished and reported back.
    const finished = text.trimEnd().endsWith('{"type":"turn_ended","status":"success"}');

    const kilobytes = Math.round(info.size / 1024);
    let state;
    if (finished) state = "finished";
    else if (quietMinutes < SUSPECT_MINUTES) state = "working";
    else state = "DROPPED";
    workers.push({ id: file.slice(0, 8), quietMinutes, kilobytes, state });
  }
  workers.sort((a, b) => a.quietMinutes - b.quietMinutes);
} catch (error) {
  console.error(`Could not read agent transcripts: ${error.message}`);
  process.exit(2);
}

// Transcript writes lag the work badly enough to be useless on their own: four
// agents were once reported dead on a quiet transcript while every one of them
// was committing. So a quiet agent is only worth waking someone over when the
// branches have gone quiet too. Otherwise work is plainly still happening, the
// transcripts are behind, and reporting it trains the reader to ignore the
// check, which costs more than the occasional missed death.
const newestBranchCommit = Number(
  await git("log", "-1", "--format=%ct", "--all", "--branches=port/*").catch(() => "0"),
);
const branchesQuietMinutes = minutesSince(newestBranchCommit);

const dropped = workers.filter((worker) => worker.state === "DROPPED");
const stranded = dropped.filter((worker) => branchesQuietMinutes >= worker.quietMinutes);

for (const worker of stranded) {
  problems.push(
    `agent ${worker.id} has no closing record, has been quiet ${worker.quietMinutes} min, ` +
      `and no worker branch has moved in ${branchesQuietMinutes} min` +
      (worker.kilobytes < TRIVIAL_KILOBYTES
        ? " (transcript nearly empty; relaunching costs nothing)"
        : ` (${worker.kilobytes} KB; check its worktree for uncommitted work before relaunching)`),
  );
}
report.push(
  `agents: ${workers.filter((w) => w.state === "working").length} working, ` +
    `${workers.filter((w) => w.state === "finished").length} finished, ` +
    `${dropped.length} quiet (${stranded.length} with no branch activity behind them)`,
);
report.push(`branch activity: newest worker commit ${branchesQuietMinutes} min ago`);

// A transcript can lag behind an agent that is committing steadily, so a drop
// call is softened when the branches show recent commits. Reported either way,
// because a false positive costs a glance and a false negative costs an hour.

// ------------------------------------------------------------ stale checklist

// The reconciler is the single writer of the checklist, and the entry gate reads
// the checklist. If row updates have landed since the checklist last moved, the
// gate is answering from a stale count and the reconciler is behind or dead.
const checklistEpoch = Number(
  await git("log", "-1", "--format=%ct", "--", `${planDir}/review-checklist.md`),
);
const rowUpdateFiles = await readdir(path.join(repoRoot, planDir, "row-updates")).catch(() => []);
const unreconciled = [];
for (const file of rowUpdateFiles.filter((name) => name.endsWith(".md"))) {
  const epoch = Number(
    await git("log", "-1", "--format=%ct", "--", `${planDir}/row-updates/${file}`),
  );
  if (epoch > checklistEpoch) unreconciled.push(file);
}
if (unreconciled.length > 0) {
  problems.push(
    `${unreconciled.length} row update(s) landed after the checklist last moved ` +
      `${minutesSince(checklistEpoch)} min ago: ${unreconciled.join(", ")}. ` +
      "The entry gate is reading a stale adverse-row count",
  );
}
report.push(
  `checklist: last moved ${minutesSince(checklistEpoch)} min ago, ${unreconciled.length} update(s) behind`,
);

// --------------------------------------------------------------- merge backlog

const branches = (await git("branch", "--list", "port/*", "--format=%(refname:short)"))
  .split("\n")
  .filter(Boolean);
const behind = [];
for (const branch of branches) {
  const count = Number(await git("rev-list", "--count", `ts-sdk-port..${branch}`));
  if (count === 0) continue;
  const age = minutesSince(Number(await git("log", "-1", "--format=%ct", branch)));
  behind.push({ branch, count, age });
}
for (const entry of behind.filter((item) => item.age >= MERGE_BACKLOG_MINUTES)) {
  problems.push(
    `${entry.branch} has ${entry.count} commit(s) unmerged and has not moved for ${entry.age} min; ` +
      "either its agent is gone or the merge was forgotten",
  );
}
report.push(
  `branches: ${behind.length} unmerged (${behind.map((item) => `${item.branch}+${item.count}`).join(", ") || "none"})`,
);

// ------------------------------------------------------------ duplicated work

// The coordinator dispatches from memory and has no way to ask what is already
// owned, so the same work gets handed out twice. Three times in one evening:
// two workers were sent at the C04 integer domain and both rewrote
// `indexer-api/src/codec.ts`, one applying a string-or-number union to every
// integer and one going per-field; the address lookup table question was
// studied twice; and the WebAssembly hasher was verified twice, which is why
// `row-updates/` carries both `wasm-verification.md` and
// `wasm-poseidon-verification.md`. Each time, two branches sat on one file for
// an hour with nothing saying so. A convention in a document cannot fix this,
// because the failure is precisely that nobody consults the document.
//
// Uncommitted work counts, and is the reason this reads worktrees rather than
// history alone. The per-field half of the C04 collision was never committed;
// it sat unstaged in a tree and was nearly lost, so a check reading commits
// would have missed the half that mattered.

// What this stays quiet about is what decides whether it gets read. Several
// branches edit the plan's shared documents and always will -- the rulings
// ledger has an author, an auditor and a rewriter on it right now, all
// legitimately -- and naming those every run teaches the reader to skip the
// whole section, which is the false-positive trap the transcript check above
// already had to be walked back from. Lockfiles are worse still: any tree that
// runs an install shows the same diff without anyone having repeated anyone.
//
// Row updates and log entries are the exception inside the plan. Those are one
// file per batch precisely so two branches cannot contend for one, so a second
// branch in one of them is not shared-document traffic; it is two batches
// working the same subject, which is the duplicate being looked for.
const dedicatedPlanFiles = [`${planDir}/row-updates/`, `${planDir}/log/`];
const generatedFiles = new Set(["package-lock.json", "Cargo.lock"]);
const worthReporting = (file) =>
  !generatedFiles.has(file) &&
  (!file.startsWith(`${planDir}/`) || dedicatedPlanFiles.some((dir) => file.startsWith(dir)));

// A branch is live if it has unmerged commits or a dirty tree. Merged is not
// finished: `port/client-b` is merged and its tree is deliberately retained,
// and an edit made there today would collide exactly like an unmerged one.
const trees = [];
try {
  for (const block of (await git("worktree", "list", "--porcelain")).split("\n\n")) {
    const dir = block.match(/^worktree (.+)$/m)?.[1];
    const branch = block.match(/^branch refs\/heads\/(port\/.+)$/m)?.[1];
    // A prunable entry names a directory that is no longer there. Reading it
    // would fail, and failing over a tree someone already deleted would report
    // a problem that does not exist.
    if (dir && branch && !/^prunable/m.test(block)) trees.push({ dir, branch });
  }
} catch (error) {
  console.error(`Could not list worktrees: ${error.message}`);
  process.exit(2);
}

// file -> branch -> whether any of that branch's edits to it are uncommitted
const touched = new Map();
const noteTouch = (file, branch, uncommitted) => {
  const branches = touched.get(file) ?? new Map();
  branches.set(branch, uncommitted || branches.get(branch) === true);
  touched.set(file, branches);
};

for (const { branch } of behind) {
  const changed = await git("diff", "--name-only", `ts-sdk-port...${branch}`);
  for (const file of changed.split("\n").filter(Boolean)) noteTouch(file, branch, false);
}
const unreadable = [];
for (const { dir, branch } of trees) {
  const status = await gitIn(dir, "status", "--porcelain").catch(() => null);
  if (status === null) {
    unreadable.push(branch);
    continue;
  }
  // Porcelain v1 prefixes two status columns, and renames read `old -> new`.
  for (const line of status.split("\n").filter(Boolean)) {
    noteTouch(line.slice(3).split(" -> ").at(-1), branch, true);
  }
}
// A tree that could not be read may be holding an overlap that cannot be seen,
// which is not the same as there being none. Say so rather than reporting clean.
if (unreadable.length > 0) {
  problems.push(
    `could not read the working tree of ${unreadable.join(", ")}, ` +
      "so any uncommitted overlap there is invisible to this check",
  );
}

// A branch's claim on a file starts at its first edit, so the overlap itself
// starts at the later of the two claims: the moment the second agent arrived.
const claimEpoch = async (branch, file) => {
  const history = await git(
    "log",
    "--format=%ct",
    "--reverse",
    `ts-sdk-port..${branch}`,
    "--",
    file,
  );
  const firstCommit = history.split("\n")[0];
  if (firstCommit) return Number(firstCommit);
  const dir = trees.find((tree) => tree.branch === branch)?.dir;
  const info = dir ? await stat(path.join(dir, file)).catch(() => null) : null;
  return info ? info.mtimeMs / 1000 : Date.now() / 1000;
};

// Which lines a branch actually changed, taken from the hunk headers of a
// zero-context diff. Two agents in one file is the cheap signal and it is wrong
// about half the time: a large module has room for two people, and the port has
// several files every batch touches for unrelated reasons. What is never fine is
// two agents in the same lines, which is both the duplicated-work case and the
// one that loses somebody's edit at the merge.
const changedLines = async (branch, file, uncommitted) => {
  const dir = trees.find((tree) => tree.branch === branch)?.dir;
  const diff = uncommitted
    ? await gitIn(dir ?? repoRoot, "diff", "-U0", "HEAD", "--", file).catch(() => "")
    : await git("diff", "-U0", `ts-sdk-port...${branch}`, "--", file).catch(() => "");

  const ranges = [];
  for (const hunk of diff.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(hunk[1]);
    const length = hunk[2] === undefined ? 1 : Number(hunk[2]);
    // A pure deletion reports zero lines at the line it deleted from, which is
    // still a claim on that point in the file.
    ranges.push([start, start + Math.max(length, 1)]);
  }
  return ranges;
};

// Git resolves a merge with three lines of context, so edits that near each
// other conflict even without touching the same line.
const CONTEXT_LINES = 3;
const rangesIntersect = (left, right) =>
  left.some(([leftStart, leftEnd]) =>
    right.some(
      ([rightStart, rightEnd]) =>
        leftStart - CONTEXT_LINES < rightEnd && rightStart - CONTEXT_LINES < leftEnd,
    ),
  );

const collisions = [];
let sharedQuietly = 0;
let separateRegions = 0;
for (const [file, branches] of touched) {
  if (branches.size < 2) continue;
  if (!worthReporting(file)) {
    sharedQuietly += 1;
    continue;
  }
  const claims = await Promise.all(
    [...branches].map(async ([branch, uncommitted]) => ({
      branch,
      uncommitted,
      epoch: await claimEpoch(branch, file),
      lines: await changedLines(branch, file, uncommitted),
    })),
  );

  // Report the file only if some pair of branches claims overlapping lines. A
  // branch whose ranges could not be read counts as overlapping everything,
  // because silence about an unreadable diff would read as a clean bill.
  const contested = claims.some((left, index) =>
    claims
      .slice(index + 1)
      .some(
        (right) =>
          left.lines.length === 0 ||
          right.lines.length === 0 ||
          rangesIntersect(left.lines, right.lines),
      ),
  );
  if (!contested) {
    separateRegions += 1;
    continue;
  }

  const minutes = minutesSince(Math.max(...claims.map((claim) => claim.epoch)));
  collisions.push({ file, minutes, branches: claims.sort((a, b) => a.epoch - b.epoch) });
}

// No minimum age, unlike the merge backlog above. A branch left unmerged for
// ten minutes is a merge still being written, but two branches on one module is
// wrong from the first minute, and the C04 overlap stood for an hour precisely
// because nothing said anything early.
for (const { file, minutes, branches } of collisions.sort((a, b) => b.minutes - a.minutes)) {
  const named = branches
    .map((claim) => (claim.uncommitted ? `${claim.branch} (uncommitted)` : claim.branch))
    .join(", ");
  problems.push(
    `${file} has overlapping edits on ${branches.length} live branches for ${minutes} min ` +
      `(${named}); either one agent is repeating the other's work, or one of them ` +
      "loses it at the merge without being told",
  );
}
report.push(
  `overlap: ${collisions.length} file(s) with contested lines` +
    (separateRegions > 0 ? `, ${separateRegions} shared but in separate regions` : "") +
    (sharedQuietly > 0 ? `, ${sharedQuietly} shared plan/lock file(s) left unreported` : ""),
);

// ------------------------------------------------------------- stale plan text

// The status block carries a timestamp because a reader has no other way to
// judge whether the numbers beside it still hold.
const readme = await readFile(path.join(repoRoot, planDir, "README.md"), "utf8").catch(() => "");
const stamp = readme.match(/Last update: (\d{4}-\d{2}-\d{2} \d{2}:\d{2})/);
if (!stamp) {
  problems.push("the plan's status block has no timestamp, so its numbers cannot be dated");
} else {
  const planAge = Math.round(
    (Date.now() - new Date(stamp[1].replace(" ", "T")).getTime()) / 60_000,
  );
  const tipAge = minutesSince(Number(await git("log", "-1", "--format=%ct", "ts-sdk-port")));
  // Age alone means nothing during a quiet spell. The plan is stale when the
  // branch moved after the plan last claimed to describe it.
  if (planAge > 45 && tipAge < planAge - 30) {
    problems.push(
      `the plan's status block is ${planAge} min old while the branch moved ${tipAge} min ago; ` +
        "its counts describe an earlier state",
    );
  }
  report.push(`plan: status block ${planAge} min old, branch tip ${tipAge} min old`);
}

// ------------------------------------------------------------------- reporting

if (json) {
  console.log(
    JSON.stringify(
      { healthy: problems.length === 0, problems, report, workers, collisions },
      null,
      2,
    ),
  );
} else {
  console.log("Port health\n");
  for (const line of report) console.log(`  ${line}`);
  if (problems.length === 0) {
    console.log("\nNothing needs attention.");
  } else {
    console.log(`\n${problems.length} thing(s) need attention:\n`);
    for (const problem of problems) console.log(`  - ${problem}`);
  }
}

process.exit(problems.length === 0 ? 0 : 1);

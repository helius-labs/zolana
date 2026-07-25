// Report the two ways the coordinator's picture of this port goes wrong.
//
// Both failures are silent, which is what makes them expensive. An agent dropped
// by the platform leaves no error and no completion message; its transcript
// simply stops, most often part-way through a tool call whose result never
// arrives. And a document that was accurate when it was written goes stale
// without changing, so it keeps reading as true.
//
// Three agents died in one evening and were found only because their branches
// happened to sit at the same commit, which is luck rather than method. The
// reconciler died an hour before anyone noticed, and because it is the single
// writer of the review checklist, the adverse-row count the entry gate reads was
// frozen that whole time while the work behind it kept moving.
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

const git = async (...args) => (await execFileAsync("git", args, { cwd: repoRoot })).stdout.trim();
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
    JSON.stringify({ healthy: problems.length === 0, problems, report, workers }, null, 2),
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

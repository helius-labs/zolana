// Report which port workers are alive, which are idle, and which died quietly.
//
// Agents on this project are dropped by the platform without notice. The drop
// leaves no error and no completion message: the transcript simply stops, most
// often part-way through a tool call whose result never arrives. Three agents
// died that way in one evening and none of them announced it. They were found
// only because their branches happened to sit at the same commit as each other,
// which was luck rather than method.
//
// A dead agent is expensive in proportion to how long it goes unnoticed, because
// the coordinator keeps counting it as in-flight and keeps not reassigning its
// work. So liveness is read here from two signals that a dead agent cannot fake:
// when its transcript was last written, and whether that transcript ends on a
// tool call with no result. Neither is conclusive alone. A working agent running
// a long build also goes quiet, and an agent that has genuinely finished also
// ends without further writes.
//
//   node sdk-libs/ts/config/worker-liveness.mjs
//   node sdk-libs/ts/config/worker-liveness.mjs --json

import { readdir, readFile, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

// Cursor writes one transcript per subagent under the parent conversation.
const CONVERSATION = "107c3460-8ada-4fe1-bac5-8c28020faad2";
const transcriptDir = path.join(
  process.env.HOME,
  ".cursor/projects/Users-tilohelius-Workspace-zolana/agent-transcripts",
  CONVERSATION,
  "subagents",
);

// Quiet for this long, having ended mid-tool-call, is the signature of a drop.
// A build can hold an agent silent for several minutes, so the threshold is set
// above the slowest gate in this repository rather than at the median.
const SUSPECT_MINUTES = 8;
// Below this, an agent cannot have done meaningful work, whatever its state says.
const TRIVIAL_KILOBYTES = 20;

const json = process.argv.includes("--json");

const { stdout: worktreeList } = await run("git", ["worktree", "list"], { cwd: repoRoot });
const branchOf = new Map();
for (const line of worktreeList.trim().split("\n")) {
  const match = line.match(/^(\S+)\s+\S+\s+\[([^\]]+)\]/);
  if (match) branchOf.set(path.basename(match[1]), match[2]);
}

const files = (await readdir(transcriptDir)).filter((name) => name.endsWith(".jsonl"));
const now = Date.now();
const workers = [];

for (const file of files) {
  const full = path.join(transcriptDir, file);
  const info = await stat(full);
  const quietMinutes = Math.round((now - info.mtimeMs) / 60_000);
  const kilobytes = Math.round(info.size / 1024);

  // Read only the tail. These files reach hundreds of kilobytes and the question
  // is answered entirely by how the last record ends.
  const handle = await readFile(full, "utf8").catch(() => "");
  const tail = handle.slice(-4000);
  const endsMidToolCall =
    /"type":"tool_use"/.test(tail.slice(tail.lastIndexOf('{"type"'))) ||
    (tail.lastIndexOf('"tool_use"') > tail.lastIndexOf('"tool_result"') &&
      tail.lastIndexOf('"tool_use"') !== -1);

  let state;
  if (quietMinutes < SUSPECT_MINUTES) state = "working";
  else if (endsMidToolCall) state = "DROPPED";
  else state = "finished or idle";

  workers.push({
    id: file.slice(0, 8),
    quietMinutes,
    kilobytes,
    state,
    // A drop that happened before the agent produced anything is worth calling
    // out separately: relaunching it costs nothing, so there is no salvage step.
    trivial: kilobytes < TRIVIAL_KILOBYTES,
  });
}

workers.sort((a, b) => a.quietMinutes - b.quietMinutes);

const dropped = workers.filter((worker) => worker.state === "DROPPED");

if (json) {
  console.log(
    JSON.stringify({ dropped: dropped.length, workers, branches: [...branchOf] }, null, 2),
  );
} else {
  console.log("Worker liveness\n");
  for (const worker of workers) {
    const mark =
      worker.state === "DROPPED" ? "DROPPED" : worker.state === "working" ? "working" : "idle";
    console.log(
      `  [${mark.padEnd(8)}] ${worker.id}  quiet ${String(worker.quietMinutes).padStart(3)} min  ${String(worker.kilobytes).padStart(4)} KB` +
        (worker.trivial && worker.state === "DROPPED"
          ? "  (produced nothing; relaunch, no salvage)"
          : ""),
    );
  }
  console.log(
    `\nWorktree branches: ${[...branchOf.values()].filter((b) => b.startsWith("port/")).join(", ")}`,
  );
  if (dropped.length > 0) {
    console.log(
      `\n${dropped.length} agent(s) ended mid-tool-call and have been quiet past ${SUSPECT_MINUTES} minutes.` +
        "\nCheck each one's worktree for uncommitted work before relaunching; salvage first, relaunch second.",
    );
  }
}

process.exit(dropped.length > 0 ? 1 : 0);

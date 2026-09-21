import { writeFile } from "node:fs/promises";
import { join } from "node:path";

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character],
  );
const csv = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
const number = (value) => (Number.isFinite(value) ? value.toFixed(2) : "");

export async function writeReports({ directory, metadata, results, budget }) {
  await writeFile(
    join(directory, "results.json"),
    JSON.stringify({ metadata, budget, results }, null, 2),
    { mode: 0o600 },
  );
  const columns = [
    "attempt",
    "family",
    "deployment",
    "source",
    "repetition",
    "shape",
    "actualShape",
    "variant",
    "route",
    "status",
    "verified",
    "proofReceivedMs",
    "sdkReadyMs",
    "totalMs",
    "reason",
    "error",
  ];
  const rows = [columns, ...results.map((result) => columns.map((key) => result[key]))];
  await writeFile(
    join(directory, "results.csv"),
    rows.map((row) => row.map(csv).join(",")).join("\n") + "\n",
    { mode: 0o600 },
  );
  const stages = [
    [
      "attempt",
      "family",
      "deployment",
      "lane",
      "operation",
      "startMs",
      "endMs",
      "durationMs",
      "status",
      "responseBytes",
      "contextSlot",
      "serverTiming",
      "clock",
    ],
  ];
  for (const result of results) {
    for (const request of result.requests ?? [])
      stages.push([
        result.attempt,
        result.family,
        result.deployment,
        request.lane,
        request.operation,
        request.startMs,
        request.endMs,
        request.durationMs,
        request.status,
        request.responseBytes,
        request.contextSlot,
        request.serverTiming,
        "client",
      ]);
    for (const span of result.spans ?? [])
      stages.push([
        result.attempt,
        result.family,
        result.deployment,
        "client",
        span.name,
        span.startMs,
        span.endMs,
        span.durationMs,
        "",
        "",
        "",
        "",
        "client",
      ]);
    for (const request of result.requests ?? []) {
      for (const stage of request.serverStages ?? [])
        stages.push([
          result.attempt,
          result.family,
          result.deployment,
          "server",
          stage.name,
          stage.start_ms,
          stage.start_ms + stage.duration_ms,
          stage.duration_ms,
          stage.complete ? "complete" : "incomplete",
          "",
          "",
          "",
          "server",
        ]);
    }
  }
  await writeFile(
    join(directory, "stages.csv"),
    stages.map((row) => row.map(csv).join(",")).join("\n") + "\n",
    { mode: 0o600 },
  );
  const longest = Math.max(1, ...results.map((result) => result.totalMs ?? 0));
  const pixelsPerMs = Math.max(0.05, Math.min(4, 1200 / longest));
  const width = Math.max(600, longest * pixelsPerMs);
  const bar = (name, start, end, lane) =>
    `<div class="row"><span>${escape(name)}</span><div class="track" style="width:${width}px"><div class="bar ${lane}" style="left:${start * pixelsPerMs}px;width:${Math.max(1, (end - start) * pixelsPerMs)}px" title="${number(start)}–${number(end)} ms">${number(end - start)} ms</div></div></div>`;
  const charts = results
    .map((result) => {
      const title = `${result.attempt ?? "—"} ${result.family} / ${result.deployment} / ${result.source}${result.variant ? ` / ${result.variant} / ${result.actualShape ?? result.shape} / ${result.route}` : ""} / ${result.status}`;
      if (!result.requests)
        return `<section><h2>${escape(title)}</h2><p>${escape(result.reason)}</p></section>`;
      const rows = [bar("End to end", 0, result.proofReceivedMs ?? result.totalMs, "total")];
      for (const span of result.spans)
        rows.push(bar(span.name, span.startMs, span.endMs, "client"));
      for (const request of result.requests) {
        rows.push(
          bar(`${request.lane} ${request.operation}`, request.startMs, request.endMs, request.lane),
        );
        const points = [
          ["socket", request.phases.socketMs],
          ["DNS", request.phases.dnsMs],
          ["TCP", request.phases.connectMs],
          ["TLS", request.phases.tlsMs],
          ["Upload", request.phases.uploadFinishedMs],
          ["Wait for headers", request.phases.firstByteMs],
          ["Download", request.endMs],
        ].filter(([, value]) => Number.isFinite(value));
        let start = request.startMs;
        for (const [name, end] of points) {
          rows.push(
            bar(
              `  ${name}${request.reusedConnection && name === "socket" ? " (reused)" : ""}`,
              start,
              end,
              request.lane,
            ),
          );
          start = end;
        }
        if (request.serverTiming)
          rows.push(`<p class="timing">Server-Timing ${escape(request.serverTiming)}</p>`);
      }
      for (const request of result.requests) {
        if (!request.serverStages?.length) continue;
        rows.push(
          "<p>Server clock starts at request receipt. Its origin is separate from the client clock above. Nested stages overlap.</p>",
        );
        for (const stage of request.serverStages)
          rows.push(
            bar(
              `${stage.name}${stage.complete ? "" : " (incomplete)"}`,
              stage.start_ms,
              stage.start_ms + stage.duration_ms,
              stage.name.startsWith("get") ? "indexer" : "prover",
            ),
          );
      }
      return `<section><h2>${escape(title)}</h2><p>Proof received ${number(result.proofReceivedMs)} ms · Verified ${escape(result.verified ?? false)} · Total ${number(result.totalMs)} ms${result.error ? ` · ${escape(result.error)}` : ""}</p>${rows.join("")}</section>`;
    })
    .join("");
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Live proof latency</title><style>body{font:14px system-ui;margin:24px;background:#101827;color:#e5e7eb}h1{font-size:24px}h2{font-size:16px}section{margin:28px 0;padding:16px;background:#182234;overflow-x:auto}.row{display:flex;height:25px;align-items:center}.row>span{width:260px;flex-shrink:0;font-size:12px}.track{position:relative;height:20px;flex-shrink:0;background:repeating-linear-gradient(90deg,transparent,transparent 99px,#334155 100px)}.bar{position:absolute;height:18px;border-radius:2px;white-space:nowrap;font-size:11px;color:white}.total{background:#64748b}.client{background:#8b5cf6}.indexer{background:#0284c7}.prover{background:#059669}.timing{margin-left:260px;font:12px monospace}p{color:#cbd5e1}</style><h1>Live proof latency</h1><p>One common scale across all attempts. ${number(pixelsPerMs)} pixels per millisecond. Indexer calls overlap when sent together. Socket events measure the client connection to its endpoint. Server stages and client socket phases overlap and must not be added together. Missing server phases are unobserved. First use can include key loading. These samples do not establish tail latency.</p>${charts}</html>`;
  await writeFile(join(directory, "waterfall.html"), html, { mode: 0o600 });
}

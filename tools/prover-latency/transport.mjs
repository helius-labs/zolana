import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";

export class TimedTransport {
  #agents = {
    "http:": new http.Agent({ keepAlive: true }),
    "https:": new https.Agent({ keepAlive: true }),
  };

  close() {
    for (const agent of Object.values(this.#agents)) agent.destroy();
  }

  async request({ url, init = {}, signal, origin, record }) {
    const target = new URL(url);
    if (!this.#agents[target.protocol]) throw new Error("Unsupported transport");
    const start = performance.now();
    const relative = () => performance.now() - origin;
    const row = { startMs: start - origin, endMs: null, phases: {}, reusedConnection: false };
    record(row);
    return new Promise((resolve, reject) => {
      const fail = (error) => {
        row.endMs = relative();
        row.durationMs = performance.now() - start;
        row.error = signal?.aborted ? "aborted" : "transport_error";
        reject(error);
      };
      const client = target.protocol === "https:" ? https : http;
      const headers = Object.fromEntries(new Headers(init.headers));
      headers["accept-encoding"] = "identity";
      const body = init.body === undefined ? undefined : Buffer.from(String(init.body));
      if (body) headers["content-length"] = String(body.length);
      row.requestBytes = body?.length ?? 0;
      const request = client.request(
        target,
        {
          method: init.method ?? "GET",
          headers,
          agent: this.#agents[target.protocol],
          signal,
        },
        (response) => {
          row.phases.firstByteMs = relative();
          row.status = response.statusCode;
          row.serverTiming = response.headers["server-timing"] ?? null;
          row.serverStages = parseServerStages(response.headers["x-prover-timing"]);
          row.requestId = response.headers["x-request-id"] ?? null;
          const chunks = [];
          let bytes = 0;
          response.on("data", (chunk) => {
            bytes += chunk.length;
            if (bytes > 4 * 1024 * 1024) request.destroy(new Error("Response exceeds limit"));
            else chunks.push(chunk);
          });
          response.on("error", fail);
          response.on("end", () => {
            row.endMs = relative();
            row.responseBytes = bytes;
            row.durationMs = performance.now() - start;
            const status = response.statusCode ?? 500;
            const responseHeaders = Object.entries(response.headers).flatMap(([key, value]) =>
              value === undefined ? [] : [[key, Array.isArray(value) ? value.join(", ") : value]],
            );
            resolve(
              new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), {
                status,
                headers: responseHeaders,
              }),
            );
          });
        },
      );
      request.on("socket", (socket) => {
        row.reusedConnection = request.reusedSocket;
        row.phases.socketMs = relative();
        if (socket.connecting) {
          socket.once("lookup", () => {
            row.phases.dnsMs = relative();
          });
          socket.once("connect", () => {
            row.phases.connectMs = relative();
          });
          socket.once("secureConnect", () => {
            row.phases.tlsMs = relative();
          });
        }
      });
      request.on("finish", () => {
        row.phases.uploadFinishedMs = relative();
      });
      request.on("error", fail);
      request.end(body);
    });
  }
}

export function parseServerStages(header) {
  if (typeof header !== "string") return [];
  try {
    const stages = JSON.parse(header);
    if (!Array.isArray(stages) || stages.length > 33) return [];
    return stages
      .filter(
        (stage) =>
          stage &&
          typeof stage.name === "string" &&
          stage.name.length <= 64 &&
          Number.isFinite(stage.start_ms) &&
          stage.start_ms >= 0 &&
          Number.isFinite(stage.duration_ms) &&
          stage.duration_ms >= 0 &&
          typeof stage.complete === "boolean",
      )
      .map(({ name, start_ms, duration_ms, complete }) => ({
        name,
        start_ms,
        duration_ms,
        complete,
      }));
  } catch {
    return [];
  }
}

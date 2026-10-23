// The gateway docs/gateway.md describes and nothing beyond it. The live suite
// reaches the prover, Photon and ring RPC through it the way it reaches a
// hosted deployment, without depending on any one gateway's configuration.
import { readFileSync } from "node:fs";
import {
  createServer,
  request,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from "node:http";

import { wireDecoder } from "../src/interface/decode.js";

export type Origin = "prover" | "photon" | "ringRpc";

export interface Route {
  readonly method: string;
  readonly path: string;
  readonly origin: Origin;
}

/** One answered request, as the gateway bills it. */
export interface Billed {
  readonly route: Route;
  readonly status: number;
  /** Zero for anything but a 2xx answer. */
  readonly units: number;
}

export interface ReferenceGateway {
  readonly url: URL;
  /** Every request the gateway forwarded, in the order it answered them. */
  readonly billed: readonly Billed[];
  close(): Promise<void>;
}

const ORIGINS: readonly Origin[] = ["prover", "photon", "ringRpc"];
const decode = wireDecoder((path) => new Error(`docs/gateway.json ${path}`));
const file = decode.record(
  JSON.parse(readFileSync(new URL("../../../docs/gateway.json", import.meta.url), "utf8")),
  "",
);

function origin(value: unknown, path: string): Origin {
  const name = decode.string(value, path);
  const known = ORIGINS.find((origin) => origin === name);
  if (known === undefined) throw new Error(`docs/gateway.json ${path}`);
  return known;
}

function headerNames(key: string): readonly string[] {
  return decode
    .list(file[key], key)
    .map((name, index) => decode.string(name, `${key}[${index}]`).toLowerCase());
}

export const contract = Object.freeze({
  credential: decode.string(file["credential"], "credential"),
  meteringUnitsHeader: decode
    .string(file["meteringUnitsHeader"], "meteringUnitsHeader")
    .toLowerCase(),
  routes: decode.list(file["routes"], "routes").map((entry, index): Route => {
    const route = decode.record(entry, `routes[${index}]`);
    return Object.freeze({
      method: decode.string(route["method"], `routes[${index}].method`),
      path: decode.string(route["path"], `routes[${index}].path`),
      origin: origin(route["origin"], `routes[${index}].origin`),
    });
  }),
  requestHeaders: headerNames("requestHeaders"),
  responseHeaders: headerNames("responseHeaders"),
});

/** The route serving `method` on `path`; a `{name}` segment matches any one segment. */
export function routeOf(method: string, path: string): Route | undefined {
  const segments = path.split("/");
  return contract.routes.find((route) => {
    const pattern = route.path.split("/");
    return (
      route.method === method &&
      pattern.length === segments.length &&
      pattern.every((part, index) =>
        /^\{\w+\}$/u.test(part) ? segments[index] !== "" : part === segments[index],
      )
    );
  });
}

/**
 * Splits a request target into the target a gateway forwards and the
 * credentials it removed: every query pair whose form-decoded name is the
 * credential. Every other pair is kept byte for byte and in order.
 */
export function withoutCredentials(
  target: string,
): Readonly<{ target: string; credentials: readonly string[] }> {
  const separator = target.indexOf("?");
  if (separator === -1) return { target, credentials: [] };
  const credentials: string[] = [];
  const kept: string[] = [];
  for (const pair of target.slice(separator + 1).split("&")) {
    // URLSearchParams drops one leading "?", so the prefix keeps a pair's own.
    const first = new URLSearchParams(`?${pair}`).entries().next();
    if (!first.done && first.value[0] === contract.credential) credentials.push(first.value[1]);
    else kept.push(pair);
  }
  const path = target.slice(0, separator);
  return { target: kept.length === 0 ? path : `${path}?${kept.join("&")}`, credentials };
}

function pick(headers: IncomingHttpHeaders, names: readonly string[]): OutgoingHttpHeaders {
  const picked: OutgoingHttpHeaders = {};
  for (const name of names) {
    const value = headers[name];
    if (value !== undefined) picked[name] = value;
  }
  return picked;
}

function meteringUnits(headers: IncomingHttpHeaders): number {
  const value = headers[contract.meteringUnitsHeader];
  if (value === undefined) return 1;
  const units = typeof value === "string" && /^[1-9]\d*$/u.test(value) ? Number(value) : NaN;
  if (!Number.isSafeInteger(units)) throw new Error(`malformed ${contract.meteringUnitsHeader}`);
  return units;
}

async function body(message: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of message) {
    if (!(chunk instanceof Buffer)) throw new Error("unexpected body chunk");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * node:http rather than fetch, which parses the target as a WHATWG URL and can
 * re-encode it; the contract forwards the target byte for byte.
 */
function forward(
  origin: URL,
  method: string,
  target: string,
  headers: OutgoingHttpHeaders,
  payload: Buffer,
): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const call = request(
      {
        host: origin.hostname,
        port: origin.port,
        method,
        path: target,
        headers: { ...headers, "content-length": payload.length },
      },
      resolve,
    );
    call.on("error", reject);
    call.end(payload);
  });
}

export async function startReferenceGateway(
  input: Readonly<{ origins: Readonly<Record<Origin, string>>; apiKeys: readonly string[] }>,
): Promise<ReferenceGateway> {
  const origins = new Map(ORIGINS.map((name) => [name, new URL(input.origins[name])]));
  for (const [name, url] of origins) {
    // The path reaches the origin unchanged, so an origin is a host alone.
    if (url.pathname !== "/" || url.search !== "") throw new Error(`${name} origin has a path`);
  }
  const apiKeys = new Set(input.apiKeys);
  const billed: Billed[] = [];

  async function serve(incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
    const method = incoming.method ?? "";
    const target = incoming.url ?? "";
    const separator = target.indexOf("?");
    const route = routeOf(method, separator === -1 ? target : target.slice(0, separator));
    if (route === undefined) {
      outgoing.writeHead(404).end();
      return;
    }
    const forwarded = withoutCredentials(target);
    const [key] = forwarded.credentials;
    if (forwarded.credentials.length !== 1 || key === undefined || !apiKeys.has(key)) {
      outgoing.writeHead(401).end();
      return;
    }
    const origin = origins.get(route.origin);
    if (origin === undefined) throw new Error(`no ${route.origin} origin`);
    const answer = await forward(
      origin,
      method,
      forwarded.target,
      pick(incoming.headers, contract.requestHeaders),
      await body(incoming),
    );
    const status = answer.statusCode ?? 0;
    const payload = await body(answer);
    const units = status >= 200 && status < 300 ? meteringUnits(answer.headers) : 0;
    billed.push(Object.freeze({ route, status, units }));
    outgoing.writeHead(status, pick(answer.headers, contract.responseHeaders)).end(payload);
  }

  const server = createServer((incoming, outgoing) => {
    serve(incoming, outgoing).catch(() => {
      if (!outgoing.headersSent) outgoing.writeHead(502);
      outgoing.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("gateway has no port");
  return {
    url: new URL(`http://127.0.0.1:${address.port}`),
    billed,
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      }),
  };
}

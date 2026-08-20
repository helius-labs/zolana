#!/usr/bin/env python3
"""Record /prove request bodies while forwarding them to a real prover.

The prover's happy path cannot be hand-written: every field of a witness is
Poseidon-consistent with the others, so a replayable request body has to come
from a run that produced one. This proxy sits in front of the prover, writes
each POST /prove (or /queue/add) body to a file, and forwards the request
untouched. tools/hurl/prover/prove*.hurl replay those files.

    tools/hurl/capture-witness.py --listen 3101 --prover http://127.0.0.1:3001

    # anything that proves, pointed at the proxy instead of the prover
    ZOLANA_PROVER_URL=http://127.0.0.1:3101 just test-transact

Files land in tools/hurl/fixtures as <circuitType>-<in>x<out>-<n>.json. A
witness is plaintext -- amounts, owner hashes, blindings, nullifier secrets --
so the fixtures directory is gitignored. Keep captures out of anywhere that is
not.
"""

import argparse
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Rewritten or dropped per hop, so never copied between the two connections.
HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

CAPTURED_PATHS = {"/prove", "/queue/add"}


def build_handler(prover, out_dir):
    prover = prover.rstrip("/")
    captured = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.forward(None)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if self.path.split("?")[0] in CAPTURED_PATHS:
                self.save(body)
            self.forward(body)

        def save(self, body):
            try:
                request = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            if not isinstance(request, dict):
                return
            circuit = request.get("circuitType", "unknown")
            shape = ""
            if "nInputs" in request and "nOutputs" in request:
                shape = "-{}x{}".format(request["nInputs"], request["nOutputs"])
            captured["count"] += 1
            path = os.path.join(
                out_dir, "{}{}-{:03d}.json".format(circuit, shape, captured["count"])
            )
            with open(path, "wb") as handle:
                handle.write(body)
            print("captured {} ({} bytes)".format(path, len(body)), flush=True)

        def forward(self, body):
            headers = {
                name: value
                for name, value in self.headers.items()
                if name.lower() not in HOP_BY_HOP
            }
            request = urllib.request.Request(
                prover + self.path, data=body, headers=headers, method=self.command
            )
            try:
                # Generous: a cold key load plus a batch proof runs for minutes,
                # and timing out here would look like a prover failure.
                with urllib.request.urlopen(request, timeout=900) as response:
                    self.relay(response.status, response.headers, response.read())
            except urllib.error.HTTPError as error:
                self.relay(error.code, error.headers, error.read())
            except OSError as error:
                self.relay(502, {}, str(error).encode())

        def relay(self, status, headers, body):
            self.send_response(status)
            for name, value in dict(headers).items():
                if name.lower() not in HOP_BY_HOP:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def main():
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=int, default=3101, help="local proxy port")
    parser.add_argument(
        "--prover", default="http://127.0.0.1:3001", help="prover to forward to"
    )
    parser.add_argument("--out-dir", default=default_out, help="where to write bodies")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.listen), build_handler(args.prover, args.out_dir)
    )
    print(
        "capturing /prove bodies to {}; forwarding 127.0.0.1:{} -> {}".format(
            args.out_dir, args.listen, args.prover
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

import contextlib
import fcntl
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "gpu"))

import aws_host  # noqa: E402
from aws_host import NGINX, healthy, run, secret  # noqa: E402

ROOT = Path("/opt/zolana-nitro")
ENCLAVE = "zolana-prover"
ENCLAVE_CID = 16
# Pinned to the VSOCK-LISTEN port in prover/server/nitro/entrypoint.sh.
ENCLAVE_PORT = 3001
# Matches the prover upstream port in aws_host.gateway.
INGRESS_PORT = 3003
AUTHORIZER_PORT = 3004
GATEWAY_PORT = 3001
PROXY_CONFIG = Path("/etc/nitro_enclaves/zolana-vsock-proxy.yaml")
# Exceeds the prover's default indexer concurrency plus key downloads.
PROXY_WORKERS = 64
ALLOCATOR_CONFIG = Path("/etc/nitro_enclaves/allocator.yaml")
UNITS = Path("/etc/systemd/system")
# SSM runs nitro-cli without HOME.
ARTIFACTS = Path("/var/lib/zolana-nitro/artifacts")
MEASUREMENTS = "install/measurements.json"
PCRS = ("PCR0", "PCR1", "PCR2")
# PCRs change with the nitro-cli release.
NITRO_CLI = "1.5.0-0.amzn2023"
NITRO_PACKAGES = tuple(
    f"{name}-{NITRO_CLI}"
    for name in ("aws-nitro-enclaves-cli", "aws-nitro-enclaves-cli-devel")
)
ROUTE = re.compile(
    r"(127\.0\.0\.[0-9]{1,3}) ((?:[a-z0-9-]+\.)+[a-z0-9-]+) ([0-9]{1,5}) ([0-9]{4,5})"
)


def allocator(config):
    return f"---\nmemory_mib: {config['enclave_memory_mib']}\ncpu_count: {config['enclave_cpus']}\n"


# Only a local measure shows stderr, host output can carry secrets.
SHOW_ERRORS = False


def nitro(*args, timeout=300):
    ARTIFACTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    return run(
        "nitro-cli",
        *args,
        timeout=timeout,
        env=dict(os.environ, NITRO_CLI_ARTIFACTS=str(ARTIFACTS)),
        show_errors=SHOW_ERRORS,
    )


def enclave_command(config):
    return [
        "run-enclave",
        "--eif-path",
        str(ROOT / "prover.eif"),
        "--cpu-count",
        str(config["enclave_cpus"]),
        "--memory",
        str(config["enclave_memory_mib"]),
        "--enclave-cid",
        str(ENCLAVE_CID),
        "--enclave-name",
        ENCLAVE,
    ]


def parse_routes(text):
    routes = []
    for line in text.splitlines():
        match = ROUTE.fullmatch(line)
        if not match:
            raise ValueError("Image carries a malformed egress route")
        address, host, port, vsock = match.groups()
        routes.append(
            {"address": address, "host": host, "port": int(port), "vsock": int(vsock)}
        )
    if not routes or len({route["vsock"] for route in routes}) != len(routes):
        raise ValueError("Image egress routes are empty or reuse a vsock port")
    return routes


def proxy_config(routes):
    return json.dumps(
        {
            "allowlist": [
                {"address": route["host"], "port": route["port"]} for route in routes
            ]
        },
        indent=2,
    )


def unit(description, command, options=(), requires=()):
    lines = [
        "[Unit]",
        f"Description={description}",
        "After=network-online.target nitro-enclaves-allocator.service",
        "Wants=network-online.target",
        *(f"Requires={name}" for name in requires),
        "",
        "[Service]",
        f"ExecStart={command}",
        "Restart=always",
        "RestartSec=5",
        *options,
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def units(routes):
    sandbox = ("DynamicUser=yes", "PrivateTmp=yes", "Environment=HOME=/tmp")
    written_units = {
        f"zolana-egress-{route['vsock']}.service": unit(
            f"Enclave egress to {route['host']}",
            f"/usr/bin/vsock-proxy --ipv4 --num_workers {PROXY_WORKERS} --config {PROXY_CONFIG} {route['vsock']} {route['host']} {route['port']}",
            sandbox,
        )
        for route in routes
    }
    written_units["zolana-ingress.service"] = unit(
        "Prover ingress into the enclave",
        f"/usr/bin/socat TCP-LISTEN:{INGRESS_PORT},bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:{ENCLAVE_CID}:{ENCLAVE_PORT}",
        sandbox,
    )
    written_units["zolana-authorizer.service"] = unit(
        "Gateway API key check",
        f"/usr/bin/python3 {ROOT}/aws_nitro_host.py authorize {ROOT}/config.json",
        sandbox,
    )
    written_units["zolana-enclave.service"] = unit(
        "Prover enclave",
        f"/usr/bin/python3 {ROOT}/aws_nitro_host.py supervise {ROOT}/config.json",
        (
            f"Environment=NITRO_CLI_ARTIFACTS={ARTIFACTS}",
            f"ExecStopPost=-/usr/bin/nitro-cli terminate-enclave --enclave-name {ENCLAVE}",
        ),
        requires=("nitro-enclaves-allocator.service",),
    )
    return written_units


def presented_key(headers, query):
    if headers.get("X-API-Key"):
        return headers["X-API-Key"]
    authorization = headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[len("Bearer ") :]
    return urllib.parse.parse_qs(query).get("api-key", [""])[0]


def authorizer(key):
    expected = key.encode()

    class Handler(BaseHTTPRequestHandler):
        def answer(self):
            url = urllib.parse.urlsplit(self.path)
            provided = presented_key(self.headers, url.query).encode("utf-8", "replace")
            allowed = (
                url.path == "/auth"
                and provided
                and hmac.compare_digest(provided, expected)
            )
            self.send_response(204 if allowed else 401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = answer

        def log_message(self, *args):
            pass

    return Handler


def serve_authorizer(key, port=AUTHORIZER_PORT):
    ThreadingHTTPServer(("127.0.0.1", port), authorizer(key)).serve_forever()


def enclave_state():
    try:
        enclaves = json.loads(nitro("describe-enclaves", timeout=60))
    except (RuntimeError, ValueError):
        print("nitro-cli describe-enclaves failed", file=sys.stderr, flush=True)
        return None
    return next(
        (e.get("State") for e in enclaves if e.get("EnclaveName") == ENCLAVE),
        "ABSENT",
    )


def supervise(config, poll=10):
    with contextlib.suppress(RuntimeError):
        nitro("terminate-enclave", "--enclave-name", ENCLAVE, timeout=120)
    nitro(*enclave_command(config))
    while (state := enclave_state()) in ("RUNNING", None):
        time.sleep(poll)
    raise RuntimeError(f"Enclave is {state}")


def image_files(image):
    container = run("docker", "create", image)
    try:
        with tempfile.TemporaryDirectory() as directory:
            run("docker", "cp", f"{container}:/etc/zolana-nitro/.", directory)
            files = Path(directory)
            return (
                parse_routes((files / "routes").read_text()),
                (files / "indexer-url").read_text().strip(),
            )
    finally:
        run("docker", "rm", container)


def measurements(built, described, image):
    pcrs = {name: described["Measurements"][name] for name in PCRS}
    if any(built["Measurements"][name] != value for name, value in pcrs.items()):
        raise RuntimeError("describe-eif disagrees with build-enclave")
    return {
        **pcrs,
        "HashAlgorithm": described["Measurements"]["HashAlgorithm"],
        "image": image,
        "nitro_cli": nitro("--version"),
    }


def build_eif(image, eif):
    built = json.loads(
        nitro(
            "build-enclave",
            "--docker-uri",
            image,
            "--output-file",
            str(eif),
            timeout=900,
        )
    )
    described = json.loads(nitro("describe-eif", "--eif-path", str(eif)))
    return measurements(built, described, image)


def install_nitro_cli(*packages):
    run(
        "dnf",
        "install",
        "-y",
        "-q",
        *NITRO_PACKAGES,
        *packages,
        timeout=900,
        show_errors=SHOW_ERRORS,
    )


def write(path, text, mode=0o644):
    path.write_text(text)
    path.chmod(mode)


def install(config):
    outputs = config["outputs"]
    image = config["prover_image"]
    install_nitro_cli("docker", "socat")
    subprocess.run(
        ["systemctl", "stop", "zolana-enclave.service"],
        capture_output=True,
        check=False,
        timeout=180,
    )
    write(ALLOCATOR_CONFIG, allocator(config))
    run("systemctl", "enable", "--now", "docker")
    run("systemctl", "enable", "nitro-enclaves-allocator.service")
    run("systemctl", "restart", "nitro-enclaves-allocator.service", timeout=600)

    aws_host.pull(config, (image, NGINX))

    routes, indexer_url = image_files(image)
    if indexer_url != config["indexer_url"]:
        raise ValueError("The image was built for another indexer URL")
    record = ROOT / "measurements.json"
    write(record, json.dumps(build_eif(image, ROOT / "prover.eif"), indent=2))
    run(
        "aws",
        "--region",
        config["region"],
        "s3",
        "cp",
        str(record),
        f"s3://{outputs['Bucket']}/{MEASUREMENTS}",
        "--only-show-errors",
    )

    # Systemd sandboxed units read the scripts and config as other users.
    ROOT.chmod(0o755)
    for name in ("aws_host.py", "aws_nitro_host.py", "config.json"):
        (ROOT / name).chmod(0o644)
    write(PROXY_CONFIG, proxy_config(routes))
    written = units(routes)
    for name, text in written.items():
        write(UNITS / name, text)
    run("systemctl", "daemon-reload")
    for name in written:
        run("systemctl", "enable", name)
        run("systemctl", "restart", name, timeout=180)
    healthy(f"http://127.0.0.1:{INGRESS_PORT}/ready", timeout=600)

    gateway_path = ROOT / "nginx.conf"
    write(
        gateway_path,
        aws_host.gateway(False, authorizer=f"http://127.0.0.1:{AUTHORIZER_PORT}/auth"),
    )
    aws_host.start_container(
        config,
        "gateway",
        NGINX,
        options=("-v", f"{gateway_path}:/etc/nginx/nginx.conf:ro"),
    )
    key = secret(outputs["ApiKeySecret"], config["region"])
    healthy(f"http://127.0.0.1:{GATEWAY_PORT}/ready", key=key)
    print("Enclave and gateway ready", flush=True)


def main(argv):
    aws_host.ROOT = ROOT
    action, path = ("install", argv[1]) if len(argv) == 2 else (argv[1], argv[2])
    if action == "measure":
        global SHOW_ERRORS
        SHOW_ERRORS = True
        install_nitro_cli()
        with tempfile.TemporaryDirectory() as directory:
            record = build_eif(path, Path(directory) / "prover.eif")
        print(json.dumps(record, indent=2))
        return
    config = json.loads(Path(path).read_text())
    if action == "authorize":
        serve_authorizer(secret(config["outputs"]["ApiKeySecret"], config["region"]))
    elif action == "supervise":
        supervise(config)
    else:
        os.umask(0o077)
        with (ROOT / "install.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            install(config)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))

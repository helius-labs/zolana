import base64
import contextlib
import errno
import fcntl
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "gpu"))

import aws_host  # noqa: E402
from aws_host import NGINX, healthy, run, secret  # noqa: E402

ROOT = Path("/opt/zolana-nitro")
ENCLAVE = "zolana-prover"
FIRST_CID = 16
# Pinned to the VSOCK-LISTEN port in prover/server/nitro/entrypoint.sh.
ENCLAVE_PORT = 3001
# Enclave i ingress is INGRESS_PORT + 2i, skipping the authorizer port.
INGRESS_PORT = 3003
AUTHORIZER_PORT = 3004
GATEWAY_PORT = 3001
PARENT_CID = 3
KMS_PORT = 8200
KMS_LIMIT = 65536
KMS_TIMEOUT = 10
IMDS = "http://169.254.169.254/latest"
PROXY_CONFIG = Path("/etc/nitro_enclaves/zolana-vsock-proxy.yaml")
# Exceeds the prover's default indexer concurrency plus key downloads.
PROXY_WORKERS = 64
ALLOCATOR = "/usr/bin/nitro-enclaves-allocator"
ALLOCATOR_UNIT = "zolana-allocator.service"
CPU_POOL = Path("/sys/module/nitro_enclaves/parameters/ne_cpus")
UNITS = Path("/etc/systemd/system")
# SSM runs nitro-cli without HOME.
ARTIFACTS = Path("/var/lib/zolana-nitro/artifacts")
LAYOUT = ROOT / "enclaves.json"
SEED = ROOT / "hpke-seed.bin"
MEASUREMENTS = "install/measurements.json"
SEED_OBJECT = "install/hpke-seed.bin"
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

SYSFS = Path("/sys/devices/system")
NODE_MARGIN_MIB = 2048
HUGE_PAGE_MIB = 2


def cpu_list(text):
    cpus = set()
    for part in filter(None, text.strip().split(",")):
        low, _, high = part.partition("-")
        cpus.update(range(int(low), int(high or low) + 1))
    return cpus


# Offline CPUs hide their thread siblings.
def topology(sysfs=SYSFS):
    if (sysfs / "cpu/offline").read_text().strip():
        raise RuntimeError("CPUs are offline, stop every enclave before installing")

    def core(cpu):
        path = sysfs / f"cpu/cpu{cpu}/topology/thread_siblings_list"
        return tuple(sorted(cpu_list(path.read_text())))

    reserved = core(0)
    nodes = []
    for node in sorted(sysfs.glob("node/node[0-9]*"), key=lambda n: int(n.name[4:])):
        cores = {core(cpu) for cpu in cpu_list((node / "cpulist").read_text())}
        total_kib = next(
            int(line.split()[-2])
            for line in (node / "meminfo").read_text().splitlines()
            if "MemTotal:" in line
        )
        nodes.append((sorted(cores - {reserved}), total_kib // 1024))
    return nodes


# Nitro confines an enclave to one NUMA node.
def layout(nodes, config, shared_key):
    enclaves = []
    for cores, node_mib in nodes:
        cpus = []
        for core in cores:
            if len(cpus) + len(core) <= config["enclave_cpus"]:
                cpus.extend(core)
        memory = min(node_mib - NODE_MARGIN_MIB, config["enclave_memory_mib"])
        if len(cpus) >= 2:
            enclaves.append(
                {
                    "cpus": sorted(cpus),
                    "memory_mib": memory - memory % HUGE_PAGE_MIB,
                }
            )
    if not enclaves:
        raise RuntimeError("No NUMA node has room for an enclave")
    if shared_key:
        return enclaves
    return [max(enclaves, key=lambda e: (len(e["cpus"]), e["memory_mib"]))]


def ingress_port(index):
    return INGRESS_PORT + 2 * index


def allocator(enclave):
    pool = ",".join(map(str, enclave["cpus"]))
    return f"---\nmemory_mib: {enclave['memory_mib']}\ncpu_pool: {pool}\n"


# The stock allocator reserves huge pages on one NUMA node per run.
def allocate(enclaves):
    for enclave in enclaves:
        with tempfile.TemporaryDirectory() as prefix:
            directory = Path(prefix, "etc/nitro_enclaves")
            directory.mkdir(parents=True)
            (directory / "allocator.yaml").write_text(allocator(enclave))
            if subprocess.run(
                [ALLOCATOR],
                cwd=prefix,
                env=dict(os.environ, NITRO_CLI_INSTALL_DIR=prefix),
                timeout=600,
                check=False,
            ).returncode:
                raise RuntimeError("nitro-enclaves-allocator failed")
    CPU_POOL.write_text(
        ",".join(str(cpu) for enclave in enclaves for cpu in enclave["cpus"]) + "\n"
    )


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


def enclave_command(enclave, index):
    return [
        "run-enclave",
        "--eif-path",
        str(ROOT / "prover.eif"),
        "--cpu-ids",
        *map(str, enclave["cpus"]),
        "--memory",
        str(enclave["memory_mib"]),
        "--enclave-cid",
        str(FIRST_CID + index),
        "--enclave-name",
        f"{ENCLAVE}-{index}",
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


RESTART = ("Restart=always", "RestartSec=5")
SANDBOX = ("DynamicUser=yes", "PrivateTmp=yes", "Environment=HOME=/tmp")


def unit(description, command, options=(), requires=(), after=(ALLOCATOR_UNIT,)):
    lines = [
        "[Unit]",
        f"Description={description}",
        " ".join(("After=network-online.target", *after)),
        "Wants=network-online.target",
        *(f"Requires={name}" for name in requires),
        "",
        "[Service]",
        f"ExecStart={command}",
        *options,
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def units(routes, enclaves, shared_key):
    script = f"/usr/bin/python3 {ROOT}/aws_nitro_host.py"
    written_units = {
        f"zolana-egress-{route['vsock']}.service": unit(
            f"Enclave egress to {route['host']}",
            f"/usr/bin/vsock-proxy --ipv4 --num_workers {PROXY_WORKERS} --config {PROXY_CONFIG} {route['vsock']} {route['host']} {route['port']}",
            (*RESTART, *SANDBOX),
        )
        for route in routes
    }
    written_units[ALLOCATOR_UNIT] = unit(
        "Enclave CPUs and memory per NUMA node",
        f"{script} allocate {ROOT}/config.json",
        ("Type=oneshot", "RemainAfterExit=yes"),
        after=(),
    )
    for index in range(len(enclaves)):
        written_units[f"zolana-ingress-{index}.service"] = unit(
            f"Prover ingress into enclave {index}",
            f"/usr/bin/socat TCP-LISTEN:{ingress_port(index)},bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:{FIRST_CID + index}:{ENCLAVE_PORT}",
            (*RESTART, *SANDBOX),
        )
    written_units["zolana-authorizer.service"] = unit(
        "Gateway API key check",
        f"{script} authorize {ROOT}/config.json",
        (*RESTART, *SANDBOX),
    )
    if shared_key:
        written_units["zolana-kms.service"] = unit(
            "Enclave KMS configuration",
            f"{script} kms {ROOT}/config.json",
            (*RESTART, *SANDBOX),
        )
    written_units["zolana-enclave@.service"] = unit(
        "Prover enclave %i",
        f"{script} supervise {ROOT}/config.json %i",
        (
            *RESTART,
            f"Environment=NITRO_CLI_ARTIFACTS={ARTIFACTS}",
            f"ExecStopPost=-/usr/bin/nitro-cli terminate-enclave --enclave-name {ENCLAVE}-%i",
        ),
        requires=(ALLOCATOR_UNIT,),
        after=(ALLOCATOR_UNIT, "zolana-kms.service"),
    )
    return written_units


def services(written_units, enclaves):
    return [
        *(name for name in written_units if not name.endswith("@.service")),
        *(f"zolana-enclave@{index}.service" for index in range(len(enclaves))),
    ]


def retire_units():
    names = {
        path.name
        for pattern in ("zolana-*.service", "*.wants/zolana-*.service")
        for path in UNITS.glob(pattern)
        if not path.name.endswith("@.service")
    }
    if names:
        subprocess.run(
            ["systemctl", "disable", "--now", *sorted(names)],
            capture_output=True,
            check=False,
            timeout=300,
        )
    for path in UNITS.glob("zolana-*.service"):
        path.unlink()
    with contextlib.suppress(RuntimeError):
        nitro("terminate-enclave", "--all", timeout=120)
    if CPU_POOL.exists():
        try:
            CPU_POOL.write_text("\n")
        # The driver frees the pool before refusing the empty list.
        except OSError as error:
            if error.errno != errno.EINVAL:
                raise


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


def read(request, opener):
    with opener(request, timeout=5) as response:
        return response.read().decode()


def role_credentials(opener=urllib.request.urlopen):
    token = read(
        urllib.request.Request(
            IMDS + "/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        ),
        opener,
    )
    headers = {"X-aws-ec2-metadata-token": token}
    credentials = IMDS + "/meta-data/iam/security-credentials/"
    role = read(urllib.request.Request(credentials, headers=headers), opener).split()
    if len(role) != 1:
        raise RuntimeError("The instance has no single role")
    record = json.loads(
        read(urllib.request.Request(credentials + role[0], headers=headers), opener)
    )
    if record.get("Code") != "Success":
        raise RuntimeError("Instance role credentials are unavailable")
    return record


def kms_config(ciphertext, credentials):
    line = (
        json.dumps(
            {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "access_key_id": credentials["AccessKeyId"],
                "secret_access_key": credentials["SecretAccessKey"],
                "session_token": credentials["Token"],
            }
        )
        + "\n"
    ).encode()
    if len(line) > KMS_LIMIT:
        raise ValueError("KMS configuration exceeds its limit")
    return line


def answer_kms(connection, peer, cids, message):
    with connection:
        if peer[0] not in cids:
            return
        connection.settimeout(KMS_TIMEOUT)
        try:
            connection.sendall(message())
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            print(f"KMS configuration failed: {error}", file=sys.stderr, flush=True)


def serve_kms(listener, cids, message):
    while True:
        answer_kms(*listener.accept(), cids, message)


def enclave_state(name):
    try:
        enclaves = json.loads(nitro("describe-enclaves", timeout=60))
    except (RuntimeError, ValueError):
        print("nitro-cli describe-enclaves failed", file=sys.stderr, flush=True)
        return None
    return next(
        (e.get("State") for e in enclaves if e.get("EnclaveName") == name),
        "ABSENT",
    )


def supervise(enclaves, index, poll=10):
    name = f"{ENCLAVE}-{index}"
    with contextlib.suppress(RuntimeError):
        nitro("terminate-enclave", "--enclave-name", name, timeout=120)
    nitro(*enclave_command(enclaves[index], index))
    while (state := enclave_state(name)) in ("RUNNING", None):
        time.sleep(poll)
    raise RuntimeError(f"Enclave {index} is {state}")


def image_files(image):
    container = run("docker", "create", image)
    try:
        with tempfile.TemporaryDirectory() as directory:
            run("docker", "cp", f"{container}:/etc/zolana-nitro/.", directory)
            files = Path(directory)
            source, key = files / "key-source", files / "kms-key"
            kms_key = None
            if source.exists() and source.read_text().strip() == "kms":
                kms_key = key.read_text().strip() if key.exists() else ""
                if not kms_key:
                    raise ValueError("The image enables KMS without naming a key")
            return {
                "routes": parse_routes((files / "routes").read_text()),
                "indexer_url": (files / "indexer-url").read_text().strip(),
                "kms_key": kms_key,
            }
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


def s3_copy(config, source, target):
    run(
        "aws",
        "--region",
        config["region"],
        "s3",
        "cp",
        source,
        target,
        "--only-show-errors",
    )


def install(config):
    outputs = config["outputs"]
    image = config["prover_image"]
    install_nitro_cli("docker", "socat")
    retire_units()
    run("systemctl", "disable", "--now", "nitro-enclaves-allocator.service")
    run("systemctl", "enable", "--now", "docker")

    aws_host.pull(config, (image, NGINX))

    files = image_files(image)
    if files["indexer_url"] != config["indexer_url"]:
        raise ValueError("The image was built for another indexer URL")
    shared_key = files["kms_key"] is not None
    nodes = topology()
    enclaves = layout(nodes, config, shared_key)
    if len(nodes) > 1 and not shared_key:
        print("The image draws a boot key, running one enclave", flush=True)
    if shared_key:
        s3_copy(config, f"s3://{outputs['Bucket']}/{SEED_OBJECT}", str(SEED))
        SEED.chmod(0o644)
    write(LAYOUT, json.dumps(enclaves, indent=2))
    record = ROOT / "measurements.json"
    measured = build_eif(image, ROOT / "prover.eif")
    write(
        record,
        json.dumps(
            dict(measured, enclaves=len(enclaves), kms_key=files["kms_key"]), indent=2
        ),
    )
    s3_copy(config, str(record), f"s3://{outputs['Bucket']}/{MEASUREMENTS}")

    # Systemd sandboxed units read the scripts and config as other users.
    ROOT.chmod(0o755)
    for name in ("aws_host.py", "aws_nitro_host.py", "config.json"):
        (ROOT / name).chmod(0o644)
    write(PROXY_CONFIG, proxy_config(files["routes"]))
    written = units(files["routes"], enclaves, shared_key)
    for name, text in written.items():
        write(UNITS / name, text)
    run("systemctl", "daemon-reload")
    for name in services(written, enclaves):
        run("systemctl", "enable", name)
        run("systemctl", "restart", name, timeout=600)
    for index in range(len(enclaves)):
        healthy(f"http://127.0.0.1:{ingress_port(index)}/ready", timeout=600)

    gateway_path = ROOT / "nginx.conf"
    write(
        gateway_path,
        aws_host.gateway(
            False,
            authorizer=f"http://127.0.0.1:{AUTHORIZER_PORT}/auth",
            upstreams=[
                f"127.0.0.1:{ingress_port(index)}" for index in range(len(enclaves))
            ],
        ),
    )
    aws_host.start_container(
        config,
        "gateway",
        NGINX,
        options=("-v", f"{gateway_path}:/etc/nginx/nginx.conf:ro"),
    )
    key = secret(outputs["ApiKeySecret"], config["region"])
    healthy(f"http://127.0.0.1:{GATEWAY_PORT}/ready", key=key)
    print(f"{len(enclaves)} enclaves and gateway ready", flush=True)


def main(argv):
    aws_host.ROOT = ROOT
    action, path, *rest = ("install", argv[1]) if len(argv) == 2 else argv[1:]
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
    elif action == "allocate":
        allocate(json.loads(LAYOUT.read_text()))
    elif action == "supervise":
        supervise(json.loads(LAYOUT.read_text()), int(rest[0]))
    elif action == "kms":
        ciphertext = SEED.read_bytes()
        cids = {
            FIRST_CID + index for index in range(len(json.loads(LAYOUT.read_text())))
        }
        listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        listener.bind((PARENT_CID, KMS_PORT))
        listener.listen()
        serve_kms(listener, cids, lambda: kms_config(ciphertext, role_credentials()))
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

import fcntl
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/opt/zolana-gpu")
POSTGRES = "public.ecr.aws/docker/library/postgres:16-bookworm"
NGINX = "public.ecr.aws/docker/library/nginx:1.28-alpine"


def run(*args, data=None, timeout=300):
    try:
        result = subprocess.run(
            args,
            input=data,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"{args[0]} {args[1]} timed out, inspect the host service logs"
        ) from None
    if result.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed, inspect the host service logs")
    return result.stdout.strip()


def secret(arn, region):
    return run(
        "aws",
        "--region",
        region,
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        arn,
        "--query",
        "SecretString",
        "--output",
        "text",
    )


def write_private(name, contents):
    path = ROOT / name
    path.write_text(contents)
    path.chmod(0o600)
    return str(path)


def environment(name, values):
    if any("\n" in str(value) or "\r" in str(value) for value in values.values()):
        raise ValueError("Environment values must fit on one line")
    return write_private(
        name, "".join(f"{key}={value}\n" for key, value in values.items())
    )


def healthy(url, timeout=300, key=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                url, headers={"X-API-Key": key} if key else {}
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(3)
    raise RuntimeError(f"Readiness timed out for {url}")


def gateway(with_indexer):
    indexer = (
        """
        location = /indexer { proxy_pass http://127.0.0.1:8784/; }
        location /indexer/ { proxy_pass http://127.0.0.1:8784/; }
    """
        if with_indexer
        else "location /indexer { return 404; }"
    )
    return (
        """
events {}
http {
    access_log /dev/stdout;
    error_log /dev/stderr warn;
    server {
        listen 3001;
        client_max_body_size 16m;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_read_timeout 60s;
        proxy_hide_header Access-Control-Allow-Origin;
        proxy_hide_header Access-Control-Allow-Headers;
        proxy_hide_header Access-Control-Allow-Methods;
        proxy_hide_header Access-Control-Expose-Headers;
        auth_request /_authorize;
        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Headers "Content-Type,Authorization,X-API-Key,X-Prover-Timing,X-Request-ID,X-Sync,X-Async" always;
        add_header Access-Control-Allow-Methods "GET,POST,OPTIONS" always;
        add_header Access-Control-Expose-Headers "Server-Timing,X-Prover-Timing,X-Request-ID" always;
        if ($request_method = OPTIONS) { return 204; }
        location = /_authorize {
            internal;
            auth_request off;
            proxy_pass http://127.0.0.1:3003/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
        location / { proxy_pass http://127.0.0.1:3003; }
    """
        + indexer
        + "\n    }\n}\n"
    )


def install(config):
    outputs = config["outputs"]
    gpu = run(
        "nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"
    ).splitlines()
    if not gpu or any(value.strip() != "8.9" for value in gpu):
        raise RuntimeError("The published image requires an L4 or L40S GPU")
    run("nvidia-ctk", "runtime", "configure", "--runtime=docker")
    run("systemctl", "restart", "docker")
    registry = config["prover_image"].split("/")[0]
    password = run(
        "aws", "--region", config["image_region"], "ecr", "get-login-password"
    )
    run(
        "docker",
        "login",
        "--username",
        "AWS",
        "--password-stdin",
        registry,
        data=password,
    )
    images = [config["prover_image"], NGINX]
    if config["with_indexer"]:
        images += [config["photon_image"], POSTGRES]
    for image in images:
        print(f"Pulling {image}", flush=True)
        run("docker", "pull", image, timeout=600)
    run("docker", "logout", registry)

    def container(name, image, options=(), command=(), restart="unless-stopped"):
        result = subprocess.run(
            ["docker", "inspect", name], capture_output=True, check=False, timeout=30
        )
        if result.returncode == 0:
            run("docker", "rm", "-f", name)
        run(
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--restart",
            restart,
            "--network",
            "host",
            "--log-driver",
            "awslogs",
            "--log-opt",
            f"awslogs-region={config['region']}",
            "--log-opt",
            f"awslogs-group={outputs['LogGroup']}",
            "--log-opt",
            f"awslogs-stream={name}",
            *options,
            image,
            *command,
        )

    if config["with_indexer"]:
        db_password = secret(outputs["DatabaseSecret"], config["region"])
        pg_env = environment(
            "postgres.env",
            {
                "POSTGRES_DB": "photon",
                "POSTGRES_USER": "photon",
                "POSTGRES_PASSWORD": db_password,
            },
        )
        container(
            "postgres",
            POSTGRES,
            ("--env-file", pg_env, "-v", f"{ROOT}/postgres:/var/lib/postgresql/data"),
            ("-c", "listen_addresses=127.0.0.1"),
        )
        for _ in range(60):
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "postgres",
                    "pg_isready",
                    "-U",
                    "photon",
                    "-d",
                    "photon",
                ],
                capture_output=True,
                check=False,
                timeout=30,
            )
            if result.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError("PostgreSQL startup timed out")
        marker = ROOT / "restored"
        if not marker.exists():
            # 2. A crash can leave a committed restore without its marker.
            count = run(
                "docker",
                "exec",
                "postgres",
                "psql",
                "-U",
                "photon",
                "-d",
                "photon",
                "-Atc",
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'",
            )
            if count != "0":
                raise RuntimeError(
                    "Target database is not empty and has no restore marker"
                )
            dump = str(ROOT / "cache.dump")
            run(
                "aws",
                "--region",
                config["region"],
                "s3",
                "cp",
                f"s3://{outputs['Bucket']}/cache/photon.dump",
                dump,
                "--only-show-errors",
                timeout=600,
            )
            run("docker", "cp", dump, "postgres:/tmp/cache.dump")
            run(
                "docker",
                "exec",
                "postgres",
                "timeout",
                "--kill-after=10s",
                "900",
                "pg_restore",
                "-U",
                "photon",
                "-d",
                "photon",
                "--single-transaction",
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                "/tmp/cache.dump",
                timeout=930,
            )
            marker.touch(mode=0o600)
            Path(dump).unlink()
            run("docker", "exec", "postgres", "rm", "/tmp/cache.dump")
        database_url = f"postgres://photon:{db_password}@127.0.0.1:5432/photon"
        migration_env = environment("migration.env", {"DATABASE_URL": database_url})
        container(
            "migration",
            config["photon_image"],
            ("--env-file", migration_env),
            ("timeout", "--kill-after=10s", "900", "photon-migration", "up"),
            restart="no",
        )
        try:
            if run("docker", "wait", "migration", timeout=930) != "0":
                raise RuntimeError(
                    "Local database migration failed, inspect the migration log stream"
                )
        finally:
            run("docker", "rm", "-f", "migration")
        rpc = secret(config["rpc_secret"], config["source_region"])
        container(
            "photon",
            config["photon_image"],
            ("-e", "TOKIO_WORKER_THREADS=2"),
            (
                "photon",
                "--port",
                "8784",
                "--db-url",
                database_url,
                "--rpc-url",
                rpc,
                "--max-db-conn",
                "20",
                "--max-concurrent-block-fetches",
                "10",
                "--logging-format",
                "json",
            ),
        )
        healthy("http://127.0.0.1:8784/readiness")

    api_key = secret(outputs["ApiKeySecret"], config["region"])
    prover_env = {
        "PROVER_API_KEY": api_key,
        "PROVER_REQUEST_TIMING": "true",
        "GOMAXPROCS": str(config["prover_cpus"]),
        "PROVER_TRANSFER_CONCURRENCY": "2",
        "PROVER_INDEXER_URL": config["indexer_url"],
    }
    if config.get("indexer_key_secret"):
        prover_env["PROVER_INDEXER_API_KEY"] = secret(
            config["indexer_key_secret"], config["source_region"]
        )
    key_dir = ROOT / "keys"
    key_dir.mkdir(exist_ok=True)
    os.chown(key_dir, 65532, 65532)
    container(
        "prover",
        config["prover_image"],
        (
            "--gpus",
            "all",
            "--env-file",
            environment("prover.env", prover_env),
            "-v",
            f"{key_dir}:/proving-keys",
        ),
        (
            "start",
            "--require-optimized-build",
            "--server-only",
            "--auto-download",
            "--keys-dir",
            "/proving-keys",
            "--preload-keys",
            "none",
            "--prover-address",
            "127.0.0.1:3003",
            "--metrics-address",
            "127.0.0.1:9997",
        ),
    )
    healthy("http://127.0.0.1:3003/ready")
    gateway_path = ROOT / "nginx.conf"
    gateway_path.write_text(gateway(config["with_indexer"]))
    gateway_path.chmod(0o644)
    container("gateway", NGINX, ("-v", f"{gateway_path}:/etc/nginx/nginx.conf:ro"))
    healthy("http://127.0.0.1:3001/ready", key=api_key)
    if config["with_indexer"]:
        healthy("http://127.0.0.1:3001/indexer/readiness", key=api_key)
    (ROOT / "ready").touch(mode=0o600)
    print("Prover and gateway ready", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT / "install.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            install(json.loads(Path(sys.argv[1]).read_text()))
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            sys.exit(str(error))

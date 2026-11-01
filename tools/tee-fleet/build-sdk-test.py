"""Build local proof-test executables and fetch only the pinned 2x2 proving key."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

root = Path(__file__).resolve().parents[2]
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True)
subprocess.run(
    ["go", "build", "-o", str(output / "prover"), "."],
    cwd=root / "prover/server",
    check=True,
)
result = subprocess.run(
    [
        "cargo",
        "test",
        "-p",
        "spr-client",
        "--lib",
        "--features",
        "tee-tuf",
        "--no-run",
        "--locked",
        "--message-format=json",
    ],
    cwd=root,
    check=True,
    stdout=subprocess.PIPE,
    text=True,
)
executables = [
    message["executable"]
    for line in result.stdout.splitlines()
    if (message := json.loads(line)).get("reason") == "compiler-artifact"
    and message["target"]["name"] == "spr_client"
    and message.get("executable")
]
if len(executables) != 1:
    raise SystemExit("expected one Rust SDK test executable")
shutil.copy2(executables[0], output / "rust-sdk-test")
manifest = json.loads(
    (root / "prover/server/prover/provingkeys/proving-keys.lock").read_text()
)
name = "transfer_confidential_2_2.key"
entry = manifest["keys"][name]
keys = output / "keys"
keys.mkdir()
# Same public asset base as prover/server/prover/common/key_downloader.go.
url = f"https://d3gbdb0egjwcw9.cloudfront.net/{manifest['prefix']}/{name}"
with urlopen(url, timeout=120) as response, (keys / name).open("xb") as destination:
    digest, size = hashlib.sha256(), 0
    while chunk := response.read(1 << 20):
        size += len(chunk)
        if size > entry["size"]:
            raise SystemExit("proving key exceeds pinned size")
        digest.update(chunk)
        destination.write(chunk)
    if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
        raise SystemExit("proving key does not match pinned manifest")
print(f"built SDK proof-test tools at {output}")

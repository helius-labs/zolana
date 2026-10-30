"""Regenerate public test fixtures: tuf==7.0.1, securesystemslib[crypto]==1.6.0.

Deterministic, publicly known test keys ONLY. Never use this root in production.
The checked-in JSON contains signed public artifacts, never private keys.
"""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

HERE = Path(__file__).parent
POLICY = json.loads((HERE / "tee_fleet_policy.json").read_text())["policy"]
EXPIRY = datetime.fromtimestamp(2_000_010_000, UTC)


def keys(offset):
    seeds = iter(range(offset, offset + 8))
    return {
        role: [
            CryptoSigner(
                Ed25519PrivateKey.from_private_bytes(bytes([next(seeds)]) * 32)
            )
            for _ in range(3 if role in {"root", "targets"} else 1)
        ]
        for role in ["root", "targets", "snapshot", "timestamp"]
    }


OLD = keys(1)
NEW = keys(9)


def signed(value, signers):
    metadata = Metadata(value)
    for signer in signers:
        metadata.sign(signer, append=True)
    return metadata.to_bytes().decode()


def root(version, role_keys):
    value = Root(version=version, expires=EXPIRY)
    for role, signers in role_keys.items():
        for signer in signers:
            value.add_key(signer.public_key, role)
        value.roles[role].threshold = 2 if role in {"root", "targets"} else 1
    return value


BOOTSTRAP = signed(root(1, OLD), OLD["root"][:2])


def repository(
    version=1,
    revision=1,
    rotated=False,
    timestamp_expires=EXPIRY,
    substitute=False,
    hash_algorithm="sha256",
):
    role_keys = NEW if rotated else OLD
    policy = copy.deepcopy(POLICY)
    policy["revision"] = revision
    if substitute:
        policy["expires_at"] -= 1
    payload = json.dumps(policy, separators=(",", ":")).encode()
    target = TargetFile.from_data("fixture/fleet.json", payload, [hash_algorithm])
    targets = signed(
        Targets(version=version, expires=EXPIRY, targets={target.path: target}),
        role_keys["targets"][:2],
    )
    snapshot = signed(
        Snapshot(
            version=version,
            expires=EXPIRY,
            meta={
                "targets.json": MetaFile.from_data(
                    version, targets.encode(), ["sha256"]
                )
            },
        ),
        role_keys["snapshot"],
    )
    timestamp = signed(
        Timestamp(
            version=version,
            expires=timestamp_expires,
            snapshot_meta=MetaFile.from_data(version, snapshot.encode(), ["sha256"]),
        ),
        role_keys["timestamp"],
    )
    files = {
        "metadata/timestamp.json": timestamp,
        f"metadata/{version}.targets.json": targets,
        f"metadata/{version}.snapshot.json": snapshot,
        f"targets/fixture/{target.hashes[hash_algorithm]}.fleet.json": payload.decode(),
    }
    if rotated:
        files["metadata/2.root.json"] = signed(
            root(2, NEW), OLD["root"][:2] + NEW["root"][:2]
        )
    return files


def main():
    cases = {
        "v1": repository(),
        "v2": repository(2, 2),
        "rotated": repository(2, 2, rotated=True),
        "rollback": repository(3, 1),
        "substitution": repository(3, 1, substitute=True),
        "expired": repository(
            timestamp_expires=datetime.fromtimestamp(1_500_000_000, UTC)
        ),
        "fractional": repository(
            timestamp_expires=datetime.fromtimestamp(1_999_999_999.5, UTC)
        ),
        "weak_hash": repository(hash_algorithm="md5"),
    }
    for label, signers in [
        ("rotation_old_only", OLD["root"][:2]),
        ("rotation_new_only", NEW["root"][:2]),
    ]:
        cases[label] = repository(2, 2, rotated=True)
        cases[label]["metadata/2.root.json"] = signed(root(2, NEW), signers)
    mismatch = repository()
    target_path = next(path for path in mismatch if path.startswith("targets/"))
    mismatch[target_path] += " "
    cases["hash_mismatch"] = mismatch
    signature = repository()
    timestamp = json.loads(signature["metadata/timestamp.json"])
    timestamp["signatures"][0]["sig"] = "00" * 64
    signature["metadata/timestamp.json"] = json.dumps(timestamp, separators=(",", ":"))
    cases["bad_signature"] = signature
    vector = {
        "description": "Publicly known deterministic test keys only. Generated with python-tuf 7.0.1; shared Node/Rust verification and rollback vectors.",
        "bootstrap_root": BOOTSTRAP,
        "network": "fixture",
        "fractional_valid_until": 1_999_999_999,
        "repositories": cases,
    }
    (HERE / "tee_tuf_repository.json").write_text(json.dumps(vector, indent=2) + "\n")


if __name__ == "__main__":
    main()

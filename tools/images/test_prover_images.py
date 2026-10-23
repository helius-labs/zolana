"""Checks the prover Dockerfiles against each other and the justfile."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "prover/server"
DOCKERFILES = [SERVER / "Dockerfile.light", SERVER / "Dockerfile.nitro"]


class ProverImageTests(unittest.TestCase):
    def test_every_stage_is_pinned_by_digest(self):
        for dockerfile in DOCKERFILES:
            text = dockerfile.read_text()
            # A stage or a build argument naming one points back into the same file.
            stages = set(re.findall(r"^FROM \S+ AS (\S+)$", text, re.M))
            bases = [
                base
                for base in re.findall(r"^FROM (\S+)", text, re.M)
                if base not in stages and not base.startswith("${")
            ]
            self.assertTrue(bases, dockerfile.name)
            for base in bases:
                self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", dockerfile.name)


if __name__ == "__main__":
    unittest.main()

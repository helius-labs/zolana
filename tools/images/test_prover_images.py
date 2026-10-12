"""Checks the prover Dockerfiles against each other and the justfile."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "prover/server"
DOCKERFILES = [SERVER / "Dockerfile.light", SERVER / "Dockerfile.nitro"]


def release_keys_stage(dockerfile: Path) -> str:
    text = dockerfile.read_text()
    match = re.search(r"^FROM \S+ AS release-keys\n.*?(?=^FROM )", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"{dockerfile.name} has no release-keys stage")
    return match.group(0)


class ProverImageTests(unittest.TestCase):
    def test_every_stage_is_pinned_by_digest(self):
        for dockerfile in DOCKERFILES:
            bases = re.findall(r"^FROM (\S+)", dockerfile.read_text(), re.M)
            self.assertTrue(bases, dockerfile.name)
            for base in bases:
                self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", dockerfile.name)

    def test_one_release_carries_the_custom_ring_keys(self):
        urls = {
            dockerfile.name: re.search(r"^ARG RELEASE_KEYS_URL=(\S+)$", dockerfile.read_text(), re.M).group(1)
            for dockerfile in DOCKERFILES
        }
        urls["justfile"] = re.search(
            r'release_url="\$\{ZOLANA_RING_KEYS_URL:-(\S+)\}"', (ROOT / "justfile").read_text()
        ).group(1)
        self.assertEqual(len(set(urls.values())), 1, urls)

    def test_the_release_keys_stages_differ_only_in_the_lockfile_path(self):
        light, nitro = (release_keys_stage(dockerfile) for dockerfile in DOCKERFILES)
        self.assertEqual(
            light.replace("COPY prover/provingkeys/", "COPY prover/server/prover/provingkeys/"), nitro
        )


if __name__ == "__main__":
    unittest.main()

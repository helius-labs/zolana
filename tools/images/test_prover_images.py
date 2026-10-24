"""Checks the prover Dockerfiles against each other and the build settings."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "prover/server"
DOCKERFILES = [SERVER / "Dockerfile.light", SERVER / "Dockerfile.nitro"]


def stage(dockerfile: Path, name: str) -> str:
    text = dockerfile.read_text()
    match = re.search(rf"^FROM \S+ AS {name}\n.*?(?=^FROM )", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"{dockerfile.name} has no {name} stage")
    return match.group(0)


class ProverImageTests(unittest.TestCase):
    def test_every_stage_is_pinned_by_digest(self):
        for dockerfile in DOCKERFILES:
            text = dockerfile.read_text()
            # A stage or a build argument naming one points back into the same file.
            stages = set(re.findall(r"^FROM \S+ AS (\S+)$", text, re.M))
            bases = [
                base
                for base in re.findall(r"^FROM (\S+)", text, re.M)
                if base not in stages and "${" not in base
            ]
            self.assertTrue(bases, dockerfile.name)
            for base in bases:
                self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", dockerfile.name)

    def test_the_extension_pin_selects_the_extension_stages(self):
        for dockerfile in DOCKERFILES:
            text = dockerfile.read_text()
            self.assertRegex(text, r"(?m)^ARG PROVER_EXTENSION_REF=$", dockerfile.name)
            for selected in ("source", "release-keys"):
                self.assertIn(f"FROM {selected}${{PROVER_EXTENSION_REF:+-extension}} AS ", text, dockerfile.name)

    def test_the_extension_key_stages_are_identical(self):
        for name in ("release-key-list", "release-keys-extension"):
            light, nitro = (stage(dockerfile, name) for dockerfile in DOCKERFILES)
            self.assertEqual(light, nitro, name)
        self.assertIn("light-prover release-keys", stage(DOCKERFILES[0], "release-key-list"))

    def test_a_zolana_checkout_builds_the_plain_prover(self):
        self.assertIsNone(extension_context(self.settings(ROOT, (SERVER / "release-build.env").read_text())))

    def test_an_extension_checkout_builds_itself(self):
        with tempfile.TemporaryDirectory() as cwd:
            root = Path(cwd)
            (root / "prover").mkdir()
            (root / "prover/go.mod").write_text("module example.test/extension\n")
            git = ["git", "-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
            subprocess.run(git[:3] + ["init", "-q"], check=True)
            subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "t"], check=True)
            head = subprocess.run(git[:3] + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            settings = self.settings(root, (SERVER / "release-build.env").read_text())
            self.assertIn(f"extension_ref={head}\n", settings)
            self.assertEqual(extension_context(settings), "prover-extension=.")

    def settings(self, cwd: Path, env: str) -> str:
        with tempfile.TemporaryDirectory() as scripts:
            shutil.copy(SERVER / "release-settings.sh", scripts)
            Path(scripts, "release-build.env").write_text(env)
            return subprocess.run(
                ["sh", str(Path(scripts, "release-settings.sh"))], cwd=cwd, check=True, capture_output=True, text=True
            ).stdout


def extension_context(settings: str) -> str | None:
    match = re.search(r"(?m)^extension_context=(.*)$", settings)
    return match and match.group(1)


if __name__ == "__main__":
    unittest.main()

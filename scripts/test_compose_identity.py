"""Check Compose interpolation only; no Docker engine, image build, or service start."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
IDENTITY = {
    "FLAGON_SERVICE_DID": "did:web:directory.example",
    "FLAGON_SERVICE_METHOD_HISTORY_HEAD": "sha256:" + "a" * 64,
    "FLAGON_SERVICE_VERSION_ID": "synthetic-jcs-sha256:" + "a" * 64,
}


class ComposeIdentityTests(unittest.TestCase):
    def render(self, identity):
        docker = shutil.which("docker")
        self.assertIsNotNone(docker, "Docker CLI with Compose is required for this parser test")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("FLAGON_")}
        environment.update(identity)
        with tempfile.TemporaryDirectory(prefix="flagon-compose-identity-") as directory:
            env_file = Path(directory) / "empty.env"
            env_file.write_text("", encoding="utf-8")
            return subprocess.run(
                [docker, "compose", "--project-directory", str(REPOSITORY),
                 "--env-file", str(env_file), "-f", str(REPOSITORY / "docker-compose.yml"),
                 "config", "--format", "json"],
                env=environment, text=True, encoding="utf-8", capture_output=True,
                timeout=30, check=False,
            )

    def test_operator_tuple_reaches_container_environment_exactly(self):
        # These values test interpolation, not identity verification or startup.
        result = self.render(IDENTITY)
        self.assertEqual(result.returncode, 0, result.stderr)
        container = json.loads(result.stdout)["services"]["flagon-server"]["environment"]
        self.assertEqual({key: container[key] for key in IDENTITY}, IDENTITY)
        self.assertNotIn("FLAGON_SERVICE_ID", container)

    def test_each_missing_or_empty_identity_component_fails_before_startup(self):
        for key in IDENTITY:
            for missing in (True, False):
                with self.subTest(key=key, missing=missing):
                    identity = dict(IDENTITY)
                    if missing:
                        del identity[key]
                    else:
                        identity[key] = ""
                    result = self.render(identity)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(key, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

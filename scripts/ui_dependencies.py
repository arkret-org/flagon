"""Resolve UI assets and provenance from the locked Cargo package graph."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

EXPECTED = {
    "glory": "https://github.com/glory-rs/glory.git",
    "sapid": "https://github.com/sapid-ui/sapid.git",
}


def cargo_environment(root, environment=None):
    env = dict(os.environ if environment is None else environment)
    cache = None
    if os.name == "nt":
        cache = Path("D:/BuildCache") / (root.name + "-glory")
    elif env.get("WSL_DISTRO_NAME"):
        mounts = Path("/proc/mounts").read_text().splitlines()
        if not any(line.split()[1] == "/mnt/d" and line.split()[0].upper().startswith("D:") for line in mounts):
            raise RuntimeError("Verify /mnt/d is mounted from D: before resolving Cargo dependencies")
        cache = Path("/mnt/d/BuildCache") / (root.name + "-glory")
    if cache:
        temporary = cache / "tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        env.setdefault("CARGO_TARGET_DIR", str(cache / "target"))
        env.setdefault("CARGO_HOME", str(cache.parent / "cargo"))
        env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temporary)
        for key in ("CARGO_TARGET_DIR", "CARGO_HOME"):
            path = Path(env[key]).resolve()
            if os.name == "nt" and path.drive.lower() != "d:":
                raise RuntimeError(f"{key} must be on D:")
            if env.get("WSL_DISTRO_NAME") and not path.is_relative_to("/mnt/d"):
                raise RuntimeError(f"{key} must stay on the verified /mnt/d mount")
    return env


def cargo_metadata(root, environment=None):
    env = cargo_environment(root, environment)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        cwd=root, env=env, text=True))
    target = Path(metadata["target_directory"]).resolve()
    if os.name == "nt" and target.drive.lower() != "d:":
        raise RuntimeError(f"Cargo target directory must be on D: {target}")
    if env.get("WSL_DISTRO_NAME") and not target.is_relative_to("/mnt/d"):
        raise RuntimeError(f"Cargo target directory must stay on the verified /mnt/d mount: {target}")
    return metadata


def ui_packages(metadata):
    result = {}
    for name, expected in EXPECTED.items():
        packages = [package for package in metadata["packages"] if package["name"] == name]
        if len(packages) != 1:
            raise RuntimeError(f"Expected one resolved {name} package, found {len(packages)}")
        package = packages[0]
        source = package.get("source") or ""
        location, separator, revision = source.partition("#")
        if location != "git+" + expected + "?branch=main" or not separator or len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
            raise RuntimeError(f"{name} must resolve to the locked GitHub main dependency: {source!r}")
        manifest = Path(package["manifest_path"]).resolve()
        if not manifest.is_file():
            raise FileNotFoundError(manifest)
        result[name] = {"source": source, "revision": revision,
                        "manifest_path": str(manifest), "version": package["version"]}
    return result


def sapid_stylesheet(metadata):
    package = ui_packages(metadata)["sapid"]
    stylesheet = Path(package["manifest_path"]).parent / "styles" / "sapid.css"
    if not stylesheet.is_file():
        raise FileNotFoundError(stylesheet)
    return stylesheet


def ui_provenance(metadata):
    result = ui_packages(metadata)
    result["sapid"]["stylesheet_sha256"] = hashlib.sha256(sapid_stylesheet(metadata).read_bytes()).hexdigest()
    return result


def verify_web_provenance(directory, metadata):
    recorded = json.loads((directory / "ui-build-info.json").read_text(encoding="utf-8"))
    expected = ui_provenance(metadata)
    for name in EXPECTED:
        for field in ("source", "revision", "version"):
            if recorded.get(name, {}).get(field) != expected[name][field]:
                raise RuntimeError(f"Web artifact {name} {field} does not match the locked Cargo graph")
    if recorded.get("sapid", {}).get("stylesheet_sha256") != expected["sapid"]["stylesheet_sha256"]:
        raise RuntimeError("Web artifact Sapid stylesheet does not match the locked dependency")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    metadata = cargo_metadata(root)
    print(json.dumps({"target_directory": metadata["target_directory"],
                      "ui_dependencies": ui_provenance(metadata)}, indent=2))

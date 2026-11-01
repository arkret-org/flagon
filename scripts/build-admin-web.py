#!/usr/bin/env python3
"""Build the Glory/Sapid audit console into Cargo's reported target directory."""
import argparse
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
from ui_dependencies import cargo_metadata, sapid_stylesheet, ui_provenance

ROOT = Path(__file__).resolve().parents[1]

def locked_bindgen_version(root=ROOT):
    packages = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8")).get("package", [])
    packages = [package for package in packages if package.get("name") == "wasm-bindgen"]
    if len(packages) != 1:
        raise SystemExit("Cargo.lock must contain exactly one wasm-bindgen package")
    version = packages[0].get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
    ):
        raise SystemExit("Cargo.lock wasm-bindgen version is invalid")
    return version


def find_bindgen(env, version):
    selected = env.get("WASM_BINDGEN")
    candidates = [selected] if selected else []
    if not selected:
        if env.get("CARGO_HOME"):
            executable = "wasm-bindgen.exe" if os.name == "nt" else "wasm-bindgen"
            candidates.append(str(Path(env["CARGO_HOME"]) / "bin" / executable))
        candidates.append(shutil.which("wasm-bindgen", path=env.get("PATH")) or "wasm-bindgen")
    for candidate in candidates:
        try:
            actual = subprocess.check_output(
                [candidate, "--version"], cwd=ROOT, env=env, text=True
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if actual == f"wasm-bindgen {version}":
            return candidate
    raise SystemExit(f"Install wasm-bindgen-cli {version} on D: or set WASM_BINDGEN to a matching CLI")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--print-bindgen-version',action='store_true')
    parser.add_argument('--release',action='store_true')
    parser.add_argument('--out-dir',type=Path)
    args=parser.parse_args()
    version=locked_bindgen_version()
    if args.print_bindgen_version:
        print(version)
        return
    env=os.environ.copy()
    if os.name=='nt':
        cache=Path('D:/BuildCache/flagon-glory')
        temporary=cache/'tmp'
        temporary.mkdir(parents=True,exist_ok=True)
        env.setdefault('CARGO_HOME','D:/BuildCache/cargo')
        env.setdefault('CARGO_TARGET_DIR',str(cache/'target'))
        env['TEMP']=env['TMP']=str(temporary)
        tempfile.tempdir=str(temporary)
        if Path(env['CARGO_HOME']).resolve().drive.lower()!='d:':
            raise SystemExit('CARGO_HOME must be on D:')
    metadata=cargo_metadata(ROOT, env)
    provenance=ui_provenance(metadata)
    target=Path(metadata['target_directory']).resolve()
    output=(args.out_dir or target/'web').resolve()
    if os.name=='nt' and any(p.drive.lower()!='d:' for p in [target,output]):
        raise SystemExit('Build and browser output must be on D:')
    bindgen=find_bindgen(env, version)
    command=['cargo','build','--locked','-p','admin','--lib','--target','wasm32-unknown-unknown']
    if args.release:command.append('--release')
    subprocess.run(command,cwd=ROOT,env=env,check=True,timeout=3600)
    output.mkdir(parents=True,exist_ok=True)
    profile='release' if args.release else 'debug'
    subprocess.run([bindgen,str(target/'wasm32-unknown-unknown'/profile/'admin.wasm'),'--target','web','--out-name','admin','--out-dir',str(output/'pkg')],cwd=ROOT,env=env,check=True,timeout=3600)
    for source in (ROOT/'crates/admin/web').iterdir():
        if source.is_dir():shutil.copytree(source,output/source.name,dirs_exist_ok=True)
        else:shutil.copy2(source,output/source.name)
    shutil.copy2(ROOT/'crates/admin/assets/main.css',output/'main.css')
    (output/'ui-build-info.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    print(f'Static audit console: {output}')

if __name__=='__main__':main()

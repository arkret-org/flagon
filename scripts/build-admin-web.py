#!/usr/bin/env python3
"""Build the Glory/Sapid audit console into Cargo's reported target directory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
from ui_dependencies import cargo_metadata, sapid_stylesheet, ui_provenance

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',action='store_true')
    parser.add_argument('--out-dir',type=Path)
    args=parser.parse_args()
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
    version=next(p['version'] for p in tomllib.loads((ROOT/'Cargo.lock').read_text(encoding='utf-8'))['package'] if p['name']=='wasm-bindgen')
    bindgen=env.get('WASM_BINDGEN') or shutil.which('wasm-bindgen')
    if not bindgen:
        raise SystemExit(f'Install wasm-bindgen-cli {version} or set WASM_BINDGEN')
    actual=subprocess.check_output([bindgen,'--version'],cwd=ROOT,env=env,text=True).strip()
    if actual!=f'wasm-bindgen {version}':
        raise SystemExit(f'Expected wasm-bindgen {version}, got {actual}')
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

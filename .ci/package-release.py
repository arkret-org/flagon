#!/usr/bin/env python3
"""Stage Cargo and static browser outputs and create a checksummed release archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ui_dependencies import cargo_metadata, ui_provenance, verify_web_provenance


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def copy(source, destination):
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)
    elif source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    else:
        raise FileNotFoundError(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--binary', action='append', default=[])
    parser.add_argument('--resource', action='append', default=[])
    parser.add_argument('--web', action='store_true')
    parser.add_argument('--crates', action='store_true')
    args = parser.parse_args()
    root = Path.cwd()
    if os.name == 'nt':
        temporary = Path('D:/BuildCache/flagon-glory/tmp')
        temporary.mkdir(parents=True, exist_ok=True)
        tempfile.tempdir = str(temporary)
    project = root.name
    tag = os.environ.get('GITHUB_REF_NAME', 'verification')
    tag = re.sub(r'[^A-Za-z0-9._-]', '-', tag)
    name = f'{project}-{tag}-{args.target}'
    metadata = cargo_metadata(root)
    ui_sources = ui_provenance(metadata)
    target = Path(metadata['target_directory']).resolve()
    if os.name == 'nt' and (target.drive.lower() != 'd:' or root.resolve().drive.lower() != 'd:'):
        raise SystemExit('Release outputs must be on D:')
    output = root / 'release-assets'
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='release-') as temporary:
        stage = Path(temporary) / name
        stage.mkdir()
        suffix = '.exe' if 'windows' in args.target else ''
        for binary in args.binary:
            source, _, destination = binary.partition('=')
            destination = destination or source
            copy(target / args.target / 'release' / (source + suffix),
                 stage / (destination + suffix))
        if args.web:
            source = target / 'web'
            if not (source / 'index.html').is_file() or not list(source.rglob('*.wasm')):
                raise RuntimeError('The browser bundle must contain index.html and WASM')
            verify_web_provenance(source, metadata)
            copy(source, stage)
        if args.crates:
            packages = [package for package in metadata['packages']
                        if package['id'] in metadata['workspace_members']
                        and package['publish'] != []]
            if not packages:
                raise RuntimeError('Cargo produced no source packages')
            for package in packages:
                crate = target / 'package' / f"{package['name']}-{package['version']}.crate"
                copy(crate, stage / crate.name)
        if not (args.binary or args.web or args.crates):
            parser.error('At least one build output is required')
        for resource in args.resource:
            source, _, destination = resource.partition('=')
            copy(root / source, stage / (destination or source))
        for pattern in ['README*', 'LICENSE*', 'NOTICE*', 'RELEASING.md']:
            for path in root.glob(pattern):
                if path.is_file():
                    copy(path, stage / path.name)
        repositories = {}
        local_roots = {root, *(Path(package['manifest_path']).parent for package in metadata['packages'] if package.get('source') is None)}
        for directory in sorted(local_roots):
            resolved = subprocess.run(['git', '-C', str(directory), 'rev-parse', '--show-toplevel'],
                                      capture_output=True, text=True)
            if resolved.returncode == 0:
                repository = Path(resolved.stdout.strip())
                repositories[repository.name] = run('git', '-C', str(repository), 'rev-parse', 'HEAD')
        provenance = {'repository': project, 'ref': os.environ.get('GITHUB_REF'),
                      'target': args.target, 'commits': repositories, 'ui_dependencies': ui_sources,
                      'lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()}
        (stage / 'build-info.json').write_text(json.dumps(provenance, indent=2) + '\n')
        if 'windows' in args.target:
            archive = output / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(stage.rglob('*')):
                    if path.is_file():
                        bundle.write(path, path.relative_to(stage.parent))
        else:
            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as bundle:
                bundle.add(stage, arcname=name)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name + '.sha256').write_bytes(f'{digest}  {archive.name}\n'.encode('ascii'))
        print(archive)


if __name__ == '__main__':
    main()

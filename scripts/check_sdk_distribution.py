#!/usr/bin/env python3
"""ADR 0049: exercise an SDK alone and its distributable, with owned temporary trees."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, env=None):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def boundary(root):
    for path in root.rglob('*'):
        if not path.is_file() or any(p in {'.git', '.venv', 'target', '__pycache__'} for p in path.parts):
            continue
        if path.suffix not in {'.py', '.rs', '.go', '.md', '.sh', '.toml'}:
            continue
        text = path.read_text()
        references = re.findall(r'(?<![\w/])(?:\.\./)+[\w./-]+', text)
        for reference in references:
            target = (path.parent / reference).resolve()
            if not target.is_relative_to(root.resolve()):
                raise RuntimeError(f'{path.relative_to(root)}: parent-path read or link leaves SDK: {reference}')
        for link in re.findall(r'\]\(([^)]+)\)', text) if path.suffix == '.md' else []:
            if ':' in link or link.startswith('#'):
                continue
            target = (path.parent / link.split('#')[0]).resolve()
            if not target.is_relative_to(root.resolve()):
                raise RuntimeError(f'{path.relative_to(root)}: documentation link leaves SDK: {link}')


def python_suite(root):
    run(['uv', 'sync', '--locked'], root)
    run(['uv', 'run', 'pytest', '-q'], root)
    for name in ['run', 'run_v2', 'run_v3', 'run_strict', 'run_producer_canonicality', 'run_selector_float_zero']:
        run(['uv', 'run', 'python', f'tests/conformance/{name}.py'], root)
    for tool in ['purity_check', 'license_check']:
        run(['uv', 'run', 'python', f'tools/{tool}.py'], root)


def python_package(root, temp):
    artifacts = temp / 'python-artifacts'
    run(['uv', 'build', '--sdist', '--wheel', '--out-dir', str(artifacts)], root)
    wheel, = artifacts.glob('*.whl')
    with zipfile.ZipFile(wheel) as archive:
        assert all(
            name.split('/', 1)[0] == 'bounded_authority_verifier'
            or name.split('/', 1)[0].endswith('.dist-info')
            for name in archive.namelist()
        ), 'wheel includes files outside the runtime package and distribution metadata'
    sdist, = artifacts.glob('*.tar.gz')
    unpack = temp / 'sdist'
    with tarfile.open(sdist) as archive:
        archive.extractall(unpack, filter='data')
    extracted, = unpack.iterdir()
    assert (extracted / 'tests').is_dir() and (extracted / 'conformance/priv/conformance/verdict-digests.json').is_file()
    python_suite(extracted)


def rust_suite(root, env):
    run(['cargo', 'test', '--locked'], root, env)
    run(['sh', 'tools/purity_check.sh'], root, env)


def rust_package(root, temp, env):
    run(['cargo', 'package', '--allow-dirty', '--locked'], root, env)
    artifact, = (Path(env['CARGO_TARGET_DIR']) / 'package').glob('*.crate')
    unpack = temp / 'crate'
    with tarfile.open(artifact) as archive:
        archive.extractall(unpack, filter='data')
    extracted, = unpack.iterdir()
    assert (extracted / 'conformance/priv/conformance/verdict-digests.json').is_file()
    rust_suite(extracted, env)


def go_zip(root, temp, env):
    cache = Path(subprocess.check_output(['go', 'env', 'GOMODCACHE'], cwd=root, env=env, text=True).strip())
    candidates = sorted((cache / 'golang.org/x').glob('mod@*/zip/zip.go'))
    if not candidates:
        raise RuntimeError('golang.org/x/mod zip tooling is absent from the box module cache')
    cached = candidates[-1].parent.parent
    work = temp / 'zip-tool'
    work.mkdir()
    (work / 'go.mod').write_text('module corpuszip\n\ngo 1.25\n\nrequire golang.org/x/mod ' + cached.name.split('@')[1] + '\n\nreplace golang.org/x/mod => ' + str(cached) + '\n')
    (work / 'main.go').write_text('package main\nimport("os";"golang.org/x/mod/module";"golang.org/x/mod/zip")\nfunc main(){f,e:=os.Create(os.Args[2]);if e!=nil{panic(e)};defer f.Close();if e=zip.CreateFromDir(f,module.Version{Path:"github.com/baselabs/bounded_authority_protocol_go",Version:"v0.0.0"},os.Args[1]);e!=nil{panic(e)}}\n')
    artifact = temp / 'module.zip'
    run(['go', 'run', '.', str(root), str(artifact)], work, {**env, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOWORK': 'off'})
    with zipfile.ZipFile(artifact) as archive:
        names = {name.split('@v0.0.0/', 1)[1] for name in archive.namelist()}
        unpack = temp / 'module'
        archive.extractall(unpack)
    expected = {p.relative_to(root).as_posix() for p in (root / 'conformance').rglob('*') if p.is_file()}
    assert expected <= names, f'module zip omits conformance files: {sorted(expected - names)}'
    print('Go module zip carries the complete conformance tree', flush=True)
    module_root = unpack / 'github.com/baselabs/bounded_authority_protocol_go@v0.0.0'
    run(['go', 'test', './...'], module_root, env)
    run(['sh', 'tools/purity_check.sh'], module_root, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk', choices=['python', 'rust', 'go'])
    parser.add_argument('--boundary-only', action='store_true')
    args = parser.parse_args()
    source = ROOT / 'sdks' / args.sdk
    boundary(source)
    if args.boundary_only:
        return
    with tempfile.TemporaryDirectory(prefix='bap-sdk-distribution-') as directory:
        temp = Path(directory)
        root = temp / args.sdk
        shutil.copytree(source, root, ignore=shutil.ignore_patterns('.venv', 'target', '__pycache__', '.pytest_cache', '.ruff_cache', '.mypy_cache', 'dist'))
        boundary(root)
        env = {**os.environ, 'CARGO_TARGET_DIR': str(temp / 'target')}
        if args.sdk == 'python':
            python_suite(root)
            python_package(root, temp)
        elif args.sdk == 'rust':
            rust_suite(root, env)
            rust_package(root, temp, env)
        else:
            run(['go', 'test', './...'], root, env)
            run(['sh', 'tools/purity_check.sh'], root, env)
            go_zip(root, temp, env)
    print(f'{args.sdk}: isolated suite and package: PASS')


if __name__ == '__main__':
    main()

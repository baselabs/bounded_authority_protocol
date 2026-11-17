#!/usr/bin/env python3
"""Prove the native Rust and Go corpus gates fail closed in isolated SDK trees."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def invoke(argv, root, env, red=None):
    result = subprocess.run(argv, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if red is None:
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode != 0 and red in result.stdout, result.stdout
        print(f'RED {root.name}: {red}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk', choices=['rust', 'go'])
    sdk = parser.parse_args().sdk
    with tempfile.TemporaryDirectory(prefix='bap-native-corpus-mutations-') as directory:
        temp = Path(directory)
        root = temp / sdk
        shutil.copytree(ROOT / 'sdks' / sdk, root, ignore=shutil.ignore_patterns('target', '.venv', '__pycache__'))
        env = {**os.environ, 'CARGO_TARGET_DIR': str(temp / 'target')}
        argv = ['cargo', 'test', '--locked', '--test', 'conformance'] if sdk == 'rust' else ['go', 'test', './conformance', '-run', '^TestConformance$', '-count=1']
        invoke(argv, root, env)
        corpus = root / 'conformance/priv/conformance/v1/corpus'
        case_path = corpus / 'cases/uri/normalize.json'
        raw_path = next(corpus.rglob('*.raw'))
        for name, path, mode, message in [
            ('case byte', case_path, 'byte', 'file SHA mismatch'),
            ('raw byte', raw_path, 'byte', 'file SHA mismatch'),
            ('extra file', corpus / 'extra.json', 'extra', 'corpus file set mismatch'),
            ('missing file', case_path, 'remove', 'indexed file missing' if sdk == 'rust' else 'no such file'),
        ]:
            original = path.read_bytes() if path.exists() else None
            if mode == 'remove':
                path.unlink()
            else:
                path.write_bytes(original + b' ' if mode == 'byte' else b'{}')
            invoke(argv, root, env, message)
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)
            invoke(argv, root, env)
            print(f'GREEN {sdk}: restored {name}', flush=True)
        runner = root / 'conformance' / ('run.rs' if sdk == 'rust' else 'run_test.go')
        original = runner.read_text()
        if sdk == 'rust':
            loop = 'for case in &all_cases {'
            assert original.count(loop) == 1
            skipped = original.replace(loop, 'for case in all_cases.iter().skip(1) {')
            duplicate = original.replace(loop, 'for (position, source_case) in all_cases.iter().enumerate() { let case = if position == 1 { &all_cases[0] } else { source_case };')
            always = original.replace('let agree = dispatch(case, &root, &mut census);', 'let _ = dispatch(case, &root, &mut census); let agree = true;')
            always = always.replace('census.actual.take().expect("missing computed outcome")', '{ let _ = census.actual.take(); json!({"verdict":"invalid"}) }')
        else:
            loop = 'for _, c := range lf.cf.Cases {'
            assert original.count(loop) == 1
            skipped = original.replace(loop, 'for position, c := range lf.cf.Cases { if position == 1 { continue };')
            duplicate = original.replace(loop, 'for position, c := range lf.cf.Cases { if position == 1 { c = lf.cf.Cases[0] };')
            always = original.replace('func checkVerdict(t *testing.T, c corpusCase, err error) {', 'func checkVerdict(t *testing.T, c corpusCase, err error) { c.Actual["verdict"]="invalid"; return;')
        for name, contents, message in [
            ('skipped case', skipped, 'execution completeness: skipped cases'),
            ('duplicate replacing skipped ID', duplicate, 'duplicate executed ID'),
            ('always-pass comparator', always, 'computed verdict digest mismatch'),
        ]:
            assert contents != original, f'{name}: mutation anchor absent'
            runner.write_text(contents)
            invoke(argv, root, env, message)
            runner.write_text(original)
            invoke(argv, root, env)
            print(f'GREEN {sdk}: restored {name}', flush=True)
    print(f'{sdk}: native corpus mutations: PASS', flush=True)


if __name__ == '__main__':
    main()

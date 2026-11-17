#!/usr/bin/env python3
"""Prove SDK corpus gates and value-bearing facts fail closed in isolated trees."""
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
    return result.stdout


def fact_mutations(sdk, root, env):
    """Change an SDK fact, without changing the case, verdict, or runner."""
    if sdk == 'python':
        source = ROOT / 'sdks/python'
        invoke(['uv', 'sync', '--locked'], source, env)
        python = str(source / '.venv/bin/python')
        env = {**env, 'PYTHONPATH': str(root / 'src'), 'PYTHONDONTWRITEBYTECODE': '1'}
        path = root / 'src/bounded_authority_verifier/facts.py'
        original = path.read_text()
        mutated = original.replace('return self._row_count', 'return self._row_count + 1', 1)
        runners = [[python, f'tests/conformance/{name}.py'] for name in ['run', 'run_v2', 'run_v3']]
        message = 'check_chain: row_count fact'
    elif sdk == 'go':
        path = root / 'accessors.go'
        original = path.read_text()
        mutated = original.replace('return facts.data().RowCount', 'return facts.data().RowCount + 1', 1)
        runners = [['go', 'test', './conformance', '-run', f'^{name}$', '-count=1'] for name in ['TestConformance', 'TestEcdsaConformance']]
        message = 'check_chain fact mismatch'
    else:
        for major in [1, 2, 3]:
            path = root / f'src/v{major}.rs'
            original = path.read_text()
            anchor = 'row_count: parsed.len() as i64,'
            assert original.count(anchor) == 1
            argv = ['cargo', 'test', '--locked', '--test', 'conformance' + (f'_v{major}' if major > 1 else '')]
            invoke(argv, root, env)
            try:
                path.write_text(original.replace(anchor, 'row_count: parsed.len() as i64 + 1,'))
                invoke(argv, root, env, 'row_count fact')
            finally:
                path.write_text(original)
            invoke(argv, root, env)
            print(f'GREEN rust: restored v{major} row_count fact', flush=True)
        return
    assert mutated != original, f'{sdk}: fact mutation anchor absent'
    for argv in runners:
        invoke(argv, root, env)
        try:
            path.write_text(mutated)
            invoke(argv, root, env, message)
        finally:
            path.write_text(original)
        invoke(argv, root, env)
        print(f'GREEN {sdk}: restored row_count fact ({argv})', flush=True)


def go_subtest_mutations(root, env):
    for name, anchor, call, test in [
        ('run_test.go', 'execution.Record(t, c.ID, lf.path, c.Actual)', 'execution.Record(t, c.ID, lf.path, c.Actual)', 'TestConformance'),
        ('strict_test.go', 'execution.Record(t, ref.head.ID, ref.file, ref.Actual)', 'execution.Record(t, ref.head.ID, ref.file, ref.Actual)', 'TestStrictEd25519Corpus'),
    ]:
        path = root / 'conformance' / name
        original = path.read_text()
        assert original.count(anchor) == 1
        argv = ['go', 'test', './conformance', '-run', f'^{test}$', '-count=1']
        try:
            path.write_text(original.replace(anchor, anchor + '; ' + call))
            output = invoke(argv, root, env, 'duplicate executed ID')
            assert f'--- FAIL: {test}/' in output, output
            assert 'subtest may have called FailNow on a parent test' not in output, output
            print(f'RED go: {test} duplicate fails on the active subtest', flush=True)
        finally:
            path.write_text(original)
        invoke(argv, root, env)
        print(f'GREEN go: restored {test} duplicate control', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk', choices=['rust', 'go', 'python'])
    sdk = parser.parse_args().sdk
    with tempfile.TemporaryDirectory(prefix='bap-native-corpus-mutations-') as directory:
        temp = Path(directory)
        root = temp / sdk
        shutil.copytree(ROOT / 'sdks' / sdk, root, ignore=shutil.ignore_patterns('target', '.venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'))
        env = {**os.environ, 'CARGO_TARGET_DIR': str(temp / 'target')}
        fact_mutations(sdk, root, env)
        if sdk == 'python':
            print('python: fact mutations: PASS', flush=True)
            return
        if sdk == 'go':
            go_subtest_mutations(root, env)
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

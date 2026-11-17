#!/usr/bin/env python3
"""Prove SDK execution, source boundaries, generator inputs, and publish guards red (D11)."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def command(argv, cwd, expected=None, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if expected is None:
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode != 0 and expected in result.stdout, result.stdout
        print(f'RED: {expected}', flush=True)
    return result


def main():
    with tempfile.TemporaryDirectory(prefix='bap-distribution-mutations-') as directory:
        temp = Path(directory)
        sdk = temp / 'python'
        shutil.copytree(ROOT / 'sdks/python', sdk, ignore=shutil.ignore_patterns('.venv', '__pycache__', '.pytest_cache', '.ruff_cache', '.mypy_cache'))
        python = str(ROOT / 'sdks/python/.venv/bin/python')
        if not Path(python).exists():
            command(['uv', 'sync', '--locked'], ROOT / 'sdks/python')
        env = {**os.environ, 'PYTHONPATH': str(sdk / 'src'), 'PYTHONDONTWRITEBYTECODE': '1'}
        runner = sdk / 'tests/conformance/run.py'
        original = runner.read_text()
        command([python, str(runner)], sdk, env=env)
        # The expectation comparator always returns true while a computed valid result
        # is changed to a closed invalid result. Only the computed digest can reject it.
        anchor = '        if compare_verdict(c["expected"], actual):'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, '        if True:').replace('        execution.record(c["id"], computed(c["expected"], actual, INVALID), c["_file"])', '        execution.record(c["id"], {"verdict":"invalid"} if c["expected"]["verdict"] == "valid" else computed(c["expected"], actual, INVALID), c["_file"])'))
        command([python, str(runner)], sdk, 'computed verdict digest mismatch', env)
        runner.write_text(original)
        command([python, str(runner)], sdk, env=env)
        print('GREEN: restored comparator and computed results', flush=True)
        anchor = '        execution.record(c["id"], computed(c["expected"], actual, INVALID), c["_file"])'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, anchor + '\n' + anchor))
        command([python, str(runner)], sdk, 'duplicate executed ID', env)
        runner.write_text(original)
        # Replace a skipped ID with a previously executed ID rather than merely reducing
        # a pass count. Exact ID accounting must reject the apparent replacement.
        anchor = '    for c in cases:\n        inp = c["input"]'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, '    for c in cases:\n        if c is cases[1]:\n            execution.record(cases[0]["id"], {"verdict":"invalid"}, cases[1]["_file"])\n            continue\n        inp = c["input"]'))
        command([python, str(runner)], sdk, 'duplicate executed ID', env)
        runner.write_text(original)
        command([python, str(runner)], sdk, env=env)
        print('GREEN: restored exact ID accounting', flush=True)
        runner.write_text(original.replace(anchor, '    for c in cases:\n        if c is cases[1]:\n            continue\n        inp = c["input"]'))
        command([python, str(runner)], sdk, 'execution completeness: skipped cases', env)
        runner.write_text(original)
        command([python, str(runner)], sdk, env=env)
        print('GREEN: restored complete execution', flush=True)
        spec = importlib.util.spec_from_file_location('distribution', ROOT / 'scripts/check_sdk_distribution.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.boundary(sdk)
        injected = sdk / 'src/parent_read.py'
        injected.write_text('open("../../priv/conformance/v1/corpus/index.json")\n')
        try:
            module.boundary(sdk)
        except RuntimeError as error:
            assert 'parent-path read or link leaves SDK' in str(error)
            print(f'RED: {error}', flush=True)
        else:
            raise AssertionError('parent-path source read survived')
        injected.unlink()
        module.boundary(sdk)
        print('GREEN: restored source boundary', flush=True)
        tree = temp / 'generator'
        shutil.copytree(ROOT / 'conformance/generators', tree / 'conformance/generators')
        shutil.copytree(ROOT / 'priv/conformance/v1/corpus', tree / 'priv/conformance/v1/corpus')
        shutil.copy2(ROOT / '.tool-versions', tree / '.tool-versions')
        generator = ['node', 'conformance/generators/build_corpus.mjs', '--verify', '--major', '1']
        command(generator, tree)
        curated = tree / 'conformance/generators/curated-inputs.json'
        original_curated = curated.read_text()
        # Alter a declared census member while leaving the certified index untouched.
        import json
        values = json.loads(original_curated)
        def change(value):
            if isinstance(value, dict):
                for key, member in value.items():
                    if key == 'public_key_fingerprints':
                        member[0] = 'A' * 43
                        return True
                    if change(member): return True
            return False
        assert change(values), 'curated census anchor missing'
        curated.write_text(json.dumps(values))
        command(generator, tree, 'index.json does not equal the rebuild')
        curated.write_text(original_curated)
        command(generator, tree)
        print('GREEN: restored curated inputs', flush=True)
        # The signed-content generator has a frozen-input verify mode: no private keys
        # are needed to prove its own per-file integrity gate red and green.
        (tree / 'scripts').mkdir()
        shutil.copy2(ROOT / 'scripts/build_content_assertion_corpus.py', tree / 'scripts/build_content_assertion_corpus.py')
        content = tree / 'priv/conformance/attestation-profiles/content-assertion/v1'
        shutil.copytree(ROOT / 'priv/conformance/attestation-profiles/content-assertion/v1', content)
        verify_content = [sys.executable, 'scripts/build_content_assertion_corpus.py', '--verify']
        command(verify_content, tree)
        case_file = content / 'digest-cases.json'
        case_bytes = case_file.read_bytes()
        case_file.write_bytes(case_bytes + b' ')
        command(verify_content, tree, 'digest-cases.json: file SHA mismatch')
        case_file.write_bytes(case_bytes)
        command(verify_content, tree)
        print('GREEN: restored signed-content generator inputs', flush=True)
        publish = subprocess.run(['sh', str(ROOT / 'scripts/check_sdk_publish_infra.sh'), '.github/actions/release/action.yml'], input='run: cargo publish\n', text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert publish.returncode == 1 and 'registry-publish command' in publish.stdout
        print('RED: ' + publish.stdout.strip(), flush=True)
        clean = subprocess.run(['sh', str(ROOT / 'scripts/check_sdk_publish_infra.sh'), '.github/actions/release/action.yml'], input='run: cargo test\n', text=True)
        assert clean.returncode == 0
        print('GREEN: composite action restored', flush=True)
    print('corpus distribution execution mutations: PASS', flush=True)


if __name__ == '__main__':
    main()

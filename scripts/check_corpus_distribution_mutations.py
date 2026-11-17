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
        env = {**os.environ, 'UV_PROJECT_ENVIRONMENT': str(temp / 'venv'), 'PYTHONPATH': str(sdk / 'src'), 'PYTHONDONTWRITEBYTECODE': '1'}
        command(['uv', 'sync', '--locked'], sdk, env=env)
        python = str(temp / 'venv/bin/python')
        runner = sdk / 'tests/conformance/run.py'
        original = runner.read_text()
        command([python, '-O', str(runner)], sdk, env=env)
        # The expectation comparator always returns true while a computed valid result
        # is changed to a closed invalid result. Only the computed digest can reject it.
        anchor = '        if compare_verdict(c["expected"], actual):'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, '        if True:').replace('        execution.record(c["id"], computed(c["expected"], actual, INVALID), c["_file"])', '        execution.record(c["id"], {"verdict":"invalid"} if c["expected"]["verdict"] == "valid" else computed(c["expected"], actual, INVALID), c["_file"])'))
        command([python, '-O', str(runner)], sdk, 'computed verdict digest mismatch', env)
        runner.write_text(original)
        command([python, '-O', str(runner)], sdk, env=env)
        print('GREEN: restored comparator and computed results', flush=True)
        anchor = '        execution.record(c["id"], computed(c["expected"], actual, INVALID), c["_file"])'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, anchor + '\n' + anchor))
        command([python, '-O', str(runner)], sdk, 'duplicate executed ID', env)
        runner.write_text(original)
        # Replace a skipped ID with a previously executed ID rather than merely reducing
        # a pass count. Exact ID accounting must reject the apparent replacement.
        anchor = '    for c in cases:\n        inp = c["input"]'
        assert original.count(anchor) == 1
        runner.write_text(original.replace(anchor, '    for c in cases:\n        if c is cases[1]:\n            execution.record(cases[0]["id"], {"verdict":"invalid"}, cases[1]["_file"])\n            continue\n        inp = c["input"]'))
        command([python, '-O', str(runner)], sdk, 'duplicate executed ID', env)
        runner.write_text(original)
        command([python, '-O', str(runner)], sdk, env=env)
        print('GREEN: restored exact ID accounting', flush=True)
        runner.write_text(original.replace(anchor, '    for c in cases:\n        if c is cases[1]:\n            continue\n        inp = c["input"]'))
        command([python, '-O', str(runner)], sdk, 'execution completeness: skipped cases', env)
        runner.write_text(original)
        command([python, '-O', str(runner)], sdk, env=env)
        print('GREEN: restored complete execution', flush=True)
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location('distribution', ROOT / 'scripts/check_sdk_distribution.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.boundary(sdk)
        # Source strings, chained joins, API traversal, and packaging must all
        # fail before execution; nested source paths cannot change the base.
        for name, relative, source in [
            ('relative literal', 'src/parent_read.py', 'open("../../priv/conformance/v1/corpus/index.json")'),
            ('formatted literal', 'tests/parent_read.rs', 'format!("{}/../../priv/conformance/index.json", root);'),
            ('Rust chained joins', 'examples/parent_read.rs', 'root.join("..").join("..");'),
            ('Go join arguments', 'tests/parent_read.go', 'filepath.Join("..", "..", "priv")'),
            ('Python parents index', 'src/parent_read.py', 'Path(__file__).parents[9] / "priv"'),
            ('Python parent chain', 'examples/parent_read.py', 'Path(__file__).parent.parent.parent.parent / "priv"'),
            ('Rust parent chain', 'src/parent_read.rs', 'Path::parent(root).unwrap().parent().unwrap();'),
            ('Rust method parents', 'tests/parent_read.rs', 'root.parent().unwrap().parent().unwrap();'),
            ('Go parent API', 'src/parent_read.go', 'filepath.Dir(filepath.Dir(root))'),
            ('packaging literal', 'boundary.toml', 'include = ["../priv/conformance"]'),
            ('unquoted packaging path', 'MANIFEST.in', 'include ../../priv/conformance/index.json'),
            ('Windows literal', 'src/parent_read.py', r'open("..\\..\\priv\\index.json")'),
            ('escaped component', 'tests/parent_read.go', r'filepath.Join("\x2e\x2e", "priv")'),
            ('raw literal', 'src/parent_read.rs', 'r#"../../priv/index.json"#;'),
            ('multiline parent chain', 'src/parent_read.py', '(Path(__file__)\n .parent\n .parent\n .parent\n .parent)'),
            ('root-relative ambiguity', 'src/deep/nested/parent_read.py', 'open("../../priv/index.json")'),
            ('Python imported pardir', 'src/parent_read.py', 'from os import pardir as up'),
            ('Rust imported parent component', 'src/parent_read.rs', 'use std::path::Component::{ParentDir};'),
            ('Go split API reference', 'src/parent_read.go', 'split := filepath.Split'),
            ('Python pardir constant', 'src/parent_read.py', 'os.path.join(os.pardir, "priv")'),
            ('Python built dots', 'src/parent_read.py', 'open("." + "." + "/priv")'),
            ('Python path splitting', 'src/parent_read.py', 'os.path.split(root)[0]'),
            ('Python parent getattr', 'src/parent_read.py', 'getattr(p, "parent")'),
            ('Python parents getattr', 'src/parent_read.py', 'getattr(p, "parents")[2]'),
            ('Rust pop', 'src/parent_read.rs', 'PathBuf::pop(&mut root);'),
            ('Rust parent component', 'src/parent_read.rs', 'Component::ParentDir;'),
            ('Rust built dots', 'src/parent_read.rs', 'root.join(concat!(".", "."));'),
            ('Go path splitting', 'src/parent_read.go', 'filepath.Split(root)'),
            ('Go built dots', 'src/parent_read.go', 'filepath.Join("." + ".", "priv")'),
        ]:
            injected = sdk / relative
            injected.parent.mkdir(parents=True, exist_ok=True)
            injected.write_text(source + '\n')
            try:
                module.boundary(sdk)
            except RuntimeError as error:
                assert 'parent-path read or link leaves SDK' in str(error)
                print(f'RED {name}: {error}', flush=True)
            else:
                raise AssertionError(f'{name}: parent-path source read survived')
            finally:
                injected.unlink()
            module.boundary(sdk)
            print(f'GREEN: restored {name}', flush=True)
        # Dependency locations are parsed as manifests, not searched as tokens.
        for name, relative, source, append in [
            ('Go module replace', 'go.mod', 'module example.com/sdk\n\ngo 1.25\n\nreplace example.com/x => ../y\n', False),
            ('Go grouped replace', 'go.mod', 'module example.com/sdk\n\ngo 1.25\n\nreplace (\nexample.com/x => ../y\n)\n', False),
            ('Go workspace use', 'go.work', 'go 1.25\nuse ../y\n', False),
            ('Go workspace grouped use', 'go.work', 'go 1.25\nuse (\n../y\n)\n', False),
            ('Go workspace replace', 'go.work', 'go 1.25\nreplace example.com/x => ../y\n', False),
            ('Cargo dependency path', 'Cargo.toml', '[dependencies]\nx = { path = "../y" }\n', False),
            ('Cargo workspace path', 'Cargo.toml', '[workspace.dependencies]\nx = { path = "../y" }\n', False),
            ('Cargo local registry source', 'Cargo.lock', 'version = 4\n[[package]]\nname = "x"\nversion = "0.1.0"\nsource = "registry+file:../y"\n', False),
            ('Cargo local git source', 'Cargo.lock', 'version = 4\n[[package]]\nname = "x"\nversion = "0.1.0"\nsource = "git+file:../y"\n', False),
            ('Cargo lock source', 'Cargo.lock', 'version = 4\n[[package]]\nname = "x"\nversion = "0.1.0"\nsource = "path+file:../y"\n', False),
            ('Python uv source path', 'pyproject.toml', '\n[tool.uv.sources]\nx = { path = "../y" }\n', True),
            ('Python uv workspace member', 'pyproject.toml', '\n[tool.uv.workspace]\nmembers = ["../y"]\n', True),
            ('Python uv editable source', 'pyproject.toml', '\n[tool.uv.sources]\nx = { path = "../y", editable = true }\n', True),
            ('Python direct file dependency', 'pyproject.toml', '\n[project.optional-dependencies]\nprobe = ["x @ file:../y"]\n', True),
            ('Python lock path', 'uv.lock', '\n[[package]]\nname = "probe"\nversion = "0.1.0"\nsource = { path = "../y" }\n', True),
            ('Python lock editable', 'uv.lock', '\n[[package]]\nname = "probe"\nversion = "0.1.0"\nsource = { editable = "../y" }\n', True),
            ('Python lock directory', 'uv.lock', '\n[[package]]\nname = "probe"\nversion = "0.1.0"\nsource = { directory = "../y" }\n', True),
            ('requirements local', 'requirements.txt', '../y\n', False),
            ('requirements editable', 'requirements-dev.txt', '-e ../y\n', False),
            ('requirements direct file', 'requirements-test.txt', 'x @ file:../y\n', False),
            ('requirements include', 'requirements-extra.txt', '-r ../requirements.txt\n', False),
            ('requirements constraints', 'requirements-ci.txt', '--constraint=../constraints.txt\n', False),
            ('requirements quoted path', 'requirements-quoted.txt', '"../path with spaces"\n', False),
            ('requirements find-links file', 'requirements-links.txt', '--no-index --find-links file:../wheels\n', False),
            ('requirements attached editable', 'requirements-editable.txt', '--editable=../y\n', False),
        ]:
            path = sdk / relative
            original = path.read_bytes() if path.exists() else None
            path.write_text((original.decode() if append and original else '') + source)
            try:
                module.boundary(sdk)
            except RuntimeError as error:
                assert 'dependency path leaves SDK' in str(error), str(error)
                print(f'RED {name}: {error}', flush=True)
            else:
                raise AssertionError(f'{name}: escaping dependency survived')
            finally:
                if original is None: path.unlink()
                else: path.write_bytes(original)
            module.boundary(sdk)
            print(f'GREEN: restored {name}', flush=True)
        # Included files use the requirements grammar even without a conventional name.
        included = sdk / 'nested-dependencies.txt'
        include = sdk / 'requirements-include.txt'
        included.write_text('-e ../outside\n')
        include.write_text('-r file:nested-dependencies.txt\n')
        try:
            module.boundary(sdk)
        except RuntimeError as error:
            assert 'dependency path leaves SDK' in str(error), str(error)
            print('RED: requirements local file URL include', flush=True)
        else:
            raise AssertionError('requirements local file URL include survived')
        finally:
            include.unlink()
            included.unlink()
        module.boundary(sdk)
        print('GREEN: restored requirements local file URL include', flush=True)
        # Safe local dependency targets remain valid after format-aware parsing.
        local = sdk / 'requirements-local.txt'
        local.write_text('-e .\n')
        module.boundary(sdk)
        local.unlink()
        exception = sdk / 'tests/test_quickstart.py'
        original = exception.read_text()
        for name, contents, message in [
            ('duplicated exception', original + '\nOTHER = Path(__file__).resolve().parents[1]\n', 'unproven traversal'),
            ('missing exception', original.replace('Path(__file__).resolve().parents[1]', 'Path("local")'), 'exception occurrence missing'),
        ]:
            exception.write_text(contents)
            try:
                module.boundary(sdk)
            except RuntimeError as error:
                assert message in str(error), str(error)
                print(f'RED {name}: {error}', flush=True)
            else:
                raise AssertionError(f'{name}: exception count drift survived')
            finally:
                exception.write_text(original)
            module.boundary(sdk)
            print(f'GREEN: restored {name}', flush=True)
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

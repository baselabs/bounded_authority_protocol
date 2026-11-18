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


def replace_once(source, anchor, replacement):
    assert source.count(anchor) == 1, f'mutation anchor count: {anchor!r}'
    return source.replace(anchor, replacement, 1)


def change_member(source, start, anchor, replacement):
    offset = source.index(start)
    end = source.find("\nclass ", offset + 1) if start.startswith('class ') else source.find("\nfunc ", offset + 1)
    end = len(source) if end == -1 else end
    return source[:offset] + replace_once(source[offset:end], anchor, replacement) + source[end:]


def mutation(root, env, changes, runners, message, label):
    originals = {path: path.read_text() for path in changes}
    try:
        for path, contents in changes.items(): path.write_text(contents)
        for argv in runners: invoke(argv, root, env, message)
    finally:
        for path, contents in originals.items(): path.write_text(contents)
    for argv in runners: invoke(argv, root, env)
    print(f'GREEN {root.name}: restored {label}', flush=True)


def fact_mutations(sdk, root, env):
    """Corrupt each fact class in the SDK, keeping case inputs and verdicts intact."""
    if sdk == 'python':
        invoke(['uv', 'sync', '--locked'], root, env)
        python = str(Path(env['UV_PROJECT_ENVIRONMENT']) / 'bin/python')
        runners = [[python, '-O', f'tests/conformance/{name}.py'] for name in ['run', 'run_v2', 'run_v3']]
        path = root / 'src/bounded_authority_verifier/facts.py'
        original = path.read_text()
        for cls, member, value, message in [
            ('ChainFacts', 'row_count', 'self._row_count + 1', 'check_chain: row_count fact'),
            ('AnchorFacts', 'anchor_id', 'self._anchor_id + "mutated"', 'anchor: anchor_id fact'),
            ('KeyTransitionFacts', 'transition_id', 'self._transition_id + "mutated"', 'transition: transition_id fact'),
            ('AnchoredExportFacts', 'chain_id', 'self._chain_id + "mutated"', 'export: chain_id fact'),
            ('GrantFacts', 'version', 'self._version + 1', 'verify_grant: version fact'),
            ('GrantFacts', 'authorization', '"mutated"', 'authorization'),
        ]:
            contents = change_member(original, f'class {cls}(', f'return self._{member}', 'return ' + value)
            mutation(root, env, {path: contents}, runners, message, cls + '.' + member + ' under python -O')
        return
    if sdk == 'go':
        path = root / 'accessors.go'
        original = path.read_text()
        runners = [['go', 'test', './conformance', '-run', f'^{name}$', '-count=1'] for name in ['TestConformance', 'TestEcdsaConformance']]
        for cls, member, value, message in [
            ('ChainFacts', 'RowCount', 'facts.data().RowCount + 1', 'check_chain fact mismatch'),
            ('AnchorFacts', 'AnchorID', 'facts.data().AnchorID + "mutated"', 'verify_historical_anchor fact mismatch'),
            ('KeyTransitionFacts', 'TransitionID', 'facts.data().TransitionID + "mutated"', 'verify_key_transition fact mismatch'),
            ('AnchoredExportFacts', 'ChainID', 'facts.data().ChainID + "mutated"', 'verify_anchored_export fact mismatch'),
            ('GrantFacts', 'Version', 'facts.data().Version + 1', 'verify_grant fact mismatch'),
            ('GrantFacts', 'Authorization', 'Authorization(99)', 'verify_grant fact mismatch'),
        ]:
            contents = change_member(original, f'func (facts {cls}) {member}()', f'return facts.data().{member}', 'return ' + value)
            mutation(root, env, {path: contents}, runners, message, cls + '.' + member)
        return
    for major in [1, 2, 3]:
        path = root / f'src/v{major}.rs'
        original = path.read_text()
        argv = ['cargo', 'test', '--locked', '--test', 'conformance' + (f'_v{major}' if major > 1 else '')]
        invoke(argv, root, env)
        anchor = 'row_count: parsed.len() as i64,'
        mutation(root, env, {path: replace_once(original, anchor, 'row_count: parsed.len() as i64 + 1,')}, [argv], 'row_count fact', f'v{major} row_count fact')
    path = root / 'src/v1.rs'
    original = path.read_text()
    runners = [['cargo', 'test', '--locked', '--test', target] for target in ['conformance', 'conformance_strict']]
    for anchor, replacement, message in [
        ('anchor_id: a.payload.anchor_id,', 'anchor_id: a.payload.anchor_id + "mutated",', 'anchor: anchor_id fact'),
        ('transition_id: t.payload.transition_id,', 'transition_id: t.payload.transition_id + "mutated",', 'transition: transition_id fact'),
        ('chain_id: header.chain_id,', 'chain_id: header.chain_id + "mutated",', 'export: chain_id fact'),
        ('Ok(GrantFacts {\n        version: g.payload.version,', 'Ok(GrantFacts {\n        version: g.payload.version + 1,', 'version fact'),
    ]:
        mutation(root, env, {path: replace_once(original, anchor, replacement)}, runners, message, message)
    # The production marker is a unit type: there is no representable wrong value.
    # Expand it only in this temporary SDK to return a distinguishable corrupt marker.
    facts = root / 'src/facts.rs'
    marker = replace_once(facts.read_text(), 'pub struct NotEvaluated;',
        'pub struct CorruptibleNotEvaluated(pub bool);\n/// Mutation-only alias for the corruptible marker.\npub type NotEvaluated = CorruptibleNotEvaluated;\n/// Mutation-only uncorrupted marker value.\n#[allow(non_upper_case_globals)]\npub const NotEvaluated: NotEvaluated = CorruptibleNotEvaluated(false);')
    start = original.index('Ok(GrantFacts {')
    contents = original[:start] + original[start:].replace('authorization: NotEvaluated,', 'authorization: crate::facts::CorruptibleNotEvaluated(true),', 1)
    mutation(root, env, {facts: marker, path: contents}, runners, 'CorruptibleNotEvaluated(true)', 'authorization marker')


def census_mutations(sdk, root, env):
    """An undeclared key observed at the import boundary must fail every major."""
    for major in [1, 2, 3]:
        if sdk == 'python':
            path = root / 'tests/conformance' / ('run' + (f'_v{major}' if major > 1 else '') + '.py')
            original = path.read_text()
            contents = replace_once(original, '    imported = set(_input_fingerprints)', '    _input_fingerprints.add("undeclared-mutation-key")\n    imported = set(_input_fingerprints)')
            argv = [str(Path(env['UV_PROJECT_ENVIRONMENT']) / 'bin/python'), '-O', str(path)]
            message = 'census: imported != declared'
        elif sdk == 'go':
            path = root / 'conformance' / (f'v{major}_test.go' if major > 1 else 'run_test.go')
            original = path.read_text()
            census = 'es256Census' if major == 3 else 'census'
            contents = replace_once(original, '	execution.Finish()', f'\texecution.Finish()\n\t{census}["undeclared-mutation-key"] = true')
            argv = ['go', 'test', './conformance', '-run', '^TestEcdsaConformance$' if major == 3 else '^TestConformance$', '-count=1']
            message = 'census: undeclared imported key'
        else:
            path = root / 'conformance' / ('run' + (f'_v{major}' if major > 1 else '') + '.rs')
            original = path.read_text()
            anchor = '    assert_census(&census.observed, &declared'
            assert original.count(anchor) == 1
            contents = original.replace(anchor, '    census.observed.insert("undeclared-mutation-key".to_string());\n' + anchor)
            argv = ['cargo', 'test', '--locked', '--test', 'conformance' + (f'_v{major}' if major > 1 else '')]
            message = 'census EXTRA keys'
        mutation(root, env, {path: contents}, [argv], message, f'v{major} exact census')


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
        env = {**os.environ, 'CARGO_TARGET_DIR': str(temp / 'target'), 'UV_PROJECT_ENVIRONMENT': str(temp / 'venv'), 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(root / 'src')}
        fact_mutations(sdk, root, env)
        census_mutations(sdk, root, env)
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

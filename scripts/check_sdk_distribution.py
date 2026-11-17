#!/usr/bin/env python3
"""ADR 0049: exercise an SDK alone and its distributable in owned temporary trees.

Parsed dependency metadata rejects local paths outside the SDK. The source scan is
an early lint, not a complete analysis of executable code. The binding guarantee
is the copied-alone isolated package run, including the unpacked distributable.
"""
from __future__ import annotations

import argparse
import ast
import os
import json
import shlex
import tomllib
from urllib.parse import unquote, urlsplit
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

# Each exception identifies exactly one occurrence of a reviewed source expression.
# Counts are checked too: deleting or duplicating an exception is a gate failure.
BOUNDARY_EXCEPTIONS = {
    ('rust/tests/permissiveness.rs', 'let src = include_str!("../src/v1.rs");', 1):
        'Compile-time include from tests/ resolves to src/v1.rs inside the SDK root.',
    ('go/internal/corpuscheck/corpus.go', 'if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") || declared[name] {', 1):
        'Rejects unsafe indexed names before joining them to the SDK-local corpus root.',
    ('go/local_loopback_http_test.go', '{"HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"},', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/src/bounded_authority_verifier/uri.py', "python:inp == b'.' or inp == b'..'", 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/src/bounded_authority_verifier/uri.py', "python:inp == b'/..'", 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/src/bounded_authority_verifier/uri.py', "python:inp.startswith(b'/../')", 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/src/bounded_authority_verifier/uri.py', "python:inp.startswith(b'../')", 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/inspect.rs', '"../tests/fixtures/decoded-binary-rendering.json"', 1):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('rust/src/lib.rs', '#[doc = include_str!("../README.md")]', 1):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('rust/src/uri.rs', 'else if input == b"." || input == b".." {', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/uri.rs', 'else if input.starts_with(b"/../") {', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/uri.rs', 'if input.starts_with(b"../") {', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/uri.rs', 'uri_normalize("https://example.com/a/../b", &B()).unwrap(),', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/uri.rs', 'uri_normalize("https://example.com/a/b/../../c", &B()).unwrap(),', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('rust/src/uri.rs', '} else if input == b"/.." {', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/tests/conformance/run.py', "python:_HERE.parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run.py', "python:_HERE.parents[2] / 'src'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_producer_canonicality.py', "python:Path(__file__).resolve().parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_producer_canonicality.py', 'python:sys.path.insert(0, str(Path(__file__).resolve().parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_selector_float_zero.py', "python:Path(__file__).resolve().parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_selector_float_zero.py', 'python:sys.path.insert(0, str(Path(__file__).resolve().parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_strict.py', "python:_HERE.parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_strict.py', "python:_HERE.parents[2] / 'src'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_strict.py', 'python:importlib.util.spec_from_file_location(name, _HERE.parent / filename)', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_strict.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v2.py', "python:_HERE.parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v2.py', "python:_HERE.parents[2] / 'src'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v2.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v3.py', "python:_HERE.parents[2] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v3.py', "python:_HERE.parents[2] / 'src'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/run_v3.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/test_conformance.py', 'python:Path(__file__).resolve().parent', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/test_conformance_producer_canonicality.py', "python:Path(__file__).resolve().parent / 'run_producer_canonicality.py'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/test_conformance_selector_float_zero.py', "python:Path(__file__).resolve().parent / 'run_selector_float_zero.py'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/conformance/test_conformance_strict.py', "python:Path(__file__).resolve().parent / 'run_strict.py'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('rust/tests/content_assertion.rs', '#[path = "../conformance/support.rs"]', 1):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('python/tests/corpus_support.py', "python:Path(__file__).resolve().parents[1] / 'conformance/priv/conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/corpus_support.py', "python:require(all((p != 'index.json' and (not Path(p).is_absolute()) and ('..' not in Path(p).parts) for p in paths)), 'unsafe indexed path')", 1):
        'Rejects unsafe indexed names before joining them to the SDK-local corpus root.',
    ('rust/tests/local_loopback_http.rs', '#[path = "../conformance/support.rs"]', 1):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('rust/tests/local_loopback_http.rs', '("HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"),', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "anchored-export", "encode.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "anchored-export", "verify.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "envelope", "check.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v2/corpus", "cases", "envelope", "check.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v2/corpus", "cases", surface, "verify.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('go/tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", corpus, "cases", "grant-decode", "decode.json"))', 1):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('rust/tests/role_attestation.rs', '#[path = "../conformance/support.rs"]', 1):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('python/tests/test_content_assertion.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/attestation-profiles/content-assertion/v1'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_decoded_rendering.py', "python:Path(__file__).parent / 'fixtures'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_host_boundaries.py', "python:Path(bap.__file__).parent / 'json_alg.py'", 1):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('python/tests/test_host_boundaries.py', "python:(Path(__file__).parents[1] / 'README.md').read_text()", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_local_loopback_http.py', "python:(b'HTTP://127.0.0.1:80/a/../invoke', b'http://127.0.0.1/invoke')", 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/tests/test_local_loopback_http.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/application-profiles/local-loopback-http/v1'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_packaging.py', "python:(Path(bounded_authority_verifier.__file__).parent / 'py.typed').is_file()", 1):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('python/tests/test_permissiveness.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv' / 'conformance' / 'v1' / 'corpus' / 'cases' / 'anchored-export' / 'verify.json'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_permissiveness.py', "python:protected_seg + b'..'", 1):
        'Empty JWS segment test data; never used as a filesystem path.',
    ('python/tests/test_quickstart.py', 'python:Path(__file__).resolve().parents[1]', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_review_regressions.py', "python:Path(__file__).resolve().parents[1] / 'conformance'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_review_regressions.py', 'python:Path(bap.__file__).parent', 1):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('python/tests/test_review_regressions.py', "python:ast.parse((Path(bap.__file__).parent / 'bounds.py').read_text())", 1):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('python/tests/test_role_attestation.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/attestation-profiles/role-attestation/v1'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('python/tests/test_strict_ed25519.py', 'python:Path(sdk_jwk.__file__).resolve().parent', 1):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('python/tools/license_check.py', "python:Path(__file__).resolve().parent.parent / 'pyproject.toml'", 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('rust/tools/license_check.sh', 'cd "$(dirname "$0")/.."', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('go/tools/license_check.sh', 'cd "$(dirname "$0")/.."', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('python/tools/purity_check.py', 'python:Path(__file__).resolve().parent.parent', 1):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('go/tools/purity_check.sh', 'lib_dir=$(cd "$(dirname "$0")/.." && pwd)', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('rust/tools/purity_check.sh', 'sdk_dir=$(cd "$(dirname "$0")/.." && pwd)', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('go/tools/purity_check.sh', 'sdk_dir=$(cd "$(dirname "$0")/.." && pwd)', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('rust/tools/purity_check.sh', 'src_dir=$(cd "$(dirname "$0")/.." && pwd)/src', 1):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('go/uri.go', 'case "..":', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/uri.go', 'if strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") ||', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/uri.go', 'path == "." || path == ".." {', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/uri_test.go', '{"https://example.test/..", "https://example.test/"},', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/uri_test.go', '{"https://example.test/a/../b", "https://example.test/b"},', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('go/uri_test.go', '{"https://example.test/a/b/..", "https://example.test/a/"},', 1):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('python/src/bounded_authority_verifier/role_attestation.py', "python:hints.pop('return', None)", 1):
        "Removes a return-annotation entry from a type-hint dictionary; no filesystem path is involved.",
    ('python/src/bounded_authority_verifier/v1.py', "python:hints.pop('return', None)", 1):
        "Removes a return-annotation entry from a type-hint dictionary; no filesystem path is involved.",
    ('python/src/bounded_authority_verifier/v2.py', "python:hints.pop('return', None)", 1):
        "Removes a return-annotation entry from a type-hint dictionary; no filesystem path is involved.",
    ('python/src/bounded_authority_verifier/v3.py', "python:hints.pop('return', None)", 1):
        "Removes a return-annotation entry from a type-hint dictionary; no filesystem path is involved.",
    ('python/tests/test_review_regressions.py', "python:expected.pop('trusted_issuer')", 1):
        "Removes a context field from a test dictionary; no filesystem path is involved.",

}

# Tokenize native strings before looking for APIs, so comments, URI text, Rust
# ranges, Go variadics, and Python type ellipses do not become path operations.
NATIVE_TOKENS = re.compile(
    r'(?P<comment>//[^\n]*|/\*.*?\*/)|'
    r'r(?P<hashes>\#*)"(?P<raw>.*?)"(?P=hashes)|'
    r'(?P<quoted>"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])\')',
    re.DOTALL,
)
PARENT_API = re.compile(
    r'(?:\.|::)\s*(?:parent|parents|ancestors|pardir|ParentDir|pop)\b|'
    r'\b(?:filepath|path)\s*\.\s*(?:Dir|Split|SplitList)\b|'
    r'\b(?:ParentDir|pardir)\b|'
    r'\bos\s*\.\s*path\s*\.\s*(?:dirname|split|splitdrive|splitroot)\b|\bdirname\b'
)


def decoded_literal(value):
    # Decode escaped dots/separators in native strings, including Rust's \u{...}.
    return re.sub(
        r'\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|([0-7]{3})|([\\/]))',
        lambda m: chr(int(next(g for g in m.groups()[:3] if g), 16))
        if any(m.groups()[:3]) else chr(int(m[4], 8)) if m[4] else m[5],
        value,
    )


def source_references(path, source):
    """Yield (line, reference, exception text, occurrence anchor) for the early lint."""
    if path.suffix == '.py':
        tree = ast.parse(source, filename=str(path))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

        def reference(node):
            context = node
            while isinstance(parents.get(context), ast.expr) and not isinstance(parents[context], (ast.List, ast.Set, ast.Dict)):
                context = parents[context]
            text = ast.unparse(context)
            return context.lineno, text, 'python:' + text, (context.lineno, context.col_offset)

        def literal(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                return node.value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left, right = literal(node.left), literal(node.right)
                if isinstance(left, (str, bytes)) and type(left) is type(right):
                    return left + right
            return None

        for node in ast.walk(tree):
            value = literal(node)
            if isinstance(value, bytes):
                value = value.decode('latin1')
            if isinstance(value, str) and '..' in re.split(r'[/\\]', value):
                yield reference(node)
            if isinstance(node, ast.Attribute) and PARENT_API.search(ast.unparse(node)):
                yield reference(node)
            if isinstance(node, ast.Name) and node.id in {'pardir', 'ParentDir'}:
                yield reference(node)
            if isinstance(node, ast.ImportFrom) and ((node.module == 'os' and any(n.name == 'pardir' for n in node.names)) or (node.module == 'os.path' and any(n.name in {'dirname', 'split', 'splitdrive', 'splitroot'} for n in node.names))):
                yield reference(node)
            if isinstance(node, ast.Call):
                if PARENT_API.search(ast.unparse(node.func)):
                    yield reference(node)
                if isinstance(node.func, ast.Name) and node.func.id == 'getattr' and len(node.args) >= 2 and literal(node.args[1]) in {'parent', 'parents', 'ancestors', 'pardir', 'pop'}:
                    yield reference(node)
        return

    code = list(source)
    strings = []
    for token in NATIVE_TOKENS.finditer(source):
        if token['comment'] is None:
            value = token['raw'] if token['raw'] is not None else decoded_literal(token['quoted'][1:-1])
            strings.append((token.start(), token.end(), value))
            if '..' in re.split(r'[/\\]', value):
                line = source.count('\n', 0, token.start()) + 1
                yield line, value, source.splitlines()[line - 1].strip(), line
        code[token.start():token.end()] = ['\n' if c == '\n' else ' ' for c in token[0]]
    # Catch literal-built components (concatenation and Rust concat!). Code can
    # construct paths arbitrarily; isolated execution remains the binding gate.
    for left, right in zip(strings, strings[1:]):
        between = source[left[1]:right[0]].strip()
        if left[2].endswith('.') and right[2].startswith('.') and between in {'+', ',', ''}:
            line = source.count('\n', 0, left[0]) + 1
            yield line, 'string-built parent component', source.splitlines()[line - 1].strip(), line
    api_source = source if path.suffix == '.sh' else ''.join(code)
    for match in PARENT_API.finditer(api_source):
        line = source.count('\n', 0, match.start()) + 1
        yield line, match[0], source.splitlines()[line - 1].strip(), line
    if path.suffix in {'.sh', '.toml', '.yaml', '.yml', '.cfg', '.ini'} or path.name in {'Makefile', 'Dockerfile', 'MANIFEST.in'}:
        for match in re.finditer(r'(?<![\w.-])\.\.(?=$|[/\\\s\"\';,()\[\]])', source):
            line = source.count('\n', 0, match.start()) + 1
            yield line, match[0], source.splitlines()[line - 1].strip(), line


def local_path(root, manifest, value):
    """Validate an actual local dependency location, relative to its manifest."""
    if not isinstance(value, str) or not value:
        raise RuntimeError(f'{manifest.name}: invalid local dependency path {value!r}')
    if value.startswith(('path+', 'git+file:', 'registry+file:', 'sparse+file:')):
        value = value.split('+', 1)[1]
    if value.startswith('file:'):
        url = urlsplit(value)
        if url.netloc not in {'', 'localhost'}:
            raise RuntimeError(f'{manifest.name}: nonlocal file URL leaves SDK: {value}')
        value = unquote(url.path)
    if re.match(r'^[A-Za-z]:|^\\', value):
        raise RuntimeError(f'{manifest.name}: dependency path leaves SDK: {value}')
    if '$' in value or value.startswith('~'):
        raise RuntimeError(f'{manifest.name}: unresolved dependency path leaves SDK: {value}')
    target = (manifest.parent / value).resolve()
    if not target.is_relative_to(root):
        raise RuntimeError(f'{manifest.relative_to(root)}: dependency path leaves SDK: {value}')


def metadata_boundary(root, path, seen=None):
    """Parse supported package manifests and lockfiles; return whether handled."""
    if path.name in {'go.mod', 'go.work'}:
        kind = 'mod' if path.name == 'go.mod' else 'work'
        env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOPROXY': 'off'}
        result = subprocess.run(['go', kind, 'edit', '-json', str(path)], env=env, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data = json.loads(result.stdout)
        for replacement in data.get('Replace') or []:
            target = replacement['New']
            if not target.get('Version'):
                local_path(root, path, target['Path'])
        for use in data.get('Use') or []:
            local_path(root, path, use['DiskPath'])
        return True
    if path.name in {'Cargo.toml', 'Cargo.lock', 'pyproject.toml', 'uv.lock'}:
        data = tomllib.loads(path.read_text())

        def paths(value):
            if isinstance(value, list):
                for child in value:
                    paths(child)
            elif isinstance(value, dict):
                for key, child in value.items():
                    if key in {'path', 'directory', 'editable', 'virtual'} and isinstance(child, str):
                        local_path(root, path, child)
                    elif key == 'source' and isinstance(child, str) and child.startswith(('path+', 'file:', 'git+file:', 'registry+file:', 'sparse+file:')):
                        local_path(root, path, child)
                    else:
                        paths(child)
        paths(data)
        if path.name == 'Cargo.toml':
            for member in data.get('workspace', {}).get('members', []):
                local_path(root, path, member)
        if path.name == 'pyproject.toml':
            for member in data.get('tool', {}).get('uv', {}).get('workspace', {}).get('members', []):
                local_path(root, path, member)
        # PEP 508 direct references in project, group and build dependencies.
        if path.name == 'pyproject.toml':
            def references(value):
                if isinstance(value, str) and '@' in value:
                    location = value.split('@', 1)[1].strip().split(';', 1)[0].strip()
                    if location.startswith('file:') or not urlsplit(location).scheme:
                        local_path(root, path, location)
                elif isinstance(value, dict):
                    for child in value.values(): references(child)
                elif isinstance(value, list):
                    for child in value: references(child)
            for table in ['project', 'dependency-groups', 'build-system']:
                references(data.get(table, {}))
        return True
    if (path.name.startswith('requirements') and path.suffix == '.txt') or seen is not None:
        seen = set() if seen is None else seen
        if path in seen:
            return True
        seen.add(path)
        text = re.sub(r'\\\n', '', path.read_text())
        # Requirements have logical lines, dependency declarations, and pip
        # options. Parse the options with their arities; never skip a whole line
        # just because its first option has no path argument.
        path_options = {'-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-f', '--find-links', '-i', '--index-url', '--extra-index-url'}
        value_options = {'--trusted-host', '--only-binary', '--no-binary', '--hash', '--config-settings', '--global-option', '--install-option', '--use-feature', '--use-deprecated'}
        flags = {'--no-index', '--pre', '--prefer-binary', '--require-hashes', '--no-deps', '--no-build-isolation', '--use-pep517'}

        def location(value, *, include=False):
            if value.startswith(('file:', 'git+file:')) or not urlsplit(value).scheme or re.match(r'^[A-Za-z]:|^\\', value):
                local_path(root, path if include else root / "requirements.txt", value)

        for line in text.splitlines():
            line = re.split(r'\s+#', line, 1)[0].strip()
            if not line or line.startswith('#'):
                continue
            words = shlex.split(line)
            dependency = []
            position = 0
            while position < len(words):
                token = words[position]
                if token.startswith('-'):
                    option, separator, value = token.partition('=')
                    if option not in path_options | value_options | flags and token[:2] in {'-r', '-c', '-e', '-f', '-i'}:
                        option, value, separator = token[:2], token[2:], '='
                    if option in flags:
                        position += 1
                        continue
                    if option not in path_options | value_options:
                        raise RuntimeError(f'{path.name}: unsupported requirement option {option}')
                    if not separator:
                        position += 1
                        if position == len(words):
                            raise RuntimeError(f'{path.name}: missing argument for {option}')
                        value = words[position]
                    if option in path_options:
                        location(value, include=option in {"-r", "--requirement", "-c", "--constraint"})
                        if option in {'-r', '--requirement', '-c', '--constraint'} and (not urlsplit(value).scheme or value.startswith('file:')):
                            include_value = unquote(urlsplit(value).path) if value.startswith('file:') else value
                            included = (path.parent / include_value).resolve()
                            if included.is_file(): metadata_boundary(root, included, seen)
                    position += 1
                    continue
                dependency.append(token)
                position += 1
            if not dependency:
                continue
            # A direct reference is NAME [EXTRAS] @ LOCATION [; MARKER]. A
            # bare name/version has no local location. A quoted path stays one
            # shlex token, so spaces cannot hide an escaping path.
            if '@' in dependency:
                index = dependency.index('@') + 1
                if index >= len(dependency): raise RuntimeError(f'{path.name}: missing direct-reference target')
                location(dependency[index].split(';', 1)[0])
            else:
                value = dependency[0].split(';', 1)[0]
                if '@' in value and not value.startswith(('git+', 'http:', 'https:')):
                    location(value.split('@', 1)[1])
                elif value.startswith(('file:', 'git+file:', '.', '/', '~')) or '/' in value or '\\' in value or value.endswith(('.whl', '.zip', '.tar.gz')):
                    location(value)
        return True
    return False


def run(command, cwd, env=None):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def boundary(root):
    root = root.resolve()
    sdk = 'python' if (root / 'pyproject.toml').is_file() else 'rust' if (root / 'Cargo.toml').is_file() else 'go'
    expected = {key for key in BOUNDARY_EXCEPTIONS if key[0].startswith(sdk + '/')}
    observed = set()
    counts = {}
    for path in sorted(root.rglob('*')):
        if not path.is_file() or any(p in {'.git', '.venv', 'target', '__pycache__'} for p in path.relative_to(root).parts):
            continue
        if metadata_boundary(root, path):
            continue
        if path.suffix not in {'.py', '.rs', '.go', '.md', '.sh', '.toml', '.yaml', '.yml', '.cfg', '.ini'} and path.name not in {'Makefile', 'Dockerfile', 'MANIFEST.in'}:
            continue
        source = path.read_text()
        relative = path.relative_to(root).as_posix()
        if path.suffix != '.md':
            references = {(anchor, exception): (line, reference) for line, reference, exception, anchor in source_references(path, source)}
            for (anchor, exception), (line, reference) in sorted(references.items()):
                pair = (sdk + '/' + relative, exception)
                counts[pair] = counts.get(pair, 0) + 1
                key = (*pair, counts[pair])
                observed.add(key)
                if key not in expected:
                    raise RuntimeError(f'{relative}:{line}: parent-path read or link leaves SDK (unproven traversal): {reference}')
        for link in re.findall(r'\]\(([^)]+)\)', source) if path.suffix == '.md' else []:
            if ':' in link or link.startswith('#'):
                continue
            target = (path.parent / link.split('#')[0]).resolve()
            if not target.is_relative_to(root):
                raise RuntimeError(f'{relative}: documentation link leaves SDK: {link}')
    if expected - observed:
        raise RuntimeError(f'boundary exception occurrence missing: {sorted(expected - observed)}')


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

#!/usr/bin/env python3
"""ADR 0049: exercise an SDK alone and its distributable, with owned temporary trees."""
from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

# Exact, reviewed native source lines and Python expression trees only.
# Python trees preserve the full traversal expression across formatting changes.
# Each reason proves SDK-local resolution or identifies non-filesystem data.
BOUNDARY_EXCEPTIONS = {
    ('tests/permissiveness.rs', 'let src = include_str!("../src/v1.rs");'):
        'Compile-time include from tests/ resolves to src/v1.rs inside the SDK root.',
    ('internal/corpuscheck/corpus.go', 'if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") || declared[name] {'):
        'Rejects unsafe indexed names before joining them to the SDK-local corpus root.',
    ('local_loopback_http_test.go', '{"HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"},'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/bounded_authority_verifier/uri.py', "python:inp == b'.' or inp == b'..'"):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/bounded_authority_verifier/uri.py', "python:inp == b'/..'"):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/bounded_authority_verifier/uri.py', "python:inp.startswith(b'/../')"):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/bounded_authority_verifier/uri.py', "python:inp.startswith(b'../')"):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/inspect.rs', '"../tests/fixtures/decoded-binary-rendering.json"'):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('src/lib.rs', '#[doc = include_str!("../README.md")]'):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('src/uri.rs', 'else if input == b"." || input == b".." {'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/uri.rs', 'else if input.starts_with(b"/../") {'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/uri.rs', 'if input.starts_with(b"../") {'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/uri.rs', 'uri_normalize("https://example.com/a/../b", &B()).unwrap(),'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/uri.rs', 'uri_normalize("https://example.com/a/b/../../c", &B()).unwrap(),'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('src/uri.rs', '} else if input == b"/.." {'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('tests/conformance/run.py', "python:_HERE.parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run.py', "python:_HERE.parents[2] / 'src'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_producer_canonicality.py', "python:Path(__file__).resolve().parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_producer_canonicality.py', 'python:sys.path.insert(0, str(Path(__file__).resolve().parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_selector_float_zero.py', "python:Path(__file__).resolve().parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_selector_float_zero.py', 'python:sys.path.insert(0, str(Path(__file__).resolve().parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_strict.py', "python:_HERE.parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_strict.py', "python:_HERE.parents[2] / 'src'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_strict.py', 'python:importlib.util.spec_from_file_location(name, _HERE.parent / filename)'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_strict.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v2.py', "python:_HERE.parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v2.py', "python:_HERE.parents[2] / 'src'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v2.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v3.py', "python:_HERE.parents[2] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v3.py', "python:_HERE.parents[2] / 'src'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/run_v3.py', 'python:sys.path.insert(0, str(_HERE.parents[1]))'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/test_conformance.py', 'python:Path(__file__).resolve().parent'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/test_conformance_producer_canonicality.py', "python:Path(__file__).resolve().parent / 'run_producer_canonicality.py'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/test_conformance_selector_float_zero.py', "python:Path(__file__).resolve().parent / 'run_selector_float_zero.py'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/conformance/test_conformance_strict.py', "python:Path(__file__).resolve().parent / 'run_strict.py'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/content_assertion.rs', '#[path = "../conformance/support.rs"]'):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('tests/corpus_support.py', "python:Path(__file__).resolve().parents[1] / 'conformance/priv/conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/corpus_support.py', "python:all((p != 'index.json' and (not Path(p).is_absolute()) and ('..' not in Path(p).parts) for p in paths))"):
        'Rejects unsafe indexed names before joining them to the SDK-local corpus root.',
    ('tests/local_loopback_http.rs', '#[path = "../conformance/support.rs"]'):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('tests/local_loopback_http.rs', '("HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"),'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "anchored-export", "encode.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "anchored-export", "verify.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v1/corpus", "cases", "envelope", "check.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v2/corpus", "cases", "envelope", "check.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", "priv/conformance/v2/corpus", "cases", surface, "verify.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/permissiveness_test.go', 'raw, err := os.ReadFile(filepath.Join("..", "conformance", corpus, "cases", "grant-decode", "decode.json"))'):
        'Go runs this package in tests/; one parent reaches the SDK root and the fixed conformance tree.',
    ('tests/role_attestation.rs', '#[path = "../conformance/support.rs"]'):
        'Compile-time include is relative to this source file and targets a file inside the SDK root.',
    ('tests/test_content_assertion.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/attestation-profiles/content-assertion/v1'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_decoded_rendering.py', "python:json.loads((Path(__file__).parent / 'fixtures' / 'decoded-rendering.json').read_text())"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_decoded_rendering.py', "python:json.loads((Path(__file__).parent / 'fixtures' / 'decoded-binary-rendering.json').read_text())"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_decoded_rendering.py', "python:json.loads((Path(__file__).parent / 'fixtures' / 'decoded-wire-rendering.json').read_text())"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_host_boundaries.py', "python:Path(bap.__file__).parent / 'json_alg.py'"):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('tests/test_host_boundaries.py', "python:(Path(__file__).parents[1] / 'README.md').read_text()"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_local_loopback_http.py', "python:(b'HTTP://127.0.0.1:80/a/../invoke', b'http://127.0.0.1/invoke')"):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('tests/test_local_loopback_http.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/application-profiles/local-loopback-http/v1'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_packaging.py', "python:(Path(bounded_authority_verifier.__file__).parent / 'py.typed').is_file()"):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('tests/test_permissiveness.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv' / 'conformance' / 'v1' / 'corpus' / 'cases' / 'anchored-export' / 'verify.json'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_permissiveness.py', "python:protected_seg + b'..'"):
        'Empty JWS segment test data; never used as a filesystem path.',
    ('tests/test_quickstart.py', 'python:Path(__file__).resolve().parents[1]'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_review_regressions.py', "python:Path(__file__).resolve().parents[1] / 'conformance'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_review_regressions.py', 'python:Path(bap.__file__).parent'):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('tests/test_review_regressions.py', "python:ast.parse((Path(bap.__file__).parent / 'bounds.py').read_text())"):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('tests/test_role_attestation.py', "python:Path(__file__).resolve().parents[1] / 'conformance' / 'priv/conformance/attestation-profiles/role-attestation/v1'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tests/test_strict_ed25519.py', 'python:Path(sdk_jwk.__file__).resolve().parent'):
        'The imported SDK module lives in src/bounded_authority_verifier; its directory stays in the SDK.',
    ('tools/license_check.py', "python:Path(__file__).resolve().parent.parent / 'pyproject.toml'"):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tools/license_check.sh', 'cd "$(dirname "$0")/.."'):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('tools/purity_check.py', 'python:Path(__file__).resolve().parent.parent'):
        '__file__-anchored traversal stops at the SDK root or a directory beneath it.',
    ('tools/purity_check.sh', 'lib_dir=$(cd "$(dirname "$0")/.." && pwd)'):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('tools/purity_check.sh', 'sdk_dir=$(cd "$(dirname "$0")/.." && pwd)'):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('tools/purity_check.sh', 'src_dir=$(cd "$(dirname "$0")/.." && pwd)/src'):
        '$0 is tools/<checker>; its directory plus one parent is exactly the SDK root.',
    ('uri.go', 'case "..":'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('uri.go', 'if strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") ||'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('uri.go', 'path == "." || path == ".." {'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('uri_test.go', '{"https://example.test/..", "https://example.test/"},'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('uri_test.go', '{"https://example.test/a/../b", "https://example.test/b"},'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
    ('uri_test.go', '{"https://example.test/a/b/..", "https://example.test/a/"},'):
        'RFC 3986 URI normalization input or token; never used as a filesystem path.',
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
    r'(?:\.|::)\s*(?:parent|parents|ancestors)\b|'
    r'\b(?:filepath|path)\s*\.\s*Dir\s*\(|'
    r'\bos\s*\.\s*path\s*\.\s*dirname\s*\(|\bdirname\b'
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
    """Yield (line, reference, exception key) for parent components and APIs."""
    if path.suffix == '.py':
        tree = ast.parse(source, filename=str(path))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

        def reference(node):
            context = node
            while isinstance(parents.get(context), ast.expr) and not isinstance(parents[context], (ast.List, ast.Set, ast.Dict)):
                context = parents[context]
            return node.lineno, ast.unparse(context), 'python:' + ast.unparse(context)

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                value = node.value.decode('latin1') if isinstance(node.value, bytes) else node.value
                if '..' in re.split(r'[/\\]', value):
                    yield reference(node)
            if isinstance(node, ast.Attribute) and node.attr in {'parent', 'parents', 'ancestors'}:
                yield reference(node)
            if isinstance(node, ast.Call) and PARENT_API.search(ast.unparse(node.func)):
                yield reference(node)
        return

    code = list(source)
    for token in NATIVE_TOKENS.finditer(source):
        if token['comment'] is None:
            value = token['raw'] if token['raw'] is not None else decoded_literal(token['quoted'][1:-1])
            if '..' in re.split(r'[/\\]', value):
                line = source.count('\n', 0, token.start()) + 1
                yield line, value, source.splitlines()[line - 1].strip()
        code[token.start():token.end()] = ['\n' if c == '\n' else ' ' for c in token[0]]
    # Shell's nested command substitutions must remain visible to the API scan.
    api_source = source if path.suffix == '.sh' else ''.join(code)
    for match in PARENT_API.finditer(api_source):
        line = source.count('\n', 0, match.start()) + 1
        yield line, match[0], source.splitlines()[line - 1].strip()
    # Shell and manifests also have unquoted path-valued words. Treat their
    # parent components as paths; do not interpret them relative to this file.
    if path.suffix in {'.sh', '.toml', '.yaml', '.yml', '.cfg', '.ini'} or path.name in {'Makefile', 'Dockerfile', 'MANIFEST.in'}:
        for match in re.finditer(r'(?<![\w.-])\.\.(?=$|[/\\\s\"\';,()\[\]])', source):
            line = source.count('\n', 0, match.start()) + 1
            yield line, match[0], source.splitlines()[line - 1].strip()


def run(command, cwd, env=None):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def boundary(root):
    root = root.resolve()
    for path in root.rglob('*'):
        if not path.is_file() or any(p in {'.git', '.venv', 'target', '__pycache__'} for p in path.relative_to(root).parts):
            continue
        if path.suffix not in {'.py', '.rs', '.go', '.md', '.sh', '.toml', '.yaml', '.yml', '.cfg', '.ini'} and path.name not in {'Makefile', 'Dockerfile', 'MANIFEST.in', 'go.mod'}:
            continue
        text = path.read_text()
        relative = path.relative_to(root).as_posix()
        # No general source-directory resolution: runtime relative paths are
        # SDK-root-relative. Every parent component is rejected unless this
        # exact source line or expression has a reviewed proof in BOUNDARY_EXCEPTIONS.
        if path.suffix != '.md':
            for line, reference, exception in source_references(path, text):
                if (relative, exception) not in BOUNDARY_EXCEPTIONS:
                    raise RuntimeError(f'{relative}:{line}: parent-path read or link leaves SDK (unproven traversal): {reference}')
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

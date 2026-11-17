#!/usr/bin/env python3
"""ADR 0014 D7: each D6 closure must independently turn its own test red.

Python requires a named JUnit AssertionError; Rust requires a named assert!/assert_eq!
assertion panic. Go requires the named --- FAIL without a panic. Other exceptions,
compiler/import errors, missing tests, timeouts, and unrelated failures fail the gate.
The original SDK is untouched; temporary copies and their outputs are always removed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (source, exact original, replacement, test). Anchors must match exactly once;
# source drift requires an explicit mutation update, rather than silently losing coverage.
PYTHON = [
    (
        "json_alg.py",
        '        if name_str in members:\n            fail("json: duplicate member")\n',
        "",
        "test_duplicate_member_at_depth_3",
    ),
    (
        "json_alg.py",
        "    members: dict[str, Tagged] = {}",
        "    members: dict[str, Tagged] = _AttributeMembers()",
        "test_dunder_member_preserved_as_data",
    ),
    (
        "json_alg.py",
        '    if len(lexeme) > bounds_resolve(ctx.bounds, "number_lexeme_bytes"):',
        "    if False:",
        "test_66_byte_number_lexeme",
    ),
    (
        "json_alg.py",
        "    if not _lexeme_magnitude_within(text, MAX_INT):",
        "    if False:",
        "test_integer_magnitude_over_bound",
    ),
    (
        "json_alg.py",
        "        if not _lexeme_magnitude_within(text, MAX_FLOAT):",
        "        if False:",
        "test_float_magnitude_checked_on_raw_lexeme_not_lossy_conversion",
    ),
    (
        "json_alg.py",
        "    if ctx.pos != len(src):",
        "    if False:",
        "test_trailing_bytes",
    ),
    (
        "json_alg.py",
        "        return JFloat(n)",
        "        return JInt(int(n))",
        "test_integer_and_float_distinct_identity",
    ),
]
RUST = [
    (
        "json.rs",
        "            if members.iter().any(|(k, _)| k == &name) {",
        "            if false {",
        "closure_1_duplicate_member_rejected",
    ),
    (
        "json.rs",
        "        Ok(JsonValue::Object(members))",
        "        members.sort_by(|a, b| a.0.cmp(&b.0));\n        Ok(JsonValue::Object(members))",
        "closure_2_source_member_order_preserved",
    ),
    (
        "json.rs",
        "        if lexeme.len() as u64 > self.bounds.number_lexeme_bytes() {",
        "        if false {",
        "closure_3_raw_lexeme_byte_ceiling_and_magnitude_enforced_pre_conversion",
    ),
    (
        "json.rs",
        "        if !magnitude_ok(stripped, scale, bound) {",
        "        if false {",
        "closure_3_raw_lexeme_byte_ceiling_and_magnitude_enforced_pre_conversion",
    ),
    (
        "json.rs",
        "    if d.pos != d.input.len() {",
        "    if false {",
        "closure_4_trailing_bytes_after_single_value_rejected",
    ),
    (
        "json.rs",
        "        let is_float = lexeme.iter().any(|&b| matches!(b, b'.' | b'e' | b'E'));",
        "        let is_float = true;",
        "closure_5_int_and_float_tags_do_not_collapse",
    ),
    (
        "jcs.rs",
        "    if *nodes > bounds.total_nodes() {",
        "    if false {",
        "closure_6_total_nodes_over_bound_rejected",
    ),
    (
        "jcs.rs",
        "            if *n < -mag || *n > mag {",
        "            if false {",
        "closure_6_over_magnitude_and_duplicate_members_rejected",
    ),
    (
        "jcs.rs",
        "                if k.len() as u64 > bounds.key_bytes() || !seen.insert(k.as_str()) {",
        "                if k.len() as u64 > bounds.key_bytes() || { seen.insert(k.as_str()); false } {",
        "closure_6_over_magnitude_and_duplicate_members_rejected",
    ),
]
GO = [
    (
        "json.go",
        "\t\tif _, dup := seen[key]; dup {",
        "\t\tif false {",
        "TestPermissiveDuplicateReject",
    ),
    (
        "json.go",
        "\t\tobj = append(obj, Member{Key: key, Val: v})",
        "\t\tobj = append(Obj{{Key: key, Val: v}}, obj...)",
        "TestPermissiveSourceOrderPreserved",
    ),
    (
        "json.go",
        "\tif len(lexeme) > d.b.NumberLexemeBytes {",
        "\tif false {",
        "TestPermissiveRawLexeme",
    ),
    (
        "json.go",
        "\t\tif cmpDigits(string(digits), strconv.Itoa(d.b.IntegerMagnitude)) > 0 {",
        "\t\tif false {",
        "TestPermissiveRawMagnitude",
    ),
    (
        "json.go",
        "\tif r.Abs(r).Cmp(limit) > 0 {",
        "\tif false {",
        "TestPermissiveRawMagnitude",
    ),
    (
        "json.go",
        "\tif d.pos != len(d.data) {",
        "\tif false {",
        "TestPermissiveSingleValue",
    ),
    (
        "json.go",
        "\treturn Float(f), nil",
        "\treturn Int(f), nil",
        "TestPermissiveIntFloatTag",
    ),
]


def invoke(
    command: list[str], cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )


def run(sdk: str) -> None:
    mutations = {"python": PYTHON, "rust": RUST, "go": GO}[sdk]
    source = ROOT / "sdks" / sdk
    # Keep corpus-relative fixture paths working, and exclude all build/cache state.
    with tempfile.TemporaryDirectory(prefix="bap-closures-") as directory:
        scratch = Path(directory)
        target = scratch / "sdks" / sdk
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns(
                "target",
                ".venv",
                "__pycache__",
                ".pytest_cache",
                ".mypy_cache",
                ".ruff_cache",
            ),
        )
        (scratch / "priv").symlink_to(ROOT / "priv", target_is_directory=True)
        env = dict(os.environ)
        env.pop("RUSTFLAGS", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(target / "src")
        # Dependencies may be cached, but code/test artifacts must come from this copy.
        env["CARGO_TARGET_DIR"] = str(target / "target")
        if sdk == "python":
            # pytest's JUnit failure element omits exception types. Record the actual
            # exception class from its report, rather than guessing from error text.
            with (target / "conftest.py").open("a") as hook:
                hook.write(
                    "\nimport pytest\n"
                    "@pytest.hookimpl(hookwrapper=True)\n"
                    "def pytest_runtest_makereport(item, call):\n"
                    "    yield\n"
                    "    if call.when == 'call' and call.excinfo is not None:\n"
                    "        cls = call.excinfo.type\n"
                    "        item.user_properties.append(('exception_type', cls.__module__ + '.' + cls.__qualname__))\n"
                )
        original: dict[Path, str] = {}
        for filename, _, _, _ in mutations:
            path = (
                target / "src" / "bounded_authority_verifier" / filename
                if sdk == "python"
                else target / ("src" if sdk == "rust" else "") / filename
            )
            original[path] = path.read_text()

        def command(test: str | None) -> list[str]:
            if sdk == "python":
                selection = "tests/test_permissiveness.py" + (
                    "::" + test if test else ""
                )
                return [
                    sys.executable,
                    "-m",
                    "pytest",
                    selection,
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--junitxml=" + str(scratch / "result.xml"),
                ]
            if sdk == "rust":
                return ["cargo", "test", "--locked", "--test", "permissiveness"] + (
                    [test, "--", "--exact"] if test else []
                )
            return ["go", "test", "-count=1", "./tests"] + (
                ["-run", "^" + test + "$"] if test else []
            )

        baseline = invoke(command(None), target, env)
        if baseline.returncode != 0:
            raise RuntimeError(
                "unmodified permissiveness suite failed:\n" + baseline.stdout
            )
        print(f"{sdk}: unmodified permissiveness suite GREEN", flush=True)
        for number, (filename, before, after, test) in enumerate(mutations, 1):
            for path, contents in original.items():
                path.write_text(contents)
            path = next(path for path in original if path.name == filename)
            contents = original[path]
            if contents.count(before) != 1:
                raise RuntimeError(
                    f"{sdk}/{filename}: mutation {number} anchor matched {contents.count(before)} times"
                )
            mutated = contents.replace(before, after)
            if sdk == "python" and "_AttributeMembers()" in after:
                # Attribute access absorbs a dunder key instead of subscription returning its data.
                mutated += "\n\nclass _AttributeMembers(dict):\n    def __getitem__(self, key):\n        return getattr(self, key) if hasattr(self, key) else super().__getitem__(key)\n"
            # Removing the Go float magnitude guard must not leave an unused local (a build failure).
            if sdk == "go" and "r.Abs(r)" in before:
                mutated = mutated.replace(
                    "limit := new(big.Rat).SetInt64(int64(d.b.FloatMagnitude))",
                    "_ = r\n\tlimit := new(big.Rat).SetInt64(int64(d.b.FloatMagnitude))\n\t_ = limit",
                )
            path.write_text(mutated)
            result = invoke(command(test), target, env)
            if sdk == "python":
                cases = ET.parse(scratch / "result.xml").findall(".//testcase")
                killed = (
                    len(cases) == 1
                    and cases[0].get("name") == test
                    and cases[0].find("failure") is not None
                    and any(
                        prop.get("name") == "exception_type"
                        and prop.get("value") == "builtins.AssertionError"
                        for prop in cases[0].findall("./properties/property")
                    )
                    and cases[0].find("error") is None
                )
            elif sdk == "rust":
                killed = (
                    f"test {test} ... FAILED" in result.stdout
                    and "test result: FAILED" in result.stdout
                    and "could not compile" not in result.stdout
                    and re.search(
                        r"panicked at[^\n]*\nassertion [`\x27]?", result.stdout
                    )
                    is not None
                )
            else:
                killed = (
                    re.search(r"--- FAIL: " + re.escape(test) + r"\b", result.stdout)
                    is not None
                    and "[build failed]" not in result.stdout
                    and "panic:" not in result.stdout
                )
            if result.returncode == 0 or not killed:
                raise RuntimeError(
                    f"{sdk}: mutation {number} failed to produce the named assertion failure ({test}):\n{result.stdout}"
                )
            print(f"{sdk}: mutation {number} RED in {test}", flush=True)
        print(f"{sdk}: all {len(mutations)} closure removals killed", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"python", "rust", "go"}:
        sys.exit("usage: python3 scripts/check_sdk_closures.py python|rust|go")
    run(sys.argv[1])

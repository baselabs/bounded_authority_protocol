# Release-candidate reproducibility gate (BAP-06).
#
# Builds the unpublished candidate archive TWICE, each in a fresh COPY of the source
# tree under a temp dir, and asserts the two archives are byte-identical (SHA-256
# equal). This DETECTS output-byte drift between two independently-built archives;
# it does not assert "the build is reproducible" from a shared-cache self-comparison
# (the original overclaim defeated by the design's adversarial pass, Challenge 3).
#
# Isolation strategy: each copy gets its own `deps.get` + `hex.build`, so the two
# builds share no compiled artifacts and no fetched deps — the cache isolation that
# makes the gate meaningful. The developer's `_build`/`deps` are NEVER mutated (the
# earlier purge-in-place approach was redesigned after the closeout correctness lens
# found it left the tree degraded and depended on a best-effort restore that could
# fail silently); building in copies sidesteps both.
#
# Honest scope (verified via the red-capable proof at authoring): `mix hex.build`
# packages SOURCE files (the `files:` list — lib/, priv/, docs, metadata), not
# compiled BEAMs. The two builds therefore package the SAME source tree, and the
# gate's value is REGRESSION DETECTION — it catches the moment a future change
# introduces a non-deterministic packaged input (a generated file embedding a build
# path or timestamp, a dep that writes into a packaged dir, a metadata field that
# varies per build). The fresh-copy + fresh-deps.get ensures the second build
# re-resolves and re-assembles rather than reusing any prior state. Hex normalizes
# tar mtimes to epoch, so mtime non-determinism is neutralized. A tamper that changes
# a packaged source file between the two builds is confirmed to make the gate exit
# non-zero (the red-capable proof).
#
# The gate does NOT mutate the project tree; a green or red run leaves the
# developer's environment exactly as it was (the copies live under a temp dir that
# is removed in the `after` block).
#
# Wired into `mix quality` via the `release.candidate` alias (mix.exs). The SHA-256
# printed on success is the candidate-evidence yardstick (same yardstick the
# supply-chain workflow's `SHA256SUMS` uses) — recorded locally, NOT an authority
# shape (AGENTS rule 1: no `receipt`/`decision`).

defmodule BoundedAuthorityProtocol.ReleaseCandidateCheck do
  @moduledoc false

  def run! do
    source_root = File.cwd!()
    assert_mix_lock_present!(source_root)

    tmp = unique_tmp_root!()

    try do
      # Isolation strategy (reconciled closeout F1+F2): build in two fresh COPIES of the
      # source tree, so the developer's _build/deps are never mutated and no restore is
      # needed. Each copy gets its own deps.get + hex.build, so the two builds share no
      # compiled artifacts and no fetched deps — the cache isolation that makes the gate
      # meaningful. The earlier purge-in-place approach (deps.clean + rm -rf _build)
      # left the dev's tree degraded (no _build, including dialyzer PLTs) and depended on
      # a best-effort restore that could fail silently; copying avoids both.
      copy1 = Path.join(tmp, "copy1")
      copy2 = Path.join(tmp, "copy2")
      build1 = Path.join(tmp, "build1.tar")
      build2 = Path.join(tmp, "build2.tar")

      copy_source_tree!(source_root, copy1)
      copy_source_tree!(source_root, copy2)

      build_in!(copy1, build1)
      build_in!(copy2, build2)

      digest1 = sha256_file(build1)
      digest2 = sha256_file(build2)

      unless digest1 == digest2 do
        fail!(
          "candidate archive is not reproducible across independent builds: " <>
            "build1=#{digest1} build2=#{digest2} (two fresh source-tree copies, no shared " <>
            "cache; a non-deterministic input produced different bytes)"
        )
      end

      IO.puts("release candidate reproducibility gate passed (two independent builds agree)")
      IO.puts("candidate archive SHA-256: #{digest1}")
    after
      File.rm_rf!(tmp)
    end
  end

  defp assert_mix_lock_present!(source_root) do
    unless File.regular?(Path.join(source_root, "mix.lock")) do
      fail!("mix.lock is missing — reproducibility cannot be checked without a locked dep set")
    end
  end

  # Copy the source tree into dest, excluding build artifacts, fetched deps, editor/tool
  # state, and generated output. What remains is exactly the source a reproducible build
  # starts from: lib, priv, docs, scripts, tools, mix.exs, mix.lock, and the metadata/docs.
  @copy_excludes ~w(_build deps .git .forge .zcode artifacts cover doc graphify-out
                    bounded_authority_conformance conformance compliance erl_crash.dump)

  defp copy_source_tree!(source, dest) do
    File.mkdir_p!(dest)

    source
    |> File.ls!()
    |> Enum.reject(&(&1 in @copy_excludes))
    |> Enum.each(fn entry ->
      # File.cp_r!/2 handles regular files, directories, and symlinks correctly
      # (it preserves symlinks rather than following them). The earlier case-on-
      # File.lstat form was dead code: File.lstat returns {:ok, %File.Stat{}},
      # not {:regular, _}/{:symlink, _}, so every branch fell through here anyway.
      File.cp_r!(Path.join(source, entry), Path.join(dest, entry))
    end)
  end

  defp build_in!(copy_root, output) do
    # Fetch deps into the copy, then build the archive there. The copy has no _build
    # and no deps, so this is a from-scratch resolve + assemble.
    run!("mix", ["deps.get"], copy_root)
    run!("mix", ["hex.build", "--output", output], copy_root)
    assert_regular_nonempty!(output)
  end

  defp unique_tmp_root! do
    template = Path.join(System.tmp_dir!(), "bounded-authority-release-candidate.XXXXXX")

    case System.cmd("mktemp", ["-d", template], stderr_to_stdout: true) do
      {path, 0} ->
        path = String.trim(path)

        if File.dir?(path),
          do: path,
          else: fail!("mktemp returned a missing directory")

      {output, status} ->
        fail!("mktemp exited with status #{status}: #{String.trim(output)}")
    end
  end

  defp sha256_file(path) do
    case System.cmd("shasum", ["-a", "256", path], stderr_to_stdout: true) do
      {output, 0} ->
        output
        |> String.trim()
        |> String.split(~r/\s+/, parts: 2)
        |> hd()

      {output, status} ->
        fail!("shasum exited with status #{status}: #{String.trim(output)}")
    end
  end

  defp assert_regular_nonempty!(path) do
    unless File.regular?(path) and File.stat!(path).size > 0 do
      fail!("candidate archive is missing or empty: #{path}")
    end
  end

  defp run!(command, arguments, directory) do
    case System.cmd(command, arguments,
           cd: directory,
           stderr_to_stdout: true,
           into: IO.stream(:stdio, :line)
         ) do
      {_output, 0} ->
        :ok

      {_output, status} ->
        fail!("#{command} #{Enum.join(arguments, " ")} exited with status #{status}")
    end
  end

  defp fail!(message), do: raise("release candidate check failed: #{message}")
end

BoundedAuthorityProtocol.ReleaseCandidateCheck.run!()

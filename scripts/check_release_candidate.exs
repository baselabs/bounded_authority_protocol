# Release-candidate reproducibility gate (BAP-06).
#
# Builds the unpublished candidate archive TWICE from independently-prepared build
# environments — purging `_build` and `deps` between the two builds so the second
# build re-resolves and repackages from scratch — and asserts the two archives are
# byte-identical (SHA-256 equal). This DETECTS output-byte drift between two
# independently-built archives; it does not assert "the build is reproducible" from
# a shared-cache self-comparison (the original overclaim defeated by the design's
# adversarial pass, Challenge 3).
#
# Honest scope (verified via the red-capable proof at authoring): `mix hex.build`
# packages SOURCE files (the `files:` list — lib/, priv/, docs, metadata), not
# compiled BEAMs. The two builds therefore package the SAME source tree, and the
# gate's value is REGRESSION DETECTION — it catches the moment a future change
# introduces a non-deterministic packaged input (a generated file embedding a build
# path or timestamp, a dep that writes into a packaged dir, a metadata field that
# varies per build). The cache purge between builds ensures the second build
# re-resolves deps and re-assembles the archive rather than reusing mix's assembled
# state, so any non-determinism in the assembly path surfaces. Hex normalizes tar
# mtimes to epoch, so mtime non-determinism is already neutralized; the gate catches
# the rest. A tamper that changes a packaged source file between the two builds is
# confirmed to make the gate exit non-zero (the red-capable proof).
#
# The gate mutates the project tree (`mix deps.clean --all`, `rm -rf _build`) and
# restores it (`mix deps.get`) before exiting, so a green run leaves a working tree.
# A red run (byte drift) exits non-zero AFTER restoring the tree, so the developer's
# environment is never left broken by the gate.
#
# Wired into `mix quality` via the `release.candidate` alias (mix.exs). The SHA-256
# printed on success is the candidate-evidence yardstick (same yardstick the
# supply-chain workflow's `SHA256SUMS` uses) — recorded locally, NOT an authority
# shape (AGENTS rule 1: no `receipt`/`decision`).

defmodule BoundedAuthorityProtocol.ReleaseCandidateCheck do
  @moduledoc false

  def run! do
    source_root = File.cwd!()

    tmp = unique_tmp_root!()
    build1 = Path.join(tmp, "build1.tar")
    build2 = Path.join(tmp, "build2.tar")

    try do
      assert_mix_lock_present!(source_root)

      run!("mix", ["hex.build", "--output", build1], source_root)
      assert_regular_nonempty!(build1)
      digest1 = sha256_file(build1)

      # Cache isolation: purge compiled artifacts and fetched deps so build #2
      # recompiles every source and re-resolves every dependency from scratch.
      run!("mix", ["deps.clean", "--all"], source_root)
      File.rm_rf!(Path.join(source_root, "_build"))

      run!("mix", ["hex.build", "--output", build2], source_root)
      assert_regular_nonempty!(build2)
      digest2 = sha256_file(build2)

      unless digest1 == digest2 do
        fail!(
          "candidate archive is not reproducible across independent builds: " <>
            "build1=#{digest1} build2=#{digest2} (cache was purged between builds; " <>
            "a non-deterministic input produced different bytes)"
        )
      end

      IO.puts("release candidate reproducibility gate passed (two independent builds agree)")
      IO.puts("candidate archive SHA-256: #{digest1}")
    after
      # Restore the tree so the gate never leaves the developer's environment broken.
      restore_deps!(source_root)
      File.rm_rf!(tmp)
    end
  end

  defp assert_mix_lock_present!(source_root) do
    unless File.regular?(Path.join(source_root, "mix.lock")) do
      fail!("mix.lock is missing — reproducibility cannot be checked without a locked dep set")
    end
  end

  defp restore_deps!(source_root) do
    # Re-fetch deps destroyed by deps.clean --all. Best-effort: if this fails the
    # developer can run `mix deps.get` manually, but a silent broken tree is worse
    # than a loud restore error.
    case System.cmd("mix", ["deps.get"],
           cd: source_root,
           stderr_to_stdout: true,
           into: IO.stream(:stdio, :line)
         ) do
      {_output, 0} ->
        :ok

      {_output, status} ->
        IO.puts(
          "warning: mix deps.get exited #{status} during restore — run `mix deps.get` manually"
        )
    end
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

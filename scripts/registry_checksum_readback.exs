# Release read-back: the Hex registry checksum of a published release must equal the SHA-256 the
# supply-chain workflow attested for that release's archive (its SHA256SUMS artifact).
#
#   mix run --no-start scripts/registry_checksum_readback.exs -- --version 1.0.0 \
#     --sums path/to/SHA256SUMS [--tarball path/to/bounded_authority_protocol-1.0.0.tar]
#   mix run --no-start scripts/registry_checksum_readback.exs -- --self-check
#
# The registry checksum is the release API's `checksum` (SHA-256 of the whole package tarball,
# the "outer" checksum `mix hex.publish` prints), read from
# https://hex.pm/api/packages/bounded_authority_protocol/releases/VERSION with TLS peer
# verification. SHA256SUMS is the file the supply-chain workflow writes with `sha256sum` beside
# the attested archive; verify it first (`sha256sum --check SHA256SUMS` and
# `gh attestation verify`). `--tarball` also compares a local archive's SHA-256 (release step 3,
# the pre-publish binding, or a fresh download).
#
# Prints one JSON evidence line. Exit 0: every compared checksum is equal; 1: a mismatch or a
# missing/unreadable value; 2: usage. `--self-check` exercises the comparison and the SHA256SUMS
# parser on built-in inputs without the network.

defmodule BoundedAuthorityProtocol.RegistryChecksumReadback do
  @moduledoc false

  @package "bounded_authority_protocol"
  @api "https://hex.pm/api/packages/#{@package}/releases/"

  def main(argv) do
    case parse(argv, %{}) do
      {:ok, %{self_check: true}} -> self_check()
      {:ok, %{version: version, sums: sums} = opts} -> read_back(version, sums, opts[:tarball])
      _usage -> usage()
    end
  end

  defp parse([], acc), do: {:ok, acc}
  defp parse(["--" | rest], acc), do: parse(rest, acc)
  defp parse(["--self-check" | rest], acc), do: parse(rest, Map.put(acc, :self_check, true))
  defp parse(["--version", v | rest], acc), do: parse(rest, Map.put(acc, :version, v))
  defp parse(["--sums", path | rest], acc), do: parse(rest, Map.put(acc, :sums, path))
  defp parse(["--tarball", path | rest], acc), do: parse(rest, Map.put(acc, :tarball, path))
  defp parse(_argv, _acc), do: :usage

  defp usage do
    IO.puts(
      :stderr,
      "usage: scripts/registry_checksum_readback.exs --version X.Y.Z --sums SHA256SUMS " <>
        "[--tarball ARCHIVE] | --self-check"
    )

    System.halt(2)
  end

  defp read_back(version, sums_path, tarball) do
    archive = "#{@package}-#{version}.tar"

    with {:ok, sums} <- read(sums_path, "SHA256SUMS"),
         {:ok, attested} <- attested_sha256(sums, archive),
         {:ok, registry} <- registry_checksum(version),
         {:ok, local} <- local_sha256(tarball) do
      report(%{
        package: @package,
        version: version,
        archive: archive,
        attested_sha256: attested,
        registry_checksum: registry,
        local_tarball_sha256: local
      })
    else
      {:error, reason} -> fail(reason)
    end
  end

  @doc false
  # The comparison every mode uses: every present checksum equals the attested one.
  def compare(%{attested_sha256: attested} = evidence) do
    checks =
      [evidence[:registry_checksum], evidence[:local_tarball_sha256]]
      |> Enum.reject(&is_nil/1)

    checks != [] and Enum.all?(checks, &(&1 == attested))
  end

  defp report(evidence) do
    match = compare(evidence)

    IO.puts(
      :json.encode(evidence |> Map.reject(fn {_k, v} -> is_nil(v) end) |> Map.put(:match, match))
    )

    if match, do: :ok, else: System.halt(1)
  end

  defp fail(reason) do
    IO.puts(:stderr, "registry read-back failed: #{reason}")
    System.halt(1)
  end

  defp read(path, label) do
    case File.read(path) do
      {:ok, bytes} ->
        {:ok, bytes}

      {:error, reason} ->
        {:error, "cannot read #{label} at #{path}: #{:file.format_error(reason)}"}
    end
  end

  @doc false
  # `sha256sum` lines: 64 lowercase hex digits, two spaces (or space and `*`), the file name.
  def attested_sha256(sums, archive) do
    matches =
      for line <- String.split(sums, "\n", trim: true),
          [hash, name] <- [String.split(String.trim_trailing(line), ~r/ [ *]/, parts: 2)],
          name == archive,
          do: hash

    case matches do
      [hash] ->
        if Regex.match?(~r/\A[0-9a-f]{64}\z/, hash),
          do: {:ok, hash},
          else: {:error, "the SHA256SUMS entry for #{archive} is not a SHA-256"}

      [] ->
        {:error, "SHA256SUMS has no entry for #{archive}"}

      _many ->
        {:error, "SHA256SUMS has more than one entry for #{archive}"}
    end
  end

  defp registry_checksum(version) do
    {:ok, _apps} = Application.ensure_all_started([:inets, :ssl])

    request = {String.to_charlist(@api <> version), [{~c"accept", ~c"application/json"}]}

    ssl = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    case :httpc.request(:get, request, [ssl: ssl, timeout: 30_000], body_format: :binary) do
      {:ok, {{_http, 200, _reason}, _headers, body}} ->
        case :json.decode(body) do
          %{"checksum" => checksum} when is_binary(checksum) -> {:ok, String.downcase(checksum)}
          _other -> {:error, "the registry release has no checksum"}
        end

      {:ok, {{_http, status, _reason}, _headers, _body}} ->
        {:error, "the registry answered HTTP #{status} for #{@package} #{version}"}

      {:error, reason} ->
        {:error, "the registry request failed: #{inspect(reason)}"}
    end
  end

  defp local_sha256(nil), do: {:ok, nil}

  defp local_sha256(path) do
    with {:ok, bytes} <- read(path, "the tarball") do
      {:ok, Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}
    end
  end

  defp self_check do
    hash = Base.encode16(:crypto.hash(:sha256, "archive"), case: :lower)
    other = Base.encode16(:crypto.hash(:sha256, "other"), case: :lower)
    archive = "#{@package}-1.0.0.tar"
    sums = "#{hash}  #{archive}\n#{other}  #{@package}-0.9.1.tar\n"

    checks = [
      {"parses the archive's line", attested_sha256(sums, archive) == {:ok, hash}},
      {"accepts the binary-mode marker",
       attested_sha256("#{hash} *#{archive}\n", archive) == {:ok, hash}},
      {"refuses a missing entry",
       match?({:error, _}, attested_sha256(sums, "#{@package}-2.0.0.tar"))},
      {"refuses a duplicate entry", match?({:error, _}, attested_sha256(sums <> sums, archive))},
      {"refuses a non-digest",
       match?({:error, _}, attested_sha256("XYZ  #{archive}\n", archive))},
      {"matches equal checksums",
       compare(%{attested_sha256: hash, registry_checksum: hash, local_tarball_sha256: hash})},
      {"rejects a different registry checksum",
       not compare(%{attested_sha256: hash, registry_checksum: other})},
      {"rejects a different local tarball",
       not compare(%{attested_sha256: hash, registry_checksum: hash, local_tarball_sha256: other})},
      {"rejects a comparison with nothing to compare", not compare(%{attested_sha256: hash})}
    ]

    failed = for {name, false} <- checks, do: name

    if failed == [] do
      IO.puts("registry read-back self-check: ok checks=#{length(checks)}")
    else
      IO.puts(:stderr, "registry read-back self-check FAILED: #{Enum.join(failed, "; ")}")
      System.halt(1)
    end
  end
end

BoundedAuthorityProtocol.RegistryChecksumReadback.main(System.argv())

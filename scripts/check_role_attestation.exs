# Role-attestation profile check (BAP-23): certified-corpus verification receipt.
#
# Verifies the profile corpus exactly as the ExUnit suite does — the pinned certified index
# digest, per-file digests, profile identity/revision/counts, every case's decode/verify
# verdict, the v1 cross-rejection direction, and the v2/v3 rejection of attestation bytes —
# then emits a secret-free receipt with source identity. Run via `mix role_attestation.verify`.

# REQ-RA1-CONFORMANCE-certified-pin: every corpus consumer pins the certified digest
# independently; a regenerated, self-consistent corpus must not verify green (the pin is the
# only comparison that distinguishes the certified corpus from a fresh mint).
# @certified_index_sha256 matches test/bounded_authority_protocol/role_attestation/v1_test.exs
# and spec/bap-role-attestation-v1.md §6 (rev 1, 40 cases).
certified_index_sha256 = "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

alias BoundedAuthorityProtocol.RoleAttestation.V1
alias BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation
alias BoundedAuthorityProtocol.V1, as: StandardV1
alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
alias BoundedAuthorityProtocol.V2, as: StandardV2
alias BoundedAuthorityProtocol.V3, as: StandardV3

root = "priv/conformance/attestation-profiles/role-attestation/v1"

{source_head_sha, 0} =
  System.cmd("git", ["rev-parse", "HEAD"], stderr_to_stdout: true)

source_head_sha = String.trim(source_head_sha)

index_bytes = root |> Path.join("index.json") |> File.read!()

index_sha = Base.encode16(:crypto.hash(:sha256, index_bytes), case: :lower)

unless index_sha == certified_index_sha256,
  do:
    raise(
      "role-attestation certified index digest mismatch: got #{index_sha}, want #{certified_index_sha256}"
    )

index = :json.decode(index_bytes)

unless index["profile"] == "bap-role-attestation/1" and index["revision"] == 1 and
         Enum.map(index["files"], & &1["path"]) == ["profile.json", "attestation-cases.json"] do
  raise "role-attestation corpus identity mismatch: #{inspect(index)}"
end

Enum.each(index["files"], fn %{"path" => path, "sha256" => expected_sha} ->
  actual =
    root
    |> Path.join(path)
    |> File.read!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)

  unless actual == expected_sha,
    do: raise("role-attestation corpus file digest mismatch: #{path}")
end)

profile = root |> Path.join("profile.json") |> File.read!() |> :json.decode()

{:ok, attestor_public} = Base.url_decode64(profile["attestor"]["public_key"], padding: false)
{:ok, subject_public} = Base.url_decode64(profile["subject"]["public_key"], padding: false)

expected = %ExpectedAttestation{
  attestor: %HistoricalPublicKey{
    key_id: profile["attestor"]["key_id"],
    public_key: attestor_public,
    valid_from: profile["attestor"]["valid_from"],
    valid_before: profile["attestor"]["valid_before"]
  },
  subject_key_id: profile["subject"]["key_id"],
  subject_public_key: subject_public,
  now: profile["now"],
  bounds: %{}
}

cases = root |> Path.join("attestation-cases.json") |> File.read!() |> :json.decode()

unless length(cases) == index["attestation_cases"] do
  raise "role-attestation case count mismatch"
end

results =
  Enum.map(cases, fn attestation_case ->
    case_expected =
      case Map.get(attestation_case, "expected_overrides", %{}) do
        overrides when map_size(overrides) == 0 ->
          expected

        %{"now" => now} = o when map_size(o) == 1 ->
          %{expected | now: now}

        %{"subject_public_key" => enc} = o when map_size(o) == 1 ->
          {:ok, public_key} = Base.url_decode64(enc, padding: false)
          %{expected | subject_public_key: public_key}

        %{"subject_key_id" => key_id} = o when map_size(o) == 1 ->
          %{expected | subject_key_id: key_id}

        %{"attestor_public_key" => enc} = o when map_size(o) == 1 ->
          {:ok, public_key} = Base.url_decode64(enc, padding: false)
          %{expected | attestor: %{expected.attestor | public_key: public_key}}

        %{"subject_key_id" => key_id, "subject_public_key" => enc} = o when map_size(o) == 2 ->
          {:ok, public_key} = Base.url_decode64(enc, padding: false)
          %{expected | subject_key_id: key_id, subject_public_key: public_key}
      end

    %{
      id: attestation_case["id"],
      decode: match?({:ok, _}, V1.decode_attestation(attestation_case["compact"], %{})),
      decode_expected: attestation_case["decode"],
      verify: match?({:ok, _}, V1.verify_attestation(attestation_case["compact"], case_expected)),
      verify_expected: attestation_case["verify"],
      standard_grant: match?({:ok, _}, StandardV1.decode_grant(attestation_case["compact"], %{})),
      standard_grant_expected: Map.get(attestation_case, "v1_grant", false),
      successor_grant_rejects:
        match?({:error, :invalid}, StandardV2.decode_grant(attestation_case["compact"], %{})),
      es256_grant_rejects:
        match?({:error, :invalid}, StandardV3.decode_grant(attestation_case["compact"], %{}))
    }
  end)

mismatches =
  Enum.filter(results, fn r ->
    r.decode != r.decode_expected or r.verify != r.verify_expected or
      r.standard_grant != r.standard_grant_expected or not r.successor_grant_rejects or
      not r.es256_grant_rejects
  end)

if mismatches != [] do
  raise "role-attestation corpus verdict mismatch: #{inspect(Enum.map(mismatches, & &1.id))}"
end

receipt = %{
  profile: "bap-role-attestation/1",
  source_head_sha: source_head_sha,
  corpus_index_sha256: index_sha,
  cases: length(cases),
  elixir: System.version(),
  keys: "ephemeral_in_memory_minted",
  credentials_retained: false,
  decode_agreed: length(results),
  verify_agreed: length(results),
  cross_profile_rejections: "v1_v2_v3"
}

IO.puts(:json.encode(receipt))

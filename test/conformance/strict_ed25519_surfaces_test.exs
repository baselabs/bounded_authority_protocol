Code.require_file("../../test_support/ed25519_reference.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Conformance.StrictEd25519SurfacesTest do
  @moduledoc """
  End to end, every Ed25519 verification surface refuses the keyless small-order forgery.

  The forged signature is `R = identity, S = 0`, made with no private key. It satisfies the
  cofactorless equation under any key whose point is the identity, so a verifier that skips
  rule S1 accepts it. Each surface is driven with the canonical identity key and with its
  non-canonical alias `y = 1 + p`.

  Every forged artifact is built from an honest producer output with the key material swapped
  in afterward (a header JWK `x`, a payload fingerprint, or an RA1 subject key), so the
  artifact reaches the verifier whether or not the producers accept weak keys. Each surface
  also carries a positive control: the identical construction under an honest key and an
  honest signature verifies, so a rejection here is the key or signature rule and not a broken
  fixture.

  The producers and the JWK functions refuse every weak key encoding (the 8 small-order
  points, the 40 non-canonical encodings and a canonical off-curve encoding, all derived by
  arithmetic in `test_support/ed25519_reference.ex`), and accept an honest key and its
  mixed-order torsion variant, which key acceptance admits by design.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: CA
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RA
  alias BoundedAuthorityProtocol.TestSupport.Ed25519Reference, as: Ref
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.ArchivedObject
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
  alias BoundedAuthorityProtocol.V1.ConsumptionEntry
  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedAnchoredExport
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedExport
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.HistoricalKeyChain
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V1.TrustedIssuer
  alias BoundedAuthorityProtocol.V2

  # The canonical identity encoding and its non-canonical alias y = 1 + p.
  @weak_keys [
    {"the identity key", <<1, 0::248>>},
    {"the identity alias y = 1 + p", Base.decode16!("EE" <> String.duplicate("FF", 30) <> "7F")}
  ]

  # R = identity, S = 0: no private key involved.
  @forged <<1, 0::248, 0::256>>
  @zero_hash <<0::256>>

  @surfaces [
    {"v1 grant (issuer key)", {:grant, 1}},
    {"v2 grant (issuer key)", {:grant, 2}},
    {"v1 envelope (holder key)", {:envelope, 1}},
    {"v2 envelope (holder key)", {:envelope, 2}},
    {"loopback envelope (holder key)", :loopback_envelope},
    {"v1 boundary anchor (archive key)", {:anchor, 1}},
    {"v2 boundary anchor (archive key)", {:anchor, 2}},
    {"v1 key transition (current key)", {:transition, 1}},
    {"v2 key transition (current key)", {:transition, 2}},
    {"v1 anchored export (archive key)", {:export, 1}},
    {"v2 anchored export (archive key)", {:export, 2}},
    {"RA1 attestation (attestor key)", :ra1_attestor},
    {"RA1 attestation (subject key)", :ra1_subject},
    {"CA1 assertion (attestor key)", :ca1_attestor}
  ]

  # A string tag per surface, so a mutation script can select one surface with
  # `--only surface:<tag>` (for example `surface:ca1-attestor`).
  surface_tag = fn
    {kind, major} -> "#{kind}-#{major}"
    surface -> surface |> Atom.to_string() |> String.replace("_", "-")
  end

  for {label, surface} <- @surfaces do
    @tag surface: surface_tag.(surface)
    test "#{label}: the honest positive control verifies" do
      {public, private} = :crypto.generate_key(:eddsa, :ed25519)
      signer = fn message -> :crypto.sign(:eddsa, :none, message, [private, :ed25519]) end

      assert {:ok, _facts} = run_surface(unquote(surface), public, signer)
    end

    for {key_label, key} <- @weak_keys do
      @tag surface: surface_tag.(surface)
      test "#{label}: the keyless forgery under #{key_label} is refused" do
        assert {:error, :invalid} =
                 run_surface(unquote(surface), unquote(key), fn _message -> @forged end)
      end
    end
  end

  # --- producers and key acceptance ------------------------------------------------------

  # Every weak encoding, by arithmetic: the 8 points of E[8], the 40 non-canonical encodings,
  # and the first canonical y whose strict decoding fails (off the curve).
  @small_order_encodings Enum.map(Ref.torsion_points(), &Ref.encode/1)
  @off_curve Enum.find_value(2..1000, fn y ->
               bytes = <<y::little-size(256)>>
               if Ref.decode(bytes, :strict) == :error, do: bytes
             end)
  @weak_encodings @small_order_encodings ++ Ref.non_canonical_encodings() ++ [@off_curve]

  @producers [
    {"V1.proof_signing_input", {:proof, 1}},
    {"V2.proof_signing_input", {:proof, 2}},
    {"loopback proof_signing_input", :proof_loopback},
    {"V1.boundary_anchor_signing_input", {:anchor, 1}},
    {"V2.boundary_anchor_signing_input", {:anchor, 2}},
    {"V1.key_transition_signing_input (current key)", {:transition_current, 1}},
    {"V1.key_transition_signing_input (next key)", {:transition_next, 1}},
    {"V2.key_transition_signing_input (current key)", {:transition_current, 2}},
    {"V2.key_transition_signing_input (next key)", {:transition_next, 2}},
    {"RA1 attestation_signing_input (subject key)", :attestation_subject},
    {"Jwk.encode_public", :jwk_encode},
    {"Jwk.decode_public", :jwk_decode},
    {"Jwk.public_key_thumbprint_raw", :jwk_thumbprint}
  ]

  for {label, producer} <- @producers do
    @tag surface: "producers"
    test "#{label} refuses every weak key and accepts honest and mixed-order keys" do
      assert length(@weak_encodings) == 49
      assert Ref.decode(@off_curve, :strict) == :error

      {honest, _private} = :crypto.generate_key(:eddsa, :ed25519)
      mixed = Ref.encode(Ref.add(elem(Ref.decode(honest), 1), Enum.at(Ref.torsion_points(), 1)))

      assert {:ok, _honest} = produce(unquote(producer), honest)
      assert {:ok, _mixed} = produce(unquote(producer), mixed)

      accepted =
        for weak <- @weak_encodings,
            produce(unquote(producer), weak) != {:error, :invalid},
            do: Base.encode16(weak, case: :lower)

      assert accepted == []
    end
  end

  defp produce({:proof, 1}, key),
    do: V1.proof_signing_input(proof(V1.Proof, key, "https://service.example/a", nil), %{})

  defp produce({:proof, 2}, key),
    do: V2.proof_signing_input(proof(V2.Proof, key, "https://service.example/a", nil), %{})

  defp produce(:proof_loopback, key),
    do:
      Loopback.proof_signing_input(
        proof(V1.Proof, key, "http://127.0.0.1:4000/invoke", "challenge-1"),
        %{}
      )

  defp produce({:anchor, 1}, key),
    do:
      V1.boundary_anchor_signing_input(
        %{anchor("urn:example:anchor:a", 1, 0, @zero_hash) | public_key: key},
        %{}
      )

  defp produce({:anchor, 2}, key),
    do:
      V2.boundary_anchor_signing_input(
        %{anchor("urn:example:anchor:a", 1, 0, @zero_hash) | public_key: key},
        %{}
      )

  defp produce({:transition_current, 1}, key),
    do: V1.key_transition_signing_input(transition(key, generated()), %{})

  defp produce({:transition_next, 1}, key),
    do: V1.key_transition_signing_input(transition(generated(), key), %{})

  defp produce({:transition_current, 2}, key),
    do: V2.key_transition_signing_input(transition(key, generated()), %{})

  defp produce({:transition_next, 2}, key),
    do: V2.key_transition_signing_input(transition(generated(), key), %{})

  defp produce(:attestation_subject, key), do: RA.attestation_signing_input(attestation(key), %{})
  defp produce(:jwk_encode, key), do: Jwk.encode_public(key, %{})

  defp produce(:jwk_decode, key),
    do: Jwk.decode_public(~s({"crv":"Ed25519","kty":"OKP","x":"#{b64(key)}"}), %{})

  defp produce(:jwk_thumbprint, key), do: Jwk.public_key_thumbprint_raw(key, %{})

  defp proof(module, holder_key, target_uri, nonce) do
    struct!(module,
      holder_public_key: holder_key,
      proof_id: "urn:example:proof:1",
      method: "POST",
      target_uri: target_uri,
      issued_at: 1_800_001_000,
      nonce: nonce,
      invocation_id: "7d444840-9dc0-11ed-a8fc-0242ac120002",
      operation: "read_record",
      grant_compact: "e30.e30." <> b64(<<0::512>>),
      cast_arguments: {:object, []}
    )
  end

  defp transition(current_key, next_key) do
    %KeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: "urn:example:chain",
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_public_key: current_key,
      next_key_id: "archive-key-b",
      next_public_key: next_key
    }
  end

  defp generated, do: elem(:crypto.generate_key(:eddsa, :ed25519), 0)

  # --- surfaces --------------------------------------------------------------------------

  defp run_surface({:grant, 1}, key, signer),
    do: grant_surface(V1, V1.Grant, V1.Operation, key, signer)

  defp run_surface({:grant, 2}, key, signer),
    do: grant_surface(V2, V2.Grant, V2.Operation, key, signer)

  defp run_surface({:envelope, 1}, key, signer),
    do: envelope_surface(V1, V1.Grant, V1.Operation, V1.Proof, key, signer)

  defp run_surface({:envelope, 2}, key, signer),
    do: envelope_surface(V2, V2.Grant, V2.Operation, V2.Proof, key, signer)

  defp run_surface(:loopback_envelope, key, signer), do: loopback_surface(key, signer)
  defp run_surface({:anchor, 1}, key, signer), do: anchor_surface(V1, key, signer)
  defp run_surface({:anchor, 2}, key, signer), do: anchor_surface(V2, key, signer)
  defp run_surface({:transition, 1}, key, signer), do: transition_surface(V1, key, signer)
  defp run_surface({:transition, 2}, key, signer), do: transition_surface(V2, key, signer)
  defp run_surface({:export, 1}, key, signer), do: export_surface(V1, key, signer)
  defp run_surface({:export, 2}, key, signer), do: export_surface(V2, key, signer)
  defp run_surface(:ra1_attestor, key, signer), do: ra1_attestor_surface(key, signer)
  defp run_surface(:ra1_subject, key, _signer), do: ra1_subject_surface(key)
  defp run_surface(:ca1_attestor, key, signer), do: ca1_surface(key, signer)

  defp grant_surface(facade, grant_module, operation_module, issuer_key, signer) do
    {holder_public, _holder_private} = :crypto.generate_key(:eddsa, :ed25519)
    grant = grant(grant_module, operation_module, "issuer-x", raw_thumbprint(holder_public))
    {:ok, input} = facade.grant_signing_input(grant, %{})
    {:ok, compact} = facade.assemble_compact(input, signer.(input.message))

    facade.verify_grant(
      compact,
      %TrustedIssuer{key_id: "issuer-x", public_key: issuer_key},
      %ExpectedGrant{
        issuer: "https://issuer.example",
        audience: "https://service.example",
        evaluation_time: 1_800_001_000,
        clock_skew: 60,
        bounds: %{}
      }
    )
  end

  defp envelope_surface(facade, grant_module, operation_module, proof_module, holder_key, signer) do
    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
    {carrier_public, _carrier_private} = :crypto.generate_key(:eddsa, :ed25519)

    grant = grant(grant_module, operation_module, "issuer-1", raw_thumbprint(holder_key))
    {:ok, grant_input} = facade.grant_signing_input(grant, %{})
    grant_compact = honest_compact(grant_input.message, issuer_private)

    arguments = {:object, [{"x", {:string, "attacker-chosen"}}]}

    proof =
      struct!(proof_module,
        holder_public_key: carrier_public,
        proof_id: "p-forged",
        method: "POST",
        target_uri: "https://service.example/anything",
        issued_at: 1_800_001_000,
        nonce: nil,
        invocation_id: "7d444840-9dc0-11ed-a8fc-0242ac120002",
        operation: "read_record",
        grant_compact: grant_compact,
        cast_arguments: arguments
      )

    {:ok, proof_input} = facade.proof_signing_input(proof, %{})
    message = swap(proof_input.message, b64(carrier_public), b64(holder_key))

    facade.check_envelope(
      %Credentials{grant: grant_compact, proof: compact(message, signer.(message))},
      %ExpectedRequest{
        trusted_issuer: %TrustedIssuer{key_id: "issuer-1", public_key: issuer_public},
        issuer: "https://issuer.example",
        audience: "https://service.example",
        method: "POST",
        target_uri: "https://service.example/anything",
        invocation_id: "7d444840-9dc0-11ed-a8fc-0242ac120002",
        operation: "read_record",
        cast_arguments: arguments,
        evaluation_time: 1_800_001_000,
        clock_skew: 60,
        proof_max_age: 300,
        nonce: :not_required,
        bounds: %{}
      }
    )
  end

  defp loopback_surface(holder_key, signer) do
    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
    {carrier_public, _carrier_private} = :crypto.generate_key(:eddsa, :ed25519)

    grant = %V1.Grant{
      key_id: "issuer-local-1",
      issuer: "urn:example:issuer:local",
      grant_id: "g-local",
      audiences: ["urn:example:audience:local"],
      issued_at: 1_735_689_600,
      not_before: 1_735_689_600,
      expires_at: 1_735_693_200,
      holder_thumbprint: raw_thumbprint(holder_key),
      operations: [%V1.Operation{name: "read_record", selectors: [:all]}]
    }

    {:ok, grant_input} = V1.grant_signing_input(grant, %{})
    grant_compact = honest_compact(grant_input.message, issuer_private)
    arguments = {:object, [{"record_id", {:string, "record-1"}}]}

    proof = %V1.Proof{
      holder_public_key: carrier_public,
      proof_id: "urn:example:proof:local",
      method: "POST",
      target_uri: "http://127.0.0.1:4000/invoke",
      issued_at: 1_735_689_660,
      nonce: "challenge-local-001",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "read_record",
      grant_compact: grant_compact,
      cast_arguments: arguments
    }

    {:ok, proof_input} = Loopback.proof_signing_input(proof, %{})
    message = swap(proof_input.message, b64(carrier_public), b64(holder_key))

    Loopback.check_envelope(
      %Credentials{grant: grant_compact, proof: compact(message, signer.(message))},
      %ExpectedRequest{
        trusted_issuer: %TrustedIssuer{key_id: "issuer-local-1", public_key: issuer_public},
        issuer: "urn:example:issuer:local",
        audience: "urn:example:audience:local",
        method: "POST",
        target_uri: proof.target_uri,
        invocation_id: proof.invocation_id,
        operation: proof.operation,
        cast_arguments: arguments,
        evaluation_time: proof.issued_at,
        clock_skew: 60,
        proof_max_age: 300,
        nonce: {:required, proof.nonce},
        bounds: %{}
      }
    )
  end

  defp anchor_surface(facade, archive_key, signer) do
    anchor = anchor("urn:example:anchor:start", 1999, 0, @zero_hash)
    compact = forged_anchor(facade, anchor, archive_key, signer)

    facade.verify_historical_anchor(
      compact,
      historical_key("archive-key-a", archive_key),
      expected_anchor(anchor, raw_thumbprint(archive_key))
    )
  end

  defp transition_surface(facade, current_key, signer) do
    {carrier_public, _carrier_private} = :crypto.generate_key(:eddsa, :ed25519)
    {next_public, _next_private} = :crypto.generate_key(:eddsa, :ed25519)

    transition = %KeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: "urn:example:chain",
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_public_key: carrier_public,
      next_key_id: "archive-key-b",
      next_public_key: next_public
    }

    {:ok, input} = facade.key_transition_signing_input(transition, %{})

    message =
      swap(input.message, b64(raw_thumbprint(carrier_public)), b64(raw_thumbprint(current_key)))

    facade.verify_key_transition(
      compact(message, signer.(message)),
      historical_key("archive-key-a", current_key),
      historical_key("archive-key-b", next_public),
      %ExpectedKeyTransition{
        transition_id: transition.transition_id,
        chain_id: transition.chain_id,
        effective_at: transition.effective_at,
        current_key_id: "archive-key-a",
        current_key_fingerprint: raw_thumbprint(current_key),
        next_key_id: "archive-key-b",
        next_key_fingerprint: raw_thumbprint(next_public),
        bounds: %{}
      }
    )
  end

  # A one-row export with no key transition: both boundary anchors are signed under the
  # same archive key, which is the only key in the historical key chain.
  defp export_surface(facade, archive_key, signer) do
    {:ok, row} =
      facade.encode_consumption_entry(
        %ConsumptionEntry{
          chain_id: "urn:example:chain",
          sequence: 1,
          previous_hash: @zero_hash,
          commitment: :crypto.hash(:sha256, "commitment-a")
        },
        %{}
      )

    chain = %ExpectedChain{
      chain_id: "urn:example:chain",
      first_sequence: 1,
      last_sequence: 1,
      row_count: 1,
      previous_hash: @zero_hash,
      last_hash: row.hash,
      bounds: %{}
    }

    fingerprint = raw_thumbprint(archive_key)
    start_anchor = anchor("urn:example:anchor:start", 1999, 0, @zero_hash)
    end_anchor = anchor("urn:example:anchor:end", 2001, 1, row.hash)
    start_expected = expected_anchor(start_anchor, fingerprint)
    end_expected = expected_anchor(end_anchor, fingerprint)

    {:ok, encoded} =
      facade.encode_anchored_export(
        %V1.AnchoredExportInput{
          rows: [row.bytes],
          start_anchor: forged_anchor(facade, start_anchor, archive_key, signer),
          transitions: [],
          end_anchor: forged_anchor(facade, end_anchor, archive_key, signer)
        },
        %ExpectedExport{
          chain: chain,
          start_anchor: start_expected,
          transitions: [],
          end_anchor: end_expected,
          bounds: %{}
        }
      )

    facade.verify_anchored_export(
      %ArchivedObject{chunks: encoded.chunks, version: "object-version-1"},
      %HistoricalKeyChain{keys: [historical_key("archive-key-a", archive_key)]},
      %ExpectedAnchoredExport{
        chain: chain,
        start_anchor: start_expected,
        transitions: [],
        end_anchor: end_expected,
        digest: encoded.digest,
        object_version: "object-version-1",
        bounds: %{}
      }
    )
  end

  defp ra1_attestor_surface(attestor_key, signer) do
    {subject_public, _subject_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, input} = RA.attestation_signing_input(attestation(subject_public), %{})
    {:ok, compact} = RA.assemble_compact(input, signer.(input.message), %{})
    RA.verify_attestation(compact, expected_attestation(attestor_key, subject_public))
  end

  # The attestor is honest; the attested subject key is the one under test.
  defp ra1_subject_surface(subject_key) do
    {attestor_public, attestor_private} = :crypto.generate_key(:eddsa, :ed25519)
    {carrier_public, _carrier_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, input} = RA.attestation_signing_input(attestation(carrier_public), %{})
    message = swap(input.message, b64(carrier_public), b64(subject_key))
    compact = honest_compact(message, attestor_private)
    RA.verify_attestation(compact, expected_attestation(attestor_public, subject_key))
  end

  defp ca1_surface(attestor_key, signer) do
    {:ok, digest} = CA.content_digest("document", %{})

    assertion =
      struct!(CA.ContentAssertion,
        attestor_key_id: "issuer-key",
        jti: "assertion-1",
        iss: "issuer",
        aud: "audience",
        sub: "lineage",
        profile: "urn:example:profile:1",
        profile_digest: :crypto.hash(:sha256, "schema"),
        content_digest: digest,
        gen: 1,
        prev: @zero_hash,
        iat: 5,
        nbf: 10,
        exp: 30
      )

    {:ok, input} = CA.assertion_signing_input(assertion, %{})
    {:ok, compact} = CA.assemble_compact(input, signer.(input.message))

    CA.verify_assertion(
      compact,
      struct!(CA.ExpectedContentAssertion,
        attestor: %HistoricalPublicKey{
          key_id: "issuer-key",
          public_key: attestor_key,
          valid_from: 5,
          valid_before: 30
        },
        issuer: "issuer",
        audience: "audience",
        subject: "lineage",
        profile: assertion.profile,
        profile_digest: assertion.profile_digest,
        content_digest: digest,
        now: 20,
        bounds: %{}
      )
    )
  end

  # --- builders --------------------------------------------------------------------------

  defp grant(grant_module, operation_module, key_id, holder_thumbprint) do
    struct!(grant_module,
      key_id: key_id,
      issuer: "https://issuer.example",
      grant_id: "g-forged",
      audiences: ["https://service.example"],
      issued_at: 1_800_000_000,
      not_before: 1_800_000_000,
      expires_at: 1_800_003_600,
      holder_thumbprint: holder_thumbprint,
      operations: [struct!(operation_module, name: "read_record", selectors: [:all])]
    )
  end

  defp anchor(anchor_id, anchored_at, sequence, chain_hash) do
    %BoundaryAnchor{
      anchor_id: anchor_id,
      anchored_at: anchored_at,
      chain_id: "urn:example:chain",
      sequence: sequence,
      chain_hash: chain_hash,
      key_id: "archive-key-a",
      public_key: nil
    }
  end

  # Produces the anchor under a carrier key, then swaps the archive key's fingerprint into
  # the payload before signing.
  defp forged_anchor(facade, anchor, archive_key, signer) do
    {carrier_public, _carrier_private} = :crypto.generate_key(:eddsa, :ed25519)

    {:ok, input} =
      facade.boundary_anchor_signing_input(%{anchor | public_key: carrier_public}, %{})

    message =
      swap(input.message, b64(raw_thumbprint(carrier_public)), b64(raw_thumbprint(archive_key)))

    compact(message, signer.(message))
  end

  defp expected_anchor(anchor, fingerprint) do
    %ExpectedAnchor{
      anchor_id: anchor.anchor_id,
      anchored_at: anchor.anchored_at,
      chain_id: anchor.chain_id,
      sequence: anchor.sequence,
      chain_hash: anchor.chain_hash,
      key_id: anchor.key_id,
      key_fingerprint: fingerprint,
      bounds: %{}
    }
  end

  defp historical_key(key_id, public_key),
    do: %HistoricalPublicKey{
      key_id: key_id,
      public_key: public_key,
      valid_from: 1000,
      valid_before: 3000
    }

  defp attestation(subject_public) do
    %RA.RoleAttestation{
      attestor_key_id: "attestor-1",
      jti: "urn:example:attestation:1",
      key_id: "holder-key-1",
      public_key: subject_public,
      role: "issuer",
      nbf: 1_735_689_600,
      exp: 1_735_693_200
    }
  end

  defp expected_attestation(attestor_public, subject_public) do
    %RA.ExpectedAttestation{
      attestor: %HistoricalPublicKey{
        key_id: "attestor-1",
        public_key: attestor_public,
        valid_from: 1_735_689_000,
        valid_before: 1_735_694_000
      },
      subject_key_id: "holder-key-1",
      subject_public_key: subject_public,
      now: 1_735_691_000,
      bounds: %{}
    }
  end

  # --- bytes -----------------------------------------------------------------------------

  # The RFC 7638 thumbprint digest computed directly from the key bytes, with no key check,
  # so a weak key's fingerprint can be placed in an artifact and an expectation.
  defp raw_thumbprint(public_key),
    do: :crypto.hash(:sha256, ~s({"crv":"Ed25519","kty":"OKP","x":"#{b64(public_key)}"}))

  # Replaces one base64url value inside the decoded protected header or payload of a JWS
  # signing input. Both values have the same length, so the JCS member order is unchanged.
  defp swap(message, from, to) do
    message
    |> String.split(".")
    |> Enum.map_join(".", fn segment ->
      decoded = Base.url_decode64!(segment, padding: false)
      b64(String.replace(decoded, from, to))
    end)
    |> tap(fn swapped -> assert swapped != message or from == to end)
  end

  defp honest_compact(message, private_key),
    do: compact(message, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519]))

  defp compact(message, signature), do: message <> "." <> b64(signature)

  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)
end

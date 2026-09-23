defmodule BoundedAuthorityProtocol.SignatureWidthErrorShapeTest do
  # A compact whose signature segment decodes to a byte length other than the suite's
  # signature width must fail with exactly {:error, :invalid} on every public decode and
  # verification surface — never a bare boolean leaked from a `with` guard. Found by the
  # role-attestation profile's ES256 confusion corpus case (a 66-byte raw ECDSA r||s
  # signature survived scan and base64url decode and reached the width guard); v3 already
  # normalizes, v1/v2 leaked `false`. Fixed by the v3-style parse wrapper (ADR 0036 landing).
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V2

  test "oversized signatures return the closed error value on every v1 and v2 surface" do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)

    {:ok, input} =
      V1.grant_signing_input(
        %Grant{
          key_id: "issuer-shape-1",
          issuer: "urn:example:issuer:shape",
          grant_id: "urn:example:grant:shape",
          audiences: ["urn:example:audience:shape"],
          issued_at: 1_735_689_600,
          not_before: 1_735_689_600,
          expires_at: 1_735_693_200,
          holder_thumbprint: <<0::256>>,
          operations: [%Operation{name: "read_record", selectors: [:all]}]
        },
        %{}
      )

    signature =
      :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])

    for oversized <- [signature <> <<0, 0>>, binary_part(signature, 0, 62)] do
      compact =
        input.protected_segment <>
          "." <>
          input.payload_segment <>
          "." <>
          Base.url_encode64(oversized, padding: false)

      assert {:error, :invalid} = V1.decode_grant(compact, %{})
      assert {:error, :invalid} = V1.decode_proof(compact, %{})
      assert {:error, :invalid} = V2.decode_grant(compact, %{})
      assert {:error, :invalid} = V2.decode_proof(compact, %{})

      assert {:error, :invalid} =
               V1.verify_grant(
                 compact,
                 %V1.TrustedIssuer{key_id: "issuer-shape-1", public_key: public},
                 %V1.ExpectedGrant{
                   issuer: "urn:example:issuer:shape",
                   audience: "urn:example:audience:shape",
                   evaluation_time: 1_735_691_000,
                   clock_skew: 60,
                   bounds: %{}
                 }
               )

      assert {:error, :invalid} =
               V2.verify_grant(
                 compact,
                 %V1.TrustedIssuer{key_id: "issuer-shape-1", public_key: public},
                 %V1.ExpectedGrant{
                   issuer: "urn:example:issuer:shape",
                   audience: "urn:example:audience:shape",
                   evaluation_time: 1_735_691_000,
                   clock_skew: 60,
                   bounds: %{}
                 }
               )
    end
  end
end

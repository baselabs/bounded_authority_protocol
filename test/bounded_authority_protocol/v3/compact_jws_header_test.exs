defmodule BoundedAuthorityProtocol.V3.CompactJwsHeaderTest do
  @moduledoc """
  Header-shape closure legs for `V3.CompactJws.assemble/3`: the per-kind exact-header
  walk's reject arms (wrong member set, wrong typ, undecodable JWK) and the unknown-kind
  fallthrough. The signing-input builders produce only conforming headers, so these arms
  are reachable only through direct assembly with hand-built segments — exactly the
  producer-side closed set the corpus pins verify-side.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V3.CompactJws

  defp input(kind, header_json) do
    seg64 = Base.url_encode64(header_json, padding: false)
    payload = Base.url_encode64(~s({"v":3}), padding: false)

    struct!(SigningInput,
      kind: kind,
      protected_segment: seg64,
      payload_segment: payload,
      message: seg64 <> "." <> payload
    )
  end

  test "grant header reject arms: wrong member values and member sets" do
    # Non-string kid (member present, wrong shape).
    bad_kid = input(:grant, ~s({"alg":"ES256","kid":3,"typ":"ba+cap"}))
    assert {:error, :invalid} = CompactJws.assemble(bad_kid, :binary.copy(<<1>>, 64), %{})

    # Wrong typ.
    bad_typ = input(:grant, ~s({"alg":"ES256","kid":"a","typ":"ba+other"}))
    assert {:error, :invalid} = CompactJws.assemble(bad_typ, :binary.copy(<<1>>, 64), %{})

    # Extra member (member set not exactly {alg,kid,typ}).
    extra = input(:grant, ~s({"alg":"ES256","kid":"a","typ":"ba+cap","x":"y"}))
    assert {:error, :invalid} = CompactJws.assemble(extra, :binary.copy(<<1>>, 64), %{})

    # Empty kid fails the byte bounds inside the matched arm.
    empty_kid = input(:grant, ~s({"alg":"ES256","kid":"","typ":"ba+cap"}))
    assert {:error, :invalid} = CompactJws.assemble(empty_kid, :binary.copy(<<1>>, 64), %{})
  end

  test "proof header reject arms: wrong members and an undecodable JWK member" do
    # The jwk member present but not an object encodable to the EC member set.
    bad_jwk = input(:proof, ~s({"alg":"ES256","jwk":"not-an-object","typ":"dpop+jwt"}))
    assert {:error, :invalid} = CompactJws.assemble(bad_jwk, :binary.copy(<<1>>, 64), %{})

    # A structurally valid JWK object with the wrong member set (missing y).
    wrong_jwk =
      input(
        :proof,
        ~s({"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"short"},"typ":"dpop+jwt"})
      )

    assert {:error, :invalid} = CompactJws.assemble(wrong_jwk, :binary.copy(<<1>>, 64), %{})

    # Wrong typ on the proof shape.
    bad_typ =
      input(
        :proof,
        ~s({"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"x","y":"y"},"typ":"ba+cap"})
      )

    assert {:error, :invalid} = CompactJws.assemble(bad_typ, :binary.copy(<<1>>, 64), %{})
  end

  test "anchor and transition header reject arms: wrong typ for the kind" do
    anchor_bad = input(:boundary_anchor, ~s({"alg":"ES256","kid":"a","typ":"ba+key-transition"}))

    assert {:error, :invalid} =
             CompactJws.assemble(anchor_bad, :binary.copy(<<1>>, 64), %{})

    transition_bad = input(:key_transition, ~s({"alg":"ES256","kid":"a","typ":"ba+chain-anchor"}))

    assert {:error, :invalid} =
             CompactJws.assemble(transition_bad, :binary.copy(<<1>>, 64), %{})
  end

  test "unknown kind and non-object header reach the closed fallthrough" do
    unknown = input(:other, ~s({"alg":"ES256","kid":"a","typ":"ba+cap"}))
    assert {:error, :invalid} = CompactJws.assemble(unknown, :binary.copy(<<1>>, 64), %{})

    non_object = input(:grant, ~s([1,2,3]))
    assert {:error, :invalid} = CompactJws.assemble(non_object, :binary.copy(<<1>>, 64), %{})
  end
end

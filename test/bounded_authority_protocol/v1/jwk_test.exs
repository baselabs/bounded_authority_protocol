defmodule BoundedAuthorityProtocol.V1.JwkTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Jwk

  @jwk ~s({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
  @thumbprint_preimage ~s({"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
  @thumbprint "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

  test "RFC 8037 public OKP JWK and RFC 7638 thumbprint are exact" do
    assert {:ok, _public_key} = Jwk.decode_public(@jwk, %{})
    assert {:ok, @thumbprint_preimage} = Jwk.thumbprint_preimage(@jwk, %{})
    assert {:ok, @thumbprint} = Jwk.thumbprint(@jwk, %{})
  end

  test "JWK member order is insignificant but the set is closed" do
    reordered =
      ~s({"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","crv":"Ed25519","kty":"OKP"})

    assert {:ok, _public_key} = Jwk.decode_public(reordered, %{})
    assert {:ok, @thumbprint} = Jwk.thumbprint(reordered, %{})

    for invalid <- [
          ~s({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"AAAA"}),
          ~s({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"hint"}),
          ~s({"kty":"EC","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}),
          ~s({"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}),
          ~s({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURp"}),
          ~s({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
        ] do
      assert {:error, :invalid} = Jwk.decode_public(invalid, %{})
    end
  end

  test "public-key production accepts exactly 32 bytes" do
    key = Base.url_decode64!("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", padding: false)

    assert {:ok, @thumbprint_preimage} = Jwk.encode_public(key, %{})
    assert {:error, :invalid} = Jwk.encode_public(binary_part(key, 0, 31), %{})
    assert {:error, :invalid} = Jwk.encode_public(key <> <<0>>, %{})
  end

  test "all malformed inputs return the fixed public error" do
    assert {:error, :invalid} = Jwk.encode_public(:not_binary, %{})
    assert {:error, :invalid} = Jwk.decode_public("", %{})
    assert {:error, :invalid} = Jwk.decode_public("[]", %{})
    assert {:error, :invalid} = Jwk.decode_public(@jwk, %{decoded_segment_bytes: 1})
    assert {:error, :invalid} = Jwk.thumbprint(123, %{})

    short_key = Base.url_encode64(:binary.copy(<<0>>, 31), padding: false)

    assert {:error, :invalid} =
             Jwk.decode_public(
               ~s({"crv":"Ed25519","kty":"OKP","x":"#{short_key}"}),
               %{}
             )
  end

  test "the unchecked thumbprint digest refuses anything but 32 bytes" do
    # Positive control: the 32-byte RFC 8032 key digests to the RFC 7638 thumbprint.
    {:ok, public_key} = Jwk.decode_public(@jwk, %{})
    assert {:ok, digest} = Jwk.thumbprint_digest_unchecked(public_key)
    assert Base.url_encode64(digest, padding: false) == @thumbprint

    for input <- [<<>>, :binary.copy(<<1>>, 31), :binary.copy(<<1>>, 33), nil, 32] do
      assert {:error, :invalid} = Jwk.thumbprint_digest_unchecked(input)
    end
  end
end

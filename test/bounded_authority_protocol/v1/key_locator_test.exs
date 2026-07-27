defmodule BoundedAuthorityProtocol.V1.KeyLocatorTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.KeyLocator

  test "returns only a closed untrusted kid hint" do
    compact = compact(~s({"typ":"ba+cap","kid":"key-1","alg":"EdDSA"}), "not-json", "!")

    assert {:ok, %KeyLocator{kid: "key-1", trust: :not_evaluated}} =
             V1.untrusted_key_locator(compact)

    refute Map.has_key?(
             Map.from_struct(elem(V1.untrusted_key_locator(compact), 1)),
             :authorization
           )
  end

  test "does not decode or interpret payload or signature segments" do
    header = ~s({"alg":"EdDSA","typ":"ba+cap","kid":"A._~-9"})

    assert {:ok, %KeyLocator{kid: "A._~-9"}} =
             V1.untrusted_key_locator(compact(header, <<0xFF>>, <<0xFF>>))
  end

  test "rejects unknown, missing, duplicate, wrong-valued, and wrong-typed header members" do
    headers = [
      ~s({"alg":"EdDSA","typ":"ba+cap"}),
      ~s({"alg":"EdDSA","typ":"ba+cap","kid":"a","x":1}),
      ~s({"alg":"EdDSA","typ":"ba+cap","kid":"a","kid":"b"}),
      ~s({"alg":"HS256","typ":"ba+cap","kid":"a"}),
      ~s({"alg":"EdDSA","typ":"JWT","kid":"a"}),
      ~s({"alg":"EdDSA","typ":"ba+cap","kid":1})
    ]

    for header <- headers do
      assert {:error, :invalid} = V1.untrusted_key_locator(compact(header))
    end
  end

  test "enforces compact, protected-segment, decoded, and kid boundaries" do
    kid = :binary.copy("a", 128)
    encoded = Base.url_encode64(~s({"alg":"EdDSA","typ":"ba+cap","kid":"#{kid}"}), padding: false)
    token = encoded <> ".."

    assert {:ok, %KeyLocator{kid: ^kid}} = V1.untrusted_key_locator(token)
    assert {:error, :invalid} = V1.untrusted_key_locator(token, %{kid_bytes: 127})

    assert {:error, :invalid} =
             V1.untrusted_key_locator(token, %{compact_bytes: byte_size(token) - 1})

    assert {:error, :invalid} =
             V1.untrusted_key_locator(token, %{encoded_segment_bytes: byte_size(encoded) - 1})

    assert {:error, :invalid} =
             V1.untrusted_key_locator(
               compact(~s({"alg":"EdDSA","typ":"ba+cap","kid":"a"}), "xx"),
               %{
                 encoded_segment_bytes: 1
               }
             )

    assert {:error, :invalid} =
             V1.untrusted_key_locator(
               compact(~s({"alg":"EdDSA","typ":"ba+cap","kid":"a"}), "", "xx"),
               %{
                 encoded_segment_bytes: 1
               }
             )

    decoded_size = byte_size(Base.url_decode64!(encoded, padding: false))

    assert {:error, :invalid} =
             V1.untrusted_key_locator(token, %{decoded_segment_bytes: decoded_size - 1})
  end

  test "rejects malformed compact shape and noncanonical protected encoding" do
    for token <- ["", ".", "..x.", "a.b", "a.b.c.d", "=.x.y", "AB.x.y"] do
      assert {:error, :invalid} = V1.untrusted_key_locator(token)
    end
  end

  test "rejects non-binary compact input and kid bytes outside the closed grammar" do
    assert {:error, :invalid} = V1.untrusted_key_locator(:not_binary)

    assert {:error, :invalid} =
             V1.untrusted_key_locator(compact(~s({"alg":"EdDSA","typ":"ba+cap","kid":"a/b"})))
  end

  defp compact(header, payload \\ "", signature \\ "") do
    Base.url_encode64(header, padding: false) <> "." <> payload <> "." <> signature
  end
end

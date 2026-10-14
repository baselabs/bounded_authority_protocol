defmodule BoundedAuthorityProtocol.Es256Test do
  @moduledoc """
  `BoundedAuthorityProtocol.Es256`: the canonical-signature rule, public-key acceptance, strict
  verification, and the producer utilities `normalize_low_s/1` and `der_to_raw/1`.

  The group order, the field prime and the curve constant are restated here from SEC 2 and
  checked by arithmetic against the RFC 6979 A.2.5 key; the DER encodings in the properties come
  from an encoder written in this file, not from the module.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.Es256

  # SEC 2 secp256r1: group order n, field prime p.
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @half_n div(@n, 2)
  @p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

  # RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field): the public key U = xG.
  @ux 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
  @uy 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
  @public_key <<4, @ux::256, @uy::256>>

  # RFC 6979 A.2.5, SHA-256: messages "sample" and "test".
  @vectors [
    {"sample", 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
     0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8},
    {"test", 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
     0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083}
  ]

  defp raw(r, s), do: <<r::unsigned-big-256, s::unsigned-big-256>>

  # Minimal DER written here, independent of the module.
  defp der(r, s) do
    body = der_int(r) <> der_int(s)
    <<0x30, byte_size(body), body::binary>>
  end

  defp der_int(value) do
    bytes = :binary.encode_unsigned(value)
    bytes = if :binary.first(bytes) >= 0x80, do: <<0>> <> bytes, else: bytes
    <<0x02, byte_size(bytes), bytes::binary>>
  end

  @b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

  defp small_x_point do
    Enum.find_value(0..1_000, fn x ->
      rhs = Integer.mod(x * x * x - 3 * x + @b, @p)
      y = pow_mod(rhs, div(@p + 1, 4))
      if Integer.mod(y * y, @p) == rhs, do: {x, y}
    end)
  end

  defp pow_mod(base, exponent),
    do: :crypto.mod_pow(base, exponent, @p) |> :binary.decode_unsigned()

  defp otp_verify(message, r, s, key),
    do: :crypto.verify(:ecdsa, :sha256, message, der(r, s), [key, :prime256v1])

  describe "RFC 6979 A.2.5 (P-256, SHA-256)" do
    test "the vectors verify under the backend, so the transcription is exact" do
      for {message, r, s} <- @vectors do
        assert otp_verify(message, r, s, @public_key), message
      end
    end

    test "the low-S vector verifies strictly; the high-S vector only after normalization" do
      [{"sample", r1, s1}, {"test", r2, s2}] = @vectors

      # "sample" carries a high s: valid ECDSA, refused by the low-S rule.
      assert s1 > @half_n
      refute Es256.canonical_signature?(raw(r1, s1))
      refute Es256.verify_strict("sample", raw(r1, s1), @public_key)
      assert {:ok, low} = Es256.normalize_low_s(raw(r1, s1))
      assert low == raw(r1, @n - s1)
      assert Es256.verify_strict("sample", low, @public_key)

      # "test" carries a low s.
      assert s2 <= @half_n
      assert Es256.canonical_signature?(raw(r2, s2))
      assert Es256.verify_strict("test", raw(r2, s2), @public_key)
      assert Es256.normalize_low_s(raw(r2, s2)) == {:ok, raw(r2, s2)}
      refute Es256.verify_strict("tesT", raw(r2, s2), @public_key)
    end

    test "every high-S twin is a valid ECDSA signature that the strict rule refuses" do
      for {message, r, s} <- @vectors do
        {low, high} = if s > @half_n, do: {@n - s, s}, else: {s, @n - s}
        assert otp_verify(message, r, high, @public_key)
        assert otp_verify(message, r, low, @public_key)
        refute Es256.verify_strict(message, raw(r, high), @public_key)
        assert Es256.verify_strict(message, raw(r, low), @public_key)
      end
    end

    test "the RFC key is acceptable" do
      assert Es256.acceptable_public_key?(@public_key)
    end
  end

  describe "canonical_signature?/1" do
    test "the scalar boundaries" do
      assert Es256.canonical_signature?(raw(1, 1))
      assert Es256.canonical_signature?(raw(@n - 1, @half_n))
      refute Es256.canonical_signature?(raw(0, 1))
      refute Es256.canonical_signature?(raw(@n, 1))
      refute Es256.canonical_signature?(raw(1, 0))
      refute Es256.canonical_signature?(raw(1, @half_n + 1))
      refute Es256.canonical_signature?(raw(1, @n))
      refute Es256.canonical_signature?(raw(2 ** 256 - 1, 1))
      refute Es256.canonical_signature?(raw(1, 2 ** 256 - 1))
    end

    test "only an exact 64-byte binary is considered" do
      refute Es256.canonical_signature?(binary_part(raw(1, 1), 0, 63))
      refute Es256.canonical_signature?(raw(1, 1) <> <<0>>)
      refute Es256.canonical_signature?(:not_binary)
    end
  end

  describe "acceptable_public_key?/1" do
    test "off-curve, out-of-field, compressed and wrong-width keys are refused" do
      refute Es256.acceptable_public_key?(<<4, @ux::256, @uy + 1::256>>)
      refute Es256.acceptable_public_key?(<<4, @ux + @p::256, @uy::256>>)
      refute Es256.acceptable_public_key?(<<4, @ux::256, @uy + @p::256>>)
      refute Es256.acceptable_public_key?(<<2, @ux::256, @uy::256>>)
      refute Es256.acceptable_public_key?(<<2, @ux::256>>)
      refute Es256.acceptable_public_key?(binary_part(@public_key, 0, 64))
      refute Es256.acceptable_public_key?(:not_binary)
      # (0, sqrt(b)) does not exist and (0, 0) is not on the curve.
      refute Es256.acceptable_public_key?(<<4, 0::512>>)
    end

    test "an x at or above p is refused even when its residue is on the curve" do
      # The smallest x with a curve point; p = 3 (mod 4), so y = rhs^((p + 1) / 4).
      {x, y} = small_x_point()
      assert x + @p < 2 ** 256
      assert Es256.acceptable_public_key?(<<4, x::256, y::256>>)
      refute Es256.acceptable_public_key?(<<4, x + @p::256, y::256>>)
    end
  end

  describe "verify_strict/3" do
    test "never raises and refuses non-binary input" do
      [_sample, {"test", r, s}] = @vectors
      refute Es256.verify_strict(:not_binary, raw(r, s), @public_key)
      refute Es256.verify_strict("test", :not_binary, @public_key)
      refute Es256.verify_strict("test", raw(r, s), :not_binary)
      refute Es256.verify_strict("test", raw(r, s), <<4, @ux::256, @uy + 1::256>>)
    end
  end

  describe "normalize_low_s/1" do
    test "the boundaries" do
      assert Es256.normalize_low_s(raw(1, @half_n)) == {:ok, raw(1, @half_n)}
      assert Es256.normalize_low_s(raw(1, @half_n + 1)) == {:ok, raw(1, @n - @half_n - 1)}
      assert Es256.normalize_low_s(raw(@n - 1, @n - 1)) == {:ok, raw(@n - 1, 1)}
      assert Es256.normalize_low_s(raw(0, 1)) == {:error, :invalid}
      assert Es256.normalize_low_s(raw(@n, 1)) == {:error, :invalid}
      assert Es256.normalize_low_s(raw(1, 0)) == {:error, :invalid}
      assert Es256.normalize_low_s(raw(1, @n)) == {:error, :invalid}
      assert Es256.normalize_low_s(raw(1, 2 ** 256 - 1)) == {:error, :invalid}
      assert Es256.normalize_low_s(binary_part(raw(1, 1), 0, 63)) == {:error, :invalid}
      assert Es256.normalize_low_s(:not_binary) == {:error, :invalid}
    end
  end

  describe "der_to_raw/1" do
    test "the RFC vectors convert exactly and are not normalized" do
      for {_message, r, s} <- @vectors do
        assert Es256.der_to_raw(der(r, s)) == {:ok, raw(r, s)}
      end
    end

    test "the smallest and largest in-range scalars" do
      assert Es256.der_to_raw(der(1, 1)) == {:ok, raw(1, 1)}
      assert Es256.der_to_raw(der(@n - 1, @n - 1)) == {:ok, raw(@n - 1, @n - 1)}
      assert Es256.der_to_raw(der(0x7F, 0x80)) == {:ok, raw(0x7F, 0x80)}
    end

    test "malleable and malformed encodings are refused" do
      [_sample, {"test", r, s}] = @vectors
      good = der(r, s)
      <<0x30, len, body::binary>> = good
      r_int = der_int(r)
      s_int = der_int(s)

      cases = %{
        # A leading 00 where the next byte's high bit is clear (non-minimal).
        "non-minimal leading zero" =>
          seq(
            <<0x02, byte_size(r_int) - 1, 0,
              binary_part(r_int, 2, byte_size(r_int) - 2)::binary>>,
            s_int
          ),
        "padded with two zeros" => seq(int_bytes(<<0, 0, 0x01>>), s_int),
        "a leading 00 before a small value" => seq(int_bytes(<<0, 0x7F>>), s_int),
        # A high-bit first byte with no 00 guard is a negative INTEGER.
        "negative r" => seq(int_bytes(<<0x80, 1>>), s_int),
        "negative s" => seq(r_int, int_bytes(<<0xFF>>)),
        "long-form sequence length" => <<0x30, 0x81, len, body::binary>>,
        "long-form integer length" =>
          seq(
            <<0x02, 0x81, byte_size(r_int) - 2,
              binary_part(r_int, 2, byte_size(r_int) - 2)::binary>>,
            s_int
          ),
        "trailing garbage after the sequence" => good <> <<0>>,
        "trailing bytes inside the sequence" => seq(r_int, s_int <> <<0x02, 1, 1>>),
        "sequence length too short" => <<0x30, len - 1, body::binary>>,
        "sequence length too long" => <<0x30, len + 1, body::binary>>,
        "integer length overrunning" => seq(<<0x02, 0x40>> <> binary_part(r_int, 2, 32), s_int),
        "missing s" => seq(r_int, <<>>),
        "wrong outer tag" => <<0x31, len, body::binary>>,
        "wrong integer tag" =>
          seq(<<0x03>> <> binary_part(r_int, 1, byte_size(r_int) - 1), s_int),
        "zero-length integer" => seq(<<0x02, 0>>, s_int),
        "r = 0" => der(0, s),
        "s = 0" => der(r, 0),
        "r = n" => der(@n, s),
        "s = n" => der(r, @n),
        "s = 2^256 - 1" => der(r, 2 ** 256 - 1),
        "a 33-byte value without a guard" =>
          seq(int_bytes(<<1>> <> :binary.copy(<<0>>, 32)), s_int),
        "empty" => <<>>,
        "not binary" => :not_binary
      }

      for {label, encoding} <- cases do
        assert Es256.der_to_raw(encoding) == {:error, :invalid}, label
      end
    end
  end

  defp seq(r_int, s_int) do
    body = r_int <> s_int
    <<0x30, byte_size(body), body::binary>>
  end

  defp int_bytes(content), do: <<0x02, byte_size(content), content::binary>>

  describe "laws" do
    defp scalar, do: StreamData.integer(1..(@n - 1))

    property "normalize_low_s is idempotent and its output is canonical" do
      check all(r <- scalar(), s <- scalar(), max_runs: 300) do
        assert {:ok, once} = Es256.normalize_low_s(raw(r, s))
        assert Es256.normalize_low_s(once) == {:ok, once}
        assert Es256.canonical_signature?(once)
        assert once == raw(r, min(s, @n - s))
      end
    end

    property "der_to_raw inverts minimal DER for every in-range r and s" do
      check all(r <- scalar(), s <- scalar(), max_runs: 300) do
        assert Es256.der_to_raw(der(r, s)) == {:ok, raw(r, s)}
      end
    end

    property "verify_strict agrees with the backend on honest low-S signatures" do
      check all(secret <- scalar(), message <- StreamData.binary(), max_runs: 50) do
        {public_key, _private} = :crypto.generate_key(:ecdh, :prime256v1, <<secret::256>>)
        der_signature = :crypto.sign(:ecdsa, :sha256, message, [<<secret::256>>, :prime256v1])

        assert {:ok, signature} = Es256.der_to_raw(der_signature)
        assert {:ok, low} = Es256.normalize_low_s(signature)
        assert Es256.acceptable_public_key?(public_key)

        <<r::256, s::256>> = low
        assert otp_verify(message, r, s, public_key)
        assert Es256.verify_strict(message, low, public_key)

        # The high twin verifies under the backend and is refused strictly.
        assert otp_verify(message, r, @n - s, public_key)
        refute Es256.verify_strict(message, raw(r, @n - s), public_key)
      end
    end
  end
end

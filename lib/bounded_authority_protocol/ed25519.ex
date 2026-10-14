defmodule BoundedAuthorityProtocol.Ed25519 do
  @moduledoc """
  Strict Ed25519 verification and public-key acceptance (rule S1).

  This module is the single owner of the Ed25519 point and scalar rules for every Ed25519
  surface of the protocol. It is pure: no clock, randomness, process state, or I/O.

  ## Rule S1

  `verify_strict/3` accepts a signature `R || S` over a message under a public key `A` only if
  all of the following hold, checked in this order before any backend call:

    1. the key is exactly 32 bytes and the signature exactly 64 bytes;
    2. `A` and `R` are canonical encodings: the encoded `y` is below `p = 2^255 - 19`, and the
       sign bit is clear whenever `x = 0` (RFC 8032 §5.1.3);
    3. neither `A` nor `R` is one of the eight small-order encodings (one shared table serves
       both);
    4. `S < L`, the prime order of the base point (RFC 8032 §5.1.7);
    5. the cofactorless equation `encode([S]B - [k]A) == R` holds byte for byte, computed by the
       `:crypto` backend.

  Curve membership of `A` is left to the backend at verification; it rejects off-curve keys.
  There is no subgroup check at verification: a key with a small torsion component passes
  S1 if its signature satisfies the cofactorless equation. Hosts close that gap once per key
  with `torsion_free?/1`.

  ## Key acceptance

  `acceptable_public_key?/1` is the check for a key entering any verification input: canonical,
  not small-order, and on the curve (the RFC 8032 §5.1.3 decoding succeeds).

  `torsion_free?/1` additionally requires `[L]A = O`. It costs a full scalar multiplication
  (about 0.45 ms) and is meant for hosts at key enrollment, trust install, and before any
  deny-list or revocation comparison; it never runs on the verification path. A canonical,
  torsion-free key has exactly one encoding per secret, so key equality is identity equality.

  A `true` result proves only that the bytes satisfy the rule. It never selects trusted keys or
  grants authority.
  """

  # The field prime p = 2^255 - 19; the base-point order
  # L = 2^252 + 27742317777372353535851937790883648493; the curve constant
  # d = -121665/121666 mod p; and sqrt(-1) = 2^((p - 1) / 4) mod p.
  @p 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
  @l 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
  @d 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
  @sqrt_m1 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0
  @p_minus_one @p - 1
  @sign_bit 0x8000000000000000000000000000000000000000000000000000000000000000

  # The eight small-order encodings (the points of E[8]), in canonical form. One table serves
  # both the key A and the signature's R.
  @small_order [
    # order 1 (identity)
    <<0x0100000000000000000000000000000000000000000000000000000000000000::256>>,
    # order 2
    <<0xECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F::256>>,
    # order 4
    <<0x0000000000000000000000000000000000000000000000000000000000000000::256>>,
    <<0x0000000000000000000000000000000000000000000000000000000000000080::256>>,
    # order 8
    <<0x26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05::256>>,
    <<0x26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85::256>>,
    <<0xC7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A::256>>,
    <<0xC7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA::256>>
  ]

  @doc """
  Verifies an Ed25519 signature under rule S1.

  Returns `true` only for a 64-byte signature and a 32-byte key that pass the canonical,
  small-order and scalar-range checks and then the cofactorless equation. Any other input,
  including non-binary or wrong-size input, returns `false`; the function never raises.
  """
  @spec verify_strict(binary(), binary(), binary()) :: boolean()
  def verify_strict(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and byte_size(signature) == 64 and
             is_binary(public_key) and byte_size(public_key) == 32 do
    strict_gate?(signature, public_key) and
      :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  def verify_strict(_message, _signature, _public_key), do: false

  @doc """
  Returns whether a raw 32-byte Ed25519 public key may enter a verification input.

  The key must be canonical, must not be one of the eight small-order encodings, and must
  decode to a point on the curve. Any other input returns `false`.
  """
  @spec acceptable_public_key?(binary()) :: boolean()
  def acceptable_public_key?(<<_::binary-size(32)>> = public_key) do
    canonical?(public_key) and not small_order?(public_key) and
      match?({:ok, _point}, decode_point(public_key))
  end

  def acceptable_public_key?(_public_key), do: false

  @doc """
  Returns whether a raw 32-byte Ed25519 public key is acceptable and torsion free (`[L]A = O`).

  A host calls this at key enrollment, at trust install, and before any deny-list or
  revocation comparison. It runs one full scalar multiplication in pure integer arithmetic
  (about 0.45 ms), so it never belongs on the per-signature verification path.
  """
  @spec torsion_free?(binary()) :: boolean()
  def torsion_free?(<<_::binary-size(32)>> = public_key) do
    canonical?(public_key) and not small_order?(public_key) and
      prime_order_point?(decode_point(public_key))
  end

  def torsion_free?(_public_key), do: false

  # The byte-level part of rule S1 (clauses 2 to 4), separate from the backend so that each
  # clause stays testable on its own: a cofactorless backend already refuses a non-canonical R
  # and S >= L, so only a direct test of the gate can show those two clauses are present.
  @doc false
  @spec strict_gate?(binary(), binary()) :: boolean()
  def strict_gate?(<<_::binary-size(64)>> = signature, <<_::binary-size(32)>> = a) do
    canonical?(a) and not small_order?(a) and signature_gate?(signature)
  end

  def strict_gate?(_signature, _public_key), do: false

  # The keyless part of rule S1, the signature clauses alone: R canonical, R not of small order,
  # and S < L. The verify gate above calls it, and every Ed25519 producer surface (compact
  # assembly and anchored-export encoding, erratum 3) refuses a signature that fails it, so one
  # function owns the clauses. It does not decode R, so the producer surfaces accept exactly the
  # signatures whose clauses the verify gate accepts.
  @doc false
  @spec signature_gate?(binary()) :: boolean()
  def signature_gate?(<<r::binary-size(32), s::little-size(256)>>) do
    canonical?(r) and not small_order?(r) and s < @l
  end

  def signature_gate?(_signature), do: false

  # Canonical: y < p, and the sign bit is clear on the two x = 0 points (y = 1 and y = p - 1).
  defp canonical?(<<v::little-size(256)>>) do
    y = rem(v, @sign_bit)
    y < @p and (v < @sign_bit or nonzero_x?(y))
  end

  defp nonzero_x?(1), do: false
  defp nonzero_x?(@p_minus_one), do: false
  defp nonzero_x?(_y), do: true

  # One clause per encoding: `in` over a list of binaries compiles to :lists.member/2 on
  # Elixir before 1.20, which the compiled-purity gate does not admit.
  for encoding <- @small_order do
    defp small_order?(unquote(encoding)), do: true
  end

  defp small_order?(_encoding), do: false

  defp prime_order_point?({:ok, point}), do: identity?(multiply(@l, point))
  defp prime_order_point?(:error), do: false

  # RFC 8032 §5.1.3 decoding of a canonical encoding: x^2 = (y^2 - 1) / (d y^2 + 1), with the
  # candidate root x = u v^3 (u v^7)^((p - 5) / 8).
  defp decode_point(<<v::little-size(256)>>) do
    y = rem(v, @sign_bit)
    u = field(y * y - 1)
    w = field(@d * y * y + 1)
    w3 = field(field(w * w) * w)
    w7 = field(field(w3 * w3) * w)
    candidate = field(u * w3 * pow_p58(field(u * w7)))

    x =
      cond do
        field(w * candidate * candidate - u) == 0 -> candidate
        field(w * candidate * candidate + u) == 0 -> field(candidate * @sqrt_m1)
        true -> :none
      end

    point(x, y, v >= @sign_bit)
  end

  defp point(:none, _y, _signed?), do: :error

  defp point(x, y, signed?) do
    odd? = rem(x, 2) == 1
    x = if odd? == signed?, do: x, else: field(-x)
    {:ok, {x, y, 1, field(x * y)}}
  end

  # Extended twisted Edwards coordinates (X:Y:Z:T), a = -1 (RFC 8032 §5.1.4).
  defp add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    y_minus_x = field((y1 - x1) * (y2 - x2))
    y_plus_x = field((y1 + x1) * (y2 + x2))
    t_term = field(2 * @d * t1 * t2)
    z_term = field(2 * z1 * z2)
    e = y_plus_x - y_minus_x
    f = z_term - t_term
    g = z_term + t_term
    h = y_plus_x + y_minus_x
    {field(e * f), field(g * h), field(f * g), field(e * h)}
  end

  defp double({x1, y1, z1, _t1}) do
    a = field(x1 * x1)
    b = field(y1 * y1)
    c = field(2 * z1 * z1)
    h = a + b
    e = field(h - (x1 + y1) * (x1 + y1))
    g = a - b
    f = c + g
    {field(e * f), field(g * h), field(f * g), field(e * h)}
  end

  defp multiply(scalar, point), do: multiply(scalar, point, {0, 1, 1, 0})

  defp multiply(0, _point, acc), do: acc

  defp multiply(scalar, point, acc) do
    acc = if rem(scalar, 2) == 1, do: add(acc, point), else: acc
    multiply(div(scalar, 2), double(point), acc)
  end

  defp identity?({x, y, z, _t}), do: x == 0 and y == z

  # z^((p - 5) / 8) = z^(2^252 - 3) by a fixed addition chain: 251 squarings and 11
  # multiplications.
  defp pow_p58(z) do
    z2 = field(z * z)
    z9 = field(square(z2, 2) * z)
    z11 = field(z9 * z2)
    z_5_0 = field(field(z11 * z11) * z9)
    z_10_0 = field(square(z_5_0, 5) * z_5_0)
    z_20_0 = field(square(z_10_0, 10) * z_10_0)
    z_40_0 = field(square(z_20_0, 20) * z_20_0)
    z_50_0 = field(square(z_40_0, 10) * z_10_0)
    z_100_0 = field(square(z_50_0, 50) * z_50_0)
    z_200_0 = field(square(z_100_0, 100) * z_100_0)
    z_250_0 = field(square(z_200_0, 50) * z_50_0)
    field(square(z_250_0, 2) * z)
  end

  defp square(value, 0), do: value
  defp square(value, count), do: square(field(value * value), count - 1)

  defp field(value) do
    case rem(value, @p) do
      residue when residue < 0 -> residue + @p
      residue -> residue
    end
  end
end

defmodule BoundedAuthorityProtocol.TestSupport.Ed25519Reference.Field do
  @moduledoc false

  # Square-and-multiply modular exponentiation over plain integers, so the reference's
  # constants (d, sqrt(-1), B) are computed rather than pasted.

  import Bitwise

  def pow_mod(base, exponent, modulus),
    do: pow_mod(Integer.mod(base, modulus), exponent, modulus, 1)

  defp pow_mod(_base, 0, _modulus, acc), do: acc

  defp pow_mod(base, exponent, modulus, acc) do
    acc = if (exponent &&& 1) == 1, do: rem(acc * base, modulus), else: acc
    pow_mod(rem(base * base, modulus), exponent >>> 1, modulus, acc)
  end
end

defmodule BoundedAuthorityProtocol.TestSupport.Ed25519Reference do
  @moduledoc false

  # Independent pure-integer Ed25519 reference for tests only (RFC 8032 §5.1).
  #
  # It shares no code and no table with `BoundedAuthorityProtocol.Ed25519`:
  #
  #   * points are decoded by the RFC 8032 §5.1.3 square-root recipe and compared in extended
  #     twisted Edwards coordinates (§5.1.4), never by encoding bytes;
  #   * "small order" means [8]P = O and "torsion free" means [L]P = O, both computed by
  #     scalar multiplication;
  #   * the eight small-order points are derived as the multiples of an order-8 point found by
  #     arithmetic, never copied from a list;
  #   * the S1 verdict is RFC 8032 strict decoding of A and R, the [8]P = O order test on both,
  #     S < L, and the cofactorless equation encode([S]B - [k]A) == R, with no crypto backend.
  #
  # Everything is plain integer arithmetic; only SHA-512 comes from :crypto.

  import Bitwise

  @p (1 <<< 255) - 19
  @l (1 <<< 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493

  @doc "The field prime 2^255 - 19."
  def p, do: @p

  @doc "The prime order L of the base point."
  def l, do: @l

  # --- field ---------------------------------------------------------------------------------

  alias BoundedAuthorityProtocol.TestSupport.Ed25519Reference.Field

  # d = -121665 / 121666 and sqrt(-1) = 2^((p - 1) / 4), computed at compile time, not pasted.
  @d Integer.mod(-121_665 * Field.pow_mod(121_666, @p - 2, @p), @p)
  @sqrt_m1 Field.pow_mod(2, div(@p - 1, 4), @p)

  defp f(a), do: Integer.mod(a, @p)
  defp pow_mod(base, exponent), do: Field.pow_mod(base, exponent, @p)
  defp inv(a), do: pow_mod(a, @p - 2)
  defp d, do: @d
  defp sqrt_m1, do: @sqrt_m1

  # --- points (extended coordinates X:Y:Z:T, a = -1) -----------------------------------------

  @doc "The neutral element."
  def identity, do: {0, 1, 1, 0}

  @doc "The RFC 8032 base point B (y = 4/5, x even)."
  def base do
    {:ok, point} = decode(<<f(4 * inv(5))::little-size(256)>>)
    point
  end

  @doc "Point addition (RFC 8032 §5.1.4); the formula is complete, so it also doubles."
  def add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    a = f((y1 - x1) * (y2 - x2))
    b = f((y1 + x1) * (y2 + x2))
    c = f(2 * t1 * t2 * d())
    dd = f(2 * z1 * z2)
    {e, ff, g, h} = {b - a, dd - c, dd + c, b + a}
    {f(e * ff), f(g * h), f(ff * g), f(e * h)}
  end

  @doc "Point negation."
  def neg({x, y, z, t}), do: {f(-x), y, z, f(-t)}

  @doc "Scalar multiplication [k]P by double-and-add."
  def mul(k, point) when k >= 0, do: mul(k, point, identity())

  defp mul(0, _point, acc), do: acc

  defp mul(k, point, acc) do
    acc = if (k &&& 1) == 1, do: add(acc, point), else: acc
    mul(k >>> 1, add(point, point), acc)
  end

  @doc "Projective equality."
  def eq?({x1, y1, z1, _}, {x2, y2, z2, _}),
    do: f(x1 * z2 - x2 * z1) == 0 and f(y1 * z2 - y2 * z1) == 0

  @doc "[8]P = O."
  def small_order?(point), do: eq?(mul(8, point), identity())

  @doc "[L]P = O."
  def torsion_free?(point), do: eq?(mul(@l, point), identity())

  @doc "Encodes a point (RFC 8032 §5.1.2)."
  def encode({x, y, z, _}) do
    zi = inv(z)
    xa = f(x * zi)
    ya = f(y * zi)
    <<ya + ((xa &&& 1) <<< 255)::little-size(256)>>
  end

  @doc """
  Decodes 32 bytes. `:strict` is RFC 8032 §5.1.3 (y < p; x = 0 with the sign bit fails).
  `:lenient` is the permissive ref10 shape (y reduced mod p; x = 0 with the sign bit accepted),
  used only to classify non-canonical encodings.
  """
  def decode(bytes, mode \\ :strict)

  def decode(<<v::little-size(256)>>, mode) do
    sign = v >>> 255
    y = v &&& (1 <<< 255) - 1

    if y >= @p and mode == :strict, do: :error, else: recover(f(y), sign, mode)
  end

  def decode(_bytes, _mode), do: :error

  defp recover(y, sign, mode) do
    x2 = f((y * y - 1) * inv(d() * y * y + 1))

    cond do
      x2 == 0 and sign == 1 and mode == :strict -> :error
      x2 == 0 -> {:ok, {0, y, 1, 0}}
      true -> square_root(x2) |> signed_point(y, sign)
    end
  end

  # RFC 8032 §5.1.3 step 3: x = x2^((p + 3) / 8), times sqrt(-1) when needed.
  defp square_root(x2) do
    x = pow_mod(x2, div(@p + 3, 8))
    x = if f(x * x - x2) == 0, do: x, else: f(x * sqrt_m1())
    if f(x * x - x2) == 0, do: {:ok, x}, else: :error
  end

  defp signed_point(:error, _y, _sign), do: :error

  defp signed_point({:ok, x}, y, sign) do
    x = if (x &&& 1) == sign, do: x, else: @p - x
    {:ok, {x, y, 1, f(x * y)}}
  end

  # --- E[8] and the encoding census ----------------------------------------------------------

  @doc """
  The eight points of E[8] as [i]T for i in 0..7, where T is an order-8 point obtained as
  [L]P for the first decodable P whose [L]P has order exactly 8.
  """
  def torsion_points do
    t = find_order8(2)
    for i <- 0..7, do: mul(i, t)
  end

  defp find_order8(y) do
    with {:ok, point} <- decode(<<y::little-size(256)>>),
         t = mul(@l, point),
         false <- eq?(mul(4, t), identity()) do
      t
    else
      _ -> find_order8(y + 1)
    end
  end

  @doc """
  Every non-canonical 32-byte encoding: y in [p, 2^255) with either sign bit (19 x 2), plus the
  two x = 0 encodings carrying the sign bit (y = 1 and y = p - 1).
  """
  def non_canonical_encodings do
    high =
      for y <- @p..((1 <<< 255) - 1)//1, sign <- [0, 1] do
        <<y + (sign <<< 255)::little-size(256)>>
      end

    high ++ [<<1 + (1 <<< 255)::little-size(256)>>, <<@p - 1 + (1 <<< 255)::little-size(256)>>]
  end

  # --- signing (RFC 8032 §5.1.5 and §5.1.6) --------------------------------------------------

  @doc "SHA-512 of the concatenation, as a little-endian integer."
  def sha512_int(parts) do
    <<v::little-size(512)>> = :crypto.hash(:sha512, parts)
    v
  end

  @doc "Expands a 32-byte seed to the clamped scalar a and the nonce prefix."
  def secret_expand(<<_::binary-size(32)>> = seed) do
    <<head::little-size(256), prefix::binary-size(32)>> = :crypto.hash(:sha512, seed)
    a = (head &&& (1 <<< 254) - 8) ||| 1 <<< 254
    {a, prefix}
  end

  @doc "Public key encoding for a seed."
  def public_key(seed) do
    {a, _prefix} = secret_expand(seed)
    encode(mul(a, base()))
  end

  @doc "The challenge k = SHA-512(R || A || M) mod L."
  def challenge(r_bytes, a_bytes, message),
    do: rem(sha512_int([r_bytes, a_bytes, message]), @l)

  @doc "S as 32 little-endian bytes."
  def scalar_bytes(s), do: <<s::little-size(256)>>

  # --- S1 reference verdicts -----------------------------------------------------------------

  @doc """
  The S1 verdict by arithmetic only: strict-decode A and R, reject [8]P = O for either,
  require S < L, then the cofactorless equation encode([S]B - [k]A) == R byte for byte.
  """
  def verify_s1(message, signature, public_key)
      when is_binary(message) and byte_size(signature) == 64 and byte_size(public_key) == 32 do
    <<r_bytes::binary-size(32), s::little-size(256)>> = signature

    with {:ok, a} <- decode(public_key),
         {:ok, r} <- decode(r_bytes),
         false <- small_order?(a),
         false <- small_order?(r),
         true <- s < @l do
      k = challenge(r_bytes, public_key, message)
      encode(add(mul(s, base()), neg(mul(k, a)))) == r_bytes
    else
      _ -> false
    end
  end

  def verify_s1(_message, _signature, _public_key), do: false

  @doc "Key acceptance by arithmetic: strict decode succeeds and [8]A != O."
  def acceptable?(public_key) do
    case decode(public_key) do
      {:ok, a} -> not small_order?(a)
      :error -> false
    end
  end

  @doc "Torsion freedom by arithmetic: acceptable and [L]A = O."
  def torsion_free_key?(public_key) do
    case decode(public_key) do
      {:ok, a} -> not small_order?(a) and torsion_free?(a)
      :error -> false
    end
  end
end

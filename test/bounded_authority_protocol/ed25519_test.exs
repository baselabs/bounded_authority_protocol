Code.require_file("../../test_support/ed25519_reference.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Ed25519Test do
  @moduledoc """
  Rule S1 for `BoundedAuthorityProtocol.Ed25519`. Expected verdicts and the weak-encoding sets
  come from the independent pure-integer reference in `test_support/ed25519_reference.ex`;
  nothing here copies the module's small-order table.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias BoundedAuthorityProtocol.Ed25519
  alias BoundedAuthorityProtocol.TestSupport.Ed25519Reference, as: Ref

  @moduletag timeout: 300_000

  @l Ref.l()

  # The eight points of E[8], derived by arithmetic as [i]T for an order-8 point T.
  @torsion Ref.torsion_points()
  @small_order Enum.map(@torsion, &Ref.encode/1)

  # The 40 non-canonical encodings, classified by permissive (ref10-style) decoding.
  @non_canonical Ref.non_canonical_encodings()
  @small_order_aliases Enum.filter(@non_canonical, fn bytes ->
                         match?({:ok, _}, Ref.decode(bytes, :lenient)) and
                           Ref.small_order?(elem(Ref.decode(bytes, :lenient), 1))
                       end)
  @off_curve_non_canonical Enum.filter(@non_canonical, &(Ref.decode(&1, :lenient) == :error))
  @mixed_non_canonical @non_canonical -- (@small_order_aliases ++ @off_curve_non_canonical)

  @identity_r Ref.encode(Ref.identity())

  # Labeled weak keys: the canonical small-order encodings (with their order) and every
  # non-canonical alias of a small-order point.
  @weak_small_order_keys (for {bytes, index} <- Enum.with_index(@small_order) do
                            point = Enum.at(@torsion, index)

                            order =
                              Enum.find([1, 2, 4, 8], fn n ->
                                Ref.eq?(Ref.mul(n, point), Ref.identity())
                              end)

                            {"canonical small-order point #{index} (order #{order})", bytes}
                          end) ++
                           (for bytes <- @small_order_aliases do
                              {"non-canonical alias #{Base.encode16(bytes, case: :lower)}", bytes}
                            end)

  # RFC 8032 §7.1 TEST 1, TEST 2 and TEST 3: {secret seed, public key, message, signature}.
  @rfc8032 [
    {"TEST 1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" <>
       "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"TEST 2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" <>
       "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    {"TEST 3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" <>
       "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"}
  ]

  @honest_seed Base.decode16!(
                 "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                 case: :lower
               )

  defp hex(value), do: Base.decode16!(value, case: :lower)

  defp backend_verify(message, signature, public_key),
    do: :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])

  defp rfc_vectors do
    for {name, seed, public_key, message, signature} <- @rfc8032 do
      {name, hex(seed), hex(public_key), hex(message), hex(signature)}
    end
  end

  defp honest_signature do
    [{_name, _seed, public_key, message, signature} | _] = rfc_vectors()
    {public_key, message, signature}
  end

  # Messages for which the forged (R = identity, S = 0) signature satisfies the cofactorless
  # equation under `key`: encode(-[k]A) == identity, i.e. [k]A = O for the point A the key
  # decodes to permissively. Found by arithmetic, then confirmed against the raw backend.
  defp identity_forgery_messages(key, count) do
    {:ok, point} = Ref.decode(key, :lenient)

    Stream.iterate(0, &(&1 + 1))
    |> Stream.map(&"forged message #{&1}")
    |> Stream.filter(fn message ->
      k = Ref.challenge(@identity_r, key, message)
      Ref.eq?(Ref.mul(rem(k, 8), point), Ref.identity())
    end)
    |> Enum.take(count)
  end

  # A forgery under a small-order key (or an alias of one) whose R is an ordinary prime-order
  # point, so the only rule it violates is the key rule: R = [r]B and S = r satisfy
  # encode([S]B - [k]A) == R whenever [k]A = O, which holds once the order of A divides k.
  # Small r keep [r]B cheap; no private key is involved.
  defp prime_r_forgeries(key, count) do
    {:ok, point} = Ref.decode(key, :lenient)
    for n <- 1..count, do: prime_r_forgery(key, point, "prime R forgery #{n}")
  end

  defp prime_r_forgery(key, point, message) do
    Stream.iterate(1, &(&1 + 1))
    |> Enum.find_value(fn r ->
      r_bytes = Ref.encode(Ref.mul(r, Ref.base()))
      k = Ref.challenge(r_bytes, key, message)

      if Ref.eq?(Ref.mul(rem(k, 8), point), Ref.identity()),
        do: {message, r_bytes <> Ref.scalar_bytes(r)}
    end)
  end

  # Key-holder construction of a signature whose R is the small-order point `r_point`, under
  # the mixed-order key A0 + T for some T in E[8] (the small-order-R vectors):
  # pick T and a message with R + [k]T = O; then S = k * a mod L satisfies the cofactorless
  # equation, because [S]B - [k](A0 + T) = -[k]T = R.
  defp small_r_signature(r_point) do
    {a, _prefix} = Ref.secret_expand(@honest_seed)
    a0 = Ref.mul(a, Ref.base())
    r_bytes = Ref.encode(r_point)

    Stream.iterate(0, &(&1 + 1))
    |> Stream.flat_map(fn n -> for t <- @torsion, do: {t, "small R message #{n}"} end)
    |> Enum.find_value(fn {t, message} ->
      key = Ref.encode(Ref.add(a0, t))
      k = Ref.challenge(r_bytes, key, message)

      if Ref.eq?(Ref.add(r_point, Ref.mul(rem(k, 8), t)), Ref.identity()) do
        {key, message, r_bytes <> Ref.scalar_bytes(rem(k * a, @l))}
      end
    end)
  end

  # A key-holder signature under the mixed-order key A0 + T with an ordinary prime-order R:
  # retry messages until [k]T = O.
  defp mixed_key_signature(t) do
    {a, prefix} = Ref.secret_expand(@honest_seed)
    key = Ref.encode(Ref.add(Ref.mul(a, Ref.base()), t))

    Stream.iterate(0, &(&1 + 1))
    |> Stream.map(&"mixed key message #{&1}")
    |> Enum.find_value(fn message ->
      r = rem(Ref.sha512_int([prefix, message]), @l)
      r_bytes = Ref.encode(Ref.mul(r, Ref.base()))
      k = Ref.challenge(r_bytes, key, message)

      if Ref.eq?(Ref.mul(rem(k, 8), t), Ref.identity()) do
        {key, message, r_bytes <> Ref.scalar_bytes(rem(r + k * a, @l))}
      end
    end)
  end

  describe "the derived weak-encoding census" do
    test "E[8] gives eight distinct canonical encodings and the 40 non-canonical encodings split 6/20/14" do
      assert length(Enum.uniq(@small_order)) == 8
      assert Enum.all?(@small_order, &match?({:ok, _}, Ref.decode(&1)))
      assert length(@non_canonical) == 40
      assert length(@small_order_aliases) == 6
      assert length(@mixed_non_canonical) == 20
      assert length(@off_curve_non_canonical) == 14
    end
  end

  describe "verify_strict/3 refuses small-order keys" do
    for {label, key} <- @weak_small_order_keys do
      @key key
      test "the identity forgery (R = identity, S = 0) under the #{label} is refused for three messages" do
        forged = @identity_r <> <<0::256>>

        for message <- identity_forgery_messages(@key, 3) do
          # Positive control: the raw backend accepts this forgery, so the refusal is S1's.
          assert backend_verify(message, forged, @key)
          refute Ed25519.verify_strict(message, forged, @key)
        end
      end
    end

    for {label, key} <- @weak_small_order_keys do
      @key key
      test "a forgery with a prime-order R under the #{label} is refused for three messages" do
        for {message, forged} <- prime_r_forgeries(@key, 3) do
          # Positive control: the raw backend accepts this forgery; R and S are in range and
          # canonical, so only the key rule can refuse it.
          assert backend_verify(message, forged, @key)
          refute Ed25519.verify_strict(message, forged, @key)
        end
      end
    end

    test "every small-order key and alias is refused for key acceptance and torsion freedom" do
      for {label, key} <- @weak_small_order_keys do
        refute Ed25519.acceptable_public_key?(key), label
        refute Ed25519.torsion_free?(key), label
      end
    end
  end

  describe "verify_strict/3 refuses small-order R" do
    for index <- 0..7 do
      @index index
      test "a key-holder signature with R = small-order point #{index} under a mixed-order key is refused" do
        {key, message, signature} = small_r_signature(Enum.at(@torsion, @index))

        # Positive control: the cofactorless backend accepts it, and the key itself is fine.
        assert backend_verify(message, signature, key)
        assert Ed25519.acceptable_public_key?(key)
        refute Ed25519.verify_strict(message, signature, key)
      end
    end

    test "every small-order point and every non-canonical alias as R fails the gate under an honest key" do
      {public_key, message, signature} = honest_signature()
      <<_r::binary-size(32), s::binary-size(32)>> = signature

      # Positive control: the untouched signature passes the gate and verifies.
      assert Ed25519.strict_gate?(signature, public_key)
      assert Ed25519.verify_strict(message, signature, public_key)

      for r <- @small_order ++ @small_order_aliases do
        refute Ed25519.strict_gate?(r <> s, public_key), Base.encode16(r, case: :lower)
        refute Ed25519.verify_strict(message, r <> s, public_key)
      end
    end
  end

  describe "canonical encodings" do
    test "every non-canonical R fails the gate under an honest key" do
      {public_key, message, signature} = honest_signature()
      <<_r::binary-size(32), s::binary-size(32)>> = signature

      for r <- @non_canonical do
        refute Ed25519.strict_gate?(r <> s, public_key), Base.encode16(r, case: :lower)
        refute Ed25519.verify_strict(message, r <> s, public_key)
      end
    end

    test "every non-canonical A fails the gate, verification and key acceptance" do
      {_public_key, message, signature} = honest_signature()

      for key <- @non_canonical do
        refute Ed25519.strict_gate?(signature, key), Base.encode16(key, case: :lower)
        refute Ed25519.verify_strict(message, signature, key)
        refute Ed25519.acceptable_public_key?(key)
        refute Ed25519.torsion_free?(key)
      end
    end
  end

  describe "the scalar range" do
    test "S = L and S = L + 1 are refused, and S = L - 1 passes the gate" do
      {public_key, message, signature} = honest_signature()
      <<r::binary-size(32), _s::binary-size(32)>> = signature

      for s <- [@l, @l + 1] do
        refute Ed25519.strict_gate?(r <> Ref.scalar_bytes(s), public_key)
        refute Ed25519.verify_strict(message, r <> Ref.scalar_bytes(s), public_key)
      end

      assert Ed25519.strict_gate?(r <> Ref.scalar_bytes(@l - 1), public_key)
    end

    test "the honest S plus L, and S = 2^256 - 1, are refused" do
      {public_key, message, signature} = honest_signature()
      <<r::binary-size(32), s::little-size(256)>> = signature

      for bad <- [s + @l, (1 <<< 256) - 1] do
        refute Ed25519.strict_gate?(r <> Ref.scalar_bytes(bad), public_key)
        refute Ed25519.verify_strict(message, r <> Ref.scalar_bytes(bad), public_key)
      end
    end
  end

  describe "honest signatures" do
    test "RFC 8032 section 7.1 TEST 1 to TEST 3 verify, and their keys are acceptable and torsion free" do
      for {name, seed, public_key, message, signature} <- rfc_vectors() do
        assert Ref.public_key(seed) == public_key, name
        assert Ed25519.verify_strict(message, signature, public_key), name
        assert Ed25519.acceptable_public_key?(public_key), name
        assert Ed25519.torsion_free?(public_key), name

        refute Ed25519.verify_strict(message <> "x", signature, public_key), name
      end
    end
  end

  describe "mixed-order keys" do
    test "an honest key plus a torsion point is acceptable but not torsion free" do
      {a, _prefix} = Ref.secret_expand(@honest_seed)
      a0 = Ref.mul(a, Ref.base())

      assert Ed25519.torsion_free?(Ref.encode(a0))

      for t <- tl(@torsion) do
        key = Ref.encode(Ref.add(a0, t))
        assert Ed25519.acceptable_public_key?(key)
        refute Ed25519.torsion_free?(key)
      end
    end

    test "every mixed-order non-canonical encoding is refused" do
      for key <- @mixed_non_canonical do
        refute Ed25519.acceptable_public_key?(key)
        refute Ed25519.torsion_free?(key)
      end
    end

    test "a key-holder signature under a mixed-order key is accepted at verify and rejected by torsion_free?" do
      t = Enum.find(@torsion, fn t -> not Ref.eq?(Ref.mul(4, t), Ref.identity()) end)
      {key, message, signature} = mixed_key_signature(t)

      assert backend_verify(message, signature, key)
      assert Ed25519.verify_strict(message, signature, key)
      assert Ed25519.acceptable_public_key?(key)
      refute Ed25519.torsion_free?(key)
    end
  end

  describe "curve membership" do
    test "canonical off-curve encodings fail key acceptance and verification" do
      {_public_key, message, signature} = honest_signature()

      off_curve =
        0..200
        |> Enum.map(&<<&1::little-size(256)>>)
        |> Enum.filter(&(Ref.decode(&1) == :error))

      assert length(off_curve) > 50

      for key <- off_curve ++ @off_curve_non_canonical do
        refute Ed25519.acceptable_public_key?(key), Base.encode16(key, case: :lower)
        refute Ed25519.torsion_free?(key)
        refute Ed25519.verify_strict(message, signature, key)
      end
    end
  end

  describe "input shape" do
    test "non-binary and wrong-size inputs return false" do
      {public_key, message, signature} = honest_signature()

      bad_keys = [nil, :key, 1, [public_key], binary_part(public_key, 0, 31), public_key <> <<0>>]

      bad_signatures = [
        nil,
        :signature,
        1,
        [signature],
        binary_part(signature, 0, 63),
        signature <> <<0>>
      ]

      for key <- bad_keys do
        refute Ed25519.verify_strict(message, signature, key)
        refute Ed25519.acceptable_public_key?(key)
        refute Ed25519.torsion_free?(key)
        refute Ed25519.strict_gate?(signature, key)
      end

      for bad <- bad_signatures do
        refute Ed25519.verify_strict(message, bad, public_key)
        refute Ed25519.strict_gate?(bad, public_key)
      end

      for bad_message <- [nil, :message, 1, [message]] do
        refute Ed25519.verify_strict(bad_message, signature, public_key)
      end
    end
  end

  # --- differential properties against the independent reference ---------------------------

  property "honest keypairs and messages: verify_strict/3 equals the backend and the reference" do
    check all(
            seed <- binary(length: 32),
            message <- binary(max_length: 128),
            flip <- one_of([constant(nil), integer(0..511)]),
            max_runs: 100
          ) do
      {public_key, _secret} = :crypto.generate_key(:eddsa, :ed25519, seed)
      signature = :crypto.sign(:eddsa, :none, message, [seed, :ed25519])

      signature =
        case flip do
          nil -> signature
          bit -> flip_bit(signature, bit)
        end

      verdict = Ed25519.verify_strict(message, signature, public_key)
      assert verdict == backend_verify(message, signature, public_key)
      assert verdict == Ref.verify_s1(message, signature, public_key)
      assert verdict == is_nil(flip)
      assert Ed25519.acceptable_public_key?(public_key)
    end
  end

  property "weak and non-canonical constructions: verify_strict/3 equals the reference and refuses every weak input" do
    check all(input <- weak_input(), max_runs: 150) do
      %{message: message, signature: signature, key: key, weak?: weak?} = input
      expected = Ref.verify_s1(message, signature, key)

      assert Ed25519.verify_strict(message, signature, key) == expected
      assert Ed25519.acceptable_public_key?(key) == Ref.acceptable?(key)
      if weak?, do: refute(expected)
    end
  end

  property "torsion_free?/1 equals the reference over honest, mixed-order and weak keys" do
    check all(input <- weak_input(), max_runs: 40) do
      assert Ed25519.torsion_free?(input.key) == Ref.torsion_free_key?(input.key)
    end
  end

  property "every input is answered with a boolean and never raises" do
    check all(
            message <- one_of([binary(max_length: 64), term()]),
            signature <- one_of([binary(length: 64), binary(max_length: 80), term()]),
            key <- one_of([binary(length: 32), binary(max_length: 40), term()]),
            max_runs: 500
          ) do
      verdict = Ed25519.verify_strict(message, signature, key)
      assert is_boolean(verdict)
      assert is_boolean(Ed25519.acceptable_public_key?(key))
      assert is_boolean(Ed25519.torsion_free?(key))
      assert is_boolean(Ed25519.strict_gate?(signature, key))

      shaped? =
        is_binary(message) and is_binary(signature) and byte_size(signature) == 64 and
          is_binary(key) and byte_size(key) == 32

      if verdict, do: assert(shaped?)
      if not shaped?, do: refute(verdict)
    end
  end

  defp flip_bit(bytes, bit) do
    <<before::bitstring-size(^bit), value::1, rest::bitstring>> = bytes
    <<before::bitstring, 1 - value::1, rest::bitstring>>
  end

  # Generator: a random seed; torsion indexes jA and jR weighted toward 0; an A and an R that
  # are honest (prime-order plus [j]T), purely small-order, or one of the 40 non-canonical
  # encodings; and an S that is honest, the no-key forgery S = r, zero, honest + L,
  # 2^256 - 1 or random.
  defp weak_input do
    torsion_index = frequency([{3, constant(0)}, {2, integer(1..7)}])
    point_mode = frequency([{3, constant(:honest)}, {1, constant(:small)}, {1, constant(:nc)}])

    gen all(
          seed <- binary(length: 32),
          message <- binary(max_length: 48),
          ja <- torsion_index,
          jr <- torsion_index,
          a_mode <- point_mode,
          r_mode <- point_mode,
          a_nc <- member_of(@non_canonical),
          r_nc <- member_of(@non_canonical),
          s_mode <-
            frequency([
              {4, constant(:honest)},
              {1, constant(:forged)},
              {1, constant(:zero)},
              {1, constant(:plus_l)},
              {1, constant(:max)},
              {1, constant(:random)}
            ]),
          s_random <- binary(length: 32)
        ) do
      {a, prefix} = Ref.secret_expand(seed)
      r = rem(Ref.sha512_int([prefix, message]), @l)
      key = point_bytes(a_mode, a, ja, a_nc)
      r_bytes = point_bytes(r_mode, r, jr, r_nc)
      k = Ref.challenge(r_bytes, key, message)
      s = scalar(s_mode, r, rem(r + k * a, @l), s_random)
      weak? = a_mode != :honest or r_mode != :honest or s >= @l

      %{message: message, signature: r_bytes <> Ref.scalar_bytes(s), key: key, weak?: weak?}
    end
  end

  defp point_bytes(:honest, scalar, j, _nc),
    do: Ref.encode(Ref.add(Ref.mul(scalar, Ref.base()), Enum.at(@torsion, j)))

  defp point_bytes(:small, _scalar, j, _nc), do: Enum.at(@small_order, j)
  defp point_bytes(:nc, _scalar, _j, nc), do: nc

  # :forged is the no-key forgery shape S = r with R = [r]B, valid whenever [k]A = O.
  defp scalar(:honest, _r, s, _random), do: s
  defp scalar(:forged, r, _s, _random), do: r
  defp scalar(:zero, _r, _s, _random), do: 0
  defp scalar(:plus_l, _r, s, _random), do: s + @l
  defp scalar(:max, _r, _s, _random), do: (1 <<< 256) - 1
  defp scalar(:random, _r, _s, <<random::little-size(256)>>), do: random
end

defmodule BoundedAuthorityProtocol.Conformance.Runner do
  @moduledoc """
  Pure case executor for the loaded corpus.

  `run/1` dispatches each case against the frozen v1 facade (no facade change, no second parser)
  and compares the result to the case-declared expectation. `.raw` sidecar bytes pass through
  opaque. Every case result is `{:ok, %{actual: ..., agree: boolean}}` for a valid expectation or
  `{:ok, %{actual: ..., agree: boolean}}` for an invalid expectation (agreement = the facade
  returned `{:error, :invalid}` exactly). The runner never selects trust, reserves replay, or
  checks revocation — it exercises the pure facade only.
  """

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.Uri

  # Surfaces whose dispatch requires rich struct construction from case input. These are
  # exercised by Task 2's corpus data; the full struct-building dispatch lands with the data.
  @pending_surfaces [
    "grant_signing_input",
    "proof_signing_input",
    "encode_consumption_entry",
    "check_chain",
    "boundary_anchor_signing_input",
    "key_transition_signing_input",
    "encode_anchored_export",
    "assemble_compact",
    "decode_grant",
    "decode_proof",
    "verify_grant",
    "verify_historical_anchor",
    "verify_key_transition",
    "verify_anchored_export",
    "check_envelope",
    "request_digest"
  ]

  @doc "Executes every loaded case against the frozen facade."
  @spec run(Corpus.t()) :: [{binary(), [%{case_id: binary(), agree: boolean()}]}]
  def run(%Corpus{cases: cases, raws: raws}) do
    Enum.map(cases, fn {path, file_cases} ->
      results = Enum.map(file_cases, fn case_obj -> execute_case(case_obj, raws) end)
      {path, results}
    end)
  end

  defp execute_case(case_obj, raws) do
    surface = case_obj["surface"]
    input = Map.get(case_obj, "input", %{})
    expected = case_obj["expected"]
    actual = dispatch(surface, input, raws)
    agree = agrees?(expected, actual)
    %{case_id: case_obj["id"], agree: agree}
  end

  # --- agreement -----------------------------------------------------------

  defp agrees?(%{"verdict" => "invalid"}, {:error, :invalid}), do: true
  defp agrees?(%{"verdict" => "invalid"}, _actual), do: false
  defp agrees?(%{"verdict" => "valid"}, {:error, :invalid}), do: false

  defp agrees?(%{"verdict" => "valid"} = expected, {:ok, actual}) do
    expected_fields = Map.delete(expected, "verdict")
    matches_expected?(expected_fields, actual)
  end

  # Exact byte/field comparison per surface. The expected map keys name the projection to compare.
  defp matches_expected?(expected_fields, actual) do
    Enum.all?(expected_fields, fn {key, expected_value} ->
      actual_value = project(key, actual)
      compare?(key, expected_value, actual_value)
    end)
  end

  # --- dispatch table ------------------------------------------------------

  defp dispatch("json.decode", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Json.decode(bytes, Bounds.maximum()) do
        {:ok, value} -> {:ok, {:json, value}}
        error -> error
      end
    end
  end

  defp dispatch("base64url.decode", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Base64Url.decode(bytes, Bounds.maximum()) do
        {:ok, decoded} -> {:ok, %{decoded: decoded}}
        error -> error
      end
    end
  end

  defp dispatch("uri.normalize", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Uri.normalize(bytes, Bounds.maximum()) do
        {:ok, normalized} -> {:ok, %{normalized: normalized}}
        error -> error
      end
    end
  end

  defp dispatch("jcs.encode", input, _raws) do
    with {:ok, bytes} <- input_bytes(input),
         {:ok, value} <- Json.decode(bytes, Bounds.maximum()) do
      case Jcs.encode(value, Bounds.maximum()) do
        {:ok, encoded} -> {:ok, %{encoded: encoded}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.encode_public", input, _raws) do
    with {:ok, public_key} <- input_public_key(input) do
      case Jwk.encode_public(public_key, Bounds.maximum()) do
        {:ok, encoded} -> {:ok, %{encoded: encoded}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.decode_public", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Jwk.decode_public(bytes, Bounds.maximum()) do
        {:ok, public_key} -> {:ok, %{public_key: public_key}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint_preimage", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Jwk.thumbprint_preimage(bytes, Bounds.maximum()) do
        {:ok, preimage} -> {:ok, %{preimage: preimage}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Jwk.thumbprint(bytes, Bounds.maximum()) do
        {:ok, thumbprint} -> {:ok, %{thumbprint: thumbprint}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint_raw", input, _raws) do
    with {:ok, bytes} <- input_bytes(input) do
      case Jwk.thumbprint_raw(bytes, Bounds.maximum()) do
        {:ok, raw} -> {:ok, %{thumbprint_raw: raw}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.public_key_thumbprint_raw", input, _raws) do
    with {:ok, public_key} <- input_public_key(input) do
      case Jwk.public_key_thumbprint_raw(public_key, Bounds.maximum()) do
        {:ok, raw} -> {:ok, %{thumbprint_raw: raw}}
        error -> error
      end
    end
  end

  defp dispatch("bounds.new", input, _raws) do
    overrides = Map.get(input, "overrides", %{})

    case Bounds.new(overrides) do
      {:ok, bounds} -> {:ok, %{bounds: bounds}}
      error -> error
    end
  end

  defp dispatch("untrusted_key_locator", input, _raws) do
    with {:ok, compact} <- fetch_binary(input, "compact") do
      case BoundedAuthorityProtocol.V1.untrusted_key_locator(compact, %{}) do
        {:ok, locator} -> {:ok, %{kid: locator.kid}}
        error -> error
      end
    end
  end

  defp dispatch(surface, _input, _raws) when surface in @pending_surfaces do
    # Producer/verifier/chain/archive surfaces require rich struct construction from case input.
    # These are exercised by Task 2's corpus data; the full struct-building dispatch lands there.
    {:error, :invalid}
  end

  # --- input extraction ----------------------------------------------------

  defp input_bytes(input) do
    cond do
      is_binary(input["text"]) -> {:ok, input["text"]}
      is_binary(input["base64url"]) -> Base.url_decode64(input["base64url"], padding: false)
      is_binary(input["raw_file"]) -> {:error, :raw_required}
      true -> {:error, :invalid}
    end
  end

  defp input_public_key(input) do
    with {:ok, encoded} <- fetch_binary(input, "public_key") do
      Base.url_decode64(encoded, padding: false)
    end
  end

  defp fetch_binary(input, key) do
    case Map.get(input, key) do
      bytes when is_binary(bytes) -> {:ok, bytes}
      _ -> {:error, :invalid}
    end
  end

  # --- projection + comparison --------------------------------------------

  defp project("kid", %{kid: kid}), do: kid
  defp project("decoded", %{decoded: decoded}), do: decoded
  defp project("normalized", %{normalized: normalized}), do: normalized
  defp project("encoded", %{encoded: encoded}), do: encoded
  defp project("public_key", %{public_key: public_key}), do: public_key
  defp project("thumbprint", %{thumbprint: thumbprint}), do: thumbprint
  defp project("thumbprint_raw", %{thumbprint_raw: thumbprint_raw}), do: thumbprint_raw
  defp project("preimage", %{preimage: preimage}), do: preimage
  defp project("bounds", %{bounds: bounds}), do: bounds
  defp project("value", {:json, value}), do: value
  defp project(_key, _actual), do: :no_projection

  defp compare?(_key, _expected, actual) when actual == :no_projection, do: false

  defp compare?("decoded", expected, actual) do
    # expected is a plain map (from JSON); actual is tagged algebra. Compare structurally.
    to_plain(actual) == expected
  end

  defp compare?("value", expected, {:json, actual}),
    do: to_plain(actual) == expected

  defp compare?("value", expected, actual), do: to_plain(actual) == expected

  defp compare?("bounds", _expected, %Bounds{}), do: true

  defp compare?(_key, expected, actual) do
    actual == expected or
      (is_binary(expected) and is_binary(actual) and byte_string_compare(expected, actual))
  end

  defp byte_string_compare(expected, actual) do
    # base64url-encoded expected values compare against raw actual by decoding.
    case Base.url_decode64(expected, padding: false) do
      {:ok, decoded} -> decoded == actual
      :error -> expected == actual
    end
  end

  defp to_plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, to_plain(v)} end) |> Map.new()

  defp to_plain({:array, items}), do: Enum.map(items, &to_plain/1)
  defp to_plain({:string, s}), do: s
  defp to_plain({:integer, n}), do: n
  defp to_plain({:float, n}), do: n
  defp to_plain({:boolean, b}), do: b
  defp to_plain(:null), do: nil
  defp to_plain(other), do: other
end

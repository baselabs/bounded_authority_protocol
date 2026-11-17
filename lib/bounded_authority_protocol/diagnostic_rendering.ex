defmodule BoundedAuthorityProtocol.DiagnosticRendering do
  @moduledoc false

  # spec/diagnostic-rendering.md §§ Structural rendering and Scalar rendering.
  # The budget is returned by every recursive call, including nested containers.
  @container_budget 200
  @printable_limit 4096
  @grant_fields ~w(version key_id issuer grant_id audiences issued_at not_before expires_at
                   holder_thumbprint operations verification)a
  @attestation_fields ~w(version attestor_key_id jti key_id public_key role nbf exp verification)a
  @proof_fields ~w(version proof_id method target_uri issued_at nonce invocation_id operation
                   grant_hash request_hash holder_public_key holder_thumbprint verification)a

  @doc false
  @spec render(term()) :: binary()
  def render(value) do
    {document, _remaining} = term(value, @container_budget)
    :erlang.iolist_to_binary(document)
  end

  defp term(%{__struct__: module} = value, budget)
       when module in [
              BoundedAuthorityProtocol.V1.DecodedGrant,
              BoundedAuthorityProtocol.V2.DecodedGrant,
              BoundedAuthorityProtocol.V3.DecodedGrant
            ],
       do: structure(value, module, @grant_fields, budget)

  defp term(%{__struct__: module} = value, budget)
       when module in [
              BoundedAuthorityProtocol.V1.Operation,
              BoundedAuthorityProtocol.V2.Operation,
              BoundedAuthorityProtocol.V3.Operation
            ],
       do: structure(value, module, [:name, :selectors], budget)

  defp term(%BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation{} = value, budget),
    do:
      structure(
        value,
        BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation,
        @attestation_fields,
        budget
      )

  defp term(%{__struct__: module} = value, budget)
       when module in [
              BoundedAuthorityProtocol.V1.DecodedProof,
              BoundedAuthorityProtocol.V2.DecodedProof,
              BoundedAuthorityProtocol.V3.DecodedProof
            ] do
    case field_values(value, @proof_fields) do
      {:ok, fields} ->
        <<"Elixir.", name::binary>> = Atom.to_string(module)
        {["#", name, "<", proof_fields(fields), ">"], budget}

      :error ->
        {"#unrenderable", budget}
    end
  end

  defp term(value, budget) when is_list(value) do
    if proper_list?(value) do
      mode = if keyword?(value), do: :fields, else: :values
      {document, remaining} = entries(value, budget, mode)
      {["[", document, "]"], remaining}
    else
      {"#unrenderable", budget}
    end
  end

  defp term(value, budget) when is_tuple(value) do
    {document, remaining} = entries(Tuple.to_list(value), budget, :values)
    {["{", document, "}"], remaining}
  end

  defp term(value, budget) when is_binary(value) do
    if printable?(value, @printable_limit) do
      {quoted(value, @printable_limit), budget}
    else
      {document, remaining} = entries(:binary.bin_to_list(value), budget, :values)
      {["<<", document, ">>"], remaining}
    end
  end

  defp term(nil, budget), do: {"nil", budget}
  defp term(true, budget), do: {"true", budget}
  defp term(false, budget), do: {"false", budget}

  defp term(value, budget) when is_atom(value) do
    name = Atom.to_string(value)
    document = if identifier?(name), do: [":", name], else: "#unrenderable"
    {document, budget}
  end

  defp term(value, budget) when is_integer(value), do: {Integer.to_string(value), budget}

  defp term(value, budget) when is_float(value) do
    {:erlang.float_to_binary(value, [:short]), budget}
  end

  defp term(_value, budget), do: {"#unrenderable", budget}

  defp structure(value, module, keys, budget) do
    case field_values(value, keys) do
      {:ok, fields} ->
        <<"Elixir.", name::binary>> = Atom.to_string(module)
        {document, remaining} = entries(fields, budget, :fields)
        {["%", name, "{", document, "}"], remaining}

      :error ->
        {"#unrenderable", budget}
    end
  end

  defp field_values(_value, []), do: {:ok, []}

  defp field_values(value, [key | keys]) do
    case value do
      %{^key => field} ->
        case field_values(value, keys) do
          {:ok, fields} -> {:ok, [{key, field} | fields]}
          :error -> :error
        end

      _value ->
        :error
    end
  end

  defp proper_list?([]), do: true
  defp proper_list?([_value | rest]), do: proper_list?(rest)
  defp proper_list?(_value), do: false

  defp keyword?([]), do: true

  defp keyword?([{key, _value} | rest]) when is_atom(key),
    do: identifier?(Atom.to_string(key)) and keyword?(rest)

  defp keyword?(_value), do: false

  defp identifier?(<<first, rest::binary>>) when first in ?a..?z or first == ?_,
    do: identifier_tail?(rest)

  defp identifier?(_name), do: false
  defp identifier_tail?(<<>>), do: true
  defp identifier_tail?(<<suffix>>) when suffix in [??, ?!], do: true

  defp identifier_tail?(<<character, rest::binary>>)
       when character in ?a..?z or character in ?A..?Z or character in ?0..?9 or character == ?_,
       do: identifier_tail?(rest)

  defp identifier_tail?(_name), do: false

  # Fixed-form proofs have always rendered each visible field independently.
  # Replace a present nonce before rendering, including malformed present values.
  defp proof_fields([]), do: []

  defp proof_fields([{key, field} | fields]) do
    field = if key == :nonce and field != nil, do: :redacted, else: field
    separator = if fields == [], do: [], else: ", "
    [Atom.to_string(key), ": ", render(field), separator, proof_fields(fields)]
  end

  defp entries([], budget, _mode), do: {[], budget}
  defp entries(_values, 0, _mode), do: {"...", 0}

  defp entries([value | rest], budget, mode) do
    {document, remaining} = entry(value, budget - 1, mode)
    {tail, remaining} = entries(rest, remaining, mode)
    separator = if rest == [], do: [], else: ", "
    {[document, separator, tail], remaining}
  end

  defp entry({key, value}, budget, :fields) do
    {document, remaining} = term(value, budget)
    {[Atom.to_string(key), ": ", document], remaining}
  end

  defp entry(value, budget, :values), do: term(value, budget)

  defp printable?(<<>>, _limit), do: true
  defp printable?(_value, 0), do: true

  defp printable?(<<codepoint::utf8, rest::binary>>, limit)
       when codepoint in 7..13 or codepoint == 27 or codepoint in 0x20..0x7F or
              codepoint in 0xA0..0xD7FF or codepoint in 0xE000..0xFFFD or
              codepoint in 0x10000..0x10FFFF,
       do: printable?(rest, limit - 1)

  defp printable?(_value, _limit), do: false

  defp quoted(value, limit) do
    {document, rest} = escape(value, limit)
    suffix = if rest == <<>>, do: [], else: " <> ..."
    ["\"", document, "\"", suffix]
  end

  defp escape(<<>>, _limit), do: {[], <<>>}
  defp escape(value, 0), do: {[], value}

  # Escaping the two-character interpolation introducer consumes one printable unit.
  defp escape(<<35, 123, rest::binary>>, limit) do
    {document, rest} = escape(rest, limit - 1)
    {["\\", <<35, 123>>, document], rest}
  end

  defp escape(<<codepoint::utf8, rest::binary>>, limit) do
    {document, rest} = escape(rest, limit - 1)
    {[escape_codepoint(codepoint), document], rest}
  end

  defp escape(<<byte, rest::binary>>, limit) do
    {document, rest} = escape(rest, limit - 1)
    {["\\x", hex(byte, 2), document], rest}
  end

  defp escape_codepoint(0), do: "\\0"
  defp escape_codepoint(7), do: "\\a"
  defp escape_codepoint(8), do: "\\b"
  defp escape_codepoint(9), do: "\\t"
  defp escape_codepoint(10), do: "\\n"
  defp escape_codepoint(11), do: "\\v"
  defp escape_codepoint(12), do: "\\f"
  defp escape_codepoint(13), do: "\\r"
  defp escape_codepoint(27), do: "\\e"
  defp escape_codepoint(34), do: "\\\""
  defp escape_codepoint(92), do: "\\\\"
  defp escape_codepoint(127), do: "\\d"

  defp escape_codepoint(codepoint)
       when codepoint in [0xA0, 0x34F, 0x61C, 0xFEFF] or codepoint in 0x2000..0x200F or
              codepoint in 0x2028..0x202E or codepoint in 0x205F..0x2064 or
              codepoint in 0x2066..0x2069 or codepoint in 0xFFF9..0xFFFC do
    ["\\u", hex(codepoint, 4)]
  end

  defp escape_codepoint(codepoint)
       when codepoint in 0x20..0x7E or codepoint in 0xA0..0xD7FF or
              codepoint in 0xE000..0xFFFD or codepoint in 0x10000..0x10FFFF,
       do: <<codepoint::utf8>>

  defp escape_codepoint(codepoint) when codepoint < 0x100, do: ["\\x", hex(codepoint, 2)]
  defp escape_codepoint(codepoint), do: ["\\x{", hex(codepoint, 4), "}"]

  defp hex(value, width), do: String.pad_leading(Integer.to_string(value, 16), width, "0")
end

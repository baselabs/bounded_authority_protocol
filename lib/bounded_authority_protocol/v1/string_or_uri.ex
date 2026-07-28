defmodule BoundedAuthorityProtocol.V1.StringOrUri do
  @moduledoc false

  @uri_punctuation ~c"-._~:/?#[]@!$&'()*+,;="

  @spec valid?(binary()) :: boolean()
  def valid?(value) when is_binary(value) do
    String.valid?(value) and valid_string?(value)
  end

  def valid?(_value), do: false

  defp valid_string?(value) do
    case :binary.split(value, <<":">>) do
      [_plain] -> true
      [scheme, _rest] -> valid_scheme?(scheme) and valid_uri?(value)
    end
  end

  defp valid_uri?(value) do
    match?({:ok, %URI{scheme: scheme}} when is_binary(scheme), URI.new(value)) and
      uri_bytes?(value)
  end

  defp valid_scheme?(<<first, rest::binary>>) when first in ?A..?Z or first in ?a..?z,
    do: scheme_rest?(rest)

  defp valid_scheme?(_scheme), do: false

  defp scheme_rest?(<<>>), do: true

  defp scheme_rest?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?+, ?-, ?.],
       do: scheme_rest?(rest)

  defp scheme_rest?(_rest), do: false

  defp uri_bytes?(<<>>), do: true

  defp uri_bytes?(<<?%, first, second, rest::binary>>) do
    hexadecimal?(first) and hexadecimal?(second) and uri_bytes?(rest)
  end

  defp uri_bytes?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in @uri_punctuation,
       do: uri_bytes?(rest)

  defp uri_bytes?(_rest), do: false

  defp hexadecimal?(byte),
    do: byte in ?0..?9 or byte in ?A..?F or byte in ?a..?f
end

defmodule BoundedAuthorityProtocol.ApiExamplesTest do
  use ExUnit.Case, async: false

  @modules [
    BoundedAuthorityProtocol.V1,
    BoundedAuthorityProtocol.V2,
    BoundedAuthorityProtocol.V3,
    BoundedAuthorityProtocol.V1.Json,
    BoundedAuthorityProtocol.V1.Jcs,
    BoundedAuthorityProtocol.V1.Base64Url,
    BoundedAuthorityProtocol.V1.Bounds,
    BoundedAuthorityProtocol.V1.Uri,
    BoundedAuthorityProtocol.V1.Jwk,
    BoundedAuthorityProtocol.V3.EcJwk,
    BoundedAuthorityProtocol.Ed25519,
    BoundedAuthorityProtocol.Es256,
    BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1,
    BoundedAuthorityProtocol.RoleAttestation.V1,
    BoundedAuthorityProtocol.ContentAssertion.V1,
    BoundedAuthorityProtocol.Conformance.Cli
  ]

  for module <- @modules do
    doctest module
  end

  test "every visible public function has an executed native reference example" do
    {:ok, modules} = :application.get_key(:bounded_authority_protocol, :modules)

    missing =
      for module <- modules,
          {:docs_v1, _, _, _, moduledoc, _, entries} = Code.fetch_docs(module),
          is_map(moduledoc),
          {{:function, name, arity}, _, _, documentation, _} <- entries,
          documentation != :hidden,
          not (module in @modules and example?(documentation)),
          do: {module, name, arity}

    assert missing == [], "Public functions without executed examples: #{inspect(missing)}"
  end

  defp example?(%{"en" => text}), do: String.contains?(text, "iex>")
  defp example?(_), do: false
end

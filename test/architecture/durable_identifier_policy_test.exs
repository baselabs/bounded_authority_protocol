Code.require_file("../../test_support/durable_identifier_policy.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Architecture.DurableIdentifierPolicyTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Test.DurableIdentifierPolicy

  test "enumerated package and wire identities are accepted" do
    for fixture <- [
          %{path: "lib/bounded_authority_protocol/v1.ex", kind: :path, name: "v1"},
          %{
            path: "lib/bounded_authority_protocol/v1/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V1.Grant"
          },
          %{path: "docs/protocol-v1.md", kind: :path, name: "protocol-v1"},
          %{
            path: "mix.exs",
            kind: :package_source_ref,
            name: ~s(source_ref: "v\#{@version}")
          },
          %{path: "docs/protocol-v1.md", kind: :wire_suite, name: "BAP1-Ed25519-SHA256"},
          %{
            path: "lib/bounded_authority_protocol/v1/grant.ex",
            kind: :wire_domain,
            name: "BAP1-GRANT"
          },
          %{
            path: "docs/protocol-v1.md",
            kind: :requirement_id,
            name: "REQ1-HEADER-issuer-fingerprint"
          },
          %{path: "priv/conformance/v1/corpus/index.json", kind: :wire_field, name: ~s("v": 1)},
          %{
            path: "lib/bounded_authority_protocol/application_profile/local_loopback_http/v1.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1"
          },
          %{
            path: "priv/conformance/application-profiles/local-loopback-http/v1/index.json",
            kind: :path,
            name: "v1"
          }
        ] do
      assert :ok = DurableIdentifierPolicy.check(fixture)
    end
  end

  test "implementation genealogy and unaccepted contract majors are rejected" do
    for fixture <- [
          %{path: "lib/bounded_authority_protocol/v2.ex", kind: :path, name: "v2"},
          %{
            path: "lib/bounded_authority_protocol/v2/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V2.Grant"
          },
          %{
            path: "lib/bounded_authority_protocol/v1/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V10.Grant"
          },
          %{path: "lib/bounded_authority_protocol/worker.ex", kind: :function, name: "decode_v2"},
          %{path: "docs/protocol-v2.md", kind: :path, name: "protocol-v2"},
          %{path: "docs/protocol-v1.md", kind: :wire_domain, name: "BAP2-GRANT"},
          %{path: "docs/example.md", kind: :wire_domain, name: "BAP1-GRANT"},
          %{
            path: "lib/bounded_authority_protocol/example.ex",
            kind: :external_wire_module,
            name: "BoundedAuthorityProtocol.V1"
          },
          %{
            path: "docs/protocol-v1.md",
            kind: :requirement_id,
            name: "REQ1-UNKNOWN-example"
          },
          %{
            path: "docs/protocol-v1.md",
            kind: :requirement_id,
            name: "REQ1-HEADER-task-" <> "4"
          },
          %{
            path: "docs/example.md",
            kind: :package_source_ref,
            name: ~s(source_ref: "v\#{@version}")
          },
          %{
            path: "lib/bounded_authority_protocol/application_profile/local_loopback_http/v2.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V2"
          }
        ] do
      assert {:error, :implementation_lifecycle_identifier} =
               DurableIdentifierPolicy.check(fixture)
    end
  end

  test "the tracked product tree contains no unaccepted lifecycle identifiers" do
    assert DurableIdentifierPolicy.owned_tree_findings() == []
  end

  test "the tracked scanner observes every contract family and quoted atoms" do
    observations = DurableIdentifierPolicy.contract_observations()

    for kind <- [
          :package_source_ref,
          :wire_suite,
          :wire_domain,
          :wire_field,
          :requirement_id,
          :module
        ] do
      assert Enum.any?(observations, &(&1.kind == kind)), "missing observed #{kind}"
    end

    assert {:error, :implementation_lifecycle_identifier} =
             DurableIdentifierPolicy.check_source("lib/example.ex", ~S(def x, do: :"queue-v2"))
  end

  test "the independent requirement fixture exactly covers the normative map" do
    fixture_ids =
      "test/fixtures/durable_identifier_requirements.txt"
      |> File.read!()
      |> String.split()
      |> MapSet.new()

    map_ids =
      "docs/design/requirement-map.md"
      |> File.read!()
      |> then(&Regex.scan(~r/\bREQ1-[A-Z0-9]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\b/, &1))
      |> Enum.map(fn [name] -> name end)
      |> MapSet.new()

    assert map_ids == fixture_ids
  end
end

Code.require_file("../../test_support/durable_identifier_policy.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Architecture.DurableIdentifierPolicyTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.TestSupport.DurableIdentifierPolicy

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
          },
          %{path: "lib/bounded_authority_protocol/v2.ex", kind: :path, name: "v2"},
          %{
            path: "lib/bounded_authority_protocol/v2/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V2.Grant"
          },
          %{path: "spec/bap-v2.md", kind: :path, name: "bap-v2"},
          %{path: "docs/protocol-v1.md", kind: :wire_suite, name: "BAP2-Ed25519-SHA256"},
          %{
            path: "lib/bounded_authority_protocol/v2/consumption_chain.ex",
            kind: :wire_domain,
            name: "BAP2-CHAIN"
          },
          %{
            path: "docs/design/requirement-map.md",
            kind: :requirement_id,
            name: "REQ1-HEADER-issuer-fingerprint"
          },
          %{path: "priv/conformance/v2/corpus/index.json", kind: :wire_field, name: ~s("v": 2)},
          %{path: "lib/bounded_authority_protocol/v3.ex", kind: :path, name: "v3"},
          %{
            path: "lib/bounded_authority_protocol/v3/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V3.Grant"
          },
          %{path: "spec/bap-v3.md", kind: :path, name: "bap-v3"},
          %{path: "spec/bap-v3.md", kind: :wire_suite, name: "BAP3-ES256-SHA256"},
          %{
            path: "lib/bounded_authority_protocol/v3/consumption_chain.ex",
            kind: :wire_domain,
            name: "BAP3-CHAIN"
          },
          %{
            path: "spec/bap-v3.md",
            kind: :requirement_id,
            name: "REQ3-KEY-uncompressed-sec1"
          },
          %{path: "priv/conformance/v3/corpus/index.json", kind: :wire_field, name: ~s("v": 3)}
        ] do
      assert :ok = DurableIdentifierPolicy.check(fixture)
    end
  end

  test "implementation genealogy and unaccepted contract majors are rejected" do
    for fixture <- [
          %{path: "lib/bounded_authority_protocol/v4.ex", kind: :path, name: "v4"},
          %{
            path: "lib/bounded_authority_protocol/v4/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V4.Grant"
          },
          %{
            path: "lib/bounded_authority_protocol/v2/grant.ex",
            kind: :module,
            name: "BoundedAuthorityProtocol.V20.Grant"
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
      |> then(&Regex.scan(~r/\bREQ[123]-[A-Z0-9]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\b/, &1))
      |> Enum.map(fn [name] -> name end)
      |> MapSet.new()

    assert map_ids == fixture_ids
  end

  # The map<->fixture gate above cannot see the specs: an id cited in a normative
  # spec but absent from the map/fixture (or vice versa after a spec edit) drifted
  # silently — found by cross-vendor review of the v2 activation. The specs are the
  # upstream of the mapping, so every spec-cited id must be fixture-known.
  test "every requirement id cited in a normative spec is fixture-known" do
    fixture_ids =
      "test/fixtures/durable_identifier_requirements.txt"
      |> File.read!()
      |> String.split()
      |> MapSet.new()

    for spec <- ["spec/bap-v1.md", "spec/bap-v2.md"] do
      spec_ids =
        spec
        |> File.read!()
        |> then(&Regex.scan(~r/\bREQ[12]-[A-Z0-9]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\b/, &1))
        |> Enum.map(fn [name] -> name end)
        |> MapSet.new()

      assert MapSet.subset?(spec_ids, fixture_ids),
             "#{spec} cites ids absent from the fixture: #{MapSet.to_list(MapSet.difference(spec_ids, fixture_ids))}"
    end
  end
end

defmodule BoundedAuthorityProtocol.SpecFactsTest do
  # Spec-facts rule 1 (test-time, read-only): the authority's extracted bounds table equals the
  # LIVE Bounds.maximum/0 dump, field for field. Lives as an ExUnit test (not in the gate script)
  # because it needs the compiled Bounds module. A digit changed on either pole — the spec table
  # or the implementation — fails here with the divergent pair named.

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @baseline Path.expand("../spec/facts/baseline-v1.json", __DIR__)

  # Extracted table label → Bounds field. The widths row carries both cryptographic constants.
  @label_to_field %{
    "compact input bytes" => :compact_bytes,
    "encoded segment bytes" => :encoded_segment_bytes,
    "decoded segment bytes" => :decoded_segment_bytes,
    "raw JSON bytes" => :json_bytes,
    "nesting depth" => :depth,
    "members per object" => :object_members,
    "items per array" => :array_items,
    "total JSON value nodes" => :total_nodes,
    "string bytes" => :string_bytes,
    "object-name bytes" => :key_bytes,
    "numeric lexeme bytes" => :number_lexeme_bytes,
    "integer magnitude" => :integer_magnitude,
    "float magnitude" => :float_magnitude,
    "`kid` bytes" => :kid_bytes,
    "JCS output bytes" => :jcs_bytes,
    "normalized target URI bytes" => :uri_bytes,
    "issuer, audience, or token identifier bytes" => :identifier_bytes,
    "nonce bytes" => :nonce_bytes,
    "HTTP method bytes" => :method_bytes,
    "operation name bytes" => :operation_bytes,
    "audiences per grant" => :audiences,
    "operations per grant" => :operations,
    "selectors per operation" => :selectors,
    "selector path segments" => :path_segments,
    "values in `one_of`" => :one_of_values,
    "SHA-256 digest bytes" => :digest_bytes,
    "clock skew seconds" => :clock_skew,
    "proof maximum age seconds" => :proof_max_age,
    "canonical consumption row bytes" => :chain_row_bytes,
    "consumption rows per range" => :chain_rows,
    "boundary anchor or key-transition compact bytes" => :anchor_bytes,
    "anchored-export header bytes" => :archive_header_bytes,
    "historical key transitions" => :key_transitions,
    "anchored-export chunks" => :archive_chunks,
    "anchored-export bytes" => :archive_bytes,
    "object-store version bytes" => :object_version_bytes
  }

  @widths_row "Ed25519 public key / signature bytes"
  @widths_fields [:public_key_bytes, :signature_bytes]

  test "rule 1: extracted bounds table equals the live Bounds.maximum/0 dump" do
    bounds = Bounds.maximum() |> Map.from_struct()
    extracted = baseline_bounds()

    # Every extracted label must be known to the mapping (an unknown label means the spec table
    # grew a row the gate cannot check — fail loudly, never skip).
    unknown_labels = Map.keys(extracted) -- (Map.keys(@label_to_field) ++ [@widths_row])

    assert unknown_labels == [],
           "bounds table labels the gate cannot map: #{inspect(unknown_labels)}"

    # Every live field must appear in the extracted table (a dropped row is silent loosening).
    covered_fields =
      Enum.flat_map(extracted, fn {label, value} ->
        case label do
          @widths_row -> @widths_fields
          _ -> [@label_to_field[label]]
        end
      end)

    uncovered_fields = Map.keys(bounds) -- covered_fields

    assert uncovered_fields == [],
           "bounds fields absent from the extracted table: #{inspect(uncovered_fields)}"

    Enum.each(extracted, fn {label, value} ->
      case label do
        @widths_row ->
          [want_public, want_signature] = @widths_fields

          assert value == [bounds[want_public], bounds[want_signature]],
                 "rule 1: #{@widths_row} says #{inspect(value)}, live dump says " <>
                   "[#{bounds[want_public]}, #{bounds[want_signature]}]"

        _ ->
          field = @label_to_field[label]

          assert value == bounds[field],
                 "rule 1: #{label} says #{inspect(value)}, live Bounds.maximum/0 says #{inspect(bounds[field])}"
      end
    end)
  end

  test "rule 1 non-vacuity: a scratch Bounds.maximum change diverges from the extracted table" do
    extracted = baseline_bounds()
    scratch = Map.put(extracted, "nesting depth", extracted["nesting depth"] + 1)
    bounds = Bounds.maximum() |> Map.from_struct()

    refute scratch["nesting depth"] == bounds[:depth],
           "a changed spec digit must disagree with the live dump"
  end

  defp baseline_bounds do
    bytes = File.read!(@baseline)
    {:ok, tagged} = Json.decode(bytes, Bounds.maximum())
    facts = plain(tagged)
    facts["bounds"]
  end

  defp plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, plain(v)} end) |> Map.new()

  defp plain({:array, items}), do: Enum.map(items, &plain/1)
  defp plain({:string, s}), do: s
  defp plain({:integer, n}), do: n
  defp plain({:float, n}), do: n
  defp plain({:boolean, b}), do: b
  defp plain(:null), do: nil
end

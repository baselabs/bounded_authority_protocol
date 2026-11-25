defmodule BoundedAuthorityProtocol.ActionApproval.V1.RecordCodec do
  @moduledoc false

  alias BoundedAuthorityProtocol.ActionApproval.V1.Record
  alias BoundedAuthorityProtocol.ContentAssertion.V1.Codec
  alias BoundedAuthorityProtocol.V1.{Base64Url, Jcs, Json}

  @maximum %{string_bytes: 1_024, resource_count: 4_096, record_bytes: 65_536}
  @keys ~w(action approver_role request_id resources revision_digest subject v)
  @empty_record ~s({"action":"","approver_role":"","request_id":"","resources":[],"revision_digest":"","subject":"","v":1})
  @record_overhead byte_size(@empty_record) + 43

  def bounds(limits, ca) when is_map(limits) and not is_map_key(limits, :__struct__) do
    if Enum.all?(limits, &valid_bound?/1) do
      effective = Map.merge(@maximum, limits)
      {:ok, %{effective | record_bytes: min(effective.record_bytes, ca.content_bytes)}}
    else
      {:error, :invalid}
    end
  end

  def bounds(_, _), do: {:error, :invalid}

  defp valid_bound?({key, value}),
    do: is_integer(value) and value > 0 and value <= Map.get(@maximum, key, 0)

  def parse(bytes, %{record_bytes: maximum} = bounds, ca)
      when is_binary(bytes) and byte_size(bytes) > 0 and byte_size(bytes) <= maximum do
    with {:ok, {:object, members}} <-
           Json.decode_approval_record(bytes, bounds.string_bytes, bounds.resource_count),
         true <- Enum.sort(Enum.map(members, &elem(&1, 0))) == @keys,
         {:ok, record} <- from_wire(Map.new(members)),
         {:ok, ^bytes} <- encode(record, bounds, ca, false) do
      {:ok, record}
    else
      _failure -> {:error, :invalid}
    end
  end

  def parse(_, _, _), do: {:error, :invalid}

  defp from_wire(%{
         "v" => {:integer, 1},
         "subject" => {:string, subject},
         "action" => {:string, action},
         "request_id" => {:string, request_id},
         "approver_role" => {:string, role},
         "resources" => {:array, resources},
         "revision_digest" => {:string, <<encoded::binary-size(43)>>}
       }) do
    with {:ok, digest} <- Base64Url.decode(encoded, %{}),
         {:ok, names} <- wire_strings(resources, []) do
      {:ok,
       %Record{
         subject: subject,
         action: action,
         request_id: request_id,
         approver_role: role,
         resources: names,
         revision_digest: digest
       }}
    end
  end

  defp from_wire(_), do: {:error, :invalid}

  defp wire_strings([], names), do: {:ok, Enum.reverse(names)}

  defp wire_strings([{:string, name} | rest], names),
    do: wire_strings(rest, [name | names])

  defp wire_strings(_, _), do: {:error, :invalid}

  def encode(
        %Record{
          subject: subject,
          action: action,
          request_id: request_id,
          approver_role: role,
          resources: resources,
          revision_digest: digest
        } = record,
        bounds,
        ca,
        canonicalize?
      )
      when map_size(record) == 7 and is_boolean(canonicalize?) do
    result =
      with true <- text?(subject, bounds) and text?(action, bounds) and text?(role, bounds),
           true <- request_id?(request_id, bounds, ca),
           true <- is_binary(digest) and byte_size(digest) == 32,
           true <- resources?(resources, bounds, canonicalize?),
           names = canonical_resources(resources, canonicalize?),
           true <- fits_encoding?(record, names, bounds.record_bytes) do
        value =
          {:object,
           [
             {"action", {:string, action}},
             {"approver_role", {:string, role}},
             {"request_id", {:string, request_id}},
             {"resources", {:array, Enum.map(names, &{:string, &1})}},
             {"revision_digest", {:string, Base.url_encode64(digest, padding: false)}},
             {"subject", {:string, subject}},
             {"v", {:integer, 1}}
           ]}

        Jcs.encode_approval_record(
          value,
          bounds.record_bytes,
          bounds.string_bytes,
          bounds.resource_count
        )
      end

    stage(result, :invalid)
  end

  def encode(_, _, _, _), do: {:error, :invalid}

  defp fits_encoding?(record, resources, limit) do
    # The empty record already includes the four quote pairs.
    encoding_fits?(
      [record.action, record.approver_role, record.request_id, record.subject],
      resources,
      limit - @record_overhead + 8
    )
  end

  defp encoding_fits?([], resources, remaining), do: resources_fit?(resources, remaining)

  defp encoding_fits?([field | rest], resources, remaining) do
    case Jcs.escaped_string_bytes(field, remaining) do
      {:ok, size} -> encoding_fits?(rest, resources, remaining - size)
      {:error, :invalid} -> false
    end
  end

  defp resources_fit?([], remaining), do: remaining >= 0

  defp resources_fit?([name | rest], remaining) do
    remaining = remaining - separator_bytes(rest)

    case Jcs.escaped_string_bytes(name, remaining) do
      {:ok, size} -> resources_fit?(rest, remaining - size)
      {:error, :invalid} -> false
    end
  end

  defp separator_bytes([]), do: 0
  defp separator_bytes([_ | _]), do: 1

  defp canonical_resources(resources, false), do: resources
  defp canonical_resources(resources, true), do: resources |> Enum.sort() |> Enum.dedup()

  def request_id?(value, bounds, ca),
    do: text?(value, bounds) and Codec.identifier?(value, ca)

  def text?(value, bounds),
    do:
      is_binary(value) and byte_size(value) > 0 and byte_size(value) <= bounds.string_bytes and
        String.valid?(value)

  def resources?([_ | _] = resources, bounds, canonicalize?),
    do: valid_resources?(resources, nil, bounds.resource_count, bounds, canonicalize?)

  def resources?(_, _, _), do: false

  defp valid_resources?([], _, _, _, _), do: true

  defp valid_resources?([name | rest], previous, count, bounds, canonicalize?) when count > 0 do
    text?(name, bounds) and (canonicalize? or is_nil(previous) or previous < name) and
      valid_resources?(rest, name, count - 1, bounds, canonicalize?)
  end

  defp valid_resources?(_, _, _, _, _), do: false

  defp stage({:ok, _} = result, _code), do: result
  defp stage(_, code), do: {:error, code}
end

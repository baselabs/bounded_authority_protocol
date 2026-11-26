defmodule ActionApprovalExample do
  @moduledoc false

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Content
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @profile "bap-action-approval/1"
  @role "records reviewer"
  @domain "records-operations"
  @audience "records-service"
  @issuer "records-review"
  @kid "review-key"
  @now 20

  def run! do
    suffix = Base.url_encode64(:crypto.strong_rand_bytes(12))
    directory = Path.join(System.tmp_dir!(), "bap-approval-#{suffix}")
    File.mkdir!(directory)

    try do
      demonstrate(Path.join(directory, "host.sqlite"), Path.join(directory, "destination.sqlite"))
    after
      File.rm_rf!(directory)
    end
  end

  defp demonstrate(host, destination) do
    {public_key, sign} = signing_backend()
    policy = host_policy(public_key)
    request = frozen_request("activate-7")
    effect = effect(request)
    record = %Approval.Record{
      request_id: request.request_id,
      revision_digest: request.revision_digest,
      subject: request.subject,
      action: request.action,
      resources: request.resources,
      approver_role: @role
    }

    with_db(destination, fn db ->
      [] = query!(db, "CREATE TABLE applied (id BLOB PRIMARY KEY NOT NULL, effect BLOB NOT NULL);")
    end)

    with_db(host, fn db ->
      create_host_tables(db)
      store_request(db, request)
      artifact = signed_record(record, "artifact-1", sign)
      context = Map.merge(request, policy)
      {:ok, facts} = verify(artifact, context)
      wrong_profile = signed_record(record, "wrong-profile", sign, "other-profile")
      {:error, :record_mismatch} = verify(wrong_profile, context)
      {:error, :request_mismatch} = verify(artifact, %{context | request_id: "different-request"})
      {:error, :request_mismatch} = verify(artifact, %{context | revision_digest: <<0::256>>})
      {:error, :role_not_permitted} = verify(artifact, %{context | roles: ["records operator"]})
      snapshot = context.snapshot
      {:error, :expired} = verify(artifact, %{context | now: 35, snapshot: %{snapshot | as_of: 35}})
      {:error, :stale_trust} = verify(artifact, %{context | snapshot: %{snapshot | as_of: 9}})
      {:error, :unknown_key} = verify(artifact, %{context | snapshot: %{snapshot | entries: []}})

      for altered <- [
            %{record | action: "remove"},
            %{record | resources: ["archive/east"]},
            %{record | resources: ["archive/east", "archive/north", "archive/west"]}
          ] do
        {:error, :scope_mismatch} = verify(signed_record(altered, "different-scope", sign), context)
      end

      # Use the real write path with a different proposed effect after verification succeeded.
      for different_effect <- [
            %{effect | subject: "different index"},
            %{effect | action: "remove"},
            %{effect | resources: ["archive/east"]}
          ] do
        {:error, :effect_mismatch} = claim(db, facts, different_effect, :local)
        ["0|0|0|0"] = totals(db)
      end

      fingerprint = facts.assertion.attestor_key_fingerprint
      [] = query!(db, "INSERT INTO revoked_keys VALUES (#{blob(fingerprint)});")
      {:error, :revoked_key} = claim(db, facts, effect, :local)
      ["0|0|0|0"] = totals(db)
      [] = query!(db, "DELETE FROM revoked_keys;")

      {:ok, id} = claim(db, facts, effect, :local)
      expected_effect = Base.encode16(effect_bytes(effect))
      [^expected_effect] = query!(db, "SELECT hex(effect) FROM effects WHERE id = #{blob(id)};")

      copy = frozen_request("activate-copy")
      store_request(db, copy)
      copy_artifact = signed_record(%{record | request_id: copy.request_id}, "artifact-1", sign)
      {:ok, copy_facts} = verify(copy_artifact, Map.merge(copy, policy))
      {:error, :artifact_collision} = claim(db, copy_facts, effect, :local)

      {:ok, second_facts} = verify(signed_record(record, "artifact-2", sign), context)
      {:error, :request_revision_collision} = claim(db, second_facts, effect, :local)
      [] = query!(db, "SELECT 1 FROM artifacts WHERE jti = #{blob("artifact-2")};")
      ["1|1|1|0"] = totals(db)

      rollback = frozen_request("activate-rollback")
      rollback_facts = verify_request(db, rollback, record, "artifact-3", sign, policy)
      [] = query!(db, """
      CREATE TRIGGER refuse_effect BEFORE INSERT ON effects
      BEGIN SELECT RAISE(ABORT, 'effect write failed'); END;
      """)
      {:error, :database} = claim(db, rollback_facts, effect, :local)
      ["1|1|1|0"] = totals(db)
      [] = query!(db, "DROP TRIGGER refuse_effect;")
      {:ok, _} = claim(db, rollback_facts, effect, :local)

      compare = frozen_request("activate-compare")
      comparison = verify_request(db, compare, record, "artifact-4", sign, policy)
      with_db(host, fn writer ->
        [] = query!(writer, "BEGIN IMMEDIATE;")
        next_revision = :crypto.hash(:sha256, "records revision 8")
        [] = query!(writer, """
        UPDATE requests SET revision = #{blob(next_revision)} WHERE id = #{blob(compare.request_id)};
        """)

        {:error, :busy} = claim(db, comparison, effect, :external)
        [] = query!(writer, "COMMIT;")
      end)
      {:error, :revision_changed} = claim(db, comparison, effect, :external)
      ["2|2|2|0"] = totals(db)

      for {mode, request_id, artifact_id, prior_count} <- [
            {"before-commit", "external-1", "artifact-5", 0},
            {"after-commit", "external-2", "artifact-6", 1}
          ] do
        external = frozen_request(request_id)
        checked = verify_request(db, external, record, artifact_id, sign, policy)
        {:ok, intent_id} = claim(db, checked, effect, :external)
        identity = blob(intent_id)

        # Each run starts a new BEAM and loads the intent from the host database.
        75 = worker(host, destination, mode)
        ["0"] = query!(db, "SELECT delivered FROM intents WHERE id = #{identity};")
        before_retry = if mode == "before-commit", do: [], else: [expected_effect]
        ^before_retry = destination_effect(destination, identity)

        if mode == "after-commit" do
          with_db(destination, fn dest ->
            [] = query!(dest, """
            CREATE TRIGGER refuse_repeat BEFORE INSERT ON applied
            BEGIN SELECT RAISE(ABORT, 'recovery must confirm the existing effect'); END;
            """)
          end)
        end

        0 = worker(host, destination, "recover")
        [^expected_effect] = destination_effect(destination, identity)
        ["1"] = query!(db, "SELECT delivered FROM intents WHERE id = #{identity};")
        count = Integer.to_string(prior_count + 1)
        with_db(destination, fn dest -> [^count] = query!(dest, "SELECT count(*) FROM applied;") end)
      end

      ["4|4|2|2"] = totals(db)
      :ok
    end)
  end

  defp frozen_request(id) do
    %{
      request_id: id,
      revision_digest: :crypto.hash(:sha256, "records revision 7"),
      subject: "retention index",
      action: "activate",
      resources: ["archive/east", "archive/west"]
    }
  end

  defp host_policy(public_key) do
    true = BoundedAuthorityProtocol.Ed25519.torsion_free?(public_key)
    key = %HistoricalPublicKey{
      key_id: @kid,
      public_key: public_key,
      valid_from: 0,
      valid_before: :unbounded
    }

    snapshot = %{
      trust_domain: @domain,
      suite: :eddsa,
      provenance: "enrolled-records-keys",
      as_of: @now,
      entries: [%{issuer: @issuer, key: key, roles: [@role]}]
    }

    %{
      trust_domain: @domain,
      audience: @audience,
      snapshot: snapshot,
      now: @now,
      roles: [@role],
      max_staleness: 10,
      max_lifetime: 30,
      bounds: %{},
      record_bounds: %{}
    }
  end

  defp signing_backend do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    sign = fn bytes -> :crypto.sign(:eddsa, :none, bytes, [private, :ed25519]) end
    {public, sign}
  end

  defp signed_record(record, id, sign, profile \\ @profile) do
    {:ok, bytes} = Approval.encode_record(record)
    {:ok, digest} = Content.content_digest(bytes, %{})

    assertion = %Content.ContentAssertion{
      attestor_key_id: @kid,
      jti: id,
      iss: @issuer,
      aud: @audience,
      sub: record.request_id,
      profile: profile,
      profile_digest: Approval.profile_digest(),
      content_digest: digest,
      gen: 1,
      prev: <<0::256>>,
      iat: 15,
      nbf: 15,
      exp: 35
    }

    {:ok, input} = Content.assertion_signing_input(assertion, %{})
    {:ok, compact} = Content.assemble_compact(input, sign.(input.message))
    {bytes, compact}
  end

  # The host selects the approval profile and EdDSA entry point from its own policy.
  defp verify({record, compact}, context), do: Approval.verify_eddsa(record, compact, context)

  defp verify_request(db, request, record, artifact_id, sign, policy) do
    store_request(db, request)
    artifact = signed_record(%{record | request_id: request.request_id}, artifact_id, sign)
    {:ok, facts} = verify(artifact, Map.merge(request, policy))
    facts
  end

  defp effect(request), do: Map.take(request, [:subject, :action, :resources])

  defp effect_bytes(%{subject: subject, action: action, resources: resources}),
    do: IO.iodata_to_binary(:json.encode([subject, action, resources]))

  defp create_host_tables(db) do
    [] = query!(db, """
    CREATE TABLE requests (id BLOB PRIMARY KEY NOT NULL, revision BLOB NOT NULL, effect BLOB NOT NULL);
    CREATE TABLE artifacts (domain BLOB, issuer BLOB, jti BLOB, PRIMARY KEY (domain, issuer, jti))
      WITHOUT ROWID;
    CREATE TABLE claims (request BLOB, revision BLOB, PRIMARY KEY (request, revision)) WITHOUT ROWID;
    CREATE TABLE revoked_keys (fingerprint BLOB PRIMARY KEY NOT NULL);
    CREATE TABLE effects (id BLOB PRIMARY KEY NOT NULL, effect BLOB NOT NULL);
    CREATE TABLE intents (id BLOB PRIMARY KEY NOT NULL, effect BLOB NOT NULL, delivered INTEGER NOT NULL);
    """)
  end

  defp store_request(db, request) do
    [] = query!(db, """
    INSERT INTO requests VALUES (#{blob(request.request_id)}, #{blob(request.revision_digest)},
      #{blob(effect_bytes(effect(request)))});
    """)
  end

  defp claim(db, facts, proposed_effect, mode) do
    # BEGIN IMMEDIATE serializes this comparison and both claims with revision writers.
    transaction(db, fn ->
      record = facts.record
      requested = blob(record.request_id)
      revision = blob(record.revision_digest)
      fingerprint = blob(facts.assertion.attestor_key_fingerprint)
      approved_effect = effect(record)
      approved_bytes = effect_bytes(approved_effect)
      expected_revision = Base.encode16(record.revision_digest)
      expected_effect = Base.encode16(approved_bytes)
      id = IO.iodata_to_binary(:json.encode([record.request_id, expected_revision]))

      with :ok <- require_rows(db, "SELECT hex(revision) FROM requests WHERE id = #{requested};",
             [expected_revision], :revision_changed),
           true <- proposed_effect == approved_effect,
           :ok <- require_rows(db, "SELECT hex(effect) FROM requests WHERE id = #{requested};",
             [expected_effect], :effect_mismatch),
           :ok <- require_rows(db, "SELECT 1 FROM revoked_keys WHERE fingerprint = #{fingerprint};",
             [], :revoked_key),
           :ok <- insert_claim(db, :artifact_collision, """
           INSERT INTO artifacts VALUES (#{blob(facts.trust_domain)}, #{blob(facts.assertion.iss)},
             #{blob(facts.assertion.jti)}) ON CONFLICT DO NOTHING;
           """),
           :ok <- insert_claim(db, :request_revision_collision, """
           INSERT INTO claims VALUES (#{requested}, #{revision}) ON CONFLICT DO NOTHING;
           """),
           {:ok, []} <- write_effect(db, mode, id, approved_bytes) do
        {:ok, id}
      else
        false -> {:error, :effect_mismatch}
        {:error, _} = error -> error
      end
    end)
  end

  defp require_rows(db, sql, expected, mismatch) do
    case query(db, sql) do
      {:ok, ^expected} -> :ok
      {:ok, _} -> {:error, mismatch}
      {:error, _} = error -> error
    end
  end

  defp insert_claim(db, collision, insert) do
    case query(db, insert <> "SELECT changes();") do
      {:ok, ["1"]} -> :ok
      {:ok, ["0"]} -> {:error, collision}
      {:error, _} = error -> error
    end
  end

  defp write_effect(db, :local, id, bytes),
    do: query(db, "INSERT INTO effects VALUES (#{blob(id)}, #{blob(bytes)});")

  defp write_effect(db, :external, id, bytes),
    do: query(db, "INSERT INTO intents VALUES (#{blob(id)}, #{blob(bytes)}, 0);")

  defp transaction(db, work) do
    with {:ok, []} <- query(db, "BEGIN IMMEDIATE;") do
      case work.() do
        {:ok, _} = success ->
          case query(db, "COMMIT;") do
            {:ok, []} -> success
            {:error, _} = error -> rollback(db, error)
          end

        {:error, _} = error ->
          rollback(db, error)
      end
    end
  end

  defp rollback(db, error) do
    [] = query!(db, "ROLLBACK;")
    error
  end

  defp totals(db) do
    query!(db, """
    SELECT (SELECT count(*) FROM artifacts), (SELECT count(*) FROM claims),
      (SELECT count(*) FROM effects), (SELECT count(*) FROM intents);
    """)
  end

  defp worker(host, destination, mode) do
    code_path = :code.which(Approval) |> to_string() |> Path.dirname()
    args = ["-pa", code_path, __ENV__.file, "--worker", host, destination, mode]
    {_output, status} = System.cmd("elixir", args, stderr_to_stdout: true)
    status
  end

  def deliver(host, destination, mode) do
    rows = with_db(host, &query!(&1, "SELECT hex(id), hex(effect) FROM intents WHERE delivered = 0;"))

    for row <- rows do
      [id, bytes] = String.split(row, "|", parts: 2)
      # Hex from SQLite is decoded before it is turned back into an SQL literal.
      identity = id |> Base.decode16!() |> blob()
      value = bytes |> Base.decode16!() |> blob()

      outcome =
        with_db(destination, fn dest ->
          lookup = "SELECT hex(effect) FROM applied WHERE id = #{identity};"

          case query!(dest, lookup) do
            [] when mode == "before-commit" ->
              :interrupted

            [] ->
              [] = query!(dest, """
              INSERT INTO applied VALUES (#{identity}, #{value}) ON CONFLICT DO NOTHING;
              """)

              [^bytes] = query!(dest, lookup)
              :confirmed

            [^bytes] ->
              :confirmed

            _ ->
              raise "Destination effect differs from the stored intent"
          end
        end)

      if outcome == :interrupted or mode == "after-commit", do: System.halt(75)
      [] = with_db(host, &query!(&1, "UPDATE intents SET delivered = 1 WHERE id = #{identity};"))
    end
  end

  defp destination_effect(path, identity) do
    with_db(path, &query!(&1, "SELECT hex(effect) FROM applied WHERE id = #{identity};"))
  end

  # The demo uses the SQLite CLI over standard I/O. Encode binary values as SQL BLOB literals.
  defp blob(bytes), do: "X'#{Base.encode16(bytes)}'"

  defp with_db(path, work) do
    executable = System.find_executable("sqlite3") || raise "SQLite CLI is required"
    db = Port.open({:spawn_executable, executable}, [:binary, :exit_status, :stderr_to_stdout,
      {:line, 65_536}, {:args, ["-batch", "-list", "-noheader", "-init", "/dev/null", path]}])
    try do
      work.(db)
    after
      if Port.info(db) do
        Port.command(db, ".quit\n")
        receive do
          {^db, {:exit_status, _}} -> :ok
        after
          5_000 -> Port.close(db)
        end
      end
    end
  end

  defp query!(db, sql) do
    {:ok, rows} = query(db, sql)
    rows
  end

  defp query(db, sql) do
    true = Port.command(db, [sql, "\n.print bap-sql-end\n"])
    collect(db, [], nil)
  end

  defp collect(db, rows, error) do
    receive do
      {^db, {:data, {:eol, "bap-sql-end"}}} ->
        if error, do: {:error, error}, else: {:ok, Enum.reverse(rows)}
      {^db, {:data, {:eol, line}}} ->
        case line do
          "Runtime error" <> _ ->
            code = if String.contains?(line, "database is locked"), do: :busy, else: :database
            collect(db, rows, code)
          "Parse error" <> _ -> collect(db, rows, :database)
          _ -> collect(db, [line | rows], error)
        end
      {^db, {:exit_status, _}} -> {:error, :database}
    after
      5_000 -> raise "SQLite did not complete the query"
    end
  end
end

case System.argv() do
  ["--worker", host, destination, mode] -> ActionApprovalExample.deliver(host, destination, mode)
  _ -> ActionApprovalExample.run!()
end

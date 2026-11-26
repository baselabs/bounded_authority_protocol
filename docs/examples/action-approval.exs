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
      next_revision = :crypto.hash(:sha256, "records revision 8")

      with_db(host, fn writer ->
        [] = query!(writer, "BEGIN IMMEDIATE;")
        [] = query!(writer, revision_update(compare, next_revision))
        {:error, :busy} = claim(db, comparison, effect, :external)
        [] = query!(writer, "COMMIT;")
      end)

      {:error, :revision_changed} = claim(db, comparison, effect, :external)
      ["2|2|2|0"] = totals(db)

      claim_first = frozen_request("activate-claim-first")
      first_facts = verify_request(db, claim_first, record, "artifact-5", sign, policy)
      update = revision_update(claim_first, next_revision)

      with_db(host, fn writer ->
        # Pause at the completed comparison and try the update on a second connection.
        {:ok, first_id} = claim(db, first_facts, effect, :local, fn ->
          {:error, :busy} = query(writer, update)
          :ok
        end)

        revision = Base.encode16(claim_first.revision_digest)
        read_revision = revision_query(claim_first.request_id)
        [^revision] = query!(writer, read_revision)

        [^expected_effect] =
          query!(writer, "SELECT hex(effect) FROM effects WHERE id = #{blob(first_id)};")

        [] = query!(writer, update)
        next_hex = Base.encode16(next_revision)
        [^next_hex] = query!(writer, read_revision)
        {:error, :revision_changed} = claim(db, first_facts, effect, :local)
      end)

      for {mode, request_id, artifact_id, prior_count} <- [
            {"before-commit", "external-1", "artifact-6", 0},
            {"after-commit", "external-2", "artifact-7", 1}
          ] do
        external = frozen_request(request_id)
        external = if mode == "before-commit", do: large_request(external), else: external
        external_effect = effect(external)
        external_bytes = effect_bytes(external_effect)
        expected_external_effect = Base.encode16(external_bytes)
        if mode == "before-commit", do: true = byte_size(expected_external_effect) > 65_536
        checked = verify_request(db, external, record, artifact_id, sign, policy)
        {:ok, intent_id} = claim(db, checked, external_effect, :external)
        identity = blob(intent_id)

        # Each run starts a new BEAM and loads the intent from the host database.
        75 = worker(host, destination, mode)
        ["0"] = query!(db, "SELECT delivered FROM intents WHERE id = #{identity};")
        before_retry = if mode == "before-commit", do: [], else: [expected_external_effect]
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
        [^expected_external_effect] = destination_effect(destination, identity)
        ["1"] = query!(db, "SELECT delivered FROM intents WHERE id = #{identity};")
        count = Integer.to_string(prior_count + 1)
        with_db(destination, fn dest -> [^count] = query!(dest, "SELECT count(*) FROM applied;") end)
      end

      ["5|5|3|2"] = totals(db)
      :ok
    end)
  end

  defp large_request(request) do
    # A 40 KiB effect produces a hexadecimal SQL row longer than a port line fragment.
    suffix = String.duplicate("x", 940)
    resources = Enum.map(10..53, &"archive/#{&1}/#{suffix}")
    %{request | resources: resources}
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
    artifact = signed_record(struct!(record, request), artifact_id, sign)
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

  defp revision_query(request_id) do
    "SELECT hex(revision) FROM requests WHERE id = #{blob(request_id)};"
  end

  defp revision_update(request, revision) do
    "UPDATE requests SET revision = #{blob(revision)} WHERE id = #{blob(request.request_id)};"
  end

  defp compare_revision(db, record, after_comparison) do
    expected = [Base.encode16(record.revision_digest)]

    with :ok <- require_rows(db, revision_query(record.request_id), expected, :revision_changed) do
      after_comparison.()
    end
  end

  defp claim(db, facts, proposed_effect, mode, after_comparison \\ fn -> :ok end) do
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

      with :ok <- compare_revision(db, record, after_comparison),
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
    code_path = Application.app_dir(:bounded_authority_protocol, "ebin")
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
            [] ->
              [] = query!(dest, "BEGIN IMMEDIATE;")
              [] = query!(dest, """
              INSERT INTO applied VALUES (#{identity}, #{value}) ON CONFLICT DO NOTHING;
              """)

              [^bytes] = query!(dest, lookup)

              if mode == "before-commit" do
                # Closing the connection interrupts the attempted write before it commits.
                :interrupted
              else
                [] = query!(dest, "COMMIT;")
                :confirmed
              end

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
    collect(db, [], [], nil)
  end

  defp collect(db, rows, fragments, error) do
    receive do
      {^db, {:data, {:eol, "bap-sql-end"}}} when fragments == [] ->
        if error, do: {:error, error}, else: {:ok, Enum.reverse(rows)}
      {^db, {:data, {:noeol, fragment}}} ->
        collect(db, rows, [fragment | fragments], error)
      {^db, {:data, {:eol, last}}} ->
        line = fragments |> Enum.reverse([last]) |> IO.iodata_to_binary()
        if sqlite_error?(line) do
          collect(db, rows, [], error_code(line))
        else
          collect(db, [line | rows], [], error)
        end
      {^db, {:exit_status, _}} -> {:error, :database}
    after
      5_000 -> raise "SQLite did not complete the query"
    end
  end

  defp sqlite_error?(line),
    do: Enum.any?(["Runtime error", "Parse error", "Error"], &String.starts_with?(line, &1))

  # The CLI reports SQLITE_BUSY as "database is locked" under each error prefix.
  defp error_code(line),
    do: if(String.contains?(line, "database is locked"), do: :busy, else: :database)
end

case System.argv() do
  ["--worker", host, destination, mode] -> ActionApprovalExample.deliver(host, destination, mode)
  _ -> ActionApprovalExample.run!()
end

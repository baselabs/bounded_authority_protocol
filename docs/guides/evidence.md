# Evidence: chains, anchors, transitions, and exports

Verifying a request answers "may these bytes be accepted now?". Evidence answers a later
question: "what did this service accept, and can anyone show that the record was not altered?".
The protocol defines four evidence formats for that, and verifies each of them with the same
posture as credentials: pure functions, caller-supplied keys and expectations, redacted facts,
and the single `{:error, :invalid}`.

| Format | What it is | Produce | Verify | Facts |
|---|---|---|---|---|
| Consumption chain | Hash-linked rows, one per accepted invocation | `encode_consumption_entry/2` | `check_chain/2` | `ChainFacts` |
| Boundary anchor | A signed statement that a chain had a given head at a given time (`typ: "ba+chain-anchor"`) | `boundary_anchor_signing_input/2`, `assemble_compact/2` | `verify_historical_anchor/3` | `AnchorFacts` |
| Key transition | The current archive key authenticating its successor (`typ: "ba+key-transition"`) | `key_transition_signing_input/2`, `assemble_compact/2` | `verify_key_transition/4` | `KeyTransitionFacts` |
| Anchored export | One archive object holding rows, anchors, and transitions | `encode_anchored_export/2` | `verify_anchored_export/3` | `AnchoredExportFacts` |

Every contract-major has all eight functions in its own namespace, with its own domain
separators (`BAP1-CHAIN`, `BAP2-CHAIN`, `BAP3-CHAIN`, and the matching archive prefixes); under
contract-major 3 the anchors and transitions are ES256-signed. The normative rules are in
[`spec/bap-v1.md` § 15](../../spec/bap-v1.md#chain).

`ChainFacts`, `AnchorFacts`, and `KeyTransitionFacts` carry `trust: :not_evaluated`;
`AnchoredExportFacts` carries `trust: :not_evaluated` and `authorization: :not_evaluated`. They
say the bytes are consistent with what you supplied. They do not say the archive is complete,
that you should trust its keys, or that anything it records was authorized.

## A consumption chain

A row binds a chain id, a sequence number, the previous row's hash, and a 32-byte commitment.
The host computes the commitment over whatever it recorded for the invocation, for example the
envelope facts and the outcome, and keeps the preimage private: the public row carries only the
digest. The first row links to the all-zero hash.

```elixir
alias BoundedAuthorityProtocol.V1
alias BoundedAuthorityProtocol.V1.{ChainInput, ConsumptionEntry, ExpectedChain}

chain_id = "urn:example:chain:model-evaluations"

{rows, head} =
  ["eval run 41", "eval run 42", "eval run 43"]
  |> Enum.with_index(1)
  |> Enum.map_reduce(<<0::256>>, fn {record, sequence}, previous ->
    entry = %ConsumptionEntry{
      chain_id: chain_id,
      sequence: sequence,
      previous_hash: previous,
      commitment: :crypto.hash(:sha256, record)
    }

    {:ok, encoded} = V1.encode_consumption_entry(entry, %{})
    {encoded.bytes, encoded.hash}
  end)

expected_chain = %ExpectedChain{
  chain_id: chain_id,
  first_sequence: 1,
  last_sequence: 3,
  row_count: 3,
  previous_hash: <<0::256>>,
  last_hash: head,
  bounds: %{}
}

{:ok, chain_facts} = V1.check_chain(%ChainInput{rows: rows}, expected_chain)
[first, _second, third] = rows

{chain_facts.row_count, chain_facts.verification,
 V1.check_chain(%ChainInput{rows: [first, third]}, expected_chain)}
```

The value is `{3, :boundary_consistent, {:error, :invalid}}`: the chain verifies, and the same
chain with a row dropped does not.

Chain verification checks consistency between the boundaries you name, and only that. A chain
that was validly truncated or rebuilt from some earlier row still links. What makes it evidence
is that the expected head (`last_hash`) and the predecessor come from your own records or from
signed anchors, never from the rows you are checking ([usage rules](../../usage-rules.md) 10
and 11).

## Anchors and key transitions

An archive key signs a boundary anchor at the chain's start (sequence 0, all-zero hash) and at
its end (the last sequence and head). Archive keys are historical keys: each
`HistoricalPublicKey` carries `valid_from` and `valid_before` (or `:unbounded`), and an anchor
verifies only when its `anchored_at` falls inside the window of the key that signed it.

When the archive moves to a new key, the current key signs a key transition naming the next key
by id and RFC 7638 fingerprint, effective at a time inside both windows. A verifier that trusts
the first key in the history can then follow the archive onto later keys without trusting each
one out of band. `verify_key_transition/4` takes the current key, the next key, and the expected
transition; it refuses a transition signed by the next key.

## Anchored exports

`encode_anchored_export/2` frames the rows, the start anchor, the transitions, and the end anchor
into one archive object. It first checks them against the same expectations a verifier will use,
so it refuses to build an archive that would not verify. It returns the object as a list of
chunks, its SHA-256 digest, and its byte count.

The host writes the chunks to an object store and records two values from outside the archive:
the digest and the object version the store reports. To verify the archive later,
`verify_anchored_export/3` takes the bytes read back (`ArchivedObject`, any chunking), the ordered
key history (`HistoricalKeyChain`), and an `ExpectedAnchoredExport` built from the host's own
records. It checks every byte to the exact end of the object, the digest, the object version,
the chain, every anchor, and every transition.

The [chains and archives Livebook](../livebooks/chains-and-archives.livemd) builds all four
formats end to end with ephemeral keys and shows the attacks each one refuses: a dropped,
reordered, or edited row, a truncated head, an anchor outside its key's window, a transition
signed by the wrong key, a trailing byte, another object version, and a missing key in the
history.

## What the host owns

The package checks evidence; it does not keep it. The host:

- decides what each commitment covers and keeps the preimages;
- appends rows atomically, so two accepted invocations never share a sequence number;
- decides when to anchor and which archive keys to use, and protects those private keys;
- stores archives, and records each digest and object version where an attacker who can write
  the archive cannot also rewrite them;
- decides which archive keys it trusts, for which windows, and whether a verified archive is
  enough for its audit.

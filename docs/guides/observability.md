# Caller-side observability

The library emits nothing: no telemetry, logs, spans, clock reads, counters, or process state.
Instrumentation belongs to the caller around the public verification boundary. A host may
measure elapsed time and publish a fixed outcome class through its own metrics backend.

This complete example measures a real refusal with a monotonic host clock. It returns only a
fixed class and duration to instrumentation; it does not pass the input or facts to a handler.

```elixir
observe = fn credentials, expected ->
  started = System.monotonic_time()
  result = BoundedAuthorityProtocol.V1.check_envelope(credentials, expected)
  duration = System.monotonic_time() - started
  class = case result do
    {:ok, _facts} -> :verified
    {:error, :invalid} -> :invalid
  end
  {result, %{duration: duration}, %{profile: :v1, result_class: class}}
end
{{:error, :invalid}, %{duration: duration}, %{profile: :v1, result_class: :invalid}} = observe.(nil, nil)
true = is_integer(duration) and duration >= 0
:observed_invalid
```

The value is `:observed_invalid`. In your application, send the measurement and metadata to
your real logger, tracer, or telemetry backend. Record host policy refusal, revocation failure,
and reservation outage as separate fixed classes at their own boundaries. Never label with
issuer ids, grant ids, invocation ids, operation arguments, nonces, compact credentials, or keys.
Avoid attaching raw facts or exception bindings even when their ordinary inspection is redacted.

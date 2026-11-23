# Tagged arguments and selectors

Use the protocol's tagged JSON algebra after applying your route's real argument casting.
`{:integer, 4}` and `{:float, 4.0}` are distinct request values. Objects are member lists;
duplicate members are invalid, and object order does not change the canonical digest. Arrays
remain ordered. A missing member is different from a member with `:null`.

Convert cast Elixir terms with `BoundedAuthorityProtocol.V1.Json.from_term/2`. Plain maps may
use binary or atom keys; colliding names, structs, invalid UTF-8, and over-limit values return
`{:error, :invalid}`. Object members are sorted by binary name. Integers and floats keep their
tags, including whole floats. This helper serves all three contract-majors. When the body is
still raw bytes, use `BoundedAuthorityProtocol.V1.Json.decode/2` to retain duplicate-name checks.
The term converter applies the decoder's structural and magnitude limits; raw `json_bytes`
and `number_lexeme_bytes` limits do not apply.

```elixir
alias BoundedAuthorityProtocol.V1
V1.Json.from_term(%{width: 4, scale: 4.0}, %{object_members: 2})
```

The value is `{:ok, {:object, [{"scale", {:float, 4.0}}, {"width", {:integer, 4}}]}}`.

All selectors for an operation must hold. contract-major 1 supports `:all`, `equals`, and `one_of`. contract-major 2 and
contract-major 3 add inclusive `lte` and `gte`; both operands must have the same numeric tag. Paths traverse
object members only and never index arrays. Unknown kinds, empty paths, non-numeric range bounds,
and over-limit values fail closed. Producers refuse float-tagged whole-number selector values
because canonical JSON would re-tag them as integers; decoders also reject float zero inside
`equals` and `one_of` (erratum 6). Never coerce a refused value into a passing one.

```elixir
{:ok, integer_digest} = V1.request_digest("resize_image", {:object, [{"width", {:integer, 4}}]}, %{})
{:ok, float_digest} = V1.request_digest("resize_image", {:object, [{"width", {:float, 4.0}}]}, %{})
integer_digest != float_digest
```

The value is `true`. The [contract-major 2 notebook](../notebooks/range-selectors.livemd) executes both inclusive
boundaries, a tag mismatch with a correctly signed proof, and invalid selector producers.

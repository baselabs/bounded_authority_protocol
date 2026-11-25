defmodule BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts do
  @moduledoc "Verification facts under explicit approval context and snapshot data."

  alias BoundedAuthorityProtocol.ActionApproval.V1.Record
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts, as: EsFacts
  alias BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts

  @enforce_keys [:suite, :trust_domain, :record, :assertion]
  defstruct @enforce_keys ++ [trust: :not_evaluated]

  @typedoc "Redacted approval facts with unevaluated trust."
  @type t :: %__MODULE__{
          suite: :eddsa | :es256,
          trust_domain: binary(),
          record: Record.t(),
          assertion: ContentAssertionFacts.t() | EsFacts.t(),
          trust: :not_evaluated
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts do
  def inspect(_value, _options),
    do:
      Inspect.Algebra.string(
        "#BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>"
      )
end

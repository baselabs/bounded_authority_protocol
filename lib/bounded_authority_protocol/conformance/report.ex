defmodule BoundedAuthorityProtocol.Conformance.Report do
  @moduledoc """
  Pure report builder for the loaded corpus and runner results.

  `build/2` computes overall agreement (every case agreed with its expectation), the exit
  status (0 on complete agreement, 1 otherwise), and the applicability matrix summary.
  `to_bytes/2` emits deterministic JCS-canonical report bytes through the package's own
  `V1.Jcs.encode/2` — one canonicalizer, no second encoder.
  """

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs

  @enforce_keys [:agreement, :exit_status, :total, :agreed, :disagreed]
  defstruct [:agreement, :exit_status, :total, :agreed, :disagreed]

  @type t :: %__MODULE__{
          agreement: boolean(),
          exit_status: 0 | 1,
          total: non_neg_integer(),
          agreed: non_neg_integer(),
          disagreed: non_neg_integer()
        }

  @doc "Builds the agreement report from the loaded corpus and runner results."
  @spec build(Corpus.t(), [{binary(), [%{case_id: binary(), agree: boolean()}]}]) :: t()
  def build(%Corpus{}, results) do
    all = results |> Enum.flat_map(&elem(&1, 1))

    total = length(all)
    agreed = Enum.count(all, fn result -> result.agree end)
    disagreed = total - agreed
    agreement = disagreed == 0

    %__MODULE__{
      agreement: agreement,
      exit_status: if(agreement, do: 0, else: 1),
      total: total,
      agreed: agreed,
      disagreed: disagreed
    }
  end

  @doc "Emits deterministic JCS-canonical report bytes."
  @spec to_bytes(Corpus.t(), [{binary(), [%{case_id: binary(), agree: boolean()}]}]) ::
          {:ok, binary()} | {:error, :invalid}
  def to_bytes(%Corpus{} = corpus, results) do
    report = build(corpus, results)

    value =
      {:object,
       [
         {"format", {:string, "bounded-authority-protocol-v1-conformance-report"}},
         {"agreement", {:boolean, report.agreement}},
         {"exit_status", {:integer, report.exit_status}},
         {"total", {:integer, report.total}},
         {"agreed", {:integer, report.agreed}},
         {"disagreed", {:integer, report.disagreed}},
         {"index_sha256_base64url", {:string, index_identity(corpus.index_bytes)}}
       ]}

    Jcs.encode(value, Bounds.maximum())
  end

  defp index_identity(index_bytes) do
    # The report binds the index identity: the SHA-256 of the exact index.json bytes the run
    # loaded. This is the canonical corpus identity, recomputed at load and bound to HEAD.
    Base.url_encode64(:crypto.hash(:sha256, index_bytes), padding: false)
  end
end

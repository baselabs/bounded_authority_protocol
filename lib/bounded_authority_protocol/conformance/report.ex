defmodule BoundedAuthorityProtocol.Conformance.Report do
  @moduledoc false

  # Internal to the conformance CLI (not public API). Pure report builder for a loaded corpus and
  # its runner results. `build/2` computes agreement and the exit status; `to_bytes/2` emits the
  # deterministic JCS report bytes through the package's own `V1.Jcs.encode/2`.
  #
  # Agreement needs more than zero disagreements: the results must be the loaded census exactly.
  # Executed case ids are unique, their set equals the certified corpus's `case_ids`, their count
  # equals the corpus's `total_cases`, and every result sits under the file that declared its
  # case. A runner that dropped, duplicated, invented or misfiled a case cannot report agreement.

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs

  @report_formats %{
    1 => "bounded-authority-protocol-v1-conformance-report",
    2 => "bounded-authority-protocol-v2-conformance-report",
    3 => "bounded-authority-protocol-v3-conformance-report",
    :strict_ed25519 => "bounded-authority-protocol-strict-ed25519-conformance-report",
    :producer_canonicality =>
      "bounded-authority-protocol-producer-canonicality-conformance-report",
    :selector_float_zero => "bounded-authority-protocol-selector-float-zero-conformance-report",
    :local_loopback_http => "bounded-authority-protocol-local-loopback-http-conformance-report",
    :role_attestation => "bounded-authority-protocol-role-attestation-conformance-report",
    :content_assertion => "bounded-authority-protocol-content-assertion-conformance-report"
  }

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
  def build(%Corpus{} = corpus, results) do
    all = results |> Enum.flat_map(&elem(&1, 1))

    total = length(all)
    agreed = Enum.count(all, fn result -> result.agree end)
    disagreed = total - agreed
    # A zero-case corpus verifies nothing: agreement requires at least one executed case AND
    # zero disagreements. Without the `total > 0` floor an empty-but-valid corpus (total_cases:0,
    # files:[], every applicability cell n_a) passes integrity and reports agreement -> exit 0,
    # which is the vacuous-conformance-green failure the CLI's required --corpus exists to kill.
    agreement = total > 0 and disagreed == 0 and Corpus.complete?(corpus, results)

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
         {"format", {:string, Map.get(@report_formats, corpus.major)}},
         {"agreement", {:boolean, report.agreement}},
         {"exit_status", {:integer, report.exit_status}},
         {"total", {:integer, report.total}},
         {"agreed", {:integer, report.agreed}},
         {"disagreed", {:integer, report.disagreed}},
         {"index_sha256_base64url", {:string, index_identity(corpus.index_bytes)}}
       ]}

    Jcs.encode(value, Bounds.maximum())
  end

  @doc """
  The canonical corpus identity: base64url of the SHA-256 of the exact `index.json` bytes the run
  loaded. Recomputed at load; bound into the report and asserted by the CLI against the certified
  snapshot (the SDK runners pin the same values).
  """
  @spec index_identity(binary()) :: binary()
  def index_identity(index_bytes) do
    Base.url_encode64(:crypto.hash(:sha256, index_bytes), padding: false)
  end
end

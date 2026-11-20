defmodule SigilGuard.Decision do
  @moduledoc """
  Runtime gate decision returned by boundary-aware SigilGuard checks.

  `:action` carries the unified verdict vocabulary:
  `:allow | :redact | :confirm | :quarantine | :block`, ordered from least to
  most restrictive. `:verdict` carries the three-way policy verdict
  (`:allowed | :blocked | {:confirm, reason}`) alongside it for
  compatibility.

  On a `:confirm` decision, `:action` is the unified verdict `:confirm` while
  `:effect` records the executable action (`:allow | :redact | :quarantine`) to
  run once confirmation is accepted. Confirmation dispatch uses `:effect`.

  `matched_rules` and `evidence_refs` explain a verdict and link its evidence
  without raw payloads. The decision also carries the boundary labels
  (`source`, `sink`, `trust_zone`, `actor`, `resource`, `phase`).

  `evidence_refs` holds `SigilGuard.Audit.Evidence` references. The gate and
  the kernel return an empty list: they hold no audit artifacts. A host sets
  the field once it has a checkpoint, export or anchor for the decision, and
  `SigilGuard.Attestation.from_decision/3` then writes the references into
  the statement.
  """

  @typedoc "What the host does with the crossing."
  @type action :: :allow | :redact | :quarantine | :block | :confirm
  @typedoc "The action that runs if the decision is carried out: for a confirm decision, after acceptance; nil for a block."
  @type effect :: :allow | :redact | :quarantine | nil
  @typedoc "The three-way verdict, kept for compatibility beside `action`."
  @type verdict :: SigilGuard.Policy.verdict()

  @typedoc "A rule that contributed to the verdict; mirrors attestation matched rules."
  @type matched_rule :: %{rule_id: String.t(), explanation: String.t()}

  @typedoc "The outcome of a boundary evaluation."
  @type t :: %__MODULE__{
          verdict: verdict(),
          action: action(),
          reason: String.t() | nil,
          phase: SigilGuard.Context.phase() | SigilGuard.Lifecycle.phase(),
          risk_level: SigilGuard.Policy.risk_level(),
          trust_level: SigilGuard.Identity.trust_level(),
          hits: [SigilGuard.Patterns.scan_hit()],
          indicators: [map()],
          matched_rules: [matched_rule()],
          evidence_refs: [SigilGuard.Audit.Evidence.ref()],
          effect: effect(),
          source: atom() | String.t() | nil,
          sink: atom() | String.t() | nil,
          trust_zone: atom() | String.t() | nil,
          actor: String.t() | nil,
          resource: String.t() | nil,
          sanitized_text: String.t() | nil,
          content_hash: String.t() | nil,
          audit_metadata: map()
        }

  @enforce_keys [:verdict, :action, :phase, :risk_level, :trust_level]
  defstruct [
    :verdict,
    :action,
    :reason,
    :phase,
    :risk_level,
    :trust_level,
    :sanitized_text,
    :content_hash,
    :source,
    :sink,
    :trust_zone,
    :actor,
    :resource,
    :effect,
    hits: [],
    indicators: [],
    matched_rules: [],
    evidence_refs: [],
    audit_metadata: %{}
  ]

  @doc "Return true when the decision allows the boundary crossing."
  @spec allowed?(t()) :: boolean()
  def allowed?(%__MODULE__{verdict: :allowed}), do: true
  def allowed?(_), do: false

  @doc "Return true when the decision blocks the boundary crossing."
  @spec blocked?(t()) :: boolean()
  def blocked?(%__MODULE__{verdict: :blocked}), do: true
  def blocked?(_), do: false

  @doc "Return true when the decision requires confirmation."
  @spec confirm?(t()) :: boolean()
  def confirm?(%__MODULE__{verdict: {:confirm, _}}), do: true
  def confirm?(_), do: false
end

defmodule SigilGuard.EffectAuthority do
  @moduledoc """
  Binding and admission for tool requests that change the physical world.

  A physical-effect request carries a closed binding record at
  `params._meta["dev.sigilguard/effect"]`. The record names the operation, the
  target, the artifacts, the frame revision, the policy epoch, and the dispatch
  window. It travels inside the guarded payload, so the SP.01 payload digest
  and the confirmation token already cover it.

  Every function here is pure. None reads a clock, process state, ETS, or the
  application environment, and none raises on malformed input. The host owns
  the durable effect ledger, the current facts, and the target protocol.

  See `docs/specs/SP.19-physical-effect-authority.md` for the contract.

  ## Example

      iex> record = %{
      ...>   "binding_format" => "sigil_guard_effect_binding/v1",
      ...>   "operation_id" => "op-1",
      ...>   "target" => %{"id" => "urn:example:cell-a:arm-1", "environment" => "physical"},
      ...>   "policy_epoch" => "example-bundle:42",
      ...>   "not_after" => "2026-11-19T12:05:00.000Z"
      ...> }
      ...>
      ...> SigilGuard.EffectAuthority.validate_binding(record)
      :ok
      iex> SigilGuard.EffectAuthority.validate_binding(Map.put(record, "speed", 120))
      {:error, :invalid_effect_binding}
  """
  @moduledoc since: "1.1.0"

  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Crypto
  alias SigilGuard.Decision
  alias SigilGuard.EffectAuthority.Envelope
  alias SigilGuard.EffectAuthority.Facts
  alias SigilGuard.EffectAuthority.Outcome
  alias SigilGuard.EffectAuthority.Record
  alias SigilGuard.MCP.SecurityPayload

  @typedoc "The reason an admission is refused, in the order the checks run."
  @type refusal ::
          :invalid_options
          | :effect_binding_required
          | :invalid_effect_binding
          | :not_authorized
          | :invalid_current_facts
          | :stale_current_facts
          | :principal_mismatch
          | :target_mismatch
          | :target_environment_mismatch
          | :artifact_mismatch
          | :frame_revision_mismatch
          | :policy_epoch_mismatch
          | :effect_not_yet_valid
          | :effect_deadline_passed
          | :authority_expired
          | :unknown_effect_envelope
          | :invalid_effect_envelope
          | :effect_envelope_mismatch
          | :effect_envelope_expired
          | :target_out_of_envelope
          | :operation_out_of_envelope
          | :parameter_out_of_envelope

  @typedoc "What an outcome report claims, kept apart from what the host observed."
  @type outcome :: %{
          authentication: :verified | :unsigned | :invalid,
          claimed: :success | :failure | :none,
          acceptance: :accepted | :rejected | :undetermined
        }

  @typedoc "Values for one audit event about a physical-effect operation."
  @type audit_fields :: %{
          result: String.t(),
          result_info: SigilGuard.Audit.ExecutionResult.t(),
          metadata: %{optional(String.t()) => String.t()}
        }

  @doc """
  Read the binding record from a request and validate it.

  The record is read from the `params` value the gateway binds: the string key
  `"params"`, or `:params` when the string key is absent. An absent record
  returns `:effect_binding_required`. A record that breaks the closed schema, a
  value that is not a map, or a `params` map with both `"_meta"` and `:_meta`
  returns `:invalid_effect_binding`.
  """
  @doc since: "1.1.0"
  @spec fetch_binding(term()) ::
          {:ok, map()} | {:error, :effect_binding_required | :invalid_effect_binding}
  def fetch_binding(request), do: Record.fetch(request)

  @doc """
  Validate a binding record against the closed schema.

  Unknown keys, wrong types, identifiers outside 1 to 256 bytes of printable
  ASCII, unsorted or duplicate artifacts, and a `not_before` that is not
  earlier than `not_after` are refused.
  """
  @doc since: "1.1.0"
  @spec validate_binding(term()) :: :ok | {:error, :invalid_effect_binding}
  def validate_binding(record), do: Record.validate(record)

  @doc """
  Return the lowercase-hex SHA-256 of the record's JCS bytes.
  """
  @doc since: "1.1.0"
  @spec binding_digest(term()) :: {:ok, String.t()} | {:error, :invalid_effect_binding}
  def binding_digest(record) do
    with :ok <- Record.validate(record), do: {:ok, jcs_digest(record)}
  end

  @doc """
  Return the ledger key for the operation a record names.

  The key is the lowercase-hex SHA-256 of the JCS bytes of
  `{"operation_id": ..., "target_id": ...}`. Two records for the same operation
  on the same target share a key whatever else they contain.
  """
  @doc since: "1.1.0"
  @spec operation_key(term()) :: {:ok, String.t()} | {:error, :invalid_effect_binding}
  def operation_key(record) do
    with :ok <- Record.validate(record), do: {:ok, operation_digest(record)}
  end

  @doc """
  Return the lowercase-hex SHA-256 of an effect envelope's JCS bytes.

  The document is validated first. An unknown key, a float bound, an inverted
  range, unsorted or duplicate targets or operations, and a string that is not
  valid UTF-8 are refused.
  """
  @doc since: "1.1.0"
  @spec envelope_digest(term()) :: {:ok, String.t()} | {:error, :invalid_effect_envelope}
  def envelope_digest(document), do: Envelope.digest(document)

  @doc """
  Decide whether an allowed request may be dispatched now.

  `decision` is the value `SigilGuard.ToolGateway.guard_request/3` returned for
  `request` and `context` with `effect_binding: :required`. An allowed decision
  guarded with `:off`, or one whose `effect_binding_digest` and
  `effect_operation_key` belong to another record, is refused with
  `:not_authorized`. `current` is an
  atom-keyed closed map of facts the host read from its own sources:
  `:principal`, `:target` (`%{id: ..., environment: :physical | :simulated}`),
  `:policy_epoch`, `:observed_at`, and `:now`, plus optional `:artifacts`
  (`%{name: ..., sha256: ...}` maps) and `:frame_revision`.

  Options:

    * `:max_fact_age_ms` - required positive integer. Facts older than this at
      `:now`, or observed after `:now`, are stale.
    * `:envelope` - the approved effect envelope document, when the record
      names one.

  `:authority_expired` refuses a `:now` later than the decision's
  `effect_authority_expires_at`, the earliest stated expiry of the token and
  the attestation the gateway accepted. The checks run in the SP.19 admission
  order, and the first failure is returned as `{:error, reason}`. The result is not a credential: it applies to the
  dispatch that follows immediately, and a refusal never upgrades a verdict.
  """
  @doc since: "1.1.0"
  @spec admit(term(), term(), Context.t() | map() | keyword(), term(), term()) ::
          :ok | {:error, refusal()}
  def admit(decision, request, context, current, opts) do
    with {:ok, options} <- admit_options(opts),
         {:ok, record} <- Record.fetch(request),
         bound_context = SecurityPayload.context(request, :request, context),
         {:ok, authority} <- authorized(decision, request, record, bound_context),
         {:ok, facts} <- Facts.validate(current),
         :ok <- fresh(facts, options.max_fact_age_ms),
         :ok <- conditions(record, facts, bound_context.actor),
         :ok <- unexpired(authority.expires_at, facts.now) do
      Envelope.admit(record, options.envelope, %{
        actor: bound_context.actor,
        now: facts.now,
        request: request,
        manifest_digest: authority.manifest_digest
      })
    end
  end

  @doc """
  Check whether a host ledger record may move from one state to another.

  The states are `:claimed`, `:refused`, `:dispatched`, `:acknowledged`,
  `:cancel_requested`, `:unknown`, `:finished`, `:failed`, and `:cancelled`.
  `:refused`, `:finished`, `:failed`, and `:cancelled` are terminal. A cancel
  request moves to `:cancel_requested`, never directly to `:cancelled`. Any
  other term returns `false`.
  """
  @doc since: "1.1.0"
  @spec valid_transition?(term(), term()) :: boolean()
  def valid_transition?(from, to), do: Outcome.valid_transition?(from, to)

  @doc """
  Separate what an outcome report claims from what the host observed.

  The input is an atom-keyed closed map:

    * `:authentication` - `:verified`, `:unsigned`, or `:invalid`, from
      verifying the report.
    * `:claimed` - `:success`, `:failure`, or `:none`, as the report states.
    * `:observations` - at most 256 `%{source: ..., result: :confirms | :contradicts}`
      maps from sources other than the report issuer.
    * `:required_observations` - positive integer.
    * `:issuer` - optional identifier of the report issuer.

  `:authentication` and `:claimed` are returned unchanged. `:acceptance` is
  `:rejected` when any observation contradicts, `:accepted` when at least
  `:required_observations` distinct sources confirm, and `:undetermined`
  otherwise. The report's own claim is never an observation.
  """
  @doc since: "1.1.0"
  @spec classify_outcome(term()) :: {:ok, outcome()} | {:error, :invalid_outcome_input}
  def classify_outcome(input), do: Outcome.classify(input)

  @doc """
  Build the audit values for a physical-effect operation.

  The input is an atom-keyed closed map with `:state` (a ledger state) and
  optional `:binding_digest`, `:operation_key`, `:refusal`, and `:outcome`
  (the map `classify_outcome/1` returned). `:refusal` is an admission refusal,
  valid with state `:refused`, or one of the ledger results
  `:operation_already_claimed` and `:operation_binding_conflict`.

  `result` is the ledger state. `result_info.success` is `true` only for an
  accepted outcome, `false` for a rejected one, and `nil` otherwise. Pass
  `result` and `metadata` to `SigilGuard.Audit.new_event/5` and set
  `result_info` on the event. The audit chain covers `result` only.
  """
  @doc since: "1.1.0"
  @spec audit_fields(term()) :: {:ok, audit_fields()} | {:error, :invalid_audit_input}
  def audit_fields(input), do: Outcome.audit_fields(input)

  defp admit_options(opts) do
    with true <- Keyword.keyword?(opts),
         [] <- Keyword.keys(opts) -- [:max_fact_age_ms, :envelope],
         {:ok, age} when is_integer(age) and age > 0 <- Keyword.fetch(opts, :max_fact_age_ms) do
      {:ok, %{max_fact_age_ms: age, envelope: Keyword.fetch(opts, :envelope)}}
    else
      _ -> {:error, :invalid_options}
    end
  end

  # A confirmed decision guarded with `effect_binding: :off` carries the same
  # action digest as a physical-effect approval. Only the effect metadata shows
  # that the gateway applied the physical-effect checks to this record.
  defp authorized(
         %Decision{
           verdict: :allowed,
           action: :allow,
           audit_metadata:
             %{
               action_digest: action_digest,
               effect_binding: :valid,
               effect_binding_digest: binding_digest,
               effect_operation_key: operation_key
             } = metadata
         },
         request,
         record,
         bound_context
       )
       when is_binary(action_digest) do
    payload = SecurityPayload.for_gate(request, :request, protocol_opts(metadata))

    with ^binding_digest <- jcs_digest(record),
         ^operation_key <- operation_digest(record),
         {:ok, expires_at} <- authority_expiry(metadata),
         :ok <- SigilGuard.Limits.check(payload),
         {:ok, ^action_digest} <- Confirmation.fetch_action_digest(payload, bound_context) do
      {:ok, %{expires_at: expires_at, manifest_digest: metadata[:manifest_digest]}}
    else
      _ -> {:error, :not_authorized}
    end
  end

  defp authorized(_, _, _, _), do: {:error, :not_authorized}

  # The gateway records no expiry for a decision the policy allowed without a
  # token or an attestation; the operation deadline alone bounds it.
  defp authority_expiry(metadata) do
    case Map.get(metadata, :effect_authority_expires_at) do
      nil -> {:ok, nil}
      expires_at -> authority_instant(SigilGuard.Clock.parse(expires_at))
    end
  end

  defp authority_instant({:ok, datetime}), do: {:ok, DateTime.to_unix(datetime, :millisecond)}
  defp authority_instant(:error), do: :error

  defp protocol_opts(%{protocol_version: version}) when is_binary(version),
    do: [protocol_version: version]

  defp protocol_opts(_), do: []

  defp fresh(%{now: now, observed_at: observed_at}, max_age)
       when observed_at <= now and now - observed_at <= max_age,
       do: :ok

  defp fresh(_, _), do: {:error, :stale_current_facts}

  defp conditions(record, facts, actor) do
    target = record["target"]

    with :ok <- Record.check(facts.principal == actor, :principal_mismatch),
         :ok <- Record.check(target["id"] == facts.target["id"], :target_mismatch),
         :ok <-
           Record.check(
             target["environment"] == facts.target["environment"],
             :target_environment_mismatch
           ),
         :ok <- Record.check(artifact_digests(record) == facts.artifacts, :artifact_mismatch),
         :ok <-
           Record.check(
             record["frame_revision"] == facts.frame_revision,
             :frame_revision_mismatch
           ),
         :ok <- Record.check(record["policy_epoch"] == facts.policy_epoch, :policy_epoch_mismatch) do
      window(record, facts.now)
    end
  end

  defp unexpired(expires_at, now) when is_nil(expires_at) or now <= expires_at, do: :ok
  defp unexpired(_, _), do: {:error, :authority_expired}

  defp artifact_digests(%{"artifacts" => artifacts}),
    do: Map.new(artifacts, &{&1["name"], &1["sha256"]})

  defp artifact_digests(_), do: nil

  defp window(record, now) do
    cond do
      now < unix_ms(record["not_before"], now) -> {:error, :effect_not_yet_valid}
      now > unix_ms(record["not_after"], now) -> {:error, :effect_deadline_passed}
      true -> :ok
    end
  end

  defp unix_ms(nil, absent), do: absent

  defp unix_ms(timestamp, _) do
    {:ok, datetime} = SigilGuard.Clock.parse(timestamp)
    DateTime.to_unix(datetime, :millisecond)
  end

  defp operation_digest(record) do
    jcs_digest(%{"operation_id" => record["operation_id"], "target_id" => record["target"]["id"]})
  end

  # A validated record holds ASCII strings only, which JCS always encodes.
  defp jcs_digest(value) do
    {:ok, digest} = Crypto.jcs_sha256_hex(value)
    digest
  end
end

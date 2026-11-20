defmodule SigilGuard.EffectAuthority.Outcome do
  @moduledoc false

  alias SigilGuard.Audit.ExecutionResult
  alias SigilGuard.EffectAuthority.Record

  @transitions %{
    claimed: [:refused, :dispatched],
    refused: [],
    dispatched: [:acknowledged, :cancel_requested, :failed, :unknown],
    acknowledged: [:finished, :failed, :cancel_requested, :unknown],
    cancel_requested: [:cancelled, :finished, :failed, :unknown],
    unknown: [:finished, :failed, :cancelled],
    finished: [],
    failed: [],
    cancelled: []
  }

  @authentication [:verified, :unsigned, :invalid]
  @claimed [:success, :failure, :none]
  @acceptance [:accepted, :rejected, :undetermined]
  @observation_results [:confirms, :contradicts]
  @max_observations 256

  @admission_refusals [
    :invalid_options,
    :not_authorized,
    :effect_binding_required,
    :invalid_effect_binding,
    :invalid_current_facts,
    :stale_current_facts,
    :principal_mismatch,
    :target_mismatch,
    :target_environment_mismatch,
    :artifact_mismatch,
    :frame_revision_mismatch,
    :policy_epoch_mismatch,
    :effect_not_yet_valid,
    :effect_deadline_passed,
    :unknown_effect_envelope,
    :invalid_effect_envelope,
    :effect_envelope_mismatch,
    :effect_envelope_expired,
    :target_out_of_envelope,
    :operation_out_of_envelope,
    :parameter_out_of_envelope
  ]
  @claim_results [:operation_already_claimed, :operation_binding_conflict]

  @doc false
  @spec valid_transition?(term(), term()) :: boolean()
  def valid_transition?(from, to), do: to in Map.get(@transitions, from, [])

  @doc false
  @spec classify(term()) ::
          {:ok, SigilGuard.EffectAuthority.outcome()} | {:error, :invalid_outcome_input}
  def classify(input) do
    with true <-
           closed?(input, [:authentication, :claimed, :observations, :required_observations], [
             :issuer
           ]),
         true <- input.authentication in @authentication and input.claimed in @claimed,
         true <- is_integer(input.required_observations) and input.required_observations > 0,
         true <- absent_or_identifier?(input, :issuer),
         {:ok, observations} <- observations(input.observations, input[:issuer]) do
      {:ok,
       %{
         authentication: input.authentication,
         claimed: input.claimed,
         acceptance: acceptance(observations, input.required_observations)
       }}
    else
      _ -> {:error, :invalid_outcome_input}
    end
  end

  @doc false
  @spec audit_fields(term()) ::
          {:ok, SigilGuard.EffectAuthority.audit_fields()} | {:error, :invalid_audit_input}
  def audit_fields(input) do
    with true <- closed?(input, [:state], [:binding_digest, :operation_key, :refusal, :outcome]),
         true <- is_map_key(@transitions, input.state),
         true <- absent_or?(input, :binding_digest, &SigilGuard.Crypto.sha256_hex?/1),
         true <- absent_or?(input, :operation_key, &SigilGuard.Crypto.sha256_hex?/1),
         true <- absent_or?(input, :refusal, &refusal?(&1, input.state)),
         true <- absent_or?(input, :outcome, &outcome?/1) do
      {:ok,
       %{
         result: Atom.to_string(input.state),
         result_info: %ExecutionResult{success: success(input[:outcome])},
         metadata: metadata(input)
       }}
    else
      _ -> {:error, :invalid_audit_input}
    end
  end

  defp closed?(input, required, optional) when is_map(input) and not is_struct(input) do
    keys = Map.keys(input)

    Enum.all?(required, &(&1 in keys)) and
      Enum.all?(keys, &(&1 in required or &1 in optional))
  end

  defp closed?(_, _, _), do: false

  defp absent_or_identifier?(input, key), do: absent_or?(input, key, &Record.identifier?/1)

  defp absent_or?(input, key, valid?) do
    case Map.fetch(input, key) do
      {:ok, value} -> valid?.(value)
      :error -> true
    end
  end

  defp observations(observations, issuer) do
    if Record.bounded_list?(observations, @max_observations) and
         Enum.all?(observations, &observation?(&1, issuer)) do
      {:ok, observations}
    else
      :error
    end
  end

  defp observation?(%{source: source, result: result} = observation, issuer)
       when map_size(observation) == 2,
       do: Record.identifier?(source) and source != issuer and result in @observation_results

  defp observation?(_, _), do: false

  defp acceptance(observations, required) do
    confirming = for %{result: :confirms, source: source} <- observations, uniq: true, do: source

    cond do
      Enum.any?(observations, &(&1.result == :contradicts)) -> :rejected
      length(confirming) >= required -> :accepted
      true -> :undetermined
    end
  end

  defp refusal?(refusal, :refused) when refusal in @admission_refusals, do: true
  defp refusal?(refusal, _), do: refusal in @claim_results

  defp outcome?(
         %{authentication: authentication, claimed: claimed, acceptance: acceptance} = outcome
       )
       when map_size(outcome) == 3,
       do: authentication in @authentication and claimed in @claimed and acceptance in @acceptance

  defp outcome?(_), do: false

  defp success(%{acceptance: :accepted}), do: true
  defp success(%{acceptance: :rejected}), do: false
  defp success(_), do: nil

  defp metadata(input) do
    outcome = Map.get(input, :outcome, %{})

    [
      {"effect_state", input.state},
      {"effect_binding_digest", input[:binding_digest]},
      {"effect_operation_key", input[:operation_key]},
      {"effect_refusal", input[:refusal]},
      {"effect_authentication", outcome[:authentication]},
      {"effect_claimed", outcome[:claimed]},
      {"effect_acceptance", outcome[:acceptance]}
    ]
    |> Enum.reject(fn {_, value} -> is_nil(value) end)
    |> Map.new(fn {key, value} -> {key, to_string(value)} end)
  end
end

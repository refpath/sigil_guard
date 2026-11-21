defmodule SigilGuard.ToolGateway.Effect do
  @moduledoc false

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.EffectAuthority

  @type digests :: %{
          action_digest: String.t(),
          payload_digest: String.t(),
          context_digest: String.t()
        }

  @type t :: %__MODULE__{
          mode: :off | :required | :invalid,
          replay_protected?: boolean(),
          digests: {:ok, digests()} | :error,
          record: {:ok, map()} | {:error, :effect_binding_required | :invalid_effect_binding},
          binding_digest: String.t() | nil,
          operation_key: String.t() | nil
        }

  @type denial ::
          :invalid_effect_binding
          | :effect_binding_required
          | :effect_replay_protection_required
          | :invalid_payload

  @budget_keys [:max_input_bytes, :max_input_nodes, :max_input_depth]

  defstruct mode: :off,
            replay_protected?: true,
            digests: :error,
            record: {:error, :effect_binding_required},
            binding_digest: nil,
            operation_key: nil

  @doc false
  @spec new(term(), map(), Context.t(), keyword()) :: t()
  def new(request, payload, %Context{} = context, opts) do
    case Keyword.get(opts, :effect_binding, :off) do
      :off -> %__MODULE__{}
      :required -> required(request, payload, context, opts)
      _ -> %__MODULE__{mode: :invalid}
    end
  end

  @doc false
  @spec check_option(t()) :: :ok | {:error, :invalid_effect_binding}
  def check_option(%__MODULE__{mode: :invalid}), do: {:error, :invalid_effect_binding}
  def check_option(%__MODULE__{}), do: :ok

  @doc false
  @spec check_request(t()) :: :ok | {:error, denial()}
  def check_request(%__MODULE__{mode: :required, replay_protected?: false}),
    do: {:error, :effect_replay_protection_required}

  def check_request(%__MODULE__{mode: :required, digests: :error}),
    do: {:error, :invalid_payload}

  def check_request(%__MODULE__{mode: :required, record: {:error, reason}}),
    do: {:error, reason}

  def check_request(%__MODULE__{}), do: :ok

  @doc false
  @spec metadata(t()) :: map()
  def metadata(%__MODULE__{mode: :required} = effect) do
    Map.merge(digest_metadata(effect.digests), binding_metadata(effect))
  end

  def metadata(%__MODULE__{}), do: %{}

  @doc false
  @spec put_authority_expiry(Decision.t(), DateTime.t() | nil) :: Decision.t()
  def put_authority_expiry(%Decision{audit_metadata: metadata} = decision, attestation_until) do
    expiries =
      Enum.flat_map(
        [metadata[:confirmation_expires_at], attestation_until],
        &instant/1
      )

    case expiries do
      [] ->
        decision

      _ ->
        expires_at = timestamp(Enum.min(expiries, DateTime))
        %{decision | audit_metadata: Map.put(metadata, :effect_authority_expires_at, expires_at)}
    end
  end

  defp instant(%DateTime{} = datetime), do: [datetime]

  # The token's expiry parsed when the token verified.
  defp instant(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> [datetime]
      {:error, _} -> []
    end
  end

  defp instant(_), do: []

  # The SP.01 timestamp form. Dropping sub-millisecond digits can only move
  # the expiry earlier.
  defp timestamp(datetime) do
    datetime
    |> DateTime.to_unix(:millisecond)
    |> DateTime.from_unix!(:millisecond)
    |> DateTime.to_iso8601()
  end

  defp required(request, payload, context, opts) do
    record = EffectAuthority.fetch_binding(request)

    %__MODULE__{
      mode: :required,
      replay_protected?: SigilGuard.Options.flag(opts, :consume_confirmation, true, false),
      digests: digests(payload, context, opts),
      record: record,
      binding_digest: record_digest(record, &EffectAuthority.binding_digest/1),
      operation_key: record_digest(record, &EffectAuthority.operation_key/1)
    }
  end

  # The digests are computed before the runtime gate, so the gate's input
  # budget is checked first. The payload digest applies the default budget and
  # runs before the action digest, whose legacy encoder applies none.
  defp digests(payload, context, opts) do
    with :ok <- SigilGuard.Limits.check(payload, Keyword.take(opts, @budget_keys)),
         {:ok, payload_digest} <- Digest.payload_digest(payload),
         {:ok, action_digest} <- Confirmation.fetch_action_digest(payload, context),
         {:ok, context_digest} <- Digest.context_digest(context.phase, context) do
      {:ok,
       %{
         action_digest: action_digest,
         payload_digest: payload_digest,
         context_digest: context_digest
       }}
    else
      {:error, _} -> :error
    end
  end

  defp record_digest({:ok, record}, digest) do
    {:ok, value} = digest.(record)
    value
  end

  defp record_digest({:error, _}, _), do: nil

  defp digest_metadata({:ok, digests}), do: digests
  defp digest_metadata(:error), do: %{}

  defp binding_metadata(%__MODULE__{record: {:ok, _}} = effect) do
    %{
      effect_binding: :valid,
      effect_binding_digest: effect.binding_digest,
      effect_operation_key: effect.operation_key
    }
  end

  defp binding_metadata(%__MODULE__{record: {:error, :effect_binding_required}}),
    do: %{effect_binding: :absent}

  defp binding_metadata(%__MODULE__{}), do: %{effect_binding: :invalid}
end

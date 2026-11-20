defmodule SigilGuard.ToolGateway.Effect do
  @moduledoc false

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
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

  defp required(request, payload, context, opts) do
    record = EffectAuthority.fetch_binding(request)

    %__MODULE__{
      mode: :required,
      replay_protected?: Keyword.get(opts, :consume_confirmation, true) not in [false, nil],
      digests: digests(payload, context),
      record: record,
      binding_digest: record_digest(record, &EffectAuthority.binding_digest/1),
      operation_key: record_digest(record, &EffectAuthority.operation_key/1)
    }
  end

  defp digests(payload, context) do
    with {:ok, action_digest} <- Confirmation.fetch_action_digest(payload, context),
         {:ok, payload_digest} <- Digest.payload_digest(payload),
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

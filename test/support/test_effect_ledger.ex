defmodule SigilGuard.TestEffectLedger do
  @moduledoc """
  In-memory stand-in for a host's durable effect ledger (SP.19 PE.28 to PE.31).

  The ledger keeps one record per operation key and survives a
  `SigilGuard.Runtime` restart because it runs in its own process. It also
  records every command "sent" to the target, so a test can count dispatches.
  It is a test double: a real ledger is durable storage shared by every host
  instance that can reach the target.
  """

  use Agent

  alias SigilGuard.Decision
  alias SigilGuard.EffectAuthority

  @in_flight [:dispatched, :acknowledged, :cancel_requested]

  @type ledger_record :: %{
          operation_key: String.t(),
          payload_digest: String.t(),
          context_digest: String.t(),
          binding_digest: String.t()
        }

  @doc "Start an empty ledger. Pass `:name` to register it."
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts \\ []) do
    Agent.start_link(fn -> %{records: %{}, commands: []} end, Keyword.take(opts, [:name]))
  end

  @doc "Build the ledger record from the digests a gateway decision records."
  @spec record(Decision.t()) :: ledger_record()
  def record(%Decision{audit_metadata: metadata}) do
    %{
      operation_key: metadata.effect_operation_key,
      payload_digest: metadata.payload_digest,
      context_digest: metadata.context_digest,
      binding_digest: metadata.effect_binding_digest
    }
  end

  @doc """
  Claim an operation key with create-if-absent semantics.

  An existing key with equal digests returns the recorded state. An existing
  key with different digests is a conflict.
  """
  @spec claim(Agent.agent(), ledger_record()) ::
          :claimed | {:operation_already_claimed, atom()} | :operation_binding_conflict
  def claim(ledger, %{operation_key: key} = record) do
    digests = Map.delete(record, :operation_key)

    Agent.get_and_update(ledger, fn state ->
      case state.records do
        %{^key => %{digests: ^digests, state: existing}} ->
          {{:operation_already_claimed, existing}, state}

        %{^key => _} ->
          {:operation_binding_conflict, state}

        _ ->
          {:claimed, put_in(state.records[key], %{digests: digests, state: :claimed})}
      end
    end)
  end

  @doc "Move a record to `to` when `EffectAuthority.valid_transition?/2` allows it."
  @spec transition(Agent.agent(), String.t(), atom()) :: :ok | {:error, :invalid_transition}
  def transition(ledger, key, to) do
    Agent.get_and_update(ledger, fn state ->
      from = get_in(state.records, [key, :state])

      if EffectAuthority.valid_transition?(from, to) do
        {:ok, put_in(state.records[key].state, to)}
      else
        {{:error, :invalid_transition}, state}
      end
    end)
  end

  @doc "Record `to` and note that a command for `key` went to the target."
  @spec dispatch(Agent.agent(), String.t()) :: :ok | {:error, :invalid_transition}
  def dispatch(ledger, key) do
    with :ok <- transition(ledger, key, :dispatched) do
      Agent.update(ledger, &update_in(&1.commands, fn commands -> [key | commands] end))
    end
  end

  @doc "Return the state recorded for `key`, or `nil`."
  @spec state(Agent.agent(), String.t()) :: atom() | nil
  def state(ledger, key), do: Agent.get(ledger, &get_in(&1.records, [key, :state]))

  @doc "Return the operation keys of the commands sent to the target, oldest first."
  @spec commands(Agent.agent()) :: [String.t()]
  def commands(ledger), do: Agent.get(ledger, &Enum.reverse(&1.commands))

  @doc """
  Apply the restart rule of PE.31.

  A record that was in flight becomes `:unknown`. A `:claimed` record is left
  for the host to resume at the admission step. Nothing is dispatched.
  """
  @spec restart(Agent.agent()) :: :ok
  def restart(ledger) do
    Agent.update(ledger, fn state ->
      %{state | records: Map.new(state.records, &interrupt/1)}
    end)
  end

  defp interrupt({key, %{state: state} = record}) when state in @in_flight,
    do: {key, %{record | state: :unknown}}

  defp interrupt(entry), do: entry
end

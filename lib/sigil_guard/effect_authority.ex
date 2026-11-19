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

  alias SigilGuard.Canonical.JCS
  alias SigilGuard.EffectAuthority.Record

  @doc """
  Reads the binding record from a request and validates it.

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
  Validates a binding record against the closed schema.

  Unknown keys, wrong types, identifiers outside 1 to 256 bytes of printable
  ASCII, unsorted or duplicate artifacts, and a `not_before` that is not
  earlier than `not_after` are refused.
  """
  @doc since: "1.1.0"
  @spec validate_binding(term()) :: :ok | {:error, :invalid_effect_binding}
  def validate_binding(record), do: Record.validate(record)

  @doc """
  Returns the lowercase-hex SHA-256 of the record's JCS bytes.
  """
  @doc since: "1.1.0"
  @spec binding_digest(term()) :: {:ok, String.t()} | {:error, :invalid_effect_binding}
  def binding_digest(record) do
    with :ok <- Record.validate(record), do: jcs_digest(record, :invalid_effect_binding)
  end

  @doc """
  Returns the ledger key for the operation a record names.

  The key is the lowercase-hex SHA-256 of the JCS bytes of
  `{"operation_id": ..., "target_id": ...}`. Two records for the same operation
  on the same target share a key whatever else they contain.
  """
  @doc since: "1.1.0"
  @spec operation_key(term()) :: {:ok, String.t()} | {:error, :invalid_effect_binding}
  def operation_key(record) do
    with :ok <- Record.validate(record) do
      jcs_digest(
        %{"operation_id" => record["operation_id"], "target_id" => record["target"]["id"]},
        :invalid_effect_binding
      )
    end
  end

  defp jcs_digest(value, error) do
    case JCS.encode(value) do
      {:ok, bytes} -> {:ok, Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}
      {:error, _} -> {:error, error}
    end
  end
end

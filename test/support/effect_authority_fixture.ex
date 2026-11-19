defmodule SigilGuard.EffectAuthorityFixture do
  @moduledoc """
  Neutral fixtures for the SP.19 physical-effect tests.

  `request/0` is the baseline request `R0`. Its binding record names a
  synthetic physical target and carries no production identifier.
  """

  alias SigilGuard.FixturePath

  @record_key "dev.sigilguard/effect"

  @doc "Return the baseline `tools/call` request with its binding record."
  @spec request() :: map()
  def request, do: FixturePath.read_json!("effect_authority/request.json")

  @doc "Return the binding record carried by `request/0`."
  @spec record() :: map()
  def record, do: request()["params"]["_meta"][@record_key]

  @doc "Return `request` with its binding record replaced by `record`."
  @spec put_record(map(), term()) :: map()
  def put_record(request, record),
    do: put_in(request, ["params", "_meta", @record_key], record)
end

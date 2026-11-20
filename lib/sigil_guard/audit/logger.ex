defmodule SigilGuard.Audit.Logger do
  @moduledoc """
  Behaviour for audit event persistence backends.

  A host implements `log/1` to write each event to storage it owns.

  ## Example

      defmodule MyApp.DbAuditLogger do
        @behaviour SigilGuard.Audit.Logger

        @impl true
        def log(event) do
          %MyApp.AuditLog{}
          |> MyApp.AuditLog.changeset(event_to_map(event))
          |> MyApp.Repo.insert!()
          :ok
        end
      end

  """

  @doc "Persist an audit event. Returns `:ok` on success."
  @callback log(event :: SigilGuard.Audit.t()) :: :ok | {:error, term()}
end

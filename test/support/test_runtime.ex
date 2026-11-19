defmodule SigilGuard.TestRuntime do
  @moduledoc false

  @doc "Restart the application-supervised runtime, discarding its per-boot ETS state."
  @spec restart() :: :ok
  def restart do
    :ok = Supervisor.terminate_child(SigilGuard.Supervisor, SigilGuard.Runtime)
    {:ok, _} = Supervisor.restart_child(SigilGuard.Supervisor, SigilGuard.Runtime)
    :ok
  end
end

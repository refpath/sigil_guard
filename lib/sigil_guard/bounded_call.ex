defmodule SigilGuard.BoundedCall do
  @moduledoc false

  # Runs a host callback (a boundary hook or an adaptive detector) in its own
  # process, with a time limit, and binds that process to the caller's
  # lifetime.
  #
  # The callback runs apart from the caller so that a crash, an exit or an
  # endless loop in host code becomes a result and not the caller's fate. A
  # monitor, not a link, connects the two for that reason: a link would carry
  # a kill signal back to the caller.
  #
  # A monitor alone leaves the worker running when the caller dies first,
  # since only the caller enforces the time limit. The worker therefore starts
  # a watcher that kills it when the caller goes down. The watcher ends with
  # whichever of the two ends first, so no process outlives the call.

  @default_timeout_ms 5_000
  @max_timeout_ms 4_294_967_295

  @typedoc "The callback's value, or how it failed to produce one."
  @type result :: {:ok, term()} | :crash | :timeout

  @doc false
  @spec timeout(keyword()) :: {:ok, non_neg_integer()} | :error
  def timeout(opts) do
    case Keyword.get(opts, :hook_timeout_ms, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout >= 0 and timeout <= @max_timeout_ms ->
        {:ok, timeout}

      _ ->
        :error
    end
  end

  @doc false
  @spec run((-> term()), timeout()) :: result()
  def run(fun, timeout) when is_function(fun, 0) do
    caller = self()
    ref = make_ref()

    {worker, monitor} =
      spawn_monitor(fn ->
        watch(caller, self())
        send(caller, {ref, safe_call(fun)})
      end)

    receive do
      {^ref, outcome} ->
        Process.demonitor(monitor, [:flush])
        outcome

      {:DOWN, ^monitor, :process, ^worker, _} ->
        :crash
    after
      timeout ->
        stop(worker, monitor, ref)
        :timeout
    end
  end

  # The worker may have sent its result just before the kill reached it.
  # Waiting for it to be down and then taking that message keeps the caller's
  # mailbox free of anything from this call.
  defp stop(worker, monitor, ref) do
    Process.exit(worker, :kill)

    receive do
      {:DOWN, ^monitor, :process, ^worker, _} -> :ok
    end

    receive do
      {^ref, _} -> :ok
    after
      0 -> :ok
    end
  end

  # A caller that is already dead gives the watcher an immediate `:DOWN`, so
  # there is no window in which the worker runs unwatched.
  defp watch(caller, worker) do
    spawn(fn ->
      caller_monitor = Process.monitor(caller)
      worker_monitor = Process.monitor(worker)

      receive do
        {:DOWN, ^caller_monitor, :process, _, _} -> Process.exit(worker, :kill)
        {:DOWN, ^worker_monitor, :process, _, _} -> :ok
      end
    end)
  end

  # Caught in the worker so that a failing callback is a result and produces
  # no crash report. An exit that cannot be caught reaches the caller as
  # `:DOWN`.
  defp safe_call(fun) do
    {:ok, fun.()}
  rescue
    _ -> :crash
  catch
    _, _ -> :crash
  end
end

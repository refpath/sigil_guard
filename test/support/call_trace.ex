defmodule SigilGuard.CallTrace do
  @moduledoc false

  # Counts calls the test process makes to one exported function, so a test
  # can show that a refusal skipped work instead of discarding its result.
  # The tracer is a separate process: a process traced with itself as the
  # tracer receives no call messages.

  @doc "Run `fun` and return its result with the number of calls to `mfa`."
  @spec count(mfa(), (-> result)) :: {result, non_neg_integer()} when result: term()
  def count({module, _, _} = mfa, fun) do
    Code.ensure_loaded!(module)
    tracer = spawn_link(fn -> collect(mfa, 0) end)
    1 = :erlang.trace_pattern(mfa, true, [:global])
    1 = :erlang.trace(self(), true, [:call, {:tracer, tracer}])

    result =
      try do
        fun.()
      after
        :erlang.trace(self(), false, [:call])
        :erlang.trace_pattern(mfa, false, [:global])
      end

    ref = :erlang.trace_delivered(self())

    receive do
      {:trace_delivered, _, ^ref} -> :ok
    end

    send(tracer, {:count, self()})

    receive do
      {:call_count, ^tracer, calls} -> {result, calls}
    end
  end

  defp collect({module, function, arity} = mfa, calls) do
    receive do
      {:trace, _, :call, {^module, ^function, args}} when length(args) == arity ->
        collect(mfa, calls + 1)

      {:count, from} ->
        send(from, {:call_count, self(), calls})
    end
  end
end

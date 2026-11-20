defmodule SigilGuard.BoundedCallTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundedCall

  defp wait_until_dead(pid) do
    monitor = Process.monitor(pid)

    receive do
      {:DOWN, ^monitor, :process, ^pid, _} -> :dead
    after
      1_000 -> :alive
    end
  end

  test "returns the callback's value" do
    assert BoundedCall.run(fn -> {:value, 7} end, 1_000) == {:ok, {:value, 7}}
    assert BoundedCall.run(fn -> nil end, 1_000) == {:ok, nil}
  end

  test "a raise, a throw, an exit and a kill are each a crash, not the caller's" do
    for failing <- [
          fn -> raise "boom" end,
          fn -> throw(:boom) end,
          fn -> exit(:boom) end,
          fn -> :erlang.error(:badarg) end,
          fn -> Process.exit(self(), :kill) end
        ] do
      assert BoundedCall.run(failing, 1_000) == :crash
    end

    assert Process.alive?(self())
  end

  test "a callback that outlasts the limit is killed" do
    test = self()

    assert BoundedCall.run(
             fn ->
               send(test, {:worker, self()})
               Process.sleep(:infinity)
             end,
             20
           ) == :timeout

    assert_receive {:worker, worker}
    assert wait_until_dead(worker) == :dead
  end

  test "the worker dies with its caller, however the caller ends" do
    test = self()

    for exit_reason <- [:normal, :shutdown, :kill] do
      caller =
        spawn(fn ->
          BoundedCall.run(
            fn ->
              send(test, {:worker, self()})
              Process.sleep(:infinity)
            end,
            :infinity
          )
        end)

      assert_receive {:worker, worker}
      assert Process.alive?(worker)

      Process.exit(caller, exit_reason)

      # A `:normal` exit signal from another process is ignored, so stop the
      # caller the way a finished process stops.
      if exit_reason == :normal, do: Process.exit(caller, :kill)

      assert wait_until_dead(caller) == :dead
      assert wait_until_dead(worker) == :dead, "worker survived a caller exit: #{exit_reason}"
    end
  end

  test "a caller that returns normally leaves no process behind" do
    test = self()

    caller =
      spawn(fn ->
        result =
          BoundedCall.run(
            fn ->
              send(test, {:worker, self()})
              :done
            end,
            1_000
          )

        send(test, {:result, result})
      end)

    assert_receive {:worker, worker}
    assert_receive {:result, {:ok, :done}}
    assert wait_until_dead(worker) == :dead
    assert wait_until_dead(caller) == :dead
  end

  test "no message of the call is left in the caller's mailbox" do
    assert BoundedCall.run(fn -> :ok end, 1_000) == {:ok, :ok}
    assert BoundedCall.run(fn -> Process.sleep(:infinity) end, 10) == :timeout
    assert BoundedCall.run(fn -> exit(:boom) end, 1_000) == :crash

    refute_receive _, 50
  end
end

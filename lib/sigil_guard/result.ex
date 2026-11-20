defmodule SigilGuard.Result do
  @moduledoc false

  # Applies `fun` to each element in order. Every element must produce
  # `{:ok, value}`; the first element that produces anything else stops the
  # walk, and that value is returned unchanged.

  @doc false
  @spec map_ok(list(), (term() -> {:ok, value} | other)) :: {:ok, [value]} | other
        when value: term(), other: term()
  def map_ok(list, fun) when is_list(list), do: map_ok(list, fun, [])

  defp map_ok([], _, acc), do: {:ok, Enum.reverse(acc)}

  defp map_ok([item | rest], fun, acc) do
    case fun.(item) do
      {:ok, value} -> map_ok(rest, fun, [value | acc])
      other -> other
    end
  end
end

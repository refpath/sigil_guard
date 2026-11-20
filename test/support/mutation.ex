defmodule SigilGuard.TestMutation do
  @moduledoc """
  Generators for hostile input: arbitrary JSON-like terms and single-point
  mutations of a valid fixture.

  A mutated fixture reaches code that a random term never does, because every
  other field still passes validation. Neither generator creates atoms, so a
  property that uses them can also assert that the atom table does not grow.
  """

  import StreamData, except: [term: 0]

  @atoms [
    :allow,
    :block,
    :confirm,
    :tool_request,
    :tool_result,
    :model,
    :tool,
    :high,
    :low,
    :untrusted,
    :off,
    :required,
    :bogus,
    true,
    false,
    nil
  ]
  @keys [
    "params",
    "name",
    "arguments",
    "_meta",
    "result",
    "content",
    "payload",
    "signatures",
    "keyid",
    "sig",
    "id",
    "method",
    "tool",
    :params,
    :name,
    :tool,
    :result,
    :_meta
  ]
  @digest String.duplicate("a", 64)

  @doc "Generate a JSON-like term, including shapes a JSON decoder never returns."
  @spec term() :: StreamData.t(term())
  def term do
    tree(leaf(), fn child ->
      one_of([
        list_of(child, max_length: 3),
        map_of(one_of([string(:alphanumeric, max_length: 6), member_of(@keys)]), child,
          max_length: 3
        )
      ])
    end)
  end

  @doc """
  Generate `fixture` with one node replaced by a term, set to `nil`, or removed.
  """
  @spec mutant(term()) :: StreamData.t(term())
  def mutant(fixture) do
    {member_of(paths(fixture, [])), integer(0..9), term()}
    |> tuple()
    |> map(fn {path, choice, value} -> mutate(fixture, Enum.reverse(path), choice, value) end)
  end

  defp leaf do
    one_of([
      integer(),
      constant(9_007_199_254_740_993),
      float(),
      binary(max_length: 12),
      string(:printable, max_length: 12),
      member_of(@atoms),
      constant(~U[2026-11-19 12:01:00.000Z]),
      constant({1, 2}),
      constant(@digest),
      constant(@digest <> "\n"),
      constant(""),
      constant(%{}),
      constant([]),
      constant(improper_list())
    ])
  end

  # `[1 | 2]`, decoded at run time so the literal does not trip Dialyzer.
  defp improper_list, do: :erlang.binary_to_term(<<131, 108, 0, 0, 0, 1, 97, 1, 97, 2>>)

  defp mutate(_, [], _, value), do: value
  defp mutate(fixture, path, 0, _), do: drop(fixture, path)
  defp mutate(fixture, path, 1, _), do: put(fixture, path, nil)
  defp mutate(fixture, path, _, value), do: put(fixture, path, value)

  # Paths are built in reverse and reversed once, when a path is chosen.
  defp paths(map, prefix) when is_map(map) and not is_struct(map) do
    [prefix | Enum.flat_map(map, fn {key, value} -> paths(value, [{:key, key} | prefix]) end)]
  end

  defp paths([_ | _] = list, prefix) do
    indexed = Enum.with_index(list)

    [prefix | Enum.flat_map(indexed, fn {value, at} -> paths(value, [{:at, at} | prefix]) end)]
  end

  defp paths(_, prefix), do: [prefix]

  defp put(_, [], value), do: value

  defp put(map, [{:key, key} | rest], value),
    do: Map.put(map, key, put(Map.fetch!(map, key), rest, value))

  defp put(list, [{:at, at} | rest], value), do: List.update_at(list, at, &put(&1, rest, value))

  defp drop(map, [{:key, key}]), do: Map.delete(map, key)
  defp drop(list, [{:at, at}]), do: List.delete_at(list, at)

  defp drop(map, [{:key, key} | rest]),
    do: Map.put(map, key, drop(Map.fetch!(map, key), rest))

  defp drop(list, [{:at, at} | rest]), do: List.update_at(list, at, &drop(&1, rest))
end

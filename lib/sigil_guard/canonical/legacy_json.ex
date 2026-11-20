defmodule SigilGuard.Canonical.LegacyJSON do
  @moduledoc false

  # The sorted-key JSON form the audit, confirmation and repo policy digests
  # were defined over before JCS. Keys may be atoms, strings or numbers and
  # are compared as strings; structs, improper lists and values without a
  # JSON form have no canonical form.

  @typep canonical :: binary() | nonempty_list(list() | ?[ | ?] | ?{ | ?})

  @doc false
  @spec encode(term()) :: {:ok, canonical()} | :error
  def encode(value) when is_map(value) and not is_struct(value) do
    with {:ok, pairs} <- canonical_pairs(value),
         {:ok, parts} <- encode_pairs(Enum.sort_by(pairs, &elem(&1, 0)), []) do
      {:ok, [?{, Enum.intersperse(parts, ","), ?}]}
    end
  end

  def encode(value) when is_list(value) do
    with {:ok, items} <- encode_items(value, []) do
      {:ok, [?[, Enum.intersperse(items, ","), ?]]}
    end
  end

  def encode(value) when is_atom(value) and not is_boolean(value) and not is_nil(value),
    do: encode_scalar(Atom.to_string(value))

  def encode(value)
      when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value),
      do: encode_scalar(value)

  def encode(_), do: :error

  @doc false
  @spec encode!(term()) :: canonical()
  def encode!(value) do
    case encode(value) do
      {:ok, iodata} -> iodata
      :error -> raise ArgumentError, "value has no canonical JSON form"
    end
  end

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(value), do: encode(value) != :error

  defp encode_scalar(value) do
    case Jason.encode(value) do
      {:ok, json} -> {:ok, json}
      {:error, _} -> :error
    end
  end

  defp canonical_pairs(map) do
    pairs = for {key, item} <- map, do: {canonical_key(key), item}
    keys = for {key, _} <- pairs, do: key

    if Enum.all?(keys, &is_binary/1) and length(keys) == MapSet.size(MapSet.new(keys)),
      do: {:ok, pairs},
      else: :error
  end

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key
  defp canonical_key(key) when is_number(key), do: to_string(key)
  defp canonical_key(_), do: nil

  defp encode_pairs([], acc), do: {:ok, Enum.reverse(acc)}

  defp encode_pairs([{key, item} | rest], acc) do
    with {:ok, encoded_key} <- encode_scalar(key),
         {:ok, encoded_item} <- encode(item) do
      encode_pairs(rest, [[encoded_key, ?:, encoded_item] | acc])
    end
  end

  defp encode_items([], acc), do: {:ok, Enum.reverse(acc)}

  defp encode_items([head | tail], acc) do
    case encode(head) do
      {:ok, encoded} -> encode_items(tail, [encoded | acc])
      :error -> :error
    end
  end

  defp encode_items(_, _), do: :error
end

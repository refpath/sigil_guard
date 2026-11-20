defmodule SigilGuard.Field do
  @moduledoc false

  # Wire documents arrive with string keys and host-built maps often use atom
  # keys. The string key wins when both are present. Each caller passes its
  # own closed map from string key to atom, so external input never creates
  # an atom.

  @doc false
  @spec fetch(map(), String.t(), %{required(String.t()) => atom()}) :: {:ok, term()} | :error
  def fetch(map, key, atoms) do
    case Map.fetch(map, key) do
      {:ok, _} = found -> found
      :error -> Map.fetch(map, Map.fetch!(atoms, key))
    end
  end

  @doc false
  @spec get(map(), String.t(), %{required(String.t()) => atom()}) :: term()
  def get(map, key, atoms) do
    case fetch(map, key, atoms) do
      {:ok, value} -> value
      :error -> nil
    end
  end
end

defmodule SigilGuard.Level do
  @moduledoc false

  # Risk and trust share one ordered scale. `SigilGuard.Identity` and
  # `SigilGuard.Policy` keep their public comparison functions and delegate
  # here.

  import Kernel, except: [max: 2]

  @rank %{low: 0, medium: 1, high: 2}

  @doc false
  @spec compare(atom(), atom()) :: :lt | :eq | :gt
  def compare(a, b) do
    rank_a = Map.fetch!(@rank, a)
    rank_b = Map.fetch!(@rank, b)

    cond do
      rank_a < rank_b -> :lt
      rank_a > rank_b -> :gt
      true -> :eq
    end
  end

  # The higher of two levels, where nil means no signal. On a tie the first
  # argument wins.
  @doc false
  @spec max(atom() | nil, atom() | nil) :: atom() | nil
  def max(level, nil), do: level
  def max(nil, other), do: other
  def max(level, other), do: if(compare(other, level) == :gt, do: other, else: level)

  @doc false
  @spec strongest([atom()]) :: atom() | nil
  def strongest(levels), do: Enum.reduce(levels, nil, &max(&2, &1))

  # A value outside the scale counts as the weakest level.
  @doc false
  @spec clamp(term()) :: :low | :medium | :high
  def clamp(level) when is_map_key(@rank, level), do: level
  def clamp(_), do: :low
end

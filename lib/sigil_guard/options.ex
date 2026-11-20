defmodule SigilGuard.Options do
  @moduledoc false

  # A switch option is a boolean. A value of another type is not read by
  # truthiness: each caller names the reading that keeps its check strict, so
  # `nil` or a typo never switches a protection off or a relaxation on.

  @doc false
  @spec flag(keyword(), atom(), boolean(), boolean()) :: boolean()
  def flag(opts, key, default, strict) do
    case Keyword.get(opts, key, default) do
      value when is_boolean(value) -> value
      _ -> strict
    end
  end

  # A keyword list whose every key is one of `keys`.
  @doc false
  @spec only?(term(), [atom()]) :: boolean()
  def only?(opts, keys),
    do: Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in keys))
end

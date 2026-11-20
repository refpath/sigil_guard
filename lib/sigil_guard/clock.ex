defmodule SigilGuard.Clock do
  @moduledoc false

  # The library reads the wall clock here and nowhere else: a caller's `:now`
  # option wins, and every timestamp the library writes has millisecond
  # precision. Each caller names the reason a malformed `:now` returns, since
  # that reason is part of its own error contract.

  @doc false
  @spec timestamp() :: String.t()
  def timestamp, do: DateTime.to_iso8601(DateTime.utc_now(:millisecond))

  @doc false
  @spec now(keyword(), atom()) :: {:ok, DateTime.t()} | {:error, atom()}
  def now(opts, error) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, error}
    end
  end
end

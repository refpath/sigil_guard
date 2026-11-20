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

  # The one timestamp form the library's documents carry: UTC with exactly
  # three fractional digits, such as `2026-01-01T00:00:00.000Z`.
  @utc_milliseconds ~r/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\z/

  @doc false
  @spec parse(term()) :: {:ok, DateTime.t()} | :error
  def parse(value) when is_binary(value) do
    with true <- Regex.match?(@utc_milliseconds, value),
         {:ok, datetime, 0} <- DateTime.from_iso8601(value) do
      {:ok, datetime}
    else
      _ -> :error
    end
  end

  def parse(_), do: :error
end

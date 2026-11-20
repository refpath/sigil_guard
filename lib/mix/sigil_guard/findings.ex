defmodule Mix.SigilGuard.Findings do
  @moduledoc false

  # The finding shape, order and report format the repository's document
  # gates share.

  @type t :: %{
          required(:check) => atom(),
          required(:path) => String.t(),
          required(:line) => pos_integer() | nil,
          required(:message) => String.t()
        }

  @doc false
  @spec new(atom(), String.t(), pos_integer() | nil, String.t()) :: t()
  def new(check, path, line, message),
    do: %{check: check, path: path, line: line, message: message}

  @doc false
  @spec result([t()]) :: :ok | {:error, [t()]}
  def result([]), do: :ok
  def result(findings), do: {:error, Enum.sort_by(findings, &{&1.path, &1.line || 0, &1.check})}

  @doc false
  @spec format(String.t(), [t()]) :: String.t()
  def format(title, findings) do
    lines =
      Enum.map(findings, fn finding ->
        location = if finding.line, do: "#{finding.path}:#{finding.line}", else: finding.path
        "#{location}: #{finding.check}: #{finding.message}"
      end)

    title <> ":\n" <> Enum.join(lines, "\n")
  end
end

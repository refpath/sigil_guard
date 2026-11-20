defmodule SigilGuard.Runtime.OutputContract do
  @moduledoc false

  alias SigilGuard.BoundaryPolicy.Contract
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.Patterns
  alias SigilGuard.Scanner

  @pii_categories [:pii, "pii"]

  @type transform :: :credentials | :pii | :truncate
  @type outcome ::
          :none
          | {:crossed, binary() | nil, [transform()]}
          | {:block, String.t()}

  # Applies the contract the policy file declares for `sink` to content the
  # verdict lets cross. `text` is what the gate would release; `payload`
  # decides the content class. A text transform applies to a text payload
  # only: a structured payload that passes the class check crosses unchanged.
  @doc false
  @spec apply(term(), atom(), term(), binary() | nil, keyword()) :: outcome()
  def apply(%PolicyFile{contracts: contracts}, sink, payload, text, opts) when is_atom(sink) do
    case Map.get(contracts, Atom.to_string(sink)) do
      %Contract{} = contract -> enforce(contract, Atom.to_string(sink), payload, text, opts)
      nil -> :none
    end
  end

  def apply(_, _, _, _, _), do: :none

  defp enforce(contract, sink, payload, text, opts) when is_binary(payload) and is_binary(text) do
    with {:ok, credentials} <- credentials(contract, text),
         {:ok, pii} <- pii(contract, text, opts),
         {:ok, released} <-
           Contract.enforce(contract, sink, text, credentials: credentials, pii: pii) do
      {:crossed, released, transforms(contract, text, credentials, pii)}
    else
      :scan_failed -> {:block, "contract.#{sink}.scan"}
      {:block, rule_id} -> {:block, rule_id}
    end
  end

  defp enforce(contract, sink, payload, text, _) do
    case Contract.enforce(contract, sink, payload, []) do
      {:ok, _} -> {:crossed, text, []}
      {:block, rule_id} -> {:block, rule_id}
    end
  end

  # The re-scan uses the built-in secret patterns whatever pattern set the
  # host scanned with: it is the backstop for a set that misses a secret.
  defp credentials(%Contract{no_raw_credentials: false}, _), do: {:ok, []}

  defp credentials(%Contract{}, text),
    do: matches(text, [patterns: Patterns.built_in()], &Patterns.secret_category?/1)

  defp pii(%Contract{digest_only_pii: false}, _, _), do: {:ok, []}

  defp pii(%Contract{}, text, opts),
    do: matches(text, Keyword.take(opts, [:patterns, :pipeline]), &(&1 in @pii_categories))

  # A scan that cannot run leaves the contract unproven, so the crossing fails.
  defp matches(text, scan_opts, wanted?) do
    case Scanner.scan_result(text, scan_opts) do
      {:ok, _} -> {:ok, []}
      {:hit, hits} -> {:ok, for(hit <- hits, wanted?.(hit.category), do: hit.match)}
      {:error, _} -> :scan_failed
    end
  end

  defp transforms(contract, text, credentials, pii) do
    [
      credentials != [] and :credentials,
      pii != [] and :pii,
      is_integer(contract.max_size) and byte_size(text) > contract.max_size and :truncate
    ]
    |> Enum.filter(& &1)
  end
end

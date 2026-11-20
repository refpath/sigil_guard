defmodule SigilGuard.Quarantine do
  @moduledoc """
  Deterministic quarantine checks for untrusted tool and resource content.

  This is intentionally small and local: it catches common prompt-injection
  and tool-poisoning indicators before content is passed onward to a model
  or privileged tool. It is not a replacement for policy; it produces
  evidence for the runtime gate.
  """

  alias SigilGuard.Context

  @type verdict :: :safe | :suspicious | :blocked

  @type result :: %{
          verdict: verdict(),
          indicators: [map()],
          content_hash: String.t(),
          sanitized_text: String.t() | nil
        }

  # A built-in indicator can only match text that contains one of these words.
  # They are searched in an ASCII-lowercased copy, which is what a
  # case-insensitive regular expression without the `u` flag matches, with one
  # compiled multi-word pattern. A regex alternation of the same words took
  # about 18 times as long on 1 KiB.
  @prefilter_words ~w(instruction exfiltrate send upload post system developer reveal dump
                      print repeat extract ask prompt request collect when before after <!--
                      display visibility <script)

  # The built-in `poisoning` set is explicit; all other indicators are injection.
  @poisoning_indicator_ids [:tool_poisoning_directive]

  @doc """
  Return the built-in indicators for the `:injection` or `:poisoning` set.

  These are the defaults `SigilGuard.PatternSets` uses when a trust bundle
  supplies neither set.
  """
  @spec built_in_indicators(:injection | :poisoning) :: [map()]
  def built_in_indicators(:poisoning),
    do: Enum.filter(indicators(), &(&1.id in @poisoning_indicator_ids))

  def built_in_indicators(:injection),
    do: Enum.reject(indicators(), &(&1.id in @poisoning_indicator_ids))

  @doc """
  Return whether `sets` is a well-formed `:indicator_sets` option.

  The `:injection` and `:poisoning` entries, where present, must be lists of
  indicators with an atom or string `:id`, a compiled `:pattern`, a
  `:severity` of `:low`, `:medium` or `:high`, and a `:prefilter` list of
  strings. `inspect/3` raises on other shapes; `SigilGuard.Runtime.Gate`
  checks with this function first and blocks.

      iex> SigilGuard.Quarantine.valid_indicator_sets?(%{injection: []})
      true

      iex> SigilGuard.Quarantine.valid_indicator_sets?(%{injection: [%{id: :x}]})
      false

  """
  @doc since: "1.1.0"
  @spec valid_indicator_sets?(term()) :: boolean()
  def valid_indicator_sets?(sets) when is_map(sets) and not is_struct(sets) do
    sets
    |> Map.take([:injection, :poisoning])
    |> Enum.all?(fn {_, indicators} -> valid_indicators?(indicators) end)
  end

  def valid_indicator_sets?(_), do: false

  defp valid_indicators?(indicators) when is_list(indicators),
    do: not List.improper?(indicators) and Enum.all?(indicators, &valid_indicator?/1)

  defp valid_indicators?(_), do: false

  defp valid_indicator?(%{id: id, pattern: %Regex{}, severity: severity, prefilter: prefilter})
       when (is_atom(id) or is_binary(id)) and severity in [:low, :medium, :high] and
              is_list(prefilter),
       do: not List.improper?(prefilter) and Enum.all?(prefilter, &is_binary/1)

  defp valid_indicator?(_), do: false

  @doc """
  Inspect text for deterministic quarantine indicators.

  The `:indicator_sets` option (`%{injection: [...], poisoning: [...]}`, from
  `SigilGuard.PatternSets`) overrides either set; an absent set keeps its
  built-in default.
  """
  @spec inspect(String.t() | nil, Context.t() | map() | keyword(), keyword()) :: result()
  def inspect(text, context \\ %Context{}, opts \\ [])

  def inspect(text, context, opts) when is_binary(text) do
    context = castable_context(context)
    active_indicators = indicators_for(text, opts)
    indicators = find_indicators(text, active_indicators)
    verdict = verdict(indicators, context, opts)

    %{
      verdict: verdict,
      indicators: indicators,
      content_hash: hash(text),
      sanitized_text: sanitized_text(text, active_indicators, indicators)
    }
  end

  def inspect(_, _, _) do
    %{
      verdict: :safe,
      indicators: [],
      content_hash: hash(""),
      sanitized_text: nil
    }
  end

  @doc """
  Replace deterministic quarantine indicator spans with a neutral marker.
  """
  @spec sanitize(String.t()) :: String.t()
  def sanitize(text) when is_binary(text) do
    text
    |> indicators_for([])
    |> sanitize(text)
  end

  defp sanitize(indicators, text) do
    indicators
    |> Enum.reduce(text, fn indicator, acc ->
      Regex.replace(indicator.pattern, acc, "[QUARANTINED]")
    end)
  end

  defp find_indicators(text, active_indicators) do
    Enum.flat_map(active_indicators, fn indicator ->
      if Regex.match?(indicator.pattern, text) do
        [Map.take(indicator, [:id, :severity, :category])]
      else
        []
      end
    end)
  end

  defp sanitized_text(text, _, []), do: text
  defp sanitized_text(text, active_indicators, _), do: sanitize(active_indicators, text)

  defp prefilter_match?(text), do: :binary.match(ascii_lowercase(text), prefilter()) != :nomatch

  # A compiled binary pattern cannot be a module attribute, and compiling it
  # costs more than the search, so it is built once and kept in
  # `:persistent_term`, like the indicator list below.
  defp prefilter do
    case :persistent_term.get({__MODULE__, :prefilter}, :undefined) do
      :undefined ->
        pattern = :binary.compile_pattern(@prefilter_words)
        :persistent_term.put({__MODULE__, :prefilter}, pattern)
        pattern

      pattern ->
        pattern
    end
  end

  defp ascii_lowercase(text) do
    for <<byte <- text>>, into: <<>>, do: <<if(byte in ?A..?Z, do: byte + 32, else: byte)>>
  end

  defp indicators_for(text, opts) do
    {active, custom?} = active_indicators(opts)

    if custom? or prefilter_match?(text) do
      lowercase = String.downcase(text)
      Enum.filter(active, &prefilter_active?(&1, lowercase))
    else
      []
    end
  end

  # An absent `:indicator_sets` uses the built-ins with the fast-path prefilter;
  # a supplied map overrides each set independently and is checked per indicator
  # (the fast-path pattern covers only the built-in vocabulary).
  defp active_indicators(opts) do
    case Keyword.get(opts, :indicator_sets) do
      %{} = sets ->
        {categorized(sets, :injection) ++ categorized(sets, :poisoning), true}

      _ ->
        {indicators(), false}
    end
  end

  # The set an indicator comes from is its category, the value a boundary
  # policy `indicator:` matcher compares.
  defp categorized(sets, set) do
    sets
    |> Map.get(set, built_in_indicators(set))
    |> Enum.map(&Map.put(&1, :category, set))
  end

  # Regexes nested inside collections cannot be injected from module
  # attributes on Elixir 1.18 with OTP 28, so the indicator list is built at
  # runtime and cached in `:persistent_term` (same approach as
  # `SigilGuard.Patterns.built_in/0`).
  defp indicators do
    case :persistent_term.get({__MODULE__, :indicators}, :undefined) do
      :undefined ->
        indicators = Enum.map(built_in_indicator_list(), &put_built_in_category/1)
        :persistent_term.put({__MODULE__, :indicators}, indicators)
        indicators

      indicators ->
        indicators
    end
  end

  defp put_built_in_category(%{id: id} = indicator) do
    category = if id in @poisoning_indicator_ids, do: :poisoning, else: :injection
    Map.put(indicator, :category, category)
  end

  defp built_in_indicator_list do
    [
      %{
        id: :ignore_instructions,
        severity: :high,
        prefilter: ["instruction"],
        pattern: ~r/ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i
      },
      %{
        id: :exfiltration_request,
        severity: :high,
        prefilter: ["exfiltrate", "send", "upload", "post"],
        pattern: ~r/(exfiltrate|send|upload|post).{0,40}(secret|token|key|credential|password)/i
      },
      %{
        id: :system_prompt_probe,
        severity: :medium,
        prefilter: ["system", "developer"],
        pattern: ~r/(system|developer)\s+(prompt|message|instructions?)/i
      },
      %{
        id: :model_extraction_request,
        severity: :high,
        prefilter: ["reveal", "dump", "print", "repeat", "extract", "send"],
        pattern:
          ~r/(reveal|dump|print|repeat|extract|send).{0,60}(system prompt|developer message|hidden instructions?|training data|memorized data)/i
      },
      %{
        id: :credential_harvest_instruction,
        severity: :high,
        prefilter: ["ask", "prompt", "request", "collect"],
        pattern:
          ~r/(ask|prompt|request|collect).{0,50}(password|api[_\s-]?key|token|credential|secret)/i
      },
      %{
        id: :tool_poisoning_directive,
        severity: :medium,
        prefilter: ["when", "before", "after"],
        pattern:
          ~r/(when|before|after)\s+(using|calling|invoking).{0,50}(this\s+)?(tool|function|connector).{0,80}(ignore|override|prefer|follow|use)/i
      },
      %{
        id: :hidden_html_instruction,
        severity: :medium,
        prefilter: ["<!--", "display", "visibility", "<script"],
        pattern: ~r/(<!--|display\s*:\s*none|visibility\s*:\s*hidden|<script\b)/i
      }
    ]
  end

  # An empty prefilter means “always scan”; otherwise require a matching token.
  defp prefilter_active?(%{prefilter: []}, _), do: true

  defp prefilter_active?(%{prefilter: prefilter}, lowercase),
    do: contains_any?(lowercase, prefilter)

  defp contains_any?(text, tokens) do
    Enum.any?(tokens, fn token ->
      :binary.match(text, token) != :nomatch
    end)
  end

  # A term that is not a context gets the defaults, which never select the
  # tool-result downgrade.
  defp castable_context(context) do
    case Context.cast(context) do
      {:ok, context} -> context
      {:error, :invalid_context} -> %Context{}
    end
  end

  defp verdict([], _, _), do: :safe

  defp verdict(indicators, %Context{phase: :tool_result, sink: :model}, opts) do
    if SigilGuard.Options.flag(opts, :strict_quarantine, false, true) or
         high_severity?(indicators) do
      :blocked
    else
      :suspicious
    end
  end

  defp verdict(indicators, _, _) do
    if high_severity?(indicators), do: :blocked, else: :suspicious
  end

  defp high_severity?(indicators), do: Enum.any?(indicators, &(&1.severity == :high))

  defp hash(text) do
    :sha256
    |> :crypto.hash(text)
    |> Base.encode16(case: :lower)
  end
end

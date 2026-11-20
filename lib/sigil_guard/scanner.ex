defmodule SigilGuard.Scanner do
  @moduledoc """
  Sensitivity scanning and redaction for text content.

  Scans strings for credentials and other secrets with a staged deterministic
  pipeline over compiled regex patterns. The built-in patterns cover secrets
  only; PII detection needs host-supplied patterns. The pipeline validates and
  enriches regex candidates with confidence and signal metadata, then provides
  redaction with configurable replacement hints.

  ## Pipeline Extensions

  Pass `pipeline: MyPipeline` to use a module that implements this module's
  `c:scan/3` callback: it receives `(text, patterns, opts)` and returns scan
  hits. `SigilGuard.Scanner.Pipeline` is the built-in implementation.
  """

  alias SigilGuard.Patterns
  alias SigilGuard.Scanner.Pipeline
  alias SigilGuard.Telemetry

  @typedoc "Why `scan_result/2` returned no scan."
  @type scan_error ::
          :invalid_text
          | :invalid_options
          | :input_too_large
          | :invalid_pipeline
          | :invalid_patterns
          | :invalid_pipeline_result
          | :pipeline_failed

  @doc """
  Find the sensitive spans in `text` with the compiled `patterns`.

  Each hit must lie inside `text`; `scan/2` checks the result.
  """
  @callback scan(
              text :: String.t(),
              patterns :: [Patterns.compiled_pattern()],
              opts :: keyword()
            ) :: [Patterns.scan_hit()]

  @doc """
  Scan text for sensitive content using the given patterns.

  Returns `{:ok, text}` if no hits are found, or `{:hit, hits}` with one
  `t:SigilGuard.Patterns.scan_hit/0` map per match.

  ## Options

    * `:max_input_bytes` - binary-data budget (default: 1 MiB); exhaustion raises `ArgumentError`.
    * `:patterns` - compiled patterns to use. Defaults to built-in patterns.
    * `:pipeline` - `:staged` (default), `:regex`, or a module with `scan/3`.
    * `:validate` - set to `false` to keep all regex candidates in staged mode.
    * `:min_confidence` - discard staged hits below this score. Defaults to `0.0`.

  ## Examples

      iex> SigilGuard.Scanner.scan("safe text")
      {:ok, "safe text"}

      iex> {:hit, hits} =
      ...>   SigilGuard.Scanner.scan("Authorization: Bearer sk-abc123def456ghi789jkl012mno345")
      ...>
      ...> length(hits) > 0
      true

  """
  @spec scan(String.t(), keyword()) :: {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}
  def scan(text, opts \\ []) do
    validate_options!(opts)

    if SigilGuard.Limits.check(text, opts) != :ok,
      do: raise(ArgumentError, "scanner input budget exceeded")

    spanned_scan(text, opts, :raise)
  end

  @doc """
  Scan like `scan/2`, but return a reason where `scan/2` raises.

  Returns `{:ok, text}`, `{:hit, hits}`, or `{:error, reason}`: `:invalid_text`
  for text that is not a binary, `:invalid_options`, `:input_too_large` past
  `:max_input_bytes`, `:invalid_pipeline` for a `:pipeline` value that is not a
  pipeline, `:invalid_patterns` when a built-in pipeline is given `:patterns`
  that are not compiled pattern maps, `:invalid_pipeline_result` for hits that do not describe the
  text, and `:pipeline_failed` when the pipeline raises, throws, or exits.
  `SigilGuard.Runtime.Gate` and output contracts scan through this function,
  so a scan that cannot run fails their decision closed.

  ## Examples

      iex> SigilGuard.Scanner.scan_result("safe text")
      {:ok, "safe text"}

      iex> SigilGuard.Scanner.scan_result("text", max_input_bytes: 2)
      {:error, :input_too_large}

  """
  @doc since: "1.1.0"
  @spec scan_result(term(), term()) ::
          {:ok, String.t()} | {:hit, [Patterns.scan_hit()]} | {:error, scan_error()}
  def scan_result(text, opts \\ []) do
    cond do
      not is_binary(text) -> {:error, :invalid_text}
      not Keyword.keyword?(opts) -> {:error, :invalid_options}
      SigilGuard.Limits.check(text, opts) != :ok -> {:error, :input_too_large}
      true -> spanned_scan(text, opts, :return)
    end
  end

  defp spanned_scan(text, opts, mode) do
    patterns = Keyword.get_lazy(opts, :patterns, &Patterns.built_in/0)
    metadata = telemetry_metadata(patterns, opts)

    Telemetry.span([:sigil_guard, :scan], metadata, fn ->
      result =
        text
        |> run_pipeline(patterns, opts, mode)
        |> checked_hits(text)
        |> settle(text, mode)

      {result, Map.put(metadata, :hit_count, hit_count(result))}
    end)
  end

  @doc """
  Replace all matched regions in `text` with their replacement hints.

  Overlapping spans are merged against the original bytes. The leftmost,
  longest hit supplies the replacement; ties sort by replacement text.

  ## Options

    * `:default_replacement` - fallback replacement when a hit has no
      `replacement_hint`. Default: `"[REDACTED]"`

  ## Examples

      iex> hits = [
      ...>   %{offset: 0, length: 20, match: "AKIAIOSFODNN7EXAMPLE", replacement_hint: "[AWS_KEY]"}
      ...> ]
      ...>
      ...> SigilGuard.Scanner.redact("AKIAIOSFODNN7EXAMPLE secret", hits)
      "[AWS_KEY] secret"

  """
  @spec redact(String.t(), [Patterns.scan_hit()], keyword()) :: String.t()
  def redact(text, hits, opts \\ []) do
    validate_options!(opts)
    default = Keyword.get(opts, :default_replacement, "[REDACTED]")

    spans =
      hits
      |> Enum.map(&redaction_span!(&1, text, default))
      |> Enum.sort()
      |> Enum.reduce([], &merge_span/2)
      |> Enum.reverse()

    {parts, position} =
      Enum.reduce(spans, {[], 0}, fn {offset, negative_end, replacement}, {parts, position} ->
        prefix = binary_part(text, position, offset - position)
        {[parts, prefix, replacement], -negative_end}
      end)

    IO.iodata_to_binary([parts, binary_part(text, position, byte_size(text) - position)])
  end

  defp redaction_span!(%{offset: offset, length: length} = hit, text, default)
       when is_integer(offset) and offset >= 0 and is_integer(length) and length > 0 and
              offset + length <= byte_size(text) do
    replacement = Map.get(hit, :replacement_hint) || default
    if not is_binary(replacement), do: raise(ArgumentError, "replacement must be a binary")
    {offset, -(offset + length), replacement}
  end

  defp redaction_span!(_, _, _), do: raise(ArgumentError, "invalid redaction span")

  defp merge_span({offset, ending, _}, [{start, previous_end, replacement} | rest])
       when offset < -previous_end do
    [{start, min(ending, previous_end), replacement} | rest]
  end

  defp merge_span(span, spans), do: [span | spans]

  @doc """
  Scan text and redact every hit in one call. Returns the redacted text, or the
  text unchanged when nothing matches.
  """
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts \\ []) do
    validate_options!(opts)

    case scan(text, opts) do
      {:ok, clean_text} -> clean_text
      {:hit, hits} -> redact(text, hits, opts)
    end
  end

  defp validate_options!(opts) do
    if Keyword.keyword?(opts),
      do: :ok,
      else: raise(ArgumentError, "options must be a keyword list")
  end

  defp run_pipeline(text, patterns, opts, :raise), do: pipeline_hits(text, patterns, opts)

  # The gate and output contracts decide even when a pipeline fails, so here
  # any failure inside the pipeline, built-in or host-supplied, is a reason.
  defp run_pipeline(text, patterns, opts, :return) do
    pipeline_hits(text, patterns, opts)
  rescue
    _ -> {:error, :pipeline_failed, nil}
  catch
    _, _ -> {:error, :pipeline_failed, nil}
  end

  defp pipeline_hits(text, patterns, opts) do
    case Keyword.get(opts, :pipeline, :staged) do
      :staged ->
        with :ok <- check_patterns(patterns), do: {:ok, Pipeline.scan(text, patterns, opts)}

      :regex ->
        with :ok <- check_patterns(patterns), do: {:ok, Pipeline.regex_scan(text, patterns)}

      module when is_atom(module) ->
        module_hits(module, text, patterns, opts)

      other ->
        {:error, :invalid_pipeline, "invalid scanner pipeline #{inspect(other)}"}
    end
  end

  # The built-in pipelines read these fields of every pattern. A host
  # pipeline module receives the patterns as given and owns their shape.
  defp check_patterns(patterns) do
    if is_list(patterns) and not List.improper?(patterns) and
         Enum.all?(patterns, &compiled_pattern?/1),
       do: :ok,
       else: {:error, :invalid_patterns, "scanner patterns must be compiled pattern maps"}
  end

  defp compiled_pattern?(%{regex: %Regex{}, name: name} = pattern) when is_binary(name),
    do: Enum.all?([:category, :severity, :replacement_hint], &Map.has_key?(pattern, &1))

  defp compiled_pattern?(_), do: false

  defp module_hits(module, text, patterns, opts) do
    Code.ensure_loaded(module)

    if function_exported?(module, :scan, 3),
      do: {:ok, module.scan(text, patterns, opts)},
      else: {:error, :invalid_pipeline, "scanner pipeline module must export scan/3"}
  end

  defp checked_hits({:ok, hits}, text) when is_list(hits) do
    if not List.improper?(hits) and Enum.all?(hits, &valid_hit?(&1, text)),
      do: {:ok, hits},
      else: {:error, :invalid_pipeline_result, "scanner pipeline must return valid scan hits"}
  end

  defp checked_hits({:ok, _}, _),
    do: {:error, :invalid_pipeline_result, "scanner pipeline must return a hit list"}

  defp checked_hits(error, _), do: error

  defp settle({:ok, []}, text, _), do: {:ok, text}
  defp settle({:ok, hits}, _, _), do: {:hit, hits}
  defp settle({:error, _, message}, _, :raise), do: raise(ArgumentError, message)
  defp settle({:error, reason, _}, _, :return), do: {:error, reason}

  defp hit_count({:hit, hits}), do: length(hits)
  defp hit_count(_), do: 0

  defp pattern_count(patterns) when is_list(patterns),
    do: if(List.improper?(patterns), do: 0, else: length(patterns))

  defp pattern_count(_), do: 0

  defp valid_hit?(
         %{
           name: name,
           category: category,
           severity: severity,
           match: match,
           offset: offset,
           length: length
         } = hit,
         text
       )
       when is_binary(name) and severity in [:low, :medium, :high] and
              is_binary(match) and is_integer(offset) and is_integer(length) and
              offset >= 0 and length >= 0 and offset + length <= byte_size(text) do
    valid_category?(category) and valid_replacement_hint?(Map.get(hit, :replacement_hint))
  end

  defp valid_hit?(_, _), do: false

  # Built-in patterns emit the closed :secret/:injection/:poisoning atoms;
  # custom/compatibility-bundle patterns may carry a free-form string category.
  defp valid_category?(category), do: is_atom(category) or is_binary(category)

  defp valid_replacement_hint?(hint), do: is_binary(hint) or is_nil(hint)

  defp telemetry_metadata(patterns, opts) do
    %{
      patterns_checked: pattern_count(patterns),
      pipeline: pipeline_name(Keyword.get(opts, :pipeline, :staged)),
      scanner_validate: SigilGuard.Options.flag(opts, :validate, true, true)
    }
  end

  defp pipeline_name(module) when is_atom(module), do: module
  defp pipeline_name(other), do: inspect(other)
end

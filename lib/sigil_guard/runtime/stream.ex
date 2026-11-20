defmodule SigilGuard.Runtime.Stream do
  @moduledoc """
  Chunk-safe sanitizer for streaming runtime output.

  Streaming output can split credentials or prompt-injection phrases across
  chunk boundaries. This module keeps a configurable trailing holdback window,
  evaluates each buffered boundary crossing with `SigilGuard.Runtime.Gate`,
  and only emits content outside that window and any incomplete candidate.
  Unknown custom regex widths, custom indicators and custom pipelines retain
  the whole message until `finish/1`. Pending bytes default to a 1 MiB cap;
  `:max_stream_bytes` changes that cap. Exceeding it fails closed.

  If the gate blocks or requires confirmation, no new content is emitted and
  the stream is marked halted. Callers can inspect the returned decision to
  decide whether to drop, quarantine, or request approval.

  The decision that ends a stream, from `finish/1` or from the push that
  halts it, carries what crossed in its audit metadata:
  `stream_input_bytes` and `stream_input_sha256` over every chunk pushed, and
  `stream_emitted_bytes` and `stream_emitted_sha256` over every chunk
  released, in order. A halt the stream itself decides also sets
  `deny_reason` to `:stream_holdback_overflow`, `:invalid_utf8`, or
  `:incomplete_utf8`.

  The struct holds the two running hash states. They are references, so two
  streams that saw the same chunks do not compare equal and a stream does not
  survive serialization.
  """

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Patterns
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Scanner

  @default_window_bytes 256
  @default_max_pending_bytes 1_048_576
  @unbounded_prefix ~r/api[_-]?key|bearer|postgres:\/\/|mysql:\/\/|mongodb:\/\/|secret|password|token|ignore|system|developer|when|before|after|display|visibility/i

  @typedoc "A stream in progress; pass it back to `push/2` and `finish/1`."
  @type t :: %__MODULE__{
          context: Context.t(),
          opts: keyword(),
          pending: String.t(),
          window_bytes: pos_integer(),
          halted?: boolean(),
          decision: Decision.t() | nil,
          input: {non_neg_integer(), :crypto.hash_state() | nil},
          emitted: {non_neg_integer(), :crypto.hash_state() | nil}
        }

  defstruct context: %Context{},
            opts: [],
            pending: "",
            window_bytes: @default_window_bytes,
            halted?: false,
            decision: nil,
            input: {0, nil},
            emitted: {0, nil}

  @doc """
  Start a stream sanitizer for a labeled boundary.

  Options are passed through to `SigilGuard.Runtime.Gate.evaluate/3`.
  `:stream_window_bytes` controls the trailing holdback window and defaults
  to `#{@default_window_bytes}` bytes. Invalid window values fall back to the
  default so stream checks keep a conservative holdback. Options must be a
  keyword list. `:patterns` must contain compiled regex maps with positive
  integer width hints when supplied; invalid configuration raises `ArgumentError`.
  """
  @spec new(Context.t() | map() | keyword(), keyword()) :: t()
  def new(context \\ %Context{}, opts \\ []) do
    validate_options!(opts)

    %__MODULE__{
      context: Context.new(context),
      opts: opts,
      window_bytes: stream_window_bytes(opts)
    }
  end

  @doc """
  Push one output chunk through the sanitizer.

  Returns `{stream, decision, emitted_chunk}`. `emitted_chunk` is empty when
  the held-back content is not yet safe to release, or when the gate blocks
  or requires confirmation.
  """
  @spec push(t(), String.t()) :: {t(), Decision.t(), String.t()}
  def push(%__MODULE__{halted?: true, decision: %Decision{} = decision} = stream, chunk)
      when is_binary(chunk) do
    {stream, decision, ""}
  end

  def push(%__MODULE__{} = stream, chunk) when is_binary(chunk) do
    stream = %{stream | input: absorb(stream.input, chunk)}
    combined = stream.pending <> chunk
    limit = Keyword.get(stream.opts, :max_stream_bytes, @default_max_pending_bytes)

    if not is_integer(limit) or limit <= 0 or byte_size(combined) > limit do
      halt(stream, "stream capacity exceeded", :stream_holdback_overflow)
    else
      push_validated(stream, combined, :unicode.characters_to_binary(combined))
    end
  end

  defp push_validated(stream, _, {:error, _, _}),
    do: halt(stream, "invalid UTF-8", :invalid_utf8)

  defp push_validated(stream, combined, {:incomplete, valid, _}),
    do: evaluate_chunk(stream, combined, valid)

  defp push_validated(stream, combined, valid), do: evaluate_chunk(stream, combined, valid)

  defp evaluate_chunk(stream, combined, valid) do
    decision = Gate.evaluate(valid, stream.context, window_opts(stream))

    if Decision.allowed?(decision) do
      {emittable, pending} = split_emittable(combined, decision.hits, stream, valid)

      emitted =
        sanitize_allowed(emittable, decision.hits, byte_size(emittable), decision, stream.opts)

      emitted_state = absorb(stream.emitted, emitted)

      {%{stream | pending: pending, decision: decision, emitted: emitted_state}, decision,
       emitted}
    else
      halted(stream, decision)
    end
  end

  defp halt(stream, reason, deny_reason) do
    halted(stream, %Decision{
      verdict: :blocked,
      action: :block,
      phase: stream.context.phase,
      risk_level: :high,
      trust_level: stream.context.trust_level,
      reason: reason,
      audit_metadata: %{verdict: :blocked, action: :block, deny_reason: deny_reason}
    })
  end

  defp halted(stream, decision) do
    decision = with_evidence(decision, stream)

    {%{stream | pending: "", halted?: true, decision: decision}, decision, ""}
  end

  defp absorb({bytes, state}, chunk) do
    {bytes + byte_size(chunk), :crypto.hash_update(state || :crypto.hash_init(:sha256), chunk)}
  end

  defp with_evidence(%Decision{} = decision, stream) do
    {input_bytes, input_sha256} = digest(stream.input)
    {emitted_bytes, emitted_sha256} = digest(stream.emitted)

    evidence = %{
      stream_input_bytes: input_bytes,
      stream_input_sha256: input_sha256,
      stream_emitted_bytes: emitted_bytes,
      stream_emitted_sha256: emitted_sha256
    }

    %{decision | audit_metadata: Map.merge(decision.audit_metadata, evidence)}
  end

  defp digest({bytes, state}) do
    final = :crypto.hash_final(state || :crypto.hash_init(:sha256))

    {bytes, Base.encode16(final, case: :lower)}
  end

  @doc """
  Flush the held-back content at end of stream.

  Returns `{stream, decision, emitted_chunk}`. If the final decision blocks
  or requires confirmation, no content is emitted.
  """
  @spec finish(t()) :: {t(), Decision.t(), String.t()}
  def finish(%__MODULE__{halted?: true, decision: %Decision{} = decision} = stream) do
    {stream, decision, ""}
  end

  def finish(%__MODULE__{} = stream) do
    if String.valid?(stream.pending),
      do: finish_valid(stream),
      else: halt(stream, "incomplete UTF-8", :incomplete_utf8)
  end

  defp finish_valid(stream) do
    decision = Gate.evaluate(stream.pending, stream.context, window_opts(stream))
    emitted = if Decision.allowed?(decision), do: decision.sanitized_text || "", else: ""
    stream = %{stream | pending: "", emitted: absorb(stream.emitted, emitted)}
    decision = with_evidence(decision, stream)

    {%{stream | decision: decision}, decision, emitted}
  end

  defp split_emittable(text, hits, stream, valid) do
    base_size = max(byte_size(valid) - stream.window_bytes, 0)
    candidate_start = candidate_start(valid, stream.opts)

    emit_size =
      base_size
      |> min(candidate_start)
      |> safe_emit_size(hits)
      |> utf8_boundary(valid)

    {
      binary_part(text, 0, emit_size),
      binary_part(text, emit_size, byte_size(text) - emit_size)
    }
  end

  defp candidate_start(text, opts) do
    patterns = Keyword.get(opts, :patterns, Patterns.built_in())
    built_in? = patterns == Patterns.built_in()

    literal? =
      is_list(patterns) and
        Enum.all?(patterns, &Regex.match?(~r/\A[a-zA-Z0-9 _-]+\z/, Regex.source(&1.regex)))

    if (built_in? or literal?) and not Keyword.has_key?(opts, :indicator_sets) and
         Keyword.get(opts, :pipeline, :staged) in [:staged, :regex] do
      case Regex.run(@unbounded_prefix, text, return: :index) do
        [{offset, _}] -> offset
        nil -> byte_size(text)
      end
    else
      0
    end
  end

  defp utf8_boundary(0, _), do: 0

  defp utf8_boundary(size, text) do
    if Bitwise.band(:binary.at(text, size), 0xC0) == 0x80,
      do: utf8_boundary(size - 1, text),
      else: size
  end

  defp safe_emit_size(base_size, hits) do
    hits
    |> Enum.sort_by(& &1.offset, :desc)
    |> Enum.reduce(base_size, fn hit, emit_size ->
      if crosses_boundary?(hit, emit_size), do: min(emit_size, hit.offset), else: emit_size
    end)
  end

  defp crosses_boundary?(hit, emit_size) do
    hit.offset < emit_size and hit.offset + hit.length > emit_size
  end

  defp sanitize_allowed(emittable, hits, emit_size, %Decision{action: :redact}, opts) do
    emittable_hits = Enum.filter(hits, &contained?(&1, emit_size))
    Scanner.redact(emittable, emittable_hits, opts)
  end

  defp sanitize_allowed(emittable, _, _, _, _), do: emittable

  defp contained?(hit, emit_size), do: hit.offset + hit.length <= emit_size

  # A window is part of a message. A per-sink output contract, with its size
  # cap and class check, is a property of the whole message, so the host
  # applies it to the assembled output.
  defp window_opts(%__MODULE__{opts: opts}), do: Keyword.put(opts, :output_contracts, false)

  # Width hints set a minimum; candidate_start/2 handles expressions for which
  # a finite holdback cannot prove a safe emission boundary.
  defp stream_window_bytes(opts) do
    max(configured_window(opts), active_max_match_bytes(opts))
  end

  defp configured_window(opts) do
    case Keyword.get(opts, :stream_window_bytes, @default_window_bytes) do
      value when is_integer(value) and value > 0 -> value
      _ -> @default_window_bytes
    end
  end

  defp validate_options!(opts) do
    unless is_list(opts) and Keyword.keyword?(opts),
      do: raise(ArgumentError, "stream options must be a keyword list")

    patterns = Keyword.get(opts, :patterns, Patterns.built_in())

    unless valid_patterns?(patterns),
      do:
        raise(
          ArgumentError,
          "stream patterns must contain compiled regexes and positive integer widths"
        )
  end

  defp valid_patterns?([]), do: true

  defp valid_patterns?([%{regex: %Regex{}} = pattern | rest]) do
    width = Map.get(pattern, :max_match_bytes, Patterns.default_max_match_bytes())
    is_integer(width) and width > 0 and valid_patterns?(rest)
  end

  defp valid_patterns?(_), do: false

  defp active_max_match_bytes(opts) do
    patterns = Keyword.get(opts, :patterns, Patterns.built_in())

    Enum.reduce(patterns, Patterns.largest_max_match_bytes(patterns), fn pattern, width ->
      max(width, byte_size(Regex.source(pattern.regex)))
    end)
  end
end

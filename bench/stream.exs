Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Stream do
  @moduledoc "Benchmarks of the chunk-safe stream sanitizer."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Runtime.Stream, as: GateStream

  @chunk_bytes 512
  @stream "BM.04 runtime stream 64k split secret"
  @single_pass "BM.04 single pass gate 64k"

  @impl SigilGuard.Bench
  def id, do: "stream"

  @impl SigilGuard.Bench
  def title, do: "Streaming Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    `SigilGuard.Runtime.Stream` evaluates each pushed chunk together with the
    bytes it still holds back, so that a secret split across two chunks is
    caught. The suite pushes 64 KiB in 128 chunks of 512 bytes, with one
    secret across a chunk boundary, and compares that with one gate
    evaluation over the same bytes. The context has high trust, so secrets
    are redacted and every chunk is evaluated. At low trust the first secret
    asks for confirmation and halts the stream.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    split = chunks("stream_split_64k.txt")
    clean = chunks("clean_64k.txt")
    payload = Fixtures.corpus!("stream_split_64k.txt")

    %{
      @stream => fn -> run(split, &discard/2, nil) end,
      "BM.04 runtime stream 64k clean" => fn -> run(clean, &discard/2, nil) end,
      @single_pass => fn -> Gate.evaluate(payload, context()) end
    }
  end

  @impl SigilGuard.Bench
  def derived(stats) do
    chunk_count = div(65_536, @chunk_bytes)

    %{
      "BM.04 stream median per chunk" => %{
        "median_ns" => div(Bench.median(stats, @stream), chunk_count)
      },
      "BM.04 stream overhead versus single pass" => Bench.overhead(stats, @stream, @single_pass)
    }
  end

  defp context,
    do: [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      action: "fetch_file",
      trust_level: :high
    ]

  defp chunks(name) do
    for <<chunk::binary-size(@chunk_bytes) <- Fixtures.corpus!(name)>>, do: chunk
  end

  defp run(chunks, collect, acc) do
    stream = GateStream.new(context(), stream_window_bytes: @chunk_bytes)

    {stream, acc} =
      Enum.reduce(chunks, {stream, acc}, fn chunk, {stream, acc} ->
        {stream, _, emitted} = GateStream.push(stream, chunk)
        {stream, collect.(emitted, acc)}
      end)

    {stream, decision, emitted} = GateStream.finish(stream)
    {stream, decision, collect.(emitted, acc)}
  end

  defp discard(_, acc), do: acc
  defp collect(emitted, acc), do: [emitted | acc]

  @impl SigilGuard.Bench
  def preconditions! do
    {stream, decision, emitted} = run(chunks("stream_split_64k.txt"), &collect/2, [])
    text = IO.iodata_to_binary(Enum.reverse(emitted))

    Bench.expect!(not stream.halted?, "BM.04 stream halts: #{inspect(decision.verdict)}")
    Bench.expect!(not String.contains?(text, Fixtures.secret()), "BM.04 stream releases a secret")
    Bench.expect!(byte_size(text) > 0, "BM.04 stream releases nothing")

    {clean, _, released} = run(chunks("clean_64k.txt"), &collect/2, [])

    Bench.expect!(not clean.halted?, "BM.04 clean stream halts")

    Bench.expect!(
      IO.iodata_length(released) == 65_536,
      "BM.04 clean stream does not release every byte"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Stream)

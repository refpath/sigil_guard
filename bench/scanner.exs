Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Scanner do
  @moduledoc "Benchmarks of secret scanning, redaction and the quarantine inspector."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures

  @sizes ["1k", "64k", "1m"]
  @block_bytes 4096
  @chunk_bytes 512
  @context [phase: :tool_result, origin: :tool, sink: :model]

  @impl SigilGuard.Bench
  def id, do: "scanner"

  @impl SigilGuard.Bench
  def title, do: "Scanner Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    Every boundary crossing starts with a scan, so its cost bounds everything
    built on it. The suite scans clean text and text with one documented
    synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
    quarantine inspector that looks for prompt injection, and compiles a
    bundle's pattern entries into the sets the scanner uses.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    %{}
    |> Map.merge(for size <- @sizes, into: %{}, do: clean(size))
    |> Map.merge(for size <- @sizes, into: %{}, do: hits(size))
    |> Map.merge(for size <- ["1k", "64k"], into: %{}, do: redact(size))
    |> Map.merge(quarantine())
    |> Map.merge(pattern_sets())
  end

  defp clean(size) do
    payload = Fixtures.corpus!("clean_#{size}.txt")
    {"BM.01 scan clean #{size}", fn -> SigilGuard.scan(payload) end}
  end

  defp hits(size) do
    payload = Fixtures.corpus!("hits_#{size}.txt")
    {"BM.02 scan hits #{size}", fn -> SigilGuard.scan(payload) end}
  end

  defp redact(size) do
    payload = Fixtures.corpus!("hits_#{size}.txt")
    {"BM.09 scan and redact hits #{size}", fn -> SigilGuard.scan_and_redact(payload) end}
  end

  defp quarantine do
    clean = Fixtures.corpus!("clean_1k.txt")
    injection = Fixtures.injection()

    %{
      "BM.10 quarantine inspect clean 1k" => fn ->
        SigilGuard.Quarantine.inspect(clean, @context, [])
      end,
      "BM.10 quarantine inspect injection" => fn ->
        SigilGuard.Quarantine.inspect(injection, @context, [])
      end
    }
  end

  defp pattern_sets do
    entries = SigilGuard.TrustBundle.patterns(Fixtures.bundle())

    %{
      "BM.11 pattern sets resolve 10 entries" => fn -> SigilGuard.PatternSets.resolve(entries) end
    }
  end

  @impl SigilGuard.Bench
  def preconditions! do
    assert_corpus!()

    Bench.expect!(
      not String.contains?(
        SigilGuard.scan_and_redact(Fixtures.corpus!("hits_64k.txt")),
        Fixtures.secret()
      ),
      "BM.09 releases a secret"
    )

    clean = SigilGuard.Quarantine.inspect(Fixtures.corpus!("clean_1k.txt"), @context, [])
    flagged = SigilGuard.Quarantine.inspect(Fixtures.injection(), @context, [])

    Bench.expect!(clean.indicators == [], "BM.10 clean text has indicators")
    Bench.expect!(flagged.indicators != [], "BM.10 injection text has no indicator")

    entries = SigilGuard.TrustBundle.patterns(Fixtures.bundle())

    Bench.expect!(length(entries) == 10, "BM.11 bundle does not hold ten patterns")

    Bench.expect!(
      match?({:ok, _}, SigilGuard.PatternSets.resolve(entries)),
      "BM.11 resolve fails"
    )
  end

  @doc """
  Check the hit counts of the committed corpus.

  A clean file holds no secret. A hit file holds one per complete 4 KiB
  block, or one when it is shorter than a block, and none of them lies across
  a 512-byte chunk boundary. The stream file holds one more, across a
  boundary.
  """
  @spec assert_corpus!() :: :ok
  def assert_corpus! do
    for size <- @sizes do
      hits = Fixtures.corpus!("hits_#{size}.txt")

      assert_hit_count!(Fixtures.corpus!("clean_#{size}.txt"), 0)
      assert_hit_count!(hits, expected_hits(byte_size(hits)))
      assert_split_count!(hits, 0)
    end

    split = Fixtures.corpus!("stream_split_64k.txt")

    assert_hit_count!(split, expected_hits(byte_size(split)) + 1)
    assert_split_count!(split, 1)
  end

  defp expected_hits(size), do: max(div(size, @block_bytes), 1)

  defp assert_hit_count!(payload, expected) do
    actual = length(:binary.matches(payload, Fixtures.secret()))

    Bench.expect!(actual == expected, "corpus hit count is #{actual}, expected #{expected}")

    scanned =
      case SigilGuard.scan(payload) do
        {:ok, _} -> 0
        {:hit, hits} -> length(hits)
      end

    Bench.expect!(scanned == expected, "scanner finds #{scanned} hits, expected #{expected}")
  end

  defp assert_split_count!(payload, expected) do
    actual =
      payload
      |> :binary.matches(Fixtures.secret())
      |> Enum.count(fn {offset, length} ->
        div(offset, @chunk_bytes) != div(offset + length - 1, @chunk_bytes)
      end)

    Bench.expect!(actual == expected, "corpus has #{actual} split secrets, expected #{expected}")
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Scanner)

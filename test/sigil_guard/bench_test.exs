defmodule SigilGuard.BenchTest do
  @moduledoc false

  use ExUnit.Case, async: false

  Code.require_file("../../bench/corpus.exs", __DIR__)
  Code.require_file("../../bench/run.exs", __DIR__)

  @secret "AKIAIOSFODNN7EXAMPLE"

  test "corpus generation is byte-identical from the fixed seed" do
    first = tmp_dir("first")
    second = tmp_dir("second")

    SigilGuard.BenchCorpus.generate!(first)
    SigilGuard.BenchCorpus.generate!(second)

    first_files = relative_files(first)
    assert first_files == relative_files(second)

    for file <- first_files do
      assert File.read!(Path.join(first, file)) == File.read!(Path.join(second, file))
    end
  end

  test "committed hit corpora satisfy the benchmark precondition" do
    SigilGuard.Bench.assert_corpus!()

    for {name, expected_hits} <- [
          {"clean_1k.txt", 0},
          {"clean_64k.txt", 0},
          {"clean_1m.txt", 0},
          {"hits_1k.txt", 1},
          {"hits_64k.txt", 16},
          {"hits_1m.txt", 256},
          {"stream_split_64k.txt", 17}
        ] do
      payload = File.read!(Path.join("bench/corpus", name))
      assert length(Regex.scan(~r/#{@secret}/, payload)) == expected_hits
    end
  end

  test "the committed corpus is what the generator writes" do
    dir = tmp_dir("committed")
    SigilGuard.BenchCorpus.generate!(dir)

    files = relative_files(dir)

    assert files == relative_files("bench/corpus")

    for file <- files do
      assert File.read!(Path.join(dir, file)) == File.read!(Path.join("bench/corpus", file)), file
    end
  end

  test "one secret of the stream corpus lies across a chunk boundary" do
    payload = File.read!("bench/corpus/stream_split_64k.txt")

    split =
      for {offset, length} <- :binary.matches(payload, @secret),
          div(offset, 512) != div(offset + length - 1, 512),
          do: offset

    assert split == [1526]
  end

  test "every scenario takes the path it is named for" do
    assert SigilGuard.Bench.assert_fixtures!() == :ok
  end

  test "the audit chain fixture has the same bytes on every build" do
    first = SigilGuard.Bench.audit_chain(64)

    assert first == SigilGuard.Bench.audit_chain(64)
    assert hd(first).id == "00000000000000000000000000000001"
    assert hd(first).timestamp == "2026-07-03T12:00:00.001Z"
  end

  test "derived figures follow from the scenario medians" do
    scenarios = %{
      "BM.04 runtime stream 64k split secret" => %{"median_ns" => 1_280_000},
      "BM.04 single pass gate 64k" => %{"median_ns" => 800_000},
      "BM.08 tool gateway guard_request" => %{"median_ns" => 24_457},
      "BM.08 no-op baseline" => %{"median_ns" => 2}
    }

    derived = SigilGuard.Bench.derived(scenarios)

    assert derived == %{
             "BM.04 stream median per chunk" => %{"median_ns" => 10_000},
             "BM.04 stream overhead versus single pass" => %{
               "median_ns" => 480_000,
               "percent" => 60.0
             },
             "BM.08 gateway overhead versus no-op" => %{"median_ns" => 24_455}
           }

    markdown = SigilGuard.Bench.derived_markdown(derived)

    assert markdown =~ "| BM.04 stream overhead versus single pass | 480.000 | 60.0 |"
    assert markdown =~ "| BM.08 gateway overhead versus no-op | 24.455 |  |"

    assert SigilGuard.Bench.derived(%{})["BM.04 stream overhead versus single pass"] ==
             %{"median_ns" => 0, "percent" => nil}
  end

  test "the environment block names the memory size" do
    assert SigilGuard.Bench.memory_info() =~ ~r/\A(\d+ GB|unknown) RAM\z/
  end

  test "benchmark harness covers the BM.01 through BM.08 scenario matrix" do
    assert SigilGuard.Bench.scenario_ids() ==
             MapSet.new(~w[BM.01 BM.02 BM.03 BM.04 BM.05 BM.06 BM.07 BM.08])

    scenarios = SigilGuard.Bench.scenarios()

    assert map_size(scenarios) == 21
    assert Enum.any?(scenarios, &match?({"BM.04 single pass gate 64k", _}, &1))
    assert Enum.any?(scenarios, &match?({"BM.08 no-op baseline", _}, &1))
    assert Enum.any?(scenarios, &match?({"BM.08 tool gateway guard_request", _}, &1))
  end

  test "smoke mode keeps full Benchee settings only for real runs" do
    assert SigilGuard.Bench.bench_config(false) == [warmup: 2, time: 5, memory_time: 2]
    assert SigilGuard.Bench.bench_config(true) == [warmup: 0, time: 0.01, memory_time: 0]
  end

  defp relative_files(dir) do
    dir
    |> Path.join("**/*")
    |> Path.wildcard()
    |> Enum.reject(&File.dir?/1)
    |> Enum.map(&Path.relative_to(&1, dir))
    |> Enum.sort()
  end

  defp tmp_dir(name) do
    path = Path.join(System.tmp_dir!(), "sigil_guard_bench_#{name}_#{System.unique_integer()}")
    File.rm_rf!(path)
    path
  end
end

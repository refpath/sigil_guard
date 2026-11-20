defmodule SigilGuard.BenchTest do
  @moduledoc false

  use ExUnit.Case, async: false

  Code.require_file("../../bench/corpus.exs", __DIR__)
  Code.require_file("../../bench/run.exs", __DIR__)

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Suites

  @secret "AKIAIOSFODNN7EXAMPLE"

  setup do
    on_exit(fn ->
      SigilGuard.TrustBundle.Cache.clear()
      SigilGuard.ReplayStore.clear()
    end)
  end

  describe "corpus" do
    test "generation is byte-identical from the fixed seed" do
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

    test "the committed corpus is what the generator writes" do
      dir = tmp_dir("committed")
      SigilGuard.BenchCorpus.generate!(dir)

      files = relative_files(dir)

      assert files == relative_files("bench/corpus")

      assert Enum.sort(SigilGuard.BenchCorpus.files("bench/corpus")) ==
               Enum.sort(Enum.map(files, &Path.join("bench/corpus", &1)))

      for file <- files do
        assert File.read!(Path.join(dir, file)) == File.read!(Path.join("bench/corpus", file)),
               file
      end
    end

    test "hit corpora hold exactly the expected synthetic secrets" do
      assert Bench.Scanner.assert_corpus!() == :ok

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

    test "one secret of the stream corpus lies across a chunk boundary" do
      payload = File.read!("bench/corpus/stream_split_64k.txt")

      split =
        for {offset, length} <- :binary.matches(payload, @secret),
            div(offset, 512) != div(offset + length - 1, 512),
            do: offset

      assert split == [1526]
    end
  end

  describe "suites" do
    test "every fixture takes the path its scenario is named for" do
      for suite <- Suites.all() do
        assert suite.preconditions!() == :ok, inspect(suite)
      end
    end

    test "the scenario matrix covers BM.01 through BM.31 with unique names" do
      ids =
        for number <- 1..31, do: "BM." <> String.pad_leading(Integer.to_string(number), 2, "0")

      assert Bench.scenario_ids(Suites.all()) == MapSet.new(ids)

      names = Enum.flat_map(Suites.all(), &Map.keys(&1.scenarios()))

      assert names == Enum.uniq(names)
      assert Enum.all?(names, &String.starts_with?(&1, "BM."))

      assert Enum.all?(
               Enum.flat_map(Suites.all(), &Map.values(&1.scenarios())),
               &is_function(&1, 0)
             )
    end

    test "every baseline scenario is still measured" do
      baseline = Jason.decode!(File.read!("bench/baseline.json"))
      names = Enum.flat_map(Suites.all(), &Map.keys(&1.scenarios()))

      assert Map.keys(baseline["scenarios"]) -- names == []
    end

    test "each suite has a script, a mix alias and a published page" do
      aliases =
        Map.new(Mix.Project.config()[:aliases], fn {name, steps} ->
          {Atom.to_string(name), steps}
        end)

      extras = Enum.map(Keyword.keys(Mix.Project.config()[:docs][:extras]), &Atom.to_string/1)
      ids = Enum.map(Suites.all(), & &1.id())

      assert ids == Enum.uniq(ids)

      for suite <- Suites.all() do
        id = suite.id()

        assert File.regular?("bench/#{id}.exs")
        assert aliases["bench.#{id}"] == ["run bench/#{id}.exs"]
        assert "bench/output/#{id}.md" in extras
        assert String.trim(suite.title()) != ""
        assert String.length(String.trim(suite.description())) > 80
      end

      assert "bench/output/benchmarks.md" in extras
    end
  end

  describe "harness" do
    test "a smoke run keeps its budgets and its output apart from a measured run" do
      assert Bench.bench_config(false) == [warmup: 2, time: 5, memory_time: 2]
      assert Bench.bench_config(true) == [warmup: 0, time: 0.01, memory_time: 0]
      assert Bench.output_dir(false) == "bench/output"
      assert Bench.output_dir(true) == "bench/output/smoke"
      assert Bench.smoke?(["--smoke"])
    end

    test "a scenario faster than the target runs in batches and reports per call" do
      assert Bench.batch_size(fn -> :ok end, true) == 1
      assert Bench.batch_size(fn -> Process.sleep(1) end, false) == 1

      fast = Bench.batch_size(fn -> :crypto.hash(:sha256, "x") end, false)
      assert fast > 1 and fast <= 100_000

      counter = :counters.new(1, [])
      Bench.batched(fn -> :counters.add(counter, 1, 1) end, 7).()
      assert :counters.get(counter, 1) == 7

      sample = fn values -> %{samples: values, statistics: nil} end

      scenario = %{
        name: "BM.28 sha256 hex 1k",
        run_time_data: sample.([7_000, 14_000]),
        memory_usage_data: sample.([700]),
        reductions_data: sample.([]),
        input: nil
      }

      %{scenarios: [divided]} = Bench.per_call(%{scenarios: [scenario]}, %{scenario.name => 7})

      assert divided.run_time_data.samples == [1_000.0, 2_000.0]
      assert divided.memory_usage_data.samples == [100.0]

      assert Bench.per_call(%{scenarios: [scenario]}, %{}) == %{scenarios: [scenario]}
    end

    test "CI=true selects the smoke budgets" do
      previous = System.get_env("CI")

      on_exit(fn ->
        if previous, do: System.put_env("CI", previous), else: System.delete_env("CI")
      end)

      System.delete_env("CI")
      refute Bench.smoke?([])

      System.put_env("CI", "true")
      assert Bench.smoke?([])
    end

    test "a suite file loaded by another file does not run" do
      assert Bench.script(Bench.Scanner) == :ok
    end

    test "scenario ids and failed preconditions" do
      assert Bench.scenario_id("BM.04 runtime stream 64k split secret") == "BM.04"
      assert Bench.expect!(true, "holds") == :ok

      assert_raise RuntimeError, "benchmark fixture precondition failed: BM.99 broken", fn ->
        Bench.expect!(false, "BM.99 broken")
      end
    end

    test "derived figures follow from the scenario medians" do
      stream = %{
        "BM.04 runtime stream 64k split secret" => %{"median_ns" => 1_280_000},
        "BM.04 single pass gate 64k" => %{"median_ns" => 800_000}
      }

      assert Bench.Stream.derived(stream) == %{
               "BM.04 stream median per chunk" => %{"median_ns" => 10_000},
               "BM.04 stream overhead versus single pass" => %{
                 "median_ns" => 480_000,
                 "percent" => 60.0
               }
             }

      gateway = %{
        "BM.08 tool gateway guard_request" => %{"median_ns" => 24_457},
        "BM.08 no-op baseline" => %{"median_ns" => 2}
      }

      assert Bench.Gateway.derived(gateway) ==
               %{"BM.08 gateway overhead versus no-op" => %{"median_ns" => 24_455}}

      assert Bench.Stream.derived(%{})["BM.04 stream overhead versus single pass"] ==
               %{"median_ns" => 0, "percent" => nil}

      markdown =
        Bench.derived_markdown(
          Map.merge(Bench.Stream.derived(stream), Bench.Gateway.derived(gateway))
        )

      assert markdown =~ "| BM.04 stream overhead versus single pass | 480.000 | 60.0 |"
      assert markdown =~ "| BM.08 gateway overhead versus no-op | 24.455 |  |"
    end

    test "the summary page lists every suite with its scenarios and a link" do
      stats = %{
        "BM.01 scan clean 1k" => %{
          "median_ns" => 13_000,
          "p99_ns" => 24_000,
          "memory_bytes" => 4_448
        }
      }

      page = Bench.summary_markdown([{Bench.Scanner, stats}], false, %{})

      assert page =~ "# SigilGuard Performance Benchmarks"
      assert page =~ "Mode: measured."
      assert page =~ "## Environment"
      assert page =~ ~r/- Hardware: .+, \d+ cores, (\d+ GB|unknown) RAM/
      assert page =~ "## Scanner Benchmarks"
      assert page =~ "[Scanner Benchmarks](scanner.md)"
      assert page =~ "| BM.01 scan clean 1k | 13.000 | 24.000 | 4448 |"
      refute page =~ "## Derived figures"
    end

    test "the environment block names the memory size" do
      assert Bench.memory_info() =~ ~r/\A(\d+ GB|unknown) RAM\z/
    end
  end

  describe "audit chain fixture" do
    test "has the same bytes on every build" do
      first = Bench.Audit.chain(64)

      assert first == Bench.Audit.chain(64)
      assert hd(first).id == "00000000000000000000000000000001"
      assert hd(first).timestamp == "2026-07-03T12:00:00.001Z"
    end
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
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end

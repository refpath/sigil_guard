defmodule SigilGuard.BenchCompareTest do
  @moduledoc false

  use ExUnit.Case, async: true

  Code.require_file("../../bench/compare.exs", __DIR__)

  @scenario "BM.01 scan clean 1k"

  test "25 percent median regression fails on a matching runner class" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 125)

    assert {:error, [{:fail, message}]} = SigilGuard.BenchCompare.compare(baseline, run)
    assert message =~ "regressed by 25.0%"
  end

  test "15 percent median regression passes on a matching runner class" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 115)

    assert {:ok, [{:pass, "no binding benchmark regressions"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "a regression of exactly 20 percent passes and one above it fails" do
    baseline = document(median_ns: 100)

    assert {:ok, [{:pass, "no binding benchmark regressions"}]} =
             SigilGuard.BenchCompare.compare(baseline, document(median_ns: 120))

    assert {:error, [{:fail, message}]} =
             SigilGuard.BenchCompare.compare(baseline, document(median_ns: 121))

    assert message =~ "regressed by 21.0%"
  end

  test "missing baseline scenario in the run fails" do
    baseline = document()
    run = put_in(document(), ["scenarios"], %{"BM.02 scan hits 1k" => stats(median_ns: 100)})

    assert {:error, findings} = SigilGuard.BenchCompare.compare(baseline, run)
    assert {:fail, "missing run scenario: " <> @scenario} in findings
  end

  test "new run scenarios pass with a warning" do
    baseline = document()

    run =
      document()
      |> put_in(["scenarios", "BM.99 new scenario"], stats(median_ns: 1))

    assert {:ok, [{:warn, "new scenario without baseline: BM.99 new scenario"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "runner class mismatch is informational" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 10_000) |> put_in(["environment", "hardware"], "different")

    assert {:ok, [{:warn, message}]} = SigilGuard.BenchCompare.compare(baseline, run)
    assert message =~ "runner class differs"
  end

  test "smoke run validates the benchmark matrix without median regression checks" do
    baseline = document(median_ns: 100)
    run = document(mode: "smoke", median_ns: 10_000)

    assert {:ok, [{:pass, "smoke benchmark matrix matches baseline"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "smoke run still fails when a baseline scenario is missing" do
    baseline = document()

    run =
      document(mode: "smoke")
      |> put_in(["scenarios"], %{"BM.99 new scenario" => stats(median_ns: 1)})

    assert {:error, findings} = SigilGuard.BenchCompare.compare(baseline, run)
    assert {:fail, "missing run scenario: " <> @scenario} in findings
  end

  test "invalid benchmark mode fails validation" do
    assert {:error, message} =
             document(mode: "partial")
             |> SigilGuard.BenchCompare.validate_document("run")

    assert message == "run mode must be measured or smoke"
  end

  test "committed baseline and latest output satisfy the data model" do
    for path <- ["bench/baseline.json", "bench/output/benchmarks.json"] do
      document =
        path
        |> File.read!()
        |> Jason.decode!()

      assert :ok = SigilGuard.BenchCompare.validate_document(document, path)
    end
  end

  test "llm-guard comparison artifact is scanner-scope and labeled" do
    document =
      "bench/output/llm_guard_comparison.json"
      |> File.read!()
      |> Jason.decode!()

    assert document["schema"] == "sigil_guard_llm_guard_comparison/v1"
    assert document["environment"]["llm_guard"] =~ ~r/^\d+\.\d+\.\d+/
    assert document["scope"]["comparison"] =~ "SigilGuard.scan/1 versus llm-guard input scanners"
    assert document["scope"]["paths"]["ml"] =~ "not measured"

    result_names = Map.keys(document["results"])
    assert Enum.any?(result_names, &String.starts_with?(&1, "sigil_guard.scan "))
    assert Enum.any?(result_names, &String.starts_with?(&1, "llm_guard."))
    refute Enum.any?(result_names, &String.contains?(&1, "gate"))
    refute Enum.any?(result_names, &String.contains?(&1, "attestation"))

    assert Enum.all?(document["results"], fn {_, result} ->
             result["path"] == "deterministic" and String.ends_with?(result["corpus"], ".txt")
           end)
  end

  test "allocation regressions fail even when latency is unchanged" do
    assert {:error, [{:fail, message}]} =
             SigilGuard.BenchCompare.compare(
               document(memory_bytes: 10),
               document(memory_bytes: 13)
             )

    assert message =~ "allocation regressed"

    assert {:error, [{:fail, from_zero}]} =
             SigilGuard.BenchCompare.compare(document(memory_bytes: 0), document(memory_bytes: 1))

    assert from_zero =~ "unbounded increase from zero (1 vs 0)"
  end

  describe "band/1" do
    test "three measured runs within 5 percent of their mean pass" do
      runs = Enum.map([100, 104, 96], &measured(median_ns: &1))

      assert {:ok, [{:pass, "every scenario median within +/-5% across 3 runs"}]} =
               SigilGuard.BenchCompare.band(runs)
    end

    test "a median exactly 5 percent from the mean passes and one beyond it fails" do
      assert {:ok, _} =
               SigilGuard.BenchCompare.band(Enum.map([95, 100, 105], &measured(median_ns: &1)))

      assert {:error, [{:fail, message}]} =
               SigilGuard.BenchCompare.band(Enum.map([94, 100, 106], &measured(median_ns: &1)))

      assert message == "#{@scenario} median 6.0% from the mean of [94, 100, 106]"
    end

    test "every scenario outside the band is named" do
      runs =
        for median <- [100, 100, 130] do
          measured(median_ns: median)
          |> put_in(["scenarios", "BM.02 scan hits 1k"], stats(median_ns: 200 - median))
        end

      assert {:error, findings} = SigilGuard.BenchCompare.band(runs)

      assert Enum.map(findings, fn {:fail, message} -> hd(String.split(message, " median")) end) ==
               ["BM.01 scan clean 1k", "BM.02 scan hits 1k"]
    end

    test "fewer than three runs are refused" do
      assert {:error, [{:fail, "a baseline refresh needs at least 3 runs"}]} =
               SigilGuard.BenchCompare.band([measured(), measured()])

      assert {:error, [{:fail, "a baseline refresh needs at least 3 runs"}]} =
               SigilGuard.BenchCompare.band(:not_a_list)
    end

    test "a smoke run or a run without a mode is refused" do
      assert {:error, [{:fail, "run 2 is not a measured run"}]} =
               SigilGuard.BenchCompare.band([measured(), document(mode: "smoke"), measured()])

      assert {:error, [{:fail, "run 3 is not a measured run"}]} =
               SigilGuard.BenchCompare.band([measured(), measured(), document()])
    end

    test "runs from different runner classes or with different scenarios are refused" do
      other_cpu = put_in(measured(), ["environment", "hardware"], "other")

      assert {:error, [{:fail, "runs differ in runner class"}]} =
               SigilGuard.BenchCompare.band([measured(), measured(), other_cpu])

      extra = put_in(measured(), ["scenarios", "BM.99 new scenario"], stats(median_ns: 1))

      assert {:error, [{:fail, "runs differ in scenario set"}]} =
               SigilGuard.BenchCompare.band([measured(), extra, measured()])
    end

    test "a malformed run is refused with its position" do
      assert {:error, [{:fail, "run 2 missing schema"}]} =
               SigilGuard.BenchCompare.band([
                 measured(),
                 Map.delete(measured(), "schema"),
                 measured()
               ])

      assert {:error, [{:fail, "run 1 must be a JSON object"}]} =
               SigilGuard.BenchCompare.band([[], measured(), measured()])
    end

    test "the accepted last run is written as the baseline, without its mode and with sorted keys" do
      dir = Path.join(System.tmp_dir!(), "sigil_guard_band_#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      paths =
        for {median, index} <- Enum.with_index([100, 102, 99], 1) do
          path = Path.join(dir, "run-#{index}.json")
          File.write!(path, Jason.encode!(measured(median_ns: median)))
          path
        end

      out = Path.join(dir, "baseline.json")
      args = Enum.flat_map(paths, &["--band", &1]) ++ ["--write-baseline", out]

      ExUnit.CaptureIO.capture_io(fn -> assert :ok = SigilGuard.BenchCompare.main(args) end)

      text = File.read!(out)
      baseline = Jason.decode!(text)

      assert baseline == Map.delete(measured(median_ns: 99), "mode")
      assert :ok = SigilGuard.BenchCompare.validate_document(baseline, "baseline")

      assert Enum.sort_by(~w(environment recorded_at scenarios schema), &:binary.match(text, &1)) ==
               ~w(environment recorded_at scenarios schema)
    end
  end

  defp measured(overrides \\ []), do: document([mode: "measured"] ++ overrides)

  defp document(overrides \\ []) do
    mode = Keyword.get(overrides, :mode)
    stats_overrides = Keyword.drop(overrides, [:mode])

    document = %{
      "schema" => "sigil_guard_bench_baseline/v1",
      "environment" => %{
        "hardware" => "runner",
        "cores" => 8,
        "os" => "unix/linux",
        "elixir" => "1.20.0",
        "otp" => "29",
        "benchee" => "warmup 2 s, time 5 s, memory_time 2 s",
        "date" => "2026-07-07",
        "sigil_guard" => "1.0.0 (abc123)"
      },
      "recorded_at" => "2026-07-07",
      "scenarios" => %{@scenario => stats(stats_overrides)}
    }

    if mode, do: Map.put(document, "mode", mode), else: document
  end

  defp stats(overrides) do
    Keyword.merge([median_ns: 100, p99_ns: 150, memory_bytes: 10], overrides)
    |> Map.new(fn {key, value} -> {Atom.to_string(key), value} end)
  end
end

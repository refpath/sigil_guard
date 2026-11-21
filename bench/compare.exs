defmodule SigilGuard.BenchCompare do
  @moduledoc false

  @schema "sigil_guard_bench_baseline/v1"
  @threshold 0.20
  @band 0.05
  @band_runs 3
  @runner_keys ~w(hardware cores os elixir otp benchee)
  @stat_keys ~w(median_ns p99_ns memory_bytes)

  @type finding ::
          {:fail, String.t()}
          | {:warn, String.t()}
          | {:pass, String.t()}

  @doc """
  Compare a run with the baseline, or check a baseline refresh with
  `--band` given once per run. Halts with status 1 on a failure.
  """
  @spec main([String.t()]) :: :ok
  def main(argv \\ System.argv()) do
    case parse_args(argv) do
      %{band: [_ | _]} = opts -> main_band(opts)
      opts -> main_compare(opts)
    end
  end

  @doc """
  Check that a baseline refresh holds: at least three measured runs of one
  runner class with the same scenarios, and every scenario's median within
  +/-5% of the mean of its medians.
  """
  @spec band([term()]) :: {:ok, [finding()]} | {:error, [finding()]}
  def band(runs) when is_list(runs) and length(runs) >= @band_runs do
    with :ok <- validate_band_runs(runs),
         :ok <- same_across(runs, &runner_class/1, "runner class"),
         :ok <- same_across(runs, &scenario_names/1, "scenario set") do
      band_findings(runs)
    else
      {:error, reason} -> {:error, [{:fail, reason}]}
    end
  end

  def band(_), do: {:error, [{:fail, "a baseline refresh needs at least #{@band_runs} runs"}]}

  @doc "The baseline document for an accepted run: the run without its `mode`."
  @spec baseline(map()) :: map()
  def baseline(run) when is_map(run), do: Map.delete(run, "mode")

  defp main_band(opts) do
    runs = Enum.map(opts.band, &read_json!/1)

    case band(runs) do
      {:ok, findings} ->
        print_findings(findings)
        write_baseline(opts.write_baseline, List.last(runs))

      {:error, findings} ->
        print_findings(findings)
        System.halt(1)
    end
  end

  defp write_baseline(nil, _), do: :ok

  defp write_baseline(path, run) do
    json = Jason.encode!(ordered(baseline(run)), pretty: true)
    File.write!(path, [json, "\n"])
    Mix.shell().info("Wrote #{path}")
  end

  # Sorted keys keep a baseline refresh a readable diff.
  defp ordered(map) when is_map(map) do
    map
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(fn {key, value} -> {key, ordered(value)} end)
    |> Jason.OrderedObject.new()
  end

  defp ordered(value), do: value

  defp validate_band_runs(runs) do
    Enum.reduce_while(Enum.with_index(runs, 1), :ok, fn {run, index}, :ok ->
      case validate_band_run(run, "run #{index}") do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_band_run(run, label) when is_map(run) do
    with :ok <- validate_document(run, label) do
      if run["mode"] == "measured",
        do: :ok,
        else: {:error, "#{label} is not a measured run"}
    end
  end

  defp validate_band_run(_, label), do: {:error, "#{label} must be a JSON object"}

  defp same_across(runs, key, what) do
    if match?([_], Enum.uniq_by(runs, key)),
      do: :ok,
      else: {:error, "runs differ in #{what}"}
  end

  defp scenario_names(run), do: Enum.sort(Map.keys(run["scenarios"]))

  defp band_findings([first | _] = runs) do
    outside =
      first["scenarios"]
      |> Map.keys()
      |> Enum.sort()
      |> Enum.flat_map(fn name ->
        band_finding(name, Enum.map(runs, & &1["scenarios"][name]["median_ns"]))
      end)

    case outside do
      [] -> {:ok, [{:pass, "every scenario median within +/-5% across #{length(runs)} runs"}]}
      _ -> {:error, outside}
    end
  end

  defp band_finding(name, medians) do
    deviation = mean_deviation(medians)

    if deviation > @band do
      percent = Float.round(deviation * 100, 1)
      values = inspect(medians, charlists: :as_lists)
      [{:fail, "#{name} median #{percent}% from the mean of #{values}"}]
    else
      []
    end
  end

  # The largest distance of a median from the mean, as a fraction of the mean.
  defp mean_deviation(medians) do
    mean = Enum.sum(medians) / length(medians)

    if mean == 0,
      do: 0.0,
      else: Enum.max(Enum.map(medians, &abs(&1 - mean))) / mean
  end

  defp main_compare(opts) do
    baseline = read_json!(opts.baseline)
    run = read_json!(opts.run)

    if opts.require_comparable and
         (smoke_run?(run) or runner_class(baseline) != runner_class(run)) do
      raise ArgumentError, "measured results from a comparable runner are required"
    end

    case compare(baseline, run) do
      {:ok, findings} ->
        print_findings(findings)
        :ok

      {:error, findings} ->
        print_findings(findings)
        System.halt(1)
    end
  end

  @doc "Compare two benchmark documents and return the findings."
  @spec compare(term(), term()) :: {:ok, [finding()]} | {:error, [finding()]}
  def compare(baseline, run) when is_map(baseline) and is_map(run) do
    with :ok <- validate_document(baseline, "baseline"),
         :ok <- validate_document(run, "run") do
      compare_valid(baseline, run)
    else
      {:error, reason} -> {:error, [{:fail, reason}]}
    end
  end

  def compare(_, _), do: {:error, [{:fail, "benchmark documents must be JSON objects"}]}

  @doc "Check that `document` has the shape of a benchmark run or baseline."
  @spec validate_document(map(), String.t()) :: :ok | {:error, String.t()}
  def validate_document(document, label) do
    with :ok <- require_field(document, "schema", label),
         :ok <- require_field(document, "environment", label),
         :ok <- require_field(document, "recorded_at", label),
         :ok <- require_field(document, "scenarios", label),
         :ok <- require_schema(document, label),
         :ok <- require_environment(document["environment"], label),
         :ok <- require_recorded_at(document["recorded_at"], label),
         :ok <- require_mode(document, label) do
      require_scenarios(document["scenarios"], label)
    end
  end

  defp compare_valid(baseline, run) do
    cond do
      smoke_run?(run) ->
        smoke_compare(baseline["scenarios"], run["scenarios"])

      runner_class(baseline) == runner_class(run) ->
        binding_compare(baseline["scenarios"], run["scenarios"])

      true ->
        {:ok,
         [
           {:warn,
            "runner class differs from baseline; comparison is informational and does not fail"}
         ]}
    end
  end

  defp binding_compare(baseline_scenarios, run_scenarios) do
    regressions =
      baseline_scenarios
      |> Enum.flat_map(fn {name, baseline_stats} ->
        case Map.fetch(run_scenarios, name) do
          {:ok, run_stats} -> regression_findings(name, baseline_stats, run_stats)
          :error -> []
        end
      end)

    findings = scenario_presence_findings(baseline_scenarios, run_scenarios) ++ regressions

    if Enum.any?(findings, &match?({:fail, _}, &1)) do
      {:error, findings}
    else
      {:ok, pass_if_empty(findings)}
    end
  end

  defp smoke_compare(baseline_scenarios, run_scenarios) do
    findings = scenario_presence_findings(baseline_scenarios, run_scenarios)

    if Enum.any?(findings, &match?({:fail, _}, &1)) do
      {:error, findings}
    else
      {:ok, pass_if_empty(findings, "smoke benchmark matrix matches baseline")}
    end
  end

  defp scenario_presence_findings(baseline_scenarios, run_scenarios) do
    missing =
      baseline_scenarios
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(run_scenarios, &1))
      |> Enum.map(&{:fail, "missing run scenario: #{&1}"})

    new_scenarios =
      run_scenarios
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(baseline_scenarios, &1))
      |> Enum.map(&{:warn, "new scenario without baseline: #{&1}"})

    missing ++ new_scenarios
  end

  defp regression_findings(name, baseline_stats, run_stats) do
    Enum.flat_map([{"median_ns", "median"}, {"memory_bytes", "allocation"}], fn {metric, label} ->
      baseline_value = baseline_stats[metric]
      run_value = run_stats[metric]

      if run_value > baseline_value * (1 + @threshold) do
        [
          {:fail,
           "#{name} #{label} regressed by #{percent(run_value, baseline_value)} " <>
             "(#{run_value} vs #{baseline_value})"}
        ]
      else
        []
      end
    end)
  end

  defp pass_if_empty(findings, message \\ "no binding benchmark regressions")
  defp pass_if_empty([], message), do: [{:pass, message}]
  defp pass_if_empty(findings, _), do: findings

  defp percent(_, 0), do: "unbounded increase from zero"

  defp percent(run, baseline) when baseline > 0 do
    ((run - baseline) / baseline * 100)
    |> Float.round(1)
    |> then(&"#{&1}%")
  end

  defp runner_class(document) do
    Map.take(document["environment"], @runner_keys)
  end

  defp require_field(document, field, label) do
    if Map.has_key?(document, field), do: :ok, else: {:error, "#{label} missing #{field}"}
  end

  defp require_schema(%{"schema" => @schema}, _), do: :ok
  defp require_schema(_, label), do: {:error, "#{label} has unsupported schema"}

  defp require_environment(environment, label) when is_map(environment) do
    missing = Enum.reject(@runner_keys ++ ["date", "sigil_guard"], &Map.has_key?(environment, &1))

    case missing do
      [] -> :ok
      _ -> {:error, "#{label} environment missing #{Enum.join(missing, ", ")}"}
    end
  end

  defp require_environment(_, label), do: {:error, "#{label} environment must be an object"}

  defp require_recorded_at(date, _) when is_binary(date) do
    case Date.from_iso8601(date) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, "recorded_at must be an ISO 8601 date"}
    end
  end

  defp require_recorded_at(_, _), do: {:error, "recorded_at must be a string"}

  defp require_mode(%{"mode" => mode}, label) when mode not in ["measured", "smoke"] do
    {:error, "#{label} mode must be measured or smoke"}
  end

  defp require_mode(_, _), do: :ok

  defp smoke_run?(%{"mode" => "smoke"}), do: true
  defp smoke_run?(_), do: false

  defp require_scenarios(scenarios, label) when is_map(scenarios) and map_size(scenarios) > 0 do
    scenarios
    |> Enum.find_value(:ok, fn {name, stats} -> validate_stats(name, stats, label) end)
  end

  defp require_scenarios(_, label), do: {:error, "#{label} scenarios must be a non-empty object"}

  defp validate_stats(name, stats, label) when is_binary(name) and is_map(stats) do
    cond do
      missing_stat = Enum.find(@stat_keys, &(not Map.has_key?(stats, &1))) ->
        {:error, "#{label} scenario #{name} missing #{missing_stat}"}

      Enum.any?(@stat_keys, &(not non_negative_integer?(stats[&1]))) ->
        {:error, "#{label} scenario #{name} has invalid numeric statistics"}

      true ->
        false
    end
  end

  defp validate_stats(_, _, label), do: {:error, "#{label} scenario entries are invalid"}

  defp non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp read_json!(path) do
    path
    |> File.read!()
    |> Jason.decode!()
  end

  defp parse_args(argv) do
    {opts, _, invalid} =
      OptionParser.parse(argv,
        strict: [
          baseline: :string,
          run: :string,
          require_comparable: :boolean,
          band: :keep,
          write_baseline: :string
        ],
        aliases: [b: :baseline, r: :run]
      )

    if invalid != [] do
      raise ArgumentError, "invalid options: #{inspect(invalid)}"
    end

    %{
      band: Keyword.get_values(opts, :band),
      write_baseline: Keyword.get(opts, :write_baseline),
      require_comparable: Keyword.get(opts, :require_comparable, false),
      baseline: Keyword.get(opts, :baseline, "bench/baseline.json"),
      run: Keyword.get(opts, :run, "bench/output/benchmarks.json")
    }
  end

  defp print_findings(findings) do
    Enum.each(findings, fn
      {:pass, message} -> Mix.shell().info("PASS: #{message}")
      {:warn, message} -> Mix.shell().info("WARN: #{message}")
      {:fail, message} -> Mix.shell().error("FAIL: #{message}")
    end)
  end
end

unless function_exported?(Mix, :env, 0) and Mix.env() == :test do
  SigilGuard.BenchCompare.main()
end

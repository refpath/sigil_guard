defmodule SigilGuard.Bench do
  @moduledoc """
  Shared harness for the benchmark suites in `bench/`.

  A suite is a module that implements this behaviour. `run/2` checks each
  suite's fixtures, times its scenarios with Benchee, and writes one Markdown
  page per suite to `bench/output/`. `run_all/2` also writes the summary page
  and the machine-readable `benchmarks.json` that `bench/compare.exs` reads.

  A smoke run (`--smoke`, or `CI=true`) uses tiny budgets and writes under
  `bench/output/smoke/`, so it never replaces the published pages.
  """

  # Benchee is a development dependency. The test environment loads this file
  # to check the fixtures and never runs a suite.
  @compile {:no_warn_undefined, [Benchee, Benchee.Formatter]}

  @typedoc "Scenario name to the function Benchee times."
  @type scenarios :: %{required(String.t()) => (-> term())}

  @typedoc "Scenario name to its median, 99th percentile and memory per call."
  @type stats :: %{required(String.t()) => %{required(String.t()) => non_neg_integer()}}

  @doc "File name stem of the suite's page, such as `\"scanner\"`."
  @callback id() :: String.t()

  @doc "Title of the suite's page."
  @callback title() :: String.t()

  @doc "What the suite measures and why, as the page's opening paragraph."
  @callback description() :: String.t()

  @doc "The scenarios to time. Every name starts with its `BM.NN` id."
  @callback scenarios() :: scenarios()

  @doc """
  Evaluate each fixture once and raise when it takes another path than its
  scenario names.
  """
  @callback preconditions!() :: :ok

  @doc "Figures computed from the medians of this suite's scenarios."
  @callback derived(stats()) :: %{required(String.t()) => map()}

  @optional_callbacks derived: 1

  @schema "sigil_guard_bench_baseline/v1"
  @output_dir "bench/output"
  @smoke_dir "bench/output/smoke"
  @full_config [warmup: 2, time: 5, memory_time: 2]
  @smoke_config [warmup: 0, time: 0.01, memory_time: 0]
  @batch_target_ns 10_000

  @doc "Run a suite when its file is the script, not when another file loads it."
  @spec script(module()) :: :ok
  def script(suite) do
    unless library?(), do: run([suite])
    :ok
  end

  @doc "Mark this process as loading suites for their definitions only."
  @spec library!() :: :ok
  def library! do
    Process.put(:sigil_guard_bench_library, true)
    :ok
  end

  defp library?, do: Process.get(:sigil_guard_bench_library, false) or test_env?()

  defp test_env?, do: function_exported?(Mix, :env, 0) and Mix.env() == :test

  @doc "Time the given suites and write their pages. Returns each suite's stats."
  @spec run([module()], [String.t()]) :: [{module(), stats()}]
  def run(suites, argv \\ System.argv()) do
    smoke? = smoke?(argv)
    dir = output_dir(smoke?)
    File.mkdir_p!(dir)

    for suite <- suites do
      suite.preconditions!()
      {suite, run_suite(suite, smoke?, dir)}
    end
  end

  @doc "Time every suite, then write the summary page and `benchmarks.json`."
  @spec run_all([module()], [String.t()]) :: :ok
  def run_all(suites, argv \\ System.argv()) do
    smoke? = smoke?(argv)
    results = run(suites, argv)

    write_summary(results, smoke?, output_dir(smoke?))
  end

  @doc "Whether the run uses the smoke budgets."
  @spec smoke?([String.t()]) :: boolean()
  def smoke?(argv), do: "--smoke" in argv or System.get_env("CI") in ["true", "1"]

  @doc "Benchee budgets for a smoke or a measured run."
  @spec bench_config(boolean()) :: keyword()
  def bench_config(true), do: @smoke_config
  def bench_config(false), do: @full_config

  @doc "Where a smoke or a measured run writes."
  @spec output_dir(boolean()) :: Path.t()
  def output_dir(true), do: @smoke_dir
  def output_dir(false), do: @output_dir

  @doc "The `BM.NN` id a scenario name starts with."
  @spec scenario_id(String.t()) :: String.t()
  def scenario_id("BM." <> rest) do
    [number | _] = String.split(rest, " ", parts: 2)
    "BM." <> number
  end

  @doc "The ids of every scenario in the given suites."
  @spec scenario_ids([module()]) :: MapSet.t(String.t())
  def scenario_ids(suites) do
    for suite <- suites, name <- Map.keys(suite.scenarios()), into: MapSet.new() do
      scenario_id(name)
    end
  end

  @doc "Raise unless a precondition holds. `label` names the scenario."
  @spec expect!(boolean(), String.t()) :: :ok
  def expect!(true, _), do: :ok
  def expect!(_, label), do: raise("benchmark fixture precondition failed: #{label}")

  defp run_suite(suite, smoke?, dir) do
    file = Path.join(dir, suite.id() <> ".md")
    scenarios = suite.scenarios()
    batches = Map.new(scenarios, fn {name, fun} -> {name, batch_size(fun, smoke?)} end)

    config =
      Keyword.merge(bench_config(smoke?),
        percentiles: [99],
        print: [fast_warning: false],
        formatters: [
          Benchee.Formatters.Console,
          {Benchee.Formatters.Markdown, file: file, description: page_description(suite, smoke?)}
        ]
      )

    # The stages of `Benchee.run/2`, with the samples of batched scenarios
    # divided back to one call before the statistics are computed.
    result =
      config
      |> Benchee.init()
      |> Benchee.system()
      |> add_jobs(scenarios, batches)
      |> Benchee.collect()
      |> per_call(batches)
      |> Benchee.statistics()
      |> Benchee.relative_statistics()
      |> Benchee.Formatter.output()

    stats = scenario_stats(result)
    place_header!(file, page_header(smoke?, suite_derived(suite, stats)))
    stats
  end

  defp page_description(suite, smoke?) do
    """
    # #{suite.title()}

    #{String.trim(suite.description())}

    Mode: #{mode(smoke?)}. Values are measured for this environment, not ratified SLO bounds.
    Scenarios that take less than #{div(@batch_target_ns, 1_000)} µs run in batches of calls;
    every value is per call.
    """
  end

  defp add_jobs(suite, scenarios, batches) do
    Enum.reduce(scenarios, suite, fn {name, fun}, acc ->
      Benchee.benchmark(acc, name, batched(fun, Map.fetch!(batches, name)))
    end)
  end

  @doc """
  How many calls of `fun` one timed sample runs.

  A clock that reports nanoseconds may advance in coarser steps (about 42 ns
  on Apple silicon), and Benchee repeats a fast function only when the
  reported resolution is coarse. A scenario under the target therefore runs
  enough calls per sample to take about #{div(@batch_target_ns, 1_000)} µs, which keeps one clock
  step under half a percent of a sample. A smoke run times single calls.
  """
  @spec batch_size((-> term()), boolean()) :: pos_integer()
  def batch_size(_, true), do: 1

  def batch_size(fun, false) do
    fun.()
    {calls, elapsed_ns} = time_calls(fun, 1, 0)
    per_call = max(div(elapsed_ns, calls), 1)

    # One nanosecond per call is the floor, so a batch never exceeds 10,000.
    if per_call >= @batch_target_ns,
      do: 1,
      else: div(@batch_target_ns + per_call - 1, per_call)
  end

  defp time_calls(fun, calls, elapsed_ns) when elapsed_ns < 2_000_000 and calls < 1_000_000 do
    start = System.monotonic_time(:nanosecond)
    Enum.each(1..calls, fn _ -> fun.() end)
    time_calls(fun, calls * 2, elapsed_ns + System.monotonic_time(:nanosecond) - start)
  end

  defp time_calls(_, calls, elapsed_ns), do: {calls - 1, elapsed_ns}

  @doc "A function that runs `fun` `n` times."
  @spec batched((-> term()), pos_integer()) :: (-> term())
  def batched(fun, 1), do: fun
  def batched(fun, n), do: fn -> Enum.each(1..n, fn _ -> fun.() end) end

  @doc """
  Divide the samples of each batched scenario by its batch size, so the
  statistics and the pages describe one call.
  """
  @spec per_call(map(), %{required(String.t()) => pos_integer()}) :: map()
  def per_call(%{scenarios: scenarios} = suite, batches) do
    %{
      suite
      | scenarios: Enum.map(scenarios, &scenario_per_call(&1, Map.get(batches, &1.name, 1)))
    }
  end

  defp scenario_per_call(scenario, 1), do: scenario

  defp scenario_per_call(scenario, n) do
    %{
      scenario
      | run_time_data: divide_samples(scenario.run_time_data, n),
        memory_usage_data: divide_samples(scenario.memory_usage_data, n),
        reductions_data: divide_samples(scenario.reductions_data, n)
    }
  end

  defp divide_samples(%{samples: samples} = data, n),
    do: %{data | samples: Enum.map(samples, &(&1 / n))}

  defp suite_derived(suite, stats) do
    if function_exported?(suite, :derived, 1), do: suite.derived(stats), else: %{}
  end

  defp scenario_stats(%{scenarios: scenarios}) do
    Map.new(scenarios, fn scenario ->
      run_time = scenario.run_time_data.statistics
      memory = scenario.memory_usage_data.statistics

      {scenario.name,
       %{
         "median_ns" => round(run_time.median || 0),
         "p99_ns" => round(run_time.percentiles[99] || run_time.maximum || 0),
         "memory_bytes" => round(memory.average || memory.median || 0)
       }}
    end)
  end

  defp write_summary(results, smoke?, dir) do
    scenarios = Enum.reduce(results, %{}, fn {_, stats}, acc -> Map.merge(acc, stats) end)

    derived =
      Enum.reduce(results, %{}, fn {suite, stats}, acc ->
        Map.merge(acc, suite_derived(suite, stats))
      end)

    document = %{
      "schema" => @schema,
      "mode" => mode(smoke?),
      "environment" => environment(smoke?),
      "recorded_at" => Date.to_iso8601(Date.utc_today()),
      "scenarios" => scenarios,
      "derived" => derived
    }

    File.write!(Path.join(dir, "benchmarks.json"), Jason.encode!(document, pretty: true))
    File.write!(Path.join(dir, "benchmarks.md"), summary_markdown(results, smoke?, derived))
    :ok
  end

  @doc "The summary page: environment, derived figures, and every scenario."
  @spec summary_markdown([{module(), stats()}], boolean(), map()) :: String.t()
  def summary_markdown(results, smoke?, derived) do
    sections =
      Enum.map_join(results, "\n", fn {suite, stats} ->
        rows =
          stats
          |> Enum.sort()
          |> Enum.map_join("\n", fn {name, stat} ->
            "| #{name} | #{microseconds(stat["median_ns"])} | " <>
              "#{microseconds(stat["p99_ns"])} | #{stat["memory_bytes"]} |"
          end)

        """
        ## #{suite.title()}

        #{String.trim(suite.description())}

        Full statistics: [#{suite.title()}](#{suite.id()}.md).

        | Scenario | Median (us) | p99 (us) | Memory (bytes) |
        |----------|------------:|---------:|---------------:|
        #{rows}
        """
      end)

    """
    # SigilGuard Performance Benchmarks

    Mode: #{mode(smoke?)}. Values are measured for this environment, not ratified SLO bounds.
    Each suite has its own page with the full Benchee statistics.

    #{page_header(smoke?, derived)}
    #{sections}
    """
  end

  defp page_header(smoke?, derived) when map_size(derived) == 0, do: environment_markdown(smoke?)

  defp page_header(smoke?, derived),
    do: environment_markdown(smoke?) <> "\n" <> derived_markdown(derived)

  # Benchee's page opens with a bare "Benchmark" line, the description, and
  # its own system table. The environment block and the derived figures go
  # between the description and that table.
  defp place_header!(file, header) do
    body = String.replace_prefix(File.read!(file), "Benchmark\n\n", "")

    page =
      case String.split(body, "## System", parts: 2) do
        [intro, rest] -> intro <> header <> "\n## System" <> rest
        [_] -> header <> "\n\n" <> body
      end

    File.write!(file, page)
  end

  @doc "The derived-figures table of a page."
  @spec derived_markdown(map()) :: String.t()
  def derived_markdown(derived) do
    rows =
      derived
      |> Enum.sort()
      |> Enum.map_join("\n", fn {name, figure} ->
        "| #{name} | #{microseconds(figure["median_ns"])} | #{figure["percent"] || ""} |"
      end)

    """
    ## Derived figures

    | Figure | Median (us) | Percent |
    |--------|------------:|--------:|
    #{rows}
    """
  end

  @doc "The difference of two scenario medians, with a percentage of the base."
  @spec overhead(stats(), String.t(), String.t()) :: map()
  def overhead(stats, name, base_name) do
    delta = median(stats, name) - median(stats, base_name)

    %{"median_ns" => delta, "percent" => percent(delta, median(stats, base_name))}
  end

  @doc "The median of a scenario, or 0 when the run has none."
  @spec median(stats(), String.t()) :: non_neg_integer()
  def median(stats, name), do: get_in(stats, [name, "median_ns"]) || 0

  defp percent(_, 0), do: nil
  defp percent(delta, base), do: Float.round(delta * 100 / base, 1)

  defp microseconds(nanoseconds), do: :erlang.float_to_binary(nanoseconds / 1000, decimals: 3)

  defp mode(true), do: "smoke"
  defp mode(false), do: "measured"

  defp environment(smoke?) do
    %{
      "hardware" => cpu_info(),
      "cores" => System.schedulers_online(),
      "memory" => memory_info(),
      "os" => os_info(),
      "elixir" => System.version(),
      "otp" => System.otp_release(),
      "sigil_guard" => "#{Application.spec(:sigil_guard, :vsn)} (#{git_commit()})",
      "benchee" => benchee_label(smoke?),
      "date" => Date.to_iso8601(Date.utc_today())
    }
  end

  defp environment_markdown(smoke?) do
    env = environment(smoke?)

    """
    ## Environment

    - Hardware: #{env["hardware"]}, #{env["cores"]} cores, #{env["memory"]}
    - OS: #{env["os"]}
    - Elixir: #{env["elixir"]} / OTP: #{env["otp"]}
    - SigilGuard: #{env["sigil_guard"]}
    - Benchee: #{env["benchee"]}
    - Date: #{env["date"]}
    """
  end

  defp benchee_label(smoke?) do
    config = bench_config(smoke?)

    "warmup #{format_duration(config[:warmup])}, time #{format_duration(config[:time])}, " <>
      "memory_time #{format_duration(config[:memory_time])}"
  end

  defp format_duration(0), do: "0 ns"

  defp format_duration(seconds) when is_float(seconds) and seconds < 1,
    do: "#{round(seconds * 1000)} ms"

  defp format_duration(seconds), do: "#{seconds} s"

  defp cpu_info do
    case command("sysctl", ["-n", "machdep.cpu.brand_string"]) do
      {:ok, cpu} -> cpu
      :error -> inspect(:erlang.system_info(:cpu_topology), limit: 8)
    end
  end

  # Runs a command with an empty environment and returns its trimmed output.
  # A command that is missing or fails is `:error`.
  defp command(name, args) do
    case System.cmd(name, args, env: clean_env(), stderr_to_stdout: true) do
      {output, 0} -> {:ok, String.trim(output)}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  # Nothing these commands print depends on the caller's environment, so they
  # get none of it apart from the search path.
  defp clean_env do
    for {name, _} <- System.get_env(), name != "PATH", do: {name, nil}
  end

  @doc "Installed memory in whole gigabytes, or `unknown RAM`."
  @spec memory_info() :: String.t()
  def memory_info do
    case memory_bytes() do
      bytes when is_integer(bytes) and bytes > 0 -> "#{round(bytes / 1_073_741_824)} GB RAM"
      _ -> "unknown RAM"
    end
  end

  defp memory_bytes do
    case :os.type() do
      {:unix, :darwin} -> sysctl_integer("hw.memsize")
      {:unix, _} -> meminfo_bytes()
      _ -> nil
    end
  end

  defp sysctl_integer(name) do
    with {:ok, value} <- command("sysctl", ["-n", name]),
         {bytes, _} <- Integer.parse(value) do
      bytes
    else
      _ -> nil
    end
  end

  defp meminfo_bytes do
    with {:ok, text} <- File.read("/proc/meminfo"),
         [_, kilobytes] <- Regex.run(~r/^MemTotal:\s+(\d+) kB/m, text) do
      String.to_integer(kilobytes) * 1024
    else
      _ -> nil
    end
  end

  defp os_info do
    {family, name} = :os.type()
    "#{family}/#{name}"
  end

  defp git_commit do
    case command("git", ["rev-parse", "--short", "HEAD"]) do
      {:ok, commit} -> commit
      :error -> "unknown"
    end
  end
end

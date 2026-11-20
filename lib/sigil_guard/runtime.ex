defmodule SigilGuard.Runtime do
  @moduledoc """
  Caller-supervised owner for SigilGuard's in-memory runtime state.

  SigilGuard starts this runtime automatically by default. To control its
  supervision-tree placement, disable automatic startup and add the child to
  the host application:

      config :sigil_guard, runtime: false

      children = [
        {SigilGuard.Runtime,
         config: [
           trust_bundle: {:priv, :my_app, "sigil/trust_bundle.json"},
           scanner_patterns: :bundle
         ]}
      ]

  Obtain boundary options with `scanner_options/2` and pass them to the gate
  or stream. Selecting `:bundle` in configuration alone does not alter standalone
  scanner calls.

  Passing `:config` keeps the runtime's own behaviour out of the global
  application environment: which bundle it loads and what `scanner_options/2`
  returns. Include `runtime: false` in explicit configuration to describe that
  posture. When `:config` is omitted, the runtime validates configuration from
  `config :sigil_guard, ...` for backwards-compatible host configuration.

  The other keys are validated here and read elsewhere. `SigilGuard.Attestation`
  takes `:ttl_ms`, `:max_skew_ms` and `:replay_ttl_ms` per call and falls back
  to the application environment, and `SigilGuard.Identity.Static.trust_level/1`
  reads `:trust_mappings` from the application environment. Neither asks the
  runtime. A host that configures the runtime explicitly applies those values
  with `attestation_options/1` and `trust_mappings/1`:

      opts = SigilGuard.Runtime.attestation_options()
      SigilGuard.Attestation.verify(envelope, trust_material, opts ++ [payload: payload])

      mappings = SigilGuard.Runtime.trust_mappings()
      SigilGuard.Identity.Static.trust_level(actor, mappings)

  SigilGuard's tables are intentionally process-global named tables, so a host
  should run exactly one runtime. Only the runtime creates them. Without a
  running runtime the stateful functions fail closed: a nonce cannot be
  recorded (`:replay_store_unavailable`), the default rate limiter refuses,
  and the bundle cache reads as empty and refuses a write
  (`:cache_unavailable`). The runtime fails fast when another process has
  created one of the tables first.
  """

  use GenServer

  alias SigilGuard.Config
  alias SigilGuard.Policy
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @typedoc "A `start_link/1` option."
  @type option :: {:config, keyword()} | {:name, GenServer.name()}

  @doc "Start the runtime and take ownership of SigilGuard's named ETS tables."
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) when is_list(opts) do
    {name, init_opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, init_opts, name: name)
  end

  @doc "Return the validated configuration held by a running runtime."
  @spec configuration(GenServer.server()) :: keyword()
  def configuration(server \\ __MODULE__), do: GenServer.call(server, :configuration)

  @doc """
  Resolve scanner and quarantine options from this runtime's verified bundle.

  Pass the returned options to `SigilGuard.Runtime.Gate.evaluate/3` or
  `SigilGuard.Runtime.Stream.new/2`. Bare scanner calls use built-ins. Bundle
  freshness is rechecked when resolving options; resolve again at each boundary.
  """
  @spec scanner_options(GenServer.server(), keyword()) :: {:ok, keyword()} | {:error, atom()}
  def scanner_options(server \\ __MODULE__, opts \\ []) do
    config = configuration(server, [:scanner_patterns, :trust_bundle])

    case Keyword.fetch!(config, :scanner_patterns) do
      :built_in ->
        {:ok, []}

      :bundle ->
        with {:ok, bundle} <- TrustBundle.load(Keyword.fetch!(config, :trust_bundle), opts),
             {:ok, sets} <- TrustBundle.pattern_sets(bundle) do
          {:ok, [patterns: sets.secret, indicator_sets: Map.take(sets, [:injection, :poisoning])]}
        end
    end
  end

  @doc """
  Return the attestation options of this runtime's configuration.

  The result is `[ttl_ms: _, max_skew_ms: _, replay_ttl_ms: _]`, from the
  `:attestation_ttl_ms`, `:max_skew_ms` and `:replay_ttl_ms` keys. Pass it to
  `SigilGuard.Attestation.from_decision/3`, `sign/3` and `verify/3`, which
  otherwise read the application environment.
  """
  @doc since: "1.1.0"
  @spec attestation_options(GenServer.server()) :: keyword()
  def attestation_options(server \\ __MODULE__) do
    config = configuration(server, [:attestation_ttl_ms, :max_skew_ms, :replay_ttl_ms])

    [
      ttl_ms: Keyword.fetch!(config, :attestation_ttl_ms),
      max_skew_ms: Keyword.fetch!(config, :max_skew_ms),
      replay_ttl_ms: Keyword.fetch!(config, :replay_ttl_ms)
    ]
  end

  @doc """
  Return the actor-to-trust table of this runtime's configuration.

  Pass it to `SigilGuard.Identity.Static.trust_level/2`.
  """
  @doc since: "1.1.0"
  @spec trust_mappings(GenServer.server()) :: [{String.t(), SigilGuard.Identity.trust_level()}]
  def trust_mappings(server \\ __MODULE__),
    do: Keyword.fetch!(configuration(server, [:trust_mappings]), :trust_mappings)

  # The helpers above run at each boundary; asking for their keys copies a
  # few values out of the runtime instead of the whole configuration, which
  # can hold an inline bundle source and the vault master key.
  defp configuration(server, keys), do: GenServer.call(server, {:configuration, keys})

  @impl GenServer
  def init(opts) do
    config = runtime_config!(opts)

    Policy.ensure_rate_table()
    ReplayStore.ensure_table()
    Cache.ensure_table()
    Quarantine.ensure_table()
    ensure_table_ownership!()
    TrustBundle.load_configured!(config)

    {:ok, config}
  end

  @impl GenServer
  def handle_call(:configuration, _, config), do: {:reply, config, config}

  def handle_call({:configuration, keys}, _, config),
    do: {:reply, Keyword.take(config, keys), config}

  defp runtime_config!(opts) do
    case Keyword.validate(opts, config: :application_env) do
      {:ok, validated} ->
        case Keyword.fetch!(validated, :config) do
          :application_env -> Config.validate!()
          config -> Config.validate!(config)
        end

      {:error, invalid} ->
        raise ArgumentError, "invalid SigilGuard.Runtime options: #{inspect(invalid)}"
    end
  end

  defp ensure_table_ownership! do
    owner = self()

    Enum.each(SigilGuard.Runtime.Tables.all(), fn table ->
      case :ets.info(table, :owner) do
        ^owner ->
          :ok

        other ->
          raise ArgumentError,
                "SigilGuard.Runtime cannot own #{inspect(table)}; it is already owned by " <>
                  "#{inspect(other)}. Start the runtime before calling stateful APIs."
      end
    end)
  end
end

defmodule SigilGuard.Backend do
  @moduledoc """
  Behaviour of the SigilGuard processing backend.

  `SigilGuard.Backend.Elixir` is the only backend. The `:backend` application
  key was removed in 1.0: `impl/0` raises `SigilGuard.ConfigError` when it is
  set, as `SigilGuard.Config` does at runtime start. To change how text is
  scanned, pass a `:pipeline` module to `SigilGuard.Scanner.scan/2`.

  ## Example

      backend = SigilGuard.Backend.impl()
      {:ok, "safe"} = backend.scan("safe", [])

  """

  alias SigilGuard.Audit
  alias SigilGuard.Identity
  alias SigilGuard.Patterns
  alias SigilGuard.Policy

  @typedoc "The backend module"
  @type backend_module :: SigilGuard.Backend.Elixir

  @typedoc "Backend configuration atoms"
  @type backend_type :: :elixir

  @doc "Scan text for sensitive content."
  @callback scan(text :: String.t(), opts :: keyword()) ::
              {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}

  @doc "Replace matched regions with replacement hints."
  @callback redact(text :: String.t(), hits :: [Patterns.scan_hit()], opts :: keyword()) ::
              String.t()

  @doc "Scan and redact in a single pass."
  @callback scan_and_redact(text :: String.t(), opts :: keyword()) :: String.t()

  @doc "Evaluate an action against a trust level."
  @callback evaluate_policy(
              action :: String.t(),
              trust_level :: Identity.trust_level(),
              opts :: keyword()
            ) :: Policy.verdict()

  @doc "Classify the risk level of an action."
  @callback classify_risk(action :: String.t(), opts :: keyword()) :: Policy.risk_level()

  @doc "Sign an audit event, linking it to the previous event in the chain."
  @callback audit_sign_event(event :: Audit.t(), key :: binary(), prev_hmac :: String.t() | nil) ::
              Audit.t()

  @doc "Verify the integrity of an audit event chain."
  @callback audit_verify_chain(events :: [Audit.t()], key :: binary()) ::
              :ok | {:broken, non_neg_integer()}

  @doc """
  Returns the backend module, `SigilGuard.Backend.Elixir`.

  Raises `SigilGuard.ConfigError` when the removed `:backend` application key
  is set, whatever its value.

  ## Examples

      iex> SigilGuard.Backend.impl()
      SigilGuard.Backend.Elixir

  """
  @spec impl() :: backend_module()
  def impl do
    case Application.fetch_env(:sigil_guard, :backend) do
      :error ->
        SigilGuard.Backend.Elixir

      {:ok, _} ->
        raise SigilGuard.ConfigError.new(
                :backend,
                :legacy_contract_removed,
                "legacy config key removed"
              )
    end
  end

  @doc """
  Check whether a backend is available on this system.

  ## Examples

      iex> SigilGuard.Backend.available?(:elixir)
      true

  """
  @spec available?(atom()) :: boolean()
  def available?(:elixir), do: true
  def available?(_), do: false

  @doc """
  Return the backends available on this system.
  """
  @spec available_backends() :: [backend_type(), ...]
  def available_backends, do: [:elixir]
end

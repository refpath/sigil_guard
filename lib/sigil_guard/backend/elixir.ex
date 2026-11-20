defmodule SigilGuard.Backend.Elixir do
  @moduledoc """
  Pure-Elixir backend using OTP `:crypto`.

  This is the default backend requiring no external dependencies beyond
  OTP. It delegates to the existing SigilGuard modules:

    * `SigilGuard.Scanner` — staged deterministic sensitivity scanning
    * `SigilGuard.Policy` — risk classification and trust gating
    * `SigilGuard.Audit` — HMAC-SHA256 chain integrity

  ## When to Use

  This is the only built-in backend. It keeps deployment simple, avoids
  native crash risk, and uses OTP `:crypto` plus BEAM regex/ETS primitives.

  ## Example

      {:hit, [hit]} = SigilGuard.Backend.Elixir.scan("AKIAIOSFODNN7EXAMPLE", [])
      hit.name
      # => "aws_access_key"

      SigilGuard.Backend.Elixir.classify_risk("read_file", [])
      # => :low

  """

  @behaviour SigilGuard.Backend

  alias SigilGuard.Audit
  alias SigilGuard.Identity
  alias SigilGuard.Patterns
  alias SigilGuard.Policy
  alias SigilGuard.Scanner

  @doc "Scan text with `SigilGuard.Scanner.scan/2`."
  @impl SigilGuard.Backend
  @spec scan(String.t(), keyword()) :: {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}
  def scan(text, opts), do: Scanner.scan(text, opts)

  @doc "Redact hits with `SigilGuard.Scanner.redact/3`."
  @impl SigilGuard.Backend
  @spec redact(String.t(), [Patterns.scan_hit()], keyword()) :: String.t()
  def redact(text, hits, opts), do: Scanner.redact(text, hits, opts)

  @doc "Scan and redact with `SigilGuard.Scanner.scan_and_redact/2`."
  @impl SigilGuard.Backend
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts), do: Scanner.scan_and_redact(text, opts)

  @doc "Evaluate an action with `SigilGuard.Policy.evaluate/3`."
  @impl SigilGuard.Backend
  @spec evaluate_policy(String.t(), Identity.trust_level(), keyword()) :: Policy.verdict()
  def evaluate_policy(action, trust_level, opts), do: Policy.evaluate(action, trust_level, opts)

  @doc "Classify an action with `SigilGuard.Policy.classify_risk/2`."
  @impl SigilGuard.Backend
  @spec classify_risk(String.t(), keyword()) :: Policy.risk_level()
  def classify_risk(action, opts), do: Policy.classify_risk(action, opts)

  @doc "Sign an audit event with `SigilGuard.Audit.sign_event/3`."
  @impl SigilGuard.Backend
  @spec audit_sign_event(Audit.t(), binary(), String.t() | nil) :: Audit.t()
  def audit_sign_event(event, key, prev_hmac), do: Audit.sign_event(event, key, prev_hmac)

  @doc "Verify an audit chain with `SigilGuard.Audit.verify_chain/2`."
  @impl SigilGuard.Backend
  @spec audit_verify_chain([Audit.t()], binary()) :: :ok | {:broken, non_neg_integer()}
  def audit_verify_chain(events, key), do: Audit.verify_chain(events, key)
end

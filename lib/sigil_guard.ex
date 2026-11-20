defmodule SigilGuard do
  @moduledoc """
  Native Elixir security runtime for MCP and agent tool boundaries.

  This module holds the shortest calls: scanning, redaction and the policy
  verdict. A host that guards MCP traffic starts at `SigilGuard.ToolGateway`
  or `SigilGuard.Runtime.Gate`; the module list below says where each part
  lives.

  ## Runtime Configuration

  Stateless APIs can be used without starting a process. ETS-backed rate,
  replay, and trust-bundle state is owned by `SigilGuard.Runtime`, which starts
  automatically by default and validates the closed 1.0 configuration surface.
  Hosts can disable automatic startup and supervise the runtime explicitly.
  The built-in backend is native Elixir and uses OTP `:crypto`, Regex, ETS,
  and ordinary OTP supervision; no backend selector is required.

  ## Quick Start

      {:ok, "safe text"} = SigilGuard.scan("safe text")
      {:hit, hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")

      "key=[AWS_KEY]" = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")

      :allowed = SigilGuard.policy_verdict("read_file", :medium)
      :blocked = SigilGuard.policy_verdict("delete_database", :low)

  ## Modules

  - `SigilGuard.ToolGateway` and `SigilGuard.MCP.Gateway`: MCP tool requests
    and results, manifests, attestations and confirmation tokens.
  - `SigilGuard.Runtime.Gate` and `SigilGuard.Runtime.Stream`: one boundary
    decision over text, and the same over chunks.
  - `SigilGuard.Scanner` and `SigilGuard.Patterns`: secret detection and
    redaction.
  - `SigilGuard.BoundaryPolicy` and `SigilGuard.RepoPolicy`: source-to-sink
    rules and repository path rules.
  - `SigilGuard.Confirmation`: approval tokens bound to one action.
  - `SigilGuard.Attestation` and `SigilGuard.AgentTrust`: signed Agent Trust
    statements.
  - `SigilGuard.TrustBundle`: signed local trust material.
  - `SigilGuard.Audit`, `SigilGuard.Audit.Checkpoint` and
    `SigilGuard.Audit.Export`: the HMAC event chain, Merkle checkpoints and
    signed exports.
  - `SigilGuard.EffectAuthority`: requests that change the physical world.
  - `SigilGuard.Vault`, `SigilGuard.Signer` and `SigilGuard.Identity`: host
    seams for secrets, signing keys and identity.
  """

  alias SigilGuard.Backend
  alias SigilGuard.Identity
  alias SigilGuard.Patterns
  alias SigilGuard.Policy
  alias SigilGuard.Runtime

  @doc """
  Scan text for sensitive content.

  Returns `{:ok, text}` if clean, or `{:hit, hits}` with match details.

  ## Options

    * `:patterns` — compiled patterns to use (default: built-in patterns)

  ## Examples

      iex> SigilGuard.scan("safe text")
      {:ok, "safe text"}

      iex> {:hit, hits} = SigilGuard.scan("Bearer sk-abc123def456ghi789jkl012mno345")
      ...> hd(hits).name
      "bearer_token"

  """
  @spec scan(String.t(), keyword()) :: {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}
  def scan(text, opts \\ []), do: Backend.impl().scan(text, opts)

  @doc """
  Replace matched regions in text with replacement hints.

  ## Options

    * `:default_replacement` — fallback when a hit has no hint (default: `"[REDACTED]"`)

  """
  @spec redact(String.t(), [Patterns.scan_hit()], keyword()) :: String.t()
  def redact(text, hits, opts \\ []), do: Backend.impl().redact(text, hits, opts)

  @doc """
  Scan and redact in a single pass.

  Returns the original text if clean, or the redacted version if hits are found.

  ## Examples

      iex> SigilGuard.scan_and_redact("nothing sensitive here")
      "nothing sensitive here"

  """
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts \\ []), do: Backend.impl().scan_and_redact(text, opts)

  @doc """
  Evaluate a boundary-aware runtime decision.

  This is the entrypoint for MCP/tool-call security. It combines
  scanning, quarantine indicators, source-to-sink rules, and policy
  evaluation into a `%SigilGuard.Decision{}`.

  ## Examples

      iex> decision =
      ...>   SigilGuard.guard("safe text", %{
      ...>     phase: :tool_result,
      ...>     sink: :model,
      ...>     trust_level: :medium
      ...>   })
      ...>
      ...> decision.verdict
      :allowed

  """
  @spec guard(term(), SigilGuard.Context.t() | map() | keyword(), keyword()) ::
          SigilGuard.Decision.t()
  def guard(payload, context \\ %SigilGuard.Context{}, opts \\ []) do
    Runtime.Gate.evaluate(payload, context, opts)
  end

  @doc """
  Evaluate an action against a trust level and return a verdict.

  Returns `:allowed`, `:blocked`, or `{:confirm, reason}`.

  ## Options

    * `:risk_level` — override the risk classification
    * `:risk_mappings` — map of action to risk level
    * `:trust_thresholds` — override default trust thresholds

  ## Examples

      iex> SigilGuard.policy_verdict("read_file", :medium)
      :allowed

      iex> SigilGuard.policy_verdict("delete_database", :low)
      :blocked

  """
  @spec policy_verdict(String.t(), Identity.trust_level(), keyword()) :: Policy.verdict()
  def policy_verdict(action, trust_level, opts \\ []) do
    Backend.impl().evaluate_policy(action, trust_level, opts)
  end
end

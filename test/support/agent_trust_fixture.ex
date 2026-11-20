defmodule SigilGuard.AgentTrustFixture do
  @moduledoc false

  # A peer agent with a card signed by a trusted issuer, and the request and
  # response a local agent exchanges with it.

  alias SigilGuard.AgentCard
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Decision

  @peer_id "spiffe://prod.example.org/agents/reviewer"

  defmodule Issuer do
    @moduledoc false
    use SigilGuard.TestSigner, seed: :binary.copy(<<0x21>>, 32)
  end

  defmodule Agent do
    @moduledoc false
    use SigilGuard.TestSigner, seed: :binary.copy(<<0x41>>, 32)
  end

  defmodule Local do
    @moduledoc false
    use SigilGuard.TestSigner, seed: :binary.copy(<<0x71>>, 32)
  end

  @doc false
  @spec peer_id() :: String.t()
  def peer_id, do: @peer_id

  @doc false
  @spec issuer_material() :: %{String.t() => binary()}
  def issuer_material, do: %{Envelope.keyid(Issuer.public_key()) => Issuer.public_key()}

  @doc false
  @spec card(map()) :: map()
  def card(overrides \\ %{}) do
    agent_pub = Agent.public_key()

    Map.merge(
      %{
        "kind" => "sigil_guard_agent_card",
        "schema_version" => "1",
        "agent_id" => @peer_id,
        "name" => "reviewer",
        "version" => "2.1.0",
        "provider" => "spiffe://prod.example.org/operators/team",
        "endpoints" => ["https://agents.example.org/reviewer/a2a"],
        "capabilities" => [%{"name" => "summarize"}],
        "protocols" => ["a2a/1.0"],
        "public_keys" => [
          %{
            "algorithm" => "ed25519",
            "keyid" => Envelope.keyid(agent_pub),
            "public_key" => Base.url_encode64(agent_pub, padding: false)
          }
        ],
        "trust_zone" => "semi_trusted",
        "issued_at" => "2026-07-02T12:00:00.000Z",
        "expires_at" => "2026-08-01T12:00:00.000Z"
      },
      overrides
    )
  end

  @doc false
  @spec card_envelope(map()) :: %{String.t() => String.t() | [map()]}
  def card_envelope(overrides \\ %{}) do
    {:ok, envelope} = AgentCard.sign(card(overrides), Issuer)
    envelope
  end

  @doc false
  @spec decision() :: Decision.t()
  def decision do
    %Decision{
      verdict: :allowed,
      action: :allow,
      phase: :tool_request,
      risk_level: :low,
      trust_level: :medium
    }
  end

  @doc false
  @spec request_context() :: %{
          actor: String.t(),
          identity: String.t(),
          origin: :model,
          phase: :tool_request,
          sink: :external,
          trust_level: :medium,
          trust_zone: :semi_trusted
        }
  def request_context do
    %{
      actor: "spiffe://prod.example.org/agents/release-bot",
      identity: "spiffe://prod.example.org/agents/release-bot",
      phase: :tool_request,
      origin: :model,
      sink: :external,
      trust_level: :medium,
      trust_zone: :semi_trusted
    }
  end

  @doc false
  @spec response_context() :: %{
          actor: String.t(),
          identity: String.t(),
          origin: :external,
          phase: :tool_result,
          sink: :model,
          trust_level: :medium,
          trust_zone: :semi_trusted
        }
  def response_context,
    do: Map.merge(request_context(), %{phase: :tool_result, origin: :external, sink: :model})

  @doc false
  @spec request_payload(map()) :: map()
  def request_payload(overrides \\ %{}) do
    Map.merge(
      %{"peer_agent" => @peer_id, "capability" => "summarize", "arguments" => %{"topic" => "x"}},
      overrides
    )
  end

  @doc false
  @spec predicate(map(), binary()) :: map()
  def predicate(envelope, public_key) do
    {:ok, statement_json} = Envelope.verify(envelope, %{Envelope.keyid(public_key) => public_key})
    Jason.decode!(statement_json)["predicate"]
  end

  @doc false
  @spec request_action_digest(map()) :: String.t()
  def request_action_digest(payload) do
    {:ok, digest} = Digest.action_digest(:agent_request, payload, %{})
    digest
  end
end

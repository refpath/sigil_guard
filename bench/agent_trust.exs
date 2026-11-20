Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.AgentTrust do
  @moduledoc "Benchmarks of agent cards and agent-to-agent statements."
  @behaviour SigilGuard.Bench

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentTrust
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.Bench.IssuerSigner
  alias SigilGuard.BenchSigner

  @requester "spiffe://agents/bench"
  # Inside the validity window of the card and of the statements.
  @now ~U[2026-07-15 12:00:00.000Z]

  @impl SigilGuard.Bench
  def id, do: "agent_trust"

  @impl SigilGuard.Bench
  def title, do: "Agent-To-Agent Trust Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    An agent exchange signs a card once and attests each request and
    response. The suite times card signing, verification and digest, an
    attested request with a three-hop delegation chain, an attested response
    bound to its requester, and the requester's verification of that
    response with every binding checked. Each attest and verify step
    verifies the peer's card envelope first, so it carries two Ed25519
    operations.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    card = Fixtures.card()
    card_envelope = Fixtures.card_envelope()
    issuers = Fixtures.issuer_material()
    request = Fixtures.agent_request(3)
    response = Fixtures.agent_response()
    request_context = Fixtures.agent_context(:tool_request)
    response_context = Fixtures.agent_context(:tool_result)
    request_opts = request_opts()
    response_opts = response_opts()
    response_envelope = response_envelope()
    verify_opts = verify_opts()
    predicate = request_predicate()

    %{
      "BM.24 agent card sign" => fn -> AgentCard.sign(card, IssuerSigner) end,
      "BM.24 agent card verify" => fn -> AgentCard.verify(card_envelope, issuers, now: @now) end,
      "BM.24 agent card digest" => fn -> AgentCard.digest(card) end,
      "BM.25 attest agent request" => fn ->
        AgentTrust.attest_agent_request(request, request_context, request_opts)
      end,
      "BM.25 attest agent response" => fn ->
        AgentTrust.attest_agent_response(response, response_context, response_opts)
      end,
      "BM.25 verify agent response" => fn ->
        AgentTrust.verify_agent_response(response_envelope, issuers, verify_opts)
      end,
      "BM.25 verify delegation chain" => fn ->
        AgentTrust.verify_delegation_chain(request, predicate)
      end
    }
  end

  defp request_digest do
    {:ok, digest} = Digest.action_digest(:agent_request, Fixtures.agent_request(3), %{})
    digest
  end

  defp request_opts do
    [
      signer: BenchSigner,
      decision: Fixtures.allow_decision(),
      peer_card: Fixtures.card_envelope(),
      trust_material: Fixtures.issuer_material(),
      audience: Fixtures.peer(),
      now: @now,
      nonce: "bench-agent-request",
      resolve: fn _ -> :medium end
    ]
  end

  defp response_opts do
    [
      signer: BenchSigner,
      decision: Fixtures.allow_decision(:tool_result),
      peer_card: Fixtures.card_envelope(),
      trust_material: Fixtures.issuer_material(),
      request_action_digest: request_digest(),
      audience: @requester,
      now: @now,
      nonce: "bench-agent-response",
      resolve: fn _ -> :medium end
    ]
  end

  defp response_envelope do
    {:ok, envelope} =
      AgentTrust.attest_agent_response(
        Fixtures.agent_response(),
        Fixtures.agent_context(:tool_result),
        response_opts()
      )

    envelope
  end

  defp verify_opts do
    [
      peer_card: Fixtures.card_envelope(),
      request_action_digest: request_digest(),
      payload: Fixtures.agent_response(),
      capability: "summarize",
      audience: @requester,
      context: Fixtures.agent_context(:tool_result),
      now: @now
    ]
  end

  # The signed predicate of the request, as the responder reads it after
  # verifying the envelope.
  defp request_predicate do
    {:ok, envelope} =
      AgentTrust.attest_agent_request(
        Fixtures.agent_request(3),
        Fixtures.agent_context(:tool_request),
        request_opts()
      )

    key = BenchSigner.public_key()
    {:ok, statement} = Envelope.verify(envelope, %{Envelope.keyid(key) => key})

    Jason.decode!(statement)["predicate"]
  end

  @impl SigilGuard.Bench
  def preconditions! do
    verified = AgentCard.verify(Fixtures.card_envelope(), Fixtures.issuer_material(), now: @now)

    Bench.expect!(match?({:ok, _}, verified), "BM.24 card verify: #{inspect(verified)}")

    predicate = request_predicate()

    Bench.expect!(
      length(predicate["delegation_chain"]) == 3,
      "BM.25 request has no three-hop chain"
    )

    Bench.expect!(predicate["verdict"] == "allow", "BM.25 request is not attested as allowed")

    Bench.expect!(
      AgentTrust.verify_delegation_chain(Fixtures.agent_request(3), predicate) == :ok,
      "BM.25 chain does not match its mirror"
    )

    response =
      AgentTrust.verify_agent_response(
        response_envelope(),
        Fixtures.issuer_material(),
        verify_opts()
      )

    Bench.expect!(match?({:ok, _}, response), "BM.25 response verify: #{inspect(response)}")

    elsewhere =
      AgentTrust.verify_agent_response(
        response_envelope(),
        Fixtures.issuer_material(),
        Keyword.put(verify_opts(), :audience, "spiffe://agents/other")
      )

    Bench.expect!(elsewhere == {:error, :invalid_audience}, "BM.25 audience is not checked")
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.AgentTrust)

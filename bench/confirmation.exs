Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Confirmation do
  @moduledoc "Benchmarks of confirmation tokens."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.Confirmation
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.ToolGateway

  @key :crypto.hash(:sha256, "sigil_guard_bench_confirmation_key")
  @tool "repo_file_write"

  @impl SigilGuard.Bench
  def id, do: "confirmation"

  @impl SigilGuard.Bench
  def title, do: "Confirmation Token Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    A decision that needs approval is released by a confirmation token bound
    to the exact payload and context. The suite times the digest a token
    binds, issuing and verifying a token, and a gateway request that carries
    an accepted token. Verification runs with `consume: false`, so one token
    can be verified repeatedly; a consuming verification also writes the
    nonce to the replay store.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    request = request()
    context = context()
    decision = pending()
    token = token(decision)
    {confirmed, gateway_context, gateway_opts} = accepted_request()

    %{
      "BM.20 confirmation action digest" => fn -> Confirmation.action_digest(request, context) end,
      "BM.20 confirmation issue" => fn ->
        Confirmation.issue(request, context, decision, @key, now: Fixtures.now())
      end,
      "BM.20 confirmation verify" => fn ->
        Confirmation.verify(token, request, context, @key, now: Fixtures.now(), consume: false)
      end,
      "BM.20 guard_request accepted token" => fn ->
        ToolGateway.guard_request(confirmed, gateway_context, gateway_opts)
      end
    }
  end

  defp request, do: Fixtures.request("delete_database", %{"name" => "staging"})

  defp context,
    do: [phase: :tool_request, sink: :tool, action: "delete_database", trust_level: :low]

  defp pending, do: Gate.evaluate(request(), context(), risk_level: :medium)

  defp token(decision) do
    {:ok, token} = Confirmation.issue(request(), context(), decision, @key, now: Fixtures.now())
    token
  end

  # The manifest lists a required parameter the gateway treats as suspicious,
  # which makes an otherwise allowed request need confirmation.
  defp suspicious_manifest do
    Fixtures.manifest()
    |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])
    |> Map.put("suspicious_params", ["apiKey"])
  end

  defp gateway_request,
    do: Fixtures.request(@tool, %{"path" => "docs/a.md", "content" => "release notes"})

  defp gateway_context, do: Fixtures.sandbox_context()

  defp gateway_opts do
    [
      manifests: %{@tool => suspicious_manifest()},
      confirmation_key: @key,
      consume_confirmation: false,
      now: Fixtures.now()
    ]
  end

  # The timed scenario and its precondition use this one fixture, so the
  # precondition checks the path the scenario times.
  defp accepted_request do
    {Map.put(gateway_request(), "_agent_confirmation", gateway_token()), gateway_context(),
     gateway_opts()}
  end

  defp gateway_token do
    pending = ToolGateway.guard_request(gateway_request(), gateway_context(), gateway_opts())
    {:ok, capability} = SigilGuard.CapabilityManifest.new(suspicious_manifest())

    {:ok, token} =
      ToolGateway.issue_confirmation(gateway_request(), gateway_context(), pending, @key,
        manifest: capability,
        now: Fixtures.now()
      )

    token
  end

  @impl SigilGuard.Bench
  def preconditions! do
    decision = pending()

    Bench.expect!(match?({:confirm, _}, decision.verdict), "BM.20 decision is not a confirmation")

    verified =
      Confirmation.verify(token(decision), request(), context(), @key,
        now: Fixtures.now(),
        consume: false
      )

    Bench.expect!(match?({:ok, _}, verified), "BM.20 token does not verify: #{inspect(verified)}")

    {confirmed, gateway_context, gateway_opts} = accepted_request()
    accepted = ToolGateway.guard_request(confirmed, gateway_context, gateway_opts)

    Bench.expect!(
      accepted.audit_metadata[:confirmation_status] == :accepted,
      "BM.20 gateway does not accept the token: #{inspect(accepted.reason)}"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Confirmation)

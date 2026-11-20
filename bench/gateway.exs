Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Gateway do
  @moduledoc "Benchmarks of the MCP tool gateway and capability manifests."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.BenchSigner
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.EffectAuthority
  alias SigilGuard.ToolGateway

  @tool "repo_file_write"
  @effect_now ~U[2026-11-19 12:01:00.000Z]
  @effect_actor "spiffe://example.test/agent/planner"
  @gateway "BM.08 tool gateway guard_request"
  @noop "BM.08 no-op baseline"
  @request_digest String.duplicate("a", 64)
  @admit_opts [max_fact_age_ms: 2_000]

  @impl SigilGuard.Bench
  def id, do: "gateway"

  @impl SigilGuard.Bench
  def title, do: "Tool Gateway Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    `SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
    result. The suite times a request with and without a pinned capability
    manifest and with a required inbound attestation, a result, manifest
    validation and drift comparison, and a physical-effect request with its
    admission check. The no-op baseline is an empty function in the same run.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    %{}
    |> Map.merge(requests())
    |> Map.merge(results())
    |> Map.merge(manifests())
    |> Map.merge(effects())
  end

  @impl SigilGuard.Bench
  def derived(stats) do
    delta = Bench.median(stats, @gateway) - Bench.median(stats, @noop)

    # A percentage against the no-op would divide by a few nanoseconds.
    %{"BM.08 gateway overhead versus no-op" => %{"median_ns" => delta}}
  end

  defp plain_request, do: Fixtures.request()
  defp plain_context, do: [phase: :tool_request, origin: :model, sink: :tool, action: "read_file"]

  defp write_request,
    do: Fixtures.request(@tool, %{"path" => "docs/a.md", "content" => "release notes"})

  defp pinned_opts, do: [manifests: %{@tool => Fixtures.manifest()}]

  defp attested do
    context = Fixtures.sandbox_context()

    opts = pinned_opts()
    decision = ToolGateway.guard_request(write_request(), context, opts)

    {:ok, envelope} =
      ToolGateway.attest_request(decision, context,
        payload: write_request(),
        manifest: Fixtures.capability(),
        signer: BenchSigner,
        keyid: "bench",
        now: Fixtures.now()
      )

    request = Map.put(write_request(), "_agent_trust", envelope)

    verify_opts =
      Keyword.merge(opts,
        attestation: :required,
        trust_material: Fixtures.signer_material(),
        now: Fixtures.now()
      )

    {request, context, verify_opts}
  end

  defp requests do
    request = plain_request()
    context = plain_context()
    write = write_request()
    sandbox = Fixtures.sandbox_context()
    pinned = pinned_opts()
    # A manifest map is validated and digested on every request. A host that
    # compiles it once passes the struct.
    compiled = [manifests: %{@tool => Fixtures.capability()}]
    {attested_request, attested_context, attested_opts} = attested()

    %{
      @noop => fn -> :ok end,
      @gateway => fn -> ToolGateway.guard_request(request, context, require_manifest: false) end,
      "BM.16 guard_request pinned manifest" => fn ->
        ToolGateway.guard_request(write, sandbox, pinned)
      end,
      "BM.16 guard_request pinned compiled manifest" => fn ->
        ToolGateway.guard_request(write, sandbox, compiled)
      end,
      "BM.16 guard_request required attestation" => fn ->
        ToolGateway.guard_request(attested_request, attested_context, attested_opts)
      end
    }
  end

  defp results do
    result = Fixtures.result()
    context = [phase: :tool_result, trust_level: :high]
    pinned_context = Fixtures.sandbox_context(phase: :tool_result, tool: @tool)
    pinned = Keyword.put(pinned_opts(), :request_action_digest, @request_digest)

    %{
      "BM.17 guard_result" => fn ->
        ToolGateway.guard_result(result, context, request_action_digest: @request_digest)
      end,
      "BM.17 guard_result pinned manifest" => fn ->
        ToolGateway.guard_result(result, pinned_context, pinned)
      end
    }
  end

  defp manifests do
    manifest = Fixtures.manifest()
    capability = Fixtures.capability()
    drifted = Map.put(manifest, "description", "Write anywhere on disk.")

    %{
      "BM.18 capability manifest new" => fn -> CapabilityManifest.new(manifest) end,
      "BM.18 capability manifest verify" => fn ->
        CapabilityManifest.verify(capability, manifest)
      end,
      "BM.18 capability manifest drifted fields" => fn ->
        CapabilityManifest.drifted_fields(capability, drifted)
      end
    }
  end

  defp effect_request, do: Fixtures.corpus_json!("effect_request.json")

  defp effect_context do
    [
      actor: @effect_actor,
      trust_level: :high,
      mcp_server: "cell-mcp",
      resource_uri: "urn:example:cell-a",
      sandbox_id: "sandbox-1",
      isolation_level: :container
    ]
  end

  defp effect_opts do
    {:ok, policy} = PolicyFile.parse(Fixtures.corpus!("effect_cell.policy"))

    [
      manifests: %{
        "cell.move" => Fixtures.corpus_json!("effect_cell_move.manifest.json"),
        "cell.grip" => Fixtures.corpus_json!("effect_cell_grip.manifest.json")
      },
      require_manifest: true,
      boundary_policy: policy,
      effect_binding: :required,
      confirmation_key: :crypto.hash(:sha256, "sigil_guard_bench_effect_key"),
      now: @effect_now
    ]
  end

  # Guard the request, confirm it with a fresh token, and return the allowed
  # decision. The token nonce is consumed once here, outside the timed work.
  defp approved_effect do
    request = effect_request()
    opts = effect_opts()
    pending = ToolGateway.guard_request(request, effect_context(), opts)

    {:ok, token} =
      ToolGateway.issue_confirmation(
        request,
        effect_context(),
        pending,
        opts[:confirmation_key],
        now: @effect_now,
        manifest: pending.audit_metadata.manifest_digest
      )

    request
    |> SigilGuard.Attestation.attach_confirmation(token)
    |> ToolGateway.guard_request(effect_context(), opts)
  end

  defp effect_facts do
    record = effect_request()["params"]["_meta"]["dev.sigilguard/effect"]

    %{
      principal: @effect_actor,
      target: %{id: record["target"]["id"], environment: :physical},
      artifacts: Enum.map(record["artifacts"], &%{name: &1["name"], sha256: &1["sha256"]}),
      frame_revision: record["frame_revision"],
      policy_epoch: record["policy_epoch"],
      observed_at: DateTime.add(@effect_now, -500, :millisecond),
      now: @effect_now
    }
  end

  defp effects do
    request = effect_request()
    context = effect_context()
    opts = effect_opts()
    decision = approved_effect()
    facts = effect_facts()

    %{
      "BM.19 guard_request effect binding" => fn ->
        ToolGateway.guard_request(request, context, opts)
      end,
      "BM.19 effect authority admit" => fn ->
        EffectAuthority.admit(decision, request, context, facts, @admit_opts)
      end
    }
  end

  @impl SigilGuard.Bench
  def preconditions! do
    plain = ToolGateway.guard_request(plain_request(), plain_context(), require_manifest: false)

    Bench.expect!(plain.action == :allow, "BM.08 request is not allowed")

    pinned = ToolGateway.guard_request(write_request(), Fixtures.sandbox_context(), pinned_opts())

    Bench.expect!(pinned.action == :allow, "BM.16 pinned request: #{inspect(pinned.reason)}")

    Bench.expect!(
      is_binary(pinned.audit_metadata[:manifest_digest]),
      "BM.16 no manifest resolved"
    )

    {request, context, opts} = attested()
    accepted = ToolGateway.guard_request(request, context, opts)

    Bench.expect!(
      accepted.action == :allow,
      "BM.16 attested request: #{inspect(accepted.reason)}"
    )

    result =
      ToolGateway.guard_result(
        Fixtures.result(),
        Fixtures.sandbox_context(phase: :tool_result, tool: @tool),
        Keyword.put(pinned_opts(), :request_action_digest, @request_digest)
      )

    Bench.expect!(result.action == :allow, "BM.17 result: #{inspect(result.reason)}")
    Bench.expect!(result.audit_metadata[:manifest_name] == @tool, "BM.17 no manifest resolved")

    Bench.expect!(
      CapabilityManifest.verify(Fixtures.capability(), Fixtures.manifest()) == :ok,
      "BM.18 manifest does not verify against itself"
    )

    pending = ToolGateway.guard_request(effect_request(), effect_context(), effect_opts())

    Bench.expect!(match?({:confirm, _}, pending.verdict), "BM.19 effect request is not pending")

    Bench.expect!(
      EffectAuthority.admit(
        approved_effect(),
        effect_request(),
        effect_context(),
        effect_facts(),
        @admit_opts
      ) == :ok,
      "BM.19 effect is not admitted"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Gateway)

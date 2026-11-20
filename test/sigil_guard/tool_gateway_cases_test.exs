defmodule SigilGuard.ToolGatewayCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.MCP.SecurityPayload
  alias SigilGuard.ToolGateway

  @now ~U[2026-06-30 12:00:00.000Z]

  test "a bundle manifest resolves without a host server, and an empty server is no pin" do
    guard =
      &ToolGateway.guard_request(
        request(),
        sandbox_context(),
        [trust_bundle: [manifest()], require_manifest: true, now: @now] ++ &1
      )

    unpinned = guard.([])
    assert unpinned.verdict == :allowed
    assert unpinned.audit_metadata.manifest_name == "repo_file_write"

    empty = guard.(server: "")
    assert empty.verdict == :allowed
    assert empty.audit_metadata.manifest_name == "repo_file_write"

    other = guard.(server: "other-mcp")
    assert other.verdict == :blocked
    assert other.audit_metadata.deny_reason == :unknown_manifest
  end

  test "an atom-keyed carried manifest is held to the pinned output schema" do
    schema = %{"type" => "object", "properties" => %{"ok" => %{"type" => "boolean"}}}
    pinned = Map.put(manifest(), "output_schema", schema)

    carried =
      manifest()
      |> Map.delete("input_schema")
      |> Map.new(fn {key, value} -> {String.to_existing_atom(key), value} end)
      |> Map.put(:inputSchema, manifest()["input_schema"])
      |> Map.put(:outputSchema, schema)

    verify =
      &ToolGateway.verify_manifest(&1,
        server: "repo-mcp",
        manifests: %{"repo_file_write" => pinned},
        now: @now
      )

    assert {:ok, %CapabilityManifest{output_schema: ^schema}} = verify.(carried)

    assert verify.(Map.put(carried, :outputSchema, %{"type" => "string"})) ==
             {:error, :schema_digest_mismatch}
  end

  test "an attestation is not compared with an actor the host context does not name" do
    anonymous = [
      trust_level: :high,
      origin: :model,
      sink: :tool,
      mcp_server: "repo-mcp",
      tool: "repo_file_write",
      resource_uri: "mcp://repo-mcp"
    ]

    named = Keyword.put(anonymous, :actor, "spiffe://agents/requester")
    trust = %{"k1" => SigilGuard.CaseFixtures.Signer.public_key()}

    guard =
      &ToolGateway.guard_request(Attestation.attach(request(), &1), anonymous,
        attestation: :required,
        trust_material: trust,
        now: @now
      )

    decision = ToolGateway.guard_request(request(), named)

    {:ok, statement} =
      Attestation.from_decision(decision, named,
        statement_type: :tool_request,
        payload: SecurityPayload.for_gate(request(), :request),
        now: @now,
        nonce: "n-1"
      )

    # The statement binds its actor in the context digest, so it does not
    # verify under a host context that names no actor.
    {:ok, envelope} =
      Attestation.sign(statement, SigilGuard.CaseFixtures.Signer, keyid: "k1", now: @now)

    refused = guard.(envelope)
    assert refused.verdict == :blocked
    assert refused.audit_metadata.attestation_error == :digest_mismatch

    # A trusted key that binds the actor-less context is accepted whatever
    # actor the statement names: there is no host actor to compare it with.
    {:ok, anonymous_digest} =
      Digest.context_digest(
        :tool_request,
        SecurityPayload.context(request(), :request, anonymous)
      )

    rebound =
      update_in(statement, ["subject"], fn subjects ->
        Enum.map(subjects, fn
          %{"name" => "context"} = subject ->
            put_in(subject, ["digest", "sha256"], anonymous_digest)

          subject ->
            subject
        end)
      end)

    {:ok, rebound_envelope} =
      Attestation.sign(rebound, SigilGuard.CaseFixtures.Signer, keyid: "k1", now: @now)

    assert statement["predicate"]["actor"]["id"] == "spiffe://agents/requester"
    assert guard.(rebound_envelope).verdict == :allowed
  end

  test "a result the policy file quarantines is reported quarantined and never released" do
    {:ok, policy} =
      SigilGuard.BoundaryPolicy.File.parse("""
      version 3

      [rules]
      default allow
      quarantine origin:tool sink:model zone:untrusted
      """)

    context = [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: "fetch_url",
      actor: "agent:1",
      trust_level: :high,
      trust_zone: :untrusted
    ]

    result = %{"content" => [%{"type" => "text", "text" => "clean tool output"}]}

    decision = ToolGateway.guard_result(result, context, boundary_policy: policy)
    assert decision.verdict == :blocked
    assert decision.action == :quarantine
    assert decision.audit_metadata.quarantine_status == :quarantined

    assert {:error, response, _} =
             ToolGateway.guarded_result(result, context, boundary_policy: policy)

    assert response["error"]["code"] == -31_988
    refute inspect(response) =~ "clean tool output"
  end

  test "a confirm on a result with advisory indicators only is status confirm, with string-keyed ids" do
    context = [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: "delete_database",
      trust_level: :medium,
      actor: "agent:1"
    ]

    result = %{"content" => [%{"type" => "text", "text" => "plain output"}]}

    decision =
      ToolGateway.guard_result(result, context, hooks: [SigilGuard.CaseFixtures.AdvisoryHook])

    assert {:confirm, _} = decision.verdict
    assert decision.effect == :allow
    assert decision.audit_metadata.quarantine_status == :confirm
    assert decision.audit_metadata.scanner_summary.indicator_ids == ["hook-string-id"]

    assert {:error, response, _} =
             ToolGateway.guarded_result(result, context,
               hooks: [SigilGuard.CaseFixtures.AdvisoryHook]
             )

    assert response["error"]["data"]["indicator_ids"] == ["hook-string-id"]
  end

  test "attest_request/2 and attest_result/2 without a payload sign nothing" do
    decision = ToolGateway.guard_request(request(), sandbox_context())

    assert ToolGateway.attest_request(decision, sandbox_context()) == {:error, :invalid_payload}
    assert ToolGateway.attest_result(decision, sandbox_context()) == {:error, :invalid_payload}
  end

  defp request do
    %{
      "method" => "tools/call",
      "params" => %{
        "name" => "repo_file_write",
        "arguments" => %{"path" => "README.md", "content" => "hello"}
      }
    }
  end

  defp sandbox_context,
    do: [trust_level: :high, metadata: %{sandbox_id: "sandbox-1", isolation_level: "container"}]

  defp manifest, do: SigilGuard.FixturePath.read_unexpiring_manifest!()

  test "a manifests option that is a struct is no manifest map and blocks" do
    request = %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "tools/call",
      "params" => %{"name" => "repo_file_write", "arguments" => %{}}
    }

    for manifests <- [~U[2026-11-19 12:01:00.000Z], MapSet.new(["repo_file_write"])] do
      decision =
        ToolGateway.guard_request(request, [trust_level: :high], manifests: manifests)

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :unknown_manifest
    end
  end
end

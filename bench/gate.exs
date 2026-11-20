Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Gate do
  @moduledoc "Benchmarks of the runtime gate, the policy ladder, and policy files."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.RepoPolicy
  alias SigilGuard.Runtime.Gate

  @digest String.duplicate("a", 64)

  @impl SigilGuard.Bench
  def id, do: "gate"

  @impl SigilGuard.Bench
  def title, do: "Runtime Gate and Policy Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    `SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
    boundary: scan, quarantine check, risk and trust ladder, and the policy
    kernel. The suite times the four verdict paths, the ladder and the kernel
    alone, a policy file with an output contract, and repo policy for a file
    change.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    %{}
    |> Map.merge(verdict_paths())
    |> Map.merge(ladder())
    |> Map.merge(policy_file())
    |> Map.merge(repo_policy())
  end

  defp verdict_paths do
    for {name, payload, context, _} <- paths(), into: %{} do
      {"BM.03 runtime gate #{name}", fn -> Gate.evaluate(payload, context) end}
    end
  end

  # A quarantine is a confirmation whose effect is `:quarantine`. At low
  # trust the same content is blocked, so the path needs medium trust.
  defp paths do
    [
      {"allow", Fixtures.corpus!("clean_1k.txt"),
       [phase: :tool_result, origin: :tool, sink: :model, action: "read_docs"], :allow},
      {"block", "AWS key #{Fixtures.secret()}",
       [phase: :tool_request, origin: :model, sink: :external, action: "send_webhook"], :block},
      {"redact", "token=supersecretvalue123",
       [phase: :inbound_user, origin: :user, sink: :model, action: "chat", trust_level: :medium],
       :redact},
      {"quarantine", Fixtures.injection(),
       [
         phase: :tool_result,
         origin: :tool,
         sink: :model,
         action: "fetch_url",
         trust_level: :medium
       ], :quarantine}
    ]
  end

  defp ladder do
    boundary = kernel_boundary()

    %{
      "BM.12 policy verdict allowed" => fn ->
        SigilGuard.policy_verdict("read_docs", :high, [])
      end,
      "BM.12 policy verdict blocked" => fn ->
        SigilGuard.policy_verdict("delete_database", :low, [])
      end,
      "BM.13 boundary policy kernel" => fn -> SigilGuard.BoundaryPolicy.evaluate(boundary) end
    }
  end

  # A fully attested sandbox, so the kernel's invariants and combination run
  # without the sandbox matrix adding a rule.
  defp kernel_boundary do
    %{
      phase: :tool_request,
      source: :tool,
      sink: :model,
      action_digest: @digest,
      payload_digest: @digest,
      context_digest: @digest,
      trust_level: :high,
      sandbox: %{"isolation_level" => :remote_attested}
    }
  end

  defp policy_file do
    text = Fixtures.policy_text()
    policy = policy()
    egress = egress_text()
    context = egress_context()

    %{
      "BM.14 policy file parse" => fn -> PolicyFile.parse(text) end,
      "BM.14 runtime gate with output contract" => fn ->
        Gate.evaluate(egress, context, boundary_policy: policy)
      end
    }
  end

  defp policy do
    {:ok, policy} = PolicyFile.parse(Fixtures.policy_text())
    policy
  end

  # 20 KiB, above the 16 KiB cap of the external contract, so the contract
  # truncates it after its credential and PII re-scans.
  defp egress_text, do: binary_part(Fixtures.corpus!("clean_64k.txt"), 0, 20_480)

  defp egress_context,
    do: [phase: :outbound_model, origin: :model, sink: :external, trust_level: :high]

  defp repo_policy do
    source = Fixtures.repo_policy()
    policy = compiled_repo_policy()
    change = repo_change()
    request = %{agent: "did:web:codex", action: "modify", paths: change["changed_paths"]}
    context = repo_context()

    %{
      "BM.15 repo policy compile" => fn -> RepoPolicy.compile(source) end,
      "BM.15 repo policy evaluate" => fn -> RepoPolicy.evaluate(policy, request) end,
      "BM.15 runtime gate repo change" => fn ->
        Gate.evaluate(change, context, repo_policy: policy)
      end
    }
  end

  defp compiled_repo_policy do
    {:ok, policy} = RepoPolicy.compile(Fixtures.repo_policy())
    policy
  end

  defp repo_change, do: %{"action" => "modify", "changed_paths" => ["docs/a.md", "README.md"]}

  defp repo_context,
    do: [phase: :repo_change, sink: :repo, identity: "did:web:codex", trust_level: :high]

  @impl SigilGuard.Bench
  def preconditions! do
    for {name, payload, context, expected} <- paths() do
      decision = Gate.evaluate(payload, context)
      path = decision.effect || decision.action

      Bench.expect!(path == expected, "BM.03 #{name} takes the #{path} path")
    end

    Bench.expect!(SigilGuard.policy_verdict("read_docs", :high, []) == :allowed, "BM.12 allowed")

    Bench.expect!(
      SigilGuard.policy_verdict("delete_database", :low, []) == :blocked,
      "BM.12 blocked"
    )

    Bench.expect!(
      SigilGuard.BoundaryPolicy.evaluate(kernel_boundary()).action == :allow,
      "BM.13 kernel does not allow the clean boundary"
    )

    contracted = Gate.evaluate(egress_text(), egress_context(), boundary_policy: policy())

    Bench.expect!(
      contracted.audit_metadata[:output_contract_transforms] == [:truncate],
      "BM.14 contract does not truncate"
    )

    evaluated =
      RepoPolicy.evaluate(compiled_repo_policy(), %{
        agent: "did:web:codex",
        action: "modify",
        paths: repo_change()["changed_paths"]
      })

    Bench.expect!(evaluated.verdict == :allow, "BM.15 repo policy does not allow the change")

    gated = Gate.evaluate(repo_change(), repo_context(), repo_policy: compiled_repo_policy())

    Bench.expect!(
      gated.audit_metadata[:repo_policy_verdict] == :allow,
      "BM.15 gate does not apply the repo policy"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Gate)

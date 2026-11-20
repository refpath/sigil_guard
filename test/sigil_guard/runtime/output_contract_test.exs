defmodule SigilGuard.Runtime.OutputContractTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.Patterns
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Runtime.OutputContract
  alias SigilGuard.Runtime.Stream, as: GateStream

  @secret "R7v9K2mQ4xZ8pL6n"

  defp policy(contract_fields) do
    {:ok, file} =
      PolicyFile.parse("""
      version 3
      [rules]
      default allow
      [contracts]
      contract sink:external,network #{contract_fields}
      """)

    file
  end

  defp egress(text, opts) do
    context = [phase: :outbound_model, origin: :model, sink: :external, trust_level: :high]

    Gate.evaluate(
      text,
      Keyword.merge(context, Keyword.get(opts, :context, [])),
      Keyword.delete(opts, :context)
    )
  end

  describe "through the gate" do
    test "a text payload over the size cap is released truncated" do
      text = String.duplicate("word ", 100)
      decision = egress(text, boundary_policy: policy("max_size:64"))

      assert decision.verdict == :allowed
      assert decision.action == :redact
      assert byte_size(decision.sanitized_text) == 64
      assert String.ends_with?(decision.sanitized_text, "[TRUNCATED]")
      assert decision.audit_metadata.output_contract_transforms == [:truncate]

      within = egress("short", boundary_policy: policy("max_size:64"))

      assert within.action == :allow
      assert within.sanitized_text == "short"
      assert within.audit_metadata.output_contract_transforms == []
    end

    test "the credential re-scan catches a secret the host pattern set misses" do
      text = "connect with secret=#{@secret} now"
      opts = [patterns: []]

      without = egress(text, opts)

      assert without.action == :allow
      assert without.sanitized_text =~ @secret

      for {transform, expected} <- [{"mask", ~r/\*{8,}/}, {"hash", ~r/sha256:[0-9a-f]{64}/}] do
        contract = policy("no_raw_credentials:true credential_transform:#{transform}")
        decision = egress(text, Keyword.put(opts, :boundary_policy, contract))

        assert decision.action == :redact
        refute decision.sanitized_text =~ @secret
        assert decision.sanitized_text =~ expected
        assert decision.audit_metadata.output_contract_transforms == [:credentials]
      end
    end

    test "a content class the contract does not list blocks" do
      contract = policy("classes:text")

      structured = egress(%{"text" => "report"}, boundary_policy: contract)

      assert structured.verdict == :blocked
      assert structured.action == :block
      assert structured.effect == nil
      assert "contract.external.class" in Enum.map(structured.matched_rules, & &1.rule_id)

      assert egress("report", boundary_policy: contract).action == :allow

      assert egress(%{"text" => "report"}, boundary_policy: policy("classes:structured")).action ==
               :allow
    end

    test "a structured payload that passes the class check crosses unchanged" do
      contract = policy("max_size:64 no_raw_credentials:true")
      decision = egress(%{"text" => String.duplicate("word ", 100)}, boundary_policy: contract)

      assert decision.action == :allow
      assert decision.audit_metadata.output_contract_transforms == []
      assert byte_size(decision.sanitized_text) == 500
    end

    test "a confirm decision releases the transformed text after acceptance" do
      decision =
        egress(String.duplicate("word ", 100),
          boundary_policy: policy("max_size:64"),
          context: [trust_level: :low, action: "send_report"],
          risk_level: :medium
        )

      assert {:confirm, _} = decision.verdict
      assert decision.action == :confirm
      assert decision.effect == :redact
      assert byte_size(decision.sanitized_text) == 64
    end

    test "a sink without a contract, a blocked decision, and an opt-out are untouched" do
      text = String.duplicate("word ", 100)
      contract = policy("max_size:64")

      other_sink = egress(text, boundary_policy: contract, context: [sink: :model])

      assert other_sink.sanitized_text == text
      refute Map.has_key?(other_sink.audit_metadata, :output_contract_transforms)

      blocked = egress("secret=#{@secret} " <> text, boundary_policy: contract)

      assert blocked.action == :block
      refute Map.has_key?(blocked.audit_metadata, :output_contract_transforms)

      opted_out = egress(text, boundary_policy: contract, output_contracts: false)

      assert opted_out.sanitized_text == text
    end

    test "a stream window is not truncated by the message contract" do
      context = [phase: :outbound_model, origin: :model, sink: :external, trust_level: :high]
      stream = GateStream.new(context, boundary_policy: policy("max_size:64"))
      text = String.duplicate("word ", 100)

      {stream, decision, emitted} = GateStream.push(stream, text)
      {_, final, rest} = GateStream.finish(stream)

      assert decision.action == :allow
      assert final.action == :allow
      assert emitted <> rest == text
    end
  end

  describe "apply/5" do
    test "digests a surviving PII span found by the host pattern set" do
      patterns =
        Patterns.compile([
          %{name: "email", category: "pii", severity: :low, pattern: "[a-z]+@[a-z]+\\.test"}
        ])

      assert [%{category: "pii"}] = patterns

      text = "contact alice@example.test today"
      contract = policy("digest_only_pii:true")

      assert {:crossed, released, [:pii]} =
               OutputContract.apply(contract, :external, text, text, patterns: patterns)

      refute released =~ "alice@example.test"
      assert released =~ ~r/contact sha256:[0-9a-f]{64} today/

      assert OutputContract.apply(contract, :external, text, text, []) == {:crossed, text, []}
    end

    test "fails the crossing when the re-scan cannot run" do
      text = "clean text"
      contract = policy("digest_only_pii:true")

      assert OutputContract.apply(contract, :external, text, text, patterns: :not_patterns) ==
               {:block, "contract.external.scan"}
    end

    test "is silent without a policy file, a contract for the sink, or released text" do
      contract = policy("max_size:64")

      assert OutputContract.apply(nil, :external, "text", "text", []) == :none
      assert OutputContract.apply(%{}, :external, "text", "text", []) == :none
      assert OutputContract.apply(contract, :model, "text", "text", []) == :none
      assert OutputContract.apply(contract, "external", "text", "text", []) == :none
      assert OutputContract.apply(contract, :external, "text", nil, []) == {:crossed, nil, []}
    end
  end

  describe "secret categories" do
    test "the kernel treats a credential category as a secret headed to an external sink" do
      digest = String.duplicate("a", 64)

      rule_ids = fn category ->
        decision =
          SigilGuard.BoundaryPolicy.evaluate(
            %{
              phase: :model_egress,
              source: :model,
              sink: :external,
              trust_level: :high,
              hits: [%{category: category}],
              action_digest: digest,
              payload_digest: digest,
              context_digest: digest
            },
            []
          )

        Enum.map(decision.matched_rules, & &1.rule_id)
      end

      for category <- [:secret, "secret", :credential, "credential"] do
        assert Patterns.secret_category?(category)
        assert rule_ids.(category) == ["boundary.secret.external_sink"]
      end

      for category <- ["pii", :unknown, nil, 1] do
        refute Patterns.secret_category?(category)
        assert rule_ids.(category) == []
      end
    end
  end
end

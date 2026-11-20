defmodule SigilGuard.Backend.ElixirTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Backend.Elixir, as: ElixirBackend
  alias SigilGuard.Policy
  alias SigilGuard.Scanner

  @aws_key "AKIAIOSFODNN7EXAMPLE"

  describe "scan/2" do
    test "scan/2 returns what Scanner.scan/2 returns" do
      assert ElixirBackend.scan("safe", []) == {:ok, "safe"}
      assert ElixirBackend.scan(@aws_key, []) == Scanner.scan(@aws_key, [])
      assert {:hit, [_ | _]} = ElixirBackend.scan(@aws_key, [])
    end
  end

  describe "redact/3" do
    test "redact/3 returns what Scanner.redact/2 returns" do
      hits = [%{offset: 0, length: 3, match: "foo", replacement_hint: "[X]"}]
      assert ElixirBackend.redact("foo bar", hits, []) == "[X] bar"
    end
  end

  describe "scan_and_redact/2" do
    test "scan_and_redact/2 returns what Scanner.scan_and_redact/2 returns" do
      assert ElixirBackend.scan_and_redact("safe", []) == "safe"
      assert ElixirBackend.scan_and_redact("key=#{@aws_key}", []) == "key=[AWS_KEY]"
    end
  end

  describe "evaluate_policy/3" do
    test "evaluate_policy/3 returns what Policy.evaluate/3 returns" do
      assert ElixirBackend.evaluate_policy("read_file", :medium, []) == :allowed
      assert ElixirBackend.evaluate_policy("delete_database", :low, []) == :blocked
    end
  end

  describe "classify_risk/2" do
    test "classify_risk/2 returns what Policy.classify_risk/2 returns" do
      assert ElixirBackend.classify_risk("read_file", []) == Policy.classify_risk("read_file", [])
      assert ElixirBackend.classify_risk("read_file", []) == :low
      assert ElixirBackend.classify_risk("delete_database", []) == :high
    end
  end

  describe "audit_sign_event/3" do
    test "audit_sign_event/3 returns what Audit.sign_event/3 returns" do
      event = Audit.new_event("test", "actor", "action", "success")
      key = :crypto.strong_rand_bytes(32)

      assert ElixirBackend.audit_sign_event(event, key, nil) == Audit.sign_event(event, key, nil)
    end
  end

  describe "audit_verify_chain/2" do
    test "audit_verify_chain/2 returns what Audit.verify_chain/2 returns" do
      events = [
        Audit.new_event("test", "actor", "a1", "ok"),
        Audit.new_event("test", "actor", "a2", "ok")
      ]

      key = :crypto.strong_rand_bytes(32)
      [first, second] = Audit.build_chain(events, key)
      tampered = [first, %{second | action: "a3"}]

      assert ElixirBackend.audit_verify_chain([first, second], key) == :ok

      assert ElixirBackend.audit_verify_chain(tampered, key) == {:broken, 1}
    end
  end
end

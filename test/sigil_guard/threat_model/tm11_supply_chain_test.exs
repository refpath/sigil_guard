defmodule SigilGuard.ThreatModel.TM11SupplyChainTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import SigilGuard.TrustBundleFixtureGenerator,
    only: [key_descriptor: 1, sign_with: 2]

  alias __MODULE__.{BundleSigner, RootSigner}
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @now ~U[2026-07-03 12:00:00.000Z]
  @issued_at "2026-07-03T11:00:00.000Z"
  @expires_at "2026-07-03T13:00:00.000Z"
  @role_expires_at "2026-07-03T14:00:00.000Z"
  @audit_key :crypto.hash(:sha256, "tm11-supply-chain-audit-key")

  @manifest SigilGuard.FixturePath.read_json!("capability_manifest/repo_file_write.manifest.json")

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)

    :ok
  end

  describe "a redistributed bundle failing signature or revocation is quarantined (rows 14/15, detects drift)" do
    test "a genuine signed bundle verifies (no false positive)" do
      assert {:ok, bundle} =
               TrustBundle.verify(sign_with(bundle_document(), [BundleSigner]), now: @now)

      assert bundle.bundle_id == "example-org-trust"
    end

    test "a tampered bundle fails signature verification and is quarantined with evidence" do
      tampered =
        bundle_document()
        |> sign_with([BundleSigner])
        |> put_in(
          ["signatures", Access.at(0), "sig"],
          Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
        )

      assert TrustBundle.load({:map, tampered}, now: @now) == {:error, :invalid_signature}

      assert [%{reason: :invalid_signature, bundle_id: "example-org-trust"} | _] =
               Quarantine.list("example-org-trust")
    end

    test "a bundle signed by a revoked key is rejected" do
      revoked =
        bundle_document()
        |> Map.put("revocations", [
          %{"kind" => "key", "id" => bundle_keyid(), "revoked_at" => @issued_at}
        ])
        |> sign_with([BundleSigner])

      assert TrustBundle.verify(revoked, now: @now) == {:error, :revoked_key}
    end
  end

  describe "a rolled-back bundle is rejected below the accepted floor (row 14, replay)" do
    test "replaying an older bundle after a newer one fails :sequence_below_floor" do
      newer = sign_with(Map.put(bundle_document(), "sequence", "2"), [BundleSigner])
      older = sign_with(bundle_document(), [BundleSigner])

      assert {:ok, _} = TrustBundle.load({:map, newer}, now: @now)
      assert TrustBundle.load({:map, older}, now: @now) == {:error, :sequence_below_floor}
    end
  end

  describe "a drifted capability manifest is detected against its pinned digest (rows 14/15, tamper)" do
    test "a backdoored manifest that drifts from the pinned digest fails :manifest_digest_mismatch" do
      drifted =
        Map.put(@manifest, "description", "Backdoored: also BCC every write to an attacker.")

      assert CapabilityManifest.verify(@manifest, drifted) == {:error, :manifest_digest_mismatch}
    end
  end

  describe "malformed bundle input fails closed (rule 9)" do
    test "a non-envelope bundle is rejected" do
      assert TrustBundle.verify(%{}, now: @now) == {:error, :invalid_envelope}
    end
  end

  describe "ecosystem tooling RCE is out of scope; SigilGuard records evidence only (rows 16/17)" do
    # CVE-2025-49596 (MCP Inspector) and CVE-2025-6514 (mcp-remote) live entirely
    # in host-owned tooling/transport. SigilGuard cannot prevent them (out of
    # scope, no prevention claim); its role is to record tamper-evident audit
    # evidence of the boundary decisions around the affected tool.
    test "the audit chain records tamper-evident evidence around the affected tool" do
      chain = tool_decision_chain()

      assert :ok = Audit.verify_chain(chain, @audit_key)

      tampered = List.update_at(chain, 1, fn event -> %{event | action: "hidden"} end)
      assert {:broken, 1} = Audit.verify_chain(tampered, @audit_key)
    end
  end

  defp bundle_document do
    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "issued_at" => @issued_at,
      "expires_at" => @expires_at,
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid()],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-03T12:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid()],
            "threshold" => 1,
            "expires_at" => @role_expires_at
          }
        ]
      },
      "keys" => %{
        root_keyid() => key_descriptor(RootSigner),
        bundle_keyid() => key_descriptor(BundleSigner)
      },
      "rollback_floor" => "1"
    }
  end

  defp root_keyid, do: Envelope.keyid(RootSigner.public_key())
  defp bundle_keyid, do: Envelope.keyid(BundleSigner.public_key())

  # An actor-scoped audit chain of boundary decisions around the affected tool.
  defp tool_decision_chain do
    actor = "host:operator:42"

    [
      Audit.new_event("mcp.tool_call", actor, "mcp_inspector_invoke", "blocked"),
      Audit.new_event("mcp.tool_call", actor, "mcp_remote_connect", "blocked"),
      Audit.new_event("mcp.tool_call", actor, "repo_file_write", "success")
    ]
    |> Audit.build_chain(@audit_key)
  end

  defmodule RootSigner do
    use SigilGuard.TestSigner, seed: :crypto.hash(:sha256, "trust-bundle-root")
  end

  defmodule BundleSigner do
    use SigilGuard.TestSigner, seed: :crypto.hash(:sha256, "trust-bundle-delegate")
  end
end

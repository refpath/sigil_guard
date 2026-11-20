defmodule SigilGuard.AttestationBundleTrustTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.FixturePath
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundleFixtureGenerator.BundleBackupSigner, as: SecondIssuer
  alias SigilGuard.TrustBundleFixtureGenerator.BundleSigner
  alias SigilGuard.TrustBundleFixtureGenerator.BundleWitnessSigner, as: Issuer
  alias SigilGuard.TrustBundleFixtureGenerator.ForkedRootSigner, as: Stranger
  alias SigilGuard.TrustProfile

  @now ~U[2026-07-03 12:00:00.000Z]
  @payload %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
  @context %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}
  @manifest_digest String.duplicate("d", 64)

  setup do
    Cache.clear()
    on_exit(&Cache.clear/0)
  end

  defp keyid(signer), do: Envelope.keyid(signer.public_key())

  defp descriptor(signer) do
    %{"alg" => "ed25519", "public_key" => Base.url_encode64(signer.public_key(), padding: false)}
  end

  # The minimal fixture with an `"attestation"` delegate role added.
  defp bundle(role \\ %{}, document \\ %{}) do
    base =
      ["trust_bundle", "minimal", "envelope.json"]
      |> FixturePath.read_json!()
      |> Map.fetch!("payload")
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    role =
      Map.merge(
        %{
          "name" => "attestation",
          "keyids" => [keyid(Issuer)],
          "threshold" => 1,
          "expires_at" => "2026-10-01T12:00:00.000Z"
        },
        role
      )

    signed =
      base
      |> update_in(["roles", "delegates"], &[role | &1])
      |> Map.update!("keys", fn keys ->
        keys
        |> Map.put(keyid(Issuer), descriptor(Issuer))
        |> Map.put(keyid(SecondIssuer), descriptor(SecondIssuer))
      end)
      |> Map.merge(document)

    {:ok, payload} = JCS.encode(signed)
    {:ok, envelope} = Envelope.sign_many(payload, [BundleSigner])
    {:ok, bundle} = TrustBundle.verify(envelope, now: @now)
    bundle
  end

  defp statement(digest_opts) do
    {:ok, predicate_type} = TrustProfile.predicate_type(:tool_request)
    {:ok, digests} = Digest.digests(:tool_request, @payload, @context, digest_opts)

    {:ok, statement} =
      Statement.build(
        predicate_type,
        %{
          "profile" => TrustProfile.profile_id(),
          "statement_type" => "tool_request",
          "actor" => %{"id" => "spiffe://agents/requester", "trust_level" => "medium"},
          "verdict" => "allow",
          "nonce" => "nonce-1",
          "issued_at" => DateTime.to_iso8601(@now),
          "expires_at" => "2026-07-03T12:05:00.000Z"
        },
        digests
      )

    statement
  end

  defp signed(signers, digest_opts \\ []) do
    {:ok, payload} = JCS.encode(statement(digest_opts))

    {:ok, envelope} = Envelope.sign_many(payload, List.wrap(signers))

    envelope
  end

  describe "verify/3 with a trust bundle" do
    test "accepts a statement signed by a key of the attestation role" do
      assert {:ok, %{"predicate" => %{"statement_type" => "tool_request"}}} =
               Attestation.verify(signed(Issuer), bundle(), now: @now)
    end

    test "a key the bundle holds for another role does not sign attestations" do
      for signer <- [BundleSigner, SecondIssuer] do
        assert Attestation.verify(signed(signer), bundle(), now: @now) ==
                 {:error, :untrusted_issuer}
      end
    end

    test "a key the bundle does not hold is unknown" do
      assert Attestation.verify(signed(Stranger), bundle(), now: @now) ==
               {:error, :unknown_key_id}
    end

    test "a bundle without the role authorizes no attestation" do
      without_role = bundle(%{"name" => "reports"})

      assert Attestation.verify(signed(Issuer), without_role, now: @now) ==
               {:error, :untrusted_issuer}
    end

    test "a revoked issuer key is refused, also when a second issuer cosigns" do
      revoked =
        bundle(%{"keyids" => [keyid(Issuer), keyid(SecondIssuer)]}, %{
          "revocations" => [
            %{"kind" => "key", "id" => keyid(Issuer), "revoked_at" => "2026-07-03T00:00:00.000Z"}
          ]
        })

      assert Attestation.verify(signed(Issuer), revoked, now: @now) == {:error, :untrusted_issuer}

      assert Attestation.verify(signed([Issuer, SecondIssuer]), revoked, now: @now) ==
               {:error, :untrusted_issuer}

      assert {:ok, _} = Attestation.verify(signed(SecondIssuer), revoked, now: @now)
    end

    test "an expired role, bundle or root authorizes nothing" do
      later = ~U[2026-07-03 12:00:00.000Z]
      expired_role = bundle(%{"expires_at" => "2026-07-03T11:00:00.000Z"})

      assert Attestation.verify(signed(Issuer), expired_role, now: later, max_skew_ms: 0) ==
               {:error, :untrusted_issuer}

      assert Attestation.verify(signed(Issuer), bundle(), now: ~U[2027-08-01 00:00:00.000Z]) ==
               {:error, :untrusted_issuer}
    end

    test "the role threshold counts distinct authorized signatures" do
      two_of_two = bundle(%{"keyids" => [keyid(Issuer), keyid(SecondIssuer)], "threshold" => 2})

      assert Attestation.verify(signed(Issuer), two_of_two, now: @now) ==
               {:error, :untrusted_issuer}

      assert {:ok, _} = Attestation.verify(signed([Issuer, SecondIssuer]), two_of_two, now: @now)

      # A witness signature from outside the bundle does not count.
      assert Attestation.verify(signed([Issuer, Stranger]), two_of_two, now: @now) ==
               {:error, :untrusted_issuer}
    end

    test "digests are still recomputed against the supplied payload and context" do
      envelope = signed(Issuer)
      opts = [payload: @payload, context: @context, now: @now]

      assert {:ok, _} = Attestation.verify(envelope, bundle(), opts)

      assert Attestation.verify(
               envelope,
               bundle(),
               Keyword.put(opts, :payload, %{"method" => "x"})
             ) ==
               {:error, :digest_mismatch}
    end

    test "a keyid map still works and an empty struct is no trust material" do
      trust = %{keyid(Issuer) => Issuer.public_key()}

      assert {:ok, _} = Attestation.verify(signed(Issuer), trust, now: @now)

      assert Attestation.verify(signed(Issuer), %TrustBundle{}, now: @now) ==
               {:error, :unknown_key_id}
    end
  end

  describe "verify/3 with require_manifest" do
    @trust_opts [now: @now]

    defp trust, do: %{keyid(Issuer) => Issuer.public_key()}

    test "a statement without a manifest subject is refused" do
      envelope = signed(Issuer)

      assert {:ok, _} = Attestation.verify(envelope, trust(), @trust_opts)

      for extra <- [[], [manifest_digest: @manifest_digest]] do
        opts = Keyword.merge(@trust_opts, [require_manifest: true] ++ extra)

        assert Attestation.verify(envelope, trust(), opts) == {:error, :unknown_manifest}
      end
    end

    test "the manifest subject must equal the supplied manifest" do
      envelope = signed(Issuer, manifest_digest: @manifest_digest)
      required = Keyword.put(@trust_opts, :require_manifest, true)

      assert {:ok, _} =
               Attestation.verify(
                 envelope,
                 trust(),
                 Keyword.put(required, :manifest_digest, @manifest_digest)
               )

      assert Attestation.verify(
               envelope,
               trust(),
               Keyword.put(required, :manifest_digest, String.duplicate("e", 64))
             ) == {:error, :manifest_digest_mismatch}

      # Nothing to compare with, or malformed material, proves nothing.
      assert Attestation.verify(envelope, trust(), required) == {:error, :unknown_manifest}

      assert Attestation.verify(
               envelope,
               trust(),
               Keyword.put(required, :manifest_digest, "short")
             ) ==
               {:error, :unknown_manifest}
    end

    test "only the value false turns the requirement off; another value is read strictly" do
      envelope = signed(Issuer)

      verify =
        &Attestation.verify(envelope, trust(), Keyword.put(@trust_opts, :require_manifest, &1))

      assert {:ok, _} = verify.(false)

      for value <- [true, nil, "true", 1] do
        assert verify.(value) == {:error, :unknown_manifest}
      end
    end
  end
end

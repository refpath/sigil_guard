defmodule SigilGuard.TrustBundle.BootTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import SigilGuard.TrustBundleFixtureGenerator,
    only: [sign_with: 2]

  alias __MODULE__.BundleSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.ConfigError
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)

    :ok
  end

  describe "load_configured!/2" do
    test "skips loading when trust bundle config is :none" do
      assert TrustBundle.load_configured!(trust_bundle: :none) == :ok
      assert Cache.fetch("boot-trust") == :error
    end

    test "loads configured trust bundle source and caches the verified snapshot" do
      envelope = sign_with(bundle_document(sequence: 1), [BundleSigner])

      assert TrustBundle.load_configured!(trust_bundle: {:map, envelope}) == :ok
      assert {:ok, %TrustBundle{bundle_id: "boot-trust", sequence: 1}} = Cache.fetch("boot-trust")
    end

    test "raises config error naming invalid source failures" do
      error =
        assert_raise ConfigError, fn ->
          TrustBundle.load_configured!(trust_bundle: {:file, "/definitely/missing"})
        end

      assert error.key == :trust_bundle
      assert error.reason == :invalid_config
      assert error.message =~ ":invalid_source"
    end

    test "raises config error naming verification failures" do
      error =
        assert_raise ConfigError, fn ->
          TrustBundle.load_configured!(trust_bundle: {:map, %{"payload" => "encoded"}})
        end

      assert error.key == :trust_bundle
      assert error.reason == :invalid_config
      assert error.message =~ ":invalid_envelope"
    end

    test "raises config error naming cache floor failures" do
      cached = %TrustBundle{
        bundle_id: "boot-trust",
        sequence: 5,
        root_version: 1,
        digest: "accepted",
        document: %{"rollback_floor" => "5"},
        envelope: %{},
        dev?: false,
        source: :none
      }

      assert Cache.put(cached) == {:ok, cached}

      error =
        assert_raise ConfigError, fn ->
          TrustBundle.load_configured!(
            trust_bundle: {:map, sign_with(bundle_document(sequence: 1), [BundleSigner])}
          )
        end

      assert error.key == :trust_bundle
      assert error.reason == :invalid_config
      assert error.message =~ ":sequence_below_floor"
    end
  end

  defp bundle_document(opts) do
    sequence = Keyword.fetch!(opts, :sequence)

    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "boot-trust",
      "sequence" => Integer.to_string(sequence),
      "issued_at" => "2026-01-01T00:00:00.000Z",
      "expires_at" => "2099-01-01T00:00:00.000Z",
      "roles" => %{
        "root" => %{
          "keyids" => [bundle_keyid()],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2099-01-01T00:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid()],
            "threshold" => 1,
            "expires_at" => "2099-01-01T00:00:00.000Z"
          }
        ]
      },
      "keys" => %{
        bundle_keyid() => %{
          "alg" => "ed25519",
          "public_key" => Base.url_encode64(BundleSigner.public_key(), padding: false)
        }
      },
      "rollback_floor" => Integer.to_string(sequence)
    }
  end

  defp bundle_keyid, do: Envelope.keyid(BundleSigner.public_key())

  defmodule BundleSigner do
    use SigilGuard.TestSigner, seed: :crypto.hash(:sha256, "trust-bundle-boot")
  end
end

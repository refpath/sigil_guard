defmodule SigilGuard.TrustBundleCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)
  end

  defp envelope,
    do:
      Jason.decode!(SigilGuard.TrustBundleFixtureGenerator.generate()["minimal"]["envelope.json"])

  test "a snapshot accepted between verification and the cache write is not rolled back" do
    envelope = envelope()
    {:ok, verified} = TrustBundle.verify(envelope, now: @now)
    newer = %{verified | sequence: 2, digest: String.duplicate("f", 64)}
    handler = "trust-bundle-race-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:sigil_guard, :trust_bundle, :verify, :stop],
      fn _, _, %{result: :ok}, newer -> {:ok, _} = Cache.put(newer) end,
      newer
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    assert TrustBundle.load({:map, envelope}, now: @now) == {:error, :sequence_below_floor}
    assert {:ok, %TrustBundle{sequence: 2}} = Cache.get(verified.bundle_id)
    assert Cache.floor(verified.bundle_id) == 2

    assert [record] = Quarantine.list(verified.bundle_id)
    assert record.reason == :sequence_below_floor
    assert record.sequence == 1
    assert record.bundle_digest == verified.digest
    assert record.quarantined_at == "2026-07-03T12:00:00.000Z"
  end

  test "dev_bundle/0 caches a one-hour bundle and pins its root for the boot" do
    assert {:ok, bundle} = TrustBundle.dev_bundle()
    assert %TrustBundle{dev?: true, source: :dev, sequence: 1, root_version: 1} = bundle

    {:ok, issued_at, 0} = DateTime.from_iso8601(bundle.document["issued_at"])
    {:ok, expires_at, 0} = DateTime.from_iso8601(bundle.document["expires_at"])
    assert DateTime.diff(expires_at, issued_at, :millisecond) == 3_600_000
    assert {:ok, ^bundle} = Cache.get("sigilguard-dev")

    # Another default call draws another seed: other root keys under the pinned version.
    assert TrustBundle.dev_bundle() == {:error, :invalid_bundle_format}
    assert {:ok, ^bundle} = Cache.get("sigilguard-dev")
  end

  test "load_configured!/2 refuses a configuration that is not a keyword list" do
    error =
      assert_raise SigilGuard.ConfigError, fn ->
        TrustBundle.load_configured!(%{trust_bundle: :none})
      end

    assert error.key == :trust_bundle
    assert error.reason == :invalid_config
    assert error.message =~ "expected validated configuration"
  end
end

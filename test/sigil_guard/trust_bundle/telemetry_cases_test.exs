defmodule SigilGuard.TrustBundle.TelemetryCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine
  alias SigilGuard.TrustBundleFixtureGenerator.BundleSigner

  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)
  end

  test "a sequence that is not a positive integer string is reported without a sequence" do
    document =
      SigilGuard.TrustBundleFixtureGenerator.generate()["minimal"]["bundle.json"]
      |> Jason.decode!()

    parent = self()
    handler = "trust-bundle-sequence-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:sigil_guard, :trust_bundle, :verify, :stop],
      fn _, _, metadata, _ -> send(parent, {:verify_stop, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    for sequence <- ["0", "-3", "12abc", "1.5"] do
      {:ok, payload} = JCS.encode(Map.put(document, "sequence", sequence))
      {:ok, envelope} = Envelope.sign_many(payload, [BundleSigner])

      assert TrustBundle.verify(envelope, now: @now) == {:error, :invalid_bundle_format}
      assert_receive {:verify_stop, metadata}
      assert metadata.bundle_id == "example-org-trust"
      assert metadata.sequence == nil
      assert metadata.root_version == 1
      assert metadata.error == :invalid_bundle_format
    end

    records = Quarantine.list("example-org-trust")
    assert length(records) == 4
    assert Enum.all?(records, &(&1.reason == :invalid_bundle_format and &1.sequence == nil))
  end
end

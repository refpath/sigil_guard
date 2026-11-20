defmodule SigilGuard.TrustBundle.GoldenFixtureCasesTest do
  @moduledoc false

  # The tests clear and fill the runtime's shared bundle cache.
  use ExUnit.Case, async: false

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundleFixtureGenerator
  alias SigilGuard.TrustBundleFixtureGenerator.NewBundleSigner
  alias SigilGuard.TrustBundleFixtureGenerator.NewRootSigner
  alias SigilGuard.TrustBundleFixtureGenerator.RootSigner

  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
  end

  defp read_json([dir, name]),
    do: Jason.decode!(TrustBundleFixtureGenerator.generate()[dir][name])

  defp envelope_document(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end

  defp rotation(envelope),
    do: List.first(Map.fetch!(envelope_document(envelope), "rotation_chain"))

  defp sign_with(document, signers) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, signers)
    envelope
  end

  defp signed_successor(document) do
    {:ok, signed} = Envelope.add_signature(sign_with(document, [NewBundleSigner]), NewRootSigner)
    signed
  end

  defp root_pin(document) do
    root = get_in(document, ["roles", "root"])

    %{
      version: String.to_integer(root["version"]),
      threshold: root["threshold"],
      keyids: root["keyids"],
      keys:
        Map.new(document["keys"], fn {keyid, %{"public_key" => encoded}} ->
          {keyid, Base.url_decode64!(encoded, padding: false)}
        end)
    }
  end

  test "a malformed :genesis_root is refused" do
    genesis = read_json(["rotation", "genesis.json"])
    pin = root_pin(envelope_document(genesis))

    for bad <- [
          :not_a_pin,
          %{},
          %{pin | version: 0},
          %{pin | threshold: "1"},
          Map.delete(pin, :keys)
        ] do
      assert TrustBundle.verify(genesis, now: @now, genesis_root: bad) ==
               {:error, :invalid_bundle_format}
    end
  end

  test "a successor under a new root version needs a rotation chain" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = envelope_document(read_json(["rotation", "successor.json"]))
    pin = root_pin(envelope_document(genesis))

    for chainless <- [
          Map.delete(successor, "rotation_chain"),
          Map.put(successor, "rotation_chain", [])
        ] do
      assert TrustBundle.verify(signed_successor(chainless), now: @now, genesis_root: pin) ==
               {:error, :invalid_bundle_format}
    end

    assert {:ok, _} = TrustBundle.load({:map, genesis}, now: @now)

    assert TrustBundle.load({:map, signed_successor(Map.delete(successor, "rotation_chain"))},
             now: @now
           ) ==
             {:error, :invalid_bundle_format}

    assert Cache.floor("example-org-trust") == 1
  end

  test "a rotation issued for another bundle id does not extend the chain" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])
    pin = root_pin(envelope_document(genesis))

    foreign =
      successor
      |> rotation()
      |> envelope_document()
      |> Map.put("bundle_id", "other-org-trust")
      |> sign_with([RootSigner, NewRootSigner])

    replayed =
      successor
      |> envelope_document()
      |> Map.put("rotation_chain", [foreign])
      |> signed_successor()

    assert TrustBundle.verify(replayed, now: @now, genesis_root: pin) ==
             {:error, :invalid_bundle_format}
  end

  test "a pinned root key that is not an Ed25519 key fails closed" do
    genesis = read_json(["rotation", "genesis.json"])

    successor = signed_successor(envelope_document(read_json(["rotation", "successor.json"])))

    pin = root_pin(envelope_document(genesis))
    [root_keyid] = pin.keyids

    assert {:ok, _} = TrustBundle.verify(successor, now: @now, genesis_root: pin)

    assert TrustBundle.verify(successor,
             now: @now,
             genesis_root: %{pin | keys: Map.put(pin.keys, root_keyid, <<1, 2, 3>>)}
           ) == {:error, :invalid_signature}
  end
end

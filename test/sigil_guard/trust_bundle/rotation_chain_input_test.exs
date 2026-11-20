defmodule SigilGuard.TrustBundle.RotationChainInputTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import SigilGuard.TrustBundleFixtureGenerator,
    only: [envelope_document: 1, read_json: 1, root_pin: 1, sign_with: 2, signed_successor: 1]

  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundleFixtureGenerator.NewRootSigner
  alias SigilGuard.TrustBundleFixtureGenerator.RootSigner

  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
  end

  test "a rotation chain entry that is not a rotation envelope is refused" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])
    pin = root_pin(envelope_document(genesis))
    [rotation] = envelope_document(successor)["rotation_chain"]

    future_profile =
      rotation
      |> envelope_document()
      |> Map.put("profile", "sigil_guard_root_rotation/v9")
      |> sign_with([RootSigner, NewRootSigner])

    for {entry, reason} <- [
          {"not an envelope", :invalid_envelope},
          {7, :invalid_envelope},
          {nil, :invalid_envelope},
          {%{}, :invalid_envelope},
          {genesis, :invalid_bundle_format},
          {Map.put(rotation, "payload", "***"), :invalid_base64},
          {future_profile, :unsupported_profile_version}
        ] do
      bundle =
        successor
        |> envelope_document()
        |> Map.put("rotation_chain", [entry])
        |> signed_successor()

      assert TrustBundle.verify(bundle, now: @now, genesis_root: pin) == {:error, reason}
    end
  end

  test "a genesis root that lists a key id without its key is refused" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = signed_successor(envelope_document(read_json(["rotation", "successor.json"])))
    pin = root_pin(envelope_document(genesis))

    assert {:ok, _} = TrustBundle.verify(successor, now: @now, genesis_root: pin)

    assert TrustBundle.verify(successor, now: @now, genesis_root: %{pin | keys: %{}}) ==
             {:error, :invalid_bundle_format}
  end
end

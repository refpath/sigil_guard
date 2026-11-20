defmodule SigilGuard.TrustBundle.GoldenFixtureTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias __MODULE__.OldBundleSigner
  alias __MODULE__.SuccessorSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Schema
  alias SigilGuard.TrustBundleFixtureGenerator

  @fixtures SigilGuard.FixturePath.path("trust_bundle")
  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()

    on_exit(fn -> Cache.clear() end)
  end

  test "committed trust-bundle fixtures regenerate byte-identically" do
    for {dir, files} <- TrustBundleFixtureGenerator.generate(),
        {name, bytes} <- files do
      assert File.read!(Path.join([@fixtures, dir, name])) == bytes
    end
  end

  test "minimal and multisig fixtures verify and assert stored digests" do
    for name <- ~w(minimal multisig) do
      bundle_json = File.read!(Path.join([@fixtures, name, "bundle.json"]))
      envelope = read_json([name, "envelope.json"])
      expected = read_json([name, "expected.json"])

      assert {:ok, ^bundle_json} = JCS.encode(read_json([name, "bundle.json"]))
      assert digest(bundle_json) == expected["bundle_digest"]
      assert digest(Envelope.pae(Envelope.payload_type(), bundle_json)) == expected["pae_sha256"]
      assert signatures(envelope) == expected["signatures"]

      assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(envelope, now: @now)
      assert digest == expected["bundle_digest"]
    end
  end

  test "rotation fixtures validate current schema and record recomputed digests" do
    expected = read_json(["rotation", "expected.json"])

    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()
    genesis_root = root_pin(envelope_document(genesis))

    assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(genesis, now: @now)
    assert digest == expected["bundle_digest"]["genesis"]

    assert {:ok, %TrustBundle{digest: digest, root_version: 2}} =
             TrustBundle.verify(successor, now: @now, genesis_root: genesis_root)

    assert digest == expected["bundle_digest"]["successor"]

    for name <- ~w(rotation-2 forked-2) do
      envelope = read_json(["rotation", "#{name}.json"])
      document = envelope_document(envelope)

      assert Schema.validate(document) == {:ok, :rotation, document}
      assert TrustBundle.verify(envelope, now: @now) == {:error, :invalid_bundle_format}
      assert document_digest(document) == expected["bundle_digest"][name]

      assert digest(Envelope.pae(Envelope.payload_type(), envelope_payload(envelope))) ==
               expected["pae_sha256"][name]

      assert signatures(envelope) == expected["signatures"][name]
    end
  end

  test "rotation chain rejects missing quorums, gaps, and terminal mismatches" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()
    genesis_root = root_pin(envelope_document(genesis))
    [rotation] = get_in(envelope_document(successor), ["rotation_chain"])

    old_only =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [
        put_in(rotation, ["signatures"], [old_root_signature(rotation)])
      ])
      |> signed_successor()

    assert TrustBundle.verify(old_only, now: @now, genesis_root: genesis_root) ==
             {:error, :rotation_below_threshold}

    gapped =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain", Access.at(0), "payload"], gapped_rotation_payload(rotation))
      |> signed_successor()

    assert TrustBundle.verify(gapped, now: @now, genesis_root: genesis_root) ==
             {:error, :invalid_bundle_format}

    terminal_mismatch =
      successor
      |> envelope_document()
      |> put_in(["roles", "root", "threshold"], 2)
      |> signed_successor()

    assert TrustBundle.verify(terminal_mismatch, now: @now, genesis_root: genesis_root) ==
             {:error, :invalid_bundle_format}
  end

  test "cached genesis pin verifies successor rotation chain" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()

    assert {:ok, %TrustBundle{root_version: 1}} = TrustBundle.load({:map, genesis}, now: @now)

    assert {:ok, %TrustBundle{root_version: 2, sequence: 2}} =
             TrustBundle.load({:map, successor}, now: @now)
  end

  test "rotation chain rejects forked roots in-chain and against cached digests" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()
    forked_rotation = read_json(["rotation", "forked-2.json"])
    genesis_root = root_pin(envelope_document(genesis))

    in_chain_fork =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [rotation(successor), forked_rotation])
      |> signed_successor()

    assert TrustBundle.verify(in_chain_fork, now: @now, genesis_root: genesis_root) ==
             {:error, :forked_root_chain}

    assert {:ok, %TrustBundle{root_version: 1}} = TrustBundle.load({:map, genesis}, now: @now)
    assert {:ok, %TrustBundle{root_version: 2}} = TrustBundle.load({:map, successor}, now: @now)

    cached_fork =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [forked_rotation])
      |> signed_successor()

    assert TrustBundle.verify(cached_fork, now: @now) == {:error, :forked_root_chain}
  end

  test "pre-rotation bundles replay below the accepted floor" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()

    assert {:ok, %TrustBundle{sequence: 1}} = TrustBundle.load({:map, genesis}, now: @now)

    assert {:ok, %TrustBundle{sequence: 2, root_version: 2}} =
             TrustBundle.load({:map, successor}, now: @now)

    assert TrustBundle.load({:map, genesis}, now: @now) == {:error, :sequence_below_floor}
  end

  test "signer compromise ceremony revokes old key and keeps revocation irreversible" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()
    genesis_document = envelope_document(genesis)
    old_bundle_keyid = read_json(["rotation", "expected.json"])["keyids"]["bundle"]

    revoking_successor =
      successor
      |> envelope_document()
      |> Map.put("revocations", [
        %{"kind" => "key", "id" => old_bundle_keyid, "revoked_at" => "2026-07-02T12:00:00.000Z"}
      ])
      |> signed_successor()

    assert {:ok, %TrustBundle{sequence: 1}} = TrustBundle.load({:map, genesis}, now: @now)

    assert {:ok, %TrustBundle{sequence: 2, root_version: 2}} =
             TrustBundle.load({:map, revoking_successor}, now: @now)

    assert Cache.floor("example-org-trust") == 2
    assert TrustBundle.load({:map, genesis}, now: @now) == {:error, :revoked_key}

    reauthorized_old_key =
      successor
      |> envelope_document()
      |> Map.drop(["revocations"])
      |> Map.put("sequence", "3")
      |> Map.put("rollback_floor", "3")
      |> put_in(["roles", "delegates"], [old_bundle_role(old_bundle_keyid)])
      |> put_in(["keys", old_bundle_keyid], genesis_document["keys"][old_bundle_keyid])
      |> signed_old_bundle()

    assert TrustBundle.verify(reauthorized_old_key, now: @now) == {:error, :revoked_key}
  end

  describe "rollback against the state accepted in this boot" do
    alias SigilGuard.TrustBundleFixtureGenerator.BundleSigner

    defp next_minimal(sequence) do
      ["minimal", "envelope.json"]
      |> read_json()
      |> envelope_document()
      |> Map.put("sequence", Integer.to_string(sequence))
      |> signed_document(BundleSigner)
    end

    test "verify/2 and an uncached load refuse a bundle below the cached snapshot" do
      first = read_json(["minimal", "envelope.json"])
      second = next_minimal(2)

      # Nothing is cached yet, so either bundle verifies.
      assert {:ok, %TrustBundle{sequence: 1}} = TrustBundle.verify(first, now: @now)
      assert {:ok, %TrustBundle{sequence: 2}} = TrustBundle.verify(second, now: @now)
      assert Cache.floor("example-org-trust") == 0

      assert {:ok, %TrustBundle{sequence: 2}} = TrustBundle.load({:map, second}, now: @now)

      assert TrustBundle.verify(first, now: @now) == {:error, :sequence_below_floor}

      assert TrustBundle.load({:map, first}, now: @now, cache: false) ==
               {:error, :sequence_below_floor}

      assert {:ok, %TrustBundle{sequence: 2}} = TrustBundle.verify(second, now: @now)
      assert {:ok, %TrustBundle{sequence: 3}} = TrustBundle.verify(next_minimal(3), now: @now)

      # verify/2 records nothing.
      assert Cache.floor("example-org-trust") == 2
    end

    test "an uncached load does not raise the floor" do
      second = next_minimal(2)

      assert {:ok, _} = TrustBundle.load({:map, second}, now: @now, cache: false)
      assert Cache.floor("example-org-trust") == 0

      assert {:ok, %TrustBundle{sequence: 1}} =
               TrustBundle.verify(read_json(["minimal", "envelope.json"]), now: @now)
    end

    test "Cache.check/1 answers as put/1 would, without recording" do
      {:ok, first} = TrustBundle.verify(read_json(["minimal", "envelope.json"]), now: @now)
      {:ok, second} = TrustBundle.verify(next_minimal(2), now: @now)

      assert Cache.check(first) == :ok
      assert {:ok, _} = Cache.put(second)
      assert Cache.check(second) == :ok
      assert Cache.check(first) == {:error, :sequence_below_floor}
      assert Cache.check(%TrustBundle{}) == {:error, :invalid_bundle}
      assert Cache.put(%TrustBundle{}) == {:error, :invalid_bundle}
    end
  end

  describe "rotation rollback floors" do
    alias SigilGuard.TrustBundleFixtureGenerator.ForkedRootSigner
    alias SigilGuard.TrustBundleFixtureGenerator.NewBundleSigner
    alias SigilGuard.TrustBundleFixtureGenerator.NewRootSigner
    alias SigilGuard.TrustBundleFixtureGenerator.RootSigner

    defp key_descriptor(signer) do
      %{
        "alg" => "ed25519",
        "public_key" => Base.url_encode64(signer.public_key(), padding: false)
      }
    end

    defp sign_with(document, signers) do
      {:ok, payload} = JCS.encode(document)
      {:ok, envelope} = Envelope.sign_many(payload, signers)
      envelope
    end

    # The committed successor with its rotation document re-issued at `floor`.
    defp successor_with_rotation_floor(floor, sequence) do
      successor = read_json(["rotation", "successor.json"])

      rotation =
        successor
        |> rotation()
        |> envelope_document()
        |> Map.put("rollback_floor", Integer.to_string(floor))
        |> sign_with([RootSigner, NewRootSigner])

      successor
      |> envelope_document()
      |> Map.put("rotation_chain", [rotation])
      |> Map.put("sequence", Integer.to_string(sequence))
      |> Map.put("rollback_floor", Integer.to_string(min(floor, sequence)))
      |> sign_with([NewBundleSigner, NewRootSigner])
    end

    # A bundle under root version 3, reached through two rotations whose
    # floors are `second_floor` and `third_floor`.
    defp twice_rotated(second_floor, third_floor) do
      successor = envelope_document(read_json(["rotation", "successor.json"]))
      second = envelope_document(rotation(read_json(["rotation", "successor.json"])))
      new_root_keyid = Envelope.keyid(NewRootSigner.public_key())
      third_root_keyid = Envelope.keyid(ForkedRootSigner.public_key())
      third_root = %{second["roles"]["root"] | "keyids" => [third_root_keyid], "version" => "3"}

      second_rotation =
        second
        |> Map.put("rollback_floor", Integer.to_string(second_floor))
        |> sign_with([RootSigner, NewRootSigner])

      third_rotation =
        second
        |> Map.put("root_version", "3")
        |> Map.put("rollback_floor", Integer.to_string(third_floor))
        |> Map.put("roles", %{"root" => third_root})
        |> Map.put("keys", %{
          new_root_keyid => key_descriptor(NewRootSigner),
          third_root_keyid => key_descriptor(ForkedRootSigner)
        })
        |> sign_with([NewRootSigner, ForkedRootSigner])

      sequence = Integer.to_string(max(second_floor, third_floor) + 1)

      successor
      |> Map.put("rotation_chain", [second_rotation, third_rotation])
      |> Map.put("sequence", sequence)
      |> Map.put("rollback_floor", sequence)
      |> put_in(["roles", "root"], third_root)
      |> Map.update!("keys", fn keys ->
        keys
        |> Map.delete(new_root_keyid)
        |> Map.put(third_root_keyid, key_descriptor(ForkedRootSigner))
      end)
      |> sign_with([NewBundleSigner, ForkedRootSigner])
    end

    setup do
      %{pin: root_pin(envelope_document(read_json(["rotation", "genesis.json"])))}
    end

    test "a bundle below the floor its own rotation set is refused", %{pin: pin} do
      verify = &TrustBundle.verify(&1, now: @now, genesis_root: pin)

      assert {:ok, %TrustBundle{sequence: 2}} = verify.(successor_with_rotation_floor(2, 2))
      assert {:ok, %TrustBundle{sequence: 5}} = verify.(successor_with_rotation_floor(5, 5))
      assert {:ok, %TrustBundle{sequence: 7}} = verify.(successor_with_rotation_floor(5, 7))

      assert verify.(successor_with_rotation_floor(5, 2)) == {:error, :sequence_below_floor}
      assert verify.(successor_with_rotation_floor(5, 4)) == {:error, :sequence_below_floor}
    end

    test "each rotation raises the floor above the one before it", %{pin: pin} do
      verify = &TrustBundle.verify(&1, now: @now, genesis_root: pin)

      assert {:ok, %TrustBundle{root_version: 3}} = verify.(twice_rotated(2, 3))
      assert {:ok, %TrustBundle{root_version: 3}} = verify.(twice_rotated(2, 9))

      assert verify.(twice_rotated(2, 2)) == {:error, :sequence_below_floor}
      assert verify.(twice_rotated(4, 3)) == {:error, :sequence_below_floor}
    end
  end

  defp read_json(path) when is_list(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end

  defp envelope_document(envelope) do
    envelope
    |> envelope_payload()
    |> Jason.decode!()
  end

  defp envelope_payload(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
  end

  defp encoded_payload(document) do
    {:ok, bytes} = JCS.encode(document)
    Base.url_encode64(bytes, padding: false)
  end

  defp signed_successor(document) do
    signed_document(document, SuccessorSigner) |> authorize_successor()
  end

  defp signed_old_bundle(document) do
    signed_document(document, OldBundleSigner)
  end

  defp signed_document(document, signer) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, [signer])
    envelope
  end

  defp rotation(envelope) do
    envelope
    |> envelope_document()
    |> Map.fetch!("rotation_chain")
    |> List.first()
  end

  defp root_pin(document) do
    root = get_in(document, ["roles", "root"])

    %{
      version: String.to_integer(root["version"]),
      threshold: root["threshold"],
      keyids: root["keyids"],
      keys: decoded_keys(document)
    }
  end

  defp decoded_keys(document) do
    Map.new(document["keys"], fn {keyid, %{"public_key" => encoded}} ->
      {:ok, public_key} = Base.url_decode64(encoded, padding: false)
      {keyid, public_key}
    end)
  end

  defp old_bundle_role(keyid) do
    %{
      "name" => "bundle",
      "keyids" => [keyid],
      "threshold" => 1,
      "expires_at" => "2026-10-01T12:00:00.000Z"
    }
  end

  defp old_root_signature(rotation) do
    expected = read_json(["rotation", "expected.json"])
    old_root_keyid = expected["keyids"]["root"]
    Enum.find(rotation["signatures"], &(Map.fetch!(&1, "keyid") == old_root_keyid))
  end

  defp gapped_rotation_payload(rotation) do
    rotation
    |> envelope_document()
    |> Map.put("root_version", "3")
    |> put_in(["roles", "root", "version"], "3")
    |> encoded_payload()
  end

  defp document_digest(document) do
    {:ok, bytes} = JCS.encode(document)
    digest(bytes)
  end

  defp signatures(envelope), do: Map.new(envelope["signatures"], &{&1["keyid"], &1["sig"]})
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defmodule SuccessorSigner do
    @behaviour SigilGuard.Signer
    @seed :binary.copy(<<0x99>>, 32)

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defmodule OldBundleSigner do
    @behaviour SigilGuard.Signer
    @seed :binary.copy(<<0xBB>>, 32)

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defp authorize_successor(envelope) do
    {:ok, signed} =
      Envelope.add_signature(envelope, SigilGuard.TrustBundleFixtureGenerator.NewRootSigner)

    signed
  end

  test "a cached root cannot be replaced by a self-authorized signing key" do
    original = read_json(["minimal", "envelope.json"])
    assert {:ok, _} = TrustBundle.load({:map, original}, now: @now)
    key = Envelope.keyid(SuccessorSigner.public_key())

    descriptor = %{
      "alg" => "ed25519",
      "public_key" => Base.url_encode64(SuccessorSigner.public_key(), padding: false)
    }

    document =
      original
      |> envelope_document()
      |> Map.put("sequence", "2")
      |> Map.put("keys", %{key => descriptor})
      |> put_in(["roles", "root", "keyids"], [key])
      |> put_in(["roles", "delegates", Access.at(0), "keyids"], [key])

    malicious = signed_document(document, SuccessorSigner)
    assert TrustBundle.load({:map, malicious}, now: @now) == {:error, :invalid_bundle_format}
    assert Cache.floor("example-org-trust") == 1
  end

  test "rotation alone does not authorize a successor's newly declared delegates" do
    original = read_json(["rotation", "genesis.json"])
    incomplete = read_json(["rotation", "successor.json"])
    assert {:ok, _} = TrustBundle.load({:map, original}, now: @now)
    assert TrustBundle.verify(incomplete, now: @now) == {:error, :threshold_not_met}
    assert {:ok, _} = TrustBundle.load({:map, authorize_successor(incomplete)}, now: @now)
  end

  test "a bundle delegate cannot change its own role under the pinned root version" do
    original = read_json(["minimal", "envelope.json"])
    assert {:ok, _} = TrustBundle.load({:map, original}, now: @now)

    changed =
      original
      |> envelope_document()
      |> Map.put("sequence", "2")
      |> put_in(["roles", "delegates", Access.at(0), "expires_at"], "2027-10-01T12:00:00.000Z")
      |> signed_old_bundle()

    assert TrustBundle.verify(changed, now: @now) == {:error, :invalid_bundle_format}
  end
end

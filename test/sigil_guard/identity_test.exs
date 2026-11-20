defmodule SigilGuard.IdentityTest do
  @moduledoc false

  use ExUnit.Case, async: true

  doctest SigilGuard.Identity

  alias SigilGuard.Identity

  describe "compare_trust/2" do
    test "low < medium" do
      assert :lt = Identity.compare_trust(:low, :medium)
    end

    test "medium < high" do
      assert :lt = Identity.compare_trust(:medium, :high)
    end

    test "equal levels return :eq" do
      for level <- Identity.trust_levels() do
        assert :eq = Identity.compare_trust(level, level)
      end
    end

    test "higher trust returns :gt" do
      assert :gt = Identity.compare_trust(:high, :low)
      assert :gt = Identity.compare_trust(:medium, :low)
    end

    test "full ordering is transitive" do
      levels = Identity.trust_levels()

      for {a, i} <- Enum.with_index(levels),
          {b, j} <- Enum.with_index(levels) do
        expected =
          cond do
            i < j -> :lt
            i > j -> :gt
            true -> :eq
          end

        assert Identity.compare_trust(a, b) == expected,
               "compare_trust(#{a}, #{b}) expected #{expected}"
      end
    end
  end

  describe "sufficient_trust?/2" do
    test "same level is sufficient" do
      for level <- Identity.trust_levels() do
        assert Identity.sufficient_trust?(level, level)
      end
    end

    test "higher level is sufficient" do
      assert Identity.sufficient_trust?(:high, :low)
      assert Identity.sufficient_trust?(:high, :medium)
      assert Identity.sufficient_trust?(:medium, :low)
    end

    test "lower level is insufficient" do
      refute Identity.sufficient_trust?(:low, :medium)
      refute Identity.sufficient_trust?(:medium, :high)
    end

    test "low is only sufficient for low" do
      assert Identity.sufficient_trust?(:low, :low)
      refute Identity.sufficient_trust?(:low, :medium)
      refute Identity.sufficient_trust?(:low, :high)
    end

    test "high is sufficient for all levels" do
      for level <- Identity.trust_levels() do
        assert Identity.sufficient_trust?(:high, level)
      end
    end
  end

  describe "trust_levels/0" do
    test "returns all three levels in ascending order" do
      assert [:low, :medium, :high] = Identity.trust_levels()
    end
  end

  describe "spiffe_id?/1" do
    test "accepts the forms the SPIFFE-ID standard allows" do
      for id <- [
            "spiffe://example.org",
            "spiffe://example.org/agent",
            "spiffe://example.org/ns/prod/sa/planner",
            "spiffe://trust_domain-1.example/Workload.A/b_c-d",
            "spiffe://" <> String.duplicate("a", 255) <> "/x"
          ] do
        assert Identity.spiffe_id?(id), id
      end
    end

    test "refuses each violation of the standard" do
      for id <- [
            "spiffe://",
            "spiffe:///agent",
            "spiffe://Example.org/agent",
            "SPIFFE://example.org/agent",
            "https://example.org/agent",
            "spiffe://example.org/",
            "spiffe://example.org/agent/",
            "spiffe://example.org//agent",
            "spiffe://example.org/./agent",
            "spiffe://example.org/../agent",
            "spiffe://example.org/agent?x=1",
            "spiffe://example.org/agent#frag",
            "spiffe://example.org/a%20b",
            "spiffe://user@example.org/agent",
            "spiffe://example.org:8443/agent",
            "spiffe://example.org/agent name",
            "spiffe://exa mple.org/agent",
            "spiffe://example.org/agent\n",
            "spiffe://" <> String.duplicate("a", 256) <> "/x",
            "spiffe://example.org/" <> String.duplicate("a", 2048)
          ] do
        refute Identity.spiffe_id?(id), id
      end
    end

    test "refuses a term that is not a string" do
      for term <- [nil, :spiffe, 1, ~c"spiffe://example.org", %{}, ["spiffe://example.org"]] do
        refute Identity.spiffe_id?(term)
      end
    end

    test "accepts an identifier of exactly 2048 bytes" do
      prefix = "spiffe://example.org/"
      id = prefix <> String.duplicate("a", 2048 - byte_size(prefix))

      assert byte_size(id) == 2048
      assert Identity.spiffe_id?(id)
      refute Identity.spiffe_id?(id <> "a")
    end
  end

  describe "did_key_public_key/1" do
    @spec_did "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    @spec_key "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6"

    test "decodes the identifier from the did:key specification examples" do
      assert {:ok, key} = Identity.did_key_public_key(@spec_did)
      assert Base.encode16(key, case: :lower) == @spec_key
    end

    test "round-trips a key the test encodes itself, and the key verifies a signature" do
      {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
      did = "did:key:z" <> base58(<<0xED, 0x01>> <> public_key)

      assert String.starts_with?(did, "did:key:z6Mk")
      assert Identity.did_key_public_key(did) == {:ok, public_key}

      signature = :crypto.sign(:eddsa, :none, "message", [private_key, :ed25519])
      {:ok, decoded} = Identity.did_key_public_key(did)

      assert :crypto.verify(:eddsa, :none, "message", signature, [decoded, :ed25519])
    end

    test "refuses another method, multibase, key type, length or character" do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519)

      for did <- [
            "did:web:example.org",
            "did:key:" <> String.slice(@spec_did, 9..-1//1),
            "did:key:u" <> String.slice(@spec_did, 9..-1//1),
            "DID:KEY:" <> String.slice(@spec_did, 8..-1//1),
            @spec_did <> "#" <> String.slice(@spec_did, 8..-1//1),
            @spec_did <> "1",
            String.slice(@spec_did, 0..-2//1),
            String.replace(@spec_did, "L", "0", global: false),
            String.replace(@spec_did, "L", "l", global: false),
            "did:key:1:" <> String.slice(@spec_did, 8..-1//1),
            # secp256k1-pub (0xe7 0x01) and a 31-byte Ed25519 value
            "did:key:z" <> base58(<<0xE7, 0x01>> <> public_key),
            "did:key:z" <> base58(<<0xED, 0x01>> <> binary_part(public_key, 0, 31)),
            "did:key:z" <> base58(<<0xED, 0x02>> <> public_key),
            "did:key:z",
            ""
          ] do
        assert Identity.did_key_public_key(did) == {:error, :invalid_did_key}, did
      end
    end

    test "refuses a term that is not a string" do
      for term <- [nil, :did, 1, ~c"did:key:z6Mk", %{}] do
        assert Identity.did_key_public_key(term) == {:error, :invalid_did_key}
      end
    end

    @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    defp base58(binary) do
      binary
      |> :binary.decode_unsigned()
      |> Stream.unfold(fn
        0 -> nil
        n -> {Enum.at(@alphabet, rem(n, 58)), div(n, 58)}
      end)
      |> Enum.reverse()
      |> List.to_string()
    end
  end
end

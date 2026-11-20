defmodule SigilGuard.CryptoTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Crypto

  describe "sha256_hex/1" do
    test "matches the FIPS 180-4 vectors for the empty string and abc" do
      assert Crypto.sha256_hex("") ==
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

      assert Crypto.sha256_hex("abc") ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    end

    test "hashes iodata as its concatenation" do
      assert Crypto.sha256_hex(["a", [?b, "c"]]) == Crypto.sha256_hex("abc")
    end
  end

  describe "secure_compare/2" do
    test "is true only for identical binaries" do
      assert Crypto.secure_compare("", "")
      assert Crypto.secure_compare("digest", "digest")
      refute Crypto.secure_compare("digest", "digesu")
      refute Crypto.secure_compare("Digest", "digest")
    end

    test "is false, not an error, for binaries of different size" do
      refute Crypto.secure_compare("digest", "digest ")
      refute Crypto.secure_compare("digest", "diges")
      refute Crypto.secure_compare("", "d")
    end

    test "is false for a term that is not a binary" do
      for term <- [nil, :digest, 1, ~c"digest", %{}, ["digest"]] do
        refute Crypto.secure_compare(term, "digest")
        refute Crypto.secure_compare("digest", term)
        refute Crypto.secure_compare(term, term)
      end
    end
  end
end

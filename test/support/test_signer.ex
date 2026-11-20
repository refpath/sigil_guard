defmodule SigilGuard.TestSigner do
  @moduledoc """
  Deterministic test signer with a fixed Ed25519 keypair.

  Uses a SHA-256 hash of a static seed string to derive a reproducible
  Ed25519 keypair. This ensures that attestation signatures and public keys
  are identical across test runs, making assertions on signed data stable.

  ## Usage

      SigilGuard.TestSigner.sign("payload")
      SigilGuard.TestSigner.public_key_b64u()

  A test that needs another key defines its own signer from a 32-byte seed:

      defmodule RootSigner do
        use SigilGuard.TestSigner, seed: :crypto.hash(:sha256, "root")
      end

  """

  @behaviour SigilGuard.Signer

  @seed :crypto.hash(:sha256, "sigil_guard_test_seed_v1")

  @doc false
  defmacro __using__(opts) do
    seed = Keyword.fetch!(opts, :seed)

    quote bind_quoted: [seed: seed] do
      @behaviour SigilGuard.Signer
      @seed seed

      @doc false
      @spec seed() :: binary()
      def seed, do: @seed

      @impl SigilGuard.Signer
      def sign(message) do
        {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
        :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
      end

      @impl SigilGuard.Signer
      def public_key do
        {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
        public_key
      end
    end
  end

  @doc false
  @spec keypair() :: {binary(), binary()}
  def keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, @seed)
    {pub, priv}
  end

  @impl SigilGuard.Signer
  def sign(message) do
    {_, priv} = keypair()
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @impl SigilGuard.Signer
  def public_key do
    {pub, _} = keypair()
    pub
  end

  @doc "Return the public key as base64url (no padding) for attestation verification."
  @spec public_key_b64u() :: String.t()
  def public_key_b64u do
    Base.url_encode64(public_key(), padding: false)
  end
end

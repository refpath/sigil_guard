defmodule SigilGuard.Audit.Anchor.Receipt do
  @moduledoc """
  Canonical bytes, digest and Ed25519 signature for audit anchor receipts.

  Anchor stores return compact receipt maps that point back to an externally
  persisted audit anchor. This module defines the canonical receipt bytes used
  for receipt digests and Ed25519 provenance, so remote WORM/append-only
  services can produce receipts that `SigilGuard.Audit.Anchor.Store.HTTP`
  verifies in strict mode.

  Top-level `"signature"` metadata is excluded from canonical bytes, matching
  the checkpoint signing pattern (`SigilGuard.Audit.Checkpoint.canonical_bytes/1`).
  """

  alias SigilGuard.Audit.SignatureMetadata

  @metadata_keys ~w(signature)
  @metadata_atom_keys [:signature]

  @typedoc "Store-specific persistence receipt for an anchor record."
  @type t :: %{required(String.t()) => term()}

  @doc """
  Return canonical receipt bytes, excluding top-level signature metadata.
  """
  @spec canonical_bytes(map()) :: binary()
  def canonical_bytes(receipt) when is_map(receipt) do
    receipt
    |> unsigned()
    |> SigilGuard.Canonical.LegacyJSON.encode!()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical receipt bytes.
  """
  @spec digest(map()) :: String.t()
  def digest(receipt) when is_map(receipt) do
    receipt
    |> canonical_bytes()
    |> SigilGuard.Crypto.sha256_hex()
  end

  @doc """
  Return the receipt without top-level signature metadata.
  """
  @spec unsigned(map()) :: map()
  def unsigned(receipt) when is_map(receipt),
    do: Map.drop(receipt, @metadata_keys ++ @metadata_atom_keys)

  @doc """
  Sign a receipt using a `SigilGuard.Signer` module.

  Options:

    * `:issuer` - required receipt issuer identifier, usually a DID.
  """
  @spec sign(map(), module(), keyword()) :: map()
  def sign(receipt, signer, opts) when is_map(receipt) and is_atom(signer) and is_list(opts) do
    issuer = Keyword.fetch!(opts, :issuer)
    unsigned_receipt = unsigned(receipt)
    canonical = canonical_bytes(unsigned_receipt)

    Map.put(
      unsigned_receipt,
      "signature",
      SignatureMetadata.sign(canonical, signer, %{"issuer" => issuer})
    )
  end

  @doc """
  Verify signed receipt provenance.

  Options:

    * `:public_keys` - map of issuer to base64/base64url Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any issuer.
  """
  @spec verify(map(), keyword()) :: :ok | {:error, atom()}
  def verify(receipt, opts \\ [])

  def verify(receipt, opts) when is_map(receipt) and is_list(opts) do
    case signature(receipt) do
      signature when is_map(signature) -> verify_signature(receipt, signature, opts)
      nil -> {:error, :unsigned_receipt}
      _ -> {:error, :invalid_signature_metadata}
    end
  end

  def verify(_, _), do: {:error, :invalid_receipt}

  @doc """
  Return top-level signature metadata from a string-keyed or atom-keyed receipt.
  """
  @spec signature(map()) :: map() | term() | nil
  def signature(receipt) when is_map(receipt) do
    case Map.fetch(receipt, "signature") do
      {:ok, signature} -> signature
      :error -> Map.get(receipt, :signature)
    end
  end

  defp verify_signature(receipt, signature, opts) do
    with {:ok, canonical} <- receipt_canonical_bytes(receipt),
         {:ok, _} <- SignatureMetadata.verify(signature, canonical, opts),
         do: :ok
  end

  defp receipt_canonical_bytes(receipt) do
    with true <- SigilGuard.Canonical.JSON.unique_keys?(receipt),
         {:ok, iodata} <- SigilGuard.Canonical.LegacyJSON.encode(unsigned(receipt)) do
      {:ok, IO.iodata_to_binary(iodata)}
    else
      _ -> {:error, :invalid_receipt}
    end
  end
end

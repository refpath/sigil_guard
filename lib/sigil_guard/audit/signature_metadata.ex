defmodule SigilGuard.Audit.SignatureMetadata do
  @moduledoc false

  # Checkpoints and anchor receipts carry the same detached Ed25519 signature
  # block over their canonical bytes: issuer, algorithm, the SHA-256 digest of
  # the bytes, and the base64url signature. Each document adds its own fields
  # (a checkpoint records `issued_at`) and owns its canonical form.

  alias SigilGuard.Crypto

  @algorithm "Ed25519"
  @atom_fields %{
    "algorithm" => :algorithm,
    "digest" => :digest,
    "issuer" => :issuer,
    "signature" => :signature
  }

  @doc false
  @spec algorithm() :: String.t()
  def algorithm, do: @algorithm

  @doc false
  @spec sign(binary(), module(), map()) :: map()
  def sign(canonical, signer, fields) when is_binary(canonical) and is_map(fields) do
    Map.merge(fields, %{
      "algorithm" => @algorithm,
      "digest" => Crypto.sha256_hex(canonical),
      "signature" => Base.url_encode64(signer.sign(canonical), padding: false)
    })
  end

  # Options: `:public_keys` maps an issuer to a base64 or base64url key, and
  # `:public_key_b64u` is the key for any issuer not in that map.
  @doc false
  @spec verify(map(), binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def verify(signature, canonical, opts) when is_map(signature) and is_binary(canonical) do
    with {:ok, fields} <- fields(signature),
         :ok <- check_digest(Crypto.sha256_hex(canonical), fields.digest),
         {:ok, public_key} <- public_key(fields.issuer, opts),
         {:ok, decoded} <- decode_signature(fields.signature),
         :ok <- verify_ed25519(canonical, decoded, public_key) do
      {:ok, fields.issuer}
    end
  end

  defp fields(signature) do
    fields = Map.new(@atom_fields, fn {key, atom} -> {atom, field(signature, key)} end)

    with :ok <- require_binary(fields.issuer, :missing_issuer),
         :ok <- require_binary(fields.algorithm, :missing_algorithm),
         :ok <- require_algorithm(fields.algorithm),
         :ok <- require_binary(fields.digest, :missing_digest),
         :ok <- require_binary(fields.signature, :missing_signature),
         true <- SigilGuard.Canonical.JSON.unique_keys?(signature) do
      {:ok, fields}
    else
      false -> {:error, :invalid_signature_metadata}
      error -> error
    end
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_algorithm(@algorithm), do: :ok
  defp require_algorithm(_), do: {:error, :unsupported_algorithm}

  defp check_digest(digest, claimed) do
    if Crypto.secure_compare(digest, claimed), do: :ok, else: {:error, :digest_mismatch}
  end

  defp public_key(issuer, opts) do
    case Keyword.get(opts, :public_keys, %{}) do
      public_keys when is_map(public_keys) ->
        with {:ok, encoded} <- public_key_source(public_keys, issuer, opts),
             do: decode_public_key(encoded)

      _ ->
        {:error, :invalid_public_keys}
    end
  end

  defp public_key_source(public_keys, issuer, opts) do
    case Map.fetch(public_keys, issuer) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, _} -> {:error, :invalid_key}
      :error -> fallback_public_key(opts)
    end
  end

  defp fallback_public_key(opts) do
    case Keyword.get(opts, :public_key_b64u) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, :unknown_issuer}
    end
  end

  defp decode_public_key(value) do
    case Crypto.decode_base64(value) do
      {:ok, key} when byte_size(key) == 32 -> {:ok, key}
      {:ok, _} -> {:error, :invalid_key}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_signature(value) do
    case Crypto.decode_base64(value) do
      {:ok, signature} when byte_size(signature) == 64 -> {:ok, signature}
      {:ok, _} -> {:error, :invalid_signature}
      :error -> {:error, :invalid_base64}
    end
  end

  defp verify_ed25519(canonical, signature, public_key) do
    if :crypto.verify(:eddsa, :none, canonical, signature, [public_key, :ed25519]),
      do: :ok,
      else: {:error, :invalid_signature}
  rescue
    ErlangError -> {:error, :invalid_signature}
  end

  defp field(map, key), do: SigilGuard.Field.get(map, key, @atom_fields)
end

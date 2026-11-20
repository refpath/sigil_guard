defmodule SigilGuard.Crypto do
  @moduledoc false

  @doc false
  @spec sha256_hex(iodata()) :: String.t()
  def sha256_hex(data), do: Base.encode16(:crypto.hash(:sha256, data), case: :lower)

  @doc false
  @spec jcs_sha256_hex(term()) :: {:ok, String.t()} | {:error, atom()}
  def jcs_sha256_hex(value) do
    with {:ok, canonical} <- SigilGuard.Canonical.JCS.encode(value),
         do: {:ok, sha256_hex(canonical)}
  end

  # Keys and signatures arrive in either base64 alphabet, with or without
  # padding. The url-safe alphabet is tried first because the library writes
  # it.
  @doc false
  @spec decode_base64(term()) :: {:ok, binary()} | :error
  def decode_base64(value) when is_binary(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true),
         :error <- Base.decode64(value, padding: false) do
      Base.decode64(value, padding: true)
    end
  end

  def decode_base64(_), do: :error

  @doc false
  @spec random_hex(pos_integer()) :: String.t()
  def random_hex(bytes), do: Base.encode16(:crypto.strong_rand_bytes(bytes), case: :lower)

  # A SHA-256 digest as the library writes it: 64 lowercase hex digits.
  @doc false
  @spec sha256_hex?(term()) :: boolean()
  def sha256_hex?(value), do: is_binary(value) and value =~ ~r/\A[0-9a-f]{64}\z/

  # `:crypto.hash_equals/2` raises on operands of different size, so the size
  # check is part of the comparison, not an optimization.
  @doc false
  @spec secure_compare(term(), term()) :: boolean()
  def secure_compare(left, right) when is_binary(left) and is_binary(right),
    do: byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)

  def secure_compare(_, _), do: false
end

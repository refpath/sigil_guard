defmodule SigilGuard.Crypto do
  @moduledoc false

  @doc false
  @spec sha256_hex(iodata()) :: String.t()
  def sha256_hex(data), do: Base.encode16(:crypto.hash(:sha256, data), case: :lower)

  # `:crypto.hash_equals/2` raises on operands of different size, so the size
  # check is part of the comparison, not an optimization.
  @doc false
  @spec secure_compare(term(), term()) :: boolean()
  def secure_compare(left, right) when is_binary(left) and is_binary(right),
    do: byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)

  def secure_compare(_, _), do: false
end

defmodule SigilGuard.TestVersionedVault do
  @moduledoc """
  A `SigilGuard.Vault` backend with versioned master keys, for tests.

  It follows the SP.10 key rotation guidance for durable implementations:
  each ciphertext records the key version that encrypted it, a successful
  read under an old version re-encrypts under the current one, and a key
  version can be retired only when no entry references it.
  """

  @behaviour SigilGuard.Vault

  use Agent

  @aad "test_versioned_vault_v1"

  @type state :: %{
          keys: %{pos_integer() => binary()},
          current: pos_integer(),
          entries: %{String.t() => {pos_integer(), binary(), binary(), binary()}}
        }

  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(_ \\ []) do
    Agent.start_link(
      fn -> %{keys: %{1 => :crypto.strong_rand_bytes(32)}, current: 1, entries: %{}} end,
      name: __MODULE__
    )
  end

  @doc "Add a new key version and make it current."
  @spec rotate() :: pos_integer()
  def rotate do
    Agent.get_and_update(__MODULE__, fn state ->
      version = state.current + 1
      keys = Map.put(state.keys, version, :crypto.strong_rand_bytes(32))
      {version, %{state | keys: keys, current: version}}
    end)
  end

  @doc "Retire a key version. Refused while an entry or the current version uses it."
  @spec retire(pos_integer()) :: :ok | {:error, :key_in_use | :unknown_key_version}
  def retire(version) do
    Agent.get_and_update(__MODULE__, fn state ->
      cond do
        not Map.has_key?(state.keys, version) -> {{:error, :unknown_key_version}, state}
        version == state.current -> {{:error, :key_in_use}, state}
        version in versions(state) -> {{:error, :key_in_use}, state}
        true -> {:ok, %{state | keys: Map.delete(state.keys, version)}}
      end
    end)
  end

  @doc "Destroy a key version even when entries reference it."
  @spec destroy(pos_integer()) :: :ok
  def destroy(version) do
    Agent.update(__MODULE__, &%{&1 | keys: Map.delete(&1.keys, version)})
  end

  @doc "The key versions that stored entries reference, ascending."
  @spec versions_in_use() :: [pos_integer()]
  def versions_in_use, do: Agent.get(__MODULE__, &versions/1)

  @impl SigilGuard.Vault
  def encrypt(plaintext, _) when is_binary(plaintext) do
    Agent.get_and_update(__MODULE__, fn state ->
      id = "vault_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
      {{:ok, id}, put_in(state.entries[id], seal(plaintext, state.current, state.keys))}
    end)
  end

  @impl SigilGuard.Vault
  def decrypt(id) do
    Agent.get_and_update(__MODULE__, fn state ->
      with {:ok, entry} <- Map.fetch(state.entries, id),
           {:ok, plaintext} <- open(entry, state.keys) do
        {{:ok, plaintext}, put_in(state.entries[id], seal(plaintext, state.current, state.keys))}
      else
        :error -> {{:error, :not_found}, state}
        {:error, reason} -> {{:error, reason}, state}
      end
    end)
  end

  @impl SigilGuard.Vault
  def exists?(id), do: Agent.get(__MODULE__, &Map.has_key?(&1.entries, id))

  defp versions(state) do
    state.entries
    |> Map.values()
    |> Enum.map(&elem(&1, 0))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp seal(plaintext, version, keys) do
    iv = :crypto.strong_rand_bytes(12)
    key = Map.fetch!(keys, version)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, @aad, true)

    {version, iv, ciphertext, tag}
  end

  defp open({version, iv, ciphertext, tag}, keys) do
    with {:ok, key} <- Map.fetch(keys, version),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, @aad, tag, false) do
      {:ok, plaintext}
    else
      _ -> {:error, :decryption_failed}
    end
  end
end

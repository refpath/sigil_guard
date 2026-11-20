defmodule SigilGuard.VaultTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Vault.InMemory

  setup do
    sentinel = make_ref()
    previous_master_key = Application.get_env(:sigil_guard, :vault_master_key, sentinel)

    on_exit(fn ->
      case previous_master_key do
        ^sentinel -> Application.delete_env(:sigil_guard, :vault_master_key)
        value -> Application.put_env(:sigil_guard, :vault_master_key, value)
      end
    end)

    master_key = :crypto.strong_rand_bytes(32)
    start_supervised!({InMemory, master_key: master_key})
    %{master_key: master_key}
  end

  describe "encrypt/2 and decrypt/1" do
    test "decrypt returns exactly the plaintext encrypted" do
      for plaintext <- [
            "my-secret-key",
            :crypto.strong_rand_bytes(256),
            "",
            "пароль_тест_日本語"
          ] do
        {:ok, vault_id} = InMemory.encrypt(plaintext, "secret")

        assert InMemory.decrypt(vault_id) == {:ok, plaintext}
      end
    end

    test "each encryption produces a unique vault ID" do
      ids =
        for _ <- 1..50 do
          {:ok, id} = InMemory.encrypt("same-secret", "test")
          id
        end

      assert length(Enum.uniq(ids)) == 50
    end

    test "vault ids are vault_ followed by 32 lowercase hex characters" do
      {:ok, vault_id} = InMemory.encrypt("secret", "test")

      assert vault_id =~ ~r/\Avault_[0-9a-f]{32}\z/
    end
  end

  describe "decrypt/1 errors" do
    test "returns error for non-existent vault ID" do
      assert {:error, :not_found} = InMemory.decrypt("vault_nonexistent")
    end

    test "returns error when decryption fails due to corrupted data" do
      {:ok, vault_id} = InMemory.encrypt("my-secret", "test")

      # Corrupt the ETS entry from inside the GenServer process (ETS table is :private)
      :sys.replace_state(InMemory, fn state ->
        [{^vault_id, entry}] = :ets.lookup(state.table, vault_id)
        corrupted = %{entry | tag: :crypto.strong_rand_bytes(16)}
        :ets.insert(state.table, {vault_id, corrupted})
        state
      end)

      assert {:error, :decryption_failed} = InMemory.decrypt(vault_id)
    end
  end

  describe "exists?/1" do
    test "returns true for existing entries" do
      {:ok, vault_id} = InMemory.encrypt("secret", "test")

      assert InMemory.exists?(vault_id)
    end

    test "returns false for non-existent entries" do
      refute InMemory.exists?("vault_doesnotexist")
    end
  end

  describe "list_entries/0" do
    test "returns empty list initially" do
      assert [] = InMemory.list_entries()
    end

    test "lists stored entries with IDs and descriptions" do
      {:ok, id1} = InMemory.encrypt("secret1", "First key")
      {:ok, id2} = InMemory.encrypt("secret2", "Second key")

      entries = InMemory.list_entries()

      assert length(entries) == 2
      assert {id1, "First key"} in entries
      assert {id2, "Second key"} in entries
    end
  end

  describe "delete/1" do
    test "removes an existing entry" do
      {:ok, vault_id} = InMemory.encrypt("secret", "to delete")

      assert :ok = InMemory.delete(vault_id)
      refute InMemory.exists?(vault_id)
      assert {:error, :not_found} = InMemory.decrypt(vault_id)
    end

    test "returns error for non-existent entry" do
      assert {:error, :not_found} = InMemory.delete("vault_nope")
    end
  end

  describe "encryption isolation" do
    test "different entries decrypt independently" do
      {:ok, id1} = InMemory.encrypt("alpha", "first")
      {:ok, id2} = InMemory.encrypt("beta", "second")
      {:ok, id3} = InMemory.encrypt("gamma", "third")

      assert {:ok, "alpha"} = InMemory.decrypt(id1)
      assert {:ok, "beta"} = InMemory.decrypt(id2)
      assert {:ok, "gamma"} = InMemory.decrypt(id3)
    end
  end

  describe "master key from application config" do
    test "uses auto-generated key when no config and no opt" do
      stop_supervised!(InMemory)
      Application.delete_env(:sigil_guard, :vault_master_key)
      start_supervised!(InMemory)

      assert byte_size(:sys.get_state(InMemory).master_key) == 32
      {:ok, vault_id} = InMemory.encrypt("test", "auto-key")
      assert InMemory.decrypt(vault_id) == {:ok, "test"}
    end

    test "uses base64-encoded key from application config" do
      stop_supervised!(InMemory)
      key = :crypto.strong_rand_bytes(32)
      Application.put_env(:sigil_guard, :vault_master_key, Base.encode64(key))

      start_supervised!(InMemory)

      assert :sys.get_state(InMemory).master_key == key
      {:ok, vault_id} = InMemory.encrypt("config-test", "from config")
      assert InMemory.decrypt(vault_id) == {:ok, "config-test"}
    end

    test "rejects malformed :master_key options at start" do
      stop_supervised!(InMemory)

      for {key, reason} <- [
            {"short", {:invalid_master_key, :invalid_length}},
            {:not_binary, {:invalid_master_key, :invalid_type}}
          ] do
        assert_start_link_error(reason, master_key: key)
      end
    end

    test "rejects malformed configured master keys cleanly" do
      stop_supervised!(InMemory)

      for {configured, reason} <- [
            {"not base64!", {:invalid_master_key, :invalid_base64}},
            {Base.encode64("short"), {:invalid_master_key, :invalid_length}},
            {:not_binary, {:invalid_master_key, :invalid_type}}
          ] do
        Application.put_env(:sigil_guard, :vault_master_key, configured)

        assert_start_link_error(reason)
      end
    end

    test "rejects non-keyword start options at start" do
      stop_supervised!(InMemory)

      assert_start_link_error(:invalid_options, :bad)
      assert_start_link_error(:invalid_options, [:bad])
    end

    test "documents start options from the NimbleOptions schema" do
      docs = InMemory.start_options_docs()

      assert docs =~ ":master_key"
      assert docs =~ "AES-256-GCM"
    end
  end

  describe "format_status/1" do
    test "redacts master key from :sys.get_status" do
      {:status, _, _, items} = :sys.get_status(InMemory)
      status_str = inspect(items, limit: :infinity)

      assert status_str =~ "REDACTED"
      refute status_str =~ "master_key: <<"
    end
  end

  describe "an unavailable vault" do
    test "returns the canonical atom instead of exiting the caller" do
      {:ok, vault_id} = InMemory.encrypt("my-secret", "test")
      :ok = stop_supervised(InMemory)

      assert InMemory.encrypt("my-secret", "test") == {:error, :vault_unavailable}
      assert InMemory.decrypt(vault_id) == {:error, :vault_unavailable}
      assert InMemory.delete(vault_id) == {:error, :vault_unavailable}
      assert InMemory.exists?(vault_id) == false
      assert InMemory.list_entries() == []

      assert SigilGuard.Vault.decrypt(vault_id, InMemory) == {:error, :vault_unavailable}
    end

    test "input validation still answers without the process" do
      :ok = stop_supervised(InMemory)

      assert InMemory.encrypt(:not_binary, "test") == {:error, :invalid_plaintext}
      assert InMemory.encrypt("secret", <<255>>) == {:error, :invalid_description}
    end
  end

  describe "concurrent callers" do
    test "need no caller-side serialization" do
      results =
        1..64
        |> Task.async_stream(
          fn n ->
            plaintext = "secret-#{n}"
            {:ok, vault_id} = InMemory.encrypt(plaintext, "entry #{n}")
            true = InMemory.exists?(vault_id)
            {:ok, ^plaintext} = InMemory.decrypt(vault_id)
            if rem(n, 2) == 0, do: :ok = InMemory.delete(vault_id)
            {n, vault_id}
          end,
          max_concurrency: 16,
          ordered: false
        )
        |> Enum.map(fn {:ok, result} -> result end)

      ids = Enum.map(results, &elem(&1, 1))

      assert length(Enum.uniq(ids)) == 64

      for {n, vault_id} <- results do
        assert InMemory.exists?(vault_id) == (rem(n, 2) == 1)
      end

      assert length(InMemory.list_entries()) == 32
    end

    test "exists?/1 reads without changing the entry" do
      {:ok, vault_id} = InMemory.encrypt("my-secret", "test")
      before = table_dump()

      for _ <- 1..5, do: assert(InMemory.exists?(vault_id))

      assert table_dump() == before
      assert InMemory.list_entries() == [{vault_id, "test"}]
    end
  end

  describe "no leakage" do
    @plaintext "vault-plaintext-7c1f9a"

    test "errors, telemetry and logs carry neither plaintext nor key material", ctx do
      handler = "vault-leak-#{System.unique_integer()}"
      parent = self()

      :telemetry.attach_many(
        handler,
        SigilGuard.Telemetry.events(),
        fn event, measurements, metadata, _ ->
          send(parent, {:event, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, vault_id} = InMemory.encrypt(@plaintext, "api key")
          {:ok, @plaintext} = InMemory.decrypt(vault_id)
          {:error, :not_found} = InMemory.decrypt("vault_missing")

          :sys.replace_state(InMemory, fn state ->
            [{^vault_id, entry}] = :ets.lookup(state.table, vault_id)
            :ets.insert(state.table, {vault_id, %{entry | tag: :crypto.strong_rand_bytes(16)}})
            state
          end)

          send(parent, {:failure, InMemory.decrypt(vault_id)})
        end)

      assert_received {:failure, {:error, :decryption_failed}}
      refute_received {:event, _, _, _}

      key_b64 = Base.encode64(ctx.master_key)

      for text <- [log, inspect(:sys.get_status(InMemory), limit: :infinity)] do
        refute text =~ @plaintext
        refute text =~ key_b64
        refute text =~ inspect(ctx.master_key, limit: :infinity)
      end
    end

    test "an audit event that references a vault entry exports no vault content" do
      {:ok, vault_id} = InMemory.encrypt(@plaintext, "api key")
      chain_key = :crypto.hash(:sha256, "vault export chain key")

      event =
        "vault.read"
        |> SigilGuard.Audit.new_event("did:web:agent", "decrypt", "ok", %{"vault_ref" => vault_id})
        |> SigilGuard.Audit.sign_event(chain_key)

      attributes =
        SigilGuard.Telemetry.otel_attributes(
          [:sigil_guard, :audit, :log],
          %{},
          Map.from_struct(event),
          include_high_cardinality: true
        )

      cloud_event = SigilGuard.Audit.CloudEvents.project(event, source: "urn:example:host")
      chain_bytes = SigilGuard.Audit.canonical_bytes(event)
      exported = inspect({chain_bytes, cloud_event, attributes}, limit: :infinity)

      refute exported =~ @plaintext
    end
  end

  describe "key rotation guidance for durable backends" do
    alias SigilGuard.TestVersionedVault, as: Versioned

    setup do
      start_supervised!(Versioned)
      :ok
    end

    test "old entries stay readable after rotation and converge on read" do
      {:ok, old} = Versioned.encrypt("first", "entry")
      assert Versioned.rotate() == 2
      {:ok, new} = Versioned.encrypt("second", "entry")

      assert Versioned.versions_in_use() == [1, 2]
      assert Versioned.decrypt(new) == {:ok, "second"}

      # Reading under the old version re-encrypts under the current one.
      assert Versioned.decrypt(old) == {:ok, "first"}
      assert Versioned.versions_in_use() == [2]
      assert Versioned.decrypt(old) == {:ok, "first"}
    end

    test "a key version is retired only when no entry references it" do
      {:ok, old} = Versioned.encrypt("first", "entry")
      Versioned.rotate()

      assert Versioned.retire(1) == {:error, :key_in_use}
      assert Versioned.retire(2) == {:error, :key_in_use}
      assert Versioned.retire(9) == {:error, :unknown_key_version}

      assert Versioned.decrypt(old) == {:ok, "first"}
      assert Versioned.retire(1) == :ok
      assert Versioned.decrypt(old) == {:ok, "first"}
    end

    test "destroying a referenced version erases those entries and no others" do
      {:ok, old} = Versioned.encrypt("first", "entry")
      Versioned.rotate()
      {:ok, new} = Versioned.encrypt("second", "entry")

      :ok = Versioned.destroy(1)

      assert Versioned.decrypt(old) == {:error, :decryption_failed}
      assert Versioned.exists?(old)
      assert Versioned.decrypt(new) == {:ok, "second"}
      assert SigilGuard.Vault.decrypt(new, Versioned) == {:ok, "second"}
    end
  end

  describe "SigilGuard.Vault facade" do
    test "encrypt/3 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("test", "desc", InMemory)

      assert InMemory.decrypt(vault_id) == {:ok, "test"}
    end

    test "decrypt/2 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("facade_test", "desc", InMemory)
      {:ok, plaintext} = SigilGuard.Vault.decrypt(vault_id, InMemory)

      assert plaintext == "facade_test"
    end

    test "exists?/2 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("test", "desc", InMemory)

      assert SigilGuard.Vault.exists?(vault_id, InMemory)
      refute SigilGuard.Vault.exists?("vault_nope", InMemory)
    end
  end

  defp assert_start_link_error(reason, opts \\ []) do
    trap_exit? = Process.flag(:trap_exit, true)

    try do
      assert {:error, ^reason} = InMemory.start_link(opts)
      drain_start_link_exit(reason)
      refute Process.whereis(InMemory)
    after
      Process.flag(:trap_exit, trap_exit?)
    end
  end

  defp drain_start_link_exit(reason) do
    receive do
      {:EXIT, _, ^reason} -> :ok
    after
      100 -> :ok
    end
  end

  # The table is private, so read it from inside the vault process.
  defp table_dump do
    me = self()

    :sys.replace_state(InMemory, fn state ->
      send(me, {:dump, Enum.sort(:ets.tab2list(state.table))})
      state
    end)

    receive do
      {:dump, rows} -> rows
    after
      1_000 -> flunk("vault did not answer")
    end
  end
end

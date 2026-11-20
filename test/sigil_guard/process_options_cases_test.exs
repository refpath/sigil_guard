defmodule SigilGuard.ProcessOptionsCasesTest do
  @moduledoc false

  # The tests change the application environment the vault reads.
  use ExUnit.Case, async: false

  alias SigilGuard.Signer.Ed25519
  alias SigilGuard.Telemetry
  alias SigilGuard.Vault.InMemory

  test "an unknown signer start option is refused before the agent starts" do
    assert Ed25519.start_link(private_key: :binary.copy(<<7>>, 32), key_id: "extra") ==
             {:error, :invalid_options}

    assert Process.whereis(Ed25519) == nil
  end

  test "an unknown vault start option is refused before the vault starts" do
    Process.flag(:trap_exit, true)

    assert InMemory.start_link(master_key: :crypto.hash(:sha256, "k"), ttl: 5) ==
             {:error, :invalid_options}

    assert Process.whereis(InMemory) == nil
  end

  test "start_link/0 takes the master key from the application environment" do
    Process.flag(:trap_exit, true)
    previous = Application.get_env(:sigil_guard, :vault_master_key)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:sigil_guard, :vault_master_key, previous),
        else: Application.delete_env(:sigil_guard, :vault_master_key)
    end)

    Application.put_env(:sigil_guard, :vault_master_key, "not base64 !!")
    assert InMemory.start_link() == {:error, {:invalid_master_key, :invalid_base64}}

    Application.put_env(
      :sigil_guard,
      :vault_master_key,
      Base.encode64(:crypto.hash(:sha256, "configured"))
    )

    assert {:ok, pid} = InMemory.start_link()
    assert :sys.get_state(pid).master_key == :crypto.hash(:sha256, "configured")
    assert {:ok, id} = InMemory.encrypt("secret", "configured key")
    assert InMemory.decrypt(id) == {:ok, "secret"}
    GenServer.stop(pid)
  end

  test "attach_otel_forwarder/2 forwards policy and gate events without actor or hash attributes" do
    parent = self()
    handler_id = "sigil-otel-default-test-#{System.unique_integer()}"

    assert :ok =
             Telemetry.attach_otel_forwarder(handler_id, fn event, _, _, attributes ->
               send(parent, {:forwarded, event, attributes})
             end)

    on_exit(fn -> Telemetry.detach(handler_id) end)

    Telemetry.emit([:sigil_guard, :policy, :decision], %{}, %{
      actor: "did:web:alice",
      action: "cell.move",
      content_hash: String.duplicate("a", 64)
    })

    Telemetry.emit([:sigil_guard, :runtime, :gate], %{}, %{
      verdict: :allowed,
      content_hash: String.duplicate("b", 64)
    })

    assert_receive {:forwarded, [:sigil_guard, :policy, :decision], policy_attributes}

    assert policy_attributes == %{
             "sigilguard.action" => "cell.move",
             "sigilguard.component" => "policy",
             "sigilguard.event" => "sigil_guard.policy.decision",
             "sigilguard.operation" => "decision"
           }

    assert_receive {:forwarded, [:sigil_guard, :runtime, :gate], gate_attributes}

    assert gate_attributes == %{
             "sigilguard.component" => "runtime",
             "sigilguard.event" => "sigil_guard.runtime.gate",
             "sigilguard.operation" => "gate",
             "sigilguard.verdict" => "allowed"
           }
  end
end

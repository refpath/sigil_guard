Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Primitives do
  @moduledoc "Benchmarks of canonical encoding, hashing, identity, vault, replay and telemetry."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Attestation
  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Crypto
  alias SigilGuard.Identity
  alias SigilGuard.ReplayStore
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Telemetry
  alias SigilGuard.Vault

  @spiffe "spiffe://prod.example.org/agents/release-bot"
  # The example identifier of the did:key specification.
  @did "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  @gate_event [:sigil_guard, :runtime, :gate]
  @field_hash_key :crypto.hash(:sha256, "sigil_guard_bench_field_hash_key")

  @impl SigilGuard.Bench
  def id, do: "primitives"

  @impl SigilGuard.Bench
  def title, do: "Primitive Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    The building blocks the decision paths call: RFC 8785 canonical encoding
    of a statement, strict JSON decoding, SHA-256 and constant-time
    comparison, identifier syntax checks, reads from the in-memory vault, the
    replay store's rejection of a seen nonce, and the projection of a gate
    event into OpenTelemetry attributes.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    %{}
    |> Map.merge(canonical())
    |> Map.merge(hashing())
    |> Map.merge(identity())
    |> Map.merge(state())
    |> Map.merge(telemetry())
  end

  defp statement do
    {:ok, statement} =
      Attestation.from_decision(Fixtures.allow_decision(), Fixtures.attestation_context(),
        payload: Fixtures.request(),
        now: Fixtures.now(),
        nonce: "bench-attestation-nonce"
      )

    statement
  end

  defp canonical do
    statement = statement()
    {:ok, bytes} = JCS.encode(statement)

    %{
      "BM.27 jcs encode statement" => fn -> JCS.encode(statement) end,
      "BM.27 canonical json decode statement" => fn -> SigilGuard.Canonical.JSON.decode(bytes) end
    }
  end

  defp hashing do
    text = Fixtures.corpus!("clean_1k.txt")
    left = Crypto.sha256_hex(text)
    right = Crypto.sha256_hex(text)

    %{
      "BM.28 sha256 hex 1k" => fn -> Crypto.sha256_hex(text) end,
      "BM.28 secure compare 64 bytes" => fn -> Crypto.secure_compare(left, right) end
    }
  end

  defp identity do
    %{
      "BM.29 identity spiffe id check" => fn -> Identity.spiffe_id?(@spiffe) end,
      "BM.29 identity did:key public key" => fn -> Identity.did_key_public_key(@did) end
    }
  end

  defp state do
    start_vault!()
    {:ok, vault_id} = Vault.encrypt("benchmark secret value", "bench", Vault.InMemory)
    # Seeds the nonce; the fixture check may have done so already.
    ReplayStore.check_and_put("bench-actor", "bench-nonce", 600_000)

    # Encrypting is not timed: every call adds an entry, and the store would
    # grow for as long as the measurement runs.
    %{
      "BM.30 vault decrypt" => fn -> Vault.decrypt(vault_id, Vault.InMemory) end,
      "BM.30 vault exists" => fn -> Vault.exists?(vault_id, Vault.InMemory) end,
      # A fresh nonce per call would fill the table within the measured time,
      # so the scenario times the rejection of a nonce the store has seen.
      "BM.30 replay store detect replay" => fn ->
        ReplayStore.check_and_put("bench-actor", "bench-nonce", 600_000)
      end
    }
  end

  defp start_vault! do
    case Vault.InMemory.start_link([]) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
    end
  end

  defp gate_metadata do
    decision =
      Gate.evaluate(
        Fixtures.corpus!("clean_1k.txt"),
        [
          phase: :tool_result,
          origin: :tool,
          sink: :model,
          action: "read_docs",
          actor: Fixtures.actor(),
          sandbox_id: "sandbox-1"
        ],
        decision_id: "bench-decision-1"
      )

    decision.audit_metadata
  end

  defp telemetry do
    metadata = gate_metadata()
    opts = [include_high_cardinality: true, field_hash_key: @field_hash_key]

    %{
      "BM.31 telemetry otel attributes" => fn ->
        Telemetry.otel_attributes(@gate_event, %{}, metadata)
      end,
      "BM.31 telemetry otel attributes high cardinality" => fn ->
        Telemetry.otel_attributes(@gate_event, %{}, metadata, opts)
      end
    }
  end

  @impl SigilGuard.Bench
  def preconditions! do
    statement = statement()
    {:ok, bytes} = JCS.encode(statement)

    Bench.expect!(
      SigilGuard.Canonical.JSON.decode(bytes) == {:ok, statement},
      "BM.27 statement does not round-trip"
    )

    Bench.expect!(Identity.spiffe_id?(@spiffe), "BM.29 SPIFFE id is refused")
    Bench.expect!(match?({:ok, _}, Identity.did_key_public_key(@did)), "BM.29 did:key is refused")

    start_vault!()
    {:ok, vault_id} = Vault.encrypt("benchmark secret value", "bench", Vault.InMemory)

    Bench.expect!(
      Vault.decrypt(vault_id, Vault.InMemory) == {:ok, "benchmark secret value"},
      "BM.30 vault does not return the value"
    )

    ReplayStore.check_and_put("bench-actor", "bench-nonce", 600_000)

    Bench.expect!(
      ReplayStore.check_and_put("bench-actor", "bench-nonce", 600_000) ==
        {:error, :replay_detected},
      "BM.30 replay is not detected"
    )

    low = Telemetry.otel_attributes(@gate_event, %{}, gate_metadata())

    high =
      Telemetry.otel_attributes(@gate_event, %{}, gate_metadata(),
        include_high_cardinality: true,
        field_hash_key: @field_hash_key
      )

    Bench.expect!(low["sigilguard.verdict"] == "allowed", "BM.31 verdict attribute is missing")
    Bench.expect!(high["sigilguard.decision.id"] == "bench-decision-1", "BM.31 no decision id")

    Bench.expect!(
      String.starts_with?(high["sigilguard.actor.hash"], "fh1:"),
      "BM.31 actor is not hashed"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Primitives)

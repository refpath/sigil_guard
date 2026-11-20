Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Audit do
  @moduledoc "Benchmarks of the audit chain, checkpoints, proofs and exports."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Bench

  @chain_start ~U[2026-07-03 12:00:00.000Z]
  @chain_length 10_000
  @short_length 1_000

  @impl SigilGuard.Bench
  def id, do: "audit"

  @impl SigilGuard.Bench
  def title, do: "Audit Evidence Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    Every decision can append one HMAC-chained audit event, and a host
    periodically checkpoints the chain into a Merkle root and exports
    evidence. The suite appends to a chain of 10,000 events, creates a
    checkpoint over it, builds and verifies inclusion and consistency proofs,
    verifies a chain of 1,000 events, and exports it. Event ids and
    timestamps follow from the event index, so the chain has the same bytes
    on every run.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    key = key()
    chain = chain()
    short = Enum.take(chain, @short_length)
    event = event(@chain_length + 1, "tail")
    {:ok, checkpoint} = Checkpoint.create(chain, chain_id: "bench-chain")
    {:ok, proof} = Proof.inclusion(chain, @chain_length - 1)
    {:ok, consistency} = Proof.consistency(chain, div(@chain_length, 2))

    {:ok, older} =
      Checkpoint.create(Enum.take(chain, div(@chain_length, 2)), chain_id: "bench-chain")

    last = List.last(chain)

    %{
      "BM.07 audit append onto 10k chain" => fn -> Audit.sign_event(event, key, last.hmac) end,
      "BM.07 audit checkpoint create 10k" => fn ->
        Checkpoint.create(chain, chain_id: "bench-chain")
      end,
      "BM.07 audit inclusion verify 10k" => fn ->
        Proof.verify_inclusion(proof, last.hmac, checkpoint["merkle_root"])
      end,
      "BM.26 audit verify chain 1k" => fn -> Audit.verify_chain(short, key) end,
      "BM.26 audit inclusion proof 10k" => fn -> Proof.inclusion(chain, @chain_length - 1) end,
      "BM.26 audit consistency proof 10k" => fn ->
        Proof.consistency(chain, div(@chain_length, 2))
      end,
      "BM.26 audit consistency verify 10k" => fn ->
        Proof.verify_consistency(consistency, older["merkle_root"], checkpoint["merkle_root"])
      end,
      "BM.26 audit export create 1k" => fn -> Export.create(short, inclusion_proofs: :all) end
    }
  end

  @doc """
  Build the benchmark chain.

  `Audit.new_event/4` draws a random id and reads the clock, so the fixture
  replaces both with values that follow from the index.
  """
  @spec chain(pos_integer()) :: [Audit.t()]
  def chain(length \\ @chain_length) do
    1..length
    |> Enum.map(&event(&1, "action_#{&1}"))
    |> Audit.build_chain(key())
  end

  defp event(index, action) do
    event = Audit.new_event("bench", "actor", action, "ok")

    %{
      event
      | id: Base.encode16(<<index::128>>, case: :lower),
        timestamp: DateTime.to_iso8601(DateTime.add(@chain_start, index, :millisecond))
    }
  end

  defp key, do: :crypto.hash(:sha256, "sigil_guard_bench_audit_key")

  @impl SigilGuard.Bench
  def preconditions! do
    chain = chain(@short_length)

    Bench.expect!(Audit.verify_chain(chain, key()) == :ok, "BM.26 chain does not verify")
    Bench.expect!(chain == chain(@short_length), "BM.07 chain differs between builds")

    {:ok, checkpoint} = Checkpoint.create(chain, chain_id: "bench-chain")
    {:ok, proof} = Proof.inclusion(chain, @short_length - 1)
    included = Proof.verify_inclusion(proof, List.last(chain).hmac, checkpoint["merkle_root"])

    Bench.expect!(included == :ok, "BM.07 inclusion proof: #{inspect(included)}")

    half = div(@short_length, 2)
    {:ok, older} = Checkpoint.create(Enum.take(chain, half), chain_id: "bench-chain")
    {:ok, consistency} = Proof.consistency(chain, half)

    consistent =
      Proof.verify_consistency(consistency, older["merkle_root"], checkpoint["merkle_root"])

    Bench.expect!(consistent == :ok, "BM.26 consistency proof: #{inspect(consistent)}")

    Bench.expect!(
      match?({:ok, _}, Export.create(chain, inclusion_proofs: :all)),
      "BM.26 export fails"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Audit)

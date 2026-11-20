defmodule SigilGuard.AuditCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Audit.Witness
  alias SigilGuard.AuditProofFixture, as: Fixture
  alias SigilGuard.Canonical.JCS

  @query_key :crypto.hash(:sha256, "audit query test key")
  @generated_at "2026-01-01T00:00:00.000Z"

  defp query_events do
    0..4
    |> Enum.map(fn i ->
      %{
        Audit.new_event(if(rem(i, 2) == 0, do: "gate", else: "scan"), "alice", "act#{i}", "ok")
        | id: "id#{i}",
          timestamp: "2026-07-02T12:00:0#{i}.000Z"
      }
    end)
    |> Audit.build_chain(@query_key)
  end

  defp build_signed_chain(count) do
    1..count
    |> Enum.map(&Audit.new_event("test", "alice", "action#{&1}", "ok"))
    |> Audit.build_chain(:crypto.hash(:sha256, "audit checkpoint test key"))
  end

  test "query/1 returns the whole chain and a time window may be open at either end" do
    events = query_events()

    assert Audit.query(events) == {:ok, events}

    assert {:ok, until} = Audit.query(events, to_time: "2026-07-02T12:00:01.000Z")
    assert Enum.map(until, & &1.id) == ["id0", "id1"]

    assert {:ok, since} = Audit.query(events, from_time: "2026-07-02T12:00:03.000Z")
    assert Enum.map(since, & &1.id) == ["id3", "id4"]
  end

  test "verifies a continuation checkpoint only against its own predecessor and segment" do
    [first, second, third] = build_signed_chain(3)

    {:ok, checkpoint} =
      Checkpoint.create([second, third], prev_hmac: first.hmac, generated_at: @generated_at)

    assert {:ok, %{status: :unsigned}} = Checkpoint.verify(checkpoint, [second, third])

    assert Checkpoint.verify(%{checkpoint | "prev_hmac" => String.duplicate("0", 64)}, [
             second,
             third
           ]) ==
             {:error, :broken_chain}

    assert Checkpoint.verify(checkpoint, [first, second]) == {:error, :broken_chain}

    assert Checkpoint.verify(Map.put(checkpoint, "prev_hmac", 7), [second, third]) ==
             {:error, :invalid_prev_hmac}
  end

  test "an empty continuation segment keeps its predecessor anchor" do
    [first] = build_signed_chain(1)

    assert {:ok, checkpoint} =
             Checkpoint.create([], prev_hmac: first.hmac, generated_at: @generated_at)

    assert checkpoint["event_count"] == 0
    assert checkpoint["prev_hmac"] == first.hmac
    assert {:ok, _} = Checkpoint.verify(checkpoint, [])
    assert Checkpoint.verify(checkpoint, [first]) == {:error, :broken_chain}
  end

  test "an unsigned event breaks the chain at any position" do
    [first, second] = build_signed_chain(2)
    unsigned = Audit.new_event("test", "alice", "action", "ok")

    assert Checkpoint.create([unsigned]) == {:error, :broken_chain}
    assert Checkpoint.create([%{first | hmac: ""}]) == {:error, :broken_chain}
    assert Checkpoint.create([first, %{second | hmac: nil}]) == {:error, :broken_chain}
  end

  test "a previous statement whose root or subject digest is not a string fails :invalid_proof" do
    {:ok, payload} = JCS.encode(Fixture.statement())
    {:ok, envelope} = Envelope.sign(payload, Fixture.signer())
    events = Fixture.signed_events()
    {:ok, cp3} = Checkpoint.create(Enum.take(events, 3), generated_at: "2026-07-02T12:00:03.000Z")
    {:ok, statement3} = Checkpoint.to_statement(cp3)
    {:ok, proof} = Proof.consistency(events, 3)

    for statement <- [
          put_in(statement3, ["predicate", "merkle_root"], 123),
          put_in(statement3, ["predicate", "merkle_root"], nil),
          put_in(statement3, ["subject", Access.at(0), "digest", "sha256"], ["ab"])
        ] do
      previous = %{statement: statement, consistency_proof: proof}

      assert Witness.cosign(envelope, Fixture.signer(), keyid: "witness-1", previous: previous) ==
               {:error, :invalid_proof}
    end
  end

  test "an anchor option map keeps the known keys and drops the rest" do
    events = build_signed_chain(3)

    assert {:ok, export} =
             Export.create(events,
               generated_at: @generated_at,
               anchor: %{
                 "storage" => "s3-object-lock",
                 "anchored_at" => "2026-01-01T00:00:05.000Z",
                 "bucket" => "ignored",
                 retention: 1
               }
             )

    assert export["anchor"]["storage"] == "s3-object-lock"
    assert export["anchor"]["anchored_at"] == "2026-01-01T00:00:05.000Z"
    refute Map.has_key?(export["anchor"], "bucket")
    refute Map.has_key?(export["anchor"], "retention")
    assert {:ok, _} = Export.verify(export, events)
  end
end

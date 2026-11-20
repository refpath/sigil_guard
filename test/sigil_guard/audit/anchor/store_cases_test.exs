defmodule SigilGuard.Audit.Anchor.StoreCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Checkpoint

  defmodule MemoryStore do
    @behaviour Store
    @impl Store
    def put(anchor, _),
      do: {:ok, %{anchor_digest: Anchor.digest(anchor), record: anchor, worm: true}}

    @impl Store
    def fetch(%{record: record}, _), do: {:ok, record}
  end

  defmodule DigestlessReceiptStore do
    @behaviour Store
    @impl Store
    def put(_, _), do: {:ok, %{"note" => "accepted", "worm" => true}}
    @impl Store
    def fetch(_, _), do: {:error, :not_found}
  end

  defp checkpoint do
    {:ok, checkpoint} = Checkpoint.create([], generated_at: "2026-01-01T00:00:00.000Z")
    checkpoint
  end

  defp anchor do
    Anchor.create(checkpoint(),
      anchored_at: "2026-01-01T00:00:05.000Z",
      storage: :memory,
      uri: "memory://anchors/1"
    )
  end

  test "a fetched record that is an anchor of the wrong shape keeps its reason" do
    for {record, reason} <- [
          {Map.delete(anchor(), "anchored_at"), :missing_anchored_at},
          {Map.put(anchor(), "worm", "yes"), :invalid_worm},
          {Map.put(anchor(), "metadata", []), :invalid_metadata},
          {Map.put(anchor(), "version", 2), :invalid_version}
        ] do
      assert Store.fetch(MemoryStore, %{record: record}) == {:error, reason}
      assert Store.verify(MemoryStore, %{record: record}, checkpoint()) == {:error, reason}
    end
  end

  test "a receipt without a digest reports no anchor digest" do
    event = [:sigil_guard, :audit, :anchor_store, :put, :stop]
    handler = "anchor-store-digestless-#{System.unique_integer([:positive])}"
    parent = self()
    expected_store = inspect(DigestlessReceiptStore)

    :telemetry.attach(
      handler,
      event,
      fn ^event, _, metadata, _ ->
        if metadata.anchor_store == expected_store, do: send(parent, {:anchor_store, metadata})
      end,
      nil
    )

    try do
      assert Store.put(DigestlessReceiptStore, anchor(), require_worm: true) ==
               {:ok, %{"note" => "accepted", "worm" => true}}

      assert_receive {:anchor_store, metadata}
      assert metadata.outcome == :ok
      refute Map.has_key?(metadata, :anchor_digest)
      refute Map.has_key?(metadata, :anchor_storage)
    after
      :telemetry.detach(handler)
    end
  end
end

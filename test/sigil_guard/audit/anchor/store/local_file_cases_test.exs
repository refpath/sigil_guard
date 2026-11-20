defmodule SigilGuard.Audit.Anchor.Store.LocalFileCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.LocalFile
  alias SigilGuard.Audit.Checkpoint

  defp anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "anchor-store-#{&1}", "ok"))
      |> Audit.build_chain(:crypto.hash(:sha256, "audit anchor store test key"))

    {:ok, checkpoint} =
      Checkpoint.create(events, chain_id: "chain-a", generated_at: "2026-01-01T00:00:00.000Z")

    anchor =
      Anchor.create(checkpoint,
        anchored_at: "2026-01-01T00:00:05.000Z",
        storage: :local_file,
        uri: "file://anchors.jsonl"
      )

    {checkpoint, anchor}
  end

  defp tmp_path, do: Path.join(SigilGuard.CaseFixtures.Tmp.dir("local_file"), "anchors.jsonl")

  test "a receipt may carry the digest only, or only in its uri fragment" do
    {_, anchor} = anchor_fixture()
    path = tmp_path()
    digest = Anchor.digest(anchor)
    assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)

    assert {:ok, ^anchor} = Store.fetch(LocalFile, %{"anchor_digest" => digest}, path: path)
    assert Store.fetch(LocalFile, %{"anchor_digest" => digest}) == {:error, :missing_path}

    assert {:ok, ^anchor} = Store.fetch(LocalFile, Map.delete(receipt, "anchor_digest"))

    assert Store.fetch(LocalFile, %{"uri" => "file://#{path}#not-a-digest"}) ==
             {:error, :missing_digest}

    assert {:ok, ^anchor} =
             Store.fetch(LocalFile, %{
               "anchor_digest" => digest,
               "uri" => "file://#{path}#section-2"
             })
  end

  test "a reference that is neither a digest nor a receipt has no digest" do
    {_, anchor} = anchor_fixture()
    digest = Anchor.digest(anchor)

    for ref <- [123, nil, [digest], {:digest, digest}] do
      assert Store.fetch(LocalFile, ref, path: tmp_path()) == {:error, :missing_digest}
    end
  end

  test "a log path that is a directory returns the file error" do
    {_, anchor} = anchor_fixture()
    directory = Path.dirname(tmp_path())

    assert Store.fetch(LocalFile, Anchor.digest(anchor), path: directory) == {:error, :eisdir}
  end

  test "an unterminated final record for another digest is not found" do
    {_, anchor} = anchor_fixture()
    path = tmp_path()
    File.write!(path, Jason.encode!(%{"anchor_digest" => String.duplicate("0", 64)}))

    assert Store.fetch(LocalFile, Anchor.digest(anchor), path: path) == {:error, :not_found}
  end

  test "a log object without an anchor digest stops the search" do
    {_, anchor} = anchor_fixture()
    source = tmp_path()
    assert {:ok, _} = Store.put(LocalFile, anchor, path: source)
    entry = File.read!(source)

    for line <- [
          "{}",
          ~s({"record":{"kind":"sigil_guard.audit.anchor"}}),
          ~s({"anchor_digest ":"x"})
        ] do
      path = tmp_path()
      File.write!(path, [line, ?\n, entry])

      assert Store.fetch(LocalFile, Anchor.digest(anchor), path: path) == {:error, :invalid_log}
    end
  end
end

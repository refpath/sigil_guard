defmodule Mix.Tasks.SigilGuard.MigrationGateCasesTest do
  @moduledoc false

  # File.cd!/2 changes the working directory of the whole VM.
  use ExUnit.Case, async: false

  import SigilGuard.CaseFixtures.Tmp, only: [fixture_root: 1]

  alias Mix.Tasks.SigilGuard.MigrationGate

  test "a guide that lacks a mapping or has a broken link raises with every finding" do
    root =
      fixture_root(%{
        "MIGRATING-1.0.md" => "# Migrating\n\nSee [the old guide](docs/gone.md).\n"
      })

    error =
      assert_raise Mix.Error, fn ->
        File.cd!(root, fn -> MigrationGate.run([]) end)
      end

    lines = String.split(error.message, "\n")
    assert hd(lines) == "migration gate failed:"
    assert "MIGRATING-1.0.md: missing_mapping: module SigilGuard.Registry is not mapped" in lines
    assert "MIGRATING-1.0.md: missing_mapping: config :backend is not mapped" in lines

    assert List.last(lines) ==
             "MIGRATING-1.0.md:3: invalid_link: missing link target: docs/gone.md"
  end

  test "an absent guide raises" do
    root = fixture_root(%{})

    assert_raise Mix.Error,
                 ~r/\Amigration gate failed:\nMIGRATING-1\.0\.md: missing_mapping: /,
                 fn ->
                   File.cd!(root, fn -> MigrationGate.run([]) end)
                 end
  end
end

defmodule Mix.Tasks.SigilGuard.DocsLintCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import SigilGuard.CaseFixtures.Tmp, only: [fixture_root: 1]

  alias Mix.Tasks.SigilGuard.DocsLint

  defp front_matter(id), do: "---\nid: \"#{id}\"\n---\n\n# #{id}\n"

  test "formats a finding that has no line" do
    root =
      fixture_root(%{
        "README.md" => "Public docs\n",
        "docs/specs/SP.07-example.md" => front_matter("SP.07"),
        "docs/tasks/sigil-tasks.md" => "# Tasks\n"
      })

    error =
      assert_raise Mix.Error, fn ->
        File.cd!(root, fn -> DocsLint.run([]) end)
      end

    assert error.message ==
             "docs lint failed:\ndocs/tasks/sigil-tasks.md: spec_drift: SP.07 has no task reference"
  end

  test "skips a directory whose name ends in .md" do
    root =
      fixture_root(%{
        "README.md" => "Public docs\n",
        "docs/specs/SP.01-example.md" => front_matter("SP.01"),
        "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n",
        "docs/archive.md/note.txt" => "not markdown\n"
      })

    assert File.dir?(Path.join(root, "docs/archive.md"))
    assert DocsLint.lint(root: root) == :ok
  end
end

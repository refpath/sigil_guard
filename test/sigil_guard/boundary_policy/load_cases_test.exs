defmodule SigilGuard.BoundaryPolicy.LoadCasesTest do
  @moduledoc false

  # One test removes read permission from a file other tests read.
  use ExUnit.Case, async: false

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile

  @policy "version 3\n\n[rules]\ndefault allow\n"

  setup do
    dir =
      Path.join(
        System.tmp_dir!(),
        "sigil_guard_policy_load_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    File.write!(Path.join(dir, "custom-policy"), @policy)

    on_exit(fn ->
      File.chmod(Path.join(dir, "custom-policy"), 0o644)
      File.rm_rf!(dir)
    end)

    {:ok, dir: dir}
  end

  test "a single candidate may be given as a string", %{dir: dir} do
    assert {:ok, policy} = PolicyFile.load(dir, candidates: "custom-policy")
    assert policy.default == :allow
    assert policy.digest == PolicyFile.digest(@policy)
    assert PolicyFile.load(dir, candidates: "missing-policy") == {:error, :not_found}
  end

  test "a candidate set or legacy mapping of another shape is refused before the filesystem is read",
       %{dir: dir} do
    for opts <- [
          [candidates: :custom_policy],
          [candidates: %{0 => "custom-policy"}],
          [candidates: ["custom-policy"], legacy_replacements: %{"a" => "b"}],
          [candidates: ["custom-policy"], legacy_replacements: :none]
        ] do
      assert PolicyFile.load(dir, opts) == {:error, :invalid_options}
    end
  end

  @tag :posix_permissions
  test "a policy file that exists and cannot be read is not reported as absent", %{dir: dir} do
    File.chmod!(Path.join(dir, "custom-policy"), 0o000)

    assert PolicyFile.load(dir, candidates: ["custom-policy"]) == {:error, :unreadable_policy}
    assert PolicyFile.load(dir, candidates: ["no-such-policy"]) == {:error, :not_found}
  end
end

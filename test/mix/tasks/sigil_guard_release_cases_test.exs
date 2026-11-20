defmodule Mix.Tasks.SigilGuard.ReleaseCasesTest do
  @moduledoc false

  # The tests set and restore process-wide environment variables.
  use ExUnit.Case, async: false

  alias Mix.Tasks.SigilGuard.ReleaseStatement
  alias Mix.Tasks.SigilGuard.VerifyReleaseRef

  setup do
    repository = SigilGuard.CaseFixtures.Tmp.dir("release_ref")
    git!(repository, ["init", "--quiet"])
    git!(repository, ["config", "user.email", "release-test@example.invalid"])
    git!(repository, ["config", "user.name", "Release Test"])
    git!(repository, ["config", "commit.gpgsign", "false"])
    File.write!(Path.join(repository, "release.txt"), "first\n")
    git!(repository, ["add", "release.txt"])
    git!(repository, ["commit", "--quiet", "-m", "first"])
    sha = git!(repository, ["rev-parse", "HEAD"])
    git!(repository, ["tag", "v1.0.0"])
    %{repository: repository, sha: sha}
  end

  defp git!(repository, arguments) do
    options = [
      stderr_to_stdout: true,
      env: [{"GIT_CONFIG_GLOBAL", "/dev/null"}, {"GIT_CONFIG_SYSTEM", "/dev/null"}]
    ]

    case System.cmd("git", ["-C", repository | arguments], options) do
      {output, 0} -> String.trim(output)
      {output, status} -> flunk("git failed with status #{status}: #{output}")
    end
  end

  test "a version that is not a string is refused" do
    directory = SigilGuard.CaseFixtures.Tmp.dir("release_statement")
    tarball = Path.join(directory, "pkg.tar")
    sbom = Path.join(directory, "pkg.spdx.json")
    File.write!(tarball, "tarball bytes")
    File.write!(sbom, "{}")

    for version <- [100, nil, :"1.0.0", ~c"1.0.0"] do
      assert ReleaseStatement.statement(tarball: tarball, sbom: sbom, version: version) ==
               {:error, {:invalid_option, :version}}
    end
  end

  test "an environment without a ref name is refused" do
    sha = String.duplicate("a", 40)

    for environment <- [
          %{},
          %{"GITHUB_REF_NAME" => ""},
          %{
            "GITHUB_REF" => "refs/tags/v1.0.0",
            "GITHUB_SHA" => sha,
            "GITHUB_REF_PROTECTED" => "true"
          }
        ] do
      assert VerifyReleaseRef.verify("1.0.0", environment) == {:error, :missing_ref_name}
    end
  end

  test "the tag-name preflight needs no repository" do
    assert VerifyReleaseRef.verify("1.0.0", %{"GITHUB_REF_NAME" => "v1.0.0"}) == :ok
  end

  test "arguments of the wrong type are refused", context do
    environment = %{"GITHUB_REF_NAME" => "v1.0.0"}

    assert VerifyReleaseRef.verify(100, environment, context.repository) ==
             {:error, :invalid_environment}

    assert VerifyReleaseRef.verify("1.0.0", [{"GITHUB_REF_NAME", "v1.0.0"}], context.repository) ==
             {:error, :invalid_environment}

    assert VerifyReleaseRef.verify("1.0.0", environment, nil) == {:error, :invalid_environment}
  end

  test "a version whose tag is not in the checkout cannot be resolved", context do
    environment = %{
      "GITHUB_REF" => "refs/tags/v1.0.1",
      "GITHUB_REF_NAME" => "v1.0.1",
      "GITHUB_REF_PROTECTED" => "true",
      "GITHUB_SHA" => context.sha
    }

    assert {:error, {:cannot_resolve, "refs/tags/v1.0.1", _}} =
             VerifyReleaseRef.verify("1.0.1", environment, context.repository)
  end

  test "run/1 refuses any argument" do
    assert_raise Mix.Error, ~r/does not accept arguments/, fn ->
      VerifyReleaseRef.run(["--tag", "v1.0.0"])
    end
  end

  test "run/1 checks the process environment against the project version" do
    names = ~w(GITHUB_REF GITHUB_REF_NAME GITHUB_SHA GITHUB_REF_PROTECTED)
    saved = Map.new(names, &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)

    Enum.each(names, &System.delete_env/1)
    version = Mix.Project.config()[:version]

    assert_raise Mix.Error, "release ref verification failed: :missing_ref_name", fn ->
      VerifyReleaseRef.run([])
    end

    System.put_env("GITHUB_REF_NAME", "main")

    assert_raise Mix.Error,
                 ~r/release ref verification failed: \{:unexpected_ref_name, "v#{Regex.escape(version)}", "main"\}/,
                 fn ->
                   VerifyReleaseRef.run([])
                 end

    System.put_env("GITHUB_REF_NAME", "v#{version}")

    output = ExUnit.CaptureIO.capture_io(fn -> assert VerifyReleaseRef.run([]) == :ok end)
    assert output =~ "Verified release ref v#{version}"
  end
end

defmodule Mix.Tasks.SigilGuard.SbomCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.SigilGuard.Sbom
  alias SigilGuard.CaseFixtures.Tmp

  @created_at "2026-06-30T12:00:00Z"
  @git_revision String.duplicate("a", 40)

  # A fixture project whose configuration the test supplies, so a test can
  # point :lockfile and :deps_path at files it wrote.
  defmodule ConfiguredProject do
    @spec project() :: keyword()
    def project, do: Process.get(__MODULE__)
  end

  defp with_config(deps, extra \\ [], fun) do
    Process.put(
      ConfiguredProject,
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [name: "sigil_guard_sbom_fixture", licenses: ["MIT"]],
        deps: deps
      ] ++ extra
    )

    with_project(ConfiguredProject, fun)
  end

  defp with_project(project, fun) do
    Mix.Project.push(project)

    try do
      fun.()
    after
      Mix.Project.pop()
    end
  end

  defp package_names(sbom), do: Enum.sort(Enum.map(sbom["packages"], & &1["name"]))

  defp depends_on(sbom) do
    for %{"relationshipType" => "DEPENDS_ON"} = relationship <- sbom["relationships"] do
      {relationship["spdxElementId"], relationship["relatedSpdxElement"]}
    end
    |> Enum.sort()
  end

  defp write_lock(body) do
    path = Path.join(Tmp.dir("lock"), "mix.lock")
    File.write!(path, body)
    path
  end

  defp deps_with_metadata(metadata) do
    deps = Tmp.dir("deps")
    File.mkdir_p!(Path.join(deps, "jason"))
    if metadata, do: File.write!(Path.join([deps, "jason", "hex_metadata.config"]), metadata)
    deps
  end

  describe "generate/1 dependency selection" do
    test "the :only option decides whether a declared dependency is a runtime dependency" do
      deps = [
        {:jason, "~> 1.4", override: true},
        {:telemetry, "~> 1.0", only: :prod},
        {:nimble_options, "~> 1.1", only: [:prod, :test]},
        {:credo, "~> 1.7", only: [:dev, :test]},
        {:dialyxir, "~> 1.4", only: "prod"}
      ]

      with_config(deps, fn ->
        sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)

        # An :only of an unexpected shape ("prod") is listed, with its own
        # dependencies, rather than left out of the document.
        assert package_names(sbom) == [
                 "dialyxir",
                 "erlex",
                 "jason",
                 "nimble_options",
                 "sigil_guard_sbom_fixture",
                 "telemetry"
               ]
      end)
    end

    test "rejects runtime dependency tuples of an unsupported shape" do
      for dependency <- [{:odd, "~> 1.0", [:not_keyword]}, {:odd, nil, []}, {:odd, 5}] do
        with_config([dependency], fn ->
          assert Sbom.verify_document(%{}) == {:error, {:unsupported_runtime_dependency, :odd}}
        end)
      end

      with_config([{:odd, nil, [only: :dev]}], fn ->
        assert Sbom.verify_document(%{}) == {:error, :invalid_spdx_version}
      end)
    end

    test "a transitive runtime dependency is a package and an edge from its parent" do
      with_config([{:plug, "~> 1.0"}, {:telemetry, "~> 1.0"}], fn ->
        sbom = Sbom.generate(created_at: @created_at)

        assert package_names(sbom) ==
                 ["mime", "plug", "plug_crypto", "sigil_guard_sbom_fixture", "telemetry"]

        assert depends_on(sbom) == [
                 {"SPDXRef-Package-plug", "SPDXRef-Package-mime"},
                 {"SPDXRef-Package-plug", "SPDXRef-Package-plug-crypto"},
                 {"SPDXRef-Package-plug", "SPDXRef-Package-telemetry"},
                 {"SPDXRef-Package-sigil-guard-sbom-fixture", "SPDXRef-Package-plug"},
                 {"SPDXRef-Package-sigil-guard-sbom-fixture", "SPDXRef-Package-telemetry"}
               ]

        assert :ok = Sbom.verify_document(sbom)

        transitive = %{
          "spdxElementId" => "SPDXRef-Package-plug",
          "relationshipType" => "DEPENDS_ON",
          "relatedSpdxElement" => "SPDXRef-Package-telemetry"
        }

        dropped = update_in(sbom["relationships"], &List.delete(&1, transitive))
        assert Sbom.verify_document(dropped) == {:error, :missing_dependency_relationship}

        reparented =
          update_in(sbom["relationships"], fn relationships ->
            Enum.map(relationships, fn
              ^transitive -> %{transitive | "spdxElementId" => "SPDXRef-Package-mime"}
              other -> other
            end)
          end)

        assert Sbom.verify_document(reparented) == {:error, :missing_dependency_relationship}
      end)
    end
  end

  describe "generate/1 lockfile and fetched metadata" do
    test "rejects a runtime dependency that the lock pins to git, direct or transitive" do
      direct =
        write_lock(
          ~s(%{\n  "jason": {:git, "https://example.invalid/jason.git", "#{@git_revision}", []},\n}\n)
        )

      with_config([{:jason, "~> 1.4"}], [lockfile: direct], fn ->
        assert Sbom.verify_document(%{}) ==
                 {:error, {:unsupported_runtime_dependency_lock, :jason}}

        assert_raise Mix.Error, ~r/unsupported_runtime_dependency_lock.*jason/, fn ->
          Sbom.generate(created_at: @created_at, git_revision: @git_revision)
        end
      end)

      plug =
        ~s("plug": {:hex, :plug, "1.20.4", "aa", [:mix], [{:mime, "~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}], "hexpm", "bb"})

      transitive =
        write_lock(
          ~s(%{\n  #{plug},\n  "mime": {:git, "https://example.invalid/mime.git", "#{@git_revision}", []},\n}\n)
        )

      with_config([{:plug, "~> 1.0"}], [lockfile: transitive], fn ->
        assert Sbom.verify_document(%{}) ==
                 {:error, {:unsupported_runtime_dependency_lock, :mime}}
      end)

      missing = write_lock(~s(%{\n  #{plug},\n}\n))

      with_config([{:plug, "~> 1.0"}], [lockfile: missing], fn ->
        assert Sbom.verify_document(%{}) == {:error, {:missing_runtime_dependency_lock, :mime}}
      end)
    end

    test "rejects fetched package metadata that is absent, differs from the lock, or names no licence" do
      for metadata <- [
            nil,
            ~s({<<"version">>,<<"9.9.9">>}.\n{<<"licenses">>,[<<"Apache-2.0">>]}.\n),
            ~s({<<"licenses">>,[<<"Apache-2.0">>]}.\n),
            ~s({<<"version">>,145}.\n{<<"licenses">>,[<<"Apache-2.0">>]}.\n),
            ~s({<<"version">>,<<"1.4.5">>}.\n),
            ~s({<<"version">>,<<"1.4.5">>}.\n{<<"licenses">>,[]}.\n),
            ~s({<<"version">>,<<"1.4.5">>}.\n{<<"licenses">>,[<<>>]}.\n)
          ] do
        lock =
          write_lock(
            ~s(%{\n  "jason": {:hex, :jason, "1.4.5", "aa", [:mix], [], "hexpm", "bb"},\n}\n)
          )

        with_config(
          [{:jason, "~> 1.4"}],
          [lockfile: lock, deps_path: deps_with_metadata(metadata)],
          fn ->
            assert Sbom.verify_document(%{}) ==
                     {:error, {:invalid_runtime_dependency_metadata, :jason}}

            assert_raise Mix.Error, ~r/invalid_runtime_dependency_metadata.*jason/, fn ->
              Sbom.generate(created_at: @created_at, git_revision: @git_revision)
            end
          end
        )
      end

      lock =
        write_lock(
          ~s(%{\n  "jason": {:hex, :jason, "1.4.5", "aa", [:mix], [], "hexpm", "bb"},\n}\n)
        )

      good = ~s({<<"version">>,<<"1.4.5">>}.\n{<<"licenses">>,[<<"Apache-2.0">>,<<"MIT">>]}.\n)

      with_config(
        [{:jason, "~> 1.4"}],
        [lockfile: lock, deps_path: deps_with_metadata(good)],
        fn ->
          sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)
          jason = Enum.find(sbom["packages"], &(&1["name"] == "jason"))
          assert jason["licenseDeclared"] == "Apache-2.0 OR MIT"
          assert jason["checksums"] == [%{"algorithm" => "SHA256", "checksumValue" => "bb"}]
        end
      )
    end
  end

  describe "verify_document/1 malformed documents" do
    test "rejects creation info, namespace, packages and relationships of the wrong type" do
      sbom = Sbom.generate(created_at: @created_at)
      assert :ok = Sbom.verify_document(sbom)

      for {document, reason} <- [
            {Map.delete(sbom, "creationInfo"), :invalid_creation_info},
            {Map.put(sbom, "creationInfo", "2026"), :invalid_creation_info},
            {put_in(sbom["creationInfo"]["created"], 1_782_820_800), :invalid_creation_info},
            {put_in(sbom["creationInfo"]["creators"], "Tool: mix sigil_guard.sbom"),
             :invalid_creation_info},
            {Map.delete(sbom, "documentNamespace"), :invalid_document_namespace},
            {Map.put(sbom, "documentNamespace", 7), :invalid_document_namespace},
            {Map.delete(sbom, "packages"), :invalid_packages},
            {Map.put(sbom, "packages", %{}), :invalid_packages},
            {update_in(sbom["packages"], &["junk" | &1]), :invalid_packages},
            {update_in(sbom["packages"], &List.insert_at(&1, -1, 7)), :invalid_packages},
            {Map.delete(sbom, "relationships"), :invalid_relationships},
            {Map.put(sbom, "relationships", %{}), :invalid_relationships},
            {update_in(sbom["relationships"], &["junk" | &1]), :invalid_relationships},
            {update_in(sbom["relationships"], &List.insert_at(&1, -1, nil)),
             :invalid_relationships}
          ] do
        assert Sbom.verify_document(document) == {:error, reason}
      end
    end
  end

  describe "run/1 with --sha256" do
    test "verifies the file against the digest and refuses any other bytes" do
      output = Path.join(Tmp.dir("sbom"), "sigil_guard.spdx.json")

      File.write!(
        output,
        Jason.encode_to_iodata!(Sbom.generate(created_at: @created_at), pretty: true)
      )

      digest = :crypto.hash(:sha256, File.read!(output)) |> Base.encode16(case: :lower)

      assert capture_io(fn ->
               Sbom.run(["--verify", output, "--sha256", String.upcase(digest)])
             end) =~
               "Verified SBOM at #{output}"

      assert_raise Mix.Error, "invalid SBOM: :sbom_digest_mismatch", fn ->
        Sbom.run(["--verify", output, "--sha256", String.duplicate("0", 64)])
      end

      File.write!(output, File.read!(output) <> "\n")

      assert_raise Mix.Error, "invalid SBOM: :sbom_digest_mismatch", fn ->
        Sbom.run(["--verify", output, "--sha256", digest])
      end
    end
  end

  describe "generate/1 without git" do
    test "the document namespace uses NOASSERTION outside a work tree and without a git executable" do
      hash =
        :crypto.hash(:sha256, "sigil_guard_sbom_fixture:1.0.0:NOASSERTION:#{@created_at}")
        |> Base.encode16(case: :lower)

      expected =
        "https://example.invalid/sigil_guard_sbom_fixture/sbom/sigil_guard_sbom_fixture-1.0.0-" <>
          hash

      outside = Tmp.dir("not_a_repo")
      path = System.get_env("PATH")
      ceiling = System.get_env("GIT_CEILING_DIRECTORIES")

      on_exit(fn ->
        System.put_env("PATH", path)

        if ceiling,
          do: System.put_env("GIT_CEILING_DIRECTORIES", ceiling),
          else: System.delete_env("GIT_CEILING_DIRECTORIES")
      end)

      with_config([], fn ->
        System.put_env("GIT_CEILING_DIRECTORIES", Path.dirname(outside))

        assert File.cd!(outside, fn -> Sbom.generate(created_at: @created_at) end)[
                 "documentNamespace"
               ] ==
                 expected

        System.put_env("PATH", outside)
        assert Sbom.generate(created_at: @created_at)["documentNamespace"] == expected
      end)
    end
  end
end

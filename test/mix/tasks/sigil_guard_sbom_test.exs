defmodule Mix.Tasks.SigilGuard.SbomTest do
  @moduledoc false

  # Mix.Project.push/1, File.cd!/2 and PATH changes are VM-wide.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.SigilGuard.Sbom
  alias SigilGuard.CaseFixtures.Tmp

  @created_at "2026-06-30T12:00:00Z"
  @git_revision String.duplicate("a", 40)

  defmodule TwoTupleKeywordProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:credo, only: [:dev, :test], runtime: false}
        ]
      ]
    end
  end

  defmodule MissingRuntimeLockProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:not_locked, "~> 0.1"}
        ]
      ]
    end
  end

  defmodule RuntimePathProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:local_runtime, path: "../local_runtime"}
        ]
      ]
    end
  end

  defmodule NonRuntimePathProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:local_dev, path: "../local_dev", only: :dev, runtime: false}
        ]
      ]
    end
  end

  defmodule RuntimeGithubProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:remote_runtime, "~> 0.1", github: "example/remote_runtime"}
        ]
      ]
    end
  end

  defmodule BadDependencyShapeProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [:not_a_tuple]
      ]
    end
  end

  defmodule BadDependencyOptionsProject do
    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:bad_options, [:not_keyword]}
        ]
      ]
    end
  end

  # A fixture project whose configuration the test supplies, so a test can
  # point :lockfile and :deps_path at files it wrote.
  defmodule ConfiguredProject do
    @spec project() :: keyword()
    def project, do: Process.get(__MODULE__)
  end

  describe "generate/1" do
    test "builds an SPDX 2.3 document from the project and lockfile" do
      sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)

      assert sbom["spdxVersion"] == "SPDX-2.3"
      assert sbom["dataLicense"] == "CC0-1.0"
      assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"
      assert sbom["creationInfo"]["created"] == @created_at

      package_names = MapSet.new(sbom["packages"], & &1["name"])

      assert Enum.any?(sbom["packages"], fn package ->
               package["name"] == "sigil_guard" and
                 package["externalRefs"] == [
                   %{
                     "referenceCategory" => "PACKAGE-MANAGER",
                     "referenceType" => "purl",
                     "referenceLocator" => "pkg:hex/sigil_guard@#{Mix.Project.config()[:version]}"
                   }
                 ]
             end)

      assert Enum.any?(sbom["packages"], fn package ->
               package["name"] == "jason" and package["versionInfo"] == "1.4.5"
             end)

      for name <- ["jason", "nimble_options", "telemetry"] do
        package = Enum.find(sbom["packages"], &(&1["name"] == name))
        assert package["licenseDeclared"] == "Apache-2.0"
        assert package["licenseConcluded"] == "Apache-2.0"
      end

      refute Enum.any?(sbom["packages"], &(&1["licenseDeclared"] == "NOASSERTION"))

      refute MapSet.member?(package_names, "finch")
      refute MapSet.member?(package_names, "mint")
      refute MapSet.member?(package_names, "credo")
      refute MapSet.member?(package_names, "benchee")

      assert direct_dependency_ids(sbom) ==
               MapSet.new([
                 "SPDXRef-Package-jason",
                 "SPDXRef-Package-nimble-options",
                 "SPDXRef-Package-telemetry"
               ])
    end

    test "excludes non-runtime two-tuple keyword dependencies" do
      with_project(TwoTupleKeywordProject, fn ->
        sbom = Sbom.generate(created_at: @created_at)
        package_names = MapSet.new(sbom["packages"], & &1["name"])

        assert MapSet.member?(package_names, "jason")
        refute MapSet.member?(package_names, "credo")
        assert :ok = Sbom.verify_document(sbom)
      end)
    end

    test "rejects runtime dependencies missing from the lockfile" do
      with_project(MissingRuntimeLockProject, fn ->
        assert_raise Mix.Error, ~r/missing_runtime_dependency_lock.*not_locked/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:missing_runtime_dependency_lock, :not_locked}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects runtime non-Hex dependency sources" do
      with_project(RuntimePathProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*local_runtime/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :local_runtime}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects runtime git dependency sources" do
      with_project(RuntimeGithubProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*remote_runtime/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :remote_runtime}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects invalid dependency shapes" do
      with_project(BadDependencyShapeProject, fn ->
        assert_raise Mix.Error, ~r/invalid_dependency/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, :invalid_dependency} = Sbom.verify_document(%{})
      end)
    end

    test "rejects dependency tuples with invalid option lists" do
      with_project(BadDependencyOptionsProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*bad_options/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :bad_options}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "allows non-runtime non-Hex dependency sources" do
      with_project(NonRuntimePathProject, fn ->
        sbom = Sbom.generate(created_at: @created_at)
        package_names = MapSet.new(sbom["packages"], & &1["name"])

        assert MapSet.member?(package_names, "jason")
        refute MapSet.member?(package_names, "local_dev")
        assert :ok = Sbom.verify_document(sbom)
      end)
    end

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

    test "a runtime dependency tuple of an unsupported shape is refused, and a dev-only one is skipped" do
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

    test "a runtime dependency the lock pins to git, or does not list, is refused" do
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

    test "fetched package metadata that is absent, differs from the lock or names no licence is refused" do
      lock =
        write_lock(
          ~s(%{\n  "jason": {:hex, :jason, "1.4.5", "aa", [:mix], [], "hexpm", "bb"},\n}\n)
        )

      with_config(
        [{:jason, "~> 1.4"}],
        [lockfile: lock, deps_path: deps_with_metadata(nil)],
        fn ->
          assert Sbom.verify_document(%{}) ==
                   {:error, {:unreadable_runtime_dependency_metadata, :jason, :enoent}}
        end
      )

      for metadata <- [
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

    test "the document namespace uses NOASSERTION outside a work tree and without a git executable" do
      expected =
        "https://example.invalid/sigil_guard_sbom_fixture/sbom/sigil_guard_sbom_fixture-1.0.0-" <>
          "a7ce4fb40de9102a71504833371f83cb69c3f592dc8dfe2e61a3d0fafd705995"

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

  describe "verify_document/1" do
    test "accepts the generated SPDX document shape for the current project" do
      sbom = verifiable_sbom()

      assert :ok = Sbom.verify_document(sbom)
    end

    test "rejects non-map documents" do
      assert {:error, :invalid_document} = Sbom.verify_document([])
    end

    test "rejects invalid SPDX metadata" do
      sbom =
        verifiable_sbom()
        |> Map.put("spdxVersion", "SPDX-2.2")

      assert {:error, :invalid_spdx_version} = Sbom.verify_document(sbom)

      assert {:error, :invalid_document_name} =
               verifiable_sbom()
               |> Map.put("name", "tampered")
               |> Sbom.verify_document()

      assert {:error, :invalid_document_namespace} =
               verifiable_sbom()
               |> Map.put("documentNamespace", "https://example.invalid/sbom/tampered")
               |> Sbom.verify_document()

      assert {:error, :invalid_document_namespace} =
               verifiable_sbom()
               |> Map.update!("documentNamespace", fn namespace ->
                 Regex.replace(~r/[a-f0-9]{64}\z/, namespace, String.duplicate("b", 64))
               end)
               |> Sbom.verify_document()

      assert {:error, :invalid_creation_info} =
               verifiable_sbom()
               |> put_in(["creationInfo", "created"], "not-a-timestamp")
               |> Sbom.verify_document()
    end

    test "rejects documents without the expected root package" do
      sbom =
        verifiable_sbom()
        |> Map.put("packages", [])

      assert {:error, :missing_root_package} = Sbom.verify_document(sbom)
    end

    test "rejects tampered root package metadata" do
      for {field, value} <- [
            {"downloadLocation", "https://evil.example/source"},
            {"licenseDeclared", "NOASSERTION"},
            {"licenseConcluded", "NOASSERTION"},
            {"supplier", "Organization: Other"},
            {"filesAnalyzed", true}
          ] do
        sbom =
          verifiable_sbom()
          |> update_root_package(field, value)

        assert {:error, :invalid_root_package} = Sbom.verify_document(sbom),
               "expected invalid root package after tampering #{field}"
      end
    end

    test "rejects documents without the root DESCRIBES relationship" do
      sbom =
        verifiable_sbom()
        |> Map.put("relationships", [])

      assert {:error, :missing_describes_relationship} = Sbom.verify_document(sbom)
    end

    test "rejects tampered dependency packages" do
      sbom =
        verifiable_sbom()
        |> update_in(["packages"], fn packages ->
          Enum.map(packages, fn
            %{"name" => "jason"} = package -> %{package | "versionInfo" => "9.9.9"}
            package -> package
          end)
        end)

      assert {:error, :invalid_dependency_package} = Sbom.verify_document(sbom)
    end

    test "rejects missing dependency packages" do
      sbom =
        verifiable_sbom()
        |> update_in(["packages"], fn packages ->
          Enum.reject(packages, &(&1["name"] == "jason"))
        end)

      assert {:error, :missing_dependency_package} = Sbom.verify_document(sbom)
    end

    test "rejects unexpected packages" do
      sbom =
        verifiable_sbom()
        |> update_in(["packages"], fn packages ->
          [
            %{
              "name" => "shadow",
              "SPDXID" => "SPDXRef-Package-shadow",
              "versionInfo" => "9.9.9"
            }
            | packages
          ]
        end)

      assert {:error, :unexpected_package} = Sbom.verify_document(sbom)
    end

    test "rejects missing dependency relationships" do
      sbom =
        verifiable_sbom()
        |> update_in(["relationships"], fn relationships ->
          Enum.reject(relationships, fn relationship ->
            relationship["spdxElementId"] == "SPDXRef-Package-sigil-guard" and
              relationship["relationshipType"] == "DEPENDS_ON" and
              relationship["relatedSpdxElement"] == "SPDXRef-Package-jason"
          end)
        end)

      assert {:error, :missing_dependency_relationship} = Sbom.verify_document(sbom)
    end

    test "rejects unexpected relationships" do
      sbom =
        verifiable_sbom()
        |> update_in(["relationships"], fn relationships ->
          [
            %{
              "spdxElementId" => "SPDXRef-Package-sigil-guard",
              "relationshipType" => "DEPENDS_ON",
              "relatedSpdxElement" => "SPDXRef-Package-shadow"
            }
            | relationships
          ]
        end)

      assert {:error, :unexpected_relationship} = Sbom.verify_document(sbom)
    end

    test "creation info, namespace, packages and relationships of the wrong type are refused" do
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

  describe "verify_file/1" do
    test "accepts valid JSON SPDX files" do
      output = tmp_path("valid")
      sbom = verifiable_sbom()

      File.write!(output, Jason.encode!(sbom))

      assert :ok = Sbom.verify_file(output)
    end

    test "rejects invalid JSON and missing files" do
      output = tmp_path("invalid")

      File.write!(output, "{")

      assert {:error, :invalid_json} = Sbom.verify_file(output)
      assert {:error, :enoent} = Sbom.verify_file(tmp_path("missing"))
      assert {:error, :invalid_path} = Sbom.verify_file(:not_a_path)
    end
  end

  describe "verify_file/2 (SHA-256 digest verification)" do
    test "accepts a file whose digest matches the expected value" do
      output = tmp_path("digest-ok")
      body = Jason.encode!(verifiable_sbom())
      File.write!(output, body)
      sha256 = Base.encode16(:crypto.hash(:sha256, body), case: :lower)

      assert :ok = Sbom.verify_file(output, sha256)
      # The expected digest is compared case-insensitively.
      assert :ok = Sbom.verify_file(output, String.upcase(sha256))
    end

    test "fails :sbom_digest_mismatch on digest drift, before structural checks" do
      output = tmp_path("digest-drift")
      File.write!(output, Jason.encode!(%{}))

      assert Sbom.verify_file(output) == {:error, :invalid_spdx_version}

      assert Sbom.verify_file(output, String.duplicate("0", 64)) ==
               {:error, :sbom_digest_mismatch}
    end

    test "rejects malformed inputs" do
      assert {:error, :invalid_path} = Sbom.verify_file(:not_a_path, "abc")

      assert {:error, :enoent} =
               Sbom.verify_file(tmp_path("missing"), String.duplicate("0", 64))
    end
  end

  describe "run/1" do
    test "writes pretty JSON to the selected output path" do
      output = tmp_path("write")

      capture_io(fn ->
        Sbom.run(["--output", output])
      end)

      body = File.read!(output)
      assert body =~ ~r/\A\{\n  "/
      assert Jason.decode!(body)["spdxVersion"] == "SPDX-2.3"
    end

    test "verifies an existing SBOM file" do
      output = tmp_path("verify")

      capture_io(fn ->
        Sbom.run(["--output", output])
      end)

      assert capture_io(fn ->
               Sbom.run(["--verify", output])
             end) =~ "Verified SBOM"
    end

    test "raises for invalid CLI options" do
      assert_raise Mix.Error, ~r/invalid options/, fn ->
        Sbom.run(["--unknown"])
      end
    end

    test "raises for invalid SBOM files" do
      output = tmp_path("verify-invalid")
      File.write!(output, Jason.encode!(%{}))

      assert_raise Mix.Error, ~r/invalid SBOM: :invalid_spdx_version/, fn ->
        Sbom.run(["--verify", output])
      end
    end

    test "a file verifies against its digest and any other bytes are refused" do
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

  defp direct_dependency_ids(sbom) do
    sbom["relationships"]
    |> Enum.filter(fn relationship ->
      relationship["spdxElementId"] == "SPDXRef-Package-sigil-guard" and
        relationship["relationshipType"] == "DEPENDS_ON"
    end)
    |> Enum.map(& &1["relatedSpdxElement"])
    |> MapSet.new()
  end

  defp verifiable_sbom do
    Sbom.generate(created_at: @created_at)
  end

  defp update_root_package(sbom, field, value) do
    update_in(sbom, ["packages"], fn packages ->
      Enum.map(packages, fn
        %{"name" => "sigil_guard"} = package -> Map.put(package, field, value)
        package -> package
      end)
    end)
  end

  defp with_project(project, fun) do
    Mix.Project.push(project)

    try do
      fun.()
    after
      Mix.Project.pop()
    end
  end

  defp tmp_path(label) do
    path =
      System.tmp_dir!()
      |> Path.join("sigil_guard_sbom_test_#{label}_#{System.unique_integer()}.json")

    on_exit(fn -> File.rm(path) end)
    path
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
end

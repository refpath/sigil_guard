defmodule SigilGuard.CapabilityManifestCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.CapabilityManifest

  describe "new/1" do
    test "rejects a UI block without a visibility list or with a resource URI that is not a string" do
      for ui <- [
            %{"resource_uri" => "ui://repo/review"},
            %{"resource_uri" => "ui://repo/review", "visibility" => "app"},
            %{"resource_uri" => 7, "visibility" => ["app"]},
            "ui://repo/review"
          ] do
        assert CapabilityManifest.new(Map.put(manifest(), "ui", ui)) ==
                 {:error, :invalid_manifest}
      end

      assert {:ok, _} =
               CapabilityManifest.new(
                 Map.put(manifest(), "ui", %{
                   "resource_uri" => "ui://repo/review",
                   "visibility" => ["app"]
                 })
               )
    end

    test "rejects icons of the wrong shape" do
      icon = %{"src" => "https://example.test/icon.png"}

      assert {:ok, _} = CapabilityManifest.new(Map.put(manifest(), "icons", [icon]))

      for icons <- [
            icon,
            "https://example.test/icon.png",
            ["https://example.test/icon.png"],
            [%{"mimeType" => "image/png"}],
            [%{"src" => 7}],
            [%{"src" => "data:image/svg+xml,<svg/>"}],
            [Map.put(icon, "sizes", "48x48")]
          ] do
        assert CapabilityManifest.new(Map.put(manifest(), "icons", icons)) ==
                 {:error, :invalid_manifest}
      end
    end
  end

  describe "digest/1" do
    test "a struct without a cached digest fails closed on a preimage with no canonical form" do
      {:ok, pinned} = CapabilityManifest.new(manifest())
      uncached = fn preimage -> %CapabilityManifest{digest: nil, preimage: preimage} end

      assert CapabilityManifest.digest(uncached.(pinned.preimage)) == {:ok, pinned.digest}

      assert CapabilityManifest.digest(
               uncached.(Map.put(pinned.preimage, "version", 9_007_199_254_740_992))
             ) == {:error, :unsupported_number_range}

      assert CapabilityManifest.digest(uncached.(Map.put(pinned.preimage, "version", {1, 4, 2}))) ==
               {:error, :invalid_manifest}

      assert CapabilityManifest.digest(uncached.(Map.put(pinned.preimage, "name", <<255>>))) ==
               {:error, :invalid_manifest}
    end
  end

  defp manifest do
    %{
      "allowed_sink_zones" => ["semi_trusted", "trusted"],
      "allowed_source_zones" => ["semi_trusted", "trusted"],
      "annotations" => %{"destructiveHint" => false, "title" => "Repo File Write"},
      "description" => "Write one UTF-8 text file inside the repository working tree.",
      "expires_at" => "2027-01-01T00:00:00.000Z",
      "input_schema" => %{
        "$schema" => "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties" => false,
        "properties" => %{"content" => %{"type" => "string"}, "path" => %{"type" => "string"}},
        "required" => ["content", "path"],
        "type" => "object"
      },
      "input_sensitivity" => "internal",
      "issuer_keyid" => "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
      "manifest_format" => "sigil_guard_capability_manifest/v2",
      "name" => "repo_file_write",
      "network_access" => "none",
      "output_sensitivity" => "internal",
      "reversibility" => "reversible",
      "sandbox" => %{"min_isolation" => "container", "required" => true},
      "scopes" => ["repo:write"],
      "server" => "repo-mcp",
      "side_effects" => ["write"],
      "suspicious_params" => [],
      "version" => "1.4.2"
    }
  end
end

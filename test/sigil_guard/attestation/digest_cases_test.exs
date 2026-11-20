defmodule SigilGuard.Attestation.DigestCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Digest

  describe "context_digest/2" do
  end

  describe "digests/4" do
    test "digests/3 states no manifest subject" do
      payload = %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
      context = %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}

      assert {:ok, digests} = Digest.digests(:tool_request, payload, context)
      assert Map.keys(digests) == ["action", "context", "payload"]
      assert {:ok, ^digests} = Digest.digests(:tool_request, payload, context, [])

      # A result has no action digest without the request it answers.
      assert Digest.digests(:tool_result, payload, context) == {:error, :invalid_payload}
    end
  end
end

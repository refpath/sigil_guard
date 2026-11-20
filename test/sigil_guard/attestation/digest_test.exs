defmodule SigilGuard.Attestation.DigestTest do
  @moduledoc false

  use ExUnit.Case, async: true

  doctest SigilGuard.Attestation.Digest

  alias SigilGuard.Attestation.Digest

  @request_action_digest String.duplicate("a", 64)
  @manifest_digest String.duplicate("b", 64)

  describe "normalize/1" do
    test "converts atom keys and values, omits nil map entries, and preserves booleans" do
      assert Digest.normalize(%{
               phase: :tool_request,
               skipped: nil,
               nested: %{allow?: true, trust: :low},
               list: [:agent_request, nil, false]
             }) ==
               {:ok,
                %{
                  "phase" => "tool_request",
                  "nested" => %{"allow?" => true, "trust" => "low"},
                  "list" => ["agent_request", nil, false]
                }}
    end

    test "rejects normalized key collisions and invalid values" do
      assert Digest.normalize(%{:phase => :tool_request, "phase" => "tool_request"}) ==
               {:error, :invalid_payload}

      assert Digest.normalize(%{"bad" => self()}) == {:error, :invalid_payload}
      assert Digest.normalize(%{<<255>> => "bad-key"}) == {:error, :invalid_payload}
      assert Digest.normalize(%{"bad-list" => [self()]}) == {:error, :invalid_payload}
      assert Digest.normalize(%{"bad-struct" => DateTime.utc_now()}) == {:error, :invalid_payload}
      assert Digest.normalize(1.5) == {:ok, 1.5}
    end
  end

  describe "payload_digest/1" do
    test "hashes UTF-8 binary payload bytes directly" do
      assert Digest.payload_digest("payload") == {:ok, sha256("payload")}
    end

    test "hashes stripped normalized maps and lists" do
      payload = %{
        "name" => "repo_file_write",
        "params" => %{"arguments" => %{"path" => "README.md"}},
        "_agent_trust" => %{"payload" => "ignored"},
        confirmation_token: "ignored"
      }

      stripped = ~s({"name":"repo_file_write","params":{"arguments":{"path":"README.md"}}})
      assert Digest.payload_digest(payload) == {:ok, sha256(stripped)}

      list_payload = [payload, %{"_agent_confirmation" => "ignored", "value" => true}]

      assert Digest.payload_digest(list_payload) ==
               {:ok, sha256("[" <> stripped <> ~s(,{"value":true}]))}
    end

    test "keeps digest-neutral behavior only for attestation metadata namespaces" do
      payload = %{
        "name" => "repo_file_write",
        "params" => %{"arguments" => %{"path" => "README.md"}}
      }

      agent_payload =
        payload
        |> Map.put("_agent_trust", %{"payload" => "ignored"})
        |> Map.put("_agent_confirmation", "confirm.token")

      legacy_payload =
        payload
        |> Map.put("_sigil", %{"payload" => "ignored"})
        |> Map.put("_sigil_confirmation", "confirm.token")

      assert Digest.payload_digest(agent_payload) == Digest.payload_digest(payload)
      assert Digest.payload_digest(legacy_payload) != Digest.payload_digest(payload)
    end

    test "rejects malformed payload classes" do
      assert Digest.payload_digest({:bad}) == {:error, :invalid_payload}
      assert Digest.payload_digest(<<255>>) == {:error, :invalid_payload}
      assert Digest.payload_digest(%{1 => "bad-key"}) == {:error, :invalid_payload}
    end
  end

  describe "context_digest/2" do
    test "includes sandbox_id and isolation_level when present" do
      context = %{
        phase: :tool_request,
        origin: :user,
        sink: :tool,
        trust_zone: :untrusted,
        intended_audience: :tool,
        sandbox_id: "sbx-1",
        isolation_level: "strict"
      }

      assert Digest.context_preimage(:tool_request, context) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "trust_level" => :low,
                  "phase" => :tool_request,
                  "origin" => :user,
                  "sink" => :tool,
                  "trust_zone" => :untrusted,
                  "intended_audience" => :tool,
                  "sandbox_id" => "sbx-1",
                  "isolation_level" => "strict"
                }}

      assert {:ok, without_sandbox} =
               Digest.context_digest(:tool_request, Map.drop(context, [:sandbox_id]))

      assert {:ok, with_sandbox} = Digest.context_digest(:tool_request, context)
      refute with_sandbox == without_sandbox
    end

    test "accepts keyword context extras and rejects unknown statement types" do
      context = [
        phase: :model_ingress,
        origin: :user,
        source: "chat",
        actor: "spiffe://agents/requester",
        identity: "did:example:agent",
        trust_zone: :workspace,
        mcp_server: "local",
        resource_uri: "memory://1"
      ]

      assert {:ok, preimage} = Digest.context_preimage(:model_ingress, context)
      assert preimage["actor"] == "spiffe://agents/requester"
      assert preimage["identity"] == "did:example:agent"
      assert preimage["mcp_server"] == "local"
      assert preimage["resource_uri"] == "memory://1"

      assert Digest.context_preimage(:unknown, context) == {:error, :unknown_statement_type}
    end

    test "accepts atom-key context maps for every shared context field" do
      context = %{
        actor: "spiffe://agents/requester",
        identity: "did:example:agent",
        trust_level: :high,
        phase: :tool_request,
        origin: :user,
        sink: :tool,
        trust_zone: :trusted,
        mcp_server: "local",
        tool: "repo_file_write",
        resource_uri: "memory://1",
        intended_audience: :tool
      }

      assert Digest.context_preimage(:tool_request, context) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "actor" => "spiffe://agents/requester",
                  "identity" => "did:example:agent",
                  "trust_level" => :high,
                  "phase" => :tool_request,
                  "origin" => :user,
                  "sink" => :tool,
                  "trust_zone" => :trusted,
                  "mcp_server" => "local",
                  "tool" => "repo_file_write",
                  "resource_uri" => "memory://1",
                  "intended_audience" => :tool
                }}
    end
  end

  describe "action_preimage/4" do
    test "builds tool_request and tool_result rows" do
      request_payload = %{
        "method" => "tools/call",
        "params" => %{
          "name" => "repo_file_write",
          "arguments" => %{"path" => "README.md", "_agent_trust" => %{}}
        }
      }

      assert Digest.action_preimage(:tool_request, request_payload, %{phase: :tool_request}, []) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "tool" => "repo_file_write",
                  "method" => "tools/call",
                  "arguments" => %{"path" => "README.md"}
                }}

      assert Digest.action_preimage(
               :tool_result,
               %{"method" => "tools/call"},
               %{phase: :tool_result, tool: "repo_file_write"},
               request_action_digest: @request_action_digest
             ) ==
               {:ok,
                %{
                  "statement_type" => "tool_result",
                  "tool" => "repo_file_write",
                  "method" => "tools/call",
                  "request_action_digest" => @request_action_digest
                }}
    end

    test "builds model boundary rows" do
      assert Digest.action_preimage(
               :model_ingress,
               %{},
               %{origin: :user, source: "chat", resource_uri: "memory://1"},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "model_ingress",
                  "origin" => "user",
                  "source" => "chat",
                  "resource_uri" => "memory://1"
                }}

      assert Digest.action_preimage(
               :model_egress,
               %{},
               %{sink: :user, intended_audience: :user, resource_uri: "chat://1"},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "model_egress",
                  "sink" => "user",
                  "intended_audience" => "user",
                  "resource_uri" => "chat://1"
                }}
    end

    test "builds repo_change and release rows" do
      assert Digest.action_preimage(
               :repo_change,
               %{
                 "repository" => "sigil_guard",
                 "operation" => "write",
                 "paths" => ["lib/z.ex", "README.md"],
                 "ref" => "main"
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "repo_change",
                  "repository" => "sigil_guard",
                  "operation" => "write",
                  "paths" => ["README.md", "lib/z.ex"],
                  "ref" => "main"
                }}

      assert Digest.action_preimage(
               :release,
               %{
                 "package" => "sigil_guard",
                 "version" => "1.0.0",
                 "artifacts" => [
                   %{"name" => "z.tar", "sha256" => String.duplicate("c", 64)},
                   %{name: "a.tar", sha256: String.duplicate("d", 64)}
                 ]
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "release",
                  "package" => "sigil_guard",
                  "version" => "1.0.0",
                  "artifacts" => [
                    %{"name" => "a.tar", "sha256" => String.duplicate("d", 64)},
                    %{"name" => "z.tar", "sha256" => String.duplicate("c", 64)}
                  ]
                }}
    end

    test "builds agent_request and agent_response rows" do
      assert Digest.action_preimage(
               :agent_request,
               %{
                 "peer_agent" => "spiffe://agents/responder",
                 "capability" => "summarize",
                 "arguments" => %{"topic" => "build"}
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_request",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "arguments" => %{"topic" => "build"}
                }}

      assert Digest.action_preimage(
               :agent_response,
               %{"peer_agent" => "spiffe://agents/responder", "capability" => "summarize"},
               %{},
               request_action_digest: @request_action_digest
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_response",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "request_action_digest" => @request_action_digest
                }}
    end

    test "rejects malformed action rows" do
      assert Digest.action_preimage(:tool_request, %{}, %{}, []) == {:error, :invalid_payload}

      assert Digest.action_preimage(:repo_change, %{"paths" => [1]}, %{}, []) ==
               {:error, :invalid_payload}

      assert Digest.action_preimage(
               :agent_response,
               %{"peer_agent" => "a", "capability" => "c"},
               %{},
               []
             ) ==
               {:error, :invalid_payload}

      assert Digest.action_preimage(:unknown, %{}, %{}, []) == {:error, :unknown_statement_type}

      assert Digest.action_preimage(:tool_request, "bad", %{}, []) == {:error, :invalid_payload}

      assert Digest.action_preimage(:tool_result, %{}, %{}, request_action_digest: "bad") ==
               {:error, :invalid_payload}

      assert Digest.action_preimage(:model_ingress, %{}, %{origin: ""}, []) ==
               {:error, :invalid_payload}

      assert Digest.action_preimage(:model_egress, %{}, %{sink: ""}, []) ==
               {:error, :invalid_payload}

      for context <- [:bad_context, nil, 5, "context", [1, 2], [{1, 2}]] do
        assert Digest.action_preimage(:model_ingress, %{}, context, []) ==
                 {:error, :invalid_payload}

        assert Digest.context_digest(:tool_request, context) == {:error, :invalid_payload}
      end

      assert Digest.action_preimage(
               :release,
               %{"package" => "sigil_guard", "version" => "1.0.0", "artifacts" => []},
               %{},
               []
             ) == {:error, :invalid_payload}

      assert Digest.action_preimage(
               :release,
               %{
                 "package" => "sigil_guard",
                 "version" => "1.0.0",
                 "artifacts" => [%{"name" => "bad.tar"}]
               },
               %{},
               []
             ) == {:error, :invalid_payload}

      assert Digest.action_preimage(
               :release,
               %{
                 "package" => "sigil_guard",
                 "version" => "1.0.0",
                 "artifacts" => [%{"name" => "bad.tar", "sha256" => "bad"}]
               },
               %{},
               []
             ) == {:error, :invalid_payload}

      assert Digest.action_preimage(
               :release,
               %{
                 "package" => "sigil_guard",
                 "version" => "1.0.0",
                 "artifacts" => ["bad"]
               },
               %{},
               []
             ) == {:error, :invalid_payload}
    end

    test "a repo change row keeps a repository and an operation of any JSON type" do
      for {repository, operation} <- [{%{"owner" => "sigil"}, true}, {["sigil_guard"], 1}] do
        assert Digest.action_preimage(
                 :repo_change,
                 %{
                   "repository" => repository,
                   "operation" => operation,
                   "paths" => ["README.md"]
                 },
                 %{},
                 []
               ) ==
                 {:ok,
                  %{
                    "statement_type" => "repo_change",
                    "repository" => repository,
                    "operation" => operation,
                    "paths" => ["README.md"]
                  }}
      end
    end

    test "a tool request row takes an atom tool name from the context" do
      assert Digest.action_preimage(
               :tool_request,
               %{"method" => "tools/call", "arguments" => %{"path" => "README.md"}},
               %{tool: :repo_file_write},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "tool" => "repo_file_write",
                  "method" => "tools/call",
                  "arguments" => %{"path" => "README.md"}
                }}
    end

    test "a model ingress row keeps only the origin of a string-keyed context" do
      assert Digest.action_preimage(
               :model_ingress,
               %{},
               %{"origin" => "user", "unexpected" => "ignored"},
               []
             ) == {:ok, %{"statement_type" => "model_ingress", "origin" => "user"}}
    end
  end

  describe "digest values" do
    @digest String.duplicate("a", 64)

    test "a digest followed by a newline is not a digest" do
      result = fn digest ->
        Digest.action_digest(:tool_result, %{"ok" => true}, [tool: "reader"],
          request_action_digest: digest
        )
      end

      release = fn digest ->
        Digest.action_digest(
          :release,
          %{
            "package" => "example",
            "version" => "1.0.0",
            "artifacts" => [%{"name" => "example.tar", "sha256" => digest}]
          },
          []
        )
      end

      assert {:ok, _} = result.(@digest)
      assert {:ok, _} = release.(@digest)
      assert result.(@digest <> "\n") == {:error, :invalid_payload}
      assert release.(@digest <> "\n") == {:error, :invalid_payload}
    end
  end

  describe "digests/4" do
    test "returns action, payload, context, and applicable manifest digests" do
      payload = %{"name" => "repo_file_write"}
      context = %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}

      assert {:ok, digests} =
               Digest.digests(:tool_request, payload, context, manifest_digest: @manifest_digest)

      assert Map.keys(digests) == ~w(action context manifest payload)
      assert digests["manifest"] == @manifest_digest

      assert {:ok, model_digests} = Digest.digests(:model_ingress, %{}, %{origin: :user}, [])
      refute Map.has_key?(model_digests, "manifest")

      assert {:ok, manifest_digests} =
               Digest.digests(:tool_request, payload, context, manifest: %{"name" => "bundle"})

      assert manifest_digests["manifest"] ==
               elem(Digest.manifest_digest(%{"name" => "bundle"}), 1)

      assert Digest.digests(:tool_request, payload, context, manifest_digest: :bad) ==
               {:error, :invalid_payload}
    end
  end

  describe "manifest_digest/1" do
    test "hashes manifest strings and rejects malformed manifest classes" do
      assert Digest.manifest_digest("manifest") == {:ok, sha256("manifest")}
      assert Digest.manifest_digest(:bad) == {:error, :invalid_payload}
    end
  end

  defp sha256(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  test "null-valued application fields cannot reuse an absent-field digest" do
    assert {:ok, _} = Digest.payload_digest(%{"arguments" => %{}})

    assert {:error, :invalid_payload} =
             Digest.payload_digest(%{"arguments" => %{"delete_at" => nil}})

    assert {:error, :invalid_payload} = Digest.payload_digest([%{"nested" => nil}])
    assert {:ok, _} = Digest.payload_digest([nil])
    assert Digest.normalize(%{"optional" => nil}) == {:ok, %{}}
  end

  test "MCP wrapper nullable profile fields do not allow null application arguments" do
    alias SigilGuard.MCP.SecurityPayload
    request = %{"method" => "tools/call", "params" => %{"name" => "update", "arguments" => %{}}}
    wrapper = SecurityPayload.for_gate(request, :request)

    assert {:ok, _} =
             Digest.payload_digest(SecurityPayload.for_gate(%{"text" => "safe"}, :result))

    assert {:ok, _} = Digest.payload_digest(wrapper)
    tampered = put_in(wrapper.binding["payload"]["arguments"], %{"delete_at" => nil})
    assert {:error, :invalid_payload} = Digest.payload_digest(tampered)
    assert {:error, :invalid_payload} = Digest.payload_digest(Map.put(wrapper, :unexpected, nil))

    assert {:ok, preimage} =
             Digest.action_preimage(:tool_request, %{"name" => "other", "arguments" => %{}}, %{
               tool: "authoritative"
             })

    assert preimage["tool"] == "authoritative"
  end

  describe "null and absence at the gateway wrapper boundary" do
    @projection %{
      "kind" => "request",
      "method" => "tools/call",
      "protocol_version" => nil,
      "payload" => %{"name" => "cell.move"}
    }

    test "a projection may carry null only in its fixed wrapper fields" do
      assert {:ok, digest} = Digest.payload_digest(@projection)
      assert {:ok, ^digest} = Digest.payload_digest(Map.delete(@projection, "protocol_version"))

      assert Digest.payload_digest(put_in(@projection, ["payload", "speed"], nil)) ==
               {:error, :invalid_payload}

      assert Digest.payload_digest(%{@projection | "payload" => nil}) ==
               {:error, :invalid_payload}
    end

    test "an extra key makes the whole map application data" do
      assert Digest.payload_digest(Map.put(@projection, "extra", 1)) == {:error, :invalid_payload}

      assert {:ok, _} =
               @projection
               |> Map.delete("protocol_version")
               |> Map.put("extra", 1)
               |> Digest.payload_digest()
    end

    test "the gate wrapper follows the same rule for its binding" do
      wrapper = %{
        action: "cell.move",
        tool: nil,
        text: "move",
        binding: %{@projection | "method" => nil}
      }

      assert {:ok, _} = Digest.payload_digest(wrapper)

      assert Digest.payload_digest(put_in(wrapper, [:binding, "other"], nil)) ==
               {:error, :invalid_payload}

      assert Digest.payload_digest(put_in(wrapper, [:binding, "payload", "speed"], nil)) ==
               {:error, :invalid_payload}

      look_alike = %{a: 1, b: 2, c: 3, binding: %{"payload" => %{}, "kind" => nil}}

      assert Digest.payload_digest(look_alike) == {:error, :invalid_payload}
    end
  end

  describe "values with no JSON form" do
    test "normalize/1 refuses a struct, a tuple, a pid, and a function" do
      for value <- [~D[2026-11-19], {1, 2}, self(), &is_atom/1] do
        assert Digest.normalize(value) == {:error, :invalid_payload}
        assert Digest.normalize(%{"value" => value}) == {:error, :invalid_payload}
        assert Digest.normalize([value]) == {:error, :invalid_payload}
        assert Digest.payload_digest(%{"value" => value}) == {:error, :invalid_payload}
      end
    end

    test "a repo change needs a list of path strings" do
      payload = %{"repository" => "example/repo", "operation" => "push"}
      preimage = &Digest.action_preimage(:repo_change, Map.put(payload, "paths", &1), [], [])

      assert {:ok, %{"paths" => ["lib/a.ex", "lib/b.ex"]}} = preimage.(["lib/b.ex", "lib/a.ex"])

      for paths <- ["lib/a.ex", %{"lib/a.ex" => true}, [1], ["lib/a.ex", 2]] do
        assert preimage.(paths) == {:error, :invalid_payload}
      end
    end
  end

  describe "action preimage of a gateway payload" do
    alias SigilGuard.MCP.SecurityPayload

    @context %{phase: :tool_request, origin: :model, sink: :tool, tool: "repo_file_write"}

    defp call(arguments) do
      %{
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "tools/call",
        "params" => %{"name" => "repo_file_write", "arguments" => arguments}
      }
    end

    test "binds the method and arguments of the wrapped request" do
      request = call(%{"path" => "docs/a.md", "content" => "one"})

      assert {:ok, wrapped} =
               Digest.action_preimage(
                 :tool_request,
                 SecurityPayload.for_gate(request, :request),
                 @context
               )

      assert {:ok, raw} = Digest.action_preimage(:tool_request, request, @context)

      assert wrapped == raw
      assert wrapped["method"] == "tools/call"
      assert wrapped["arguments"] == %{"path" => "docs/a.md", "content" => "one"}
    end

    test "two calls to one tool with different arguments have different action digests" do
      digest = fn arguments ->
        {:ok, digest} =
          Digest.action_digest(
            :tool_request,
            SecurityPayload.for_gate(call(arguments), :request),
            @context
          )

        digest
      end

      first = digest.(%{"path" => "docs/a.md", "content" => "one"})

      refute first == digest.(%{"path" => "docs/a.md", "content" => "two"})
      refute first == digest.(%{"path" => "docs/b.md", "content" => "one"})
    end

    test "a result preimage reads through the wrapper and a look-alike map is left alone" do
      result = %{"jsonrpc" => "2.0", "id" => 1, "result" => %{"content" => []}}
      context = %{phase: :tool_result, origin: :tool, sink: :model, tool: "repo_file_write"}
      opts = [request_action_digest: String.duplicate("a", 64)]

      assert {:ok, %{"statement_type" => "tool_result", "tool" => "repo_file_write"}} =
               Digest.action_preimage(
                 :tool_result,
                 SecurityPayload.for_gate(result, :result),
                 context,
                 opts
               )

      # Extra keys make it application data, not the gate wrapper.
      look_alike = %{
        "binding" => %{"kind" => "request", "payload" => call(%{"path" => "x"})},
        "extra" => true
      }

      assert {:ok, preimage} = Digest.action_preimage(:tool_request, look_alike, @context)
      refute Map.has_key?(preimage, "method")
      refute Map.has_key?(preimage, "arguments")
    end

    test "a member of the params object cannot stand in for the message's own" do
      preimage = fn params ->
        request = Map.update!(call(%{"path" => "real"}), "params", &Map.merge(&1, params))

        {:ok, wrapped} =
          Digest.action_preimage(
            :tool_request,
            SecurityPayload.for_gate(request, :request),
            @context
          )

        {:ok, raw} = Digest.action_preimage(:tool_request, request, @context)

        assert wrapped == raw
        wrapped
      end

      honest = preimage.(%{})

      assert honest["arguments"] == %{"path" => "real"}

      for decoy <- [
            %{"params" => %{"arguments" => %{"path" => "decoy"}}},
            %{"params" => %{"name" => "other_tool", "arguments" => %{}}},
            %{"method" => "resources/read"}
          ] do
        assert preimage.(decoy) == honest
      end
    end

    test "a member of the result object named method stays application data" do
      context = %{phase: :tool_result, origin: :tool, sink: :model, tool: "repo_file_write"}
      opts = [request_action_digest: String.duplicate("a", 64)]

      preimage = fn result ->
        response = %{"jsonrpc" => "2.0", "id" => 1, "result" => result}

        {:ok, wrapped} =
          Digest.action_preimage(
            :tool_result,
            SecurityPayload.for_gate(response, :result),
            context,
            opts
          )

        {:ok, raw} = Digest.action_preimage(:tool_result, response, context, opts)

        assert wrapped == raw
        wrapped
      end

      plain = preimage.(%{"content" => []})

      refute Map.has_key?(plain, "method")
      assert preimage.(%{"content" => [], "method" => "tools/call"}) == plain
    end

    test "a gate payload whose tool or action is null is still read as a projection" do
      # A request the message names no tool for; the host context does.
      request = %{
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "tools/call",
        "params" => %{"arguments" => %{"path" => "docs/a.md"}}
      }

      wrapper = SecurityPayload.for_gate(request, :request)

      assert wrapper.tool == nil

      assert {:ok, wrapped} = Digest.action_preimage(:tool_request, wrapper, @context)
      assert {:ok, raw} = Digest.action_preimage(:tool_request, request, @context)

      assert wrapped == raw
      assert wrapped["arguments"] == %{"path" => "docs/a.md"}
      assert wrapped["method"] == "tools/call"

      other = put_in(request, ["params", "arguments", "path"], "docs/b.md")

      refute Digest.action_digest(
               :tool_request,
               SecurityPayload.for_gate(other, :request),
               @context
             ) ==
               Digest.action_digest(:tool_request, wrapper, @context)
    end

    test "only the gate payload shape is read as a projection" do
      projected = SecurityPayload.for_gate(call(%{"path" => "x"}), :request)

      # Outside the exact shape a null is application data and may be
      # refused, so the look-alikes below carry none.
      binding = Map.put(projected.binding, "protocol_version", "2026-07-28")
      wrapper = %{projected | binding: binding}

      assert {:ok, %{"arguments" => %{"path" => "x"}}} =
               Digest.action_preimage(:tool_request, wrapper, @context)

      for look_alike <- [
            Map.delete(wrapper, :text),
            %{"binding" => binding},
            %{wrapper | binding: Map.put(binding, "extra", "x")},
            %{wrapper | binding: Map.put(binding, "kind", "other")},
            %{wrapper | binding: Map.delete(binding, "payload")}
          ] do
        assert {:ok, preimage} = Digest.action_preimage(:tool_request, look_alike, @context)
        refute Map.has_key?(preimage, "arguments")
      end
    end
  end

  test "a context value that is an error tuple is refused, not left out" do
    context = [phase: :tool_request, actor: "agent-a", sandbox_id: {:error, :down}]

    assert SigilGuard.Attestation.Digest.context_digest(:tool_request, context) ==
             {:error, :invalid_payload}
  end
end

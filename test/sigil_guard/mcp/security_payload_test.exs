defmodule SigilGuard.MCP.SecurityPayloadTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.MCP.SecurityPayload

  doctest SecurityPayload

  test "binds structured requests and request-semantic metadata" do
    request = %{
      "jsonrpc" => "2.0",
      "id" => 17,
      "method" => "tools/call",
      "_agent_trust" => %{"signature" => "root-envelope"},
      "params" => %{
        "name" => "payments/create",
        "arguments" => %{
          "amount" => 1250,
          "approved" => false,
          "memo" => nil,
          "nested" => [%{"count" => 2}]
        },
        "_meta" => %{
          "traceparent" => "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01",
          "io.modelcontextprotocol/clientInfo" => %{"name" => "example", "version" => "1"},
          "io.modelcontextprotocol/clientCapabilities" => %{
            "extensions" => %{"com.example/review" => %{}}
          },
          "com.example/approvalMode" => "four-eyes"
        },
        "_agent_confirmation" => "confirmation-token"
      }
    }

    projection =
      SecurityPayload.request(request,
        protocol_version: "2026-07-28"
      )

    assert projection == %{
             "kind" => "request",
             "method" => "tools/call",
             "protocol_version" => "2026-07-28",
             "payload" => %{
               "name" => "payments/create",
               "arguments" => %{
                 "amount" => 1250,
                 "approved" => false,
                 "memo" => nil,
                 "nested" => [%{"count" => 2}]
               },
               "_meta" => %{
                 "io.modelcontextprotocol/clientCapabilities" => %{
                   "extensions" => %{"com.example/review" => %{}}
                 },
                 "com.example/approvalMode" => "four-eyes"
               }
             }
           }

    refute inspect(projection) =~ "confirmation-token"
    refute inspect(projection) =~ "root-envelope"
    refute inspect(projection) =~ "traceparent"
    refute inspect(projection) =~ "\"example\""
  end

  test "metadata capabilities and extensions change the security binding" do
    request = %{
      "method" => "tools/call",
      "params" => %{
        "name" => "review",
        "_meta" => %{
          "io.modelcontextprotocol/clientCapabilities" => %{"elicitation" => %{}},
          "com.example/mode" => "read"
        }
      }
    }

    changed_capability =
      put_in(
        request,
        ["params", "_meta", "io.modelcontextprotocol/clientCapabilities"],
        %{"sampling" => %{}}
      )

    changed_extension = put_in(request, ["params", "_meta", "com.example/mode"], "write")
    trace_only = put_in(request, ["params", "_meta", "traceparent"], "00-trace")

    refute SecurityPayload.request(request) == SecurityPayload.request(changed_capability)
    refute SecurityPayload.request(request) == SecurityPayload.request(changed_extension)
    assert SecurityPayload.request(request) == SecurityPayload.request(trace_only)
  end

  test "binds MRTR input requests, state, and retry responses" do
    result = %{
      "id" => "retry-2",
      "result" => %{
        "resultType" => "input_required",
        "requestState" => %{"cursor" => 4, "nonce" => "state"},
        "inputRequests" => %{
          "approval" => %{
            "method" => "elicitation/create",
            "params" => %{"message" => "Approve?"}
          }
        },
        "inputResponses" => %{"approval" => true}
      }
    }

    projection = SecurityPayload.result(result, protocol_version: "2026-07-28")

    assert projection["payload"]["resultType"] == "input_required"
    assert projection["payload"]["requestState"]["cursor"] == 4
    assert projection["payload"]["inputRequests"] != %{}
    assert projection["payload"]["inputResponses"] == %{"approval" => true}
    refute Map.has_key?(projection["payload"], "id")
  end

  test "different keys and non-string values produce different security bindings" do
    left = %{"method" => "tools/call", "params" => %{"arguments" => %{"limit" => 1}}}
    right = %{"method" => "tools/call", "params" => %{"arguments" => %{"offset" => 1}}}
    changed_value = put_in(left, ["params", "arguments", "limit"], 2)

    refute SecurityPayload.request(left) == SecurityPayload.request(right)
    refute SecurityPayload.request(left) == SecurityPayload.request(changed_value)

    gate = SecurityPayload.for_gate(left, :request)
    assert gate.binding == SecurityPayload.request(left)
    assert gate.action == "tools/call"
  end

  describe "context/3" do
    @call %{
      "method" => "tools/call",
      "server" => "cell-mcp",
      "params" => %{"name" => "cell.move", "arguments" => %{"x_mm" => 1}}
    }

    test "derives phase, origin, sink, tool, action, and server from the message" do
      assert %SigilGuard.Context{
               phase: :tool_request,
               origin: :model,
               sink: :tool,
               tool: "cell.move",
               action: "cell.move",
               mcp_server: "cell-mcp"
             } = SecurityPayload.context(@call, :request, %{})

      assert %SigilGuard.Context{phase: :tool_result, origin: :tool, sink: :model} =
               SecurityPayload.context(@call, :result, [])
    end

    test "a key present in the supplied context replaces the derived value" do
      context = SecurityPayload.context(@call, :request, tool: "other", sink: :external)

      assert context.tool == "other"
      assert context.sink == :external
      assert context.action == "cell.move"
    end

    test "a malformed name stays :invalid and a malformed server is dropped" do
      message = %{"params" => %{"name" => 7, "server" => 7}}
      context = SecurityPayload.context(message, :request, %{})

      assert context.tool == :invalid
      assert context.action == :invalid
      assert context.mcp_server == nil
    end

    test "a non-map message yields the direction defaults" do
      assert %SigilGuard.Context{tool: nil, action: nil, mcp_server: nil, phase: :tool_request} =
               SecurityPayload.context("plain", :request, :not_a_context)
    end
  end

  test "scalar messages get direction defaults and a false tool or action field is :invalid" do
    assert SecurityPayload.request("plain") == %{
             "kind" => "request",
             "method" => nil,
             "payload" => "plain",
             "protocol_version" => nil
           }

    assert SecurityPayload.result(nil) == %{
             "kind" => "result",
             "method" => nil,
             "payload" => nil,
             "protocol_version" => nil
           }

    assert SecurityPayload.tool_name(%{"tool" => false}) == :invalid
    assert SecurityPayload.action_name(%{"action" => false, "tool" => "fallback"}) == :invalid
  end
end

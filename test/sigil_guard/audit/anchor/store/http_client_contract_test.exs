defmodule SigilGuard.Audit.Anchor.Store.HTTPClientContractTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP
  alias SigilGuard.AuditProofFixture

  defmodule ErrorClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: {:error, :boom}
  end

  defmodule CrashClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: raise("adapter exploded")
  end

  defmodule BigBodyClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _) do
      {:ok, %{status: 200, headers: [], body: String.duplicate("x", 5_000)}}
    end
  end

  defmodule MangledClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _) do
      {:ok, %{status: 200, headers: [], body: "definitely not json"}}
    end
  end

  defmodule NoStatusClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: {:ok, %{body: "{}"}}
  end

  defmodule TimeoutClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, opts) do
      Process.put(:captured_timeout, opts[:timeout])
      {:ok, %{status: 200, headers: [], body: "{}"}}
    end
  end

  defmodule AtomClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: :timeout
  end

  defmodule ThrowClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: throw(:adapter_gave_up)
  end

  defmodule ExitClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: exit(:connection_process_down)
  end

  defmodule StubClient do
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(method, url, _, _, opts) do
      send(self(), {:request, method, url, opts})
      Process.get(:stub_response)
    end
  end

  setup do
    Application.delete_env(:sigil_guard, :http_client)
    on_exit(fn -> Application.delete_env(:sigil_guard, :http_client) end)
    %{anchor: anchor()}
  end

  describe "client resolution" do
    test "no configured client fails :http_client_not_configured", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/") ==
               {:error, :http_client_not_configured}
    end

    test "a module not exporting request/5 fails :http_client_not_configured", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: String) ==
               {:error, :http_client_not_configured}
    end

    test "the per-call client wins over the app-env client", ctx do
      Application.put_env(:sigil_guard, :http_client, ErrorClient)

      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: CrashClient) ==
               {:error, {:http_client_error, :adapter_crash}}
    end

    test "falls back to the app-env client when no per-call client is given", ctx do
      Application.put_env(:sigil_guard, :http_client, ErrorClient)

      assert Store.put(HTTP, ctx.anchor, url: "http://x/") ==
               {:error, {:http_client_error, :boom}}
    end
  end

  describe "failure surfacing" do
    test "an adapter error surfaces as {:http_client_error, reason}", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: ErrorClient) ==
               {:error, {:http_client_error, :boom}}
    end

    test "an adapter crash surfaces as {:http_client_error, :adapter_crash}", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: CrashClient) ==
               {:error, {:http_client_error, :adapter_crash}}
    end

    test "a response with no status surfaces as an :http_client_error", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: NoStatusClient) ==
               {:error, {:http_client_error, :invalid_response}}
    end

    test "an adapter return outside the contract surfaces as :invalid_response", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: AtomClient) ==
               {:error, {:http_client_error, :invalid_response}}
    end

    test "an adapter that throws or exits surfaces as :adapter_crash", ctx do
      for client <- [ThrowClient, ExitClient] do
        assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: client) ==
                 {:error, {:http_client_error, :adapter_crash}}
      end
    end

    test "a response body that is not a binary fails :invalid_response", ctx do
      for body <- [nil, %{"anchor_digest" => Anchor.digest(ctx.anchor)}, [~s({"worm":true})], 42] do
        stub({:ok, %{status: 200, headers: [], body: body}})

        assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient) ==
                 {:error, {:http_client_error, :invalid_response}}
      end
    end
  end

  describe "response guards" do
    test "a body over :max_body_bytes fails :response_too_large", ctx do
      assert Store.put(HTTP, ctx.anchor,
               url: "http://x/",
               http_client: BigBodyClient,
               max_body_bytes: 100
             ) == {:error, :response_too_large}
    end

    test "a mangled (non-JSON) body fails :invalid_body", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: MangledClient) ==
               {:error, :invalid_body}
    end

    test "malformed response headers are dropped and never supply the receipt uri", ctx do
      fallback = "http://x/audit/anchors##{Anchor.digest(ctx.anchor)}"

      stub(
        {:ok,
         %{
           status: 201,
           headers: [
             {"location", ["https://evil.example/a"]},
             :junk,
             {"x-n", 1},
             {"Location", "https://anchors.example/a/1"}
           ],
           body: ""
         }}
      )

      assert {:ok, %{"uri" => "https://anchors.example/a/1"}} =
               Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient)

      stub({:ok, %{status: 201, headers: [{"location", ["https://evil.example/a"]}], body: ""}})

      assert {:ok, %{"uri" => ^fallback}} =
               Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient)

      stub(
        {:ok, %{status: 201, headers: %{"location" => "https://anchors.example/a/1"}, body: ""}}
      )

      assert {:ok, %{"uri" => ^fallback}} =
               Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient)
    end

    test "a malformed :max_body_bytes is refused before any request", ctx do
      for bad <- [-1, "100", :infinity, nil, 1.5] do
        stub({:ok, %{status: 200, headers: [], body: "{}"}})

        assert Store.put(HTTP, ctx.anchor,
                 url: "http://x/",
                 http_client: StubClient,
                 max_body_bytes: bad
               ) == {:error, :invalid_options}

        refute_received {:request, _, _, _}
      end

      stub({:ok, %{status: 200, headers: [], body: "{}"}})
      assert {:ok, _} = Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient)
      assert_received {:request, :post, _, opts}
      assert opts[:max_body_bytes] == 1_048_576
    end

    test "a receipt url with a public IP literal is fetched; private and unlisted hosts are not",
         ctx do
      digest = Anchor.digest(ctx.anchor)
      stub({:ok, %{status: 200, headers: [], body: Jason.encode!(%{"record" => ctx.anchor})}})

      anchor = ctx.anchor

      assert {:ok, ^anchor} =
               Store.fetch(
                 HTTP,
                 %{"anchor_digest" => digest, "uri" => "https://203.0.113.9/a/1#latest"},
                 http_client: StubClient
               )

      assert_received {:request, :get, "https://203.0.113.9/a/1", _}

      assert {:ok, ^anchor} =
               Store.fetch(HTTP, %{"uri" => "https://[2001:db8::1]/a/1##{digest}"},
                 http_client: StubClient
               )

      assert_received {:request, :get, "https://[2001:db8::1]/a/1", _}

      for host <- ["10.0.0.8", "[fd00::1]", "[fe80::1]", "anchors.example", "例え.jp"] do
        assert Store.fetch(HTTP, %{"uri" => "https://#{host}/a/1##{digest}"},
                 http_client: StubClient
               ) ==
                 {:error, :unsafe_receipt_url}
      end

      refute_received {:request, _, _, _}
    end

    test "a remote receipt whose uri fragment is not a digest keeps its uri", ctx do
      digest = Anchor.digest(ctx.anchor)

      stub(
        {:ok,
         %{
           status: 200,
           headers: [],
           body:
             Jason.encode!(%{
               "anchor_digest" => digest,
               "uri" => "https://anchors.example/a/1#latest"
             })
         }}
      )

      assert {:ok, %{"uri" => "https://anchors.example/a/1#latest", "anchor_digest" => ^digest}} =
               Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: StubClient)
    end
  end

  describe "timeout" do
    test "the store passes the resolved timeout to the adapter", ctx do
      Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: TimeoutClient, timeout: 1234)
      assert Process.get(:captured_timeout) == 1234

      Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: TimeoutClient)
      assert Process.get(:captured_timeout) == 5_000
    end

    test "timeout: :infinity reaches the adapter and other atoms are refused", ctx do
      stub({:ok, %{status: 200, headers: [], body: "{}"}})

      assert {:ok, _} =
               Store.put(HTTP, ctx.anchor,
                 url: "http://x/",
                 http_client: StubClient,
                 timeout: :infinity
               )

      assert_received {:request, :post, _, opts}
      assert opts[:timeout] == :infinity

      assert Store.put(HTTP, ctx.anchor,
               url: "http://x/",
               http_client: StubClient,
               timeout: :forever
             ) ==
               {:error, :invalid_timeout}

      refute_received {:request, _, _, _}
    end
  end

  defp anchor do
    {_, anchor} =
      AuditProofFixture.anchor_fixture(storage: :http, uri: "https://x/1", signed: false)

    anchor
  end

  defp stub(response), do: Process.put(:stub_response, response)
end

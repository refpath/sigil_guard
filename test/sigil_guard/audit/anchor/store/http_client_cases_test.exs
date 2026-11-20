defmodule SigilGuard.Audit.Anchor.Store.HTTPClientCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP
  alias SigilGuard.Audit.Checkpoint

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
    %{anchor: anchor()}
  end

  defp anchor do
    events =
      1..2
      |> Enum.map(&Audit.new_event("test", "actor", "act#{&1}", "ok"))
      |> Audit.build_chain(:crypto.hash(:sha256, "http client contract test key"))

    {:ok, checkpoint} = Checkpoint.create(events, generated_at: "2026-01-01T00:00:00.000Z")

    Anchor.create(checkpoint,
      anchored_at: "2026-01-01T00:00:00.000Z",
      storage: :http,
      uri: "https://x/1"
    )
  end

  defp stub(response), do: Process.put(:stub_response, response)

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

    stub({:ok, %{status: 201, headers: %{"location" => "https://anchors.example/a/1"}, body: ""}})

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

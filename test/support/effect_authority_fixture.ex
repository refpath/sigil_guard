defmodule SigilGuard.EffectAuthorityFixture do
  @moduledoc """
  Neutral fixtures for the SP.19 physical-effect tests.

  `request/0` is the baseline request `R0`, `context/0` is `C0`, and
  `manifests/0` holds `M0`. The policy file returns `confirm` for the two cell
  tools and blocks everything else, so `R0` needs a confirmation token. Every
  identifier is synthetic.
  """

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.FixturePath

  @record_key "dev.sigilguard/effect"
  @actor "spiffe://example.test/agent/planner"
  @now ~U[2026-11-19 12:01:00.000Z]
  @tools ["cell.move", "cell.grip"]

  @doc "Return the baseline `tools/call` request with its binding record."
  @spec request() :: map()
  def request, do: FixturePath.read_json!("effect_authority/request.json")

  @doc "Return the binding record carried by `request/0`."
  @spec record() :: map()
  def record, do: request()["params"]["_meta"][@record_key]

  @doc "Return `request` with its binding record replaced by `record`."
  @spec put_record(map(), term()) :: map()
  def put_record(request, record),
    do: put_in(request, ["params", "_meta", @record_key], record)

  @doc "Return `request` without a binding record."
  @spec drop_record(map()) :: map()
  def drop_record(request), do: update_in(request, ["params"], &Map.delete(&1, "_meta"))

  @doc "Return the principal the fixtures act as."
  @spec actor() :: String.t()
  def actor, do: @actor

  @doc "Return a time inside the baseline dispatch window."
  @spec now() :: DateTime.t()
  def now, do: @now

  @doc "Return the baseline host context."
  @spec context() :: keyword()
  def context do
    [
      actor: @actor,
      trust_level: :high,
      mcp_server: "cell-mcp",
      resource_uri: "urn:example:cell-a",
      metadata: %{sandbox_id: "sandbox-1", isolation_level: "container"}
    ]
  end

  @doc "Return the pinned manifests for the two cell tools."
  @spec manifests() :: %{String.t() => map()}
  def manifests do
    Map.new(@tools, &{&1, FixturePath.read_json!("effect_authority/#{&1}.manifest.json")})
  end

  @doc "Return the compiled policy file that confirms the two cell tools."
  @spec policy() :: map()
  def policy do
    {:ok, policy} = PolicyFile.parse(FixturePath.read!("effect_authority/cell.policy"))
    policy
  end

  @doc "Return the confirmation key the fixtures issue tokens with."
  @spec confirmation_key() :: binary()
  def confirmation_key, do: :crypto.hash(:sha256, "effect-authority-fixture")

  @doc "Return gateway options for a physical-effect request, with `overrides` applied."
  @spec gateway_opts(keyword()) :: keyword()
  def gateway_opts(overrides \\ []) do
    Keyword.merge(
      [
        manifests: manifests(),
        require_manifest: true,
        boundary_policy: policy(),
        effect_binding: :required,
        confirmation_key: confirmation_key(),
        now: @now
      ],
      overrides
    )
  end
end

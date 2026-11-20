defmodule SigilGuard.ToolGateway do
  @moduledoc """
  Enforces manifests, attestations, and confirmations around tool boundaries.

  `SigilGuard.ToolGateway` is the enforcement core for MCP-shaped tool calls
  and results. It combines pinned `SigilGuard.CapabilityManifest` values,
  Agent Trust attestation verification, action-bound confirmation tokens, and
  `SigilGuard.Runtime.Gate` boundary decisions.
  `SigilGuard.MCP.Gateway` is the stable transport-facing facade that delegates
  here with MCP compatibility defaults.

  The gateway remains transport-neutral. The host owns protocol negotiation,
  `server/discover`, subscriptions, authorization, transport headers, schema
  validation, and execution. For MCP v2 (`2026-07-28`), pass the selected
  revision in the request `_meta` or through `:protocol_version`. SigilGuard
  binds the revision and behavior-changing metadata to the guarded action, but
  it does not claim that a decoded map is wire-valid.

  Manifest checks run before the runtime gate. Confirmation and attestation
  digests use a structured security projection, preserving map keys, arrays,
  numbers, booleans, nulls, multi-round-trip input, request state, client
  capabilities, and extension metadata that can affect behavior. JSON-RPC
  correlation fields and operational tracing metadata are excluded.

  ## Choosing an entry point

  Use `guard_request/3` before executing a tool and `guard_result/3` before
  returning output to a model. The `guarded_request/3` and `guarded_result/3`
  variants also shape adapter-friendly JSON-RPC responses. Use
  `verify_manifest/2` whenever a discovered tool definition is refreshed.

  ## Examples

      request = %{
        "method" => "tools/call",
        "params" => %{
          "name" => "read_file",
          "arguments" => %{"path" => "README.md"},
          "_meta" => %{
            "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities" => %{}
          }
        }
      }

      context = [phase: :tool_request, origin: :model, sink: :tool, trust_level: :medium]

      decision = SigilGuard.ToolGateway.guard_request(request, context)
      decision.action in [:allow, :redact, :confirm, :quarantine, :block]
  """
  @moduledoc since: "1.0.0"

  alias SigilGuard.Attestation
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Crypto
  alias SigilGuard.Decision
  alias SigilGuard.MCP.Protocol
  alias SigilGuard.MCP.SecurityPayload
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Telemetry
  alias SigilGuard.ToolGateway.Base, as: GatewayBase
  alias SigilGuard.ToolGateway.Effect
  alias SigilGuard.TrustBundle

  @typedoc "A closed reason for rejecting a manifest, request, or result."
  @type deny_reason ::
          :unknown_manifest
          | :invalid_manifest
          | :manifest_digest_mismatch
          | :manifest_expired
          | :schema_digest_mismatch
          | :invalid_header_annotation
          | :sensitive_header_param
          | :suspicious_required_param
          | :resource_mismatch
          | :audience_mismatch
          | :token_passthrough_denied
          | :sandbox_required
          | :app_visibility_denied
          | :app_server_mismatch
          | :invalid_attestation
          | :invalid_payload
          | :invalid_confirmation_token
          | :missing_confirmation_key
          | :confirmation_failed
          | :effect_binding_required
          | :invalid_effect_binding
          | :effect_replay_protection_required

  @typedoc "An attestation construction or signing failure."
  @type attest_error :: Attestation.from_decision_error() | Attestation.sign_error()

  @typedoc "A confirmation-token issue failure."
  @type confirmation_issue_error ::
          :invalid_key
          | :not_confirmable
          | :invalid_ttl
          | :invalid_actor
          | :invalid_nonce
          | :invalid_now
          | :invalid_payload

  @doc """
  Guard a tool request using manifest checks before runtime policy evaluation.

  Supported options:

    * `:manifests` - map of tool name to pinned manifest, or `{pinned, observed}`
      tuples when the observed manifest is supplied separately.
    * `:require_manifest` - block unknown tools when no manifest resolves.
      Defaults to `true` when manifests are configured, otherwise `false`.
    * `:allow_suspicious_params` - explicit boundary-policy escape hatch for
      disclosed suspicious required parameters.
    * `:attestation` - `:off`, `:optional`, or `:required`.
    * `:confirmation` - `:honor` or `:off`; defaults to `:honor`.
    * `:confirmation_token`, `:confirmation_key`, `:consume_confirmation`,
      `:now` - forwarded to token verification.
    * `:effect_binding` - `:off` (default) or `:required`. `:required` marks a
      request that changes the physical world. The request must carry a valid
      `SigilGuard.EffectAuthority` binding record, `consume_confirmation: false`
      is refused, an inbound attestation nonce is consumed once on the pass
      that allows execution, and every decision records `action_digest`,
      `payload_digest`, and `context_digest` for the host ledger.
  """
  @spec guard_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    payload = request_payload(request, opts)
    request_context = SecurityPayload.context(request, :request, context)
    effect = Effect.new(request, payload, request_context, opts)

    decision =
      with :ok <- Effect.check_option(effect),
           {:ok, capability} <- request_manifest(payload.tool, opts),
           :ok <- request_manifest_freshness(capability, opts),
           :ok <- passthrough_resource_audience(capability, opts),
           :ok <- verify_caller_visibility(capability, request_context),
           :ok <- require_sandbox(capability, request_context),
           :ok <- verify_inbound_attestation(request, payload, request_context, capability, opts),
           :ok <- Effect.check_request(effect) do
        payload
        |> Gate.evaluate(request_context, gate_opts(opts, capability))
        |> put_protocol_metadata(request, opts)
        |> put_manifest_metadata(capability)
        |> maybe_force_suspicious_confirmation(payload, request_context, capability, opts)
        |> maybe_apply_confirmation(payload, request_context, request, opts)
        |> consume_effect_attestation(
          effect,
          request,
          {payload, request_context, capability},
          opts
        )
      else
        {:error, denial} ->
          denial
          |> deny(payload, request_context)
          |> put_protocol_metadata(request, opts)
      end

    decision
    |> put_effect_metadata(effect)
    |> emit_mcp_decision()
  end

  @doc """
  Verify an observed manifest against the configured manifest set.
  """
  @spec verify_manifest(String.t() | map(), keyword()) ::
          {:ok, CapabilityManifest.t()}
          | {:error,
             :unknown_manifest
             | :invalid_manifest
             | :manifest_expired
             | :manifest_digest_mismatch
             | :schema_digest_mismatch
             | :invalid_header_annotation
             | :sensitive_header_param
             | :suspicious_required_param}
  def verify_manifest(observed, opts) when is_map(observed) do
    opts = Keyword.put(opts, :require_manifest, true)

    with {:ok, server} <- required_server(opts),
         {:ok, tool} <- observed_tool_name(observed),
         {:ok, pinned} <- resolve_manifest(tool, opts),
         :ok <- matching_server(server, pinned),
         {:ok, observed_manifest} <- observed_manifest(observed, pinned),
         :ok <- CapabilityManifest.verify(pinned, observed_manifest),
         {:ok, capability} <- manifest_struct(observed_manifest),
         :ok <- manifest_freshness(capability, opts) do
      {:ok, capability}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_manifest(tool, opts) when is_binary(tool) do
    opts = Keyword.put(opts, :require_manifest, true)

    with {:ok, capability} <- resolve_manifest(tool, opts),
         :ok <- maybe_match_server(capability, opts),
         :ok <- manifest_freshness(capability, opts) do
      {:ok, capability}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_manifest(_, _), do: {:error, :unknown_manifest}

  @doc """
  Verify a refreshed `tools/list` result after the host receives a list-change
  notification through `subscriptions/listen`.

  Every observed entry is revalidated against its pinned manifest. The
  function stops at the first mismatch and never returns a partially verified
  list.
  """
  @spec verify_list_changed([map()], keyword()) ::
          {:ok, [CapabilityManifest.t()]} | {:error, deny_reason()}
  def verify_list_changed(observed_tools, opts) when is_list(observed_tools) do
    result =
      Enum.reduce_while(observed_tools, {:ok, []}, fn observed, {:ok, capabilities} ->
        case verify_manifest(observed, opts) do
          {:ok, capability} -> {:cont, {:ok, [capability | capabilities]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, capabilities} -> {:ok, Enum.reverse(capabilities)}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_list_changed(_, _), do: {:error, :invalid_manifest}

  @doc """
  Build and sign a `tool_request` attestation envelope.
  """
  @spec attest_request(Decision.t(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_request(decision, context, opts \\ [])

  def attest_request(%Decision{} = decision, context, opts) when is_list(opts) do
    with {:ok, signer} <- required_attestation_signer(opts),
         {:ok, opts} <- attestation_opts(opts, :tool_request),
         {:ok, statement} <- Attestation.from_decision(decision, context, opts) do
      Attestation.sign(statement, signer, opts)
    end
  end

  def attest_request(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Build and sign a `tool_result` attestation envelope.
  """
  @spec attest_result(Decision.t(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_result(decision, context, opts \\ [])

  def attest_result(%Decision{} = decision, context, opts) when is_list(opts) do
    with {:ok, signer} <- required_attestation_signer(opts),
         {:ok, opts} <- attestation_opts(opts, :tool_result),
         {:ok, statement} <- Attestation.from_decision(decision, context, opts) do
      Attestation.sign(statement, signer, opts)
    end
  end

  def attest_result(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Issue a confirmation token for a confirm-required tool request or result.

  Pass `direction: :request` (default) for tool calls and `direction: :result`
  for tool output. The token is bound to the same normalized payload and context
  shape used by `guard_request/3` or `guard_result/3`.
  """
  @spec issue_confirmation(
          term(),
          Context.t() | map() | keyword(),
          Decision.t(),
          binary(),
          keyword()
        ) ::
          {:ok, String.t()} | {:error, confirmation_issue_error()}
  def issue_confirmation(payload, context, %Decision{} = decision, key, opts \\ []) do
    with {:ok, direction} <- confirmation_direction(opts) do
      payload
      |> confirmation_payload(direction, opts)
      |> Confirmation.issue(
        confirmation_context(payload, context, direction),
        decision,
        key,
        confirmation_issue_opts(opts)
      )
    end
  end

  @doc """
  Guard a tool result before it is returned to the model.
  """
  @spec guard_result(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    payload = result_payload(result, opts)
    result_context = SecurityPayload.context(result, :result, context)
    capability = result_capability(result_context, opts)

    decision =
      case request_action_digest(opts) do
        :ok ->
          payload
          |> Gate.evaluate(result_context, gate_opts(opts, capability))
          |> put_protocol_metadata(result, opts)
          |> put_manifest_metadata(capability)
          |> put_result_binding_metadata(opts)
          |> maybe_apply_result_confirmation(payload, result_context, result, opts)

        {:error, reason} ->
          reason
          |> deny(payload, result_context)
          |> put_protocol_metadata(result, opts)
      end

    emit_mcp_decision(decision)
  end

  @doc """
  Guard a tool request and return the JSON-RPC-compatible tuple shape.
  """
  @spec guarded_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_request(request, context \\ %{}, opts \\ []) do
    decision = guard_request(request, context, opts)

    if GatewayBase.executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, GatewayBase.request_id(request), opts), decision}
    end
  end

  @doc """
  Guard a tool result and return the JSON-RPC-compatible tuple shape.
  """
  @spec guarded_result(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_result(result, context \\ %{}, opts \\ []) do
    decision = guard_result(result, context, opts)

    case decision.action do
      :allow ->
        {:ok, GatewayBase.jsonrpc_result(result, GatewayBase.request_id(result), opts), decision}

      :redact ->
        id = GatewayBase.request_id(result)

        {:ok, GatewayBase.sanitized_result(result, decision, id, opts), decision}

      _ ->
        {:error, response_for_decision(decision, GatewayBase.request_id(result), opts), decision}
    end
  end

  @doc """
  Return the audit-safe JSON-RPC response for a boundary decision.

  The response contains status and sanitized decision data, never the raw
  rejected payload.
  """
  @spec response_for_decision(Decision.t(), term(), keyword()) :: map()
  def response_for_decision(%Decision{} = decision, id \\ nil, opts \\ []) do
    GatewayBase.response_for_decision(decision, id, opts)
  end

  @doc """
  Start a chunk-safe sanitizer for a streaming tool result.

  The stream retains enough data to detect a sensitive value split across
  chunk boundaries.
  """
  @spec stream_result(Context.t() | map() | keyword(), keyword()) :: SigilGuard.Runtime.Stream.t()
  def stream_result(context \\ %{}, opts \\ []), do: GatewayBase.stream_result(context, opts)

  @doc """
  Push one result chunk through the sanitizer.

  A successful `nil` response means the sanitizer is retaining a safe
  holdback; callers must not emit the original chunk.
  """
  @spec guarded_result_chunk(SigilGuard.Runtime.Stream.t(), String.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def guarded_result_chunk(stream, chunk, opts \\ []),
    do: GatewayBase.guarded_result_chunk(stream, chunk, opts)

  @doc """
  Finish a guarded result stream and return any remaining safe output.

  Call this exactly once after the final input chunk.
  """
  @spec finish_guarded_result_stream(SigilGuard.Runtime.Stream.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def finish_guarded_result_stream(stream, opts \\ []),
    do: GatewayBase.finish_guarded_result_stream(stream, opts)

  defp resolve_manifest(nil, opts) do
    if require_manifest?(opts) do
      {:error, :unknown_manifest}
    else
      {:ok, nil}
    end
  end

  defp resolve_manifest(tool, opts) do
    case manifest_entry(tool, opts) do
      {:ok, entry} -> normalize_manifest_entry(tool, entry)
      :error -> maybe_allow_missing_manifest(opts)
    end
  end

  defp request_action_digest(opts) do
    case Keyword.fetch(opts, :request_action_digest) do
      {:ok, digest} when is_binary(digest) ->
        if digest =~ ~r/\A[0-9a-f]{64}\z/, do: :ok, else: {:error, :invalid_payload}

      {:ok, _} ->
        {:error, :invalid_payload}

      :error ->
        :ok
    end
  end

  defp confirmation_direction(opts) do
    case Keyword.get(opts, :direction, :request) do
      direction when direction in [:request, :result] -> {:ok, direction}
      _ -> {:error, :invalid_payload}
    end
  end

  defp confirmation_payload(payload, :request, opts), do: request_payload(payload, opts)
  defp confirmation_payload(payload, :result, opts), do: result_payload(payload, opts)

  defp confirmation_context(payload, context, direction),
    do: SecurityPayload.context(payload, direction, context)

  defp confirmation_issue_opts(opts) do
    opts
    |> Keyword.take([:actor, :ttl_ms, :now, :nonce])
    |> maybe_put_issue_manifest(opts)
  end

  defp maybe_put_issue_manifest(issue_opts, opts) do
    cond do
      is_binary(Keyword.get(opts, :manifest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest))

      match?(%CapabilityManifest{}, Keyword.get(opts, :manifest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest).digest)

      is_binary(Keyword.get(opts, :manifest_digest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest_digest))

      true ->
        issue_opts
    end
  end

  defp maybe_allow_missing_manifest(opts) do
    if require_manifest?(opts) do
      {:error, :unknown_manifest}
    else
      {:ok, nil}
    end
  end

  defp manifest_entry(tool, opts) do
    server = Keyword.get(opts, :server)
    manifests = Keyword.get(opts, :manifests, %{})
    trust_bundle = Keyword.get(opts, :trust_bundle)

    case fetch_manifest(manifests, tool, server) do
      {:ok, _} = entry -> entry
      :error -> fetch_bundle_manifest(trust_bundle, tool, server)
    end
  end

  defp require_manifest?(opts) do
    Keyword.get_lazy(opts, :require_manifest, fn ->
      Keyword.has_key?(opts, :manifests) or Keyword.has_key?(opts, :trust_bundle)
    end)
  end

  defp fetch_manifest(manifests, tool, server) when is_map(manifests) do
    atom_tool =
      try do
        {:ok, String.to_existing_atom(tool)}
      rescue
        ArgumentError -> :error
      end

    cond do
      present?(server) and Map.has_key?(manifests, {server, tool}) ->
        {:ok, Map.fetch!(manifests, {server, tool})}

      Map.has_key?(manifests, tool) ->
        {:ok, Map.fetch!(manifests, tool)}

      match?({:ok, _}, atom_tool) and Map.has_key?(manifests, elem(atom_tool, 1)) ->
        {:ok, Map.fetch!(manifests, elem(atom_tool, 1))}

      true ->
        :error
    end
  end

  defp fetch_manifest(_, _, _), do: :error

  defp fetch_bundle_manifest(%TrustBundle{} = bundle, tool, server) do
    bundle
    |> TrustBundle.tools()
    |> fetch_manifest_from_list(tool, server)
  end

  defp fetch_bundle_manifest(%{"tools" => tools}, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(%{tools: tools}, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(tools, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(_, _, _), do: :error

  defp fetch_manifest_from_list(tools, tool, server) do
    Enum.find_value(tools, :error, fn entry ->
      with {:ok, capability} <- manifest_struct(entry),
           :ok <- matching_tool_name(tool, capability),
           :ok <- optional_matching_server(server, capability) do
        {:ok, capability}
      else
        _ -> false
      end
    end)
  end

  defp normalize_manifest_entry(tool, {pinned, observed}) do
    with {:ok, pinned} <- manifest_struct(pinned),
         :ok <- CapabilityManifest.verify(pinned, observed),
         {:ok, observed} <- manifest_struct(observed),
         :ok <- matching_tool_name(tool, observed) do
      {:ok, observed}
    end
  end

  defp normalize_manifest_entry(tool, manifest) do
    with {:ok, manifest} <- manifest_struct(manifest),
         :ok <- matching_tool_name(tool, manifest) do
      {:ok, manifest}
    end
  end

  defp manifest_struct(%CapabilityManifest{} = manifest), do: {:ok, manifest}

  defp manifest_struct(manifest) when is_map(manifest) do
    CapabilityManifest.new(manifest)
  end

  defp manifest_struct(_), do: {:error, :invalid_manifest}

  defp matching_tool_name(tool, %CapabilityManifest{name: tool}), do: :ok
  defp matching_tool_name(_, _), do: {:error, :manifest_digest_mismatch}

  defp required_server(opts) do
    case Keyword.get(opts, :server) do
      server when is_binary(server) and server != "" -> {:ok, server}
      _ -> {:error, :unknown_manifest}
    end
  end

  defp maybe_match_server(%CapabilityManifest{} = capability, opts) do
    case Keyword.get(opts, :server) do
      nil -> :ok
      server -> matching_server(server, capability)
    end
  end

  defp optional_matching_server(nil, _), do: :ok
  defp optional_matching_server("", _), do: :ok
  defp optional_matching_server(server, capability), do: matching_server(server, capability)

  defp matching_server(server, %CapabilityManifest{server: server}), do: :ok
  defp matching_server(_, _), do: {:error, :unknown_manifest}

  defp observed_tool_name(observed) do
    case observed_field(observed, "name", :name) do
      name when is_binary(name) and name != "" -> {:ok, name}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp observed_manifest(observed, %CapabilityManifest{} = pinned) do
    if carried_manifest?(observed) do
      normalize_observed_carried_manifest(observed)
    else
      observed_list_manifest(observed, pinned)
    end
  end

  defp carried_manifest?(observed) do
    manifest_format = observed_field(observed, "manifest_format", :manifest_format)

    is_binary(manifest_format)
  end

  defp normalize_observed_carried_manifest(observed) do
    normalized =
      Map.new(observed, fn
        {:inputSchema, value} -> {"input_schema", value}
        {"inputSchema", value} -> {"input_schema", value}
        {:outputSchema, value} -> {"output_schema", value}
        {"outputSchema", value} -> {"output_schema", value}
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        pair -> pair
      end)

    {:ok, normalized}
  end

  defp observed_list_manifest(observed, %CapabilityManifest{} = pinned) do
    with {:ok, name} <- required_observed_string(observed, "name", :name),
         {:ok, description} <- required_observed_string(observed, "description", :description),
         {:ok, title} <- optional_observed_string(observed, "title", :title),
         {:ok, icons} <- optional_observed_list(observed, "icons", :icons),
         {:ok, input_schema} <- required_observed_map(observed, "inputSchema", :input_schema),
         {:ok, output_schema} <- optional_observed_map(observed, "outputSchema", :output_schema),
         {:ok, annotations} <- optional_observed_map(observed, "annotations", :annotations),
         {:ok, ui} <- optional_observed_ui(observed),
         :ok <- required_when_pinned(title, pinned.title),
         :ok <- required_when_pinned(icons, pinned.icons),
         :ok <- required_when_pinned(output_schema, pinned.output_schema),
         :ok <- required_when_pinned(annotations, pinned.annotations),
         :ok <- required_when_pinned(ui, pinned.ui) do
      manifest =
        pinned
        |> pinned_manifest_map()
        |> Map.put("name", name)
        |> Map.put("description", description)
        |> Map.put("input_schema", input_schema)
        |> maybe_put_observed("title", title)
        |> maybe_put_observed("icons", icons)
        |> maybe_put_observed("output_schema", output_schema)
        |> maybe_put_observed("annotations", annotations)
        |> maybe_put_observed("ui", ui)

      {:ok, manifest}
    end
  end

  defp pinned_manifest_map(%CapabilityManifest{} = pinned) do
    pinned
    |> Map.from_struct()
    |> Map.drop([
      :annotations_sha256,
      :description_sha256,
      :digest,
      :icons_sha256,
      :input_schema_sha256,
      :output_schema_sha256,
      :title_sha256,
      :ui_sha256,
      :preimage
    ])
    |> Enum.reduce(%{}, fn
      {_, nil}, acc -> acc
      {key, value}, acc -> Map.put(acc, Atom.to_string(key), value)
    end)
  end

  defp observed_field(map, string_key, atom_key) do
    snake_key = Atom.to_string(atom_key)

    cond do
      Map.has_key?(map, string_key) -> Map.fetch!(map, string_key)
      Map.has_key?(map, snake_key) -> Map.fetch!(map, snake_key)
      Map.has_key?(map, atom_key) -> Map.fetch!(map, atom_key)
      true -> nil
    end
  end

  defp required_observed_string(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp required_observed_map(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      value when is_map(value) -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_observed_map(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      nil -> {:ok, nil}
      value when is_map(value) -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_observed_string(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_observed_list(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      nil -> {:ok, nil}
      value when is_list(value) -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_observed_ui(observed) do
    case observed_field(observed, "_meta", :_meta) do
      nil -> {:ok, nil}
      meta when is_map(meta) -> normalize_observed_ui(Map.get(meta, "ui", Map.get(meta, :ui)))
      _ -> {:error, :invalid_manifest}
    end
  end

  defp normalize_observed_ui(nil), do: {:ok, nil}

  defp normalize_observed_ui(ui) when is_map(ui) do
    uri = Map.get(ui, "resourceUri", Map.get(ui, :resourceUri))
    visibility = Map.get(ui, "visibility", Map.get(ui, :visibility, ["model", "app"]))

    if (is_nil(uri) or is_binary(uri)) and is_list(visibility) do
      normalized = %{"visibility" => Enum.sort(visibility)}
      {:ok, if(is_nil(uri), do: normalized, else: Map.put(normalized, "resource_uri", uri))}
    else
      {:error, :invalid_manifest}
    end
  end

  defp normalize_observed_ui(_), do: {:error, :invalid_manifest}

  defp required_when_pinned(_, nil), do: :ok
  defp required_when_pinned(nil, _), do: {:error, :invalid_manifest}
  defp required_when_pinned(_, _), do: :ok

  defp maybe_put_observed(manifest, _, nil), do: manifest
  defp maybe_put_observed(manifest, key, value), do: Map.put(manifest, key, value)

  # A denial for a manifest that drifted from its pin says which digest was
  # expected, which arrived, and in which preimage fields they differ.
  defp request_manifest(tool, opts) do
    with {:error, reason} <- resolve_manifest(tool, opts),
         do: {:error, drift_denial(reason, tool, opts)}
  end

  defp drift_denial(reason, tool, opts) when is_binary(tool) do
    with {:ok, {pinned, observed}} <- manifest_entry(tool, opts),
         {:ok, facts} <- drift_facts(pinned, observed) do
      {reason, facts}
    else
      _ -> reason
    end
  end

  defp drift_denial(reason, _, _), do: reason

  defp drift_facts(pinned, observed) do
    with {:ok, pinned} <- manifest_struct(pinned),
         {:ok, received} <- manifest_struct(observed),
         {:ok, fields} <- CapabilityManifest.drifted_fields(pinned, received) do
      {:ok,
       %{
         expected_manifest_digest: pinned.digest,
         received_manifest_digest: received.digest,
         drifted_fields: fields
       }}
    end
  end

  # A denial for an expired manifest says when it expired.
  defp request_manifest_freshness(capability, opts) do
    with {:error, :manifest_expired} <- manifest_freshness(capability, opts),
         do: {:error, {:manifest_expired, %{expires_at: capability.expires_at}}}
  end

  defp manifest_freshness(nil, _), do: :ok

  defp manifest_freshness(%CapabilityManifest{expires_at: expires_at}, opts) do
    with {:ok, expires_at, _} <- DateTime.from_iso8601(expires_at),
         {:ok, now} <- now(opts),
         {:ok, max_skew_ms} <- max_skew_ms(opts) do
      expires_at = DateTime.add(expires_at, max_skew_ms, :millisecond)

      if DateTime.compare(now, expires_at) == :gt do
        {:error, :manifest_expired}
      else
        :ok
      end
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp audiences(audience) when is_list(audience),
    do: if(List.improper?(audience), do: [], else: audience)

  defp audiences(audience), do: [audience]

  defp max_skew_ms(opts) do
    case Keyword.get(opts, :max_skew_ms, 0) do
      skew when is_integer(skew) and skew >= 0 -> {:ok, skew}
      _ -> {:error, :invalid_max_skew}
    end
  end

  defp now(opts) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_now}
    end
  end

  # The sandbox matrix and `effect:` rules read the classes a verified manifest
  # declares. Only a resolved manifest supplies them; a caller option cannot.
  defp gate_opts(opts, %CapabilityManifest{digest: digest, side_effects: effects})
       when is_binary(digest) and is_list(effects),
       do: Keyword.put(opts, :manifest_facts, %{manifest_digest: digest, side_effects: effects})

  defp gate_opts(opts, _), do: Keyword.delete(opts, :manifest_facts)

  # A result names no tool of its own. When the host's context does and a
  # current manifest is pinned for it, that manifest gives the sandbox matrix
  # its classes and lets a result token bind it. Anything else is no manifest,
  # as before: a result is never blocked for lacking one.
  defp result_capability(%Context{tool: tool}, opts) when is_binary(tool) do
    with {:ok, %CapabilityManifest{} = capability} <- resolve_manifest(tool, opts),
         :ok <- manifest_freshness(capability, opts) do
      capability
    else
      _ -> nil
    end
  end

  defp result_capability(_, _), do: nil

  # Passthrough compares two host options and needs no manifest.
  defp passthrough_resource_audience(nil, opts), do: token_passthrough(opts)

  defp passthrough_resource_audience(%CapabilityManifest{} = capability, opts) do
    with :ok <- token_passthrough(opts),
         :ok <- resource_match(capability, opts) do
      audience_match(capability, opts)
    end
  end

  defp token_passthrough(opts) do
    audience = Keyword.get(opts, :audience)
    self_resource = Keyword.get(opts, :self_resource)

    if present?(audience) and present?(self_resource) and
         audience_contains?(audience, self_resource) do
      {:error,
       {:token_passthrough_denied,
        %{
          audience: audience,
          self_resource: self_resource
        }}}
    else
      :ok
    end
  end

  defp resource_match(%CapabilityManifest{server: server}, opts) do
    case Keyword.get(opts, :resource) do
      nil -> :ok
      ^server -> :ok
      resource -> {:error, {:resource_mismatch, %{server: server, resource: resource}}}
    end
  end

  defp audience_match(%CapabilityManifest{server: server, audience: manifest_audience}, opts) do
    case Keyword.get(opts, :audience) do
      nil ->
        :ok

      audience ->
        accepted = [server | List.wrap(manifest_audience || [])]

        if Enum.any?(audiences(audience), &(&1 in accepted)) do
          :ok
        else
          {:error,
           {:audience_mismatch,
            %{
              audience: audience,
              accepted_audiences: accepted,
              server: server
            }}}
        end
    end
  end

  defp audience_contains?(audience, value), do: value in List.wrap(audience)
  defp present?(value), do: value not in [nil, ""]

  defp verify_caller_visibility(nil, %Context{origin: :app}),
    do: {:error, :app_visibility_denied}

  defp verify_caller_visibility(nil, _), do: :ok

  defp verify_caller_visibility(
         %CapabilityManifest{server: server, ui: ui},
         %Context{origin: :app, mcp_server: server}
       ) do
    if visible_to?(ui, "app"), do: :ok, else: {:error, :app_visibility_denied}
  end

  defp verify_caller_visibility(%CapabilityManifest{}, %Context{origin: :app}),
    do: {:error, :app_server_mismatch}

  # Every caller that is not the App is held to the tool's model visibility:
  # an App-only tool has exactly one permitted origin.
  defp verify_caller_visibility(%CapabilityManifest{ui: ui}, %Context{}) do
    if visible_to?(ui, "model"), do: :ok, else: {:error, :app_visibility_denied}
  end

  defp visible_to?(nil, "model"), do: true
  defp visible_to?(nil, "app"), do: false

  defp visible_to?(%{"visibility" => visibility}, caller) when is_list(visibility),
    do: caller in visibility

  defp visible_to?(_, _), do: false

  defp require_sandbox(nil, _), do: :ok
  defp require_sandbox(%CapabilityManifest{sandbox: %{"required" => false}}, _), do: :ok

  defp require_sandbox(
         %CapabilityManifest{name: tool, sandbox: %{"min_isolation" => min_isolation}},
         context
       ) do
    {sandbox_id, isolation_level} = sandbox_facts(context)

    if present?(sandbox_id) and isolation_sufficient?(isolation_level, min_isolation) do
      :ok
    else
      {:error,
       {:sandbox_required,
        sandbox_denial_metadata(tool, min_isolation, isolation_level, sandbox_id)}}
    end
  end

  defp require_sandbox(%CapabilityManifest{name: tool}, context) do
    {sandbox_id, isolation_level} = sandbox_facts(context)

    {:error, {:sandbox_required, sandbox_denial_metadata(tool, nil, isolation_level, sandbox_id)}}
  end

  # The context fields are the ones the SP.01 context digest binds. Context
  # metadata is the older carrier and is read when a field is unset.
  defp sandbox_facts(%Context{} = context) do
    metadata = sandbox_metadata(context)

    {context.sandbox_id || metadata[:sandbox_id] || metadata["sandbox_id"],
     isolation_name(
       context.isolation_level || metadata[:isolation_level] || metadata["isolation_level"]
     )}
  end

  defp isolation_name(level) when is_atom(level) and not is_nil(level), do: Atom.to_string(level)
  defp isolation_name(level), do: level

  # The gate rejects a context whose metadata is not a map; until then it
  # simply names no sandbox.
  defp sandbox_metadata(%Context{metadata: metadata})
       when is_map(metadata) and not is_struct(metadata),
       do: metadata

  defp sandbox_metadata(%Context{}), do: %{}

  defp sandbox_denial_metadata(tool, required_isolation, isolation_level, sandbox_id) do
    %{
      tool: tool,
      required_isolation: required_isolation,
      received_isolation: isolation_level,
      sandbox_id_present: present?(sandbox_id)
    }
  end

  defp isolation_sufficient?(received, required) do
    isolation_rank(received) >= isolation_rank(required)
  end

  defp isolation_rank("container"), do: 1
  defp isolation_rank("vm"), do: 2
  defp isolation_rank("remote_attested"), do: 3
  defp isolation_rank(_), do: 0

  defp verify_inbound_attestation(request, payload, context, capability, opts) do
    case Keyword.get(opts, :attestation, :off) do
      :off ->
        :ok

      :optional ->
        case Attestation.fetch(request) do
          {:ok, envelope} ->
            verify_attestation_envelope(envelope, payload, context, capability, opts)

          :error ->
            :ok
        end

      :required ->
        case Attestation.fetch(request) do
          {:ok, envelope} ->
            verify_attestation_envelope(envelope, payload, context, capability, opts)

          :error ->
            {:error, :invalid_attestation}
        end

      _ ->
        {:error, :invalid_attestation}
    end
  end

  defp verify_attestation_envelope(envelope, payload, context, capability, opts) do
    verify_opts = inbound_verify_opts(payload, context, capability, opts)

    case Attestation.verify(envelope, Keyword.get(opts, :trust_material, %{}), verify_opts) do
      {:ok, statement} -> attested_actor(statement, context)
      {:error, reason} -> {:error, {:invalid_attestation, %{attestation_error: reason}}}
    end
  end

  # A verified statement speaks for the actor it names. It is evidence for
  # this request only when that is the actor the host identified.
  defp attested_actor(statement, %Context{} = context) do
    expected = context.actor || context.identity

    if is_nil(expected) or expected == get_in(statement, ["predicate", "actor", "id"]),
      do: :ok,
      else: {:error, {:invalid_attestation, %{attestation_error: :actor_mismatch}}}
  end

  defp inbound_verify_opts(payload, context, capability, opts) do
    opts
    |> Keyword.take([:now, :max_skew_ms])
    |> Keyword.put(:payload, payload)
    |> Keyword.put(:context, context)
    |> maybe_put_manifest_digest(capability)
  end

  # The nonce is consumed only when the decision allows execution, so a pass
  # that ends in confirm leaves the envelope usable for the confirmed retry.
  defp consume_effect_attestation(
         %Decision{verdict: :allowed} = decision,
         %Effect{mode: :required},
         request,
         {payload, context, capability},
         opts
       ) do
    with true <- Keyword.get(opts, :attestation, :off) in [:optional, :required],
         {:ok, envelope} <- Attestation.fetch(request),
         verify_opts = inbound_verify_opts(payload, context, capability, opts),
         {:error, reason} <-
           Attestation.verify(
             envelope,
             Keyword.get(opts, :trust_material, %{}),
             Keyword.put(verify_opts, :replay, true)
           ) do
      {:invalid_attestation, %{attestation_error: reason}}
      |> deny(payload, context)
      |> put_protocol_metadata(request, opts)
    else
      _ -> decision
    end
  end

  defp consume_effect_attestation(%Decision{} = decision, _, _, _, _), do: decision

  defp put_effect_metadata(%Decision{} = decision, %Effect{} = effect) do
    %{decision | audit_metadata: Map.merge(decision.audit_metadata, Effect.metadata(effect))}
  end

  defp maybe_put_manifest_digest(opts, %CapabilityManifest{digest: digest})
       when is_binary(digest) do
    Keyword.put(opts, :manifest_digest, digest)
  end

  defp maybe_put_manifest_digest(opts, _), do: opts

  defp required_attestation_signer(opts) do
    case Keyword.get(opts, :signer) do
      signer when is_atom(signer) -> {:ok, signer}
      _ -> {:error, :invalid_signer}
    end
  end

  defp attestation_opts(opts, statement_type) do
    direction = if statement_type == :tool_result, do: :result, else: :request

    case Keyword.fetch(opts, :payload) do
      {:ok, payload} when is_map(payload) ->
        normalized =
          opts
          |> Keyword.put(:payload, SecurityPayload.for_gate(payload, direction, opts))
          |> Keyword.put(:statement_type, statement_type)
          |> normalize_attestation_manifest()

        {:ok, normalized}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp normalize_attestation_manifest(opts) do
    case Keyword.get(opts, :manifest) do
      %CapabilityManifest{} = capability ->
        opts
        |> Keyword.put(:manifest_digest, capability.digest)
        |> maybe_put_output_schema_sha256(capability.output_schema_sha256)

      _ ->
        opts
    end
  end

  defp maybe_put_output_schema_sha256(opts, digest) when is_binary(digest),
    do: Keyword.put_new(opts, :output_schema_sha256, digest)

  defp maybe_put_output_schema_sha256(opts, _), do: opts

  defp maybe_force_suspicious_confirmation(%Decision{verdict: :blocked} = decision, _, _, _, _) do
    decision
  end

  defp maybe_force_suspicious_confirmation(decision, _, _, nil, _), do: decision

  defp maybe_force_suspicious_confirmation(
         %Decision{} = decision,
         payload,
         context,
         %CapabilityManifest{suspicious_params: [_ | _]} = capability,
         opts
       ) do
    if Keyword.get(opts, :allow_suspicious_params, false) do
      decision
    else
      suspicious_confirmation(decision, payload, context, capability)
    end
  end

  defp maybe_force_suspicious_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp suspicious_confirmation(%Decision{} = decision, payload, context, capability) do
    action_digest =
      case Confirmation.fetch_action_digest(payload, context) do
        {:ok, digest} -> digest
        {:error, _} -> nil
      end

    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :confirm,
        action: :confirm,
        deny_reason: :suspicious_required_param,
        manifest_digest: capability.digest,
        manifest_name: capability.name,
        suspicious_params: capability.suspicious_params,
        action_digest: action_digest
      })

    %{
      decision
      | verdict: {:confirm, "suspicious_required_param"},
        action: :confirm,
        reason: "Capability manifest discloses suspicious required parameters",
        audit_metadata: metadata
    }
  end

  defp maybe_apply_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         payload,
         context,
         token_source,
         opts
       ) do
    case confirmation_token(opts, token_source) do
      {:ok, token} ->
        verify_confirmation(decision, payload, context, token, opts)

      :off ->
        decision

      :error ->
        decision

      {:error, reason} ->
        confirmation_failure_decision(decision, reason)
    end
  end

  defp maybe_apply_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp maybe_apply_result_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         payload,
         context,
         token_source,
         opts
       ) do
    decision
    |> maybe_apply_confirmation(payload, context, token_source, opts)
    |> release_confirmed_result()
  end

  defp maybe_apply_result_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp confirmation_token(opts, token_source) do
    case Keyword.get(opts, :confirmation, :honor) do
      :off ->
        :off

      :honor ->
        confirmation_token_option(opts, token_source)

      true ->
        :error

      token when is_binary(token) ->
        {:ok, token}

      _ ->
        {:error, :invalid_confirmation_token}
    end
  end

  defp confirmation_token_option(opts, token_source) do
    case Keyword.fetch(opts, :confirmation_token) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :error -> fetch_confirmation_token(token_source)
    end
  end

  defp fetch_confirmation_token(token_source) when is_map(token_source) do
    case Attestation.fetch_confirmation(token_source) do
      {:ok, token} -> {:ok, token}
      :error -> GatewayBase.nested_confirmation_token(token_source)
    end
  end

  defp fetch_confirmation_token(_), do: :error

  defp verify_confirmation(decision, payload, context, token, opts) do
    with {:ok, key} <- GatewayBase.confirmation_key(opts),
         {:ok, claims} <-
           Confirmation.verify(token, payload, context, key, confirmation_opts(decision, opts)) do
      confirmed_decision(decision, claims)
    else
      {:error, reason} -> confirmation_failure_decision(decision, reason)
    end
  end

  defp confirmation_opts(decision, opts) do
    opts
    |> Keyword.take([:now])
    |> Keyword.put(:consume, Keyword.get(opts, :consume_confirmation, true))
    |> Keyword.put(:manifest_binding, manifest_binding(decision))
    |> maybe_put_confirmation_manifest(decision)
  end

  # A request token must bind the pinned manifest. A result token binds it
  # when it was issued with one.
  defp manifest_binding(%Decision{phase: :tool_result}), do: :when_claimed
  defp manifest_binding(%Decision{}), do: :exact

  defp maybe_put_confirmation_manifest(opts, %Decision{
         audit_metadata: %{manifest_digest: digest}
       })
       when is_binary(digest) do
    Keyword.put(opts, :manifest, digest)
  end

  defp maybe_put_confirmation_manifest(opts, _), do: opts

  # Acceptance releases what the decision would have done without the
  # confirmation requirement. A result the gate would redact stays redacted.
  defp confirmed_decision(%Decision{} = decision, claims) do
    action = GatewayBase.confirmed_action(decision)

    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :allowed,
        action: action,
        confirmation_status: :accepted,
        confirmation_actor: claims["actor"],
        confirmation_nonce_hash: Crypto.sha256_hex(claims["nonce"]),
        confirmation_issued_at: claims["issued_at"],
        confirmation_expires_at: claims["expires_at"]
      })

    %{
      decision
      | verdict: :allowed,
        action: action,
        reason: "Confirmation token accepted",
        audit_metadata: metadata
    }
  end

  defp release_confirmed_result(
         %Decision{
           verdict: :allowed,
           audit_metadata: %{quarantine_status: :quarantined} = metadata
         } = decision
       ) do
    released_metadata =
      Map.merge(metadata, %{
        action: :redact,
        release_status: :confirmed_sanitized
      })

    %{
      decision
      | action: :redact,
        reason: "Confirmation token accepted; sanitized result released",
        audit_metadata: released_metadata
    }
  end

  defp release_confirmed_result(%Decision{} = decision), do: decision

  defp confirmation_failure_decision(%Decision{} = decision, reason) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :blocked,
        action: :block,
        risk_level: :high,
        deny_reason: :confirmation_failed,
        confirmation_status: :invalid,
        confirmation_reason: reason
      })

    %{
      decision
      | verdict: :blocked,
        action: :block,
        reason: "Tool gateway confirmation verification failed: #{format_reason(reason)}",
        risk_level: :high,
        audit_metadata: metadata
    }
  end

  defp deny(denial, payload, context) do
    {reason, denial_metadata} = denial_metadata(denial)
    content_hash = Crypto.sha256_hex(payload.text)

    %Decision{
      verdict: :blocked,
      action: :block,
      reason: "Tool gateway denied request: #{format_reason(reason)}",
      phase: context.phase,
      risk_level: :high,
      trust_level: context.trust_level,
      hits: [],
      indicators: [],
      sanitized_text: nil,
      content_hash: content_hash,
      audit_metadata:
        %{
          phase: context.phase,
          actor: context.actor,
          identity: context.identity,
          origin: context.origin,
          sink: context.sink,
          tool: context.tool,
          mcp_server: context.mcp_server,
          resource_uri: context.resource_uri,
          trust_zone: context.trust_zone,
          trust_level: context.trust_level,
          risk_level: :high,
          verdict: :blocked,
          action: :block,
          deny_reason: reason,
          hit_count: 0,
          indicator_count: 0,
          content_hash: content_hash
        }
        |> Map.merge(denial_metadata)
    }
  end

  defp denial_metadata({reason, metadata}) when is_atom(reason) and is_map(metadata) do
    {reason, Map.put(metadata, :deny_reason, reason)}
  end

  defp denial_metadata(reason) when is_atom(reason), do: {reason, %{deny_reason: reason}}

  defp put_protocol_metadata(%Decision{} = decision, message, opts) do
    metadata =
      decision.audit_metadata
      |> maybe_put_protocol_version(Protocol.version(message, opts))
      |> maybe_put_result_type(Protocol.result_type(message))

    %{decision | audit_metadata: metadata}
  end

  defp maybe_put_protocol_version(metadata, version) when is_binary(version),
    do: Map.put(metadata, :protocol_version, version)

  defp maybe_put_protocol_version(metadata, _), do: metadata

  defp maybe_put_result_type(metadata, result_type) when is_binary(result_type),
    do: Map.put(metadata, :mcp_result_type, result_type)

  defp maybe_put_result_type(metadata, _), do: metadata

  defp emit_mcp_decision(%Decision{} = decision) do
    Telemetry.emit_mcp_decision(decision.audit_metadata)
    decision
  end

  defp put_manifest_metadata(%Decision{} = decision, nil), do: decision

  defp put_manifest_metadata(%Decision{} = decision, %CapabilityManifest{} = capability) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        manifest_digest: capability.digest,
        manifest_name: capability.name,
        suspicious_params: capability.suspicious_params
      })

    %{decision | audit_metadata: metadata}
  end

  defp put_result_binding_metadata(%Decision{} = decision, opts) do
    metadata =
      decision.audit_metadata
      |> maybe_put_request_action_digest(Keyword.get(opts, :request_action_digest))
      |> Map.put(:scanner_summary, %{
        hit_count: length(decision.hits),
        indicator_count: length(decision.indicators),
        indicator_ids: GatewayBase.indicator_ids(decision.indicators)
      })
      |> Map.put(:quarantine_status, quarantine_status(decision))

    %{decision | audit_metadata: metadata}
  end

  defp maybe_put_request_action_digest(metadata, digest) when is_binary(digest),
    do: Map.put(metadata, :request_action_digest, digest)

  defp maybe_put_request_action_digest(metadata, _), do: metadata

  defp quarantine_status(%Decision{action: :quarantine}), do: :quarantined
  defp quarantine_status(%Decision{effect: :quarantine}), do: :quarantined
  defp quarantine_status(%Decision{verdict: {:confirm, _}, indicators: [_ | _]}), do: :confirm
  defp quarantine_status(%Decision{indicators: [_ | _]}), do: :suspicious
  defp quarantine_status(_), do: :safe

  defp request_payload(request, opts), do: SecurityPayload.for_gate(request, :request, opts)
  defp result_payload(result, opts), do: SecurityPayload.for_gate(result, :result, opts)

  defp format_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
end

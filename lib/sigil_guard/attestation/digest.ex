defmodule SigilGuard.Attestation.Digest do
  @moduledoc """
  Digest computation for SigilGuard agent-trust Statements.

  Digests are lowercase SHA-256 hex strings. Structured preimages are
  normalized according to the trust profile and encoded with RFC 8785 JCS
  before hashing.
  """

  alias SigilGuard.Attestation
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Context
  alias SigilGuard.Crypto

  @sha256_regex ~r/\A[0-9a-f]{64}\z/
  @statement_types ~w(
    tool_request
    tool_result
    model_ingress
    model_egress
    repo_change
    release
    agent_request
    agent_response
  )a

  @type statement_type ::
          :tool_request
          | :tool_result
          | :model_ingress
          | :model_egress
          | :repo_change
          | :release
          | :agent_request
          | :agent_response

  @type error_reason :: :invalid_payload | :unsupported_number_range | :unknown_statement_type

  @doc """
  Normalize a JSON-shaped value for digest preimages.

  Atom keys and atom values are converted to strings, booleans and nil retain
  their JSON meanings in lists, and map entries with nil values are omitted.
  Duplicate keys after normalization fail with `:invalid_payload`.
  """
  @spec normalize(term()) :: {:ok, term()} | {:error, :invalid_payload}
  def normalize(value) do
    with :ok <- SigilGuard.Limits.check(value), do: normalize_value(value)
  end

  @doc """
  Compute the payload digest for any attestation payload class.

  Application map entries with nil values fail `:invalid_payload` because v3
  omission would otherwise equate null with absence. Fixed nullable MCP profile
  fields keep their defined semantics, and null array elements are preserved.
  """
  @spec payload_digest(term()) :: {:ok, String.t()} | {:error, error_reason()}
  def payload_digest(payload) when is_binary(payload) do
    if String.valid?(payload) do
      {:ok, Crypto.sha256_hex(payload)}
    else
      {:error, :invalid_payload}
    end
  end

  def payload_digest(payload) when is_map(payload) do
    payload
    |> Attestation.strip_metadata()
    |> unambiguous_payload_digest()
  end

  def payload_digest(payload) when is_list(payload) do
    payload
    |> Attestation.strip_metadata()
    |> unambiguous_payload_digest()
  end

  def payload_digest(_), do: {:error, :invalid_payload}

  @doc """
  Return the statement type a `SigilGuard.Context` phase is digested under.

  The two model phases have their own statement types; the other phases keep
  their name.

      iex> SigilGuard.Attestation.Digest.phase_statement_type(:inbound_user)
      {:ok, :model_ingress}

      iex> SigilGuard.Attestation.Digest.phase_statement_type(:tool_result)
      {:ok, :tool_result}

      iex> SigilGuard.Attestation.Digest.phase_statement_type(:session_start)
      :error

  """
  @doc since: "1.1.0"
  @spec phase_statement_type(term()) ::
          {:ok, :model_ingress | :model_egress | :tool_request | :tool_result | :repo_change}
          | :error
  def phase_statement_type(:inbound_user), do: {:ok, :model_ingress}
  def phase_statement_type(:outbound_model), do: {:ok, :model_egress}

  def phase_statement_type(phase) when phase in [:tool_request, :tool_result, :repo_change],
    do: {:ok, phase}

  def phase_statement_type(_), do: :error

  @doc """
  Compute the shared attestation context digest for a statement type.
  """
  @spec context_digest(statement_type(), Context.t() | map() | keyword()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def context_digest(statement_type, context) do
    with {:ok, preimage} <- context_preimage(statement_type, context) do
      normalized_jcs_digest(preimage)
    end
  end

  @doc """
  Return the shared attestation context digest preimage for a statement type.
  """
  @spec context_preimage(statement_type(), Context.t() | map() | keyword()) ::
          {:ok, map()} | {:error, error_reason()}
  def context_preimage(statement_type, context) when statement_type in @statement_types do
    case Context.cast(context) do
      {:ok, normalized} ->
        {:ok, context_fields(statement_type, Map.from_struct(normalized), context)}

      {:error, :invalid_context} ->
        {:error, :invalid_payload}
    end
  end

  def context_preimage(_, _), do: {:error, :unknown_statement_type}

  defp context_fields(statement_type, context_map, context) do
    %{
      "statement_type" => Atom.to_string(statement_type),
      "trust_level" => context_map.trust_level,
      "phase" => context_map.phase,
      "origin" => context_map.origin,
      "sink" => context_map.sink,
      "trust_zone" => context_map.trust_zone,
      "intended_audience" => context_map.intended_audience
    }
    |> maybe_put("actor", context_map.actor)
    |> maybe_put("identity", context_map.identity)
    |> maybe_put("source", context_map.source)
    |> maybe_put("mcp_server", context_map.mcp_server)
    |> maybe_put("tool", context_map.tool)
    |> maybe_put("resource_uri", context_map.resource_uri)
    |> maybe_put("sandbox_id", context_extra(context, "sandbox_id"))
    |> maybe_put("isolation_level", context_extra(context, "isolation_level"))
  end

  @doc """
  Compute the attestation action digest for a statement type.
  """
  @spec action_digest(statement_type(), term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def action_digest(statement_type, payload, context, opts \\ []) do
    with {:ok, preimage} <- action_preimage(statement_type, payload, context, opts) do
      normalized_jcs_digest(preimage)
    end
  end

  @doc """
  Return the attestation action digest preimage for a statement type.
  """
  @spec action_preimage(statement_type(), term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, error_reason()}
  def action_preimage(statement_type, payload, context, opts \\ [])

  def action_preimage(:tool_request, payload, context, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         payload = gate_message(payload),
         {:ok, tool} <- tool_request_tool(payload, context) do
      %{"statement_type" => "tool_request", "tool" => tool}
      |> maybe_put("method", Map.get(payload, "method"))
      |> maybe_put("arguments", tool_request_arguments(payload))
      |> ok()
    end
  end

  def action_preimage(:tool_result, payload, context, opts) do
    with {:ok, payload} <- normalized_payload_map(payload),
         payload = gate_message(payload),
         {:ok, tool} <- required_context_field(context, "tool"),
         {:ok, request_action_digest} <- request_action_digest(opts) do
      %{
        "statement_type" => "tool_result",
        "tool" => tool,
        "request_action_digest" => request_action_digest
      }
      |> maybe_put("method", Map.get(payload, "method"))
      |> ok()
    end
  end

  def action_preimage(:model_ingress, _, context, _) do
    with {:ok, origin} <- required_context_field(context, "origin") do
      %{"statement_type" => "model_ingress", "origin" => origin}
      |> maybe_put("source", context_extra_or_known(context, "source"))
      |> maybe_put("resource_uri", context_extra_or_known(context, "resource_uri"))
      |> ok()
    end
  end

  def action_preimage(:model_egress, _, context, _) do
    with {:ok, sink} <- required_context_field(context, "sink"),
         {:ok, intended_audience} <- required_context_field(context, "intended_audience") do
      %{
        "statement_type" => "model_egress",
        "sink" => sink,
        "intended_audience" => intended_audience
      }
      |> maybe_put("resource_uri", context_extra_or_known(context, "resource_uri"))
      |> ok()
    end
  end

  def action_preimage(:repo_change, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, repository} <- required_payload_field(payload, "repository"),
         {:ok, operation} <- required_payload_field(payload, "operation"),
         {:ok, paths} <- repo_paths(payload) do
      %{
        "statement_type" => "repo_change",
        "repository" => repository,
        "operation" => operation,
        "paths" => paths
      }
      |> maybe_put("ref", Map.get(payload, "ref"))
      |> ok()
    end
  end

  def action_preimage(:release, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, package} <- required_payload_field(payload, "package"),
         {:ok, version} <- required_payload_field(payload, "version"),
         {:ok, artifacts} <- release_artifacts(payload) do
      {:ok,
       %{
         "statement_type" => "release",
         "package" => package,
         "version" => version,
         "artifacts" => artifacts
       }}
    end
  end

  def action_preimage(:agent_request, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, peer_agent} <- required_payload_field(payload, "peer_agent"),
         {:ok, capability} <- required_payload_field(payload, "capability") do
      %{
        "statement_type" => "agent_request",
        "peer_agent" => peer_agent,
        "capability" => capability
      }
      |> maybe_put("arguments", Map.get(payload, "arguments"))
      |> ok()
    end
  end

  def action_preimage(:agent_response, payload, _, opts) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, peer_agent} <- required_payload_field(payload, "peer_agent"),
         {:ok, capability} <- required_payload_field(payload, "capability"),
         {:ok, request_action_digest} <- request_action_digest(opts) do
      {:ok,
       %{
         "statement_type" => "agent_response",
         "peer_agent" => peer_agent,
         "capability" => capability,
         "request_action_digest" => request_action_digest
       }}
    end
  end

  def action_preimage(_, _, _, _), do: {:error, :unknown_statement_type}

  @doc """
  Compute action, payload, context, and applicable manifest digests.
  """
  @spec digests(statement_type(), term(), map() | keyword(), keyword()) ::
          {:ok, %{required(String.t()) => String.t()}} | {:error, error_reason()}
  def digests(statement_type, payload, context, opts \\ []) do
    with {:ok, action} <- action_digest(statement_type, payload, context, opts),
         {:ok, payload_digest} <- payload_digest(payload),
         {:ok, context_digest} <- context_digest(statement_type, context),
         {:ok, manifest} <- maybe_manifest_digest(statement_type, opts) do
      %{"action" => action, "payload" => payload_digest, "context" => context_digest}
      |> maybe_put("manifest", manifest)
      |> ok()
    end
  end

  @doc """
  Compute a manifest digest from a verified manifest value.
  """
  @spec manifest_digest(term()) :: {:ok, String.t()} | {:error, error_reason()}
  def manifest_digest(manifest) when is_binary(manifest), do: payload_digest(manifest)
  def manifest_digest(manifest) when is_map(manifest), do: normalized_jcs_digest(manifest)
  def manifest_digest(_), do: {:error, :invalid_payload}

  # A gateway digests its gate payload, which carries the MCP message as a
  # projection: the method beside the params object for a request, the result
  # object for a result. The action is the message's method and arguments, so
  # the preimage is read from the message the projection stands for.
  #
  # The message is rebuilt in its JSON-RPC shape instead of read in place. A
  # params object may hold members of any name, and one called `params` or
  # `method` would otherwise be taken for the message's own.
  #
  # Normalization has dropped the null members by now, so a gate payload is
  # recognized by `binding` and `text`, which are never null, and by having
  # no member outside the four.
  @gate_payload_keys ~w(action binding text tool)
  @binding_keys ~w(kind method payload protocol_version)

  defp gate_message(%{"binding" => %{"kind" => kind} = binding} = payload)
       when kind in ["request", "result"] do
    if gate_payload?(payload, binding),
      do: projected_message(kind, binding),
      else: payload
  end

  defp gate_message(payload), do: payload

  defp gate_payload?(payload, binding) do
    Map.has_key?(payload, "text") and Map.keys(payload) -- @gate_payload_keys == [] and
      Map.has_key?(binding, "payload") and Map.keys(binding) -- @binding_keys == []
  end

  defp projected_message("request", binding),
    do: put_method(%{"params" => Map.get(binding, "payload")}, Map.get(binding, "method"))

  defp projected_message("result", binding), do: put_method(%{}, Map.get(binding, "method"))

  defp put_method(message, method) when is_binary(method), do: Map.put(message, "method", method)
  defp put_method(message, _), do: message

  defp normalized_payload_map(payload) when is_map(payload) do
    result =
      with :ok <- SigilGuard.Limits.check(payload),
           :ok <- unambiguous_payload(payload) do
        payload
        |> Attestation.strip_metadata()
        |> normalize()
      end

    case result do
      {:ok, map} -> {:ok, map}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalized_payload_map(_), do: {:error, :invalid_payload}

  defp unambiguous_payload_digest(payload) do
    with :ok <- SigilGuard.Limits.check(payload),
         :ok <- unambiguous_payload(payload),
         do: normalized_jcs_digest(payload)
  end

  # The MCP wrapper has fixed nullable profile fields. Application data stays
  # subject to strict null/absence validation; the frozen v3 wrapper bytes stay intact.
  defp unambiguous_payload(%{binding: %{"payload" => application} = binding} = wrapper)
       when map_size(wrapper) == 4 do
    if Enum.sort(Map.keys(wrapper)) == [:action, :binding, :text, :tool] and
         Enum.all?(Map.keys(binding), &(&1 in ["kind", "method", "protocol_version", "payload"])) do
      application_payload(application)
    else
      unambiguous_map(wrapper)
    end
  end

  defp unambiguous_payload(%{"kind" => kind, "payload" => application} = projection)
       when kind in ["request", "result"] do
    if Enum.all?(Map.keys(projection), &(&1 in ["kind", "method", "protocol_version", "payload"])) do
      application_payload(application)
    else
      unambiguous_map(projection)
    end
  end

  defp unambiguous_payload(value) when is_map(value), do: unambiguous_map(value)

  defp unambiguous_payload(value) when is_list(value) do
    Enum.reduce_while(value, :ok, fn child, _ -> continue_payload(child) end)
  end

  defp unambiguous_payload(_), do: :ok

  defp application_payload(nil), do: {:error, :invalid_payload}
  defp application_payload(value), do: unambiguous_payload(value)

  defp unambiguous_map(value) do
    Enum.reduce_while(value, :ok, fn
      {_, nil}, _ -> {:halt, {:error, :invalid_payload}}
      {_, child}, _ -> continue_payload(child)
    end)
  end

  defp continue_payload(value) do
    case unambiguous_payload(value) do
      :ok -> {:cont, :ok}
      error -> {:halt, error}
    end
  end

  defp normalized_jcs_digest(value) do
    with {:ok, normalized} <- normalize(value),
         {:ok, canonical} <- JCS.encode(normalized) do
      {:ok, Crypto.sha256_hex(canonical)}
    else
      {:error, :invalid_map} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_value(nil), do: {:ok, nil}
  defp normalize_value(value) when is_boolean(value), do: {:ok, value}
  defp normalize_value(value) when is_integer(value), do: {:ok, value}
  defp normalize_value(value) when is_float(value), do: {:ok, value}

  defp normalize_value(value) when is_atom(value) do
    {:ok, Atom.to_string(value)}
  end

  defp normalize_value(value) when is_binary(value) do
    if String.valid?(value), do: {:ok, value}, else: {:error, :invalid_payload}
  end

  defp normalize_value(value) when is_list(value) do
    value
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, items} ->
      case normalize_value(item) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | items]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_ok()
  end

  defp normalize_value(%_{}), do: {:error, :invalid_payload}

  defp normalize_value(value) when is_map(value) do
    result =
      Enum.reduce_while(value, {:ok, %{}}, fn {key, raw_value}, {:ok, normalized} ->
        with {:ok, key} <- normalize_key(key),
             {:ok, value} <- normalize_value(raw_value),
             :ok <- unique_key(normalized, key) do
          {:cont, {:ok, put_normalized_value(normalized, key, value)}}
        else
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, normalized} -> {:ok, normalized}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_value(_), do: {:error, :invalid_payload}

  defp put_normalized_value(map, _, nil), do: map
  defp put_normalized_value(map, key, value), do: Map.put(map, key, value)

  defp normalize_key(key) when is_atom(key), do: {:ok, Atom.to_string(key)}

  defp normalize_key(key) when is_binary(key) do
    if String.valid?(key), do: {:ok, key}, else: {:error, :invalid_payload}
  end

  defp normalize_key(_), do: {:error, :invalid_payload}

  defp unique_key(map, key) do
    if Map.has_key?(map, key), do: {:error, :invalid_payload}, else: :ok
  end

  defp reverse_ok({:ok, values}), do: {:ok, Enum.reverse(values)}
  defp reverse_ok({:error, reason}), do: {:error, reason}

  # A term that is not a context has no context fields.
  defp context_map(context) do
    case Context.cast(context) do
      {:ok, context} -> Map.from_struct(context)
      {:error, :invalid_context} -> %{}
    end
  end

  defp context_extra_or_known(context, key) do
    context_extra(context, key) || Map.get(context_map(context), atom_key(key))
  end

  defp context_extra(context, key) do
    result =
      context
      |> raw_map()
      |> fetch_flexible(key)

    case result do
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp required_context_field(context, key) do
    case context_extra_or_known(context, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_atom(value) and not is_nil(value) -> {:ok, Atom.to_string(value)}
      _ -> {:error, :invalid_payload}
    end
  end

  defp tool_request_tool(payload, context) do
    case context_extra_or_known(context, "tool") do
      value when is_binary(value) and value != "" ->
        {:ok, value}

      value when is_atom(value) and not is_nil(value) ->
        {:ok, Atom.to_string(value)}

      _ ->
        payload
        |> nested_payload_field(["params", "name"])
        |> fallback_payload_field(payload, "name")
    end
  end

  defp fallback_payload_field({:ok, value}, _, _), do: {:ok, value}
  defp fallback_payload_field(:error, payload, key), do: required_payload_field(payload, key)

  defp tool_request_arguments(payload) do
    case nested_payload_field(payload, ["params", "arguments"]) do
      {:ok, arguments} -> Attestation.strip_metadata(arguments)
      :error -> Map.get(payload, "arguments") |> Attestation.strip_metadata()
    end
  end

  defp nested_payload_field(payload, [parent, child]) do
    case Map.get(payload, parent) do
      parent_value when is_map(parent_value) -> optional_payload_field(parent_value, child)
      _ -> :error
    end
  end

  defp optional_payload_field(payload, key) do
    case Map.get(payload, key) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  defp required_payload_field(payload, key) do
    case Map.get(payload, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_list(value) -> {:ok, value}
      value when is_map(value) -> {:ok, value}
      value when is_number(value) -> {:ok, value}
      value when is_boolean(value) -> {:ok, value}
      _ -> {:error, :invalid_payload}
    end
  end

  defp repo_paths(payload) do
    case Map.get(payload, "paths") do
      paths when is_list(paths) ->
        if Enum.all?(paths, &is_binary/1) do
          {:ok, Enum.sort(paths)}
        else
          {:error, :invalid_payload}
        end

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp release_artifacts(payload) do
    case Map.get(payload, "artifacts") do
      artifacts when is_list(artifacts) and artifacts != [] ->
        normalize_artifacts(artifacts)

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp normalize_artifacts(artifacts) do
    result =
      Enum.reduce_while(artifacts, {:ok, []}, fn artifact, {:ok, acc} ->
        case normalize_artifact(artifact) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, normalized} -> {:ok, Enum.sort_by(normalized, &Map.fetch!(&1, "name"))}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_artifact(%{} = artifact) do
    with {:ok, artifact} <- normalize(artifact),
         {:ok, name} <- required_payload_field(artifact, "name"),
         {:ok, sha256} <- artifact_sha256(artifact) do
      {:ok, %{"name" => name, "sha256" => sha256}}
    end
  end

  defp normalize_artifact(_), do: {:error, :invalid_payload}

  defp artifact_sha256(artifact) do
    case Map.get(artifact, "sha256") do
      value when is_binary(value) ->
        if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp request_action_digest(opts) do
    case Keyword.fetch(opts, :request_action_digest) do
      {:ok, value} when is_binary(value) ->
        if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp maybe_manifest_digest(statement_type, opts)
       when statement_type in [:tool_request, :tool_result, :agent_request, :agent_response],
       do: option_manifest_digest(opts)

  defp maybe_manifest_digest(_, _), do: {:ok, nil}

  @doc false
  @spec option_manifest_digest(keyword()) :: {:ok, String.t() | nil} | {:error, error_reason()}
  def option_manifest_digest(opts) do
    cond do
      Keyword.has_key?(opts, :manifest_digest) ->
        validate_digest(Keyword.fetch!(opts, :manifest_digest))

      Keyword.has_key?(opts, :manifest) ->
        manifest_digest(Keyword.fetch!(opts, :manifest))

      true ->
        {:ok, nil}
    end
  end

  defp validate_digest(value) when is_binary(value) do
    if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}
  end

  defp validate_digest(_), do: {:error, :invalid_payload}

  defp raw_map(%Context{} = context), do: Map.from_struct(context)

  defp raw_map(context) when is_list(context),
    do: if(Keyword.keyword?(context), do: Map.new(context), else: %{})

  defp raw_map(context) when is_map(context), do: context
  defp raw_map(_), do: %{}

  defp fetch_flexible(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(map, atom_key(key))
    end
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp ok(value), do: {:ok, value}

  # The context fields a preimage reads by name.
  defp atom_key("origin"), do: :origin
  defp atom_key("source"), do: :source
  defp atom_key("sink"), do: :sink
  defp atom_key("tool"), do: :tool
  defp atom_key("resource_uri"), do: :resource_uri
  defp atom_key("intended_audience"), do: :intended_audience
  defp atom_key("sandbox_id"), do: :sandbox_id
  defp atom_key("isolation_level"), do: :isolation_level
end

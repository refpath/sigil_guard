defmodule SigilGuard.AgentTrust do
  @moduledoc """
  Attests and verifies `agent_request` and `agent_response` statements
  between peer agents.

  These helpers compose `SigilGuard.AgentCard`, `SigilGuard.Attestation`, and
  `SigilGuard.Identity` into the `agent_request` / `agent_response` flows. A
  peer is trusted only through a verified card; without one the attestation
  fails closed to a `quarantine` verdict with `peer_trust` `low` and no bound
  card digest.

  The requester invokes a capability on the responder, and the governing card is
  always the responder's, as the manifest for a tool call is always the tool's.

  ## Result payloads are never exempt from scanning

  A verified `agent_response` envelope authenticates its producer; it does not
  make the response content safe. `verify_agent_response/3` returns the
  statement without touching the payload. Hosts MUST route the response payload
  through the result boundary (`SigilGuard.Runtime.Gate.evaluate/3` with a
  `:tool_result` phase) before it reaches model context, exactly like a tool
  result:

      {:ok, _statement} = SigilGuard.AgentTrust.verify_agent_response(env, bundle,
        request_action_digest: rad, peer_card: card_env, payload: response)

      decision =
        SigilGuard.Runtime.Gate.evaluate(response, %{
          phase: :tool_result,
          origin: :external,
          sink: :model
        })
  """

  alias SigilGuard.AgentCard
  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Identity
  alias SigilGuard.Telemetry
  alias SigilGuard.TrustBundle

  @atom_fields %{
    "actor" => :actor,
    "capability" => :capability,
    "delegation_chain" => :delegation_chain,
    "peer_agent" => :peer_agent
  }

  @default_max_delegation_depth 8
  @unknown_peer_rule %{
    "id" => "agent.unknown_peer.quarantine",
    "explanation" => "no bundle-declared issuer matched the peer card"
  }

  @typedoc "Why an agent request or response could not be attested."
  @type attest_error ::
          AgentCard.verify_error()
          | :unknown_agent
          | :unknown_capability
          | :card_digest_mismatch
          | :delegation_too_deep
          | :delegation_chain_tampered
          | Attestation.sign_error()
          | Attestation.from_decision_error()

  @typedoc "Why `verify_agent_response/3` refused a response statement."
  @type verify_response_error ::
          attest_error() | Attestation.verify_error() | :invalid_payload | :invalid_audience

  @doc """
  Attest an outbound `agent_request` and return a signed DSSE envelope.

  Options: `:signer` (required module), `:decision` (required
  `%SigilGuard.Decision{}`), `:peer_card` (a card map or DSSE envelope),
  `:trust_material` (verifies a `:peer_card` envelope), `:require_peer_card`
  (default `false`), `:max_delegation_depth` (default `8`), `:resolve` /
  `:identity` (per-actor trust resolution), `:audience` (the recipient's
  identity, written as `resource.audience`), `:ttl_ms`, `:now`, `:nonce`,
  `:evidence`, `:keyid`.
  """
  @spec attest_agent_request(map(), Context.t() | map(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_agent_request(payload, context, opts \\ []) do
    Telemetry.span([:sigil_guard, :agent_trust, :attest], %{statement_type: :agent_request}, fn ->
      result = do_attest_request(payload, context, opts)
      {result, span_metadata(result, :agent_request)}
    end)
  end

  defp do_attest_request(payload, context, opts) when is_map(payload) and is_list(opts) do
    with {:ok, signer} <- fetch_signer(opts),
         {:ok, decision} <- fetch_decision(opts),
         {:ok, peer} <- resolve_peer(opts),
         :ok <- check_delegation_depth(payload, opts),
         {:ok, capability} <- required_string(payload, "capability"),
         {:ok, peer_agent_id} <- required_string(payload, "peer_agent") do
      build_attestation(:agent_request, %{
        payload: payload,
        context: context,
        decision: decision,
        signer: signer,
        peer: peer,
        capability: capability,
        peer_agent_id: peer_agent_id,
        opts: opts
      })
    end
  end

  defp do_attest_request(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Attest an `agent_response` and return a signed DSSE envelope.

  Mirrors `attest_agent_request/3` for the response boundary. It also
  requires `:request_action_digest`; reads `status` from the payload; derives
  `quarantined` from the decision. No delegation chain is accepted.

  `quarantined` is `true` when the decision's action or effect is
  `:quarantine`, or when the decision carries quarantine indicators, whatever
  its verdict. Pass the requester's identity as `:audience` so the response
  cannot be presented to another requester.
  """
  @spec attest_agent_response(map(), Context.t() | map(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_agent_response(payload, context, opts \\ []) do
    Telemetry.span(
      [:sigil_guard, :agent_trust, :attest],
      %{statement_type: :agent_response},
      fn ->
        result = do_attest_response(payload, context, opts)
        {result, span_metadata(result, :agent_response)}
      end
    )
  end

  defp do_attest_response(payload, context, opts) when is_map(payload) and is_list(opts) do
    with {:ok, signer} <- fetch_signer(opts),
         {:ok, decision} <- fetch_decision(opts),
         {:ok, _} <- required_digest(opts, :request_action_digest),
         {:ok, peer} <- resolve_peer(opts),
         {:ok, capability} <- required_string(payload, "capability"),
         {:ok, peer_agent_id} <- required_string(payload, "peer_agent") do
      build_attestation(:agent_response, %{
        payload: payload,
        context: context,
        decision: decision,
        signer: signer,
        peer: peer,
        capability: capability,
        peer_agent_id: peer_agent_id,
        opts: opts
      })
    end
  end

  defp do_attest_response(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Verify an inbound `agent_response` envelope and return the statement.

  Options: `:request_action_digest` (required; absent fails `:invalid_payload`),
  `:peer_card` (card DSSE envelope resolving the agent's own keys), `:payload`
  (response content, a map, for digest binding), `:capability` (the capability
  the request invoked), `:audience` (the verifier's own identity), `:context`
  (recomputes the context digest), `:max_skew_ms`, `:now`, `:replay`,
  `:replay_ttl_ms`. Verification never exempts the payload from the result
  boundary described in the module documentation.

  Each binding is checked when its option is given. A response for another
  capability, or for one the peer's card does not declare, fails
  `:unknown_capability`. A response addressed to another requester, or to
  none, fails `:invalid_audience`. Without a `:peer_card`, `trust_material`
  is the key material `SigilGuard.Attestation.verify/3` takes.
  """
  @spec verify_agent_response(map(), AgentCard.trust_material(), keyword()) ::
          {:ok, map()} | {:error, verify_response_error()}
  def verify_agent_response(envelope, trust_material, opts \\ []) do
    Telemetry.span(
      [:sigil_guard, :agent_trust, :verify],
      %{statement_type: :agent_response},
      fn ->
        result = do_verify_response(envelope, trust_material, opts)
        {result, span_metadata(result, :agent_response)}
      end
    )
  end

  defp do_verify_response(envelope, trust_material, opts)
       when is_map(envelope) and is_list(opts) do
    with {:ok, request_action_digest} <- required_digest(opts, :request_action_digest),
         {:ok, card} <- verify_optional_peer_card(trust_material, opts),
         {:ok, material} <- response_key_material(trust_material, card),
         {:ok, statement} <- Attestation.verify(envelope, material, verify_opts(opts)),
         {:ok, predicate} <- typed_predicate(statement, "agent_response"),
         :ok <- check_back_reference(predicate, statement, request_action_digest, opts),
         :ok <- check_card_binding(predicate, statement, card),
         :ok <- check_exchange(statement, predicate, card, opts) do
      {:ok, statement}
    end
  end

  defp do_verify_response(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Return the trust zone for content that originates from a peer.

  `card` is a card that `SigilGuard.AgentCard.verify/3` returned, or `nil`
  for a peer without one. The zone is the one the card declares. A peer
  without a verified card is `:untrusted`.

  A host passes the result as `trust_zone` in the context under which it
  gates the peer's content, so that content never crosses in a more trusted
  zone than its card states.

  ## Examples

      iex> SigilGuard.AgentTrust.peer_trust_zone(%{"trust_zone" => "semi_trusted"})
      :semi_trusted

      iex> SigilGuard.AgentTrust.peer_trust_zone(nil)
      :untrusted

  """
  @doc since: "1.1.0"
  @spec peer_trust_zone(map() | nil) :: Context.trust_zone()
  def peer_trust_zone(%{"trust_zone" => "trusted"}), do: :trusted
  def peer_trust_zone(%{"trust_zone" => "semi_trusted"}), do: :semi_trusted
  def peer_trust_zone(_), do: :untrusted

  @doc """
  Verify a payload delegation chain against a signed predicate mirror.

  Inbound `agent_request` verification composes this with
  `SigilGuard.AgentCard.verify/3` and `SigilGuard.Attestation.verify/3`. The chain order is digest-bound (RFC 8785
  preserves array order), so any reorder, insertion, drop, edit, or one-sided
  presence between the payload chain and `predicate.delegation_chain` fails
  `:delegation_chain_tampered`. Depth beyond `:max_delegation_depth`
  (default 8) fails `:delegation_too_deep`.
  """
  @spec verify_delegation_chain(map(), map(), keyword()) ::
          :ok | {:error, :delegation_chain_tampered | :delegation_too_deep | :invalid_payload}
  def verify_delegation_chain(payload, predicate, opts \\ [])

  def verify_delegation_chain(payload, predicate, opts)
      when is_map(payload) and is_map(predicate) and is_list(opts) do
    with :ok <- check_delegation_depth(payload, opts) do
      compare_delegation_chains(payload, predicate)
    end
  end

  def verify_delegation_chain(_, _, _), do: {:error, :invalid_payload}

  defp compare_delegation_chains(payload, predicate) do
    payload_present = chain_present?(payload)
    predicate_present = chain_present?(predicate)

    cond do
      not payload_present and not predicate_present ->
        :ok

      payload_present != predicate_present ->
        {:error, :delegation_chain_tampered}

      true ->
        matching_chain_digests(payload, predicate)
    end
  end

  defp matching_chain_digests(payload, predicate) do
    with {:ok, payload_digest} <- AgentPredicate.delegation_chain_digest(payload),
         {:ok, predicate_digest} <- AgentPredicate.delegation_chain_digest(predicate) do
      if payload_digest == predicate_digest do
        :ok
      else
        {:error, :delegation_chain_tampered}
      end
    else
      _ -> {:error, :delegation_chain_tampered}
    end
  end

  defp chain_present?(map) do
    match?({:ok, chain} when is_list(chain), fetch_field(map, "delegation_chain"))
  end

  defp build_attestation(statement_type, params) do
    case params.peer do
      {:verified, card, card_digest} ->
        build_verified(statement_type, card, card_digest, params)

      :unknown ->
        build_unknown(statement_type, params)
    end
  end

  defp build_verified(statement_type, card, card_digest, params) do
    with :ok <- match_agent_id(card, params.peer_agent_id),
         :ok <- capability_declared(card, params.capability),
         peer_trust = derive_peer_trust(card, params.payload, params.opts),
         fd_opts <-
           from_decision_opts(statement_type, params, peer_trust, card_digest: card_digest),
         {:ok, statement} <-
           Attestation.from_decision(params.decision, params.context, fd_opts) do
      sign_statement(statement, params.signer, params.opts)
    end
  end

  defp build_unknown(statement_type, params) do
    if SigilGuard.Options.flag(params.opts, :require_peer_card, false, true) do
      {:error, :unknown_agent}
    else
      decision = quarantine_unknown(params.decision)
      fd_opts = from_decision_opts(statement_type, params, :low, [])

      with {:ok, statement} <-
             Attestation.from_decision(decision, params.context, fd_opts),
           statement = attach_unknown_peer_rule(statement),
           {:ok, envelope} <- sign_statement(statement, params.signer, params.opts) do
        emit_quarantine()
        {:ok, envelope}
      end
    end
  end

  defp from_decision_opts(statement_type, params, peer_trust, extra) do
    [
      statement_type: statement_type,
      payload: params.payload,
      peer_trust: peer_trust
    ]
    |> Keyword.merge(extra)
    |> put_card_digest(extra)
    |> maybe_put_opt(:request_action_digest, Keyword.get(params.opts, :request_action_digest))
    |> maybe_put_opt(:audience, Keyword.get(params.opts, :audience))
    |> maybe_put_opt(:ttl_ms, Keyword.get(params.opts, :ttl_ms))
    |> maybe_put_opt(:now, Keyword.get(params.opts, :now))
    |> forward_opt(:nonce, params.opts)
    |> maybe_put_opt(:evidence, Keyword.get(params.opts, :evidence))
  end

  # Unlike `maybe_put_opt/3` this keeps a `nil` or `false` the caller passed,
  # which is how a caller asks for a statement without a nonce.
  defp forward_opt(fd_opts, key, opts) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> Keyword.put(fd_opts, key, value)
      :error -> fd_opts
    end
  end

  defp put_card_digest(fd_opts, extra) do
    case Keyword.fetch(extra, :card_digest) do
      {:ok, digest} -> Keyword.put(fd_opts, :manifest_digest, digest)
      :error -> fd_opts
    end
  end

  defp sign_statement(statement, signer, opts) do
    Attestation.sign(statement, signer, keyid: Keyword.get(opts, :keyid))
  end

  defp attach_unknown_peer_rule(statement) do
    predicate = Map.get(statement, "predicate", %{})
    existing = Map.get(predicate, "matched_rules", [])
    predicate = Map.put(predicate, "matched_rules", [@unknown_peer_rule | existing])
    Map.put(statement, "predicate", predicate)
  end

  defp quarantine_unknown(%Decision{verdict: :blocked} = decision), do: decision
  defp quarantine_unknown(%Decision{} = decision), do: %{decision | action: :quarantine}

  defp resolve_peer(opts) do
    case Keyword.get(opts, :peer_card) do
      nil -> {:ok, :unknown}
      peer_card -> verify_peer_card(peer_card, opts)
    end
  end

  defp verify_peer_card(peer_card, opts) when is_map(peer_card) do
    if envelope?(peer_card) do
      verify_card_envelope(peer_card, opts)
    else
      with {:ok, card} <- AgentCard.new(peer_card),
           {:ok, digest} <- AgentCard.digest(card) do
        {:ok, {:verified, card, digest}}
      end
    end
  end

  defp verify_peer_card(_, _), do: {:error, :invalid_agent_card}

  defp verify_card_envelope(envelope, opts) do
    trust_material = Keyword.get(opts, :trust_material, %{})
    verify_opts = card_verify_opts(opts)

    with {:ok, card} <- AgentCard.verify(envelope, trust_material, verify_opts),
         {:ok, digest} <- AgentCard.digest(card) do
      {:ok, {:verified, card, digest}}
    end
  end

  defp verify_optional_peer_card(trust_material, opts) do
    case Keyword.get(opts, :peer_card) do
      nil ->
        {:ok, nil}

      envelope when is_map(envelope) ->
        material = Keyword.get(opts, :card_trust_material, trust_material)
        AgentCard.verify(envelope, material, card_verify_opts(opts))

      _ ->
        {:error, :invalid_agent_card}
    end
  end

  defp card_verify_opts(opts) do
    []
    |> maybe_put_opt(:now, Keyword.get(opts, :now))
    |> maybe_put_opt(:max_skew_ms, Keyword.get(opts, :max_skew_ms))
  end

  defp envelope?(%{} = map) do
    (Map.has_key?(map, "payloadType") or Map.has_key?(map, :payloadType)) and
      (Map.has_key?(map, "signatures") or Map.has_key?(map, :signatures))
  end

  defp match_agent_id(card, peer_agent_id) do
    if Map.get(card, "agent_id") == peer_agent_id do
      :ok
    else
      {:error, :unknown_agent}
    end
  end

  defp capability_declared(card, capability) do
    names =
      card
      |> Map.get("capabilities", [])
      |> Enum.map(&Map.get(&1, "name"))

    if capability in names, do: :ok, else: {:error, :unknown_capability}
  end

  defp derive_peer_trust(card, payload, opts) do
    resolver = build_resolver(opts)
    actor_ids = [Map.get(card, "agent_id") | delegation_actors(payload)]

    actor_ids
    |> Enum.map(&SigilGuard.Level.clamp(resolver.(&1)))
    |> min_trust()
  end

  defp delegation_actors(payload) do
    case fetch_field(payload, "delegation_chain") do
      {:ok, chain} when is_list(chain) ->
        Enum.flat_map(chain, fn
          hop when is_map(hop) -> List.wrap(fetch_field_value(hop, "actor"))
          _ -> []
        end)

      _ ->
        []
    end
  end

  defp build_resolver(opts) do
    resolve = Keyword.get(opts, :resolve)
    identity = Keyword.get(opts, :identity)

    cond do
      is_function(resolve, 1) -> resolve
      is_atom(identity) and not is_nil(identity) -> fn actor -> safe_identity(identity, actor) end
      true -> fn _ -> :low end
    end
  end

  defp safe_identity(module, actor) do
    if Code.ensure_loaded?(module) and function_exported?(module, :trust_level, 1) do
      module.trust_level(actor)
    else
      :low
    end
  rescue
    _ -> :low
  end

  defp min_trust(levels), do: Enum.reduce(levels, &min_level/2)

  defp min_level(level, acc) do
    if Identity.compare_trust(level, acc) == :gt, do: acc, else: level
  end

  # With a card the response is signed by one of the card's own keys. Without
  # one the trust material is what `Attestation.verify/3` takes, a bundle
  # included.
  defp response_key_material(%TrustBundle{} = bundle, nil), do: {:ok, bundle}

  defp response_key_material(trust_material, card) do
    base =
      if is_map(trust_material) and not bundle?(trust_material), do: trust_material, else: %{}

    material = Map.merge(base, card_public_keys(card))

    if map_size(material) > 0, do: {:ok, material}, else: {:error, :missing_trust_bundle}
  end

  defp card_public_keys(nil), do: %{}

  defp card_public_keys(card) do
    card
    |> Map.get("public_keys", [])
    |> Map.new(fn entry -> {Map.get(entry, "keyid"), Map.get(entry, "public_key")} end)
  end

  defp verify_opts(opts) do
    []
    |> maybe_put_opt(:now, Keyword.get(opts, :now))
    |> maybe_put_opt(:max_skew_ms, Keyword.get(opts, :max_skew_ms))
    |> maybe_put_opt(:replay, Keyword.get(opts, :replay))
    |> maybe_put_opt(:replay_ttl_ms, Keyword.get(opts, :replay_ttl_ms))
  end

  defp typed_predicate(statement, statement_type) do
    case Map.get(statement, "predicate") do
      %{"statement_type" => ^statement_type} = predicate -> {:ok, predicate}
      _ -> {:error, :invalid_payload}
    end
  end

  # What ties a response to this exchange beyond its back-reference: the
  # capability, the intended recipient, and the context digest.
  defp check_exchange(statement, predicate, card, opts) do
    with :ok <- check_capability(predicate, card, opts),
         :ok <- check_audience(predicate, opts) do
      check_context(statement, opts)
    end
  end

  defp check_capability(predicate, card, opts) do
    capability = Map.get(predicate, "capability")

    with :ok <- expected_capability(capability, Keyword.fetch(opts, :capability)) do
      card_capability(card, capability)
    end
  end

  defp expected_capability(_, :error), do: :ok
  defp expected_capability(capability, {:ok, capability}) when is_binary(capability), do: :ok
  defp expected_capability(_, {:ok, _}), do: {:error, :unknown_capability}

  defp card_capability(nil, _), do: :ok
  defp card_capability(card, capability), do: capability_declared(card, capability)

  defp check_audience(predicate, opts) do
    case Keyword.fetch(opts, :audience) do
      :error -> :ok
      {:ok, audience} -> matching_audience(predicate, audience)
    end
  end

  defp matching_audience(predicate, audience) when is_binary(audience) and audience != "" do
    if get_in(predicate, ["resource", "audience"]) == audience,
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp matching_audience(_, _), do: {:error, :invalid_audience}

  defp check_context(statement, opts) do
    case Keyword.fetch(opts, :context) do
      :error -> :ok
      {:ok, context} -> matching_context(statement, context)
    end
  end

  defp matching_context(statement, context) do
    with {:ok, expected} <- Digest.context_digest(:agent_response, context),
         {:ok, ^expected} <- subject_digest(statement, "context") do
      :ok
    else
      _ -> {:error, :digest_mismatch}
    end
  end

  defp check_back_reference(predicate, statement, request_action_digest, opts) do
    with :ok <- back_reference_field(predicate, request_action_digest) do
      back_reference_digest(statement, request_action_digest, opts)
    end
  end

  defp back_reference_field(predicate, request_action_digest) do
    if Map.get(predicate, "request_action_digest") == request_action_digest do
      :ok
    else
      {:error, :digest_mismatch}
    end
  end

  defp back_reference_digest(statement, request_action_digest, opts) do
    case Keyword.fetch(opts, :payload) do
      {:ok, payload} when is_map(payload) ->
        compare_response_digests(statement, payload, request_action_digest)

      # A response payload is a map. Skipping any other value would leave a
      # caller who passed one believing the content was bound.
      {:ok, _} ->
        {:error, :invalid_payload}

      :error ->
        :ok
    end
  end

  defp compare_response_digests(statement, payload, request_action_digest) do
    with {:ok, action} <- subject_digest(statement, "action"),
         {:ok, payload_digest} <- subject_digest(statement, "payload"),
         {:ok, expected_action} <-
           Digest.action_digest(:agent_response, payload, %{},
             request_action_digest: request_action_digest
           ),
         {:ok, expected_payload} <- Digest.payload_digest(payload),
         true <- action == expected_action and payload_digest == expected_payload do
      :ok
    else
      _ -> {:error, :digest_mismatch}
    end
  end

  defp check_card_binding(_, _, nil), do: :ok

  defp check_card_binding(predicate, statement, card) do
    with {:ok, card_digest} <- AgentCard.digest(card),
         peer_agent <- Map.get(predicate, "peer_agent", %{}),
         :ok <- match_response_agent_id(peer_agent, card),
         :ok <- match_card_digest(peer_agent, card_digest) do
      match_manifest_subject(statement, card_digest)
    end
  end

  defp match_response_agent_id(peer_agent, card) do
    if Map.get(peer_agent, "id") == Map.get(card, "agent_id") do
      :ok
    else
      {:error, :unknown_agent}
    end
  end

  defp match_card_digest(peer_agent, card_digest) do
    if Map.get(peer_agent, "card_digest") == card_digest do
      :ok
    else
      {:error, :card_digest_mismatch}
    end
  end

  defp match_manifest_subject(statement, card_digest) do
    case subject_digest(statement, "manifest") do
      {:ok, ^card_digest} -> :ok
      _ -> {:error, :manifest_digest_mismatch}
    end
  end

  defp subject_digest(statement, name) do
    subjects = Map.get(statement, "subject", [])

    case Enum.find(subjects, &(is_map(&1) and Map.get(&1, "name") == name)) do
      %{"digest" => %{"sha256" => hex}} when is_binary(hex) -> {:ok, hex}
      _ -> :error
    end
  end

  defp check_delegation_depth(payload, opts) do
    with {:ok, max} <- max_delegation_depth(opts) do
      enforce_delegation_depth(payload, max)
    end
  end

  defp enforce_delegation_depth(payload, max) do
    case fetch_field(payload, "delegation_chain") do
      {:ok, chain} when is_list(chain) and length(chain) > max -> {:error, :delegation_too_deep}
      _ -> :ok
    end
  end

  defp max_delegation_depth(opts) do
    case Keyword.keyword?(opts) and
           Keyword.get(opts, :max_delegation_depth, @default_max_delegation_depth) do
      max when is_integer(max) and max > 0 -> {:ok, max}
      _ -> {:error, :invalid_payload}
    end
  end

  defp fetch_signer(opts) do
    case Keyword.get(opts, :signer) do
      signer when is_atom(signer) and not is_nil(signer) -> {:ok, signer}
      _ -> {:error, :invalid_signer}
    end
  end

  defp fetch_decision(opts) do
    case Keyword.get(opts, :decision) do
      %Decision{} = decision -> {:ok, decision}
      _ -> {:error, :invalid_payload}
    end
  end

  defp required_digest(opts, key) do
    case Keyword.keyword?(opts) and Keyword.fetch(opts, key) do
      {:ok, digest} when is_binary(digest) ->
        if SigilGuard.Crypto.sha256_hex?(digest),
          do: {:ok, digest},
          else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp required_string(payload, key) do
    case fetch_field(payload, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_payload}
    end
  end

  defp fetch_field(map, key), do: SigilGuard.Field.fetch(map, key, @atom_fields)

  defp fetch_field_value(map, key), do: SigilGuard.Field.get(map, key, @atom_fields)

  defp bundle?(%TrustBundle{}), do: true
  defp bundle?(_), do: false

  defp maybe_put_opt(opts, _, nil), do: opts
  defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp emit_quarantine do
    Telemetry.emit([:sigil_guard, :agent_trust, :quarantine], %{}, %{
      reason: :unknown_peer,
      card_digest: nil
    })
  end

  defp span_metadata({:ok, _}, statement_type),
    do: %{statement_type: statement_type, result: :ok, error: nil}

  defp span_metadata({:error, reason}, statement_type),
    do: %{statement_type: statement_type, result: :error, error: reason}
end

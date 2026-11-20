defmodule SigilGuard.Runtime.Gate do
  @moduledoc """
  One decision for text crossing a boundary.

  `evaluate/3` normalizes the context, scans the text for secrets, inspects
  tool and resource output for quarantine indicators, classifies the action's
  risk against the caller's trust, applies the source-to-sink rules and any
  policy file, and emits telemetry that carries no raw content. It knows
  nothing of a transport: the MCP gateways call it before and after a tool
  runs.
  """

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Boundary
  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Crypto
  alias SigilGuard.Decision
  alias SigilGuard.Lifecycle
  alias SigilGuard.Policy
  alias SigilGuard.Quarantine
  alias SigilGuard.RepoPolicy
  alias SigilGuard.RepoPolicy.Decision, as: RepoDecision
  alias SigilGuard.Runtime.OutputContract
  alias SigilGuard.Scanner
  alias SigilGuard.Telemetry
  alias SigilGuard.Verdict

  @external_sinks ~w(external network log repo tool)a
  @risk_levels ~w(low medium high)a

  @doc """
  Evaluate whether a payload can cross the labeled boundary.

  `payload` may be a binary or a map containing `"text"`, `"content"`,
  `"output"`, or `"body"`. `context` may be a `%SigilGuard.Context{}`,
  map, or keyword list.

  ## Options

    * `:patterns` - scanner patterns
    * `:default_replacement` - binary replacement for scanner hits without a hint
    * `:risk_level` - override policy risk
    * `:on_sensitive` - `:block` or `:redact` for sensitive content
    * `:strict_quarantine` - block medium quarantine indicators too
    * `:decision_id` - a correlation id the host chooses: 1 to 128 visible
      ASCII characters. It is copied to `audit_metadata.decision_id` and the
      telemetry event so a span, an audit event and an attestation can name
      the same decision. Any other value is ignored. The gate generates none.
    * `:manifest_facts` - `%{manifest_digest: sha256, side_effects: [name]}` from
      a capability manifest the caller verified. The sandbox matrix and
      `effect:` policy rules use the classes it declares; without it a tool is
      class `execute`. `SigilGuard.ToolGateway` sets it from the pinned manifest.

  ## Examples

      iex> context = [phase: :tool_result, origin: :tool, sink: :model, trust_level: :high]
      ...> decision = SigilGuard.Runtime.Gate.evaluate("build finished in 42s", context)
      ...> {decision.verdict, decision.action}
      {:allowed, :allow}
      iex> decision = SigilGuard.Runtime.Gate.evaluate("key AKIAIOSFODNN7EXAMPLE", context)
      ...> {decision.action, decision.sanitized_text}
      {:redact, "key [AWS_KEY]"}

  """
  @spec evaluate(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def evaluate(payload, context \\ %Context{}, opts \\ []) do
    decision =
      payload
      |> evaluate_normalized(context, opts)
      |> put_correlation_id(opts)

    emit_decision(decision)
    decision
  end

  @doc false
  # The host's `:decision_id`, or nil for a value the events could not carry
  # as one attribute: 1 to 128 visible ASCII characters, no spaces or
  # control characters.
  @spec correlation_id(term()) :: String.t() | nil
  def correlation_id(opts) do
    with true <- Keyword.keyword?(opts),
         id when is_binary(id) <- Keyword.get(opts, :decision_id),
         true <- Regex.match?(~r/\A[\x21-\x7E]{1,128}\z/, id) do
      id
    else
      _ -> nil
    end
  end

  # A host-chosen correlation id. The gate mints none: a decision depends on
  # its inputs only. Every decision carries it, a refusal of malformed input
  # included.
  defp put_correlation_id(%Decision{} = decision, opts) do
    case correlation_id(opts) do
      nil -> decision
      id -> %{decision | audit_metadata: Map.put(decision.audit_metadata, :decision_id, id)}
    end
  end

  defp evaluate_normalized(payload, raw_context, opts) do
    case Context.cast(raw_context) do
      {:ok, context} ->
        with :ok <- Context.validate(context),
             :ok <- validate_runtime_options(opts),
             :ok <- SigilGuard.Limits.check(payload, opts),
             {:ok, text, action} <- runtime_inputs(payload, context) do
          evaluate_checked(payload, context, text, action, opts)
        else
          {:error, reason} -> malformed_input_decision(context, reason)
        end

      {:error, reason} ->
        malformed_input_decision(%Context{}, reason)
    end
  end

  defp validate_runtime_options(opts) do
    if Keyword.keyword?(opts) and BoundaryPolicy.valid_extension_options?(opts) and
         valid_indicator_sets?(opts) and is_binary(Keyword.get(opts, :default_replacement, "")),
       do: :ok,
       else: {:error, :invalid_options}
  end

  defp valid_indicator_sets?(opts) do
    case Keyword.fetch(opts, :indicator_sets) do
      {:ok, sets} -> Quarantine.valid_indicator_sets?(sets)
      :error -> true
    end
  end

  defp runtime_inputs(payload, context) do
    with {:ok, text} <- Context.fetch_text(payload),
         {:ok, action} <- Context.fetch_action_name(context, payload) do
      scan_text =
        case payload do
          %{binding: binding} when is_map(binding) ->
            SigilGuard.MCP.SecurityPayload.scan_text(binding)

          _ ->
            text
        end

      {:ok, scan_text, action}
    end
  end

  defp evaluate_checked(payload, context, text, action, opts) do
    {hits, scanner_error} = scan_hits(text, opts)
    quarantine = Quarantine.inspect(text, context, opts)
    {repo_policy, repo_facts} = repo_policy_decision(payload, context, action, opts)

    risk =
      risk_level(%{
        action: action,
        context: context,
        hits: hits,
        scanner_error: scanner_error,
        quarantine: quarantine,
        repo_policy: repo_policy,
        opts: opts
      })

    policy_verdict =
      if invalid_policy_risk_options?(action, opts) do
        :blocked
      else
        Policy.evaluate(action, context.trust_level, Keyword.put(opts, :risk_level, risk))
      end

    decide(%{
      payload: payload,
      text: text,
      action: action,
      context: context,
      hits: hits,
      scanner_error: scanner_error,
      quarantine: quarantine,
      repo_policy: repo_policy,
      repo_facts: repo_facts,
      risk: risk,
      policy_verdict: policy_verdict,
      opts: opts
    })
  end

  defp malformed_input_decision(context, reason) do
    quarantine = Quarantine.inspect(nil, context, [])

    %Decision{
      verdict: :blocked,
      action: :block,
      reason: "Malformed runtime input: #{reason}",
      phase: context.phase,
      risk_level: :high,
      trust_level: context.trust_level,
      hits: [],
      indicators: [],
      matched_rules: [%{rule_id: "gate.malformed_input", explanation: to_string(reason)}],
      evidence_refs: [],
      effect: nil,
      source: context.origin,
      sink: context.sink,
      trust_zone: context.trust_zone,
      actor: audit_binary(context.actor),
      resource: audit_binary(context.resource_uri),
      sanitized_text: nil,
      content_hash: quarantine.content_hash,
      audit_metadata: malformed_input_audit_metadata(context, reason, quarantine.content_hash)
    }
  end

  defp malformed_input_audit_metadata(context, reason, content_hash) do
    %{
      phase: context.phase,
      actor: context.actor,
      identity: context.identity,
      origin: context.origin,
      sink: context.sink,
      tool: audit_binary(context.tool),
      mcp_server: audit_binary(context.mcp_server),
      resource_uri: audit_binary(context.resource_uri),
      trust_zone: context.trust_zone,
      trust_level: context.trust_level,
      risk_level: :high,
      verdict: :blocked,
      action: :block,
      hit_count: 0,
      indicator_count: 0,
      indicator_ids: [],
      content_hash: content_hash,
      action_digest: nil,
      runtime_input_error: reason
    }
    |> put_present(:sandbox_id, audit_binary(context.sandbox_id))
  end

  defp audit_binary(value) when is_binary(value), do: value
  defp audit_binary(_), do: nil

  defp scan_hits(nil, _), do: {[], nil}

  defp scan_hits(text, opts) do
    case Scanner.scan_result(text, opts) do
      {:ok, _} -> {[], nil}
      {:hit, hits} -> {hits, nil}
      {:error, _} -> {scanner_error_hit(text), :scanner_failed}
    end
  end

  defp scanner_error_hit(""), do: []

  defp scanner_error_hit(text) do
    [
      %{
        name: "scanner_error",
        category: "scanner",
        severity: :high,
        match: "",
        offset: 0,
        length: byte_size(text),
        replacement_hint: "[SCANNER_ERROR]"
      }
    ]
  end

  defp risk_level(state) do
    state.opts
    |> Keyword.get_lazy(:risk_level, fn -> inferred_risk_level(state) end)
    |> normalize_risk_level()
  end

  # The highest risk any signal reports. The action's own classification
  # applies only when no signal reports one.
  defp inferred_risk_level(state) do
    signals =
      Enum.reject(
        [
          scanner_error_risk(state.scanner_error),
          repo_policy_risk(state.repo_policy),
          quarantine_risk(state.quarantine),
          hit_risk(state.hits, state.context)
        ],
        &is_nil/1
      )

    case signals do
      [] -> Policy.classify_risk(state.action, state.opts)
      [_ | _] -> Enum.max_by(signals, &risk_rank/1)
    end
  end

  defp scanner_error_risk(nil), do: nil
  defp scanner_error_risk(_), do: :high

  defp repo_policy_risk(repo_policy) do
    case repo_policy_verdict(repo_policy) do
      :block -> :high
      :require_approval -> :medium
      _ -> nil
    end
  end

  defp quarantine_risk(%{verdict: :blocked}), do: :high
  defp quarantine_risk(%{verdict: :suspicious}), do: :medium
  defp quarantine_risk(_), do: nil

  defp hit_risk(hits, context) do
    cond do
      Enum.any?(hits, &(&1.severity == :high)) and external_sink?(context.sink) -> :high
      hits != [] -> :medium
      true -> nil
    end
  end

  defp normalize_risk_level(risk) when risk in @risk_levels, do: risk
  defp normalize_risk_level(_), do: :high

  defp invalid_policy_risk_options?(action, opts) do
    invalid_risk_override?(opts) or invalid_risk_mappings?(action, opts)
  end

  defp invalid_risk_override?(opts) do
    case Keyword.fetch(opts, :risk_level) do
      {:ok, risk} -> risk not in @risk_levels
      :error -> false
    end
  end

  defp invalid_risk_mappings?(action, opts) do
    case Keyword.fetch(opts, :risk_mappings) do
      {:ok, mappings} when is_map(mappings) ->
        case Map.fetch(mappings, action) do
          {:ok, risk} -> risk not in @risk_levels
          :error -> false
        end

      {:ok, _} ->
        true

      :error ->
        false
    end
  end

  # Returns the repo decision and the `RepoPolicy.policy_facts/2` map the
  # kernel reads. Both are nil outside a repo change or without a policy.
  defp repo_policy_decision(_, %Context{phase: phase}, _, _) when phase != :repo_change,
    do: {nil, nil}

  defp repo_policy_decision(payload, context, action, opts) do
    with {:ok, raw_policy} <- repo_policy_source(opts),
         {:ok, policy} <- RepoPolicy.compile(raw_policy) do
      decision = RepoPolicy.evaluate(policy, repo_policy_context(payload, context, action))

      {decision, RepoPolicy.policy_facts(policy, decision)}
    else
      :error -> {nil, nil}
      {:error, reason} -> {{:error, reason}, nil}
    end
  end

  # An explicit `:repo_policy` wins. Otherwise the `[repo]` section of a
  # loaded `:boundary_policy` file applies.
  defp repo_policy_source(opts) do
    case {Keyword.fetch(opts, :repo_policy), Keyword.get(opts, :boundary_policy)} do
      {{:ok, raw_policy}, _} -> {:ok, raw_policy}
      {:error, %BoundaryPolicy.File{repo: %RepoPolicy{} = policy}} -> {:ok, policy}
      {:error, _} -> :error
    end
  end

  defp repo_policy_context(payload, context, action) do
    %{
      identity: context.identity,
      actor: context.actor,
      action: repo_policy_action(payload, context, action),
      changed_paths: changed_paths(payload, context)
    }
  end

  defp repo_policy_action(payload, context, fallback_action) do
    cond do
      context.action != nil ->
        context.action

      context.tool != nil ->
        context.tool

      true ->
        payload_repo_policy_action(payload, fallback_action)
    end
  end

  defp payload_repo_policy_action(payload, fallback_action) when is_map(payload) do
    case first_present_value(payload, repo_policy_action_keys()) do
      {:ok, nil} -> fallback_action
      {:ok, action} -> action
      :not_found -> fallback_action
    end
  end

  defp payload_repo_policy_action(_, fallback_action), do: fallback_action

  defp repo_policy_action_keys do
    [:action, "action", :tool, "tool", :name, "name"]
  end

  defp changed_paths(payload, context) do
    case first_present_value(context.metadata, changed_path_context_keys()) do
      {:ok, value} -> value
      :not_found -> payload_changed_paths(payload)
    end
  end

  defp payload_changed_paths(payload) do
    case first_present_value(payload, changed_path_payload_keys()) do
      {:ok, value} -> value
      :not_found -> []
    end
  end

  defp changed_path_context_keys do
    ["changed_paths", :changed_paths, "changed_files", :changed_files]
  end

  defp changed_path_payload_keys do
    ["changed_paths", :changed_paths, "changed_files", :changed_files, "files", :files]
  end

  defp first_present_value(map, keys) when is_map(map) do
    Enum.reduce_while(keys, :not_found, fn key, :not_found ->
      case Map.fetch(map, key) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :not_found}
      end
    end)
  end

  defp first_present_value(_, _), do: :not_found

  defp decide(state) do
    action_digest = Confirmation.fetch_action_digest(state.payload, state.context)
    boundary_decision = evaluate_boundary(state, action_digest)
    state = apply_advisory_signals(state, boundary_decision)

    {gate_verdict, gate_action, gate_reason} =
      strongest_verdict(state.policy_verdict, source_sink_verdict(state))

    {verdict, raw_action, reason} =
      combine_with_boundary({gate_verdict, gate_action, gate_reason}, boundary_decision)

    action = unified_action(verdict, raw_action)

    {verdict, action, reason, action_digest, action_digest_error} =
      enforce_confirmable_digest(action_digest, verdict, action, reason)

    effect = decision_effect(action, raw_action)
    sanitize_action = if action == :confirm, do: effect, else: action

    sanitized_text =
      sanitized_text(state.text, state.hits, state.quarantine, sanitize_action, state.opts)

    crossing =
      output_contract(state, %{
        verdict: verdict,
        action: action,
        effect: effect,
        reason: reason,
        sanitized_text: sanitized_text,
        rules: [],
        transforms: nil
      })

    %Decision{
      verdict: crossing.verdict,
      action: crossing.action,
      effect: crossing.effect,
      reason: crossing.reason,
      phase: state.context.phase,
      risk_level: state.risk,
      trust_level: state.context.trust_level,
      hits: state.hits,
      indicators: state.quarantine.indicators ++ state.advisory_indicators,
      matched_rules:
        matched_rules(gate_reason) ++
          boundary_matched_rules(boundary_decision) ++ crossing.rules,
      evidence_refs: [],
      source: state.context.origin,
      sink: state.context.sink,
      trust_zone: state.context.trust_zone,
      actor: audit_binary(state.context.actor),
      resource: audit_binary(state.context.resource_uri),
      sanitized_text: crossing.sanitized_text,
      content_hash: state.quarantine.content_hash,
      audit_metadata:
        state
        |> audit_metadata(crossing.verdict, crossing.action, action_digest, action_digest_error)
        |> put_present(:output_contract_transforms, crossing.transforms)
        |> put_present(:matched_rule_ids, rule_ids(boundary_decision, crossing))
    }
  end

  # SP.04 evaluation order step 3: the per-sink contract of the policy file,
  # for content the verdict lets cross. A stream evaluates windows of a
  # message and turns this step off.
  defp output_contract(state, %{action: action} = crossing)
       when action in [:allow, :redact, :confirm] do
    if Keyword.get(state.opts, :output_contracts, true) != false do
      state.opts
      |> Keyword.get(:boundary_policy)
      |> OutputContract.apply(
        state.context.sink,
        state.payload,
        crossing.sanitized_text,
        state.opts
      )
      |> contract_outcome(crossing, state.context.sink)
    else
      crossing
    end
  end

  defp output_contract(_, crossing), do: crossing

  defp contract_outcome(:none, crossing, _), do: crossing

  defp contract_outcome({:block, rule_id}, crossing, sink) do
    reason = "Output contract for sink #{sink} does not permit this content"

    %{
      crossing
      | verdict: :blocked,
        action: :block,
        effect: nil,
        reason: reason,
        rules: [%{rule_id: rule_id, explanation: reason}]
    }
  end

  defp contract_outcome({:crossed, _, []}, crossing, _), do: %{crossing | transforms: []}

  # Transformed content is released in place of the original, so an allow
  # becomes a redact, and a confirm releases the transformed text.
  defp contract_outcome({:crossed, text, transforms}, crossing, _) do
    %{crossing | sanitized_text: text, transforms: transforms}
    |> released_as_redact()
  end

  defp released_as_redact(%{action: :allow} = crossing),
    do: %{crossing | action: :redact, effect: :redact}

  defp released_as_redact(%{action: :confirm, effect: :allow} = crossing),
    do: %{crossing | effect: :redact}

  defp released_as_redact(crossing), do: crossing

  # Hooks and the adaptive detector run inside the kernel. Their indicators
  # join the decision, and a risk they raise goes back through the risk and
  # trust ladder. Neither can lower the risk the gate computed.
  defp apply_advisory_signals(state, %Decision{} = boundary_decision) do
    advisory_indicators =
      Enum.drop(boundary_decision.indicators, length(state.quarantine.indicators))

    state
    |> Map.put(:advisory_indicators, advisory_indicators)
    |> Map.put(:adaptive_error, boundary_decision.audit_metadata[:adaptive_error])
    |> raise_risk(boundary_decision.audit_metadata[:advisory_risk_level])
  end

  defp raise_risk(state, advisory) when advisory in @risk_levels do
    if risk_rank(advisory) > risk_rank(state.risk) do
      %{state | risk: advisory, policy_verdict: raised_policy_verdict(state, advisory)}
    else
      state
    end
  end

  defp raise_risk(state, _), do: state

  defp raised_policy_verdict(%{policy_verdict: :blocked}, _), do: :blocked

  defp raised_policy_verdict(state, risk) do
    Policy.evaluate(
      state.action,
      state.context.trust_level,
      Keyword.put(state.opts, :risk_level, risk)
    )
  end

  defp risk_rank(risk), do: Enum.find_index(@risk_levels, &(&1 == risk))

  # Evaluate the boundary policy kernel over a normalized `Boundary` and fold
  # its verdict into the gate's combination. The kernel contributes
  # policy-file `[rules]`, the sandbox matrix, hooks, adaptive
  # signals, and the shared invariants (untrusted-tool-request, secret->external);
  # the gate keeps scanner-failure, quarantine gradations, risk x trust, and the
  # broader sensitive-content rules it alone observes. The kernel always runs:
  # the digests are evidence, so a payload that cannot be digested still meets
  # the policy rules, and a Boundary the kernel rejects blocks.
  defp evaluate_boundary(state, action_digest) do
    state
    |> build_boundary(action_digest)
    |> BoundaryPolicy.evaluate(boundary_opts(state))
  end

  defp build_boundary(state, action_digest) do
    context = state.context

    payload_digest =
      evidence_digest(Digest.payload_digest(state.payload), "payload_digest_error:")

    action_digest = evidence_digest(action_digest, "action_digest_error:")

    Boundary.new(%{
      phase: boundary_phase(context.phase),
      source: context.origin,
      sink: context.sink,
      origin: context.origin,
      trust_level: context.trust_level,
      trust_zone: context.trust_zone,
      hits: state.hits,
      actor: boundary_fact("id", context.actor || context.identity),
      tool: boundary_tool(context.tool, Keyword.get(state.opts, :manifest_facts)),
      resource: boundary_fact("uri", context.resource_uri),
      indicators: state.quarantine.indicators,
      source_sensitivity: source_sensitivity(context),
      action_digest: action_digest,
      payload_digest: payload_digest,
      context_digest: boundary_context_digest(context),
      sandbox: boundary_sandbox(context)
    })
  end

  # `:manifest_facts` carries what a verified capability manifest declares.
  # Without it the tool is a name only, and the matrix treats it as `execute`.
  defp boundary_tool(nil, _), do: nil

  defp boundary_tool(name, %{manifest_digest: digest, side_effects: effects})
       when is_binary(digest) and is_list(effects),
       do: %{"name" => name, "manifest_digest" => digest, "side_effects" => effects}

  defp boundary_tool(name, _), do: %{"name" => name}

  # `Context` has no sensitivity field, and adding one would change every
  # confirmation digest. The host states it in context metadata instead.
  defp source_sensitivity(%Context{metadata: %{source_sensitivity: value}}), do: value
  defp source_sensitivity(%Context{metadata: %{"source_sensitivity" => value}}), do: value
  defp source_sensitivity(%Context{}), do: :internal

  defp boundary_fact(_, nil), do: nil
  defp boundary_fact(key, value), do: %{key => value}

  defp boundary_context_digest(context) do
    {:ok, statement_type} = Digest.phase_statement_type(context.phase)

    evidence_digest(Digest.context_digest(statement_type, context), "context_digest_error:")
  end

  defp evidence_digest({:ok, digest}, _), do: digest

  defp evidence_digest({:error, reason}, label),
    do: derived_digest(label <> Atom.to_string(reason))

  defp boundary_opts(state) do
    [
      evaluate_sandbox: not is_nil(state.context.isolation_level),
      repo_facts: state.repo_facts,
      on_sensitive: Keyword.get(state.opts, :on_sensitive, :block),
      policy: Keyword.get(state.opts, :boundary_policy),
      hooks: Keyword.get(state.opts, :hooks, []),
      adaptive_detector: Keyword.get(state.opts, :adaptive_detector),
      hook_timeout_ms: Keyword.get(state.opts, :hook_timeout_ms, 5_000),
      text: state.text || ""
    ]
  end

  # Supply a sandbox only when the host declared an isolation level. Sandbox
  # evaluation remains opt-in through that level.
  defp boundary_sandbox(%Context{isolation_level: nil}), do: nil

  defp boundary_sandbox(%Context{isolation_level: level, sandbox_id: id}) do
    %{"isolation_level" => level, "sandbox_id" => id}
  end

  defp boundary_phase(context_phase) do
    case Lifecycle.from_context_phase(context_phase) do
      {:ok, phase} -> phase
      :error -> :tool_request
    end
  end

  defp derived_digest(seed) do
    Crypto.sha256_hex(seed)
  end

  defp boundary_matched_rules(%Decision{matched_rules: rules}), do: rules

  defp combine_with_boundary({gate_verdict, gate_action, _} = gate, %Decision{} = boundary) do
    gate_rank = Verdict.rank(unified_strength(gate_verdict, gate_action))
    boundary_rank = Verdict.rank(unified_strength(boundary.verdict, boundary.action))

    if boundary_rank > gate_rank do
      {boundary.verdict, boundary.action, boundary.reason}
    else
      gate
    end
  end

  # Map a legacy verdict/action pair to its unified-enum strength so gate and
  # kernel contributions combine by the documented total order.
  defp unified_strength(:blocked, :quarantine), do: :quarantine
  defp unified_strength(:blocked, _), do: :block
  defp unified_strength({:confirm, _}, :quarantine), do: :quarantine
  defp unified_strength({:confirm, _}, _), do: :confirm
  defp unified_strength(:allowed, :redact), do: :redact
  defp unified_strength(:allowed, _), do: :allow

  # A confirming verdict's `action` is `:confirm`; the action to run once the
  # confirmation is accepted moves to `effect`. Every other verdict's action
  # is already in the closed set.
  defp unified_action({:confirm, _}, _), do: :confirm
  defp unified_action(_, action), do: action

  # `effect` is the post-confirmation executable action. For a `:confirm`
  # decision it is the underlying `:allow`/`:redact`/`:quarantine` the caller runs
  # after acceptance (`:require_approval`/`:confirm`-shaped source actions proceed
  # as `:allow`); for a crossing decision it mirrors the action; a block has none.
  defp decision_effect(:confirm, raw_action), do: normalize_effect(raw_action)
  defp decision_effect(action, _) when action in [:allow, :redact, :quarantine], do: action
  defp decision_effect(_, _), do: nil

  defp normalize_effect(action) when action in [:allow, :redact, :quarantine], do: action
  defp normalize_effect(_), do: :allow

  # The gate contributes one typed rule carrying its assembled reason. Kernel
  # rules are appended by `boundary_matched_rules/1`.
  defp matched_rules(nil), do: []
  defp matched_rules(reason) when is_binary(reason), do: [%{rule_id: "gate", explanation: reason}]

  defp enforce_confirmable_digest({:ok, digest}, {:confirm, _} = verdict, action, reason),
    do: {verdict, action, reason, digest, nil}

  defp enforce_confirmable_digest({:error, digest_error}, {:confirm, _}, _, _) do
    {:blocked, :block, "Confirmation action digest could not be computed: #{digest_error}", nil,
     digest_error}
  end

  defp enforce_confirmable_digest(_, verdict, action, reason) do
    {verdict, action, reason, nil, nil}
  end

  # Each signal contributes at most one verdict and the strongest wins by the
  # verdict order, so a repo approval rule cannot stand in front of a block
  # from the scanner or from quarantine. A tie keeps the earlier signal.
  defp source_sink_verdict(state) do
    contributions =
      Enum.reject(
        [
          scanner_verdict(state),
          repo_verdict(state.repo_policy),
          zone_verdict(state.context),
          quarantine_verdict(state.context, state.quarantine),
          hit_verdict(state)
        ],
        &is_nil/1
      )

    case contributions do
      [] -> {:allowed, :allow, nil}
      [_ | _] -> strongest_contribution(contributions)
    end
  end

  # An approval that wins over a redaction still releases redacted content.
  defp strongest_contribution(contributions) do
    case Enum.max_by(contributions, &contribution_rank/1) do
      {:confirm, :require_approval, reason} = approval ->
        if Enum.any?(contributions, &match?({:allowed, :redact, _}, &1)),
          do: {:confirm, :redact, reason},
          else: approval

      strongest ->
        strongest
    end
  end

  defp contribution_rank({:blocked, _, _}), do: Verdict.rank(:block)
  defp contribution_rank({:confirm, :quarantine, _}), do: Verdict.rank(:quarantine)
  defp contribution_rank({:confirm, _, _}), do: Verdict.rank(:confirm)
  defp contribution_rank({:allowed, :redact, _}), do: Verdict.rank(:redact)

  defp scanner_verdict(%{scanner_error: :scanner_failed}),
    do: {:blocked, :block, "Scanner failed during runtime gate: scanner_failed"}

  defp scanner_verdict(_), do: nil

  defp repo_verdict(%RepoDecision{verdict: :block} = decision),
    do: {:blocked, :block, decision.reason}

  defp repo_verdict(%RepoDecision{verdict: :require_approval} = decision),
    do: {:confirm, :require_approval, decision.reason}

  defp repo_verdict({:error, reason}),
    do: {:blocked, :block, "Repo policy could not be compiled: #{inspect(reason)}"}

  defp repo_verdict(_), do: nil

  defp zone_verdict(%Context{trust_zone: :untrusted, phase: :tool_request}),
    do: {:blocked, :block, "Untrusted tool requests cannot execute privileged actions"}

  defp zone_verdict(_), do: nil

  defp quarantine_verdict(context, %{verdict: :blocked}), do: blocked_quarantine_verdict(context)

  defp quarantine_verdict(%Context{phase: :tool_result}, %{verdict: :suspicious}),
    do: {:confirm, :quarantine, "Tool result should be reviewed before model ingestion"}

  defp quarantine_verdict(_, _), do: nil

  defp hit_verdict(%{context: context, hits: [_ | _], opts: opts}) do
    if external_sensitive_block?(context, opts) do
      {:blocked, :block, "Sensitive content cannot cross into #{context.sink} without redaction"}
    else
      {:allowed, :redact, "Sensitive content redacted before boundary crossing"}
    end
  end

  defp hit_verdict(_), do: nil

  defp blocked_quarantine_verdict(%Context{phase: :tool_result, sink: :model}) do
    {:confirm, :quarantine, "Tool result contains prompt-injection indicators"}
  end

  defp blocked_quarantine_verdict(_) do
    {:blocked, :block, "Content contains prompt-injection or exfiltration indicators"}
  end

  defp external_sensitive_block?(context, opts) do
    external_sink?(context.sink) and Keyword.get(opts, :on_sensitive, :block) == :block
  end

  defp strongest_verdict(:blocked, _), do: {:blocked, :block, "Policy blocked this action"}
  defp strongest_verdict(_, {:blocked, action, reason}), do: {:blocked, action, reason}

  defp strongest_verdict({:confirm, policy_reason}, {:confirm, action, source_reason}) do
    reason = Enum.join([policy_reason, source_reason], "; ")
    {{:confirm, reason}, action, source_reason}
  end

  defp strongest_verdict({:confirm, reason}, {:allowed, action, _}),
    do: {{:confirm, reason}, action, reason}

  defp strongest_verdict(:allowed, {:confirm, action, reason}),
    do: {{:confirm, reason}, action, reason}

  defp strongest_verdict(:allowed, {:allowed, action, reason}), do: {:allowed, action, reason}

  defp sanitized_text(nil, _, quarantine, _, _), do: quarantine.sanitized_text

  defp sanitized_text(text, hits, quarantine, action, opts) do
    redacted = redact_hits(text, hits, opts)

    cond do
      action == :quarantine ->
        Quarantine.sanitize(redacted)

      action == :redact ->
        redacted

      action == :block and hits != [] ->
        redacted

      action == :block and quarantine.indicators != [] ->
        Quarantine.sanitize(redacted)

      true ->
        text
    end
  end

  defp redact_hits(text, [], _), do: text
  defp redact_hits(text, hits, opts), do: Scanner.redact(text, hits, opts)

  defp external_sink?(sink), do: sink in @external_sinks

  defp audit_metadata(state, verdict, action, action_digest, action_digest_error) do
    %{
      phase: state.context.phase,
      actor: state.context.actor,
      identity: state.context.identity,
      origin: state.context.origin,
      sink: state.context.sink,
      tool: state.context.tool || action_from_payload(state.payload),
      mcp_server: state.context.mcp_server,
      resource_uri: state.context.resource_uri,
      trust_zone: state.context.trust_zone,
      trust_level: state.context.trust_level,
      risk_level: state.risk,
      verdict: audit_verdict(verdict),
      action: action,
      hit_count: length(state.hits),
      indicator_count: length(state.quarantine.indicators),
      indicator_ids: Enum.map(state.quarantine.indicators, & &1.id),
      content_hash: state.quarantine.content_hash,
      action_digest: action_digest,
      scanner_error: state.scanner_error
    }
    |> put_present(:action_digest_error, action_digest_error)
    |> put_repo_policy_metadata(state.repo_policy)
    |> put_repo_facts_metadata(state.repo_facts)
    |> put_advisory_metadata(state)
    |> put_present(:sandbox_id, audit_binary(state.context.sandbox_id))
  end

  # The kernel and contract rules behind the decision, for telemetry. The
  # gate's own `"gate"` rule carries a free-text reason and is left out.
  defp rule_ids(boundary_decision, crossing) do
    case Enum.map(boundary_matched_rules(boundary_decision) ++ crossing.rules, & &1.rule_id) do
      [] -> nil
      ids -> ids
    end
  end

  defp put_advisory_metadata(metadata, state) do
    metadata
    |> put_present(:advisory_indicator_count, advisory_count(state.advisory_indicators))
    |> put_present(:adaptive_error, state.adaptive_error)
  end

  defp advisory_count([]), do: nil
  defp advisory_count(indicators), do: length(indicators)

  defp put_present(metadata, _, nil), do: metadata
  defp put_present(metadata, key, value), do: Map.put(metadata, key, value)

  defp action_from_payload(payload) when is_map(payload) do
    payload[:tool] || payload["tool"] || payload[:action] || payload["action"]
  end

  defp action_from_payload(_), do: nil

  defp audit_verdict({:confirm, _}), do: :confirm
  defp audit_verdict(verdict), do: verdict

  defp repo_policy_verdict(%RepoDecision{verdict: verdict}), do: verdict
  defp repo_policy_verdict({:error, _}), do: :block
  defp repo_policy_verdict(_), do: nil

  defp put_repo_policy_metadata(metadata, %RepoDecision{} = decision) do
    Map.merge(metadata, %{
      repo_policy_verdict: decision.verdict,
      repo_policy_rules: decision.matched_rule_ids,
      repo_unmatched_paths: decision.unmatched_paths
    })
  end

  defp put_repo_policy_metadata(metadata, {:error, reason}) do
    Map.merge(metadata, %{
      repo_policy_verdict: :block,
      repo_policy_rules: [],
      repo_unmatched_paths: [],
      repo_policy_error: inspect(reason)
    })
  end

  defp put_repo_policy_metadata(metadata, _), do: metadata

  defp put_repo_facts_metadata(metadata, %{policy_file_digest: digest} = facts) do
    Map.merge(metadata, %{
      repo_policy_digest: digest,
      repo_policy_default: facts.default_decision
    })
  end

  defp put_repo_facts_metadata(metadata, _), do: metadata

  defp emit_decision(%Decision{} = decision) do
    Telemetry.emit(
      [:sigil_guard, :runtime, :gate],
      %{system_time: System.system_time()},
      Map.take(decision.audit_metadata, [
        :phase,
        :actor,
        :identity,
        :origin,
        :sink,
        :tool,
        :mcp_server,
        :resource_uri,
        :trust_zone,
        :trust_level,
        :risk_level,
        :verdict,
        :action,
        :hit_count,
        :indicator_count,
        :indicator_ids,
        :content_hash,
        :action_digest,
        :action_digest_error,
        :scanner_error,
        :runtime_input_error,
        :repo_policy_verdict,
        :repo_policy_rules,
        :repo_unmatched_paths,
        :repo_policy_error,
        :repo_policy_digest,
        :repo_policy_default,
        :decision_id,
        :sandbox_id,
        :matched_rule_ids
      ])
    )
  end
end

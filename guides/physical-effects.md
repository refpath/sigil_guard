# Physical-Effect Requests

A tool request that moves a robot arm, opens a valve, or starts a machine has
an effect that cannot be rolled back. `SigilGuard.EffectAuthority` and the
`:effect_binding` gateway option bind such a request to its target and
conditions, check those conditions again immediately before dispatch, and keep
a signed report apart from an observed result.

The contract is [SP.19](https://github.com/refpath/sigil_guard/blob/main/docs/specs/SP.19-physical-effect-authority.md).
The library keeps no durable state. The host owns the effect ledger, the
current facts, and the target protocol; [Limits](#limits) lists what the
library does not cover.

## 1. Carry A Binding Record

The request names what it will act on in a closed record under
`params._meta["dev.sigilguard/effect"]`. Every leaf value is a string. An
unknown key or a malformed value is refused.

```json
{
  "method": "tools/call",
  "params": {
    "name": "cell.move",
    "arguments": {"x_mm": 250, "y_mm": 100, "speed_mm_s": 120},
    "_meta": {
      "dev.sigilguard/effect": {
        "binding_format": "sigil_guard_effect_binding/v1",
        "operation_id": "op-0001",
        "target": {"id": "urn:example:cell-a:arm-1", "environment": "physical"},
        "artifacts": [{"name": "program", "sha256": "<64 hex characters>"}],
        "frame_revision": "cal-r3",
        "policy_epoch": "example-bundle:42",
        "not_before": "2026-11-19T12:00:00.000Z",
        "not_after": "2026-11-19T12:05:00.000Z"
      }
    }
  }
}
```

Use one `operation_id` per intended effect on a target. `policy_epoch` must
change whenever the trust bundle sequence, the policy file, or a revocation
changes. `target.environment` is `physical` or `simulated`; an approval for one
never admits against the other. Express quantities in integer base units: an
effect envelope bounds integers only, and `120` and `120.0` are different values
to a confirmation token.

## 2. Guard With `effect_binding: :required`

```elixir
decision =
  SigilGuard.ToolGateway.guard_request(request, context,
    manifests: manifests,
    boundary_policy: policy,
    confirmation_key: confirmation_key,
    effect_binding: :required
  )
```

With `:required` the gateway blocks a request without a valid record
(`:effect_binding_required`, `:invalid_effect_binding`), blocks
`consume_confirmation: false` (`:effect_replay_protection_required`), and
blocks a request whose digests cannot be computed (`:invalid_payload`), for
example one with a `null` argument or one over the input budget, which is
checked before any digest. Every other decision records
`action_digest`, `payload_digest`, `context_digest`, `effect_binding_digest`,
and `effect_operation_key` in `decision.audit_metadata`. An inbound
attestation nonce is consumed once, on the pass that allows execution. An
allowed decision also records `effect_authority_expires_at`, the earliest
`expires_at` of the accepted token and the consumed attestation.

The option only refuses. A valid record never replaces a confirmation the
policy requires.

## 3. Claim, Admit, Dispatch

The receiving boundary is the last host component that can refuse before I/O
reaches the target. It claims the operation in durable storage, checks current
conditions, records the dispatch, and only then sends the command.

```elixir
defmodule MyApp.Cell.Boundary do
  @moduledoc "Last host check before a command reaches the cell."

  alias SigilGuard.Decision
  alias SigilGuard.EffectAuthority

  @max_fact_age_ms 500

  @doc """
  Dispatch an allowed physical-effect request at most once.

  `ledger` is durable host storage with create-if-absent `claim/1`. `facts` is
  a zero-arity function that reads the current facts from host sources.
  """
  def dispatch(
        %Decision{verdict: :allowed, audit_metadata: %{effect_operation_key: key} = metadata} =
          decision,
        request,
        context,
        %{ledger: ledger, target: target, facts: facts}
      ) do
    record = %{
      operation_key: key,
      payload_digest: metadata.payload_digest,
      context_digest: metadata.context_digest,
      binding_digest: metadata.effect_binding_digest
    }

    with :claimed <- ledger.claim(record),
         :ok <- admit(decision, request, context, facts.()) do
      :ok = ledger.transition(key, :dispatched)
      target.send_command(key, request)
    else
      {:error, reason} ->
        :ok = ledger.transition(key, :refused)
        {:refused, reason}

      claim_result ->
        claim_result
    end
  end

  def dispatch(_, _, _, _), do: {:refused, :not_authorized}

  defp admit(decision, request, context, current) do
    EffectAuthority.admit(decision, request, context, current,
      max_fact_age_ms: @max_fact_age_ms
    )
  end
end
```

`context` is the same value the host passed to `guard_request/3`. The current
facts are an atom-keyed map the host builds from its own sources, never from
the request:

```elixir
%{
  principal: "spiffe://example.test/agent/planner",
  target: %{id: "urn:example:cell-a:arm-1", environment: :physical},
  artifacts: [%{name: "program", sha256: program_sha256}],
  frame_revision: "cal-r3",
  policy_epoch: "example-bundle:42",
  observed_at: observed_at,
  now: DateTime.utc_now()
}
```

`admit/5` returns `:ok` or `{:error, reason}` for the first failing check, such
as `:target_mismatch`, `:policy_epoch_mismatch`, `:stale_current_facts`, or
`:effect_deadline_passed`. It refuses with `:not_authorized` a decision that
does not allow this exact request, including a confirmed decision guarded with
`effect_binding: :off` and one whose `effect_operation_key` belongs to another
record. It refuses with `:authority_expired` when `now` is later than
`effect_authority_expires_at`, even inside the operation window, so an approval
that expires before dispatch needs a new one. The result is not a credential. It applies to the dispatch that follows
immediately.

## 4. Record The Outcome

A verified signature on a report shows which key endorsed it. It does not show
that the work succeeded. Classify the report and the host's own observations
separately:

```elixir
{:ok, outcome} =
  SigilGuard.EffectAuthority.classify_outcome(%{
    authentication: :verified,
    claimed: :success,
    issuer: "urn:example:cell-a:gateway",
    observations: [%{source: "urn:example:cell-a:camera-1", result: :confirms}],
    required_observations: 1
  })

{:ok, fields} =
  SigilGuard.EffectAuthority.audit_fields(%{
    state: :finished,
    binding_digest: binding_digest,
    operation_key: operation_key,
    outcome: outcome
  })

event =
  "mcp.tool_call"
  |> SigilGuard.Audit.new_event(actor, "cell.move", fields.result, fields.metadata)
  |> Map.put(:result_info, fields.result_info)
```

`fields.result_info.success` is `true` only when the observations accept the
result. A signed success claim with no observation leaves it `nil`. The audit
chain covers `result`, the ledger state; `result_info` and `metadata` are
outside the chain preimage.

## Effect Envelopes

An exact request is approved once. A generated program that chooses among a
finite set of operations and values can instead act under an effect envelope:
a closed document that lists the principal, artifacts, targets, tools with
their manifest digests, and an integer range or scalar enum for every
argument. Approve it by confirming a host-chosen request that carries the
document at `params._meta["dev.sigilguard/effect-envelope"]`, guarded with
`effect_binding: :off`, and call `EffectAuthority.envelope_digest/1` before
showing the approval. A record then names the envelope by `id` and `sha256`,
and the host passes the approved document as the `:envelope` option of
`admit/5`. Changing anything in an envelope changes its digest and needs a
new approval. The library keeps no record of which envelopes are approved.

## Host Obligations

| Concern | What the host does |
|---------|--------------------|
| Durable ledger | Writes the claim before any I/O, with create-if-absent semantics, in storage that survives restart and is visible to every host instance that can reach the target. |
| Existing claims | On equal digests, does not dispatch; reads the recorded state and reconciles. On different digests for the same key, refuses as a binding conflict. |
| Restart | Lets a record left in `claimed`, which saw no I/O, resume at admission with fresh facts. Marks a record in `dispatched`, `acknowledged`, or `cancel_requested` as `unknown` and reconciles it against the target; it is never dispatched again automatically. |
| Command identity | Carries `operation_id` in the target protocol's order or goal identity, where it has one, so the target can suppress a duplicate the ledger could not. |
| Argument schemas | Validates `minimum`, `maximum`, and `enum`. The library pins a tool's `input_schema` digest and does not evaluate arguments against it. |
| Acceptance criterion | Decides which observations count, how many are required, and whether their sources are independent. |

`EffectAuthority.valid_transition?/2` answers whether a ledger record may move
from one state to another. A cancel request moves a record to
`cancel_requested`. It becomes `cancelled` only on evidence that the work did
not complete.

## Limits

The replay store is per boot and per node: a confirmation token consumed
before a restart verifies again until it expires. The ledger, not the replay
store, prevents a repeated dispatch. A ledger gives at-most-once dispatch
decisions among cooperating hosts; a command can still be delivered and its
acknowledgement lost, and only the target can close that gap.

Admission narrows the interval between check and use. It does not close it:
after `admit/5` returns `:ok` a person can enter the workspace. Controller
state checks and the equipment's protective functions own that interval. The
library plans no motion and is not part of an emergency or protective stop. No
output of this library is a safety function, a certification, or a claim of
conformity with a machinery or cybersecurity standard.

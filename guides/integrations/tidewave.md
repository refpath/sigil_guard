# Tidewave Integration

Tidewave is dev-only tooling. SigilGuard does not make Tidewave safe for
production exposure and must not be used as a reason to expose Tidewave outside
a trusted development environment. The policy helper below supports host-owned
authorization for local development. It does not intercept Tidewave calls by
itself.

## Dependencies

For local validation:

```elixir
def deps do
  [
    {:tidewave, "~> 0.6.0", only: :dev},
    {:bandit, "~> 1.0", only: :dev},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

## Example Policy

This repository ships a Tidewave policy at
`examples/tidewave/SIGILGUARD_POLICY`. It:

- Blocks eval-class tools such as `project_eval`.
- Requires approval for write-class repo operations such as SQL mutation or
  file writes.
- Allows read-only docs and schema discovery tools such as `get_docs`,
  `get_source_location`, `get_ecto_schemas`, `get_ash_resources`, and
  `get_logs`.

Load it at application boot in development:

```elixir
{:ok, tidewave_policy} =
  SigilGuard.BoundaryPolicy.File.load("examples/tidewave")
```

## Integration Limitation

Tidewave 0.6.1 requires its public Plug to run before body parsing and raises if
`conn.body_params` is already populated. A wrapper that matches a parsed body
therefore raises on allowed calls, and unparsed calls bypass its guard.
Compile-only validation does not catch this.

There is no validated drop-in SigilGuard Plug adapter for this version. Do not
mount such a wrapper, call Tidewave's private router to bypass its checks, or
assume a policy helper intercepts requests automatically. A host transport
adapter must preserve Tidewave's local-address and Origin checks and define
bounded parsing and body replay. This library does not implement that adapter.

## Authorization At A Host-Owned Message Seam

Use the pure helper below where a host already owns the decoded message and
dispatch. `boundary` must contain trusted actor, tool, manifest, isolation and
digest facts constructed for that request, as required by `SigilGuard.Boundary`.
Tool identity and the complete request payload digest are checked before policy
evaluation. A policy allow still requires scanning the complete request. Only
`:allow` returns the original value; structured `:redact` is refused until the
host implements and revalidates a schema-specific transform.

```elixir
defmodule MyApp.TidewavePolicy do
  alias SigilGuard.{Boundary, BoundaryPolicy, Decision, ToolGateway}
  alias SigilGuard.Attestation.Digest

  def authorize(request, %Boundary{} = boundary, policy, opts \\ []) do
    with :ok <- Boundary.validate(boundary),
         :ok <- match_tool(request, boundary),
         {:ok, digest} <- Digest.payload_digest(request),
         true <- digest === boundary.payload_digest do
      case BoundaryPolicy.evaluate(boundary, policy: policy) do
        %Decision{action: :allow} -> scan_request(request, boundary, opts)
        %Decision{} = denied -> {:error, denied}
      end
    else
      false -> {:error, :payload_binding_mismatch}
      error -> error
    end
  end

  defp match_tool(%{"method" => "tools/call", "params" => %{"name" => name}}, boundary)
       when is_binary(name) do
    if boundary.phase == :tool_request and boundary.tool["name"] == name,
      do: :ok,
      else: {:error, :tool_binding_mismatch}
  end

  defp match_tool(_, _), do: {:error, :invalid_request}

  defp scan_request(request, boundary, opts) do
    context = [
      phase: :tool_request,
      origin: boundary.origin,
      sink: boundary.sink,
      tool: boundary.tool["name"],
      actor: boundary.actor["id"],
      trust_level: boundary.trust_level,
      trust_zone: boundary.trust_zone
    ]

    case ToolGateway.guard_request(request, context, opts) do
      %Decision{action: :allow} -> {:ok, request}
      %Decision{} = denied -> {:error, denied}
    end
  end
end
```

The helper neither authenticates a caller nor dispatches a Tidewave tool. The
host owns those steps and must not derive trusted boundary facts from model
arguments. Pass only host-configured gate options.

## Compatibility

- Target packages: `tidewave` `0.6.1`, `bandit` `1.12.0`.
- Validated 2026-09-11 with Elixir 1.19.6 / Erlang/OTP 28.5.0.6 against an
  unpacked SigilGuard Hex artifact in an isolated consumer.
- The authorization helper compiles with `mix compile --warnings-as-errors`.
  Three consumer tests pass, including the actual Tidewave parsed-body
  rejection. Core tests cover policy/scanner composition and identity binding.
- No drop-in transport adapter is validated for Tidewave 0.6.1.
- Hex reports Bandit 1.12.0 advisories CVE-2026-74836, CVE-2026-65623 and
  CVE-2026-75484. This pin records compatibility testing, not a deployment
  recommendation. SigilGuard does not add Bandit or Tidewave as dependencies.

Revalidate with
`SIGIL_GUIDE_TARGET=tidewave mix run /path/to/sigil_guard/bin/guide_consumer.exs`
(see [Library
Maintenance](../library-maintenance.md#revalidating-integration-guides)).

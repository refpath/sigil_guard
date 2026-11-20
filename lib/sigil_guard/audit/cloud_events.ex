defmodule SigilGuard.Audit.CloudEvents do
  @moduledoc """
  Project a signed audit event into a CloudEvents 1.0 envelope.

  `project/2` maps a `SigilGuard.Audit` event to a CloudEvents structured JSON
  envelope: `type` is the registered `io.sigilguard.decision.v1`, `source` is
  host-configured (recommended `urn:sigilguard:<deployment id>`), and trace
  context is projected via the CloudEvents distributed-tracing `traceparent`
  extension when `trace_id`/`span_id` are in the event metadata.

  The `data` payload is the privacy-filtered event: the scalar fields verbatim
  (`actor` is whatever the event already carries, so classify it with
  `SigilGuard.Audit.classify/2` first) plus an allowlist of the reserved
  metadata keys. Unknown host keys and raw content are omitted, and
  `trace_id`/`span_id` move to `traceparent` rather than appearing in `data`.
  """

  alias SigilGuard.Audit

  @specversion "1.0"
  @type_uri "io.sigilguard.decision.v1"
  @datacontenttype "application/json"
  @default_source "urn:sigilguard"

  # These reserved clear-class keys project into `data.metadata`.
  # `trace_id`/`span_id` are deliberately excluded - they become `traceparent`.
  @reserved_metadata_keys ~w(
    evidence decision_id decision scanner_summary
    action_digest payload_digest context_digest manifest_digest policy_digest
    sandbox_id quarantine_ref
  )

  @typedoc "A CloudEvents 1.0 structured JSON envelope."
  @type cloud_event :: %{required(String.t()) => term()}

  @doc """
  Project a signed audit `event` into a CloudEvents 1.0 envelope.

  Options:

    * `:source` - the CloudEvents `source` producer id (default `"urn:sigilguard"`;
      the recommended form is `urn:sigilguard:<deployment id>`).

  Emits `specversion` `1.0`, `type` `io.sigilguard.decision.v1`, and a
  privacy-filtered `data` object. A `traceparent` extension is added only when
  the event metadata holds a W3C `trace_id` (32 lowercase hex digits) and
  `span_id` (16), neither all zeros.
  """
  @spec project(Audit.t(), keyword()) :: cloud_event()
  def project(%Audit{} = event, opts \\ []) when is_list(opts) do
    envelope = %{
      "specversion" => @specversion,
      "id" => event.id,
      "source" => Keyword.get(opts, :source, @default_source),
      "type" => @type_uri,
      "time" => event.timestamp,
      "datacontenttype" => @datacontenttype,
      "data" => project_data(event)
    }

    maybe_put_traceparent(envelope, event.metadata)
  end

  defp project_data(event) do
    %{
      "id" => event.id,
      "type" => event.type,
      "actor" => event.actor,
      "action" => event.action,
      "result" => event.result,
      "timestamp" => event.timestamp,
      "metadata" => Map.take(event.metadata, @reserved_metadata_keys),
      "prev_hmac" => event.prev_hmac,
      "hmac" => event.hmac
    }
  end

  # W3C Trace Context: a 32-hex-digit trace id and a 16-hex-digit span id,
  # lowercase and not all zero. Other values would produce a header that
  # downstream tracers reject or misread, so they are left out.
  defp maybe_put_traceparent(envelope, metadata) do
    with trace_id when is_binary(trace_id) <- Map.get(metadata, "trace_id"),
         span_id when is_binary(span_id) <- Map.get(metadata, "span_id"),
         true <- trace_field?(trace_id, 32) and trace_field?(span_id, 16) do
      Map.put(envelope, "traceparent", "00-#{trace_id}-#{span_id}-01")
    else
      _ -> envelope
    end
  end

  defp trace_field?(value, size) do
    byte_size(value) == size and value =~ ~r/\A[0-9a-f]+\z/ and
      value != String.duplicate("0", size)
  end
end

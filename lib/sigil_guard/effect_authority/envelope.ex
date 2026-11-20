defmodule SigilGuard.EffectAuthority.Envelope do
  @moduledoc false

  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Crypto
  alias SigilGuard.EffectAuthority.Record
  alias SigilGuard.Limits
  alias SigilGuard.MCP.SecurityPayload

  @format "sigil_guard_effect_envelope/v1"
  @required ~w(envelope_format id principal artifacts targets operations policy_epoch not_after)
  @optional ~w(frame_revision)
  @max_targets 16
  @max_operations 64
  @max_enum 64
  @max_safe_integer 9_007_199_254_740_991

  @type refusal ::
          :unknown_effect_envelope
          | :invalid_effect_envelope
          | :effect_envelope_mismatch
          | :principal_mismatch
          | :target_out_of_envelope
          | :artifact_mismatch
          | :frame_revision_mismatch
          | :policy_epoch_mismatch
          | :effect_envelope_expired
          | :operation_out_of_envelope
          | :parameter_out_of_envelope

  @typedoc "Host and request values a record is checked against."
  @type subject :: %{
          actor: String.t() | nil,
          now: integer(),
          request: term(),
          manifest_digest: term()
        }

  @doc false
  @spec validate(term()) :: :ok | {:error, :invalid_effect_envelope}
  def validate(document) do
    if valid?(document), do: :ok, else: {:error, :invalid_effect_envelope}
  end

  @doc false
  @spec digest(term()) :: {:ok, String.t()} | {:error, :invalid_effect_envelope}
  def digest(document) do
    with :ok <- validate(document),
         {:ok, bytes} <- JCS.encode(document) do
      {:ok, Crypto.sha256_hex(bytes)}
    else
      {:error, _} -> {:error, :invalid_effect_envelope}
    end
  end

  @doc false
  @spec admit(map(), {:ok, term()} | :error, subject()) :: :ok | {:error, refusal()}
  def admit(%{"envelope" => _}, :error, _), do: {:error, :unknown_effect_envelope}
  def admit(_, :error, _), do: :ok

  def admit(%{"envelope" => reference} = record, {:ok, document}, subject) do
    with {:ok, sha256} <- digest(document),
         :ok <- check(same_document?(reference, document, sha256), :effect_envelope_mismatch),
         :ok <- conditions(record, document, subject),
         {:ok, operation} <- operation(document, subject) do
      parameters(operation["parameters"], arguments(subject.request))
    end
  end

  def admit(_, {:ok, _}, _), do: {:error, :effect_envelope_mismatch}

  defp same_document?(reference, document, sha256),
    do: reference["sha256"] == sha256 and reference["id"] == document["id"]

  defp conditions(record, document, subject) do
    with :ok <- check(subject.actor == document["principal"], :principal_mismatch),
         :ok <- check(record["target"] in document["targets"], :target_out_of_envelope),
         :ok <- check(record["artifacts"] == document["artifacts"], :artifact_mismatch),
         :ok <-
           check(
             record["frame_revision"] == document["frame_revision"],
             :frame_revision_mismatch
           ),
         :ok <- check(record["policy_epoch"] == document["policy_epoch"], :policy_epoch_mismatch) do
      check(within_lifetime?(record, document, subject.now), :effect_envelope_expired)
    end
  end

  defp within_lifetime?(record, document, now) do
    {:ok, envelope_end} = Record.timestamp(document["not_after"])
    {:ok, record_end} = Record.timestamp(record["not_after"])
    limit = DateTime.to_unix(envelope_end, :millisecond)

    now <= limit and DateTime.to_unix(record_end, :millisecond) <= limit
  end

  defp operation(document, subject) do
    tool = SecurityPayload.tool_name(subject.request)

    case Enum.find(document["operations"], &(&1["tool"] == tool)) do
      %{"manifest_sha256" => digest} = operation when digest == subject.manifest_digest ->
        {:ok, operation}

      _ ->
        {:error, :operation_out_of_envelope}
    end
  end

  # The record was read from these params, so they are a map.
  defp arguments(request) do
    {:ok, params} = Record.params(request)

    case params do
      %{"arguments" => arguments} -> arguments
      %{arguments: arguments} -> arguments
      _ -> %{}
    end
  end

  defp parameters(bounds, arguments) when is_map(arguments) do
    same_keys? = Enum.sort(Map.keys(arguments)) == Enum.sort(Map.keys(bounds))

    check(
      same_keys? and Enum.all?(bounds, fn {name, bound} -> within?(bound, arguments[name]) end),
      :parameter_out_of_envelope
    )
  end

  defp parameters(_, _), do: {:error, :parameter_out_of_envelope}

  defp within?(%{"enum" => values}, value), do: value in values

  defp within?(%{"range" => %{"min" => min, "max" => max}}, value),
    do: is_integer(value) and min <= value and value <= max

  defp check(true, _), do: :ok
  defp check(false, reason), do: {:error, reason}

  defp valid?(document) when is_map(document) do
    Limits.check(document) == :ok and Record.closed?(document, @required, @optional) and
      scalars?(document) and Record.artifacts?(document["artifacts"]) and
      targets?(document["targets"]) and operations?(document["operations"])
  end

  defp valid?(_), do: false

  defp scalars?(document) do
    document["envelope_format"] == @format and Record.identifier?(document["id"]) and
      Record.identifier?(document["principal"]) and Record.identifier?(document["policy_epoch"]) and
      match?({:ok, _}, Record.timestamp(document["not_after"])) and
      (not Map.has_key?(document, "frame_revision") or
         Record.identifier?(document["frame_revision"]))
  end

  defp targets?([_ | _] = targets) do
    Record.bounded_list?(targets, @max_targets) and Enum.all?(targets, &Record.target?/1) and
      Record.strictly_ascending?(Enum.map(targets, & &1["id"]))
  end

  defp targets?(_), do: false

  defp operations?([_ | _] = operations) do
    Record.bounded_list?(operations, @max_operations) and Enum.all?(operations, &operation?/1) and
      Record.strictly_ascending?(Enum.map(operations, & &1["tool"]))
  end

  defp operations?(_), do: false

  defp operation?(
         %{"tool" => tool, "manifest_sha256" => digest, "parameters" => parameters} = operation
       )
       when map_size(operation) == 3 and is_map(parameters) do
    Record.identifier?(tool) and Record.sha256?(digest) and
      Enum.all?(parameters, fn {name, bound} -> parameter_name?(name) and bound?(bound) end)
  end

  defp operation?(_), do: false

  defp parameter_name?(name), do: is_binary(name) and name != "" and String.valid?(name)

  defp bound?(%{"enum" => [_ | _] = values} = bound) when map_size(bound) == 1,
    do: Record.bounded_list?(values, @max_enum) and Enum.all?(values, &enum_scalar?/1)

  defp bound?(%{"range" => %{"min" => min, "max" => max} = range} = bound)
       when map_size(bound) == 1 and map_size(range) == 2,
       do: safe_integer?(min) and safe_integer?(max) and min <= max

  defp bound?(_), do: false

  defp enum_scalar?(value) when is_binary(value), do: String.valid?(value)
  defp enum_scalar?(value), do: is_boolean(value) or safe_integer?(value)

  defp safe_integer?(value),
    do: is_integer(value) and value >= -@max_safe_integer and value <= @max_safe_integer
end

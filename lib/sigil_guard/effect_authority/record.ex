defmodule SigilGuard.EffectAuthority.Record do
  @moduledoc false

  alias SigilGuard.Limits

  @record_key "dev.sigilguard/effect"
  @format "sigil_guard_effect_binding/v1"
  @required ~w(binding_format operation_id target policy_epoch not_after)
  @optional ~w(artifacts frame_revision not_before envelope)
  @environments ~w(physical simulated)
  @max_artifacts 16
  @max_identifier_bytes 256
  @timestamp ~r/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\z/
  @sha256 ~r/\A[0-9a-f]{64}\z/

  @type error :: :effect_binding_required | :invalid_effect_binding

  @doc false
  @spec fetch(term()) :: {:ok, map()} | {:error, error()}
  def fetch(request) do
    with {:ok, params} <- params(request),
         {:ok, metadata} <- metadata(params),
         {:ok, record} <- Map.fetch(metadata, @record_key),
         :ok <- validate(record) do
      {:ok, record}
    else
      :error -> {:error, :effect_binding_required}
      :ambiguous -> {:error, :invalid_effect_binding}
      {:error, :invalid_effect_binding} = error -> error
    end
  end

  @doc false
  @spec validate(term()) :: :ok | {:error, :invalid_effect_binding}
  def validate(record) do
    if valid?(record), do: :ok, else: {:error, :invalid_effect_binding}
  end

  @doc false
  @spec closed?(map(), [String.t()], [String.t()]) :: boolean()
  def closed?(map, required, optional) do
    keys = Map.keys(map)

    Enum.all?(required, &(&1 in keys)) and
      Enum.all?(keys, &(&1 in required or &1 in optional))
  end

  @doc false
  @spec identifier?(term()) :: boolean()
  def identifier?(value) when is_binary(value) and byte_size(value) in 1..@max_identifier_bytes,
    do: printable?(value)

  def identifier?(_), do: false

  @doc false
  @spec sha256?(term()) :: boolean()
  def sha256?(value), do: is_binary(value) and Regex.match?(@sha256, value)

  @doc false
  @spec timestamp(term()) :: {:ok, DateTime.t()} | :error
  def timestamp(value) when is_binary(value) do
    with true <- Regex.match?(@timestamp, value),
         {:ok, datetime, 0} <- DateTime.from_iso8601(value) do
      {:ok, datetime}
    else
      _ -> :error
    end
  end

  def timestamp(_), do: :error

  @doc false
  @spec target?(term()) :: boolean()
  def target?(%{"id" => id, "environment" => environment} = target) when map_size(target) == 2,
    do: identifier?(id) and environment in @environments

  def target?(_), do: false

  @doc false
  @spec artifacts?(term()) :: boolean()
  def artifacts?([_ | _] = artifacts) do
    bounded_list?(artifacts, @max_artifacts) and Enum.all?(artifacts, &artifact?/1) and
      strictly_ascending?(Enum.map(artifacts, & &1["name"]))
  end

  def artifacts?(_), do: false

  @doc false
  @spec bounded_list?(term(), non_neg_integer()) :: boolean()
  def bounded_list?([], _), do: true
  def bounded_list?([_ | rest], left) when left > 0, do: bounded_list?(rest, left - 1)
  def bounded_list?(_, _), do: false

  @doc false
  @spec strictly_ascending?([String.t()]) :: boolean()
  def strictly_ascending?([first, second | rest]) when first < second,
    do: strictly_ascending?([second | rest])

  def strictly_ascending?([_, _ | _]), do: false
  def strictly_ascending?(_), do: true

  defp params(%{"params" => params}) when is_map(params), do: {:ok, params}
  defp params(%{"params" => _}), do: :error
  defp params(%{params: params}) when is_map(params), do: {:ok, params}
  defp params(_), do: :error

  defp metadata(%{"_meta" => _, _meta: _}), do: :ambiguous
  defp metadata(%{"_meta" => metadata}) when is_map(metadata), do: {:ok, metadata}
  defp metadata(%{_meta: metadata}) when is_map(metadata), do: {:ok, metadata}
  defp metadata(_), do: :error

  defp valid?(record) when is_map(record) do
    Limits.check(record) == :ok and closed?(record, @required, @optional) and
      required_fields?(record) and optional_fields?(record) and window?(record)
  end

  defp valid?(_), do: false

  defp required_fields?(record) do
    record["binding_format"] == @format and identifier?(record["operation_id"]) and
      target?(record["target"]) and identifier?(record["policy_epoch"])
  end

  defp optional_fields?(record) do
    absent_or?(record, "artifacts", &artifacts?/1) and
      absent_or?(record, "frame_revision", &identifier?/1) and
      absent_or?(record, "envelope", &envelope_reference?/1)
  end

  defp absent_or?(record, key, valid?) do
    case Map.fetch(record, key) do
      {:ok, value} -> valid?.(value)
      :error -> true
    end
  end

  defp window?(record) do
    with {:ok, not_after} <- timestamp(record["not_after"]),
         {:ok, not_before} <- not_before(record) do
      is_nil(not_before) or DateTime.before?(not_before, not_after)
    else
      :error -> false
    end
  end

  defp not_before(%{"not_before" => value}), do: timestamp(value)
  defp not_before(_), do: {:ok, nil}

  defp artifact?(%{"name" => name, "sha256" => digest} = artifact) when map_size(artifact) == 2,
    do: identifier?(name) and sha256?(digest)

  defp artifact?(_), do: false

  defp envelope_reference?(%{"id" => id, "sha256" => digest} = reference)
       when map_size(reference) == 2,
       do: identifier?(id) and sha256?(digest)

  defp envelope_reference?(_), do: false

  defp printable?(<<byte, rest::binary>>) when byte in 0x21..0x7E, do: printable?(rest)
  defp printable?(<<>>), do: true
  defp printable?(_), do: false
end

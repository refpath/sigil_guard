defmodule SigilGuard.EffectAuthority.Facts do
  @moduledoc false

  alias SigilGuard.EffectAuthority.Record

  @required [:principal, :target, :policy_epoch, :observed_at, :now]
  @optional [:artifacts, :frame_revision]
  @environments %{physical: "physical", simulated: "simulated"}
  @max_artifacts 16

  @type t :: %{
          principal: String.t(),
          target: %{String.t() => String.t()},
          artifacts: %{String.t() => String.t()} | nil,
          frame_revision: String.t() | nil,
          policy_epoch: String.t(),
          observed_at: integer(),
          now: integer()
        }

  @doc false
  @spec validate(term()) :: {:ok, t()} | {:error, :invalid_current_facts}
  def validate(current) when is_map(current) and not is_struct(current) do
    with true <- closed?(current),
         {:ok, target} <- target(current[:target]),
         {:ok, artifacts} <- artifacts(Map.fetch(current, :artifacts)),
         {:ok, observed_at} <- unix_ms(current[:observed_at]),
         {:ok, now} <- unix_ms(current[:now]),
         true <- identifiers?(current) do
      {:ok,
       %{
         principal: current.principal,
         target: target,
         artifacts: artifacts,
         frame_revision: current[:frame_revision],
         policy_epoch: current.policy_epoch,
         observed_at: observed_at,
         now: now
       }}
    else
      _ -> {:error, :invalid_current_facts}
    end
  end

  def validate(_), do: {:error, :invalid_current_facts}

  defp closed?(current) do
    keys = Map.keys(current)

    Enum.all?(@required, &(&1 in keys)) and
      Enum.all?(keys, &(&1 in @required or &1 in @optional))
  end

  defp identifiers?(current) do
    Record.identifier?(current.principal) and Record.identifier?(current.policy_epoch) and
      (not Map.has_key?(current, :frame_revision) or Record.identifier?(current.frame_revision))
  end

  defp target(%{id: id, environment: environment} = target) when map_size(target) == 2 do
    with true <- Record.identifier?(id),
         {:ok, name} <- Map.fetch(@environments, environment) do
      {:ok, %{"id" => id, "environment" => name}}
    else
      _ -> :error
    end
  end

  defp target(_), do: :error

  defp artifacts(:error), do: {:ok, nil}

  defp artifacts({:ok, [_ | _] = artifacts}) do
    with true <- Record.bounded_list?(artifacts, @max_artifacts),
         true <- Enum.all?(artifacts, &artifact?/1),
         digests = Map.new(artifacts, &{&1.name, &1.sha256}),
         true <- map_size(digests) == length(artifacts) do
      {:ok, digests}
    else
      _ -> :error
    end
  end

  defp artifacts(_), do: :error

  defp artifact?(%{name: name, sha256: digest} = artifact) when map_size(artifact) == 2,
    do: Record.identifier?(name) and Record.sha256?(digest)

  defp artifact?(_), do: false

  # A DateTime built by hand can hold any term in its fields, and the calendar
  # functions raise on those.
  defp unix_ms(%DateTime{} = datetime) do
    {:ok, DateTime.to_unix(datetime, :millisecond)}
  rescue
    _ in [ArgumentError, ArithmeticError, FunctionClauseError, UndefinedFunctionError] -> :error
  end

  defp unix_ms(_), do: :error
end

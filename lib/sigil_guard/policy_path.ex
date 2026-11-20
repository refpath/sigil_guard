defmodule SigilGuard.PolicyPath do
  @moduledoc false

  # Locating a policy file under a repository root. A candidate counts only
  # when it stays inside the root and no path segment on the way is a symlink,
  # so a link cannot point the loader at a file outside the repository.

  @doc false
  @spec inside_root?(Path.t(), Path.t()) :: boolean()
  def inside_root?(root, path) do
    root = Path.expand(root)
    path = Path.expand(path)
    path == root or String.starts_with?(path, root <> "/")
  end

  @doc false
  @spec first_existing(Path.t(), [Path.t()]) :: Path.t() | nil
  def first_existing(root, candidates) do
    Enum.find_value(candidates, fn relative ->
      path = Path.expand(relative, root)
      if inside_root?(root, path) and safe_regular_candidate?(root, path), do: path
    end)
  end

  @doc false
  @spec safe_regular_candidate?(Path.t(), Path.t()) :: boolean()
  def safe_regular_candidate?(root, path) do
    path
    |> Path.relative_to(root)
    |> Path.split()
    |> Enum.reduce_while(root, fn segment, current ->
      candidate = Path.join(current, segment)

      case File.lstat(candidate) do
        {:ok, %{type: :symlink}} -> {:halt, false}
        {:ok, _} -> {:cont, candidate}
        {:error, _} -> {:halt, false}
      end
    end)
    |> then(&(&1 == path and File.regular?(path)))
  end
end

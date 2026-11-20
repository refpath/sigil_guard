defmodule SigilGuard.CaseFixtures do
  @moduledoc false

  # Byte helpers shared by tests that pin digests or tamper with signed values.

  @doc "Lowercase hex SHA-256 of the bytes."
  @spec sha256_hex(iodata()) :: String.t()
  def sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  @doc "A hex string with its first digit changed, so it stays hex but no longer matches."
  @spec flip_hex(String.t()) :: String.t()
  def flip_hex(<<first::binary-size(1), rest::binary>>) do
    flipped = if first == "0", do: "1", else: "0"
    flipped <> rest
  end

  @doc "A base64 string with its first character changed, so it still decodes but differs."
  @spec flip_base64(String.t()) :: String.t()
  def flip_base64(<<first::binary-size(1), rest::binary>>) do
    flipped = if first == "A", do: "B", else: "A"
    flipped <> rest
  end
end

defmodule SigilGuard.CaseFixtures.Signer do
  @moduledoc false
  use SigilGuard.TestSigner, seed: :crypto.hash(:sha256, "sigil_guard_case_signer")
end

defmodule SigilGuard.CaseFixtures.AdvisoryHook do
  @moduledoc false

  @behaviour SigilGuard.Hooks
  @signal %{
    risk_level: :medium,
    indicators: [%{"id" => "hook-string-id", "category" => "change"}]
  }

  @impl SigilGuard.Hooks
  def on_tool_request(_, _), do: {:ok, :continue, @signal}
  @impl SigilGuard.Hooks
  def on_tool_result(_, _), do: {:ok, :continue, @signal}
end

defmodule SigilGuard.CaseFixtures.HookMedium do
  @moduledoc false

  @behaviour SigilGuard.Hooks
  @impl SigilGuard.Hooks
  def on_tool_request(_, _), do: {:ok, :continue, %{risk_level: :medium}}
end

defmodule SigilGuard.CaseFixtures.HookHigh do
  @moduledoc false

  @behaviour SigilGuard.Hooks
  @impl SigilGuard.Hooks
  def on_tool_request(_, _), do: {:ok, :continue, %{risk_level: :high}}
end

defmodule SigilGuard.CaseFixtures.DetectorHigh do
  @moduledoc false

  @behaviour SigilGuard.AdaptiveDetector
  @impl SigilGuard.AdaptiveDetector
  def analyze(_, _, _), do: {:ok, [%{id: "adaptive-1", severity: :high, confidence: 0.9}]}
end

defmodule SigilGuard.CaseFixtures.DetectorLow do
  @moduledoc false

  @behaviour SigilGuard.AdaptiveDetector
  @impl SigilGuard.AdaptiveDetector
  def analyze(_, _, _), do: {:ok, [%{id: "adaptive-1", severity: :low, confidence: 0.9}]}
end

defmodule SigilGuard.CaseFixtures.NotifyOkHook do
  @moduledoc false

  @behaviour SigilGuard.Hooks
  @impl SigilGuard.Hooks
  def on_session_start(_, _), do: :ok
end

defmodule SigilGuard.CaseFixtures.BadIndicatorsHook do
  @moduledoc false

  def on_tool_request(_, _), do: {:ok, :continue, %{indicators: :not_a_list}}
  def on_session_start(_, _), do: {:ok, %{indicators: :not_a_list}}
end

defmodule SigilGuard.CaseFixtures.SelfKillHook do
  @moduledoc false

  def on_tool_request(_, _) do
    Process.exit(self(), :kill)
    {:ok, :continue}
  end
end

defmodule SigilGuard.CaseFixtures.SelfKillDetector do
  @moduledoc false

  def analyze(_, _, _) do
    Process.exit(self(), :kill)
    {:ok, []}
  end
end

defmodule SigilGuard.CaseFixtures.ThrowDetector do
  @moduledoc false

  @dialyzer {:nowarn_function, analyze: 3}

  @spec analyze(term(), term(), term()) :: no_return()
  def analyze(_, _, _), do: throw(:detector_gave_up)
end

defmodule SigilGuard.CaseFixtures.ExitDetector do
  @moduledoc false

  @dialyzer {:nowarn_function, analyze: 3}

  @spec analyze(term(), term(), term()) :: no_return()
  def analyze(_, _, _), do: exit(:detector_exit)
end

defmodule SigilGuard.CaseFixtures.Tmp do
  @moduledoc false

  @root Path.join(System.tmp_dir!(), "sigil_guard_case_fixtures")

  @spec root() :: String.t()
  def root, do: @root

  @spec dir(String.t()) :: String.t()
  def dir(label) do
    # The integer restarts with each VM, so a random suffix keeps a directory
    # left by an earlier run from being reused with its old files.
    suffix = Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
    path = Path.join(@root, "#{label}_#{System.unique_integer([:positive])}_#{suffix}")
    File.rm_rf!(path)
    File.mkdir_p!(path)
    path
  end

  @spec fixture_root([{String.t(), iodata()}]) :: String.t()
  def fixture_root(files) do
    root = dir("fixture")

    Enum.each(files, fn {relative_path, content} ->
      path = Path.join(root, relative_path)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, content)
    end)

    root
  end
end

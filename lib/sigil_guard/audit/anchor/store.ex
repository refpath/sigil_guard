defmodule SigilGuard.Audit.Anchor.Store do
  @moduledoc """
  Behaviour and facade for external audit anchor storage.

  Anchor records are compact, JSON-compatible checkpoint summaries. A store
  persists those records somewhere outside the local audit chain, such as an
  append-only file, WORM bucket, transparency log, or database table. Stores
  should return a receipt that lets callers fetch the same anchor later.
  """

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Field
  alias SigilGuard.Telemetry

  @atom_fields %{
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "storage" => :storage,
    "uri" => :uri,
    "worm" => :worm
  }
  @anchor_kind "sigil_guard.audit.anchor"

  @typedoc "Store-specific persistence receipt for an anchor record."
  @type receipt :: %{required(String.t()) => term()}

  @callback put(Anchor.t(), keyword()) :: {:ok, receipt()} | {:error, term()}
  @callback fetch(receipt() | String.t(), keyword()) :: {:ok, Anchor.t()} | {:error, term()}

  @doc """
  Persist an anchor record through a store module.

  Options:

    * `:require_worm` - when `true`, rejects receipts unless they explicitly
      mark the external storage target as immutable with `"worm"` or `:worm`
      set to `true`.
  """
  @spec put(module(), Anchor.t(), keyword()) :: {:ok, receipt()} | {:error, term()}
  def put(store, record, opts \\ [])

  def put(store, record, opts) when is_atom(store) and is_map(record) and is_list(opts) do
    if Keyword.keyword?(opts) do
      put_with_valid_options(store, record, opts)
    else
      {:error, :invalid_options}
    end
  end

  def put(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor record by store receipt or digest.
  """
  @spec fetch(module(), receipt() | String.t(), keyword()) ::
          {:ok, Anchor.t()} | {:error, term()}
  def fetch(store, receipt_or_digest, opts \\ [])

  def fetch(store, receipt_or_digest, opts) when is_atom(store) and is_list(opts) do
    if Keyword.keyword?(opts) do
      fetch_with_valid_options(store, receipt_or_digest, opts)
    else
      {:error, :invalid_options}
    end
  end

  def fetch(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor from a store and verify it against a checkpoint.
  """
  @spec verify(module(), receipt() | String.t(), Checkpoint.t(), keyword()) ::
          {:ok, Anchor.verified()} | {:error, term()}
  def verify(store, receipt_or_digest, checkpoint, opts \\ [])

  def verify(store, receipt_or_digest, checkpoint, opts) when is_map(checkpoint) do
    span(:verify, store, fn ->
      case fetch(store, receipt_or_digest, opts) do
        {:ok, record} -> Anchor.verify(record, checkpoint)
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  def verify(_, _, _, _), do: {:error, :invalid_anchor}

  defp put_with_valid_options(store, record, opts) do
    span(:put, store, fn ->
      result = if store?(store), do: store.put(record, opts), else: {:error, :invalid_store}
      enforce_required_worm(result, opts)
    end)
  end

  defp fetch_with_valid_options(store, receipt_or_digest, opts) do
    span(:fetch, store, fn ->
      result =
        if store?(store),
          do: store.fetch(receipt_or_digest, opts),
          else: {:error, :invalid_store}

      enforce_anchor_result(result)
    end)
  end

  defp span(operation, store, fun) do
    metadata = %{anchor_store: inspect(store)}

    Telemetry.span([:sigil_guard, :audit, :anchor_store, operation], metadata, fn ->
      result = fun.()
      {result, Map.merge(metadata, result_metadata(result))}
    end)
  end

  defp result_metadata({:ok, receipt_or_record}) do
    receipt_or_record
    |> digest_metadata()
    |> Map.merge(storage_metadata(receipt_or_record))
    |> Map.put(:outcome, :ok)
  end

  defp result_metadata({:error, reason}) do
    %{outcome: :error, error_reason: reason}
  end

  defp result_metadata(_), do: %{outcome: :unknown}

  defp enforce_required_worm({:ok, receipt}, opts) when is_map(receipt) do
    cond do
      not SigilGuard.Options.flag(opts, :require_worm, false, true) ->
        {:ok, receipt}

      field(receipt, "worm") == true ->
        {:ok, receipt}

      true ->
        {:error, :worm_required}
    end
  end

  defp enforce_required_worm({:ok, _}, _), do: {:error, :invalid_receipt}
  defp enforce_required_worm(result, _), do: result

  # The helpers below are shared by the built-in stores.

  # A store reports a record of another kind as an invalid anchor.
  @doc false
  @spec validate_anchor(Anchor.t()) ::
          :ok
          | {:error,
             :invalid_anchor
             | :invalid_metadata
             | :invalid_uri
             | :invalid_version
             | :invalid_worm
             | :missing_anchored_at
             | :missing_checkpoint_digest
             | :missing_event_count
             | :missing_merkle_root
             | :missing_storage}
  def validate_anchor(record) do
    case Anchor.validate(record) do
      {:error, :invalid_kind} -> {:error, :invalid_anchor}
      result -> result
    end
  end

  # Receipt metadata must encode as a JSON object with unique keys, so an
  # atom key and its string twin are refused.
  @doc false
  @spec metadata(keyword()) :: {:ok, map()} | {:error, :invalid_metadata}
  def metadata(opts) do
    with metadata when is_map(metadata) <- Keyword.get(opts, :metadata, %{}),
         {:ok, _} <- Jason.encode(metadata, maps: :strict) do
      {:ok, metadata}
    else
      _ -> {:error, :invalid_metadata}
    end
  rescue
    _ in [Protocol.UndefinedError, UnicodeConversionError] -> {:error, :invalid_metadata}
  end

  # A reference is a bare digest or a receipt. A receipt names its digest in
  # `anchor_digest`, or in the fragment of its URI; `uri_digest` reads that
  # fragment the way the store writes it. When both are present they must
  # agree.
  @doc false
  @spec digest_from_ref(term(), (map() -> String.t() | nil)) ::
          {:ok, String.t()} | {:error, :missing_digest | :digest_mismatch}
  def digest_from_ref(digest, _) when is_binary(digest) do
    if SigilGuard.Crypto.sha256_hex?(digest), do: {:ok, digest}, else: {:error, :missing_digest}
  end

  def digest_from_ref(%{} = receipt, uri_digest) do
    case Field.fetch(receipt, "anchor_digest", %{"anchor_digest" => :anchor_digest}) do
      {:ok, digest} when is_binary(digest) ->
        with {:ok, digest} <- digest_from_ref(digest, uri_digest),
             :ok <- check_uri_digest(uri_digest.(receipt), digest),
             do: {:ok, digest}

      {:ok, _} ->
        {:error, :missing_digest}

      :error ->
        case uri_digest.(receipt) do
          digest when is_binary(digest) -> digest_from_ref(digest, uri_digest)
          _ -> {:error, :missing_digest}
        end
    end
  end

  def digest_from_ref(_, _), do: {:error, :missing_digest}

  # A URI fragment that is not a digest says nothing about the anchor; one
  # that is must name the same anchor.
  @doc false
  @spec check_uri_digest(term(), String.t()) :: :ok | {:error, :digest_mismatch}
  def check_uri_digest(uri_digest, digest) do
    if SigilGuard.Crypto.sha256_hex?(uri_digest) and uri_digest != digest,
      do: {:error, :digest_mismatch},
      else: :ok
  end

  defp enforce_anchor_result({:ok, record}) when is_map(record) do
    with :ok <- validate_anchor(record), do: {:ok, record}
  end

  defp enforce_anchor_result({:ok, _}), do: {:error, :invalid_anchor}
  defp enforce_anchor_result(result), do: result

  defp digest_metadata(%{digest: digest}) when is_binary(digest), do: %{anchor_digest: digest}

  defp digest_metadata(%{} = map) do
    case {field(map, "anchor_digest"), field(map, "kind")} do
      {digest, _} when is_binary(digest) -> %{anchor_digest: digest}
      {_, @anchor_kind} -> %{anchor_digest: Anchor.digest(map)}
      _ -> %{}
    end
  end

  defp storage_metadata(%{record: record}) when is_map(record), do: storage_metadata(record)

  defp storage_metadata(%{} = map) do
    %{}
    |> Field.put_present(:anchor_storage, field(map, "storage"))
    |> Field.put_present(:anchor_uri_scheme, uri_scheme(field(map, "uri")))
  end

  defp uri_scheme(uri) when is_binary(uri), do: URI.parse(uri).scheme
  defp uri_scheme(_), do: nil

  defp field(map, key) when is_map(map), do: Field.get(map, key, @atom_fields)

  defp store?(store) do
    Code.ensure_loaded?(store) and function_exported?(store, :put, 2) and
      function_exported?(store, :fetch, 2)
  end
end

defmodule SigilGuard.Audit.Anchor do
  @moduledoc """
  External anchor records for audit checkpoints.

  `SigilGuard.Audit.Checkpoint` proves the local audit segment shape. An anchor
  record is the small JSON-compatible object that a deployment writes to an
  external append-only or WORM system. It carries the checkpoint digest plus a
  compact summary that can be compared later without storing raw audit events in
  the external system.

  Any append-only store can persist the returned record: S3 Object Lock, immutable blob
  storage, transparency logs, notarization services, or database append-only
  tables can all persist the returned record.
  """

  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Crypto

  @kind "sigil_guard.audit.anchor"
  @version 1
  @atom_fields %{
    "anchored_at" => :anchored_at,
    "chain_id" => :chain_id,
    "checkpoint_digest" => :checkpoint_digest,
    "checkpoint_kind" => :checkpoint_kind,
    "event_count" => :event_count,
    "kind" => :kind,
    "last_event_id" => :last_event_id,
    "last_hmac" => :last_hmac,
    "merkle_root" => :merkle_root,
    "metadata" => :metadata,
    "storage" => :storage,
    "uri" => :uri,
    "version" => :version,
    "worm" => :worm
  }

  @typedoc "An audit anchor record with string keys."
  @type t :: %{required(String.t()) => term()}

  @typedoc "An anchor record that verified, with its digest."
  @type verified :: %{
          record: t(),
          digest: String.t()
        }

  @doc """
  Create an external anchor record for a checkpoint.

  Options:

    * `:anchored_at` - optional ISO 8601 timestamp, defaults to current UTC.
    * `:storage` - external store kind, such as `"s3-object-lock"` or `"worm"`.
    * `:uri` - immutable object/log location assigned by the external store.
    * `:worm` - whether the target store is expected to be immutable.
    * `:metadata` - JSON-compatible deployment metadata.
  """
  @spec create(Checkpoint.t(), keyword()) :: t()
  def create(checkpoint, opts \\ []) when is_map(checkpoint) and is_list(opts) do
    %{
      "kind" => @kind,
      "version" => @version,
      "anchored_at" => Keyword.get_lazy(opts, :anchored_at, &timestamp/0),
      "checkpoint_digest" => Checkpoint.digest(checkpoint),
      "checkpoint_kind" => field(checkpoint, "kind"),
      "chain_id" => field(checkpoint, "chain_id"),
      "event_count" => field(checkpoint, "event_count"),
      "last_event_id" => field(checkpoint, "last_event_id"),
      "last_hmac" => field(checkpoint, "last_hmac"),
      "merkle_root" => field(checkpoint, "merkle_root"),
      "metadata" => Keyword.get(opts, :metadata, %{}),
      "storage" => normalize_value(Keyword.get(opts, :storage, "external")),
      "uri" => Keyword.get(opts, :uri),
      "worm" => Keyword.get(opts, :worm, true)
    }
  end

  @doc """
  Verify an anchor record against a checkpoint.
  """
  @spec verify(t(), Checkpoint.t()) :: {:ok, verified()} | {:error, atom()}
  def verify(record, checkpoint) when is_map(record) and is_map(checkpoint) do
    with {:ok, record_digest} <- verify_record(record),
         {:ok, checkpoint_digest} <- safe_checkpoint_digest(checkpoint),
         :ok <- verify_checkpoint_digest(record, checkpoint_digest),
         :ok <- verify_checkpoint_summary(record, checkpoint) do
      {:ok, %{record: record, digest: record_digest}}
    end
  end

  def verify(_, _), do: {:error, :invalid_anchor}

  @doc """
  Validate the standalone shape of an anchor record.

  This checks the stable fields that can be validated before a checkpoint is
  available. Use `verify/2` when comparing an anchor to its checkpoint.
  """
  @spec validate(t()) :: :ok | {:error, atom()}
  def validate(record) when is_map(record) do
    case verify_record(record) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  def validate(_), do: {:error, :invalid_anchor}

  @doc """
  Return canonical anchor bytes used for digesting and external comparison.
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(record) when is_map(record) do
    record
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical anchor bytes.
  """
  @spec digest(t()) :: String.t()
  def digest(record) when is_map(record) do
    record
    |> canonical_bytes()
    |> Crypto.sha256_hex()
  end

  defp verify_static_fields(record) do
    with :ok <- require_field(record, "kind", @kind, :invalid_kind),
         :ok <- require_field(record, "version", @version, :invalid_version),
         :ok <- require_binary(field(record, "anchored_at"), :missing_anchored_at),
         :ok <- require_binary(field(record, "checkpoint_digest"), :missing_checkpoint_digest),
         :ok <- require_integer(field(record, "event_count"), :missing_event_count),
         :ok <- require_binary(field(record, "merkle_root"), :missing_merkle_root),
         :ok <- require_binary(field(record, "storage"), :missing_storage),
         :ok <- require_optional_binary(field(record, "uri"), :invalid_uri),
         :ok <- require_boolean(field(record, "worm"), :invalid_worm) do
      require_metadata(field(record, "metadata"))
    end
  end

  defp verify_record(record) do
    with :ok <- verify_static_fields(record) do
      safe_digest(record)
    end
  end

  defp verify_checkpoint_digest(record, checkpoint_digest) do
    if Crypto.secure_compare(field(record, "checkpoint_digest"), checkpoint_digest) do
      :ok
    else
      {:error, :anchor_mismatch}
    end
  end

  defp verify_checkpoint_summary(record, checkpoint) do
    matches? =
      field(record, "checkpoint_kind") === field(checkpoint, "kind") and
        field(record, "chain_id") === field(checkpoint, "chain_id") and
        field(record, "event_count") === field(checkpoint, "event_count") and
        field(record, "last_event_id") === field(checkpoint, "last_event_id") and
        field(record, "last_hmac") === field(checkpoint, "last_hmac") and
        field(record, "merkle_root") === field(checkpoint, "merkle_root")

    if matches?, do: :ok, else: {:error, :anchor_mismatch}
  end

  defp require_field(record, key, value, reason) do
    if field(record, key) === value, do: :ok, else: {:error, reason}
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_optional_binary(nil, _), do: :ok
  defp require_optional_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_optional_binary(_, reason), do: {:error, reason}

  defp require_boolean(value, _) when is_boolean(value), do: :ok
  defp require_boolean(_, reason), do: {:error, reason}

  defp require_integer(value, _) when is_integer(value) and value >= 0, do: :ok
  defp require_integer(_, reason), do: {:error, reason}

  defp require_metadata(metadata) when is_map(metadata), do: :ok
  defp require_metadata(_), do: {:error, :invalid_metadata}

  defp safe_digest(record) do
    with true <- is_map(record),
         {:ok, iodata} <- SigilGuard.Canonical.LegacyJSON.encode(record) do
      {:ok, Crypto.sha256_hex(IO.iodata_to_binary(iodata))}
    else
      _ -> {:error, :invalid_anchor}
    end
  end

  defp safe_checkpoint_digest(checkpoint) do
    case Checkpoint.fetch_digest(checkpoint) do
      {:ok, digest} -> {:ok, digest}
      :error -> {:error, :invalid_checkpoint}
    end
  end

  defp field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Map.fetch!(@atom_fields, key))
    end
  end

  defp normalize_value(value) when is_atom(value), do: Atom.to_string(value)
  defp normalize_value(value), do: value

  defp timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end

  defp canonical_iodata(value), do: SigilGuard.Canonical.LegacyJSON.encode!(value)
end

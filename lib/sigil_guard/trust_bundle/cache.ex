defmodule SigilGuard.TrustBundle.Cache do
  @moduledoc """
  Per-boot ETS snapshot cache for verified trust bundles.

  The cache keeps the last accepted bundle for each bundle id and the
  monotonic rollback floor observed during this boot. It does not verify
  signatures or documents; callers must only pass verified
  `SigilGuard.TrustBundle` structs.
  """

  alias SigilGuard.Crypto
  alias SigilGuard.TrustBundle

  @table SigilGuard.Runtime.Tables.trust_bundle()

  @typedoc """
  A pinned root: version, signature threshold, key ids, raw public keys, and
  the `roles` and `keys` of the bundle that pinned it.
  """
  @type root_pin :: %{
          required(:version) => pos_integer(),
          required(:threshold) => pos_integer(),
          required(:keyids) => [String.t()],
          required(:keys) => %{String.t() => binary()},
          optional(:authority) => map()
        }

  @typedoc "Why `put/1` refused a bundle."
  @type put_error ::
          :sequence_below_floor
          | :forked_root_chain
          | :revoked_key
          | :cache_unavailable
          | :invalid_bundle

  @doc """
  Create the trust-bundle ETS table if it does not already exist.

  `SigilGuard.Runtime` calls this when it starts and thereby owns the table.
  No other function creates it. Without the table, readers find nothing and
  `put/1` returns `{:error, :cache_unavailable}`.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    SigilGuard.Runtime.Tables.ensure(@table, [
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])
  end

  @doc """
  Fetch the cached snapshot for a bundle id.

  Returns `{:ok, bundle}`, or `:error` when nothing is cached for the id or
  the runtime is not running.
  """
  @doc since: "1.1.0"
  @spec fetch(bundle_id :: String.t()) :: {:ok, TrustBundle.t()} | :error
  def fetch(bundle_id) when is_binary(bundle_id) do
    case lookup(bundle_id) do
      [{^bundle_id, bundle, _, _, _, _}] -> {:ok, bundle}
      [] -> :error
    end
  end

  @doc """
  Return the cached snapshot for a bundle id.

  The same as `fetch/1`; the name does not follow the `get` convention, which
  returns a value or a default.
  """
  @doc deprecated: "Use SigilGuard.TrustBundle.Cache.fetch/1"
  @spec get(bundle_id :: String.t()) :: {:ok, TrustBundle.t()} | :error
  def get(bundle_id) when is_binary(bundle_id), do: fetch(bundle_id)

  @doc """
  Return the root descriptor pinned for a bundle id, or `:error` when none is
  pinned. Rotation verification starts from it.
  """
  @spec root_pin(bundle_id :: String.t()) :: {:ok, root_pin()} | :error
  def root_pin(bundle_id) when is_binary(bundle_id) do
    case lookup(bundle_id) do
      [{^bundle_id, _, _, nil, _, _}] -> :error
      [{^bundle_id, _, _, pin, _, _}] -> {:ok, pin}
      [] -> :error
    end
  end

  # The key ids a bundle document itself revokes.
  @doc false
  @spec document_revoked_keyids(map()) :: MapSet.t(String.t())
  def document_revoked_keyids(document) do
    document
    |> Map.get("revocations", [])
    |> Enum.filter(&(is_map(&1) and Map.get(&1, "kind") == "key"))
    |> MapSet.new(&Map.get(&1, "id"))
  end

  @doc """
  Return the key ids revoked for a bundle id. Revocations accumulate and are
  never lifted by a later bundle.
  """
  @spec revoked_keyids(bundle_id :: String.t()) :: MapSet.t(String.t())
  def revoked_keyids(bundle_id) when is_binary(bundle_id) do
    case lookup(bundle_id) do
      [{^bundle_id, _, _, _, _, revoked}] -> revoked
      [] -> MapSet.new()
    end
  end

  @doc """
  Return the digest of the rotation accepted for a root version of a bundle
  id. A different rotation for the same version is a fork.
  """
  @spec rotation_digest(bundle_id :: String.t(), root_version :: pos_integer()) ::
          {:ok, String.t()} | :error
  def rotation_digest(bundle_id, root_version)
      when is_binary(bundle_id) and is_integer(root_version) do
    case lookup(bundle_id) do
      [{^bundle_id, _, _, _, digests, _}] -> Map.fetch(digests, root_version)
      [] -> :error
    end
  end

  @doc """
  Check whether `put/1` would accept `bundle`, without recording anything.

  `SigilGuard.TrustBundle.verify/2` calls this as the last verification step,
  so a bundle below the state already accepted in this boot is refused even
  when the caller does not cache it.
  """
  @doc since: "1.1.0"
  @spec check(TrustBundle.t()) :: :ok | {:error, put_error()}
  def check(%TrustBundle{bundle_id: bundle_id, sequence: sequence} = bundle)
      when is_binary(bundle_id) and is_integer(sequence) and sequence > 0 do
    case lookup(bundle_id) do
      [] -> :ok
      [row] -> rejection(bundle, row)
    end
  end

  def check(%TrustBundle{}), do: {:error, :invalid_bundle}

  @doc """
  Accept a verified trust-bundle snapshot if it advances the sequence floor.

  A byte-identical re-put, represented by the same sequence and digest, is
  an accepted no-op. A stale sequence, a bundle below the current floor, or
  a duplicate sequence with a different digest fails with
  `:sequence_below_floor`.
  """
  @spec put(TrustBundle.t()) :: {:ok, TrustBundle.t()} | {:error, put_error()}
  def put(%TrustBundle{bundle_id: bundle_id, sequence: sequence} = bundle)
      when is_binary(bundle_id) and is_integer(sequence) and sequence > 0 do
    case table_lookup(bundle_id) do
      :unavailable -> {:error, :cache_unavailable}
      [] -> put_new(bundle)
      [row] -> put_existing(bundle, row)
    end
  end

  def put(%TrustBundle{}), do: {:error, :invalid_bundle}

  @doc """
  Return the current monotonic floor for a bundle id.

  Unknown bundle ids return `0`.
  """
  @spec floor(bundle_id :: String.t()) :: non_neg_integer()
  def floor(bundle_id) when is_binary(bundle_id) do
    case lookup(bundle_id) do
      [{^bundle_id, _, floor, _, _, _}] -> floor
      [] -> 0
    end
  end

  @doc """
  Remove every cached bundle, pin, rotation and revocation. Intended for
  tests; a running host loses its rollback floors.
  """
  @spec clear() :: :ok
  def clear do
    if :ets.whereis(@table) != :undefined, do: :ets.delete_all_objects(@table)
    :ok
  end

  # A reader sees a missing table as an empty one: nothing has been accepted
  # in this boot. Only `ensure_table/0` creates the table, so that its owner
  # is the runtime and not whichever process asked first.
  defp lookup(bundle_id) do
    case table_lookup(bundle_id) do
      :unavailable -> []
      rows -> rows
    end
  end

  defp table_lookup(bundle_id) do
    if :ets.whereis(@table) == :undefined,
      do: :unavailable,
      else: :ets.lookup(@table, bundle_id)
  end

  defp put_new(bundle) do
    floor = accepted_floor(0, bundle)

    inserted? =
      :ets.insert_new(
        @table,
        {bundle.bundle_id, bundle, floor, build_root_pin(bundle), rotation_digests(bundle),
         document_revoked_keyids(bundle.document)}
      )

    if inserted?, do: {:ok, bundle}, else: put(bundle)
  end

  # `:ok` for the cached snapshot itself and for a bundle that advances it.
  defp rejection(bundle, {_, cached, floor, _, digests, revoked}) do
    cond do
      same_snapshot?(bundle, cached) -> :ok
      bundle.sequence <= cached.sequence -> {:error, :sequence_below_floor}
      bundle.sequence < floor -> {:error, :sequence_below_floor}
      root_version_below_cached?(bundle, cached) -> {:error, :sequence_below_floor}
      revoked_signature?(bundle, revoked) -> {:error, :revoked_key}
      forked_authority?(bundle, cached, digests) -> {:error, :forked_root_chain}
      true -> :ok
    end
  end

  defp put_existing(bundle, {_, cached, _, _, _, _} = row) do
    case {same_snapshot?(bundle, cached), rejection(bundle, row)} do
      {true, _} -> {:ok, cached}
      {false, {:error, reason}} -> {:error, reason}
      {false, :ok} -> replace(bundle, row)
    end
  end

  defp replace(bundle, {_, _, floor, pin, digests, revoked} = row) do
    replacement =
      {bundle.bundle_id, bundle, accepted_floor(floor, bundle), pin,
       Map.merge(digests, rotation_digests(bundle)),
       MapSet.union(revoked, document_revoked_keyids(bundle.document))}

    match = [
      {{bundle.bundle_id, :"$2", :"$3", :"$4", :"$5", :"$6"}, [{:"=:=", :"$_", {:const, row}}],
       [{:const, replacement}]}
    ]

    if :ets.select_replace(@table, match) == 1, do: {:ok, bundle}, else: put(bundle)
  end

  defp revoked_signature?(bundle, revoked) do
    bundle.envelope
    |> Map.get("signatures", [])
    |> Enum.any?(&MapSet.member?(revoked, Map.get(&1, "keyid")))
  end

  defp forked_authority?(bundle, cached, digests) do
    changed_roles? =
      bundle.root_version == cached.root_version and
        Map.take(bundle.document, ["keys", "roles"]) !=
          Map.take(cached.document, ["keys", "roles"])

    changed_roles? or
      Enum.any?(rotation_digests(bundle), fn {version, digest} ->
        Map.has_key?(digests, version) and Map.fetch!(digests, version) != digest
      end)
  end

  defp same_snapshot?(bundle, cached) do
    bundle.sequence == cached.sequence and bundle.digest == cached.digest
  end

  defp root_version_below_cached?(bundle, cached) do
    bundle.root_version < cached.root_version
  end

  defp accepted_floor(floor, bundle) do
    max(floor, max(rollback_floor(bundle), bundle.sequence))
  end

  defp rollback_floor(%TrustBundle{document: %{"rollback_floor" => rollback_floor}})
       when is_binary(rollback_floor) do
    String.to_integer(rollback_floor)
  end

  defp rollback_floor(_), do: 0

  defp build_root_pin(
         %TrustBundle{document: %{"roles" => %{"root" => root}, "keys" => _}} = bundle
       ) do
    %{
      version: bundle.root_version,
      threshold: Map.fetch!(root, "threshold"),
      keyids: Map.fetch!(root, "keyids"),
      keys: decoded_keys(bundle.document),
      authority: Map.take(bundle.document, ["roles", "keys"])
    }
  end

  defp build_root_pin(_), do: nil

  defp rotation_digests(bundle) do
    bundle.document
    |> Map.get("rotation_chain", [])
    |> Map.new(fn envelope ->
      document = envelope_document!(envelope)
      {String.to_integer(Map.fetch!(document, "root_version")), document_digest!(document)}
    end)
  end

  defp envelope_document!(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end

  defp document_digest!(document) do
    {:ok, digest} = Crypto.jcs_sha256_hex(document)
    digest
  end

  defp decoded_keys(%{"keys" => keys}) do
    Map.new(keys, fn {keyid, %{"public_key" => encoded}} ->
      {:ok, public_key} = Base.url_decode64(encoded, padding: false)
      {keyid, public_key}
    end)
  end
end

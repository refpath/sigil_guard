defmodule SigilGuard.TrustBundle.Issuers do
  @moduledoc false

  # Resolves the keys a trust bundle authorizes for one delegate role and
  # verifies a DSSE envelope against them. Agent cards use the `"agent_card"`
  # role and attestations the `"attestation"` role: a key signs only what its
  # role covers, so the root and bundle-signing keys authorize neither.

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache

  @default_max_skew_ms 60_000

  @type resolver ::
          :map | {:bundle, %{String.t() => term()}, term(), MapSet.t(String.t())}

  @doc false
  @spec resolve(term(), String.t(), keyword()) ::
          {:ok, %{String.t() => term()}, resolver()}
          | {:error, :untrusted_issuer | :missing_trust_bundle}
  def resolve(%TrustBundle{bundle_id: id, document: document} = bundle, role_name, opts)
      when is_map(document) do
    document = current_document(bundle)
    keys = bundle_keys(document)
    revoked = revoked_keyids(document, id)
    role = delegate_role(document, role_name)

    authorized =
      keys
      |> Map.take(role_keyids(role))
      |> Map.drop(MapSet.to_list(revoked))

    with :ok <- check_fresh(role, opts),
         :ok <- check_fresh(document, opts),
         :ok <- check_fresh(get_in(document, ["roles", "root"]) || %{}, opts) do
      {:ok, authorized, {:bundle, keys, Map.get(role, "threshold", 1), revoked}}
    end
  end

  def resolve(trust_material, _, _) when is_map(trust_material) and map_size(trust_material) > 0,
    do: {:ok, trust_material, :map}

  def resolve(_, _, _), do: {:error, :missing_trust_bundle}

  # Verifies `envelope` against the authorized keys. For a bundle it also
  # refuses a revoked signing key, a key the bundle holds for another role,
  # and fewer authorized signatures than the role threshold.
  @doc false
  @spec verify_envelope(term(), %{String.t() => term()}, resolver()) ::
          {:ok, binary()} | {:error, atom()}
  def verify_envelope(envelope, authorized, resolver) do
    with :ok <- reject_revoked(envelope, resolver),
         {:ok, payload} <- verify_signatures(envelope, authorized, resolver),
         :ok <- threshold(envelope, authorized, resolver) do
      {:ok, payload}
    end
  end

  defp current_document(%TrustBundle{bundle_id: id, sequence: sequence, document: document})
       when is_binary(id) do
    case Cache.fetch(id) do
      {:ok, cached} when cached.sequence >= sequence -> cached.document
      _ -> document
    end
  end

  defp current_document(bundle), do: bundle.document

  defp revoked_keyids(document, id) do
    listed = Cache.document_revoked_keyids(document)

    if is_binary(id), do: MapSet.union(listed, Cache.revoked_keyids(id)), else: listed
  end

  defp delegate_role(%{"roles" => %{"delegates" => delegates}}, name) when is_list(delegates),
    do: Enum.find(delegates, %{}, &(is_map(&1) and Map.get(&1, "name") == name))

  defp delegate_role(_, _), do: %{}

  defp role_keyids(%{"keyids" => keyids}) when is_list(keyids),
    do: Enum.filter(keyids, &is_binary/1)

  defp role_keyids(_), do: []

  defp bundle_keys(%{"keys" => keys}) when is_map(keys) do
    Map.new(keys, fn
      {keyid, %{"public_key" => public_key}} when is_binary(public_key) -> {keyid, public_key}
      {keyid, _} -> {keyid, nil}
    end)
  end

  defp bundle_keys(_), do: %{}

  defp check_fresh(%{"expires_at" => expiry}, opts) when is_binary(expiry) do
    skew = Keyword.get(opts, :max_skew_ms, @default_max_skew_ms)

    with {:ok, now} <- SigilGuard.Clock.now(opts, :untrusted_issuer),
         true <- is_integer(skew) and skew >= 0,
         {:ok, expiry, _} <- DateTime.from_iso8601(expiry),
         false <- DateTime.after?(now, DateTime.add(expiry, skew, :millisecond)) do
      :ok
    else
      _ -> {:error, :untrusted_issuer}
    end
  end

  defp check_fresh(%{"expires_at" => _}, _), do: {:error, :untrusted_issuer}
  defp check_fresh(_, _), do: :ok

  defp reject_revoked(envelope, {:bundle, _, _, revoked}) do
    if Enum.any?(signature_keyids(envelope), &MapSet.member?(revoked, &1)),
      do: {:error, :untrusted_issuer},
      else: :ok
  end

  defp reject_revoked(_, _), do: :ok

  defp verify_signatures(envelope, authorized, resolver) do
    usable = Map.reject(authorized, fn {_, value} -> is_nil(value) end)

    with {:error, :unknown_key_id} <- Envelope.verify(envelope, usable),
         do: unresolved(envelope, resolver)
  end

  defp unresolved(_, :map), do: {:error, :unknown_key_id}

  defp unresolved(envelope, {:bundle, bundle_keys, _, _}) do
    if Enum.any?(signature_keyids(envelope), &Map.has_key?(bundle_keys, &1)),
      do: {:error, :untrusted_issuer},
      else: {:error, :unknown_key_id}
  end

  defp threshold(envelope, authorized, {:bundle, _, threshold, _})
       when is_integer(threshold) and threshold > 0 do
    count =
      envelope
      |> signature_keyids()
      |> Enum.uniq()
      |> Enum.count(&Map.has_key?(authorized, &1))

    if count >= threshold, do: :ok, else: {:error, :untrusted_issuer}
  end

  defp threshold(_, _, :map), do: :ok
  defp threshold(_, _, _), do: {:error, :untrusted_issuer}

  defp signature_keyids(%{} = envelope) do
    case Map.get(envelope, "signatures") || Map.get(envelope, :signatures) do
      signatures when is_list(signatures) -> Enum.flat_map(signatures, &signature_keyid/1)
      _ -> []
    end
  end

  defp signature_keyids(_), do: []

  defp signature_keyid(%{} = signature),
    do: List.wrap(Map.get(signature, "keyid") || Map.get(signature, :keyid))

  defp signature_keyid(_), do: []
end

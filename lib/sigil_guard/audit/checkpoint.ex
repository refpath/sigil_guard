defmodule SigilGuard.Audit.Checkpoint do
  @moduledoc """
  Portable checkpoints for signed audit chains.

  `SigilGuard.Audit` protects each local event chain with an HMAC link, but
  events alone cannot prove that the tail has not been truncated. Checkpoints
  summarize a chain or chain segment into a deterministic record that can be
  signed, exported, and stored in an external append-only or WORM system.

  A checkpoint contains:

    * event count and first/last event identifiers
    * first/last HMACs and the segment's previous HMAC anchor
    * an ordered SHA-256 Merkle root over event HMACs
    * optional deployment metadata and external anchor details
    * optional Ed25519 signature over canonical checkpoint bytes

  The signature and digest cover the checkpoint fields, not the raw event
  bodies. This makes checkpoints safe to anchor in external systems without
  leaking audit metadata.
  """

  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Audit
  alias SigilGuard.Audit.SignatureMetadata
  alias SigilGuard.Canonical.LegacyJSON
  alias SigilGuard.Crypto

  @kind "sigil_guard.audit.checkpoint"
  @version 1
  @algorithm "sha256-merkle-v1"
  @checkpoint_state_predicate_type "https://sigilguard.dev/audit-checkpoint-state/v1"
  @checkpoint_profile "sigil_guard_agent_trust/v1"
  @empty_root_input "sigil-audit-empty-v1"
  @leaf_prefix "sigil-audit-leaf-v1:"
  @node_prefix "sigil-audit-node-v1:"
  @metadata_keys ~w(signature)
  @metadata_atom_keys [:signature]
  @atom_fields %{
    "algorithm" => :algorithm,
    "chain_id" => :chain_id,
    "digest" => :digest,
    "event_count" => :event_count,
    "first_event_id" => :first_event_id,
    "first_hmac" => :first_hmac,
    "generated_at" => :generated_at,
    "issuer" => :issuer,
    "kind" => :kind,
    "last_event_id" => :last_event_id,
    "last_hmac" => :last_hmac,
    "merkle_root" => :merkle_root,
    "prev_hmac" => :prev_hmac,
    "signature" => :signature,
    "version" => :version
  }

  @typedoc "`:verified` for a checkpoint with a valid signature, `:unsigned` for one without."
  @type status :: :verified | :unsigned
  @typedoc "An audit checkpoint."
  @type t :: map()

  @typedoc "A checkpoint that verified: its digest, signature status and issuer."
  @type verified :: %{
          checkpoint: t(),
          status: status(),
          digest: String.t(),
          issuer: String.t() | nil
        }

  @doc """
  Create an unsigned checkpoint for a signed audit chain or continuation segment.

  Options:

    * `:prev_hmac` - expected previous HMAC for a continuation segment.
    * `:chain_id` - optional stable identifier for the logical audit chain.
    * `:metadata` - optional JSON-compatible metadata for operators.
    * `:anchor` - optional external anchor/WORM location metadata.
    * `:generated_at` - optional ISO 8601 timestamp, defaults to current UTC.

  ## Examples

      iex> key = :binary.copy(<<1>>, 32)
      ...>
      ...> chain =
      ...>   SigilGuard.Audit.build_chain(
      ...>     [SigilGuard.Audit.new_event("tool_call", "agent-1", "read_file", "allowed")],
      ...>     key
      ...>   )
      ...>
      ...> {:ok, checkpoint} = SigilGuard.Audit.Checkpoint.create(chain, [])
      ...> {:ok, verified} = SigilGuard.Audit.Checkpoint.verify(checkpoint, chain, [])
      ...> verified.status
      :unsigned

  """
  @spec create([Audit.t()], keyword()) :: {:ok, t()} | {:error, atom()}
  def create(events, opts \\ [])

  def create(events, opts) when is_list(events) and is_list(opts) do
    prev_hmac = Keyword.get(opts, :prev_hmac)

    with {:ok, generated_at} <- generated_at(opts),
         {:ok, metadata} <- metadata(opts),
         {:ok, anchor} <- anchor(opts),
         :ok <- valid_chain_id(Keyword.get(opts, :chain_id)),
         :ok <- validate_links(events, prev_hmac),
         {:ok, root} <- merkle_root(events) do
      checkpoint =
        base_checkpoint(events, root, %{
          prev_hmac: prev_hmac,
          chain_id: Keyword.get(opts, :chain_id),
          metadata: metadata,
          anchor: anchor,
          generated_at: generated_at
        })

      if LegacyJSON.valid?(checkpoint),
        do: {:ok, checkpoint},
        else: {:error, :invalid_checkpoint}
    end
  end

  def create(_, _), do: {:error, :invalid_events}

  @doc """
  Return the ordered Merkle root for a list of signed audit events.

  The root is calculated over event HMACs only, with domain-separated SHA-256
  leaf and node hashes. Odd nodes are promoted to the next level, avoiding the
  duplicate-last-leaf ambiguity common in simpler Merkle tree implementations.
  """
  @spec merkle_root([Audit.t()]) :: {:ok, String.t()} | {:error, atom()}
  def merkle_root(events) when is_list(events) do
    with {:ok, leaves} <- leaf_hashes(events) do
      root =
        leaves
        |> root_hash()
        |> Base.encode16(case: :lower)

      {:ok, root}
    end
  end

  def merkle_root(_), do: {:error, :invalid_events}

  @doc """
  Return the domain-separated leaf hash `LEAF(h) = SHA-256("sigil-audit-leaf-v1:" || h)`.

  `h` is the event `hmac` exactly as stored (64 lowercase-hex ASCII bytes,
  never the decoded 32 bytes). The result is the raw 32-byte hash.
  """
  @spec leaf_hash(String.t()) :: binary()
  def leaf_hash(hmac) when is_binary(hmac), do: :crypto.hash(:sha256, [@leaf_prefix, hmac])

  @doc """
  Return the domain-separated node hash `NODE(l, r) = SHA-256("sigil-audit-node-v1:" || l || r)`.

  `l` and `r` are raw 32-byte child hashes; the result is the raw 32-byte
  parent hash.
  """
  @spec node_hash(binary(), binary()) :: binary()
  def node_hash(left, right) when is_binary(left) and is_binary(right),
    do: :crypto.hash(:sha256, [@node_prefix, left, right])

  @doc """
  Return the ordered raw leaf hashes for a signed event list.

  Each leaf is `leaf_hash/1` over the event `hmac`; any unsigned event fails
  `{:error, :unsigned_event}`.
  """
  @spec leaf_hashes([Audit.t()]) :: {:ok, [binary()]} | {:error, :unsigned_event}
  def leaf_hashes(events) when is_list(events) do
    SigilGuard.Result.map_ok(events, fn
      %Audit{hmac: hmac} when is_binary(hmac) and byte_size(hmac) > 0 -> {:ok, leaf_hash(hmac)}
      _ -> {:error, :unsigned_event}
    end)
  end

  @doc """
  Return the Merkle tree levels bottom-up for a non-empty list of raw hashes.

  Level 0 is `leaves`; each subsequent level pairs the previous left-to-right
  via `node_hash/2` with an unpaired last node promoted upward; the final level
  is the single root. `SigilGuard.Audit.Proof` reads sibling hashes from these
  levels. The empty tree has no levels (proofs over it fail `:out_of_range`).
  """
  @spec levels([binary()]) :: [[binary()]]
  def levels([]), do: []
  def levels([root]), do: [[root]]

  def levels([_ | _] = leaves), do: [leaves | levels(pair_level(leaves, []))]

  @doc """
  Return canonical checkpoint bytes used for digesting and signatures.

  Top-level signature metadata is excluded so a signed checkpoint verifies
  against the same canonical bytes as the unsigned checkpoint.
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(checkpoint) when is_map(checkpoint) do
    checkpoint
    |> unsigned_checkpoint()
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical checkpoint bytes.
  """
  @spec digest(t()) :: String.t()
  def digest(checkpoint) when is_map(checkpoint) do
    checkpoint
    |> canonical_bytes()
    |> Crypto.sha256_hex()
  end

  @doc """
  Return `{:ok, digest}` as `digest/1` computes it, or `:error` for a value
  that is not a checkpoint map with a canonical form.
  """
  @doc since: "1.1.0"
  @spec fetch_digest(term()) :: {:ok, String.t()} | :error
  def fetch_digest(checkpoint) do
    case checkpoint_canonical_bytes(checkpoint) do
      {:ok, canonical} -> {:ok, Crypto.sha256_hex(canonical)}
      {:error, _} -> :error
    end
  end

  @doc """
  Build the DSSE checkpoint-state statement for `checkpoint`.

  Returns the in-toto Statement whose registered predicate type is
  `https://sigilguard.dev/audit-checkpoint-state/v1` and whose predicate binds
  the audit state `(merkle_root, tree_size, generated_at)` - `tree_size` is the
  event count as a JSON string to preserve growable-counter compatibility, and
  `chain_id` is included only when present. The single subject `checkpoint` is
  digested with `digest/1` over the unchanged local record, so signed and
  unsigned checkpoints yield the same subject digest. This wraps exports and
  cosigning only.

  A checkpoint missing the required fields fails `{:error, :invalid_checkpoint}`.
  """
  @spec to_statement(t()) :: {:ok, map()} | {:error, :invalid_checkpoint}
  def to_statement(checkpoint) when is_map(checkpoint) do
    with :ok <- verify_static_fields(checkpoint),
         :ok <- valid_chain_id(field(checkpoint, "chain_id")),
         {:ok, canonical} <- checkpoint_canonical_bytes(checkpoint) do
      {:ok, checkpoint_statement(checkpoint, Crypto.sha256_hex(canonical))}
    else
      _ -> {:error, :invalid_checkpoint}
    end
  end

  def to_statement(_), do: {:error, :invalid_checkpoint}

  @doc false
  @spec statement_state(term()) ::
          {:ok, %{root: String.t(), size: non_neg_integer(), chain_id: String.t() | nil}}
          | {:error, :invalid_proof}
  def statement_state(
        %{
          "_type" => "https://in-toto.io/Statement/v1",
          "predicateType" => @checkpoint_state_predicate_type,
          "subject" => [%{"name" => "checkpoint", "digest" => %{"sha256" => digest}}],
          "predicate" =>
            %{
              "profile" => @checkpoint_profile,
              "merkle_root" => root,
              "tree_size" => size,
              "generated_at" => generated_at
            } = predicate
        } = statement
      ) do
    with :ok <- SigilGuard.Limits.check(statement),
         true <- LegacyJSON.valid?(statement),
         true <- hex_digest?(root) and hex_digest?(digest),
         true <- is_binary(generated_at) and generated_at != "",
         true <- is_binary(size),
         {count, ""} when count >= 0 <- Integer.parse(size),
         true <- Integer.to_string(count) === size,
         chain_id = Map.get(predicate, "chain_id"),
         true <- is_nil(chain_id) or is_binary(chain_id) do
      {:ok, %{root: root, size: count, chain_id: chain_id}}
    else
      _ -> {:error, :invalid_proof}
    end
  end

  def statement_state(_), do: {:error, :invalid_proof}

  defp hex_digest?(value) when is_binary(value), do: Crypto.sha256_hex?(value)
  defp hex_digest?(_), do: false

  @doc """
  Sign a checkpoint with an Ed25519 `SigilGuard.Signer` module.

  Options:

    * `:issuer` - required issuer identifier, usually a DID.
    * `:issued_at` - optional ISO 8601 timestamp, defaults to current UTC.
  """
  @spec sign(t(), module(), keyword()) :: t()
  def sign(checkpoint, signer, opts) when is_map(checkpoint) and is_atom(signer) do
    issuer = Keyword.fetch!(opts, :issuer)
    issued_at = Keyword.get_lazy(opts, :issued_at, &SigilGuard.Clock.timestamp/0)
    unsigned = unsigned_checkpoint(checkpoint)
    fields = %{"issuer" => issuer, "issued_at" => issued_at}

    Map.put(
      unsigned,
      "signature",
      SignatureMetadata.sign(canonical_bytes(unsigned), signer, fields)
    )
  end

  @doc """
  Verify that a checkpoint matches the supplied events and optional signature.

  Options:

    * `:public_keys` - map of issuer to base64/base64url Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any issuer.
    * `:require_signature` - reject unsigned checkpoints when true.
  """
  @spec verify(t(), [Audit.t()], keyword()) :: {:ok, verified()} | {:error, atom()}
  def verify(checkpoint, events, opts \\ [])

  def verify(checkpoint, events, opts)
      when is_map(checkpoint) and is_list(events) and is_list(opts) do
    with :ok <- verify_static_fields(checkpoint),
         {:ok, prev_hmac} <- checkpoint_prev_hmac(checkpoint),
         :ok <- validate_links(events, prev_hmac),
         :ok <- verify_event_summary(checkpoint, events),
         {:ok, canonical} <- checkpoint_canonical_bytes(checkpoint),
         digest = Crypto.sha256_hex(canonical),
         {:ok, signature_status} <- verify_signature_status(checkpoint, opts, canonical) do
      {:ok,
       %{
         checkpoint: unsigned_checkpoint(checkpoint),
         status: signature_status.status,
         digest: digest,
         issuer: signature_status.issuer
       }}
    end
  end

  def verify(_, _, _), do: {:error, :invalid_checkpoint}

  defp base_checkpoint(events, root, attrs) do
    {first_event, last_event} = endpoints(events)

    %{
      "kind" => @kind,
      "version" => @version,
      "algorithm" => @algorithm,
      "generated_at" => attrs.generated_at,
      "chain_id" => attrs.chain_id,
      "event_count" => length(events),
      "prev_hmac" => attrs.prev_hmac,
      "first_event_id" => event_field(first_event, :id),
      "last_event_id" => event_field(last_event, :id),
      "first_hmac" => event_field(first_event, :hmac),
      "last_hmac" => event_field(last_event, :hmac),
      "merkle_root" => root,
      "metadata" => attrs.metadata,
      "anchor" => attrs.anchor
    }
  end

  defp endpoints([]), do: {nil, nil}
  defp endpoints(events), do: {List.first(events), List.last(events)}

  defp event_field(nil, _), do: nil
  defp event_field(%Audit{} = event, key), do: Map.fetch!(event, key)

  defp verify_static_fields(checkpoint) do
    with :ok <- require_field(checkpoint, "kind", @kind, :invalid_kind),
         :ok <- require_field(checkpoint, "version", @version, :invalid_version),
         :ok <- require_field(checkpoint, "algorithm", @algorithm, :invalid_algorithm),
         :ok <- require_binary(field(checkpoint, "generated_at"), :missing_generated_at),
         :ok <- require_integer(field(checkpoint, "event_count"), :missing_event_count) do
      require_binary(field(checkpoint, "merkle_root"), :missing_merkle_root)
    end
  end

  defp require_field(checkpoint, key, value, reason) do
    if field(checkpoint, key) === value, do: :ok, else: {:error, reason}
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_integer(value, _) when is_integer(value) and value >= 0, do: :ok
  defp require_integer(_, reason), do: {:error, reason}

  defp checkpoint_statement(checkpoint, digest) do
    %{
      "_type" => Statement.statement_type(),
      "predicateType" => @checkpoint_state_predicate_type,
      "predicate" => checkpoint_predicate(checkpoint),
      "subject" => [
        %{"name" => "checkpoint", "digest" => %{"sha256" => digest}}
      ]
    }
  end

  defp checkpoint_predicate(checkpoint) do
    base = %{
      "generated_at" => field(checkpoint, "generated_at"),
      "merkle_root" => field(checkpoint, "merkle_root"),
      "profile" => @checkpoint_profile,
      "tree_size" => Integer.to_string(field(checkpoint, "event_count"))
    }

    put_chain_id(base, field(checkpoint, "chain_id"))
  end

  defp put_chain_id(predicate, chain_id) when is_binary(chain_id),
    do: Map.put(predicate, "chain_id", chain_id)

  defp put_chain_id(predicate, _), do: predicate

  defp valid_chain_id(nil), do: :ok
  defp valid_chain_id(value) when is_binary(value), do: :ok
  defp valid_chain_id(_), do: {:error, :invalid_checkpoint}

  defp generated_at(opts) do
    case Keyword.get_lazy(opts, :generated_at, &SigilGuard.Clock.timestamp/0) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_generated_at}
    end
  end

  defp metadata(opts) do
    case Keyword.get(opts, :metadata, %{}) do
      metadata when is_map(metadata) -> json_metadata(metadata, :invalid_metadata)
      _ -> {:error, :invalid_metadata}
    end
  end

  defp anchor(opts) do
    case Keyword.get(opts, :anchor, %{}) do
      anchor when is_map(anchor) -> json_metadata(anchor, :invalid_anchor_metadata)
      _ -> {:error, :invalid_anchor_metadata}
    end
  end

  defp json_metadata(value, reason) do
    if LegacyJSON.valid?(value), do: {:ok, value}, else: {:error, reason}
  end

  defp checkpoint_prev_hmac(checkpoint) do
    case field(checkpoint, "prev_hmac") do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_prev_hmac}
    end
  end

  defp verify_event_summary(checkpoint, events) do
    with {:ok, root} <- merkle_root(events),
         true <- field(checkpoint, "event_count") === length(events),
         true <- field(checkpoint, "merkle_root") === root,
         true <- endpoints_match?(checkpoint, events) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      false -> {:error, :checkpoint_mismatch}
    end
  end

  defp endpoints_match?(checkpoint, events) do
    {first_event, last_event} = endpoints(events)

    field(checkpoint, "first_event_id") === event_field(first_event, :id) and
      field(checkpoint, "last_event_id") === event_field(last_event, :id) and
      field(checkpoint, "first_hmac") === event_field(first_event, :hmac) and
      field(checkpoint, "last_hmac") === event_field(last_event, :hmac)
  end

  defp checkpoint_canonical_bytes(checkpoint) do
    with true <- is_map(checkpoint) and SigilGuard.Canonical.JSON.unique_keys?(checkpoint),
         {:ok, iodata} <- LegacyJSON.encode(unsigned_checkpoint(checkpoint)) do
      {:ok, IO.iodata_to_binary(iodata)}
    else
      _ -> {:error, :invalid_checkpoint}
    end
  end

  defp verify_signature_status(checkpoint, opts, canonical) do
    case field(checkpoint, "signature") do
      nil -> verify_unsigned(opts)
      signature when is_map(signature) -> verify_signed(signature, opts, canonical)
      _ -> {:error, :invalid_signature_metadata}
    end
  end

  defp verify_unsigned(opts) do
    if SigilGuard.Options.flag(opts, :require_signature, false, true) do
      {:error, :unsigned_checkpoint}
    else
      {:ok, %{status: :unsigned, issuer: nil}}
    end
  end

  defp verify_signed(signature, opts, canonical) do
    with {:ok, issuer} <- SignatureMetadata.verify(signature, canonical, opts),
         do: {:ok, %{status: :verified, issuer: issuer}}
  end

  defp validate_links([], nil), do: :ok
  defp validate_links([], prev_hmac) when is_binary(prev_hmac) and prev_hmac != "", do: :ok
  defp validate_links([], _), do: {:error, :invalid_prev_hmac}

  defp validate_links([%Audit{} = first | rest], prev_hmac)
       when is_nil(prev_hmac) or (is_binary(prev_hmac) and prev_hmac != "") do
    if first.prev_hmac === prev_hmac and signed_event?(first) do
      validate_next_links(rest, first.hmac)
    else
      {:error, :broken_chain}
    end
  end

  defp validate_links([_ | _], prev_hmac)
       when is_nil(prev_hmac) or (is_binary(prev_hmac) and prev_hmac != ""),
       do: {:error, :invalid_events}

  defp validate_links(_, _), do: {:error, :invalid_prev_hmac}

  defp validate_next_links([], _), do: :ok

  defp validate_next_links([%Audit{} = event | rest], prev_hmac) do
    if event.prev_hmac === prev_hmac and signed_event?(event) do
      validate_next_links(rest, event.hmac)
    else
      {:error, :broken_chain}
    end
  end

  defp validate_next_links(_, _), do: {:error, :invalid_events}

  defp signed_event?(%Audit{hmac: hmac}) when is_binary(hmac) and byte_size(hmac) > 0, do: true
  defp signed_event?(_), do: false

  defp root_hash([]), do: :crypto.hash(:sha256, @empty_root_input)
  defp root_hash([root]), do: root

  defp root_hash(nodes) do
    nodes
    |> pair_level([])
    |> root_hash()
  end

  defp pair_level([], acc), do: Enum.reverse(acc)
  defp pair_level([node], acc), do: Enum.reverse([node | acc])

  defp pair_level([left, right | rest], acc) do
    pair_level(rest, [node_hash(left, right) | acc])
  end

  defp unsigned_checkpoint(checkpoint) do
    Map.drop(checkpoint, @metadata_keys ++ @metadata_atom_keys)
  end

  defp canonical_iodata(value), do: LegacyJSON.encode!(value)

  defp field(map, key) when is_map(map), do: SigilGuard.Field.get(map, key, @atom_fields)
end

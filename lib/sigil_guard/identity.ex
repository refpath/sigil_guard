defmodule SigilGuard.Identity do
  @moduledoc """
  Identity provider behaviour and trust levels for SigilGuard runtime policy.

  Trust levels are ordered; a higher level meets every threshold a lower one
  meets.

  ## Trust Level Hierarchy

      :low < :medium < :high

  - low: anonymous or unverified user. Meets only a `:low` trust threshold.
  - medium: verified identity (email, OIDC, social login).
  - high: strong verification (eIDAS, government ID, hardware key).

  ## Implementing an Identity Provider

      defmodule MyApp.SessionIdentity do
        @behaviour SigilGuard.Identity

        @impl true
        def identity(context) do
          "did:web:" <> context.user_id
        end

        @impl true
        def trust_level(context) do
          if context.verified?, do: :high, else: :medium
        end

        @impl true
        def bindings(context) do
          ["session:" <> context.session_id]
        end
      end

  """

  @typedoc "How far an actor is trusted."
  @type trust_level :: :low | :medium | :high

  @doc "Return the identity string (e.g., DID, principal ID) for the given context."
  @callback identity(context :: term()) :: String.t()

  @doc "Return the trust level for the given context."
  @callback trust_level(context :: term()) :: trust_level()

  @doc "Return a list of binding identifiers (session, device, etc.) for the given context."
  @callback bindings(context :: term()) :: [String.t()]

  @trust_order %{
    low: 0,
    medium: 1,
    high: 2
  }

  @doc """
  Compare two trust levels.

  Returns `:lt`, `:eq`, or `:gt` following the trust hierarchy.

  ## Examples

      iex> SigilGuard.Identity.compare_trust(:low, :high)
      :lt

      iex> SigilGuard.Identity.compare_trust(:high, :medium)
      :gt

      iex> SigilGuard.Identity.compare_trust(:medium, :medium)
      :eq

  """
  @spec compare_trust(trust_level(), trust_level()) :: :lt | :eq | :gt
  def compare_trust(a, b) do
    ord_a = Map.fetch!(@trust_order, a)
    ord_b = Map.fetch!(@trust_order, b)

    cond do
      ord_a < ord_b -> :lt
      ord_a > ord_b -> :gt
      true -> :eq
    end
  end

  @doc """
  Check if `actual` trust level meets or exceeds the `required` trust level.

  ## Examples

      iex> SigilGuard.Identity.sufficient_trust?(:high, :medium)
      true

      iex> SigilGuard.Identity.sufficient_trust?(:low, :high)
      false

  """
  @spec sufficient_trust?(trust_level(), trust_level()) :: boolean()
  def sufficient_trust?(actual, required) do
    compare_trust(actual, required) in [:eq, :gt]
  end

  @doc """
  Return all trust levels in ascending order.

  ## Examples

      iex> SigilGuard.Identity.trust_levels()
      [:low, :medium, :high]

  """
  @spec trust_levels() :: [trust_level(), ...]
  def trust_levels do
    [:low, :medium, :high]
  end

  @spiffe_max_bytes 2048
  @spiffe_trust_domain_max_bytes 255
  @spiffe_trust_domain ~r/\A[a-z0-9._-]+\z/
  @spiffe_segment ~r/\A[a-zA-Z0-9._-]+\z/

  @doc """
  Returns whether `value` is a SPIFFE ID as the SPIFFE-ID standard defines it.

  The check is pure string work. The scheme is `spiffe`. The trust domain is
  1 to 255 bytes of lowercase letters, digits, dots, dashes and underscores,
  with no user information or port. A path is optional; each segment holds
  letters, digits, dots, dashes and underscores, is not empty, and is neither
  `.` nor `..`. A trailing slash, a query, a fragment, a percent-encoded
  character, or a total length above 2048 bytes makes the value invalid.

  SigilGuard never requires this shape: an actor or issuer is an opaque
  string. A host that wants SPIFFE-shaped identifiers checks them here.

  ## Examples

      iex> SigilGuard.Identity.spiffe_id?("spiffe://example.org/agent/planner")
      true

      iex> SigilGuard.Identity.spiffe_id?("spiffe://Example.org/agent")
      false

      iex> SigilGuard.Identity.spiffe_id?("spiffe://example.org/agent/")
      false

  """
  @doc since: "1.1.0"
  @spec spiffe_id?(term()) :: boolean()
  def spiffe_id?("spiffe://" <> rest = value) when byte_size(value) <= @spiffe_max_bytes do
    case String.split(rest, "/") do
      [trust_domain] -> spiffe_trust_domain?(trust_domain)
      [trust_domain | segments] -> spiffe_trust_domain?(trust_domain) and spiffe_path?(segments)
    end
  end

  def spiffe_id?(_), do: false

  defp spiffe_trust_domain?(trust_domain) do
    byte_size(trust_domain) <= @spiffe_trust_domain_max_bytes and
      Regex.match?(@spiffe_trust_domain, trust_domain)
  end

  defp spiffe_path?(segments) do
    Enum.all?(segments, &(&1 not in [".", ".."] and Regex.match?(@spiffe_segment, &1)))
  end

  @base58 ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @base58_index Map.new(Enum.with_index(@base58))
  # 0xed 0x01 is the varint multicodec code of an Ed25519 public key.
  @ed25519_multicodec <<0xED, 0x01>>
  @ed25519_did_key_chars 48

  @doc """
  Returns the Ed25519 public key that a `did:key` identifier embeds.

  The identifier is `did:key:z` followed by the base58btc encoding of the two
  multicodec bytes `0xed 0x01` and the 32-byte key, 48 characters in all. Any
  other method, multibase prefix, key type, length or character returns
  `{:error, :invalid_did_key}`. A DID URL with a fragment or path is not an
  identifier and is refused.

  Decoding proves nothing about who holds the key. A host that designates a
  `did:key` issuer adds the returned key to its attestation trust material
  under the key id it expects.

  ## Examples

      iex> did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      ...> {:ok, key} = SigilGuard.Identity.did_key_public_key(did)
      ...> Base.encode16(key, case: :lower)
      "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6"

      iex> SigilGuard.Identity.did_key_public_key("did:web:example.org")
      {:error, :invalid_did_key}

  """
  @doc since: "1.1.0"
  @spec did_key_public_key(term()) :: {:ok, <<_::256>>} | {:error, :invalid_did_key}
  def did_key_public_key("did:key:z" <> encoded)
      when byte_size(encoded) == @ed25519_did_key_chars - 1 do
    case base58_integer(String.to_charlist(encoded), 0) do
      {:ok, integer} -> ed25519_key(:binary.encode_unsigned(integer))
      :error -> {:error, :invalid_did_key}
    end
  end

  def did_key_public_key(_), do: {:error, :invalid_did_key}

  defp ed25519_key(<<@ed25519_multicodec, key::binary-size(32)>>), do: {:ok, key}
  defp ed25519_key(_), do: {:error, :invalid_did_key}

  defp base58_integer([], acc), do: {:ok, acc}

  defp base58_integer([char | rest], acc) do
    case Map.fetch(@base58_index, char) do
      {:ok, digit} -> base58_integer(rest, acc * 58 + digit)
      :error -> :error
    end
  end
end

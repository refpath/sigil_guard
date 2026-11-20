defmodule SigilGuard.AgentCardFixtureGenerator do
  @moduledoc false

  import SigilGuard.CaseFixtures, only: [sha256_hex: 1]

  alias SigilGuard.AgentCard
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle

  @issuer_seed for b <- 0x21..0x40, into: <<>>, do: <<b>>
  @agent_seed for b <- 0x41..0x60, into: <<>>, do: <<b>>
  @issued_at "2026-07-02T12:00:00.000Z"
  @expires_at "2026-08-01T12:00:00.000Z"

  @doc false
  @spec fixtures() :: [String.t()]
  def fixtures, do: Map.keys(generate()) |> Enum.sort()

  @doc false
  @spec write!(Path.t()) :: :ok
  def write!(root) do
    root = Path.expand(root)
    File.rm_rf!(root)

    File.mkdir_p!(root)

    for {name, bytes} <- generate() do
      File.write!(Path.join(root, name), bytes)
    end

    :ok
  end

  @doc false
  @spec generate() :: %{required(String.t()) => binary()}
  def generate do
    research_peer_files()
  end

  defp research_peer_files do
    Code.ensure_loaded!(__MODULE__.IssuerSigner)
    {:ok, card} = AgentCard.new(card())
    {:ok, card_json} = JCS.encode(card)
    {:ok, envelope} = Envelope.sign(card_json, __MODULE__.IssuerSigner)
    {:ok, envelope_json} = JCS.encode(envelope)
    {:ok, expected_json} = JCS.encode(expected(card_json, envelope))

    %{
      "research_peer.card.json" => card_json,
      "research_peer.envelope.json" => envelope_json,
      "research_peer.expected.json" => expected_json
    }
  end

  @doc "The research-peer card the committed fixtures sign."
  @spec card() :: map()
  def card do
    %{
      "agent_id" => "spiffe://prod.example.org/agents/research-peer",
      "capabilities" => [
        %{"description" => "Summarize a document set", "name" => "summarize"},
        %{"description" => "Web research with citations", "name" => "web_research"}
      ],
      "endpoints" => ["https://agents.example.org/research-peer/a2a"],
      "expires_at" => @expires_at,
      "issued_at" => @issued_at,
      "kind" => "sigil_guard_agent_card",
      "name" => "research-peer",
      "protocols" => ["a2a/1.0"],
      "provider" => "spiffe://prod.example.org/operators/platform-team",
      "public_keys" => [
        %{
          "algorithm" => "ed25519",
          "keyid" => Envelope.keyid(agent_public_key()),
          "public_key" => Base.url_encode64(agent_public_key(), padding: false)
        }
      ],
      "schema_version" => "1",
      "scopes" => ["research:read"],
      "trust_zone" => "semi_trusted",
      "version" => "2.1.0"
    }
  end

  defp expected(card_json, envelope) do
    [signature] = envelope["signatures"]

    %{
      "agent_keyid" => Envelope.keyid(agent_public_key()),
      "agent_public_key_hex" => Base.encode16(agent_public_key(), case: :lower),
      "agent_seed_hex" => Base.encode16(@agent_seed, case: :lower),
      "card_digest" => sha256_hex(card_json),
      "expires_at" => @expires_at,
      "issued_at" => @issued_at,
      "issuer_keyid" => Envelope.keyid(issuer_public_key()),
      "issuer_public_key_hex" => Base.encode16(issuer_public_key(), case: :lower),
      "issuer_seed_hex" => Base.encode16(@issuer_seed, case: :lower),
      "pae_sha256" => sha256_hex(Envelope.pae(Envelope.payload_type(), card_json)),
      "signature" => signature["sig"]
    }
  end

  @doc false
  @spec issuer_public_key() :: binary()
  def issuer_public_key, do: public_key(@issuer_seed)

  @doc false
  @spec agent_public_key() :: binary()
  def agent_public_key, do: public_key(@agent_seed)

  @doc false
  @spec issuer_keyid() :: String.t()
  def issuer_keyid, do: Envelope.keyid(issuer_public_key())

  @doc false
  @spec issuer_material() :: %{String.t() => binary()}
  def issuer_material, do: %{issuer_keyid() => issuer_public_key()}

  @doc "A trust bundle whose agent_card role lists `role_keyids` over `keys`."
  @spec bundle_with_role([String.t()], keys: %{String.t() => binary()}) :: TrustBundle.t()
  def bundle_with_role(role_keyids, keys: keys) do
    document = %{
      "keys" =>
        Map.new(keys, fn {keyid, public_key} ->
          {keyid,
           %{"alg" => "ed25519", "public_key" => Base.url_encode64(public_key, padding: false)}}
        end),
      "roles" => %{"delegates" => [%{"name" => "agent_card", "keyids" => role_keyids}]}
    }

    %TrustBundle{document: document}
  end

  defp public_key(seed) do
    case :crypto.generate_key(:eddsa, :ed25519, seed) do
      {public_key, _} when is_binary(public_key) -> public_key
    end
  end

  defmodule IssuerSigner do
    @moduledoc false
    use SigilGuard.TestSigner, seed: for(b <- 0x21..0x40, into: <<>>, do: <<b>>)
  end
end

defmodule SigilGuard.BenchCorpus do
  @moduledoc false

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS

  @seed {1763, 8785, 9162}
  @dir Path.expand("corpus", __DIR__)
  @secret "AKIAIOSFODNN7EXAMPLE"
  @marker " #{@secret} "
  @block_bytes 4096
  @chunk_bytes 512
  @sizes [{"1k", 1024}, {"64k", 65_536}, {"1m", 1_048_576}]

  # The marker starts 11 bytes before the fourth chunk boundary, which puts
  # ten bytes of the secret on each side of it.
  @split_offset 3 * @chunk_bytes - 11

  @bundle_file "trust_bundle_delegations.json"
  @bundle_pattern_count 10

  @doc false
  def generate!(dir \\ @dir) do
    :rand.seed(:exsss, @seed)
    File.mkdir_p!(dir)

    for {label, bytes} <- @sizes do
      write!(dir, "clean_#{label}.txt", clean_payload(bytes))
      write!(dir, "hits_#{label}.txt", hits_payload(bytes))
    end

    hits_64k = File.read!(Path.join(dir, "hits_64k.txt"))

    write!(dir, "stream_split_64k.txt", place_marker(hits_64k, @split_offset))
    write!(dir, @bundle_file, bundle_envelope())
    :ok
  end

  @doc false
  def files(dir \\ @dir) do
    texts =
      for {label, _bytes} <- @sizes,
          kind <- ["clean", "hits"] do
        Path.join(dir, "#{kind}_#{label}.txt")
      end

    texts ++ [Path.join(dir, "stream_split_64k.txt"), Path.join(dir, @bundle_file)]
  end

  defp clean_payload(bytes), do: payload(bytes, false)

  # A payload shorter than one block gets its secret written over the first
  # bytes. That draws nothing from the generator, so the files after it keep
  # their bytes.
  defp hits_payload(bytes) when bytes < @block_bytes,
    do: bytes |> payload(true) |> place_marker(0)

  defp hits_payload(bytes), do: payload(bytes, true)

  defp payload(bytes, with_hits?) do
    chunks = div(bytes, @block_bytes)

    base =
      1..max(chunks, 1)
      |> Enum.map(fn index ->
        marker =
          if with_hits? and index <= chunks do
            @marker
          else
            " documented synthetic benchmark text #{index} "
          end

        fill = random_ascii(max(@block_bytes - byte_size(marker), 0))
        marker <> fill
      end)
      |> IO.iodata_to_binary()

    binary_part(base <> random_ascii(bytes), 0, bytes)
  end

  defp place_marker(payload, offset) do
    rest = offset + byte_size(@marker)

    binary_part(payload, 0, offset) <>
      @marker <> binary_part(payload, rest, byte_size(payload) - rest)
  end

  defp random_ascii(0), do: ""

  defp random_ascii(count) do
    for _ <- 1..count, into: <<>> do
      <<Enum.random(?a..?z)>>
    end
  end

  defp write!(dir, name, payload), do: File.write!(Path.join(dir, name), payload)

  # A signed bundle with two delegate roles and ten pattern entries. Keys come
  # from fixed seeds and the timestamps are constants, so the envelope bytes
  # are the same on every run.
  defp bundle_envelope do
    root = key("root")
    bundle = key("bundle")
    attestation = key("attestation")

    document = %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "sigilguard-bench",
      "sequence" => "1",
      "rollback_floor" => "1",
      "issued_at" => "2026-07-02T12:00:00.000Z",
      "expires_at" => "2026-08-01T12:00:00.000Z",
      "roles" => %{
        "root" => %{
          "keyids" => [root.keyid],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-02T12:00:00.000Z"
        },
        "delegates" => [delegate("bundle", bundle), delegate("attestation", attestation)]
      },
      "keys" => Map.new([root, bundle, attestation], &{&1.keyid, key_entry(&1)}),
      "patterns" => patterns()
    }

    {:ok, payload} = JCS.encode(document)
    pae = Envelope.pae(Envelope.payload_type(), payload)
    signature = :crypto.sign(:eddsa, :none, pae, [bundle.private, :ed25519])

    {:ok, envelope} =
      JCS.encode(%{
        "payload" => Base.url_encode64(payload, padding: false),
        "payloadType" => Envelope.payload_type(),
        "signatures" => [
          %{"keyid" => bundle.keyid, "sig" => Base.url_encode64(signature, padding: false)}
        ]
      })

    envelope
  end

  defp key(label) do
    seed = :crypto.hash(:sha256, "sigil_guard_bench_bundle_#{label}")
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)

    %{keyid: Envelope.keyid(public), public: public, private: private}
  end

  defp key_entry(key),
    do: %{"alg" => "ed25519", "public_key" => Base.url_encode64(key.public, padding: false)}

  defp delegate(name, key) do
    %{
      "name" => name,
      "keyids" => [key.keyid],
      "threshold" => 1,
      "expires_at" => "2026-10-01T12:00:00.000Z"
    }
  end

  defp patterns do
    for index <- 1..@bundle_pattern_count do
      id = index |> Integer.to_string() |> String.pad_leading(2, "0")

      %{
        "set" => "secret",
        "name" => "bench_token_#{id}",
        "regex" => "BENCH#{id}_[A-Z0-9]{16}",
        "max_match_bytes" => 24
      }
    end
  end
end

unless function_exported?(Mix, :env, 0) and Mix.env() == :test do
  SigilGuard.BenchCorpus.generate!()
end

defmodule SigilGuard.Audit.Anchor.Store.LocalFile do
  @moduledoc """
  Append-only local JSONL store for audit anchor records.

  This store is useful for development, tests, and deployments that ship the
  JSONL file to append-only or WORM storage using external infrastructure. Each
  line contains a receipt plus the compact anchor record. Fetching validates the
  record digest before returning it, so corrupted or mismatched log entries are
  rejected. Writes enforce the same `:max_line_bytes` limit as reads (default
  1 MiB), including receipt metadata, before touching the file. Hosts serialize
  writers and provide durable storage; this adapter does not supply locking,
  transactions, rollback, crash recovery, or protection against hostile
  concurrent filesystem replacement.
  """

  @behaviour SigilGuard.Audit.Anchor.Store

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Receipt
  alias SigilGuard.Audit.Anchor.Store

  @default_max_line_bytes 1_048_576
  @read_chunk_bytes 65_536
  @atom_fields %{
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "uri" => :uri
  }

  @doc """
  Persist an anchor record to the local append-only file and return its receipt.

  Hosts usually call `SigilGuard.Audit.Anchor.Store.put/3`, which adds
  telemetry. The options are described in the module documentation.
  """
  @impl SigilGuard.Audit.Anchor.Store
  @spec put(term(), keyword()) ::
          {:ok, SigilGuard.Audit.Anchor.Store.receipt()} | {:error, term()}
  def put(record, opts) when is_map(record) and is_list(opts) do
    with :ok <- validate_options(opts),
         :ok <- Store.validate_anchor(record),
         :ok <- allow_local_receipt(opts),
         {:ok, path} <- path_from_opts(opts),
         {:ok, metadata} <- Store.metadata(opts),
         {:ok, max_line_bytes} <- max_line_bytes(opts),
         {:ok, receipt} <- receipt(record, path, metadata),
         {:ok, entry} <- encode_entry(receipt, record, max_line_bytes),
         :ok <- ensure_parent(path),
         :ok <- append_entry(path, entry) do
      {:ok, receipt}
    end
  end

  def put(_, _), do: {:error, :invalid_anchor}

  @doc """
  Fetch the anchor record a receipt or an anchor digest names, and check that
  it digests to the expected value.

  Hosts usually call `SigilGuard.Audit.Anchor.Store.fetch/3`.
  """
  @impl SigilGuard.Audit.Anchor.Store
  @spec fetch(term(), keyword()) :: {:ok, Anchor.t()} | {:error, term()}
  def fetch(receipt_or_digest, opts) when is_list(opts) do
    with :ok <- validate_options(opts),
         {:ok, digest} <-
           Store.digest_from_ref(receipt_or_digest, &digest_from_uri(field(&1, "uri"))),
         {:ok, path} <- path_from_ref(receipt_or_digest, opts),
         {:ok, max_line_bytes} <- max_line_bytes(opts) do
      find_record(path, digest, max_line_bytes)
    end
  end

  def fetch(_, _), do: {:error, :missing_path}

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp allow_local_receipt(opts) do
    if SigilGuard.Options.flag(opts, :require_worm, false, true) do
      {:error, :worm_required}
    else
      :ok
    end
  end

  defp path_from_opts(opts) do
    case Keyword.get(opts, :path) do
      path when is_binary(path) and path != "" -> {:ok, Path.expand(path)}
      _ -> {:error, :missing_path}
    end
  end

  defp path_from_ref(%{} = ref, opts) do
    with :ok <- validate_receipt_uri(ref) do
      path_from_ref_with_opts(ref, opts)
    end
  end

  defp path_from_ref(ref, opts), do: path_from_ref_with_opts(ref, opts)

  defp path_from_ref_with_opts(ref, opts) do
    case path_from_opts(opts) do
      {:ok, path} ->
        {:ok, path}

      {:error, :missing_path} ->
        receipt_path(ref)
    end
  end

  defp receipt_path(%{} = receipt) do
    receipt
    |> field("uri")
    |> path_from_uri()
  end

  defp receipt_path(_), do: {:error, :missing_path}

  defp validate_receipt_uri(%{} = receipt) do
    case fetch_field(receipt, "uri") do
      {:ok, "file://" <> _ = uri} ->
        with {:ok, _} <- path_from_uri(uri), do: :ok

      {:ok, _} ->
        {:error, :missing_path}

      :error ->
        :ok
    end
  end

  defp path_from_uri("file://" <> _ = uri) do
    case URI.parse(uri) do
      %URI{scheme: "file", host: host, path: path}
      when host in [nil, ""] and is_binary(path) and path != "" ->
        {:ok, URI.decode(path)}

      %URI{scheme: "file", host: host} when is_binary(host) and host != "" ->
        {:error, :remote_file_uri}

      _ ->
        {:error, :missing_path}
    end
  end

  defp path_from_uri(_), do: {:error, :missing_path}

  defp receipt(record, path, metadata) do
    digest = Anchor.digest(record)

    {:ok,
     %{
       "kind" => Receipt.kind(),
       "version" => Receipt.version(),
       "storage" => "local_file",
       "uri" => file_uri(path, digest),
       "anchor_digest" => digest,
       "stored_at" => SigilGuard.Clock.timestamp(),
       "worm" => false,
       "metadata" => metadata
     }}
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp ensure_parent(path), do: File.mkdir_p(Path.dirname(path))

  defp encode_entry(receipt, record, max_line_bytes) do
    case Jason.encode_to_iodata(Map.put(receipt, "record", record), maps: :strict) do
      {:ok, entry} ->
        if IO.iodata_length(entry) <= max_line_bytes,
          do: {:ok, entry},
          else: {:error, :log_line_too_large}

      {:error, _} ->
        {:error, :invalid_anchor}
    end
  rescue
    _ in [Protocol.UndefinedError, UnicodeConversionError] -> {:error, :invalid_anchor}
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp append_entry(path, entry), do: File.write(path, [entry, ?\n], [:append, :binary])

  # sobelow_skip ["Traversal.FileModule"]
  defp find_record(path, digest, max_line_bytes) do
    case File.open(path, [:read, :binary]) do
      {:ok, io} ->
        try do
          read_record_chunks(io, digest, max_line_bytes, "")
        after
          File.close(io)
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_record_chunks(io, digest, max_line_bytes, buffer) do
    case IO.binread(io, @read_chunk_bytes) do
      :eof -> consume_final_line(buffer, digest, max_line_bytes)
      {:error, reason} -> {:error, reason}
      chunk -> consume_record_lines(io, digest, max_line_bytes, buffer <> chunk)
    end
  end

  defp consume_record_lines(io, digest, max_line_bytes, data) do
    case :binary.match(data, "\n") do
      {index, 1} when index > max_line_bytes ->
        {:error, :log_line_too_large}

      {index, 1} ->
        <<line::binary-size(^index), ?\n, rest::binary>> = data

        case consume_record_line(line, digest) do
          :not_found -> consume_record_lines(io, digest, max_line_bytes, rest)
          result -> result
        end

      :nomatch when byte_size(data) > max_line_bytes ->
        {:error, :log_line_too_large}

      :nomatch ->
        read_record_chunks(io, digest, max_line_bytes, data)
    end
  end

  defp consume_final_line("", _, _), do: {:error, :not_found}

  defp consume_final_line(line, digest, max_line_bytes) when byte_size(line) <= max_line_bytes,
    do: consume_record_line(line, digest) |> normalize_not_found()

  defp consume_final_line(_, _, _), do: {:error, :log_line_too_large}

  defp consume_record_line("", _), do: :not_found

  defp consume_record_line(line, digest) do
    case find_record_entry(line, :not_found, digest) do
      {:cont, :not_found} -> :not_found
      {:halt, result} -> result
    end
  end

  defp normalize_not_found(:not_found), do: {:error, :not_found}
  defp normalize_not_found(result), do: result

  defp max_line_bytes(opts) do
    case Keyword.get(opts, :max_line_bytes, @default_max_line_bytes) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, :invalid_max_line_bytes}
    end
  end

  defp find_record_entry(line, :not_found, digest) do
    case decode_entry(line) do
      {:ok, %{"anchor_digest" => ^digest, "record" => record}} when is_map(record) ->
        matching_record_result(record, digest)

      {:ok, %{"anchor_digest" => ^digest}} ->
        {:halt, {:error, :invalid_log}}

      {:ok, %{"anchor_digest" => _}} ->
        {:cont, :not_found}

      {:ok, _} ->
        {:halt, {:error, :invalid_log}}

      {:error, reason} ->
        {:halt, {:error, reason}}
    end
  end

  defp matching_record_result(record, digest) do
    with :ok <- Store.validate_anchor(record),
         true <- Anchor.digest(record) == digest do
      {:halt, {:ok, record}}
    else
      {:error, reason} -> {:halt, {:error, reason}}
      false -> {:halt, {:error, :digest_mismatch}}
    end
  end

  defp decode_entry(line) do
    case SigilGuard.Canonical.JSON.decode(line) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _} -> {:error, :invalid_log}
      {:error, _} -> {:error, :invalid_log}
    end
  end

  defp digest_from_uri("file://" <> _ = uri) do
    uri
    |> URI.parse()
    |> Map.get(:fragment)
  end

  defp digest_from_uri(_), do: nil

  defp field(map, key) when is_map(map), do: SigilGuard.Field.get(map, key, @atom_fields)

  defp fetch_field(map, key) when is_map(map),
    do: SigilGuard.Field.fetch(map, key, @atom_fields)

  defp file_uri(path, digest) do
    encoded_path =
      path
      |> String.split("/", trim: false)
      |> Enum.map_join("/", &URI.encode(&1, fn char -> URI.char_unreserved?(char) end))

    "file://#{encoded_path}##{digest}"
  end
end

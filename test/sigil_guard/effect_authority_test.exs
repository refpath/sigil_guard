defmodule SigilGuard.EffectAuthorityTest do
  @moduledoc false

  use ExUnit.Case, async: false

  use ExUnitProperties

  alias SigilGuard.EffectAuthority
  alias SigilGuard.EffectAuthorityFixture, as: Fixture

  doctest EffectAuthority

  @sha String.duplicate("a", 64)

  describe "fetch_binding/1" do
    test "returns the valid record carried by the request" do
      assert EffectAuthority.fetch_binding(Fixture.request()) == {:ok, Fixture.record()}
    end

    test "reads atom-keyed params and metadata" do
      request = %{params: %{_meta: %{"dev.sigilguard/effect" => Fixture.record()}}}

      assert EffectAuthority.fetch_binding(request) == {:ok, Fixture.record()}
    end

    test "reads the params value the gateway binds when both aliases exist" do
      shadow = Map.put(Fixture.record(), "operation_id", "op-shadow")

      request =
        Map.put(Fixture.request(), :params, %{_meta: %{"dev.sigilguard/effect" => shadow}})

      assert EffectAuthority.fetch_binding(request) == {:ok, Fixture.record()}
    end

    test "an absent record is required, not invalid" do
      absent = [
        "plain text",
        nil,
        %{},
        %{"params" => "not a map"},
        %{"params" => %{}},
        %{"params" => %{"_meta" => "not a map"}},
        %{"params" => %{"_meta" => %{"com.example/other" => %{}}}},
        %{"_meta" => %{"dev.sigilguard/effect" => Fixture.record()}}
      ]

      for request <- absent do
        assert EffectAuthority.fetch_binding(request) == {:error, :effect_binding_required}
      end
    end

    test "a params map with both metadata aliases is ambiguous" do
      request =
        put_in(Fixture.request(), ["params", :_meta], %{
          "dev.sigilguard/effect" => Fixture.record()
        })

      assert EffectAuthority.fetch_binding(request) == {:error, :invalid_effect_binding}
    end

    test "a present value that is not a valid record is invalid" do
      for record <- ["text", 1, nil, [], %{}, Map.delete(Fixture.record(), "not_after")] do
        request = Fixture.put_record(Fixture.request(), record)

        assert EffectAuthority.fetch_binding(request) == {:error, :invalid_effect_binding}
      end
    end
  end

  describe "validate_binding/1" do
    test "accepts the full record and the required fields alone" do
      minimal =
        Map.take(Fixture.record(), ~w(binding_format operation_id target policy_epoch not_after))

      assert EffectAuthority.validate_binding(Fixture.record()) == :ok
      assert EffectAuthority.validate_binding(minimal) == :ok
    end

    test "accepts the identifier and artifact bounds" do
      artifacts =
        for index <- 1..16 do
          %{
            "name" => "artifact-" <> String.pad_leading("#{index}", 2, "0"),
            "sha256" => @sha
          }
        end

      record =
        Fixture.record()
        |> Map.put("operation_id", String.duplicate("o", 256))
        |> Map.put("artifacts", artifacts)
        |> Map.put("envelope", %{"id" => "env-1", "sha256" => @sha})

      assert EffectAuthority.validate_binding(record) == :ok
    end

    for key <- ~w(binding_format operation_id target policy_epoch not_after) do
      test "refuses a record without #{key}" do
        record = Map.delete(Fixture.record(), unquote(key))

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
      end
    end

    test "refuses unknown and atom keys" do
      atom_keyed = Map.put(Map.delete(Fixture.record(), "not_after"), :not_after, "x")

      for record <- [
            Map.put(Fixture.record(), "speed_mm_s", "120"),
            Map.put(Fixture.record(), :operation_id, "op-0001"),
            atom_keyed
          ] do
        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
      end
    end

    test "refuses values outside the identifier rule" do
      for value <- [
            "",
            String.duplicate("o", 257),
            "op 1",
            "op\n1",
            "op-é",
            <<255>>,
            1,
            1.5,
            nil,
            :op,
            ["op"]
          ],
          key <- ~w(operation_id policy_epoch frame_revision) do
        record = Map.put(Fixture.record(), key, value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding},
               "#{key} accepted #{inspect(value)}"
      end
    end

    test "refuses a wrong format marker" do
      for value <- ["sigil_guard_effect_binding/v2", "", nil, 1] do
        record = Map.put(Fixture.record(), "binding_format", value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
      end
    end

    test "refuses malformed targets" do
      target = Fixture.record()["target"]

      for value <- [
            Map.put(target, "environment", "real"),
            Map.put(target, "environment", :physical),
            Map.put(target, "zone", "a"),
            Map.delete(target, "id"),
            Map.put(target, "id", ""),
            "urn:example:cell-a:arm-1",
            nil
          ] do
        record = Map.put(Fixture.record(), "target", value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
      end
    end

    test "refuses malformed artifact lists" do
      [first, second] = Fixture.record()["artifacts"]
      seventeen = for index <- 10..26, do: %{"name" => "artifact-#{index}", "sha256" => @sha}

      for value <- [
            [],
            [second, first],
            [first, first],
            [Map.put(first, "size", "1")],
            [Map.put(first, "sha256", String.upcase(@sha))],
            [Map.put(first, "sha256", String.duplicate("a", 63))],
            [Map.put(first, "name", "")],
            [Map.delete(first, "sha256")],
            ["program"],
            seventeen,
            [first | second],
            %{"name" => "program", "sha256" => @sha},
            nil
          ] do
        record = Map.put(Fixture.record(), "artifacts", value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding},
               "accepted #{inspect(value)}"
      end
    end

    test "refuses malformed timestamps and an inverted window" do
      for {key, value} <- [
            {"not_after", "2026-11-19T12:05:00Z"},
            {"not_after", "2026-11-19T12:05:00.000+01:00"},
            {"not_after", "2026-13-40T12:05:00.000Z"},
            {"not_after", "2026-11-19 12:05:00.000Z"},
            {"not_after", 1_795_000_000},
            {"not_after", nil},
            {"not_before", "2026-11-19T12:05:00.000Z"},
            {"not_before", "2026-11-19T12:05:00.001Z"},
            {"not_before", "yesterday"},
            {"not_before", nil}
          ] do
        record = Map.put(Fixture.record(), key, value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding},
               "#{key} accepted #{inspect(value)}"
      end
    end

    test "accepts a window of one millisecond" do
      record = Map.put(Fixture.record(), "not_before", "2026-11-19T12:04:59.999Z")

      assert EffectAuthority.validate_binding(record) == :ok
    end

    test "refuses malformed envelope references" do
      for value <- [
            %{"id" => "env-1"},
            %{"id" => "env-1", "sha256" => "short"},
            %{"id" => "", "sha256" => @sha},
            %{"id" => "env-1", "sha256" => @sha, "version" => "1"},
            "env-1",
            nil
          ] do
        record = Map.put(Fixture.record(), "envelope", value)

        assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
      end
    end

    test "refuses a record beyond the input budget" do
      record = Map.put(Fixture.record(), "operation_id", String.duplicate("o", 1_048_577))

      assert EffectAuthority.validate_binding(record) == {:error, :invalid_effect_binding}
    end
  end

  describe "binding_digest/1 and operation_key/1" do
    @minimal %{
      "binding_format" => "sigil_guard_effect_binding/v1",
      "operation_id" => "op-1",
      "target" => %{"id" => "urn:example:cell-a:arm-1", "environment" => "physical"},
      "policy_epoch" => "epoch-1",
      "not_after" => "2026-11-19T12:05:00.000Z"
    }

    test "the binding digest is the SHA-256 of the record's JCS bytes" do
      jcs =
        ~s({"binding_format":"sigil_guard_effect_binding/v1",) <>
          ~s("not_after":"2026-11-19T12:05:00.000Z","operation_id":"op-1",) <>
          ~s("policy_epoch":"epoch-1",) <>
          ~s("target":{"environment":"physical","id":"urn:example:cell-a:arm-1"}})

      assert EffectAuthority.binding_digest(@minimal) == {:ok, sha256(jcs)}
    end

    test "the operation key is the SHA-256 of the operation and target identifiers" do
      jcs = ~s({"operation_id":"op-1","target_id":"urn:example:cell-a:arm-1"})

      assert EffectAuthority.operation_key(@minimal) == {:ok, sha256(jcs)}
    end

    test "every field changes the binding digest" do
      {:ok, baseline} = EffectAuthority.binding_digest(Fixture.record())

      changes = [
        {"operation_id", "op-0002"},
        {"target", %{"id" => "urn:example:cell-b:arm-1", "environment" => "physical"}},
        {"target", %{"id" => "urn:example:cell-a:arm-1", "environment" => "simulated"}},
        {"artifacts", [%{"name" => "program", "sha256" => @sha}]},
        {"frame_revision", "cal-r4"},
        {"policy_epoch", "example-bundle:43"},
        {"not_before", "2026-11-19T12:00:00.001Z"},
        {"not_after", "2026-11-19T12:05:00.001Z"},
        {"envelope", %{"id" => "env-1", "sha256" => @sha}}
      ]

      for {key, value} <- changes do
        assert {:ok, digest} =
                 EffectAuthority.binding_digest(Map.put(Fixture.record(), key, value))

        refute digest == baseline, "#{key} did not change the digest"
      end
    end

    test "only the operation and target identifiers change the operation key" do
      {:ok, baseline} = EffectAuthority.operation_key(Fixture.record())

      same =
        Fixture.record()
        |> Map.put("frame_revision", "cal-r4")
        |> Map.put("target", %{"id" => "urn:example:cell-a:arm-1", "environment" => "simulated"})

      other_operation = Map.put(Fixture.record(), "operation_id", "op-0002")

      other_target =
        Map.put(Fixture.record(), "target", %{
          "id" => "urn:example:cell-b:arm-1",
          "environment" => "physical"
        })

      assert EffectAuthority.operation_key(same) == {:ok, baseline}
      refute EffectAuthority.operation_key(other_operation) == {:ok, baseline}
      refute EffectAuthority.operation_key(other_target) == {:ok, baseline}
    end

    test "an invalid record has neither a digest nor a key" do
      invalid = Map.put(Fixture.record(), "extra", "x")

      assert EffectAuthority.binding_digest(invalid) == {:error, :invalid_effect_binding}
      assert EffectAuthority.operation_key(invalid) == {:error, :invalid_effect_binding}
    end
  end

  describe "totality" do
    property "the record functions return a tagged result for any term" do
      check all(term <- term()) do
        assert EffectAuthority.fetch_binding(term) in [
                 {:error, :effect_binding_required},
                 {:error, :invalid_effect_binding}
               ]

        assert EffectAuthority.validate_binding(term) == {:error, :invalid_effect_binding}
        assert EffectAuthority.binding_digest(term) == {:error, :invalid_effect_binding}
        assert EffectAuthority.operation_key(term) == {:error, :invalid_effect_binding}
      end
    end

    property "a record with any one field replaced by an arbitrary term never raises" do
      check all(
              key <- member_of(Map.keys(Fixture.record())),
              value <- term()
            ) do
        record = Map.put(Fixture.record(), key, value)

        assert EffectAuthority.validate_binding(record) in [
                 :ok,
                 {:error, :invalid_effect_binding}
               ]

        assert match?({_, _}, EffectAuthority.binding_digest(record))
      end
    end

    test "distinct record keys and values create no atoms" do
      probe = fn index ->
        EffectAuthority.fetch_binding(
          Fixture.put_record(Fixture.request(), %{"key-#{index}" => "value-#{index}"})
        )
      end

      probe.(0)
      before = :erlang.system_info(:atom_count)
      Enum.each(1..500, probe)

      assert :erlang.system_info(:atom_count) == before
    end
  end

  defp sha256(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end

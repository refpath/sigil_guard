Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.TrustBundle do
  @moduledoc "Benchmarks of trust bundle verification and the bundle cache."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache

  @impl SigilGuard.Bench
  def id, do: "trust_bundle"

  @impl SigilGuard.Bench
  def title, do: "Trust Bundle Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    A host verifies a trust bundle when it loads one and reads it from the
    cache afterwards. The fixture is a signed bundle with one root key, two
    delegate roles and ten pattern entries. Cold verification covers the
    envelope signature, the schema, role thresholds, freshness and the
    rollback check against the cache. The warm path is one cache read.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    Cache.clear()

    envelope = Fixtures.bundle_envelope()
    bundle = Fixtures.bundle()
    now = Fixtures.bundle_now()
    {:ok, _} = Cache.put(bundle)

    %{
      "BM.06 trust bundle verify cold" => fn -> TrustBundle.verify(envelope, now: now) end,
      "BM.06 trust bundle cache warm" => fn -> Cache.get(bundle.bundle_id) end,
      "BM.23 trust bundle load" => fn ->
        TrustBundle.load({:map, envelope}, now: now, cache: false)
      end,
      "BM.23 trust bundle pattern sets" => fn -> TrustBundle.pattern_sets(bundle) end
    }
  end

  @impl SigilGuard.Bench
  def preconditions! do
    Cache.clear()

    bundle = Fixtures.bundle()
    delegates = get_in(bundle.document, ["roles", "delegates"])

    Bench.expect!(length(delegates) == 2, "BM.06 bundle does not have two delegations")
    Bench.expect!(length(TrustBundle.patterns(bundle)) == 10, "BM.06 bundle lacks ten patterns")

    Bench.expect!(
      match?({:ok, _}, TrustBundle.pattern_sets(bundle)),
      "BM.23 patterns do not resolve"
    )

    loaded =
      TrustBundle.load({:map, Fixtures.bundle_envelope()},
        now: Fixtures.bundle_now(),
        cache: false
      )

    Bench.expect!(match?({:ok, _}, loaded), "BM.23 load: #{inspect(loaded)}")

    {:ok, _} = Cache.put(bundle)

    Bench.expect!(match?({:ok, _}, Cache.get(bundle.bundle_id)), "BM.06 cache read misses")
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.TrustBundle)

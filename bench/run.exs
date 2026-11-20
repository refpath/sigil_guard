# Runs every benchmark suite, then writes the summary page and the
# machine-readable results that `bench/compare.exs` reads.
#
#     mix bench            # measured run, writes bench/output/
#     mix bench --smoke    # tiny budgets, writes bench/output/smoke/
#
# One suite alone: `mix bench.scanner`, `mix bench.gate`, and so on.

Code.require_file("support/harness.exs", __DIR__)
SigilGuard.Bench.library!()

for suite <- ~w(scanner gate stream gateway confirmation attestation trust_bundle agent_trust
                audit primitives) do
  Code.require_file(suite <> ".exs", __DIR__)
end

defmodule SigilGuard.Bench.Suites do
  @moduledoc "The benchmark suites, in the order of their pages."

  @doc "Every suite module."
  @spec all() :: [module(), ...]
  def all do
    [
      SigilGuard.Bench.Scanner,
      SigilGuard.Bench.Gate,
      SigilGuard.Bench.Stream,
      SigilGuard.Bench.Gateway,
      SigilGuard.Bench.Confirmation,
      SigilGuard.Bench.Attestation,
      SigilGuard.Bench.TrustBundle,
      SigilGuard.Bench.AgentTrust,
      SigilGuard.Bench.Audit,
      SigilGuard.Bench.Primitives
    ]
  end
end

unless function_exported?(Mix, :env, 0) and Mix.env() == :test do
  SigilGuard.Bench.run_all(SigilGuard.Bench.Suites.all())
end

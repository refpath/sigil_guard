Code.require_file("support/harness.exs", __DIR__)
Code.require_file("support/fixtures.exs", __DIR__)

defmodule SigilGuard.Bench.Attestation do
  @moduledoc "Benchmarks of Agent Trust statements: build, sign, verify."
  @behaviour SigilGuard.Bench

  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Bench
  alias SigilGuard.Bench.Fixtures
  alias SigilGuard.Bench.RoleSigner
  alias SigilGuard.BenchSigner
  alias SigilGuard.TrustProfile

  @impl SigilGuard.Bench
  def id, do: "attestation"

  @impl SigilGuard.Bench
  def title, do: "Attestation Benchmarks"

  @impl SigilGuard.Bench
  def description do
    """
    An attestation is a DSSE envelope over a JCS-canonical statement whose
    subjects are the action, payload, context and manifest digests. The suite
    times each step a host or a verifier runs: computing the digests,
    building the statement from a decision, validating it, signing, and
    verifying against a key map and against a trust bundle role. Signing and
    verification are dominated by Ed25519.
    """
  end

  @impl SigilGuard.Bench
  def scenarios do
    payload = payload()
    context = Fixtures.attestation_context()
    decision = Fixtures.allow_decision()
    statement = statement()
    envelope = envelope(BenchSigner)
    material = %{hd(envelope["signatures"])["keyid"] => BenchSigner.public_key()}
    bundle = Fixtures.bundle()
    role_envelope = envelope(RoleSigner)
    # A statement lives five minutes. Verification reads the clock unless it
    # is given one, and against the wall clock the fixture has expired.
    now = Fixtures.now()

    %{
      "BM.05 attestation sign" => fn -> Attestation.sign(statement, BenchSigner) end,
      "BM.05 attestation verify" => fn ->
        Attestation.verify(envelope, material, payload: payload, context: context, now: now)
      end,
      "BM.21 attestation digests" => fn -> Digest.digests(:tool_request, payload, context) end,
      "BM.21 attestation from_decision" => fn ->
        Attestation.from_decision(decision, context, statement_opts())
      end,
      "BM.21 trust profile validate" => fn -> TrustProfile.validate(statement) end,
      "BM.22 attestation verify signature only" => fn ->
        Attestation.verify(envelope, material, now: now)
      end,
      "BM.22 attestation verify with trust bundle" => fn ->
        Attestation.verify(role_envelope, bundle, payload: payload, context: context, now: now)
      end
    }
  end

  defp payload, do: Fixtures.request()

  defp statement_opts,
    do: [payload: payload(), now: Fixtures.now(), nonce: "bench-attestation-nonce"]

  defp statement do
    {:ok, statement} =
      Attestation.from_decision(
        Fixtures.allow_decision(),
        Fixtures.attestation_context(),
        statement_opts()
      )

    statement
  end

  defp envelope(signer) do
    {:ok, envelope} = Attestation.sign(statement(), signer)
    envelope
  end

  @impl SigilGuard.Bench
  def preconditions! do
    envelope = envelope(BenchSigner)
    material = %{hd(envelope["signatures"])["keyid"] => BenchSigner.public_key()}
    context = Fixtures.attestation_context()

    verified =
      Attestation.verify(envelope, material,
        payload: payload(),
        context: context,
        now: Fixtures.now()
      )

    Bench.expect!(match?({:ok, _}, verified), "BM.05 verify: #{inspect(verified)}")
    Bench.expect!(envelope == envelope(BenchSigner), "BM.05 signed bytes differ between builds")

    Bench.expect!(
      TrustProfile.validate(statement()) == {:ok, statement()},
      "BM.21 statement does not validate"
    )

    by_role =
      Attestation.verify(envelope(RoleSigner), Fixtures.bundle(),
        payload: payload(),
        context: context,
        now: Fixtures.now()
      )

    Bench.expect!(match?({:ok, _}, by_role), "BM.22 bundle verify: #{inspect(by_role)}")

    refused = Attestation.verify(envelope, Fixtures.bundle(), now: Fixtures.now())

    Bench.expect!(
      match?({:error, _}, refused),
      "BM.22 bundle accepts a key outside its attestation role"
    )
  end
end

SigilGuard.Bench.script(SigilGuard.Bench.Attestation)

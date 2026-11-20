defmodule SigilGuard.Attestation.EnvelopeCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Envelope

  test "cosigning refuses a term that is not an envelope map" do
    signer = SigilGuard.TestSigner

    for term <- [nil, "envelope", [%{"payload" => ""}], 7] do
      assert Envelope.add_signature(term, signer) == {:error, :invalid_envelope}
      assert Envelope.add_signature(term, signer, keyid: "second") == {:error, :invalid_envelope}
    end
  end
end

# Attestation Benchmarks

An attestation is a DSSE envelope over a JCS-canonical statement whose
subjects are the action, payload, context and manifest digests. The suite
times each step a host or a verifier runs: computing the digests,
building the statement from a decision, validating it, signing, and
verifying against a key map and against a trust bundle role. Signing and
verification are dominated by Ed25519.

Mode: measured. Values are measured for this environment, not ratified SLO bounds.


## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (3471773)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## System

Benchmark suite executing on the following system:

<table style="width: 1%">
  <tr>
    <th style="width: 1%; white-space: nowrap">Operating System</th>
    <td>macOS</td>
  </tr><tr>
    <th style="white-space: nowrap">CPU Information</th>
    <td style="white-space: nowrap">Apple M4 Max</td>
  </tr><tr>
    <th style="white-space: nowrap">Number of Available Cores</th>
    <td style="white-space: nowrap">16</td>
  </tr><tr>
    <th style="white-space: nowrap">Available Memory</th>
    <td style="white-space: nowrap">128 GB</td>
  </tr><tr>
    <th style="white-space: nowrap">Elixir Version</th>
    <td style="white-space: nowrap">1.20.4</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">29.0.4</td>
  </tr>
</table>

## Configuration

Benchmark suite executing with the following configuration:

<table style="width: 1%">
  <tr>
    <th style="width: 1%">:time</th>
    <td style="white-space: nowrap">5 s</td>
  </tr><tr>
    <th>:parallel</th>
    <td style="white-space: nowrap">1</td>
  </tr><tr>
    <th>:warmup</th>
    <td style="white-space: nowrap">2 s</td>
  </tr>
</table>

## Statistics



Run Time

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Deviation</th>
    <th style="text-align: right">Median</th>
    <th style="text-align: right">99th&nbsp;%</th>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 trust profile validate</td>
    <td style="white-space: nowrap; text-align: right">347.65 K</td>
    <td style="white-space: nowrap; text-align: right">2.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;268.83%</td>
    <td style="white-space: nowrap; text-align: right">2.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">59.00 K</td>
    <td style="white-space: nowrap; text-align: right">16.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.25%</td>
    <td style="white-space: nowrap; text-align: right">15.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.47 K</td>
    <td style="white-space: nowrap; text-align: right">26.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.39%</td>
    <td style="white-space: nowrap; text-align: right">25.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.39 K</td>
    <td style="white-space: nowrap; text-align: right">61.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.90%</td>
    <td style="white-space: nowrap; text-align: right">60.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">12.46 K</td>
    <td style="white-space: nowrap; text-align: right">80.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.58%</td>
    <td style="white-space: nowrap; text-align: right">78.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">100.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">11.95 K</td>
    <td style="white-space: nowrap; text-align: right">83.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.80%</td>
    <td style="white-space: nowrap; text-align: right">82.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">104.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">10.71 K</td>
    <td style="white-space: nowrap; text-align: right">93.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.05%</td>
    <td style="white-space: nowrap; text-align: right">91.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">115.42 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.21 trust profile validate</td>
    <td style="white-space: nowrap;text-align: right">347.65 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">59.00 K</td>
    <td style="white-space: nowrap; text-align: right">5.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.47 K</td>
    <td style="white-space: nowrap; text-align: right">9.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.39 K</td>
    <td style="white-space: nowrap; text-align: right">21.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">12.46 K</td>
    <td style="white-space: nowrap; text-align: right">27.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">11.95 K</td>
    <td style="white-space: nowrap; text-align: right">29.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">10.71 K</td>
    <td style="white-space: nowrap; text-align: right">32.45x</td>
  </tr>

</table>



Memory Usage

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Factor</th>
  </tr>
  <tr>
    <td style="white-space: nowrap">BM.21 trust profile validate</td>
    <td style="white-space: nowrap">3.40 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap">50.46 KB</td>
    <td>14.85x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap">65.47 KB</td>
    <td>19.26x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap">27.83 KB</td>
    <td>8.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">79.36 KB</td>
    <td>23.35x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap">84.75 KB</td>
    <td>24.94x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">49.94 KB</td>
    <td>14.69x</td>
  </tr>
</table>
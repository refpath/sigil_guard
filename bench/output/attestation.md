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
- SigilGuard: 1.0.5 (1426856)
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
    <td style="white-space: nowrap; text-align: right">386.88 K</td>
    <td style="white-space: nowrap; text-align: right">2.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;274.93%</td>
    <td style="white-space: nowrap; text-align: right">2.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">62.32 K</td>
    <td style="white-space: nowrap; text-align: right">16.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.10%</td>
    <td style="white-space: nowrap; text-align: right">15.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">36.87 K</td>
    <td style="white-space: nowrap; text-align: right">27.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.46%</td>
    <td style="white-space: nowrap; text-align: right">25.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">61.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.54%</td>
    <td style="white-space: nowrap; text-align: right">61.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.22 K</td>
    <td style="white-space: nowrap; text-align: right">75.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.79%</td>
    <td style="white-space: nowrap; text-align: right">74.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">98.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">13.05 K</td>
    <td style="white-space: nowrap; text-align: right">76.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.17%</td>
    <td style="white-space: nowrap; text-align: right">76.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">98 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">10.65 K</td>
    <td style="white-space: nowrap; text-align: right">93.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.49%</td>
    <td style="white-space: nowrap; text-align: right">92.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">116.79 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">386.88 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">62.32 K</td>
    <td style="white-space: nowrap; text-align: right">6.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">36.87 K</td>
    <td style="white-space: nowrap; text-align: right">10.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">23.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.22 K</td>
    <td style="white-space: nowrap; text-align: right">29.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">13.05 K</td>
    <td style="white-space: nowrap; text-align: right">29.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">10.65 K</td>
    <td style="white-space: nowrap; text-align: right">36.33x</td>
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
    <td style="white-space: nowrap">26.22 KB</td>
    <td>7.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">77.41 KB</td>
    <td>22.78x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap">83.15 KB</td>
    <td>24.47x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">49.94 KB</td>
    <td>14.69x</td>
  </tr>
</table>
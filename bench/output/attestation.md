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
- SigilGuard: 1.0.5 (0eca0a4)
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
    <td style="white-space: nowrap; text-align: right">336.30 K</td>
    <td style="white-space: nowrap; text-align: right">2.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;333.01%</td>
    <td style="white-space: nowrap; text-align: right">2.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">62.82 K</td>
    <td style="white-space: nowrap; text-align: right">15.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.06%</td>
    <td style="white-space: nowrap; text-align: right">14.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.40 K</td>
    <td style="white-space: nowrap; text-align: right">26.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.80%</td>
    <td style="white-space: nowrap; text-align: right">25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.82 K</td>
    <td style="white-space: nowrap; text-align: right">59.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.23%</td>
    <td style="white-space: nowrap; text-align: right">57.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">12.91 K</td>
    <td style="white-space: nowrap; text-align: right">77.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.75%</td>
    <td style="white-space: nowrap; text-align: right">75.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">99.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">12.32 K</td>
    <td style="white-space: nowrap; text-align: right">81.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.61%</td>
    <td style="white-space: nowrap; text-align: right">79.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.07 K</td>
    <td style="white-space: nowrap; text-align: right">90.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.18%</td>
    <td style="white-space: nowrap; text-align: right">89.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.83 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">336.30 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">62.82 K</td>
    <td style="white-space: nowrap; text-align: right">5.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.40 K</td>
    <td style="white-space: nowrap; text-align: right">8.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.82 K</td>
    <td style="white-space: nowrap; text-align: right">19.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">12.91 K</td>
    <td style="white-space: nowrap; text-align: right">26.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">12.32 K</td>
    <td style="white-space: nowrap; text-align: right">27.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.07 K</td>
    <td style="white-space: nowrap; text-align: right">30.37x</td>
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
    <td style="white-space: nowrap">49.90 KB</td>
    <td>14.68x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap">64.52 KB</td>
    <td>18.99x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap">26.22 KB</td>
    <td>7.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">76.97 KB</td>
    <td>22.65x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap">82.03 KB</td>
    <td>24.14x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">49.94 KB</td>
    <td>14.69x</td>
  </tr>
</table>
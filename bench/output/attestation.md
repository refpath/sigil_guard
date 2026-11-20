# Attestation Benchmarks

An attestation is a DSSE envelope over a JCS-canonical statement whose
subjects are the action, payload, context and manifest digests. The suite
times each step a host or a verifier runs: computing the digests,
building the statement from a decision, validating it, signing, and
verifying against a key map and against a trust bundle role. Signing and
verification are dominated by Ed25519.

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Scenarios that take less than 10 µs run in batches of calls;
every value is per call.


## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (39a9315)
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
    <td style="white-space: nowrap; text-align: right">284.41 K</td>
    <td style="white-space: nowrap; text-align: right">3.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;399.26%</td>
    <td style="white-space: nowrap; text-align: right">2.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">58.27 K</td>
    <td style="white-space: nowrap; text-align: right">17.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.89%</td>
    <td style="white-space: nowrap; text-align: right">15.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">35.29 K</td>
    <td style="white-space: nowrap; text-align: right">28.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.44%</td>
    <td style="white-space: nowrap; text-align: right">25.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">48.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.48 K</td>
    <td style="white-space: nowrap; text-align: right">60.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;44.27%</td>
    <td style="white-space: nowrap; text-align: right">58.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.69 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.74 K</td>
    <td style="white-space: nowrap; text-align: right">72.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.84%</td>
    <td style="white-space: nowrap; text-align: right">73.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">86.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.72 K</td>
    <td style="white-space: nowrap; text-align: right">85.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.22%</td>
    <td style="white-space: nowrap; text-align: right">85.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">99.52 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">11.51 K</td>
    <td style="white-space: nowrap; text-align: right">86.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;75.95%</td>
    <td style="white-space: nowrap; text-align: right">82.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">242.17 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">284.41 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">58.27 K</td>
    <td style="white-space: nowrap; text-align: right">4.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">35.29 K</td>
    <td style="white-space: nowrap; text-align: right">8.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">16.48 K</td>
    <td style="white-space: nowrap; text-align: right">17.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.74 K</td>
    <td style="white-space: nowrap; text-align: right">20.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.72 K</td>
    <td style="white-space: nowrap; text-align: right">24.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">11.51 K</td>
    <td style="white-space: nowrap; text-align: right">24.71x</td>
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
    <td style="white-space: nowrap">3.41 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap">50.46 KB</td>
    <td>14.81x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap">65.47 KB</td>
    <td>19.22x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap">27.83 KB</td>
    <td>8.17x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">79.36 KB</td>
    <td>23.3x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">49.94 KB</td>
    <td>14.66x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap">84.75 KB</td>
    <td>24.88x</td>
  </tr>
</table>
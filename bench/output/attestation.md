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
- SigilGuard: 1.0.5 (becb2d6)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-21

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
    <td style="white-space: nowrap; text-align: right">427.96 K</td>
    <td style="white-space: nowrap; text-align: right">2.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;63.74%</td>
    <td style="white-space: nowrap; text-align: right">2.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">59.71 K</td>
    <td style="white-space: nowrap; text-align: right">16.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.64%</td>
    <td style="white-space: nowrap; text-align: right">16.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.04 K</td>
    <td style="white-space: nowrap; text-align: right">27.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.94%</td>
    <td style="white-space: nowrap; text-align: right">26.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">18.67 K</td>
    <td style="white-space: nowrap; text-align: right">53.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.14%</td>
    <td style="white-space: nowrap; text-align: right">52.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.70 K</td>
    <td style="white-space: nowrap; text-align: right">73.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.24%</td>
    <td style="white-space: nowrap; text-align: right">72.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">89.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">13.63 K</td>
    <td style="white-space: nowrap; text-align: right">73.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.41%</td>
    <td style="white-space: nowrap; text-align: right">72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.40 K</td>
    <td style="white-space: nowrap; text-align: right">87.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.10%</td>
    <td style="white-space: nowrap; text-align: right">86.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">105.71 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">427.96 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap; text-align: right">59.71 K</td>
    <td style="white-space: nowrap; text-align: right">7.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap; text-align: right">37.04 K</td>
    <td style="white-space: nowrap; text-align: right">11.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap; text-align: right">18.67 K</td>
    <td style="white-space: nowrap; text-align: right">22.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">13.70 K</td>
    <td style="white-space: nowrap; text-align: right">31.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap; text-align: right">13.63 K</td>
    <td style="white-space: nowrap; text-align: right">31.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.40 K</td>
    <td style="white-space: nowrap; text-align: right">37.54x</td>
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
    <td style="white-space: nowrap">3.23 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation digests</td>
    <td style="white-space: nowrap">50.69 KB</td>
    <td>15.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.21 attestation from_decision</td>
    <td style="white-space: nowrap">64.84 KB</td>
    <td>20.07x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify signature only</td>
    <td style="white-space: nowrap">27.52 KB</td>
    <td>8.52x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">79.05 KB</td>
    <td>24.47x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.22 attestation verify with trust bundle</td>
    <td style="white-space: nowrap">84.63 KB</td>
    <td>26.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">49.28 KB</td>
    <td>15.25x</td>
  </tr>
</table>
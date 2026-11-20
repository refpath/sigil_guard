# Agent-To-Agent Trust Benchmarks

An agent exchange signs a card once and attests each request and
response. The suite times card signing, verification and digest, an
attested request with a three-hop delegation chain, an attested response
bound to its requester, and the requester's verification of that
response with every binding checked. Each attest and verify step
verifies the peer's card envelope first, so it carries two Ed25519
operations.

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
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap; text-align: right">284.10 K</td>
    <td style="white-space: nowrap; text-align: right">3.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.06%</td>
    <td style="white-space: nowrap; text-align: right">3.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">50.27 K</td>
    <td style="white-space: nowrap; text-align: right">19.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;162.20%</td>
    <td style="white-space: nowrap; text-align: right">16.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">64.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">15.17 K</td>
    <td style="white-space: nowrap; text-align: right">65.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.38%</td>
    <td style="white-space: nowrap; text-align: right">65.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">91.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.94%</td>
    <td style="white-space: nowrap; text-align: right">88.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">112.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">6.02 K</td>
    <td style="white-space: nowrap; text-align: right">165.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.42%</td>
    <td style="white-space: nowrap; text-align: right">166.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">191.48 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.57 K</td>
    <td style="white-space: nowrap; text-align: right">218.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.82%</td>
    <td style="white-space: nowrap; text-align: right">218.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">255.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.50 K</td>
    <td style="white-space: nowrap; text-align: right">222.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.02%</td>
    <td style="white-space: nowrap; text-align: right">221.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">256.68 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap;text-align: right">284.10 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">50.27 K</td>
    <td style="white-space: nowrap; text-align: right">5.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">15.17 K</td>
    <td style="white-space: nowrap; text-align: right">18.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">25.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">6.02 K</td>
    <td style="white-space: nowrap; text-align: right">47.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.57 K</td>
    <td style="white-space: nowrap; text-align: right">62.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.50 K</td>
    <td style="white-space: nowrap; text-align: right">63.08x</td>
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
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap">9.96 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap">36.82 KB</td>
    <td>3.7x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap">48.66 KB</td>
    <td>4.89x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap">39.58 KB</td>
    <td>3.98x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap">160.69 KB</td>
    <td>16.14x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap">209.53 KB</td>
    <td>21.05x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap">226.95 KB</td>
    <td>22.8x</td>
  </tr>
</table>
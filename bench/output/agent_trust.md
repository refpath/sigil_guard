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
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap; text-align: right">264.76 K</td>
    <td style="white-space: nowrap; text-align: right">3.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.98%</td>
    <td style="white-space: nowrap; text-align: right">3.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">10.19 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">60.89 K</td>
    <td style="white-space: nowrap; text-align: right">16.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.07%</td>
    <td style="white-space: nowrap; text-align: right">15.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">16.15 K</td>
    <td style="white-space: nowrap; text-align: right">61.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.61%</td>
    <td style="white-space: nowrap; text-align: right">60.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">12.32 K</td>
    <td style="white-space: nowrap; text-align: right">81.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.89%</td>
    <td style="white-space: nowrap; text-align: right">79.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">6.27 K</td>
    <td style="white-space: nowrap; text-align: right">159.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.20%</td>
    <td style="white-space: nowrap; text-align: right">157.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">188.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.84 K</td>
    <td style="white-space: nowrap; text-align: right">206.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.65%</td>
    <td style="white-space: nowrap; text-align: right">204.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">242.76 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.71 K</td>
    <td style="white-space: nowrap; text-align: right">212.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.21%</td>
    <td style="white-space: nowrap; text-align: right">211.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">243.64 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">264.76 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">60.89 K</td>
    <td style="white-space: nowrap; text-align: right">4.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">16.15 K</td>
    <td style="white-space: nowrap; text-align: right">16.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">12.32 K</td>
    <td style="white-space: nowrap; text-align: right">21.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">6.27 K</td>
    <td style="white-space: nowrap; text-align: right">42.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.84 K</td>
    <td style="white-space: nowrap; text-align: right">54.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.71 K</td>
    <td style="white-space: nowrap; text-align: right">56.19x</td>
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
    <td style="white-space: nowrap">9.07 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap">37 KB</td>
    <td>4.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap">48.32 KB</td>
    <td>5.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap">39.96 KB</td>
    <td>4.4x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap">159.30 KB</td>
    <td>17.56x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap">222.23 KB</td>
    <td>24.49x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap">205.81 KB</td>
    <td>22.68x</td>
  </tr>
</table>
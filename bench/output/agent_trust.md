# Agent-To-Agent Trust Benchmarks

An agent exchange signs a card once and attests each request and
response. The suite times card signing, verification and digest, an
attested request with a three-hop delegation chain, an attested response
bound to its requester, and the requester's verification of that
response with every binding checked. Each attest and verify step
verifies the peer's card envelope first, so it carries two Ed25519
operations.

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
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap; text-align: right">244.95 K</td>
    <td style="white-space: nowrap; text-align: right">4.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;209.19%</td>
    <td style="white-space: nowrap; text-align: right">3.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">57.84 K</td>
    <td style="white-space: nowrap; text-align: right">17.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.09%</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">14.87 K</td>
    <td style="white-space: nowrap; text-align: right">67.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.08%</td>
    <td style="white-space: nowrap; text-align: right">66.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">11.05 K</td>
    <td style="white-space: nowrap; text-align: right">90.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.70%</td>
    <td style="white-space: nowrap; text-align: right">89.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">110.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">5.60 K</td>
    <td style="white-space: nowrap; text-align: right">178.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.82%</td>
    <td style="white-space: nowrap; text-align: right">175.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">221.30 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">231.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.12%</td>
    <td style="white-space: nowrap; text-align: right">225.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">298.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.23 K</td>
    <td style="white-space: nowrap; text-align: right">236.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.97%</td>
    <td style="white-space: nowrap; text-align: right">229.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">309.90 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">244.95 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">57.84 K</td>
    <td style="white-space: nowrap; text-align: right">4.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">14.87 K</td>
    <td style="white-space: nowrap; text-align: right">16.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">11.05 K</td>
    <td style="white-space: nowrap; text-align: right">22.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">5.60 K</td>
    <td style="white-space: nowrap; text-align: right">43.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">56.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">4.23 K</td>
    <td style="white-space: nowrap; text-align: right">57.94x</td>
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
    <td style="white-space: nowrap">9.91 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap">36.82 KB</td>
    <td>3.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap">48.66 KB</td>
    <td>4.91x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap">39.58 KB</td>
    <td>3.99x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap">158.15 KB</td>
    <td>15.95x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap">208.16 KB</td>
    <td>21.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap">225.58 KB</td>
    <td>22.75x</td>
  </tr>
</table>
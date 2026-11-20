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
    <td style="white-space: nowrap">BM.25 verify delegation chain</td>
    <td style="white-space: nowrap; text-align: right">233.40 K</td>
    <td style="white-space: nowrap; text-align: right">4.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;189.83%</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">10.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">54.40 K</td>
    <td style="white-space: nowrap; text-align: right">18.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.52%</td>
    <td style="white-space: nowrap; text-align: right">17.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">14.52 K</td>
    <td style="white-space: nowrap; text-align: right">68.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.33%</td>
    <td style="white-space: nowrap; text-align: right">67.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">87.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">10.21 K</td>
    <td style="white-space: nowrap; text-align: right">97.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.92%</td>
    <td style="white-space: nowrap; text-align: right">98.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">118.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">5.68 K</td>
    <td style="white-space: nowrap; text-align: right">175.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.71%</td>
    <td style="white-space: nowrap; text-align: right">175.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">210.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.05 K</td>
    <td style="white-space: nowrap; text-align: right">247.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.11%</td>
    <td style="white-space: nowrap; text-align: right">244.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">313.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">3.90 K</td>
    <td style="white-space: nowrap; text-align: right">256.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.03%</td>
    <td style="white-space: nowrap; text-align: right">257.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">318.62 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">233.40 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card digest</td>
    <td style="white-space: nowrap; text-align: right">54.40 K</td>
    <td style="white-space: nowrap; text-align: right">4.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card verify</td>
    <td style="white-space: nowrap; text-align: right">14.52 K</td>
    <td style="white-space: nowrap; text-align: right">16.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.24 agent card sign</td>
    <td style="white-space: nowrap; text-align: right">10.21 K</td>
    <td style="white-space: nowrap; text-align: right">22.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 verify agent response</td>
    <td style="white-space: nowrap; text-align: right">5.68 K</td>
    <td style="white-space: nowrap; text-align: right">41.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap; text-align: right">4.05 K</td>
    <td style="white-space: nowrap; text-align: right">57.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap; text-align: right">3.90 K</td>
    <td style="white-space: nowrap; text-align: right">59.88x</td>
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
    <td style="white-space: nowrap">159.17 KB</td>
    <td>16.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent response</td>
    <td style="white-space: nowrap">209.16 KB</td>
    <td>21.1x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.25 attest agent request</td>
    <td style="white-space: nowrap">227.02 KB</td>
    <td>22.9x</td>
  </tr>
</table>
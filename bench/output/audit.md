# Audit Evidence Benchmarks

Every decision can append one HMAC-chained audit event, and a host
periodically checkpoints the chain into a Merkle root and exports
evidence. The suite appends to a chain of 10,000 events, creates a
checkpoint over it, builds and verifies inclusion and consistency proofs,
verifies a chain of 1,000 events, and exports it. Event ids and
timestamps follow from the event index, so the chain has the same bytes
on every run.

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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">635851.90</td>
    <td style="white-space: nowrap; text-align: right">0.00157 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;54.88%</td>
    <td style="white-space: nowrap; text-align: right">0.00149 ms</td>
    <td style="white-space: nowrap; text-align: right">0.00313 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">131278.12</td>
    <td style="white-space: nowrap; text-align: right">0.00762 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;79.50%</td>
    <td style="white-space: nowrap; text-align: right">0.00660 ms</td>
    <td style="white-space: nowrap; text-align: right">0.0518 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">86953.00</td>
    <td style="white-space: nowrap; text-align: right">0.0115 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;99.22%</td>
    <td style="white-space: nowrap; text-align: right">0.00958 ms</td>
    <td style="white-space: nowrap; text-align: right">0.101 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">628.12</td>
    <td style="white-space: nowrap; text-align: right">1.59 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.70%</td>
    <td style="white-space: nowrap; text-align: right">1.58 ms</td>
    <td style="white-space: nowrap; text-align: right">1.88 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">287.60</td>
    <td style="white-space: nowrap; text-align: right">3.48 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.84%</td>
    <td style="white-space: nowrap; text-align: right">3.47 ms</td>
    <td style="white-space: nowrap; text-align: right">3.73 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">184.02</td>
    <td style="white-space: nowrap; text-align: right">5.43 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.67%</td>
    <td style="white-space: nowrap; text-align: right">5.42 ms</td>
    <td style="white-space: nowrap; text-align: right">6.94 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">182.23</td>
    <td style="white-space: nowrap; text-align: right">5.49 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.71%</td>
    <td style="white-space: nowrap; text-align: right">5.55 ms</td>
    <td style="white-space: nowrap; text-align: right">6.79 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">181.20</td>
    <td style="white-space: nowrap; text-align: right">5.52 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.83%</td>
    <td style="white-space: nowrap; text-align: right">5.60 ms</td>
    <td style="white-space: nowrap; text-align: right">6.94 ms</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap;text-align: right">635851.90</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">131278.12</td>
    <td style="white-space: nowrap; text-align: right">4.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">86953.00</td>
    <td style="white-space: nowrap; text-align: right">7.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">628.12</td>
    <td style="white-space: nowrap; text-align: right">1012.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">287.60</td>
    <td style="white-space: nowrap; text-align: right">2210.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">184.02</td>
    <td style="white-space: nowrap; text-align: right">3455.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">182.23</td>
    <td style="white-space: nowrap; text-align: right">3489.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">181.20</td>
    <td style="white-space: nowrap; text-align: right">3509.08x</td>
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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap">0.00166 MB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap">0.00541 MB</td>
    <td>3.26x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap">0.00786 MB</td>
    <td>4.74x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap">1.46 MB</td>
    <td>884.16x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap">2.58 MB</td>
    <td>1559.07x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">3.75 MB</td>
    <td>2263.43x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap">3.99 MB</td>
    <td>2408.26x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap">3.89 MB</td>
    <td>2349.96x</td>
  </tr>
</table>
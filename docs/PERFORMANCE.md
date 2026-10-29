# Performance and capacity planning

IronTrellis (formerly Continuity) checks a history when it opens it, instead of taking it on trust, and checking takes time. How much depends on the history, the machine and the way you run IronTrellis. This page helps you plan a deployment: what has been measured, why those numbers won't carry over to yours as they stand, and what to measure yourself.

## What has been measured

[BENCHMARKS](BENCHMARKS.md) is the source for measured performance claims. It holds two kinds of measurement:

| Set | What it describes |
|---|---|
| Format 2, 12 October 2026 | One 10,000-event history on one machine, with the 1.0.0-rc.2 engine as it stood that day. Five of its eight budgets were met. Three were missed: the hook check, the full replay and a state root from scratch. |
| September 2026 | Legacy and format-1 builds, each with its own histories, hardware and date |

The dated [scale report](history/PERFORMANCE-2026-09-26.md) keeps the earlier method, measurements and regression budgets.

None of these is a capacity guarantee. A budget, in either set, is an engineering check, not a service-level promise. No benchmark was run for this page.

## Why your numbers will differ

These are different workloads, with different costs:

| Workload | What it involves |
|---|---|
| Opening a history | Reading the file and checking it, by a full replay or by resuming from a saved snapshot |
| Querying a state that is already open | A decision on a state already in memory (a "warm" decision) |
| Appending with durable flushes | Writing an event and flushing it to disk before it counts |
| Synchronizing with a witness | Bringing a remote witness up to the history's latest head |

Each cost also moves with the history's size, its mix of admissions and signatures, and its authority graph, and with your storage, CPU, memory and witness mode. A benchmark of warm decisions doesn't measure a complete cold execution, or an external service.

## What the format allows is not what has been shown

The format's hard limits are bounds, not demonstrated capacity:

| | Format 2 allows | The format-2 history on BENCHMARKS |
|---|---|---|
| State records | 1,048,576 | 13,552 |
| File size | 1 GiB | 12,466,632 bytes (10,000 events) |

[BENCHMARKS](BENCHMARKS.md) has no format-2 measurement near these limits, and [known issues](records/KNOWN-ISSUES-r2.5.md) 1, 2, 10 and 33 describe what is known, or untested, close to them. A proposed run plan isn't a demonstrated capacity either.

## Measure your own

Before you choose a deployment budget, measure the release you'll deploy, set up the way you'll run it, on histories like the ones you expect. With every result, record:

- the toolchain and the build;
- the event and authority counts;
- whether the state was warm or cold;
- the number of samples;
- the durability settings;
- peak memory;
- any limit at which work was refused, and any stage that didn't finish.

Report outliers and failed runs instead of extrapolating from successful small cases. [BENCHMARKS](BENCHMARKS.md) shows the commands behind its own numbers.

## When a history nears its limits

`irontrellis doctor` warns when a format-2 history reaches about 500,000 events or 500 MiB, and fails one within 10% of its hard file limit. Plan a successor history before a limit forces one: [OPERATOR §5](OPERATOR.md#5-monitoring) covers watching capacity, and [§6](OPERATOR.md#6-incident-playbook) what to do when it runs out. Don't relax validation or durability to get a better benchmark number.

*Last reviewed: 24 October 2026. This page is revisited at each release.*

# CyTL Monitor documentation

CyTL Monitor checks temporal-quantitative properties of a stream of
timestamped events *online*: each event is processed once, as it arrives, and
every part of the result is published as soon as it is decided. The
top-level [README](../README.md) gives a short overview and a quick start; these
pages explain how the library is built and how its classes fit together.

| Page | What it covers |
| --- | --- |
| [Architecture and design patterns](architecture.md) | the layers, the packages and how they depend on each other, and the patterns the code follows |
| [The streaming model](streaming-model.md) | the three streams (events, segments, intervals with horizons), their contracts, and when results are published |
| [Core data types](core.md) | `Interval`, `Polynomial`, `Segment`, `Signal`, `BooleanSignal` |
| [Events](events.md) | `Payload`, `Event`, `EventSequence`, `EventConsumer`, `EventProcessor` and the event relations |
| [Expressions](expressions.md) | the quantitative operators, from events to real-valued signals |
| [Monitors](monitors.md) | the boolean operators, from events to boolean signals |
| [Consumers](consumers.md) | the interfaces receiving signals, and the plotting consumers |
| [Offline evaluation](offline.md) | `Measure` and `SignalExpression`, over a whole event sequence |
| [Reading events from files](io.md) | `JsonEventReader`, `CsvEventReader`: the formats, the checks, schemas, feeding a monitor from a file |
| [Composing monitors](composition.md) | worked examples: building trees of operators, attaching consumers, writing new operators |

## Reading guide

* To *use* the library, read [the streaming model](streaming-model.md), then
  [composing monitors](composition.md), and look up the operators in
  [expressions](expressions.md) and [monitors](monitors.md).
* To *extend* it, read [architecture](architecture.md) for the patterns new
  classes should follow, and the last section of
  [composing monitors](composition.md).

## Conventions

* Intervals are written as in the code: `[a, b)` is closed on the left and open
  on the right, `[a,)` is unbounded on the right, `[a, a]` is a single point.
* `t` is the current time, `h` a horizon: a signal with horizon `h` is known on
  `[0, h)`.
* The examples are doctests: `cytlmonitor/tests/test_docs.py` runs every
  `>>>` session in these pages, so the outputs shown are those the code
  produces.

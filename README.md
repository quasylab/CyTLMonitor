# CyTL Monitor — online monitoring of event streams with a temporal-quantitative logic

CyTL Monitor is a Python library for checking properties of streams of
timestamped events while the events arrive. Properties combine quantities
computed over the stream, such as the number of packets or the sum of their
sizes over a sliding window, with comparisons, boolean connectives and
temporal operators (eventually, globally, until, since). Network traffic is the
main application: a monitor can raise an alarm when the number of half-open TCP
connections over the last 10 seconds goes above a threshold, when a high packet
rate lasts for several seconds, or when a password-guessing attack ends with a
successful login.

Monitors work online: each event is processed once, as it arrives, and every
part of the result is published as soon as it is known. Processing time grows
linearly with the length of the stream, and memory stays bounded.

---

## Contents of the repository

```text
cytlmonitor/        the library
  tests/            unit tests (pytest), including smoke tests of the examples
examples/           runnable examples on synthetic traffic, and a scalability benchmark
past/               an earlier prototype: a PyQt5 desktop application, kept for reference
requirements.txt
LICENSE             Apache License 2.0
```

---

## Concepts

**Events.** An `Event` has a time and a `Payload`, a read-only mapping of
fields to values. Events must arrive ordered by time. The examples use the
fields of a network packet (`size`, `protocol`, `tcp_syn`, `tcp_ack`,
`dst_port`, ...), but any fields can be used.

**Signals.** Monitoring builds signals over time, starting at 0:

* a *real-valued signal* is a sequence of `Segment`s, each a `Polynomial` over an
  `Interval`, with open or closed ends (`Signal`);
* a *boolean signal* is the sequence of `Interval`s where it is true
  (`BooleanSignal`).

**Expressions** (`StreamExpression`) consume events and publish a real-valued
signal, segment by segment, to the `SignalConsumer`s attached to them. They are
combined into trees.

| Expression | Signal |
| --- | --- |
| `SumWindowExpression(w, a, b)` | sum of `w(e)` over the events in `[t + a, t + b]` |
| `MaxWindowExpression(g, a, b)`, `MinWindowExpression(g, a, b)` | max / min of the piecewise-constant signal `g` over `[t + a, t + b]` |
| `ShiftExpression(g, d)` | `g(t - d)`: shifting a window sum by its length makes it look back, over `[t - d, t]` |
| `SumExpression`, `DifferenceExpression`, `ProductExpression`, `DivisionExpression` | point-wise arithmetic on two signals (division by 0 gives 0) |
| `NegationExpression`, `AbsExpression` | `-g(t)`, `abs(g(t))` |
| `ConstantExpression(c)` | the constant `c`, typically a threshold |

**Monitors** (`EventMonitor`) consume events and publish a boolean signal to the
`BooleanSignalConsumer`s attached to them, as intervals in time order, together
with a *horizon*: the signal is known on `[0, horizon)`. Monitors that look into
the future, such as eventually, are known later than the stream they read.

| Monitor | True at `t` when |
| --- | --- |
| `AtomicLessMonitor`, `AtomicLeqMonitor`, `AtomicGreaterMonitor`, `AtomicGeqMonitor` | the signal of one expression is `<`, `<=`, `>`, `>=` the signal of another |
| `TrueMonitor`, `FalseMonitor` | always, never |
| `NotMonitor`, `AndMonitor`, `OrMonitor`, `ImplyMonitor` | the boolean connectives |
| `EventuallyMonitor(m, I)` | `m` is true at some `t + t'`, `t'` in `I` |
| `GloballyMonitor(m, I)` | `m` is true at every `t + t'`, `t'` in `I` |
| `UntilMonitor(m1, m2, I)` | `m2` is true at some `t'` in `t + I`, and `m1` on `[t, t')` |
| `SinceMonitor(m1, m2, I)` | `m2` was true at some `t'` with `t - t'` in `I`, and `m1` is true on `(t', t]` |

In until and since, `m1` is not required at `t'` itself, so `m1` may stop (or
start) exactly where `m2` starts (or stops). When `I` contains 0, `t' = t` is
allowed and `m2` alone makes the property true: use a window such as `(0, 30]`
when that is not wanted. In since, `t'` may also be the open end of an interval
where `m2` is true, as long as `t' < t`, so that a property can take over from
`m2` right where `m2`'s interval `[a, b)` ends.

**Consumers** receive what expressions and monitors publish.
`PlotSignalConsumer` and `PlotBooleanSignalConsumer` plot it with Matplotlib,
updating the figure while the stream is processed when Matplotlib is in
interactive mode. Any number of consumers can be attached to an expression or a
monitor, including those nested inside another. An expression or a monitor,
however, must not be the argument of two others: each would pass it every
event.

**Event processors** (`EventProcessor`, `PreviousRelation`, `NextRelation`)
transform event streams and relate each event to the previous or next one.

---

## Quick start

```python
from cytlmonitor import (
    AtomicGreaterMonitor, BooleanSignalConsumer, ConstantExpression, Event, Payload,
    ShiftExpression, SumWindowExpression,
)

# Packets over the last 2 seconds, and an alarm when they are more than 5.
packets = ShiftExpression(SumWindowExpression(lambda e: 1.0, 0, 2), 2)
burst = AtomicGreaterMonitor(packets, ConstantExpression(5))


class Print(BooleanSignalConsumer):
    def consume(self, interval):
        print('alarm on', interval)

    def set_horizon(self, t):
        pass


burst.add(Print())
for t in [0.5, 1.0, 3.0, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 7.0]:
    burst.consume(Event(t, Payload({'size': 60})))
```

```text
alarm on [3.5,3.6)
alarm on [3.6,5.0]
alarm on (5.0,5.1]
```

The alarm holds on `[3.5, 5.1]`, while the window holds six or more packets. It
is published in pieces, each as soon as it is known; `examples/_traffic.py` has
a consumer, `AlarmPrinter`, that merges them.

---

## Examples

The `examples/` folder has runnable scripts on synthetic network traffic, each
printing when its properties hold; `--plot` also plots the signals:

```bash
python examples/syn_flood.py --plot
```

| Script | Property |
| --- | --- |
| `syn_flood.py` | more than 100 half-open TCP connections over the last 10 s |
| `sustained_rate.py` | a high packet rate lasting 3 s, ignoring short spikes |
| `port_scan.py` | a port scan (many SYNs, few ACKs) or an ICMP flood, and the same rule written with an implication |
| `until_since.py` | an SSH brute force ending with a successful login, and failures going on after a login |
| `quiet_since_attack.py` | cooling down and all clear after attacks reported by a detector |
| `scalability.py` | the time and memory the monitors need as the stream grows |

`examples/README.md` explains each of them, and the points worth knowing when
writing monitors.

---

## Performance

`examples/scalability.py` feeds the monitors of the examples with streams of up
to hundreds of thousands of events. On a laptop, every monitor scales linearly
with the length of the stream, at 10 to 50 µs per event (20,000 to 100,000
events per second, depending on the monitor), and the memory used while
monitoring stays within a few hundred KiB however long the stream is.

```bash
python examples/scalability.py --sizes 1000 10000 100000 --memory --plot
```

---

## Installation

Python 3.10 or later; developed and tested with Python 3.13.

```bash
git clone <repository-url>
cd CyTLMonitor
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The library itself needs only the standard library; Matplotlib is needed for
the plotting consumers and the `--plot` option of the examples, and pytest to
run the tests. PyQt5, pyqtgraph and Scapy are only used by the prototype in
`past/`; Scapy also needs a packet-capture library on the system (Npcap on
Windows, `libpcap` on Linux and macOS).

## Running the tests

```bash
python -m pytest cytlmonitor/tests
```

---

## Authors

* Marco Quadrini
* Michele Loreti

## License

Apache License 2.0: see `LICENSE`.

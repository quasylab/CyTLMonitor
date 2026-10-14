# Examples

Each script builds a few monitors from `cytlmonitor`, feeds them with synthetic
network traffic, and prints the time windows where each property holds. Run
them from the repository root:

```bash
python examples/syn_flood.py
python examples/syn_flood.py --plot     # also plot the signals and the alarms
```

The traffic is generated with a fixed seed, so every run gives the same
output. The events have the same payload fields as the packets read by
`cytl_capture.parse_packet` (`size`, `protocol`, `tcp_syn`, `tcp_ack`,
`dst_port`, ...), so the same monitors work on real captures.

| Script | Property | Shows |
| --- | --- | --- |
| `syn_flood.py` | more than 100 half-open connections (SYNs minus ACKs) over the last 10 s | `SumWindowExpression`, `ShiftExpression`, `DifferenceExpression`, `ConstantExpression`, `AtomicGreaterMonitor` |
| `sustained_rate.py` | a rate above 150 packets/s that lasts 3 s, ignoring short spikes | `GloballyMonitor`, `EventuallyMonitor`, several monitors on one stream |
| `port_scan.py` | many SYNs and few ACKs, or an ICMP flood; the same rule written with an implication | `AndMonitor`, `OrMonitor`, `NotMonitor`, `ImplyMonitor`, `AtomicLessMonitor`, `ProductExpression` |
| `until_since.py` | SSH brute force that ends in a successful login, and failures that go on after a login | `UntilMonitor`, `SinceMonitor`, events with custom fields |
| `quiet_since_attack.py` | quiet since an attack, reported by a detector's alerts, that ended less than 30 s ago (cooling down), or at least 30 s ago (all clear) | a custom `EventMonitor`, `SinceMonitor` with windows `(0, 30]` and `[30, ∞)`, `NotMonitor`, handing over between complementary signals |

`scalability.py` measures how these monitors cope with longer streams: see
[Scalability](#scalability) below.

`_traffic.py` holds what the scripts share: the traffic generators, the
`count_last` helper and `AlarmPrinter`, a consumer that merges the pieces a
monitor publishes and prints each alarm once it is over.

## Things worth knowing

**Counting over the last seconds.** `SumWindowExpression(w, 0, s)` sums `w`
over the window `[t, t + s]`, ahead of `t`. Shifting it forward by `s` with
`ShiftExpression` gives the sum over the last `s` seconds, `[t - s, t]`; this is
what `count_last` does.

**Build a new expression for every use.** An expression or a monitor passes
each event to its arguments. If the same instance is the argument of two
monitors, it receives every event twice, which breaks its state. The scripts
build their expressions with small functions, such as `syns()` or
`brute_force()`, that return a new instance at every call. Consumers are
different: any number can be attached to the same monitor, including monitors
nested inside another, as `port_scan.py` does to print each part of the rule.

**Monitors that look ahead are known later.** `sustained` in
`sustained_rate.py` (high for the next 3 s) and `breach` in `until_since.py`
(a login within the next 30 s) can only be decided once the future they look
at has been seen, so their horizon lags behind the stream. Monitors that only
look back, such as `SinceMonitor`, are known as soon as their arguments are.

**Until, since and windows containing 0.** `UntilMonitor` requires its first
argument on `[t, t')` and `SinceMonitor` on `(t', t]`, `t'` being when the
second argument holds; neither requires it at `t'` itself, so the first can
stop (or start) exactly where the second starts (or stops), as quiet and
attack do in `quiet_since_attack.py`. For since, `t'` may also be the open
end of an interval of the second argument, as long as `t' < t`: there, the
attack `[20, 28)` is followed by quiet from 28 on, a hand-over with
`t' = 28`. When the window contains 0, `t' = t` is
allowed and the second argument alone makes the property true: the examples
use windows such as `(0, 30]` when that is not wanted.

**Alarms that flicker.** In `port_scan.py`, "fewer than one ACK every four
SYNs" alone shows a 0.03 s alarm right after the scan, as the ratio crosses the
threshold again for an instant. Combined with "more than 100 SYNs" in the port
scan rule, it does not.

**Plotting.** With `--plot`, each script stacks a `PlotSignalConsumer` or
`PlotBooleanSignalConsumer` per signal; the dashed vertical line is the
horizon. The consumers only redraw while the stream is processed when
Matplotlib is in interactive mode (`matplotlib.pyplot.ion()`); otherwise the
figure is drawn once, at the end.

## Scalability

```bash
python examples/scalability.py                       # 1,000 to 100,000 events
python examples/scalability.py --sizes 1000 1000000  # pick the stream lengths
python examples/scalability.py --memory --plot       # also memory, and plots
```

The script feeds the monitors of the other examples (SYN flood, sustained
rate, port scan, until and since) with streams of increasing length, built
by repeating a 60 s cycle of traffic that contains every kind of activity they
look for, and measures the time spent in `consume`. For each monitor it
prints the time, the time per event and the events per second for every
length, and the exponent `k` of `time ~ n^k`, fitted on the larger lengths:
`k` close to 1 means that each event costs the same however long the stream
is. On a laptop, up to 300,000 events, every monitor scales linearly
(`k` between 0.99 and 1.03), at 10 to 50 µs per event depending on how much
it computes.

With `--memory`, a second run measures the peak memory allocated while
monitoring, with `tracemalloc` (which slows Python down, so it is kept out of
the timed run). It stays within a few hundred KiB however long the stream
is: the monitors only keep the intervals and window contents they still
need. The peak is the largest over all the cycles, so it can creep up a
little as more cycles are seen, without the memory kept by the monitor
growing.

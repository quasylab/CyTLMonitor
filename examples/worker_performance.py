"""
Performance of a worker
=======================

A worker runs jobs of two kinds, ``A`` and ``B``, two services sharing it,
and reports, as events, what each of them does. The payload of an event is
one of

- ``{'op': 'START', 'session': i, 'type': k}``: job ``i``, of kind ``k``
  (``'A'`` or ``'B'``), starts (``i`` is not the id of any running job; ids
  are reused once a job is over);
- ``{'op': 'STEP', 'session': i}``: job ``i`` completed a step;
- ``{'op': 'DONE', 'session': i}``: job ``i`` is over.

Three properties are monitored, each true where it holds:

- ``load``: the average number of running jobs stays in
  ``[MIN_JOBS, MAX_JOBS]`` for the next 10 time units,

      G[0,10] (MIN_JOBS <= running <= MAX_JOBS)

  where ``running`` is the time-weighted average number of running jobs over
  the next ``AVERAGE_WINDOW`` time units;
- ``completion``: the average time to complete a job stays below
  ``MST_THRESHOLD`` for the next 50 time units,

      G[0,50] (completion_time < MST_THRESHOLD)

  where ``completion_time`` is the average duration of the jobs ending
  within the next ``AVERAGE_WINDOW`` time units (0 if none does);
- ``heavy``: fewer than ``HEAVY_JOBS`` jobs taking more than
  ``HEAVY_DURATION`` time units end within the next 50 time units.

Three more use the next modality, filters and until:

- ``next job``: jobs keep arriving: on the START events alone, the next one
  comes within ``MAX_IDLE`` time units,

      filter[start] <any>[0,MAX_IDLE] true

  The filter makes the next event the next START: on the whole stream, the
  next event is often a STEP or a DONE;
- ``B service``: on the DONE events of jobs of kind B alone, the next one
  comes within ``B_RESPONSE`` time units and ends a job that was not heavy,

      filter[b_done] <quick>[0,B_RESPONSE] true

- ``recovery``: the worker recovers from an overload within ``RECOVERY``
  time units: where the average number of running jobs is above
  ``MAX_JOBS``, it is back in ``[MIN_JOBS, MAX_JOBS]`` within ``RECOVERY``,
  without falling below ``MIN_JOBS`` on the way,

      over -> (not_idle U[0,RECOVERY] in_range)

  Until requires its first argument up to the point where the second starts
  to hold. ``over U not_over`` would depend on which of the two holds where
  the average crosses ``MAX_JOBS``: when ``not_over`` only holds after that
  point, there is no first point where it holds, and the until is false.
  ``not_idle`` holds on both sides of the crossing.

Two expressions compare the services, over the next ``RATE_WINDOW`` time
units, in jobs per time unit:

- ``arrivals``: the arrival rate of ``A`` minus that of ``B``, from the START
  events of each kind;
- ``throughput``: the throughput of ``A`` minus that of ``B``, from the DONE
  events of each kind.

The duration of a job is read from a SessionRelation, which relates each
DONE event to the START event of the same session; so is the kind of job a
DONE event ends, which only the START event carries. The time since the
previous event comes from a PreviousRelation. An InstrumentedMonitor updates
both relations with every event before the properties see it. The two
expressions are fed with the events right after it, so that the relations
are up to date for them too.

The averages look ahead, as the properties do, so they need no warm-up: an
average over the last time units would be 0 at the beginning, before any
time has passed. The number of running jobs is not a function of a window of
events: it is kept by a counter, updated once per event, whatever the number
of expressions asking for it.

Two scenarios are generated: a ``stable`` worker, where the three properties
hold, and an ``unreliable`` one. In the unreliable worker, service ``B`` is
overloaded between 60 and 100: its jobs arrive faster and take longer, while
``A`` goes on as before; then the worker is nearly idle between 140 and 160.
The arrival rates differ as soon as the overload starts, while the
throughput of ``B`` first lags behind its arrivals, as its jobs pile up, and
then exceeds them, as they are drained after the overload.

``next job`` fails now and then while the worker is nearly idle, when no job
arrives for a while. ``B service`` fails during the overload of B, wherever
the next job of B to end is heavy, so it flickers. The overload lasts 40
time units, longer than ``RECOVERY``, so ``recovery`` fails in its first
part, until the end of the overload is within reach. The
properties look ahead up to 50 time units, so they are known up to 50
before the end of the 200 time units of each run. They are violated as soon
as a problem comes within their reach: ``completion`` and ``heavy`` from 50
before the overload.

Shows: SessionRelation and PreviousRelation with ``eval``,
InstrumentedMonitor, DivisionExpression as an average, DifferenceExpression
comparing two rates, NextMonitor inside FilterMonitor, UntilMonitor with
ImplyMonitor, and ``plot`` placing the nodes of two built monitors side by
side.

Run with ``python examples/worker_performance.py`` (add ``--plot`` to
compare the two scenarios).
"""

import heapq
import random
from typing import Callable, Dict, List, Optional, Tuple

from _traffic import arguments, feed, show
from cytlmonitor import (
    AndMonitor, AtomicGeqMonitor, AtomicGreaterMonitor, AtomicLeqMonitor, AtomicLessMonitor,
    BooleanSignal, BooleanSignalConsumer, ConstantExpression, DifferenceExpression,
    DivisionExpression, Event, FilterMonitor, FormulaNode, GloballyMonitor, ImplyMonitor,
    InstrumentedMonitor, Interval, NextMonitor, Payload, PreviousRelation, Segment,
    SessionRelation, SignalConsumer, StreamExpression, SumWindowExpression, TrueMonitor,
    UntilMonitor,
)
from cytlmonitor import plot as plot_nodes

MIN_JOBS = 10.0
MAX_JOBS = 20.0
MST_THRESHOLD = 1.0
HEAVY_JOBS = 1.0
# A job is heavy when it takes more than this to terminate.
HEAVY_DURATION = 2.0
# The averages are taken over the next AVERAGE_WINDOW time units.
AVERAGE_WINDOW = 5.0
# The next job starts within MAX_IDLE time units.
MAX_IDLE = 0.5
# The next job of kind B ends within B_RESPONSE time units.
B_RESPONSE = 2.0
# An overload is over within RECOVERY time units.
RECOVERY = 20.0
# The rates are counted over the next RATE_WINDOW time units: arrivals are
# random, so the longer the window, the smoother the rates.
RATE_WINDOW = 10.0
DURATION = 200.0
KINDS = ('A', 'B')


# --------------------------------------------------------------------------
# Synthetic workers
# --------------------------------------------------------------------------

def worker(until: float, arrival_rate: Callable[[str, float], float],
           job_duration: Callable[[str, float, random.Random], float], rng: random.Random,
           initial_jobs: Dict[str, int]) -> List[Event]:
    """The events of a worker running, up to ``until``, ``initial_jobs[k]``
    jobs of each kind ``k`` started at 0, and then jobs of kind ``k`` arriving
    at ``arrival_rate(k, t)`` per time unit on average, each taking
    ``job_duration(k, t, rng)`` and completing one to three steps on the way.
    Each job gets the smallest id no running job has.
    """
    jobs: List[Tuple[float, str, float]] = []
    for kind in KINDS:
        for _ in range(initial_jobs.get(kind, 0)):
            jobs.append((0.0, kind, job_duration(kind, 0.0, rng)))
        t = 0.0
        while True:
            # Arrivals of a Poisson process with a rate varying in time, by
            # thinning one at the highest rate.
            t += rng.expovariate(PEAK_RATE)
            if t >= until:
                break
            if rng.random() < arrival_rate(kind, t) / PEAK_RATE:
                jobs.append((t, kind, job_duration(kind, t, rng)))
    jobs.sort(key=lambda job: job[0])

    events, running, free, next_id = [], [], [], 0
    for start, kind, length in jobs:
        while running and running[0][0] < start:
            heapq.heappush(free, heapq.heappop(running)[1])
        if free:
            session = heapq.heappop(free)
        else:
            session, next_id = next_id, next_id + 1
        done = start + length
        heapq.heappush(running, (done, session))
        events.append(job_event(start, 'START', session, kind))
        for step in sorted(rng.uniform(start, done) for _ in range(rng.randint(1, 3))):
            events.append(job_event(step, 'STEP', session))
        events.append(job_event(done, 'DONE', session))
    return sorted((e for e in events if e.time < until), key=lambda e: e.time)


# The highest arrival rate of one kind of job in the scenarios below.
PEAK_RATE = 25.0
# Jobs of each kind per time unit, and how long they take, in the stable
# worker: about 15 jobs running, completing in 0.6 on average, none heavy.
STABLE_RATES = {'A': 15.0, 'B': 10.0}
STABLE_DURATIONS = {'A': (0.2, 0.8), 'B': (0.4, 1.0)}
INITIAL_JOBS = {'A': 8, 'B': 7}


def job_event(time: float, op: str, session: int, kind: Optional[str] = None) -> Event:
    """An event of job ``session``; the START event carries its ``kind``."""
    fields = {'op': op, 'session': session}
    if kind is not None:
        fields['type'] = kind
    return Event(time, Payload(fields))


def stable_duration(kind: str, rng: random.Random) -> float:
    return rng.uniform(*STABLE_DURATIONS[kind])


def stable_worker(seed: int = 1, until: float = DURATION) -> List[Event]:
    """15 jobs of kind A per time unit, taking 0.2 to 0.8, and 10 of kind
    B, taking 0.4 to 1.0."""
    rng = random.Random(seed)
    return worker(until, lambda kind, t: STABLE_RATES[kind],
                  lambda kind, t, rng: stable_duration(kind, rng), rng, INITIAL_JOBS)


def unreliable_worker(seed: int = 2, until: float = DURATION) -> List[Event]:
    """The stable worker, with service B overloaded between 60 and 100,
    where 20 jobs of kind B arrive per time unit and take 1.7 on average,
    often more than 2, and nearly idle between 140 and 160, where 3 jobs of
    kind A and 2 of kind B arrive per time unit."""
    rng = random.Random(seed)

    def rate(kind, t):
        if 60 <= t < 100 and kind == 'B':
            return 20.0
        if 140 <= t < 160:
            return STABLE_RATES[kind] / 5
        return STABLE_RATES[kind]

    def duration(kind, t, rng):
        if 60 <= t < 100 and kind == 'B':
            return 0.7 + rng.expovariate(1.0)
        return stable_duration(kind, rng)

    return worker(until, rate, duration, rng, INITIAL_JOBS)


# --------------------------------------------------------------------------
# Monitors
# --------------------------------------------------------------------------

def op_is(op: str) -> Callable[[Event], bool]:
    return lambda e: e.payload['op'] == op


class RunningJobs:
    """The number of jobs running just before each event.

    Called on the events in stream order, it updates the count once per
    event, so that several expressions can ask for it: the count of the
    latest event is kept for the others.
    """

    def __init__(self):
        self.running = 0
        self.last: Optional[Event] = None
        self.before = 0

    def __call__(self, e: Event) -> float:
        if e is not self.last:
            self.last, self.before = e, self.running
            op = e.payload['op']
            self.running += 1 if op == 'START' else -1 if op == 'DONE' else 0
        return float(self.before)


class Worker:
    """The relations and the three properties monitored on one worker, under
    a single InstrumentedMonitor, and the two expressions comparing its
    services; ``consumers`` are fed with its events, in this order."""

    def __init__(self):
        self.previous = PreviousRelation()
        is_start, is_done = op_is('START'), op_is('DONE')
        self.sessions = SessionRelation(
            lambda e: e.payload['session'] if is_start(e) else None,
            lambda e: e.payload['session'] if is_done(e) else None)
        running = RunningJobs()
        # The time of the event related to ``e``, or the time of ``e``.
        previous_time = self.previous.eval(lambda p: p.time, -1.0)
        start_time = self.sessions.eval(lambda s: s.time, -1.0)

        def gap(e):
            """The time since the previous event."""
            t = previous_time(e)
            return 0.0 if t < 0 else e.time - t

        def area(e):
            """Running jobs times the time since the previous event: the
            area under the number of running jobs since then."""
            return running(e) * gap(e)

        def duration(e):
            """The duration of the job a DONE event ends, 0 for the others."""
            t = start_time(e)
            return 0.0 if t < 0 else e.time - t

        def heavy(e):
            """1 for a DONE event ending a heavy job."""
            return float(duration(e) > HEAVY_DURATION)

        def done(e):
            return float(is_done(e))

        def started(kind):
            """1 for a START event of a job of ``kind``."""
            return lambda e: float(is_start(e) and e.payload['type'] == kind)

        def finished(kind):
            """1 for a DONE event ending a job of ``kind``, read on the
            START event of its session."""
            return self.sessions.eval(lambda s: float(s.payload['type'] == kind), 0.0)

        def rate(w):
            """The number of events counted by ``w`` per time unit, over the
            next RATE_WINDOW."""
            return DivisionExpression(SumWindowExpression(w, 0, RATE_WINDOW),
                                      ConstantExpression(RATE_WINDOW))

        def difference(count):
            """The rate of the events of kind A counted by ``count(kind)``
            minus that of kind B."""
            return DifferenceExpression(rate(count('A')), rate(count('B')))

        def ahead(w):
            """The sum of ``w`` over the events of the next AVERAGE_WINDOW."""
            return SumWindowExpression(w, 0, AVERAGE_WINDOW)

        def running_average():
            return DivisionExpression(ahead(area), ahead(gap))

        self.load = GloballyMonitor(
            AndMonitor(AtomicGeqMonitor(running_average(), ConstantExpression(MIN_JOBS)),
                       AtomicLeqMonitor(running_average(), ConstantExpression(MAX_JOBS))),
            Interval(0, 10, right_open=False))
        self.completion = GloballyMonitor(
            AtomicLessMonitor(DivisionExpression(ahead(duration), ahead(done)),
                              ConstantExpression(MST_THRESHOLD)),
            Interval(0, 50, right_open=False))
        self.heavy = AtomicLessMonitor(SumWindowExpression(heavy, 0, 50),
                                       ConstantExpression(HEAVY_JOBS))

        # Named, so that the formulas of the nodes read well.
        def start(e):
            return is_start(e)

        def any_event(e):
            return True

        finished_b = finished('B')

        def b_done(e):
            """A DONE event ending a job of kind B."""
            return finished_b(e) == 1.0

        def quick(e):
            """A DONE event ending a job that was not heavy."""
            return duration(e) <= HEAVY_DURATION

        def over():
            return AtomicGreaterMonitor(running_average(), ConstantExpression(MAX_JOBS))

        def not_idle():
            return AtomicGeqMonitor(running_average(), ConstantExpression(MIN_JOBS))

        def in_range():
            return AndMonitor(not_idle(), AtomicLeqMonitor(running_average(),
                                                           ConstantExpression(MAX_JOBS)))

        self.next_job = FilterMonitor(start, NextMonitor(any_event, 0, MAX_IDLE, TrueMonitor()))
        self.b_service = FilterMonitor(b_done, NextMonitor(quick, 0, B_RESPONSE, TrueMonitor()))
        self.recovery = ImplyMonitor(
            over(),
            UntilMonitor(not_idle(), in_range(), Interval(0, RECOVERY, right_open=False)))

        self.monitor = InstrumentedMonitor(
            [self.previous, self.sessions],
            AndMonitor(AndMonitor(AndMonitor(self.load, self.completion), self.heavy),
                       AndMonitor(AndMonitor(self.next_job, self.b_service), self.recovery)))
        self.properties = {'load': self.load, 'completion': self.completion,
                           'heavy': self.heavy, 'next job': self.next_job,
                           'B service': self.b_service, 'recovery': self.recovery}
        self.measures: Dict[str, StreamExpression] = {
            'arrivals': difference(started), 'throughput': difference(finished)}
        # The monitor first: it updates the relations the measures read.
        self.consumers = [self.monitor, *self.measures.values()]

    def plotted(self) -> Dict[FormulaNode, str]:
        """The nodes to plot, each with its title: the measures comparing the
        services, then every property after the signal it checks, reached in
        the built monitors."""
        return {
            self.measures['arrivals']: f'Arrival rate A - B, next {RATE_WINDOW:g}',
            self.measures['throughput']: f'Throughput A - B, next {RATE_WINDOW:g}',
            self.load.node(0, 0, 0): f'Average running jobs, next {AVERAGE_WINDOW:g}',
            self.load: f'load: in [{MIN_JOBS:g}, {MAX_JOBS:g}] for the next 10',
            self.completion.node(0, 0): f'Average completion time, next {AVERAGE_WINDOW:g}',
            self.completion: f'completion: below {MST_THRESHOLD:g} for the next 50',
            self.heavy.node(0): f'Jobs over {HEAVY_DURATION:g} ending in the next 50',
            self.heavy: f'heavy: fewer than {HEAVY_JOBS:g} in the next 50',
            self.next_job: f'next job: the next job starts within {MAX_IDLE:g}',
            self.b_service: f'B service: the next B job ends within {B_RESPONSE:g}, '
                            f'not heavy',
            self.recovery: f'recovery: from over {MAX_JOBS:g} running, back in range '
                           f'within {RECOVERY:g}',
        }


class Range(SignalConsumer):
    """The least and the greatest value of a piecewise-constant signal."""

    def __init__(self):
        self.low = self.high = None

    def consume(self, s: Segment) -> None:
        value = s.polynomial.evaluate(s.interval.start)
        if self.low is None:
            self.low = self.high = value
        self.low, self.high = min(self.low, value), max(self.high, value)


class Violations(BooleanSignalConsumer):
    """Collects the signal of a property, to report where it is false."""

    def __init__(self):
        self.signal = BooleanSignal()

    def consume(self, i: Interval) -> None:
        self.signal.add(i)

    def set_horizon(self, t: float) -> None:
        self.signal.set_horizon(t)

    def intervals(self) -> List[Interval]:
        """Where the property is known to be false."""
        return list(self.signal.complement())


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

SCENARIOS = {'stable': stable_worker, 'unreliable': unreliable_worker}


def summary(violations: List[Interval]) -> str:
    """Where a property is violated: the intervals, if they are few, or
    how many there are, how long they last in all, and the stretch they
    cover."""
    if not violations:
        return 'holds'
    if len(violations) <= 3:
        return 'violated on ' + ' '.join(f'[{i.start:.1f}, {i.end:.1f})' for i in violations)
    total = sum(i.end - i.start for i in violations)
    return (f'violated {len(violations)} times, {total:.1f} time units in all, '
            f'between {violations[0].start:.1f} and {violations[-1].end:.1f}')


def main(plot: bool = False, quiet: bool = False, until: float = DURATION):
    workers = {name: Worker() for name in SCENARIOS}
    violations = {name: {p: Violations() for p in w.properties}
                  for name, w in workers.items()}
    ranges = {name: {m: Range() for m in w.measures} for name, w in workers.items()}
    for name, w in workers.items():
        for p, monitor in w.properties.items():
            monitor.add(violations[name][p])
        for m, expression in w.measures.items():
            expression.add(ranges[name][m])

    plotters = {}
    if plot:
        import matplotlib.pyplot as plt

        rows = len(workers['stable'].plotted())
        figure, grid = plt.subplots(rows, len(workers), sharex=True,
                                    figsize=(14, 1.9 * rows + 0.6), squeeze=False)
        figure.suptitle('Performance of a worker: stable (left) and unreliable (right)',
                        x=0.01, ha='left', fontsize=13)
        figure.set_layout_engine('constrained')
        for column, (name, w) in enumerate(workers.items()):
            titles = w.plotted()
            plotters[name] = plot_nodes(w.monitor, nodes=list(titles), axes=grid[:, column],
                                  titles={n: f'{name} - {t}' for n, t in titles.items()})
        for column in range(len(workers)):
            grid[2, column].axhspan(MIN_JOBS, MAX_JOBS, color='#2a78d6', alpha=0.08)
            for row, level in ((0, 0.0), (1, 0.0), (4, MST_THRESHOLD), (6, HEAVY_JOBS)):
                grid[row, column].axhline(level, color='#898781', linewidth=1,
                                          linestyle=(0, (4, 3)))

    for name, generate in SCENARIOS.items():
        events = generate(until=until)
        if not quiet:
            print(f'{name}: {len(events)} events')
        feed(workers[name].consumers, events)

    result = {name: {p: v.intervals() for p, v in vs.items()}
              for name, vs in violations.items()}
    for name, rs in ranges.items():
        result[name].update({m: (r.low, r.high) for m, r in rs.items()})
    if not quiet:
        for name, properties in result.items():
            print(f'{name}:')
            for p in workers[name].measures:
                low, high = properties[p]
                print(f'  {p:10} A - B between {low:6.2f} and {high:6.2f} jobs per time unit')
            for p in workers[name].properties:
                print(f'  {p:10} {summary(properties[p])}')

    if plot:
        # The same scale in both columns, for the signals.
        for row in (0, 1, 2, 4, 6):
            axes = grid[row]
            low = min(ax.get_ylim()[0] for ax in axes)
            high = max(ax.get_ylim()[1] for ax in axes)
            for ax in axes:
                ax.set_ylim(low, high)
        show()
    return result


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)

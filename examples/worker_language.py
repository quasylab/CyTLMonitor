"""
Worker performance, with the properties written in the specification language.

``worker.mon``, next to this script, states in words the properties and the
measures that ``worker_performance.py`` builds operator by operator:

    properties
      load       : throughout the next 10, load_avg is between MIN_JOBS and MAX_JOBS
      next_job   : considering only start events,
                   the next event comes within MAX_IDLE
      recovery   : whenever load_avg > MAX_JOBS,
                   load_avg >= MIN_JOBS until, within RECOVERY,
                   load_avg is between MIN_JOBS and MAX_JOBS
      ...

The file is loaded once per scenario, since a specification holds the state
of its monitors, and fed with the events of the stable and of the unreliable
worker of ``worker_performance.py``. The results are the same as there.
``load`` takes ``constants`` to change some constants of the file without
editing it.

Shows: ``load``, ``Specification.run``, consumers attached to the properties
and measures of a specification by name, ``Specification.plot``.

Run with ``python examples/worker_language.py`` (add ``--plot`` to compare
the two scenarios).
"""

from pathlib import Path
from typing import Dict, Mapping, Optional

from _traffic import arguments, show
from worker_performance import DURATION, SCENARIOS, Range, Violations, summary
from cytlmonitor import Specification, load

SPECIFICATION = Path(__file__).resolve().parent / 'worker.mon'


def specification(constants: Optional[Mapping[str, float]] = None) -> Specification:
    """The properties and measures of ``worker.mon``."""
    return load(SPECIFICATION, constants)


def main(plot: bool = False, quiet: bool = False, until: float = DURATION,
         constants: Optional[Mapping[str, float]] = None) -> Dict[str, dict]:
    specs = {name: specification(constants) for name in SCENARIOS}
    violations = {name: {p: Violations() for p in spec.properties}
                  for name, spec in specs.items()}
    ranges = {name: {m: Range() for m in spec.measures} for name, spec in specs.items()}
    for name, spec in specs.items():
        for p, monitor in spec.properties.items():
            monitor.add(violations[name][p])
        for m, expression in spec.measures.items():
            expression.add(ranges[name][m])

    if plot:
        import matplotlib.pyplot as plt

        rows = len(specs['stable'].show)
        figure, grid = plt.subplots(rows, len(specs), sharex=True,
                                    figsize=(14, 1.9 * rows + 0.6), squeeze=False)
        figure.suptitle('worker.mon: stable (left) and unreliable (right)',
                        x=0.01, ha='left', fontsize=13)
        figure.set_layout_engine('constrained')
        for column, (name, spec) in enumerate(specs.items()):
            spec.plot(axes=grid[:, column],
                      titles={n: f'{name} - {n}' for n in spec.show})

    for name, generate in SCENARIOS.items():
        events = generate(until=until)
        if not quiet:
            print(f'{name}: {len(events)} events')
        specs[name].run(events)

    result = {name: {p: v.intervals() for p, v in vs.items()}
              for name, vs in violations.items()}
    for name, rs in ranges.items():
        result[name].update({m: (r.low, r.high) for m, r in rs.items()})
    if not quiet:
        for name, spec in specs.items():
            print(f'{name}:')
            for m in ('arrivals', 'throughput'):
                low, high = result[name][m]
                print(f'  {m:15} A - B between {low:6.2f} and {high:6.2f} jobs per time unit')
            for p in spec.properties:
                print(f'  {p:15} {summary(result[name][p])}')
    if plot:
        show()
    return result


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)

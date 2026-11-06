"""CyTLMonitor: online monitoring of temporal properties over event streams.

The library is organised in subpackages:

* :mod:`cytlmonitor.core`        -- intervals, polynomials, segments and signals;
* :mod:`cytlmonitor.events`      -- events, event sequences and stream plumbing;
* :mod:`cytlmonitor.consumers`   -- signal consumers (plotting in ``consumers.plot``);
* :mod:`cytlmonitor.expressions` -- online quantitative expressions;
* :mod:`cytlmonitor.monitors`    -- online boolean monitors;
* :mod:`cytlmonitor.offline`     -- offline evaluation over an event sequence.

Every public class is also re-exported here.
"""

from cytlmonitor.consumers import BooleanSignalConsumer, SignalConsumer
from cytlmonitor.consumers.plot import PlotBooleanSignalConsumer, PlotSignalConsumer
from cytlmonitor.core import BooleanSignal, Interval, Polynomial, Segment, Signal
from cytlmonitor.events import (
    Event,
    EventConsumer,
    EventProcessor,
    EventRelation,
    EventSequence,
    NextRelation,
    Payload,
    PreviousRelation,
)
from cytlmonitor.expressions import (
    AbsExpression,
    ConstantExpression,
    DifferenceExpression,
    DivisionExpression,
    MaxWindowExpression,
    MinWindowExpression,
    NegationExpression,
    ProductExpression,
    ShiftExpression,
    StreamExpression,
    SumExpression,
    SumWindowExpression,
)
from cytlmonitor.monitors import (
    AndMonitor,
    AtomicGeqMonitor,
    AtomicGreaterMonitor,
    AtomicLeqMonitor,
    AtomicLessMonitor,
    EventMonitor,
    EventuallyMonitor,
    FalseMonitor,
    GloballyMonitor,
    ImplyMonitor,
    NotMonitor,
    OrMonitor,
    SinceMonitor,
    TrueMonitor,
    UntilMonitor,
)
from cytlmonitor.offline import Measure, SignalExpression

__all__ = [
    'Interval', 'Polynomial', 'Segment', 'Signal', 'Payload', 'Event', 'EventSequence',
    'EventConsumer', 'EventProcessor', 'EventRelation', 'PreviousRelation',
    'NextRelation', 'SignalConsumer', 'PlotSignalConsumer', 'BooleanSignalConsumer',
    'PlotBooleanSignalConsumer', 'EventMonitor', 'TrueMonitor', 'FalseMonitor',
    'AndMonitor', 'OrMonitor', 'NotMonitor', 'ImplyMonitor', 'AtomicLeqMonitor',
    'AtomicLessMonitor', 'AtomicGeqMonitor', 'AtomicGreaterMonitor',
    'EventuallyMonitor', 'GloballyMonitor', 'UntilMonitor', 'SinceMonitor',
    'StreamExpression', 'ConstantExpression', 'SumExpression', 'ProductExpression',
    'DifferenceExpression', 'DivisionExpression', 'NegationExpression', 'AbsExpression',
    'ShiftExpression', 'SumWindowExpression', 'MaxWindowExpression',
    'MinWindowExpression', 'BooleanSignal', 'Measure', 'SignalExpression',
]

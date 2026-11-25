"""CyTLMonitor: online monitoring of temporal properties over event streams.

The library is organised in subpackages:

* :mod:`cytlmonitor.core`        -- intervals, polynomials, segments and signals;
* :mod:`cytlmonitor.events`      -- events, event sequences and stream plumbing;
* :mod:`cytlmonitor.consumers`   -- signal consumers (plotting in ``consumers.plot``);
* :mod:`cytlmonitor.expressions` -- online quantitative expressions;
* :mod:`cytlmonitor.monitors`    -- online boolean monitors;
* :mod:`cytlmonitor.offline`     -- offline evaluation over an event sequence;
* :mod:`cytlmonitor.io`          -- readers of event sequences from JSON and CSV files.

Every public class is also re-exported here.
"""

from cytlmonitor.consumers import BooleanSignalConsumer, SignalConsumer
from cytlmonitor.consumers.plot import PlotBooleanSignalConsumer, PlotSignalConsumer, plot
from cytlmonitor.core import BooleanSignal, Interval, Polynomial, Segment, Signal
from cytlmonitor.core.node import FormulaNode
from cytlmonitor.events import (
    Event,
    EventConsumer,
    EventProcessor,
    EventRelation,
    EventSequence,
    Payload,
    PreviousRelation,
    SessionRelation,
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
    FilterMonitor,
    InstrumentedMonitor,
    GloballyMonitor,
    ImplyMonitor,
    NextMonitor,
    NotMonitor,
    OrMonitor,
    SinceMonitor,
    TrueMonitor,
    UntilMonitor,
)
from cytlmonitor.io import CsvEventReader, EventFormatError, EventReader, JsonEventReader
from cytlmonitor.offline import Measure, SignalExpression

__all__ = [
    'Interval', 'Polynomial', 'Segment', 'Signal', 'FormulaNode', 'plot', 'Payload', 'Event',
    'EventSequence',
    'EventConsumer', 'EventProcessor', 'EventRelation', 'PreviousRelation',
    'SessionRelation', 'SignalConsumer', 'PlotSignalConsumer', 'BooleanSignalConsumer',
    'PlotBooleanSignalConsumer', 'EventMonitor', 'TrueMonitor', 'FalseMonitor',
    'AndMonitor', 'OrMonitor', 'NotMonitor', 'ImplyMonitor', 'AtomicLeqMonitor',
    'AtomicLessMonitor', 'AtomicGeqMonitor', 'AtomicGreaterMonitor',
    'EventuallyMonitor', 'GloballyMonitor', 'UntilMonitor', 'SinceMonitor',
    'FilterMonitor', 'NextMonitor', 'InstrumentedMonitor', 'StreamExpression',
    'ConstantExpression', 'SumExpression', 'ProductExpression',
    'DifferenceExpression', 'DivisionExpression', 'NegationExpression', 'AbsExpression',
    'ShiftExpression', 'SumWindowExpression', 'MaxWindowExpression',
    'MinWindowExpression', 'BooleanSignal', 'Measure', 'SignalExpression',
    'EventReader', 'JsonEventReader', 'CsvEventReader', 'EventFormatError',
]

"""
cytlmonitor.language
====================
A language to write the properties to monitor in words.

A specification names the events of interest, the links between events,
the values read on each event, the measures computed over time and the
properties that must hold, in sections (see ``docs/language.md``)::

    events
      start : op is "START"
      done  : op is "DONE"

    links
      job : from start to done, matched by session

    values
      duration = time - job.time when done

    measures
      completion = average of duration over done events in the next 5

    properties
      fast : throughout the next 50, completion < 1

:func:`parse` (or :func:`load`, for a file) builds the monitors and the
expressions it describes, as a
:class:`~cytlmonitor.language.specification.Specification`, the consumer to
feed the events to.
"""

from cytlmonitor.language.lexer import SpecificationError
from cytlmonitor.language.parser import RESERVED, load, parse
from cytlmonitor.language.specification import Specification

__all__ = ['parse', 'load', 'Specification', 'SpecificationError', 'RESERVED']

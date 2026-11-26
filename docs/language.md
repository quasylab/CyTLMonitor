# The specification language

`cytlmonitor.language` reads properties written in words, and builds the
monitors and expressions they describe. Use it when you want the properties to
make sense to people who do not work with temporal logics. A specification
reads like this:

```
events
  start : op is "START"
  done  : op is "DONE"

links
  job : from start to done, matched by session

values
  duration = time - job.time, otherwise 0

measures
  completion = average of duration over done events in the next 5

properties
  fast : throughout the next 50, completion < 1
```

`parse` turns the text into a `Specification`, and `load` does the same for a
file. A `Specification` holds one monitor per property and one expression per
measure. Feed it the events, never its monitors directly. For each event, it
first updates the links and the counters, and then passes the event to every
property and every measure.

```python
>>> from cytlmonitor import Event, Payload, parse
>>> spec = parse('''
... events
...   start : op is "START"
...   done  : op is "DONE"
... links
...   job : from start to done, matched by session
... values
...   duration = time - job.time, otherwise 0
... measures
...   completion = average of duration over done events in the next 5
... properties
...   fast : throughout the next 5, completion < 1
... ''')
>>> spec
Specification(properties=['fast'], measures=['completion'])
>>> print(spec['fast'])
G[0,5] ((sum[0,5] duration over done events / sum[0,5] number of done events) < 1)

```

The monitors and the expressions are ordinary nodes, so consumers can be
attached to them before the events are fed:

```python
>>> from cytlmonitor import BooleanSignal, BooleanSignalConsumer
>>> class Collect(BooleanSignalConsumer):
...     def __init__(self):
...         self.signal = BooleanSignal()
...     def consume(self, i):
...         self.signal.add(i)
...     def set_horizon(self, t):
...         pass
>>> fast = Collect()
>>> spec['fast'].add(fast)
>>> events = [Event(t, Payload(p)) for t, p in [
...     (0, {'op': 'START', 'session': 1}), (0.5, {'op': 'DONE', 'session': 1}),
...     (6, {'op': 'START', 'session': 2}), (9, {'op': 'DONE', 'session': 2}),
...     (20, {'op': 'STEP', 'session': 0})]]
>>> spec.run(events)
Specification(properties=['fast'], measures=['completion'])
>>> list(fast.signal)
[(9.0,10.0)]

```

The second job takes 3 time units and ends at 9, so `completion` is 3 on
`[4, 9]`. `fast` looks 5 further ahead, so it fails up to 9 and holds after
that. The last event, at 20, makes it known up to 10, because the property and
the average each look 5 ahead.

Two other functions go with this:

- `spec.plot(*names)` plots some properties and measures, each titled with
  its name. Without names, it plots those of the `show` section, or all of
  them.
- `spec.build(name)` returns a new, independent copy of a node.

`examples/worker.mon` is the whole worker example of
`examples/worker_performance.py` in this language, and
`examples/worker_language.py` runs it.

## Layout

- **Sections.** A specification is made of sections: `constants`, `events`,
  `links`, `values`, `counters`, `measures`, `properties` and `show`. Each
  starts with a line holding its name alone, not indented, with an optional
  `:` after it. The sections can come in any order and can be repeated.
- **Entries.** The lines of a section are indented. Every line indented like
  the first one starts a new entry. A line indented further continues the
  entry above it, so a long property can be spread over several lines.
- **Names.** Each entry gives a name to what it defines, followed by `:` or
  `=`. A name must be defined before it is used. A name can only be defined
  once, and cannot be one of the words of the language (`RESERVED`).
- **Comments.** `#` starts a comment, up to the end of the line.

## Constants

```
constants
  MIN_JOBS = 10    MAX_JOBS = 20
  WINDOW = 2 * 5
```

Constants are numbers, which can be combined with `+ - * /` and parentheses.
`inf` is infinity. Several constants can share a line.

`parse(text, constants={'MAX_JOBS': 30})` replaces the values the
specification gives, without editing the file. The constants defined from
them follow: `WINDOW = 2 * MAX_JOBS` would become 60.

## Events, values and links

These sections are about each event on its own.

### Events

An entry of `events` names a condition on an event:

```
events
  start  : op is "START"
  b_done : op is "DONE" and kind "B"
```

### Values

An entry of `values` names a number, a string or a condition, computed on
each event:

| Written | Is |
| --- | --- |
| `op`, `session`, ... | a field of the payload of the event (any name that is not defined) |
| `field "to"` | the field `to`, whatever its name |
| `time` | the time of the event |
| `3`, `"A"`, `true`, `false`, `none`, `inf` | constants |
| `+ - * /`, parentheses | arithmetic |
| `< <= > >= == !=` | comparisons |
| `x is "A"`, `x is not "A"`, `kind "A"` | equality, inequality, and a short form of equality |
| `x is between 1 and 3`, `is above`, `is below`, `is at least`, `is at most` | comparisons in words |
| `and`, `or`, `not` | conditions |
| `if c then a else b` | a choice |
| `v when c` | `v` on the events satisfying `c`, `none` on the others |
| `v, otherwise d` | `v`, or `d` where `v` is `none` |
| `abs(x)`, `min(x, y)`, `max(x, y)`, and the functions given to `parse` | function calls |
| an event, a value, a counter, a constant | their value on the event |
| `job.time`, `job.kind` | a field of the event linked by `job` (see below) |
| `previous.time`, `previous.x` | a field of the event before |

`none` stands for something unknown, such as a missing field or the linked
event of an event that has none:

- arithmetic with `none` gives `none`;
- a comparison with `none` is false, except `is none`;
- dividing by zero gives `none`.

A condition used as a number counts 1 when it holds, and 0 otherwise.

Python functions can be called by name:
`parse(text, functions={'port_class': f})`.

### Links

A link relates each event to a past one. `from E1 to E2, matched by key`
links each event satisfying `E2` to the latest event satisfying `E1` with the
same `key`, such as the start of the same session:

```
links
  job : from start to done, matched by session
values
  duration = time - job.time, otherwise 0
```

`previous` is always available, and links each event to the one before it.
Links are `SessionRelation`s and a `PreviousRelation`.

### Counters

```
counters
  running : starts at 0, +1 at start, -1 at done
```

A counter starts at a value, 0 if none is given, and changes with each event
that satisfies a condition. The value of a counter at an event includes the
change that event makes.

## Measures

Measures are signals: they have a value at every time, computed from the
events in a window ahead of that time.

| Written | Is |
| --- | --- |
| `sum of v in the next 5` | the sum of `v` over the events in `[t, t + 5]` |
| `sum of v over done events in the next 5` | the same, over the `done` events only |
| `number of done events with kind "B" in the next 5` | how many events of a kind, with a condition |
| `rate of start events over the next 10` | their number divided by the length of the window |
| `average of v over done events in the next 5` | the sum of `v` divided by the number of events (0 if there are none) |
| `time average of running over the next 5` | the average over time of `running`, taken to hold from each event up to the next one |
| `largest of m over the next 5`, `smallest of ...` | the largest and the smallest value of the measure `m` |
| `m delayed by 5`, `m advanced by 5` | `m` 5 time units later, or earlier |
| `+ - * /`, `abs(m)`, parentheses, constants, numbers | arithmetic |

A window is written `in the next d` or `over the next d`, which both mean
`[t, t + d]`, or `between a and b from now`, which means `[t + a, t + b]`. In
an event clause (`done events with ...`), the word before `events` is an event
or any condition. `events` alone means all of them.

A measure used elsewhere is built again at each use, because a node cannot be
shared.

## Properties

Properties are boolean signals. They hold or fail at every time.

| Written | Is |
| --- | --- |
| `m < 3`, `<=`, `>`, `>=` | a comparison of measures |
| `m is between a and b`, `is above`, `is below`, `is at least`, `is at most` | the same, in words |
| `and`, `or`, `not`, `true`, `false`, parentheses | boolean operators |
| `p implies q`, `whenever p, q`, `if p then q` | implication |
| `throughout the next 10, p` | `p` holds at every time of the window |
| `always p` | `p` holds from now on |
| `at some point within the next 10, p`, `eventually within 10, p` | `p` holds at some time of the window (`eventually p`: at some time) |
| `p until, within 20, q` | `q` holds within 20, and `p` holds up to then |
| `p since, within the last 20, q` | `q` held within the last 20, and `p` has held since then |
| `the next event comes within 2` | the next event comes within 2 |
| `... and has duration <= 2` | the next event, in addition, satisfies a condition |
| `..., then p` | `p` holds when the next event comes |
| `considering only start events, p` | `p` evaluated on the `start` events alone |
| the name of a property | that property |

The windows of properties accept these forms:

- ahead of each time: `the next d`, `within d`, `within the next d`, or
  `between a and b from now`;
- behind each time, for `since`: `within the last d`, or `between a and b ago`.

`until` needs a bounded window. The other operators default to `[0, inf)`
when no window is given.

The prefixes, `throughout`, `eventually`, `considering only` and `whenever`,
apply to everything after their comma. `and` binds tighter than `or`, which
binds tighter than `until` and `since`, which bind tighter than `implies`.
Parentheses make the intent clear. In
`the next event comes within 2 and has c`, the condition `c` is a single
comparison, so write `has (a and b)` for more.

`considering only E events` makes the property see only those events. Its
next event, for instance, is the next `E` event. On the whole stream, the next
event after a `START` is often a `STEP`.

## Show

```
show
  all properties, arrivals, throughput
```

This lists what `spec.plot()` plots by default.

## Errors

Mistakes are reported as a `SpecificationError`, with the line and the column
where they are found:

```python
>>> from cytlmonitor import SpecificationError
>>> try:
...     parse('''
... measures
...   rate_a = rate of events over the next 10
... properties
...   busy : rate_b > 3
... ''')
... except SpecificationError as error:
...     print(error)
line 5, column 10: 'rate_b' is not a measure or a constant: did you mean 'rate_a'?
      busy : rate_b > 3
             ^

```

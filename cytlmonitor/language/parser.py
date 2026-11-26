"""
cytlmonitor.language.parser
===========================
Parsing a specification and building its monitors and expressions.

:class:`Parser` reads the entries of a specification (see
:mod:`cytlmonitor.language.lexer`) in order, each by recursive descent, and
builds as it goes:

- the value of each constant;
- a Python function of the event for each event, value and condition;
- an :class:`~cytlmonitor.events.relations.EventRelation` for each link,
  and a :class:`~cytlmonitor.language.specification.Counter` for each
  counter;
- a *builder* for each measure and property: a function returning a new
  :class:`~cytlmonitor.expressions.base.StreamExpression` or
  :class:`~cytlmonitor.monitors.base.EventMonitor` each time it is called.
  A node consumes its events itself, so it cannot be shared: every use of a
  measure or of a property builds new nodes for it.

A name must be defined before it is used. In the values and conditions of
the events, a name that is not defined anywhere is a field of the payload of
the event.

The grammar is described in ``docs/language.md``.
"""

from __future__ import annotations

import difflib
import math
import operator
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.events.relations import EventRelation, PreviousRelation, SessionRelation
from cytlmonitor.expressions.arithmetic import (
    AbsExpression, DifferenceExpression, DivisionExpression, NegationExpression,
    ProductExpression, SumExpression)
from cytlmonitor.expressions.constant import ConstantExpression
from cytlmonitor.expressions.shift import ShiftExpression
from cytlmonitor.expressions.window import (
    MaxWindowExpression, MinWindowExpression, SumWindowExpression)
from cytlmonitor.language.lexer import (
    END, NAME, NUMBER, STRING, SpecificationError, Token, entries, source_line, span)
from cytlmonitor.language.specification import Counter, Holding, Specification
from cytlmonitor.monitors.atomic import (
    AtomicGeqMonitor, AtomicGreaterMonitor, AtomicLeqMonitor, AtomicLessMonitor)
from cytlmonitor.monitors.boolean import AndMonitor, ImplyMonitor, NotMonitor, OrMonitor
from cytlmonitor.monitors.constants import FalseMonitor, TrueMonitor
from cytlmonitor.monitors.filter import FilterMonitor
from cytlmonitor.monitors.next import NextMonitor
from cytlmonitor.monitors.temporal import (
    EventuallyMonitor, GloballyMonitor, SinceMonitor, UntilMonitor)

# The words of the language: they cannot name anything.
RESERVED = frozenset('''
    abs ago all always and arrives at average below between by comes considering
    delayed advanced else event events eventually false field from has if implies in
    inf largest last least matched maximum measures minimum most next none not now
    number of only or otherwise over point previous properties rate satisfies since
    smallest some starts sum the then throughout time to true until when whenever
    with within above is
'''.split())

# Functions of the event: the values and conditions.
Fn = Callable[[Event], Any]

_COMPARISONS = {'<': operator.lt, '<=': operator.le, '>': operator.gt, '>=': operator.ge,
                '==': operator.eq, '!=': operator.ne}
_MONITORS = {'<': AtomicLessMonitor, '<=': AtomicLeqMonitor, '>': AtomicGreaterMonitor,
             '>=': AtomicGeqMonitor}
_WORD_COMPARISONS = {'above': '>', 'below': '<'}


def _builtin_min(*args):
    return min(args)


def _builtin_max(*args):
    return max(args)


BUILTINS: Dict[str, Callable] = {'abs': abs, 'min': _builtin_min, 'max': _builtin_max}


def _named(f: Callable, name: str) -> Callable:
    f.__name__ = name
    return f


def _interval(a: float, b: float) -> Interval:
    """The closed interval [a, b], right unbounded if b is infinite."""
    return Interval(a) if math.isinf(b) else Interval(a, b, right_open=False)


class _Symbol:
    __slots__ = ('kind', 'value', 'token')

    def __init__(self, kind: str, value: Any, token: Token):
        self.kind, self.value, self.token = kind, value, token


_KINDS = {'constant': 'a constant', 'event': 'an event', 'link': 'a link',
          'value': 'a value', 'counter': 'a counter', 'measure': 'a measure',
          'property': 'a property', 'function': 'a function'}


class Parser:
    """Parser of a specification: :meth:`parse` returns its
    :class:`~cytlmonitor.language.specification.Specification`.

    - ``constants`` replace the values of some constants of the
      specification, which must define them;
    - ``functions`` are Python functions the values can call by name.
    """

    def __init__(self, source: str, constants: Optional[Mapping[str, float]] = None,
                 functions: Optional[Mapping[str, Callable]] = None):
        self.source = source
        self.overrides = {name: float(v) for name, v in (constants or {}).items()}
        self.symbols: Dict[str, _Symbol] = {}
        self.declared: Dict[str, Token] = {}
        for name, f in (functions or {}).items():
            if not callable(f):
                raise TypeError(f"function {name!r} is not callable")
            self._check_name(name, None)
            self.symbols[name] = _Symbol('function', f, None)
        self.constants: Dict[str, float] = {}
        self.properties: Dict[str, Callable] = {}
        self.measures: Dict[str, Callable] = {}
        self.show: List[str] = []
        self.relations: List[EventRelation] = []
        self.updaters: List[Callable[[Event], None]] = []
        self.previous: Optional[PreviousRelation] = None
        self.tokens: List[Token] = []
        self.pos = 0

    # ------------------------------------------------------------------
    # Tokens
    # ------------------------------------------------------------------

    def peek(self, k: int = 0) -> Token:
        return self.tokens[min(self.pos + k, len(self.tokens) - 1)]

    def advance(self) -> Token:
        token = self.tokens[self.pos]
        if token.kind != END:
            self.pos += 1
        return token

    @property
    def last(self) -> Token:
        """The last token consumed."""
        return self.tokens[max(self.pos - 1, 0)]

    def at(self, *words: str) -> bool:
        return self.peek().is_word(*words)

    def at_symbol(self, *symbols: str) -> bool:
        return self.peek().is_symbol(*symbols)

    def accept(self, *words: str) -> bool:
        if self.at(*words):
            self.advance()
            return True
        return False

    def accept_symbol(self, *symbols: str) -> bool:
        if self.at_symbol(*symbols):
            self.advance()
            return True
        return False

    def expect(self, *words: str) -> Token:
        if not self.at(*words):
            self.fail(f"expected {self._alternatives(words)}, found {self.peek().describe()}")
        return self.advance()

    def expect_symbol(self, *symbols: str) -> Token:
        if not self.at_symbol(*symbols):
            self.fail(f"expected {self._alternatives(symbols)}, found {self.peek().describe()}")
        return self.advance()

    @staticmethod
    def _alternatives(options) -> str:
        quoted = [f"'{o}'" for o in options]
        return quoted[0] if len(quoted) == 1 else ', '.join(quoted[:-1]) + ' or ' + quoted[-1]

    def fail(self, message: str, token: Optional[Token] = None):
        token = token or self.peek()
        raise SpecificationError(message, token.line, token.column,
                                 source_line(self.source, token.line))

    def text(self, first: Token) -> str:
        """The source from ``first`` to the last token consumed."""
        return span(self.source, first, self.last)

    def mark(self) -> Tuple[int, int]:
        return self.pos, len(self.updaters)

    def reset(self, mark: Tuple[int, int]) -> None:
        self.pos = mark[0]
        del self.updaters[mark[1]:]

    # ------------------------------------------------------------------
    # Names
    # ------------------------------------------------------------------

    def _check_name(self, name: str, token: Optional[Token]) -> None:
        if name in RESERVED:
            message = f"'{name}' is a word of the language: choose another name"
            if token is None:
                raise SpecificationError(message)
            self.fail(message, token)

    def define(self, token: Token, kind: str, value: Any) -> None:
        name = token.value
        previous = self.symbols.get(name)
        if previous is not None:
            where = f' at line {previous.token.line}' if previous.token else ''
            self.fail(f"'{name}' is already defined{where}", token)
        self.symbols[name] = _Symbol(kind, value, token)

    def lookup(self, token: Token) -> Optional[_Symbol]:
        """The symbol named by ``token``; an error if it is only defined
        later."""
        symbol = self.symbols.get(token.value)
        if symbol is None and token.value in self.declared:
            declared = self.declared[token.value]
            self.fail(f"'{token.value}' is defined later, at line {declared.line}: "
                      f"define it before using it", token)
        return symbol

    def unknown(self, token: Token, expected: str):
        names = [n for n, s in self.symbols.items() if s.kind in expected.split('|')]
        close = difflib.get_close_matches(token.value, names, n=1)
        hint = f": did you mean '{close[0]}'?" if close else ''
        kinds = ' or '.join(_KINDS[k] for k in expected.split('|'))
        self.fail(f"'{token.value}' is not {kinds}{hint}", token)

    def _declare(self, entry_section: str, tokens: List[Token]) -> None:
        """Record the names an entry defines, so that using them before
        they are defined is reported as such."""
        if entry_section == 'show':
            return
        candidates = []
        if entry_section == 'constants':
            candidates = [t for t, nxt in zip(tokens, tokens[1:])
                          if t.kind == NAME and nxt.is_symbol('=', ':')]
        elif tokens[0].kind == NAME and tokens[1].is_symbol('=', ':'):
            candidates = [tokens[0]]
        for t in candidates:
            self.declared.setdefault(t.value, t)

    def new_name(self) -> Token:
        token = self.peek()
        if token.kind != NAME:
            self.fail(f"expected a name, found {token.describe()}")
        self._check_name(token.value, token)
        self.advance()
        if not self.accept_symbol(':', '='):
            self.fail(f"expected ':' or '=' after the name '{token.value}', "
                      f"found {self.peek().describe()}")
        return token

    def expect_end(self) -> None:
        if self.peek().kind != END:
            self.fail(f"unexpected {self.peek().describe()}")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def parse(self) -> Specification:
        items = entries(self.source)
        for entry in items:
            self._declare(entry.section, entry.tokens)
        for entry in items:
            self.tokens, self.pos = entry.tokens, 0
            getattr(self, f'_entry_{entry.section}')()
        unknown = set(self.overrides) - set(self.constants)
        if unknown:
            raise SpecificationError(
                'no constant named ' + ', '.join(sorted(repr(n) for n in unknown)))
        relations = ([self.previous] if self.previous else []) + self.relations
        try:
            return Specification(self.constants, self.properties, self.measures, self.show,
                                 relations, self.updaters)
        except (TypeError, ValueError) as error:
            raise SpecificationError(str(error)) from error

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _entry_constants(self) -> None:
        while self.peek().kind != END:
            token = self.new_name()
            value = self.number()
            value = self.overrides.get(token.value, value)
            self.define(token, 'constant', value)
            self.constants[token.value] = value
            self.accept_symbol(',')

    def _entry_events(self) -> None:
        token = self.new_name()
        condition = self.condition_expression()
        self.expect_end()
        self.define(token, 'event', _named(lambda e: bool(condition(e)), token.value))

    def _entry_values(self) -> None:
        token = self.new_name()
        f = self.value_expression()
        self.expect_end()
        self.define(token, 'value', _named(lambda e: f(e), token.value))

    def _entry_links(self) -> None:
        token = self.new_name()
        self.expect('from')
        opens = self.value_or()
        self.expect('to')
        closes = self.value_or()
        self.accept_symbol(',')
        self.expect('matched')
        self.expect('by')
        key = self.value_expression()
        self.expect_end()

        def f_open(e):
            return key(e) if opens(e) else None

        def f_close(e):
            return key(e) if closes(e) else None

        relation = SessionRelation(f_open, f_close)
        self.relations.append(relation)
        self.define(token, 'link', relation)

    def _entry_counters(self) -> None:
        token = self.new_name()
        start = 0.0
        changes = []
        while True:
            if self.accept('starts'):
                self.expect('at')
                start = self.number()
            elif self.at_symbol('+', '-'):
                sign = -1.0 if self.advance().value == '-' else 1.0
                delta = sign * self.number()
                self.expect('at')
                condition = self.value_or()
                changes.append((delta, condition))
            else:
                self.fail(f"expected a change such as '+1 at start', found "
                          f"{self.peek().describe()}")
            if not self.accept_symbol(','):
                break
        self.expect_end()
        counter = Counter(token.value, start, changes)
        self.updaters.append(counter.update)
        self.define(token, 'counter', counter)

    def _entry_measures(self) -> None:
        token = self.new_name()
        build = self.measure()
        self.expect_end()
        self._check_builder(build, token)
        self.define(token, 'measure', build)
        self.measures[token.value] = build

    def _entry_properties(self) -> None:
        token = self.new_name()
        build = self.property()
        self.expect_end()
        self._check_builder(build, token)
        self.define(token, 'property', build)
        self.properties[token.value] = build

    def _check_builder(self, build: Callable, token: Token) -> None:
        try:
            build()
        except (TypeError, ValueError) as error:
            self.fail(f"cannot build '{token.value}': {error}", token)

    def _entry_show(self) -> None:
        while True:
            token = self.peek()
            if self.accept('all'):
                which = self.expect('properties', 'measures').value
                self.show.extend(self.properties if which == 'properties' else self.measures)
            elif token.kind == NAME and (token.value in self.properties
                                         or token.value in self.measures):
                self.advance()
                self.show.append(token.value)
            elif token.kind == NAME:
                symbol = self.lookup(token)
                if symbol is None:
                    self.unknown(token, 'property|measure')
                self.fail(f"'{token.value}' is {_KINDS[symbol.kind]}: only properties "
                          f"and measures can be shown", token)
            else:
                self.fail(f"expected the name of a property or of a measure, found "
                          f"{token.describe()}")
            if not self.accept_symbol(','):
                break
        self.expect_end()

    # ------------------------------------------------------------------
    # Numbers known when parsing: constants, windows, bounds
    # ------------------------------------------------------------------

    def number(self) -> float:
        value = self.number_term()
        while self.at_symbol('+', '-'):
            op = self.advance().value
            other = self.number_term()
            value = value + other if op == '+' else value - other
        return value

    def bound(self) -> float:
        """A number in a window or a shift: a number, a constant, or an
        expression between parentheses, so that a window can be followed by
        an operator, as in 'in the next 10 - ...'."""
        return self.number_factor()

    def number_term(self) -> float:
        value = self.number_factor()
        while self.at_symbol('*', '/'):
            op = self.advance()
            other = self.number_factor()
            if op.value == '/' and other == 0:
                self.fail('division by zero', op)
            value = value * other if op.value == '*' else value / other
        return value

    def number_factor(self) -> float:
        token = self.peek()
        if self.accept_symbol('-'):
            return -self.number_factor()
        if self.accept_symbol('('):
            value = self.number()
            self.expect_symbol(')')
            return value
        if token.kind == NUMBER:
            self.advance()
            return token.value
        if self.accept('inf'):
            return math.inf
        if token.kind == NAME and token.value not in RESERVED:
            symbol = self.lookup(token)
            if symbol is not None and symbol.kind == 'constant':
                self.advance()
                return symbol.value
            if symbol is None:
                self.unknown(token, 'constant')
            self.fail(f"'{token.value}' is {_KINDS[symbol.kind]}: a number or a constant "
                      f"is needed here", token)
        self.fail(f"expected a number or a constant, found {token.describe()}")

    # ------------------------------------------------------------------
    # Values and conditions of the events
    # ------------------------------------------------------------------

    def condition_expression(self) -> Fn:
        return self.value_expression()

    def value_expression(self) -> Fn:
        """value ('when' or | [','] 'otherwise' or)*"""
        first = self.peek()
        f = self.value_or()
        while True:
            if self.accept('when'):
                c = self.value_or()
                f = self._when(f, c)
            elif self.at('otherwise') or (self.at_symbol(',') and self.peek(1).is_word('otherwise')):
                self.accept_symbol(',')
                self.advance()
                d = self.value_or()
                f = self._otherwise(f, d)
            else:
                break
        text = self.text(first)
        if f.__name__ not in ('<lambda>', text):
            # A function defined elsewhere: renaming it would rename it there too.
            g = f
            f = lambda e: g(e)
        return _named(f, text)

    @staticmethod
    def _when(f: Fn, c: Fn) -> Fn:
        return lambda e: f(e) if c(e) else None

    @staticmethod
    def _otherwise(f: Fn, d: Fn) -> Fn:
        def otherwise(e):
            v = f(e)
            return d(e) if v is None else v
        return otherwise

    def value_or(self) -> Fn:
        f = self.value_and()
        while self.accept('or'):
            g = self.value_and()
            f = (lambda a, b: lambda e: bool(a(e)) or bool(b(e)))(f, g)
        return f

    def value_and(self) -> Fn:
        f = self.value_not()
        while self.at('and') and not self.peek(1).is_word('then', 'has', 'satisfies', 'is'):
            self.advance()
            g = self.value_not()
            f = (lambda a, b: lambda e: bool(a(e)) and bool(b(e)))(f, g)
        return f

    def value_not(self) -> Fn:
        if self.accept('not'):
            f = self.value_not()
            return lambda e: not f(e)
        return self.value_comparison()

    def value_comparison(self) -> Fn:
        f = self.value_sum()
        token = self.peek()
        if token.is_symbol(*_COMPARISONS):
            self.advance()
            g = self.value_sum()
            return self._compare(_COMPARISONS[token.value], f, g)
        if self.accept('is'):
            negated = self.accept('not')
            if self.accept('between'):
                low = self.value_sum()
                self.expect('and')
                high = self.value_sum()
                result = self._between(f, low, high)
            elif self.at(*_WORD_COMPARISONS):
                op = _COMPARISONS[_WORD_COMPARISONS[self.advance().value]]
                result = self._compare(op, f, self.value_sum())
            elif self.accept('at'):
                op = operator.ge if self.expect('least', 'most').value == 'least' else operator.le
                result = self._compare(op, f, self.value_sum())
            else:
                g = self.value_sum()
                result = lambda e: f(e) == g(e)
            return (lambda r: lambda e: not r(e))(result) if negated else result
        if token.kind == STRING:
            # ``type "A"`` is ``type is "A"``.
            self.advance()
            value = token.value
            return lambda e: f(e) == value
        return f

    @staticmethod
    def _compare(op, f: Fn, g: Fn) -> Fn:
        def compare(e):
            a, b = f(e), g(e)
            if a is None or b is None:
                return False
            try:
                return op(a, b)
            except TypeError:
                return False
        return compare

    @staticmethod
    def _between(f: Fn, low: Fn, high: Fn) -> Fn:
        def between(e):
            v, a, b = f(e), low(e), high(e)
            if v is None or a is None or b is None:
                return False
            try:
                return a <= v <= b
            except TypeError:
                return False
        return between

    def value_sum(self) -> Fn:
        f = self.value_product()
        while self.at_symbol('+', '-'):
            op = self.advance()
            g = self.value_product()
            f = self._arithmetic(operator.add if op.value == '+' else operator.sub, f, g, op)
        return f

    def value_product(self) -> Fn:
        f = self.value_unary()
        while self.at_symbol('*', '/'):
            op = self.advance()
            g = self.value_unary()
            f = self._arithmetic(operator.mul if op.value == '*' else operator.truediv, f, g, op)
        return f

    def _arithmetic(self, op, f: Fn, g: Fn, token: Token) -> Fn:
        source, line, column = self.source, token.line, token.column

        def compute(e):
            a, b = f(e), g(e)
            if a is None or b is None:
                return None
            try:
                return op(a, b)
            except ZeroDivisionError:
                return None
            except TypeError:
                raise SpecificationError(
                    f"cannot apply '{token.value}' to {a!r} and {b!r}, at {e!r}",
                    line, column, source_line(source, line)) from None
        return compute

    def value_unary(self) -> Fn:
        token = self.peek()
        if self.accept_symbol('-'):
            f = self.value_unary()
            minus = self._arithmetic(operator.sub, lambda e: 0, f, token)
            return minus
        return self.value_primary()

    def value_primary(self) -> Fn:
        token = self.peek()
        if token.kind in (NUMBER, STRING):
            self.advance()
            value = token.value
            return lambda e: value
        if self.accept_symbol('('):
            f = self.value_expression()
            self.expect_symbol(')')
            return f
        if self.accept('true'):
            return lambda e: True
        if self.accept('false'):
            return lambda e: False
        if self.accept('none'):
            return lambda e: None
        if self.accept('inf'):
            return lambda e: math.inf
        if self.accept('time'):
            return lambda e: e.time
        if self.accept('field'):
            name = self.peek()
            if name.kind != STRING:
                self.fail(f"expected the name of a field, as a string, after 'field'")
            self.advance()
            field = name.value
            return lambda e: e.payload.get(field)
        if self.accept('if'):
            c = self.value_or()
            self.accept_symbol(',')
            self.expect('then')
            a = self.value_or()
            self.accept_symbol(',')
            self.expect('else')
            b = self.value_or()
            return lambda e: a(e) if c(e) else b(e)
        if token.is_word('previous') or (token.kind == NAME and self.peek(1).is_symbol('.')):
            return self.value_link()
        if token.kind == NAME and self.peek(1).is_symbol('('):
            return self.value_call()
        if token.kind == NAME and token.value not in RESERVED:
            return self.value_name()
        self.fail(f"expected a value, found {token.describe()}")

    def value_link(self) -> Fn:
        token = self.advance()
        if token.value == 'previous':
            if self.previous is None:
                self.previous = PreviousRelation()
            relation = self.previous
        else:
            symbol = self.lookup(token)
            if symbol is None or symbol.kind != 'link':
                if symbol is None:
                    self.unknown(token, 'link')
                self.fail(f"'{token.value}' is {_KINDS[symbol.kind]}, not a link: "
                          f"'.' reads a field of a linked event", token)
            relation = symbol.value
        self.expect_symbol('.')
        field = self.peek()
        if field.is_word('time'):
            self.advance()
            return lambda e: (lambda r: None if r is None else r.time)(relation.get(e))
        if field.kind in (NAME, STRING):
            self.advance()
            name = field.value
            return lambda e: (lambda r: None if r is None else r.payload.get(name))(relation.get(e))
        self.fail(f"expected a field after '.', found {field.describe()}")

    def value_call(self) -> Fn:
        token = self.advance()
        symbol = self.lookup(token)
        if symbol is not None and symbol.kind == 'function':
            function = symbol.value
        elif symbol is None and token.value in BUILTINS:
            function = BUILTINS[token.value]
        else:
            if symbol is None:
                self.unknown(token, 'function')
            self.fail(f"'{token.value}' is {_KINDS[symbol.kind]}, not a function", token)
        self.expect_symbol('(')
        arguments = []
        if not self.at_symbol(')'):
            arguments.append(self.value_expression())
            while self.accept_symbol(','):
                arguments.append(self.value_expression())
        self.expect_symbol(')')
        source, line, column = self.source, token.line, token.column

        def call(e):
            values = [a(e) for a in arguments]
            if any(v is None for v in values):
                return None
            try:
                return function(*values)
            except Exception as error:
                raise SpecificationError(f"'{token.value}' failed at {e!r}: {error}",
                                         line, column, source_line(source, line)) from error
        return call

    def value_name(self) -> Fn:
        token = self.advance()
        symbol = self.lookup(token)
        if symbol is None:
            field = token.value
            return lambda e: e.payload.get(field)
        kind, value = symbol.kind, symbol.value
        if kind == 'constant':
            return lambda e: value
        if kind in ('event', 'value'):
            return value
        if kind == 'counter':
            return lambda e: value.value
        if kind == 'link':
            self.fail(f"'{token.value}' is a link: read a field of the linked event, "
                      f"as in '{token.value}.time'", token)
        if kind in ('measure', 'property'):
            self.fail(f"'{token.value}' is {_KINDS[kind]}, a signal over time: here a value "
                      f"of each event is needed", token)
        self.fail(f"'{token.value}' is {_KINDS[kind]}: call it, as in '{token.value}(...)'",
                  token)

    def events(self) -> Fn:
        """[condition] 'events' ['with' condition]: the events satisfying
        both conditions."""
        first = self.peek()
        if self.accept('all'):
            self.expect('events', 'event')
            selected = None
        elif self.accept('events', 'event'):
            selected = None
        else:
            selected = self.value_or()
            self.expect('events', 'event')
        if self.accept('with'):
            extra = self.value_or()
            if selected is None:
                selected = extra
            else:
                selected = (lambda a, b: lambda e: bool(a(e)) and bool(b(e)))(selected, extra)
        if selected is None:
            selected = lambda e: True
        f = selected
        return _named(lambda e: bool(f(e)), self.text(first))

    # ------------------------------------------------------------------
    # Measures: signals over time
    # ------------------------------------------------------------------

    def measure(self) -> Callable:
        build = self.measure_product()
        while self.at_symbol('+', '-'):
            kind = SumExpression if self.advance().value == '+' else DifferenceExpression
            other = self.measure_product()
            build = (lambda k, a, b: lambda: k(a(), b()))(kind, build, other)
        return build

    def measure_product(self) -> Callable:
        build = self.measure_unary()
        while self.at_symbol('*', '/'):
            kind = ProductExpression if self.advance().value == '*' else DivisionExpression
            other = self.measure_unary()
            build = (lambda k, a, b: lambda: k(a(), b()))(kind, build, other)
        return build

    def measure_unary(self) -> Callable:
        if self.accept_symbol('-'):
            build = self.measure_unary()
            return lambda: NegationExpression(build())
        build = self.measure_primary()
        while self.at('delayed', 'advanced'):
            sign = 1.0 if self.advance().value == 'delayed' else -1.0
            self.expect('by')
            t = sign * self.bound()
            build = (lambda b, d: lambda: ShiftExpression(b(), d))(build, t)
        return build

    def window(self) -> Tuple[float, float]:
        """'in'|'over' 'the' 'next' d, or 'between' a 'and' b ['from' 'now']:
        the window [a, b] of a measure, ahead of each time."""
        first = self.peek()
        if self.accept('in', 'over', 'within'):
            if self.accept('the'):
                self.expect('next')
                a, b = 0.0, self.bound()
            else:
                self.expect('between')
                a, b = self.between()
        elif self.accept('between'):
            a, b = self.between()
        else:
            self.fail(f"expected a window, such as 'in the next 10', found "
                      f"{self.peek().describe()}")
        if not 0 <= a < b or math.isinf(b):
            self.fail(f"a window of a measure must go from a time to a later one, both "
                      f"finite and not negative: got [{a:g}, {b:g}]", first)
        return a, b

    def between(self) -> Tuple[float, float]:
        a = self.bound()
        self.expect('and')
        b = self.bound()
        if self.accept('from'):
            self.expect('now')
        return a, b

    def measure_primary(self) -> Callable:
        token = self.peek()
        if token.kind == NUMBER or token.is_word('inf'):
            value = self.number_factor()
            return lambda: ConstantExpression(value)
        if self.accept_symbol('('):
            build = self.measure()
            self.expect_symbol(')')
            return build
        if token.is_word('abs') and self.peek(1).is_symbol('('):
            self.advance()
            self.expect_symbol('(')
            build = self.measure()
            self.expect_symbol(')')
            return lambda: AbsExpression(build())
        if self.accept('sum'):
            self.expect('of')
            weight = self._weight(self.value_expression())
            selected = self._events_over()
            a, b = self.window()
            w = self._select(weight, selected)
            return lambda: SumWindowExpression(w, a, b)
        if self.accept('number'):
            self.expect('of')
            selected = self.events()
            a, b = self.window()
            w = _named(lambda e: 1.0 if selected(e) else 0.0, selected.__name__)
            return lambda: SumWindowExpression(w, a, b)
        if self.accept('rate'):
            self.expect('of')
            selected = self.events()
            a, b = self.window()
            w = _named(lambda e: 1.0 if selected(e) else 0.0, selected.__name__)
            return lambda: DivisionExpression(SumWindowExpression(w, a, b),
                                              ConstantExpression(b - a))
        if self.accept('average'):
            self.expect('of')
            return self._average()
        if token.is_word('time') and self.peek(1).is_word('average'):
            self.advance()
            self.advance()
            self.expect('of')
            return self._time_average()
        if self.accept('largest', 'maximum', 'smallest', 'minimum'):
            kind = MaxWindowExpression if token.value in ('largest', 'maximum') \
                else MinWindowExpression
            self.expect('of')
            build = self.measure_unary()
            a, b = self.window()
            return lambda: kind(build(), a, b)
        if token.kind == NAME and token.value not in RESERVED:
            self.advance()
            symbol = self.lookup(token)
            if symbol is None:
                self.unknown(token, 'measure|constant')
            if symbol.kind == 'constant':
                value = symbol.value
                return lambda: ConstantExpression(value)
            if symbol.kind == 'measure':
                return symbol.value
            if symbol.kind in ('value', 'counter', 'event'):
                self.fail(f"'{token.value}' is {_KINDS[symbol.kind]} of each event, not a "
                          f"signal over time: use it in 'sum of', 'average of' or "
                          f"'time average of'", token)
            self.fail(f"'{token.value}' is {_KINDS[symbol.kind]}: a measure is needed here",
                      token)
        self.fail(f"expected a measure, found {token.describe()}")

    def _events_over(self) -> Optional[Fn]:
        """['over' events]: the events a sum or an average is taken over,
        when given."""
        if self.at('over') and not self.peek(1).is_word('the', 'between'):
            self.advance()
            return self.events()
        return None

    def _weight(self, value: Fn) -> Fn:
        """``value`` as a number: 0 for none, 1 and 0 for true and false."""
        def weight(e):
            v = value(e)
            if v is None:
                return 0.0
            try:
                return float(v)
            except (TypeError, ValueError):
                raise SpecificationError(f"'{value.__name__}' is {v!r} at {e!r}: a number "
                                         f"is needed") from None
        return _named(weight, value.__name__)

    @staticmethod
    def _select(weight: Fn, selected: Optional[Fn]) -> Fn:
        if selected is None:
            return weight
        return _named(lambda e: weight(e) if selected(e) else 0.0,
                      f'{weight.__name__} over {selected.__name__}')

    def _average(self) -> Callable:
        value = self.value_expression()
        selected = self._events_over() or _named(lambda e: True, 'events')
        a, b = self.window()
        weight = self._weight(value)

        def total(e):
            return weight(e) if selected(e) else 0.0

        def count(e):
            return 1.0 if selected(e) and value(e) is not None else 0.0

        _named(total, f'{value.__name__} over {selected.__name__}')
        _named(count, f'number of {selected.__name__}')
        return lambda: DivisionExpression(SumWindowExpression(total, a, b),
                                          SumWindowExpression(count, a, b))

    def _time_average(self) -> Callable:
        value = self._weight_or_none(self.value_expression())
        a, b = self.window()
        holding = Holding(value)
        self.updaters.append(holding.update)
        weight = _named(lambda e: holding.weight, f'{value.__name__} * gap')
        gap = _named(lambda e: holding.gap, 'gap')
        return lambda: DivisionExpression(SumWindowExpression(weight, a, b),
                                          SumWindowExpression(gap, a, b))

    @staticmethod
    def _weight_or_none(value: Fn) -> Fn:
        def number(e):
            v = value(e)
            if v is None:
                return None
            try:
                return float(v)
            except (TypeError, ValueError):
                raise SpecificationError(f"'{value.__name__}' is {v!r} at {e!r}: a number "
                                         f"is needed") from None
        return _named(number, value.__name__)

    # ------------------------------------------------------------------
    # Properties: boolean signals over time
    # ------------------------------------------------------------------

    def property(self) -> Callable:
        if self.accept('whenever'):
            premise = self.property_or()
            self.expect_symbol(',')
            conclusion = self.property()
            return lambda: ImplyMonitor(premise(), conclusion())
        if self.accept('if'):
            premise = self.property_or()
            self.accept_symbol(',')
            self.expect('then')
            conclusion = self.property()
            return lambda: ImplyMonitor(premise(), conclusion())
        build = self.property_until()
        if self.accept('implies'):
            conclusion = self.property()
            return (lambda p, c: lambda: ImplyMonitor(p(), c()))(build, conclusion)
        return build

    def property_until(self) -> Callable:
        build = self.property_or()
        if self.accept('until'):
            self.accept_symbol(',')
            first = self.peek()
            a, b = self.future_window(optional=True)
            if math.isinf(b):
                self.fail("'until' needs a bounded window, such as 'until, within 10,'",
                          first)
            self.accept_symbol(',')
            other = self.property_or()
            i = _interval(a, b)
            return lambda: UntilMonitor(build(), other(), i)
        if self.accept('since'):
            self.accept_symbol(',')
            a, b = self.past_window()
            self.accept_symbol(',')
            other = self.property_or()
            i = _interval(a, b)
            return lambda: SinceMonitor(build(), other(), i)
        return build

    def property_or(self) -> Callable:
        build = self.property_and()
        while self.accept('or'):
            other = self.property_and()
            build = (lambda a, b: lambda: OrMonitor(a(), b()))(build, other)
        return build

    def property_and(self) -> Callable:
        build = self.property_not()
        while self.accept('and'):
            other = self.property_not()
            build = (lambda a, b: lambda: AndMonitor(a(), b()))(build, other)
        return build

    def property_not(self) -> Callable:
        if self.accept('not'):
            build = self.property_not()
            return lambda: NotMonitor(build())
        return self.property_prefix()

    def future_window(self, optional: bool = False) -> Tuple[float, float]:
        """A window ahead of each time: 'the next' d, 'within' [the next] d,
        'in the next' d, or 'between' a 'and' b ['from' 'now']. With
        ``optional``, [0, inf) when none is given."""
        first = self.peek()
        if self.accept('within', 'in', 'over'):
            if self.accept('the'):
                self.expect('next')
                a, b = 0.0, self.bound()
            elif first.is_word('within') and not self.at('between'):
                a, b = 0.0, self.bound()
            else:
                self.expect('between')
                a, b = self.between()
        elif self.accept('the'):
            self.expect('next')
            a, b = 0.0, self.bound()
        elif self.accept('between'):
            a, b = self.between()
        elif optional:
            return 0.0, math.inf
        else:
            self.fail(f"expected a window, such as 'the next 10', found "
                      f"{self.peek().describe()}")
        if not 0 <= a <= b:
            self.fail(f"a window must go from a time to a later one, not negative: got "
                      f"[{a:g}, {b:g}]", first)
        return a, b

    def past_window(self) -> Tuple[float, float]:
        """A window behind each time: 'within' ['the' 'last'] d, 'in the
        last' d, or 'between' a 'and' b 'ago'; [0, inf) when none is
        given."""
        first = self.peek()
        if self.accept('within', 'in', 'over'):
            if self.accept('the'):
                self.expect('last')
                a, b = 0.0, self.bound()
            elif first.is_word('within') and not self.at('between'):
                a, b = 0.0, self.bound()
            else:
                self.expect('between')
                a, b = self.bound(), None
                self.expect('and')
                b = self.bound()
                self.expect('ago')
        elif self.accept('the'):
            self.expect('last')
            a, b = 0.0, self.bound()
        elif self.accept('between'):
            a = self.bound()
            self.expect('and')
            b = self.bound()
            self.expect('ago')
        else:
            return 0.0, math.inf
        if not 0 <= a <= b:
            self.fail(f"a window must go from a time to a later one, not negative: got "
                      f"[{a:g}, {b:g}]", first)
        return a, b

    def property_prefix(self) -> Callable:
        if self.accept('throughout'):
            a, b = self.future_window()
            self.accept_symbol(',')
            body = self.property()
            i = _interval(a, b)
            return lambda: GloballyMonitor(body(), i)
        if self.accept('always'):
            self.accept_symbol(',')
            body = self.property()
            return lambda: GloballyMonitor(body(), Interval(0))
        if self.at('eventually') or (self.at('at') and self.peek(1).is_word('some')):
            if self.accept('at'):
                self.expect('some')
                self.expect('point')
            else:
                self.advance()
            a, b = self.future_window(optional=True)
            self.accept_symbol(',')
            body = self.property()
            i = _interval(a, b)
            return lambda: EventuallyMonitor(body(), i)
        if self.accept('considering'):
            self.expect('only')
            selected = self.events()
            self.accept_symbol(',')
            body = self.property()
            return lambda: FilterMonitor(selected, body())
        if (self.at('the') and self.peek(1).is_word('next') and self.peek(2).is_word('event')) \
                or (self.at('next') and self.peek(1).is_word('event')):
            return self.property_next()
        return self.property_atom()

    def property_next(self) -> Callable:
        """['the'] 'next' 'event' ['comes'|'arrives'] window
        ['and' ('has'|'is'|'satisfies') condition] [[','|'and'] 'then' property]"""
        first = self.peek()
        self.accept('the')
        self.expect('next')
        self.expect('event')
        self.accept('comes', 'arrives')
        if self.accept('within'):
            self.accept('the') and self.expect('next')
            a, b = 0.0, self.bound()
        elif self.accept('between'):
            a, b = self.between()
        else:
            self.fail(f"expected when the next event comes, such as 'within 5', found "
                      f"{self.peek().describe()}")
        if not 0 <= a < b:
            self.fail(f"the next event must be expected from a time to a later one, not "
                      f"negative: got [{a:g}, {b:g}]", first)
        condition: Fn = _named(lambda e: True, 'any')
        if self.at('and') and self.peek(1).is_word('has', 'is', 'satisfies'):
            self.advance()
            self.advance()
            start = self.peek()
            f = self.value_not()
            condition = _named(lambda e: bool(f(e)), self.text(start))
        inner: Callable = TrueMonitor
        if self.at('then') or (self.at_symbol(',') and self.peek(1).is_word('then')) \
                or (self.at('and') and self.peek(1).is_word('then')):
            if not self.accept('then'):
                self.advance()
                self.advance()
            inner = self.property()
        return lambda: NextMonitor(condition, a, b, inner())

    def property_atom(self) -> Callable:
        token = self.peek()
        if self.accept('true'):
            return TrueMonitor
        if self.accept('false'):
            return FalseMonitor
        if token.is_symbol('('):
            mark = self.mark()
            try:
                self.advance()
                build = self.property()
                self.expect_symbol(')')
                if not self._continues_measure():
                    return build
                failure = None
            except SpecificationError as error:
                failure = error
            self.reset(mark)
            try:
                return self.comparison()
            except SpecificationError as error:
                if failure is not None and (failure.line, failure.column) > \
                        (error.line or 0, error.column or 0):
                    raise failure from None
                raise
        if token.kind == NAME and token.value not in RESERVED:
            symbol = self.lookup(token)
            if symbol is not None and symbol.kind == 'property':
                self.advance()
                return symbol.value
        return self.comparison()

    def _continues_measure(self) -> bool:
        token = self.peek()
        return token.is_symbol('<', '<=', '>', '>=', '==', '!=', '+', '-', '*', '/') \
            or token.is_word('is', 'delayed', 'advanced')

    def comparison(self) -> Callable:
        left = self.measure()
        token = self.peek()
        if token.is_symbol(*_MONITORS):
            self.advance()
            right = self.measure()
            kind = _MONITORS[token.value]
            return lambda: kind(left(), right())
        if token.is_symbol('==', '!='):
            self.fail(f"'{token.value}' cannot compare measures, which change "
                      f"continuously: use 'is between' or '<=' and '>='", token)
        if self.accept('is'):
            if self.accept('between'):
                low = self.measure()
                self.expect('and')
                high = self.measure()
                return lambda: AndMonitor(AtomicGeqMonitor(left(), low()),
                                          AtomicLeqMonitor(left(), high()))
            if self.at(*_WORD_COMPARISONS):
                kind = _MONITORS[_WORD_COMPARISONS[self.advance().value]]
                right = self.measure()
                return lambda: kind(left(), right())
            if self.accept('at'):
                kind = AtomicGeqMonitor if self.expect('least', 'most').value == 'least' \
                    else AtomicLeqMonitor
                right = self.measure()
                return lambda: kind(left(), right())
            self.fail(f"expected 'between', 'above', 'below', 'at least' or 'at most' "
                      f"after 'is', found {self.peek().describe()}")
        self.fail(f"expected a comparison, such as '<' or 'is between', after the "
                  f"measure, found {token.describe()}")


def parse(source: str, constants: Optional[Mapping[str, float]] = None,
          functions: Optional[Mapping[str, Callable]] = None) -> Specification:
    """Parse the specification ``source`` and build its monitors and
    expressions.

    - ``constants`` replace the values of some constants of the
      specification;
    - ``functions`` are Python functions the values of the events can call
      by name.

    Raises :class:`~cytlmonitor.language.lexer.SpecificationError` if the
    specification is not well formed.
    """
    return Parser(source, constants, functions).parse()


def load(path, constants: Optional[Mapping[str, float]] = None,
         functions: Optional[Mapping[str, Callable]] = None) -> Specification:
    """Parse the specification in the file at ``path`` (see :func:`parse`)."""
    with open(path, encoding='utf-8') as file:
        return parse(file.read(), constants, functions)

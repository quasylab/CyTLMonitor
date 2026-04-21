"""
cytl_mg.py — CyTL Monitoring Graph
====================================
Complete implementation of CyTL operators (Definition 1 & 2, ESORICS paper).

Formula Language
----------------
  # Quantitative expressions (rho)  — Definition 1
  counting(ta, tb, w)     #[ta,tb][w]  sliding-window sum
  min_op(ta, tb, rho)     min[ta,tb][rho]  sliding-window minimum
  max_op(ta, tb, rho)     max[ta,tb][rho]  sliding-window maximum
  const(c)                constant c
  weight(fn, name)        custom weight function

  # Weight functions
  w_SYN, w_ACK, w_SYN_ACK, w_FIN, w_RST, w_SIZE, w_ONE, w_UDP, w_ICMP

  # Arithmetic  (on QExprMG)  op ∈ {+, −, ×, ÷}
  rho1 + rho2,  rho1 - rho2,  rho1 * rho2,  rho1 / rho2,  -rho

  # Atomic comparisons  -> FormulaMG
  rho > c,  rho >= c,  rho < c,  rho <= c
  rho1.eq(rho2),  rho1.neq(rho2)

  # Logical combinators  (on FormulaMG)  — Definition 2
  phi1 | phi2   DisjunctionMG      φ1 ∨ φ2
  phi1 & phi2   ConjunctionMG      φ1 ∧ φ2  (derived: ¬(¬φ1 ∨ ¬φ2))
  ~phi          NegationMG         ¬φ

  # Temporal operators
  UntilMG(phi1, phi2, ta, tb)      φ1 U[ta,tb] φ2
  ShiftForwardMG(phi, a)           φ≫a  (future shift)
  ShiftBackMG(phi, a)              φ≪a  (past shift)

  # Packet-predicate operators
  PacketModalityMG(pred, phi, ta, tb)   ⟨β⟩[ta,tb]φ
  FilterMG(pred, phi, name)            β▷φ

  # Boolean constants
  TRUE, FALSE
"""

from __future__ import annotations

from collections import deque
from typing import Callable, List, Optional

from cytl_monitor_unit import PacketEvent, Segment, SegmentCollector


def _wrap_formula(x) -> 'FormulaMG':
    if isinstance(x, FormulaMG):
        return x
    if x is True:
        return TRUE
    if x is False:
        return FALSE
    raise TypeError(f'Expected FormulaMG or bool, got {type(x).__name__}')


# =============================================================================
# MonitorResult
# =============================================================================

class MonitorResult:
    __slots__ = ('verdict', 'robustness')

    def __init__(self, verdict: bool, robustness: float):
        self.verdict = verdict
        self.robustness = robustness

    def __repr__(self):
        return f"MonitorResult(verdict={self.verdict}, rob={self.robustness:.3f})"


# =============================================================================
# QExprMG  — quantitative (robustness) expressions
# =============================================================================

class QExprMG:
    """Base for expressions that evaluate to a float robustness value."""

    def process(self, event: PacketEvent) -> float:
        raise NotImplementedError

    def horizon(self) -> float:
        return _horizon(self)

    # ── Arithmetic operators ──────────────────────────────────────────────────
    def __add__(self, other):   return LinearCombMG('+',   [self, _wrap(other)])
    def __radd__(self, other):  return LinearCombMG('+',   [_wrap(other), self])
    def __sub__(self, other):   return LinearCombMG('-',   [self, _wrap(other)])
    def __rsub__(self, other):  return LinearCombMG('-',   [_wrap(other), self])
    def __mul__(self, other):   return LinearCombMG('*',   [self, _wrap(other)])
    def __rmul__(self, other):  return LinearCombMG('*',   [_wrap(other), self])
    def __truediv__(self, other): return LinearCombMG('/', [self, _wrap(other)])
    def __neg__(self):          return LinearCombMG('neg', [self])

    # ── Comparison operators  →  FormulaMG ───────────────────────────────────
    def __gt__(self, other):    return ComparisonMG(self, _wrap(other), '>')
    def __ge__(self, other):    return ComparisonMG(self, _wrap(other), '>=')
    def __lt__(self, other):    return ComparisonMG(self, _wrap(other), '<')
    def __le__(self, other):    return ComparisonMG(self, _wrap(other), '<=')
    def eq(self, other):        return ComparisonMG(self, _wrap(other), '=')
    def neq(self, other):       return ComparisonMG(self, _wrap(other), '!=')

    def __str__(self):          return 'QExpr'


def _wrap(x) -> QExprMG:
    """Coerce a plain number to ConstantMG; leave QExprMG unchanged."""
    if isinstance(x, QExprMG):
        return x
    return ConstantMG(float(x))

# =============================================================================
# FormulaMG  — boolean / quantitative formulas
# =============================================================================

class FormulaMG:
    """Base for CyTL formulas — return MonitorResult on each event."""

    def process(self, event: PacketEvent) -> MonitorResult:
        raise NotImplementedError

    def horizon(self) -> float:
        return _horizon(self)

    # ── Logical operators ─────────────────────────────────────────────────────
    def __or__(self, other):    return DisjunctionMG([self, other])
    def __and__(self, other):   return ConjunctionMG([self, other])
    def __invert__(self):       return NegationMG(self)

    def __str__(self):          return 'Formula'


# =============================================================================
# ConstantMG
# =============================================================================

class ConstantMG(QExprMG):
    def __init__(self, value: float):
        self.value = value

    def process(self, event: PacketEvent) -> float:
        return self.value

    def __str__(self):
        return str(self.value)


# =============================================================================
# WeightFnMG
# =============================================================================

class WeightFnMG(QExprMG):
    def __init__(self, fn: Callable, name: str = ''):
        self.fn   = fn
        self.name = name

    def process(self, event: PacketEvent) -> float:
        return float(self.fn(event.payload))

    def __str__(self):
        return f'w({self.name})'


# =============================================================================
# LinearCombMG  — arithmetic combinations of QExprMG nodes
# =============================================================================

class LinearCombMG(QExprMG):
    def __init__(self, op: str, children: list):
        self.op       = op
        self.children = children
        self.name     = op

    def process(self, event: PacketEvent) -> float:
        vals = [c.process(event) for c in self.children]
        if self.op == '+':   return vals[0] + vals[1]
        if self.op == '-':   return vals[0] - vals[1]
        if self.op == '*':   return vals[0] * vals[1]
        if self.op == '/':   return vals[0] / vals[1] if vals[1] != 0.0 else float('inf')
        if self.op == 'neg': return -vals[0]
        raise ValueError(f'Unknown LinearCombMG op: {self.op!r}')

    def __str__(self):
        if self.op == 'neg':
            return f'(-{self.children[0]})'
        return f'({self.children[0]} {self.op} {self.children[1]})'


# =============================================================================
# CountingOpMG
# =============================================================================

class CountingOpMG(QExprMG):
    """
    #[ta, tb][inner] — sum the inner weight over all events in [t-tb, t-ta].

    Versione ottimizzata:
    - non rifà più la somma completa ad ogni pacchetto
    - mantiene due code:
      * _pending: eventi già visti ma non ancora entrati nella finestra
      * _active:  eventi attualmente conteggiati
    """

    def __init__(self, ta: float, tb: float, inner: QExprMG,
                 track_history: bool = False):
        self.ta = ta
        self.tb = tb
        self.inner = inner

        self._pending: deque = deque()   # (timestamp, value)
        self._active: deque = deque()    # (timestamp, value)
        self._active_sum: float = 0.0

        self._track = track_history
        self.history: Optional[SegmentCollector] = (
            SegmentCollector() if track_history else None
        )
        self._last_t: Optional[float] = None
        self._last_val: float = 0.0

    @property
    def monitor(self) -> 'CountingOpMG':
        return self

    def process(self, event: PacketEvent) -> float:
        t = event.get_time()
        val = self.inner.process(event)

        # 1) il nuovo evento entra nei pending
        self._pending.append((t, val))

        # 2) attiva tutti gli eventi che ora cadono entro t-ta
        win_hi = t - self.ta
        while self._pending and self._pending[0][0] <= win_hi:
            et, ev = self._pending.popleft()
            self._active.append((et, ev))
            self._active_sum += ev

        # 3) scarta gli eventi troppo vecchi: < t-tb
        win_lo = t - self.tb
        while self._active and self._active[0][0] < win_lo:
            _, ev = self._active.popleft()
            self._active_sum -= ev

        result = self._active_sum

        if self._track and self.history is not None:
            start = self._last_t if self._last_t is not None else 0.0
            if t >= start:
                self.history.consume(Segment(start, t, self._last_val))
                self._last_t = t
            self._last_val = result

        return result

    def flush(self, end_time: float):
        if self._track and self.history is not None and self._last_t is not None:
            self.history.consume(Segment(self._last_t, end_time, self._last_val))
            self._last_t = end_time

    def reset(self):
        self._pending.clear()
        self._active.clear()
        self._active_sum = 0.0
        self._last_t = None
        self._last_val = 0.0
        if self.history is not None:
            self.history.clear()

    def __str__(self):
        return f'#[{self.ta},{self.tb}]({self.inner})'


# =============================================================================
# MinOpMG  — min[ta,tb][rho]
# =============================================================================

class MinOpMG(QExprMG):
    """
    min[ta, tb][inner] — sliding-window minimum of inner over [t-tb, t-ta].

    Uses a monotonic deque for O(1) amortised min queries.
    """

    def __init__(self, ta: float, tb: float, inner: QExprMG):
        self.ta = ta
        self.tb = tb
        self.inner = inner

        self._pending: deque = deque()   # (timestamp, seq, value) not yet in window
        self._eligible: deque = deque()  # (timestamp, seq, value) in window
        self._mono: deque = deque()      # monotonic increasing (front = min)
        self._seq = 0

    def process(self, event: PacketEvent) -> float:
        t = event.get_time()
        val = self.inner.process(event)

        item = (t, self._seq, val)
        self._seq += 1
        self._pending.append(item)

        win_hi = t - self.ta
        win_lo = t - self.tb

        while self._pending and self._pending[0][0] <= win_hi:
            it = self._pending.popleft()
            self._eligible.append(it)
            while self._mono and self._mono[-1][2] >= it[2]:
                self._mono.pop()
            self._mono.append(it)

        while self._eligible and self._eligible[0][0] < win_lo:
            old = self._eligible.popleft()
            if self._mono and self._mono[0][1] == old[1]:
                self._mono.popleft()

        if not self._mono:
            return float('inf')
        return self._mono[0][2]

    def __str__(self):
        return f'min[{self.ta},{self.tb}]({self.inner})'


# =============================================================================
# MaxOpMG  — max[ta,tb][rho]
# =============================================================================

class MaxOpMG(QExprMG):
    """
    max[ta, tb][inner] — sliding-window maximum of inner over [t-tb, t-ta].

    Uses a monotonic deque for O(1) amortised max queries.
    """

    def __init__(self, ta: float, tb: float, inner: QExprMG):
        self.ta = ta
        self.tb = tb
        self.inner = inner

        self._pending: deque = deque()   # (timestamp, seq, value) not yet in window
        self._eligible: deque = deque()  # (timestamp, seq, value) in window
        self._mono: deque = deque()      # monotonic decreasing (front = max)
        self._seq = 0

    def process(self, event: PacketEvent) -> float:
        t = event.get_time()
        val = self.inner.process(event)

        item = (t, self._seq, val)
        self._seq += 1
        self._pending.append(item)

        win_hi = t - self.ta
        win_lo = t - self.tb

        while self._pending and self._pending[0][0] <= win_hi:
            it = self._pending.popleft()
            self._eligible.append(it)
            while self._mono and self._mono[-1][2] <= it[2]:
                self._mono.pop()
            self._mono.append(it)

        while self._eligible and self._eligible[0][0] < win_lo:
            old = self._eligible.popleft()
            if self._mono and self._mono[0][1] == old[1]:
                self._mono.popleft()

        if not self._mono:
            return float('-inf')
        return self._mono[0][2]

    def __str__(self):
        return f'max[{self.ta},{self.tb}]({self.inner})'


# =============================================================================
# ComparisonMG
# =============================================================================

class ComparisonMG(FormulaMG):
    """Atomic formula: rho1 op rho2"""

    def __init__(self, rho1: QExprMG, rho2: QExprMG, op: str = '>'):
        self.rho1 = rho1
        self.rho2 = rho2
        self.op   = op

    def process(self, event: PacketEvent) -> MonitorResult:
        l = self.rho1.process(event)
        r = self.rho2.process(event)

        if self.op in ('>', '>='):
            rob = l - r
        elif self.op in ('<', '<='):
            rob = r - l
        elif self.op == '=':
            rob = -abs(l - r)
        elif self.op == '!=':
            rob = abs(l - r)
        else:
            rob = l - r

        if   self.op == '>':  verdict = rob > 0
        elif self.op == '>=': verdict = rob >= 0
        elif self.op == '<':  verdict = rob > 0
        elif self.op == '<=': verdict = rob >= 0
        elif self.op == '=':  verdict = rob >= 0
        elif self.op == '!=': verdict = rob > 0
        else:                 verdict = rob > 0

        return MonitorResult(verdict, rob)

    def __str__(self):
        return f'({self.rho1} {self.op} {self.rho2})'


# =============================================================================
# NegationMG
# =============================================================================

class NegationMG(FormulaMG):
    def __init__(self, child: FormulaMG):
        self.child = _wrap_formula(child)

    def process(self, event: PacketEvent) -> MonitorResult:
        r = self.child.process(event)
        return MonitorResult(not r.verdict, -r.robustness)

    def __str__(self):
        return f'~({self.child})'


# =============================================================================
# ConjunctionMG
# =============================================================================

class ConjunctionMG(FormulaMG):
    """AND of multiple formulas. Robustness = min."""

    def __init__(self, *args):
        # Accept ConjunctionMG([phi1, phi2]) or ConjunctionMG(phi1, phi2)
        if len(args) == 1 and isinstance(args[0], list):
            self.children: List[FormulaMG] = [_wrap_formula(x) for x in args[0]]
        else:
            self.children = [_wrap_formula(x) for x in args]

    # Flatten when chaining &
    def __and__(self, other):
        return ConjunctionMG(self.children + [_wrap_formula(other)])

    def process(self, event: PacketEvent) -> MonitorResult:
        results = [c.process(event) for c in self.children]
        rob = min(r.robustness for r in results)
        return MonitorResult(all(r.verdict for r in results), rob)

    def __str__(self):
        return ' ∧ '.join(f'({c})' for c in self.children)

# =============================================================================
# DisjunctionMG
# =============================================================================
class DisjunctionMG(FormulaMG):
    """OR of multiple formulas. Robustness = max."""

    def __init__(self, *args):
        if len(args) == 1 and isinstance(args[0], list):
            self.children: List[FormulaMG] = [_wrap_formula(x) for x in args[0]]
        else:
            self.children = [_wrap_formula(x) for x in args]

    def __or__(self, other):
        return DisjunctionMG(self.children + [_wrap_formula(other)])

    def process(self, event: PacketEvent) -> MonitorResult:
        results = [c.process(event) for c in self.children]
        rob = max(r.robustness for r in results)
        return MonitorResult(any(r.verdict for r in results), rob)

    def __str__(self):
        return ' ∨ '.join(f'({c})' for c in self.children)


# =============================================================================
# FilterMG
# =============================================================================

class FilterMG(FormulaMG):
    """
    beta > phi
    Passes the event to phi only if pred(payload) is True;
    otherwise returns (False, -inf).
    """

    def __init__(self, pred: Callable, child: FormulaMG, name: str = 'beta'):
        self.pred  = pred
        self.child = _wrap_formula(child)
        self.name  = name

    def process(self, event: PacketEvent) -> MonitorResult:
        if self.pred(event.payload):
            return self.child.process(event)
        return MonitorResult(False, float('-inf'))

    def __str__(self):
        return f'Filter({self.name}, {self.child})'


# =============================================================================
# UntilMG  — past-time Until
# =============================================================================

class UntilMG(FormulaMG):
    """
    Past Until: phi1 U[ta, tb] phi2

    Semantics (past, online):
      At time t there exists t' in [t-tb, t-ta] such that
        - phi2 holds at t'
        - phi1 holds continuously from t' to t
    Robustness:
      max over t' in [t-tb, t-ta] of  min(rob(phi2, t'),  min_rob1_from_t'_to_t)
    """

    def __init__(self, phi1: FormulaMG, phi2: FormulaMG, ta: float, tb: float):
        self.phi1 = _wrap_formula(phi1)
        self.phi2 = _wrap_formula(phi2)
        self.ta   = ta
        self.tb   = tb
        # buffer: (timestamp, rob_phi1, rob_phi2)
        self._buf: deque = deque()

    def process(self, event: PacketEvent) -> MonitorResult:
        t  = event.get_time()
        r1 = self.phi1.process(event)
        r2 = self.phi2.process(event)
        self._buf.append((t, r1.robustness, r2.robustness))

        win_lo = t - self.tb
        win_hi = t - self.ta

        # Expire entries outside left edge
        while self._buf and self._buf[0][0] < win_lo:
            self._buf.popleft()

        buf_list = list(self._buf)
        best_rob = float('-inf')

        # Sweep right-to-left to compute running min of rob_phi1
        min_rob1 = float('inf')
        for i in range(len(buf_list) - 1, -1, -1):
            ti, rob1_i, rob2_i = buf_list[i]
            min_rob1 = min(min_rob1, rob1_i)
            if win_lo <= ti <= win_hi:
                candidate = min(rob2_i, min_rob1)
                if candidate > best_rob:
                    best_rob = candidate

        if best_rob == float('-inf'):
            return MonitorResult(False, float('-inf'))
        return MonitorResult(best_rob > 0, best_rob)

    def __str__(self):
        return f'({self.phi1}) U[{self.ta},{self.tb}] ({self.phi2})'


# =============================================================================
# ShiftForwardMG  — φ≫a
# =============================================================================

class ShiftForwardMG(FormulaMG):
    """
    Future shift: φ≫a  — evaluate φ at time t+a.

    Online implementation: buffers incoming events and processes them through
    child with a delay of 'a' seconds.  At time t the reported result is that
    of child evaluated on packets that arrived at time t-a.
    """

    def __init__(self, child: FormulaMG, a: float):
        self.child = _wrap_formula(child)
        self.a = a
        self._buf: deque = deque()                          # buffered PacketEvents
        self._last: MonitorResult = MonitorResult(False, float('-inf'))

    def process(self, event: PacketEvent) -> MonitorResult:
        t = event.get_time()
        self._buf.append(event)

        while self._buf and (t - self._buf[0].timestamp) >= self.a:
            old = self._buf.popleft()
            self._last = self.child.process(old)

        return self._last

    def __str__(self):
        return f'({self.child})≫{self.a}'


# =============================================================================
# ShiftBackMG  — φ≪a
# =============================================================================

class ShiftBackMG(FormulaMG):
    """
    Past shift: φ≪a  — evaluate φ at time t-a.

    Maintains a bounded history of child's MonitorResult values and returns
    the result from 'a' seconds ago.  Returns (False, -∞) when t < a.
    """

    def __init__(self, child: FormulaMG, a: float):
        self.child = _wrap_formula(child)
        self.a = a
        self._history: deque = deque()   # (timestamp, MonitorResult)

    def process(self, event: PacketEvent) -> MonitorResult:
        t = event.get_time()
        r = self.child.process(event)
        self._history.append((t, r))

        target = t - self.a

        # Expire entries that are much older than needed
        while len(self._history) > 1 and self._history[0][0] < target - self.a:
            self._history.popleft()

        # Return the latest result at or before target time
        past_result = None
        for ts, res in self._history:
            if ts <= target:
                past_result = res

        if past_result is None:
            return MonitorResult(False, float('-inf'))
        return past_result

    def __str__(self):
        return f'({self.child})≪{self.a}'


# =============================================================================
# PacketModalityMG  — ⟨β, [ta,tb]⟩φ
# =============================================================================

class PacketModalityMG(FormulaMG):
    """
    Packet Modality: ⟨β, [ta,tb]⟩φ

    Versione ottimizzata:
    - valuta sempre child per mantenere lo stato interno consistente
    - memorizza solo gli eventi che soddisfano pred
    - usa deque monotona per max
    """

    def __init__(self, pred: Callable, child: FormulaMG, ta: float, tb: float):
        self.pred = pred
        self.child = child
        self.ta = ta
        self.tb = tb

        self._pending: deque = deque()   # (timestamp, seq, robustness) solo se pred=True
        self._eligible: deque = deque()  # (timestamp, seq, robustness)
        self._mono: deque = deque()      # monotonic decreasing by robustness
        self._seq = 0

    def process(self, event: PacketEvent) -> MonitorResult:
        t = event.get_time()
        r = self.child.process(event)

        if self.pred(event.payload):
            item = (t, self._seq, r.robustness)
            self._seq += 1
            self._pending.append(item)

        win_hi = t - self.ta
        win_lo = t - self.tb

        while self._pending and self._pending[0][0] <= win_hi:
            it = self._pending.popleft()
            self._eligible.append(it)

            while self._mono and self._mono[-1][2] <= it[2]:
                self._mono.pop()
            self._mono.append(it)

        while self._eligible and self._eligible[0][0] < win_lo:
            old = self._eligible.popleft()
            if self._mono and self._mono[0][1] == old[1]:
                self._mono.popleft()

        if not self._mono:
            return MonitorResult(False, float('-inf'))

        rob = self._mono[0][2]
        return MonitorResult(rob > 0, rob)

    def __str__(self):
        return f'⟨β,[{self.ta},{self.tb}]⟩({self.child})'


# =============================================================================
# TrueMG / FalseMG
# =============================================================================

class TrueMG(FormulaMG):
    def process(self, event: PacketEvent) -> MonitorResult:
        return MonitorResult(True, float('inf'))

    def __str__(self): return 'TRUE'


class FalseMG(FormulaMG):
    def process(self, event: PacketEvent) -> MonitorResult:
        return MonitorResult(False, float('-inf'))

    def __str__(self): return 'FALSE'


TRUE  = TrueMG()
FALSE = FalseMG()


# =============================================================================
# MonitoringGraph
# =============================================================================

class MonitoringGraph:
    def __init__(self, formula: FormulaMG, name: str = ''):
        self.formula = formula
        self.name    = name

    def process(self, event: PacketEvent) -> MonitorResult:
        return self.formula.process(event)

    def flush(self, end_time: float):
        _visit(self.formula, lambda obj: obj.flush(end_time)
               if isinstance(obj, CountingOpMG) else None)

    def reset(self):
        def _reset_node(obj):
            if isinstance(obj, CountingOpMG):
                obj.reset()
            if isinstance(obj, (MinOpMG, MaxOpMG)):
                obj._pending.clear()
                obj._eligible.clear()
                obj._mono.clear()
                obj._seq = 0
            if isinstance(obj, UntilMG):
                obj._buf.clear()
            if isinstance(obj, PacketModalityMG):
                obj._pending.clear()
                obj._eligible.clear()
                obj._mono.clear()
                obj._seq = 0
            if isinstance(obj, ShiftForwardMG):
                obj._buf.clear()
                obj._last = MonitorResult(False, float('-inf'))
            if isinstance(obj, ShiftBackMG):
                obj._history.clear()
        _visit(self.formula, _reset_node)


def _visit(obj, fn):
    """Recursively visit all formula/expr nodes and apply fn."""
    fn(obj)
    for attr in ('phi', 'phi1', 'phi2', 'child', 'rho', 'rho1', 'rho2', 'inner'):
        child = getattr(obj, attr, None)
        if child is not None:
            _visit(child, fn)
    for kids in (getattr(obj, 'children', None),):
        if kids:
            for c in kids:
                _visit(c, fn)


# =============================================================================
# Weight functions
# =============================================================================

def _wfn(fn: Callable, name: str) -> WeightFnMG:
    return WeightFnMG(fn, name)


w_SYN = _wfn(
    lambda p: float(bool(p.get('tcp_syn', 0) or p.get('SYN', 0))),
    'w_SYN',
)
w_ACK = _wfn(
    lambda p: float(bool(p.get('tcp_ack', 0) or p.get('ACK', 0))),
    'w_ACK',
)
w_SYN_ACK = _wfn(
    lambda p: float(
        bool(p.get('tcp_syn', 0) or p.get('SYN', 0)) and
        bool(p.get('tcp_ack', 0) or p.get('ACK', 0))
    ),
    'w_SYN_ACK',
)
w_FIN = _wfn(
    lambda p: float(bool(p.get('tcp_fin', 0))),
    'w_FIN',
)
w_RST = _wfn(
    lambda p: float(bool(p.get('tcp_rst', 0))),
    'w_RST',
)
w_SIZE = _wfn(
    lambda p: float(p.get('size', 0) or 0),
    'w_SIZE',
)
w_ONE = _wfn(
    lambda p: 1.0,
    'w_ONE',
)
w_UDP = _wfn(
    lambda p: 1.0 if (p.get('protocol', '') or '').upper() == 'UDP' else 0.0,
    'w_UDP',
)
w_ICMP = _wfn(
    lambda p: 1.0 if (p.get('protocol', '') or '').upper() == 'ICMP' else 0.0,
    'w_ICMP',
)


# =============================================================================
# Predicate helpers  (for FilterMG)
# =============================================================================

def pred_syn(p):     return bool(p.get('tcp_syn', 0) or p.get('SYN', 0))
def pred_ack(p):     return bool(p.get('tcp_ack', 0) or p.get('ACK', 0))
def pred_syn_ack(p): return pred_syn(p) and pred_ack(p)
def pred_fin(p):     return bool(p.get('tcp_fin', 0))
def pred_rst(p):     return bool(p.get('tcp_rst', 0))
def pred_tcp(p):     return (p.get('protocol', '') or '').upper() == 'TCP'
def pred_udp(p):     return (p.get('protocol', '') or '').upper() == 'UDP'
def pred_icmp(p):    return (p.get('protocol', '') or '').upper() == 'ICMP'
def pred_ftp(p):    return (p.get('protocol', '') or '').upper() == 'TCP' and p.get('dst_port', 0) == 21
def pred_ssh(p):    return (p.get('protocol', '') or '').upper() == 'TCP' and p.get('dst_port', 0) == 22
def pred_http(p):   return (p.get('protocol', '') or '').upper() == 'TCP' and p.get('dst_port', 0) == 80
def pred_udp(p):    return (p.get('protocol', '') or '').upper() == 'UDP'

# =============================================================================
# Horizon helper  (max time window in the formula tree)
# =============================================================================

def _horizon(obj) -> float:
    """Return the maximum time bound (tb/a) found in any temporal/counting node."""
    h = 0.0
    if isinstance(obj, (CountingOpMG, MinOpMG, MaxOpMG, UntilMG, PacketModalityMG)):
        h = getattr(obj, 'tb', 0.0)
    elif isinstance(obj, (ShiftForwardMG, ShiftBackMG)):
        h = getattr(obj, 'a', 0.0)
    for attr in ('phi', 'phi1', 'phi2', 'child', 'rho', 'rho1', 'rho2', 'inner'):
        child = getattr(obj, attr, None)
        if child is not None:
            h = max(h, _horizon(child))
    kids = getattr(obj, 'children', None)
    if kids:
        for c in kids:
            h = max(h, _horizon(c))
    return h


# =============================================================================
# Constructor helpers
# =============================================================================

def counting(ta: float, tb: float, w) -> CountingOpMG:
    """Create a #[ta,tb][w] counting operator (no history tracking)."""
    inner = w if isinstance(w, WeightFnMG) else WeightFnMG(w, getattr(w, '__name__', ''))
    return CountingOpMG(ta, tb, inner, track_history=False)


def fresh_counting(ta: float, tb: float, w) -> CountingOpMG:
    """Create a #[ta,tb][w] counting operator with segment history tracking."""
    inner = w if isinstance(w, WeightFnMG) else WeightFnMG(w, getattr(w, '__name__', ''))
    return CountingOpMG(ta, tb, inner, track_history=True)


def min_op(ta: float, tb: float, rho) -> MinOpMG:
    """Create a min[ta,tb][rho] sliding-window minimum operator."""
    inner = rho if isinstance(rho, QExprMG) else ConstantMG(float(rho))
    return MinOpMG(ta, tb, inner)


def max_op(ta: float, tb: float, rho) -> MaxOpMG:
    """Create a max[ta,tb][rho] sliding-window maximum operator."""
    inner = rho if isinstance(rho, QExprMG) else ConstantMG(float(rho))
    return MaxOpMG(ta, tb, inner)


def shift_forward(phi: FormulaMG, a: float) -> ShiftForwardMG:
    """Create a φ≫a future-shift operator."""
    return ShiftForwardMG(phi, a)


def shift_back(phi: FormulaMG, a: float) -> ShiftBackMG:
    """Create a φ≪a past-shift operator."""
    return ShiftBackMG(phi, a)


def weight(fn: Callable, name: str = '') -> WeightFnMG:
    return WeightFnMG(fn, name)


def const(c: float) -> ConstantMG:
    return ConstantMG(float(c))


def make_filter(pred: Callable, phi: FormulaMG, name: str = 'beta') -> FilterMG:
    return FilterMG(pred, phi, name)

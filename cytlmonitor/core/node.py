"""
cytlmonitor.core.node
=====================
Navigation of the tree of expressions and monitors built for a formula.

A :class:`FormulaNode` is a node of that tree: every
:class:`~cytlmonitor.expressions.base.StreamExpression` and
:class:`~cytlmonitor.monitors.base.EventMonitor` is one. Its children are
its :attr:`FormulaNode.operands`, the expressions or monitors it was built
from, in the order they were passed to its constructor; atomic comparisons
have expressions as operands, so the tree of a monitor reaches down to the
expressions it compares.

Once a monitor is built, :meth:`FormulaNode.nodes` lists the nodes of its
tree and :meth:`FormulaNode.node` reaches one of them by its path, so that
consumers, for instance plots, can be attached to any of them with ``add``
(see :func:`cytlmonitor.consumers.plot.plot`).

``str`` of a node is the formula it computes, written with the operands'
formulas, which titles a plot. A node whose class does not define a formula
is written with the name of its class.
"""

from __future__ import annotations

import math
from typing import Callable, Iterator, Optional, Tuple


class FormulaNode:
    """A node of the tree of expressions and monitors of a formula."""

    __slots__ = ()

    # True when the formula is written with an infix operator, so that it is
    # parenthesised as an operand.
    _infix = False

    @property
    def operands(self) -> Tuple['FormulaNode', ...]:
        """The expressions or monitors this node is built from, in order."""
        return ()

    def nodes(self, depth: Optional[int] = None) -> Iterator['FormulaNode']:
        """Yield the nodes of the tree rooted here, in pre-order: this node,
        then the nodes of each operand in turn, down to ``depth`` levels
        below this node (all of them if ``depth`` is None). A node reached
        twice is yielded once."""
        if depth is not None and depth < 0:
            raise ValueError(f"depth must be non negative, got {depth}.")
        seen = set()
        stack = [(self, 0)]
        while stack:
            node, level = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            yield node
            if depth is None or level < depth:
                stack.extend((child, level + 1) for child in reversed(node.operands))

    def node(self, *path: int) -> 'FormulaNode':
        """Return the node reached by following ``path`` from here: each
        index selects an operand of the node reached so far. With no index,
        this node."""
        node = self
        for k, index in enumerate(path):
            operands = node.operands
            if not -len(operands) <= index < len(operands):
                raise IndexError(
                    f"{node} has {len(operands)} operand(s): no operand {index} "
                    f"at position {k} of path {path}."
                )
            node = operands[index]
        return node

    def __str__(self) -> str:
        return type(self).__name__


def operand(node: FormulaNode) -> str:
    """The formula of ``node`` as an operand: parenthesised if it is
    written with an infix operator."""
    text = str(node)
    return f'({text})' if node._infix else text


def number(x: float) -> str:
    """``x`` written briefly: ``2`` for 2.0, ``inf`` for infinity."""
    if math.isinf(x):
        return 'inf' if x > 0 else '-inf'
    return f'{x:g}'


def window(start: float, end: Optional[float], left_open: bool = False,
           right_open: bool = False) -> str:
    """The window from ``start`` to ``end`` (unbounded if None), as
    ``[a,b]``, with round brackets at the open ends."""
    left = '(' if left_open else '['
    right = ')' if right_open or end is None or math.isinf(end) else ']'
    return f'{left}{number(start)},{number(math.inf if end is None else end)}{right}'


def interval_window(i) -> str:
    """The window of the Interval ``i``."""
    return window(i.start, i.end, i.left_open, i.right_open)


def function_name(f: Callable, default: str) -> str:
    """The name of ``f``, or ``default`` for a lambda or a callable with no
    name."""
    name = getattr(f, '__name__', None)
    return default if not name or name == '<lambda>' else name

"""
CyTL Rule Compiler
==================
Compiles user-written CyTL formula strings into Rule objects.
Validates syntax, evaluates in a restricted namespace, and analyses
the formula tree.

All formula types are from cytl_mg.py.  Operators follow Definition 1 & 2
of the ESORICS paper exactly.

Formula Language Quick Reference  (Definition 1 — rho)
-------------------------------------------------------
  counting(ta, tb, w)        #[ta,tb][w]   — sliding-window sum
  min_op(ta, tb, rho)        min[ta,tb][rho] — sliding-window minimum
  max_op(ta, tb, rho)        max[ta,tb][rho] — sliding-window maximum
  const(c)                   constant c
  w_SYN, w_ACK, ...          predefined weight functions

  Arithmetic (op ∈ {+, −, ×, ÷}):
  rho1 + rho2,  rho1 - rho2,  rho1 * rho2,  rho1 / rho2,  -rho

  Comparisons  →  FormulaMG:
  rho1 > c,  rho1 >= c,  rho1 < c,  rho1 <= c
  rho1.eq(rho2)   rho1.neq(rho2)

Formula Language Quick Reference  (Definition 2 — phi)
-------------------------------------------------------
  phi1 | phi2               φ1 ∨ φ2    Disjunction
  phi1 & phi2               φ1 ∧ φ2    Conjunction (derived)
  ~phi                      ¬φ         Negation
  Until(phi1, phi2, ta, tb) φ1 U[ta,tb] φ2
  ShiftForward(phi, a)      φ≫a        future shift
  ShiftBack(phi, a)         φ≪a        past shift
  PacketModality(pred, ta, tb, phi)    ⟨β⟩[ta,tb]φ
  Filter(pred, phi, name='beta')       β▷φ
  TRUE, FALSE

Examples
---------
  counting(0, 10, w_SYN) - counting(0, 10, w_ACK) > 100
  counting(0, 5, w_ONE) > 200
  Until(counting(0,5,w_SYN) > 50, counting(0,5,w_ACK) > 40, 0, 10)
  Filter(pred_tcp, counting(0, 10, w_ONE) > 300, 'is_tcp')
  ShiftBack(counting(0, 10, w_SYN) > 50, 5)
"""

from __future__ import annotations

import ast
import random
import traceback
from dataclasses import dataclass, field
from typing import List, Optional

from cytl_monitor_unit import Payload, PacketEvent
from cytl_mg import (
    FormulaMG, QExprMG, MonitoringGraph, MonitorResult,
    ConstantMG, WeightFnMG, CountingOpMG, MinOpMG, MaxOpMG, LinearCombMG,
    ComparisonMG, NegationMG, ConjunctionMG, DisjunctionMG,
    FilterMG, UntilMG, ShiftForwardMG, ShiftBackMG, PacketModalityMG,
    TrueMG, FalseMG, TRUE, FALSE,
    counting, min_op, max_op, shift_forward, shift_back,
    weight, const, make_filter,
    w_SYN, w_ACK, w_SYN_ACK, w_FIN, w_RST,
    w_SIZE, w_ONE, w_UDP, w_ICMP,
    pred_syn, pred_ack, pred_syn_ack, pred_fin, pred_rst,
    pred_tcp, pred_udp, pred_icmp, pred_ftp, pred_ssh, pred_http,
)
from cytl_rules_mg import Rule


# =============================================================================
# Safe eval namespace
# =============================================================================
COMPILER_NS: dict = {
    # Quantitative expression constructors  — Definition 1
    'counting':   counting,
    'min_op':     min_op,
    'max_op':     max_op,
    'weight':     weight,
    'const':      const,
    'Constant':   ConstantMG,
    'WeightFn':   WeightFnMG,
    'CountingOp': CountingOpMG,
    'MinOp':      MinOpMG,
    'MaxOp':      MaxOpMG,

    # Predefined weight functions
    'w_SYN':     w_SYN,
    'w_ACK':     w_ACK,
    'w_SYN_ACK': w_SYN_ACK,
    'w_FIN':     w_FIN,
    'w_RST':     w_RST,
    'w_SIZE':    w_SIZE,
    'w_ONE':     w_ONE,
    'w_UDP':     w_UDP,
    'w_ICMP':    w_ICMP,

    # Formula constructors  — Definition 2
    'Negation':       NegationMG,
    'Disjunction':    DisjunctionMG,
    'Conjunction':    ConjunctionMG,
    'Until':          lambda phi1, phi2, ta, tb: UntilMG(phi1, phi2, ta, tb),
    'ShiftForward':   lambda phi, a: ShiftForwardMG(phi, a),
    'ShiftBack':      lambda phi, a: ShiftBackMG(phi, a),
    'Filter':         lambda pred, phi, name='beta': FilterMG(pred, phi, name),
    'PacketModality': lambda pred, ta, tb, phi: PacketModalityMG(pred, phi, ta, tb),
    'TRUE':        TRUE,
    'FALSE':       FALSE,

    # Predicate helpers  (for use with Filter / PacketModality)
    'pred_syn':     pred_syn,
    'pred_ack':     pred_ack,
    'pred_syn_ack': pred_syn_ack,
    'pred_fin':     pred_fin,
    'pred_rst':     pred_rst,
    'pred_tcp':     pred_tcp,
    'pred_udp':     pred_udp,
    'pred_icmp':    pred_icmp,
    'pred_ftp':     pred_ftp,
    'pred_ssh':     pred_ssh,
    'pred_http':    pred_http,

    # Safe builtins
    'abs': abs,
    'float': float, 'int': int, 'bool': bool,
    '__builtins__': {},
}



# =============================================================================
# Compile result
# =============================================================================

@dataclass
class CompileResult:
    success:     bool                  = False
    formula:     Optional[FormulaMG]   = None
    error:       str                   = ''
    warnings:    List[str]             = field(default_factory=list)
    formula_str: str                   = ''
    horizon_val: float                 = 0.0
    tree_str:    str                   = ''
    complexity:  str                   = ''


# =============================================================================
# Compiler
# =============================================================================

def compile_formula(expr: str) -> CompileResult:
    """
    Compile a CyTL formula expression string.

    Steps:
      1. Python AST syntax check + security scan.
      2. Restricted eval in COMPILER_NS.
      3. Type validation (must yield a FormulaMG).
      4. Structural analysis (horizon, tree, complexity).
    """
    result = CompileResult()

    expr = expr.strip()
    if not expr:
        result.error = 'Formula is empty.'
        return result

    # Strip inline comments
    clean_expr = '\n'.join(line.split('#')[0] for line in expr.splitlines()).strip()
    if not clean_expr:
        result.error = 'Formula contains only comments.'
        return result

    # 1. Syntax check
    try:
        tree = ast.parse(clean_expr, mode='eval')
    except SyntaxError as e:
        result.error = f'Syntax error on line {e.lineno}: {e.msg}'
        return result

    # Security: ban dangerous AST nodes
    allowed_attrs = {'eq', 'neq', '__add__', '__sub__', '__mul__', '__truediv__',
                     '__neg__', '__gt__', '__ge__', '__lt__', '__le__',
                     '__or__', '__and__', '__invert__'}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom,
                              ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Delete)):
            result.error = f'Forbidden construct: {type(node).__name__}'
            return result
        if isinstance(node, ast.Attribute) and node.attr not in allowed_attrs:
            if not node.attr.startswith('_'):
                result.error = f'Forbidden attribute access: .{node.attr}'
                return result

    # 2. Evaluate
    try:
        formula = eval(compile(tree, '<formula>', 'eval'), dict(COMPILER_NS))
    except NameError as e:
        result.error = (
            f'Unknown name: {e}\n'
            f'Available: counting(), w_SYN, w_ACK, w_ONE, w_SIZE, ...'
        )
        return result
    except TypeError as e:
        result.error = f'Type error: {e}'
        return result
    except Exception as e:
        result.error = f'{type(e).__name__}: {e}'
        return result

    # 3. Type check
    if not isinstance(formula, FormulaMG):
        if isinstance(formula, QExprMG):
            result.error = (
                f'Result is a quantitative expression ({type(formula).__name__}), '
                f'not a formula.\nAdd a comparison, e.g.:  ... > 100'
            )
        else:
            result.error = (
                f'Result is {type(formula).__name__} — expected a CyTL formula.\n'
                f'The expression must end with a comparison operator.'
            )
        return result

    # 4. Analysis
    result.success     = True
    result.formula     = formula
    result.formula_str = str(formula)
    result.horizon_val = _horizon(formula)
    result.tree_str    = _formula_tree(formula)
    result.complexity  = _complexity(formula)

    if result.horizon_val > 300:
        result.warnings.append(
            f'Large horizon ({result.horizon_val:.0f}s). Consider reducing window sizes.'
        )
    if result.horizon_val == 0:
        result.warnings.append(
            'Horizon is 0 — formula has no temporal extent. '
            'Consider using counting(ta, tb, ...).'
        )
    return result


def build_rule(name: str, description: str, severity: str, category: str,
               window_size: float, formula: FormulaMG) -> Rule:
    """Wrap a compiled formula into a Rule object."""
    return Rule(
        name=name,
        description=description,
        formula=formula,
        severity=severity,
        category=category,
        params={'window': window_size},
    )


# =============================================================================
# Quick-test: inject sample packets and observe robustness
# =============================================================================

def test_formula(formula: FormulaMG, scenario: str = 'syn_flood',
                 window: float = 60.0, n_packets: int = 20) -> List[dict]:
    """
    Feed simulated PacketEvent objects into a fresh MonitoringGraph.
    Returns list of {'t', 'robustness', 'verdict', 'payload_summary'}.
    """
    graph   = MonitoringGraph(formula, name='test')
    results = []
    t       = 0.0

    for _ in range(n_packets):
        t += random.uniform(0.05, 0.5)

        if scenario == 'syn_flood':
            fields = {
                'src_ip': f'{random.randint(1,254)}.0.0.{random.randint(1,254)}',
                'dst_ip': '10.0.0.1',
                'src_port': random.randint(1024, 65535), 'dst_port': 80,
                'protocol': 'TCP', 'size': 60, 'ttl': 64,
                'tcp_syn': 1, 'tcp_ack': 0, 'tcp_fin': 0,
                'tcp_rst': 0, 'tcp_psh': 0, 'tcp_urg': 0,
            }
        elif scenario == 'normal':
            is_syn = random.random() < 0.3
            is_ack = random.random() < 0.7
            fields = {
                'src_ip': f'192.168.1.{random.randint(1,50)}',
                'dst_ip': f'10.0.0.{random.randint(1,5)}',
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22]),
                'protocol': 'TCP', 'size': random.randint(40, 1500), 'ttl': 64,
                'tcp_syn': int(is_syn and not is_ack),
                'tcp_ack': int(is_ack),
                'tcp_fin': 0, 'tcp_rst': 0, 'tcp_psh': 0, 'tcp_urg': 0,
            }
        elif scenario == 'icmp_flood':
            fields = {
                'src_ip': f'{random.randint(1,254)}.0.0.1', 'dst_ip': '10.0.0.1',
                'protocol': 'ICMP', 'size': 64, 'ttl': 64,
                'icmp_type': 8, 'icmp_code': 0,
                'tcp_syn': 0, 'tcp_ack': 0, 'tcp_fin': 0,
                'tcp_rst': 0, 'tcp_psh': 0, 'tcp_urg': 0,
            }
        else:   # udp / mixed
            fields = {
                'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8',
                'protocol': 'UDP', 'size': 512, 'ttl': 64,
                'tcp_syn': 0, 'tcp_ack': 0, 'tcp_fin': 0,
                'tcp_rst': 0, 'tcp_psh': 0, 'tcp_urg': 0,
            }

        event = PacketEvent(timestamp=t, payload=Payload(fields))
        res   = graph.process(event)
        proto = fields.get('protocol', '')
        flags = ''.join(k[-3:] for k in ('tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst')
                        if fields.get(k))
        results.append({
            't':               t,
            'robustness':      res.robustness,
            'verdict':         res.verdict,
            'payload_summary': f"{proto} {fields.get('src_ip','')} -> {fields.get('dst_ip','')} flags={flags}",
        })

    return results


# =============================================================================
# Formula tree visualiser
# =============================================================================

def _formula_tree(obj, indent: int = 0) -> str:
    p = '  ' * indent

    if isinstance(obj, TrueMG):   return p + 'TRUE'
    if isinstance(obj, FalseMG):  return p + 'FALSE'

    if isinstance(obj, ComparisonMG):
        sym = {'>=': '>=', '<=': '<=', '=': '=', '>': '>', '<': '<', '!=': '!='}
        op  = sym.get(obj.op, obj.op)
        return '\n'.join([
            p + f'Comparison  rho1 {op} rho2',
            _qexpr_tree(obj.rho1, indent + 1),
            _qexpr_tree(obj.rho2, indent + 1),
        ])

    if isinstance(obj, NegationMG):
        return '\n'.join([p + 'Negation', _formula_tree(obj.child, indent + 1)])

    if isinstance(obj, ConjunctionMG):
        lines = [p + 'Conjunction']
        for c in obj.children:
            lines.append(_formula_tree(c, indent + 1))
        return '\n'.join(lines)

    if isinstance(obj, DisjunctionMG):
        lines = [p + 'Disjunction']
        for c in obj.children:
            lines.append(_formula_tree(c, indent + 1))
        return '\n'.join(lines)

    if isinstance(obj, UntilMG):
        return '\n'.join([
            p + f'Until  phi1 U[{obj.ta}, {obj.tb}] phi2',
            _formula_tree(obj.phi1, indent + 1),
            _formula_tree(obj.phi2, indent + 1),
        ])

    if isinstance(obj, ShiftForwardMG):
        return '\n'.join([
            p + f'ShiftForward  phi≫{obj.a}',
            _formula_tree(obj.child, indent + 1),
        ])

    if isinstance(obj, ShiftBackMG):
        return '\n'.join([
            p + f'ShiftBack  phi≪{obj.a}',
            _formula_tree(obj.child, indent + 1),
        ])

    if isinstance(obj, FilterMG):
        return '\n'.join([
            p + f'Filter  {obj.name} ▷ phi',
            _formula_tree(obj.child, indent + 1),
        ])

    if isinstance(obj, PacketModalityMG):
        return '\n'.join([
            p + f'PacketModality  <beta>[{obj.ta},{obj.tb}]',
            _formula_tree(obj.child, indent + 1),
        ])

    return p + str(obj)


def _qexpr_tree(obj, indent: int = 0) -> str:
    p = '  ' * indent

    if isinstance(obj, ConstantMG):
        return p + f'Constant  {obj.value}'

    if isinstance(obj, WeightFnMG):
        return p + f'WeightFn  {obj.name}'

    if isinstance(obj, CountingOpMG):
        return '\n'.join([
            p + f'CountingOp  #[{obj.ta}, {obj.tb}]',
            _qexpr_tree(obj.inner, indent + 1),
        ])

    if isinstance(obj, MinOpMG):
        return '\n'.join([
            p + f'MinOp  min[{obj.ta}, {obj.tb}]',
            _qexpr_tree(obj.inner, indent + 1),
        ])

    if isinstance(obj, MaxOpMG):
        return '\n'.join([
            p + f'MaxOp  max[{obj.ta}, {obj.tb}]',
            _qexpr_tree(obj.inner, indent + 1),
        ])

    if isinstance(obj, LinearCombMG):
        lines = [p + f'LinearComb  {obj.name}']
        for c in obj.children:
            lines.append(_qexpr_tree(c, indent + 1))
        return '\n'.join(lines)

    return p + str(obj)


def _complexity(phi) -> str:
    n_cnt    = _count(phi, CountingOpMG)
    n_min    = _count(phi, MinOpMG)
    n_max    = _count(phi, MaxOpMG)
    n_until  = _count(phi, UntilMG)
    n_sfwd   = _count(phi, ShiftForwardMG)
    n_sbck   = _count(phi, ShiftBackMG)
    n_filt   = _count(phi, FilterMG)
    n_modal  = _count(phi, PacketModalityMG)
    parts = []
    if n_cnt:   parts.append(f'{n_cnt} counting op(s)')
    if n_min:   parts.append(f'{n_min} min op(s)')
    if n_max:   parts.append(f'{n_max} max op(s)')
    if n_until: parts.append(f'{n_until} Until op(s)')
    if n_sfwd:  parts.append(f'{n_sfwd} ShiftForward op(s)')
    if n_sbck:  parts.append(f'{n_sbck} ShiftBack op(s)')
    if n_filt:  parts.append(f'{n_filt} filter op(s)')
    if n_modal: parts.append(f'{n_modal} modality op(s)')
    return ', '.join(parts) if parts else 'atomic'


def _count(obj, cls) -> int:
    count = int(isinstance(obj, cls))
    for attr in ('phi', 'phi1', 'phi2', 'child', 'rho', 'rho1', 'rho2', 'inner'):
        child = getattr(obj, attr, None)
        if child is not None:
            count += _count(child, cls)
    for children in (getattr(obj, 'children', None),):
        if children:
            for c in children:
                count += _count(c, cls)
    return count


def _horizon(obj) -> float:
    """Return the max time window used in any counting/temporal op."""
    h = 0.0
    if isinstance(obj, (CountingOpMG, MinOpMG, MaxOpMG, UntilMG, PacketModalityMG)):
        h = getattr(obj, 'tb', 0.0)
    elif isinstance(obj, (ShiftForwardMG, ShiftBackMG)):
        h = getattr(obj, 'a', 0.0)
    for attr in ('phi', 'phi1', 'phi2', 'child', 'rho', 'rho1', 'rho2', 'inner'):
        child = getattr(obj, attr, None)
        if child is not None:
            h = max(h, _horizon(child))
    for children in (getattr(obj, 'children', None),):
        if children:
            for c in children:
                h = max(h, _horizon(c))
    return h

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import ClassVar, Dict, List, Optional

from cytl_monitor_unit import PacketEvent
from cytl_mg import (
    FormulaMG,
    MonitoringGraph,
    ConjunctionMG,
    DisjunctionMG,
    NegationMG,
    FilterMG,
    UntilMG,
    const,
    counting,
    fresh_counting,
    w_ACK,
    w_FIN,
    w_ICMP,
    w_ONE,
    w_RST,
    w_SIZE,
    w_SYN,
    w_SYN_ACK,
    w_UDP,
    pred_tcp,
    pred_udp,
    pred_icmp,
    pred_syn,
    pred_rst,
)


# =============================================================================
# Rule
# =============================================================================

@dataclass
class Rule:
    name: str
    description: str
    formula: FormulaMG
    severity: str
    category: str
    params: Dict[str, float] = field(default_factory=dict)

    @property
    def window_size(self) -> float:
        return self.params.get('window', 0.0)

    def create_graph(self) -> MonitoringGraph:
        return MonitoringGraph(self.formula, name=self.name)


# =============================================================================
# RuleHit
# =============================================================================

@dataclass
class RuleHit:
    rule_name: str
    event_time: float
    severity: str
    category: str
    robustness: float
    description: str

    # Dict-compatible access so AlertsTable.add_alert(rule_hit) works
    # Keys expected by the UI: 'time', 'rule', 'severity', 'category',
    #                          'robustness', 'description'
    _KEY_MAP: ClassVar[Dict[str, str]] = {
        'time':        'event_time',
        'rule':        'rule_name',
        'severity':    'severity',
        'category':    'category',
        'robustness':  'robustness',
        'description': 'description',
    }

    def get(self, key: str, default=None):
        attr = self._KEY_MAP.get(key, key)
        return getattr(self, attr, default)


# =============================================================================
# Built-in rule factories
# =============================================================================

def make_ddos_syn_flood(window: float = 10.0, threshold: float = 100.0) -> Rule:
    rho_syn = fresh_counting(0, window, w_SYN)
    rho_ack = fresh_counting(0, window, w_ACK)
    return Rule(
        name="DDoS SYN Flood",
        description="Half-open TCP connections exceed threshold — classic SYN flood.",
        formula=(rho_syn - rho_ack) > threshold,
        severity="HIGH",
        category="DDoS",
        params={"window": window, "threshold": threshold},
    )


def make_high_packet_rate(window: float = 5.0, threshold: float = 200.0) -> Rule:
    return Rule(
        name="High Packet Rate",
        description="Total packet count in the window exceeds threshold.",
        formula=fresh_counting(0, window, w_ONE) > threshold,
        severity="HIGH",
        category="DDoS",
        params={"window": window, "threshold": threshold},
    )


def make_port_scan(window: float = 5.0, syn_threshold: float = 20.0) -> Rule:
    rho_syn_1 = fresh_counting(0, window, w_SYN)
    rho_syn_2 = fresh_counting(0, window, w_SYN)
    rho_ack_2 = fresh_counting(0, window, w_ACK)
    formula = ConjunctionMG(
        rho_syn_1 > syn_threshold,
        (rho_syn_2 - rho_ack_2 * const(0.1)) > (syn_threshold * 0.9),
    )
    return Rule(
        name="Port Scan",
        description="Many SYNs with comparatively few ACKs — port scan pattern.",
        formula=formula,
        severity="MEDIUM",
        category="Reconnaissance",
        params={"window": window, "threshold": syn_threshold},
    )


def make_icmp_flood(window: float = 5.0, threshold: float = 50.0) -> Rule:
    return Rule(
        name="ICMP Flood",
        description="ICMP packet count exceeds threshold — Ping flood / Smurf attack.",
        formula=fresh_counting(0, window, w_ICMP) > threshold,
        severity="MEDIUM",
        category="DDoS",
        params={"window": window, "threshold": threshold},
    )


def make_udp_flood(window: float = 5.0, threshold: float = 200.0) -> Rule:
    return Rule(
        name="UDP Flood",
        description="UDP packet count exceeds threshold.",
        severity="HIGH",
        category="DDoS",
        formula=fresh_counting(0, window, w_UDP) > threshold,
        params={"window": window, "threshold": threshold},
    )


def make_rst_attack(window: float = 5.0, threshold: float = 30.0) -> Rule:
    return Rule(
        name="TCP RST Attack",
        description="RST packet count exceeds threshold — TCP reset injection.",
        formula=fresh_counting(0, window, w_RST) > threshold,
        severity="MEDIUM",
        category="DoS",
        params={"window": window, "threshold": threshold},
    )


def make_large_payload(window: float = 10.0, size_threshold: float = 1_000_000.0) -> Rule:
    return Rule(
        name="Large Payload Volume",
        description="Total payload volume exceeds threshold — possible data exfiltration.",
        formula=fresh_counting(0, window, w_SIZE) > size_threshold,
        severity="MEDIUM",
        category="Exfiltration",
        params={"window": window, "threshold": size_threshold},
    )


def make_syn_ack_ratio(window: float = 10.0, threshold: float = 0.3) -> Rule:
    """Flags when SYN-ACK / SYN ratio drops below threshold (many unanswered SYNs)."""
    rho_syn = fresh_counting(0, window, w_SYN)
    rho_sa  = fresh_counting(0, window, w_SYN_ACK)
    # rob > 0 when  rho_syn * threshold > rho_sa  i.e. not enough SYN-ACKs
    formula = (rho_syn * const(threshold)) - rho_sa > const(0)
    return Rule(
        name="Low SYN-ACK Ratio",
        description=(
            "Ratio of SYN-ACK to SYN packets is abnormally low "
            "— indicative of half-open connection flood."
        ),
        formula=formula,
        severity="HIGH",
        category="DDoS",
        params={"window": window, "threshold": threshold},
    )


def make_fin_scan(window: float = 5.0, threshold: float = 20.0) -> Rule:
    """Detects FIN-only scans (FINs without established sessions)."""
    rho_fin = fresh_counting(0, window, w_FIN)
    rho_sa  = fresh_counting(0, window, w_SYN_ACK)
    # Many FINs but very few SYN-ACKs → suspicious
    formula = ConjunctionMG(
        rho_fin > threshold,
        rho_fin - rho_sa * const(2.0) > const(0),
    )
    return Rule(
        name="FIN Scan",
        description="High FIN count with few SYN-ACKs — possible FIN port scan.",
        formula=formula,
        severity="MEDIUM",
        category="Reconnaissance",
        params={"window": window, "threshold": threshold},
    )


def make_dns_amplification(window: float = 5.0, threshold: float = 100.0) -> Rule:
    """Large UDP bursts on port 53 — DNS amplification DDoS."""
    rho_udp  = fresh_counting(0, window, w_UDP)
    rho_size = fresh_counting(0, window, w_SIZE)
    formula = ConjunctionMG(
        rho_udp > threshold,
        rho_size > const(threshold * 512),   # avg packet > 512 bytes
    )
    return Rule(
        name="DNS Amplification",
        description="High UDP packet count with large payloads — DNS amplification attack.",
        formula=formula,
        severity="HIGH",
        category="DDoS",
        params={"window": window, "threshold": threshold},
    )


def make_tcp_connection_exhaustion(
        window: float = 30.0, threshold: float = 500.0) -> Rule:
    """Many SYNs sustained over a longer window — connection-table exhaustion."""
    return Rule(
        name="TCP Connection Exhaustion",
        description=(
            "High sustained SYN rate over a wide window "
            "— connection-table exhaustion / slow-rate DDoS."
        ),
        formula=fresh_counting(0, window, w_SYN) > threshold,
        severity="HIGH",
        category="DoS",
        params={"window": window, "threshold": threshold},
    )


def make_xmas_scan(window: float = 5.0, threshold: float = 10.0) -> Rule:
    """Detects XMAS scan — packets with SYN+FIN+RST all set (unusual flag combination)."""
    # XMAS / invalid-flag packets: RST packets that also carry FIN
    rho_rst = fresh_counting(0, window, w_RST)
    rho_fin = fresh_counting(0, window, w_FIN)
    formula = ConjunctionMG(
        rho_rst > threshold,
        rho_fin > threshold,
    )
    return Rule(
        name="XMAS / Invalid Flag Scan",
        description="Simultaneous RST and FIN bursts — XMAS scan or invalid-flag probe.",
        formula=formula,
        severity="MEDIUM",
        category="Reconnaissance",
        params={"window": window, "threshold": threshold},
    )


# =============================================================================
# RuleSet
# =============================================================================

class RuleSet:
    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        if rules is None:
            rules = []
        self.rules: Dict[str, Rule] = {}
        self.graphs: Dict[str, MonitoringGraph] = {}
        self._last_robustness: Dict[str, float] = {}
        self._lock = threading.Lock()
        for rule in rules:
            self._register(rule)

    def _register(self, rule: Rule) -> None:
        self.rules[rule.name] = rule
        self.graphs[rule.name] = rule.create_graph()
        self._last_robustness[rule.name] = 0.0

    def add(self, rule: Rule) -> None:
        with self._lock:
            self._register(rule)

    def remove(self, name: str) -> None:
        with self._lock:
            self.rules.pop(name, None)
            self.graphs.pop(name, None)
            self._last_robustness.pop(name, None)

    def process(self, event: PacketEvent) -> List[RuleHit]:
        hits: List[RuleHit] = []
        with self._lock:
            graphs = list(self.graphs.items())
        for name, graph in graphs:
            result = graph.process(event)
            rob = result.robustness
            self._last_robustness[name] = rob
            if rob > 0:
                with self._lock:
                    rule = self.rules.get(name)
                if rule:
                    hits.append(RuleHit(
                        rule_name=name,
                        event_time=event.timestamp,
                        severity=rule.severity,
                        category=rule.category,
                        robustness=rob,
                        description=rule.description,
                    ))
        return hits

    def reset_all(self) -> None:
        with self._lock:
            for name, graph in self.graphs.items():
                graph.reset()
                self._last_robustness[name] = 0.0


# =============================================================================
# Default rule list / ruleset
# =============================================================================

def _default_rules() -> List[Rule]:
    return []
    return [
        make_ddos_syn_flood(),
        make_high_packet_rate(),
        make_port_scan(),
        make_icmp_flood(),
        make_udp_flood(),
        make_rst_attack(),
        make_large_payload(),
        make_syn_ack_ratio(),
        make_fin_scan(),
        make_dns_amplification(),
        make_tcp_connection_exhaustion(),
        make_xmas_scan(),
    ]


def default_ruleset() -> RuleSet:
    return RuleSet([])
    #return RuleSet(_default_rules())

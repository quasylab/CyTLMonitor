"""
CyTL IDS — Intrusion Detection System
======================================
Graphical interface for the CyTL Temporal-Quantitative Logic IDS.

Based on: "A Temporal-Quantitative Logic Framework for Monitoring Network Traffic"
          by Michele Loreti and Marco Quadrini

Usage:
  python main.py
"""

from __future__ import annotations

import sys
import os
import time
import threading
from datetime import datetime
import collections
from typing import Dict, List, Optional, Tuple

# ── PyQt5 ─────────────────────────────────────────────────────────────────────
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLabel, QStatusBar,
    QGroupBox, QListWidget, QListWidgetItem, QTextEdit, QLineEdit,
    QComboBox, QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QFormLayout, QDoubleSpinBox, QProgressBar, QFrame,
    QTabWidget, QCheckBox, QAbstractItemView, QSizePolicy,
    QScrollArea, QPlainTextEdit
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QObject, QSize, QRegExp
)
from PyQt5.QtGui import (
    QColor, QFont, QPalette, QTextCharFormat, QSyntaxHighlighter,
    QTextCursor, QTextDocument
)

# ── pyqtgraph ─────────────────────────────────────────────────────────────────
try:
    import pyqtgraph as pg
    pg.setConfigOption('background', '#0d1117')
    pg.setConfigOption('foreground', '#c9d1d9')
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False

# ── Project modules ───────────────────────────────────────────────────────────
from cytl_monitor_unit import Payload, PacketEvent
from cytl_rules_mg import Rule, RuleSet, _default_rules
from cytl_capture import (
    PcapLoader, LiveCapture, get_interfaces, get_interface_details,
    flags_str, SCAPY_AVAILABLE, InterfaceInfo,
)
from cytl_compiler import compile_formula, build_rule, test_formula, COMPILER_NS

# ──────────────────────────────────────────────────────────────────────────────
# THEME
# ──────────────────────────────────────────────────────────────────────────────
BG_DARK  = '#0d1117'; BG_MID   = '#161b22'; BG_PANEL = '#21262d'
BG_HOVER = '#30363d'; BORDER   = '#30363d'
TEXT_PRIM  = '#c9d1d9'; TEXT_SEC = '#8b949e'; TEXT_MUTED = '#484f58'
ACCENT_BLUE = '#58a6ff'; ACCENT_GRN  = '#3fb950'; ACCENT_RED  = '#f85149'
ACCENT_ORG  = '#d29922'; ACCENT_PRP  = '#bc8cff'; ACCENT_CYAN = '#39d353'

SEVERITY_COLORS = {'HIGH': ACCENT_RED, 'MEDIUM': ACCENT_ORG, 'LOW': ACCENT_BLUE}
PROTO_COLORS    = {'TCP': ACCENT_BLUE, 'UDP': ACCENT_PRP, 'ICMP': ACCENT_ORG, 'OTHER': TEXT_SEC}


def stylesheet() -> str:
    return f"""
    QMainWindow, QDialog {{ background-color:{BG_DARK}; color:{TEXT_PRIM}; }}
    QWidget {{ background-color:{BG_DARK}; color:{TEXT_PRIM};
               font-family:'Segoe UI','Consolas',monospace; font-size:12px; }}
    QGroupBox {{ background-color:{BG_MID}; border:1px solid {BORDER};
                 border-radius:6px; margin-top:12px; padding:8px;
                 font-weight:bold; color:{ACCENT_BLUE}; }}
    QGroupBox::title {{ subcontrol-origin:margin; subcontrol-position:top left;
                        padding:0 6px; color:{ACCENT_BLUE}; }}
    QTableWidget {{ background-color:{BG_MID}; border:1px solid {BORDER};
                    border-radius:4px; gridline-color:{BORDER}; color:{TEXT_PRIM};
                    selection-background-color:{BG_HOVER}; }}
    QTableWidget::item {{ padding:3px 6px; border:none; }}
    QTableWidget::item:hover {{ background-color:{BG_HOVER}; }}
    QHeaderView::section {{ background-color:{BG_PANEL}; color:{TEXT_SEC};
                             border:none; border-bottom:1px solid {BORDER};
                             padding:5px 8px; font-weight:bold; font-size:11px; }}
    QPushButton {{ background-color:{BG_PANEL}; color:{TEXT_PRIM};
                   border:1px solid {BORDER}; border-radius:5px; padding:6px 14px;
                   font-weight:500; }}
    QPushButton:hover {{ background-color:{BG_HOVER}; border-color:{ACCENT_BLUE}; }}
    QPushButton:pressed {{ background-color:{ACCENT_BLUE}; color:{BG_DARK}; }}
    QPushButton:disabled {{ color:{TEXT_MUTED}; border-color:{TEXT_MUTED}; }}
    QPushButton#btn_start {{ background-color:#1a4a1a; border-color:{ACCENT_GRN}; color:{ACCENT_GRN}; font-weight:bold; }}
    QPushButton#btn_start:hover {{ background-color:#2a6a2a; }}
    QPushButton#btn_stop {{ background-color:#4a1a1a; border-color:{ACCENT_RED}; color:{ACCENT_RED}; font-weight:bold; }}
    QPushButton#btn_stop:hover {{ background-color:#6a2a2a; }}
    QPushButton#btn_compile {{ background-color:#1a3a2a; border-color:{ACCENT_GRN}; color:{ACCENT_GRN}; font-weight:bold; }}
    QPushButton#btn_compile:hover {{ background-color:#2a5a3a; }}
    QPushButton#btn_add_rule {{ background-color:#1a2a4a; border-color:{ACCENT_BLUE}; color:{ACCENT_BLUE}; font-weight:bold; }}
    QPushButton#btn_add_rule:hover {{ background-color:#2a4a6a; }}
    QTextEdit, QPlainTextEdit, QLineEdit {{
        background-color:{BG_MID}; border:1px solid {BORDER}; border-radius:4px;
        color:{TEXT_PRIM}; padding:4px 8px;
        font-family:'Consolas','Courier New',monospace; }}
    QTextEdit:focus, QPlainTextEdit:focus, QLineEdit:focus {{ border-color:{ACCENT_BLUE}; }}
    QComboBox {{ background-color:{BG_MID}; border:1px solid {BORDER};
                 border-radius:4px; color:{TEXT_PRIM}; padding:4px 8px; min-width:120px; }}
    QComboBox::drop-down {{ border:none; }}
    QComboBox QAbstractItemView {{ background-color:{BG_PANEL}; border:1px solid {BORDER};
                                   color:{TEXT_PRIM}; selection-background-color:{ACCENT_BLUE}; }}
    QListWidget {{ background-color:{BG_MID}; border:1px solid {BORDER};
                   border-radius:4px; color:{TEXT_PRIM}; outline:none; }}
    QListWidget::item {{ padding:6px 10px; border-radius:3px; }}
    QListWidget::item:hover {{ background-color:{BG_HOVER}; }}
    QListWidget::item:selected {{ background-color:{ACCENT_BLUE}; color:{BG_DARK}; }}
    QScrollBar:vertical {{ background:{BG_MID}; width:8px; border-radius:4px; }}
    QScrollBar::handle:vertical {{ background:{BG_HOVER}; border-radius:4px; min-height:20px; }}
    QScrollBar::handle:vertical:hover {{ background:{TEXT_SEC}; }}
    QScrollBar:horizontal {{ background:{BG_MID}; height:8px; border-radius:4px; }}
    QScrollBar::handle:horizontal {{ background:{BG_HOVER}; border-radius:4px; min-width:20px; }}
    QTabWidget::pane {{ border:1px solid {BORDER}; border-radius:4px; background:{BG_MID}; }}
    QTabBar::tab {{ background:{BG_PANEL}; color:{TEXT_SEC}; padding:6px 16px;
                    border:1px solid {BORDER}; border-bottom:none;
                    border-radius:4px 4px 0 0; margin-right:2px; }}
    QTabBar::tab:selected {{ background:{BG_MID}; color:{ACCENT_BLUE};
                              border-bottom:2px solid {ACCENT_BLUE}; }}
    QTabBar::tab:hover {{ background:{BG_HOVER}; color:{TEXT_PRIM}; }}
    QStatusBar {{ background-color:{BG_PANEL}; color:{TEXT_SEC}; border-top:1px solid {BORDER}; }}
    QSplitter::handle {{ background-color:{BORDER}; width:2px; height:2px; }}
    QProgressBar {{ background-color:{BG_PANEL}; border:1px solid {BORDER};
                    border-radius:4px; text-align:center; color:{TEXT_PRIM}; height:14px; }}
    QProgressBar::chunk {{ background-color:{ACCENT_BLUE}; border-radius:3px; }}
    QDoubleSpinBox, QSpinBox {{ background-color:{BG_MID}; border:1px solid {BORDER};
                                border-radius:4px; color:{TEXT_PRIM}; padding:3px 6px; }}
    QCheckBox {{ color:{TEXT_PRIM}; spacing:6px; }}
    QCheckBox::indicator {{ width:14px; height:14px; border:1px solid {BORDER};
                             border-radius:3px; background:{BG_MID}; }}
    QCheckBox::indicator:checked {{ background:{ACCENT_BLUE}; border-color:{ACCENT_BLUE}; }}
    """


# ──────────────────────────────────────────────────────────────────────────────
# SYNTAX HIGHLIGHTER  (for the rule compiler editor)
# ──────────────────────────────────────────────────────────────────────────────

class CyTLHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for CyTL formula expressions."""

    def __init__(self, document: QTextDocument):
        super().__init__(document)
        self._rules: List[Tuple[QRegExp, QTextCharFormat]] = []

        def fmt(color, bold=False, italic=False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:   f.setFontWeight(QFont.Bold)
            if italic: f.setFontItalic(True)
            return f

        # CyTL operators / keywords
        kw_fmt = fmt(ACCENT_BLUE, bold=True)
        for kw in ['counting', 'min_op', 'max_op', 'weight', 'const',
                   'Constant', 'WeightFn', 'CountingOp', 'MinOp', 'MaxOp',
                   'Until', 'ShiftForward', 'ShiftBack',
                   'PacketModality', 'Filter',
                   'Negation', 'Disjunction', 'Conjunction',
                   'TRUE', 'FALSE']:
            self._rules.append((QRegExp(rf'\b{kw}\b'), kw_fmt))

        # Weight function names
        wfn_fmt = fmt(ACCENT_CYAN)
        for wfn in ['w_SYN', 'w_ACK', 'w_SYN_ACK', 'w_FIN', 'w_RST',
                    'w_SIZE', 'w_ONE', 'w_UDP', 'w_ICMP']:
            self._rules.append((QRegExp(rf'\b{wfn}\b'), wfn_fmt))

        # Predicate helpers
        pred_fmt = fmt(ACCENT_PRP)
        for p in ['pred_syn', 'pred_ack', 'pred_syn_ack', 'pred_fin',
                  'pred_rst', 'pred_tcp', 'pred_udp', 'pred_icmp']:
            self._rules.append((QRegExp(rf'\b{p}\b'), pred_fmt))

        # Numbers
        self._rules.append((QRegExp(r'\b\d+\.?\d*\b'), fmt(ACCENT_ORG)))

        # Operators
        self._rules.append((QRegExp(r'[><=!+\-*/|&~]+'), fmt('#79c0ff')))

        # Parentheses / brackets
        self._rules.append((QRegExp(r'[\(\)\[\]]'), fmt(TEXT_SEC)))

        # Comments
        self._rules.append((QRegExp(r'#[^\n]*'), fmt(TEXT_MUTED, italic=True)))

        # Strings
        self._rules.append((QRegExp(r'"[^"]*"'), fmt(ACCENT_GRN)))
        self._rules.append((QRegExp(r"'[^']*'"), fmt(ACCENT_GRN)))

    def highlightBlock(self, text: str):
        for pattern, fmt in self._rules:
            idx = pattern.indexIn(text)
            while idx >= 0:
                length = pattern.matchedLength()
                self.setFormat(idx, length, fmt)
                idx = pattern.indexIn(text, idx + length)


# ──────────────────────────────────────────────────────────────────────────────
# INTERFACE SELECTOR DIALOG
# ──────────────────────────────────────────────────────────────────────────────

class InterfaceSelectorDialog(QDialog):
    """
    Full-featured network interface selector.
    Shows all interfaces with IP, MAC, description, and live status.
    Lets the user pick an interface and optionally set a BPF capture filter.
    """

    # Emits (device_id, label, bpf_filter) when the user confirms
    interface_selected = pyqtSignal(str, str, str)

    # Status → colour mapping
    _STATUS_COLORS = {
        'ACTIVE':       ACCENT_GRN,
        'LOOPBACK':     ACCENT_BLUE,
        'VIRTUAL':      TEXT_SEC,
        'DISCONNECTED': TEXT_MUTED,
    }
    _STATUS_ICONS = {
        'ACTIVE':       '●',
        'LOOPBACK':     '⟳',
        'VIRTUAL':      '◌',
        'DISCONNECTED': '○',
    }

    def __init__(self, current_dev: str = '', current_bpf: str = '', parent=None):
        super().__init__(parent)
        self.setWindowTitle('Select Network Interface')
        self.setMinimumSize(820, 520)
        self.resize(900, 560)
        self.setStyleSheet(stylesheet())

        self._interfaces: List[InterfaceInfo] = []
        self._current_dev = current_dev
        self._selected_dev = current_dev
        self._selected_label = ''

        self._build_ui(current_bpf)
        self._load_interfaces()

    # ── Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self, current_bpf: str):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Header
        hdr = QLabel('Network Interface Selection')
        hdr.setStyleSheet(
            f'font-size:16px; font-weight:bold; color:{ACCENT_BLUE};')
        sub = QLabel(
            'Select the interface to capture from. '
            'Double-click or press Select to confirm.')
        sub.setStyleSheet(f'color:{TEXT_SEC}; font-size:11px;')
        root.addWidget(hdr)
        root.addWidget(sub)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f'color:{BORDER};')
        root.addWidget(sep)

        # Legend
        leg_row = QHBoxLayout()
        for status, col in self._STATUS_COLORS.items():
            icon = self._STATUS_ICONS[status]
            lbl = QLabel(f'{icon} {status}')
            lbl.setStyleSheet(f'color:{col}; font-size:11px; padding:0 8px;')
            leg_row.addWidget(lbl)
        leg_row.addStretch()
        btn_refresh = QPushButton('↺  Refresh')
        btn_refresh.setMaximumWidth(100)
        btn_refresh.clicked.connect(self._load_interfaces)
        leg_row.addWidget(btn_refresh)
        root.addLayout(leg_row)

        # Interface table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ['', 'Name', 'Description', 'IP Address', 'MAC Address', 'Status'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.table.setColumnWidth(0, 28)   # icon
        self.table.setColumnWidth(1, 180)  # name
        self.table.setColumnWidth(2, 240)  # description
        self.table.setColumnWidth(3, 130)  # IP
        self.table.setColumnWidth(4, 130)  # MAC
        self.table.horizontalHeader().setStretchLastSection(True)  # status
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.itemDoubleClicked.connect(self._on_double_click)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        root.addWidget(self.table, 1)

        # Detail panel
        detail_grp = QGroupBox('Interface Details')
        detail_l = QHBoxLayout(detail_grp)
        detail_l.setContentsMargins(8, 8, 8, 8)
        self.detail_lbl = QLabel('Select an interface to see details.')
        self.detail_lbl.setWordWrap(True)
        self.detail_lbl.setStyleSheet(
            f'color:{TEXT_SEC}; font-family:Consolas; font-size:11px;')
        detail_l.addWidget(self.detail_lbl)
        root.addWidget(detail_grp)

        # BPF filter
        bpf_grp = QGroupBox('BPF Capture Filter  (optional)')
        bpf_l = QVBoxLayout(bpf_grp)
        bpf_l.setContentsMargins(8, 8, 8, 8)
        bpf_top = QHBoxLayout()
        self.bpf_edit = QLineEdit(current_bpf)
        self.bpf_edit.setFont(QFont('Consolas', 11))
        self.bpf_edit.setPlaceholderText(
            'e.g.  tcp  |  port 80  |  host 192.168.1.1  |  tcp and port 443')
        bpf_top.addWidget(self.bpf_edit, 1)

        # Quick BPF presets
        preset_combo = QComboBox()
        preset_combo.setMinimumWidth(170)
        preset_combo.addItems([
            '— quick preset —',
            'TCP only',
            'UDP only',
            'ICMP only',
            'HTTP (port 80)',
            'HTTPS (port 443)',
            'DNS (port 53)',
            'SSH (port 22)',
            'No loopback (not lo)',
            'Clear filter',
        ])
        preset_combo.currentIndexChanged.connect(self._apply_bpf_preset)
        bpf_top.addWidget(preset_combo)
        bpf_l.addLayout(bpf_top)

        bpf_hint = QLabel(
            'BPF syntax: tcpdump-compatible expressions.  '
            'Leave empty to capture all traffic.')
        bpf_hint.setStyleSheet(f'color:{TEXT_MUTED}; font-size:10px;')
        bpf_l.addWidget(bpf_hint)
        root.addWidget(bpf_grp)

        # Buttons
        btn_row = QHBoxLayout()
        self.btn_select = QPushButton('✔  Select Interface')
        self.btn_select.setObjectName('btn_compile')   # reuse green style
        self.btn_select.clicked.connect(self._confirm)
        self.btn_select.setEnabled(False)

        btn_cancel = QPushButton('Cancel')
        btn_cancel.clicked.connect(self.reject)

        self.selected_lbl = QLabel('No interface selected')
        self.selected_lbl.setStyleSheet(f'color:{TEXT_SEC}; font-size:11px;')

        btn_row.addWidget(self.selected_lbl, 1)
        btn_row.addWidget(self.btn_select)
        btn_row.addWidget(btn_cancel)
        root.addLayout(btn_row)

    # ── Data loading ───────────────────────────────────────────────────────

    def _load_interfaces(self):
        self.table.setRowCount(0)
        self._interfaces = get_interface_details()

        # Sort: active first, then virtual/disconnected, loopback last
        def sort_key(i: InterfaceInfo) -> int:
            s = i.status_badge
            return {'ACTIVE': 0, 'VIRTUAL': 1, 'DISCONNECTED': 2, 'LOOPBACK': 3}.get(s, 2)

        self._interfaces.sort(key=sort_key)

        for iface in self._interfaces:
            self._add_row(iface)

        # Re-select previously chosen interface
        if self._current_dev:
            for row in range(self.table.rowCount()):
                if self.table.item(row, 0) and \
                   self.table.item(row, 0).data(Qt.UserRole) == self._current_dev:
                    self.table.selectRow(row)
                    break

    def _add_row(self, iface: InterfaceInfo):
        row = self.table.rowCount()
        self.table.insertRow(row)
        status = iface.status_badge
        col    = self._STATUS_COLORS.get(status, TEXT_SEC)
        icon   = self._STATUS_ICONS.get(status, '●')

        # Icon cell — carries the device_id as UserRole
        icon_item = QTableWidgetItem(icon)
        icon_item.setTextAlignment(Qt.AlignCenter)
        icon_item.setForeground(QColor(col))
        icon_item.setData(Qt.UserRole, iface.dev_id)   # hidden payload
        self.table.setItem(row, 0, icon_item)

        cells = [
            (iface.name,        TEXT_PRIM if iface.is_connected else TEXT_MUTED),
            (iface.description, TEXT_SEC),
            (iface.ip  or '—',  ACCENT_CYAN if iface.ip else TEXT_MUTED),
            (iface.mac or '—',  TEXT_SEC),
            (status,            col),
        ]
        for col_idx, (text, fg) in enumerate(cells, start=1):
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            item.setForeground(QColor(fg))
            if col_idx == 6:  # status
                item.setFont(QFont('Segoe UI', 10, QFont.Bold))
            self.table.setItem(row, col_idx, item)

        # Dim disconnected rows
        if not iface.is_connected:
            for c in range(self.table.columnCount()):
                it = self.table.item(row, c)
                if it:
                    it.setForeground(QColor(TEXT_MUTED))

    # ── Interaction ────────────────────────────────────────────────────────

    def _on_selection(self):
        rows = self.table.selectedItems()
        if not rows:
            return
        row = self.table.currentRow()
        dev_id = self.table.item(row, 0).data(Qt.UserRole)
        iface  = next((i for i in self._interfaces if i.dev_id == dev_id), None)
        if not iface:
            return
        self._selected_dev   = iface.dev_id
        self._selected_label = iface.label
        self.btn_select.setEnabled(True)
        self.selected_lbl.setText(
            f'<span style="color:{ACCENT_GRN}">Selected: </span>'
            f'<b>{iface.name}</b>')
        self.selected_lbl.setTextFormat(Qt.RichText)

        # Detail pane
        status_c = self._STATUS_COLORS.get(iface.status_badge, TEXT_SEC)
        self.detail_lbl.setText(
            f'<span style="color:{TEXT_SEC}">Name:</span> '
            f'<b style="color:{TEXT_PRIM}">{iface.name}</b>&nbsp;&nbsp;&nbsp;'
            f'<span style="color:{TEXT_SEC}">Device:</span> '
            f'<span style="color:{TEXT_MUTED}; font-size:10px;">{iface.dev_id}</span><br>'
            f'<span style="color:{TEXT_SEC}">Description:</span> {iface.description}<br>'
            f'<span style="color:{TEXT_SEC}">IP:</span> '
            f'<b style="color:{ACCENT_CYAN}">{iface.ip or "—"}</b>&nbsp;&nbsp;'
            f'<span style="color:{TEXT_SEC}">MAC:</span> '
            f'<span style="color:{TEXT_SEC}">{iface.mac or "—"}</span><br>'
            f'<span style="color:{TEXT_SEC}">Flags:</span> '
            f'<span style="color:{TEXT_MUTED}">{iface.flags}</span>&nbsp;&nbsp;'
            f'<span style="color:{TEXT_SEC}">Status:</span> '
            f'<b style="color:{status_c}">{iface.status_badge}</b>'
        )
        self.detail_lbl.setTextFormat(Qt.RichText)

    def _on_double_click(self, _):
        if self._selected_dev:
            self._confirm()

    def _apply_bpf_preset(self, idx: int):

        presets = {
            1: 'tcp', 2: 'udp', 3: 'icmp',
            4: 'tcp port 80', 5: 'tcp port 443',
            6: 'port 53',     7: 'tcp port 22',
            8: 'not loopback', 9: '',
        }
        if idx in presets:
            self.bpf_edit.setText(presets[idx])
        # reset combo to placeholder
        self.sender().setCurrentIndex(0)

    def _confirm(self):
        if not self._selected_dev:
            QMessageBox.warning(self, 'No interface', 'Please select an interface.')
            return
        bpf = self.bpf_edit.text().strip()
        self.interface_selected.emit(self._selected_dev, self._selected_label, bpf)
        self.accept()

    # ── Public accessors ───────────────────────────────────────────────────

    def selected_device(self) -> str:
        return self._selected_dev

    def bpf_filter(self) -> str:
        return self.bpf_edit.text().strip()


# ──────────────────────────────────────────────────────────────────────────────
# RULE COMPILER DIALOG
# ──────────────────────────────────────────────────────────────────────────────

class RuleCompilerDialog(QDialog):
    """
    Full-featured CyTL Rule Compiler.
    Users write formulas in Python-expression syntax using all CyTL operators.
    """
    rule_added = pyqtSignal(object)   # emits Rule

    def __init__(self, existing_rule: Optional[Rule] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle('CyTL Rule Compiler')
        self.setMinimumSize(1100, 780)
        self.resize(1200, 860)
        self.setStyleSheet(stylesheet())

        self._compile_timer = QTimer(self)
        self._compile_timer.setSingleShot(True)
        self._compile_timer.timeout.connect(self._do_compile)
        self._last_result = None

        self._build_ui(existing_rule)

    # ── Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self, existing_rule: Optional[Rule]):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Title row
        title = QLabel('CyTL Rule Compiler')
        title.setStyleSheet(
            f'font-size:18px; font-weight:bold; color:{ACCENT_BLUE}; padding:4px 0;')
        sub = QLabel(
            'Write a formula using CyTL operators, compile to validate, '
            'then add to the active rule set.')
        sub.setStyleSheet(f'color:{TEXT_SEC}; font-size:11px;')
        root.addWidget(title)
        root.addWidget(sub)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f'color:{BORDER};'); root.addWidget(sep)

        # Main horizontal split: editor | results
        hsplit = QSplitter(Qt.Horizontal)
        root.addWidget(hsplit, 1)

        # ── LEFT: metadata + editor ────────────────────────────────────────
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 4, 0)
        ll.setSpacing(6)

        # Metadata form
        meta_grp = QGroupBox('Rule Metadata')
        mf = QFormLayout(meta_grp)
        mf.setLabelAlignment(Qt.AlignRight)

        self.name_edit = QLineEdit(existing_rule.name if existing_rule else 'My Custom Rule')
        self.name_edit.setPlaceholderText('Unique rule name')
        mf.addRow('Name:', self.name_edit)

        self.desc_edit = QLineEdit(
            existing_rule.description.split('\n')[0] if existing_rule else '')
        self.desc_edit.setPlaceholderText('Short description of the attack')
        mf.addRow('Description:', self.desc_edit)

        row1 = QHBoxLayout()
        self.sev_combo = QComboBox()
        self.sev_combo.addItems(['HIGH', 'MEDIUM', 'LOW'])
        if existing_rule:
            self.sev_combo.setCurrentText(existing_rule.severity)
        self.cat_edit = QLineEdit(existing_rule.category if existing_rule else 'Custom')
        self.cat_edit.setPlaceholderText('e.g. DDoS, Reconnaissance…')
        row1.addWidget(self.sev_combo)
        row1.addWidget(QLabel('Category:'))
        row1.addWidget(self.cat_edit, 1)
        mf.addRow('Severity:', row1)

        self.window_spin = QDoubleSpinBox()
        self.window_spin.setRange(1, 3600)
        self.window_spin.setValue(existing_rule.window_size if existing_rule else 60.0)
        self.window_spin.setSuffix(' s')
        self.window_spin.setToolTip('Sliding window size for the monitor')
        mf.addRow('Monitor Window:', self.window_spin)

        ll.addWidget(meta_grp)

        # Formula editor
        editor_grp = QGroupBox('CyTL Formula Expression')
        el = QVBoxLayout(editor_grp)
        el.setContentsMargins(4, 8, 4, 4)

        # Template quick-insert bar
        tmpl_row = QHBoxLayout()
        tmpl_lbl = QLabel('Insert template:')
        tmpl_lbl.setStyleSheet(f'color:{TEXT_SEC}; font-size:11px;')
        self.tmpl_combo = QComboBox()
        self.tmpl_combo.setMinimumWidth(260)
        self.tmpl_combo.addItems([
            '— select template —',
            'DDoS SYN Flood',
            'High Packet Rate',
            'SYN / ACK Ratio',
            'ICMP Flood',
            'UDP Flood',
            'Large Payload',
            'TCP RST Flood',
            'Until (temporal)',
            'ShiftBack (past shift)',
            'Filter (TCP only)',
            'Conjunction (AND)',
        ])
        self.tmpl_combo.currentIndexChanged.connect(self._insert_template)
        btn_clear = QPushButton('Clear')
        btn_clear.setMaximumWidth(60)
        btn_clear.clicked.connect(lambda: self.editor.clear())
        tmpl_row.addWidget(tmpl_lbl)
        tmpl_row.addWidget(self.tmpl_combo, 1)
        tmpl_row.addWidget(btn_clear)
        el.addLayout(tmpl_row)

        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont('Consolas', 12))
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.editor.setPlaceholderText(
            '# Write a CyTL formula expression here\n'
            '# Example — DDoS SYN flood:\n'
            'counting(0, 10, w_SYN) - counting(0, 10, w_ACK) > 100')
        font_metrics = self.editor.fontMetrics()
        self.editor.setMinimumHeight(font_metrics.height() * 8)
        self._highlighter = CyTLHighlighter(self.editor.document())
        self.editor.textChanged.connect(self._on_text_changed)
        el.addWidget(self.editor, 1)

        if existing_rule:
            self.editor.setPlainText(str(existing_rule.formula))

        # Compile status bar (inline)
        self.inline_status = QLabel('  Type a formula above…')
        self.inline_status.setStyleSheet(
            f'color:{TEXT_MUTED}; font-size:11px; padding:2px 4px;')
        el.addWidget(self.inline_status)

        ll.addWidget(editor_grp, 1)

        # Reference quick-guide
        ref_grp = QGroupBox('Quick Reference')
        rl = QVBoxLayout(ref_grp)
        ref = QPlainTextEdit()
        ref.setReadOnly(True)
        ref.setFont(QFont('Consolas', 10))
        ref.setMaximumHeight(160)
        ref.setPlainText(
            'WEIGHT FUNCTIONS:  w_SYN  w_ACK  w_SYN_ACK  w_FIN  w_RST  w_SIZE  w_ONE  w_UDP  w_ICMP\n'
            'COUNTING (Def.1):  counting(ta, tb, w)         — #[ta,tb][w]   sliding-window sum\n'
            '                   min_op(ta, tb, rho)         — min[ta,tb][rho]\n'
            '                   max_op(ta, tb, rho)         — max[ta,tb][rho]\n'
            'ARITHMETIC:        +   -   *   /   -rho   (op ∈ {+,−,×,÷})\n'
            'COMPARISONS:       > >= < <=   .eq()  .neq()   (return Formula)\n'
            'LOGIC (Def.2):     phi1 | phi2   phi1 & phi2   ~phi\n'
            'TEMPORAL:          Until(phi1, phi2, ta, tb)   φ1 U[ta,tb] φ2\n'
            '                   ShiftForward(phi, a)        φ≫a  (future shift)\n'
            '                   ShiftBack(phi, a)           φ≪a  (past shift)\n'
            'MODALITY:          PacketModality(pred, ta, tb, phi)   ⟨β⟩[ta,tb]φ\n'
            'FILTERING:         Filter(pred, phi)                   β ▷ φ\n'
            'PREDICATES:        pred_syn  pred_ack  pred_tcp  pred_udp  pred_icmp'
        )
        self._highlighter2 = CyTLHighlighter(ref.document())
        rl.addWidget(ref)
        ll.addWidget(ref_grp)

        # Bottom buttons
        btn_row = QHBoxLayout()
        self.btn_compile = QPushButton('⚙  Compile & Validate')
        self.btn_compile.setObjectName('btn_compile')
        self.btn_compile.clicked.connect(self._do_compile)

        self.btn_add = QPushButton('✚  Add to Active Rules')
        self.btn_add.setObjectName('btn_add_rule')
        self.btn_add.setEnabled(False)
        self.btn_add.clicked.connect(self._add_rule)

        btn_close = QPushButton('Close')
        btn_close.clicked.connect(self.reject)

        btn_row.addWidget(self.btn_compile)
        btn_row.addWidget(self.btn_add)
        btn_row.addStretch()
        btn_row.addWidget(btn_close)
        ll.addLayout(btn_row)

        hsplit.addWidget(left)

        # ── RIGHT: results tabs ────────────────────────────────────────────
        right = QWidget()
        rl2 = QVBoxLayout(right)
        rl2.setContentsMargins(4, 0, 0, 0)
        rl2.setSpacing(6)

        tabs = QTabWidget()
        rl2.addWidget(tabs)

        # Tab 1: Compilation result
        tab_result = QWidget()
        trl = QVBoxLayout(tab_result)
        trl.setContentsMargins(4, 4, 4, 4)

        self.result_status = QLabel('Not compiled yet')
        self.result_status.setStyleSheet(
            f'font-size:13px; font-weight:bold; color:{TEXT_SEC}; padding:4px;')
        trl.addWidget(self.result_status)

        self.result_formula = QPlainTextEdit()
        self.result_formula.setReadOnly(True)
        self.result_formula.setFont(QFont('Consolas', 11))
        self.result_formula.setMaximumHeight(60)
        self.result_formula.setPlaceholderText('Compiled formula will appear here…')
        trl.addWidget(self.result_formula)

        info_row = QHBoxLayout()
        self.lbl_horizon = self._info_card('Horizon', '—')
        self.lbl_complexity = self._info_card('Operators', '—')
        info_row.addWidget(self.lbl_horizon[0])
        info_row.addWidget(self.lbl_complexity[0])
        info_row.addStretch()
        trl.addLayout(info_row)

        err_lbl = QLabel('Errors / Warnings:')
        err_lbl.setStyleSheet(f'color:{TEXT_SEC}; font-weight:bold;')
        trl.addWidget(err_lbl)

        self.error_box = QPlainTextEdit()
        self.error_box.setReadOnly(True)
        self.error_box.setFont(QFont('Consolas', 11))
        self.error_box.setMaximumHeight(80)
        trl.addWidget(self.error_box)

        trl.addStretch()
        tabs.addTab(tab_result, '⚙ Compilation')

        # Tab 2: Formula Tree
        tab_tree = QWidget()
        ttl = QVBoxLayout(tab_tree)
        ttl.setContentsMargins(4, 4, 4, 4)
        tree_lbl = QLabel('Formula Parse Tree:')
        tree_lbl.setStyleSheet(f'color:{TEXT_SEC}; font-weight:bold;')
        ttl.addWidget(tree_lbl)
        self.tree_view = QPlainTextEdit()
        self.tree_view.setReadOnly(True)
        self.tree_view.setFont(QFont('Consolas', 11))
        ttl.addWidget(self.tree_view)
        tabs.addTab(tab_tree, '🌳 Formula Tree')

        # Tab 3: Test Panel
        tab_test = QWidget()
        test_l = QVBoxLayout(tab_test)
        test_l.setContentsMargins(4, 4, 4, 4)

        test_ctrl = QHBoxLayout()
        sc_lbl = QLabel('Scenario:')
        sc_lbl.setStyleSheet(f'color:{TEXT_SEC};')
        self.scenario_combo = QComboBox()
        self.scenario_combo.addItems([
            'SYN Flood', 'Normal Traffic', 'ICMP Flood', 'UDP Traffic'])
        npkt_lbl = QLabel('Packets:')
        npkt_lbl.setStyleSheet(f'color:{TEXT_SEC};')
        self.npkt_spin = QDoubleSpinBox()
        self.npkt_spin.setRange(5, 500)
        self.npkt_spin.setValue(30)
        self.npkt_spin.setDecimals(0)
        btn_test = QPushButton('▶  Run Test')
        btn_test.clicked.connect(self._run_test)
        test_ctrl.addWidget(sc_lbl)
        test_ctrl.addWidget(self.scenario_combo)
        test_ctrl.addWidget(npkt_lbl)
        test_ctrl.addWidget(self.npkt_spin)
        test_ctrl.addWidget(btn_test)
        test_ctrl.addStretch()
        test_l.addLayout(test_ctrl)

        self.test_table = QTableWidget(0, 4)
        self.test_table.setHorizontalHeaderLabels(
            ['Time (s)', 'Robustness', 'Verdict', 'Packet Summary'])
        self.test_table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.test_table.setColumnWidth(0, 80)
        self.test_table.setColumnWidth(1, 100)
        self.test_table.setColumnWidth(2, 70)
        self.test_table.horizontalHeader().setStretchLastSection(True)
        self.test_table.verticalHeader().setVisible(False)
        self.test_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.test_table.verticalHeader().setDefaultSectionSize(22)
        test_l.addWidget(self.test_table)

        self.test_summary = QLabel('')
        self.test_summary.setStyleSheet(f'color:{TEXT_SEC}; font-size:11px; padding:4px;')
        test_l.addWidget(self.test_summary)

        tabs.addTab(tab_test, '▶ Test')

        # Tab 4: Operator Reference
        tab_ref = QWidget()
        ref_l = QVBoxLayout(tab_ref)
        ref_l.setContentsMargins(4, 4, 4, 4)
        full_ref = QPlainTextEdit()
        full_ref.setReadOnly(True)
        full_ref.setFont(QFont('Consolas', 10))
        full_ref.setPlainText(__import__('cytl_compiler').__doc__)
        self._hl_ref = CyTLHighlighter(full_ref.document())
        ref_l.addWidget(full_ref)
        tabs.addTab(tab_ref, '📖 Reference')

        hsplit.addWidget(right)
        hsplit.setStretchFactor(0, 1)
        hsplit.setStretchFactor(1, 1)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _info_card(self, label: str, value: str):
        frame = QFrame()
        frame.setStyleSheet(
            f'QFrame {{ background:{BG_PANEL}; border:1px solid {BORDER}; '
            f'border-radius:4px; padding:4px; }}')
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(8, 4, 8, 4)
        fl.setSpacing(1)
        val_lbl = QLabel(value)
        val_lbl.setStyleSheet(
            f'color:{ACCENT_CYAN}; font-family:Consolas; font-size:14px; '
            f'font-weight:bold; border:none; background:transparent;')
        val_lbl.setAlignment(Qt.AlignCenter)
        lbl_lbl = QLabel(label)
        lbl_lbl.setStyleSheet(
            f'color:{TEXT_SEC}; font-size:10px; border:none; background:transparent;')
        lbl_lbl.setAlignment(Qt.AlignCenter)
        fl.addWidget(val_lbl)
        fl.addWidget(lbl_lbl)
        return frame, val_lbl

    # ── Template insertion ─────────────────────────────────────────────────

    def _insert_template(self, idx: int):
        if idx == 0:
            return
        w = self.window_spin.value()
        templates = {
            1:  f'# DDoS SYN Flood (Example 5 from CyTL paper)\n'
                f'# ρhalfOpen = ρNumSYN − ρNumACK > threshold\n'
                f'counting(0, {w:.0f}, w_SYN) - counting(0, {w:.0f}, w_ACK) > 100',
            2:  f'# High packet rate\n'
                f'counting(0, {w:.0f}, w_ONE) > 200',
            3:  f'# SYN / ACK ratio — many SYN but few ACK\n'
                f'(counting(0, {w:.0f}, w_SYN) - counting(0, {w:.0f}, w_ACK) * 0.1) > 50',
            4:  f'# ICMP flood\n'
                f'counting(0, {w:.0f}, w_ICMP) > 50',
            5:  f'# UDP flood\n'
                f'counting(0, {w:.0f}, w_UDP) > 200',
            6:  f'# Large payload volume (potential exfiltration)\n'
                f'counting(0, {w:.0f}, w_SIZE) > 1000000',
            7:  f'# TCP RST flood\n'
                f'counting(0, {w:.0f}, w_RST) > 30',
            8:  f'# Temporal: SYN flood UNTIL ACK responses drop\n'
                f'# φ1 U[ta,tb] φ2  — φ2 must hold at some point in [ta,tb]\n'
                f'Until(\n'
                f'    counting(0, {w:.0f}, w_SYN) > 50,   # φ1: high SYN\n'
                f'    counting(0, {w:.0f}, w_ACK) < 5,    # φ2: almost no ACK\n'
                f'    0, {w*2:.0f}\n'
                f')',
            9:  f'# ShiftBack: flood condition that held {w/2:.0f}s ago (past shift φ≪a)\n'
                f'ShiftBack(\n'
                f'    counting(0, {w:.0f}, w_SYN) - counting(0, {w:.0f}, w_ACK) > 100,\n'
                f'    {w/2:.0f}\n'
                f')',
            10: f'# Filter: restrict to TCP traffic only, then apply rule\n'
                f'Filter(\n'
                f'    pred_tcp,\n'
                f'    counting(0, {w:.0f}, w_ONE) > 300,\n'
                f"    'is_tcp'\n"
                f')',
            11: f'# Conjunction: high rate AND large payloads\n'
                f'(counting(0, {w:.0f}, w_ONE) > 100) & (counting(0, {w:.0f}, w_SIZE) > 500000)',
        }
        txt = templates.get(idx, '')
        if txt:
            self.editor.setPlainText(txt)
        self.tmpl_combo.setCurrentIndex(0)

    # ── Compile logic ──────────────────────────────────────────────────────

    def _on_text_changed(self):
        self.inline_status.setText(f'  <span style="color:{TEXT_MUTED}">Compiling…</span>')
        self.inline_status.setTextFormat(Qt.RichText)
        self._compile_timer.start(600)   # debounce 600ms

    def _do_compile(self):
        expr = self.editor.toPlainText().strip()
        if not expr:
            self.result_status.setText('Empty formula')
            self.result_status.setStyleSheet(
                f'font-size:13px; font-weight:bold; color:{TEXT_MUTED}; padding:4px;')
            self.btn_add.setEnabled(False)
            return

        result = compile_formula(expr)
        self._last_result = result

        if result.success:
            self.result_status.setText('✔  Compiled successfully')
            self.result_status.setStyleSheet(
                f'font-size:13px; font-weight:bold; color:{ACCENT_GRN}; padding:4px;')
            self.inline_status.setText(
                f'  <span style="color:{ACCENT_GRN}">✔ OK — horizon: {result.horizon_val:.1f}s</span>')
            self.result_formula.setPlainText(result.formula_str)
            self.lbl_horizon[1].setText(f'{result.horizon_val:.1f} s')
            self.lbl_complexity[1].setText(result.complexity)
            self.tree_view.setPlainText(result.tree_str)

            msgs = []
            if result.warnings:
                msgs += [f'⚠ {w}' for w in result.warnings]
            self.error_box.setPlainText('\n'.join(msgs) if msgs else '(none)')
            self.error_box.setStyleSheet(
                f'color:{ACCENT_ORG}; background:{BG_MID}; border:1px solid {BORDER};')

            self.btn_add.setEnabled(True)
        else:
            self.result_status.setText('✘  Compilation failed')
            self.result_status.setStyleSheet(
                f'font-size:13px; font-weight:bold; color:{ACCENT_RED}; padding:4px;')
            self.inline_status.setText(
                f'  <span style="color:{ACCENT_RED}">✘ Error</span>')
            self.result_formula.clear()
            self.lbl_horizon[1].setText('—')
            self.lbl_complexity[1].setText('—')
            self.tree_view.clear()
            self.error_box.setPlainText(result.error)
            self.error_box.setStyleSheet(
                f'color:{ACCENT_RED}; background:{BG_MID}; border:1px solid {BORDER};')
            self.btn_add.setEnabled(False)

        self.inline_status.setTextFormat(Qt.RichText)

    # ── Test ────────────────────────────────────────────────────────────────

    def _run_test(self):
        if not self._last_result or not self._last_result.success:
            QMessageBox.warning(self, 'Compile first',
                                'Please compile the formula successfully before testing.')
            return
        scenario_map = {
            'SYN Flood':     'syn_flood',
            'Normal Traffic':'normal',
            'ICMP Flood':    'icmp_flood',
            'UDP Traffic':   'udp',
        }
        scenario = scenario_map.get(self.scenario_combo.currentText(), 'syn_flood')
        n = int(self.npkt_spin.value())

        try:
            rows = test_formula(
                self._last_result.formula, scenario,
                window=self.window_spin.value(), n_packets=n)
        except Exception as e:
            QMessageBox.critical(self, 'Test Error', str(e))
            return

        self.test_table.setRowCount(0)
        violations = 0
        for r in rows:
            row = self.test_table.rowCount()
            self.test_table.insertRow(row)
            rob = r['robustness']
            verd = r['verdict']

            t_item  = QTableWidgetItem(f"{r['t']:.3f}")
            r_item  = QTableWidgetItem(f"{rob:.3f}")
            v_item  = QTableWidgetItem(
                'VIOLATION' if verd is False else ('SATISFIED' if verd is True else '…'))
            p_item  = QTableWidgetItem(r['payload_summary'])

            for item in (t_item, r_item, v_item, p_item):
                item.setTextAlignment(Qt.AlignCenter)

            if rob < 0:
                r_item.setForeground(QColor(ACCENT_RED))
                violations += 1
            elif rob > 0:
                r_item.setForeground(QColor(ACCENT_GRN))

            if verd is False:
                v_item.setForeground(QColor(ACCENT_RED))
                v_item.setFont(QFont('Segoe UI', 10, QFont.Bold))

            for col, item in enumerate((t_item, r_item, v_item, p_item)):
                self.test_table.setItem(row, col, item)

        col = ACCENT_RED if violations else ACCENT_GRN
        self.test_summary.setText(
            f'<span style="color:{col}">{violations} violation(s) detected '
            f'out of {n} packets in scenario "{self.scenario_combo.currentText()}"</span>')
        self.test_summary.setTextFormat(Qt.RichText)

    # ── Add rule ────────────────────────────────────────────────────────────

    def _add_rule(self):
        if not self._last_result or not self._last_result.success:
            return
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, 'Missing name', 'Please enter a rule name.')
            return

        rule = build_rule(
            name=name,
            description=self.desc_edit.text().strip() or name,
            severity=self.sev_combo.currentText(),
            category=self.cat_edit.text().strip() or 'Custom',
            window_size=self.window_spin.value(),
            formula=self._last_result.formula,
        )
        self.rule_added.emit(rule)
        QMessageBox.information(
            self, 'Rule Added',
            f'Rule "{name}" has been added to the active rule set.')


# ──────────────────────────────────────────────────────────────────────────────
# WORKER THREAD
# ──────────────────────────────────────────────────────────────────────────────

class CaptureWorker(QObject):
    # Carries List[Tuple[PacketEvent, List[RuleHit]]]
    packet_received = pyqtSignal(object)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    done = pyqtSignal()

    _BATCH_INTERVAL_MS = 100
    _BATCH_SIZE = 2000

    def __init__(self):
        super().__init__()
        self._pcap: Optional[PcapLoader] = None
        self._live: Optional[LiveCapture] = None
        self._sim_stop = threading.Event()
        self._sim_thread: Optional[threading.Thread] = None
        self._ruleset: Optional[RuleSet] = None
        self._results_buffer: collections.deque = collections.deque()
        self._last_progress_emit: float = 0.0

    def set_ruleset(self, ruleset: RuleSet) -> None:
        self._ruleset = ruleset

    def _init_batch_timer(self):
        self._batch_timer = QTimer(self)
        self._batch_timer.timeout.connect(self._emit_batch)
        self._batch_timer.start(self._BATCH_INTERVAL_MS)

    def _emit_batch(self):
        if not self._results_buffer:
            return

        batch = []
        for _ in range(self._BATCH_SIZE):
            try:
                batch.append(self._results_buffer.popleft())
            except IndexError:
                break

        if batch:
            self.packet_received.emit(batch)

    def _on_loader_progress(self, c: int, t: int):
        now = time.time()
        if c == 1 or (now - self._last_progress_emit) >= 0.20:
            self._last_progress_emit = now
            self.progress.emit(c, t)

    # ── PCAP ──────────────────────────────────────────────────────────────
    def load_pcap(self, filepath: str):
        self._last_progress_emit = 0.0
        base = os.path.basename(filepath)
        self._pcap = PcapLoader(
            callback=self._emit_pkt,
            speed=0.0,
            on_done=self._on_done,
            on_progress=self._on_loader_progress,
            on_error=lambda e: self.error_occurred.emit(e),
            on_source=lambda name: self.status_changed.emit(f'Loading {name}…'),
        )
        if base.lower().endswith('.zip'):
            self.status_changed.emit(f'Opening archive {base}…')
        else:
            self.status_changed.emit(f'Loading {base}…')
        self._pcap.load(filepath)

    def stop_pcap(self):
        if self._pcap:
            self._pcap.stop()

    # ── Live ──────────────────────────────────────────────────────────────
    def start_live(self, iface: str, bpf: str):
        self._live = LiveCapture(
            callback=self._emit_pkt,
            iface=iface,
            bpf_filter=bpf,
            on_error=lambda e: self.error_occurred.emit(e),
        )
        self._live.start()
        self.status_changed.emit(f'Capturing on {iface}')

    def stop_live(self):
        if self._live:
            self._live.stop()
        self._on_done()

    # ── Simulation ────────────────────────────────────────────────────────
    def start_simulation(self, mode: str):
        self._sim_stop.clear()
        self._sim_thread = threading.Thread(
            target=self._sim_worker, args=(mode,), daemon=True
        )
        self._sim_thread.start()
        self.status_changed.emit(f'Simulation: {mode}')

    def stop_simulation(self):
        self._sim_stop.set()
        self._on_done()

    def _sim_worker(self, mode: str):
        try:
            t0 = time.time()
            for i in range(1000):
                if self._sim_stop.is_set():
                    break
                ts = time.time() - t0

                if mode == 'syn_flood':
                    payload = Payload({
                        'protocol': 'TCP',
                        'src_ip': f'10.0.0.{(i % 250) + 1}',
                        'dst_ip': '192.168.1.10',
                        'src_port': 10000 + (i % 40000),
                        'dst_port': 80,
                        'size': 60,
                        'ttl': 64,
                        'tcp_syn': 1,
                        'tcp_ack': 0,
                        'tcp_fin': 0,
                        'tcp_rst': 0,
                        'tcp_psh': 0,
                        'tcp_urg': 0,
                    })
                elif mode == 'udp_flood':
                    payload = Payload({
                        'protocol': 'UDP',
                        'src_ip': f'10.0.0.{(i % 250) + 1}',
                        'dst_ip': '192.168.1.10',
                        'src_port': 10000 + (i % 40000),
                        'dst_port': 53,
                        'size': 512,
                        'ttl': 64,
                        'tcp_syn': 0,
                        'tcp_ack': 0,
                        'tcp_fin': 0,
                        'tcp_rst': 0,
                        'tcp_psh': 0,
                        'tcp_urg': 0,
                    })
                else:
                    payload = Payload({
                        'protocol': 'TCP',
                        'src_ip': f'192.168.1.{(i % 250) + 1}',
                        'dst_ip': '192.168.1.10',
                        'src_port': 20000 + (i % 20000),
                        'dst_port': 443,
                        'size': 100 + (i % 100),
                        'ttl': 64,
                        'tcp_syn': 0,
                        'tcp_ack': 1,
                        'tcp_fin': 0,
                        'tcp_rst': 0,
                        'tcp_psh': 1,
                        'tcp_urg': 0,
                    })

                self._emit_pkt(PacketEvent(ts, payload))
                time.sleep(0.005)
        finally:
            self._on_done()

    def _emit_pkt(self, event: PacketEvent):
        if self._ruleset is not None:
            try:
                alerts = self._ruleset.process(event)
            except Exception:
                alerts = []
        else:
            alerts = []
        self._results_buffer.append((event, alerts))

    def _on_done(self):
        self.status_changed.emit('Idle')
        self.done.emit()


# ──────────────────────────────────────────────────────────────────────────────
# REAL-TIME ROBUSTNESS CHART
# ──────────────────────────────────────────────────────────────────────────────

if PYQTGRAPH_AVAILABLE:
    class RobustnessChart(pg.PlotWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setBackground(BG_MID)
            self.showGrid(x=True, y=True, alpha=0.2)
            self.setLabel('bottom', 'Time (s)', **{'color': TEXT_SEC, 'font-size':'10px'})
            self.setLabel('left',   'Robustness', **{'color': TEXT_SEC, 'font-size':'10px'})
            self.addLegend(offset=(10, 10))
            self.addLine(y=0, pen=pg.mkPen(color=ACCENT_RED, width=1, style=Qt.DashLine))
            self._curves: Dict[str, pg.PlotDataItem] = {}
            self._data:   Dict[str, Tuple[List, List]] = {}
            self._cols = [ACCENT_BLUE, ACCENT_GRN, ACCENT_ORG,
                          ACCENT_RED, ACCENT_PRP, ACCENT_CYAN]
            self._ci = 0
            self.setMaximumHeight(200)

        def update(self, name: str, t: float, r: float):
            if name not in self._curves:
                col  = self._cols[self._ci % len(self._cols)]; self._ci += 1
                self._curves[name] = self.plot([], [], name=name[:20],
                                                pen=pg.mkPen(color=col, width=2))
                self._data[name]   = ([], [])
            ts, rs = self._data[name]
            ts.append(t); rs.append(max(-500, min(500, r)))
            if len(ts) > 400: ts.pop(0); rs.pop(0)
            self._curves[name].setData(ts, rs)

        def clear_all(self):
            for c in self._curves.values(): self.removeItem(c)
            self._curves.clear(); self._data.clear(); self._ci = 0

else:
    class RobustnessChart(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            lbl = QLabel('pyqtgraph not found — run: pip install pyqtgraph')
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(f'color:{TEXT_SEC};')
            QVBoxLayout(self).addWidget(lbl)
            self.setMaximumHeight(200)
        def update(self, name, t, r): pass
        def clear_all(self): pass


# ──────────────────────────────────────────────────────────────────────────────
# STAT CARD
# ──────────────────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, label: str, value: str = '0', color: str = ACCENT_CYAN):
        super().__init__()
        self.setStyleSheet(
            f'QFrame{{background:{BG_MID};border:1px solid {BORDER};border-radius:6px;}}')
        vl = QVBoxLayout(self); vl.setContentsMargins(8,6,8,6); vl.setSpacing(2)
        self._v = QLabel(value)
        self._v.setStyleSheet(
            f'color:{color};font-family:Consolas;font-size:20px;font-weight:bold;'
            f'border:none;background:transparent;')
        self._v.setAlignment(Qt.AlignCenter)
        self._l = QLabel(label)
        self._l.setStyleSheet(
            f'color:{TEXT_SEC};font-size:10px;border:none;background:transparent;')
        self._l.setAlignment(Qt.AlignCenter)
        vl.addWidget(self._v); vl.addWidget(self._l)

    def set_value(self, v): self._v.setText(str(v))


# ──────────────────────────────────────────────────────────────────────────────
# RULES PANEL
# ──────────────────────────────────────────────────────────────────────────────

class RulesPanel(QWidget):
    rules_changed = pyqtSignal()

    def __init__(self, ruleset: RuleSet, parent=None):
        super().__init__(parent)
        self.ruleset = ruleset
        self._all: List[Rule] = []
        self._active: Dict[str, bool] = {}

        ll = QVBoxLayout(self); ll.setContentsMargins(0,0,0,0); ll.setSpacing(4)

        hdr = QLabel('Detection Rules')
        hdr.setStyleSheet(f'color:{ACCENT_BLUE};font-weight:bold;font-size:13px;padding:4px 0;')
        ll.addWidget(hdr)

        self.rule_list = QListWidget()
        self.rule_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rule_list.itemDoubleClicked.connect(self._show_detail)
        ll.addWidget(self.rule_list)

        row = QHBoxLayout()
        self.btn_all  = QPushButton('All ON');  self.btn_all.clicked.connect(self._enable_all)
        self.btn_none = QPushButton('All OFF'); self.btn_none.clicked.connect(self._disable_all)
        self.btn_det  = QPushButton('Details'); self.btn_det.clicked.connect(self._show_detail)
        for b in (self.btn_all, self.btn_none, self.btn_det): row.addWidget(b)
        ll.addLayout(row)

        self.lbl = QLabel()
        self.lbl.setStyleSheet(f'color:{TEXT_SEC};font-size:10px;')
        ll.addWidget(self.lbl)


    def _register(self, rule: Rule, enabled: bool = True):
        self._all.append(rule)
        self._active[rule.name] = enabled
        if enabled:
            self.ruleset.add(rule)
        self._add_list_item(rule, enabled)
        self._update_lbl()

    def _add_list_item(self, rule: Rule, enabled: bool):
        item = QListWidgetItem()
        item.setData(Qt.UserRole, rule.name)
        icon = {'HIGH':'⚠','MEDIUM':'●','LOW':'○'}.get(rule.severity,'●')
        item.setText(f'{icon} {rule.name}')
        item.setForeground(QColor(SEVERITY_COLORS.get(rule.severity, TEXT_SEC)))
        item.setCheckState(Qt.Checked if enabled else Qt.Unchecked)
        try:
            self.rule_list.itemChanged.disconnect(self._on_changed)
        except (RuntimeError, TypeError):
            pass
        self.rule_list.addItem(item)
        self.rule_list.itemChanged.connect(self._on_changed)

    def _on_changed(self, item: QListWidgetItem):
        name = item.data(Qt.UserRole)
        en   = item.checkState() == Qt.Checked
        self._active[name] = en
        if en:
            rule = next((r for r in self._all if r.name == name), None)
            if rule: self.ruleset.add(rule)
        else:
            self.ruleset.remove(name)
        self._update_lbl()
        self.rules_changed.emit()

    def _enable_all(self):
        self.rule_list.itemChanged.disconnect(self._on_changed)
        for i in range(self.rule_list.count()):
            self.rule_list.item(i).setCheckState(Qt.Checked)
        self.rule_list.itemChanged.connect(self._on_changed)
        for r in self._all:
            self._active[r.name] = True
            if r.name not in self.ruleset.rules: self.ruleset.add(r)
        self._update_lbl(); self.rules_changed.emit()

    def _disable_all(self):
        self.rule_list.itemChanged.disconnect(self._on_changed)
        for i in range(self.rule_list.count()):
            self.rule_list.item(i).setCheckState(Qt.Unchecked)
        self.rule_list.itemChanged.connect(self._on_changed)
        for r in self._all:
            self._active[r.name] = False
            self.ruleset.remove(r.name)
        self._update_lbl(); self.rules_changed.emit()

    def _update_lbl(self):
        n = sum(1 for v in self._active.values() if v)
        self.lbl.setText(f'{n}/{len(self._all)} rules active')

    def _show_detail(self):
        sel = self.rule_list.selectedItems()
        if not sel: return
        name = sel[0].data(Qt.UserRole)
        rule = next((r for r in self._all if r.name == name), None)
        if not rule: return
        dlg = QDialog(self); dlg.setWindowTitle(f'Rule: {rule.name}')
        dlg.setMinimumSize(520, 380); dlg.setStyleSheet(stylesheet())
        vl = QVBoxLayout(dlg)
        hdr = QLabel(rule.name)
        hdr.setStyleSheet(f'font-size:15px;font-weight:bold;color:{ACCENT_BLUE};')
        vl.addWidget(hdr)
        sev_c = SEVERITY_COLORS.get(rule.severity, TEXT_SEC)
        info  = QLabel(f'Severity: <b style="color:{sev_c}">{rule.severity}</b>   '
                       f'Category: {rule.category}   '
                       f'Window: {rule.window_size}s   '
                       f'Horizon: {rule.formula.horizon():.1f}s')
        info.setTextFormat(Qt.RichText)
        vl.addWidget(info)
        f = QFrame(); f.setFrameShape(QFrame.HLine)
        f.setStyleSheet(f'color:{BORDER};'); vl.addWidget(f)
        desc = QLabel(rule.description); desc.setWordWrap(True)
        vl.addWidget(desc)
        vl.addWidget(QLabel('CyTL Formula:'))
        fe = QPlainTextEdit(); fe.setReadOnly(True); fe.setPlainText(str(rule.formula))
        fe.setMaximumHeight(80); fe.setFont(QFont('Consolas',11))
        CyTLHighlighter(fe.document())
        vl.addWidget(fe)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject); vl.addWidget(btns)
        dlg.exec_()

    def add_custom_rule(self, rule: Rule):
        """Add a user-compiled rule."""
        # Remove old entry if same name
        existing = next((i for i in range(self.rule_list.count())
                         if self.rule_list.item(i).data(Qt.UserRole) == rule.name), None)
        if existing is not None:
            self.rule_list.takeItem(existing)
            self._all = [r for r in self._all if r.name != rule.name]
            self.ruleset.remove(rule.name)
        self._register(rule, enabled=True)


# ──────────────────────────────────────────────────────────────────────────────
# PACKET TABLE
# ──────────────────────────────────────────────────────────────────────────────

class PacketTable(QTableWidget):
    MAX = 2000
    COLS = [('Time',80),('Src IP',120),('Dst IP',120),('SPort',60),
            ('DPort',60),('Proto',60),('Size',60),('Flags',60),('TTL',45)]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels([c[0] for c in self.COLS])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        for i,(_, w) in enumerate(self.COLS): self.setColumnWidth(i, w)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.verticalHeader().setDefaultSectionSize(22)
        self._auto_scroll = True

    def add_packet(self, abs_time: float, payload: Payload, is_alert: bool = False):
        r = self.rowCount()
        if r >= self.MAX:
            # Batch-remove 10% of rows at once to amortise the cost
            drop = max(1, self.MAX // 10)
            self.model().removeRows(0, drop)
            r = self.rowCount()
        self.insertRow(r)
        proto = payload.get('protocol','OTHER')
        fs    = flags_str(payload)
        vals  = [f'{abs_time:.3f}', payload.get('src_ip','-') or '-',
                 payload.get('dst_ip','-') or '-',
                 str(payload.get('src_port','-') or '-'),
                 str(payload.get('dst_port','-') or '-'),
                 proto, str(payload.get('size','-') or '-'), fs,
                 str(payload.get('ttl','-') or '-')]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignCenter)
            if col == 5: item.setForeground(QColor(PROTO_COLORS.get(proto, TEXT_SEC)))
            if col == 7 and 'S' in fs: item.setForeground(QColor(ACCENT_ORG))
            if is_alert:
                item.setBackground(QColor('#2a1a1a'))
                item.setForeground(QColor(ACCENT_RED))
            self.setItem(r, col, item)
        if self._auto_scroll: self.scrollToBottom()

    def clear_packets(self): self.setRowCount(0)


# ──────────────────────────────────────────────────────────────────────────────
# ALERTS TABLE
# ──────────────────────────────────────────────────────────────────────────────

class AlertsTable(QTableWidget):
    COLS = [('Period', 220), ('Severity', 80), ('Rule', 160),
            ('Category', 100), ('Description', 300)]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels([c[0] for c in self.COLS])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        for i, (_, w) in enumerate(self.COLS): self.setColumnWidth(i, w)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setDefaultSectionSize(24)

    @staticmethod
    def _fmt_t(t: float) -> str:
        return datetime.fromtimestamp(t).strftime('%H:%M:%S')

    def add_alert(self, alert: dict, start_time: float) -> int:
        """Add a new alert row. Returns the row index."""
        r = self.rowCount()
        self.insertRow(r)
        sev = alert.get('severity', 'MEDIUM')
        period = f'{self._fmt_t(start_time)} → active'
        vals = [period, sev,
                alert.get('rule', ''), alert.get('category', ''),
                alert.get('description', '')]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setTextAlignment(
                Qt.AlignCenter if col < 4 else Qt.AlignLeft | Qt.AlignVCenter)
            if col == 1:
                item.setForeground(QColor(SEVERITY_COLORS.get(sev, TEXT_SEC)))
                item.setFont(QFont('Segoe UI', 10, QFont.Bold))
            self.setItem(r, col, item)
        self.scrollToBottom()
        return r

    def update_alert_end(self, row: int, start_time: float, end_time: float,
                         active: bool = True):
        """Update the Period cell of an existing row."""
        if row < 0 or row >= self.rowCount():
            return
        end_str = 'active' if active else self._fmt_t(end_time)
        text = f'{self._fmt_t(start_time)} → {end_str}'
        item = self.item(row, 0)
        if item:
            item.setText(text)


# ──────────────────────────────────────────────────────────────────────────────
# STATISTICS PANEL
# ──────────────────────────────────────────────────────────────────────────────

class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        ll = QVBoxLayout(self)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(6)

        hdr = QLabel('Traffic Statistics')
        hdr.setStyleSheet(f'color:{ACCENT_BLUE};font-weight:bold;font-size:13px;padding:4px 0;')
        ll.addWidget(hdr)

        g1 = QHBoxLayout()
        self.c_total = StatCard('TOTAL', '0', ACCENT_CYAN)
        self.c_tcp   = StatCard('TCP',   '0', ACCENT_BLUE)
        self.c_udp   = StatCard('UDP',   '0', ACCENT_PRP)
        self.c_icmp  = StatCard('ICMP',  '0', ACCENT_ORG)
        for c in (self.c_total, self.c_tcp, self.c_udp, self.c_icmp):
            g1.addWidget(c)
        ll.addLayout(g1)

        g2 = QHBoxLayout()
        self.c_syn   = StatCard('SYN',       '0', ACCENT_ORG)
        self.c_ack   = StatCard('ACK',       '0', ACCENT_GRN)
        self.c_alrt  = StatCard('ALERTS',    '0', ACCENT_RED)
        self.c_half  = StatCard('HALF-OPEN', '0', ACCENT_RED)
        for c in (self.c_syn, self.c_ack, self.c_alrt, self.c_half):
            g2.addWidget(c)
        ll.addLayout(g2)

        ll.addStretch()

        self._cnt = collections.Counter()
        self._alerts = 0

    def update_packet(self, payload: Payload, is_alert: bool = False):
        self._cnt['total'] += 1
        proto = payload.get('protocol', 'OTHER')
        self._cnt[proto] += 1

        if payload.get('tcp_syn') and not payload.get('tcp_ack'):
            self._cnt['syn'] += 1
        if payload.get('tcp_ack'):
            self._cnt['ack'] += 1
        if is_alert:
            self._alerts += 1

    def refresh_cards(self):
        self.c_total.set_value(self._cnt['total'])
        self.c_tcp.set_value(self._cnt['TCP'])
        self.c_udp.set_value(self._cnt['UDP'])
        self.c_icmp.set_value(self._cnt['ICMP'])
        self.c_syn.set_value(self._cnt['syn'])
        self.c_ack.set_value(self._cnt['ack'])
        self.c_alrt.set_value(self._alerts)
        self.c_half.set_value(max(0, self._cnt['syn'] - self._cnt['ack']))

    def reset(self):
        self._cnt.clear()
        self._alerts = 0
        for c in (
            self.c_total, self.c_tcp, self.c_udp, self.c_icmp,
            self.c_syn, self.c_ack, self.c_alrt, self.c_half
        ):
            c.set_value('0')


# ──────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ──────────────────────────────────────────────────────────────────────────────

class CyTLMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('CyTL IDS — Intrusion Detection System')
        self.setMinimumSize(1400, 860)
        self.resize(1600, 960)

        self.ruleset = RuleSet()
        self.worker = CaptureWorker()
        self.worker.set_ruleset(self.ruleset)

        self._thread = QThread()
        self.worker.moveToThread(self._thread)
        self._thread.started.connect(self.worker._init_batch_timer)
        self._thread.start()

        self._capturing = False
        self._pkt_count = 0
        self._alert_count = 0
        self._pps_cnt = 0

        # UI buffers
        self._pkt_buf: collections.deque = collections.deque()
        # Alert episode tracking: rule_name → episode dict
        # episode = {'row': int|None, 'start_time': float, 'last_time': float, 'data': dict}
        self._open_alerts: dict = {}
        # Pending UI actions: ('new', episode) or ('close', episode)
        self._alert_action_buf: collections.deque = collections.deque()

        # Alert log file (created lazily on first alert)
        self._alert_log_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'alerts.txt')
        self._alert_log_file = None

        self.worker.packet_received.connect(self._on_pkt, Qt.QueuedConnection)
        self.worker.status_changed.connect(self._on_status, Qt.QueuedConnection)
        self.worker.error_occurred.connect(self._on_error, Qt.QueuedConnection)
        self.worker.progress.connect(self._on_progress, Qt.QueuedConnection)
        self.worker.done.connect(self._on_done, Qt.QueuedConnection)

        # One UI refresh every 500 ms
        self._ui_timer = QTimer(self)
        self._ui_timer.timeout.connect(self._flush_ui)
        self._ui_timer.start(500)

        self._pps_tmr = QTimer(self)
        self._pps_tmr.timeout.connect(self._upd_pps)
        self._pps_tmr.start(1000)

        self._build_ui()

    # ── UI Build ───────────────────────────────────────────────────────────

    def _build_ui(self):
        self.setStyleSheet(stylesheet())
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

    def _build_toolbar(self):
        tb = self.addToolBar('Controls')
        tb.setMovable(False)

        logo = QLabel('  ⬡ CyTL IDS ')
        logo.setStyleSheet(
            f'font-size:15px;font-weight:bold;color:{ACCENT_BLUE};'
            f'font-family:Consolas;padding:0 12px;')
        tb.addWidget(logo)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f'color:{BORDER};')
        tb.addWidget(sep)

        self._selected_dev: str = ''
        self._selected_bpf: str = ''

        for iface in get_interface_details():
            if iface.status_badge == 'ACTIVE':
                self._selected_dev = iface.dev_id
                break

        self.iface_display = QLabel()
        self.iface_display.setMinimumWidth(200)
        self.iface_display.setStyleSheet(
            f'color:{TEXT_PRIM}; font-family:Consolas; font-size:11px; '
            f'background:{BG_PANEL}; border:1px solid {BORDER}; '
            f'border-radius:4px; padding:4px 8px;')
        self._update_iface_display()
        tb.addWidget(self.iface_display)

        self.btn_select_iface = QPushButton('🔌  Select Interface')
        self.btn_select_iface.setStyleSheet(
            f'background:{BG_PANEL}; border:1px solid {ACCENT_BLUE}; '
            f'color:{ACCENT_BLUE}; border-radius:5px; padding:6px 12px;')
        self.btn_select_iface.clicked.connect(self._open_iface_selector)
        tb.addWidget(self.btn_select_iface)

        tb.addSeparator()

        self.btn_start = QPushButton('▶  Live Capture')
        self.btn_start.setObjectName('btn_start')
        self.btn_start.clicked.connect(self._start_live)
        self.btn_start.setEnabled(SCAPY_AVAILABLE and bool(self._selected_dev))
        tb.addWidget(self.btn_start)

        self.btn_stop = QPushButton('■  Stop')
        self.btn_stop.setObjectName('btn_stop')
        self.btn_stop.clicked.connect(self._stop)
        self.btn_stop.setEnabled(False)
        tb.addWidget(self.btn_stop)

        tb.addSeparator()

        btn_pcap = QPushButton('📂  Load PCAP')
        btn_pcap.clicked.connect(self._load_pcap)
        tb.addWidget(btn_pcap)

        tb.addSeparator()

        sim_lbl = QLabel(' Simulate: ')
        sim_lbl.setStyleSheet(f'color:{TEXT_SEC};')
        tb.addWidget(sim_lbl)

        self.sim_combo = QComboBox()
        self.sim_combo.addItems(['Normal Traffic', 'SYN Flood (DDoS)', 'Port Scan'])
        tb.addWidget(self.sim_combo)

        self.btn_sim = QPushButton('⚡ Run')
        self.btn_sim.clicked.connect(self._start_sim)
        tb.addWidget(self.btn_sim)

        tb.addSeparator()

        self.btn_compiler = QPushButton('⚗  Rule Compiler')
        self.btn_compiler.setStyleSheet(
            f'background:{BG_PANEL};border:1px solid {ACCENT_PRP};'
            f'color:{ACCENT_PRP};border-radius:5px;padding:6px 14px;font-weight:bold;')
        self.btn_compiler.clicked.connect(self._open_compiler)
        tb.addWidget(self.btn_compiler)

        tb.addSeparator()

        btn_clear = QPushButton('🗑  Clear')
        btn_clear.clicked.connect(self._clear)
        tb.addWidget(btn_clear)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(180)
        self.progress_bar.setMaximumHeight(18)
        self.progress_bar.setVisible(False)
        tb.addWidget(self.progress_bar)

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        ml = QVBoxLayout(central)
        ml.setContentsMargins(6, 6, 6, 6)
        ml.setSpacing(4)

        top = QSplitter(Qt.Horizontal)

        left = QWidget()
        left.setMaximumWidth(290)
        left.setMinimumWidth(230)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(4)

        self._rules_panel = RulesPanel(self.ruleset)
        for _r in _default_rules():
            self._rules_panel._register(_r)
        ll.addWidget(self._rules_panel)
        top.addWidget(left)

        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(4)

        pkt_grp = QGroupBox('Packet Capture')
        pl = QVBoxLayout(pkt_grp)
        pl.setContentsMargins(4, 8, 4, 4)

        sc_row = QHBoxLayout()
        self.chk_scroll = QCheckBox('Auto-scroll')
        self.chk_scroll.setChecked(True)

        self._pkt_table = PacketTable()
        self.chk_scroll.toggled.connect(
            lambda v: setattr(self._pkt_table, '_auto_scroll', v)
        )

        self.pkt_lbl = QLabel('0 packets')
        self.pkt_lbl.setStyleSheet(f'color:{TEXT_SEC};')

        sc_row.addWidget(self.chk_scroll)
        sc_row.addStretch()
        sc_row.addWidget(self.pkt_lbl)
        pl.addLayout(sc_row)

        pl.addWidget(self._pkt_table)
        cl.addWidget(pkt_grp, 1)

        top.addWidget(center)

        self._stats = StatsPanel()
        self._stats.setMinimumWidth(270)
        self._stats.setMaximumWidth(330)
        top.addWidget(self._stats)

        top.setStretchFactor(0, 0)
        top.setStretchFactor(1, 1)
        top.setStretchFactor(2, 0)

        ml.addWidget(top, 3)

        alrt_grp = QGroupBox('Alerts')
        al = QVBoxLayout(alrt_grp)
        al.setContentsMargins(4, 8, 4, 4)

        arow = QHBoxLayout()
        self.alrt_lbl = QLabel('No alerts')
        self.alrt_lbl.setStyleSheet(f'color:{TEXT_SEC};')

        btn_ca = QPushButton('Clear Alerts')
        btn_ca.setMaximumWidth(100)
        btn_ca.clicked.connect(self._clear_alerts)

        arow.addWidget(self.alrt_lbl)
        arow.addStretch()
        arow.addWidget(btn_ca)
        al.addLayout(arow)

        self._alerts_table = AlertsTable()
        self._alerts_table.setMaximumHeight(180)
        al.addWidget(self._alerts_table)

        ml.addWidget(alrt_grp, 1)

    def _build_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)

        self._status_lbl = QLabel('Ready')
        self._status_lbl.setStyleSheet(f'color:{TEXT_SEC};')
        sb.addWidget(self._status_lbl)

        self._pps_lbl = QLabel('')
        self._pps_lbl.setStyleSheet(f'color:{ACCENT_CYAN};')
        sb.addPermanentWidget(self._pps_lbl)

    # ── Packet processing ──────────────────────────────────────────────────

    def _on_pkt(self, batch):
        """
        Riceve batch dal worker.
        Qui NON aggiorniamo la GUI subito: mettiamo tutto in buffer.
        """
        for event, alerts in batch:
            self._pkt_count += 1
            self._pps_cnt += 1

            is_alert = bool(alerts)
            self._pkt_buf.append((event, is_alert))
            self._stats.update_packet(event.payload, is_alert)

            current_rules = {a.get('rule') for a in alerts}

            # Open new episodes or extend existing ones
            for a in alerts:
                rule = a.get('rule')
                t = a.get('time', 0.0)
                if rule not in self._open_alerts:
                    episode = {'row': None, 'start_time': t, 'last_time': t, 'data': a}
                    self._open_alerts[rule] = episode
                    self._alert_count += 1
                    self._alert_action_buf.append(('new', episode))
                else:
                    self._open_alerts[rule]['last_time'] = t

            # Close episodes whose rule is no longer triggering
            for rule in list(self._open_alerts.keys()):
                if rule not in current_rules:
                    episode = self._open_alerts.pop(rule)
                    self._alert_action_buf.append(('close', episode))
                    self._log_alert(episode)

    def _flush_ui(self):
        """
        Refresh GUI ogni 500 ms.
        """
        # Packet table
        pkt_to_show = min(300, len(self._pkt_buf))
        for _ in range(pkt_to_show):
            event, is_alert = self._pkt_buf.popleft()
            self._pkt_table.add_packet(event.get_time(), event.payload, is_alert)

        # Alert episodes — process pending open/close actions
        while self._alert_action_buf:
            action = self._alert_action_buf.popleft()
            kind, episode = action
            if kind == 'new':
                row = self._alerts_table.add_alert(episode['data'], episode['start_time'])
                episode['row'] = row
            elif kind == 'close':
                if episode['row'] is not None:
                    self._alerts_table.update_alert_end(
                        episode['row'], episode['start_time'],
                        episode['last_time'], active=False)

        # Refresh end-time for all currently open (active) episodes
        for episode in self._open_alerts.values():
            if episode['row'] is not None:
                self._alerts_table.update_alert_end(
                    episode['row'], episode['start_time'],
                    episode['last_time'], active=True)

        # Labels + stats
        self.pkt_lbl.setText(f'{self._pkt_count} packets')

        if self._alert_count > 0:
            self.alrt_lbl.setText(
                f'<span style="color:{ACCENT_RED};font-weight:bold;">'
                f'{self._alert_count} alert(s)</span>'
            )
            self.alrt_lbl.setTextFormat(Qt.RichText)
        else:
            self.alrt_lbl.setText('No alerts')

        self._stats.refresh_cards()

    # ── Interface selector helpers ─────────────────────────────────────────

    def _update_iface_display(self):
        if not self._selected_dev:
            self.iface_display.setText('  No interface selected')
            return

        for iface in get_interface_details():
            if iface.dev_id == self._selected_dev:
                status_col = {
                    'ACTIVE': ACCENT_GRN,
                    'LOOPBACK': ACCENT_BLUE,
                    'VIRTUAL': TEXT_SEC,
                    'DISCONNECTED': TEXT_MUTED,
                }.get(iface.status_badge, TEXT_SEC)

                ip_part = f'  {iface.ip}' if iface.ip else ''
                bpf_part = f'  │  filter: {self._selected_bpf}' if self._selected_bpf else ''

                self.iface_display.setText(
                    f'<span style="color:{status_col}">●</span> '
                    f'<b style="color:{TEXT_PRIM}">{iface.name}</b>'
                    f'<span style="color:{ACCENT_CYAN}">{ip_part}</span>'
                    f'<span style="color:{TEXT_MUTED}">{bpf_part}</span>'
                )
                self.iface_display.setTextFormat(Qt.RichText)
                return

        self.iface_display.setText(f'  {self._selected_dev[:40]}')

    def _open_iface_selector(self):
        dlg = InterfaceSelectorDialog(
            current_dev=self._selected_dev,
            current_bpf=self._selected_bpf,
            parent=self,
        )
        dlg.interface_selected.connect(self._on_iface_selected)
        dlg.exec_()

    def _on_iface_selected(self, dev_id: str, label: str, bpf: str):
        self._selected_dev = dev_id
        self._selected_bpf = bpf
        self._update_iface_display()
        self.btn_start.setEnabled(SCAPY_AVAILABLE and bool(dev_id))
        self._status_lbl.setText(
            f'Interface: {label}' + (f'  |  BPF: {bpf}' if bpf else '')
        )

    # ── Capture controls ───────────────────────────────────────────────────

    def _start_live(self):
        if not self._selected_dev:
            QMessageBox.warning(
                self,
                'No interface',
                'Please select a network interface first.\nClick "🔌 Select Interface".'
            )
            return
        self._set_cap(True)
        self.worker.start_live(self._selected_dev, self._selected_bpf)

    def _stop(self):
        self.worker.stop_live()
        self.worker.stop_pcap()
        self.worker.stop_simulation()
        self._set_cap(False)

    def _load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            'Open PCAP / Archive',
            '',
            'PCAP & archives (*.pcap *.pcapng *.cap *.zip);;'
            'PCAP files (*.pcap *.pcapng *.cap);;'
            'ZIP archives (*.zip);;'
            'All files (*)'
        )
        if path:
            self._set_cap(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.worker.load_pcap(path)

    def _start_sim(self):
        modes = {
            'Normal Traffic': 'mixed',
            'SYN Flood (DDoS)': 'ddos',
            'Port Scan': 'portscan'
        }
        self._set_cap(True)
        self.worker.start_simulation(modes.get(self.sim_combo.currentText(), 'mixed'))

    def _set_cap(self, on: bool):
        self._capturing = on
        can_start = (not on) and SCAPY_AVAILABLE and bool(self._selected_dev)
        self.btn_start.setEnabled(can_start)
        self.btn_stop.setEnabled(on)
        self.btn_sim.setEnabled(not on)
        self.btn_select_iface.setEnabled(not on)

    def _on_done(self):
        self._set_cap(False)
        self.progress_bar.setVisible(False)

    def _on_status(self, msg: str):
        self._status_lbl.setText(msg)

    def _on_error(self, msg: str):
        QMessageBox.critical(self, 'Error', msg)
        self._set_cap(False)

    def _on_progress(self, c: int, t: int):
        if t > 0:
            self.progress_bar.setMaximum(t)
            self.progress_bar.setValue(c)

    # ── Rule Compiler ──────────────────────────────────────────────────────

    def _open_compiler(self):
        dlg = RuleCompilerDialog(parent=self)
        dlg.rule_added.connect(self._on_rule_added)
        dlg.exec_()

    def _on_rule_added(self, rule: Rule):
        self._rules_panel.add_custom_rule(rule)

    # ── Misc ───────────────────────────────────────────────────────────────

    def _clear(self):
        self._pkt_table.clear_packets()
        self._pkt_buf.clear()
        self._open_alerts.clear()
        self._alert_action_buf.clear()
        self._pkt_count = 0
        self._alert_count = 0

        self.pkt_lbl.setText('0 packets')
        self.alrt_lbl.setText('No alerts')

        self._alerts_table.setRowCount(0)
        self._stats.reset()
        self.ruleset.reset_all()

    def _clear_alerts(self):
        self._alerts_table.setRowCount(0)
        self._open_alerts.clear()
        self._alert_action_buf.clear()
        self._alert_count = 0
        self.alrt_lbl.setText('No alerts')

    def _log_alert(self, episode: dict):
        """Append a closed alert episode to alerts.txt."""
        try:
            if self._alert_log_file is None:
                self._alert_log_file = open(
                    self._alert_log_path, 'a', encoding='utf-8', buffering=1)
                self._alert_log_file.write(
                    f'\n{"="*60}\n'
                    f'CyTL Alert Log — session started '
                    f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n'
                    f'{"="*60}\n')
            data = episode['data']
            start = datetime.fromtimestamp(episode['start_time']).strftime('%Y-%m-%d %H:%M:%S')
            end   = datetime.fromtimestamp(episode['last_time']).strftime('%Y-%m-%d %H:%M:%S')
            line = (
                f'[{start}] → [{end}]  '
                f'{data.get("severity","?"):6s}  '
                f'{data.get("rule","?"):<30s}  '
                f'[{data.get("category","?")}]  '
                f'{data.get("description","")}\n'
            )
            self._alert_log_file.write(line)
        except OSError:
            pass

    def _upd_pps(self):
        if self._capturing:
            self._pps_lbl.setText(f'{self._pps_cnt} pkt/s')
        else:
            self._pps_lbl.setText('')
        self._pps_cnt = 0

    def closeEvent(self, event):
        self._stop()
        self._thread.quit()
        self._thread.wait(2000)
        if self._alert_log_file is not None:
            try:
                self._alert_log_file.close()
            except OSError:
                pass
        event.accept()


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName('CyTL IDS')
    app.setStyle('Fusion')

    pal = QPalette()
    pal.setColor(QPalette.Window,        QColor(BG_DARK))
    pal.setColor(QPalette.WindowText,    QColor(TEXT_PRIM))
    pal.setColor(QPalette.Base,          QColor(BG_MID))
    pal.setColor(QPalette.AlternateBase, QColor(BG_PANEL))
    pal.setColor(QPalette.Text,          QColor(TEXT_PRIM))
    pal.setColor(QPalette.Button,        QColor(BG_PANEL))
    pal.setColor(QPalette.ButtonText,    QColor(TEXT_PRIM))
    pal.setColor(QPalette.Highlight,     QColor(ACCENT_BLUE))
    pal.setColor(QPalette.HighlightedText, QColor(BG_DARK))
    pal.setColor(QPalette.Link,          QColor(ACCENT_BLUE))
    app.setPalette(pal)

    w = CyTLMainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

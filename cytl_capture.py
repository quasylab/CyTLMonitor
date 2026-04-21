"""
CyTL Network Capture
=====================
Live packet capture (scapy AsyncSniffer) and PCAP file loading.
Converts raw network packets into CyTL Payload objects.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

from cytl_monitor_unit import Payload, PacketEvent

# ── scapy import ──────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        PcapReader, Ether, IP, IPv6, TCP, UDP, ICMP,
        AsyncSniffer, IFACES, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

PacketCallback = Callable[[PacketEvent], None]

# PCAP and PCAPNG magic numbers (first 4 bytes)
_PCAP_MAGIC = {
    b'\xa1\xb2\xc3\xd4',  # pcap big-endian
    b'\xd4\xc3\xb2\xa1',  # pcap little-endian
    b'\xa1\xb2\x3c\x4d',  # pcap-ns big-endian
    b'\x4d\x3c\xb2\xa1',  # pcap-ns little-endian
    b'\x0a\x0d\x0d\x0a',  # pcapng
}


def _is_pcap_data(data: bytes) -> bool:
    """Return True if data begins with a known PCAP/PCAPNG magic number."""
    return len(data) >= 4 and data[:4] in _PCAP_MAGIC


# ──────────────────────────────────────────────────────────────────────────────
# INTERFACE INFO
# ──────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass


@dataclass
class InterfaceInfo:
    """Full information about a network interface."""
    dev_id: str
    name: str
    description: str
    ip: str
    mac: str
    flags: str
    label: str

    @property
    def is_connected(self) -> bool:
        return 'DISCONNECTED' not in self.flags.upper()

    @property
    def is_loopback(self) -> bool:
        return 'LOOPBACK' in self.flags.upper()

    @property
    def is_virtual(self) -> bool:
        virt_kws = ('virtual', 'miniport', 'vpn', 'tap', 'tunneling',
                    'pseudo', 'wan miniport')
        combo = (self.description + self.name).lower()
        return any(k in combo for k in virt_kws)

    @property
    def status_badge(self) -> str:
        if self.is_loopback:
            return 'LOOPBACK'
        if not self.is_connected:
            return 'DISCONNECTED'
        if self.is_virtual:
            return 'VIRTUAL'
        return 'ACTIVE'


def get_interface_details() -> List[InterfaceInfo]:
    """Return rich InterfaceInfo objects for all available interfaces."""
    if not SCAPY_AVAILABLE:
        return []

    result: List[InterfaceInfo] = []
    try:
        for dev_id, iface in IFACES.items():
            name = getattr(iface, 'name', '') or ''
            desc = getattr(iface, 'description', '') or ''
            ip = getattr(iface, 'ip', '') or ''
            mac = getattr(iface, 'mac', '') or ''
            flags = getattr(iface, 'flags', '') or ''
            if callable(flags):
                flags = ''

            if name and desc and name.lower() != desc.lower():
                label = f'{name}  [{desc}]'
            elif name:
                label = name
            elif desc:
                label = desc
            else:
                label = dev_id

            result.append(InterfaceInfo(
                dev_id=dev_id,
                name=name,
                description=desc,
                ip=ip,
                mac=mac,
                flags=str(flags),
                label=label,
            ))
    except Exception:
        pass

    return result


def get_interfaces() -> List[Tuple[str, str]]:
    """Return [(device_id, friendly_label), ...] — lightweight version."""
    return [(i.dev_id, i.label) for i in get_interface_details()]


# ──────────────────────────────────────────────────────────────────────────────
# PACKET PARSER
# ──────────────────────────────────────────────────────────────────────────────

def parse_packet(raw_pkt) -> Optional[Payload]:
    """Convert a scapy packet into a CyTL Payload."""
    if not SCAPY_AVAILABLE:
        return None

    fields: Dict = {}
    try:
        fields['size'] = len(raw_pkt)

        if IP in raw_pkt:
            ip = raw_pkt[IP]
            fields['src_ip'] = ip.src
            fields['dst_ip'] = ip.dst
            fields['ttl'] = ip.ttl
            fields['ip_len'] = getattr(ip, 'len', len(raw_pkt))
        elif IPv6 in raw_pkt:
            ip6 = raw_pkt[IPv6]
            fields['src_ip'] = ip6.src
            fields['dst_ip'] = ip6.dst
            fields['ttl'] = ip6.hlim
            fields['ip_len'] = getattr(ip6, 'plen', len(raw_pkt))

        if TCP in raw_pkt:
            tcp = raw_pkt[TCP]
            fields['protocol'] = 'TCP'
            fields['src_port'] = tcp.sport
            fields['dst_port'] = tcp.dport
            fields['tcp_seq'] = tcp.seq
            fields['tcp_ack_num'] = tcp.ack
            fields['tcp_window'] = tcp.window

            flags = int(tcp.flags)
            fields['tcp_syn'] = int(bool(flags & 0x02))
            fields['tcp_ack'] = int(bool(flags & 0x10))
            fields['tcp_fin'] = int(bool(flags & 0x01))
            fields['tcp_rst'] = int(bool(flags & 0x04))
            fields['tcp_psh'] = int(bool(flags & 0x08))
            fields['tcp_urg'] = int(bool(flags & 0x20))

        elif UDP in raw_pkt:
            udp = raw_pkt[UDP]
            fields['protocol'] = 'UDP'
            fields['src_port'] = udp.sport
            fields['dst_port'] = udp.dport
            for f in ('tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'tcp_psh', 'tcp_urg'):
                fields[f] = 0

        elif ICMP in raw_pkt:
            icmp = raw_pkt[ICMP]
            fields['protocol'] = 'ICMP'
            fields['icmp_type'] = icmp.type
            fields['icmp_code'] = icmp.code
            for f in ('tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'tcp_psh', 'tcp_urg'):
                fields[f] = 0

        else:
            fields['protocol'] = 'OTHER'
            for f in ('tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'tcp_psh', 'tcp_urg'):
                fields[f] = 0

    except Exception:
        return None

    return Payload(fields)


def flags_str(payload: Payload) -> str:
    flags = []
    if payload.get('tcp_syn'):
        flags.append('S')
    if payload.get('tcp_ack'):
        flags.append('A')
    if payload.get('tcp_fin'):
        flags.append('F')
    if payload.get('tcp_rst'):
        flags.append('R')
    if payload.get('tcp_psh'):
        flags.append('P')
    if payload.get('tcp_urg'):
        flags.append('U')
    return ''.join(flags) if flags else '-'


# ──────────────────────────────────────────────────────────────────────────────
# PCAP FILE LOADER
# ──────────────────────────────────────────────────────────────────────────────

class PcapLoader:
    """
    Streaming PCAP loader.

    Features:
    - uses PcapReader instead of rdpcap()
    - does not load the whole PCAP into RAM
    - supports ZIP archives containing multiple PCAP/PCAPNG files
    - each file inside a ZIP can be treated as an independent trace
    - progress callbacks are throttled
    """

    def __init__(
        self,
        callback: PacketCallback,
        speed: float = 0.0,
        on_done: Optional[Callable] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_source: Optional[Callable[[str], None]] = None,
        on_new_trace: Optional[Callable[[str], None]] = None,
    ):
        self.callback = callback
        self.speed = speed
        self.on_done = on_done
        self.on_progress = on_progress
        self.on_error = on_error
        self.on_source = on_source
        self.on_new_trace = on_new_trace

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.total_packets = 0
        self.loaded_packets = 0

        # Progress throttling
        self._progress_every = 1000
        self._progress_min_interval = 0.10
        self._last_progress_ts = 0.0

        # Debug console
        self.debug_print = False
        self.debug_every = 1000

    def load(self, filepath: str, blocking: bool = False):
        if not SCAPY_AVAILABLE:
            if self.on_error:
                self.on_error('scapy not installed. Run: pip install scapy')
            return

        if not os.path.exists(filepath):
            if self.on_error:
                self.on_error(f'File not found: {filepath}')
            return

        self._stop.clear()
        self.loaded_packets = 0
        self.total_packets = 0
        self._last_progress_ts = 0.0

        self._thread = threading.Thread(
            target=self._worker,
            args=(filepath,),
            daemon=True,
        )
        self._thread.start()

        if blocking:
            self._thread.join()

    def _emit_progress(self, force: bool = False):
        if self.on_progress is None:
            return

        now = time.time()
        if (
            force
            or self.loaded_packets <= 1
            or self.loaded_packets % self._progress_every == 0
            or (now - self._last_progress_ts) >= self._progress_min_interval
        ):
            self._last_progress_ts = now
            self.on_progress(self.loaded_packets, self.total_packets)

    def _resolve_sources(self, filepath: str):
        """
        Yield (tmp_path, label, is_temp) tuples for every PCAP to process.

        - Plain PCAP/PCAPNG/CAP: yields the original path directly.
        - ZIP archive: extracts each PCAP member to a temp file and yields it.
        """
        try:
            is_zip = zipfile.is_zipfile(filepath)
        except Exception:
            is_zip = False

        if is_zip:
            with zipfile.ZipFile(filepath, 'r') as zf:
                members = sorted(zf.namelist())
                for name in members:
                    if self._stop.is_set():
                        return

                    try:
                        data = zf.read(name)
                    except Exception:
                        continue

                    if not _is_pcap_data(data):
                        continue

                    suffix = os.path.splitext(name)[1] or '.pcap'
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)

                    try:
                        tmp.write(data)
                        tmp.close()
                        yield tmp.name, name, True
                    except Exception:
                        try:
                            tmp.close()
                        except Exception:
                            pass
                        try:
                            os.unlink(tmp.name)
                        except Exception:
                            pass
        else:
            yield filepath, os.path.basename(filepath), False

    def _read_pcap(self, filepath: str):
        """Stream all packets from a single PCAP file into the callback."""
        prev_time = None

        with PcapReader(filepath) as packets:
            for pkt in packets:
                if self._stop.is_set():
                    return

                try:
                    abs_time = float(pkt.time)
                except Exception:
                    continue

                payload = parse_packet(pkt)
                if payload is None:
                    continue

                if self.speed > 0 and prev_time is not None:
                    delay = (abs_time - prev_time) / self.speed
                    if 0 < delay < 0.5:
                        time.sleep(delay)
                prev_time = abs_time

                self.callback(PacketEvent(timestamp=abs_time, payload=payload))
                self.loaded_packets += 1
                if self.debug_print and self.loaded_packets % self.debug_every == 0:
                    print(
                        f"[PCAP] pkt={self.loaded_packets} "
                        f"time={abs_time:.6f} "
                        f"proto={payload.get('protocol', '-')} "
                        f"src={payload.get('src_ip', '-')}:"
                        f"{payload.get('src_port', '-')} "
                        f"dst={payload.get('dst_ip', '-')}:"
                        f"{payload.get('dst_port', '-')} "
                        f"size={payload.get('size', '-')} "
                        f"flags={flags_str(payload)}"
                    )

                self._emit_progress()

    def _worker(self, filepath: str):
        try:
            first_source = True

            for src_path, src_label, is_temp in self._resolve_sources(filepath):
                if self._stop.is_set():
                    break

                # Notify current source/file name
                if self.on_source:
                    self.on_source(src_label)

                # IMPORTANT:
                # Treat each file as an independent trace.
                # Reset monitor/ruleset before every new source.
                if self.on_new_trace:
                    try:
                        self.on_new_trace(src_label)
                    except Exception as e:
                        if self.on_error:
                            self.on_error(f'Cannot reset state before {src_label}: {e}')
                        # Continue anyway; caller may decide how critical this is.

                try:
                    self._read_pcap(src_path)
                except Exception as e:
                    if self.on_error:
                        self.on_error(f'Cannot read {src_label}: {e}')
                finally:
                    if is_temp:
                        try:
                            os.unlink(src_path)
                        except Exception:
                            pass

                first_source = False

        except Exception as e:
            if self.on_error:
                self.on_error(f'Cannot open file: {e}')
            if self.on_done:
                self.on_done()
            return

        self._emit_progress(force=True)

        if self.on_done:
            self.on_done()

    def stop(self):
        self._stop.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ──────────────────────────────────────────────────────────────────────────────
# LIVE CAPTURE  (uses AsyncSniffer for reliable stop on Windows)
# ──────────────────────────────────────────────────────────────────────────────

class LiveCapture:
    def __init__(
        self,
        callback: PacketCallback,
        iface: Optional[str] = None,
        bpf_filter: str = '',
        on_error: Optional[Callable[[str], None]] = None
    ):
        self.callback = callback
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.on_error = on_error

        self._sniffer = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self.packet_count = 0

    def start(self):
        if not SCAPY_AVAILABLE:
            if self.on_error:
                self.on_error('scapy not installed. Run: pip install scapy')
            return

        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        try:
            kwargs = {
                'prn': self._on_pkt,
                'store': False,
            }

            if self.iface:
                kwargs['iface'] = self.iface
            if self.bpf_filter:
                kwargs['filter'] = self.bpf_filter

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()

            while not self._stop.is_set():
                time.sleep(0.05)

            self._sniffer.stop()

        except PermissionError:
            msg = (
                'Permission denied.\n'
                'On Windows, run as Administrator to capture live traffic.\n'
                'Or use "Load PCAP" / "Simulation" mode instead.'
            )
            if self.on_error:
                self.on_error(msg)

        except OSError as e:
            msg = (
                f'Capture failed: {e}\n\n'
                'Make sure Npcap is installed (https://npcap.com) '
                'and the selected interface is correct.'
            )
            if self.on_error:
                self.on_error(msg)

        except Exception as e:
            if self.on_error:
                self.on_error(f'Capture error: {type(e).__name__}: {e}')

    def _on_pkt(self, pkt):
        payload = parse_packet(pkt)
        if payload is not None:
            self.packet_count += 1
            self.callback(PacketEvent(timestamp=float(pkt.time), payload=payload))

    def stop(self):
        self._stop.set()

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

        if self._thread:
            self._thread.join(timeout=3.0)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
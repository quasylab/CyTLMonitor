"""Read PCAP/PCAPNG files as CyTL events, one packet at a time.

Packet fields reuse the mapping in past/cytl_capture.py. Times are relative
to the first packet; timestamps must be strictly increasing. No packet is
silently skipped, reordered or assigned an artificial timestamp.

This reader does not finalize monitors or assign attack labels. Use one
reader iteration per capture and a fresh monitor for independent captures.
"""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from os import PathLike, fspath
from typing import Iterator, Optional, Union

from scapy.all import ICMP, IP, IPv6, TCP, UDP, PcapReader

from cytlmonitor.events.event import Event
from cytlmonitor.events.event_sequence import EventSequence
from cytlmonitor.events.payload import Payload
from cytlmonitor.io.reader import EventFormatError


class PcapEventReader:
    """Convert a capture into timestamped events without loading it all.

    ``events(path)`` yields events lazily. ``read(path)`` loads an entire
    EventSequence and should only be used for small files.

    ``first_packet_time`` retains the absolute time origin as a Decimal.
    Counters are reset at the start of each iteration. Do not run concurrent
    iterations on the same instance. Conversion errors stop the iteration.

    Equal or decreasing timestamps raise EventFormatError, including when
    distinct original times become equal after conversion to float. This
    preserves EventSequence's strict ordering instead of changing the data.

    ``size`` is the captured byte length, not necessarily the on-wire length
    when the capture is truncated. IPv6 ``ip_len`` includes the fixed header.
    """

    def __init__(self) -> None:
        self.first_packet_time: Optional[Decimal] = None
        self.last_event_time: Optional[float] = None
        self.packets_read = 0
        self.events_emitted = 0

    def events(self, source: Union[str, PathLike]) -> Iterator[Event]:
        """Yield one event per packet; close the file on exhaustion/error.

        If stopping early, call close() on the returned generator (or use
        contextlib.closing) so the file is closed immediately.
        """
        path = fspath(source)
        self.first_packet_time = None
        self.last_event_time = None
        self.packets_read = 0
        self.events_emitted = 0

        with PcapReader(path) as packets:
            for index, packet in enumerate(packets, start=1):
                self.packets_read += 1
                location = f"packet {index}"
                try:
                    timestamp = Decimal(str(packet.time))
                except (AttributeError, InvalidOperation, ValueError) as exc:
                    raise EventFormatError(
                        "missing or invalid capture timestamp", path, location
                    ) from exc
                if not timestamp.is_finite():
                    raise EventFormatError(
                        "capture timestamp must be finite", path, location
                    )

                if self.first_packet_time is None:
                    self.first_packet_time = timestamp
                # Subtract before conversion to avoid large Unix-time floats.
                time = float(timestamp - self.first_packet_time)
                if not math.isfinite(time) or time < 0:
                    raise EventFormatError(
                        "relative timestamp must be finite and nonnegative",
                        path, location,
                    )
                if self.last_event_time is not None and time <= self.last_event_time:
                    raise EventFormatError(
                        f"timestamp {time!r} is not strictly after "
                        f"{self.last_event_time!r}; duplicate, unordered or "
                        "indistinguishable float timestamps are unsupported",
                        path, location,
                    )
                try:
                    payload = self.parse_packet(packet)
                except (AttributeError, TypeError, ValueError, OverflowError) as exc:
                    raise EventFormatError(
                        f"packet conversion failed: {exc}", path, location
                    ) from exc

                event = Event(time, payload)
                self.last_event_time = time
                self.events_emitted += 1
                yield event

    def read(self, source: Union[str, PathLike]) -> EventSequence:
        """Load all events into memory; prefer events() for dataset PCAPs."""
        return EventSequence(self.events(source))

    @staticmethod
    def parse_packet(packet) -> Payload:
        """Extract the fields used by the existing CyTL traffic examples.

        Non-IP and unsupported protocols still become events with protocol
        OTHER. Missing fields (such as ports on non-TCP/UDP packets) are
        omitted. This is packet decoding, not TCP/application reassembly.
        """
        fields = {"size": len(packet), "protocol": "OTHER"}
        flag_bits = {
            "tcp_syn": 0x02, "tcp_ack": 0x10, "tcp_fin": 0x01,
            "tcp_rst": 0x04, "tcp_psh": 0x08, "tcp_urg": 0x20,
        }
        fields.update({name: 0 for name in flag_bits})

        if IP in packet:
            ip = packet[IP]
            fields.update(
                src_ip=str(ip.src), dst_ip=str(ip.dst), ttl=int(ip.ttl),
                ip_len=int(ip.len) if ip.len is not None else len(ip),
            )
        elif IPv6 in packet:
            ip = packet[IPv6]
            fields.update(
                src_ip=str(ip.src), dst_ip=str(ip.dst), ttl=int(ip.hlim),
                ip_len=40 + int(ip.plen) if ip.plen is not None else len(ip),
            )

        if TCP in packet:
            tcp = packet[TCP]
            fields.update(
                protocol="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport),
                tcp_seq=int(tcp.seq), tcp_ack_num=int(tcp.ack),
                tcp_window=int(tcp.window),
            )
            flags = int(tcp.flags)
            fields.update({name: int(bool(flags & bit))
                           for name, bit in flag_bits.items()})
        elif UDP in packet:
            udp = packet[UDP]
            fields.update(
                protocol="UDP", src_port=int(udp.sport), dst_port=int(udp.dport),
            )
        elif ICMP in packet:
            icmp = packet[ICMP]
            fields.update(
                protocol="ICMP", icmp_type=int(icmp.type), icmp_code=int(icmp.code),
            )

        return Payload(fields)

"""One class: PCAP input, FTP/SSH rules and one combined TXT report.

Place this file in examples/ and run from the CyTLMonitor repository root:
    python examples/ftp_ssh_bruteforce.py dataset results/segnalazioni.txt

The only inputs are the capture path and an output TXT path or directory.
One TXT contains all merged true intervals, source PCAPs, configuration,
per-capture summaries and errors. No per-PCAP output files are created.
Existing reports are preserved by selecting an unused filename. Directories
are searched recursively. All settings, including thresholds, are class
constants. Client/server IPs are discovered from traffic, not supplied by the
user. The sample thresholds are not calibrated. Rules detect packet-level indicators,
not authentication failures or successful compromise. No other example module
or separately supplied PCAP reader is required.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from decimal import Decimal, InvalidOperation
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.all import ICMP, IP, IPv6, TCP, UDP, PcapReader

from cytlmonitor import (
    AndMonitor, AtomicGeqMonitor, AtomicGreaterMonitor, BooleanSignalConsumer,
    ConstantExpression, Event, Payload, ProductExpression, ShiftExpression,
    SumWindowExpression,
)


class FTPSSHBruteForceExample(BooleanSignalConsumer):
    """Analyze captures using two CyTL rules defined in this class.

    Edit build_ssh_rule() and build_ftp_rule() to change the formulae.
    A fresh monitor is created per (rule, observed client, observed server).
    On initial SYNs, destination IP is the server; on FTP RST/ACK responses,
    source IP is the server. Counts are never pooled across different pairs.
    Every subsequent real event is forwarded to all monitors, including events
    with weight zero. Each capture is independent; state is not shared across
    files. This straightforward dispatch costs O(events * active scopes).

    The class is also the output consumer. CyTL publishes synchronously during
    monitor.consume(event), so _active_scope identifies the publishing monitor.
    Instances must not be used concurrently or from multiple threads.

    SYN retransmissions count; FTP RST/ACKs are aggregated without individual
    request/response matching. Neither rule proves an authentication failure.
    The first W seconds use ShiftExpression's zero-filled prefix and must be
    treated separately in evaluation. Equal timestamps are retained. If a
    capture goes backwards in time, its partial attempt is discarded and it
    is retried using a stable disk-backed timestamp sort. Packet timestamps
    are not adjusted and packets are not discarded. No EOF padding.
    """

    # Edit settings HERE. They are deliberately not command-line arguments.
    WINDOW_SECONDS = 10.0
    SSH_SYN_THRESHOLD = 20.0
    FTP_SYN_THRESHOLD = 20.0
    FTP_REJECT_FRACTION = 0.8
    SSH_PORT = 22
    FTP_PORT = 21
    MAX_SCOPES = 1000

    PCAP_MAGIC = {
        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
        b"\x0a\x0d\x0d\x0a",
    }

    def __init__(self, source, output_dir):
        self.source = Path(source).expanduser().resolve()
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.window = float(self.WINDOW_SECONDS)
        self.ssh_threshold = float(self.SSH_SYN_THRESHOLD)
        self.ftp_threshold = float(self.FTP_SYN_THRESHOLD)
        self.reject_fraction = float(self.FTP_REJECT_FRACTION)
        self.max_scopes = self.MAX_SCOPES
        self.report_path = None
        if not math.isfinite(self.window) or self.window <= 0:
            raise ValueError("window must be finite and positive")
        for value in (self.ssh_threshold, self.ftp_threshold):
            if not math.isfinite(value) or value < 0:
                raise ValueError("thresholds must be finite and nonnegative")
        if not math.isfinite(self.reject_fraction) or not 0 < self.reject_fraction <= 1:
            raise ValueError("reject_fraction must be in (0, 1]")
        if type(self.max_scopes) is not int or self.max_scopes <= 0:
            raise ValueError("max_scopes must be a positive integer")

    # ------------------------------------------------------------------
    # RULE DEFINITIONS: all formula construction is here.
    # ------------------------------------------------------------------

    def _is_syn(self, event, port, client_ip=None, server_ip=None):
        p = event.payload
        return (
            p.get("protocol") == "TCP"
            and p.get("dst_port") == port
            and p.get("tcp_syn") == 1
            and p.get("tcp_ack") == 0
            and (client_ip is None or p.get("src_ip") == client_ip)
            and (server_ip is None or p.get("dst_ip") == server_ip)
        )

    def _is_ftp_refusal(self, event, client_ip=None, server_ip=None):
        p = event.payload
        return (
            p.get("protocol") == "TCP"
            and p.get("src_port") == self.FTP_PORT
            and p.get("tcp_rst") == 1
            and p.get("tcp_ack") == 1
            and (client_ip is None or p.get("dst_ip") == client_ip)
            and (server_ip is None or p.get("src_ip") == server_ip)
        )

    def _count_last(self, weight):
        return ShiftExpression(
            SumWindowExpression(weight, 0, self.window), self.window,
        )

    def build_ssh_rule(self, client_ip, server_ip):
        """SSH: SYN_22(last W seconds) > ssh_threshold, per client/server."""
        def ssh_syn(event):
            return float(self._is_syn(event, self.SSH_PORT, client_ip, server_ip))

        return AtomicGreaterMonitor(
            self._count_last(ssh_syn),
            ConstantExpression(self.ssh_threshold),
        )

    def build_ftp_rule(self, client_ip, server_ip):
        """FTP: SYN_21 > ftp_threshold AND RST_ACK_21 >= alpha * SYN_21."""
        def ftp_syn(event):
            return float(self._is_syn(event, self.FTP_PORT, client_ip, server_ip))

        def ftp_refusal(event):
            return float(self._is_ftp_refusal(event, client_ip, server_ip))

        many_attempts = AtomicGreaterMonitor(
            self._count_last(ftp_syn),
            ConstantExpression(self.ftp_threshold),
        )
        many_refusals = AtomicGeqMonitor(
            self._count_last(ftp_refusal),
            ProductExpression(
                ConstantExpression(self.reject_fraction),
                self._count_last(ftp_syn),
            ),
        )
        # Every branch owns new expression instances: no double feeding.
        return AndMonitor(many_attempts, many_refusals)

    # ------------------------------------------------------------------
    # PCAP DISCOVERY AND CONVERSION.
    # ------------------------------------------------------------------

    def _capture_files(self):
        if self.source.is_file():
            return [self.source]
        if not self.source.is_dir():
            raise FileNotFoundError(f"input does not exist: {self.source}")
        candidates = self.source.rglob("*")
        files = []
        for path in candidates:
            if not path.is_file():
                continue
            if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
                files.append(path)
            else:
                # Some original CIC captures have numeric filename suffixes.
                with path.open("rb") as handle:
                    if handle.read(4) in self.PCAP_MAGIC:
                        files.append(path)
        if not files:
            raise ValueError(f"no PCAP/PCAPNG captures found in {self.source}")
        return sorted(files)

    @staticmethod
    def _packet_payload(packet):
        """Reuse the old prototype's packet-field mapping, without past imports."""
        bits = {"tcp_syn": 2, "tcp_ack": 16, "tcp_fin": 1,
                "tcp_rst": 4, "tcp_psh": 8, "tcp_urg": 32}
        fields = {"size": len(packet), "protocol": "OTHER"}
        fields.update({name: 0 for name in bits})
        if IP in packet:
            ip = packet[IP]
            fields.update(src_ip=str(ip.src), dst_ip=str(ip.dst), ttl=int(ip.ttl),
                          ip_len=int(ip.len) if ip.len is not None else len(ip))
        elif IPv6 in packet:
            ip = packet[IPv6]
            fields.update(src_ip=str(ip.src), dst_ip=str(ip.dst), ttl=int(ip.hlim),
                          ip_len=40 + int(ip.plen) if ip.plen is not None else len(ip))
        if TCP in packet:
            tcp = packet[TCP]
            fields.update(protocol="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport),
                          tcp_seq=int(tcp.seq), tcp_ack_num=int(tcp.ack), tcp_window=int(tcp.window))
            fields.update({name: int(bool(int(tcp.flags) & bit)) for name, bit in bits.items()})
        elif UDP in packet:
            udp = packet[UDP]
            fields.update(protocol="UDP", src_port=int(udp.sport), dst_port=int(udp.dport))
        elif ICMP in packet:
            icmp = packet[ICMP]
            fields.update(protocol="ICMP", icmp_type=int(icmp.type), icmp_code=int(icmp.code))
        return Payload(fields)

    def _read_events(self, capture):
        if self._sort_timestamps:
            yield from self._read_sorted_events(capture)
            return
        with PcapReader(str(capture)) as packets:
            for index, packet in enumerate(packets, 1):
                self._packets_read += 1
                try:
                    absolute = self._packet_time(packet)
                    event = self._make_event(absolute, self._packet_payload(packet))
                except (AttributeError, InvalidOperation, TypeError, ValueError, OverflowError) as exc:
                    raise ValueError(f"{capture}, packet {index}: {exc}") from exc
                yield event

    @staticmethod
    def _packet_time(packet):
        absolute = Decimal(str(packet.time))
        if not absolute.is_finite():
            raise ValueError("timestamp must be finite")
        return absolute

    def _make_event(self, absolute, payload):
        if self._last_absolute is not None and absolute < self._last_absolute:
            self._timestamp_regression = (
                f"previous={self._last_absolute}, current={absolute}"
            )
            raise ValueError(f"capture timestamp decreased: {self._timestamp_regression}")
        if self._origin is None:
            self._origin = absolute
        relative = float(absolute - self._origin)
        if not math.isfinite(relative) or relative < 0:
            raise ValueError("relative timestamp must be finite and nonnegative")
        if self._last_absolute is not None:
            if absolute == self._last_absolute:
                self._equal_timestamps += 1
            elif relative == self._last_time:
                self._float_time_collisions += 1
        self._last_absolute, self._last_time = absolute, relative
        self._events_emitted += 1
        return Event(relative, payload)

    @staticmethod
    def _compare_decimal_times(left, right):
        left, right = Decimal(left), Decimal(right)
        return (left > right) - (left < right)

    def _read_sorted_events(self, capture):
        """Stable sort using a temporary SQLite database, not an in-RAM list.

        Store extracted fields and exact decimal timestamps. Equal timestamps
        keep the original packet order. Temporary storage is closed and removed
        on success, error, or generator.close(), including on Windows.
        """
        with tempfile.TemporaryDirectory(prefix="cytl-pcap-sort-") as folder:
            with closing(sqlite3.connect(str(Path(folder) / "events.sqlite"))) as db:
                db.create_collation("DECIMAL_TIME", self._compare_decimal_times)
                db.execute("PRAGMA temp_store=FILE")
                db.execute("CREATE TABLE events (ts TEXT, packet_index INTEGER, payload TEXT)")
                previous = None
                with PcapReader(str(capture)) as packets:
                    for index, packet in enumerate(packets, 1):
                        self._packets_read += 1
                        try:
                            absolute = self._packet_time(packet)
                            payload = self._packet_payload(packet)
                            if previous is not None and absolute < previous:
                                self._source_regressions += 1
                            previous = absolute
                            fields = json.dumps(dict(payload), allow_nan=False)
                        except (AttributeError, InvalidOperation, TypeError, ValueError, OverflowError) as exc:
                            raise ValueError(f"{capture}, packet {index}: {exc}") from exc
                        db.execute("INSERT INTO events VALUES (?, ?, ?)",
                                   (str(absolute), index, fields))
                        if index % 10000 == 0:
                            db.commit()
                db.commit()
                ordered = db.execute(
                    "SELECT ts, payload FROM events "
                    "ORDER BY ts COLLATE DECIMAL_TIME, packet_index"
                )
                for timestamp, fields in ordered:
                    yield self._make_event(Decimal(timestamp), Payload(json.loads(fields)))

    # ------------------------------------------------------------------
    # OUTPUT CONSUMER: callbacks from the active CyTL monitor.
    # ------------------------------------------------------------------

    def consume(self, interval):
        """Receive a true interval, not an input packet/event."""
        if self._active_scope is None:
            raise RuntimeError("no active monitor during result publication")
        scope = self._groups[self._active_scope]
        current = scope["pending"]
        if current is not None and (current.just_before(interval) or current.intersect(interval)):
            scope["pending"] = current.join(interval)
            scope["last_available"] = self._input_time
        else:
            self._flush_scope(scope)
            scope["pending"] = interval
            scope["first_available"] = self._input_time
            scope["last_available"] = self._input_time

    def set_horizon(self, t):
        if self._active_scope is None:
            raise RuntimeError("no active monitor during horizon publication")
        scope = self._groups[self._active_scope]
        scope["horizon"] = t
        pending = scope["pending"]
        if pending is not None and pending.end is not None and pending.end < t:
            self._flush_scope(scope)

    def _flush_scope(self, scope):
        interval = scope["pending"]
        if interval is None:
            return
        metadata = scope["metadata"]
        label = ("FTP - tentativi ripetuti con rifiuti TCP"
                 if metadata["rule"] == "ftp_refused_attempts"
                 else "SSH - aperture TCP frequenti")
        start_unix = self._origin + Decimal(str(interval.start))
        end_unix = (self._origin + Decimal(str(interval.end))
                    if interval.end is not None else "non limitato")
        self._report.write(
            f"\n[SEGNALAZIONE] {label}\n"
            f"  PCAP: {self._capture}\n"
            f"  Client: {metadata['client_ip']}\n"
            f"  Server: {metadata['server_ip']}:{metadata['server_port']}\n"
            f"  Regola: {metadata['rule']} | monitor: {metadata['scope_id']}\n"
            f"  Intervallo relativo: {interval} s\n"
            f"  Inizio Unix: {start_unix} | fine Unix: {end_unix}\n"
            f"  Primo verdetto disponibile a: {scope['first_available']} s\n"
            f"  Ultimo aggiornamento del verdetto a: {scope['last_available']} s\n"
        )
        self._report.flush()
        scope["interval_count"] += 1
        scope["pending"] = None

    # ------------------------------------------------------------------
    # EXPERIMENT EXECUTION.
    # ------------------------------------------------------------------

    def _discover_scopes(self, event):
        for rule, port in (("ftp_refused_attempts", self.FTP_PORT),
                           ("ssh_syn_burst", self.SSH_PORT)):
            syn = self._is_syn(event, port)
            refusal = port == self.FTP_PORT and self._is_ftp_refusal(event)
            if not (syn or refusal):
                continue
            client = event.payload.get("src_ip" if syn else "dst_ip")
            server = event.payload.get("dst_ip" if syn else "src_ip")
            if not all(isinstance(ip, str) and ip for ip in (client, server)):
                raise ValueError("relevant TCP packet is missing a client or server IP")
            key = (rule, client, server)
            if key in self._groups:
                continue
            if len(self._groups) >= self.max_scopes:
                raise ValueError(f"max_scopes={self.max_scopes} exceeded")
            monitor = (self.build_ftp_rule(client, server) if port == self.FTP_PORT
                       else self.build_ssh_rule(client, server))
            monitor.add(self)
            self._groups[key] = {
                "monitor": monitor, "horizon": 0.0, "pending": None,
                "interval_count": 0, "discovered_at": event.time,
                "first_available": None, "last_available": None,
                "metadata": {
                    "scope_id": f"scope-{len(self._groups) + 1:04d}",
                    "rule": rule, "client_ip": client,
                    "server_ip": server, "server_port": port,
                },
            }

    def _run_capture(self, capture):
        started = time.perf_counter()
        position = self._report.tell()
        result = self._analyze_capture(capture, sort_timestamps=False, started=started)
        if self._timestamp_regression is not None:
            reason = self._timestamp_regression
            # No partial verdict from the unordered pass belongs in the final report.
            self._report.seek(position)
            self._report.truncate()
            self._report.write(
                f"\n[RIORDINAMENTO] {capture}\n"
                f"  Inversione rilevata: {reason}\n"
                "  Cattura riletta e ordinata stabilmente per timestamp su disco.\n"
                "  Il tentativo parziale precedente e' stato scartato.\n"
            )
            self._report.flush()
            print(f"Riordino su disco: {capture}", file=sys.stderr)
            result = self._analyze_capture(capture, sort_timestamps=True, started=started)
        return result

    def _analyze_capture(self, capture, *, sort_timestamps, started):
        self._capture = capture
        self._groups, self._active_scope = {}, None
        self._origin, self._last_time, self._input_time = None, None, None
        self._last_absolute = None
        self._timestamp_regression = None
        self._sort_timestamps = sort_timestamps
        self._equal_timestamps = self._float_time_collisions = self._source_regressions = 0
        self._packets_read = self._events_emitted = 0
        consumed = calls = 0
        monitoring_seconds = 0.0
        status, error = "ok", ""
        self._started = started
        self._report.write(f"\n[INIZIO PCAP] {capture}\n")
        self._report.flush()
        try:
            with closing(self._read_events(capture)) as events:
                for event in events:
                    self._input_time = event.time
                    self._discover_scopes(event)
                    tick = time.perf_counter()
                    try:
                        for key, scope in self._groups.items():
                            self._active_scope = key
                            scope["monitor"].consume(event)
                            calls += 1
                    finally:
                        monitoring_seconds += time.perf_counter() - tick
                        self._active_scope = None
                    consumed += 1
        except Exception as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
        finally:
            for scope in self._groups.values():
                self._flush_scope(scope)
        elapsed = time.perf_counter() - self._started
        result = {
            "source": str(capture), "status": status, "error": error,
            "packets_read": self._packets_read, "events_emitted": self._events_emitted,
            "events_consumed": consumed, "monitor_consume_calls": calls,
            "scopes": len(self._groups),
            "first_packet_unix_time": str(self._origin) if self._origin is not None else None,
            "last_event_seconds": self._last_time,
            "known_horizon_seconds": min((s["horizon"] for s in self._groups.values()), default=0.0),
            "true_intervals": sum(s["interval_count"] for s in self._groups.values()),
            "equal_timestamps": self._equal_timestamps,
            "float_time_collisions": self._float_time_collisions,
            "timestamps_sorted": sort_timestamps,
            "source_timestamp_regressions": self._source_regressions,
            "elapsed_seconds": elapsed, "monitoring_seconds": monitoring_seconds,
            "output_txt": str(self.report_path),
        }
        self._report.write(
            f"\n[FINE PCAP] {capture}\n"
            f"  Stato: {status}\n"
            f"  Pacchetti letti: {self._packets_read} | eventi elaborati: {consumed}\n"
            f"  Pacchetti con tempo uguale al precedente: {self._equal_timestamps}\n"
            f"  Collisioni introdotte dalla conversione a float: {self._float_time_collisions}\n"
            f"  Riordinamento: {'si' if sort_timestamps else 'no'} | "
            f"inversioni nell'ordine originale: {self._source_regressions}\n"
            f"  Monitor creati: {result['scopes']} | segnalazioni: {result['true_intervals']}\n"
            f"  Origine temporale Unix: {result['first_packet_unix_time']}\n"
            f"  Ultimo evento relativo: {self._last_time} s\n"
            f"  Orizzonte noto minimo: {result['known_horizon_seconds']} s\n"
            f"  Tempo totale: {elapsed:.6f} s | inoltro ai monitor: {monitoring_seconds:.6f} s\n"
        )
        if error:
            self._report.write(
                f"  ERRORE: {error}\n"
                "  Le segnalazioni di questa cattura sono parziali.\n"
            )
        self._report.flush()
        return result

    def _open_report(self):
        """Create exactly one output file; never overwrite an existing report."""
        destination = self.output_dir
        if destination.suffix.lower() == ".txt" and not destination.is_dir():
            destination.parent.mkdir(parents=True, exist_ok=True)
            index = 0
            while True:
                candidate = (destination if index == 0 else
                             destination.with_name(f"{destination.stem}_{index}.txt"))
                try:
                    handle = candidate.open("x", encoding="utf-8", newline="\n")
                except FileExistsError:
                    index += 1
                    continue
                self.report_path = candidate
                return handle
        destination.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False,
            prefix="segnalazioni_", suffix=".txt", dir=destination,
        )
        self.report_path = Path(handle.name)
        return handle

    def run(self):
        """Analyze captures separately and write every result to one TXT."""
        captures = self._capture_files()
        results = []
        with self._open_report() as report:
            self._report = report
            report.write(
                "CyTL Monitor - segnalazioni FTP/SSH\n"
                f"Sorgente: {self.source}\n"
                f"Catture selezionate: {len(captures)}\n"
                "Ricerca ricorsiva; tutti gli IP; conteggi separati per client/server.\n"
                "Ogni PCAP viene analizzato con stato indipendente.\n"
                f"Finestra: {self.window} s\n"
                f"SSH (porta {self.SSH_PORT}): SYN > {self.ssh_threshold}\n"
                f"FTP (porta {self.FTP_PORT}): SYN > {self.ftp_threshold} AND "
                f"RST/ACK >= {self.reject_fraction} * SYN\n"
                f"Limite monitor per cattura: {self.max_scopes}\n"
                "Soglie sperimentali interne, da calibrare. I SYN includono ritrasmissioni.\n"
                "Le segnalazioni sono indicatori di traffico, non prove di login falliti.\n"
                "I tempi relativi ripartono da zero per ciascun PCAP.\n"
                "Le parentesi [ ] includono gli estremi; ( ) li escludono.\n"
                "Primo verdetto e ultimo aggiornamento indicano tempi della traccia, "
                "non il tempo reale di esecuzione.\n"
                "I primi W secondi hanno il prefisso a zero di ShiftExpression.\n"
                "Timestamp uguali sono mantenuti. Le catture con tempi decrescenti "
                "sono rilette e ordinate stabilmente su disco, senza cambiare i tempi.\n"
                "Il riordinamento usa spazio temporaneo su disco per i campi estratti; "
                "puo' richiedere una seconda lettura. I contatori si riferiscono "
                "all'analisi finale, il tempo totale include l'eventuale tentativo iniziale.\n"
                "Il risultato e' noto solo entro l'orizzonte pubblicato; nessun evento "
                "viene aggiunto a fine cattura.\n"
                "Gli intervalli sono uniti solo nello stesso PCAP/client/server/regola "
                "e scritti quando disponibili, non in ordine cronologico globale.\n"
            )
            report.flush()
            for index, capture in enumerate(captures, 1):
                result = self._run_capture(capture)
                results.append(result)
                print(f"[{index}/{len(captures)}] {capture.name}: {result['status']}, "
                      f"{result['true_intervals']} segnalazioni")
                if result["error"]:
                    print(f"  {result['error']}", file=sys.stderr)
            failures = sum(r["status"] == "error" for r in results)
            report.write(
                "\n[RIEPILOGO COMPLESSIVO]\n"
                f"  PCAP completati: {len(results) - failures}\n"
                f"  PCAP con errori: {failures}\n"
                f"  Pacchetti letti: {sum(r['packets_read'] for r in results)}\n"
                f"  Segnalazioni totali: {sum(r['true_intervals'] for r in results)}\n"
                "  Il totale conta intervalli per coppia/regola e puo' includere "
                "risultati parziali di file con errore; non e' un numero di attacchi.\n"
            )
        print(f"Report TXT: {self.report_path}")
        return results

    @classmethod
    def main(cls, argv=None):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("source", help="PCAP file or directory of extracted captures")
        parser.add_argument("output", help="output TXT file or directory for the single report")
        args = parser.parse_args(argv)
        try:
            results = cls(args.source, args.output).run()
        except (OSError, ValueError, TypeError) as exc:
            parser.exit(2, f"error: {exc}\n")
        return 1 if any(r["status"] == "error" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(FTPSSHBruteForceExample.main())

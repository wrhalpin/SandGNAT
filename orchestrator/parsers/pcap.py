# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""PCAP parser.

Delegates packet decoding to `scapy` (optional dependency; install the
`sandgnat-orchestrator[pcap]` extra). We don't ship our own dissector — scapy
is the de facto standard and keeps this file small.

Output is aggregated at the flow level (5-tuple), not per-packet, which is what
STIX `network-traffic` objects model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class PcapFlow:
    """One aggregated flow extracted from a PCAP.

    Keyed on the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
    Packet count + byte total + DNS queries are accumulated across every
    packet matching the tuple.
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str  # 'tcp' | 'udp' | 'icmp' | 'other'
    start: float  # epoch seconds
    end: float
    packets: int = 0
    bytes_: int = 0
    dns_queries: list[str] = field(default_factory=list)


def parse_pcap(source: Path) -> list[PcapFlow]:
    """Aggregate a PCAP into flow records.

    Raises ImportError if scapy isn't installed — callers should gate on the
    `pcap` extra or handle the ImportError and skip network analysis.
    """
    try:
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "parse_pcap requires the 'pcap' extra: pip install sandgnat-orchestrator[pcap]"
        ) from exc

    flows: dict[tuple[str, str, int | None, int | None, str], PcapFlow] = {}

    with PcapReader(str(source)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            if TCP in pkt:
                proto = "tcp"
                sport: int | None = int(pkt[TCP].sport)
                dport: int | None = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "udp"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            else:
                proto = "other"
                sport = dport = None

            key = (ip.src, ip.dst, sport, dport, proto)
            ts = float(pkt.time)
            flow = flows.get(key)
            if flow is None:
                flow = PcapFlow(
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    start=ts,
                    end=ts,
                )
                flows[key] = flow
            flow.end = max(flow.end, ts)
            flow.packets += 1
            flow.bytes_ += len(bytes(pkt))

            if proto == "udp" and DNS in pkt and pkt[DNS].qr == 0:
                dns_layer = pkt[DNS]
                if dns_layer.qdcount and DNSQR in pkt:
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("idna", errors="replace").rstrip(".")
                    if qname and qname not in flow.dns_queries:
                        flow.dns_queries.append(qname)

    return list(flows.values())

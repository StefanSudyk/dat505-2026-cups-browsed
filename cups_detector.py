"""
Watches CUPS traffic (live or from a pcap) and flags things that look like an
attack against printer discovery: adverts from hosts we don't trust, callbacks
to advertised printers, discovery floods, and broken browse packets.

Alerts go to stdout and optionally to csv/json. Live capture needs root.
"""

import argparse
import csv
import json
import logging
import shlex
import sys
import time
from collections import defaultdict, deque

from scapy.all import IP, IPv6, TCP, UDP, Raw, rdpcap, sniff

log = logging.getLogger("cups_detector")

SCHEMES = ("ipp", "ipps", "http", "https")
STATES = ("3", "4", "5")  # idle, processing, stopped
SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SYN_TTL = 2.0  # seconds; collapse retransmitted SYNs within this window


def parse_browse(payload):
    """Pull apart a CUPS browse line. Returns (fields, problems)."""
    problems = []
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None, ["non-utf8 payload"]

    if any(ord(c) < 9 or 13 < ord(c) < 32 for c in text):
        problems.append("control characters in payload")

    try:
        parts = shlex.split(text)
    except ValueError:
        return None, ["unbalanced quotes"]

    if len(parts) < 3:
        return None, ["too few fields (%d)" % len(parts)]

    ptype, state, uri = parts[0], parts[1], parts[2]
    host = None
    port = None

    try:
        int(ptype, 0)
    except ValueError:
        problems.append("bad type field '%s'" % ptype)

    if state not in STATES:
        problems.append("unexpected state '%s'" % state)

    if "://" not in uri:
        problems.append("uri without scheme")
    else:
        scheme, rest = uri.split("://", 1)
        if scheme not in SCHEMES:
            problems.append("unexpected scheme '%s'" % scheme)
        hostport = rest.split("/", 1)[0]
        if ":" in hostport:
            host, raw_port = hostport.rsplit(":", 1)
            try:
                port = int(raw_port)
            except ValueError:
                problems.append("non-numeric port '%s'" % raw_port)
        else:
            host = hostport

    return {"type": ptype, "state": state, "uri": uri, "host": host, "port": port}, problems


class Detector:
    def __init__(self, args):
        self.args = args
        self.trusted = set(args.allow)
        self.ipp_ports = set(args.ipp_ports)
        self.advertised = {}              # (host, port) -> who advertised it
        self.seen = defaultdict(deque)    # src -> advert timestamps
        self.flooding = set()             # sources we've already flagged this burst
        self.recent_syn = {}              # (src, dst, dport) -> last timestamp
        self.alerts = []

    def raise_alert(self, ts, sev, kind, src, dst, detail):
        row = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "severity": sev,
            "category": kind,
            "src": src or "",
            "dst": dst or "",
            "detail": detail,
        }
        self.alerts.append(row)
        log.warning("[%s] %s  %s -> %s  %s", sev, kind, row["src"], row["dst"], detail)

    def inspect(self, pkt):
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        ts = float(getattr(pkt, "time", time.time()))

        if UDP in pkt and pkt[UDP].dport == self.args.browse_port and Raw in pkt:
            self._check_advert(ts, src, dst, pkt[Raw].load)

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02 and not flags & 0x10:   # SYN without ACK
                dport = int(pkt[TCP].dport)
                if not self._syn_seen(ts, src, dst, dport):
                    self._check_connection(ts, src, dst, dport)

    def _syn_seen(self, ts, src, dst, dport):
        """True if we've already seen this SYN tuple within SYN_TTL (a retransmit)."""
        key = (src, dst, dport)
        last = self.recent_syn.get(key)
        self.recent_syn[key] = ts
        if len(self.recent_syn) > 4096:      # keep the table from growing forever
            for k, t in list(self.recent_syn.items()):
                if ts - t > SYN_TTL:
                    del self.recent_syn[k]
        return last is not None and ts - last < SYN_TTL

    def _check_advert(self, ts, src, dst, payload):
        fields, problems = parse_browse(payload)

        if src not in self.trusted:
            self.raise_alert(ts, "HIGH", "unauthorized-advertisement", src, dst,
                             "browse packet from untrusted host; payload=%r" % payload[:120])

        if problems:
            self.raise_alert(ts, "MEDIUM", "malformed-fields", src, dst,
                             "; ".join(problems))

        if fields and fields["host"]:
            self.advertised.setdefault((fields["host"], fields["port"]), src)

        # rolling count of adverts per source, one alert per burst
        window = self.args.rate_window
        q = self.seen[src]
        q.append(ts)
        while q and ts - q[0] > window:
            q.popleft()
        if len(q) >= self.args.rate_threshold:
            if src not in self.flooding:
                self.flooding.add(src)
                self.raise_alert(ts, "HIGH", "discovery-flood", src, dst,
                                 "%d adverts in %gs" % (len(q), window))
        else:
            self.flooding.discard(src)

    def _check_connection(self, ts, src, dst, dport):
        for (host, port), who in self.advertised.items():
            if dst == host and (port is None or dport == port):
                self.raise_alert(ts, "CRITICAL", "victim-callback", src, dst,
                                 "connected back to advertised printer %s:%s (advertised by %s)"
                                 % (host, port, who))
                return

        if dport in self.ipp_ports and dst not in self.trusted:
            self.raise_alert(ts, "MEDIUM", "suspicious-ipp-connection", src, dst,
                             "IPP connection to tcp/%d, dst not trusted" % dport)


def export(alerts, path, fmt, min_severity=None):
    if min_severity:
        cutoff = SEVERITY[min_severity]
        alerts = [a for a in alerts if SEVERITY.get(a["severity"], 0) >= cutoff]
    if not alerts:
        log.info("nothing to export")
        return
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2)
    else:
        cols = ["time", "severity", "category", "src", "dst", "detail"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(alerts)
    log.info("wrote %d alerts to %s", len(alerts), path)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Detect suspicious CUPS activity (live or pcap).")

    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--pcap", help="read from a pcap file")
    where.add_argument("--iface", help="live capture (root)")

    p.add_argument("--browse-port", type=int, default=631)
    p.add_argument("--ipp-ports", type=int, nargs="+", default=[631, 8632])
    p.add_argument("--allow", nargs="*", default=[],
                   help="trusted IPs (real printers / admin hosts)")
    p.add_argument("--rate-window", type=float, default=10.0,
                   help="seconds for the flood counter")
    p.add_argument("--rate-threshold", type=int, default=5,
                   help="adverts per window before it's a flood")
    p.add_argument("--count", type=int, default=None, help="live: stop after N packets")

    p.add_argument("--out", help="export alerts here")
    p.add_argument("--format", choices=["csv", "json"], default="csv")
    p.add_argument("--min-severity", choices=list(SEVERITY), default=None,
                   help="only export alerts at or above this severity")
    p.add_argument("--log-file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%H:%M:%S", handlers=handlers)

    det = Detector(args)

    if args.pcap:
        pkts = rdpcap(args.pcap)
        for pkt in pkts:
            det.inspect(pkt)
        log.info("processed %d packets from %s", len(pkts), args.pcap)
    else:
        ports = " or ".join("tcp port %d" % pt for pt in args.ipp_ports)
        bpf = "udp port %d or %s" % (args.browse_port, ports)
        log.info("listening on %s (%s), ctrl-c to stop", args.iface, bpf)
        sniff(iface=args.iface, filter=bpf, prn=det.inspect, store=False, count=args.count)

    tally = defaultdict(int)
    for a in det.alerts:
        tally[a["severity"]] += 1
    log.info("%d alerts: %s", len(det.alerts), dict(tally) or "none")

    if args.out:
        export(det.alerts, args.out, args.format, args.min_severity)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)

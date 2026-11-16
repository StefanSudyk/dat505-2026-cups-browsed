# CUPS Printer Discovery Exploitation and Attack Detection Using Scapy

Dat505 assignment. Scapy-based tools that demonstrate and detect the insecure
printer-discovery mechanism in `cups-browsed` (CVE-2024-47176), with the captured
traffic, logs, and a mitigation.

**Lab use only.** These tools send forged CUPS packets; run them only against the
isolated lab, never against a host you do not own.

## Vulnerability

`cups-browsed` listens on UDP port 631 and trusts printer advertisements from any
source on any interface. An attacker can advertise a printer at an address of
their choosing; the victim creates a queue and connects back to it. That callback
is the root cause of the CVE-2024-47176 chain (Vulhub image: rejected id
CVE-2024-47177).

## Repository layout

```
cups_attack.py     # Scapy attack tool (forges browse advertisements)
cups_detector.py   # Scapy detection tool (live or offline pcap)
requirements.txt   # Python dependencies
pcap_files/        # captured traffic (normal, attack, variants, before/after)
evidence/          # tool logs, detector CSVs, screenshots, network config
```

## Setup

```bash
pip install -r requirements.txt
sudo docker compose up -d            # victim, from the Vulhub CVE-2024-47177 dir
ippeveprinter -r off -v -p 8632 "Lab Printer" > evidence/printer.log 2>&1 &
```

Lab: attacker + virtual printer on the Kali host (172.18.0.1), victim container
at 172.18.0.2, Docker bridge 172.18.0.0/16.

## Usage

```bash
# attack: advertise a printer to the victim and capture the exchange
sudo python3 cups_attack.py --target 172.18.0.2 \
    --printer-host 172.18.0.1 --printer-port 8632 \
    --printer-name EvilPrinter --pcap pcap_files/attack.pcap -v

# detect: analyse a capture and export alerts
python3 cups_detector.py --pcap pcap_files/attack.pcap --out evidence/detect_attack.csv
```

The victim's callback appears in the virtual printer log (`evidence/printer.log`);
a captured run is in `evidence/02_attack_callback.log`.

Run each tool with `--help` for all options (crafted fields, `--count`/`--interval`
flood, `--minimal`, allowlist `--allow`, live `--iface`, CSV/JSON export). The
detector reports `unauthorized-advertisement`, `malformed-fields`,
`discovery-flood`, `suspicious-ipp-connection`, and `victim-callback`. Full method
and results are in the PDF report.

## Ethics

All testing was confined to the isolated lab; no real printers, third-party
hosts, or personal data were involved. Full remote code execution was out of
scope, and the attack tool is paired with a detector and a mitigation so the
project supports defence.

# NEXUS SNIFFER

A beginner-friendly Python network packet metadata analyzer built with Scapy.
It provides a terminal menu, captures a limited number of IPv4 packets from a
chosen interface, identifies common protocols, and displays basic statistics.

## Features

- Terminal banner and menu
- List available network interfaces
- Display the selected interface's IPv4 address
- Capture up to 20 IPv4 packets, with a 30-second timeout
- Display source IP, destination IP, and protocol (TCP, UDP, ICMP, or OTHER)
- Show protocol counts for the latest capture

## Requirements

- Python 3
- Scapy
- Linux (tested as a Kali Linux learning project)
- Packet-capture permissions; on Kali, run with appropriate privileges

## Installation on Kali Linux

```bash
sudo apt update
sudo apt install python3-scapy figlet -y
```

## Run

The default interface in `sniffer.py` is `eth0`. Check your interface name first:

```bash
ip -br addr
```

If your interface has a different name, change `INTERFACE = "eth0"` near the top
of `sniffer.py` to the correct interface name.

Then run:

```bash
sudo python3 sniffer.py
```

Choose `1` to start a capture. Generate ordinary traffic from your own Kali VM
or an authorized lab network. Choose `4` to view protocol statistics.

## Safety and scope

Use this tool only on a device and network you own or are explicitly authorized
to monitor. The program displays packet metadata only; it does not print packet
payloads or attempt to access private communications. The default capture is
limited to 20 IPv4 packets or 30 seconds.

## Project structure

```text
NEXUS_SNIFFER/
├── sniffer.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Learning outcomes

- Basic Python functions, conditionals, loops, and exception handling
- Network interface concepts
- IPv4 packet structure and common transport protocols
- Packet capture and metadata analysis with Scapy

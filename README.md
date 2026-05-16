[README (2).md](https://github.com/user-attachments/files/27858925/README.2.md)
# WPA2 4-Way Handshake Analyzer


## Overview

This project analyzes the WPA2 4-Way Handshake to study its structure, cryptographic fields, and common vulnerabilities. All analysis is done **offline using simulated/captured pcap data** — no real networks, hardware, or unauthorized traffic were used.

---

## Files

```
├── hand_shake-creation.py       # Basic WPA2 handshake analyzer (original)
├── hand_shake-analysis.py       # Enhanced analyzer with demo mode and handshake grouping
├── hand_shake-creation.txt      # Reference copy of the creation script
└── Cyber-Security_Project_Report.pdf
```

---

## Requirements

```
Python 3.x
scapy
```

Install dependencies:

```bash
pip install scapy
```

---

## Usage

### Basic Analyzer (`hand_shake-creation.py`)

```bash
python3 hand_shake-creation.py capture.pcap              # Default detailed view
python3 hand_shake-creation.py capture.pcap -s           # Summary only
python3 hand_shake-creation.py capture.pcap -t           # Timeline view
python3 hand_shake-creation.py capture.pcap -c           # Export to CSV
python3 hand_shake-creation.py capture.pcap --no-color   # Disable colors
```

### Enhanced Analyzer (`hand_shake-analysis.py`)

```bash
python3 hand_shake-analysis.py capture.pcap              # Full analysis
python3 hand_shake-analysis.py capture.pcap -s           # Summary only
python3 hand_shake-analysis.py capture.pcap -t           # Timeline view
python3 hand_shake-analysis.py capture.pcap --table      # Compact table
python3 hand_shake-analysis.py capture.pcap -c           # Export to CSV
python3 hand_shake-analysis.py --demo                    # Run with synthetic handshake (no pcap needed)
```

The `--demo` flag synthesizes a complete 4-way handshake for showcasing without needing a real capture file.

---

## What the Scripts Do

- Parse EAPOL packets from a `.pcap` file
- Classify each packet as Message 1–4 of the 4-way handshake
- Extract key fields: ANonce, SNonce, MIC, Replay Counter, Key Info flags
- Group packets by AP/Client MAC pair
- Detect whether a complete or partial handshake is present
- Display results in multiple formats (detailed, summary, timeline, table)
- Optionally export results to CSV

---

## Output Example (Summary View)

```
Handshake 1: AP=aa:bb:cc:dd:ee:ff  Client=11:22:33:44:55:66
  Message 1:  ✓
  Message 2:  ✓
  Message 3:  ✓
  Message 4:  ✓
  Suitable for cracking: Yes
```

---

## Ethical Note

This project was conducted entirely offline for educational purposes. No real SSIDs, MAC addresses, or passphrases were used. All handshake data was either simulated or captured in a controlled, authorized environment.

---

## Key Findings

- Weak passphrases (e.g. `12345678`) allow fast offline PMK derivation
- Predictable or repeated nonces can enable key-reconstruction attacks
- Improper replay counter handling exposes networks to replay attacks
- WPA3 (SAE) addresses most of these weaknesses

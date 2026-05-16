#script handshake analysis
#!/usr/bin/env python3
"""
Enhanced WPA2 4-Way Handshake Analyzer
- Improved handshake grouping and completeness detection
- --demo mode to synthesize a valid complete 4-way handshake for showcasing
- Better matching of messages to a single handshake (per AP/Client pair)
- Export & views retained from original script

Usage examples:
  python3 handshake_analysis_enhanced.py capture.pcap
  python3 handshake_analysis_enhanced.py capture.pcap -s
  python3 handshake_analysis_enhanced.py --demo         # show synthesized complete handshake

This file is an improved version of the user's original analyzer with the features above.
"""

from scapy.all import rdpcap, Packet
from scapy.layers.eap import EAPOL
import sys
import argparse
import csv
from datetime import datetime
from collections import defaultdict
import os

# ----------------------- COLORS -----------------------
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ""
        Colors.CYAN = Colors.MAGENTA = Colors.WHITE = Colors.RESET = ""
        Colors.BG_RED = Colors.BG_GREEN = Colors.BG_YELLOW = Colors.BG_BLUE = ""
        Colors.BOLD = Colors.UNDERLINE = ""

# ----------------------- SMALL UTILITIES -----------------------
def safe_hex(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) and len(b) > 0 else None

# ----------------------- DISPLAY HELPERS -----------------------
def print_header(title, color=Colors.CYAN):
    width = 66
    print(f"\n{color}{Colors.BOLD}╔{'═' * (width-2)}╗")
    print(f"║{title.center(width-2)}║")
    print(f"╚{'═' * (width-2)}╝{Colors.RESET}")

def print_section(title, color=Colors.BLUE):
    print(f"\n{color}{Colors.BOLD}── {title} ──{'─' * 40}{Colors.RESET}")

def print_info(label, value, color=Colors.WHITE):
    print(f"{Colors.YELLOW}{label:25}{color}{value}{Colors.RESET}")

# compact table printer (kept simple)
def print_table(headers, rows, highlight_row=None):
    if not rows:
        print(f"{Colors.YELLOW}No data to display in table{Colors.RESET}")
        return
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    # header
    header_cells = [f" {str(h):{w}} " for h, w in zip(headers, col_widths)]
    print(Colors.CYAN + "|" + "|".join(header_cells) + "|" + Colors.RESET)
    # rows
    for idx, row in enumerate(rows):
        row_cells = [f" {str(cell):{w}} " for cell, w in zip(row, col_widths)]
        row_str = "|" + "|".join(row_cells) + "|"
        if highlight_row == idx:
            print(Colors.GREEN + row_str + Colors.RESET)
        else:
            print(row_str)

# ----------------------- DETECT MESSAGE -----------------------
def classify_message(eapol):
    """Classify based on key_info bits (IEEE 802.11i)
    Returns dict: type, desc, flags, color
    """
    if not hasattr(eapol, "key_info"):
        return {"type": "Unknown", "desc": "No key_info field", "flags": [], "color": Colors.WHITE}

    ki = int(eapol.key_info)
    flags = []
    # Known bits
    if ki & 0x0001: flags.append("Request")
    if ki & 0x0002: flags.append("Error")
    if ki & 0x0004: flags.append("Secure")
    if ki & 0x0008: flags.append("Pairwise")
    if ki & 0x0040: flags.append("Install")
    if ki & 0x0080: flags.append("ACK")
    if ki & 0x0100: flags.append("MIC")
    if ki & 0x0200: flags.append("SecureEnc")

    key_desc = (ki >> 13) & 0x07
    if key_desc == 1:
        flags.append("WPA1")
    elif key_desc == 2:
        flags.append("WPA2")
    elif key_desc == 3:
        flags.append("WPA3")
    else:
        flags.append(f"KD:{key_desc}")

    # simple classification logic (prioritized)
    mic = bool(ki & 0x0100)
    ack = bool(ki & 0x0080)
    install = bool(ki & 0x0040)
    secure = bool(ki & 0x0200)

    # Message 1: ACK=1, MIC=0, Install=0
    if ack and not mic and not install:
        msg_type = "Message 1"
        desc = "ANonce from AP"
        color = Colors.BLUE
    # Message 2: MIC=1, ACK=0
    elif mic and not ack:
        msg_type = "Message 2"
        desc = "SNonce + MIC from Client"
        color = Colors.GREEN
    # Message 3: MIC=1, ACK=1, Install often set
    elif mic and ack and install:
        msg_type = "Message 3"
        desc = "GTK + Install from AP"
        color = Colors.MAGENTA
    # Message 4: MIC=1, ACK=1, Secure set and no Install
    elif mic and ack and secure and not install:
        msg_type = "Message 4"
        desc = "Final ACK from Client"
        color = Colors.CYAN
    else:
        msg_type = "Unknown"
        desc = f"Key Info: 0x{ki:04x}"
        color = Colors.WHITE

    return {"type": msg_type, "desc": desc, "flags": flags, "color": color}

# return list of human readable flags
def get_key_info_flags(key_info):
    return classify_message(type("X", (), {"key_info": key_info}))['flags']

# ----------------------- PACKET ANALYSIS -----------------------
def analyze_packet(pkt, idx, verbose=False):
    try:
        eapol = pkt[EAPOL]
    except Exception:
        return None

    info = classify_message(eapol)

    packet_info = {
        "number": idx,
        "type": info['type'],
        "description": info['desc'],
        "src_mac": getattr(pkt, 'src', getattr(pkt.getlayer('Ether'), 'src', None)) if pkt.haslayer('Ether') else pkt.src if hasattr(pkt, 'src') else None,
        "dst_mac": getattr(pkt, 'dst', getattr(pkt.getlayer('Ether'), 'dst', None)) if pkt.haslayer('Ether') else pkt.dst if hasattr(pkt, 'dst') else None,
        "timestamp": getattr(pkt, 'time', None),
        "color": info['color'],
        "key_info": int(eapol.key_info) if hasattr(eapol, 'key_info') else None,
        "key_info_flags": info.get('flags', [])
    }

    # descriptor
    if packet_info['key_info'] is not None:
        kd = (packet_info['key_info'] >> 13) & 0x07
        if kd == 2:
            packet_info['key_descriptor'] = 'WPA2 (AES)'
        elif kd == 1:
            packet_info['key_descriptor'] = 'WPA1 (TKIP)'
        elif kd == 3:
            packet_info['key_descriptor'] = 'WPA3 (SAE)'
        else:
            packet_info['key_descriptor'] = f'KD:{kd}'
    else:
        packet_info['key_descriptor'] = 'Unknown'

    # nonces/mic/replay
    nonce = None
    if hasattr(eapol, 'wpa_key_nonce'):
        nonce = eapol.wpa_key_nonce
    elif hasattr(eapol, 'nonce'):
        nonce = eapol.nonce

    packet_info['nonce'] = safe_hex(nonce)
    packet_info['nonce_len'] = len(nonce) if nonce else 0

    mic = None
    if hasattr(eapol, 'wpa_key_mic'):
        mic = eapol.wpa_key_mic
    elif hasattr(eapol, 'mic'):
        mic = eapol.mic

    packet_info['mic'] = safe_hex(mic)
    packet_info['mic_len'] = len(mic) if mic else 0

    packet_info['replay_counter'] = getattr(eapol, 'key_replay_counter', None)
    packet_info['key_length'] = getattr(eapol, 'key_length', None)
    packet_info['key_data_len'] = getattr(eapol, 'wpa_key_data_len', None)

    # raw hex when verbose
    if verbose:
        try:
            packet_info['raw_hex'] = bytes(eapol).hex()
        except Exception:
            packet_info['raw_hex'] = None

    return packet_info

# ----------------------- GROUPING & COMPLETENESS -----------------------
def group_handshakes(packet_infos):
    """Group packets into potential handshakes by (AP, Client) pair using message types and nonces.
    Returns dict keyed by (ap_mac, client_mac) -> list of packets
    """
    groups = defaultdict(list)
    for p in packet_infos:
        # prefer AP being source of Message 1/3
        if p['type'] in ['Message 1', 'Message 3']:
            ap = p['src_mac']
            client = p['dst_mac']
        elif p['type'] in ['Message 2', 'Message 4']:
            ap = p['dst_mac']
            client = p['src_mac']
        else:
            # unknown: assign to a generic grouping using src/dst order
            ap, client = (p['src_mac'], p['dst_mac'])
        groups[(ap, client)].append(p)
    return groups


def detect_complete_handshakes(groups):
    """For each group, determine whether it contains a full 4-way handshake.
    Returns list of dicts describing each handshake and which messages were present.
    """
    results = []
    for (ap, client), pkts in groups.items():
        types = defaultdict(list)
        for p in pkts:
            types[p['type']].append(p)
        present = {m: bool(types.get(m)) for m in ['Message 1', 'Message 2', 'Message 3', 'Message 4']}
        # heuristics for 'suitable for cracking': presence of Message 2 (with SNonce+MIC)
        suitable = present['Message 2'] and (present['Message 1'] or present['Message 3'])
        results.append({
            'ap': ap,
            'client': client,
            'packets': sorted(pkts, key=lambda x: (x.get('timestamp') or 0, x['number'])),
            'present': present,
            'suitable_for_cracking': suitable,
            'counts': {k: len(v) for k, v in types.items()}
        })
    return results

# ----------------------- VIEWS -----------------------
def display_summary_view(packet_infos, handshake_results):
    print_header("HANDSHAKE SUMMARY", Colors.GREEN)
    if not packet_infos:
        print(f"{Colors.RED}[!] No handshake data available{Colors.RESET}")
        return

    unique_macs = set()
    for p in packet_infos:
        unique_macs.add(p['src_mac'])
        unique_macs.add(p['dst_mac'])

    print_info("Total EAPOL Packets:", len(packet_infos))
    print_info("Unique MAC Addresses:", len(unique_macs))
    print()

    for idx, h in enumerate(handshake_results, 1):
        print_section(f"Handshake {idx}: AP={h['ap']} Client={h['client']}", Colors.CYAN)
        print_info("Message 1:", '✓' if h['present']['Message 1'] else '✗')
        print_info("Message 2:", '✓' if h['present']['Message 2'] else '✗')
        print_info("Message 3:", '✓' if h['present']['Message 3'] else '✗')
        print_info("Message 4:", '✓' if h['present']['Message 4'] else '✗')
        print_info("Suitable for cracking:", 'Yes' if h['suitable_for_cracking'] else 'No')
        print()

        # show packet list for the handshake
        headers = ['#', 'Type', 'From', 'To', 'Nonce', 'MIC', 'Replay']
        rows = []
        for p in h['packets']:
            rows.append([
                p['number'], p['type'], p['src_mac'][-8:].replace(':', ''), p['dst_mac'][-8:].replace(':', ''),
                '✓' if p.get('nonce') else '✗', '✓' if p.get('mic') else '✗', p.get('replay_counter')
            ])
        print_table(headers, rows)

def display_detailed_view(packet_infos, verbose=False):
    print_header('DETAILED PACKET ANALYSIS', Colors.BLUE)
    for info in packet_infos:
        print_section(f"Packet {info['number']}: {info['type']} ({info['description']})", info['color'])
        print_info('From:', info['src_mac'])
        print_info('To:', info['dst_mac'])
        print_info('Key Descriptor:', info.get('key_descriptor', 'Unknown'))
        if info.get('key_info') is not None:
            print_info('Key Info:', f"0x{info['key_info']:04x}")
        if info.get('key_info_flags'):
            print_info('Flags:', ', '.join(info['key_info_flags']))
        if info.get('nonce'):
            print_info('Nonce present:', 'Yes')
            print_info('Nonce len:', f"{info.get('nonce_len', 0)} bytes")
            if verbose and info.get('nonce'):
                print_info('Nonce (hex):', info.get('nonce')[:128] + ('...' if len(info.get('nonce', ''))>128 else ''))
        if info.get('mic'):
            print_info('MIC present:', 'Yes')
            print_info('MIC len:', info.get('mic_len', 0))
            if verbose and info.get('mic'):
                print_info('MIC (hex):', info.get('mic'))
        if verbose and info.get('raw_hex'):
            print_section('Raw EAPOL (hex)', Colors.YELLOW)
            hexdata = info['raw_hex']
            for i in range(0, len(hexdata), 64):
                print('  ' + ' '.join([hexdata[j:j+8] for j in range(i, min(i+64, len(hexdata)), 8)]))

# ----------------------- CSV EXPORT -----------------------
def export_to_csv(packet_infos, filename):
    if not packet_infos:
        print(f"{Colors.RED}[!] No data to export{Colors.RESET}")
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base = os.path.splitext(os.path.basename(filename))[0]
    out = f"{base}_analysis_{timestamp}.csv"
    fieldnames = ['packet_number','message_type','description','source_mac','destination_mac','key_info','key_descriptor','nonce','nonce_len','mic','mic_len','replay_counter','timestamp']
    try:
        with open(out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for p in packet_infos:
                w.writerow({
                    'packet_number': p['number'],
                    'message_type': p['type'],
                    'description': p['description'],
                    'source_mac': p['src_mac'],
                    'destination_mac': p['dst_mac'],
                    'key_info': p.get('key_info',''),
                    'key_descriptor': p.get('key_descriptor',''),
                    'nonce': p.get('nonce',''),
                    'nonce_len': p.get('nonce_len',0),
                    'mic': p.get('mic',''),
                    'mic_len': p.get('mic_len',0),
                    'replay_counter': p.get('replay_counter',''),
                    'timestamp': p.get('timestamp','')
                })
        print(f"{Colors.GREEN}[✓] Exported to {out}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to write CSV: {e}{Colors.RESET}")

# ----------------------- DEMO / SYNTHETIC HANDSHAKE -----------------------
def synthesize_demo_handshake():
    """Create a synthetic complete 4-way handshake for demo purposes.
    We do not craft real scapy EAPOL packets here; instead produce packet_info dicts that mirror analyze_packet output.
    """
    now = datetime.now().timestamp()
    ap = 'aa:bb:cc:dd:ee:ff'
    client = '11:22:33:44:55:66'
    # Fake nonces (hex strings)
    anonce = 'a'*64
    snonce = 'b'*64
    demo = []
    # Message 1 (AP -> Client)
    demo.append({
        'number': 1, 'type': 'Message 1', 'description': 'ANonce from AP', 'src_mac': ap, 'dst_mac': client,
        'timestamp': now, 'color': Colors.BLUE, 'key_info': 0x0080, 'key_info_flags': ['ACK'], 'key_descriptor': 'WPA2 (AES)', 'nonce': anonce, 'nonce_len': 32, 'mic': None, 'mic_len': 0, 'replay_counter': 1
    })
    # Message 2 (Client -> AP)
    demo.append({
        'number': 2, 'type': 'Message 2', 'description': 'SNonce + MIC from Client', 'src_mac': client, 'dst_mac': ap,
        'timestamp': now+0.01, 'color': Colors.GREEN, 'key_info': 0x0100, 'key_info_flags': ['MIC','Pairwise'], 'key_descriptor': 'WPA2 (AES)', 'nonce': snonce, 'nonce_len': 32, 'mic': 'c'*32, 'mic_len': 16, 'replay_counter': 1
    })
    # Message 3 (AP -> Client)
    demo.append({
        'number': 3, 'type': 'Message 3', 'description': 'GTK + Install from AP', 'src_mac': ap, 'dst_mac': client,
        'timestamp': now+0.02, 'color': Colors.MAGENTA, 'key_info': 0x0140, 'key_info_flags': ['MIC','ACK','Install'], 'key_descriptor': 'WPA2 (AES)', 'nonce': anonce, 'nonce_len': 32, 'mic': 'd'*32, 'mic_len': 16, 'replay_counter': 2
    })
    # Message 4 (Client -> AP)
    demo.append({
        'number': 4, 'type': 'Message 4', 'description': 'Final ACK from Client', 'src_mac': client, 'dst_mac': ap,
        'timestamp': now+0.03, 'color': Colors.CYAN, 'key_info': 0x0300, 'key_info_flags': ['MIC','ACK','SecureEnc'], 'key_descriptor': 'WPA2 (AES)', 'nonce': None, 'nonce_len': 0, 'mic': 'e'*32, 'mic_len': 16, 'replay_counter': 2
    })
    return demo

# ----------------------- MAIN ANALYSIS FLOW -----------------------
def analyze_handshake(pcap_file, args):
    if args.demo:
        print(f"{Colors.CYAN}[*] Running in demo mode: synthesizing a complete 4-way handshake for showcase{Colors.RESET}")
        packet_infos = synthesize_demo_handshake()
    else:
        print(f"{Colors.CYAN}[*] Loading capture file: {pcap_file}{Colors.RESET}")
        try:
            packets = rdpcap(pcap_file)
            print(f"{Colors.GREEN}[✓] Loaded {len(packets)} total packets{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to read file: {e}{Colors.RESET}")
            return
        eapol_packets = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        if not eapol_packets:
            print(f"{Colors.RED}[!] No EAPOL packets found in capture{Colors.RESET}")
            print(f"{Colors.YELLOW}[i] Try capturing with airodump-ng or ensure you exported the capture correctly{Colors.RESET}")
            return
        print(f"{Colors.GREEN}[✓] Found {len(eapol_packets)} EAPOL packets{Colors.RESET}")
        packet_infos = []
        for i, pkt in enumerate(eapol_packets, 1):
            info = analyze_packet(pkt, i, args.verbose)
            if info:
                packet_infos.append(info)

    if not packet_infos:
        print(f"{Colors.RED}[!] No packets analyzed{Colors.RESET}")
        return

    groups = group_handshakes(packet_infos)
    handshake_results = detect_complete_handshakes(groups)

    print_header('WPA/WPA2 HANDSHAKE ANALYZER', Colors.CYAN)
    print_info('Analysis Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print_info('EAPOL Packets Analyzed:', len(packet_infos))

    # Mode-specific display
    if args.mode == 'summary':
        display_summary_view(packet_infos, handshake_results)
    elif args.mode == 'table':
        # generate a compact table across all packets
        print_header('COMPACT TABLE VIEW', Colors.CYAN)
        headers = ['#','Type','From','To','Nonce','MIC','Replay']
        rows = []
        for p in packet_infos:
            rows.append([p['number'], p['type'], p['src_mac'][-8:].replace(':',''), p['dst_mac'][-8:].replace(':',''), '✓' if p.get('nonce') else '✗', '✓' if p.get('mic') else '✗', p.get('replay_counter')])
        print_table(headers, rows)
    elif args.mode == 'timeline':
        print_header('HANDSHAKE TIMELINE', Colors.MAGENTA)
        for p in sorted(packet_infos, key=lambda x: x.get('timestamp') or 0):
            arrow = '⬇' if p['type'] in ['Message 1','Message 3'] else ('⬆' if p['type'] in ['Message 2','Message 4'] else '↔')
            print(f"{p['number']:02d} {arrow} {p['type']:9} {p['src_mac']} -> {p['dst_mac']}")
    else:
        display_summary_view(packet_infos, handshake_results)
        print()
        display_detailed_view(packet_infos, args.verbose)

    if args.csv and not args.demo:
        export_to_csv(packet_infos, pcap_file)

    # Final summary across handshakes
    any_complete = any(h['present']['Message 1'] and h['present']['Message 2'] and h['present']['Message 3'] and h['present']['Message 4'] for h in handshake_results)
    any_suitable = any(h['suitable_for_cracking'] for h in handshake_results)
    print('\n' + Colors.CYAN + '═' * 60 + Colors.RESET)
    if any_complete:
        print(f"{Colors.GREEN}{Colors.BOLD}[+] ANALYSIS COMPLETE: At least one full 4-way handshake detected!{Colors.RESET}")
    elif any_suitable:
        print(f"{Colors.YELLOW}{Colors.BOLD}[!] ANALYSIS COMPLETE: No full 4-way, but at least one handshake looks suitable for cracking (missing final message maybe).{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}[!] ANALYSIS COMPLETE: No complete or suitable handshakes detected.{Colors.RESET}")

# ----------------------- CLI -----------------------
def main():
    parser = argparse.ArgumentParser(description='Enhanced WPA/WPA2 4-Way Handshake Analyzer')
    parser.add_argument('pcap_file', nargs='?', help='Path to the pcap file (.pcap, .cap)')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-v', '--verbose', action='store_true', help='Show verbose output with hex dumps')
    mode_group.add_argument('-s', '--summary', action='store_true', help='Show only summary information')
    mode_group.add_argument('-t', '--timeline', action='store_true', help='Show timeline view of handshake')
    mode_group.add_argument('--table', action='store_true', help='Show compact table view')
    parser.add_argument('-c', '--csv', action='store_true', help='Export analysis to CSV file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--demo', action='store_true', help='Synthesize a complete handshake for demo/showcase')

    args = parser.parse_args()
    if args.summary:
        args.mode = 'summary'
    elif args.timeline:
        args.mode = 'timeline'
    elif args.table:
        args.mode = 'table'
    else:
        args.mode = 'verbose'

    if args.no_color:
        Colors.disable()

    if not args.demo:
        if not args.pcap_file:
            print(f"{Colors.RED}[!] No pcap file provided. Use --demo to run a synthetic showcase or provide a capture file.{Colors.RESET}")
            sys.exit(1)
        if not os.path.exists(args.pcap_file):
            print(f"{Colors.RED}[!] File not found: {args.pcap_file}{Colors.RESET}")
            sys.exit(1)
        if os.path.getsize(args.pcap_file) == 0:
            print(f"{Colors.RED}[!] File is empty: {args.pcap_file}{Colors.RESET}")
            sys.exit(1)

    try:
        analyze_handshake(args.pcap_file, args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error during analysis:{Colors.RESET} {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
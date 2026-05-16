#script for handshake creation
#!/usr/bin/env python3
"""
Advanced WPA2 4-Way Handshake Analyzer
Shows detailed breakdown of all EAPOL-Key fields.

Usage:
    python3 handshake_analysis.py <pcap_file> [options]

Options:
    -v, --verbose    Show verbose output with hex dumps
    -s, --summary    Show only summary information
    -t, --timeline   Show timeline view of handshake
    -c, --csv        Export to CSV format
    --no-color       Disable colored output
"""

from scapy.all import *
from scapy.layers.eap import EAPOL
import sys
import argparse
import csv
from datetime import datetime
from collections import defaultdict
 ----------------------- COLORS -----------------------
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    # Styles
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    
    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ""
        Colors.CYAN = Colors.MAGENTA = Colors.WHITE = Colors.RESET = ""
        Colors.BG_RED = Colors.BG_GREEN = Colors.BG_YELLOW = Colors.BG_BLUE = ""
        Colors.BOLD = Colors.UNDERLINE = ""
         ----------------------- DISPLAY FUNCTIONS -----------------------
def print_header(title, color=Colors.CYAN):
    """Print formatted header"""
    width = 60
    print(f"\n{color}{Colors.BOLD}╔{'═' * (width-2)}╗")
    print(f"║{title.center(width-2)}║")
    print(f"╚{'═' * (width-2)}╝{Colors.RESET}")

def print_section(title, color=Colors.BLUE):
    """Print section header"""
    print(f"\n{color}{Colors.BOLD}── {title} ──{'─' * 40}{Colors.RESET}")

def print_info(label, value, color=Colors.WHITE):
    """Print key-value information"""
    print(f"{Colors.YELLOW}{label:25}{color}{value}{Colors.RESET}")

def print_table(headers, rows, highlight_row=None):
    """Print formatted table"""
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Print header
    header_line = "┌" + "─" * (sum(col_widths) + len(col_widths) * 3 - 1) + "┐"
    print(f"{Colors.CYAN}{header_line}")
    header_cells = [f" {h:{w}} " for h, w in zip(headers, col_widths)]
    print("│" + "│".join(header_cells) + "│")
    
    # Print separator
    sep_line = "├" + "─" * (sum(col_widths) + len(col_widths) * 3 - 1) + "┤"
    print(sep_line)
    
    # Print rows
    for idx, row in enumerate(rows):
        row_cells = [f" {str(cell):{w}} " for cell, w in zip(row, col_widths)]
        row_str = "│" + "│".join(row_cells) + "│"
        if highlight_row == idx:
            print(f"{Colors.GREEN}{row_str}{Colors.RESET}")
        else:
            print(row_str)
    
    # Print footer
    footer_line = "└" + "─" * (sum(col_widths) + len(col_widths) * 3 - 1) + "┘"
    print(f"{footer_line}{Colors.RESET}")

# ----------------------- DETECT MESSAGE -----------------------
def classify_message(eapol):
    """WPA2/RSN 4-way handshake message classification"""
    if not hasattr(eapol, "key_info"):
        return "Unknown"

    ki = eapol.key_info
 # Bit masks
    key_descriptor = (ki >> 13) & 0x07  # Bits 13-15
    key_type = bool(ki & 0x0008)        # Bit 3
    install = bool(ki & 0x0040)         # Bit 6
    ack = bool(ki & 0x0080)             # Bit 7
    mic = bool(ki & 0x0100)             # Bit 8
    secure = bool(ki & 0x0200)          # Bit 9
    error = bool(ki & 0x0002)           # Bit 1
    request = bool(ki & 0x0001)         # Bit 0
    
    # Determine descriptor type
    if key_descriptor == 1:
        descriptor = "RC4"
    elif key_descriptor == 2:
        descriptor = "AES"
    else:
        descriptor = f"Unknown({key_descriptor})"
    
    # Message classification
    if ack and not mic and not secure:
        return {"type": "Message 1", "desc": "ANonce", "color": Colors.BLUE}
    elif mic and not install and not secure:
        return {"type": "Message 2", "desc": "SNonce + MIC", "color": Colors.GREEN}
    elif mic and install and not secure:
        return {"type": "Message 3", "desc": "GTK + Install", "color": Colors.MAGENTA}
    elif mic and secure and not install:
        return {"type": "Message 4", "desc": "Final ACK", "color": Colors.CYAN}
 elif error:
        return {"type": "Error", "desc": "Key Error", "color": Colors.RED}
    elif request:
        return {"type": "Request", "desc": "Key Request", "color": Colors.YELLOW}
    else:
        return {"type": "Unknown", "desc": descriptor, "color": Colors.WHITE}

def get_key_info_flags(key_info):
    """Parse and return all key info flags"""
    flags = []
    
    # Bit meanings (IEEE 802.11i-2004)
    bit_definitions = {
        0: "Request",
        1: "Error",
        2: "Secure",
        3: "Key Type (1=Pairwise, 0=Group)",
        4: "Key Index (bits 4-5)",
        5: "Key Index",
        6: "Install",
        7: "ACK",
        8: "MIC",
        9: "Secure (encrypted)",
        10: "SMK Message",
        13: "Key Descriptor Type (bits 13-15)",
        14: "Key Descriptor Type",
        15: "Key Descriptor Type"
    }
     elif error:
        return {"type": "Error", "desc": "Key Error", "color": Colors.RED}
    elif request:
        return {"type": "Request", "desc": "Key Request", "color": Colors.YELLOW}
    else:
        return {"type": "Unknown", "desc": descriptor, "color": Colors.WHITE}

for bit in range(16):
        if key_info & (1 << bit):
            if bit in bit_definitions:
                flags.append(bit_definitions[bit])
    
    return flags

# ----------------------- ANALYSIS FUNCTIONS -----------------------
def analyze_packet(pkt, idx, verbose=False):
    """Analyze individual EAPOL packet"""
    eapol = pkt[EAPOL]
    msg_info = classify_message(eapol)
    
    # Basic info
    packet_info = {
        "number": idx,
        "type": msg_info["type"],
        "description": msg_info["desc"],
        "src_mac": pkt[Ether].src,
        "dst_mac": pkt[Ether].dst,
        "timestamp": pkt.time if hasattr(pkt, 'time') else None,
        "color": msg_info["color"]
    }
    
    # Key Info details
    if hasattr(eapol, "key_info"):
        packet_info["key_info"] = eapol.key_info

# Key descriptor version
        key_descriptor = (eapol.key_info >> 13) & 0x07
        if key_descriptor == 2:
            packet_info["key_descriptor"] = "WPA2 (AES-CCMP)"
        elif key_descriptor == 1:
            packet_info["key_descriptor"] = "WPA (RC4/TKIP)"
        else:
            packet_info["key_descriptor"] = f"Unknown ({key_descriptor})"
    
    # Nonce
    try:
        nonce = eapol.wpa_key_nonce
        packet_info["nonce"] = nonce.hex()
        packet_info["nonce_len"] = len(nonce)
    except:
        packet_info["nonce"] = None
    
    # MIC
    try:
        mic = eapol.wpa_key_mic
        packet_info["mic"] = mic.hex()
        packet_info["mic_len"] = len(mic)
    except:
 packet_info["mic"] = None
    
    # Other fields
    packet_info["replay_counter"] = getattr(eapol, 'key_replay_counter', None)
    packet_info["key_length"] = getattr(eapol, 'key_length', None)
    packet_info["key_data_len"] = getattr(eapol, 'wpa_key_data_len', None)
    
    return packet_info

def summarize_handshake(packet_infos):
    """Create summary of handshake"""
    summary = {
        "total_packets": len(packet_infos),
        "message_types": defaultdict(int),
        "mac_addresses": set(),
        "has_full_handshake": False,
        "missing_messages": []
    }
    
    # Count message types
    for info in packet_infos:
        summary["message_types"][info["type"]] += 1
        summary["mac_addresses"].add(info["src_mac"])
        summary["mac_addresses"].add(info["dst_mac"])
    
    # Check for complete handshake
    required = ["Message 1", "Message 2", "Message 3", "Message 4"]
    found = [msg for msg in required if summary["message_types"][msg] > 0]
    return summary

# ----------------------- OUTPUT FORMATS -----------------------
def display_timeline_view(packet_infos):
    """Display timeline view of handshake"""
    print_header("HANDSHAKE TIMELINE VIEW", Colors.MAGENTA)
    
    for info in packet_infos:
        color = info["color"]
        arrow = "→" if info["type"] in ["Message 1", "Message 3"] else "←"
        
        print(f"\n{color}{Colors.BOLD}[{info['number']:02d}] {info['type']:12} {arrow} {info['description']}{Colors.RES>
        print(f"   {Colors.YELLOW}From:{Colors.RESET} {info['src_mac']}")
        print(f"   {Colors.YELLOW}To:{Colors.RESET}   {info['dst_mac']}")

        if info.get('key_descriptor'):
            print(f"   {Colors.YELLOW}Desc:{Colors.RESET} {info['key_descriptor']}")

def display_detailed_view(packet_infos):
    """Display detailed view of all packets"""
    print_header("DETAILED PACKET ANALYSIS", Colors.BLUE)
    
    for info in packet_infos:
        color = info["color"]
        print_section(f"Packet {info['number']}: {info['type']} - {info['description']}", color)

        print_info("Source MAC:", info['src_mac'])
  print_info("Destination MAC:", info['dst_mac'])
        
        if 'key_descriptor' in info:
            print_info("Key Descriptor:", info['key_descriptor'])
        
        print_info("Key Info Value:", f"0x{info.get('key_info', 0):04x}")
        
        if 'key_info_flags' in info:
            print(f"{Colors.YELLOW}Key Info Flags:{Colors.RESET}")
            for flag in info['key_info_flags']:
                print(f"  • {flag}")
        
        if info.get('nonce'):
            nonce = info['nonce']
            print_info("Nonce:", f"{nonce[:16]}...{nonce[-16:]}")
            print_info("Nonce Length:", f"{info.get('nonce_len', 0)} bytes")
        
        if info.get('mic'):
            mic = info['mic']
            print_info("MIC:", f"{mic[:8]}...{mic[-8:]}")
        
        if info.get('replay_counter'):
            print_info("Replay Counter:", info['replay_counter'])

def display_summary_view(packet_infos, summary):
    """Display summary view"""
    print_header("HANDSHAKE SUMMARY", Colors.GREEN)

 print_info("Total Packets:", summary['total_packets'])
    print_info("Unique MACs:", len(summary['mac_addresses']))
    
    print(f"\n{Colors.YELLOW}Message Distribution:{Colors.RESET}")
    for msg_type, count in sorted(summary['message_types'].items()):
        color = Colors.GREEN if count > 0 else Colors.RED
        print(f"  {msg_type:12}: {color}{count}{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}Completeness Check:{Colors.RESET}")
    if summary['has_full_handshake']:
        print(f"{Colors.GREEN}  ✓ Full 4-way handshake detected!{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}  ⚠ Incomplete handshake{Colors.RESET}")
        if summary['missing_messages']:
            print(f"{Colors.RED}  Missing: {', '.join(summary['missing_messages'])}{Colors.RESET}")
    
    # Display MAC addresses
    print(f"\n{Colors.YELLOW}MAC Addresses:{Colors.RESET}")
    for mac in summary['mac_addresses']:
        print(f"  {mac}")

def display_table_view(packet_infos):
    """Display compact table view"""
    print_header("COMPACT TABLE VIEW", Colors.CYAN)
    
    headers = ["#", "Type", "Description", "Source MAC", "Dest MAC", "Nonce", "MIC"]
    rows = []
 for info in packet_infos:
        src_short = info['src_mac'][-8:]
        dst_short = info['dst_mac'][-8:]
        nonce = "Yes" if info.get('nonce') else "No"
        mic = "Yes" if info.get('mic') else "No"
        
        rows.append([
            info['number'],
            info['type'],
            info['description'],
            src_short,
            dst_short,
            nonce,
            mic
        ])
    
    print_table(headers, rows)

def export_to_csv(packet_infos, filename):
    """Export analysis to CSV file"""
    csv_filename = f"handshake_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = [
                 'packet_number', 'message_type', 'description',
            'source_mac', 'destination_mac', 'key_info',
            'key_descriptor', 'nonce', 'nonce_length',
            'mic', 'mic_length', 'replay_counter'
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for info in packet_infos:
            writer.writerow({
                'packet_number': info['number'],
                'message_type': info['type'],
                'description': info['description'],
                'source_mac': info['src_mac'],
                'destination_mac': info['dst_mac'],
                'key_info': info.get('key_info', ''),
                'key_descriptor': info.get('key_descriptor', ''),
                'nonce': info.get('nonce', ''),
                'nonce_length': info.get('nonce_len', 0),
                'mic': info.get('mic', ''),
                'mic_length': info.get('mic_len', 0),
                'replay_counter': info.get('replay_counter', '')
            })
    
    print(f"{Colors.GREEN}[✓] Analysis exported to: {csv_filename}{Colors.RESET}")

# ----------------------- MAIN ANALYSIS -----------------------
def analyze_handshake(pcap_file, args):
    """Main analysis function with multiple output formats"""
    
    # Load pcap file
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to read file: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[i] Tip: Make sure the file exists and is a valid .pcap format{Colors.RESET}")
        return
    
    # Filter EAPOL packets
    eapol_packets = [p for p in packets if p.haslayer(EAPOL)]
    if len(eapol_packets) == 0:
        print(f"{Colors.RED}[!] No EAPOL packets found{Colors.RESET}")
        return
    
    # Analyze all packets
    packet_infos = []
    for i, pkt in enumerate(eapol_packets, 1):
        packet_infos.append(analyze_packet(pkt, i, args.verbose))
    
    # Create summary
    summary = summarize_handshake(packet_infos)
    
    # Display main header
    print_header(f"WPA2 HANDSHAKE ANALYZER - {pcap_file}", Colors.CYAN)
      print(f"{Colors.YELLOW}File:{Colors.RESET} {pcap_file}")
    print(f"{Colors.YELLOW}Date:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.YELLOW}Total Packets:{Colors.RESET} {len(packets)}")
    print(f"{Colors.YELLOW}EAPOL Packets:{Colors.RESET} {len(eapol_packets)}")
    
    # Display based on mode
    if args.mode == 'summary':
        display_summary_view(packet_infos, summary)
    elif args.mode == 'timeline':
        display_timeline_view(packet_infos)
    elif args.mode == 'table':
        display_table_view(packet_infos)
    else:  # verbose/default
        display_summary_view(packet_infos, summary)
        print()
        display_detailed_view(packet_infos)
    
    # Export to CSV if requested
    if args.csv:
        export_to_csv(packet_infos, pcap_file)

# ----------------------- MAIN -----------------------
def main():
    parser = argparse.ArgumentParser(
        description="Advanced WPA2 4-Way Handshake Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
%(prog)s capture.pcap                    # Default detailed view
  %(prog)s capture.pcap -s                # Summary only
  %(prog)s capture.pcap -t                # Timeline view
  %(prog)s capture.pcap -c                # Export to CSV
  %(prog)s capture.pcap -s -t            # Multiple views
  %(prog)s capture.pcap --no-color       # Disable colors
        """
    )
    
    parser.add_argument("pcap_file", help="Path to the pcap file")
    
    # View modes (mutually exclusive group)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("-v", "--verbose", action="store_const", 
                          dest="mode", const="verbose", default="verbose",
                          help="Show verbose output (default)")
    mode_group.add_argument("-s", "--summary", action="store_const",
                          dest="mode", const="summary",
                          help="Show only summary information")
    mode_group.add_argument("-t", "--timeline", action="store_const",
                          dest="mode", const="timeline",
                          help="Show timeline view")
    mode_group.add_argument("--table", action="store_const",
                          dest="mode", const="table",
                          help="Show compact table view")
    
    # Additional options
    parser.add_argument("-c", "--csv", action="store_true",
    help="Export analysis to CSV file")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        Colors.disable()
    
    # Check file exists
    try:
        with open(args.pcap_file, 'rb'):
            pass
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {args.pcap_file}{Colors.RESET}")
        sys.exit(1)
    
    # Run analysis
    try:
        analyze_handshake(args.pcap_file, args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)
if __name__ == "__main__":
    main()
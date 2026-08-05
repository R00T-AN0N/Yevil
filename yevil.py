#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (Absolute Overwrite Engine)
"""

import os
import sys
import subprocess
import time
import signal
import csv
import select
import shutil
import re
import fcntl
import termios
from collections import defaultdict

# ============================================
# ENHANCED ANSI COLORS & STYLES
# ============================================

# Base colors
BLACK = '\033[30m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'

# Bright variants
BRIGHT_RED = '\033[38;5;196m'
BRIGHT_GREEN = '\033[38;5;82m'
BRIGHT_YELLOW = '\033[38;5;226m'
BRIGHT_CYAN = '\033[38;5;51m'
BRIGHT_MAGENTA = '\033[38;5;201m'
ORANGE = '\033[38;5;208m'

# Styles
BOLD = '\033[1m'
DIM = '\033[2m'
ITALIC = '\033[3m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'
RESET = '\033[0m'

# Background colors
BG_BLACK = '\033[40m'
BG_RED = '\033[41m'
BG_GREEN = '\033[42m'
BG_YELLOW = '\033[43m'
BG_BLUE = '\033[44m'
BG_MAGENTA = '\033[45m'
BG_CYAN = '\033[46m'
BG_WHITE = '\033[47m'
BG_DARK_GRAY = '\033[48;5;235m'

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
STOP_SCANNING = False
CSV_PREFIX = '/tmp/yevil_scan'
HAS_SAVED_CURSOR = False

# ============================================
# CLEANUP
# ============================================

def cleanup():
    global MONITOR_INTERFACE, SCANNER_PROCESS
    print(f"\n{YELLOW}[+]{RESET} Cleaning up...")
    if SCANNER_PROCESS:
        try:
            SCANNER_PROCESS.terminate()
            time.sleep(0.5)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
        except:
            pass
        SCANNER_PROCESS = None

    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    if MONITOR_INTERFACE:
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', MONITOR_INTERFACE, 'down'],
                           capture_output=True, check=False)
            subprocess.run(['sudo', 'iw', 'dev', MONITOR_INTERFACE, 'set', 'type', 'managed'],
                           capture_output=True, check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', MONITOR_INTERFACE, 'up'],
                           capture_output=True, check=False)
            print(f"{GREEN}[+]{RESET} {MONITOR_INTERFACE} reset to managed mode")
        except:
            pass
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                           capture_output=True, check=False)
            print(f"{GREEN}[+]{RESET} NetworkManager restarted")
        except:
            pass
    print(f"{GREEN}[+]{RESET} Cleanup complete!")

def signal_handler(sig, frame):
    global STOP_SCANNING
    STOP_SCANNING = True

# ============================================
# ADAPTER FUNCTIONS
# ============================================

def detect_adapters():
    print(f"\n{CYAN}[+]{RESET} Detecting wireless adapters...")
    adapters = []
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                adapter = line.split()[0]
                if adapter not in adapters and 'mon' not in adapter:
                    adapters.append(adapter)
    except:
        pass
    return adapters

def set_monitor_mode(adapter):
    global MONITOR_INTERFACE
    print(f"\n{CYAN}[+]{RESET} Setting {BRIGHT_CYAN}{adapter}{RESET} to monitor mode...")
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, text=True)
        time.sleep(1)
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'],
                       check=True, capture_output=True)
        subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'],
                       check=True, capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'],
                       check=True, capture_output=True)
        MONITOR_INTERFACE = adapter
        result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            print(f"{GREEN}[+]{RESET} ✅ {BRIGHT_GREEN}{adapter}{RESET} is now in {BRIGHT_MAGENTA}MONITOR MODE{RESET}!")
            return True
        else:
            print(f"{RED}[!]{RESET} Monitor mode not verified!")
            return False
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed: {e}")
        return False

# ============================================
# CSV PARSER
# ============================================

def parse_networks(csv_file):
    networks = []
    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 14:
                    continue
                if row[0] == 'BSSID':
                    continue
                bssid = row[0].strip()
                if not bssid:
                    continue
                networks.append({
                    'bssid': bssid,
                    'channel': row[3],
                    'privacy': row[5],
                    'cipher': row[6],
                    'authentication': row[7],
                    'power': row[8],
                    'ssid': row[13].strip() if len(row) > 13 and row[13].strip() else '<Hidden>'
                })
    except:
        pass
    return networks

def parse_stations(csv_file):
    clients = defaultdict(int)
    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 6:
                    continue
                if row[0] == 'Station MAC':
                    continue
                bssid = row[5].strip()
                if bssid:
                    clients[bssid.upper()] += 1
    except:
        pass
    return clients

# ============================================
# UTILITY FUNCTIONS
# ============================================

def strip_ansi(text):
    """Remove ANSI escape codes from text for length calculation."""
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)

def visible_len(text):
    """Get visible length of text (excluding ANSI codes)."""
    return len(strip_ansi(text))

def pad_to_width(text, width):
    """Pad text to exact width, accounting for ANSI codes."""
    vis_len = visible_len(text)
    if vis_len >= width:
        return text
    return text + ' ' * (width - vis_len)

def truncate_text(text, max_width):
    """Truncate text to fit within max_width, preserving ANSI codes."""
    clean = strip_ansi(text)
    if len(clean) <= max_width:
        return text
    if max_width <= 3:
        return text[:max_width]
    # Find where to cut (accounting for ANSI codes in original)
    return text[:max_width-3] + f"{DIM}...{RESET}"

def get_power_color(power_val):
    """Return color based on signal strength."""
    try:
        pwr = int(power_val)
        if pwr > -50:
            return BRIGHT_GREEN
        elif pwr > -65:
            return BRIGHT_YELLOW
        elif pwr > -75:
            return ORANGE
        else:
            return BRIGHT_RED
    except:
        return WHITE

def get_encryption_color(privacy):
    """Return color based on encryption type."""
    p = privacy.upper()
    if 'WPA3' in p or 'SAE' in p:
        return GREEN
    elif 'WPA2' in p:
        return YELLOW
    elif 'WPA' in p:
        return ORANGE
    elif 'WEP' in p:
        return RED
    elif 'OPN' in p:
        return BRIGHT_RED
    return WHITE

# ============================================
# ENHANCED TABLE BUILDER
# ============================================

def draw_horizontal_line(widths, left='┌', mid='┬', right='┐'):
    """Draw a horizontal line with box-drawing characters."""
    parts = [left]
    for i, w in enumerate(widths):
        parts.append('─' * (w + 2))
        if i < len(widths) - 1:
            parts.append(mid)
    parts.append(right)
    return ''.join(parts)

def draw_separator(widths, left='├', mid='┼', right='┤'):
    """Draw a separator line between rows."""
    parts = [left]
    for i, w in enumerate(widths):
        parts.append('─' * (w + 2))
        if i < len(widths) - 1:
            parts.append(mid)
    parts.append(right)
    return ''.join(parts)

def draw_bottom(widths):
    """Draw the bottom border."""
    return draw_horizontal_line(widths, '└', '┴', '┘')

def build_table(networks, clients):
    term_width = shutil.get_terminal_size().columns
    
    # Sort networks by power
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    # Fixed column widths
    col_widths = {
        'num': 4,
        'essid': min(25, max(12, term_width - 95)),
        'bssid': 17,
        'ch': 4,
        'pwr': 6,
        'enc': 10,
        'cipher': 10,
        'auth': 12,
        'clients': 7
    }
    
    widths = list(col_widths.values())
    
    lines = []
    
    # Title bar
    title_text = f" YEVIL WiFi SCANNER │ Networks: {len(networks)} "
    title_bar = f"{BG_DARK_GRAY}{BRIGHT_CYAN}{BOLD}{title_text.center(term_width)}{RESET}"
    lines.append(title_bar)
    lines.append('')
    
    # Top border
    lines.append(f"{CYAN}{draw_horizontal_line(widths)}{RESET}")
    
    # Header row
    headers = [
        f"{BOLD}{WHITE}#",
        f"{BOLD}{WHITE}ESSID",
        f"{BOLD}{WHITE}BSSID",
        f"{BOLD}{WHITE}CH",
        f"{BOLD}{WHITE}PWR",
        f"{BOLD}{WHITE}ENC",
        f"{BOLD}{WHITE}CIPHER",
        f"{BOLD}{WHITE}AUTH",
        f"{BOLD}{WHITE}CLIENTS"
    ]
    
    header_cells = []
    for i, (header, width) in enumerate(zip(headers, widths)):
        header_cells.append(f" {pad_to_width(header, width)} ")
    
    lines.append(f"{CYAN}│{RESET}" + f"{CYAN}│{RESET}".join(header_cells) + f"{CYAN}│{RESET}")
    lines.append(f"{CYAN}{draw_separator(widths)}{RESET}")
    
    # Data rows
    for idx, net in enumerate(networks_sorted, 1):
        pwr_color = get_power_color(net['power'])
        enc_color = get_encryption_color(net['privacy'])
        
        # Format SSID
        ssid = net['ssid']
        if ssid == '<Hidden>':
            ssid_display = f"{DIM}{ITALIC}{ssid}{RESET}"
        else:
            ssid_display = f"{WHITE}{ssid}{RESET}"
        
        ssid_display = truncate_text(ssid_display, col_widths['essid'])
        
        # Get client count
        client_count = clients.get(net['bssid'].upper(), 0)
        client_display = f"{BRIGHT_GREEN}{client_count}{RESET}" if client_count > 0 else f"{DIM}0{RESET}"
        
        # Build row cells
        cells = [
            f" {pad_to_width(f'{BRIGHT_CYAN}{idx}{RESET}', col_widths['num'])} ",
            f" {pad_to_width(ssid_display, col_widths['essid'])} ",
            f" {pad_to_width(f'{MAGENTA}{net['bssid']}{RESET}', col_widths['bssid'])} ",
            f" {pad_to_width(f'{CYAN}{net['channel']}{RESET}', col_widths['ch'])} ",
            f" {pad_to_width(f'{pwr_color}{net['power']}{RESET}', col_widths['pwr'])} ",
            f" {pad_to_width(f'{enc_color}{net['privacy']}{RESET}', col_widths['enc'])} ",
            f" {pad_to_width(f'{WHITE}{net['cipher']}{RESET}', col_widths['cipher'])} ",
            f" {pad_to_width(f'{WHITE}{net['authentication']}{RESET}', col_widths['auth'])} ",
            f" {pad_to_width(client_display, col_widths['clients'])} "
        ]
        
        lines.append(f"{CYAN}│{RESET}" + f"{CYAN}│{RESET}".join(cells) + f"{CYAN}│{RESET}")
    
    # Bottom border
    lines.append(f"{CYAN}{draw_bottom(widths)}{RESET}")
    
    # Footer with instructions
    footer = f"{BG_DARK_GRAY}{BRIGHT_YELLOW} Press 'q' to stop scanning {RESET}"
    lines.append('')
    lines.append(footer)
    
    return lines

# ============================================
# FLAWLESS ANSI UPDATE ENGINE
# ============================================

def update_display(new_lines):
    global HAS_SAVED_CURSOR
    
    if not HAS_SAVED_CURSOR:
        # First time: Save cursor and clear screen below
        sys.stdout.write('\033[s')  # Save cursor position
        HAS_SAVED_CURSOR = True
        # Print table
        sys.stdout.write('\n'.join(new_lines) + '\n')
    else:
        # Restore and clear
        sys.stdout.write('\033[u')  # Restore cursor
        sys.stdout.write('\033[J')  # Clear from cursor to end
        # Print table
        sys.stdout.write('\n'.join(new_lines) + '\n')
    
    sys.stdout.flush()

# ============================================
# SCANNER LOOP
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg',
           '--output-format', 'csv',
           '--write', CSV_PREFIX,
           '--write-interval', '1']
    
    print(f"\n{CYAN}[+]{RESET} Running: {DIM}{' '.join(cmd)}{RESET}")
    print(f"{CYAN}[+]{RESET} Starting real-time UI...")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to start scanner: {e}")
        return

    time.sleep(2)  # Wait for first CSV

    last_networks = []
    last_clients = defaultdict(int)

    # Set stdin to non-blocking for 'q' detection
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    while not STOP_SCANNING:
        # Detect 'q' input
        try:
            ch = sys.stdin.read(1)
            if ch.lower() == 'q':
                STOP_SCANNING = True
                break
        except (BlockingIOError, ValueError):
            pass

        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            time.sleep(0.2)
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)

        if networks != last_networks or clients != last_clients:
            new_lines = build_table(networks, clients)
            update_display(new_lines)
            
            last_networks = networks
            last_clients = clients
        
        time.sleep(0.3)

    # Kill process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(0.5)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

# ============================================
# MAIN
# ============================================

def print_banner():
    banner = f"""
{BRIGHT_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}
{BRIGHT_CYAN}║{RESET}                                                               {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}    {BOLD}{BRIGHT_CYAN}██╗   ██╗{RESET}{CYAN}███████╗{RESET}{BRIGHT_CYAN}██╗   ██╗{RESET}{CYAN}██╗{RESET}{BRIGHT_CYAN}██╗{RESET}                          {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}    {BOLD}{BRIGHT_CYAN}╚██╗ ██╔╝{RESET}{CYAN}██╔════╝{RESET}{BRIGHT_CYAN}██║   ██║{RESET}{CYAN}██║{RESET}{BRIGHT_CYAN}██║{RESET}                          {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}     {BOLD}{BRIGHT_CYAN}╚████╔╝{RESET} {CYAN}█████╗  {RESET}{BRIGHT_CYAN}██║   ██║{RESET}{CYAN}██║{RESET}{BRIGHT_CYAN}██║{RESET}                          {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}      {BOLD}{BRIGHT_CYAN}╚██╔╝{RESET}  {CYAN}██╔══╝  {RESET}{BRIGHT_CYAN}╚██╗ ██╔╝{RESET}{CYAN}██║{RESET}{BRIGHT_CYAN}██║{RESET}                          {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}       {BOLD}{BRIGHT_CYAN}██║{RESET}   {CYAN}███████╗{RESET} {BRIGHT_CYAN}╚████╔╝{RESET} {CYAN}██║{RESET}{BRIGHT_CYAN}███████╗{RESET}                     {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}       {BOLD}{BRIGHT_CYAN}╚═╝{RESET}   {CYAN}╚══════╝{RESET}  {BRIGHT_CYAN}╚═══╝{RESET}  {CYAN}╚═╝{RESET}{BRIGHT_CYAN}╚══════╝{RESET}                     {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}                                                               {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}           {WHITE}WiFi Security Testing Tool {DIM}(ANSI TUI){RESET}               {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}           {YELLOW}⚠️  For Educational Purposes Only!{RESET}                  {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}║{RESET}                                                               {BRIGHT_CYAN}║{RESET}
{BRIGHT_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print_banner()
    print(f"{CYAN}[+]{RESET} Yevil - WiFi Security Testing Tool")
    print(f"{YELLOW}[!]{RESET} For Educational Purposes Only!")
    print(f"{DIM}{'='*50}{RESET}")

    if os.geteuid() != 0:
        print(f"\n{RED}[!]{RESET} This tool requires {BRIGHT_RED}root privileges{RESET}!")
        print(f"{YELLOW}[!]{RESET} Please run with: {BRIGHT_CYAN}sudo python3 yevil.py{RESET}")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        print(f"\n{RED}[!]{RESET} No wireless adapters detected!")
        sys.exit(1)

    print(f"\n{GREEN}[+]{RESET} Detected Adapters:")
    for i, adapter in enumerate(adapters, 1):
        print(f"   {BRIGHT_CYAN}{i}.{RESET} {adapter}")

    print()
    while True:
        try:
            choice = input(f"{CYAN}[?]{RESET} Select adapter (1-{len(adapters)}): ")
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
        except:
            pass
        print(f"{RED}[-]{RESET} Invalid selection!")

    print(f"\n{GREEN}[+]{RESET} Selected: {BRIGHT_CYAN}{selected}{RESET}")

    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
    if 'Mode:Monitor' in result.stdout:
        print(f"{GREEN}[+]{RESET} Already in monitor mode")
        monitor_adapter = selected
    else:
        print(f"{YELLOW}[!]{RESET} Adapter is not in monitor mode!")
        set_mon = input(f"\n{CYAN}[?]{RESET} Set monitor mode now? ({BRIGHT_GREEN}y{RESET}/{BRIGHT_RED}n{RESET}): ")
        if set_mon.lower() == 'y':
            if set_monitor_mode(selected):
                monitor_adapter = selected
            else:
                print(f"{RED}[!]{RESET} Failed to set monitor mode!")
                sys.exit(1)
        else:
            print(f"{YELLOW}[+]{RESET} Exiting...")
            sys.exit(0)

    # Start scan
    start_scanner(monitor_adapter)

    # The table remains perfectly on the screen. We ask for cleanup underneath it.
    print()  # Move cursor down
    print(f"{DIM}{'='*50}{RESET}")
    cleanup_choice = input(f"\n{CYAN}[?]{RESET} Cleanup monitor mode? ({BRIGHT_GREEN}y{RESET}/{BRIGHT_RED}n{RESET}): ")
    if cleanup_choice.lower() == 'y':
        cleanup()
    else:
        print(f"{YELLOW}[+]{RESET} Adapter remains in monitor mode")
        print(f"{DIM}[+]{RESET} Manual cleanup: {DIM}sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up{RESET}")

    print(f"\n{GREEN}[+]{RESET} Done!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[+]{RESET} Ctrl+C detected. Cleaning up...")
        cleanup()
        print(f"{GREEN}[+]{RESET} Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[-]{RESET} Error: {e}")
        cleanup()
        sys.exit(1)

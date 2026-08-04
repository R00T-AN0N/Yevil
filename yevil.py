#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (Single Unified Table using Rich)
"""

import os
import sys
import subprocess
import time
import signal
import csv
from collections import defaultdict

# Rich Library Imports
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
STOP_SCANNING = False
CSV_PREFIX = '/tmp/yevil_scan'
console = Console()

# ============================================
# CLEANUP
# ============================================

def cleanup():
    global MONITOR_INTERFACE, SCANNER_PROCESS
    console.print("\n[bold yellow][+] Cleaning up...[/bold yellow]")
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
            console.print(f"[green][+] {MONITOR_INTERFACE} reset to managed mode[/green]")
        except:
            pass
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                           capture_output=True, check=False)
            console.print("[green][+] NetworkManager restarted[/green]")
        except:
            pass
    console.print("[green][+] Cleanup complete![/green]")

def signal_handler(sig, frame):
    global STOP_SCANNING
    print("\n[!] Ctrl+C detected")
    STOP_SCANNING = True
    cleanup()
    print("\n[+] Goodbye!")
    sys.exit(0)

# ============================================
# ADAPTER FUNCTIONS
# ============================================

def detect_adapters():
    console.print("\n[bold cyan][+] Detecting wireless adapters...[/bold cyan]")
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
    console.print(f"\n[bold cyan][+] Setting {adapter} to monitor mode...[/bold cyan]")
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
            console.print(f"[green][+] ✅ {adapter} is now in MONITOR MODE![/green]")
            return True
        else:
            console.print("[red][!] Monitor mode not verified![/red]")
            return False
    except Exception as e:
        console.print(f"[red][-] Failed: {e}[/red]")
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
                    'beacons': row[9],
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
                if len(row) < 8:
                    continue
                if row[0] == 'Station MAC':
                    continue
                bssid = row[5].strip()
                if bssid:
                    clients[bssid] += 1
    except:
        pass
    return clients

# ============================================
# RICH TABLE GENERATOR (Single Unified Table)
# ============================================

def generate_table(networks, clients):
    """Generate a single Rich Table object."""
    # Sort by signal strength
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    table = Table(title=f"YEVIL - Real-Time WiFi Scanner (Networks found: {len(networks)})",
                  style="bold cyan", expand=True)
    
    table.add_column("#", justify="right", style="bold yellow")
    table.add_column("ESSID", style="cyan", no_wrap=False)
    table.add_column("BSSID", style="magenta")
    table.add_column("CH", justify="center")
    table.add_column("PWR", justify="right")
    table.add_column("ENC", justify="center")
    table.add_column("CIPHER", justify="center")
    table.add_column("AUTH", justify="center")
    table.add_column("CLIENTS", justify="center")

    for idx, net in enumerate(networks_sorted, 1):
        # Determine color based on signal strength
        try:
            pwr = int(net['power'])
            if pwr > -50:
                pwr_color = "green"
            elif pwr > -65:
                pwr_color = "yellow"
            else:
                pwr_color = "red"
        except:
            pwr_color = "white"

        ssid = net['ssid']
        if ssid == '<Hidden>':
            ssid = f"[bold red]<Hidden>[/bold red]"
        
        client_count = clients.get(net['bssid'], 0)

        table.add_row(
            str(idx),
            ssid,
            net['bssid'],
            net['channel'],
            f"[{pwr_color}]{net['power']}[/{pwr_color}]",
            net['privacy'],
            net['cipher'],
            net['authentication'],
            str(client_count)
        )

    table.caption = "Press Ctrl+C to stop scanning | Auto-refreshes every 1 second"
    table.caption_style = "blink bold yellow"
    return table

# ============================================
# SCANNER LOOP (Uses Rich Live to update in-place)
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    # Clean old CSVs
    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg',
           '--output-format', 'csv',
           '--write', CSV_PREFIX,
           '--write-interval', '1']
    
    console.print(f"\n[bold green][+] Running: {' '.join(cmd)}[/bold green]")
    console.print("[yellow][+] Starting real-time UI...[/yellow]")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
    except Exception as e:
        console.print(f"[red][-] Failed to start scanner: {e}[/red]")
        return

    # Wait for first CSV
    time.sleep(2)

    last_networks = []
    last_clients = {}

    # Use Rich Live to handle the single-table updates
    try:
        with Live(refresh_per_second=1, console=console) as live:
            while not STOP_SCANNING:
                time.sleep(0.5)
                csv_file = f'{CSV_PREFIX}-01.csv'
                if not os.path.exists(csv_file):
                    continue

                networks = parse_networks(csv_file)
                clients = parse_stations(csv_file)

                # Only update the table if data actually changed
                if networks != last_networks or clients != last_clients:
                    table = generate_table(networks, clients)
                    live.update(table)
                    last_networks = networks
                    last_clients = clients

    except KeyboardInterrupt:
        pass
    finally:
        # Cleanup process
        if SCANNER_PROCESS:
            SCANNER_PROCESS.terminate()
            time.sleep(1)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
            SCANNER_PROCESS = None

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    # Welcome Banner
    console.print(Panel.fit(
        "[bold cyan]YEVIL - WiFi Security Testing Tool v2.0.0\n"
        "[yellow]⚠️  For Educational Purposes Only![/yellow]",
        border_style="cyan"
    ))

    if os.geteuid() != 0:
        console.print("[bold red][!] This tool requires root privileges![/bold red]")
        console.print("[yellow][!] Please run with: sudo python3 yevil.py[/yellow]")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        console.print("\n[bold red][!] No wireless adapters detected![/bold red]")
        sys.exit(1)

    console.print("\n[bold cyan]📋 Detected Adapters:[/bold cyan]")
    for i, adapter in enumerate(adapters, 1):
        console.print(f"   {i}. {adapter}")

    print()
    while True:
        try:
            choice = input("[?] Select adapter (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
        except:
            pass
        console.print("[red][-] Invalid selection![/red]")

    console.print(f"\n[green][+] Selected: {selected}[/green]")

    # Check mode
    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
    if 'Mode:Monitor' in result.stdout:
        console.print("[green][+] Already in monitor mode[/green]")
        monitor_adapter = selected
    else:
        console.print("[yellow][!] Adapter is not in monitor mode![/yellow]")
        set_mon = input("\n[?] Set monitor mode now? (y/n): ")
        if set_mon.lower() == 'y':
            if set_monitor_mode(selected):
                monitor_adapter = selected
            else:
                console.print("[red][!] Failed to set monitor mode![/red]")
                sys.exit(1)
        else:
            console.print("[yellow][+] Exiting...[/yellow]")
            sys.exit(0)

    start_scanner(monitor_adapter)

    # Post-scan cleanup
    print("\n" + "="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup()
    else:
        console.print("[yellow][+] Adapter remains in monitor mode[/yellow]")
        console.print(f"[yellow][+] Manual cleanup: sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up[/yellow]")

    console.print("\n[bold green][+] Done![/bold green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][+] Ctrl+C detected. Cleaning up...[/bold yellow]")
        cleanup()
        console.print("[bold cyan][+] Goodbye![/bold cyan]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][-] Error: {e}[/bold red]")
        cleanup()
        sys.exit(1)

# pylint: disable=too-many-locals, too-many-branches, too-many-statements, import-outside-toplevel, broad-exception-caught, unused-argument, line-too-long, no-member, no-else-return, unused-import, duplicate-code
"""
Argos — CLI Interface (Elite Purple Edition)
=============================================
Interactive menu with Rich. Corporate purple palette.
No emojis. Elite cybersecurity tool aesthetics.
"""

import sys
import time
import ctypes
import platform
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.live import Live
from rich import box
from argos.core.models import DeviceModel, ScanResultModel

from argos.core.net_utils import (
    get_local_interfaces,
    get_active_interfaces,
    get_network_cidr,
    is_private_ip,
)
from argos.core.discovery import full_scan
from argos.core.speed_test import SpeedTestServer, SpeedTestClient, DEFAULT_PORT
from argos.ui.report import (
    create_device_table,
    display_animated_device_table,
    create_interface_table,
    create_speed_result_panel,
    create_scan_summary,
    create_port_table,
    create_traceroute_table,
    create_ping_summary,
)
from argos.ui.theme import (
    ARGOS_PRIMARY,
    ARGOS_PRIMARY_BOLD,
    ARGOS_PRIMARY_DIM,
    ARGOS_WHITE,
    ARGOS_DIM,
    ARGOS_MUTED,
    ARGOS_SUCCESS,
    ARGOS_SUCCESS_BOLD,
    ARGOS_ERROR,
    ARGOS_ERROR_BOLD,
    ARGOS_WARN,
    ARGOS_WARN_BOLD,
    BANNER_ART,
    BANNER_SUBTITLE,
    BANNER_VERSION,
    create_status_bar,
    create_context_panel,
    create_tcp_flags_panel,
    create_tcp_flags_display,
    print_footer,
    print_section_header,
    create_menu_table,
    argos_log,
)

console = Console()


# ─────────────────────────────────────────────────────────────
# Banner y utilidades
# ─────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """Verifies administrator privileges."""
    try:
        if platform.system().lower() == "windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os

            return os.geteuid() == 0
    except Exception:
        return False


def _get_primary_iface() -> Optional[dict]:
    """Gets the primary active network interface."""
    active = get_active_interfaces()
    if active:
        return active[0]
    all_ifaces = get_local_interfaces()
    candidates = [i for i in all_ifaces if i["is_up"] and i["ip"] != "127.0.0.1"]
    return candidates[0] if candidates else None


def show_banner():
    """Shows banner + status bar."""
    console.print(BANNER_ART)
    console.print(BANNER_SUBTITLE)
    console.print(BANNER_VERSION)
    console.print()

    iface = _get_primary_iface()
    create_status_bar(console, iface, is_admin())


def show_main_menu():
    """Main menu with purple palette. No emojis."""
    admin_status = (
        f"[{ARGOS_SUCCESS}]MODE: Admin[/{ARGOS_SUCCESS}]"
        if is_admin()
        else f"[{ARGOS_ERROR}]MODE: Non-Admin[/{ARGOS_ERROR}]"
    )

    menu = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style=ARGOS_PRIMARY,
        padding=(0, 2),
        title=f"[{ARGOS_PRIMARY_BOLD}]ARGOS -- MAIN MENU[/{ARGOS_PRIMARY_BOLD}]   {admin_status}",
        title_style="bold",
    )
    menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
    menu.add_column(style=ARGOS_WHITE)

    menu.add_row("1", "NETWORK SCAN -- Discover devices on LAN")
    menu.add_row("2", "SPEED TEST -- Measure throughput and latency")
    menu.add_row("3", "NETWORK INTERFACES -- Local adapter info")
    menu.add_row("4", "PACKET FACTORY -- Forge packets (L2/L3/L4)")
    menu.add_row("5", "SECURITY AUDIT -- Passive & active tasks")
    menu.add_row("6", "SENTINEL MODE -- Real-time IDS monitoring")
    menu.add_row("7", "EXIT")

    console.print()
    console.print(menu)
    print_footer(console)
    console.print()


# ─────────────────────────────────────────────────────────────
# Option 1: Network Scan
# ─────────────────────────────────────────────────────────────


def menu_scan_network():
    """Complete network scan flow."""
    print_section_header(console, "NETWORK SCAN")

    iface = _select_interface()
    if iface is None:
        return

    # Network context panel
    create_context_panel(console, "NETWORK DISCOVERY", iface)

    ip = iface["ip"]
    mask = iface["mask"]
    cidr = get_network_cidr(ip, mask)

    if not is_admin():
        console.print(
            f"\n  [{ARGOS_WARN}]WARNING: Non-Admin -- using Ping Sweep (slower)[/{ARGOS_WARN}]"
        )
        console.print(f"  [{ARGOS_DIM}]Run as Administrator for ARP scan[/{ARGOS_DIM}]")

    console.print()

    # Scan with magenta progress bar
    devices: List[DeviceModel] = []
    scan_method = ""
    start_time = time.perf_counter()

    with Progress(
        SpinnerColumn(style=ARGOS_PRIMARY),
        TextColumn(f"[{ARGOS_WHITE}]" + "{task.description}" + f"[/{ARGOS_WHITE}]"),
        BarColumn(bar_width=30, style=ARGOS_PRIMARY_DIM, complete_style=ARGOS_PRIMARY),
        TextColumn(f"[{ARGOS_PRIMARY}]" + "{task.percentage:>3.0f}%" + f"[/{ARGOS_PRIMARY}]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Starting scan...", total=100)

        def update_progress(msg, pct):
            progress.update(task, completed=int(pct * 100), description=msg)

        devices, scan_method = full_scan(ip, mask, progress_callback=update_progress)
        progress.update(task, completed=100, description="Network scan completed")

    if devices:
        from argos.core.vendor_manager import VendorManager
        
        with Progress(
            SpinnerColumn(style=ARGOS_PRIMARY),
            TextColumn(f"[{ARGOS_WHITE}]" + "{task.description}" + f"[/{ARGOS_WHITE}]"),
            BarColumn(bar_width=30, style=ARGOS_PRIMARY_DIM, complete_style=ARGOS_WHITE),
            TextColumn(f"[{ARGOS_PRIMARY}]" + "{task.percentage:>3.0f}%" + f"[/{ARGOS_PRIMARY}]"),
            console=console,
        ) as progress:
            task = progress.add_task("Identifying vendors...", total=100)

            def vendor_progress(msg, pct):
                progress.update(task, completed=int(pct * 100), description=msg)

            vm = VendorManager()
            vm.resolve_vendors_concurrently(devices, progress_callback=vendor_progress)
            progress.update(task, completed=100, description="MAC processing completed")

    elapsed = time.perf_counter() - start_time
    scan_result = ScanResultModel(
        network_cidr=cidr,
        scan_method=scan_method,
        duration_sec=elapsed,
        devices_found=len(devices),
        devices=devices
    )

    if devices:
        console.print()
        display_animated_device_table(console, devices, scan_method, ip)
        console.print()
        console.print(create_scan_summary(devices, scan_method, elapsed, cidr))

        from argos.storage.database import db
        if db.save_scan(scan_result):
            console.print(f"  [{ARGOS_DIM}]>> Results archived in local database (argos_audit.db)[/{ARGOS_DIM}]")

        console.print()
        export_choice = Prompt.ask(
            f"  [{ARGOS_PRIMARY}]Do you want to export the results?[/{ARGOS_PRIMARY}]",
            choices=["y", "n"],
            default="n",
        )
        if export_choice.lower() == "y":
            format_choice = Prompt.ask(
                f"  [{ARGOS_PRIMARY}]Format[/{ARGOS_PRIMARY}]",
                choices=["json", "md", "csv"],
                default="json",
            )
            filename_default = f"argos_scan_{int(time.time())}.{format_choice}"
            filepath = Prompt.ask(
                f"  [{ARGOS_PRIMARY}]File[/{ARGOS_PRIMARY}]",
                default=filename_default,
            )
            
            from argos.storage.exporter import ReportExporter
            success = False
            if format_choice == "json":
                success = ReportExporter.to_json(filepath, scan_result)
            elif format_choice == "md":
                success = ReportExporter.to_markdown(filepath, scan_result)
            elif format_choice == "csv":
                success = ReportExporter.to_csv(filepath, devices)
                
            if success:
                console.print(f"  [{ARGOS_SUCCESS_BOLD}]>> Results exported to {filepath}[/{ARGOS_SUCCESS_BOLD}]")
            else:
                console.print(f"  [{ARGOS_ERROR_BOLD}]X Error exporting results[/{ARGOS_ERROR_BOLD}]")

    else:
        console.print(f"\n  [{ARGOS_WARN}]No devices found on the network.[/{ARGOS_WARN}]")
        console.print(
            f"  [{ARGOS_DIM}]Check your connection or run as administrator.[/{ARGOS_DIM}]"
        )

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back to the menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Option 2: Speed Test
# ─────────────────────────────────────────────────────────────


def menu_speed_test():
    """Speed test (LAN Throughput) flow."""
    print_section_header(console, "ARGOS SPEED TEST :: LAN THROUGHPUT MEASUREMENT")

    console.print(f"[{ARGOS_WHITE}]Select operation mode:[/{ARGOS_WHITE}]")
    console.print(
        f"[{ARGOS_PRIMARY}]1.[/{ARGOS_PRIMARY}] SERVER MODE (Wait for connection from another host)"
    )
    console.print(
        f"[{ARGOS_PRIMARY}]2.[/{ARGOS_PRIMARY}] CLIENT MODE (Connect to an Argos server)"
    )
    console.print()

    choice = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Argos > Speed Mode >[/{ARGOS_PRIMARY}]", choices=["1", "2"], default="2"
    )

    if choice == "1":
        _run_server_mode()
    elif choice == "2":
        _run_client_mode()


def _run_server_mode():
    """Speed test server."""
    active = get_active_interfaces()
    if active:
        ip = active[0]["ip"]
    else:
        ip = "Unknown"

    port = DEFAULT_PORT

    console.print(f"\n[{ARGOS_PRIMARY_BOLD}]:: SERVER MODE ACTIVE ::[/{ARGOS_PRIMARY_BOLD}]")
    console.print(f"[{ARGOS_WHITE}]Local IP:[/{ARGOS_WHITE}] {ip}")
    console.print(f"[{ARGOS_WHITE}]Port:[/{ARGOS_WHITE}] {port}")
    console.print(f"[{ARGOS_PRIMARY}]Waiting for data burst from client...[/{ARGOS_PRIMARY}]\n")

    def server_log(msg):
        # Clean output
        pass

    server = SpeedTestServer(port=port, status_callback=server_log)
    server.start()

    try:
        input()
    except KeyboardInterrupt:
        pass

    server.stop()

    if server.last_result:
        console.print()
        result = server.last_result
        result["server_ip"] = "localhost"
        result["port"] = port
        result["total_MB"] = round(result.get("total_bytes", 0) / (1024 * 1024), 2)
        result["client_speed_mbps"] = result.get("speed_mbps", 0)
        result["client_speed_MBs"] = result.get("speed_MBs", 0)
        console.print(create_speed_result_panel(result))

    console.print(f"\n[{ARGOS_DIM}]Server stopped.[/{ARGOS_DIM}]")
    Prompt.ask(f"[{ARGOS_DIM}]Press Enter to go back to the menu[/{ARGOS_DIM}]")


def _run_client_mode():
    """Speed test client."""
    server_ip = Prompt.ask(f"\n[{ARGOS_PRIMARY}]Server IP[/{ARGOS_PRIMARY}]")

    if not server_ip:
        console.print(f"[{ARGOS_ERROR}]Empty IP, cancelling.[/{ARGOS_ERROR}]")
        return

    if not is_private_ip(server_ip):
        console.print(
            f"[{ARGOS_ERROR_BOLD}]X {server_ip} is not a private IP.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"[{ARGOS_DIM}]Only tests within local network are allowed.[/{ARGOS_DIM}]")
        Prompt.ask(f"[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
        return

    port = DEFAULT_PORT

    console.print(f"\n[{ARGOS_PRIMARY_BOLD}]:: CONNECTED TO {server_ip} ::[/{ARGOS_PRIMARY_BOLD}]")
    console.print(f"[{ARGOS_WHITE}]Sending data blocks (TCP)...[/{ARGOS_WHITE}]\n")

    def client_log(msg):
        pass

    client = SpeedTestClient(status_callback=client_log)

    from argos.core.speed_test import quick_latency_test

    latency = quick_latency_test(server_ip, count=3)
    rtt_ms = latency["avg_ms"] if latency else None

    result = None
    with Progress(
        TextColumn(f"[{ARGOS_PRIMARY}]Progress:[/{ARGOS_PRIMARY}]"),
        BarColumn(bar_width=40, style=ARGOS_PRIMARY_DIM, complete_style=ARGOS_PRIMARY),
        TextColumn(f"[{ARGOS_WHITE}]" + "{task.percentage:>3.0f}%" + f"[/{ARGOS_WHITE}]"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Testing...", total=100)

        def update_client_progress(msg, pct):
            progress.update(task, completed=int(pct * 100))

        result = client.run_test(server_ip, port, 10, update_client_progress)

    if result:
        speed = result.get("client_speed_mbps", 0)
        console.print(
            f"[{ARGOS_WHITE}]Calculated speed:[/{ARGOS_WHITE}] [{ARGOS_SUCCESS_BOLD}]{speed:.1f} Mbps[/{ARGOS_SUCCESS_BOLD}]"
        )
        if rtt_ms:
            console.print(f"[{ARGOS_WHITE}]Latency (RTT):[/{ARGOS_WHITE}] {rtt_ms}ms")
        else:
            console.print(
                f"[{ARGOS_WHITE}]Latency (RTT):[/{ARGOS_WHITE}] [{ARGOS_MUTED}]N/A[/{ARGOS_MUTED}]"
            )
    else:
        console.print(
            f"\n[{ARGOS_ERROR_BOLD}]X Could not complete the speed test.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"[{ARGOS_DIM}]Verify the server is running.[/{ARGOS_DIM}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back to the menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Option 3: Network Interfaces
# ─────────────────────────────────────────────────────────────


def menu_show_interfaces():
    """Shows network interfaces information."""
    print_section_header(console, "NETWORK INTERFACES")

    interfaces = get_local_interfaces()

    if interfaces:
        console.print(create_interface_table(interfaces))
        active = [i for i in interfaces if i["is_up"] and i["ip"] != "127.0.0.1"]
        console.print(
            f"\n  [{ARGOS_DIM}]Total interfaces:[/{ARGOS_DIM}] [{ARGOS_WHITE}]{len(interfaces)}[/{ARGOS_WHITE}]"
        )
        console.print(
            f"  [{ARGOS_DIM}]Active (with IP):[/{ARGOS_DIM}] [{ARGOS_SUCCESS}]{len(active)}[/{ARGOS_SUCCESS}]"
        )
    else:
        console.print(f"  [{ARGOS_WARN}]No network interfaces found.[/{ARGOS_WARN}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back to the menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Option 4: Packet Factory
# ─────────────────────────────────────────────────────────────


def menu_packet_factory():
    """Packet Factory Menu."""
    print_section_header(console, "ARGOS PACKET FACTORY")
    console.print(
        f"  [{ARGOS_DIM}]Packet construction and sending :: OSI Layers 2, 3 and 4[/{ARGOS_DIM}]"
    )

    if not is_admin():
        console.print(
            f"\n  [{ARGOS_WARN_BOLD}]WARNING: Administrator privileges required[/{ARGOS_WARN_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]Run as admin to send raw packets[/{ARGOS_DIM}]")

    console.print()

    submenu = create_menu_table(
        "AVAILABLE OPERATIONS",
        [
            ("1", "LAYER 2", "ARP REQUEST -- Resolve MAC from IP"),
            ("2", "LAYER 3", "ICMP PING -- Custom ping with TTL and size"),
            ("3", "LAYER 3", "TRACEROUTE -- Manual routing with incremental TTL"),
            ("4", "LAYER 4", "TCP SYN PROBE -- TCP ports scan"),
            ("5", "LAYER 4", "TCP CUSTOM -- TCP segment with custom flags"),
            ("6", "LAYER 4", "UDP PROBE -- UDP port scan"),
            ("7", "WIZARD", "VISUAL BUILDER -- Interactive step-by-step packet assembly"),
            ("8", "PRO", "ASYNC BULK SCAN -- Scan 1000+ ports in seconds"),
            ("9", "", "BACK"),
        ],
        has_category=True,
    )

    console.print(submenu)
    print_footer(console)
    console.print()

    choice = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Select operation[/{ARGOS_PRIMARY}]",
        choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        default="9",
    )

    if choice == "1":
        _pf_arp_request()
    elif choice == "2":
        _pf_icmp_ping()
    elif choice == "3":
        _pf_traceroute()
    elif choice == "4":
        _pf_tcp_probe()
    elif choice == "5":
        _pf_tcp_custom()
    elif choice == "6":
        _pf_udp_probe()
    elif choice == "7":
        _pf_visual_builder()
    elif choice == "8":
        _pf_pro_async_scan()


def _pf_log(msg):
    """Logger for Packet Factory."""
    argos_log(console, msg)


def _pf_arp_request():
    """Interactive ARP Request."""
    from argos.core.packet_factory import send_arp_request

    print_section_header(console, "ARP REQUEST :: LAYER 2")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "ARP REQUEST", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    src_mac = Prompt.ask(
        f"  [{ARGOS_PRIMARY}]Source MAC (Enter = auto)[/{ARGOS_PRIMARY}]", default=""
    )

    console.print()
    try:
        result = send_arp_request(
            target_ip, src_mac=src_mac if src_mac else None, log_callback=_pf_log
        )
        if result:
            console.print(
                f"\n  [{ARGOS_SUCCESS_BOLD}]+ MAC resolved: {result['response_mac']}[/{ARGOS_SUCCESS_BOLD}]"
            )
        else:
            console.print(f"\n  [{ARGOS_WARN}]No ARP response from {target_ip}[/{ARGOS_WARN}]")
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_icmp_ping():
    """Custom ICMP Ping."""
    from argos.core.packet_factory import send_icmp_ping

    print_section_header(console, "ICMP PING :: LAYER 3")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "ICMP PING", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    count = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Number of pings[/{ARGOS_PRIMARY}]", default="4"))
    ttl = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]TTL[/{ARGOS_PRIMARY}]", default="64"))
    size = int(
        Prompt.ask(f"  [{ARGOS_PRIMARY}]Payload size (bytes)[/{ARGOS_PRIMARY}]", default="56")
    )

    console.print()
    try:
        stats = send_icmp_ping(
            target_ip, count=count, ttl=ttl, payload_size=size, log_callback=_pf_log
        )
        console.print()
        console.print(create_ping_summary(stats))
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_traceroute():
    """Manual Traceroute."""
    from argos.core.packet_factory import manual_traceroute

    print_section_header(console, "TRACEROUTE :: LAYER 3")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TRACEROUTE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    max_hops = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Max hops[/{ARGOS_PRIMARY}]", default="30"))

    console.print()
    try:
        hops = manual_traceroute(target_ip, max_hops=max_hops, log_callback=_pf_log)
        console.print()
        console.print(create_traceroute_table(hops))
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_tcp_probe():
    """TCP SYN Probe to ports."""
    from argos.core.packet_factory import tcp_port_probe, get_common_port_groups

    print_section_header(console, "TCP SYN PROBE :: LAYER 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TCP SYN PROBE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    groups = get_common_port_groups()
    group_names = list(groups.keys())
    console.print(f"  [{ARGOS_DIM}]Groups: {', '.join(group_names)}[/{ARGOS_DIM}]")

    port_input = Prompt.ask(
        f"  [{ARGOS_PRIMARY}]Ports (e.g. 80,443 or 'web' group)[/{ARGOS_PRIMARY}]", default="top20"
    )

    if port_input in groups:
        ports = groups[port_input]
    else:
        try:
            ports = [int(p.strip()) for p in port_input.split(",")]
        except ValueError:
            console.print(f"  [{ARGOS_ERROR}]Invalid port format[/{ARGOS_ERROR}]")
            return

    console.print()
    try:
        results = tcp_port_probe(target_ip, ports, log_callback=_pf_log)
        console.print()
        console.print(create_port_table(results))
        
        from argos.core.fingerprint import OSFingerprinter
        guess = "Unknown"
        for r in results:
            if r.get("ttl"):
                guess = OSFingerprinter.identify_os_from_ttl(r["ttl"])
                break
        
        if guess == "Unknown":
            from argos.core.packet_factory import send_icmp_ping
            ping_res = send_icmp_ping(target_ip, count=1)
            if ping_res.get("ttl"):
                guess = OSFingerprinter.identify_os_from_ttl(ping_res["ttl"])

        if guess != "Unknown":
            console.print(f"  [{ARGOS_PRIMARY_BOLD}]>> OS HEURISTIC GUESS:[/{ARGOS_PRIMARY_BOLD}] [{ARGOS_WHITE}]{guess}[/{ARGOS_WHITE}]")
        
        open_ports = [r for r in results if r["status"] == "open"]
        console.print(
            f"\n  [{ARGOS_SUCCESS_BOLD}]Open ports: {len(open_ports)}/{len(results)}[/{ARGOS_SUCCESS_BOLD}]"
        )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_tcp_custom():
    """Envio de segmento TCP personalizado con formulario visual de flags."""
    from argos.core.packet_factory import send_tcp_custom

    print_section_header(console, "TCP CUSTOM SEGMENT :: CAPA 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TCP CUSTOM", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination port[/{ARGOS_PRIMARY}]", default="80"))

    # Mostrar formulario de flags disponibles
    console.print(
        f"\n  [{ARGOS_DIM}]Available flags: S(YN) A(CK) F(IN) R(ST) P(SH) U(RG) E(CE) C(WR)[/{ARGOS_DIM}]"
    )
    console.print(
        f"  [{ARGOS_DIM}]Combine letters :: Example: SA = SYN+ACK, FA = FIN+ACK[/{ARGOS_DIM}]\n"
    )

    flags = Prompt.ask(f"  [{ARGOS_PRIMARY}]Flags TCP[/{ARGOS_PRIMARY}]", default="S")

    # Mostrar panel visual de flags seleccionados
    create_tcp_flags_panel(console, flags)
    console.print()

    try:
        result = send_tcp_custom(target_ip, port, flags=flags, log_callback=_pf_log)
        if result:
            console.print(
                f"\n  [{ARGOS_PRIMARY_BOLD}]>> Status: {result.get('status', 'N/A')}[/{ARGOS_PRIMARY_BOLD}]"
            )
            if result.get("flags_received"):
                console.print(
                    f"  [{ARGOS_WHITE}]   Response flags: {result['flags_received']}[/{ARGOS_WHITE}]"
                )
                create_tcp_flags_panel(console, str(result["flags_received"]))
            if result.get("latency_ms"):
                console.print(
                    f"  [{ARGOS_WHITE}]   Latency: {result['latency_ms']} ms[/{ARGOS_WHITE}]"
                )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_udp_probe():
    """Sondeo UDP."""
    from argos.core.packet_factory import send_udp_probe

    print_section_header(console, "UDP PROBE :: CAPA 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "UDP PROBE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination port[/{ARGOS_PRIMARY}]", default="53"))

    console.print()
    try:
        result = send_udp_probe(target_ip, port, log_callback=_pf_log)
        console.print(
            f"\n  [{ARGOS_PRIMARY_BOLD}]>> Port {result['port']}: {result['status'].upper()}[/{ARGOS_PRIMARY_BOLD}]"
        )
        if result.get("latency_ms"):
            console.print(
                f"  [{ARGOS_WHITE}]   Latency: {result['latency_ms']} ms[/{ARGOS_WHITE}]"
            )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")


def _pf_visual_builder():
    """Interactive Visual Packet Builder."""
    from argos.core.packet_factory import (
        craft_ethernet_frame, craft_ip_packet, send_custom_packet
    )
    from scapy.all import ICMP, TCP, UDP, Raw

    print_section_header(console, "VISUAL PACKET BUILDER")
    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "VISUAL BUILDER", iface)

    console.print(f"  [{ARGOS_PRIMARY_BOLD}]=== LAYER 2 (Data Link) ===[/{ARGOS_PRIMARY_BOLD}]")
    use_l2 = Prompt.ask(f"  [{ARGOS_PRIMARY}]Include Ethernet layer?[/{ARGOS_PRIMARY}]", choices=["y", "n"], default="n")
    l2_layer = None
    if use_l2 == "y":
        dst_mac = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination MAC[/{ARGOS_PRIMARY}]", default="ff:ff:ff:ff:ff:ff")
        src_mac = Prompt.ask(f"  [{ARGOS_PRIMARY}]Source MAC[/{ARGOS_PRIMARY}]", default=iface["mac"] if iface else "")
        if dst_mac and src_mac:
            l2_layer = craft_ethernet_frame(dst_mac, src_mac)

    console.print(f"\n  [{ARGOS_PRIMARY_BOLD}]=== LAYER 3 (Network) ===[/{ARGOS_PRIMARY_BOLD}]")
    dst_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
    if not dst_ip: 
        return
    src_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Source IP (Spoofing) [Enter for default][/{ARGOS_PRIMARY}]", default="")
    ttl = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]TTL[/{ARGOS_PRIMARY}]", default="64"))
    
    l3_layer = craft_ip_packet(dst_ip, src_ip if src_ip else None, ttl=ttl)

    console.print(f"\n  [{ARGOS_PRIMARY_BOLD}]=== LAYER 4 (Transport) ===[/{ARGOS_PRIMARY_BOLD}]")
    proto = Prompt.ask(f"  [{ARGOS_PRIMARY}]Protocol[/{ARGOS_PRIMARY}]", choices=["TCP", "UDP", "ICMP", "None"], default="TCP")
    
    l4_layer = None
    if proto == "TCP":
        dport = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination Port[/{ARGOS_PRIMARY}]", default="80"))
        sport_str = Prompt.ask(f"  [{ARGOS_PRIMARY}]Source Port [Enter for random][/{ARGOS_PRIMARY}]", default="")
        flags = Prompt.ask(f"  [{ARGOS_PRIMARY}]TCP Flags (e.g. S, SA, FA, R, PA)[/{ARGOS_PRIMARY}]", default="S")
        
        tcp_kwargs = {"dport": dport, "flags": flags}
        if sport_str.isdigit():
            tcp_kwargs["sport"] = int(sport_str)
        l4_layer = TCP(**tcp_kwargs)
        
    elif proto == "UDP":
        dport = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination Port[/{ARGOS_PRIMARY}]", default="53"))
        sport_str = Prompt.ask(f"  [{ARGOS_PRIMARY}]Source Port [Enter for random][/{ARGOS_PRIMARY}]", default="")
        udp_kwargs = {"dport": dport}
        if sport_str.isdigit():
            udp_kwargs["sport"] = int(sport_str)
        l4_layer = UDP(**udp_kwargs)
        
    elif proto == "ICMP":
        l4_layer = ICMP()

    console.print(f"\n  [{ARGOS_PRIMARY_BOLD}]=== PAYLOAD ===[/{ARGOS_PRIMARY_BOLD}]")
    payload_str = Prompt.ask(f"  [{ARGOS_PRIMARY}]Raw Payload (String) [Enter to skip][/{ARGOS_PRIMARY}]", default="")
    
    # Assembly
    packet = l3_layer
    if l4_layer:
        packet = packet / l4_layer
    if payload_str:
        packet = packet / Raw(load=payload_str)
    if l2_layer:
        packet = l2_layer / packet
        
    console.print(f"\n  [{ARGOS_SUCCESS_BOLD}]>> Packet Assembled:[/{ARGOS_SUCCESS_BOLD}] {packet.summary()}")
    
    confirm = Prompt.ask(f"  [{ARGOS_WARN}]Send packet?[/{ARGOS_WARN}]", choices=["y", "n"], default="y")
    if confirm == "y":
        console.print()
        send_custom_packet(packet, timeout=3, layer2=(l2_layer is not None), log_callback=_pf_log)

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
# Opcion 5: Auditoria de Seguridad
# ─────────────────────────────────────────────────────────────

def menu_security_audit():
    """Corporate security audit submenu."""
    print_section_header(console, "SECURITY AUDIT")
    console.print(f"  [{ARGOS_DIM}]Scan and validate critical network services[/{ARGOS_DIM}]")
    console.print()

    submenu = create_menu_table(
        "AUDIT OPERATIONS",
        [
            ("1", "SSL/TLS", "Check validity and integrity of an HTTPS certificate"),
            ("2", "DHCP", "Search for Rogue DHCP servers (Requires Admin/Scapy)"),
            ("3", "QoS/VoIP", "Measure Jitter & Packet Loss for real-time streams"),
            ("4", "BACK", ""),
        ],
        has_category=True,
    )
    console.print(submenu)
    print_footer(console)
    console.print()

    choice = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Select audit[/{ARGOS_PRIMARY}]",
        choices=["1", "2", "3", "4"],
        default="4",
    )

    if choice == "1":
        _audit_ssl()
    elif choice == "2":
        _audit_dhcp()
    elif choice == "3":
        _audit_qos()

def _audit_ssl():
    """Executes SSL certificate check."""
    from argos.core.audit import ssl_cert_check_advanced

    print_section_header(console, "SSL/TLS AUDIT")
    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Target IP or Domain[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return
        
    port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Port[/{ARGOS_PRIMARY}]", default="443"))

    console.print()
    try:
        result = ssl_cert_check_advanced(target_ip, port, log_callback=_pf_log)
        
        if result["status"] == "ok":
            color_date = ARGOS_ERROR_BOLD if result["expired"] else ARGOS_SUCCESS_BOLD
            console.print(f"\n  [{ARGOS_PRIMARY_BOLD}]>> CERTIFICATE RESULTS:[/{ARGOS_PRIMARY_BOLD}]")
            console.print(f"  [{ARGOS_WHITE}]Issued by:[/{ARGOS_WHITE}] {result['issuer'][:60]}")
            console.print(f"  [{ARGOS_WHITE}]Subject:[/{ARGOS_WHITE}]      {result['subject'][:60]}")
            console.print(f"  [{ARGOS_WHITE}]Valid until:[/{ARGOS_WHITE}] {result['valid_to']}")
            console.print(f"  [{ARGOS_WHITE}]TLS Version:[/{ARGOS_WHITE}]  {result['version']}")
            console.print(f"  [{ARGOS_WHITE}]Status:[/{ARGOS_WHITE}]       [{color_date}]{result['days_left']} days left[/{color_date}]")
            if result["expired"]:
                console.print(f"  [{ARGOS_ERROR_BOLD}]ALERT! CERTIFICATE HAS EXPIRED.[/{ARGOS_ERROR_BOLD}]")
        else:
            console.print(f"\n  [{ARGOS_WARN}]Could not verify certificate. It likely doesn't support TLS or is internal.[/{ARGOS_WARN}]")

    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")

def _audit_dhcp():
    """Executes DHCP server mapping."""
    from argos.core.audit import dhcp_rogue_scan

    print_section_header(console, "DHCP ROGUE DISCOVERY")
    
    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "DHCP DISCOVERY", iface)

    if not is_admin():
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]X ADMINISTRATOR REQUIRED TO SEND DHCP BROADCASTS[/{ARGOS_ERROR_BOLD}]")
        Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
        return

    legit_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Authorized Server IP (Enter to map all)[/{ARGOS_PRIMARY}]", default="")
    
    console.print()
    try:
        rogues = dhcp_rogue_scan(legit_ip, timeout=5, log_callback=_pf_log)
        if rogues:
            console.print(f"\n  [{ARGOS_PRIMARY_BOLD}]>> RESPONDING SERVERS:[/{ARGOS_PRIMARY_BOLD}]")
            for r in rogues:
                is_rogue = r.get("is_rogue", False)
                color = ARGOS_ERROR_BOLD if is_rogue else ARGOS_SUCCESS
                tag = "(ROGUE DETECTED)" if is_rogue else "(Authorized/Unknown)"
                console.print(f"  [{color}]- IP: {r['dhcp_server_ip']} | MAC: {r['server_mac']} | Offers: {r['offered_ip']} {tag}[/{color}]")
        else:
            console.print(f"\n  [{ARGOS_WARN}]No DHCP servers responded on the local network.[/{ARGOS_WARN}]")

    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")

def _pf_pro_async_scan():
    """High-speed Async Port Scan."""
    print_section_header(console, "PRO ASYNC BULK SCAN :: ELITE PERFORMANCE")
    
    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Target IP[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    console.print(f"  [{ARGOS_DIM}]Enter port range (e.g. 1-1024 or 1,80,443)[/{ARGOS_DIM}]")
    port_input = Prompt.ask(f"  [{ARGOS_PRIMARY}]Ports[/{ARGOS_PRIMARY}]", default="1-1024")
    
    ports = []
    try:
        if "-" in port_input:
            start, end = map(int, port_input.split("-"))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in port_input.split(",")]
    except ValueError:
        console.print(f"  [{ARGOS_ERROR}]Invalid format[/{ARGOS_ERROR}]")
        return

    console.print(f"\n  [{ARGOS_WHITE}]Starting Async Scan for {len(ports)} ports...[/{ARGOS_WHITE}]")
    
    from argos.core.scanner_async import run_bulk_scan
    start_time = time.perf_counter()
    
    # We use a simple progress for aesthetics
    with Progress(
        SpinnerColumn(style=ARGOS_PRIMARY),
        TextColumn(f"[{ARGOS_WHITE}]" + "{task.description}" + f"[/{ARGOS_WHITE}]"),
        BarColumn(bar_width=30, style=ARGOS_PRIMARY_DIM, complete_style=ARGOS_PRIMARY),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(ports))
        
        # Note: scanner_async would need a callback to update this exactly, 
        # but for now we just run it and update when done or use a wrapper.
        # Let's use the actual async call with callback.
        import asyncio
        from argos.core.scanner_async import scan_ports_bulk_async
        
        def update_p(msg, pct):
            progress.update(task, completed=int(pct * len(ports)), description=msg)
            
        results = asyncio.run(scan_ports_bulk_async(target_ip, ports, concurrency=500, progress_callback=update_p))

    elapsed = time.perf_counter() - start_time
    console.print(f"\n  [{ARGOS_SUCCESS}]Scan completed in {elapsed:.2f}s[/{ARGOS_SUCCESS}]")
    
    if results:
        # Format results for create_port_table
        table_data = [{"port": r["port"], "status": "open", "service": "", "banner": ""} for r in results]
        console.print(create_port_table(table_data))
    else:
        console.print(f"  [{ARGOS_WARN}]No open ports detected.[/{ARGOS_WARN}]")
        console.print(f"\n  [{ARGOS_WARN}]No open ports detected.[/{ARGOS_WARN}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")

def _audit_qos():
    """Executes QoS / Jitter test."""
    from argos.core.qos import measure_qos_jitter
    from argos.ui.report import create_qos_panel
    from rich.live import Live

    print_section_header(console, "JITTER & QoS ANALYST (VoIP)")
    
    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "QoS ANALYST", iface)

    if not is_admin():
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]X ADMINISTRATOR REQUIRED FOR ACTIVE ICMP PROBING[/{ARGOS_ERROR_BOLD}]")
        Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
        return

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Target IP (e.g. Gateway or 8.8.8.8)[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    count = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Number of probes[/{ARGOS_PRIMARY}]", default="50"))
    
    console.print()

    with Live(create_qos_panel(target_ip, 0, count, 0, 0, 0), console=console, refresh_per_second=10) as live:
        def qos_update(sent, total, avg_lat, jitter, loss_pct):
            live.update(create_qos_panel(target_ip, sent, total, avg_lat, jitter, loss_pct))
            
        try:
            res = measure_qos_jitter(target_ip, count=count, interval=0.05, update_callback=qos_update)
            if res.status == "ok":
                from argos.core.qos import _calculate_mos
                mos, rating = _calculate_mos(res.avg_latency, res.jitter, res.loss_pct)
                final_data = res.model_dump()
                final_data["mos"] = mos
                final_data["rating"] = rating
                
                live.update(create_qos_panel(target_ip, count, count, res.avg_latency, res.jitter, res.loss_pct, final=True, final_res=final_data))
            else:
                live.stop()
                console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {res.status}[/{ARGOS_ERROR_BOLD}]")
        except Exception as e:
            live.stop()
            console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {str(e)}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")

# ─────────────────────────────────────────────────────────────

def menu_sentinel_mode():
    """Sentinel Mode UI flow."""
    from argos.core.sentinel import Sentinel
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    import threading
    
    print_section_header(console, "SENTINEL MODE :: PASSIVE IDS MONITOR")
    
    iface_dict = _get_primary_iface()
    if not iface_dict:
        return
    
    iface_name = iface_dict["name"]

    if not is_admin():
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]X ADMINISTRATOR REQUIRED FOR PASSIVE SNIFFING[/{ARGOS_ERROR_BOLD}]")
        Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
        return

    console.print(f"\n  [{ARGOS_WHITE}]Initializing Sentinel on {iface_name}...[/{ARGOS_WHITE}]")
    console.print(f"  [{ARGOS_DIM}]Passive monitoring mode: No packets will be sent.[/{ARGOS_DIM}]")
    console.print(f"  [{ARGOS_DIM}]Press Ctrl+C to deactivate Sentinel and return to menu.[/{ARGOS_DIM}]")
    console.print()

    events = []
    
    def sentinel_log(msg):
        ts = time.strftime("%H:%M:%S")
        color = ARGOS_WHITE
        if "[CRITICAL]" in msg: color = ARGOS_ERROR_BOLD
        elif "[WARNING]" in msg: color = ARGOS_WARN
        elif "[SUCCESS]" in msg: color = ARGOS_SUCCESS
        
        events.append(f"[{ARGOS_DIM}]{ts}[/{ARGOS_DIM}] [{color}]{msg}[/{color}]")
        if len(events) > 18:
            events.pop(0)

    sentinel = Sentinel(iface_name, log_callback=sentinel_log)
    
    sentinel_thread = threading.Thread(target=sentinel.start, daemon=True)
    sentinel_thread.start()

    try:
        with Live(Panel(Text("Waiting for network events...", justify="center"), title="SENTINEL LIVE LOG", border_style=ARGOS_PRIMARY), console=console, refresh_per_second=4) as live:
            while sentinel.is_running:
                log_content = "\n".join(events) if events else "Listening for traffic patterns..."
                live.update(Panel(Text.from_markup(log_content), title=f"SENTINEL ACTIVE :: {iface_name}", border_style=ARGOS_PRIMARY, subtitle="[ctrl+c to stop]"))
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        sentinel.stop()
        console.print(f"\n  [{ARGOS_PRIMARY}]Sentinel deactivated.[/{ARGOS_PRIMARY}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")

# ─────────────────────────────────────────────────────────────
# Internal Utilities
# ─────────────────────────────────────────────────────────────


def _select_interface() -> Optional[dict]:
    """Active network interface selection."""
    active = get_active_interfaces()

    if not active:
        all_ifaces = get_local_interfaces()
        active = [i for i in all_ifaces if i["is_up"] and i["ip"] != "127.0.0.1"]

    if not active:
        console.print(
            f"  [{ARGOS_ERROR_BOLD}]X No active interfaces found.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]Check your network connection.[/{ARGOS_DIM}]")
        Prompt.ask(f"[{ARGOS_DIM}]Press Enter to go back[/{ARGOS_DIM}]")
        return None

    if len(active) == 1:
        iface = active[0]
        console.print(
            f"  [{ARGOS_DIM}]Detected interface::[/{ARGOS_DIM}] [{ARGOS_SUCCESS}]{iface['name']}[/{ARGOS_SUCCESS}] ({iface['ip']})"
        )
        return iface

    console.print(
        f"  [{ARGOS_PRIMARY_BOLD}]Select a network interface:[/{ARGOS_PRIMARY_BOLD}]\n"
    )
    for i, iface in enumerate(active, 1):
        console.print(
            f"    [{ARGOS_PRIMARY}]{i}[/{ARGOS_PRIMARY}]  {iface['type']}  [{ARGOS_WHITE}]{iface['ip']}[/{ARGOS_WHITE}]  ({iface['name']})"
        )

    console.print()
    choice = IntPrompt.ask(
        f"  [{ARGOS_PRIMARY}]Interface[/{ARGOS_PRIMARY}]",
        default=1,
    )

    idx = choice - 1
    if 0 <= idx < len(active):
        return active[idx]

    console.print(f"  [{ARGOS_ERROR}]Invalid selection.[/{ARGOS_ERROR}]")
    return None


# ─────────────────────────────────────────────────────────────
# Main Loop
# ─────────────────────────────────────────────────────────────


def main_loop():
    """Argos main loop."""
    show_banner()

    while True:
        show_main_menu()

        choice = Prompt.ask(
            f"[{ARGOS_PRIMARY}]Argos >[/{ARGOS_PRIMARY}]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="7",
        )

        if choice == "1":
            menu_scan_network()
        elif choice == "2":
            menu_speed_test()
        elif choice == "3":
            menu_show_interfaces()
        elif choice == "4":
            menu_packet_factory()
        elif choice == "5":
            menu_security_audit()
        elif choice == "6":
            menu_sentinel_mode()
        elif choice == "7":
            console.print(f"\n  [{ARGOS_PRIMARY}]Argos disconnected.[/{ARGOS_PRIMARY}]\n")
            sys.exit(0)

# pylint: disable=line-too-long
"""
Argos — Visual Reports Module (Elite Purple Edition)
Tables and panels with corporate purple palette. No emojis.
"""

from typing import List, Dict, Any, Optional
from argos.core.models import DeviceModel

from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box
import time

from argos.ui.theme import (
    ARGOS_PRIMARY,
    ARGOS_PRIMARY_BOLD,
    ARGOS_WHITE,
    ARGOS_DIM,
    ARGOS_MUTED,
    ARGOS_SUCCESS,
    ARGOS_SUCCESS_BOLD,
    ARGOS_ERROR,
    ARGOS_ERROR_BOLD,
    ARGOS_WARN,
    ARGOS_WARN_BOLD,
    format_latency,
    format_port_status,
)


def create_device_table(devices: List[DeviceModel], scan_method: str = "", _local_ip: str = "") -> Table:
    """Table of discovered devices."""
    title = f"DISCOVERED DEVICES ({len(devices)})"
    if scan_method:
        title += f"  ::  Method: {scan_method}"

    table = Table(
        title=title,
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Hostname", style=ARGOS_WHITE, width=28)
    table.add_column("Latency", width=12, justify="right")
    table.add_column("Vendor", style=ARGOS_MUTED, width=15)

    for i, device in enumerate(devices, 1):
        ip = device.ip
        mac = device.mac
        hostname = device.hostname
        latency = device.latency_ms
        vendor = device.vendor

        lat_str = format_latency(latency)

        if hostname == "Unknown" and ip.endswith(".1"):
            hostname = f"[{ARGOS_WARN}]>> Gateway (probable)[/{ARGOS_WARN}]"

        table.add_row(str(i), ip, mac, hostname, lat_str, vendor)

    return table

def display_animated_device_table(console, devices: List[DeviceModel], scan_method: str = "", _local_ip: str = ""):
    """Displays the device table with Matrix-style animation."""
    title = f"DISCOVERED DEVICES ({len(devices)})"
    if scan_method:
        title += f"  ::  Method: {scan_method}"

    table = Table(
        title=title,
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Hostname", style=ARGOS_WHITE, width=28)
    table.add_column("Latency", width=12, justify="right")
    table.add_column("Vendor", style=ARGOS_MUTED, width=15)

    with Live(table, console=console, refresh_per_second=15, vertical_overflow="visible") as live:
        for i, device in enumerate(devices, 1):
            ip = device.ip
            mac = device.mac
            hostname = device.hostname
            latency = device.latency_ms
            vendor = device.vendor

            lat_str = format_latency(latency)

            if hostname == "Unknown" and ip.endswith(".1"):
                hostname = f"[{ARGOS_WARN}]>> Gateway (probable)[/{ARGOS_WARN}]"

            table.add_row(str(i), ip, mac, hostname, lat_str, vendor)
            time.sleep(0.04) # Animación Matrix


def create_interface_table(interfaces: List[Dict]) -> Table:
    """Network interfaces table."""
    table = Table(
        title="NETWORK INTERFACES",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("Name", style=ARGOS_WHITE, width=30)
    table.add_column("Type", style=ARGOS_PRIMARY, width=14)
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Mask", style=ARGOS_MUTED, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Status", width=10, justify="center")

    for i, iface in enumerate(interfaces, 1):
        status = (
            f"[{ARGOS_SUCCESS}]UP[/{ARGOS_SUCCESS}]"
            if iface["is_up"]
            else f"[{ARGOS_ERROR}]DOWN[/{ARGOS_ERROR}]"
        )
        table.add_row(
            str(i),
            iface["name"],
            iface["type"],
            iface["ip"],
            iface["mask"],
            iface["mac"],
            status,
        )

    return table


def create_speed_result_panel(result: Dict) -> Panel:
    """Speed test results panel."""
    lines = []

    lines.append(
        f"  [{ARGOS_DIM}]Server:[/{ARGOS_DIM}]    [{ARGOS_WHITE}]"
        f"{result.get('server_ip', 'N/A')}:{result.get('port', 'N/A')}[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Duration:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]"
        f"{result.get('duration_s', 0)} s[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Transferred:[/{ARGOS_DIM}] [{ARGOS_WHITE}]"
        f"{result.get('total_MB', 0)} MB[/{ARGOS_WHITE}]"
    )
    lines.append("")

    speed_mbps = result.get("client_speed_mbps", 0)
    speed_mbs = result.get("client_speed_mbs", 0)

    if speed_mbps >= 900:
        color = ARGOS_SUCCESS
        rating = "EXCELLENT (Gigabit)"
    elif speed_mbps >= 400:
        color = ARGOS_SUCCESS
        rating = "GOOD"
    elif speed_mbps >= 100:
        color = ARGOS_WARN
        rating = "ACCEPTABLE"
    elif speed_mbps >= 10:
        color = ARGOS_ERROR
        rating = "SLOW"
    else:
        color = ARGOS_ERROR
        rating = "VERY SLOW"

    lines.append(f"  [{color}]  >> Speed: {speed_mbps} Mbps  ({speed_mbs} MB/s)[/{color}]")
    lines.append(f"  [{color}]  >> Rating: {rating}[/{color}]")
    lines.append("")

    if "server_speed_mbps" in result:
        lines.append(
            f"  [{ARGOS_DIM}]Server measures:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]"
            f"{result['server_speed_mbps']} Mbps ({result.get('server_speed_mbs', 0)} MB/s)"
            f"[/{ARGOS_WHITE}]"
        )

    bar_width = 40
    fill = min(int((speed_mbps / 1000) * bar_width), bar_width)
    progress_bar = (
        f"[{ARGOS_PRIMARY}]{'#' * fill}[/{ARGOS_PRIMARY}]"
        f"[{ARGOS_MUTED}]{'.' * (bar_width - fill)}[/{ARGOS_MUTED}]"
    )
    lines.append(f"\n  {progress_bar}  [{ARGOS_DIM}]{speed_mbps}/1000 Mbps[/{ARGOS_DIM}]")

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]SPEED TEST RESULTS[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


def create_scan_summary(
    devices: List[DeviceModel], scan_method: str, duration: float, network_cidr: str
) -> Panel:
    """Scan summary panel."""
    total = len(devices)
    with_hostname = sum(1 for d in devices if d.hostname != "Unknown")

    latencies = [d.latency_ms for d in devices if d.latency_ms is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    lines = [
        f"  [{ARGOS_DIM}]Scanned Network:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]{network_cidr}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Method:[/{ARGOS_DIM}]         [{ARGOS_WHITE}]{scan_method}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Time:[/{ARGOS_DIM}]           [{ARGOS_WHITE}]{duration:.1f} s[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Devices:[/{ARGOS_DIM}]        [{ARGOS_SUCCESS}]{total}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]With hostname:[/{ARGOS_DIM}]   [{ARGOS_WHITE}]{with_hostname}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Avg Latency:[/{ARGOS_DIM}]     [{ARGOS_WHITE}]{avg_latency:.1f} ms[/{ARGOS_WHITE}]",
    ]

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]SCAN SUMMARY[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


def create_port_table(results: List[Dict]) -> Table:
    """Port scan results table."""
    table = Table(
        title="PORT SCAN RESULTS",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("Port", style=ARGOS_WHITE, width=8, justify="right")
    table.add_column("Service", style=ARGOS_PRIMARY, width=12)
    table.add_column("Status", width=18)
    table.add_column("Flags", style=ARGOS_MUTED, width=10)
    table.add_column("Banner / Info", style=ARGOS_WHITE, width=32)

    for r in results:
        table.add_row(
            str(r["port"]),
            r.get("service", ""),
            format_port_status(r["status"]),
            r.get("flags_received", "-"),
            r.get("banner", "")[:32]
        )

    return table


def create_traceroute_table(hops: List[Dict]) -> Table:
    """Traceroute table."""
    table = Table(
        title="TRACEROUTE",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("TTL", style=ARGOS_PRIMARY, width=5, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Latency", width=12, justify="right")
    table.add_column("Status", width=10)

    for hop in hops:
        lat = format_latency(hop.get("latency_ms"))
        status_str = (
            f"[{ARGOS_SUCCESS}]OK[/{ARGOS_SUCCESS}]"
            if hop.get("status") == "ok"
            else f"[{ARGOS_WARN}]TIMEOUT[/{ARGOS_WARN}]"
        )
        ip_str = hop["ip"] if hop["ip"] != "*" else f"[{ARGOS_MUTED}]*[/{ARGOS_MUTED}]"
        table.add_row(str(hop["ttl"]), ip_str, lat, status_str)

    return table


def create_ping_summary(stats: Dict) -> Panel:
    """ICMP ping summary panel."""
    lines = [
        f"  [{ARGOS_DIM}]Target:[/{ARGOS_DIM}]      "
        f"[{ARGOS_WHITE}]{stats.get('dst', 'N/A')}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Sent:[/{ARGOS_DIM}]        "
        f"[{ARGOS_WHITE}]{stats.get('sent', 0)}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Received:[/{ARGOS_DIM}]    "
        f"[{ARGOS_SUCCESS}]{stats.get('received', 0)}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]Lost:[/{ARGOS_DIM}]        "
        f"[{ARGOS_ERROR}]{stats.get('lost', 0)} ({stats.get('loss_pct', 0)}%)[/{ARGOS_ERROR}]",
        "",
    ]

    if stats.get("min_ms") is not None:
        lines.extend(
            [
                f"  [{ARGOS_DIM}]Minimum:[/{ARGOS_DIM}]       {format_latency(stats['min_ms'])}",
                f"  [{ARGOS_DIM}]Average:[/{ARGOS_DIM}]       {format_latency(stats['avg_ms'])}",
                f"  [{ARGOS_DIM}]Maximum:[/{ARGOS_DIM}]       {format_latency(stats['max_ms'])}",
            ]
        )

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]ICMP PING RESULTS[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


def create_qos_panel(target: str, sent: int, total: int, avg_lat: float, jitter: float, loss_pct: float, final: bool = False, final_res: Dict = None) -> Panel:
    """Real-time QoS & Jitter display panel."""
    progress_bar = f"[{ARGOS_PRIMARY}]{'#' * int((sent/total)*20)}[/{ARGOS_PRIMARY}][{ARGOS_MUTED}]{'.' * (20 - int((sent/total)*20))}[/{ARGOS_MUTED}]"

    lines = [
        f"  [{ARGOS_DIM}]Target:[/{ARGOS_DIM}]      [{ARGOS_WHITE}]{target}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Progress:[/{ARGOS_DIM}]    {progress_bar} [{ARGOS_WHITE}]{sent}/{total}[/{ARGOS_WHITE}]",
        "",
        f"  [{ARGOS_DIM}]Avg Latency:[/{ARGOS_DIM}] {format_latency(avg_lat)}",
    ]
    
    # Jitter Color
    j_color = ARGOS_SUCCESS if jitter < 15 else (ARGOS_WARN if jitter < 30 else ARGOS_ERROR)
    lines.append(f"  [{ARGOS_DIM}]Jitter:[/{ARGOS_DIM}]      [{j_color}]{jitter:.1f} ms[/{j_color}]")
    
    # Loss Color
    l_color = ARGOS_SUCCESS if loss_pct == 0 else ARGOS_ERROR
    lines.append(f"  [{ARGOS_DIM}]Packet Loss:[/{ARGOS_DIM}] [{l_color}]{loss_pct:.1f}%[/{l_color}]")

    if final and final_res:
        lines.append("")
        mos = final_res["mos"]
        rating = final_res["rating"]
        r_color = ARGOS_SUCCESS_BOLD if mos >= 3.6 else (ARGOS_WARN_BOLD if mos >= 3.0 else ARGOS_ERROR_BOLD)
        
        lines.append(f"  [{ARGOS_PRIMARY_BOLD}]>> VoIP Readiness Assessment <<[/{ARGOS_PRIMARY_BOLD}]")
        lines.append(f"  [{ARGOS_DIM}]MOS Score:[/{ARGOS_DIM}]   [{r_color}]{mos} / 5.0[/{r_color}]")
        lines.append(f"  [{ARGOS_DIM}]Net Rating:[/{ARGOS_DIM}]  [{r_color}]{rating}[/{r_color}]")

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]JITTER & QoS ANALYST[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


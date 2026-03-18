# pylint: disable=line-too-long
"""
Argos — Modulo de Reportes Visuales (Elite Purple Edition)
Tablas y paneles con paleta morada corporativa. Sin emojis.
"""

from typing import List, Dict

from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box
import time

from ui.theme import (
    ARGOS_PRIMARY,
    ARGOS_PRIMARY_BOLD,
    ARGOS_WHITE,
    ARGOS_DIM,
    ARGOS_MUTED,
    ARGOS_SUCCESS,
    ARGOS_ERROR,
    ARGOS_WARN,
    format_latency,
    format_port_status,
)


def create_device_table(devices: List[Dict], scan_method: str = "", _local_ip: str = "") -> Table:
    """Tabla de dispositivos descubiertos."""
    title = f"DISPOSITIVOS DESCUBIERTOS ({len(devices)})"
    if scan_method:
        title += f"  ::  Metodo: {scan_method}"

    table = Table(
        title=title,
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEADED,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Hostname", style=ARGOS_WHITE, width=28)
    table.add_column("Latencia", width=12, justify="right")
    table.add_column("Fabricante", style=ARGOS_MUTED, width=15)

    for i, device in enumerate(devices, 1):
        ip = device["ip"]
        mac = device.get("mac", "N/A")
        hostname = device.get("hostname", "Desconocido")
        latency = device.get("latency_ms")
        vendor = device.get("vendor", "")

        lat_str = format_latency(latency)

        if hostname == "Desconocido" and ip.endswith(".1"):
            hostname = f"[{ARGOS_WARN}]>> Gateway (probable)[/{ARGOS_WARN}]"

        table.add_row(str(i), ip, mac, hostname, lat_str, vendor)

    return table

def display_animated_device_table(console, devices: List[Dict], scan_method: str = "", _local_ip: str = ""):
    """Muestra la tabla de dispositivos con animación estilo Matrix."""
    title = f"DISPOSITIVOS DESCUBIERTOS ({len(devices)})"
    if scan_method:
        title += f"  ::  Metodo: {scan_method}"

    table = Table(
        title=title,
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEADED,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Hostname", style=ARGOS_WHITE, width=28)
    table.add_column("Latencia", width=12, justify="right")
    table.add_column("Fabricante", style=ARGOS_MUTED, width=15)

    with Live(table, console=console, refresh_per_second=15, vertical_overflow="visible") as live:
        for i, device in enumerate(devices, 1):
            ip = device["ip"]
            mac = device.get("mac", "N/A")
            hostname = device.get("hostname", "Desconocido")
            latency = device.get("latency_ms")
            vendor = device.get("vendor", "")

            lat_str = format_latency(latency)

            if hostname == "Desconocido" and ip.endswith(".1"):
                hostname = f"[{ARGOS_WARN}]>> Gateway (probable)[/{ARGOS_WARN}]"

            table.add_row(str(i), ip, mac, hostname, lat_str, vendor)
            time.sleep(0.04) # Animación Matrix


def create_interface_table(interfaces: List[Dict]) -> Table:
    """Tabla de interfaces de red."""
    table = Table(
        title="INTERFACES DE RED",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEADED,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("Nombre", style=ARGOS_WHITE, width=30)
    table.add_column("Tipo", style=ARGOS_PRIMARY, width=14)
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Mascara", style=ARGOS_MUTED, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Estado", width=10, justify="center")

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
    """Panel de resultados del speed test."""
    lines = []

    lines.append(
        f"  [{ARGOS_DIM}]Servidor:[/{ARGOS_DIM}]    [{ARGOS_WHITE}]"
        f"{result.get('server_ip', 'N/A')}:{result.get('port', 'N/A')}[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Duracion:[/{ARGOS_DIM}]    [{ARGOS_WHITE}]"
        f"{result.get('duration_s', 0)} s[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Transferido:[/{ARGOS_DIM}] [{ARGOS_WHITE}]"
        f"{result.get('total_MB', 0)} MB[/{ARGOS_WHITE}]"
    )
    lines.append("")

    speed_mbps = result.get("client_speed_mbps", 0)
    speed_mbs = result.get("client_speed_mbs", 0)

    if speed_mbps >= 900:
        color = ARGOS_SUCCESS
        rating = "EXCELENTE (Gigabit)"
    elif speed_mbps >= 400:
        color = ARGOS_SUCCESS
        rating = "BUENA"
    elif speed_mbps >= 100:
        color = ARGOS_WARN
        rating = "ACEPTABLE"
    elif speed_mbps >= 10:
        color = ARGOS_ERROR
        rating = "LENTA"
    else:
        color = ARGOS_ERROR
        rating = "MUY LENTA"

    lines.append(f"  [{color}]  >> Velocidad: {speed_mbps} Mbps  ({speed_mbs} MB/s)[/{color}]")
    lines.append(f"  [{color}]  >> Rating: {rating}[/{color}]")
    lines.append("")

    if "server_speed_mbps" in result:
        lines.append(
            f"  [{ARGOS_DIM}]Servidor mide:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]"
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
        box=box.SQUARE_DOUBLE_HEADED,
    )


def create_scan_summary(
    devices: List[Dict], scan_method: str, duration: float, network_cidr: str
) -> Panel:
    """Panel resumen del escaneo."""
    total = len(devices)
    with_hostname = sum(1 for d in devices if d.get("hostname", "Desconocido") != "Desconocido")

    latencies = [d["latency_ms"] for d in devices if d.get("latency_ms") is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    lines = [
        f"  [{ARGOS_DIM}]Red escaneada:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]{network_cidr}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Metodo:[/{ARGOS_DIM}]         [{ARGOS_WHITE}]{scan_method}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Tiempo:[/{ARGOS_DIM}]         [{ARGOS_WHITE}]{duration:.1f} s[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Dispositivos:[/{ARGOS_DIM}]   [{ARGOS_SUCCESS}]{total}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]Con hostname:[/{ARGOS_DIM}]   [{ARGOS_WHITE}]{with_hostname}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Latencia media:[/{ARGOS_DIM}] [{ARGOS_WHITE}]{avg_latency:.1f} ms[/{ARGOS_WHITE}]",
    ]

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]SCAN SUMMARY[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEADED,
    )


def create_port_table(results: List[Dict]) -> Table:
    """Tabla de resultados de port scan."""
    table = Table(
        title="PORT SCAN RESULTS",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEADED,
    )

    table.add_column("Puerto", style=ARGOS_WHITE, width=8, justify="right")
    table.add_column("Servicio", style=ARGOS_PRIMARY, width=12)
    table.add_column("Estado", width=18)
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
    """Tabla de traceroute."""
    table = Table(
        title="TRACEROUTE",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEADED,
    )

    table.add_column("TTL", style=ARGOS_PRIMARY, width=5, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Latencia", width=12, justify="right")
    table.add_column("Estado", width=10)

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
    """Panel resumen de ICMP ping."""
    lines = [
        f"  [{ARGOS_DIM}]Destino:[/{ARGOS_DIM}]     "
        f"[{ARGOS_WHITE}]{stats.get('dst', 'N/A')}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Enviados:[/{ARGOS_DIM}]    "
        f"[{ARGOS_WHITE}]{stats.get('sent', 0)}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Recibidos:[/{ARGOS_DIM}]   "
        f"[{ARGOS_SUCCESS}]{stats.get('received', 0)}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]Perdidos:[/{ARGOS_DIM}]    "
        f"[{ARGOS_ERROR}]{stats.get('lost', 0)} ({stats.get('loss_pct', 0)}%)[/{ARGOS_ERROR}]",
        "",
    ]

    if stats.get("min_ms") is not None:
        lines.extend(
            [
                f"  [{ARGOS_DIM}]Minimo:[/{ARGOS_DIM}]     {format_latency(stats['min_ms'])}",
                f"  [{ARGOS_DIM}]Media:[/{ARGOS_DIM}]      {format_latency(stats['avg_ms'])}",
                f"  [{ARGOS_DIM}]Maximo:[/{ARGOS_DIM}]     {format_latency(stats['max_ms'])}",
            ]
        )

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]ICMP PING RESULTS[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEADED,
    )

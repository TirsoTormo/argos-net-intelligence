# pylint: disable=too-many-locals, too-many-branches, too-many-statements, import-outside-toplevel, broad-exception-caught, unused-argument, line-too-long, no-member, no-else-return, unused-import, duplicate-code
"""
Argos — Interfaz CLI (Elite Purple Edition)
=============================================
Menu interactivo con Rich. Paleta morada corporativa.
Sin emojis. Estetica de herramienta de ciberseguridad elite.
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

from modules.net_utils import (
    get_local_interfaces,
    get_active_interfaces,
    get_network_cidr,
    is_private_ip,
)
from modules.discovery import full_scan
from modules.speed_test import SpeedTestServer, SpeedTestClient, DEFAULT_PORT
from modules.report import (
    create_device_table,
    create_interface_table,
    create_speed_result_panel,
    create_scan_summary,
    create_port_table,
    create_traceroute_table,
    create_ping_summary,
)
from modules.theme import (
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
    """Verifica privilegios de administrador."""
    try:
        if platform.system().lower() == "windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os

            return os.geteuid() == 0
    except Exception:
        return False


def _get_primary_iface() -> Optional[dict]:
    """Obtiene la interfaz de red principal activa."""
    active = get_active_interfaces()
    if active:
        return active[0]
    all_ifaces = get_local_interfaces()
    candidates = [i for i in all_ifaces if i["is_up"] and i["ip"] != "127.0.0.1"]
    return candidates[0] if candidates else None


def show_banner():
    """Muestra banner + status bar."""
    console.print(BANNER_ART)
    console.print(BANNER_SUBTITLE)
    console.print(BANNER_VERSION)
    console.print()

    iface = _get_primary_iface()
    create_status_bar(console, iface, is_admin())


def show_main_menu():
    """Menu principal con paleta morada. Sin emojis."""
    admin_status = (
        f"[{ARGOS_SUCCESS}]MODO: Admin[/{ARGOS_SUCCESS}]"
        if is_admin()
        else f"[{ARGOS_ERROR}]MODO: Sin Admin[/{ARGOS_ERROR}]"
    )

    menu = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style=ARGOS_PRIMARY,
        padding=(0, 2),
        title=f"[{ARGOS_PRIMARY_BOLD}]ARGOS -- MENU PRINCIPAL[/{ARGOS_PRIMARY_BOLD}]   {admin_status}",
        title_style="bold",
    )
    menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
    menu.add_column(style=ARGOS_WHITE)

    menu.add_row("1", "ESCANEAR RED -- Descubrir dispositivos en la LAN")
    menu.add_row("2", "TEST DE VELOCIDAD -- Medir rendimiento entre equipos")
    menu.add_row("3", "INTERFACES DE RED -- Informacion de adaptadores locales")
    menu.add_row("4", "PACKET FACTORY -- Forjar paquetes (Capas 2/3/4)")
    menu.add_row("5", "SALIR")

    console.print()
    console.print(menu)
    print_footer(console)
    console.print()


# ─────────────────────────────────────────────────────────────
# Opcion 1: Escaneo de red
# ─────────────────────────────────────────────────────────────


def menu_scan_network():
    """Flujo completo de escaneo de red."""
    print_section_header(console, "ESCANEAR RED")

    iface = _select_interface()
    if iface is None:
        return

    # Panel de contexto de red
    create_context_panel(console, "NETWORK DISCOVERY", iface)

    ip = iface["ip"]
    mask = iface["mask"]
    cidr = get_network_cidr(ip, mask)

    if not is_admin():
        console.print(
            f"\n  [{ARGOS_WARN}]AVISO: Sin admin -- se usara Ping Sweep (mas lento)[/{ARGOS_WARN}]"
        )
        console.print(f"  [{ARGOS_DIM}]Ejecuta como administrador para ARP scan[/{ARGOS_DIM}]")

    console.print()

    # Escanear con barra de progreso magenta
    devices = []
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
        task = progress.add_task("Iniciando escaneo...", total=100)

        def update_progress(msg, pct):
            progress.update(task, completed=int(pct * 100), description=msg)

        devices, scan_method = full_scan(ip, mask, progress_callback=update_progress)
        progress.update(task, completed=100, description="Escaneo completado")

    elapsed = time.perf_counter() - start_time

    if devices:
        console.print()
        console.print(create_device_table(devices, scan_method, ip))
        console.print()
        console.print(create_scan_summary(devices, scan_method, elapsed, cidr))
    else:
        console.print(f"\n  [{ARGOS_WARN}]No se encontraron dispositivos en la red.[/{ARGOS_WARN}]")
        console.print(
            f"  [{ARGOS_DIM}]Verifica tu conexion o ejecuta como administrador.[/{ARGOS_DIM}]"
        )

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver al menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Opcion 2: Test de velocidad
# ─────────────────────────────────────────────────────────────


def menu_speed_test():
    """Flujo del test de velocidad LAN."""
    print_section_header(console, "ARGOS SPEED TEST :: MEDICION DE RENDIMIENTO LAN")

    console.print(f"[{ARGOS_WHITE}]Seleccione el modo de operacion:[/{ARGOS_WHITE}]")
    console.print(
        f"[{ARGOS_PRIMARY}]1.[/{ARGOS_PRIMARY}] MODO SERVIDOR (Esperar conexion de otro equipo)"
    )
    console.print(
        f"[{ARGOS_PRIMARY}]2.[/{ARGOS_PRIMARY}] MODO CLIENTE  (Conectar a un servidor de Argos)"
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
    """Servidor de speed test."""
    active = get_active_interfaces()
    if active:
        ip = active[0]["ip"]
    else:
        ip = "Desconocida"

    port = DEFAULT_PORT

    console.print(f"\n[{ARGOS_PRIMARY_BOLD}]:: MODO SERVIDOR ACTIVO ::[/{ARGOS_PRIMARY_BOLD}]")
    console.print(f"[{ARGOS_WHITE}]IP Local:[/{ARGOS_WHITE}] {ip}")
    console.print(f"[{ARGOS_WHITE}]Puerto:[/{ARGOS_WHITE}] {port}")
    console.print(f"[{ARGOS_PRIMARY}]Esperando rafaga de datos del cliente...[/{ARGOS_PRIMARY}]\n")

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

    console.print(f"\n[{ARGOS_DIM}]Servidor detenido.[/{ARGOS_DIM}]")
    Prompt.ask(f"[{ARGOS_DIM}]Presiona Enter para volver al menu[/{ARGOS_DIM}]")


def _run_client_mode():
    """Cliente de speed test."""
    server_ip = Prompt.ask(f"\n[{ARGOS_PRIMARY}]IP del servidor[/{ARGOS_PRIMARY}]")

    if not server_ip:
        console.print(f"[{ARGOS_ERROR}]IP vacia, cancelando.[/{ARGOS_ERROR}]")
        return

    if not is_private_ip(server_ip):
        console.print(
            f"[{ARGOS_ERROR_BOLD}]X {server_ip} no es una IP privada.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"[{ARGOS_DIM}]Solo se permiten tests dentro de la red local.[/{ARGOS_DIM}]")
        Prompt.ask(f"[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")
        return

    port = DEFAULT_PORT

    console.print(f"\n[{ARGOS_PRIMARY_BOLD}]:: CONECTADO A {server_ip} ::[/{ARGOS_PRIMARY_BOLD}]")
    console.print(f"[{ARGOS_WHITE}]Enviando bloques de datos (TCP)...[/{ARGOS_WHITE}]\n")

    def client_log(msg):
        pass

    client = SpeedTestClient(status_callback=client_log)

    from modules.speed_test import quick_latency_test

    latency = quick_latency_test(server_ip, count=3)
    rtt_ms = latency["avg_ms"] if latency else None

    result = None
    with Progress(
        TextColumn(f"[{ARGOS_PRIMARY}]Progreso:[/{ARGOS_PRIMARY}]"),
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
            f"[{ARGOS_WHITE}]Velocidad calculada:[/{ARGOS_WHITE}] [{ARGOS_SUCCESS_BOLD}]{speed:.1f} Mbps[/{ARGOS_SUCCESS_BOLD}]"
        )
        if rtt_ms:
            console.print(f"[{ARGOS_WHITE}]Latencia (RTT):[/{ARGOS_WHITE}] {rtt_ms}ms")
        else:
            console.print(
                f"[{ARGOS_WHITE}]Latencia (RTT):[/{ARGOS_WHITE}] [{ARGOS_MUTED}]N/A[/{ARGOS_MUTED}]"
            )
    else:
        console.print(
            f"\n[{ARGOS_ERROR_BOLD}]X No se pudo completar el test de velocidad.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"[{ARGOS_DIM}]Verifica que el servidor este ejecutandose.[/{ARGOS_DIM}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver al menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Opcion 3: Interfaces de red
# ─────────────────────────────────────────────────────────────


def menu_show_interfaces():
    """Muestra informacion de interfaces de red."""
    print_section_header(console, "INTERFACES DE RED")

    interfaces = get_local_interfaces()

    if interfaces:
        console.print(create_interface_table(interfaces))
        active = [i for i in interfaces if i["is_up"] and i["ip"] != "127.0.0.1"]
        console.print(
            f"\n  [{ARGOS_DIM}]Total interfaces:[/{ARGOS_DIM}] [{ARGOS_WHITE}]{len(interfaces)}[/{ARGOS_WHITE}]"
        )
        console.print(
            f"  [{ARGOS_DIM}]Activas (con IP):[/{ARGOS_DIM}] [{ARGOS_SUCCESS}]{len(active)}[/{ARGOS_SUCCESS}]"
        )
    else:
        console.print(f"  [{ARGOS_WARN}]No se encontraron interfaces de red.[/{ARGOS_WARN}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver al menu[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Opcion 4: Packet Factory
# ─────────────────────────────────────────────────────────────


def menu_packet_factory():
    """Menu de la Fabrica de Paquetes."""
    print_section_header(console, "ARGOS PACKET FACTORY")
    console.print(
        f"  [{ARGOS_DIM}]Construccion y envio de paquetes :: Capas 2, 3 y 4 del modelo OSI[/{ARGOS_DIM}]"
    )

    if not is_admin():
        console.print(
            f"\n  [{ARGOS_WARN_BOLD}]AVISO: Se requieren privilegios de administrador[/{ARGOS_WARN_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]Ejecuta como admin para enviar paquetes raw[/{ARGOS_DIM}]")

    console.print()

    submenu = create_menu_table(
        "OPERACIONES DISPONIBLES",
        [
            ("1", "CAPA 2", "ARP REQUEST -- Resolver MAC de una IP"),
            ("2", "CAPA 3", "ICMP PING -- Ping personalizado con TTL y size"),
            ("3", "CAPA 3", "TRACEROUTE -- Trazado manual con TTL incremental"),
            ("4", "CAPA 4", "TCP SYN PROBE -- Sondeo de puertos TCP"),
            ("5", "CAPA 4", "TCP CUSTOM -- Segmento TCP con flags personalizados"),
            ("6", "CAPA 4", "UDP PROBE -- Sondeo de puerto UDP"),
            ("7", "", "VOLVER"),
        ],
        has_category=True,
    )

    console.print(submenu)
    print_footer(console)
    console.print()

    choice = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Selecciona operacion[/{ARGOS_PRIMARY}]",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="7",
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


def _pf_log(msg):
    """Logger para Packet Factory."""
    argos_log(console, msg)


def _pf_arp_request():
    """ARP Request interactivo."""
    from modules.packet_factory import send_arp_request

    print_section_header(console, "ARP REQUEST :: CAPA 2")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "ARP REQUEST", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    src_mac = Prompt.ask(
        f"  [{ARGOS_PRIMARY}]MAC origen (Enter = auto)[/{ARGOS_PRIMARY}]", default=""
    )

    console.print()
    try:
        result = send_arp_request(
            target_ip, src_mac=src_mac if src_mac else None, log_callback=_pf_log
        )
        if result:
            console.print(
                f"\n  [{ARGOS_SUCCESS_BOLD}]+ MAC resuelta: {result['response_mac']}[/{ARGOS_SUCCESS_BOLD}]"
            )
        else:
            console.print(f"\n  [{ARGOS_WARN}]Sin respuesta ARP de {target_ip}[/{ARGOS_WARN}]")
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


def _pf_icmp_ping():
    """ICMP Ping personalizado."""
    from modules.packet_factory import send_icmp_ping

    print_section_header(console, "ICMP PING :: CAPA 3")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "ICMP PING", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    count = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Numero de pings[/{ARGOS_PRIMARY}]", default="4"))
    ttl = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]TTL[/{ARGOS_PRIMARY}]", default="64"))
    size = int(
        Prompt.ask(f"  [{ARGOS_PRIMARY}]Tamano payload (bytes)[/{ARGOS_PRIMARY}]", default="56")
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
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


def _pf_traceroute():
    """Traceroute manual."""
    from modules.packet_factory import manual_traceroute

    print_section_header(console, "TRACEROUTE :: CAPA 3")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TRACEROUTE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    max_hops = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Max saltos[/{ARGOS_PRIMARY}]", default="30"))

    console.print()
    try:
        hops = manual_traceroute(target_ip, max_hops=max_hops, log_callback=_pf_log)
        console.print()
        console.print(create_traceroute_table(hops))
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


def _pf_tcp_probe():
    """TCP SYN Probe a puertos."""
    from modules.packet_factory import tcp_port_probe, get_common_port_groups

    print_section_header(console, "TCP SYN PROBE :: CAPA 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TCP SYN PROBE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    groups = get_common_port_groups()
    group_names = list(groups.keys())
    console.print(f"  [{ARGOS_DIM}]Grupos: {', '.join(group_names)}[/{ARGOS_DIM}]")

    port_input = Prompt.ask(
        f"  [{ARGOS_PRIMARY}]Puertos (ej: 80,443 o grupo 'web')[/{ARGOS_PRIMARY}]", default="top20"
    )

    if port_input in groups:
        ports = groups[port_input]
    else:
        try:
            ports = [int(p.strip()) for p in port_input.split(",")]
        except ValueError:
            console.print(f"  [{ARGOS_ERROR}]Formato de puertos invalido[/{ARGOS_ERROR}]")
            return

    console.print()
    try:
        results = tcp_port_probe(target_ip, ports, log_callback=_pf_log)
        console.print()
        console.print(create_port_table(results))
        open_ports = [r for r in results if r["status"] == "open"]
        console.print(
            f"\n  [{ARGOS_SUCCESS_BOLD}]Puertos abiertos: {len(open_ports)}/{len(results)}[/{ARGOS_SUCCESS_BOLD}]"
        )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


def _pf_tcp_custom():
    """Envio de segmento TCP personalizado con formulario visual de flags."""
    from modules.packet_factory import send_tcp_custom, describe_flags

    print_section_header(console, "TCP CUSTOM SEGMENT :: CAPA 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "TCP CUSTOM", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Puerto destino[/{ARGOS_PRIMARY}]", default="80"))

    # Mostrar formulario de flags disponibles
    console.print(
        f"\n  [{ARGOS_DIM}]Flags disponibles: S(YN) A(CK) F(IN) R(ST) P(SH) U(RG) E(CE) C(WR)[/{ARGOS_DIM}]"
    )
    console.print(
        f"  [{ARGOS_DIM}]Combina letras  :: Ejemplo: SA = SYN+ACK, FA = FIN+ACK[/{ARGOS_DIM}]\n"
    )

    flags = Prompt.ask(f"  [{ARGOS_PRIMARY}]Flags TCP[/{ARGOS_PRIMARY}]", default="S")

    # Mostrar panel visual de flags seleccionados
    create_tcp_flags_panel(console, flags)
    console.print()

    try:
        result = send_tcp_custom(target_ip, port, flags=flags, log_callback=_pf_log)
        if result:
            console.print(
                f"\n  [{ARGOS_PRIMARY_BOLD}]>> Estado: {result.get('status', 'N/A')}[/{ARGOS_PRIMARY_BOLD}]"
            )
            if result.get("flags_received"):
                console.print(
                    f"  [{ARGOS_WHITE}]   Flags respuesta: {result['flags_received']}[/{ARGOS_WHITE}]"
                )
                create_tcp_flags_panel(console, str(result["flags_received"]))
            if result.get("latency_ms"):
                console.print(
                    f"  [{ARGOS_WHITE}]   Latencia: {result['latency_ms']} ms[/{ARGOS_WHITE}]"
                )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


def _pf_udp_probe():
    """Sondeo UDP."""
    from modules.packet_factory import send_udp_probe

    print_section_header(console, "UDP PROBE :: CAPA 4")

    iface = _get_primary_iface()
    if iface:
        create_context_panel(console, "UDP PROBE", iface)

    target_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]IP destino[/{ARGOS_PRIMARY}]")
    if not target_ip:
        return

    port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Puerto destino[/{ARGOS_PRIMARY}]", default="53"))

    console.print()
    try:
        result = send_udp_probe(target_ip, port, log_callback=_pf_log)
        console.print(
            f"\n  [{ARGOS_PRIMARY_BOLD}]>> Puerto {result['port']}: {result['status'].upper()}[/{ARGOS_PRIMARY_BOLD}]"
        )
        if result.get("latency_ms"):
            console.print(
                f"  [{ARGOS_WHITE}]   Latencia: {result['latency_ms']} ms[/{ARGOS_WHITE}]"
            )
    except Exception as e:
        console.print(f"\n  [{ARGOS_ERROR_BOLD}]Error: {e}[/{ARGOS_ERROR_BOLD}]")

    print_footer(console)
    Prompt.ask(f"\n[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")


# ─────────────────────────────────────────────────────────────
# Utilidades internas
# ─────────────────────────────────────────────────────────────


def _select_interface() -> Optional[dict]:
    """Seleccion de interfaz de red activa."""
    active = get_active_interfaces()

    if not active:
        all_ifaces = get_local_interfaces()
        active = [i for i in all_ifaces if i["is_up"] and i["ip"] != "127.0.0.1"]

    if not active:
        console.print(
            f"  [{ARGOS_ERROR_BOLD}]X No se encontraron interfaces activas.[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]Verifica tu conexion de red.[/{ARGOS_DIM}]")
        Prompt.ask(f"[{ARGOS_DIM}]Presiona Enter para volver[/{ARGOS_DIM}]")
        return None

    if len(active) == 1:
        iface = active[0]
        console.print(
            f"  [{ARGOS_DIM}]Interfaz detectada::[/{ARGOS_DIM}] [{ARGOS_SUCCESS}]{iface['name']}[/{ARGOS_SUCCESS}] ({iface['ip']})"
        )
        return iface

    console.print(
        f"  [{ARGOS_PRIMARY_BOLD}]Selecciona una interfaz de red:[/{ARGOS_PRIMARY_BOLD}]\n"
    )
    for i, iface in enumerate(active, 1):
        console.print(
            f"    [{ARGOS_PRIMARY}]{i}[/{ARGOS_PRIMARY}]  {iface['type']}  [{ARGOS_WHITE}]{iface['ip']}[/{ARGOS_WHITE}]  ({iface['name']})"
        )

    console.print()
    choice = IntPrompt.ask(
        f"  [{ARGOS_PRIMARY}]Interfaz[/{ARGOS_PRIMARY}]",
        default=1,
    )

    idx = choice - 1
    if 0 <= idx < len(active):
        return active[idx]

    console.print(f"  [{ARGOS_ERROR}]Seleccion invalida.[/{ARGOS_ERROR}]")
    return None


# ─────────────────────────────────────────────────────────────
# Loop principal
# ─────────────────────────────────────────────────────────────


def main_loop():
    """Loop principal de Argos."""
    show_banner()

    while True:
        show_main_menu()

        choice = Prompt.ask(
            f"[{ARGOS_PRIMARY}]Argos >[/{ARGOS_PRIMARY}]",
            choices=["1", "2", "3", "4", "5"],
            default="5",
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
            console.print(f"\n  [{ARGOS_PRIMARY}]Argos desconectado.[/{ARGOS_PRIMARY}]\n")
            sys.exit(0)

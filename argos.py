#!/usr/bin/env python3
"""
Argos — Network Intelligence & Packet Factory
===============================================
Herramienta CLI empresarial para ingeniería de red:
- Descubrimiento de dispositivos en la red local
- Test de velocidad LAN entre equipos
- Fábrica de paquetes personalizados (Capas 2/3/4 del modelo OSI)

Uso:
    python argos.py                    → Menú interactivo
    python argos.py --scan             → Escaneo rápido de red
    python argos.py --interfaces       → Mostrar interfaces
    python argos.py --server           → Servidor de speed test
    python argos.py --client <IP>      → Cliente de speed test
    python argos.py --dst <IP> --flags S --port 443   → Enviar TCP custom
    python argos.py --probe <IP> --ports web          → TCP port probe
    python argos.py --traceroute <IP>  → Traceroute manual

Argos — Enterprise-Grade Network Tool v1.0
Requiere privilegios de administrador para operaciones de Capa 2 y TCP flags.
"""

import sys
import os
import ctypes
import platform
import argparse
import time

from rich.console import Console

console = Console()


def enforce_admin():
    """
    Verifica que Argos se ejecute con privilegios de administrador.
    En Windows: si no es admin, se re-lanza con elevación UAC automáticamente.
    En Linux/Mac: muestra instrucciones para usar sudo.
    """
    system = platform.system().lower()

    if system == "windows":
        # Comprobar si ya somos admin
        if ctypes.windll.shell32.IsUserAnAdmin() != 0:
            return  # Ya somos admin

        console.print("\n  [bold yellow]⚠ Argos requiere privilegios de Administrador[/bold yellow]")
        console.print("  [dim]Re-lanzando con elevación UAC...[/dim]\n")

        # Re-lanzar el script con elevación UAC
        try:
            script = os.path.abspath(sys.argv[0])
            params = " ".join(sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}" {params}', None, 1
            )
        except Exception as e:
            console.print(f"  [bold red]✗ No se pudo elevar: {e}[/bold red]")
            console.print("  [dim]Ejecuta manualmente como Administrador.[/dim]")
        sys.exit(0)

    else:
        # Linux / macOS
        if os.geteuid() == 0:
            return  # Ya somos root

        console.print("\n  [bold red]✗ Argos requiere privilegios de root[/bold red]")
        console.print("  [dim]Ejecuta con: sudo python argos.py[/dim]\n")
        sys.exit(1)


def check_dependencies():
    """Verifica que las dependencias estén instaladas."""
    missing = []

    try:
        import rich
    except ImportError:
        missing.append("rich")

    try:
        import psutil
    except ImportError:
        missing.append("psutil")

    # Scapy es opcional (fallback a ping sweep), pero requerido para Packet Factory
    scapy_available = False
    try:
        import scapy
        scapy_available = True
    except ImportError:
        pass

    if missing:
        print("\n  ✗ Faltan dependencias requeridas:")
        for dep in missing:
            print(f"    - {dep}")
        print(f"\n  Instálalas con: pip install {' '.join(missing)}")
        print(f"  O ejecuta:     pip install -r requirements.txt\n")
        sys.exit(1)

    return scapy_available


def parse_args():
    """Parsea argumentos de línea de comandos de Argos."""
    parser = argparse.ArgumentParser(
        description="Argos — Network Intelligence & Packet Factory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python argos.py                          Menú interactivo
  python argos.py --scan                   Escaneo rápido de red
  python argos.py --server                 Servidor speed test
  python argos.py --client 192.168.1.10    Cliente speed test

  Packet Factory (requiere admin + Scapy):
  python argos.py --dst 192.168.1.1 --flags S --port 443
  python argos.py --probe 192.168.1.1 --ports 80,443,22
  python argos.py --probe 192.168.1.1 --ports web
  python argos.py --traceroute 192.168.1.1
  python argos.py --ping 192.168.1.1 --count 10 --ttl 128
        """
    )

    # Opciones generales
    general = parser.add_argument_group("General")
    general.add_argument("--scan", action="store_true",
                         help="Escaneo rápido de red")
    general.add_argument("--interfaces", action="store_true",
                         help="Mostrar interfaces de red")

    # Speed test
    speed = parser.add_argument_group("Speed Test LAN")
    speed.add_argument("--server", action="store_true",
                       help="Iniciar servidor de speed test")
    speed.add_argument("--client", type=str, metavar="IP",
                       help="Conectar como cliente al servidor")
    speed.add_argument("--duration", type=int, default=10,
                       help="Duración del speed test (default: 10s)")

    # Packet Factory
    pf = parser.add_argument_group("Packet Factory (Capas 2/3/4)")
    pf.add_argument("--dst", type=str, metavar="IP",
                    help="IP destino para envío de paquete TCP/UDP custom")
    pf.add_argument("--flags", type=str, default="S",
                    help="Flags TCP: S(YN) A(CK) F(IN) R(ST) P(SH) (default: S)")
    pf.add_argument("--port", type=int, default=80,
                    help="Puerto destino para paquete custom (default: 80)")
    pf.add_argument("--probe", type=str, metavar="IP",
                    help="TCP SYN probe a puertos de una IP")
    pf.add_argument("--ports", type=str, default="top20",
                    help="Puertos para --probe (ej: 80,443 o grupo: web,top20,mikrotik)")
    pf.add_argument("--traceroute", type=str, metavar="IP",
                    help="Traceroute manual por ICMP con TTL incremental")
    pf.add_argument("--max-hops", type=int, default=30,
                    help="Máximo de saltos para traceroute (default: 30)")
    pf.add_argument("--ping", type=str, metavar="IP",
                    help="ICMP ping personalizado")
    pf.add_argument("--count", type=int, default=4,
                    help="Número de pings (default: 4)")
    pf.add_argument("--ttl", type=int, default=64,
                    help="TTL para paquetes IP (default: 64)")
    pf.add_argument("--size", type=int, default=56,
                    help="Tamaño de payload ICMP en bytes (default: 56)")

    # Compartido
    parser.add_argument("--sport", type=int, default=None,
                        help="Puerto origen TCP/UDP (default: aleatorio)")

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# Comandos directos (modo no interactivo)
# ─────────────────────────────────────────────────────────────

def cmd_quick_scan():
    """Escaneo rápido de red."""
    from modules.net_utils import get_active_interfaces, get_network_cidr
    from modules.discovery import full_scan
    from modules.report import create_device_table, create_scan_summary

    active = get_active_interfaces()
    if not active:
        console.print("[red]No se encontraron interfaces de red activas.[/red]")
        return

    iface = active[0]
    ip = iface["ip"]
    mask = iface["mask"]
    cidr = get_network_cidr(ip, mask)

    console.print(f"\n[bright_cyan]Argos escaneando {cidr} ({iface['name']})...[/bright_cyan]\n")

    start = time.perf_counter()
    devices, method = full_scan(ip, mask)
    elapsed = time.perf_counter() - start

    if devices:
        console.print(create_device_table(devices, method, ip))
        console.print()
        console.print(create_scan_summary(devices, method, elapsed, cidr))
    else:
        console.print("[yellow]No se encontraron dispositivos.[/yellow]")


def cmd_show_interfaces():
    """Muestra interfaces de red."""
    from modules.net_utils import get_local_interfaces
    from modules.report import create_interface_table

    interfaces = get_local_interfaces()
    if interfaces:
        console.print()
        console.print(create_interface_table(interfaces))
    else:
        console.print("[yellow]No se encontraron interfaces.[/yellow]")


def cmd_server(port: int = 45678):
    """Inicia servidor de speed test."""
    from modules.net_utils import get_active_interfaces
    from modules.speed_test import SpeedTestServer
    from modules.report import create_speed_result_panel

    active = get_active_interfaces()
    if active:
        console.print("\n[bright_green]Argos Speed Server — IPs:[/bright_green]")
        for iface in active:
            console.print(f"  ▶ {iface['ip']}  ({iface['name']})")

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    server = SpeedTestServer(port=port, status_callback=log)
    server.start()

    console.print(f"\n[bright_green]Servidor activo en puerto {port}[/bright_green]")
    console.print("[dim]Presiona Ctrl+C para detener...[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    server.stop()

    if server.last_result:
        result = server.last_result
        result["server_ip"] = "localhost"
        result["port"] = port
        result["total_MB"] = round(result.get("total_bytes", 0) / (1024 * 1024), 2)
        result["client_speed_mbps"] = result.get("speed_mbps", 0)
        result["client_speed_MBs"] = result.get("speed_MBs", 0)
        console.print(create_speed_result_panel(result))

    console.print("\n[dim]Servidor detenido.[/dim]")


def cmd_client(server_ip: str, port: int, duration: int):
    """Ejecuta cliente de speed test."""
    from modules.net_utils import is_private_ip
    from modules.speed_test import SpeedTestClient
    from modules.report import create_speed_result_panel

    if not is_private_ip(server_ip):
        console.print(f"[bold red]✗ {server_ip} no es una IP privada. Abortado.[/bold red]")
        return

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    client = SpeedTestClient(status_callback=log)
    console.print(f"\n[bright_yellow]Argos conectando a {server_ip}:{port}...[/bright_yellow]\n")

    result = client.run_test(server_ip, port, duration)

    if result:
        console.print()
        console.print(create_speed_result_panel(result))
    else:
        console.print("[bold red]✗ No se pudo completar el test.[/bold red]")


def cmd_tcp_custom(dst_ip: str, port: int, flags: str, src_port=None):
    """Envía un segmento TCP personalizado."""
    from modules.packet_factory import send_tcp_custom, describe_flags

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    console.print(f"\n[bright_cyan]Argos Packet Factory — TCP {describe_flags(flags)} → {dst_ip}:{port}[/bright_cyan]\n")

    result = send_tcp_custom(dst_ip, port, flags=flags, src_port=src_port, log_callback=log)

    if result:
        console.print(f"\n  [bold]Estado: {result.get('status', 'N/A')}[/bold]")
        if result.get("flags_received"):
            console.print(f"  Flags respuesta: {result['flags_received']}")
        if result.get("latency_ms"):
            console.print(f"  Latencia: {result['latency_ms']} ms")


def cmd_tcp_probe(dst_ip: str, ports_input: str):
    """TCP SYN probe a puertos."""
    from modules.packet_factory import tcp_port_probe, get_common_port_groups

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    groups = get_common_port_groups()
    if ports_input in groups:
        ports = groups[ports_input]
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            console.print("[red]Formato de puertos inválido[/red]")
            return

    console.print(f"\n[bright_cyan]Argos TCP SYN Probe → {dst_ip} ({len(ports)} puertos)[/bright_cyan]\n")

    results = tcp_port_probe(dst_ip, ports, log_callback=log)
    open_ports = [r for r in results if r["status"] == "open"]
    console.print(f"\n  [bold bright_green]Puertos abiertos: {len(open_ports)}/{len(results)}[/bold bright_green]")


def cmd_traceroute(dst_ip: str, max_hops: int):
    """Traceroute manual."""
    from modules.packet_factory import manual_traceroute

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    console.print(f"\n[bright_cyan]Argos Traceroute → {dst_ip} (max {max_hops} saltos)[/bright_cyan]\n")
    hops = manual_traceroute(dst_ip, max_hops=max_hops, log_callback=log)
    console.print(f"\n  [bold bright_green]Completado: {len(hops)} saltos[/bold bright_green]")


def cmd_icmp_ping(dst_ip: str, count: int, ttl: int, size: int):
    """ICMP ping personalizado."""
    from modules.packet_factory import send_icmp_ping

    def log(msg):
        console.print(f"  [bright_white]│[/bright_white] {msg}")

    console.print(f"\n[bright_cyan]Argos ICMP Ping → {dst_ip} (count={count}, ttl={ttl}, size={size})[/bright_cyan]\n")
    stats = send_icmp_ping(dst_ip, count=count, ttl=ttl, payload_size=size, log_callback=log)

    if stats["avg_ms"] is not None:
        console.print(f"\n  [bold bright_green]Min: {stats['min_ms']}ms  Avg: {stats['avg_ms']}ms  Max: {stats['max_ms']}ms[/bold bright_green]")
    console.print(f"  [dim]Pérdida: {stats['loss_pct']}%[/dim]")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    """Punto de entrada principal de Argos."""
    enforce_admin()
    
    # Comprobar actualizaciones en GitHub
    from modules.updater import check_for_updates
    check_for_updates()
    
    scapy_available = check_dependencies()
    args = parse_args()

    # Detectar si se pidió algún modo directo
    if args.scan:
        cmd_quick_scan()
    elif args.interfaces:
        cmd_show_interfaces()
    elif args.server:
        from modules.speed_test import DEFAULT_PORT
        cmd_server(DEFAULT_PORT)
    elif args.client:
        from modules.speed_test import DEFAULT_PORT
        cmd_client(args.client, DEFAULT_PORT, args.duration)
    elif args.dst:
        # Packet Factory: TCP custom
        if not scapy_available:
            console.print("[bold red]✗ Scapy requerido para Packet Factory. pip install scapy[/bold red]")
            sys.exit(1)
        cmd_tcp_custom(args.dst, args.port, args.flags, args.sport)
    elif args.probe:
        # Packet Factory: TCP probe
        if not scapy_available:
            console.print("[bold red]✗ Scapy requerido para Packet Factory. pip install scapy[/bold red]")
            sys.exit(1)
        cmd_tcp_probe(args.probe, args.ports)
    elif args.traceroute:
        if not scapy_available:
            console.print("[bold red]✗ Scapy requerido para Packet Factory. pip install scapy[/bold red]")
            sys.exit(1)
        cmd_traceroute(args.traceroute, args.max_hops)
    elif args.ping:
        if not scapy_available:
            console.print("[bold red]✗ Scapy requerido para Packet Factory. pip install scapy[/bold red]")
            sys.exit(1)
        cmd_icmp_ping(args.ping, args.count, args.ttl, args.size)
    else:
        # Modo interactivo
        from modules.cli_ui import main_loop
        main_loop()


if __name__ == "__main__":
    main()

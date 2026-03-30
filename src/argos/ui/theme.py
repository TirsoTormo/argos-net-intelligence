# pylint: disable=import-outside-toplevel
"""
Argos — Visual Theme System (Elite Purple Edition)
======================================================
Purple/magenta palette for elite cybersecurity aesthetics.
No emojis. Pure text, separators, and ASCII.
"""

from typing import Dict, Optional

from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich import box

# ─────────────────────────────────────────────────────────────
# CORPORATE PALETTE — ELITE PURPLE
# ─────────────────────────────────────────────────────────────

# Purple / Magenta — Main color
ARGOS_PRIMARY = "magenta"
ARGOS_PRIMARY_BOLD = "bold magenta"
ARGOS_PRIMARY_DIM = "#8B008B"

# White / Gray — Descriptive text and data
ARGOS_WHITE = "bright_white"
ARGOS_DIM = "dim"
ARGOS_MUTED = "#888888"

# Green — Only for success states
ARGOS_SUCCESS = "green"
ARGOS_SUCCESS_BOLD = "bold green"

# Red — Critical errors and denial
ARGOS_ERROR = "#FF1744"
ARGOS_ERROR_BOLD = "bold red"

# Yellow — Warnings
ARGOS_WARN = "yellow"
ARGOS_WARN_BOLD = "bold yellow"


# ─────────────────────────────────────────────────────────────
# RICH THEME
# ─────────────────────────────────────────────────────────────

ARGOS_THEME = Theme(
    {
        "argos.title": ARGOS_PRIMARY_BOLD,
        "argos.subtitle": f"bold {ARGOS_WHITE}",
        "argos.label": ARGOS_PRIMARY,
        "argos.value": ARGOS_WHITE,
        "argos.success": ARGOS_SUCCESS_BOLD,
        "argos.warning": ARGOS_WARN_BOLD,
        "argos.error": ARGOS_ERROR_BOLD,
        "argos.dim": ARGOS_DIM,
        "argos.border": ARGOS_PRIMARY,
        "argos.header": f"bold {ARGOS_WHITE} on #2D002D",
        "argos.menu.key": ARGOS_PRIMARY_BOLD,
        "argos.menu.text": ARGOS_WHITE,
    }
)


# ─────────────────────────────────────────────────────────────
# BANNER ASCII
# ─────────────────────────────────────────────────────────────

BANNER_ART = r"""[bold magenta]
   █████╗ ██████╗  ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗██╔════╝
  ███████║██████╔╝██║  ███╗██║   ██║███████╗
  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
[/bold magenta]"""

BANNER_SUBTITLE = f"[{ARGOS_WHITE}]  Network Intelligence & Packet Factory[/{ARGOS_WHITE}]"
BANNER_VERSION = (
    f"[{ARGOS_DIM}]  Enterprise-Grade Network Tool v1.0 -- Local network only (RFC 1918)[/{ARGOS_DIM}]"
)


# ─────────────────────────────────────────────────────────────
# REUSABLE COMPONENTS
# ─────────────────────────────────────────────────────────────


def create_status_bar(console: Console, iface: Optional[Dict] = None, is_admin: bool = False):
    """
    Horizontal Status Bar: active interface, IP, Gateway, admin.
    No emojis. Pure text.
    """
    admin_str = (
        f"[{ARGOS_SUCCESS}]MODE: Admin[/{ARGOS_SUCCESS}]"
        if is_admin
        else f"[{ARGOS_ERROR}]MODE: Non-Admin[/{ARGOS_ERROR}]"
    )

    if iface:
        from argos.core.net_utils import get_gateway_ip, get_network_cidr

        gateway = get_gateway_ip(iface["ip"], iface["mask"])
        cidr = get_network_cidr(iface["ip"], iface["mask"])

        parts = [
            f"[{ARGOS_PRIMARY}]IF:[/{ARGOS_PRIMARY}] "
            f"[{ARGOS_WHITE}]{iface['name']}[/{ARGOS_WHITE}]",
            f"[{ARGOS_PRIMARY}]IP:[/{ARGOS_PRIMARY}] "
            f"[{ARGOS_WHITE}]{iface['ip']}[/{ARGOS_WHITE}]",
            f"[{ARGOS_PRIMARY}]NET:[/{ARGOS_PRIMARY}] "
            f"[{ARGOS_WHITE}]{cidr}[/{ARGOS_WHITE}]",
            f"[{ARGOS_PRIMARY}]GW:[/{ARGOS_PRIMARY}] "
            f"[{ARGOS_WHITE}]{gateway}[/{ARGOS_WHITE}]",
            f"[{ARGOS_PRIMARY}]MAC:[/{ARGOS_PRIMARY}] "
            f"[{ARGOS_WHITE}]{iface['mac']}[/{ARGOS_WHITE}]",
            admin_str,
        ]
    else:
        parts = [
            f"[{ARGOS_WARN}]No active interface detected[/{ARGOS_WARN}]",
            admin_str,
        ]

    bar_text = "  |  ".join(parts)
    console.print(
        Panel(
            bar_text,
            border_style=ARGOS_PRIMARY,
            padding=(0, 1),
            box=box.HEAVY,
        )
    )


def create_context_panel(console: Console, module_name: str, iface: Optional[Dict] = None):
    """
    Network context panel at the beginning of each module.
    No emojis. Pure text with separators.
    """
    if iface:
        from argos.core.net_utils import get_gateway_ip, get_network_cidr

        gateway = get_gateway_ip(iface["ip"], iface["mask"])
        cidr = get_network_cidr(iface["ip"], iface["mask"])

        lines = [
            f"  [{ARGOS_PRIMARY}]Interface:[/{ARGOS_PRIMARY}]  "
            f"[{ARGOS_WHITE}]{iface['name']}[/{ARGOS_WHITE}]  ({iface['type']})",
            f"  [{ARGOS_PRIMARY}]Local IP:[/{ARGOS_PRIMARY}]   "
            f"[{ARGOS_WHITE}]{iface['ip']}[/{ARGOS_WHITE}]",
            f"  [{ARGOS_PRIMARY}]Subnet:[/{ARGOS_PRIMARY}]     "
            f"[{ARGOS_WHITE}]{cidr}[/{ARGOS_WHITE}]",
            f"  [{ARGOS_PRIMARY}]Gateway:[/{ARGOS_PRIMARY}]    "
            f"[{ARGOS_WHITE}]{gateway}[/{ARGOS_WHITE}]",
            f"  [{ARGOS_PRIMARY}]MAC:[/{ARGOS_PRIMARY}]        "
            f"[{ARGOS_WHITE}]{iface['mac']}[/{ARGOS_WHITE}]",
        ]
    else:
        lines = [f"  [{ARGOS_WARN}]No active network interface[/{ARGOS_WARN}]"]

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[{ARGOS_PRIMARY_BOLD}]:: {module_name} ::[/{ARGOS_PRIMARY_BOLD}]",
            border_style=ARGOS_PRIMARY,
            padding=(1, 2),
            box=box.DOUBLE,
        )
    )


def create_tcp_flags_display(flags: str) -> str:
    """
    Visual TCP flags form with ASCII checkmarks.
    Active: [X] in magenta. Inactive: [ ] in gray.
    """
    all_flags = [
        ("S", "SYN"),
        ("A", "ACK"),
        ("F", "FIN"),
        ("R", "RST"),
        ("P", "PSH"),
        ("U", "URG"),
        ("E", "ECE"),
        ("C", "CWR"),
    ]

    parts = []
    for code, name in all_flags:
        if code in flags.upper():
            parts.append(f"[{ARGOS_PRIMARY_BOLD}][X] {name}[/{ARGOS_PRIMARY_BOLD}]")
        else:
            parts.append(f"[{ARGOS_MUTED}][ ] {name}[/{ARGOS_MUTED}]")

    return "  ".join(parts)


def create_tcp_flags_panel(console: Console, flags: str):
    """Visual panel for selected TCP flags."""
    flags_display = create_tcp_flags_display(flags)
    console.print(
        Panel(
            f"  {flags_display}",
            title=f"[{ARGOS_PRIMARY_BOLD}]TCP FLAGS[/{ARGOS_PRIMARY_BOLD}]",
            border_style=ARGOS_PRIMARY,
            padding=(0, 1),
            box=box.ROUNDED,
        )
    )


def print_footer(console: Console):
    """Footer with keyboard shortcuts. No emojis."""
    console.print(
        f"\n  [{ARGOS_MUTED}]"
        f"Ctrl+C: Abort  |  "
        f"Enter: Confirm  |  "
        f"Argos v1.0"
        f"[/{ARGOS_MUTED}]"
    )


def print_section_header(console: Console, title: str):
    """Section header with decorative line. No emojis."""
    console.print(f"\n[{ARGOS_PRIMARY_BOLD}]{'=' * 3} {title} {'=' * 3}[/{ARGOS_PRIMARY_BOLD}]\n")


def format_latency(ms: Optional[float]) -> str:
    """Formats latency with color according to value."""
    if ms is None:
        return f"[{ARGOS_MUTED}]N/A[/{ARGOS_MUTED}]"
    if ms < 5:
        return f"[{ARGOS_SUCCESS}]{ms:.1f} ms[/{ARGOS_SUCCESS}]"
    if ms < 50:
        return f"[{ARGOS_WARN}]{ms:.1f} ms[/{ARGOS_WARN}]"
    return f"[{ARGOS_ERROR}]{ms:.1f} ms[/{ARGOS_ERROR}]"


def format_port_status(status: str) -> str:
    """Port status with color. No emojis."""
    if status == "open":
        return f"[{ARGOS_SUCCESS_BOLD}]OPEN[/{ARGOS_SUCCESS_BOLD}]"
    if status == "closed":
        return f"[{ARGOS_ERROR_BOLD}]CLOSED[/{ARGOS_ERROR_BOLD}]"
    if status == "filtered":
        return f"[{ARGOS_WARN_BOLD}]FILTERED[/{ARGOS_WARN_BOLD}]"
    if "open|filtered" in status:
        return f"[{ARGOS_WARN}]OPEN|FILTERED[/{ARGOS_WARN}]"
    return f"[{ARGOS_MUTED}]{status.upper()}[/{ARGOS_MUTED}]"


def create_menu_table(title: str, rows: list, has_category: bool = False) -> Table:
    """Stylized menu table. No emojis."""
    table = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style=ARGOS_PRIMARY,
        padding=(0, 2),
        title=f"[{ARGOS_PRIMARY_BOLD}]{title}[/{ARGOS_PRIMARY_BOLD}]",
        title_style="bold",
    )
    table.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
    if has_category:
        table.add_column(width=8, style=ARGOS_MUTED)
    table.add_column(style=ARGOS_WHITE)

    for row in rows:
        table.add_row(*row)

    return table


def argos_log(console: Console, msg: str, level: str = "info"):
    """Visual logger. No emojis."""
    icons = {
        "info": "|",
        "success": "+",
        "warning": "!",
        "error": "X",
    }
    colors = {
        "info": ARGOS_PRIMARY,
        "success": ARGOS_SUCCESS,
        "warning": ARGOS_WARN,
        "error": ARGOS_ERROR,
    }
    color = colors.get(level, ARGOS_PRIMARY)
    icon = icons.get(level, "|")
    console.print(f"  [{color}]{icon}[/{color}] {msg}")

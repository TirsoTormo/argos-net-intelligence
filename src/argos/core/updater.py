# pylint: disable=broad-exception-caught, import-outside-toplevel, disable=line-too-long
"""
Argos — Automatic Update Module
===========================================
Checks remote version.txt in the GitHub repository and compares it with the local one.
Shows an interactive panel if an update is available and uses git pull to apply it.
"""

import os
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

# Import corporate Elite Purple colors
try:
    from argos.ui.theme import (
        ARGOS_PRIMARY_BOLD,
        ARGOS_PRIMARY,
        ARGOS_WHITE,
        ARGOS_DIM,
        ARGOS_SUCCESS_BOLD,
        ARGOS_ERROR_BOLD,
    )
except ImportError:
    ARGOS_PRIMARY_BOLD = "bold magenta"
    ARGOS_PRIMARY = "magenta"
    ARGOS_WHITE = "bright_white"
    ARGOS_DIM = "dim"
    ARGOS_SUCCESS_BOLD = "bold green"
    ARGOS_ERROR_BOLD = "bold red"

console = Console()

REPO_URL = "https://raw.githubusercontent.com/TirsoTormo/argos-net-intelligence/main/version.txt"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_VERSION_FILE = os.path.join(PROJECT_ROOT, "version.txt")


def get_local_version() -> str:
    """Reads the local version from version.txt."""
    if not os.path.exists(LOCAL_VERSION_FILE):
        return "1.0.0"  # Fallback if it doesn't exist

    with open(LOCAL_VERSION_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def parse_version(v: str) -> tuple:
    """Converts a version string '1.0.0' into a tuple of integers (1,0,0) for comparison."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


def check_for_updates():
    """Checks remote version on GitHub and prompts the user if a newer one exists."""
    try:
        import requests
    except ImportError:
        # Silently ignore if library is missing
        return

    local_ver = get_local_version()

    try:
        # Fast request, short timeout to not slow down startup
        response = requests.get(REPO_URL, timeout=3)
        if response.status_code == 200:
            remote_ver = response.text.strip()

            # Compare versions
            if parse_version(remote_ver) > parse_version(local_ver):
                _show_update_panel(local_ver, remote_ver)
    except Exception:
        # Silently fail if no internet or network error
        pass


def _show_update_panel(local_ver: str, remote_ver: str):
    """Shows the visual panel notifying about a new version."""

    panel_text = (
        f"[{ARGOS_WHITE}]A new version of Argos has been detected "
        f"available on GitHub.[/{ARGOS_WHITE}]\n\n"
        f"  [{ARGOS_DIM}]Local Version:[/{ARGOS_DIM}]   "
        f"[{ARGOS_WHITE}]v{local_ver}[/{ARGOS_WHITE}]\n"
        f"  [{ARGOS_DIM}]Remote Version:[/{ARGOS_DIM}]  "
        f"[{ARGOS_SUCCESS_BOLD}]v{remote_ver}[/{ARGOS_SUCCESS_BOLD}]\n\n"
        f"[{ARGOS_PRIMARY}]Do you want to update now using git pull?[/{ARGOS_PRIMARY}]"
    )

    console.print()
    console.print(
        Panel(
            panel_text,
            title=f"[{ARGOS_PRIMARY_BOLD}]:: ARGOS UPDATE AVAILABLE ::[/{ARGOS_PRIMARY_BOLD}]",
            border_style=ARGOS_PRIMARY,
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    respuesta = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Argos > Update[/{ARGOS_PRIMARY}]", choices=["y", "n"], default="n"
    )

    if respuesta.lower() == "y":
        _apply_update()


def _apply_update():
    """Executes system commands to update from git."""
    console.print(f"\n  [{ARGOS_PRIMARY}]>> Starting update via git...[/{ARGOS_PRIMARY}]")

    try:
        # Move to project root before doing git pull
        os.chdir(PROJECT_ROOT)
        result = subprocess.run(["git", "pull"], capture_output=True, text=True, check=True)

        console.print(
            f"  [{ARGOS_SUCCESS_BOLD}]+ Update completed "
            f"successfully.[/{ARGOS_SUCCESS_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]Git output:[/{ARGOS_DIM}]\n{result.stdout.strip()}")

        console.print(
            f"\n  [{ARGOS_WHITE}]Please restart Argos to "
            f"apply changes.[/{ARGOS_WHITE}]"
        )
        sys.exit(0)
    except FileNotFoundError:
        console.print(
            f"  [{ARGOS_ERROR_BOLD}]X Error: Git is not installed "
            f"or not found in PATH.[/{ARGOS_ERROR_BOLD}]"
        )
    except subprocess.CalledProcessError as e:
        console.print(
            f"  [{ARGOS_ERROR_BOLD}]X Error applying update "
            f"(git pull failed):[/{ARGOS_ERROR_BOLD}]"
        )
        console.print(f"  [{ARGOS_DIM}]{e.stderr.strip()}[/{ARGOS_DIM}]")
    except Exception as e:
        console.print(f"  [{ARGOS_ERROR_BOLD}]X Unexpected error:[/{ARGOS_ERROR_BOLD}] {e}")

    console.print()

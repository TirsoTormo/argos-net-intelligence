"""
Argos — Modulo de Actualizacion Automatica
===========================================
Revisa version.txt remota en el repositorio de GitHub y compara con la local.
Muestra un panel magenta interactivo si hay actualizacion y utiliza git pull para aplicarla.
"""

import os
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

# Importar colores corporativos Elite Purple
try:
    from modules.theme import ARGOS_PRIMARY_BOLD, ARGOS_PRIMARY, ARGOS_WHITE, ARGOS_DIM, ARGOS_SUCCESS_BOLD, ARGOS_ERROR_BOLD
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
    """Lee la versión local desde version.txt."""
    if not os.path.exists(LOCAL_VERSION_FILE):
        return "1.0.0"  # Fallback si no existe
    
    with open(LOCAL_VERSION_FILE, "r") as f:
        return f.read().strip()


def parse_version(v: str) -> tuple:
    """Convierte un string de version '1.0.0' en tupla de enteros (1,0,0) para comparar."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


def check_for_updates():
    """Consulta version remota en GitHub y promtea al usuario si hay una mas nueva."""
    try:
        import requests
    except ImportError:
        # Se ignora silenciosamente si falta la libreria
        return

    local_ver = get_local_version()

    try:
        # Peticion rapida, timeout corto para no ralentizar el arranque
        response = requests.get(REPO_URL, timeout=3)
        if response.status_code == 200:
            remote_ver = response.text.strip()
            
            # Comparar versiones
            if parse_version(remote_ver) > parse_version(local_ver):
                _show_update_panel(local_ver, remote_ver)
    except Exception:
        # Falla silenciosamente si no hay internet o error de red
        pass


def _show_update_panel(local_ver: str, remote_ver: str):
    """Muestra el panel visual magenta avisando de nueva version."""
    
    panel_text = (
        f"[{ARGOS_WHITE}]Se ha detectado una nueva version de Argos disponible en GitHub.[/{ARGOS_WHITE}]\n\n"
        f"  [{ARGOS_DIM}]Version Local:[/{ARGOS_DIM}]   [{ARGOS_WHITE}]v{local_ver}[/{ARGOS_WHITE}]\n"
        f"  [{ARGOS_DIM}]Version Remota:[/{ARGOS_DIM}]  [{ARGOS_SUCCESS_BOLD}]v{remote_ver}[/{ARGOS_SUCCESS_BOLD}]\n\n"
        f"[{ARGOS_PRIMARY}]¿Desea actualizar ahora usando git pull?[/{ARGOS_PRIMARY}]"
    )
    
    console.print()
    console.print(Panel(
        panel_text,
        title=f"[{ARGOS_PRIMARY_BOLD}]:: ACTUALIZACION DE ARGOS DISPONIBLE ::[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        box=box.DOUBLE,
        padding=(1, 2)
    ))
    
    respuesta = Prompt.ask(
        f"[{ARGOS_PRIMARY}]Argos > Update[/{ARGOS_PRIMARY}]",
        choices=["s", "n"],
        default="n"
    )
    
    if respuesta.lower() == "s":
        _apply_update()


def _apply_update():
    """Ejecuta los comandos de sistema para actualizar desde git."""
    console.print(f"\n  [{ARGOS_PRIMARY}]>> Iniciando actualizacion via git...[/{ARGOS_PRIMARY}]")
    
    try:
        # Nos movemos a la raiz del proyecto antes de hacer git pull
        os.chdir(PROJECT_ROOT)
        result = subprocess.run(
            ["git", "pull"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        console.print(f"  [{ARGOS_SUCCESS_BOLD}]+ Actualizacion completada correctamente.[/{ARGOS_SUCCESS_BOLD}]")
        console.print(f"  [{ARGOS_DIM}]Salida de git:[/{ARGOS_DIM}]\n{result.stdout.strip()}")
        
        console.print(f"\n  [{ARGOS_WHITE}]Por favor reinicia Argos para aplicar los cambios.[/{ARGOS_WHITE}]")
        sys.exit(0)
    except FileNotFoundError:
        console.print(f"  [{ARGOS_ERROR_BOLD}]X Error: Git no esta instalado o no se encuentra en el PATH.[/{ARGOS_ERROR_BOLD}]")
    except subprocess.CalledProcessError as e:
        console.print(f"  [{ARGOS_ERROR_BOLD}]X Error aplicando actualizacion (git pull faliido):[/{ARGOS_ERROR_BOLD}]")
        console.print(f"  [{ARGOS_DIM}]{e.stderr.strip()}[/{ARGOS_DIM}]")
    except Exception as e:
        console.print(f"  [{ARGOS_ERROR_BOLD}]X Error inesperado:[/{ARGOS_ERROR_BOLD}] {e}")
    
    console.print()

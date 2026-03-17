# Argos — Network Intelligence & Packet Factory
   █████╗ ██████╗  ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗██╔════╝
  ███████║██████╔╝██║  ███╗██║   ██║███████╗
  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
  
Herramienta CLI empresarial e interfaz de consola avanzada (Elite Purple Edition) para ingeniería de red, descubrimiento de dispositivos, pruebas de rendimiento LAN y forjado de paquetes a medida (Packet Factory OSI L2-4). Orientada para entornos locales estrictos (RFC 1918) sin dependencias de salida a Internet.

## Estructura / Structure

📂 **Organización del Proyecto**

* **`argos.py`**: El núcleo que arranca la herramienta. (Main entry point).
* **`modules/`**:
  * **`cli_ui.py`**: Interfaz visual en Morado/Magenta con la librería Rich. (UI logic).
  * **`discovery.py`**: Escaneo de red y detección de dispositivos. (Network discovery).
  * **`packet_factory.py`**: Creación de paquetes a medida (Capas 2-4). (Packet crafting).
  * **`net_utils.py`**: Herramientas para validar IPs y tarjetas de red. (Network helpers).
  * **`theme.py`**: Sistema central de paleta de colores y componentes visuales. (Theme system).
  * **`speed_test.py`**: Cliente/Servidor TCP para medir el throughput. (LAN Speed test).
  * **`report.py`**: Motor de formateo visual para tablas y paneles de reporting. (Rich reporting).
* **`requirements.txt`**: Librerías externas necesarias. (Dependencies).
* **`.agent/skills/argos-identity/SKILL.md`**: Definición técnica de identidad y directrices. (Agent skill definition).

## Características (Features)

1. **Discovery**: Escaneo local usando Scapy (ARP) o fallback automático a Ping Sweep, detectando MAC, Hostname y fabricante (Vendor).
2. **Speed Test**: Interfaz gráfica nativa en terminal para levantar un Servidor o conectar como Cliente y saturar artificialmente la transferencia TCP para calcular latencia (RTT) y velocidad bruta (Mbps / MB/s).
3. **Packet Factory**: Módulo de privilegios bajos nivel:
   * **Capa 2**: Tramas Ethernet crudas, peticiones ARP dirigidas.
   * **Capa 3**: Manipulación IP, ping ICMP, traceroutes configurando TTL incremental.
   * **Capa 4**: Envío TCP manual formulando flags específicas (SYN, ACK, PSH, RST, FIN) para tests, y sondeo TCP/UDP de capa de transporte.

## Requisitos y Configuración

El framework emplea utilidades de terminal modernas, por lo cual se recomienda una consola que soporte renderizado de color estilo Truecolor (PowerShell moderno o Windows Terminal, Gnome Terminal, iTerm2, etc).

Además es estrictamente necesario:
- **Python 3.10+** instalado y en PATH.
- **Scapy** funcional y, muy importante, **permisos de Administrador / Root** para operar la fábrica de paquetes. En Windows Argos lo solicitará (UAC prompt) automáticamente; en sistemas basados en UNIX requiere correr bajo entorno `sudo`.

```bash
# Instalar dependencias requeridas
pip install -r requirements.txt

# Iniciar la interfaz interactiva
python argos.py
```

## Uso Rápido (Expert CLI Arguments)

Admite paso de parámetros de control directo para los usuarios avanzados que deseen bypassear la interfaz de menú e integrarlo en sus scripts. Todos los ejemplos devuelven reporting altamente diseñado.

```powershell
python argos.py --interfaces
python argos.py --scan

# Pruebas manuales TCP a nivel paquete
python argos.py --dst 192.168.1.1 --flags S --port 443
python argos.py --probe 192.168.1.1 --ports web
python argos.py --traceroute 192.168.1.1
```